//! Durable RFC 3464 DSN admission.
//!
//! The implementation is intentionally kept separate from the legacy Redis
//! task JSON.  A PostgreSQL outbox row is the only source of truth for a DSN;
//! Redis is populated only after the queue/index/maildir transaction commits.

use std::{fmt, fmt::Write as _};

use chrono::{DateTime, Utc};
use idna::domain_to_ascii_strict;
use mail_parser::MessageParser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::{
    outbound::{DsnAdmission, OutboundError, OutboundService},
    outbound_delivery::{DeliveryStateError, PostgresDeliveryState},
};

const MAX_DSN_RECIPIENTS: usize = 1_000;
const MAX_DSN_BYTES: usize = 2 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 700;
const DSN_WORK_BUDGET: std::time::Duration = std::time::Duration::from_secs(90);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DsnRecipientSnapshot {
    pub recipient: String,
    pub state: String,
    pub smtp_code: Option<u16>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct DsnEligibility {
    pub original_task_id: i64,
    pub sender_address: String,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    pub created_at: String,
    pub terminal_at: String,
    pub recipients: Vec<DsnRecipientSnapshot>,
}

impl DsnEligibility {
    pub(crate) fn validate(&self) -> bool {
        self.original_task_id > 0
            && !self.sender_address.is_empty()
            && self.sender_address.len() <= 320
            && !self.recipients.is_empty()
            && self.recipients.len() <= MAX_DSN_RECIPIENTS
            && self
                .recipients
                .iter()
                .any(|recipient| recipient.state == "PERMANENT")
            && self.recipients.iter().all(|recipient| {
                !recipient.recipient.is_empty()
                    && recipient.recipient.len() <= 320
                    && !recipient.recipient.chars().any(char::is_control)
                    && matches!(recipient.state.as_str(), "DELIVERED" | "PERMANENT")
            })
            && DateTime::parse_from_rfc3339(&self.created_at).is_ok()
            && DateTime::parse_from_rfc3339(&self.terminal_at).is_ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RenderedDsn {
    pub sender: String,
    pub recipient: String,
    pub subject: String,
    pub message_id: String,
    pub created_at: DateTime<Utc>,
    pub body: String,
}

#[derive(Clone)]
pub(crate) struct DsnDispatcher {
    state: PostgresDeliveryState,
    outbound: OutboundService,
}

#[derive(Debug)]
pub(crate) enum DsnDispatchError {
    Cancelled,
    State(DeliveryStateError),
    Admission(OutboundError),
}

impl fmt::Display for DsnDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("outbound DSN dispatch was cancelled"),
            Self::State(error) => write!(formatter, "outbound DSN state failed: {error}"),
            Self::Admission(error) => write!(formatter, "outbound DSN admission failed: {error}"),
        }
    }
}

impl std::error::Error for DsnDispatchError {}

impl From<DeliveryStateError> for DsnDispatchError {
    fn from(error: DeliveryStateError) -> Self {
        Self::State(error)
    }
}

impl From<OutboundError> for DsnDispatchError {
    fn from(error: OutboundError) -> Self {
        Self::Admission(error)
    }
}

impl DsnDispatcher {
    pub(crate) fn new(state: PostgresDeliveryState, outbound: OutboundService) -> Self {
        Self { state, outbound }
    }

    pub(crate) async fn dispatch_batch(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<usize, DsnDispatchError> {
        if cancellation.is_cancelled() {
            return Err(DsnDispatchError::Cancelled);
        }
        self.outbound
            .republish_admitted_dsns(cancellation)
            .await
            .map_err(|error| {
                if cancellation.is_cancelled() {
                    DsnDispatchError::Cancelled
                } else {
                    DsnDispatchError::Admission(error)
                }
            })?;
        let mut dispatched = 0;
        for _ in 0..limit {
            if cancellation.is_cancelled() {
                return Err(DsnDispatchError::Cancelled);
            }
            let Some(item) = self.state.stage_and_lease_dsns(1, Utc::now()).await?.pop() else {
                break;
            };
            let deadline = Instant::now() + DSN_WORK_BUDGET;
            let Some(rendered) = render_dsn(&item.payload) else {
                self.state
                    .suppress_dsn(
                        item.original_task_id,
                        &item.lease_token,
                        "terminal DSN payload could not be rendered safely",
                        Utc::now(),
                    )
                    .await?;
                continue;
            };
            let dsn_task_id = match item.dsn_task_id {
                Some(task_id) => task_id,
                None => {
                    let task_id = tokio::select! {
                        _ = cancellation.cancelled() => return Err(DsnDispatchError::Cancelled),
                        result = timeout_at(deadline, self.outbound.reserve_task_id()) => {
                            result.map_err(|_| DsnDispatchError::Admission(OutboundError::Unavailable))??
                        }
                    };
                    tokio::select! {
                        _ = cancellation.cancelled() => return Err(DsnDispatchError::Cancelled),
                        result = timeout_at(
                            deadline,
                            self.state.bind_dsn_task_id(
                                item.original_task_id,
                                &item.lease_token,
                                task_id,
                                Utc::now(),
                            ),
                        ) => {
                            result
                                .map_err(|_| DsnDispatchError::State(DeliveryStateError::Unavailable))??;
                        }
                    }
                    task_id
                }
            };
            let expected_sha256 = Sha256::digest(rendered.body.as_bytes()).into();
            let admission_cancellation = cancellation.child_token();
            let mut admission = Box::pin(self.outbound.admit_dsn(
                DsnAdmission {
                    source_task_id: item.original_task_id,
                    task_id: dsn_task_id,
                    lease_token: item.lease_token,
                    sender: rendered.sender,
                    recipient: rendered.recipient,
                    subject: rendered.subject,
                    message_id: rendered.message_id,
                    body: rendered.body,
                    created_at: rendered.created_at,
                    unsigned_sha256: expected_sha256,
                },
                &admission_cancellation,
            ));
            let result = tokio::select! {
                _ = cancellation.cancelled() => {
                    admission_cancellation.cancel();
                    let _ = admission.await;
                    return Err(DsnDispatchError::Cancelled);
                }
                result = timeout_at(deadline, &mut admission) => {
                    match result {
                        Ok(result) => result,
                        Err(_) => {
                            admission_cancellation.cancel();
                            let _ = admission.await;
                            return Err(DsnDispatchError::Admission(OutboundError::Unavailable));
                        }
                    }
                }
            };
            result.map_err(|error| {
                if cancellation.is_cancelled() {
                    DsnDispatchError::Cancelled
                } else {
                    DsnDispatchError::Admission(error)
                }
            })?;
            dispatched += 1;
        }
        Ok(dispatched)
    }
}

/// Validate the original sender before generating a DSN.  This deliberately
/// accepts the same dot-atom/EAI local-part shape as the outbound API, but
/// additionally requires a local mailbox to be checked by the durable
/// dispatcher.  Display names, groups, control characters, and multiple
/// addresses are rejected so a DSN can never become an open relay.
pub(crate) fn normalize_reply_address(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 320 || value.chars().any(char::is_control) {
        return None;
    }
    let synthetic = format!("From: {value}\r\n\r\n");
    let message = MessageParser::default().parse(synthetic.as_bytes())?;
    let addresses = message.from()?;
    let mut iter = addresses.iter();
    let address = iter.next()?.address()?;
    if iter.next().is_some() {
        return None;
    }
    let (local, domain) = address.rsplit_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || domain.is_empty()
        || domain.contains('@')
        || !local.chars().all(valid_local_character)
    {
        return None;
    }
    let ascii_domain = domain_to_ascii_strict(domain).ok()?.to_ascii_lowercase();
    Some(if local.is_ascii() {
        format!("{}@{ascii_domain}", local.to_ascii_lowercase())
    } else {
        format!("{local}@{ascii_domain}")
    })
}

fn valid_local_character(character: char) -> bool {
    if character.is_ascii() {
        character.is_ascii_alphanumeric() || ".!#$%&'*+/=?^_`{|}~-".contains(character)
    } else {
        !character.is_control() && !character.is_whitespace()
    }
}

pub(crate) fn stable_message_id(
    original_task_id: i64,
    original_message_id: Option<&str>,
    sender: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(original_task_id.to_be_bytes());
    digest.update(original_message_id.unwrap_or_default().as_bytes());
    digest.update(sender.as_bytes());
    let digest = digest.finalize();
    let mut suffix = String::with_capacity(32);
    for byte in &digest[..16] {
        let _ = write!(suffix, "{byte:02x}");
    }
    let domain = sender
        .rsplit_once('@')
        .map_or("invalid", |(_, domain)| domain);
    format!("<dsn-{original_task_id}-{suffix}@{domain}>")
}

pub(crate) fn render_dsn(payload: &DsnEligibility) -> Option<RenderedDsn> {
    if !payload.validate() {
        return None;
    }
    let recipient = normalize_reply_address(&payload.sender_address)?;
    let (_, domain) = recipient.rsplit_once('@')?;
    let message_id = stable_message_id(
        payload.original_task_id,
        payload.message_id.as_deref(),
        &recipient,
    );
    let arrival_at = DateTime::parse_from_rfc3339(&payload.created_at)
        .ok()?
        .with_timezone(&Utc);
    let created_at = DateTime::parse_from_rfc3339(&payload.terminal_at)
        .ok()?
        .with_timezone(&Utc);
    let boundary = format!(
        "=_lmyzmail_dsn_{}",
        &hex_digest(message_id.as_bytes())[..32]
    );
    let mut failed = payload
        .recipients
        .iter()
        .filter(|recipient| recipient.state == "PERMANENT")
        .take(MAX_DSN_RECIPIENTS)
        .collect::<Vec<_>>();
    if failed.is_empty() {
        return None;
    }
    failed.sort_by(|left, right| left.recipient.cmp(&right.recipient));
    let global_report = !recipient.is_ascii()
        || failed.iter().any(|item| {
            !item.recipient.is_ascii()
                || !diagnostic(item.smtp_code, item.detail.as_deref()).is_ascii()
        })
        || payload
            .subject
            .as_deref()
            .is_some_and(|value| !sanitize_header(value, 800).is_ascii())
        || payload
            .message_id
            .as_deref()
            .is_some_and(|value| !sanitize_header(value, 255).is_ascii());
    let report_type = if global_report {
        "global-delivery-status"
    } else {
        "delivery-status"
    };

    let mut human =
        String::from("This is an automatically generated Delivery Status Notification.\r\n\r\n");
    human.push_str("Delivery to the following recipient(s) failed:\r\n");
    for item in &failed {
        human.push_str("  ");
        human.push_str(&sanitize_text(&item.recipient, 320));
        human.push_str("\r\n");
    }

    let mut body = String::new();
    let _ = write!(
        body,
        "From: Mail Delivery Subsystem <mailer-daemon@{domain}>\r\n\
To: {recipient}\r\n\
Subject: Delivery Status Notification (Failure)\r\n\
Date: {}\r\n\
Message-ID: {message_id}\r\n\
Auto-Submitted: auto-replied\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/report; report-type={report_type}; boundary=\"{boundary}\"\r\n\r\n",
        rfc2822_date(created_at),
    );
    write_boundary(&mut body, &boundary, false);
    body.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
    body.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    body.push_str(&quoted_printable(&human));
    body.push_str("\r\n");

    write_boundary(&mut body, &boundary, false);
    let mut delivery_status = format!("Reporting-MTA: dns; {domain}\r\n");
    delivery_status.push_str(&format!(
        "Arrival-Date: {}\r\n\r\n",
        rfc2822_date(arrival_at)
    ));
    for item in &failed {
        let address_type = if item.recipient.is_ascii() {
            "rfc822"
        } else {
            "utf-8"
        };
        delivery_status.push_str(&format!("Final-Recipient: {address_type}; "));
        delivery_status.push_str(&sanitize_text(&item.recipient, 320));
        delivery_status.push_str("\r\nAction: failed\r\nStatus: ");
        delivery_status.push_str(&status_code(item.smtp_code, item.detail.as_deref()));
        delivery_status.push_str("\r\nDiagnostic-Code: smtp; ");
        delivery_status.push_str(&diagnostic(item.smtp_code, item.detail.as_deref()));
        delivery_status.push_str("\r\n\r\n");
    }
    if global_report {
        body.push_str("Content-Type: message/global-delivery-status\r\n");
        if recipient.is_ascii() {
            body.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
            body.push_str(&quoted_printable(&delivery_status));
            body.push_str("\r\n");
        } else {
            body.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
            body.push_str(&delivery_status);
        }
    } else {
        body.push_str("Content-Type: message/delivery-status\r\n\r\n");
        body.push_str(&delivery_status);
    }

    // The third part is the RFC 3464 optional message/rfc822 return-content.
    // Only bounded headers are returned; no original body or attachment bytes
    // are copied into a bounce.
    write_boundary(&mut body, &boundary, false);
    let mut returned_headers = format!(
        "Message-ID: {}\r\n",
        sanitize_header(payload.message_id.as_deref().unwrap_or(""), 255)
    );
    if let Some(subject) = payload.subject.as_deref() {
        returned_headers.push_str(&format!("Subject: {}\r\n", sanitize_header(subject, 800)));
    }
    returned_headers.push_str(&format!(
        "From: {}\r\n\r\n",
        sanitize_header(&recipient, 320)
    ));
    if global_report {
        body.push_str("Content-Type: message/global-headers\r\n");
        if recipient.is_ascii() {
            body.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
            body.push_str(&quoted_printable(&returned_headers));
            body.push_str("\r\n");
        } else {
            body.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
            body.push_str(&returned_headers);
        }
    } else {
        body.push_str("Content-Type: text/rfc822-headers\r\n\r\n");
        body.push_str(&returned_headers);
    }
    write_boundary(&mut body, &boundary, true);
    if body.len() > MAX_DSN_BYTES {
        return None;
    }
    Some(RenderedDsn {
        sender: format!("mailer-daemon@{domain}"),
        recipient,
        subject: "Delivery Status Notification (Failure)".to_owned(),
        message_id,
        created_at,
        body,
    })
}

fn write_boundary(body: &mut String, boundary: &str, final_boundary: bool) {
    body.push_str("--");
    body.push_str(boundary);
    if final_boundary {
        body.push_str("--");
    }
    body.push_str("\r\n");
}

fn status_code(_code: Option<u16>, detail: Option<&str>) -> String {
    if let Some(value) = detail.and_then(extract_enhanced_status) {
        return value;
    }
    "5.0.0".to_owned()
}

fn extract_enhanced_status(value: &str) -> Option<String> {
    for token in value.split(|character: char| !character.is_ascii_digit() && character != '.') {
        let mut components = token.split('.');
        let class = components.next();
        let subject = components.next();
        let detail = components.next();
        if class == Some("5")
            && components.next().is_none()
            && subject.is_some_and(valid_status_component)
            && detail.is_some_and(valid_status_component)
        {
            return Some(token.to_owned());
        }
    }
    None
}

fn valid_status_component(value: &str) -> bool {
    (1..=3).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn diagnostic(code: Option<u16>, detail: Option<&str>) -> String {
    let prefix = code
        .filter(|value| (500..=599).contains(value))
        .map_or_else(|| "550".to_owned(), |value| value.to_string());
    let detail = sanitize_text(
        detail.unwrap_or("permanent delivery failure"),
        MAX_DIAGNOSTIC_BYTES,
    );
    if detail.is_empty() {
        prefix
    } else if detail.starts_with(&prefix) {
        detail
    } else {
        format!("{prefix} {detail}")
    }
}

fn sanitize_text(value: &str, maximum: usize) -> String {
    let mut output = String::with_capacity(value.len().min(maximum));
    for character in value.chars() {
        if output.len() + character.len_utf8() > maximum {
            break;
        }
        if character == '\r' || character == '\n' || character.is_control() {
            output.push(' ');
        } else {
            output.push(character);
        }
    }
    output
}

fn sanitize_header(value: &str, maximum: usize) -> String {
    sanitize_text(value, maximum)
}

fn quoted_printable(value: &str) -> String {
    let mut output = Vec::new();
    let _ = mail_builder::encoders::quoted_printable::quoted_printable_encode(
        value.as_bytes(),
        &mut output,
        true,
    );
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_digest(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn rfc2822_date(value: DateTime<Utc>) -> String {
    value.to_rfc2822()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_parser::decoders::quoted_printable::quoted_printable_decode;

    fn eligible_payload() -> DsnEligibility {
        DsnEligibility {
            original_task_id: 42,
            sender_address: "Sender@Example.Test".to_owned(),
            subject: Some("Quarterly report".to_owned()),
            message_id: Some("<original-42@example.test>".to_owned()),
            created_at: "2026-08-06T01:02:03.123456Z".to_owned(),
            terminal_at: "2026-08-06T02:03:04.654321Z".to_owned(),
            recipients: vec![
                DsnRecipientSnapshot {
                    recipient: "delivered@example.test".to_owned(),
                    state: "DELIVERED".to_owned(),
                    smtp_code: Some(250),
                    detail: None,
                },
                DsnRecipientSnapshot {
                    recipient: "z-failed@example.test".to_owned(),
                    state: "PERMANENT".to_owned(),
                    smtp_code: Some(550),
                    detail: Some("550 5.1.1 user unknown".to_owned()),
                },
                DsnRecipientSnapshot {
                    recipient: "a-failed@example.test".to_owned(),
                    state: "PERMANENT".to_owned(),
                    smtp_code: Some(554),
                    detail: Some("554 5.7.1 policy rejected".to_owned()),
                },
            ],
        }
    }

    fn decoded_quoted_printable_part(body: &str, media_type: &str) -> String {
        let marker = format!(
            "Content-Type: {media_type}\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
        );
        let encoded = body
            .split_once(&marker)
            .and_then(|(_, remainder)| remainder.split_once("\r\n--=_lmyzmail_dsn_"))
            .map(|(value, _)| value)
            .expect("quoted-printable global part must be bounded by the next MIME boundary");
        String::from_utf8(quoted_printable_decode(encoded.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn render_dsn_has_rfc3464_parts_and_crlf_only() {
        let rendered = render_dsn(&eligible_payload()).expect("eligible payload must render");
        let body = &rendered.body;
        let boundary = body
            .split_once("boundary=\"")
            .and_then(|(_, value)| value.split_once('\"'))
            .map(|(value, _)| value)
            .expect("multipart boundary must be present");

        assert_eq!(rendered.sender, "mailer-daemon@example.test");
        assert_eq!(rendered.recipient, "sender@example.test");
        assert_eq!(rendered.subject, "Delivery Status Notification (Failure)");
        assert_eq!(
            rendered.created_at,
            DateTime::parse_from_rfc3339("2026-08-06T02:03:04.654321Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert!(body.starts_with("From: Mail Delivery Subsystem <mailer-daemon@example.test>\r\n"));
        assert!(
            body.contains(
                "Content-Type: multipart/report; report-type=delivery-status; boundary=\""
            )
        );
        assert!(body.contains("Content-Type: text/plain; charset=UTF-8\r\n"));
        assert!(body.contains("Content-Transfer-Encoding: quoted-printable\r\n\r\n"));
        assert!(body.contains("Content-Type: message/delivery-status\r\n\r\n"));
        assert!(body.contains("Content-Type: text/rfc822-headers\r\n\r\n"));
        assert!(body.contains("Reporting-MTA: dns; example.test\r\n"));
        assert!(body.contains("Date: Thu, 6 Aug 2026 02:03:04 +0000\r\n"));
        assert!(body.contains("Arrival-Date: Thu, 6 Aug 2026 01:02:03 +0000\r\n"));
        assert!(!body.contains("Original-Envelope-Id:"));
        assert!(body.contains("Final-Recipient: rfc822; a-failed@example.test\r\n"));
        assert!(body.contains("Action: failed\r\nStatus: 5.7.1\r\n"));
        assert!(body.contains("Diagnostic-Code: smtp; 554 5.7.1 policy rejected\r\n"));
        assert!(body.contains("Final-Recipient: rfc822; z-failed@example.test\r\n"));
        assert_eq!(body.matches(&format!("--{boundary}")).count(), 4);
        assert!(body.ends_with(&format!("--{boundary}--\r\n")));
        assert!(!body.replace("\r\n", "").contains('\n'));
        assert!(!body.replace("\r\n", "").contains('\r'));
    }

    #[test]
    fn fixed_input_has_stable_message_id_bytes_and_sha256() {
        let first = render_dsn(&eligible_payload()).expect("eligible payload must render");
        let second = render_dsn(&eligible_payload()).expect("eligible payload must render");

        assert_eq!(first, second);
        assert_eq!(
            first.message_id,
            "<dsn-42-46af9006970e3b499098ccdf728ac23f@example.test>"
        );
        assert_eq!(
            hex_digest(&Sha256::digest(first.body.as_bytes())),
            "1d6e6868d94e2083e110e5feeff9df5131f9fad251e80f41075a9b4d903af8a2"
        );
    }

    #[test]
    fn header_and_diagnostic_crlf_injection_is_flattened() {
        let mut payload = eligible_payload();
        payload.subject = Some("subject\r\nBcc: attacker@example.test".to_owned());
        payload.message_id = Some("<original\r\nX-Injected: yes>".to_owned());
        payload.recipients[1].detail = Some("550 5.1.1\r\nX-Diagnostic: injected".to_owned());

        let rendered = render_dsn(&payload).expect("header controls must be flattened");
        assert!(
            rendered
                .body
                .contains("Subject: subject  Bcc: attacker@example.test\r\n")
        );
        assert!(
            rendered.body.contains(
                "Message-ID: <original  X-Injected: yes>\r\nSubject: subject  Bcc: attacker@example.test\r\n"
            )
        );
        assert!(
            rendered
                .body
                .contains("Diagnostic-Code: smtp; 550 5.1.1  X-Diagnostic: injected\r\n")
        );
        assert!(!rendered.body.contains("\r\nBcc:"));
        assert!(!rendered.body.contains("\r\nX-Injected:"));
        assert!(!rendered.body.contains("\r\nX-Diagnostic:"));
    }

    #[test]
    fn enhanced_status_accepts_only_permanent_class() {
        let mut payload = eligible_payload();
        payload.recipients[1].smtp_code = Some(550);
        payload.recipients[1].detail = Some("550 2.0.0 misleading success text".to_owned());
        let rendered = render_dsn(&payload).expect("ASCII permanent failure must render");
        assert!(rendered.body.contains("Status: 5.0.0\r\n"));
        assert!(!rendered.body.contains("Status: 2.0.0\r\n"));

        payload.recipients[1].detail = Some("550 5.123.999 valid bounded status".to_owned());
        let rendered = render_dsn(&payload).expect("bounded 5.x.x status must render");
        assert!(rendered.body.contains("Status: 5.123.999\r\n"));

        payload.recipients[1].detail = Some("550 5.1234.1 oversized subject".to_owned());
        let rendered = render_dsn(&payload).expect("invalid status must use the fallback");
        assert!(rendered.body.contains("Status: 5.0.0\r\n"));
    }

    #[test]
    fn recipient_crlf_injection_is_suppressed_before_rendering() {
        let mut payload = eligible_payload();
        payload.recipients[1].recipient = "victim@example.test\r\nX-Recipient: injected".to_owned();
        assert!(render_dsn(&payload).is_none());

        payload = eligible_payload();
        payload.sender_address = "sender@example.test\r\nX-Recipient: injected".to_owned();
        assert!(render_dsn(&payload).is_none());
    }

    #[test]
    fn smtp_utf8_reply_address_uses_rfc6533_8bit_parts() {
        let mut payload = eligible_payload();
        payload.sender_address = "\u{7528}\u{6237}@example.test".to_owned();
        let rendered = render_dsn(&payload).expect("EAI reply address must produce a global DSN");
        assert_eq!(rendered.recipient, "\u{7528}\u{6237}@example.test");
        assert_eq!(rendered.sender, "mailer-daemon@example.test");
        assert!(rendered.message_id.ends_with("@example.test>"));
        assert!(
            rendered
                .body
                .contains("To: \u{7528}\u{6237}@example.test\r\n")
        );
        assert!(
            rendered
                .body
                .contains("report-type=global-delivery-status;")
        );
        assert!(rendered.body.contains(
            "Content-Type: message/global-delivery-status\r\nContent-Transfer-Encoding: 8bit\r\n"
        ));
        assert!(rendered.body.contains(
            "Content-Type: message/global-headers\r\nContent-Transfer-Encoding: 8bit\r\n"
        ));
        assert!(
            rendered
                .body
                .contains("From: \u{7528}\u{6237}@example.test\r\n")
        );
    }

    #[test]
    fn ascii_reply_with_global_fields_stays_seven_bit_on_the_wire() {
        let mut payload = eligible_payload();
        payload.recipients[1].recipient = "\u{5931}\u{8d25}@example.test".to_owned();
        payload.recipients[1].detail =
            Some("550 5.1.1 \u{7528}\u{6237}\u{4e0d}\u{5b58}\u{5728}".to_owned());
        payload.subject = Some("\u{5931}\u{8d25}\u{7684}\u{62a5}\u{544a}".to_owned());
        let rendered = render_dsn(&payload).expect("global fields must produce a DSN");
        assert!(rendered.body.is_ascii());
        assert!(
            rendered
                .body
                .contains("report-type=global-delivery-status;")
        );
        assert!(!rendered.body.contains("message/global-delivery-status;"));
        assert!(!rendered.body.contains("message/global-headers;"));
        assert!(!rendered.body.contains("=?UTF-8?"));

        let status =
            decoded_quoted_printable_part(&rendered.body, "message/global-delivery-status");
        assert!(status.contains("Final-Recipient: utf-8; \u{5931}\u{8d25}@example.test\r\n"));
        assert!(status.contains("Final-Recipient: rfc822; a-failed@example.test\r\n"));
        assert!(status.contains(
            "Diagnostic-Code: smtp; 550 5.1.1 \u{7528}\u{6237}\u{4e0d}\u{5b58}\u{5728}\r\n"
        ));

        let headers = decoded_quoted_printable_part(&rendered.body, "message/global-headers");
        assert!(headers.contains("Subject: \u{5931}\u{8d25}\u{7684}\u{62a5}\u{544a}\r\n"));
        assert!(headers.contains("From: sender@example.test\r\n"));
        assert!(!headers.contains("=?UTF-8?"));
    }

    #[test]
    fn idn_only_reply_domain_is_normalized_to_ascii_without_global_report() {
        let mut payload = eligible_payload();
        payload.sender_address = "Sender@\u{4f8b}\u{5b50}.\u{6d4b}\u{8bd5}".to_owned();
        let rendered = render_dsn(&payload).expect("IDN domain must normalize to an A-label");
        assert!(rendered.recipient.is_ascii());
        assert_eq!(rendered.recipient, "sender@xn--fsqu00a.xn--0zwm56d");
        assert!(rendered.message_id.ends_with("@xn--fsqu00a.xn--0zwm56d>"));
        assert!(rendered.body.contains("report-type=delivery-status;"));
        assert!(!rendered.body.contains("message/global-delivery-status"));
    }

    #[test]
    fn malformed_or_ineligible_payloads_are_suppressed() {
        let mut payload = eligible_payload();
        payload
            .recipients
            .iter_mut()
            .for_each(|recipient| recipient.state = "DELIVERED".to_owned());
        assert!(render_dsn(&payload).is_none());

        for sender in [
            "not-an-address",
            "sender@@example.test",
            "sender@example.test\r\nX-Injected: yes",
        ] {
            let mut payload = eligible_payload();
            payload.sender_address = sender.to_owned();
            assert!(
                render_dsn(&payload).is_none(),
                "sender should be rejected: {sender:?}"
            );
        }

        let mut payload = eligible_payload();
        payload.recipients = (0..=MAX_DSN_RECIPIENTS)
            .map(|index| DsnRecipientSnapshot {
                recipient: format!("user{index}@example.test"),
                state: if index == 0 {
                    "PERMANENT".to_owned()
                } else {
                    "DELIVERED".to_owned()
                },
                smtp_code: Some(550),
                detail: None,
            })
            .collect();
        assert!(render_dsn(&payload).is_none());

        payload = eligible_payload();
        payload.created_at = "not-a-time".to_owned();
        assert!(render_dsn(&payload).is_none());
        payload = eligible_payload();
        payload.terminal_at = "not-a-time".to_owned();
        assert!(render_dsn(&payload).is_none());
    }
}
