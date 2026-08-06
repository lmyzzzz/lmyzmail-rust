use std::{collections::BTreeSet, fmt, sync::Arc, time::Duration};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use deadpool_postgres::Pool;
use getrandom::fill as fill_random;
use idna::domain_to_ascii_strict;
use mail_parser::MessageParser;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use crate::{
    auth::{AuthError, AuthService, CredentialOutcome},
    config::RuntimeConfig,
};

const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const DEFAULT_MAX_PENDING_TASKS: i64 = 10_000;
const DEFAULT_MAX_RETRIES: i32 = 5;
const DEFAULT_MAX_EMAILS_PER_ACCOUNT: i64 = 100;
const DEFAULT_RATE_WINDOW_HOURS: i64 = 3;
const MAX_RECIPIENTS: usize = 1_000;
const MAX_ADDRESS_BYTES: usize = 254;
const MAX_SUBJECT_BYTES: usize = 1_000;

#[derive(Debug)]
pub enum OutboundError {
    Database(String),
    InvalidInput(&'static str),
    InvalidCredentials,
    QueueFull,
    RateLimited { remaining: i64 },
    SynchronousUnsupported,
    Unavailable,
}

impl fmt::Display for OutboundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) | Self::Unavailable => {
                formatter.write_str("outbound queue unavailable")
            }
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::InvalidCredentials => formatter.write_str("Invalid credentials"),
            Self::QueueFull => formatter.write_str("Outbound queue is full"),
            Self::RateLimited { remaining } => {
                write!(
                    formatter,
                    "Rate limit exceeded. Remaining quota: {remaining}"
                )
            }
            Self::SynchronousUnsupported => {
                formatter.write_str("Synchronous sending is not available")
            }
        }
    }
}

impl std::error::Error for OutboundError {}

#[derive(Clone)]
pub struct OutboundService {
    pool: Pool,
    domain: Arc<str>,
    max_pending_tasks: i64,
    max_retries: i32,
    max_emails_per_account: i64,
    rate_window: ChronoDuration,
    max_email_size_bytes: u64,
    max_attachment_size_bytes: u64,
    max_total_attachments_size_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    pub from: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub subject: Option<String>,
    pub text: Option<String>,
    pub html: Option<String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentInput>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    #[serde(rename = "async")]
    pub asynchronous: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentInput {
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub content_base64: Option<String>,
    #[serde(default)]
    pub inline: bool,
    pub content_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueResponse {
    pub queued: bool,
    pub queue_id: i64,
    pub message_id: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiStatusResponse {
    pub queue_id: i64,
    pub message_id: Option<String>,
    pub status: String,
    pub retry_count: i32,
    pub max_retries: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebStatusResponse {
    pub queue_id: i64,
    pub message_id: Option<String>,
    pub status: String,
    pub aggregated_status: String,
    pub status_description: String,
    pub retry_count: i32,
    pub max_retries: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_file_name: Option<String>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaResponse<'a> {
    pub address: &'a str,
    pub remaining_quota: i64,
}

struct StatusRow {
    queue_id: i64,
    message_id: Option<String>,
    status: String,
    retry_count: i32,
    max_retries: i32,
    last_error: Option<String>,
    sent_file_name: Option<String>,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    next_retry_at: Option<DateTime<Utc>>,
}

impl OutboundService {
    pub fn from_config(config: &RuntimeConfig, pool: Pool) -> Result<Self, OutboundError> {
        let max_pending_tasks = parse_bounded_i64(
            config,
            "lmyzmail.outbound.max-pending-tasks",
            "botmail.outbound.max-pending-tasks",
            DEFAULT_MAX_PENDING_TASKS,
            1,
            1_000_000,
        )?;
        let max_retries = parse_bounded_i64(
            config,
            "lmyzmail.outbound.retry-count",
            "botmail.outbound.retry-count",
            i64::from(DEFAULT_MAX_RETRIES),
            0,
            1_000,
        )? as i32;
        let max_emails_per_account = parse_bounded_i64(
            config,
            "lmyzmail.rate-limit.max-emails-per-account",
            "botmail.rate-limit.max-emails-per-account",
            DEFAULT_MAX_EMAILS_PER_ACCOUNT,
            1,
            1_000_000,
        )?;
        let rate_window_hours = parse_bounded_i64(
            config,
            "lmyzmail.rate-limit.email-rate-window-hours",
            "botmail.rate-limit.email-rate-window-hours",
            DEFAULT_RATE_WINDOW_HOURS,
            1,
            24 * 365,
        )?;
        Ok(Self {
            pool,
            domain: Arc::from(config.domain.as_str()),
            max_pending_tasks,
            max_retries,
            max_emails_per_account,
            rate_window: ChronoDuration::hours(rate_window_hours),
            max_email_size_bytes: config.limits.max_email_size_bytes,
            max_attachment_size_bytes: config.limits.max_attachment_size_bytes,
            max_total_attachments_size_bytes: config.limits.max_total_attachments_size_bytes,
        })
    }

    pub async fn enqueue(
        &self,
        request: SendRequest,
        credentials: Option<(&AuthService, &str)>,
    ) -> Result<QueueResponse, OutboundError> {
        if request.asynchronous == Some(false) {
            return Err(OutboundError::SynchronousUnsupported);
        }
        let sender = normalize_address(
            request
                .from
                .as_deref()
                .ok_or(OutboundError::InvalidInput("from_required"))?,
        )?;
        if sender.rsplit_once('@').map(|(_, value)| value) != Some(self.domain.as_ref()) {
            return Err(OutboundError::InvalidInput("sending_not_allowed"));
        }
        if credentials.is_some()
            && request
                .password
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(OutboundError::InvalidInput("password_required"));
        }
        self.validate_sizes(&request)?;
        let recipients = ValidatedRecipients::new(request.to, request.cc, request.bcc)?;
        let subject = sanitize_subject(
            request
                .subject
                .as_deref()
                .ok_or(OutboundError::InvalidInput("subject_required"))?,
        )?;
        if request
            .text
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
            && request
                .html
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(OutboundError::InvalidInput("body_required"));
        }
        let recipients_json =
            serde_json::to_string(&recipients).map_err(|_| OutboundError::Unavailable)?;
        let attachments_json =
            serde_json::to_string(&request.attachments).map_err(|_| OutboundError::Unavailable)?;
        if let Some((auth, client_ip)) = credentials {
            let password = request.password.as_deref().unwrap_or_default();
            match auth
                .verify_mailbox_credentials(&sender, password, client_ip)
                .await
                .map_err(map_auth_error)?
            {
                CredentialOutcome::Valid { .. } => {}
                CredentialOutcome::Invalid { .. } => {
                    return Err(OutboundError::InvalidCredentials);
                }
            }
        }
        let now = Utc::now();
        let message_id = new_message_id(self.domain.as_ref())?;
        let next_retry_at = now;
        let mut client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(|error| OutboundError::Database(error.to_string()))?;
        let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(db_error)?;
        for lock_name in ["lmyzmail:outbound:queue", sender.as_str()] {
            timeout(
                DATABASE_TIMEOUT,
                transaction.query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
                    &[&lock_name],
                ),
            )
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(db_error)?;
        }
        let pending: i64 = timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "SELECT count(*) FROM outbound_mail_queue WHERE status IN ('PENDING','PROCESSING')",
                &[],
            ),
        )
        .await
        .map_err(|_| OutboundError::Unavailable)?
        .map_err(db_error)?
        .get(0);
        if pending >= self.max_pending_tasks {
            return Err(OutboundError::QueueFull);
        }
        let window_start = now - self.rate_window;
        let used: i64 = timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "SELECT count(*) FROM outbound_mail_queue WHERE sender_address=$1 AND created_at >= $2",
                &[&sender, &window_start],
            ),
        )
        .await
        .map_err(|_| OutboundError::Unavailable)?
        .map_err(db_error)?
        .get(0);
        if used >= self.max_emails_per_account {
            return Err(OutboundError::RateLimited { remaining: 0 });
        }
        let row = timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "INSERT INTO outbound_mail_queue
                 (sender_address,recipients_json,subject,body_text,body_html,attachments_json,
                  message_id,sent_file_name,sent_subdirectory,status,retry_count,max_retries,
                  next_retry_at,last_error,sent_domains_json,failed_domains_json,created_at,
                  updated_at,sent_at,processing_started_at,processor_id)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,NULL,'PENDING',0,$8,$9,NULL,'[]','{}',$10,$10,NULL,NULL,NULL)
                 RETURNING id",
                &[
                    &sender,
                    &recipients_json,
                    &subject,
                    &request.text,
                    &request.html,
                    &attachments_json,
                    &message_id,
                    &self.max_retries,
                    &next_retry_at,
                    &now,
                ],
            ),
        )
        .await
        .map_err(|_| OutboundError::Unavailable)?
        .map_err(db_error)?;
        let queue_id: i64 = row.get(0);
        timeout(DATABASE_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(db_error)?;
        Ok(QueueResponse {
            queued: true,
            queue_id,
            message_id,
            status: "PENDING",
            error: None,
        })
    }

    pub async fn api_status_by_id(
        &self,
        queue_id: i64,
    ) -> Result<Option<ApiStatusResponse>, OutboundError> {
        Ok(self
            .status_row("id=$1", &queue_id, None)
            .await?
            .map(StatusRow::into_api))
    }

    pub async fn api_status_by_message_id(
        &self,
        message_id: &str,
    ) -> Result<Option<ApiStatusResponse>, OutboundError> {
        if message_id.is_empty() || message_id.len() > 255 {
            return Ok(None);
        }
        Ok(self
            .status_row(
                "message_id=$1 AND status NOT IN ('PENDING','PROCESSING')",
                &message_id,
                None,
            )
            .await?
            .map(StatusRow::into_api))
    }

    pub async fn web_status_by_id(
        &self,
        queue_id: i64,
        sender: &str,
    ) -> Result<Option<WebStatusResponse>, OutboundError> {
        Ok(self
            .status_row("id=$1", &queue_id, Some(sender))
            .await?
            .map(StatusRow::into_web))
    }

    pub async fn web_status_by_file(
        &self,
        file_name: &str,
        sender: &str,
    ) -> Result<Option<WebStatusResponse>, OutboundError> {
        if file_name.is_empty() || file_name.len() > 255 {
            return Ok(None);
        }
        Ok(self
            .status_row("sent_file_name=$1", &file_name, Some(sender))
            .await?
            .map(StatusRow::into_web))
    }

    pub async fn remaining_quota(&self, sender: &str) -> Result<i64, OutboundError> {
        let sender = normalize_address(sender)?;
        let client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(|error| OutboundError::Database(error.to_string()))?;
        let window_start = Utc::now() - self.rate_window;
        let used: i64 = timeout(
            DATABASE_TIMEOUT,
            client.query_one(
                "SELECT count(*) FROM outbound_mail_queue WHERE sender_address=$1 AND created_at >= $2",
                &[&sender, &window_start],
            ),
        )
        .await
        .map_err(|_| OutboundError::Unavailable)?
        .map_err(db_error)?
        .get(0);
        Ok((self.max_emails_per_account - used).max(0))
    }

    async fn status_row<T: tokio_postgres::types::ToSql + Sync>(
        &self,
        predicate: &str,
        value: &T,
        sender: Option<&str>,
    ) -> Result<Option<StatusRow>, OutboundError> {
        let client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(|error| OutboundError::Database(error.to_string()))?;
        let query = if sender.is_some() {
            format!(
                "SELECT id,message_id,status,retry_count,max_retries,last_error,sent_file_name,
                 created_at,sent_at,next_retry_at FROM outbound_mail_queue
                 WHERE {predicate} AND lower(sender_address)=lower($2)"
            )
        } else {
            format!(
                "SELECT id,message_id,status,retry_count,max_retries,last_error,sent_file_name,
                 created_at,sent_at,next_retry_at FROM outbound_mail_queue WHERE {predicate}"
            )
        };
        let row = match sender {
            Some(sender) => timeout(
                DATABASE_TIMEOUT,
                client.query_opt(&query, &[value, &sender]),
            )
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(db_error)?,
            None => timeout(DATABASE_TIMEOUT, client.query_opt(&query, &[value]))
                .await
                .map_err(|_| OutboundError::Unavailable)?
                .map_err(db_error)?,
        };
        Ok(row.map(|row| StatusRow {
            queue_id: row.get(0),
            message_id: row.get(1),
            status: row.get(2),
            retry_count: row.get(3),
            max_retries: row.get(4),
            last_error: row.get(5),
            sent_file_name: row.get(6),
            created_at: row.get(7),
            sent_at: row.get(8),
            next_retry_at: row.get(9),
        }))
    }

    fn validate_sizes(&self, request: &SendRequest) -> Result<(), OutboundError> {
        let mut total = 0_u64;
        for attachment in &request.attachments {
            let Some(content) = attachment.content_base64.as_deref() else {
                continue;
            };
            let size = decoded_base64_size(content)?;
            if size > self.max_attachment_size_bytes {
                return Err(OutboundError::InvalidInput("attachment_too_large"));
            }
            total = total
                .checked_add(size)
                .ok_or(OutboundError::InvalidInput("attachments_too_large"))?;
        }
        if total > self.max_total_attachments_size_bytes {
            return Err(OutboundError::InvalidInput("attachments_too_large"));
        }
        let estimated = request.text.as_ref().map_or(0, String::len) as u64
            + request.html.as_ref().map_or(0, String::len) as u64
            + total.saturating_mul(4).div_ceil(3)
            + 4_096;
        if estimated > self.max_email_size_bytes {
            return Err(OutboundError::InvalidInput("email_too_large"));
        }
        Ok(())
    }
}

impl StatusRow {
    fn into_api(self) -> ApiStatusResponse {
        let next_retry_at = visible_next_retry(&self);
        ApiStatusResponse {
            queue_id: self.queue_id,
            message_id: self.message_id,
            status: self.status,
            retry_count: self.retry_count,
            max_retries: self.max_retries,
            last_error: self.last_error,
            created_at: instant(self.created_at),
            sent_at: self.sent_at.map(instant),
            next_retry_at,
        }
    }

    fn into_web(self) -> WebStatusResponse {
        let next_retry_at = visible_next_retry(&self);
        let status_description = match self.status.as_str() {
            "PENDING" if self.retry_count > 0 => {
                format!("等待重试 (第 {} 次)", self.retry_count)
            }
            "PENDING" => "等待发送".to_owned(),
            "PROCESSING" => "正在发送...".to_owned(),
            "SENT" => "发送成功".to_owned(),
            "PARTIAL_SUCCESS" => "部分发送成功".to_owned(),
            "FAILED" => "发送失败".to_owned(),
            "CANCELLED" => "已取消".to_owned(),
            value => value.to_owned(),
        };
        WebStatusResponse {
            queue_id: self.queue_id,
            message_id: self.message_id,
            aggregated_status: self.status.clone(),
            status: self.status,
            status_description,
            retry_count: self.retry_count,
            max_retries: self.max_retries,
            last_error: self.last_error,
            sent_file_name: self.sent_file_name,
            created_at: instant(self.created_at),
            sent_at: self.sent_at.map(instant),
            next_retry_at,
        }
    }
}

fn visible_next_retry(row: &StatusRow) -> Option<String> {
    if row.status == "PENDING" && row.retry_count == 0 {
        None
    } else {
        row.next_retry_at.map(instant)
    }
}

#[derive(Serialize)]
struct ValidatedRecipients {
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
}

impl ValidatedRecipients {
    fn new(to: Vec<String>, cc: Vec<String>, bcc: Vec<String>) -> Result<Self, OutboundError> {
        if to.is_empty() && cc.is_empty() && bcc.is_empty() {
            return Err(OutboundError::InvalidInput("to_required"));
        }
        if to.len().saturating_add(cc.len()).saturating_add(bcc.len()) > MAX_RECIPIENTS {
            return Err(OutboundError::InvalidInput("too_many_recipients"));
        }
        let mut unique = BTreeSet::new();
        let validate = |values: Vec<String>,
                        unique: &mut BTreeSet<String>|
         -> Result<Vec<String>, OutboundError> {
            values
                .into_iter()
                .map(|value| {
                    let normalized = normalize_address(&value)?;
                    if !unique.insert(normalized.clone()) {
                        return Err(OutboundError::InvalidInput("duplicate_recipient"));
                    }
                    Ok(normalized)
                })
                .collect()
        };
        Ok(Self {
            to: validate(to, &mut unique)?,
            cc: validate(cc, &mut unique)?,
            bcc: validate(bcc, &mut unique)?,
        })
    }
}

fn normalize_address(value: &str) -> Result<String, OutboundError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_ADDRESS_BYTES || value.chars().any(char::is_control) {
        return Err(OutboundError::InvalidInput("invalid_address"));
    }
    let synthetic = format!("From: {value}\r\n\r\n");
    let message = MessageParser::default()
        .parse(synthetic.as_bytes())
        .ok_or(OutboundError::InvalidInput("invalid_address"))?;
    let addresses = message
        .from()
        .ok_or(OutboundError::InvalidInput("invalid_address"))?;
    let mut addresses = addresses.iter();
    let address = addresses
        .next()
        .and_then(|address| address.address())
        .ok_or(OutboundError::InvalidInput("invalid_address"))?;
    if addresses.next().is_some() || address.len() > MAX_ADDRESS_BYTES {
        return Err(OutboundError::InvalidInput("invalid_address"));
    }
    let (local, domain) = address
        .rsplit_once('@')
        .ok_or(OutboundError::InvalidInput("invalid_address"))?;
    if local.is_empty()
        || domain.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.chars().all(valid_local_character)
    {
        return Err(OutboundError::InvalidInput("invalid_address"));
    }
    domain_to_ascii_strict(domain).map_err(|_| OutboundError::InvalidInput("invalid_address"))?;
    if address.is_ascii() {
        Ok(address.to_ascii_lowercase())
    } else {
        Ok(format!("{local}@{}", domain.to_lowercase()))
    }
}

fn valid_local_character(character: char) -> bool {
    if character.is_ascii() {
        character.is_ascii_alphanumeric() || ".!#$%&'*+/=?^_`{|}~-".contains(character)
    } else {
        !character.is_control() && !character.is_whitespace()
    }
}

fn sanitize_subject(value: &str) -> Result<String, OutboundError> {
    let value = value.replace(['\r', '\n'], " ").trim().to_owned();
    if value.is_empty() {
        return Err(OutboundError::InvalidInput("subject_required"));
    }
    if value.len() > MAX_SUBJECT_BYTES {
        return Err(OutboundError::InvalidInput("subject_too_long"));
    }
    Ok(value)
}

fn decoded_base64_size(value: &str) -> Result<u64, OutboundError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Ok(0);
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(OutboundError::InvalidInput("invalid_attachment"));
    }
    let (prefix, final_quantum) = bytes.split_at(bytes.len() - 4);
    if !prefix.iter().all(|byte| is_base64_symbol(*byte)) {
        return Err(OutboundError::InvalidInput("invalid_attachment"));
    }
    let padding = match final_quantum {
        [a, b, c, d] if [*a, *b, *c, *d].into_iter().all(is_base64_symbol) => 0,
        [a, b, c, b'=']
            if [*a, *b, *c].into_iter().all(is_base64_symbol)
                && base64_value(*c).is_some_and(|value| value & 0b11 == 0) =>
        {
            1
        }
        [a, b, b'=', b'=']
            if [*a, *b].into_iter().all(is_base64_symbol)
                && base64_value(*b).is_some_and(|value| value & 0b1111 == 0) =>
        {
            2
        }
        _ => return Err(OutboundError::InvalidInput("invalid_attachment")),
    };
    Ok((bytes.len() as u64 / 4) * 3 - padding)
}

fn is_base64_symbol(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn new_message_id(domain: &str) -> Result<String, OutboundError> {
    let mut bytes = [0_u8; 16];
    fill_random(&mut bytes).map_err(|_| OutboundError::Unavailable)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "<{:08x}-{:04x}-{:04x}-{:04x}-{:012x}@{}>",
        u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
        u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
        u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
        u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ]),
        domain
    ))
}

fn instant(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

fn parse_bounded_i64(
    config: &RuntimeConfig,
    new_key: &str,
    old_key: &str,
    default: i64,
    minimum: i64,
    maximum: i64,
) -> Result<i64, OutboundError> {
    let value = config
        .preferred_value(new_key, old_key)
        .map(str::parse)
        .transpose()
        .map_err(|_| OutboundError::InvalidInput("invalid_outbound_configuration"))?
        .unwrap_or(default);
    if !(minimum..=maximum).contains(&value) {
        return Err(OutboundError::InvalidInput(
            "invalid_outbound_configuration",
        ));
    }
    Ok(value)
}

fn db_error(error: tokio_postgres::Error) -> OutboundError {
    OutboundError::Database(error.to_string())
}

fn map_auth_error(error: AuthError) -> OutboundError {
    match error {
        AuthError::Database(message) => OutboundError::Database(message),
        AuthError::InvalidInput(_) | AuthError::Unavailable => OutboundError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipients_are_normalized_bounded_and_unique() {
        let recipients = ValidatedRecipients::new(
            vec![" A@Example.Test ".into()],
            vec!["b@example.test".into()],
            vec![],
        )
        .unwrap();
        assert_eq!(recipients.to, ["a@example.test"]);
        assert!(
            ValidatedRecipients::new(
                vec!["a@example.test".into()],
                vec!["A@example.test".into()],
                vec![]
            )
            .is_err()
        );
    }

    #[test]
    fn attachment_size_rejects_malformed_padding() {
        assert_eq!(decoded_base64_size("").unwrap(), 0);
        assert_eq!(decoded_base64_size("YWJjZA==").unwrap(), 4);
        assert_eq!(decoded_base64_size("YWJj").unwrap(), 3);
        assert!(decoded_base64_size("abc").is_err());
        assert!(decoded_base64_size("a===").is_err());
        assert!(decoded_base64_size("AA=A").is_err());
        assert!(decoded_base64_size("====").is_err());
        assert!(decoded_base64_size("YW=JjA==").is_err());
        assert!(decoded_base64_size("AB==").is_err());
        assert!(decoded_base64_size("AAB=").is_err());
    }

    #[test]
    fn addresses_use_structural_and_strict_domain_validation() {
        assert_eq!(
            normalize_address("Display Name <A@Example.Test>").unwrap(),
            "a@example.test"
        );
        assert_eq!(
            normalize_address("用戶@例子.测试").unwrap(),
            "用戶@例子.测试"
        );
        for invalid in [
            "a@-example.test",
            "a@example-.test",
            "a@example/test",
            "a<>@example.test",
            "a@example.test, b@example.test",
            "a b@example.test",
            "a@example.test trailing",
            "prefix a@example.test",
        ] {
            assert!(normalize_address(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(normalize_address(&format!("{}@example.test", "a".repeat(65))).is_err());
    }

    #[test]
    fn generated_message_id_is_uuid_shaped_and_domain_scoped() {
        let value = new_message_id("example.test").unwrap();
        assert!(value.starts_with('<'));
        assert!(value.ends_with("@example.test>"));
        assert_eq!(value.len(), 51);
    }
}
