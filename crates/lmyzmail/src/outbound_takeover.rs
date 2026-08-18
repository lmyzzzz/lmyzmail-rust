use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Component, Path, PathBuf},
};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use tokio::{fs::File, io::AsyncReadExt};
use tokio_util::sync::CancellationToken;

use crate::{
    outbound_delivery::{
        DeliveryStateError, LegacyRedisTaskMaterialization, OutboundContentAuthority,
        OutboundContentRoot, PostgresDeliveryState, parse_recipient_roster_json, recipient_domain,
    },
    outbound_queue::{DomainStatus, LegacyOutboundQueue, QueueClaim, QueueError, TaskDetail},
    outbound_smtp::{MessageContentProof, TrustedFileSource},
};

const MAX_SENT_HEADER_BYTES: u64 = 256 * 1024;
const MAX_DOMAIN_ERROR_BYTES: usize = 2_000;

#[derive(Clone)]
pub struct LegacyRedisTakeover {
    queue: LegacyOutboundQueue,
    state: PostgresDeliveryState,
    maildir_base: PathBuf,
    max_message_bytes: u64,
}

#[derive(Debug)]
pub enum LegacyTakeoverError {
    Invalid(&'static str),
    Queue(QueueError),
    DeliveryState(DeliveryStateError),
    Cancelled,
}

impl fmt::Display for LegacyTakeoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Queue(error) => write!(formatter, "legacy Redis takeover queue failed: {error}"),
            Self::DeliveryState(error) => {
                write!(formatter, "legacy Redis takeover database failed: {error}")
            }
            Self::Cancelled => formatter.write_str("legacy Redis takeover was cancelled"),
        }
    }
}

impl std::error::Error for LegacyTakeoverError {}

impl From<QueueError> for LegacyTakeoverError {
    fn from(error: QueueError) -> Self {
        Self::Queue(error)
    }
}

impl From<DeliveryStateError> for LegacyTakeoverError {
    fn from(error: DeliveryStateError) -> Self {
        Self::DeliveryState(error)
    }
}

impl LegacyRedisTakeover {
    pub fn new(
        queue: LegacyOutboundQueue,
        state: PostgresDeliveryState,
        maildir_base: PathBuf,
        max_message_bytes: u64,
    ) -> Result<Self, LegacyTakeoverError> {
        if maildir_base.as_os_str().is_empty() || max_message_bytes == 0 {
            return Err(LegacyTakeoverError::Invalid(
                "legacy Redis takeover configuration is invalid",
            ));
        }
        Ok(Self {
            queue,
            state,
            maildir_base,
            max_message_bytes,
        })
    }

    pub async fn materialize(
        &self,
        claim: &QueueClaim,
        cancellation: &CancellationToken,
    ) -> Result<TaskDetail, LegacyTakeoverError> {
        check_cancellation(cancellation)?;
        let task = claim.task.as_ref().ok_or(LegacyTakeoverError::Invalid(
            "legacy Redis task detail is missing",
        ))?;
        if task.id != claim.task_id {
            return Err(LegacyTakeoverError::Invalid(
                "legacy Redis task ID does not match its queue entry",
            ));
        }
        task.validate()?;

        let recipients = parse_recipient_roster_json(&task.recipients_json)?;
        let domain_rosters = domain_rosters(&recipients)?;
        let expected_domains = domain_rosters.keys().cloned().collect::<BTreeSet<_>>();
        let statuses = self
            .queue
            .read_domain_statuses(claim, &expected_domains)
            .await?;
        validate_domain_rosters(&statuses, &domain_rosters)?;

        let sent_copy = self.resolve_sent_copy(task).await?;
        let (sent_headers, content_proof) =
            read_headers_and_proof(&sent_copy.source, self.max_message_bytes, cancellation).await?;
        let mut replacement = task.clone();
        replacement.message_file_path = Some(sent_copy.path_string);
        replacement.signed_content_base64 = None;
        check_cancellation(cancellation)?;
        let created_at = parse_timestamp(
            &task.created_at,
            "legacy Redis task creation time is invalid",
        )?;
        let next_retry_at = task
            .next_retry_at
            .as_deref()
            .map(|value| parse_timestamp(value, "legacy Redis retry time is invalid"))
            .transpose()?
            .unwrap_or_else(Utc::now);
        let (sent_domains, failed_domains) = projected_domains(&statuses);
        let input = LegacyRedisTaskMaterialization {
            task_id: task.id,
            sender_address: task.sender_address.clone(),
            recipients_json: task.recipients_json.clone(),
            subject: task.subject.clone(),
            message_id: task.message_id.clone(),
            sent_file_name: task
                .sent_file_name
                .clone()
                .ok_or(LegacyTakeoverError::Invalid(
                    "legacy Redis Sent filename is missing",
                ))?,
            sent_subdirectory: task.sent_subdirectory.ok_or(LegacyTakeoverError::Invalid(
                "legacy Redis Sent subdirectory is missing",
            ))?,
            retry_count: task.retry_count,
            max_retries: task.max_retries,
            next_retry_at,
            last_error: task.last_error.clone(),
            sent_domains,
            failed_domains,
            created_at,
            mail_size_bytes: sent_copy.size_bytes,
            has_attachments: header_has_attachment(&sent_headers),
            to_addresses_json: header_to_addresses(&sent_headers),
            content_authority: OutboundContentAuthority {
                task_id: task.id,
                source_root: OutboundContentRoot::Maildir,
                relative_path: sent_copy.relative_path,
                content_size: content_proof.size,
                content_sha256: content_proof.sha256,
            },
        };
        self.state
            .materialize_legacy_redis_task(&input, Utc::now())
            .await?;
        match self
            .queue
            .replace_claimed_task_source(claim, &replacement)
            .await
        {
            Ok(()) => {}
            Err(QueueError::OutcomeUnknown) => {
                if self.queue.read_claimed_task(claim).await? != replacement {
                    return Err(QueueError::OutcomeUnknown.into());
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(replacement)
    }

    async fn resolve_sent_copy(&self, task: &TaskDetail) -> Result<SentCopy, LegacyTakeoverError> {
        let relative = legacy_sent_relative_path(task)?;
        let source = TrustedFileSource::new(&self.maildir_base, &relative)
            .map_err(|_| LegacyTakeoverError::Invalid("legacy Redis Sent copy is unavailable"))?;
        if source.initial_size() == 0 || source.initial_size() > self.max_message_bytes {
            return Err(LegacyTakeoverError::Invalid(
                "legacy Redis Sent copy violates the message size budget",
            ));
        }
        let path_string = source
            .compatibility_path()
            .to_str()
            .map(str::to_owned)
            .ok_or(LegacyTakeoverError::Invalid(
                "legacy Redis Sent copy path is not UTF-8",
            ))?;
        let size_bytes = i64::try_from(source.initial_size()).map_err(|_| {
            LegacyTakeoverError::Invalid("legacy Redis Sent copy violates the message size budget")
        })?;
        Ok(SentCopy {
            source,
            path_string,
            relative_path: relative.to_str().map(str::to_owned).ok_or(
                LegacyTakeoverError::Invalid("legacy Redis Sent copy relative path is not UTF-8"),
            )?,
            size_bytes,
        })
    }
}

pub(crate) fn legacy_sent_relative_path(task: &TaskDetail) -> Result<PathBuf, LegacyTakeoverError> {
    let file_name = task
        .sent_file_name
        .as_deref()
        .ok_or(LegacyTakeoverError::Invalid(
            "legacy Redis Sent filename is missing",
        ))?;
    validate_file_name(file_name)?;
    let subdirectory =
        task.sent_subdirectory
            .filter(|value| *value > 0)
            .ok_or(LegacyTakeoverError::Invalid(
                "legacy Redis Sent subdirectory is invalid",
            ))?;
    let address = java_maildir_address(&task.sender_address);
    if address == "unknown" {
        return Err(LegacyTakeoverError::Invalid(
            "legacy Redis sender cannot identify a Maildir",
        ));
    }
    Ok(PathBuf::from(address)
        .join("sent")
        .join(subdirectory.to_string())
        .join(file_name))
}

struct SentCopy {
    source: TrustedFileSource,
    path_string: String,
    relative_path: String,
    size_bytes: i64,
}

fn check_cancellation(cancellation: &CancellationToken) -> Result<(), LegacyTakeoverError> {
    if cancellation.is_cancelled() {
        Err(LegacyTakeoverError::Cancelled)
    } else {
        Ok(())
    }
}

fn domain_rosters(
    recipients: &[String],
) -> Result<BTreeMap<String, Vec<String>>, LegacyTakeoverError> {
    let mut rosters = BTreeMap::<String, Vec<String>>::new();
    for recipient in recipients {
        rosters
            .entry(recipient_domain(recipient)?)
            .or_default()
            .push(recipient.clone());
    }
    Ok(rosters)
}

fn validate_domain_rosters(
    statuses: &BTreeMap<String, DomainStatus>,
    rosters: &BTreeMap<String, Vec<String>>,
) -> Result<(), LegacyTakeoverError> {
    if statuses.len() != rosters.len()
        || statuses.iter().any(|(domain, status)| {
            status.domain != *domain || rosters.get(domain) != Some(&status.recipients)
        })
    {
        return Err(LegacyTakeoverError::Invalid(
            "legacy Redis domain detail does not match the recipient roster",
        ));
    }
    Ok(())
}

fn projected_domains(
    statuses: &BTreeMap<String, DomainStatus>,
) -> (Vec<String>, BTreeMap<String, String>) {
    let mut sent = Vec::new();
    let mut failed = BTreeMap::new();
    for (domain, status) in statuses {
        match status.status.as_str() {
            "SENT" => sent.push(domain.clone()),
            "FAILED" => {
                failed.insert(
                    domain.clone(),
                    bounded_error(
                        status
                            .error
                            .as_deref()
                            .unwrap_or("legacy Redis delivery failure"),
                    ),
                );
            }
            _ => {}
        }
    }
    (sent, failed)
}

fn validate_file_name(file_name: &str) -> Result<(), LegacyTakeoverError> {
    let mut components = Path::new(file_name).components();
    let valid = matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && !file_name.contains('\\')
        && file_name.chars().count() <= 255
        && !file_name.chars().any(char::is_control);
    if valid {
        Ok(())
    } else {
        Err(LegacyTakeoverError::Invalid(
            "legacy Redis Sent filename is invalid",
        ))
    }
}

fn java_maildir_address(address: &str) -> String {
    let mut output = String::with_capacity(address.len());
    for character in address.trim().to_lowercase().chars() {
        if character.is_control() {
            continue;
        }
        if matches!(
            character,
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
        ) {
            output.push('_');
        } else {
            output.push(character);
        }
    }
    if output.trim().is_empty() {
        return "unknown".into();
    }
    if output.starts_with('.') {
        output.replace_range(..1, "_");
    }
    if output.ends_with('.') {
        output.pop();
        output.push('_');
    }
    if matches!(output.as_str(), "." | "..") {
        "unknown".into()
    } else {
        output
    }
}

async fn read_headers_and_proof(
    source: &TrustedFileSource,
    maximum: u64,
    cancellation: &CancellationToken,
) -> Result<(Vec<u8>, MessageContentProof), LegacyTakeoverError> {
    let mut file = source
        .open_initial(maximum)
        .map(File::from_std)
        .map_err(|_| LegacyTakeoverError::Invalid("legacy Redis Sent copy is unavailable"))?;
    source
        .validate_opened_metadata(
            &file.metadata().await.map_err(|_| {
                LegacyTakeoverError::Invalid("legacy Redis Sent copy is unavailable")
            })?,
            maximum,
        )
        .map_err(|_| LegacyTakeoverError::Invalid("legacy Redis Sent copy is unavailable"))?;
    let mut bytes = Vec::new();
    let mut digest = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(LegacyTakeoverError::Cancelled),
            result = file.read(&mut buffer) => result
                .map_err(|_| LegacyTakeoverError::Invalid("legacy Redis Sent copy is unavailable"))?,
        };
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(read as u64)
            .ok_or(LegacyTakeoverError::Invalid(
                "legacy Redis Sent copy violates the message size budget",
            ))?;
        if observed > maximum {
            return Err(LegacyTakeoverError::Invalid(
                "legacy Redis Sent copy violates the message size budget",
            ));
        }
        digest.update(&buffer[..read]);
        let remaining = (MAX_SENT_HEADER_BYTES as usize).saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..read.min(remaining)]);
    }
    if observed != source.initial_size() {
        return Err(LegacyTakeoverError::Invalid(
            "legacy Redis Sent copy changed while hashing",
        ));
    }
    source
        .validate_opened_metadata(
            &file.metadata().await.map_err(|_| {
                LegacyTakeoverError::Invalid("legacy Redis Sent copy is unavailable")
            })?,
            maximum,
        )
        .map_err(|_| {
            LegacyTakeoverError::Invalid("legacy Redis Sent copy changed while hashing")
        })?;
    let end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| index + 2)
        })
        .unwrap_or(bytes.len());
    bytes.truncate(end);
    Ok((
        bytes,
        MessageContentProof::new(observed, digest.finalize().into()),
    ))
}

fn unfolded_header(headers: &[u8], wanted: &str) -> Option<String> {
    let text = String::from_utf8_lossy(headers).replace("\r\n", "\n");
    let mut fields = Vec::<String>::new();
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            if let Some(previous) = fields.last_mut() {
                previous.push(' ');
                previous.push_str(line.trim());
            }
        } else {
            fields.push(line.to_owned());
        }
    }
    fields.into_iter().find_map(|field| {
        let (name, value) = field.split_once(':')?;
        name.eq_ignore_ascii_case(wanted)
            .then(|| value.trim().to_owned())
    })
}

fn header_to_addresses(headers: &[u8]) -> String {
    let Some(value) = unfolded_header(headers, "to") else {
        return "[]".into();
    };
    let addresses = value
        .split(',')
        .filter_map(|part| {
            let trimmed = part.trim();
            let address = trimmed
                .rsplit_once('<')
                .and_then(|(_, rest)| rest.strip_suffix('>'))
                .unwrap_or(trimmed)
                .trim();
            (!address.is_empty()).then(|| address.to_lowercase())
        })
        .collect::<Vec<_>>();
    let json = serde_json::to_string(&addresses).unwrap_or_else(|_| "[]".into());
    truncate_chars(&json, 2_000)
}

fn header_has_attachment(headers: &[u8]) -> bool {
    unfolded_header(headers, "content-disposition").is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("attachment") || value.contains("inline")
    }) || unfolded_header(headers, "content-type").is_some_and(|value| {
        let mime = value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        !mime.is_empty()
            && !mime.starts_with("text/plain")
            && !mime.starts_with("text/html")
            && !mime.starts_with("multipart/")
    })
}

fn parse_timestamp(
    value: &str,
    message: &'static str,
) -> Result<DateTime<Utc>, LegacyTakeoverError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| LegacyTakeoverError::Invalid(message))
}

fn bounded_error(value: &str) -> String {
    if value.len() <= MAX_DOMAIN_ERROR_BYTES {
        return value.to_owned();
    }
    let mut boundary = MAX_DOMAIN_ERROR_BYTES - 3;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}...", &value[..boundary])
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_maildir_paths_and_headers_are_compatible_and_bounded() {
        assert_eq!(
            java_maildir_address(" Alice@Example.Test "),
            "alice@example.test"
        );
        assert_eq!(
            java_maildir_address("../unsafe@example.test"),
            "_./unsafe@example.test".replace('/', "_")
        );
        assert!(validate_file_name("1700000000.eml").is_ok());
        assert!(validate_file_name("../message.eml").is_err());
        assert!(validate_file_name("nested/message.eml").is_err());

        let headers = b"To: User <USER@Example.Test>\r\n\t, second@example.test\r\nContent-Type: application/pdf\r\n\r\n";
        assert_eq!(
            header_to_addresses(headers),
            r#"["user@example.test","second@example.test"]"#
        );
        assert!(header_has_attachment(headers));
        assert_eq!(truncate_chars(&"x".repeat(2_001), 2_000).len(), 2_000);
    }
}
