use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use ammonia::clean;
use deadpool_postgres::{
    Config as DatabasePoolConfig, ManagerConfig, Pool, PoolConfig, RecyclingMethod, Runtime,
};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use serde::Serialize;
use tokio::{task::spawn_blocking, time::timeout};
use tokio_postgres::NoTls;

use crate::config::RuntimeConfig;

const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_HEADER_BYTES: usize = 256 * 1024;
const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_RAW_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILENAME_BYTES: usize = 255;

#[derive(Debug)]
pub enum MailboxError {
    Database(String),
    InvalidInput(String),
    InvalidFileName,
    NotFound,
    Io(io::Error),
    TooLarge,
}

impl fmt::Display for MailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) => f.write_str("mailbox backend unavailable"),
            Self::InvalidInput(message) => f.write_str(message),
            Self::InvalidFileName => f.write_str("invalid file name"),
            Self::NotFound => f.write_str("not found"),
            Self::Io(error) => write!(f, "mailbox I/O failed: {error}"),
            Self::TooLarge => f.write_str("message exceeds the configured read limit"),
        }
    }
}

impl std::error::Error for MailboxError {}

impl From<io::Error> for MailboxError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone)]
pub struct MailboxService {
    pool: Pool,
    base_dir: Arc<PathBuf>,
    max_email_size: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailListItem {
    pub file_name: String,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub received_at: String,
    pub starred: bool,
    pub has_attachments: bool,
    pub labels: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_status_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailListPage {
    pub content: Vec<EmailListItem>,
    pub current_page: i32,
    pub page_size: i32,
    pub total_elements: i64,
    pub total_pages: i32,
    pub has_next: bool,
    pub has_previous: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentMeta {
    pub filename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_id: Option<String>,
    pub inline: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailDetail {
    pub subject: Option<String>,
    pub from: Option<String>,
    pub reply_to: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub date: Option<String>,
    pub text: Option<String>,
    pub html: Option<String>,
    #[serde(skip_serializing)]
    pub raw_html: Option<String>,
    pub attachments: Vec<AttachmentMeta>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    pub raw_headers: String,
    pub starred: bool,
    pub labels: Vec<i64>,
}

impl MailboxService {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, MailboxError> {
        let mut pool_config = DatabasePoolConfig::new();
        pool_config.host = Some(config.postgres.host.clone());
        pool_config.port = Some(config.postgres.port);
        pool_config.dbname = Some(config.postgres.database.clone());
        pool_config.user = Some(config.postgres.username.clone());
        pool_config.password = Some(config.postgres.password.clone());
        pool_config.connect_timeout = Some(DATABASE_TIMEOUT);
        pool_config.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        pool_config.pool = Some(PoolConfig::new(config.limits.postgres_pool as usize));
        let pool = pool_config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|error| MailboxError::Database(error.to_string()))?;
        Ok(Self {
            pool,
            base_dir: Arc::new(config.maildir.clone()),
            max_email_size: config.limits.max_email_size_bytes,
        })
    }

    pub async fn list_folder(
        &self,
        mailbox: &str,
        folder: &str,
        page: i32,
        size: i32,
        starred_only: bool,
    ) -> Result<EmailListPage, MailboxError> {
        validate_folder(folder)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let page = page.max(0);
        let size = size.clamp(1, 200);
        let offset = i64::from(page).saturating_mul(i64::from(size));
        let client = self.db().await?;
        let starred_rows = timeout(
            DATABASE_TIMEOUT,
            client.query(
                "SELECT email_file_name FROM starred_email WHERE mailbox_address=$1 AND folder=$2",
                &[&mailbox, &folder],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?;
        let starred = starred_rows
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<HashSet<_>>();
        let total_query = if starred_only {
            "SELECT COUNT(*) FROM email_index e WHERE mailbox_address=$1 AND folder=$2 AND EXISTS (
                SELECT 1 FROM starred_email s WHERE s.mailbox_address=e.mailbox_address
                AND s.folder=e.folder AND s.email_file_name=e.file_name)"
        } else {
            "SELECT COUNT(*) FROM email_index WHERE mailbox_address=$1 AND folder=$2"
        };
        let total: i64 = timeout(
            DATABASE_TIMEOUT,
            client.query_one(total_query, &[&mailbox, &folder]),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?
        .get(0);
        let list_query = if starred_only {
            "SELECT e.file_name, e.subject, e.from_address, e.to_addresses, e.received_at, e.has_attachments
             FROM email_index e WHERE e.mailbox_address=$1 AND e.folder=$2 AND EXISTS (
                SELECT 1 FROM starred_email s WHERE s.mailbox_address=e.mailbox_address
                AND s.folder=e.folder AND s.email_file_name=e.file_name)
             ORDER BY e.received_at DESC OFFSET $3 LIMIT $4"
        } else {
            "SELECT file_name, subject, from_address, to_addresses, received_at, has_attachments
             FROM email_index WHERE mailbox_address=$1 AND folder=$2
             ORDER BY received_at DESC OFFSET $3 LIMIT $4"
        };
        let rows = timeout(
            DATABASE_TIMEOUT,
            client.query(list_query, &[&mailbox, &folder, &offset, &i64::from(size)]),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?;
        let label_rows = timeout(
            DATABASE_TIMEOUT,
            client.query(
                "SELECT email_file_name, label_id FROM email_label_assignment
                 WHERE mailbox_address=$1 AND folder=$2 ORDER BY email_file_name, label_id",
                &[&mailbox, &folder],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?;
        let mut labels = HashMap::<String, Vec<i64>>::new();
        for row in label_rows {
            labels
                .entry(row.get(0))
                .or_default()
                .push(row.get::<_, i64>(1));
        }
        let content = rows
            .into_iter()
            .map(|row| {
                let file_name: String = row.get(0);
                EmailListItem {
                    subject: row.get(1),
                    from: row.get(2),
                    to: parse_to_addresses(row.get(3)),
                    received_at: row
                        .get::<_, chrono::DateTime<chrono::Utc>>(4)
                        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
                    starred: starred.contains(&file_name),
                    has_attachments: row.get(5),
                    labels: labels.remove(&file_name).unwrap_or_default(),
                    file_name,
                    send_status: None,
                    send_status_description: None,
                    retry_count: None,
                    last_error: None,
                }
            })
            .collect::<Vec<_>>();
        let total_pages = if total == 0 {
            0
        } else {
            ((total + i64::from(size) - 1) / i64::from(size)) as i32
        };
        Ok(EmailListPage {
            content,
            current_page: page,
            page_size: size,
            total_elements: total,
            total_pages,
            has_next: page + 1 < total_pages,
            has_previous: page > 0,
        })
    }

    pub async fn read_detail(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<EmailDetail, MailboxError> {
        let path = self.authorized_path(mailbox, folder, file_name).await?;
        let (starred, labels) = self.decorations(mailbox, folder, file_name).await?;
        let max_size = self.max_email_size.clamp(1, MAX_RAW_BYTES);
        let mut detail = spawn_blocking(move || parse_detail(&path, max_size))
            .await
            .map_err(|error| MailboxError::Database(format!("parser task failed: {error}")))??;
        detail.starred = starred;
        detail.labels = labels;
        Ok(detail)
    }

    pub async fn open_raw(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<(tokio::fs::File, u64), MailboxError> {
        let path = self.authorized_path(mailbox, folder, file_name).await?;
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|_| MailboxError::NotFound)?;
        let max_size = self.max_email_size.clamp(1, MAX_RAW_BYTES);
        if metadata.len() > max_size {
            return Err(MailboxError::TooLarge);
        }
        let length = metadata.len();
        let file = tokio::fs::File::open(path)
            .await
            .map_err(MailboxError::Io)?;
        Ok((file, length))
    }

    pub async fn read_headers(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<String, MailboxError> {
        let path = self.authorized_path(mailbox, folder, file_name).await?;
        spawn_blocking(move || extract_headers(&path))
            .await
            .map_err(|error| MailboxError::Database(format!("header task failed: {error}")))?
    }

    async fn authorized_path(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<PathBuf, MailboxError> {
        validate_folder(folder)?;
        validate_filename(file_name)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let client = self.db().await?;
        let row = timeout(
            DATABASE_TIMEOUT,
            client.query_opt(
                "SELECT subdirectory FROM email_index WHERE mailbox_address=$1 AND folder=$2 AND file_name=$3 ORDER BY subdirectory NULLS FIRST LIMIT 1",
                &[&mailbox, &folder, &file_name],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?
        .ok_or(MailboxError::NotFound)?;
        let subdirectory: Option<i32> = row.get(0);
        let base = self
            .base_dir
            .join(sanitize_address_for_path(&mailbox))
            .join(folder);
        let path = match subdirectory.filter(|value| *value > 0) {
            Some(value) => base.join(value.to_string()).join(file_name),
            None => base.join(file_name),
        };
        let normalized_base = tokio::fs::canonicalize(&base)
            .await
            .map_err(|_| MailboxError::NotFound)?;
        let normalized_path = tokio::fs::canonicalize(&path)
            .await
            .map_err(|_| MailboxError::NotFound)?;
        if !normalized_path.starts_with(&normalized_base) {
            return Err(MailboxError::InvalidInput("path traversal detected".into()));
        }
        Ok(normalized_path)
    }

    async fn decorations(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<(bool, Vec<i64>), MailboxError> {
        let mailbox = normalize_mailbox(mailbox)?;
        let client = self.db().await?;
        let starred: bool = timeout(
            DATABASE_TIMEOUT,
            client.query_one(
                "SELECT EXISTS(SELECT 1 FROM starred_email WHERE mailbox_address=$1 AND folder=$2 AND email_file_name=$3)",
                &[&mailbox, &folder, &file_name],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?
        .get(0);
        let labels = timeout(
            DATABASE_TIMEOUT,
            client.query(
                "SELECT label_id FROM email_label_assignment WHERE mailbox_address=$1 AND folder=$2 AND email_file_name=$3 ORDER BY label_id",
                &[&mailbox, &folder, &file_name],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?
        .into_iter()
        .map(|row| row.get(0))
        .collect();
        Ok((starred, labels))
    }

    async fn db(&self) -> Result<deadpool_postgres::Object, MailboxError> {
        timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| MailboxError::Database("pool timeout".into()))?
            .map_err(|error| MailboxError::Database(error.to_string()))
    }
}

fn db_error(error: tokio_postgres::Error) -> MailboxError {
    MailboxError::Database(error.to_string())
}

fn parse_to_addresses(value: Option<String>) -> Vec<String> {
    value
        .and_then(|value| serde_json::from_str::<Vec<String>>(&value).ok())
        .unwrap_or_default()
}

fn normalize_mailbox(value: &str) -> Result<String, MailboxError> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 255
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(MailboxError::InvalidInput("invalid mailbox address".into()));
    }
    Ok(value)
}

fn validate_folder(folder: &str) -> Result<(), MailboxError> {
    if matches!(
        folder.to_ascii_lowercase().as_str(),
        "inbox" | "sent" | "drafts" | "trash" | "spam"
    ) {
        Ok(())
    } else {
        Err(MailboxError::InvalidInput("Invalid folder name".into()))
    }
}

fn validate_filename(file_name: &str) -> Result<(), MailboxError> {
    if file_name.is_empty()
        || file_name.len() > MAX_FILENAME_BYTES
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name.contains("..")
        || !file_name.to_ascii_lowercase().ends_with(".eml")
        || file_name
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        || !file_name
            .chars()
            .all(|ch| ch.is_alphanumeric() || matches!(ch, '.' | '_' | '@' | '-'))
    {
        return Err(MailboxError::InvalidFileName);
    }
    Ok(())
}

fn sanitize_address_for_path(address: &str) -> String {
    let mut output = String::with_capacity(address.len());
    for ch in address.trim().to_ascii_lowercase().chars() {
        if ch.is_control() {
            continue;
        }
        if matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            output.push('_');
        } else {
            output.push(ch);
        }
    }
    if output.is_empty() {
        "unknown".into()
    } else {
        output.replace("..", "__")
    }
}

fn parse_detail(path: &Path, max_size: u64) -> Result<EmailDetail, MailboxError> {
    let metadata = std::fs::metadata(path).map_err(|_| MailboxError::NotFound)?;
    if metadata.len() > max_size {
        return Err(MailboxError::TooLarge);
    }
    let bytes = std::fs::read(path).map_err(MailboxError::Io)?;
    let parser = MessageParser::default()
        .with_minimal_headers()
        .with_message_ids();
    let message = parser.parse(&bytes).ok_or(MailboxError::NotFound)?;
    let to = message
        .to()
        .map(|addresses| addresses.iter().map(display_address).collect())
        .unwrap_or_default();
    let cc = message
        .cc()
        .map(|addresses| addresses.iter().map(display_address).collect())
        .unwrap_or_default();
    let text = message.parts.iter().find_map(|part| match &part.body {
        PartType::Text(value) => Some(truncate_text(value)),
        _ => None,
    });
    let raw_html = message.parts.iter().find_map(|part| match &part.body {
        PartType::Html(value) => Some(truncate_text(value)),
        _ => None,
    });
    let html = raw_html.as_deref().map(clean);
    let attachments = message
        .attachments()
        .map(|part| AttachmentMeta {
            filename: part
                .content_disposition()
                .and_then(|value| value.attribute("filename"))
                .or_else(|| {
                    part.content_type()
                        .and_then(|value| value.attribute("name"))
                })
                .unwrap_or("attachment")
                .to_owned(),
            content_type: part.content_type().map(|value| {
                format!(
                    "{}{}",
                    value.ctype(),
                    value
                        .subtype()
                        .map_or(String::new(), |subtype| format!("/{subtype}"))
                )
            }),
            size: part.len() as u64,
            content_id: part.content_id().map(str::to_owned),
            inline: part
                .content_disposition()
                .is_some_and(|value| value.ctype().eq_ignore_ascii_case("inline")),
        })
        .collect();
    let raw_headers = extract_headers_from_bytes(&bytes);
    Ok(EmailDetail {
        subject: message.subject().map(str::to_owned),
        from: message
            .from()
            .and_then(|value| value.first())
            .map(display_address),
        reply_to: message
            .reply_to()
            .and_then(|value| value.first())
            .map(display_address),
        to,
        cc,
        date: raw_header_value(&raw_headers, "date"),
        text,
        html,
        raw_html,
        attachments,
        message_id: raw_header_value(&raw_headers, "message-id"),
        in_reply_to: raw_header_value(&raw_headers, "in-reply-to"),
        references: raw_header_value(&raw_headers, "references"),
        raw_headers,
        starred: false,
        labels: Vec::new(),
    })
}

fn display_address(address: &mail_parser::Addr<'_>) -> String {
    match (address.name(), address.address.as_deref()) {
        (Some(name), Some(value)) => format!("{name} <{value}>"),
        (_, Some(value)) => value.to_owned(),
        (Some(name), None) => name.to_owned(),
        (None, None) => String::new(),
    }
}

fn truncate_text(value: &str) -> String {
    if value.len() <= MAX_TEXT_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_TEXT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn raw_header_value(headers: &str, wanted: &str) -> Option<String> {
    let normalized = headers.replace("\r\n", "\n");
    let mut value = None::<String>;
    for line in normalized.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(value) = &mut value {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        let Some((name, body)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case(wanted) {
            value = Some(body.trim().to_owned());
        } else if value.is_some() {
            break;
        }
    }
    value
}

fn extract_headers(path: &Path) -> Result<String, MailboxError> {
    let bytes = std::fs::read(path).map_err(MailboxError::Io)?;
    Ok(extract_headers_from_bytes(&bytes))
}

fn extract_headers_from_bytes(bytes: &[u8]) -> String {
    let limit = bytes.len().min(MAX_HEADER_BYTES);
    let bytes = &bytes[..limit];
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
        .unwrap_or(limit);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_validation_rejects_traversal_and_non_eml_names() {
        assert!(validate_filename("safe.eml").is_ok());
        assert!(validate_filename("../safe.eml").is_err());
        assert!(validate_filename("safe.eml/other").is_err());
        assert!(validate_filename("safe.txt").is_err());
        assert!(validate_filename("safe\r\n.eml").is_err());
    }

    #[test]
    fn header_extraction_preserves_crlf_and_is_bounded() {
        let value = extract_headers_from_bytes(b"Subject: test\r\n\r\nbody");
        assert_eq!(value, "Subject: test\r\n\r\n");
        assert!(
            extract_headers_from_bytes(&vec![b'x'; MAX_HEADER_BYTES + 20]).len()
                <= MAX_HEADER_BYTES
        );
    }

    #[test]
    fn address_sanitization_is_lowercase_and_not_a_path() {
        assert_eq!(
            sanitize_address_for_path("QA/../EXAMPLE.TEST"),
            "qa____example.test"
        );
        assert_eq!(sanitize_address_for_path(""), "unknown");
    }
}
