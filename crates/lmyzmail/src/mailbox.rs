use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    fmt,
    future::Future,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use ammonia::clean;
use deadpool_postgres::Pool;
use getrandom::fill as fill_random;
use mail_parser::{MessageParser, MimeHeaders, PartType};
use serde::Serialize;
use tokio::{
    task::spawn_blocking,
    time::{Instant, timeout, timeout_at},
};
use tokio_postgres::IsolationLevel;
use tokio_util::sync::CancellationToken;

use crate::{
    config::RuntimeConfig,
    durability::{fsync, sync_all},
};

const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_HEADER_BYTES: usize = 256 * 1024;
const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_RAW_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_API_RAW_BYTES: u64 = 32 * 1024;
const MAX_FILENAME_BYTES: usize = 255;
const LEGACY_MAILBOX_OWNERSHIP_PAGE_ROWS: i64 = 256;
const MAILBOX_PATH_CHUNK_BYTES: usize = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupDeadline {
    PerOperation(Duration),
    Overall(Instant),
}

impl CleanupDeadline {
    fn operation_deadline(self, now: Instant) -> Instant {
        match self {
            Self::PerOperation(duration) => now + duration,
            Self::Overall(deadline) => deadline,
        }
    }

    fn commit_attempt_deadline(self, now: Instant) -> Instant {
        let operation_deadline = self.operation_deadline(now);
        let remaining = operation_deadline.saturating_duration_since(now);
        operation_deadline - remaining.min(Duration::from_secs(1)) / 2
    }
}

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

async fn cleanup_operation<T, F>(
    deadline: CleanupDeadline,
    cancellation: &CancellationToken,
    future: F,
    timeout_message: &'static str,
) -> Result<T, MailboxError>
where
    F: Future<Output = T>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            Err(MailboxError::Database("cleanup cancelled".into()))
        }
        result = timeout_at(deadline.operation_deadline(Instant::now()), future) => {
            result.map_err(|_| MailboxError::Database(timeout_message.into()))
        }
    }
}

#[derive(Clone)]
pub struct MailboxService {
    pool: Pool,
    base_dir: Arc<PathBuf>,
    max_email_size: u64,
    max_attachment_size: u64,
    max_total_attachments_size: u64,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FolderRunCounts {
    pub(crate) total: i64,
    pub(crate) matching: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiPollEmail {
    pub file_name: String,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub received_at: String,
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

#[derive(Debug)]
pub struct AttachmentData {
    pub filename: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LabelRecord {
    pub id: i64,
    pub name: String,
    pub color: Option<String>,
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
    pub fn from_config(config: &RuntimeConfig, pool: Pool) -> Self {
        Self {
            pool,
            base_dir: Arc::new(config.maildir.clone()),
            max_email_size: config.limits.max_email_size_bytes,
            max_attachment_size: config.limits.max_attachment_size_bytes,
            max_total_attachments_size: config.limits.max_total_attachments_size_bytes,
        }
    }

    pub(crate) fn user_directory(&self, mailbox: &str) -> Result<PathBuf, MailboxError> {
        let mailbox = normalize_mailbox(mailbox)?;
        Ok(self.base_dir.join(sanitize_address_for_path(&mailbox)))
    }

    pub(crate) async fn count_folder(
        &self,
        mailbox: &str,
        folder: &str,
        cancellation: &CancellationToken,
    ) -> Result<i64, MailboxError> {
        validate_folder(folder)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let client = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(MailboxError::Database("query cancelled".into()));
            }
            result = timeout(DATABASE_TIMEOUT, self.pool.get()) => result
                .map_err(|_| MailboxError::Database("pool timeout".into()))?
                .map_err(|error| MailboxError::Database(error.to_string()))?,
        };
        let count_params: [&(dyn tokio_postgres::types::ToSql + Sync); 2] = [&mailbox, &folder];
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                Err(MailboxError::Database("query cancelled".into()))
            }
            result = timeout(
                DATABASE_TIMEOUT,
                client.query_one(
                    "SELECT count(*) FROM email_index WHERE mailbox_address=$1 AND folder=$2",
                    &count_params,
                ),
            ) => Ok(result
                .map_err(|_| MailboxError::Database("query timeout".into()))?
                .map_err(db_error)?
                .get(0)),
        }
    }

    pub(crate) async fn count_folder_run_marker(
        &self,
        mailbox: &str,
        folder: &str,
        subject_suffix: &str,
        cancellation: &CancellationToken,
    ) -> Result<FolderRunCounts, MailboxError> {
        validate_folder(folder)?;
        if subject_suffix.is_empty() || subject_suffix.len() > 64 || !subject_suffix.is_ascii() {
            return Err(MailboxError::InvalidInput(
                "invalid stress run marker".into(),
            ));
        }
        let mailbox = normalize_mailbox(mailbox)?;
        let client = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(MailboxError::Database("query cancelled".into()));
            }
            result = timeout(DATABASE_TIMEOUT, self.pool.get()) => result
                .map_err(|_| MailboxError::Database("pool timeout".into()))?
                .map_err(|error| MailboxError::Database(error.to_string()))?,
        };
        let params: [&(dyn tokio_postgres::types::ToSql + Sync); 3] =
            [&mailbox, &folder, &subject_suffix];
        let row = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(MailboxError::Database("query cancelled".into()));
            }
            result = timeout(
                DATABASE_TIMEOUT,
                client.query_one(
                    "SELECT count(*), count(*) FILTER (
                         WHERE right(COALESCE(subject,''), char_length($3))=$3
                     ) FROM email_index WHERE mailbox_address=$1 AND folder=$2",
                    &params,
                ),
            ) => result
                .map_err(|_| MailboxError::Database("query timeout".into()))?
                .map_err(db_error)?,
        };
        Ok(FolderRunCounts {
            total: row.get(0),
            matching: row.get(1),
        })
    }

    pub(crate) async fn delete_indexes_for_mailbox(
        &self,
        mailbox: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), MailboxError> {
        self.delete_indexes_for_mailbox_with_policy(
            mailbox,
            cancellation,
            CleanupDeadline::PerOperation(DATABASE_TIMEOUT),
        )
        .await
    }

    pub(crate) async fn delete_indexes_for_mailbox_with_deadline(
        &self,
        mailbox: &str,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> Result<(), MailboxError> {
        self.delete_indexes_for_mailbox_with_policy(
            mailbox,
            cancellation,
            CleanupDeadline::Overall(deadline),
        )
        .await
    }

    async fn delete_indexes_for_mailbox_with_policy(
        &self,
        mailbox: &str,
        cancellation: &CancellationToken,
        deadline: CleanupDeadline,
    ) -> Result<(), MailboxError> {
        let mailbox = normalize_mailbox(mailbox)?;
        let mut client = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(MailboxError::Database("cleanup cancelled".into()));
            }
            result = cleanup_operation(deadline, cancellation, self.pool.get(), "pool timeout") => result?
                .map_err(|error| MailboxError::Database(error.to_string()))?,
        };
        let transaction = cleanup_operation(
            deadline,
            cancellation,
            client.transaction(),
            "transaction timeout",
        )
        .await?
        .map_err(db_error)?;
        let mailbox_params: [&(dyn tokio_postgres::types::ToSql + Sync); 1] = [&mailbox];
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(MailboxError::Database("cleanup cancelled".into()));
            }
            result = cleanup_operation(
                deadline,
                cancellation,
                transaction.query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
                    &mailbox_params,
                ),
                "cleanup lock timeout",
            ) => {
                result
                    ?
                    .map_err(db_error)?;
            }
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(MailboxError::Database("cleanup cancelled".into()));
            }
            result = cleanup_operation(
                deadline,
                cancellation,
                transaction.execute(
                    "DELETE FROM email_index WHERE mailbox_address=$1",
                    &mailbox_params,
                ),
                "cleanup delete timeout",
            ) => {
                result
                    ?
                    .map_err(db_error)?;
                }
        }
        for (statement, operation) in [
            (
                "DELETE FROM lmyzmail_inbound_mail_count_state WHERE mailbox_address=$1",
                "cleanup exact-count state timeout",
            ),
            (
                "DELETE FROM lmyzmail_inbound_mail_count_projection WHERE mailbox_address=$1",
                "cleanup projection state timeout",
            ),
        ] {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    return Err(MailboxError::Database("cleanup cancelled".into()));
                }
                result = cleanup_operation(
                    deadline,
                    cancellation,
                    transaction.execute(statement, &mailbox_params),
                    operation,
                ) => {
                    result?
                        .map_err(db_error)?;
                }
            }
        }
        let commit = timeout_at(
            deadline.commit_attempt_deadline(Instant::now()),
            transaction.commit(),
        )
        .await;
        if matches!(commit, Ok(Ok(()))) {
            return Ok(());
        }

        // The same PostgreSQL connection orders this query after COMMIT even if
        // its response was lost. Only a confirmed empty index is a successful
        // cleanup; an unavailable reconciliation leaves the stress gate dirty.
        let reconciled = timeout_at(
            deadline.operation_deadline(Instant::now()),
            client.query_one(
                "SELECT NOT EXISTS(
                     SELECT 1 FROM email_index WHERE mailbox_address=$1
                 )",
                &mailbox_params,
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("cleanup commit outcome unknown".into()))?
        .map_err(db_error)?
        .get::<_, bool>(0);
        if reconciled {
            Ok(())
        } else {
            Err(MailboxError::Database(
                "cleanup commit was not applied".into(),
            ))
        }
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

    pub async fn poll_emails(
        &self,
        mailbox: &str,
        since: Option<chrono::DateTime<chrono::Utc>>,
        limit: i64,
    ) -> Result<Vec<ApiPollEmail>, MailboxError> {
        let mailbox = normalize_mailbox(mailbox)?;
        let limit = limit.clamp(1, 1_000);
        let client = self.db().await?;
        let rows = if let Some(since) = since {
            timeout(
                DATABASE_TIMEOUT,
                client.query(
                    "SELECT file_name, subject, from_address, received_at
                     FROM email_index
                     WHERE mailbox_address=$1 AND folder='inbox' AND received_at >= $2
                     ORDER BY received_at DESC LIMIT $3",
                    &[&mailbox, &since, &limit],
                ),
            )
            .await
            .map_err(|_| MailboxError::Database("poll query timeout".into()))?
            .map_err(db_error)?
        } else {
            timeout(
                DATABASE_TIMEOUT,
                client.query(
                    "SELECT file_name, subject, from_address, received_at
                     FROM email_index
                     WHERE mailbox_address=$1 AND folder='inbox'
                     ORDER BY received_at DESC LIMIT $2",
                    &[&mailbox, &limit],
                ),
            )
            .await
            .map_err(|_| MailboxError::Database("poll query timeout".into()))?
            .map_err(db_error)?
        };
        Ok(rows
            .into_iter()
            .map(|row| ApiPollEmail {
                file_name: row.get(0),
                subject: row.get(1),
                from: row.get(2),
                received_at: row
                    .get::<_, chrono::DateTime<chrono::Utc>>(3)
                    .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            })
            .collect())
    }

    pub async fn list_starred(
        &self,
        mailbox: &str,
        folder: &str,
    ) -> Result<Vec<String>, MailboxError> {
        validate_folder(folder)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let client = self.db().await?;
        let rows = timeout(
            DATABASE_TIMEOUT,
            client.query(
                "SELECT email_file_name FROM starred_email
                 WHERE mailbox_address=$1 AND folder=$2 ORDER BY email_file_name",
                &[&mailbox, &folder],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    pub async fn toggle_star(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<bool, MailboxError> {
        validate_folder(folder)?;
        validate_filename(file_name)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let mut client = self.db().await?;
        let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
            .await
            .map_err(|_| MailboxError::Database("transaction timeout".into()))?
            .map_err(db_error)?;
        // Serialize toggles for one mailbox so concurrent insert/delete pairs
        // cannot race the unique index on (mailbox_address, folder, file).
        timeout(
            DATABASE_TIMEOUT,
            transaction.query_opt(
                "SELECT id FROM mailbox WHERE address=$1 FOR UPDATE",
                &[&mailbox],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("mailbox lock timeout".into()))?
        .map_err(db_error)?;
        let existing = timeout(
            DATABASE_TIMEOUT,
            transaction.query_opt(
                "SELECT id FROM starred_email
                 WHERE mailbox_address=$1 AND folder=$2 AND email_file_name=$3
                 FOR UPDATE",
                &[&mailbox, &folder, &file_name],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?;
        let starred = if let Some(row) = existing {
            let id: i64 = row.get(0);
            timeout(
                DATABASE_TIMEOUT,
                transaction.execute("DELETE FROM starred_email WHERE id=$1", &[&id]),
            )
            .await
            .map_err(|_| MailboxError::Database("delete timeout".into()))?
            .map_err(db_error)?;
            false
        } else {
            timeout(
                DATABASE_TIMEOUT,
                transaction.execute(
                    "INSERT INTO starred_email (mailbox_address, folder, email_file_name, starred_at)
                     VALUES ($1, $2, $3, CURRENT_TIMESTAMP)",
                    &[&mailbox, &folder, &file_name],
                ),
            )
            .await
            .map_err(|_| MailboxError::Database("insert timeout".into()))?
            .map_err(db_error)?;
            true
        };
        timeout(DATABASE_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| MailboxError::Database("commit timeout".into()))?
            .map_err(db_error)?;
        Ok(starred)
    }

    pub async fn list_labels(&self, mailbox: &str) -> Result<Vec<LabelRecord>, MailboxError> {
        let mailbox = normalize_mailbox(mailbox)?;
        let client = self.db().await?;
        let rows = timeout(
            DATABASE_TIMEOUT,
            client.query(
                "SELECT id, label_name, color FROM email_label
                 WHERE mailbox_address=$1 ORDER BY label_name ASC, id ASC",
                &[&mailbox],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?;
        Ok(rows
            .into_iter()
            .map(|row| LabelRecord {
                id: row.get(0),
                name: row.get(1),
                color: row.get(2),
            })
            .collect())
    }

    pub async fn create_label(
        &self,
        mailbox: &str,
        name: &str,
        color: Option<&str>,
    ) -> Result<LabelRecord, MailboxError> {
        let name = validate_label_name(name)?;
        let color = validate_label_color(color)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let mut client = self.db().await?;
        let transaction = self.lock_mailbox(&mut client, &mailbox).await?;
        let existing = timeout(
            DATABASE_TIMEOUT,
            transaction.query_opt(
                "SELECT id FROM email_label WHERE mailbox_address=$1 AND label_name=$2",
                &[&mailbox, &name],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?;
        if existing.is_some() {
            return Err(MailboxError::InvalidInput("Label already exists".into()));
        }
        let row = timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "INSERT INTO email_label (mailbox_address, label_name, color, created_at)
                 VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
                 RETURNING id, label_name, color",
                &[&mailbox, &name, &color],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("insert timeout".into()))?
        .map_err(db_error)?;
        let label = LabelRecord {
            id: row.get(0),
            name: row.get(1),
            color: row.get(2),
        };
        timeout(DATABASE_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| MailboxError::Database("commit timeout".into()))?
            .map_err(db_error)?;
        Ok(label)
    }

    pub async fn update_label(
        &self,
        mailbox: &str,
        id: i64,
        name: &str,
        color: Option<&str>,
    ) -> Result<LabelRecord, MailboxError> {
        let name = validate_label_name(name)?;
        let color = validate_label_color(color)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let mut client = self.db().await?;
        let transaction = self.lock_mailbox(&mut client, &mailbox).await?;
        let row = timeout(
            DATABASE_TIMEOUT,
            transaction.query_opt(
                "UPDATE email_label SET label_name=$1, color=$2
                 WHERE mailbox_address=$3 AND id=$4
                 RETURNING id, label_name, color",
                &[&name, &color, &mailbox, &id],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("update timeout".into()))?
        .map_err(db_error)?
        .ok_or_else(|| MailboxError::InvalidInput("Label not found".into()))?;
        let label = LabelRecord {
            id: row.get(0),
            name: row.get(1),
            color: row.get(2),
        };
        timeout(DATABASE_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| MailboxError::Database("commit timeout".into()))?
            .map_err(db_error)?;
        Ok(label)
    }

    pub async fn delete_label(&self, mailbox: &str, id: i64) -> Result<(), MailboxError> {
        let mailbox = normalize_mailbox(mailbox)?;
        let mut client = self.db().await?;
        let transaction = self.lock_mailbox(&mut client, &mailbox).await?;
        let deleted = timeout(
            DATABASE_TIMEOUT,
            transaction.execute(
                "DELETE FROM email_label_assignment WHERE mailbox_address=$1 AND label_id=$2",
                &[&mailbox, &id],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("assignment delete timeout".into()))?
        .map_err(db_error)?;
        let _ = deleted;
        let labels_deleted = timeout(
            DATABASE_TIMEOUT,
            transaction.execute(
                "DELETE FROM email_label WHERE mailbox_address=$1 AND id=$2",
                &[&mailbox, &id],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("label delete timeout".into()))?
        .map_err(db_error)?;
        if labels_deleted == 0 {
            return Err(MailboxError::InvalidInput("Label not found".into()));
        }
        timeout(DATABASE_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| MailboxError::Database("commit timeout".into()))?
            .map_err(db_error)
    }

    pub async fn email_labels(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<Vec<i64>, MailboxError> {
        validate_folder(folder)?;
        validate_filename(file_name)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let client = self.db().await?;
        let rows = timeout(
            DATABASE_TIMEOUT,
            client.query(
                "SELECT label_id FROM email_label_assignment
                 WHERE mailbox_address=$1 AND folder=$2 AND email_file_name=$3
                 ORDER BY label_id ASC",
                &[&mailbox, &folder, &file_name],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("query timeout".into()))?
        .map_err(db_error)?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    pub async fn assign_label(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
        label_id: i64,
    ) -> Result<(), MailboxError> {
        validate_folder(folder)?;
        validate_filename(file_name)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let mut client = self.db().await?;
        let transaction = self.lock_mailbox(&mut client, &mailbox).await?;
        let label_exists = timeout(
            DATABASE_TIMEOUT,
            transaction.query_opt(
                "SELECT id FROM email_label WHERE mailbox_address=$1 AND id=$2",
                &[&mailbox, &label_id],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("label query timeout".into()))?
        .map_err(db_error)?
        .is_some();
        if !label_exists {
            return Err(MailboxError::InvalidInput("Label not found".into()));
        }
        let assignment_exists = timeout(
            DATABASE_TIMEOUT,
            transaction.query_opt(
                "SELECT id FROM email_label_assignment
                 WHERE mailbox_address=$1 AND folder=$2 AND email_file_name=$3 AND label_id=$4",
                &[&mailbox, &folder, &file_name, &label_id],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("assignment query timeout".into()))?
        .map_err(db_error)?
        .is_some();
        if !assignment_exists {
            timeout(
                DATABASE_TIMEOUT,
                transaction.execute(
                    "INSERT INTO email_label_assignment
                     (mailbox_address, folder, email_file_name, label_id, assigned_at)
                     VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)",
                    &[&mailbox, &folder, &file_name, &label_id],
                ),
            )
            .await
            .map_err(|_| MailboxError::Database("assignment insert timeout".into()))?
            .map_err(db_error)?;
        }
        timeout(DATABASE_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| MailboxError::Database("commit timeout".into()))?
            .map_err(db_error)
    }

    pub async fn remove_label(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
        label_id: i64,
    ) -> Result<(), MailboxError> {
        validate_folder(folder)?;
        validate_filename(file_name)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let mut client = self.db().await?;
        let transaction = self.lock_mailbox(&mut client, &mailbox).await?;
        let row = timeout(
            DATABASE_TIMEOUT,
            transaction.query_opt(
                "SELECT id FROM email_label_assignment
                 WHERE mailbox_address=$1 AND folder=$2 AND email_file_name=$3 AND label_id=$4
                 ORDER BY id ASC LIMIT 1",
                &[&mailbox, &folder, &file_name, &label_id],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("assignment query timeout".into()))?
        .map_err(db_error)?;
        if let Some(row) = row {
            let id: i64 = row.get(0);
            timeout(
                DATABASE_TIMEOUT,
                transaction.execute("DELETE FROM email_label_assignment WHERE id=$1", &[&id]),
            )
            .await
            .map_err(|_| MailboxError::Database("assignment delete timeout".into()))?
            .map_err(db_error)?;
        }
        timeout(DATABASE_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| MailboxError::Database("commit timeout".into()))?
            .map_err(db_error)
    }

    async fn lock_mailbox<'a>(
        &self,
        client: &'a mut deadpool_postgres::Object,
        mailbox: &str,
    ) -> Result<deadpool_postgres::Transaction<'a>, MailboxError> {
        let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
            .await
            .map_err(|_| MailboxError::Database("transaction timeout".into()))?
            .map_err(db_error)?;
        timeout(
            DATABASE_TIMEOUT,
            transaction.query_opt(
                "SELECT id FROM mailbox WHERE address=$1 FOR UPDATE",
                &[&mailbox],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("mailbox lock timeout".into()))?
        .map_err(db_error)?;
        Ok(transaction)
    }

    pub async fn read_detail(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<EmailDetail, MailboxError> {
        let path = self
            .authorized_path(mailbox, folder, file_name, true)
            .await?;
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
        self.open_raw_limited(mailbox, folder, file_name, self.max_email_size)
            .await
    }

    pub async fn open_raw_limited(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
        requested_max_size: u64,
    ) -> Result<(tokio::fs::File, u64), MailboxError> {
        let path = self
            .authorized_path(mailbox, folder, file_name, true)
            .await?;
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(|_| MailboxError::NotFound)?;
        let max_size = requested_max_size
            .min(self.max_email_size)
            .clamp(1, MAX_RAW_BYTES);
        if metadata.len() > max_size {
            return Err(MailboxError::TooLarge);
        }
        let length = metadata.len();
        let file = tokio::fs::File::open(path)
            .await
            .map_err(MailboxError::Io)?;
        Ok((file, length))
    }

    pub async fn read_decoded_text(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
        prefer_html: bool,
    ) -> Result<String, MailboxError> {
        let path = self
            .authorized_path(mailbox, folder, file_name, true)
            .await?;
        let max_size = self.max_email_size.clamp(1, MAX_RAW_BYTES);
        spawn_blocking(move || parse_decoded_text(&path, max_size, prefer_html))
            .await
            .map_err(|error| {
                MailboxError::Database(format!("decoded parser task failed: {error}"))
            })?
    }

    pub async fn read_attachment(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
        index: i32,
    ) -> Result<AttachmentData, MailboxError> {
        let path = self
            .authorized_path(mailbox, folder, file_name, true)
            .await?;
        let index = usize::try_from(index).map_err(|_| MailboxError::NotFound)?;
        let max_email_size = self.max_email_size.clamp(1, MAX_RAW_BYTES);
        let max_attachment_size = self.max_attachment_size.min(max_email_size);
        let max_total_attachments_size = self.max_total_attachments_size.min(max_email_size);
        spawn_blocking(move || {
            parse_attachment(
                &path,
                index,
                max_email_size,
                max_attachment_size,
                max_total_attachments_size,
            )
        })
        .await
        .map_err(|error| MailboxError::Database(format!("attachment task failed: {error}")))?
    }

    pub async fn delete_email(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<(), MailboxError> {
        // Takeover includes deleting existing messages. The legacy lookup
        // proves unique mailbox ownership before exposing the indexed file;
        // rejecting every legacy path made readable mail impossible to delete.
        let path = self
            .authorized_path(mailbox, folder, file_name, true)
            .await?;
        let parent = path.parent().ok_or(MailboxError::NotFound)?.to_owned();
        let tombstone = deletion_tombstone(&parent)?;
        tokio::fs::rename(&path, &tombstone)
            .await
            .map_err(|_| MailboxError::NotFound)?;
        let result = self.remove_email_rows(mailbox, folder, file_name).await;
        if let Err(error) = result {
            let _ = tokio::fs::rename(&tombstone, &path).await;
            return Err(error);
        }
        tokio::fs::remove_file(&tombstone)
            .await
            .map_err(MailboxError::Io)?;
        let parent_for_sync = parent.clone();
        spawn_blocking(move || {
            let directory = std::fs::File::open(parent_for_sync)?;
            sync_all(&directory)
        })
        .await
        .map_err(|error| MailboxError::Database(format!("directory sync task failed: {error}")))?
        .map_err(MailboxError::Io)?;
        Ok(())
    }

    pub async fn read_headers(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<String, MailboxError> {
        let path = self
            .authorized_path(mailbox, folder, file_name, true)
            .await?;
        spawn_blocking(move || extract_headers(&path))
            .await
            .map_err(|error| MailboxError::Database(format!("header task failed: {error}")))?
    }

    async fn authorized_path(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
        allow_legacy_read: bool,
    ) -> Result<PathBuf, MailboxError> {
        validate_folder(folder)?;
        validate_filename(file_name)?;
        let mailbox = normalize_mailbox(mailbox)?;
        let mut client = self.db().await?;
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
            .join(v2_sanitize_address_for_path(&mailbox))
            .join(folder);
        let path = match subdirectory.filter(|value| *value > 0) {
            Some(value) => base.join(value.to_string()).join(file_name),
            None => base.join(file_name),
        };
        if let (Ok(normalized_base), Ok(normalized_path)) = (
            tokio::fs::canonicalize(&base).await,
            tokio::fs::canonicalize(&path).await,
        ) {
            if !normalized_path.starts_with(&normalized_base) {
                return Err(MailboxError::InvalidInput("path traversal detected".into()));
            }
            return Ok(normalized_path);
        }
        if !allow_legacy_read {
            return Err(MailboxError::NotFound);
        }

        // v1 was used by early Rust candidates and is injective, but a single
        // percent-encoded component can exceed Linux NAME_MAX. Keep it as a
        // read-only bridge for data created by earlier Rust candidates, but
        // prove ownership first: v1-qa@example.test is also a literal Java
        // mailbox directory, so an index row alone cannot authorize that alias.

        // Frozen Java installations mapped several distinct mailbox names to
        // the same directory.  Read that alias only when the database proves
        // that no other registered mailbox shares it. This proof also applies
        // to new messages in the rollback-compatible directory layout.
        let mut legacy_components = vec![
            v1_sanitize_address_for_path(&mailbox),
            legacy_sanitize_address_for_path(&mailbox),
        ];
        let smtp_component = legacy_smtp_sanitize_address_for_path(&mailbox);
        if !legacy_components.contains(&smtp_component) {
            legacy_components.push(smtp_component);
        }
        let proof_deadline = Instant::now() + DATABASE_TIMEOUT;
        let transaction = timeout_at(
            proof_deadline,
            client
                .build_transaction()
                .isolation_level(IsolationLevel::RepeatableRead)
                .read_only(true)
                .start(),
        )
        .await
        .map_err(|_| MailboxError::Database("legacy ownership snapshot timeout".into()))?
        .map_err(db_error)?;
        let mut ownership = vec![(false, true); legacy_components.len()];
        let mut after_id = i64::MIN;
        loop {
            let owners = timeout_at(
                proof_deadline,
                transaction.query(
                    "SELECT id,address FROM mailbox
                     WHERE id > $1
                     ORDER BY id
                     LIMIT $2",
                    &[&after_id, &LEGACY_MAILBOX_OWNERSHIP_PAGE_ROWS],
                ),
            )
            .await
            .map_err(|_| MailboxError::Database("legacy ownership query timeout".into()))?
            .map_err(db_error)?;
            if owners.is_empty() {
                break;
            }
            for owner in &owners {
                after_id = owner.get(0);
                let raw_owner: String = owner.get(1);
                for (index, (component, (found, unique))) in
                    legacy_components.iter().zip(&mut ownership).enumerate()
                {
                    let proof = if index == 0 {
                        observe_v1_mailbox_owner(&mailbox, component, &raw_owner, found)
                    } else {
                        observe_legacy_mailbox_owner(&mailbox, component, &raw_owner, found)
                    };
                    if proof.is_err() {
                        *unique = false;
                    }
                }
            }
            if owners.len() < LEGACY_MAILBOX_OWNERSHIP_PAGE_ROWS as usize {
                break;
            }
        }
        timeout_at(proof_deadline, transaction.commit())
            .await
            .map_err(|_| MailboxError::Database("legacy ownership snapshot timeout".into()))?
            .map_err(db_error)?;
        for (component, (found, unique)) in legacy_components.into_iter().zip(ownership) {
            if !found || !unique {
                continue;
            }
            let base = self.base_dir.join(component).join(folder);
            let path = match subdirectory.filter(|value| *value > 0) {
                Some(value) => base.join(value.to_string()).join(file_name),
                None => base.join(file_name),
            };
            let (Ok(normalized_base), Ok(normalized_path)) = (
                tokio::fs::canonicalize(&base).await,
                tokio::fs::canonicalize(&path).await,
            ) else {
                continue;
            };
            if !normalized_path.starts_with(&normalized_base) {
                return Err(MailboxError::InvalidInput("path traversal detected".into()));
            }
            return Ok(normalized_path);
        }
        Err(MailboxError::NotFound)
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

    async fn remove_email_rows(
        &self,
        mailbox: &str,
        folder: &str,
        file_name: &str,
    ) -> Result<(), MailboxError> {
        let mailbox = normalize_mailbox(mailbox)?;
        let mut client = self.db().await?;
        let transaction = self.lock_mailbox(&mut client, &mailbox).await?;
        let deleted = timeout(
            DATABASE_TIMEOUT,
            transaction.execute(
                "DELETE FROM email_index
                 WHERE mailbox_address=$1 AND folder=$2 AND file_name=$3",
                &[&mailbox, &folder, &file_name],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("index delete timeout".into()))?
        .map_err(db_error)?;
        if deleted == 0 {
            return Err(MailboxError::NotFound);
        }
        let count: i64 = timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "SELECT COUNT(*) FROM email_index WHERE mailbox_address=$1 AND folder=$2",
                &[&mailbox, &folder],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("mail-count projection query timeout".into()))?
        .map_err(db_error)?
        .get(0);
        timeout(
            DATABASE_TIMEOUT,
            transaction.execute(
                "INSERT INTO lmyzmail_inbound_mail_count_state
                 (mailbox_address,folder,exact_count,updated_at)
                 VALUES ($1,$2,$3,CURRENT_TIMESTAMP)
                 ON CONFLICT (mailbox_address,folder) DO UPDATE SET
                     exact_count=EXCLUDED.exact_count,
                     updated_at=CURRENT_TIMESTAMP",
                &[&mailbox, &folder, &count],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("mail-count exact state timeout".into()))?
        .map_err(db_error)?;
        timeout(
            DATABASE_TIMEOUT,
            transaction.execute(
                "INSERT INTO lmyzmail_inbound_mail_count_projection
                 (mailbox_address,folder,generation,desired_count,updated_at)
                 VALUES ($1,$2,1,$3,CURRENT_TIMESTAMP)
                 ON CONFLICT (mailbox_address,folder) DO UPDATE SET
                     generation=CASE
                         WHEN lmyzmail_inbound_mail_count_projection.generation=9223372036854775807
                         THEN 1
                         ELSE lmyzmail_inbound_mail_count_projection.generation+1
                     END,
                     desired_count=EXCLUDED.desired_count,
                     updated_at=CURRENT_TIMESTAMP",
                &[&mailbox, &folder, &count],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("mail-count projection update timeout".into()))?
        .map_err(db_error)?;
        timeout(
            DATABASE_TIMEOUT,
            transaction.execute(
                "DELETE FROM starred_email
                 WHERE mailbox_address=$1 AND folder=$2 AND email_file_name=$3",
                &[&mailbox, &folder, &file_name],
            ),
        )
        .await
        .map_err(|_| MailboxError::Database("star delete timeout".into()))?
        .map_err(db_error)?;
        timeout(DATABASE_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| MailboxError::Database("commit timeout".into()))?
            .map_err(db_error)
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

pub(crate) fn normalize_mailbox(value: &str) -> Result<String, MailboxError> {
    let value = value.trim().to_lowercase();
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

fn validate_label_name(name: &str) -> Result<String, MailboxError> {
    if name.is_empty() || name.len() > 100 || name.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(MailboxError::InvalidInput("Invalid label name".into()));
    }
    Ok(name.to_owned())
}

fn validate_label_color(color: Option<&str>) -> Result<Option<String>, MailboxError> {
    let Some(color) = color else {
        return Ok(None);
    };
    if color.len() > 20 || color.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(MailboxError::InvalidInput("Invalid label color".into()));
    }
    Ok(Some(color.to_owned()))
}

fn deletion_tombstone(parent: &Path) -> Result<PathBuf, MailboxError> {
    let mut bytes = [0_u8; 16];
    fill_random(&mut bytes).map_err(|error| MailboxError::Database(error.to_string()))?;
    let mut suffix = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(suffix, "{byte:02x}");
    }
    Ok(parent.join(format!(".lmyzmail-delete-{suffix}.tmp")))
}

pub(crate) fn sanitize_address_for_path(address: &str) -> PathBuf {
    let normalized = address.trim().to_lowercase();
    // Preserve the Java layout only where its lossy sanitizer cannot map a
    // different valid mailbox onto this name. In particular, '_' can originate
    // from a slash, a forbidden character or '..', so it is not safe here.
    // Reserve v1-* for early Rust data and v2/ for the encoded namespace.
    if normalized.contains('@')
        && normalized.len() <= 255
        && !normalized.starts_with("v1-")
        && !normalized.contains("..")
        && normalized
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'-' | b'+'))
    {
        return PathBuf::from(normalized);
    }
    v2_sanitize_address_for_path(&normalized)
}

pub(crate) fn v2_sanitize_address_for_path(address: &str) -> PathBuf {
    let normalized = address.trim().to_lowercase();
    let mut output = PathBuf::from("v2");
    for chunk in normalized.as_bytes().chunks(MAILBOX_PATH_CHUNK_BYTES) {
        let mut component = String::with_capacity(2 + chunk.len() * 2);
        component.push_str("c-");
        for byte in chunk {
            use std::fmt::Write as _;
            let _ = write!(component, "{byte:02X}");
        }
        output.push(component);
    }
    output.push(format!("z-{:08X}", normalized.len()));
    output
}

pub(crate) fn secure_mailbox_folder(
    base: &Path,
    address: &str,
    folder: &str,
) -> io::Result<PathBuf> {
    let mut folder_components = Path::new(folder).components();
    if !matches!(
        folder_components.next(),
        Some(std::path::Component::Normal(_))
    ) || folder_components.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mailbox folder is not a single path component",
        ));
    }
    let relative = sanitize_address_for_path(address);
    let mut relative_components = relative.components();
    if !matches!(
        relative_components.next(),
        Some(std::path::Component::Normal(_))
    ) || relative_components
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mailbox address path is not safely relative",
        ));
    }

    let mut path = secure_create_directory_tree(base)?;
    let mut directory = open_secure_directory(&path)?;
    for component in relative
        .components()
        .chain(std::iter::once(std::path::Component::Normal(OsStr::new(
            folder,
        ))))
    {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "mailbox path contains a non-normal component",
            ));
        };
        directory = ensure_secure_child_directory(&directory, name)?;
        path.push(name);
    }
    Ok(path)
}

pub(crate) fn secure_directory_child(parent: &Path, name: &str) -> io::Result<PathBuf> {
    let directory = open_secure_directory(parent)?;
    let _child = ensure_secure_child_directory(&directory, OsStr::new(name))?;
    Ok(parent.join(name))
}

pub(crate) fn secure_directory_root(path: &Path) -> io::Result<PathBuf> {
    secure_create_directory_tree(path)
}

fn secure_create_directory_tree(path: &Path) -> io::Result<PathBuf> {
    let mut existing = path.to_path_buf();
    let mut missing = Vec::<OsString>::new();
    loop {
        match std::fs::symlink_metadata(&existing) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "mailbox path ancestor is not a real directory",
                    ));
                }
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = existing.file_name().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "mailbox directory has no creatable component",
                    )
                })?;
                missing.push(name.to_os_string());
                existing = existing
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf();
            }
            Err(error) => return Err(error),
        }
    }

    let mut directory = open_secure_directory(&existing)?;
    let mut canonical = std::fs::canonicalize(&existing)?;
    for name in missing.iter().rev() {
        directory = ensure_secure_child_directory(&directory, name)?;
        canonical.push(name);
    }
    Ok(canonical)
}

fn open_secure_directory(path: &Path) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags, fstat, openat2};

    let directory = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let stat = fstat(&directory).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mailbox path is not a directory",
        ));
    }
    Ok(directory)
}

fn ensure_secure_child_directory(
    parent: &std::os::fd::OwnedFd,
    name: &OsStr,
) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, mkdirat, openat2};

    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid mailbox directory component",
        ));
    }
    let created = match mkdirat(parent, name, Mode::RWXU) {
        Ok(()) => true,
        Err(error) if error == rustix::io::Errno::EXIST => false,
        Err(error) => return Err(io::Error::from(error)),
    };
    let directory = openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let parent_stat = fstat(parent).map_err(io::Error::from)?;
    let stat = fstat(&directory).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != parent_stat.st_uid
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mailbox child is not an owned directory",
        ));
    }
    if created {
        fsync(&directory).map_err(io::Error::from)?;
        fsync(parent).map_err(io::Error::from)?;
    }
    Ok(directory)
}

pub(crate) fn v1_sanitize_address_for_path(address: &str) -> String {
    let normalized = address.trim().to_lowercase();
    let mut output = String::with_capacity(3 + normalized.len());
    output.push_str("v1-");
    for byte in normalized.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'-' | b'+') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

pub(crate) fn legacy_sanitize_address_for_path(address: &str) -> String {
    let mut output = String::with_capacity(address.len());
    for ch in address.trim().to_lowercase().chars() {
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

// Frozen MailFileStore's writer differs from MailReadService's reader: it
// preserves interior ".." and replaces only leading/trailing dots. Keep this
// read-only alias for already indexed files, under the same ownership proof.
fn legacy_smtp_sanitize_address_for_path(address: &str) -> String {
    let mut output = String::with_capacity(address.len());
    for ch in address.trim().to_lowercase().chars() {
        if ch <= '\u{1f}' || ch == '\u{7f}' {
            continue;
        }
        output.push(
            if matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                ch
            },
        );
    }
    if output.is_empty() {
        return "unknown".into();
    }
    if output.starts_with('.') {
        output.replace_range(..1, "_");
    }
    if output.ends_with('.') {
        output.pop();
        output.push('_');
    }
    output
}

fn observe_legacy_mailbox_owner(
    requested_mailbox: &str,
    requested_component: &str,
    raw_owner: &str,
    requested_owner_found: &mut bool,
) -> Result<(), MailboxError> {
    if legacy_sanitize_address_for_path(raw_owner) != requested_component
        && legacy_smtp_sanitize_address_for_path(raw_owner) != requested_component
    {
        return Ok(());
    }
    let owner = normalize_mailbox(raw_owner).map_err(|_| MailboxError::NotFound)?;
    if owner != requested_mailbox {
        return Err(MailboxError::NotFound);
    }
    *requested_owner_found = true;
    Ok(())
}

fn observe_v1_mailbox_owner(
    requested_mailbox: &str,
    requested_component: &str,
    raw_owner: &str,
    requested_owner_found: &mut bool,
) -> Result<(), MailboxError> {
    if normalize_mailbox(raw_owner).ok().as_deref() == Some(requested_mailbox) {
        *requested_owner_found = true;
        return Ok(());
    }
    if legacy_sanitize_address_for_path(raw_owner) == requested_component
        || legacy_smtp_sanitize_address_for_path(raw_owner) == requested_component
    {
        return Err(MailboxError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
fn decode_address_path(path: &Path) -> Option<String> {
    let components = path
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    if components.len() == 1 {
        let address = components[0];
        return (sanitize_address_for_path(address) == path).then(|| address.to_owned());
    }
    if components.first().copied() != Some("v2") || components.len() < 2 {
        return None;
    }
    let length = usize::from_str_radix(components.last()?.strip_prefix("z-")?, 16).ok()?;
    let mut bytes = Vec::with_capacity(length);
    for component in &components[1..components.len() - 1] {
        let encoded = component.strip_prefix("c-")?.as_bytes();
        if encoded.is_empty()
            || encoded.len() > MAILBOX_PATH_CHUNK_BYTES * 2
            || encoded.len() % 2 != 0
        {
            return None;
        }
        for pair in encoded.chunks_exact(2) {
            bytes.push(hex_value(pair[0])? << 4 | hex_value(pair[1])?);
        }
    }
    if bytes.len() != length {
        return None;
    }
    let decoded = String::from_utf8(bytes).ok()?;
    (v2_sanitize_address_for_path(&decoded) == path).then_some(decoded)
}

#[cfg(test)]
fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
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

fn parse_decoded_text(
    path: &Path,
    max_size: u64,
    prefer_html: bool,
) -> Result<String, MailboxError> {
    let bytes = read_bounded(path, max_size)?;
    let message = MessageParser::default()
        .with_minimal_headers()
        .parse(&bytes)
        .ok_or(MailboxError::NotFound)?;
    let text = message.parts.iter().find_map(|part| match &part.body {
        PartType::Text(value) => Some(truncate_text(value)),
        _ => None,
    });
    let html = message.parts.iter().find_map(|part| match &part.body {
        PartType::Html(value) => Some(truncate_text(value)),
        _ => None,
    });
    if prefer_html && let Some(html) = html {
        return Ok(clean(&html));
    }
    if let Some(text) = text {
        return Ok(text);
    }
    Ok(html.map(|value| clean(&value)).unwrap_or_default())
}

fn parse_attachment(
    path: &Path,
    index: usize,
    max_email_size: u64,
    max_attachment_size: u64,
    max_total_attachments_size: u64,
) -> Result<AttachmentData, MailboxError> {
    let bytes = read_bounded(path, max_email_size)?;
    parse_attachment_bytes(
        &bytes,
        index,
        max_attachment_size,
        max_total_attachments_size,
    )
}

fn read_bounded(path: &Path, max_size: u64) -> Result<Vec<u8>, MailboxError> {
    let mut file = std::fs::File::open(path).map_err(|_| MailboxError::NotFound)?;
    if file.metadata().map_err(MailboxError::Io)?.len() > max_size {
        return Err(MailboxError::TooLarge);
    }
    let read_limit = max_size.checked_add(1).ok_or(MailboxError::TooLarge)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(MailboxError::Io)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > max_size) {
        return Err(MailboxError::TooLarge);
    }
    Ok(bytes)
}

fn parse_attachment_bytes(
    bytes: &[u8],
    index: usize,
    max_attachment_size: u64,
    max_total_attachments_size: u64,
) -> Result<AttachmentData, MailboxError> {
    let mut message = MessageParser::default()
        .parse(bytes)
        .ok_or(MailboxError::NotFound)?;
    let mut total_size = 0_u64;
    for part_id in &message.attachments {
        let part = message
            .parts
            .get(*part_id as usize)
            .ok_or(MailboxError::NotFound)?;
        let part_size = u64::try_from(part.len()).map_err(|_| MailboxError::TooLarge)?;
        if part_size > max_attachment_size {
            return Err(MailboxError::TooLarge);
        }
        total_size = total_size
            .checked_add(part_size)
            .ok_or(MailboxError::TooLarge)?;
        if total_size > max_total_attachments_size {
            return Err(MailboxError::TooLarge);
        }
    }

    let part_id = *message
        .attachments
        .get(index)
        .ok_or(MailboxError::NotFound)? as usize;
    let part = message
        .parts
        .get_mut(part_id)
        .ok_or(MailboxError::NotFound)?;
    let filename = part
        .content_disposition()
        .and_then(|value| value.attribute("filename"))
        .or_else(|| {
            part.content_type()
                .and_then(|value| value.attribute("name"))
        })
        .map(str::to_owned)
        .unwrap_or_else(|| format!("attachment_{index}"));
    let content_type = part.content_type().map(|value| {
        format!(
            "{}{}",
            value.ctype(),
            value
                .subtype()
                .map_or(String::new(), |subtype| format!("/{subtype}"))
        )
    });
    let body = match std::mem::take(&mut part.body) {
        PartType::Binary(value) | PartType::InlineBinary(value) => value.into_owned(),
        PartType::Text(Cow::Owned(value)) | PartType::Html(Cow::Owned(value)) => value.into_bytes(),
        PartType::Text(Cow::Borrowed(value)) | PartType::Html(Cow::Borrowed(value)) => {
            value.as_bytes().to_vec()
        }
        PartType::Message(value) => value.raw_message.into_owned(),
        PartType::Multipart(_) => return Err(MailboxError::NotFound),
    };
    Ok(AttachmentData {
        filename,
        content_type,
        body,
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
    fn cleanup_deadlines_shrink_only_for_the_explicit_overall_policy() {
        let started = Instant::now();
        let later = started + Duration::from_secs(3);
        let ordinary = CleanupDeadline::PerOperation(DATABASE_TIMEOUT);
        let overall_deadline = started + Duration::from_secs(5);
        let overall = CleanupDeadline::Overall(overall_deadline);

        assert_eq!(
            ordinary
                .operation_deadline(started)
                .saturating_duration_since(started),
            DATABASE_TIMEOUT
        );
        assert_eq!(
            ordinary
                .operation_deadline(later)
                .saturating_duration_since(later),
            DATABASE_TIMEOUT
        );
        assert_eq!(overall.operation_deadline(started), overall_deadline);
        assert_eq!(overall.operation_deadline(later), overall_deadline);
        assert_eq!(
            overall_deadline.saturating_duration_since(later),
            Duration::from_secs(2)
        );
    }

    #[tokio::test]
    async fn cleanup_operation_propagates_the_stage_timeout_message() {
        let error = cleanup_operation(
            CleanupDeadline::Overall(Instant::now()),
            &CancellationToken::new(),
            std::future::pending::<()>(),
            "cleanup delete timeout",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            MailboxError::Database(message) if message == "cleanup delete timeout"
        ));
    }

    #[tokio::test]
    async fn cleanup_operation_observes_cancellation_before_a_stalled_stage() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let error = cleanup_operation(
            CleanupDeadline::PerOperation(DATABASE_TIMEOUT),
            &cancellation,
            std::future::pending::<()>(),
            "transaction timeout",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            MailboxError::Database(message) if message == "cleanup cancelled"
        ));
    }

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
    fn address_path_encoding_is_injective_reversible_and_not_a_path() {
        assert_eq!(
            decode_address_path(&sanitize_address_for_path("QA/../EXAMPLE.TEST")),
            Some("qa/../example.test".into())
        );
        assert_eq!(
            decode_address_path(&sanitize_address_for_path("")),
            Some(String::new())
        );
        assert_ne!(
            sanitize_address_for_path("foo/./bar@example.test"),
            sanitize_address_for_path("foo//bar@example.test")
        );
        assert_ne!(
            sanitize_address_for_path("foo/bar@example.test"),
            sanitize_address_for_path("foo_bar@example.test")
        );
        assert_ne!(
            sanitize_address_for_path("foo%bar@example.test"),
            sanitize_address_for_path("foo/bar@example.test")
        );
        assert_eq!(
            decode_address_path(&sanitize_address_for_path("foo%bar@example.test")),
            Some("foo%bar@example.test".into())
        );
        assert!(
            sanitize_address_for_path("/tmp/mail@example.test")
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
        );
        assert_eq!(
            sanitize_address_for_path("\u{0130}USER@example.test"),
            sanitize_address_for_path("i\u{307}user@example.test")
        );
        assert_eq!(
            normalize_mailbox("\u{0130}USER@example.test").unwrap(),
            "i\u{307}user@example.test"
        );
        for address in [
            "foo/bar@example.test",
            "foo_bar@example.test",
            "foo%bar@example.test",
            "\u{90ae}\u{4ef6}@example.test",
        ] {
            let normalized = address.trim().to_lowercase();
            assert_eq!(
                decode_address_path(&sanitize_address_for_path(address)),
                Some(normalized)
            );
        }
        assert_eq!(
            legacy_sanitize_address_for_path("foo/bar@example.test"),
            legacy_sanitize_address_for_path("foo_bar@example.test")
        );
    }

    #[test]
    fn v2_address_paths_bound_components_and_round_trip_chunk_boundaries() {
        for length in [0, 1, 119, 120, 121, 239, 240, 241, 255] {
            let address = "a".repeat(length);
            let path = sanitize_address_for_path(&address);
            assert_eq!(decode_address_path(&path), Some(address), "length={length}");
            assert!(path.components().all(|component| match component {
                std::path::Component::Normal(value) => value.as_encoded_bytes().len() <= 255,
                _ => false,
            }));
            assert!(path.as_os_str().as_encoded_bytes().len() < 4_096);
        }

        let unicode = "邮".repeat(50);
        let path = sanitize_address_for_path(&unicode);
        assert_eq!(decode_address_path(&path), Some(unicode));
        assert!(path.components().all(|component| match component {
            std::path::Component::Normal(value) => value.as_encoded_bytes().len() <= 255,
            _ => false,
        }));
    }

    #[test]
    fn ordinary_mailboxes_preserve_java_paths_without_lossy_aliases() {
        assert_eq!(
            sanitize_address_for_path(" QA+tag@EXAMPLE.TEST "),
            PathBuf::from("qa+tag@example.test")
        );
        for address in [
            "foo_bar@example.test",
            "foo/bar@example.test",
            "foo..bar@example.test",
            "v1-qa@example.test",
            "v2",
            "../qa@example.test",
        ] {
            assert_eq!(
                sanitize_address_for_path(address),
                v2_sanitize_address_for_path(address)
            );
        }
        assert_ne!(
            sanitize_address_for_path("qa@example.test"),
            sanitize_address_for_path("v1-qa@example.test")
        );
    }

    #[test]
    fn secure_mailbox_folder_creates_all_address_classes_beneath_root() {
        let mut nonce = [0_u8; 16];
        fill_random(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "lmyzmail-mailbox-v2-{}",
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir(&root).unwrap();
        let addresses = [
            "foo/bar@example.test".to_owned(),
            "/absolute/qa@example.test".to_owned(),
            "../qa@example.test".to_owned(),
            "foo%bar@example.test".to_owned(),
            format!("{}@example.test", "邮".repeat(50)),
            format!("{}@example.test", "a".repeat(242)),
        ];
        let canonical_root = std::fs::canonicalize(&root).unwrap();
        for address in addresses {
            let normalized = normalize_mailbox(&address).unwrap();
            let first = secure_mailbox_folder(&root, &normalized, "inbox").unwrap();
            let second = secure_mailbox_folder(&root, &normalized, "inbox").unwrap();
            assert_eq!(first, second);
            assert!(first.starts_with(&canonical_root));
            assert!(first.ends_with(sanitize_address_for_path(&normalized).join("inbox")));
            assert!(first.is_dir());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secure_mailbox_folder_rejects_intermediate_symlink_without_outside_writes() {
        use std::os::unix::fs::symlink;

        let mut nonce = [0_u8; 16];
        fill_random(&mut nonce).unwrap();
        let suffix = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let root = std::env::temp_dir().join(format!("lmyzmail-mailbox-link-{suffix}"));
        let outside = std::env::temp_dir().join(format!("lmyzmail-mailbox-outside-{suffix}"));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join("qa@example.test")).unwrap();
        assert!(secure_mailbox_folder(&root, "qa@example.test", "inbox").is_err());
        symlink(&outside, root.join("v2")).unwrap();
        assert!(secure_mailbox_folder(&root, "foo/bar@example.test", "inbox").is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);

        std::fs::remove_file(root.join("qa@example.test")).unwrap();
        std::fs::remove_file(root.join("v2")).unwrap();
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn invalid_legacy_owner_that_maps_to_requested_component_fails_closed() {
        let requested = "owner@example.test";
        let component = legacy_sanitize_address_for_path(requested);
        let mut found = false;
        assert!(
            observe_legacy_mailbox_owner(
                requested,
                &component,
                "own\u{0000}er@example.test",
                &mut found,
            )
            .is_err()
        );
        assert!(!found);
    }

    #[test]
    fn legacy_ownership_proof_has_no_total_mailbox_limit_and_detects_late_collisions() {
        let requested = "owner-5000@example.test";
        let component = legacy_sanitize_address_for_path(requested);
        let mut found = false;
        for index in 0..6_000 {
            let owner = if index == 5_000 {
                requested.to_owned()
            } else {
                format!("owner-{index}@other.test")
            };
            observe_legacy_mailbox_owner(requested, &component, &owner, &mut found).unwrap();
        }
        assert!(found);

        let requested = "foo/bar@example.test";
        let component = legacy_sanitize_address_for_path(requested);
        let mut found = false;
        observe_legacy_mailbox_owner(requested, &component, requested, &mut found).unwrap();
        for index in 0..5_000 {
            observe_legacy_mailbox_owner(
                requested,
                &component,
                &format!("unrelated-{index}@example.test"),
                &mut found,
            )
            .unwrap();
        }
        assert!(observe_legacy_mailbox_owner(
            requested,
            &component,
            "foo_bar@example.test",
            &mut found,
        )
        .is_err());
    }

    #[test]
    fn legacy_smtp_alias_proof_separates_interior_dots_and_checks_both_java_mappings() {
        let requested = "user..dots@example.test";
        let writer = legacy_smtp_sanitize_address_for_path(requested);
        let reader = legacy_sanitize_address_for_path(requested);
        assert_eq!(writer, requested);
        assert_eq!(reader, "user__dots@example.test");
        let mut found = false;
        observe_legacy_mailbox_owner(requested, &writer, requested, &mut found).unwrap();
        observe_legacy_mailbox_owner(requested, &writer, &reader, &mut found).unwrap();
        assert!(found);
        assert!(observe_legacy_mailbox_owner(requested, &reader, &reader, &mut found).is_err());

        // A literal leading dot is rewritten by the frozen writer but not its
        // reader. That alternate mapping must still participate in alias proof.
        let requested = "_owner@example.test";
        let component = legacy_smtp_sanitize_address_for_path(requested);
        let mut found = false;
        observe_legacy_mailbox_owner(requested, &component, requested, &mut found).unwrap();
        assert!(
            observe_legacy_mailbox_owner(requested, &component, ".owner@example.test", &mut found,)
                .is_err()
        );
        assert!(found);
    }

    #[test]
    fn v1_alias_requires_registered_owner_and_rejects_literal_java_owner() {
        let requested = "qa@example.test";
        let component = v1_sanitize_address_for_path(requested);
        let mut found = false;
        observe_v1_mailbox_owner(requested, &component, "other@example.test", &mut found).unwrap();
        assert!(!found);
        observe_v1_mailbox_owner(requested, &component, requested, &mut found).unwrap();
        assert!(found);
        assert!(
            observe_v1_mailbox_owner(requested, &component, "v1-qa@example.test", &mut found,)
                .is_err()
        );
    }

    #[test]
    fn attachment_parser_decodes_bounded_mime_content() {
        let message = b"From: sender@example.test\r\n\
To: qa@example.test\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
--x\r\nContent-Type: application/octet-stream; name=fixture.txt\r\n\
Content-Disposition: attachment; filename=fixture.txt\r\n\
Content-Transfer-Encoding: base64\r\n\r\nZml4dHVyZQo=\r\n\
--x--\r\n";
        let attachment = parse_attachment_bytes(message, 0, 1024, 1024).unwrap();
        assert_eq!(attachment.filename, "fixture.txt");
        assert_eq!(
            attachment.content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(attachment.body, b"fixture\n");
        assert!(matches!(
            parse_attachment_bytes(message, 1, 1024, 1024),
            Err(MailboxError::NotFound)
        ));
    }

    #[test]
    fn attachment_parser_enforces_individual_and_total_budgets() {
        let message = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=x\r\n\r\n\
--x\r\nContent-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=one.bin\r\n\r\n1234\r\n\
--x\r\nContent-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=two.bin\r\n\r\n5678\r\n\
--x--\r\n";
        assert!(matches!(
            parse_attachment_bytes(message, 0, 3, 1024),
            Err(MailboxError::TooLarge)
        ));
        assert!(matches!(
            parse_attachment_bytes(message, 0, 1024, 7),
            Err(MailboxError::TooLarge)
        ));
    }
}
