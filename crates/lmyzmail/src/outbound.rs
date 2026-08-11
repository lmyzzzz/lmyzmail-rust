use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    future::Future,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use deadpool_postgres::Pool;
use deadpool_redis::Pool as RedisPool;
use getrandom::fill as fill_random;
use idna::domain_to_ascii_strict;
use mail_parser::MessageParser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    sync::Semaphore,
    task::{JoinHandle, spawn_blocking},
    time::{Instant, MissedTickBehavior, interval, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{AuthError, AuthService, CredentialOutcome},
    config::RuntimeConfig,
    outbound_delivery::{
        OutboundSpoolKind, OutboundSpoolRecord, OutboundSpoolState, parse_recipient_roster_json,
    },
    outbound_message::{
        MaterializedMessage, MessageAttachment, MessageBuildError, MessageInput,
        MessageStorageMode, MessageTextFile, OutboundMessageBuilder, SystemMaterialization,
        java_storage_mode,
    },
    outbound_queue::{DomainStatus, LegacyOutboundQueue, QueueError, TaskDetail},
};

const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const STORAGE_TIMEOUT: Duration = Duration::from_secs(60);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const OUTBOUND_BLOCKING_TASKS: usize = 4;
const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
const RECONCILE_BATCH_SIZE: i64 = 128;
const DEFAULT_MAX_PENDING_TASKS: i64 = 10_000;
const DEFAULT_MAX_RETRIES: i32 = 5;
const DEFAULT_MAX_EMAILS_PER_ACCOUNT: i64 = 100;
const DEFAULT_RATE_WINDOW_HOURS: i64 = 3;
const MAX_RECIPIENTS: usize = 1_000;
const MAX_ATTACHMENTS: usize = 256;
const MAX_ADDRESS_BYTES: usize = 254;
const MAX_SUBJECT_BYTES: usize = 1_000;
const MAX_ATTACHMENT_FILENAME_BYTES: usize = 255;
const MAX_CONTENT_TYPE_BYTES: usize = 255;
const MAX_CONTENT_ID_BYTES: usize = 998;
const MAX_DSN_PREPARED_BYTES: usize = 4 * 1024 * 1024;
const OUTBOUND_ID_ALLOCATION_LOCK: i64 = 0x4c4d_595a_4f49_4441;

#[derive(Debug)]
pub enum OutboundError {
    Database(String),
    InvalidInput(&'static str),
    InvalidCredentials,
    AttachmentTooLarge(String),
    AttachmentsTooLarge,
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
            Self::AttachmentTooLarge(filename) => {
                write!(formatter, "Attachment '{filename}' exceeds size limit")
            }
            Self::AttachmentsTooLarge => {
                formatter.write_str("Total attachments size exceeds limit")
            }
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
    queue: LegacyOutboundQueue,
    message_builder: OutboundMessageBuilder,
    blocking_permits: Arc<Semaphore>,
    domain: Arc<str>,
    max_pending_tasks: i64,
    max_retries: i32,
    max_emails_per_account: i64,
    rate_window: ChronoDuration,
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

#[derive(Debug)]
pub(crate) struct StreamingAttachmentInput {
    pub filename: String,
    pub content_type: Option<String>,
    pub path: PathBuf,
    pub size: u64,
}

/// Caller-owned, trusted temporary text source. Outbound validates and reads
/// the file but never removes it; the stress caller retains cleanup ownership.
#[derive(Debug)]
pub(crate) struct StreamingTextInput {
    pub(crate) path: PathBuf,
    pub(crate) size: u64,
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
    #[serde(skip)]
    pub sent_file_name: String,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub domain_details: Vec<WebDomainStatusResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebDomainStatusResponse {
    pub domain: String,
    pub status: String,
    pub status_description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipients: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
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
    sent_domains_json: Option<String>,
    failed_domains_json: Option<String>,
}

struct ReconcileRow {
    id: i64,
    sender_address: String,
    recipients_json: String,
    subject: Option<String>,
    body_text: Option<String>,
    body_html: Option<String>,
    attachments_json: Option<String>,
    message_id: Option<String>,
    max_retries: i32,
    retry_count: i32,
    sent_file_name: Option<String>,
    sent_subdirectory: Option<i32>,
    created_at: DateTime<Utc>,
    next_retry_at: DateTime<Utc>,
    last_error: Option<String>,
}

enum PersistenceFailure {
    NotCommitted(OutboundError),
    OutcomeUnknown(OutboundError),
}

impl From<OutboundError> for PersistenceFailure {
    fn from(error: OutboundError) -> Self {
        Self::NotCommitted(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitReconciliation {
    Committed,
    NotCommitted,
    OutcomeUnknown,
}

struct DsnAdmissionSource {
    original_task_id: i64,
    lease_token: String,
    expected_sha256: [u8; 32],
}

pub(crate) struct DsnAdmission {
    pub(crate) source_task_id: i64,
    pub(crate) task_id: i64,
    pub(crate) lease_token: String,
    pub(crate) sender: String,
    pub(crate) recipient: String,
    pub(crate) subject: String,
    pub(crate) message_id: String,
    pub(crate) body: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) unsigned_sha256: [u8; 32],
}

struct PersistenceContext<'a> {
    recipients_json: &'a str,
    attachments_json: &'a str,
    to_addresses: &'a str,
    now: DateTime<Utc>,
    dsn_source: Option<&'a DsnAdmissionSource>,
    bypass_sender_quota: bool,
}

impl OutboundService {
    pub fn from_config(
        config: &RuntimeConfig,
        pool: Pool,
        redis_pool: RedisPool,
    ) -> Result<Self, OutboundError> {
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
        let message_builder =
            OutboundMessageBuilder::from_config(config).map_err(map_message_build_error)?;
        Ok(Self {
            pool,
            queue: LegacyOutboundQueue::new(redis_pool),
            message_builder,
            blocking_permits: Arc::new(Semaphore::new(OUTBOUND_BLOCKING_TASKS)),
            domain: Arc::from(config.domain.as_str()),
            max_pending_tasks,
            max_retries,
            max_emails_per_account,
            rate_window: ChronoDuration::hours(rate_window_hours),
            max_attachment_size_bytes: config.limits.max_attachment_size_bytes,
            max_total_attachments_size_bytes: config.limits.max_total_attachments_size_bytes,
        })
    }

    pub(crate) async fn reserve_task_id(&self) -> Result<i64, OutboundError> {
        let mut client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(|error| OutboundError::Database(error.to_string()))?;
        let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(db_error)?;
        timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&OUTBOUND_ID_ALLOCATION_LOCK],
            ),
        )
        .await
        .map_err(|_| OutboundError::Unavailable)?
        .map_err(db_error)?;
        let floor: i64 = timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "WITH sequence_name AS (
                     SELECT pg_get_serial_sequence('outbound_mail_queue','id') AS value
                 )
                 SELECT GREATEST(
                     nextval(value::regclass),
                     (SELECT COALESCE(max(id),0) FROM outbound_mail_queue),
                     (SELECT COALESCE(max(dsn_task_id),0) FROM lmyzmail_outbound_dsn)
                 )
                 FROM sequence_name WHERE value IS NOT NULL",
                &[],
            ),
        )
        .await
        .map_err(|_| OutboundError::Unavailable)?
        .map_err(db_error)?
        .get(0);
        let task_id = self
            .queue
            .reserve_task_id(floor)
            .await
            .map_err(|_| OutboundError::Unavailable)?;
        let advanced: i64 = timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "SELECT setval(
                     pg_get_serial_sequence('outbound_mail_queue','id'),
                     GREATEST(
                         $1,
                         (SELECT COALESCE(max(id),0) FROM outbound_mail_queue),
                         (SELECT COALESCE(max(dsn_task_id),0) FROM lmyzmail_outbound_dsn)
                     ),
                     true
                 )",
                &[&task_id],
            ),
        )
        .await
        .map_err(|_| OutboundError::Unavailable)?
        .map_err(db_error)?
        .get(0);
        if advanced < task_id {
            return Err(OutboundError::Unavailable);
        }
        timeout(DATABASE_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(db_error)?;
        Ok(task_id)
    }

    pub async fn enqueue(
        &self,
        request: SendRequest,
        credentials: Option<(&AuthService, &str)>,
    ) -> Result<QueueResponse, OutboundError> {
        self.enqueue_with_cancellation(request, credentials, &CancellationToken::new())
            .await
    }

    pub(crate) async fn enqueue_with_cancellation(
        &self,
        request: SendRequest,
        credentials: Option<(&AuthService, &str)>,
        cancellation: &CancellationToken,
    ) -> Result<QueueResponse, OutboundError> {
        self.enqueue_inner(request, credentials, None, None, false, cancellation)
            .await
    }

    pub(crate) async fn enqueue_stress_with_cancellation(
        &self,
        request: SendRequest,
        cancellation: &CancellationToken,
    ) -> Result<QueueResponse, OutboundError> {
        self.enqueue_inner(request, None, None, None, true, cancellation)
            .await
    }

    pub(crate) async fn enqueue_stress_streaming_text_with_cancellation(
        &self,
        request: SendRequest,
        text: StreamingTextInput,
        cancellation: &CancellationToken,
    ) -> Result<QueueResponse, OutboundError> {
        self.enqueue_inner(request, None, None, Some(text), true, cancellation)
            .await
    }

    pub(crate) async fn enqueue_streaming_with_cancellation(
        &self,
        request: SendRequest,
        attachments: Vec<StreamingAttachmentInput>,
        cancellation: &CancellationToken,
    ) -> Result<QueueResponse, OutboundError> {
        self.enqueue_inner(request, None, Some(attachments), None, false, cancellation)
            .await
    }

    async fn enqueue_inner(
        &self,
        request: SendRequest,
        credentials: Option<(&AuthService, &str)>,
        streaming_attachments: Option<Vec<StreamingAttachmentInput>>,
        streaming_text: Option<StreamingTextInput>,
        bypass_sender_quota: bool,
        cancellation: &CancellationToken,
    ) -> Result<QueueResponse, OutboundError> {
        if request.asynchronous == Some(false) {
            return Err(OutboundError::SynchronousUnsupported);
        }
        let SendRequest {
            from,
            password,
            to,
            cc,
            bcc,
            subject,
            text,
            html,
            attachments,
            ..
        } = request;
        let sender = normalize_address(
            from.as_deref()
                .ok_or(OutboundError::InvalidInput("from_required"))?,
        )?;
        if sender.rsplit_once('@').map(|(_, value)| value) != Some(self.domain.as_ref()) {
            return Err(OutboundError::InvalidInput("sending_not_allowed"));
        }
        if credentials.is_some()
            && password
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(OutboundError::InvalidInput("password_required"));
        }
        let recipients = ValidatedRecipients::new(to, cc, bcc)?;
        let subject = sanitize_subject(
            subject
                .as_deref()
                .ok_or(OutboundError::InvalidInput("subject_required"))?,
        )?;
        if streaming_text.is_some() && text.is_some() {
            return Err(OutboundError::InvalidInput(
                "conflicting_outbound_text_sources",
            ));
        }
        if streaming_text.is_none()
            && text.as_deref().is_none_or(|value| value.trim().is_empty())
            && html.as_deref().is_none_or(|value| value.trim().is_empty())
        {
            return Err(OutboundError::InvalidInput("body_required"));
        }
        let text_file = streaming_text.map(|source| MessageTextFile::new(source.path, source.size));
        let attachments = match streaming_attachments {
            Some(attachments) => self.validate_streaming_attachments(attachments)?,
            None => self.validate_attachments(attachments)?,
        };
        let recipients_json =
            serde_json::to_string(&recipients).map_err(|_| OutboundError::Unavailable)?;
        if let Some((auth, client_ip)) = credentials {
            let password = password.as_deref().unwrap_or_default();
            match auth
                .verify_mailbox_credentials_with_cancellation(
                    &sender,
                    password,
                    client_ip,
                    cancellation,
                )
                .await
                .map_err(map_auth_error)?
            {
                CredentialOutcome::Valid { .. } => {}
                CredentialOutcome::Invalid { .. } => {
                    return Err(OutboundError::InvalidCredentials);
                }
            }
        }
        let now = postgres_timestamp(Utc::now());
        let message_id = new_message_id(self.domain.as_ref())?;
        let queue_id = self.reserve_task_id().await?;
        let input = MessageInput {
            task_id: queue_id,
            sender,
            to: recipients.to,
            cc: recipients.cc,
            bcc: recipients.bcc,
            subject,
            text,
            text_file,
            html,
            attachments,
            message_id: message_id.clone(),
            created_at: now,
        };
        let (materialized, input) = self.materialize_message(input, cancellation).await?;
        let attachments_json =
            serde_json::to_string(&input.attachments).map_err(|_| OutboundError::Unavailable)?;
        let to_addresses = index_to_addresses(&input.to)?;
        let domain_statuses = pending_domain_statuses(&input, now)?;

        let persistence = self
            .persist_materialized(
                &input,
                &materialized,
                PersistenceContext {
                    recipients_json: &recipients_json,
                    attachments_json: &attachments_json,
                    to_addresses: &to_addresses,
                    now,
                    dsn_source: None,
                    bypass_sender_quota,
                },
                cancellation,
            )
            .await;
        if let Err(error) = persistence {
            return match error {
                PersistenceFailure::NotCommitted(error) => {
                    self.rollback_materialized(materialized).await;
                    Err(error)
                }
                PersistenceFailure::OutcomeUnknown(error) => {
                    eprintln!(
                        "lmyzmail outbound commit outcome is unknown; preserving materialized message"
                    );
                    Err(error)
                }
            };
        }

        let message_file_path = if materialized.signed_content_base64.is_none() {
            Some(
                materialized
                    .spool_path
                    .to_str()
                    .ok_or(OutboundError::Unavailable)?
                    .to_owned(),
            )
        } else {
            None
        };
        let task = TaskDetail {
            id: queue_id,
            sender_address: input.sender,
            recipients_json,
            subject: input.subject,
            message_id: input.message_id,
            max_retries: self.max_retries,
            retry_count: 0,
            sent_file_name: Some(materialized.sent_file_name.clone()),
            sent_subdirectory: Some(materialized.sent_subdirectory),
            message_file_path,
            signed_content_base64: materialized.signed_content_base64.clone(),
            created_at: instant(now),
            next_retry_at: None,
            last_error: None,
            status: "PENDING".into(),
        };
        self.publish_with_reconciliation(&task, &domain_statuses, cancellation)
            .await?;
        self.cleanup_published(task.id, task.sender_address.clone(), materialized.clone())
            .await;
        Ok(QueueResponse {
            queued: true,
            queue_id,
            message_id,
            status: "PENDING",
            error: None,
            sent_file_name: materialized.sent_file_name,
        })
    }

    /// Admit a generated DSN through the exact same PostgreSQL queue/index/
    /// spool transaction as user mail.  The source-task outbox row is updated
    /// in that transaction, so a process crash cannot create two local DSNs.
    pub(crate) async fn admit_dsn(
        &self,
        admission: DsnAdmission,
        cancellation: &CancellationToken,
    ) -> Result<QueueResponse, OutboundError> {
        let DsnAdmission {
            source_task_id,
            task_id,
            lease_token,
            sender,
            recipient,
            subject,
            message_id,
            body,
            created_at,
            unsigned_sha256,
        } = admission;
        if source_task_id <= 0
            || task_id <= 0
            || lease_token.is_empty()
            || lease_token.len() > 100
            || sender.is_empty()
            || recipient.is_empty()
            || body.is_empty()
            || body.len() > 2 * 1024 * 1024
        {
            return Err(OutboundError::InvalidInput("invalid_dsn_message"));
        }
        let digest = Sha256::digest(body.as_bytes());
        if digest.as_slice() != unsigned_sha256 {
            return Err(OutboundError::InvalidInput("invalid_dsn_digest"));
        }
        let storage_mode =
            java_storage_mode(Some(&body), None, &[]).map_err(map_message_build_error)?;
        let prepare_builder = self.message_builder.clone();
        let body_for_signing = body.clone();
        let prepared_bytes = self
            .run_dsn_blocking(cancellation, move |cancelled| {
                prepare_builder.prepare_system_bytes(
                    created_at,
                    body_for_signing.as_bytes(),
                    &unsigned_sha256,
                    cancelled,
                )
            })
            .await?;
        let prepared_sha256: [u8; 32] = Sha256::digest(&prepared_bytes).into();
        let (durable_sha256, durable_bytes) = self
            .checkpoint_dsn_material(
                source_task_id,
                &lease_token,
                prepared_sha256,
                &prepared_bytes,
            )
            .await?;
        if cancellation.is_cancelled() {
            return Err(OutboundError::Unavailable);
        }
        let builder = self.message_builder.clone();
        let sender_for_storage = sender.clone();
        let materialized = self
            .run_dsn_blocking(cancellation, move |cancelled| {
                builder.materialize_bytes(
                    SystemMaterialization {
                        task_id,
                        sender: &sender_for_storage,
                        created_at,
                        bytes: &durable_bytes,
                        storage_mode,
                        expected_sha256: &durable_sha256,
                    },
                    cancelled,
                )
            })
            .await?;
        let input = MessageInput {
            task_id,
            sender,
            to: vec![recipient.clone()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject,
            text: Some(body),
            text_file: None,
            html: None,
            attachments: Vec::new(),
            message_id,
            created_at,
        };
        let recipients_json = format!(
            r#"{{"to":[{}],"cc":[],"bcc":[]}}"#,
            serde_json::to_string(&recipient).map_err(|_| OutboundError::Unavailable)?
        );
        let domain_statuses = pending_domain_statuses(&input, created_at)?;
        if cancellation.is_cancelled() {
            return Err(OutboundError::Unavailable);
        }
        let dsn_source = DsnAdmissionSource {
            original_task_id: source_task_id,
            lease_token,
            expected_sha256: durable_sha256,
        };
        let persistence = self
            .persist_materialized(
                &input,
                &materialized,
                PersistenceContext {
                    recipients_json: &recipients_json,
                    attachments_json: "[]",
                    to_addresses: &recipient,
                    now: created_at,
                    dsn_source: Some(&dsn_source),
                    bypass_sender_quota: true,
                },
                cancellation,
            )
            .await;
        if let Err(error) = persistence {
            return match error {
                // System-message paths are deterministic and authenticated.
                // A newer lease may already have committed the same bytes, so
                // a stale worker must never unlink them during rollback.
                PersistenceFailure::NotCommitted(error) => Err(error),
                PersistenceFailure::OutcomeUnknown(error) => {
                    eprintln!(
                        "lmyzmail DSN commit outcome is unknown; preserving materialized message"
                    );
                    Err(error)
                }
            };
        }
        if cancellation.is_cancelled() {
            return Err(OutboundError::Unavailable);
        }
        let message_file_path = if materialized.signed_content_base64.is_none() {
            Some(
                materialized
                    .spool_path
                    .to_str()
                    .ok_or(OutboundError::Unavailable)?
                    .to_owned(),
            )
        } else {
            None
        };
        let task = TaskDetail {
            id: task_id,
            sender_address: input.sender,
            recipients_json,
            subject: input.subject,
            message_id: input.message_id,
            max_retries: self.max_retries,
            retry_count: 0,
            sent_file_name: Some(materialized.sent_file_name.clone()),
            sent_subdirectory: Some(materialized.sent_subdirectory),
            message_file_path,
            signed_content_base64: materialized.signed_content_base64.clone(),
            created_at: instant(created_at),
            next_retry_at: None,
            last_error: None,
            status: "PENDING".into(),
        };
        self.publish_with_reconciliation(&task, &domain_statuses, cancellation)
            .await?;
        self.cleanup_published(task_id, task.sender_address.clone(), materialized)
            .await;
        Ok(QueueResponse {
            queued: true,
            queue_id: task_id,
            message_id: task.message_id,
            status: "PENDING",
            error: None,
            sent_file_name: task.sent_file_name.unwrap_or_default(),
        })
    }

    /// Re-publish DSNs whose PostgreSQL queue row committed but whose Redis
    /// publication was interrupted by a crash. Only PENDING rows are eligible;
    /// PROCESSING rows remain fenced to their active coordinator.
    pub async fn republish_admitted_dsns(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<usize, OutboundError> {
        let client = tokio::select! {
            _ = cancellation.cancelled() => return Err(OutboundError::Unavailable),
            result = timeout(DATABASE_TIMEOUT, self.pool.get()) => result
                .map_err(|_| OutboundError::Unavailable)?
                .map_err(|error| OutboundError::Database(error.to_string()))?,
        };
        let rows = tokio::select! {
            _ = cancellation.cancelled() => return Err(OutboundError::Unavailable),
            result = timeout(
                DATABASE_TIMEOUT,
                client.query(
                    "SELECT d.dsn_task_id,d.expected_sha256,
                            q.sender_address,q.recipients_json,q.subject,q.message_id,
                            q.max_retries,q.retry_count,q.sent_file_name,q.sent_subdirectory,
                            q.created_at,q.body_text,q.body_html,q.attachments_json
                     FROM lmyzmail_outbound_dsn d
                     JOIN outbound_mail_queue q ON q.id=d.dsn_task_id
                     WHERE d.state='ADMITTED' AND q.status='PENDING'
                     ORDER BY d.dsn_task_id
                     LIMIT 128",
                    &[],
                ),
            ) => result
                .map_err(|_| OutboundError::Unavailable)?
                .map_err(db_error)?,
        };
        let mut republished = 0;
        for row in rows {
            if cancellation.is_cancelled() {
                return Err(OutboundError::Unavailable);
            }
            let task_id: i64 = row.get(0);
            let expected: Vec<u8> = row.get(1);
            let expected: [u8; 32] = expected
                .try_into()
                .map_err(|_| OutboundError::Unavailable)?;
            let sender: String = row.get(2);
            let recipients_json: String = row.get(3);
            let subject: String = row.get::<_, Option<String>>(4).unwrap_or_default();
            let message_id: String = row
                .get::<_, Option<String>>(5)
                .ok_or(OutboundError::Unavailable)?;
            let max_retries: i32 = row.get(6);
            let retry_count: i32 = row.get(7);
            let sent_file_name: String = row
                .get::<_, Option<String>>(8)
                .ok_or(OutboundError::Unavailable)?;
            let sent_subdirectory: i32 = row
                .get::<_, Option<i32>>(9)
                .ok_or(OutboundError::Unavailable)?;
            let created_at: DateTime<Utc> = row.get(10);
            let body_text: Option<String> = row.get(11);
            let body_html: Option<String> = row.get(12);
            let attachments_json: String = row
                .get::<_, Option<String>>(13)
                .unwrap_or_else(|| "[]".to_owned());
            let attachments: Vec<MessageAttachment> =
                serde_json::from_str(&attachments_json).map_err(|_| OutboundError::Unavailable)?;
            let storage_mode =
                java_storage_mode(body_text.as_deref(), body_html.as_deref(), &attachments)
                    .map_err(map_message_build_error)?;
            let builder = self.message_builder.clone();
            let sender_for_recovery = sender.clone();
            let materialized = self
                .run_dsn_blocking(cancellation, move |cancelled| {
                    builder.recover(
                        task_id,
                        &sender_for_recovery,
                        &sent_file_name,
                        sent_subdirectory,
                        storage_mode,
                        cancelled,
                    )
                })
                .await?;
            let persisted = if let Some(encoded) = materialized.signed_content_base64.as_deref() {
                BASE64_STANDARD
                    .decode(encoded)
                    .map_err(|_| OutboundError::Unavailable)?
            } else {
                fs::read(&materialized.spool_path).map_err(|_| OutboundError::Unavailable)?
            };
            if Sha256::digest(&persisted).as_slice() != expected {
                return Err(OutboundError::Unavailable);
            }
            let recipients = parse_recipient_roster_json(&recipients_json)
                .map_err(|_| OutboundError::Unavailable)?;
            let domains =
                pending_domain_statuses_for_recipients(&recipients, &[], &[], created_at)?;
            let task = TaskDetail {
                id: task_id,
                sender_address: sender,
                recipients_json,
                subject,
                message_id,
                max_retries,
                retry_count,
                sent_file_name: Some(materialized.sent_file_name.clone()),
                sent_subdirectory: Some(materialized.sent_subdirectory),
                message_file_path: materialized
                    .signed_content_base64
                    .is_none()
                    .then(|| materialized.spool_path.to_string_lossy().into_owned()),
                signed_content_base64: materialized.signed_content_base64.clone(),
                created_at: instant(created_at),
                next_retry_at: None,
                last_error: None,
                status: "PENDING".to_owned(),
            };
            if cancellation.is_cancelled() {
                return Err(OutboundError::Unavailable);
            }
            self.publish_with_reconciliation(&task, &domains, cancellation)
                .await?;
            self.cleanup_published(task_id, task.sender_address.clone(), materialized)
                .await;
            republished += 1;
        }
        Ok(republished)
    }

    async fn run_dsn_blocking<T, F>(
        &self,
        cancellation: &CancellationToken,
        build: F,
    ) -> Result<T, OutboundError>
    where
        T: Send + 'static,
        F: FnOnce(&AtomicBool) -> Result<T, MessageBuildError> + Send + 'static,
    {
        run_bounded_message_task(
            Arc::clone(&self.blocking_permits),
            cancellation,
            STORAGE_TIMEOUT,
            build,
        )
        .await
    }

    pub(crate) async fn checkpoint_dsn_material(
        &self,
        original_task_id: i64,
        lease_token: &str,
        proposed_sha256: [u8; 32],
        proposed_bytes: &[u8],
    ) -> Result<([u8; 32], Vec<u8>), OutboundError> {
        if proposed_bytes.is_empty()
            || proposed_bytes.len() > MAX_DSN_PREPARED_BYTES
            || Sha256::digest(proposed_bytes).as_slice() != proposed_sha256
        {
            return Err(OutboundError::InvalidInput("invalid_dsn_prepared_message"));
        }
        let client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(|error| OutboundError::Database(error.to_string()))?;
        let row = timeout(
            DATABASE_TIMEOUT,
            client.query_opt(
                "UPDATE lmyzmail_outbound_dsn
                 SET expected_sha256=COALESCE(expected_sha256,$3),
                     prepared_bytes=COALESCE(prepared_bytes,$4),
                     updated_at=clock_timestamp()
                 WHERE original_task_id=$1 AND state='ADMITTING'
                   AND lease_token=$2 AND lease_until > clock_timestamp()
                 RETURNING expected_sha256,prepared_bytes",
                &[
                    &original_task_id,
                    &lease_token,
                    &&proposed_sha256[..],
                    &proposed_bytes,
                ],
            ),
        )
        .await
        .map_err(|_| OutboundError::Unavailable)?
        .map_err(db_error)?
        .ok_or(OutboundError::Unavailable)?;
        let digest: Vec<u8> = row.get(0);
        let digest: [u8; 32] = digest.try_into().map_err(|_| OutboundError::Unavailable)?;
        let bytes: Vec<u8> = row.get(1);
        if bytes.is_empty()
            || bytes.len() > MAX_DSN_PREPARED_BYTES
            || Sha256::digest(&bytes).as_slice() != digest
        {
            return Err(OutboundError::Unavailable);
        }
        Ok((digest, bytes))
    }

    async fn materialize_message(
        &self,
        mut input: MessageInput,
        cancellation: &CancellationToken,
    ) -> Result<(MaterializedMessage, MessageInput), OutboundError> {
        let builder = self.message_builder.clone();
        let (result, input) = run_bounded_message_task(
            Arc::clone(&self.blocking_permits),
            cancellation,
            STORAGE_TIMEOUT,
            move |cancelled| {
                let result = builder.materialize(&input, cancelled).and_then(|message| {
                    if let Err(error) = builder.materialize_persistence_text(&mut input, cancelled)
                    {
                        let _ = builder.rollback_unpublished(&message);
                        return Err(error);
                    }
                    Ok(message)
                });
                if cancelled.load(Ordering::Acquire)
                    && let Ok(message) = result.as_ref()
                {
                    let _ = builder.rollback_unpublished(message);
                    return Ok((Err(MessageBuildError::Cancelled), input));
                }
                Ok((result, input))
            },
        )
        .await?;
        result
            .map(|materialized| (materialized, input))
            .map_err(map_message_build_error)
    }

    async fn persist_materialized(
        &self,
        input: &MessageInput,
        materialized: &MaterializedMessage,
        context: PersistenceContext<'_>,
        cancellation: &CancellationToken,
    ) -> Result<(), PersistenceFailure> {
        let PersistenceContext {
            recipients_json,
            attachments_json,
            to_addresses,
            now,
            dsn_source,
            bypass_sender_quota,
        } = context;
        let message_bytes = i64::try_from(materialized.message_bytes)
            .map_err(|_| OutboundError::InvalidInput("email_too_large"))?;
        let mut client = cancellable_db_call(cancellation, self.pool.get(), |error| {
            OutboundError::Database(error.to_string())
        })
        .await?;
        let transaction = cancellable_db_call(cancellation, client.transaction(), db_error).await?;
        for lock_name in ["lmyzmail:outbound:queue", input.sender.as_str()] {
            cancellable_db_call(
                cancellation,
                transaction.query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
                    &[&lock_name],
                ),
                db_error,
            )
            .await?;
        }
        let pending_rows = cancellable_db_call(
            cancellation,
            transaction.query(
                "SELECT id FROM outbound_mail_queue
                 WHERE status IN ('PENDING','PROCESSING') LIMIT $1",
                &[&(self.max_pending_tasks + 1)],
            ),
            db_error,
        )
        .await?;
        let mut active_ids = pending_rows
            .into_iter()
            .map(|row| row.get::<_, i64>(0).to_string())
            .collect::<BTreeSet<_>>();
        let active_redis = tokio::select! {
            _ = cancellation.cancelled() => return Err(OutboundError::Unavailable.into()),
            result = timeout(
                DATABASE_TIMEOUT,
                self.queue.active_task_ids(self.max_pending_tasks as usize + 1),
            ) => result
                .map_err(|_| OutboundError::Unavailable)?
                .map_err(|_| OutboundError::Unavailable)?,
        };
        active_ids.extend(active_redis);
        if active_ids.len() >= self.max_pending_tasks as usize {
            return Err(OutboundError::QueueFull.into());
        }
        if dsn_source.is_none() && !bypass_sender_quota {
            let window_start = now - self.rate_window;
            let used: i64 = cancellable_db_call(
                cancellation,
                transaction.query_one(
                    "SELECT count(*) FROM outbound_mail_queue WHERE sender_address=$1 AND created_at >= $2",
                    &[&input.sender, &window_start],
                ),
                db_error,
            )
            .await?
            .get(0);
            if used >= self.max_emails_per_account {
                return Err(OutboundError::RateLimited { remaining: 0 }.into());
            }
        }
        let next_retry_at = now;
        let row = cancellable_db_call(
            cancellation,
            transaction.query_one(
                "INSERT INTO outbound_mail_queue
                 (id,sender_address,recipients_json,subject,body_text,body_html,attachments_json,
                  message_id,sent_file_name,sent_subdirectory,status,retry_count,max_retries,
                  next_retry_at,last_error,sent_domains_json,failed_domains_json,created_at,
                  updated_at,sent_at,processing_started_at,processor_id)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'PENDING',0,$11,$12,NULL,'[]','{}',$13,$13,NULL,NULL,NULL)
                 RETURNING id",
                &[
                    &input.task_id,
                    &input.sender,
                    &recipients_json,
                    &input.subject,
                    &input.text,
                    &input.html,
                    &attachments_json,
                    &input.message_id,
                    &materialized.sent_file_name,
                    &materialized.sent_subdirectory,
                    &self.max_retries,
                    &next_retry_at,
                    &now,
                ],
            ),
            db_error,
        )
        .await?;
        if row.get::<_, i64>(0) != input.task_id {
            return Err(OutboundError::Unavailable.into());
        }
        cancellable_db_call(
            cancellation,
            transaction.query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&OUTBOUND_ID_ALLOCATION_LOCK],
            ),
            db_error,
        )
        .await?;
        let sequence_row = cancellable_db_call(
            cancellation,
            transaction.query_one(
                "WITH sequence_name AS (
                     SELECT pg_get_serial_sequence('outbound_mail_queue','id') AS value
                 )
                 SELECT setval(
                     value,
                     GREATEST(
                         $1,
                         nextval(value::regclass),
                         (SELECT COALESCE(max(id),0) FROM outbound_mail_queue),
                         (SELECT COALESCE(max(dsn_task_id),0) FROM lmyzmail_outbound_dsn)
                     ),
                     true
                 )
                 FROM sequence_name WHERE value IS NOT NULL",
                &[&input.task_id],
            ),
            db_error,
        )
        .await?;
        if sequence_row.get::<_, Option<i64>>(0).is_none() {
            return Err(OutboundError::Unavailable.into());
        }
        let spool_path = materialized
            .spool_path
            .to_str()
            .ok_or(OutboundError::Unavailable)?;
        cancellable_db_call(
            cancellation,
            transaction.execute(
                "INSERT INTO lmyzmail_outbound_spool
                 (task_id,spool_path,spool_kind,cleanup_state,cleanup_after_publish,
                  created_at,updated_at)
                 VALUES ($1,$2,'RUST','OWNED',$3,$4,$4)",
                &[
                    &input.task_id,
                    &spool_path,
                    &materialized.cleanup_spool_after_publish,
                    &now,
                ],
            ),
            db_error,
        )
        .await?;
        cancellable_db_call(
            cancellation,
            transaction.execute(
                "INSERT INTO email_index
                 (has_attachments,subdirectory,indexed_at,received_at,size_bytes,folder,
                  from_address,message_id,subject,to_addresses,file_name,mailbox_address)
                 VALUES ($1,$2,$3,$3,$4,'sent',$5,$6,$7,$8,$9,$5)",
                &[
                    &(!input.attachments.is_empty()),
                    &materialized.sent_subdirectory,
                    &now,
                    &message_bytes,
                    &input.sender,
                    &input.message_id,
                    &input.subject,
                    &to_addresses,
                    &materialized.sent_file_name,
                ],
            ),
            db_error,
        )
        .await?;
        if let Some(source) = dsn_source {
            let updated = cancellable_db_call(
                cancellation,
                transaction.execute(
                    "UPDATE lmyzmail_outbound_dsn
                     SET state='ADMITTED',prepared_bytes=NULL,lease_token=NULL,
                         lease_until=NULL,updated_at=$5
                     WHERE original_task_id=$1 AND dsn_task_id=$2 AND state='ADMITTING'
                       AND expected_sha256=$3
                       AND lease_token=$4 AND lease_until > clock_timestamp()",
                    &[
                        &source.original_task_id,
                        &input.task_id,
                        &&source.expected_sha256[..],
                        &source.lease_token,
                        &now,
                    ],
                ),
                db_error,
            )
            .await?;
            if updated != 1 {
                return Err(OutboundError::Unavailable.into());
            }
        }
        if cancellation.is_cancelled() {
            return Err(OutboundError::Unavailable.into());
        }
        let commit_error = match timeout(DATABASE_TIMEOUT, transaction.commit()).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => db_error(error),
            Err(_) => OutboundError::Unavailable,
        };
        // A second transaction orders reconciliation behind this transaction's
        // advisory lock, even when the COMMIT response was lost.
        match self
            .reconcile_commit(
                input,
                recipients_json,
                attachments_json,
                to_addresses,
                materialized,
                message_bytes,
                now,
                dsn_source,
            )
            .await
        {
            CommitReconciliation::Committed => Ok(()),
            CommitReconciliation::NotCommitted => {
                Err(PersistenceFailure::NotCommitted(commit_error))
            }
            CommitReconciliation::OutcomeUnknown => {
                Err(PersistenceFailure::OutcomeUnknown(commit_error))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn reconcile_commit(
        &self,
        input: &MessageInput,
        recipients_json: &str,
        attachments_json: &str,
        to_addresses: &str,
        materialized: &MaterializedMessage,
        message_bytes: i64,
        now: DateTime<Utc>,
        dsn_source: Option<&DsnAdmissionSource>,
    ) -> CommitReconciliation {
        let deadline = Instant::now() + DATABASE_TIMEOUT;
        let mut client = match timeout_at(deadline, self.pool.get()).await {
            Ok(Ok(client)) => client,
            _ => {
                eprintln!(
                    "lmyzmail outbound commit reconciliation could not acquire a database connection"
                );
                return CommitReconciliation::OutcomeUnknown;
            }
        };
        let transaction = match timeout_at(deadline, client.transaction()).await {
            Ok(Ok(transaction)) => transaction,
            _ => {
                eprintln!(
                    "lmyzmail outbound commit reconciliation could not start a database transaction"
                );
                return CommitReconciliation::OutcomeUnknown;
            }
        };
        // The admission transaction holds this lock until its COMMIT or
        // ROLLBACK has completed on the server. A fresh statement after this
        // wait gets a new Read Committed snapshot that can safely classify the
        // otherwise unknown commit outcome.
        if !matches!(
            timeout_at(
                deadline,
                transaction.query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
                    &[&"lmyzmail:outbound:queue"],
                ),
            )
            .await,
            Ok(Ok(_))
        ) {
            eprintln!("lmyzmail outbound commit reconciliation could not order behind admission");
            return CommitReconciliation::OutcomeUnknown;
        }
        let spool_path = match materialized.spool_path.to_str() {
            Some(path) => path,
            None => return CommitReconciliation::OutcomeUnknown,
        };
        let row = match timeout_at(
            deadline,
            transaction.query_one(
                "/* lmyzmail_commit_reconciliation */
                 SELECT
                   EXISTS (
                     SELECT 1 FROM outbound_mail_queue q
                     WHERE q.id=$1 AND q.sender_address=$2 AND q.recipients_json=$3
                       AND q.subject IS NOT DISTINCT FROM $4
                       AND q.body_text IS NOT DISTINCT FROM $5
                       AND q.body_html IS NOT DISTINCT FROM $6
                       AND q.attachments_json IS NOT DISTINCT FROM $7
                       AND q.message_id IS NOT DISTINCT FROM $8
                       AND q.sent_file_name IS NOT DISTINCT FROM $9
                       AND q.sent_subdirectory IS NOT DISTINCT FROM $10
                       AND q.max_retries=$11 AND q.created_at=$12
                   ),
                   EXISTS (
                     SELECT 1 FROM outbound_mail_queue q
                     WHERE q.id=$1 OR q.message_id=$8
                        OR (q.sender_address=$2 AND q.sent_file_name=$9
                            AND q.sent_subdirectory=$10)
                   ),
                   EXISTS (
                     SELECT 1 FROM email_index i
                     WHERE i.mailbox_address=$2 AND i.folder='sent'
                       AND i.subdirectory IS NOT DISTINCT FROM $10
                       AND i.file_name=$9
                       AND i.has_attachments=$13 AND i.indexed_at=$12
                       AND i.received_at=$12 AND i.size_bytes=$14
                       AND i.from_address IS NOT DISTINCT FROM $2
                       AND i.message_id IS NOT DISTINCT FROM $8
                       AND i.subject IS NOT DISTINCT FROM $4
                       AND i.to_addresses IS NOT DISTINCT FROM $15
                   ),
                   EXISTS (
                     SELECT 1 FROM email_index i
                     WHERE i.message_id=$8
                        OR (i.mailbox_address=$2 AND i.folder='sent'
                            AND i.subdirectory IS NOT DISTINCT FROM $10
                            AND i.file_name=$9)
                   ),
                   EXISTS (
                     SELECT 1 FROM lmyzmail_outbound_spool s
                     WHERE s.task_id=$1 AND s.spool_path=$16 AND s.spool_kind='RUST'
                       AND s.cleanup_state='OWNED' AND s.cleanup_after_publish=$20
                   ),
                   EXISTS (
                     SELECT 1 FROM lmyzmail_outbound_spool s
                     WHERE s.task_id=$1 OR s.spool_path=$16
                   ),
                   EXISTS (
                     SELECT 1 FROM lmyzmail_outbound_dsn d
                     WHERE d.original_task_id=$17 AND d.dsn_task_id=$1
                       AND d.state='ADMITTED' AND d.expected_sha256=$18
                       AND d.prepared_bytes IS NULL
                       AND d.lease_token IS NULL AND d.lease_until IS NULL
                   ),
                   EXISTS (
                     SELECT 1 FROM lmyzmail_outbound_dsn d
                     WHERE d.original_task_id=$17 AND d.dsn_task_id=$1
                       AND d.state='ADMITTING' AND d.expected_sha256=$18
                       AND d.prepared_bytes IS NOT NULL
                       AND d.lease_token=$19 AND d.lease_until IS NOT NULL
                   )",
                &[
                    &input.task_id,
                    &input.sender,
                    &recipients_json,
                    &input.subject,
                    &input.text,
                    &input.html,
                    &attachments_json,
                    &input.message_id,
                    &materialized.sent_file_name,
                    &materialized.sent_subdirectory,
                    &self.max_retries,
                    &now,
                    &(!input.attachments.is_empty()),
                    &message_bytes,
                    &to_addresses,
                    &spool_path,
                    &dsn_source.map_or(0, |source| source.original_task_id),
                    &&dsn_source.map_or([0_u8; 32], |source| source.expected_sha256)[..],
                    &dsn_source.map_or("", |source| source.lease_token.as_str()),
                    &materialized.cleanup_spool_after_publish,
                ],
            ),
        )
        .await
        {
            Ok(Ok(row)) => row,
            _ => {
                eprintln!("lmyzmail outbound commit reconciliation query failed");
                return CommitReconciliation::OutcomeUnknown;
            }
        };
        let _ = timeout_at(deadline, transaction.commit()).await;
        let queue_exact: bool = row.get(0);
        let queue_identity_exists: bool = row.get(1);
        let index_exact: bool = row.get(2);
        let index_identity_exists: bool = row.get(3);
        let spool_exact: bool = row.get(4);
        let spool_identity_exists: bool = row.get(5);
        let dsn_admitted_exact: bool = row.get(6);
        let dsn_admitting_exact: bool = row.get(7);
        let spool_consistent = spool_exact;
        let dsn_committed = dsn_source.is_none() || dsn_admitted_exact;
        let dsn_not_committed = dsn_source.is_none() || dsn_admitting_exact;
        if queue_exact && index_exact && spool_consistent && dsn_committed {
            CommitReconciliation::Committed
        } else if !queue_identity_exists
            && !index_identity_exists
            && !spool_identity_exists
            && dsn_not_committed
        {
            CommitReconciliation::NotCommitted
        } else {
            // Partial or conflicting durable state cannot prove that deleting either file is safe.
            CommitReconciliation::OutcomeUnknown
        }
    }

    async fn rollback_materialized(&self, materialized: MaterializedMessage) {
        let Ok(Ok(permit)) = timeout(
            STORAGE_TIMEOUT,
            self.blocking_permits.clone().acquire_owned(),
        )
        .await
        else {
            eprintln!("lmyzmail outbound rollback could not acquire a blocking slot");
            return;
        };
        let builder = self.message_builder.clone();
        let task = spawn_blocking(move || {
            let _permit = permit;
            builder.rollback_unpublished(&materialized)
        });
        match await_blocking_io(
            task,
            STORAGE_TIMEOUT,
            "lmyzmail outbound rollback exceeded its soft deadline; waiting for filesystem ownership recovery",
        )
        .await
        {
            Ok(Ok(())) => {}
            _ => eprintln!("lmyzmail outbound unpublished-message rollback failed"),
        }
    }

    async fn publish_with_reconciliation(
        &self,
        task: &TaskDetail,
        domains: &BTreeMap<String, DomainStatus>,
        cancellation: &CancellationToken,
    ) -> Result<(), OutboundError> {
        for attempt in 0..2 {
            let published = tokio::select! {
                _ = cancellation.cancelled() => return Err(OutboundError::Unavailable),
                result = self.queue.publish_bounded(
                    task,
                    domains,
                    self.max_pending_tasks as usize,
                ) => result,
            };
            match published {
                Ok(_) => return Ok(()),
                Err(QueueError::OutcomeUnknown) => {
                    let sent_file_name = task
                        .sent_file_name
                        .as_deref()
                        .ok_or(OutboundError::Unavailable)?;
                    let complete = tokio::select! {
                        _ = cancellation.cancelled() => return Err(OutboundError::Unavailable),
                        result = self.queue.is_complete_task(task.id, sent_file_name) => result,
                    };
                    if matches!(complete, Ok(true)) {
                        return Ok(());
                    }
                    if attempt == 0 {
                        continue;
                    }
                }
                Err(_) => return Err(OutboundError::Unavailable),
            }
        }
        Err(OutboundError::Unavailable)
    }

    async fn cleanup_published(
        &self,
        task_id: i64,
        sender_address: String,
        materialized: MaterializedMessage,
    ) {
        if !materialized.cleanup_spool_after_publish {
            return;
        }
        let spool_path = match materialized.spool_path.to_str() {
            Some(path) => path.to_owned(),
            None => {
                eprintln!("lmyzmail outbound published spool path is not UTF-8");
                return;
            }
        };
        let record = OutboundSpoolRecord {
            task_id,
            spool_path: spool_path.clone(),
            kind: OutboundSpoolKind::Rust,
            state: OutboundSpoolState::Owned,
            sender_address,
            sent_file_name: materialized.sent_file_name.clone(),
            sent_subdirectory: materialized.sent_subdirectory,
        };
        let Ok(Ok(permit)) = timeout(
            CLEANUP_TIMEOUT,
            self.blocking_permits.clone().acquire_owned(),
        )
        .await
        else {
            eprintln!("lmyzmail outbound spool cleanup could not acquire a blocking slot");
            return;
        };
        let builder = self.message_builder.clone();
        let task = spawn_blocking(move || {
            let _permit = permit;
            builder.cleanup_owned_spool(&record, &AtomicBool::new(false))
        });
        match await_blocking_io(
            task,
            CLEANUP_TIMEOUT,
            "lmyzmail outbound published-spool cleanup exceeded its soft deadline; waiting for the filesystem operation",
        )
        .await
        {
            Ok(Ok(())) => {
                if self
                    .record_spool_removed(task_id, &spool_path)
                    .await
                    .is_err()
                {
                    eprintln!(
                        "lmyzmail outbound spool was removed but its durable cleanup marker could not be updated"
                    );
                }
            }
            _ => eprintln!("lmyzmail outbound small-message spool cleanup failed"),
        }
    }

    async fn record_spool_removed(
        &self,
        task_id: i64,
        spool_path: &str,
    ) -> Result<(), OutboundError> {
        let client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(|error| OutboundError::Database(error.to_string()))?;
        let updated = timeout(
            DATABASE_TIMEOUT,
            client.execute(
                "UPDATE lmyzmail_outbound_spool
                 SET cleanup_state='REMOVED',updated_at=clock_timestamp()
                 WHERE task_id=$1 AND spool_path=$2 AND spool_kind='RUST'
                   AND cleanup_state='OWNED'",
                &[&task_id, &spool_path],
            ),
        )
        .await;
        match updated {
            Ok(Ok(1)) => return Ok(()),
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {}
            Ok(Ok(_)) => return Err(OutboundError::Unavailable),
        }
        drop(client);

        let client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(|error| OutboundError::Database(error.to_string()))?;
        let row = timeout(
            DATABASE_TIMEOUT,
            client.query_opt(
                "SELECT cleanup_state FROM lmyzmail_outbound_spool
                 WHERE task_id=$1 AND spool_path=$2 AND spool_kind='RUST'",
                &[&task_id, &spool_path],
            ),
        )
        .await
        .map_err(|_| OutboundError::Unavailable)?
        .map_err(db_error)?;
        match row.as_ref().map(|row| row.get::<_, &str>(0)) {
            Some("REMOVED") => Ok(()),
            _ => Err(OutboundError::Unavailable),
        }
    }

    async fn reconcile_spool_cleanup(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<(), OutboundError> {
        let client = cancellable_db_call(cancellation, self.pool.get(), |error| {
            OutboundError::Database(error.to_string())
        })
        .await?;
        let rows = cancellable_db_call(
            cancellation,
            client.query(
                "SELECT spool.task_id,spool.spool_path,spool.cleanup_after_publish,
                        queue.status,queue.sent_file_name,queue.sender_address,
                        queue.sent_subdirectory
                 FROM lmyzmail_outbound_spool spool
                 JOIN outbound_mail_queue queue ON queue.id=spool.task_id
                 WHERE spool.spool_kind='RUST' AND spool.cleanup_state='OWNED'
                   AND (spool.cleanup_after_publish
                        OR queue.status IN ('SENT','PARTIAL_SUCCESS','FAILED','CANCELLED'))
                 ORDER BY spool.task_id LIMIT $1",
                &[&RECONCILE_BATCH_SIZE],
            ),
            db_error,
        )
        .await?;
        for row in rows {
            let task_id: i64 = row.get(0);
            let spool_path: String = row.get(1);
            let cleanup_after_publish: bool = row.get(2);
            let status: &str = row.get(3);
            let sent_file_name: String = row
                .get::<_, Option<String>>(4)
                .filter(|value| !value.is_empty())
                .ok_or(OutboundError::Unavailable)?;
            let sender_address: String = row.get(5);
            let sent_subdirectory: i32 = row
                .get::<_, Option<i32>>(6)
                .filter(|value| *value > 0)
                .ok_or(OutboundError::Unavailable)?;
            let terminal = matches!(status, "SENT" | "PARTIAL_SUCCESS" | "FAILED" | "CANCELLED");
            if cleanup_after_publish && !terminal {
                let published = tokio::select! {
                    _ = cancellation.cancelled() => return Err(OutboundError::Unavailable),
                    result = self.queue.is_complete_task(task_id, &sent_file_name) => result,
                }
                .map_err(|_| OutboundError::Unavailable)?;
                if !published {
                    continue;
                }
            }
            let builder = self.message_builder.clone();
            let record = OutboundSpoolRecord {
                task_id,
                spool_path: spool_path.clone(),
                kind: OutboundSpoolKind::Rust,
                state: OutboundSpoolState::Owned,
                sender_address,
                sent_file_name,
                sent_subdirectory,
            };
            self.run_dsn_blocking(cancellation, move |cancelled| {
                builder.cleanup_owned_spool(&record, cancelled)
            })
            .await?;
            self.record_spool_removed(task_id, &spool_path).await?;
        }

        Ok(())
    }

    pub async fn run_reconciler(&self, cancellation: CancellationToken) {
        let mut ticker = interval(RECONCILE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut after_id = 0_i64;
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = ticker.tick() => {
                    if let Err(error) = self.reconcile_spool_cleanup(&cancellation).await {
                        if cancellation.is_cancelled() {
                            break;
                        }
                        eprintln!("lmyzmail outbound spool cleanup reconciliation failed: {error}");
                    }
                    match self.reconcile_batch(after_id, &cancellation).await {
                        Ok((next_id, count)) => {
                            after_id = if count < RECONCILE_BATCH_SIZE as usize {
                                0
                            } else {
                                next_id
                            };
                        }
                        Err(error) => {
                            eprintln!("lmyzmail outbound reconciliation failed: {error}");
                        }
                    }
                }
            }
        }
    }

    async fn reconcile_batch(
        &self,
        after_id: i64,
        cancellation: &CancellationToken,
    ) -> Result<(i64, usize), OutboundError> {
        let client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(|error| OutboundError::Database(error.to_string()))?;
        let rows = timeout(
            DATABASE_TIMEOUT,
            client.query(
                "SELECT id,sender_address,recipients_json,subject,body_text,body_html,
                        attachments_json,message_id,max_retries,retry_count,sent_file_name,
                        sent_subdirectory,created_at,next_retry_at,last_error
                 FROM outbound_mail_queue
                 WHERE status='PENDING' AND id > $1 ORDER BY id LIMIT $2",
                &[&after_id, &RECONCILE_BATCH_SIZE],
            ),
        )
        .await
        .map_err(|_| OutboundError::Unavailable)?
        .map_err(db_error)?;
        drop(client);
        let count = rows.len();
        let mut next_id = after_id;
        for row in rows {
            if cancellation.is_cancelled() {
                break;
            }
            let row = ReconcileRow {
                id: row.get(0),
                sender_address: row.get(1),
                recipients_json: row.get(2),
                subject: row.get(3),
                body_text: row.get(4),
                body_html: row.get(5),
                attachments_json: row.get(6),
                message_id: row.get(7),
                max_retries: row.get(8),
                retry_count: row.get(9),
                sent_file_name: row.get(10),
                sent_subdirectory: row.get(11),
                created_at: row.get(12),
                next_retry_at: row.get(13),
                last_error: row.get(14),
            };
            next_id = row.id;
            if let Err(error) = self.reconcile_row(row, cancellation).await {
                if cancellation.is_cancelled() {
                    break;
                }
                eprintln!("lmyzmail outbound task {next_id} could not be reconciled: {error}");
            }
        }
        Ok((next_id, count))
    }

    async fn reconcile_row(
        &self,
        row: ReconcileRow,
        cancellation: &CancellationToken,
    ) -> Result<(), OutboundError> {
        let sent_file_name = row
            .sent_file_name
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or(OutboundError::Unavailable)?;
        let sent_subdirectory = row
            .sent_subdirectory
            .filter(|value| *value > 0)
            .ok_or(OutboundError::Unavailable)?;
        if self
            .queue
            .is_complete_task(row.id, &sent_file_name)
            .await
            .map_err(|_| OutboundError::Unavailable)?
        {
            return Ok(());
        }
        let recipients: ValidatedRecipients =
            serde_json::from_str(&row.recipients_json).map_err(|_| OutboundError::Unavailable)?;
        let subject = row.subject.ok_or(OutboundError::Unavailable)?;
        let message_id = row.message_id.ok_or(OutboundError::Unavailable)?;
        let attachments: Vec<MessageAttachment> = row
            .attachments_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| OutboundError::Unavailable)?
            .unwrap_or_default();
        let storage_mode = java_storage_mode(
            row.body_text.as_deref(),
            row.body_html.as_deref(),
            &attachments,
        )
        .map_err(map_message_build_error)?;
        let materialized = self
            .recover_message(
                row.id,
                &row.sender_address,
                &sent_file_name,
                sent_subdirectory,
                storage_mode,
                cancellation,
            )
            .await?;
        let statuses = pending_domain_statuses_for_recipients(
            &recipients.to,
            &recipients.cc,
            &recipients.bcc,
            row.created_at,
        )?;
        let message_file_path = if materialized.signed_content_base64.is_none() {
            Some(
                materialized
                    .spool_path
                    .to_str()
                    .ok_or(OutboundError::Unavailable)?
                    .to_owned(),
            )
        } else {
            None
        };
        let task = TaskDetail {
            id: row.id,
            sender_address: row.sender_address,
            recipients_json: row.recipients_json,
            subject,
            message_id,
            max_retries: row.max_retries,
            retry_count: row.retry_count,
            sent_file_name: Some(sent_file_name),
            sent_subdirectory: Some(sent_subdirectory),
            message_file_path,
            signed_content_base64: materialized.signed_content_base64.clone(),
            created_at: instant(row.created_at),
            next_retry_at: (row.retry_count > 0).then(|| instant(row.next_retry_at)),
            last_error: row.last_error,
            status: "PENDING".into(),
        };
        self.publish_with_reconciliation(&task, &statuses, cancellation)
            .await?;
        self.cleanup_published(row.id, task.sender_address.clone(), materialized)
            .await;
        Ok(())
    }

    async fn recover_message(
        &self,
        task_id: i64,
        sender: &str,
        sent_file_name: &str,
        sent_subdirectory: i32,
        storage_mode: MessageStorageMode,
        cancellation: &CancellationToken,
    ) -> Result<MaterializedMessage, OutboundError> {
        let builder = self.message_builder.clone();
        let sender = sender.to_owned();
        let sent_file_name = sent_file_name.to_owned();
        self.run_dsn_blocking(cancellation, move |cancelled| {
            builder.recover(
                task_id,
                &sender,
                &sent_file_name,
                sent_subdirectory,
                storage_mode,
                cancelled,
            )
        })
        .await
    }

    pub async fn api_status_by_id(
        &self,
        queue_id: i64,
    ) -> Result<Option<ApiStatusResponse>, OutboundError> {
        if let Some(task) = self
            .queue
            .read_persisted_task(queue_id)
            .await
            .map_err(map_queue_error)?
        {
            self.queue
                .read_persisted_domain_statuses(queue_id)
                .await
                .map_err(map_queue_error)?;
            return Ok(Some(task.into_api_status()));
        }
        let row = self.status_row("id=$1", &queue_id, None).await?;
        if let Some(row) = row {
            self.queue
                .read_persisted_domain_statuses(row.queue_id)
                .await
                .map_err(map_queue_error)?;
            Ok(Some(row.into_api()))
        } else {
            Ok(None)
        }
    }

    pub async fn api_status_by_message_id(
        &self,
        message_id: &str,
    ) -> Result<Option<ApiStatusResponse>, OutboundError> {
        if message_id.is_empty() || message_id.len() > 255 {
            return Ok(None);
        }
        let row = self
            .status_row(
                "message_id=$1 AND status NOT IN ('PENDING','PROCESSING')",
                &message_id,
                None,
            )
            .await?;
        if let Some(row) = row {
            self.queue
                .read_persisted_domain_statuses(row.queue_id)
                .await
                .map_err(map_queue_error)?;
            Ok(Some(row.into_api()))
        } else {
            Ok(None)
        }
    }

    pub async fn web_status_by_id(
        &self,
        queue_id: i64,
        sender: &str,
    ) -> Result<Option<WebStatusResponse>, OutboundError> {
        if let Some(task) = self
            .queue
            .read_persisted_task(queue_id)
            .await
            .map_err(map_queue_error)?
            .filter(|task| {
                task.sender_address
                    .trim()
                    .eq_ignore_ascii_case(sender.trim())
            })
        {
            return self.web_status_from_task(task).await.map(Some);
        }
        match self.status_row("id=$1", &queue_id, Some(sender)).await? {
            Some(row) => self.web_status(row).await.map(Some),
            None => Ok(None),
        }
    }

    pub async fn web_status_by_file(
        &self,
        file_name: &str,
        sender: &str,
    ) -> Result<Option<WebStatusResponse>, OutboundError> {
        if file_name.is_empty() || file_name.len() > 255 {
            return Ok(None);
        }
        let task_id = self
            .queue
            .read_task_id_by_sent_file_name(file_name)
            .await
            .unwrap_or(None);
        if let Some(task_id) = task_id
            && let Some(task) = self
                .queue
                .read_persisted_task(task_id)
                .await
                .map_err(map_queue_error)?
                .filter(|task| {
                    task.sender_address
                        .trim()
                        .eq_ignore_ascii_case(sender.trim())
                })
        {
            return self.web_status_from_task(task).await.map(Some);
        }
        match self
            .status_row("sent_file_name=$1", &file_name, Some(sender))
            .await?
        {
            Some(row) => self.web_status(row).await.map(Some),
            None => Ok(None),
        }
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
                 created_at,sent_at,next_retry_at,sent_domains_json,failed_domains_json
                 FROM outbound_mail_queue
                 WHERE {predicate} AND lower(sender_address)=lower($2)"
            )
        } else {
            format!(
                "SELECT id,message_id,status,retry_count,max_retries,last_error,sent_file_name,
                 created_at,sent_at,next_retry_at,sent_domains_json,failed_domains_json
                 FROM outbound_mail_queue WHERE {predicate}"
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
            sent_domains_json: row.get(10),
            failed_domains_json: row.get(11),
        }))
    }

    async fn web_status(&self, row: StatusRow) -> Result<WebStatusResponse, OutboundError> {
        let statuses = self
            .queue
            .read_persisted_domain_statuses(row.queue_id)
            .await
            .map_err(map_queue_error)?;
        let (aggregated_status, domain_details) = if statuses.is_empty() {
            (row.status.clone(), row.database_domain_details())
        } else {
            (
                aggregate_domain_statuses(&statuses),
                statuses
                    .into_values()
                    .map(WebDomainStatusResponse::from_domain_status)
                    .collect(),
            )
        };
        Ok(row.into_web(aggregated_status, domain_details))
    }

    async fn web_status_from_task(
        &self,
        task: TaskDetail,
    ) -> Result<WebStatusResponse, OutboundError> {
        let mut statuses = self
            .queue
            .read_persisted_domain_statuses(task.id)
            .await
            .map_err(map_queue_error)?;
        if statuses.is_empty() {
            statuses = reconstructed_task_domain_statuses(&task);
        }
        let mut aggregated_status = if statuses.is_empty() {
            task.status.clone()
        } else {
            aggregate_domain_statuses(&statuses)
        };
        if task.status == "PENDING"
            && !matches!(aggregated_status.as_str(), "PENDING" | "PROCESSING")
        {
            aggregated_status = "PENDING".into();
        }
        let domain_details = statuses
            .into_values()
            .map(WebDomainStatusResponse::from_domain_status)
            .collect();
        Ok(task.into_web_status(aggregated_status, domain_details))
    }

    fn validate_attachments(
        &self,
        attachments: Vec<AttachmentInput>,
    ) -> Result<Vec<MessageAttachment>, OutboundError> {
        if attachments.len() > MAX_ATTACHMENTS {
            return Err(OutboundError::InvalidInput("too_many_attachments"));
        }
        let mut total = 0_u64;
        let mut validated = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            let content = attachment.content_base64.unwrap_or_default();
            let size = decoded_base64_size(&content)?;
            if size > self.max_attachment_size_bytes {
                return Err(OutboundError::InvalidInput("attachment_too_large"));
            }
            total = total
                .checked_add(size)
                .ok_or(OutboundError::InvalidInput("attachments_too_large"))?;
            let filename = attachment.filename.unwrap_or_else(|| "attachment".into());
            if filename.len() > MAX_ATTACHMENT_FILENAME_BYTES
                || filename.chars().any(char::is_control)
            {
                return Err(OutboundError::InvalidInput("invalid_attachment"));
            }
            let content_type = attachment
                .content_type
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "application/octet-stream".into());
            if content_type.len() > MAX_CONTENT_TYPE_BYTES {
                return Err(OutboundError::InvalidInput("invalid_attachment"));
            }
            let content_type = content_type
                .parse::<mime::Mime>()
                .map_err(|_| OutboundError::InvalidInput("invalid_attachment"))?
                .to_string();
            let content_id = attachment.content_id.map(validate_content_id).transpose()?;
            validated.push(MessageAttachment {
                filename,
                content_type,
                content_base64: content,
                content_length: None,
                source_path: None,
                inline: attachment.inline,
                content_id,
            });
        }
        if total > self.max_total_attachments_size_bytes {
            return Err(OutboundError::InvalidInput("attachments_too_large"));
        }
        Ok(validated)
    }

    fn validate_streaming_attachments(
        &self,
        attachments: Vec<StreamingAttachmentInput>,
    ) -> Result<Vec<MessageAttachment>, OutboundError> {
        if attachments.len() > MAX_ATTACHMENTS {
            return Err(OutboundError::InvalidInput("too_many_attachments"));
        }
        let mut total = 0_u64;
        let mut validated = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            if attachment.size > self.max_attachment_size_bytes {
                return Err(OutboundError::AttachmentTooLarge(attachment.filename));
            }
            total = total
                .checked_add(attachment.size)
                .ok_or(OutboundError::AttachmentsTooLarge)?;
            if total > self.max_total_attachments_size_bytes {
                return Err(OutboundError::AttachmentsTooLarge);
            }
            if attachment.filename.len() > MAX_ATTACHMENT_FILENAME_BYTES
                || attachment.filename.chars().any(char::is_control)
            {
                return Err(OutboundError::InvalidInput("invalid_attachment"));
            }
            let content_type = attachment
                .content_type
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "application/octet-stream".into());
            if content_type.len() > MAX_CONTENT_TYPE_BYTES {
                return Err(OutboundError::InvalidInput("invalid_attachment"));
            }
            let content_type = content_type
                .parse::<mime::Mime>()
                .map_err(|_| OutboundError::InvalidInput("invalid_attachment"))?
                .to_string();
            validated.push(MessageAttachment {
                filename: attachment.filename,
                content_type,
                content_base64: String::new(),
                content_length: Some(attachment.size),
                source_path: Some(attachment.path),
                inline: false,
                content_id: None,
            });
        }
        Ok(validated)
    }
}

fn validate_content_id(value: String) -> Result<String, OutboundError> {
    if value.is_empty()
        || value.len() > MAX_CONTENT_ID_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.contains(['<', '>'])
    {
        return Err(OutboundError::InvalidInput("invalid_attachment"));
    }
    Ok(value)
}

fn index_to_addresses(addresses: &[String]) -> Result<String, OutboundError> {
    let mut json = serde_json::to_string(addresses).map_err(|_| OutboundError::Unavailable)?;
    if let Some((index, _)) = json.char_indices().nth(2_000) {
        json.truncate(index);
    }
    Ok(json)
}

fn pending_domain_statuses(
    input: &MessageInput,
    now: DateTime<Utc>,
) -> Result<BTreeMap<String, DomainStatus>, OutboundError> {
    pending_domain_statuses_for_recipients(&input.to, &input.cc, &input.bcc, now)
}

fn pending_domain_statuses_for_recipients(
    to: &[String],
    cc: &[String],
    bcc: &[String],
    now: DateTime<Utc>,
) -> Result<BTreeMap<String, DomainStatus>, OutboundError> {
    let updated_at = instant(now);
    let mut statuses = BTreeMap::<String, DomainStatus>::new();
    for address in to.iter().chain(cc).chain(bcc) {
        let (_, domain) = address
            .rsplit_once('@')
            .ok_or(OutboundError::InvalidInput("invalid_address"))?;
        statuses
            .entry(domain.to_owned())
            .or_insert_with(|| DomainStatus {
                domain: domain.to_owned(),
                status: "PENDING".into(),
                error: None,
                recipients: Vec::new(),
                updated_at: updated_at.clone(),
            })
            .recipients
            .push(address.clone());
    }
    if statuses.is_empty() {
        return Err(OutboundError::InvalidInput("to_required"));
    }
    Ok(statuses)
}

async fn run_bounded_message_task<T, F>(
    blocking_permits: Arc<Semaphore>,
    cancellation: &CancellationToken,
    soft_deadline: Duration,
    build: F,
) -> Result<T, OutboundError>
where
    T: Send + 'static,
    F: FnOnce(&AtomicBool) -> Result<T, MessageBuildError> + Send + 'static,
{
    let permit = tokio::select! {
        _ = cancellation.cancelled() => return Err(OutboundError::Unavailable),
        permit = timeout(soft_deadline, blocking_permits.acquire_owned()) => permit
            .map_err(|_| OutboundError::Unavailable)?
            .map_err(|_| OutboundError::Unavailable)?,
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let task_cancelled = Arc::clone(&cancelled);
    let mut task = spawn_blocking(move || {
        let _permit = permit;
        build(&task_cancelled)
    });
    tokio::select! {
        _ = cancellation.cancelled() => {
            cancelled.store(true, Ordering::Release);
            if task.await.is_err() {
                eprintln!("lmyzmail outbound cancelled blocking task panicked");
            }
            Err(OutboundError::Unavailable)
        }
        result = timeout(soft_deadline, &mut task) => match result {
            Ok(Ok(result)) => result.map_err(map_message_build_error),
            Ok(Err(_)) => Err(OutboundError::Unavailable),
            Err(_) => {
                cancelled.store(true, Ordering::Release);
                eprintln!(
                    "lmyzmail outbound blocking task exceeded its soft deadline; waiting for cooperative cancellation"
                );
                if task.await.is_err() {
                    eprintln!("lmyzmail outbound timed-out blocking task panicked");
                }
                Err(OutboundError::Unavailable)
            }
        }
    }
}

async fn cancellable_db_call<T, E, F, M>(
    cancellation: &CancellationToken,
    future: F,
    map_error: M,
) -> Result<T, OutboundError>
where
    F: Future<Output = Result<T, E>>,
    M: FnOnce(E) -> OutboundError,
{
    tokio::select! {
        _ = cancellation.cancelled() => Err(OutboundError::Unavailable),
        result = timeout(DATABASE_TIMEOUT, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(map_error(error)),
            Err(_) => Err(OutboundError::Unavailable),
        },
    }
}

async fn await_blocking_io<T>(
    mut task: JoinHandle<T>,
    soft_deadline: Duration,
    deadline_message: &'static str,
) -> Result<T, tokio::task::JoinError> {
    match timeout(soft_deadline, &mut task).await {
        Ok(result) => result,
        Err(_) => {
            eprintln!("{deadline_message}");
            task.await
        }
    }
}

fn map_message_build_error(error: MessageBuildError) -> OutboundError {
    match error {
        MessageBuildError::InvalidInput(code) => OutboundError::InvalidInput(code),
        MessageBuildError::Cancelled
        | MessageBuildError::Configuration(_)
        | MessageBuildError::Io(_) => OutboundError::Unavailable,
    }
}

fn map_queue_error(_: QueueError) -> OutboundError {
    OutboundError::Unavailable
}

fn reconstructed_task_domain_statuses(task: &TaskDetail) -> BTreeMap<String, DomainStatus> {
    let Ok(recipients) = parse_recipient_roster_json(&task.recipients_json) else {
        return BTreeMap::new();
    };
    let status = match task.status.as_str() {
        "PROCESSING" => "SENDING",
        "SENT" => "SENT",
        "FAILED" => "FAILED",
        _ => "PENDING",
    };
    let updated_at = Utc::now().to_rfc3339();
    let mut domains = BTreeMap::<String, DomainStatus>::new();
    for recipient in recipients {
        let Some((_, domain)) = recipient.rsplit_once('@') else {
            continue;
        };
        domains
            .entry(domain.to_owned())
            .or_insert_with(|| DomainStatus {
                domain: domain.to_owned(),
                status: status.to_owned(),
                error: (status == "FAILED")
                    .then(|| task.last_error.clone())
                    .flatten(),
                recipients: Vec::new(),
                updated_at: updated_at.clone(),
            })
            .recipients
            .push(recipient);
    }
    domains
}

impl TaskDetail {
    fn into_api_status(self) -> ApiStatusResponse {
        let next_retry_at = visible_task_next_retry(&self);
        ApiStatusResponse {
            queue_id: self.id,
            message_id: Some(self.message_id),
            status: self.status,
            retry_count: self.retry_count,
            max_retries: self.max_retries,
            last_error: self.last_error,
            created_at: self.created_at,
            sent_at: None,
            next_retry_at,
        }
    }

    fn into_web_status(
        self,
        aggregated_status: String,
        domain_details: Vec<WebDomainStatusResponse>,
    ) -> WebStatusResponse {
        let next_retry_at = visible_task_next_retry(&self);
        let status_description = status_description(&aggregated_status, self.retry_count);
        WebStatusResponse {
            queue_id: self.id,
            message_id: Some(self.message_id),
            status: self.status,
            aggregated_status,
            status_description,
            retry_count: self.retry_count,
            max_retries: self.max_retries,
            last_error: self.last_error,
            sent_file_name: self.sent_file_name,
            created_at: self.created_at,
            sent_at: None,
            next_retry_at,
            domain_details,
        }
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

    fn into_web(
        self,
        aggregated_status: String,
        domain_details: Vec<WebDomainStatusResponse>,
    ) -> WebStatusResponse {
        let next_retry_at = visible_next_retry(&self);
        let status_description = status_description(&aggregated_status, self.retry_count);
        WebStatusResponse {
            queue_id: self.queue_id,
            message_id: self.message_id,
            aggregated_status,
            status: self.status,
            status_description,
            retry_count: self.retry_count,
            max_retries: self.max_retries,
            last_error: self.last_error,
            sent_file_name: self.sent_file_name,
            created_at: instant(self.created_at),
            sent_at: self.sent_at.map(instant),
            next_retry_at,
            domain_details,
        }
    }

    fn database_domain_details(&self) -> Vec<WebDomainStatusResponse> {
        let mut details = Vec::new();
        if let Some(domains) = self
            .sent_domains_json
            .as_deref()
            .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        {
            details.extend(domains.into_iter().map(|domain| WebDomainStatusResponse {
                domain,
                status: "SENT".into(),
                status_description: domain_status_description("SENT"),
                error: None,
                recipients: None,
                updated_at: None,
            }));
        }
        if let Some(domains) = self
            .failed_domains_json
            .as_deref()
            .and_then(|value| serde_json::from_str::<BTreeMap<String, String>>(value).ok())
        {
            details.extend(
                domains
                    .into_iter()
                    .map(|(domain, error)| WebDomainStatusResponse {
                        domain,
                        status: "FAILED".into(),
                        status_description: domain_status_description("FAILED"),
                        error: Some(error),
                        recipients: None,
                        updated_at: None,
                    }),
            );
        }
        details.sort_by(|left, right| left.domain.cmp(&right.domain));
        details
    }
}

impl WebDomainStatusResponse {
    fn from_domain_status(status: DomainStatus) -> Self {
        let status_description = domain_status_description(&status.status);
        Self {
            domain: status.domain,
            status: status.status,
            status_description,
            error: status.error,
            recipients: Some(status.recipients),
            updated_at: Some(status.updated_at),
        }
    }
}

fn status_description(status: &str, retry_count: i32) -> String {
    match status {
        "PENDING" if retry_count > 0 => format!("等待重试 (第 {retry_count} 次)"),
        "PENDING" => "等待发送".to_owned(),
        "PROCESSING" | "SENDING" => "正在发送...".to_owned(),
        "SENT" => "发送成功".to_owned(),
        "PARTIAL_SUCCESS" => "部分发送成功".to_owned(),
        "FAILED" => "发送失败".to_owned(),
        "CANCELLED" => "已取消".to_owned(),
        value => value.to_owned(),
    }
}

fn domain_status_description(status: &str) -> String {
    match status {
        "PENDING" => "等待发送".to_owned(),
        "SENDING" => "正在发送...".to_owned(),
        "SENT" => "发送成功".to_owned(),
        "FAILED" => "发送失败".to_owned(),
        value => value.to_owned(),
    }
}

fn aggregate_domain_statuses(statuses: &BTreeMap<String, DomainStatus>) -> String {
    let total = statuses.len();
    let sent = statuses
        .values()
        .filter(|status| status.status == "SENT")
        .count();
    let failed = statuses
        .values()
        .filter(|status| status.status == "FAILED")
        .count();
    let permanent_failed = statuses
        .values()
        .filter(|status| {
            status.status == "FAILED" && status.error.as_deref().is_some_and(permanent_domain_error)
        })
        .count();
    if sent == total {
        "SENT".into()
    } else if permanent_failed == total {
        "FAILED".into()
    } else if sent > 0 && permanent_failed > 0 && sent + permanent_failed == total {
        "PARTIAL_SUCCESS".into()
    } else if statuses
        .values()
        .any(|status| matches!(status.status.as_str(), "PENDING" | "SENDING"))
        || failed > permanent_failed
    {
        "PROCESSING".into()
    } else {
        "PENDING".into()
    }
}

fn permanent_domain_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    [
        "does not support smtputf8",
        "requires smtputf8",
        "smtputf8 recipient",
        "was not sent with smtputf8",
        "session was not initialized",
        "user unknown",
        "mailbox not found",
        "recipient rejected",
        "no such user",
        "address rejected",
        "relay denied",
        "relay not permitted",
        "550 ",
        "551 ",
        "552 ",
        "553 ",
        "554 ",
    ]
    .iter()
    .any(|needle| error.contains(needle))
}

fn visible_next_retry(row: &StatusRow) -> Option<String> {
    if row.status == "PENDING" && row.retry_count == 0 {
        None
    } else {
        row.next_retry_at.map(instant)
    }
}

fn visible_task_next_retry(task: &TaskDetail) -> Option<String> {
    if task.status == "PENDING" && task.retry_count == 0 {
        None
    } else {
        task.next_retry_at.clone()
    }
}

#[derive(Deserialize, Serialize)]
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

fn postgres_timestamp(value: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(value.timestamp_micros())
        .expect("an existing UTC timestamp remains valid at microsecond precision")
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
        AuthError::Cancelled
        | AuthError::InvalidInput(_)
        | AuthError::OutcomeUnknown
        | AuthError::Unavailable => OutboundError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Timelike};

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

    #[test]
    fn attachment_content_ids_are_bounded_and_header_safe() {
        assert_eq!(
            validate_content_id("part.1@example.test".into()).unwrap(),
            "part.1@example.test"
        );
        for invalid in ["", "part id", "<part>", "part\r\nX-Evil: 1"] {
            assert!(validate_content_id(invalid.into()).is_err());
        }
    }

    #[test]
    fn outbound_timestamps_are_stable_across_postgres_round_trips() {
        let value = Utc
            .with_ymd_and_hms(2026, 8, 6, 1, 2, 3)
            .unwrap()
            .with_nanosecond(123_456_789)
            .unwrap();
        let normalized = postgres_timestamp(value);
        assert_eq!(normalized.nanosecond(), 123_456_000);
        assert_eq!(instant(normalized), "2026-08-06T01:02:03.123456Z");
    }

    #[test]
    fn domain_aggregation_matches_the_frozen_java_predicate() {
        let status = |domain: &str, value: &str, error: Option<&str>| DomainStatus {
            domain: domain.into(),
            status: value.into(),
            error: error.map(str::to_owned),
            recipients: vec![format!("user@{domain}")],
            updated_at: "2026-08-07T00:00:00Z".into(),
        };
        assert_eq!(
            aggregate_domain_statuses(&BTreeMap::from([
                ("alpha.test".into(), status("alpha.test", "PENDING", None)),
                ("beta.test".into(), status("beta.test", "SENDING", None)),
            ])),
            "PROCESSING"
        );
        assert_eq!(
            aggregate_domain_statuses(&BTreeMap::from([
                ("alpha.test".into(), status("alpha.test", "SENT", None)),
                (
                    "beta.test".into(),
                    status("beta.test", "FAILED", Some("550 5.1.1 user unknown")),
                ),
            ])),
            "PARTIAL_SUCCESS"
        );
        assert!(!permanent_domain_error("500 syntax error"));
        assert!(permanent_domain_error("554 5.7.1 policy rejected"));
    }

    #[tokio::test]
    async fn cancelled_blocking_task_is_joined_and_releases_its_permit() {
        let permits = Arc::new(Semaphore::new(1));
        let cancellation = CancellationToken::new();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let finished = Arc::new(AtomicBool::new(false));
        let task_permits = Arc::clone(&permits);
        let task_cancellation = cancellation.clone();
        let task_active = Arc::clone(&active);
        let task_finished = Arc::clone(&finished);
        let runner = tokio::spawn(async move {
            run_bounded_message_task(
                task_permits,
                &task_cancellation,
                Duration::from_secs(1),
                move |cancelled| {
                    task_active.fetch_add(1, Ordering::AcqRel);
                    while !cancelled.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                    task_active.fetch_sub(1, Ordering::AcqRel);
                    task_finished.store(true, Ordering::Release);
                    Err::<(), _>(MessageBuildError::Cancelled)
                },
            )
            .await
        });
        timeout(Duration::from_secs(1), async {
            while active.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancellation.cancel();
        let result = timeout(Duration::from_secs(1), runner)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(OutboundError::Unavailable)));
        assert!(finished.load(Ordering::Acquire));
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn timed_out_blocking_task_is_cancelled_and_joined() {
        let permits = Arc::new(Semaphore::new(1));
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task_active = Arc::clone(&active);
        let result = run_bounded_message_task(
            Arc::clone(&permits),
            &CancellationToken::new(),
            Duration::from_millis(5),
            move |cancelled| {
                task_active.fetch_add(1, Ordering::AcqRel);
                while !cancelled.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                task_active.fetch_sub(1, Ordering::AcqRel);
                Err::<(), _>(MessageBuildError::Cancelled)
            },
        )
        .await;
        assert!(matches!(result, Err(OutboundError::Unavailable)));
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn filesystem_task_is_joined_after_its_soft_deadline() {
        let finished = Arc::new(AtomicBool::new(false));
        let task_finished = Arc::clone(&finished);
        let task = spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(30));
            task_finished.store(true, Ordering::Release);
            7
        });
        assert_eq!(
            await_blocking_io(task, Duration::from_millis(2), "test soft deadline")
                .await
                .unwrap(),
            7
        );
        assert!(finished.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn database_call_observes_cancellation_without_waiting_for_deadline() {
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            cancellable_db_call(
                &task_cancellation,
                std::future::pending::<Result<(), ()>>(),
                |_| OutboundError::Unavailable,
            )
            .await
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        let result = timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(OutboundError::Unavailable)));
    }
}
