use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    time::Duration,
};

use chrono::{DateTime, Timelike, Utc};
use deadpool_postgres::{Object, Pool};
use getrandom::fill as fill_random;
use idna::domain_to_ascii_strict;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{CancelToken, NoTls};

use crate::outbound_dsn::{DsnEligibility, DsnRecipientSnapshot, normalize_reply_address};

const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const DATABASE_CANCEL_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_OWNER_TOKEN_BYTES: usize = 100;
const MAX_WORKER_ID_BYTES: usize = 64;
const MAX_LAST_ERROR_UTF16_UNITS: usize = 1_000;
const MAX_DOMAIN_ERROR_BYTES: usize = 2_000;
const MAX_DOMAINS: usize = 1_000;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_DOMAIN_ARCHIVE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 1_000;
const MAX_RECIPIENT_ADDRESS_BYTES: usize = 320;
const MAX_RECIPIENT_DETAIL_BYTES: usize = 2_000;
const DELIVERY_LEDGER_MIGRATION_LOCK: i64 = 0x4c4d_595a_4c44_4752;
const LEGACY_REDIS_TAKEOVER_LOCK: i64 = 0x4c4d_595a_5254_4b56;
const OUTBOUND_ID_ALLOCATION_LOCK: i64 = 0x4c4d_595a_4f49_4441;
const DELIVERY_LEDGER_SCHEMA: &str = include_str!("../migrations/001_outbound_delivery_ledger.sql");
const OUTBOUND_SPOOL_SCHEMA: &str = include_str!("../migrations/002_outbound_spool_ownership.sql");
const OUTBOUND_DSN_SCHEMA: &str = include_str!("../migrations/003_outbound_dsn.sql");
const OUTBOUND_SPOOL_CLEANUP_SCHEMA: &str =
    include_str!("../migrations/004_outbound_spool_cleanup.sql");

#[derive(Deserialize)]
#[serde(untagged)]
enum LegacyRecipientJson {
    Flat(Vec<String>),
    Structured {
        to: Option<Vec<String>>,
        cc: Option<Vec<String>>,
        bcc: Option<Vec<String>>,
    },
}

#[derive(Clone)]
pub struct PostgresDeliveryState {
    pool: Pool,
    operation_timeout: Duration,
}

#[derive(Clone, Debug)]
pub(crate) struct DsnWork {
    pub(crate) original_task_id: i64,
    pub(crate) dsn_task_id: Option<i64>,
    pub(crate) lease_token: String,
    pub(crate) payload: DsnEligibility,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeliveryAttemptId {
    task_id: i64,
    owner_token: String,
}

impl fmt::Debug for DeliveryAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryAttemptId")
            .field("task_id", &self.task_id)
            .field("owner_token", &"<redacted>")
            .finish()
    }
}

impl DeliveryAttemptId {
    pub fn generate(task_id: i64, worker_id: &str) -> Result<Self, DeliveryStateError> {
        validate_worker_identity(task_id, worker_id)?;
        let owner_token = Self::generate_lease_token(worker_id)?;
        Ok(Self {
            task_id,
            owner_token,
        })
    }

    pub fn generate_lease_token(worker_id: &str) -> Result<String, DeliveryStateError> {
        validate_worker_label(worker_id)?;
        unique_owner_token(worker_id)
    }

    pub fn from_lease_token(task_id: i64, lease_token: &str) -> Result<Self, DeliveryStateError> {
        validate_identity(task_id, lease_token)?;
        Ok(Self {
            task_id,
            owner_token: lease_token.to_owned(),
        })
    }

    pub fn task_id(&self) -> i64 {
        self.task_id
    }

    pub fn lease_token(&self) -> &str {
        &self.owner_token
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DatabaseClaim {
    pub task_id: i64,
    pub retry_count: i32,
    pub max_retries: i32,
    owner_token: String,
}

impl fmt::Debug for DatabaseClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseClaim")
            .field("task_id", &self.task_id)
            .field("retry_count", &self.retry_count)
            .field("max_retries", &self.max_retries)
            .field("owner_token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryTransition {
    pub retry_count: i32,
    pub max_retries: i32,
    pub next_retry_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRedisTaskMaterialization {
    pub task_id: i64,
    pub sender_address: String,
    pub recipients_json: String,
    pub subject: String,
    pub message_id: String,
    pub sent_file_name: String,
    pub sent_subdirectory: i32,
    pub retry_count: i32,
    pub max_retries: i32,
    pub next_retry_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub sent_domains: Vec<String>,
    pub failed_domains: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub mail_size_bytes: i64,
    pub has_attachments: bool,
    pub to_addresses_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyArchiveMaterialization {
    pub task_id: i64,
    pub sender_address: String,
    pub recipients_json: String,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    pub sent_file_name: Option<String>,
    pub sent_subdirectory: Option<i32>,
    pub retry_count: i32,
    pub max_retries: i32,
    pub next_retry_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub status: DeliveryRowStatus,
    pub sent_at: Option<DateTime<Utc>>,
    pub sent_domains_json: Option<String>,
    pub failed_domains_json: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyStatusMaterialization {
    pub task_id: i64,
    pub status: DeliveryRowStatus,
    pub sent_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub retry_count: i32,
    pub sent_domains_json: Option<String>,
    pub failed_domains_json: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryRowStatus {
    Pending,
    Processing,
    Sent,
    PartialSuccess,
    Failed,
    Cancelled,
}

impl DeliveryRowStatus {
    fn from_database(value: &str) -> Result<Self, DeliveryStateError> {
        match value {
            "PENDING" => Ok(Self::Pending),
            "PROCESSING" => Ok(Self::Processing),
            "SENT" => Ok(Self::Sent),
            "PARTIAL_SUCCESS" => Ok(Self::PartialSuccess),
            "FAILED" => Ok(Self::Failed),
            "CANCELLED" => Ok(Self::Cancelled),
            _ => Err(DeliveryStateError::Unavailable),
        }
    }

    fn database_value(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Processing => "PROCESSING",
            Self::Sent => "SENT",
            Self::PartialSuccess => "PARTIAL_SUCCESS",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }

    pub(crate) fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Sent | Self::PartialSuccess | Self::Failed | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliverySnapshot {
    pub task_id: i64,
    pub status: DeliveryRowStatus,
    pub retry_count: i32,
    pub max_retries: i32,
    pub next_retry_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub sent_at: Option<DateTime<Utc>>,
    pub processing_started_at: Option<DateTime<Utc>>,
    pub sent_file_name: Option<String>,
    pub has_owner: bool,
    pub owned_by_claim: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientDeliveryState {
    Pending,
    Retryable,
    Permanent,
    CommitArmed,
    Delivered,
    Ambiguous,
}

impl RecipientDeliveryState {
    fn database_value(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Retryable => "RETRYABLE",
            Self::Permanent => "PERMANENT",
            Self::CommitArmed => "COMMIT_ARMED",
            Self::Delivered => "DELIVERED",
            Self::Ambiguous => "AMBIGUOUS",
        }
    }

    fn from_database(value: &str) -> Result<Self, DeliveryStateError> {
        match value {
            "PENDING" => Ok(Self::Pending),
            "RETRYABLE" => Ok(Self::Retryable),
            "PERMANENT" => Ok(Self::Permanent),
            "COMMIT_ARMED" => Ok(Self::CommitArmed),
            "DELIVERED" => Ok(Self::Delivered),
            "AMBIGUOUS" => Ok(Self::Ambiguous),
            _ => Err(DeliveryStateError::Unavailable),
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Permanent | Self::Delivered | Self::Ambiguous)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAttemptPhase {
    Preparing,
    CommitArmed,
    Projected,
}

impl DeliveryAttemptPhase {
    fn database_value(self) -> &'static str {
        match self {
            Self::Preparing => "PREPARING",
            Self::CommitArmed => "COMMIT_ARMED",
            Self::Projected => "PROJECTED",
        }
    }

    fn from_database(value: &str) -> Result<Self, DeliveryStateError> {
        match value {
            "PREPARING" => Ok(Self::Preparing),
            "COMMIT_ARMED" => Ok(Self::CommitArmed),
            "PROJECTED" => Ok(Self::Projected),
            _ => Err(DeliveryStateError::Unavailable),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientLedgerEntry {
    pub ordinal: u16,
    pub recipient: String,
    pub state: RecipientDeliveryState,
    pub attempt_generation: i64,
    pub smtp_code: Option<u16>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientLedgerSnapshot {
    pub task_id: i64,
    pub generation: i64,
    pub phase: DeliveryAttemptPhase,
    pub has_owner: bool,
    pub owned_by_claim: bool,
    pub recipients: Vec<RecipientLedgerEntry>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecipientLedgerClaim {
    task_id: i64,
    generation: i64,
    owner_token: String,
    recipient_count: usize,
    roster_sha256: [u8; 32],
}

impl fmt::Debug for RecipientLedgerClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecipientLedgerClaim")
            .field("task_id", &self.task_id)
            .field("generation", &self.generation)
            .field("owner_token", &"<redacted>")
            .finish()
    }
}

impl RecipientLedgerClaim {
    pub fn task_id(&self) -> i64 {
        self.task_id
    }

    pub fn generation(&self) -> i64 {
        self.generation
    }
}

impl RecipientLedgerSnapshot {
    pub fn retryable_recipients(&self) -> Vec<&RecipientLedgerEntry> {
        self.recipients
            .iter()
            .filter(|recipient| {
                matches!(
                    recipient.state,
                    RecipientDeliveryState::Pending | RecipientDeliveryState::Retryable
                )
            })
            .collect()
    }

    pub fn allows_retry(&self) -> bool {
        self.phase != DeliveryAttemptPhase::CommitArmed
            && !self.recipients.iter().any(|recipient| {
                matches!(
                    recipient.state,
                    RecipientDeliveryState::CommitArmed | RecipientDeliveryState::Ambiguous
                )
            })
            && !self.retryable_recipients().is_empty()
    }

    pub fn allows_dsn(&self) -> bool {
        self.phase != DeliveryAttemptPhase::CommitArmed
            && !self.recipients.iter().any(|recipient| {
                matches!(
                    recipient.state,
                    RecipientDeliveryState::CommitArmed | RecipientDeliveryState::Ambiguous
                )
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedRecipientStatus {
    Accepted,
    Retryable,
    Permanent,
}

impl PreparedRecipientStatus {
    fn ledger_state(self) -> RecipientDeliveryState {
        match self {
            Self::Accepted => RecipientDeliveryState::CommitArmed,
            Self::Retryable => RecipientDeliveryState::Retryable,
            Self::Permanent => RecipientDeliveryState::Permanent,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRecipientCheckpoint {
    pub ordinal: u16,
    pub recipient: String,
    pub status: PreparedRecipientStatus,
    pub smtp_code: u16,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitResultStatus {
    Delivered,
    Retryable,
    Permanent,
}

impl CommitResultStatus {
    fn ledger_state(self) -> RecipientDeliveryState {
        match self {
            Self::Delivered => RecipientDeliveryState::Delivered,
            Self::Retryable => RecipientDeliveryState::Retryable,
            Self::Permanent => RecipientDeliveryState::Permanent,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyProjection {
    RetryScheduled(RetryTransition),
    Terminal(TerminalStatus),
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalStatus {
    Sent,
    PartialSuccess,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundSpoolKind {
    Rust,
    LegacyJava,
}

impl OutboundSpoolKind {
    fn database_value(self) -> &'static str {
        match self {
            Self::Rust => "RUST",
            Self::LegacyJava => "LEGACY_JAVA",
        }
    }

    fn from_database(value: &str) -> Result<Self, DeliveryStateError> {
        match value {
            "RUST" => Ok(Self::Rust),
            "LEGACY_JAVA" => Ok(Self::LegacyJava),
            _ => Err(DeliveryStateError::Unavailable),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundSpoolState {
    Owned,
    Removed,
}

impl OutboundSpoolState {
    fn from_database(value: &str) -> Result<Self, DeliveryStateError> {
        match value {
            "OWNED" => Ok(Self::Owned),
            "REMOVED" => Ok(Self::Removed),
            _ => Err(DeliveryStateError::Unavailable),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundSpoolRecord {
    pub task_id: i64,
    pub spool_path: String,
    pub kind: OutboundSpoolKind,
    pub state: OutboundSpoolState,
    pub sender_address: String,
    pub sent_file_name: String,
    pub sent_subdirectory: i32,
}

impl TerminalStatus {
    fn database_value(self) -> &'static str {
        match self {
            Self::Sent => "SENT",
            Self::PartialSuccess => "PARTIAL_SUCCESS",
            Self::Failed => "FAILED",
        }
    }

    fn records_sent_at(self) -> bool {
        matches!(self, Self::Sent | Self::PartialSuccess)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum DeliveryStateError {
    InvalidInput(&'static str),
    InvalidTransition(&'static str),
    Fenced,
    Unavailable,
    OutcomeUnknown,
}

impl fmt::Display for DeliveryStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::InvalidTransition(message) => formatter.write_str(message),
            Self::Fenced => formatter.write_str("PostgreSQL delivery attempt was fenced"),
            Self::Unavailable => formatter.write_str("PostgreSQL delivery state unavailable"),
            Self::OutcomeUnknown => formatter.write_str(
                "PostgreSQL delivery mutation outcome is unknown and requires reconciliation",
            ),
        }
    }
}

impl std::error::Error for DeliveryStateError {}

impl PostgresDeliveryState {
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            operation_timeout: DATABASE_TIMEOUT,
        }
    }

    pub fn with_timeout(
        pool: Pool,
        operation_timeout: Duration,
    ) -> Result<Self, DeliveryStateError> {
        if operation_timeout.is_zero() || operation_timeout > Duration::from_secs(60) {
            return Err(DeliveryStateError::InvalidInput(
                "invalid PostgreSQL delivery state timeout",
            ));
        }
        Ok(Self {
            pool,
            operation_timeout,
        })
    }

    pub async fn initialize_schema(&self) -> Result<(), DeliveryStateError> {
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            transaction
                .query_one(
                    "SELECT pg_advisory_xact_lock($1)",
                    &[&DELIVERY_LEDGER_MIGRATION_LOCK],
                )
                .await?;
            transaction.batch_execute(DELIVERY_LEDGER_SCHEMA).await?;
            transaction.batch_execute(OUTBOUND_SPOOL_SCHEMA).await?;
            transaction.batch_execute(OUTBOUND_DSN_SCHEMA).await?;
            transaction
                .batch_execute(OUTBOUND_SPOOL_CLEANUP_SCHEMA)
                .await?;
            transaction.commit().await?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn stage_and_lease_dsns(
        &self,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<Vec<DsnWork>, DeliveryStateError> {
        if limit == 0 || limit > 1_000 {
            return Err(DeliveryStateError::InvalidInput(
                "invalid outbound DSN batch limit",
            ));
        }
        let now = postgres_timestamp(now)?;
        let lease_until = now + chrono::Duration::seconds(120);
        let limit = i64::try_from(limit)
            .map_err(|_| DeliveryStateError::InvalidInput("invalid outbound DSN batch limit"))?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let rows = transaction
                .query(
                    "WITH eligible AS (
                         SELECT q.id,q.sender_address,q.subject,q.message_id,q.created_at,
                                attempt.updated_at AS terminal_at,
                                EXISTS(SELECT 1 FROM mailbox m
                                       WHERE lower(m.address)=lower(q.sender_address)) AS local_sender
                         FROM outbound_mail_queue q
                         JOIN lmyzmail_outbound_delivery_attempt attempt ON attempt.task_id=q.id
                         WHERE q.status IN ('SENT','PARTIAL_SUCCESS','FAILED','CANCELLED')
                           AND attempt.phase='PROJECTED'
                           AND EXISTS(
                               SELECT 1 FROM lmyzmail_outbound_delivery_recipient permanent
                               WHERE permanent.task_id=q.id AND permanent.state='PERMANENT'
                           )
                           AND NOT EXISTS(
                               SELECT 1 FROM lmyzmail_outbound_dsn dsn
                               WHERE dsn.original_task_id=q.id OR dsn.dsn_task_id=q.id
                           )
                         ORDER BY q.id
                         LIMIT $1
                     )
                     SELECT eligible.id,eligible.sender_address,eligible.subject,
                            eligible.message_id,eligible.created_at,eligible.terminal_at,
                            eligible.local_sender,recipient.recipient_address,
                            recipient.state,recipient.smtp_code,recipient.detail
                     FROM eligible
                     JOIN lmyzmail_outbound_delivery_recipient recipient
                       ON recipient.task_id=eligible.id
                     ORDER BY eligible.id,recipient.recipient_ordinal",
                    &[&limit],
                )
                .await?;
            let mut candidates = BTreeMap::<i64, (DsnEligibility, bool)>::new();
            for row in rows {
                let task_id: i64 = row.get(0);
                let entry = candidates.entry(task_id).or_insert_with(|| {
                    let created_at: DateTime<Utc> = row.get(4);
                    let terminal_at: DateTime<Utc> = row.get(5);
                    (
                        DsnEligibility {
                            original_task_id: task_id,
                            sender_address: row.get(1),
                            subject: row.get(2),
                            message_id: row.get(3),
                            created_at: created_at.to_rfc3339(),
                            terminal_at: terminal_at.to_rfc3339(),
                            recipients: Vec::new(),
                        },
                        row.get(6),
                    )
                });
                entry.0.recipients.push(DsnRecipientSnapshot {
                    recipient: row.get(7),
                    state: row.get(8),
                    smtp_code: row.get::<_, Option<i32>>(9).and_then(|value| u16::try_from(value).ok()),
                    detail: row.get(10),
                });
            }
            for (_, (payload, local_sender)) in candidates {
                let normalized_sender = normalize_reply_address(&payload.sender_address);
                let valid_payload = payload.validate();
                let eligible = local_sender && normalized_sender.is_some() && valid_payload;
                let payload_json = serde_json::to_string(&payload).map_err(|_| {
                    DeliveryStateError::InvalidInput("outbound DSN payload is invalid")
                })?;
                if payload_json.len() > 4 * 1024 * 1024 {
                    return Err(DeliveryStateError::InvalidInput(
                        "outbound DSN payload is too large",
                    )
                    .into());
                }
                let state = if eligible { "PENDING" } else { "SUPPRESSED" };
                let reason = if eligible {
                    None
                } else if !local_sender {
                    Some("original sender is not a local mailbox")
                } else if normalized_sender.is_none() {
                    Some("original sender address is invalid")
                } else if payload
                    .recipients
                    .iter()
                    .any(|recipient| recipient.state == "AMBIGUOUS")
                {
                    Some("delivery outcome is ambiguous")
                } else {
                    Some("terminal DSN payload is invalid")
                };
                transaction
                    .execute(
                        "INSERT INTO lmyzmail_outbound_dsn
                         (original_task_id,dsn_task_id,state,payload_json,expected_sha256,
                          suppress_reason,lease_token,lease_until,created_at,updated_at)
                         VALUES ($1,NULL,$2,$3,NULL,$4,NULL,NULL,$5,$5)
                         ON CONFLICT (original_task_id) DO NOTHING",
                        &[&payload.original_task_id, &state, &payload_json, &reason, &now],
                    )
                    .await?;
            }

            let rows = transaction
                .query(
                    "SELECT original_task_id,dsn_task_id,payload_json
                     FROM lmyzmail_outbound_dsn
                     WHERE state='PENDING'
                        OR (state='LEASED' AND lease_until <= $1)
                        OR (state='ADMITTING' AND lease_until <= $1)
                     ORDER BY original_task_id
                     FOR UPDATE SKIP LOCKED
                     LIMIT $2",
                    &[&now, &limit],
                )
                .await?;
            let mut work = Vec::with_capacity(rows.len());
            for row in rows {
                let original_task_id: i64 = row.get(0);
                let dsn_task_id = row.get::<_, Option<i64>>(1);
                let payload_json: String = row.get(2);
                let payload = match serde_json::from_str::<DsnEligibility>(&payload_json) {
                    Ok(payload) if payload.validate() => payload,
                    _ => {
                        transaction
                            .execute(
                                "UPDATE lmyzmail_outbound_dsn
                                 SET state='SUPPRESSED',expected_sha256=NULL,prepared_bytes=NULL,
                                     suppress_reason=$2,lease_token=NULL,lease_until=NULL,updated_at=$3
                                 WHERE original_task_id=$1",
                                &[&original_task_id, &"durable DSN payload is invalid", &now],
                            )
                            .await?;
                        continue;
                    }
                };
                let lease_token = unique_owner_token("dsn")?;
                let lease_state = if dsn_task_id.is_some() {
                    "ADMITTING"
                } else {
                    "LEASED"
                };
                transaction
                    .execute(
                        "UPDATE lmyzmail_outbound_dsn
                         SET state=$2,lease_token=$3,lease_until=$4,updated_at=$5
                         WHERE original_task_id=$1",
                        &[
                            &original_task_id,
                            &lease_state,
                            &lease_token,
                            &lease_until,
                            &now,
                        ],
                    )
                    .await?;
                work.push(DsnWork {
                    original_task_id,
                    dsn_task_id,
                    lease_token,
                    payload,
                });
            }
            transaction.commit().await?;
            Ok(work)
        })
        .await
    }

    pub(crate) async fn bind_dsn_task_id(
        &self,
        original_task_id: i64,
        lease_token: &str,
        dsn_task_id: i64,
        now: DateTime<Utc>,
    ) -> Result<(), DeliveryStateError> {
        if original_task_id <= 0
            || dsn_task_id <= 0
            || lease_token.is_empty()
            || lease_token.len() > MAX_OWNER_TOKEN_BYTES
        {
            return Err(DeliveryStateError::InvalidInput(
                "invalid outbound DSN task binding",
            ));
        }
        let now = postgres_timestamp(now)?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let updated = transaction
                .execute(
                    "UPDATE lmyzmail_outbound_dsn
                     SET dsn_task_id=$3,state='ADMITTING',updated_at=$4
                     WHERE original_task_id=$1 AND state='LEASED'
                       AND lease_token=$2 AND lease_until > $4
                       AND dsn_task_id IS NULL",
                    &[&original_task_id, &lease_token, &dsn_task_id, &now],
                )
                .await?;
            if updated != 1 {
                return Err(DeliveryStateError::InvalidTransition(
                    "outbound DSN lease was lost before task ID binding",
                )
                .into());
            }
            transaction.commit().await?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn suppress_dsn(
        &self,
        original_task_id: i64,
        lease_token: &str,
        reason: &'static str,
        now: DateTime<Utc>,
    ) -> Result<(), DeliveryStateError> {
        if original_task_id <= 0
            || lease_token.is_empty()
            || lease_token.len() > MAX_OWNER_TOKEN_BYTES
            || reason.is_empty()
            || reason.len() > 512
        {
            return Err(DeliveryStateError::InvalidInput(
                "invalid outbound DSN suppression",
            ));
        }
        let now = postgres_timestamp(now)?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let updated = transaction
                .execute(
                    "UPDATE lmyzmail_outbound_dsn
                     SET state='SUPPRESSED',expected_sha256=NULL,prepared_bytes=NULL,
                         suppress_reason=$2,lease_token=NULL,lease_until=NULL,updated_at=$3
                     WHERE original_task_id=$1 AND state IN ('LEASED','ADMITTING')
                       AND lease_token=$4 AND lease_until > $3",
                    &[&original_task_id, &reason, &now, &lease_token],
                )
                .await?;
            if updated != 1 {
                return Err(DeliveryStateError::InvalidTransition(
                    "outbound DSN lease was lost before suppression",
                )
                .into());
            }
            transaction.commit().await?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn is_dsn_task(&self, task_id: i64) -> Result<bool, DeliveryStateError> {
        if task_id <= 0 {
            return Err(DeliveryStateError::InvalidInput(
                "invalid outbound DSN task ID",
            ));
        }
        let deadline = Instant::now() + self.operation_timeout;
        let client = self.client(deadline).await?;
        let row = read_deadline(
            deadline,
            client.query_one(
                "SELECT EXISTS(
                     SELECT 1 FROM lmyzmail_outbound_dsn
                     WHERE dsn_task_id=$1 AND state='ADMITTED'
                 )",
                &[&task_id],
            ),
        )
        .await?;
        Ok(row.get(0))
    }

    pub async fn register_outbound_spool(
        &self,
        task_id: i64,
        spool_path: &str,
        kind: OutboundSpoolKind,
        now: DateTime<Utc>,
    ) -> Result<bool, DeliveryStateError> {
        validate_outbound_spool_identity(task_id, spool_path)?;
        let now = postgres_timestamp(now)?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            transaction
                .query_one(
                    "SELECT pg_advisory_xact_lock($1)",
                    &[&(LEGACY_REDIS_TAKEOVER_LOCK ^ task_id)],
                )
                .await?;
            let queue_exists = transaction
                .query_opt(
                    "SELECT 1 FROM outbound_mail_queue WHERE id=$1 FOR UPDATE",
                    &[&task_id],
                )
                .await?
                .is_some();
            if !queue_exists {
                return Err(DeliveryStateError::InvalidTransition(
                    "outbound spool task is missing",
                )
                .into());
            }
            let existing = transaction
                .query_opt(
                    "SELECT spool_path,spool_kind FROM lmyzmail_outbound_spool
                     WHERE task_id=$1 FOR UPDATE",
                    &[&task_id],
                )
                .await?;
            let inserted = if let Some(row) = existing {
                if row.get::<_, &str>(0) != spool_path
                    || row.get::<_, &str>(1) != kind.database_value()
                {
                    return Err(DeliveryStateError::InvalidTransition(
                        "outbound spool ownership conflicts with durable state",
                    )
                    .into());
                }
                false
            } else {
                transaction
                    .execute(
                        "INSERT INTO lmyzmail_outbound_spool
                         (task_id,spool_path,spool_kind,cleanup_state,created_at,updated_at)
                         VALUES ($1,$2,$3,'OWNED',$4,$4)",
                        &[&task_id, &spool_path, &kind.database_value(), &now],
                    )
                    .await?;
                true
            };
            transaction.commit().await?;
            Ok(inserted)
        })
        .await
    }

    pub async fn outbound_spool_snapshot(
        &self,
        task_id: i64,
    ) -> Result<Option<OutboundSpoolRecord>, DeliveryStateError> {
        if task_id <= 0 {
            return Err(DeliveryStateError::InvalidInput(
                "outbound spool task ID must be positive",
            ));
        }
        let deadline = Instant::now() + self.operation_timeout;
        let client = self.client(deadline).await?;
        let row = timeout_at(
            deadline,
            client.query_opt(
                "SELECT spool.spool_path,spool.spool_kind,spool.cleanup_state,
                        queue.sender_address,queue.sent_file_name,queue.sent_subdirectory
                 FROM lmyzmail_outbound_spool spool
                 JOIN outbound_mail_queue queue ON queue.id=spool.task_id
                 WHERE spool.task_id=$1",
                &[&task_id],
            ),
        )
        .await
        .map_err(|_| DeliveryStateError::Unavailable)?
        .map_err(|_| DeliveryStateError::Unavailable)?;
        row.map(|row| {
            let sent_file_name = row
                .get::<_, Option<String>>(4)
                .filter(|value| !value.is_empty())
                .ok_or(DeliveryStateError::Unavailable)?;
            let sent_subdirectory = row
                .get::<_, Option<i32>>(5)
                .filter(|value| *value > 0)
                .ok_or(DeliveryStateError::Unavailable)?;
            Ok(OutboundSpoolRecord {
                task_id,
                spool_path: row.get(0),
                kind: OutboundSpoolKind::from_database(row.get(1))?,
                state: OutboundSpoolState::from_database(row.get(2))?,
                sender_address: row.get(3),
                sent_file_name,
                sent_subdirectory,
            })
        })
        .transpose()
    }

    pub async fn terminal_outbound_spools(
        &self,
        limit: usize,
    ) -> Result<Vec<OutboundSpoolRecord>, DeliveryStateError> {
        if limit == 0 || limit > 10_000 {
            return Err(DeliveryStateError::InvalidInput(
                "outbound spool cleanup limit is invalid",
            ));
        }
        let deadline = Instant::now() + self.operation_timeout;
        let client = self.client(deadline).await?;
        let limit = i64::try_from(limit).map_err(|_| {
            DeliveryStateError::InvalidInput("outbound spool cleanup limit is invalid")
        })?;
        let rows = timeout_at(
            deadline,
            client.query(
                "SELECT spool.task_id,spool.spool_path,spool.spool_kind,spool.cleanup_state,
                        queue.sender_address,queue.sent_file_name,queue.sent_subdirectory
                 FROM lmyzmail_outbound_spool spool
                 JOIN outbound_mail_queue queue ON queue.id=spool.task_id
                 WHERE spool.cleanup_state='OWNED'
                   AND queue.status IN ('SENT','PARTIAL_SUCCESS','FAILED','CANCELLED')
                 ORDER BY spool.task_id LIMIT $1",
                &[&limit],
            ),
        )
        .await
        .map_err(|_| DeliveryStateError::Unavailable)?
        .map_err(|_| DeliveryStateError::Unavailable)?;
        rows.into_iter()
            .map(|row| {
                let sent_file_name = row
                    .get::<_, Option<String>>(5)
                    .filter(|value| !value.is_empty())
                    .ok_or(DeliveryStateError::Unavailable)?;
                let sent_subdirectory = row
                    .get::<_, Option<i32>>(6)
                    .filter(|value| *value > 0)
                    .ok_or(DeliveryStateError::Unavailable)?;
                Ok(OutboundSpoolRecord {
                    task_id: row.get(0),
                    spool_path: row.get(1),
                    kind: OutboundSpoolKind::from_database(row.get(2))?,
                    state: OutboundSpoolState::from_database(row.get(3))?,
                    sender_address: row.get(4),
                    sent_file_name,
                    sent_subdirectory,
                })
            })
            .collect()
    }

    pub async fn mark_outbound_spool_removed(
        &self,
        task_id: i64,
        spool_path: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, DeliveryStateError> {
        validate_outbound_spool_identity(task_id, spool_path)?;
        let now = postgres_timestamp(now)?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let row = transaction
                .query_opt(
                    "SELECT spool_path,cleanup_state FROM lmyzmail_outbound_spool
                     WHERE task_id=$1 FOR UPDATE",
                    &[&task_id],
                )
                .await?
                .ok_or(DeliveryStateError::InvalidTransition(
                    "outbound spool ownership is missing",
                ))?;
            if row.get::<_, &str>(0) != spool_path {
                return Err(DeliveryStateError::InvalidTransition(
                    "outbound spool path conflicts with durable state",
                )
                .into());
            }
            let changed = match row.get::<_, &str>(1) {
                "REMOVED" => false,
                "OWNED" => {
                    transaction
                        .execute(
                            "UPDATE lmyzmail_outbound_spool
                             SET cleanup_state='REMOVED',updated_at=$2 WHERE task_id=$1",
                            &[&task_id, &now],
                        )
                        .await?;
                    true
                }
                _ => return Err(DeliveryStateError::Unavailable.into()),
            };
            transaction.commit().await?;
            Ok(changed)
        })
        .await
    }

    pub async fn removed_outbound_spools(
        &self,
        after_task_id: i64,
        limit: usize,
    ) -> Result<Vec<OutboundSpoolRecord>, DeliveryStateError> {
        if after_task_id < 0 || limit == 0 || limit > 10_000 {
            return Err(DeliveryStateError::InvalidInput(
                "removed outbound spool scan limit is invalid",
            ));
        }
        let limit = i64::try_from(limit).map_err(|_| {
            DeliveryStateError::InvalidInput("removed outbound spool scan limit is invalid")
        })?;
        let deadline = Instant::now() + self.operation_timeout;
        let client = self.client(deadline).await?;
        let rows = timeout_at(
            deadline,
            client.query(
                "SELECT spool.task_id,spool.spool_path,spool.spool_kind,spool.cleanup_state,
                        queue.sender_address,queue.sent_file_name,queue.sent_subdirectory
                 FROM lmyzmail_outbound_spool spool
                 JOIN outbound_mail_queue queue ON queue.id=spool.task_id
                 WHERE spool.cleanup_state='REMOVED'
                   AND queue.status IN ('SENT','PARTIAL_SUCCESS','FAILED','CANCELLED')
                 ORDER BY CASE WHEN spool.task_id > $1 THEN 0 ELSE 1 END,spool.task_id
                 LIMIT $2",
                &[&after_task_id, &limit],
            ),
        )
        .await
        .map_err(|_| DeliveryStateError::Unavailable)?
        .map_err(|_| DeliveryStateError::Unavailable)?;
        rows.into_iter()
            .map(|row| {
                let sent_file_name = row
                    .get::<_, Option<String>>(5)
                    .filter(|value| !value.is_empty())
                    .ok_or(DeliveryStateError::Unavailable)?;
                let sent_subdirectory = row
                    .get::<_, Option<i32>>(6)
                    .filter(|value| *value > 0)
                    .ok_or(DeliveryStateError::Unavailable)?;
                Ok(OutboundSpoolRecord {
                    task_id: row.get(0),
                    spool_path: row.get(1),
                    kind: OutboundSpoolKind::from_database(row.get(2))?,
                    state: OutboundSpoolState::from_database(row.get(3))?,
                    sender_address: row.get(4),
                    sent_file_name,
                    sent_subdirectory,
                })
            })
            .collect()
    }

    pub async fn delete_removed_outbound_spool(
        &self,
        task_id: i64,
        spool_path: &str,
    ) -> Result<bool, DeliveryStateError> {
        validate_outbound_spool_identity(task_id, spool_path)?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let row = transaction
                .query_opt(
                    "SELECT spool.spool_path,spool.cleanup_state,queue.status
                     FROM lmyzmail_outbound_spool spool
                     JOIN outbound_mail_queue queue ON queue.id=spool.task_id
                     WHERE spool.task_id=$1
                     FOR UPDATE OF spool,queue",
                    &[&task_id],
                )
                .await?;
            let Some(row) = row else {
                transaction.commit().await?;
                return Ok(false);
            };
            if row.get::<_, &str>(0) != spool_path {
                return Err(DeliveryStateError::InvalidTransition(
                    "removed outbound spool path conflicts with durable state",
                )
                .into());
            }
            if row.get::<_, &str>(1) != "REMOVED" {
                return Err(DeliveryStateError::InvalidTransition(
                    "outbound spool cannot be deleted before removal is durable",
                )
                .into());
            }
            if !DeliveryRowStatus::from_database(row.get(2))?.is_terminal() {
                return Err(DeliveryStateError::InvalidTransition(
                    "outbound spool cannot be deleted before delivery is terminal",
                )
                .into());
            }
            let deleted = transaction
                .execute(
                    "DELETE FROM lmyzmail_outbound_spool
                     WHERE task_id=$1 AND spool_path=$2 AND cleanup_state='REMOVED'",
                    &[&task_id, &spool_path],
                )
                .await?;
            if deleted != 1 {
                return Err(DeliveryStateError::Unavailable.into());
            }
            transaction.commit().await?;
            Ok(true)
        })
        .await
    }

    pub async fn materialize_legacy_redis_task(
        &self,
        task: &LegacyRedisTaskMaterialization,
        now: DateTime<Utc>,
    ) -> Result<bool, DeliveryStateError> {
        validate_legacy_redis_materialization(task)?;
        let now = postgres_timestamp(now)?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let lock_key = LEGACY_REDIS_TAKEOVER_LOCK ^ task.task_id;
            transaction
                .query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_key])
                .await?;

            let existing = transaction
                .query_opt(
                    "SELECT sender_address,recipients_json,subject,message_id,sent_file_name,
                            sent_subdirectory,status,retry_count,max_retries,processor_id
                     FROM outbound_mail_queue WHERE id=$1 FOR UPDATE",
                    &[&task.task_id],
                )
                .await?;
            let inserted = if let Some(row) = existing {
                let compatible = row.get::<_, &str>(0) == task.sender_address
                    && row.get::<_, &str>(1) == task.recipients_json
                    && row.get::<_, Option<&str>>(2) == Some(task.subject.as_str())
                    && row.get::<_, Option<&str>>(3) == Some(task.message_id.as_str())
                    && row.get::<_, Option<&str>>(4) == Some(task.sent_file_name.as_str())
                    && row.get::<_, Option<i32>>(5) == Some(task.sent_subdirectory)
                    && row.get::<_, &str>(6) == "PENDING"
                    && row.get::<_, i32>(7) == task.retry_count
                    && row.get::<_, i32>(8) == task.max_retries
                    && row.get::<_, Option<&str>>(9).is_none();
                if !compatible {
                    return Err(DeliveryStateError::InvalidTransition(
                        "legacy Redis task ID conflicts with PostgreSQL state",
                    )
                    .into());
                }
                false
            } else {
                let sent_domains_json = serde_json::to_string(&task.sent_domains)
                    .map_err(|_| DeliveryStateError::Unavailable)?;
                let failed_domains_json = serde_json::to_string(&task.failed_domains)
                    .map_err(|_| DeliveryStateError::Unavailable)?;
                transaction
                    .execute(
                        "INSERT INTO outbound_mail_queue
                         (id,sender_address,recipients_json,subject,body_text,body_html,
                          attachments_json,message_id,sent_file_name,sent_subdirectory,status,
                          retry_count,max_retries,next_retry_at,last_error,sent_domains_json,
                          failed_domains_json,created_at,updated_at,sent_at,
                          processing_started_at,processor_id)
                         VALUES ($1,$2,$3,$4,NULL,NULL,NULL,$5,$6,$7,'PENDING',$8,$9,$10,$11,
                                 $12,$13,$14,$15,NULL,NULL,NULL)",
                        &[
                            &task.task_id,
                            &task.sender_address,
                            &task.recipients_json,
                            &task.subject,
                            &task.message_id,
                            &task.sent_file_name,
                            &task.sent_subdirectory,
                            &task.retry_count,
                            &task.max_retries,
                            &task.next_retry_at,
                            &task.last_error,
                            &sent_domains_json,
                            &failed_domains_json,
                            &task.created_at,
                            &now,
                        ],
                    )
                    .await?;
                true
            };

            transaction
                .execute(
                    "INSERT INTO email_index
                     (has_attachments,subdirectory,indexed_at,received_at,size_bytes,folder,
                      from_address,message_id,subject,to_addresses,file_name,mailbox_address)
                     VALUES ($1,$2,$3,$3,$4,'sent',$5,$6,$7,$8,$9,$5)
                     ON CONFLICT ON CONSTRAINT uk_email_index_mailbox_folder_subdir_file
                     DO NOTHING",
                    &[
                        &task.has_attachments,
                        &task.sent_subdirectory,
                        &now,
                        &task.mail_size_bytes,
                        &task.sender_address,
                        &task.message_id,
                        &task.subject,
                        &task.to_addresses_json,
                        &task.sent_file_name,
                    ],
                )
                .await?;

            advance_legacy_sequence(&transaction, task.task_id).await?;
            transaction.commit().await?;
            Ok(inserted)
        })
        .await
    }

    pub async fn materialize_legacy_archive(
        &self,
        archive: &LegacyArchiveMaterialization,
    ) -> Result<bool, DeliveryStateError> {
        validate_legacy_archive(archive)?;
        let next_retry_at = postgres_timestamp(archive.next_retry_at)?;
        let sent_at = archive.sent_at.map(postgres_timestamp).transpose()?;
        let created_at = postgres_timestamp(archive.created_at)?;
        let updated_at = postgres_timestamp(archive.updated_at)?;
        let status = archive.status.database_value();
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let lock_key = LEGACY_REDIS_TAKEOVER_LOCK ^ archive.task_id;
            transaction
                .query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_key])
                .await?;
            let existing = transaction
                .query_opt(
                    "SELECT sender_address,recipients_json,subject,message_id,sent_file_name,
                            sent_subdirectory,status,retry_count,max_retries,
                            EXISTS(SELECT 1 FROM lmyzmail_outbound_delivery_attempt
                                   WHERE task_id=$1)
                     FROM outbound_mail_queue WHERE id=$1 FOR UPDATE",
                    &[&archive.task_id],
                )
                .await?;
            let inserted = if let Some(row) = existing {
                let compatible = row.get::<_, &str>(0) == archive.sender_address
                    && row.get::<_, &str>(1) == archive.recipients_json
                    && row.get::<_, Option<&str>>(2) == archive.subject.as_deref()
                    && row.get::<_, Option<&str>>(3) == archive.message_id.as_deref()
                    && row.get::<_, Option<&str>>(4) == archive.sent_file_name.as_deref()
                    && row.get::<_, Option<i32>>(5) == archive.sent_subdirectory
                    && row.get::<_, i32>(8) == archive.max_retries;
                if !compatible {
                    return Err(DeliveryStateError::InvalidTransition(
                        "legacy archive identity conflicts with PostgreSQL state",
                    )
                    .into());
                }
                let current = DeliveryRowStatus::from_database(row.get(6))?;
                let has_sidecar: bool = row.get(9);
                if (has_sidecar || current.is_terminal()) && current != archive.status {
                    return Err(DeliveryStateError::InvalidTransition(
                        "legacy archive conflicts with a durable delivery result",
                    )
                    .into());
                }
                transaction
                    .execute(
                        "UPDATE outbound_mail_queue
                         SET retry_count=GREATEST(retry_count,$2),next_retry_at=$3,
                             last_error=$4,status=$5,sent_at=$6,sent_domains_json=$7,
                             failed_domains_json=$8,updated_at=GREATEST(updated_at,$9),
                             processor_id=NULL,processing_started_at=NULL
                         WHERE id=$1",
                        &[
                            &archive.task_id,
                            &archive.retry_count,
                            &next_retry_at,
                            &archive.last_error,
                            &status,
                            &sent_at,
                            &archive.sent_domains_json,
                            &archive.failed_domains_json,
                            &updated_at,
                        ],
                    )
                    .await?;
                false
            } else {
                transaction
                    .execute(
                        "INSERT INTO outbound_mail_queue
                         (id,sender_address,recipients_json,subject,body_text,body_html,
                          attachments_json,message_id,sent_file_name,sent_subdirectory,status,
                          retry_count,max_retries,next_retry_at,last_error,sent_domains_json,
                          failed_domains_json,created_at,updated_at,sent_at,
                          processing_started_at,processor_id)
                         VALUES ($1,$2,$3,$4,NULL,NULL,NULL,$5,$6,$7,$8,$9,$10,$11,$12,
                                 $13,$14,$15,$16,$17,NULL,NULL)",
                        &[
                            &archive.task_id,
                            &archive.sender_address,
                            &archive.recipients_json,
                            &archive.subject,
                            &archive.message_id,
                            &archive.sent_file_name,
                            &archive.sent_subdirectory,
                            &status,
                            &archive.retry_count,
                            &archive.max_retries,
                            &next_retry_at,
                            &archive.last_error,
                            &archive.sent_domains_json,
                            &archive.failed_domains_json,
                            &created_at,
                            &updated_at,
                            &sent_at,
                        ],
                    )
                    .await?;
                true
            };
            advance_legacy_sequence(&transaction, archive.task_id).await?;
            transaction.commit().await?;
            Ok(inserted)
        })
        .await
    }

    pub async fn apply_legacy_status_update(
        &self,
        update: &LegacyStatusMaterialization,
    ) -> Result<bool, DeliveryStateError> {
        validate_legacy_status(update)?;
        let sent_at = update.sent_at.map(postgres_timestamp).transpose()?;
        let updated_at = postgres_timestamp(update.updated_at)?;
        let status = update.status.database_value();
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let lock_key = LEGACY_REDIS_TAKEOVER_LOCK ^ update.task_id;
            transaction
                .query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_key])
                .await?;
            let existing = transaction
                .query_opt(
                    "SELECT status,retry_count,max_retries,
                            EXISTS(SELECT 1 FROM lmyzmail_outbound_delivery_attempt
                                   WHERE task_id=$1)
                     FROM outbound_mail_queue WHERE id=$1 FOR UPDATE",
                    &[&update.task_id],
                )
                .await?;
            let Some(row) = existing else {
                transaction.commit().await?;
                return Ok(false);
            };
            let current = DeliveryRowStatus::from_database(row.get(0))?;
            let current_retry: i32 = row.get(1);
            let max_retries: i32 = row.get(2);
            let has_sidecar: bool = row.get(3);
            if update.retry_count > max_retries
                || (update.status == DeliveryRowStatus::Pending
                    && update.retry_count < current_retry)
            {
                return Err(DeliveryStateError::InvalidTransition(
                    "legacy status retry count conflicts with PostgreSQL state",
                )
                .into());
            }
            if (has_sidecar || current.is_terminal()) && current != update.status {
                return Err(DeliveryStateError::InvalidTransition(
                    "legacy status conflicts with a durable delivery result",
                )
                .into());
            }
            transaction
                .execute(
                    "UPDATE outbound_mail_queue
                     SET status=$2,sent_at=$3,last_error=$4,
                         retry_count=GREATEST(retry_count,$5),
                         sent_domains_json=$6,failed_domains_json=$7,
                         updated_at=GREATEST(updated_at,$8),processor_id=NULL,
                         processing_started_at=NULL
                     WHERE id=$1",
                    &[
                        &update.task_id,
                        &status,
                        &sent_at,
                        &update.last_error,
                        &update.retry_count,
                        &update.sent_domains_json,
                        &update.failed_domains_json,
                        &updated_at,
                    ],
                )
                .await?;
            transaction.commit().await?;
            Ok(true)
        })
        .await
    }

    pub async fn begin_attempt(
        &self,
        claim: &DatabaseClaim,
        recipients: &[String],
        now: DateTime<Utc>,
    ) -> Result<RecipientLedgerClaim, DeliveryStateError> {
        validate_claim(claim)?;
        validate_recipient_roster(recipients)?;
        let now = postgres_timestamp(now)?;
        let roster_sha256 = roster_fingerprint(recipients);
        let recipient_count = recipients.len() as i32;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            lock_legacy_claim(&transaction, claim).await?;
            let attempt = transaction
                .query_opt(
                    "SELECT generation,owner_token,phase,recipient_count,roster_sha256
                     FROM lmyzmail_outbound_delivery_attempt
                     WHERE task_id=$1 FOR UPDATE",
                    &[&claim.task_id],
                )
                .await?;
            let existing = transaction
                .query(
                    "SELECT recipient_ordinal,recipient_address,state
                     FROM lmyzmail_outbound_delivery_recipient
                     WHERE task_id=$1 ORDER BY recipient_ordinal FOR UPDATE",
                    &[&claim.task_id],
                )
                .await?;

            if attempt.is_some() {
                if existing.len() != recipients.len()
                    || existing.iter().zip(recipients).enumerate().any(
                        |(ordinal, (row, recipient))| {
                            row.get::<_, i32>(0) != ordinal as i32
                                || row.get::<_, &str>(1) != recipient
                        },
                    )
                {
                    return Err(DeliveryStateError::InvalidTransition(
                        "delivery recipient roster changed",
                    )
                    .into());
                }
                if existing
                    .iter()
                    .any(|row| row.get::<_, &str>(2) == "AMBIGUOUS")
                {
                    return Err(DeliveryStateError::InvalidTransition(
                        "ambiguous delivery recipients cannot be retried",
                    )
                    .into());
                }
                let row = attempt.as_ref().ok_or(DeliveryStateError::Unavailable)?;
                if row.get::<_, i32>(3) != recipient_count
                    || row.get::<_, Vec<u8>>(4) != roster_sha256
                {
                    return Err(DeliveryStateError::InvalidTransition(
                        "delivery recipient roster fingerprint changed",
                    )
                    .into());
                }
                validate_commit_barrier_consistency(
                    row.get(2),
                    existing
                        .iter()
                        .any(|recipient| recipient.get::<_, &str>(2) == "COMMIT_ARMED"),
                )?;
            } else if !existing.is_empty() {
                return Err(DeliveryStateError::InvalidTransition(
                    "delivery recipient roster has no attempt row",
                )
                .into());
            }

            let generation = match attempt {
                None => {
                    transaction
                        .execute(
                            "INSERT INTO lmyzmail_outbound_delivery_attempt
                             (task_id,generation,owner_token,recipient_count,roster_sha256,
                              phase,created_at,updated_at)
                             VALUES ($1,1,$2,$3,$4,'PREPARING',$5,$5)",
                            &[
                                &claim.task_id,
                                &claim.owner_token,
                                &recipient_count,
                                &&roster_sha256[..],
                                &now,
                            ],
                        )
                        .await?;
                    let ordinals: Vec<i32> =
                        (0..recipients.len()).map(|value| value as i32).collect();
                    let states = vec!["PENDING"; recipients.len()];
                    let generations = vec![0_i64; recipients.len()];
                    transaction
                        .execute(
                            "INSERT INTO lmyzmail_outbound_delivery_recipient
                             (task_id,recipient_ordinal,recipient_address,state,
                              attempt_generation,updated_at)
                             SELECT $1,ordinal,address,state,generation,$3
                             FROM unnest($2::int4[],$4::text[],$5::text[],$6::int8[])
                                  AS roster(ordinal,address,state,generation)",
                            &[
                                &claim.task_id,
                                &ordinals,
                                &now,
                                &recipients,
                                &states,
                                &generations,
                            ],
                        )
                        .await?;
                    1
                }
                Some(row) => {
                    let generation: i64 = row.get(0);
                    let owner: Option<&str> = row.get(1);
                    let phase: &str = row.get(2);
                    if owner == Some(claim.owner_token.as_str()) && phase != "PROJECTED" {
                        generation
                    } else {
                        if phase == "COMMIT_ARMED" {
                            return Err(DeliveryStateError::InvalidTransition(
                                "armed delivery attempt requires ambiguity recovery",
                            )
                            .into());
                        }
                        let next_generation = generation.checked_add(1).ok_or(
                            DeliveryStateError::InvalidTransition(
                                "delivery attempt generation exhausted",
                            ),
                        )?;
                        transaction
                            .execute(
                                "UPDATE lmyzmail_outbound_delivery_attempt
                                 SET generation=$2,owner_token=$3,phase='PREPARING',updated_at=$4
                                 WHERE task_id=$1",
                                &[&claim.task_id, &next_generation, &claim.owner_token, &now],
                            )
                            .await?;
                        next_generation
                    }
                }
            };
            transaction.commit().await?;
            Ok(RecipientLedgerClaim {
                task_id: claim.task_id,
                generation,
                owner_token: claim.owner_token.clone(),
                recipient_count: recipients.len(),
                roster_sha256,
            })
        })
        .await
    }

    pub async fn resume_attempt(
        &self,
        claim: &DatabaseClaim,
        recipients: &[String],
    ) -> Result<Option<RecipientLedgerClaim>, DeliveryStateError> {
        validate_claim(claim)?;
        validate_recipient_roster(recipients)?;
        let deadline = Instant::now() + self.operation_timeout;
        let client = self.client(deadline).await?;
        let rows = read_deadline(
            deadline,
            client.query(
                "SELECT a.generation,a.recipient_count,a.roster_sha256,a.phase,
                        r.recipient_ordinal,r.recipient_address
                 FROM lmyzmail_outbound_delivery_attempt a
                 JOIN outbound_mail_queue legacy ON legacy.id=a.task_id
                 LEFT JOIN lmyzmail_outbound_delivery_recipient r ON r.task_id=a.task_id
                 WHERE a.task_id=$1 AND a.owner_token=$2
                   AND legacy.status='PROCESSING' AND legacy.processor_id=$2
                 ORDER BY r.recipient_ordinal",
                &[&claim.task_id, &claim.owner_token],
            ),
        )
        .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        if rows[0].get::<_, &str>(3) == "PROJECTED"
            || rows[0].get::<_, i32>(1) != recipients.len() as i32
            || rows[0].get::<_, Vec<u8>>(2) != roster_fingerprint(recipients)
            || rows.len() != recipients.len()
            || rows
                .iter()
                .zip(recipients)
                .enumerate()
                .any(|(ordinal, (row, recipient))| {
                    row.get::<_, Option<i32>>(4) != Some(ordinal as i32)
                        || row.get::<_, Option<&str>>(5) != Some(recipient)
                })
        {
            return Err(DeliveryStateError::Unavailable);
        }
        Ok(Some(RecipientLedgerClaim {
            task_id: claim.task_id,
            generation: rows[0].get(0),
            owner_token: claim.owner_token.clone(),
            recipient_count: recipients.len(),
            roster_sha256: roster_fingerprint(recipients),
        }))
    }

    pub async fn ledger_snapshot(
        &self,
        task_id: i64,
        claim: Option<&RecipientLedgerClaim>,
    ) -> Result<Option<RecipientLedgerSnapshot>, DeliveryStateError> {
        if task_id <= 0 {
            return Err(DeliveryStateError::InvalidInput("task ID must be positive"));
        }
        if let Some(claim) = claim {
            validate_ledger_claim(claim)?;
            if claim.task_id != task_id {
                return Err(DeliveryStateError::InvalidInput(
                    "delivery claim does not match task ID",
                ));
            }
        }
        let deadline = Instant::now() + self.operation_timeout;
        let client = self.client(deadline).await?;
        let rows = read_deadline(
            deadline,
            client.query(
                "SELECT a.generation,a.owner_token,a.phase,a.recipient_count,a.roster_sha256,
                        r.recipient_ordinal,r.recipient_address,r.state,
                        r.attempt_generation,r.smtp_code,r.detail
                 FROM lmyzmail_outbound_delivery_attempt a
                 LEFT JOIN lmyzmail_outbound_delivery_recipient r ON r.task_id=a.task_id
                 WHERE a.task_id=$1 ORDER BY r.recipient_ordinal",
                &[&task_id],
            ),
        )
        .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        let owner: Option<String> = rows[0].get(1);
        let mut recipients = Vec::with_capacity(rows.len());
        for row in &rows {
            let ordinal: Option<i32> = row.get(5);
            let Some(ordinal) = ordinal else {
                return Err(DeliveryStateError::Unavailable);
            };
            recipients.push(RecipientLedgerEntry {
                ordinal: u16::try_from(ordinal).map_err(|_| DeliveryStateError::Unavailable)?,
                recipient: row.get(6),
                state: RecipientDeliveryState::from_database(row.get(7))?,
                attempt_generation: row.get(8),
                smtp_code: row
                    .get::<_, Option<i32>>(9)
                    .map(u16::try_from)
                    .transpose()
                    .map_err(|_| DeliveryStateError::Unavailable)?,
                detail: row.get(10),
            });
        }
        let stored_count: i32 = rows[0].get(3);
        let stored_fingerprint: Vec<u8> = rows[0].get(4);
        let roster: Vec<String> = recipients
            .iter()
            .map(|recipient| recipient.recipient.clone())
            .collect();
        if stored_count != recipients.len() as i32
            || stored_fingerprint != roster_fingerprint(&roster)
            || recipients
                .iter()
                .enumerate()
                .any(|(ordinal, recipient)| recipient.ordinal as usize != ordinal)
        {
            return Err(DeliveryStateError::Unavailable);
        }
        let phase = DeliveryAttemptPhase::from_database(rows[0].get(2))?;
        validate_commit_barrier_consistency(
            phase.database_value(),
            recipients
                .iter()
                .any(|recipient| recipient.state == RecipientDeliveryState::CommitArmed),
        )?;
        Ok(Some(RecipientLedgerSnapshot {
            task_id,
            generation: rows[0].get(0),
            phase,
            has_owner: owner.is_some(),
            owned_by_claim: claim.is_some_and(|claim| {
                owner.as_deref() == Some(&claim.owner_token)
                    && rows[0].get::<_, i64>(0) == claim.generation
            }),
            recipients,
        }))
    }

    pub async fn checkpoint_prepared(
        &self,
        claim: &RecipientLedgerClaim,
        outcomes: &[PreparedRecipientCheckpoint],
        now: DateTime<Utc>,
    ) -> Result<bool, DeliveryStateError> {
        validate_ledger_claim(claim)?;
        validate_prepared_outcomes(outcomes)?;
        let now = postgres_timestamp(now)?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            lock_legacy_claim(&transaction, claim).await?;
            let attempt = lock_ledger_attempt(&transaction, claim).await?;
            if attempt.1 != "PREPARING" {
                return Err(DeliveryStateError::InvalidTransition(
                    "delivery attempt is not preparing",
                )
                .into());
            }
            let active = transaction
                .query(
                    "SELECT recipient_ordinal,recipient_address
                     FROM lmyzmail_outbound_delivery_recipient
                     WHERE task_id=$1 AND state IN ('PENDING','RETRYABLE')
                     ORDER BY recipient_ordinal FOR UPDATE",
                    &[&claim.task_id],
                )
                .await?;
            let mut sorted: Vec<&PreparedRecipientCheckpoint> = outcomes.iter().collect();
            sorted.sort_by_key(|outcome| outcome.ordinal);
            let domains: BTreeSet<String> = sorted
                .iter()
                .map(|outcome| recipient_domain(&outcome.recipient))
                .collect::<Result<_, _>>()?;
            let expected: Vec<_> = active
                .iter()
                .filter(|row| {
                    recipient_domain(row.get::<_, &str>(1))
                        .is_ok_and(|domain| domains.contains(&domain))
                })
                .collect();
            if expected.is_empty()
                || expected.len() != sorted.len()
                || expected.iter().zip(&sorted).any(|(row, outcome)| {
                    row.get::<_, i32>(0) != i32::from(outcome.ordinal)
                        || row.get::<_, &str>(1) != outcome.recipient
                })
            {
                return Err(DeliveryStateError::InvalidTransition(
                    "prepared checkpoint does not cover the retryable roster",
                )
                .into());
            }

            let ordinals: Vec<i32> = sorted
                .iter()
                .map(|outcome| i32::from(outcome.ordinal))
                .collect();
            let states: Vec<&str> = sorted
                .iter()
                .map(|outcome| outcome.status.ledger_state().database_value())
                .collect();
            let codes: Vec<i32> = sorted
                .iter()
                .map(|outcome| i32::from(outcome.smtp_code))
                .collect();
            let details: Vec<String> = sorted
                .iter()
                .map(|outcome| bounded_bytes(&outcome.detail, MAX_RECIPIENT_DETAIL_BYTES))
                .collect();
            let updated = transaction
                .execute(
                    "UPDATE lmyzmail_outbound_delivery_recipient recipient
                     SET state=checkpoint.state,attempt_generation=$2,
                         smtp_code=checkpoint.smtp_code,detail=checkpoint.detail,updated_at=$3
                     FROM unnest($4::int4[],$5::text[],$6::int4[],$7::text[])
                          AS checkpoint(ordinal,state,smtp_code,detail)
                     WHERE recipient.task_id=$1
                       AND recipient.recipient_ordinal=checkpoint.ordinal
                       AND recipient.state IN ('PENDING','RETRYABLE')",
                    &[
                        &claim.task_id,
                        &attempt.0,
                        &now,
                        &ordinals,
                        &states,
                        &codes,
                        &details,
                    ],
                )
                .await?;
            if updated != outcomes.len() as u64 {
                return Err(DeliveryStateError::InvalidTransition(
                    "prepared checkpoint raced with recipient state",
                )
                .into());
            }
            let armed = outcomes
                .iter()
                .any(|outcome| outcome.status == PreparedRecipientStatus::Accepted);
            let attempt_updated = transaction
                .execute(
                    "UPDATE lmyzmail_outbound_delivery_attempt
                     SET phase=$3,updated_at=$4
                     WHERE task_id=$1 AND owner_token=$2 AND generation=$5",
                    &[
                        &claim.task_id,
                        &claim.owner_token,
                        &(if armed { "COMMIT_ARMED" } else { "PREPARING" }),
                        &now,
                        &claim.generation,
                    ],
                )
                .await?;
            if attempt_updated != 1 {
                return Err(DeliveryStateError::Fenced.into());
            }
            transaction.commit().await?;
            Ok(armed)
        })
        .await
    }

    pub async fn checkpoint_result(
        &self,
        claim: &RecipientLedgerClaim,
        status: CommitResultStatus,
        smtp_code: u16,
        detail: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, DeliveryStateError> {
        validate_ledger_claim(claim)?;
        validate_commit_result(status, smtp_code, detail)?;
        let now = postgres_timestamp(now)?;
        let detail = bounded_bytes(detail, MAX_RECIPIENT_DETAIL_BYTES);
        let state = status.ledger_state().database_value();
        let smtp_code = i32::from(smtp_code);
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            lock_legacy_claim(&transaction, claim).await?;
            let attempt = lock_ledger_attempt(&transaction, claim).await?;
            if attempt.1 != "COMMIT_ARMED" {
                return Err(DeliveryStateError::InvalidTransition(
                    "delivery attempt is not commit-armed",
                )
                .into());
            }
            let updated = transaction
                .execute(
                    "UPDATE lmyzmail_outbound_delivery_recipient
                     SET state=$2,attempt_generation=$3,smtp_code=$4,detail=$5,updated_at=$6
                     WHERE task_id=$1 AND state='COMMIT_ARMED'",
                    &[
                        &claim.task_id,
                        &state,
                        &attempt.0,
                        &smtp_code,
                        &detail,
                        &now,
                    ],
                )
                .await?;
            if updated == 0 {
                return Err(DeliveryStateError::InvalidTransition(
                    "commit-armed attempt has no armed recipients",
                )
                .into());
            }
            let attempt_updated = transaction
                .execute(
                    "UPDATE lmyzmail_outbound_delivery_attempt
                     SET phase='PREPARING',updated_at=$3
                     WHERE task_id=$1 AND owner_token=$2 AND generation=$4
                       AND phase='COMMIT_ARMED'",
                    &[&claim.task_id, &claim.owner_token, &now, &claim.generation],
                )
                .await?;
            if attempt_updated != 1 {
                return Err(DeliveryStateError::Fenced.into());
            }
            transaction.commit().await?;
            Ok(updated as usize)
        })
        .await
    }

    pub async fn checkpoint_ambiguous(
        &self,
        claim: &RecipientLedgerClaim,
        detail: &str,
        now: DateTime<Utc>,
    ) -> Result<usize, DeliveryStateError> {
        validate_ledger_claim(claim)?;
        if detail.is_empty() {
            return Err(DeliveryStateError::InvalidInput(
                "ambiguous delivery detail must not be empty",
            ));
        }
        let now = postgres_timestamp(now)?;
        let detail = bounded_bytes(detail, MAX_RECIPIENT_DETAIL_BYTES);
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            lock_legacy_claim(&transaction, claim).await?;
            let attempt = lock_ledger_attempt(&transaction, claim).await?;
            if attempt.1 != "COMMIT_ARMED" {
                return Err(DeliveryStateError::InvalidTransition(
                    "delivery attempt is not commit-armed",
                )
                .into());
            }
            let updated = transaction
                .execute(
                    "UPDATE lmyzmail_outbound_delivery_recipient
                     SET state='AMBIGUOUS',attempt_generation=$2,smtp_code=NULL,
                         detail=$3,updated_at=$4
                     WHERE task_id=$1 AND state='COMMIT_ARMED'",
                    &[&claim.task_id, &attempt.0, &detail, &now],
                )
                .await?;
            if updated == 0 {
                return Err(DeliveryStateError::InvalidTransition(
                    "commit-armed attempt has no armed recipients",
                )
                .into());
            }
            let attempt_updated = transaction
                .execute(
                    "UPDATE lmyzmail_outbound_delivery_attempt
                     SET phase='PREPARING',updated_at=$3
                     WHERE task_id=$1 AND owner_token=$2 AND generation=$4
                       AND phase='COMMIT_ARMED'",
                    &[&claim.task_id, &claim.owner_token, &now, &claim.generation],
                )
                .await?;
            if attempt_updated != 1 {
                return Err(DeliveryStateError::Fenced.into());
            }
            transaction.commit().await?;
            Ok(updated as usize)
        })
        .await
    }

    pub async fn project_legacy(
        &self,
        claim: &RecipientLedgerClaim,
        next_retry_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<LegacyProjection, DeliveryStateError> {
        validate_ledger_claim(claim)?;
        let now = postgres_timestamp(now)?;
        let next_retry_at = next_retry_at.map(postgres_timestamp).transpose()?;
        if next_retry_at.is_some_and(|retry_at| retry_at <= now) {
            return Err(DeliveryStateError::InvalidInput(
                "retry deadline must be in the future",
            ));
        }
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let (retry_count, max_retries) = lock_legacy_claim(&transaction, claim).await?;
            let attempt = lock_ledger_attempt(&transaction, claim).await?;
            if attempt.1 == "COMMIT_ARMED" {
                return Err(DeliveryStateError::InvalidTransition(
                    "commit-armed delivery cannot be projected",
                )
                .into());
            }
            let rows = transaction
                .query(
                    "SELECT recipient_ordinal,recipient_address,state,detail
                     FROM lmyzmail_outbound_delivery_recipient
                     WHERE task_id=$1 ORDER BY recipient_ordinal FOR UPDATE",
                    &[&claim.task_id],
                )
                .await?;
            let mut recipients = ledger_rows_for_projection(&rows)?;
            if recipients.is_empty()
                || recipients
                    .iter()
                    .any(|recipient| recipient.state == RecipientDeliveryState::Pending)
            {
                return Err(DeliveryStateError::InvalidTransition(
                    "not all recipient domains have a checkpoint",
                )
                .into());
            }
            if recipients
                .iter()
                .any(|recipient| recipient.state == RecipientDeliveryState::CommitArmed)
            {
                return Err(DeliveryStateError::InvalidTransition(
                    "commit-armed recipients cannot be projected",
                )
                .into());
            }

            let ambiguous = recipients
                .iter()
                .any(|recipient| recipient.state == RecipientDeliveryState::Ambiguous);
            let retryable = recipients
                .iter()
                .any(|recipient| recipient.state == RecipientDeliveryState::Retryable);
            if !ambiguous && retryable && retry_count < max_retries {
                let retry_at = next_retry_at.ok_or(DeliveryStateError::InvalidInput(
                    "retry deadline is required for retryable recipients",
                ))?;
                let last_error = projection_error(&recipients, "temporary delivery failure")?;
                let row = transaction
                    .query_one(
                        "UPDATE outbound_mail_queue
                         SET status='PENDING',retry_count=retry_count+1,next_retry_at=$3,
                             last_error=$4,processor_id=NULL,processing_started_at=NULL,updated_at=$5
                         WHERE id=$1 AND status='PROCESSING' AND processor_id=$2
                         RETURNING retry_count,max_retries,next_retry_at",
                        &[&claim.task_id, &claim.owner_token, &retry_at, &last_error, &now],
                    )
                    .await?;
                project_attempt_row(&transaction, claim, now).await?;
                let transition = RetryTransition {
                    retry_count: row.get(0),
                    max_retries: row.get(1),
                    next_retry_at: row.get(2),
                };
                transaction.commit().await?;
                return Ok(LegacyProjection::RetryScheduled(transition));
            }

            let exhausted = !ambiguous && retryable;
            if exhausted {
                transaction
                    .execute(
                        "UPDATE lmyzmail_outbound_delivery_recipient
                         SET state='PERMANENT',attempt_generation=$2,
                             detail=COALESCE(detail,'retry limit exhausted'),updated_at=$3
                         WHERE task_id=$1 AND state='RETRYABLE'",
                        &[&claim.task_id, &attempt.0, &now],
                    )
                    .await?;
                for recipient in &mut recipients {
                    if recipient.state == RecipientDeliveryState::Retryable {
                        recipient.state = RecipientDeliveryState::Permanent;
                        if recipient.detail.is_none() {
                            recipient.detail = Some("retry limit exhausted".into());
                        }
                    }
                }
            }

            let (sent_domains, failed_domains) = projection_domains(&recipients)?;
            let sent_domains_json = serialize_optional(&sent_domains)?;
            let failed_domains_json = if ambiguous {
                None
            } else {
                serialize_optional(&failed_domains)?
            };
            let delivered = recipients
                .iter()
                .filter(|recipient| recipient.state == RecipientDeliveryState::Delivered)
                .count();
            let permanent = recipients
                .iter()
                .filter(|recipient| recipient.state == RecipientDeliveryState::Permanent)
                .count();
            let terminal = if ambiguous || exhausted || delivered == 0 {
                TerminalStatus::Failed
            } else if permanent == 0 {
                TerminalStatus::Sent
            } else {
                TerminalStatus::PartialSuccess
            };
            let legacy_status = terminal.database_value();
            let sent_at = terminal.records_sent_at().then_some(now);
            let last_error = if ambiguous {
                Some("Ambiguous SMTP commit; automatic retry and DSN are forbidden".to_owned())
            } else if terminal == TerminalStatus::Sent {
                None
            } else {
                Some(projection_error(&recipients, "permanent delivery failure")?)
            };
            transaction
                .execute(
                    "UPDATE outbound_mail_queue
                     SET status=$3,sent_at=$4,last_error=$5,sent_domains_json=$6,
                         failed_domains_json=$7,processor_id=NULL,
                         processing_started_at=NULL,updated_at=$8
                     WHERE id=$1 AND status='PROCESSING' AND processor_id=$2",
                    &[
                        &claim.task_id,
                        &claim.owner_token,
                        &legacy_status,
                        &sent_at,
                        &last_error,
                        &sent_domains_json,
                        &failed_domains_json,
                        &now,
                    ],
                )
                .await?;
            project_attempt_row(&transaction, claim, now).await?;
            transaction.commit().await?;
            Ok(if ambiguous {
                LegacyProjection::Ambiguous
            } else {
                LegacyProjection::Terminal(terminal)
            })
        })
        .await
    }

    pub async fn claim(
        &self,
        task_id: i64,
        worker_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DatabaseClaim>, DeliveryStateError> {
        let attempt = DeliveryAttemptId::generate(task_id, worker_id)?;
        self.claim_with_attempt(&attempt, now).await
    }

    pub async fn claim_with_attempt(
        &self,
        attempt: &DeliveryAttemptId,
        now: DateTime<Utc>,
    ) -> Result<Option<DatabaseClaim>, DeliveryStateError> {
        validate_attempt(attempt)?;
        let task_id = attempt.task_id;
        let owner_token = attempt.owner_token.clone();
        let now = postgres_timestamp(now)?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        let row = ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let row = transaction
                .query_opt(
                    "UPDATE outbound_mail_queue
                 SET status=CASE
                       WHEN retry_count >= 0 AND max_retries >= 0 AND retry_count <= max_retries
                       THEN 'PROCESSING' ELSE 'FAILED' END,
                     processor_id=CASE
                       WHEN retry_count >= 0 AND max_retries >= 0 AND retry_count <= max_retries
                       THEN $2 ELSE NULL END,
                     processing_started_at=CASE
                       WHEN retry_count >= 0 AND max_retries >= 0 AND retry_count <= max_retries
                       THEN $3 ELSE NULL END,
                     sent_at=CASE
                       WHEN retry_count >= 0 AND max_retries >= 0 AND retry_count <= max_retries
                       THEN sent_at ELSE NULL END,
                     last_error=CASE
                       WHEN retry_count >= 0 AND max_retries >= 0 AND retry_count <= max_retries
                       THEN last_error ELSE 'Invalid legacy retry state' END,
                     updated_at=$3
                 WHERE id=$1 AND status='PENDING' AND processor_id IS NULL
                   AND next_retry_at <= $3
                 RETURNING status,retry_count,max_retries",
                    &[&task_id, &owner_token, &now],
                )
                .await?;
            transaction.commit().await?;
            Ok(row)
        })
        .await?;
        Ok(row.and_then(|row| {
            (row.get::<_, &str>(0) == "PROCESSING").then(|| DatabaseClaim {
                task_id,
                retry_count: row.get(1),
                max_retries: row.get(2),
                owner_token,
            })
        }))
    }

    pub async fn reconcile_attempt_claim(
        &self,
        attempt: &DeliveryAttemptId,
    ) -> Result<Option<DatabaseClaim>, DeliveryStateError> {
        validate_attempt(attempt)?;
        let deadline = Instant::now() + self.operation_timeout;
        let client = self.client(deadline).await?;
        let row = read_deadline(
            deadline,
            client.query_opt(
                "SELECT status,retry_count,max_retries,processor_id
                 FROM outbound_mail_queue WHERE id=$1",
                &[&attempt.task_id],
            ),
        )
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let retry_count: i32 = row.get(1);
        let max_retries: i32 = row.get(2);
        if retry_count < 0 || max_retries < 0 || retry_count > max_retries {
            return Err(DeliveryStateError::InvalidTransition(
                "invalid legacy retry state reached claim reconciliation",
            ));
        }
        let owner: Option<&str> = row.get(3);
        if row.get::<_, &str>(0) != "PROCESSING" || owner != Some(attempt.owner_token.as_str()) {
            return Ok(None);
        }
        Ok(Some(DatabaseClaim {
            task_id: attempt.task_id,
            retry_count,
            max_retries,
            owner_token: attempt.owner_token.clone(),
        }))
    }

    pub async fn claimed_recipient_roster(
        &self,
        claim: &DatabaseClaim,
    ) -> Result<Vec<String>, DeliveryStateError> {
        validate_claim(claim)?;
        let deadline = Instant::now() + self.operation_timeout;
        let client = self.client(deadline).await?;
        let row = read_deadline(
            deadline,
            client.query_opt(
                "SELECT recipients_json FROM outbound_mail_queue
                 WHERE id=$1 AND status='PROCESSING' AND processor_id=$2",
                &[&claim.task_id, &claim.owner_token],
            ),
        )
        .await?
        .ok_or(DeliveryStateError::Fenced)?;
        parse_recipient_roster_json(row.get(0))
    }

    pub async fn heartbeat(
        &self,
        claim: &DatabaseClaim,
        now: DateTime<Utc>,
    ) -> Result<bool, DeliveryStateError> {
        validate_claim(claim)?;
        let now = postgres_timestamp(now)?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        let updated = ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let updated = transaction
                .execute(
                    "UPDATE outbound_mail_queue
                 SET processing_started_at=GREATEST(processing_started_at,$3),
                     updated_at=GREATEST(updated_at,$3)
                 WHERE id=$1 AND status='PROCESSING' AND processor_id=$2",
                    &[&claim.task_id, &claim.owner_token, &now],
                )
                .await?;
            transaction.commit().await?;
            Ok(updated)
        })
        .await?;
        Ok(updated == 1)
    }

    pub async fn release(
        &self,
        claim: &DatabaseClaim,
        now: DateTime<Utc>,
    ) -> Result<bool, DeliveryStateError> {
        validate_claim(claim)?;
        let now = postgres_timestamp(now)?;
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            match lock_legacy_claim(&transaction, claim).await {
                Ok(_) => {}
                Err(LedgerMutationError::State(DeliveryStateError::Fenced)) => {
                    transaction.rollback().await?;
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
            let attempt = transaction
                .query_opt(
                    "SELECT generation,owner_token,phase,recipient_count,roster_sha256
                     FROM lmyzmail_outbound_delivery_attempt
                     WHERE task_id=$1 FOR UPDATE",
                    &[&claim.task_id],
                )
                .await?;
            let armed = if let Some(attempt) = attempt {
                let generation: i64 = attempt.get(0);
                let owner: Option<&str> = attempt.get(1);
                let phase: &str = attempt.get(2);
                if owner != Some(claim.owner_token.as_str()) || phase == "PROJECTED" {
                    return Err(DeliveryStateError::Fenced.into());
                }
                let recipient_count: i32 = attempt.get(3);
                let roster_sha256: Vec<u8> = attempt.get(4);
                let fingerprint: [u8; 32] = roster_sha256.try_into().map_err(|_| {
                    DeliveryStateError::InvalidTransition(
                        "delivery recipient roster fingerprint is invalid",
                    )
                })?;
                if recipient_count <= 0
                    || !verify_roster(
                        &transaction,
                        claim.task_id,
                        recipient_count as usize,
                        &fingerprint,
                    )
                    .await?
                {
                    return Err(DeliveryStateError::InvalidTransition(
                        "delivery recipient roster failed integrity verification",
                    )
                    .into());
                }
                verify_commit_barrier_consistency(&transaction, claim.task_id, phase).await?;
                if phase == "COMMIT_ARMED" {
                    transaction
                        .execute(
                            "UPDATE lmyzmail_outbound_delivery_recipient
                             SET state='AMBIGUOUS',attempt_generation=$2,smtp_code=NULL,
                                 detail='delivery released after SMTP commit was armed',updated_at=$3
                             WHERE task_id=$1 AND state='COMMIT_ARMED'",
                            &[&claim.task_id, &generation, &now],
                        )
                        .await?;
                    true
                } else {
                    false
                }
            } else {
                false
            };
            let updated = if armed {
                transaction
                    .execute(
                        "UPDATE outbound_mail_queue
                         SET status='FAILED',sent_at=NULL,
                             last_error='Ambiguous SMTP commit; automatic retry and DSN are forbidden',
                             failed_domains_json=NULL,processor_id=NULL,
                             processing_started_at=NULL,updated_at=$3
                         WHERE id=$1 AND status='PROCESSING' AND processor_id=$2",
                        &[&claim.task_id, &claim.owner_token, &now],
                    )
                    .await?
            } else {
                transaction
                    .execute(
                        "UPDATE outbound_mail_queue
                         SET status='PENDING',processor_id=NULL,processing_started_at=NULL,
                             next_retry_at=LEAST(next_retry_at,$3),updated_at=$3
                         WHERE id=$1 AND status='PROCESSING' AND processor_id=$2",
                        &[&claim.task_id, &claim.owner_token, &now],
                    )
                    .await?
            };
            if let Some(attempt) = transaction
                .query_opt(
                    "SELECT generation FROM lmyzmail_outbound_delivery_attempt
                     WHERE task_id=$1 AND owner_token=$2 FOR UPDATE",
                    &[&claim.task_id, &claim.owner_token],
                )
                .await?
            {
                let generation: i64 = attempt.get(0);
                transaction
                    .execute(
                        "UPDATE lmyzmail_outbound_delivery_attempt
                         SET owner_token=NULL,phase='PROJECTED',updated_at=$3
                         WHERE task_id=$1 AND generation=$2 AND owner_token=$4",
                        &[&claim.task_id, &generation, &now, &claim.owner_token],
                    )
                    .await?;
            }
            transaction.commit().await?;
            Ok(updated == 1)
        })
        .await
    }

    pub async fn schedule_retry(
        &self,
        claim: &DatabaseClaim,
        next_retry_at: DateTime<Utc>,
        last_error: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<RetryTransition>, DeliveryStateError> {
        validate_claim(claim)?;
        let now = postgres_timestamp(now)?;
        let next_retry_at = postgres_timestamp(next_retry_at)?;
        if next_retry_at <= now {
            return Err(DeliveryStateError::InvalidInput(
                "retry deadline must be in the future",
            ));
        }
        let last_error = bounded_error(last_error);
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        let row = ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let row = transaction
                .query_opt(
                    "UPDATE outbound_mail_queue
                 SET status='PENDING', retry_count=retry_count+1, next_retry_at=$3,
                     last_error=$4, processor_id=NULL, processing_started_at=NULL, updated_at=$5
                 WHERE id=$1 AND status='PROCESSING' AND processor_id=$2
                   AND retry_count < max_retries
                   AND NOT EXISTS (
                       SELECT 1 FROM lmyzmail_outbound_delivery_attempt
                       WHERE task_id=$1
                   )
                 RETURNING retry_count,max_retries,next_retry_at",
                    &[
                        &claim.task_id,
                        &claim.owner_token,
                        &next_retry_at,
                        &last_error,
                        &now,
                    ],
                )
                .await?;
            transaction.commit().await?;
            Ok(row)
        })
        .await?;
        Ok(row.map(|row| RetryTransition {
            retry_count: row.get(0),
            max_retries: row.get(1),
            next_retry_at: row.get(2),
        }))
    }

    pub async fn mark_terminal(
        &self,
        claim: &DatabaseClaim,
        status: TerminalStatus,
        sent_domains: &[String],
        failed_domains: &BTreeMap<String, String>,
        last_error: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<bool, DeliveryStateError> {
        validate_claim(claim)?;
        validate_terminal(status, sent_domains, failed_domains, last_error)?;
        let now = postgres_timestamp(now)?;
        let sent_at = status.records_sent_at().then_some(now);
        let sent_domains_json = serialize_optional(sent_domains)?;
        let failed_domains_json = serialize_optional(failed_domains)?;
        let last_error = last_error.map(bounded_error);
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        let updated = ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let updated = transaction
                .execute(
                    "UPDATE outbound_mail_queue
                 SET status=$3, sent_at=$4, last_error=$5, sent_domains_json=$6,
                     failed_domains_json=$7, processor_id=NULL, processing_started_at=NULL,
                     updated_at=$8
                 WHERE id=$1 AND status='PROCESSING' AND processor_id=$2
                   AND NOT EXISTS (
                       SELECT 1 FROM lmyzmail_outbound_delivery_attempt
                       WHERE task_id=$1
                   )",
                    &[
                        &claim.task_id,
                        &claim.owner_token,
                        &status.database_value(),
                        &sent_at,
                        &last_error,
                        &sent_domains_json,
                        &failed_domains_json,
                        &now,
                    ],
                )
                .await?;
            transaction.commit().await?;
            Ok(updated)
        })
        .await?;
        Ok(updated == 1)
    }

    pub async fn recover_expired(
        &self,
        task_id: i64,
        heartbeat_before: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool, DeliveryStateError> {
        if task_id <= 0 {
            return Err(DeliveryStateError::InvalidInput("task ID must be positive"));
        }
        let heartbeat_before = postgres_timestamp(heartbeat_before)?;
        let now = postgres_timestamp(now)?;
        if heartbeat_before >= now {
            return Err(DeliveryStateError::InvalidInput(
                "heartbeat cutoff must precede recovery time",
            ));
        }
        let deadline = Instant::now() + self.operation_timeout;
        let mut client = self.client(deadline).await?;
        let cancel_token = client.cancel_token();
        ledger_mutation(deadline, cancel_token, async {
            let transaction = client.transaction().await?;
            configure_transaction_deadline(&transaction, deadline).await?;
            let legacy = transaction
                .query_opt(
                    "SELECT status,processor_id,processing_started_at,recipients_json
                     FROM outbound_mail_queue WHERE id=$1 FOR UPDATE",
                    &[&task_id],
                )
                .await?;
            let Some(legacy) = legacy else {
                transaction.commit().await?;
                return Ok(false);
            };
            let status: &str = legacy.get(0);
            let processor_id: Option<String> = legacy.get(1);
            let heartbeat: Option<DateTime<Utc>> = legacy.get(2);
            if status != "PROCESSING"
                || heartbeat.is_some_and(|heartbeat| heartbeat >= heartbeat_before)
            {
                transaction.commit().await?;
                return Ok(false);
            }
            let processor_id = processor_id.ok_or(DeliveryStateError::InvalidTransition(
                "processing delivery has no owner",
            ))?;
            let attempt = transaction
                .query_opt(
                    "SELECT generation,owner_token,phase,recipient_count,roster_sha256
                     FROM lmyzmail_outbound_delivery_attempt
                     WHERE task_id=$1 FOR UPDATE",
                    &[&task_id],
                )
                .await?;
            let Some(attempt) = attempt else {
                let recipients = parse_recipient_roster_json(legacy.get(3))?;
                let recipient_count = recipients.len() as i32;
                let roster_sha256 = roster_fingerprint(&recipients);
                transaction
                    .execute(
                        "INSERT INTO lmyzmail_outbound_delivery_attempt
                         (task_id,generation,owner_token,recipient_count,roster_sha256,
                          phase,created_at,updated_at)
                         VALUES ($1,1,NULL,$2,$3,'PROJECTED',$4,$4)",
                        &[&task_id, &recipient_count, &&roster_sha256[..], &now],
                    )
                    .await?;
                let ordinals: Vec<i32> =
                    (0..recipients.len()).map(|value| value as i32).collect();
                let states = vec!["AMBIGUOUS"; recipients.len()];
                let generations = vec![1_i64; recipients.len()];
                let details = vec![
                    "legacy processing outcome unknown at lmyzmail takeover";
                    recipients.len()
                ];
                transaction
                    .execute(
                        "INSERT INTO lmyzmail_outbound_delivery_recipient
                         (task_id,recipient_ordinal,recipient_address,state,
                          attempt_generation,smtp_code,detail,updated_at)
                         SELECT $1,ordinal,address,state,generation,NULL,detail,$3
                         FROM unnest($2::int4[],$4::text[],$5::text[],$6::int8[],$7::text[])
                              AS roster(ordinal,address,state,generation,detail)",
                        &[
                            &task_id,
                            &ordinals,
                            &now,
                            &recipients,
                            &states,
                            &generations,
                            &details,
                        ],
                    )
                    .await?;
                let updated = transaction
                    .execute(
                        "UPDATE outbound_mail_queue
                         SET status='FAILED',sent_at=NULL,
                             last_error='Ambiguous SMTP commit; automatic retry and DSN are forbidden',
                             sent_domains_json=NULL,failed_domains_json=NULL,
                             processor_id=NULL,processing_started_at=NULL,updated_at=$2
                         WHERE id=$1 AND status='PROCESSING' AND processor_id=$3",
                        &[&task_id, &now, &processor_id],
                    )
                    .await?;
                if updated != 1 {
                    return Err(DeliveryStateError::Fenced.into());
                }
                transaction.commit().await?;
                return Ok(true);
            };
            let generation: i64 = attempt.get(0);
            let ledger_owner: Option<&str> = attempt.get(1);
            let phase: &str = attempt.get(2);
            if ledger_owner != Some(processor_id.as_str()) || phase == "PROJECTED" {
                return Err(DeliveryStateError::Fenced.into());
            }
            let recipient_count: i32 = attempt.get(3);
            let roster_sha256: Vec<u8> = attempt.get(4);
            let fingerprint: [u8; 32] = roster_sha256.try_into().map_err(|_| {
                DeliveryStateError::InvalidTransition(
                    "delivery recipient roster fingerprint is invalid",
                )
            })?;
            if recipient_count <= 0
                || !verify_roster(
                    &transaction,
                    task_id,
                    recipient_count as usize,
                    &fingerprint,
                )
                .await?
            {
                return Err(DeliveryStateError::InvalidTransition(
                    "delivery recipient roster failed integrity verification",
                )
                .into());
            }
            verify_commit_barrier_consistency(&transaction, task_id, phase).await?;
            if phase == "COMMIT_ARMED" {
                transaction
                    .execute(
                        "UPDATE lmyzmail_outbound_delivery_recipient
                         SET state='AMBIGUOUS',attempt_generation=$2,smtp_code=NULL,
                             detail='process lost after SMTP commit was armed',updated_at=$3
                         WHERE task_id=$1 AND state='COMMIT_ARMED'",
                        &[&task_id, &generation, &now],
                    )
                    .await?;
            }
            let rows = transaction
                .query(
                    "SELECT recipient_ordinal,recipient_address,state,detail
                     FROM lmyzmail_outbound_delivery_recipient
                     WHERE task_id=$1 ORDER BY recipient_ordinal FOR UPDATE",
                    &[&task_id],
                )
                .await?;
            let recipients = ledger_rows_for_projection(&rows)?;
            let ambiguous = recipients
                .iter()
                .any(|recipient| recipient.state == RecipientDeliveryState::Ambiguous);
            let active = recipients.iter().any(|recipient| {
                matches!(
                    recipient.state,
                    RecipientDeliveryState::Pending | RecipientDeliveryState::Retryable
                )
            });
            if ambiguous || !active {
                let (sent_domains, failed_domains) = projection_domains(&recipients)?;
                let delivered = recipients
                    .iter()
                    .filter(|recipient| recipient.state == RecipientDeliveryState::Delivered)
                    .count();
                let permanent = recipients
                    .iter()
                    .filter(|recipient| recipient.state == RecipientDeliveryState::Permanent)
                    .count();
                let terminal = if ambiguous || delivered == 0 {
                    TerminalStatus::Failed
                } else if permanent == 0 {
                    TerminalStatus::Sent
                } else {
                    TerminalStatus::PartialSuccess
                };
                let sent_at = terminal.records_sent_at().then_some(now);
                let last_error = if ambiguous {
                    Some("Ambiguous SMTP commit; automatic retry and DSN are forbidden".to_owned())
                } else if terminal == TerminalStatus::Sent {
                    None
                } else {
                    Some(projection_error(&recipients, "permanent delivery failure")?)
                };
                let sent_domains_json = serialize_optional(&sent_domains)?;
                let failed_domains_json = if ambiguous {
                    None
                } else {
                    serialize_optional(&failed_domains)?
                };
                transaction
                    .execute(
                        "UPDATE outbound_mail_queue
                         SET status=$3,sent_at=$4,last_error=$5,sent_domains_json=$6,
                             failed_domains_json=$7,processor_id=NULL,
                             processing_started_at=NULL,updated_at=$8
                         WHERE id=$1 AND status='PROCESSING' AND processor_id=$2",
                        &[
                            &task_id,
                            &processor_id,
                            &terminal.database_value(),
                            &sent_at,
                            &last_error,
                            &sent_domains_json,
                            &failed_domains_json,
                            &now,
                        ],
                    )
                    .await?;
            } else {
                transaction
                    .execute(
                        "UPDATE outbound_mail_queue
                         SET status='PENDING',processor_id=NULL,processing_started_at=NULL,
                             next_retry_at=LEAST(next_retry_at,$3),updated_at=$3
                         WHERE id=$1 AND status='PROCESSING' AND processor_id=$2",
                        &[&task_id, &processor_id, &now],
                    )
                    .await?;
            }
            transaction
                .execute(
                    "UPDATE lmyzmail_outbound_delivery_attempt
                     SET owner_token=NULL,phase='PROJECTED',updated_at=$3
                     WHERE task_id=$1 AND generation=$2 AND owner_token=$4",
                    &[&task_id, &generation, &now, &processor_id],
                )
                .await?;
            transaction.commit().await?;
            Ok(true)
        })
        .await
    }

    pub async fn snapshot(
        &self,
        task_id: i64,
        claim: Option<&DatabaseClaim>,
    ) -> Result<Option<DeliverySnapshot>, DeliveryStateError> {
        if task_id <= 0 {
            return Err(DeliveryStateError::InvalidInput("task ID must be positive"));
        }
        if let Some(claim) = claim {
            validate_claim(claim)?;
            if claim.task_id != task_id {
                return Err(DeliveryStateError::InvalidInput(
                    "delivery claim does not match task ID",
                ));
            }
        }
        self.snapshot_with_owner(task_id, claim.map(|claim| claim.owner_token.as_str()))
            .await
    }

    pub async fn snapshot_attempt(
        &self,
        attempt: &DeliveryAttemptId,
    ) -> Result<Option<DeliverySnapshot>, DeliveryStateError> {
        validate_attempt(attempt)?;
        self.snapshot_with_owner(attempt.task_id, Some(&attempt.owner_token))
            .await
    }

    async fn snapshot_with_owner(
        &self,
        task_id: i64,
        expected_owner: Option<&str>,
    ) -> Result<Option<DeliverySnapshot>, DeliveryStateError> {
        let deadline = Instant::now() + self.operation_timeout;
        let client = self.client(deadline).await?;
        let row = read_deadline(
            deadline,
            client.query_opt(
                "SELECT status,retry_count,max_retries,next_retry_at,last_error,sent_at,
                        processing_started_at,processor_id,sent_file_name
                 FROM outbound_mail_queue WHERE id=$1",
                &[&task_id],
            ),
        )
        .await?;
        row.map(|row| {
            let owner: Option<String> = row.get(7);
            Ok(DeliverySnapshot {
                task_id,
                status: DeliveryRowStatus::from_database(row.get(0))?,
                retry_count: row.get(1),
                max_retries: row.get(2),
                next_retry_at: row.get(3),
                last_error: row.get(4),
                sent_at: row.get(5),
                processing_started_at: row.get(6),
                sent_file_name: row.get(8),
                has_owner: owner.is_some(),
                owned_by_claim: expected_owner.is_some_and(|value| owner.as_deref() == Some(value)),
            })
        })
        .transpose()
    }

    async fn client(&self, deadline: Instant) -> Result<Object, DeliveryStateError> {
        timeout_at(deadline, self.pool.get())
            .await
            .map_err(|_| DeliveryStateError::Unavailable)?
            .map_err(|_| DeliveryStateError::Unavailable)
    }
}

async fn read_deadline<T, F>(deadline: Instant, future: F) -> Result<T, DeliveryStateError>
where
    F: Future<Output = Result<T, tokio_postgres::Error>>,
{
    timeout_at(deadline, future)
        .await
        .map_err(|_| DeliveryStateError::Unavailable)?
        .map_err(|_| DeliveryStateError::Unavailable)
}

#[derive(Debug)]
enum LedgerMutationError {
    State(DeliveryStateError),
    Database,
}

impl From<DeliveryStateError> for LedgerMutationError {
    fn from(value: DeliveryStateError) -> Self {
        Self::State(value)
    }
}

impl From<tokio_postgres::Error> for LedgerMutationError {
    fn from(_: tokio_postgres::Error) -> Self {
        Self::Database
    }
}

async fn ledger_mutation<T, F>(
    deadline: Instant,
    cancel_token: CancelToken,
    future: F,
) -> Result<T, DeliveryStateError>
where
    F: Future<Output = Result<T, LedgerMutationError>>,
{
    tokio::pin!(future);
    match timeout_at(deadline, future.as_mut()).await {
        Err(_) => {
            let _cancel_sent = cancel_timed_out_query(&cancel_token).await;
            Err(DeliveryStateError::OutcomeUnknown)
        }
        Ok(Err(LedgerMutationError::Database)) => Err(DeliveryStateError::OutcomeUnknown),
        Ok(Err(LedgerMutationError::State(error))) => Err(error),
        Ok(Ok(value)) => Ok(value),
    }
}

async fn cancel_timed_out_query(cancel_token: &CancelToken) -> bool {
    let cancel_deadline = Instant::now() + DATABASE_CANCEL_TIMEOUT;
    matches!(
        timeout_at(cancel_deadline, cancel_token.cancel_query(NoTls)).await,
        Ok(Ok(()))
    )
}

async fn configure_transaction_deadline(
    transaction: &deadpool_postgres::Transaction<'_>,
    deadline: Instant,
) -> Result<(), tokio_postgres::Error> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let server_millis = (remaining.as_millis() / 2).clamp(1, i32::MAX as u128);
    let value = format!("{server_millis}ms");
    transaction
        .query_one("SELECT set_config('statement_timeout',$1,true)", &[&value])
        .await?;
    Ok(())
}

trait ClaimFence {
    fn task_id(&self) -> i64;
    fn owner_token(&self) -> &str;
    fn expected_retry_state(&self) -> Option<(i32, i32)> {
        None
    }
}

impl ClaimFence for DatabaseClaim {
    fn task_id(&self) -> i64 {
        self.task_id
    }

    fn owner_token(&self) -> &str {
        &self.owner_token
    }

    fn expected_retry_state(&self) -> Option<(i32, i32)> {
        Some((self.retry_count, self.max_retries))
    }
}

impl ClaimFence for RecipientLedgerClaim {
    fn task_id(&self) -> i64 {
        self.task_id
    }

    fn owner_token(&self) -> &str {
        &self.owner_token
    }
}

async fn advance_legacy_sequence(
    transaction: &tokio_postgres::Transaction<'_>,
    task_id: i64,
) -> Result<(), tokio_postgres::Error> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock($1)",
            &[&OUTBOUND_ID_ALLOCATION_LOCK],
        )
        .await?;
    transaction
        .query_one(
            "WITH sequence_name AS (
                 SELECT pg_get_serial_sequence('outbound_mail_queue','id') AS value
             )
             SELECT setval(
                 value,
                 GREATEST(
                     $1,
                     (SELECT COALESCE(max(id),0) FROM outbound_mail_queue),
                     (SELECT COALESCE(max(dsn_task_id),0) FROM lmyzmail_outbound_dsn),
                     nextval(value::regclass)
                 ),
                 true
             )
             FROM sequence_name WHERE value IS NOT NULL",
            &[&task_id],
        )
        .await?;
    Ok(())
}

async fn lock_legacy_claim<C: ClaimFence>(
    transaction: &deadpool_postgres::Transaction<'_>,
    claim: &C,
) -> Result<(i32, i32), LedgerMutationError> {
    let row = transaction
        .query_opt(
            "SELECT retry_count,max_retries
             FROM outbound_mail_queue
             WHERE id=$1 AND status='PROCESSING' AND processor_id=$2
             FOR UPDATE",
            &[&claim.task_id(), &claim.owner_token()],
        )
        .await?
        .ok_or(DeliveryStateError::Fenced)?;
    let retry_count: i32 = row.get(0);
    let max_retries: i32 = row.get(1);
    if retry_count < 0 || max_retries < 0 || retry_count > max_retries {
        return Err(DeliveryStateError::InvalidTransition(
            "invalid legacy retry state reached the delivery ledger",
        )
        .into());
    }
    if claim
        .expected_retry_state()
        .is_some_and(|expected| expected != (retry_count, max_retries))
    {
        return Err(DeliveryStateError::Fenced.into());
    }
    Ok((retry_count, max_retries))
}

async fn lock_ledger_attempt(
    transaction: &deadpool_postgres::Transaction<'_>,
    claim: &RecipientLedgerClaim,
) -> Result<(i64, String), LedgerMutationError> {
    let row = transaction
        .query_opt(
            "SELECT generation,phase,recipient_count,roster_sha256
             FROM lmyzmail_outbound_delivery_attempt
             WHERE task_id=$1 AND owner_token=$2 AND generation=$3 FOR UPDATE",
            &[&claim.task_id, &claim.owner_token, &claim.generation],
        )
        .await?
        .ok_or(DeliveryStateError::Fenced)?;
    let recipient_count: i32 = row.get(2);
    let roster_sha256: Vec<u8> = row.get(3);
    if recipient_count != claim.recipient_count as i32
        || roster_sha256 != claim.roster_sha256
        || !verify_roster(
            transaction,
            claim.task_id,
            claim.recipient_count,
            &claim.roster_sha256,
        )
        .await?
    {
        return Err(DeliveryStateError::InvalidTransition(
            "delivery recipient roster failed integrity verification",
        )
        .into());
    }
    let phase: String = row.get(1);
    verify_commit_barrier_consistency(transaction, claim.task_id, &phase).await?;
    Ok((row.get(0), phase))
}

async fn verify_roster(
    transaction: &deadpool_postgres::Transaction<'_>,
    task_id: i64,
    expected_count: usize,
    expected_fingerprint: &[u8; 32],
) -> Result<bool, LedgerMutationError> {
    let rows = transaction
        .query(
            "SELECT recipient_ordinal,recipient_address
             FROM lmyzmail_outbound_delivery_recipient
             WHERE task_id=$1 ORDER BY recipient_ordinal FOR SHARE",
            &[&task_id],
        )
        .await?;
    if rows.len() != expected_count {
        return Ok(false);
    }
    let mut recipients = Vec::with_capacity(rows.len());
    for (ordinal, row) in rows.iter().enumerate() {
        if row.get::<_, i32>(0) != ordinal as i32 {
            return Ok(false);
        }
        recipients.push(row.get::<_, String>(1));
    }
    Ok(roster_fingerprint(&recipients) == *expected_fingerprint)
}

async fn verify_commit_barrier_consistency(
    transaction: &deadpool_postgres::Transaction<'_>,
    task_id: i64,
    phase: &str,
) -> Result<(), LedgerMutationError> {
    let has_armed: bool = transaction
        .query_one(
            "SELECT EXISTS(
                 SELECT 1 FROM lmyzmail_outbound_delivery_recipient
                 WHERE task_id=$1 AND state='COMMIT_ARMED'
             )",
            &[&task_id],
        )
        .await?
        .get(0);
    validate_commit_barrier_consistency(phase, has_armed)?;
    Ok(())
}

async fn project_attempt_row(
    transaction: &deadpool_postgres::Transaction<'_>,
    claim: &RecipientLedgerClaim,
    now: DateTime<Utc>,
) -> Result<(), LedgerMutationError> {
    let updated = transaction
        .execute(
            "UPDATE lmyzmail_outbound_delivery_attempt
             SET owner_token=NULL,phase='PROJECTED',updated_at=$4
             WHERE task_id=$1 AND owner_token=$2 AND generation=$3
               AND phase='PREPARING'",
            &[&claim.task_id, &claim.owner_token, &claim.generation, &now],
        )
        .await?;
    if updated != 1 {
        return Err(DeliveryStateError::Fenced.into());
    }
    Ok(())
}

#[derive(Clone)]
struct ProjectionRecipient {
    recipient: String,
    state: RecipientDeliveryState,
    detail: Option<String>,
}

fn ledger_rows_for_projection(
    rows: &[tokio_postgres::Row],
) -> Result<Vec<ProjectionRecipient>, DeliveryStateError> {
    rows.iter()
        .map(|row| {
            Ok(ProjectionRecipient {
                recipient: row.get(1),
                state: RecipientDeliveryState::from_database(row.get(2))?,
                detail: row.get(3),
            })
        })
        .collect()
}

fn projection_error(
    recipients: &[ProjectionRecipient],
    fallback: &str,
) -> Result<String, DeliveryStateError> {
    let delivered = recipients
        .iter()
        .any(|recipient| recipient.state == RecipientDeliveryState::Delivered);
    let mut failed = BTreeMap::new();
    for recipient in recipients.iter().filter(|recipient| {
        matches!(
            recipient.state,
            RecipientDeliveryState::Retryable | RecipientDeliveryState::Permanent
        )
    }) {
        let domain = recipient_domain(&recipient.recipient)?;
        failed.entry(domain).or_insert_with(|| {
            recipient
                .detail
                .clone()
                .unwrap_or_else(|| fallback.to_owned())
        });
    }
    if failed.is_empty() {
        return Ok(bounded_error(fallback));
    }
    let failures = failed
        .into_iter()
        .map(|(domain, detail)| format!("{domain}={detail}"))
        .collect::<Vec<_>>()
        .join(", ");
    let prefix = if delivered {
        "Partial delivery. Failed domains: "
    } else {
        "All domains failed: "
    };
    Ok(bounded_error(&format!("{prefix}{{{failures}}}")))
}

fn projection_domains(
    recipients: &[ProjectionRecipient],
) -> Result<(Vec<String>, BTreeMap<String, String>), DeliveryStateError> {
    let mut sent = BTreeSet::new();
    let mut failed = BTreeMap::new();
    for recipient in recipients {
        let domain = recipient_domain(&recipient.recipient)?;
        match recipient.state {
            RecipientDeliveryState::Delivered => {
                if !failed.contains_key(&domain) {
                    sent.insert(domain);
                }
            }
            RecipientDeliveryState::Permanent => {
                sent.remove(&domain);
                failed.entry(domain).or_insert_with(|| {
                    bounded_bytes(
                        recipient
                            .detail
                            .as_deref()
                            .unwrap_or("permanent delivery failure"),
                        MAX_DOMAIN_ERROR_BYTES,
                    )
                });
            }
            RecipientDeliveryState::Ambiguous => {
                sent.remove(&domain);
            }
            _ => {}
        }
    }
    Ok((sent.into_iter().collect(), failed))
}

fn validate_worker_identity(task_id: i64, worker_id: &str) -> Result<(), DeliveryStateError> {
    if task_id <= 0 {
        return Err(DeliveryStateError::InvalidInput("task ID must be positive"));
    }
    validate_worker_label(worker_id)
}

fn validate_worker_label(worker_id: &str) -> Result<(), DeliveryStateError> {
    if worker_id.len() > MAX_WORKER_ID_BYTES {
        return Err(DeliveryStateError::InvalidInput(
            "invalid delivery worker ID",
        ));
    }
    validate_identity(1, worker_id)
}

fn unique_owner_token(worker_id: &str) -> Result<String, DeliveryStateError> {
    let mut random = [0_u8; 16];
    fill_random(&mut random).map_err(|_| DeliveryStateError::Unavailable)?;
    let mut token = String::with_capacity(worker_id.len() + 1 + random.len() * 2);
    token.push_str(worker_id);
    token.push(':');
    for byte in random {
        use std::fmt::Write;
        write!(&mut token, "{byte:02x}").map_err(|_| DeliveryStateError::Unavailable)?;
    }
    Ok(token)
}

fn validate_identity(task_id: i64, owner_token: &str) -> Result<(), DeliveryStateError> {
    if task_id <= 0 {
        return Err(DeliveryStateError::InvalidInput("task ID must be positive"));
    }
    if owner_token.is_empty()
        || owner_token.len() > MAX_OWNER_TOKEN_BYTES
        || !owner_token.is_ascii()
        || owner_token
            .bytes()
            .any(|value| value.is_ascii_control() || value.is_ascii_whitespace())
    {
        return Err(DeliveryStateError::InvalidInput(
            "invalid delivery owner token",
        ));
    }
    Ok(())
}

fn validate_claim(claim: &DatabaseClaim) -> Result<(), DeliveryStateError> {
    validate_identity(claim.task_id, &claim.owner_token)?;
    if claim.retry_count < 0 || claim.max_retries < 0 || claim.retry_count > claim.max_retries {
        return Err(DeliveryStateError::InvalidInput(
            "invalid delivery retry state",
        ));
    }
    Ok(())
}

fn validate_legacy_redis_materialization(
    task: &LegacyRedisTaskMaterialization,
) -> Result<(), DeliveryStateError> {
    if task.task_id <= 0
        || task.sender_address.is_empty()
        || task.sender_address.chars().count() > 255
        || task.sender_address.chars().any(char::is_control)
        || task.subject.chars().count() > 1_000
        || task.message_id.is_empty()
        || task.message_id.chars().count() > 255
        || task.message_id.chars().any(char::is_control)
        || task.sent_file_name.is_empty()
        || task.sent_file_name.chars().count() > 255
        || task.sent_file_name.chars().any(char::is_control)
        || task.sent_subdirectory <= 0
        || task.retry_count < 0
        || task.max_retries < 0
        || task.retry_count > task.max_retries
        || task.mail_size_bytes <= 0
        || task.to_addresses_json.chars().count() > 2_000
    {
        return Err(DeliveryStateError::InvalidInput(
            "invalid legacy Redis task materialization",
        ));
    }
    parse_recipient_roster_json(&task.recipients_json)?;
    postgres_timestamp(task.created_at)?;
    postgres_timestamp(task.next_retry_at)?;
    let mut domains = BTreeSet::new();
    for domain in &task.sent_domains {
        validate_domain(domain)?;
        if !domains.insert(domain.as_str()) {
            return Err(DeliveryStateError::InvalidInput(
                "duplicate legacy Redis domain state",
            ));
        }
    }
    for (domain, error) in &task.failed_domains {
        validate_domain(domain)?;
        if !domains.insert(domain.as_str())
            || error.is_empty()
            || error.len() > MAX_DOMAIN_ERROR_BYTES
        {
            return Err(DeliveryStateError::InvalidInput(
                "invalid legacy Redis domain state",
            ));
        }
    }
    Ok(())
}

fn validate_legacy_archive(
    archive: &LegacyArchiveMaterialization,
) -> Result<(), DeliveryStateError> {
    if archive.task_id <= 0
        || archive.sender_address.is_empty()
        || archive.sender_address.chars().count() > 255
        || archive.sender_address.chars().any(char::is_control)
        || archive
            .subject
            .as_deref()
            .is_some_and(|value| value.chars().count() > 1_000 || value.contains('\0'))
        || archive.message_id.as_deref().is_none_or(|value| {
            value.is_empty() || value.chars().count() > 255 || value.chars().any(char::is_control)
        })
        || archive.sent_file_name.as_deref().is_none_or(|value| {
            value.is_empty() || value.chars().count() > 255 || value.chars().any(char::is_control)
        })
        || archive.sent_subdirectory.is_none_or(|value| value <= 0)
        || archive.retry_count < 0
        || archive.max_retries < 0
        || archive.retry_count > archive.max_retries
        || !archive.status.is_terminal()
        || archive
            .last_error
            .as_deref()
            .is_some_and(|value| value.encode_utf16().count() > MAX_LAST_ERROR_UTF16_UNITS)
        || archive.updated_at < archive.created_at
    {
        return Err(DeliveryStateError::InvalidInput(
            "invalid legacy archive materialization",
        ));
    }
    validate_terminal_timestamp(archive.status, archive.sent_at)?;
    validate_legacy_json(archive.sent_domains_json.as_deref())?;
    validate_legacy_json(archive.failed_domains_json.as_deref())?;
    parse_recipient_roster_json(&archive.recipients_json)?;
    postgres_timestamp(archive.created_at)?;
    postgres_timestamp(archive.updated_at)?;
    postgres_timestamp(archive.next_retry_at)?;
    archive.sent_at.map(postgres_timestamp).transpose()?;
    Ok(())
}

fn validate_legacy_status(update: &LegacyStatusMaterialization) -> Result<(), DeliveryStateError> {
    if update.task_id <= 0
        || matches!(update.status, DeliveryRowStatus::Processing)
        || update.retry_count < 0
        || update
            .last_error
            .as_deref()
            .is_some_and(|value| value.encode_utf16().count() > MAX_LAST_ERROR_UTF16_UNITS)
    {
        return Err(DeliveryStateError::InvalidInput(
            "invalid legacy status materialization",
        ));
    }
    validate_terminal_timestamp(update.status, update.sent_at)?;
    validate_legacy_json(update.sent_domains_json.as_deref())?;
    validate_legacy_json(update.failed_domains_json.as_deref())?;
    postgres_timestamp(update.updated_at)?;
    update.sent_at.map(postgres_timestamp).transpose()?;
    Ok(())
}

fn validate_terminal_timestamp(
    status: DeliveryRowStatus,
    sent_at: Option<DateTime<Utc>>,
) -> Result<(), DeliveryStateError> {
    let records_sent = matches!(
        status,
        DeliveryRowStatus::Sent | DeliveryRowStatus::PartialSuccess
    );
    if records_sent != sent_at.is_some() {
        return Err(DeliveryStateError::InvalidInput(
            "legacy delivery sent timestamp is inconsistent",
        ));
    }
    Ok(())
}

fn validate_legacy_json(value: Option<&str>) -> Result<(), DeliveryStateError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.len() > MAX_DOMAIN_ARCHIVE_BYTES
        || serde_json::from_str::<serde_json::Value>(value).is_err()
    {
        return Err(DeliveryStateError::InvalidInput(
            "legacy delivery domain archive is invalid",
        ));
    }
    Ok(())
}

fn validate_outbound_spool_identity(
    task_id: i64,
    spool_path: &str,
) -> Result<(), DeliveryStateError> {
    if task_id <= 0
        || spool_path.is_empty()
        || spool_path.len() > 4_096
        || spool_path.contains('\0')
        || !std::path::Path::new(spool_path).is_absolute()
    {
        return Err(DeliveryStateError::InvalidInput(
            "invalid outbound spool ownership",
        ));
    }
    Ok(())
}

fn validate_ledger_claim(claim: &RecipientLedgerClaim) -> Result<(), DeliveryStateError> {
    validate_identity(claim.task_id, &claim.owner_token)?;
    if claim.generation <= 0 || claim.recipient_count == 0 || claim.recipient_count > MAX_RECIPIENTS
    {
        return Err(DeliveryStateError::InvalidInput(
            "invalid delivery ledger generation",
        ));
    }
    Ok(())
}

fn validate_attempt(attempt: &DeliveryAttemptId) -> Result<(), DeliveryStateError> {
    validate_identity(attempt.task_id, &attempt.owner_token)
}

fn validate_commit_barrier_consistency(
    phase: &str,
    has_armed_recipient: bool,
) -> Result<(), DeliveryStateError> {
    if (phase == "COMMIT_ARMED") != has_armed_recipient {
        return Err(DeliveryStateError::InvalidTransition(
            "delivery commit barrier state is inconsistent",
        ));
    }
    Ok(())
}

pub fn parse_recipient_roster_json(value: &str) -> Result<Vec<String>, DeliveryStateError> {
    let parsed: LegacyRecipientJson = serde_json::from_str(value).map_err(|_| {
        DeliveryStateError::InvalidTransition("legacy delivery recipient roster is invalid")
    })?;
    let recipients = match parsed {
        LegacyRecipientJson::Flat(recipients) => recipients,
        LegacyRecipientJson::Structured { to, cc, bcc } => to
            .into_iter()
            .flatten()
            .chain(cc.into_iter().flatten())
            .chain(bcc.into_iter().flatten())
            .collect(),
    };
    validate_recipient_roster(&recipients).map_err(|_| {
        DeliveryStateError::InvalidTransition("legacy delivery recipient roster is invalid")
    })?;
    Ok(recipients)
}

fn validate_recipient_roster(recipients: &[String]) -> Result<(), DeliveryStateError> {
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(DeliveryStateError::InvalidInput(
            "invalid delivery recipient count",
        ));
    }
    let mut seen = BTreeSet::new();
    for recipient in recipients {
        recipient_domain(recipient)?;
        if !seen.insert(recipient.as_str()) {
            return Err(DeliveryStateError::InvalidInput(
                "duplicate delivery recipient",
            ));
        }
    }
    Ok(())
}

fn roster_fingerprint(recipients: &[String]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update((recipients.len() as u32).to_be_bytes());
    for (ordinal, recipient) in recipients.iter().enumerate() {
        digest.update((ordinal as u32).to_be_bytes());
        digest.update((recipient.len() as u32).to_be_bytes());
        digest.update(recipient.as_bytes());
    }
    digest.finalize().into()
}

fn validate_prepared_outcomes(
    outcomes: &[PreparedRecipientCheckpoint],
) -> Result<(), DeliveryStateError> {
    if outcomes.is_empty() || outcomes.len() > MAX_RECIPIENTS {
        return Err(DeliveryStateError::InvalidInput(
            "invalid prepared recipient count",
        ));
    }
    let mut ordinals = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for outcome in outcomes {
        recipient_domain(&outcome.recipient)?;
        if !ordinals.insert(outcome.ordinal) || !identities.insert(outcome.recipient.as_str()) {
            return Err(DeliveryStateError::InvalidInput(
                "duplicate prepared recipient outcome",
            ));
        }
        let valid_code = match outcome.status {
            PreparedRecipientStatus::Accepted => (250..=252).contains(&outcome.smtp_code),
            PreparedRecipientStatus::Retryable => (400..=499).contains(&outcome.smtp_code),
            PreparedRecipientStatus::Permanent => (500..=599).contains(&outcome.smtp_code),
        };
        if !valid_code
            || outcome.detail.is_empty()
            || outcome.detail.len() > MAX_RECIPIENT_DETAIL_BYTES
        {
            return Err(DeliveryStateError::InvalidInput(
                "invalid prepared recipient outcome",
            ));
        }
    }
    Ok(())
}

fn validate_commit_result(
    status: CommitResultStatus,
    smtp_code: u16,
    detail: &str,
) -> Result<(), DeliveryStateError> {
    let valid_code = match status {
        CommitResultStatus::Delivered => (200..=299).contains(&smtp_code),
        CommitResultStatus::Retryable => (400..=499).contains(&smtp_code),
        CommitResultStatus::Permanent => (500..=599).contains(&smtp_code),
    };
    if !valid_code || detail.is_empty() || detail.len() > MAX_RECIPIENT_DETAIL_BYTES {
        return Err(DeliveryStateError::InvalidInput(
            "invalid SMTP commit result",
        ));
    }
    Ok(())
}

pub(crate) fn recipient_domain(recipient: &str) -> Result<String, DeliveryStateError> {
    if recipient.is_empty()
        || recipient.len() > MAX_RECIPIENT_ADDRESS_BYTES
        || recipient.chars().any(char::is_control)
    {
        return Err(DeliveryStateError::InvalidInput(
            "invalid delivery recipient identity",
        ));
    }
    let (local, domain) = recipient
        .rsplit_once('@')
        .ok_or(DeliveryStateError::InvalidInput(
            "invalid delivery recipient identity",
        ))?;
    if local.is_empty() || local.contains('@') {
        return Err(DeliveryStateError::InvalidInput(
            "invalid delivery recipient identity",
        ));
    }
    let canonical = domain_to_ascii_strict(domain)
        .map_err(|_| DeliveryStateError::InvalidInput("invalid delivery recipient identity"))?
        .to_ascii_lowercase();
    validate_domain(&canonical)?;
    Ok(canonical)
}

fn validate_terminal(
    status: TerminalStatus,
    sent_domains: &[String],
    failed_domains: &BTreeMap<String, String>,
    last_error: Option<&str>,
) -> Result<(), DeliveryStateError> {
    if sent_domains.len() + failed_domains.len() > MAX_DOMAINS
        || (status == TerminalStatus::Sent
            && (sent_domains.is_empty() || !failed_domains.is_empty()))
        || (status == TerminalStatus::PartialSuccess
            && (sent_domains.is_empty() || failed_domains.is_empty()))
        || (status == TerminalStatus::Failed
            && failed_domains.is_empty()
            && (!sent_domains.is_empty() || last_error.is_none_or(str::is_empty)))
    {
        return Err(DeliveryStateError::InvalidInput(
            "invalid terminal domain outcome",
        ));
    }
    let mut seen = BTreeSet::new();
    for domain in sent_domains {
        validate_domain(domain)?;
        if !seen.insert(domain.as_str()) {
            return Err(DeliveryStateError::InvalidInput(
                "duplicate terminal domain outcome",
            ));
        }
    }
    for (domain, error) in failed_domains {
        validate_domain(domain)?;
        if !seen.insert(domain.as_str()) || error.is_empty() || error.len() > MAX_DOMAIN_ERROR_BYTES
        {
            return Err(DeliveryStateError::InvalidInput(
                "invalid failed-domain outcome",
            ));
        }
    }
    Ok(())
}

fn validate_domain(domain: &str) -> Result<(), DeliveryStateError> {
    let canonical = domain_to_ascii_strict(domain)
        .ok()
        .map(|value| value.to_ascii_lowercase());
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_BYTES
        || domain.chars().any(char::is_whitespace)
        || canonical.as_deref() != Some(domain)
    {
        return Err(DeliveryStateError::InvalidInput("invalid delivery domain"));
    }
    Ok(())
}

fn serialize_optional<T>(value: &T) -> Result<Option<String>, DeliveryStateError>
where
    T: serde::Serialize + ?Sized,
{
    let json = serde_json::to_string(value).map_err(|_| DeliveryStateError::Unavailable)?;
    if json.len() > MAX_DOMAIN_ARCHIVE_BYTES {
        return Err(DeliveryStateError::InvalidInput(
            "terminal domain archive exceeds its byte budget",
        ));
    }
    if json == "[]" || json == "{}" {
        Ok(None)
    } else {
        Ok(Some(json))
    }
}

fn bounded_error(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_LAST_ERROR_UTF16_UNITS) + 3);
    let mut utf16_units = 0;
    for character in value.chars() {
        let character_units = character.len_utf16();
        if utf16_units + character_units > MAX_LAST_ERROR_UTF16_UNITS {
            output.push_str("...");
            return output;
        }
        output.push(character);
        utf16_units += character_units;
    }
    output
}

fn bounded_bytes(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let keep = maximum.saturating_sub(3);
    let mut boundary = keep.min(value.len());
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}...", &value[..boundary])
}

fn postgres_timestamp(value: DateTime<Utc>) -> Result<DateTime<Utc>, DeliveryStateError> {
    if value.timestamp() <= 0 {
        return Err(DeliveryStateError::InvalidInput(
            "delivery timestamp must be after the Unix epoch",
        ));
    }
    value
        .with_nanosecond((value.timestamp_subsec_nanos() / 1_000) * 1_000)
        .ok_or(DeliveryStateError::InvalidInput(
            "invalid delivery timestamp",
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_tokens_and_retry_timestamps_are_bounded() {
        assert!(validate_identity(1, "worker-a:opaque-token").is_ok());
        assert!(validate_identity(0, "worker-a").is_err());
        assert!(validate_identity(1, "worker a").is_err());
        assert!(validate_identity(1, &"x".repeat(101)).is_err());

        let token = DeliveryAttemptId::generate_lease_token("worker-a").unwrap();
        assert!(token.starts_with("worker-a:"));
        assert_eq!(token.len(), "worker-a:".len() + 32);
        let bound = DeliveryAttemptId::from_lease_token(41, &token).unwrap();
        assert_eq!(bound.task_id(), 41);
        assert_eq!(bound.lease_token(), token);
        assert!(!format!("{bound:?}").contains(&token));
        assert_ne!(
            DeliveryAttemptId::generate_lease_token("worker-a").unwrap(),
            token
        );
        assert!(DeliveryAttemptId::from_lease_token(0, &token).is_err());
        assert!(DeliveryAttemptId::generate_lease_token("worker a").is_err());
    }

    #[test]
    fn legacy_recipient_formats_and_commit_barrier_consistency_are_strict() {
        assert_eq!(
            parse_recipient_roster_json(r#"["one@example.test","two@example.test"]"#).unwrap(),
            ["one@example.test", "two@example.test"]
        );
        assert_eq!(
            parse_recipient_roster_json(
                r#"{"to":["to@example.test"],"cc":null,"bcc":["bcc@example.test"]}"#
            )
            .unwrap(),
            ["to@example.test", "bcc@example.test"]
        );
        assert!(parse_recipient_roster_json(r#"{"to":[],"cc":[],"bcc":[]}"#).is_err());
        assert!(
            parse_recipient_roster_json(r#"["duplicate@example.test","duplicate@example.test"]"#)
                .is_err()
        );
        assert!(validate_commit_barrier_consistency("PREPARING", false).is_ok());
        assert!(validate_commit_barrier_consistency("COMMIT_ARMED", true).is_ok());
        assert!(validate_commit_barrier_consistency("PROJECTED", false).is_ok());
        assert!(validate_commit_barrier_consistency("PREPARING", true).is_err());
        assert!(validate_commit_barrier_consistency("COMMIT_ARMED", false).is_err());
    }

    #[test]
    fn errors_follow_java_utf16_truncation_without_invalid_utf8() {
        assert_eq!(bounded_error(&"a".repeat(1_000)), "a".repeat(1_000));
        assert_eq!(
            bounded_error(&"a".repeat(1_001)),
            format!("{}...", "a".repeat(1_000))
        );
        assert_eq!(bounded_error(&"😀".repeat(500)), "😀".repeat(500));
        assert_eq!(
            bounded_error(&"😀".repeat(501)),
            format!("{}...", "😀".repeat(500))
        );
        assert_eq!(
            bounded_error(&format!("{}😀", "a".repeat(999))),
            format!("{}...", "a".repeat(999))
        );
        assert_eq!(bounded_error("remote\nreply"), "remote\nreply");
    }

    #[test]
    fn terminal_domains_are_unique_and_status_consistent() {
        let failed = BTreeMap::from([("failed.example".into(), "550 rejected".into())]);
        assert!(validate_terminal(TerminalStatus::Failed, &[], &failed, None).is_ok());
        assert!(
            validate_terminal(
                TerminalStatus::PartialSuccess,
                &["sent.example".into()],
                &failed,
                None,
            )
            .is_ok()
        );
        assert!(validate_terminal(TerminalStatus::Sent, &[], &failed, None).is_err());
        assert!(
            validate_terminal(
                TerminalStatus::Failed,
                &["sent.example".into()],
                &failed,
                None,
            )
            .is_ok()
        );
        assert!(
            validate_terminal(
                TerminalStatus::Failed,
                &[],
                &BTreeMap::new(),
                Some("local failure")
            )
            .is_ok()
        );
        assert!(validate_terminal(TerminalStatus::Failed, &[], &BTreeMap::new(), None).is_err());
        assert!(
            validate_terminal(
                TerminalStatus::PartialSuccess,
                &["failed.example".into()],
                &failed,
                None,
            )
            .is_err()
        );
        assert!(
            validate_terminal(
                TerminalStatus::Sent,
                &["MixedCase.example".into()],
                &BTreeMap::new(),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn recipient_ledger_inputs_are_bounded() {
        let roster: Vec<String> = (0..=MAX_RECIPIENTS)
            .map(|ordinal| format!("user{ordinal}@example.test"))
            .collect();
        assert_eq!(
            validate_recipient_roster(&roster),
            Err(DeliveryStateError::InvalidInput(
                "invalid delivery recipient count"
            ))
        );
        assert_eq!(
            validate_prepared_outcomes(&[PreparedRecipientCheckpoint {
                ordinal: 0,
                recipient: "user@example.test".into(),
                status: PreparedRecipientStatus::Retryable,
                smtp_code: 451,
                detail: "x".repeat(MAX_RECIPIENT_DETAIL_BYTES + 1),
            }]),
            Err(DeliveryStateError::InvalidInput(
                "invalid prepared recipient outcome"
            ))
        );
        assert_eq!(
            bounded_bytes(&format!("{}😀", "x".repeat(1_998)), 2_000),
            format!("{}...", "x".repeat(1_997))
        );
    }

    #[cfg(target_os = "linux")]
    mod postgres_dsn {
        use std::{
            fs,
            net::TcpListener,
            path::{Path, PathBuf},
            process::{Child, Command, Stdio},
            time::{Duration, Instant, SystemTime, UNIX_EPOCH},
        };

        use chrono::{DateTime, TimeZone, Utc};
        use deadpool_postgres::Pool;

        use crate::{
            config::{Properties, RuntimeConfig},
            database,
            outbound::{DsnAdmission, OutboundService},
            outbound_queue::LegacyOutboundQueue,
            redis as redis_config,
        };
        use tokio_util::sync::CancellationToken;

        use super::*;

        struct PostgresProcess {
            child: Child,
            directory: PathBuf,
            port: u16,
        }

        impl PostgresProcess {
            fn start() -> Self {
                let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
                let port = listener.local_addr().unwrap().port();
                drop(listener);

                let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .and_then(Path::parent)
                    .unwrap();
                let root = repository.join(".blackbox/runtime/postgres-root");
                let binary_directory = root.join("usr/lib/postgresql/16/bin");
                let library_directory = root.join("usr/lib/x86_64-linux-gnu");
                let initdb = binary_directory.join("initdb");
                let postgres = binary_directory.join("postgres");
                let pg_isready = binary_directory.join("pg_isready");
                assert!(initdb.is_file(), "PostgreSQL initdb missing");
                assert!(postgres.is_file(), "PostgreSQL server missing");
                assert!(pg_isready.is_file(), "PostgreSQL pg_isready missing");

                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let directory = std::env::temp_dir().join(format!(
                    "lmyzmail-postgres-dsn-{}-{nonce}",
                    std::process::id()
                ));
                let data_directory = directory.join("data");
                let socket_directory = directory.join("socket");
                fs::create_dir_all(&socket_directory).unwrap();

                let initialize = Command::new(initdb)
                    .args([
                        "--pgdata",
                        data_directory.to_str().unwrap(),
                        "--username=lmyzmail_test",
                        "--auth=trust",
                        "--encoding=UTF8",
                        "--no-locale",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .env("LD_LIBRARY_PATH", &library_directory)
                    .status()
                    .unwrap();
                assert!(initialize.success(), "PostgreSQL initdb failed");

                let child = Command::new(postgres)
                    .args([
                        "-D",
                        data_directory.to_str().unwrap(),
                        "-h",
                        "127.0.0.1",
                        "-p",
                        &port.to_string(),
                        "-k",
                        socket_directory.to_str().unwrap(),
                        "-F",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .env("LD_LIBRARY_PATH", &library_directory)
                    .spawn()
                    .unwrap();

                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    let ready = Command::new(&pg_isready)
                        .args([
                            "--host=127.0.0.1",
                            &format!("--port={port}"),
                            "--username=lmyzmail_test",
                            "--dbname=postgres",
                            "--timeout=1",
                        ])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .env("LD_LIBRARY_PATH", &library_directory)
                        .status()
                        .unwrap();
                    if ready.success() {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "PostgreSQL test process did not start"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }

                Self {
                    child,
                    directory,
                    port,
                }
            }

            fn port(&self) -> u16 {
                self.port
            }
        }

        impl Drop for PostgresProcess {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                if self
                    .directory
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.starts_with("lmyzmail-postgres-dsn-"))
                {
                    let _ = fs::remove_dir_all(&self.directory);
                }
            }
        }

        struct RedisProcess {
            child: Child,
            directory: PathBuf,
            port: u16,
        }

        impl RedisProcess {
            fn start() -> Self {
                let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
                let port = listener.local_addr().unwrap().port();
                drop(listener);
                let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .and_then(Path::parent)
                    .unwrap();
                let root = repository.join(".blackbox/runtime/redis-root");
                let binary = root.join("usr/bin/redis-server");
                let library_directory = root.join("usr/lib/x86_64-linux-gnu");
                assert!(binary.is_file(), "Redis server missing");
                assert!(library_directory.is_dir());
                let nonce = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let directory = std::env::temp_dir().join(format!(
                    "lmyzmail-redis-dsn-checkpoint-{}-{nonce}",
                    std::process::id()
                ));
                fs::create_dir(&directory).unwrap();
                let child = Command::new(binary)
                    .args([
                        "--bind",
                        "127.0.0.1",
                        "--port",
                        &port.to_string(),
                        "--save",
                        "",
                        "--appendonly",
                        "no",
                        "--protected-mode",
                        "yes",
                        "--dir",
                        directory.to_str().unwrap(),
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .env("LD_LIBRARY_PATH", library_directory)
                    .spawn()
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
                    assert!(Instant::now() < deadline, "Redis did not start");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Self {
                    child,
                    directory,
                    port,
                }
            }

            fn port(&self) -> u16 {
                self.port
            }
        }

        impl Drop for RedisProcess {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                if self
                    .directory
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.starts_with("lmyzmail-redis-dsn-checkpoint-"))
                {
                    let _ = fs::remove_dir_all(&self.directory);
                }
            }
        }

        fn timestamp(seconds: i64) -> DateTime<Utc> {
            Utc.timestamp_opt(seconds, 0).single().unwrap()
        }

        fn configuration(port: u16) -> RuntimeConfig {
            let mut properties = Properties::default();
            for (key, value) in [
                ("lmyzmail.postgres.host", "127.0.0.1".to_owned()),
                ("lmyzmail.postgres.port", port.to_string()),
                ("lmyzmail.postgres.database", "postgres".to_owned()),
                ("lmyzmail.postgres.username", "lmyzmail_test".to_owned()),
                ("lmyzmail.postgres.password", String::new()),
                ("lmyzmail.postgres.pool.max-size", "4".to_owned()),
            ] {
                properties.insert(key.to_owned(), value).unwrap();
            }
            RuntimeConfig::from_properties(properties).unwrap()
        }

        fn outbound_configuration(
            postgres_port: u16,
            redis_port: u16,
            storage: &Path,
        ) -> RuntimeConfig {
            let mut properties = Properties::default();
            for (key, value) in [
                ("lmyzmail.postgres.host", "127.0.0.1".to_owned()),
                ("lmyzmail.postgres.port", postgres_port.to_string()),
                ("lmyzmail.postgres.database", "postgres".to_owned()),
                ("lmyzmail.postgres.username", "lmyzmail_test".to_owned()),
                ("lmyzmail.postgres.password", String::new()),
                ("lmyzmail.postgres.pool.max-size", "4".to_owned()),
                ("lmyzmail.redis.host", "127.0.0.1".to_owned()),
                ("lmyzmail.redis.port", redis_port.to_string()),
                ("lmyzmail.redis.pool.max-active", "1".to_owned()),
                (
                    "lmyzmail.maildir.base",
                    storage.join("maildir").to_string_lossy().into_owned(),
                ),
                (
                    "lmyzmail.outbound.spool-dir",
                    storage.join("spool").to_string_lossy().into_owned(),
                ),
                ("lmyzmail.domains.main.domain", "example.test".to_owned()),
            ] {
                properties.insert(key.to_owned(), value).unwrap();
            }
            RuntimeConfig::from_properties(properties).unwrap()
        }

        async fn setup() -> (PostgresProcess, Pool, PostgresDeliveryState) {
            let process = PostgresProcess::start();
            let pool = database::create_pool(&configuration(process.port())).unwrap();
            let client = pool.get().await.unwrap();
            let legacy_ddl =
                include_str!("../../../blackbox/fixtures/legacy/postgres-longtext-oracle.sql")
                    .replace("LONGTEXT", "TEXT");
            client.batch_execute(&legacy_ddl).await.unwrap();
            client
                .batch_execute(
                    "CREATE TABLE mailbox (
                         address varchar(320) PRIMARY KEY
                     )",
                )
                .await
                .unwrap();
            drop(client);

            let state = PostgresDeliveryState::new(pool.clone());
            state.initialize_schema().await.unwrap();
            (process, pool, state)
        }

        async fn insert_terminal(pool: &Pool, task_id: i64, sender: &str, now: DateTime<Utc>) {
            let client = pool.get().await.unwrap();
            client
                .execute(
                    "INSERT INTO outbound_mail_queue
                     (id,sender_address,recipients_json,status,retry_count,max_retries,
                      next_retry_at,created_at,updated_at,subject,message_id)
                     VALUES ($1,$2,'[\"recipient@remote.test\"]','FAILED',0,3,
                             $3,$3,$3,'terminal subject',$4)",
                    &[
                        &task_id,
                        &sender,
                        &now,
                        &format!("<{task_id}@example.test>"),
                    ],
                )
                .await
                .unwrap();
            let roster_hash = vec![0_u8; 32];
            client
                .execute(
                    "INSERT INTO lmyzmail_outbound_delivery_attempt
                     (task_id,generation,owner_token,recipient_count,roster_sha256,
                      phase,created_at,updated_at)
                     VALUES ($1,1,NULL,1,$2,'PROJECTED',$3,$3)",
                    &[&task_id, &roster_hash, &now],
                )
                .await
                .unwrap();
            client
                .execute(
                    "INSERT INTO lmyzmail_outbound_delivery_recipient
                     (task_id,recipient_ordinal,recipient_address,state,
                      attempt_generation,smtp_code,detail,updated_at)
                     VALUES ($1,0,'recipient@remote.test','PERMANENT',1,550,
                             'permanent failure',$2)",
                    &[&task_id, &now],
                )
                .await
                .unwrap();
        }

        async fn insert_ambiguous_recipient(pool: &Pool, task_id: i64, now: DateTime<Utc>) {
            pool.get()
                .await
                .unwrap()
                .execute(
                    "INSERT INTO lmyzmail_outbound_delivery_recipient
                     (task_id,recipient_ordinal,recipient_address,state,
                      attempt_generation,smtp_code,detail,updated_at)
                     VALUES ($1,1,'ambiguous@remote.test','AMBIGUOUS',1,NULL,
                             'ambiguous outcome',$2)",
                    &[&task_id, &now],
                )
                .await
                .unwrap();
        }

        async fn set_sequence_above(pool: &Pool, value: i64) {
            pool.get()
                .await
                .unwrap()
                .execute(
                    "SELECT setval(pg_get_serial_sequence('outbound_mail_queue','id'), $1, true)",
                    &[&value],
                )
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn dsn_staging_requires_local_sender_and_reuses_leased_id() {
            let (_process, pool, state) = setup().await;
            let now = timestamp(1_786_400_000);
            pool.get()
                .await
                .unwrap()
                .execute(
                    "INSERT INTO mailbox(address) VALUES ('qa@example.test')",
                    &[],
                )
                .await
                .unwrap();
            insert_terminal(&pool, 7_401, "qa@example.test", now).await;
            insert_terminal(&pool, 7_402, "spoof@example.test", now).await;
            set_sequence_above(&pool, 20_000).await;

            let work = state.stage_and_lease_dsns(16, now).await.unwrap();
            assert_eq!(work.len(), 1);
            let first = &work[0];
            assert_eq!(first.original_task_id, 7_401);
            assert_eq!(first.payload.sender_address, "qa@example.test");
            assert_eq!(first.payload.recipients[0].state, "PERMANENT");
            assert!(first.dsn_task_id.is_none());

            let client = pool.get().await.unwrap();
            let states = client
                .query(
                    "SELECT original_task_id,dsn_task_id,state,suppress_reason
                     FROM lmyzmail_outbound_dsn ORDER BY original_task_id",
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(states.len(), 2);
            assert_eq!(states[0].get::<_, i64>(0), 7_401);
            assert_eq!(states[0].get::<_, Option<i64>>(1), None);
            assert_eq!(states[0].get::<_, &str>(2), "LEASED");
            assert_eq!(states[0].get::<_, Option<&str>>(3), None);
            assert_eq!(states[1].get::<_, i64>(0), 7_402);
            assert_eq!(states[1].get::<_, &str>(2), "SUPPRESSED");
            assert!(states[1].get::<_, Option<&str>>(3).is_some());
            drop(client);

            let bound_id = 20_001_i64;
            state
                .bind_dsn_task_id(
                    first.original_task_id,
                    &first.lease_token,
                    bound_id,
                    now + chrono::Duration::seconds(1),
                )
                .await
                .unwrap();
            let (active_a, active_b) = tokio::join!(
                state.stage_and_lease_dsns(16, now),
                state.stage_and_lease_dsns(16, now),
            );
            assert!(active_a.unwrap().is_empty());
            assert!(active_b.unwrap().is_empty());

            let expired = now + chrono::Duration::seconds(121);
            let (expired_a, expired_b) = tokio::join!(
                state.stage_and_lease_dsns(16, expired),
                state.stage_and_lease_dsns(16, expired),
            );
            let mut recovered = expired_a.unwrap();
            recovered.extend(expired_b.unwrap());
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].original_task_id, first.original_task_id);
            assert_eq!(recovered[0].dsn_task_id, Some(bound_id));
            assert_ne!(recovered[0].lease_token, first.lease_token);
            assert_eq!(
                state
                    .suppress_dsn(
                        first.original_task_id,
                        &first.lease_token,
                        "stale lease",
                        expired + chrono::Duration::seconds(1),
                    )
                    .await
                    .unwrap_err(),
                DeliveryStateError::InvalidTransition(
                    "outbound DSN lease was lost before suppression"
                )
            );
        }

        #[tokio::test]
        async fn dsn_suppression_admission_visibility_and_recursive_staging_are_bounded() {
            let (_process, pool, state) = setup().await;
            let now = timestamp(1_786_400_100);
            pool.get()
                .await
                .unwrap()
                .execute(
                    "INSERT INTO mailbox(address) VALUES ('qa@example.test')",
                    &[],
                )
                .await
                .unwrap();
            insert_terminal(&pool, 7_403, "qa@example.test", now).await;
            insert_terminal(&pool, 7_404, "qa@example.test", now).await;
            insert_terminal(&pool, 7_405, "qa@example.test", now).await;
            insert_ambiguous_recipient(&pool, 7_405, now).await;
            set_sequence_above(&pool, 21_000).await;

            let staged = state.stage_and_lease_dsns(16, now).await.unwrap();
            assert_eq!(staged.len(), 2);
            let ambiguous_row = pool
                .get()
                .await
                .unwrap()
                .query_one(
                    "SELECT state,suppress_reason,lease_token,lease_until
                     FROM lmyzmail_outbound_dsn
                     WHERE original_task_id=7405",
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(ambiguous_row.get::<_, &str>(0), "SUPPRESSED");
            assert_eq!(
                ambiguous_row.get::<_, Option<&str>>(1),
                Some("delivery outcome is ambiguous")
            );
            assert_eq!(ambiguous_row.get::<_, Option<&str>>(2), None);
            assert_eq!(ambiguous_row.get::<_, Option<DateTime<Utc>>>(3), None);
            let suppressed = staged
                .iter()
                .find(|item| item.original_task_id == 7_403)
                .unwrap()
                .clone();
            assert!(suppressed.dsn_task_id.is_none());
            state
                .bind_dsn_task_id(
                    suppressed.original_task_id,
                    &suppressed.lease_token,
                    21_002,
                    now + chrono::Duration::seconds(1),
                )
                .await
                .unwrap();
            pool.get()
                .await
                .unwrap()
                .execute(
                    "UPDATE lmyzmail_outbound_dsn
                     SET expected_sha256=$2,prepared_bytes=$3
                     WHERE original_task_id=$1",
                    &[
                        &suppressed.original_task_id,
                        &vec![3_u8; 32],
                        &b"durable recovery image".as_slice(),
                    ],
                )
                .await
                .unwrap();
            state
                .suppress_dsn(
                    7_403,
                    &suppressed.lease_token,
                    "test suppression",
                    now + chrono::Duration::seconds(2),
                )
                .await
                .unwrap();
            assert_eq!(
                pool.get()
                    .await
                    .unwrap()
                    .query_one(
                        "SELECT state,suppress_reason,lease_token,lease_until
                         FROM lmyzmail_outbound_dsn
                         WHERE original_task_id=7403",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get::<_, &str>(0),
                "SUPPRESSED"
            );
            let suppressed_row = pool
                .get()
                .await
                .unwrap()
                .query_one(
                    "SELECT suppress_reason,lease_token,lease_until,expected_sha256
                     FROM lmyzmail_outbound_dsn WHERE original_task_id=7403",
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(suppressed_row.get::<_, &str>(0), "test suppression");
            assert_eq!(suppressed_row.get::<_, Option<&str>>(1), None);
            assert_eq!(suppressed_row.get::<_, Option<DateTime<Utc>>>(2), None);
            assert_eq!(suppressed_row.get::<_, Option<Vec<u8>>>(3), None);

            let admitted = staged
                .iter()
                .find(|item| item.original_task_id == 7_404)
                .unwrap();
            let admitted_id = 21_001_i64;
            state
                .bind_dsn_task_id(
                    admitted.original_task_id,
                    &admitted.lease_token,
                    admitted_id,
                    now + chrono::Duration::seconds(1),
                )
                .await
                .unwrap();
            assert!(!state.is_dsn_task(admitted_id).await.unwrap());
            let digest = vec![7_u8; 32];
            pool.get()
                .await
                .unwrap()
                .execute(
                    "UPDATE lmyzmail_outbound_dsn
                     SET state='ADMITTED',expected_sha256=$2,lease_token=NULL,
                         lease_until=NULL,
                         updated_at=$3
                     WHERE original_task_id=$1",
                    &[&admitted.original_task_id, &digest, &now],
                )
                .await
                .unwrap();
            assert!(state.is_dsn_task(admitted_id).await.unwrap());

            insert_terminal(&pool, admitted_id, "qa@example.test", now).await;
            let recursive = state
                .stage_and_lease_dsns(16, now + chrono::Duration::seconds(1))
                .await
                .unwrap();
            assert!(recursive.is_empty(), "generated DSNs must not recurse");
            let dsn_rows: i64 = pool
                .get()
                .await
                .unwrap()
                .query_one("SELECT count(*) FROM lmyzmail_outbound_dsn", &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(dsn_rows, 3);
        }

        #[tokio::test]
        async fn dsn_checkpoint_is_first_writer_wins_and_admission_clears_recovery_image() {
            let (process, pool, state) = setup().await;
            let redis = RedisProcess::start();
            let now = Utc::now();
            let client = pool.get().await.unwrap();
            client
                .batch_execute(
                    "CREATE TABLE email_index (
                         id bigint generated by default as identity primary key,
                         mailbox_address varchar(255) not null,
                         folder varchar(50) not null,
                         file_name varchar(255) not null,
                         subdirectory integer,
                         subject varchar(1000),
                         from_address varchar(500),
                         to_addresses varchar(2000),
                         received_at timestamp(6) with time zone not null,
                         has_attachments boolean not null,
                         message_id varchar(500),
                         size_bytes bigint,
                         indexed_at timestamp(6) with time zone not null,
                         CONSTRAINT uk_email_index_mailbox_folder_subdir_file
                             UNIQUE (mailbox_address, folder, subdirectory, file_name)
                     );
                     INSERT INTO mailbox(address) VALUES ('qa@example.test')",
                )
                .await
                .unwrap();
            drop(client);
            insert_terminal(&pool, 7_406, "qa@example.test", now).await;
            let work = state.stage_and_lease_dsns(16, now).await.unwrap();
            assert_eq!(work.len(), 1);
            let work = &work[0];
            let dsn_task_id = 21_003_i64;
            state
                .bind_dsn_task_id(work.original_task_id, &work.lease_token, dsn_task_id, now)
                .await
                .unwrap();

            let storage = process.directory.join("outbound-checkpoint");
            let runtime = outbound_configuration(process.port(), redis.port(), &storage);
            let redis_pool = redis_config::create_pool(&runtime).unwrap();
            let first_service =
                OutboundService::from_config(&runtime, pool.clone(), redis_pool.clone()).unwrap();
            let body = concat!(
                "From: mailer-daemon@example.test\r\n",
                "To: qa@example.test\r\n",
                "Subject: Delivery Status Notification (Failure)\r\n",
                "Message-ID: <dsn-checkpoint@example.test>\r\n",
                "MIME-Version: 1.0\r\n\r\n",
                "Checkpoint body.\r\n",
            );
            let first_digest: [u8; 32] = Sha256::digest(body.as_bytes()).into();
            let first = first_service
                .checkpoint_dsn_material(
                    work.original_task_id,
                    &work.lease_token,
                    first_digest,
                    body.as_bytes(),
                )
                .await
                .unwrap();
            assert_eq!(first, (first_digest, body.as_bytes().to_vec()));

            let rotated_body = b"different bytes after a signing-key rotation\r\n";
            let rotated_digest: [u8; 32] = Sha256::digest(rotated_body).into();
            let restarted_service =
                OutboundService::from_config(&runtime, pool.clone(), redis_pool.clone()).unwrap();
            let after_restart = restarted_service
                .checkpoint_dsn_material(
                    work.original_task_id,
                    &work.lease_token,
                    rotated_digest,
                    rotated_body,
                )
                .await
                .unwrap();
            assert_eq!(after_restart, first);

            let admission = tokio::time::timeout(
                Duration::from_secs(10),
                restarted_service.admit_dsn(
                    DsnAdmission {
                        source_task_id: work.original_task_id,
                        task_id: dsn_task_id,
                        lease_token: work.lease_token.clone(),
                        sender: "qa@example.test".into(),
                        recipient: "qa@example.test".into(),
                        subject: "Delivery Status Notification (Failure)".into(),
                        message_id: "<dsn-checkpoint@example.test>".into(),
                        body: body.into(),
                        created_at: now,
                        unsigned_sha256: first_digest,
                    },
                    &CancellationToken::new(),
                ),
            )
            .await
            .expect("DSN admission must remain bounded")
            .unwrap();

            let client = pool.get().await.unwrap();
            let queue_count = client
                .query_one(
                    "SELECT count(*) FROM outbound_mail_queue WHERE id=$1 AND status='PENDING'",
                    &[&dsn_task_id],
                )
                .await
                .unwrap()
                .get::<_, i64>(0);
            let index_count = client
                .query_one(
                    "SELECT count(*) FROM email_index
                     WHERE mailbox_address='qa@example.test' AND folder='sent'",
                    &[],
                )
                .await
                .unwrap()
                .get::<_, i64>(0);
            let checkpoint = client
                .query_one(
                    "SELECT state,expected_sha256,prepared_bytes,lease_token,lease_until
                     FROM lmyzmail_outbound_dsn WHERE original_task_id=$1",
                    &[&work.original_task_id],
                )
                .await
                .unwrap();
            let spool = client
                .query_one(
                    "SELECT cleanup_state,cleanup_after_publish,spool_path
                     FROM lmyzmail_outbound_spool WHERE task_id=$1",
                    &[&dsn_task_id],
                )
                .await
                .unwrap();
            assert_eq!(
                checkpoint.get::<_, &str>(0),
                "ADMITTED",
                "admission={admission:?}, queue_count={queue_count}, index_count={index_count}"
            );
            assert_eq!(checkpoint.get::<_, Vec<u8>>(1), first_digest);
            assert_eq!(checkpoint.get::<_, Option<Vec<u8>>>(2), None);
            assert_eq!(checkpoint.get::<_, Option<&str>>(3), None);
            assert_eq!(checkpoint.get::<_, Option<DateTime<Utc>>>(4), None);
            assert_eq!(queue_count, 1);
            assert_eq!(index_count, 1);
            assert_eq!(spool.get::<_, &str>(0), "REMOVED");
            assert!(spool.get::<_, bool>(1));
            assert!(!Path::new(spool.get::<_, &str>(2)).exists());

            let spool_path = PathBuf::from(spool.get::<_, &str>(2));
            let sent_subdirectory = client
                .query_one(
                    "SELECT sent_subdirectory FROM outbound_mail_queue WHERE id=$1",
                    &[&dsn_task_id],
                )
                .await
                .unwrap()
                .get::<_, i32>(0);
            let sent_path = storage
                .join("maildir/qa@example.test/sent")
                .join(sent_subdirectory.to_string())
                .join(&admission.sent_file_name);
            fs::copy(&sent_path, &spool_path).unwrap();
            client
                .execute(
                    "UPDATE lmyzmail_outbound_spool
                     SET cleanup_state='OWNED' WHERE task_id=$1",
                    &[&dsn_task_id],
                )
                .await
                .unwrap();
            drop(client);

            let mut redis_connection = redis_pool.get().await.unwrap();
            deadpool_redis::redis::cmd("FLUSHDB")
                .query_async::<()>(&mut redis_connection)
                .await
                .unwrap();
            drop(redis_connection);

            let reconciliation_cancellation = CancellationToken::new();
            let reconciliation_service = restarted_service.clone();
            let task_cancellation = reconciliation_cancellation.clone();
            let reconciliation_task = tokio::spawn(async move {
                reconciliation_service
                    .run_reconciler(task_cancellation)
                    .await;
            });
            let redis_queue = LegacyOutboundQueue::new(redis_pool);
            let publication_deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if redis_queue
                    .is_complete_task(dsn_task_id, &admission.sent_file_name)
                    .await
                    .unwrap()
                {
                    break;
                }
                assert!(
                    Instant::now() < publication_deadline,
                    "durable task was not republished"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let cleanup_state = pool
                    .get()
                    .await
                    .unwrap()
                    .query_one(
                        "SELECT cleanup_state FROM lmyzmail_outbound_spool WHERE task_id=$1",
                        &[&dsn_task_id],
                    )
                    .await
                    .unwrap()
                    .get::<_, String>(0);
                if cleanup_state == "REMOVED" && !spool_path.exists() {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "durable inline-spool cleanup was not recovered"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            reconciliation_cancellation.cancel();
            tokio::time::timeout(Duration::from_secs(1), reconciliation_task)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
