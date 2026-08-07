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
const DELIVERY_LEDGER_SCHEMA: &str = include_str!("../migrations/001_outbound_delivery_ledger.sql");

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
            transaction.commit().await?;
            Ok(())
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
                             nextval(value::regclass)
                         ),
                         true
                     )
                     FROM sequence_name WHERE value IS NOT NULL",
                    &[&task.task_id],
                )
                .await?;
            transaction.commit().await?;
            Ok(inserted)
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
                let last_error = projection_error(&recipients, "temporary delivery failure");
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
                Some(projection_error(&recipients, "permanent delivery failure"))
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
                    Some(projection_error(&recipients, "permanent delivery failure"))
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
                        processing_started_at,processor_id
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

fn projection_error(recipients: &[ProjectionRecipient], fallback: &str) -> String {
    bounded_error(
        recipients
            .iter()
            .find_map(|recipient| recipient.detail.as_deref())
            .unwrap_or(fallback),
    )
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
}
