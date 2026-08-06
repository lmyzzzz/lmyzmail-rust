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
use tokio::time::{Instant, timeout_at};

const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_OWNER_TOKEN_BYTES: usize = 100;
const MAX_WORKER_ID_BYTES: usize = 64;
const MAX_LAST_ERROR_UTF16_UNITS: usize = 1_000;
const MAX_DOMAIN_ERROR_BYTES: usize = 2_000;
const MAX_DOMAINS: usize = 1_000;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_DOMAIN_ARCHIVE_BYTES: usize = 2 * 1024 * 1024;

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
        Ok(Self {
            task_id,
            owner_token: unique_owner_token(worker_id)?,
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
    pub sent_at: Option<DateTime<Utc>>,
    pub processing_started_at: Option<DateTime<Utc>>,
    pub has_owner: bool,
    pub owned_by_claim: bool,
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
    Unavailable,
    OutcomeUnknown,
}

impl fmt::Display for DeliveryStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => formatter.write_str(message),
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
        let client = self.client(deadline).await?;
        let row = mutation_deadline(
            deadline,
            client.query_opt(
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
            ),
        )
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

    pub async fn heartbeat(
        &self,
        claim: &DatabaseClaim,
        now: DateTime<Utc>,
    ) -> Result<bool, DeliveryStateError> {
        validate_claim(claim)?;
        let now = postgres_timestamp(now)?;
        let deadline = Instant::now() + self.operation_timeout;
        let client = self.client(deadline).await?;
        let updated = mutation_deadline(
            deadline,
            client.execute(
                "UPDATE outbound_mail_queue
                 SET processing_started_at=GREATEST(processing_started_at,$3),
                     updated_at=GREATEST(updated_at,$3)
                 WHERE id=$1 AND status='PROCESSING' AND processor_id=$2",
                &[&claim.task_id, &claim.owner_token, &now],
            ),
        )
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
        let client = self.client(deadline).await?;
        let updated = mutation_deadline(
            deadline,
            client.execute(
                "UPDATE outbound_mail_queue
                 SET status='PENDING', processor_id=NULL, processing_started_at=NULL,
                     next_retry_at=LEAST(next_retry_at,$3), updated_at=$3
                 WHERE id=$1 AND status='PROCESSING' AND processor_id=$2",
                &[&claim.task_id, &claim.owner_token, &now],
            ),
        )
        .await?;
        Ok(updated == 1)
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
        let client = self.client(deadline).await?;
        let row = mutation_deadline(
            deadline,
            client.query_opt(
                "UPDATE outbound_mail_queue
                 SET status='PENDING', retry_count=retry_count+1, next_retry_at=$3,
                     last_error=$4, processor_id=NULL, processing_started_at=NULL, updated_at=$5
                 WHERE id=$1 AND status='PROCESSING' AND processor_id=$2
                   AND retry_count < max_retries
                 RETURNING retry_count,max_retries,next_retry_at",
                &[
                    &claim.task_id,
                    &claim.owner_token,
                    &next_retry_at,
                    &last_error,
                    &now,
                ],
            ),
        )
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
        let client = self.client(deadline).await?;
        let updated = mutation_deadline(
            deadline,
            client.execute(
                "UPDATE outbound_mail_queue
                 SET status=$3, sent_at=$4, last_error=$5, sent_domains_json=$6,
                     failed_domains_json=$7, processor_id=NULL, processing_started_at=NULL,
                     updated_at=$8
                 WHERE id=$1 AND status='PROCESSING' AND processor_id=$2",
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
            ),
        )
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
        let client = self.client(deadline).await?;
        let updated = mutation_deadline(
            deadline,
            client.execute(
                "UPDATE outbound_mail_queue
                 SET status='PENDING', processor_id=NULL, processing_started_at=NULL,
                     next_retry_at=LEAST(next_retry_at,$3), updated_at=$3
                 WHERE id=$1 AND status='PROCESSING'
                   AND (processing_started_at IS NULL OR processing_started_at < $2)",
                &[&task_id, &heartbeat_before, &now],
            ),
        )
        .await?;
        Ok(updated == 1)
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
                "SELECT status,retry_count,max_retries,next_retry_at,sent_at,
                        processing_started_at,processor_id
                 FROM outbound_mail_queue WHERE id=$1",
                &[&task_id],
            ),
        )
        .await?;
        row.map(|row| {
            let owner: Option<String> = row.get(6);
            Ok(DeliverySnapshot {
                task_id,
                status: DeliveryRowStatus::from_database(row.get(0))?,
                retry_count: row.get(1),
                max_retries: row.get(2),
                next_retry_at: row.get(3),
                sent_at: row.get(4),
                processing_started_at: row.get(5),
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

async fn mutation_deadline<T, F>(deadline: Instant, future: F) -> Result<T, DeliveryStateError>
where
    F: Future<Output = Result<T, tokio_postgres::Error>>,
{
    timeout_at(deadline, future)
        .await
        .map_err(|_| DeliveryStateError::OutcomeUnknown)?
        .map_err(|_| DeliveryStateError::OutcomeUnknown)
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

fn validate_worker_identity(task_id: i64, worker_id: &str) -> Result<(), DeliveryStateError> {
    if worker_id.len() > MAX_WORKER_ID_BYTES {
        return Err(DeliveryStateError::InvalidInput(
            "invalid delivery worker ID",
        ));
    }
    validate_identity(task_id, worker_id)
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

fn validate_attempt(attempt: &DeliveryAttemptId) -> Result<(), DeliveryStateError> {
    validate_identity(attempt.task_id, &attempt.owner_token)
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
}
