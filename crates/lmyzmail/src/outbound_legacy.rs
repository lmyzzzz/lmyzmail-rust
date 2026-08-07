use std::fmt;

use chrono::{DateTime, Utc};
use getrandom::fill as fill_random;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::{
    outbound_delivery::{
        DeliveryRowStatus, DeliveryStateError, LegacyArchiveMaterialization,
        LegacyStatusMaterialization, PostgresDeliveryState,
    },
    outbound_queue::{
        LegacyListClaim, LegacyListKind, LegacyListRecord, LegacyOutboundQueue, QueueError,
    },
};

const MAX_ARCHIVE_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAX_STATUS_RECORD_BYTES: usize = 256 * 1024;
const RECONCILIATION_ATTEMPTS: usize = 3;

#[derive(Clone)]
pub struct LegacyQueueMigrator {
    queue: LegacyOutboundQueue,
    state: PostgresDeliveryState,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MigrationSummary {
    pub archives: usize,
    pub status_updates: usize,
    pub quarantined: usize,
}

#[derive(Debug)]
pub enum LegacyMigrationError {
    Queue(QueueError),
    DeliveryState(DeliveryStateError),
    Reconciliation(&'static str),
    Cancelled,
}

impl fmt::Display for LegacyMigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queue(error) => write!(formatter, "legacy Redis migration failed: {error}"),
            Self::DeliveryState(error) => {
                write!(formatter, "legacy PostgreSQL migration failed: {error}")
            }
            Self::Reconciliation(message) => formatter.write_str(message),
            Self::Cancelled => formatter.write_str("legacy outbound migration was cancelled"),
        }
    }
}

impl std::error::Error for LegacyMigrationError {}

impl From<QueueError> for LegacyMigrationError {
    fn from(error: QueueError) -> Self {
        Self::Queue(error)
    }
}

impl From<DeliveryStateError> for LegacyMigrationError {
    fn from(error: DeliveryStateError) -> Self {
        Self::DeliveryState(error)
    }
}

impl LegacyQueueMigrator {
    pub fn new(queue: LegacyOutboundQueue, state: PostgresDeliveryState) -> Self {
        Self { queue, state }
    }

    pub async fn migrate_batch(
        &self,
        limit_per_list: usize,
        cancellation: &CancellationToken,
    ) -> Result<MigrationSummary, LegacyMigrationError> {
        if limit_per_list == 0 || limit_per_list > 10_000 {
            return Err(LegacyMigrationError::Queue(QueueError::InvalidTask(
                "legacy migration batch bound is invalid",
            )));
        }
        let mut summary = MigrationSummary::default();
        self.migrate_archives(limit_per_list, cancellation, &mut summary)
            .await?;
        self.migrate_status_updates(limit_per_list, cancellation, &mut summary)
            .await?;
        Ok(summary)
    }

    async fn migrate_archives(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
        summary: &mut MigrationSummary,
    ) -> Result<(), LegacyMigrationError> {
        for _ in 0..limit {
            check_cancelled(cancellation)?;
            let claim = self
                .claim_record(LegacyListKind::Archive, MAX_ARCHIVE_RECORD_BYTES)
                .await?;
            let record = match claim {
                LegacyListClaim::Empty => break,
                LegacyListClaim::Settled => continue,
                LegacyListClaim::Quarantined(_) => {
                    summary.quarantined += 1;
                    continue;
                }
                LegacyListClaim::Record(record) => record,
            };
            let parsed = match parse_archive(&record.payload, Utc::now()) {
                Ok(parsed) => parsed,
                Err(reason) => {
                    self.quarantine(&record, reason).await?;
                    summary.quarantined += 1;
                    continue;
                }
            };
            match self.persist_archive(&parsed.materialization).await {
                Ok(()) => {}
                Err(LegacyMigrationError::DeliveryState(
                    DeliveryStateError::InvalidInput(_)
                    | DeliveryStateError::InvalidTransition(_)
                    | DeliveryStateError::Fenced,
                )) => {
                    self.quarantine(&record, "archive-conflict").await?;
                    summary.quarantined += 1;
                    continue;
                }
                Err(error) => return Err(error),
            }
            self.cleanup_terminal_task(
                parsed.materialization.task_id,
                parsed.materialization.sent_file_name.as_deref(),
            )
            .await?;
            self.acknowledge(&record).await?;
            summary.archives += 1;
        }
        Ok(())
    }

    async fn migrate_status_updates(
        &self,
        limit: usize,
        cancellation: &CancellationToken,
        summary: &mut MigrationSummary,
    ) -> Result<(), LegacyMigrationError> {
        for _ in 0..limit {
            check_cancelled(cancellation)?;
            let claim = self
                .claim_record(LegacyListKind::StatusUpdates, MAX_STATUS_RECORD_BYTES)
                .await?;
            let record = match claim {
                LegacyListClaim::Empty => break,
                LegacyListClaim::Settled => continue,
                LegacyListClaim::Quarantined(_) => {
                    summary.quarantined += 1;
                    continue;
                }
                LegacyListClaim::Record(record) => record,
            };
            let update = match parse_status(&record.payload, Utc::now()) {
                Ok(update) => update,
                Err(reason) => {
                    self.quarantine(&record, reason).await?;
                    summary.quarantined += 1;
                    continue;
                }
            };
            match self.persist_status(&update).await {
                Ok(true) => {}
                Ok(false) => {
                    self.quarantine(&record, "status-row-missing").await?;
                    summary.quarantined += 1;
                    continue;
                }
                Err(LegacyMigrationError::DeliveryState(
                    DeliveryStateError::InvalidInput(_)
                    | DeliveryStateError::InvalidTransition(_)
                    | DeliveryStateError::Fenced,
                )) => {
                    self.quarantine(&record, "status-conflict").await?;
                    summary.quarantined += 1;
                    continue;
                }
                Err(error) => return Err(error),
            }
            self.acknowledge(&record).await?;
            summary.status_updates += 1;
        }
        Ok(())
    }

    async fn claim_record(
        &self,
        kind: LegacyListKind,
        max_record_bytes: usize,
    ) -> Result<LegacyListClaim, LegacyMigrationError> {
        let token = migration_token()?;
        for _ in 0..RECONCILIATION_ATTEMPTS {
            match self
                .queue
                .claim_legacy_list_record(kind, &token, max_record_bytes)
                .await
            {
                Ok(claim) => return Ok(claim),
                Err(QueueError::OutcomeUnknown) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(LegacyMigrationError::Reconciliation(
            "legacy Redis list claim could not be reconciled",
        ))
    }

    async fn acknowledge(&self, record: &LegacyListRecord) -> Result<(), LegacyMigrationError> {
        for _ in 0..RECONCILIATION_ATTEMPTS {
            match self.queue.acknowledge_legacy_list_record(record).await {
                Ok(true) => return Ok(()),
                Ok(false) | Err(QueueError::OutcomeUnknown) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(LegacyMigrationError::Reconciliation(
            "legacy Redis list acknowledgement could not be reconciled",
        ))
    }

    async fn quarantine(
        &self,
        record: &LegacyListRecord,
        reason: &'static str,
    ) -> Result<(), LegacyMigrationError> {
        for _ in 0..RECONCILIATION_ATTEMPTS {
            match self
                .queue
                .quarantine_legacy_list_record(record, reason)
                .await
            {
                Ok(true) => return Ok(()),
                Ok(false) | Err(QueueError::OutcomeUnknown) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(LegacyMigrationError::Reconciliation(
            "legacy Redis quarantine could not be reconciled",
        ))
    }

    async fn persist_archive(
        &self,
        archive: &LegacyArchiveMaterialization,
    ) -> Result<(), LegacyMigrationError> {
        for _ in 0..RECONCILIATION_ATTEMPTS {
            match self.state.materialize_legacy_archive(archive).await {
                Ok(_) => return Ok(()),
                Err(DeliveryStateError::OutcomeUnknown) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(LegacyMigrationError::Reconciliation(
            "legacy archive commit could not be reconciled",
        ))
    }

    async fn persist_status(
        &self,
        update: &LegacyStatusMaterialization,
    ) -> Result<bool, LegacyMigrationError> {
        for _ in 0..RECONCILIATION_ATTEMPTS {
            match self.state.apply_legacy_status_update(update).await {
                Ok(applied) => return Ok(applied),
                Err(DeliveryStateError::OutcomeUnknown) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(LegacyMigrationError::Reconciliation(
            "legacy status commit could not be reconciled",
        ))
    }

    async fn cleanup_terminal_task(
        &self,
        task_id: i64,
        sent_file_name: Option<&str>,
    ) -> Result<(), LegacyMigrationError> {
        for _ in 0..RECONCILIATION_ATTEMPTS {
            match self
                .queue
                .cleanup_migrated_terminal_task(task_id, sent_file_name)
                .await
            {
                Ok(()) => return Ok(()),
                Err(QueueError::OutcomeUnknown) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(LegacyMigrationError::Reconciliation(
            "legacy terminal task cleanup could not be reconciled",
        ))
    }
}

#[derive(Debug)]
struct ParsedArchive {
    materialization: LegacyArchiveMaterialization,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyArchiveDto {
    detail: LegacyTaskDto,
    final_status: Option<LegacyStatusDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyTaskDto {
    id: i64,
    sender_address: String,
    recipients_json: String,
    subject: Option<String>,
    message_id: Option<String>,
    max_retries: i32,
    retry_count: i32,
    sent_file_name: Option<String>,
    sent_subdirectory: Option<i32>,
    message_file_path: Option<String>,
    signed_content_base64: Option<String>,
    created_at: Option<String>,
    next_retry_at: Option<String>,
    last_error: Option<String>,
    status: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyStatusDto {
    task_id: i64,
    status: String,
    sent_at: Option<String>,
    last_error: Option<String>,
    retry_count: i32,
    sent_domains_json: Option<String>,
    failed_domains_json: Option<String>,
    updated_at: Option<String>,
}

fn parse_archive(payload: &str, now: DateTime<Utc>) -> Result<ParsedArchive, &'static str> {
    let dto: LegacyArchiveDto =
        serde_json::from_str(payload).map_err(|_| "archive-invalid-json")?;
    if dto
        .detail
        .message_file_path
        .as_deref()
        .is_some_and(str::is_empty)
        || dto
            .detail
            .signed_content_base64
            .as_deref()
            .is_some_and(str::is_empty)
    {
        return Err("archive-invalid-content");
    }
    let final_status = dto.final_status.as_ref();
    if final_status.is_some_and(|status| status.task_id != dto.detail.id) {
        return Err("archive-task-mismatch");
    }
    let status = parse_status_name(
        final_status
            .map(|status| status.status.as_str())
            .or(dto.detail.status.as_deref())
            .ok_or("archive-status-missing")?,
    )?;
    if !matches!(
        status,
        DeliveryRowStatus::Sent
            | DeliveryRowStatus::PartialSuccess
            | DeliveryRowStatus::Failed
            | DeliveryRowStatus::Cancelled
    ) {
        return Err("archive-status-invalid");
    }
    let created_at = parse_timestamp(dto.detail.created_at.as_deref(), now)?;
    let next_retry_at = parse_timestamp(dto.detail.next_retry_at.as_deref(), now)?;
    let updated_at = parse_timestamp(
        final_status.and_then(|status| status.updated_at.as_deref()),
        now,
    )?;
    let sent_at = final_status
        .and_then(|status| status.sent_at.as_deref())
        .map(parse_required_timestamp)
        .transpose()?;
    let retry_count = final_status
        .filter(|status| status.retry_count > 0)
        .map(|status| status.retry_count)
        .unwrap_or(dto.detail.retry_count);
    let last_error = final_status
        .and_then(|status| status.last_error.clone())
        .or(dto.detail.last_error);
    Ok(ParsedArchive {
        materialization: LegacyArchiveMaterialization {
            task_id: dto.detail.id,
            sender_address: dto.detail.sender_address,
            recipients_json: dto.detail.recipients_json,
            subject: dto.detail.subject,
            message_id: dto.detail.message_id,
            sent_file_name: dto.detail.sent_file_name,
            sent_subdirectory: dto.detail.sent_subdirectory,
            retry_count,
            max_retries: dto.detail.max_retries,
            next_retry_at,
            last_error,
            status,
            sent_at,
            sent_domains_json: final_status.and_then(|status| status.sent_domains_json.clone()),
            failed_domains_json: final_status.and_then(|status| status.failed_domains_json.clone()),
            created_at,
            updated_at,
        },
    })
}

fn parse_status(
    payload: &str,
    now: DateTime<Utc>,
) -> Result<LegacyStatusMaterialization, &'static str> {
    let dto: LegacyStatusDto = serde_json::from_str(payload).map_err(|_| "status-invalid-json")?;
    let status = parse_status_name(&dto.status)?;
    if status == DeliveryRowStatus::Processing {
        return Err("status-state-invalid");
    }
    Ok(LegacyStatusMaterialization {
        task_id: dto.task_id,
        status,
        sent_at: dto
            .sent_at
            .as_deref()
            .map(parse_required_timestamp)
            .transpose()?,
        last_error: dto.last_error,
        retry_count: dto.retry_count,
        sent_domains_json: dto.sent_domains_json,
        failed_domains_json: dto.failed_domains_json,
        updated_at: parse_timestamp(dto.updated_at.as_deref(), now)?,
    })
}

fn parse_status_name(value: &str) -> Result<DeliveryRowStatus, &'static str> {
    match value {
        "PENDING" => Ok(DeliveryRowStatus::Pending),
        "PROCESSING" => Ok(DeliveryRowStatus::Processing),
        "SENT" => Ok(DeliveryRowStatus::Sent),
        "PARTIAL_SUCCESS" => Ok(DeliveryRowStatus::PartialSuccess),
        "FAILED" => Ok(DeliveryRowStatus::Failed),
        "CANCELLED" => Ok(DeliveryRowStatus::Cancelled),
        _ => Err("legacy-status-invalid"),
    }
}

fn parse_timestamp(
    value: Option<&str>,
    fallback: DateTime<Utc>,
) -> Result<DateTime<Utc>, &'static str> {
    value
        .map(parse_required_timestamp)
        .transpose()
        .map(|value| value.unwrap_or(fallback))
}

fn parse_required_timestamp(value: &str) -> Result<DateTime<Utc>, &'static str> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| "legacy-timestamp-invalid")
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), LegacyMigrationError> {
    if cancellation.is_cancelled() {
        Err(LegacyMigrationError::Cancelled)
    } else {
        Ok(())
    }
}

fn migration_token() -> Result<String, LegacyMigrationError> {
    let mut random = [0_u8; 16];
    fill_random(&mut random).map_err(|_| LegacyMigrationError::Queue(QueueError::Unavailable))?;
    let mut token = String::with_capacity(40);
    token.push_str("migrate:");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut token, "{byte:02x}")
            .map_err(|_| LegacyMigrationError::Queue(QueueError::Unavailable))?;
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frozen_archive_and_status_shapes() {
        let now = DateTime::parse_from_rfc3339("2026-08-07T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let archive = parse_archive(
            r#"{
              "detail":{
                "id":42,"senderAddress":"qa@example.test",
                "recipientsJson":"[\"user@remote.test\"]","subject":"subject",
                "messageId":"<42@example.test>","maxRetries":5,"retryCount":2,
                "sentFileName":"sent.eml","sentSubdirectory":1,
                "messageFilePath":null,"signedContentBase64":null,
                "createdAt":"2026-08-07T00:00:00Z","nextRetryAt":null,
                "lastError":null,"status":"SENT"
              },
              "finalStatus":{
                "taskId":42,"status":"SENT","sentAt":"2026-08-07T00:00:01Z",
                "lastError":null,"retryCount":0,"sentDomainsJson":"[\"remote.test\"]",
                "failedDomainsJson":null,"updatedAt":"2026-08-07T00:00:01Z"
              }
            }"#,
            now,
        )
        .unwrap();
        assert_eq!(archive.materialization.status, DeliveryRowStatus::Sent);
        assert_eq!(archive.materialization.retry_count, 2);
        assert_eq!(
            archive.materialization.sent_at.unwrap().to_rfc3339(),
            "2026-08-07T00:00:01+00:00"
        );

        let status = parse_status(
            r#"{"taskId":42,"status":"FAILED","sentAt":null,"lastError":"failed",
                "retryCount":5,"sentDomainsJson":null,"failedDomainsJson":"{}",
                "updatedAt":"2026-08-07T00:00:02Z"}"#,
            now,
        )
        .unwrap();
        assert_eq!(status.status, DeliveryRowStatus::Failed);
        assert_eq!(status.retry_count, 5);
    }

    #[test]
    fn rejects_mismatched_or_nonterminal_archive_records() {
        let now = Utc::now();
        let mismatch = r#"{
          "detail":{"id":1,"senderAddress":"qa@example.test","recipientsJson":"[]",
            "subject":null,"messageId":"<1@example.test>","maxRetries":1,"retryCount":0,
            "sentFileName":"sent.eml","sentSubdirectory":1,"messageFilePath":null,
            "signedContentBase64":null,"createdAt":null,"nextRetryAt":null,
            "lastError":null,"status":"SENT"},
          "finalStatus":{"taskId":2,"status":"SENT","sentAt":null,"lastError":null,
            "retryCount":0,"sentDomainsJson":null,"failedDomainsJson":null,"updatedAt":null}
        }"#;
        assert_eq!(
            parse_archive(mismatch, now).unwrap_err(),
            "archive-task-mismatch"
        );
    }
}
