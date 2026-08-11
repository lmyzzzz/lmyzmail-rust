use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::File,
    future::Future,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool as PostgresPool;
use deadpool_redis::Pool as RedisPool;
use tokio::{
    sync::{Mutex, Semaphore, oneshot},
    task::{JoinHandle, spawn_blocking},
    time::{MissedTickBehavior, interval, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

#[cfg(not(target_os = "linux"))]
use std::fs;

use crate::{
    config::RuntimeConfig,
    outbound_delivery::{
        CommitResultStatus, DatabaseClaim, DeliveryAttemptId, DeliveryAttemptPhase,
        DeliveryRowStatus, DeliverySnapshot, DeliveryStateError, LegacyProjection,
        OutboundSpoolKind, OutboundSpoolRecord, OutboundSpoolState, PostgresDeliveryState,
        PreparedRecipientCheckpoint, PreparedRecipientStatus, RecipientDeliveryState,
        RecipientLedgerClaim, RecipientLedgerSnapshot, RetryTransition, TerminalStatus,
        legacy_smtp_failure_is_retryable, parse_recipient_roster_json, recipient_domain,
    },
    outbound_queue::{
        ClaimReconciliation, DomainStatus, LegacyOutboundQueue, QueueClaim, QueueError,
        QueueSettlement, SettlementReconciliation, TaskDetail,
    },
    outbound_route::{DeliveryRoute, OutboundRouteResolver, RouteError, RouteErrorKind},
    outbound_smtp::{
        DataStatus, DeliveryError, DeliveryErrorKind, DeliveryPreparation, DeliveryRequest,
        DeliveryResult, MessageSource, OutboundSmtpClient, RecipientResult, RecipientStatus,
    },
    outbound_takeover::{LegacyRedisTakeover, LegacyTakeoverError},
};

const DEFAULT_LEASE_SECONDS: u64 = 90;
const DEFAULT_RENEW_SECONDS: u64 = 10;
const DEFAULT_TASK_DEADLINE_MINUTES: u64 = 10;
const DEFAULT_RETRY_BASE_SECONDS: u64 = 30;
const DEFAULT_RETRY_MAX_SECONDS: u64 = 3_600;
const MAX_TASK_DEADLINE_MINUTES: u64 = 60;
const MAX_RECONCILIATION_ATTEMPTS: usize = 3;
const RECONCILIATION_PAUSE: Duration = Duration::from_millis(25);
const MAX_BASE64_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_DETAIL_BYTES: usize = 2_048;
const MAX_WORKER_ID_BYTES: usize = 64;
const MIN_SAFE_LEASE_SECONDS: u64 = 65;
const SPOOL_CLEANUP_TASKS: usize = 16;
const SPOOL_IO_TIMEOUT: Duration = Duration::from_secs(8);
const FILE_COMPARE_BUFFER_BYTES: usize = 64 * 1024;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait RouteLookup: Send + Sync {
    fn resolve<'a>(
        &'a self,
        recipient_domain: &'a str,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<DeliveryRoute, RouteError>>;
}

impl RouteLookup for OutboundRouteResolver {
    fn resolve<'a>(
        &'a self,
        recipient_domain: &'a str,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<DeliveryRoute, RouteError>> {
        Box::pin(self.resolve(recipient_domain, cancellation))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorConfig {
    pub worker_id: String,
    pub hello_name: String,
    pub lease_duration: Duration,
    pub renew_interval: Duration,
    pub task_deadline: Duration,
    pub retry_base: Duration,
    pub retry_max: Duration,
    pub max_message_bytes: u64,
    pub maildir_base: PathBuf,
    pub spool_dir: PathBuf,
}

impl CoordinatorConfig {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, CoordinatorError> {
        let worker_id = config
            .preferred_value("lmyzmail.queue.worker-id", "botmail.queue.worker-id")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("lmyzmail-{}", std::process::id()));
        let lease_seconds = property_u64(
            config,
            "lmyzmail.queue.lease-seconds",
            "botmail.queue.lease-seconds",
            DEFAULT_LEASE_SECONDS,
        )?;
        let renew_seconds = property_u64(
            config,
            "lmyzmail.queue.renew-seconds",
            "botmail.queue.renew-seconds",
            DEFAULT_RENEW_SECONDS,
        )?;
        let task_deadline_minutes = property_u64(
            config,
            "lmyzmail.queue.processing-timeout-minutes",
            "botmail.queue.processing-timeout-minutes",
            DEFAULT_TASK_DEADLINE_MINUTES,
        )?;
        let retry_base_seconds = property_u64(
            config,
            "lmyzmail.queue.retry-base-seconds",
            "botmail.queue.retry-base-seconds",
            DEFAULT_RETRY_BASE_SECONDS,
        )?;
        let retry_max_seconds = property_u64(
            config,
            "lmyzmail.queue.retry-max-seconds",
            "botmail.queue.retry-max-seconds",
            DEFAULT_RETRY_MAX_SECONDS,
        )?;
        let value = Self {
            worker_id,
            hello_name: config
                .preferred_value(
                    "lmyzmail.outbound.helo-hostname",
                    "botmail.outbound.helo-hostname",
                )
                .unwrap_or(config.domain.as_str())
                .to_owned(),
            lease_duration: Duration::from_secs(lease_seconds),
            renew_interval: Duration::from_secs(renew_seconds),
            task_deadline: Duration::from_secs(task_deadline_minutes.checked_mul(60).ok_or(
                CoordinatorError::Configuration("outbound task deadline is invalid"),
            )?),
            retry_base: Duration::from_secs(retry_base_seconds),
            retry_max: Duration::from_secs(retry_max_seconds),
            max_message_bytes: config.limits.max_email_size_bytes,
            maildir_base: config.maildir.clone(),
            spool_dir: config
                .preferred_value("lmyzmail.outbound.spool-dir", "botmail.outbound.temp-dir")
                .map(PathBuf::from)
                .unwrap_or_else(|| config.maildir.join(".lmyzmail-outbound")),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), CoordinatorError> {
        if self.worker_id.is_empty()
            || self.worker_id.len() > MAX_WORKER_ID_BYTES
            || !self.worker_id.is_ascii()
            || self
                .worker_id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(CoordinatorError::Configuration(
                "outbound worker ID is invalid",
            ));
        }
        if self.hello_name.is_empty()
            || self.hello_name.len() > 253
            || !self.hello_name.is_ascii()
            || self
                .hello_name
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || self.lease_duration < Duration::from_secs(MIN_SAFE_LEASE_SECONDS)
            || self.lease_duration > Duration::from_secs(60 * 60)
            || self.renew_interval.is_zero()
            || self.renew_interval >= self.lease_duration / 2
            || self.task_deadline.is_zero()
            || self.task_deadline > Duration::from_secs(MAX_TASK_DEADLINE_MINUTES * 60)
            || self.retry_base.is_zero()
            || self.retry_base > self.retry_max
            || self.retry_max > Duration::from_secs(24 * 60 * 60)
            || self.max_message_bytes == 0
            || self.max_message_bytes > MAX_BASE64_SOURCE_BYTES as u64
            || self.maildir_base.as_os_str().is_empty()
            || self.spool_dir.as_os_str().is_empty()
        {
            return Err(CoordinatorError::Configuration(
                "outbound coordinator limits are invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct OutboundCoordinator {
    queue: LegacyOutboundQueue,
    state: PostgresDeliveryState,
    routes: Arc<dyn RouteLookup>,
    smtp: Arc<OutboundSmtpClient>,
    takeover: LegacyRedisTakeover,
    spool_cleanup_permits: Arc<Semaphore>,
    removed_spool_cursor: Arc<AtomicI64>,
    config: CoordinatorConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorOutcome {
    Idle,
    Deferred {
        task_id: i64,
    },
    Released {
        task_id: i64,
    },
    Completed {
        task_id: i64,
        projection: LegacyProjection,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueueMaintenanceOutcome {
    pub next_expired_cursor: u64,
    pub moved_retries: usize,
    pub recovered_claims: usize,
    pub terminal_cleanups: usize,
    pub removed_spool_sidecars: usize,
}

#[derive(Debug)]
pub enum CoordinatorError {
    Configuration(&'static str),
    InvalidTask(&'static str),
    Queue(QueueError),
    DeliveryState(DeliveryStateError),
    Takeover(LegacyTakeoverError),
    Reconciliation(&'static str),
    SpoolCleanup(&'static str),
    LeaseLost,
    Cancelled,
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message)
            | Self::InvalidTask(message)
            | Self::Reconciliation(message)
            | Self::SpoolCleanup(message) => formatter.write_str(message),
            Self::Queue(error) => write!(formatter, "outbound Redis state failed: {error}"),
            Self::DeliveryState(error) => {
                write!(formatter, "outbound PostgreSQL state failed: {error}")
            }
            Self::Takeover(error) => write!(formatter, "outbound legacy takeover failed: {error}"),
            Self::LeaseLost => formatter.write_str("outbound delivery lease was lost"),
            Self::Cancelled => formatter.write_str("outbound delivery was cancelled"),
        }
    }
}

impl std::error::Error for CoordinatorError {}

impl From<QueueError> for CoordinatorError {
    fn from(error: QueueError) -> Self {
        Self::Queue(error)
    }
}

impl From<DeliveryStateError> for CoordinatorError {
    fn from(error: DeliveryStateError) -> Self {
        Self::DeliveryState(error)
    }
}

impl From<LegacyTakeoverError> for CoordinatorError {
    fn from(error: LegacyTakeoverError) -> Self {
        Self::Takeover(error)
    }
}

impl OutboundCoordinator {
    pub fn from_config(
        config: &RuntimeConfig,
        postgres_pool: PostgresPool,
        redis_pool: RedisPool,
    ) -> Result<Self, CoordinatorError> {
        let coordinator_config = CoordinatorConfig::from_config(config)?;
        let routes = OutboundRouteResolver::from_config(config, redis_pool.clone())
            .map_err(|_| CoordinatorError::Configuration("outbound route configuration failed"))?;
        Self::with_components(
            coordinator_config,
            LegacyOutboundQueue::new(redis_pool),
            PostgresDeliveryState::new(postgres_pool),
            Arc::new(routes),
            Arc::new(OutboundSmtpClient::default()),
        )
    }

    pub fn with_components(
        config: CoordinatorConfig,
        queue: LegacyOutboundQueue,
        state: PostgresDeliveryState,
        routes: Arc<dyn RouteLookup>,
        smtp: Arc<OutboundSmtpClient>,
    ) -> Result<Self, CoordinatorError> {
        config.validate()?;
        let takeover = LegacyRedisTakeover::new(
            queue.clone(),
            state.clone(),
            config.maildir_base.clone(),
            config.max_message_bytes,
        )?;
        Ok(Self {
            queue,
            state,
            routes,
            smtp,
            takeover,
            spool_cleanup_permits: Arc::new(Semaphore::new(SPOOL_CLEANUP_TASKS)),
            removed_spool_cursor: Arc::new(AtomicI64::new(0)),
            config,
        })
    }

    pub async fn initialize(&self) -> Result<(), CoordinatorError> {
        self.state.initialize_schema().await.map_err(Into::into)
    }

    pub async fn maintain_queue(
        &self,
        expired_cursor: u64,
        limit: usize,
        cancellation: &CancellationToken,
    ) -> Result<QueueMaintenanceOutcome, CoordinatorError> {
        if limit == 0 || limit > 10_000 {
            return Err(CoordinatorError::Configuration(
                "outbound maintenance batch bound is invalid",
            ));
        }
        if cancellation.is_cancelled() {
            return Err(CoordinatorError::Cancelled);
        }
        let now = Utc::now();
        let now_millis = now.timestamp_millis();
        let stale_before = now
            - chrono::Duration::from_std(self.config.task_deadline).map_err(|_| {
                CoordinatorError::Configuration("outbound recovery deadline is invalid")
            })?;
        let moved_retries = self.queue.move_due_retries(now_millis, limit).await?.len();
        let page = self
            .queue
            .scan_stale_expired_claims(expired_cursor, limit, stale_before.timestamp_millis())
            .await?;
        let mut outcome = QueueMaintenanceOutcome {
            next_expired_cursor: page.next_cursor,
            moved_retries,
            recovered_claims: 0,
            terminal_cleanups: 0,
            removed_spool_sidecars: 0,
        };
        for task_id in page.task_ids {
            if cancellation.is_cancelled() {
                return Err(CoordinatorError::Cancelled);
            }
            let before = self.state.snapshot(task_id, None).await?;
            if before
                .as_ref()
                .is_some_and(|snapshot| snapshot.status == DeliveryRowStatus::Processing)
            {
                match self.state.recover_expired(task_id, stale_before, now).await {
                    Ok(_) | Err(DeliveryStateError::OutcomeUnknown) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            let after = self.state.snapshot(task_id, None).await?;
            match after {
                None
                | Some(DeliverySnapshot {
                    status: DeliveryRowStatus::Pending,
                    ..
                }) => {
                    if self.queue.recover_expired_claim(task_id, true).await? {
                        outcome.recovered_claims += 1;
                    }
                }
                Some(snapshot) if snapshot.status.is_terminal() => {
                    if self.queue.recover_expired_claim(task_id, true).await? {
                        outcome.recovered_claims += 1;
                    }
                }
                Some(_) => {}
            }
        }
        for record in self.state.terminal_outbound_spools(limit).await? {
            if cancellation.is_cancelled() {
                return Err(CoordinatorError::Cancelled);
            }
            self.cleanup_owned_spool(record).await?;
            outcome.terminal_cleanups += 1;
        }
        let removed_cursor = self.removed_spool_cursor.load(Ordering::Acquire);
        let removed_records = self
            .state
            .removed_outbound_spools(removed_cursor, limit)
            .await?;
        self.removed_spool_cursor.store(
            removed_records.last().map_or(0, |record| record.task_id),
            Ordering::Release,
        );
        for record in removed_records {
            if cancellation.is_cancelled() {
                return Err(CoordinatorError::Cancelled);
            }
            if self
                .queue
                .terminal_acknowledgement_proven(record.task_id, &record.sent_file_name)
                .await?
            {
                self.delete_removed_spool_reconciled(&record).await?;
                outcome.removed_spool_sidecars += 1;
            }
        }
        Ok(outcome)
    }

    pub async fn process_next(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<CoordinatorOutcome, CoordinatorError> {
        self.process_next_inner(cancellation, None).await
    }

    pub(crate) async fn process_next_with_claim_signal(
        &self,
        cancellation: &CancellationToken,
        claim_signal: oneshot::Sender<bool>,
    ) -> Result<CoordinatorOutcome, CoordinatorError> {
        self.process_next_inner(cancellation, Some(claim_signal))
            .await
    }

    async fn process_next_inner(
        &self,
        cancellation: &CancellationToken,
        claim_signal: Option<oneshot::Sender<bool>>,
    ) -> Result<CoordinatorOutcome, CoordinatorError> {
        if cancellation.is_cancelled() {
            return Err(CoordinatorError::Cancelled);
        }
        let lease_token = DeliveryAttemptId::generate_lease_token(&self.config.worker_id)?;
        let claimed_at = now_epoch_millis()?;
        let Some(queue_claim) = self
            .claim_queue(&lease_token, claimed_at, cancellation)
            .await?
        else {
            if let Some(signal) = claim_signal {
                let _ = signal.send(false);
            }
            return Ok(CoordinatorOutcome::Idle);
        };
        if let Some(signal) = claim_signal {
            let _ = signal.send(true);
        }
        if cancellation.is_cancelled() {
            self.release_queue(&queue_claim, true).await?;
            return Ok(CoordinatorOutcome::Released {
                task_id: queue_claim.task_id,
            });
        }
        let attempt = DeliveryAttemptId::from_lease_token(queue_claim.task_id, &lease_token)?;
        let database_claim = match self.claim_database(&attempt, cancellation).await {
            Ok(Some(claim)) => claim,
            Ok(None) => {
                return self
                    .settle_unclaimable(queue_claim, &attempt, cancellation)
                    .await;
            }
            Err(CoordinatorError::Cancelled) => {
                self.release_queue(&queue_claim, true).await?;
                return Ok(CoordinatorOutcome::Released {
                    task_id: queue_claim.task_id,
                });
            }
            Err(error @ CoordinatorError::DeliveryState(DeliveryStateError::Unavailable)) => {
                self.release_queue(&queue_claim, true).await?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        let work_cancellation = cancellation.child_token();
        let deadline_cancellation = work_cancellation.clone();
        let task_deadline = self.config.task_deadline;
        let deadline_task = tokio::spawn(async move {
            sleep(task_deadline).await;
            deadline_cancellation.cancel();
        });
        let keepalive = Keepalive::start(
            self.queue.clone(),
            self.state.clone(),
            queue_claim.clone(),
            database_claim.clone(),
            self.config.lease_duration,
            self.config.renew_interval,
            work_cancellation.clone(),
        );

        let result = self
            .process_claimed(
                &queue_claim,
                &database_claim,
                &work_cancellation,
                &keepalive,
            )
            .await;
        deadline_task.abort();
        match result {
            Ok(outcome) => {
                keepalive.stop().await?;
                Ok(outcome)
            }
            Err(CoordinatorError::Cancelled) => {
                let release = self
                    .release_cancelled(&queue_claim, &database_claim, keepalive)
                    .await;
                release?;
                Ok(CoordinatorOutcome::Released {
                    task_id: queue_claim.task_id,
                })
            }
            Err(error @ CoordinatorError::SpoolCleanup(_)) => {
                keepalive.stop().await?;
                Err(error)
            }
            Err(error) => {
                match self
                    .release_cancelled(&queue_claim, &database_claim, keepalive)
                    .await
                {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(cleanup),
                }
            }
        }
    }

    async fn claim_queue(
        &self,
        lease_token: &str,
        claimed_at: i64,
        cancellation: &CancellationToken,
    ) -> Result<Option<QueueClaim>, CoordinatorError> {
        if cancellation.is_cancelled() {
            return Err(CoordinatorError::Cancelled);
        }
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self
                .queue
                .claim_next(lease_token, self.config.lease_duration, claimed_at)
                .await
            {
                Ok(claim) => return Ok(claim),
                Err(QueueError::OutcomeUnknown | QueueError::AttemptTokenInUse) => {
                    match self.queue.reconcile_claim(lease_token).await? {
                        ClaimReconciliation::Empty => return Ok(None),
                        ClaimReconciliation::Active(claim) => return Ok(Some(claim.claim)),
                        ClaimReconciliation::NotFound => {
                            sleep(RECONCILIATION_PAUSE).await;
                        }
                        ClaimReconciliation::Inconsistent => {
                            return Err(CoordinatorError::Reconciliation(
                                "Redis claim reconciliation found inconsistent state",
                            ));
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "Redis claim outcome could not be reconciled",
        ))
    }

    async fn process_claimed(
        &self,
        queue_claim: &QueueClaim,
        database_claim: &DatabaseClaim,
        cancellation: &CancellationToken,
        keepalive: &Keepalive,
    ) -> Result<CoordinatorOutcome, CoordinatorError> {
        keepalive.check().await?;
        if cancellation.is_cancelled() {
            return Err(CoordinatorError::Cancelled);
        }
        let roster = match self.state.claimed_recipient_roster(database_claim).await {
            Ok(roster) => roster,
            Err(DeliveryStateError::InvalidTransition(_)) => {
                return self
                    .terminalize_invalid_roster(queue_claim, database_claim, keepalive)
                    .await;
            }
            Err(error) => return Err(error.into()),
        };
        let ledger_claim = self
            .begin_ledger_reconciled(database_claim, &roster)
            .await?;
        let mut ledger = self
            .state
            .ledger_snapshot(database_claim.task_id, Some(&ledger_claim))
            .await?
            .ok_or(CoordinatorError::Reconciliation(
                "delivery ledger disappeared after begin_attempt",
            ))?;
        validate_owned_ledger(&ledger, &ledger_claim)?;

        let task = match queue_claim.task.as_ref() {
            Some(task) => task,
            None => {
                self.checkpoint_local_failure(
                    &ledger_claim,
                    &ledger,
                    "Redis outbound task detail is missing",
                )
                .await?;
                return self
                    .project_and_finalize(
                        queue_claim,
                        database_claim,
                        &ledger_claim,
                        None,
                        None,
                        keepalive,
                    )
                    .await;
            }
        };
        let envelope_from = if self.state.is_dsn_task(database_claim.task_id).await? {
            ""
        } else {
            task.sender_address.as_str()
        };
        let domain_rosters = match validate_task_rosters(
            task,
            database_claim.task_id,
            database_claim.retry_count,
            database_claim.max_retries,
            &roster,
        ) {
            Ok(rosters) => rosters,
            Err(message) => {
                self.checkpoint_local_failure(&ledger_claim, &ledger, message)
                    .await?;
                return self
                    .project_and_finalize(
                        queue_claim,
                        database_claim,
                        &ledger_claim,
                        Some(task),
                        None,
                        keepalive,
                    )
                    .await;
            }
        };
        let expected_domains: BTreeSet<String> = domain_rosters.keys().cloned().collect();
        let domain_statuses = match self
            .queue
            .read_domain_statuses(queue_claim, &expected_domains)
            .await
        {
            Ok(statuses) if domain_status_rosters_match(&statuses, &domain_rosters) => statuses,
            Ok(_) | Err(QueueError::MissingDomainStatuses | QueueError::CorruptDomainStatuses) => {
                self.checkpoint_local_failure(
                    &ledger_claim,
                    &ledger,
                    "Redis outbound domain roster is corrupt",
                )
                .await?;
                return self
                    .project_and_finalize(
                        queue_claim,
                        database_claim,
                        &ledger_claim,
                        Some(task),
                        None,
                        keepalive,
                    )
                    .await;
            }
            Err(QueueError::StaleClaim) => return Err(CoordinatorError::LeaseLost),
            Err(error) => return Err(error.into()),
        };
        let message = match message_source(task, self.config.max_message_bytes) {
            Ok(message) => message,
            Err(message) => {
                self.checkpoint_local_failure(&ledger_claim, &ledger, message)
                    .await?;
                return self
                    .project_and_finalize(
                        queue_claim,
                        database_claim,
                        &ledger_claim,
                        Some(task),
                        Some(&domain_statuses),
                        keepalive,
                    )
                    .await;
            }
        };

        let retryable_domains = retryable_domain_rosters(&ledger)?;
        for (domain_index, (domain, recipients)) in retryable_domains.iter().enumerate() {
            keepalive.check().await?;
            if cancellation.is_cancelled() {
                return Err(CoordinatorError::Cancelled);
            }
            match self
                .deliver_domain(
                    &ledger_claim,
                    &ledger,
                    domain,
                    recipients,
                    DomainDeliveryContext {
                        envelope_from,
                        message: &message,
                        cancellation,
                    },
                )
                .await?
            {
                DomainDelivery::Complete => {}
                DomainDelivery::Cancelled => return Err(CoordinatorError::Cancelled),
                DomainDelivery::Ambiguous => {
                    if domain_index + 1 < retryable_domains.len() {
                        self.checkpoint_unsent_domains(
                            &ledger_claim,
                            &ledger,
                            &retryable_domains[domain_index + 1..],
                        )
                        .await?;
                    }
                    break;
                }
            }
            ledger = self
                .state
                .ledger_snapshot(database_claim.task_id, Some(&ledger_claim))
                .await?
                .ok_or(CoordinatorError::Reconciliation(
                    "delivery ledger disappeared between recipient domains",
                ))?;
        }
        self.project_and_finalize(
            queue_claim,
            database_claim,
            &ledger_claim,
            Some(task),
            Some(&domain_statuses),
            keepalive,
        )
        .await
    }

    async fn terminalize_invalid_roster(
        &self,
        queue_claim: &QueueClaim,
        database_claim: &DatabaseClaim,
        keepalive: &Keepalive,
    ) -> Result<CoordinatorOutcome, CoordinatorError> {
        let mut durable = false;
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self
                .state
                .mark_terminal(
                    database_claim,
                    TerminalStatus::Failed,
                    &[],
                    &BTreeMap::new(),
                    Some("PostgreSQL outbound recipient roster is invalid"),
                    Utc::now(),
                )
                .await
            {
                Ok(true) => {
                    durable = true;
                    break;
                }
                Ok(false) | Err(DeliveryStateError::OutcomeUnknown) => {
                    let snapshot = self
                        .state
                        .snapshot(database_claim.task_id, Some(database_claim))
                        .await?;
                    if snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot.status == DeliveryRowStatus::Failed && !snapshot.has_owner
                    }) {
                        durable = true;
                        break;
                    }
                    if snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot.status == DeliveryRowStatus::Processing && snapshot.owned_by_claim
                    }) {
                        sleep(RECONCILIATION_PAUSE).await;
                        continue;
                    }
                    return Err(CoordinatorError::LeaseLost);
                }
                Err(error) => return Err(error.into()),
            }
        }
        if !durable {
            return Err(CoordinatorError::Reconciliation(
                "invalid recipient roster terminal state could not be reconciled",
            ));
        }
        keepalive.database_finished();
        self.renew_queue_claim(queue_claim).await?;
        keepalive.quiesce().await?;
        self.acknowledge_queue(queue_claim).await?;
        Ok(CoordinatorOutcome::Completed {
            task_id: queue_claim.task_id,
            projection: LegacyProjection::Terminal(TerminalStatus::Failed),
        })
    }

    async fn begin_ledger_reconciled(
        &self,
        database_claim: &DatabaseClaim,
        roster: &[String],
    ) -> Result<RecipientLedgerClaim, CoordinatorError> {
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self
                .state
                .begin_attempt(database_claim, roster, Utc::now())
                .await
            {
                Ok(claim) => return Ok(claim),
                Err(DeliveryStateError::OutcomeUnknown) => {
                    if let Some(claim) = self.state.resume_attempt(database_claim, roster).await? {
                        return Ok(claim);
                    }
                    let legacy = self
                        .state
                        .snapshot(database_claim.task_id, Some(database_claim))
                        .await?;
                    if !legacy.is_some_and(|snapshot| {
                        snapshot.status == DeliveryRowStatus::Processing && snapshot.owned_by_claim
                    }) {
                        return Err(CoordinatorError::LeaseLost);
                    }
                    sleep(RECONCILIATION_PAUSE).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "begin_attempt could not be reconciled",
        ))
    }

    async fn checkpoint_local_failure(
        &self,
        claim: &RecipientLedgerClaim,
        ledger: &RecipientLedgerSnapshot,
        detail: &str,
    ) -> Result<(), CoordinatorError> {
        let detail = bounded_detail(detail);
        let outcomes: Vec<PreparedRecipientCheckpoint> = ledger
            .retryable_recipients()
            .into_iter()
            .map(|recipient| PreparedRecipientCheckpoint {
                ordinal: recipient.ordinal,
                recipient: recipient.recipient.clone(),
                status: PreparedRecipientStatus::Permanent,
                smtp_code: 550,
                detail: detail.clone(),
            })
            .collect();
        if outcomes.is_empty() {
            return Ok(());
        }
        self.checkpoint_prepared_reconciled(claim, ledger, &outcomes)
            .await
            .map(|_| ())
    }

    async fn checkpoint_unsent_domains(
        &self,
        claim: &RecipientLedgerClaim,
        ledger: &RecipientLedgerSnapshot,
        domains: &[(String, Vec<DomainRecipient>)],
    ) -> Result<(), CoordinatorError> {
        let outcomes = domains
            .iter()
            .flat_map(|(_, recipients)| recipients)
            .filter(|recipient| {
                ledger.recipients.iter().any(|entry| {
                    entry.ordinal == recipient.ordinal
                        && matches!(
                            entry.state,
                            RecipientDeliveryState::Pending | RecipientDeliveryState::Retryable
                        )
                })
            })
            .map(|recipient| PreparedRecipientCheckpoint {
                ordinal: recipient.ordinal,
                recipient: recipient.address.clone(),
                status: PreparedRecipientStatus::Retryable,
                smtp_code: 451,
                detail: "delivery cancelled after an ambiguous recipient domain".into(),
            })
            .collect::<Vec<_>>();
        if outcomes.is_empty() {
            return Ok(());
        }
        self.checkpoint_prepared_reconciled(claim, ledger, &outcomes)
            .await
            .map(|_| ())
    }

    async fn deliver_domain(
        &self,
        ledger_claim: &RecipientLedgerClaim,
        ledger: &RecipientLedgerSnapshot,
        domain: &str,
        recipients: &[DomainRecipient],
        context: DomainDeliveryContext<'_>,
    ) -> Result<DomainDelivery, CoordinatorError> {
        let route = match self.routes.resolve(domain, context.cancellation).await {
            Ok(route) => route,
            Err(error) if error.kind == RouteErrorKind::Cancelled => {
                return Ok(DomainDelivery::Cancelled);
            }
            Err(error) => {
                let status = if matches!(
                    error.kind,
                    RouteErrorKind::Configuration | RouteErrorKind::Permanent
                ) {
                    PreparedRecipientStatus::Permanent
                } else {
                    PreparedRecipientStatus::Retryable
                };
                let outcomes = uniform_outcomes(recipients, status, &error.message);
                self.checkpoint_prepared_reconciled(ledger_claim, ledger, &outcomes)
                    .await?;
                return Ok(DomainDelivery::Complete);
            }
        };
        if route.recipient_domain != domain || route.candidates.is_empty() {
            let outcomes = uniform_outcomes(
                recipients,
                PreparedRecipientStatus::Permanent,
                "outbound route returned an invalid recipient domain",
            );
            self.checkpoint_prepared_reconciled(ledger_claim, ledger, &outcomes)
                .await?;
            return Ok(DomainDelivery::Complete);
        }

        let addresses: Vec<String> = recipients
            .iter()
            .map(|recipient| recipient.address.clone())
            .collect();
        let mut last_failure = None;
        for candidate in route.candidates {
            if context.cancellation.is_cancelled() {
                return Ok(DomainDelivery::Cancelled);
            }
            let request = DeliveryRequest {
                endpoint: candidate.endpoint,
                hello_name: self.config.hello_name.clone(),
                envelope_from: context.envelope_from.to_owned(),
                recipients: addresses.clone(),
                message: context.message.clone(),
                tls_mode: route.tls_mode,
                max_message_bytes: self.config.max_message_bytes,
            };
            match self.smtp.prepare(&request, context.cancellation).await {
                Ok(DeliveryPreparation::Complete(result)) => {
                    let outcomes = complete_delivery_outcomes(recipients, &result)?;
                    self.checkpoint_prepared_reconciled(ledger_claim, ledger, &outcomes)
                        .await?;
                    return Ok(DomainDelivery::Complete);
                }
                Ok(DeliveryPreparation::CommitReady(prepared)) => {
                    let outcomes = recipient_outcomes(
                        recipients,
                        prepared.recipients(),
                        AcceptedDisposition::Arm,
                        "SMTP recipient result is incomplete",
                    )?;
                    let armed = self
                        .checkpoint_prepared_reconciled(ledger_claim, ledger, &outcomes)
                        .await?;
                    if !armed {
                        return Err(CoordinatorError::Reconciliation(
                            "SMTP transaction was ready but no recipient was commit-armed",
                        ));
                    }
                    match prepared.commit().await {
                        Ok(result) => {
                            let (status, code, detail) = commit_outcome(&result)?;
                            self.checkpoint_result_reconciled(ledger_claim, status, code, &detail)
                                .await?;
                            return Ok(DomainDelivery::Complete);
                        }
                        Err(error) => {
                            self.checkpoint_ambiguous_reconciled(
                                ledger_claim,
                                &bounded_detail(&error.message),
                            )
                            .await?;
                            return Ok(DomainDelivery::Ambiguous);
                        }
                    }
                }
                Err(error) if error.kind == DeliveryErrorKind::Cancelled => {
                    return Ok(DomainDelivery::Cancelled);
                }
                Err(error) if error.kind == DeliveryErrorKind::Ambiguous => {
                    let outcomes = recipient_outcomes(
                        recipients,
                        &error.recipients,
                        AcceptedDisposition::ArmMissing,
                        &error.message,
                    )?;
                    let armed = self
                        .checkpoint_prepared_reconciled(ledger_claim, ledger, &outcomes)
                        .await?;
                    if !armed {
                        return Err(CoordinatorError::Reconciliation(
                            "ambiguous SMTP preparation did not arm a recipient",
                        ));
                    }
                    self.checkpoint_ambiguous_reconciled(
                        ledger_claim,
                        &bounded_detail(&error.message),
                    )
                    .await?;
                    return Ok(DomainDelivery::Ambiguous);
                }
                Err(error) => last_failure = Some(error),
            }
        }
        let failure = last_failure.ok_or(CoordinatorError::Reconciliation(
            "outbound route had no usable SMTP candidate",
        ))?;
        let status = delivery_failure_status(&failure);
        let outcomes = recipient_outcomes(
            recipients,
            &failure.recipients,
            AcceptedDisposition::Fail(status),
            &failure.message,
        )?;
        self.checkpoint_prepared_reconciled(ledger_claim, ledger, &outcomes)
            .await?;
        Ok(DomainDelivery::Complete)
    }

    async fn checkpoint_prepared_reconciled(
        &self,
        claim: &RecipientLedgerClaim,
        prior: &RecipientLedgerSnapshot,
        outcomes: &[PreparedRecipientCheckpoint],
    ) -> Result<bool, CoordinatorError> {
        let expected_armed = outcomes
            .iter()
            .any(|outcome| outcome.status == PreparedRecipientStatus::Accepted);
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self
                .state
                .checkpoint_prepared(claim, outcomes, Utc::now())
                .await
            {
                Ok(armed) if armed == expected_armed => return Ok(armed),
                Ok(_) => {
                    return Err(CoordinatorError::Reconciliation(
                        "prepared checkpoint returned an inconsistent barrier state",
                    ));
                }
                Err(DeliveryStateError::OutcomeUnknown) => {
                    let snapshot = self
                        .state
                        .ledger_snapshot(claim.task_id(), Some(claim))
                        .await?
                        .ok_or(CoordinatorError::Reconciliation(
                            "prepared checkpoint ledger disappeared",
                        ))?;
                    if prepared_checkpoint_matches(&snapshot, claim, outcomes) {
                        return Ok(expected_armed);
                    }
                    if ledger_checkpoint_unchanged(&snapshot, prior, outcomes) {
                        sleep(RECONCILIATION_PAUSE).await;
                        continue;
                    }
                    return Err(CoordinatorError::Reconciliation(
                        "prepared checkpoint outcome is inconsistent",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "prepared checkpoint could not be reconciled",
        ))
    }

    async fn checkpoint_result_reconciled(
        &self,
        claim: &RecipientLedgerClaim,
        status: CommitResultStatus,
        smtp_code: u16,
        detail: &str,
    ) -> Result<(), CoordinatorError> {
        let detail = bounded_detail(detail);
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            let before = self
                .state
                .ledger_snapshot(claim.task_id(), Some(claim))
                .await?
                .ok_or(CoordinatorError::Reconciliation(
                    "commit result ledger disappeared",
                ))?;
            match self
                .state
                .checkpoint_result(claim, status, smtp_code, &detail, Utc::now())
                .await
            {
                Ok(updated) if updated > 0 => return Ok(()),
                Ok(_) => {
                    return Err(CoordinatorError::Reconciliation(
                        "commit result checkpoint updated no recipients",
                    ));
                }
                Err(DeliveryStateError::OutcomeUnknown) => {
                    let snapshot = self
                        .state
                        .ledger_snapshot(claim.task_id(), Some(claim))
                        .await?
                        .ok_or(CoordinatorError::Reconciliation(
                            "commit result ledger disappeared",
                        ))?;
                    if commit_checkpoint_matches(
                        &before, &snapshot, claim, status, smtp_code, &detail,
                    ) {
                        return Ok(());
                    }
                    if commit_barrier_unchanged(&before, &snapshot) {
                        sleep(RECONCILIATION_PAUSE).await;
                        continue;
                    }
                    return Err(CoordinatorError::Reconciliation(
                        "commit result checkpoint outcome is inconsistent",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "commit result checkpoint could not be reconciled",
        ))
    }

    async fn checkpoint_ambiguous_reconciled(
        &self,
        claim: &RecipientLedgerClaim,
        detail: &str,
    ) -> Result<(), CoordinatorError> {
        let detail = bounded_detail(detail);
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            let before = self
                .state
                .ledger_snapshot(claim.task_id(), Some(claim))
                .await?
                .ok_or(CoordinatorError::Reconciliation(
                    "ambiguous checkpoint ledger disappeared",
                ))?;
            match self
                .state
                .checkpoint_ambiguous(claim, &detail, Utc::now())
                .await
            {
                Ok(updated) if updated > 0 => return Ok(()),
                Ok(_) => {
                    return Err(CoordinatorError::Reconciliation(
                        "ambiguous checkpoint updated no recipients",
                    ));
                }
                Err(DeliveryStateError::OutcomeUnknown) => {
                    let snapshot = self
                        .state
                        .ledger_snapshot(claim.task_id(), Some(claim))
                        .await?
                        .ok_or(CoordinatorError::Reconciliation(
                            "ambiguous checkpoint ledger disappeared",
                        ))?;
                    if ambiguous_checkpoint_matches(&before, &snapshot, claim, &detail) {
                        return Ok(());
                    }
                    if commit_barrier_unchanged(&before, &snapshot) {
                        sleep(RECONCILIATION_PAUSE).await;
                        continue;
                    }
                    return Err(CoordinatorError::Reconciliation(
                        "ambiguous checkpoint outcome is inconsistent",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "ambiguous checkpoint could not be reconciled",
        ))
    }

    async fn project_and_finalize(
        &self,
        queue_claim: &QueueClaim,
        database_claim: &DatabaseClaim,
        ledger_claim: &RecipientLedgerClaim,
        task: Option<&TaskDetail>,
        prior_domain_statuses: Option<&BTreeMap<String, DomainStatus>>,
        keepalive: &Keepalive,
    ) -> Result<CoordinatorOutcome, CoordinatorError> {
        let ledger = self
            .state
            .ledger_snapshot(database_claim.task_id, Some(ledger_claim))
            .await?
            .ok_or(CoordinatorError::Reconciliation(
                "delivery ledger disappeared before projection",
            ))?;
        validate_owned_ledger(&ledger, ledger_claim)?;
        if ledger.phase == DeliveryAttemptPhase::CommitArmed
            || ledger.recipients.iter().any(|recipient| {
                matches!(
                    recipient.state,
                    RecipientDeliveryState::Pending | RecipientDeliveryState::CommitArmed
                )
            })
        {
            return Err(CoordinatorError::Reconciliation(
                "delivery projection was attempted before every recipient was durable",
            ));
        }
        let now = Utc::now();
        let retry_at = now
            + chrono::Duration::from_std(retry_delay(
                database_claim.retry_count,
                self.config.retry_base,
                self.config.retry_max,
            ))
            .map_err(|_| CoordinatorError::Configuration("retry delay is outside UTC range"))?;
        let projection = self
            .project_legacy_reconciled(ledger_claim, retry_at)
            .await?;
        keepalive.database_finished();

        let final_ledger = self
            .state
            .ledger_snapshot(database_claim.task_id, None)
            .await?
            .ok_or(CoordinatorError::Reconciliation(
                "projected delivery ledger disappeared",
            ))?;
        if final_ledger.phase != DeliveryAttemptPhase::Projected || final_ledger.has_owner {
            return Err(CoordinatorError::Reconciliation(
                "delivery ledger is not durably projected",
            ));
        }
        let legacy = self
            .state
            .snapshot_attempt(&DeliveryAttemptId::from_lease_token(
                database_claim.task_id,
                &queue_claim.lease_token,
            )?)
            .await?
            .ok_or(CoordinatorError::Reconciliation(
                "projected legacy delivery row disappeared",
            ))?;
        if let Some(prior) = prior_domain_statuses {
            let updates = project_domain_statuses(prior, &final_ledger, Utc::now())?;
            self.update_domain_statuses_reconciled(queue_claim, prior, &updates)
                .await?;
        }

        self.renew_queue_claim(queue_claim).await?;
        keepalive.quiesce().await?;
        match &projection {
            LegacyProjection::RetryScheduled(_) => {
                let task = task.ok_or(CoordinatorError::InvalidTask(
                    "retry projection has no Redis task detail",
                ))?;
                let retry_task = projected_retry_task(task, &legacy)?;
                self.schedule_queue_retry(
                    queue_claim,
                    &retry_task,
                    legacy.next_retry_at.timestamp_millis(),
                )
                .await?;
            }
            LegacyProjection::Terminal(_) | LegacyProjection::Ambiguous => {
                self.acknowledge_queue(queue_claim).await?;
            }
        }
        Ok(CoordinatorOutcome::Completed {
            task_id: queue_claim.task_id,
            projection,
        })
    }

    async fn project_legacy_reconciled(
        &self,
        claim: &RecipientLedgerClaim,
        retry_at: DateTime<Utc>,
    ) -> Result<LegacyProjection, CoordinatorError> {
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self
                .state
                .project_legacy(claim, Some(retry_at), Utc::now())
                .await
            {
                Ok(projection) => return Ok(projection),
                Err(DeliveryStateError::OutcomeUnknown) => {
                    let ledger = self
                        .state
                        .ledger_snapshot(claim.task_id(), None)
                        .await?
                        .ok_or(CoordinatorError::Reconciliation(
                            "projection reconciliation lost the delivery ledger",
                        ))?;
                    let legacy = self.state.snapshot(claim.task_id(), None).await?.ok_or(
                        CoordinatorError::Reconciliation(
                            "projection reconciliation lost the legacy row",
                        ),
                    )?;
                    if let Some(projection) = infer_projection(&ledger, &legacy) {
                        return Ok(projection);
                    }
                    if ledger.phase == DeliveryAttemptPhase::Preparing
                        && ledger.owned_by_claim
                        && legacy.status == DeliveryRowStatus::Processing
                        && legacy.has_owner
                    {
                        sleep(RECONCILIATION_PAUSE).await;
                        continue;
                    }
                    return Err(CoordinatorError::Reconciliation(
                        "legacy projection outcome is inconsistent",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "legacy projection could not be reconciled",
        ))
    }

    async fn update_domain_statuses_reconciled(
        &self,
        queue_claim: &QueueClaim,
        prior: &BTreeMap<String, DomainStatus>,
        updates: &BTreeMap<String, DomainStatus>,
    ) -> Result<(), CoordinatorError> {
        let expected: BTreeSet<String> = prior.keys().cloned().collect();
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self
                .queue
                .update_domain_statuses(queue_claim, &expected, updates)
                .await
            {
                Ok(()) => return Ok(()),
                Err(QueueError::OutcomeUnknown) => {
                    let current = self
                        .queue
                        .read_domain_statuses(queue_claim, &expected)
                        .await?;
                    if updates
                        .iter()
                        .all(|(domain, status)| current.get(domain) == Some(status))
                    {
                        return Ok(());
                    }
                    if current == *prior {
                        sleep(RECONCILIATION_PAUSE).await;
                        continue;
                    }
                    return Err(CoordinatorError::Reconciliation(
                        "Redis domain status mutation outcome is inconsistent",
                    ));
                }
                Err(QueueError::StaleClaim) => return Err(CoordinatorError::LeaseLost),
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "Redis domain status update could not be reconciled",
        ))
    }

    async fn claim_database(
        &self,
        attempt: &DeliveryAttemptId,
        cancellation: &CancellationToken,
    ) -> Result<Option<DatabaseClaim>, CoordinatorError> {
        let mut outcome_unknown = false;
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            if cancellation.is_cancelled() {
                return if outcome_unknown {
                    Err(CoordinatorError::Reconciliation(
                        "PostgreSQL claim remains unknown after cancellation",
                    ))
                } else {
                    Err(CoordinatorError::Cancelled)
                };
            }
            match self.state.claim_with_attempt(attempt, Utc::now()).await {
                Ok(Some(claim)) => return Ok(Some(claim)),
                Ok(None) if !outcome_unknown => return Ok(None),
                Ok(None) | Err(DeliveryStateError::OutcomeUnknown) => {
                    outcome_unknown = true;
                    match self.state.reconcile_attempt_claim(attempt).await {
                        Ok(Some(claim)) => return Ok(Some(claim)),
                        Ok(None) => sleep(RECONCILIATION_PAUSE).await,
                        Err(_) => sleep(RECONCILIATION_PAUSE).await,
                    }
                }
                Err(_) if outcome_unknown => sleep(RECONCILIATION_PAUSE).await,
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "PostgreSQL claim outcome could not be reconciled",
        ))
    }

    async fn settle_unclaimable(
        &self,
        queue_claim: QueueClaim,
        attempt: &DeliveryAttemptId,
        cancellation: &CancellationToken,
    ) -> Result<CoordinatorOutcome, CoordinatorError> {
        let snapshot = self.state.snapshot_attempt(attempt).await?;
        let task_id = queue_claim.task_id;
        match snapshot {
            None => {
                if cancellation.is_cancelled() {
                    self.release_queue(&queue_claim, true).await?;
                    return Ok(CoordinatorOutcome::Released { task_id });
                }
                match self.takeover.materialize(&queue_claim, cancellation).await {
                    Ok(_) => {
                        self.release_queue(&queue_claim, true).await?;
                        Ok(CoordinatorOutcome::Released { task_id })
                    }
                    Err(LegacyTakeoverError::Cancelled) => {
                        self.release_queue(&queue_claim, true).await?;
                        Ok(CoordinatorOutcome::Released { task_id })
                    }
                    Err(error) => {
                        self.release_queue(&queue_claim, true).await?;
                        Err(error.into())
                    }
                }
            }
            Some(snapshot)
                if matches!(
                    snapshot.status,
                    DeliveryRowStatus::Sent
                        | DeliveryRowStatus::PartialSuccess
                        | DeliveryRowStatus::Failed
                        | DeliveryRowStatus::Cancelled
                ) =>
            {
                self.reconcile_projected_domain_statuses(&queue_claim, &snapshot)
                    .await?;
                self.acknowledge_queue(&queue_claim).await?;
                let status = match snapshot.status {
                    DeliveryRowStatus::Sent => TerminalStatus::Sent,
                    DeliveryRowStatus::PartialSuccess => TerminalStatus::PartialSuccess,
                    DeliveryRowStatus::Failed | DeliveryRowStatus::Cancelled => {
                        TerminalStatus::Failed
                    }
                    DeliveryRowStatus::Pending | DeliveryRowStatus::Processing => unreachable!(),
                };
                Ok(CoordinatorOutcome::Completed {
                    task_id,
                    projection: LegacyProjection::Terminal(status),
                })
            }
            Some(snapshot) if snapshot.status == DeliveryRowStatus::Pending => {
                if cancellation.is_cancelled() {
                    self.release_queue(&queue_claim, true).await?;
                    return Ok(CoordinatorOutcome::Released { task_id });
                }
                let Some(mut task) = queue_claim.task.clone() else {
                    self.release_queue(&queue_claim, false).await?;
                    return Ok(CoordinatorOutcome::Deferred { task_id });
                };
                if snapshot.next_retry_at <= Utc::now() || task.validate().is_err() {
                    self.release_queue(&queue_claim, true).await?;
                    return Ok(CoordinatorOutcome::Released { task_id });
                }
                self.reconcile_projected_domain_statuses(&queue_claim, &snapshot)
                    .await?;
                task.retry_count = snapshot.retry_count;
                task.max_retries = snapshot.max_retries;
                task.next_retry_at = Some(instant(snapshot.next_retry_at));
                task.last_error = snapshot.last_error;
                task.status = "PENDING".into();
                self.schedule_queue_retry(
                    &queue_claim,
                    &task,
                    snapshot.next_retry_at.timestamp_millis(),
                )
                .await?;
                Ok(CoordinatorOutcome::Deferred { task_id })
            }
            Some(_) => {
                self.release_queue(&queue_claim, false).await?;
                Ok(CoordinatorOutcome::Deferred { task_id })
            }
        }
    }

    async fn reconcile_projected_domain_statuses(
        &self,
        queue_claim: &QueueClaim,
        legacy: &DeliverySnapshot,
    ) -> Result<(), CoordinatorError> {
        let Some(task) = queue_claim.task.as_ref() else {
            return Ok(());
        };
        let Some(ledger) = self
            .state
            .ledger_snapshot(queue_claim.task_id, None)
            .await?
        else {
            return Ok(());
        };
        if ledger.phase != DeliveryAttemptPhase::Projected || ledger.has_owner {
            return Err(CoordinatorError::Reconciliation(
                "Redis settlement was attempted before the delivery ledger was projected",
            ));
        }
        let roster: Vec<String> = ledger
            .recipients
            .iter()
            .map(|recipient| recipient.recipient.clone())
            .collect();
        let domain_rosters = validate_task_rosters(
            task,
            queue_claim.task_id,
            task.retry_count,
            legacy.max_retries,
            &roster,
        )
        .map_err(CoordinatorError::InvalidTask)?;
        let expected: BTreeSet<String> = domain_rosters.keys().cloned().collect();
        let prior = self
            .queue
            .read_domain_statuses(queue_claim, &expected)
            .await?;
        if !domain_status_rosters_match(&prior, &domain_rosters) {
            return Err(CoordinatorError::Reconciliation(
                "Redis outbound domain roster is corrupt during settlement",
            ));
        }
        let updates = project_domain_statuses(&prior, &ledger, Utc::now())?;
        self.update_domain_statuses_reconciled(queue_claim, &prior, &updates)
            .await
    }

    async fn release_cancelled(
        &self,
        queue_claim: &QueueClaim,
        database_claim: &DatabaseClaim,
        keepalive: Keepalive,
    ) -> Result<(), CoordinatorError> {
        let database_release = self.release_database(database_claim).await;
        keepalive.database_finished();
        let queue_renewal = if database_release.is_ok() {
            self.renew_queue_claim(queue_claim).await
        } else {
            Ok(())
        };
        let quiesce = keepalive.quiesce().await;
        database_release?;
        queue_renewal?;
        quiesce?;
        let snapshot = self
            .state
            .snapshot(database_claim.task_id, Some(database_claim))
            .await?;
        match snapshot {
            Some(snapshot)
                if snapshot.status == DeliveryRowStatus::Pending
                    && snapshot.retry_count > database_claim.retry_count =>
            {
                let Some(task) = queue_claim.task.as_ref() else {
                    return self.release_queue(queue_claim, false).await;
                };
                let task = projected_retry_task(task, &snapshot)?;
                self.schedule_queue_retry(
                    queue_claim,
                    &task,
                    snapshot.next_retry_at.timestamp_millis(),
                )
                .await
            }
            Some(snapshot) if snapshot.status == DeliveryRowStatus::Pending => {
                self.release_queue(queue_claim, true).await
            }
            Some(snapshot) if snapshot.status.is_terminal() => {
                self.reconcile_projected_domain_statuses(queue_claim, &snapshot)
                    .await?;
                self.acknowledge_queue(queue_claim).await
            }
            _ => self.acknowledge_queue(queue_claim).await,
        }
    }

    async fn release_database(&self, claim: &DatabaseClaim) -> Result<(), CoordinatorError> {
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self.state.release(claim, Utc::now()).await {
                Ok(true) => return Ok(()),
                Ok(false) | Err(DeliveryStateError::OutcomeUnknown) => {
                    let legacy = self.state.snapshot(claim.task_id, Some(claim)).await?;
                    let ledger = self.state.ledger_snapshot(claim.task_id, None).await?;
                    if release_is_durable(legacy.as_ref(), ledger.as_ref()) {
                        return Ok(());
                    }
                    if legacy.as_ref().is_some_and(|snapshot| {
                        snapshot.status == DeliveryRowStatus::Processing && snapshot.owned_by_claim
                    }) {
                        sleep(RECONCILIATION_PAUSE).await;
                        continue;
                    }
                    return Err(CoordinatorError::LeaseLost);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "PostgreSQL release could not be reconciled",
        ))
    }

    async fn renew_queue_claim(&self, claim: &QueueClaim) -> Result<(), CoordinatorError> {
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            let renewed_at = now_epoch_millis()?;
            match self
                .queue
                .renew_claim(claim, self.config.lease_duration, renewed_at)
                .await
            {
                Ok(true) => return Ok(()),
                Ok(false) => return Err(CoordinatorError::LeaseLost),
                Err(QueueError::OutcomeUnknown) => {
                    match self.queue.reconcile_claim(&claim.lease_token).await? {
                        ClaimReconciliation::Active(reconciled)
                            if reconciled.claim.task_id == claim.task_id
                                && reconciled.processing_time_epoch_millis >= renewed_at =>
                        {
                            return Ok(());
                        }
                        ClaimReconciliation::Active(_) => {
                            sleep(RECONCILIATION_PAUSE).await;
                        }
                        ClaimReconciliation::NotFound => {
                            return Err(CoordinatorError::LeaseLost);
                        }
                        ClaimReconciliation::Empty | ClaimReconciliation::Inconsistent => {
                            return Err(CoordinatorError::Reconciliation(
                                "Redis lease renewal reconciliation found inconsistent state",
                            ));
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "Redis lease renewal could not be reconciled",
        ))
    }

    async fn release_queue(
        &self,
        claim: &QueueClaim,
        requeue: bool,
    ) -> Result<(), CoordinatorError> {
        let settlement = QueueSettlement::Release { requeue };
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self.queue.release_claim(claim, requeue).await {
                Ok(true) | Err(QueueError::OutcomeUnknown) => {
                    match self.queue.reconcile_settlement(claim, settlement).await? {
                        SettlementReconciliation::Applied => return Ok(()),
                        SettlementReconciliation::Active => {
                            sleep(RECONCILIATION_PAUSE).await;
                        }
                        SettlementReconciliation::NotFound => {
                            return Err(CoordinatorError::LeaseLost);
                        }
                        SettlementReconciliation::Inconsistent => {
                            return Err(CoordinatorError::Reconciliation(
                                "Redis release postcondition is inconsistent",
                            ));
                        }
                    }
                }
                Ok(false) => return Err(CoordinatorError::LeaseLost),
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "Redis release could not be reconciled",
        ))
    }

    async fn acknowledge_queue(&self, claim: &QueueClaim) -> Result<(), CoordinatorError> {
        if let Err(error) = self.cleanup_terminal_spool(claim).await {
            self.release_queue(claim, true).await?;
            return Err(error);
        }
        let settlement = QueueSettlement::Acknowledge;
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self.queue.acknowledge(claim).await {
                Ok(true) | Err(QueueError::OutcomeUnknown) => {
                    match self.queue.reconcile_settlement(claim, settlement).await? {
                        SettlementReconciliation::Applied => {
                            self.delete_acknowledged_spool_sidecar(claim.task_id)
                                .await?;
                            return Ok(());
                        }
                        SettlementReconciliation::Active => {
                            sleep(RECONCILIATION_PAUSE).await;
                        }
                        SettlementReconciliation::NotFound => {
                            return Err(CoordinatorError::LeaseLost);
                        }
                        SettlementReconciliation::Inconsistent => {
                            return Err(CoordinatorError::Reconciliation(
                                "Redis acknowledgement postcondition is inconsistent",
                            ));
                        }
                    }
                }
                Ok(false) => return Err(CoordinatorError::LeaseLost),
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "Redis acknowledgement could not be reconciled",
        ))
    }

    async fn delete_acknowledged_spool_sidecar(
        &self,
        task_id: i64,
    ) -> Result<(), CoordinatorError> {
        let record = self
            .state
            .outbound_spool_snapshot(task_id)
            .await
            .map_err(|_| {
                CoordinatorError::SpoolCleanup(
                    "acknowledged outbound spool sidecar could not be read",
                )
            })?;
        let Some(record) = record else {
            return Ok(());
        };
        if record.state != OutboundSpoolState::Removed {
            return Err(CoordinatorError::SpoolCleanup(
                "acknowledged outbound spool is not durably removed",
            ));
        }
        self.delete_removed_spool_reconciled(&record).await
    }

    async fn delete_removed_spool_reconciled(
        &self,
        record: &OutboundSpoolRecord,
    ) -> Result<(), CoordinatorError> {
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self
                .state
                .delete_removed_outbound_spool(record.task_id, &record.spool_path)
                .await
            {
                Ok(_) => return Ok(()),
                Err(DeliveryStateError::OutcomeUnknown) => {
                    let snapshot = self
                        .state
                        .outbound_spool_snapshot(record.task_id)
                        .await
                        .map_err(|_| {
                            CoordinatorError::SpoolCleanup(
                                "outbound spool sidecar deletion reconciliation failed",
                            )
                        })?;
                    match snapshot {
                        None => return Ok(()),
                        Some(snapshot)
                            if snapshot.spool_path == record.spool_path
                                && snapshot.state == OutboundSpoolState::Removed =>
                        {
                            sleep(RECONCILIATION_PAUSE).await;
                        }
                        Some(_) => {
                            return Err(CoordinatorError::SpoolCleanup(
                                "outbound spool sidecar changed during deletion",
                            ));
                        }
                    }
                }
                Err(_) => {
                    return Err(CoordinatorError::SpoolCleanup(
                        "outbound spool sidecar deletion failed",
                    ));
                }
            }
        }
        Err(CoordinatorError::SpoolCleanup(
            "outbound spool sidecar deletion remained unknown",
        ))
    }

    async fn cleanup_terminal_spool(&self, claim: &QueueClaim) -> Result<(), CoordinatorError> {
        let mut record = self
            .state
            .outbound_spool_snapshot(claim.task_id)
            .await
            .map_err(|_| CoordinatorError::SpoolCleanup("outbound spool ownership read failed"))?;
        if record.is_none() {
            let Some(task) = claim.task.as_ref() else {
                return Ok(());
            };
            let Some(spool_path) = task.message_file_path.as_deref() else {
                return Ok(());
            };
            let Some(kind) = spool_kind_for_task_path(claim.task_id, spool_path)? else {
                return Ok(());
            };
            let candidate = OutboundSpoolRecord {
                task_id: claim.task_id,
                spool_path: spool_path.to_owned(),
                kind,
                state: OutboundSpoolState::Owned,
                sender_address: task.sender_address.clone(),
                sent_file_name: task
                    .sent_file_name
                    .clone()
                    .filter(|value| !value.is_empty())
                    .ok_or(CoordinatorError::SpoolCleanup(
                        "outbound spool has no Sent Maildir identity",
                    ))?,
                sent_subdirectory: task.sent_subdirectory.filter(|value| *value > 0).ok_or(
                    CoordinatorError::SpoolCleanup(
                        "outbound spool has no Sent Maildir subdirectory",
                    ),
                )?,
            };
            self.run_spool_io(candidate.clone(), false).await?;
            self.register_spool_reconciled(&candidate).await?;
            record = self
                .state
                .outbound_spool_snapshot(claim.task_id)
                .await
                .map_err(|_| {
                    CoordinatorError::SpoolCleanup(
                        "registered outbound spool ownership could not be read",
                    )
                })?;
        }
        let Some(record) = record else {
            return Err(CoordinatorError::SpoolCleanup(
                "outbound spool ownership disappeared",
            ));
        };
        if record.state == OutboundSpoolState::Removed {
            return Ok(());
        }
        self.cleanup_owned_spool(record).await
    }

    async fn cleanup_owned_spool(
        &self,
        record: OutboundSpoolRecord,
    ) -> Result<(), CoordinatorError> {
        if record.state == OutboundSpoolState::Removed {
            return Ok(());
        }
        self.run_spool_io(record.clone(), true).await?;
        self.mark_spool_removed_reconciled(&record).await
    }

    async fn register_spool_reconciled(
        &self,
        record: &OutboundSpoolRecord,
    ) -> Result<(), CoordinatorError> {
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self
                .state
                .register_outbound_spool(
                    record.task_id,
                    &record.spool_path,
                    record.kind,
                    Utc::now(),
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(DeliveryStateError::OutcomeUnknown) => {
                    let snapshot = self
                        .state
                        .outbound_spool_snapshot(record.task_id)
                        .await
                        .map_err(|_| {
                            CoordinatorError::SpoolCleanup(
                                "outbound spool registration reconciliation failed",
                            )
                        })?;
                    if snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot.spool_path == record.spool_path && snapshot.kind == record.kind
                    }) {
                        return Ok(());
                    }
                    sleep(RECONCILIATION_PAUSE).await;
                }
                Err(_) => {
                    return Err(CoordinatorError::SpoolCleanup(
                        "outbound spool registration failed",
                    ));
                }
            }
        }
        Err(CoordinatorError::SpoolCleanup(
            "outbound spool registration remained unknown",
        ))
    }

    async fn mark_spool_removed_reconciled(
        &self,
        record: &OutboundSpoolRecord,
    ) -> Result<(), CoordinatorError> {
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self
                .state
                .mark_outbound_spool_removed(record.task_id, &record.spool_path, Utc::now())
                .await
            {
                Ok(_) => return Ok(()),
                Err(DeliveryStateError::OutcomeUnknown) => {
                    let snapshot = self
                        .state
                        .outbound_spool_snapshot(record.task_id)
                        .await
                        .map_err(|_| {
                            CoordinatorError::SpoolCleanup(
                                "outbound spool cleanup reconciliation failed",
                            )
                        })?;
                    if snapshot
                        .as_ref()
                        .is_some_and(|snapshot| snapshot.state == OutboundSpoolState::Removed)
                    {
                        return Ok(());
                    }
                    sleep(RECONCILIATION_PAUSE).await;
                }
                Err(_) => {
                    return Err(CoordinatorError::SpoolCleanup(
                        "outbound spool cleanup checkpoint failed",
                    ));
                }
            }
        }
        Err(CoordinatorError::SpoolCleanup(
            "outbound spool cleanup checkpoint remained unknown",
        ))
    }

    async fn run_spool_io(
        &self,
        record: OutboundSpoolRecord,
        remove: bool,
    ) -> Result<(), CoordinatorError> {
        let permit = timeout(
            SPOOL_IO_TIMEOUT,
            self.spool_cleanup_permits.clone().acquire_owned(),
        )
        .await
        .map_err(|_| CoordinatorError::SpoolCleanup("outbound spool cleanup pool is saturated"))?
        .map_err(|_| CoordinatorError::SpoolCleanup("outbound spool cleanup pool is closed"))?;
        let spool_dir = self.config.spool_dir.clone();
        let maildir_base = self.config.maildir_base.clone();
        let max_message_bytes = self.config.max_message_bytes;
        let task = spawn_blocking(move || {
            let _permit = permit;
            validate_and_maybe_remove_spool(
                &record,
                &spool_dir,
                &maildir_base,
                max_message_bytes,
                remove,
            )
        });
        await_spool_io(task, remove, SPOOL_IO_TIMEOUT).await
    }

    async fn schedule_queue_retry(
        &self,
        claim: &QueueClaim,
        task: &TaskDetail,
        retry_at_epoch_millis: i64,
    ) -> Result<(), CoordinatorError> {
        let settlement = QueueSettlement::Retry {
            task,
            retry_at_epoch_millis,
        };
        for _ in 0..MAX_RECONCILIATION_ATTEMPTS {
            match self
                .queue
                .schedule_retry(claim, task, retry_at_epoch_millis)
                .await
            {
                Ok(true) | Err(QueueError::OutcomeUnknown) => {
                    match self.queue.reconcile_settlement(claim, settlement).await? {
                        SettlementReconciliation::Applied => return Ok(()),
                        SettlementReconciliation::Active => {
                            sleep(RECONCILIATION_PAUSE).await;
                        }
                        SettlementReconciliation::NotFound => {
                            return Err(CoordinatorError::LeaseLost);
                        }
                        SettlementReconciliation::Inconsistent => {
                            return Err(CoordinatorError::Reconciliation(
                                "Redis retry postcondition is inconsistent",
                            ));
                        }
                    }
                }
                Ok(false) => return Err(CoordinatorError::LeaseLost),
                Err(error) => return Err(error.into()),
            }
        }
        Err(CoordinatorError::Reconciliation(
            "Redis retry scheduling could not be reconciled",
        ))
    }
}

async fn await_spool_io(
    mut task: JoinHandle<io::Result<()>>,
    irreversible: bool,
    soft_deadline: Duration,
) -> Result<(), CoordinatorError> {
    let result = match timeout(soft_deadline, &mut task).await {
        Ok(result) => result,
        Err(_) if irreversible => {
            eprintln!(
                "lmyzmail outbound spool cleanup exceeded its soft deadline; waiting for the irreversible filesystem operation"
            );
            task.await
        }
        Err(_) => {
            return Err(CoordinatorError::SpoolCleanup(
                "outbound spool validation exceeded its deadline",
            ));
        }
    };
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(CoordinatorError::SpoolCleanup(
            "outbound spool failed ownership validation or cleanup",
        )),
        Err(_) => Err(CoordinatorError::SpoolCleanup(
            "outbound spool cleanup task panicked",
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeepaliveFailure {
    Redis,
    Postgres,
}

struct Keepalive {
    stop: CancellationToken,
    database_finished: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<KeepaliveFailure>>>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Keepalive {
    fn start(
        queue: LegacyOutboundQueue,
        state: PostgresDeliveryState,
        queue_claim: QueueClaim,
        database_claim: DatabaseClaim,
        lease_duration: Duration,
        renew_interval: Duration,
        work_cancellation: CancellationToken,
    ) -> Self {
        let stop = CancellationToken::new();
        let task_stop = stop.clone();
        let database_finished = Arc::new(AtomicBool::new(false));
        let task_database_finished = Arc::clone(&database_finished);
        let failure = Arc::new(Mutex::new(None));
        let task_failure = Arc::clone(&failure);
        let handle = tokio::spawn(async move {
            let mut ticks = interval(renew_interval);
            ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
            ticks.tick().await;
            loop {
                tokio::select! {
                    _ = task_stop.cancelled() => return,
                    _ = ticks.tick() => {}
                }
                let now_millis = match now_epoch_millis() {
                    Ok(value) => value,
                    Err(_) => {
                        record_keepalive_failure(
                            &task_failure,
                            KeepaliveFailure::Redis,
                            &work_cancellation,
                        )
                        .await;
                        return;
                    }
                };
                let redis_ok = match queue
                    .renew_claim(&queue_claim, lease_duration, now_millis)
                    .await
                {
                    Ok(value) => value,
                    Err(QueueError::OutcomeUnknown) => matches!(
                        queue.reconcile_claim(&queue_claim.lease_token).await,
                        Ok(ClaimReconciliation::Active(reconciled))
                            if reconciled.claim.task_id == queue_claim.task_id
                                && reconciled.processing_time_epoch_millis >= now_millis
                    ),
                    Err(_) => false,
                };
                if !redis_ok {
                    record_keepalive_failure(
                        &task_failure,
                        KeepaliveFailure::Redis,
                        &work_cancellation,
                    )
                    .await;
                    return;
                }
                if task_database_finished.load(Ordering::Acquire) {
                    continue;
                }
                let now = Utc::now();
                let postgres_ok = match state.heartbeat(&database_claim, now).await {
                    Ok(value) => value,
                    Err(DeliveryStateError::OutcomeUnknown) => state
                        .snapshot(database_claim.task_id, Some(&database_claim))
                        .await
                        .ok()
                        .flatten()
                        .is_some_and(|snapshot| {
                            snapshot.status == DeliveryRowStatus::Processing
                                && snapshot.owned_by_claim
                                && snapshot
                                    .processing_started_at
                                    .is_some_and(|heartbeat| heartbeat >= now)
                        }),
                    Err(_) => false,
                };
                if !postgres_ok {
                    if task_database_finished.load(Ordering::Acquire) {
                        continue;
                    }
                    record_keepalive_failure(
                        &task_failure,
                        KeepaliveFailure::Postgres,
                        &work_cancellation,
                    )
                    .await;
                    return;
                }
            }
        });
        Self {
            stop,
            database_finished,
            failure,
            handle: Mutex::new(Some(handle)),
        }
    }

    fn database_finished(&self) {
        self.database_finished.store(true, Ordering::Release);
    }

    async fn check(&self) -> Result<(), CoordinatorError> {
        match *self.failure.lock().await {
            None => Ok(()),
            Some(KeepaliveFailure::Redis) => Err(CoordinatorError::LeaseLost),
            Some(KeepaliveFailure::Postgres) => Err(CoordinatorError::Reconciliation(
                "PostgreSQL delivery heartbeat failed",
            )),
        }
    }

    async fn quiesce(&self) -> Result<(), CoordinatorError> {
        self.stop.cancel();
        if let Some(handle) = self.handle.lock().await.take() {
            handle
                .await
                .map_err(|_| CoordinatorError::Reconciliation("outbound keepalive task failed"))?;
        }
        self.check().await
    }

    async fn stop(self) -> Result<(), CoordinatorError> {
        self.quiesce().await
    }
}

impl Drop for Keepalive {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

async fn record_keepalive_failure(
    failure: &Mutex<Option<KeepaliveFailure>>,
    value: KeepaliveFailure,
    cancellation: &CancellationToken,
) {
    *failure.lock().await = Some(value);
    cancellation.cancel();
}

fn release_is_durable(
    legacy: Option<&DeliverySnapshot>,
    ledger: Option<&RecipientLedgerSnapshot>,
) -> bool {
    let Some(legacy) = legacy else {
        return true;
    };
    if legacy.status == DeliveryRowStatus::Pending && !legacy.has_owner {
        return ledger.is_none_or(|ledger| {
            ledger.phase == DeliveryAttemptPhase::Projected && !ledger.has_owner
        });
    }
    matches!(
        legacy.status,
        DeliveryRowStatus::Sent
            | DeliveryRowStatus::PartialSuccess
            | DeliveryRowStatus::Failed
            | DeliveryRowStatus::Cancelled
    ) && !legacy.has_owner
        && ledger.is_some_and(|ledger| {
            ledger.phase == DeliveryAttemptPhase::Projected && !ledger.has_owner
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DomainRecipient {
    ordinal: u16,
    address: String,
}

struct DomainDeliveryContext<'a> {
    envelope_from: &'a str,
    message: &'a MessageSource,
    cancellation: &'a CancellationToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DomainDelivery {
    Complete,
    Cancelled,
    Ambiguous,
}

#[derive(Clone, Copy)]
enum AcceptedDisposition {
    Arm,
    ArmMissing,
    Fail(PreparedRecipientStatus),
}

fn validate_task_rosters(
    task: &TaskDetail,
    task_id: i64,
    retry_count: i32,
    max_retries: i32,
    database_roster: &[String],
) -> Result<BTreeMap<String, Vec<String>>, &'static str> {
    task.validate()
        .map_err(|_| "Redis outbound task detail is invalid")?;
    if task.id != task_id || task.retry_count != retry_count || task.max_retries != max_retries {
        return Err("Redis and PostgreSQL outbound task state differs");
    }
    let task_roster = parse_recipient_roster_json(&task.recipients_json)
        .map_err(|_| "Redis outbound recipient roster is invalid")?;
    if task_roster != database_roster {
        return Err("Redis and PostgreSQL outbound recipient rosters differ");
    }
    let mut domains = BTreeMap::<String, Vec<String>>::new();
    for recipient in database_roster {
        let domain = recipient_domain(recipient)
            .map_err(|_| "PostgreSQL outbound recipient roster is invalid")?;
        domains.entry(domain).or_default().push(recipient.clone());
    }
    Ok(domains)
}

fn domain_status_rosters_match(
    statuses: &BTreeMap<String, DomainStatus>,
    rosters: &BTreeMap<String, Vec<String>>,
) -> bool {
    statuses.len() == rosters.len()
        && rosters.iter().all(|(domain, recipients)| {
            statuses
                .get(domain)
                .is_some_and(|status| status.domain == *domain && status.recipients == *recipients)
        })
}

fn message_source(
    task: &TaskDetail,
    max_message_bytes: u64,
) -> Result<MessageSource, &'static str> {
    match (
        task.signed_content_base64.as_deref(),
        task.message_file_path.as_deref(),
    ) {
        (Some(encoded), None) if !encoded.is_empty() => {
            let maximum_encoded = max_message_bytes
                .checked_add(2)
                .and_then(|value| value.checked_div(3))
                .and_then(|value| value.checked_mul(4))
                .ok_or("outbound message size budget overflowed")?;
            if encoded.len() as u64 > maximum_encoded
                || encoded.len() > MAX_BASE64_SOURCE_BYTES.saturating_mul(2)
            {
                return Err("outbound Base64 message exceeds its byte budget");
            }
            let bytes = BASE64_STANDARD
                .decode(encoded)
                .map_err(|_| "outbound Base64 message is invalid")?;
            if bytes.is_empty()
                || bytes.len() as u64 > max_message_bytes
                || BASE64_STANDARD.encode(&bytes) != encoded
            {
                return Err("outbound Base64 message is non-canonical or oversized");
            }
            Ok(MessageSource::Bytes(Arc::from(bytes)))
        }
        (None, Some(path))
            if !path.is_empty()
                && path.len() <= MAX_PATH_BYTES
                && !path.contains('\0')
                && PathBuf::from(path).is_absolute() =>
        {
            Ok(MessageSource::File(PathBuf::from(path)))
        }
        _ => Err("outbound task has no unique stable message source"),
    }
}

fn retryable_domain_rosters(
    ledger: &RecipientLedgerSnapshot,
) -> Result<Vec<(String, Vec<DomainRecipient>)>, CoordinatorError> {
    let mut domains = BTreeMap::<String, Vec<DomainRecipient>>::new();
    for recipient in ledger.retryable_recipients() {
        let domain = recipient_domain(&recipient.recipient)?;
        domains.entry(domain).or_default().push(DomainRecipient {
            ordinal: recipient.ordinal,
            address: recipient.recipient.clone(),
        });
    }
    Ok(domains.into_iter().collect())
}

fn uniform_outcomes(
    recipients: &[DomainRecipient],
    status: PreparedRecipientStatus,
    detail: &str,
) -> Vec<PreparedRecipientCheckpoint> {
    let smtp_code = match status {
        PreparedRecipientStatus::Accepted => 250,
        PreparedRecipientStatus::Retryable => 451,
        PreparedRecipientStatus::Permanent => 550,
    };
    let detail = bounded_detail(detail);
    recipients
        .iter()
        .map(|recipient| PreparedRecipientCheckpoint {
            ordinal: recipient.ordinal,
            recipient: recipient.address.clone(),
            status,
            smtp_code,
            detail: detail.clone(),
        })
        .collect()
}

fn recipient_outcomes(
    recipients: &[DomainRecipient],
    results: &[RecipientResult],
    accepted: AcceptedDisposition,
    fallback_detail: &str,
) -> Result<Vec<PreparedRecipientCheckpoint>, CoordinatorError> {
    let mut indexed = BTreeMap::new();
    for result in results {
        if !recipients
            .iter()
            .any(|recipient| recipient.address == result.recipient)
            || indexed.insert(result.recipient.as_str(), result).is_some()
        {
            return Err(CoordinatorError::Reconciliation(
                "SMTP recipient results do not match the durable roster",
            ));
        }
    }
    let mut outcomes = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let result = indexed.get(recipient.address.as_str()).copied();
        let (status, smtp_code, detail) = match result.map(|result| result.status) {
            Some(RecipientStatus::TemporaryFailure) => {
                let result = result.expect("matched result exists");
                (
                    legacy_prepared_failure_status(result.code),
                    result.code,
                    java_smtp_failure_detail("RCPT TO failed", result.code, &result.reply),
                )
            }
            Some(RecipientStatus::PermanentFailure) => {
                let result = result.expect("matched result exists");
                (
                    legacy_prepared_failure_status(result.code),
                    result.code,
                    java_smtp_failure_detail("RCPT TO failed", result.code, &result.reply),
                )
            }
            Some(RecipientStatus::Accepted) => match accepted {
                AcceptedDisposition::Arm | AcceptedDisposition::ArmMissing => {
                    let result = result.expect("matched result exists");
                    (
                        PreparedRecipientStatus::Accepted,
                        result.code,
                        bounded_detail(&result.reply),
                    )
                }
                AcceptedDisposition::Fail(status) => (
                    status,
                    synthetic_code(status),
                    bounded_detail(fallback_detail),
                ),
            },
            None => match accepted {
                AcceptedDisposition::Arm => {
                    return Err(CoordinatorError::Reconciliation(
                        "SMTP prepared result omitted a durable recipient",
                    ));
                }
                AcceptedDisposition::ArmMissing => (
                    PreparedRecipientStatus::Accepted,
                    250,
                    bounded_detail(fallback_detail),
                ),
                AcceptedDisposition::Fail(status) => (
                    status,
                    synthetic_code(status),
                    bounded_detail(fallback_detail),
                ),
            },
        };
        outcomes.push(PreparedRecipientCheckpoint {
            ordinal: recipient.ordinal,
            recipient: recipient.address.clone(),
            status,
            smtp_code,
            detail,
        });
    }
    Ok(outcomes)
}

fn complete_delivery_outcomes(
    recipients: &[DomainRecipient],
    result: &DeliveryResult,
) -> Result<Vec<PreparedRecipientCheckpoint>, CoordinatorError> {
    if result.recipients.len() != recipients.len()
        || result
            .recipients
            .iter()
            .zip(recipients)
            .any(|(result, recipient)| result.recipient != recipient.address)
    {
        return Err(CoordinatorError::Reconciliation(
            "complete SMTP result does not match the durable recipient roster",
        ));
    }
    let mut outcomes = Vec::with_capacity(recipients.len());
    for (recipient, result_recipient) in recipients.iter().zip(&result.recipients) {
        let (status, code, detail) = match result_recipient.status {
            RecipientStatus::TemporaryFailure => (
                legacy_prepared_failure_status(result_recipient.code),
                result_recipient.code,
                java_smtp_failure_detail(
                    "RCPT TO failed",
                    result_recipient.code,
                    &result_recipient.reply,
                ),
            ),
            RecipientStatus::PermanentFailure => (
                legacy_prepared_failure_status(result_recipient.code),
                result_recipient.code,
                java_smtp_failure_detail(
                    "RCPT TO failed",
                    result_recipient.code,
                    &result_recipient.reply,
                ),
            ),
            RecipientStatus::Accepted => match result.data_status {
                DataStatus::TemporaryFailure => {
                    let code = result.data_code.ok_or(CoordinatorError::Reconciliation(
                        "temporary DATA result has no reply code",
                    ))?;
                    (
                        legacy_prepared_failure_status(code),
                        code,
                        java_smtp_failure_detail(
                            "Message not accepted",
                            code,
                            result
                                .data_reply
                                .as_deref()
                                .unwrap_or("temporary DATA failure"),
                        ),
                    )
                }
                DataStatus::PermanentFailure => {
                    let code = result.data_code.ok_or(CoordinatorError::Reconciliation(
                        "permanent DATA result has no reply code",
                    ))?;
                    (
                        legacy_prepared_failure_status(code),
                        code,
                        java_smtp_failure_detail(
                            "Message not accepted",
                            code,
                            result
                                .data_reply
                                .as_deref()
                                .unwrap_or("permanent DATA failure"),
                        ),
                    )
                }
                DataStatus::Accepted | DataStatus::NotAttempted => {
                    return Err(CoordinatorError::Reconciliation(
                        "complete SMTP result bypassed the durable commit barrier",
                    ));
                }
            },
        };
        outcomes.push(PreparedRecipientCheckpoint {
            ordinal: recipient.ordinal,
            recipient: recipient.address.clone(),
            status,
            smtp_code: code,
            detail,
        });
    }
    Ok(outcomes)
}

fn commit_outcome(
    result: &DeliveryResult,
) -> Result<(CommitResultStatus, u16, String), CoordinatorError> {
    let code = result.data_code.ok_or(CoordinatorError::Reconciliation(
        "SMTP commit result has no reply code",
    ))?;
    let reply = result
        .data_reply
        .as_deref()
        .unwrap_or("SMTP commit returned no reply text");
    let status = match result.data_status {
        DataStatus::Accepted => CommitResultStatus::Delivered,
        DataStatus::TemporaryFailure | DataStatus::PermanentFailure => {
            legacy_commit_failure_status(code)
        }
        DataStatus::NotAttempted => {
            return Err(CoordinatorError::Reconciliation(
                "SMTP commit result says DATA was not attempted",
            ));
        }
    };
    let detail = if status == CommitResultStatus::Delivered {
        bounded_detail(reply)
    } else {
        java_smtp_failure_detail("Message not accepted", code, reply)
    };
    Ok((status, code, detail))
}

fn delivery_failure_status(error: &DeliveryError) -> PreparedRecipientStatus {
    if matches!(
        error.kind,
        DeliveryErrorKind::Configuration | DeliveryErrorKind::Permanent
    ) || error
        .smtp_code
        .is_some_and(|code| !legacy_smtp_failure_is_retryable(code))
    {
        PreparedRecipientStatus::Permanent
    } else {
        PreparedRecipientStatus::Retryable
    }
}

fn legacy_prepared_failure_status(code: u16) -> PreparedRecipientStatus {
    if legacy_smtp_failure_is_retryable(code) {
        PreparedRecipientStatus::Retryable
    } else {
        PreparedRecipientStatus::Permanent
    }
}

fn legacy_commit_failure_status(code: u16) -> CommitResultStatus {
    if legacy_smtp_failure_is_retryable(code) {
        CommitResultStatus::Retryable
    } else {
        CommitResultStatus::Permanent
    }
}

fn synthetic_code(status: PreparedRecipientStatus) -> u16 {
    match status {
        PreparedRecipientStatus::Accepted => 250,
        PreparedRecipientStatus::Retryable => 451,
        PreparedRecipientStatus::Permanent => 550,
    }
}

fn java_smtp_failure_detail(prefix: &str, code: u16, reply: &str) -> String {
    let reply = reply.trim();
    let code_text = code.to_string();
    let reply_with_code = if reply == code_text
        || reply
            .strip_prefix(&code_text)
            .is_some_and(|suffix| suffix.starts_with(char::is_whitespace))
    {
        reply.to_owned()
    } else if reply.is_empty() {
        code_text
    } else {
        format!("{code} {reply}")
    };
    bounded_detail(&format!("{prefix}: {reply_with_code}"))
}

fn prepared_checkpoint_matches(
    snapshot: &RecipientLedgerSnapshot,
    claim: &RecipientLedgerClaim,
    outcomes: &[PreparedRecipientCheckpoint],
) -> bool {
    let armed = outcomes
        .iter()
        .any(|outcome| outcome.status == PreparedRecipientStatus::Accepted);
    snapshot.generation == claim.generation()
        && snapshot.owned_by_claim
        && snapshot.phase
            == if armed {
                DeliveryAttemptPhase::CommitArmed
            } else {
                DeliveryAttemptPhase::Preparing
            }
        && outcomes.iter().all(|outcome| {
            snapshot.recipients.iter().any(|recipient| {
                recipient.ordinal == outcome.ordinal
                    && recipient.recipient == outcome.recipient
                    && recipient.attempt_generation == claim.generation()
                    && recipient.state == prepared_state(outcome.status)
                    && recipient.smtp_code == Some(outcome.smtp_code)
                    && recipient.detail.as_deref() == Some(outcome.detail.as_str())
            })
        })
}

fn ledger_checkpoint_unchanged(
    snapshot: &RecipientLedgerSnapshot,
    prior: &RecipientLedgerSnapshot,
    outcomes: &[PreparedRecipientCheckpoint],
) -> bool {
    snapshot.generation == prior.generation
        && snapshot.phase == prior.phase
        && snapshot.owned_by_claim == prior.owned_by_claim
        && outcomes.iter().all(|outcome| {
            let current = snapshot
                .recipients
                .iter()
                .find(|recipient| recipient.ordinal == outcome.ordinal);
            let previous = prior
                .recipients
                .iter()
                .find(|recipient| recipient.ordinal == outcome.ordinal);
            current == previous
        })
}

fn commit_checkpoint_matches(
    before: &RecipientLedgerSnapshot,
    after: &RecipientLedgerSnapshot,
    claim: &RecipientLedgerClaim,
    status: CommitResultStatus,
    smtp_code: u16,
    detail: &str,
) -> bool {
    let armed: Vec<_> = before
        .recipients
        .iter()
        .filter(|recipient| recipient.state == RecipientDeliveryState::CommitArmed)
        .collect();
    !armed.is_empty()
        && after.phase == DeliveryAttemptPhase::Preparing
        && after.generation == claim.generation()
        && after.owned_by_claim
        && armed.iter().all(|armed| {
            after.recipients.iter().any(|recipient| {
                recipient.ordinal == armed.ordinal
                    && recipient.recipient == armed.recipient
                    && recipient.state == committed_state(status)
                    && recipient.attempt_generation == claim.generation()
                    && recipient.smtp_code == Some(smtp_code)
                    && recipient.detail.as_deref() == Some(detail)
            })
        })
}

fn ambiguous_checkpoint_matches(
    before: &RecipientLedgerSnapshot,
    after: &RecipientLedgerSnapshot,
    claim: &RecipientLedgerClaim,
    detail: &str,
) -> bool {
    let armed: Vec<_> = before
        .recipients
        .iter()
        .filter(|recipient| recipient.state == RecipientDeliveryState::CommitArmed)
        .collect();
    !armed.is_empty()
        && after.phase == DeliveryAttemptPhase::Preparing
        && after.generation == claim.generation()
        && after.owned_by_claim
        && !after.allows_retry()
        && !after.allows_dsn()
        && armed.iter().all(|armed| {
            after.recipients.iter().any(|recipient| {
                recipient.ordinal == armed.ordinal
                    && recipient.recipient == armed.recipient
                    && recipient.state == RecipientDeliveryState::Ambiguous
                    && recipient.attempt_generation == claim.generation()
                    && recipient.smtp_code.is_none()
                    && recipient.detail.as_deref() == Some(detail)
            })
        })
}

fn commit_barrier_unchanged(
    before: &RecipientLedgerSnapshot,
    after: &RecipientLedgerSnapshot,
) -> bool {
    before == after
        && before.phase == DeliveryAttemptPhase::CommitArmed
        && before
            .recipients
            .iter()
            .any(|recipient| recipient.state == RecipientDeliveryState::CommitArmed)
}

fn prepared_state(status: PreparedRecipientStatus) -> RecipientDeliveryState {
    match status {
        PreparedRecipientStatus::Accepted => RecipientDeliveryState::CommitArmed,
        PreparedRecipientStatus::Retryable => RecipientDeliveryState::Retryable,
        PreparedRecipientStatus::Permanent => RecipientDeliveryState::Permanent,
    }
}

fn committed_state(status: CommitResultStatus) -> RecipientDeliveryState {
    match status {
        CommitResultStatus::Delivered => RecipientDeliveryState::Delivered,
        CommitResultStatus::Retryable => RecipientDeliveryState::Retryable,
        CommitResultStatus::Permanent => RecipientDeliveryState::Permanent,
    }
}

fn validate_owned_ledger(
    ledger: &RecipientLedgerSnapshot,
    claim: &RecipientLedgerClaim,
) -> Result<(), CoordinatorError> {
    if ledger.task_id != claim.task_id()
        || ledger.generation != claim.generation()
        || !ledger.owned_by_claim
        || !ledger.has_owner
        || ledger.phase == DeliveryAttemptPhase::Projected
    {
        return Err(CoordinatorError::LeaseLost);
    }
    Ok(())
}

fn retry_delay(retry_count: i32, base: Duration, maximum: Duration) -> Duration {
    let mut delay = base;
    for _ in 0..retry_count.max(0) {
        delay = delay.saturating_mul(2).min(maximum);
        if delay == maximum {
            break;
        }
    }
    delay
}

fn infer_projection(
    ledger: &RecipientLedgerSnapshot,
    legacy: &DeliverySnapshot,
) -> Option<LegacyProjection> {
    if ledger.phase != DeliveryAttemptPhase::Projected || ledger.has_owner || legacy.has_owner {
        return None;
    }
    if ledger
        .recipients
        .iter()
        .any(|recipient| recipient.state == RecipientDeliveryState::Ambiguous)
    {
        return (legacy.status == DeliveryRowStatus::Failed).then_some(LegacyProjection::Ambiguous);
    }
    match legacy.status {
        DeliveryRowStatus::Pending => Some(LegacyProjection::RetryScheduled(RetryTransition {
            retry_count: legacy.retry_count,
            max_retries: legacy.max_retries,
            next_retry_at: legacy.next_retry_at,
        })),
        DeliveryRowStatus::Sent => Some(LegacyProjection::Terminal(TerminalStatus::Sent)),
        DeliveryRowStatus::PartialSuccess => {
            Some(LegacyProjection::Terminal(TerminalStatus::PartialSuccess))
        }
        DeliveryRowStatus::Failed => Some(LegacyProjection::Terminal(TerminalStatus::Failed)),
        DeliveryRowStatus::Processing | DeliveryRowStatus::Cancelled => None,
    }
}

fn project_domain_statuses(
    prior: &BTreeMap<String, DomainStatus>,
    ledger: &RecipientLedgerSnapshot,
    now: DateTime<Utc>,
) -> Result<BTreeMap<String, DomainStatus>, CoordinatorError> {
    let mut projected = BTreeMap::new();
    for (domain, old) in prior {
        let mut entries = Vec::with_capacity(old.recipients.len());
        for address in &old.recipients {
            let entry = ledger
                .recipients
                .iter()
                .find(|entry| entry.recipient == *address)
                .ok_or(CoordinatorError::Reconciliation(
                    "projected domain roster is missing a recipient",
                ))?;
            if recipient_domain(&entry.recipient)? != *domain {
                return Err(CoordinatorError::Reconciliation(
                    "projected recipient moved between domains",
                ));
            }
            entries.push(entry);
        }
        let (status, error) = if entries.iter().any(|entry| {
            matches!(
                entry.state,
                RecipientDeliveryState::Pending | RecipientDeliveryState::Retryable
            )
        }) {
            ("PENDING", None)
        } else if entries.iter().any(|entry| {
            matches!(
                entry.state,
                RecipientDeliveryState::Permanent | RecipientDeliveryState::Ambiguous
            )
        }) {
            (
                "FAILED",
                entries
                    .iter()
                    .find_map(|entry| entry.detail.as_ref())
                    .cloned()
                    .or_else(|| Some("permanent delivery failure".into())),
            )
        } else if entries
            .iter()
            .all(|entry| entry.state == RecipientDeliveryState::Delivered)
        {
            ("SENT", None)
        } else {
            return Err(CoordinatorError::Reconciliation(
                "projected domain contains a commit-armed recipient",
            ));
        };
        projected.insert(
            domain.clone(),
            DomainStatus {
                domain: domain.clone(),
                status: status.into(),
                error,
                recipients: old.recipients.clone(),
                updated_at: instant(now),
            },
        );
    }
    Ok(projected)
}

fn projected_retry_task(
    task: &TaskDetail,
    legacy: &DeliverySnapshot,
) -> Result<TaskDetail, CoordinatorError> {
    if legacy.status != DeliveryRowStatus::Pending
        || legacy.has_owner
        || legacy.retry_count <= task.retry_count
        || legacy.retry_count > legacy.max_retries
    {
        return Err(CoordinatorError::Reconciliation(
            "projected retry state is inconsistent",
        ));
    }
    let mut task = task.clone();
    task.retry_count = legacy.retry_count;
    task.max_retries = legacy.max_retries;
    task.next_retry_at = Some(instant(legacy.next_retry_at));
    task.last_error = legacy.last_error.clone();
    task.status = "PENDING".into();
    task.validate()?;
    Ok(task)
}

fn instant(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

fn bounded_detail(value: &str) -> String {
    let value = if value.is_empty() {
        "outbound delivery failure"
    } else {
        value
    };
    if value.len() <= MAX_DETAIL_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_DETAIL_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn spool_kind_for_task_path(
    task_id: i64,
    spool_path: &str,
) -> Result<Option<OutboundSpoolKind>, CoordinatorError> {
    let path = Path::new(spool_path);
    if task_id <= 0
        || !path.is_absolute()
        || spool_path.is_empty()
        || spool_path.len() > MAX_PATH_BYTES
        || spool_path.contains('\0')
    {
        return Err(CoordinatorError::SpoolCleanup(
            "outbound spool path is invalid",
        ));
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Err(CoordinatorError::SpoolCleanup(
            "outbound spool file name is invalid",
        ));
    };
    if file_name == format!("message-{task_id}.eml") {
        Ok(Some(OutboundSpoolKind::Rust))
    } else if file_name == format!("signed-{task_id}.eml") {
        Ok(Some(OutboundSpoolKind::LegacyJava))
    } else {
        Ok(None)
    }
}

pub(crate) fn validate_and_maybe_remove_spool(
    record: &OutboundSpoolRecord,
    spool_dir: &Path,
    maildir_base: &Path,
    max_message_bytes: u64,
    remove: bool,
) -> io::Result<()> {
    if record.task_id <= 0 || max_message_bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid outbound spool cleanup identity",
        ));
    }
    let expected_name = match record.kind {
        OutboundSpoolKind::Rust => format!("message-{}.eml", record.task_id),
        OutboundSpoolKind::LegacyJava => format!("signed-{}.eml", record.task_id),
    };
    let target = Path::new(&record.spool_path);
    if !target.is_absolute()
        || target.file_name().and_then(|value| value.to_str()) != Some(expected_name.as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound spool path does not match its durable identity",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        validate_and_maybe_remove_spool_linux(
            record,
            spool_dir,
            maildir_base,
            max_message_bytes,
            remove,
            &expected_name,
            target,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        validate_and_maybe_remove_spool_portable(
            record,
            spool_dir,
            maildir_base,
            max_message_bytes,
            remove,
            target,
        )
    }
}

#[cfg(target_os = "linux")]
fn validate_and_maybe_remove_spool_linux(
    record: &OutboundSpoolRecord,
    spool_dir: &Path,
    maildir_base: &Path,
    max_message_bytes: u64,
    remove: bool,
    expected_name: &str,
    target: &Path,
) -> io::Result<()> {
    use rustix::fs::{
        AtFlags, FileType, Mode, OFlags, ResolveFlags, fstat, fsync, open, openat2, statat,
        unlinkat,
    };

    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let spool_fd = open(spool_dir, directory_flags, Mode::empty()).map_err(io::Error::from)?;
    let parent = target.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound spool has no parent",
        )
    })?;
    let parent_fd = open(parent, directory_flags, Mode::empty()).map_err(io::Error::from)?;
    let spool_stat = fstat(&spool_fd).map_err(io::Error::from)?;
    let parent_stat = fstat(&parent_fd).map_err(io::Error::from)?;
    if FileType::from_raw_mode(spool_stat.st_mode) != FileType::Directory
        || FileType::from_raw_mode(parent_stat.st_mode) != FileType::Directory
        || spool_stat.st_dev != parent_stat.st_dev
        || spool_stat.st_ino != parent_stat.st_ino
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound spool escapes its configured root",
        ));
    }

    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    let file_flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let target_fd = match openat2(&spool_fd, expected_name, file_flags, Mode::empty(), resolve) {
        Ok(fd) => fd,
        Err(error) => {
            let error = io::Error::from(error);
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(error);
        }
    };
    let target_stat = fstat(&target_fd).map_err(io::Error::from)?;
    validate_open_spool_stat(&target_stat, max_message_bytes)?;

    let mut target_file = File::from(target_fd);
    if record.kind == OutboundSpoolKind::LegacyJava {
        if record.sent_subdirectory <= 0
            || !single_normal_component(&record.sender_address)
            || !single_normal_component(&record.sent_file_name)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Sent Maildir identity for outbound spool",
            ));
        }
        let maildir_fd =
            open(maildir_base, directory_flags, Mode::empty()).map_err(io::Error::from)?;
        let sent_relative = PathBuf::from(&record.sender_address)
            .join("sent")
            .join(record.sent_subdirectory.to_string())
            .join(&record.sent_file_name);
        let sent_fd = openat2(
            &maildir_fd,
            &sent_relative,
            file_flags,
            Mode::empty(),
            resolve,
        )
        .map_err(io::Error::from)?;
        let sent_stat = fstat(&sent_fd).map_err(io::Error::from)?;
        validate_open_spool_stat(&sent_stat, max_message_bytes)?;
        let mut sent_file = File::from(sent_fd);
        if !files_equal_opened(
            &mut target_file,
            target_stat.st_size as u64,
            &mut sent_file,
            sent_stat.st_size as u64,
            max_message_bytes,
        )? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "legacy outbound spool differs from its Sent Maildir copy",
            ));
        }
    }
    if remove {
        let current =
            statat(&spool_fd, expected_name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
        if current.st_dev != target_stat.st_dev
            || current.st_ino != target_stat.st_ino
            || FileType::from_raw_mode(current.st_mode) != FileType::RegularFile
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "outbound spool changed during ownership validation",
            ));
        }
        unlinkat(&spool_fd, expected_name, AtFlags::empty()).map_err(io::Error::from)?;
        fsync(&spool_fd).map_err(io::Error::from)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_open_spool_stat(stat: &rustix::fs::Stat, maximum: u64) -> io::Result<()> {
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_size <= 0
        || stat.st_size as u64 > maximum
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound spool is not a bounded non-empty regular file",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn files_equal_opened(
    left: &mut File,
    left_size: u64,
    right: &mut File,
    right_size: u64,
    maximum: u64,
) -> io::Result<bool> {
    if left_size != right_size || left_size == 0 || left_size > maximum {
        return Ok(false);
    }
    let mut left_buffer = vec![0_u8; FILE_COMPARE_BUFFER_BYTES];
    let mut right_buffer = vec![0_u8; FILE_COMPARE_BUFFER_BYTES];
    loop {
        let left_read = left.read(&mut left_buffer)?;
        let right_read = right.read(&mut right_buffer)?;
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn validate_and_maybe_remove_spool_portable(
    record: &OutboundSpoolRecord,
    spool_dir: &Path,
    maildir_base: &Path,
    max_message_bytes: u64,
    remove: bool,
    target: &Path,
) -> io::Result<()> {
    let spool_root = secure_existing_directory(spool_dir)?;
    let target_parent = target.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound spool has no parent",
        )
    })?;
    let target_parent = secure_existing_directory(target_parent)?;
    if target_parent != spool_root {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound spool escapes its configured root",
        ));
    }

    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound spool is not a non-empty regular file",
        ));
    }
    if metadata.len() > max_message_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound spool exceeds its byte budget",
        ));
    }

    if record.kind == OutboundSpoolKind::LegacyJava {
        let sent_path = secure_sent_file(record, maildir_base)?;
        if !files_equal_bounded(target, &sent_path, max_message_bytes)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "legacy outbound spool differs from its Sent Maildir copy",
            ));
        }
    }
    if remove {
        fs::remove_file(target)?;
        File::open(&spool_root)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn secure_existing_directory(path: &Path) -> io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "storage directory is not a real directory",
        ));
    }
    fs::canonicalize(path)
}

#[cfg(not(target_os = "linux"))]
fn secure_sent_file(record: &OutboundSpoolRecord, maildir_base: &Path) -> io::Result<PathBuf> {
    if record.sent_subdirectory <= 0
        || !single_normal_component(&record.sender_address)
        || !single_normal_component(&record.sent_file_name)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Sent Maildir identity for outbound spool",
        ));
    }
    let base = secure_existing_directory(maildir_base)?;
    let mailbox = secure_existing_directory(&base.join(&record.sender_address))?;
    if !mailbox.starts_with(&base) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound spool mailbox escapes Maildir",
        ));
    }
    let sent = secure_existing_directory(&mailbox.join("sent"))?;
    let shard = secure_existing_directory(&sent.join(record.sent_subdirectory.to_string()))?;
    if !sent.starts_with(&mailbox) || !shard.starts_with(&sent) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound spool Sent path escapes Maildir",
        ));
    }
    let path = shard.join(&record.sent_file_name);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_BASE64_SOURCE_BYTES as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound Sent copy is not a bounded regular file",
        ));
    }
    Ok(path)
}

fn single_normal_component(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && Path::new(value).components().count() == 1
}

#[cfg(not(target_os = "linux"))]
fn files_equal_bounded(left: &Path, right: &Path, maximum: u64) -> io::Result<bool> {
    let left_metadata = fs::metadata(left)?;
    let right_metadata = fs::metadata(right)?;
    if left_metadata.len() != right_metadata.len()
        || left_metadata.len() == 0
        || left_metadata.len() > maximum
    {
        return Ok(false);
    }
    let mut left = File::open(left)?;
    let mut right = File::open(right)?;
    let mut left_buffer = vec![0_u8; FILE_COMPARE_BUFFER_BYTES];
    let mut right_buffer = vec![0_u8; FILE_COMPARE_BUFFER_BYTES];
    loop {
        let left_read = left.read(&mut left_buffer)?;
        let right_read = right.read(&mut right_buffer)?;
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

fn property_u64(
    config: &RuntimeConfig,
    new_key: &str,
    legacy_key: &str,
    default: u64,
) -> Result<u64, CoordinatorError> {
    config
        .preferred_value(new_key, legacy_key)
        .map(str::parse)
        .transpose()
        .map_err(|_| CoordinatorError::Configuration("outbound coordinator property is invalid"))
        .map(|value| value.unwrap_or(default))
}

fn now_epoch_millis() -> Result<i64, CoordinatorError> {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CoordinatorError::Configuration("system clock is before the Unix epoch"))?
            .as_millis(),
    )
    .map_err(|_| CoordinatorError::Configuration("system clock is outside the supported range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Properties, outbound_delivery::RecipientLedgerEntry};
    use std::{fs, sync::atomic::AtomicU64};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lmyzmail-outbound-coordinator-{}-{id}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn task(recipients_json: &str) -> TaskDetail {
        TaskDetail {
            id: 42,
            sender_address: "sender@example.test".into(),
            recipients_json: recipients_json.into(),
            subject: "subject".into(),
            message_id: "<coordinator@example.test>".into(),
            max_retries: 5,
            retry_count: 0,
            sent_file_name: Some("42.eml".into()),
            sent_subdirectory: Some(1),
            message_file_path: None,
            signed_content_base64: Some("SGVsbG8=".into()),
            created_at: "2026-08-07T00:00:00Z".into(),
            next_retry_at: None,
            last_error: None,
            status: "PENDING".into(),
        }
    }

    fn recipient(
        ordinal: u16,
        address: &str,
        state: RecipientDeliveryState,
        detail: Option<&str>,
    ) -> RecipientLedgerEntry {
        RecipientLedgerEntry {
            ordinal,
            recipient: address.into(),
            state,
            attempt_generation: 1,
            smtp_code: None,
            detail: detail.map(str::to_owned),
        }
    }

    fn ledger(entries: Vec<RecipientLedgerEntry>) -> RecipientLedgerSnapshot {
        RecipientLedgerSnapshot {
            task_id: 42,
            generation: 1,
            phase: DeliveryAttemptPhase::Projected,
            has_owner: false,
            owned_by_claim: false,
            recipients: entries,
        }
    }

    fn delivery_snapshot(status: DeliveryRowStatus) -> DeliverySnapshot {
        let now = DateTime::from_timestamp(1_786_000_000, 0).unwrap();
        DeliverySnapshot {
            task_id: 42,
            status,
            retry_count: 1,
            max_retries: 5,
            next_retry_at: now,
            last_error: Some("temporary".into()),
            sent_at: None,
            processing_started_at: None,
            sent_file_name: Some("42.eml".into()),
            has_owner: false,
            owned_by_claim: false,
        }
    }

    #[test]
    fn coordinator_configuration_uses_new_key_precedence_and_safe_bounds() {
        let properties = Properties::parse(
            b"botmail.queue.lease-seconds=75\n\
              lmyzmail.queue.lease-seconds=90\n\
              botmail.queue.renew-seconds=25\n\
              lmyzmail.queue.renew-seconds=10\n\
              botmail.queue.processing-timeout-minutes=9\n\
              lmyzmail.queue.processing-timeout-minutes=8\n\
              botmail.outbound.helo-hostname=legacy.example\n\
              lmyzmail.outbound.helo-hostname=blackbox.example\n\
              lmyzmail.queue.worker-id=qa-worker\n",
        )
        .unwrap();
        let runtime = RuntimeConfig::from_properties(properties).unwrap();
        let config = CoordinatorConfig::from_config(&runtime).unwrap();
        assert_eq!(config.worker_id, "qa-worker");
        assert_eq!(config.hello_name, "blackbox.example");
        assert_eq!(config.lease_duration, Duration::from_secs(90));
        assert_eq!(config.renew_interval, Duration::from_secs(10));
        assert_eq!(config.task_deadline, Duration::from_secs(8 * 60));

        let invalid = RuntimeConfig::from_properties(
            Properties::parse(
                b"lmyzmail.queue.lease-seconds=64\nlmyzmail.queue.renew-seconds=20\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(CoordinatorConfig::from_config(&invalid).is_err());

        let oversized_worker = RuntimeConfig::from_properties(
            Properties::parse(
                format!(
                    "lmyzmail.queue.worker-id={}\n",
                    "w".repeat(MAX_WORKER_ID_BYTES + 1)
                )
                .as_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(CoordinatorConfig::from_config(&oversized_worker).is_err());

        let invalid_hello = RuntimeConfig::from_properties(
            Properties::parse(b"lmyzmail.outbound.helo-hostname=bad name\n").unwrap(),
        )
        .unwrap();
        assert!(CoordinatorConfig::from_config(&invalid_hello).is_err());
    }

    #[test]
    fn task_postgres_and_domain_rosters_match_by_ordinal() {
        let task = task(r#"{"to":["a@alpha.test"],"cc":["b@beta.test"],"bcc":["c@alpha.test"]}"#);
        let roster = vec![
            "a@alpha.test".into(),
            "b@beta.test".into(),
            "c@alpha.test".into(),
        ];
        let domains = validate_task_rosters(&task, 42, 0, 5, &roster).unwrap();
        assert_eq!(domains["alpha.test"], ["a@alpha.test", "c@alpha.test"]);
        assert_eq!(domains["beta.test"], ["b@beta.test"]);

        let mut reordered = roster.clone();
        reordered.swap(0, 1);
        assert!(validate_task_rosters(&task, 42, 0, 5, &reordered).is_err());
    }

    #[test]
    fn message_sources_are_canonical_bounded_and_unique() {
        let task = task(r#"["a@alpha.test"]"#);
        match message_source(&task, 5).unwrap() {
            MessageSource::Bytes(bytes) => assert_eq!(&*bytes, b"Hello"),
            MessageSource::File(_) => panic!("small message did not remain in memory"),
        }
        assert!(message_source(&task, 4).is_err());

        let mut malformed = task.clone();
        malformed.signed_content_base64 = Some("SGVsbG8".into());
        assert!(message_source(&malformed, 5).is_err());

        let mut duplicate = task.clone();
        duplicate.message_file_path = Some("/tmp/message-42.eml".into());
        assert!(message_source(&duplicate, 5).is_err());

        let mut file = task;
        file.signed_content_base64 = None;
        file.message_file_path = Some("/tmp/message-42.eml".into());
        assert!(matches!(
            message_source(&file, 5),
            Ok(MessageSource::File(_))
        ));
    }

    #[test]
    fn recipient_and_data_results_map_without_losing_ordinals() {
        let recipients = vec![
            DomainRecipient {
                ordinal: 3,
                address: "accepted@alpha.test".into(),
            },
            DomainRecipient {
                ordinal: 7,
                address: "temporary@alpha.test".into(),
            },
        ];
        let results = vec![
            RecipientResult {
                recipient: "accepted@alpha.test".into(),
                status: RecipientStatus::Accepted,
                code: 250,
                reply: "250 accepted".into(),
            },
            RecipientResult {
                recipient: "temporary@alpha.test".into(),
                status: RecipientStatus::TemporaryFailure,
                code: 451,
                reply: "451 later".into(),
            },
        ];
        let prepared =
            recipient_outcomes(&recipients, &results, AcceptedDisposition::Arm, "missing").unwrap();
        assert_eq!(prepared[0].ordinal, 3);
        assert_eq!(prepared[0].status, PreparedRecipientStatus::Accepted);
        assert_eq!(prepared[1].ordinal, 7);
        assert_eq!(prepared[1].status, PreparedRecipientStatus::Retryable);
        assert_eq!(prepared[1].detail, "RCPT TO failed: 451 later");

        let complete = DeliveryResult {
            recipients: results,
            data_status: DataStatus::TemporaryFailure,
            data_code: Some(421),
            data_reply: Some("421 queue unavailable".into()),
            tls: false,
            smtp_utf8: false,
            pipelining: true,
        };
        let complete = complete_delivery_outcomes(&recipients, &complete).unwrap();
        assert_eq!(complete[0].status, PreparedRecipientStatus::Retryable);
        assert_eq!(complete[0].smtp_code, 421);
        assert_eq!(
            complete[0].detail,
            "Message not accepted: 421 queue unavailable"
        );
        assert_eq!(complete[1].smtp_code, 451);
        assert_eq!(complete[1].detail, "RCPT TO failed: 451 later");

        let committed = DeliveryResult {
            recipients: vec![],
            data_status: DataStatus::PermanentFailure,
            data_code: Some(550),
            data_reply: Some("mailbox unavailable".into()),
            tls: false,
            smtp_utf8: false,
            pipelining: true,
        };
        let (status, code, detail) = commit_outcome(&committed).unwrap();
        assert_eq!(status, CommitResultStatus::Permanent);
        assert_eq!(code, 550);
        assert_eq!(detail, "Message not accepted: 550 mailbox unavailable");
    }

    #[test]
    fn frozen_java_smtp_code_classification_covers_rcpt_data_and_commit() {
        let recipients = vec![DomainRecipient {
            ordinal: 0,
            address: "user@alpha.test".into(),
        }];
        for (code, expected) in [
            (400, PreparedRecipientStatus::Permanent),
            (421, PreparedRecipientStatus::Retryable),
            (450, PreparedRecipientStatus::Retryable),
            (451, PreparedRecipientStatus::Retryable),
            (452, PreparedRecipientStatus::Retryable),
            (499, PreparedRecipientStatus::Permanent),
        ] {
            let reply = format!("{code} fixture reply");
            let rcpt = recipient_outcomes(
                &recipients,
                &[RecipientResult {
                    recipient: recipients[0].address.clone(),
                    status: RecipientStatus::TemporaryFailure,
                    code,
                    reply: reply.clone(),
                }],
                AcceptedDisposition::Arm,
                "missing",
            )
            .unwrap();
            assert_eq!(rcpt[0].status, expected, "RCPT code {code}");

            let data = DeliveryResult {
                recipients: vec![RecipientResult {
                    recipient: recipients[0].address.clone(),
                    status: RecipientStatus::Accepted,
                    code: 250,
                    reply: "250 accepted".into(),
                }],
                data_status: DataStatus::TemporaryFailure,
                data_code: Some(code),
                data_reply: Some(reply),
                tls: false,
                smtp_utf8: false,
                pipelining: false,
            };
            let complete = complete_delivery_outcomes(&recipients, &data).unwrap();
            assert_eq!(complete[0].status, expected, "DATA code {code}");

            let (committed, committed_code, _) = commit_outcome(&data).unwrap();
            assert_eq!(committed_code, code);
            assert_eq!(
                committed,
                if expected == PreparedRecipientStatus::Retryable {
                    CommitResultStatus::Retryable
                } else {
                    CommitResultStatus::Permanent
                },
                "commit code {code}"
            );
        }
    }

    #[test]
    fn retry_backoff_matches_the_frozen_java_sequence_and_caps() {
        let base = Duration::from_secs(30);
        let maximum = Duration::from_secs(3_600);
        assert_eq!(retry_delay(0, base, maximum), Duration::from_secs(30));
        assert_eq!(retry_delay(1, base, maximum), Duration::from_secs(60));
        assert_eq!(retry_delay(2, base, maximum), Duration::from_secs(120));
        assert_eq!(retry_delay(1000, base, maximum), maximum);
    }

    #[test]
    fn projected_domains_preserve_full_rosters_and_terminal_precedence() {
        let prior = BTreeMap::from([(
            "alpha.test".into(),
            DomainStatus {
                domain: "alpha.test".into(),
                status: "SENDING".into(),
                error: None,
                recipients: vec!["ok@alpha.test".into(), "bad@alpha.test".into()],
                updated_at: "old".into(),
            },
        )]);
        let ledger = ledger(vec![
            recipient(0, "ok@alpha.test", RecipientDeliveryState::Delivered, None),
            recipient(
                1,
                "bad@alpha.test",
                RecipientDeliveryState::Permanent,
                Some("550 rejected"),
            ),
        ]);
        let projected = project_domain_statuses(&prior, &ledger, Utc::now()).unwrap();
        assert_eq!(projected["alpha.test"].status, "FAILED");
        assert_eq!(
            projected["alpha.test"].error.as_deref(),
            Some("550 rejected")
        );
        assert_eq!(
            projected["alpha.test"].recipients,
            prior["alpha.test"].recipients
        );
    }

    #[test]
    fn projection_reconciliation_distinguishes_retry_terminal_and_ambiguity() {
        let retry_ledger = ledger(vec![recipient(
            0,
            "later@alpha.test",
            RecipientDeliveryState::Retryable,
            Some("451 later"),
        )]);
        assert!(matches!(
            infer_projection(
                &retry_ledger,
                &delivery_snapshot(DeliveryRowStatus::Pending)
            ),
            Some(LegacyProjection::RetryScheduled(_))
        ));

        let ambiguous = ledger(vec![recipient(
            0,
            "maybe@alpha.test",
            RecipientDeliveryState::Ambiguous,
            Some("final reply lost"),
        )]);
        assert_eq!(
            infer_projection(&ambiguous, &delivery_snapshot(DeliveryRowStatus::Failed)),
            Some(LegacyProjection::Ambiguous)
        );
    }

    #[test]
    fn bounded_details_do_not_split_utf8() {
        let value = "x".repeat(MAX_DETAIL_BYTES - 1) + "\u{754c}";
        let bounded = bounded_detail(&value);
        assert!(bounded.len() <= MAX_DETAIL_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert_eq!(bounded, "x".repeat(MAX_DETAIL_BYTES - 1));
    }

    #[test]
    fn legacy_spool_cleanup_is_bounded_to_matching_owned_files() {
        let root = TestDirectory::new();
        let spool = root.0.join("spool");
        let maildir = root.0.join("maildir");
        let sent = maildir.join("sender@example.test/sent/1");
        fs::create_dir_all(&spool).unwrap();
        fs::create_dir_all(&sent).unwrap();
        let sent_path = sent.join("sent.eml");
        let spool_path = spool.join("signed-42.eml");
        fs::write(&sent_path, b"same signed message").unwrap();
        fs::write(&spool_path, b"same signed message").unwrap();
        let record = OutboundSpoolRecord {
            task_id: 42,
            spool_path: spool_path.to_string_lossy().into_owned(),
            kind: OutboundSpoolKind::LegacyJava,
            state: OutboundSpoolState::Owned,
            sender_address: "sender@example.test".into(),
            sent_file_name: "sent.eml".into(),
            sent_subdirectory: 1,
        };
        validate_and_maybe_remove_spool(&record, &spool, &maildir, 1_024, false).unwrap();
        assert!(spool_path.exists());
        validate_and_maybe_remove_spool(&record, &spool, &maildir, 1_024, true).unwrap();
        assert!(!spool_path.exists());
        assert_eq!(fs::read(sent_path).unwrap(), b"same signed message");
        validate_and_maybe_remove_spool(&record, &spool, &maildir, 1_024, true).unwrap();
    }

    #[test]
    fn spool_cleanup_rejects_content_mismatch_and_path_escape() {
        let root = TestDirectory::new();
        let spool = root.0.join("spool");
        let maildir = root.0.join("maildir");
        let sent = maildir.join("sender@example.test/sent/1");
        fs::create_dir_all(&spool).unwrap();
        fs::create_dir_all(&sent).unwrap();
        let sent_path = sent.join("sent.eml");
        fs::write(&sent_path, b"sent copy").unwrap();
        let mismatch = spool.join("signed-42.eml");
        fs::write(&mismatch, b"different spool").unwrap();
        let mut record = OutboundSpoolRecord {
            task_id: 42,
            spool_path: mismatch.to_string_lossy().into_owned(),
            kind: OutboundSpoolKind::LegacyJava,
            state: OutboundSpoolState::Owned,
            sender_address: "sender@example.test".into(),
            sent_file_name: "sent.eml".into(),
            sent_subdirectory: 1,
        };
        assert!(validate_and_maybe_remove_spool(&record, &spool, &maildir, 1_024, true).is_err());
        assert!(mismatch.exists());

        fs::remove_file(&mismatch).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&sent_path, &mismatch).unwrap();
            assert!(
                validate_and_maybe_remove_spool(&record, &spool, &maildir, 1_024, true).is_err()
            );
            assert!(
                mismatch
                    .symlink_metadata()
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read(&sent_path).unwrap(), b"sent copy");
            fs::remove_file(&mismatch).unwrap();
        }

        let escaped = root.0.join("signed-42.eml");
        fs::write(&escaped, b"sent copy").unwrap();
        record.spool_path = escaped.to_string_lossy().into_owned();
        assert!(validate_and_maybe_remove_spool(&record, &spool, &maildir, 1_024, true).is_err());
        assert!(escaped.exists());
    }

    #[tokio::test]
    async fn irreversible_spool_io_is_joined_after_its_soft_deadline() {
        let finished = Arc::new(AtomicBool::new(false));
        let task_finished = Arc::clone(&finished);
        let task = spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(50));
            task_finished.store(true, Ordering::Release);
            Ok(())
        });

        await_spool_io(task, true, Duration::from_millis(5))
            .await
            .unwrap();
        assert!(finished.load(Ordering::Acquire));
    }
}
