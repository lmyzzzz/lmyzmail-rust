use std::{fmt, time::Duration};

use deadpool_postgres::Pool as PostgresPool;
use deadpool_redis::Pool as RedisPool;
use getrandom::fill as fill_random;
use tokio::{
    sync::oneshot,
    task::{JoinError, JoinSet},
    time::{Instant, MissedTickBehavior, interval, interval_at, sleep, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::RuntimeConfig,
    outbound::OutboundService,
    outbound_coordinator::{
        CoordinatorError, CoordinatorOutcome, OutboundCoordinator, QueueMaintenanceOutcome,
    },
    outbound_delivery::PostgresDeliveryState,
    outbound_dsn::{DsnDispatchError, DsnDispatcher},
    outbound_legacy::{LegacyMigrationError, LegacyQueueMigrator},
    outbound_queue::LegacyOutboundQueue,
};

const DEFAULT_MAX_CONCURRENT_SENDS: usize = 100;
const DEFAULT_BATCH_SIZE: usize = 50;
const DEFAULT_POLL_INTERVAL_MILLIS: u64 = 1_000;
const DEFAULT_MIGRATION_BATCH_SIZE: usize = 1_000;
const RETRY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);
const LEGACY_MIGRATION_INTERVAL: Duration = Duration::from_secs(1);
const OPERATION_ERROR_BACKOFF_MIN: Duration = Duration::from_secs(1);
const OPERATION_ERROR_BACKOFF_MAX: Duration = Duration::from_secs(30);
const MIGRATION_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_SENDS: usize = 256;
const MAX_BATCH_SIZE: usize = 10_000;
const DSN_DISPATCH_BATCH_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundWorkerConfig {
    pub max_concurrent_sends: usize,
    pub batch_size: usize,
    pub poll_interval: Duration,
    pub migration_batch_size: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OperationBackoff {
    consecutive_failures: u32,
}

impl OperationBackoff {
    fn next_delay(&mut self) -> Duration {
        let shift = self.consecutive_failures.min(5);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        OPERATION_ERROR_BACKOFF_MIN
            .checked_mul(1_u32 << shift)
            .unwrap_or(OPERATION_ERROR_BACKOFF_MAX)
            .min(OPERATION_ERROR_BACKOFF_MAX)
    }

    fn reset(&mut self) {
        self.consecutive_failures = 0;
    }

    fn next_jittered_delay(&mut self) -> Duration {
        let base = self.next_delay();
        let mut random = [0_u8; 8];
        let sample = if fill_random(&mut random).is_ok() {
            u64::from_le_bytes(random)
        } else {
            0
        };
        equal_jitter(base, sample)
    }
}

fn equal_jitter(base: Duration, sample: u64) -> Duration {
    let millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    let floor = millis / 2;
    let window = millis.saturating_sub(floor);
    Duration::from_millis(floor.saturating_add(sample % window.saturating_add(1)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliveryTaskOutcome {
    Completed,
    OperationFailed,
}

type DeliveryJoinResult = Result<(bool, Result<CoordinatorOutcome, CoordinatorError>), JoinError>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DeliveryCircuit {
    #[default]
    Closed,
    Backoff {
        retry_at: Instant,
    },
    HalfOpenWaiting,
    HalfOpenProbe,
}

impl DeliveryCircuit {
    fn advance(&mut self, now: Instant) {
        if matches!(self, Self::Backoff { retry_at } if *retry_at <= now) {
            *self = Self::HalfOpenWaiting;
        }
    }

    fn is_closed(self) -> bool {
        self == Self::Closed
    }

    fn half_open_probe_ready(self) -> bool {
        self == Self::HalfOpenWaiting
    }

    fn start_half_open_probe(&mut self) -> bool {
        if *self != Self::HalfOpenWaiting {
            return false;
        }
        *self = Self::HalfOpenProbe;
        true
    }

    fn trip(&mut self, retry_at: Instant) {
        *self = Self::Backoff { retry_at };
    }

    fn close(&mut self) {
        *self = Self::Closed;
    }
}

impl OutboundWorkerConfig {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, OutboundWorkerError> {
        let value = Self {
            max_concurrent_sends: property_usize(
                config,
                "lmyzmail.queue.max-concurrent-sends",
                "botmail.queue.max-concurrent-sends",
                DEFAULT_MAX_CONCURRENT_SENDS,
            )?,
            batch_size: property_usize(
                config,
                "lmyzmail.queue.batch-size",
                "botmail.queue.batch-size",
                DEFAULT_BATCH_SIZE,
            )?,
            poll_interval: Duration::from_millis(property_u64(
                config,
                "lmyzmail.queue.poll-interval-ms",
                "botmail.queue.poll-interval-ms",
                DEFAULT_POLL_INTERVAL_MILLIS,
            )?),
            migration_batch_size: property_usize(
                config,
                "lmyzmail.queue.migration-batch-size",
                "botmail.queue.persist.batch-size",
                DEFAULT_MIGRATION_BATCH_SIZE,
            )?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), OutboundWorkerError> {
        if self.max_concurrent_sends == 0
            || self.max_concurrent_sends > MAX_CONCURRENT_SENDS
            || self.batch_size == 0
            || self.batch_size > MAX_BATCH_SIZE
            || self.poll_interval < Duration::from_millis(10)
            || self.poll_interval > Duration::from_secs(60)
            || self.migration_batch_size == 0
            || self.migration_batch_size > MAX_BATCH_SIZE
        {
            return Err(OutboundWorkerError::Configuration(
                "outbound worker limits are invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct OutboundWorker {
    coordinator: OutboundCoordinator,
    migrator: LegacyQueueMigrator,
    dsn_dispatcher: DsnDispatcher,
    config: OutboundWorkerConfig,
}

#[derive(Debug)]
pub enum OutboundWorkerError {
    Configuration(&'static str),
    Coordinator(CoordinatorError),
    Migration(LegacyMigrationError),
    DeliveryTaskPanicked,
    MigrationTaskPanicked,
    MigrationTaskExited,
    ShutdownTimeout,
}

impl fmt::Display for OutboundWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => formatter.write_str(message),
            Self::Coordinator(error) => write!(formatter, "outbound coordinator failed: {error}"),
            Self::Migration(error) => write!(formatter, "outbound migration failed: {error}"),
            Self::DeliveryTaskPanicked => formatter.write_str("outbound delivery task panicked"),
            Self::MigrationTaskPanicked => formatter.write_str("outbound migration task panicked"),
            Self::MigrationTaskExited => {
                formatter.write_str("outbound migration task exited unexpectedly")
            }
            Self::ShutdownTimeout => {
                formatter.write_str("outbound worker did not stop before its shutdown deadline")
            }
        }
    }
}

impl std::error::Error for OutboundWorkerError {}

impl From<CoordinatorError> for OutboundWorkerError {
    fn from(error: CoordinatorError) -> Self {
        Self::Coordinator(error)
    }
}

impl From<LegacyMigrationError> for OutboundWorkerError {
    fn from(error: LegacyMigrationError) -> Self {
        Self::Migration(error)
    }
}

impl OutboundWorker {
    pub fn from_config(
        config: &RuntimeConfig,
        postgres_pool: PostgresPool,
        redis_pool: RedisPool,
    ) -> Result<Self, OutboundWorkerError> {
        let worker_config = OutboundWorkerConfig::from_config(config)?;
        let coordinator =
            OutboundCoordinator::from_config(config, postgres_pool.clone(), redis_pool.clone())?;
        let delivery_state = PostgresDeliveryState::new(postgres_pool.clone());
        let migrator = LegacyQueueMigrator::new(
            LegacyOutboundQueue::new(redis_pool.clone()),
            delivery_state.clone(),
        );
        let outbound = OutboundService::from_config(config, postgres_pool, redis_pool)
            .map_err(|_| OutboundWorkerError::Configuration("outbound DSN configuration failed"))?;
        let dsn_dispatcher = DsnDispatcher::new(delivery_state, outbound);
        Ok(Self {
            coordinator,
            migrator,
            dsn_dispatcher,
            config: worker_config,
        })
    }

    pub async fn initialize(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<bool, OutboundWorkerError> {
        let mut backoff = OperationBackoff::default();
        loop {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let initialized = tokio::select! {
                _ = cancellation.cancelled() => return Ok(false),
                result = self.coordinator.initialize() => result,
            };
            match initialized {
                Ok(()) => return Ok(true),
                Err(error) => {
                    eprintln!("lmyzmail outbound PostgreSQL initialization failed: {error}");
                    let delay = backoff.next_jittered_delay();
                    tokio::select! {
                        _ = cancellation.cancelled() => return Ok(false),
                        _ = sleep(delay) => {}
                    }
                }
            }
        }
    }

    pub async fn run(&self, cancellation: CancellationToken) -> Result<(), OutboundWorkerError> {
        let mut migration_task = tokio::spawn(run_legacy_migration(
            self.migrator.clone(),
            self.config.migration_batch_size,
            cancellation.clone(),
        ));
        let mut migration_finished = false;
        let mut deliveries = JoinSet::new();
        let mut claim_signal: Option<oneshot::Receiver<bool>> = None;
        let mut dispatch_budget = 0_usize;
        let mut dispatch_tick = interval(self.config.poll_interval);
        dispatch_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let start = Instant::now();
        let mut maintenance_tick = interval_at(
            start + RETRY_MAINTENANCE_INTERVAL,
            RETRY_MAINTENANCE_INTERVAL,
        );
        maintenance_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut expired_cursor = 0_u64;
        let mut delivery_backoff = OperationBackoff::default();
        let mut delivery_circuit = DeliveryCircuit::default();
        let mut maintenance_backoff = OperationBackoff::default();
        let mut maintenance_retry_at: Option<Instant> = None;

        loop {
            if cancellation.is_cancelled() {
                break;
            }
            delivery_circuit.advance(Instant::now());
            let half_open_probe = delivery_circuit.half_open_probe_ready()
                && deliveries.is_empty()
                && claim_signal.is_none();
            let regular_dispatch = delivery_circuit.is_closed() && dispatch_budget > 0;
            if (regular_dispatch || half_open_probe)
                && claim_signal.is_none()
                && deliveries.len() < self.config.max_concurrent_sends
            {
                if half_open_probe {
                    debug_assert!(delivery_circuit.start_half_open_probe());
                } else {
                    dispatch_budget -= 1;
                }
                let (sender, receiver) = oneshot::channel();
                let coordinator = self.coordinator.clone();
                let task_cancellation = cancellation.clone();
                deliveries.spawn(async move {
                    (
                        half_open_probe,
                        coordinator
                            .process_next_with_claim_signal(&task_cancellation, sender)
                            .await,
                    )
                });
                claim_signal = Some(receiver);
                continue;
            }

            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = dispatch_tick.tick() => {
                    delivery_circuit.advance(Instant::now());
                    dispatch_budget = if delivery_circuit.is_closed() {
                        self.config.batch_size
                    } else {
                        0
                    };
                }
                signal = wait_for_claim_signal(&mut claim_signal), if claim_signal.is_some() => {
                    claim_signal = None;
                    match signal {
                        Ok(true) => {}
                        Ok(false) => dispatch_budget = 0,
                        Err(_) => dispatch_budget = 0,
                    }
                }
                joined = deliveries.join_next(), if !deliveries.is_empty() => {
                    let (was_half_open_probe, outcome) = handle_delivery_result(joined)?;
                    match outcome {
                        DeliveryTaskOutcome::Completed => {
                            if was_half_open_probe {
                                delivery_circuit.close();
                                delivery_backoff.reset();
                                dispatch_budget = self.config.batch_size;
                            } else if delivery_circuit.is_closed() {
                                delivery_backoff.reset();
                            }
                        }
                        DeliveryTaskOutcome::OperationFailed => {
                            dispatch_budget = 0;
                            delivery_circuit
                                .trip(Instant::now() + delivery_backoff.next_delay());
                        }
                    }
                }
                joined = &mut migration_task => {
                    match joined {
                        Ok(()) if cancellation.is_cancelled() => {
                            migration_finished = true;
                            break;
                        }
                        Ok(()) => return Err(OutboundWorkerError::MigrationTaskExited),
                        Err(_) => return Err(OutboundWorkerError::MigrationTaskPanicked),
                    }
                }
                _ = maintenance_tick.tick(), if retry_ready(maintenance_retry_at, Instant::now()) => {
                    match self.coordinator
                        .maintain_queue(
                            expired_cursor,
                            self.config.batch_size.min(MAX_BATCH_SIZE),
                            &cancellation,
                        )
                        .await
                    {
                        Ok(QueueMaintenanceOutcome { next_expired_cursor, .. }) => {
                            expired_cursor = next_expired_cursor;
                            match self.dsn_dispatcher
                                .dispatch_batch(DSN_DISPATCH_BATCH_SIZE, &cancellation)
                                .await
                            {
                                Ok(_) => {
                                    maintenance_backoff.reset();
                                    maintenance_retry_at = None;
                                }
                                Err(DsnDispatchError::Cancelled) if cancellation.is_cancelled() => break,
                                Err(error) => {
                                    eprintln!("lmyzmail outbound DSN maintenance failed: {error}");
                                    maintenance_retry_at =
                                        Some(Instant::now() + maintenance_backoff.next_delay());
                                }
                            }
                        }
                        Err(CoordinatorError::Cancelled) if cancellation.is_cancelled() => break,
                        Err(error) => {
                            eprintln!("lmyzmail outbound maintenance failed: {error}");
                            maintenance_retry_at =
                                Some(Instant::now() + maintenance_backoff.next_delay());
                        }
                    }
                }
            }
        }
        if !migration_finished
            && timeout(MIGRATION_SHUTDOWN_DEADLINE, &mut migration_task)
                .await
                .is_err()
        {
            migration_task.abort();
            let _ = migration_task.await;
            return Err(OutboundWorkerError::ShutdownTimeout);
        }
        self.shutdown_deliveries(deliveries).await
    }

    async fn shutdown_deliveries(
        &self,
        mut deliveries: JoinSet<(bool, Result<CoordinatorOutcome, CoordinatorError>)>,
    ) -> Result<(), OutboundWorkerError> {
        let deadline = Instant::now() + SHUTDOWN_DEADLINE;
        while !deliveries.is_empty() {
            let joined = match timeout_at(deadline, deliveries.join_next()).await {
                Ok(joined) => joined,
                Err(_) => {
                    deliveries.abort_all();
                    while deliveries.join_next().await.is_some() {}
                    return Err(OutboundWorkerError::ShutdownTimeout);
                }
            };
            let _ = handle_delivery_result(joined)?;
        }
        Ok(())
    }
}

async fn run_legacy_migration(
    migrator: LegacyQueueMigrator,
    batch_size: usize,
    cancellation: CancellationToken,
) {
    let mut tick = interval(LEGACY_MIGRATION_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut backoff = OperationBackoff::default();
    let mut unhealthy = false;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tick.tick() => {
                match migrator.migrate_batch(batch_size, &cancellation).await {
                    Ok(_) => {
                        if unhealthy {
                            eprintln!("lmyzmail legacy outbound migration recovered");
                        }
                        unhealthy = false;
                        backoff.reset();
                    }
                    Err(LegacyMigrationError::Cancelled) if cancellation.is_cancelled() => return,
                    Err(error) => {
                        eprintln!("lmyzmail legacy outbound migration failed: {error}");
                        unhealthy = true;
                        let delay = backoff.next_jittered_delay();
                        tokio::select! {
                            _ = cancellation.cancelled() => return,
                            _ = sleep(delay) => {}
                        }
                    }
                }
            }
        }
    }
}

async fn wait_for_claim_signal(
    receiver: &mut Option<oneshot::Receiver<bool>>,
) -> Result<bool, oneshot::error::RecvError> {
    receiver
        .as_mut()
        .expect("claim signal is guarded by select")
        .await
}

fn handle_delivery_result(
    joined: Option<DeliveryJoinResult>,
) -> Result<(bool, DeliveryTaskOutcome), OutboundWorkerError> {
    match joined {
        Some(Ok((probe, Ok(_)))) => Ok((probe, DeliveryTaskOutcome::Completed)),
        Some(Ok((probe, Err(CoordinatorError::Cancelled)))) => {
            Ok((probe, DeliveryTaskOutcome::Completed))
        }
        Some(Ok((probe, Err(error)))) => {
            eprintln!("lmyzmail outbound delivery failed: {error}");
            Ok((probe, DeliveryTaskOutcome::OperationFailed))
        }
        Some(Err(error)) if error.is_cancelled() => Ok((false, DeliveryTaskOutcome::Completed)),
        Some(Err(_)) => Err(OutboundWorkerError::DeliveryTaskPanicked),
        None => Ok((false, DeliveryTaskOutcome::Completed)),
    }
}

fn retry_ready(retry_at: Option<Instant>, now: Instant) -> bool {
    retry_at.is_none_or(|retry_at| retry_at <= now)
}

fn property_usize(
    config: &RuntimeConfig,
    new: &str,
    legacy: &str,
    default: usize,
) -> Result<usize, OutboundWorkerError> {
    config
        .preferred_value(new, legacy)
        .map(str::parse)
        .transpose()
        .map_err(|_| OutboundWorkerError::Configuration("outbound worker property is invalid"))
        .map(|value| value.unwrap_or(default))
}

fn property_u64(
    config: &RuntimeConfig,
    new: &str,
    legacy: &str,
    default: u64,
) -> Result<u64, OutboundWorkerError> {
    config
        .preferred_value(new, legacy)
        .map(str::parse)
        .transpose()
        .map_err(|_| OutboundWorkerError::Configuration("outbound worker property is invalid"))
        .map(|value| value.unwrap_or(default))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Properties;

    #[test]
    fn worker_configuration_preserves_legacy_defaults_and_new_precedence() {
        let properties = Properties::parse(
            b"botmail.queue.max-concurrent-sends=12\n\
              lmyzmail.queue.max-concurrent-sends=8\n\
              botmail.queue.batch-size=7\n\
              lmyzmail.queue.poll-interval-ms=25\n\
              botmail.queue.persist.batch-size=33\n",
        )
        .unwrap();
        let runtime = RuntimeConfig::from_properties(properties).unwrap();
        assert_eq!(
            OutboundWorkerConfig::from_config(&runtime).unwrap(),
            OutboundWorkerConfig {
                max_concurrent_sends: 8,
                batch_size: 7,
                poll_interval: Duration::from_millis(25),
                migration_batch_size: 33,
            }
        );
        assert!(
            OutboundWorkerConfig::from_config(
                &RuntimeConfig::from_properties(
                    Properties::parse(b"lmyzmail.queue.max-concurrent-sends=0\n").unwrap()
                )
                .unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn operation_backoff_grows_to_a_hard_cap_and_resets() {
        let mut backoff = OperationBackoff::default();
        let delays = (0..8).map(|_| backoff.next_delay()).collect::<Vec<_>>();
        assert_eq!(
            delays,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(30),
                Duration::from_secs(30),
                Duration::from_secs(30),
            ]
        );
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn equal_jitter_stays_within_the_upper_half_of_each_backoff() {
        for base in [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(30),
        ] {
            let low = equal_jitter(base, 0);
            let high = equal_jitter(base, u64::MAX);
            assert!(low >= base / 2 && low <= base);
            assert!(high >= base / 2 && high <= base);
        }
    }

    #[test]
    fn retry_deadline_blocks_until_it_elapses() {
        let now = Instant::now();
        assert!(retry_ready(None, now));
        assert!(!retry_ready(Some(now + Duration::from_secs(1)), now));
        assert!(retry_ready(Some(now), now));
    }

    #[test]
    fn delivery_circuit_requires_one_successful_half_open_probe() {
        let now = Instant::now();
        let retry_at = now + Duration::from_secs(1);
        let mut circuit = DeliveryCircuit::default();
        assert!(circuit.is_closed());

        circuit.trip(retry_at);
        circuit.advance(now);
        assert_eq!(circuit, DeliveryCircuit::Backoff { retry_at });
        assert!(!circuit.half_open_probe_ready());

        circuit.advance(retry_at);
        assert!(circuit.half_open_probe_ready());
        assert!(circuit.start_half_open_probe());
        assert_eq!(circuit, DeliveryCircuit::HalfOpenProbe);
        assert!(!circuit.start_half_open_probe());
        assert!(!circuit.is_closed());

        circuit.close();
        assert!(circuit.is_closed());
    }

    #[test]
    fn failed_half_open_probe_returns_to_backoff() {
        let now = Instant::now();
        let mut circuit = DeliveryCircuit::HalfOpenWaiting;
        assert!(circuit.start_half_open_probe());
        circuit.trip(now + Duration::from_secs(2));
        assert!(!circuit.is_closed());
        assert!(!circuit.half_open_probe_ready());
        circuit.advance(now + Duration::from_secs(2));
        assert!(circuit.half_open_probe_ready());
    }
}
