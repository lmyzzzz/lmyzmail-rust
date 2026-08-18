use std::{
    fmt,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write as _},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering},
    },
    time::Duration,
};

use futures_util::{StreamExt, stream};
use serde::Serialize;
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{Instant, sleep, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{AuthError, AuthService},
    bounded_blocking::{BoundedBlockingPool, SubmitError},
    config::{RuntimeConfig, StressConfig},
    mailbox::MailboxService,
    outbound::{
        OutboundError, OutboundService, SendRequest, StreamingTextInput, StressEnqueueError,
        StressTaskIdentity, StressTaskIdentitySink,
    },
};

const IN_MEMORY_THRESHOLD_BYTES: usize = 20 * 1024;
const DEFAULT_MAX_CONCURRENCY: usize = 1_500;
const BODY_WORKERS: usize = 4;
const OUTBOUND_QUEUE_CAPACITY: usize = 64;
// Each active enqueue owns at most one body generation, materialization, or
// rollback job. Keep admission bounded while covering the endpoint's largest
// frozen concurrency tier; the separate byte semaphore bounds payload memory.
const BODY_QUEUE_CAPACITY: usize = DEFAULT_MAX_CONCURRENCY;
const BODY_MEMORY_BUDGET_BYTES: usize = 1024 * 1024 * 1024;
const STREAMING_BODY_BUFFER_BYTES: usize = 32 * 1024;
const STREAMING_BODY_HEADER_BYTES: usize = 512;
// Outbound persistence currently materializes streaming text after generation, so
// admission must cover the complete body plus the bounded writer/header scratch.
const STREAMING_BODY_SCRATCH_BYTES: usize =
    STREAMING_BODY_BUFFER_BYTES + STREAMING_BODY_HEADER_BYTES;
const QUEUE_WAIT: Duration = Duration::from_secs(30 * 60);
const DELIVERY_WAIT: Duration = Duration::from_secs(20 * 60);
const DELIVERY_POLL: Duration = Duration::from_secs(1);
const DELIVERY_STABLE_POLLS: usize = 2;
const TASK_QUIESCENCE_BATCH_SIZE: usize = 512;
const TASK_QUIESCENCE_POLL: Duration = Duration::from_millis(250);
const DEFERRED_RECOVERY_RETRY: Duration = Duration::from_secs(1);
const DEFERRED_RECOVERY_MAX_RETRY: Duration = Duration::from_secs(30);
const FINAL_CLEANUP_BASE_SECONDS: u64 = 10;
const FINAL_CLEANUP_BASE_SECONDS_DURATION: Duration =
    Duration::from_secs(FINAL_CLEANUP_BASE_SECONDS);
const FINAL_CLEANUP_MAX_SECONDS: u64 = 90;
const CLEANUP_MAILBOX_COPIES: u64 = 2;
const CLEANUP_MESSAGES_PER_SECOND: u64 = 20_000;
const CLEANUP_BYTES_PER_SECOND: u64 = 500_000_000;
const TEMP_CLEANUP_DEADLINE: Duration = Duration::from_secs(5);
const BLOCKING_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
const BLOCKING_QUIESCENCE_DEADLINE: Duration = Duration::from_secs(5);
const MAX_CLEANUP_ENTRIES: usize = 1_100_000;
const FILLER: &str = "The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet. ";
static LAST_RUN_MARKER: AtomicI64 = AtomicI64::new(0);

#[derive(Debug)]
pub(crate) enum StressError {
    Disabled,
    Busy,
    NoDomain,
    Cancelled,
    Backend,
}

impl fmt::Display for StressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("stress test endpoint is disabled"),
            Self::Busy => formatter.write_str("stress test concurrency limit reached"),
            Self::NoDomain => formatter.write_str("no stress test domain configured"),
            Self::Cancelled => formatter.write_str("stress test cancelled"),
            Self::Backend => formatter.write_str("stress test backend unavailable"),
        }
    }
}

impl std::error::Error for StressError {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StressStartResponse {
    message: &'static str,
    round: i32,
    mode: &'static str,
    email_count: i32,
    #[serde(rename = "emailSizeKB")]
    email_size_kb: i32,
    max_concurrency: usize,
    warmup_rounds_remaining: i32,
    in_memory_mode: bool,
    #[serde(rename = "inMemoryThresholdKB")]
    in_memory_threshold_kb: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StressStatusResponse {
    completed_rounds: i32,
    warmup_rounds: i32,
    warmup_remaining: i32,
    next_mode: &'static str,
    next_count: i32,
    warmup_count: i32,
    production_count: i32,
    #[serde(rename = "emailSizeKB")]
    email_size_kb: i32,
    max_concurrency: usize,
    streaming_enabled: bool,
    in_memory_mode: bool,
    #[serde(rename = "inMemoryThresholdKB")]
    in_memory_threshold_kb: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StressResetResponse {
    message: &'static str,
    previous_round: i32,
    warmup_rounds: i32,
}

#[derive(Debug, Serialize)]
pub(crate) struct StressCleanupResponse {
    pub(crate) message: String,
}

struct RunCounters {
    queued: std::sync::atomic::AtomicUsize,
    failed: std::sync::atomic::AtomicUsize,
    first_failure: OnceLock<String>,
    tasks: StressTaskIdentitySink,
}

impl RunCounters {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            queued: std::sync::atomic::AtomicUsize::new(0),
            failed: std::sync::atomic::AtomicUsize::new(0),
            first_failure: OnceLock::new(),
            tasks: StressTaskIdentitySink::with_capacity(capacity),
        }
    }

    fn record_failure(&self, reason: impl Into<String>) {
        self.failed.fetch_add(1, Ordering::Relaxed);
        let _ = self.first_failure.set(reason.into());
    }

    fn queue_target(&self, requested: usize) -> Result<i64, StressError> {
        let queued = self.queued_count();
        let failed = self.failed_count();
        if queued != requested || failed != 0 {
            eprintln!(
                "lmyzmail stress enqueue failed: requested={requested}, queued={queued}, \
                 failed={failed}, first_failure={}",
                self.first_failure
                    .get()
                    .map(String::as_str)
                    .unwrap_or("unrecorded")
            );
            return Err(StressError::Backend);
        }
        i64::try_from(requested).map_err(|_| StressError::Backend)
    }

    fn queued_target(&self) -> Result<i64, StressError> {
        i64::try_from(self.queued_count()).map_err(|_| StressError::Backend)
    }

    fn queued_count(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    fn failed_count(&self) -> usize {
        self.failed.load(Ordering::Relaxed)
    }

    fn record_task(&self, task: StressTaskIdentity) {
        let _ = self.tasks.record(task);
    }

    fn task_sink(&self) -> StressTaskIdentitySink {
        self.tasks.clone()
    }

    fn task_snapshot(&self) -> Result<Vec<StressTaskIdentity>, StressError> {
        self.tasks.snapshot().map_err(|()| StressError::Backend)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeliveryOutcome {
    delivered: i64,
    timed_out: bool,
}

struct DeliveryWaitContext<'a> {
    receiver: &'a str,
    baseline: i64,
    subject_suffix: &'a str,
    target: i64,
    requested: usize,
    started: Instant,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StressPhase {
    Enqueue,
    DeliveryWait,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StressSchedule {
    active_enqueue_cap: usize,
}

impl StressSchedule {
    fn for_email_size_kb(email_size_kb: i32) -> Self {
        Self {
            active_enqueue_cap: max_concurrency(email_size_kb),
        }
    }

    fn active_job_cap(self, phase: StressPhase) -> usize {
        match phase {
            StressPhase::Enqueue => self.active_enqueue_cap,
            StressPhase::DeliveryWait => 0,
        }
    }
}

struct StressInner {
    config: StressConfig,
    send_domain: Option<Arc<str>>,
    receive_domain: Option<Arc<str>>,
    temp_dir: PathBuf,
    auth: Arc<AuthService>,
    mailbox: Arc<MailboxService>,
    outbound: Arc<OutboundService>,
    round: AtomicI32,
    active: Arc<Semaphore>,
    blocking_admission: Arc<Semaphore>,
    body_memory: Arc<Semaphore>,
    blocking_pool: Arc<BoundedBlockingPool>,
    outbound_admission: Arc<Semaphore>,
    outbound_blocking_pool: Arc<BoundedBlockingPool>,
    tasks: Mutex<JoinSet<()>>,
    quiescence_tasks: Mutex<JoinSet<()>>,
    clean: AtomicBool,
    cancellation: CancellationToken,
}

#[derive(Clone)]
pub(crate) struct StressService {
    inner: Arc<StressInner>,
}

impl StressService {
    pub(crate) fn from_config(
        config: &RuntimeConfig,
        auth: Arc<AuthService>,
        mailbox: Arc<MailboxService>,
        outbound: Arc<OutboundService>,
        cancellation: CancellationToken,
    ) -> io::Result<Self> {
        let outbound_workers =
            outbound_worker_count(config.stress.email_size_kb, config.storage.fsync_enabled);
        let blocking_pool = Arc::new(BoundedBlockingPool::new(
            "lmyzmail-stress-body",
            BODY_WORKERS,
            BODY_QUEUE_CAPACITY,
        )?);
        let outbound_blocking_pool = Arc::new(BoundedBlockingPool::new(
            "lmyzmail-stress-outbound",
            outbound_workers,
            OUTBOUND_QUEUE_CAPACITY,
        )?);
        let (send_domain, receive_domain) = stress_domains(config);
        Ok(Self {
            inner: Arc::new(StressInner {
                config: config.stress.clone(),
                send_domain: send_domain.map(Arc::from),
                receive_domain: receive_domain.map(Arc::from),
                temp_dir: config.maildir.join(".lmyzmail-stress"),
                auth,
                mailbox,
                outbound,
                round: AtomicI32::new(0),
                active: Arc::new(Semaphore::new(1)),
                blocking_admission: Arc::new(Semaphore::new(BODY_QUEUE_CAPACITY)),
                body_memory: Arc::new(Semaphore::new(BODY_MEMORY_BUDGET_BYTES)),
                blocking_pool,
                outbound_admission: Arc::new(Semaphore::new(outbound_workers)),
                outbound_blocking_pool,
                tasks: Mutex::new(JoinSet::new()),
                quiescence_tasks: Mutex::new(JoinSet::new()),
                clean: AtomicBool::new(false),
                cancellation,
            }),
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        self.inner.config.enabled
    }

    pub(crate) async fn recover_stale_state(
        &self,
        cancellation: &CancellationToken,
    ) -> io::Result<()> {
        let temp_dir = self.inner.temp_dir.clone();
        match self
            .run_blocking(cancellation, move |job_cancellation| {
                remove_tree(&temp_dir, &job_cancellation)
            })
            .await
        {
            Ok(result) => result?,
            Err(StressError::Cancelled) => {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "stress state recovery cancelled",
                ));
            }
            Err(error) => return Err(io::Error::other(error)),
        }
        let (sender, receiver) = self.optional_addresses();
        if let Some(sender) = sender.as_deref() {
            let active_tasks = self
                .inner
                .outbound
                .stress_active_tasks(sender, cancellation)
                .await
                .map_err(io::Error::other)?;
            wait_for_task_quiescence(
                &self.inner.outbound,
                &active_tasks,
                Instant::now() + DELIVERY_WAIT,
                cancellation,
            )
            .await
            .map_err(io::Error::other)?;
        }
        match (sender.as_deref(), receiver.as_deref()) {
            (Some(sender), Some(receiver)) => self
                .cleanup_addresses_best_effort(sender, receiver, cancellation, None)
                .await
                .map_err(io::Error::other)?,
            (Some(address), None) | (None, Some(address)) => self
                .cleanup_address_result(address, cancellation)
                .await
                .map_err(io::Error::other)?,
            (None, None) => {}
        }
        self.inner.clean.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn status(&self) -> Result<StressStatusResponse, StressError> {
        self.require_enabled()?;
        let current = self.inner.round.load(Ordering::SeqCst);
        let warmup = current < self.inner.config.warmup_rounds;
        let in_memory = self.in_memory_mode();
        Ok(StressStatusResponse {
            completed_rounds: current,
            warmup_rounds: self.inner.config.warmup_rounds,
            warmup_remaining: self
                .inner
                .config
                .warmup_rounds
                .saturating_sub(current)
                .max(0),
            next_mode: if warmup { "WARMUP" } else { "PRODUCTION" },
            next_count: if warmup {
                self.inner.config.warmup_count
            } else {
                self.inner.config.production_count
            },
            warmup_count: self.inner.config.warmup_count,
            production_count: self.inner.config.production_count,
            email_size_kb: self.inner.config.email_size_kb,
            max_concurrency: StressSchedule::for_email_size_kb(self.inner.config.email_size_kb)
                .active_job_cap(StressPhase::Enqueue),
            streaming_enabled: !in_memory,
            in_memory_mode: in_memory,
            in_memory_threshold_kb: IN_MEMORY_THRESHOLD_BYTES / 1024,
        })
    }

    pub(crate) fn reset(&self) -> Result<StressResetResponse, StressError> {
        self.require_enabled()?;
        Ok(StressResetResponse {
            message: "Round counter reset to 0",
            previous_round: self.inner.round.swap(0, Ordering::SeqCst),
            warmup_rounds: self.inner.config.warmup_rounds,
        })
    }

    pub(crate) async fn start(&self) -> Result<StressStartResponse, StressError> {
        self.require_enabled()?;
        if self.addresses().is_none() {
            return Err(StressError::NoDomain);
        }
        let active = self
            .inner
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| StressError::Busy)?;
        if self
            .inner
            .clean
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            drop(active);
            return Err(StressError::Backend);
        }
        let current = self.inner.round.fetch_add(1, Ordering::SeqCst);
        let warmup = current < self.inner.config.warmup_rounds;
        let email_count = if warmup {
            self.inner.config.warmup_count
        } else {
            self.inner.config.production_count
        };
        let schedule = StressSchedule::for_email_size_kb(self.inner.config.email_size_kb);
        let max_concurrency = schedule.active_job_cap(StressPhase::Enqueue);
        let in_memory = self.in_memory_mode();
        let response = StressStartResponse {
            message: if in_memory {
                "Stress test started (in-memory mode). Check logs (at ERROR level) for progress."
            } else {
                "Stress test started (streaming mode). Check logs (at ERROR level) for progress."
            },
            round: current.wrapping_add(1),
            mode: if warmup { "WARMUP" } else { "PRODUCTION" },
            email_count,
            email_size_kb: self.inner.config.email_size_kb,
            max_concurrency,
            warmup_rounds_remaining: self
                .inner
                .config
                .warmup_rounds
                .saturating_sub(current)
                .saturating_sub(1)
                .max(0),
            in_memory_mode: in_memory,
            in_memory_threshold_kb: IN_MEMORY_THRESHOLD_BYTES / 1024,
        };

        let inner = Arc::clone(&self.inner);
        let mut tasks = self.inner.tasks.lock().await;
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            run_stress(inner, active, current, warmup, email_count, schedule).await;
        });
        Ok(response)
    }

    pub(crate) async fn cleanup(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<StressCleanupResponse, StressError> {
        self.require_enabled()?;
        let active = self
            .inner
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| StressError::Busy)?;
        let (sender, receiver) = self.addresses().ok_or(StressError::NoDomain)?;
        self.inner.clean.store(false, Ordering::Release);
        let active_tasks = match self
            .inner
            .outbound
            .stress_active_tasks(&sender, cancellation)
            .await
        {
            Ok(tasks) => tasks,
            Err(_) => {
                retain_active_for_recovery(
                    Arc::clone(&self.inner),
                    active,
                    sender,
                    receiver,
                    None,
                    FINAL_CLEANUP_BASE_SECONDS_DURATION,
                )
                .await;
                return Err(StressError::Backend);
            }
        };
        let deadline = Instant::now() + FINAL_CLEANUP_BASE_SECONDS_DURATION;
        let cleanup_result = finish_cleanup_attempt(
            &self.inner,
            &sender,
            &receiver,
            Some(&active_tasks),
            deadline,
            cancellation,
        )
        .await;
        if let Err(error) = cleanup_result {
            retain_active_for_recovery(
                Arc::clone(&self.inner),
                active,
                sender,
                receiver,
                Some(active_tasks),
                FINAL_CLEANUP_BASE_SECONDS_DURATION,
            )
            .await;
            return Err(error);
        }
        self.inner.clean.store(true, Ordering::Release);
        drop(active);
        Ok(StressCleanupResponse {
            message: format!("Cleanup completed for {sender} and {receiver}"),
        })
    }

    pub(crate) async fn shutdown(&self, deadline: Instant) -> bool {
        self.inner.cancellation.cancel();
        shutdown_task_set(&self.inner.tasks, deadline).await;
        shutdown_task_set(&self.inner.quiescence_tasks, deadline).await;
        let blocking_deadline = deadline
            .saturating_duration_since(Instant::now())
            .min(BLOCKING_SHUTDOWN_DEADLINE);
        let (body_quiesced, outbound_quiesced) = tokio::join!(
            self.inner.blocking_pool.shutdown_strict(blocking_deadline),
            self.inner
                .outbound_blocking_pool
                .shutdown_strict(blocking_deadline),
        );
        if !body_quiesced {
            eprintln!(
                "lmyzmail stress body blocking pool did not quiesce before the shutdown deadline"
            );
        }
        if !outbound_quiesced {
            eprintln!(
                "lmyzmail stress outbound blocking pool did not quiesce before the shutdown deadline"
            );
        }
        body_quiesced && outbound_quiesced
    }

    fn require_enabled(&self) -> Result<(), StressError> {
        if self.enabled() {
            Ok(())
        } else {
            Err(StressError::Disabled)
        }
    }

    fn in_memory_mode(&self) -> bool {
        usize::try_from(self.inner.config.email_size_kb)
            .unwrap_or_default()
            .saturating_mul(1024)
            <= IN_MEMORY_THRESHOLD_BYTES
    }

    fn addresses(&self) -> Option<(String, String)> {
        let (sender, receiver) = self.optional_addresses();
        Some((sender?, receiver?))
    }

    fn optional_addresses(&self) -> (Option<String>, Option<String>) {
        (
            self.inner
                .send_domain
                .as_deref()
                .map(|domain| format!("{}@{domain}", self.inner.config.sender_prefix)),
            self.inner
                .receive_domain
                .as_deref()
                .map(|domain| format!("{}@{domain}", self.inner.config.receiver_prefix)),
        )
    }

    async fn cleanup_address_result(
        &self,
        address: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), StressError> {
        self.cleanup_address_result_with_deadline(address, cancellation, None)
            .await
    }

    async fn cleanup_address_result_with_deadline(
        &self,
        address: &str,
        cancellation: &CancellationToken,
        database_deadline: Option<Instant>,
    ) -> Result<(), StressError> {
        let Ok(path) = self.inner.mailbox.user_directory(address) else {
            return Err(StressError::Backend);
        };
        let index_cleanup = async {
            if let Some(deadline) = database_deadline {
                self.inner
                    .mailbox
                    .delete_indexes_for_mailbox_with_deadline(address, cancellation, deadline)
                    .await
            } else {
                self.inner
                    .mailbox
                    .delete_indexes_for_mailbox(address, cancellation)
                    .await
            }
        };
        let file_cleanup = self.run_blocking(cancellation, move |job_cancellation| {
            remove_tree(&path, &job_cancellation)
        });
        let (index_result, file_result) = tokio::join!(index_cleanup, file_cleanup);
        if index_result.is_err() || !matches!(file_result, Ok(Ok(()))) {
            return Err(StressError::Backend);
        }
        Ok(())
    }

    async fn cleanup_addresses_best_effort(
        &self,
        sender: &str,
        receiver: &str,
        cancellation: &CancellationToken,
        database_deadline: Option<Instant>,
    ) -> Result<(), StressError> {
        let (sender_result, receiver_result) = run_best_effort_pair(
            self.cleanup_address_result_with_deadline(sender, cancellation, database_deadline),
            self.cleanup_address_result_with_deadline(receiver, cancellation, database_deadline),
        )
        .await;
        combine_cleanup_results(sender_result, receiver_result)
    }

    async fn run_blocking<T, F>(
        &self,
        cancellation: &CancellationToken,
        work: F,
    ) -> Result<T, StressError>
    where
        T: Send + 'static,
        F: FnOnce(CancellationToken) -> T + Send + 'static,
    {
        run_blocking(&self.inner, cancellation, work).await
    }
}

async fn shutdown_task_set(tasks: &Mutex<JoinSet<()>>, deadline: Instant) {
    let mut tasks = tasks.lock().await;
    if timeout_at(deadline, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

async fn run_best_effort_pair<A, B>(first: A, second: B) -> (A::Output, B::Output)
where
    A: std::future::Future,
    B: std::future::Future,
{
    tokio::join!(first, second)
}

fn combine_cleanup_results(
    sender: Result<(), StressError>,
    receiver: Result<(), StressError>,
) -> Result<(), StressError> {
    match (sender, receiver) {
        (Ok(()), Ok(())) => Ok(()),
        (sender, receiver) => {
            eprintln!("lmyzmail stress cleanup errors: sender={sender:?}, receiver={receiver:?}");
            Err(StressError::Backend)
        }
    }
}

async fn run_stress(
    inner: Arc<StressInner>,
    active: OwnedSemaphorePermit,
    round: i32,
    warmup: bool,
    email_count: i32,
    schedule: StressSchedule,
) {
    let service = StressService {
        inner: Arc::clone(&inner),
    };
    let Some((sender, receiver)) = service.addresses() else {
        eprintln!(
            "lmyzmail stress round {} failed before completion: no stress test domain configured",
            round.wrapping_add(1)
        );
        return;
    };
    let cancellation = inner.cancellation.child_token();
    let run_marker = next_run_marker();
    let subject_suffix = format!(" - {run_marker}");
    let requested = usize::try_from(email_count.max(0)).unwrap_or_default();
    let counters = Arc::new(RunCounters::with_capacity(requested));
    let mode = if warmup { "WARMUP" } else { "PRODUCTION" };
    eprintln!(
        "========== [STRESS TEST] ROUND {} ({mode}) STARTING ==========",
        round.wrapping_add(1)
    );
    let result =
        async {
            ensure_mailbox(&inner.auth, &sender, &inner.config.password, &cancellation).await?;
            ensure_mailbox(
                &inner.auth,
                &receiver,
                &inner.config.password,
                &cancellation,
             )
             .await?;
            let stale_tasks = inner
                .outbound
                .stress_active_tasks(&sender, &cancellation)
                .await
                .map_err(|_| StressError::Backend)?;
            if !stale_tasks.is_empty() {
                eprintln!(
                    "lmyzmail stress clean-state gate found {} active outbound tasks",
                    stale_tasks.len()
                );
                for task in stale_tasks {
                    counters.record_task(task);
                }
                return Err(StressError::Backend);
            }
            let sender_before = inner
                .mailbox
                .count_folder(&sender, "sent", &cancellation)
                .await
                .map_err(|_| StressError::Backend)?;
            let receiver_before = inner
                .mailbox
                .count_folder_run_marker(
                    &receiver,
                    "inbox",
                    &subject_suffix,
                    &cancellation,
                )
                .await
                .map_err(|_| StressError::Backend)?;
            if sender_before != 0 || receiver_before.total != 0 || receiver_before.matching != 0 {
                eprintln!(
                    "lmyzmail stress clean-state gate rejected residual mail: \
                     sender_sent={sender_before}, receiver_inbox={}, marker_matches={}",
                    receiver_before.total,
                    receiver_before.matching,
                );
                return Err(StressError::Backend);
            }
            let receiver_baseline = receiver_before.total;
            eprintln!(
                "[STRESS TEST] Config: Round={}, Mode={mode}, Sender={sender}, Receiver={receiver}, \
                 Count={email_count}, EmailSize={}KB, MaxConcurrency={}, InMemory={}",
                round.wrapping_add(1),
                inner.config.email_size_kb,
                schedule.active_job_cap(StressPhase::Enqueue),
                inner.config.email_size_kb as usize * 1024 <= IN_MEMORY_THRESHOLD_BYTES,
            );
            eprintln!(
                "[STRESS TEST] Queueing {email_count} emails ({}KB each) with max concurrency {} ({} mode)...",
                inner.config.email_size_kb,
                schedule.active_job_cap(StressPhase::Enqueue),
                if inner.config.email_size_kb as usize * 1024 <= IN_MEMORY_THRESHOLD_BYTES {
                    "in-memory"
                } else {
                    "streaming"
                },
            );
            let started = Instant::now();
            let queue_input_cancellation = cancellation.clone();
            let queueing = stream::iter(0..email_count)
            .take_until(queue_input_cancellation.cancelled_owned())
            .for_each_concurrent(
                Some(schedule.active_job_cap(StressPhase::Enqueue)),
                |index| {
                let inner = Arc::clone(&inner);
                let counters = Arc::clone(&counters);
                let task_identities = counters.task_sink();
                let sender = sender.clone();
                let receiver = receiver.clone();
                let cancellation = cancellation.clone();
                async move {
                    if cancellation.is_cancelled() {
                        counters.record_failure("cancelled before body admission");
                        return;
                    }
                    let subject = format!(
                        "Stress Test R{} #{} - {run_marker}",
                        round.wrapping_add(1),
                        index
                    );
                    let body_size = usize::try_from(inner.config.email_size_kb)
                        .unwrap_or_default()
                        .saturating_mul(1024);
                    let body_permits = u32::try_from(body_memory_per_job(body_size))
                        .expect("validated stress body size fits semaphore permits");
                    let body_memory = Arc::new(tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => {
                            counters.record_failure("cancelled waiting for body memory");
                            return;
                        }
                        result = inner.body_memory.clone().acquire_many_owned(body_permits) => {
                            match result {
                                Ok(permit) => permit,
                                Err(_) => {
                                    counters.record_failure("body memory admission closed");
                                    return;
                                }
                            }
                        }
                    });
                    let worker_body_memory = Arc::clone(&body_memory);
                    let body_millis = chrono::Utc::now().timestamp_millis();
                    let temp_dir = inner.temp_dir.clone();
                    let generated = run_blocking(&inner, &cancellation, move |job_cancellation| {
                        let _body_memory = worker_body_memory;
                        if body_size <= IN_MEMORY_THRESHOLD_BYTES {
                            generate_body(
                                round,
                                mode,
                                index,
                                body_size,
                                body_millis,
                                &job_cancellation,
                            )
                            .map(GeneratedBody::Memory)
                        } else {
                            generate_body_to_file(
                                &temp_dir,
                                BodySpec {
                                    round,
                                    mode,
                                    index,
                                    size: body_size,
                                    millis: body_millis,
                                },
                                &job_cancellation,
                            )
                            .map(GeneratedBody::File)
                        }
                    })
                    .await;
                    let body = match generated {
                        Ok(Ok(body)) => body,
                        Err(error) => {
                            counters.record_failure(format!(
                                "body generation admission failed: {error}"
                            ));
                            return;
                        }
                        Ok(Err(error)) => {
                            counters.record_failure(format!("body generation failed: {error}"));
                            return;
                        }
                    };
                    let mut request = SendRequest {
                        from: Some(sender),
                        password: None,
                        to: vec![receiver],
                        cc: Vec::new(),
                        bcc: Vec::new(),
                        subject: Some(subject),
                        text: None,
                        html: None,
                        attachments: Vec::new(),
                        in_reply_to: None,
                        references: None,
                        asynchronous: Some(true),
                    };
                    let result = match body {
                        GeneratedBody::Memory(body) => {
                            request.text = Some(body);
                            let enqueue = inner
                                .outbound
                                .enqueue_stress_with_cancellation(
                                    request,
                                    &task_identities,
                                    Arc::clone(&inner.outbound_blocking_pool),
                                    Arc::clone(&inner.outbound_admission),
                                    &cancellation,
                                )
                                .await;
                            drop(body_memory);
                            enqueue
                        }
                        GeneratedBody::File(mut body) => {
                            let path = body.path().to_path_buf();
                            body.disarm();
                            let enqueue = inner
                                .outbound
                                .enqueue_stress_streaming_text_with_cancellation(
                                    request,
                                    StreamingTextInput::owned(path, body_size as u64),
                                    &task_identities,
                                    Arc::clone(&inner.outbound_blocking_pool),
                                    Arc::clone(&inner.outbound_admission),
                                    &cancellation,
                                )
                                .await;
                            drop(body_memory);
                            enqueue
                        }
                    };
                    match result {
                        Ok(_) => {
                            counters.queued.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(StressEnqueueError {
                            error,
                            stage,
                            diagnostic,
                        }) => {
                            counters.record_failure(format!(
                                "outbound enqueue failed: stage={}, diagnostic={}, error={error:?}",
                                stage.as_str(),
                                diagnostic.unwrap_or("unspecified")
                            ));
                        }
                    }
                }
            },
            );
            tokio::pin!(queueing);
            if timeout(QUEUE_WAIT, &mut queueing).await.is_err() {
                cancellation.cancel();
                if timeout(TEMP_CLEANUP_DEADLINE, &mut queueing).await.is_err() {
                    eprintln!(
                        "[STRESS TEST] Queue timed out and active enqueue jobs did not quiesce within {}s",
                        TEMP_CLEANUP_DEADLINE.as_secs()
                    );
                    return Err(StressError::Backend);
                }
                return Err(StressError::Backend);
            }
            if cancellation.is_cancelled() {
                return Err(StressError::Cancelled);
            }
            let queue_finished = Instant::now();
            let queued = counters.queued_count();
            let failed = counters.failed_count();
            let queue_duration = queue_finished.saturating_duration_since(started);
            eprintln!(
                "[STRESS TEST] Queue completed in {} ms: success={queued}, failed={failed}, \
                 exceptions=0, oom=0, rateLimited=0",
                queue_duration.as_millis()
            );
            eprintln!("[STRESS TEST] Waiting for delivery...");
            let target = counters.queued_target()?;
            debug_assert_eq!(schedule.active_job_cap(StressPhase::DeliveryWait), 0);
            let delivery = wait_for_delivery(
                &inner.mailbox,
                DeliveryWaitContext {
                    receiver: &receiver,
                    baseline: receiver_baseline,
                    subject_suffix: &subject_suffix,
                    target,
                    requested,
                    started,
                    deadline: started + DELIVERY_WAIT,
                },
                &cancellation,
            )
            .await?;
            let finished = Instant::now();
            log_stress_results(
                round,
                mode,
                warmup,
                requested,
                inner.config.email_size_kb,
                schedule.active_job_cap(StressPhase::Enqueue),
                queued,
                failed,
                delivery.delivered,
                finished.saturating_duration_since(started),
                queue_duration,
                inner.config.warmup_rounds,
                inner.config.production_count,
            );
            if delivery.timed_out {
                return Err(StressError::Backend);
            }
            // Preserve Java's drain semantics: every successfully queued message
            // reaches the mailbox before partial admission is reported as failed.
            counters.queue_target(requested)?;
            Ok::<(), StressError>(())
        }
        .await;
    if let Err(error) = &result
        && !matches!(error, StressError::Cancelled)
    {
        eprintln!(
            "lmyzmail stress round {} failed before completion: {error}",
            round.wrapping_add(1)
        );
    }
    // Shutdown cancels the round first, but bounded rollback and owned-file
    // cleanup must still run to completion after enqueue jobs have quiesced.
    let cleanup_cancellation = CancellationToken::new();
    let cleanup_budget = final_cleanup_deadline(email_count, inner.config.email_size_kb);
    let cleanup_deadline = Instant::now() + cleanup_budget;
    let task_snapshot = counters.task_snapshot().ok();
    eprintln!("[STRESS TEST] Cleaning up data...");
    let cleanup_result = finish_cleanup_attempt(
        &inner,
        &sender,
        &receiver,
        task_snapshot.as_deref(),
        cleanup_deadline,
        &cleanup_cancellation,
    )
    .await;
    if cleanup_result.is_ok() {
        inner.clean.store(true, Ordering::Release);
        eprintln!("[STRESS TEST] Cleanup finished.");
        drop(active);
    } else {
        eprintln!(
            "lmyzmail stress round {} cleanup failed; residual data may remain",
            round.wrapping_add(1)
        );
        retain_active_for_recovery(
            Arc::clone(&inner),
            active,
            sender.clone(),
            receiver.clone(),
            task_snapshot,
            cleanup_budget,
        )
        .await;
    }
    if result.is_ok() && cleanup_result.is_ok() {
        eprintln!(
            "========== [STRESS TEST] ROUND {} ({mode}) COMPLETED ==========",
            round.wrapping_add(1)
        );
    } else {
        eprintln!(
            "========== [STRESS TEST] ROUND {} ({mode}) FAILED ==========",
            round.wrapping_add(1)
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn log_stress_results(
    round: i32,
    mode: &str,
    warmup: bool,
    requested: usize,
    email_size_kb: i32,
    max_concurrency: usize,
    queued: usize,
    failed: usize,
    delivered: i64,
    total_duration: Duration,
    queue_duration: Duration,
    warmup_rounds: i32,
    production_count: i32,
) {
    let seconds = total_duration.as_secs_f64();
    let throughput = if seconds > 0.0 {
        queued as f64 / seconds
    } else {
        0.0
    };
    let data_throughput_mb = if seconds > 0.0 {
        queued as f64 * f64::from(email_size_kb) / 1024.0 / seconds
    } else {
        0.0
    };
    let lost = requested.saturating_sub(queued.saturating_add(failed));
    let delivery_duration = total_duration.saturating_sub(queue_duration);

    eprintln!("[RESULT] Round: {} ({mode})", round.wrapping_add(1));
    eprintln!("[RESULT] Target Email Count: {requested}");
    eprintln!("[RESULT] Email Size: {email_size_kb} KB");
    eprintln!("[RESULT] Max Concurrency: {max_concurrency}");
    eprintln!(
        "[RESULT] Body Generation Mode: {}",
        if email_size_kb as usize * 1024 <= IN_MEMORY_THRESHOLD_BYTES {
            "IN-MEMORY"
        } else {
            "STREAMING"
        }
    );
    eprintln!(
        "[RESULT] Actually Queued: {queued} (success={queued}, failed={failed}, \
         exceptions=0, oom=0, rateLimited=0)"
    );
    eprintln!(
        "[RESULT] Lost Count: {lost} \
         (target - success - failed - exceptions - oom) [IMPORTANT]"
    );
    eprintln!("[RESULT] Received: {delivered}");
    eprintln!(
        "[RESULT] Total Time: {} ms ({seconds:.2} s)",
        total_duration.as_millis()
    );
    eprintln!("[RESULT] Throughput: {throughput:.2} emails/second");
    eprintln!("[RESULT] Data Throughput: {data_throughput_mb:.2} MB/second");
    eprintln!("[RESULT] Queueing Time: {} ms", queue_duration.as_millis());
    eprintln!(
        "[RESULT] Delivery Time: {} ms",
        delivery_duration.as_millis()
    );
    if warmup {
        let remaining = warmup_rounds.saturating_sub(round).saturating_sub(1);
        if remaining > 0 {
            eprintln!("[RESULT] Warmup rounds remaining: {remaining}");
        } else {
            eprintln!(
                "[RESULT] Warmup complete! Next round will use production count: \
                 {production_count}"
            );
        }
    }
    eprintln!("===========================================");
}

fn next_run_marker() -> i64 {
    let now = chrono::Utc::now().timestamp_millis().max(1);
    let mut previous = LAST_RUN_MARKER.load(Ordering::Acquire);
    loop {
        let next = now.max(previous.saturating_add(1));
        match LAST_RUN_MARKER.compare_exchange_weak(
            previous,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return next,
            Err(observed) => previous = observed,
        }
    }
}

async fn wait_for_task_quiescence(
    outbound: &OutboundService,
    tasks: &[StressTaskIdentity],
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), StressError> {
    loop {
        let mut all_quiesced = true;
        for batch in tasks.chunks(TASK_QUIESCENCE_BATCH_SIZE) {
            let quiesced = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(StressError::Cancelled),
                result = timeout_at(
                    deadline,
                    outbound.stress_tasks_quiesced(batch, cancellation),
                ) => result
                    .map_err(|_| StressError::Backend)?
                    .map_err(|_| StressError::Backend)?,
            };
            if !quiesced {
                all_quiesced = false;
                break;
            }
        }
        if all_quiesced {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(StressError::Backend);
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(StressError::Cancelled),
            result = timeout_at(deadline, sleep(TASK_QUIESCENCE_POLL)) => {
                result.map_err(|_| StressError::Backend)?;
            }
        }
    }
}

async fn wait_for_blocking_quiescence(
    blocking_admission: Arc<Semaphore>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), StressError> {
    let permits = u32::try_from(BODY_QUEUE_CAPACITY).expect("blocking queue capacity fits u32");
    let deadline = deadline.min(Instant::now() + BLOCKING_QUIESCENCE_DEADLINE);
    let quiescence = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(StressError::Cancelled),
        result = timeout_at(
            deadline,
            blocking_admission.acquire_many_owned(permits),
        ) => result
            .map_err(|_| StressError::Backend)?
            .map_err(|_| StressError::Backend)?,
    };
    drop(quiescence);
    Ok(())
}

async fn finish_cleanup_attempt(
    inner: &Arc<StressInner>,
    sender: &str,
    receiver: &str,
    tasks: Option<&[StressTaskIdentity]>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), StressError> {
    let tasks = tasks.ok_or(StressError::Backend)?;
    wait_for_task_quiescence(&inner.outbound, tasks, deadline, cancellation).await?;
    let service = StressService {
        inner: Arc::clone(inner),
    };
    let temp_dir = inner.temp_dir.clone();
    let temp_cleanup = timeout_at(
        deadline,
        service.run_blocking(cancellation, move |job_cancellation| {
            remove_tree(&temp_dir, &job_cancellation)
        }),
    )
    .await
    .map_err(|_| StressError::Backend)?
    .map_err(|_| StressError::Backend)?;
    temp_cleanup.map_err(|_| StressError::Backend)?;
    timeout_at(
        deadline,
        service.cleanup_addresses_best_effort(sender, receiver, cancellation, Some(deadline)),
    )
    .await
    .map_err(|_| StressError::Backend)??;

    let mut stable_clean_polls = 0;
    while stable_clean_polls < DELIVERY_STABLE_POLLS {
        wait_for_task_quiescence(&inner.outbound, tasks, deadline, cancellation).await?;
        let (sender_count, receiver_count) = timeout_at(deadline, async {
            let sender_count = inner
                .mailbox
                .count_folder(sender, "sent", cancellation)
                .await
                .map_err(|_| StressError::Backend)?;
            let receiver_count = inner
                .mailbox
                .count_folder(receiver, "inbox", cancellation)
                .await
                .map_err(|_| StressError::Backend)?;
            Ok::<_, StressError>((sender_count, receiver_count))
        })
        .await
        .map_err(|_| StressError::Backend)??;
        stable_clean_polls =
            cleanup_stability_after_poll(stable_clean_polls, sender_count, receiver_count)?;
        if stable_clean_polls < DELIVERY_STABLE_POLLS {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(StressError::Cancelled),
                result = timeout_at(deadline, sleep(TASK_QUIESCENCE_POLL)) => {
                    result.map_err(|_| StressError::Backend)?;
                }
            }
        }
    }
    wait_for_blocking_quiescence(
        Arc::clone(&inner.blocking_admission),
        deadline,
        cancellation,
    )
    .await
}

fn cleanup_stability_after_poll(
    previous_stable_polls: usize,
    sender_count: i64,
    receiver_count: i64,
) -> Result<usize, StressError> {
    if sender_count != 0 || receiver_count != 0 {
        return Err(StressError::Backend);
    }
    Ok(previous_stable_polls.saturating_add(1))
}

async fn retain_active_for_recovery(
    inner: Arc<StressInner>,
    active: OwnedSemaphorePermit,
    sender: String,
    receiver: String,
    tasks: Option<Vec<StressTaskIdentity>>,
    attempt_budget: Duration,
) {
    let recovery_inner = Arc::clone(&inner);
    let mut quiescence_tasks = inner.quiescence_tasks.lock().await;
    while quiescence_tasks.try_join_next().is_some() {}
    quiescence_tasks.spawn(async move {
        let active = active;
        let inner = recovery_inner;
        let mut uncertain = tasks
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|identity| identity.requires_complete_rescan())
            .cloned()
            .collect::<Vec<_>>();
        let mut tasks = if uncertain.is_empty() { tasks } else { None };
        let mut retry_delay = DEFERRED_RECOVERY_RETRY;
        if tasks.is_none() {
            eprintln!(
                "lmyzmail stress task identity snapshot was unavailable; retrying complete active-task scans"
            );
        }
        loop {
            if inner.cancellation.is_cancelled() {
                drop(active);
                return;
            }
            if tasks.is_none() {
                match inner
                    .outbound
                    .stress_active_tasks(&sender, &inner.cancellation)
                    .await
                {
                    Ok(mut active_tasks) => {
                        let active_ids = active_tasks
                            .iter()
                            .map(|identity| identity.queue_id)
                            .collect::<std::collections::BTreeSet<_>>();
                        active_tasks.extend(
                            uncertain
                                .iter()
                                .filter(|identity| !active_ids.contains(&identity.queue_id))
                                .cloned(),
                        );
                        tasks = Some(active_tasks);
                        retry_delay = DEFERRED_RECOVERY_RETRY;
                    }
                    Err(_) => {
                        if !sleep_for_deferred_recovery(&inner, retry_delay).await {
                            drop(active);
                            return;
                        }
                        retry_delay = next_deferred_recovery_retry(retry_delay);
                        continue;
                    }
                }
            }
            let deadline = Instant::now() + attempt_budget;
            if finish_cleanup_attempt(
                &inner,
                &sender,
                &receiver,
                tasks.as_deref(),
                deadline,
                &inner.cancellation,
            )
            .await
            .is_ok()
            {
                inner.clean.store(true, Ordering::Release);
                drop(active);
                eprintln!("lmyzmail stress deferred cleanup reached quiescence");
                return;
            }
            // A failed proof may reflect a previously unknown enqueue or a
            // task that changed state after the snapshot. Never retry forever
            // against the same dead view.
            uncertain = tasks
                .take()
                .unwrap_or_default()
                .into_iter()
                .filter(StressTaskIdentity::requires_complete_rescan)
                .collect();
            if !sleep_for_deferred_recovery(&inner, retry_delay).await {
                drop(active);
                return;
            }
            retry_delay = next_deferred_recovery_retry(retry_delay);
        }
    });
}

async fn sleep_for_deferred_recovery(inner: &StressInner, delay: Duration) -> bool {
    tokio::select! {
        biased;
        _ = inner.cancellation.cancelled() => false,
        _ = sleep(delay) => true,
    }
}

fn next_deferred_recovery_retry(current: Duration) -> Duration {
    current.saturating_mul(2).min(DEFERRED_RECOVERY_MAX_RETRY)
}

fn stress_domains(config: &RuntimeConfig) -> (Option<&str>, Option<&str>) {
    (
        config.sendable_domains().first().copied(),
        config.receivable_domains().first().copied(),
    )
}

async fn ensure_mailbox(
    auth: &AuthService,
    address: &str,
    password: &str,
    cancellation: &CancellationToken,
) -> Result<(), StressError> {
    if auth
        .mailbox_exists_with_cancellation(address, cancellation)
        .await
        .map_err(|_| StressError::Backend)?
    {
        return Ok(());
    }
    match auth
        .create_mailbox_api_with_cancellation(address, password, "127.0.0.1", cancellation)
        .await
    {
        Ok(_) => Ok(()),
        Err(AuthError::InvalidInput(_)) => {
            match auth
                .mailbox_exists_with_cancellation(address, cancellation)
                .await
            {
                Ok(true) => Ok(()),
                _ => Err(StressError::Backend),
            }
        }
        Err(_) if cancellation.is_cancelled() => Err(StressError::Cancelled),
        Err(_) => Err(StressError::Backend),
    }
}

async fn wait_for_delivery(
    mailbox: &MailboxService,
    context: DeliveryWaitContext<'_>,
    cancellation: &CancellationToken,
) -> Result<DeliveryOutcome, StressError> {
    let DeliveryWaitContext {
        receiver,
        baseline,
        subject_suffix,
        target,
        requested,
        started,
        deadline,
    } = context;
    if target <= 0 {
        return Ok(DeliveryOutcome {
            delivered: 0,
            timed_out: false,
        });
    }
    let mut stable_polls = 0;
    let mut last_progress_second = None;
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(StressError::Cancelled),
            _ = sleep(DELIVERY_POLL) => {}
        }
        let observation = mailbox
            .count_folder_run_marker(receiver, "inbox", subject_suffix, cancellation)
            .await
            .map_err(|_| StressError::Backend)?;
        let (delivered, next_stable_polls, stable) = delivery_stability_after_poll(
            stable_polls,
            baseline,
            observation.total,
            observation.matching,
            target,
        )?;
        stable_polls = next_stable_polls;
        let elapsed_seconds = Instant::now().saturating_duration_since(started).as_secs();
        if elapsed_seconds.is_multiple_of(5) && last_progress_second != Some(elapsed_seconds) {
            eprintln!(
                "[STRESS TEST] Progress: {delivered}/{requested} received \
                 ({elapsed_seconds}s elapsed, target={target})"
            );
            last_progress_second = Some(elapsed_seconds);
        }
        if stable {
            return Ok(DeliveryOutcome {
                delivered,
                timed_out: false,
            });
        }
        if Instant::now() >= deadline {
            eprintln!(
                "[STRESS TEST] TIMED OUT waiting for delivery! Received: \
                 {delivered}/{requested} (queued: {target})"
            );
            return Ok(DeliveryOutcome {
                delivered,
                timed_out: true,
            });
        }
    }
}

fn delivery_stability_after_poll(
    previous_stable_polls: usize,
    baseline: i64,
    total: i64,
    matching: i64,
    target: i64,
) -> Result<(i64, usize, bool), StressError> {
    let delta = total.checked_sub(baseline).ok_or(StressError::Backend)?;
    if baseline < 0
        || target < 0
        || delta < 0
        || matching < 0
        || matching > delta
        || matching > target
        || delta > target
    {
        return Err(StressError::Backend);
    }
    let stable_polls = if matching == target && delta == target {
        previous_stable_polls.saturating_add(1)
    } else {
        0
    };
    Ok((
        matching,
        stable_polls,
        stable_polls >= DELIVERY_STABLE_POLLS,
    ))
}

async fn run_blocking<T, F>(
    inner: &StressInner,
    cancellation: &CancellationToken,
    work: F,
) -> Result<T, StressError>
where
    T: Send + 'static,
    F: FnOnce(CancellationToken) -> T + Send + 'static,
{
    let permit = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(StressError::Cancelled),
        result = inner.blocking_admission.clone().acquire_owned() => {
            result.map_err(|_| StressError::Backend)?
        }
    };
    let job_cancellation = cancellation.clone();
    let receiver = inner
        .blocking_pool
        .submit(move || {
            let _permit = permit;
            work(job_cancellation)
        })
        .map_err(|error| match error {
            SubmitError::Closed | SubmitError::Full => StressError::Backend,
        })?;
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(StressError::Cancelled),
        result = receiver => result.map_err(|_| StressError::Backend)?,
    };
    if cancellation.is_cancelled() {
        return Err(StressError::Cancelled);
    }
    Ok(result)
}

fn max_concurrency(email_size_kb: i32) -> usize {
    match email_size_kb {
        10_000.. => 80,
        5_000.. => 120,
        1_000.. => 200,
        100.. => 400,
        10.. => 1_000,
        _ => DEFAULT_MAX_CONCURRENCY,
    }
}

fn outbound_worker_count(email_size_kb: i32, filesystem_fsync_enabled: bool) -> usize {
    if email_size_kb >= 1_000 {
        4
    } else if filesystem_fsync_enabled {
        8
    } else {
        32
    }
}

fn body_memory_per_job(body_size: usize) -> usize {
    if body_size <= IN_MEMORY_THRESHOLD_BYTES {
        body_size
    } else {
        body_size.saturating_add(STREAMING_BODY_SCRATCH_BYTES)
    }
}

fn final_cleanup_deadline(email_count: i32, email_size_kb: i32) -> Duration {
    let message_count = u64::try_from(email_count.max(0)).unwrap_or_default();
    let message_bytes = u64::try_from(email_size_kb.max(0))
        .unwrap_or_default()
        .saturating_mul(1024);
    let cleanup_items = message_count.saturating_mul(CLEANUP_MAILBOX_COPIES);
    let total_bytes = cleanup_items.saturating_mul(message_bytes);
    let message_seconds = cleanup_items.div_ceil(CLEANUP_MESSAGES_PER_SECOND);
    let byte_seconds = total_bytes.div_ceil(CLEANUP_BYTES_PER_SECOND);
    Duration::from_secs(
        FINAL_CLEANUP_BASE_SECONDS
            .saturating_add(message_seconds)
            .saturating_add(byte_seconds)
            .min(FINAL_CLEANUP_MAX_SECONDS),
    )
}

fn generate_body(
    round: i32,
    mode: &str,
    index: i32,
    size: usize,
    millis: i64,
    cancellation: &CancellationToken,
) -> Result<String, StressError> {
    let mut body = String::with_capacity(size.saturating_add(256));
    let _ = write!(
        body,
        "=== Stress Test Email ===\r\n\
         Round: {}\r\n\
         Mode: {mode}\r\n\
         Index: {index}\r\n\
         Timestamp: {millis}\r\n\
         Target Size: {} KB\r\n\
         Generation: {}\r\n\
         =========================\r\n\r\n",
        round.wrapping_add(1),
        size / 1024,
        if size <= IN_MEMORY_THRESHOLD_BYTES {
            "IN-MEMORY"
        } else {
            "STREAMING"
        },
    );
    let mut remaining = size.saturating_sub(body.len());
    let mut line_length = 0_usize;
    while remaining > 0 {
        if cancellation.is_cancelled() {
            return Err(StressError::Cancelled);
        }
        let count = FILLER.len().min(remaining);
        body.push_str(&FILLER[..count]);
        remaining -= count;
        line_length += count;
        if line_length >= 70 && remaining > 2 {
            body.push_str("\r\n");
            remaining -= 2;
            line_length = 0;
        }
    }
    Ok(body)
}

enum GeneratedBody {
    Memory(String),
    File(TempBody),
}

#[derive(Clone, Copy)]
struct BodySpec<'a> {
    round: i32,
    mode: &'a str,
    index: i32,
    size: usize,
    millis: i64,
}

struct TempBody {
    path: Option<PathBuf>,
}

impl TempBody {
    fn path(&self) -> &Path {
        self.path.as_deref().expect("temporary body path is armed")
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempBody {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

fn generate_body_to_file(
    temp_dir: &Path,
    body: BodySpec<'_>,
    cancellation: &CancellationToken,
) -> Result<TempBody, StressError> {
    ensure_private_temp_dir(temp_dir).map_err(|_| StressError::Backend)?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| StressError::Backend)?;
    let mut name = String::with_capacity("body-.txt".len() + random.len() * 2);
    name.push_str("body-");
    for byte in random {
        let _ = write!(name, "{byte:02x}");
    }
    name.push_str(".txt");
    let path = temp_dir.join(name);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| StressError::Backend)?;
    let result = write_body(
        BufWriter::with_capacity(STREAMING_BODY_BUFFER_BYTES, file),
        body,
        "STREAMING",
        cancellation,
    );
    if result.is_err() {
        let _ = fs::remove_file(&path);
    }
    result.map(|()| TempBody { path: Some(path) })
}

fn write_body(
    mut output: BufWriter<File>,
    body: BodySpec<'_>,
    generation: &str,
    cancellation: &CancellationToken,
) -> Result<(), StressError> {
    let BodySpec {
        round,
        mode,
        index,
        size,
        millis,
    } = body;
    let mut header = String::with_capacity(STREAMING_BODY_HEADER_BYTES);
    let _ = write!(
        header,
        "=== Stress Test Email ===\r\n\
         Round: {}\r\n\
         Mode: {mode}\r\n\
         Index: {index}\r\n\
         Timestamp: {millis}\r\n\
         Target Size: {} KB\r\n\
         Generation: {generation}\r\n\
         =========================\r\n\r\n",
        round.wrapping_add(1),
        size / 1024,
    );
    if header.len() > STREAMING_BODY_HEADER_BYTES {
        return Err(StressError::Backend);
    }
    output
        .write_all(header.as_bytes())
        .map_err(|_| StressError::Backend)?;
    let mut remaining = size.saturating_sub(header.len());
    let mut line_length = 0_usize;
    while remaining > 0 {
        if cancellation.is_cancelled() {
            return Err(StressError::Cancelled);
        }
        let count = FILLER.len().min(remaining);
        output
            .write_all(&FILLER.as_bytes()[..count])
            .map_err(|_| StressError::Backend)?;
        remaining -= count;
        line_length += count;
        if line_length >= 70 && remaining > 2 {
            output
                .write_all(b"\r\n")
                .map_err(|_| StressError::Backend)?;
            remaining -= 2;
            line_length = 0;
        }
    }
    output.flush().map_err(|_| StressError::Backend)
}

fn ensure_private_temp_dir(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("stress temp directory has no parent"))?;
    fs::create_dir_all(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(io::Error::other(
            "stress temp parent is not a real directory",
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(io::Error::other("stress temp path is not a real directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(path)?;
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err(io::Error::other(
                            "stress temp path raced with a non-directory",
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn remove_tree(root: &Path, cancellation: &CancellationToken) -> io::Result<()> {
    remove_tree_with_budget(root, cancellation, MAX_CLEANUP_ENTRIES)
}

fn remove_tree_with_budget(
    root: &Path,
    cancellation: &CancellationToken,
    max_entries: usize,
) -> io::Result<()> {
    use std::{ffi::CString, os::fd::AsFd as _, os::unix::ffi::OsStrExt as _};

    use rustix::fs::{AtFlags, Mode, OFlags, open, statat, unlinkat};

    let parent = root
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = root
        .file_name()
        .ok_or_else(|| io::Error::other("stress cleanup root has no filename"))?;
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::other("stress cleanup root contains NUL"))?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let parent = match open(parent, directory_flags, Mode::empty()) {
        Ok(parent) => parent,
        Err(error) => {
            let error = io::Error::from(error);
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            };
        }
    };
    let mut entries = 0_usize;
    let Some(root) = open_cleanup_directory(&parent, name)? else {
        return Ok(());
    };
    let mut stack = vec![root];
    loop {
        if cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cleanup cancelled",
            ));
        }
        let child_name = {
            let directory = &mut stack
                .last_mut()
                .expect("cleanup directory stack is never empty")
                .directory;
            match directory.next() {
                Some(Ok(entry)) => Some(entry.file_name().to_owned()),
                Some(Err(error)) => return Err(io::Error::from(error)),
                None => None,
            }
        };
        if let Some(child_name) = child_name {
            if matches!(child_name.to_bytes(), b"." | b"..") {
                continue;
            }
            entries = entries.saturating_add(1);
            if entries > max_entries {
                return Err(io::Error::other("stress cleanup entry budget exceeded"));
            }
            let parent_fd = stack
                .last()
                .expect("cleanup directory stack is never empty")
                .directory
                .fd()
                .map_err(io::Error::from)?;
            if let Some(child) = open_cleanup_directory(parent_fd, child_name)? {
                stack.push(child);
            }
            continue;
        }

        let completed = stack.pop().expect("cleanup directory stack is never empty");
        let parent_fd = match stack.last() {
            Some(parent_frame) => parent_frame.directory.fd().map_err(io::Error::from)?,
            None => parent.as_fd(),
        };
        let current = statat(parent_fd, &completed.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)?;
        if current.st_dev != completed.device || current.st_ino != completed.inode {
            return Err(io::Error::other(
                "stress cleanup directory changed during traversal",
            ));
        }
        unlinkat(parent_fd, &completed.name, AtFlags::REMOVEDIR).map_err(io::Error::from)?;
        if stack.is_empty() {
            return Ok(());
        }
    }
}

struct CleanupDirectory {
    name: std::ffi::CString,
    device: u64,
    inode: u64,
    directory: rustix::fs::Dir,
}

fn open_cleanup_directory<Fd: std::os::fd::AsFd>(
    parent: Fd,
    name: std::ffi::CString,
) -> io::Result<Option<CleanupDirectory>> {
    use rustix::fs::{
        AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags, fstat, openat2, statat, unlinkat,
    };

    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    let descriptor = match openat2(&parent, &name, directory_flags, Mode::empty(), resolve) {
        Ok(descriptor) => descriptor,
        Err(open_error) => {
            let open_error = io::Error::from(open_error);
            let metadata = match statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(metadata) => metadata,
                Err(error) => {
                    let error = io::Error::from(error);
                    return if error.kind() == io::ErrorKind::NotFound {
                        Ok(None)
                    } else {
                        Err(error)
                    };
                }
            };
            if FileType::from_raw_mode(metadata.st_mode) == FileType::Directory {
                return Err(open_error);
            }
            unlinkat(&parent, &name, AtFlags::empty()).map_err(io::Error::from)?;
            return Ok(None);
        }
    };
    let metadata = fstat(&descriptor).map_err(io::Error::from)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
        return Err(io::Error::other(
            "stress cleanup opened a non-directory as a directory",
        ));
    }
    Ok(Some(CleanupDirectory {
        name,
        device: metadata.st_dev,
        inode: metadata.st_ino,
        directory: Dir::new(descriptor).map_err(io::Error::from)?,
    }))
}

impl From<OutboundError> for StressError {
    fn from(_: OutboundError) -> Self {
        Self::Backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Properties;

    #[test]
    fn schedule_matches_frozen_enqueue_caps_and_releases_jobs_before_delivery_wait() {
        for (email_size_kb, expected_cap) in [
            (1, 1_500),
            (10, 1_000),
            (100, 400),
            (1_000, 200),
            (5_000, 120),
            (10_000, 80),
            (10_240, 80),
        ] {
            let schedule = StressSchedule::for_email_size_kb(email_size_kb);
            assert_eq!(schedule.active_job_cap(StressPhase::Enqueue), expected_cap);
            assert_eq!(schedule.active_job_cap(StressPhase::DeliveryWait), 0);
        }
    }

    #[test]
    fn blocking_queue_covers_every_frozen_enqueue_concurrency_tier() {
        for email_size_kb in [1, 10, 100, 1_000, 5_000, 10_000] {
            assert!(
                BODY_QUEUE_CAPACITY >= max_concurrency(email_size_kb),
                "blocking queue is smaller than the {email_size_kb}KB enqueue tier"
            );
        }
    }

    #[test]
    fn outbound_workers_scale_by_durability_and_frozen_body_size_boundary() {
        for (email_size_kb, filesystem_fsync_enabled, expected_workers) in [
            (1, true, 8),
            (10, true, 8),
            (999, true, 8),
            (1, false, 32),
            (10, false, 32),
            (999, false, 32),
            (1_000, true, 4),
            (1_000, false, 4),
            (9_999, false, 4),
            (10_000, false, 4),
        ] {
            assert_eq!(
                outbound_worker_count(email_size_kb, filesystem_fsync_enabled),
                expected_workers,
                "unexpected worker bound for the {email_size_kb}KB tier with filesystem fsync={filesystem_fsync_enabled}"
            );
        }
    }

    #[test]
    fn delivery_stability_uses_the_round_delta_and_requires_exact_target() {
        assert_eq!(
            delivery_stability_after_poll(0, 40, 40, 0, 1).unwrap(),
            (0, 0, false)
        );
        assert_eq!(
            delivery_stability_after_poll(0, 40, 41, 1, 1).unwrap(),
            (1, 1, false)
        );
        assert_eq!(
            delivery_stability_after_poll(1, 40, 41, 1, 1).unwrap(),
            (1, 2, true)
        );
        assert!(delivery_stability_after_poll(0, 40, 42, 2, 1).is_err());
        assert_eq!(
            delivery_stability_after_poll(0, 40, 41, 0, 1).unwrap(),
            (0, 0, false)
        );
        assert!(delivery_stability_after_poll(0, 40, 42, 1, 1).is_err());
        assert!(delivery_stability_after_poll(0, 40, 39, 0, 1).is_err());
    }

    #[test]
    fn late_delivery_resurrection_breaks_cleanup_stability() {
        assert_eq!(cleanup_stability_after_poll(0, 0, 0).unwrap(), 1);
        assert!(cleanup_stability_after_poll(1, 0, 1).is_err());
        assert!(cleanup_stability_after_poll(1, 1, 0).is_err());
        assert_eq!(cleanup_stability_after_poll(1, 0, 0).unwrap(), 2);
    }

    #[test]
    fn run_markers_are_strictly_monotonic() {
        let first = next_run_marker();
        let second = next_run_marker();
        assert!(first > 0);
        assert!(second > first);
    }

    #[test]
    fn streaming_body_budget_accounts_for_full_outbound_materialization() {
        assert_eq!(body_memory_per_job(1024), 1024);
        assert_eq!(
            body_memory_per_job(IN_MEMORY_THRESHOLD_BYTES),
            IN_MEMORY_THRESHOLD_BYTES
        );
        assert_eq!(
            body_memory_per_job(IN_MEMORY_THRESHOLD_BYTES + 1),
            IN_MEMORY_THRESHOLD_BYTES + 1 + STREAMING_BODY_SCRATCH_BYTES
        );

        let ten_megabytes = 10 * 1024 * 1024;
        assert_eq!(
            body_memory_per_job(ten_megabytes),
            ten_megabytes + STREAMING_BODY_BUFFER_BYTES + STREAMING_BODY_HEADER_BYTES
        );
        let active_cap =
            StressSchedule::for_email_size_kb(10_240).active_job_cap(StressPhase::Enqueue);
        assert_eq!(active_cap, 80);
        assert!(body_memory_per_job(ten_megabytes) * active_cap <= BODY_MEMORY_BUDGET_BYTES);
        assert_eq!(BODY_MEMORY_BUDGET_BYTES / ten_megabytes, 102);
    }

    #[test]
    fn final_cleanup_deadline_scales_and_stays_below_harness_recovery_window() {
        assert_eq!(final_cleanup_deadline(0, 1), Duration::from_secs(10));
        assert_eq!(final_cleanup_deadline(500_000, 1), Duration::from_secs(63));
        assert_eq!(final_cleanup_deadline(500_000, 10), Duration::from_secs(81));
        assert_eq!(
            final_cleanup_deadline(1_000, 10_240),
            Duration::from_secs(53)
        );
        assert_eq!(
            final_cleanup_deadline(i32::MAX, i32::MAX),
            Duration::from_secs(FINAL_CLEANUP_MAX_SECONDS)
        );
        assert!(final_cleanup_deadline(i32::MAX, i32::MAX) < Duration::from_secs(120));
    }

    #[test]
    fn deferred_recovery_backoff_is_bounded() {
        let mut delay = DEFERRED_RECOVERY_RETRY;
        for _ in 0..32 {
            delay = next_deferred_recovery_retry(delay);
            assert!(delay <= DEFERRED_RECOVERY_MAX_RETRY);
        }
        assert_eq!(delay, DEFERRED_RECOVERY_MAX_RETRY);
    }

    #[test]
    fn queue_target_exposes_partial_delivery_target_before_rejecting_admission() {
        let complete = RunCounters::with_capacity(64);
        complete.queued.store(64, Ordering::Relaxed);
        assert_eq!(complete.queue_target(64).unwrap(), 64);

        let partial = RunCounters::with_capacity(64);
        partial.queued.store(63, Ordering::Relaxed);
        partial.record_failure("database pool timeout");
        assert_eq!(partial.queued_target().unwrap(), 63);
        assert!(matches!(
            partial.queue_target(64),
            Err(StressError::Backend)
        ));
        assert_eq!(
            partial.first_failure.get().map(String::as_str),
            Some("database pool timeout")
        );
    }

    #[test]
    fn run_counters_preserve_outcome_unknown_task_identities() {
        let counters = RunCounters::with_capacity(1);
        counters.record_task(StressTaskIdentity {
            queue_id: 41,
            lifecycle: crate::outbound::StressTaskLifecycle::Unknown {
                sent_file_name: Some("stress.eml".into()),
                owned_files: None,
            },
        });
        assert_eq!(
            counters.task_snapshot().unwrap(),
            [StressTaskIdentity {
                queue_id: 41,
                lifecycle: crate::outbound::StressTaskLifecycle::Unknown {
                    sent_file_name: Some("stress.eml".into()),
                    owned_files: None,
                },
            }]
        );
    }

    #[tokio::test]
    async fn first_cleanup_failure_still_polls_the_second_cleanup() {
        let second_polled = Arc::new(AtomicBool::new(false));
        let second_flag = Arc::clone(&second_polled);
        let (first, second) =
            run_best_effort_pair(async { Err::<(), _>(StressError::Backend) }, async move {
                second_flag.store(true, Ordering::Release);
                Ok::<(), StressError>(())
            })
            .await;
        assert!(first.is_err());
        assert!(second.is_ok());
        assert!(second_polled.load(Ordering::Acquire));
        assert!(combine_cleanup_results(first, second).is_err());
    }

    #[test]
    fn stress_uses_first_send_and_receive_domains_independently() {
        let config = RuntimeConfig::from_properties(
            Properties::parse(
                b"lmyzmail.domain=fallback.example.test\n\
botmail.domains.primary.domain=example.test\n\
botmail.domains.primary.receiveEnabled=false\n\
botmail.domains.primary.sendEnabled=false\n\
botmail.domains.second.domain=receive.example.test\n\
botmail.domains.second.receiveEnabled=true\n\
botmail.domains.second.sendEnabled=false\n\
botmail.domains.send.domain=send.example.test\n\
botmail.domains.send.receiveEnabled=false\n\
botmail.domains.send.sendEnabled=true\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            stress_domains(&config),
            (Some("send.example.test"), Some("receive.example.test"))
        );
    }

    #[test]
    fn stress_uses_primary_domain_when_no_domain_map_is_configured() {
        let config = RuntimeConfig::from_properties(
            Properties::parse(b"lmyzmail.domain=fallback.example.test\n").unwrap(),
        )
        .unwrap();
        assert_eq!(
            stress_domains(&config),
            (Some("fallback.example.test"), Some("fallback.example.test"))
        );
    }

    #[test]
    fn stress_does_not_fall_back_when_configured_domains_are_disabled() {
        let config = RuntimeConfig::from_properties(
            Properties::parse(
                b"lmyzmail.domain=fallback.example.test\n\
botmail.domains.main.domain=disabled.example.test\n\
botmail.domains.main.receiveEnabled=false\n\
botmail.domains.main.sendEnabled=false\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(stress_domains(&config), (None, None),);
    }

    #[test]
    fn generated_body_has_exact_target_size_and_frozen_header() {
        let body = generate_body(
            0,
            "WARMUP",
            0,
            1024,
            1_725_000_000_000,
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(body.len(), 1024);
        assert!(
            body.starts_with(
                "=== Stress Test Email ===\r\nRound: 1\r\nMode: WARMUP\r\nIndex: 0\r\n"
            )
        );
        assert!(body.contains("Timestamp: 1725000000000\r\n"));
        assert!(body.contains("Generation: IN-MEMORY\r\n"));
    }

    #[test]
    fn generated_body_observes_cancellation() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            generate_body(0, "WARMUP", 0, 1024, 1, &cancellation),
            Err(StressError::Cancelled)
        ));
    }

    #[test]
    fn streaming_body_file_matches_frozen_generated_bytes_and_mode() {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let temporary = std::env::temp_dir().join(format!(
            "lmyzmail-stress-body-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        let temp_dir = temporary.join("spool");
        let cancellation = CancellationToken::new();
        let body = generate_body_to_file(
            &temp_dir,
            BodySpec {
                round: 2,
                mode: "PRODUCTION",
                index: 7,
                size: 32 * 1024,
                millis: 1_725_000_000_000,
            },
            &cancellation,
        )
        .unwrap();
        let expected = generate_body(
            2,
            "PRODUCTION",
            7,
            32 * 1024,
            1_725_000_000_000,
            &cancellation,
        )
        .unwrap();
        assert_eq!(fs::read(body.path()).unwrap(), expected.as_bytes());
        assert!(expected.contains("Generation: STREAMING\r\n"));
        assert_eq!(
            fs::metadata(body.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(temporary).unwrap();
    }

    #[test]
    fn cancelled_streaming_generation_removes_its_partial_file() {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let temporary = std::env::temp_dir().join(format!(
            "lmyzmail-stress-body-cancel-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        let temp_dir = temporary.join("spool");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            generate_body_to_file(
                &temp_dir,
                BodySpec {
                    round: 0,
                    mode: "WARMUP",
                    index: 0,
                    size: 32 * 1024,
                    millis: 1,
                },
                &cancellation,
            ),
            Err(StressError::Cancelled)
        ));
        assert_eq!(fs::read_dir(&temp_dir).unwrap().count(), 0);
        fs::remove_dir_all(temporary).unwrap();
    }

    #[tokio::test]
    async fn generated_body_budget_remains_held_by_a_running_worker() {
        let budget = Arc::new(Semaphore::new(1));
        let async_permit = Arc::new(budget.clone().acquire_owned().await.unwrap());
        let worker_permit = Arc::clone(&async_permit);
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _body_memory = worker_permit;
            started_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
        });
        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        drop(async_permit);
        assert!(budget.clone().try_acquire_owned().is_err());
        release_sender.send(()).unwrap();
        worker.join().unwrap();
        assert!(budget.try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn blocking_quiescence_cannot_complete_while_a_job_is_running() {
        let blocking = Arc::new(Semaphore::new(BODY_QUEUE_CAPACITY));
        let running_job = Arc::clone(&blocking).acquire_owned().await.unwrap();
        assert!(
            wait_for_blocking_quiescence(
                Arc::clone(&blocking),
                Instant::now() + Duration::from_millis(1),
                &CancellationToken::new(),
            )
            .await
            .is_err()
        );
        drop(running_job);
        wait_for_blocking_quiescence(
            Arc::clone(&blocking),
            Instant::now() + Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shutdown_joins_or_aborts_every_service_held_quiescence_task() {
        struct Dropped(Arc<AtomicBool>);

        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let tasks = Mutex::new(JoinSet::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        tasks.lock().await.spawn({
            let dropped = Arc::clone(&dropped);
            async move {
                let _dropped = Dropped(dropped);
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            }
        });
        started_rx.await.unwrap();
        shutdown_task_set(&tasks, Instant::now() + Duration::from_millis(1)).await;
        assert!(dropped.load(Ordering::Acquire));
        assert!(tasks.lock().await.is_empty());
    }

    #[test]
    fn response_json_preserves_java_acronym_keys() {
        let response = StressStatusResponse {
            completed_rounds: 0,
            warmup_rounds: 1,
            warmup_remaining: 1,
            next_mode: "WARMUP",
            next_count: 1,
            warmup_count: 1,
            production_count: 2,
            email_size_kb: 1,
            max_concurrency: 1_500,
            streaming_enabled: false,
            in_memory_mode: true,
            in_memory_threshold_kb: 20,
        };
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["emailSizeKB"], 1);
        assert_eq!(value["inMemoryThresholdKB"], 20);
        assert!(value.get("emailSizeKb").is_none());
        assert!(value.get("inMemoryThresholdKb").is_none());
    }

    #[test]
    fn cleanup_never_follows_symlinks() {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let temporary = std::env::temp_dir().join(format!(
            "lmyzmail-stress-cleanup-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        let outside = temporary.join("outside");
        let root = temporary.join("root");
        fs::create_dir(&temporary).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"keep").unwrap();
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        remove_tree(&root, &CancellationToken::new()).unwrap();
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"keep");
        fs::remove_dir_all(temporary).unwrap();
    }

    #[test]
    fn cleanup_stops_at_entry_budget() {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let temporary = std::env::temp_dir().join(format!(
            "lmyzmail-stress-cleanup-budget-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        let root = temporary.join("root");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("one"), b"1").unwrap();
        fs::write(root.join("two"), b"2").unwrap();

        let error = remove_tree_with_budget(&root, &CancellationToken::new(), 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(root.exists());
        fs::remove_dir_all(temporary).unwrap();
    }

    #[test]
    fn startup_recovery_removes_stale_private_body_files() {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let temporary = std::env::temp_dir().join(format!(
            "lmyzmail-stress-recovery-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        let temp_dir = temporary.join("maildir/.lmyzmail-stress");
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(temp_dir.join("body-stale.txt"), b"partial body").unwrap();

        remove_tree(&temp_dir, &CancellationToken::new()).unwrap();

        assert!(!temp_dir.exists());
        fs::remove_dir_all(temporary).unwrap();
    }

    #[test]
    fn startup_recovery_accepts_an_absent_maildir_parent() {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let temporary = std::env::temp_dir().join(format!(
            "lmyzmail-stress-recovery-absent-{}-{}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        let root = temporary.join("maildir/.lmyzmail-stress");

        remove_tree(&root, &CancellationToken::new()).unwrap();

        assert!(!temporary.exists());
    }
}
