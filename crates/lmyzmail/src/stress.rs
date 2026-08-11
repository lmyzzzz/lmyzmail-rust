use std::{
    fmt,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write as _},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
    time::Duration,
};

use futures_util::{StreamExt, stream};
use serde::Serialize;
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{AuthError, AuthService},
    bounded_blocking::{BoundedBlockingPool, SubmitError},
    config::{RuntimeConfig, StressConfig},
    mailbox::MailboxService,
    outbound::{OutboundError, OutboundService, SendRequest, StreamingTextInput},
};

const IN_MEMORY_THRESHOLD_BYTES: usize = 20 * 1024;
const DEFAULT_MAX_CONCURRENCY: usize = 1_500;
const BODY_WORKERS: usize = 4;
const BODY_QUEUE_CAPACITY: usize = 4;
const BODY_MEMORY_BUDGET_BYTES: usize = 64 * 1024 * 1024;
const QUEUE_WAIT: Duration = Duration::from_secs(30 * 60);
const DELIVERY_WAIT: Duration = Duration::from_secs(20 * 60);
const DELIVERY_POLL: Duration = Duration::from_secs(1);
const FINAL_CLEANUP_DEADLINE: Duration = Duration::from_secs(10);
const TEMP_CLEANUP_DEADLINE: Duration = Duration::from_secs(5);
const BLOCKING_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
const MAX_CLEANUP_ENTRIES: usize = 1_100_000;
const FILLER: &str = "The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet. ";

#[derive(Debug)]
pub(crate) enum StressError {
    Disabled,
    Busy,
    Cancelled,
    Backend,
}

impl fmt::Display for StressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("stress test endpoint is disabled"),
            Self::Busy => formatter.write_str("stress test concurrency limit reached"),
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

#[derive(Default)]
struct RunCounters {
    queued: std::sync::atomic::AtomicUsize,
    failed: std::sync::atomic::AtomicUsize,
}

struct StressInner {
    config: StressConfig,
    domain: Arc<str>,
    temp_dir: PathBuf,
    auth: Arc<AuthService>,
    mailbox: Arc<MailboxService>,
    outbound: Arc<OutboundService>,
    round: AtomicI32,
    active: Arc<Semaphore>,
    blocking_admission: Arc<Semaphore>,
    body_memory: Arc<Semaphore>,
    blocking_pool: Arc<BoundedBlockingPool>,
    tasks: Mutex<JoinSet<()>>,
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
        let blocking_pool = Arc::new(BoundedBlockingPool::new(
            "lmyzmail-stress-body",
            BODY_WORKERS,
            BODY_QUEUE_CAPACITY,
        )?);
        Ok(Self {
            inner: Arc::new(StressInner {
                config: config.stress.clone(),
                domain: Arc::from(config.domain.as_str()),
                temp_dir: config.maildir.join(".lmyzmail-stress"),
                auth,
                mailbox,
                outbound,
                round: AtomicI32::new(0),
                active: Arc::new(Semaphore::new(1)),
                blocking_admission: Arc::new(Semaphore::new(BODY_WORKERS + BODY_QUEUE_CAPACITY)),
                body_memory: Arc::new(Semaphore::new(BODY_MEMORY_BUDGET_BYTES)),
                blocking_pool,
                tasks: Mutex::new(JoinSet::new()),
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
        let (sender, receiver) = self.addresses();
        self.cleanup_address_result(&sender, cancellation)
            .await
            .map_err(io::Error::other)?;
        self.cleanup_address_result(&receiver, cancellation)
            .await
            .map_err(io::Error::other)
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
            max_concurrency: max_concurrency(self.inner.config.email_size_kb),
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
        let active = self
            .inner
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| StressError::Busy)?;
        let current = self.inner.round.fetch_add(1, Ordering::SeqCst);
        let warmup = current < self.inner.config.warmup_rounds;
        let email_count = if warmup {
            self.inner.config.warmup_count
        } else {
            self.inner.config.production_count
        };
        let max_concurrency = max_concurrency(self.inner.config.email_size_kb);
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
            run_stress(inner, active, current, warmup, email_count, max_concurrency).await;
        });
        Ok(response)
    }

    pub(crate) async fn cleanup(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<StressCleanupResponse, StressError> {
        self.require_enabled()?;
        let _active = self
            .inner
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| StressError::Busy)?;
        let (sender, receiver) = self.addresses();
        self.cleanup_address(&sender, cancellation).await;
        self.cleanup_address(&receiver, cancellation).await;
        Ok(StressCleanupResponse {
            message: format!("Cleanup completed for {sender} and {receiver}"),
        })
    }

    pub(crate) async fn shutdown(&self, deadline: Instant) {
        self.inner.cancellation.cancel();
        let mut tasks = self.inner.tasks.lock().await;
        if tokio::time::timeout_at(deadline, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        drop(tasks);
        let blocking_deadline = deadline
            .saturating_duration_since(Instant::now())
            .min(BLOCKING_SHUTDOWN_DEADLINE);
        if !self.inner.blocking_pool.shutdown(blocking_deadline).await {
            eprintln!("lmyzmail stress blocking pool exceeded its shutdown deadline");
        }
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

    fn addresses(&self) -> (String, String) {
        (
            format!("{}@{}", self.inner.config.sender_prefix, self.inner.domain),
            format!(
                "{}@{}",
                self.inner.config.receiver_prefix, self.inner.domain
            ),
        )
    }

    async fn cleanup_address(&self, address: &str, cancellation: &CancellationToken) {
        if let Err(error) = self.cleanup_address_result(address, cancellation).await {
            eprintln!("lmyzmail stress cleanup failed for {address}: {error}");
        }
    }

    async fn cleanup_address_result(
        &self,
        address: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), StressError> {
        let Ok(path) = self.inner.mailbox.user_directory(address) else {
            return Err(StressError::Backend);
        };
        let index_cleanup = self
            .inner
            .mailbox
            .delete_indexes_for_mailbox(address, cancellation);
        let file_cleanup = self.run_blocking(cancellation, move |job_cancellation| {
            remove_tree(&path, &job_cancellation)
        });
        let (index_result, file_result) = tokio::join!(index_cleanup, file_cleanup);
        if index_result.is_err() || !matches!(file_result, Ok(Ok(()))) {
            return Err(StressError::Backend);
        }
        Ok(())
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

async fn run_stress(
    inner: Arc<StressInner>,
    _active: OwnedSemaphorePermit,
    round: i32,
    warmup: bool,
    email_count: i32,
    max_concurrency: usize,
) {
    let service = StressService {
        inner: Arc::clone(&inner),
    };
    let (sender, receiver) = service.addresses();
    let cancellation = inner.cancellation.child_token();
    let mode = if warmup { "WARMUP" } else { "PRODUCTION" };
    let started = Instant::now();
    let result = async {
        ensure_mailbox(&inner.auth, &sender, &inner.config.password, &cancellation).await?;
        ensure_mailbox(
            &inner.auth,
            &receiver,
            &inner.config.password,
            &cancellation,
        )
        .await?;
        let counters = Arc::new(RunCounters::default());
        let queue_input_cancellation = cancellation.clone();
        let queueing = stream::iter(0..email_count)
            .take_until(queue_input_cancellation.cancelled_owned())
            .for_each_concurrent(Some(max_concurrency), |index| {
                let inner = Arc::clone(&inner);
                let counters = Arc::clone(&counters);
                let sender = sender.clone();
                let receiver = receiver.clone();
                let cancellation = cancellation.clone();
                async move {
                    if cancellation.is_cancelled() {
                        counters.failed.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    let subject_millis = chrono::Utc::now().timestamp_millis();
                    let subject = format!(
                        "Stress Test R{} #{} - {subject_millis}",
                        round.wrapping_add(1),
                        index
                    );
                    let body_size = usize::try_from(inner.config.email_size_kb)
                        .unwrap_or_default()
                        .saturating_mul(1024);
                    let body_permits = u32::try_from(body_size)
                        .expect("validated stress body size fits semaphore permits");
                    let body_memory = Arc::new(tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => {
                            counters.failed.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        result = inner.body_memory.clone().acquire_many_owned(body_permits) => {
                            match result {
                                Ok(permit) => permit,
                                Err(_) => {
                                    counters.failed.fetch_add(1, Ordering::Relaxed);
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
                    let Ok(Ok(body)) = generated else {
                        counters.failed.fetch_add(1, Ordering::Relaxed);
                        return;
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
                            inner
                                .outbound
                                .enqueue_stress_with_cancellation(request, &cancellation)
                                .await
                        }
                        GeneratedBody::File(mut body) => {
                            let path = body.path().to_path_buf();
                            let enqueue = inner
                                .outbound
                                .enqueue_stress_streaming_text_with_cancellation(
                                    request,
                                    StreamingTextInput {
                                        path: path.clone(),
                                        size: body_size as u64,
                                    },
                                    &cancellation,
                                )
                                .await;
                            if cleanup_temp_file(&inner, path).await {
                                body.disarm();
                            }
                            enqueue
                        }
                    };
                    match result {
                        Ok(_) => {
                            counters.queued.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            counters.failed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    drop(body_memory);
                }
            });
        tokio::pin!(queueing);
        if timeout(QUEUE_WAIT, &mut queueing).await.is_err() {
            cancellation.cancel();
            if timeout(TEMP_CLEANUP_DEADLINE, &mut queueing).await.is_err() {
                return Err(StressError::Backend);
            }
            return Err(StressError::Backend);
        }
        if cancellation.is_cancelled() {
            return Err(StressError::Cancelled);
        }
        let target = counters.queued.load(Ordering::Relaxed) as i64;
        wait_for_delivery(
            &inner.mailbox,
            &receiver,
            target,
            started + DELIVERY_WAIT,
            &cancellation,
        )
        .await?;
        Ok::<(), StressError>(())
    }
    .await;
    if let Err(error) = result
        && !matches!(error, StressError::Cancelled)
    {
        eprintln!(
            "lmyzmail stress round {} failed before completion: {error}",
            round.wrapping_add(1)
        );
    }
    let cleanup_cancellation = CancellationToken::new();
    if timeout(FINAL_CLEANUP_DEADLINE, async {
        service
            .cleanup_address(&sender, &cleanup_cancellation)
            .await;
        service
            .cleanup_address(&receiver, &cleanup_cancellation)
            .await;
    })
    .await
    .is_err()
    {
        cleanup_cancellation.cancel();
        eprintln!(
            "lmyzmail stress round {} cleanup exceeded its deadline",
            round.wrapping_add(1)
        );
    }
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
    receiver: &str,
    target: i64,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), StressError> {
    if target <= 0 {
        return Ok(());
    }
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(StressError::Cancelled),
            _ = sleep(DELIVERY_POLL) => {}
        }
        if mailbox
            .count_folder(receiver, "inbox", cancellation)
            .await
            .map_err(|_| StressError::Backend)?
            >= target
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Ok(());
        }
    }
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
        BufWriter::with_capacity(32 * 1024, file),
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
    let header = format!(
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

async fn cleanup_temp_file(inner: &StressInner, path: PathBuf) -> bool {
    let cleanup_cancellation = CancellationToken::new();
    let cleanup = run_blocking(inner, &cleanup_cancellation, move |_| fs::remove_file(path));
    match timeout(TEMP_CLEANUP_DEADLINE, cleanup).await {
        Ok(Ok(Ok(()))) => true,
        Ok(Ok(Err(error))) if error.kind() == io::ErrorKind::NotFound => true,
        Ok(Ok(Err(error))) => {
            eprintln!("lmyzmail stress body temp cleanup failed: {error}");
            false
        }
        Ok(Err(error)) => {
            eprintln!("lmyzmail stress body temp cleanup failed: {error}");
            false
        }
        Err(_) => {
            cleanup_cancellation.cancel();
            eprintln!("lmyzmail stress body temp cleanup exceeded its deadline");
            false
        }
    }
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

    #[test]
    fn concurrency_matches_frozen_thresholds() {
        assert_eq!(max_concurrency(1), 1_500);
        assert_eq!(max_concurrency(10), 1_000);
        assert_eq!(max_concurrency(100), 400);
        assert_eq!(max_concurrency(1_000), 200);
        assert_eq!(max_concurrency(5_000), 120);
        assert_eq!(max_concurrency(10_000), 80);
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
