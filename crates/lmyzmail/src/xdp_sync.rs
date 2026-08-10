use std::{collections::HashSet, fmt, future::Future, panic::AssertUnwindSafe, sync::Arc};

use futures_util::FutureExt;
use serde::Serialize;
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    cringe::{CringeError, CringeService},
    xdp::{XdpError, XdpService},
};

const SYNC_SHUTDOWN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);
const DECAY_UNBAN_SYNC_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);
const DECAY_UNBAN_SYNC_DRAIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Debug, Clone)]
pub enum XdpSyncError {
    Cancelled,
    Database(Arc<CringeError>),
    Native(Arc<XdpError>),
    WorkerPanicked,
}

impl fmt::Display for XdpSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("XDP sync cancelled"),
            Self::Database(error) => write!(formatter, "XDP sync database failure: {error}"),
            Self::Native(error) => write!(formatter, "XDP sync native failure: {error}"),
            Self::WorkerPanicked => formatter.write_str("XDP sync worker panicked"),
        }
    }
}

impl std::error::Error for XdpSyncError {}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XdpSyncResult {
    pub banned: usize,
    pub unbanned: usize,
    pub unchanged: usize,
    pub skipped_whitelist: usize,
    pub rebanned: usize,
    pub message: String,
}

type SharedOutcome = Arc<Result<XdpSyncResult, XdpSyncError>>;

#[derive(Default)]
struct SyncFlightState {
    generation: u64,
    sender: Option<watch::Sender<Option<SharedOutcome>>>,
    worker: Option<JoinHandle<()>>,
    worker_cancellation: Option<CancellationToken>,
    closed: bool,
}

#[derive(Default)]
struct SyncFlight {
    state: Mutex<SyncFlightState>,
}

impl SyncFlight {
    async fn run<F, Fut>(
        self: &Arc<Self>,
        cancellation: &CancellationToken,
        operation: F,
    ) -> Result<XdpSyncResult, XdpSyncError>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<XdpSyncResult, XdpSyncError>> + Send + 'static,
    {
        let mut state = self.state.lock().await;
        if state.closed {
            return Err(XdpSyncError::Cancelled);
        }
        let receiver = if let Some(sender) = state.sender.as_ref() {
            sender.subscribe()
        } else {
            state.worker = None;
            state.generation = state.generation.wrapping_add(1).max(1);
            let generation = state.generation;
            let (sender, receiver) = watch::channel(None);
            state.sender = Some(sender.clone());
            let worker_cancellation = CancellationToken::new();
            state.worker_cancellation = Some(worker_cancellation.clone());
            let flight = Arc::clone(self);
            let worker = tokio::spawn(async move {
                let outcome = AssertUnwindSafe(operation(worker_cancellation))
                    .catch_unwind()
                    .await
                    .unwrap_or(Err(XdpSyncError::WorkerPanicked));
                let outcome = Arc::new(outcome);
                let mut state = flight.state.lock().await;
                if state.generation == generation {
                    state.sender = None;
                    state.worker_cancellation = None;
                }
                drop(state);
                sender.send_replace(Some(outcome));
            });
            state.worker = Some(worker);
            receiver
        };
        drop(state);
        wait_for_outcome(receiver, cancellation).await
    }

    async fn shutdown(&self) {
        let (worker_cancellation, worker) = {
            let mut state = self.state.lock().await;
            state.closed = true;
            (state.worker_cancellation.take(), state.worker.take())
        };
        if let Some(worker_cancellation) = worker_cancellation {
            worker_cancellation.cancel();
        }
        let Some(mut worker) = worker else {
            return;
        };
        if timeout(SYNC_SHUTDOWN_DEADLINE, &mut worker).await.is_err() {
            worker.abort();
            let _ = worker.await;
        }
    }
}

async fn wait_for_outcome(
    mut receiver: watch::Receiver<Option<SharedOutcome>>,
    cancellation: &CancellationToken,
) -> Result<XdpSyncResult, XdpSyncError> {
    loop {
        if let Some(outcome) = receiver.borrow().clone() {
            return outcome.as_ref().clone();
        }
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(XdpSyncError::Cancelled),
            changed = receiver.changed() => {
                if changed.is_err() {
                    return Err(XdpSyncError::Cancelled);
                }
            }
        }
    }
}

pub struct XdpSyncService {
    xdp: Arc<XdpService>,
    cringe: CringeService,
    flight: Arc<SyncFlight>,
    decay_unban_flight: Arc<SyncFlight>,
    operation_lock: Arc<Mutex<()>>,
}

impl XdpSyncService {
    pub fn new(xdp: Arc<XdpService>, cringe: CringeService) -> Self {
        Self {
            xdp,
            cringe,
            flight: Arc::new(SyncFlight::default()),
            decay_unban_flight: Arc::new(SyncFlight::default()),
            operation_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn xdp(&self) -> &XdpService {
        &self.xdp
    }

    pub async fn perform_full_sync(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<XdpSyncResult, XdpSyncError> {
        let xdp = Arc::clone(&self.xdp);
        let cringe = self.cringe.clone();
        let operation_lock = Arc::clone(&self.operation_lock);
        self.flight
            .run(cancellation, move |worker_cancellation| async move {
                let _guard = tokio::select! {
                    biased;
                    _ = worker_cancellation.cancelled() => return Err(XdpSyncError::Cancelled),
                    guard = operation_lock.lock() => guard,
                };
                perform_full_sync(&xdp, &cringe, &worker_cancellation).await
            })
            .await
    }

    pub async fn perform_decay_unbans(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<XdpSyncResult, XdpSyncError> {
        let xdp = Arc::clone(&self.xdp);
        let cringe = self.cringe.clone();
        let operation_lock = Arc::clone(&self.operation_lock);
        self.decay_unban_flight
            .run(cancellation, move |worker_cancellation| async move {
                perform_decay_unbans_bounded(operation_lock, &xdp, &cringe, &worker_cancellation)
                    .await
            })
            .await
    }

    pub async fn shutdown(&self) {
        self.flight.shutdown().await;
        self.decay_unban_flight.shutdown().await;
    }
}

async fn perform_decay_unbans_bounded(
    operation_lock: Arc<Mutex<()>>,
    xdp: &XdpService,
    cringe: &CringeService,
    cancellation: &CancellationToken,
) -> Result<XdpSyncResult, XdpSyncError> {
    let operation_cancellation = cancellation.child_token();
    let operation = async {
        let _guard = tokio::select! {
            biased;
            _ = operation_cancellation.cancelled() => return Err(XdpSyncError::Cancelled),
            guard = operation_lock.lock() => guard,
        };
        perform_decay_unbans(xdp, cringe, &operation_cancellation).await
    };
    run_decay_unban_operation_bounded(
        &operation_cancellation,
        DECAY_UNBAN_SYNC_DEADLINE,
        DECAY_UNBAN_SYNC_DRAIN_DEADLINE,
        operation,
    )
    .await
}

async fn run_decay_unban_operation_bounded<F>(
    operation_cancellation: &CancellationToken,
    deadline: std::time::Duration,
    drain_deadline: std::time::Duration,
    operation: F,
) -> Result<XdpSyncResult, XdpSyncError>
where
    F: Future<Output = Result<XdpSyncResult, XdpSyncError>>,
{
    tokio::pin!(operation);
    tokio::select! {
        biased;
        result = &mut operation => result,
        () = tokio::time::sleep(deadline) => {
            operation_cancellation.cancel();
            let _ = timeout(drain_deadline, &mut operation).await;
            Err(XdpSyncError::Native(Arc::new(XdpError::Timeout)))
        }
    }
}

async fn perform_decay_unbans(
    xdp: &XdpService,
    cringe: &CringeService,
    cancellation: &CancellationToken,
) -> Result<XdpSyncResult, XdpSyncError> {
    if cancellation.is_cancelled() {
        return Err(XdpSyncError::Cancelled);
    }
    if !xdp.ready() {
        return Ok(XdpSyncResult {
            banned: 0,
            unbanned: 0,
            unchanged: 0,
            skipped_whitelist: 0,
            rebanned: 0,
            message: "XDP not ready".into(),
        });
    }
    let existing = xdp.all_banned(cancellation).await.map_err(map_xdp_error)?;
    let candidates = cringe
        .xdp_decay_unban_candidates(&existing, xdp.config().unban_threshold, cancellation)
        .await
        .map_err(|error| match error {
            CringeError::Cancelled => XdpSyncError::Cancelled,
            other => XdpSyncError::Database(Arc::new(other)),
        })?;
    let result = xdp
        .unban_many_bounded(candidates, cancellation)
        .await
        .map_err(map_xdp_error)?;
    if result.failed > 0 {
        eprintln!(
            "lmyzmail XDP decay unban skipped {} failed entries; first error: {}",
            result.failed,
            result.first_error.as_deref().unwrap_or("unknown error")
        );
    }
    Ok(XdpSyncResult {
        banned: 0,
        unbanned: result.unbanned,
        unchanged: existing.len().saturating_sub(result.unbanned),
        skipped_whitelist: 0,
        rebanned: 0,
        message: format!(
            "Decay sync completed: {} IPs unbanned, {} failed",
            result.unbanned, result.failed
        ),
    })
}

fn map_xdp_error(error: XdpError) -> XdpSyncError {
    match error {
        XdpError::Cancelled => XdpSyncError::Cancelled,
        other => XdpSyncError::Native(Arc::new(other)),
    }
}

async fn perform_full_sync(
    xdp: &XdpService,
    cringe: &CringeService,
    cancellation: &CancellationToken,
) -> Result<XdpSyncResult, XdpSyncError> {
    if cancellation.is_cancelled() {
        return Err(XdpSyncError::Cancelled);
    }
    if !xdp.ready() {
        return Ok(XdpSyncResult {
            banned: 0,
            unbanned: 0,
            unchanged: 0,
            skipped_whitelist: 0,
            rebanned: 0,
            message: "XDP not ready".into(),
        });
    }
    let existing = xdp
        .all_banned(cancellation)
        .await
        .map_err(|error| XdpSyncError::Native(Arc::new(error)))?;
    let candidates = cringe
        .xdp_reconcile_candidates(
            &existing,
            xdp.config().ban_threshold,
            xdp.config().unban_threshold,
            cancellation,
        )
        .await
        .map_err(|error| match error {
            CringeError::Cancelled => XdpSyncError::Cancelled,
            other => XdpSyncError::Database(Arc::new(other)),
        })?;
    let counts = xdp
        .reconcile(
            candidates,
            existing.into_iter().collect::<HashSet<_>>(),
            cancellation,
        )
        .await
        .map_err(|error| XdpSyncError::Native(Arc::new(error)))?;
    Ok(XdpSyncResult {
        banned: counts.banned,
        unbanned: counts.unbanned,
        unchanged: counts.unchanged,
        skipped_whitelist: counts.skipped_whitelist,
        rebanned: 0,
        message: format!(
            "Sync completed: {} newly banned, {} unbanned ({} whitelist + {} score), {} unchanged ({} high + {} mid), {} skipped whitelist (thresholds: ban={}, unban={})",
            counts.banned,
            counts.unbanned,
            counts.unbanned_whitelist,
            counts.unbanned_score,
            counts.unchanged,
            counts.unchanged_high,
            counts.unchanged_mid,
            counts.skipped_whitelist,
            xdp.config().ban_threshold,
            xdp.config().unban_threshold,
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use tokio::sync::{Semaphore, oneshot};

    use super::*;

    fn result(message: &str) -> XdpSyncResult {
        XdpSyncResult {
            banned: 1,
            unbanned: 2,
            unchanged: 3,
            skipped_whitelist: 4,
            rebanned: 0,
            message: message.to_owned(),
        }
    }

    async fn wait_for_receivers(flight: &SyncFlight, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let state = flight.state.lock().await;
                let receivers = state
                    .sender
                    .as_ref()
                    .map_or(0, watch::Sender::receiver_count);
                drop(state);
                if receivers >= expected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("singleflight subscribers must become visible");
    }

    #[tokio::test]
    async fn concurrent_syncs_share_one_operation_and_result() {
        let flight = Arc::new(SyncFlight::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let (started_sender, started_receiver) = oneshot::channel();

        let leader = tokio::spawn({
            let flight = Arc::clone(&flight);
            let calls = Arc::clone(&calls);
            let release = Arc::clone(&release);
            async move {
                let cancellation = CancellationToken::new();
                flight
                    .run(&cancellation, move |_| async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started_sender.send(()).expect("test receiver is alive");
                        let permit = release.acquire().await.expect("semaphore is open");
                        permit.forget();
                        Ok(result("shared"))
                    })
                    .await
            }
        });
        started_receiver.await.expect("leader must start");

        let follower = tokio::spawn({
            let flight = Arc::clone(&flight);
            let calls = Arc::clone(&calls);
            async move {
                let cancellation = CancellationToken::new();
                flight
                    .run(&cancellation, move |_| async move {
                        calls.fetch_add(100, Ordering::SeqCst);
                        Ok(result("unexpected"))
                    })
                    .await
            }
        });
        wait_for_receivers(&flight, 2).await;
        release.add_permits(1);

        assert_eq!(leader.await.unwrap().unwrap(), result("shared"));
        assert_eq!(follower.await.unwrap().unwrap(), result("shared"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let cancellation = CancellationToken::new();
        let next = flight
            .run(&cancellation, {
                let calls = Arc::clone(&calls);
                move |_| async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(result("next"))
                }
            })
            .await
            .unwrap();
        assert_eq!(next, result("next"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_cancel_the_shared_operation() {
        let flight = Arc::new(SyncFlight::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let (started_sender, started_receiver) = oneshot::channel();
        let leader = tokio::spawn({
            let flight = Arc::clone(&flight);
            let calls = Arc::clone(&calls);
            let release = Arc::clone(&release);
            async move {
                let cancellation = CancellationToken::new();
                flight
                    .run(&cancellation, move |_| async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started_sender.send(()).expect("test receiver is alive");
                        let permit = release.acquire().await.expect("semaphore is open");
                        permit.forget();
                        Ok(result("leader"))
                    })
                    .await
            }
        });
        started_receiver.await.expect("leader must start");

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let follower = flight
            .run(&cancelled, |_| async { Ok(result("unexpected")) })
            .await;
        assert!(matches!(follower, Err(XdpSyncError::Cancelled)));

        release.add_permits(1);
        assert_eq!(leader.await.unwrap().unwrap(), result("leader"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelled_leader_does_not_cancel_a_live_follower() {
        let flight = Arc::new(SyncFlight::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Semaphore::new(0));
        let leader_cancellation = CancellationToken::new();
        let (started_sender, started_receiver) = oneshot::channel();
        let leader =
            tokio::spawn({
                let flight = Arc::clone(&flight);
                let calls = Arc::clone(&calls);
                let release = Arc::clone(&release);
                let leader_cancellation = leader_cancellation.clone();
                async move {
                    flight
                    .run(&leader_cancellation, move |worker_cancellation| async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started_sender.send(()).expect("test receiver is alive");
                        tokio::select! {
                            _ = worker_cancellation.cancelled() => Err(XdpSyncError::Cancelled),
                            permit = release.acquire() => {
                                permit.expect("semaphore is open").forget();
                                Ok(result("survived"))
                            }
                        }
                    })
                    .await
                }
            });
        started_receiver.await.expect("leader must start");

        let follower = tokio::spawn({
            let flight = Arc::clone(&flight);
            async move {
                let cancellation = CancellationToken::new();
                flight
                    .run(&cancellation, |_| async { Ok(result("unexpected")) })
                    .await
            }
        });
        wait_for_receivers(&flight, 2).await;

        leader_cancellation.cancel();
        assert!(matches!(
            leader.await.unwrap(),
            Err(XdpSyncError::Cancelled)
        ));
        assert!(!follower.is_finished());
        release.add_permits(1);

        assert_eq!(follower.await.unwrap().unwrap(), result("survived"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn panicked_worker_notifies_waiters_and_releases_the_next_generation() {
        let flight = Arc::new(SyncFlight::default());
        let cancellation = CancellationToken::new();
        let first = flight
            .run(&cancellation, |_| async {
                panic!("injected XDP sync panic");
            })
            .await;
        assert!(matches!(first, Err(XdpSyncError::WorkerPanicked)));

        let second = flight
            .run(&cancellation, |_| async { Ok(result("recovered")) })
            .await
            .unwrap();
        assert_eq!(second, result("recovered"));
    }

    #[tokio::test]
    async fn shutdown_drains_the_in_flight_worker() {
        let flight = Arc::new(SyncFlight::default());
        let release = Arc::new(Semaphore::new(0));
        let (started_sender, started_receiver) = oneshot::channel();
        let (cancelled_sender, cancelled_receiver) = oneshot::channel();
        let waiter = tokio::spawn({
            let flight = Arc::clone(&flight);
            let release = Arc::clone(&release);
            async move {
                let cancellation = CancellationToken::new();
                flight
                    .run(&cancellation, move |worker_cancellation| async move {
                        started_sender.send(()).expect("test receiver is alive");
                        worker_cancellation.cancelled().await;
                        cancelled_sender.send(()).expect("test receiver is alive");
                        let permit = release.acquire().await.expect("semaphore is open");
                        permit.forget();
                        Ok(result("drained"))
                    })
                    .await
            }
        });
        started_receiver.await.expect("worker must start");

        let shutdown = tokio::spawn({
            let flight = Arc::clone(&flight);
            async move { flight.shutdown().await }
        });
        cancelled_receiver
            .await
            .expect("shutdown must cancel the shared worker");
        assert!(!shutdown.is_finished());
        release.add_permits(1);

        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("shutdown must drain the worker")
            .expect("shutdown task must not panic");
        assert_eq!(waiter.await.unwrap().unwrap(), result("drained"));
        assert!(flight.state.lock().await.worker.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn decay_unban_deadline_cancels_and_bounds_the_drain() {
        let cancellation = CancellationToken::new();
        let operation_cancellation = cancellation.clone();
        let cancellation_observed = Arc::new(AtomicUsize::new(0));
        let operation_observed = Arc::clone(&cancellation_observed);
        let task = tokio::spawn(async move {
            let operation_token = operation_cancellation.clone();
            run_decay_unban_operation_bounded(
                &operation_cancellation,
                Duration::from_secs(20),
                Duration::from_secs(2),
                async move {
                    operation_token.cancelled().await;
                    operation_observed.store(1, Ordering::SeqCst);
                    std::future::pending().await
                },
            )
            .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(20)).await;
        tokio::task::yield_now().await;
        assert_eq!(cancellation_observed.load(Ordering::SeqCst), 1);
        assert!(!task.is_finished());

        tokio::time::advance(Duration::from_secs(2)).await;
        let result = task.await.unwrap();
        assert!(matches!(
            result,
            Err(XdpSyncError::Native(error)) if matches!(error.as_ref(), XdpError::Timeout)
        ));
    }
}
