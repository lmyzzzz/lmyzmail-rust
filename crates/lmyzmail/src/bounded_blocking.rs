use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
};

use tokio::sync::oneshot;
use tokio::time::{Duration, Instant, sleep};

type Job = Box<dyn FnOnce() + Send + 'static>;
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SubmitError {
    Closed,
    Full,
}

impl fmt::Display for SubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("blocking pool is closed"),
            Self::Full => formatter.write_str("blocking pool queue is full"),
        }
    }
}

pub(crate) struct BoundedBlockingPool {
    sender: Mutex<Option<SyncSender<Job>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    strict_shutdown_started: AtomicBool,
}

impl BoundedBlockingPool {
    pub(crate) fn new(
        thread_name: &'static str,
        worker_count: usize,
        queue_capacity: usize,
    ) -> std::io::Result<Self> {
        assert!(worker_count > 0, "blocking pool requires a worker");
        assert!(queue_capacity > 0, "blocking pool requires queue capacity");

        let (sender, receiver) = mpsc::sync_channel::<Job>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(worker_count);
        for index in 0..worker_count {
            let worker_receiver = Arc::clone(&receiver);
            let spawn = thread::Builder::new()
                .name(format!("{thread_name}-{index}"))
                .spawn(move || worker_loop(&worker_receiver));
            match spawn {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    drop(sender);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error);
                }
            }
        }

        Ok(Self {
            sender: Mutex::new(Some(sender)),
            workers: Mutex::new(workers),
            strict_shutdown_started: AtomicBool::new(false),
        })
    }

    pub(crate) fn submit<T, F>(&self, work: F) -> Result<oneshot::Receiver<T>, SubmitError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let (result_sender, result_receiver) = oneshot::channel();
        let job = Box::new(move || {
            let _ = result_sender.send(work());
        });
        let sender = self
            .sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(sender) = sender.as_ref() else {
            return Err(SubmitError::Closed);
        };
        sender.try_send(job).map_err(|error| match error {
            TrySendError::Full(_) => SubmitError::Full,
            TrySendError::Disconnected(_) => SubmitError::Closed,
        })?;
        Ok(result_receiver)
    }

    pub(crate) async fn shutdown(&self, deadline: Duration) -> bool {
        self.close_admission();

        let deadline = Instant::now() + deadline;
        loop {
            let workers_finished = self
                .workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .all(JoinHandle::is_finished);
            if workers_finished || Instant::now() >= deadline {
                break;
            }
            sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(SHUTDOWN_POLL_INTERVAL),
            )
            .await;
        }

        join_finished_and_detach_rest(
            &mut self
                .workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Closes admission and waits up to `deadline` for every worker OS thread
    /// to exit. Unfinished handles remain owned by the pool so a later call can
    /// retry without detaching workers that still own stress-test resources.
    pub(crate) async fn shutdown_strict(&self, deadline: Duration) -> bool {
        self.strict_shutdown_started.store(true, Ordering::Release);
        self.close_admission();

        let deadline = Instant::now() + deadline;
        loop {
            {
                let mut workers = self
                    .workers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                join_finished(workers.as_mut());
                if workers.is_empty() {
                    return true;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(SHUTDOWN_POLL_INTERVAL),
            )
            .await;
        }

        let mut workers = self
            .workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        join_finished(workers.as_mut());
        workers.is_empty()
    }

    fn close_admission(&self) {
        let sender = self
            .sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(sender);
    }
}

impl Drop for BoundedBlockingPool {
    fn drop(&mut self) {
        let sender = self
            .sender
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(sender);
        let workers = self
            .workers
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        join_finished(workers);
        if self.strict_shutdown_started.load(Ordering::Acquire) && !workers.is_empty() {
            eprintln!(
                "lmyzmail strict blocking pool dropped with live workers; aborting to preserve ownership invariants"
            );
            std::process::abort();
        }
        join_finished_and_detach_rest(workers);
    }
}

fn join_finished_and_detach_rest(workers: &mut Vec<JoinHandle<()>>) -> bool {
    let mut joined_all = true;
    for worker in workers.drain(..) {
        if worker.is_finished() {
            let _ = worker.join();
        } else {
            joined_all = false;
            drop(worker);
        }
    }
    joined_all
}

fn join_finished(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

fn worker_loop(receiver: &Mutex<Receiver<Job>>) {
    loop {
        let job = receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv();
        let Ok(job) = job else {
            return;
        };
        let _ = catch_unwind(AssertUnwindSafe(job));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn executes_on_named_dedicated_worker() {
        let pool = BoundedBlockingPool::new("lmyzmail-test-pool", 1, 1).unwrap();
        let receiver = pool
            .submit(|| std::thread::current().name().map(str::to_owned))
            .unwrap();
        assert_eq!(
            receiver.await.unwrap().as_deref(),
            Some("lmyzmail-test-pool-0")
        );
    }

    #[test]
    fn rejects_work_when_the_bounded_queue_is_full() {
        let pool = BoundedBlockingPool::new("lmyzmail-test-bound", 1, 1).unwrap();
        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let _running = pool
            .submit(move || {
                started_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
            })
            .unwrap();
        started_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        let (queued_sender, queued_receiver) = mpsc::channel();
        let _queued = pool
            .submit(move || queued_receiver.recv().unwrap())
            .unwrap();
        assert_eq!(pool.submit(|| ()).unwrap_err(), SubmitError::Full);

        release_sender.send(()).unwrap();
        queued_sender.send(()).unwrap();
    }

    #[tokio::test]
    async fn bounded_shutdown_detaches_a_stalled_worker() {
        let pool = BoundedBlockingPool::new("lmyzmail-test-shutdown", 1, 1).unwrap();
        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let result = pool
            .submit(move || {
                started_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
                42_u8
            })
            .unwrap();
        started_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        assert!(!pool.shutdown(Duration::from_millis(10)).await);
        assert!(
            pool.workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
        assert_eq!(pool.submit(|| ()).unwrap_err(), SubmitError::Closed);

        release_sender.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), result)
                .await
                .expect("detached worker must remain memory-safe")
                .unwrap(),
            42
        );
    }

    #[tokio::test]
    async fn strict_shutdown_retains_a_stalled_worker_for_a_later_retry() {
        let pool = Arc::new(BoundedBlockingPool::new("lmyzmail-test-strict", 1, 1).unwrap());
        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let result = pool
            .submit(move || {
                started_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
                42_u8
            })
            .unwrap();
        started_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        assert!(!pool.shutdown_strict(Duration::from_millis(10)).await);
        assert_eq!(pool.submit(|| ()).unwrap_err(), SubmitError::Closed);
        assert_eq!(
            pool.workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );

        release_sender.send(()).unwrap();
        assert_eq!(result.await.unwrap(), 42);
        assert!(pool.shutdown_strict(Duration::from_secs(1)).await);
        assert!(
            pool.workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }
}
