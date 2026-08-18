use std::{
    env,
    fmt::Write as _,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const ENABLE_ENV: &str = "LMYZMAIL_QUEUE_OBSERVER";
const SCHEMA: &str = "lmyzmail.redis-queue-observation.v1";
const SNAPSHOT_INTERVAL: u64 = 256;

#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum Operation {
    ActiveTaskIds,
    Publish,
}

impl Operation {
    const ALL: [Self; 2] = [Self::ActiveTaskIds, Self::Publish];

    const fn name(self) -> &'static str {
        match self {
            Self::ActiveTaskIds => "active_task_ids",
            Self::Publish => "publish",
        }
    }
}

#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum PublishFailure {
    Connection,
    Timeout,
    TaskIdConflict,
    DomainStatusConflict,
    SentFileConflict,
    WrongType,
    Other,
}

impl PublishFailure {
    const ALL: [Self; 7] = [
        Self::Connection,
        Self::Timeout,
        Self::TaskIdConflict,
        Self::DomainStatusConflict,
        Self::SentFileConflict,
        Self::WrongType,
        Self::Other,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Timeout => "timeout",
            Self::TaskIdConflict => "task_id_conflict",
            Self::DomainStatusConflict => "domain_status_conflict",
            Self::SentFileConflict => "sent_file_conflict",
            Self::WrongType => "wrong_type",
            Self::Other => "other",
        }
    }
}

struct Counters {
    completed: AtomicU64,
    failed: AtomicU64,
    cancelled: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            completed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            cancelled: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
        }
    }

    fn record(&self, elapsed: Duration, outcome: Outcome) {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        match outcome {
            Outcome::Completed => &self.completed,
            Outcome::Failed => &self.failed,
            Outcome::Cancelled => &self.cancelled,
        }
        .fetch_add(1, Ordering::Relaxed);
        let _ = self
            .total_ns
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                Some(total.saturating_add(elapsed_ns))
            });
        self.max_ns.fetch_max(elapsed_ns, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
enum Outcome {
    Completed,
    Failed,
    Cancelled,
}

struct Observer {
    operations: [Counters; Operation::ALL.len()],
    publish_failures: [AtomicU64; PublishFailure::ALL.len()],
    calls: AtomicU64,
    sequence: AtomicU64,
}

impl Observer {
    fn new() -> Self {
        Self {
            operations: std::array::from_fn(|_| Counters::new()),
            publish_failures: std::array::from_fn(|_| AtomicU64::new(0)),
            calls: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
        }
    }

    fn from_environment() -> Option<Self> {
        (env::var(ENABLE_ENV).as_deref() == Ok("1")).then(Self::new)
    }

    fn record(&self, operation: Operation, elapsed: Duration, outcome: Outcome) {
        self.operations[operation as usize].record(elapsed, outcome);
        let calls = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        if calls.is_multiple_of(SNAPSHOT_INTERVAL) {
            eprintln!("LMYZMAIL_QUEUE_OBSERVER {}", self.snapshot());
        }
    }

    fn record_publish_failure(&self, failure: PublishFailure) {
        self.publish_failures[failure as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> String {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let mut output = String::with_capacity(512);
        write!(
            output,
            "{{\"schema\":\"{SCHEMA}\",\"sequence\":{sequence},\"pid\":{},\"calls\":{},\"operations\":{{",
            std::process::id(),
            self.calls.load(Ordering::Relaxed),
        )
        .expect("writing a bounded queue observation to String cannot fail");
        for (index, operation) in Operation::ALL.into_iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let counters = &self.operations[operation as usize];
            write!(
                output,
                "\"{}\":{{\"completed\":{},\"failed\":{},\"cancelled\":{},\"total_ns\":{},\"max_ns\":{}}}",
                operation.name(),
                counters.completed.load(Ordering::Relaxed),
                counters.failed.load(Ordering::Relaxed),
                counters.cancelled.load(Ordering::Relaxed),
                counters.total_ns.load(Ordering::Relaxed),
                counters.max_ns.load(Ordering::Relaxed),
            )
            .expect("writing a bounded queue observation to String cannot fail");
        }
        output.push_str("},\"publish_failures\":{");
        for (index, failure) in PublishFailure::ALL.into_iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            write!(
                output,
                "\"{}\":{}",
                failure.name(),
                self.publish_failures[failure as usize].load(Ordering::Relaxed),
            )
            .expect("writing a bounded queue observation to String cannot fail");
        }
        output.push_str("}}");
        output
    }
}

static OBSERVER: OnceLock<Option<Observer>> = OnceLock::new();

fn observer() -> Option<&'static Observer> {
    OBSERVER.get_or_init(Observer::from_environment).as_ref()
}

pub(crate) fn record_publish_failure(failure: PublishFailure) {
    if let Some(observer) = observer() {
        observer.record_publish_failure(failure);
    }
}

pub(crate) struct Timer {
    observer: Option<&'static Observer>,
    operation: Operation,
    started: Option<Instant>,
}

impl Timer {
    pub(crate) fn start(operation: Operation) -> Self {
        let observer = observer();
        Self {
            observer,
            operation,
            started: observer.map(|_| Instant::now()),
        }
    }

    pub(crate) fn finish(mut self, completed: bool) {
        if let (Some(observer), Some(started)) = (self.observer, self.started.take()) {
            observer.record(
                self.operation,
                started.elapsed(),
                if completed {
                    Outcome::Completed
                } else {
                    Outcome::Failed
                },
            );
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let (Some(observer), Some(started)) = (self.observer, self.started.take()) {
            observer.record(self.operation, started.elapsed(), Outcome::Cancelled);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_keeps_operation_outcomes_separate() {
        let observer = Observer::new();
        observer.record(
            Operation::Publish,
            Duration::from_micros(7),
            Outcome::Completed,
        );
        observer.record(
            Operation::ActiveTaskIds,
            Duration::from_micros(11),
            Outcome::Failed,
        );
        let value: serde_json::Value = serde_json::from_str(&observer.snapshot()).unwrap();
        assert_eq!(value["calls"], 2);
        assert_eq!(value["operations"]["publish"]["completed"], 1);
        assert_eq!(value["operations"]["publish"]["total_ns"], 7_000);
        assert_eq!(value["operations"]["active_task_ids"]["failed"], 1);
        assert_eq!(value["operations"]["active_task_ids"]["max_ns"], 11_000);
        assert_eq!(value["publish_failures"]["timeout"], 0);
    }

    #[test]
    fn snapshot_classifies_publish_failures_without_error_payloads() {
        let observer = Observer::new();
        observer.record_publish_failure(PublishFailure::TaskIdConflict);
        observer.record_publish_failure(PublishFailure::TaskIdConflict);
        observer.record_publish_failure(PublishFailure::Timeout);
        let value: serde_json::Value = serde_json::from_str(&observer.snapshot()).unwrap();
        assert_eq!(value["publish_failures"]["task_id_conflict"], 2);
        assert_eq!(value["publish_failures"]["timeout"], 1);
        assert_eq!(value["publish_failures"]["other"], 0);
    }
}
