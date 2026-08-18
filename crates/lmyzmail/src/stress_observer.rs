use std::{
    env,
    fmt::Write as _,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const ENABLE_ENV: &str = "LMYZMAIL_STRESS_ENQUEUE_OBSERVER";
const SCHEMA: &str = "lmyzmail.stress-enqueue-observation.v1";
const SNAPSHOT_INTERVAL: u64 = 256;

#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum Stage {
    AdmissionWait,
    Reserve,
    Materialize,
    Persist,
    Publish,
    Cleanup,
    Total,
}

impl Stage {
    const ALL: [Self; 7] = [
        Self::AdmissionWait,
        Self::Reserve,
        Self::Materialize,
        Self::Persist,
        Self::Publish,
        Self::Cleanup,
        Self::Total,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::AdmissionWait => "admission_wait",
            Self::Reserve => "reserve",
            Self::Materialize => "materialize",
            Self::Persist => "persist",
            Self::Publish => "publish",
            Self::Cleanup => "cleanup",
            Self::Total => "total",
        }
    }
}

struct Counters {
    count: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
        }
    }

    fn record(&self, elapsed: Duration) -> u64 {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = self
            .total_ns
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                Some(total.saturating_add(elapsed_ns))
            });
        self.max_ns.fetch_max(elapsed_ns, Ordering::Relaxed);
        count
    }
}

struct Observer {
    stages: [Counters; Stage::ALL.len()],
    active: AtomicU64,
    peak_active: AtomicU64,
    sequence: AtomicU64,
}

impl Observer {
    fn new() -> Self {
        Self {
            stages: std::array::from_fn(|_| Counters::new()),
            active: AtomicU64::new(0),
            peak_active: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
        }
    }

    fn from_environment() -> Option<Self> {
        (env::var(ENABLE_ENV).as_deref() == Ok("1")).then(Self::new)
    }

    fn record(&self, stage: Stage, elapsed: Duration) {
        let count = self.stages[stage as usize].record(elapsed);
        if matches!(stage, Stage::Total) && count.is_multiple_of(SNAPSHOT_INTERVAL) {
            eprintln!("LMYZMAIL_STRESS_ENQUEUE_OBSERVER {}", self.snapshot());
        }
    }

    fn acquire(&self) {
        let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak_active.fetch_max(active, Ordering::Relaxed);
    }

    fn release(&self) {
        let previous = self.active.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0);
    }

    fn snapshot(&self) -> String {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let mut output = String::with_capacity(1_024);
        write!(
            output,
            "{{\"schema\":\"{SCHEMA}\",\"sequence\":{sequence},\"pid\":{},\"active\":{},\"peak_active\":{},\"stages\":{{",
            std::process::id(),
            self.active.load(Ordering::Relaxed),
            self.peak_active.load(Ordering::Relaxed),
        )
        .expect("writing a bounded stress observation to String cannot fail");
        for (index, stage) in Stage::ALL.into_iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let counters = &self.stages[stage as usize];
            write!(
                output,
                "\"{}\":{{\"count\":{},\"total_ns\":{},\"max_ns\":{}}}",
                stage.name(),
                counters.count.load(Ordering::Relaxed),
                counters.total_ns.load(Ordering::Relaxed),
                counters.max_ns.load(Ordering::Relaxed),
            )
            .expect("writing a bounded stress observation to String cannot fail");
        }
        output.push_str("}}");
        output
    }
}

static OBSERVER: OnceLock<Option<Observer>> = OnceLock::new();

fn observer(enabled: bool) -> Option<&'static Observer> {
    enabled
        .then(|| OBSERVER.get_or_init(Observer::from_environment).as_ref())
        .flatten()
}

pub(crate) struct Timer {
    observer: Option<&'static Observer>,
    stage: Stage,
    started: Option<Instant>,
}

impl Timer {
    pub(crate) fn start(stage: Stage, enabled: bool) -> Self {
        let observer = observer(enabled);
        Self {
            observer,
            stage,
            started: observer.map(|_| Instant::now()),
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let (Some(observer), Some(started)) = (self.observer, self.started.take()) {
            observer.record(self.stage, started.elapsed());
        }
    }
}

pub(crate) struct ActiveGuard {
    observer: Option<&'static Observer>,
}

impl ActiveGuard {
    pub(crate) fn acquire(enabled: bool) -> Self {
        let observer = observer(enabled);
        if let Some(observer) = observer {
            observer.acquire();
        }
        Self { observer }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if let Some(observer) = self.observer.take() {
            observer.release();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_contains_stage_and_occupancy_totals() {
        let observer = Observer::new();
        observer.acquire();
        observer.record(Stage::Persist, Duration::from_nanos(17));
        observer.record(Stage::Total, Duration::from_nanos(29));
        observer.release();

        let value: serde_json::Value = serde_json::from_str(&observer.snapshot()).unwrap();
        assert_eq!(value["schema"], SCHEMA);
        assert_eq!(value["active"], 0);
        assert_eq!(value["peak_active"], 1);
        assert_eq!(value["stages"]["persist"]["count"], 1);
        assert_eq!(value["stages"]["persist"]["total_ns"], 17);
        assert_eq!(value["stages"]["total"]["total_ns"], 29);
    }
}
