use std::{
    env,
    fmt::Write as _,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const ENABLE_ENV: &str = "LMYZMAIL_COORDINATOR_OBSERVER";
const SCHEMA: &str = "lmyzmail.coordinator-stage-observation.v1";
const SNAPSHOT_INTERVAL: u64 = 256;
const INBOUND_INDEX_BATCH_BUCKETS: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum CoordinatorStage {
    QueueClaim,
    DatabaseClaim,
    RecipientRoster,
    BeginAttempt,
    InitialLedger,
    DsnLookup,
    DomainStatusRead,
    ContentAuthority,
    RouteResolve,
    SmtpPrepare,
    SmtpAuthorize,
    SmtpConnect,
    SmtpGreeting,
    SmtpEhlo,
    SmtpStartTls,
    SmtpEnvelope,
    SmtpMessagePrepare,
    SmtpDataReady,
    SmtpBodyWrite,
    PreparedCheckpoint,
    SmtpCommit,
    SmtpFinalDot,
    SmtpFinalReply,
    SmtpQuit,
    ResultCheckpoint,
    ResultCheckpointSnapshot,
    ResultCheckpointMutation,
    ResultCheckpointPool,
    ResultCheckpointBegin,
    ResultCheckpointDeadline,
    ResultCheckpointLegacyLock,
    ResultCheckpointAttemptLock,
    ResultCheckpointAttemptRowLock,
    ResultCheckpointRosterVerify,
    ResultCheckpointBarrierVerify,
    ResultCheckpointRecipientUpdate,
    ResultCheckpointAttemptUpdate,
    ResultCheckpointCommit,
    DomainLedgerRefresh,
    ProjectionLedgerRead,
    LegacyProjection,
    FinalLedgerRead,
    LegacyAttemptRead,
    DomainStatusWrite,
    QueueRenew,
    KeepaliveQuiesce,
    QueueAcknowledge,
    QueueAckSpoolCleanup,
    QueueAckSpoolSnapshot,
    QueueAckSpoolPermit,
    QueueAckSpoolSetup,
    QueueAckSpoolProofValidation,
    QueueAckSpoolSentCompare,
    QueueAckSpoolMutation,
    QueueAckSpoolDurability,
    QueueAckSpoolProofCleanup,
    QueueAckSpoolCheckpoint,
    QueueAckMutation,
    QueueAckReconciliation,
    QueueAckSidecarCleanup,
    QueueAckSidecarSnapshot,
    QueueAckSidecarProofCleanup,
    QueueAckSidecarDelete,
    InboundPrepareFile,
    InboundIntentInsert,
    InboundPublishFile,
    InboundIndexCommit,
    InboundIndexBatchAdmission,
    InboundIndexBatchQueueWait,
    InboundIndexBatchDispatchWait,
    InboundIndexBatchCollect,
    InboundIndexBatchWorker,
    InboundIndexBatchResponseWait,
    InboundIndexPool,
    InboundIndexBegin,
    InboundIndexIntentLock,
    InboundIndexIntentRead,
    InboundIndexMailboxRead,
    InboundIndexExistingRead,
    InboundIndexInsert,
    InboundIndexCountState,
    InboundIndexProjectionState,
    InboundIndexIntentAdvance,
    InboundIndexMutation,
    InboundIndexTransactionCommit,
    InboundPublishVerify,
    InboundIntentComplete,
    InboundCompletionBatchAdmission,
    InboundCompletionBatchQueueWait,
    InboundCompletionBatchDispatchWait,
    InboundCompletionBatchCollect,
    InboundCompletionBatchWorker,
    InboundCompletionBatchResponseWait,
    InboundIntentCompletePool,
    InboundIntentCompleteBegin,
    InboundIntentCompleteLock,
    InboundIntentCompleteRead,
    InboundIntentCompleteDelete,
    InboundIntentCompleteTransactionCommit,
    InboundProjectionFlush,
}

impl CoordinatorStage {
    const ALL: [Self; 100] = [
        Self::QueueClaim,
        Self::DatabaseClaim,
        Self::RecipientRoster,
        Self::BeginAttempt,
        Self::InitialLedger,
        Self::DsnLookup,
        Self::DomainStatusRead,
        Self::ContentAuthority,
        Self::RouteResolve,
        Self::SmtpPrepare,
        Self::SmtpAuthorize,
        Self::SmtpConnect,
        Self::SmtpGreeting,
        Self::SmtpEhlo,
        Self::SmtpStartTls,
        Self::SmtpEnvelope,
        Self::SmtpMessagePrepare,
        Self::SmtpDataReady,
        Self::SmtpBodyWrite,
        Self::PreparedCheckpoint,
        Self::SmtpCommit,
        Self::SmtpFinalDot,
        Self::SmtpFinalReply,
        Self::SmtpQuit,
        Self::ResultCheckpoint,
        Self::ResultCheckpointSnapshot,
        Self::ResultCheckpointMutation,
        Self::ResultCheckpointPool,
        Self::ResultCheckpointBegin,
        Self::ResultCheckpointDeadline,
        Self::ResultCheckpointLegacyLock,
        Self::ResultCheckpointAttemptLock,
        Self::ResultCheckpointAttemptRowLock,
        Self::ResultCheckpointRosterVerify,
        Self::ResultCheckpointBarrierVerify,
        Self::ResultCheckpointRecipientUpdate,
        Self::ResultCheckpointAttemptUpdate,
        Self::ResultCheckpointCommit,
        Self::DomainLedgerRefresh,
        Self::ProjectionLedgerRead,
        Self::LegacyProjection,
        Self::FinalLedgerRead,
        Self::LegacyAttemptRead,
        Self::DomainStatusWrite,
        Self::QueueRenew,
        Self::KeepaliveQuiesce,
        Self::QueueAcknowledge,
        Self::QueueAckSpoolCleanup,
        Self::QueueAckSpoolSnapshot,
        Self::QueueAckSpoolPermit,
        Self::QueueAckSpoolSetup,
        Self::QueueAckSpoolProofValidation,
        Self::QueueAckSpoolSentCompare,
        Self::QueueAckSpoolMutation,
        Self::QueueAckSpoolDurability,
        Self::QueueAckSpoolProofCleanup,
        Self::QueueAckSpoolCheckpoint,
        Self::QueueAckMutation,
        Self::QueueAckReconciliation,
        Self::QueueAckSidecarCleanup,
        Self::QueueAckSidecarSnapshot,
        Self::QueueAckSidecarProofCleanup,
        Self::QueueAckSidecarDelete,
        Self::InboundPrepareFile,
        Self::InboundIntentInsert,
        Self::InboundPublishFile,
        Self::InboundIndexCommit,
        Self::InboundIndexBatchAdmission,
        Self::InboundIndexBatchQueueWait,
        Self::InboundIndexBatchDispatchWait,
        Self::InboundIndexBatchCollect,
        Self::InboundIndexBatchWorker,
        Self::InboundIndexBatchResponseWait,
        Self::InboundIndexPool,
        Self::InboundIndexBegin,
        Self::InboundIndexIntentLock,
        Self::InboundIndexIntentRead,
        Self::InboundIndexMailboxRead,
        Self::InboundIndexExistingRead,
        Self::InboundIndexInsert,
        Self::InboundIndexCountState,
        Self::InboundIndexProjectionState,
        Self::InboundIndexIntentAdvance,
        Self::InboundIndexMutation,
        Self::InboundIndexTransactionCommit,
        Self::InboundPublishVerify,
        Self::InboundIntentComplete,
        Self::InboundCompletionBatchAdmission,
        Self::InboundCompletionBatchQueueWait,
        Self::InboundCompletionBatchDispatchWait,
        Self::InboundCompletionBatchCollect,
        Self::InboundCompletionBatchWorker,
        Self::InboundCompletionBatchResponseWait,
        Self::InboundIntentCompletePool,
        Self::InboundIntentCompleteBegin,
        Self::InboundIntentCompleteLock,
        Self::InboundIntentCompleteRead,
        Self::InboundIntentCompleteDelete,
        Self::InboundIntentCompleteTransactionCommit,
        Self::InboundProjectionFlush,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::QueueClaim => "queue_claim",
            Self::DatabaseClaim => "database_claim",
            Self::RecipientRoster => "recipient_roster",
            Self::BeginAttempt => "begin_attempt",
            Self::InitialLedger => "initial_ledger",
            Self::DsnLookup => "dsn_lookup",
            Self::DomainStatusRead => "domain_status_read",
            Self::ContentAuthority => "content_authority",
            Self::RouteResolve => "route_resolve",
            Self::SmtpPrepare => "smtp_prepare",
            Self::SmtpAuthorize => "smtp_authorize",
            Self::SmtpConnect => "smtp_connect",
            Self::SmtpGreeting => "smtp_greeting",
            Self::SmtpEhlo => "smtp_ehlo",
            Self::SmtpStartTls => "smtp_starttls",
            Self::SmtpEnvelope => "smtp_envelope",
            Self::SmtpMessagePrepare => "smtp_message_prepare",
            Self::SmtpDataReady => "smtp_data_ready",
            Self::SmtpBodyWrite => "smtp_body_write",
            Self::PreparedCheckpoint => "prepared_checkpoint",
            Self::SmtpCommit => "smtp_commit",
            Self::SmtpFinalDot => "smtp_final_dot",
            Self::SmtpFinalReply => "smtp_final_reply",
            Self::SmtpQuit => "smtp_quit",
            Self::ResultCheckpoint => "result_checkpoint",
            Self::ResultCheckpointSnapshot => "result_checkpoint_snapshot",
            Self::ResultCheckpointMutation => "result_checkpoint_mutation",
            Self::ResultCheckpointPool => "result_checkpoint_pool",
            Self::ResultCheckpointBegin => "result_checkpoint_begin",
            Self::ResultCheckpointDeadline => "result_checkpoint_deadline",
            Self::ResultCheckpointLegacyLock => "result_checkpoint_legacy_lock",
            Self::ResultCheckpointAttemptLock => "result_checkpoint_attempt_lock",
            Self::ResultCheckpointAttemptRowLock => "result_checkpoint_attempt_row_lock",
            Self::ResultCheckpointRosterVerify => "result_checkpoint_roster_verify",
            Self::ResultCheckpointBarrierVerify => "result_checkpoint_barrier_verify",
            Self::ResultCheckpointRecipientUpdate => "result_checkpoint_recipient_update",
            Self::ResultCheckpointAttemptUpdate => "result_checkpoint_attempt_update",
            Self::ResultCheckpointCommit => "result_checkpoint_commit",
            Self::DomainLedgerRefresh => "domain_ledger_refresh",
            Self::ProjectionLedgerRead => "projection_ledger_read",
            Self::LegacyProjection => "legacy_projection",
            Self::FinalLedgerRead => "final_ledger_read",
            Self::LegacyAttemptRead => "legacy_attempt_read",
            Self::DomainStatusWrite => "domain_status_write",
            Self::QueueRenew => "queue_renew",
            Self::KeepaliveQuiesce => "keepalive_quiesce",
            Self::QueueAcknowledge => "queue_acknowledge",
            Self::QueueAckSpoolCleanup => "queue_ack_spool_cleanup",
            Self::QueueAckSpoolSnapshot => "queue_ack_spool_snapshot",
            Self::QueueAckSpoolPermit => "queue_ack_spool_permit",
            Self::QueueAckSpoolSetup => "queue_ack_spool_setup",
            Self::QueueAckSpoolProofValidation => "queue_ack_spool_proof_validation",
            Self::QueueAckSpoolSentCompare => "queue_ack_spool_sent_compare",
            Self::QueueAckSpoolMutation => "queue_ack_spool_mutation",
            Self::QueueAckSpoolDurability => "queue_ack_spool_durability",
            Self::QueueAckSpoolProofCleanup => "queue_ack_spool_proof_cleanup",
            Self::QueueAckSpoolCheckpoint => "queue_ack_spool_checkpoint",
            Self::QueueAckMutation => "queue_ack_mutation",
            Self::QueueAckReconciliation => "queue_ack_reconciliation",
            Self::QueueAckSidecarCleanup => "queue_ack_sidecar_cleanup",
            Self::QueueAckSidecarSnapshot => "queue_ack_sidecar_snapshot",
            Self::QueueAckSidecarProofCleanup => "queue_ack_sidecar_proof_cleanup",
            Self::QueueAckSidecarDelete => "queue_ack_sidecar_delete",
            Self::InboundPrepareFile => "inbound_prepare_file",
            Self::InboundIntentInsert => "inbound_intent_insert",
            Self::InboundPublishFile => "inbound_publish_file",
            Self::InboundIndexCommit => "inbound_index_commit",
            Self::InboundIndexBatchAdmission => "inbound_index_batch_admission",
            Self::InboundIndexBatchQueueWait => "inbound_index_batch_queue_wait",
            Self::InboundIndexBatchDispatchWait => "inbound_index_batch_dispatch_wait",
            Self::InboundIndexBatchCollect => "inbound_index_batch_collect",
            Self::InboundIndexBatchWorker => "inbound_index_batch_worker",
            Self::InboundIndexBatchResponseWait => "inbound_index_batch_response_wait",
            Self::InboundIndexPool => "inbound_index_pool",
            Self::InboundIndexBegin => "inbound_index_begin",
            Self::InboundIndexIntentLock => "inbound_index_intent_lock",
            Self::InboundIndexIntentRead => "inbound_index_intent_read",
            Self::InboundIndexMailboxRead => "inbound_index_mailbox_read",
            Self::InboundIndexExistingRead => "inbound_index_existing_read",
            Self::InboundIndexInsert => "inbound_index_insert",
            Self::InboundIndexCountState => "inbound_index_count_state",
            Self::InboundIndexProjectionState => "inbound_index_projection_state",
            Self::InboundIndexIntentAdvance => "inbound_index_intent_advance",
            Self::InboundIndexMutation => "inbound_index_mutation",
            Self::InboundIndexTransactionCommit => "inbound_index_transaction_commit",
            Self::InboundPublishVerify => "inbound_publish_verify",
            Self::InboundIntentComplete => "inbound_intent_complete",
            Self::InboundCompletionBatchAdmission => "inbound_completion_batch_admission",
            Self::InboundCompletionBatchQueueWait => "inbound_completion_batch_queue_wait",
            Self::InboundCompletionBatchDispatchWait => "inbound_completion_batch_dispatch_wait",
            Self::InboundCompletionBatchCollect => "inbound_completion_batch_collect",
            Self::InboundCompletionBatchWorker => "inbound_completion_batch_worker",
            Self::InboundCompletionBatchResponseWait => "inbound_completion_batch_response_wait",
            Self::InboundIntentCompletePool => "inbound_intent_complete_pool",
            Self::InboundIntentCompleteBegin => "inbound_intent_complete_begin",
            Self::InboundIntentCompleteLock => "inbound_intent_complete_lock",
            Self::InboundIntentCompleteRead => "inbound_intent_complete_read",
            Self::InboundIntentCompleteDelete => "inbound_intent_complete_delete",
            Self::InboundIntentCompleteTransactionCommit => {
                "inbound_intent_complete_transaction_commit"
            }
            Self::InboundProjectionFlush => "inbound_projection_flush",
        }
    }
}

struct StageCounters {
    count: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
}

impl StageCounters {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
        }
    }

    fn record(&self, elapsed: Duration) {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        self.count.fetch_add(1, Ordering::Relaxed);
        let _ = self
            .total_ns
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                Some(total.saturating_add(elapsed_ns))
            });
        self.max_ns.fetch_max(elapsed_ns, Ordering::Relaxed);
    }
}

struct InboundIndexBatchCounters {
    // The single index-commit worker is the sole writer; snapshots may run on any task.
    sequence: AtomicU64,
    batches: AtomicU64,
    rows: AtomicU64,
    max_rows: AtomicU64,
    size_buckets: [AtomicU64; INBOUND_INDEX_BATCH_BUCKETS],
}

impl InboundIndexBatchCounters {
    fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            rows: AtomicU64::new(0),
            max_rows: AtomicU64::new(0),
            size_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn record(&self, rows: usize) {
        debug_assert!((1..=64).contains(&rows));
        let rows = u64::try_from(rows).unwrap_or(u64::MAX);
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.batches.fetch_add(1, Ordering::Relaxed);
        let _ = self
            .rows
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                Some(total.saturating_add(rows))
            });
        self.max_rows.fetch_max(rows, Ordering::Relaxed);
        let bucket = match rows {
            1 => 0,
            2..=4 => 1,
            5..=8 => 2,
            9..=16 => 3,
            17..=32 => 4,
            _ => 5,
        };
        self.size_buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.sequence.fetch_add(1, Ordering::Release);
    }

    fn snapshot(&self) -> InboundIndexBatchSnapshot {
        loop {
            let before = self.sequence.load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                std::hint::spin_loop();
                continue;
            }
            let snapshot = InboundIndexBatchSnapshot {
                batches: self.batches.load(Ordering::Relaxed),
                rows: self.rows.load(Ordering::Relaxed),
                max_rows: self.max_rows.load(Ordering::Relaxed),
                size_buckets: std::array::from_fn(|index| {
                    self.size_buckets[index].load(Ordering::Relaxed)
                }),
            };
            if self.sequence.load(Ordering::Acquire) == before {
                return snapshot;
            }
        }
    }
}

struct InboundIndexBatchSnapshot {
    batches: u64,
    rows: u64,
    max_rows: u64,
    size_buckets: [u64; INBOUND_INDEX_BATCH_BUCKETS],
}

struct Observer {
    stages: [StageCounters; CoordinatorStage::ALL.len()],
    inbound_index_batches: InboundIndexBatchCounters,
    completed_tasks: AtomicU64,
    completed_total_ns: AtomicU64,
    completed_max_ns: AtomicU64,
    sequence: AtomicU64,
    snapshot_interval: u64,
}

impl Observer {
    fn new(snapshot_interval: u64) -> Self {
        Self {
            stages: std::array::from_fn(|_| StageCounters::new()),
            inbound_index_batches: InboundIndexBatchCounters::new(),
            completed_tasks: AtomicU64::new(0),
            completed_total_ns: AtomicU64::new(0),
            completed_max_ns: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
            snapshot_interval,
        }
    }

    fn from_environment() -> Option<Self> {
        (env::var(ENABLE_ENV).as_deref() == Ok("1")).then(|| Self::new(SNAPSHOT_INTERVAL))
    }

    fn record_stage(&self, stage: CoordinatorStage, elapsed: Duration) {
        self.stages[stage as usize].record(elapsed);
    }

    fn record_inbound_index_batch(&self, rows: usize) {
        self.inbound_index_batches.record(rows);
    }

    fn record_completed_task(&self, elapsed: Duration) {
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let completed = self.completed_tasks.fetch_add(1, Ordering::Relaxed) + 1;
        let _ =
            self.completed_total_ns
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                    Some(total.saturating_add(elapsed_ns))
                });
        self.completed_max_ns
            .fetch_max(elapsed_ns, Ordering::Relaxed);
        if completed.is_multiple_of(self.snapshot_interval) {
            eprintln!("LMYZMAIL_COORDINATOR_OBSERVER {}", self.snapshot());
        }
    }

    fn snapshot(&self) -> String {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let completed = self.completed_tasks.load(Ordering::Relaxed);
        let mut output = String::with_capacity(4_096);
        write!(
            output,
            concat!(
                "{{\"schema\":\"{}\",\"sequence\":{},\"pid\":{},",
                "\"completed_tasks\":{},\"completed_total_ns\":{},",
                "\"completed_max_ns\":{},\"stages\":{{"
            ),
            SCHEMA,
            sequence,
            std::process::id(),
            completed,
            self.completed_total_ns.load(Ordering::Relaxed),
            self.completed_max_ns.load(Ordering::Relaxed),
        )
        .expect("writing a bounded coordinator observation to String cannot fail");
        for (index, stage) in CoordinatorStage::ALL.into_iter().enumerate() {
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
            .expect("writing a bounded coordinator observation to String cannot fail");
        }
        let inbound_index_batches = self.inbound_index_batches.snapshot();
        output.push_str("},\"inbound_index_batches\":{");
        write!(
            output,
            concat!(
                "\"batches\":{},\"rows\":{},\"max_rows\":{},",
                "\"size_buckets\":{{"
            ),
            inbound_index_batches.batches,
            inbound_index_batches.rows,
            inbound_index_batches.max_rows,
        )
        .expect("writing bounded inbound index batch counters to String cannot fail");
        for (index, label) in ["1", "2_4", "5_8", "9_16", "17_32", "33_64"]
            .into_iter()
            .enumerate()
        {
            if index != 0 {
                output.push(',');
            }
            write!(
                output,
                "\"{label}\":{}",
                inbound_index_batches.size_buckets[index]
            )
            .expect("writing bounded inbound index batch buckets to String cannot fail");
        }
        output.push_str("}}}");
        output
    }
}

static OBSERVER: OnceLock<Option<Observer>> = OnceLock::new();

fn observer() -> Option<&'static Observer> {
    OBSERVER.get_or_init(Observer::from_environment).as_ref()
}

pub(crate) fn observation_instant() -> Option<Instant> {
    observer().map(|_| Instant::now())
}

pub(crate) fn record_stage_elapsed(stage: CoordinatorStage, elapsed: Duration) {
    if let Some(observer) = observer() {
        observer.record_stage(stage, elapsed);
    }
}

pub(crate) fn record_inbound_index_batch(rows: usize) {
    if let Some(observer) = observer() {
        observer.record_inbound_index_batch(rows);
    }
}

pub(crate) struct StageTimer {
    stage: CoordinatorStage,
    started: Option<Instant>,
}

impl StageTimer {
    pub(crate) fn start(stage: CoordinatorStage) -> Self {
        Self {
            stage,
            started: observer().map(|_| Instant::now()),
        }
    }
}

impl Drop for StageTimer {
    fn drop(&mut self) {
        if let (Some(observer), Some(started)) = (observer(), self.started) {
            observer.record_stage(self.stage, started.elapsed());
        }
    }
}

pub(crate) struct CompletedTaskTimer {
    started: Option<Instant>,
}

impl CompletedTaskTimer {
    pub(crate) fn start() -> Self {
        Self {
            started: observer().map(|_| Instant::now()),
        }
    }

    pub(crate) fn complete(mut self) {
        if let (Some(observer), Some(started)) = (observer(), self.started.take()) {
            observer.record_completed_task(started.elapsed());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, time::Duration};

    use super::{CoordinatorStage, Observer};

    #[test]
    fn stage_names_are_unique() {
        let names = CoordinatorStage::ALL
            .into_iter()
            .map(CoordinatorStage::name)
            .collect::<HashSet<_>>();
        assert_eq!(names.len(), CoordinatorStage::ALL.len());
    }

    #[test]
    fn result_checkpoint_stage_names_are_stable() {
        let names = [
            CoordinatorStage::ResultCheckpointPool,
            CoordinatorStage::ResultCheckpointBegin,
            CoordinatorStage::ResultCheckpointDeadline,
            CoordinatorStage::ResultCheckpointLegacyLock,
            CoordinatorStage::ResultCheckpointAttemptLock,
            CoordinatorStage::ResultCheckpointAttemptRowLock,
            CoordinatorStage::ResultCheckpointRosterVerify,
            CoordinatorStage::ResultCheckpointBarrierVerify,
            CoordinatorStage::ResultCheckpointRecipientUpdate,
            CoordinatorStage::ResultCheckpointAttemptUpdate,
            CoordinatorStage::ResultCheckpointCommit,
        ]
        .map(CoordinatorStage::name);
        assert_eq!(
            names,
            [
                "result_checkpoint_pool",
                "result_checkpoint_begin",
                "result_checkpoint_deadline",
                "result_checkpoint_legacy_lock",
                "result_checkpoint_attempt_lock",
                "result_checkpoint_attempt_row_lock",
                "result_checkpoint_roster_verify",
                "result_checkpoint_barrier_verify",
                "result_checkpoint_recipient_update",
                "result_checkpoint_attempt_update",
                "result_checkpoint_commit",
            ]
        );
    }

    #[test]
    fn inbound_index_batch_stage_names_are_stable() {
        let names = [
            CoordinatorStage::InboundIndexBatchAdmission,
            CoordinatorStage::InboundIndexBatchQueueWait,
            CoordinatorStage::InboundIndexBatchDispatchWait,
            CoordinatorStage::InboundIndexBatchCollect,
            CoordinatorStage::InboundIndexBatchWorker,
            CoordinatorStage::InboundIndexBatchResponseWait,
        ]
        .map(CoordinatorStage::name);
        assert_eq!(
            names,
            [
                "inbound_index_batch_admission",
                "inbound_index_batch_queue_wait",
                "inbound_index_batch_dispatch_wait",
                "inbound_index_batch_collect",
                "inbound_index_batch_worker",
                "inbound_index_batch_response_wait",
            ]
        );
    }

    #[test]
    fn inbound_completion_batch_stage_names_are_stable() {
        let names = [
            CoordinatorStage::InboundCompletionBatchAdmission,
            CoordinatorStage::InboundCompletionBatchQueueWait,
            CoordinatorStage::InboundCompletionBatchDispatchWait,
            CoordinatorStage::InboundCompletionBatchCollect,
            CoordinatorStage::InboundCompletionBatchWorker,
            CoordinatorStage::InboundCompletionBatchResponseWait,
        ]
        .map(CoordinatorStage::name);
        assert_eq!(
            names,
            [
                "inbound_completion_batch_admission",
                "inbound_completion_batch_queue_wait",
                "inbound_completion_batch_dispatch_wait",
                "inbound_completion_batch_collect",
                "inbound_completion_batch_worker",
                "inbound_completion_batch_response_wait",
            ]
        );
    }

    #[test]
    fn inbound_intent_completion_stage_names_are_stable() {
        let names = [
            CoordinatorStage::InboundIntentCompletePool,
            CoordinatorStage::InboundIntentCompleteBegin,
            CoordinatorStage::InboundIntentCompleteLock,
            CoordinatorStage::InboundIntentCompleteRead,
            CoordinatorStage::InboundIntentCompleteDelete,
            CoordinatorStage::InboundIntentCompleteTransactionCommit,
        ]
        .map(CoordinatorStage::name);
        assert_eq!(
            names,
            [
                "inbound_intent_complete_pool",
                "inbound_intent_complete_begin",
                "inbound_intent_complete_lock",
                "inbound_intent_complete_read",
                "inbound_intent_complete_delete",
                "inbound_intent_complete_transaction_commit",
            ]
        );
    }

    #[test]
    fn snapshot_reports_cumulative_stage_and_completion_totals() {
        let observer = Observer::new(2);
        observer.record_stage(CoordinatorStage::DatabaseClaim, Duration::from_nanos(11));
        observer.record_stage(CoordinatorStage::DatabaseClaim, Duration::from_nanos(13));
        for rows in [1, 2, 4, 5, 8, 9, 16, 17, 32, 33, 64] {
            observer.record_inbound_index_batch(rows);
        }
        observer.record_completed_task(Duration::from_nanos(101));

        let value: serde_json::Value = serde_json::from_str(&observer.snapshot()).unwrap();
        assert_eq!(value["schema"], "lmyzmail.coordinator-stage-observation.v1");
        assert_eq!(value["completed_tasks"], 1);
        assert_eq!(value["completed_total_ns"], 101);
        assert_eq!(value["completed_max_ns"], 101);
        assert_eq!(value["stages"]["database_claim"]["count"], 2);
        assert_eq!(value["stages"]["database_claim"]["total_ns"], 24);
        assert_eq!(value["stages"]["database_claim"]["max_ns"], 13);
        assert_eq!(value["inbound_index_batches"]["batches"], 11);
        assert_eq!(value["inbound_index_batches"]["rows"], 191);
        assert_eq!(value["inbound_index_batches"]["max_rows"], 64);
        assert_eq!(value["inbound_index_batches"]["size_buckets"]["1"], 1);
        for bucket in ["2_4", "5_8", "9_16", "17_32", "33_64"] {
            assert_eq!(value["inbound_index_batches"]["size_buckets"][bucket], 2);
        }
    }
}
