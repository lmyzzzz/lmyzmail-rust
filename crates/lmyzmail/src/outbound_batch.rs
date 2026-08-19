use std::{
    collections::BTreeSet,
    env,
    fmt::Write as _,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{outbound::OutboundError, outbound_queue::LegacyOutboundQueue};

const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const BATCH_CHANNEL_CAPACITY: usize = 256;
const MAX_BATCH_ROWS: usize = 64;
const BATCH_COLLECTION_WINDOW: Duration = Duration::from_millis(2);
const BATCH_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);
// Leave a bounded safety margin so concurrent admission cannot stampede the
// expensive exact Redis union while the queue is already effectively full.
pub(crate) const REDIS_CAPACITY_GUARD: usize = 128;
const QUEUE_LOCK_NAME: &str = "lmyzmail:outbound:queue";
const OBSERVER_ENV: &str = "LMYZMAIL_STRESS_ENQUEUE_OBSERVER";
const OBSERVER_SCHEMA: &str = "lmyzmail.outbound-batch-observation.v1";
const OBSERVER_SNAPSHOT_ROWS: u64 = 256;

#[derive(Debug)]
pub(crate) struct BatchRow {
    pub(crate) task_id: i64,
    pub(crate) sender: String,
    pub(crate) recipients_json: String,
    pub(crate) subject: String,
    pub(crate) body_text: Option<String>,
    pub(crate) body_html: Option<String>,
    pub(crate) attachments_json: String,
    pub(crate) message_id: String,
    pub(crate) sent_file_name: String,
    pub(crate) sent_subdirectory: i32,
    pub(crate) max_retries: i32,
    pub(crate) now: DateTime<Utc>,
    pub(crate) spool_path: String,
    pub(crate) cleanup_after_publish: bool,
    pub(crate) message_bytes: i64,
    pub(crate) content_sha256: Vec<u8>,
    pub(crate) to_addresses: String,
    pub(crate) has_attachments: bool,
}

#[derive(Debug)]
pub(crate) enum BatchOutcome {
    Committed,
    NotCommitted(OutboundError),
    CommitUncertain(OutboundError),
}

struct BatchRequest {
    row: BatchRow,
    cancellation: CancellationToken,
    response: oneshot::Sender<BatchOutcome>,
}

impl BatchRequest {
    fn respond(self, outcome: BatchOutcome) {
        let _ = self.response.send(outcome);
    }
}

pub(crate) struct BatchPersistence {
    sender: mpsc::Sender<BatchRequest>,
    shutdown: CancellationToken,
    worker: Mutex<Option<JoinHandle<()>>>,
}

pub(crate) fn postgres_queue_capacity_exhausted(
    postgres_active_rows: usize,
    max_pending_tasks: usize,
) -> bool {
    postgres_active_rows >= max_pending_tasks
}

pub(crate) fn redis_queue_capacity_guard_triggered(
    redis_active_references: usize,
    max_pending_tasks: usize,
) -> bool {
    if max_pending_tasks == 0 {
        return true;
    }
    let guard = REDIS_CAPACITY_GUARD.min(max_pending_tasks.saturating_sub(1));
    redis_active_references >= max_pending_tasks.saturating_sub(guard)
}

impl BatchPersistence {
    pub(crate) fn start(
        pool: Pool,
        queue: LegacyOutboundQueue,
        max_pending_tasks: usize,
    ) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(BATCH_CHANNEL_CAPACITY);
        let shutdown = CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let worker = tokio::spawn(run_worker(
            pool,
            queue,
            max_pending_tasks,
            receiver,
            worker_shutdown,
        ));
        Arc::new(Self {
            sender,
            shutdown,
            worker: Mutex::new(Some(worker)),
        })
    }

    pub(crate) async fn submit(
        &self,
        row: BatchRow,
        cancellation: &CancellationToken,
    ) -> BatchOutcome {
        let sender = self.sender.clone();
        let permit = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return BatchOutcome::NotCommitted(OutboundError::Unavailable);
            }
            result = timeout(DATABASE_TIMEOUT, sender.reserve_owned()) => match result {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) | Err(_) => {
                    return BatchOutcome::NotCommitted(OutboundError::Unavailable);
                }
            },
        };
        let (response, receiver) = oneshot::channel();
        permit.send(BatchRequest {
            row,
            cancellation: cancellation.clone(),
            response,
        });
        match timeout(BATCH_RESPONSE_TIMEOUT, receiver).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) | Err(_) => BatchOutcome::CommitUncertain(OutboundError::Unavailable),
        }
    }

    pub(crate) async fn shutdown(&self, deadline: Instant) -> bool {
        self.shutdown.cancel();
        let Some(mut worker) = self.worker.lock().await.take() else {
            return true;
        };
        if timeout_at(deadline, &mut worker).await.is_ok() {
            return true;
        }
        worker.abort();
        let _ = worker.await;
        false
    }
}

async fn run_worker(
    pool: Pool,
    queue: LegacyOutboundQueue,
    max_pending_tasks: usize,
    mut receiver: mpsc::Receiver<BatchRequest>,
    shutdown: CancellationToken,
) {
    loop {
        let first = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                receiver.close();
                receiver.recv().await
            }
            request = receiver.recv() => request,
        };
        let Some(first) = first else {
            break;
        };
        let mut batch = Vec::with_capacity(MAX_BATCH_ROWS);
        batch.push(first);
        let collection_deadline = Instant::now() + BATCH_COLLECTION_WINDOW;
        while batch.len() < MAX_BATCH_ROWS {
            let request = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    receiver.close();
                    receiver.try_recv().ok()
                }
                result = timeout_at(collection_deadline, receiver.recv()) => {
                    result.ok().flatten()
                }
            };
            let Some(request) = request else {
                break;
            };
            batch.push(request);
        }
        persist_batch(&pool, &queue, max_pending_tasks, batch).await;
    }
}

async fn persist_batch(
    pool: &Pool,
    queue: &LegacyOutboundQueue,
    max_pending_tasks: usize,
    mut batch: Vec<BatchRequest>,
) {
    let started = Instant::now();
    batch = retain_live_requests(batch);
    if batch.is_empty() {
        return;
    }

    let mut client = match timeout(DATABASE_TIMEOUT, pool.get()).await {
        Ok(Ok(client)) => client,
        Ok(Err(error)) => {
            fail_not_committed(batch, Failure::Database(error.to_string()));
            return;
        }
        Err(_) => {
            fail_not_committed(batch, Failure::Unavailable);
            return;
        }
    };
    let transaction = match timeout(DATABASE_TIMEOUT, client.transaction()).await {
        Ok(Ok(transaction)) => transaction,
        Ok(Err(error)) => {
            fail_not_committed(batch, Failure::Database(error.to_string()));
            return;
        }
        Err(_) => {
            fail_not_committed(batch, Failure::Unavailable);
            return;
        }
    };
    match timeout(
        DATABASE_TIMEOUT,
        transaction.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
            &[&QUEUE_LOCK_NAME],
        ),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            fail_not_committed(batch, Failure::Database(error.to_string()));
            return;
        }
        Err(_) => {
            fail_not_committed(batch, Failure::Unavailable);
            return;
        }
    }

    batch = retain_live_requests(batch);
    if batch.is_empty() {
        commit_read_only(transaction).await;
        return;
    }

    let redis_references = match timeout(
        DATABASE_TIMEOUT,
        queue.active_reference_upper_bound(max_pending_tasks),
    )
    .await
    {
        Ok(Ok(references)) => references,
        Ok(Err(_)) | Err(_) => {
            commit_read_only(transaction).await;
            fail_not_committed(batch, Failure::Unavailable);
            return;
        }
    };
    if redis_references >= max_pending_tasks {
        commit_read_only(transaction).await;
        for request in batch {
            request.respond(BatchOutcome::NotCommitted(OutboundError::QueueFull));
        }
        return;
    }
    if redis_queue_capacity_guard_triggered(redis_references, max_pending_tasks) {
        commit_read_only(transaction).await;
        for request in batch {
            request.respond(BatchOutcome::NotCommitted(OutboundError::QueueFull));
        }
        return;
    }

    let pending_rows = match timeout(
        DATABASE_TIMEOUT,
        transaction.query(
            "SELECT id FROM outbound_mail_queue
             WHERE status IN ('PENDING','PROCESSING') ORDER BY id LIMIT $1",
            &[&i64::try_from(max_pending_tasks).unwrap_or(i64::MAX)],
        ),
    )
    .await
    {
        Ok(Ok(rows)) => rows,
        Ok(Err(error)) => {
            fail_not_committed(batch, Failure::Database(error.to_string()));
            return;
        }
        Err(_) => {
            fail_not_committed(batch, Failure::Unavailable);
            return;
        }
    };
    if postgres_queue_capacity_exhausted(pending_rows.len(), max_pending_tasks) {
        commit_read_only(transaction).await;
        for request in batch {
            request.respond(BatchOutcome::NotCommitted(OutboundError::QueueFull));
        }
        return;
    }
    let mut active_ids = pending_rows
        .into_iter()
        .map(|row| row.get::<_, i64>(0).to_string())
        .collect::<BTreeSet<_>>();
    let redis_active_ids =
        match timeout(DATABASE_TIMEOUT, queue.active_task_ids(max_pending_tasks)).await {
            Ok(Ok(ids)) => ids,
            Ok(Err(_)) | Err(_) => {
                commit_read_only(transaction).await;
                fail_not_committed(batch, Failure::Unavailable);
                return;
            }
        };
    active_ids.extend(redis_active_ids);
    batch = retain_live_requests(batch);
    if batch.is_empty() {
        commit_read_only(transaction).await;
        return;
    }
    let available = max_pending_tasks.saturating_sub(active_ids.len());
    if available < batch.len() {
        let rejected = batch.split_off(available);
        for request in rejected {
            request.respond(BatchOutcome::NotCommitted(OutboundError::QueueFull));
        }
    }
    if batch.is_empty() {
        commit_read_only(transaction).await;
        return;
    }

    if let Err(failure) = insert_batch(&transaction, &batch).await {
        fail_not_committed(batch, failure);
        return;
    }
    let commit = timeout(DATABASE_TIMEOUT, transaction.commit()).await;
    match commit {
        Ok(Ok(())) => {
            observe_batch(batch.len(), started.elapsed(), BatchDisposition::Committed);
            for request in batch {
                request.respond(BatchOutcome::Committed);
            }
        }
        Ok(Err(error)) => {
            observe_batch(
                batch.len(),
                started.elapsed(),
                BatchDisposition::CommitUncertain,
            );
            fail_commit_uncertain(batch, Failure::Database(error.to_string()));
        }
        Err(_) => {
            observe_batch(
                batch.len(),
                started.elapsed(),
                BatchDisposition::CommitUncertain,
            );
            fail_commit_uncertain(batch, Failure::Unavailable);
        }
    }
}

pub(crate) async fn commit_read_only(transaction: deadpool_postgres::Transaction<'_>) {
    // Capacity and cancellation outcomes are expected control flow. End the
    // read-only transaction explicitly so PostgreSQL rollback telemetry remains
    // reserved for real database failures and deadline expiry.
    let _ = timeout(DATABASE_TIMEOUT, transaction.commit()).await;
}

async fn insert_batch(
    transaction: &tokio_postgres::Transaction<'_>,
    batch: &[BatchRequest],
) -> Result<(), Failure> {
    let ids = batch
        .iter()
        .map(|item| item.row.task_id)
        .collect::<Vec<_>>();
    let senders = batch
        .iter()
        .map(|item| item.row.sender.as_str())
        .collect::<Vec<_>>();
    let recipients = batch
        .iter()
        .map(|item| item.row.recipients_json.as_str())
        .collect::<Vec<_>>();
    let subjects = batch
        .iter()
        .map(|item| item.row.subject.as_str())
        .collect::<Vec<_>>();
    let body_text = batch
        .iter()
        .map(|item| item.row.body_text.as_deref())
        .collect::<Vec<_>>();
    let body_html = batch
        .iter()
        .map(|item| item.row.body_html.as_deref())
        .collect::<Vec<_>>();
    let attachments = batch
        .iter()
        .map(|item| item.row.attachments_json.as_str())
        .collect::<Vec<_>>();
    let message_ids = batch
        .iter()
        .map(|item| item.row.message_id.as_str())
        .collect::<Vec<_>>();
    let sent_names = batch
        .iter()
        .map(|item| item.row.sent_file_name.as_str())
        .collect::<Vec<_>>();
    let sent_subdirectories = batch
        .iter()
        .map(|item| item.row.sent_subdirectory)
        .collect::<Vec<_>>();
    let retries = batch
        .iter()
        .map(|item| item.row.max_retries)
        .collect::<Vec<_>>();
    let timestamps = batch.iter().map(|item| item.row.now).collect::<Vec<_>>();
    let spool_paths = batch
        .iter()
        .map(|item| item.row.spool_path.as_str())
        .collect::<Vec<_>>();
    let cleanup = batch
        .iter()
        .map(|item| item.row.cleanup_after_publish)
        .collect::<Vec<_>>();
    let message_bytes = batch
        .iter()
        .map(|item| item.row.message_bytes)
        .collect::<Vec<_>>();
    let content_hashes = batch
        .iter()
        .map(|item| item.row.content_sha256.as_slice())
        .collect::<Vec<_>>();
    let to_addresses = batch
        .iter()
        .map(|item| item.row.to_addresses.as_str())
        .collect::<Vec<_>>();
    let has_attachments = batch
        .iter()
        .map(|item| item.row.has_attachments)
        .collect::<Vec<_>>();

    let row = timeout(
        DATABASE_TIMEOUT,
        transaction.query_one(
            "WITH input AS (
               SELECT id,sender,recipients,subject,body_text,body_html,attachments,
                      message_id,sent_name,sent_subdirectory,max_retries,created_at,
                      spool_path,cleanup_after_publish,message_bytes,content_sha256,
                      to_addresses,has_attachments
               FROM unnest(
                 $1::bigint[],$2::text[],$3::text[],$4::text[],$5::text[],$6::text[],
                 $7::text[],$8::text[],$9::text[],$10::int4[],$11::int4[],
                 $12::timestamptz[],$13::text[],$14::bool[],$15::bigint[],
                 $16::bytea[],$17::text[],$18::bool[]
               ) AS value(
                 id,sender,recipients,subject,body_text,body_html,attachments,
                 message_id,sent_name,sent_subdirectory,max_retries,created_at,
                 spool_path,cleanup_after_publish,message_bytes,content_sha256,
                 to_addresses,has_attachments
               )
             ), queue_rows AS (
               INSERT INTO outbound_mail_queue
                 (id,sender_address,recipients_json,subject,body_text,body_html,
                  attachments_json,message_id,sent_file_name,sent_subdirectory,status,
                  retry_count,max_retries,next_retry_at,last_error,sent_domains_json,
                  failed_domains_json,created_at,updated_at,sent_at,processing_started_at,
                  processor_id)
               SELECT id,sender,recipients,subject,body_text,body_html,attachments,
                      message_id,sent_name,sent_subdirectory,'PENDING',0,max_retries,
                      created_at,NULL,'[]','{}',created_at,created_at,NULL,NULL,NULL
               FROM input
               RETURNING id
             ), spool_rows AS (
               INSERT INTO lmyzmail_outbound_spool
                 (task_id,spool_path,spool_kind,cleanup_state,cleanup_after_publish,
                  created_at,updated_at)
               SELECT input.id,input.spool_path,'RUST','OWNED',
                      input.cleanup_after_publish,input.created_at,input.created_at
               FROM input JOIN queue_rows USING (id)
               RETURNING task_id
             ), content_rows AS (
               INSERT INTO lmyzmail_outbound_content
                 (task_id,source_root,relative_path,content_size,content_sha256,
                  created_at,updated_at)
               SELECT input.id,'SPOOL','message-' || input.id || '.eml',
                      input.message_bytes,input.content_sha256,input.created_at,
                      input.created_at
               FROM input JOIN queue_rows USING (id)
               RETURNING task_id
             ), index_rows AS (
               INSERT INTO email_index
                 (has_attachments,subdirectory,indexed_at,received_at,size_bytes,folder,
                  from_address,message_id,subject,to_addresses,file_name,mailbox_address)
               SELECT input.has_attachments,input.sent_subdirectory,input.created_at,
                      input.created_at,input.message_bytes,'sent',input.sender,
                      input.message_id,input.subject,input.to_addresses,input.sent_name,
                      input.sender
               FROM input JOIN queue_rows USING (id)
               RETURNING file_name
             )
             SELECT (SELECT count(*) FROM queue_rows),
                    (SELECT count(*) FROM spool_rows),
                    (SELECT count(*) FROM content_rows),
                    (SELECT count(*) FROM index_rows)",
            &[
                &ids,
                &senders,
                &recipients,
                &subjects,
                &body_text,
                &body_html,
                &attachments,
                &message_ids,
                &sent_names,
                &sent_subdirectories,
                &retries,
                &timestamps,
                &spool_paths,
                &cleanup,
                &message_bytes,
                &content_hashes,
                &to_addresses,
                &has_attachments,
            ],
        ),
    )
    .await
    .map_err(|_| Failure::Unavailable)?
    .map_err(|error| Failure::Database(error.to_string()))?;
    let expected = i64::try_from(batch.len()).map_err(|_| Failure::Unavailable)?;
    if (0..4).any(|index| row.get::<_, i64>(index) != expected) {
        return Err(Failure::Unavailable);
    }
    Ok(())
}

#[derive(Clone)]
enum Failure {
    Database(String),
    Unavailable,
}

impl Failure {
    fn into_error(self) -> OutboundError {
        match self {
            Self::Database(error) => OutboundError::Database(error),
            Self::Unavailable => OutboundError::Unavailable,
        }
    }
}

fn fail_not_committed(batch: Vec<BatchRequest>, failure: Failure) {
    for request in batch {
        request.respond(BatchOutcome::NotCommitted(failure.clone().into_error()));
    }
}

fn fail_commit_uncertain(batch: Vec<BatchRequest>, failure: Failure) {
    for request in batch {
        request.respond(BatchOutcome::CommitUncertain(failure.clone().into_error()));
    }
}

fn retain_live_requests(batch: Vec<BatchRequest>) -> Vec<BatchRequest> {
    let mut live = Vec::with_capacity(batch.len());
    for request in batch {
        if request.response.is_closed() {
            continue;
        }
        if request.cancellation.is_cancelled() {
            request.respond(BatchOutcome::NotCommitted(OutboundError::Unavailable));
        } else {
            live.push(request);
        }
    }
    live
}

#[derive(Clone, Copy)]
enum BatchDisposition {
    Committed,
    CommitUncertain,
}

struct BatchObserver {
    batches: AtomicU64,
    rows: AtomicU64,
    max_rows: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
    uncertain_batches: AtomicU64,
    sequence: AtomicU64,
}

impl BatchObserver {
    const fn new() -> Self {
        Self {
            batches: AtomicU64::new(0),
            rows: AtomicU64::new(0),
            max_rows: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
            uncertain_batches: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
        }
    }

    fn record(&self, rows: usize, elapsed: Duration, disposition: BatchDisposition) {
        let rows = u64::try_from(rows).unwrap_or(u64::MAX);
        let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        self.batches.fetch_add(1, Ordering::Relaxed);
        let previous_rows = self.rows.fetch_add(rows, Ordering::Relaxed);
        self.max_rows.fetch_max(rows, Ordering::Relaxed);
        let _ = self
            .total_ns
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                Some(total.saturating_add(elapsed_ns))
            });
        self.max_ns.fetch_max(elapsed_ns, Ordering::Relaxed);
        if matches!(disposition, BatchDisposition::CommitUncertain) {
            self.uncertain_batches.fetch_add(1, Ordering::Relaxed);
        }
        let current_rows = previous_rows.saturating_add(rows);
        if previous_rows / OBSERVER_SNAPSHOT_ROWS != current_rows / OBSERVER_SNAPSHOT_ROWS {
            eprintln!("LMYZMAIL_OUTBOUND_BATCH_OBSERVER {}", self.snapshot());
        }
    }

    fn snapshot(&self) -> String {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let mut output = String::with_capacity(320);
        write!(
            output,
            "{{\"schema\":\"{OBSERVER_SCHEMA}\",\"sequence\":{sequence},\"pid\":{},\"batches\":{},\"rows\":{},\"max_rows\":{},\"total_ns\":{},\"max_ns\":{},\"uncertain_batches\":{}}}",
            std::process::id(),
            self.batches.load(Ordering::Relaxed),
            self.rows.load(Ordering::Relaxed),
            self.max_rows.load(Ordering::Relaxed),
            self.total_ns.load(Ordering::Relaxed),
            self.max_ns.load(Ordering::Relaxed),
            self.uncertain_batches.load(Ordering::Relaxed),
        )
        .expect("writing a bounded batch observation to String cannot fail");
        output
    }
}

static BATCH_OBSERVER: OnceLock<Option<BatchObserver>> = OnceLock::new();

fn observe_batch(rows: usize, elapsed: Duration, disposition: BatchDisposition) {
    if let Some(observer) = BATCH_OBSERVER
        .get_or_init(|| (env::var(OBSERVER_ENV).as_deref() == Ok("1")).then(BatchObserver::new))
        .as_ref()
    {
        observer.record(rows, elapsed, disposition);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_bounds_are_fixed_and_nonzero() {
        assert_eq!(MAX_BATCH_ROWS, 64);
        assert_eq!(BATCH_CHANNEL_CAPACITY, 256);
        assert!(BATCH_COLLECTION_WINDOW > Duration::ZERO);
    }

    #[test]
    fn postgres_capacity_short_circuits_at_the_configured_bound() {
        assert!(!postgres_queue_capacity_exhausted(9_999, 10_000));
        assert!(postgres_queue_capacity_exhausted(10_000, 10_000));
        assert!(postgres_queue_capacity_exhausted(10_001, 10_000));
    }

    #[test]
    fn redis_capacity_guard_is_bounded_and_fail_closed() {
        assert!(!redis_queue_capacity_guard_triggered(9_871, 10_000));
        assert!(redis_queue_capacity_guard_triggered(9_872, 10_000));
        assert!(redis_queue_capacity_guard_triggered(9_999, 10_000));
        assert!(!redis_queue_capacity_guard_triggered(0, 1));
        assert!(redis_queue_capacity_guard_triggered(1, 1));
        assert!(redis_queue_capacity_guard_triggered(0, 0));
    }

    #[test]
    fn observer_snapshot_contains_bounded_batch_totals() {
        let observer = BatchObserver::new();
        observer.record(8, Duration::from_nanos(17), BatchDisposition::Committed);
        observer.record(
            3,
            Duration::from_nanos(29),
            BatchDisposition::CommitUncertain,
        );
        let value: serde_json::Value = serde_json::from_str(&observer.snapshot()).unwrap();
        assert_eq!(value["schema"], OBSERVER_SCHEMA);
        assert_eq!(value["batches"], 2);
        assert_eq!(value["rows"], 11);
        assert_eq!(value["max_rows"], 8);
        assert_eq!(value["total_ns"], 46);
        assert_eq!(value["max_ns"], 29);
        assert_eq!(value["uncertain_batches"], 1);
    }
}
