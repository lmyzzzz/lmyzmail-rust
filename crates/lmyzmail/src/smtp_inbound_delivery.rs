use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ffi::{OsStr, OsString},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use deadpool_postgres::{Object, Pool};
use deadpool_redis::Pool as RedisPool;
use sha2::{Digest as _, Sha256};
use tokio::{
    sync::{Mutex as AsyncMutex, Semaphore, mpsc, oneshot},
    task::{JoinHandle, spawn_blocking},
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    coordinator_observer::{CoordinatorStage, StageTimer},
    durability::{fsync, sync_all},
    mailbox::{
        normalize_mailbox, secure_directory_child, secure_directory_root, secure_mailbox_folder,
    },
};

const INBOUND_SCHEMA: &str = include_str!("../migrations/006_inbound_delivery_intent.sql");
const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const REDIS_TIMEOUT: Duration = Duration::from_secs(5);
const SCHEMA_LOCK_ID: i64 = 0x4c4d_595a_494e_4244;
const STAGING_DIRECTORY: &str = ".lmyzmail-inbound";
const STAGING_PREFIX: &str = ".lmyzmail-inbound-";
const STAGING_SUFFIX: &str = ".tmp";
pub(crate) const RECOVERY_BATCH_SIZE: i64 = 64;
pub(crate) const MAX_STARTUP_RECOVERY_INTENTS: usize = 4_096;
pub(crate) const PROJECTION_BATCH_SIZE: i64 = 64;
pub(crate) const AUDIT_BATCH_SIZE: i64 = 16;
pub(crate) const STAGING_ENTRY_LIMIT: usize = 65_536;
pub(crate) const STAGING_CLEANUP_BATCH_SIZE: usize = 64;
pub(crate) const STAGING_ORPHAN_MIN_AGE: Duration = Duration::from_secs(300);
pub(crate) const MAX_ACTIVE_INBOUND_INTENTS: usize = 256;
const INDEX_BATCH_CHANNEL_CAPACITY: usize = MAX_ACTIVE_INBOUND_INTENTS;
const MAX_INDEX_BATCH_ROWS: usize = 64;
const INDEX_BATCH_COLLECTION_WINDOW: Duration = Duration::from_millis(2);
const INDEX_BATCH_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct ActiveInboundIntent {
    mailbox: String,
    durable: bool,
}

#[derive(Debug, Default)]
struct ActiveInboundState {
    intents: HashMap<String, ActiveInboundIntent>,
    blocked_mailboxes: HashSet<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ActiveInboundIntents {
    state: Mutex<ActiveInboundState>,
}

#[derive(Debug)]
pub(crate) struct ActiveInboundIntentGuard {
    registry: Arc<ActiveInboundIntents>,
    intent_id: String,
    completed: bool,
}

impl ActiveInboundIntents {
    pub(crate) fn reserve(
        self: &Arc<Self>,
        intent_id: String,
        mailbox: String,
    ) -> io::Result<ActiveInboundIntentGuard> {
        validate_intent_id(&intent_id)?;
        let mut state = self.lock()?;
        if state.blocked_mailboxes.contains(&mailbox) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "recipient has an inbound delivery awaiting recovery",
            ));
        }
        if state.intents.len() >= MAX_ACTIVE_INBOUND_INTENTS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "SMTP active inbound intent limit reached",
            ));
        }
        if state.intents.contains_key(&intent_id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "SMTP inbound intent id collision",
            ));
        }
        state.intents.insert(
            intent_id.clone(),
            ActiveInboundIntent {
                mailbox,
                durable: false,
            },
        );
        Ok(ActiveInboundIntentGuard {
            registry: Arc::clone(self),
            intent_id,
            completed: false,
        })
    }

    pub(crate) fn active_ids(&self) -> io::Result<HashSet<String>> {
        Ok(self.lock()?.intents.keys().cloned().collect())
    }

    pub(crate) fn is_active(&self, intent_id: &str) -> io::Result<bool> {
        Ok(self.lock()?.intents.contains_key(intent_id))
    }

    pub(crate) fn blocked_mailboxes(&self) -> io::Result<Vec<String>> {
        Ok(self.lock()?.blocked_mailboxes.iter().cloned().collect())
    }

    pub(crate) fn clear_blocked_mailbox(&self, mailbox: &str) -> io::Result<()> {
        self.lock()?.blocked_mailboxes.remove(mailbox);
        Ok(())
    }

    fn mark_durable(&self, intent_id: &str) -> io::Result<()> {
        let mut state = self.lock()?;
        let intent = state.intents.get_mut(intent_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "SMTP active inbound intent disappeared",
            )
        })?;
        intent.durable = true;
        Ok(())
    }

    fn complete(&self, intent_id: &str) -> io::Result<()> {
        let removed = self.lock()?.intents.remove(intent_id);
        if removed.is_some() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "SMTP active inbound intent disappeared before completion",
            ))
        }
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, ActiveInboundState>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("SMTP active inbound intent registry is poisoned"))
    }
}

impl ActiveInboundIntentGuard {
    pub(crate) fn mark_durable(&self) -> io::Result<()> {
        self.registry.mark_durable(&self.intent_id)
    }

    pub(crate) fn complete(mut self) -> io::Result<()> {
        self.registry.complete(&self.intent_id)?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for ActiveInboundIntentGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let Ok(mut state) = self.registry.state.lock() else {
            return;
        };
        if let Some(intent) = state.intents.remove(&self.intent_id)
            && intent.durable
        {
            state.blocked_mailboxes.insert(intent.mailbox);
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct InboundIndexMetadata {
    pub mailbox: String,
    pub folder: String,
    pub subdirectory: Option<i32>,
    pub file_name: String,
    pub has_attachments: bool,
    pub received_at: DateTime<Utc>,
    pub size_bytes: i64,
    pub from_address: Option<String>,
    pub message_id: String,
    pub subject: Option<String>,
    pub to_addresses: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedInbound {
    pub intent_id: String,
    pub temporary_name: OsString,
    pub staging_parent: PathBuf,
    pub final_parent: PathBuf,
    pub identity: FileIdentity,
    pub index: InboundIndexMetadata,
    state: IntentState,
}

struct IndexCommitRequest {
    prepared: PreparedInbound,
    response: oneshot::Sender<io::Result<()>>,
}

impl IndexCommitRequest {
    fn respond(self, result: io::Result<()>) {
        let _ = self.response.send(result);
    }
}

#[derive(Clone)]
struct IndexCommitFailure {
    kind: io::ErrorKind,
    message: Arc<str>,
}

impl IndexCommitFailure {
    fn from_error(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: Arc::from(error.to_string()),
        }
    }

    fn to_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.to_string())
    }

    fn is_request_specific(&self) -> bool {
        matches!(
            self.kind,
            io::ErrorKind::InvalidData
                | io::ErrorKind::InvalidInput
                | io::ErrorKind::NotFound
                | io::ErrorKind::AlreadyExists
        )
    }
}

pub(crate) struct IndexCommitter {
    sender: mpsc::Sender<IndexCommitRequest>,
    shutdown: CancellationToken,
    worker: AsyncMutex<Option<JoinHandle<()>>>,
}

impl IndexCommitter {
    pub(crate) fn start(pool: Pool) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(INDEX_BATCH_CHANNEL_CAPACITY);
        let shutdown = CancellationToken::new();
        let worker = tokio::spawn(run_index_commit_worker(pool, receiver, shutdown.clone()));
        Arc::new(Self {
            sender,
            shutdown,
            worker: AsyncMutex::new(Some(worker)),
        })
    }

    pub(crate) async fn submit(&self, prepared: &PreparedInbound) -> io::Result<()> {
        let sender = self.sender.clone();
        let permit = timeout(DATABASE_TIMEOUT, sender.reserve_owned())
            .await
            .map_err(|_| timed_out("inbound index batch admission"))?
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "inbound index worker closed")
            })?;
        let (response, receiver) = oneshot::channel();
        permit.send(IndexCommitRequest {
            prepared: prepared.clone(),
            response,
        });
        timeout(INDEX_BATCH_RESPONSE_TIMEOUT, receiver)
            .await
            .map_err(|_| timed_out("inbound index batch response"))?
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "inbound index worker dropped its response",
                )
            })?
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

impl Drop for IndexCommitter {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

async fn run_index_commit_worker(
    pool: Pool,
    mut receiver: mpsc::Receiver<IndexCommitRequest>,
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
        let mut batch = Vec::with_capacity(MAX_INDEX_BATCH_ROWS);
        batch.push(first);
        let collection_deadline = Instant::now() + INDEX_BATCH_COLLECTION_WINDOW;
        while batch.len() < MAX_INDEX_BATCH_ROWS {
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
        persist_index_batch(&pool, batch).await;
    }
}

async fn persist_index_batch(pool: &Pool, batch: Vec<IndexCommitRequest>) {
    let mut live = Vec::with_capacity(batch.len());
    for request in batch {
        if !request.response.is_closed() {
            live.push(request);
        }
    }
    if live.is_empty() {
        return;
    }
    let prepared = live
        .iter()
        .map(|request| &request.prepared)
        .collect::<Vec<_>>();
    match commit_index_batch(pool, &prepared).await {
        Ok(()) => {
            for request in live {
                request.respond(Ok(()));
            }
        }
        Err(error) => {
            let failure = IndexCommitFailure::from_error(error);
            if live.len() > 1 && failure.is_request_specific() {
                for request in live {
                    let result = commit_index_and_compact(pool, &request.prepared).await;
                    request.respond(result);
                }
            } else {
                for request in live {
                    request.respond(Err(failure.to_error()));
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntentState {
    Prepared,
    Indexed,
}

#[derive(Debug)]
struct StagingCandidate {
    name: OsString,
    intent_id: String,
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

pub(crate) async fn initialize_schema(pool: &Pool) -> io::Result<()> {
    let mut client = database_client(pool).await?;
    let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
        .await
        .map_err(|_| timed_out("inbound schema transaction"))?
        .map_err(database_error)?;
    timeout(
        DATABASE_TIMEOUT,
        transaction.query_one("SELECT pg_advisory_xact_lock($1)", &[&SCHEMA_LOCK_ID]),
    )
    .await
    .map_err(|_| timed_out("inbound schema lock"))?
    .map_err(database_error)?;
    timeout(DATABASE_TIMEOUT, transaction.batch_execute(INBOUND_SCHEMA))
        .await
        .map_err(|_| timed_out("inbound schema migration"))?
        .map_err(database_error)?;
    timeout(DATABASE_TIMEOUT, transaction.commit())
        .await
        .map_err(|_| timed_out("inbound schema commit"))?
        .map_err(database_error)
}

pub(crate) fn initialize_staging(maildir: &Path) -> io::Result<()> {
    use rustix::fs::fstat;

    let maildir = secure_directory_root(maildir)?;
    let staging = secure_directory_child(&maildir, STAGING_DIRECTORY)?;
    let maildir_fd = super::open_maildir_directory(&maildir)?;
    let staging_fd = super::open_maildir_directory(&staging)?;
    let maildir_stat = fstat(&maildir_fd).map_err(io::Error::from)?;
    let staging_stat = fstat(&staging_fd).map_err(io::Error::from)?;
    if maildir_stat.st_dev == staging_stat.st_dev {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::CrossesDevices,
            "SMTP staging directory must share the Maildir filesystem",
        ))
    }
}

pub(crate) fn prepare_file(
    maildir: &Path,
    final_parent: PathBuf,
    intent_id: String,
    data: &[u8],
    index: InboundIndexMetadata,
) -> io::Result<PreparedInbound> {
    use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, openat2, unlinkat};

    validate_intent_id(&intent_id)?;
    validate_file_name(&index.file_name)?;
    if index.size_bytes != i64::try_from(data.len()).unwrap_or(i64::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inbound index size does not match accepted message",
        ));
    }
    let staging_parent = secure_directory_child(maildir, STAGING_DIRECTORY)?;
    let temporary_name = OsString::from(format!("{STAGING_PREFIX}{intent_id}{STAGING_SUFFIX}"));
    let staging = super::open_maildir_directory(&staging_parent)?;
    let maildir_directory = super::open_maildir_directory(maildir)?;
    let final_directory = super::open_maildir_directory(&final_parent)?;
    let maildir_stat = fstat(&maildir_directory).map_err(io::Error::from)?;
    let staging_stat = fstat(&staging).map_err(io::Error::from)?;
    let final_stat = fstat(&final_directory).map_err(io::Error::from)?;
    if staging_stat.st_dev != maildir_stat.st_dev || final_stat.st_dev != maildir_stat.st_dev {
        return Err(io::Error::new(
            io::ErrorKind::CrossesDevices,
            "SMTP staging and final Maildir must share one filesystem",
        ));
    }
    let descriptor = openat2(
        &staging,
        &temporary_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let mut file = std::fs::File::from(descriptor);
    let prepared = (|| {
        use std::io::{Read as _, Seek as _, Write as _};

        file.write_all(data)?;
        file.flush()?;
        sync_all(&file)?;
        let stat = fstat(&file).map_err(io::Error::from)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_nlink != 1
            || stat.st_size < 0
            || stat.st_size as usize != data.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMTP staged file identity is invalid",
            ));
        }
        file.rewind()?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 32 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        let sha256: [u8; 32] = digest.finalize().into();
        let expected_sha256: [u8; 32] = Sha256::digest(data).into();
        if sha256 != expected_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMTP staged file digest does not match the accepted message",
            ));
        }
        fsync(&staging).map_err(io::Error::from)?;
        Ok(FileIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size as u64,
            sha256,
        })
    })();
    let identity = match prepared {
        Ok(identity) => identity,
        Err(error) => {
            let _ = unlinkat(&staging, &temporary_name, rustix::fs::AtFlags::empty());
            let _ = fsync(&staging);
            return Err(error);
        }
    };
    Ok(PreparedInbound {
        intent_id,
        temporary_name,
        staging_parent,
        final_parent,
        identity,
        index,
        state: IntentState::Prepared,
    })
}

pub(crate) async fn insert_intent(pool: &Pool, prepared: &PreparedInbound) -> io::Result<()> {
    let mut client = database_client(pool).await?;
    let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
        .await
        .map_err(|_| timed_out("inbound intent transaction"))?
        .map_err(database_error)?;
    let lock_id = intent_lock_id(&prepared.intent_id);
    timeout(
        DATABASE_TIMEOUT,
        transaction.query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_id]),
    )
    .await
    .map_err(|_| timed_out("inbound intent lock"))?
    .map_err(database_error)?;
    let device = prepared.identity.device.to_be_bytes().to_vec();
    let inode = prepared.identity.inode.to_be_bytes().to_vec();
    let sha256 = prepared.identity.sha256.to_vec();
    let temporary_name = prepared
        .temporary_name
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 staging name"))?;
    let insert = timeout(
        DATABASE_TIMEOUT,
        transaction.execute(
            "INSERT INTO lmyzmail_inbound_delivery_intent
             (intent_id,mailbox_address,folder,subdirectory,temporary_file_name,file_name,
              device,inode,size_bytes,sha256,has_attachments,received_at,from_address,
              message_id,subject,to_addresses,state,updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'PREPARED',CURRENT_TIMESTAMP)",
            &[
                &prepared.intent_id,
                &prepared.index.mailbox,
                &prepared.index.folder,
                &prepared.index.subdirectory,
                &temporary_name,
                &prepared.index.file_name,
                &device,
                &inode,
                &prepared.index.size_bytes,
                &sha256,
                &prepared.index.has_attachments,
                &prepared.index.received_at,
                &prepared.index.from_address,
                &prepared.index.message_id,
                &prepared.index.subject,
                &prepared.index.to_addresses,
            ],
        ),
    )
    .await;
    let inserted = match insert {
        Ok(Ok(1)) => true,
        Ok(Ok(_)) => false,
        Ok(Err(error)) => {
            drop(transaction);
            return reconcile_intent_insert(pool, prepared, database_error(error)).await;
        }
        Err(_) => {
            drop(transaction);
            return reconcile_intent_insert(pool, prepared, timed_out("inbound intent insert"))
                .await;
        }
    };
    if !inserted {
        return Err(io::Error::other("inbound intent insert affected no row"));
    }
    match timeout(DATABASE_TIMEOUT, transaction.commit()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => reconcile_intent_insert(pool, prepared, database_error(error)).await,
        Err(_) => {
            reconcile_intent_insert(pool, prepared, timed_out("inbound intent insert commit")).await
        }
    }
}

async fn reconcile_intent_insert(
    pool: &Pool,
    prepared: &PreparedInbound,
    original: io::Error,
) -> io::Result<()> {
    match load_intent(pool, &prepared.intent_id).await? {
        Some(record) if record.matches(prepared) => Ok(()),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound intent identity collision",
        )),
        None => Err(original),
    }
}

pub(crate) async fn has_unowned_pending_for(
    pool: &Pool,
    mailbox: &str,
    active_ids: &HashSet<String>,
) -> io::Result<bool> {
    if active_ids.len() > MAX_ACTIVE_INBOUND_INTENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SMTP active inbound intent snapshot exceeds its bound",
        ));
    }
    let limit = i64::try_from(active_ids.len().saturating_add(1))
        .map_err(|_| io::Error::other("SMTP inbound admission limit overflow"))?;
    let client = database_client(pool).await?;
    let rows = timeout(
        DATABASE_TIMEOUT,
        client.query(
            "SELECT intent_id
             FROM lmyzmail_inbound_delivery_intent
             WHERE mailbox_address=$1
             ORDER BY created_at,intent_id
             LIMIT $2",
            &[&mailbox, &limit],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound unowned intent admission query"))?
    .map_err(database_error)?;
    Ok(rows
        .iter()
        .map(|row| row.get::<_, String>(0))
        .any(|intent_id| !active_ids.contains(&intent_id)))
}

pub(crate) async fn load_unowned_intent_batch(
    pool: &Pool,
    limit: i64,
    active_ids: &HashSet<String>,
) -> io::Result<Vec<PreparedInbound>> {
    if !(1..=RECOVERY_BATCH_SIZE).contains(&limit) || active_ids.len() > MAX_ACTIVE_INBOUND_INTENTS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inbound unowned recovery batch limit is invalid",
        ));
    }
    let database_limit =
        limit
            .checked_add(i64::try_from(active_ids.len()).map_err(|_| {
                io::Error::other("SMTP active inbound intent snapshot length overflow")
            })?)
            .ok_or_else(|| io::Error::other("SMTP inbound recovery query limit overflow"))?;
    let client = database_client(pool).await?;
    let rows = timeout(
        DATABASE_TIMEOUT,
        client.query(
            "SELECT intent_id,mailbox_address,folder,subdirectory,temporary_file_name,file_name,
                    device,inode,size_bytes,sha256,has_attachments,received_at,from_address,
                    message_id,subject,to_addresses,state
             FROM lmyzmail_inbound_delivery_intent
             ORDER BY created_at,intent_id
             LIMIT $1",
            &[&database_limit],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound unowned recovery query"))?
    .map_err(database_error)?;
    rows.iter()
        .filter(|row| !active_ids.contains(&row.get::<_, String>(0)))
        .take(usize::try_from(limit).unwrap_or(RECOVERY_BATCH_SIZE as usize))
        .map(row_to_prepared)
        .collect()
}

pub(crate) async fn pending_intent_count(pool: &Pool) -> io::Result<i64> {
    let client = database_client(pool).await?;
    let row = timeout(
        DATABASE_TIMEOUT,
        client.query_one("SELECT COUNT(*) FROM lmyzmail_inbound_delivery_intent", &[]),
    )
    .await
    .map_err(|_| timed_out("inbound recovery count"))?
    .map_err(database_error)?;
    Ok(row.get(0))
}

pub(crate) async fn load_intent(
    pool: &Pool,
    intent_id: &str,
) -> io::Result<Option<PreparedInbound>> {
    let mut client = database_client(pool).await?;
    let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
        .await
        .map_err(|_| timed_out("inbound reconciliation transaction"))?
        .map_err(database_error)?;
    let lock_id = intent_lock_id(intent_id);
    timeout(
        DATABASE_TIMEOUT,
        transaction.query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_id]),
    )
    .await
    .map_err(|_| timed_out("inbound reconciliation lock"))?
    .map_err(database_error)?;
    let row = timeout(
        DATABASE_TIMEOUT,
        transaction.query_opt(
            "SELECT intent_id,mailbox_address,folder,subdirectory,temporary_file_name,file_name,
                    device,inode,size_bytes,sha256,has_attachments,received_at,from_address,
                    message_id,subject,to_addresses,state
             FROM lmyzmail_inbound_delivery_intent
             WHERE intent_id=$1",
            &[&intent_id],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound intent reconciliation query"))?
    .map_err(database_error)?;
    let prepared = row.as_ref().map(row_to_prepared).transpose()?;
    // The advisory lock protected a read-only snapshot; releasing it is not a rollback.
    let _ = timeout(DATABASE_TIMEOUT, transaction.commit()).await;
    Ok(prepared)
}

fn row_to_prepared(row: &tokio_postgres::Row) -> io::Result<PreparedInbound> {
    let intent_id: String = row.get(0);
    validate_intent_id(&intent_id)?;
    let mailbox: String = row.get(1);
    let mailbox = normalize_mailbox(&mailbox)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mailbox in intent"))?;
    let folder: String = row.get(2);
    validate_folder(&folder)?;
    let subdirectory: Option<i32> = row.get(3);
    if subdirectory.is_some_and(|value| value <= 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Maildir shard in intent",
        ));
    }
    let temporary_name: String = row.get(4);
    if temporary_name != format!("{STAGING_PREFIX}{intent_id}{STAGING_SUFFIX}") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound intent staging name is not bound to its id",
        ));
    }
    let file_name: String = row.get(5);
    validate_file_name(&file_name)?;
    let device = decode_u64(&row.get::<_, Vec<u8>>(6), "device")?;
    let inode = decode_u64(&row.get::<_, Vec<u8>>(7), "inode")?;
    let size_bytes: i64 = row.get(8);
    let size = u64::try_from(size_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative inbound intent size"))?;
    let sha256 = decode_sha256(&row.get::<_, Vec<u8>>(9))?;
    let has_attachments = row.get(10);
    let received_at = row.get(11);
    let from_address = row.get(12);
    let message_id = row.get::<_, Option<String>>(13).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound intent message id is missing",
        )
    })?;
    let subject = row.get(14);
    let to_addresses = row.get::<_, Option<String>>(15).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound intent recipient list is missing",
        )
    })?;
    let state = match row.get::<_, String>(16).as_str() {
        "PREPARED" => IntentState::Prepared,
        "INDEXED" => IntentState::Indexed,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid inbound intent state",
            ));
        }
    };
    let final_parent = PathBuf::new();
    Ok(PreparedInbound {
        intent_id,
        temporary_name: OsString::from(temporary_name),
        staging_parent: PathBuf::new(),
        final_parent,
        identity: FileIdentity {
            device,
            inode,
            size,
            sha256,
        },
        index: InboundIndexMetadata {
            mailbox,
            folder,
            subdirectory,
            file_name,
            has_attachments,
            received_at,
            size_bytes,
            from_address,
            message_id,
            subject,
            to_addresses,
        },
        state,
    })
}

impl PreparedInbound {
    fn matches(&self, other: &Self) -> bool {
        self.intent_id == other.intent_id
            && self.temporary_name == other.temporary_name
            && self.identity == other.identity
            && self.index.mailbox == other.index.mailbox
            && self.index.folder == other.index.folder
            && self.index.subdirectory == other.index.subdirectory
            && self.index.file_name == other.index.file_name
            && self.index.has_attachments == other.index.has_attachments
            && self.index.received_at == other.index.received_at
            && self.index.size_bytes == other.index.size_bytes
            && self.index.from_address == other.index.from_address
            && self.index.message_id == other.index.message_id
            && self.index.subject == other.index.subject
            && self.index.to_addresses == other.index.to_addresses
            && self.state == other.state
    }

    fn matches_index(&self, other: &Self) -> bool {
        self.intent_id == other.intent_id
            && self.temporary_name == other.temporary_name
            && self.identity == other.identity
            && self.index.mailbox == other.index.mailbox
            && self.index.folder == other.index.folder
            && self.index.subdirectory == other.index.subdirectory
            && self.index.file_name == other.index.file_name
            && self.index.has_attachments == other.index.has_attachments
            && self.index.received_at == other.index.received_at
            && self.index.size_bytes == other.index.size_bytes
            && self.index.from_address == other.index.from_address
            && self.index.message_id == other.index.message_id
            && self.index.subject == other.index.subject
            && self.index.to_addresses == other.index.to_addresses
    }

    pub(crate) fn bind_paths(&mut self, maildir: &Path) -> io::Result<()> {
        let folder_root = secure_mailbox_folder(maildir, &self.index.mailbox, &self.index.folder)?;
        self.final_parent = match self.index.subdirectory {
            Some(value) => secure_directory_child(&folder_root, &value.to_string())?,
            None => folder_root,
        };
        self.staging_parent = secure_directory_child(maildir, STAGING_DIRECTORY)?;
        Ok(())
    }
}

pub(crate) fn publish_file(prepared: &PreparedInbound) -> io::Result<()> {
    use rustix::fs::{RenameFlags, renameat_with};

    if prepared.staging_parent.as_os_str().is_empty()
        || prepared.final_parent.as_os_str().is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inbound intent paths are not bound",
        ));
    }
    let staging = super::open_maildir_directory(&prepared.staging_parent)?;
    let final_directory = super::open_maildir_directory(&prepared.final_parent)?;
    let final_name = OsStr::new(&prepared.index.file_name);

    match inspect_file(&final_directory, final_name) {
        Ok(identity) if identity == prepared.identity => {
            confirm_published(&staging, &final_directory, final_name, &prepared.identity)?;
            return confirm_staging_absent(&staging, &prepared.temporary_name);
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Maildir destination is owned by a different file",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let staged_identity = inspect_file(&staging, &prepared.temporary_name)?;
    if staged_identity != prepared.identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "staged inbound file identity changed before publication",
        ));
    }
    match renameat_with(
        &staging,
        &prepared.temporary_name,
        &final_directory,
        final_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        Err(error) => {
            if let Ok(identity) = inspect_file(&final_directory, final_name)
                && identity == prepared.identity
            {
                return confirm_published(
                    &staging,
                    &final_directory,
                    final_name,
                    &prepared.identity,
                )
                .and_then(|()| confirm_staging_absent(&staging, &prepared.temporary_name));
            }
            return Err(io::Error::from(error));
        }
    }
    confirm_published(&staging, &final_directory, final_name, &prepared.identity)?;
    confirm_staging_absent(&staging, &prepared.temporary_name)
}

pub(crate) fn verify_published_file(prepared: &PreparedInbound) -> io::Result<()> {
    if prepared.staging_parent.as_os_str().is_empty()
        || prepared.final_parent.as_os_str().is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inbound intent paths are not bound",
        ));
    }
    let staging = super::open_maildir_directory(&prepared.staging_parent)?;
    let final_directory = super::open_maildir_directory(&prepared.final_parent)?;
    let final_name = OsStr::new(&prepared.index.file_name);
    let rebound = inspect_file(&final_directory, final_name)?;
    if rebound != prepared.identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "published inbound file identity changed after index commit",
        ));
    }
    confirm_staging_absent(&staging, &prepared.temporary_name)
}

fn confirm_published(
    staging: &std::os::fd::OwnedFd,
    final_directory: &std::os::fd::OwnedFd,
    final_name: &OsStr,
    expected: &FileIdentity,
) -> io::Result<()> {
    fsync(final_directory).map_err(io::Error::from)?;
    fsync(staging).map_err(io::Error::from)?;
    let rebound = inspect_file(final_directory, final_name)?;
    if &rebound == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "published inbound file identity changed after directory sync",
        ))
    }
}

fn confirm_staging_absent(
    staging: &std::os::fd::OwnedFd,
    temporary_name: &OsStr,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, statat};

    match statat(staging, temporary_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staging name still exists after Maildir publication",
        )),
        Err(error) if io::Error::from(error).kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn inspect_file(directory: &std::os::fd::OwnedFd, name: &OsStr) -> io::Result<FileIdentity> {
    use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, openat2};
    use std::io::Read as _;

    let descriptor = openat2(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let mut file = std::fs::File::from(descriptor);
    let stat = fstat(&file).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_size < 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "inbound path does not reference one regular file",
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(FileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        size: stat.st_size as u64,
        sha256: digest.finalize().into(),
    })
}

pub(crate) async fn commit_index_and_compact(
    pool: &Pool,
    prepared: &PreparedInbound,
) -> io::Result<()> {
    let mut client = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexPool);
        database_client(pool).await?
    };
    let transaction = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexBegin);
        timeout(DATABASE_TIMEOUT, client.transaction())
            .await
            .map_err(|_| timed_out("inbound index transaction"))?
            .map_err(database_error)?
    };
    let intent_lock = intent_lock_id(&prepared.intent_id);
    {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexIntentLock);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query_one("SELECT pg_advisory_xact_lock($1)", &[&intent_lock]),
        )
        .await
        .map_err(|_| timed_out("inbound index intent lock"))?
        .map_err(database_error)?;
    }
    let intent_row = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexIntentRead);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query_opt(
                "SELECT intent_id,mailbox_address,folder,subdirectory,temporary_file_name,file_name,
                        device,inode,size_bytes,sha256,has_attachments,received_at,from_address,
                        message_id,subject,to_addresses,state
                 FROM lmyzmail_inbound_delivery_intent
                 WHERE intent_id=$1
                 FOR UPDATE",
                &[&prepared.intent_id],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound index intent identity query"))?
        .map_err(database_error)?
    };
    let Some(intent_row) = intent_row else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "inbound durable intent disappeared before index commit",
        ));
    };
    let stored_intent = row_to_prepared(&intent_row)?;
    if !stored_intent.matches_index(prepared) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound durable intent identity changed before index commit",
        ));
    }
    let mailbox_row = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexMailboxRead);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query_opt(
                "SELECT id FROM mailbox WHERE address=$1 FOR KEY SHARE",
                &[&prepared.index.mailbox],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound mailbox lock"))?
        .map_err(database_error)?
    };
    if mailbox_row.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "inbound recipient mailbox disappeared before commit",
        ));
    }
    let rows = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexExistingRead);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query(
                "SELECT has_attachments,subdirectory,received_at,size_bytes,folder,from_address,
                        message_id,subject,to_addresses,file_name,mailbox_address
                 FROM email_index
                 WHERE mailbox_address=$1 AND folder=$2 AND file_name=$3
                   AND subdirectory IS NOT DISTINCT FROM $4
                 ORDER BY id",
                &[
                    &prepared.index.mailbox,
                    &prepared.index.folder,
                    &prepared.index.file_name,
                    &prepared.index.subdirectory,
                ],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound exact index lookup"))?
        .map_err(database_error)?
    };
    let index_inserted = match rows.as_slice() {
        [] => {
            let _timer = StageTimer::start(CoordinatorStage::InboundIndexInsert);
            let inserted = timeout(
                DATABASE_TIMEOUT,
                transaction.execute(
                    "INSERT INTO email_index
                     (has_attachments,subdirectory,indexed_at,received_at,size_bytes,folder,
                      from_address,message_id,subject,to_addresses,file_name,mailbox_address)
                     VALUES ($1,$2,$3,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                    &[
                        &prepared.index.has_attachments,
                        &prepared.index.subdirectory,
                        &prepared.index.received_at,
                        &prepared.index.size_bytes,
                        &prepared.index.folder,
                        &prepared.index.from_address,
                        &prepared.index.message_id,
                        &prepared.index.subject,
                        &prepared.index.to_addresses,
                        &prepared.index.file_name,
                        &prepared.index.mailbox,
                    ],
                ),
            )
            .await
            .map_err(|_| timed_out("inbound index insert"))?
            .map_err(database_error)?;
            if inserted != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "inbound index insert did not create exactly one row",
                ));
            }
            true
        }
        [row] if index_row_matches(row, &prepared.index) => false,
        [_] => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "existing inbound index row does not match the durable intent",
            ));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "multiple inbound index rows match one durable intent",
            ));
        }
    };
    let count_lock = mailbox_count_lock_id(&prepared.index.mailbox, &prepared.index.folder);
    {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexCountState);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query_one("SELECT pg_advisory_xact_lock($1)", &[&count_lock]),
        )
        .await
        .map_err(|_| timed_out("inbound exact count lock"))?
        .map_err(database_error)?;
    }
    let count: i64 = if index_inserted {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexCountState);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "INSERT INTO lmyzmail_inbound_mail_count_state
                 (mailbox_address,folder,exact_count,updated_at)
                 SELECT $1::varchar(255),$2::varchar(50),COUNT(*),CURRENT_TIMESTAMP
                 FROM email_index
                 WHERE mailbox_address=$1::varchar(255)
                   AND folder=$2::varchar(50)
                 ON CONFLICT (mailbox_address,folder) DO UPDATE SET
                     exact_count=lmyzmail_inbound_mail_count_state.exact_count+1,
                     updated_at=CURRENT_TIMESTAMP
                 RETURNING exact_count",
                &[&prepared.index.mailbox, &prepared.index.folder],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound exact count increment"))?
        .map_err(database_error)?
        .get(0)
    } else {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexCountState);
        let count: i64 = timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "SELECT COUNT(*) FROM email_index WHERE mailbox_address=$1 AND folder=$2",
                &[&prepared.index.mailbox, &prepared.index.folder],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound replay projection count"))?
        .map_err(database_error)?
        .get(0);
        timeout(
            DATABASE_TIMEOUT,
            transaction.execute(
                "INSERT INTO lmyzmail_inbound_mail_count_state
                 (mailbox_address,folder,exact_count,updated_at)
                 VALUES ($1,$2,$3,CURRENT_TIMESTAMP)
                 ON CONFLICT (mailbox_address,folder) DO UPDATE SET
                     exact_count=EXCLUDED.exact_count,
                     updated_at=CURRENT_TIMESTAMP",
                &[&prepared.index.mailbox, &prepared.index.folder, &count],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound replay exact count repair"))?
        .map_err(database_error)?;
        count
    };
    {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexProjectionState);
        timeout(
            DATABASE_TIMEOUT,
            transaction.execute(
                "INSERT INTO lmyzmail_inbound_mail_count_projection
                 (mailbox_address,folder,generation,desired_count,updated_at)
                 VALUES ($1,$2,1,$3,CURRENT_TIMESTAMP)
                 ON CONFLICT (mailbox_address,folder) DO UPDATE SET
                     generation=CASE
                         WHEN lmyzmail_inbound_mail_count_projection.generation=9223372036854775807
                         THEN 1
                         ELSE lmyzmail_inbound_mail_count_projection.generation+1
                     END,
                     desired_count=EXCLUDED.desired_count,
                     updated_at=CURRENT_TIMESTAMP",
                &[&prepared.index.mailbox, &prepared.index.folder, &count],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound projection compact"))?
        .map_err(database_error)?;
    }
    let advanced = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexIntentAdvance);
        timeout(
            DATABASE_TIMEOUT,
            transaction.execute(
                "UPDATE lmyzmail_inbound_delivery_intent
                 SET state='INDEXED',updated_at=CURRENT_TIMESTAMP
                 WHERE intent_id=$1",
                &[&prepared.intent_id],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound intent compact"))?
        .map_err(database_error)?
    };
    if advanced != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound intent disappeared before state advance",
        ));
    }
    let commit = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexTransactionCommit);
        timeout(DATABASE_TIMEOUT, transaction.commit()).await
    };
    match commit {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => reconcile_index_commit(pool, prepared, database_error(error)).await,
        Err(_) => reconcile_index_commit(pool, prepared, timed_out("inbound index commit")).await,
    }
}

async fn commit_index_batch(pool: &Pool, prepared: &[&PreparedInbound]) -> io::Result<()> {
    if prepared.is_empty() || prepared.len() > MAX_INDEX_BATCH_ROWS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inbound index batch size is invalid",
        ));
    }
    let mut ordered = prepared.to_vec();
    ordered.sort_by(|left, right| left.intent_id.cmp(&right.intent_id));
    if ordered
        .windows(2)
        .any(|pair| pair[0].intent_id == pair[1].intent_id)
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "inbound index batch contains a duplicate intent",
        ));
    }

    let mut client = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexPool);
        database_client(pool).await?
    };
    let transaction = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexBegin);
        timeout(DATABASE_TIMEOUT, client.transaction())
            .await
            .map_err(|_| timed_out("inbound index batch transaction"))?
            .map_err(database_error)?
    };

    let mut intent_locks = ordered
        .iter()
        .map(|item| intent_lock_id(&item.intent_id))
        .collect::<Vec<_>>();
    intent_locks.sort_unstable();
    intent_locks.dedup();
    {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexIntentLock);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query(
                "SELECT pg_advisory_xact_lock(value)
                 FROM (
                   SELECT value
                   FROM unnest($1::bigint[]) AS lock_id(value)
                   ORDER BY value
                 ) AS ordered_locks",
                &[&intent_locks],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound index batch intent locks"))?
        .map_err(database_error)?;
    }

    let intent_ids = ordered
        .iter()
        .map(|item| item.intent_id.as_str())
        .collect::<Vec<_>>();
    let mailboxes = ordered
        .iter()
        .map(|item| item.index.mailbox.as_str())
        .collect::<Vec<_>>();
    let folders = ordered
        .iter()
        .map(|item| item.index.folder.as_str())
        .collect::<Vec<_>>();
    let file_names = ordered
        .iter()
        .map(|item| item.index.file_name.as_str())
        .collect::<Vec<_>>();
    let subdirectories = ordered
        .iter()
        .map(|item| item.index.subdirectory)
        .collect::<Vec<_>>();
    let expected_by_intent = ordered
        .iter()
        .map(|item| (item.intent_id.as_str(), *item))
        .collect::<BTreeMap<_, _>>();
    let expected_mailboxes = ordered
        .iter()
        .map(|item| item.index.mailbox.as_str())
        .collect::<BTreeSet<_>>();
    let validation_rows = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexIntentRead);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query(
                "WITH input AS (
                   SELECT intent_id,mailbox_address,folder,file_name,subdirectory,ordinal
                   FROM unnest($1::text[],$2::text[],$3::text[],$4::text[],$5::int4[])
                     WITH ORDINALITY
                     AS value(intent_id,mailbox_address,folder,file_name,subdirectory,ordinal)
                 ),
                 locked_intents AS MATERIALIZED (
                   SELECT intent_id,mailbox_address,folder,subdirectory,temporary_file_name,
                          file_name,device,inode,size_bytes,sha256,has_attachments,received_at,
                          from_address,message_id,subject,to_addresses,state
                   FROM lmyzmail_inbound_delivery_intent
                   WHERE intent_id::text = ANY($1::text[])
                   ORDER BY intent_id
                   FOR UPDATE OF lmyzmail_inbound_delivery_intent
                 ),
                 locked_mailboxes AS MATERIALIZED (
                   SELECT mailbox.address::text AS address,
                          intent_barrier.locked_intent_count
                   FROM mailbox
                   CROSS JOIN (
                     SELECT COUNT(*) AS locked_intent_count
                     FROM locked_intents
                   ) AS intent_barrier
                   WHERE mailbox.address::text = ANY($2::text[])
                   ORDER BY mailbox.address
                   FOR KEY SHARE OF mailbox
                 )
                 SELECT locked_intents.intent_id,locked_intents.mailbox_address,
                        locked_intents.folder,locked_intents.subdirectory,
                        locked_intents.temporary_file_name,locked_intents.file_name,
                        locked_intents.device,locked_intents.inode,locked_intents.size_bytes,
                        locked_intents.sha256,locked_intents.has_attachments,
                        locked_intents.received_at,locked_intents.from_address,
                        locked_intents.message_id,locked_intents.subject,
                        locked_intents.to_addresses,locked_intents.state,
                        input.intent_id,locked_mailboxes.address,
                        locked_mailboxes.locked_intent_count,email_index.id,
                        email_index.has_attachments,email_index.subdirectory,
                        email_index.received_at,email_index.size_bytes,email_index.folder,
                        email_index.from_address,email_index.message_id,email_index.subject,
                        email_index.to_addresses,email_index.file_name,
                        email_index.mailbox_address
                 FROM input
                 LEFT JOIN locked_intents
                   ON locked_intents.intent_id::text=input.intent_id
                 LEFT JOIN locked_mailboxes
                   ON locked_mailboxes.address=input.mailbox_address
                 LEFT JOIN email_index
                   ON email_index.mailbox_address::text=input.mailbox_address
                  AND email_index.folder::text=input.folder
                  AND email_index.file_name::text=input.file_name
                  AND email_index.subdirectory IS NOT DISTINCT FROM input.subdirectory
                 ORDER BY input.ordinal,email_index.id",
                &[
                    &intent_ids,
                    &mailboxes,
                    &folders,
                    &file_names,
                    &subdirectories,
                ],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound index batch validation query"))?
        .map_err(database_error)?
    };
    let mut stored_intents = BTreeMap::new();
    let mut existing_mailboxes = BTreeSet::new();
    for row in &validation_rows {
        let expected_intent_id = row.get::<_, String>(17);
        if !expected_by_intent.contains_key(expected_intent_id.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inbound batch validation returned an unknown intent",
            ));
        }
        if row.get::<_, Option<String>>(0).is_some()
            && !stored_intents.contains_key(&expected_intent_id)
        {
            let stored = row_to_prepared(row)?;
            if stored.intent_id != expected_intent_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "inbound batch validation returned a mismatched durable intent",
                ));
            }
            stored_intents.insert(expected_intent_id, stored);
        }
        if let Some(mailbox) = row.get::<_, Option<String>>(18) {
            existing_mailboxes.insert(mailbox);
        }
    }
    for expected in &ordered {
        match stored_intents.get(&expected.intent_id) {
            Some(stored) if stored.matches_index(expected) => {}
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "inbound durable intent identity changed before batch index commit",
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "inbound durable intent disappeared before batch index commit",
                ));
            }
        }
    }
    if existing_mailboxes.len() != expected_mailboxes.len()
        || expected_mailboxes
            .iter()
            .any(|mailbox| !existing_mailboxes.contains(*mailbox))
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "inbound batch recipient mailbox disappeared before commit",
        ));
    }
    let mut replayed = BTreeSet::new();
    for row in &validation_rows {
        if row.get::<_, Option<i64>>(20).is_none() {
            continue;
        }
        let intent_id = row.get::<_, String>(17);
        let Some(expected) = expected_by_intent.get(intent_id.as_str()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inbound batch index lookup returned an unknown intent",
            ));
        };
        if !replayed.insert(intent_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "multiple inbound index rows match one durable batch intent",
            ));
        }
        if !index_row_matches_at(row, &expected.index, 21) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "existing inbound index row does not match the durable batch intent",
            ));
        }
    }

    let missing = ordered
        .iter()
        .copied()
        .filter(|item| !replayed.contains(&item.intent_id))
        .collect::<Vec<_>>();
    let has_attachments = missing
        .iter()
        .map(|item| item.index.has_attachments)
        .collect::<Vec<_>>();
    let missing_subdirectories = missing
        .iter()
        .map(|item| item.index.subdirectory)
        .collect::<Vec<_>>();
    let received_at = missing
        .iter()
        .map(|item| item.index.received_at)
        .collect::<Vec<_>>();
    let size_bytes = missing
        .iter()
        .map(|item| item.index.size_bytes)
        .collect::<Vec<_>>();
    let missing_folders = missing
        .iter()
        .map(|item| item.index.folder.as_str())
        .collect::<Vec<_>>();
    let from_addresses = missing
        .iter()
        .map(|item| item.index.from_address.as_deref())
        .collect::<Vec<_>>();
    let message_ids = missing
        .iter()
        .map(|item| item.index.message_id.as_str())
        .collect::<Vec<_>>();
    let subjects = missing
        .iter()
        .map(|item| item.index.subject.as_deref())
        .collect::<Vec<_>>();
    let to_addresses = missing
        .iter()
        .map(|item| item.index.to_addresses.as_str())
        .collect::<Vec<_>>();
    let missing_file_names = missing
        .iter()
        .map(|item| item.index.file_name.as_str())
        .collect::<Vec<_>>();
    let missing_mailboxes = missing
        .iter()
        .map(|item| item.index.mailbox.as_str())
        .collect::<Vec<_>>();

    let mut groups = BTreeMap::<(String, String), i64>::new();
    for item in &ordered {
        let entry = groups
            .entry((item.index.mailbox.clone(), item.index.folder.clone()))
            .or_insert(0);
        if !replayed.contains(&item.intent_id) {
            *entry = (*entry)
                .checked_add(1)
                .ok_or_else(|| io::Error::other("inbound batch count delta overflow"))?;
        }
    }
    let mut group_locks = groups
        .keys()
        .map(|(mailbox, folder)| mailbox_count_lock_id(mailbox, folder))
        .collect::<Vec<_>>();
    group_locks.sort_unstable();
    group_locks.dedup();
    {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexCountState);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query(
                "SELECT pg_advisory_xact_lock(value)
                 FROM (
                   SELECT value
                   FROM unnest($1::bigint[]) AS lock_id(value)
                   ORDER BY value
                 ) AS ordered_locks",
                &[&group_locks],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound batch count locks"))?
        .map_err(database_error)?;
    }

    let group_mailboxes = groups
        .keys()
        .map(|(mailbox, _)| mailbox.as_str())
        .collect::<Vec<_>>();
    let group_folders = groups
        .keys()
        .map(|(_, folder)| folder.as_str())
        .collect::<Vec<_>>();
    let group_deltas = groups.values().copied().collect::<Vec<_>>();
    let mutation_row = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexMutation);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "WITH missing_input AS (
                   SELECT has_attachments,subdirectory,received_at,size_bytes,folder,
                          from_address,message_id,subject,to_addresses,file_name,mailbox_address
                   FROM unnest(
                     $1::bool[],$2::int4[],$3::timestamptz[],$4::bigint[],$5::text[],
                     $6::text[],$7::text[],$8::text[],$9::text[],$10::text[],$11::text[]
                   ) AS value(
                     has_attachments,subdirectory,received_at,size_bytes,folder,
                     from_address,message_id,subject,to_addresses,file_name,mailbox_address
                   )
                 ),
                 inserted_index AS MATERIALIZED (
                   INSERT INTO email_index
                     (has_attachments,subdirectory,indexed_at,received_at,size_bytes,folder,
                      from_address,message_id,subject,to_addresses,file_name,mailbox_address)
                   SELECT has_attachments,subdirectory,received_at,received_at,size_bytes,
                          folder,from_address,message_id,subject,to_addresses,file_name,
                          mailbox_address
                   FROM missing_input
                   RETURNING mailbox_address::text AS mailbox_address,folder::text AS folder
                 ),
                 insert_barrier AS MATERIALIZED (
                   SELECT COUNT(*)::bigint AS inserted_count FROM inserted_index
                 ),
                 group_input AS (
                   SELECT mailbox_address,folder,delta
                   FROM unnest($12::text[],$13::text[],$14::bigint[])
                     AS value(mailbox_address,folder,delta)
                 ),
                 exact_counts AS MATERIALIZED (
                   SELECT group_input.mailbox_address,group_input.folder,
                          COUNT(email_index.id)::bigint+group_input.delta AS exact_count,
                          insert_barrier.inserted_count
                   FROM group_input
                   CROSS JOIN insert_barrier
                   LEFT JOIN email_index
                     ON email_index.mailbox_address::text=group_input.mailbox_address
                    AND email_index.folder::text=group_input.folder
                   GROUP BY group_input.mailbox_address,group_input.folder,
                            group_input.delta,insert_barrier.inserted_count
                 ),
                 count_state AS MATERIALIZED (
                   INSERT INTO lmyzmail_inbound_mail_count_state
                     (mailbox_address,folder,exact_count,updated_at)
                   SELECT mailbox_address,folder,exact_count,CURRENT_TIMESTAMP
                   FROM exact_counts
                   ON CONFLICT (mailbox_address,folder) DO UPDATE SET
                       exact_count=EXCLUDED.exact_count,
                       updated_at=CURRENT_TIMESTAMP
                   RETURNING mailbox_address::text AS mailbox_address,
                             folder::text AS folder,exact_count
                 ),
                 projection_state AS MATERIALIZED (
                   INSERT INTO lmyzmail_inbound_mail_count_projection
                     (mailbox_address,folder,generation,desired_count,updated_at)
                   SELECT mailbox_address,folder,1,exact_count,CURRENT_TIMESTAMP
                   FROM count_state
                   ON CONFLICT (mailbox_address,folder) DO UPDATE SET
                       generation=CASE
                         WHEN lmyzmail_inbound_mail_count_projection.generation=9223372036854775807
                         THEN 1
                         ELSE lmyzmail_inbound_mail_count_projection.generation+1
                       END,
                       desired_count=EXCLUDED.desired_count,
                       updated_at=CURRENT_TIMESTAMP
                   RETURNING mailbox_address
                 ),
                 projection_barrier AS MATERIALIZED (
                   SELECT COUNT(*)::bigint AS projection_count FROM projection_state
                 ),
                 advanced_intents AS MATERIALIZED (
                   UPDATE lmyzmail_inbound_delivery_intent
                   SET state='INDEXED',updated_at=CURRENT_TIMESTAMP
                   FROM projection_barrier
                   WHERE intent_id::text = ANY($15::text[])
                   RETURNING intent_id
                 )
                 SELECT insert_barrier.inserted_count,
                        (SELECT COUNT(*)::bigint FROM count_state),
                        projection_barrier.projection_count,
                        (SELECT COUNT(*)::bigint FROM advanced_intents)
                 FROM insert_barrier
                 CROSS JOIN projection_barrier",
                &[
                    &has_attachments,
                    &missing_subdirectories,
                    &received_at,
                    &size_bytes,
                    &missing_folders,
                    &from_addresses,
                    &message_ids,
                    &subjects,
                    &to_addresses,
                    &missing_file_names,
                    &missing_mailboxes,
                    &group_mailboxes,
                    &group_folders,
                    &group_deltas,
                    &intent_ids,
                ],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound batch mutation"))?
        .map_err(database_error)?
    };
    let inserted = mutation_row.get::<_, i64>(0);
    let count_states = mutation_row.get::<_, i64>(1);
    let projections = mutation_row.get::<_, i64>(2);
    let advanced = mutation_row.get::<_, i64>(3);
    if inserted != missing.len() as i64
        || count_states != groups.len() as i64
        || projections != groups.len() as i64
        || advanced != ordered.len() as i64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound batch mutation did not update every expected row",
        ));
    }
    let commit = {
        let _timer = StageTimer::start(CoordinatorStage::InboundIndexTransactionCommit);
        timeout(DATABASE_TIMEOUT, transaction.commit()).await
    };
    match commit {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => reconcile_index_batch_commit(pool, &ordered, database_error(error)).await,
        Err(_) => {
            reconcile_index_batch_commit(pool, &ordered, timed_out("inbound index batch commit"))
                .await
        }
    }
}

async fn reconcile_index_batch_commit(
    pool: &Pool,
    prepared: &[&PreparedInbound],
    original: io::Error,
) -> io::Result<()> {
    let failure = IndexCommitFailure::from_error(original);
    for item in prepared {
        reconcile_index_commit(pool, item, failure.to_error()).await?;
    }
    Ok(())
}

pub(crate) async fn complete_intent(pool: &Pool, prepared: &PreparedInbound) -> io::Result<()> {
    let mut client = database_client(pool).await?;
    let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
        .await
        .map_err(|_| timed_out("inbound completion transaction"))?
        .map_err(database_error)?;
    let intent_lock = intent_lock_id(&prepared.intent_id);
    timeout(
        DATABASE_TIMEOUT,
        transaction.query_one("SELECT pg_advisory_xact_lock($1)", &[&intent_lock]),
    )
    .await
    .map_err(|_| timed_out("inbound completion lock"))?
    .map_err(database_error)?;
    let row = timeout(
        DATABASE_TIMEOUT,
        transaction.query_opt(
            "SELECT intent_id,mailbox_address,folder,subdirectory,temporary_file_name,file_name,
                    device,inode,size_bytes,sha256,has_attachments,received_at,from_address,
                    message_id,subject,to_addresses,state
             FROM lmyzmail_inbound_delivery_intent
             WHERE intent_id=$1
             FOR UPDATE",
            &[&prepared.intent_id],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound completion identity query"))?
    .map_err(database_error)?;
    let Some(row) = row else {
        return Ok(());
    };
    let stored = row_to_prepared(&row)?;
    if stored.state != IntentState::Indexed || !stored.matches_index(prepared) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound completion intent identity changed",
        ));
    }
    let deleted = timeout(
        DATABASE_TIMEOUT,
        transaction.execute(
            "DELETE FROM lmyzmail_inbound_delivery_intent WHERE intent_id=$1 AND state='INDEXED'",
            &[&prepared.intent_id],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound completion delete"))?
    .map_err(database_error)?;
    if deleted != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound completion did not delete exactly one intent",
        ));
    }
    match timeout(DATABASE_TIMEOUT, transaction.commit()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => reconcile_intent_completion(pool, prepared, database_error(error)).await,
        Err(_) => {
            reconcile_intent_completion(pool, prepared, timed_out("inbound completion commit"))
                .await
        }
    }
}

async fn reconcile_intent_completion(
    pool: &Pool,
    prepared: &PreparedInbound,
    original: io::Error,
) -> io::Result<()> {
    match load_intent(pool, &prepared.intent_id).await? {
        None => Ok(()),
        Some(intent) if intent.state == IntentState::Indexed && intent.matches_index(prepared) => {
            Err(original)
        }
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound completion outcome is inconsistent",
        )),
    }
}

async fn reconcile_index_commit(
    pool: &Pool,
    prepared: &PreparedInbound,
    original: io::Error,
) -> io::Result<()> {
    match load_intent(pool, &prepared.intent_id).await? {
        Some(intent) if intent.state == IntentState::Indexed && intent.matches_index(prepared) => {}
        Some(_) => return Err(original),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inbound index commit removed its durable intent",
            ));
        }
    }
    let client = database_client(pool).await?;
    let rows = timeout(
        DATABASE_TIMEOUT,
        client.query(
            "SELECT has_attachments,subdirectory,received_at,size_bytes,folder,from_address,
                    message_id,subject,to_addresses,file_name,mailbox_address
             FROM email_index
             WHERE mailbox_address=$1 AND folder=$2 AND file_name=$3
               AND subdirectory IS NOT DISTINCT FROM $4
             ORDER BY id",
            &[
                &prepared.index.mailbox,
                &prepared.index.folder,
                &prepared.index.file_name,
                &prepared.index.subdirectory,
            ],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound index commit reconciliation"))?
    .map_err(database_error)?;
    if matches!(rows.as_slice(), [row] if index_row_matches(row, &prepared.index)) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "inbound index commit outcome is inconsistent",
        ))
    }
}

fn index_row_matches(row: &tokio_postgres::Row, expected: &InboundIndexMetadata) -> bool {
    index_row_matches_at(row, expected, 0)
}

fn index_row_matches_at(
    row: &tokio_postgres::Row,
    expected: &InboundIndexMetadata,
    offset: usize,
) -> bool {
    row.get::<_, bool>(offset) == expected.has_attachments
        && row.get::<_, Option<i32>>(offset + 1) == expected.subdirectory
        && row.get::<_, DateTime<Utc>>(offset + 2) == expected.received_at
        && row.get::<_, Option<i64>>(offset + 3) == Some(expected.size_bytes)
        && row.get::<_, String>(offset + 4) == expected.folder
        && row.get::<_, Option<String>>(offset + 5) == expected.from_address
        && row.get::<_, Option<String>>(offset + 6).as_deref() == Some(expected.message_id.as_str())
        && row.get::<_, Option<String>>(offset + 7) == expected.subject
        && row.get::<_, Option<String>>(offset + 8).as_deref()
            == Some(expected.to_addresses.as_str())
        && row.get::<_, String>(offset + 9) == expected.file_name
        && row.get::<_, String>(offset + 10) == expected.mailbox
}

pub(crate) async fn flush_projection_batch(
    pool: &Pool,
    redis_pool: &RedisPool,
    limit: i64,
) -> io::Result<usize> {
    if !(1..=PROJECTION_BATCH_SIZE).contains(&limit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inbound projection batch limit is invalid",
        ));
    }
    let client = database_client(pool).await?;
    let rows = timeout(
        DATABASE_TIMEOUT,
        client.query(
            "SELECT mailbox_address,folder
             FROM lmyzmail_inbound_mail_count_projection
             ORDER BY updated_at,mailbox_address,folder
             LIMIT $1",
            &[&limit],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound projection queue query"))?
    .map_err(database_error)?;
    let mut flushed = 0_usize;
    for row in &rows {
        let mailbox: String = row.get(0);
        let folder: String = row.get(1);
        flush_projection(pool, redis_pool, &mailbox, &folder).await?;
        flushed = flushed.saturating_add(1);
    }
    Ok(flushed)
}

pub(crate) async fn audit_projection_batch(
    pool: &Pool,
    after: Option<&(String, String)>,
    limit: i64,
) -> io::Result<(usize, Option<(String, String)>)> {
    if !(1..=AUDIT_BATCH_SIZE).contains(&limit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inbound audit batch limit is invalid",
        ));
    }
    let after_mailbox = after.map(|value| value.0.as_str());
    let after_folder = after.map(|value| value.1.as_str());
    let client = database_client(pool).await?;
    let rows = timeout(
        DATABASE_TIMEOUT,
        client.query(
            "SELECT mailbox_address,folder
             FROM email_index
             WHERE $1::varchar IS NULL
                OR mailbox_address > $1
                OR (mailbox_address = $1 AND folder > $2)
             GROUP BY mailbox_address,folder
             ORDER BY mailbox_address,folder
             LIMIT $3",
            &[&after_mailbox, &after_folder, &limit],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound projection audit query"))?
    .map_err(database_error)?;
    if rows.is_empty() {
        return Ok((0, None));
    }
    let mut cursor = None;
    for row in &rows {
        let mailbox: String = row.get(0);
        let folder: String = row.get(1);
        coalesce_exact_projection(pool, &mailbox, &folder).await?;
        cursor = Some((mailbox, folder));
    }
    Ok((rows.len(), cursor))
}

async fn coalesce_exact_projection(pool: &Pool, mailbox: &str, folder: &str) -> io::Result<()> {
    let mut client = database_client(pool).await?;
    let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
        .await
        .map_err(|_| timed_out("inbound audit transaction"))?
        .map_err(database_error)?;
    let mailbox_row = timeout(
        DATABASE_TIMEOUT,
        transaction.query_opt(
            "SELECT id FROM mailbox WHERE address=$1 FOR UPDATE",
            &[&mailbox],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound audit mailbox lock"))?
    .map_err(database_error)?;
    if mailbox_row.is_none() {
        return Ok(());
    }
    let count: i64 = timeout(
        DATABASE_TIMEOUT,
        transaction.query_one(
            "SELECT COUNT(*) FROM email_index WHERE mailbox_address=$1 AND folder=$2",
            &[&mailbox, &folder],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound audit count"))?
    .map_err(database_error)?
    .get(0);
    timeout(
        DATABASE_TIMEOUT,
        transaction.execute(
            "INSERT INTO lmyzmail_inbound_mail_count_state
             (mailbox_address,folder,exact_count,updated_at)
             VALUES ($1,$2,$3,CURRENT_TIMESTAMP)
             ON CONFLICT (mailbox_address,folder) DO UPDATE SET
                 exact_count=EXCLUDED.exact_count,
                 updated_at=CURRENT_TIMESTAMP",
            &[&mailbox, &folder, &count],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound audit exact count state"))?
    .map_err(database_error)?;
    timeout(
        DATABASE_TIMEOUT,
        transaction.execute(
            "INSERT INTO lmyzmail_inbound_mail_count_projection
             (mailbox_address,folder,generation,desired_count,updated_at)
             VALUES ($1,$2,1,$3,CURRENT_TIMESTAMP)
             ON CONFLICT (mailbox_address,folder) DO UPDATE SET
                 generation=CASE
                     WHEN lmyzmail_inbound_mail_count_projection.generation=9223372036854775807
                     THEN 1
                     ELSE lmyzmail_inbound_mail_count_projection.generation+1
                 END,
                 desired_count=EXCLUDED.desired_count,
                 updated_at=CURRENT_TIMESTAMP",
            &[&mailbox, &folder, &count],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound audit projection compact"))?
    .map_err(database_error)?;
    timeout(DATABASE_TIMEOUT, transaction.commit())
        .await
        .map_err(|_| timed_out("inbound audit commit"))?
        .map_err(database_error)
}

pub(crate) async fn flush_projection(
    pool: &Pool,
    redis_pool: &RedisPool,
    mailbox: &str,
    folder: &str,
) -> io::Result<()> {
    let mut client = database_client(pool).await?;
    let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
        .await
        .map_err(|_| timed_out("inbound projection transaction"))?
        .map_err(database_error)?;
    let row = timeout(
        DATABASE_TIMEOUT,
        transaction.query_opt(
            "SELECT generation,desired_count
             FROM lmyzmail_inbound_mail_count_projection
             WHERE mailbox_address=$1 AND folder=$2
             FOR UPDATE",
            &[&mailbox, &folder],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound projection lock"))?
    .map_err(database_error)?;
    let Some(row) = row else {
        return Ok(());
    };
    let generation: i64 = row.get(0);
    let desired_count: i64 = row.get(1);
    let mut redis = timeout(REDIS_TIMEOUT, redis_pool.get())
        .await
        .map_err(|_| timed_out("inbound Redis projection pool"))?
        .map_err(|_| io::Error::other("inbound Redis projection unavailable"))?;
    let key = format!("mail:count:{mailbox}:{folder}");
    timeout(
        REDIS_TIMEOUT,
        deadpool_redis::redis::cmd("SET")
            .arg(&key)
            .arg(desired_count)
            .arg("KEEPTTL")
            .query_async::<()>(&mut redis),
    )
    .await
    .map_err(|_| timed_out("inbound Redis projection command"))?
    .map_err(|_| io::Error::other("inbound Redis projection command failed"))?;
    timeout(
        DATABASE_TIMEOUT,
        transaction.execute(
            "DELETE FROM lmyzmail_inbound_mail_count_projection
             WHERE mailbox_address=$1 AND folder=$2 AND generation=$3",
            &[&mailbox, &folder, &generation],
        ),
    )
    .await
    .map_err(|_| timed_out("inbound projection acknowledgement"))?
    .map_err(database_error)?;
    timeout(DATABASE_TIMEOUT, transaction.commit())
        .await
        .map_err(|_| timed_out("inbound projection commit"))?
        .map_err(database_error)
}

pub(crate) async fn cleanup_untracked_staging(
    maildir: &Path,
    pool: &Pool,
    blocking_permits: &Arc<Semaphore>,
    minimum_age: Duration,
    entry_limit: usize,
) -> io::Result<usize> {
    if entry_limit == 0 || entry_limit > STAGING_ENTRY_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "inbound staging cleanup limit is invalid",
        ));
    }
    let scan_permit = blocking_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| io::Error::other("SMTP blocking pool closed"))?;
    let maildir_for_scan = maildir.to_path_buf();
    let candidates = spawn_blocking(move || {
        let _permit = scan_permit;
        scan_staging(&maildir_for_scan, minimum_age, entry_limit)
    })
    .await
    .map_err(|error| io::Error::other(error.to_string()))??;
    if candidates.is_empty() {
        return Ok(0);
    }
    let mut removed = 0_usize;
    for candidate in candidates.into_iter().take(STAGING_CLEANUP_BATCH_SIZE) {
        let remove_permit = blocking_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("SMTP blocking pool closed"))?;
        let mut client = database_client(pool).await?;
        let transaction = timeout(DATABASE_TIMEOUT, client.transaction())
            .await
            .map_err(|_| timed_out("inbound staging cleanup transaction"))?
            .map_err(database_error)?;
        let lock_id = intent_lock_id(&candidate.intent_id);
        timeout(
            DATABASE_TIMEOUT,
            transaction.query_one("SELECT pg_advisory_xact_lock($1)", &[&lock_id]),
        )
        .await
        .map_err(|_| timed_out("inbound staging cleanup intent lock"))?
        .map_err(database_error)?;
        let tracked: bool = timeout(
            DATABASE_TIMEOUT,
            transaction.query_one(
                "SELECT EXISTS(
                     SELECT 1 FROM lmyzmail_inbound_delivery_intent WHERE intent_id=$1
                 )",
                &[&candidate.intent_id],
            ),
        )
        .await
        .map_err(|_| timed_out("inbound staging cleanup intent query"))?
        .map_err(database_error)?
        .get(0);
        if tracked {
            // The tracked branch performed no writes; commit only releases its lock.
            let _ = timeout(DATABASE_TIMEOUT, transaction.commit()).await;
            continue;
        }
        let maildir_for_remove = maildir.to_path_buf();
        spawn_blocking(move || {
            let _permit = remove_permit;
            remove_staging(&maildir_for_remove, std::slice::from_ref(&candidate))
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))??;
        timeout(DATABASE_TIMEOUT, transaction.commit())
            .await
            .map_err(|_| timed_out("inbound staging cleanup commit"))?
            .map_err(database_error)?;
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

fn scan_staging(
    maildir: &Path,
    minimum_age: Duration,
    entry_limit: usize,
) -> io::Result<Vec<StagingCandidate>> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = match std::fs::symlink_metadata(maildir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SMTP Maildir root is not a real directory",
        ));
    }
    let staging_path = maildir.join(STAGING_DIRECTORY);
    let staging_metadata = match std::fs::symlink_metadata(&staging_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !staging_metadata.is_dir() || staging_metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SMTP inbound staging path is not a real directory",
        ));
    }
    let mut candidates = Vec::new();
    let mut visited = 0_usize;
    for entry in std::fs::read_dir(&staging_path)? {
        visited = visited.saturating_add(1);
        if visited > entry_limit {
            return Err(io::Error::other(
                "SMTP inbound staging cleanup entry budget exceeded",
            ));
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(intent_id) = staging_intent_id(&name) else {
            continue;
        };
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SMTP inbound staging candidate is not a regular file",
            ));
        }
        let metadata = entry.metadata()?;
        let modified = metadata.modified()?;
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::ZERO);
        if age >= minimum_age {
            let intent_id = intent_id.to_owned();
            candidates.push(StagingCandidate {
                name,
                intent_id,
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.size(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
            });
        }
    }
    Ok(candidates)
}

fn remove_staging(maildir: &Path, candidates: &[StagingCandidate]) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType, statat, unlinkat};

    let staging_path = maildir.join(STAGING_DIRECTORY);
    let staging = super::open_maildir_directory(&staging_path)?;
    for candidate in candidates {
        let stat = statat(&staging, &candidate.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_nlink != 1
            || stat.st_dev != candidate.device
            || stat.st_ino != candidate.inode
            || stat.st_size < 0
            || stat.st_size as u64 != candidate.size
            || stat.st_mtime != candidate.modified_seconds
            || i64::try_from(stat.st_mtime_nsec).ok() != Some(candidate.modified_nanoseconds)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SMTP inbound staging cleanup found a non-owned candidate",
            ));
        }
        unlinkat(&staging, &candidate.name, AtFlags::empty()).map_err(io::Error::from)?;
    }
    fsync(&staging).map_err(io::Error::from)
}

fn staging_intent_id(name: &OsStr) -> Option<&str> {
    let value = name.to_str()?;
    let intent_id = value
        .strip_prefix(STAGING_PREFIX)?
        .strip_suffix(STAGING_SUFFIX)?;
    (intent_id.len() == 32 && intent_id.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(intent_id)
}

fn validate_intent_id(value: &str) -> io::Result<()> {
    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid inbound intent id",
        ))
    }
}

fn validate_folder(value: &str) -> io::Result<()> {
    if matches!(value, "inbox" | "sent" | "spam" | "drafts" | "trash") {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid folder in inbound intent",
        ))
    }
}

fn validate_file_name(value: &str) -> io::Result<()> {
    if !value.is_empty()
        && value.len() <= 255
        && value.ends_with(".eml")
        && !value.contains("..")
        && !value.contains('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid inbound Maildir filename",
        ))
    }
}

fn decode_u64(value: &[u8], label: &str) -> io::Result<u64> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid inbound intent {label}"),
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_sha256(value: &[u8]) -> io::Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid inbound intent SHA-256"))
}

fn intent_lock_id(intent_id: &str) -> i64 {
    let digest = Sha256::digest(intent_id.as_bytes());
    i64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is eight bytes"),
    )
}

fn mailbox_count_lock_id(mailbox: &str, folder: &str) -> i64 {
    let mut input = String::with_capacity(mailbox.len() + folder.len() + 32);
    input.push_str("lmyzmail-inbound-count:");
    input.push_str(mailbox);
    input.push('\0');
    input.push_str(folder);
    let digest = Sha256::digest(input.as_bytes());
    i64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is eight bytes"),
    )
}

async fn database_client(pool: &Pool) -> io::Result<Object> {
    timeout(DATABASE_TIMEOUT, pool.get())
        .await
        .map_err(|_| timed_out("inbound database pool"))?
        .map_err(|error| io::Error::other(error.to_string()))
}

fn timed_out(operation: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{operation} timeout"))
}

fn database_error(error: tokio_postgres::Error) -> io::Error {
    let message = error.as_db_error().map_or_else(
        || error.to_string(),
        |database| {
            format!(
                "PostgreSQL {} {}: {}",
                database.severity(),
                database.code().code(),
                database.message()
            )
        },
    );
    io::Error::other(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::TcpListener,
        process::{Child, Command, Stdio},
    };

    use crate::{
        config::{Properties, RuntimeConfig},
        database,
    };

    const TEST_DATABASE_SCHEMA: &str = r#"
CREATE TABLE mailbox (
    id bigint generated by default as identity primary key,
    address varchar(255) not null unique
);
CREATE TABLE email_index (
    id bigint generated by default as identity primary key,
    mailbox_address varchar(255) not null,
    folder varchar(50) not null,
    file_name varchar(255) not null,
    subdirectory integer,
    subject varchar(1000),
    from_address varchar(500),
    to_addresses varchar(2000),
    received_at timestamp(6) with time zone not null,
    has_attachments boolean not null,
    message_id varchar(500),
    size_bytes bigint,
    indexed_at timestamp(6) with time zone not null,
    CONSTRAINT uk_email_index_mailbox_folder_subdir_file
        UNIQUE (mailbox_address, folder, subdirectory, file_name)
);
INSERT INTO mailbox (address) VALUES ('qa@example.test');
"#;

    static TEST_POSTGRES_START_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct TestPostgres {
        child: Child,
        directory: PathBuf,
        port: u16,
    }

    impl TestPostgres {
        fn start() -> Self {
            let _guard = TEST_POSTGRES_START_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);

            let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .unwrap();
            let root = repository.join(".blackbox/runtime/postgres-root");
            let binary_directory = root.join("usr/lib/postgresql/16/bin");
            let library_directory = root.join("usr/lib/x86_64-linux-gnu");
            assert!(binary_directory.join("initdb").is_file());
            assert!(binary_directory.join("postgres").is_file());
            assert!(binary_directory.join("pg_isready").is_file());

            let directory = test_directory("postgres-batch");
            let data_directory = directory.join("data");
            let socket_directory = directory.join("socket");
            std::fs::create_dir(&socket_directory).unwrap();
            let initialized = Command::new(binary_directory.join("initdb"))
                .args([
                    "--pgdata",
                    data_directory.to_str().unwrap(),
                    "--username=lmyzmail_test",
                    "--auth=trust",
                    "--encoding=UTF8",
                    "--no-locale",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .env("LD_LIBRARY_PATH", &library_directory)
                .status()
                .unwrap();
            assert!(initialized.success(), "PostgreSQL initdb failed");
            let child = Command::new(binary_directory.join("postgres"))
                .args([
                    "-D",
                    data_directory.to_str().unwrap(),
                    "-h",
                    "127.0.0.1",
                    "-p",
                    &port.to_string(),
                    "-k",
                    socket_directory.to_str().unwrap(),
                    "-F",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .env("LD_LIBRARY_PATH", &library_directory)
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let ready = Command::new(binary_directory.join("pg_isready"))
                    .args([
                        "--host=127.0.0.1",
                        &format!("--port={port}"),
                        "--username=lmyzmail_test",
                        "--dbname=postgres",
                        "--timeout=1",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .env("LD_LIBRARY_PATH", &library_directory)
                    .status()
                    .unwrap();
                if ready.success() {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "PostgreSQL did not start"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Self {
                child,
                directory,
                port,
            }
        }
    }

    impl Drop for TestPostgres {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if self
                .directory
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with("lmyzmail-inbound-postgres-batch-"))
            {
                let _ = std::fs::remove_dir_all(&self.directory);
            }
        }
    }

    async fn test_database() -> (TestPostgres, Pool) {
        let postgres = TestPostgres::start();
        let mut properties = Properties::default();
        for (key, value) in [
            ("lmyzmail.postgres.host", "127.0.0.1".to_owned()),
            ("lmyzmail.postgres.port", postgres.port.to_string()),
            ("lmyzmail.postgres.database", "postgres".to_owned()),
            ("lmyzmail.postgres.username", "lmyzmail_test".to_owned()),
            ("lmyzmail.postgres.password", String::new()),
            ("lmyzmail.postgres.pool.max-size", "8".to_owned()),
        ] {
            properties.insert(key.to_owned(), value).unwrap();
        }
        let config = RuntimeConfig::from_properties(properties).unwrap();
        let pool = database::create_pool(&config).unwrap();
        pool.get()
            .await
            .unwrap()
            .batch_execute(TEST_DATABASE_SCHEMA)
            .await
            .unwrap();
        initialize_schema(&pool).await.unwrap();
        (postgres, pool)
    }

    fn database_prepared(sequence: u64, folder: &str) -> PreparedInbound {
        let size = 1_024 + sequence;
        PreparedInbound {
            intent_id: format!("{sequence:032x}"),
            temporary_name: OsString::from(format!(".lmyzmail-inbound-{sequence:032x}.tmp")),
            staging_parent: PathBuf::new(),
            final_parent: PathBuf::new(),
            identity: FileIdentity {
                device: 1,
                inode: sequence + 1,
                size,
                sha256: [sequence as u8; 32],
            },
            index: InboundIndexMetadata {
                mailbox: "qa@example.test".to_owned(),
                folder: folder.to_owned(),
                subdirectory: Some((sequence / 10_000 + 1) as i32),
                file_name: format!("message-{sequence:08}.eml"),
                has_attachments: sequence.is_multiple_of(2),
                received_at: DateTime::from_timestamp(1_754_395_200 + sequence as i64, 0).unwrap(),
                size_bytes: size as i64,
                from_address: Some(format!("sender-{sequence}@example.test")),
                message_id: format!("<batch-{sequence}@example.test>"),
                subject: Some(format!("batch {sequence}")),
                to_addresses: r#"["qa@example.test"]"#.to_owned(),
            },
            state: IntentState::Prepared,
        }
    }

    async fn insert_prepared(pool: &Pool, values: &[PreparedInbound]) {
        for prepared in values {
            insert_intent(pool, prepared).await.unwrap();
        }
    }

    async fn assert_exact_count(pool: &Pool, folder: &str, expected: i64) {
        let client = pool.get().await.unwrap();
        let indexed: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM email_index WHERE mailbox_address=$1 AND folder=$2",
                &[&"qa@example.test", &folder],
            )
            .await
            .unwrap()
            .get(0);
        let state: i64 = client
            .query_one(
                "SELECT exact_count FROM lmyzmail_inbound_mail_count_state
                 WHERE mailbox_address=$1 AND folder=$2",
                &[&"qa@example.test", &folder],
            )
            .await
            .unwrap()
            .get(0);
        let projection: i64 = client
            .query_one(
                "SELECT desired_count FROM lmyzmail_inbound_mail_count_projection
                 WHERE mailbox_address=$1 AND folder=$2",
                &[&"qa@example.test", &folder],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!((indexed, state, projection), (expected, expected, expected));
    }

    async fn assert_failed_batch_was_atomic(pool: &Pool, existing_indexes: i64) {
        let client = pool.get().await.unwrap();
        let index_count: i64 = client
            .query_one("SELECT COUNT(*) FROM email_index", &[])
            .await
            .unwrap()
            .get(0);
        let advanced_intents: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM lmyzmail_inbound_delivery_intent
                 WHERE state <> 'PREPARED'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let count_states: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM lmyzmail_inbound_mail_count_state",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let projections: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM lmyzmail_inbound_mail_count_projection",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(
            (index_count, advanced_intents, count_states, projections),
            (existing_indexes, 0, 0, 0)
        );
    }

    async fn database_xact_rollback(pool: &Pool) -> i64 {
        let client = pool.get().await.unwrap();
        client
            .batch_execute("SELECT pg_stat_force_next_flush(); SELECT pg_stat_clear_snapshot();")
            .await
            .unwrap();
        client
            .query_one(
                "SELECT xact_rollback FROM pg_stat_database WHERE datname=current_database()",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_commit_is_exact_and_replay_safe() {
        let (_postgres, pool) = test_database().await;
        let prepared = (1..=MAX_INDEX_BATCH_ROWS as u64)
            .map(|sequence| database_prepared(sequence, "inbox"))
            .collect::<Vec<_>>();
        insert_prepared(&pool, &prepared).await;
        let references = prepared.iter().collect::<Vec<_>>();

        commit_index_batch(&pool, &references).await.unwrap();
        assert_exact_count(&pool, "inbox", MAX_INDEX_BATCH_ROWS as i64).await;

        commit_index_batch(&pool, &references).await.unwrap();
        assert_exact_count(&pool, "inbox", MAX_INDEX_BATCH_ROWS as i64).await;
        let client = pool.get().await.unwrap();
        let indexed_intents: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM lmyzmail_inbound_delivery_intent WHERE state='INDEXED'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(indexed_intents, MAX_INDEX_BATCH_ROWS as i64);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_validation_failures_are_atomic_and_error_specific() {
        let (_postgres, pool) = test_database().await;
        let mut first = database_prepared(6_000, "inbox");
        first.index.subdirectory = None;
        let second = database_prepared(6_001, "inbox");
        insert_intent(&pool, &first).await.unwrap();
        let references = [&first, &second];

        let error = commit_index_batch(&pool, &references).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_failed_batch_was_atomic(&pool, 0).await;

        insert_intent(&pool, &second).await.unwrap();
        let client = pool.get().await.unwrap();
        client
            .execute(
                "UPDATE lmyzmail_inbound_delivery_intent
                 SET subject='identity drift' WHERE intent_id=$1",
                &[&second.intent_id],
            )
            .await
            .unwrap();
        drop(client);
        let error = commit_index_batch(&pool, &references).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_failed_batch_was_atomic(&pool, 0).await;

        let client = pool.get().await.unwrap();
        client
            .execute(
                "UPDATE lmyzmail_inbound_delivery_intent
                 SET subject=$2 WHERE intent_id=$1",
                &[&second.intent_id, &second.index.subject],
            )
            .await
            .unwrap();
        client.execute("DELETE FROM mailbox", &[]).await.unwrap();
        drop(client);
        let error = commit_index_batch(&pool, &references).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_failed_batch_was_atomic(&pool, 0).await;

        let client = pool.get().await.unwrap();
        client
            .execute(
                "INSERT INTO mailbox (address) VALUES ('qa@example.test')",
                &[],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO email_index
                   (has_attachments,subdirectory,indexed_at,received_at,size_bytes,folder,
                    from_address,message_id,subject,to_addresses,file_name,mailbox_address)
                 SELECT has_attachments,subdirectory,received_at,received_at,size_bytes,folder,
                        from_address,message_id,'replay drift',to_addresses,file_name,
                        mailbox_address
                 FROM lmyzmail_inbound_delivery_intent WHERE intent_id=$1",
                &[&first.intent_id],
            )
            .await
            .unwrap();
        drop(client);
        let error = commit_index_batch(&pool, &references).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_failed_batch_was_atomic(&pool, 1).await;

        let client = pool.get().await.unwrap();
        client
            .execute(
                "UPDATE email_index SET subject=$1 WHERE file_name=$2",
                &[&first.index.subject, &first.index.file_name],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO email_index
                   (has_attachments,subdirectory,indexed_at,received_at,size_bytes,folder,
                    from_address,message_id,subject,to_addresses,file_name,mailbox_address)
                 SELECT has_attachments,subdirectory,indexed_at,received_at,size_bytes,folder,
                        from_address,message_id,subject,to_addresses,file_name,mailbox_address
                 FROM email_index WHERE file_name=$1 LIMIT 1",
                &[&first.index.file_name],
            )
            .await
            .unwrap();
        drop(client);
        let error = commit_index_batch(&pool, &references).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_failed_batch_was_atomic(&pool, 2).await;

        let client = pool.get().await.unwrap();
        client
            .execute(
                "DELETE FROM email_index WHERE id=(
                   SELECT MAX(id) FROM email_index WHERE file_name=$1
                 )",
                &[&first.index.file_name],
            )
            .await
            .unwrap();
        drop(client);
        commit_index_batch(&pool, &references).await.unwrap();
        assert_exact_count(&pool, "inbox", 2).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_commit_initializes_legacy_groups_and_multiple_folders() {
        let (_postgres, pool) = test_database().await;
        pool.get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO email_index
                   (has_attachments,subdirectory,indexed_at,received_at,size_bytes,folder,
                    from_address,message_id,subject,to_addresses,file_name,mailbox_address)
                 VALUES
                   (FALSE,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,512,'inbox',
                    'legacy@example.test','<legacy@example.test>','legacy',
                    '[\"qa@example.test\"]','legacy.eml','qa@example.test')",
                &[],
            )
            .await
            .unwrap();
        let prepared = [
            database_prepared(100, "inbox"),
            database_prepared(101, "sent"),
            database_prepared(102, "inbox"),
            database_prepared(103, "sent"),
        ];
        insert_prepared(&pool, &prepared).await;
        let references = prepared.iter().collect::<Vec<_>>();

        commit_index_batch(&pool, &references).await.unwrap();
        assert_exact_count(&pool, "inbox", 3).await;
        assert_exact_count(&pool, "sent", 2).await;

        commit_index_batch(&pool, &references).await.unwrap();
        assert_exact_count(&pool, "inbox", 3).await;
        assert_exact_count(&pool, "sent", 2).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn committer_isolates_request_failure_and_drains_shutdown_queue() {
        let (_postgres, pool) = test_database().await;
        let valid = database_prepared(1_000, "spam");
        let missing = database_prepared(1_001, "spam");
        insert_intent(&pool, &valid).await.unwrap();
        let committer = IndexCommitter::start(pool.clone());
        let mut responses = Vec::new();
        for prepared in [valid.clone(), missing] {
            let (response, receiver) = oneshot::channel();
            committer
                .sender
                .send(IndexCommitRequest { prepared, response })
                .await
                .unwrap();
            responses.push(receiver);
        }
        assert!(responses.remove(0).await.unwrap().is_ok());
        assert_eq!(
            responses.remove(0).await.unwrap().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_exact_count(&pool, "spam", 1).await;

        let queued = (2_000..2_000 + MAX_INDEX_BATCH_ROWS as u64)
            .map(|sequence| database_prepared(sequence, "sent"))
            .collect::<Vec<_>>();
        insert_prepared(&pool, &queued).await;
        let mut queued_responses = Vec::new();
        for prepared in queued {
            let (response, receiver) = oneshot::channel();
            committer
                .sender
                .send(IndexCommitRequest { prepared, response })
                .await
                .unwrap();
            queued_responses.push(receiver);
        }
        assert!(
            committer
                .shutdown(Instant::now() + Duration::from_secs(10))
                .await
        );
        for receiver in queued_responses {
            receiver.await.unwrap().unwrap();
        }
        assert_exact_count(&pool, "sent", MAX_INDEX_BATCH_ROWS as i64).await;
        assert_eq!(
            committer.submit(&valid).await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_and_single_recovery_share_exact_count_lock() {
        let (_postgres, pool) = test_database().await;
        let batch = (3_000..3_000 + MAX_INDEX_BATCH_ROWS as u64)
            .map(|sequence| database_prepared(sequence, "drafts"))
            .collect::<Vec<_>>();
        let recovery = database_prepared(4_000, "drafts");
        insert_prepared(&pool, &batch).await;
        insert_intent(&pool, &recovery).await.unwrap();

        let batch_pool = pool.clone();
        let batch_task = tokio::spawn(async move {
            let references = batch.iter().collect::<Vec<_>>();
            commit_index_batch(&batch_pool, &references).await
        });
        let recovery_pool = pool.clone();
        let recovery_task =
            tokio::spawn(async move { commit_index_and_compact(&recovery_pool, &recovery).await });
        batch_task.await.unwrap().unwrap();
        recovery_task.await.unwrap().unwrap();
        assert_exact_count(&pool, "drafts", MAX_INDEX_BATCH_ROWS as i64 + 1).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn read_only_intent_locks_do_not_count_postgresql_rollbacks() {
        let (_postgres, pool) = test_database().await;
        let prepared = database_prepared(5_000, "inbox");
        insert_intent(&pool, &prepared).await.unwrap();

        let control_before = database_xact_rollback(&pool).await;
        let mut client = pool.get().await.unwrap();
        client
            .transaction()
            .await
            .unwrap()
            .rollback()
            .await
            .unwrap();
        drop(client);
        let rollbacks_before = database_xact_rollback(&pool).await;
        assert_eq!(rollbacks_before, control_before + 1);

        let loaded = load_intent(&pool, &prepared.intent_id)
            .await
            .unwrap()
            .unwrap();
        assert!(loaded.matches(&prepared));
        assert_eq!(database_xact_rollback(&pool).await, rollbacks_before);

        let root = test_directory("tracked-staging");
        initialize_staging(&root).unwrap();
        std::fs::write(
            root.join(STAGING_DIRECTORY).join(&prepared.temporary_name),
            b"tracked",
        )
        .unwrap();
        let removed = cleanup_untracked_staging(
            &root,
            &pool,
            &Arc::new(Semaphore::new(1)),
            Duration::ZERO,
            8,
        )
        .await
        .unwrap();
        assert_eq!(removed, 0);
        assert!(
            root.join(STAGING_DIRECTORY)
                .join(&prepared.temporary_name)
                .is_file()
        );
        assert_eq!(database_xact_rollback(&pool).await, rollbacks_before);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn test_directory(label: &str) -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;

        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "lmyzmail-inbound-{label}-{}",
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700).create(&path).unwrap();
        path
    }

    fn test_index(file_name: &str, size: usize) -> InboundIndexMetadata {
        InboundIndexMetadata {
            mailbox: "qa@example.test".into(),
            folder: "inbox".into(),
            subdirectory: Some(1),
            file_name: file_name.into(),
            has_attachments: false,
            received_at: DateTime::from_timestamp(1_754_395_200, 123_456_000).unwrap(),
            size_bytes: size as i64,
            from_address: Some("sender@example.test".into()),
            message_id: "<durable@example.test>".into(),
            subject: Some("durable".into()),
            to_addresses: r#"["qa@example.test"]"#.into(),
        }
    }

    #[test]
    fn staging_names_are_strict_and_intent_bound() {
        assert_eq!(
            staging_intent_id(OsStr::new(
                ".lmyzmail-inbound-0123456789abcdef0123456789ABCDEF.tmp"
            )),
            Some("0123456789abcdef0123456789ABCDEF")
        );
        assert_eq!(
            staging_intent_id(OsStr::new(".lmyzmail-inbound-../escape.tmp")),
            None
        );
        assert_eq!(
            staging_intent_id(OsStr::new(
                ".lmyzmail-inbound-0123456789abcdef0123456789abcdef.tmp.extra"
            )),
            None
        );
    }

    #[test]
    fn migration_is_additive_and_lmyzmail_owned() {
        assert!(INBOUND_SCHEMA.contains("lmyzmail_inbound_delivery_intent"));
        assert!(INBOUND_SCHEMA.contains("lmyzmail_inbound_mail_count_projection"));
        assert!(INBOUND_SCHEMA.contains("lmyzmail_inbound_mail_count_state"));
        assert!(INBOUND_SCHEMA.contains("CREATE TABLE IF NOT EXISTS"));
        assert!(
            !INBOUND_SCHEMA
                .to_ascii_lowercase()
                .contains("alter table email_index")
        );
        assert!(!INBOUND_SCHEMA.to_ascii_lowercase().contains("drop table"));
    }

    #[test]
    fn active_intent_guard_blocks_only_after_a_durable_failure() {
        let registry = Arc::new(ActiveInboundIntents::default());
        {
            let _guard = registry
                .reserve(
                    "00000000000000000000000000000001".into(),
                    "qa@example.test".into(),
                )
                .unwrap();
        }
        assert!(registry.blocked_mailboxes().unwrap().is_empty());

        {
            let guard = registry
                .reserve(
                    "00000000000000000000000000000002".into(),
                    "qa@example.test".into(),
                )
                .unwrap();
            guard.mark_durable().unwrap();
        }
        assert_eq!(
            registry.blocked_mailboxes().unwrap(),
            vec!["qa@example.test".to_owned()]
        );
        assert_eq!(
            registry
                .reserve(
                    "00000000000000000000000000000003".into(),
                    "qa@example.test".into(),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        registry.clear_blocked_mailbox("qa@example.test").unwrap();
        registry
            .reserve(
                "00000000000000000000000000000003".into(),
                "qa@example.test".into(),
            )
            .unwrap()
            .complete()
            .unwrap();
        assert!(registry.active_ids().unwrap().is_empty());
    }

    #[test]
    fn active_intent_registry_has_a_hard_capacity() {
        let registry = Arc::new(ActiveInboundIntents::default());
        let mut guards = Vec::new();
        for value in 0..MAX_ACTIVE_INBOUND_INTENTS {
            guards.push(
                registry
                    .reserve(
                        format!("{value:032x}"),
                        format!("mailbox-{value}@example.test"),
                    )
                    .unwrap(),
            );
        }
        assert_eq!(
            registry.active_ids().unwrap().len(),
            MAX_ACTIVE_INBOUND_INTENTS
        );
        assert_eq!(
            registry
                .reserve(
                    "ffffffffffffffffffffffffffffffff".into(),
                    "overflow@example.test".into(),
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(guards);
        assert!(registry.active_ids().unwrap().is_empty());
    }

    #[test]
    fn projection_uses_legacy_key_and_preserves_ttl() {
        let source = include_str!("smtp_inbound_delivery.rs");
        assert!(source.contains("mail:count:{mailbox}:{folder}"));
        assert!(source.contains(".arg(\"KEEPTTL\")"));
        assert!(!source.contains("cmd(\"INCR\")"));
    }

    #[test]
    fn staged_file_is_identity_bound_and_publish_is_replay_safe() {
        let root = test_directory("publish-replay");
        initialize_staging(&root).unwrap();
        let folder = secure_mailbox_folder(&root, "qa@example.test", "inbox").unwrap();
        let final_parent = secure_directory_child(&folder, "1").unwrap();
        let data = b"From: sender@example.test\r\n\r\ndurable\r\n";
        let prepared = prepare_file(
            &root,
            final_parent.clone(),
            "0123456789abcdef0123456789abcdef".into(),
            data,
            test_index("durable.eml", data.len()),
        )
        .unwrap();
        assert!(!final_parent.join("durable.eml").exists());
        publish_file(&prepared).unwrap();
        publish_file(&prepared).unwrap();
        verify_published_file(&prepared).unwrap();
        assert_eq!(
            std::fs::read(final_parent.join("durable.eml")).unwrap(),
            data
        );
        assert!(
            !prepared
                .staging_parent
                .join(&prepared.temporary_name)
                .exists()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn published_identity_replacement_is_rejected_by_verification() {
        let root = test_directory("publish-replacement");
        initialize_staging(&root).unwrap();
        let folder = secure_mailbox_folder(&root, "qa@example.test", "inbox").unwrap();
        let final_parent = secure_directory_child(&folder, "1").unwrap();
        let data = b"same bytes, different inode";
        let prepared = prepare_file(
            &root,
            final_parent.clone(),
            "00112233445566778899aabbccddeeff".into(),
            data,
            test_index("replaced.eml", data.len()),
        )
        .unwrap();
        publish_file(&prepared).unwrap();
        let destination = final_parent.join("replaced.eml");
        let replacement = final_parent.join(".replacement.eml");
        std::fs::write(&replacement, data).unwrap();
        std::fs::remove_file(&destination).unwrap();
        std::fs::rename(&replacement, &destination).unwrap();
        assert_eq!(
            verify_published_file(&prepared).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn published_staging_residue_is_rejected_by_verification() {
        let root = test_directory("publish-residue");
        initialize_staging(&root).unwrap();
        let folder = secure_mailbox_folder(&root, "qa@example.test", "inbox").unwrap();
        let final_parent = secure_directory_child(&folder, "1").unwrap();
        let data = b"published with unexpected staging residue";
        let prepared = prepare_file(
            &root,
            final_parent,
            "ffeeddccbbaa99887766554433221100".into(),
            data,
            test_index("residue.eml", data.len()),
        )
        .unwrap();
        publish_file(&prepared).unwrap();
        std::fs::write(prepared.staging_parent.join(&prepared.temporary_name), data).unwrap();
        assert_eq!(
            verify_published_file(&prepared).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(publish_file(&prepared).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staged_mutation_is_rejected_before_publication() {
        let root = test_directory("stage-mutation");
        initialize_staging(&root).unwrap();
        let folder = secure_mailbox_folder(&root, "qa@example.test", "inbox").unwrap();
        let final_parent = secure_directory_child(&folder, "1").unwrap();
        let data = b"original";
        let prepared = prepare_file(
            &root,
            final_parent.clone(),
            "fedcba9876543210fedcba9876543210".into(),
            data,
            test_index("mutated.eml", data.len()),
        )
        .unwrap();
        std::fs::write(
            prepared.staging_parent.join(&prepared.temporary_name),
            b"mutation",
        )
        .unwrap();
        assert!(publish_file(&prepared).is_err());
        assert!(!final_parent.join("mutated.eml").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staging_scan_is_prefix_age_and_entry_bounded() {
        let root = test_directory("staging-scan");
        initialize_staging(&root).unwrap();
        let staging = root.join(STAGING_DIRECTORY);
        let owned = staging.join(".lmyzmail-inbound-00112233445566778899aabbccddeeff.tmp");
        std::fs::write(&owned, b"orphan").unwrap();
        std::fs::write(staging.join("unrelated.tmp"), b"keep").unwrap();
        let candidates = scan_staging(&root, Duration::ZERO, 2).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].intent_id, "00112233445566778899aabbccddeeff");
        assert!(scan_staging(&root, Duration::ZERO, 1).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
