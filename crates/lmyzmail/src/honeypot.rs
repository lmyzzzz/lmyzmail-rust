use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    fs::{self, File},
    future::Future,
    io::{self, Read, Write},
    net::IpAddr,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use deadpool_postgres::{Object, Pool};
use getrandom::fill as fill_random;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, SubjectAlternativeName},
    },
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{Instant, sleep, timeout_at},
};
use tokio_postgres::{CancelToken, NoTls};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{
    bounded_blocking::{BoundedBlockingPool, SubmitError},
    config::{HoneypotConfig, RuntimeConfig},
    durability::{fsync, sync_all},
};

const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const DATABASE_CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);
const CERTIFICATE_VALIDITY_SECONDS: i64 = 3650 * 24 * 60 * 60;
const MAX_CONSECUTIVE_ACCEPT_ERRORS: usize = 8;
const READ_CHUNK_BYTES: usize = 4096;
const TLS_READ_CHUNK_BYTES: usize = 8192;
const MAX_QUEUED_OVERFLOW_DISCARD_BYTES: usize = 64 * 1024;
const JOURNAL_SCHEMA_VERSION: u64 = 1;
const JOURNAL_CAPACITY: usize = 4096;
const JOURNAL_RECORD_MAX_BYTES: usize = 4096;
const JOURNAL_REPLAY_BATCH: usize = 64;
const JOURNAL_REPLAY_INTERVAL: Duration = Duration::from_secs(1);
const JOURNAL_BLOCKING_WORKERS: usize = 4;
const JOURNAL_BLOCKING_QUEUE: usize = 64;
const JOURNAL_DIRECTORY: &str = "honeypot-replay";
const JOURNAL_NAMESPACE_DIRECTORY: &str = ".lmyzmail";
// PostgreSQL's `timestamp without time zone` range is much wider, but this
// bound keeps journal replay inside the range accepted by every supported
// PostgreSQL version and makes malformed local files fail closed.
const MAX_JOURNAL_TIMESTAMP_MILLIS: i64 = 253_402_300_799_999;
const RECEIPT_SCHEMA_LOCK: i64 = 0x4c4d_595a_4850_4f54;
const ASSET_SCHEMA_VERSION: u64 = 1;
const FROZEN_JAVA_COMMIT: &str = "5dac2ab2922c30c726c4a83d7626c95ad4e231c8";

const REQUIRED_ASSETS: &[&str] = &[
    "ftp",
    "imap",
    "memcached",
    "minecraft_legacy",
    "minecraft_modern",
    "mongodb",
    "mysql",
    "pop3",
    "postgresql",
    "redis",
    "smtp",
    "socks4",
    "socks5",
    "ssh",
    "unknown",
    "zabbix_binary",
    "zabbix_text",
    "http_0",
    "http_1",
    "http_2",
    "http_3",
    "mysql_greeting_normalized",
    "smtp_banner",
    "ssh_banner",
    "ftp_banner",
    "pop3_banner",
    "imap_banner",
    "vnc_banner",
    "rdp_negotiation",
    "rdp_disconnect",
    "vnc_security_types",
    "vnc_challenge",
    "vnc_security_result",
    "vnc_server_init",
];

#[derive(Debug, Deserialize)]
struct AssetManifest {
    schema_version: u64,
    provenance: AssetProvenance,
    assets: HashMap<String, EncodedAsset>,
}

#[derive(Debug, Deserialize)]
struct AssetProvenance {
    frozen_java_commit: String,
}

#[derive(Debug, Deserialize)]
struct EncodedAsset {
    encoding: String,
    base64: String,
    length: usize,
    sha256: String,
}

#[derive(Debug)]
struct HoneypotAssets {
    values: HashMap<String, Arc<[u8]>>,
    mysql_greeting: Arc<[u8]>,
}

impl HoneypotAssets {
    fn load() -> io::Result<Self> {
        let manifest: AssetManifest = serde_json::from_str(include_str!("honeypot_assets.json"))
            .map_err(|error| {
                invalid_data(format!("honeypot asset manifest is invalid: {error}"))
            })?;
        if manifest.schema_version != ASSET_SCHEMA_VERSION {
            return Err(invalid_data(format!(
                "unsupported honeypot asset schema {}",
                manifest.schema_version
            )));
        }
        if manifest.provenance.frozen_java_commit != FROZEN_JAVA_COMMIT {
            return Err(invalid_data(
                "honeypot assets are not bound to the frozen Java oracle",
            ));
        }

        let mut values = HashMap::with_capacity(manifest.assets.len());
        for (name, encoded) in manifest.assets {
            if encoded.encoding != "base64" {
                return Err(invalid_data(format!(
                    "honeypot asset {name} has unsupported encoding {}",
                    encoded.encoding
                )));
            }
            let value = BASE64.decode(encoded.base64.as_bytes()).map_err(|error| {
                invalid_data(format!(
                    "honeypot asset {name} is not valid base64: {error}"
                ))
            })?;
            if value.len() != encoded.length {
                return Err(invalid_data(format!(
                    "honeypot asset {name} length mismatch: expected {}, got {}",
                    encoded.length,
                    value.len()
                )));
            }
            let digest = hex_lower(&Sha256::digest(&value));
            if !digest.eq_ignore_ascii_case(&encoded.sha256) {
                return Err(invalid_data(format!(
                    "honeypot asset {name} SHA-256 mismatch"
                )));
            }
            values.insert(name, Arc::<[u8]>::from(value));
        }
        for required in REQUIRED_ASSETS {
            if !values.contains_key(*required) {
                return Err(invalid_data(format!(
                    "honeypot asset manifest is missing {required}"
                )));
            }
        }
        let mysql_greeting = Arc::from(randomize_mysql_greeting(
            values
                .get("mysql_greeting_normalized")
                .expect("required MySQL greeting asset is present"),
        )?);
        Ok(Self {
            values,
            mysql_greeting,
        })
    }

    fn get(&self, name: &str) -> io::Result<&[u8]> {
        self.values
            .get(name)
            .map(AsRef::as_ref)
            .ok_or_else(|| invalid_data(format!("honeypot asset {name} is unavailable")))
    }

    fn random_http(&self) -> io::Result<&[u8]> {
        let mut random = [0_u8; 1];
        fill_random(&mut random).map_err(io::Error::other)?;
        self.get(&format!("http_{}", random[0] & 3))
    }

    fn mysql_greeting(&self) -> &[u8] {
        &self.mysql_greeting
    }
}

fn randomize_mysql_greeting(normalized: &[u8]) -> io::Result<Vec<u8>> {
    if normalized.len() != 103 {
        return Err(invalid_data("normalized MySQL greeting must be 103 bytes"));
    }
    let mut greeting = normalized.to_vec();
    let mut random = [0_u8; 24];
    fill_random(&mut random).map_err(io::Error::other)?;
    let connection_id = random_connection_id(u32::from_le_bytes(
        random[0..4]
            .try_into()
            .expect("four-byte connection id seed"),
    ));
    greeting[37..41].copy_from_slice(&connection_id.to_le_bytes());
    greeting[41..49].copy_from_slice(&random[4..12]);
    greeting[68..80].copy_from_slice(&random[12..24]);
    Ok(greeting)
}

fn random_connection_id(seed: u32) -> u32 {
    seed % 99_999 + 1
}

#[derive(Clone)]
struct HoneypotTls {
    acceptor: TlsAcceptor,
    #[allow(dead_code)]
    certificate_der: Arc<[u8]>,
}

impl HoneypotTls {
    fn generate() -> io::Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(io::Error::other)?;
        let ec_key = EcKey::generate(&group).map_err(io::Error::other)?;
        let private_key = PKey::from_ec_key(ec_key).map_err(io::Error::other)?;

        let mut name = X509NameBuilder::new().map_err(io::Error::other)?;
        name.append_entry_by_nid(
            Nid::COMMONNAME,
            "HONEYPOT TRIGGERED - Your IP Has Been Logged",
        )
        .map_err(io::Error::other)?;
        name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "Skibidi Toilet Security Team")
            .map_err(io::Error::other)?;
        name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Ohio Brainrot Detection Division")
            .map_err(io::Error::other)?;
        name.append_entry_by_nid(Nid::LOCALITYNAME, "Fanum Tax Collection Center")
            .map_err(io::Error::other)?;
        name.append_entry_by_nid(Nid::STATEORPROVINCENAME, "State of Absolute Cringe")
            .map_err(io::Error::other)?;
        name.append_entry_by_nid(Nid::COUNTRYNAME, "JM")
            .map_err(io::Error::other)?;
        let name = name.build();

        let mut builder = X509::builder().map_err(io::Error::other)?;
        builder.set_version(2).map_err(io::Error::other)?;
        let serial = BigNum::from_dec_str("69420")
            .and_then(|number| Asn1Integer::from_bn(&number))
            .map_err(io::Error::other)?;
        builder
            .set_serial_number(&serial)
            .map_err(io::Error::other)?;
        builder.set_subject_name(&name).map_err(io::Error::other)?;
        builder.set_issuer_name(&name).map_err(io::Error::other)?;
        builder.set_pubkey(&private_key).map_err(io::Error::other)?;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let not_before_unix = i64::try_from(now_unix.as_secs()).map_err(io::Error::other)?;
        let not_after_unix = not_before_unix
            .checked_add(CERTIFICATE_VALIDITY_SECONDS)
            .ok_or_else(|| io::Error::other("honeypot certificate expiry overflow"))?;
        let not_before = Asn1Time::from_unix(not_before_unix).map_err(io::Error::other)?;
        let not_after = Asn1Time::from_unix(not_after_unix).map_err(io::Error::other)?;
        builder
            .set_not_before(&not_before)
            .map_err(io::Error::other)?;
        builder
            .set_not_after(&not_after)
            .map_err(io::Error::other)?;
        builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .build()
                    .map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
        let mut san = SubjectAlternativeName::new();
        for name in [
            "skibidi.toilet.honeypot.hit.your.ip.has.been.logged",
            "skibidi.dop.dop.yes.yes",
            "nice.try.script.kiddie",
            "go.away.muppet",
            "L-plus-ratio.fanum.taxed",
            "rdp.honeypot.trap",
            "not.a.real.server",
        ] {
            san.dns(name);
        }
        let san = san
            .build(&builder.x509v3_context(None, None))
            .map_err(io::Error::other)?;
        builder.append_extension(san).map_err(io::Error::other)?;
        builder
            .sign(&private_key, MessageDigest::sha256())
            .map_err(io::Error::other)?;
        let certificate = builder.build();
        let certificate_der = certificate.to_der().map_err(io::Error::other)?;
        let private_key_der = private_key
            .private_key_to_pkcs8()
            .map_err(io::Error::other)?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der)),
            )
            .map_err(io::Error::other)?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            certificate_der: Arc::from(certificate_der),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEvent {
    schema_version: u64,
    event_id: String,
    observed_at_millis: i64,
    ip_address: String,
    metadata: String,
}

impl JournalEvent {
    fn new(peer_ip: IpAddr, metadata: String) -> io::Result<Self> {
        let observed_at_millis = Utc::now().timestamp_millis();
        let mut random = [0_u8; 32];
        fill_random(&mut random).map_err(io::Error::other)?;
        random[..8].copy_from_slice(&(observed_at_millis as u64).to_be_bytes());
        Ok(Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            event_id: hex_lower(&random),
            observed_at_millis,
            ip_address: peer_ip.to_string(),
            metadata,
        })
    }

    fn validate(&self) -> io::Result<()> {
        if self.schema_version != JOURNAL_SCHEMA_VERSION
            || !valid_event_id(&self.event_id)
            || self.observed_at_millis <= 0
            || self.observed_at_millis > MAX_JOURNAL_TIMESTAMP_MILLIS
            || self.metadata.is_empty()
            || self.metadata.len() > 1024
            || self.metadata.contains('\0')
        {
            return Err(invalid_data("invalid honeypot journal event"));
        }
        let ip_address: IpAddr = self
            .ip_address
            .parse()
            .map_err(|_| invalid_data("honeypot journal contains an invalid IP address"))?;
        if is_exact_localhost(ip_address) {
            return Err(invalid_data(
                "honeypot journal must not persist an exact localhost address",
            ));
        }
        let event_timestamp = u64::from_str_radix(&self.event_id[..16], 16)
            .map_err(|_| invalid_data("honeypot journal event ID has an invalid timestamp"))?;
        if event_timestamp != self.observed_at_millis as u64 {
            return Err(invalid_data(
                "honeypot journal event ID timestamp does not match observed_at_millis",
            ));
        }
        Ok(())
    }

    fn file_name(&self) -> String {
        format!("{}.json", self.event_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalEntryState {
    Writing,
    Ready,
    InFlight,
}

#[derive(Debug)]
struct JournalState {
    capacity: usize,
    entries: BTreeMap<String, JournalEntryState>,
}

struct HoneypotJournal {
    directory: Arc<std::os::fd::OwnedFd>,
    blocking: Arc<BoundedBlockingPool>,
    state: StdMutex<JournalState>,
}

impl HoneypotJournal {
    async fn open(maildir: &Path) -> io::Result<Arc<Self>> {
        Self::open_with_capacity(maildir, JOURNAL_CAPACITY).await
    }

    async fn open_with_capacity(maildir: &Path, capacity: usize) -> io::Result<Arc<Self>> {
        if capacity == 0 || capacity > JOURNAL_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "honeypot journal capacity is outside its hard bound",
            ));
        }
        let blocking = Arc::new(BoundedBlockingPool::new(
            "lmyzmail-honeypot-journal",
            JOURNAL_BLOCKING_WORKERS,
            JOURNAL_BLOCKING_QUEUE,
        )?);
        let maildir = maildir.to_path_buf();
        let (directory, entries) = submit_journal_work(&blocking, move || {
            initialize_journal_directory(&maildir, capacity)
        })
        .await?;
        Ok(Arc::new(Self {
            directory: Arc::new(directory),
            blocking,
            state: StdMutex::new(JournalState { capacity, entries }),
        }))
    }

    async fn enqueue(&self, event: &JournalEvent) -> io::Result<()> {
        event.validate()?;
        let bytes = serde_json::to_vec(event).map_err(io::Error::other)?;
        if bytes.is_empty() || bytes.len() > JOURNAL_RECORD_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "honeypot journal record exceeds its byte bound",
            ));
        }
        let file_name = event.file_name();
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.entries.contains_key(&file_name) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "honeypot journal event ID collision",
                ));
            }
            if state.entries.len() >= state.capacity {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "honeypot replay journal is full",
                ));
            }
            state
                .entries
                .insert(file_name.clone(), JournalEntryState::Writing);
        }

        let directory = Arc::clone(&self.directory);
        let blocking = Arc::clone(&self.blocking);
        let write_name = file_name.clone();
        let outcome = submit_journal_work(&blocking, move || {
            Ok(write_journal_record(&directory, &write_name, &bytes))
        })
        .await;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match outcome {
            Ok(JournalWriteOutcome::Durable) => {
                state.entries.insert(file_name, JournalEntryState::Ready);
                Ok(())
            }
            Ok(JournalWriteOutcome::Failed {
                error,
                retained_state,
            }) => {
                if let Some(retained_state) = retained_state {
                    state.entries.insert(file_name, retained_state);
                } else {
                    state.entries.remove(&file_name);
                }
                Err(error)
            }
            Err(error) => {
                state.entries.insert(file_name, JournalEntryState::Writing);
                Err(error)
            }
        }
    }

    fn claim_batch(&self) -> Vec<String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let names = state
            .entries
            .iter()
            .filter_map(|(name, entry)| {
                (*entry == JournalEntryState::Ready).then_some(name.clone())
            })
            .take(JOURNAL_REPLAY_BATCH)
            .collect::<Vec<_>>();
        for name in &names {
            state
                .entries
                .insert(name.clone(), JournalEntryState::InFlight);
        }
        names
    }

    async fn read_claimed(&self, file_name: &str) -> io::Result<JournalEvent> {
        let directory = Arc::clone(&self.directory);
        let name = file_name.to_owned();
        let blocking = Arc::clone(&self.blocking);
        let bytes =
            submit_journal_work(&blocking, move || read_journal_record(&directory, &name)).await?;
        let event: JournalEvent = serde_json::from_slice(&bytes)
            .map_err(|error| invalid_data(format!("invalid honeypot journal JSON: {error}")))?;
        event.validate()?;
        if event.file_name() != file_name {
            return Err(invalid_data(
                "honeypot journal filename does not match its event ID",
            ));
        }
        Ok(event)
    }

    async fn complete(&self, file_name: &str) -> io::Result<()> {
        let directory = Arc::clone(&self.directory);
        let name = file_name.to_owned();
        let blocking = Arc::clone(&self.blocking);
        submit_journal_work(&blocking, move || remove_journal_record(&directory, &name)).await?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.entries.remove(file_name);
        Ok(())
    }

    fn release(&self, file_name: &str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.entries.get(file_name) == Some(&JournalEntryState::InFlight) {
            state
                .entries
                .insert(file_name.to_owned(), JournalEntryState::Ready);
        }
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .len()
    }
}

struct HoneypotPersistence {
    pool: Pool,
    journal: Arc<HoneypotJournal>,
    schema_ready: AtomicBool,
    schema_lock: Mutex<()>,
}

impl HoneypotPersistence {
    async fn open(maildir: &Path, pool: Pool) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            pool,
            journal: HoneypotJournal::open(maildir).await?,
            schema_ready: AtomicBool::new(false),
            schema_lock: Mutex::new(()),
        }))
    }

    async fn replay(self: Arc<Self>, cancellation: CancellationToken) -> io::Result<()> {
        loop {
            if let Err(error) = self.replay_once(&cancellation).await
                && !cancellation.is_cancelled()
            {
                eprintln!("lmyzmail honeypot replay deferred: {error}");
            }
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                _ = sleep(JOURNAL_REPLAY_INTERVAL) => {}
            }
        }
    }

    async fn replay_once(&self, cancellation: &CancellationToken) -> io::Result<()> {
        let names = self.journal.claim_batch();
        if names.is_empty() {
            return Ok(());
        }
        if let Err(error) = self.ensure_schema(cancellation).await {
            for name in &names {
                self.journal.release(name);
            }
            return Err(persistence_to_io(error));
        }

        for (index, name) in names.iter().enumerate() {
            if cancellation.is_cancelled() {
                for pending in &names[index..] {
                    self.journal.release(pending);
                }
                return Ok(());
            }
            let event = match self.journal.read_claimed(name).await {
                Ok(event) => event,
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    // Invalid JSON or event fields cannot be safely reconciled. Remove only
                    // records proven invalid; transient I/O and permission errors stay queued
                    // for retry so a valid event is never lost due to a temporary fault.
                    match self.journal.complete(name).await {
                        Ok(()) => eprintln!(
                            "lmyzmail honeypot discarded invalid journal record {name}: {error}"
                        ),
                        Err(cleanup_error) => {
                            self.journal.release(name);
                            eprintln!(
                                "lmyzmail honeypot invalid journal record {name} could not be removed: {cleanup_error}"
                            );
                        }
                    }
                    continue;
                }
                Err(error) => {
                    self.journal.release(name);
                    eprintln!("lmyzmail honeypot journal record {name} is invalid: {error}");
                    continue;
                }
            };
            match self.commit_event(&event, cancellation).await {
                Ok(()) => {
                    if let Err(error) = self.journal.complete(name).await {
                        self.journal.release(name);
                        eprintln!(
                            "lmyzmail honeypot journal cleanup for {name} was deferred: {error}"
                        );
                    }
                }
                Err(error) => {
                    self.journal.release(name);
                    for pending in &names[index + 1..] {
                        self.journal.release(pending);
                    }
                    return Err(persistence_to_io(error));
                }
            }
        }
        Ok(())
    }

    async fn ensure_schema(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<(), PersistenceError> {
        if self.schema_ready.load(Ordering::Acquire) {
            return Ok(());
        }
        let _guard = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(PersistenceError::Cancelled),
            guard = self.schema_lock.lock() => guard,
        };
        if self.schema_ready.load(Ordering::Acquire) {
            return Ok(());
        }

        let deadline = Instant::now() + DATABASE_TIMEOUT;
        let client = bounded_pool(deadline, cancellation, self.pool.get()).await?;
        let mut connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let operation_cancellation = cancellation.child_token();
        let commit_started = AtomicBool::new(false);
        let outcome = database_operation(
            deadline,
            &operation_cancellation,
            &cancel_token,
            &commit_started,
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(|error| database_error("begin receipt schema transaction", error))?;
                configure_transaction_deadline(&transaction, deadline).await?;
                transaction
                    .query_one("SELECT pg_advisory_xact_lock($1)", &[&RECEIPT_SCHEMA_LOCK])
                    .await
                    .map_err(|error| database_error("lock receipt schema", error))?;
                transaction
                    .batch_execute(
                        "CREATE TABLE IF NOT EXISTS lmyzmail_honeypot_event_receipt (\
                            event_id VARCHAR(64) PRIMARY KEY,\
                            observed_at TIMESTAMPTZ NOT NULL,\
                            ip_address VARCHAR(45) NOT NULL,\
                            committed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP\
                         )",
                    )
                    .await
                    .map_err(|error| database_error("create receipt schema", error))?;
                start_commit(deadline, &operation_cancellation, &commit_started)?;
                transaction
                    .commit()
                    .await
                    .map_err(|error| commit_error("commit receipt schema", error))?;
                Ok(())
            },
        )
        .await;
        connection.finish(outcome)?;
        self.schema_ready.store(true, Ordering::Release);
        Ok(())
    }

    async fn commit_event(
        &self,
        event: &JournalEvent,
        cancellation: &CancellationToken,
    ) -> Result<(), PersistenceError> {
        let deadline = Instant::now() + DATABASE_TIMEOUT;
        let client = bounded_pool(deadline, cancellation, self.pool.get()).await?;
        let mut connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let operation_cancellation = cancellation.child_token();
        let commit_started = AtomicBool::new(false);
        let outcome = database_operation(
            deadline,
            &operation_cancellation,
            &cancel_token,
            &commit_started,
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(|error| database_error("begin activity transaction", error))?;
                configure_transaction_deadline(&transaction, deadline).await?;
                ensure_active(&operation_cancellation)?;
                let inserted = transaction
                    .query_opt(
                        "INSERT INTO lmyzmail_honeypot_event_receipt (\
                            event_id, observed_at, ip_address\
                         ) VALUES ($1, to_timestamp(($2::bigint)::double precision / 1000.0), $3)\
                         ON CONFLICT (event_id) DO NOTHING \
                         RETURNING event_id",
                        &[
                            &event.event_id,
                            &event.observed_at_millis,
                            &event.ip_address,
                        ],
                    )
                    .await
                    .map_err(|error| database_error("insert event receipt", error))?
                    .is_some();

                if inserted {
                    transaction
                        .execute(
                            "INSERT INTO skibidi_cringe_ip_activity (\
                                timestamp, activity_type, score, ip_address, session_id, response_message, \
                                metadata, helo_name, mail_from, rcpt_to\
                             ) VALUES (to_timestamp(($1::bigint)::double precision / 1000.0), 'HONEYPOT_HIT', 8, $2, NULL, NULL, $3, NULL, NULL, NULL)",
                            &[
                                &event.observed_at_millis,
                                &event.ip_address,
                                &event.metadata,
                            ],
                        )
                        .await
                        .map_err(|error| database_error("insert activity", error))?;
                    transaction
                        .execute(
                            "INSERT INTO skibidi_cringe_ip (\
                                ip_address, total_score, current_score, activity_count, \
                                first_seen_at, last_seen_at, last_decay_at, \
                                self_spoofing_count, open_relay_count, auth_probe_count, \
                                illegal_domain_count, spamhaus_count, http_on_smtp_count, \
                                ssh_on_smtp_count, http_port_scanning_count, honeypot_hit_count, \
                                ssh_bruteforce_count, pps_overlimit_count, syn_flood_count, other_count\
                             ) VALUES (\
                                $1, 8, 8, 1, \
                                to_timestamp(($2::bigint)::double precision / 1000.0), \
                                to_timestamp(($2::bigint)::double precision / 1000.0), \
                                to_timestamp(($2::bigint)::double precision / 1000.0), \
                                0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0\
                             ) ON CONFLICT (ip_address) DO UPDATE SET \
                                total_score = skibidi_cringe_ip.total_score + 8, \
                                current_score = skibidi_cringe_ip.current_score + 8, \
                                activity_count = skibidi_cringe_ip.activity_count + 1, \
                                last_seen_at = GREATEST(skibidi_cringe_ip.last_seen_at, EXCLUDED.last_seen_at), \
                                honeypot_hit_count = COALESCE(skibidi_cringe_ip.honeypot_hit_count, 0) + 1",
                            &[&event.ip_address, &event.observed_at_millis],
                        )
                        .await
                        .map_err(|error| database_error("upsert aggregate", error))?;
                }

                start_commit(deadline, &operation_cancellation, &commit_started)?;
                transaction
                    .commit()
                    .await
                    .map_err(|error| commit_error("commit activity", error))?;
                Ok(())
            },
        )
        .await;
        connection.finish(outcome)
    }
}

async fn submit_journal_work<T, F>(blocking: &Arc<BoundedBlockingPool>, work: F) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    let receiver = blocking.submit(work).map_err(|error| match error {
        SubmitError::Full => io::Error::new(
            io::ErrorKind::WouldBlock,
            "honeypot journal blocking queue is full",
        ),
        SubmitError::Closed => io::Error::new(
            io::ErrorKind::BrokenPipe,
            "honeypot journal blocking pool is closed",
        ),
    })?;
    receiver.await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "honeypot journal worker stopped without a result",
        )
    })?
}

fn initialize_journal_directory(
    maildir: &Path,
    capacity: usize,
) -> io::Result<(std::os::fd::OwnedFd, BTreeMap<String, JournalEntryState>)> {
    use rustix::fs::{
        AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, ResolveFlags, fchmod, flock, fstat,
        open, statat, unlinkat,
    };

    fs::create_dir_all(maildir)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    let maildir_fd = open(maildir, directory_flags, Mode::empty()).map_err(io::Error::from)?;
    let maildir_stat = fstat(&maildir_fd).map_err(io::Error::from)?;
    if FileType::from_raw_mode(maildir_stat.st_mode) != FileType::Directory {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "configured maildir is not a real directory",
        ));
    }

    let namespace_fd = open_or_create_journal_directory(
        &maildir_fd,
        JOURNAL_NAMESPACE_DIRECTORY,
        maildir_stat.st_uid,
        directory_flags,
        resolve,
    )?;
    let namespace_stat = fstat(&namespace_fd).map_err(io::Error::from)?;
    let replay_fd = open_or_create_journal_directory(
        &namespace_fd,
        JOURNAL_DIRECTORY,
        namespace_stat.st_uid,
        directory_flags,
        resolve,
    )?;
    flock(&replay_fd, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("honeypot replay journal is already owned: {error}"),
        )
    })?;
    fchmod(&replay_fd, Mode::RWXU).map_err(io::Error::from)?;
    fsync(&replay_fd).map_err(io::Error::from)?;

    let replay_stat = fstat(&replay_fd).map_err(io::Error::from)?;
    if FileType::from_raw_mode(replay_stat.st_mode) != FileType::Directory
        || replay_stat.st_uid != namespace_stat.st_uid
        || replay_stat.st_mode & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "honeypot replay journal directory has unsafe ownership or permissions",
        ));
    }

    let mut entries = BTreeMap::new();
    let mut removed_temporary = false;
    let mut directory = Dir::read_from(&replay_fd).map_err(io::Error::from)?;
    for entry in &mut directory {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| invalid_data("honeypot journal filename is not UTF-8"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        let (event_id, temporary) = parse_journal_file_name(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("unexpected file in honeypot journal: {name}"),
            )
        })?;
        if !valid_event_id(event_id) {
            return Err(invalid_data("invalid honeypot journal event filename"));
        }
        let stat = statat(&replay_fd, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != replay_stat.st_uid
            || stat.st_mode & 0o777 != 0o600
            || stat.st_size < 0
            || stat.st_size as usize > JOURNAL_RECORD_MAX_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("honeypot journal file has unsafe metadata: {name}"),
            ));
        }
        if temporary {
            unlinkat(&replay_fd, name, AtFlags::empty()).map_err(io::Error::from)?;
            removed_temporary = true;
            continue;
        }
        if entries.len() >= capacity {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "honeypot replay journal exceeds its hard capacity",
            ));
        }
        entries.insert(name.to_owned(), JournalEntryState::Ready);
    }
    if removed_temporary {
        fsync(&replay_fd).map_err(io::Error::from)?;
    }
    Ok((replay_fd, entries))
}

fn open_or_create_journal_directory<Fd: std::os::fd::AsFd>(
    parent: Fd,
    name: &str,
    expected_uid: u32,
    directory_flags: rustix::fs::OFlags,
    resolve: rustix::fs::ResolveFlags,
) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{FileType, Mode, fchmod, fstat, mkdirat, openat2};

    match mkdirat(&parent, name, Mode::RWXU) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(io::Error::from(error)),
    }
    let directory =
        openat2(&parent, name, directory_flags, Mode::empty(), resolve).map_err(io::Error::from)?;
    fchmod(&directory, Mode::RWXU).map_err(io::Error::from)?;
    let stat = fstat(&directory).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != expected_uid
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("honeypot journal directory is unsafe: {name}"),
        ));
    }
    fsync(&parent).map_err(io::Error::from)?;
    Ok(directory)
}

fn write_journal_record(
    directory: &std::os::fd::OwnedFd,
    file_name: &str,
    bytes: &[u8],
) -> JournalWriteOutcome {
    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, fchmod, openat2, renameat_with, unlinkat,
    };

    if parse_journal_file_name(file_name).is_none() || !file_name.ends_with(".json") {
        return JournalWriteOutcome::Failed {
            error: invalid_data("invalid honeypot journal destination name"),
            retained_state: None,
        };
    }
    let temporary_name = format!("{}.tmp", &file_name[..file_name.len() - 5]);
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    let descriptor = match openat2(
        directory,
        &temporary_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        resolve,
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            return JournalWriteOutcome::Failed {
                error: io::Error::from(error),
                retained_state: None,
            };
        }
    };
    if let Err(error) = fchmod(&descriptor, Mode::RUSR | Mode::WUSR) {
        drop(descriptor);
        let cleaned = unlinkat(directory, &temporary_name, AtFlags::empty()).is_ok()
            && fsync(directory).is_ok();
        return JournalWriteOutcome::Failed {
            error: io::Error::from(error),
            retained_state: (!cleaned).then_some(JournalEntryState::Writing),
        };
    }
    let mut file = File::from(descriptor);
    let mut renamed = false;
    let result: io::Result<()> = (|| {
        file.write_all(bytes)?;
        sync_all(&file)?;
        drop(file);
        renameat_with(
            directory,
            &temporary_name,
            directory,
            file_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)?;
        renamed = true;
        fsync(directory).map_err(io::Error::from)
    })();
    match result {
        Ok(()) => JournalWriteOutcome::Durable,
        Err(error) if renamed => JournalWriteOutcome::Failed {
            error,
            retained_state: Some(JournalEntryState::Ready),
        },
        Err(error) => {
            let cleaned = unlinkat(directory, &temporary_name, AtFlags::empty()).is_ok()
                && fsync(directory).is_ok();
            JournalWriteOutcome::Failed {
                error,
                retained_state: (!cleaned).then_some(JournalEntryState::Writing),
            }
        }
    }
}

#[derive(Debug)]
enum JournalWriteOutcome {
    Durable,
    Failed {
        error: io::Error,
        retained_state: Option<JournalEntryState>,
    },
}

fn read_journal_record(directory: &std::os::fd::OwnedFd, file_name: &str) -> io::Result<Vec<u8>> {
    use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, openat2};

    if parse_journal_file_name(file_name).is_none() || !file_name.ends_with(".json") {
        return Err(invalid_data("invalid honeypot journal source name"));
    }
    let descriptor = openat2(
        directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let stat = fstat(&descriptor).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_mode & 0o777 != 0o600
        || stat.st_size <= 0
        || stat.st_size as usize > JOURNAL_RECORD_MAX_BYTES
    {
        return Err(invalid_data("unsafe honeypot journal record metadata"));
    }
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    File::from(descriptor)
        .take(JOURNAL_RECORD_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() != stat.st_size as usize || bytes.len() > JOURNAL_RECORD_MAX_BYTES {
        return Err(invalid_data(
            "honeypot journal record changed while it was read",
        ));
    }
    Ok(bytes)
}

fn remove_journal_record(directory: &std::os::fd::OwnedFd, file_name: &str) -> io::Result<()> {
    use rustix::fs::{
        AtFlags, FileType, Mode, OFlags, ResolveFlags, fstat, openat2, statat, unlinkat,
    };

    if parse_journal_file_name(file_name).is_none() || !file_name.ends_with(".json") {
        return Err(invalid_data("invalid honeypot journal removal name"));
    }
    let descriptor = match openat2(
        directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => {
            fsync(directory).map_err(io::Error::from)?;
            return Ok(());
        }
        Err(error) => return Err(io::Error::from(error)),
    };
    let opened = fstat(&descriptor).map_err(io::Error::from)?;
    let current =
        statat(directory, file_name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        || opened.st_mode & 0o777 != 0o600
        || opened.st_dev != current.st_dev
        || opened.st_ino != current.st_ino
        || FileType::from_raw_mode(current.st_mode) != FileType::RegularFile
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "honeypot journal record changed before removal",
        ));
    }
    unlinkat(directory, file_name, AtFlags::empty()).map_err(io::Error::from)?;
    fsync(directory).map_err(io::Error::from)
}

fn parse_journal_file_name(name: &str) -> Option<(&str, bool)> {
    if let Some(event_id) = name.strip_suffix(".json") {
        return Some((event_id, false));
    }
    name.strip_suffix(".tmp").map(|event_id| (event_id, true))
}

fn valid_event_id(event_id: &str) -> bool {
    event_id.len() == 64
        && event_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct BoundTrap {
    listener: TcpListener,
    config: HoneypotConfig,
}

pub async fn serve_honeypots(
    config: Arc<RuntimeConfig>,
    pool: Pool,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let traps = bind_honeypot_traps(&config).await?;
    serve_bound_honeypots(config, pool, cancellation, traps).await
}

async fn bind_honeypot_traps(config: &RuntimeConfig) -> io::Result<Vec<BoundTrap>> {
    if config.listen.honeypots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "honeypot service requires at least one configured trap",
        ));
    }
    let mut traps = Vec::with_capacity(config.listen.honeypots.len());
    for trap in &config.listen.honeypots {
        let listener = match TcpListener::bind((trap.bind_address.as_str(), trap.port)).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!(
                    "lmyzmail honeypot {} could not bind {}:{}: {error}",
                    trap.label, trap.bind_address, trap.port
                );
                continue;
            }
        };
        traps.push(BoundTrap {
            listener,
            config: trap.clone(),
        });
    }
    if traps.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "none of the configured honeypot traps could bind",
        ));
    }
    Ok(traps)
}

async fn serve_bound_honeypots(
    config: Arc<RuntimeConfig>,
    pool: Pool,
    cancellation: CancellationToken,
    traps: Vec<BoundTrap>,
) -> io::Result<()> {
    let assets = Arc::new(HoneypotAssets::load()?);
    let tls = Arc::new(HoneypotTls::generate()?);
    let persistence = HoneypotPersistence::open(&config.maildir, pool).await?;

    let service_cancellation = cancellation.child_token();
    let mut listeners = JoinSet::new();
    let replay_persistence = Arc::clone(&persistence);
    let replay_cancellation = service_cancellation.child_token();
    listeners.spawn(async move { replay_persistence.replay(replay_cancellation).await });
    for trap in traps {
        let assets = Arc::clone(&assets);
        let tls = Arc::clone(&tls);
        let persistence = Arc::clone(&persistence);
        let limits = ConnectionLimits::from_config(&config);
        let child_cancellation = service_cancellation.child_token();
        listeners.spawn(async move {
            serve_trap(trap, persistence, assets, tls, limits, child_cancellation).await
        });
    }

    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => Ok(()),
        joined = listeners.join_next() => match joined {
            Some(Ok(Ok(()))) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "honeypot listener stopped before cancellation",
            )),
            Some(Ok(Err(error))) => Err(error),
            Some(Err(error)) => Err(io::Error::other(format!("honeypot listener panicked: {error}"))),
            None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "all honeypot listeners stopped")),
        },
    };

    service_cancellation.cancel();
    let shutdown_deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    while !listeners.is_empty() {
        match timeout_at(shutdown_deadline, listeners.join_next()).await {
            Ok(Some(Ok(Ok(())))) => {}
            Ok(Some(Ok(Err(error)))) if result.is_ok() => {
                eprintln!("lmyzmail honeypot listener shutdown failed: {error}");
            }
            Ok(Some(Err(error))) => {
                eprintln!("lmyzmail honeypot listener panicked during shutdown: {error}");
            }
            Ok(None) => break,
            Err(_) => {
                listeners.abort_all();
                while listeners.join_next().await.is_some() {}
                break;
            }
            _ => {}
        }
    }
    result
}

#[derive(Clone, Copy)]
struct ConnectionLimits {
    initial_delay: Duration,
    post_banner_timeout: Duration,
    max_connections: usize,
    max_read_bytes: usize,
}

impl ConnectionLimits {
    fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            initial_delay: Duration::from_millis(config.limits.honeypot_initial_delay_ms),
            post_banner_timeout: Duration::from_millis(
                config.limits.honeypot_post_banner_timeout_ms,
            ),
            max_connections: config.limits.max_honeypot_connections_per_trap,
            max_read_bytes: config.limits.max_honeypot_read_bytes,
        }
    }
}

async fn serve_trap(
    trap: BoundTrap,
    persistence: Arc<HoneypotPersistence>,
    assets: Arc<HoneypotAssets>,
    tls: Arc<HoneypotTls>,
    limits: ConnectionLimits,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let mut connections = JoinSet::new();
    let mut consecutive_accept_errors = 0_usize;

    loop {
        while let Some(joined) = connections.try_join_next() {
            report_connection_result(joined);
        }

        let accepted = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            accepted = trap.listener.accept() => accepted,
        };
        let (mut stream, peer) = match accepted {
            Ok(value) => {
                consecutive_accept_errors = 0;
                value
            }
            Err(error) => {
                consecutive_accept_errors += 1;
                if consecutive_accept_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                    return Err(io::Error::new(
                        error.kind(),
                        format!(
                            "honeypot {} accept failed repeatedly: {error}",
                            trap.config.label
                        ),
                    ));
                }
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    _ = sleep(ACCEPT_RETRY_DELAY) => {}
                }
                continue;
            }
        };

        let permit = match Arc::clone(&permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let _ = stream.shutdown().await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let persistence = Arc::clone(&persistence);
        let assets = Arc::clone(&assets);
        let tls = Arc::clone(&tls);
        let trap_config = trap.config.clone();
        let connection_cancellation = cancellation.child_token();
        connections.spawn(async move {
            serve_connection(
                stream,
                peer.ip(),
                trap_config,
                persistence,
                assets,
                tls,
                limits,
                permit,
                connection_cancellation,
            )
            .await
        });
    }

    cancellation.cancel();
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    while !connections.is_empty() {
        match timeout_at(deadline, connections.join_next()).await {
            Ok(Some(joined)) => report_connection_result(joined),
            Ok(None) => break,
            Err(_) => {
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                break;
            }
        }
    }
    Ok(())
}

fn report_connection_result(joined: Result<io::Result<()>, tokio::task::JoinError>) {
    match joined {
        Ok(Ok(())) => {}
        Ok(Err(error))
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
            ) => {}
        Ok(Err(error)) => eprintln!("lmyzmail honeypot connection failed: {error}"),
        Err(error) => eprintln!("lmyzmail honeypot connection task panicked: {error}"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Protocol {
    Tls,
    Socks5,
    Socks4,
    Rdp,
    ZabbixBinary,
    MongoDb,
    PostgreSql,
    MySql,
    Minecraft,
    Http,
    Redis,
    Memcached,
    Ssh,
    Vnc,
    Smtp,
    Ftp,
    Pop3,
    Imap,
    ZabbixText,
    Unknown,
}

impl Protocol {
    fn activity_name(self) -> &'static str {
        match self {
            Self::Tls => "TLS",
            Self::Socks5 => "SOCKS5",
            Self::Socks4 => "SOCKS4",
            Self::Rdp => "RDP",
            Self::ZabbixBinary | Self::ZabbixText => "ZABBIX",
            Self::MongoDb => "MONGODB",
            Self::PostgreSql => "POSTGRESQL",
            Self::MySql => "MYSQL",
            Self::Minecraft => "MINECRAFT",
            Self::Http => "HTTP",
            Self::Redis => "REDIS",
            Self::Memcached => "MEMCACHED",
            Self::Ssh => "SSH",
            Self::Vnc => "VNC",
            Self::Smtp => "SMTP",
            Self::Ftp => "FTP",
            Self::Pop3 => "POP3",
            Self::Imap => "IMAP",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Detection {
    protocol: Protocol,
    summary: String,
    minecraft_legacy: bool,
}

impl Detection {
    fn new(protocol: Protocol, summary: impl Into<String>) -> Self {
        Self {
            protocol,
            summary: summary.into(),
            minecraft_legacy: false,
        }
    }

    fn minecraft(summary: impl Into<String>, legacy: bool) -> Self {
        Self {
            protocol: Protocol::Minecraft,
            summary: summary.into(),
            minecraft_legacy: legacy,
        }
    }

    fn unknown(data: &[u8]) -> Self {
        Self::new(Protocol::Unknown, unknown_summary(data))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DetectionDecision {
    NeedMore,
    Detected(Detection),
}

#[derive(Debug)]
enum InitialRead {
    Silent,
    Disconnected,
    Data {
        detection: Detection,
        buffered: Vec<u8>,
        consumed: usize,
    },
}

#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    mut stream: TcpStream,
    peer_ip: IpAddr,
    trap: HoneypotConfig,
    persistence: Arc<HoneypotPersistence>,
    assets: Arc<HoneypotAssets>,
    tls: Arc<HoneypotTls>,
    limits: ConnectionLimits,
    _permit: OwnedSemaphorePermit,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let initial_deadline = Instant::now() + limits.initial_delay;
    match read_initial(
        &mut stream,
        limits.max_read_bytes,
        initial_deadline,
        limits.post_banner_timeout,
        &cancellation,
    )
    .await?
    {
        InitialRead::Disconnected => Ok(()),
        InitialRead::Silent => {
            let Some(banner_name) = server_banner_asset(&trap.protocol) else {
                record_activity(
                    &persistence,
                    peer_ip,
                    &trap,
                    &Detection::new(Protocol::Unknown, "Silent connection (no data sent)"),
                    "PASSIVE_TIMEOUT",
                    &cancellation,
                )
                .await?;
                return Ok(());
            };

            let banner = if banner_name == "mysql_greeting_normalized" {
                assets.mysql_greeting()
            } else {
                assets.get(banner_name)?
            };
            write_with_deadline(
                &mut stream,
                banner,
                Instant::now() + limits.post_banner_timeout,
                &cancellation,
            )
            .await?;

            let post_deadline = Instant::now() + limits.post_banner_timeout;
            match read_initial(
                &mut stream,
                limits.max_read_bytes,
                post_deadline,
                limits.post_banner_timeout,
                &cancellation,
            )
            .await?
            {
                InitialRead::Disconnected => Ok(()),
                InitialRead::Silent => {
                    record_activity(
                        &persistence,
                        peer_ip,
                        &trap,
                        &Detection::new(
                            protocol_from_server_name(&trap.protocol),
                            format!("Received {} banner but sent no response", trap.protocol),
                        ),
                        "BANNER_IGNORED",
                        &cancellation,
                    )
                    .await
                }
                InitialRead::Data {
                    detection,
                    buffered,
                    consumed,
                } => {
                    handle_detection(
                        stream,
                        peer_ip,
                        trap,
                        persistence,
                        assets,
                        tls,
                        limits,
                        detection,
                        buffered,
                        consumed,
                        "AFTER_BANNER",
                        cancellation,
                    )
                    .await
                }
            }
        }
        InitialRead::Data {
            detection,
            buffered,
            consumed,
        } => {
            handle_detection(
                stream,
                peer_ip,
                trap,
                persistence,
                assets,
                tls,
                limits,
                detection,
                buffered,
                consumed,
                "CLIENT_FIRST",
                cancellation,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_detection(
    mut stream: TcpStream,
    peer_ip: IpAddr,
    trap: HoneypotConfig,
    persistence: Arc<HoneypotPersistence>,
    assets: Arc<HoneypotAssets>,
    tls: Arc<HoneypotTls>,
    limits: ConnectionLimits,
    detection: Detection,
    buffered: Vec<u8>,
    consumed: usize,
    direction: &'static str,
    cancellation: CancellationToken,
) -> io::Result<()> {
    if detection.protocol == Protocol::Unknown && consumed == limits.max_read_bytes {
        discard_queued_overflow(&mut stream);
    }
    record_activity(
        &persistence,
        peer_ip,
        &trap,
        &detection,
        direction,
        &cancellation,
    )
    .await?;

    match detection.protocol {
        Protocol::Tls => {
            let remaining = limits.max_read_bytes.saturating_sub(consumed);
            handle_tls(
                BudgetedStream::with_prefix(stream, buffered, remaining),
                &assets,
                &tls,
                limits.post_banner_timeout,
                &cancellation,
            )
            .await
        }
        Protocol::Rdp => {
            let remaining = limits.max_read_bytes.saturating_sub(consumed);
            let tls_prefix = rdp_tls_prefix(&buffered)?.to_vec();
            handle_rdp(
                stream,
                tls_prefix,
                remaining,
                &assets,
                &tls,
                limits.post_banner_timeout,
                &cancellation,
            )
            .await
        }
        Protocol::Vnc => {
            let remaining = limits.max_read_bytes.saturating_sub(consumed);
            handle_vnc(
                stream,
                buffered,
                remaining,
                &assets,
                limits.post_banner_timeout,
                &cancellation,
            )
            .await
        }
        Protocol::Http => {
            let response = assets.random_http()?;
            write_with_deadline(
                &mut stream,
                response,
                Instant::now() + limits.post_banner_timeout,
                &cancellation,
            )
            .await
        }
        _ => {
            let name = response_asset(&detection);
            write_with_deadline(
                &mut stream,
                assets.get(name)?,
                Instant::now() + limits.post_banner_timeout,
                &cancellation,
            )
            .await
        }
    }
}

fn discard_queued_overflow(stream: &mut TcpStream) {
    // Linux resets a close with unread inbound data. Discard only bytes already queued in the
    // socket, under a separate hard cap; none of them enter the protocol parser or its budget.
    let mut discarded = 0_usize;
    let mut buffer = [0_u8; READ_CHUNK_BYTES];
    while discarded < MAX_QUEUED_OVERFLOW_DISCARD_BYTES {
        let remaining = MAX_QUEUED_OVERFLOW_DISCARD_BYTES - discarded;
        let read_limit = remaining.min(buffer.len());
        match stream.try_read(&mut buffer[..read_limit]) {
            Ok(0) => break,
            Ok(read) => discarded += read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

fn server_banner_asset(protocol: &str) -> Option<&'static str> {
    match protocol {
        "SMTP" => Some("smtp_banner"),
        "SSH" => Some("ssh_banner"),
        "FTP" => Some("ftp_banner"),
        "MYSQL" => Some("mysql_greeting_normalized"),
        "POP3" => Some("pop3_banner"),
        "IMAP" => Some("imap_banner"),
        "VNC" => Some("vnc_banner"),
        _ => None,
    }
}

fn protocol_from_server_name(protocol: &str) -> Protocol {
    match protocol {
        "SMTP" => Protocol::Smtp,
        "SSH" => Protocol::Ssh,
        "FTP" => Protocol::Ftp,
        "MYSQL" => Protocol::MySql,
        "POP3" => Protocol::Pop3,
        "IMAP" => Protocol::Imap,
        "VNC" => Protocol::Vnc,
        _ => Protocol::Unknown,
    }
}

fn response_asset(detection: &Detection) -> &'static str {
    match detection.protocol {
        Protocol::Socks5 => "socks5",
        Protocol::Socks4 => "socks4",
        Protocol::ZabbixBinary => "zabbix_binary",
        Protocol::MongoDb => "mongodb",
        Protocol::PostgreSql => "postgresql",
        Protocol::MySql => "mysql",
        Protocol::Minecraft if detection.minecraft_legacy => "minecraft_legacy",
        Protocol::Minecraft => "minecraft_modern",
        Protocol::Redis => "redis",
        Protocol::Memcached => "memcached",
        Protocol::Ssh => "ssh",
        Protocol::Smtp => "smtp",
        Protocol::Ftp => "ftp",
        Protocol::Pop3 => "pop3",
        Protocol::Imap => "imap",
        Protocol::ZabbixText => "zabbix_text",
        _ => "unknown",
    }
}

async fn read_initial(
    stream: &mut TcpStream,
    max_bytes: usize,
    first_byte_deadline: Instant,
    partial_input_timeout: Duration,
    cancellation: &CancellationToken,
) -> io::Result<InitialRead> {
    let mut buffered = Vec::with_capacity(max_bytes.min(READ_CHUNK_BYTES));
    let mut read_deadline = first_byte_deadline;
    loop {
        if !buffered.is_empty()
            && let DetectionDecision::Detected(detection) = detect_incremental(&buffered, false)
        {
            let consumed = buffered.len();
            return Ok(InitialRead::Data {
                detection,
                buffered,
                consumed,
            });
        }
        if buffered.len() == max_bytes {
            return Ok(InitialRead::Data {
                detection: force_detection(&buffered),
                consumed: buffered.len(),
                buffered,
            });
        }

        let mut chunk = [0_u8; READ_CHUNK_BYTES];
        let capacity = (max_bytes - buffered.len()).min(chunk.len());
        let read = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(cancelled()),
            read = timeout_at(read_deadline, stream.read(&mut chunk[..capacity])) => match read {
                Ok(read) => read?,
                Err(_) if buffered.is_empty() => return Ok(InitialRead::Silent),
                Err(_) => {
                    return Ok(InitialRead::Data {
                        detection: force_detection(&buffered),
                        consumed: buffered.len(),
                        buffered,
                    });
                }
            },
        };
        if read == 0 {
            if buffered.is_empty() {
                return Ok(InitialRead::Disconnected);
            }
            return Ok(InitialRead::Data {
                detection: force_detection(&buffered),
                consumed: buffered.len(),
                buffered,
            });
        }
        if buffered.is_empty() {
            read_deadline = Instant::now() + partial_input_timeout;
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
}

fn force_detection(data: &[u8]) -> Detection {
    match detect_incremental(data, true) {
        DetectionDecision::Detected(detection) => detection,
        DetectionDecision::NeedMore => Detection::unknown(data),
    }
}

fn detect_incremental(data: &[u8], force: bool) -> DetectionDecision {
    if data.is_empty() {
        return DetectionDecision::NeedMore;
    }

    let mut binary_maybe = false;

    if data[0] == 0x16 {
        if data.len() < 3 {
            binary_maybe = true;
        } else if data[1] == 0x03 && data[2] <= 0x04 {
            let summary = if data.len() >= 6 && data[5] == 0x01 {
                format!("TLS ClientHello (version 0x{:02X}{:02X})", data[1], data[2])
            } else {
                "TLS Handshake".to_owned()
            };
            return detected(Protocol::Tls, summary);
        }
    }

    if data[0] == 0x05 {
        if data.len() < 2 {
            binary_maybe = true;
        } else if data[1] > 0 {
            return detected(
                Protocol::Socks5,
                if data.len() >= 2 + usize::from(data[1]) {
                    format!("SOCKS5 auth methods={}", data[1])
                } else {
                    "SOCKS5 handshake".to_owned()
                },
            );
        }
    }

    if data[0] == 0x04 {
        if data.len() < 2 {
            binary_maybe = true;
        } else if matches!(data[1], 0x01 | 0x02) {
            return detected(
                Protocol::Socks4,
                if data[1] == 1 {
                    "SOCKS4 CONNECT"
                } else {
                    "SOCKS4 BIND"
                },
            );
        }
    }

    if data[0] == 0x03 {
        if data.len() < 4 {
            binary_maybe = data.len() == 1 || data.get(1) == Some(&0);
        } else if data[1] == 0 {
            let packet_length = usize::from(u16::from_be_bytes([data[2], data[3]]));
            if (11..=512).contains(&packet_length) && data.len() < packet_length {
                binary_maybe = true;
            } else if (11..=512).contains(&packet_length) && data[5] == 0xe0 {
                return detected(
                    Protocol::Rdp,
                    format!(
                        "RDP Connection Request (TPKT len={packet_length}, X.224 len={})",
                        data[4]
                    ),
                );
            }
        }
    }

    const ZABBIX_HEADER: &[u8] = b"ZBXD\x01";
    if data.len() < ZABBIX_HEADER.len() && ZABBIX_HEADER.starts_with(data) {
        binary_maybe = true;
    } else if data.starts_with(ZABBIX_HEADER) {
        let summary = if data.len() >= 13 {
            let data_length =
                u64::from_le_bytes(data[5..13].try_into().expect("eight-byte length"));
            format!("Zabbix Request (len={data_length}): ")
        } else {
            "Zabbix Request (ZBXD header)".to_owned()
        };
        return detected(Protocol::ZabbixBinary, summary);
    }

    if data.len() >= 16 {
        let message_length = i32::from_le_bytes(data[0..4].try_into().expect("four-byte length"));
        let opcode = i32::from_le_bytes(data[12..16].try_into().expect("four-byte opcode"));
        if message_length > 16
            && message_length < 48 * 1024 * 1024
            && matches!(opcode, 2001 | 2002 | 2004 | 2005 | 2006 | 2007 | 2013)
        {
            return detected(
                Protocol::MongoDb,
                format!("MongoDB opCode={opcode}, len={message_length}"),
            );
        }
    } else if data.len() >= 4 {
        let message_length = i32::from_le_bytes(data[0..4].try_into().expect("four-byte length"));
        if message_length > 16 && message_length < 48 * 1024 * 1024 {
            binary_maybe = true;
        }
    }

    if data.len() >= 8 {
        let message_length = i32::from_be_bytes(data[0..4].try_into().expect("four-byte length"));
        let protocol = i32::from_be_bytes(data[4..8].try_into().expect("four-byte protocol"));
        if (8..10_000).contains(&message_length) && protocol == 0x0003_0000 {
            return detected(Protocol::PostgreSql, "PostgreSQL StartupMessage v3.0");
        }
        if message_length == 8 && protocol == 80_877_103 {
            return detected(Protocol::PostgreSql, "PostgreSQL SSLRequest");
        }
        if message_length == 16 && protocol == 80_877_102 {
            return detected(Protocol::PostgreSql, "PostgreSQL CancelRequest");
        }
    } else if data[0] == 0 {
        binary_maybe = true;
    }

    if data.len() >= 4 {
        let packet_length =
            usize::from(data[0]) | (usize::from(data[1]) << 8) | (usize::from(data[2]) << 16);
        if packet_length > 0 && packet_length < 65_535 && data[3] == 1 {
            if data.len() < 4 + packet_length {
                binary_maybe = true;
            } else if packet_length >= 32 {
                let capabilities = u32::from_le_bytes(
                    data[4..8]
                        .try_into()
                        .expect("four-byte MySQL capability flags"),
                );
                if capabilities & 1 != 0 {
                    return detected(
                        Protocol::MySql,
                        format!("MySQL AuthResponse caps=0x{capabilities:08X}"),
                    );
                }
            }
        }
    }

    if data[0] == 0xfe {
        if data.len() == 1 && !force {
            return DetectionDecision::NeedMore;
        }
        if data.get(1) == Some(&1) {
            let summary = if data.get(2) == Some(&0xfa) {
                "Minecraft Legacy Ping 1.6+ (FE 01 FA)"
            } else {
                "Minecraft Legacy Ping 1.4-1.5 (FE 01)"
            };
            return DetectionDecision::Detected(Detection::minecraft(summary, true));
        }
        return DetectionDecision::Detected(Detection::minecraft(
            "Minecraft Legacy Ping Beta (FE)",
            true,
        ));
    }

    match detect_minecraft(data) {
        MinecraftDetection::Detected(summary) => {
            return DetectionDecision::Detected(Detection::minecraft(summary, false));
        }
        MinecraftDetection::NeedMore => binary_maybe = true,
        MinecraftDetection::NoMatch => {}
    }

    if let Some(detection) = detect_text(data, force) {
        return DetectionDecision::Detected(detection);
    }
    if force {
        return DetectionDecision::Detected(Detection::unknown(data));
    }
    if binary_maybe || data.len() < 16 || is_probably_text(data) {
        DetectionDecision::NeedMore
    } else {
        DetectionDecision::Detected(Detection::unknown(data))
    }
}

fn detected(protocol: Protocol, summary: impl Into<String>) -> DetectionDecision {
    DetectionDecision::Detected(Detection::new(protocol, summary))
}

enum MinecraftDetection {
    NeedMore,
    NoMatch,
    Detected(String),
}

fn detect_minecraft(data: &[u8]) -> MinecraftDetection {
    let (packet_length, mut offset) = match read_varint(data, 0) {
        VarIntRead::Complete(value, bytes) => (value, bytes),
        VarIntRead::Incomplete => return MinecraftDetection::NeedMore,
        VarIntRead::Invalid => return MinecraftDetection::NoMatch,
    };
    if !(6..=300).contains(&packet_length) {
        return MinecraftDetection::NoMatch;
    }
    let packet_length = packet_length as usize;
    if data.len() < offset + packet_length {
        return MinecraftDetection::NeedMore;
    }
    let end = offset + packet_length;
    let (packet_id, bytes) = match read_varint(&data[..end], offset) {
        VarIntRead::Complete(value, bytes) => (value, bytes),
        _ => return MinecraftDetection::NoMatch,
    };
    if packet_id != 0 {
        return MinecraftDetection::NoMatch;
    }
    offset += bytes;
    let (protocol_version, bytes) = match read_varint(&data[..end], offset) {
        VarIntRead::Complete(value, bytes) => (value, bytes),
        _ => return MinecraftDetection::NoMatch,
    };
    if protocol_version != -1 && !(1..=1200).contains(&protocol_version) {
        return MinecraftDetection::NoMatch;
    }
    offset += bytes;
    let (address_length, bytes) = match read_varint(&data[..end], offset) {
        VarIntRead::Complete(value, bytes) => (value, bytes),
        _ => return MinecraftDetection::NoMatch,
    };
    if !(1..=255).contains(&address_length) {
        return MinecraftDetection::NoMatch;
    }
    offset += bytes;
    let address_length = address_length as usize;
    if offset + address_length + 3 > end {
        return MinecraftDetection::NoMatch;
    }
    let address = String::from_utf8_lossy(&data[offset..offset + address_length]);
    offset += address_length;
    let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    let (next_state, _) = match read_varint(&data[..end], offset) {
        VarIntRead::Complete(value, bytes) => (value, bytes),
        _ => return MinecraftDetection::NoMatch,
    };
    if !matches!(next_state, 1 | 2) {
        return MinecraftDetection::NoMatch;
    }
    let state = if next_state == 1 { "Status" } else { "Login" };
    MinecraftDetection::Detected(format!(
        "Minecraft protocol={protocol_version} -> {address}:{port} [{state}]"
    ))
}

enum VarIntRead {
    Complete(i32, usize),
    Incomplete,
    Invalid,
}

fn read_varint(data: &[u8], offset: usize) -> VarIntRead {
    let mut value = 0_u32;
    for index in 0..5 {
        let Some(byte) = data.get(offset + index).copied() else {
            return VarIntRead::Incomplete;
        };
        value |= u32::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return VarIntRead::Complete(value as i32, index + 1);
        }
    }
    VarIntRead::Invalid
}

fn detect_text(data: &[u8], force: bool) -> Option<Detection> {
    if !is_probably_text(data) {
        return None;
    }
    let line_end = data.iter().position(|byte| *byte == b'\n');
    let line_complete = line_end.is_some();
    let end = line_end.unwrap_or(data.len()).min(256);
    let line = String::from_utf8_lossy(&data[..end])
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if line.is_empty() {
        return None;
    }
    let upper = line.to_ascii_uppercase();

    if upper.starts_with("GET ") {
        return Some(Detection::new(Protocol::Http, truncate(&line, 100)));
    }
    if starts_with_any(
        &upper,
        &[
            "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
        ],
    ) {
        return Some(Detection::new(Protocol::Http, truncate(&line, 100)));
    }
    if upper.starts_with('*')
        || starts_with_any(
            &upper,
            &[
                "PING", "INFO", "AUTH ", "COMMAND", "CONFIG ", "DBSIZE", "KEYS ", "SCAN ",
                "CLIENT ",
            ],
        )
    {
        return Some(Detection::new(Protocol::Redis, truncate(&line, 100)));
    }
    if starts_with_any(
        &upper,
        &[
            "GETS ",
            "SET ",
            "ADD ",
            "REPLACE ",
            "DELETE ",
            "STATS",
            "VERSION",
            "FLUSH_ALL",
            "INCR ",
            "DECR ",
        ],
    ) {
        return Some(Detection::new(Protocol::Memcached, truncate(&line, 100)));
    }
    if upper.starts_with("SSH-") {
        return Some(Detection::new(Protocol::Ssh, truncate(&line, 100)));
    }
    if upper.starts_with("RFB ") {
        if data.len() < 12 && !line_complete && !force {
            return None;
        }
        let version = line.get(4..11).unwrap_or("unknown").trim();
        return Some(Detection::new(
            Protocol::Vnc,
            format!("VNC ProtocolVersion (RFB {version})"),
        ));
    }
    if starts_with_any(&upper, &["EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:"]) {
        return Some(Detection::new(Protocol::Smtp, truncate(&line, 100)));
    }
    if starts_with_any(
        &upper,
        &[
            "USER ", "PASS ", "LIST", "RETR ", "STOR ", "PWD", "CWD ", "QUIT",
        ],
    ) {
        return Some(Detection::new(Protocol::Ftp, truncate(&line, 100)));
    }
    if starts_with_any(&upper, &["STAT", "RETR ", "DELE ", "CAPA"]) {
        if upper == "STAT" && !line_complete && !force {
            return None;
        }
        return Some(Detection::new(Protocol::Pop3, truncate(&line, 100)));
    }
    if let Some((tag, command_and_arguments)) = line.split_once(' ')
        && !tag.is_empty()
        && tag.bytes().all(|byte| byte.is_ascii_alphanumeric())
        && starts_with_any(
            command_and_arguments,
            &[
                "LOGIN",
                "SELECT",
                "EXAMINE",
                "LIST",
                "FETCH",
                "LOGOUT",
                "CAPABILITY",
            ],
        )
    {
        return Some(Detection::new(Protocol::Imap, truncate(&line, 100)));
    }
    if starts_with_any(
        &upper,
        &[
            "AGENT.",
            "SYSTEM.",
            "VFS.",
            "NET.",
            "VM.",
            "WEB.",
            "PROC.",
            "LOG.",
            "EVENTLOG.",
            "KERNEL.",
            "SENSOR.",
            "ICMPPING",
        ],
    ) {
        return Some(Detection::new(
            Protocol::ZabbixText,
            format!("Zabbix command: {}", truncate(&line, 80)),
        ));
    }

    if line_complete || force {
        return Some(Detection::new(Protocol::Unknown, truncate(&line, 100)));
    }
    if potential_text_prefix(upper.as_bytes()) || is_probably_text(data) {
        None
    } else {
        Some(Detection::unknown(data))
    }
}

fn starts_with_any(value: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| value.starts_with(prefix))
}

fn potential_text_prefix(value: &[u8]) -> bool {
    const PREFIXES: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
        b"PING",
        b"INFO",
        b"AUTH ",
        b"COMMAND",
        b"CONFIG ",
        b"DBSIZE",
        b"KEYS ",
        b"SCAN ",
        b"CLIENT ",
        b"GETS ",
        b"SET ",
        b"ADD ",
        b"REPLACE ",
        b"STATS",
        b"VERSION",
        b"FLUSH_ALL",
        b"INCR ",
        b"DECR ",
        b"SSH-",
        b"RFB ",
        b"EHLO ",
        b"HELO ",
        b"MAIL FROM:",
        b"RCPT TO:",
        b"USER ",
        b"PASS ",
        b"LIST",
        b"RETR ",
        b"STOR ",
        b"PWD",
        b"CWD ",
        b"QUIT",
        b"STAT",
        b"DELE ",
        b"CAPA",
        b"AGENT.",
        b"SYSTEM.",
        b"VFS.",
        b"NET.",
        b"VM.",
        b"WEB.",
        b"PROC.",
        b"LOG.",
        b"EVENTLOG.",
        b"KERNEL.",
        b"SENSOR.",
        b"ICMPPING",
    ];
    PREFIXES.iter().any(|prefix| prefix.starts_with(value))
}

fn is_probably_text(data: &[u8]) -> bool {
    data.iter()
        .take(256)
        .all(|byte| matches!(*byte, b'\t' | b'\r' | b'\n' | 0x20..=0x7e))
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn unknown_summary(data: &[u8]) -> String {
    if is_probably_text(data) {
        let end = data
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(data.len());
        return truncate(
            String::from_utf8_lossy(&data[..end]).trim_end_matches(['\r', '\n']),
            100,
        );
    }
    let mut value = String::new();
    for (index, byte) in data.iter().take(32).enumerate() {
        if index != 0 {
            value.push(' ');
        }
        use fmt::Write as _;
        let _ = write!(value, "{byte:02X}");
    }
    value
}

async fn handle_tls(
    stream: BudgetedStream,
    assets: &HoneypotAssets,
    tls: &HoneypotTls,
    operation_timeout: Duration,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    let deadline = Instant::now() + operation_timeout;
    let mut stream = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(cancelled()),
        accepted = timeout_at(deadline, tls.acceptor.accept(stream)) => match accepted {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("honeypot TLS handshake failed: {error}"))),
            Err(_) => return Err(timed_out("honeypot TLS handshake")),
        },
    };
    let response = assets.random_http()?;
    write_with_deadline(
        &mut stream,
        response,
        Instant::now() + operation_timeout,
        cancellation,
    )
    .await?;
    shutdown_with_deadline(
        &mut stream,
        Instant::now() + operation_timeout,
        cancellation,
    )
    .await
}

async fn handle_rdp(
    mut stream: TcpStream,
    tls_prefix: Vec<u8>,
    remaining_read_bytes: usize,
    assets: &HoneypotAssets,
    tls: &HoneypotTls,
    operation_timeout: Duration,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    write_with_deadline(
        &mut stream,
        assets.get("rdp_negotiation")?,
        Instant::now() + operation_timeout,
        cancellation,
    )
    .await?;
    let deadline = Instant::now() + operation_timeout;
    let mut stream = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(cancelled()),
        accepted = timeout_at(
            deadline,
            tls.acceptor.accept(BudgetedStream::with_prefix(
                stream,
                tls_prefix,
                remaining_read_bytes,
            )),
        ) => match accepted {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("honeypot RDP TLS handshake failed: {error}"))),
            Err(_) => return Err(timed_out("honeypot RDP TLS handshake")),
        },
    };
    write_with_deadline(
        &mut stream,
        assets.get("rdp_disconnect")?,
        Instant::now() + operation_timeout,
        cancellation,
    )
    .await?;
    shutdown_with_deadline(
        &mut stream,
        Instant::now() + operation_timeout,
        cancellation,
    )
    .await
}

fn rdp_tls_prefix(buffered: &[u8]) -> io::Result<&[u8]> {
    if buffered.len() < 4 || buffered[0] != 3 || buffered[1] != 0 {
        return Err(invalid_data("RDP request does not contain a TPKT header"));
    }
    let request_length = usize::from(u16::from_be_bytes([buffered[2], buffered[3]]));
    if request_length < 11 || request_length > buffered.len() {
        return Err(invalid_data("RDP request has an incomplete TPKT frame"));
    }
    Ok(&buffered[request_length..])
}

async fn handle_vnc(
    stream: TcpStream,
    buffered: Vec<u8>,
    remaining_read_bytes: usize,
    assets: &HoneypotAssets,
    operation_timeout: Duration,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    let mut stream = PhaseReader::new(stream, buffered, remaining_read_bytes);
    let version = stream
        .read_exact(12, Instant::now() + operation_timeout, cancellation)
        .await?;
    if !version.starts_with(b"RFB ") {
        return Err(invalid_data("VNC client version is invalid"));
    }
    write_with_deadline(
        &mut stream.stream,
        assets.get("vnc_security_types")?,
        Instant::now() + operation_timeout,
        cancellation,
    )
    .await?;

    let selection = stream
        .read_exact(1, Instant::now() + operation_timeout, cancellation)
        .await?[0];
    if selection == 2 {
        write_with_deadline(
            &mut stream.stream,
            assets.get("vnc_challenge")?,
            Instant::now() + operation_timeout,
            cancellation,
        )
        .await?;
        stream
            .read_exact(16, Instant::now() + operation_timeout, cancellation)
            .await?;
    }

    write_with_deadline(
        &mut stream.stream,
        assets.get("vnc_security_result")?,
        Instant::now() + operation_timeout,
        cancellation,
    )
    .await?;
    stream
        .read_exact(1, Instant::now() + operation_timeout, cancellation)
        .await?;
    write_with_deadline(
        &mut stream.stream,
        assets.get("vnc_server_init")?,
        Instant::now() + operation_timeout,
        cancellation,
    )
    .await?;
    shutdown_with_deadline(
        &mut stream.stream,
        Instant::now() + operation_timeout,
        cancellation,
    )
    .await
}

struct PhaseReader {
    stream: TcpStream,
    buffered: Vec<u8>,
    offset: usize,
    remaining_read_bytes: usize,
}

impl PhaseReader {
    fn new(stream: TcpStream, buffered: Vec<u8>, remaining_read_bytes: usize) -> Self {
        Self {
            stream,
            buffered,
            offset: 0,
            remaining_read_bytes,
        }
    }

    async fn read_exact(
        &mut self,
        length: usize,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> io::Result<Vec<u8>> {
        let mut value = Vec::with_capacity(length);
        let buffered = (self.buffered.len() - self.offset).min(length);
        value.extend_from_slice(&self.buffered[self.offset..self.offset + buffered]);
        self.offset += buffered;

        while value.len() < length {
            if self.remaining_read_bytes == 0 {
                return Err(invalid_data("honeypot read budget exhausted"));
            }
            let wanted = (length - value.len()).min(self.remaining_read_bytes);
            let old_length = value.len();
            value.resize(old_length + wanted, 0);
            let read = tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(cancelled()),
                read = timeout_at(deadline, self.stream.read(&mut value[old_length..])) => match read {
                    Ok(read) => read?,
                    Err(_) => return Err(timed_out("honeypot protocol read")),
                },
            };
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "honeypot peer closed during protocol exchange",
                ));
            }
            value.truncate(old_length + read);
            self.remaining_read_bytes -= read;
        }
        Ok(value)
    }
}

struct BudgetedStream {
    inner: TcpStream,
    prefix: Vec<u8>,
    prefix_offset: usize,
    remaining_read_bytes: usize,
}

impl BudgetedStream {
    fn with_prefix(inner: TcpStream, prefix: Vec<u8>, remaining_read_bytes: usize) -> Self {
        Self {
            inner,
            prefix,
            prefix_offset: 0,
            remaining_read_bytes,
        }
    }
}

impl AsyncRead for BudgetedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix_offset < self.prefix.len() {
            let available = self.prefix.len() - self.prefix_offset;
            let copied = available.min(buffer.remaining());
            buffer.put_slice(&self.prefix[self.prefix_offset..self.prefix_offset + copied]);
            self.prefix_offset += copied;
            return Poll::Ready(Ok(()));
        }
        if self.remaining_read_bytes == 0 || buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let wanted = self
            .remaining_read_bytes
            .min(buffer.remaining())
            .min(TLS_READ_CHUNK_BYTES);
        let mut temporary = [0_u8; TLS_READ_CHUNK_BYTES];
        let mut temporary_buffer = ReadBuf::new(&mut temporary[..wanted]);
        match Pin::new(&mut self.inner).poll_read(context, &mut temporary_buffer) {
            Poll::Ready(Ok(())) => {
                let read = temporary_buffer.filled().len();
                self.remaining_read_bytes -= read;
                buffer.put_slice(temporary_buffer.filled());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for BudgetedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

async fn write_with_deadline<W: AsyncWrite + Unpin>(
    stream: &mut W,
    value: &[u8],
    deadline: Instant,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(cancelled()),
        written = timeout_at(deadline, stream.write_all(value)) => match written {
            Ok(result) => result,
            Err(_) => Err(timed_out("honeypot response write")),
        },
    }
}

async fn shutdown_with_deadline<W: AsyncWrite + Unpin>(
    stream: &mut W,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(cancelled()),
        result = timeout_at(deadline, stream.shutdown()) => match result {
            Ok(result) => result,
            Err(_) => Err(timed_out("honeypot connection shutdown")),
        },
    }
}

#[derive(Debug)]
enum PersistenceError {
    Cancelled,
    Database(String),
    OutcomeUnknown,
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("honeypot persistence cancelled"),
            Self::Database(error) => write!(formatter, "honeypot persistence failed: {error}"),
            Self::OutcomeUnknown => formatter.write_str("honeypot persistence outcome is unknown"),
        }
    }
}

struct DatabaseOutcome<T> {
    result: Result<T, PersistenceError>,
    discard_connection: bool,
}

struct DatabaseConnection {
    client: Option<Object>,
}

impl DatabaseConnection {
    fn new(client: Object) -> Self {
        Self {
            client: Some(client),
        }
    }

    fn client_mut(&mut self) -> &mut Object {
        self.client
            .as_mut()
            .expect("honeypot database connection is present")
    }

    fn cancel_token(&self) -> CancelToken {
        self.client
            .as_ref()
            .expect("honeypot database connection is present")
            .cancel_token()
    }

    fn finish<T>(mut self, outcome: DatabaseOutcome<T>) -> Result<T, PersistenceError> {
        let client = self
            .client
            .take()
            .expect("honeypot database connection is present");
        if outcome.discard_connection {
            drop(Object::take(client));
        } else {
            drop(client);
        }
        outcome.result
    }
}

impl Drop for DatabaseConnection {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            drop(Object::take(client));
        }
    }
}

async fn record_activity(
    persistence: &HoneypotPersistence,
    peer_ip: IpAddr,
    trap: &HoneypotConfig,
    detection: &Detection,
    direction: &str,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    if is_exact_localhost(peer_ip) {
        return Ok(());
    }
    if cancellation.is_cancelled() {
        return Err(cancelled());
    }
    let metadata = format!(
        "Honeypot[{}:{}] | Protocol: {} | Direction: {} | Detail: {}",
        trap.label,
        trap.port,
        detection.protocol.activity_name(),
        direction,
        truncate(&detection.summary, 200)
    );
    let event = JournalEvent::new(peer_ip, metadata)?;
    // Once submitted, this bounded filesystem operation is joined even if shutdown is requested.
    // A protocol response is therefore never emitted for an event whose durable state is unknown.
    persistence.journal.enqueue(&event).await
}

fn is_exact_localhost(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.octets() == [127, 0, 0, 1],
        IpAddr::V6(ip) => ip.octets() == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    }
}

async fn bounded_pool<T, E, F>(
    deadline: Instant,
    cancellation: &CancellationToken,
    future: F,
) -> Result<T, PersistenceError>
where
    E: fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(PersistenceError::Cancelled),
        result = timeout_at(deadline, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(PersistenceError::Database(format!("pool: {error}"))),
            Err(_) => Err(PersistenceError::Database("pool deadline exceeded".into())),
        },
    }
}

async fn database_operation<T, F>(
    deadline: Instant,
    cancellation: &CancellationToken,
    cancel_token: &CancelToken,
    commit_started: &AtomicBool,
    future: F,
) -> DatabaseOutcome<T>
where
    F: Future<Output = Result<T, PersistenceError>>,
{
    tokio::pin!(future);
    let interruption = tokio::select! {
        biased;
        _ = cancellation.cancelled() => PersistenceError::Cancelled,
        result = timeout_at(deadline, future.as_mut()) => match result {
            Ok(result) => return completed_database_outcome(result),
            Err(_) => PersistenceError::Database("operation deadline exceeded".into()),
        },
    };

    let recovery_deadline = Instant::now() + DATABASE_CANCEL_DRAIN_TIMEOUT;
    if commit_started.load(Ordering::Acquire) {
        return match timeout_at(recovery_deadline, future.as_mut()).await {
            Ok(result) => completed_database_outcome(result),
            Err(_) => DatabaseOutcome {
                result: Err(PersistenceError::OutcomeUnknown),
                discard_connection: true,
            },
        };
    }

    cancellation.cancel();
    let recovery = timeout_at(recovery_deadline, async {
        tokio::join!(cancel_token.cancel_query(NoTls), future.as_mut())
    })
    .await;
    let discard_connection = match recovery {
        Ok((Ok(()), _)) => false,
        Ok((Err(_), _)) | Err(_) => true,
    };
    DatabaseOutcome {
        result: Err(interruption),
        discard_connection,
    }
}

fn completed_database_outcome<T>(result: Result<T, PersistenceError>) -> DatabaseOutcome<T> {
    let discard_connection = matches!(result, Err(PersistenceError::OutcomeUnknown));
    DatabaseOutcome {
        result,
        discard_connection,
    }
}

fn start_commit(
    deadline: Instant,
    cancellation: &CancellationToken,
    commit_started: &AtomicBool,
) -> Result<(), PersistenceError> {
    ensure_active(cancellation)?;
    if Instant::now() >= deadline {
        return Err(PersistenceError::Database(
            "commit deadline exceeded".into(),
        ));
    }
    commit_started.store(true, Ordering::Release);
    Ok(())
}

async fn configure_transaction_deadline(
    transaction: &deadpool_postgres::Transaction<'_>,
    deadline: Instant,
) -> Result<(), PersistenceError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let server_millis = (remaining.as_millis() / 2).clamp(1, i32::MAX as u128);
    let value = format!("{server_millis}ms");
    transaction
        .query_one("SELECT set_config('statement_timeout',$1,true)", &[&value])
        .await
        .map_err(|error| database_error("statement timeout", error))?;
    Ok(())
}

fn ensure_active(cancellation: &CancellationToken) -> Result<(), PersistenceError> {
    if cancellation.is_cancelled() {
        Err(PersistenceError::Cancelled)
    } else {
        Ok(())
    }
}

fn database_error(label: &str, error: impl fmt::Display + fmt::Debug) -> PersistenceError {
    PersistenceError::Database(format!("{label}: {error} ({error:?})"))
}

fn commit_error(label: &str, error: tokio_postgres::Error) -> PersistenceError {
    if error.as_db_error().is_some() {
        database_error(label, error)
    } else {
        PersistenceError::OutcomeUnknown
    }
}

fn persistence_to_io(error: PersistenceError) -> io::Error {
    match error {
        PersistenceError::Cancelled => cancelled(),
        PersistenceError::Database(error) => io::Error::other(error),
        PersistenceError::OutcomeUnknown => {
            io::Error::other("honeypot database commit response was lost; connection was discarded")
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "honeypot service cancelled")
}

fn timed_out(operation: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("{operation} timed out"))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::Ipv4Addr,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering as AtomicOrdering},
    };

    use deadpool_postgres::{
        Config as DatabasePoolConfig, ManagerConfig, PoolConfig, RecyclingMethod, Runtime,
    };
    use proptest::prelude::*;
    use tokio::{io::AsyncReadExt, time::timeout};

    use super::*;
    use crate::config::Properties;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed);
            let mut random = [0_u8; 8];
            fill_random(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "lmyzmail-honeypot-test-{}-{sequence}-{}",
                std::process::id(),
                hex_lower(&random)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn persistence_with_journal(journal: Arc<HoneypotJournal>) -> Arc<HoneypotPersistence> {
        Arc::new(HoneypotPersistence {
            pool: unused_pool(),
            journal,
            schema_ready: AtomicBool::new(false),
            schema_lock: Mutex::new(()),
        })
    }

    fn mysql_probe() -> Vec<u8> {
        let mut payload = vec![0_u8; 32];
        payload[0] = 1;
        let mut packet = vec![32, 0, 0, 1];
        packet.extend(payload);
        packet
    }

    fn minecraft_probe() -> Vec<u8> {
        let address = b"honeypot.example";
        let mut body = vec![0, 47, address.len() as u8];
        body.extend_from_slice(address);
        body.extend_from_slice(&[0x63, 0xdd, 1]);
        let mut packet = vec![body.len() as u8];
        packet.extend(body);
        packet
    }

    fn probes() -> Vec<(Vec<u8>, Protocol)> {
        let mongo = {
            let mut value = Vec::new();
            value.extend_from_slice(&17_i32.to_le_bytes());
            value.extend_from_slice(&1_i32.to_le_bytes());
            value.extend_from_slice(&0_i32.to_le_bytes());
            value.extend_from_slice(&2013_i32.to_le_bytes());
            value.push(0);
            value
        };
        vec![
            (vec![5, 1, 0], Protocol::Socks5),
            (vec![4, 1, 0, 80, 127, 0, 0, 1, b'x', 0], Protocol::Socks4),
            (b"ZBXD\x01\0\0\0\0\0\0\0\0".to_vec(), Protocol::ZabbixBinary),
            (mongo, Protocol::MongoDb),
            (vec![0, 0, 0, 8, 0, 3, 0, 0], Protocol::PostgreSql),
            (mysql_probe(), Protocol::MySql),
            (vec![0xfe, 1], Protocol::Minecraft),
            (minecraft_probe(), Protocol::Minecraft),
            (b"GET / HTTP/1.1\r\n\r\n".to_vec(), Protocol::Http),
            (b"PING\r\n".to_vec(), Protocol::Redis),
            (b"stats\r\n".to_vec(), Protocol::Memcached),
            (b"SSH-2.0-scanner\r\n".to_vec(), Protocol::Ssh),
            (b"RFB 003.008\n".to_vec(), Protocol::Vnc),
            (b"EHLO scanner.example\r\n".to_vec(), Protocol::Smtp),
            (b"USER scanner\r\n".to_vec(), Protocol::Ftp),
            (b"STAT\r\n".to_vec(), Protocol::Pop3),
            (b"A001 LOGIN scanner secret\r\n".to_vec(), Protocol::Imap),
            (b"agent.ping\n".to_vec(), Protocol::ZabbixText),
            (b"wat even is this\r\n".to_vec(), Protocol::Unknown),
            (vec![0x16, 3, 3, 0, 1, 1], Protocol::Tls),
            (vec![3, 0, 0, 11, 6, 0xe0, 0, 0, 0, 0, 0], Protocol::Rdp),
        ]
    }

    fn assert_protocol(data: &[u8], expected: Protocol) {
        let DetectionDecision::Detected(detection) = detect_incremental(data, false) else {
            panic!("complete probe was not classified: {data:?}");
        };
        assert_eq!(detection.protocol, expected, "probe {data:?}");
    }

    #[test]
    fn frozen_probe_set_classifies_with_oracle_priority() {
        for (probe, protocol) in probes() {
            assert_protocol(&probe, protocol);
        }
        assert_protocol(b"GET cache-key\r\n", Protocol::Http);
        assert_protocol(b"RETR message\r\n", Protocol::Ftp);
        assert_protocol(b"stats\r\n", Protocol::Memcached);
        assert_protocol(b"STAT\r\n", Protocol::Pop3);
        assert_protocol(b"DELETE / HTTP/1.1\r\n", Protocol::Http);
        assert_protocol(b"A001 login scanner secret\r\n", Protocol::Unknown);
        assert_protocol(b"A001  LOGIN scanner secret\r\n", Protocol::Unknown);
    }

    #[test]
    fn journal_event_rejects_unrepresentable_or_mismatched_timestamps() {
        let event = JournalEvent::new("192.0.2.30".parse().unwrap(), "valid".into()).unwrap();
        event.validate().unwrap();

        let mut out_of_range = event.clone();
        out_of_range.observed_at_millis = MAX_JOURNAL_TIMESTAMP_MILLIS + 1;
        assert_eq!(
            out_of_range.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut mismatched = event;
        let mismatched_timestamp = mismatched.observed_at_millis as u64 + 1;
        mismatched.event_id = format!("{mismatched_timestamp:016x}{}", "0".repeat(48));
        assert_eq!(
            mismatched.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn every_fragmented_probe_converges_without_wrong_classification() {
        for (probe, expected) in probes() {
            for end in 1..=probe.len() {
                match detect_incremental(&probe[..end], false) {
                    DetectionDecision::NeedMore => assert!(end < probe.len()),
                    DetectionDecision::Detected(detection) => {
                        assert_eq!(detection.protocol, expected, "prefix {end} of {probe:?}");
                    }
                }
            }
        }
        assert_eq!(detect_incremental(b"P", false), DetectionDecision::NeedMore);
        assert_protocol(b"PING\r\n", Protocol::Redis);
    }

    proptest! {
        #[test]
        fn arbitrary_fragment_boundaries_preserve_the_final_protocol(
            probe_index in 0usize..21,
            first_cut in 0usize..80,
            second_cut in 0usize..80,
        ) {
            let values = probes();
            let (probe, expected) = &values[probe_index];
            let mut cuts = [first_cut.min(probe.len()), second_cut.min(probe.len()), probe.len()];
            cuts.sort_unstable();
            for cut in cuts {
                if cut == 0 {
                    continue;
                }
                if let DetectionDecision::Detected(detection) = detect_incremental(&probe[..cut], false) {
                    prop_assert_eq!(detection.protocol, *expected);
                }
            }
            let DetectionDecision::Detected(final_detection) = detect_incremental(probe, false) else {
                prop_assert!(false, "complete probe was not detected");
                return Ok(());
            };
            prop_assert_eq!(final_detection.protocol, *expected);
        }

        #[test]
        fn arbitrary_bounded_detector_input_never_panics_or_expands_summaries(
            data in proptest::collection::vec(any::<u8>(), 1..=65_536),
            force in any::<bool>(),
        ) {
            if let DetectionDecision::Detected(detection) = detect_incremental(&data, force) {
                prop_assert!(detection.summary.chars().count() <= 200);
            }
        }
    }

    #[test]
    fn read_limit_forces_a_bounded_generic_decision() {
        assert_eq!(detect_incremental(b"P", false), DetectionDecision::NeedMore);
        let forced = force_detection(b"P");
        assert_eq!(forced.protocol, Protocol::Unknown);
        assert_eq!(forced.summary, "P");

        let oversized = vec![b'x'; 1024];
        let forced = force_detection(&oversized);
        assert_eq!(forced.protocol, Protocol::Unknown);
        assert_eq!(forced.summary.len(), 100);
    }

    #[test]
    fn assets_are_complete_hash_checked_and_byte_exact() {
        let assets = HoneypotAssets::load().unwrap();
        assert_eq!(assets.get("redis").unwrap().len(), 98);
        assert_eq!(assets.get("vnc_security_types").unwrap().len(), 256);
        assert_eq!(assets.get("vnc_challenge").unwrap(), b"SKIBIDI DOP DOP!");
        assert_eq!(
            assets.get("rdp_negotiation").unwrap(),
            &[3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 1, 0, 2, 0, 8, 0, 1, 0, 0, 0]
        );
        assert_eq!(
            assets.get("rdp_disconnect").unwrap(),
            &[3, 0, 0, 9, 2, 0xf0, 0x80, 0x21, 0x80]
        );

        let http_hashes: HashSet<_> = (0..4)
            .map(|index| {
                hex_lower(&Sha256::digest(
                    assets.get(&format!("http_{index}")).unwrap(),
                ))
            })
            .collect();
        assert_eq!(http_hashes.len(), 4);

        let greeting = assets.mysql_greeting().to_vec();
        assert_eq!(assets.mysql_greeting(), greeting);
        assert!((1..100_000).contains(&u32::from_le_bytes(greeting[37..41].try_into().unwrap())));
        let mut normalized = greeting;
        normalized[37..41].fill(0);
        normalized[41..49].fill(0);
        normalized[68..80].fill(0);
        assert_eq!(normalized, assets.get("mysql_greeting_normalized").unwrap());
    }

    #[test]
    fn rdp_frame_completion_and_coalesced_tls_prefix_are_preserved() {
        let request = [3, 0, 0, 11, 6, 0xe0, 0, 0, 0, 0, 0];
        let tls_prefix = [0x16, 3, 3, 0, 1, 1];
        let mut coalesced = request.to_vec();
        coalesced.extend_from_slice(&tls_prefix);
        assert_protocol(&coalesced, Protocol::Rdp);
        assert_eq!(rdp_tls_prefix(&coalesced).unwrap(), tls_prefix);

        let incomplete = [3, 0, 0, 19, 6, 0xe0, 0, 0, 0, 0, 0];
        assert_eq!(
            detect_incremental(&incomplete, false),
            DetectionDecision::NeedMore
        );
        assert!(rdp_tls_prefix(&incomplete).is_err());
    }

    #[test]
    fn generated_certificate_matches_frozen_semantics() {
        let tls = HoneypotTls::generate().unwrap();
        let certificate = X509::from_der(&tls.certificate_der).unwrap();
        assert_eq!(
            certificate
                .serial_number()
                .to_bn()
                .unwrap()
                .to_dec_str()
                .unwrap()
                .to_string(),
            "69420"
        );
        let subject: Vec<_> = certificate
            .subject_name()
            .entries()
            .map(|entry| (entry.object().nid(), entry.data().to_string().unwrap()))
            .collect();
        assert_eq!(
            subject,
            vec![
                (
                    Nid::COMMONNAME,
                    "HONEYPOT TRIGGERED - Your IP Has Been Logged".into()
                ),
                (
                    Nid::ORGANIZATIONALUNITNAME,
                    "Skibidi Toilet Security Team".into()
                ),
                (
                    Nid::ORGANIZATIONNAME,
                    "Ohio Brainrot Detection Division".into()
                ),
                (Nid::LOCALITYNAME, "Fanum Tax Collection Center".into()),
                (Nid::STATEORPROVINCENAME, "State of Absolute Cringe".into()),
                (Nid::COUNTRYNAME, "JM".into()),
            ]
        );
        assert_eq!(
            certificate.subject_name().to_der().unwrap(),
            certificate.issuer_name().to_der().unwrap()
        );
        let public_key = certificate.public_key().unwrap();
        assert_eq!(
            public_key.ec_key().unwrap().group().curve_name(),
            Some(Nid::X9_62_PRIME256V1)
        );
        assert_eq!(
            certificate.signature_algorithm().object().nid(),
            Nid::ECDSA_WITH_SHA256
        );
        let validity = certificate
            .not_before()
            .diff(certificate.not_after())
            .unwrap();
        assert_eq!(validity.days.abs(), 3650);
        assert_eq!(validity.secs, 0);

        let mut sans: Vec<_> = certificate
            .subject_alt_names()
            .unwrap()
            .iter()
            .filter_map(|name| name.dnsname().map(str::to_owned))
            .collect();
        sans.sort();
        assert_eq!(
            sans,
            vec![
                "L-plus-ratio.fanum.taxed",
                "go.away.muppet",
                "nice.try.script.kiddie",
                "not.a.real.server",
                "rdp.honeypot.trap",
                "skibidi.dop.dop.yes.yes",
                "skibidi.toilet.honeypot.hit.your.ip.has.been.logged",
            ]
        );
        let text = String::from_utf8(certificate.to_text().unwrap()).unwrap();
        assert!(text.contains("X509v3 Basic Constraints: critical"));
        assert!(text.contains("CA:FALSE"));
    }

    async fn vnc_exchange(selection: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let assets = Arc::new(HoneypotAssets::load().unwrap());
        let cancellation = CancellationToken::new();
        let client = TcpStream::connect(address);
        let server = listener.accept();
        let (client, server) = tokio::join!(client, server);
        let mut client = client.unwrap();
        let (server, _) = server.unwrap();
        let server_assets = Arc::clone(&assets);
        let server_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            handle_vnc(
                server,
                Vec::new(),
                1024,
                &server_assets,
                Duration::from_secs(1),
                &server_cancellation,
            )
            .await
        });

        client.write_all(b"RFB 003.008\n").await.unwrap();
        let mut security_types = vec![0; 256];
        client.read_exact(&mut security_types).await.unwrap();
        client.write_all(&[selection]).await.unwrap();
        let challenge = if selection == 2 {
            let mut challenge = vec![0; 16];
            client.read_exact(&mut challenge).await.unwrap();
            client.write_all(&[0; 16]).await.unwrap();
            challenge
        } else {
            Vec::new()
        };
        let mut security_result = vec![0; 4];
        client.read_exact(&mut security_result).await.unwrap();
        client.write_all(&[1]).await.unwrap();
        let mut server_init = Vec::new();
        client.read_to_end(&mut server_init).await.unwrap();
        task.await.unwrap().unwrap();
        (security_types, challenge, security_result, server_init)
    }

    #[tokio::test]
    async fn vnc_none_auth_and_unknown_phases_are_incremental_and_exact() {
        let assets = HoneypotAssets::load().unwrap();
        for selection in [1, 42] {
            let (types, challenge, result, init) = vnc_exchange(selection).await;
            assert_eq!(types, assets.get("vnc_security_types").unwrap());
            assert!(challenge.is_empty());
            assert_eq!(result, assets.get("vnc_security_result").unwrap());
            assert_eq!(init, assets.get("vnc_server_init").unwrap());
        }
        let (types, challenge, result, init) = vnc_exchange(2).await;
        assert_eq!(types, assets.get("vnc_security_types").unwrap());
        assert_eq!(challenge, assets.get("vnc_challenge").unwrap());
        assert_eq!(result, assets.get("vnc_security_result").unwrap());
        assert_eq!(init, assets.get("vnc_server_init").unwrap());
    }

    #[tokio::test]
    async fn budgeted_stream_never_reads_past_its_total_budget() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address);
        let server = listener.accept();
        let (client, server) = tokio::join!(client, server);
        let mut client = client.unwrap();
        let (server, _) = server.unwrap();
        client.write_all(b"abcdefgh").await.unwrap();
        client.shutdown().await.unwrap();

        let mut stream = BudgetedStream::with_prefix(server, b"xy".to_vec(), 3);
        let mut value = Vec::new();
        stream.read_to_end(&mut value).await.unwrap();
        assert_eq!(value, b"xyabc");
    }

    #[tokio::test]
    async fn partial_client_input_uses_the_bounded_completion_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address);
        let server = listener.accept();
        let (client, server) = tokio::join!(client, server);
        let mut client = client.unwrap();
        let (mut server, _) = server.unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(async move {
            read_initial(
                &mut server,
                1024,
                Instant::now() + Duration::from_millis(25),
                Duration::from_millis(500),
                &cancellation,
            )
            .await
        });

        client.write_all(b"P").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.write_all(b"ING\r\n").await.unwrap();
        let InitialRead::Data { detection, .. } = task.await.unwrap().unwrap() else {
            panic!("fragmented input was not retained");
        };
        assert_eq!(detection.protocol, Protocol::Redis);
    }

    fn unused_pool() -> Pool {
        let mut config = DatabasePoolConfig::new();
        config.host = Some("127.0.0.1".into());
        config.port = Some(1);
        config.dbname = Some("unused".into());
        config.user = Some("unused".into());
        config.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        config.pool = Some(PoolConfig::new(1));
        config.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
    }

    #[test]
    fn only_exact_localhost_addresses_bypass_persistence() {
        assert!(is_exact_localhost("127.0.0.1".parse().unwrap()));
        assert!(is_exact_localhost("::1".parse().unwrap()));
        assert!(!is_exact_localhost("127.0.0.2".parse().unwrap()));
        assert!(!is_exact_localhost("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn journal_is_private_bounded_atomic_and_restartable() {
        use std::os::unix::fs::MetadataExt;

        let directory = TestDirectory::new();
        let journal = HoneypotJournal::open_with_capacity(directory.path(), 1)
            .await
            .unwrap();
        let event = JournalEvent::new(
            "192.0.2.10".parse().unwrap(),
            "Honeypot[test:1] | Protocol: REDIS | Direction: CLIENT_FIRST | Detail: PING".into(),
        )
        .unwrap();
        assert_eq!(
            u64::from_str_radix(&event.event_id[..16], 16).unwrap(),
            event.observed_at_millis as u64
        );
        journal.enqueue(&event).await.unwrap();
        assert_eq!(journal.entry_count(), 1);
        assert_eq!(
            journal.enqueue(&event).await.unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(journal.entry_count(), 1);

        let replay_directory = directory
            .path()
            .join(JOURNAL_NAMESPACE_DIRECTORY)
            .join(JOURNAL_DIRECTORY);
        let replay_metadata = fs::metadata(&replay_directory).unwrap();
        assert_eq!(replay_metadata.mode() & 0o777, 0o700);
        let record_path = replay_directory.join(event.file_name());
        let record_metadata = fs::metadata(&record_path).unwrap();
        assert_eq!(record_metadata.mode() & 0o777, 0o600);
        assert!(record_metadata.len() <= JOURNAL_RECORD_MAX_BYTES as u64);
        assert_eq!(
            fs::read_dir(&replay_directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(
                    |entry| entry.path().extension().and_then(|value| value.to_str())
                        == Some("tmp")
                )
                .count(),
            0
        );

        let second = JournalEvent::new("192.0.2.11".parse().unwrap(), "bounded".into()).unwrap();
        assert_eq!(
            journal.enqueue(&second).await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            HoneypotJournal::open_with_capacity(directory.path(), 1)
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::AddrInUse
        );

        let names = journal.claim_batch();
        assert_eq!(names, vec![event.file_name()]);
        assert_eq!(journal.read_claimed(&names[0]).await.unwrap(), event);
        journal.release(&names[0]);
        drop(journal);

        let reopened = HoneypotJournal::open_with_capacity(directory.path(), 1)
            .await
            .unwrap();
        let names = reopened.claim_batch();
        assert_eq!(names, vec![event.file_name()]);
        assert_eq!(reopened.read_claimed(&names[0]).await.unwrap(), event);
        reopened.complete(&names[0]).await.unwrap();
        assert_eq!(reopened.entry_count(), 0);
        assert!(!record_path.exists());
    }

    #[tokio::test]
    async fn journal_rejects_symlinks_and_cleans_crash_temporary_files() {
        use std::os::unix::{fs::PermissionsExt, fs::symlink};

        let directory = TestDirectory::new();
        let journal = HoneypotJournal::open_with_capacity(directory.path(), 2)
            .await
            .unwrap();
        drop(journal);
        let replay_directory = directory
            .path()
            .join(JOURNAL_NAMESPACE_DIRECTORY)
            .join(JOURNAL_DIRECTORY);
        let temporary = replay_directory.join(format!("{}.tmp", "1".repeat(64)));
        fs::write(&temporary, b"partial").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        let journal = HoneypotJournal::open_with_capacity(directory.path(), 2)
            .await
            .unwrap();
        assert!(!temporary.exists());
        drop(journal);

        let empty = replay_directory.join(format!("{}.json", "3".repeat(64)));
        File::create(&empty).unwrap();
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o600)).unwrap();
        let journal = HoneypotJournal::open_with_capacity(directory.path(), 2)
            .await
            .unwrap();
        let names = journal.claim_batch();
        assert_eq!(names, vec![format!("{}.json", "3".repeat(64))]);
        assert_eq!(
            journal.read_claimed(&names[0]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        journal.complete(&names[0]).await.unwrap();
        assert!(!empty.exists());
        drop(journal);

        let malicious = replay_directory.join(format!("{}.json", "2".repeat(64)));
        symlink("/dev/null", &malicious).unwrap();
        assert_eq!(
            HoneypotJournal::open_with_capacity(directory.path(), 2)
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn concurrent_journal_admission_never_exceeds_its_capacity() {
        let directory = TestDirectory::new();
        let journal = HoneypotJournal::open_with_capacity(directory.path(), 8)
            .await
            .unwrap();
        let mut tasks = JoinSet::new();
        for index in 0..32 {
            let journal = Arc::clone(&journal);
            tasks.spawn(async move {
                let event = JournalEvent::new(
                    format!("192.0.2.{}", index + 1).parse().unwrap(),
                    format!("concurrent event {index}"),
                )
                .unwrap();
                journal.enqueue(&event).await
            });
        }
        let mut admitted = 0;
        while let Some(result) = tasks.join_next().await {
            match result.unwrap() {
                Ok(()) => admitted += 1,
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
            }
        }
        assert_eq!(admitted, 8);
        assert_eq!(journal.entry_count(), 8);
    }

    #[tokio::test]
    async fn full_journal_prevents_protocol_response_before_durable_admission() {
        let directory = TestDirectory::new();
        let journal = HoneypotJournal::open_with_capacity(directory.path(), 1)
            .await
            .unwrap();
        let existing = JournalEvent::new("192.0.2.20".parse().unwrap(), "existing".into()).unwrap();
        journal.enqueue(&existing).await.unwrap();
        let persistence = persistence_with_journal(journal);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address);
        let server = listener.accept();
        let (client, server) = tokio::join!(client, server);
        let mut client = client.unwrap();
        let (server, _) = server.unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(handle_detection(
            server,
            "192.0.2.21".parse().unwrap(),
            HoneypotConfig {
                port: address.port(),
                protocol: "NONE".into(),
                label: "durability-test".into(),
                bind_address: "127.0.0.1".into(),
            },
            persistence,
            Arc::new(HoneypotAssets::load().unwrap()),
            Arc::new(HoneypotTls::generate().unwrap()),
            ConnectionLimits {
                initial_delay: Duration::from_millis(10),
                post_banner_timeout: Duration::from_secs(1),
                max_connections: 1,
                max_read_bytes: 1024,
            },
            Detection::new(Protocol::Redis, "PING"),
            b"PING\r\n".to_vec(),
            6,
            "CLIENT_FIRST",
            cancellation,
        ));
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
    }

    #[tokio::test]
    async fn trap_admission_is_bounded_and_cancellation_drains_connections() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let trap = BoundTrap {
            listener,
            config: HoneypotConfig {
                port: address.port(),
                protocol: "SSH".into(),
                label: "admission-test".into(),
                bind_address: "127.0.0.1".into(),
            },
        };
        let limits = ConnectionLimits {
            initial_delay: Duration::from_millis(20),
            post_banner_timeout: Duration::from_secs(5),
            max_connections: 1,
            max_read_bytes: 1024,
        };
        let assets = Arc::new(HoneypotAssets::load().unwrap());
        let tls = Arc::new(HoneypotTls::generate().unwrap());
        let directory = TestDirectory::new();
        let persistence = HoneypotPersistence::open(directory.path(), unused_pool())
            .await
            .unwrap();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            serve_trap(trap, persistence, assets, tls, limits, task_cancellation).await
        });

        let mut first = TcpStream::connect(address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut second = TcpStream::connect(address).await.unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(
            timeout(Duration::from_millis(250), second.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );

        let mut banner = vec![
            0;
            HoneypotAssets::load()
                .unwrap()
                .get("ssh_banner")
                .unwrap()
                .len()
        ];
        timeout(Duration::from_millis(250), first.read_exact(&mut banner))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            banner,
            HoneypotAssets::load().unwrap().get("ssh_banner").unwrap()
        );
        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn one_busy_trap_does_not_disable_other_traps() {
        let directory = TestDirectory::new();
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();

        let properties = Properties::parse(
            format!(
                "lmyzmail.honeypot.enabled=true\n\
                 lmyzmail.maildir.base={}\n\
                 lmyzmail.honeypot.initial-delay-ms=20\n\
                 lmyzmail.honeypot.post-banner-timeout-ms=100\n\
                 lmyzmail.honeypot.traps[0].port={occupied_port}\n\
                 lmyzmail.honeypot.traps[0].protocol=SSH\n\
                 lmyzmail.honeypot.traps[0].bind-address=127.0.0.1\n\
                 lmyzmail.honeypot.traps[1].port=1\n\
                 lmyzmail.honeypot.traps[1].protocol=SSH\n\
                 lmyzmail.honeypot.traps[1].bind-address=127.0.0.1\n",
                directory.path().display()
            )
            .as_bytes(),
        )
        .unwrap();
        let mut config = RuntimeConfig::from_properties(properties).unwrap();
        config.listen.honeypots[1].port = 0;
        let config = Arc::new(config);
        let traps = bind_honeypot_traps(&config).await.unwrap();
        assert_eq!(traps.len(), 1);
        let available_port = traps[0].listener.local_addr().unwrap().port();
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            serve_bound_honeypots(config, unused_pool(), task_cancellation, traps).await
        });

        let mut client = timeout(Duration::from_secs(1), async {
            loop {
                match TcpStream::connect((Ipv4Addr::LOCALHOST, available_port)).await {
                    Ok(client) => break client,
                    Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                        sleep(Duration::from_millis(5)).await;
                    }
                    Err(error) => panic!("unexpected trap connection error: {error}"),
                }
            }
        })
        .await
        .unwrap();
        let expected = HoneypotAssets::load().unwrap();
        let mut banner = vec![0; expected.get("ssh_banner").unwrap().len()];
        timeout(Duration::from_secs(1), client.read_exact(&mut banner))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(banner, expected.get("ssh_banner").unwrap());

        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn all_busy_traps_fail_startup_instead_of_running_only_replay() {
        let directory = TestDirectory::new();
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let properties = Properties::parse(
            format!(
                "lmyzmail.honeypot.enabled=true\n\
                 lmyzmail.maildir.base={}\n\
                 lmyzmail.honeypot.traps[0].port={occupied_port}\n\
                 lmyzmail.honeypot.traps[0].protocol=SSH\n\
                 lmyzmail.honeypot.traps[0].bind-address=127.0.0.1\n",
                directory.path().display()
            )
            .as_bytes(),
        )
        .unwrap();
        let config = Arc::new(RuntimeConfig::from_properties(properties).unwrap());
        let error = serve_honeypots(config, unused_pool(), CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    }
}
