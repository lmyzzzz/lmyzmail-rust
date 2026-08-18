use std::{
    collections::{HashMap, VecDeque},
    fmt,
    future::Future,
    io::SeekFrom,
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use idna::domain_to_ascii_strict;
use rustls::{
    AlertDescription, ClientConfig, Error as RustlsError, RootCertStore, pki_types::ServerName,
};
use sha2::{Digest, Sha256};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout_at},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::sync::CancellationToken;

use crate::{
    config::RuntimeConfig,
    coordinator_observer::{CoordinatorStage, StageTimer},
};

const MAX_REPLY_LINE_BYTES: usize = 2_048;
const MAX_REPLY_BYTES: usize = 64 * 1024;
const MAX_REPLY_LINES: usize = 100;
const READ_CHUNK_BYTES: usize = 4 * 1024;
const MESSAGE_CHUNK_BYTES: usize = 16 * 1024;
const MAX_PIPELINE_BYTES: usize = 512 * 1024;
const MAX_RECIPIENTS: usize = 1_000;
const MAX_HOST_BYTES: usize = 253;
const MAX_ADDRESS_BYTES: usize = 254;
const MAX_REPLY_SUMMARY_CHARS: usize = 2_048;
const MAX_POOL_KEYS: usize = 256;
const MAX_POOL_IDLE_CONNECTIONS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TlsMode {
    Disabled,
    Opportunistic,
    Required,
}

#[derive(Clone, Debug)]
pub struct SmtpEndpoint {
    connect_addr: SocketAddr,
    tls_name: String,
}

impl SmtpEndpoint {
    pub fn public_mx(
        connect_addr: SocketAddr,
        tls_name: impl Into<String>,
    ) -> Result<Self, DeliveryError> {
        if !is_public_smtp_ip(connect_addr.ip()) {
            return Err(error(
                DeliveryErrorKind::Configuration,
                "outbound SMTP MX resolved to a non-public address",
            ));
        }
        Self::validated(connect_addr, tls_name.into())
    }

    /// For an administrator-controlled relay only; never use this with MX DNS results.
    pub fn trusted_relay(
        connect_addr: SocketAddr,
        tls_name: impl Into<String>,
    ) -> Result<Self, DeliveryError> {
        Self::validated(connect_addr, tls_name.into())
    }

    fn validated(connect_addr: SocketAddr, tls_name: String) -> Result<Self, DeliveryError> {
        if connect_addr.port() == 0 {
            return Err(error(
                DeliveryErrorKind::Configuration,
                "invalid outbound SMTP port",
            ));
        }
        validate_host(&tls_name)?;
        Ok(Self {
            connect_addr,
            tls_name,
        })
    }
}

#[derive(Clone)]
pub enum MessageSource {
    Bytes(Arc<[u8]>),
    File(TrustedFileSource),
}

#[derive(Clone)]
pub struct TrustedFileSource {
    root: Arc<TrustedFileRoot>,
    relative: PathBuf,
    initial_identity: FileIdentity,
    authority: Option<MessageContentProof>,
}

struct TrustedFileRoot {
    absolute_path: PathBuf,
    device: u64,
    #[cfg(target_os = "linux")]
    descriptor: std::os::fd::OwnedFd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    links: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileProof {
    identity: FileIdentity,
    sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageContentProof {
    pub size: u64,
    pub sha256: [u8; 32],
}

impl MessageContentProof {
    pub fn new(size: u64, sha256: [u8; 32]) -> Self {
        Self { size, sha256 }
    }
}

impl MessageSource {
    pub fn file_under_root(
        root: impl AsRef<Path>,
        relative: impl AsRef<Path>,
        proof: MessageContentProof,
    ) -> Result<Self, DeliveryError> {
        TrustedFileSource::with_authority(root.as_ref(), relative.as_ref(), proof)
            .map(Self::File)
            .map_err(|_| {
                error(
                    DeliveryErrorKind::Permanent,
                    "outbound message source is not a trusted regular file",
                )
            })
    }
}

impl TrustedFileSource {
    pub(crate) fn new(root: &Path, relative: &Path) -> std::io::Result<Self> {
        validate_relative_source_path(relative)?;
        let root = Arc::new(TrustedFileRoot::open(root)?);
        let file = root.open_relative(relative)?;
        let initial_identity = file_identity(&file)?;
        validate_file_identity(&initial_identity, root.device, u64::MAX)?;
        Ok(Self {
            root,
            relative: relative.to_path_buf(),
            initial_identity,
            authority: None,
        })
    }

    pub(crate) fn with_authority(
        root: &Path,
        relative: &Path,
        authority: MessageContentProof,
    ) -> std::io::Result<Self> {
        let mut source = Self::new(root, relative)?;
        if source.initial_identity.size != authority.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "outbound message source size conflicts with durable authority",
            ));
        }
        source.authority = Some(authority);
        Ok(source)
    }

    pub(crate) fn compatibility_path(&self) -> PathBuf {
        // The caller may persist this only for the frozen Java/Redis schema. It
        // is never accepted back as authority without rebuilding this contract.
        self.root.absolute_path.join(&self.relative)
    }

    pub(crate) fn initial_size(&self) -> u64 {
        self.initial_identity.size
    }

    pub(crate) fn validate_opened_metadata(
        &self,
        metadata: &std::fs::Metadata,
        maximum: u64,
    ) -> std::io::Result<()> {
        let observed = file_identity_from_metadata(metadata)?;
        validate_file_identity(&observed, self.root.device, maximum)?;
        if observed != self.initial_identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "outbound message source identity changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn open_initial(&self, maximum: u64) -> std::io::Result<std::fs::File> {
        self.open_matching(self.initial_identity, maximum)
    }

    fn open_matching(
        &self,
        expected: FileIdentity,
        maximum: u64,
    ) -> std::io::Result<std::fs::File> {
        let file = self.root.open_relative(&self.relative)?;
        let observed = file_identity(&file)?;
        validate_file_identity(&observed, self.root.device, maximum)?;
        if observed != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "outbound message source identity changed",
            ));
        }
        Ok(file)
    }
}

impl TrustedFileRoot {
    #[cfg(target_os = "linux")]
    fn open(path: &Path) -> std::io::Result<Self> {
        use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags, fstat, openat2};

        let absolute_path = std::path::absolute(path)?;
        let descriptor = openat2(
            CWD,
            &absolute_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(std::io::Error::from)?;
        let stat = fstat(&descriptor).map_err(std::io::Error::from)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "outbound message root is not a directory",
            ));
        }
        Ok(Self {
            absolute_path,
            device: stat.st_dev,
            descriptor,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn open(path: &Path) -> std::io::Result<Self> {
        let absolute_path = std::path::absolute(path)?;
        reject_symlink_components(&absolute_path)?;
        let metadata = std::fs::metadata(&absolute_path)?;
        if !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "outbound message root is not a directory",
            ));
        }
        Ok(Self {
            absolute_path,
            device: 0,
        })
    }

    #[cfg(target_os = "linux")]
    fn open_relative(&self, relative: &Path) -> std::io::Result<std::fs::File> {
        use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

        let descriptor = openat2(
            &self.descriptor,
            relative,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
        .map_err(std::io::Error::from)?;
        Ok(std::fs::File::from(descriptor))
    }

    #[cfg(not(target_os = "linux"))]
    fn open_relative(&self, relative: &Path) -> std::io::Result<std::fs::File> {
        let path = self.absolute_path.join(relative);
        reject_symlink_components(&path)?;
        std::fs::File::open(path)
    }
}

fn validate_relative_source_path(path: &Path) -> std::io::Result<()> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "outbound message path is not a safe relative path",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn file_identity(file: &std::fs::File) -> std::io::Result<FileIdentity> {
    file_identity_from_metadata(&file.metadata()?)
}

#[cfg(target_os = "linux")]
fn file_identity_from_metadata(metadata: &std::fs::Metadata) -> std::io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "outbound message source is not a regular file",
        ));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        links: metadata.nlink(),
    })
}

#[cfg(not(target_os = "linux"))]
fn file_identity(file: &std::fs::File) -> std::io::Result<FileIdentity> {
    file_identity_from_metadata(&file.metadata()?)
}

#[cfg(not(target_os = "linux"))]
fn file_identity_from_metadata(metadata: &std::fs::Metadata) -> std::io::Result<FileIdentity> {
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "outbound message source is not a regular file",
        ));
    }
    Ok(FileIdentity {
        device: 0,
        inode: 0,
        size: metadata.len(),
        links: 1,
    })
}

fn validate_file_identity(
    identity: &FileIdentity,
    root_device: u64,
    maximum: u64,
) -> std::io::Result<()> {
    if identity.links != 1
        || identity.size > maximum
        || (cfg!(target_os = "linux") && identity.device != root_device)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "outbound message source violates its trusted-root contract",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn reject_symlink_components(path: &Path) -> std::io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if std::fs::symlink_metadata(&current)?
            .file_type()
            .is_symlink()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "outbound message source contains a symlink",
            ));
        }
    }
    Ok(())
}

impl fmt::Debug for MessageSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("byte_count", &bytes.len())
                .finish(),
            Self::File(_) => formatter.write_str("File(<redacted>)"),
        }
    }
}

#[derive(Clone)]
pub struct DeliveryRequest {
    pub endpoint: SmtpEndpoint,
    pub hello_name: String,
    pub envelope_from: String,
    pub recipients: Vec<String>,
    pub message: MessageSource,
    pub tls_mode: TlsMode,
    pub max_message_bytes: u64,
}

impl fmt::Debug for DeliveryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryRequest")
            .field("endpoint", &self.endpoint)
            .field("hello_name", &self.hello_name)
            .field("envelope_from", &"<redacted>")
            .field("recipient_count", &self.recipients.len())
            .field("message", &self.message)
            .field("tls_mode", &self.tls_mode)
            .field("max_message_bytes", &self.max_message_bytes)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientStatus {
    Accepted,
    TemporaryFailure,
    PermanentFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientResult {
    pub recipient: String,
    pub status: RecipientStatus,
    pub code: u16,
    pub reply: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataStatus {
    Accepted,
    TemporaryFailure,
    PermanentFailure,
    NotAttempted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryResult {
    pub recipients: Vec<RecipientResult>,
    pub data_status: DataStatus,
    pub data_code: Option<u16>,
    pub data_reply: Option<String>,
    pub tls: bool,
    pub smtp_utf8: bool,
    pub pipelining: bool,
}

// Commit-ready values are bounded by the coordinator concurrency limit. Boxing
// this variant would add one allocator round trip to every delivered message.
#[allow(clippy::large_enum_variant)]
pub enum DeliveryPreparation {
    Complete(DeliveryResult),
    CommitReady(PreparedDelivery),
}

impl fmt::Debug for DeliveryPreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete(result) => formatter.debug_tuple("Complete").field(result).finish(),
            Self::CommitReady(_) => formatter.write_str("CommitReady(<SMTP transaction>)"),
        }
    }
}

pub struct PreparedDelivery {
    connection: PooledConnection,
    pool_return: Option<(Arc<SmtpConnectionPool>, PoolKey)>,
    recipients: Vec<RecipientResult>,
    tls: bool,
    smtp_utf8: bool,
    pipelining: bool,
}

impl fmt::Debug for PreparedDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDelivery")
            .field("recipient_count", &self.recipients.len())
            .field("tls", &self.tls)
            .field("smtp_utf8", &self.smtp_utf8)
            .field("pipelining", &self.pipelining)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryErrorKind {
    Configuration,
    Temporary,
    Permanent,
    Ambiguous,
    Protocol,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryStage {
    Request,
    Connect,
    Greeting,
    Ehlo,
    StartTls,
    Envelope,
    MessageSource,
    DataCommand,
    DataBody,
    DataFinal,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DeliveryFailureSource {
    #[default]
    Other,
    Deadline {
        operation: &'static str,
        timeout: Duration,
    },
    Io {
        operation: &'static str,
        kind: std::io::ErrorKind,
    },
    TlsAlert {
        operation: &'static str,
        alert: AlertDescription,
    },
}

#[derive(Debug)]
pub struct DeliveryError {
    pub kind: DeliveryErrorKind,
    pub stage: DeliveryStage,
    pub smtp_code: Option<u16>,
    pub message: String,
    pub recipients: Vec<RecipientResult>,
    source: DeliveryFailureSource,
}

impl DeliveryError {
    fn at(mut self, stage: DeliveryStage) -> Self {
        self.stage = stage;
        self
    }

    fn with_smtp_code(mut self, code: u16) -> Self {
        self.smtp_code = Some(code);
        self
    }
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DeliveryError {}

#[derive(Clone)]
pub struct OutboundSmtpClient {
    tls_config: Arc<ClientConfig>,
    connect_timeout: Duration,
    command_timeout: Duration,
    session_timeout: Duration,
    pool: Option<Arc<SmtpConnectionPool>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SmtpPoolConfig {
    max_connections_per_host: usize,
    max_messages_per_connection: usize,
    max_idle_time: Duration,
    max_lifetime: Duration,
    cleanup_interval: Duration,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PoolKey {
    connect_addr: SocketAddr,
    tls_name: String,
    hello_name: String,
    tls_mode: TlsMode,
    attempt_tls: bool,
}

struct PooledConnection {
    session: SmtpSession,
    extensions: Extensions,
    tls_active: bool,
    created_at: Instant,
    last_used_at: Instant,
    message_count: usize,
}

struct SmtpConnectionPool {
    config: SmtpPoolConfig,
    state: Mutex<SmtpPoolState>,
}

struct SmtpPoolState {
    connections: HashMap<PoolKey, VecDeque<PooledConnection>>,
    idle_connections: usize,
    next_cleanup: Instant,
}

impl Default for OutboundSmtpClient {
    fn default() -> Self {
        let native = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let _ = roots.add_parsable_certificates(native.certs);
        if roots.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let tls_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            tls_config: Arc::new(tls_config),
            connect_timeout: Duration::from_secs(10),
            command_timeout: Duration::from_secs(15),
            session_timeout: Duration::from_secs(90),
            pool: None,
        }
    }
}

impl SmtpConnectionPool {
    fn new(config: SmtpPoolConfig) -> Self {
        let now = Instant::now();
        Self {
            config,
            state: Mutex::new(SmtpPoolState {
                connections: HashMap::new(),
                idle_connections: 0,
                next_cleanup: now + config.cleanup_interval,
            }),
        }
    }

    fn checkout(
        &self,
        key: &PoolKey,
        command_timeout: Duration,
        session_deadline: Instant,
        cancellation: CancellationToken,
    ) -> Option<PooledConnection> {
        let now = Instant::now();
        let mut state = self.state.lock().ok()?;
        state.prune_if_due(now, self.config);
        let mut selected = None;
        let mut remove_key = false;
        let mut removed = 0_usize;
        if let Some(connections) = state.connections.get_mut(key) {
            while let Some(connection) = connections.pop_front() {
                removed += 1;
                if self.idle_connection_is_reusable(&connection, now) {
                    selected = Some(connection);
                    break;
                }
            }
            remove_key = connections.is_empty();
        }
        state.idle_connections = state.idle_connections.saturating_sub(removed);
        if remove_key {
            state.connections.remove(key);
        }
        drop(state);
        selected.map(|mut connection| {
            connection
                .session
                .rebind(command_timeout, session_deadline, cancellation);
            connection
        })
    }

    fn can_reset_after_message(&self, connection: &PooledConnection, now: Instant) -> bool {
        connection.message_count < self.config.max_messages_per_connection
            && now.duration_since(connection.created_at) <= self.config.max_lifetime
            && connection.session.is_reusable()
    }

    fn checkin(&self, key: PoolKey, mut connection: PooledConnection) {
        let now = Instant::now();
        connection.last_used_at = now;
        connection.session.make_idle();
        if !self.idle_connection_is_reusable(&connection, now) {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.prune_if_due(now, self.config);
        if state.idle_connections >= MAX_POOL_IDLE_CONNECTIONS {
            state.prune_expired(now, self.config);
        }
        if state.idle_connections >= MAX_POOL_IDLE_CONNECTIONS
            || (!state.connections.contains_key(&key) && state.connections.len() >= MAX_POOL_KEYS)
        {
            return;
        }
        let connections = state.connections.entry(key).or_default();
        if connections.len() >= self.config.max_connections_per_host {
            return;
        }
        connections.push_back(connection);
        state.idle_connections += 1;
    }

    fn idle_connection_is_reusable(&self, connection: &PooledConnection, now: Instant) -> bool {
        connection.message_count < self.config.max_messages_per_connection
            && now.duration_since(connection.last_used_at) <= self.config.max_idle_time
            && now.duration_since(connection.created_at) <= self.config.max_lifetime
            && connection.session.is_reusable()
    }
}

impl SmtpPoolState {
    fn prune_if_due(&mut self, now: Instant, config: SmtpPoolConfig) {
        if now >= self.next_cleanup {
            self.prune_expired(now, config);
        }
    }

    fn prune_expired(&mut self, now: Instant, config: SmtpPoolConfig) {
        for connections in self.connections.values_mut() {
            connections.retain(|connection| {
                connection.message_count < config.max_messages_per_connection
                    && now.duration_since(connection.last_used_at) <= config.max_idle_time
                    && now.duration_since(connection.created_at) <= config.max_lifetime
                    && connection.session.is_reusable()
            });
        }
        self.connections
            .retain(|_, connections| !connections.is_empty());
        self.idle_connections = self.connections.values().map(VecDeque::len).sum();
        self.next_cleanup = now + config.cleanup_interval;
    }
}

impl OutboundSmtpClient {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, DeliveryError> {
        let connect_timeout = outbound_timeout(
            config,
            "lmyzmail.outbound.connection-timeout-ms",
            "botmail.outbound.connection-timeout-ms",
            30_000,
        )?;
        let command_timeout = outbound_timeout(
            config,
            "lmyzmail.outbound.read-timeout-ms",
            "botmail.outbound.read-timeout-ms",
            60_000,
        )?;
        let session_timeout = Duration::from_secs(90)
            .max(connect_timeout)
            .max(command_timeout);
        let pool = outbound_pool_config(config)?
            .map(SmtpConnectionPool::new)
            .map(Arc::new);
        Ok(Self {
            connect_timeout,
            command_timeout,
            session_timeout,
            pool,
            ..Self::default()
        })
    }

    pub fn new(
        tls_config: Arc<ClientConfig>,
        connect_timeout: Duration,
        command_timeout: Duration,
        session_timeout: Duration,
    ) -> Result<Self, DeliveryError> {
        if connect_timeout.is_zero()
            || command_timeout.is_zero()
            || session_timeout < connect_timeout
            || session_timeout < command_timeout
            || session_timeout > Duration::from_secs(15 * 60)
        {
            return Err(error(
                DeliveryErrorKind::Configuration,
                "invalid outbound SMTP deadlines",
            ));
        }
        Ok(Self {
            tls_config,
            connect_timeout,
            command_timeout,
            session_timeout,
            pool: None,
        })
    }

    pub async fn deliver(
        &self,
        request: &DeliveryRequest,
        cancellation: &CancellationToken,
    ) -> Result<DeliveryResult, DeliveryError> {
        match self.prepare(request, cancellation).await? {
            DeliveryPreparation::Complete(result) => Ok(result),
            DeliveryPreparation::CommitReady(prepared) => prepared.commit().await,
        }
    }

    pub async fn prepare(
        &self,
        request: &DeliveryRequest,
        cancellation: &CancellationToken,
    ) -> Result<DeliveryPreparation, DeliveryError> {
        validate_request(request)?;
        let session_deadline = Instant::now() + self.session_timeout;
        let authorized_message = {
            let _timer = StageTimer::start(CoordinatorStage::SmtpAuthorize);
            authorize_message(
                &request.message,
                request.max_message_bytes,
                cancellation,
                self.command_timeout,
                session_deadline,
            )
            .await
        }
        .map_err(|failure| failure.at(DeliveryStage::MessageSource))?;
        self.prepare_with_tls_policy(request, &authorized_message, cancellation, session_deadline)
            .await
    }

    async fn prepare_with_tls_policy(
        &self,
        request: &DeliveryRequest,
        authorized_message: &AuthorizedMessage<'_>,
        cancellation: &CancellationToken,
        session_deadline: Instant,
    ) -> Result<DeliveryPreparation, DeliveryError> {
        let attempt_tls = request.tls_mode != TlsMode::Disabled;
        match self
            .prepare_once(
                request,
                authorized_message,
                cancellation,
                attempt_tls,
                session_deadline,
            )
            .await
        {
            Err(failure)
                if request.tls_mode == TlsMode::Opportunistic
                    && failure.kind == DeliveryErrorKind::Temporary
                    && failure.stage == DeliveryStage::StartTls =>
            {
                self.prepare_once(
                    request,
                    authorized_message,
                    cancellation,
                    false,
                    session_deadline,
                )
                .await
            }
            Err(failure) if request.tls_mode == TlsMode::Required => {
                Err(required_tls_failure(failure))
            }
            result => result,
        }
    }

    async fn prepare_once(
        &self,
        request: &DeliveryRequest,
        authorized_message: &AuthorizedMessage<'_>,
        cancellation: &CancellationToken,
        attempt_tls: bool,
        session_deadline: Instant,
    ) -> Result<DeliveryPreparation, DeliveryError> {
        let pool_key = self.pool.as_ref().map(|_| PoolKey {
            connect_addr: request.endpoint.connect_addr,
            tls_name: request.endpoint.tls_name.clone(),
            hello_name: request.hello_name.clone(),
            tls_mode: request.tls_mode,
            attempt_tls,
        });
        let pooled = self
            .pool
            .as_ref()
            .zip(pool_key.as_ref())
            .and_then(|(pool, key)| {
                pool.checkout(
                    key,
                    self.command_timeout,
                    session_deadline,
                    cancellation.clone(),
                )
            });
        let mut connection = if let Some(connection) = pooled {
            connection
        } else {
            let created_at = Instant::now();
            let stream = {
                let _timer = StageTimer::start(CoordinatorStage::SmtpConnect);
                io_deadline(
                    cancellation,
                    self.connect_timeout,
                    session_deadline,
                    TcpStream::connect(request.endpoint.connect_addr),
                    DeliveryErrorKind::Temporary,
                    "SMTP connect",
                )
                .await
            }
            .map_err(|failure| failure.at(DeliveryStage::Connect))?;
            stream.set_nodelay(true).map_err(|_| {
                error(
                    DeliveryErrorKind::Temporary,
                    "SMTP socket configuration failed",
                )
                .at(DeliveryStage::Connect)
            })?;
            let mut session = SmtpSession::new(
                stream,
                self.command_timeout,
                session_deadline,
                cancellation.clone(),
            );
            let greeting = {
                let _timer = StageTimer::start(CoordinatorStage::SmtpGreeting);
                session.read_reply(false).await
            }
            .map_err(|failure| failure.at(DeliveryStage::Greeting))?;
            if greeting.code != 220 {
                return Err(reply_error(
                    DeliveryStage::Greeting,
                    true,
                    "SMTP greeting rejected",
                    &greeting,
                ));
            }
            let mut extensions = {
                let _timer = StageTimer::start(CoordinatorStage::SmtpEhlo);
                session.ehlo(&request.hello_name).await
            }?;
            let mut tls_active = false;
            if attempt_tls && extensions.has("STARTTLS") {
                let _timer = StageTimer::start(CoordinatorStage::SmtpStartTls);
                let reply = session
                    .command("STARTTLS")
                    .await
                    .map_err(|failure| failure.at(DeliveryStage::StartTls))?;
                if reply.code != 220 {
                    return Err(error(
                        DeliveryErrorKind::Temporary,
                        format!("STARTTLS command rejected: {}", reply.summary()),
                    )
                    .at(DeliveryStage::StartTls)
                    .with_smtp_code(reply.code));
                }
                let server_name =
                    ServerName::try_from(request.endpoint.tls_name.clone()).map_err(|_| {
                        error(
                            DeliveryErrorKind::Configuration,
                            "invalid outbound SMTP TLS name",
                        )
                    })?;
                session
                    .start_tls(
                        TlsConnector::from(Arc::clone(&self.tls_config)),
                        server_name,
                    )
                    .await
                    .map_err(|mut failure| {
                        failure.message =
                            format!("STARTTLS negotiation failed: {}", failure.message);
                        failure.at(DeliveryStage::StartTls)
                    })?;
                tls_active = true;
                extensions = session
                    .ehlo(&request.hello_name)
                    .await
                    .map_err(|mut failure| {
                        failure.message = format!("post-STARTTLS EHLO failed: {}", failure.message);
                        failure.at(DeliveryStage::StartTls)
                    })?;
            } else if request.tls_mode == TlsMode::Required {
                return Err(error(
                    DeliveryErrorKind::Temporary,
                    "MTA-STS policy requires TLS, but server does not support STARTTLS",
                )
                .at(DeliveryStage::StartTls));
            }
            let now = Instant::now();
            PooledConnection {
                session,
                extensions,
                tls_active,
                created_at,
                last_used_at: now,
                message_count: 0,
            }
        };
        let smtp_utf8_supported = connection.extensions.has("SMTPUTF8");
        let pipelining = connection.extensions.has("PIPELINING");
        let tls_active = connection.tls_active;

        let envelope = prepare_envelope(
            &request.envelope_from,
            &request.recipients,
            smtp_utf8_supported,
        )
        .map_err(|failure| failure.at(DeliveryStage::Envelope))?;
        let (mail_reply, recipient_replies) = {
            let _timer = StageTimer::start(CoordinatorStage::SmtpEnvelope);
            connection
                .session
                .envelope(
                    &envelope.sender,
                    &envelope.recipients,
                    envelope.smtp_utf8,
                    pipelining,
                )
                .await
        }
        .map_err(|failure| failure.at(DeliveryStage::Envelope))?;
        if mail_reply.code != 250 {
            return Err(if matches!(mail_reply.code / 100, 4 | 5) {
                reply_error(
                    DeliveryStage::Envelope,
                    false,
                    "MAIL FROM rejected",
                    &mail_reply,
                )
            } else {
                protocol_error(false, "unexpected MAIL FROM reply code")
                    .at(DeliveryStage::Envelope)
                    .with_smtp_code(mail_reply.code)
            });
        }
        let mut recipient_results = Vec::with_capacity(request.recipients.len());
        for (recipient, reply) in request.recipients.iter().zip(recipient_replies) {
            let Some(status) = recipient_status(reply.code) else {
                let mut failure = protocol_error(false, "unexpected RCPT TO reply code")
                    .at(DeliveryStage::Envelope)
                    .with_smtp_code(reply.code);
                failure.recipients = recipient_results;
                return Err(failure);
            };
            recipient_results.push(RecipientResult {
                recipient: recipient.clone(),
                status,
                code: reply.code,
                reply: reply.summary(),
            });
        }
        let accepted = recipient_results
            .iter()
            .filter(|result| result.status == RecipientStatus::Accepted)
            .count();
        if accepted == 0 {
            return Ok(DeliveryPreparation::Complete(DeliveryResult {
                recipients: recipient_results,
                data_status: DataStatus::NotAttempted,
                data_code: None,
                data_reply: None,
                tls: tls_active,
                smtp_utf8: envelope.smtp_utf8,
                pipelining,
            }));
        }

        let mut message = {
            let _timer = StageTimer::start(CoordinatorStage::SmtpMessagePrepare);
            connection
                .session
                .prepare_message(authorized_message, request.max_message_bytes)
                .await
        }
        .map_err(|mut failure| {
            failure.stage = DeliveryStage::MessageSource;
            failure.recipients = recipient_results.clone();
            failure
        })?;
        let data_ready = {
            let _timer = StageTimer::start(CoordinatorStage::SmtpDataReady);
            connection.session.command("DATA").await
        }
        .map_err(|mut failure| {
            failure.stage = DeliveryStage::DataCommand;
            failure.recipients = recipient_results.clone();
            failure
        })?;
        if data_ready.code != 354 {
            let Some(status) = rejected_data_status(data_ready.code) else {
                let mut failure = protocol_error(false, "unexpected DATA readiness reply code")
                    .at(DeliveryStage::DataCommand)
                    .with_smtp_code(data_ready.code);
                failure.recipients = recipient_results;
                return Err(failure);
            };
            return Ok(DeliveryPreparation::Complete(DeliveryResult {
                recipients: recipient_results,
                data_status: status,
                data_code: Some(data_ready.code),
                data_reply: Some(data_ready.summary()),
                tls: tls_active,
                smtp_utf8: envelope.smtp_utf8,
                pipelining,
            }));
        }
        {
            let _timer = StageTimer::start(CoordinatorStage::SmtpBodyWrite);
            connection
                .session
                .write_message_body(&mut message, request.max_message_bytes)
                .await
        }
        .map_err(|mut failure| {
            if failure.stage == DeliveryStage::Request {
                failure.stage = DeliveryStage::DataBody;
            }
            failure.recipients = recipient_results.clone();
            failure
        })?;
        Ok(DeliveryPreparation::CommitReady(PreparedDelivery {
            connection,
            pool_return: self.pool.as_ref().cloned().zip(pool_key),
            recipients: recipient_results,
            tls: tls_active,
            smtp_utf8: envelope.smtp_utf8,
            pipelining,
        }))
    }
}

impl PreparedDelivery {
    pub fn recipients(&self) -> &[RecipientResult] {
        &self.recipients
    }

    pub async fn commit(self) -> Result<DeliveryResult, DeliveryError> {
        let Self {
            mut connection,
            pool_return,
            recipients,
            tls,
            smtp_utf8,
            pipelining,
        } = self;
        {
            let _timer = StageTimer::start(CoordinatorStage::SmtpFinalDot);
            connection.session.write_all(b".\r\n", true).await
        }
        .map_err(|mut failure| {
            failure.stage = DeliveryStage::DataFinal;
            failure.recipients = recipients.clone();
            failure
        })?;
        let data_result = {
            let _timer = StageTimer::start(CoordinatorStage::SmtpFinalReply);
            connection.session.read_reply(true).await
        }
        .map_err(|mut failure| {
            failure.stage = DeliveryStage::DataFinal;
            failure.recipients = recipients.clone();
            failure
        })?;
        let Some(status) = final_data_status(data_result.code) else {
            let mut failure = protocol_error(true, "unexpected final DATA reply code")
                .at(DeliveryStage::DataFinal)
                .with_smtp_code(data_result.code);
            failure.recipients = recipients;
            return Err(failure);
        };
        if status == DataStatus::Accepted {
            let _timer = StageTimer::start(CoordinatorStage::SmtpQuit);
            connection.message_count = connection.message_count.saturating_add(1);
            connection.last_used_at = Instant::now();
            if let Some((pool, key)) = pool_return {
                if pool.can_reset_after_message(&connection, connection.last_used_at) {
                    connection.session.refresh_deadline();
                    if connection
                        .session
                        .command("RSET")
                        .await
                        .is_ok_and(|reply| reply.code == 250)
                    {
                        pool.checkin(key, connection);
                    }
                }
            } else {
                let _ = connection.session.command("QUIT").await;
            }
        }
        Ok(DeliveryResult {
            recipients,
            data_status: status,
            data_code: Some(data_result.code),
            data_reply: Some(data_result.summary()),
            tls,
            smtp_utf8,
            pipelining,
        })
    }
}

#[derive(Debug)]
struct Envelope {
    sender: String,
    recipients: Vec<String>,
    smtp_utf8: bool,
}

#[derive(Default)]
struct Extensions {
    names: Vec<String>,
}

impl Extensions {
    fn has(&self, name: &str) -> bool {
        self.names.iter().any(|value| value == name)
    }
}

struct Reply {
    code: u16,
    lines: Vec<Vec<u8>>,
}

impl Reply {
    fn summary(&self) -> String {
        let joined = self
            .lines
            .iter()
            .map(|line| String::from_utf8_lossy(&line[4..line.len() - 2]))
            .collect::<Vec<_>>()
            .join(" | ");
        joined
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .take(MAX_REPLY_SUMMARY_CHARS)
            .collect()
    }
}

enum Transport {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Transport {
    #[cfg(target_os = "linux")]
    fn idle_socket_is_quiet(&self) -> bool {
        use rustix::net::{RecvFlags, recv};

        let stream = match self {
            Self::Plain(stream) => stream,
            Self::Tls(stream) => stream.get_ref().0,
        };
        let mut byte = [0_u8; 1];
        matches!(
            recv(
                stream,
                &mut byte,
                RecvFlags::PEEK | RecvFlags::DONTWAIT
            ),
            Err(error) if error == rustix::io::Errno::AGAIN
        )
    }

    #[cfg(not(target_os = "linux"))]
    fn idle_socket_is_quiet(&self) -> bool {
        true
    }
}

enum AuthorizedMessage<'a> {
    Bytes(&'a [u8]),
    File(Box<AuthorizedFile>),
}

struct AuthorizedFile {
    source: TrustedFileSource,
    proof: FileProof,
}

enum PreparedMessage<'a> {
    Bytes(&'a [u8]),
    File(Box<PreparedFile>),
}

struct PreparedFile {
    file: File,
    source: TrustedFileSource,
    proof: FileProof,
}

async fn authorize_message<'a>(
    source: &'a MessageSource,
    max_message_bytes: u64,
    cancellation: &CancellationToken,
    command_timeout: Duration,
    session_deadline: Instant,
) -> Result<AuthorizedMessage<'a>, DeliveryError> {
    // File delivery deliberately pays three bounded verification passes per
    // SMTP attempt (authorization, retained-fd pre-DATA, and post-DATA) in
    // addition to the streamed pass. This avoids whole-message buffering while
    // making every path/identity/hash transition fail closed.
    match source {
        MessageSource::Bytes(bytes) => {
            if bytes.len() as u64 > max_message_bytes {
                return Err(error(
                    DeliveryErrorKind::Permanent,
                    "outbound message exceeds configured size",
                ));
            }
            Ok(AuthorizedMessage::Bytes(bytes))
        }
        MessageSource::File(source) => {
            let authority = source.authority.ok_or_else(|| {
                message_source_failure(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "outbound message source has no durable content authority",
                ))
            })?;
            if authority.size > max_message_bytes {
                return Err(error(
                    DeliveryErrorKind::Permanent,
                    "outbound message exceeds configured size",
                ));
            }
            let file = source
                .open_initial(max_message_bytes)
                .map_err(message_source_failure)?;
            let mut file = File::from_std(file);
            let proof = hash_verified_file(
                &mut file,
                source.initial_identity,
                max_message_bytes,
                cancellation,
                command_timeout,
                session_deadline,
                "outbound message source authorization",
            )
            .await?;
            if proof.identity.size != authority.size || proof.sha256 != authority.sha256 {
                return Err(message_source_failure(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "outbound message source conflicts with durable content authority",
                )));
            }
            Ok(AuthorizedMessage::File(Box::new(AuthorizedFile {
                source: source.clone(),
                proof,
            })))
        }
    }
}

async fn hash_verified_file(
    file: &mut File,
    expected: FileIdentity,
    max_message_bytes: u64,
    cancellation: &CancellationToken,
    command_timeout: Duration,
    session_deadline: Instant,
    operation: &'static str,
) -> Result<FileProof, DeliveryError> {
    let before = io_deadline(
        cancellation,
        command_timeout,
        session_deadline,
        file.metadata(),
        DeliveryErrorKind::Temporary,
        operation,
    )
    .await
    .and_then(|metadata| file_identity_from_metadata(&metadata).map_err(message_source_failure))?;
    validate_file_identity(&before, expected.device, max_message_bytes)
        .map_err(message_source_failure)?;
    if before != expected {
        return Err(message_source_failure(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "outbound message source identity changed",
        )));
    }
    io_deadline(
        cancellation,
        command_timeout,
        session_deadline,
        file.seek(SeekFrom::Start(0)),
        DeliveryErrorKind::Temporary,
        operation,
    )
    .await?;
    let mut digest = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; MESSAGE_CHUNK_BYTES];
    loop {
        let read = io_deadline(
            cancellation,
            command_timeout,
            session_deadline,
            file.read(&mut buffer),
            DeliveryErrorKind::Temporary,
            operation,
        )
        .await?;
        if read == 0 {
            break;
        }
        observed = observed.saturating_add(read as u64);
        if observed > max_message_bytes {
            return Err(error(
                DeliveryErrorKind::Permanent,
                "outbound message exceeds configured size",
            ));
        }
        digest.update(&buffer[..read]);
    }
    if observed != expected.size {
        return Err(message_source_failure(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "outbound message source size changed",
        )));
    }
    let after = io_deadline(
        cancellation,
        command_timeout,
        session_deadline,
        file.metadata(),
        DeliveryErrorKind::Temporary,
        operation,
    )
    .await
    .and_then(|metadata| file_identity_from_metadata(&metadata).map_err(message_source_failure))?;
    if after != expected {
        return Err(message_source_failure(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "outbound message source changed while hashing",
        )));
    }
    io_deadline(
        cancellation,
        command_timeout,
        session_deadline,
        file.seek(SeekFrom::Start(0)),
        DeliveryErrorKind::Temporary,
        operation,
    )
    .await?;
    Ok(FileProof {
        identity: expected,
        sha256: digest.finalize().into(),
    })
}

fn message_source_failure(_: std::io::Error) -> DeliveryError {
    error(
        DeliveryErrorKind::Permanent,
        "outbound message source failed trusted-root verification",
    )
}

struct SmtpSession {
    transport: Option<Transport>,
    read_buffer: Vec<u8>,
    command_timeout: Duration,
    session_deadline: Instant,
    cancellation: CancellationToken,
    #[cfg(test)]
    data_chunk_hook: Option<Arc<dyn Fn(u64) + Send + Sync>>,
}

impl SmtpSession {
    fn new(
        stream: TcpStream,
        command_timeout: Duration,
        session_deadline: Instant,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            transport: Some(Transport::Plain(stream)),
            read_buffer: Vec::with_capacity(READ_CHUNK_BYTES),
            command_timeout,
            session_deadline,
            cancellation,
            #[cfg(test)]
            data_chunk_hook: None,
        }
    }

    fn rebind(
        &mut self,
        command_timeout: Duration,
        session_deadline: Instant,
        cancellation: CancellationToken,
    ) {
        self.command_timeout = command_timeout;
        self.session_deadline = session_deadline;
        self.cancellation = cancellation;
    }

    fn refresh_deadline(&mut self) {
        self.session_deadline = Instant::now() + self.command_timeout;
    }

    fn make_idle(&mut self) {
        self.cancellation = CancellationToken::new();
        self.refresh_deadline();
    }

    fn is_reusable(&self) -> bool {
        self.transport
            .as_ref()
            .is_some_and(Transport::idle_socket_is_quiet)
            && self.read_buffer.is_empty()
    }

    async fn ehlo(&mut self, hello_name: &str) -> Result<Extensions, DeliveryError> {
        let reply = self
            .command(&format!("EHLO {hello_name}"))
            .await
            .map_err(|failure| failure.at(DeliveryStage::Ehlo))?;
        if reply.code != 250 {
            let helo = self
                .command(&format!("HELO {hello_name}"))
                .await
                .map_err(|failure| failure.at(DeliveryStage::Ehlo))?;
            if helo.code != 250 {
                return Err(reply_error(
                    DeliveryStage::Ehlo,
                    true,
                    "EHLO/HELO rejected",
                    &helo,
                ));
            }
            return Ok(Extensions::default());
        }
        let mut names = Vec::new();
        for line in &reply.lines {
            let value = &line[4..line.len() - 2];
            let name = value
                .split(|byte| byte.is_ascii_whitespace())
                .next()
                .unwrap_or_default();
            if !name.is_empty() && name.is_ascii() {
                names.push(String::from_utf8_lossy(name).to_ascii_uppercase());
            }
        }
        Ok(Extensions { names })
    }

    async fn envelope(
        &mut self,
        sender: &str,
        recipients: &[String],
        smtp_utf8: bool,
        pipelining: bool,
    ) -> Result<(Reply, Vec<Reply>), DeliveryError> {
        let mail = if smtp_utf8 {
            format!("MAIL FROM:<{sender}> SMTPUTF8\r\n")
        } else {
            format!("MAIL FROM:<{sender}>\r\n")
        };
        if pipelining {
            let mut commands = Vec::with_capacity(mail.len() + recipients.len() * 300);
            commands.extend_from_slice(mail.as_bytes());
            for recipient in recipients {
                commands.extend_from_slice(format!("RCPT TO:<{recipient}>\r\n").as_bytes());
                if commands.len() > MAX_PIPELINE_BYTES {
                    return Err(error(
                        DeliveryErrorKind::Configuration,
                        "SMTP command pipeline exceeds its byte budget",
                    ));
                }
            }
            self.write_all(&commands, false).await?;
            let mail_reply = self.read_reply(false).await?;
            let mut replies = Vec::with_capacity(recipients.len());
            for _ in recipients {
                replies.push(self.read_reply(false).await?);
            }
            Ok((mail_reply, replies))
        } else {
            self.write_all(mail.as_bytes(), false).await?;
            let mail_reply = self.read_reply(false).await?;
            let mut replies = Vec::with_capacity(recipients.len());
            if mail_reply.code / 100 == 2 {
                for recipient in recipients {
                    replies.push(self.command(&format!("RCPT TO:<{recipient}>")).await?);
                }
            } else {
                replies.resize_with(recipients.len(), || Reply {
                    code: 503,
                    lines: vec![b"503 5.5.1 MAIL FROM rejected\r\n".to_vec()],
                });
            }
            Ok((mail_reply, replies))
        }
    }

    async fn command(&mut self, command: &str) -> Result<Reply, DeliveryError> {
        if command.is_empty()
            || command.len() + 2 > MAX_REPLY_LINE_BYTES
            || command
                .bytes()
                .any(|value| matches!(value, b'\r' | b'\n' | 0))
        {
            return Err(error(
                DeliveryErrorKind::Configuration,
                "invalid outbound SMTP command",
            ));
        }
        let mut bytes = Vec::with_capacity(command.len() + 2);
        bytes.extend_from_slice(command.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        self.write_all(&bytes, false).await?;
        self.read_reply(false).await
    }

    async fn start_tls(
        &mut self,
        connector: TlsConnector,
        server_name: ServerName<'static>,
    ) -> Result<(), DeliveryError> {
        if !self.read_buffer.is_empty() {
            return Err(error(
                DeliveryErrorKind::Protocol,
                "SMTP server sent plaintext bytes after STARTTLS readiness",
            ));
        }
        let Some(Transport::Plain(stream)) = self.transport.take() else {
            return Err(error(
                DeliveryErrorKind::Protocol,
                "SMTP STARTTLS attempted in an invalid state",
            ));
        };
        let tls = io_deadline(
            &self.cancellation,
            self.command_timeout,
            self.session_deadline,
            connector.connect(server_name, stream),
            DeliveryErrorKind::Temporary,
            "SMTP TLS handshake",
        )
        .await?;
        self.transport = Some(Transport::Tls(Box::new(tls)));
        Ok(())
    }

    async fn read_reply(&mut self, after_data: bool) -> Result<Reply, DeliveryError> {
        let mut lines = Vec::new();
        let mut total = 0;
        let mut expected_code = None;
        loop {
            if lines.len() >= MAX_REPLY_LINES || total >= MAX_REPLY_BYTES {
                return Err(protocol_error(
                    after_data,
                    "SMTP reply exceeded its line or byte budget",
                ));
            }
            let line = self.read_line(after_data).await?;
            total += line.len();
            if total > MAX_REPLY_BYTES {
                return Err(protocol_error(
                    after_data,
                    "SMTP reply exceeded its line or byte budget",
                ));
            }
            if line.len() < 5
                || !line[..3].iter().all(u8::is_ascii_digit)
                || !matches!(line[3], b' ' | b'-')
            {
                return Err(protocol_error(after_data, "malformed SMTP reply"));
            }
            let code = u16::from(line[0] - b'0') * 100
                + u16::from(line[1] - b'0') * 10
                + u16::from(line[2] - b'0');
            if !(200..=599).contains(&code) || expected_code.is_some_and(|value| value != code) {
                return Err(protocol_error(after_data, "inconsistent SMTP reply code"));
            }
            expected_code = Some(code);
            let final_line = line[3] == b' ';
            lines.push(line);
            if final_line {
                return Ok(Reply { code, lines });
            }
        }
    }

    async fn read_line(&mut self, after_data: bool) -> Result<Vec<u8>, DeliveryError> {
        loop {
            if let Some(index) = self.read_buffer.iter().position(|value| *value == b'\n') {
                if index + 1 > MAX_REPLY_LINE_BYTES {
                    return Err(protocol_error(
                        after_data,
                        "SMTP reply line exceeded its byte budget",
                    ));
                }
                let line = self.read_buffer.drain(..=index).collect::<Vec<_>>();
                if !line.ends_with(b"\r\n") {
                    return Err(protocol_error(
                        after_data,
                        "SMTP reply did not use CRLF framing",
                    ));
                }
                return Ok(line);
            }
            if self.read_buffer.len() >= MAX_REPLY_LINE_BYTES {
                return Err(protocol_error(
                    after_data,
                    "SMTP reply line exceeded its byte budget",
                ));
            }
            let mut chunk = [0_u8; READ_CHUNK_BYTES];
            let read = self.read(&mut chunk, after_data).await?;
            if read == 0 {
                return Err(error(
                    if after_data {
                        DeliveryErrorKind::Ambiguous
                    } else {
                        DeliveryErrorKind::Temporary
                    },
                    if after_data {
                        "SMTP connection closed after DATA body"
                    } else {
                        "SMTP connection closed before transaction completion"
                    },
                ));
            }
            self.read_buffer.extend_from_slice(&chunk[..read]);
        }
    }

    async fn prepare_message<'a>(
        &self,
        source: &AuthorizedMessage<'a>,
        max_message_bytes: u64,
    ) -> Result<PreparedMessage<'a>, DeliveryError> {
        match source {
            AuthorizedMessage::Bytes(bytes) => Ok(PreparedMessage::Bytes(bytes)),
            AuthorizedMessage::File(authorized) => {
                let file = authorized
                    .source
                    .open_matching(authorized.proof.identity, max_message_bytes)
                    .map_err(message_source_failure)?;
                let mut file = File::from_std(file);
                let observed = hash_verified_file(
                    &mut file,
                    authorized.proof.identity,
                    max_message_bytes,
                    &self.cancellation,
                    self.command_timeout,
                    self.session_deadline,
                    "outbound message source pre-DATA verification",
                )
                .await?;
                if observed != authorized.proof {
                    return Err(message_source_failure(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "outbound message source digest changed before DATA",
                    )));
                }
                Ok(PreparedMessage::File(Box::new(PreparedFile {
                    file,
                    source: authorized.source.clone(),
                    proof: authorized.proof,
                })))
            }
        }
    }

    async fn write_message_body(
        &mut self,
        source: &mut PreparedMessage<'_>,
        max_message_bytes: u64,
    ) -> Result<(), DeliveryError> {
        let mut state = DotStuffState::default();
        match source {
            PreparedMessage::Bytes(bytes) => {
                state.input_bytes = bytes.len() as u64;
                self.write_dot_stuffed(bytes, &mut state).await?;
            }
            PreparedMessage::File(prepared) => {
                let mut digest = Sha256::new();
                let mut buffer = [0_u8; MESSAGE_CHUNK_BYTES];
                loop {
                    let read = io_deadline(
                        &self.cancellation,
                        self.command_timeout,
                        self.session_deadline,
                        prepared.file.read(&mut buffer),
                        DeliveryErrorKind::Temporary,
                        "outbound message source read",
                    )
                    .await?;
                    if read == 0 {
                        break;
                    }
                    state.input_bytes = state.input_bytes.saturating_add(read as u64);
                    if state.input_bytes > max_message_bytes {
                        return Err(error(
                            DeliveryErrorKind::Permanent,
                            "outbound message exceeds configured size",
                        ));
                    }
                    digest.update(&buffer[..read]);
                    #[cfg(test)]
                    if let Some(hook) = self.data_chunk_hook.as_ref() {
                        hook(state.input_bytes);
                    }
                    self.write_dot_stuffed(&buffer[..read], &mut state).await?;
                }
                let streamed_sha256: [u8; 32] = digest.finalize().into();
                if state.input_bytes != prepared.proof.identity.size
                    || streamed_sha256 != prepared.proof.sha256
                {
                    return Err(message_source_failure(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "outbound message source changed during DATA",
                    )));
                }
                let streamed_identity = self
                    .file_deadline(
                        prepared.file.metadata(),
                        "outbound message source post-DATA metadata",
                    )
                    .await
                    .and_then(|metadata| {
                        file_identity_from_metadata(&metadata).map_err(message_source_failure)
                    })?;
                if streamed_identity != prepared.proof.identity {
                    return Err(message_source_failure(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "outbound message source identity changed during DATA",
                    )));
                }

                // A complete post-stream pass is intentionally paid before the
                // SMTP terminator. This bounds replacement/in-place-write races
                // without ever buffering the message in memory.
                let post_file = prepared
                    .source
                    .open_matching(prepared.proof.identity, max_message_bytes)
                    .map_err(message_source_failure)?;
                let mut post_file = File::from_std(post_file);
                let post = hash_verified_file(
                    &mut post_file,
                    prepared.proof.identity,
                    max_message_bytes,
                    &self.cancellation,
                    self.command_timeout,
                    self.session_deadline,
                    "outbound message source post-DATA verification",
                )
                .await?;
                if post != prepared.proof {
                    return Err(message_source_failure(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "outbound message source changed after DATA",
                    )));
                }
            }
        }
        let mut ending = Vec::with_capacity(2);
        if state.pending_cr {
            ending.extend_from_slice(b"\r\n");
            state.at_line_start = true;
            state.pending_cr = false;
        }
        if state.wrote_anything && !state.at_line_start {
            ending.extend_from_slice(b"\r\n");
        }
        if !ending.is_empty() {
            self.write_all(&ending, false).await?;
        }
        Ok(())
    }

    async fn file_deadline<T, F>(&self, future: F, operation: &str) -> Result<T, DeliveryError>
    where
        F: Future<Output = std::io::Result<T>>,
    {
        let operation_deadline = (Instant::now() + self.command_timeout).min(self.session_deadline);
        tokio::select! {
            _ = self.cancellation.cancelled() => Err(error(
                DeliveryErrorKind::Cancelled,
                format!("{operation} cancelled"),
            ).at(DeliveryStage::MessageSource)),
            result = timeout_at(operation_deadline, future) => match result {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(failure)) => Err(error(
                    file_error_kind(failure.kind()),
                    format!("{operation} is unavailable"),
                ).at(DeliveryStage::MessageSource)),
                Err(_) => Err(error(
                    DeliveryErrorKind::Temporary,
                    format!("{operation} deadline exceeded"),
                ).at(DeliveryStage::MessageSource)),
            }
        }
    }

    async fn write_dot_stuffed(
        &mut self,
        input: &[u8],
        state: &mut DotStuffState,
    ) -> Result<(), DeliveryError> {
        let mut output = Vec::with_capacity(MESSAGE_CHUNK_BYTES + 2);
        for byte in input {
            state.wrote_anything = true;
            match *byte {
                b'\n' => {
                    output.extend_from_slice(b"\r\n");
                    state.at_line_start = true;
                    state.pending_cr = false;
                }
                b'\r' => {
                    if state.pending_cr {
                        output.extend_from_slice(b"\r\n");
                        state.at_line_start = true;
                    }
                    state.pending_cr = true;
                }
                value => {
                    if state.pending_cr {
                        output.extend_from_slice(b"\r\n");
                        state.at_line_start = true;
                        state.pending_cr = false;
                    }
                    if state.at_line_start && value == b'.' {
                        output.push(b'.');
                    }
                    output.push(value);
                    state.at_line_start = false;
                }
            }
            if output.len() >= MESSAGE_CHUNK_BYTES {
                self.write_all(&output, false).await?;
                output.clear();
            }
        }
        if !output.is_empty() {
            self.write_all(&output, false).await?;
        }
        Ok(())
    }

    async fn read(&mut self, buffer: &mut [u8], after_data: bool) -> Result<usize, DeliveryError> {
        let future = async {
            match self.transport.as_mut() {
                Some(Transport::Plain(stream)) => stream.read(buffer).await,
                Some(Transport::Tls(stream)) => stream.read(buffer).await,
                None => Err(std::io::Error::other("SMTP transport unavailable")),
            }
        };
        io_deadline(
            &self.cancellation,
            self.command_timeout,
            self.session_deadline,
            future,
            if after_data {
                DeliveryErrorKind::Ambiguous
            } else {
                DeliveryErrorKind::Temporary
            },
            "SMTP read",
        )
        .await
    }

    async fn write_all(&mut self, bytes: &[u8], after_data: bool) -> Result<(), DeliveryError> {
        let future = async {
            match self.transport.as_mut() {
                Some(Transport::Plain(stream)) => stream.write_all(bytes).await,
                Some(Transport::Tls(stream)) => stream.write_all(bytes).await,
                None => Err(std::io::Error::other("SMTP transport unavailable")),
            }
        };
        io_deadline(
            &self.cancellation,
            self.command_timeout,
            self.session_deadline,
            future,
            if after_data {
                DeliveryErrorKind::Ambiguous
            } else {
                DeliveryErrorKind::Temporary
            },
            "SMTP write",
        )
        .await
    }
}

struct DotStuffState {
    input_bytes: u64,
    at_line_start: bool,
    wrote_anything: bool,
    pending_cr: bool,
}

impl Default for DotStuffState {
    fn default() -> Self {
        Self {
            input_bytes: 0,
            at_line_start: true,
            wrote_anything: false,
            pending_cr: false,
        }
    }
}

fn validate_request(request: &DeliveryRequest) -> Result<(), DeliveryError> {
    validate_host(&request.endpoint.tls_name)?;
    validate_host(&request.hello_name)?;
    if request.max_message_bytes == 0
        || request.recipients.is_empty()
        || request.recipients.len() > MAX_RECIPIENTS
    {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP request bounds",
        ));
    }
    if !request.envelope_from.is_empty() {
        validate_address(&request.envelope_from)?;
    }
    for recipient in &request.recipients {
        validate_address(recipient)?;
    }
    Ok(())
}

pub(crate) fn is_public_smtp_ip(value: IpAddr) -> bool {
    match value {
        IpAddr::V4(value) => {
            let [first, second, third, _] = value.octets();
            !(value.is_unspecified()
                || value.is_loopback()
                || value.is_private()
                || value.is_link_local()
                || value.is_multicast()
                || value.is_broadcast()
                || value.is_documentation()
                || first == 0
                || (first == 100 && (64..=127).contains(&second))
                || (first == 192 && second == 0 && third == 0)
                || (first == 192 && second == 88 && third == 99)
                || (first == 198 && matches!(second, 18 | 19))
                || first >= 240)
        }
        IpAddr::V6(value) => {
            let segments = value.segments();
            if segments[0] & 0xe000 != 0x2000
                || (segments[0] == 0x2001 && matches!(segments[1], 0 | 0x0db8))
            {
                return false;
            }
            if segments[0] == 0x2002 {
                let embedded = std::net::Ipv4Addr::new(
                    (segments[1] >> 8) as u8,
                    segments[1] as u8,
                    (segments[2] >> 8) as u8,
                    segments[2] as u8,
                );
                return is_public_smtp_ip(IpAddr::V4(embedded));
            }
            true
        }
    }
}

fn validate_host(value: &str) -> Result<(), DeliveryError> {
    if value.is_empty()
        || value.len() > MAX_HOST_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP host name",
        ));
    }
    let domain = value.strip_suffix('.').unwrap_or(value);
    if domain.parse::<IpAddr>().is_err() && domain_to_ascii_strict(domain).is_err() {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP host name",
        ));
    }
    Ok(())
}

fn validate_address(value: &str) -> Result<(), DeliveryError> {
    let parts = value.rsplit_once('@');
    if value.is_empty()
        || value.len() > MAX_ADDRESS_BYTES
        || value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '<' | '>')
        })
        || parts.is_none()
    {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP envelope address",
        ));
    }
    let (local, domain) = parts.unwrap();
    let local_is_valid = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.chars().all(|character| {
            !character.is_ascii()
                || character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    '.' | '!'
                        | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '/'
                        | '='
                        | '?'
                        | '^'
                        | '_'
                        | '`'
                        | '{'
                        | '|'
                        | '}'
                        | '~'
                )
        });
    let ascii_domain = domain_to_ascii_strict(domain).ok();
    if !local_is_valid
        || domain.is_empty()
        || local.contains('@')
        || ascii_domain.as_deref().is_none_or(|domain| {
            !valid_ascii_domain(domain) || local.len() + 1 + domain.len() > MAX_ADDRESS_BYTES
        })
    {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP envelope address",
        ));
    }
    Ok(())
}

fn valid_ascii_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn prepare_envelope(
    sender: &str,
    recipients: &[String],
    server_supports_smtp_utf8: bool,
) -> Result<Envelope, DeliveryError> {
    let needs_smtp_utf8 = !sender.is_ascii() || recipients.iter().any(|value| !value.is_ascii());
    if !needs_smtp_utf8 {
        return Ok(Envelope {
            sender: sender.to_owned(),
            recipients: recipients.to_vec(),
            smtp_utf8: false,
        });
    }
    if server_supports_smtp_utf8 {
        return Ok(Envelope {
            sender: sender.to_owned(),
            recipients: recipients.to_vec(),
            smtp_utf8: true,
        });
    }
    Ok(Envelope {
        sender: if sender.is_empty() {
            String::new()
        } else {
            downgrade_domain(sender)?
        },
        recipients: recipients
            .iter()
            .map(|value| downgrade_domain(value))
            .collect::<Result<_, _>>()?,
        smtp_utf8: false,
    })
}

fn downgrade_domain(address: &str) -> Result<String, DeliveryError> {
    let (local, domain) = address.rsplit_once('@').ok_or_else(|| {
        error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP envelope address",
        )
    })?;
    if !local.is_ascii() {
        return Err(error(
            DeliveryErrorKind::Permanent,
            "SMTPUTF8 is required for a non-ASCII local part",
        ));
    }
    let domain = domain_to_ascii_strict(domain).map_err(|_| {
        error(
            DeliveryErrorKind::Permanent,
            "internationalized envelope domain cannot be downgraded",
        )
    })?;
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

fn recipient_status(code: u16) -> Option<RecipientStatus> {
    match code {
        250..=252 => Some(RecipientStatus::Accepted),
        400..=499 => Some(RecipientStatus::TemporaryFailure),
        500..=599 => Some(RecipientStatus::PermanentFailure),
        _ => None,
    }
}

fn rejected_data_status(code: u16) -> Option<DataStatus> {
    match code {
        400..=499 => Some(DataStatus::TemporaryFailure),
        500..=599 => Some(DataStatus::PermanentFailure),
        _ => None,
    }
}

fn final_data_status(code: u16) -> Option<DataStatus> {
    match code {
        250 => Some(DataStatus::Accepted),
        400..=499 => Some(DataStatus::TemporaryFailure),
        500..=599 => Some(DataStatus::PermanentFailure),
        _ => None,
    }
}

fn reply_error(
    stage: DeliveryStage,
    endpoint_scoped: bool,
    context: &str,
    reply: &Reply,
) -> DeliveryError {
    error(
        if !endpoint_scoped && reply.code / 100 == 5 {
            DeliveryErrorKind::Permanent
        } else {
            DeliveryErrorKind::Temporary
        },
        format!("{context}: {}", reply.summary()),
    )
    .at(stage)
    .with_smtp_code(reply.code)
}

fn error(kind: DeliveryErrorKind, message: impl Into<String>) -> DeliveryError {
    DeliveryError {
        kind,
        stage: DeliveryStage::Request,
        smtp_code: None,
        message: message.into(),
        recipients: Vec::new(),
        source: DeliveryFailureSource::Other,
    }
}

fn outbound_timeout(
    config: &RuntimeConfig,
    new_key: &str,
    legacy_key: &str,
    default_millis: u64,
) -> Result<Duration, DeliveryError> {
    let millis = config
        .preferred_value(new_key, legacy_key)
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_| {
            error(
                DeliveryErrorKind::Configuration,
                "invalid outbound SMTP timeout",
            )
        })?
        .unwrap_or(default_millis);
    if millis == 0 || millis > 15 * 60 * 1_000 {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP timeout",
        ));
    }
    Ok(Duration::from_millis(millis))
}

fn outbound_pool_config(config: &RuntimeConfig) -> Result<Option<SmtpPoolConfig>, DeliveryError> {
    let enabled = match config.preferred_value(
        "lmyzmail.outbound.pool-enabled",
        "botmail.outbound.pool-enabled",
    ) {
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        Some(_) => {
            return Err(error(
                DeliveryErrorKind::Configuration,
                "invalid outbound SMTP pool configuration",
            ));
        }
        None => true,
    };
    if !enabled {
        return Ok(None);
    }
    let max_connections_per_host = outbound_pool_usize(
        config,
        "lmyzmail.outbound.max-connections-per-host",
        "botmail.outbound.max-connections-per-host",
        5,
        MAX_POOL_IDLE_CONNECTIONS,
    )?;
    let max_messages_per_connection = outbound_pool_usize(
        config,
        "lmyzmail.outbound.max-messages-per-connection",
        "botmail.outbound.max-messages-per-connection",
        100,
        1_000_000,
    )?;
    let max_idle_time = outbound_pool_duration(
        config,
        "lmyzmail.outbound.max-idle-time-ms",
        "botmail.outbound.max-idle-time-ms",
        60_000,
        24 * 60 * 60 * 1_000,
    )?;
    let max_lifetime = outbound_pool_duration(
        config,
        "lmyzmail.outbound.connection-life-time-ms",
        "botmail.outbound.connection-life-time-ms",
        300_000,
        24 * 60 * 60 * 1_000,
    )?;
    let cleanup_interval = outbound_pool_duration(
        config,
        "lmyzmail.outbound.pool-cleanup-interval-ms",
        "botmail.outbound.pool-cleanup-interval-ms",
        30_000,
        60 * 60 * 1_000,
    )?;
    Ok(Some(SmtpPoolConfig {
        max_connections_per_host,
        max_messages_per_connection,
        max_idle_time,
        max_lifetime,
        cleanup_interval,
    }))
}

fn outbound_pool_usize(
    config: &RuntimeConfig,
    new_key: &str,
    legacy_key: &str,
    default: usize,
    maximum: usize,
) -> Result<usize, DeliveryError> {
    let value = config
        .preferred_value(new_key, legacy_key)
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| {
            error(
                DeliveryErrorKind::Configuration,
                "invalid outbound SMTP pool configuration",
            )
        })?
        .unwrap_or(default);
    if value == 0 || value > maximum {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP pool configuration",
        ));
    }
    Ok(value)
}

fn outbound_pool_duration(
    config: &RuntimeConfig,
    new_key: &str,
    legacy_key: &str,
    default_millis: u64,
    maximum_millis: u64,
) -> Result<Duration, DeliveryError> {
    let millis = config
        .preferred_value(new_key, legacy_key)
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_| {
            error(
                DeliveryErrorKind::Configuration,
                "invalid outbound SMTP pool configuration",
            )
        })?
        .unwrap_or(default_millis);
    if millis == 0 || millis > maximum_millis {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP pool configuration",
        ));
    }
    Ok(Duration::from_millis(millis))
}

fn required_tls_failure(mut failure: DeliveryError) -> DeliveryError {
    if failure.stage != DeliveryStage::StartTls
        || matches!(
            failure.kind,
            DeliveryErrorKind::Cancelled
                | DeliveryErrorKind::Ambiguous
                | DeliveryErrorKind::Configuration
        )
    {
        return failure;
    }
    let retryable_transport = matches!(
        failure.source,
        DeliveryFailureSource::Deadline { .. }
            | DeliveryFailureSource::Io {
                kind: std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::WouldBlock,
                ..
            }
    );
    if let DeliveryFailureSource::Deadline {
        operation: "SMTP TLS handshake",
        timeout,
    } = failure.source
    {
        failure.message = format!(
            "MTA-STS policy requires TLS, but TLS failed: MTA-STS requires TLS: \
             MTA-STS enforced TLS handshake failed: TLS handshake timeout after {}ms",
            timeout.as_millis()
        );
    } else if let DeliveryFailureSource::TlsAlert {
        operation: "SMTP TLS handshake",
        alert,
    } = failure.source
    {
        let detail = match alert {
            AlertDescription::ProtocolVersion => {
                "error:1000042e:SSL routines:OPENSSL_internal:TLSV1_ALERT_PROTOCOL_VERSION"
            }
            AlertDescription::HandshakeFailure => {
                "error:10000410:SSL routines:OPENSSL_internal:SSLV3_ALERT_HANDSHAKE_FAILURE"
            }
            _ => "General OpenSslEngine problem",
        };
        failure.message = format!(
            "MTA-STS policy requires TLS, but TLS failed: MTA-STS requires TLS: \
             MTA-STS enforced TLS handshake failed: TLS handshake failed: {detail}"
        );
    } else if matches!(
        failure.source,
        DeliveryFailureSource::Io {
            operation: "SMTP TLS handshake",
            kind: std::io::ErrorKind::InvalidData,
        }
    ) {
        failure.message = "MTA-STS policy requires TLS, but TLS failed: MTA-STS requires TLS: \
             MTA-STS enforced TLS handshake failed: TLS handshake failed: \
             General OpenSslEngine problem"
            .to_owned();
    } else if let Some(code) = failure.smtp_code {
        let detail = failure
            .message
            .split_once(": ")
            .map_or(failure.message.as_str(), |(_, detail)| detail);
        let code_text = code.to_string();
        let detail = detail
            .strip_prefix(&code_text)
            .map_or(detail, str::trim_start);
        failure.message = format!(
            "MTA-STS policy requires TLS, but TLS failed: MTA-STS requires TLS: \
             STARTTLS failed: {code} {detail}"
        );
    } else if failure.message == "MTA-STS policy requires TLS, but server does not support STARTTLS"
    {
        // This policy error already uses the frozen queue detail verbatim.
    } else if failure.message.contains("STARTTLS negotiation failed") {
        failure.message = format!(
            "MTA-STS policy requires TLS, but TLS failed: MTA-STS requires TLS: {}",
            failure.message
        );
    }
    if !retryable_transport {
        failure.kind = DeliveryErrorKind::Permanent;
    }
    failure
}

fn file_error_kind(kind: std::io::ErrorKind) -> DeliveryErrorKind {
    match kind {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::PermissionDenied
        | std::io::ErrorKind::InvalidInput
        | std::io::ErrorKind::InvalidData => DeliveryErrorKind::Permanent,
        _ => DeliveryErrorKind::Temporary,
    }
}

fn protocol_error(after_data: bool, message: &'static str) -> DeliveryError {
    error(
        if after_data {
            DeliveryErrorKind::Ambiguous
        } else {
            DeliveryErrorKind::Protocol
        },
        message,
    )
}

fn io_failure_source(operation: &'static str, failure: &std::io::Error) -> DeliveryFailureSource {
    if operation == "SMTP TLS handshake"
        && let Some(RustlsError::AlertReceived(alert)) = failure
            .get_ref()
            .and_then(|source| source.downcast_ref::<RustlsError>())
    {
        return DeliveryFailureSource::TlsAlert {
            operation,
            alert: *alert,
        };
    }
    DeliveryFailureSource::Io {
        operation,
        kind: failure.kind(),
    }
}

async fn io_deadline<T, F>(
    cancellation: &CancellationToken,
    operation_timeout: Duration,
    session_deadline: Instant,
    future: F,
    failure_kind: DeliveryErrorKind,
    operation: &'static str,
) -> Result<T, DeliveryError>
where
    F: Future<Output = std::io::Result<T>>,
{
    let operation_deadline = (Instant::now() + operation_timeout).min(session_deadline);
    tokio::select! {
        _ = cancellation.cancelled() => Err(error(
            if failure_kind == DeliveryErrorKind::Ambiguous {
                DeliveryErrorKind::Ambiguous
            } else {
                DeliveryErrorKind::Cancelled
            },
            format!("{operation} cancelled"),
        )),
        result = timeout_at(operation_deadline, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(failure)) => {
                let source = io_failure_source(operation, &failure);
                let mut failure = error(failure_kind, format!("{operation} failed: {failure}"));
                failure.source = source;
                Err(failure)
            }
            Err(_) => {
                let mut failure = error(failure_kind, format!("{operation} deadline exceeded"));
                failure.source = DeliveryFailureSource::Deadline {
                    operation,
                    timeout: operation_timeout,
                };
                Err(failure)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tokio::io::{AsyncBufReadExt, BufReader};

    static NEXT_FILE_TEST: AtomicU64 = AtomicU64::new(1);

    struct FileTestDirectory(PathBuf);

    impl FileTestDirectory {
        fn new() -> Self {
            let id = NEXT_FILE_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lmyzmail-outbound-source-{}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for FileTestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn message_content_proof(bytes: &[u8]) -> MessageContentProof {
        MessageContentProof::new(bytes.len() as u64, Sha256::digest(bytes).into())
    }

    async fn unconnected_session() -> (SmtpSession, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
        let client = client.unwrap();
        let (server, _) = accepted.unwrap();
        (
            SmtpSession::new(
                client,
                Duration::from_secs(5),
                Instant::now() + Duration::from_secs(20),
                CancellationToken::new(),
            ),
            server,
        )
    }

    #[test]
    fn smtp_utf8_downgrades_only_domains() {
        let envelope =
            prepare_envelope("sender@例え.test", &["user@例え.test".into()], false).unwrap();
        assert_eq!(envelope.sender, "sender@xn--r8jz45g.test");
        assert_eq!(envelope.recipients, ["user@xn--r8jz45g.test"]);
        assert!(!envelope.smtp_utf8);
        let failure = prepare_envelope("送信@example.test", &["user@example.test".into()], false)
            .unwrap_err();
        assert_eq!(failure.kind, DeliveryErrorKind::Permanent);
    }

    #[test]
    fn smtp_utf8_is_preserved_when_advertised() {
        let envelope =
            prepare_envelope("送信@example.test", &["受信@example.test".into()], true).unwrap();
        assert_eq!(envelope.sender, "送信@example.test");
        assert!(envelope.smtp_utf8);
    }

    #[tokio::test]
    async fn null_reverse_path_is_emitted_exactly_on_the_wire() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut read = BufReader::new(read);
            let mut line = String::new();
            let mut commands = Vec::new();
            let mut in_data = false;
            write
                .write_all(b"220 smtp.example.test ESMTP\r\n")
                .await
                .unwrap();
            loop {
                line.clear();
                if read.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                if in_data {
                    if line == ".\r\n" {
                        in_data = false;
                        write.write_all(b"250 2.0.0 queued\r\n").await.unwrap();
                    }
                    continue;
                }
                let command = line.trim_end_matches(['\r', '\n']).to_owned();
                commands.push(command.clone());
                if command.starts_with("EHLO ") {
                    write
                        .write_all(b"250-smtp.example.test\r\n250 PIPELINING\r\n")
                        .await
                        .unwrap();
                } else if command.starts_with("MAIL FROM:") || command.starts_with("RCPT TO:") {
                    write.write_all(b"250 2.1.0 ok\r\n").await.unwrap();
                } else if command == "DATA" {
                    in_data = true;
                    write
                        .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        .await
                        .unwrap();
                } else if command == "QUIT" {
                    write.write_all(b"221 2.0.0 bye\r\n").await.unwrap();
                    break;
                } else {
                    panic!("unexpected SMTP command: {command}");
                }
            }
            commands
        });

        let request = DeliveryRequest {
            endpoint: SmtpEndpoint::trusted_relay(address, "smtp.example.test").unwrap(),
            hello_name: "mail.example.test".into(),
            envelope_from: String::new(),
            recipients: vec!["recipient@example.test".into()],
            message: MessageSource::Bytes(Arc::from(
                &b"Subject: DSN\r\n\r\nDelivery failed.\r\n"[..],
            )),
            tls_mode: TlsMode::Disabled,
            max_message_bytes: 4_096,
        };
        let result = OutboundSmtpClient::default()
            .deliver(&request, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(result.data_status, DataStatus::Accepted);
        let commands = server.await.unwrap();
        assert!(commands.iter().any(|command| command == "MAIL FROM:<>"));
        assert!(
            !commands
                .iter()
                .any(|command| command.starts_with("MAIL FROM:<mailer-daemon@"))
        );
    }

    #[test]
    fn request_validation_rejects_command_injection() {
        let request = DeliveryRequest {
            endpoint: SmtpEndpoint::trusted_relay(([127, 0, 0, 1], 25).into(), "smtp.example.test")
                .unwrap(),
            hello_name: "mail.example.test".into(),
            envelope_from: "sender@example.test\r\nRCPT TO:<victim@example.test>".into(),
            recipients: vec!["user@example.test".into()],
            message: MessageSource::Bytes(Arc::from(&b"Subject: test\r\n\r\nbody\r\n"[..])),
            tls_mode: TlsMode::Disabled,
            max_message_bytes: 1_024,
        };
        assert_eq!(
            validate_request(&request).unwrap_err().kind,
            DeliveryErrorKind::Configuration
        );
    }

    #[test]
    fn public_mx_rejects_special_addresses_and_trusted_relay_is_explicit() {
        for address in [
            "0.0.0.1:25",
            "10.0.0.1:25",
            "100.64.0.1:25",
            "127.0.0.1:25",
            "169.254.1.1:25",
            "192.0.2.1:25",
            "198.18.0.1:25",
            "203.0.113.1:25",
            "[::1]:25",
            "[fc00::1]:25",
            "[fe80::1]:25",
            "[2001:db8::1]:25",
            "[2002:7f00:1::1]:25",
        ] {
            let failure =
                SmtpEndpoint::public_mx(address.parse().unwrap(), "smtp.example.test").unwrap_err();
            assert_eq!(failure.kind, DeliveryErrorKind::Configuration, "{address}");
        }
        for address in ["8.8.8.8:25", "[2606:4700:4700::1111]:25"] {
            SmtpEndpoint::public_mx(address.parse().unwrap(), "smtp.example.test").unwrap();
        }
        SmtpEndpoint::trusted_relay("127.0.0.1:2525".parse().unwrap(), "relay.example.test")
            .unwrap();
    }

    #[test]
    fn request_debug_redacts_message_path_addresses_and_bytes() {
        let request = DeliveryRequest {
            endpoint: SmtpEndpoint::trusted_relay(([127, 0, 0, 1], 25).into(), "smtp.example.test")
                .unwrap(),
            hello_name: "mail.example.test".into(),
            envelope_from: "secret-sender@example.test".into(),
            recipients: vec!["secret-recipient@example.test".into()],
            message: MessageSource::Bytes(Arc::from(&b"secret body"[..])),
            tls_mode: TlsMode::Required,
            max_message_bytes: 1_024,
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("byte_count: 11"));
        assert!(!rendered.contains("secret"));

        let root = FileTestDirectory::new();
        std::fs::write(root.0.join("secret.eml"), b"secret").unwrap();
        let rendered = format!(
            "{:?}",
            MessageSource::file_under_root(
                &root.0,
                Path::new("secret.eml"),
                message_content_proof(b"secret"),
            )
            .unwrap()
        );
        assert_eq!(rendered, "File(<redacted>)");
    }

    #[test]
    fn request_validation_rejects_invalid_mailbox_syntax() {
        for address in [
            ".user@example.test",
            "user..tag@example.test",
            "user@example-.test",
            "user@-example.test",
            "user@example/test",
            "user name@example.test",
        ] {
            assert_eq!(
                validate_address(address).unwrap_err().kind,
                DeliveryErrorKind::Configuration,
                "{address}"
            );
        }
        validate_address("user+tag@example.test").unwrap();
        validate_address("受信@example.test").unwrap();
    }

    #[test]
    fn required_tls_policy_failures_distinguish_policy_from_transport_failures() {
        let required = required_tls_failure(
            error(
                DeliveryErrorKind::Temporary,
                "MTA-STS policy requires TLS, but server does not support STARTTLS",
            )
            .at(DeliveryStage::StartTls),
        );
        assert_eq!(required.kind, DeliveryErrorKind::Permanent);
        assert_eq!(required.stage, DeliveryStage::StartTls);

        let cancelled = required_tls_failure(
            error(DeliveryErrorKind::Cancelled, "cancelled").at(DeliveryStage::StartTls),
        );
        assert_eq!(cancelled.kind, DeliveryErrorKind::Cancelled);

        let mut deadline = error(
            DeliveryErrorKind::Temporary,
            "SMTP TLS handshake deadline exceeded",
        )
        .at(DeliveryStage::StartTls);
        deadline.source = DeliveryFailureSource::Deadline {
            operation: "SMTP TLS handshake",
            timeout: Duration::from_secs(1),
        };
        assert_eq!(
            required_tls_failure(deadline).kind,
            DeliveryErrorKind::Temporary
        );

        let mut reset = error(
            DeliveryErrorKind::Temporary,
            "SMTP TLS handshake connection reset",
        )
        .at(DeliveryStage::StartTls);
        reset.source = DeliveryFailureSource::Io {
            operation: "SMTP TLS handshake",
            kind: std::io::ErrorKind::ConnectionReset,
        };
        assert_eq!(
            required_tls_failure(reset).kind,
            DeliveryErrorKind::Temporary
        );

        let mut certificate = error(
            DeliveryErrorKind::Temporary,
            "SMTP TLS certificate validation failed",
        )
        .at(DeliveryStage::StartTls);
        certificate.source = DeliveryFailureSource::Io {
            operation: "SMTP TLS handshake",
            kind: std::io::ErrorKind::InvalidData,
        };
        assert_eq!(
            required_tls_failure(certificate).kind,
            DeliveryErrorKind::Permanent
        );

        for (alert, expected) in [
            (
                AlertDescription::ProtocolVersion,
                "error:1000042e:SSL routines:OPENSSL_internal:TLSV1_ALERT_PROTOCOL_VERSION",
            ),
            (
                AlertDescription::HandshakeFailure,
                "error:10000410:SSL routines:OPENSSL_internal:SSLV3_ALERT_HANDSHAKE_FAILURE",
            ),
        ] {
            let mut failure =
                error(DeliveryErrorKind::Temporary, "rustls alert").at(DeliveryStage::StartTls);
            failure.source = DeliveryFailureSource::TlsAlert {
                operation: "SMTP TLS handshake",
                alert,
            };
            let failure = required_tls_failure(failure);
            assert_eq!(failure.kind, DeliveryErrorKind::Permanent);
            assert_eq!(
                failure.message,
                format!(
                    "MTA-STS policy requires TLS, but TLS failed: MTA-STS requires TLS: \
                     MTA-STS enforced TLS handshake failed: TLS handshake failed: {expected}"
                )
            );
        }

        let connect = required_tls_failure(
            error(DeliveryErrorKind::Temporary, "connect failed").at(DeliveryStage::Connect),
        );
        assert_eq!(connect.kind, DeliveryErrorKind::Temporary);
    }

    #[test]
    fn tls_alerts_are_extracted_from_the_typed_io_error_source() {
        for alert in [
            AlertDescription::ProtocolVersion,
            AlertDescription::HandshakeFailure,
        ] {
            let failure = std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                RustlsError::AlertReceived(alert),
            );
            assert_eq!(
                io_failure_source("SMTP TLS handshake", &failure),
                DeliveryFailureSource::TlsAlert {
                    operation: "SMTP TLS handshake",
                    alert,
                }
            );
        }

        let certificate = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            RustlsError::InvalidCertificate(rustls::CertificateError::Expired),
        );
        assert_eq!(
            io_failure_source("SMTP TLS handshake", &certificate),
            DeliveryFailureSource::Io {
                operation: "SMTP TLS handshake",
                kind: std::io::ErrorKind::InvalidData,
            }
        );
        assert_eq!(
            io_failure_source("SMTP read", &certificate),
            DeliveryFailureSource::Io {
                operation: "SMTP read",
                kind: std::io::ErrorKind::InvalidData,
            }
        );
    }

    #[test]
    fn outbound_smtp_timeouts_accept_legacy_aliases_with_new_precedence() {
        use crate::config::Properties;

        let legacy = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.outbound.connection-timeout-ms=1200\n\
              botmail.outbound.read-timeout-ms=2300\n",
            )
            .unwrap(),
        )
        .unwrap();
        let client = OutboundSmtpClient::from_config(&legacy).unwrap();
        assert_eq!(client.connect_timeout, Duration::from_millis(1_200));
        assert_eq!(client.command_timeout, Duration::from_millis(2_300));

        let both = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.outbound.connection-timeout-ms=1200\n\
              lmyzmail.outbound.connection-timeout-ms=3400\n\
              botmail.outbound.read-timeout-ms=2300\n\
              lmyzmail.outbound.read-timeout-ms=4500\n",
            )
            .unwrap(),
        )
        .unwrap();
        let client = OutboundSmtpClient::from_config(&both).unwrap();
        assert_eq!(client.connect_timeout, Duration::from_millis(3_400));
        assert_eq!(client.command_timeout, Duration::from_millis(4_500));

        let invalid = RuntimeConfig::from_properties(
            Properties::parse(b"lmyzmail.outbound.read-timeout-ms=0\n").unwrap(),
        )
        .unwrap();
        let failure = match OutboundSmtpClient::from_config(&invalid) {
            Ok(_) => panic!("zero outbound SMTP timeout must be rejected"),
            Err(failure) => failure,
        };
        assert_eq!(failure.kind, DeliveryErrorKind::Configuration);
    }

    #[test]
    fn outbound_smtp_pool_accepts_legacy_aliases_with_new_precedence() {
        use crate::config::Properties;

        let legacy = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.outbound.pool-enabled=true\n\
                  botmail.outbound.max-connections-per-host=7\n\
                  botmail.outbound.max-messages-per-connection=23\n\
                  botmail.outbound.max-idle-time-ms=1200\n\
                  botmail.outbound.connection-life-time-ms=3400\n\
                  botmail.outbound.pool-cleanup-interval-ms=5600\n",
            )
            .unwrap(),
        )
        .unwrap();
        let client = OutboundSmtpClient::from_config(&legacy).unwrap();
        let pool = client.pool.unwrap();
        assert_eq!(pool.config.max_connections_per_host, 7);
        assert_eq!(pool.config.max_messages_per_connection, 23);
        assert_eq!(pool.config.max_idle_time, Duration::from_millis(1_200));
        assert_eq!(pool.config.max_lifetime, Duration::from_millis(3_400));
        assert_eq!(pool.config.cleanup_interval, Duration::from_millis(5_600));

        let both = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.outbound.max-connections-per-host=7\n\
                  lmyzmail.outbound.max-connections-per-host=3\n\
                  botmail.outbound.max-messages-per-connection=23\n\
                  lmyzmail.outbound.max-messages-per-connection=11\n",
            )
            .unwrap(),
        )
        .unwrap();
        let client = OutboundSmtpClient::from_config(&both).unwrap();
        let pool = client.pool.unwrap();
        assert_eq!(pool.config.max_connections_per_host, 3);
        assert_eq!(pool.config.max_messages_per_connection, 11);

        let disabled = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.outbound.pool-enabled=true\n\
                  lmyzmail.outbound.pool-enabled=false\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            OutboundSmtpClient::from_config(&disabled)
                .unwrap()
                .pool
                .is_none()
        );

        let invalid = RuntimeConfig::from_properties(
            Properties::parse(b"lmyzmail.outbound.max-connections-per-host=0\n").unwrap(),
        )
        .unwrap();
        let failure = match OutboundSmtpClient::from_config(&invalid) {
            Ok(_) => panic!("zero outbound SMTP pool capacity must be rejected"),
            Err(failure) => failure,
        };
        assert_eq!(failure.kind, DeliveryErrorKind::Configuration);
    }

    #[test]
    fn file_errors_distinguish_missing_content_from_transient_resources() {
        assert_eq!(
            file_error_kind(std::io::ErrorKind::NotFound),
            DeliveryErrorKind::Permanent
        );
        assert_eq!(
            file_error_kind(std::io::ErrorKind::PermissionDenied),
            DeliveryErrorKind::Permanent
        );
        assert_eq!(
            file_error_kind(std::io::ErrorKind::WouldBlock),
            DeliveryErrorKind::Temporary
        );
        assert_eq!(
            file_error_kind(std::io::ErrorKind::Other),
            DeliveryErrorKind::Temporary
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trusted_file_source_rejects_escape_symlink_and_out_of_root_hardlink() {
        use std::os::unix::fs::symlink;

        let root = FileTestDirectory::new();
        let outside = root.0.parent().unwrap().join(format!(
            "lmyzmail-outbound-outside-{}",
            NEXT_FILE_TEST.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&outside, b"outside secret").unwrap();
        let outside_proof = message_content_proof(b"outside secret");
        assert!(
            MessageSource::file_under_root(&root.0, Path::new("../outside"), outside_proof)
                .is_err()
        );

        symlink(&outside, root.0.join("symlink.eml")).unwrap();
        assert!(
            MessageSource::file_under_root(&root.0, Path::new("symlink.eml"), outside_proof)
                .is_err()
        );

        let hardlink = root.0.join("hardlink.eml");
        std::fs::hard_link(&outside, &hardlink).unwrap();
        assert!(
            MessageSource::file_under_root(&root.0, Path::new("hardlink.eml"), outside_proof)
                .is_err()
        );
        std::fs::remove_file(hardlink).unwrap();
        std::fs::remove_file(outside).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn replacement_between_authorization_and_data_is_rejected() {
        let root = FileTestDirectory::new();
        let path = root.0.join("message.eml");
        let original = b"Subject: original\r\n\r\noriginal\r\n";
        std::fs::write(&path, original).unwrap();
        let message = MessageSource::file_under_root(
            &root.0,
            Path::new("message.eml"),
            message_content_proof(original),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let authorized = authorize_message(
            &message,
            1_024,
            &CancellationToken::new(),
            Duration::from_secs(5),
            deadline,
        )
        .await
        .unwrap();

        let replacement = root.0.join("replacement.eml");
        std::fs::write(&replacement, b"Subject: replacement\r\n\r\nsecret\r\n").unwrap();
        std::fs::rename(replacement, &path).unwrap();

        let (session, _server) = unconnected_session().await;
        let failure = match session.prepare_message(&authorized, 1_024).await {
            Ok(_) => panic!("replacement source must be rejected before DATA"),
            Err(failure) => failure,
        };
        assert_eq!(failure.kind, DeliveryErrorKind::Permanent);
    }

    #[cfg(target_os = "linux")]
    async fn mid_data_path_change_is_rejected(replace: bool) {
        let root = FileTestDirectory::new();
        let path = root.0.join("message.eml");
        let mut original = b"Subject: original\r\n\r\n".to_vec();
        original.resize(MESSAGE_CHUNK_BYTES * 2, b'a');
        std::fs::write(&path, &original).unwrap();
        let message = MessageSource::file_under_root(
            &root.0,
            Path::new("message.eml"),
            message_content_proof(&original),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let authorized = authorize_message(
            &message,
            original.len() as u64,
            &CancellationToken::new(),
            Duration::from_secs(5),
            deadline,
        )
        .await
        .unwrap();
        let (mut session, mut server) = unconnected_session().await;
        let mut prepared = session
            .prepare_message(&authorized, original.len() as u64)
            .await
            .unwrap();

        let changed = Arc::new(AtomicBool::new(false));
        let hook_changed = Arc::clone(&changed);
        let hook_path = path.clone();
        let moved = root.0.join("moved.eml");
        let replacement = root.0.join("replacement.eml");
        if replace {
            std::fs::write(&replacement, b"local replacement secret").unwrap();
        }
        session.data_chunk_hook = Some(Arc::new(move |_| {
            if hook_changed.swap(true, Ordering::SeqCst) {
                return;
            }
            if replace {
                std::fs::rename(&replacement, &hook_path).unwrap();
            } else {
                std::fs::rename(&hook_path, &moved).unwrap();
            }
        }));

        let failure = session
            .write_message_body(&mut prepared, original.len() as u64)
            .await
            .unwrap_err();
        assert_eq!(failure.kind, DeliveryErrorKind::Permanent);
        assert!(changed.load(Ordering::SeqCst));
        drop(session);
        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        assert!(
            !wire
                .windows(b"local replacement secret".len())
                .any(|window| { window == b"local replacement secret" })
        );
        assert!(!wire.ends_with(b".\r\n"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn replacement_during_data_is_rejected_before_terminator() {
        mid_data_path_change_is_rejected(true).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rename_during_data_is_rejected_before_terminator() {
        mid_data_path_change_is_rejected(false).await;
    }
}
