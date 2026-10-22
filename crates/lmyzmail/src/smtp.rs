use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    future::Future,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

#[cfg(test)]
use std::ffi::OsString;

use chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use deadpool_postgres::Pool;
use deadpool_redis::Pool as RedisPool;
use getrandom::fill as fill_random;
use mail_parser::MessageParser;
use openssl::pkcs12::Pkcs12;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Notify, RwLock, Semaphore, mpsc},
    task::{JoinSet, spawn_blocking},
    time::{Instant, sleep, timeout, timeout_at},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_util::sync::CancellationToken;

use crate::{
    config::{ContentFilterConfig, MailRenderSimdMode, RuntimeConfig},
    coordinator_observer::{CoordinatorStage, StageTimer},
    cringe::{CringeError, CringeService},
    mailbox::{normalize_mailbox, secure_directory_child, secure_mailbox_folder},
    skibidi::SkibidiGenerator,
    skibidi_inferx::InferxService,
    smtp_ascii::AsciiSimdMode,
    smtp_content_filter::{
        ContentScan, NewDomainScanner, ParsedHeaders, RblScanner, has_first_mime_attachment,
        scan_attachments, scan_body,
    },
    smtp_dkim::{DkimVerification, DkimVerifier},
    smtp_dmarc::{DmarcRecord, DmarcVerification, DmarcVerifier},
    smtp_domain::validate_routable_domain,
    smtp_skibidi_quiz::{AnswerOutcome, QuizLevel, QuizState, ensure_question_bank_loaded},
    smtp_skibidi_video::{VideoDefaults, VideoService, VideoStartError, frame_wire_bytes},
    smtp_spamhaus::SpamhausService,
    smtp_spf::{SpfVerification, SpfVerifier},
    video_asset::locate_frozen_video_asset,
};

#[cfg(test)]
use crate::durability::{fsync, sync_all};

#[path = "smtp_inbound_delivery.rs"]
pub(crate) mod inbound_delivery;

const HOSTNAME: &str = "lmyzmail";
const MAX_COMMAND_BYTES: usize = 1_000;
const MAX_MESSAGE_BYTES: usize = 15_728_640;
const MAX_RECIPIENTS: usize = 100;
const MAX_CONNECTIONS: usize = 256;
const STORAGE_TIMEOUT: Duration = Duration::from_secs(15);
const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const VIDEO_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TLS_KEYSTORE_BYTES: u64 = 16 * 1024 * 1024;
const SMTP_QUEUE_CAPACITY: usize = 256;
const CRINGE_QUEUE_CAPACITY: usize = 256;
const CRINGE_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
const CRINGE_FORCED_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);
const INBOUND_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const INBOUND_MAINTENANCE_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
const INBOUND_COMMITTER_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
const MAX_SMTP_REPLY_TEXT_BYTES: usize = 506;
const MAILDIR_SHARD_LOCKS: usize = 64;
const MAX_INBOUND_SHARD_CACHE_ENTRIES: usize = 4_096;
const MAX_INBOUND_SHARD_CACHE_ENTRIES_PER_LOCK: usize =
    MAX_INBOUND_SHARD_CACHE_ENTRIES / MAILDIR_SHARD_LOCKS;
const INBOUND_SHARD_RESCAN_INTERVAL: usize = 256;
static FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct InboundFolderKey {
    mailbox: String,
    folder: String,
}

#[derive(Clone, Copy, Debug)]
struct InboundShardState {
    current_shard: i32,
    allocated: usize,
    in_flight: usize,
    reservations_since_scan: usize,
    last_used: u64,
}

#[derive(Debug)]
struct InboundShardAllocator {
    shards: [StdMutex<HashMap<InboundFolderKey, InboundShardState>>; MAILDIR_SHARD_LOCKS],
    clock: AtomicU64,
    capacity_available: Notify,
}

#[derive(Debug)]
struct InboundShardReservation {
    allocator: Arc<InboundShardAllocator>,
    shard_index: usize,
    key: InboundFolderKey,
    subdirectory: i32,
    preserve_allocation: bool,
}

#[derive(Debug)]
enum InboundPrepareAttempt {
    Prepared {
        prepared: inbound_delivery::PreparedInbound,
        shard_reservation: Option<InboundShardReservation>,
    },
    Backpressured {
        raw: Vec<u8>,
        index: inbound_delivery::InboundIndexMetadata,
        intent_id: String,
    },
}

impl Default for InboundShardAllocator {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| StdMutex::new(HashMap::new())),
            clock: AtomicU64::new(1),
            capacity_available: Notify::new(),
        }
    }
}

impl InboundShardAllocator {
    fn reserve(
        self: &Arc<Self>,
        folder_root: &Path,
        mailbox: &str,
        folder: &str,
        max_files: usize,
    ) -> io::Result<InboundShardReservation> {
        if max_files == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Maildir shard capacity must be positive",
            ));
        }
        let key = InboundFolderKey {
            mailbox: mailbox.to_owned(),
            folder: folder.to_owned(),
        };
        let shard_index = maildir_lock_index(mailbox, folder);
        let mut states = self.shards[shard_index]
            .lock()
            .map_err(|_| io::Error::other("SMTP inbound shard allocator is poisoned"))?;
        let now = self.clock.fetch_add(1, Ordering::Relaxed);
        if !states.contains_key(&key) {
            let (current_shard, allocated) = inspect_inbound_subdirectory(folder_root)?;
            if states.len() >= MAX_INBOUND_SHARD_CACHE_ENTRIES_PER_LOCK
                && let Some(evicted) = states
                    .iter()
                    .filter(|(_, state)| state.in_flight == 0)
                    .min_by_key(|(_, state)| state.last_used)
                    .map(|(key, _)| key.clone())
            {
                states.remove(&evicted);
            }
            if states.len() >= MAX_INBOUND_SHARD_CACHE_ENTRIES_PER_LOCK {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "SMTP inbound shard cache partition is fully reserved",
                ));
            }
            states.insert(
                key.clone(),
                InboundShardState {
                    current_shard,
                    allocated,
                    in_flight: 0,
                    reservations_since_scan: 0,
                    last_used: now,
                },
            );
        }
        let state = states.get_mut(&key).ok_or_else(|| {
            io::Error::other("SMTP inbound shard state disappeared while reserved")
        })?;
        if state.reservations_since_scan >= INBOUND_SHARD_RESCAN_INTERVAL {
            let (observed_shard, observed_count) = inspect_inbound_subdirectory(folder_root)?;
            if observed_shard > state.current_shard {
                state.current_shard = observed_shard;
                state.allocated = observed_count;
            } else if observed_shard == state.current_shard {
                state.allocated = state.allocated.max(observed_count);
            }
            state.reservations_since_scan = 0;
        }
        if state.allocated >= max_files {
            state.current_shard = state
                .current_shard
                .checked_add(1)
                .ok_or_else(|| io::Error::other("Maildir shard index overflow"))?;
            state.allocated = 0;
            state.reservations_since_scan = 0;
        }
        let selected = state.current_shard;
        state.allocated = state.allocated.saturating_add(1);
        state.in_flight = state.in_flight.saturating_add(1);
        state.reservations_since_scan = state.reservations_since_scan.saturating_add(1);
        state.last_used = now;
        Ok(InboundShardReservation {
            allocator: Arc::clone(self),
            shard_index,
            key,
            subdirectory: selected,
            preserve_allocation: false,
        })
    }
}

impl InboundShardReservation {
    fn subdirectory(&self) -> i32 {
        self.subdirectory
    }

    fn mark_durable(&mut self) {
        self.preserve_allocation = true;
    }
}

impl Drop for InboundShardReservation {
    fn drop(&mut self) {
        if let Ok(mut states) = self.allocator.shards[self.shard_index].lock()
            && let Some(state) = states.get_mut(&self.key)
        {
            state.in_flight = state.in_flight.saturating_sub(1);
            if !self.preserve_allocation && state.current_shard == self.subdirectory {
                state.allocated = state.allocated.saturating_sub(1);
            }
            state.last_used = self.allocator.clock.fetch_add(1, Ordering::Relaxed);
        }
        self.allocator.capacity_available.notify_one();
    }
}

#[derive(Debug)]
pub enum SmtpError {
    Database(String),
    InvalidConfig(String),
}

impl std::fmt::Display for SmtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "SMTP database unavailable: {error}"),
            Self::InvalidConfig(error) => f.write_str(error),
        }
    }
}

impl std::error::Error for SmtpError {}

pub async fn initialize_inbound_storage(
    pool: &Pool,
    cancellation: &CancellationToken,
) -> io::Result<bool> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Ok(false),
        result = inbound_delivery::initialize_schema(pool) => result.map(|()| true),
    }
}

#[derive(Clone)]
pub struct SmtpService {
    config: Arc<RuntimeConfig>,
    pool: Pool,
    redis_pool: RedisPool,
    blocking_permits: Arc<Semaphore>,
    delivery_queue: Arc<Semaphore>,
    maildir_max_files_per_directory: Option<usize>,
    inbound_shard_allocator: Arc<InboundShardAllocator>,
    active_inbound_intents: Arc<inbound_delivery::ActiveInboundIntents>,
    inbound_intent_committer: Arc<inbound_delivery::IntentCommitter>,
    inbound_index_committer: Arc<inbound_delivery::IndexCommitter>,
    inbound_completion_committer: Arc<inbound_delivery::CompletionCommitter>,
    inbound_staging_gate: Arc<RwLock<()>>,
    tls_acceptor: Option<TlsAcceptor>,
    rbl_scanner: RblScanner,
    new_domain_scanner: NewDomainScanner,
    spf_verifier: SpfVerifier,
    dkim_verifier: DkimVerifier,
    dmarc_verifier: DmarcVerifier,
    spamhaus_service: SpamhausService,
    skibidi_generator: SkibidiGenerator,
    inferx_service: Arc<InferxService>,
    cringe_sender: mpsc::Sender<SmtpCringeActivity>,
    skibidi_video: Option<Arc<VideoService>>,
}

impl SmtpService {
    fn from_config(
        config: Arc<RuntimeConfig>,
        pool: Pool,
        redis_pool: RedisPool,
        inferx_service: Arc<InferxService>,
        cringe_sender: mpsc::Sender<SmtpCringeActivity>,
    ) -> Result<Self, SmtpError> {
        let maildir_max_files_per_directory = match config
            .preferred_value(
                "lmyzmail.maildir.max-files-per-directory",
                "botmail.maildir.max-files-per-directory",
            )
            .unwrap_or("10000")
            .parse::<i64>()
        {
            Ok(-1) => None,
            Ok(value @ 1..=1_000_000) => Some(value as usize),
            _ => {
                return Err(SmtpError::InvalidConfig(
                    "maildir max-files-per-directory must be -1 or between 1 and 1000000".into(),
                ));
            }
        };
        let tls_acceptor = if config.tls.enabled {
            let path = config.tls.keystore_path.as_deref().ok_or_else(|| {
                SmtpError::InvalidConfig("TLS keystore path is not configured".into())
            })?;
            let mut file = std::fs::File::open(path).map_err(|error| {
                SmtpError::InvalidConfig(format!("TLS keystore cannot be read: {error}"))
            })?;
            let metadata = file.metadata().map_err(|error| {
                SmtpError::InvalidConfig(format!("TLS keystore cannot be inspected: {error}"))
            })?;
            if !metadata.is_file() || metadata.len() > MAX_TLS_KEYSTORE_BYTES {
                return Err(SmtpError::InvalidConfig(format!(
                    "TLS keystore is not a regular file or exceeds {MAX_TLS_KEYSTORE_BYTES} bytes"
                )));
            }
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            use std::io::Read as _;
            file.by_ref()
                .take(MAX_TLS_KEYSTORE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    SmtpError::InvalidConfig(format!("TLS keystore cannot be read: {error}"))
                })?;
            if bytes.len() as u64 > MAX_TLS_KEYSTORE_BYTES {
                return Err(SmtpError::InvalidConfig(format!(
                    "TLS keystore exceeds {MAX_TLS_KEYSTORE_BYTES} bytes"
                )));
            }
            let password = std::env::var_os("LMYZMAIL_SSL_KEYSTORE_PASSWORD")
                .or_else(|| std::env::var_os("BOTMAIL_SSL_KEYSTORE_PASSWORD"))
                .map(|value| {
                    value.into_string().map_err(|_| {
                        SmtpError::InvalidConfig(
                            "TLS keystore password environment value is not UTF-8".into(),
                        )
                    })
                })
                .transpose()?
                .unwrap_or_else(|| config.tls.keystore_password.clone());
            let parsed = Pkcs12::from_der(&bytes)
                .and_then(|keystore| keystore.parse2(&password))
                .map_err(|error| {
                    SmtpError::InvalidConfig(format!("TLS PKCS#12 keystore is invalid: {error}"))
                })?;
            let private_key = parsed.pkey.ok_or_else(|| {
                SmtpError::InvalidConfig("TLS PKCS#12 keystore has no private key".into())
            })?;
            let certificate = parsed.cert.ok_or_else(|| {
                SmtpError::InvalidConfig("TLS PKCS#12 keystore has no certificate".into())
            })?;
            let mut certificates =
                vec![CertificateDer::from(certificate.to_der().map_err(
                    |error| SmtpError::InvalidConfig(error.to_string()),
                )?)];
            if let Some(chain) = parsed.ca {
                for certificate in chain {
                    certificates.push(CertificateDer::from(
                        certificate
                            .to_der()
                            .map_err(|error| SmtpError::InvalidConfig(error.to_string()))?,
                    ));
                }
            }
            let private_key = private_key
                .private_key_to_pkcs8()
                .map_err(|error| SmtpError::InvalidConfig(error.to_string()))?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let tls_config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|error| SmtpError::InvalidConfig(error.to_string()))?
                .with_no_client_auth()
                .with_single_cert(
                    certificates,
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key)),
                )
                .map_err(|error| {
                    SmtpError::InvalidConfig(format!("TLS acceptor setup failed: {error}"))
                })?;
            Some(TlsAcceptor::from(Arc::new(tls_config)))
        } else {
            None
        };
        let skibidi_generator = SkibidiGenerator::new(
            &config.features.smtp_skibidi_mode,
            config.features.smtp_skibidi_enable_avx512,
            config.features.smtp_skibidi_enable_simd_rng,
        )
        .map_err(|error| {
            SmtpError::InvalidConfig(format!("SMTP Skibidi generator cannot start: {error}"))
        })?;
        let skibidi_info = skibidi_generator.runtime_info().map_err(|error| {
            SmtpError::InvalidConfig(format!(
                "SMTP Skibidi generator runtime is invalid: {error}"
            ))
        })?;
        eprintln!(
            "lmyzmail SMTP Skibidi generator: backend={}, version={}, capabilities=0x{:x}, hardware_avx2={}, hardware_avx512={}, avx512_enabled={}, simd_rng={}",
            skibidi_info.backend.name(),
            skibidi_info.version,
            skibidi_info.capabilities,
            skibidi_info.has_avx2,
            skibidi_info.has_avx512,
            skibidi_info.avx512_enabled,
            skibidi_info.simd_rng_enabled,
        );
        let rbl_scanner = RblScanner::new().map_err(|error| {
            SmtpError::InvalidConfig(format!(
                "SMTP content-filter RBL resolver cannot start: {error}"
            ))
        })?;
        let new_domain_scanner = NewDomainScanner::new().map_err(|error| {
            SmtpError::InvalidConfig(format!(
                "SMTP content-filter DNS resolver cannot start: {error}"
            ))
        })?;
        let spf_verifier =
            SpfVerifier::new(config.features.smtp_spf_dns_server).map_err(|error| {
                SmtpError::InvalidConfig(format!("SMTP SPF resolver cannot start: {error}"))
            })?;
        let dkim_verifier =
            DkimVerifier::new(config.features.smtp_spf_dns_server).map_err(|error| {
                SmtpError::InvalidConfig(format!("SMTP DKIM resolver cannot start: {error}"))
            })?;
        let dmarc_verifier =
            DmarcVerifier::new(config.features.smtp_spf_dns_server).map_err(|error| {
                SmtpError::InvalidConfig(format!("SMTP DMARC resolver cannot start: {error}"))
            })?;
        let spamhaus_service = SpamhausService::new(
            config.smtp_spamhaus.clone(),
            config.features.smtp_spf_dns_server,
        )
        .map_err(SmtpError::InvalidConfig)?;
        let skibidi_video = if config.smtp_skibidi.enabled {
            ensure_question_bank_loaded().map_err(|error| {
                SmtpError::InvalidConfig(format!("SMTP quiz question bank is invalid: {error}"))
            })?;
            let video_asset = locate_frozen_video_asset().map_err(|error| {
                SmtpError::InvalidConfig(format!("SMTP Skibidi video is unavailable: {error}"))
            })?;
            let ascii = &config.smtp_skibidi.ascii;
            let simd_mode = match ascii.simd_mode {
                MailRenderSimdMode::Auto => AsciiSimdMode::Auto,
                MailRenderSimdMode::Scalar => AsciiSimdMode::Scalar,
                MailRenderSimdMode::Avx2 => AsciiSimdMode::Avx2,
                MailRenderSimdMode::Avx512 => AsciiSimdMode::Avx512,
            };
            Some(Arc::new(
                VideoService::new(
                    video_asset,
                    VideoDefaults {
                        max_width: ascii.max_width as usize,
                        max_fps: ascii.max_fps,
                        default_width: ascii.default_width as usize,
                        default_fps: ascii.default_fps,
                        default_contrast: ascii.default_contrast,
                        char_aspect: ascii.char_aspect,
                        simd_mode,
                    },
                )
                .map_err(|error| {
                    SmtpError::InvalidConfig(format!(
                        "SMTP Skibidi video worker cannot start: {error}"
                    ))
                })?,
            ))
        } else {
            None
        };
        Ok(Self {
            config,
            pool: pool.clone(),
            redis_pool,
            blocking_permits: Arc::new(Semaphore::new(4)),
            delivery_queue: Arc::new(Semaphore::new(SMTP_QUEUE_CAPACITY)),
            maildir_max_files_per_directory,
            inbound_shard_allocator: Arc::new(InboundShardAllocator::default()),
            active_inbound_intents: Arc::new(inbound_delivery::ActiveInboundIntents::default()),
            inbound_intent_committer: inbound_delivery::IntentCommitter::start(pool.clone()),
            inbound_index_committer: inbound_delivery::IndexCommitter::start(pool.clone()),
            inbound_completion_committer: inbound_delivery::CompletionCommitter::start(
                pool.clone(),
            ),
            inbound_staging_gate: Arc::new(RwLock::new(())),
            tls_acceptor,
            rbl_scanner,
            new_domain_scanner,
            spf_verifier,
            dkim_verifier,
            dmarc_verifier,
            spamhaus_service,
            skibidi_generator,
            inferx_service,
            cringe_sender,
            skibidi_video,
        })
    }

    async fn self_spoof_rejection(
        &self,
        peer: IpAddr,
        sender: &str,
        verification: &SpfVerification,
        cancellation: &CancellationToken,
    ) -> Option<String> {
        let sender_domain = sender.rsplit_once('@').map(|(_, domain)| domain)?;
        let own_domain = sender_domain.trim_end_matches('.');
        let is_local_domain = self.config.domains.iter().any(|domain| {
            let configured = domain.domain.as_str();
            own_domain.eq_ignore_ascii_case(configured)
                || own_domain
                    .strip_suffix(configured)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        });
        if !is_local_domain {
            return None;
        }

        if verification.passed() {
            return None;
        }
        let spf_result = verification.result();
        let spf_reason = verification.reason();

        let seed = format!("{peer}:{sender}:{}", Utc::now().timestamp_millis());
        let insult = if self.config.features.smtp_skibidi_insults {
            self.inferx_service
                .generate_insult(seed, cancellation)
                .await
        } else {
            crate::skibidi_inferx::InsultResult {
                message: "5.7.1 Sender address rejected: SPF validation failed for local domain."
                    .to_owned(),
                lm_generated: false,
            }
        };
        let message = sanitize_smtp_reply_text(&format!(
            "{} This domain belongs to this server and your IP ({peer}) is not authorized to send from it. SPF result: {spf_result}.{}",
            insult.message,
            insult.lm_tag(),
        ));
        let metadata = format!(
            "SPF: {spf_result}, Reason: {spf_reason}, Domain: {sender_domain}, LM-generated: {}",
            insult.lm_generated,
        );
        let activity = SmtpCringeActivity::SelfSpoof {
            ip: peer,
            mail_from: sender.to_owned(),
            response_message: message.clone(),
            metadata,
        };
        if let Err(error) = self.cringe_sender.try_send(activity) {
            eprintln!("lmyzmail SMTP self-spoof activity queue rejected a record: {error}");
        }
        Some(message)
    }

    fn sender_domain_rejection(&self, peer: IpAddr, sender: &str) -> Option<String> {
        let sender_domain = sender
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .filter(|domain| !domain.is_empty())?;
        let reason = validate_routable_domain(sender_domain).err()?;
        let metadata = format!("Invalid domain: {sender_domain} - {reason}");
        let activity = SmtpCringeActivity::IllegalSenderDomain {
            ip: peer,
            mail_from: sender.to_owned(),
            metadata,
        };
        if let Err(error) = self.cringe_sender.try_send(activity) {
            eprintln!("lmyzmail SMTP illegal-domain activity queue rejected a record: {error}");
        }
        Some(format!("5.1.8 Sender address rejected: {reason}"))
    }

    async fn spamhaus_rejection(
        &self,
        peer: IpAddr,
        sender: &str,
        cancellation: &CancellationToken,
    ) -> Option<Vec<u8>> {
        let sender_domain = sender.rsplit_once('@').map(|(_, domain)| domain)?;
        let result = self
            .spamhaus_service
            .check(peer, sender_domain, cancellation)
            .await;
        if !result.is_any_listed() || !self.config.smtp_spamhaus.reject_on_listed {
            return None;
        }
        let activity = SmtpCringeActivity::Spamhaus {
            ip: peer,
            mail_from: sender.to_owned(),
            metadata: result.metadata(),
        };
        if let Err(error) = self.cringe_sender.try_send(activity) {
            eprintln!("lmyzmail SMTP Spamhaus activity queue rejected a record: {error}");
        }
        Some(result.rejection_wire(peer, sender_domain))
    }

    fn queue_protocol_violation(&self, peer: IpAddr, helo: &str, session_id: &str, metadata: &str) {
        let activity = SmtpCringeActivity::ProtocolViolation {
            ip: peer,
            helo_name: helo.to_owned(),
            session_id: session_id.to_owned(),
            metadata: metadata.to_owned(),
        };
        if let Err(error) = self.cringe_sender.try_send(activity) {
            eprintln!("lmyzmail SMTP protocol activity queue rejected a record: {error}");
        }
    }

    async fn deliver(
        &self,
        envelope: Envelope,
        peer: IpAddr,
        helo: &str,
        encrypted: bool,
        cancellation: &CancellationToken,
    ) -> io::Result<String> {
        let permit = self
            .delivery_queue
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("SMTP delivery queue closed"))?;
        let result = timeout(
            STORAGE_TIMEOUT,
            self.deliver_inner(envelope, peer, helo.to_owned(), encrypted, cancellation),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SMTP delivery deadline exceeded"))?;
        drop(permit);
        result
    }

    async fn deliver_inner(
        &self,
        mut envelope: Envelope,
        peer: IpAddr,
        helo: String,
        encrypted: bool,
        cancellation: &CancellationToken,
    ) -> io::Result<String> {
        envelope.dkim = Some(
            self.dkim_verifier
                .verify(&envelope.data, cancellation)
                .await,
        );
        let headers = ParsedHeaders::parse(&envelope.data)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let parsed_message = MessageParser::default().parse_headers(&envelope.data);
        envelope.dmarc = Some(
            self.dmarc_verifier
                .verify(
                    parsed_message.as_ref(),
                    envelope.sender.as_deref(),
                    envelope.spf.as_ref(),
                    envelope.dkim.as_ref(),
                    envelope.dmarc_record.clone(),
                    cancellation,
                )
                .await,
        );
        let mut content_scan = self
            .rbl_scanner
            .scan(peer, &self.config.content_filter)
            .await;
        content_scan.append(
            self.new_domain_scanner
                .scan(
                    envelope.sender.as_deref(),
                    &headers,
                    &self.config.content_filter,
                )
                .await,
        );
        // The frozen Java verification path does not forward envelope RCPTs
        // into ScanContext, so header rules observe an envelope count of zero.
        content_scan.append(headers.scan(0, &self.config.content_filter));
        content_scan.append(
            scan_body(&envelope.data, &self.config.content_filter)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        );
        content_scan.append(
            scan_attachments(&envelope.data, &self.config.content_filter)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        );
        let mailbox = normalize_mailbox(
            envelope
                .recipients
                .first()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "recipient missing"))?,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid recipient mailbox"))?;
        let message_id = headers.first_trimmed("message-id").unwrap_or_else(|| {
            format!(
                "<smtp-{}@{}>",
                FILE_COUNTER.load(Ordering::Relaxed),
                self.config.domain
            )
        });
        let subject = parsed_message
            .as_ref()
            .and_then(|message| message.subject().map(str::to_owned))
            .or_else(|| headers.first_trimmed("subject"));
        // Java Mime4j overwrites this scalar for each From field while parsing.
        let from_address = headers.last_trimmed("from");
        let to_addresses = headers
            .first_trimmed("to")
            .map(|value| address_list_json(&value))
            .unwrap_or_else(|| "[]".to_owned());
        let has_attachments = has_first_mime_attachment(&envelope.data)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let received_at = DateTime::<Utc>::from_timestamp_micros(Utc::now().timestamp_micros())
            .expect("current UTC timestamp is representable at PostgreSQL precision");
        let received_id = random_hex_upper(7).map_err(io::Error::other)?;
        let accepted_id = random_hex(4).map_err(io::Error::other)?;
        if envelope
            .dmarc
            .as_ref()
            .is_some_and(DmarcVerification::should_reject)
        {
            return Ok(accepted_id);
        }
        let content_quarantined = content_scan.is_suspicious(&self.config.content_filter);
        let authentication_passed = envelope.spf.as_ref().is_some_and(SpfVerification::passed)
            || envelope.dkim.as_ref().is_some_and(DkimVerification::passed)
            || envelope
                .dmarc
                .as_ref()
                .is_some_and(DmarcVerification::passed);
        let authentication_quarantined = envelope
            .dmarc
            .as_ref()
            .is_some_and(DmarcVerification::should_quarantine);
        let folder = if authentication_passed && !content_quarantined && !authentication_quarantined
        {
            "inbox"
        } else {
            "spam"
        };
        let raw = compose_message(
            &envelope,
            MessageComposition {
                mailbox: &mailbox,
                peer,
                helo: &helo,
                encrypted,
                received_at,
                received_id: &received_id,
                content_scan: &content_scan,
                content_filter: &self.config.content_filter,
            },
        );
        if raw.len() > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message exceeds configured maximum",
            ));
        }
        let raw_len = raw.len();
        let counter = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now_millis = received_at.timestamp_subsec_millis();
        let file_name = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}.{:03}-{}-{}.eml",
            received_at.year(),
            received_at.month(),
            received_at.day(),
            received_at.hour(),
            received_at.minute(),
            received_at.second(),
            now_millis,
            counter,
            counter,
        );
        let intent_id = random_hex(16).map_err(io::Error::other)?;
        let index = inbound_delivery::InboundIndexMetadata {
            mailbox: mailbox.clone(),
            folder: folder.to_owned(),
            subdirectory: None,
            file_name: file_name.clone(),
            has_attachments,
            received_at,
            size_bytes: raw_len as i64,
            from_address,
            message_id,
            subject,
            to_addresses,
        };
        let active_intent = self
            .active_inbound_intents
            .reserve(intent_id.clone(), mailbox.clone())?;
        let staging_guard = self.inbound_staging_gate.read().await;
        let max_files_per_directory = self.maildir_max_files_per_directory;
        let maildir = self.config.maildir.clone();
        let mailbox_for_write = mailbox.clone();
        let folder_for_write = folder.to_owned();
        let inbound_shard_allocator = Arc::clone(&self.inbound_shard_allocator);
        let prepare_deadline = Instant::now() + STORAGE_TIMEOUT;
        let mut pending_raw = Some(raw);
        let mut pending_index = Some(index);
        let mut pending_intent_id = Some(intent_id);
        let (prepared, mut shard_reservation) = loop {
            let notified = inbound_shard_allocator.capacity_available.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let blocking_permit = timeout_at(
                prepare_deadline,
                self.blocking_permits.clone().acquire_owned(),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SMTP storage timeout"))?
            .map_err(|_| io::Error::other("SMTP blocking pool closed"))?;
            let raw = pending_raw
                .take()
                .ok_or_else(|| io::Error::other("SMTP inbound body disappeared"))?;
            let index = pending_index
                .take()
                .ok_or_else(|| io::Error::other("SMTP inbound index disappeared"))?;
            let intent_id = pending_intent_id
                .take()
                .ok_or_else(|| io::Error::other("SMTP inbound intent id disappeared"))?;
            let maildir = maildir.clone();
            let mailbox_for_write = mailbox_for_write.clone();
            let folder_for_write = folder_for_write.clone();
            let inbound_shard_allocator = Arc::clone(&inbound_shard_allocator);
            let attempt = {
                let _timer = StageTimer::start(CoordinatorStage::InboundPrepareFile);
                timeout_at(
                    prepare_deadline,
                    spawn_blocking(move || {
                        let _permit = blocking_permit;
                        let folder_root =
                            secure_mailbox_folder(&maildir, &mailbox_for_write, &folder_for_write)?;
                        let shard_reservation = match max_files_per_directory {
                            Some(max_files) => {
                                match inbound_shard_allocator.reserve(
                                    &folder_root,
                                    &mailbox_for_write,
                                    &folder_for_write,
                                    max_files,
                                ) {
                                    Ok(reservation) => Some(reservation),
                                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                        return Ok(InboundPrepareAttempt::Backpressured {
                                            raw,
                                            index,
                                            intent_id,
                                        });
                                    }
                                    Err(error) => return Err(error),
                                }
                            }
                            None => None,
                        };
                        let subdirectory = shard_reservation
                            .as_ref()
                            .map(InboundShardReservation::subdirectory);
                        let final_parent = match subdirectory {
                            Some(value) => {
                                secure_directory_child(&folder_root, &value.to_string())?
                            }
                            None => folder_root,
                        };
                        let mut index = index;
                        index.subdirectory = subdirectory;
                        let prepared = inbound_delivery::prepare_file(
                            &maildir,
                            final_parent,
                            intent_id,
                            &raw,
                            index,
                        )?;
                        Ok(InboundPrepareAttempt::Prepared {
                            prepared,
                            shard_reservation,
                        })
                    }),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SMTP storage timeout"))?
                .map_err(|error| io::Error::other(error.to_string()))??
            };
            match attempt {
                InboundPrepareAttempt::Prepared {
                    prepared,
                    shard_reservation,
                } => break (prepared, shard_reservation),
                InboundPrepareAttempt::Backpressured {
                    raw,
                    index,
                    intent_id,
                } => {
                    pending_raw = Some(raw);
                    pending_index = Some(index);
                    pending_intent_id = Some(intent_id);
                    timeout_at(prepare_deadline, notified).await.map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "SMTP inbound shard cache backpressure timeout",
                        )
                    })?;
                }
            }
        };
        {
            let _timer = StageTimer::start(CoordinatorStage::InboundIntentInsert);
            self.inbound_intent_committer.submit(&prepared).await?;
        }
        if let Some(reservation) = shard_reservation.as_mut() {
            reservation.mark_durable();
        }
        active_intent.mark_durable()?;
        drop(staging_guard);
        let publish_permit = self
            .blocking_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("SMTP blocking pool closed"))?;
        let prepared_for_publish = prepared.clone();
        {
            let _timer = StageTimer::start(CoordinatorStage::InboundPublishFile);
            spawn_blocking(move || {
                let _permit = publish_permit;
                inbound_delivery::publish_file(&prepared_for_publish)
            })
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
        }
        drop(shard_reservation);
        {
            let _timer = StageTimer::start(CoordinatorStage::InboundIndexCommit);
            self.inbound_index_committer.submit(&prepared).await?;
        }
        let verify_permit = self
            .blocking_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("SMTP blocking pool closed"))?;
        let prepared_for_verify = prepared.clone();
        {
            let _timer = StageTimer::start(CoordinatorStage::InboundPublishVerify);
            spawn_blocking(move || {
                let _permit = verify_permit;
                inbound_delivery::verify_published_file(&prepared_for_verify)
            })
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
        }
        {
            let _timer = StageTimer::start(CoordinatorStage::InboundIntentComplete);
            self.inbound_completion_committer.submit(&prepared).await?;
        }
        active_intent.complete()?;
        // The index transaction durably coalesces this Redis projection; bounded
        // inbound maintenance flushes and acknowledges the newest generation.
        Ok(accepted_id)
    }

    async fn mailbox_exists(&self, address: &str) -> io::Result<bool> {
        let address = normalize_mailbox(address).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid recipient mailbox")
        })?;
        let client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "database pool timeout"))?
            .map_err(|error| io::Error::other(error.to_string()))?;
        let row = timeout(
            DATABASE_TIMEOUT,
            client.query_one(
                "SELECT EXISTS(SELECT 1 FROM mailbox WHERE address=$1)",
                &[&address],
            ),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mailbox lookup timeout"))?
        .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(row.get(0))
    }

    async fn recover_inbound_batch(&self) -> io::Result<usize> {
        let active_ids = self.active_inbound_intents.active_ids()?;
        let intents = inbound_delivery::load_unowned_intent_batch(
            &self.pool,
            inbound_delivery::RECOVERY_BATCH_SIZE,
            &active_ids,
        )
        .await?;
        let recovered = intents.len();
        for intent in intents {
            if self.active_inbound_intents.is_active(&intent.intent_id)? {
                continue;
            }
            let Some(intent) = inbound_delivery::load_intent(&self.pool, &intent.intent_id).await?
            else {
                continue;
            };
            let permit = self
                .blocking_permits
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| io::Error::other("SMTP blocking pool closed"))?;
            let maildir = self.config.maildir.clone();
            let intent = spawn_blocking(move || {
                let _permit = permit;
                let mut intent = intent;
                intent.bind_paths(&maildir)?;
                inbound_delivery::publish_file(&intent)?;
                Ok::<_, io::Error>(intent)
            })
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
            inbound_delivery::commit_index_and_compact(&self.pool, &intent).await?;
            let verify_permit = self
                .blocking_permits
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| io::Error::other("SMTP blocking pool closed"))?;
            let intent_for_verify = intent.clone();
            spawn_blocking(move || {
                let _permit = verify_permit;
                inbound_delivery::verify_published_file(&intent_for_verify)
            })
            .await
            .map_err(|error| io::Error::other(error.to_string()))??;
            self.inbound_completion_committer.submit(&intent).await?;
        }
        for mailbox in self.active_inbound_intents.blocked_mailboxes()? {
            let active_ids = self.active_inbound_intents.active_ids()?;
            if !inbound_delivery::has_unowned_pending_for(&self.pool, &mailbox, &active_ids).await?
            {
                self.active_inbound_intents
                    .clear_blocked_mailbox(&mailbox)?;
            }
        }
        Ok(recovered)
    }

    async fn recover_inbound_startup(&self, cancellation: &CancellationToken) -> io::Result<bool> {
        let count = inbound_delivery::pending_intent_count(&self.pool).await?;
        if count < 0 || count as usize > inbound_delivery::MAX_STARTUP_RECOVERY_INTENTS {
            return Err(io::Error::other(format!(
                "SMTP inbound recovery backlog {count} exceeds the startup bound {}",
                inbound_delivery::MAX_STARTUP_RECOVERY_INTENTS
            )));
        }
        let mut recovered = 0_usize;
        loop {
            let batch = tokio::select! {
                biased;
                () = cancellation.cancelled() => return Ok(false),
                batch = self.recover_inbound_batch() => batch?,
            };
            if batch == 0 {
                break;
            }
            recovered = recovered.saturating_add(batch);
            if recovered > inbound_delivery::MAX_STARTUP_RECOVERY_INTENTS {
                return Err(io::Error::other(
                    "SMTP inbound recovery exceeded its startup work bound",
                ));
            }
        }
        Ok(true)
    }
}

#[derive(Debug)]
enum SmtpCringeActivity {
    SelfSpoof {
        ip: IpAddr,
        mail_from: String,
        response_message: String,
        metadata: String,
    },
    IllegalSenderDomain {
        ip: IpAddr,
        mail_from: String,
        metadata: String,
    },
    Spamhaus {
        ip: IpAddr,
        mail_from: String,
        metadata: String,
    },
    ProtocolViolation {
        ip: IpAddr,
        helo_name: String,
        session_id: String,
        metadata: String,
    },
}

impl SmtpCringeActivity {
    const fn kind(&self) -> &'static str {
        match self {
            Self::SelfSpoof { .. } => "SELF_SPOOFING",
            Self::IllegalSenderDomain { .. } => "ILLEGAL_SENDER_DOMAIN",
            Self::Spamhaus { .. } => "SPAMHAUS_LISTED",
            Self::ProtocolViolation { .. } => "PROTOCOL_VIOLATION",
        }
    }
}

fn sanitize_smtp_reply_text(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len().min(MAX_SMTP_REPLY_TEXT_BYTES));
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if sanitized.len() + character.len_utf8() > MAX_SMTP_REPLY_TEXT_BYTES {
            break;
        }
        sanitized.push(character);
    }
    sanitized
}

async fn run_cringe_persistence(
    receiver: mpsc::Receiver<SmtpCringeActivity>,
    cringe_service: CringeService,
    cancellation: CancellationToken,
) {
    run_cringe_persistence_with(
        receiver,
        cancellation,
        move |activity, activity_cancellation| {
            persist_cringe_activity(cringe_service.clone(), activity, activity_cancellation)
        },
    )
    .await;
}

async fn run_cringe_persistence_with<P, F>(
    mut receiver: mpsc::Receiver<SmtpCringeActivity>,
    cancellation: CancellationToken,
    mut persist: P,
) where
    P: FnMut(SmtpCringeActivity, CancellationToken) -> F,
    F: Future<Output = Result<Option<i32>, CringeError>>,
{
    loop {
        let activity = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            activity = receiver.recv() => match activity {
                Some(activity) => activity,
                None => return,
            },
        };
        let kind = activity.kind();
        if let Err(error) = persist(activity, cancellation.clone()).await {
            eprintln!("lmyzmail SMTP cringe {kind} persistence failed: {error}");
        }
    }
}

async fn persist_cringe_activity(
    cringe_service: CringeService,
    activity: SmtpCringeActivity,
    cancellation: CancellationToken,
) -> Result<Option<i32>, CringeError> {
    match activity {
        SmtpCringeActivity::SelfSpoof {
            ip,
            mail_from,
            response_message,
            metadata,
        } => {
            cringe_service
                .record_self_spoofing(ip, &mail_from, &response_message, &metadata, &cancellation)
                .await
        }
        SmtpCringeActivity::IllegalSenderDomain {
            ip,
            mail_from,
            metadata,
        } => {
            cringe_service
                .record_illegal_sender_domain(ip, &mail_from, &metadata, &cancellation)
                .await
        }
        SmtpCringeActivity::Spamhaus {
            ip,
            mail_from,
            metadata,
        } => {
            cringe_service
                .record_spamhaus(ip, &mail_from, &metadata, &cancellation)
                .await
        }
        SmtpCringeActivity::ProtocolViolation {
            ip,
            helo_name,
            session_id,
            metadata,
        } => {
            cringe_service
                .record_protocol_violation(ip, &helo_name, &session_id, &metadata, &cancellation)
                .await
        }
    }
}

async fn run_inbound_maintenance(service: Arc<SmtpService>, cancellation: CancellationToken) {
    let mut cleanup_ticks = 300_u16;
    let mut audit_cursor = None;
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            () = sleep(INBOUND_RECOVERY_INTERVAL) => {}
        }
        match service.recover_inbound_batch().await {
            Ok(_) => {}
            Err(error) => eprintln!("lmyzmail SMTP inbound recovery deferred: {error}"),
        }
        match inbound_delivery::flush_projection_batch(
            &service.pool,
            &service.redis_pool,
            inbound_delivery::PROJECTION_BATCH_SIZE,
        )
        .await
        {
            Ok(_) => {}
            Err(error) => eprintln!("lmyzmail SMTP mail-count projection deferred: {error}"),
        }
        cleanup_ticks = cleanup_ticks.saturating_add(1);
        if cleanup_ticks >= 300 {
            match inbound_delivery::audit_projection_batch(
                &service.pool,
                audit_cursor.as_ref(),
                inbound_delivery::AUDIT_BATCH_SIZE,
            )
            .await
            {
                Ok((_, cursor)) => audit_cursor = cursor,
                Err(error) => eprintln!("lmyzmail SMTP projection audit deferred: {error}"),
            }
            let _staging_guard = service.inbound_staging_gate.write().await;
            match inbound_delivery::cleanup_untracked_staging(
                &service.config.maildir,
                &service.pool,
                &service.blocking_permits,
                inbound_delivery::STAGING_ORPHAN_MIN_AGE,
                inbound_delivery::STAGING_ENTRY_LIMIT,
            )
            .await
            {
                Ok(_) => {}
                Err(error) => eprintln!("lmyzmail SMTP staging cleanup deferred: {error}"),
            }
            cleanup_ticks = 0;
        }
    }
}

pub async fn serve_smtp(
    config: Arc<RuntimeConfig>,
    database_pool: Pool,
    redis_pool: RedisPool,
    inferx_service: Arc<InferxService>,
    cringe_service: CringeService,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let (cringe_sender, cringe_receiver) = mpsc::channel(CRINGE_QUEUE_CAPACITY);
    let cringe_cancellation = CancellationToken::new();
    let service = Arc::new(
        SmtpService::from_config(
            Arc::clone(&config),
            database_pool,
            redis_pool,
            inferx_service,
            cringe_sender,
        )
        .map_err(io::Error::other)?,
    );
    let staging_permit = service
        .blocking_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| io::Error::other("SMTP blocking pool closed"))?;
    let maildir = service.config.maildir.clone();
    spawn_blocking(move || {
        let _permit = staging_permit;
        inbound_delivery::initialize_staging(&maildir)
    })
    .await
    .map_err(|error| io::Error::other(error.to_string()))??;
    if !service.recover_inbound_startup(&cancellation).await? {
        return Ok(());
    }
    let staging_guard = service.inbound_staging_gate.write().await;
    inbound_delivery::cleanup_untracked_staging(
        &service.config.maildir,
        &service.pool,
        &service.blocking_permits,
        inbound_delivery::STAGING_ORPHAN_MIN_AGE,
        inbound_delivery::STAGING_ENTRY_LIMIT,
    )
    .await?;
    drop(staging_guard);
    let listener = TcpListener::bind((config.listen.host.as_str(), config.listen.smtp)).await?;
    let mut cringe_task = tokio::spawn(run_cringe_persistence(
        cringe_receiver,
        cringe_service,
        cringe_cancellation.clone(),
    ));
    let maintenance_cancellation = CancellationToken::new();
    let mut maintenance_task = tokio::spawn(run_inbound_maintenance(
        Arc::clone(&service),
        maintenance_cancellation.clone(),
    ));
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Ok(Err(error)) = result {
                eprintln!("lmyzmail SMTP connection failed: {error}");
            }
        }
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Some(permit) = connections.clone().try_acquire_owned().ok() else {
                    drop(stream);
                    continue;
                };
                let service = Arc::clone(&service);
                tasks.spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, peer.ip().to_canonical(), service).await
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    maintenance_cancellation.cancel();
    let maintenance_result =
        timeout(INBOUND_MAINTENANCE_SHUTDOWN_DEADLINE, &mut maintenance_task).await;
    let maintenance_drained = matches!(&maintenance_result, Ok(Ok(())));
    if let Ok(Err(error)) = &maintenance_result {
        eprintln!("lmyzmail SMTP inbound maintenance failed during shutdown: {error}");
    } else if let Err(error) = &maintenance_result {
        eprintln!("lmyzmail SMTP inbound maintenance exceeded its shutdown deadline: {error}");
    }
    if maintenance_result.is_err() {
        maintenance_task.abort();
        let _ = maintenance_task.await;
    }
    let inbound_committer_deadline = Instant::now() + INBOUND_COMMITTER_SHUTDOWN_DEADLINE;
    let (intent_drained, index_drained, completion_drained) = tokio::join!(
        service
            .inbound_intent_committer
            .shutdown(inbound_committer_deadline),
        service
            .inbound_index_committer
            .shutdown(inbound_committer_deadline),
        service
            .inbound_completion_committer
            .shutdown(inbound_committer_deadline),
    );
    if !intent_drained {
        eprintln!("lmyzmail SMTP inbound intent worker exceeded its shutdown deadline");
    }
    if !index_drained {
        eprintln!("lmyzmail SMTP inbound index worker exceeded its shutdown deadline");
    }
    if !completion_drained {
        eprintln!("lmyzmail SMTP inbound completion worker exceeded its shutdown deadline");
    }
    if let Some(video) = service.skibidi_video.as_ref()
        && !video.shutdown().await
    {
        eprintln!("lmyzmail SMTP video worker exceeded its shutdown deadline");
    }
    if !maintenance_drained || !intent_drained || !index_drained || !completion_drained {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "lmyzmail SMTP storage workers did not drain before shutdown",
        ));
    }
    let blocking_permits =
        u32::try_from(MAX_CONNECTIONS.min(4)).expect("SMTP blocking permit count fits u32");
    let blocking_quiescence = timeout_at(
        inbound_committer_deadline,
        service
            .blocking_permits
            .clone()
            .acquire_many_owned(blocking_permits),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "lmyzmail SMTP blocking file workers did not stop before shutdown",
        )
    })?
    .map_err(|_| io::Error::other("lmyzmail SMTP blocking pool closed"))?;
    drop(blocking_quiescence);
    drop(service);
    if timeout(CRINGE_SHUTDOWN_DEADLINE, &mut cringe_task)
        .await
        .is_err()
    {
        cringe_cancellation.cancel();
        if timeout(CRINGE_FORCED_SHUTDOWN_DEADLINE, &mut cringe_task)
            .await
            .is_err()
        {
            cringe_task.abort();
            let _ = cringe_task.await;
            eprintln!("lmyzmail SMTP cringe persistence worker exceeded its shutdown deadline");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct Envelope {
    sender: Option<String>,
    recipients: Vec<String>,
    data: Vec<u8>,
    spf: Option<SpfVerification>,
    dkim: Option<DkimVerification>,
    dmarc_record: Option<DmarcRecord>,
    dmarc: Option<DmarcVerification>,
}

impl Envelope {
    fn reset(&mut self) {
        self.sender = None;
        self.recipients.clear();
        self.data.clear();
        self.spf = None;
        self.dkim = None;
        self.dmarc_record = None;
        self.dmarc = None;
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SessionState {
    Connected,
    Greeted,
}

impl SessionState {
    fn oracle_name(self, envelope: &Envelope) -> &'static str {
        match (
            self,
            envelope.sender.is_some(),
            envelope.recipients.is_empty(),
        ) {
            (Self::Connected, _, _) => "CONNECT",
            (Self::Greeted, false, _) => "HELO",
            (Self::Greeted, true, true) => "MAIL",
            (Self::Greeted, true, false) => "RCPT",
        }
    }
}

enum ConnectionStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    Closed,
}

impl AsyncRead for ConnectionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SMTP connection is closed",
            ))),
        }
    }
}

impl AsyncWrite for ConnectionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, bytes),
            Self::Tls(stream) => Pin::new(stream).poll_write(context, bytes),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SMTP connection is closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream).poll_flush(context),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SMTP connection is closed",
            ))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Closed => Poll::Ready(Ok(())),
        }
    }
}

struct BufferedConnection {
    stream: ConnectionStream,
    buffer: Vec<u8>,
}

impl BufferedConnection {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream: ConnectionStream::Plain(stream),
            buffer: Vec::with_capacity(4096),
        }
    }

    async fn upgrade_tls(&mut self, acceptor: &TlsAcceptor) -> io::Result<()> {
        let stream = std::mem::replace(&mut self.stream, ConnectionStream::Closed);
        let ConnectionStream::Plain(mut stream) = stream else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SMTP connection is already encrypted",
            ));
        };
        let mut client_hello_prefix = [0_u8; 11];
        let read = stream.peek(&mut client_hello_prefix).await?;
        if read == 0 || client_hello_prefix[0] != 0x16 {
            let mut discarded = [0_u8; 4096];
            let _ = timeout(Duration::from_millis(100), stream.read(&mut discarded)).await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMTP STARTTLS did not receive a TLS handshake record",
            ));
        }
        if read >= client_hello_prefix.len()
            && client_hello_prefix[5] == 0x01
            && u16::from_be_bytes([client_hello_prefix[9], client_hello_prefix[10]]) < 0x0303
        {
            stream.write_all(b"\x15\x03\x03\x00\x02\x02\x46").await?;
            stream.shutdown().await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMTP STARTTLS rejected a legacy TLS ClientHello",
            ));
        }
        let stream = acceptor
            .accept(stream)
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        self.stream = ConnectionStream::Tls(Box::new(stream));
        Ok(())
    }

    async fn read_line(&mut self, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(index) = self.buffer.iter().position(|byte| *byte == b'\n') {
                if index > max_bytes + 1 {
                    self.buffer.drain(..=index);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                let line = self.buffer.drain(..=index).collect::<Vec<_>>();
                return Ok(Some(line));
            }
            if self.buffer.len() > max_bytes + 1 {
                self.buffer.clear();
                loop {
                    let mut chunk = [0_u8; 2048];
                    let read = self.stream.read(&mut chunk).await?;
                    if read == 0 {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial line"));
                    }
                    if let Some(index) = chunk[..read].iter().position(|byte| *byte == b'\n') {
                        self.buffer.extend_from_slice(&chunk[index + 1..read]);
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                    }
                }
            }
            let mut chunk = [0_u8; 2048];
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial line"));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    async fn read_exact_bytes(&mut self, size: usize) -> io::Result<Vec<u8>> {
        if size > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk too large",
            ));
        }
        let mut output = Vec::with_capacity(size);
        let take = size.min(self.buffer.len());
        output.extend(self.buffer.drain(..take));
        while output.len() < size {
            let mut chunk = [0_u8; 8192];
            let remaining = size - output.len();
            let read_size = remaining.min(chunk.len());
            let read = self.stream.read(&mut chunk[..read_size]).await?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial BDAT"));
            }
            output.extend_from_slice(&chunk[..read]);
        }
        Ok(output)
    }

    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await
    }
}

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

const SKIBIDI_HELP_LINES: &[&str] = &[
    "SKIBIDITOILET - Brainrot Quiz & Video SMTP Extension",
    "Tests your Gen Alpha / internet slang knowledge. Are you built different?",
    "",
    "Subcommands:",
    "  SKIBIDITOILET HELP",
    "    Prints this help message. You clearly needed it.",
    "",
    "  SKIBIDITOILET START <LEVEL>",
    "    Starts a quiz. Available levels:",
    "      BABYGRONK      - 15 questions, easy mode. For the NPC crowd.",
    "      SKIBIDITOILET  - 30 questions, balanced. Mid-tier rizz required.",
    "      OHIOFINALBOSS  - 60 questions, maximum aura drain. Only sigma males apply.",
    "",
    "  SKIBIDITOILET ANSWER <your answer>",
    "    For multiple choice: reply with A, B, C, or D.",
    "    For fill-in-the-blank: type your answer.",
    "",
    "  SKIBIDITOILET QUIT",
    "    Forfeits the current quiz. Your aura will not recover from this.",
    "",
    "  SKIBIDITOILET WATCHSKIBIDITOILET [params...]",
    "    Streams Skibidi Toilet Episode 1 as ASCII Art over SMTP.",
    "    Your terminal must support ANSI escape codes.",
    "",
    "    Parameters (space-separated, all optional):",
    "      WIDTH=<n>       Output width in characters    (default: 120, max: 450)",
    "      FPS=<n>         Playback frame rate           (default: 10.0, max: 20)",
    "      CONTRAST=<f>    Contrast multiplier           (default: 1.2)",
    "      BRIGHTNESS=<f>  Brightness offset             (default: 0.0)",
    "      GAMMA=<f>       Gamma correction              (default: 1.0)",
    "      ASPECT=<f>      Character height/width ratio  (default: 2.0)",
    "      INVERT          Invert brightness mapping",
    "",
    "    Example:",
    "      SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=160 FPS=12 CONTRAST=1.5",
    "",
    "    WARNING: Color mode is not supported (monochrome only).",
    "    WARNING: Once playback starts, it CANNOT be stopped except by",
    "             disconnecting. You have been warned. No cap.",
    "    WARNING: Maximum 1 concurrent viewer globally.",
    "    WARNING: Each line is prefixed with '250-' per SMTP multi-line",
    "             response format. This is normal. Embrace the jank.",
    "",
    "Notes:",
    "  - Quiz runs inline in the SMTP session. No MAIL transaction needed.",
    "  - Commands are case-insensitive. Your excuses are not.",
    "214 End of HELP. Skibidi dop dop yes yes.",
];

fn multiline_reply<T: AsRef<str>>(code: u16, lines: &[T]) -> Vec<u8> {
    debug_assert!(!lines.is_empty());
    let code = code.to_string();
    let capacity = lines
        .iter()
        .map(|line| code.len() + 3 + line.as_ref().len())
        .sum();
    let mut output = Vec::with_capacity(capacity);
    for (index, line) in lines.iter().enumerate() {
        output.extend_from_slice(code.as_bytes());
        output.push(if index + 1 == lines.len() { b' ' } else { b'-' });
        output.extend_from_slice(line.as_ref().as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output
}

async fn write_video_bytes(io: &mut BufferedConnection, bytes: &[u8]) -> io::Result<()> {
    timeout(VIDEO_WRITE_TIMEOUT, io.write_all(bytes))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "SMTP video write deadline exceeded",
            )
        })?
}

async fn handle_skibidi_command(
    io: &mut BufferedConnection,
    argument: &str,
    quiz_state: &mut Option<QuizState>,
    video: Option<&Arc<VideoService>>,
    connection_cancellation: &CancellationToken,
) -> io::Result<()> {
    let argument = argument.trim_start();
    let (subcommand, subargument) = argument
        .split_once(char::is_whitespace)
        .map_or((argument, ""), |(command, rest)| (command, rest));
    match subcommand.to_ascii_uppercase().as_str() {
        "HELP" => {
            io.write_all(&multiline_reply(214, SKIBIDI_HELP_LINES))
                .await
        }
        "START" => {
            if quiz_state.is_some() {
                return io
                    .write_all(b"503 5.5.1 Quiz already in progress. SKIBIDITOILET QUIT to forfeit, or SKIBIDITOILET ANSWER to keep coping.\r\n")
                    .await;
            }
            let level_value = subargument.trim_matches(|character| character <= '\u{0020}');
            if level_value.is_empty() {
                return io
                    .write_all(b"501 5.5.4 Syntax: SKIBIDITOILET START <LEVEL>. Levels: BABYGRONK, SKIBIDITOILET, OHIOFINALBOSS\r\n")
                    .await;
            }
            let Some(level) = QuizLevel::from_arg(level_value) else {
                let displayed = if level_value.bytes().all(|byte| byte.is_ascii_graphic()) {
                    level_value
                } else {
                    "INVALID"
                };
                return io
                    .write_all(
                        format!(
                            "501 5.5.4 Unknown level '{displayed}'. Valid: BABYGRONK, SKIBIDITOILET, OHIOFINALBOSS. Cope harder and try again.\r\n"
                        )
                        .as_bytes(),
                    )
                    .await;
            };
            match QuizState::start(level) {
                Ok(start) => {
                    let reply = multiline_reply(250, &start.lines);
                    *quiz_state = Some(start.state);
                    io.write_all(&reply).await
                }
                Err(error) => {
                    eprintln!("lmyzmail SMTP quiz initialization failed: {error}");
                    io.write_all(
                        b"451 4.3.0 Brainrot quiz unavailable. The server lost its aura.\r\n",
                    )
                    .await
                }
            }
        }
        "ANSWER" => {
            let Some(active) = quiz_state.as_mut() else {
                return io
                    .write_all(b"503 5.5.1 No quiz in progress. Use SKIBIDITOILET START <LEVEL> to begin. Stop yapping and do something.\r\n")
                    .await;
            };
            if subargument
                .trim_matches(|character| character <= '\u{0020}')
                .is_empty()
            {
                return io
                    .write_all(b"501 5.5.4 Empty answer detected. Submitting nothing is peak NPC behavior. Type SKIBIDITOILET ANSWER <your answer>.\r\n")
                    .await;
            }
            let outcome = active.answer(subargument).map_err(io::Error::other)?;
            match outcome {
                AnswerOutcome::Continue(lines) => io.write_all(&multiline_reply(250, &lines)).await,
                AnswerOutcome::Complete {
                    answer_lines,
                    final_lines,
                } => {
                    io.write_all(&multiline_reply(250, &answer_lines)).await?;
                    io.write_all(&multiline_reply(220, &final_lines)).await?;
                    *quiz_state = None;
                    Ok(())
                }
            }
        }
        "QUIT" => {
            let Some(active) = quiz_state.take() else {
                return io
                    .write_all(b"503 5.5.1 No quiz in progress. There is nothing to quit from. Classic NPC move.\r\n")
                    .await;
            };
            io.write_all(&multiline_reply(250, &active.into_forfeit_lines()))
                .await
        }
        "WATCHSKIBIDITOILET" => {
            let Some(video) = video else {
                return io
                    .write_all(b"451 4.3.0 ASCII Art engine unavailable. The native library failed to load. Ohio moment.\r\n")
                    .await;
            };
            let mut playback = match video.start(subargument, connection_cancellation).await {
                Ok(playback) => playback,
                Err(VideoStartError::Busy) => {
                    return io
                        .write_all(b"451 4.3.0 Another session is already watching Skibidi Toilet. Max 1 concurrent viewer. Cope and try later.\r\n")
                        .await;
                }
                Err(VideoStartError::Invalid(message)) => {
                    return io.write_all(format!("501 {message}\r\n").as_bytes()).await;
                }
                Err(VideoStartError::Unavailable(error)) => {
                    eprintln!("lmyzmail SMTP video admission failed: {error}");
                    return io
                        .write_all(b"451 4.3.0 ASCII Art engine unavailable. The native library failed to load. Ohio moment.\r\n")
                        .await;
                }
                Err(VideoStartError::Cancelled) => return Ok(()),
            };
            let params = playback.params();
            eprintln!(
                "lmyzmail SMTP video started: {}x{} at {} FPS",
                params.width, params.height, params.fps
            );
            write_video_bytes(io, b"250-\x1b[2J\x1b[H\r\n").await?;
            let frame_interval = Duration::from_secs_f64(1.0 / f64::from(params.fps));
            let mut backend_logged = false;
            loop {
                let frame_started = Instant::now();
                match playback.next_frame().await {
                    Ok(Some(frame)) => {
                        if !backend_logged {
                            eprintln!(
                                "lmyzmail SMTP video ASCII backend: {}",
                                frame.backend.name()
                            );
                            backend_logged = true;
                        }
                        let bytes = frame_wire_bytes(&frame).map_err(io::Error::other)?;
                        write_video_bytes(io, &bytes).await?;
                    }
                    Ok(None) => {
                        write_video_bytes(
                            io,
                            b"250 PLAYBACK COMPLETE. Skibidi dop dop yes yes!\r\n",
                        )
                        .await?;
                        return Ok(());
                    }
                    Err(error) => {
                        eprintln!("lmyzmail SMTP video playback failed: {error}");
                        write_video_bytes(
                            io,
                            format!("250 PLAYBACK ERROR: {error}\r\n").as_bytes(),
                        )
                        .await?;
                        return Ok(());
                    }
                }
                let remaining = frame_interval.saturating_sub(frame_started.elapsed());
                tokio::select! {
                    _ = connection_cancellation.cancelled() => return Ok(()),
                    _ = sleep(remaining) => {}
                }
            }
        }
        _ => {
            io.write_all(b"501 5.5.4 Unknown subcommand. Type SKIBIDITOILET HELP to git gud.\r\n")
                .await
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: IpAddr,
    service: Arc<SmtpService>,
) -> io::Result<()> {
    configure_connection_socket(&stream)?;
    let connection_cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop(connection_cancellation.clone());
    let session_id = random_hex(4).map_err(io::Error::other)?;
    let mut io = BufferedConnection::new(stream);
    let greeting = service
        .skibidi_generator
        .generate()
        .map_err(io::Error::other)?;
    io.write_all(b"220 lmyzmail ESMTP lmyzmail SMTP Server 2.8.0 - ")
        .await?;
    io.write_all(greeting.as_bytes()).await?;
    io.write_all(b"\r\n").await?;
    let mut state = SessionState::Connected;
    let mut envelope = Envelope::default();
    let mut helo = "localhost".to_owned();
    let mut dispatcher_errors = 0_u8;
    let mut auth_probe_count = 0_u8;
    let mut tls_active = false;
    let mut quiz_state = None;
    loop {
        let line = match io.read_line(MAX_COMMAND_BYTES).await {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                io.write_all(b"500 5.5.2 Line too long\r\n").await?;
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        let Some(command_line) = trim_crlf(&line) else {
            io.write_all(b"500 5.5.1 Command not recognized: \r\n")
                .await?;
            continue;
        };
        let command_line = command_line.trim_ascii();
        let (verb, argument) = split_command(command_line);
        let upper = verb.to_ascii_uppercase();
        match upper.as_str() {
            "EHLO" | "HELO" => {
                if argument.trim().is_empty() {
                    io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?;
                    continue;
                }
                helo = argument.trim().to_owned();
                state = SessionState::Greeted;
                envelope.reset();
                let response = if upper == "EHLO" {
                    b"250-lmyzmail Hello "
                } else {
                    b"250 lmyzmail Hello "
                };
                io.write_all(response).await?;
                io.write_all(helo.as_bytes()).await?;
                if upper == "EHLO" {
                    io.write_all(
                        b"\r\n250-PIPELINING\r\n250-SIZE 15728640\r\n250-8BITMIME\r\n250-CHUNKING\r\n",
                    )
                    .await?;
                    if service.tls_acceptor.is_some() && !tls_active {
                        io.write_all(b"250-STARTTLS\r\n").await?;
                    }
                    if service.config.smtp_skibidi.enabled {
                        io.write_all(
                            b"250-ENHANCEDSTATUSCODES\r\n250-SMTPUTF8\r\n250 SKIBIDITOILET\r\n",
                        )
                        .await?;
                    } else {
                        io.write_all(b"250-ENHANCEDSTATUSCODES\r\n250 SMTPUTF8\r\n")
                            .await?;
                    }
                } else {
                    io.write_all(b"\r\n").await?;
                }
            }
            "MAIL" => {
                if auth_probe_count >= 20 {
                    io.write_all(b"550 5.7.1 Access denied\r\n").await?;
                    continue;
                }
                if state != SessionState::Greeted || envelope.sender.is_some() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                    continue;
                }
                match parse_mail(argument) {
                    Ok(Some(sender)) => {
                        if let Some(message) =
                            service.sender_domain_rejection(peer, &sender.canonical)
                        {
                            io.write_all(format!("550 {message}\r\n").as_bytes())
                                .await?;
                            continue;
                        }
                        if let Some(wire) = service
                            .spamhaus_rejection(peer, &sender.original, &connection_cancellation)
                            .await
                        {
                            io.write_all(&wire).await?;
                            continue;
                        }
                        let spf = if sender.canonical.is_empty() {
                            None
                        } else {
                            Some(
                                service
                                    .spf_verifier
                                    .verify(
                                        peer,
                                        &helo,
                                        &service.config.domain,
                                        &sender.canonical,
                                        &connection_cancellation,
                                    )
                                    .await,
                                )
                        };
                        let dmarc_record = if sender.canonical.is_empty() {
                            None
                        } else {
                            service
                                .dmarc_verifier
                                .lookup_sender_record(
                                    &sender.canonical,
                                    &connection_cancellation,
                                )
                                .await
                        };
                        if let Some(verification) = spf.as_ref()
                            && let Some(message) = service
                                .self_spoof_rejection(
                                    peer,
                                    &sender.canonical,
                                    verification,
                                    &connection_cancellation,
                                )
                                .await
                        {
                            io.write_all(format!("550 {message}\r\n").as_bytes())
                                .await?;
                            continue;
                        }
                        envelope.sender = Some(sender.canonical);
                        envelope.recipients.clear();
                        envelope.spf = spf;
                        envelope.dmarc_record = dmarc_record;
                        io.write_all(b"250 2.1.0 Sender OK\r\n").await?;
                    }
                    Ok(None) => io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?,
                    Err(ParseError::TooLarge) => io.write_all(b"552 5.3.4 Message size exceeds limit of 15728640 bytes\r\n").await?,
                    Err(ParseError::Invalid) => io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?,
                }
            }
            "RCPT" => {
                if state != SessionState::Greeted || envelope.sender.is_none() {
                    let metadata = format!(
                        "Bad sequence: RCPT in state {}",
                        state.oracle_name(&envelope),
                    );
                    service.queue_protocol_violation(
                        peer,
                        &helo,
                        &session_id,
                        &metadata,
                    );
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                    continue;
                }
                match parse_recipient(argument) {
                    Some(recipient) => {
                        let Some((_, recipient_domain)) = recipient.rsplit_once('@') else {
                            io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?;
                            continue;
                        };
                        let normalized_domain = recipient_domain.trim_end_matches('.').to_ascii_lowercase();
                        let Some(domain_config) = service.config.domain_config(&normalized_domain) else {
                            io.write_all(format!("550 5.1.2 Domain not accepted: {normalized_domain}\r\n").as_bytes()).await?;
                            continue;
                        };
                        if !domain_config.receive_enabled {
                            io.write_all(format!("550 5.1.2 Domain does not accept mail: {normalized_domain}\r\n").as_bytes()).await?;
                        } else if envelope.recipients.len() >= MAX_RECIPIENTS {
                            io.write_all(b"452 4.5.3 Too many recipients\r\n").await?;
                        } else if !domain_config.require_existing_mailbox || service.mailbox_exists(&recipient).await? {
                            envelope.recipients.push(recipient);
                            io.write_all(b"250 2.1.5 Recipient OK\r\n").await?;
                        } else {
                            io.write_all(format!("550 5.1.1 Mailbox not found: {recipient}\r\n").as_bytes()).await?;
                        }
                    }
                    None => io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?,
                }
            }
            "DATA" => {
                if state != SessionState::Greeted || envelope.sender.is_none() || envelope.recipients.is_empty() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                    continue;
                }
                io.write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n").await?;
                match read_data(&mut io).await {
                    Ok(Some(data)) => {
                        envelope.data = data;
                        match service
                            .deliver(
                                envelope.clone(),
                                peer,
                                &helo,
                                tls_active,
                                &connection_cancellation,
                            )
                            .await
                        {
                            Ok(id) => io.write_all(format!("250 2.0.0 Message accepted for delivery, id={id}\r\n").as_bytes()).await?,
                            Err(error) => {
                                eprintln!("lmyzmail SMTP DATA delivery failed: {error}");
                                io.write_all(b"451 4.3.0 Temporary delivery failure\r\n")
                                    .await?
                            }
                        }
                        envelope.reset();
                    }
                    Ok(None) => return Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                        io.write_all(b"552 5.3.4 Message size exceeds limit of 15728640 bytes\r\n").await?;
                        envelope.reset();
                    }
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
            "BDAT" => {
                if state != SessionState::Greeted || envelope.sender.is_none() || envelope.recipients.is_empty() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                    continue;
                }
                match parse_bdat(argument) {
                    Ok((size, last)) if size <= MAX_MESSAGE_BYTES.saturating_sub(envelope.data.len()) => {
                        if size == 0 && last {
                            envelope.reset();
                            io.write_all(b"250 2.0.0 0 bytes received\r\n").await?;
                            continue;
                        }
                        let chunk = io.read_exact_bytes(size).await?;
                        envelope.data.extend_from_slice(&chunk);
                        if last {
                            match service
                                .deliver(
                                    envelope.clone(),
                                    peer,
                                    &helo,
                                    tls_active,
                                    &connection_cancellation,
                                )
                                .await
                            {
                                Ok(id) => io.write_all(format!("250 2.0.0 Message accepted for delivery, id={id}\r\n").as_bytes()).await?,
                                Err(error) => {
                                    eprintln!("lmyzmail SMTP BDAT delivery failed: {error}");
                                    io.write_all(b"451 4.3.0 Temporary delivery failure\r\n")
                                        .await?
                                }
                            }
                            envelope.reset();
                        } else {
                            io.write_all(format!("250 2.0.0 {size} bytes received\r\n").as_bytes()).await?;
                        }
                    }
                    Ok(_) => {
                        envelope.reset();
                        io.write_all(b"552 5.3.4 Message size exceeds limit of 15728640 bytes\r\n").await?;
                    }
                    Err(_) => io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?,
                }
            }
            "RSET" => {
                envelope.reset();
                io.write_all(b"250 2.0.0 Reset OK\r\n").await?;
            }
            "NOOP" => io.write_all(b"250 OK\r\n").await?,
            "HELP" => io.write_all(b"214-Supported commands:\r\n214-HELO EHLO MAIL RCPT DATA BDAT\r\n214-RSET NOOP QUIT VRFY HELP STARTTLS\r\n214 For more information, see RFC 5321\r\n").await?,
            "STARTTLS" => {
                let Some(acceptor) = service.tls_acceptor.as_ref() else {
                    io.write_all(b"502 5.5.1 STARTTLS command not implemented\r\n")
                        .await?;
                    continue;
                };
                if tls_active || envelope.sender.is_some() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                    continue;
                }
                io.write_all(b"220 2.0.0 Ready to start TLS\r\n").await?;
                // Never interpret bytes that were already buffered before the TLS
                // handshake as plaintext SMTP commands.
                if !io.buffer.is_empty() {
                    return Ok(());
                }
                match timeout(TLS_HANDSHAKE_TIMEOUT, io.upgrade_tls(acceptor)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => return Ok(()),
                }
                tls_active = true;
                state = SessionState::Connected;
                helo = "localhost".to_owned();
                envelope.reset();
            }
            "VRFY" => io.write_all(b"252 2.5.2 Cannot verify user, but will accept message and attempt delivery\r\n").await?,
            "AUTH" => {
                if state != SessionState::Greeted || envelope.sender.is_some() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                } else {
                    auth_probe_count = auth_probe_count.saturating_add(1);
                    io.write_all(b"502 5.5.1 AUTH command not implemented. Blud is yapping about AUTH but nobody is listening. We don't do that here. Take your L and go back to the lobby.\r\n").await?;
                }
            }
            "SKIBIDITOILET" if service.config.smtp_skibidi.enabled => {
                handle_skibidi_command(
                    &mut io,
                    argument,
                    &mut quiz_state,
                    service.skibidi_video.as_ref(),
                    &connection_cancellation,
                )
                .await?;
            }
            "QUIT" => {
                drop(quiz_state.take());
                io.write_all(b"221 2.0.0 lmyzmail closing connection\r\n").await?;
                return Ok(());
            }
            _ => {
                dispatcher_errors = dispatcher_errors.saturating_add(1);
                if dispatcher_errors >= 10 {
                    io.write_all(b"421 4.3.2 lmyzmail Service not available\r\n").await?;
                    return Ok(());
                }
                io.write_all(
                    format!("500 5.5.1 Command not recognized: {upper}\r\n").as_bytes(),
                )
                .await?;
            }
        }
    }
}

fn configure_connection_socket(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ParseError {
    Invalid,
    TooLarge,
}

fn trim_crlf(line: &[u8]) -> Option<&[u8]> {
    line.strip_suffix(b"\r\n")
}

fn split_command(line: &[u8]) -> (&str, &str) {
    let text = std::str::from_utf8(line).unwrap_or("");
    text.split_once(char::is_whitespace)
        .map_or((text, ""), |(verb, argument)| (verb, argument))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedMailFrom {
    canonical: String,
    original: String,
}

fn parse_mail(argument: &str) -> Result<Option<ParsedMailFrom>, ParseError> {
    let trimmed = argument.trim_start();
    let Some(rest) = trimmed
        .strip_prefix("FROM:")
        .or_else(|| trimmed.strip_prefix("from:"))
    else {
        return Ok(None);
    };
    let mut parts = rest.split_whitespace();
    let path = parts.next().ok_or(ParseError::Invalid)?;
    if path == "<>" {
        if let Some(parameter) = parts.next()
            && let Some(size) = parameter.strip_prefix("SIZE=")
        {
            let size = size.parse::<usize>().map_err(|_| ParseError::Invalid)?;
            if size > MAX_MESSAGE_BYTES {
                return Err(ParseError::TooLarge);
            }
        }
        return Ok(Some(ParsedMailFrom {
            canonical: String::new(),
            original: String::new(),
        }));
    }
    let Some(value) = path
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
    else {
        return Ok(None);
    };
    if value.is_empty() || !value.contains('@') {
        return Ok(None);
    }
    Ok(Some(ParsedMailFrom {
        canonical: value.to_ascii_lowercase(),
        original: value.to_owned(),
    }))
}

fn parse_recipient(argument: &str) -> Option<String> {
    let trimmed = argument.trim_start();
    let rest = trimmed
        .strip_prefix("TO:")
        .or_else(|| trimmed.strip_prefix("to:"))?
        .trim();
    let value = rest
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .unwrap_or(rest);
    if !value.contains('@') || value.contains(char::is_whitespace) {
        return None;
    }
    normalize_mailbox(value).ok()
}

fn parse_bdat(argument: &str) -> Result<(usize, bool), ParseError> {
    let mut parts = argument.split_whitespace();
    let size = parts
        .next()
        .ok_or(ParseError::Invalid)?
        .parse::<usize>()
        .map_err(|_| ParseError::Invalid)?;
    let last = parts
        .next()
        .is_some_and(|word| word.eq_ignore_ascii_case("LAST"));
    if parts.next().is_some() {
        return Err(ParseError::Invalid);
    }
    Ok((size, last))
}

async fn read_data(io: &mut BufferedConnection) -> io::Result<Option<Vec<u8>>> {
    let mut data = Vec::new();
    loop {
        let Some(line) = io
            .read_line(MAX_MESSAGE_BYTES.saturating_sub(data.len()))
            .await?
        else {
            return Ok(None);
        };
        if line == b".\r\n" {
            return Ok(Some(data));
        }
        let content = line.strip_prefix(b".").unwrap_or(&line);
        if data.len().saturating_add(content.len()) > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        data.extend_from_slice(content);
    }
}

#[cfg(test)]
fn header_value(data: &[u8], wanted: &str) -> Option<String> {
    let header_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(data.len());
    let text = std::str::from_utf8(&data[..header_end]).ok()?;
    text.split("\r\n")
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted)
                .then(|| value.trim().to_owned())
        })
}

fn address_list_json(value: &str) -> String {
    let addresses = value
        .split(',')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                return None;
            }
            let address = trimmed
                .rsplit_once('<')
                .and_then(|(_, rest)| rest.strip_suffix('>'))
                .unwrap_or(trimmed)
                .trim();
            (!address.is_empty()).then(|| address.to_ascii_lowercase())
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&addresses).unwrap_or_else(|_| "[]".to_owned())
}

struct MessageComposition<'a> {
    mailbox: &'a str,
    peer: IpAddr,
    helo: &'a str,
    encrypted: bool,
    received_at: DateTime<Utc>,
    received_id: &'a str,
    content_scan: &'a ContentScan,
    content_filter: &'a ContentFilterConfig,
}

fn compose_message(envelope: &Envelope, composition: MessageComposition<'_>) -> Vec<u8> {
    let MessageComposition {
        mailbox,
        peer,
        helo,
        encrypted,
        received_at,
        received_id,
        content_scan,
        content_filter,
    } = composition;
    let sender_clause = envelope
        .sender
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("");
    let auth_spf = if sender_clause.is_empty() {
        "spf=none (No MAIL FROM address)".to_owned()
    } else if let Some(spf) = envelope.spf.as_ref() {
        format!("spf={} ({})", spf.result(), spf.reason())
    } else {
        "spf=temperror (SPF verification unavailable)".to_owned()
    };
    let auth_dkim = envelope.dkim.as_ref().map_or_else(
        || "dkim=temperror (DKIM verification unavailable)".to_owned(),
        |verification| format!("dkim={} ({})", verification.result(), verification.reason()),
    );
    let auth_dmarc = envelope.dmarc.as_ref().map_or_else(
        || "dmarc=none No DMARC record found".to_owned(),
        DmarcVerification::authentication_result,
    );
    let protocol = if encrypted { "ESMTPS" } else { "ESMTP" };
    let date = java_rfc1123(received_at);
    let status = if content_scan.is_suspicious(content_filter)
        || envelope
            .spf
            .as_ref()
            .is_some_and(SpfVerification::should_quarantine)
        || envelope
            .dkim
            .as_ref()
            .is_some_and(DkimVerification::should_quarantine)
        || envelope
            .dmarc
            .as_ref()
            .is_some_and(DmarcVerification::should_quarantine)
    {
        "Yes"
    } else {
        "No"
    };
    let protocol_score = envelope
        .spf
        .as_ref()
        .map_or(0.0, SpfVerification::protocol_score)
        + envelope
            .dkim
            .as_ref()
            .map_or(0.0, DkimVerification::protocol_score)
        + envelope
            .dmarc
            .as_ref()
            .map_or(0.0, DmarcVerification::protocol_score);
    let total_score = java_one_decimal(content_scan.total_score() + protocol_score);
    let reverse_dns = match peer {
        IpAddr::V4(address) if address == Ipv4Addr::LOCALHOST => "localhost",
        IpAddr::V6(address) if address == Ipv6Addr::LOCALHOST => "localhost",
        _ => "unverified",
    };
    let mut header = format!(
        "Received: from {helo} ({reverse_dns} [{peer}])\r\n\tby {HOSTNAME} with {protocol} id {received_id}\r\n\tfor <{mailbox}>;\r\n\t{date}\r\nAuthentication-Results: {HOSTNAME};\r\n\t{auth_spf} smtp.client-ip={peer} smtp.mailfrom={sender_clause};\r\n\t{auth_dkim};\r\n\t{auth_dmarc}\r\nX-Spam-Status: {status}\r\nX-Spam-Score: {total_score}\r\n",
    );
    let rules = content_scan
        .hits()
        .map(|(name, score)| format!("{name}={}", java_one_decimal(score)))
        .collect::<Vec<_>>();
    if !rules.is_empty() {
        header.push_str("X-Spam-Rules: ");
        header.push_str(&rules.join(", "));
        header.push_str("\r\n");
    }
    let mut output = header.into_bytes();
    output.extend_from_slice(&envelope.data);
    output
}

fn java_one_decimal(value: f64) -> String {
    debug_assert!(value.is_finite() && value >= 0.0);
    let tenths = (value * 10.0).round() as u64;
    format!("{}.{:01}", tenths / 10, tenths % 10)
}

fn java_rfc1123(value: DateTime<Utc>) -> String {
    let weekday = match value.weekday() {
        Weekday::Mon => "Mon",
        Weekday::Tue => "Tue",
        Weekday::Wed => "Wed",
        Weekday::Thu => "Thu",
        Weekday::Fri => "Fri",
        Weekday::Sat => "Sat",
        Weekday::Sun => "Sun",
    };
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][value.month0() as usize];
    format!(
        "{weekday}, {} {month} {} {:02}:{:02}:{:02} GMT",
        value.day(),
        value.year(),
        value.hour(),
        value.minute(),
        value.second()
    )
}

fn random_hex(bytes: usize) -> Result<String, getrandom::Error> {
    let mut value = vec![0_u8; bytes];
    fill_random(&mut value)?;
    Ok(value
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn random_hex_upper(bytes: usize) -> Result<String, getrandom::Error> {
    let mut value = vec![0_u8; bytes];
    fill_random(&mut value)?;
    Ok(value
        .into_iter()
        .map(|byte| format!("{byte:02X}"))
        .collect())
}

fn maildir_lock_index(mailbox: &str, folder: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    mailbox.hash(&mut hasher);
    folder.hash(&mut hasher);
    (hasher.finish() as usize) % MAILDIR_SHARD_LOCKS
}

fn inspect_inbound_subdirectory(folder_root: &Path) -> io::Result<(i32, usize)> {
    if !folder_root.exists() {
        return Ok((1, 0));
    }

    let mut maximum = 0_i32;
    for entry in std::fs::read_dir(folder_root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let Some(index) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| *value > 0)
        else {
            continue;
        };
        maximum = maximum.max(index);
    }
    if maximum == 0 {
        return Ok((1, 0));
    }

    let maximum_path = folder_root.join(maximum.to_string());
    let mut file_count = 0_usize;
    for entry in std::fs::read_dir(maximum_path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_file()
            && !file_type.is_symlink()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".eml"))
        {
            file_count = file_count.saturating_add(1);
        }
    }
    Ok((maximum, file_count))
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct PublishedInboundOwnership {
    parent: std::path::PathBuf,
    file_name: OsString,
    device: u64,
    inode: u64,
}

#[cfg(test)]
fn atomic_publish(
    temporary: &Path,
    final_path: &Path,
    data: &[u8],
) -> io::Result<PublishedInboundOwnership> {
    use rustix::fs::{
        AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags, fstat, openat2, renameat_with,
        statat, unlinkat,
    };

    let temporary_parent = temporary
        .parent()
        .ok_or_else(|| io::Error::other("missing temp parent"))?;
    let final_parent = final_path
        .parent()
        .ok_or_else(|| io::Error::other("missing final parent"))?;
    let temporary_name = temporary
        .file_name()
        .ok_or_else(|| io::Error::other("missing temp filename"))?;
    let final_name = final_path
        .file_name()
        .ok_or_else(|| io::Error::other("missing final filename"))?;
    let temporary_directory = open_maildir_directory(temporary_parent)?;
    let final_directory = open_maildir_directory(final_parent)?;
    let descriptor = openat2(
        &temporary_directory,
        temporary_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let mut file = std::fs::File::from(descriptor);
    let identity = (|| {
        use std::io::Write as _;
        file.write_all(data)?;
        file.flush()?;
        sync_all(&file)?;
        fstat(&file).map_err(io::Error::from)
    })();
    let identity = match identity {
        Ok(identity) => identity,
        Err(error) => {
            let _ = unlinkat(&temporary_directory, temporary_name, AtFlags::empty());
            let _ = fsync(&temporary_directory);
            return Err(error);
        }
    };
    if FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile
        || identity.st_size < 0
        || identity.st_size as usize != data.len()
    {
        let _ = unlinkat(&temporary_directory, temporary_name, AtFlags::empty());
        let _ = fsync(&temporary_directory);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SMTP temporary is not the expected regular file",
        ));
    }
    let mut published = false;
    let result = (|| {
        renameat_with(
            &temporary_directory,
            temporary_name,
            &final_directory,
            final_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)?;
        published = true;
        fsync(&final_directory).map_err(io::Error::from)?;
        fsync(&temporary_directory).map_err(io::Error::from)
    })();
    if let Err(error) = result {
        let (directory, name) = if published {
            (&final_directory, final_name)
        } else {
            (&temporary_directory, temporary_name)
        };
        let owned = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(|stat| {
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                && stat.st_dev == identity.st_dev
                && stat.st_ino == identity.st_ino
        });
        if owned {
            let _ = unlinkat(directory, name, AtFlags::empty());
            let _ = fsync(directory);
        }
        return Err(error);
    }
    Ok(PublishedInboundOwnership {
        parent: final_parent.to_path_buf(),
        file_name: final_name.to_os_string(),
        device: identity.st_dev,
        inode: identity.st_ino,
    })
}

fn open_maildir_directory(path: &Path) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags, fstat, openat2};

    let directory = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let stat = fstat(&directory).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SMTP Maildir parent is not a directory",
        ));
    }
    Ok(directory)
}

#[cfg(test)]
fn remove_published_file(published: &PublishedInboundOwnership) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType, statat, unlinkat};

    let parent = open_maildir_directory(&published.parent)?;
    let stat = statat(&parent, &published.file_name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_dev != published.device
        || stat.st_ino != published.inode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "published Maildir path no longer references the owned inode",
        ));
    }
    unlinkat(&parent, &published.file_name, AtFlags::empty()).map_err(io::Error::from)?;
    fsync(&parent).map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn smtp_test_directory(label: &str) -> std::path::PathBuf {
        let mut nonce = [0_u8; 16];
        fill_random(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "lmyzmail-smtp-{label}-{}",
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn accepted_connection_enables_tcp_nodelay_before_smtp_io() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let _client = client.unwrap();
        let (server, _) = accepted.unwrap();
        server.set_nodelay(false).unwrap();
        assert!(!server.nodelay().unwrap());

        configure_connection_socket(&server).unwrap();

        assert!(server.nodelay().unwrap());
    }

    #[test]
    fn inbound_shard_allocator_reserves_without_overfilling_a_shard() {
        let root = smtp_test_directory("shard-reservation");
        std::fs::create_dir(root.join("1")).unwrap();
        std::fs::write(root.join("1/one.eml"), b"one").unwrap();
        std::fs::write(root.join("1/two.eml"), b"two").unwrap();
        let allocator = InboundShardAllocator::default();
        let allocator = Arc::new(allocator);
        for expected in [2, 2, 3] {
            let mut reservation = allocator
                .reserve(&root, "qa@example.test", "inbox", 2)
                .unwrap();
            assert_eq!(reservation.subdirectory(), expected);
            reservation.mark_durable();
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inbound_shard_allocator_rolls_back_only_nondurable_reservations() {
        let root = smtp_test_directory("shard-rollback");
        let allocator = Arc::new(InboundShardAllocator::default());
        let reservation = allocator
            .reserve(&root, "qa@example.test", "inbox", 1)
            .unwrap();
        assert_eq!(reservation.subdirectory(), 1);
        drop(reservation);

        let mut durable = allocator
            .reserve(&root, "qa@example.test", "inbox", 1)
            .unwrap();
        assert_eq!(durable.subdirectory(), 1);
        durable.mark_durable();
        drop(durable);
        let next = allocator
            .reserve(&root, "qa@example.test", "inbox", 1)
            .unwrap();
        assert_eq!(next.subdirectory(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inbound_shard_allocator_cache_has_a_hard_bound() {
        let root = smtp_test_directory("shard-cache-bound");
        let allocator = Arc::new(InboundShardAllocator::default());
        for value in 0..MAX_INBOUND_SHARD_CACHE_ENTRIES {
            allocator
                .reserve(&root, &format!("mailbox-{value}@example.test"), "inbox", 10)
                .unwrap();
        }
        allocator
            .reserve(&root, "overflow@example.test", "inbox", 10)
            .unwrap();
        let lengths = allocator
            .shards
            .iter()
            .map(|shard| shard.lock().unwrap().len())
            .collect::<Vec<_>>();
        assert!(
            lengths
                .iter()
                .all(|length| *length <= MAX_INBOUND_SHARD_CACHE_ENTRIES_PER_LOCK)
        );
        assert!(lengths.iter().sum::<usize>() <= MAX_INBOUND_SHARD_CACHE_ENTRIES);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inbound_shard_allocator_never_evicts_in_flight_entries() {
        let root = smtp_test_directory("shard-active-bound");
        let allocator = Arc::new(InboundShardAllocator::default());
        let partition = 0;
        let mut mailboxes = Vec::new();
        let mut value = 0_u64;
        while mailboxes.len() <= MAX_INBOUND_SHARD_CACHE_ENTRIES_PER_LOCK {
            let mailbox = format!("active-{value}@example.test");
            if maildir_lock_index(&mailbox, "inbox") == partition {
                mailboxes.push(mailbox);
            }
            value = value.saturating_add(1);
        }
        let mut active = Vec::new();
        for mailbox in mailboxes
            .iter()
            .take(MAX_INBOUND_SHARD_CACHE_ENTRIES_PER_LOCK)
        {
            active.push(allocator.reserve(&root, mailbox, "inbox", 10).unwrap());
        }
        let error = allocator
            .reserve(
                &root,
                &mailboxes[MAX_INBOUND_SHARD_CACHE_ENTRIES_PER_LOCK],
                "inbox",
                10,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(allocator.shards[partition].lock().unwrap().len(), 64);

        drop(active.remove(0));
        let replacement = allocator
            .reserve(
                &root,
                &mailboxes[MAX_INBOUND_SHARD_CACHE_ENTRIES_PER_LOCK],
                "inbox",
                10,
            )
            .unwrap();
        let states = allocator.shards[partition].lock().unwrap();
        assert_eq!(states.len(), 64);
        assert!(active.iter().all(|guard| states.contains_key(&guard.key)));
        assert!(states.contains_key(&replacement.key));
        drop(states);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skibidi_help_wire_is_exactly_frozen() {
        let wire = multiline_reply(214, SKIBIDI_HELP_LINES);
        assert_eq!(SKIBIDI_HELP_LINES.len(), 47);
        assert_eq!(wire.len(), 2_267);
        let digest = Sha256::digest(&wire)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            digest,
            "a9e3fc50710c4061298ee32f48887633bc4ae74afd7445bd293aa64b37e828e6"
        );
        assert!(wire.ends_with(b"214 214 End of HELP. Skibidi dop dop yes yes.\r\n"));
    }

    #[test]
    fn parses_mail_rcpt_and_bdat_bounds() {
        let null_sender = ParsedMailFrom {
            canonical: String::new(),
            original: String::new(),
        };
        assert_eq!(parse_mail("FROM:<>").unwrap(), Some(null_sender.clone()));
        assert_eq!(
            parse_mail("FROM:<qa@example.test> SIZE=10").unwrap(),
            Some(ParsedMailFrom {
                canonical: "qa@example.test".into(),
                original: "qa@example.test".into(),
            })
        );
        assert_eq!(parse_mail("FROM:<>").unwrap(), Some(null_sender.clone()));
        assert_eq!(parse_mail("FROM:<>").unwrap(), Some(null_sender));
        assert_eq!(
            parse_mail("FROM:<Sender@KnOwN-DbL.CoM>").unwrap(),
            Some(ParsedMailFrom {
                canonical: "sender@known-dbl.com".into(),
                original: "Sender@KnOwN-DbL.CoM".into(),
            })
        );
        assert_eq!(
            parse_recipient("TO:<qa@example.test>"),
            Some("qa@example.test".into())
        );
        assert_eq!(
            parse_recipient("TO:qa@example.test"),
            Some("qa@example.test".into())
        );
        assert_eq!(parse_bdat("10 LAST"), Ok((10, true)));
        assert_eq!(parse_bdat("10"), Ok((10, false)));
        assert!(parse_bdat("10 LAST extra").is_err());
    }

    #[test]
    fn recipient_parser_canonicalizes_pathish_eai_and_boundary_addresses() {
        for address in [
            "foo/bar@example.test".to_owned(),
            "/absolute/qa@example.test".to_owned(),
            "../qa@example.test".to_owned(),
            "foo%bar@example.test".to_owned(),
            format!("{}@example.test", "邮".repeat(50)),
            format!("{}@example.test", "a".repeat(242)),
        ] {
            assert_eq!(
                parse_recipient(&format!("TO:<{address}>")),
                Some(address.to_lowercase())
            );
        }
        assert!(parse_recipient(&format!("TO:<{}@example.test>", "a".repeat(243))).is_none());
        assert!(parse_recipient("TO:<qa user@example.test>").is_none());
    }

    #[test]
    fn inbound_atomic_publish_is_dirfd_bound_and_replacement_safe() {
        let root = smtp_test_directory("atomic");
        let temporary_root = secure_mailbox_folder(&root, "qa@example.test", "temp").unwrap();
        let final_root = secure_mailbox_folder(&root, "qa@example.test", "inbox").unwrap();
        let temporary =
            temporary_root.join(".lmyzmail-incoming-00112233445566778899aabbccddeeff.tmp");
        let final_path = final_root.join("message.eml");
        let published = atomic_publish(&temporary, &final_path, b"owned message").unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), b"owned message");

        let displaced = root.join("displaced.eml");
        std::fs::rename(&final_path, &displaced).unwrap();
        std::fs::write(&final_path, b"replacement").unwrap();
        assert!(remove_published_file(&published).is_err());
        assert_eq!(std::fs::read(&final_path).unwrap(), b"replacement");
        assert_eq!(std::fs::read(&displaced).unwrap(), b"owned message");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbound_atomic_publish_rejects_symlink_parent_without_outside_write() {
        use std::os::unix::fs::symlink;

        let root = smtp_test_directory("atomic-link");
        let outside = smtp_test_directory("atomic-outside");
        let temporary_root = root.join("temp");
        std::fs::create_dir(&temporary_root).unwrap();
        symlink(&outside, root.join("inbox")).unwrap();
        let temporary =
            temporary_root.join(".lmyzmail-incoming-00112233445566778899aabbccddeeff.tmp");
        let final_path = root.join("inbox/message.eml");

        assert!(atomic_publish(&temporary, &final_path, b"must not escape").is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn data_unstuffs_one_leading_dot_and_preserves_binary_bytes() {
        let mut line = b"..hello\r\n".to_vec();
        let content = line.strip_prefix(b".").unwrap();
        assert_eq!(content, b".hello\r\n");
        line.extend_from_slice(b"\0\xff");
        assert_eq!(&line[line.len() - 2..], b"\0\xff");
    }

    #[test]
    fn java_date_uses_unpadded_day_and_gmt() {
        let value = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(java_rfc1123(value), "Mon, 1 Jan 2024 00:00:00 GMT");
    }

    #[test]
    fn content_filter_headers_are_composed_in_frozen_order() {
        let envelope = Envelope {
            sender: None,
            recipients: vec!["qa@example.test".into()],
            data: b"From: sender@external.test\r\nDate: Tue, 5 Aug 2025 12:00:00 GMT\r\nSubject: =?UTF-8?Q?FREE?= =?ISO-8859-1?Q?MONEY?=\r\nMessage-ID: <encoded@example.test>\r\n\r\nbody\r\n".to_vec(),
            spf: None,
            dkim: None,
            dmarc_record: None,
            dmarc: None,
        };
        let config = ContentFilterConfig::default();
        let scan = ParsedHeaders::parse(&envelope.data)
            .unwrap()
            .scan(0, &config);
        let received_at = chrono::DateTime::parse_from_rfc3339("2025-08-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let raw = compose_message(
            &envelope,
            MessageComposition {
                mailbox: "qa@example.test",
                peer: "127.0.0.1".parse().unwrap(),
                helo: "blackbox.example",
                encrypted: false,
                received_at,
                received_id: "ABCDEF01234567",
                content_scan: &scan,
                content_filter: &config,
            },
        );
        let text = String::from_utf8(raw).unwrap();
        assert!(text.contains(
            "X-Spam-Status: No\r\nX-Spam-Score: 2.5\r\nX-Spam-Rules: SUBJECT_ENCODING_TRICK=2.5\r\nFrom: sender@external.test\r\n"
        ));
    }

    #[test]
    fn content_filter_empty_scan_serializes_positive_zero() {
        let envelope = Envelope {
            sender: None,
            recipients: vec!["qa@example.test".into()],
            data: b"From: sender@external.test\r\nDate: Tue, 5 Aug 2025 12:00:00 GMT\r\nSubject: clean\r\nMessage-ID: <clean@example.test>\r\n\r\nbody\r\n".to_vec(),
            spf: None,
            dkim: None,
            dmarc_record: None,
            dmarc: None,
        };
        let config = ContentFilterConfig::default();
        let scan = ParsedHeaders::parse(&envelope.data)
            .unwrap()
            .scan(0, &config);
        let received_at = chrono::DateTime::parse_from_rfc3339("2025-08-05T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let raw = compose_message(
            &envelope,
            MessageComposition {
                mailbox: "qa@example.test",
                peer: "127.0.0.1".parse().unwrap(),
                helo: "blackbox.example",
                encrypted: false,
                received_at,
                received_id: "ABCDEF01234567",
                content_scan: &scan,
                content_filter: &config,
            },
        );
        let text = String::from_utf8(raw).unwrap();
        assert!(text.contains("X-Spam-Status: No\r\nX-Spam-Score: 0.0\r\n"));
        assert!(!text.contains("X-Spam-Score: -0.0"));
    }

    #[test]
    fn content_filter_score_formatting_matches_java_half_up_ties() {
        assert_eq!(java_one_decimal(0.0), "0.0");
        assert_eq!(java_one_decimal(-0.0), "0.0");
        assert_eq!(java_one_decimal(2.24), "2.2");
        assert_eq!(java_one_decimal(2.25), "2.3");
        assert_eq!(java_one_decimal(18.25), "18.3");
    }

    #[test]
    fn header_only_mime_parse_decodes_adjacent_encoded_words_like_java_indexing() {
        let message = b"Subject: =?UTF-8?Q?FREE?= =?ISO-8859-1?Q?MONEY?=\r\n\r\nbody";
        let subject = MessageParser::default()
            .parse_headers(message)
            .and_then(|parsed| parsed.subject().map(str::to_owned));
        assert_eq!(subject.as_deref(), Some("FREEMONEY"));
    }

    #[test]
    fn binary_body_does_not_break_header_indexing() {
        let message = b"From: Sender <sender@example.test>\r\n\
To: qa@example.test, Other <other@example.test>\r\n\
Subject: binary\r\nMessage-ID: <binary@example.test>\r\n\r\n\x00\xff\x80";
        assert_eq!(header_value(message, "subject").as_deref(), Some("binary"));
        assert_eq!(
            header_value(message, "message-id").as_deref(),
            Some("<binary@example.test>")
        );
        assert_eq!(
            address_list_json(&header_value(message, "to").unwrap()),
            r#"["qa@example.test","other@example.test"]"#
        );
    }

    #[test]
    fn attachment_index_matches_oracle_first_part_behavior() {
        let attachment_first = b"Content-Type: multipart/mixed; boundary=bb\r\n\r\n\
--bb\r\nContent-Disposition: attachment; filename=x\r\n\r\ndata\r\n\
--bb\r\nContent-Type: text/plain\r\n\r\nbody\r\n--bb--\r\n";
        let body_first = b"Content-Type: multipart/mixed; boundary=bb\r\n\r\n\
--bb\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
--bb\r\nContent-Disposition: attachment; filename=x\r\n\r\ndata\r\n--bb--\r\n";
        assert!(has_first_mime_attachment(attachment_first).unwrap());
        assert!(!has_first_mime_attachment(body_first).unwrap());
        assert!(
            has_first_mime_attachment(b"Content-Type: application/octet-stream\r\n\r\ndata\r\n")
                .unwrap()
        );
        assert!(
            has_first_mime_attachment(
                b"Content-Type: text/plain\r\nContent-Disposition: inline\r\n\r\ndata\r\n"
            )
            .unwrap()
        );
        assert!(has_first_mime_attachment(
            b"Content-Type: multipart/mixed; boundary=bb\r\n\r\n--bb\r\nContent-Type: application/pdf\r\n\r\ndata\r\n--bb--\r\n"
        )
        .unwrap());
        assert!(!has_first_mime_attachment(
            b"Content-Type: text/plain; boundary=bb\r\n\r\n--bb\r\nContent-Disposition: attachment; filename=x\r\n\r\ndata\r\n--bb--\r\n"
        )
        .unwrap());
        assert!(!has_first_mime_attachment(
            b"Content-Type: multipart/mixed; boundary=bb\r\n\r\n--bb\r\nContent-Type: message/rfc822\r\n\r\nContent-Type: text/plain\r\n\r\nbody\r\n--bb--\r\n"
        )
        .unwrap());
        assert!(has_first_mime_attachment(
            b"Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/plain\r\n\r\nbody\r\n--inner--\r\n--outer--\r\n"
        )
        .unwrap());
    }

    #[test]
    fn smtp_reply_sanitizer_blocks_response_injection_and_preserves_utf8_boundaries() {
        let malicious = format!(
            "5.7.1 rejected\r\n250 injected\0{}",
            "\u{e9}".repeat(MAX_SMTP_REPLY_TEXT_BYTES),
        );
        let sanitized = sanitize_smtp_reply_text(&malicious);
        assert!(sanitized.starts_with("5.7.1 rejected  250 injected "));
        assert!(sanitized.chars().all(|character| !character.is_control()));
        assert!(sanitized.len() <= MAX_SMTP_REPLY_TEXT_BYTES);
        assert!(std::str::from_utf8(sanitized.as_bytes()).is_ok());
    }

    #[test]
    fn oracle_state_name_is_derived_from_session_and_envelope() {
        let mut envelope = Envelope::default();
        assert_eq!(SessionState::Connected.oracle_name(&envelope), "CONNECT");
        assert_eq!(SessionState::Greeted.oracle_name(&envelope), "HELO");
        envelope.sender = Some("sender@example.test".to_owned());
        assert_eq!(SessionState::Greeted.oracle_name(&envelope), "MAIL");
        envelope.recipients.push("qa@example.test".to_owned());
        assert_eq!(SessionState::Greeted.oracle_name(&envelope), "RCPT");
    }

    #[tokio::test]
    async fn cringe_worker_uses_a_bounded_queue_and_drains_it_after_sender_close() {
        let (sender, receiver) = mpsc::channel(2);
        sender
            .try_send(SmtpCringeActivity::SelfSpoof {
                ip: "192.0.2.1".parse().unwrap(),
                mail_from: "sender@example.test".to_owned(),
                response_message: "rejected".to_owned(),
                metadata: "spf".to_owned(),
            })
            .unwrap();
        sender
            .try_send(SmtpCringeActivity::ProtocolViolation {
                ip: "192.0.2.1".parse().unwrap(),
                helo_name: "example.test".to_owned(),
                session_id: "01234567".to_owned(),
                metadata: "bad sequence".to_owned(),
            })
            .unwrap();
        assert!(matches!(
            sender.try_send(SmtpCringeActivity::ProtocolViolation {
                ip: "192.0.2.2".parse().unwrap(),
                helo_name: "example.test".to_owned(),
                session_id: "89abcdef".to_owned(),
                metadata: "queue full".to_owned(),
            }),
            Err(mpsc::error::TrySendError::Full(_)),
        ));
        drop(sender);

        let observed = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let worker_observed = Arc::clone(&observed);
        run_cringe_persistence_with(receiver, CancellationToken::new(), move |activity, _| {
            let worker_observed = Arc::clone(&worker_observed);
            async move {
                worker_observed.lock().await.push(activity.kind());
                Ok::<Option<i32>, CringeError>(None)
            }
        })
        .await;
        assert_eq!(
            *observed.lock().await,
            vec!["SELF_SPOOFING", "PROTOCOL_VIOLATION"],
        );
    }
}
