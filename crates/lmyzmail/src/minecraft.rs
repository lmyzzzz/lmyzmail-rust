use std::{
    collections::{HashMap, VecDeque},
    io::{self, Write as _},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI32, AtomicU64, Ordering},
    },
    time::{Duration, Instant as StdInstant},
};

use flate2::{Compression, write::ZlibEncoder};
use getrandom::fill as fill_random;
use icu_casemap::CaseMapper;
use md5::{Digest as _, Md5};
use openssl::{
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
    symm::{Cipher, Crypter, Mode},
};
use reqwest::{Client, StatusCode, redirect::Policy};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{Instant, sleep_until, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    auth::{AuthError, AuthService, LoginOutcome},
    bounded_blocking::{BoundedBlockingPool, SubmitError},
    config::{MinecraftConfig, RuntimeConfig},
    minecraft_world::{self, NbtValue, WorldTemplate},
};

const MAX_FRAME_LENGTH: usize = 2 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 64;
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(20);
const ACCEPT_RETRY_MIN: Duration = Duration::from_millis(25);
const ACCEPT_RETRY_MAX: Duration = Duration::from_secs(1);
const COMPRESSION_WORKERS: usize = 2;
const COMPRESSION_QUEUE: usize = 8;
const COMPRESSION_CHUNK_BYTES: usize = 64 * 1024;
const CRYPTO_WORKERS: usize = 2;
const CRYPTO_QUEUE: usize = 8;
const ENCRYPTION_FIELD_MAX_BYTES: usize = 512;
const VERIFY_TOKEN_BYTES: usize = 4;
const SHARED_SECRET_BYTES: usize = 16;
const AUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_AUTH_RESPONSE_BYTES: usize = 64 * 1024;
const POSITION_CHECK_INTERVAL: Duration = Duration::from_secs(2);
const HOLOGRAM_TELEPORT_INTERVAL: Duration = Duration::from_secs(2);
const TIME_UPDATE_INTERVAL: Duration = Duration::from_secs(15);
const MAX_SPAWN_DISTANCE: f64 = 100.0;
const RENDER_MAPS_X_DEFAULT: i32 = 10;
const RENDER_MAPS_X_MIN: i32 = 2;
const RENDER_MAPS_X_MAX: i32 = 24;
const RENDER_MAPS_Y_DEFAULT: i32 = 20;
const RENDER_MAPS_Y_MIN: i32 = 2;
const RENDER_MAPS_Y_MAX: i32 = 20;
const RENDER_FONT_SIZE_DEFAULT: i32 = 20;
const RENDER_FONT_SIZE_MIN: i32 = 8;
const RENDER_FONT_SIZE_MAX: i32 = 48;
const UPDATE_SIGN_LINE_MAX_UTF16_UNITS: usize = 384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionState {
    Handshake,
    Status,
    Login,
    Play,
}

#[derive(Debug)]
enum ProtocolError {
    Cancelled,
    TimedOut,
    Malformed,
    Io(io::Error),
}

const MAX_MINECRAFT_AUTH_RECORDS: usize = 16_384;

struct MinecraftAuthLimiter {
    max_attempts: usize,
    lockout: Duration,
    window: Duration,
    records: Mutex<HashMap<String, MinecraftAuthAttempt>>,
}

struct MinecraftAuthAttempt {
    failures: VecDeque<StdInstant>,
    locked_until: Option<StdInstant>,
}

#[derive(Default)]
struct MinecraftDraft {
    to: String,
    cc: String,
    bcc: String,
    subject: String,
    body_pages: Vec<String>,
}

struct WindowClick {
    window_id: u8,
    slot: i16,
    action_number: i16,
    mode: u8,
}

struct UpdateSign {
    lines: [String; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RenderSettings {
    maps_x: i32,
    maps_y: i32,
    font_size: i32,
}

impl Default for RenderSettings {
    fn default() -> Self {
        Self {
            maps_x: RENDER_MAPS_X_DEFAULT,
            maps_y: RENDER_MAPS_Y_DEFAULT,
            font_size: RENDER_FONT_SIZE_DEFAULT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MainMenuEffect {
    None,
    Close,
    SwitchAccount,
    OpenRenderSettings,
    OpenLogoutConfirm(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogoutConfirmEffect {
    None,
    OpenMainMenu(u8),
    Disconnect,
}

impl MinecraftDraft {
    fn clear(&mut self) {
        self.to.clear();
        self.cc.clear();
        self.bcc.clear();
        self.subject.clear();
        self.body_pages.clear();
    }
}

#[derive(Clone)]
struct MinecraftSlot {
    item_id: i16,
    count: u8,
    damage: i16,
    nbt: Option<NbtValue>,
}

impl MinecraftSlot {
    fn empty() -> Self {
        Self {
            item_id: -1,
            count: 0,
            damage: 0,
            nbt: None,
        }
    }

    fn item(item_id: i16, damage: i16, nbt: NbtValue) -> Self {
        Self {
            item_id,
            count: 1,
            damage,
            nbt: Some(nbt),
        }
    }
}

impl MinecraftAuthLimiter {
    fn new(config: &MinecraftConfig) -> Self {
        Self {
            max_attempts: config.auth_max_attempts as usize,
            lockout: Duration::from_secs(config.auth_lockout_seconds),
            window: Duration::from_secs(config.auth_window_seconds),
            records: Mutex::new(HashMap::with_capacity(64)),
        }
    }

    fn locked_remaining(&self, ip: &str) -> Option<u64> {
        self.locked_remaining_at(ip, StdInstant::now())
    }

    fn locked_remaining_at(&self, ip: &str, now: StdInstant) -> Option<u64> {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = records.get_mut(ip)?;
        match record.locked_until {
            Some(until) if until > now => Some(until.duration_since(now).as_secs()),
            Some(_) => {
                record.locked_until = None;
                record.failures.clear();
                None
            }
            None => None,
        }
    }

    fn record_failure(&self, ip: &str) -> (bool, usize) {
        self.record_failure_at(ip, StdInstant::now())
    }

    fn record_failure_at(&self, ip: &str, now: StdInstant) -> (bool, usize) {
        let window_start = now.checked_sub(self.window).unwrap_or(now);
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !records.contains_key(ip) && records.len() >= MAX_MINECRAFT_AUTH_RECORDS {
            records.retain(|_, record| {
                record.locked_until.is_some_and(|until| until > now)
                    || record
                        .failures
                        .back()
                        .is_some_and(|last| *last > window_start)
            });
            if records.len() >= MAX_MINECRAFT_AUTH_RECORDS {
                return (true, 0);
            }
        }
        let record = records
            .entry(ip.to_owned())
            .or_insert_with(|| MinecraftAuthAttempt {
                failures: VecDeque::new(),
                locked_until: None,
            });
        while record
            .failures
            .front()
            .is_some_and(|failure| *failure < window_start)
        {
            record.failures.pop_front();
        }
        record.failures.push_back(now);
        if record.failures.len() >= self.max_attempts {
            record.locked_until = Some(now + self.lockout);
            (true, 0)
        } else {
            (false, self.max_attempts - record.failures.len())
        }
    }

    fn clear(&self, ip: &str) {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(ip);
    }
}

struct OnlineModeService {
    private_key: Arc<Rsa<Private>>,
    public_key_der: Arc<[u8]>,
    crypto_pool: BoundedBlockingPool,
    session_client: Client,
    session_server_url: reqwest::Url,
}

impl OnlineModeService {
    fn new(config: &MinecraftConfig) -> io::Result<Self> {
        let rsa = Rsa::generate(1024).map_err(crypto_io)?;
        let public_key_der = PKey::from_rsa(rsa.clone())
            .and_then(|key| key.public_key_to_der())
            .map_err(crypto_io)?;
        if public_key_der.len() > ENCRYPTION_FIELD_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Minecraft RSA public key exceeded the protocol field limit",
            ));
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let session_client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(AUTH_REQUEST_TIMEOUT)
            .timeout(AUTH_REQUEST_TIMEOUT)
            .user_agent("lmyzmail-minecraft/0.1")
            .build()
            .map_err(io::Error::other)?;
        let session_server_url = reqwest::Url::parse(&config.session_server_url)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            private_key: Arc::new(rsa),
            public_key_der: public_key_der.into(),
            crypto_pool: BoundedBlockingPool::new(
                "lmyzmail-minecraft-crypto",
                CRYPTO_WORKERS,
                CRYPTO_QUEUE,
            )?,
            session_client,
            session_server_url,
        })
    }
}

struct PendingOnlineLogin {
    username: String,
    verify_token: [u8; VERIFY_TOKEN_BYTES],
}

struct MinecraftCipher {
    decryptor: Crypter,
    encryptor: Crypter,
    decrypt_scratch: Vec<u8>,
    encrypt_scratch: Vec<u8>,
}

impl MinecraftCipher {
    fn new(secret: &[u8; SHARED_SECRET_BYTES]) -> Result<Self, ProtocolError> {
        let cipher = Cipher::aes_128_cfb8();
        let mut decryptor =
            Crypter::new(cipher, Mode::Decrypt, secret, Some(secret)).map_err(crypto_protocol)?;
        let mut encryptor =
            Crypter::new(cipher, Mode::Encrypt, secret, Some(secret)).map_err(crypto_protocol)?;
        decryptor.pad(false);
        encryptor.pad(false);
        Ok(Self {
            decryptor,
            encryptor,
            decrypt_scratch: Vec::new(),
            encrypt_scratch: Vec::new(),
        })
    }

    fn decrypt_in_place(&mut self, bytes: &mut [u8]) -> Result<(), ProtocolError> {
        transform_in_place(&mut self.decryptor, &mut self.decrypt_scratch, bytes)
    }

    fn encrypt<'a>(&'a mut self, bytes: &[u8]) -> Result<&'a [u8], ProtocolError> {
        transform_to_scratch(&mut self.encryptor, &mut self.encrypt_scratch, bytes)
    }
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

struct StatusService {
    config: MinecraftConfig,
    status_frame: Arc<[u8]>,
    blacklist_frame: Arc<[u8]>,
    whitelist_frame: Arc<[u8]>,
    whitelist_enabled: bool,
    whitelist_players: Arc<[String]>,
    blacklist_players: Arc<[String]>,
    compression_pool: BoundedBlockingPool,
    online_mode: Option<OnlineModeService>,
    next_entity_id: AtomicI32,
    next_hologram_entity_id: AtomicI32,
    next_window_id: AtomicI32,
    next_connection_id: AtomicU64,
    online_sessions: Arc<Mutex<HashMap<String, u64>>>,
    world: Arc<WorldTemplate>,
    connection_timeout: Duration,
    auth: Option<Arc<AuthService>>,
    auth_limiter: Arc<MinecraftAuthLimiter>,
}

impl StatusService {
    fn new(config: &MinecraftConfig) -> io::Result<Self> {
        let status_frame = build_status_frame(config, 0)?;
        let blacklist_frame =
            login_disconnect_frame(r#"{"text":"You are banned from this server.","color":"red"}"#)?;
        let whitelist_frame =
            login_disconnect_frame(r#"{"text":"You are not whitelisted.","color":"red"}"#)?;
        let world = WorldTemplate::load_shared(&config.world_template)?;
        Ok(Self {
            config: config.clone(),
            status_frame: status_frame.into(),
            blacklist_frame: blacklist_frame.into(),
            whitelist_frame: whitelist_frame.into(),
            whitelist_enabled: config.whitelist_enabled,
            whitelist_players: config.whitelist_players.clone().into(),
            blacklist_players: config.blacklist_players.clone().into(),
            compression_pool: BoundedBlockingPool::new(
                "lmyzmail-minecraft-zlib",
                COMPRESSION_WORKERS,
                COMPRESSION_QUEUE,
            )?,
            online_mode: config
                .online_mode
                .then(|| OnlineModeService::new(config))
                .transpose()?,
            next_entity_id: AtomicI32::new(1),
            next_hologram_entity_id: AtomicI32::new(900_000),
            next_window_id: AtomicI32::new(1),
            next_connection_id: AtomicU64::new(1),
            online_sessions: Arc::new(Mutex::new(HashMap::with_capacity(MAX_CONNECTIONS))),
            world,
            connection_timeout: Duration::from_secs(config.read_timeout_seconds),
            auth: None,
            auth_limiter: Arc::new(MinecraftAuthLimiter::new(config)),
        })
    }

    fn with_auth(config: &MinecraftConfig, auth: Arc<AuthService>) -> io::Result<Self> {
        let mut service = Self::new(config)?;
        service.auth = Some(auth);
        Ok(service)
    }

    fn rejection_frame(&self, username: &str) -> Option<&[u8]> {
        if contains_player(&self.blacklist_players, username) {
            Some(&self.blacklist_frame)
        } else if self.whitelist_enabled && !contains_player(&self.whitelist_players, username) {
            Some(&self.whitelist_frame)
        } else {
            None
        }
    }

    fn current_status_frame(&self) -> io::Result<Vec<u8>> {
        let online = self
            .online_sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len() as u32;
        if online == 0 {
            Ok(self.status_frame.to_vec())
        } else {
            build_status_frame(&self.config, online)
        }
    }

    fn next_entity_id(&self) -> i32 {
        self.next_entity_id.fetch_add(1, Ordering::Relaxed)
    }

    fn reserve_hologram_entity_ids(&self, count: i32) -> i32 {
        self.next_hologram_entity_id
            .fetch_add(count, Ordering::Relaxed)
    }

    fn next_window_id(&self) -> u8 {
        self.next_window_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some((current % 100) + 1)
            })
            .unwrap_or_else(|current| current) as u8
    }

    fn register_online(&self, uuid: String) -> OnlineCountGuard {
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        self.online_sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(uuid.clone(), connection_id);
        OnlineCountGuard {
            sessions: Arc::clone(&self.online_sessions),
            uuid,
            connection_id,
        }
    }
}

struct OnlineCountGuard {
    sessions: Arc<Mutex<HashMap<String, u64>>>,
    uuid: String,
    connection_id: u64,
}

impl Drop for OnlineCountGuard {
    fn drop(&mut self) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if sessions.get(&self.uuid) == Some(&self.connection_id) {
            sessions.remove(&self.uuid);
        }
    }
}

pub async fn serve_minecraft(
    config: Arc<RuntimeConfig>,
    database_pool: deadpool_postgres::Pool,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let listener =
        TcpListener::bind((config.listen.host.as_str(), config.listen.minecraft)).await?;
    let auth = AuthService::from_config(&config, database_pool).map_err(io::Error::other)?;
    let service = Arc::new(StatusService::with_auth(&config.minecraft, Arc::new(auth))?);
    serve_listener(listener, service, cancellation, MAX_CONNECTIONS).await
}

async fn serve_listener(
    listener: TcpListener,
    service: Arc<StatusService>,
    cancellation: CancellationToken,
    max_connections: usize,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(max_connections.clamp(1, MAX_CONNECTIONS)));
    let mut tasks = JoinSet::new();
    let mut retry_delay = ACCEPT_RETRY_MIN;
    let mut terminal_error = None;

    loop {
        while let Some(result) = tasks.try_join_next() {
            match result {
                Ok(Err(error)) => eprintln!("lmyzmail Minecraft connection failed: {error}"),
                Err(error) => eprintln!("lmyzmail Minecraft connection task failed: {error}"),
                Ok(Ok(())) => {}
            }
        }
        let accepted = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, _) = match accepted {
            Ok(value) => {
                retry_delay = ACCEPT_RETRY_MIN;
                value
            }
            Err(error) if retryable_accept_error(&error) => {
                eprintln!(
                    "lmyzmail Minecraft accept failed; retrying in {} ms: {error}",
                    retry_delay.as_millis()
                );
                let delay = retry_delay;
                retry_delay = retry_delay.saturating_mul(2).min(ACCEPT_RETRY_MAX);
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    _ = tokio::time::sleep(delay) => continue,
                }
            }
            Err(error) => {
                terminal_error = Some(error);
                cancellation.cancel();
                break;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let deadline = Instant::now() + service.connection_timeout;
        let service = Arc::clone(&service);
        let child = cancellation.child_token();
        tasks.spawn(
            async move { handle_connection(stream, service, child, permit, deadline).await },
        );
    }

    if timeout(SHUTDOWN_DEADLINE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    terminal_error.map_or(Ok(()), Err)
}

async fn handle_connection(
    stream: TcpStream,
    service: Arc<StatusService>,
    cancellation: CancellationToken,
    _permit: OwnedSemaphorePermit,
    deadline: Instant,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let client_ip = stream
        .peer_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_owned());
    let (mut reader, mut writer) = stream.into_split();
    let mut state = ConnectionState::Handshake;
    let mut compression = None;
    let mut cipher = None;
    let mut pending_online = None;
    let mut _online_guard = None;
    let mut player_position = (
        service.config.spawn.x,
        service.config.spawn.y,
        service.config.spawn.z,
    );
    let mut hologram_entity_base = 0;
    let mut next_position_check = None;
    let mut next_hologram_teleport = None;
    let mut next_time_update = None;
    let mut pending_email = None;
    let mut authenticated = None;
    let mut player_username = String::new();
    let mut draft = MinecraftDraft::default();
    let mut open_menu_window_id = None;
    let mut logout_confirm_window_id = None;
    let mut render_settings = RenderSettings::default();
    let mut render_settings_pending = false;

    loop {
        let raw_frame_result = if state == ConnectionState::Play {
            let position_at = next_position_check.expect("PLAY position timer was not armed");
            let hologram_at = next_hologram_teleport.expect("PLAY hologram timer was not armed");
            let time_update_at = next_time_update.expect("PLAY time timer was not armed");
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                _ = sleep_until(position_at) => {
                    next_position_check = Some(position_at + POSITION_CHECK_INTERVAL);
                    let spawn = &service.config.spawn;
                    let dx = player_position.0 - spawn.x;
                    let dy = player_position.1 - spawn.y;
                    let dz = player_position.2 - spawn.z;
                    if dx * dx + dy * dy + dz * dz > MAX_SPAWN_DISTANCE * MAX_SPAWN_DISTANCE {
                        for packet in teleport_back_packets(&service.config)? {
                            if let Err(error) = write_packet(
                                &mut writer,
                                &service,
                                packet,
                                compression,
                                cipher.as_mut(),
                                deadline,
                                &cancellation,
                            )
                            .await
                            {
                                return finish_write_error(error);
                            }
                        }
                        player_position = (spawn.x, spawn.y, spawn.z);
                    }
                    continue;
                }
                _ = sleep_until(hologram_at) => {
                    next_hologram_teleport = Some(hologram_at + HOLOGRAM_TELEPORT_INTERVAL);
                    for packet in hologram_teleport_packets(hologram_entity_base) {
                        if let Err(error) = write_packet(
                            &mut writer,
                            &service,
                            packet,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    }
                    continue;
                }
                _ = sleep_until(time_update_at) => {
                    next_time_update = Some(time_update_at + TIME_UPDATE_INTERVAL);
                    if let Err(error) = write_packet(
                        &mut writer,
                        &service,
                        time_update_packet(),
                        compression,
                        cipher.as_mut(),
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        return finish_write_error(error);
                    }
                    continue;
                }
                result = read_frame(&mut reader, cipher.as_mut(), deadline, &cancellation) => result,
            }
        } else {
            read_frame(&mut reader, cipher.as_mut(), deadline, &cancellation).await
        };
        let raw_frame = match raw_frame_result {
            Ok(Some(frame)) => frame,
            Ok(None)
            | Err(ProtocolError::Cancelled | ProtocolError::TimedOut | ProtocolError::Malformed) => {
                return Ok(());
            }
            Err(ProtocolError::Io(error)) if connection_ended(&error) => return Ok(()),
            Err(ProtocolError::Io(error)) => return Err(error),
        };
        let frame = match compression {
            Some(threshold) => match decode_compression_envelope(
                &service,
                raw_frame,
                threshold,
                deadline,
                &cancellation,
            )
            .await
            {
                Ok(frame) => frame,
                Err(
                    ProtocolError::Cancelled | ProtocolError::TimedOut | ProtocolError::Malformed,
                ) => {
                    return Ok(());
                }
                Err(ProtocolError::Io(error)) if connection_ended(&error) => return Ok(()),
                Err(ProtocolError::Io(error)) => return Err(error),
            },
            None => raw_frame,
        };

        let mut packet = PacketReader::new(&frame);
        let packet_id = match packet.read_varint() {
            Ok(value) => value,
            Err(()) => return Ok(()),
        };
        match state {
            ConnectionState::Handshake => {
                if packet_id != 0 {
                    continue;
                }
                if parse_handshake(&mut packet).is_err() {
                    return Ok(());
                }
                match packet.read_varint() {
                    Ok(1) => state = ConnectionState::Status,
                    Ok(2) => state = ConnectionState::Login,
                    Ok(_) | Err(_) => return Ok(()),
                }
            }
            ConnectionState::Status => match packet_id {
                0 => {
                    let frame = service.current_status_frame()?;
                    if let Err(error) =
                        write_bytes(&mut writer, &frame, None, deadline, &cancellation).await
                    {
                        return finish_write_error(error);
                    }
                }
                1 => {
                    let Ok(payload) = packet.read_i64() else {
                        return Ok(());
                    };
                    let mut packet = [0_u8; 9];
                    packet[0] = 1;
                    packet[1..].copy_from_slice(&payload.to_be_bytes());
                    let pong = encode_frame(&packet)?;
                    if let Err(error) =
                        write_bytes(&mut writer, &pong, None, deadline, &cancellation).await
                    {
                        return finish_write_error(error);
                    }
                    let _ = tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => Ok(()),
                        result = timeout_at(deadline, writer.shutdown()) => result
                            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Minecraft shutdown timed out"))?,
                    };
                    return Ok(());
                }
                _ => {}
            },
            ConnectionState::Login => match packet_id {
                0 => {
                    let Ok(username) = packet.read_string(16) else {
                        return Ok(());
                    };
                    if let Some(frame) = service.rejection_frame(&username) {
                        if let Err(error) =
                            write_bytes(&mut writer, frame, None, deadline, &cancellation).await
                        {
                            return finish_write_error(error);
                        }
                        shutdown_stream(&mut writer, deadline, &cancellation).await?;
                        return Ok(());
                    }
                    if service.config.online_mode {
                        let Some(online) = service.online_mode.as_ref() else {
                            return Ok(());
                        };
                        let mut verify_token = [0_u8; VERIFY_TOKEN_BYTES];
                        fill_random(&mut verify_token).map_err(io::Error::other)?;
                        let frame =
                            encryption_request_frame(&online.public_key_der, &verify_token)?;
                        if let Err(error) =
                            write_bytes(&mut writer, &frame, None, deadline, &cancellation).await
                        {
                            return finish_write_error(error);
                        }
                        pending_online = Some(PendingOnlineLogin {
                            username,
                            verify_token,
                        });
                        continue;
                    }
                    match complete_login(
                        &mut writer,
                        &service,
                        offline_uuid(&username)?,
                        &username,
                        None,
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        Ok((active_compression, online_guard, entity_base)) => {
                            compression = active_compression;
                            _online_guard = Some(online_guard);
                            hologram_entity_base = entity_base;
                            player_username = username;
                            let now = Instant::now();
                            next_position_check = Some(now + POSITION_CHECK_INTERVAL);
                            next_hologram_teleport = Some(now + HOLOGRAM_TELEPORT_INTERVAL);
                            next_time_update = Some(now + TIME_UPDATE_INTERVAL);
                            state = ConnectionState::Play;
                        }
                        Err(
                            ProtocolError::Cancelled
                            | ProtocolError::TimedOut
                            | ProtocolError::Malformed,
                        ) => return Ok(()),
                        Err(ProtocolError::Io(error)) if connection_ended(&error) => {
                            return Ok(());
                        }
                        Err(ProtocolError::Io(error)) => return Err(error),
                    }
                }
                1 => {
                    let Some(pending) = pending_online.take() else {
                        continue;
                    };
                    let Ok(encrypted_secret) = packet.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES)
                    else {
                        return Ok(());
                    };
                    let Ok(encrypted_token) = packet.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES)
                    else {
                        return Ok(());
                    };
                    let Some(online) = service.online_mode.as_ref() else {
                        return Ok(());
                    };
                    let mut secret = match decrypt_online_response(
                        online,
                        encrypted_secret,
                        encrypted_token,
                        pending.verify_token,
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        Ok(secret) => secret,
                        Err(
                            ProtocolError::Cancelled
                            | ProtocolError::TimedOut
                            | ProtocolError::Malformed,
                        ) => return Ok(()),
                        Err(ProtocolError::Io(error)) => return Err(error),
                    };
                    let mut active_cipher = match MinecraftCipher::new(&secret) {
                        Ok(cipher) => cipher,
                        Err(_) => {
                            secret.zeroize();
                            return Ok(());
                        }
                    };
                    let auth = authenticate_online(
                        online,
                        &pending.username,
                        &secret,
                        deadline,
                        &cancellation,
                    )
                    .await;
                    secret.zeroize();
                    let profile = match auth {
                        Ok(profile) => profile,
                        Err(error) => {
                            let packet = authentication_failure_packet(error.message())?;
                            let frame = encode_frame(&packet)?;
                            let _ = write_bytes(
                                &mut writer,
                                &frame,
                                Some(&mut active_cipher),
                                deadline,
                                &cancellation,
                            )
                            .await;
                            let _ = shutdown_stream(&mut writer, deadline, &cancellation).await;
                            return Ok(());
                        }
                    };
                    match complete_login(
                        &mut writer,
                        &service,
                        profile.uuid,
                        &profile.name,
                        Some(&mut active_cipher),
                        deadline,
                        &cancellation,
                    )
                    .await
                    {
                        Ok((active_compression, online_guard, entity_base)) => {
                            compression = active_compression;
                            cipher = Some(active_cipher);
                            _online_guard = Some(online_guard);
                            hologram_entity_base = entity_base;
                            player_username = profile.name;
                            let now = Instant::now();
                            next_position_check = Some(now + POSITION_CHECK_INTERVAL);
                            next_hologram_teleport = Some(now + HOLOGRAM_TELEPORT_INTERVAL);
                            next_time_update = Some(now + TIME_UPDATE_INTERVAL);
                            state = ConnectionState::Play;
                        }
                        Err(
                            ProtocolError::Cancelled
                            | ProtocolError::TimedOut
                            | ProtocolError::Malformed,
                        ) => return Ok(()),
                        Err(ProtocolError::Io(error)) if connection_ended(&error) => {
                            return Ok(());
                        }
                        Err(ProtocolError::Io(error)) => return Err(error),
                    }
                }
                _ => {}
            },
            ConnectionState::Play => match packet_id {
                0x01 => {
                    let Ok(mut message) = packet.read_string(100) else {
                        return Ok(());
                    };
                    if pending_email.is_none() && authenticated.is_none() {
                        let (email, responses) = awaiting_email_responses(&message)?;
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                        pending_email = email;
                    } else if let Some(email) = pending_email.clone() {
                        if let Some(remaining) = service.auth_limiter.locked_remaining(&client_ip) {
                            let responses = vec![chat_packet(
                                &format!(
                                    "\u{00a7}cToo many failed attempts. Try again in {remaining} seconds."
                                ),
                                Some("red"),
                            )?];
                            if let Err(error) = write_packet_list(
                                &mut writer,
                                &service,
                                responses,
                                compression,
                                cipher.as_mut(),
                                deadline,
                                &cancellation,
                            )
                            .await
                            {
                                return finish_write_error(error);
                            }
                            message.zeroize();
                            continue;
                        }
                        let Some(auth) = service.auth.as_ref().cloned() else {
                            return Ok(());
                        };
                        let auth_cancellation = cancellation.child_token();
                        let result = {
                            let auth_future = auth.login_with_cancellation(
                                &email,
                                &message,
                                &client_ip,
                                Some("Minecraft"),
                                &auth_cancellation,
                            );
                            tokio::pin!(auth_future);
                            tokio::select! {
                                biased;
                                _ = cancellation.cancelled() => {
                                    auth_cancellation.cancel();
                                    let _ = auth_future.await;
                                    None
                                }
                                result = timeout_at(deadline, &mut auth_future) => match result {
                                    Ok(result) => Some(result),
                                    Err(_) => {
                                        auth_cancellation.cancel();
                                        let _ = auth_future.await;
                                        None
                                    }
                                },
                            }
                        };
                        message.zeroize();
                        let Some(result) = result else {
                            return Ok(());
                        };
                        auth_cancellation.cancel();
                        let mut close_after_write = false;
                        let responses = match result {
                            Ok((LoginOutcome::Invalid { .. }, _)) => {
                                let (locked, remaining) =
                                    service.auth_limiter.record_failure(&client_ip);
                                if locked {
                                    close_after_write = true;
                                    vec![
                                        chat_packet(
                                            "\u{00a7}c\u{00a7}lToo many failed attempts!",
                                            Some("red"),
                                        )?,
                                        chat_packet(
                                            &format!(
                                                "\u{00a7}cLocked out for {} seconds.",
                                                service.config.auth_lockout_seconds
                                            ),
                                            Some("red"),
                                        )?,
                                        disconnect_play_packet(
                                            "Too many failed authentication attempts",
                                        )?,
                                    ]
                                } else {
                                    vec![
                                        chat_packet(
                                            &format!(
                                                "\u{00a7}cAuthentication failed. {remaining} attempt(s) remaining."
                                            ),
                                            Some("red"),
                                        )?,
                                        chat_packet(
                                            "\u{00a7}aPlease enter your password:",
                                            Some("green"),
                                        )?,
                                    ]
                                }
                            }
                            Ok((LoginOutcome::Success, Some(login))) => {
                                service.auth_limiter.clear(&client_ip);
                                pending_email = None;
                                authenticated = Some((email.clone(), Zeroizing::new(login.token)));
                                authenticated_packets(&player_username, &email, render_settings)?
                            }
                            Ok((LoginOutcome::Success, None))
                            | Err(AuthError::Cancelled)
                            | Err(AuthError::Database(_))
                            | Err(AuthError::OutcomeUnknown)
                            | Err(AuthError::Unavailable)
                            | Err(AuthError::InvalidInput(_)) => vec![
                                chat_packet(
                                    "\u{00a7}cAuthentication service unavailable.",
                                    Some("red"),
                                )?,
                                chat_packet("\u{00a7}aPlease enter your password:", Some("green"))?,
                            ],
                        };
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                        if close_after_write {
                            shutdown_stream(&mut writer, deadline, &cancellation).await?;
                            return Ok(());
                        }
                    } else if authenticated.is_some() {
                        let command = java_trim(&message);
                        let command_end = command.find(java_regex_space).unwrap_or(command.len());
                        let menu_window_id = command[..command_end]
                            .eq_ignore_ascii_case("/menu")
                            .then(|| service.next_window_id());
                        let mut responses = Vec::new();
                        let replaced_gui = open_menu_window_id.take().is_some()
                            | logout_confirm_window_id.take().is_some();
                        if menu_window_id.is_some() && replaced_gui {
                            responses.extend(restore_hotbar_packets()?);
                        }
                        responses.extend(authenticated_command_packets(
                            &message,
                            &service.config,
                            &mut draft,
                            menu_window_id,
                            render_settings,
                        )?);
                        message.zeroize();
                        if let Some(window_id) = menu_window_id {
                            open_menu_window_id = Some(window_id);
                            logout_confirm_window_id = None;
                        }
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    }
                }
                0x0d => {
                    if packet.read_u8().is_err() {
                        return Ok(());
                    }
                    let closed_gui = open_menu_window_id.take().is_some()
                        | logout_confirm_window_id.take().is_some();
                    if closed_gui
                        && let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            restore_hotbar_packets()?,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                    {
                        return finish_write_error(error);
                    }
                }
                0x0e => {
                    let Ok(click) = read_window_click(&mut packet) else {
                        return Ok(());
                    };
                    if open_menu_window_id == Some(click.window_id) {
                        let logout_window_id =
                            (click.mode == 0 && click.slot == 34).then(|| service.next_window_id());
                        let (responses, effect) =
                            main_menu_click_packets(click, logout_window_id, render_settings)?;
                        match effect {
                            MainMenuEffect::None => {}
                            MainMenuEffect::Close => {
                                open_menu_window_id = None;
                                logout_confirm_window_id = None;
                            }
                            MainMenuEffect::SwitchAccount => {
                                open_menu_window_id = None;
                                logout_confirm_window_id = None;
                                pending_email = None;
                                authenticated = None;
                            }
                            MainMenuEffect::OpenRenderSettings => {
                                open_menu_window_id = None;
                                logout_confirm_window_id = None;
                                render_settings_pending = true;
                            }
                            MainMenuEffect::OpenLogoutConfirm(window_id) => {
                                open_menu_window_id = None;
                                logout_confirm_window_id = Some(window_id);
                            }
                        }
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    } else if logout_confirm_window_id == Some(click.window_id) {
                        let main_window_id =
                            (click.mode == 0 && click.slot == 15).then(|| service.next_window_id());
                        let (responses, effect) = logout_confirmation_click_packets(
                            click,
                            main_window_id,
                            render_settings,
                        )?;
                        match effect {
                            LogoutConfirmEffect::None => {}
                            LogoutConfirmEffect::OpenMainMenu(window_id) => {
                                logout_confirm_window_id = None;
                                open_menu_window_id = Some(window_id);
                            }
                            LogoutConfirmEffect::Disconnect => {
                                logout_confirm_window_id = None;
                                open_menu_window_id = None;
                                pending_email = None;
                                authenticated = None;
                            }
                        }
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                        if effect == LogoutConfirmEffect::Disconnect {
                            shutdown_stream(&mut writer, deadline, &cancellation).await?;
                            return Ok(());
                        }
                    }
                }
                0x12 => {
                    let Ok(update) = read_update_sign(&mut packet) else {
                        return Ok(());
                    };
                    if render_settings_pending && let Some((email, _)) = authenticated.as_ref() {
                        render_settings_pending = false;
                        let responses = render_settings_update_packets(
                            update,
                            &mut render_settings,
                            &player_username,
                            email,
                            &draft,
                        )?;
                        if let Err(error) = write_packet_list(
                            &mut writer,
                            &service,
                            responses,
                            compression,
                            cipher.as_mut(),
                            deadline,
                            &cancellation,
                        )
                        .await
                        {
                            return finish_write_error(error);
                        }
                    }
                }
                0x04 | 0x06 => match read_player_position(&mut packet, packet_id) {
                    Ok(position) => player_position = position,
                    Err(()) => return Ok(()),
                },
                _ => {}
            },
        }
    }
}

async fn shutdown_stream<W: AsyncWrite + Unpin>(
    stream: &mut W,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Ok(()),
        result = timeout_at(deadline, stream.shutdown()) => result
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Minecraft shutdown timed out"))?,
    }
}

fn finish_write_error(error: ProtocolError) -> io::Result<()> {
    match error {
        ProtocolError::Cancelled | ProtocolError::TimedOut | ProtocolError::Malformed => Ok(()),
        ProtocolError::Io(error) if connection_ended(&error) => Ok(()),
        ProtocolError::Io(error) => Err(error),
    }
}

fn parse_handshake(packet: &mut PacketReader<'_>) -> Result<(), ()> {
    packet.read_varint()?;
    packet.read_string(255)?;
    packet.read_u16()?;
    Ok(())
}

fn read_player_position(
    packet: &mut PacketReader<'_>,
    packet_id: i32,
) -> Result<(f64, f64, f64), ()> {
    let position = (packet.read_f64()?, packet.read_f64()?, packet.read_f64()?);
    if packet_id == 0x06 {
        packet.read_f32()?;
        packet.read_f32()?;
    }
    packet.read_u8()?;
    Ok(position)
}

fn read_window_click(packet: &mut PacketReader<'_>) -> Result<WindowClick, ()> {
    let window_id = packet.read_u8()?;
    let slot = packet.read_i16()?;
    let _button = packet.read_u8()?;
    let action_number = packet.read_i16()?;
    let mode = packet.read_u8()?;
    packet.skip_slot()?;
    Ok(WindowClick {
        window_id,
        slot,
        action_number,
        mode,
    })
}

fn read_update_sign(packet: &mut PacketReader<'_>) -> Result<UpdateSign, ()> {
    packet.read_i64()?;
    Ok(UpdateSign {
        lines: [
            packet.read_string(UPDATE_SIGN_LINE_MAX_UTF16_UNITS)?,
            packet.read_string(UPDATE_SIGN_LINE_MAX_UTF16_UNITS)?,
            packet.read_string(UPDATE_SIGN_LINE_MAX_UTF16_UNITS)?,
            packet.read_string(UPDATE_SIGN_LINE_MAX_UTF16_UNITS)?,
        ],
    })
}

fn encryption_request_frame(
    public_key_der: &[u8],
    verify_token: &[u8; VERIFY_TOKEN_BYTES],
) -> io::Result<Vec<u8>> {
    let mut packet = Vec::new();
    packet
        .try_reserve_exact(public_key_der.len() + verify_token.len() + 12)
        .map_err(|error| io::Error::other(format!("Minecraft frame allocation failed: {error}")))?;
    packet.push(0x01);
    write_string(&mut packet, "")?;
    write_byte_array(&mut packet, public_key_der)?;
    write_byte_array(&mut packet, verify_token)?;
    encode_frame(&packet)
}

async fn decrypt_online_response(
    online: &OnlineModeService,
    encrypted_secret: Vec<u8>,
    encrypted_token: Vec<u8>,
    expected_token: [u8; VERIFY_TOKEN_BYTES],
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<[u8; SHARED_SECRET_BYTES], ProtocolError> {
    let private_key = Arc::clone(&online.private_key);
    let worker_cancellation = cancellation.clone();
    let receiver = online
        .crypto_pool
        .submit(move || {
            compression_budget(&worker_cancellation, deadline)?;
            let mut token = rsa_private_decrypt(&private_key, &encrypted_token)?;
            let token_matches: bool = expected_token.as_slice().ct_eq(&token).into();
            token.zeroize();
            if !token_matches {
                return Err(ProtocolError::Malformed);
            }
            compression_budget(&worker_cancellation, deadline)?;
            let mut secret = rsa_private_decrypt(&private_key, &encrypted_secret)?;
            if secret.len() != SHARED_SECRET_BYTES {
                secret.zeroize();
                return Err(ProtocolError::Malformed);
            }
            let mut result = [0_u8; SHARED_SECRET_BYTES];
            result.copy_from_slice(&secret);
            secret.zeroize();
            compression_budget(&worker_cancellation, deadline)?;
            Ok(result)
        })
        .map_err(submit_error)?;
    await_compression(receiver, deadline, cancellation).await?
}

fn rsa_private_decrypt(
    private_key: &Rsa<Private>,
    encrypted: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if encrypted.len() != private_key.size() as usize {
        return Err(ProtocolError::Malformed);
    }
    let mut output = vec![0_u8; private_key.size() as usize];
    let written = private_key
        .private_decrypt(encrypted, &mut output, Padding::PKCS1)
        .map_err(crypto_protocol)?;
    output.truncate(written);
    Ok(output)
}

#[derive(Debug)]
struct JoinedProfile {
    uuid: String,
    name: String,
}

#[derive(Debug)]
struct AuthenticationFailure {
    message: String,
}

impl AuthenticationFailure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn message(&self) -> &str {
        &self.message
    }
}

#[derive(serde::Deserialize)]
struct JoinedResponse {
    id: String,
    name: String,
}

async fn authenticate_online(
    online: &OnlineModeService,
    username: &str,
    shared_secret: &[u8; SHARED_SECRET_BYTES],
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<JoinedProfile, AuthenticationFailure> {
    let operation_deadline = deadline.min(Instant::now() + AUTH_REQUEST_TIMEOUT);
    let server_hash = minecraft_server_hash("", shared_secret, &online.public_key_der);
    let mut url = online.session_server_url.clone();
    url.query_pairs_mut()
        .clear()
        .append_pair("username", username)
        .append_pair("serverId", &server_hash);
    let response = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            return Err(AuthenticationFailure::new("Interrupted"));
        }
        response = timeout_at(operation_deadline, online.session_client.get(url).send()) => {
            response
                .map_err(|_| AuthenticationFailure::new("Auth server error: request timed out"))?
                .map_err(|_| AuthenticationFailure::new("Auth server error: request failed"))?
        }
    };
    let status = response.status();
    if status == StatusCode::NO_CONTENT {
        return Err(AuthenticationFailure::new("Session not found"));
    }
    if status != StatusCode::OK {
        return Err(AuthenticationFailure::new(format!(
            "HTTP {}",
            status.as_u16()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_AUTH_RESPONSE_BYTES as u64)
    {
        return Err(AuthenticationFailure::new(
            "Auth server error: response exceeded byte limit",
        ));
    }
    let mut response = response;
    let mut body = Vec::new();
    loop {
        let chunk = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(AuthenticationFailure::new("Interrupted"));
            }
            chunk = timeout_at(operation_deadline, response.chunk()) => {
                chunk
                    .map_err(|_| AuthenticationFailure::new("Auth server error: response timed out"))?
                    .map_err(|_| AuthenticationFailure::new("Auth server error: response failed"))?
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > MAX_AUTH_RESPONSE_BYTES {
            return Err(AuthenticationFailure::new(
                "Auth server error: response exceeded byte limit",
            ));
        }
        body.try_reserve_exact(chunk.len()).map_err(|_| {
            AuthenticationFailure::new("Auth server error: response allocation failed")
        })?;
        body.extend_from_slice(&chunk);
    }
    let profile: JoinedResponse = serde_json::from_slice(&body)
        .map_err(|_| AuthenticationFailure::new("Auth server error: invalid response"))?;
    let uuid = normalize_joined_uuid(&profile.id)
        .ok_or_else(|| AuthenticationFailure::new("Auth server error: invalid response"))?;
    if !valid_online_name(&profile.name) || !java_equals_ignore_case(&profile.name, username) {
        return Err(AuthenticationFailure::new(
            "Auth server error: invalid response",
        ));
    }
    Ok(JoinedProfile {
        uuid,
        name: profile.name,
    })
}

fn minecraft_server_hash(
    server_id: &str,
    shared_secret: &[u8; SHARED_SECRET_BYTES],
    public_key_der: &[u8],
) -> String {
    let mut digest = Sha1::new();
    digest.update(server_id.as_bytes());
    digest.update(shared_secret);
    digest.update(public_key_der);
    signed_hex(digest.finalize().as_slice())
}

fn signed_hex(bytes: &[u8]) -> String {
    let negative = bytes.first().is_some_and(|byte| byte & 0x80 != 0);
    let mut magnitude = bytes.to_vec();
    if negative {
        for byte in &mut magnitude {
            *byte = !*byte;
        }
        for byte in magnitude.iter_mut().rev() {
            let (value, carry) = byte.overflowing_add(1);
            *byte = value;
            if !carry {
                break;
            }
        }
    }
    let first = magnitude
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(magnitude.len());
    if first == magnitude.len() {
        return "0".to_owned();
    }
    let mut output = String::with_capacity((magnitude.len() - first) * 2 + usize::from(negative));
    if negative {
        output.push('-');
    }
    use std::fmt::Write as _;
    write!(output, "{:x}", magnitude[first]).expect("writing to String cannot fail");
    for byte in &magnitude[first + 1..] {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn normalize_joined_uuid(value: &str) -> Option<String> {
    let valid_shape = value.len() == 32
        || (value.len() == 36
            && value.as_bytes()[8] == b'-'
            && value.as_bytes()[13] == b'-'
            && value.as_bytes()[18] == b'-'
            && value.as_bytes()[23] == b'-');
    if !valid_shape {
        return None;
    }
    let compact: String = value
        .chars()
        .filter(|character| *character != '-')
        .collect();
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &compact[0..8].to_ascii_lowercase(),
        &compact[8..12].to_ascii_lowercase(),
        &compact[12..16].to_ascii_lowercase(),
        &compact[16..20].to_ascii_lowercase(),
        &compact[20..32].to_ascii_lowercase()
    ))
}

fn valid_online_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn authentication_failure_packet(message: &str) -> io::Result<Vec<u8>> {
    let text = format!("Authentication failed: {message}");
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    login_disconnect_packet(&format!(r#"{{"text":"{escaped}","color":"red"}}"#))
}

async fn complete_login<W: AsyncWrite + Unpin>(
    stream: &mut W,
    service: &StatusService,
    uuid: String,
    username: &str,
    mut cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(Option<i32>, OnlineCountGuard, i32), ProtocolError> {
    let compression = if service.config.compression_threshold >= 0 {
        let threshold = service.config.compression_threshold;
        let mut packet = vec![0x03];
        write_varint(&mut packet, threshold as u32);
        let frame = encode_frame(&packet)?;
        write_bytes(
            stream,
            &frame,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
        Some(threshold)
    } else {
        None
    };

    let mut login_success = vec![0x02];
    write_string(&mut login_success, &uuid)?;
    write_string(&mut login_success, username)?;
    write_packet(
        stream,
        service,
        login_success,
        compression,
        cipher.as_deref_mut(),
        deadline,
        cancellation,
    )
    .await?;

    let player_list_uuid = uuid.clone();
    let static_play_packets =
        static_play_packets(&player_list_uuid, username).map_err(ProtocolError::Io)?;
    let online_guard = service.register_online(uuid);
    let entity_id = service.next_entity_id();
    for packet in initial_play_packets(entity_id, &service.config)? {
        write_packet(
            stream,
            service,
            packet,
            compression,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
    }
    send_world_bootstrap(
        stream,
        service,
        compression,
        cipher.as_deref_mut(),
        deadline,
        cancellation,
    )
    .await?;
    for packet in static_play_packets {
        write_packet(
            stream,
            service,
            packet,
            compression,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
    }
    let hologram_entity_base = service.reserve_hologram_entity_ids(7);
    for packet in post_static_play_packets(hologram_entity_base).map_err(ProtocolError::Io)? {
        write_packet(
            stream,
            service,
            packet,
            compression,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
    }
    Ok((compression, online_guard, hologram_entity_base))
}

async fn send_world_bootstrap<W: AsyncWrite + Unpin>(
    stream: &mut W,
    service: &StatusService,
    compression: Option<i32>,
    mut cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), ProtocolError> {
    let spawn = &service.config.spawn;
    let chunk_centers = [
        ((spawn.x as i32) >> 4, (spawn.z as i32) >> 4),
        (
            service.config.video.center_x >> 4,
            service.config.video.wall_z >> 4,
        ),
    ];
    for chunk in service
        .world
        .chunks_near_centers(&chunk_centers, service.config.view_distance as i32)
    {
        let (mask, data) = minecraft_world::serialize_chunk(chunk, true, true);
        let mut packet = vec![0x21];
        packet.extend_from_slice(&chunk.chunk_x.to_be_bytes());
        packet.extend_from_slice(&chunk.chunk_z.to_be_bytes());
        packet.push(1);
        packet.extend_from_slice(&mask.to_be_bytes());
        write_byte_array(&mut packet, &data).map_err(ProtocolError::Io)?;
        write_packet(
            stream,
            service,
            packet,
            compression,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
    }
    for chunk in service.world.chunks() {
        for tile_entity in &chunk.tile_entities {
            let action = match tile_entity.id.as_str() {
                "Sign" => 9,
                "Banner" => 6,
                _ => continue,
            };
            let mut packet = vec![0x35];
            write_block_position(&mut packet, tile_entity.x, tile_entity.y, tile_entity.z);
            packet.push(action);
            minecraft_world::write_nbt(Some(&tile_entity.nbt), &mut packet)
                .map_err(ProtocolError::Io)?;
            write_packet(
                stream,
                service,
                packet,
                compression,
                cipher.as_deref_mut(),
                deadline,
                cancellation,
            )
            .await?;
        }
    }
    let mut position = vec![0x08];
    position.extend_from_slice(&spawn.x.to_be_bytes());
    position.extend_from_slice(&spawn.y.to_be_bytes());
    position.extend_from_slice(&spawn.z.to_be_bytes());
    position.extend_from_slice(&spawn.yaw.to_be_bytes());
    position.extend_from_slice(&spawn.pitch.to_be_bytes());
    position.push(0);
    write_packet(
        stream,
        service,
        position,
        compression,
        cipher,
        deadline,
        cancellation,
    )
    .await?;
    Ok(())
}

fn write_block_position(output: &mut Vec<u8>, x: i32, y: i32, z: i32) {
    let packed = ((i64::from(x) & 0x3ff_ffff) << 38)
        | ((i64::from(y) & 0xfff) << 26)
        | (i64::from(z) & 0x3ff_ffff);
    output.extend_from_slice(&packed.to_be_bytes());
}

fn static_play_packets(uuid: &str, username: &str) -> io::Result<Vec<Vec<u8>>> {
    let uuid_bytes = parse_uuid_bytes(uuid)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid player UUID"))?;

    let mut packets = Vec::with_capacity(11);
    let mut player_list = vec![0x38];
    write_varint(&mut player_list, 0);
    write_varint(&mut player_list, 1);
    player_list.extend_from_slice(&uuid_bytes);
    write_string(&mut player_list, username)?;
    write_varint(&mut player_list, 0);
    write_varint(&mut player_list, 2);
    write_varint(&mut player_list, 0);
    player_list.push(0);
    packets.push(player_list);

    let mut header_footer = vec![0x47];
    write_string(
        &mut header_footer,
        &chat_json("\u{00a7}6\u{00a7}lLMYZMAIL", Some("gold")),
    )?;
    write_string(
        &mut header_footer,
        &chat_json(
            "\u{00a7}7Send emails in Minecraft! Skibidi dop dop yes yes!",
            Some("gray"),
        ),
    )?;
    packets.push(header_footer);

    let titles: [(u32, Option<String>, i32, i32, i32); 3] = [
        (2, None, 10, 60, 20),
        (0, Some(chat_json("\u{00a7}6LMYZMAIL", None)), 0, 0, 0),
        (
            1,
            Some(chat_json(
                "\u{00a7}7Type your email to get started",
                Some("gray"),
            )),
            0,
            0,
            0,
        ),
    ];
    for (action, text, fade_in, stay, fade_out) in titles {
        let mut title = vec![0x45];
        write_varint(&mut title, action);
        if let Some(text) = text {
            write_string(&mut title, &text)?;
        } else {
            title.extend_from_slice(&fade_in.to_be_bytes());
            title.extend_from_slice(&stay.to_be_bytes());
            title.extend_from_slice(&fade_out.to_be_bytes());
        }
        packets.push(title);
    }

    for (text, color) in [
        (
            "\u{00a7}e\u{00a7}l=== Welcome to LMYZMAIL Minecraft Server ===",
            Some("yellow"),
        ),
        (
            "\u{00a7}7Send emails directly from Minecraft!",
            Some("gray"),
        ),
        ("", None),
        ("\u{00a7}aPlease enter your email address:", Some("green")),
    ] {
        let mut chat = vec![0x02];
        write_string(&mut chat, &chat_json(text, color))?;
        chat.push(0);
        packets.push(chat);
    }

    for (slot, item_id, nbt) in [
        (36_i16, 386_i16, book_item_nbt()),
        (44_i16, 399_i16, menu_star_nbt()),
    ] {
        let mut item = vec![0x2f, 0];
        item.extend_from_slice(&slot.to_be_bytes());
        item.extend_from_slice(&item_id.to_be_bytes());
        item.push(1);
        item.extend_from_slice(&0_i16.to_be_bytes());
        minecraft_world::write_nbt(Some(&nbt), &mut item)?;
        packets.push(item);
    }
    debug_assert_eq!(packets.len(), 11);
    Ok(packets)
}

fn post_static_play_packets(hologram_entity_base: i32) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = empty_draft_sign_packets()?;
    packets.reserve(16);

    let mut objective = vec![0x3b];
    write_string(&mut objective, "lmyz")?;
    objective.push(0);
    write_string(&mut objective, "\u{00a7}6\u{00a7}lLMYZMAIL")?;
    write_string(&mut objective, "dummy")?;
    packets.push(objective);

    let mut display = vec![0x3d, 1];
    write_string(&mut display, "lmyz")?;
    packets.push(display);

    let lines = [
        "\u{00a7}6\u{00a7}lLMYZMAIL",
        "\u{00a7}7Minecraft Skibidi Email Server",
        "\u{00a7}7by \u{00a7}elmyzzz the great skibidi scientist",
        " ",
        "\u{00a7}eHold \u{00a7}fNether Star \u{00a7}e+ Right-click -> \u{00a7}fMenu",
        "\u{00a7}eWrite in \u{00a7}fBook & Quill \u{00a7}e-> Email body",
        "\u{00a7}eClick \u{00a7}fSign Buttons \u{00a7}e-> Set To/Subject",
    ];
    for (index, line) in lines.into_iter().enumerate() {
        let entity_id = hologram_entity_base + index as i32;
        let y = 163.0 - index as f64 * 0.55;
        let mut spawn = vec![0x0f];
        write_varint(&mut spawn, entity_id as u32);
        spawn.push(30);
        spawn.extend_from_slice(&16_i32.to_be_bytes());
        spawn.extend_from_slice(&((y * 32.0) as i32).to_be_bytes());
        spawn.extend_from_slice(&16_i32.to_be_bytes());
        spawn.extend_from_slice(&[0, 0, 0]);
        spawn.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        spawn.extend_from_slice(&[0x00, 0x20, 0x0a, 0x09, 0x7f]);
        packets.push(spawn);

        let mut metadata = vec![0x1c];
        write_varint(&mut metadata, entity_id as u32);
        metadata.push(0x82);
        write_string(&mut metadata, line)?;
        metadata.extend_from_slice(&[0x03, 1, 0x7f]);
        packets.push(metadata);
    }
    debug_assert_eq!(packets.len(), 20);
    Ok(packets)
}

fn time_update_packet() -> Vec<u8> {
    let mut packet = vec![0x03];
    packet.extend_from_slice(&0_i64.to_be_bytes());
    packet.extend_from_slice(&(-6000_i64).to_be_bytes());
    packet
}

fn teleport_back_packets(config: &MinecraftConfig) -> io::Result<Vec<Vec<u8>>> {
    let mut position = vec![0x08];
    position.extend_from_slice(&config.spawn.x.to_be_bytes());
    position.extend_from_slice(&config.spawn.y.to_be_bytes());
    position.extend_from_slice(&config.spawn.z.to_be_bytes());
    position.extend_from_slice(&config.spawn.yaw.to_be_bytes());
    position.extend_from_slice(&config.spawn.pitch.to_be_bytes());
    position.push(0);

    Ok(vec![
        position,
        chat_packet("\u{00a7}cYou were teleported back to spawn!", Some("red"))?,
    ])
}

fn hologram_teleport_packets(hologram_entity_base: i32) -> Vec<Vec<u8>> {
    let mut packets = Vec::with_capacity(7);
    for index in 0..7 {
        let entity_id = hologram_entity_base + index;
        let y = (163.0 - f64::from(index) * 0.55) * 32.0;
        let mut packet = vec![0x18];
        write_varint(&mut packet, entity_id as u32);
        packet.extend_from_slice(&16_i32.to_be_bytes());
        packet.extend_from_slice(&(y as i32).to_be_bytes());
        packet.extend_from_slice(&16_i32.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0]);
        packets.push(packet);
    }
    packets
}

fn awaiting_email_responses(message: &str) -> io::Result<(Option<String>, Vec<Vec<u8>>)> {
    let email = java_trim(message);
    if email.is_empty() || !email.contains('@') {
        return Ok((
            None,
            vec![chat_packet(
                "\u{00a7}cInvalid email format. Please try again:",
                Some("red"),
            )?],
        ));
    }
    Ok((
        Some(email.to_owned()),
        vec![
            chat_packet(&format!("\u{00a7}aEmail: \u{00a7}f{email}"), None)?,
            chat_packet("\u{00a7}aPlease enter your password:", Some("green"))?,
            chat_packet("\u{00a7}7(Your password will not be visible)", Some("gray"))?,
        ],
    ))
}

fn chat_packet(text: &str, color: Option<&str>) -> io::Result<Vec<u8>> {
    let mut packet = vec![0x02];
    write_string(&mut packet, &chat_json(text, color))?;
    packet.push(0);
    Ok(packet)
}

fn disconnect_play_packet(reason: &str) -> io::Result<Vec<u8>> {
    let mut packet = vec![0x40];
    write_string(&mut packet, &chat_json(reason, Some("red")))?;
    Ok(packet)
}

fn authenticated_packets(
    username: &str,
    email: &str,
    render_settings: RenderSettings,
) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = vec![
        chat_packet(
            "\u{00a7}a\u{00a7}lAuthentication successful!",
            Some("green"),
        )?,
        chat_packet(&format!("\u{00a7}aLogged in as: \u{00a7}f{email}"), None)?,
        chat_packet("", None)?,
    ];
    packets.extend(email_instruction_packets()?);
    packets.extend(empty_draft_sign_packets()?);
    packets.push(draft_book_packet()?);
    packets.extend(authenticated_scoreboard_packets(
        username,
        email,
        render_settings,
    )?);
    debug_assert_eq!(packets.len(), 29);
    Ok(packets)
}

fn email_instruction_packets() -> io::Result<Vec<Vec<u8>>> {
    [
        "\u{00a7}e\u{00a7}l=== How to Send Email ===",
        "\u{00a7}71. Click the buttons next to signs to edit:",
        "\u{00a7}7   \u{00a7}fTo\u{00a7}7, \u{00a7}fCC\u{00a7}7, \u{00a7}fBCC\u{00a7}7, \u{00a7}fSubject",
        "\u{00a7}72. Write your email body in the \u{00a7}fBook & Quill",
        "\u{00a7}73. Click the \u{00a7}cSend \u{00a7}7button when ready",
        "\u{00a7}74. Hold \u{00a7}f\u{2605} Nether Star \u{00a7}7+ right-click \u{2192} Mail menu",
        "\u{00a7}7   Or type \u{00a7}f/menu \u{00a7}7to open",
        "\u{00a7}e================================",
    ]
    .into_iter()
    .map(|text| chat_packet(text, None))
    .collect()
}

fn authenticated_command_packets(
    message: &str,
    config: &MinecraftConfig,
    draft: &mut MinecraftDraft,
    menu_window_id: Option<u8>,
    render_settings: RenderSettings,
) -> io::Result<Vec<Vec<u8>>> {
    let command = java_trim(message);
    if !command.starts_with('/') {
        return Ok(Vec::new());
    }
    let split = command.find(java_regex_space).unwrap_or(command.len());
    let name = command[..split].to_ascii_lowercase();
    let has_arguments = split < command.len();
    match name.as_str() {
        "/help" => email_instruction_packets(),
        "/stuck" => stuck_command_packets(config),
        "/skibidi" => Ok(vec![chat_packet(
            "Brrrrrr Skibidi dop dop dop yes yes!",
            None,
        )?]),
        "/video" if !has_arguments => Ok(vec![
            chat_packet(
                "\u{00a7}cUsage: /video play map [width=5] [fps=10] [dither=1]",
                Some("red"),
            )?,
            chat_packet(
                "\u{00a7}c       /video play [width=48] [fps=6]",
                Some("red"),
            )?,
            chat_packet("\u{00a7}c       /video stop | /video pause", Some("red"))?,
        ]),
        "/draft" => draft_summary_packets(draft),
        "/clear" => {
            draft.clear();
            let mut packets = vec![chat_packet("\u{00a7}aDraft cleared!", Some("green"))?];
            packets.extend(empty_draft_sign_packets()?);
            packets.push(draft_book_packet()?);
            Ok(packets)
        }
        "/menu" => menu_window_id.map_or_else(
            || Ok(Vec::new()),
            |window_id| main_menu_packets(window_id, render_settings),
        ),
        "/mail" | "/video" => Ok(Vec::new()),
        _ => Ok(vec![chat_packet(
            "\u{00a7}cUnknown command. Use /help",
            Some("red"),
        )?]),
    }
}

fn draft_summary_packets(draft: &MinecraftDraft) -> io::Result<Vec<Vec<u8>>> {
    [
        "\u{00a7}e\u{00a7}lCurrent Draft:".to_owned(),
        format!("\u{00a7}7To: \u{00a7}f{}", draft_display(&draft.to)),
        format!("\u{00a7}7CC: \u{00a7}f{}", draft_display(&draft.cc)),
        format!("\u{00a7}7BCC: \u{00a7}f{}", draft_display(&draft.bcc)),
        format!(
            "\u{00a7}7Subject: \u{00a7}f{}",
            draft_display(&draft.subject)
        ),
        format!("\u{00a7}7Body: \u{00a7}f{} page(s)", draft.body_pages.len()),
    ]
    .into_iter()
    .map(|text| chat_packet(&text, None))
    .collect()
}

fn draft_display(value: &str) -> &str {
    if value.chars().all(char::is_whitespace) {
        "(empty)"
    } else {
        value
    }
}

fn main_menu_packets(window_id: u8, render_settings: RenderSettings) -> io::Result<Vec<Vec<u8>>> {
    let mut open = vec![0x2d, window_id];
    write_string(&mut open, "minecraft:chest")?;
    write_string(&mut open, &chat_json("\u{00a7}8LMYZMAIL Menu", None))?;
    open.push(54);

    Ok(vec![
        open,
        main_menu_contents_packet(window_id, render_settings)?,
    ])
}

fn main_menu_contents_packet(
    window_id: u8,
    render_settings: RenderSettings,
) -> io::Result<Vec<u8>> {
    let filler = gui_slot(160, 15, " ", &[], false);
    let mut slots = vec![filler; 54];
    slots.extend((0..36).map(|_| MinecraftSlot::empty()));
    slots[4] = gui_slot(
        399,
        0,
        "\u{00a7}6\u{00a7}lLMYZMAIL",
        &[
            "\u{00a7}7Minecraft Mail Server",
            "\u{00a7}7Skibidi dop dop yes yes!",
        ],
        true,
    );
    slots[10] = gui_slot(
        54,
        0,
        "\u{00a7}a\u{00a7}lInbox",
        &[
            "\u{00a7}7View received emails",
            "",
            "\u{00a7}eClick to open",
        ],
        false,
    );
    slots[12] = gui_slot(
        262,
        0,
        "\u{00a7}b\u{00a7}lSent",
        &["\u{00a7}7View sent emails", "", "\u{00a7}eClick to open"],
        false,
    );
    slots[14] = gui_slot(
        327,
        0,
        "\u{00a7}c\u{00a7}lTrash",
        &["\u{00a7}7View deleted emails", "", "\u{00a7}eClick to open"],
        false,
    );
    slots[16] = gui_slot(
        367,
        0,
        "\u{00a7}4\u{00a7}lSpam",
        &["\u{00a7}7View spam emails", "", "\u{00a7}eClick to open"],
        false,
    );
    let render_current = format!(
        "\u{00a7}7Current: \u{00a7}f{}\u{00d7}{} \u{00a7}7maps",
        render_settings.maps_x, render_settings.maps_y
    );
    let render_pixels = format!(
        "\u{00a7}7({}\u{00d7}{} px)",
        render_settings.maps_x * 128,
        render_settings.maps_y * 128
    );
    let render_font = format!("\u{00a7}7Font: \u{00a7}f{}px", render_settings.font_size);
    slots[22] = gui_slot(
        323,
        0,
        "\u{00a7}e\u{00a7}lRender Settings",
        &[
            "\u{00a7}7Mail render dimensions",
            &render_current,
            &render_pixels,
            &render_font,
            "",
            "\u{00a7}eClick to change",
        ],
        false,
    );
    slots[28] = gui_slot(
        49,
        0,
        "\u{00a7}c\u{00a7}lVideo Player",
        &[
            "\u{00a7}7Watch Skibidi Toilet EP.1",
            "\u{00a7}7in Minecraft!",
            "",
            "\u{00a7}eClick to choose mode",
        ],
        false,
    );
    slots[30] = gui_slot(
        340,
        0,
        "\u{00a7}f\u{00a7}lHelp",
        &["\u{00a7}7Show command help", "", "\u{00a7}eClick for help"],
        false,
    );
    slots[32] = gui_slot(
        345,
        0,
        "\u{00a7}e\u{00a7}lSwitch Account",
        &[
            "\u{00a7}7Log out and sign in",
            "\u{00a7}7with a different email",
            "",
            "\u{00a7}eClick to switch",
        ],
        false,
    );
    slots[34] = gui_slot(
        166,
        0,
        "\u{00a7}c\u{00a7}lLogout",
        &[
            "\u{00a7}7Disconnect from LMYZMAIL",
            "",
            "\u{00a7}eClick to logout",
        ],
        false,
    );
    slots[49] = gui_slot(
        331,
        0,
        "\u{00a7}7Close Menu",
        &["\u{00a7}8Click to close"],
        false,
    );
    slots[81] = MinecraftSlot::item(386, 0, book_item_nbt());
    slots[89] = MinecraftSlot::item(399, 0, menu_star_nbt());

    let mut contents = vec![0x30, window_id];
    contents.extend_from_slice(&(slots.len() as i16).to_be_bytes());
    for slot in &slots {
        write_slot(&mut contents, slot)?;
    }
    Ok(contents)
}

fn main_menu_click_packets(
    click: WindowClick,
    logout_window_id: Option<u8>,
    render_settings: RenderSettings,
) -> io::Result<(Vec<Vec<u8>>, MainMenuEffect)> {
    let mut confirmation = vec![0x32, click.window_id];
    confirmation.extend_from_slice(&click.action_number.to_be_bytes());
    confirmation.push(0);

    let mut clear_cursor = vec![0x2f, u8::MAX];
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());

    let mut packets = vec![
        confirmation,
        clear_cursor,
        main_menu_contents_packet(click.window_id, render_settings)?,
    ];
    let effect = if click.mode != 0 || !(0..54).contains(&click.slot) {
        MainMenuEffect::None
    } else {
        match click.slot {
            22 => {
                packets.extend(close_menu_packets(click.window_id)?);
                packets.extend(render_settings_editor_packets(render_settings)?);
                MainMenuEffect::OpenRenderSettings
            }
            30 => {
                packets.extend(close_menu_packets(click.window_id)?);
                packets.extend(help_menu_packets()?);
                MainMenuEffect::Close
            }
            32 => {
                packets.extend(close_menu_packets(click.window_id)?);
                packets.push(chat_packet(
                    "\u{00a7}aPlease enter your new email address:",
                    Some("green"),
                )?);
                MainMenuEffect::SwitchAccount
            }
            34 => {
                let Some(window_id) = logout_window_id else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Minecraft logout confirmation window ID is missing",
                    ));
                };
                packets.extend(restore_hotbar_packets()?);
                packets.extend(logout_confirmation_packets(window_id)?);
                MainMenuEffect::OpenLogoutConfirm(window_id)
            }
            49 => {
                packets.extend(close_menu_packets(click.window_id)?);
                MainMenuEffect::Close
            }
            _ => MainMenuEffect::None,
        }
    };
    Ok((packets, effect))
}

fn render_settings_editor_packets(render_settings: RenderSettings) -> io::Result<Vec<Vec<u8>>> {
    let sign_nbt = NbtValue::Compound(vec![
        ("id".to_owned(), NbtValue::String("Sign".to_owned())),
        ("x".to_owned(), NbtValue::Int(0)),
        ("y".to_owned(), NbtValue::Int(0)),
        ("z".to_owned(), NbtValue::Int(0)),
        (
            "Text1".to_owned(),
            NbtValue::String(chat_json(&render_settings.maps_x.to_string(), None)),
        ),
        (
            "Text2".to_owned(),
            NbtValue::String(chat_json(&render_settings.maps_y.to_string(), None)),
        ),
        (
            "Text3".to_owned(),
            NbtValue::String(chat_json(&render_settings.font_size.to_string(), None)),
        ),
        (
            "Text4".to_owned(),
            NbtValue::String(chat_json("\u{00a7}oW H Font", None)),
        ),
    ]);
    let mut update = vec![0x35];
    write_block_position(&mut update, 0, 0, 0);
    update.push(9);
    minecraft_world::write_nbt(Some(&sign_nbt), &mut update)?;

    let mut editor = vec![0x36];
    write_block_position(&mut editor, 0, 0, 0);

    Ok(vec![
        update,
        editor,
        chat_packet(
            "\u{00a7}7Enter render dimensions in the sign:",
            Some("gray"),
        )?,
        chat_packet(
            "\u{00a7}7  Line 1: Width in maps \u{00a7}f(2-24)",
            Some("gray"),
        )?,
        chat_packet(
            "\u{00a7}7  Line 2: Height in maps \u{00a7}f(2-20)",
            Some("gray"),
        )?,
        chat_packet(
            "\u{00a7}7  Line 3: Font size in px \u{00a7}f(8-48, default 20)",
            Some("gray"),
        )?,
    ])
}

fn render_settings_update_packets(
    update: UpdateSign,
    render_settings: &mut RenderSettings,
    username: &str,
    email: &str,
    draft: &MinecraftDraft,
) -> io::Result<Vec<Vec<u8>>> {
    let width_text = clean_sign_text(&strip_chat_json(&update.lines[0]));
    let height_text = clean_sign_text(&strip_chat_json(&update.lines[1]));
    let font_text = clean_sign_text(&strip_chat_json(&update.lines[2]));
    let width = width_text.parse::<i32>();
    let height = height_text.parse::<i32>();

    let (Ok(width), Ok(height)) = (width, height) else {
        let mut packets = vec![chat_packet(
            "\u{00a7}cWidth and height must be integers.",
            Some("red"),
        )?];
        packets.extend(draft_sign_packets(draft)?);
        return Ok(packets);
    };
    if !(RENDER_MAPS_X_MIN..=RENDER_MAPS_X_MAX).contains(&width) {
        let mut packets = vec![chat_packet(
            &format!("\u{00a7}cWidth must be 2-24 maps (got {width})"),
            Some("red"),
        )?];
        packets.extend(draft_sign_packets(draft)?);
        return Ok(packets);
    }
    if !(RENDER_MAPS_Y_MIN..=RENDER_MAPS_Y_MAX).contains(&height) {
        let mut packets = vec![chat_packet(
            &format!("\u{00a7}cHeight must be 2-20 maps (got {height})"),
            Some("red"),
        )?];
        packets.extend(draft_sign_packets(draft)?);
        return Ok(packets);
    }

    render_settings.maps_x = width;
    render_settings.maps_y = height;
    let mut packets = Vec::new();
    if !font_text.is_empty()
        && let Ok(font_size) = font_text.parse::<i32>()
    {
        if (RENDER_FONT_SIZE_MIN..=RENDER_FONT_SIZE_MAX).contains(&font_size) {
            render_settings.font_size = font_size;
        } else {
            packets.push(chat_packet(
                "\u{00a7}cFont size must be 8-48px",
                Some("red"),
            )?);
        }
    }
    packets.push(chat_packet(
        &format!(
            "\u{00a7}aRender: \u{00a7}f{}\u{00d7}{} \u{00a7}amaps, font \u{00a7}f{}px",
            render_settings.maps_x, render_settings.maps_y, render_settings.font_size
        ),
        Some("green"),
    )?);
    packets.extend(authenticated_scoreboard_packets(
        username,
        email,
        *render_settings,
    )?);
    packets.extend(draft_sign_packets(draft)?);
    Ok(packets)
}

fn strip_chat_json(value: &str) -> String {
    let value = java_trim(value);
    if value.starts_with('{') {
        let Some(text_index) = value.find("\"text\"") else {
            return String::new();
        };
        let after_key = &value[text_index + 6..];
        let Some(open_quote) = after_key.find('"') else {
            return String::new();
        };
        let text_start = text_index + 6 + open_quote + 1;
        let Some(close_quote) = value[text_start..].find('"') else {
            return String::new();
        };
        return value[text_start..text_start + close_quote]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\");
    }
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        return value[1..value.len() - 1].to_owned();
    }
    value.to_owned()
}

fn clean_sign_text(value: &str) -> String {
    let mut without_formatting = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character == '\u{00a7}' {
            let _ = characters.next();
        } else {
            without_formatting.push(character);
        }
    }
    for label in ["[To]", "[CC]", "[BCC]", "[Subject]", "[Status]"] {
        without_formatting = without_formatting.replace(label, "");
    }
    without_formatting.retain(
        |character| !matches!(character, '\0'..='\u{001f}' | '\u{007f}'..='\u{009f}' | '\u{00a7}'),
    );
    java_trim(&without_formatting).to_owned()
}

fn logout_confirmation_packets(window_id: u8) -> io::Result<Vec<Vec<u8>>> {
    let mut open = vec![0x2d, window_id];
    write_string(&mut open, "minecraft:chest")?;
    write_string(&mut open, &chat_json("\u{00a7}cConfirm Logout", None))?;
    open.push(27);
    Ok(vec![open, logout_confirmation_contents_packet(window_id)?])
}

fn logout_confirmation_contents_packet(window_id: u8) -> io::Result<Vec<u8>> {
    let filler = gui_slot(160, 15, " ", &[], false);
    let mut slots = vec![filler; 27];
    slots.extend((0..36).map(|_| MinecraftSlot::empty()));
    slots[11] = gui_slot(
        35,
        5,
        "\u{00a7}a\u{00a7}lConfirm",
        &[
            "\u{00a7}7You will be disconnected.",
            "",
            "\u{00a7}aClick to confirm",
        ],
        false,
    );
    slots[15] = gui_slot(
        35,
        14,
        "\u{00a7}c\u{00a7}lCancel",
        &["\u{00a7}7Go back"],
        false,
    );
    slots[54] = MinecraftSlot::item(386, 0, book_item_nbt());
    slots[62] = MinecraftSlot::item(399, 0, menu_star_nbt());

    let mut contents = vec![0x30, window_id];
    contents.extend_from_slice(&(slots.len() as i16).to_be_bytes());
    for slot in &slots {
        write_slot(&mut contents, slot)?;
    }
    Ok(contents)
}

fn logout_confirmation_click_packets(
    click: WindowClick,
    main_window_id: Option<u8>,
    render_settings: RenderSettings,
) -> io::Result<(Vec<Vec<u8>>, LogoutConfirmEffect)> {
    let mut confirmation = vec![0x32, click.window_id];
    confirmation.extend_from_slice(&click.action_number.to_be_bytes());
    confirmation.push(0);

    let mut clear_cursor = vec![0x2f, u8::MAX];
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());
    clear_cursor.extend_from_slice(&(-1_i16).to_be_bytes());

    let mut packets = vec![
        confirmation,
        clear_cursor,
        logout_confirmation_contents_packet(click.window_id)?,
    ];
    let effect = if click.mode != 0 || !(0..27).contains(&click.slot) {
        LogoutConfirmEffect::None
    } else {
        match click.slot {
            11 => {
                packets.extend(close_menu_packets(click.window_id)?);
                packets.push(disconnect_play_packet("\u{00a7}aLogged out. See you!")?);
                LogoutConfirmEffect::Disconnect
            }
            15 => {
                let Some(window_id) = main_window_id else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Minecraft main-menu return window ID is missing",
                    ));
                };
                packets.extend(close_menu_packets(click.window_id)?);
                packets.extend(main_menu_packets(window_id, render_settings)?);
                LogoutConfirmEffect::OpenMainMenu(window_id)
            }
            _ => LogoutConfirmEffect::None,
        }
    };
    Ok((packets, effect))
}

fn close_menu_packets(window_id: u8) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = vec![vec![0x2e, window_id]];
    packets.extend(restore_hotbar_packets()?);
    Ok(packets)
}

fn help_menu_packets() -> io::Result<Vec<Vec<u8>>> {
    [
        "\u{00a7}e\u{00a7}l=== Help ===",
        "\u{00a7}7Hold \u{00a7}f\u{2605} Nether Star \u{00a7}7and right-click \u{2192} Open menu",
        "\u{00a7}7/mail close \u{00a7}7\u{2192} Close email view",
        "\u{00a7}7/mail next/prev \u{00a7}7\u{2192} Navigate pages",
        "\u{00a7}7/video play map \u{00a7}7\u{2192} Play video",
        "\u{00a7}7/draft, /clear, /stuck, /help",
    ]
    .into_iter()
    .map(|text| chat_packet(text, None))
    .collect()
}

fn gui_slot(item_id: i16, damage: i16, name: &str, lore: &[&str], glow: bool) -> MinecraftSlot {
    let mut display = vec![("Name".to_owned(), NbtValue::String(name.to_owned()))];
    if !lore.is_empty() {
        display.push((
            "Lore".to_owned(),
            NbtValue::List {
                element_type: 8,
                values: lore
                    .iter()
                    .map(|line| NbtValue::String((*line).to_owned()))
                    .collect(),
            },
        ));
    }
    let mut root = vec![("display".to_owned(), NbtValue::Compound(display))];
    if glow {
        root.push((
            "ench".to_owned(),
            NbtValue::List {
                element_type: 10,
                values: vec![NbtValue::Compound(vec![
                    ("id".to_owned(), NbtValue::Short(0)),
                    ("lvl".to_owned(), NbtValue::Short(1)),
                ])],
            },
        ));
        root.push(("HideFlags".to_owned(), NbtValue::Int(63)));
    }
    MinecraftSlot::item(item_id, damage, NbtValue::Compound(root))
}

fn write_slot(output: &mut Vec<u8>, slot: &MinecraftSlot) -> io::Result<()> {
    output.extend_from_slice(&slot.item_id.to_be_bytes());
    if slot.item_id >= 0 {
        output.push(slot.count);
        output.extend_from_slice(&slot.damage.to_be_bytes());
        minecraft_world::write_nbt(slot.nbt.as_ref(), output)?;
    }
    Ok(())
}

fn stuck_command_packets(config: &MinecraftConfig) -> io::Result<Vec<Vec<u8>>> {
    let mut position = vec![0x08];
    position.extend_from_slice(&config.spawn.x.to_be_bytes());
    position.extend_from_slice(&config.spawn.y.to_be_bytes());
    position.extend_from_slice(&config.spawn.z.to_be_bytes());
    position.extend_from_slice(&config.spawn.yaw.to_be_bytes());
    position.extend_from_slice(&config.spawn.pitch.to_be_bytes());
    position.push(0);
    Ok(vec![
        position,
        chat_packet("\u{00a7}aTeleported to spawn!", Some("green"))?,
    ])
}

fn java_trim(value: &str) -> &str {
    value.trim_matches(|character| character <= '\u{20}')
}

fn java_regex_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r')
}

fn empty_draft_sign_packets() -> io::Result<Vec<Vec<u8>>> {
    draft_sign_packets(&MinecraftDraft::default())
}

fn draft_sign_packets(draft: &MinecraftDraft) -> io::Result<Vec<Vec<u8>>> {
    let mut packets = Vec::with_capacity(4);
    for (x, label, content) in [
        (2, "\u{00a7}1[To]", draft.to.as_str()),
        (4, "\u{00a7}1[CC]", draft.cc.as_str()),
        (6, "\u{00a7}1[BCC]", draft.bcc.as_str()),
        (8, "\u{00a7}1[Subject]", draft.subject.as_str()),
    ] {
        let lines = split_sign_lines(content);
        let mut sign = vec![0x33];
        write_block_position(&mut sign, x, 161, 3);
        for text in [label, &lines[0], &lines[1], &lines[2]] {
            write_string(&mut sign, &chat_json(text, None))?;
        }
        packets.push(sign);
    }
    Ok(packets)
}

fn split_sign_lines(value: &str) -> [String; 3] {
    let mut lines = std::array::from_fn(|_| String::new());
    let encoded = value.encode_utf16().collect::<Vec<_>>();
    for (line, units) in lines.iter_mut().zip(encoded.chunks(15)) {
        *line = java_utf16_slice_to_string(units);
    }
    lines
}

fn java_utf16_slice_to_string(units: &[u16]) -> String {
    let mut output = String::with_capacity(units.len());
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if (0xd800..=0xdbff).contains(&unit)
            && let Some(&low) = units.get(index + 1)
            && (0xdc00..=0xdfff).contains(&low)
        {
            let code_point =
                0x1_0000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
            output.push(char::from_u32(code_point).expect("valid UTF-16 surrogate pair"));
            index += 2;
            continue;
        }
        if (0xd800..=0xdfff).contains(&unit) {
            output.push('?');
        } else {
            output.push(char::from_u32(u32::from(unit)).expect("valid UTF-16 BMP scalar"));
        }
        index += 1;
    }
    output
}

fn draft_book_packet() -> io::Result<Vec<u8>> {
    let mut packet = vec![0x2f, 0];
    packet.extend_from_slice(&36_i16.to_be_bytes());
    packet.extend_from_slice(&386_i16.to_be_bytes());
    packet.push(1);
    packet.extend_from_slice(&0_i16.to_be_bytes());
    minecraft_world::write_nbt(Some(&book_item_nbt()), &mut packet)?;
    Ok(packet)
}

fn restore_hotbar_packets() -> io::Result<Vec<Vec<u8>>> {
    let mut menu_star = vec![0x2f, 0];
    menu_star.extend_from_slice(&44_i16.to_be_bytes());
    menu_star.extend_from_slice(&399_i16.to_be_bytes());
    menu_star.push(1);
    menu_star.extend_from_slice(&0_i16.to_be_bytes());
    minecraft_world::write_nbt(Some(&menu_star_nbt()), &mut menu_star)?;
    Ok(vec![draft_book_packet()?, menu_star])
}

fn authenticated_scoreboard_packets(
    username: &str,
    email: &str,
    render_settings: RenderSettings,
) -> io::Result<Vec<Vec<u8>>> {
    let email = if email.encode_utf16().count() > 20 {
        format!("{}...", truncate_utf16(email, 17))
    } else {
        email.to_owned()
    };
    let divider = format!("\u{00a7}7{}", "\u{2501}".repeat(13));
    let lines = [
        divider.clone(),
        format!("\u{00a7}fPlayer: \u{00a7}a{username}"),
        format!("\u{00a7}fEmail: \u{00a7}b{email}"),
        String::new(),
        format!(
            "\u{00a7}fRender: \u{00a7}e{}\u{00d7}{} maps",
            render_settings.maps_x, render_settings.maps_y
        ),
        format!("\u{00a7}fFont: \u{00a7}e{}px", render_settings.font_size),
        String::new(),
        "\u{00a7}f/menu \u{00a7}7\u{2192} Open menu".to_owned(),
        divider,
        "\u{00a7}email.lmyz.net".to_owned(),
    ];
    let mut packets = Vec::with_capacity(13);
    let mut remove = vec![0x3b];
    write_string(&mut remove, "lmyz")?;
    remove.push(1);
    packets.push(remove);

    let mut create = vec![0x3b];
    write_string(&mut create, "lmyz")?;
    create.push(0);
    write_string(&mut create, "\u{00a7}6\u{00a7}lLMYZMAIL")?;
    write_string(&mut create, "dummy")?;
    packets.push(create);

    let mut display = vec![0x3d, 1];
    write_string(&mut display, "lmyz")?;
    packets.push(display);

    let line_count = lines.len();
    for (index, line) in lines.into_iter().enumerate() {
        let prefix = char::from_digit(index as u32, 16).unwrap_or('f');
        let score_name = truncate_utf16(&format!("\u{00a7}{prefix}\u{00a7}r{line}"), 40);
        let mut score = vec![0x3c];
        write_string(&mut score, &score_name)?;
        score.push(0);
        write_string(&mut score, "lmyz")?;
        write_varint(&mut score, (line_count - index) as u32);
        packets.push(score);
    }
    Ok(packets)
}

fn truncate_utf16(value: &str, max_units: usize) -> String {
    let mut output = String::new();
    let mut units = 0;
    for character in value.chars() {
        let character_units = character.len_utf16();
        if units + character_units > max_units {
            break;
        }
        output.push(character);
        units += character_units;
    }
    output
}

fn chat_json(text: &str, color: Option<&str>) -> String {
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    match color {
        Some(color) => format!(r#"{{"text":"{escaped}","color":"{color}"}}"#),
        None => format!(r#"{{"text":"{escaped}"}}"#),
    }
}

fn parse_uuid_bytes(value: &str) -> Option<[u8; 16]> {
    let compact = value.replace('-', "");
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut output = [0_u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (hex_nibble(compact.as_bytes()[index * 2])? << 4)
            | hex_nibble(compact.as_bytes()[index * 2 + 1])?;
    }
    Some(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn book_item_nbt() -> NbtValue {
    NbtValue::Compound(vec![(
        "pages".to_owned(),
        NbtValue::List {
            element_type: 8,
            values: vec![NbtValue::String(String::new())],
        },
    )])
}

fn menu_star_nbt() -> NbtValue {
    NbtValue::Compound(vec![
        (
            "display".to_owned(),
            NbtValue::Compound(vec![
                (
                    "Name".to_owned(),
                    NbtValue::String("\u{00a7}6\u{00a7}lMenu \u{00a7}7(Right Click)".to_owned()),
                ),
                (
                    "Lore".to_owned(),
                    NbtValue::List {
                        element_type: 8,
                        values: vec![NbtValue::String("\u{00a7}7Open the main menu".to_owned())],
                    },
                ),
            ]),
        ),
        (
            "ench".to_owned(),
            NbtValue::List {
                element_type: 10,
                values: vec![NbtValue::Compound(vec![
                    ("id".to_owned(), NbtValue::Short(0)),
                    ("lvl".to_owned(), NbtValue::Short(1)),
                ])],
            },
        ),
        ("HideFlags".to_owned(), NbtValue::Int(63)),
    ])
}

async fn write_packet<W: AsyncWrite + Unpin>(
    stream: &mut W,
    service: &StatusService,
    packet: Vec<u8>,
    compression: Option<i32>,
    cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), ProtocolError> {
    let frame = encode_packet_frame(service, packet, compression, deadline, cancellation).await?;
    write_bytes(stream, &frame, cipher, deadline, cancellation).await
}

async fn write_packet_list<W: AsyncWrite + Unpin>(
    stream: &mut W,
    service: &StatusService,
    packets: Vec<Vec<u8>>,
    compression: Option<i32>,
    mut cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), ProtocolError> {
    for packet in packets {
        write_packet(
            stream,
            service,
            packet,
            compression,
            cipher.as_deref_mut(),
            deadline,
            cancellation,
        )
        .await?;
    }
    Ok(())
}

async fn encode_packet_frame(
    service: &StatusService,
    packet: Vec<u8>,
    compression: Option<i32>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, ProtocolError> {
    let Some(threshold) = compression else {
        return encode_frame(&packet).map_err(ProtocolError::Io);
    };
    let mut envelope = Vec::new();
    if packet.len() < threshold as usize {
        envelope
            .try_reserve_exact(packet.len() + 1)
            .map_err(|error| {
                ProtocolError::Io(io::Error::other(format!(
                    "Minecraft packet allocation failed: {error}"
                )))
            })?;
        envelope.push(0);
        envelope.extend_from_slice(&packet);
    } else {
        let uncompressed_length =
            u32::try_from(packet.len()).map_err(|_| ProtocolError::Malformed)?;
        let worker_cancellation = cancellation.clone();
        let receiver = service
            .compression_pool
            .submit(move || compress_packet(packet, &worker_cancellation, deadline))
            .map_err(submit_error)?;
        let compressed = await_compression(receiver, deadline, cancellation).await??;
        envelope
            .try_reserve_exact(compressed.len() + 5)
            .map_err(|error| {
                ProtocolError::Io(io::Error::other(format!(
                    "Minecraft packet allocation failed: {error}"
                )))
            })?;
        write_varint(&mut envelope, uncompressed_length);
        envelope.extend_from_slice(&compressed);
    }
    encode_frame(&envelope).map_err(ProtocolError::Io)
}

async fn decode_compression_envelope(
    service: &StatusService,
    mut frame: Vec<u8>,
    threshold: i32,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, ProtocolError> {
    let mut reader = PacketReader::new(&frame);
    let data_length = reader
        .read_varint()
        .map_err(|()| ProtocolError::Malformed)?;
    if data_length < 0 {
        return Err(ProtocolError::Malformed);
    }
    let cursor = reader.cursor;
    if cursor == frame.len() {
        return Err(ProtocolError::Malformed);
    }
    if data_length == 0 {
        let packet_length = frame.len() - cursor;
        if packet_length >= threshold as usize {
            return Err(ProtocolError::Malformed);
        }
        frame.copy_within(cursor.., 0);
        frame.truncate(packet_length);
        return Ok(frame);
    }

    let expected = data_length as usize;
    if expected > MAX_FRAME_LENGTH || expected < threshold as usize {
        return Err(ProtocolError::Malformed);
    }
    let receiver = service
        .compression_pool
        .submit({
            let worker_cancellation = cancellation.clone();
            move || decompress_packet(frame, cursor, expected, &worker_cancellation, deadline)
        })
        .map_err(submit_error)?;
    await_compression(receiver, deadline, cancellation).await?
}

fn submit_error(error: SubmitError) -> ProtocolError {
    match error {
        SubmitError::Closed | SubmitError::Full => ProtocolError::Malformed,
    }
}

async fn await_compression<T>(
    receiver: tokio::sync::oneshot::Receiver<T>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<T, ProtocolError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProtocolError::Cancelled),
        result = timeout_at(deadline, receiver) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(ProtocolError::Io(io::Error::other(
                "Minecraft compression worker stopped",
            ))),
            Err(_) => Err(ProtocolError::TimedOut),
        },
    }
}

fn compression_budget(
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<(), ProtocolError> {
    if cancellation.is_cancelled() {
        Err(ProtocolError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(ProtocolError::TimedOut)
    } else {
        Ok(())
    }
}

fn compress_packet(
    packet: Vec<u8>,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    for chunk in packet.chunks(COMPRESSION_CHUNK_BYTES) {
        compression_budget(cancellation, deadline)?;
        encoder.write_all(chunk).map_err(ProtocolError::Io)?;
    }
    compression_budget(cancellation, deadline)?;
    let output = encoder.finish().map_err(ProtocolError::Io)?;
    compression_budget(cancellation, deadline)?;
    Ok(output)
}

fn decompress_packet(
    frame: Vec<u8>,
    cursor: usize,
    expected: usize,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> Result<Vec<u8>, ProtocolError> {
    let mut decoder = flate2::Decompress::new(true);
    let mut output = vec![0_u8; expected];
    let input = &frame[cursor..];
    let mut input_cursor = 0;
    let mut output_cursor: usize = 0;
    let mut overflow_probe = [0_u8; 1];
    loop {
        compression_budget(cancellation, deadline)?;
        let output_end = output_cursor
            .saturating_add(COMPRESSION_CHUNK_BYTES)
            .min(output.len());
        let output_chunk = if output_cursor < output.len() {
            &mut output[output_cursor..output_end]
        } else {
            &mut overflow_probe[..]
        };
        let input_before = decoder.total_in();
        let output_before = decoder.total_out();
        let status = decoder
            .decompress(
                &input[input_cursor..],
                output_chunk,
                flate2::FlushDecompress::Finish,
            )
            .map_err(|_| ProtocolError::Malformed)?;
        let consumed = (decoder.total_in() - input_before) as usize;
        let produced = (decoder.total_out() - output_before) as usize;
        input_cursor += consumed;
        if output_cursor == output.len() && produced != 0 {
            return Err(ProtocolError::Malformed);
        }
        output_cursor += produced;
        if status == flate2::Status::StreamEnd {
            break;
        }
        if consumed == 0 && produced == 0 {
            return Err(ProtocolError::Malformed);
        }
    }
    compression_budget(cancellation, deadline)?;
    if input_cursor != input.len() || output_cursor != expected {
        return Err(ProtocolError::Malformed);
    }
    Ok(output)
}

fn offline_uuid(username: &str) -> io::Result<String> {
    let input = format!("OfflinePlayer:{username}");
    let mut bytes: [u8; 16] = Md5::digest(input.as_bytes()).into();
    bytes[6] = (bytes[6] & 0x0f) | 0x30;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut value = String::with_capacity(36);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        value.push(HEX[usize::from(byte >> 4)] as char);
        value.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    Ok(value)
}

fn write_string(output: &mut Vec<u8>, value: &str) -> io::Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() > 32_767 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft outbound string exceeded 32767 bytes",
        ));
    }
    output.try_reserve_exact(bytes.len() + 5).map_err(|error| {
        io::Error::other(format!("Minecraft string allocation failed: {error}"))
    })?;
    write_varint(output, bytes.len() as u32);
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_byte_array(output: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft byte array exceeded the protocol range",
        )
    })?;
    output.try_reserve_exact(value.len() + 5).map_err(|error| {
        io::Error::other(format!("Minecraft byte array allocation failed: {error}"))
    })?;
    write_varint(output, length);
    output.extend_from_slice(value);
    Ok(())
}

fn initial_play_packets(entity_id: i32, config: &MinecraftConfig) -> io::Result<Vec<Vec<u8>>> {
    let mut join_game = vec![0x01];
    join_game.extend_from_slice(&entity_id.to_be_bytes());
    join_game.extend_from_slice(&[0x02, 0x00, 0x00, config.max_players as u8]);
    write_string(&mut join_game, "default")?;
    join_game.push(0);

    let mut spawn = vec![0x05];
    let spawn_x = config.spawn.x as i32;
    let spawn_y = config.spawn.y as i32;
    let spawn_z = config.spawn.z as i32;
    let packed_spawn = ((i64::from(spawn_x) & 0x3ff_ffff) << 38)
        | ((i64::from(spawn_y) & 0xfff) << 26)
        | (i64::from(spawn_z) & 0x3ff_ffff);
    spawn.extend_from_slice(&packed_spawn.to_be_bytes());

    let mut abilities = vec![0x39, 0x05];
    abilities.extend_from_slice(&0.05_f32.to_be_bytes());
    abilities.extend_from_slice(&0.1_f32.to_be_bytes());

    let mut time = vec![0x03];
    time.extend_from_slice(&0_i64.to_be_bytes());
    time.extend_from_slice(&(-6000_i64).to_be_bytes());

    let mut health = vec![0x06];
    health.extend_from_slice(&20.0_f32.to_be_bytes());
    write_varint(&mut health, 20);
    health.extend_from_slice(&5.0_f32.to_be_bytes());

    Ok(vec![
        join_game,
        vec![0x41, 0x00],
        spawn,
        abilities,
        time,
        health,
        vec![0x09, 0x00],
    ])
}

async fn read_frame<R: AsyncRead + Unpin>(
    stream: &mut R,
    mut cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    loop {
        let mut encoded_length = [0_u8; 5];
        let mut value = 0_u32;
        for index in 0..encoded_length.len() {
            let read = read_with_deadline(
                stream,
                &mut encoded_length[index..=index],
                cipher.as_deref_mut(),
                deadline,
                cancellation,
            )
            .await?;
            if read == 0 {
                return if index == 0 {
                    Ok(None)
                } else {
                    Err(ProtocolError::Malformed)
                };
            }
            let byte = encoded_length[index];
            if index == 4 && byte & 0xf0 != 0 {
                return Err(ProtocolError::Malformed);
            }
            value |= u32::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                let length = value as i32;
                if length < 0 || length as usize > MAX_FRAME_LENGTH {
                    return Err(ProtocolError::Malformed);
                }
                if length == 0 {
                    break;
                }
                let length = length as usize;
                let mut frame = Vec::new();
                frame.try_reserve_exact(length).map_err(|error| {
                    ProtocolError::Io(io::Error::other(format!(
                        "Minecraft frame allocation failed: {error}"
                    )))
                })?;
                frame.resize(length, 0);
                let mut cursor = 0;
                while cursor < frame.len() {
                    let read = read_with_deadline(
                        stream,
                        &mut frame[cursor..],
                        cipher.as_deref_mut(),
                        deadline,
                        cancellation,
                    )
                    .await?;
                    if read == 0 {
                        return Err(ProtocolError::Malformed);
                    }
                    cursor += read;
                }
                return Ok(Some(frame));
            }
            if index == 4 {
                return Err(ProtocolError::Malformed);
            }
        }
    }
}

async fn read_with_deadline<R: AsyncRead + Unpin>(
    stream: &mut R,
    buffer: &mut [u8],
    cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<usize, ProtocolError> {
    let read = tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProtocolError::Cancelled),
        result = timeout_at(deadline, stream.read(buffer)) => match result {
            Ok(result) => result.map_err(ProtocolError::Io),
            Err(_) => Err(ProtocolError::TimedOut),
        },
    }?;
    if let Some(cipher) = cipher {
        cipher.decrypt_in_place(&mut buffer[..read])?;
    }
    Ok(read)
}

async fn write_bytes<W: AsyncWrite + Unpin>(
    stream: &mut W,
    bytes: &[u8],
    cipher: Option<&mut MinecraftCipher>,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), ProtocolError> {
    let encrypted;
    let bytes = if let Some(cipher) = cipher {
        encrypted = cipher.encrypt(bytes)?;
        encrypted
    } else {
        bytes
    };
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProtocolError::Cancelled),
        result = timeout_at(deadline, stream.write_all(bytes)) => match result {
            Ok(result) => result.map_err(ProtocolError::Io),
            Err(_) => Err(ProtocolError::TimedOut),
        },
    }
}

fn transform_in_place(
    crypter: &mut Crypter,
    scratch: &mut Vec<u8>,
    bytes: &mut [u8],
) -> Result<(), ProtocolError> {
    let transformed = transform_to_scratch(crypter, scratch, bytes)?;
    bytes.copy_from_slice(transformed);
    Ok(())
}

fn transform_to_scratch<'a>(
    crypter: &mut Crypter,
    scratch: &'a mut Vec<u8>,
    bytes: &[u8],
) -> Result<&'a [u8], ProtocolError> {
    let capacity = bytes
        .len()
        .checked_add(Cipher::aes_128_cfb8().block_size())
        .ok_or(ProtocolError::Malformed)?;
    scratch.resize(capacity, 0);
    let written = crypter.update(bytes, scratch).map_err(crypto_protocol)?;
    if written != bytes.len() {
        return Err(ProtocolError::Malformed);
    }
    scratch.truncate(written);
    Ok(scratch)
}

fn crypto_io(error: openssl::error::ErrorStack) -> io::Error {
    io::Error::other(format!("Minecraft crypto initialization failed: {error}"))
}

fn crypto_protocol(_error: openssl::error::ErrorStack) -> ProtocolError {
    ProtocolError::Malformed
}

#[cfg(test)]
fn status_json(config: &MinecraftConfig) -> String {
    status_json_with_online(config, 0)
}

fn status_json_with_online(config: &MinecraftConfig, online: u32) -> String {
    let motd = config.motd.replace('\\', "\\\\").replace('"', "\\\"");
    let favicon = if config.favicon.trim().is_empty() {
        String::new()
    } else {
        format!(
            ",\"favicon\":\"data:image/png;base64,{}\"",
            config.favicon.trim()
        )
    };
    format!(
        "{{\"version\":{{\"name\":\"1.8.9\",\"protocol\":47}},\"players\":{{\"max\":{},\"online\":{},\"sample\":[]}},\"description\":{{\"text\":\"{}\"}}{}}}",
        config.max_players, online, motd, favicon
    )
}

fn build_status_frame(config: &MinecraftConfig, online: u32) -> io::Result<Vec<u8>> {
    let json = status_json_with_online(config, online);
    let mut payload = Vec::new();
    payload.try_reserve_exact(json.len() + 6).map_err(|error| {
        io::Error::other(format!("Minecraft status allocation failed: {error}"))
    })?;
    write_varint(&mut payload, 0);
    write_varint(&mut payload, json.len() as u32);
    payload.extend_from_slice(json.as_bytes());
    encode_frame(&payload)
}

fn login_disconnect_frame(reason_json: &str) -> io::Result<Vec<u8>> {
    encode_frame(&login_disconnect_packet(reason_json)?)
}

fn login_disconnect_packet(reason_json: &str) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(reason_json.len() + 6)
        .map_err(|error| io::Error::other(format!("Minecraft frame allocation failed: {error}")))?;
    write_varint(&mut payload, 0);
    write_varint(&mut payload, reason_json.len() as u32);
    payload.extend_from_slice(reason_json.as_bytes());
    Ok(payload)
}

fn contains_player(players: &[String], username: &str) -> bool {
    players
        .iter()
        .any(|player| java_equals_ignore_case(player, username))
}

fn java_equals_ignore_case(left: &str, right: &str) -> bool {
    if left.encode_utf16().count() != right.encode_utf16().count() {
        return false;
    }
    // JDK 22 uses Unicode 15.1; Cargo pins the matching ICU4X data generation.
    let case_mapper = CaseMapper::new();
    let mut left = left.chars();
    let mut right = right.chars();
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(left), Some(right)) => {
                if left == right {
                    continue;
                }
                let left_upper = case_mapper.simple_uppercase(left);
                let right_upper = case_mapper.simple_uppercase(right);
                if left_upper != right_upper
                    && case_mapper.simple_lowercase(left_upper)
                        != case_mapper.simple_lowercase(right_upper)
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn encode_frame(payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_FRAME_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Minecraft outbound frame is outside the protocol budget",
        ));
    }
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(payload.len() + 5)
        .map_err(|error| io::Error::other(format!("Minecraft frame allocation failed: {error}")))?;
    write_varint(&mut frame, payload.len() as u32);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn write_varint(output: &mut Vec<u8>, mut value: u32) {
    loop {
        if value & !0x7f == 0 {
            output.push(value as u8);
            return;
        }
        output.push(((value & 0x7f) | 0x80) as u8);
        value >>= 7;
    }
}

fn decode_java_utf8(bytes: &[u8]) -> Result<String, ()> {
    let mut output = String::new();
    output
        .try_reserve_exact(bytes.len().saturating_mul(3))
        .map_err(|_| ())?;
    let mut cursor = 0;
    while cursor < bytes.len() {
        let b1 = bytes[cursor];
        if b1 < 0x80 {
            output.push(char::from(b1));
            cursor += 1;
            continue;
        }
        if (0xc2..=0xdf).contains(&b1) {
            if cursor + 1 < bytes.len() && is_utf8_continuation(bytes[cursor + 1]) {
                let codepoint = (u32::from(b1 & 0x1f) << 6) | u32::from(bytes[cursor + 1] & 0x3f);
                output.push(char::from_u32(codepoint).ok_or(())?);
                cursor += 2;
            } else {
                output.push('\u{fffd}');
                cursor += 1;
            }
            continue;
        }
        if (0xe0..=0xef).contains(&b1) {
            let remaining = bytes.len() - cursor;
            if remaining < 3 {
                if remaining > 1
                    && ((b1 == 0xe0 && bytes[cursor + 1] & 0xe0 == 0x80)
                        || !is_utf8_continuation(bytes[cursor + 1]))
                {
                    output.push('\u{fffd}');
                    cursor += 1;
                } else {
                    output.push('\u{fffd}');
                    cursor = bytes.len();
                }
                continue;
            }
            let b2 = bytes[cursor + 1];
            let b3 = bytes[cursor + 2];
            if (b1 == 0xe0 && b2 & 0xe0 == 0x80)
                || !is_utf8_continuation(b2)
                || !is_utf8_continuation(b3)
            {
                let malformed_length =
                    if (b1 == 0xe0 && b2 & 0xe0 == 0x80) || !is_utf8_continuation(b2) {
                        1
                    } else {
                        2
                    };
                output.push('\u{fffd}');
                cursor += malformed_length;
                continue;
            }
            let codepoint =
                (u32::from(b1 & 0x0f) << 12) | (u32::from(b2 & 0x3f) << 6) | u32::from(b3 & 0x3f);
            if (0xd800..=0xdfff).contains(&codepoint) {
                output.push('\u{fffd}');
            } else {
                output.push(char::from_u32(codepoint).ok_or(())?);
            }
            cursor += 3;
            continue;
        }
        if (0xf0..=0xf7).contains(&b1) {
            let remaining = bytes.len() - cursor;
            if remaining < 4 {
                if b1 > 0xf4
                    || (remaining > 1 && invalid_java_utf8_four_byte_second(b1, bytes[cursor + 1]))
                {
                    output.push('\u{fffd}');
                    cursor += 1;
                } else if remaining > 2 && !is_utf8_continuation(bytes[cursor + 2]) {
                    output.push('\u{fffd}');
                    cursor += 2;
                } else {
                    output.push('\u{fffd}');
                    cursor = bytes.len();
                }
                continue;
            }
            let b2 = bytes[cursor + 1];
            let b3 = bytes[cursor + 2];
            let b4 = bytes[cursor + 3];
            let codepoint = (u32::from(b1 & 0x07) << 18)
                | (u32::from(b2 & 0x3f) << 12)
                | (u32::from(b3 & 0x3f) << 6)
                | u32::from(b4 & 0x3f);
            if !is_utf8_continuation(b2)
                || !is_utf8_continuation(b3)
                || !is_utf8_continuation(b4)
                || !(0x1_0000..=0x10_ffff).contains(&codepoint)
            {
                let malformed_length = if invalid_java_utf8_four_byte_second(b1, b2) {
                    1
                } else if !is_utf8_continuation(b3) {
                    2
                } else {
                    3
                };
                output.push('\u{fffd}');
                cursor += malformed_length;
                continue;
            }
            output.push(char::from_u32(codepoint).ok_or(())?);
            cursor += 4;
            continue;
        }
        output.push('\u{fffd}');
        cursor += 1;
    }
    Ok(output)
}

const fn is_utf8_continuation(byte: u8) -> bool {
    byte & 0xc0 == 0x80
}

const fn invalid_java_utf8_four_byte_second(first: u8, second: u8) -> bool {
    first > 0xf4
        || (first == 0xf0 && (second < 0x90 || second > 0xbf))
        || (first == 0xf4 && second & 0xf0 != 0x80)
        || !is_utf8_continuation(second)
}

struct PacketReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> PacketReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn read_varint(&mut self) -> Result<i32, ()> {
        let mut value = 0_u32;
        for index in 0..5 {
            let byte = *self.bytes.get(self.cursor).ok_or(())?;
            self.cursor += 1;
            if index == 4 && byte & 0xf0 != 0 {
                return Err(());
            }
            value |= u32::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value as i32);
            }
        }
        Err(())
    }

    fn read_string(&mut self, max_utf16_units: usize) -> Result<String, ()> {
        let length = self.read_varint()?;
        if length < 0 || length as usize > max_utf16_units.saturating_mul(4) {
            return Err(());
        }
        let length = length as usize;
        let end = self.cursor.checked_add(length).ok_or(())?;
        let bytes = self.bytes.get(self.cursor..end).ok_or(())?;
        self.cursor = end;
        let value = decode_java_utf8(bytes)?;
        if value.encode_utf16().count() > max_utf16_units {
            return Err(());
        }
        Ok(value)
    }

    fn read_byte_array(&mut self, max_bytes: usize) -> Result<Vec<u8>, ()> {
        let length = self.read_varint()?;
        if length < 0 || length as usize > max_bytes {
            return Err(());
        }
        let length = length as usize;
        let end = self.cursor.checked_add(length).ok_or(())?;
        let value = self.bytes.get(self.cursor..end).ok_or(())?.to_vec();
        self.cursor = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, ()> {
        let end = self.cursor.checked_add(2).ok_or(())?;
        let bytes: [u8; 2] = self
            .bytes
            .get(self.cursor..end)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        self.cursor = end;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_i16(&mut self) -> Result<i16, ()> {
        Ok(self.read_u16()? as i16)
    }

    fn read_u8(&mut self) -> Result<u8, ()> {
        let value = *self.bytes.get(self.cursor).ok_or(())?;
        self.cursor += 1;
        Ok(value)
    }

    fn skip_slot(&mut self) -> Result<(), ()> {
        let item_id = self.read_i16()?;
        if item_id >= 0 {
            self.read_u8()?;
            self.read_i16()?;
            let encoded = self.bytes.get(self.cursor..).ok_or(())?;
            let length = minecraft_world::network_nbt_len(encoded).map_err(|_| ())?;
            self.cursor = self.cursor.checked_add(length).ok_or(())?;
        }
        Ok(())
    }

    fn read_i64(&mut self) -> Result<i64, ()> {
        let end = self.cursor.checked_add(8).ok_or(())?;
        let bytes: [u8; 8] = self
            .bytes
            .get(self.cursor..end)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        self.cursor = end;
        Ok(i64::from_be_bytes(bytes))
    }

    fn read_f64(&mut self) -> Result<f64, ()> {
        Ok(f64::from_bits(self.read_i64()? as u64))
    }

    fn read_f32(&mut self) -> Result<f32, ()> {
        let end = self.cursor.checked_add(4).ok_or(())?;
        let bytes: [u8; 4] = self
            .bytes
            .get(self.cursor..end)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        self.cursor = end;
        Ok(f32::from_be_bytes(bytes))
    }
}

fn connection_ended(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

fn retryable_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
    ) || (cfg!(target_os = "linux")
        && matches!(
            error.raw_os_error(),
            Some(1 | 4 | 11 | 12 | 23 | 24 | 64 | 71 | 92 | 95 | 100 | 101 | 103 | 105 | 112 | 113)
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use proptest::prelude::*;
    use tokio::sync::oneshot;
    use tokio::time::sleep;

    const FROZEN_STATUS_FRAME: &str = "nAEAmQF7InZlcnNpb24iOnsibmFtZSI6IjEuOC45IiwicHJvdG9jb2wiOjQ3fSwicGxheWVycyI6eyJtYXgiOjIwLCJvbmxpbmUiOjAsInNhbXBsZSI6W119LCJkZXNjcmlwdGlvbiI6eyJ0ZXh0Ijoiwqc2TE1ZWk1BSUwgwqc3LSBTZW5kIGVtYWlscyBpbiBNaW5lY3JhZnQifX0=";

    fn config(timeout: Duration) -> MinecraftConfig {
        MinecraftConfig {
            enabled: true,
            online_mode: false,
            compression_threshold: 256,
            max_players: 20,
            motd: "§6LMYZMAIL §7- Send emails in Minecraft".to_owned(),
            favicon: String::new(),
            read_timeout_seconds: timeout.as_secs().max(1),
            session_server_url: "https://sessionserver.mojang.com/session/minecraft/hasJoined"
                .to_owned(),
            world_template: "worlds/mailroom".to_owned(),
            view_distance: 32,
            spawn: crate::config::MinecraftSpawnConfig {
                x: 0.5,
                y: 160.0,
                z: 0.5,
                yaw: 0.0,
                pitch: 0.0,
            },
            video: crate::config::MinecraftVideoConfig {
                center_x: 0,
                wall_z: -50,
            },
            whitelist_enabled: false,
            whitelist_players: Vec::new(),
            blacklist_players: Vec::new(),
            auth_max_attempts: 5,
            auth_lockout_seconds: 300,
            auth_window_seconds: 600,
        }
    }

    fn handshake(port: u16, next_state: i32) -> Vec<u8> {
        let mut packet = vec![0];
        write_varint(&mut packet, 47);
        write_varint(&mut packet, 9);
        packet.extend_from_slice(b"127.0.0.1");
        packet.extend_from_slice(&port.to_be_bytes());
        write_varint(&mut packet, next_state as u32);
        encode_frame(&packet).unwrap()
    }

    async fn start_server(
        max_connections: usize,
        timeout: Duration,
    ) -> (
        std::net::SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = Arc::new(StatusService::new(&config(timeout)).unwrap());
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task =
            tokio::spawn(
                async move { serve_listener(listener, service, child, max_connections).await },
            );
        (address, cancellation, task)
    }

    async fn start_server_with_config(
        max_connections: usize,
        config: MinecraftConfig,
    ) -> (
        std::net::SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let service = Arc::new(StatusService::new(&config).unwrap());
        let cancellation = CancellationToken::new();
        let child = cancellation.clone();
        let task =
            tokio::spawn(
                async move { serve_listener(listener, service, child, max_connections).await },
            );
        (address, cancellation, task)
    }

    async fn start_session_fixture(
        status: u16,
        body: String,
        response_delay: Duration,
    ) -> (
        std::net::SocketAddr,
        oneshot::Receiver<Vec<u8>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_sender, request_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "fixture client closed before HTTP headers");
                assert!(request.len() + read <= 8 * 1024);
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = request_sender.send(request);
            if !response_delay.is_zero() {
                sleep(response_delay).await;
            }
            let reason = match status {
                200 => "OK",
                204 => "No Content",
                _ => "Fixture",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
        (address, request_receiver, task)
    }

    fn rsa_encrypt(public_key_der: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let public_key = PKey::public_key_from_der(public_key_der)
            .unwrap()
            .rsa()
            .unwrap();
        let mut encrypted = vec![0_u8; public_key.size() as usize];
        let written = public_key
            .public_encrypt(plaintext, &mut encrypted, Padding::PKCS1)
            .unwrap();
        encrypted.truncate(written);
        encrypted
    }

    fn login_start(username: &[u8]) -> Vec<u8> {
        let mut packet = vec![0];
        write_varint(&mut packet, username.len() as u32);
        packet.extend_from_slice(username);
        encode_frame(&packet).unwrap()
    }

    async fn assert_closed_without_response(address: std::net::SocketAddr, payload: &[u8]) {
        let mut client = TcpStream::connect(address).await.unwrap();
        let _ = client.write_all(payload).await;
        let mut byte = [0_u8; 1];
        let result = timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("server did not reject malformed frame");
        assert!(
            matches!(result, Ok(0))
                || matches!(
                    result,
                    Err(ref error) if connection_ended(error)
                ),
            "unexpected rejection result: {result:?}"
        );
    }

    #[test]
    fn default_status_frame_matches_frozen_java_wire() {
        assert_eq!(MAX_CONNECTIONS, 64);
        let service = StatusService::new(&config(Duration::from_secs(30))).unwrap();
        assert_eq!(
            service.status_frame.as_ref(),
            STANDARD.decode(FROZEN_STATUS_FRAME).unwrap()
        );
    }

    #[test]
    fn minecraft_auth_limiter_matches_java_window_lockout_and_clear() {
        let limiter = MinecraftAuthLimiter {
            max_attempts: 3,
            lockout: Duration::from_secs(30),
            window: Duration::from_secs(10),
            records: Mutex::new(HashMap::new()),
        };
        let start = StdInstant::now();
        assert_eq!(limiter.record_failure_at("192.0.2.1", start), (false, 2));
        assert_eq!(
            limiter.record_failure_at("192.0.2.1", start + Duration::from_secs(10)),
            (false, 1)
        );
        assert_eq!(
            limiter.record_failure_at("192.0.2.1", start + Duration::from_secs(11)),
            (false, 1)
        );
        assert_eq!(
            limiter.record_failure_at("192.0.2.1", start + Duration::from_secs(12)),
            (true, 0)
        );
        assert_eq!(
            limiter.locked_remaining_at("192.0.2.1", start + Duration::from_secs(13)),
            Some(29)
        );
        assert_eq!(
            limiter.locked_remaining_at("192.0.2.1", start + Duration::from_secs(42)),
            None
        );
        assert_eq!(
            limiter
                .records
                .lock()
                .unwrap()
                .get("192.0.2.1")
                .unwrap()
                .failures
                .len(),
            0
        );
        limiter.clear("192.0.2.1");
        assert!(limiter.records.lock().unwrap().is_empty());
    }

    #[test]
    fn minecraft_auth_limiter_fails_closed_at_record_capacity_and_reclaims_stale_entries() {
        let limiter = MinecraftAuthLimiter {
            max_attempts: 3,
            lockout: Duration::from_secs(30),
            window: Duration::from_secs(10),
            records: Mutex::new(HashMap::new()),
        };
        let start = StdInstant::now();
        {
            let mut records = limiter.records.lock().unwrap();
            for index in 0..MAX_MINECRAFT_AUTH_RECORDS {
                records.insert(
                    format!("198.51.100.{index}"),
                    MinecraftAuthAttempt {
                        failures: VecDeque::from([start + Duration::from_secs(1)]),
                        locked_until: None,
                    },
                );
            }
        }
        assert_eq!(
            limiter.record_failure_at("203.0.113.1", start + Duration::from_secs(2)),
            (true, 0)
        );
        assert_eq!(
            limiter.records.lock().unwrap().len(),
            MAX_MINECRAFT_AUTH_RECORDS
        );

        limiter.records.lock().unwrap().clear();
        {
            let mut records = limiter.records.lock().unwrap();
            for index in 0..MAX_MINECRAFT_AUTH_RECORDS {
                records.insert(
                    format!("stale-{index}"),
                    MinecraftAuthAttempt {
                        failures: VecDeque::from([start]),
                        locked_until: None,
                    },
                );
            }
        }
        assert_eq!(
            limiter.record_failure_at("203.0.113.1", start + Duration::from_secs(11)),
            (false, 2)
        );
        assert_eq!(limiter.records.lock().unwrap().len(), 1);
    }

    #[test]
    fn authenticated_basic_commands_match_java_trim_case_and_packet_order() {
        let configured = config(Duration::from_secs(30));
        let mut draft = MinecraftDraft::default();
        let render_settings = RenderSettings::default();
        let help = authenticated_command_packets(
            "  /HeLp  ",
            &configured,
            &mut draft,
            None,
            render_settings,
        )
        .unwrap();
        assert_eq!(help, email_instruction_packets().unwrap());
        assert_eq!(help.len(), 8);
        assert!(help.iter().all(|packet| packet[0] == 0x02));

        let stuck =
            authenticated_command_packets("/stuck", &configured, &mut draft, None, render_settings)
                .unwrap();
        assert_eq!(stuck.len(), 2);
        assert_eq!(stuck[0][0], 0x08);
        assert_eq!(stuck[1][0], 0x02);
        assert_eq!(
            authenticated_command_packets(
                "/skibidi",
                &configured,
                &mut draft,
                None,
                render_settings,
            )
            .unwrap()[0],
            chat_packet("Brrrrrr Skibidi dop dop dop yes yes!", None).unwrap()
        );
        assert_eq!(
            authenticated_command_packets(
                "/video",
                &configured,
                &mut draft,
                None,
                render_settings,
            )
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            authenticated_command_packets(
                "/definitely-unknown",
                &configured,
                &mut draft,
                None,
                render_settings,
            )
            .unwrap()[0],
            chat_packet("\u{00a7}cUnknown command. Use /help", Some("red")).unwrap()
        );
        assert!(
            authenticated_command_packets(
                "plain chat",
                &configured,
                &mut draft,
                None,
                render_settings,
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn draft_commands_inspect_and_clear_the_session_state() {
        let configured = config(Duration::from_secs(30));
        let mut draft = MinecraftDraft {
            to: "to@example.test".to_owned(),
            cc: "cc@example.test".to_owned(),
            bcc: "bcc@example.test".to_owned(),
            subject: "subject".to_owned(),
            body_pages: vec!["page one".to_owned(), "page two".to_owned()],
        };
        let summary = authenticated_command_packets(
            "/draft",
            &configured,
            &mut draft,
            None,
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(summary.len(), 6);
        assert_eq!(
            summary[1],
            chat_packet("\u{00a7}7To: \u{00a7}fto@example.test", None).unwrap()
        );
        assert_eq!(
            summary[5],
            chat_packet("\u{00a7}7Body: \u{00a7}f2 page(s)", None).unwrap()
        );

        let clear = authenticated_command_packets(
            "/clear",
            &configured,
            &mut draft,
            None,
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(
            clear.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x02, 0x33, 0x33, 0x33, 0x33, 0x2f]
        );
        assert!(draft.to.is_empty());
        assert!(draft.cc.is_empty());
        assert!(draft.bcc.is_empty());
        assert!(draft.subject.is_empty());
        assert!(draft.body_pages.is_empty());
    }

    #[test]
    fn main_menu_payload_and_window_id_cycle_are_bounded() {
        let packets = main_menu_packets(1, RenderSettings::default()).unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0][0], 0x2d);
        assert_eq!(packets[0].len(), 47);
        assert_eq!(packets[1][0], 0x30);
        assert_eq!(packets[1][1], 1);
        assert_eq!(i16::from_be_bytes([packets[1][2], packets[1][3]]), 90);
        assert_eq!(packets[1].len(), 2771);

        let service = StatusService::new(&config(Duration::from_secs(30))).unwrap();
        for expected in 1..=100 {
            assert_eq!(service.next_window_id(), expected);
        }
        assert_eq!(service.next_window_id(), 1);
    }

    #[test]
    fn main_menu_click_and_close_packets_match_the_protocol_lifecycle() {
        let mut encoded_click = vec![1];
        encoded_click.extend_from_slice(&0_i16.to_be_bytes());
        encoded_click.push(0);
        encoded_click.extend_from_slice(&7_i16.to_be_bytes());
        encoded_click.push(0);
        encoded_click.extend_from_slice(&(-1_i16).to_be_bytes());
        let mut reader = PacketReader::new(&encoded_click);
        let click = read_window_click(&mut reader).unwrap();
        assert_eq!(click.window_id, 1);
        assert_eq!(click.slot, 0);
        assert_eq!(click.action_number, 7);
        assert_eq!(click.mode, 0);
        assert_eq!(reader.cursor, encoded_click.len());

        let (responses, effect) =
            main_menu_click_packets(click, None, RenderSettings::default()).unwrap();
        assert_eq!(effect, MainMenuEffect::None);
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0], [0x32, 1, 0, 7, 0]);
        assert_eq!(responses[1], [0x2f, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            responses[2],
            main_menu_contents_packet(1, RenderSettings::default()).unwrap()
        );

        let restored = restore_hotbar_packets().unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0][..6], [0x2f, 0, 0, 36, 1, 130]);
        assert_eq!(restored[1][..6], [0x2f, 0, 0, 44, 1, 143]);
    }

    #[test]
    fn synchronous_main_menu_actions_close_or_switch_state_after_base_refresh() {
        let (help, help_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 1,
                slot: 30,
                action_number: 11,
                mode: 0,
            },
            None,
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(help_effect, MainMenuEffect::Close);
        assert_eq!(
            help.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [
                0x32, 0x2f, 0x30, 0x2e, 0x2f, 0x2f, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
            ]
        );

        let (close, close_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 2,
                slot: 49,
                action_number: 12,
                mode: 0,
            },
            None,
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(close_effect, MainMenuEffect::Close);
        assert_eq!(close.len(), 6);

        let (switch, switch_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 3,
                slot: 32,
                action_number: 13,
                mode: 0,
            },
            None,
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(switch_effect, MainMenuEffect::SwitchAccount);
        assert_eq!(switch.len(), 7);
        assert_eq!(switch[6][0], 0x02);

        let (mode_only, mode_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 4,
                slot: 30,
                action_number: 14,
                mode: 1,
            },
            None,
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(mode_effect, MainMenuEffect::None);
        assert_eq!(mode_only.len(), 3);
    }

    #[test]
    fn logout_confirmation_cancel_and_confirm_have_complete_bounded_flows() {
        let (open, open_effect) = main_menu_click_packets(
            WindowClick {
                window_id: 1,
                slot: 34,
                action_number: 21,
                mode: 0,
            },
            Some(2),
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(open_effect, MainMenuEffect::OpenLogoutConfirm(2));
        assert_eq!(
            open.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x32, 0x2f, 0x30, 0x2f, 0x2f, 0x2d, 0x30]
        );
        assert_eq!(open[6], logout_confirmation_contents_packet(2).unwrap());

        let (cancel, cancel_effect) = logout_confirmation_click_packets(
            WindowClick {
                window_id: 2,
                slot: 15,
                action_number: 22,
                mode: 0,
            },
            Some(3),
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(cancel_effect, LogoutConfirmEffect::OpenMainMenu(3));
        assert_eq!(
            cancel.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x32, 0x2f, 0x30, 0x2e, 0x2f, 0x2f, 0x2d, 0x30]
        );

        let (confirm, confirm_effect) = logout_confirmation_click_packets(
            WindowClick {
                window_id: 4,
                slot: 11,
                action_number: 24,
                mode: 0,
            },
            None,
            RenderSettings::default(),
        )
        .unwrap();
        assert_eq!(confirm_effect, LogoutConfirmEffect::Disconnect);
        assert_eq!(
            confirm.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [0x32, 0x2f, 0x30, 0x2e, 0x2f, 0x2f, 0x40]
        );
        assert_eq!(
            confirm[6],
            disconnect_play_packet("\u{00a7}aLogged out. See you!").unwrap()
        );
    }

    #[test]
    fn render_settings_menu_and_editor_have_the_complete_protocol_flow() {
        let settings = RenderSettings::default();
        let (packets, effect) = main_menu_click_packets(
            WindowClick {
                window_id: 1,
                slot: 22,
                action_number: 31,
                mode: 0,
            },
            None,
            settings,
        )
        .unwrap();
        assert_eq!(effect, MainMenuEffect::OpenRenderSettings);
        assert_eq!(
            packets.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [
                0x32, 0x2f, 0x30, 0x2e, 0x2f, 0x2f, 0x35, 0x36, 0x02, 0x02, 0x02, 0x02
            ]
        );
        assert_eq!(packets[2], main_menu_contents_packet(1, settings).unwrap());
        assert_eq!(&packets[6][..10], &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        assert_eq!(packets[7], [0x36, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn render_settings_updates_match_java_validation_and_partial_font_commit() {
        let draft = MinecraftDraft::default();
        let mut settings = RenderSettings::default();
        let update = |lines: [&str; 4]| UpdateSign {
            lines: lines.map(str::to_owned),
        };

        let valid = render_settings_update_packets(
            update([
                r#"{"text":"24"}"#,
                r#"{"text":"20"}"#,
                r#"{"text":"48"}"#,
                r#"{"text":"W H Font"}"#,
            ]),
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
            &draft,
        )
        .unwrap();
        assert_eq!(
            settings,
            RenderSettings {
                maps_x: 24,
                maps_y: 20,
                font_size: 48,
            }
        );
        assert_eq!(
            valid.iter().map(|packet| packet[0]).collect::<Vec<_>>(),
            [
                0x02, 0x3b, 0x3b, 0x3d, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c, 0x3c,
                0x33, 0x33, 0x33, 0x33
            ]
        );

        let invalid_width = render_settings_update_packets(
            update(["1", "20", "48", ""]),
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
            &draft,
        )
        .unwrap();
        assert_eq!(settings.maps_x, 24);
        assert_eq!(
            invalid_width
                .iter()
                .map(|packet| packet[0])
                .collect::<Vec<_>>(),
            [0x02, 0x33, 0x33, 0x33, 0x33]
        );

        let invalid_height = render_settings_update_packets(
            update(["24", "21", "48", ""]),
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
            &draft,
        )
        .unwrap();
        assert_eq!(settings.maps_y, 20);
        assert_eq!(invalid_height.len(), 5);

        let invalid_font = render_settings_update_packets(
            update(["12", "8", "49", ""]),
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
            &draft,
        )
        .unwrap();
        assert_eq!(
            settings,
            RenderSettings {
                maps_x: 12,
                maps_y: 8,
                font_size: 48,
            }
        );
        assert_eq!(invalid_font[0][0], 0x02);
        assert_eq!(invalid_font[1][0], 0x02);
        assert_eq!(invalid_font.len(), 19);

        let non_integer = render_settings_update_packets(
            update(["twelve", "8", "48", ""]),
            &mut settings,
            "BlackboxLogin",
            "qa@example.test",
            &draft,
        )
        .unwrap();
        assert_eq!(settings.maps_x, 12);
        assert_eq!(non_integer.len(), 5);
    }

    #[test]
    fn update_sign_parser_enforces_four_bounded_utf16_lines() {
        fn encoded(lines: [&str; 4]) -> Vec<u8> {
            let mut packet = 0_i64.to_be_bytes().to_vec();
            for line in lines {
                write_string(&mut packet, line).unwrap();
            }
            packet
        }

        let ascii_limit = "a".repeat(UPDATE_SIGN_LINE_MAX_UTF16_UNITS);
        let within = encoded([&ascii_limit, "", "", ""]);
        let mut reader = PacketReader::new(&within);
        assert!(read_update_sign(&mut reader).is_ok());
        assert_eq!(reader.cursor, within.len());

        let ascii_over = "a".repeat(UPDATE_SIGN_LINE_MAX_UTF16_UNITS + 1);
        assert!(
            read_update_sign(&mut PacketReader::new(&encoded([&ascii_over, "", "", ""]))).is_err()
        );

        let supplementary_limit = "\u{1f600}".repeat(UPDATE_SIGN_LINE_MAX_UTF16_UNITS / 2);
        assert!(
            read_update_sign(&mut PacketReader::new(&encoded([
                &supplementary_limit,
                "",
                "",
                ""
            ])))
            .is_ok()
        );
        let supplementary_over = format!("{supplementary_limit}\u{1f600}");
        assert!(
            read_update_sign(&mut PacketReader::new(&encoded([
                &supplementary_over,
                "",
                "",
                ""
            ])))
            .is_err()
        );

        let mut truncated = encoded(["24", "20", "48", ""]);
        truncated.pop();
        assert!(read_update_sign(&mut PacketReader::new(&truncated)).is_err());
    }

    #[test]
    fn draft_sign_lines_match_java_utf16_substring_replacement() {
        let split_pair = format!("{}\u{1f600}x", "a".repeat(14));
        assert_eq!(
            split_sign_lines(&split_pair),
            [
                format!("{}?", "a".repeat(14)),
                "?x".to_owned(),
                String::new()
            ]
        );
        assert_eq!(
            split_sign_lines(&"b".repeat(46)),
            ["b".repeat(15), "b".repeat(15), "b".repeat(15)]
        );
    }

    #[test]
    fn click_slot_parser_skips_bounded_nbt_and_rejects_truncation() {
        let mut encoded_click = vec![1];
        encoded_click.extend_from_slice(&0_i16.to_be_bytes());
        encoded_click.push(0);
        encoded_click.extend_from_slice(&7_i16.to_be_bytes());
        encoded_click.push(0);
        encoded_click.extend_from_slice(&386_i16.to_be_bytes());
        encoded_click.push(1);
        encoded_click.extend_from_slice(&0_i16.to_be_bytes());
        minecraft_world::write_nbt(Some(&book_item_nbt()), &mut encoded_click).unwrap();

        let mut reader = PacketReader::new(&encoded_click);
        let click = read_window_click(&mut reader).unwrap();
        assert_eq!(click.window_id, 1);
        assert_eq!(reader.cursor, encoded_click.len());

        encoded_click.pop();
        assert!(read_window_click(&mut PacketReader::new(&encoded_click)).is_err());
    }

    #[test]
    fn configured_status_preserves_java_motd_and_favicon_rules() {
        let mut configured = config(Duration::from_secs(30));
        configured.max_players = 42;
        configured.motd = "quoted \\\"status\\\"".to_owned();
        configured.favicon = "  cGl4ZWw=  ".to_owned();
        assert_eq!(
            status_json(&configured),
            "{\"version\":{\"name\":\"1.8.9\",\"protocol\":47},\"players\":{\"max\":42,\"online\":0,\"sample\":[]},\"description\":{\"text\":\"quoted \\\\\\\"status\\\\\\\"\"},\"favicon\":\"data:image/png;base64,cGl4ZWw=\"}"
        );
    }

    #[test]
    fn login_rejection_frames_match_frozen_java_wire() {
        let service = StatusService::new(&config(Duration::from_secs(30))).unwrap();
        assert_eq!(
            service.blacklist_frame.as_ref(),
            STANDARD
                .decode("OwA5eyJ0ZXh0IjoiWW91IGFyZSBiYW5uZWQgZnJvbSB0aGlzIHNlcnZlci4iLCJjb2xvciI6InJlZCJ9")
                .unwrap()
        );
        assert_eq!(
            service.whitelist_frame.as_ref(),
            STANDARD
                .decode("MwAxeyJ0ZXh0IjoiWW91IGFyZSBub3Qgd2hpdGVsaXN0ZWQuIiwiY29sb3IiOiJyZWQifQ==")
                .unwrap()
        );
    }

    #[test]
    fn admission_uses_java_unicode_simple_case_comparison() {
        assert!(java_equals_ignore_case("\u{c4}User", "\u{e4}user"));
        assert!(java_equals_ignore_case("\u{130}", "i"));
        assert!(java_equals_ignore_case("\u{3a3}", "\u{3c2}"));
        assert!(!java_equals_ignore_case("\u{df}", "ss"));
    }

    #[test]
    fn encryption_request_uses_protocol_47_x509_and_four_byte_token() {
        let mut configured = config(Duration::from_secs(3));
        configured.online_mode = true;
        let online = OnlineModeService::new(&configured).unwrap();
        let token = [1, 2, 3, 4];
        let frame = encryption_request_frame(&online.public_key_der, &token).unwrap();
        let mut outer = PacketReader::new(&frame);
        let length = outer.read_varint().unwrap() as usize;
        assert_eq!(length, frame.len() - outer.cursor);
        let mut packet = PacketReader::new(&frame[outer.cursor..]);
        assert_eq!(packet.read_varint().unwrap(), 1);
        assert_eq!(packet.read_string(20).unwrap(), "");
        let der = packet.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES).unwrap();
        assert_eq!(der.as_slice(), online.public_key_der.as_ref());
        assert!(PKey::public_key_from_der(&der).is_ok());
        assert_eq!(
            packet.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES).unwrap(),
            token
        );
        assert_eq!(packet.cursor, packet.bytes.len());
    }

    #[tokio::test]
    async fn rsa_response_requires_matching_token_and_aes_128_secret() {
        let mut configured = config(Duration::from_secs(3));
        configured.online_mode = true;
        let online = OnlineModeService::new(&configured).unwrap();
        let public_key = PKey::public_key_from_der(&online.public_key_der)
            .unwrap()
            .rsa()
            .unwrap();
        let secret = *b"0123456789abcdef";
        let token = [9, 8, 7, 6];
        let mut encrypted_secret = vec![0_u8; public_key.size() as usize];
        let secret_len = public_key
            .public_encrypt(&secret, &mut encrypted_secret, Padding::PKCS1)
            .unwrap();
        encrypted_secret.truncate(secret_len);
        let mut encrypted_token = vec![0_u8; public_key.size() as usize];
        let token_len = public_key
            .public_encrypt(&token, &mut encrypted_token, Padding::PKCS1)
            .unwrap();
        encrypted_token.truncate(token_len);
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        assert_eq!(
            decrypt_online_response(
                &online,
                encrypted_secret.clone(),
                encrypted_token.clone(),
                token,
                deadline,
                &cancellation,
            )
            .await
            .unwrap(),
            secret
        );
        assert!(matches!(
            decrypt_online_response(
                &online,
                encrypted_secret,
                encrypted_token,
                [0; VERIFY_TOKEN_BYTES],
                deadline,
                &cancellation,
            )
            .await,
            Err(ProtocolError::Malformed)
        ));
    }

    #[tokio::test]
    async fn online_login_switches_to_aes_and_uses_bounded_session_fixture() {
        let profile_uuid = "0123456789abcdef0123456789abcdef";
        let profile_body = format!(r#"{{"id":"{profile_uuid}","name":"OnlineUser"}}"#);
        let (fixture_address, request_receiver, fixture_task) =
            start_session_fixture(200, profile_body, Duration::ZERO).await;
        let mut configured = config(Duration::from_secs(5));
        configured.online_mode = true;
        configured.session_server_url =
            format!("http://{fixture_address}/session/minecraft/hasJoined");
        let (address, cancellation, server_task) = start_server_with_config(8, configured).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(&handshake(address.port(), 2))
            .await
            .unwrap();
        client.write_all(&login_start(b"OnlineUser")).await.unwrap();

        let io_cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let request = read_frame(&mut client, None, deadline, &io_cancellation)
            .await
            .unwrap()
            .unwrap();
        let mut request = PacketReader::new(&request);
        assert_eq!(request.read_varint().unwrap(), 1);
        assert_eq!(request.read_string(20).unwrap(), "");
        let public_key_der = request.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES).unwrap();
        let verify_token = request.read_byte_array(ENCRYPTION_FIELD_MAX_BYTES).unwrap();
        assert_eq!(verify_token.len(), VERIFY_TOKEN_BYTES);

        let secret = *b"0123456789abcdef";
        let mut response = vec![0x01];
        write_byte_array(&mut response, &rsa_encrypt(&public_key_der, &secret)).unwrap();
        write_byte_array(&mut response, &rsa_encrypt(&public_key_der, &verify_token)).unwrap();
        client
            .write_all(&encode_frame(&response).unwrap())
            .await
            .unwrap();

        let mut client_cipher = MinecraftCipher::new(&secret).unwrap();
        let set_compression = read_frame(
            &mut client,
            Some(&mut client_cipher),
            deadline,
            &io_cancellation,
        )
        .await
        .unwrap()
        .unwrap();
        let mut set_compression = PacketReader::new(&set_compression);
        assert_eq!(set_compression.read_varint().unwrap(), 3);
        assert_eq!(set_compression.read_varint().unwrap(), 256);

        let login_success = read_frame(
            &mut client,
            Some(&mut client_cipher),
            deadline,
            &io_cancellation,
        )
        .await
        .unwrap()
        .unwrap();
        let mut envelope = PacketReader::new(&login_success);
        assert_eq!(envelope.read_varint().unwrap(), 0);
        let mut login_success = PacketReader::new(&login_success[envelope.cursor..]);
        assert_eq!(login_success.read_varint().unwrap(), 2);
        assert_eq!(
            login_success.read_string(36).unwrap(),
            "01234567-89ab-cdef-0123-456789abcdef"
        );
        assert_eq!(login_success.read_string(16).unwrap(), "OnlineUser");

        let request = request_receiver.await.unwrap();
        let request = String::from_utf8(request).unwrap();
        let request_line = request.lines().next().unwrap();
        assert!(
            request_line
                .starts_with("GET /session/minecraft/hasJoined?username=OnlineUser&serverId=")
        );
        let hash = request_line
            .split("serverId=")
            .nth(1)
            .unwrap()
            .split_ascii_whitespace()
            .next()
            .unwrap();
        assert!(!hash.is_empty());
        assert!(
            hash.bytes()
                .all(|byte| byte == b'-' || byte.is_ascii_hexdigit())
        );

        cancellation.cancel();
        timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        fixture_task.await.unwrap();
    }

    #[tokio::test]
    async fn session_fixture_errors_are_bounded_and_stable() {
        async fn run_case(
            status: u16,
            body: String,
            response_delay: Duration,
            request_budget: Duration,
        ) -> String {
            let (fixture_address, request_receiver, fixture_task) =
                start_session_fixture(status, body, response_delay).await;
            let mut configured = config(Duration::from_secs(5));
            configured.online_mode = true;
            configured.session_server_url = format!("http://{fixture_address}/hasJoined");
            let online = OnlineModeService::new(&configured).unwrap();
            let cancellation = CancellationToken::new();
            let error = authenticate_online(
                &online,
                "OnlineUser",
                b"0123456789abcdef",
                Instant::now() + request_budget,
                &cancellation,
            )
            .await
            .unwrap_err();
            request_receiver.await.unwrap();
            fixture_task.await.unwrap();
            error.message
        }

        assert_eq!(
            run_case(204, String::new(), Duration::ZERO, Duration::from_secs(2)).await,
            "Session not found"
        );
        assert_eq!(
            run_case(200, "{}".to_owned(), Duration::ZERO, Duration::from_secs(2)).await,
            "Auth server error: invalid response"
        );
        assert_eq!(
            run_case(
                200,
                "x".repeat(MAX_AUTH_RESPONSE_BYTES + 1),
                Duration::ZERO,
                Duration::from_secs(2)
            )
            .await,
            "Auth server error: response exceeded byte limit"
        );
        assert_eq!(
            run_case(
                200,
                r#"{"id":"0123456789abcdef0123456789abcdef","name":"OnlineUser"}"#.to_owned(),
                Duration::from_millis(200),
                Duration::from_millis(40)
            )
            .await,
            "Auth server error: request timed out"
        );
    }

    #[test]
    fn aes_cfb8_stream_state_survives_fragmentation() {
        let secret = *b"0123456789abcdef";
        let mut sender = MinecraftCipher::new(&secret).unwrap();
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(sender.encrypt(b"first-").unwrap());
        ciphertext.extend_from_slice(sender.encrypt(b"second-payload").unwrap());

        let mut receiver = MinecraftCipher::new(&secret).unwrap();
        let mut first = ciphertext[..3].to_vec();
        let mut second = ciphertext[3..11].to_vec();
        let mut third = ciphertext[11..].to_vec();
        receiver.decrypt_in_place(&mut first).unwrap();
        receiver.decrypt_in_place(&mut second).unwrap();
        receiver.decrypt_in_place(&mut third).unwrap();
        first.extend_from_slice(&second);
        first.extend_from_slice(&third);
        assert_eq!(first, b"first-second-payload");
    }

    #[test]
    fn signed_server_hash_matches_java_big_integer_hex_rules() {
        assert_eq!(signed_hex(&[0]), "0");
        assert_eq!(signed_hex(&[0, 0x0f]), "f");
        assert_eq!(signed_hex(&[0x7f]), "7f");
        assert_eq!(signed_hex(&[0x80]), "-80");
        assert_eq!(signed_hex(&[0xff]), "-1");
        assert_eq!(signed_hex(&[0xff, 0]), "-100");
    }

    #[test]
    fn joined_profile_validation_is_strict_and_canonical() {
        assert_eq!(
            normalize_joined_uuid("0123456789ABCDEF0123456789ABCDEF").as_deref(),
            Some("01234567-89ab-cdef-0123-456789abcdef")
        );
        assert_eq!(
            normalize_joined_uuid("01234567-89ab-cdef-0123-456789abcdef").as_deref(),
            Some("01234567-89ab-cdef-0123-456789abcdef")
        );
        assert!(normalize_joined_uuid("--0123456789abcdef0123456789abcdef").is_none());
        assert!(valid_online_name("Player_1"));
        assert!(!valid_online_name("player-name"));
        assert!(!valid_online_name("12345678901234567"));
    }

    #[test]
    fn java_utf8_replacement_consumes_the_frozen_malformed_lengths() {
        assert_eq!(decode_java_utf8(b"valid").unwrap(), "valid");
        assert_eq!(decode_java_utf8(&[0xed, 0xa0, 0x80]).unwrap(), "\u{fffd}");
        assert_eq!(decode_java_utf8(&[0xe2, 0x82, b'A']).unwrap(), "\u{fffd}A");
        assert_eq!(
            decode_java_utf8(&[0xe0, 0x80, 0x80]).unwrap(),
            "\u{fffd}\u{fffd}\u{fffd}"
        );
        assert_eq!(
            decode_java_utf8(&[0xf0, 0x80, 0x80, 0x80]).unwrap(),
            "\u{fffd}\u{fffd}\u{fffd}\u{fffd}"
        );
        assert_eq!(
            decode_java_utf8(&[0xf0, 0x90, 0x80, b'A']).unwrap(),
            "\u{fffd}A"
        );
        assert_eq!(decode_java_utf8(&[0xe2, 0x82]).unwrap(), "\u{fffd}");
        assert_eq!(
            decode_java_utf8(&[0xf0, 0x9f, 0x92, 0xa9]).unwrap(),
            "\u{1f4a9}"
        );
    }

    #[test]
    fn duplicate_uuid_status_is_unique_and_old_disconnect_is_fenced() {
        let service = StatusService::new(&config(Duration::from_secs(30))).unwrap();
        let old = service.register_online("same-uuid".to_owned());
        assert_eq!(
            service
                .online_sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );
        let current = service.register_online("same-uuid".to_owned());
        assert_eq!(
            service
                .online_sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );
        drop(old);
        assert_eq!(
            service
                .online_sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );
        drop(current);
        assert!(
            service
                .online_sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn login_admission_matches_frozen_rejections_and_username_bound() {
        let mut configured = config(Duration::from_secs(3));
        configured.whitelist_enabled = true;
        configured.whitelist_players = vec!["AllowedUser".to_owned(), "BlockedUser".to_owned()];
        configured.blacklist_players = vec!["BlockedUser".to_owned()];
        let (address, cancellation, task) = start_server_with_config(8, configured).await;

        for (username, expected) in [
            (
                b"blockeduser".as_slice(),
                "OwA5eyJ0ZXh0IjoiWW91IGFyZSBiYW5uZWQgZnJvbSB0aGlzIHNlcnZlci4iLCJjb2xvciI6InJlZCJ9",
            ),
            (
                b"OtherUser".as_slice(),
                "MwAxeyJ0ZXh0IjoiWW91IGFyZSBub3Qgd2hpdGVsaXN0ZWQuIiwiY29sb3IiOiJyZWQifQ==",
            ),
        ] {
            let mut client = TcpStream::connect(address).await.unwrap();
            client
                .write_all(&handshake(address.port(), 2))
                .await
                .unwrap();
            client.write_all(&login_start(username)).await.unwrap();
            let expected = STANDARD.decode(expected).unwrap();
            let mut actual = vec![0_u8; expected.len()];
            client.read_exact(&mut actual).await.unwrap();
            assert_eq!(actual, expected);
            let mut trailing = [0_u8; 1];
            assert_eq!(client.read(&mut trailing).await.unwrap(), 0);
        }

        let mut allowed = TcpStream::connect(address).await.unwrap();
        allowed
            .write_all(&handshake(address.port(), 2))
            .await
            .unwrap();
        allowed
            .write_all(&login_start(b"alloweduser"))
            .await
            .unwrap();
        let mut compression_prefix = [0_u8; 4];
        allowed.read_exact(&mut compression_prefix).await.unwrap();
        assert_eq!(compression_prefix, [3, 3, 0x80, 2]);

        let mut overlong = Vec::new();
        overlong.extend_from_slice(&handshake(address.port(), 2));
        overlong.extend_from_slice(&login_start(b"12345678901234567"));
        assert_closed_without_response(address, &overlong).await;

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn fragmented_handshake_status_and_ping_match_protocol_47() {
        let (address, cancellation, task) = start_server(8, Duration::from_secs(3)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        for byte in handshake(address.port(), 1) {
            client.write_all(&[byte]).await.unwrap();
        }
        client.write_all(&[1, 0]).await.unwrap();
        let expected = STANDARD.decode(FROZEN_STATUS_FRAME).unwrap();
        let mut actual = vec![0_u8; expected.len()];
        client.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);

        client
            .write_all(&[9, 1, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
            .await
            .unwrap();
        let mut pong = [0_u8; 10];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(pong, [9, 1, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let mut trailing = [0_u8; 1];
        assert_eq!(client.read(&mut trailing).await.unwrap(), 0);

        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn malformed_lengths_and_invalid_state_close_silently() {
        let (address, cancellation, task) = start_server(8, Duration::from_secs(3)).await;
        for payload in [
            handshake(address.port(), 3),
            vec![0xff, 0xff, 0xff, 0xff, 0x0f],
            {
                let mut value = Vec::new();
                write_varint(&mut value, MAX_FRAME_LENGTH as u32 + 1);
                value
            },
            vec![0x80, 0x80, 0x80, 0x80, 0x80],
        ] {
            assert_closed_without_response(address, &payload).await;
        }
        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn empty_frames_unknown_packets_and_trailing_bytes_are_ignored() {
        let (address, cancellation, task) = start_server(8, Duration::from_secs(3)).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[0]).await.unwrap();
        client
            .write_all(&encode_frame(&[7]).unwrap())
            .await
            .unwrap();
        client
            .write_all(&handshake(address.port(), 1))
            .await
            .unwrap();
        client
            .write_all(&encode_frame(&[2, 0xaa, 0xbb]).unwrap())
            .await
            .unwrap();
        client
            .write_all(&encode_frame(&[0, 0xcc]).unwrap())
            .await
            .unwrap();

        let expected = STANDARD.decode(FROZEN_STATUS_FRAME).unwrap();
        let mut actual = vec![0_u8; expected.len()];
        client.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);

        let ping = [1, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xdd];
        client
            .write_all(&encode_frame(&ping).unwrap())
            .await
            .unwrap();
        let mut pong = [0_u8; 10];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(pong, [9, 1, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn admission_is_bounded_and_cancellation_drains_partial_reads() {
        let (address, cancellation, task) = start_server(1, Duration::from_secs(30)).await;
        let mut admitted = TcpStream::connect(address).await.unwrap();
        admitted.write_all(&[0x80]).await.unwrap();
        sleep(Duration::from_millis(50)).await;

        let mut rejected = TcpStream::connect(address).await.unwrap();
        let _ = rejected.write_all(&handshake(address.port(), 1)).await;
        let mut byte = [0_u8; 1];
        let rejected_read = timeout(Duration::from_secs(1), rejected.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(rejected_read, Ok(0))
                || matches!(rejected_read, Err(ref error) if connection_ended(error))
        );

        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("Minecraft listener did not drain after cancellation")
            .unwrap()
            .unwrap();
        let admitted_read = timeout(Duration::from_secs(1), admitted.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(admitted_read, Ok(0))
                || matches!(admitted_read, Err(ref error) if connection_ended(error))
        );
    }

    #[tokio::test]
    async fn connection_deadline_is_absolute_across_fragmented_input() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let server_cancellation = cancellation.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut service = StatusService::new(&config(Duration::from_secs(1))).unwrap();
            service.connection_timeout = Duration::from_millis(150);
            handle_connection(
                stream,
                Arc::new(service),
                server_cancellation,
                Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
                Instant::now() + Duration::from_millis(150),
            )
            .await
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&[0x80]).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        let _ = client.write_all(&[0x80]).await;
        let started = Instant::now();
        let mut byte = [0_u8; 1];
        let result = timeout(Duration::from_millis(500), client.read(&mut byte))
            .await
            .expect("absolute Minecraft deadline was extended by partial reads");
        assert!(
            matches!(result, Ok(0)) || matches!(result, Err(ref error) if connection_ended(error))
        );
        assert!(started.elapsed() < Duration::from_millis(350));
        server.await.unwrap().unwrap();
    }

    #[test]
    fn offline_uuid_matches_frozen_java_name_uuid() {
        assert_eq!(
            offline_uuid("BlackboxLogin").unwrap(),
            "fba9f5f2-955e-359f-ae31-9d00075473c2"
        );
        assert_eq!(
            offline_uuid("\u{fffd}").unwrap(),
            "7f21183c-0ff2-3465-9df0-9ca82956deb0"
        );
    }

    #[tokio::test]
    async fn offline_login_prefix_matches_frozen_java_frames() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);

        let mut login_success = vec![0x02];
        write_string(&mut login_success, "fba9f5f2-955e-359f-ae31-9d00075473c2").unwrap();
        write_string(&mut login_success, "BlackboxLogin").unwrap();
        let login_frame =
            encode_packet_frame(&service, login_success, Some(256), deadline, &cancellation)
                .await
                .unwrap();
        assert_eq!(
            login_frame,
            STANDARD
                .decode("NQACJGZiYTlmNWYyLTk1NWUtMzU5Zi1hZTMxLTlkMDAwNzU0NzNjMg1CbGFja2JveExvZ2lu")
                .unwrap()
        );

        let expected = [
            "EwABAAAAAAIAABQHZGVmYXVsdAA=",
            "AwBBAA==",
            "CgAFAAAAAoAAAAA=",
            "CwA5BT1MzM09zMzN",
            "EgADAAAAAAAAAAD////////okA==",
            "CwAGQaAAABRAoAAA",
            "AwAJAA==",
        ];
        for (packet, frozen) in initial_play_packets(0, &config(Duration::from_secs(3)))
            .unwrap()
            .into_iter()
            .zip(expected)
        {
            let frame = encode_packet_frame(&service, packet, Some(256), deadline, &cancellation)
                .await
                .unwrap();
            assert_eq!(frame, STANDARD.decode(frozen).unwrap());
        }
    }

    #[tokio::test]
    async fn static_play_bootstrap_matches_frozen_java_frames() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        let expected = [
            "KAA4AAGLpuWQOgE1I75xDynrcJc1D1N0YXRpY1BsYXlQcm9iZQACAAA=",
            "ewBHKHsidGV4dCI6IsKnNsKnbExNWVpNQUlMIiwiY29sb3IiOiJnb2xkIn1PeyJ0ZXh0Ijoiwqc3U2VuZCBlbWFpbHMgaW4gTWluZWNyYWZ0ISBTa2liaWRpIGRvcCBkb3AgeWVzIHllcyEiLCJjb2xvciI6ImdyYXkifQ==",
            "DwBFAgAAAAoAAAA8AAAAFA==",
            "GgBFABZ7InRleHQiOiLCpzZMTVlaTUFJTCJ9",
            "PwBFATt7InRleHQiOiLCpzdUeXBlIHlvdXIgZW1haWwgdG8gZ2V0IHN0YXJ0ZWQiLCJjb2xvciI6ImdyYXkifQ==",
            "UgACTnsidGV4dCI6IsKnZcKnbD09PSBXZWxjb21lIHRvIExNWVpNQUlMIE1pbmVjcmFmdCBTZXJ2ZXIgPT09IiwiY29sb3IiOiJ5ZWxsb3cifQA=",
            "RQACQXsidGV4dCI6IsKnN1NlbmQgZW1haWxzIGRpcmVjdGx5IGZyb20gTWluZWNyYWZ0ISIsImNvbG9yIjoiZ3JheSJ9AA==",
            "DwACC3sidGV4dCI6IiJ9AA==",
            "QgACPnsidGV4dCI6IsKnYVBsZWFzZSBlbnRlciB5b3VyIGVtYWlsIGFkZHJlc3M6IiwiY29sb3IiOiJncmVlbiJ9AA==",
            "HQAvAAAkAYIBAAAKAAAJAAVwYWdlcwgAAAABAAAA",
            "jAEALwAALAGPAQAACgAACgAHZGlzcGxheQgABE5hbWUAG8KnNsKnbE1lbnUgwqc3KFJpZ2h0IENsaWNrKQkABExvcmUIAAAAAQAVwqc3T3BlbiB0aGUgbWFpbiBtZW51AAkABGVuY2gKAAAAAQIAAmlkAAACAANsdmwAAQADAAlIaWRlRmxhZ3MAAAA/AA==",
        ];
        let packets =
            static_play_packets("8ba6e590-3a01-3523-be71-0f29eb709735", "StaticPlayProbe").unwrap();
        assert_eq!(packets.len(), expected.len());
        for (packet, frozen) in packets.into_iter().zip(expected) {
            let frame = encode_packet_frame(&service, packet, Some(256), deadline, &cancellation)
                .await
                .unwrap();
            assert_eq!(frame, STANDARD.decode(frozen).unwrap());
        }
    }

    #[tokio::test]
    async fn post_static_play_bootstrap_matches_frozen_java_frames() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        let expected = [
            "QQAzAAAAgoQAAAMSeyJ0ZXh0IjoiwqcxW1RvXSJ9C3sidGV4dCI6IiJ9C3sidGV4dCI6IiJ9C3sidGV4dCI6IiJ9",
            "QQAzAAABAoQAAAMSeyJ0ZXh0IjoiwqcxW0NDXSJ9C3sidGV4dCI6IiJ9C3sidGV4dCI6IiJ9C3sidGV4dCI6IiJ9",
            "QgAzAAABgoQAAAMTeyJ0ZXh0IjoiwqcxW0JDQ10ifQt7InRleHQiOiIifQt7InRleHQiOiIifQt7InRleHQiOiIifQ==",
            "RgAzAAACAoQAAAMXeyJ0ZXh0IjoiwqcxW1N1YmplY3RdIn0LeyJ0ZXh0IjoiIn0LeyJ0ZXh0IjoiIn0LeyJ0ZXh0IjoiIn0=",
            "HQA7BGxteXoADsKnNsKnbExNWVpNQUlMBWR1bW15",
            "CAA9AQRsbXl6",
            "IAAPoPc2HgAAABAAABRgAAAAEAAAAAAAAAAAAAAgCgl/",
            "GAAcoPc2gg7CpzbCp2xMTVlaTUFJTAMBfw==",
            "IAAPofc2HgAAABAAABROAAAAEAAAAAAAAAAAAAAgCgl/",
            "KwAcofc2giHCpzdNaW5lY3JhZnQgU2tpYmlkaSBFbWFpbCBTZXJ2ZXIDAX8=",
            "IAAPovc2HgAAABAAABQ8AAAAEAAAAAAAAAAAAAAgCgl/",
            "NQAcovc2givCpzdieSDCp2VsbXl6enogdGhlIGdyZWF0IHNraWJpZGkgc2NpZW50aXN0AwF/",
            "IAAPo/c2HgAAABAAABQrAAAAEAAAAAAAAAAAAAAgCgl/",
            "CwAco/c2ggEgAwF/",
            "IAAPpPc2HgAAABAAABQZAAAAEAAAAAAAAAAAAAAgCgl/",
            "PAAcpPc2gjLCp2VIb2xkIMKnZk5ldGhlciBTdGFyIMKnZSsgUmlnaHQtY2xpY2sgLT4gwqdmTWVudQMBfw==",
            "IAAPpfc2HgAAABAAABQIAAAAEAAAAAAAAAAAAAAgCgl/",
            "NgAcpfc2gizCp2VXcml0ZSBpbiDCp2ZCb29rICYgUXVpbGwgwqdlLT4gRW1haWwgYm9keQMBfw==",
            "IAAPpvc2HgAAABAAABP2AAAAEAAAAAAAAAAAAAAgCgl/",
            "NwAcpvc2gi3Cp2VDbGljayDCp2ZTaWduIEJ1dHRvbnMgwqdlLT4gU2V0IFRvL1N1YmplY3QDAX8=",
        ];
        let packets = post_static_play_packets(900_000).unwrap();
        assert_eq!(packets.len(), expected.len());
        for (packet, frozen) in packets.into_iter().zip(expected) {
            let frame = encode_packet_frame(&service, packet, Some(256), deadline, &cancellation)
                .await
                .unwrap();
            assert_eq!(frame, STANDARD.decode(frozen).unwrap());
        }
    }

    #[test]
    fn scheduled_play_packets_match_protocol_fields() {
        let time_update = time_update_packet();
        let mut expected_time_update = vec![0x03];
        expected_time_update.extend_from_slice(&0_i64.to_be_bytes());
        expected_time_update.extend_from_slice(&(-6000_i64).to_be_bytes());
        assert_eq!(time_update, expected_time_update);

        let packets = hologram_teleport_packets(900_000);
        assert_eq!(packets.len(), 7);
        for (index, packet) in packets.into_iter().enumerate() {
            let mut expected = vec![0x18];
            write_varint(&mut expected, 900_000 + index as u32);
            expected.extend_from_slice(&16_i32.to_be_bytes());
            expected
                .extend_from_slice(&(((163.0 - index as f64 * 0.55) * 32.0) as i32).to_be_bytes());
            expected.extend_from_slice(&16_i32.to_be_bytes());
            expected.extend_from_slice(&[0, 0, 0]);
            assert_eq!(packet, expected);
        }

        let mut configured = config(Duration::from_secs(3));
        configured.spawn.x = -12.75;
        configured.spawn.y = 70.9;
        configured.spawn.z = 34.5;
        configured.spawn.yaw = 45.0;
        configured.spawn.pitch = -15.0;
        let packets = teleport_back_packets(&configured).unwrap();
        assert_eq!(packets.len(), 2);
        let mut expected_position = vec![0x08];
        expected_position.extend_from_slice(&configured.spawn.x.to_be_bytes());
        expected_position.extend_from_slice(&configured.spawn.y.to_be_bytes());
        expected_position.extend_from_slice(&configured.spawn.z.to_be_bytes());
        expected_position.extend_from_slice(&configured.spawn.yaw.to_be_bytes());
        expected_position.extend_from_slice(&configured.spawn.pitch.to_be_bytes());
        expected_position.push(0);
        assert_eq!(packets[0], expected_position);

        let mut expected_chat = vec![0x02];
        write_string(
            &mut expected_chat,
            &chat_json("\u{00a7}cYou were teleported back to spawn!", Some("red")),
        )
        .unwrap();
        expected_chat.push(0);
        assert_eq!(packets[1], expected_chat);
    }

    #[test]
    fn player_position_parser_rejects_truncated_packets() {
        let mut position = Vec::new();
        position.extend_from_slice(&1.0_f64.to_be_bytes());
        position.extend_from_slice(&2.0_f64.to_be_bytes());
        position.extend_from_slice(&3.0_f64.to_be_bytes());
        position.push(1);
        assert_eq!(
            read_player_position(&mut PacketReader::new(&position), 0x04).unwrap(),
            (1.0, 2.0, 3.0)
        );
        assert!(
            read_player_position(
                &mut PacketReader::new(&position[..position.len() - 1]),
                0x04
            )
            .is_err()
        );

        let mut position_and_look = position;
        position_and_look.pop();
        position_and_look.extend_from_slice(&45.0_f32.to_be_bytes());
        position_and_look.extend_from_slice(&(-15.0_f32).to_be_bytes());
        position_and_look.push(0);
        assert_eq!(
            read_player_position(&mut PacketReader::new(&position_and_look), 0x06).unwrap(),
            (1.0, 2.0, 3.0)
        );
        assert!(
            read_player_position(
                &mut PacketReader::new(&position_and_look[..position_and_look.len() - 1]),
                0x06
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn awaiting_email_prompts_match_frozen_java_frames_and_trim_rules() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);

        let (email, invalid) = awaiting_email_responses("not-an-email").unwrap();
        assert_eq!(email, None);
        let (email, valid) = awaiting_email_responses("  qa@example.test  ").unwrap();
        assert_eq!(email.as_deref(), Some("qa@example.test"));

        let expected = [
            "RwACQ3sidGV4dCI6IsKnY0ludmFsaWQgZW1haWwgZm9ybWF0LiBQbGVhc2UgdHJ5IGFnYWluOiIsImNvbG9yIjoicmVkIn0A",
            "KwACJ3sidGV4dCI6IsKnYUVtYWlsOiDCp2ZxYUBleGFtcGxlLnRlc3QifQA=",
            "PQACOXsidGV4dCI6IsKnYVBsZWFzZSBlbnRlciB5b3VyIHBhc3N3b3JkOiIsImNvbG9yIjoiZ3JlZW4ifQA=",
            "RAACQHsidGV4dCI6IsKnNyhZb3VyIHBhc3N3b3JkIHdpbGwgbm90IGJlIHZpc2libGUpIiwiY29sb3IiOiJncmF5In0A",
        ];
        for (packet, frozen) in invalid.into_iter().chain(valid).zip(expected) {
            let frame = encode_packet_frame(&service, packet, Some(256), deadline, &cancellation)
                .await
                .unwrap();
            assert_eq!(frame, STANDARD.decode(frozen).unwrap());
        }

        assert_eq!(awaiting_email_responses("\t \r\n").unwrap().0, None);
        assert_eq!(
            awaiting_email_responses("\u{00a0}qa@example.test\u{00a0}")
                .unwrap()
                .0
                .as_deref(),
            Some("\u{00a0}qa@example.test\u{00a0}")
        );

        let mut overlong = Vec::new();
        write_varint(&mut overlong, 101);
        overlong.extend_from_slice(&[b'x'; 101]);
        assert!(PacketReader::new(&overlong).read_string(100).is_err());

        let supplementary = "\u{1f600}".repeat(51);
        let mut supplementary_packet = Vec::new();
        write_string(&mut supplementary_packet, &supplementary).unwrap();
        assert!(
            PacketReader::new(&supplementary_packet)
                .read_string(100)
                .is_err()
        );
    }

    #[test]
    fn static_play_uuid_and_json_inputs_are_strict_and_escaped() {
        assert_eq!(
            parse_uuid_bytes("01234567-89AB-cdef-0123-456789abcdef"),
            Some([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ])
        );
        assert!(parse_uuid_bytes("01234567-89ab-cdef-0123-456789abcdeg").is_none());
        assert!(parse_uuid_bytes("0123456789abcdef0123456789abcde").is_none());
        assert_eq!(
            chat_json("quote=\" slash=\\", Some("gray")),
            r#"{"text":"quote=\" slash=\\","color":"gray"}"#
        );
        assert!(static_play_packets("not-a-uuid", "Player").is_err());
    }

    #[test]
    fn hologram_entity_ids_are_reserved_per_process() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        assert_eq!(service.reserve_hologram_entity_ids(7), 900_000);
        assert_eq!(service.reserve_hologram_entity_ids(7), 900_007);
    }

    #[tokio::test]
    async fn compression_envelope_is_exact_and_bounded() {
        let service = StatusService::new(&config(Duration::from_secs(3))).unwrap();
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(3);

        let packet = vec![0x5a; 256];
        let compressed = compress_packet(packet.clone(), &cancellation, deadline).unwrap();
        let mut envelope = Vec::new();
        write_varint(&mut envelope, packet.len() as u32);
        envelope.extend_from_slice(&compressed);
        assert_eq!(
            decode_compression_envelope(&service, envelope.clone(), 256, deadline, &cancellation,)
                .await
                .unwrap(),
            packet
        );

        envelope.push(0);
        assert!(matches!(
            decode_compression_envelope(&service, envelope, 256, deadline, &cancellation).await,
            Err(ProtocolError::Malformed)
        ));

        let mut uncompressed_at_threshold = vec![0];
        uncompressed_at_threshold.extend_from_slice(&vec![0x5a; 256]);
        assert!(matches!(
            decode_compression_envelope(
                &service,
                uncompressed_at_threshold,
                256,
                deadline,
                &cancellation,
            )
            .await,
            Err(ProtocolError::Malformed)
        ));

        let mut oversized = Vec::new();
        write_varint(&mut oversized, MAX_FRAME_LENGTH as u32 + 1);
        oversized.push(0);
        assert!(matches!(
            decode_compression_envelope(&service, oversized, 256, deadline, &cancellation).await,
            Err(ProtocolError::Malformed)
        ));

        let mut negative = Vec::new();
        write_varint(&mut negative, u32::MAX);
        negative.push(0);
        assert!(matches!(
            decode_compression_envelope(&service, negative, 256, deadline, &cancellation).await,
            Err(ProtocolError::Malformed)
        ));

        let short_packet = vec![0x5a; 128];
        let short_compressed = compress_packet(short_packet, &cancellation, deadline).unwrap();
        let mut below_threshold = Vec::new();
        write_varint(&mut below_threshold, 128);
        below_threshold.extend_from_slice(&short_compressed);
        assert!(matches!(
            decode_compression_envelope(&service, below_threshold, 256, deadline, &cancellation,)
                .await,
            Err(ProtocolError::Malformed)
        ));

        let mut truncated = Vec::new();
        write_varint(&mut truncated, 256);
        truncated.extend_from_slice(&compressed[..compressed.len() - 1]);
        assert!(matches!(
            decode_compression_envelope(&service, truncated, 256, deadline, &cancellation).await,
            Err(ProtocolError::Malformed)
        ));

        let mut mismatched = Vec::new();
        write_varint(&mut mismatched, 257);
        mismatched.extend_from_slice(&compressed);
        assert!(matches!(
            decode_compression_envelope(&service, mismatched, 1, deadline, &cancellation).await,
            Err(ProtocolError::Malformed)
        ));
    }

    #[test]
    fn compression_workers_observe_cancellation_and_deadline() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            compress_packet(
                vec![0; COMPRESSION_CHUNK_BYTES * 2],
                &cancellation,
                Instant::now() + Duration::from_secs(1),
            ),
            Err(ProtocolError::Cancelled)
        ));
        let active = CancellationToken::new();
        assert!(matches!(
            compress_packet(vec![0; 1], &active, Instant::now()),
            Err(ProtocolError::TimedOut)
        ));
    }

    #[test]
    fn configured_spawn_position_uses_java_integer_cast_and_wire_packing() {
        let mut configured = config(Duration::from_secs(3));
        configured.spawn.x = -12.75;
        configured.spawn.y = 70.9;
        configured.spawn.z = 34.5;
        let packets = initial_play_packets(1, &configured).unwrap();
        let expected_packed = ((i64::from(-12_i32) & 0x3ff_ffff) << 38)
            | ((i64::from(70_i32) & 0xfff) << 26)
            | (i64::from(34_i32) & 0x3ff_ffff);
        let mut expected = vec![0x05];
        expected.extend_from_slice(&expected_packed.to_be_bytes());
        assert_eq!(packets[2], expected);
    }

    proptest! {
        #[test]
        fn packet_reader_never_panics_on_arbitrary_frames(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let mut packet = PacketReader::new(&bytes);
            let _ = packet.read_varint();
            let _ = packet.read_string(255);
            let _ = packet.read_u16();
            let _ = packet.read_i64();
            prop_assert!(packet.cursor <= bytes.len());

            let mut click = PacketReader::new(&bytes);
            let _ = read_window_click(&mut click);
            prop_assert!(click.cursor <= bytes.len());

            let mut sign = PacketReader::new(&bytes);
            let _ = read_update_sign(&mut sign);
            prop_assert!(sign.cursor <= bytes.len());
        }
    }
}
