use std::{
    collections::HashMap,
    io::{self, Write as _},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI32, AtomicU64, Ordering},
    },
    time::Duration,
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
use zeroize::Zeroize;

use crate::{
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
    next_connection_id: AtomicU64,
    online_sessions: Arc<Mutex<HashMap<String, u64>>>,
    world: Arc<WorldTemplate>,
    connection_timeout: Duration,
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
            next_connection_id: AtomicU64::new(1),
            online_sessions: Arc::new(Mutex::new(HashMap::with_capacity(MAX_CONNECTIONS))),
            world,
            connection_timeout: Duration::from_secs(config.read_timeout_seconds),
        })
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
    cancellation: CancellationToken,
) -> io::Result<()> {
    let listener =
        TcpListener::bind((config.listen.host.as_str(), config.listen.minecraft)).await?;
    let service = Arc::new(StatusService::new(&config.minecraft)?);
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
    let mut packets = Vec::with_capacity(20);
    for (x, label) in [
        (2, "\u{00a7}1[To]"),
        (4, "\u{00a7}1[CC]"),
        (6, "\u{00a7}1[BCC]"),
        (8, "\u{00a7}1[Subject]"),
    ] {
        let mut sign = vec![0x33];
        write_block_position(&mut sign, x, 161, 3);
        for text in [label, "", "", ""] {
            write_string(&mut sign, &chat_json(text, None))?;
        }
        packets.push(sign);
    }

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

    let mut chat = vec![0x02];
    write_string(
        &mut chat,
        &chat_json("\u{00a7}cYou were teleported back to spawn!", Some("red")),
    )?;
    chat.push(0);
    Ok(vec![position, chat])
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

    fn read_u8(&mut self) -> Result<u8, ()> {
        let value = *self.bytes.get(self.cursor).ok_or(())?;
        self.cursor += 1;
        Ok(value)
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
        }
    }
}
