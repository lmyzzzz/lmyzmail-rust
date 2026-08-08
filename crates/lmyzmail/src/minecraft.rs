use std::{io, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::config::{MinecraftConfig, RuntimeConfig};

const MAX_FRAME_LENGTH: usize = 2 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 64;
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(20);
const ACCEPT_RETRY_MIN: Duration = Duration::from_millis(25);
const ACCEPT_RETRY_MAX: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionState {
    Handshake,
    Status,
}

#[derive(Debug)]
enum ProtocolError {
    Cancelled,
    TimedOut,
    Malformed,
    Io(io::Error),
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

struct StatusService {
    status_frame: Arc<[u8]>,
    connection_timeout: Duration,
}

impl StatusService {
    fn new(config: &MinecraftConfig) -> io::Result<Self> {
        let json = status_json(config);
        let mut payload = Vec::new();
        payload.try_reserve_exact(json.len() + 6).map_err(|error| {
            io::Error::other(format!("Minecraft status allocation failed: {error}"))
        })?;
        write_varint(&mut payload, 0);
        write_varint(&mut payload, json.len() as u32);
        payload.extend_from_slice(json.as_bytes());
        let status_frame = encode_frame(&payload)?;
        Ok(Self {
            status_frame: status_frame.into(),
            connection_timeout: Duration::from_secs(config.read_timeout_seconds),
        })
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
    mut stream: TcpStream,
    service: Arc<StatusService>,
    cancellation: CancellationToken,
    _permit: OwnedSemaphorePermit,
    deadline: Instant,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let mut state = ConnectionState::Handshake;

    loop {
        let frame = match read_frame(&mut stream, deadline, &cancellation).await {
            Ok(Some(frame)) => frame,
            Ok(None)
            | Err(ProtocolError::Cancelled | ProtocolError::TimedOut | ProtocolError::Malformed) => {
                return Ok(());
            }
            Err(ProtocolError::Io(error)) if connection_ended(&error) => return Ok(()),
            Err(ProtocolError::Io(error)) => return Err(error),
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
                    Ok(_) | Err(_) => return Ok(()),
                }
            }
            ConnectionState::Status => match packet_id {
                0 => {
                    if let Err(error) =
                        write_bytes(&mut stream, &service.status_frame, deadline, &cancellation)
                            .await
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
                        write_bytes(&mut stream, &pong, deadline, &cancellation).await
                    {
                        return finish_write_error(error);
                    }
                    let _ = tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => Ok(()),
                        result = timeout_at(deadline, stream.shutdown()) => result
                            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Minecraft shutdown timed out"))?,
                    };
                    return Ok(());
                }
                _ => {}
            },
        }
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

async fn read_frame(
    stream: &mut TcpStream,
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
                    let read =
                        read_with_deadline(stream, &mut frame[cursor..], deadline, cancellation)
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

async fn read_with_deadline(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<usize, ProtocolError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProtocolError::Cancelled),
        result = timeout_at(deadline, stream.read(buffer)) => match result {
            Ok(result) => result.map_err(ProtocolError::Io),
            Err(_) => Err(ProtocolError::TimedOut),
        },
    }
}

async fn write_bytes(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), ProtocolError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProtocolError::Cancelled),
        result = timeout_at(deadline, stream.write_all(bytes)) => match result {
            Ok(result) => result.map_err(ProtocolError::Io),
            Err(_) => Err(ProtocolError::TimedOut),
        },
    }
}

fn status_json(config: &MinecraftConfig) -> String {
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
        "{{\"version\":{{\"name\":\"1.8.9\",\"protocol\":47}},\"players\":{{\"max\":{},\"online\":0,\"sample\":[]}},\"description\":{{\"text\":\"{}\"}}{}}}",
        config.max_players, motd, favicon
    )
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
        let value = String::from_utf8_lossy(bytes).into_owned();
        if value.encode_utf16().count() > max_utf16_units {
            return Err(());
        }
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
    use tokio::time::sleep;

    const FROZEN_STATUS_FRAME: &str = "nAEAmQF7InZlcnNpb24iOnsibmFtZSI6IjEuOC45IiwicHJvdG9jb2wiOjQ3fSwicGxheWVycyI6eyJtYXgiOjIwLCJvbmxpbmUiOjAsInNhbXBsZSI6W119LCJkZXNjcmlwdGlvbiI6eyJ0ZXh0Ijoiwqc2TE1ZWk1BSUwgwqc3LSBTZW5kIGVtYWlscyBpbiBNaW5lY3JhZnQifX0=";

    fn config(timeout: Duration) -> MinecraftConfig {
        MinecraftConfig {
            enabled: true,
            max_players: 20,
            motd: "§6LMYZMAIL §7- Send emails in Minecraft".to_owned(),
            favicon: String::new(),
            read_timeout_seconds: timeout.as_secs().max(1),
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
            handle_connection(
                stream,
                Arc::new(StatusService {
                    status_frame: Arc::from([]),
                    connection_timeout: Duration::from_millis(150),
                }),
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
