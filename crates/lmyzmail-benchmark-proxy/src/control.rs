use crate::observer::{ObserverHub, PersistenceSnapshotEvidence, RoundSpec};
use crate::proxy::ProxyTelemetry;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

pub(crate) const MAX_CONTROL_CLIENTS: usize = 16;
pub(crate) const MAX_CONTROL_LINE_BYTES: usize = 64 * 1024;
// Covers the request Vec, BufReader, decoded strings, response Value/Vec, and
// conservative socket/task/allocator overhead while all copies coexist.
const CONTROL_CLIENT_ACCOUNTED_BYTES: usize = 384 * 1024;
const CONTROL_SERVER_ACCOUNTED_BYTES: usize = 256 * 1024;
const CONTROL_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const PROXY_STOP_TIMEOUT: Duration = Duration::from_secs(305);

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum ControlCommand {
    Begin {
        run_id: String,
        expected_messages: usize,
        message_bytes: usize,
        #[serde(default)]
        persistence_gate_required: bool,
        #[serde(default = "default_sender")]
        expected_sender: String,
        #[serde(default = "default_receiver")]
        expected_receiver: String,
    },
    Summary {},
    Wait {
        timeout_millis: u64,
    },
    WaitPersistenceGate {
        timeout_millis: u64,
    },
    ReleasePersistenceGate {
        gate_id: u64,
        snapshot: PersistenceSnapshotEvidence,
    },
    AbortPersistenceGate {
        gate_id: u64,
        reason: String,
    },
    Finish {},
    Shutdown {},
}

impl ControlCommand {
    fn requests_shutdown(&self) -> bool {
        matches!(self, Self::Shutdown {})
    }
}

pub(crate) fn accounted_control_reserve_bytes() -> Result<usize, String> {
    MAX_CONTROL_CLIENTS
        .checked_mul(CONTROL_CLIENT_ACCOUNTED_BYTES)
        .and_then(|value| value.checked_add(CONTROL_SERVER_ACCOUNTED_BYTES))
        .ok_or_else(|| "control runtime reserve accounting overflowed".to_owned())
}

fn default_sender() -> String {
    crate::observer::DEFAULT_SENDER.to_owned()
}

fn default_receiver() -> String {
    crate::observer::DEFAULT_RECEIVER.to_owned()
}

pub async fn serve_control(
    path: PathBuf,
    observer: ObserverHub,
    telemetry: Arc<ProxyTelemetry>,
    proxy_shutdown_tx: watch::Sender<bool>,
    control_shutdown_tx: watch::Sender<bool>,
    mut control_shutdown_rx: watch::Receiver<bool>,
    proxy_stopped_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    validate_control_path(&path)?;
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let metadata = std::fs::metadata(&path)?;
    let owner_uid = metadata.uid();
    let _socket_guard = SocketPathGuard {
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let permits = Arc::new(Semaphore::new(MAX_CONTROL_CLIENTS));
    let mut clients = JoinSet::new();
    loop {
        let permit = tokio::select! {
            changed = control_shutdown_rx.changed() => {
                if changed.is_err() || *control_shutdown_rx.borrow() {
                    break;
                }
                continue;
            }
            permit = permits.clone().acquire_owned() => {
                permit.map_err(|_| io::Error::other("control connection semaphore closed"))?
            }
        };
        let accepted = tokio::select! {
            changed = control_shutdown_rx.changed() => {
                drop(permit);
                if changed.is_err() || *control_shutdown_rx.borrow() {
                    break;
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (stream, _) = accepted?;
        if stream.peer_cred()?.uid() != owner_uid {
            drop(permit);
            observer.mark_failure("rejected benchmark control connection from a different UID");
            continue;
        }
        let client_observer = observer.clone();
        let telemetry = telemetry.clone();
        let proxy_shutdown_tx = proxy_shutdown_tx.clone();
        let control_shutdown_tx = control_shutdown_tx.clone();
        let client_shutdown_rx = control_shutdown_rx.clone();
        let proxy_stopped_rx = proxy_stopped_rx.clone();
        clients.spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_control(
                stream,
                client_observer.clone(),
                telemetry,
                proxy_shutdown_tx,
                control_shutdown_tx,
                client_shutdown_rx,
                proxy_stopped_rx,
            )
            .await
            {
                client_observer.mark_failure(format!("benchmark control protocol failed: {error}"));
            }
        });
        while let Some(result) = clients.try_join_next() {
            if let Err(error) = result {
                observer.mark_failure(format!("benchmark control task failed: {error}"));
            }
        }
    }
    drop(listener);
    let deadline = tokio::time::Instant::now() + CONTROL_SHUTDOWN_GRACE;
    loop {
        match tokio::time::timeout_at(deadline, clients.join_next()).await {
            Ok(Some(Ok(()))) => {}
            Ok(Some(Err(error))) => observer.mark_failure(format!(
                "benchmark control task failed during shutdown: {error}"
            )),
            Ok(None) => break,
            Err(_) => {
                observer.mark_failure(format!(
                    "benchmark control clients exceeded {CONTROL_SHUTDOWN_GRACE:?} shutdown grace"
                ));
                clients.abort_all();
                while clients.join_next().await.is_some() {}
                break;
            }
        }
    }
    Ok(())
}

async fn handle_control(
    stream: UnixStream,
    observer: ObserverHub,
    telemetry: Arc<ProxyTelemetry>,
    proxy_shutdown_tx: watch::Sender<bool>,
    control_shutdown_tx: watch::Sender<bool>,
    mut control_shutdown_rx: watch::Receiver<bool>,
    mut proxy_stopped_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::with_capacity(8 * 1024, reader);
    loop {
        let line = tokio::select! {
            changed = control_shutdown_rx.changed() => {
                if changed.is_err() || *control_shutdown_rx.borrow() {
                    return Ok(());
                }
                continue;
            }
            line = read_bounded_line(&mut reader, MAX_CONTROL_LINE_BYTES) => line?,
        };
        let Some(line) = line else {
            return Ok(());
        };
        let command: ControlCommand = match serde_json::from_slice(&line) {
            Ok(command) => command,
            Err(error) => {
                observer.mark_failure(format!("invalid benchmark control JSON: {error}"));
                write_response(
                    &mut writer,
                    &json!({"ok": false, "error": format!("invalid control JSON: {error}")}),
                )
                .await?;
                continue;
            }
        };
        let request_shutdown = command.requests_shutdown();
        let shutdown_guard =
            request_shutdown.then(|| ControlShutdownGuard::armed(control_shutdown_tx.clone()));
        let (response, request_shutdown) = execute_command(
            command,
            &observer,
            &telemetry,
            &proxy_shutdown_tx,
            &mut proxy_stopped_rx,
        )
        .await;
        debug_assert_eq!(request_shutdown, shutdown_guard.is_some());
        write_response(&mut writer, &response).await?;
        if request_shutdown {
            drop(shutdown_guard);
            return Ok(());
        }
    }
}

async fn execute_command(
    command: ControlCommand,
    observer: &ObserverHub,
    telemetry: &ProxyTelemetry,
    shutdown_tx: &watch::Sender<bool>,
    proxy_stopped_rx: &mut watch::Receiver<bool>,
) -> (Value, bool) {
    match command {
        ControlCommand::Begin {
            run_id,
            expected_messages,
            message_bytes,
            persistence_gate_required,
            expected_sender,
            expected_receiver,
        } => match observer.begin_with_persistence_gate(
            RoundSpec {
                run_id,
                expected_messages,
                message_bytes,
                expected_sender,
                expected_receiver,
            },
            persistence_gate_required,
        ) {
            Ok(ack) => (json!({"ok": true, "begin": ack}), false),
            Err(error) => (json!({"ok": false, "error": error}), false),
        },
        ControlCommand::Summary {} => match observer.summary() {
            Ok(round) => (
                json!({"ok": true, "round": round, "proxy": telemetry.snapshot()}),
                false,
            ),
            Err(error) => (json!({"ok": false, "error": error}), false),
        },
        ControlCommand::Wait { timeout_millis } => {
            let timeout_millis = timeout_millis.min(24 * 60 * 60 * 1_000);
            let reached = observer
                .wait_until_expected(Duration::from_millis(timeout_millis))
                .await;
            match observer.summary() {
                Ok(round) => (
                    json!({
                        "ok": true,
                        "reached_expected": reached,
                        "round": round,
                        "proxy": telemetry.snapshot(),
                    }),
                    false,
                ),
                Err(error) => (json!({"ok": false, "error": error}), false),
            }
        }
        ControlCommand::WaitPersistenceGate { timeout_millis } => {
            let timeout_millis = timeout_millis.min(24 * 60 * 60 * 1_000);
            match observer
                .wait_for_persistence_gate(Duration::from_millis(timeout_millis))
                .await
            {
                Ok(gate) => (json!({"ok": true, "persistence_gate": gate}), false),
                Err(error) => (json!({"ok": false, "error": error}), false),
            }
        }
        ControlCommand::ReleasePersistenceGate { gate_id, snapshot } => {
            match observer.release_persistence_gate(gate_id, snapshot) {
                Ok(gate) => (json!({"ok": true, "persistence_gate": gate}), false),
                Err(error) => (json!({"ok": false, "error": error}), false),
            }
        }
        ControlCommand::AbortPersistenceGate { gate_id, reason } => {
            match observer.abort_persistence_gate(gate_id, reason) {
                Ok(()) => (json!({"ok": true, "aborted": true}), false),
                Err(error) => (json!({"ok": false, "error": error}), false),
            }
        }
        ControlCommand::Finish {} => {
            if let Err(error) = stop_proxy(shutdown_tx, proxy_stopped_rx).await {
                return (json!({"ok": false, "error": error}), false);
            }
            let snapshot = telemetry.snapshot();
            match observer.finalize() {
                Ok(round) => (
                    json!({"ok": true, "round": round, "proxy": snapshot}),
                    false,
                ),
                Err(error) => (
                    json!({"ok": false, "error": error, "proxy": snapshot}),
                    false,
                ),
            }
        }
        ControlCommand::Shutdown {} => {
            if let Err(error) = stop_proxy(shutdown_tx, proxy_stopped_rx).await {
                return (json!({"ok": false, "error": error}), true);
            }
            (json!({"ok": true, "proxy": telemetry.snapshot()}), true)
        }
    }
}

async fn stop_proxy(
    shutdown_tx: &watch::Sender<bool>,
    proxy_stopped_rx: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    if *proxy_stopped_rx.borrow_and_update() {
        return Ok(());
    }
    shutdown_tx
        .send(true)
        .map_err(|_| "proxy shutdown receiver disappeared".to_owned())?;
    let stopped = async {
        loop {
            if *proxy_stopped_rx.borrow_and_update() {
                return Ok(());
            }
            proxy_stopped_rx
                .changed()
                .await
                .map_err(|_| "proxy stopped signal disappeared".to_owned())?;
        }
    };
    tokio::time::timeout(PROXY_STOP_TIMEOUT, stopped)
        .await
        .map_err(|_| {
            "proxy did not close its listener and connections before deadline".to_owned()
        })?
}

async fn read_bounded_line<R>(reader: &mut R, maximum: usize) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut output = Vec::with_capacity(1_024);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if output.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "control request ended before newline",
                ))
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if output.len().saturating_add(take) > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control request exceeded fixed line limit",
            ));
        }
        output.extend_from_slice(&available[..take]);
        reader.consume(take);
        if output.last() == Some(&b'\n') {
            output.pop();
            if output.last() == Some(&b'\r') {
                output.pop();
            }
            return Ok(Some(output));
        }
    }
}

async fn write_response<W>(writer: &mut W, value: &Value) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut encoded = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if encoded
        .len()
        .checked_add(1)
        .is_none_or(|length| length > MAX_CONTROL_LINE_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control response exceeded fixed line limit",
        ));
    }
    encoded.push(b'\n');
    writer.write_all(&encoded).await
}

struct ControlShutdownGuard {
    shutdown_tx: watch::Sender<bool>,
}

impl ControlShutdownGuard {
    fn armed(shutdown_tx: watch::Sender<bool>) -> Self {
        Self { shutdown_tx }
    }
}

impl Drop for ControlShutdownGuard {
    fn drop(&mut self) {
        self.shutdown_tx.send_replace(true);
    }
}

fn validate_control_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control socket path must be absolute",
        ));
    }
    if path.as_os_str().len() > 100 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control socket path is too long for a Unix socket",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "control socket has no parent")
    })?;
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "control socket parent does not exist",
        ));
    }
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "control socket path already exists",
        ));
    }
    Ok(())
}

struct SocketPathGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::metadata(&self.path) else {
            return;
        };
        if metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.file_type().is_socket()
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, BufReader};

    #[tokio::test]
    async fn bounded_line_reader_accepts_fragmented_input() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            writer.write_all(b"{\"command\":").await.unwrap();
            writer.write_all(b"\"summary\"}\n").await.unwrap();
        });
        let mut reader = BufReader::new(reader);
        let value = read_bounded_line(&mut reader, 64).await.unwrap().unwrap();
        task.await.unwrap();
        assert_eq!(value, br#"{"command":"summary"}"#);
    }

    #[tokio::test]
    async fn bounded_line_reader_rejects_oversize_without_growth() {
        let (mut writer, reader) = tokio::io::duplex(128);
        let task = tokio::spawn(async move {
            writer.write_all(&[b'x'; 65]).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
        });
        let mut reader = BufReader::new(reader);
        let error = read_bounded_line(&mut reader, 64).await.unwrap_err();
        task.await.unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn stop_waits_for_listener_and_connection_join_acknowledgement() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (stopped_tx, mut stopped_rx) = watch::channel(false);
        let stop = tokio::spawn(async move { stop_proxy(&shutdown_tx, &mut stopped_rx).await });
        shutdown_rx.changed().await.unwrap();
        assert!(*shutdown_rx.borrow());
        assert!(!stop.is_finished());
        stopped_tx.send(true).unwrap();
        stop.await.unwrap().unwrap();
    }

    #[test]
    fn control_commands_reject_unknown_fields() {
        let error =
            serde_json::from_slice::<ControlCommand>(br#"{"command":"summary","unexpected":true}"#)
                .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn finish_stops_the_data_plane_without_terminating_control() {
        assert!(!ControlCommand::Finish {}.requests_shutdown());
        assert!(ControlCommand::Shutdown {}.requests_shutdown());
    }

    #[tokio::test]
    async fn response_limit_includes_the_trailing_lf() {
        let json_overhead = br#"{"value":""}"#.len();
        let exact_payload = "x".repeat(MAX_CONTROL_LINE_BYTES - json_overhead - 1);
        let exact = json!({"value": exact_payload});
        let (mut client, mut server) = tokio::io::duplex(MAX_CONTROL_LINE_BYTES);
        let write = tokio::spawn(async move { write_response(&mut server, &exact).await });
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        write.await.unwrap().unwrap();
        assert_eq!(received.len(), MAX_CONTROL_LINE_BYTES);
        assert_eq!(received.last(), Some(&b'\n'));

        let oversize_payload = "x".repeat(MAX_CONTROL_LINE_BYTES - json_overhead);
        let oversize = json!({"value": oversize_payload});
        let mut sink = tokio::io::sink();
        let error = write_response(&mut sink, &oversize).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn maximum_legal_summary_fits_the_control_response_limit() {
        let limits = crate::observer::ObserverLimits {
            retained_samples: 16,
            retained_failures: 16,
            ..crate::observer::ObserverLimits::default()
        };
        let observer = ObserverHub::new(limits).unwrap();
        observer
            .begin(RoundSpec {
                run_id: "\0".repeat(256),
                expected_messages: 1,
                message_bytes: 1_024,
                expected_sender: crate::observer::DEFAULT_SENDER.to_owned(),
                expected_receiver: crate::observer::DEFAULT_RECEIVER.to_owned(),
            })
            .unwrap();
        for _ in 0..16 {
            observer.mark_failure("\0".repeat(4_096));
        }
        let value = json!({
            "ok": true,
            "round": observer.summary().unwrap(),
            "proxy": ProxyTelemetry::shared().snapshot(),
        });
        let encoded = serde_json::to_vec(&value).unwrap();
        assert!(
            encoded.len() < MAX_CONTROL_LINE_BYTES,
            "maximum legal response used {} bytes including LF",
            encoded.len() + 1
        );
    }

    #[test]
    fn armed_shutdown_guard_signals_on_drop() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        drop(ControlShutdownGuard::armed(shutdown_tx));
        assert!(*shutdown_rx.borrow());
    }
}
