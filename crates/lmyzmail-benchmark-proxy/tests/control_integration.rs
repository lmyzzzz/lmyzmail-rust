use lmyzmail_benchmark_proxy::{
    ObserverHub, ObserverLimits, ProxyConfig, ProxyServer, ProxyTelemetry, serve_control,
};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::watch;

fn localhost_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

async fn wait_for_path(path: &Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !path.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "control socket was not created"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn wait_for_listener_close(address: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if TcpStream::connect(address).await.is_err() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "proxy listener remained open after shutdown"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn exchange(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    request: Value,
) -> Value {
    writer
        .write_all(format!("{}\n", serde_json::to_string(&request).unwrap()).as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(
        !line.is_empty(),
        "control server closed before its response"
    );
    serde_json::from_str(&line).unwrap()
}

struct RunningStack {
    socket: PathBuf,
    proxy_addr: SocketAddr,
    proxy_shutdown: watch::Sender<bool>,
    proxy_stopped: watch::Receiver<bool>,
    control_shutdown: watch::Sender<bool>,
    proxy_task: tokio::task::JoinHandle<std::io::Result<()>>,
    control_task: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn start_stack(
    socket: PathBuf,
    backend: SocketAddr,
    observer: ObserverHub,
    telemetry: Arc<ProxyTelemetry>,
    max_connections: usize,
) -> RunningStack {
    let proxy = ProxyServer::bind(
        ProxyConfig {
            listen: localhost_ephemeral(),
            backend,
            max_connections,
            memory_budget_bytes: 256 * 1024 * 1024,
            shutdown_grace: Duration::from_secs(5),
        },
        observer.clone(),
        telemetry.clone(),
    )
    .await
    .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (proxy_shutdown, proxy_shutdown_rx) = watch::channel(false);
    let (proxy_stopped_tx, proxy_stopped) = watch::channel(false);
    let proxy_task = tokio::spawn(async move {
        let result = proxy.serve(proxy_shutdown_rx).await;
        proxy_stopped_tx.send_replace(true);
        result
    });
    let (control_shutdown, control_shutdown_rx) = watch::channel(false);
    let control_task = tokio::spawn(serve_control(
        socket.clone(),
        observer,
        telemetry,
        proxy_shutdown.clone(),
        control_shutdown.clone(),
        control_shutdown_rx,
        proxy_stopped.clone(),
    ));
    wait_for_path(&socket).await;
    RunningStack {
        socket,
        proxy_addr,
        proxy_shutdown,
        proxy_stopped,
        control_shutdown,
        proxy_task,
        control_task,
    }
}

async fn join_stack(stack: RunningStack) {
    tokio::time::timeout(Duration::from_secs(2), stack.control_task)
        .await
        .expect("control server did not stop")
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), stack.proxy_task)
        .await
        .expect("proxy server did not stop")
        .unwrap()
        .unwrap();
    assert!(*stack.proxy_stopped.borrow());
    assert!(!stack.socket.exists());
}

#[tokio::test]
async fn unix_control_returns_bounded_round_and_proxy_summaries() {
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("control.sock");
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    let telemetry = ProxyTelemetry::shared();
    let stack = start_stack(
        socket.clone(),
        backend.local_addr().unwrap(),
        observer,
        telemetry,
        16,
    )
    .await;
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let idle_stream = UnixStream::connect(&socket).await.unwrap();
    let (idle_reader, mut idle_writer) = idle_stream.into_split();
    let mut idle_reader = BufReader::new(idle_reader);
    let idle_ready = exchange(
        &mut idle_reader,
        &mut idle_writer,
        json!({"command": "summary"}),
    )
    .await;
    assert_eq!(idle_ready["ok"], false);

    let stream = UnixStream::connect(&socket).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let begin = exchange(
        &mut reader,
        &mut writer,
        json!({
            "command": "begin",
            "run_id": "control-integration",
            "expected_messages": 1,
            "message_bytes": 1024
        }),
    )
    .await;
    assert_eq!(begin["ok"], true);
    let second_begin = exchange(
        &mut reader,
        &mut writer,
        json!({
            "command": "begin",
            "run_id": "forbidden-second-round",
            "expected_messages": 1,
            "message_bytes": 1024
        }),
    )
    .await;
    assert_eq!(second_begin["ok"], false);
    let wait = exchange(
        &mut reader,
        &mut writer,
        json!({"command": "wait", "timeout_millis": 1}),
    )
    .await;
    assert_eq!(wait["ok"], true);
    assert_eq!(wait["reached_expected"], false);
    let summary = exchange(&mut reader, &mut writer, json!({"command": "summary"})).await;
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["round"]["expected"], 1);
    assert_eq!(summary["proxy"]["active_connections"], 0);
    assert_eq!(
        summary["proxy"]["backend_reply_block_limit_bytes"],
        128 * 1024
    );
    assert_eq!(
        summary["proxy"]["accounted_backend_reply_buffer_bytes"],
        128 * 1024
    );
    assert_eq!(summary["proxy"]["configured_max_connections"], 16);
    let accounted_connection_bytes = summary["proxy"]["accounted_connection_bytes"]
        .as_u64()
        .unwrap();
    let observer_reserve_bytes = summary["proxy"]["observer_round_reserve_bytes"]
        .as_u64()
        .unwrap();
    let control_reserve_bytes = summary["proxy"]["control_runtime_reserve_bytes"]
        .as_u64()
        .unwrap();
    let required_memory_budget_bytes = summary["proxy"]["required_memory_budget_bytes"]
        .as_u64()
        .unwrap();
    assert_eq!(
        required_memory_budget_bytes,
        accounted_connection_bytes * 16 + observer_reserve_bytes + control_reserve_bytes
    );
    assert_eq!(
        summary["proxy"]["memory_budget_headroom_bytes"]
            .as_u64()
            .unwrap(),
        summary["proxy"]["usable_memory_budget_bytes"]
            .as_u64()
            .unwrap()
            - required_memory_budget_bytes
    );
    assert!(
        summary["proxy"]["control_runtime_reserve_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        summary["proxy"]["peak_total_accounted_bytes"]
            .as_u64()
            .unwrap()
            <= summary["proxy"]["memory_budget_bytes"].as_u64().unwrap()
    );
    let finish = exchange(&mut reader, &mut writer, json!({"command": "finish"})).await;
    assert_eq!(finish["ok"], true);
    assert_eq!(finish["round"]["qualification"], false);
    let shutdown = exchange(&mut reader, &mut writer, json!({"command": "shutdown"})).await;
    assert_eq!(shutdown["ok"], true);
    drop(writer);
    drop(reader);
    drop(idle_writer);
    drop(idle_reader);
    join_stack(stack).await;
    drop(backend);
}

#[tokio::test]
async fn finish_waits_for_active_socket_join_and_reports_final_telemetry() {
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("control.sock");
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 held\r\n").await.unwrap();
        let mut discarded = Vec::new();
        stream.read_to_end(&mut discarded).await.unwrap();
    });
    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    let telemetry = ProxyTelemetry::shared();
    let stack = start_stack(socket.clone(), backend_addr, observer, telemetry, 1).await;

    let mut smtp = TcpStream::connect(stack.proxy_addr).await.unwrap();
    let mut greeting = [0_u8; 10];
    smtp.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 held\r\n");

    let control = UnixStream::connect(&socket).await.unwrap();
    let (reader, mut writer) = control.into_split();
    let mut reader = BufReader::new(reader);
    writer
        .write_all(b"{\"command\":\"finish\"}\n")
        .await
        .unwrap();
    let mut line = String::new();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), reader.read_line(&mut line))
            .await
            .is_err(),
        "finish responded before the active connection joined"
    );
    wait_for_listener_close(stack.proxy_addr).await;
    drop(smtp);
    backend_task.await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
        .await
        .expect("finish did not respond after the active connection drained")
        .unwrap();
    let finish: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(finish["ok"], false, "finish had no active observer round");
    assert_eq!(finish["proxy"]["accepted_connections"], 1);
    assert_eq!(finish["proxy"]["completed_connections"], 1);
    assert_eq!(finish["proxy"]["failed_connections"], 0);
    assert_eq!(finish["proxy"]["active_connections"], 0);
    assert_eq!(finish["proxy"]["peak_connections"], 1);
    let shutdown = exchange(&mut reader, &mut writer, json!({"command": "shutdown"})).await;
    assert_eq!(shutdown["ok"], true);
    drop(writer);
    drop(reader);
    join_stack(stack).await;
}

#[tokio::test]
async fn broken_pipe_finish_still_stops_proxy_and_control() {
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("control.sock");
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    let telemetry = ProxyTelemetry::shared();
    let stack = start_stack(
        socket.clone(),
        backend.local_addr().unwrap(),
        observer,
        telemetry,
        1,
    )
    .await;

    let stream = UnixStream::connect(&socket).await.unwrap();
    let stream = stream.into_std().unwrap();
    stream.shutdown(Shutdown::Read).unwrap();
    let mut stream = UnixStream::from_std(stream).unwrap();
    stream
        .write_all(b"{\"command\":\"finish\"}\n")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    drop(stream);
    wait_for_listener_close(stack.proxy_addr).await;
    let control = UnixStream::connect(&socket).await.unwrap();
    let (reader, mut writer) = control.into_split();
    let mut reader = BufReader::new(reader);
    let shutdown = exchange(&mut reader, &mut writer, json!({"command": "shutdown"})).await;
    assert_eq!(shutdown["ok"], true);
    drop(writer);
    drop(reader);
    join_stack(stack).await;
    drop(backend);
}

#[tokio::test]
async fn malformed_oversize_and_disconnected_clients_do_not_break_control() {
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("control.sock");
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    let telemetry = ProxyTelemetry::shared();
    let stack = start_stack(
        socket.clone(),
        backend.local_addr().unwrap(),
        observer,
        telemetry,
        1,
    )
    .await;

    let mut oversize = UnixStream::connect(&socket).await.unwrap();
    let bytes = vec![b'x'; 64 * 1024 + 1];
    let _ = oversize.write_all(&bytes).await;
    let _ = oversize.write_all(b"\n").await;
    drop(oversize);

    let malformed = UnixStream::connect(&socket).await.unwrap();
    let (reader, mut writer) = malformed.into_split();
    let mut reader = BufReader::new(reader);
    writer.write_all(b"not-json\n").await.unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["ok"], false);
    drop(writer);
    drop(reader);

    let mut disconnected = UnixStream::connect(&socket).await.unwrap();
    disconnected.write_all(b"{\"command\":").await.unwrap();
    drop(disconnected);

    let healthy = UnixStream::connect(&socket).await.unwrap();
    let (reader, mut writer) = healthy.into_split();
    let mut reader = BufReader::new(reader);
    let shutdown = exchange(&mut reader, &mut writer, json!({"command": "shutdown"})).await;
    assert_eq!(shutdown["ok"], true);
    drop(writer);
    drop(reader);
    join_stack(stack).await;
    drop(backend);
}

#[tokio::test]
async fn socket_cleanup_does_not_remove_a_replacement_file() {
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("control.sock");
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    let telemetry = ProxyTelemetry::shared();
    let stack = start_stack(
        socket.clone(),
        backend.local_addr().unwrap(),
        observer,
        telemetry,
        1,
    )
    .await;
    std::fs::remove_file(&socket).unwrap();
    std::fs::write(&socket, b"replacement").unwrap();
    stack.control_shutdown.send(true).unwrap();
    stack.proxy_shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), stack.control_task)
        .await
        .expect("control server did not stop")
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), stack.proxy_task)
        .await
        .expect("proxy server did not stop")
        .unwrap()
        .unwrap();
    assert!(*stack.proxy_stopped.borrow());
    assert_eq!(std::fs::read(&socket).unwrap(), b"replacement");
    drop(backend);
}
