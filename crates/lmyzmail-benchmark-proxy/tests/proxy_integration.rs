use lmyzmail_benchmark_proxy::{
    ObserverHub, ObserverLimits, PersistenceSnapshotEvidence, ProxyConfig, ProxyServer,
    ProxyTelemetry, RoundSpec,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Barrier, watch};

fn localhost_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn round_spec(expected: usize, message_bytes: usize) -> RoundSpec {
    RoundSpec {
        run_id: "proxy-integration".into(),
        expected_messages: expected,
        message_bytes,
        expected_sender: "stress-sender@lmyz.net".into(),
        expected_receiver: "stress-receiver@lmyz.net".into(),
    }
}

async fn start_proxy(
    backend: SocketAddr,
    observer: ObserverHub,
) -> (
    SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let telemetry = ProxyTelemetry::shared();
    let proxy = ProxyServer::bind(
        ProxyConfig {
            listen: localhost_ephemeral(),
            backend,
            max_connections: 16,
            memory_budget_bytes: 512 * 1024 * 1024,
            shutdown_grace: Duration::from_secs(5),
        },
        observer,
        telemetry,
    )
    .await
    .unwrap();
    let address = proxy.local_addr().unwrap();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(proxy.serve(shutdown_rx));
    (address, shutdown, task)
}

fn stress_message(index: usize, target: usize) -> Vec<u8> {
    let headers = format!(
        "From: stress-sender@lmyz.net\r\nTo: stress-receiver@lmyz.net\r\nSubject: Stress Test R1 #{index} - 1234\r\nMessage-ID: <integration-{index}@lmyz.net>\r\n\r\n"
    );
    assert!(headers.len() + 2 <= target);
    let mut message = headers.into_bytes();
    message.resize(target - 2, b'x');
    message.extend_from_slice(b"\r\n");
    message
}

fn qualified_snapshot(expected_messages: usize) -> PersistenceSnapshotEvidence {
    PersistenceSnapshotEvidence {
        clock_id: "CLOCK_MONOTONIC".into(),
        snapshot_started_monotonic_ns: 10,
        snapshot_completed_monotonic_ns: 20,
        postgres_query_duration_ns: 5,
        maildir_snapshot_duration_ns: 1,
        transaction_isolation: "repeatable_read".into(),
        transaction_read_only: true,
        postgres_before_rows: 0,
        postgres_rows: expected_messages as i64,
        postgres_expected_rows: expected_messages as i64,
        postgres_row_delta: expected_messages as i64,
        expected_messages,
        maildir_atomic_rename_publications: expected_messages,
        qualified: true,
    }
}

#[tokio::test]
async fn completed_round_forces_idle_keepalive_closed_without_losing_qualification() {
    let message = stress_message(0, 1_024);
    let command = format!(
        "MAIL FROM:<stress-sender@lmyz.net>\r\nRCPT TO:<stress-receiver@lmyz.net>\r\nBDAT {} LAST\r\n",
        message.len()
    );
    let mut wire = command.into_bytes();
    wire.extend_from_slice(&message);
    const REPLIES: &[u8] = b"250 mail\r\n250 rcpt\r\n250 accepted\r\n";

    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let expected_wire = wire.clone();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 keepalive\r\n").await.unwrap();
        let mut received = vec![0; expected_wire.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected_wire);
        stream.write_all(REPLIES).await.unwrap();
        let mut eof = [0_u8; 1];
        assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
    });

    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer.begin(round_spec(1, message.len())).unwrap();
    let telemetry = ProxyTelemetry::shared();
    let shutdown_grace = Duration::from_millis(25);
    let proxy = ProxyServer::bind(
        ProxyConfig {
            listen: localhost_ephemeral(),
            backend: backend_addr,
            max_connections: 1,
            memory_budget_bytes: 256 * 1024 * 1024,
            shutdown_grace,
        },
        observer.clone(),
        telemetry.clone(),
    )
    .await
    .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let proxy_task = tokio::spawn(proxy.serve(shutdown_rx));

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0_u8; 15];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 keepalive\r\n");
    client.write_all(&wire).await.unwrap();
    let mut replies = vec![0_u8; REPLIES.len()];
    client.read_exact(&mut replies).await.unwrap();
    assert_eq!(replies, REPLIES);
    assert!(
        observer.wait_until_expected(Duration::from_secs(1)).await,
        "observer did not reach the completed round before shutdown"
    );

    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    let mut eof = [0_u8; 1];
    assert!(matches!(client.read(&mut eof).await, Ok(0) | Err(_)));
    backend_task.await.unwrap();

    let summary = observer.finalize().unwrap();
    assert!(summary.qualification, "{summary:#?}");
    assert_eq!(summary.observer_failure_count, 0);
    let snapshot = telemetry.snapshot();
    assert!(snapshot.shutdown_grace_exceeded);
    assert_eq!(snapshot.shutdown_grace_ns, shutdown_grace.as_nanos() as u64);
    assert!(snapshot.shutdown_wait_ns >= snapshot.shutdown_grace_ns);
    assert_eq!(snapshot.shutdown_forced_connections, 1);
    assert_eq!(snapshot.active_connections, 0);
    assert_eq!(snapshot.failed_connections, 0);
}

#[tokio::test]
async fn incomplete_round_shutdown_timeout_remains_an_observer_failure() {
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 incomplete\r\n").await.unwrap();
        let mut eof = [0_u8; 1];
        assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
    });

    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer.begin(round_spec(1, 1_024)).unwrap();
    let telemetry = ProxyTelemetry::shared();
    let proxy = ProxyServer::bind(
        ProxyConfig {
            listen: localhost_ephemeral(),
            backend: backend_addr,
            max_connections: 1,
            memory_budget_bytes: 256 * 1024 * 1024,
            shutdown_grace: Duration::from_millis(10),
        },
        observer.clone(),
        telemetry.clone(),
    )
    .await
    .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let proxy_task = tokio::spawn(proxy.serve(shutdown_rx));

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0_u8; 16];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 incomplete\r\n");
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    backend_task.await.unwrap();

    let summary = observer.finalize().unwrap();
    assert!(!summary.qualification);
    assert_eq!(summary.observer_failure_count, 1);
    assert!(
        summary
            .observer_failures
            .iter()
            .any(|failure| failure.contains("shutdown grace"))
    );
    let snapshot = telemetry.snapshot();
    assert!(snapshot.shutdown_grace_exceeded);
    assert_eq!(snapshot.shutdown_forced_connections, 1);
    assert_eq!(snapshot.active_connections, 0);
}

#[tokio::test]
async fn concurrent_connections_cross_the_global_n_minus_one_and_n_gate_boundary() {
    let first = stress_message(0, 1_024);
    let second = stress_message(1, 1_024);
    let first_command = format!(
        "MAIL FROM:<stress-sender@lmyz.net>\r\nRCPT TO:<stress-receiver@lmyz.net>\r\nBDAT {} LAST\r\n",
        first.len()
    );
    let second_command = format!(
        "MAIL FROM:<stress-sender@lmyz.net>\r\nRCPT TO:<stress-receiver@lmyz.net>\r\nBDAT {} LAST\r\n",
        second.len()
    );
    let mut first_wire = first_command.into_bytes();
    first_wire.extend_from_slice(&first);
    let mut second_wire = second_command.into_bytes();
    second_wire.extend_from_slice(&second);

    const COMMAND_REPLIES: &[u8] = b"250 mail\r\n250 rcpt\r\n";
    const FINAL_REPLIES: [&[u8; 16]; 2] = [b"250 accepted-0\r\n", b"250 accepted-1\r\n"];
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let expected_wires = [first_wire.clone(), second_wire.clone()];
    let backend_task = tokio::spawn(async move {
        let final_barrier = Arc::new(Barrier::new(3));
        let mut handlers = Vec::new();
        for (index, expected_wire) in expected_wires.into_iter().enumerate() {
            let (mut stream, _) = backend.accept().await.unwrap();
            let final_barrier = final_barrier.clone();
            handlers.push(tokio::spawn(async move {
                stream.write_all(b"220 concurrent-gate\r\n").await.unwrap();
                let mut received = vec![0; expected_wire.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, expected_wire);
                stream.write_all(COMMAND_REPLIES).await.unwrap();
                final_barrier.wait().await;
                stream.write_all(FINAL_REPLIES[index]).await.unwrap();
                let mut eof = [0_u8; 1];
                assert_eq!(stream.read(&mut eof).await.unwrap(), 0);
            }));
        }
        final_barrier.wait().await;
        for handler in handlers {
            handler.await.unwrap();
        }
    });

    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer
        .begin_with_persistence_gate(round_spec(2, first.len()), true)
        .unwrap();
    let (proxy_addr, shutdown, proxy_task) = start_proxy(backend_addr, observer.clone()).await;
    let mut first_client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut first_greeting = [0; 21];
    first_client.read_exact(&mut first_greeting).await.unwrap();
    assert_eq!(&first_greeting, b"220 concurrent-gate\r\n");
    first_client.write_all(&first_wire).await.unwrap();
    let mut second_client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut second_greeting = [0; 21];
    second_client
        .read_exact(&mut second_greeting)
        .await
        .unwrap();
    assert_eq!(&second_greeting, b"220 concurrent-gate\r\n");
    second_client.write_all(&second_wire).await.unwrap();
    let mut first_commands = vec![0; COMMAND_REPLIES.len()];
    first_client.read_exact(&mut first_commands).await.unwrap();
    assert_eq!(first_commands, COMMAND_REPLIES);
    let mut second_commands = vec![0; COMMAND_REPLIES.len()];
    second_client
        .read_exact(&mut second_commands)
        .await
        .unwrap();
    assert_eq!(second_commands, COMMAND_REPLIES);

    let trigger = observer
        .wait_for_persistence_gate(Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(trigger.expected_messages, 2);
    let (prior_index, gated_index) = {
        let first_read = async {
            let mut reply = [0_u8; 16];
            first_client.read_exact(&mut reply).await.unwrap();
            reply
        };
        let second_read = async {
            let mut reply = [0_u8; 16];
            second_client.read_exact(&mut reply).await.unwrap();
            reply
        };
        tokio::pin!(first_read);
        tokio::pin!(second_read);
        let prior_index = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::select! {
                reply = &mut first_read => {
                    assert_eq!(&reply, FINAL_REPLIES[0]);
                    0
                }
                reply = &mut second_read => {
                    assert_eq!(&reply, FINAL_REPLIES[1]);
                    1
                }
            }
        })
        .await
        .expect("ordinal N-1 was acknowledged but did not reach either client");
        let gated_index = 1 - prior_index;
        match gated_index {
            0 => assert!(
                tokio::time::timeout(Duration::from_millis(25), &mut first_read)
                    .await
                    .is_err(),
                "ordinal N crossed its socket before persistence-gate release"
            ),
            1 => assert!(
                tokio::time::timeout(Duration::from_millis(25), &mut second_read)
                    .await
                    .is_err(),
                "ordinal N crossed its socket before persistence-gate release"
            ),
            _ => unreachable!(),
        }
        observer
            .release_persistence_gate(trigger.gate_id, qualified_snapshot(2))
            .unwrap();
        let gated_reply = match gated_index {
            0 => first_read.await,
            1 => second_read.await,
            _ => unreachable!(),
        };
        assert_eq!(&gated_reply, FINAL_REPLIES[gated_index]);
        (prior_index, gated_index)
    };
    first_client.shutdown().await.unwrap();
    second_client.shutdown().await.unwrap();
    backend_task.await.unwrap();
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();

    let summary = observer.finalize().unwrap();
    assert!(summary.qualification, "{summary:#?}");
    assert_eq!(summary.verified, 2);
    let prior_sample = summary
        .first_samples
        .iter()
        .find(|sample| sample.index == prior_index)
        .unwrap();
    assert!(
        prior_sample.accepted_at_monotonic_ns <= trigger.triggered_at_proxy_monotonic_ns,
        "gate publication preceded ordinal N-1 socket write/ack"
    );
    let boundary = summary.final_250_boundary.unwrap();
    assert_eq!(boundary.index, gated_index);
    assert_eq!(boundary.reply_bytes, FINAL_REPLIES[gated_index].len());
    assert_eq!(
        summary
            .persistence_gate
            .forwarding_completed_at_proxy_monotonic_ns,
        Some(boundary.completed_at_monotonic_ns)
    );
}

#[tokio::test]
async fn oversized_multiline_reply_is_failed_closed_without_partial_forwarding() {
    let limits = ObserverLimits::default();
    let maximum_block_bytes = limits.maximum_backend_reply_block_bytes().unwrap();
    let mut oversized = Vec::with_capacity(maximum_block_bytes + 8);
    for _ in 0..(maximum_block_bytes / 8) {
        oversized.extend_from_slice(b"250-xx\r\n");
    }
    oversized.extend_from_slice(b"250 xx\r\n");

    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 bounded\r\n").await.unwrap();
        stream.write_all(&oversized).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let observer = ObserverHub::new(limits).unwrap();
    observer.begin(round_spec(1, 1_024)).unwrap();
    let (proxy_addr, shutdown, proxy_task) = start_proxy(backend_addr, observer.clone()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0; 13];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 bounded\r\n");
    let mut leaked = Vec::new();
    client.read_to_end(&mut leaked).await.unwrap();
    assert!(leaked.is_empty(), "oversized reply bytes were forwarded");

    backend_task.await.unwrap();
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    let summary = observer.finalize().unwrap();
    assert!(!summary.qualification);
    assert!(summary.observer_failure_count > 0);
}

#[tokio::test]
async fn pipeline_reaches_backend_before_backend_emits_any_command_reply() {
    let message = stress_message(0, 1_024);
    let pipeline = b"EHLO local\r\nMAIL FROM:<stress-sender@lmyz.net>\r\nRCPT TO:<stress-receiver@lmyz.net>\r\nDATA\r\n";
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let expected_message = message.clone();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 delayed ESMTP\r\n").await.unwrap();
        let mut received_pipeline = vec![0; pipeline.len()];
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut received_pipeline),
        )
        .await
        .expect("proxy serialized the pipelined commands behind a backend reply")
        .unwrap();
        assert_eq!(received_pipeline, pipeline);
        stream
            .write_all(b"250-delayed\r\n250 PIPELINING\r\n250 mail\r\n250 rcpt\r\n354 data\r\n")
            .await
            .unwrap();
        let mut received_message = vec![0; expected_message.len() + 3];
        stream.read_exact(&mut received_message).await.unwrap();
        let mut expected_wire = expected_message;
        expected_wire.extend_from_slice(b".\r\n");
        assert_eq!(received_message, expected_wire);
        stream.write_all(b"250 accepted\r\n").await.unwrap();
        let mut quit = [0; 6];
        stream.read_exact(&mut quit).await.unwrap();
        assert_eq!(&quit, b"QUIT\r\n");
        stream.write_all(b"221 bye\r\n").await.unwrap();
    });

    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer.begin(round_spec(1, message.len())).unwrap();
    let (proxy_addr, shutdown, proxy_task) = start_proxy(backend_addr, observer.clone()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0; 19];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 delayed ESMTP\r\n");
    client.write_all(pipeline).await.unwrap();
    let replies = b"250-delayed\r\n250 PIPELINING\r\n250 mail\r\n250 rcpt\r\n354 data\r\n";
    let mut received_replies = vec![0; replies.len()];
    client.read_exact(&mut received_replies).await.unwrap();
    assert_eq!(received_replies, replies);
    client.write_all(&message).await.unwrap();
    client.write_all(b".\r\n").await.unwrap();
    let mut accepted = [0; 14];
    client.read_exact(&mut accepted).await.unwrap();
    assert_eq!(&accepted, b"250 accepted\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();
    let mut bye = [0; 9];
    client.read_exact(&mut bye).await.unwrap();
    assert_eq!(&bye, b"221 bye\r\n");
    drop(client);
    backend_task.await.unwrap();
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    let summary = observer.finalize().unwrap();
    assert!(summary.qualification, "{summary:#?}");
    assert_eq!(summary.final_250_boundary.unwrap().reply_bytes, 14);
}

#[tokio::test]
async fn malformed_observer_stream_is_still_forwarded_exactly_across_half_close() {
    let payload = vec![b'z'; 2 * 1024 * 1024];
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let expected_payload = payload.clone();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 raw\r\n").await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected_payload);
        stream.write_all(b"250 raw\r\n").await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer.begin(round_spec(1, 1_024)).unwrap();
    let (proxy_addr, shutdown, proxy_task) = start_proxy(backend_addr, observer.clone()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0; 9];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 raw\r\n");
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"250 raw\r\n");
    backend_task.await.unwrap();
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    let summary = observer.finalize().unwrap();
    assert!(!summary.qualification);
    assert!(summary.observer_failure_count > 0);
}

#[tokio::test]
async fn accepted_message_remains_qualified_when_client_half_closes_after_final_reply() {
    let message = stress_message(0, 1_024);
    let commands =
        b"MAIL FROM:<stress-sender@lmyz.net>\r\nRCPT TO:<stress-receiver@lmyz.net>\r\nDATA\r\n";
    let command_replies = b"250 mail\r\n250 rcpt\r\n354 data\r\n";
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let expected_message = message.clone();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 close-test\r\n").await.unwrap();
        let mut received_commands = vec![0; commands.len()];
        stream.read_exact(&mut received_commands).await.unwrap();
        assert_eq!(received_commands, commands);
        stream.write_all(command_replies).await.unwrap();
        let mut received_message = vec![0; expected_message.len() + 3];
        stream.read_exact(&mut received_message).await.unwrap();
        let mut expected_wire = expected_message;
        expected_wire.extend_from_slice(b".\r\n");
        assert_eq!(received_message, expected_wire);
        stream.write_all(b"250 accepted\r\n").await.unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        stream.shutdown().await.unwrap();
    });

    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer.begin(round_spec(1, message.len())).unwrap();
    let (proxy_addr, shutdown, proxy_task) = start_proxy(backend_addr, observer.clone()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0; 16];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 close-test\r\n");
    client.write_all(commands).await.unwrap();
    let mut replies = vec![0; command_replies.len()];
    client.read_exact(&mut replies).await.unwrap();
    assert_eq!(replies, command_replies);
    client.write_all(&message).await.unwrap();
    client.write_all(b".\r\n").await.unwrap();
    let mut accepted = [0; 14];
    client.read_exact(&mut accepted).await.unwrap();
    assert_eq!(&accepted, b"250 accepted\r\n");
    client.shutdown().await.unwrap();
    let mut eof = Vec::new();
    client.read_to_end(&mut eof).await.unwrap();
    assert!(eof.is_empty());
    backend_task.await.unwrap();
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    let summary = observer.finalize().unwrap();
    assert!(summary.qualification, "{summary:#?}");
    assert_eq!(summary.verified, 1);
}

#[tokio::test]
async fn rejected_non_final_bdat_chunk_cannot_become_a_verified_message() {
    let message = stress_message(0, 1_024);
    let split = message.len() / 2;
    let first_command = format!("BDAT {split}\r\n");
    let last_command = format!("BDAT {} LAST\r\n", message.len() - split);
    let backend_first_command = first_command.clone();
    let backend_last_command = last_command.clone();
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let expected_message = message.clone();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 bdat-reject\r\n").await.unwrap();
        let mail = b"MAIL FROM:<stress-sender@lmyz.net>\r\n";
        let mut received_mail = vec![0; mail.len()];
        stream.read_exact(&mut received_mail).await.unwrap();
        assert_eq!(received_mail, mail);
        stream.write_all(b"250 mail\r\n").await.unwrap();

        let mut first = vec![0; backend_first_command.len() + split];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(
            &first[..backend_first_command.len()],
            backend_first_command.as_bytes()
        );
        assert_eq!(
            &first[backend_first_command.len()..],
            &expected_message[..split]
        );
        stream.write_all(b"554 chunk rejected\r\n").await.unwrap();

        let mut last = vec![0; backend_last_command.len() + expected_message.len() - split];
        stream.read_exact(&mut last).await.unwrap();
        assert_eq!(
            &last[..backend_last_command.len()],
            backend_last_command.as_bytes()
        );
        assert_eq!(
            &last[backend_last_command.len()..],
            &expected_message[split..]
        );
        stream.write_all(b"250 accepted\r\n").await.unwrap();
        let mut quit = [0; 6];
        stream.read_exact(&mut quit).await.unwrap();
        assert_eq!(&quit, b"QUIT\r\n");
        stream.write_all(b"221 bye\r\n").await.unwrap();
    });

    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer.begin(round_spec(1, message.len())).unwrap();
    let (proxy_addr, shutdown, proxy_task) = start_proxy(backend_addr, observer.clone()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0; 17];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 bdat-reject\r\n");
    client
        .write_all(b"MAIL FROM:<stress-sender@lmyz.net>\r\n")
        .await
        .unwrap();
    let mut mail_reply = [0; 10];
    client.read_exact(&mut mail_reply).await.unwrap();
    assert_eq!(&mail_reply, b"250 mail\r\n");
    client.write_all(first_command.as_bytes()).await.unwrap();
    client.write_all(&message[..split]).await.unwrap();
    let mut rejected = [0; 20];
    client.read_exact(&mut rejected).await.unwrap();
    assert_eq!(&rejected, b"554 chunk rejected\r\n");
    client.write_all(last_command.as_bytes()).await.unwrap();
    client.write_all(&message[split..]).await.unwrap();
    let mut accepted = [0; 14];
    client.read_exact(&mut accepted).await.unwrap();
    assert_eq!(&accepted, b"250 accepted\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();
    let mut bye = [0; 9];
    client.read_exact(&mut bye).await.unwrap();
    assert_eq!(&bye, b"221 bye\r\n");
    drop(client);
    backend_task.await.unwrap();
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    let summary = observer.finalize().unwrap();
    assert!(!summary.qualification);
    assert_eq!(summary.verified, 0);
    assert!(
        summary
            .observer_failures
            .iter()
            .any(|failure| { failure.contains("rejected a non-final BDAT chunk with 554") })
    );
}

#[tokio::test]
async fn early_bdat_rejection_is_matched_before_backend_reads_the_chunk() {
    let message = stress_message(0, 1_024);
    let first_chunk = vec![b'z'; 4_096];
    let last_command = format!("BDAT {} LAST\r\n", message.len());
    let backend_last_command = last_command.clone();
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let expected_message = message.clone();
    let expected_first = first_chunk.clone();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 early-bdat\r\n").await.unwrap();
        let mail = b"MAIL FROM:<stress-sender@lmyz.net>\r\n";
        let mut received_mail = vec![0_u8; mail.len()];
        stream.read_exact(&mut received_mail).await.unwrap();
        assert_eq!(received_mail, mail);
        stream.write_all(b"250 mail\r\n").await.unwrap();
        let command = b"BDAT 4096\r\n";
        let mut received_command = vec![0_u8; command.len()];
        stream.read_exact(&mut received_command).await.unwrap();
        assert_eq!(received_command, command);
        let mut prefix = [0_u8; 16];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, &expected_first[..16]);
        stream.write_all(b"554 rejected early\r\n").await.unwrap();
        let mut suffix = vec![0_u8; expected_first.len() - prefix.len()];
        stream.read_exact(&mut suffix).await.unwrap();
        assert_eq!(suffix, expected_first[prefix.len()..]);
        let mut last = vec![0_u8; backend_last_command.len() + expected_message.len()];
        stream.read_exact(&mut last).await.unwrap();
        assert_eq!(
            &last[..backend_last_command.len()],
            backend_last_command.as_bytes()
        );
        assert_eq!(&last[backend_last_command.len()..], expected_message);
        stream.write_all(b"250 accepted\r\n").await.unwrap();
    });
    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer.begin(round_spec(1, message.len())).unwrap();
    let (proxy_addr, shutdown, proxy_task) = start_proxy(backend_addr, observer.clone()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0_u8; 16];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 early-bdat\r\n");
    client
        .write_all(b"MAIL FROM:<stress-sender@lmyz.net>\r\n")
        .await
        .unwrap();
    let mut mail_reply = [0_u8; 10];
    client.read_exact(&mut mail_reply).await.unwrap();
    client.write_all(b"BDAT 4096\r\n").await.unwrap();
    client.write_all(&first_chunk[..16]).await.unwrap();
    let mut rejected = [0_u8; 20];
    client.read_exact(&mut rejected).await.unwrap();
    assert_eq!(&rejected, b"554 rejected early\r\n");
    client.write_all(&first_chunk[16..]).await.unwrap();
    client.write_all(last_command.as_bytes()).await.unwrap();
    client.write_all(&message).await.unwrap();
    let mut accepted = [0_u8; 14];
    client.read_exact(&mut accepted).await.unwrap();
    assert_eq!(&accepted, b"250 accepted\r\n");
    drop(client);
    backend_task.await.unwrap();
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    let summary = observer.finalize().unwrap();
    assert!(!summary.qualification);
    assert_eq!(summary.verified, 0);
    assert!(
        summary
            .observer_failures
            .iter()
            .any(|failure| failure.contains("rejected a non-final BDAT chunk with 554"))
    );
}

#[tokio::test]
async fn rset_discards_partial_bdat_capture_before_the_next_transaction() {
    let message = stress_message(0, 1_024);
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let expected_message = message.clone();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 rset-test\r\n").await.unwrap();
        let exchanges: [(Vec<u8>, &'static [u8]); 4] = [
            (
                b"MAIL FROM:<stress-sender@lmyz.net>\r\n".to_vec(),
                &b"250 mail\r\n"[..],
            ),
            (b"BDAT 9\r\ndiscarded".to_vec(), &b"250 chunk\r\n"[..]),
            (b"RSET\r\n".to_vec(), &b"250 reset\r\n"[..]),
            (
                b"MAIL FROM:<stress-sender@lmyz.net>\r\n".to_vec(),
                &b"250 mail\r\n"[..],
            ),
        ];
        for (request, reply) in exchanges {
            let mut received = vec![0; request.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, request);
            stream.write_all(reply).await.unwrap();
        }
        let last_command = format!("BDAT {} LAST\r\n", expected_message.len());
        let mut last = vec![0; last_command.len() + expected_message.len()];
        stream.read_exact(&mut last).await.unwrap();
        assert_eq!(&last[..last_command.len()], last_command.as_bytes());
        assert_eq!(&last[last_command.len()..], expected_message.as_slice());
        stream.write_all(b"250 accepted\r\n").await.unwrap();
        let mut quit = [0; 6];
        stream.read_exact(&mut quit).await.unwrap();
        assert_eq!(&quit, b"QUIT\r\n");
        stream.write_all(b"221 bye\r\n").await.unwrap();
    });

    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer.begin(round_spec(1, message.len())).unwrap();
    let (proxy_addr, shutdown, proxy_task) = start_proxy(backend_addr, observer.clone()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0; 15];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 rset-test\r\n");
    for (request, reply) in [
        (
            &b"MAIL FROM:<stress-sender@lmyz.net>\r\n"[..],
            &b"250 mail\r\n"[..],
        ),
        (&b"BDAT 9\r\ndiscarded"[..], &b"250 chunk\r\n"[..]),
        (&b"RSET\r\n"[..], &b"250 reset\r\n"[..]),
        (
            &b"MAIL FROM:<stress-sender@lmyz.net>\r\n"[..],
            &b"250 mail\r\n"[..],
        ),
    ] {
        client.write_all(request).await.unwrap();
        let mut received = vec![0; reply.len()];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(received, reply);
    }
    client
        .write_all(format!("BDAT {} LAST\r\n", message.len()).as_bytes())
        .await
        .unwrap();
    client.write_all(&message).await.unwrap();
    let mut accepted = [0; 14];
    client.read_exact(&mut accepted).await.unwrap();
    assert_eq!(&accepted, b"250 accepted\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();
    let mut bye = [0; 9];
    client.read_exact(&mut bye).await.unwrap();
    assert_eq!(&bye, b"221 bye\r\n");
    drop(client);
    backend_task.await.unwrap();
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    let summary = observer.finalize().unwrap();
    assert!(summary.qualification, "{summary:#?}");
    assert_eq!(summary.total_wire_bytes, message.len() as u64);
}

#[tokio::test]
async fn shutdown_drops_listener_backlog_before_joining_active_connection() {
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 held\r\n").await.unwrap();
        let mut discard = Vec::new();
        stream.read_to_end(&mut discard).await.unwrap();
    });
    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer.begin(round_spec(1, 1_024)).unwrap();
    let telemetry = ProxyTelemetry::shared();
    let proxy = ProxyServer::bind(
        ProxyConfig {
            listen: localhost_ephemeral(),
            backend: backend_addr,
            max_connections: 1,
            memory_budget_bytes: 256 * 1024 * 1024,
            shutdown_grace: Duration::from_secs(5),
        },
        observer,
        telemetry.clone(),
    )
    .await
    .unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let proxy_task = tokio::spawn(proxy.serve(shutdown_rx));
    let mut active = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0_u8; 10];
    active.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 held\r\n");
    let mut backlogged = TcpStream::connect(proxy_addr).await.unwrap();
    shutdown.send(true).unwrap();
    let mut byte = [0_u8; 1];
    let backlog_result = tokio::time::timeout(Duration::from_secs(2), backlogged.read(&mut byte))
        .await
        .expect("queued connection remained in the closed listener backlog");
    assert!(backlog_result.is_err() || backlog_result.unwrap() == 0);
    drop(backlogged);
    drop(active);
    proxy_task.await.unwrap().unwrap();
    backend_task.await.unwrap();
    assert!(TcpStream::connect(proxy_addr).await.is_err());
    let snapshot = telemetry.snapshot();
    assert_eq!(snapshot.accepted_connections, 1);
    assert_eq!(snapshot.completed_connections, 1);
    assert_eq!(snapshot.failed_connections, 0);
    assert_eq!(snapshot.active_connections, 0);
    assert_eq!(snapshot.peak_connections, 1);
    assert_eq!(snapshot.backend_to_client_bytes, 10);
    assert_eq!(snapshot.active_accounted_connection_bytes, 0);
    assert_eq!(
        snapshot.peak_accounted_connection_bytes,
        snapshot.accounted_connection_bytes
    );
    assert!(snapshot.peak_total_accounted_bytes <= snapshot.memory_budget_bytes);
}

#[tokio::test]
async fn starttls_payload_is_forwarded_exactly_after_observer_becomes_opaque() {
    let client_tls = b"\x16\x03\x01\x00\x08abcdefgh";
    let server_tls = b"\x16\x03\x03\x00\x08ABCDEFGH";
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 starttls\r\n").await.unwrap();
        let mut command = [0_u8; 10];
        stream.read_exact(&mut command).await.unwrap();
        assert_eq!(&command, b"STARTTLS\r\n");
        stream.write_all(b"220 ready\r\n").await.unwrap();
        let mut encrypted = vec![0_u8; client_tls.len()];
        stream.read_exact(&mut encrypted).await.unwrap();
        assert_eq!(encrypted, client_tls);
        stream.write_all(server_tls).await.unwrap();
    });
    let observer = ObserverHub::new(ObserverLimits::default()).unwrap();
    observer.begin(round_spec(1, 1_024)).unwrap();
    let (proxy_addr, shutdown, proxy_task) = start_proxy(backend_addr, observer.clone()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0_u8; 14];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 starttls\r\n");
    client.write_all(b"STARTTLS\r\n").await.unwrap();
    let mut ready = [0_u8; 11];
    client.read_exact(&mut ready).await.unwrap();
    assert_eq!(&ready, b"220 ready\r\n");
    client.write_all(client_tls).await.unwrap();
    let mut encrypted = vec![0_u8; server_tls.len()];
    client.read_exact(&mut encrypted).await.unwrap();
    assert_eq!(encrypted, server_tls);
    drop(client);
    backend_task.await.unwrap();
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
    let summary = observer.finalize().unwrap();
    assert!(!summary.qualification);
    assert!(
        summary
            .observer_failures
            .iter()
            .any(|failure| failure.contains("STARTTLS"))
    );
}

#[tokio::test]
async fn slow_backend_applies_bounded_backpressure_without_byte_loss() {
    let payload = vec![b'q'; 512 * 1024];
    let backend = TcpListener::bind(localhost_ephemeral()).await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let expected_payload = payload.clone();
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        stream.write_all(b"220 slow\r\n").await.unwrap();
        let mut received = Vec::with_capacity(expected_payload.len());
        let mut chunk = [0_u8; 4 * 1024];
        while received.len() < expected_payload.len() {
            let bytes = stream.read(&mut chunk).await.unwrap();
            assert!(bytes > 0);
            received.extend_from_slice(&chunk[..bytes]);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(received, expected_payload);
        stream.shutdown().await.unwrap();
    });

    let limits = ObserverLimits {
        max_line_bytes: 4 * 1024 * 1024,
        ..ObserverLimits::default()
    };
    let observer = ObserverHub::new(limits).unwrap();
    observer.begin(round_spec(1, 1_024)).unwrap();
    let (proxy_addr, shutdown, proxy_task) = start_proxy(backend_addr, observer).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut greeting = [0; 10];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"220 slow\r\n");
    tokio::time::timeout(Duration::from_secs(10), async {
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut eof = Vec::new();
        client.read_to_end(&mut eof).await.unwrap();
    })
    .await
    .expect("bounded proxy backpressure did not drain");
    backend_task.await.unwrap();
    shutdown.send(true).unwrap();
    proxy_task.await.unwrap().unwrap();
}
