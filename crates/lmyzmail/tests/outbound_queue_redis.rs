#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use deadpool_redis::redis;
use lmyzmail::{
    config::{Properties, RuntimeConfig},
    outbound_queue::{
        ClaimReconciliation, DomainStatus, LegacyListClaim, LegacyListKind, LegacyOutboundQueue,
        QueueClaim, QueueError, QueueSettlement, SettlementReconciliation, TaskDetail,
    },
    redis::create_pool,
};
use sha2::{Digest, Sha256};

struct RedisProcess {
    child: Child,
    directory: PathBuf,
    port: u16,
}

struct DropResponseProxy {
    port: u16,
    response_dropped: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

struct DelayRequestProxy {
    port: u16,
    request_forwarded: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl DelayRequestProxy {
    fn start(upstream_port: u16, request_marker: &'static [u8], delay: Duration) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let request_forwarded = Arc::new(AtomicBool::new(false));
        let forwarded_signal = Arc::clone(&request_forwarded);
        let response_forwarded = Arc::clone(&request_forwarded);
        let thread = thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            client.set_nodelay(true).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let upstream = TcpStream::connect(("127.0.0.1", upstream_port)).unwrap();
            upstream.set_nodelay(true).unwrap();
            upstream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();

            let mut client_reader = client.try_clone().unwrap();
            let mut upstream_writer = upstream.try_clone().unwrap();
            let forward = thread::spawn(move || {
                let mut buffer = [0_u8; 16 * 1024];
                let mut tail = Vec::new();
                let mut delayed = false;
                loop {
                    let read = match client_reader.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => read,
                    };
                    if !delayed {
                        let mut observed = Vec::with_capacity(tail.len() + read);
                        observed.extend_from_slice(&tail);
                        observed.extend_from_slice(&buffer[..read]);
                        if observed
                            .windows(request_marker.len())
                            .any(|window| window == request_marker)
                        {
                            delayed = true;
                            thread::sleep(delay);
                        }
                        let keep = request_marker.len().saturating_sub(1).min(observed.len());
                        tail.clear();
                        tail.extend_from_slice(&observed[observed.len() - keep..]);
                    }
                    if upstream_writer.write_all(&buffer[..read]).is_err() {
                        break;
                    }
                    if delayed {
                        forwarded_signal.store(true, Ordering::Release);
                    }
                }
            });

            let mut upstream_reader = upstream;
            let mut client_writer = client;
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let read = match upstream_reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                if client_writer.write_all(&buffer[..read]).is_err() {
                    break;
                }
                if response_forwarded.load(Ordering::Acquire) {
                    break;
                }
            }
            let _ = client_writer.shutdown(Shutdown::Both);
            let _ = upstream_reader.shutdown(Shutdown::Both);
            let _ = forward.join();
        });
        Self {
            port,
            request_forwarded,
            thread: Some(thread),
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn wait(mut self) {
        self.thread.take().unwrap().join().unwrap();
        assert!(
            self.request_forwarded.load(Ordering::Acquire),
            "proxy did not forward the targeted request after the client deadline"
        );
    }
}

impl Drop for DelayRequestProxy {
    fn drop(&mut self) {
        let _ = self.thread.take();
    }
}

impl DropResponseProxy {
    fn start(upstream_port: u16, request_marker: &'static [u8]) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let should_drop = Arc::new(AtomicBool::new(false));
        let response_dropped = Arc::new(AtomicBool::new(false));
        let drop_signal = should_drop.clone();
        let dropped_signal = response_dropped.clone();
        let thread = thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            client.set_nodelay(true).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let upstream = TcpStream::connect(("127.0.0.1", upstream_port)).unwrap();
            upstream.set_nodelay(true).unwrap();
            upstream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();

            let mut client_reader = client.try_clone().unwrap();
            let mut upstream_writer = upstream.try_clone().unwrap();
            let forward = thread::spawn(move || {
                let mut buffer = [0_u8; 16 * 1024];
                let mut tail = Vec::new();
                loop {
                    let read = match client_reader.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => read,
                    };
                    if !drop_signal.load(Ordering::Acquire) {
                        let mut observed = Vec::with_capacity(tail.len() + read);
                        observed.extend_from_slice(&tail);
                        observed.extend_from_slice(&buffer[..read]);
                        if observed
                            .windows(request_marker.len())
                            .any(|window| window == request_marker)
                        {
                            drop_signal.store(true, Ordering::Release);
                        }
                        let keep = request_marker.len().saturating_sub(1).min(observed.len());
                        tail.clear();
                        tail.extend_from_slice(&observed[observed.len() - keep..]);
                    }
                    if upstream_writer.write_all(&buffer[..read]).is_err() {
                        break;
                    }
                }
            });

            let mut upstream_reader = upstream;
            let mut client_writer = client;
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let read = match upstream_reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                if should_drop.load(Ordering::Acquire) {
                    dropped_signal.store(true, Ordering::Release);
                    let _ = client_writer.shutdown(Shutdown::Both);
                    let _ = upstream_reader.shutdown(Shutdown::Both);
                    break;
                }
                if client_writer.write_all(&buffer[..read]).is_err() {
                    break;
                }
            }
            let _ = forward.join();
        });
        Self {
            port,
            response_dropped,
            thread: Some(thread),
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn wait(mut self) {
        self.thread.take().unwrap().join().unwrap();
        assert!(
            self.response_dropped.load(Ordering::Acquire),
            "proxy did not observe and drop the targeted Redis response"
        );
    }
}

impl Drop for DropResponseProxy {
    fn drop(&mut self) {
        let _ = self.thread.take();
    }
}

impl RedisProcess {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let binary = std::env::var_os("LMYZMAIL_TEST_REDIS_SERVER")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                repository.join(".blackbox/runtime/redis-root/usr/bin/redis-server")
            });
        let library_directory =
            repository.join(".blackbox/runtime/redis-root/usr/lib/x86_64-linux-gnu");
        assert!(
            binary.is_file(),
            "Redis test binary missing at {}",
            binary.display()
        );
        assert!(library_directory.is_dir());

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "lmyzmail-redis-lease-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let child = Command::new(binary)
            .args([
                "--bind",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
                "--protected-mode",
                "yes",
                "--dir",
                directory.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("LD_LIBRARY_PATH", library_directory)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                Instant::now() < deadline,
                "Redis test process did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Self {
            child,
            directory,
            port,
        }
    }

    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for RedisProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if self
            .directory
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with("lmyzmail-redis-lease-"))
        {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

fn task(id: i64) -> TaskDetail {
    TaskDetail {
        id,
        sender_address: "qa@example.test".into(),
        recipients_json: r#"{"to":["user@remote.test"],"cc":[],"bcc":[]}"#.into(),
        subject: "lease integration".into(),
        message_id: format!("<{id}@example.test>"),
        max_retries: 5,
        retry_count: 0,
        sent_file_name: Some(format!("{id}.eml")),
        sent_subdirectory: Some(1),
        message_file_path: None,
        signed_content_base64: Some("RnJvbTogcWE=".into()),
        created_at: "2026-08-06T00:00:00Z".into(),
        next_retry_at: None,
        last_error: None,
        status: "PENDING".into(),
    }
}

fn domains() -> BTreeMap<String, DomainStatus> {
    BTreeMap::from([(
        "remote.test".into(),
        DomainStatus {
            domain: "remote.test".into(),
            status: "PENDING".into(),
            error: None,
            recipients: vec!["user@remote.test".into()],
            updated_at: "2026-08-06T00:00:00Z".into(),
        },
    )])
}

fn two_domains() -> BTreeMap<String, DomainStatus> {
    BTreeMap::from([
        (
            "other.test".into(),
            DomainStatus {
                domain: "other.test".into(),
                status: "PENDING".into(),
                error: None,
                recipients: vec!["other@other.test".into()],
                updated_at: "2026-08-06T00:00:00Z".into(),
            },
        ),
        (
            "remote.test".into(),
            DomainStatus {
                domain: "remote.test".into(),
                status: "PENDING".into(),
                error: None,
                recipients: vec!["user@remote.test".into()],
                updated_at: "2026-08-06T00:00:00Z".into(),
            },
        ),
    ])
}

fn now_millis() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn pool_at(port: u16) -> deadpool_redis::Pool {
    let mut properties = Properties::default();
    properties
        .insert("lmyzmail.redis.host".into(), "127.0.0.1".into())
        .unwrap();
    properties
        .insert("lmyzmail.redis.port".into(), port.to_string())
        .unwrap();
    let config = RuntimeConfig::from_properties(properties).unwrap();
    create_pool(&config).unwrap()
}

async fn dump_keys(pool: &deadpool_redis::Pool, keys: &[String]) -> Vec<Option<Vec<u8>>> {
    let mut connection = pool.get().await.unwrap();
    let mut dumps = Vec::with_capacity(keys.len());
    for key in keys {
        dumps.push(
            redis::cmd("DUMP")
                .arg(key)
                .query_async::<Option<Vec<u8>>>(&mut connection)
                .await
                .unwrap(),
        );
    }
    dumps
}

fn acknowledgement_proof_keys(task_id: i64) -> Vec<String> {
    vec![
        format!("botmail:mail:queue:task:{task_id}"),
        "botmail:mail:queue:pending".into(),
        "botmail:mail:queue:processing".into(),
        "botmail:mail:queue:processing_time".into(),
        "botmail:mail:queue:retry".into(),
        "botmail:mail:queue:sentfile_index".into(),
        format!("lmyzmail:mail:queue:lease:{task_id}"),
    ]
}

#[derive(Clone, Copy, Debug)]
enum SettlementMutation {
    Release,
    Retry,
    Acknowledge,
}

fn settlement_state_keys(task_id: i64, token: &str) -> Vec<String> {
    vec![
        format!("botmail:mail:queue:task:{task_id}"),
        format!("botmail:mail:queue:domains:{task_id}"),
        "botmail:mail:queue:pending".into(),
        "botmail:mail:queue:processing".into(),
        "botmail:mail:queue:processing_time".into(),
        "botmail:mail:queue:retry".into(),
        "botmail:mail:queue:sentfile_index".into(),
        format!("lmyzmail:mail:queue:lease:{task_id}"),
        format!("lmyzmail:mail:queue:attempt:{token}"),
        format!("lmyzmail:mail:queue:claim-result:{token}"),
        "lmyzmail:mail:queue:claim-result-index".into(),
        format!("lmyzmail:mail:queue:settlement:{token}"),
        "lmyzmail:mail:queue:settlement-index".into(),
    ]
}

fn archive_migration_state_keys(token: &str) -> Vec<String> {
    vec![
        "botmail:mail:queue:archive".into(),
        "lmyzmail:mail:queue:migration:archive:inflight".into(),
        "lmyzmail:mail:queue:migration:archive:payloads".into(),
        "lmyzmail:mail:queue:migration:archive:quarantine".into(),
        "lmyzmail:mail:queue:migration:archive:quarantine-metadata".into(),
        "lmyzmail:mail:queue:migration:archive:quarantine-bytes".into(),
        "lmyzmail:mail:queue:migration:archive:done-index".into(),
        format!("lmyzmail:mail:queue:migration:archive:done:{token}"),
    ]
}

fn migrated_cleanup_state_keys(task_id: i64) -> Vec<String> {
    vec![
        "botmail:mail:queue:pending".into(),
        "botmail:mail:queue:processing".into(),
        "botmail:mail:queue:processing_time".into(),
        "botmail:mail:queue:retry".into(),
        format!("botmail:mail:queue:task:{task_id}"),
        "botmail:mail:queue:sentfile_index".into(),
        "lmyzmail:mail:queue:migration:cleanup-index".into(),
        format!("lmyzmail:mail:queue:lease:{task_id}"),
        format!("lmyzmail:mail:queue:migration:cleanup:{task_id}"),
    ]
}

fn legacy_active_task_state_keys(task_id: i64) -> Vec<String> {
    vec![
        "botmail:mail:queue:pending".into(),
        "botmail:mail:queue:processing".into(),
        "botmail:mail:queue:retry".into(),
        format!("botmail:mail:queue:task:{task_id}"),
        format!("botmail:mail:queue:domains:{task_id}"),
        "botmail:mail:queue:sentfile_index".into(),
    ]
}

fn settlement_mutation_keys(
    action: SettlementMutation,
    task_id: i64,
    token: &str,
) -> Vec<(String, bool)> {
    let mut keys = vec![
        ("botmail:mail:queue:pending".into(), false),
        ("botmail:mail:queue:processing".into(), false),
        ("botmail:mail:queue:processing_time".into(), false),
        ("botmail:mail:queue:retry".into(), false),
        ("lmyzmail:mail:queue:settlement-index".into(), false),
        ("lmyzmail:mail:queue:claim-result-index".into(), false),
        (format!("lmyzmail:mail:queue:settlement:{token}"), true),
        (format!("lmyzmail:mail:queue:lease:{task_id}"), true),
        (format!("lmyzmail:mail:queue:attempt:{token}"), true),
        (format!("botmail:mail:queue:task:{task_id}"), true),
    ];
    if matches!(action, SettlementMutation::Acknowledge) {
        keys.push(("botmail:mail:queue:sentfile_index".into(), false));
    }
    keys
}

async fn replace_with_wrong_type(pool: &deadpool_redis::Pool, key: &str, expected_string: bool) {
    let mut connection = pool.get().await.unwrap();
    redis::cmd("DEL")
        .arg(key)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    if expected_string {
        redis::cmd("HSET")
            .arg(key)
            .arg("wrong")
            .arg("type")
            .query_async::<i64>(&mut connection)
            .await
            .unwrap();
    } else {
        redis::cmd("SET")
            .arg(key)
            .arg("wrong-type")
            .query_async::<String>(&mut connection)
            .await
            .unwrap();
    }
}

async fn assert_wrong_type_settlement_mutation_is_atomic(
    action: SettlementMutation,
    corrupt_key: &str,
    expected_string: bool,
) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_230_i64;
    let token = match action {
        SettlementMutation::Release => "wrong-type:release",
        SettlementMutation::Retry => "wrong-type:retry",
        SettlementMutation::Acknowledge => "wrong-type:ack",
    };
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    let claim = queue
        .claim_next(token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    let mut retry_task = claim.task.clone().unwrap();
    retry_task.retry_count = 1;
    retry_task.next_retry_at = Some("2026-08-07T00:00:30Z".into());
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let state_keys = settlement_state_keys(task_id, token);
    let before = dump_keys(&pool, &state_keys).await;

    let result = match action {
        SettlementMutation::Release => queue.release_claim(&claim, true).await,
        SettlementMutation::Retry => {
            queue
                .schedule_retry(&claim, &retry_task, now_millis() + 30_000)
                .await
        }
        SettlementMutation::Acknowledge => queue.acknowledge(&claim).await,
    };
    assert_eq!(
        result.unwrap_err(),
        QueueError::OutcomeUnknown,
        "{action:?} did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "{action:?} partially mutated Redis before rejecting {corrupt_key}"
    );
}

async fn assert_wrong_type_settlement_reconciliation_is_read_only(
    corrupt_key: &str,
    expected_string: bool,
) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_231_i64;
    let token = "wrong-type:reconcile";
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    let claim = queue
        .claim_next(token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let state_keys = settlement_state_keys(task_id, token);
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue
            .reconcile_settlement(&claim, QueueSettlement::Acknowledge)
            .await
            .unwrap_err(),
        QueueError::Unavailable,
        "reconciliation did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "reconciliation mutated Redis before rejecting {corrupt_key}"
    );
}

#[tokio::test]
async fn settlement_wrong_types_never_partially_mutate_redis() {
    for action in [
        SettlementMutation::Release,
        SettlementMutation::Retry,
        SettlementMutation::Acknowledge,
    ] {
        for (key, expected_string) in settlement_mutation_keys(
            action,
            9_007_199_254_742_230_i64,
            match action {
                SettlementMutation::Release => "wrong-type:release",
                SettlementMutation::Retry => "wrong-type:retry",
                SettlementMutation::Acknowledge => "wrong-type:ack",
            },
        ) {
            assert_wrong_type_settlement_mutation_is_atomic(action, &key, expected_string).await;
        }
    }

    let task_id = 9_007_199_254_742_231_i64;
    let token = "wrong-type:reconcile";
    for (key, expected_string) in [
        (format!("lmyzmail:mail:queue:settlement:{token}"), true),
        (format!("lmyzmail:mail:queue:attempt:{token}"), true),
        ("botmail:mail:queue:processing".into(), false),
        ("botmail:mail:queue:processing_time".into(), false),
        ("botmail:mail:queue:pending".into(), false),
        ("botmail:mail:queue:retry".into(), false),
        (format!("botmail:mail:queue:task:{task_id}"), true),
        ("botmail:mail:queue:sentfile_index".into(), false),
        ("lmyzmail:mail:queue:settlement-index".into(), false),
        (format!("lmyzmail:mail:queue:lease:{task_id}"), true),
    ] {
        assert_wrong_type_settlement_reconciliation_is_read_only(&key, expected_string).await;
    }
}

#[tokio::test]
async fn terminal_acknowledgement_proof_tracks_all_active_references() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool);
    let task_id = 9_007_199_254_742_220_i64;
    let sent_file = task(task_id).sent_file_name.unwrap();

    assert!(
        queue
            .terminal_acknowledgement_proven(task_id, &sent_file)
            .await
            .unwrap()
    );
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    assert!(
        !queue
            .terminal_acknowledgement_proven(task_id, &sent_file)
            .await
            .unwrap()
    );
    let claim = queue
        .claim_next("ack-proof:claim", Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !queue
            .terminal_acknowledgement_proven(task_id, &sent_file)
            .await
            .unwrap()
    );
    assert!(queue.acknowledge(&claim).await.unwrap());
    assert!(
        queue
            .terminal_acknowledgement_proven(task_id, &sent_file)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn terminal_acknowledgement_proof_fails_closed_without_mutating_redis() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_221_i64;
    let sent_file = task(task_id).sent_file_name.unwrap();
    let keys = acknowledgement_proof_keys(task_id);

    for (index, key) in keys.iter().enumerate() {
        let mut connection = pool.get().await.unwrap();
        redis::cmd("DEL")
            .arg(&keys)
            .query_async::<i64>(&mut connection)
            .await
            .unwrap();
        if index == 0 || index == 6 {
            redis::cmd("HSET")
                .arg(key)
                .arg("wrong")
                .arg("type")
                .query_async::<i64>(&mut connection)
                .await
                .unwrap();
        } else {
            redis::cmd("SET")
                .arg(key)
                .arg("wrong-type")
                .query_async::<String>(&mut connection)
                .await
                .unwrap();
        }
        drop(connection);
        let before = dump_keys(&pool, &keys).await;
        assert_eq!(
            queue
                .terminal_acknowledgement_proven(task_id, &sent_file)
                .await
                .unwrap_err(),
            QueueError::Unavailable
        );
        assert_eq!(dump_keys(&pool, &keys).await, before);
    }

    let mut connection = pool.get().await.unwrap();
    redis::cmd("DEL")
        .arg(&keys)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("HSET")
        .arg("botmail:mail:queue:sentfile_index")
        .arg(&sent_file)
        .arg(task_id + 1)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let before = dump_keys(&pool, &keys).await;
    assert_eq!(
        queue
            .terminal_acknowledgement_proven(task_id, &sent_file)
            .await
            .unwrap_err(),
        QueueError::InvalidTask("terminal sent-file index conflicts with task ID")
    );
    assert_eq!(dump_keys(&pool, &keys).await, before);
}

#[tokio::test]
async fn lost_acknowledgement_proof_response_is_retryable_and_read_only() {
    let process = RedisProcess::start();
    let direct_pool = pool_at(process.port());
    let task_id = 9_007_199_254_742_222_i64;
    let sent_file = task(task_id).sent_file_name.unwrap();
    let keys = acknowledgement_proof_keys(task_id);
    let before = dump_keys(&direct_pool, &keys).await;
    let proxy = DropResponseProxy::start(process.port(), b"local task_id = ARGV[1]");
    let lossy_queue = LegacyOutboundQueue::new(pool_at(proxy.port()));

    assert_eq!(
        lossy_queue
            .terminal_acknowledgement_proven(task_id, &sent_file)
            .await
            .unwrap_err(),
        QueueError::Unavailable
    );
    drop(lossy_queue);
    proxy.wait();
    assert_eq!(dump_keys(&direct_pool, &keys).await, before);
    assert!(
        LegacyOutboundQueue::new(direct_pool)
            .terminal_acknowledgement_proven(task_id, &sent_file)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn publish_validation_failures_leave_redis_bytes_unchanged() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let base_id = 9_007_199_254_742_200_i64;
    let base_task = task(base_id);
    let base_keys = vec![
        format!("botmail:mail:queue:task:{base_id}"),
        format!("botmail:mail:queue:domains:{base_id}"),
        "botmail:mail:queue:sentfile_index".into(),
        "botmail:mail:queue:pending".into(),
        "botmail:mail:queue:processing".into(),
        "botmail:mail:queue:processing_time".into(),
        "botmail:mail:queue:retry".into(),
    ];
    assert!(queue.publish(&base_task, &domains()).await.unwrap());

    let before = dump_keys(&pool, &base_keys).await;
    let mut conflicting_domains = domains();
    conflicting_domains.get_mut("remote.test").unwrap().status = "FAILED".into();
    assert_eq!(
        queue
            .publish_bounded(&base_task, &conflicting_domains, 8)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    assert_eq!(dump_keys(&pool, &base_keys).await, before);

    let wrong_task_id = base_id + 1;
    let wrong_task_key = format!("botmail:mail:queue:task:{wrong_task_id}");
    let wrong_task_keys = vec![
        wrong_task_key.clone(),
        format!("botmail:mail:queue:domains:{wrong_task_id}"),
        "botmail:mail:queue:sentfile_index".into(),
        "botmail:mail:queue:pending".into(),
        "botmail:mail:queue:processing".into(),
        "botmail:mail:queue:processing_time".into(),
        "botmail:mail:queue:retry".into(),
    ];
    let mut connection = pool.get().await.unwrap();
    redis::cmd("RPUSH")
        .arg(&wrong_task_key)
        .arg("wrong-type-task")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let before = dump_keys(&pool, &wrong_task_keys).await;
    assert_eq!(
        queue
            .publish_bounded(&task(wrong_task_id), &domains(), 8)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    assert_eq!(dump_keys(&pool, &wrong_task_keys).await, before);

    let wrong_domain_id = wrong_task_id + 1;
    let wrong_domain_key = format!("botmail:mail:queue:domains:{wrong_domain_id}");
    let wrong_domain_keys = vec![
        format!("botmail:mail:queue:task:{wrong_domain_id}"),
        wrong_domain_key.clone(),
        "botmail:mail:queue:sentfile_index".into(),
        "botmail:mail:queue:pending".into(),
        "botmail:mail:queue:processing".into(),
        "botmail:mail:queue:processing_time".into(),
        "botmail:mail:queue:retry".into(),
    ];
    let mut connection = pool.get().await.unwrap();
    redis::cmd("SET")
        .arg(&wrong_domain_key)
        .arg("wrong-type-domain")
        .query_async::<String>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let before = dump_keys(&pool, &wrong_domain_keys).await;
    assert_eq!(
        queue
            .publish_bounded(&task(wrong_domain_id), &domains(), 8)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    assert_eq!(dump_keys(&pool, &wrong_domain_keys).await, before);

    let sent_conflict_id = wrong_domain_id + 1;
    let mut sent_conflict_task = task(sent_conflict_id);
    sent_conflict_task.sent_file_name = Some("shared-conflict.eml".into());
    let sent_conflict_keys = vec![
        format!("botmail:mail:queue:task:{sent_conflict_id}"),
        format!("botmail:mail:queue:domains:{sent_conflict_id}"),
        "botmail:mail:queue:sentfile_index".into(),
        "botmail:mail:queue:pending".into(),
        "botmail:mail:queue:processing".into(),
        "botmail:mail:queue:processing_time".into(),
        "botmail:mail:queue:retry".into(),
    ];
    let mut connection = pool.get().await.unwrap();
    redis::cmd("HSET")
        .arg("botmail:mail:queue:sentfile_index")
        .arg("shared-conflict.eml")
        .arg(42)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let before = dump_keys(&pool, &sent_conflict_keys).await;
    assert_eq!(
        queue
            .publish_bounded(&sent_conflict_task, &domains(), 8)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    assert_eq!(dump_keys(&pool, &sent_conflict_keys).await, before);
}

async fn assert_wrong_type_claim_is_atomic(corrupt_key: &str, expected_string: bool) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_211_i64;
    let token = "wrong-type:claim";
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let state_keys = settlement_state_keys(task_id, token);
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue
            .claim_next(token, Duration::from_secs(30), now_millis())
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown,
        "claim did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "claim partially mutated Redis before rejecting {corrupt_key}"
    );
}

async fn assert_wrong_type_renew_is_atomic(corrupt_key: &str, expected_string: bool) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_213_i64;
    let token = "wrong-type:renew";
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    let claim = queue
        .claim_next(token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let state_keys = settlement_state_keys(task_id, token);
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue
            .renew_claim(&claim, Duration::from_secs(2), now_millis())
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown,
        "renew did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "renew partially mutated Redis before rejecting {corrupt_key}"
    );

    let lease_key = format!("lmyzmail:mail:queue:lease:{task_id}");
    let attempt_key = format!("lmyzmail:mail:queue:attempt:{token}");
    if corrupt_key != lease_key && corrupt_key != attempt_key {
        let mut connection = pool.get().await.unwrap();
        let lease_ttl: i64 = redis::cmd("PTTL")
            .arg(&lease_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        let attempt_ttl: i64 = redis::cmd("PTTL")
            .arg(&attempt_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(
            lease_ttl > 20_000,
            "renew shortened the lease before failing"
        );
        assert!(
            attempt_ttl > 20_000,
            "renew shortened the attempt receipt before failing"
        );
    }
}

async fn assert_wrong_type_retry_move_is_atomic(corrupt_key: &str) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_214_i64;
    let token = "wrong-type:move-retry";
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    let claim = queue
        .claim_next(token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    let mut retry_task = claim.task.clone().unwrap();
    retry_task.retry_count = 1;
    retry_task.next_retry_at = Some("2026-08-07T00:00:30Z".into());
    let retry_at = now_millis() + 1_000;
    assert!(
        queue
            .schedule_retry(&claim, &retry_task, retry_at)
            .await
            .unwrap()
    );
    replace_with_wrong_type(&pool, corrupt_key, false).await;
    let state_keys = settlement_state_keys(task_id, token);
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue.move_due_retries(retry_at, 8).await.unwrap_err(),
        QueueError::OutcomeUnknown,
        "retry move did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "retry move partially mutated Redis before rejecting {corrupt_key}"
    );
}

async fn assert_wrong_type_expired_recovery_is_atomic(corrupt_key: &str, expected_string: bool) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_215_i64;
    let token = "wrong-type:recover-expired";
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    queue
        .claim_next(token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    let mut connection = pool.get().await.unwrap();
    redis::cmd("DEL")
        .arg(format!("lmyzmail:mail:queue:lease:{task_id}"))
        .arg(format!("lmyzmail:mail:queue:attempt:{token}"))
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let state_keys = settlement_state_keys(task_id, token);
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue
            .recover_expired_claim(task_id, true)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown,
        "expired recovery did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "expired recovery partially mutated Redis before rejecting {corrupt_key}"
    );
}

async fn assert_wrong_type_legacy_claim_is_atomic(corrupt_key: &str, expected_string: bool) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let token = "wrong-type:migration-claim";
    let state_keys = archive_migration_state_keys(token);
    let mut connection = pool.get().await.unwrap();
    redis::cmd("RPUSH")
        .arg(&state_keys[0])
        .arg("record")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("ZADD")
        .arg(&state_keys[6])
        .arg(0)
        .arg("expired-sentinel")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue
            .claim_legacy_list_record(LegacyListKind::Archive, token, 1_024)
            .await
            .unwrap_err(),
        QueueError::Unavailable,
        "legacy claim did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "legacy claim partially mutated Redis before rejecting {corrupt_key}"
    );
}

async fn assert_wrong_type_legacy_ack_is_atomic(corrupt_key: &str, expected_string: bool) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let token = "wrong-type:migration-ack";
    let state_keys = archive_migration_state_keys(token);
    let mut connection = pool.get().await.unwrap();
    redis::cmd("RPUSH")
        .arg(&state_keys[0])
        .arg("record")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("ZADD")
        .arg(&state_keys[6])
        .arg(0)
        .arg("expired-sentinel")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let record = match queue
        .claim_legacy_list_record(LegacyListKind::Archive, token, 1_024)
        .await
        .unwrap()
    {
        LegacyListClaim::Record(record) => record,
        other => panic!("expected migration record, got {other:?}"),
    };
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue
            .acknowledge_legacy_list_record(&record)
            .await
            .unwrap_err(),
        QueueError::Unavailable,
        "legacy acknowledgement did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "legacy acknowledgement partially mutated Redis before rejecting {corrupt_key}"
    );
}

async fn assert_wrong_type_legacy_quarantine_is_atomic(corrupt_key: &str, expected_string: bool) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let token = "wrong-type:migration-quarantine";
    let state_keys = archive_migration_state_keys(token);
    let mut connection = pool.get().await.unwrap();
    redis::cmd("RPUSH")
        .arg(&state_keys[0])
        .arg("record")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("ZADD")
        .arg(&state_keys[6])
        .arg(0)
        .arg("expired-sentinel")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let record = match queue
        .claim_legacy_list_record(LegacyListKind::Archive, token, 1_024)
        .await
        .unwrap()
    {
        LegacyListClaim::Record(record) => record,
        other => panic!("expected migration record, got {other:?}"),
    };
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue
            .quarantine_legacy_list_record(&record, "invalid-json")
            .await
            .unwrap_err(),
        QueueError::Unavailable,
        "legacy quarantine did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "legacy quarantine partially mutated Redis before rejecting {corrupt_key}"
    );
}

async fn assert_wrong_type_migrated_cleanup_is_atomic(corrupt_key: &str, expected_string: bool) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_216_i64;
    let sent_file = "wrong-type-cleanup.eml";
    let state_keys = migrated_cleanup_state_keys(task_id);
    let mut connection = pool.get().await.unwrap();
    let mut pipeline = redis::pipe();
    pipeline
        .cmd("RPUSH")
        .arg(&state_keys[0])
        .arg(task_id)
        .ignore()
        .cmd("SADD")
        .arg(&state_keys[1])
        .arg(42)
        .ignore()
        .cmd("HSET")
        .arg(&state_keys[2])
        .arg(42)
        .arg(now_millis())
        .ignore()
        .cmd("ZADD")
        .arg(&state_keys[3])
        .arg(4_102_444_800_i64)
        .arg(42)
        .ignore()
        .cmd("SET")
        .arg(&state_keys[4])
        .arg("legacy-task")
        .ignore()
        .cmd("HSET")
        .arg(&state_keys[5])
        .arg(sent_file)
        .arg(task_id)
        .ignore()
        .cmd("ZADD")
        .arg(&state_keys[6])
        .arg(0)
        .arg("expired-sentinel")
        .ignore();
    pipeline.query_async::<()>(&mut connection).await.unwrap();
    drop(connection);
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue
            .cleanup_migrated_terminal_task(task_id, Some(sent_file))
            .await
            .unwrap_err(),
        QueueError::Unavailable,
        "migrated cleanup did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "migrated cleanup partially mutated Redis before rejecting {corrupt_key}"
    );
}

async fn assert_wrong_type_active_renew_is_atomic(corrupt_key: &str, expected_string: bool) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_217_i64;
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    let state_keys = legacy_active_task_state_keys(task_id);
    let mut connection = pool.get().await.unwrap();
    for key in [&state_keys[3], &state_keys[4]] {
        redis::cmd("EXPIRE")
            .arg(key)
            .arg(120)
            .query_async::<bool>(&mut connection)
            .await
            .unwrap();
    }
    drop(connection);
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue.renew_active_task(task_id).await.unwrap_err(),
        QueueError::OutcomeUnknown,
        "active task renewal did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "active task renewal partially mutated Redis before rejecting {corrupt_key}"
    );

    if corrupt_key != state_keys[3] && corrupt_key != state_keys[4] {
        let mut connection = pool.get().await.unwrap();
        for key in [&state_keys[3], &state_keys[4]] {
            let ttl: i64 = redis::cmd("TTL")
                .arg(key)
                .query_async(&mut connection)
                .await
                .unwrap();
            assert!(
                (1..=120).contains(&ttl),
                "active task renewal refreshed {key} before failing"
            );
        }
    }
}

async fn assert_wrong_type_complete_check_is_atomic(corrupt_key: &str, expected_string: bool) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_218_i64;
    let published = task(task_id);
    let sent_file = published.sent_file_name.clone().unwrap();
    assert!(queue.publish(&published, &domains()).await.unwrap());
    let state_keys = legacy_active_task_state_keys(task_id);
    let mut connection = pool.get().await.unwrap();
    for key in [&state_keys[3], &state_keys[4]] {
        redis::cmd("EXPIRE")
            .arg(key)
            .arg(120)
            .query_async::<bool>(&mut connection)
            .await
            .unwrap();
    }
    drop(connection);
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue
            .is_complete_task(task_id, &sent_file)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown,
        "complete-task check did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "complete-task check partially mutated Redis before rejecting {corrupt_key}"
    );

    if corrupt_key != state_keys[3] && corrupt_key != state_keys[4] {
        let mut connection = pool.get().await.unwrap();
        for key in [&state_keys[3], &state_keys[4]] {
            let ttl: i64 = redis::cmd("TTL")
                .arg(key)
                .query_async(&mut connection)
                .await
                .unwrap();
            assert!(
                (1..=120).contains(&ttl),
                "complete-task check refreshed {key} before failing"
            );
        }
    }
}

async fn assert_wrong_type_claimed_source_replace_is_atomic(
    corrupt_key: &str,
    expected_string: bool,
) {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_219_i64;
    let token = "wrong-type:replace-source";
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    let claim = queue
        .claim_next(token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    let mut replacement = claim.task.clone().unwrap();
    replacement.message_file_path = Some(format!("/tmp/{task_id}.eml"));
    replacement.signed_content_base64 = None;
    replace_with_wrong_type(&pool, corrupt_key, expected_string).await;
    let state_keys = settlement_state_keys(task_id, token);
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue
            .replace_claimed_task_source(&claim, &replacement)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown,
        "claimed source replacement did not fail closed for {corrupt_key}"
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "claimed source replacement partially mutated Redis before rejecting {corrupt_key}"
    );
}

#[tokio::test]
async fn claim_preflight_rejects_wrong_types_without_partial_state() {
    let task_id = 9_007_199_254_742_211_i64;
    let token = "wrong-type:claim";
    for (key, expected_string) in [
        ("botmail:mail:queue:pending".into(), false),
        ("botmail:mail:queue:processing".into(), false),
        ("botmail:mail:queue:processing_time".into(), false),
        ("lmyzmail:mail:queue:claim-result-index".into(), false),
        (format!("lmyzmail:mail:queue:attempt:{token}"), true),
        (format!("lmyzmail:mail:queue:settlement:{token}"), true),
        (format!("lmyzmail:mail:queue:claim-result:{token}"), true),
        (format!("lmyzmail:mail:queue:lease:{task_id}"), true),
        (format!("botmail:mail:queue:task:{task_id}"), true),
        (format!("botmail:mail:queue:domains:{task_id}"), false),
    ] {
        assert_wrong_type_claim_is_atomic(&key, expected_string).await;
    }
}

#[tokio::test]
async fn renew_preflight_rejects_wrong_types_without_partial_state_or_ttl_changes() {
    let task_id = 9_007_199_254_742_213_i64;
    let token = "wrong-type:renew";
    for (key, expected_string) in [
        ("botmail:mail:queue:processing".into(), false),
        ("botmail:mail:queue:processing_time".into(), false),
        (format!("lmyzmail:mail:queue:lease:{task_id}"), true),
        (format!("lmyzmail:mail:queue:attempt:{token}"), true),
        (format!("botmail:mail:queue:task:{task_id}"), true),
        (format!("botmail:mail:queue:domains:{task_id}"), false),
    ] {
        assert_wrong_type_renew_is_atomic(&key, expected_string).await;
    }
}

#[tokio::test]
async fn retry_move_preflight_rejects_wrong_types_without_partial_state() {
    for key in [
        "botmail:mail:queue:retry",
        "botmail:mail:queue:pending",
        "botmail:mail:queue:processing",
    ] {
        assert_wrong_type_retry_move_is_atomic(key).await;
    }
}

#[tokio::test]
async fn expired_recovery_preflight_rejects_wrong_types_without_partial_state() {
    let task_id = 9_007_199_254_742_215_i64;
    for (key, expected_string) in [
        ("botmail:mail:queue:pending".into(), false),
        ("botmail:mail:queue:processing".into(), false),
        ("botmail:mail:queue:processing_time".into(), false),
        ("botmail:mail:queue:retry".into(), false),
        (format!("lmyzmail:mail:queue:lease:{task_id}"), true),
    ] {
        assert_wrong_type_expired_recovery_is_atomic(&key, expected_string).await;
    }
}

#[tokio::test]
async fn legacy_claim_preflight_rejects_every_wrong_type_without_partial_state() {
    let token = "wrong-type:migration-claim";
    for (key, expected_string) in [
        ("botmail:mail:queue:archive".into(), false),
        (
            "lmyzmail:mail:queue:migration:archive:inflight".into(),
            false,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:payloads".into(),
            false,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:quarantine".into(),
            false,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:quarantine-metadata".into(),
            false,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:quarantine-bytes".into(),
            true,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:done-index".into(),
            false,
        ),
        (
            format!("lmyzmail:mail:queue:migration:archive:done:{token}"),
            true,
        ),
    ] {
        assert_wrong_type_legacy_claim_is_atomic(&key, expected_string).await;
    }
}

#[tokio::test]
async fn legacy_ack_preflight_rejects_every_wrong_type_without_partial_state() {
    let token = "wrong-type:migration-ack";
    for (key, expected_string) in [
        (
            "lmyzmail:mail:queue:migration:archive:inflight".into(),
            false,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:payloads".into(),
            false,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:done-index".into(),
            false,
        ),
        (
            format!("lmyzmail:mail:queue:migration:archive:done:{token}"),
            true,
        ),
    ] {
        assert_wrong_type_legacy_ack_is_atomic(&key, expected_string).await;
    }
}

#[tokio::test]
async fn legacy_quarantine_preflight_rejects_every_wrong_type_without_partial_state() {
    let token = "wrong-type:migration-quarantine";
    for (key, expected_string) in [
        (
            "lmyzmail:mail:queue:migration:archive:inflight".into(),
            false,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:payloads".into(),
            false,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:quarantine".into(),
            false,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:quarantine-metadata".into(),
            false,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:quarantine-bytes".into(),
            true,
        ),
        (
            "lmyzmail:mail:queue:migration:archive:done-index".into(),
            false,
        ),
        (
            format!("lmyzmail:mail:queue:migration:archive:done:{token}"),
            true,
        ),
    ] {
        assert_wrong_type_legacy_quarantine_is_atomic(&key, expected_string).await;
    }
}

#[tokio::test]
async fn migrated_cleanup_preflight_rejects_every_wrong_type_without_partial_state() {
    let task_id = 9_007_199_254_742_216_i64;
    for (key, expected_string) in [
        ("botmail:mail:queue:pending".into(), false),
        ("botmail:mail:queue:processing".into(), false),
        ("botmail:mail:queue:processing_time".into(), false),
        ("botmail:mail:queue:retry".into(), false),
        (format!("botmail:mail:queue:task:{task_id}"), true),
        ("botmail:mail:queue:sentfile_index".into(), false),
        ("lmyzmail:mail:queue:migration:cleanup-index".into(), false),
        (format!("lmyzmail:mail:queue:lease:{task_id}"), true),
        (
            format!("lmyzmail:mail:queue:migration:cleanup:{task_id}"),
            true,
        ),
    ] {
        assert_wrong_type_migrated_cleanup_is_atomic(&key, expected_string).await;
    }
}

#[tokio::test]
async fn task_id_reservation_rejects_corrupt_and_exhausted_sequences_without_mutation() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let sequence_key = "botmail:mail:queue:seq".to_string();
    assert_eq!(
        queue.reserve_task_id(i64::MAX).await.unwrap_err(),
        QueueError::InvalidTask("task ID space is exhausted")
    );
    assert_eq!(
        dump_keys(&pool, std::slice::from_ref(&sequence_key)).await,
        vec![None]
    );

    let mut connection = pool.get().await.unwrap();
    redis::cmd("SET")
        .arg(&sequence_key)
        .arg("not-an-integer")
        .query_async::<String>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let before = dump_keys(&pool, std::slice::from_ref(&sequence_key)).await;
    assert_eq!(
        queue.reserve_task_id(10).await.unwrap_err(),
        QueueError::OutcomeUnknown
    );
    assert_eq!(
        dump_keys(&pool, std::slice::from_ref(&sequence_key)).await,
        before
    );

    let mut connection = pool.get().await.unwrap();
    redis::cmd("SET")
        .arg(&sequence_key)
        .arg(i64::MAX)
        .query_async::<String>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let before = dump_keys(&pool, std::slice::from_ref(&sequence_key)).await;
    assert_eq!(
        queue.reserve_task_id(0).await.unwrap_err(),
        QueueError::OutcomeUnknown
    );
    assert_eq!(
        dump_keys(&pool, std::slice::from_ref(&sequence_key)).await,
        before
    );

    let mut connection = pool.get().await.unwrap();
    redis::cmd("DEL")
        .arg(&sequence_key)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(queue.reserve_task_id(i64::MAX - 1).await.unwrap(), i64::MAX);
}

#[tokio::test]
async fn active_task_renew_preflight_rejects_every_wrong_type_without_ttl_changes() {
    let task_id = 9_007_199_254_742_217_i64;
    for (key, expected_string) in [
        ("botmail:mail:queue:pending".into(), false),
        ("botmail:mail:queue:processing".into(), false),
        ("botmail:mail:queue:retry".into(), false),
        (format!("botmail:mail:queue:task:{task_id}"), true),
        (format!("botmail:mail:queue:domains:{task_id}"), false),
    ] {
        assert_wrong_type_active_renew_is_atomic(&key, expected_string).await;
    }
}

#[tokio::test]
async fn complete_task_preflight_rejects_every_wrong_type_without_ttl_changes() {
    let task_id = 9_007_199_254_742_218_i64;
    for (key, expected_string) in [
        (format!("botmail:mail:queue:task:{task_id}"), true),
        (format!("botmail:mail:queue:domains:{task_id}"), false),
        ("botmail:mail:queue:sentfile_index".into(), false),
        ("botmail:mail:queue:pending".into(), false),
        ("botmail:mail:queue:processing".into(), false),
        ("botmail:mail:queue:retry".into(), false),
    ] {
        assert_wrong_type_complete_check_is_atomic(&key, expected_string).await;
    }
}

#[tokio::test]
async fn claimed_source_replace_preflight_rejects_every_wrong_type_without_overwrite() {
    let task_id = 9_007_199_254_742_219_i64;
    let token = "wrong-type:replace-source";
    for (key, expected_string) in [
        ("botmail:mail:queue:processing".into(), false),
        (format!("lmyzmail:mail:queue:lease:{task_id}"), true),
        (format!("lmyzmail:mail:queue:attempt:{token}"), true),
        (format!("botmail:mail:queue:task:{task_id}"), true),
    ] {
        assert_wrong_type_claimed_source_replace_is_atomic(&key, expected_string).await;
    }
}

#[tokio::test]
async fn claim_preflight_rejects_malformed_ids_and_oversized_tasks_without_dequeue() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let token = "invalid-id:claim";
    let pending_key = "botmail:mail:queue:pending".to_string();
    let invalid_attempt = format!("lmyzmail:mail:queue:attempt:{token}");
    let invalid_settlement = format!("lmyzmail:mail:queue:settlement:{token}");
    let invalid_result = format!("lmyzmail:mail:queue:claim-result:{token}");
    let invalid_keys = vec![
        pending_key.clone(),
        "botmail:mail:queue:processing".into(),
        "botmail:mail:queue:processing_time".into(),
        "lmyzmail:mail:queue:claim-result-index".into(),
        invalid_attempt,
        invalid_settlement,
        invalid_result,
    ];
    let mut connection = pool.get().await.unwrap();
    redis::cmd("RPUSH")
        .arg(&pending_key)
        .arg("not-a-task-id")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let before = dump_keys(&pool, &invalid_keys).await;
    assert_eq!(
        queue
            .claim_next(token, Duration::from_secs(30), now_millis())
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    assert_eq!(dump_keys(&pool, &invalid_keys).await, before);

    let mut connection = pool.get().await.unwrap();
    redis::cmd("DEL")
        .arg(&pending_key)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("RPUSH")
        .arg(&pending_key)
        .arg("9223372036854775808")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let before = dump_keys(&pool, &invalid_keys).await;
    assert_eq!(
        queue
            .claim_next(token, Duration::from_secs(30), now_millis())
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    assert_eq!(dump_keys(&pool, &invalid_keys).await, before);

    let task_id = 9_007_199_254_742_212_i64;
    let oversized_token = "oversized-task:claim";
    let oversized_queue = LegacyOutboundQueue::new(pool.clone());
    let mut connection = pool.get().await.unwrap();
    redis::cmd("DEL")
        .arg(&pending_key)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(
        oversized_queue
            .publish(&task(task_id), &domains())
            .await
            .unwrap()
    );
    let task_key = format!("botmail:mail:queue:task:{task_id}");
    let mut connection = pool.get().await.unwrap();
    redis::cmd("SET")
        .arg(&task_key)
        .arg(vec![b'x'; 2 * 1024 * 1024 + 1])
        .query_async::<String>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let oversized_keys = settlement_state_keys(task_id, oversized_token);
    let before = dump_keys(&pool, &oversized_keys).await;
    assert_eq!(
        oversized_queue
            .claim_next(oversized_token, Duration::from_secs(30), now_millis())
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    assert_eq!(dump_keys(&pool, &oversized_keys).await, before);
}

#[tokio::test]
async fn claim_lease_collision_restores_pending_reference() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_210_i64;
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());

    let lease_key = format!("lmyzmail:mail:queue:lease:{task_id}");
    let mut connection = pool.get().await.unwrap();
    redis::cmd("SET")
        .arg(&lease_key)
        .arg("existing-holder")
        .arg("PX")
        .arg(30_000)
        .query_async::<String>(&mut connection)
        .await
        .unwrap();
    drop(connection);

    assert!(
        queue
            .claim_next("collision:token", Duration::from_secs(30), now_millis())
            .await
            .unwrap()
            .is_none()
    );
    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("LPOS")
            .arg("botmail:mail:queue:pending")
            .arg(task_id)
            .query_async::<Option<i64>>(&mut connection)
            .await
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        redis::cmd("SISMEMBER")
            .arg("botmail:mail:queue:processing")
            .arg(task_id)
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        0
    );
    redis::cmd("DEL")
        .arg(&lease_key)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let claim = queue
        .claim_next("replacement:token", Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.task_id, task_id);
    assert!(queue.acknowledge(&claim).await.unwrap());
}

#[tokio::test]
async fn publish_bounded_is_atomic_and_idempotent() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let first_id = 9_007_199_254_742_000_i64;
    let second_id = first_id + 1;

    assert!(
        queue
            .publish_bounded(&task(first_id), &domains(), 1)
            .await
            .unwrap()
    );
    assert!(
        !queue
            .publish_bounded(&task(first_id), &domains(), 1)
            .await
            .unwrap(),
        "an already referenced task must remain idempotent at the active cap"
    );
    assert_eq!(
        queue
            .publish_bounded(&task(second_id), &domains(), 1)
            .await
            .unwrap_err(),
        QueueError::Unavailable
    );

    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(format!("botmail:mail:queue:task:{second_id}"))
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(format!("botmail:mail:queue:domains:{second_id}"))
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        redis::cmd("LLEN")
            .arg("botmail:mail:queue:pending")
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn claim_result_index_cap_is_atomic_and_reclaims_expired_members() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_010_i64;
    let token = "cap:claim";
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());

    let mut connection = pool.get().await.unwrap();
    let mut pipeline = redis::pipe();
    for index in 0..4_096 {
        pipeline
            .cmd("ZADD")
            .arg("lmyzmail:mail:queue:claim-result-index")
            .arg(4_102_444_800_000_i64)
            .arg(format!("claim-cap-{index}"))
            .ignore();
    }
    pipeline.query_async::<()>(&mut connection).await.unwrap();
    drop(connection);

    assert_eq!(
        queue
            .claim_next(token, Duration::from_secs(30), now_millis())
            .await
            .unwrap_err(),
        QueueError::Unavailable
    );
    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("LPOS")
            .arg("botmail:mail:queue:pending")
            .arg(task_id)
            .query_async::<Option<i64>>(&mut connection)
            .await
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        redis::cmd("SISMEMBER")
            .arg("botmail:mail:queue:processing")
            .arg(task_id)
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(format!("lmyzmail:mail:queue:attempt:{token}"))
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        0
    );
    redis::cmd("ZADD")
        .arg("lmyzmail:mail:queue:claim-result-index")
        .arg(0)
        .arg("claim-cap-0")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let claim = queue
        .claim_next(token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.task_id, task_id);
    assert!(queue.acknowledge(&claim).await.unwrap());
}

#[tokio::test]
async fn settlement_index_cap_is_atomic_and_reclaims_expired_members() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_020_i64;
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    let claim = queue
        .claim_next("cap:settlement", Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();

    let mut connection = pool.get().await.unwrap();
    let mut pipeline = redis::pipe();
    for index in 0..4_096 {
        pipeline
            .cmd("ZADD")
            .arg("lmyzmail:mail:queue:settlement-index")
            .arg(4_102_444_800_i64)
            .arg(format!("settlement-cap-{index}"))
            .ignore();
    }
    pipeline.query_async::<()>(&mut connection).await.unwrap();
    drop(connection);

    assert_eq!(
        queue.acknowledge(&claim).await.unwrap_err(),
        QueueError::Unavailable
    );
    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("SISMEMBER")
            .arg("botmail:mail:queue:processing")
            .arg(task_id)
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(format!(
                "lmyzmail:mail:queue:settlement:{}",
                claim.lease_token
            ))
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        0
    );
    redis::cmd("ZADD")
        .arg("lmyzmail:mail:queue:settlement-index")
        .arg(0)
        .arg("settlement-cap-0")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);

    assert!(queue.acknowledge(&claim).await.unwrap());
}

#[tokio::test]
async fn leases_fence_retry_recovery_and_acknowledgement() {
    let process = RedisProcess::start();
    let mut properties = Properties::default();
    properties
        .insert("lmyzmail.redis.host".into(), "127.0.0.1".into())
        .unwrap();
    properties
        .insert("lmyzmail.redis.port".into(), process.port().to_string())
        .unwrap();
    let config = RuntimeConfig::from_properties(properties).unwrap();
    let pool = create_pool(&config).unwrap();
    let queue = LegacyOutboundQueue::new(pool.clone());

    let id = 9_007_199_254_740_994_i64;
    assert!(queue.publish(&task(id), &domains()).await.unwrap());
    let claim = queue
        .claim_next("worker-a:token-1", Duration::from_secs(2), now_millis())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.task_id, id);
    assert_eq!(claim.task.as_ref().unwrap().id, id);

    let forged = QueueClaim {
        task_id: id,
        lease_token: "worker-b:forged".into(),
        task: claim.task.clone(),
    };
    assert!(!queue.release_claim(&forged, true).await.unwrap());
    assert!(
        queue
            .renew_claim(&claim, Duration::from_secs(2), now_millis())
            .await
            .unwrap()
    );

    let mut retry_task = claim.task.clone().unwrap();
    retry_task.retry_count = 1;
    retry_task.next_retry_at = Some("2026-08-06T00:00:30Z".into());
    let retry_at = now_millis() + 100;
    assert!(
        queue
            .schedule_retry(&claim, &retry_task, retry_at)
            .await
            .unwrap()
    );
    assert!(
        queue
            .move_due_retries(retry_at - 1, 8)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(queue.move_due_retries(retry_at, 8).await.unwrap(), vec![id]);

    let retry_claim = queue
        .claim_next("worker-a:token-2", Duration::from_secs(2), now_millis())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry_claim.task.as_ref().unwrap().retry_count, 1);
    assert!(queue.acknowledge(&retry_claim).await.unwrap());
    assert!(
        queue
            .claim_next("worker-a:empty", Duration::from_secs(2), now_millis())
            .await
            .unwrap()
            .is_none()
    );

    let recovered_id = id + 1;
    assert!(
        queue
            .publish(&task(recovered_id), &domains())
            .await
            .unwrap()
    );
    let expired = queue
        .claim_next("worker-a:expires", Duration::from_secs(1), now_millis())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let mut cursor = 0;
    let mut expired_ids = Vec::new();
    loop {
        let page = queue.scan_expired_claims(cursor, 8).await.unwrap();
        expired_ids.extend(page.task_ids);
        cursor = page.next_cursor;
        if cursor == 0 {
            break;
        }
    }
    assert_eq!(expired_ids, vec![recovered_id]);
    assert!(
        queue
            .recover_expired_claim(expired.task_id, true)
            .await
            .unwrap()
    );
    let recovered = queue
        .claim_next("worker-b:recovered", Duration::from_secs(2), now_millis())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.task_id, recovered_id);
    assert!(queue.acknowledge(&recovered).await.unwrap());

    let mut connection = pool.get().await.unwrap();
    let processing: i64 = redis::cmd("SCARD")
        .arg("botmail:mail:queue:processing")
        .query_async(&mut connection)
        .await
        .unwrap();
    let pending: i64 = redis::cmd("LLEN")
        .arg("botmail:mail:queue:pending")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!((processing, pending), (0, 0));
}

#[tokio::test]
async fn domain_statuses_are_bounded_validated_and_lease_fenced() {
    let process = RedisProcess::start();
    let mut properties = Properties::default();
    properties
        .insert("lmyzmail.redis.host".into(), "127.0.0.1".into())
        .unwrap();
    properties
        .insert("lmyzmail.redis.port".into(), process.port().to_string())
        .unwrap();
    let config = RuntimeConfig::from_properties(properties).unwrap();
    let pool = create_pool(&config).unwrap();
    let queue = LegacyOutboundQueue::new(pool.clone());

    let id = 9_007_199_254_741_100_i64;
    let initial = two_domains();
    let expected = initial.keys().cloned().collect::<BTreeSet<_>>();
    assert!(queue.publish(&task(id), &initial).await.unwrap());
    assert_eq!(
        queue.read_persisted_domain_statuses(id).await.unwrap(),
        initial
    );
    assert!(
        queue
            .read_persisted_domain_statuses(id + 1)
            .await
            .unwrap()
            .is_empty()
    );
    let claim = queue
        .claim_next(
            "worker-domain:token-1",
            Duration::from_secs(30),
            now_millis(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        queue.read_domain_statuses(&claim, &expected).await.unwrap(),
        initial
    );

    let key = format!("botmail:mail:queue:domains:{id}");
    let updated = DomainStatus {
        domain: "remote.test".into(),
        status: "SENDING".into(),
        error: None,
        recipients: vec!["user@remote.test".into()],
        updated_at: "2026-08-07T00:00:00.123Z".into(),
    };
    let updates = BTreeMap::from([("remote.test".into(), updated.clone())]);
    {
        let mut connection = pool.get().await.unwrap();
        let expired: i64 = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(5)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(expired, 1);
    }
    queue
        .update_domain_statuses(&claim, &expected, &updates)
        .await
        .unwrap();
    let statuses = queue.read_domain_statuses(&claim, &expected).await.unwrap();
    assert_eq!(statuses["remote.test"], updated);
    assert_eq!(statuses["other.test"], initial["other.test"]);
    assert_eq!(
        queue.read_persisted_domain_statuses(id).await.unwrap(),
        statuses
    );
    {
        let mut connection = pool.get().await.unwrap();
        let ttl_millis: i64 = redis::cmd("PTTL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!((604_799_000..=604_800_000).contains(&ttl_millis));
    }

    let forged = QueueClaim {
        task_id: id,
        lease_token: "worker-domain:forged".into(),
        task: claim.task.clone(),
    };
    assert_eq!(
        queue
            .read_domain_statuses(&forged, &expected)
            .await
            .unwrap_err(),
        QueueError::StaleClaim
    );
    let before_forged = {
        let mut connection = pool.get().await.unwrap();
        let _: i64 = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(5)
            .query_async(&mut connection)
            .await
            .unwrap();
        redis::cmd("HMGET")
            .arg(&key)
            .arg("other.test")
            .arg("remote.test")
            .query_async::<Vec<String>>(&mut connection)
            .await
            .unwrap()
    };
    assert_eq!(
        queue
            .update_domain_statuses(&forged, &expected, &updates)
            .await
            .unwrap_err(),
        QueueError::StaleClaim
    );
    {
        let mut connection = pool.get().await.unwrap();
        let after: Vec<String> = redis::cmd("HMGET")
            .arg(&key)
            .arg("other.test")
            .arg("remote.test")
            .query_async(&mut connection)
            .await
            .unwrap();
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(after, before_forged);
        assert!((1..=5).contains(&ttl));

        let removed: i64 = redis::cmd("SREM")
            .arg("botmail:mail:queue:processing")
            .arg(id)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(removed, 1);
    }
    assert_eq!(
        queue
            .update_domain_statuses(&claim, &expected, &updates)
            .await
            .unwrap_err(),
        QueueError::StaleClaim
    );
    {
        let mut connection = pool.get().await.unwrap();
        let added: i64 = redis::cmd("SADD")
            .arg("botmail:mail:queue:processing")
            .arg(id)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(added, 1);
    }

    let too_many = (0..=1_000)
        .map(|index| {
            let domain = format!("d{index}.test");
            (
                domain.clone(),
                DomainStatus {
                    domain,
                    status: "PENDING".into(),
                    error: None,
                    recipients: vec![format!("u{index}@d{index}.test")],
                    updated_at: "2026-08-07T00:00:00Z".into(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        queue
            .update_domain_statuses(&claim, &expected, &too_many)
            .await
            .unwrap_err(),
        QueueError::InvalidTask("invalid domain status update bound")
    );
    let too_many_expected = too_many.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        queue
            .read_domain_statuses(&claim, &too_many_expected)
            .await
            .unwrap_err(),
        QueueError::InvalidTask("invalid expected domain set")
    );

    let atomic_remote = DomainStatus {
        status: "SENT".into(),
        updated_at: "2026-08-07T00:01:00Z".into(),
        ..statuses["remote.test"].clone()
    };
    let missing_domain = DomainStatus {
        domain: "z-missing.test".into(),
        status: "SENT".into(),
        error: None,
        recipients: vec!["user@z-missing.test".into()],
        updated_at: "2026-08-07T00:01:00Z".into(),
    };
    let invalid_batch = BTreeMap::from([
        ("remote.test".into(), atomic_remote),
        ("z-missing.test".into(), missing_domain),
    ]);
    assert_eq!(
        queue
            .update_domain_statuses(&claim, &expected, &invalid_batch)
            .await
            .unwrap_err(),
        QueueError::InvalidTask("invalid domain status update")
    );
    assert_eq!(
        queue.read_domain_statuses(&claim, &expected).await.unwrap(),
        statuses,
        "a rejected batch must not partially update its existing fields"
    );

    let good_remote_json = serde_json::to_string(&statuses["remote.test"]).unwrap();
    let good_other_json = serde_json::to_string(&statuses["other.test"]).unwrap();
    let other_updates = BTreeMap::from([(
        "other.test".into(),
        DomainStatus {
            status: "SENT".into(),
            updated_at: "2026-08-07T00:02:00Z".into(),
            ..statuses["other.test"].clone()
        },
    )]);
    {
        let mut connection = pool.get().await.unwrap();
        let _: i64 = redis::cmd("HSET")
            .arg(&key)
            .arg("remote.test")
            .arg("{not-json")
            .query_async(&mut connection)
            .await
            .unwrap();
        let _: i64 = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(5)
            .query_async(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue
            .read_domain_statuses(&claim, &expected)
            .await
            .unwrap_err(),
        QueueError::CorruptDomainStatuses
    );
    assert_eq!(
        queue
            .update_domain_statuses(&claim, &expected, &other_updates)
            .await
            .unwrap_err(),
        QueueError::CorruptDomainStatuses
    );
    {
        let mut connection = pool.get().await.unwrap();
        let malformed: String = redis::cmd("HGET")
            .arg(&key)
            .arg("remote.test")
            .query_async(&mut connection)
            .await
            .unwrap();
        let unchanged_other: String = redis::cmd("HGET")
            .arg(&key)
            .arg("other.test")
            .query_async(&mut connection)
            .await
            .unwrap();
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(malformed, "{not-json");
        assert_eq!(unchanged_other, good_other_json);
        assert!((1..=5).contains(&ttl));
        let _: i64 = redis::cmd("HSET")
            .arg(&key)
            .arg("remote.test")
            .arg(&good_remote_json)
            .query_async(&mut connection)
            .await
            .unwrap();
    }

    let mismatched = DomainStatus {
        domain: "forged.test".into(),
        ..statuses["remote.test"].clone()
    };
    let mismatched_json = serde_json::to_string(&mismatched).unwrap();
    {
        let mut connection = pool.get().await.unwrap();
        let _: i64 = redis::cmd("HSET")
            .arg(&key)
            .arg("remote.test")
            .arg(&mismatched_json)
            .query_async(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue
            .read_domain_statuses(&claim, &expected)
            .await
            .unwrap_err(),
        QueueError::CorruptDomainStatuses
    );
    assert_eq!(
        queue
            .update_domain_statuses(&claim, &expected, &updates)
            .await
            .unwrap_err(),
        QueueError::CorruptDomainStatuses
    );
    {
        let mut connection = pool.get().await.unwrap();
        let unchanged: String = redis::cmd("HGET")
            .arg(&key)
            .arg("remote.test")
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(unchanged, mismatched_json);
        let _: i64 = redis::cmd("HSET")
            .arg(&key)
            .arg("remote.test")
            .arg(&good_remote_json)
            .query_async(&mut connection)
            .await
            .unwrap();
    }

    let unexpected = DomainStatus {
        domain: "unexpected.test".into(),
        status: "PENDING".into(),
        error: None,
        recipients: vec!["user@unexpected.test".into()],
        updated_at: "2026-08-07T00:00:00Z".into(),
    };
    let unexpected_json = serde_json::to_string(&unexpected).unwrap();
    {
        let mut connection = pool.get().await.unwrap();
        let added: i64 = redis::cmd("HSET")
            .arg(&key)
            .arg("unexpected.test")
            .arg(&unexpected_json)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(added, 1);
    }
    assert_eq!(
        queue
            .read_domain_statuses(&claim, &expected)
            .await
            .unwrap_err(),
        QueueError::CorruptDomainStatuses
    );
    assert_eq!(
        queue
            .update_domain_statuses(&claim, &expected, &updates)
            .await
            .unwrap_err(),
        QueueError::CorruptDomainStatuses
    );
    {
        let mut connection = pool.get().await.unwrap();
        let removed: i64 = redis::cmd("HDEL")
            .arg(&key)
            .arg("unexpected.test")
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(removed, 1);

        let removed: i64 = redis::cmd("HDEL")
            .arg(&key)
            .arg("remote.test")
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(removed, 1);
        let added: i64 = redis::cmd("HSET")
            .arg(&key)
            .arg("unexpected.test")
            .arg(&unexpected_json)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(added, 1);
    }
    assert_eq!(
        queue
            .read_domain_statuses(&claim, &expected)
            .await
            .unwrap_err(),
        QueueError::CorruptDomainStatuses,
        "an equal-sized hash with the wrong field set must be rejected"
    );
    assert_eq!(
        queue
            .update_domain_statuses(&claim, &expected, &updates)
            .await
            .unwrap_err(),
        QueueError::CorruptDomainStatuses
    );
    {
        let mut connection = pool.get().await.unwrap();
        let _: i64 = redis::cmd("HDEL")
            .arg(&key)
            .arg("unexpected.test")
            .query_async(&mut connection)
            .await
            .unwrap();
        let _: i64 = redis::cmd("HSET")
            .arg(&key)
            .arg("remote.test")
            .arg(&good_remote_json)
            .query_async(&mut connection)
            .await
            .unwrap();
    }

    let oversized = "x".repeat(2 * 1024 * 1024 + 1);
    {
        let mut connection = pool.get().await.unwrap();
        let _: i64 = redis::cmd("HSET")
            .arg(&key)
            .arg("remote.test")
            .arg(&oversized)
            .query_async(&mut connection)
            .await
            .unwrap();
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg("default")
            .arg("-HGET")
            .query_async::<()>(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue
            .read_domain_statuses(&claim, &expected)
            .await
            .unwrap_err(),
        QueueError::CorruptDomainStatuses,
        "oversized values must be rejected by HSTRLEN before HGET"
    );
    assert_eq!(
        queue
            .update_domain_statuses(&claim, &expected, &updates)
            .await
            .unwrap_err(),
        QueueError::CorruptDomainStatuses,
        "updates must not HGET an oversized existing value"
    );
    {
        let mut connection = pool.get().await.unwrap();
        redis::cmd("ACL")
            .arg("SETUSER")
            .arg("default")
            .arg("+HGET")
            .query_async::<()>(&mut connection)
            .await
            .unwrap();
        let value_bytes: i64 = redis::cmd("HSTRLEN")
            .arg(&key)
            .arg("remote.test")
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(value_bytes, 2 * 1024 * 1024 + 1);
        let deleted: i64 = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(deleted, 1);
    }
    assert_eq!(
        queue
            .read_domain_statuses(&claim, &expected)
            .await
            .unwrap_err(),
        QueueError::MissingDomainStatuses
    );
    assert_eq!(
        queue
            .update_domain_statuses(&claim, &expected, &updates)
            .await
            .unwrap_err(),
        QueueError::MissingDomainStatuses
    );
    {
        let mut connection = pool.get().await.unwrap();
        let exists: i64 = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(exists, 0);
    }
}

#[tokio::test]
async fn claim_reconciliation_preflight_does_not_clean_index_for_malformed_state() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let token = "reconcile:wrong-result-type";
    let attempt_key = format!("lmyzmail:mail:queue:attempt:{token}");
    let result_key = format!("lmyzmail:mail:queue:claim-result:{token}");
    let result_index_key = "lmyzmail:mail:queue:claim-result-index".to_string();
    let state_keys = vec![
        attempt_key,
        "botmail:mail:queue:processing".into(),
        "botmail:mail:queue:processing_time".into(),
        result_key.clone(),
        result_index_key.clone(),
    ];
    let mut connection = pool.get().await.unwrap();
    redis::cmd("HSET")
        .arg(&result_key)
        .arg("wrong")
        .arg("type")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("ZADD")
        .arg(&result_index_key)
        .arg(4_102_444_800_i64)
        .arg(token)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let before = dump_keys(&pool, &state_keys).await;

    assert_eq!(
        queue.reconcile_claim(token).await.unwrap(),
        ClaimReconciliation::Inconsistent
    );
    assert_eq!(
        dump_keys(&pool, &state_keys).await,
        before,
        "claim reconciliation cleaned the result index before rejecting malformed state"
    );
}

#[tokio::test]
async fn reconciliation_validates_every_claim_component() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let id = 9_007_199_254_741_200_i64;
    let token = "reconcile:component-check";
    let claimed_at = now_millis();
    assert!(queue.publish(&task(id), &domains()).await.unwrap());
    let claim = queue
        .claim_next(token, Duration::from_secs(30), claimed_at)
        .await
        .unwrap()
        .unwrap();

    let active = match queue.reconcile_claim(token).await.unwrap() {
        ClaimReconciliation::Active(active) => active,
        result => panic!("expected active reconciliation, got {result:?}"),
    };
    assert_eq!(active.claim, claim);
    assert_eq!(active.processing_time_epoch_millis, claimed_at);
    assert!((1..=30_000).contains(&active.lease_ttl_millis));
    assert_eq!(
        queue.reconcile_claim("reconcile:absent").await.unwrap(),
        ClaimReconciliation::NotFound
    );

    let attempt_key = format!("lmyzmail:mail:queue:attempt:{token}");
    let lease_key = format!("lmyzmail:mail:queue:lease:{id}");
    let task_key = format!("botmail:mail:queue:task:{id}");
    let original_task_json = serde_json::to_string(claim.task.as_ref().unwrap()).unwrap();
    {
        let mut connection = pool.get().await.unwrap();
        let _: String = redis::cmd("SET")
            .arg(&task_key)
            .arg("{broken-json")
            .arg("EX")
            .arg(60)
            .query_async(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue.reconcile_claim(token).await.unwrap(),
        ClaimReconciliation::Inconsistent
    );
    {
        let mut connection = pool.get().await.unwrap();
        let _: String = redis::cmd("SET")
            .arg(&task_key)
            .arg(&original_task_json)
            .arg("EX")
            .arg(60)
            .query_async(&mut connection)
            .await
            .unwrap();
        let _: i64 = redis::cmd("HSET")
            .arg("botmail:mail:queue:processing_time")
            .arg(id)
            .arg("not-a-time")
            .query_async(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue.reconcile_claim(token).await.unwrap(),
        ClaimReconciliation::Inconsistent
    );
    {
        let mut connection = pool.get().await.unwrap();
        let _: i64 = redis::cmd("HSET")
            .arg("botmail:mail:queue:processing_time")
            .arg(id)
            .arg(claimed_at)
            .query_async(&mut connection)
            .await
            .unwrap();
        let _: i64 = redis::cmd("SREM")
            .arg("botmail:mail:queue:processing")
            .arg(id)
            .query_async(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue.reconcile_claim(token).await.unwrap(),
        ClaimReconciliation::Inconsistent
    );
    {
        let mut connection = pool.get().await.unwrap();
        let _: i64 = redis::cmd("SADD")
            .arg("botmail:mail:queue:processing")
            .arg(id)
            .query_async(&mut connection)
            .await
            .unwrap();
        let _: String = redis::cmd("SET")
            .arg(&lease_key)
            .arg("forged-token")
            .arg("PX")
            .arg(30_000)
            .query_async(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue.reconcile_claim(token).await.unwrap(),
        ClaimReconciliation::Inconsistent
    );
    {
        let mut connection = pool.get().await.unwrap();
        let _: String = redis::cmd("SET")
            .arg(&lease_key)
            .arg(token)
            .arg("PX")
            .arg(30_000)
            .query_async(&mut connection)
            .await
            .unwrap();
        let _: String = redis::cmd("SET")
            .arg(&attempt_key)
            .arg(id + 1)
            .arg("PX")
            .arg(30_000)
            .query_async(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue.reconcile_claim(token).await.unwrap(),
        ClaimReconciliation::Inconsistent
    );
    {
        let mut connection = pool.get().await.unwrap();
        let _: String = redis::cmd("SET")
            .arg(&attempt_key)
            .arg(id)
            .arg("PX")
            .arg(30_000)
            .query_async(&mut connection)
            .await
            .unwrap();
        let _: bool = redis::cmd("PEXPIRE")
            .arg(&attempt_key)
            .arg(29_000)
            .query_async(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue.reconcile_claim(token).await.unwrap(),
        ClaimReconciliation::Inconsistent
    );
    assert!(
        queue
            .renew_claim(&claim, Duration::from_secs(30), now_millis())
            .await
            .unwrap()
    );
    assert!(matches!(
        queue.reconcile_claim(token).await.unwrap(),
        ClaimReconciliation::Active(_)
    ));
    assert!(queue.acknowledge(&claim).await.unwrap());
    assert_eq!(
        queue.reconcile_claim(token).await.unwrap(),
        ClaimReconciliation::NotFound
    );
}

#[tokio::test]
async fn committed_mutations_with_dropped_responses_are_reconcilable() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());

    let empty_token = "loss:empty";
    let empty_proxy = DropResponseProxy::start(
        process.port(),
        b"local popped_task_id = redis.call('LPOP', KEYS[1])",
    );
    let lossy_queue = LegacyOutboundQueue::new(pool_at(empty_proxy.port()));
    assert_eq!(
        lossy_queue
            .claim_next(empty_token, Duration::from_secs(30), now_millis())
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    drop(lossy_queue);
    empty_proxy.wait();
    assert_eq!(
        queue.reconcile_claim(empty_token).await.unwrap(),
        ClaimReconciliation::NotFound
    );
    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(format!("lmyzmail:mail:queue:claim-result:{empty_token}"))
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        0,
        "an empty claim must not leave a tombstone"
    );
    drop(connection);
    assert!(
        queue
            .claim_next(empty_token, Duration::from_secs(30), now_millis())
            .await
            .unwrap()
            .is_none(),
        "an empty claim result must be idempotent for the same token"
    );

    let claim_id = 9_007_199_254_741_300_i64;
    let claim_token = "loss:claim";
    assert!(queue.publish(&task(claim_id), &domains()).await.unwrap());
    let claim_proxy = DropResponseProxy::start(
        process.port(),
        b"local popped_task_id = redis.call('LPOP', KEYS[1])",
    );
    let lossy_queue = LegacyOutboundQueue::new(pool_at(claim_proxy.port()));
    assert_eq!(
        lossy_queue
            .claim_next(claim_token, Duration::from_secs(30), now_millis())
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    drop(lossy_queue);
    claim_proxy.wait();
    let claim = match queue.reconcile_claim(claim_token).await.unwrap() {
        ClaimReconciliation::Active(active) => active.claim,
        result => panic!("dropped claim response was not reconcilable: {result:?}"),
    };
    assert_eq!(claim.task_id, claim_id);
    assert_eq!(
        queue
            .claim_next(claim_token, Duration::from_secs(30), now_millis())
            .await
            .unwrap_err(),
        QueueError::AttemptTokenInUse
    );
    assert!(queue.acknowledge(&claim).await.unwrap());

    let renew_id = claim_id + 1;
    let renew_token = "loss:renew";
    assert!(queue.publish(&task(renew_id), &domains()).await.unwrap());
    let renew_claim = queue
        .claim_next(renew_token, Duration::from_secs(5), now_millis())
        .await
        .unwrap()
        .unwrap();
    let renewed_at = now_millis() + 10;
    let renew_proxy =
        DropResponseProxy::start(process.port(), b"local attempt_key = ARGV[9] .. ARGV[2]");
    let lossy_queue = LegacyOutboundQueue::new(pool_at(renew_proxy.port()));
    assert_eq!(
        lossy_queue
            .renew_claim(&renew_claim, Duration::from_secs(30), renewed_at)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    drop(lossy_queue);
    renew_proxy.wait();
    let renewed = match queue.reconcile_claim(renew_token).await.unwrap() {
        ClaimReconciliation::Active(active) => active,
        result => panic!("dropped renew response was not reconcilable: {result:?}"),
    };
    assert_eq!(renewed.processing_time_epoch_millis, renewed_at);
    assert!(renewed.lease_ttl_millis > 20_000);
    assert!(queue.acknowledge(&renew_claim).await.unwrap());

    let retry_id = claim_id + 2;
    let retry_token = "loss:retry";
    assert!(queue.publish(&task(retry_id), &domains()).await.unwrap());
    let retry_claim = queue
        .claim_next(retry_token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    let mut retry_task = retry_claim.task.clone().unwrap();
    retry_task.retry_count = 1;
    retry_task.next_retry_at = Some("2026-08-07T00:00:30Z".into());
    let retry_at = now_millis() + 30_000;
    let retry_proxy = DropResponseProxy::start(
        process.port(),
        b"redis.call('ZADD', KEYS[4], tonumber(ARGV[4]) / 1000, task_id)",
    );
    let lossy_queue = LegacyOutboundQueue::new(pool_at(retry_proxy.port()));
    assert_eq!(
        lossy_queue
            .schedule_retry(&retry_claim, &retry_task, retry_at)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    drop(lossy_queue);
    retry_proxy.wait();
    assert_eq!(
        queue.reconcile_claim(retry_token).await.unwrap(),
        ClaimReconciliation::NotFound
    );
    assert_eq!(
        queue
            .reconcile_settlement(
                &retry_claim,
                QueueSettlement::Retry {
                    task: &retry_task,
                    retry_at_epoch_millis: retry_at,
                },
            )
            .await
            .unwrap(),
        SettlementReconciliation::Applied
    );
    assert!(
        queue
            .schedule_retry(&retry_claim, &retry_task, retry_at)
            .await
            .unwrap(),
        "matching retry receipt must make replay idempotent"
    );
    {
        let mut connection = pool.get().await.unwrap();
        let retry_score: Option<f64> = redis::cmd("ZSCORE")
            .arg("botmail:mail:queue:retry")
            .arg(retry_id)
            .query_async(&mut connection)
            .await
            .unwrap();
        let attempt_exists: i64 = redis::cmd("EXISTS")
            .arg(format!("lmyzmail:mail:queue:attempt:{retry_token}"))
            .query_async(&mut connection)
            .await
            .unwrap();
        let queued_json: String = redis::cmd("GET")
            .arg(format!("botmail:mail:queue:task:{retry_id}"))
            .query_async(&mut connection)
            .await
            .unwrap();
        let queued: TaskDetail = serde_json::from_str(&queued_json).unwrap();
        assert!(retry_score.is_some());
        assert_eq!(attempt_exists, 0);
        assert_eq!(queued.retry_count, 1);
    }
    {
        let mut connection = pool.get().await.unwrap();
        redis::cmd("ZREM")
            .arg("botmail:mail:queue:retry")
            .arg(retry_id)
            .query_async::<i64>(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue
            .reconcile_settlement(
                &retry_claim,
                QueueSettlement::Retry {
                    task: &retry_task,
                    retry_at_epoch_millis: retry_at,
                },
            )
            .await
            .unwrap(),
        SettlementReconciliation::Inconsistent,
        "a receipt without the exact retry postcondition must fail closed"
    );

    let ack_id = claim_id + 3;
    let ack_token = "loss:ack";
    assert!(queue.publish(&task(ack_id), &domains()).await.unwrap());
    let ack_claim = queue
        .claim_next(ack_token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    let ack_proxy =
        DropResponseProxy::start(process.port(), b"redis.call('DEL', lease_key, attempt_key)");
    let lossy_queue = LegacyOutboundQueue::new(pool_at(ack_proxy.port()));
    assert_eq!(
        lossy_queue.acknowledge(&ack_claim).await.unwrap_err(),
        QueueError::OutcomeUnknown
    );
    drop(lossy_queue);
    ack_proxy.wait();
    assert_eq!(
        queue.reconcile_claim(ack_token).await.unwrap(),
        ClaimReconciliation::NotFound
    );
    assert_eq!(
        queue
            .reconcile_settlement(&ack_claim, QueueSettlement::Acknowledge)
            .await
            .unwrap(),
        SettlementReconciliation::Applied
    );
    assert!(queue.acknowledge(&ack_claim).await.unwrap());
    {
        let mut connection = pool.get().await.unwrap();
        let task_exists: i64 = redis::cmd("EXISTS")
            .arg(format!("botmail:mail:queue:task:{ack_id}"))
            .query_async(&mut connection)
            .await
            .unwrap();
        let domains_exists: i64 = redis::cmd("EXISTS")
            .arg(format!("botmail:mail:queue:domains:{ack_id}"))
            .query_async(&mut connection)
            .await
            .unwrap();
        let sent_index: Option<String> = redis::cmd("HGET")
            .arg("botmail:mail:queue:sentfile_index")
            .arg(format!("{ack_id}.eml"))
            .query_async(&mut connection)
            .await
            .unwrap();
        let processing: i64 = redis::cmd("SISMEMBER")
            .arg("botmail:mail:queue:processing")
            .arg(ack_id)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!((task_exists, domains_exists, processing), (0, 1, 0));
        assert_eq!(sent_index, None);
    }

    let release_id = claim_id + 4;
    let release_token = "loss:release";
    assert!(queue.publish(&task(release_id), &domains()).await.unwrap());
    let release_claim = queue
        .claim_next(release_token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    let release_proxy = DropResponseProxy::start(process.port(), b"if ARGV[3] == '1'");
    let lossy_queue = LegacyOutboundQueue::new(pool_at(release_proxy.port()));
    assert_eq!(
        lossy_queue
            .release_claim(&release_claim, true)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    drop(lossy_queue);
    release_proxy.wait();
    assert_eq!(
        queue.reconcile_claim(release_token).await.unwrap(),
        ClaimReconciliation::NotFound
    );
    assert_eq!(
        queue
            .reconcile_settlement(&release_claim, QueueSettlement::Release { requeue: true },)
            .await
            .unwrap(),
        SettlementReconciliation::Applied
    );
    assert!(queue.release_claim(&release_claim, true).await.unwrap());
    {
        let mut connection = pool.get().await.unwrap();
        let pending_position: Option<i64> = redis::cmd("LPOS")
            .arg("botmail:mail:queue:pending")
            .arg(release_id)
            .query_async(&mut connection)
            .await
            .unwrap();
        let attempt_exists: i64 = redis::cmd("EXISTS")
            .arg(format!("lmyzmail:mail:queue:attempt:{release_token}"))
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(pending_position.is_some());
        assert_eq!(attempt_exists, 0);
    }

    let expired_id = claim_id + 5;
    let expired_token = "loss:expired-without-settlement";
    assert!(queue.publish(&task(expired_id), &domains()).await.unwrap());
    let expired_claim = queue
        .claim_next(expired_token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    {
        let mut connection = pool.get().await.unwrap();
        redis::cmd("DEL")
            .arg(format!("lmyzmail:mail:queue:lease:{expired_id}"))
            .arg(format!("lmyzmail:mail:queue:attempt:{expired_token}"))
            .query_async::<i64>(&mut connection)
            .await
            .unwrap();
    }
    assert_eq!(
        queue
            .reconcile_settlement(&expired_claim, QueueSettlement::Acknowledge)
            .await
            .unwrap(),
        SettlementReconciliation::NotFound,
        "lease disappearance without a matching receipt is not completion proof"
    );
    assert!(!queue.acknowledge(&expired_claim).await.unwrap());

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let unavailable_port = listener.local_addr().unwrap().port();
    drop(listener);
    let unavailable_queue = LegacyOutboundQueue::new(pool_at(unavailable_port));
    assert_eq!(
        unavailable_queue
            .claim_next("loss:before-connect", Duration::from_secs(30), now_millis())
            .await
            .unwrap_err(),
        QueueError::Unavailable,
        "failure before a Redis connection exists must not be OutcomeUnknown"
    );
}

#[tokio::test]
async fn delayed_retry_request_cannot_settle_an_expired_lease() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_741_400_i64;
    let token = "delay:expired-retry";
    assert!(queue.publish(&task(task_id), &domains()).await.unwrap());
    let claim = queue
        .claim_next(token, Duration::from_secs(1), now_millis())
        .await
        .unwrap()
        .unwrap();
    let mut retry_task = claim.task.clone().unwrap();
    retry_task.retry_count = 1;
    retry_task.next_retry_at = Some("2026-08-07T00:00:30Z".into());
    let retry_at = now_millis() + 30_000;

    let proxy = DelayRequestProxy::start(
        process.port(),
        b"redis.call('ZADD', KEYS[4], tonumber(ARGV[4]) / 1000, task_id)",
        Duration::from_millis(5_250),
    );
    let delayed_queue = LegacyOutboundQueue::new(pool_at(proxy.port()));
    assert_eq!(
        delayed_queue
            .schedule_retry(&claim, &retry_task, retry_at)
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    drop(delayed_queue);
    proxy.wait();

    assert_eq!(
        queue
            .reconcile_settlement(
                &claim,
                QueueSettlement::Retry {
                    task: &retry_task,
                    retry_at_epoch_millis: retry_at,
                },
            )
            .await
            .unwrap(),
        SettlementReconciliation::NotFound
    );
    let mut connection = pool.get().await.unwrap();
    let retry_score: Option<f64> = redis::cmd("ZSCORE")
        .arg("botmail:mail:queue:retry")
        .arg(task_id)
        .query_async(&mut connection)
        .await
        .unwrap();
    let queued_json: String = redis::cmd("GET")
        .arg(format!("botmail:mail:queue:task:{task_id}"))
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(retry_score.is_none());
    assert_eq!(
        serde_json::from_str::<TaskDetail>(&queued_json)
            .unwrap()
            .retry_count,
        0
    );
    assert!(queue.recover_expired_claim(task_id, true).await.unwrap());
    let mut connection = pool.get().await.unwrap();
    let pending: Option<i64> = redis::cmd("LPOS")
        .arg("botmail:mail:queue:pending")
        .arg(task_id)
        .query_async(&mut connection)
        .await
        .unwrap();
    let processing: bool = redis::cmd("SISMEMBER")
        .arg("botmail:mail:queue:processing")
        .arg(task_id)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(pending.is_some());
    assert!(!processing);
}

#[tokio::test]
async fn legacy_list_migration_claims_are_crash_recoverable_and_quarantined_without_loss() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let mut connection = pool.get().await.unwrap();
    redis::cmd("RPUSH")
        .arg("botmail:mail:queue:archive")
        .arg("first-record")
        .arg("invalid-record")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("RPUSH")
        .arg("botmail:mail:queue:status_updates")
        .arg("oversized")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let first = match queue
        .claim_legacy_list_record(LegacyListKind::Archive, "migration:first", 1_024)
        .await
        .unwrap()
    {
        LegacyListClaim::Record(record) => record,
        other => panic!("expected the first archive record, got {other:?}"),
    };
    assert_eq!(first.payload, "first-record");

    let recovered = match queue
        .claim_legacy_list_record(LegacyListKind::Archive, "migration:restart", 1_024)
        .await
        .unwrap()
    {
        LegacyListClaim::Record(record) => record,
        other => panic!("expected the inflight archive record, got {other:?}"),
    };
    assert_eq!(recovered, first);
    assert!(queue.acknowledge_legacy_list_record(&first).await.unwrap());
    assert!(queue.acknowledge_legacy_list_record(&first).await.unwrap());
    assert_eq!(
        queue
            .claim_legacy_list_record(LegacyListKind::Archive, "migration:first", 1_024)
            .await
            .unwrap(),
        LegacyListClaim::Settled
    );

    let invalid = match queue
        .claim_legacy_list_record(LegacyListKind::Archive, "migration:invalid", 1_024)
        .await
        .unwrap()
    {
        LegacyListClaim::Record(record) => record,
        other => panic!("expected the second archive record, got {other:?}"),
    };
    assert!(
        queue
            .quarantine_legacy_list_record(&invalid, "invalid-json")
            .await
            .unwrap()
    );
    assert!(
        queue
            .quarantine_legacy_list_record(&invalid, "invalid-json")
            .await
            .unwrap()
    );

    let oversized = queue
        .claim_legacy_list_record(LegacyListKind::StatusUpdates, "migration:oversized", 3)
        .await
        .unwrap();
    assert!(matches!(
        oversized,
        LegacyListClaim::Quarantined(ref item)
            if item.bytes == "oversized".len() && item.sha1.len() == 40
    ));

    let mut connection = pool.get().await.unwrap();
    let archive_source: i64 = redis::cmd("LLEN")
        .arg("botmail:mail:queue:archive")
        .query_async(&mut connection)
        .await
        .unwrap();
    let archive_inflight: i64 = redis::cmd("LLEN")
        .arg("lmyzmail:mail:queue:migration:archive:inflight")
        .query_async(&mut connection)
        .await
        .unwrap();
    let archive_quarantine: Vec<String> = redis::cmd("LRANGE")
        .arg("lmyzmail:mail:queue:migration:archive:quarantine")
        .arg(0)
        .arg(-1)
        .query_async(&mut connection)
        .await
        .unwrap();
    let status_source: i64 = redis::cmd("LLEN")
        .arg("botmail:mail:queue:status_updates")
        .query_async(&mut connection)
        .await
        .unwrap();
    let status_quarantine: Vec<String> = redis::cmd("LRANGE")
        .arg("lmyzmail:mail:queue:migration:status-updates:quarantine")
        .arg(0)
        .arg(-1)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(archive_source, 0);
    assert_eq!(archive_inflight, 0);
    assert_eq!(archive_quarantine, vec!["invalid-record"]);
    assert_eq!(status_source, 0);
    assert_eq!(status_quarantine, vec!["oversized"]);
}

#[tokio::test]
async fn migration_done_receipt_index_cap_is_atomic_and_reclaims_expired_members() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let mut connection = pool.get().await.unwrap();
    redis::cmd("RPUSH")
        .arg("botmail:mail:queue:archive")
        .arg("ack-record")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let ack_record = match queue
        .claim_legacy_list_record(LegacyListKind::Archive, "cap:ack", 1_024)
        .await
        .unwrap()
    {
        LegacyListClaim::Record(record) => record,
        other => panic!("expected an ack record, got {other:?}"),
    };
    let done_index = "lmyzmail:mail:queue:migration:archive:done-index";
    let mut connection = pool.get().await.unwrap();
    let mut pipeline = redis::pipe();
    for index in 0..4_096 {
        pipeline
            .cmd("ZADD")
            .arg(done_index)
            .arg(4_102_444_800_i64)
            .arg(format!("done-cap-{index}"))
            .ignore();
    }
    pipeline.query_async::<()>(&mut connection).await.unwrap();
    drop(connection);

    assert_eq!(
        queue
            .acknowledge_legacy_list_record(&ack_record)
            .await
            .unwrap_err(),
        QueueError::Unavailable
    );
    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("LLEN")
            .arg("lmyzmail:mail:queue:migration:archive:inflight")
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        redis::cmd("HGET")
            .arg("lmyzmail:mail:queue:migration:archive:payloads")
            .arg("cap:ack")
            .query_async::<Option<String>>(&mut connection)
            .await
            .unwrap(),
        Some("ack-record".into())
    );
    redis::cmd("ZADD")
        .arg(done_index)
        .arg(0)
        .arg("done-cap-0")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(
        queue
            .acknowledge_legacy_list_record(&ack_record)
            .await
            .unwrap()
    );

    let mut connection = pool.get().await.unwrap();
    redis::cmd("RPUSH")
        .arg("botmail:mail:queue:archive")
        .arg("quarantine-record")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let quarantine_record = match queue
        .claim_legacy_list_record(LegacyListKind::Archive, "cap:quarantine", 1_024)
        .await
        .unwrap()
    {
        LegacyListClaim::Record(record) => record,
        other => panic!("expected a quarantine record, got {other:?}"),
    };
    assert_eq!(
        queue
            .quarantine_legacy_list_record(&quarantine_record, "invalid-json")
            .await
            .unwrap_err(),
        QueueError::Unavailable
    );
    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("LLEN")
            .arg("lmyzmail:mail:queue:migration:archive:inflight")
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        1
    );
    redis::cmd("ZADD")
        .arg(done_index)
        .arg(0)
        .arg("done-cap-1")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(
        queue
            .quarantine_legacy_list_record(&quarantine_record, "invalid-json")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn cleanup_receipt_index_cap_is_atomic_and_reclaims_expired_members() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_742_100_i64;
    let sent_file = "bounded-cleanup.eml";
    let task_key = format!("botmail:mail:queue:task:{task_id}");
    let domain_key = format!("botmail:mail:queue:domains:{task_id}");
    let mut connection = pool.get().await.unwrap();
    redis::cmd("SET")
        .arg(&task_key)
        .arg("legacy-detail")
        .query_async::<String>(&mut connection)
        .await
        .unwrap();
    redis::cmd("HSET")
        .arg(&domain_key)
        .arg("remote.test")
        .arg("legacy-domain-status")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("EXPIRE")
        .arg(&domain_key)
        .arg(604_800)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("RPUSH")
        .arg("botmail:mail:queue:pending")
        .arg(task_id)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("HSET")
        .arg("botmail:mail:queue:sentfile_index")
        .arg(sent_file)
        .arg(task_id)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    let mut pipeline = redis::pipe();
    for index in 0..4_096 {
        pipeline
            .cmd("ZADD")
            .arg("lmyzmail:mail:queue:migration:cleanup-index")
            .arg(4_102_444_800_i64)
            .arg(format!("cleanup-cap-{index}"))
            .ignore();
    }
    pipeline.query_async::<()>(&mut connection).await.unwrap();
    drop(connection);

    assert_eq!(
        queue
            .cleanup_migrated_terminal_task(task_id, Some(sent_file))
            .await
            .unwrap_err(),
        QueueError::Unavailable
    );
    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(&task_key)
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        redis::cmd("LPOS")
            .arg("botmail:mail:queue:pending")
            .arg(task_id)
            .query_async::<Option<i64>>(&mut connection)
            .await
            .unwrap(),
        Some(0)
    );
    assert_eq!(
        redis::cmd("HGET")
            .arg("botmail:mail:queue:sentfile_index")
            .arg(sent_file)
            .query_async::<Option<String>>(&mut connection)
            .await
            .unwrap(),
        Some(task_id.to_string())
    );
    redis::cmd("ZADD")
        .arg("lmyzmail:mail:queue:migration:cleanup-index")
        .arg(0)
        .arg("cleanup-cap-0")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);

    queue
        .cleanup_migrated_terminal_task(task_id, Some(sent_file))
        .await
        .unwrap();
    let mut connection = pool.get().await.unwrap();
    let receipt_key = format!("lmyzmail:mail:queue:migration:cleanup:{task_id}");
    let receipt_ttl: i64 = redis::cmd("TTL")
        .arg(&receipt_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!((1..=300).contains(&receipt_ttl));
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(&domain_key)
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn migration_terminal_cleanup_receipt_proves_all_redis_postconditions() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let task_id = 9_007_199_254_741_600_i64;
    let sent_file = "legacy.eml";
    let alias_file = "legacy-copy.eml";
    let mut connection = pool.get().await.unwrap();
    redis::cmd("SET")
        .arg(format!("botmail:mail:queue:task:{task_id}"))
        .arg("legacy-detail")
        .query_async::<String>(&mut connection)
        .await
        .unwrap();
    redis::cmd("HSET")
        .arg(format!("botmail:mail:queue:domains:{task_id}"))
        .arg("remote.test")
        .arg("legacy-domain-status")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("EXPIRE")
        .arg(format!("botmail:mail:queue:domains:{task_id}"))
        .arg(604_800)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("RPUSH")
        .arg("botmail:mail:queue:pending")
        .arg(task_id)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    for (file_name, indexed_task_id) in [
        (sent_file, task_id),
        (alias_file, task_id),
        ("other.eml", 42),
    ] {
        redis::cmd("HSET")
            .arg("botmail:mail:queue:sentfile_index")
            .arg(file_name)
            .arg(indexed_task_id)
            .query_async::<i64>(&mut connection)
            .await
            .unwrap();
    }
    drop(connection);

    let proxy = DropResponseProxy::start(process.port(), b"local receipt_key = ARGV[5] .. task_id");
    let lossy_queue = LegacyOutboundQueue::new(pool_at(proxy.port()));
    assert_eq!(
        lossy_queue
            .cleanup_migrated_terminal_task(task_id, Some(sent_file))
            .await
            .unwrap_err(),
        QueueError::OutcomeUnknown
    );
    drop(lossy_queue);
    proxy.wait();

    assert!(
        queue
            .cleanup_migrated_terminal_task(task_id, Some(sent_file))
            .await
            .is_ok()
    );
    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(format!("botmail:mail:queue:task:{task_id}"))
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(format!("botmail:mail:queue:domains:{task_id}"))
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        1
    );
    assert!(
        redis::cmd("TTL")
            .arg(format!("botmail:mail:queue:domains:{task_id}"))
            .query_async::<i64>(&mut connection)
            .await
            .unwrap()
            > 0
    );
    assert_eq!(
        redis::cmd("LPOS")
            .arg("botmail:mail:queue:pending")
            .arg(task_id)
            .query_async::<Option<i64>>(&mut connection)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        redis::cmd("HGET")
            .arg("botmail:mail:queue:sentfile_index")
            .arg(sent_file)
            .query_async::<Option<String>>(&mut connection)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        redis::cmd("HGET")
            .arg("botmail:mail:queue:sentfile_index")
            .arg(alias_file)
            .query_async::<Option<String>>(&mut connection)
            .await
            .unwrap(),
        Some(task_id.to_string())
    );
    assert_eq!(
        redis::cmd("HGET")
            .arg("botmail:mail:queue:sentfile_index")
            .arg("other.eml")
            .query_async::<Option<String>>(&mut connection)
            .await
            .unwrap(),
        Some("42".into())
    );
    let mut expected_receipt = String::from("CLEANED:");
    for byte in Sha256::digest(sent_file.as_bytes()) {
        expected_receipt.push_str(&format!("{byte:02x}"));
    }
    assert_eq!(
        redis::cmd("GET")
            .arg(format!("lmyzmail:mail:queue:migration:cleanup:{task_id}"))
            .query_async::<String>(&mut connection)
            .await
            .unwrap(),
        expected_receipt
    );

    assert_eq!(
        queue
            .cleanup_migrated_terminal_task(task_id, Some(alias_file))
            .await
            .unwrap_err(),
        QueueError::Unavailable,
        "a receipt for one filename must not settle a different filename"
    );

    let empty_task_id = task_id + 1;
    redis::cmd("SET")
        .arg(format!("botmail:mail:queue:task:{empty_task_id}"))
        .arg("legacy-empty-detail")
        .query_async::<String>(&mut connection)
        .await
        .unwrap();
    redis::cmd("HSET")
        .arg(format!("botmail:mail:queue:domains:{empty_task_id}"))
        .arg("remote.test")
        .arg("legacy-empty-domain-status")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("EXPIRE")
        .arg(format!("botmail:mail:queue:domains:{empty_task_id}"))
        .arg(604_800)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    redis::cmd("RPUSH")
        .arg("botmail:mail:queue:pending")
        .arg(empty_task_id)
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    queue
        .cleanup_migrated_terminal_task(empty_task_id, None)
        .await
        .unwrap();
    let mut connection = pool.get().await.unwrap();
    let mut empty_receipt = String::from("CLEANED:");
    for byte in Sha256::digest(b"") {
        empty_receipt.push_str(&format!("{byte:02x}"));
    }
    assert_eq!(
        redis::cmd("GET")
            .arg(format!(
                "lmyzmail:mail:queue:migration:cleanup:{empty_task_id}"
            ))
            .query_async::<String>(&mut connection)
            .await
            .unwrap(),
        empty_receipt
    );
    assert_eq!(
        queue
            .cleanup_migrated_terminal_task(empty_task_id, Some(""))
            .await
            .unwrap(),
        (),
        "None and an empty filename share the canonical empty digest"
    );

    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/outbound_queue.rs"
    ));
    let cleanup_start = source
        .find("const CLEANUP_MIGRATED_TERMINAL_TASK_SCRIPT")
        .expect("cleanup script must remain present");
    let cleanup_source = &source[cleanup_start
        ..source[cleanup_start..]
            .find("const RENEW_SCRIPT")
            .map(|offset| cleanup_start + offset)
            .expect("cleanup script must have a following declaration")];
    let hscan = ["H", "SCAN"].concat();
    let scan_limit = ["MAX_SENT_FILE_INDEX_", "SCAN_ENTRIES"].concat();
    assert!(
        !cleanup_source.contains(&hscan),
        "queue Lua must not scan sent-file indexes"
    );
    assert!(
        !source.contains(&scan_limit),
        "legacy sent-file scan limit must be removed"
    );
}

#[tokio::test]
async fn legacy_quarantine_has_hard_record_and_byte_limits_without_source_loss() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool.clone());
    let mut connection = pool.get().await.unwrap();
    let mut pipeline = redis::pipe();
    for index in 0..4_096 {
        pipeline
            .cmd("RPUSH")
            .arg("lmyzmail:mail:queue:migration:archive:quarantine")
            .arg("q")
            .ignore()
            .cmd("HSET")
            .arg("lmyzmail:mail:queue:migration:archive:quarantine-metadata")
            .arg(format!("existing-{index}"))
            .arg("1:0000000000000000000000000000000000000000:x")
            .ignore();
    }
    pipeline.query_async::<()>(&mut connection).await.unwrap();
    redis::cmd("RPUSH")
        .arg("botmail:mail:queue:archive")
        .arg("oversized")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);

    assert_eq!(
        queue
            .claim_legacy_list_record(LegacyListKind::Archive, "migration:full-count", 3)
            .await
            .unwrap_err(),
        QueueError::Unavailable
    );
    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("LLEN")
            .arg("botmail:mail:queue:archive")
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        1
    );
    drop(connection);

    let mut connection = pool.get().await.unwrap();
    redis::cmd("SET")
        .arg("lmyzmail:mail:queue:migration:status-updates:quarantine-bytes")
        .arg(64 * 1024 * 1024)
        .query_async::<String>(&mut connection)
        .await
        .unwrap();
    redis::cmd("RPUSH")
        .arg("botmail:mail:queue:status_updates")
        .arg("oversized")
        .query_async::<i64>(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        queue
            .claim_legacy_list_record(LegacyListKind::StatusUpdates, "migration:full-bytes", 3)
            .await
            .unwrap_err(),
        QueueError::Unavailable
    );
    let mut connection = pool.get().await.unwrap();
    assert_eq!(
        redis::cmd("LLEN")
            .arg("botmail:mail:queue:status_updates")
            .query_async::<i64>(&mut connection)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn stale_claim_scan_waits_for_processing_timeout_after_lease_expiry() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port());
    let queue = LegacyOutboundQueue::new(pool);
    let now = now_millis();
    let old_id = 9_007_199_254_741_501_i64;
    let recent_id = old_id + 1;
    assert!(queue.publish(&task(old_id), &domains()).await.unwrap());
    assert!(queue.publish(&task(recent_id), &domains()).await.unwrap());
    queue
        .claim_next("stale-scan:old", Duration::from_secs(1), now - 120_000)
        .await
        .unwrap()
        .unwrap();
    queue
        .claim_next("stale-scan:recent", Duration::from_secs(1), now)
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let page = queue
        .scan_stale_expired_claims(0, 16, now - 60_000)
        .await
        .unwrap();
    assert_eq!(page.next_cursor, 0);
    assert_eq!(page.task_ids, vec![old_id]);
    assert!(queue.recover_expired_claim(old_id, true).await.unwrap());

    let recent_page = queue
        .scan_stale_expired_claims(0, 16, now + 1)
        .await
        .unwrap();
    assert_eq!(recent_page.task_ids, vec![recent_id]);
}
