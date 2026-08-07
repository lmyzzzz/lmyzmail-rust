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
        ClaimReconciliation, DomainStatus, LegacyOutboundQueue, QueueClaim, QueueError, TaskDetail,
    },
    redis::create_pool,
};

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
    }
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

    let claim_id = 9_007_199_254_741_300_i64;
    let claim_token = "loss:claim";
    assert!(queue.publish(&task(claim_id), &domains()).await.unwrap());
    let claim_proxy = DropResponseProxy::start(
        process.port(),
        b"local task_id = redis.call('LPOP', KEYS[1])",
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

    let ack_id = claim_id + 3;
    let ack_token = "loss:ack";
    assert!(queue.publish(&task(ack_id), &domains()).await.unwrap());
    let ack_claim = queue
        .claim_next(ack_token, Duration::from_secs(30), now_millis())
        .await
        .unwrap()
        .unwrap();
    let ack_proxy =
        DropResponseProxy::start(process.port(), b"redis.call('DEL', ARGV[4] .. task_id)");
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
    {
        let mut connection = pool.get().await.unwrap();
        let task_exists: i64 = redis::cmd("EXISTS")
            .arg(format!("botmail:mail:queue:task:{ack_id}"))
            .query_async(&mut connection)
            .await
            .unwrap();
        let processing: i64 = redis::cmd("SISMEMBER")
            .arg("botmail:mail:queue:processing")
            .arg(ack_id)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!((task_exists, processing), (0, 0));
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
