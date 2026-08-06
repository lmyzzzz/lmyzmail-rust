#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use deadpool_redis::redis;
use lmyzmail::{
    config::{Properties, RuntimeConfig},
    outbound_queue::{DomainStatus, LegacyOutboundQueue, QueueClaim, QueueError, TaskDetail},
    redis::create_pool,
};

struct RedisProcess {
    child: Child,
    directory: PathBuf,
    port: u16,
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
