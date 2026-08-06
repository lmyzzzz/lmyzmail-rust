#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use deadpool_redis::redis;
use lmyzmail::{
    config::{Properties, RuntimeConfig},
    outbound_queue::{DomainStatus, LegacyOutboundQueue, QueueClaim, TaskDetail},
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
