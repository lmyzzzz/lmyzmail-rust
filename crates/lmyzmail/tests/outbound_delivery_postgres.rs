#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, TimeZone, Utc};
use lmyzmail::{
    config::{Properties, RuntimeConfig},
    database,
    outbound_delivery::{
        DeliveryAttemptId, DeliveryRowStatus, DeliveryStateError, PostgresDeliveryState,
        TerminalStatus,
    },
};

struct PostgresProcess {
    child: Child,
    directory: PathBuf,
    port: u16,
}

impl PostgresProcess {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let root = repository.join(".blackbox/runtime/postgres-root");
        let binary_directory = root.join("usr/lib/postgresql/16/bin");
        let library_directory = root.join("usr/lib/x86_64-linux-gnu");
        let initdb = binary_directory.join("initdb");
        let postgres = binary_directory.join("postgres");
        let pg_isready = binary_directory.join("pg_isready");
        assert!(initdb.is_file(), "PostgreSQL initdb missing");
        assert!(postgres.is_file(), "PostgreSQL server missing");
        assert!(pg_isready.is_file(), "PostgreSQL pg_isready missing");
        assert!(library_directory.is_dir());

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "lmyzmail-postgres-delivery-{}-{nonce}",
            std::process::id()
        ));
        let data_directory = directory.join("data");
        let socket_directory = directory.join("socket");
        fs::create_dir_all(&socket_directory).unwrap();

        let initialize = Command::new(initdb)
            .args([
                "--pgdata",
                data_directory.to_str().unwrap(),
                "--username=lmyzmail_test",
                "--auth=trust",
                "--encoding=UTF8",
                "--no-locale",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("LD_LIBRARY_PATH", &library_directory)
            .status()
            .unwrap();
        assert!(initialize.success(), "PostgreSQL initdb failed");

        let child = Command::new(postgres)
            .args([
                "-D",
                data_directory.to_str().unwrap(),
                "-h",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-k",
                socket_directory.to_str().unwrap(),
                "-F",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("LD_LIBRARY_PATH", &library_directory)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let ready = Command::new(&pg_isready)
                .args([
                    "--host=127.0.0.1",
                    &format!("--port={port}"),
                    "--username=lmyzmail_test",
                    "--dbname=postgres",
                    "--timeout=1",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .env("LD_LIBRARY_PATH", &library_directory)
                .status()
                .unwrap();
            if ready.success() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "PostgreSQL test process did not start"
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

impl Drop for PostgresProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if self
            .directory
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with("lmyzmail-postgres-delivery-"))
        {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

fn timestamp(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}

fn configuration(port: u16) -> RuntimeConfig {
    let mut properties = Properties::default();
    for (key, value) in [
        ("lmyzmail.postgres.host", "127.0.0.1".to_owned()),
        ("lmyzmail.postgres.port", port.to_string()),
        ("lmyzmail.postgres.database", "postgres".to_owned()),
        ("lmyzmail.postgres.username", "lmyzmail_test".to_owned()),
        ("lmyzmail.postgres.password", String::new()),
        ("lmyzmail.postgres.pool.max-size", "4".to_owned()),
    ] {
        properties.insert(key.to_owned(), value).unwrap();
    }
    RuntimeConfig::from_properties(properties).unwrap()
}

async fn insert_pending(
    pool: &deadpool_postgres::Pool,
    id: i64,
    retry_count: i32,
    max_retries: i32,
    now: DateTime<Utc>,
) {
    let client = pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO outbound_mail_queue
             (id,sender_address,recipients_json,status,retry_count,max_retries,
              next_retry_at,created_at,updated_at)
             VALUES ($1,'qa@example.test','[\"user@remote.test\"]','PENDING',$2,$3,$4,$4,$4)",
            &[&id, &retry_count, &max_retries, &now],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn postgres_claims_fence_retries_terminal_state_and_recovery() {
    let process = PostgresProcess::start();
    let pool = database::create_pool(&configuration(process.port())).unwrap();
    let client = pool.get().await.unwrap();
    let legacy_ddl = include_str!("../../../blackbox/fixtures/legacy/postgres-longtext-oracle.sql")
        .replace("LONGTEXT", "TEXT");
    client.batch_execute(&legacy_ddl).await.unwrap();
    drop(client);

    let state = PostgresDeliveryState::new(pool.clone());
    let now = timestamp(1_786_000_000);
    insert_pending(&pool, 4_001, 0, 2, now).await;

    let attempt_a = DeliveryAttemptId::generate(4_001, "worker-a:claim-1").unwrap();
    let attempt_b = DeliveryAttemptId::generate(4_001, "worker-b:claim-1").unwrap();
    let (claim_a, claim_b) = tokio::join!(
        state.claim_with_attempt(&attempt_a, now),
        state.claim_with_attempt(&attempt_b, now),
    );
    let claim_a = claim_a.unwrap();
    let claim_b = claim_b.unwrap();
    assert_ne!(claim_a.is_some(), claim_b.is_some());
    let (first_claim, first_attempt) = match (claim_a, claim_b) {
        (Some(claim), None) => (claim, &attempt_a),
        (None, Some(claim)) => (claim, &attempt_b),
        _ => unreachable!(),
    };
    let claimed_snapshot = state
        .snapshot_attempt(first_attempt)
        .await
        .unwrap()
        .unwrap();
    assert!(claimed_snapshot.owned_by_claim);
    assert_eq!(first_attempt.task_id(), 4_001);
    assert!(!first_attempt.lease_token().is_empty());

    assert!(
        state
            .release(&first_claim, now + chrono::Duration::seconds(1))
            .await
            .unwrap()
    );
    let second_attempt = DeliveryAttemptId::generate(4_001, "worker-a:claim-1").unwrap();
    let second_claim = state
        .claim_with_attempt(&second_attempt, now + chrono::Duration::seconds(1))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(first_claim, second_claim);
    assert!(
        !state
            .heartbeat(&first_claim, now + chrono::Duration::seconds(2))
            .await
            .unwrap()
    );
    assert!(
        state
            .heartbeat(&second_claim, now + chrono::Duration::seconds(2))
            .await
            .unwrap()
    );

    let retry_at = now + chrono::Duration::seconds(32);
    let retry = state
        .schedule_retry(
            &second_claim,
            retry_at,
            "temporary\nremote failure",
            now + chrono::Duration::seconds(2),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry.retry_count, 1);
    assert!(
        state
            .claim(
                4_001,
                "worker-d:too-early",
                retry_at - chrono::Duration::seconds(1)
            )
            .await
            .unwrap()
            .is_none()
    );
    let terminal_claim = state
        .claim(4_001, "worker-d:claim-3", retry_at)
        .await
        .unwrap()
        .unwrap();
    let failed = BTreeMap::from([("failed.example".into(), "550 rejected".into())]);
    assert!(
        state
            .mark_terminal(
                &terminal_claim,
                TerminalStatus::PartialSuccess,
                &["sent.example".into()],
                &failed,
                Some("one domain rejected"),
                retry_at + chrono::Duration::seconds(1),
            )
            .await
            .unwrap()
    );

    let client = pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT status,retry_count,last_error,sent_domains_json,failed_domains_json,
                    sent_at,processor_id,processing_started_at
             FROM outbound_mail_queue WHERE id=4001",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "PARTIAL_SUCCESS");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert_eq!(
        row.get::<_, Option<String>>(2).as_deref(),
        Some("one domain rejected")
    );
    assert_eq!(
        row.get::<_, Option<String>>(3).as_deref(),
        Some("[\"sent.example\"]")
    );
    assert_eq!(
        row.get::<_, Option<String>>(4).as_deref(),
        Some("{\"failed.example\":\"550 rejected\"}")
    );
    assert!(row.get::<_, Option<DateTime<Utc>>>(5).is_some());
    assert!(row.get::<_, Option<String>>(6).is_none());
    assert!(row.get::<_, Option<DateTime<Utc>>>(7).is_none());
    drop(client);
    let snapshot = state
        .snapshot(4_001, Some(&terminal_claim))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot.status,
        lmyzmail::outbound_delivery::DeliveryRowStatus::PartialSuccess
    );
    assert!(!snapshot.has_owner);
    assert!(!snapshot.owned_by_claim);

    insert_pending(&pool, 4_002, 1, 1, now).await;
    let exhausted = state
        .claim(4_002, "worker-a:exhausted", now)
        .await
        .unwrap()
        .unwrap();
    assert!(
        state
            .schedule_retry(
                &exhausted,
                now + chrono::Duration::seconds(30),
                "still temporary",
                now + chrono::Duration::seconds(1),
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .mark_terminal(
                &exhausted,
                TerminalStatus::Failed,
                &[],
                &BTreeMap::from([("failed.example".into(), "retry limit".into())]),
                Some("retry limit"),
                now + chrono::Duration::seconds(2),
            )
            .await
            .unwrap()
    );

    insert_pending(&pool, 4_004, 0, 1, now).await;
    let local_failure = state
        .claim(4_004, "worker-a:local-failure", now)
        .await
        .unwrap()
        .unwrap();
    assert!(
        state
            .mark_terminal(
                &local_failure,
                TerminalStatus::Failed,
                &[],
                &BTreeMap::new(),
                Some("local message source is missing"),
                now + chrono::Duration::seconds(2),
            )
            .await
            .unwrap()
    );
    let local_failure = state.snapshot(4_004, None).await.unwrap().unwrap();
    assert_eq!(
        local_failure.status,
        lmyzmail::outbound_delivery::DeliveryRowStatus::Failed
    );

    insert_pending(&pool, 4_006, 1, 1, now).await;
    let mixed_exhausted = state
        .claim(4_006, "worker-a:mixed-exhausted", now)
        .await
        .unwrap()
        .unwrap();
    assert!(
        state
            .mark_terminal(
                &mixed_exhausted,
                TerminalStatus::Failed,
                &["sent.example".into()],
                &BTreeMap::from([("failed.example".into(), "retry limit".into())]),
                Some("retry limit after partial delivery"),
                now + chrono::Duration::seconds(2),
            )
            .await
            .unwrap()
    );
    let client = pool.get().await.unwrap();
    let mixed = client
        .query_one(
            "SELECT status,sent_domains_json,failed_domains_json,sent_at
             FROM outbound_mail_queue WHERE id=4006",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(mixed.get::<_, String>(0), "FAILED");
    assert_eq!(
        mixed.get::<_, Option<String>>(1).as_deref(),
        Some("[\"sent.example\"]")
    );
    assert_eq!(
        mixed.get::<_, Option<String>>(2).as_deref(),
        Some("{\"failed.example\":\"retry limit\"}")
    );
    assert!(mixed.get::<_, Option<DateTime<Utc>>>(3).is_none());
    drop(client);

    insert_pending(&pool, 4_007, 3, 2, now).await;
    assert!(
        state
            .claim(4_007, "worker-a:poisoned", now)
            .await
            .unwrap()
            .is_none()
    );
    let client = pool.get().await.unwrap();
    let poisoned = client
        .query_one(
            "SELECT status,last_error,processor_id,processing_started_at
             FROM outbound_mail_queue WHERE id=4007",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(poisoned.get::<_, String>(0), "FAILED");
    assert_eq!(
        poisoned.get::<_, Option<String>>(1).as_deref(),
        Some("Invalid legacy retry state")
    );
    assert!(poisoned.get::<_, Option<String>>(2).is_none());
    assert!(poisoned.get::<_, Option<DateTime<Utc>>>(3).is_none());
    drop(client);
    for (task_id, retry_count, max_retries) in [(4_008, -1, 2), (4_009, 0, -1)] {
        insert_pending(&pool, task_id, retry_count, max_retries, now).await;
        assert!(
            state
                .claim(task_id, "worker-a:poisoned", now)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            state.snapshot(task_id, None).await.unwrap().unwrap().status,
            DeliveryRowStatus::Failed
        );
    }

    let short_state =
        PostgresDeliveryState::with_timeout(pool.clone(), Duration::from_millis(100)).unwrap();
    insert_pending(&pool, 4_010, 0, 2, now).await;
    let lock = pool.get().await.unwrap();
    lock.batch_execute("BEGIN").await.unwrap();
    lock.query_one(
        "SELECT id FROM outbound_mail_queue WHERE id=4010 FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        short_state
            .claim(4_010, "worker-a:unknown-claim", now)
            .await
            .unwrap_err(),
        DeliveryStateError::OutcomeUnknown
    );
    lock.batch_execute("ROLLBACK").await.unwrap();
    drop(lock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let uncertain_claim = state.snapshot(4_010, None).await.unwrap().unwrap();
    match uncertain_claim.status {
        DeliveryRowStatus::Pending => assert!(!uncertain_claim.has_owner),
        DeliveryRowStatus::Processing => {
            assert!(uncertain_claim.has_owner);
            assert!(
                state
                    .recover_expired(
                        4_010,
                        now + chrono::Duration::seconds(5),
                        now + chrono::Duration::seconds(10),
                    )
                    .await
                    .unwrap()
            );
        }
        status => panic!("unexpected claim reconciliation state: {status:?}"),
    }

    insert_pending(&pool, 4_011, 0, 2, now).await;
    let uncertain_retry_claim = state
        .claim(4_011, "worker-a:unknown-retry", now)
        .await
        .unwrap()
        .unwrap();
    let lock = pool.get().await.unwrap();
    lock.batch_execute("BEGIN").await.unwrap();
    lock.query_one(
        "SELECT id FROM outbound_mail_queue WHERE id=4011 FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        short_state
            .schedule_retry(
                &uncertain_retry_claim,
                now + chrono::Duration::seconds(30),
                "temporary failure",
                now + chrono::Duration::seconds(1),
            )
            .await
            .unwrap_err(),
        DeliveryStateError::OutcomeUnknown
    );
    lock.batch_execute("ROLLBACK").await.unwrap();
    drop(lock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let uncertain_retry = state
        .snapshot(4_011, Some(&uncertain_retry_claim))
        .await
        .unwrap()
        .unwrap();
    match uncertain_retry.status {
        DeliveryRowStatus::Pending => {
            assert_eq!(uncertain_retry.retry_count, 1);
            assert!(!uncertain_retry.has_owner);
        }
        DeliveryRowStatus::Processing => {
            assert_eq!(uncertain_retry.retry_count, 0);
            assert!(uncertain_retry.owned_by_claim);
            assert!(
                state
                    .release(&uncertain_retry_claim, now + chrono::Duration::seconds(2),)
                    .await
                    .unwrap()
            );
        }
        status => panic!("unexpected retry reconciliation state: {status:?}"),
    }

    insert_pending(&pool, 4_012, 0, 2, now).await;
    let uncertain_terminal_claim = state
        .claim(4_012, "worker-a:unknown-terminal", now)
        .await
        .unwrap()
        .unwrap();
    let lock = pool.get().await.unwrap();
    lock.batch_execute("BEGIN").await.unwrap();
    lock.query_one(
        "SELECT id FROM outbound_mail_queue WHERE id=4012 FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        short_state
            .mark_terminal(
                &uncertain_terminal_claim,
                TerminalStatus::Sent,
                &["sent.example".into()],
                &BTreeMap::new(),
                None,
                now + chrono::Duration::seconds(1),
            )
            .await
            .unwrap_err(),
        DeliveryStateError::OutcomeUnknown
    );
    lock.batch_execute("ROLLBACK").await.unwrap();
    drop(lock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let uncertain_terminal = state
        .snapshot(4_012, Some(&uncertain_terminal_claim))
        .await
        .unwrap()
        .unwrap();
    match uncertain_terminal.status {
        DeliveryRowStatus::Sent => assert!(!uncertain_terminal.has_owner),
        DeliveryRowStatus::Processing => {
            assert!(uncertain_terminal.owned_by_claim);
            assert!(
                state
                    .mark_terminal(
                        &uncertain_terminal_claim,
                        TerminalStatus::Sent,
                        &["sent.example".into()],
                        &BTreeMap::new(),
                        None,
                        now + chrono::Duration::seconds(2),
                    )
                    .await
                    .unwrap()
            );
        }
        status => panic!("unexpected terminal reconciliation state: {status:?}"),
    }

    insert_pending(&pool, 4_003, 0, 2, now).await;
    let expired = state
        .claim(4_003, "worker-a:expired", now)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !state
            .recover_expired(
                4_003,
                now - chrono::Duration::seconds(1),
                now + chrono::Duration::seconds(10),
            )
            .await
            .unwrap()
    );
    assert!(
        state
            .recover_expired(
                4_003,
                now + chrono::Duration::seconds(5),
                now + chrono::Duration::seconds(10),
            )
            .await
            .unwrap()
    );
    assert!(
        !state
            .heartbeat(&expired, now + chrono::Duration::seconds(11))
            .await
            .unwrap()
    );
    assert!(
        state
            .claim(
                4_003,
                "worker-b:recovered",
                now + chrono::Duration::seconds(10),
            )
            .await
            .unwrap()
            .is_some()
    );

    insert_pending(&pool, 4_005, 0, 1, now).await;
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE outbound_mail_queue
             SET status='PROCESSING',processor_id='legacy-worker',processing_started_at=NULL
             WHERE id=4005",
            &[],
        )
        .await
        .unwrap();
    drop(client);
    assert!(
        state
            .recover_expired(
                4_005,
                now + chrono::Duration::seconds(5),
                now + chrono::Duration::seconds(10),
            )
            .await
            .unwrap()
    );
    assert!(
        state
            .claim(
                4_005,
                "worker-b:legacy-recovery",
                now + chrono::Duration::seconds(10),
            )
            .await
            .unwrap()
            .is_some()
    );
}
