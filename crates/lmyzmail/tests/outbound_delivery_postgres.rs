#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, TimeZone, Utc};
use lmyzmail::{
    config::{Properties, RuntimeConfig},
    database,
    outbound_delivery::{
        CommitResultStatus, DeliveryAttemptId, DeliveryAttemptPhase, DeliveryRowStatus,
        DeliveryStateError, LegacyProjection, PostgresDeliveryState, PreparedRecipientCheckpoint,
        PreparedRecipientStatus, RecipientDeliveryState, TerminalStatus,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener as TokioTcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const CLAIM_MUTATION_MARKER: &[u8] = b"UPDATE outbound_mail_queue";

struct CancelFailureProxy {
    port: u16,
    mutation_seen: Arc<AtomicBool>,
    mutation_notification: Arc<tokio::sync::Notify>,
    stop_accepting: CancellationToken,
    release_responses: CancellationToken,
    accept_task: Option<JoinHandle<()>>,
}

impl CancelFailureProxy {
    async fn start(upstream_port: u16) -> Self {
        let listener = TokioTcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mutation_seen = Arc::new(AtomicBool::new(false));
        let mutation_notification = Arc::new(tokio::sync::Notify::new());
        let stop_accepting = CancellationToken::new();
        let release_responses = CancellationToken::new();

        let task_mutation_seen = Arc::clone(&mutation_seen);
        let task_mutation_notification = Arc::clone(&mutation_notification);
        let task_stop_accepting = stop_accepting.clone();
        let task_release_responses = release_responses.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = task_stop_accepting.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((client, _)) = accepted else {
                    break;
                };
                let Ok(server) = TcpStream::connect(("127.0.0.1", upstream_port)).await else {
                    continue;
                };
                let connection_mutation_seen = Arc::clone(&task_mutation_seen);
                let connection_notification = Arc::clone(&task_mutation_notification);
                let connection_release = task_release_responses.clone();
                tokio::spawn(async move {
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    let client_to_server = async {
                        let mut buffer = [0_u8; 8 * 1024];
                        let mut marker_tail = Vec::new();
                        loop {
                            let count = client_read.read(&mut buffer).await?;
                            if count == 0 {
                                break;
                            }
                            marker_tail.extend_from_slice(&buffer[..count]);
                            if marker_tail
                                .windows(CLAIM_MUTATION_MARKER.len())
                                .any(|window| window == CLAIM_MUTATION_MARKER)
                            {
                                connection_mutation_seen.store(true, Ordering::SeqCst);
                                connection_notification.notify_waiters();
                            }
                            let retained = CLAIM_MUTATION_MARKER.len().saturating_sub(1);
                            if marker_tail.len() > retained {
                                marker_tail.drain(..marker_tail.len() - retained);
                            }
                            server_write.write_all(&buffer[..count]).await?;
                        }
                        server_write.shutdown().await
                    };
                    let server_to_client = async {
                        let mut buffer = [0_u8; 8 * 1024];
                        loop {
                            let count = server_read.read(&mut buffer).await?;
                            if count == 0 {
                                break;
                            }
                            if connection_mutation_seen.load(Ordering::SeqCst) {
                                connection_release.cancelled().await;
                            }
                            client_write.write_all(&buffer[..count]).await?;
                        }
                        client_write.shutdown().await
                    };
                    let _ = tokio::join!(client_to_server, server_to_client);
                });
            }
        });

        Self {
            port,
            mutation_seen,
            mutation_notification,
            stop_accepting,
            release_responses,
            accept_task: Some(accept_task),
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn wait_for_claim_mutation(&self) {
        while !self.mutation_seen.load(Ordering::SeqCst) {
            self.mutation_notification.notified().await;
        }
    }

    async fn refuse_new_connections(&mut self) {
        self.stop_accepting.cancel();
        if let Some(task) = self.accept_task.take() {
            task.await.unwrap();
        }
        assert!(
            TcpStream::connect(("127.0.0.1", self.port)).await.is_err(),
            "proxy port must refuse the fallback CancelRequest connection"
        );
    }
}

impl Drop for CancelFailureProxy {
    fn drop(&mut self) {
        self.stop_accepting.cancel();
        self.release_responses.cancel();
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }
    }
}

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

async fn assert_no_waiting_mutation(pool: &deadpool_postgres::Pool) {
    let client = pool.get().await.unwrap();
    let waiting: i64 = client
        .query_one(
            "SELECT count(*) FROM pg_stat_activity
             WHERE datname=current_database() AND pid<>pg_backend_pid()
               AND state='active' AND wait_event_type='Lock'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(waiting, 0, "timed-out PostgreSQL mutation is still active");
}

#[tokio::test]
async fn server_deadline_prevents_late_claim_when_cancel_transport_is_refused() {
    let process = PostgresProcess::start();
    let direct_pool = database::create_pool(&configuration(process.port())).unwrap();
    let client = direct_pool.get().await.unwrap();
    let legacy_ddl = include_str!("../../../blackbox/fixtures/legacy/postgres-longtext-oracle.sql")
        .replace("LONGTEXT", "TEXT");
    client.batch_execute(&legacy_ddl).await.unwrap();
    drop(client);

    let direct_state = PostgresDeliveryState::new(direct_pool.clone());
    direct_state.initialize_schema().await.unwrap();
    let now = timestamp(1_786_000_000);
    let task_id = 4_099;
    insert_pending(&direct_pool, task_id, 0, 2, now).await;

    let mut proxy = CancelFailureProxy::start(process.port()).await;
    let proxied_pool = database::create_pool(&configuration(proxy.port())).unwrap();
    let short_state =
        PostgresDeliveryState::with_timeout(proxied_pool, Duration::from_millis(200)).unwrap();

    let lock = direct_pool.get().await.unwrap();
    lock.batch_execute("BEGIN").await.unwrap();
    lock.query_one(
        "SELECT id FROM outbound_mail_queue WHERE id=4099 FOR UPDATE",
        &[],
    )
    .await
    .unwrap();

    let attempt = DeliveryAttemptId::generate(task_id, "worker-a:cancel-refused").unwrap();
    let task_attempt = attempt.clone();
    let claim_task =
        tokio::spawn(async move { short_state.claim_with_attempt(&task_attempt, now).await });
    tokio::time::timeout(Duration::from_secs(2), proxy.wait_for_claim_mutation())
        .await
        .expect("proxied claim did not reach the PostgreSQL mutation");
    proxy.refuse_new_connections().await;

    assert_eq!(
        claim_task.await.unwrap().unwrap_err(),
        DeliveryStateError::OutcomeUnknown
    );
    assert_no_waiting_mutation(&direct_pool).await;
    let before_unlock = direct_state
        .snapshot_attempt(&attempt)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before_unlock.status, DeliveryRowStatus::Pending);
    assert!(!before_unlock.has_owner);

    lock.batch_execute("ROLLBACK").await.unwrap();
    drop(lock);
    proxy.release_responses.cancel();
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert!(
        direct_state
            .reconcile_attempt_claim(&attempt)
            .await
            .unwrap()
            .is_none(),
        "claim committed after its client deadline and a failed CancelRequest transport"
    );
    let after_unlock = direct_state
        .snapshot_attempt(&attempt)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_unlock.status, DeliveryRowStatus::Pending);
    assert!(!after_unlock.has_owner);
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
    let (initialized_a, initialized_b) =
        tokio::join!(state.initialize_schema(), state.initialize_schema());
    initialized_a.unwrap();
    initialized_b.unwrap();
    let now = timestamp(1_786_000_000);
    insert_pending(&pool, 4_001, 0, 2, now).await;

    let attempt_a_token = DeliveryAttemptId::generate_lease_token("worker-a:claim-1").unwrap();
    let attempt_a = DeliveryAttemptId::from_lease_token(4_001, &attempt_a_token).unwrap();
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
    assert_eq!(
        state
            .reconcile_attempt_claim(first_attempt)
            .await
            .unwrap()
            .as_ref(),
        Some(&first_claim)
    );
    assert_eq!(
        state.claimed_recipient_roster(&first_claim).await.unwrap(),
        ["user@remote.test"]
    );
    let wrong_attempt = DeliveryAttemptId::generate(4_001, "worker-wrong").unwrap();
    assert!(
        state
            .reconcile_attempt_claim(&wrong_attempt)
            .await
            .unwrap()
            .is_none()
    );

    assert!(
        state
            .release(&first_claim, now + chrono::Duration::seconds(1))
            .await
            .unwrap()
    );
    assert!(
        state
            .reconcile_attempt_claim(first_attempt)
            .await
            .unwrap()
            .is_none()
    );
    let second_token = DeliveryAttemptId::generate_lease_token("worker-a:claim-1").unwrap();
    let second_attempt = DeliveryAttemptId::from_lease_token(4_001, &second_token).unwrap();
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
    let uncertain_attempt = DeliveryAttemptId::generate(4_010, "worker-a:unknown-claim").unwrap();
    assert_eq!(
        short_state
            .claim_with_attempt(&uncertain_attempt, now)
            .await
            .unwrap_err(),
        DeliveryStateError::OutcomeUnknown
    );
    assert_no_waiting_mutation(&pool).await;
    lock.batch_execute("ROLLBACK").await.unwrap();
    drop(lock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        state
            .reconcile_attempt_claim(&uncertain_attempt)
            .await
            .unwrap()
            .is_none(),
        "cancelled claim committed after its client deadline"
    );
    let cancelled_claim = state
        .snapshot_attempt(&uncertain_attempt)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cancelled_claim.status, DeliveryRowStatus::Pending);
    assert!(!cancelled_claim.has_owner);

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
    assert_no_waiting_mutation(&pool).await;
    lock.batch_execute("ROLLBACK").await.unwrap();
    drop(lock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let uncertain_retry = state
        .snapshot(4_011, Some(&uncertain_retry_claim))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(uncertain_retry.status, DeliveryRowStatus::Processing);
    assert_eq!(uncertain_retry.retry_count, 0);
    assert!(uncertain_retry.owned_by_claim);
    assert!(
        state
            .release(&uncertain_retry_claim, now + chrono::Duration::seconds(2),)
            .await
            .unwrap()
    );

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
    assert_no_waiting_mutation(&pool).await;
    lock.batch_execute("ROLLBACK").await.unwrap();
    drop(lock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let uncertain_terminal = state
        .snapshot(4_012, Some(&uncertain_terminal_claim))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(uncertain_terminal.status, DeliveryRowStatus::Processing);
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

    insert_pending(&pool, 4_013, 0, 2, now).await;
    let uncertain_heartbeat_claim = state
        .claim(4_013, "worker-a:unknown-heartbeat", now)
        .await
        .unwrap()
        .unwrap();
    let lock = pool.get().await.unwrap();
    lock.batch_execute("BEGIN").await.unwrap();
    lock.query_one(
        "SELECT id FROM outbound_mail_queue WHERE id=4013 FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        short_state
            .heartbeat(
                &uncertain_heartbeat_claim,
                now + chrono::Duration::seconds(1),
            )
            .await
            .unwrap_err(),
        DeliveryStateError::OutcomeUnknown
    );
    assert_no_waiting_mutation(&pool).await;
    lock.batch_execute("ROLLBACK").await.unwrap();
    drop(lock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let cancelled_heartbeat = state
        .snapshot(4_013, Some(&uncertain_heartbeat_claim))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cancelled_heartbeat.processing_started_at, Some(now));
    assert!(cancelled_heartbeat.owned_by_claim);
    assert!(
        state
            .release(
                &uncertain_heartbeat_claim,
                now + chrono::Duration::seconds(2),
            )
            .await
            .unwrap()
    );

    insert_pending(&pool, 4_014, 0, 2, now).await;
    let uncertain_ledger_claim = state
        .claim(4_014, "worker-a:unknown-ledger", now)
        .await
        .unwrap()
        .unwrap();
    let lock = pool.get().await.unwrap();
    lock.batch_execute("BEGIN").await.unwrap();
    lock.query_one(
        "SELECT id FROM outbound_mail_queue WHERE id=4014 FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        short_state
            .begin_attempt(
                &uncertain_ledger_claim,
                &["user@example.test".into()],
                now + chrono::Duration::seconds(1),
            )
            .await
            .unwrap_err(),
        DeliveryStateError::OutcomeUnknown
    );
    assert_no_waiting_mutation(&pool).await;
    lock.batch_execute("ROLLBACK").await.unwrap();
    drop(lock);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(state.ledger_snapshot(4_014, None).await.unwrap().is_none());
    assert!(
        state
            .release(&uncertain_ledger_claim, now + chrono::Duration::seconds(2),)
            .await
            .unwrap()
    );

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
            .is_none()
    );
    let sidecarless = state.ledger_snapshot(4_003, None).await.unwrap().unwrap();
    assert_eq!(sidecarless.phase, DeliveryAttemptPhase::Projected);
    assert!(!sidecarless.allows_retry());
    assert!(!sidecarless.allows_dsn());
    assert_eq!(
        sidecarless.recipients[0].state,
        RecipientDeliveryState::Ambiguous
    );
    assert_eq!(
        state.snapshot(4_003, None).await.unwrap().unwrap().status,
        DeliveryRowStatus::Failed
    );

    insert_pending(&pool, 4_005, 0, 1, now).await;
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE outbound_mail_queue
             SET status='PROCESSING',processor_id='legacy-worker',processing_started_at=NULL,
                 recipients_json='{\"to\":[\"legacy@example.test\"],\"cc\":null,\"bcc\":[]}'
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
            .is_none()
    );
    let legacy = state.ledger_snapshot(4_005, None).await.unwrap().unwrap();
    assert_eq!(legacy.phase, DeliveryAttemptPhase::Projected);
    assert_eq!(legacy.recipients[0].recipient, "legacy@example.test");
    assert_eq!(
        legacy.recipients[0].state,
        RecipientDeliveryState::Ambiguous
    );
    assert!(!legacy.allows_retry());
    assert!(!legacy.allows_dsn());
}

#[tokio::test]
async fn recipient_ledger_is_monotonic_fenced_and_legacy_compatible() {
    let process = PostgresProcess::start();
    let pool = database::create_pool(&configuration(process.port())).unwrap();
    let client = pool.get().await.unwrap();
    let legacy_ddl = include_str!("../../../blackbox/fixtures/legacy/postgres-longtext-oracle.sql")
        .replace("LONGTEXT", "TEXT");
    client.batch_execute(&legacy_ddl).await.unwrap();
    let legacy_columns_before: Vec<String> = client
        .query(
            "SELECT column_name FROM information_schema.columns
             WHERE table_schema='public' AND table_name='outbound_mail_queue'
             ORDER BY ordinal_position",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    drop(client);

    let state = PostgresDeliveryState::new(pool.clone());
    let (initialized_a, initialized_b) =
        tokio::join!(state.initialize_schema(), state.initialize_schema());
    initialized_a.unwrap();
    initialized_b.unwrap();
    state.initialize_schema().await.unwrap();

    let client = pool.get().await.unwrap();
    let legacy_columns_after: Vec<String> = client
        .query(
            "SELECT column_name FROM information_schema.columns
             WHERE table_schema='public' AND table_name='outbound_mail_queue'
             ORDER BY ordinal_position",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(legacy_columns_before, legacy_columns_after);
    let sidecars: Vec<String> = client
        .query(
            "SELECT table_name FROM information_schema.tables
             WHERE table_schema='public' AND table_name LIKE 'lmyzmail\\_%' ESCAPE '\\'
             ORDER BY table_name",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        sidecars,
        [
            "lmyzmail_outbound_delivery_attempt",
            "lmyzmail_outbound_delivery_recipient"
        ]
    );
    drop(client);

    let now = timestamp(1_786_100_000);
    let recipients = vec![
        "accepted@alpha.test".to_owned(),
        "temporary@alpha.test".to_owned(),
        "permanent@beta.test".to_owned(),
    ];
    insert_pending(&pool, 5_001, 0, 2, now).await;
    let database_claim = state
        .claim(5_001, "worker-ledger:first", now)
        .await
        .unwrap()
        .unwrap();
    let ledger_claim = state
        .begin_attempt(&database_claim, &recipients, now)
        .await
        .unwrap();
    assert_eq!(ledger_claim.task_id(), 5_001);
    assert_eq!(ledger_claim.generation(), 1);
    assert_eq!(
        state
            .resume_attempt(&database_claim, &recipients)
            .await
            .unwrap(),
        Some(ledger_claim.clone())
    );
    assert_eq!(
        state
            .begin_attempt(
                &database_claim,
                &[
                    recipients[1].clone(),
                    recipients[0].clone(),
                    recipients[2].clone()
                ],
                now,
            )
            .await
            .unwrap_err(),
        DeliveryStateError::InvalidTransition("delivery recipient roster changed")
    );

    let accepted = PreparedRecipientCheckpoint {
        ordinal: 0,
        recipient: recipients[0].clone(),
        status: PreparedRecipientStatus::Accepted,
        smtp_code: 250,
        detail: "250 recipient accepted".into(),
    };
    let temporary = PreparedRecipientCheckpoint {
        ordinal: 1,
        recipient: recipients[1].clone(),
        status: PreparedRecipientStatus::Retryable,
        smtp_code: 451,
        detail: "451 try again".into(),
    };
    assert_eq!(
        state
            .checkpoint_result(
                &ledger_claim,
                CommitResultStatus::Delivered,
                250,
                "250 queued",
                now,
            )
            .await
            .unwrap_err(),
        DeliveryStateError::InvalidTransition("delivery attempt is not commit-armed")
    );
    assert_eq!(
        state
            .checkpoint_prepared(&ledger_claim, std::slice::from_ref(&accepted), now)
            .await
            .unwrap_err(),
        DeliveryStateError::InvalidTransition(
            "prepared checkpoint does not cover the retryable roster"
        )
    );
    assert!(matches!(
        state
            .checkpoint_prepared(&ledger_claim, &[accepted.clone(), accepted.clone()], now,)
            .await,
        Err(DeliveryStateError::InvalidInput(
            "duplicate prepared recipient outcome"
        ))
    ));
    let unknown = PreparedRecipientCheckpoint {
        ordinal: 99,
        recipient: "unknown@alpha.test".into(),
        status: PreparedRecipientStatus::Permanent,
        smtp_code: 550,
        detail: "550 unknown".into(),
    };
    assert_eq!(
        state
            .checkpoint_prepared(&ledger_claim, &[accepted.clone(), unknown], now)
            .await
            .unwrap_err(),
        DeliveryStateError::InvalidTransition(
            "prepared checkpoint does not cover the retryable roster"
        )
    );
    assert!(
        state
            .checkpoint_prepared(
                &ledger_claim,
                &[accepted.clone(), temporary.clone()],
                now + chrono::Duration::seconds(1),
            )
            .await
            .unwrap()
    );
    let armed = state
        .ledger_snapshot(5_001, Some(&ledger_claim))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(armed.phase, DeliveryAttemptPhase::CommitArmed);
    assert!(armed.owned_by_claim);
    assert_eq!(
        armed
            .recipients
            .iter()
            .map(|recipient| recipient.state)
            .collect::<Vec<_>>(),
        [
            RecipientDeliveryState::CommitArmed,
            RecipientDeliveryState::Retryable,
            RecipientDeliveryState::Pending,
        ]
    );
    assert!(
        state
            .schedule_retry(
                &database_claim,
                now + chrono::Duration::seconds(20),
                "must use recipient ledger projection",
                now + chrono::Duration::seconds(2),
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !state
            .mark_terminal(
                &database_claim,
                TerminalStatus::Sent,
                &["alpha.test".into()],
                &BTreeMap::new(),
                None,
                now + chrono::Duration::seconds(2),
            )
            .await
            .unwrap()
    );
    assert_eq!(
        state
            .checkpoint_result(
                &ledger_claim,
                CommitResultStatus::Delivered,
                250,
                "250 queued",
                now + chrono::Duration::seconds(2),
            )
            .await
            .unwrap(),
        1
    );
    let permanent = PreparedRecipientCheckpoint {
        ordinal: 2,
        recipient: recipients[2].clone(),
        status: PreparedRecipientStatus::Permanent,
        smtp_code: 550,
        detail: "550 no such user".into(),
    };
    assert!(
        !state
            .checkpoint_prepared(
                &ledger_claim,
                std::slice::from_ref(&permanent),
                now + chrono::Duration::seconds(3),
            )
            .await
            .unwrap()
    );
    let retry_at = now + chrono::Duration::seconds(30);
    assert!(matches!(
        state
            .project_legacy(
                &ledger_claim,
                Some(retry_at),
                now + chrono::Duration::seconds(4),
            )
            .await
            .unwrap(),
        LegacyProjection::RetryScheduled(_)
    ));

    let next_database_claim = state
        .claim(5_001, "worker-ledger:second", retry_at)
        .await
        .unwrap()
        .unwrap();
    let next_ledger_claim = state
        .begin_attempt(&next_database_claim, &recipients, retry_at)
        .await
        .unwrap();
    assert_eq!(next_ledger_claim.generation(), 2);
    assert_eq!(
        state
            .checkpoint_prepared(&ledger_claim, std::slice::from_ref(&temporary), retry_at,)
            .await
            .unwrap_err(),
        DeliveryStateError::Fenced
    );
    let retry_snapshot = state
        .ledger_snapshot(5_001, Some(&next_ledger_claim))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry_snapshot.retryable_recipients().len(), 1);
    assert_eq!(retry_snapshot.retryable_recipients()[0].ordinal, 1);
    let retry_accepted = PreparedRecipientCheckpoint {
        ordinal: 1,
        recipient: recipients[1].clone(),
        status: PreparedRecipientStatus::Accepted,
        smtp_code: 250,
        detail: "250 recipient accepted".into(),
    };
    assert!(
        state
            .checkpoint_prepared(
                &next_ledger_claim,
                std::slice::from_ref(&retry_accepted),
                retry_at,
            )
            .await
            .unwrap()
    );
    state
        .checkpoint_result(
            &next_ledger_claim,
            CommitResultStatus::Delivered,
            250,
            "250 queued",
            retry_at + chrono::Duration::seconds(1),
        )
        .await
        .unwrap();
    assert_eq!(
        state
            .project_legacy(
                &next_ledger_claim,
                None,
                retry_at + chrono::Duration::seconds(2),
            )
            .await
            .unwrap(),
        LegacyProjection::Terminal(TerminalStatus::PartialSuccess)
    );
    let client = pool.get().await.unwrap();
    let forbidden = client
        .execute(
            "UPDATE lmyzmail_outbound_delivery_recipient
             SET state='PENDING' WHERE task_id=5001 AND recipient_ordinal=0",
            &[],
        )
        .await;
    assert!(forbidden.is_err());
    let legacy_status: String = client
        .query_one("SELECT status FROM outbound_mail_queue WHERE id=5001", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(legacy_status, "PARTIAL_SUCCESS");
    drop(client);

    insert_pending(&pool, 5_002, 0, 2, now).await;
    let crash_database_claim = state
        .claim(5_002, "worker-ledger:crash", now)
        .await
        .unwrap()
        .unwrap();
    let crash_ledger_claim = state
        .begin_attempt(
            &crash_database_claim,
            &["one@crash.test".into(), "two@crash.test".into()],
            now,
        )
        .await
        .unwrap();
    let crash_prepared = [
        PreparedRecipientCheckpoint {
            ordinal: 0,
            recipient: "one@crash.test".into(),
            status: PreparedRecipientStatus::Accepted,
            smtp_code: 250,
            detail: "250 accepted".into(),
        },
        PreparedRecipientCheckpoint {
            ordinal: 1,
            recipient: "two@crash.test".into(),
            status: PreparedRecipientStatus::Accepted,
            smtp_code: 250,
            detail: "250 accepted".into(),
        },
    ];
    assert!(
        state
            .checkpoint_prepared(&crash_ledger_claim, &crash_prepared, now)
            .await
            .unwrap()
    );
    assert!(
        state
            .recover_expired(
                5_002,
                now + chrono::Duration::seconds(1),
                now + chrono::Duration::seconds(2),
            )
            .await
            .unwrap()
    );
    let crash_snapshot = state.ledger_snapshot(5_002, None).await.unwrap().unwrap();
    assert_eq!(crash_snapshot.phase, DeliveryAttemptPhase::Projected);
    assert!(!crash_snapshot.has_owner);
    assert!(!crash_snapshot.allows_retry());
    assert!(!crash_snapshot.allows_dsn());
    assert!(
        crash_snapshot
            .recipients
            .iter()
            .all(|recipient| recipient.state == RecipientDeliveryState::Ambiguous)
    );
    assert!(
        state
            .claim(
                5_002,
                "worker-ledger:forbidden-retry",
                now + chrono::Duration::seconds(3),
            )
            .await
            .unwrap()
            .is_none()
    );

    insert_pending(&pool, 5_003, 0, 2, now).await;
    let unknown_database_claim = state
        .claim(5_003, "worker-ledger:unknown", now)
        .await
        .unwrap()
        .unwrap();
    let unknown_ledger_claim = state
        .begin_attempt(
            &unknown_database_claim,
            &["unknown@result.test".into()],
            now,
        )
        .await
        .unwrap();
    state
        .checkpoint_prepared(
            &unknown_ledger_claim,
            &[PreparedRecipientCheckpoint {
                ordinal: 0,
                recipient: "unknown@result.test".into(),
                status: PreparedRecipientStatus::Accepted,
                smtp_code: 250,
                detail: "250 accepted".into(),
            }],
            now,
        )
        .await
        .unwrap();
    let short_state =
        PostgresDeliveryState::with_timeout(pool.clone(), Duration::from_millis(100)).unwrap();
    let lock = pool.get().await.unwrap();
    lock.batch_execute("BEGIN").await.unwrap();
    lock.query_one(
        "SELECT id FROM outbound_mail_queue WHERE id=5003 FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        short_state
            .checkpoint_result(
                &unknown_ledger_claim,
                CommitResultStatus::Delivered,
                250,
                "250 queued",
                now + chrono::Duration::seconds(1),
            )
            .await
            .unwrap_err(),
        DeliveryStateError::OutcomeUnknown
    );
    assert_no_waiting_mutation(&pool).await;
    lock.batch_execute("ROLLBACK").await.unwrap();
    drop(lock);
    state
        .checkpoint_ambiguous(
            &unknown_ledger_claim,
            "database result checkpoint was outcome-unknown",
            now + chrono::Duration::seconds(2),
        )
        .await
        .unwrap();
    assert!(matches!(
        state
            .project_legacy(
                &unknown_ledger_claim,
                None,
                now + chrono::Duration::seconds(3),
            )
            .await
            .unwrap(),
        LegacyProjection::Ambiguous
    ));

    insert_pending(&pool, 5_004, 0, 2, now).await;
    let cancelled_database_claim = state
        .claim(5_004, "worker-ledger:cancelled", now)
        .await
        .unwrap()
        .unwrap();
    let cancelled_ledger_claim = state
        .begin_attempt(
            &cancelled_database_claim,
            &["cancelled@result.test".into()],
            now,
        )
        .await
        .unwrap();
    state
        .checkpoint_prepared(
            &cancelled_ledger_claim,
            &[PreparedRecipientCheckpoint {
                ordinal: 0,
                recipient: "cancelled@result.test".into(),
                status: PreparedRecipientStatus::Accepted,
                smtp_code: 250,
                detail: "250 accepted".into(),
            }],
            now,
        )
        .await
        .unwrap();
    assert!(
        state
            .release(
                &cancelled_database_claim,
                now + chrono::Duration::seconds(1),
            )
            .await
            .unwrap()
    );
    let cancelled = state.ledger_snapshot(5_004, None).await.unwrap().unwrap();
    assert_eq!(cancelled.phase, DeliveryAttemptPhase::Projected);
    assert_eq!(
        cancelled.recipients[0].state,
        RecipientDeliveryState::Ambiguous
    );
    assert!(!cancelled.allows_retry());
    assert!(!cancelled.allows_dsn());

    insert_pending(&pool, 5_005, 0, 2, now).await;
    let corrupt_phase_claim = state
        .claim(5_005, "worker-ledger:corrupt-phase", now)
        .await
        .unwrap()
        .unwrap();
    state
        .begin_attempt(&corrupt_phase_claim, &["phase@corrupt.test".into()], now)
        .await
        .unwrap();
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE lmyzmail_outbound_delivery_attempt
             SET phase='COMMIT_ARMED' WHERE task_id=5005",
            &[],
        )
        .await
        .unwrap();
    drop(client);
    assert_eq!(
        state
            .recover_expired(
                5_005,
                now + chrono::Duration::seconds(1),
                now + chrono::Duration::seconds(2),
            )
            .await
            .unwrap_err(),
        DeliveryStateError::InvalidTransition("delivery commit barrier state is inconsistent")
    );
    assert_eq!(
        state.snapshot(5_005, None).await.unwrap().unwrap().status,
        DeliveryRowStatus::Processing
    );

    insert_pending(&pool, 5_006, 0, 2, now).await;
    let corrupt_recipient_claim = state
        .claim(5_006, "worker-ledger:corrupt-recipient", now)
        .await
        .unwrap()
        .unwrap();
    let corrupt_recipient_ledger = state
        .begin_attempt(
            &corrupt_recipient_claim,
            &["recipient@corrupt.test".into()],
            now,
        )
        .await
        .unwrap();
    state
        .checkpoint_prepared(
            &corrupt_recipient_ledger,
            &[PreparedRecipientCheckpoint {
                ordinal: 0,
                recipient: "recipient@corrupt.test".into(),
                status: PreparedRecipientStatus::Accepted,
                smtp_code: 250,
                detail: "250 accepted".into(),
            }],
            now,
        )
        .await
        .unwrap();
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE lmyzmail_outbound_delivery_attempt
             SET phase='PREPARING' WHERE task_id=5006",
            &[],
        )
        .await
        .unwrap();
    drop(client);
    assert_eq!(
        state
            .release(&corrupt_recipient_claim, now + chrono::Duration::seconds(1),)
            .await
            .unwrap_err(),
        DeliveryStateError::InvalidTransition("delivery commit barrier state is inconsistent")
    );
    assert_eq!(
        state.snapshot(5_006, None).await.unwrap().unwrap().status,
        DeliveryRowStatus::Processing
    );
}
