use std::{
    collections::HashMap,
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use deadpool_postgres::{Object, Pool};
use serde::Serialize;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{CancelToken, IsolationLevel, NoTls, Row};
use tokio_util::sync::CancellationToken;

const DATABASE_DEADLINE: Duration = Duration::from_secs(8);
const DATABASE_CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PAGE_SIZE: i64 = 500;
const MAX_EXPORT_ROWS: i64 = 10_000;
const XDP_SYNC_PAGE_SIZE: i64 = 500;
const MAX_XDP_EXISTING_BANS: usize = 200_000;
const MAX_XDP_NEW_CANDIDATES: usize = 200_000;
const MAX_XDP_RECONCILE_CANDIDATES: usize = MAX_XDP_EXISTING_BANS + MAX_XDP_NEW_CANDIDATES;
const XDP_TRAFFIC_SCORE: i32 = 50;
const SSH_BRUTEFORCE_SCORE: i32 = 10;
const DECAY_ADVISORY_LOCK_ID: i64 = 0x4c4d_595a_4445_4341;

const IP_COLUMNS: &str = "ip_address, total_score, current_score, activity_count, \
    self_spoofing_count, open_relay_count, auth_probe_count, illegal_domain_count, \
    spamhaus_count, http_on_smtp_count, ssh_on_smtp_count, http_port_scanning_count, \
    honeypot_hit_count, ssh_bruteforce_count, other_count, first_seen_at, last_seen_at, \
    last_decay_at";

const ACTIVITY_COLUMNS: &str = "id, ip_address, activity_type, score, timestamp, mail_from, \
    rcpt_to, helo_name, session_id, response_message, metadata";

#[derive(Clone)]
pub struct CringeService {
    pool: Pool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ActivityIncrements {
    self_spoofing: i32,
    illegal_domain: i32,
    spamhaus: i32,
    pps_overlimit: i32,
    syn_flood: i32,
    ssh_bruteforce: i32,
    other: i32,
}

impl ActivityIncrements {
    const fn self_spoofing() -> Self {
        Self {
            self_spoofing: 1,
            illegal_domain: 0,
            spamhaus: 0,
            pps_overlimit: 0,
            syn_flood: 0,
            ssh_bruteforce: 0,
            other: 0,
        }
    }

    const fn protocol_violation() -> Self {
        Self {
            self_spoofing: 0,
            illegal_domain: 0,
            spamhaus: 0,
            pps_overlimit: 0,
            syn_flood: 0,
            ssh_bruteforce: 0,
            other: 1,
        }
    }

    const fn illegal_sender_domain() -> Self {
        Self {
            illegal_domain: 1,
            ..Self::default_const()
        }
    }

    const fn spamhaus() -> Self {
        Self {
            spamhaus: 1,
            ..Self::default_const()
        }
    }

    const fn default_const() -> Self {
        Self {
            self_spoofing: 0,
            illegal_domain: 0,
            spamhaus: 0,
            pps_overlimit: 0,
            syn_flood: 0,
            ssh_bruteforce: 0,
            other: 0,
        }
    }
}

#[derive(Clone, Debug)]
struct ActivityDetails {
    mail_from: Option<String>,
    rcpt_to: Option<String>,
    helo_name: Option<String>,
    session_id: Option<String>,
    response_message: Option<String>,
    metadata: String,
}

impl ActivityDetails {
    fn metadata(metadata: &str) -> Self {
        Self {
            mail_from: None,
            rcpt_to: None,
            helo_name: None,
            session_id: None,
            response_message: None,
            metadata: metadata.to_owned(),
        }
    }

    fn self_spoofing(mail_from: &str, response_message: &str, metadata: &str) -> Self {
        Self {
            mail_from: Some(truncate_chars(mail_from, 255)),
            rcpt_to: None,
            helo_name: None,
            session_id: None,
            response_message: Some(truncate_chars(response_message, 512)),
            metadata: truncate_chars(metadata, 1_024),
        }
    }

    fn illegal_sender_domain(mail_from: &str, metadata: &str) -> Self {
        Self {
            mail_from: Some(truncate_chars(mail_from, 255)),
            rcpt_to: None,
            helo_name: None,
            session_id: None,
            response_message: None,
            metadata: truncate_chars(metadata, 1_024),
        }
    }

    fn spamhaus(mail_from: &str, metadata: &str) -> Self {
        Self::illegal_sender_domain(mail_from, metadata)
    }

    fn protocol_violation(helo_name: &str, session_id: &str, metadata: &str) -> Self {
        Self {
            mail_from: None,
            rcpt_to: None,
            helo_name: Some(truncate_chars(helo_name, 255)),
            session_id: Some(truncate_chars(session_id, 64)),
            response_message: None,
            metadata: truncate_chars(metadata, 1_024),
        }
    }
}

impl CringeService {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub async fn above_score(
        &self,
        min_score: i32,
        current: bool,
        cancellation: &CancellationToken,
    ) -> Result<Vec<CringeIp>, CringeError> {
        let score_column = if current {
            "current_score"
        } else {
            "total_score"
        };
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let sql = format!(
            "SELECT {IP_COLUMNS} FROM skibidi_cringe_ip \
             WHERE {score_column} >= $1 ORDER BY {score_column} DESC \
             LIMIT {MAX_EXPORT_ROWS}"
        );
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let rows = connection
                .client()
                .query(&sql, &[&min_score])
                .await
                .map_err(database_error)?;
            Ok(rows.iter().map(cringe_ip_from_row).collect())
        })
        .await;
        connection.finish(outcome)
    }

    pub async fn record_xdp_traffic(
        &self,
        ip: IpAddr,
        activity: XdpTrafficActivity,
        metadata: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<i32>, CringeError> {
        let (pps_increment, syn_increment) = activity.counter_increments();
        self.record_scored_activity(
            ip,
            activity.name(),
            XDP_TRAFFIC_SCORE,
            ActivityDetails::metadata(metadata),
            ActivityIncrements {
                self_spoofing: 0,
                illegal_domain: 0,
                spamhaus: 0,
                pps_overlimit: pps_increment,
                syn_flood: syn_increment,
                ssh_bruteforce: 0,
                other: 0,
            },
            cancellation,
        )
        .await
    }

    pub async fn record_ssh_bruteforce(
        &self,
        ip: IpAddr,
        metadata: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<i32>, CringeError> {
        self.record_scored_activity(
            ip,
            "SSH_BRUTEFORCE",
            SSH_BRUTEFORCE_SCORE,
            ActivityDetails::metadata(metadata),
            ActivityIncrements {
                self_spoofing: 0,
                illegal_domain: 0,
                spamhaus: 0,
                pps_overlimit: 0,
                syn_flood: 0,
                ssh_bruteforce: 1,
                other: 0,
            },
            cancellation,
        )
        .await
    }

    pub async fn record_self_spoofing(
        &self,
        ip: IpAddr,
        mail_from: &str,
        response_message: &str,
        metadata: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<i32>, CringeError> {
        self.record_scored_activity(
            ip,
            "SELF_SPOOFING",
            10,
            ActivityDetails::self_spoofing(mail_from, response_message, metadata),
            ActivityIncrements::self_spoofing(),
            cancellation,
        )
        .await
    }

    pub async fn record_illegal_sender_domain(
        &self,
        ip: IpAddr,
        mail_from: &str,
        metadata: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<i32>, CringeError> {
        self.record_scored_activity(
            ip,
            "ILLEGAL_SENDER_DOMAIN",
            4,
            ActivityDetails::illegal_sender_domain(mail_from, metadata),
            ActivityIncrements::illegal_sender_domain(),
            cancellation,
        )
        .await
    }

    pub async fn record_protocol_violation(
        &self,
        ip: IpAddr,
        helo_name: &str,
        session_id: &str,
        metadata: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<i32>, CringeError> {
        self.record_scored_activity(
            ip,
            "PROTOCOL_VIOLATION",
            1,
            ActivityDetails::protocol_violation(helo_name, session_id, metadata),
            ActivityIncrements::protocol_violation(),
            cancellation,
        )
        .await
    }

    pub async fn record_spamhaus(
        &self,
        ip: IpAddr,
        mail_from: &str,
        metadata: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<i32>, CringeError> {
        self.record_scored_activity(
            ip,
            "SPAMHAUS_LISTED",
            3,
            ActivityDetails::spamhaus(mail_from, metadata),
            ActivityIncrements::spamhaus(),
            cancellation,
        )
        .await
    }

    async fn record_scored_activity(
        &self,
        ip: IpAddr,
        activity_type: &str,
        score: i32,
        details: ActivityDetails,
        increments: ActivityIncrements,
        cancellation: &CancellationToken,
    ) -> Result<Option<i32>, CringeError> {
        if is_exact_localhost(ip) {
            return Ok(None);
        }
        if details.metadata.chars().count() > 1_024
            || details
                .mail_from
                .as_deref()
                .is_some_and(|value| value.chars().count() > 255)
            || details
                .response_message
                .as_deref()
                .is_some_and(|value| value.chars().count() > 512)
            || details
                .helo_name
                .as_deref()
                .is_some_and(|value| value.chars().count() > 255)
            || details
                .session_id
                .as_deref()
                .is_some_and(|value| value.chars().count() > 64)
            || details
                .rcpt_to
                .as_deref()
                .is_some_and(|value| value.chars().count() > 255)
        {
            return Err(CringeError::InvalidInput);
        }
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let activity_id = self.allocate_activity_id(deadline, cancellation).await?;
        let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
            .ok_or_else(|| CringeError::Database("current timestamp is out of range".into()))?;
        let ip_address = ip.to_string();
        let activity_type = activity_type.to_owned();
        let client = self.client(deadline, cancellation).await?;
        let mut connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = database_write(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(database_error)?;
                configure_transaction_deadline(&transaction, deadline).await?;
                ensure_active(&database_cancellation)?;
                transaction
                    .query_one("SELECT pg_advisory_xact_lock($1)", &[&activity_id])
                    .await
                    .map_err(database_error)?;
                ensure_active(&database_cancellation)?;
                transaction
                    .execute(
                        "INSERT INTO skibidi_cringe_ip_activity (\
                             id,ip_address,activity_type,score,timestamp,mail_from,rcpt_to,\
                             helo_name,session_id,response_message,metadata\
                         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                        &[
                            &activity_id,
                            &ip_address,
                            &activity_type,
                            &score,
                            &now,
                            &details.mail_from,
                            &details.rcpt_to,
                            &details.helo_name,
                            &details.session_id,
                            &details.response_message,
                            &details.metadata,
                        ],
                    )
                    .await
                    .map_err(database_error)?;
                ensure_active(&database_cancellation)?;
                let row = transaction
                    .query_one(
                        "INSERT INTO skibidi_cringe_ip (\
                             ip_address,total_score,current_score,activity_count,\
                             first_seen_at,last_seen_at,last_decay_at,\
                             self_spoofing_count,open_relay_count,auth_probe_count,\
                             illegal_domain_count,spamhaus_count,http_on_smtp_count,\
                             ssh_on_smtp_count,http_port_scanning_count,honeypot_hit_count,\
                             ssh_bruteforce_count,pps_overlimit_count,syn_flood_count,other_count\
                         ) VALUES (\
                             $1,$2,$2,1,$3,$3,$3,$7,0,0,$9,$10,0,0,0,0,$6,$4,$5,$8\
                         ) ON CONFLICT (ip_address) DO UPDATE SET \
                             total_score=skibidi_cringe_ip.total_score+$2,\
                             current_score=skibidi_cringe_ip.current_score+$2,\
                             activity_count=skibidi_cringe_ip.activity_count+1,\
                             last_seen_at=GREATEST(skibidi_cringe_ip.last_seen_at,$3),\
                             self_spoofing_count=skibidi_cringe_ip.self_spoofing_count+$7,\
                             open_relay_count=skibidi_cringe_ip.open_relay_count+0,\
                             auth_probe_count=skibidi_cringe_ip.auth_probe_count+0,\
                             illegal_domain_count=skibidi_cringe_ip.illegal_domain_count+$9,\
                             spamhaus_count=skibidi_cringe_ip.spamhaus_count+$10,\
                             http_on_smtp_count=skibidi_cringe_ip.http_on_smtp_count+0,\
                             ssh_on_smtp_count=skibidi_cringe_ip.ssh_on_smtp_count+0,\
                             http_port_scanning_count=skibidi_cringe_ip.http_port_scanning_count+0,\
                             honeypot_hit_count=skibidi_cringe_ip.honeypot_hit_count+0,\
                             ssh_bruteforce_count=CASE WHEN $6<>0 \
                                 THEN COALESCE(skibidi_cringe_ip.ssh_bruteforce_count,0)+$6 \
                                 ELSE skibidi_cringe_ip.ssh_bruteforce_count END,\
                             pps_overlimit_count=CASE WHEN $4<>0 \
                                 THEN COALESCE(skibidi_cringe_ip.pps_overlimit_count,0)+$4 \
                                 ELSE skibidi_cringe_ip.pps_overlimit_count END,\
                             syn_flood_count=CASE WHEN $5<>0 \
                                 THEN COALESCE(skibidi_cringe_ip.syn_flood_count,0)+$5 \
                                 ELSE skibidi_cringe_ip.syn_flood_count END,\
                             other_count=skibidi_cringe_ip.other_count+$8 \
                         RETURNING current_score",
                        &[
                            &ip_address,
                            &score,
                            &now,
                            &increments.pps_overlimit,
                            &increments.syn_flood,
                            &increments.ssh_bruteforce,
                            &increments.self_spoofing,
                            &increments.other,
                            &increments.illegal_domain,
                            &increments.spamhaus,
                        ],
                    )
                    .await
                    .map_err(database_error)?;
                let current_score = row.get::<_, i32>(0);
                start_commit(deadline, &database_cancellation, &commit_started)?;
                transaction.commit().await.map_err(commit_error)?;
                Ok(current_score)
            },
        )
        .await;
        match connection.finish(outcome) {
            Ok(score) => Ok(Some(score)),
            // Once COMMIT starts, cancellation cannot tell whether PostgreSQL applied it.
            // Reconcile independently, but never beyond its own absolute database deadline.
            Err(CringeError::OutcomeUnknown) => self
                .reconcile_activity(
                    activity_id,
                    &ip_address,
                    &activity_type,
                    score,
                    &details,
                    now,
                )
                .await
                .map(Some),
            Err(error) => Err(error),
        }
    }

    async fn allocate_activity_id(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<i64, CringeError> {
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            connection
                .client()
                .query_one("SELECT nextval('skibidi_cringe_ip_activity_id_seq')", &[])
                .await
                .map(|row| row.get::<_, i64>(0))
                .map_err(database_error)
        })
        .await;
        connection.finish(outcome)
    }

    async fn reconcile_activity(
        &self,
        activity_id: i64,
        ip_address: &str,
        activity_type: &str,
        score: i32,
        details: &ActivityDetails,
        timestamp: DateTime<Utc>,
    ) -> Result<i32, CringeError> {
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = timeout_at(deadline, self.pool.get())
            .await
            .map_err(|error| reconciliation_error("pool deadline", error))?
            .map_err(|error| reconciliation_error("pool acquisition", error))?;
        let mut connection = DatabaseConnection::new(client);
        let transaction = timeout_at(deadline, connection.client_mut().transaction())
            .await
            .map_err(|error| reconciliation_error("transaction deadline", error))?
            .map_err(|error| reconciliation_error("transaction start", error))?;
        configure_transaction_deadline(&transaction, deadline)
            .await
            .map_err(|error| reconciliation_error("statement deadline", error))?;
        timeout_at(
            deadline,
            transaction.query_one("SELECT pg_advisory_xact_lock($1)", &[&activity_id]),
        )
        .await
        .map_err(|error| reconciliation_error("advisory lock deadline", error))?
        .map_err(|error| reconciliation_error("advisory lock", error))?;
        let row = timeout_at(
            deadline,
            transaction.query_opt(
                "/* lmyzmail_xdp_traffic_commit_reconciliation */ \
                 SELECT a.ip_address,a.activity_type,a.score,a.timestamp,a.mail_from,a.rcpt_to,\
                        a.helo_name,a.session_id,a.response_message,a.metadata,i.current_score \
                 FROM skibidi_cringe_ip_activity a \
                 JOIN skibidi_cringe_ip i ON i.ip_address=a.ip_address \
                 WHERE a.id=$1",
                &[&activity_id],
            ),
        )
        .await
        .map_err(|error| reconciliation_error("verification deadline", error))?
        .map_err(|error| reconciliation_error("verification query", error))?;
        let discard_connection =
            !matches!(timeout_at(deadline, transaction.commit()).await, Ok(Ok(())));
        let row = connection.finish(DatabaseOutcome {
            result: Ok(row),
            discard_connection,
        })?;
        match row {
            Some(row)
                if row.get::<_, &str>(0) == ip_address
                    && row.get::<_, &str>(1) == activity_type
                    && row.get::<_, i32>(2) == score
                    && row.get::<_, DateTime<Utc>>(3) == timestamp
                    && row.get::<_, Option<&str>>(4) == details.mail_from.as_deref()
                    && row.get::<_, Option<&str>>(5) == details.rcpt_to.as_deref()
                    && row.get::<_, Option<&str>>(6) == details.helo_name.as_deref()
                    && row.get::<_, Option<&str>>(7) == details.session_id.as_deref()
                    && row.get::<_, Option<&str>>(8) == details.response_message.as_deref()
                    && row.get::<_, Option<&str>>(9) == Some(details.metadata.as_str()) =>
            {
                Ok(row.get::<_, i32>(10))
            }
            Some(_) => Err(CringeError::OutcomeUnknown),
            None => Err(CringeError::Database(
                "XDP traffic activity did not commit".into(),
            )),
        }
    }

    pub(crate) async fn xdp_reconcile_candidates(
        &self,
        existing_bans: &[IpAddr],
        ban_threshold: i32,
        unban_threshold: i32,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(IpAddr, i32)>, CringeError> {
        if existing_bans.len() > MAX_XDP_EXISTING_BANS || ban_threshold < unban_threshold {
            return Err(CringeError::InvalidInput);
        }
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let mut connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let transaction = connection
                .client_mut()
                .build_transaction()
                .isolation_level(IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()
                .await
                .map_err(database_error)?;
            let mut candidates = HashMap::with_capacity(existing_bans.len());

            for chunk in existing_bans.chunks(XDP_SYNC_PAGE_SIZE as usize) {
                let addresses = chunk.iter().map(ToString::to_string).collect::<Vec<_>>();
                let rows = transaction
                    .query(
                        "SELECT ip_address, current_score FROM skibidi_cringe_ip \
                         WHERE ip_address = ANY($1::text[])",
                        &[&addresses],
                    )
                    .await
                    .map_err(database_error)?;
                for row in rows {
                    let score = row.get::<_, i32>("current_score");
                    if score >= unban_threshold {
                        insert_xdp_candidate(&mut candidates, &row, score)?;
                    }
                }
            }

            let mut cursor: Option<(i32, String)> = None;
            let mut high_candidate_rows = 0_usize;
            loop {
                let rows = match cursor.as_ref() {
                    Some((last_score, last_ip)) => transaction
                        .query(
                            "SELECT ip_address, current_score FROM skibidi_cringe_ip \
                                 WHERE current_score >= $1 \
                                   AND (current_score < $2 OR \
                                        (current_score = $2 AND ip_address < $3)) \
                                 ORDER BY current_score DESC, ip_address DESC LIMIT $4",
                            &[&ban_threshold, last_score, last_ip, &XDP_SYNC_PAGE_SIZE],
                        )
                        .await
                        .map_err(database_error)?,
                    None => transaction
                        .query(
                            "SELECT ip_address, current_score FROM skibidi_cringe_ip \
                                 WHERE current_score >= $1 \
                                 ORDER BY current_score DESC, ip_address DESC LIMIT $2",
                            &[&ban_threshold, &XDP_SYNC_PAGE_SIZE],
                        )
                        .await
                        .map_err(database_error)?,
                };
                if rows.is_empty() {
                    break;
                }
                high_candidate_rows = high_candidate_rows
                    .checked_add(rows.len())
                    .ok_or(CringeError::CapacityExceeded)?;
                if high_candidate_rows > MAX_XDP_NEW_CANDIDATES {
                    return Err(CringeError::CapacityExceeded);
                }
                for row in &rows {
                    let score = row.get::<_, i32>("current_score");
                    insert_xdp_candidate(&mut candidates, row, score)?;
                }
                let last = rows.last().expect("non-empty XDP candidate page");
                cursor = Some((
                    last.get::<_, i32>("current_score"),
                    last.get::<_, String>("ip_address"),
                ));
                if rows.len() < XDP_SYNC_PAGE_SIZE as usize {
                    break;
                }
            }

            if candidates.len() > MAX_XDP_RECONCILE_CANDIDATES {
                return Err(CringeError::CapacityExceeded);
            }
            transaction.commit().await.map_err(database_error)?;
            Ok(candidates.into_iter().collect())
        })
        .await;
        connection.finish(outcome)
    }

    pub(crate) async fn xdp_decay_unban_candidates(
        &self,
        existing_bans: &[IpAddr],
        unban_threshold: i32,
        cancellation: &CancellationToken,
    ) -> Result<Vec<IpAddr>, CringeError> {
        if existing_bans.len() > MAX_XDP_EXISTING_BANS {
            return Err(CringeError::CapacityExceeded);
        }
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let mut connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let transaction = connection
                .client_mut()
                .build_transaction()
                .isolation_level(IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()
                .await
                .map_err(database_error)?;
            let mut candidates = Vec::new();
            for chunk in existing_bans.chunks(XDP_SYNC_PAGE_SIZE as usize) {
                let addresses = chunk.iter().map(ToString::to_string).collect::<Vec<_>>();
                let rows = transaction
                    .query(
                        "SELECT ip_address FROM skibidi_cringe_ip \
                         WHERE ip_address = ANY($1::text[]) AND current_score < $2",
                        &[&addresses, &unban_threshold],
                    )
                    .await
                    .map_err(database_error)?;
                for row in rows {
                    candidates.push(row.get::<_, String>("ip_address").parse().map_err(|_| {
                        CringeError::Database("stored cringe IP address is invalid".into())
                    })?);
                }
            }
            transaction.commit().await.map_err(database_error)?;
            Ok(candidates)
        })
        .await;
        connection.finish(outcome)
    }

    pub async fn current_score(
        &self,
        ip_address: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<i32>, CringeError> {
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            connection
                .client()
                .query_opt(
                    "SELECT current_score FROM skibidi_cringe_ip WHERE ip_address = $1",
                    &[&ip_address],
                )
                .await
                .map(|row| row.map(|row| row.get::<_, i32>(0)))
                .map_err(database_error)
        })
        .await;
        connection.finish(outcome)
    }

    pub async fn perform_score_decay(
        &self,
        interval: Duration,
        amount: i32,
        cancellation: &CancellationToken,
    ) -> Result<u64, CringeError> {
        if amount < 0 || interval.is_zero() {
            return Err(CringeError::InvalidInput);
        }
        if amount == 0 {
            return Ok(0);
        }
        let chrono_interval =
            chrono::Duration::from_std(interval).map_err(|_| CringeError::InvalidInput)?;
        let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros())
            .ok_or_else(|| CringeError::Database("current timestamp is out of range".into()))?;
        let cutoff = now
            .checked_sub_signed(chrono_interval)
            .ok_or(CringeError::InvalidInput)?;
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let mut connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let affected_before_commit = AtomicU64::new(0);
        let transaction_id = OnceLock::new();
        let database_cancellation = cancellation.child_token();
        let outcome = database_write(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(database_error)?;
                configure_transaction_deadline(&transaction, deadline).await?;
                ensure_active(&database_cancellation)?;
                transaction
                    .query_one(
                        "SELECT pg_advisory_xact_lock($1)",
                        &[&DECAY_ADVISORY_LOCK_ID],
                    )
                    .await
                    .map_err(database_error)?;
                ensure_active(&database_cancellation)?;
                let decay_transaction_id = transaction
                    .query_one("SELECT pg_current_xact_id()::xid::text", &[])
                    .await
                    .map_err(database_error)?
                    .get::<_, String>(0);
                transaction_id
                    .set(decay_transaction_id)
                    .map_err(|_| CringeError::Database("decay transaction ID reused".into()))?;
                ensure_active(&database_cancellation)?;
                let affected = transaction
                    .execute(
                        "UPDATE skibidi_cringe_ip \
                         SET current_score = GREATEST(0, current_score - $1), \
                             last_decay_at = $2 \
                         WHERE current_score > 0 \
                           AND (last_decay_at IS NULL OR last_decay_at < $3)",
                        &[&amount, &now, &cutoff],
                    )
                    .await
                    .map_err(database_error)?;
                affected_before_commit.store(affected, Ordering::Release);
                start_commit(deadline, &database_cancellation, &commit_started)?;
                transaction.commit().await.map_err(commit_error)?;
                Ok(affected)
            },
        )
        .await;
        match connection.finish(outcome) {
            Ok(affected) => Ok(affected),
            Err(CringeError::OutcomeUnknown) => {
                let expected = affected_before_commit.load(Ordering::Acquire);
                if expected == 0 {
                    Ok(0)
                } else {
                    let transaction_id = transaction_id.get().ok_or(CringeError::OutcomeUnknown)?;
                    self.reconcile_score_decay(now, transaction_id, expected, cancellation)
                        .await
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn reconcile_score_decay(
        &self,
        marker: DateTime<Utc>,
        transaction_id: &str,
        expected: u64,
        cancellation: &CancellationToken,
    ) -> Result<u64, CringeError> {
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self
            .client(deadline, cancellation)
            .await
            .map_err(|error| reconciliation_error("decay pool acquisition", error))?;
        let mut connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let transaction = connection
                .client_mut()
                .transaction()
                .await
                .map_err(database_error)?;
            configure_transaction_deadline(&transaction, deadline).await?;
            transaction
                .query_one(
                    "SELECT pg_advisory_xact_lock($1) \
                     /* lmyzmail_cringe_decay_commit_reconciliation */",
                    &[&DECAY_ADVISORY_LOCK_ID],
                )
                .await
                .map_err(database_error)?;
            let count = transaction
                .query_one(
                    "SELECT COUNT(*) FROM skibidi_cringe_ip \
                     WHERE last_decay_at = $1 AND xmin::text = $2",
                    &[&marker, &transaction_id],
                )
                .await
                .map_err(database_error)?
                .get::<_, i64>(0);
            transaction.commit().await.map_err(database_error)?;
            Ok(count)
        })
        .await;
        let count = connection
            .finish(outcome)
            .map_err(|error| reconciliation_error("decay verification", error))?;
        let count = u64::try_from(count).map_err(|_| CringeError::OutcomeUnknown)?;
        if count == expected {
            Ok(expected)
        } else {
            Err(CringeError::OutcomeUnknown)
        }
    }

    pub async fn cleanup_old_activities(
        &self,
        retention_days: u32,
        cancellation: &CancellationToken,
    ) -> Result<u64, CringeError> {
        let retention = chrono::Duration::try_days(i64::from(retention_days))
            .ok_or(CringeError::InvalidInput)?;
        let cutoff = Utc::now()
            .checked_sub_signed(retention)
            .ok_or(CringeError::InvalidInput)?;
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let mut connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = database_write(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(database_error)?;
                configure_transaction_deadline(&transaction, deadline).await?;
                ensure_active(&database_cancellation)?;
                let affected = transaction
                    .execute(
                        "DELETE FROM skibidi_cringe_ip_activity WHERE timestamp < $1",
                        &[&cutoff],
                    )
                    .await
                    .map_err(database_error)?;
                start_commit(deadline, &database_cancellation, &commit_started)?;
                transaction.commit().await.map_err(commit_error)?;
                Ok(affected)
            },
        )
        .await;
        connection.finish(outcome)
    }

    pub async fn insults(
        &self,
        query: PageQuery,
        cancellation: &CancellationToken,
    ) -> Result<ActivityPage, CringeError> {
        let (page, size) = validated_page(query.page, query.size)?;
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(
            deadline,
            cancellation,
            &cancel_token,
            activity_page_query(
                connection.client(),
                ActivityFilter::Insults(normalized_search(&query.search)),
                page,
                size.min(200),
            ),
        )
        .await;
        connection.finish(outcome)
    }

    pub async fn activities(
        &self,
        ip_address: &str,
        fallback_ip_address: Option<&str>,
        page: i64,
        size: i64,
        cancellation: &CancellationToken,
    ) -> Result<ActivityPage, CringeError> {
        let (page, size) = validated_page(page, size)?;
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let result = activity_page_query(
                connection.client(),
                ActivityFilter::Ip(ip_address.to_owned()),
                page,
                size,
            )
            .await?;
            if !result.empty {
                return Ok(result);
            }
            match fallback_ip_address.filter(|fallback| *fallback != ip_address) {
                Some(fallback) => {
                    activity_page_query(
                        connection.client(),
                        ActivityFilter::Ip(fallback.to_owned()),
                        page,
                        size,
                    )
                    .await
                }
                None => Ok(result),
            }
        })
        .await;
        connection.finish(outcome)
    }

    async fn client(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Object, CringeError> {
        wait_database(self.pool.get(), deadline, cancellation).await
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum XdpTrafficActivity {
    PpsOverlimit,
    SynFlood,
}

impl XdpTrafficActivity {
    const fn name(self) -> &'static str {
        match self {
            Self::PpsOverlimit => "PPS_OVERLIMIT",
            Self::SynFlood => "SYN_FLOOD",
        }
    }

    const fn counter_increments(self) -> (i32, i32) {
        match self {
            Self::PpsOverlimit => (1, 0),
            Self::SynFlood => (0, 1),
        }
    }
}

async fn activity_page_query(
    client: &Object,
    filter: ActivityFilter,
    page: i64,
    size: i64,
) -> Result<ActivityPage, CringeError> {
    let offset = page.checked_mul(size).ok_or(CringeError::InvalidInput)?;
    let (rows, total_elements) = match filter {
        ActivityFilter::Ip(ip_address) => {
            let sql = format!(
                "SELECT {ACTIVITY_COLUMNS} FROM skibidi_cringe_ip_activity \
                     WHERE ip_address = $1 ORDER BY timestamp DESC LIMIT $2 OFFSET $3"
            );
            let rows = client
                .query(&sql, &[&ip_address, &size, &offset])
                .await
                .map_err(database_error)?;
            let total = client
                .query_one(
                    "SELECT COUNT(*) FROM skibidi_cringe_ip_activity WHERE ip_address = $1",
                    &[&ip_address],
                )
                .await
                .map_err(database_error)?
                .get::<_, i64>(0);
            (rows, total)
        }
        ActivityFilter::Insults(search) => {
            if let Some(search) = search {
                let pattern = format!("%{search}%");
                let sql = format!(
                    "SELECT {ACTIVITY_COLUMNS} FROM skibidi_cringe_ip_activity \
                         WHERE activity_type = 'SELF_SPOOFING' AND response_message IS NOT NULL \
                         AND response_message <> '' AND LOWER(ip_address) LIKE LOWER($1) \
                         ORDER BY timestamp DESC LIMIT $2 OFFSET $3"
                );
                let rows = client
                    .query(&sql, &[&pattern, &size, &offset])
                    .await
                    .map_err(database_error)?;
                let total = client
                    .query_one(
                        "SELECT COUNT(*) FROM skibidi_cringe_ip_activity \
                         WHERE activity_type = 'SELF_SPOOFING' AND response_message IS NOT NULL \
                         AND response_message <> '' AND LOWER(ip_address) LIKE LOWER($1)",
                        &[&pattern],
                    )
                    .await
                    .map_err(database_error)?
                    .get::<_, i64>(0);
                (rows, total)
            } else {
                let sql = format!(
                    "SELECT {ACTIVITY_COLUMNS} FROM skibidi_cringe_ip_activity \
                         WHERE activity_type = 'SELF_SPOOFING' AND response_message IS NOT NULL \
                         AND response_message <> '' ORDER BY timestamp DESC LIMIT $1 OFFSET $2"
                );
                let rows = client
                    .query(&sql, &[&size, &offset])
                    .await
                    .map_err(database_error)?;
                let total = client
                    .query_one(
                        "SELECT COUNT(*) FROM skibidi_cringe_ip_activity \
                         WHERE activity_type = 'SELF_SPOOFING' AND response_message IS NOT NULL \
                         AND response_message <> ''",
                        &[],
                    )
                    .await
                    .map_err(database_error)?
                    .get::<_, i64>(0);
                (rows, total)
            }
        }
    };
    Ok(ActivityPage::new(
        rows.iter().map(activity_from_row).collect(),
        page,
        size,
        total_elements,
    ))
}

enum ActivityFilter {
    Ip(String),
    Insults(Option<String>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PageQuery {
    pub page: i64,
    pub size: i64,
    pub search: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityPage {
    pub content: Vec<CringeActivity>,
    pub pageable: Pageable,
    pub last: bool,
    pub total_elements: i64,
    pub total_pages: i64,
    pub first: bool,
    pub size: i64,
    pub number: i64,
    pub sort: PageSort,
    pub number_of_elements: i64,
    pub empty: bool,
}

impl ActivityPage {
    fn new(content: Vec<CringeActivity>, page: i64, size: i64, total_elements: i64) -> Self {
        let total_pages = page_count(total_elements, size);
        let number_of_elements = content.len() as i64;
        Self {
            content,
            pageable: Pageable {
                page_number: page,
                page_size: size,
                sort: PageSort::unsorted(),
                offset: page * size,
                paged: true,
                unpaged: false,
            },
            last: page + 1 >= total_pages,
            total_elements,
            total_pages,
            first: page == 0,
            size,
            number: page,
            sort: PageSort::unsorted(),
            number_of_elements,
            empty: number_of_elements == 0,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pageable {
    pub page_number: i64,
    pub page_size: i64,
    pub sort: PageSort,
    pub offset: i64,
    pub paged: bool,
    pub unpaged: bool,
}

#[derive(Debug, Serialize)]
pub struct PageSort {
    pub sorted: bool,
    pub empty: bool,
    pub unsorted: bool,
}

impl PageSort {
    const fn unsorted() -> Self {
        Self {
            sorted: false,
            empty: true,
            unsorted: true,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CringeIp {
    pub ip_address: String,
    pub total_score: i32,
    pub current_score: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_decay_at: Option<String>,
    pub activity_count: i32,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub self_spoofing_count: i32,
    pub open_relay_count: i32,
    pub auth_probe_count: i32,
    pub illegal_domain_count: i32,
    pub spamhaus_count: i32,
    pub http_on_smtp_count: i32,
    pub ssh_on_smtp_count: i32,
    pub http_port_scanning_count: i32,
    pub honeypot_hit_count: i32,
    pub ssh_bruteforce_count: i32,
    pub other_count: i32,
    pub protocol_mismatch_count: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CringeActivity {
    pub id: i64,
    pub ip_address: String,
    pub activity_type: String,
    pub score: i32,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rcpt_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub helo_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

#[derive(Debug)]
pub enum CringeError {
    Cancelled,
    Timeout,
    OutcomeUnknown,
    InvalidInput,
    CapacityExceeded,
    Database(String),
}

impl fmt::Display for CringeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("cringe request cancelled"),
            Self::Timeout => formatter.write_str("cringe database deadline exceeded"),
            Self::OutcomeUnknown => {
                formatter.write_str("cringe database commit outcome is unknown")
            }
            Self::InvalidInput => formatter.write_str("invalid cringe request"),
            Self::CapacityExceeded => {
                formatter.write_str("XDP reconcile candidate capacity exceeded")
            }
            Self::Database(error) => write!(formatter, "cringe database failure: {error}"),
        }
    }
}

impl std::error::Error for CringeError {}

fn cringe_ip_from_row(row: &Row) -> CringeIp {
    let http_on_smtp_count = nullable_count(row, "http_on_smtp_count");
    let ssh_on_smtp_count = nullable_count(row, "ssh_on_smtp_count");
    let http_port_scanning_count = nullable_count(row, "http_port_scanning_count");
    CringeIp {
        ip_address: row.get("ip_address"),
        total_score: row.get("total_score"),
        current_score: row.get("current_score"),
        last_decay_at: row
            .get::<_, Option<DateTime<Utc>>>("last_decay_at")
            .map(instant),
        activity_count: row.get("activity_count"),
        first_seen_at: instant(row.get("first_seen_at")),
        last_seen_at: instant(row.get("last_seen_at")),
        self_spoofing_count: nullable_count(row, "self_spoofing_count"),
        open_relay_count: nullable_count(row, "open_relay_count"),
        auth_probe_count: nullable_count(row, "auth_probe_count"),
        illegal_domain_count: nullable_count(row, "illegal_domain_count"),
        spamhaus_count: nullable_count(row, "spamhaus_count"),
        http_on_smtp_count,
        ssh_on_smtp_count,
        http_port_scanning_count,
        honeypot_hit_count: nullable_count(row, "honeypot_hit_count"),
        ssh_bruteforce_count: nullable_count(row, "ssh_bruteforce_count"),
        other_count: nullable_count(row, "other_count"),
        protocol_mismatch_count: http_on_smtp_count
            .wrapping_add(ssh_on_smtp_count)
            .wrapping_add(http_port_scanning_count),
    }
}

fn insert_xdp_candidate(
    candidates: &mut HashMap<IpAddr, i32>,
    row: &Row,
    score: i32,
) -> Result<(), CringeError> {
    merge_xdp_candidate(candidates, &row.get::<_, String>("ip_address"), score)
}

fn merge_xdp_candidate(
    candidates: &mut HashMap<IpAddr, i32>,
    address: &str,
    score: i32,
) -> Result<(), CringeError> {
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| CringeError::Database("stored cringe IP address is invalid".into()))?;
    candidates
        .entry(address)
        .and_modify(|existing| *existing = (*existing).max(score))
        .or_insert(score);
    Ok(())
}

fn activity_from_row(row: &Row) -> CringeActivity {
    CringeActivity {
        id: row.get("id"),
        ip_address: row.get("ip_address"),
        activity_type: row.get("activity_type"),
        score: row.get("score"),
        timestamp: instant(row.get("timestamp")),
        mail_from: row.get("mail_from"),
        rcpt_to: row.get("rcpt_to"),
        helo_name: row.get("helo_name"),
        session_id: row.get("session_id"),
        response_message: row.get("response_message"),
        metadata: row.get("metadata"),
    }
}

fn nullable_count(row: &Row, column: &str) -> i32 {
    row.get::<_, Option<i32>>(column).unwrap_or_default()
}

fn instant(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

fn page_count(total: i64, size: i64) -> i64 {
    if total == 0 {
        0
    } else {
        (total - 1) / size + 1
    }
}

fn validated_page(page: i64, size: i64) -> Result<(i64, i64), CringeError> {
    if page < 0 || page > i64::from(i32::MAX) || size <= 0 || size > i64::from(i32::MAX) {
        return Err(CringeError::InvalidInput);
    }
    Ok((page, size.min(MAX_PAGE_SIZE)))
}

fn normalized_search(search: &str) -> Option<String> {
    let search = search.trim();
    (!search.is_empty()).then(|| search.to_owned())
}

async fn wait_database<T, E, F>(
    future: F,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<T, CringeError>
where
    E: fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(CringeError::Cancelled),
        result = timeout_at(deadline, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(CringeError::Database(error.to_string())),
            Err(_) => Err(CringeError::Timeout),
        }
    }
}

fn database_error(error: tokio_postgres::Error) -> CringeError {
    CringeError::Database(format!("{error} ({error:?})"))
}

struct DatabaseOutcome<T> {
    result: Result<T, CringeError>,
    discard_connection: bool,
}

struct DatabaseConnection {
    client: Option<Object>,
}

impl DatabaseConnection {
    fn new(client: Object) -> Self {
        Self {
            client: Some(client),
        }
    }

    fn client(&self) -> &Object {
        self.client
            .as_ref()
            .expect("database connection is present")
    }

    fn client_mut(&mut self) -> &mut Object {
        self.client
            .as_mut()
            .expect("database connection is present")
    }

    fn cancel_token(&self) -> CancelToken {
        self.client().cancel_token()
    }

    fn finish<T>(mut self, outcome: DatabaseOutcome<T>) -> Result<T, CringeError> {
        let client = self.client.take().expect("database connection is present");
        if outcome.discard_connection {
            drop(Object::take(client));
        } else {
            drop(client);
        }
        outcome.result
    }
}

impl Drop for DatabaseConnection {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            drop(Object::take(client));
        }
    }
}

async fn database_read<T, F>(
    deadline: Instant,
    cancellation: &CancellationToken,
    cancel_token: &CancelToken,
    future: F,
) -> DatabaseOutcome<T>
where
    F: Future<Output = Result<T, CringeError>>,
{
    tokio::pin!(future);
    let interruption = tokio::select! {
        biased;
        _ = cancellation.cancelled() => CringeError::Cancelled,
        result = timeout_at(deadline, future.as_mut()) => match result {
            Ok(result) => return DatabaseOutcome {
                result,
                discard_connection: false,
            },
            Err(_) => CringeError::Timeout,
        },
    };

    let recovery = timeout_at(Instant::now() + DATABASE_CANCEL_DRAIN_TIMEOUT, async {
        tokio::join!(cancel_token.cancel_query(NoTls), future.as_mut())
    })
    .await;
    let discard_connection = !matches!(recovery, Ok((Ok(()), _)));
    DatabaseOutcome {
        result: Err(interruption),
        discard_connection,
    }
}

async fn database_write<T, F>(
    deadline: Instant,
    cancellation: &CancellationToken,
    cancel_token: &CancelToken,
    commit_started: &AtomicBool,
    future: F,
) -> DatabaseOutcome<T>
where
    F: Future<Output = Result<T, CringeError>>,
{
    tokio::pin!(future);
    let interruption = tokio::select! {
        biased;
        _ = cancellation.cancelled() => CringeError::Cancelled,
        result = timeout_at(deadline, future.as_mut()) => match result {
            Ok(result) => return completed_database_outcome(result),
            Err(_) => CringeError::Timeout,
        },
    };

    let recovery_deadline = Instant::now() + DATABASE_CANCEL_DRAIN_TIMEOUT;
    if commit_started.load(Ordering::Acquire) {
        return match timeout_at(recovery_deadline, future.as_mut()).await {
            Ok(result) => completed_database_outcome(result),
            Err(_) => DatabaseOutcome {
                result: Err(CringeError::OutcomeUnknown),
                discard_connection: true,
            },
        };
    }

    cancellation.cancel();
    let recovery = timeout_at(recovery_deadline, async {
        tokio::join!(cancel_token.cancel_query(NoTls), future.as_mut())
    })
    .await;
    DatabaseOutcome {
        result: Err(interruption),
        discard_connection: !matches!(recovery, Ok((Ok(()), _))),
    }
}

fn completed_database_outcome<T>(result: Result<T, CringeError>) -> DatabaseOutcome<T> {
    DatabaseOutcome {
        discard_connection: matches!(result, Err(CringeError::OutcomeUnknown)),
        result,
    }
}

fn start_commit(
    deadline: Instant,
    cancellation: &CancellationToken,
    commit_started: &AtomicBool,
) -> Result<(), CringeError> {
    ensure_active(cancellation)?;
    if Instant::now() >= deadline {
        return Err(CringeError::Timeout);
    }
    commit_started.store(true, Ordering::Release);
    Ok(())
}

async fn configure_transaction_deadline(
    transaction: &deadpool_postgres::Transaction<'_>,
    deadline: Instant,
) -> Result<(), CringeError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let server_millis = (remaining.as_millis() / 2).clamp(1, i32::MAX as u128);
    let value = format!("{server_millis}ms");
    timeout_at(
        deadline,
        transaction.query_one("SELECT set_config('statement_timeout',$1,true)", &[&value]),
    )
    .await
    .map_err(|_| CringeError::Timeout)?
    .map_err(database_error)?;
    Ok(())
}

fn ensure_active(cancellation: &CancellationToken) -> Result<(), CringeError> {
    if cancellation.is_cancelled() {
        Err(CringeError::Cancelled)
    } else {
        Ok(())
    }
}

fn commit_error(error: tokio_postgres::Error) -> CringeError {
    if error.as_db_error().is_some() {
        database_error(error)
    } else {
        CringeError::OutcomeUnknown
    }
}

fn reconciliation_error(stage: &str, error: impl fmt::Display + fmt::Debug) -> CringeError {
    eprintln!("lmyzmail cringe commit reconciliation failed at {stage}: {error} ({error:?})");
    CringeError::OutcomeUnknown
}

fn truncate_chars(value: &str, limit: usize) -> String {
    match value.char_indices().nth(limit) {
        Some((end, _)) => value[..end].to_owned(),
        None => value.to_owned(),
    }
}

fn is_exact_localhost(ip: IpAddr) -> bool {
    ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activity(id: i64) -> CringeActivity {
        CringeActivity {
            id,
            ip_address: "203.0.113.77".to_owned(),
            activity_type: "SELF_SPOOFING".to_owned(),
            score: 10,
            timestamp: "2024-01-02T03:04:05.123456Z".to_owned(),
            mail_from: Some("from@example.test".to_owned()),
            rcpt_to: None,
            helo_name: None,
            session_id: Some("session-1".to_owned()),
            response_message: Some("insult".to_owned()),
            metadata: None,
        }
    }

    #[test]
    fn page_counts_are_stable() {
        assert_eq!(page_count(0, 50), 0);
        assert_eq!(page_count(1, 50), 1);
        assert_eq!(page_count(51, 50), 2);
    }

    #[test]
    fn paging_rejects_invalid_java_integer_inputs_and_caps_valid_sizes() {
        assert!(matches!(
            validated_page(-1, 50),
            Err(CringeError::InvalidInput)
        ));
        assert!(matches!(
            validated_page(0, 0),
            Err(CringeError::InvalidInput)
        ));
        assert!(matches!(
            validated_page(i64::from(i32::MAX) + 1, 50),
            Err(CringeError::InvalidInput)
        ));
        assert_eq!(validated_page(2, 501).expect("valid page"), (2, 500));
    }

    #[test]
    fn activity_page_matches_spring_page_shape_and_order() {
        let json = serde_json::to_string(&ActivityPage::new(vec![activity(7)], 0, 50, 1))
            .expect("page must serialize");
        assert_eq!(
            json,
            r#"{"content":[{"id":7,"ipAddress":"203.0.113.77","activityType":"SELF_SPOOFING","score":10,"timestamp":"2024-01-02T03:04:05.123456Z","mailFrom":"from@example.test","sessionId":"session-1","responseMessage":"insult"}],"pageable":{"pageNumber":0,"pageSize":50,"sort":{"sorted":false,"empty":true,"unsorted":true},"offset":0,"paged":true,"unpaged":false},"last":true,"totalElements":1,"totalPages":1,"first":true,"size":50,"number":0,"sort":{"sorted":false,"empty":true,"unsorted":true},"numberOfElements":1,"empty":false}"#
        );
    }

    #[test]
    fn optional_cringe_fields_match_jackson_non_null_serialization() {
        let activity_json = serde_json::to_value(CringeActivity {
            response_message: Some(String::new()),
            ..activity(8)
        })
        .expect("activity must serialize");
        assert_eq!(activity_json["responseMessage"], "");
        assert!(activity_json.get("rcptTo").is_none());
        assert!(activity_json.get("heloName").is_none());
        assert!(activity_json.get("metadata").is_none());

        let ip_json = serde_json::to_value(CringeIp {
            ip_address: "198.51.100.9".to_owned(),
            total_score: 5,
            current_score: 19,
            last_decay_at: None,
            activity_count: 1,
            first_seen_at: "2024-01-01T12:00:00Z".to_owned(),
            last_seen_at: "2024-01-04T00:00:00Z".to_owned(),
            self_spoofing_count: 1,
            open_relay_count: 0,
            auth_probe_count: 0,
            illegal_domain_count: 0,
            spamhaus_count: 0,
            http_on_smtp_count: 0,
            ssh_on_smtp_count: 0,
            http_port_scanning_count: 0,
            honeypot_hit_count: 0,
            ssh_bruteforce_count: 0,
            other_count: 0,
            protocol_mismatch_count: 0,
        })
        .expect("IP must serialize");
        assert!(ip_json.get("lastDecayAt").is_none());
    }

    #[test]
    fn empty_page_matches_spring_terminal_flags() {
        let json = serde_json::to_value(ActivityPage::new(Vec::new(), 0, 50, 0))
            .expect("page must serialize");
        assert_eq!(json["last"], true);
        assert_eq!(json["first"], true);
        assert_eq!(json["empty"], true);
        assert_eq!(json["totalPages"], 0);
        assert_eq!(json["numberOfElements"], 0);
    }

    #[test]
    fn xdp_candidate_merge_is_bounded_and_keeps_the_highest_score() {
        let mut candidates = HashMap::new();
        merge_xdp_candidate(&mut candidates, "192.0.2.44", 51).unwrap();
        merge_xdp_candidate(&mut candidates, "192.0.2.44", 80).unwrap();
        merge_xdp_candidate(&mut candidates, "192.0.2.44", 60).unwrap();
        assert_eq!(candidates[&"192.0.2.44".parse().unwrap()], 80);
        assert!(matches!(
            merge_xdp_candidate(&mut candidates, "not-an-ip", 100),
            Err(CringeError::Database(_))
        ));
        assert!(MAX_XDP_EXISTING_BANS > MAX_EXPORT_ROWS as usize);
        assert_eq!(
            MAX_XDP_RECONCILE_CANDIDATES,
            MAX_XDP_EXISTING_BANS + MAX_XDP_NEW_CANDIDATES
        );
    }

    #[test]
    fn smtp_activity_details_truncate_on_character_boundaries_and_increment_one_category() {
        let mail_from = "\u{e9}".repeat(300);
        let response = "\u{e9}".repeat(600);
        let metadata = "\u{e9}".repeat(1_100);
        let self_spoof = ActivityDetails::self_spoofing(&mail_from, &response, &metadata);
        assert_eq!(
            self_spoof.mail_from.as_deref().unwrap().chars().count(),
            255
        );
        assert_eq!(
            self_spoof
                .response_message
                .as_deref()
                .unwrap()
                .chars()
                .count(),
            512,
        );
        assert_eq!(self_spoof.metadata.chars().count(), 1_024);
        assert_eq!(
            ActivityIncrements::self_spoofing(),
            ActivityIncrements {
                self_spoofing: 1,
                ..ActivityIncrements::default()
            },
        );

        let illegal = ActivityDetails::illegal_sender_domain(&mail_from, &metadata);
        assert_eq!(illegal.mail_from.as_deref().unwrap().chars().count(), 255);
        assert!(illegal.response_message.is_none());
        assert_eq!(illegal.metadata.chars().count(), 1_024);
        assert_eq!(
            ActivityIncrements::illegal_sender_domain(),
            ActivityIncrements {
                illegal_domain: 1,
                ..ActivityIncrements::default()
            },
        );

        let spamhaus = ActivityDetails::spamhaus(&mail_from, &metadata);
        assert_eq!(spamhaus.mail_from.as_deref().unwrap().chars().count(), 255);
        assert!(spamhaus.response_message.is_none());
        assert_eq!(spamhaus.metadata.chars().count(), 1_024);
        assert_eq!(
            ActivityIncrements::spamhaus(),
            ActivityIncrements {
                spamhaus: 1,
                ..ActivityIncrements::default()
            },
        );

        let protocol =
            ActivityDetails::protocol_violation(&"h".repeat(300), &"s".repeat(80), &metadata);
        assert_eq!(protocol.helo_name.as_deref().unwrap().len(), 255);
        assert_eq!(protocol.session_id.as_deref().unwrap().len(), 64);
        assert_eq!(protocol.metadata.chars().count(), 1_024);
        assert_eq!(
            ActivityIncrements::protocol_violation(),
            ActivityIncrements {
                other: 1,
                ..ActivityIncrements::default()
            },
        );
    }
}
