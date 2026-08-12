use std::{
    collections::HashMap,
    fmt,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bcrypt::{hash, verify};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use deadpool_postgres::{Object, Pool};
use getrandom::fill as fill_random;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::{
    sync::{Mutex, Semaphore},
    time::{Instant, timeout_at},
};
use tokio_postgres::{CancelToken, NoTls, Row, types::ToSql};
use tokio_util::sync::CancellationToken;

use crate::{bounded_blocking::BoundedBlockingPool, config::RuntimeConfig};

const TOKEN_BYTES: usize = 32;
const TOKEN_PREFIX_BYTES: usize = 8;
const PASSWORD_COST: u32 = 10;
const DB_TIMEOUT: Duration = Duration::from_secs(8);
const DB_CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_FAILURE_LIMIT: u32 = 10;
const DEFAULT_REGISTRATION_LIMIT: u32 = 5;
const MAX_RATE_LIMIT_ENTRIES: usize = 16_384;
const PASSWORD_WORKERS: usize = 4;
const DUMMY_BCRYPT: &str = "$2a$10$KMejGNeOXWSJBM831XMwmeVrw.16AhD65yYCs7vxZIM0osXpoyPsm";

#[derive(Debug)]
pub enum AuthError {
    Cancelled,
    Database(String),
    InvalidInput(String),
    OutcomeUnknown,
    Unavailable,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled | Self::Database(_) | Self::OutcomeUnknown | Self::Unavailable => {
                f.write_str("authentication backend unavailable")
            }
            Self::InvalidInput(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for AuthError {}

#[derive(Debug, Clone, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterResponse {
    pub id: i64,
    pub address: String,
    pub message: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CreatedMailbox {
    pub id: i64,
    pub address: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LoginOutcome {
    Invalid { ip_banned: bool },
    Success,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CredentialOutcome {
    Invalid { ip_banned: bool },
    Valid { address: String },
}

#[derive(Debug, Clone)]
struct TokenBucket {
    remaining: u32,
    refill_at: std::time::Instant,
}

impl TokenBucket {
    fn consume(&mut self, now: std::time::Instant, capacity: u32, window: Duration) -> bool {
        if now >= self.refill_at {
            self.remaining = capacity;
            self.refill_at = now + window;
        }
        if self.remaining == 0 {
            false
        } else {
            self.remaining -= 1;
            true
        }
    }
}

#[derive(Debug, Default)]
struct RateLimitState {
    ip_login: HashMap<String, TokenBucket>,
    principal_login: HashMap<String, TokenBucket>,
    registration: HashMap<String, TokenBucket>,
    banned_ips: HashMap<String, IpBan>,
    overflow_ban: Option<IpBan>,
}

#[derive(Debug, Clone)]
struct IpBan {
    until: std::time::Instant,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AuthCommitReconciliation<T> {
    Committed(T),
    NotCommitted,
    OutcomeUnknown,
}

#[derive(Debug, Clone)]
enum TokenValidationCommit {
    Expired {
        address: String,
        expires_at: DateTime<Utc>,
    },
    LastUsed {
        address: String,
        expires_at: DateTime<Utc>,
        used_at: DateTime<Utc>,
    },
}

#[derive(Clone)]
pub struct AuthService {
    pool: Pool,
    registration_domains: Arc<HashMap<String, bool>>,
    public_registration: bool,
    session_expiry_days: i64,
    max_sessions_per_user: i64,
    track_last_used: bool,
    rate_enabled: bool,
    failed_login_limit: u32,
    failed_login_window: Duration,
    ban_duration: Duration,
    registration_limit: u32,
    registration_window: Duration,
    rate_limits: Arc<Mutex<RateLimitState>>,
    password_pool: Arc<BoundedBlockingPool>,
    password_permits: Arc<Semaphore>,
    registration_permit: Arc<Semaphore>,
}

impl AuthService {
    pub fn from_config(config: &RuntimeConfig, pool: Pool) -> Result<Self, AuthError> {
        let session_expiry_days = config
            .preferred_value(
                "lmyzmail.session.expiry-days",
                "botmail.session.expiry-days",
            )
            .unwrap_or("7")
            .parse::<i64>()
            .map_err(|_| AuthError::InvalidInput("session expiry is invalid".into()))?;
        let max_sessions_per_user = config
            .preferred_value(
                "lmyzmail.session.max-per-user",
                "botmail.session.max-per-user",
            )
            .unwrap_or("10")
            .parse::<i64>()
            .map_err(|_| AuthError::InvalidInput("session limit is invalid".into()))?;
        let track_last_used = config
            .preferred_value(
                "lmyzmail.session.track-last-used",
                "botmail.session.track-last-used",
            )
            .unwrap_or("true")
            .parse::<bool>()
            .map_err(|_| AuthError::InvalidInput("session tracking flag is invalid".into()))?;
        let rate_enabled = parse_bool(
            config,
            "lmyzmail.rate-limit.enabled",
            "botmail.rate-limit.enabled",
            true,
        )?;
        let failed_login_limit = parse_u32(
            config,
            "lmyzmail.rate-limit.max-failed-login-attempts",
            "botmail.rate-limit.max-failed-login-attempts",
            DEFAULT_FAILURE_LIMIT,
        )?;
        let failed_login_window = bounded_minutes(parse_u64(
            config,
            "lmyzmail.rate-limit.failed-login-window-minutes",
            "botmail.rate-limit.failed-login-window-minutes",
            5,
        )?)?;
        let ban_duration = bounded_hours(parse_u64(
            config,
            "lmyzmail.rate-limit.ip-ban-duration-hours",
            "botmail.rate-limit.ip-ban-duration-hours",
            3,
        )?)?;
        let registration_limit = parse_u32(
            config,
            "lmyzmail.rate-limit.max-registrations-per-ip",
            "botmail.rate-limit.max-registrations-per-ip",
            DEFAULT_REGISTRATION_LIMIT,
        )?;
        let registration_window = bounded_hours(parse_u64(
            config,
            "lmyzmail.rate-limit.registration-rate-window-hours",
            "botmail.rate-limit.registration-rate-window-hours",
            3,
        )?)?;
        if !(1..=3650).contains(&session_expiry_days)
            || !(1..=1000).contains(&max_sessions_per_user)
            || failed_login_limit == 0
            || failed_login_limit > 1_000_000
            || registration_limit == 0
            || registration_limit > 1_000_000
        {
            return Err(AuthError::InvalidInput(
                "session settings are outside safe bounds".into(),
            ));
        }
        let password_pool =
            BoundedBlockingPool::new("lmyzmail-auth-bcrypt", PASSWORD_WORKERS, PASSWORD_WORKERS)
                .map_err(|error| AuthError::Database(format!("password worker pool: {error}")))?;
        let registration_domains = config
            .domains
            .iter()
            .map(|domain| (domain.domain.clone(), domain.receive_enabled))
            .collect::<HashMap<_, _>>();
        debug_assert!(!registration_domains.is_empty());
        Ok(Self {
            pool,
            registration_domains: Arc::new(registration_domains),
            public_registration: config.features.public_registration,
            session_expiry_days,
            max_sessions_per_user,
            track_last_used,
            rate_enabled,
            failed_login_limit,
            failed_login_window,
            ban_duration,
            registration_limit,
            registration_window,
            rate_limits: Arc::new(Mutex::new(RateLimitState::default())),
            password_pool: Arc::new(password_pool),
            password_permits: Arc::new(Semaphore::new(PASSWORD_WORKERS)),
            registration_permit: Arc::new(Semaphore::new(1)),
        })
    }

    pub async fn login(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
        user_agent: Option<&str>,
    ) -> Result<(LoginOutcome, Option<LoginResponse>), AuthError> {
        self.login_with_cancellation(
            address,
            password,
            client_ip,
            user_agent,
            &CancellationToken::new(),
        )
        .await
    }

    pub async fn login_with_cancellation(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
        user_agent: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<(LoginOutcome, Option<LoginResponse>), AuthError> {
        let deadline = auth_deadline();
        let response_address = address.to_owned();
        let address = match self
            .verify_mailbox_credentials_until(address, password, client_ip, deadline, cancellation)
            .await?
        {
            CredentialOutcome::Invalid { ip_banned } => {
                return Ok((LoginOutcome::Invalid { ip_banned }, None));
            }
            CredentialOutcome::Valid { address } => address,
        };
        let token = generate_token()?;
        let token_hash = hash_token(&token);
        let now = postgres_timestamp(Utc::now());
        let expires = now + ChronoDuration::days(self.session_expiry_days);
        let token_prefix = token[..TOKEN_PREFIX_BYTES.min(token.len())].to_owned();
        let user_agent = user_agent.map(|value| value.chars().take(500).collect::<String>());
        let mut connection = AuthDatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = auth_database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(db_error)?;
                configure_auth_transaction_deadline(&transaction, deadline).await?;
                ensure_auth_active(&database_cancellation)?;
                transaction
                    .query_one(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
                        &[&address],
                    )
                    .await
                    .map_err(db_error)?;
                ensure_auth_active(&database_cancellation)?;
                let rows = transaction
                    .query(
                        "SELECT id FROM user_session WHERE mailbox_address=$1 AND expires_at>$2 ORDER BY created_at DESC",
                        &[&address, &now],
                    )
                    .await
                    .map_err(db_error)?;
                if rows.len() as i64 >= self.max_sessions_per_user {
                    let remove = rows.len() as i64 - self.max_sessions_per_user + 1;
                    for row in rows.into_iter().rev().take(remove as usize) {
                        let id: i64 = row.get(0);
                        transaction
                            .execute("DELETE FROM user_session WHERE id=$1", &[&id])
                            .await
                            .map_err(db_error)?;
                    }
                }
                ensure_auth_active(&database_cancellation)?;
                transaction.execute(
                    "INSERT INTO user_session (mailbox_address, token_hash, token_prefix, created_at, expires_at, last_used_at, created_ip, user_agent) VALUES ($1,$2,$3,$4,$5,$4,$6,$7)",
                    &[&address, &token_hash, &token_prefix, &now, &expires, &client_ip, &user_agent],
                ).await.map_err(db_error)?;
                start_auth_commit(deadline, &database_cancellation, &commit_started)?;
                transaction.commit().await.map_err(auth_commit_error)
            },
        )
        .await;
        match connection.finish(outcome) {
            Ok(()) => {}
            Err(AuthError::OutcomeUnknown) => {
                match self
                    .reconcile_login(
                        &address,
                        &token_hash,
                        &token_prefix,
                        now,
                        expires,
                        client_ip,
                        user_agent.as_deref(),
                    )
                    .await
                {
                    AuthCommitReconciliation::Committed(()) => {}
                    AuthCommitReconciliation::NotCommitted => {
                        return Err(AuthError::Unavailable);
                    }
                    AuthCommitReconciliation::OutcomeUnknown => {
                        return Err(AuthError::OutcomeUnknown);
                    }
                }
            }
            Err(error) => return Err(error),
        }
        Ok((
            LoginOutcome::Success,
            Some(LoginResponse {
                token,
                address: response_address,
            }),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn reconcile_login(
        &self,
        address: &str,
        token_hash: &str,
        token_prefix: &str,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        client_ip: &str,
        user_agent: Option<&str>,
    ) -> AuthCommitReconciliation<()> {
        let row = match auth_reconciliation_query(
            &self.pool,
            address,
            "login",
            "/* lmyzmail_auth_login_commit_reconciliation */
             SELECT mailbox_address,token_prefix,created_at,expires_at,last_used_at,created_ip,user_agent
             FROM user_session WHERE token_hash=$1",
            &[&token_hash],
        )
        .await
        {
            Ok(row) => row,
            Err(_) => return AuthCommitReconciliation::OutcomeUnknown,
        };
        match row {
            Some(row)
                if row.get::<_, &str>(0) == address
                    && row.get::<_, Option<&str>>(1) == Some(token_prefix)
                    && row.get::<_, DateTime<Utc>>(2) == created_at
                    && row.get::<_, DateTime<Utc>>(3) == expires_at
                    && row.get::<_, Option<DateTime<Utc>>>(4) == Some(created_at)
                    && row.get::<_, Option<&str>>(5) == Some(client_ip)
                    && row.get::<_, Option<&str>>(6) == user_agent =>
            {
                AuthCommitReconciliation::Committed(())
            }
            Some(_) => AuthCommitReconciliation::OutcomeUnknown,
            None => AuthCommitReconciliation::NotCommitted,
        }
    }

    pub async fn verify_mailbox_credentials(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
    ) -> Result<CredentialOutcome, AuthError> {
        self.verify_mailbox_credentials_with_cancellation(
            address,
            password,
            client_ip,
            &CancellationToken::new(),
        )
        .await
    }

    pub async fn verify_mailbox_credentials_with_cancellation(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
        cancellation: &CancellationToken,
    ) -> Result<CredentialOutcome, AuthError> {
        self.verify_mailbox_credentials_until(
            address,
            password,
            client_ip,
            auth_deadline(),
            cancellation,
        )
        .await
    }

    async fn verify_mailbox_credentials_until(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<CredentialOutcome, AuthError> {
        let address = normalize_login_address(address).unwrap_or_default();
        if self.ban_expiry(client_ip).await.is_some() {
            return Ok(CredentialOutcome::Invalid { ip_banned: true });
        }
        let row = self
            .db_query_mailbox(&address, deadline, cancellation)
            .await?;
        let (mailbox_exists, password_hash) = match row {
            Some((_, password_hash)) => (true, password_hash),
            None => (false, DUMMY_BCRYPT.to_owned()),
        };
        let valid = self
            .verify_password(password.to_owned(), password_hash, deadline, cancellation)
            .await?;
        if !valid || !mailbox_exists {
            let ip_banned = self.record_failure(client_ip, &address).await;
            return Ok(CredentialOutcome::Invalid { ip_banned });
        }
        self.clear_principal_failure(client_ip, &address).await;
        Ok(CredentialOutcome::Valid { address })
    }

    pub async fn register(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
    ) -> Result<RegisterResponse, AuthError> {
        self.register_with_cancellation(address, password, client_ip, &CancellationToken::new())
            .await
    }

    pub async fn register_with_cancellation(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
        cancellation: &CancellationToken,
    ) -> Result<RegisterResponse, AuthError> {
        if !self.public_registration {
            return Err(AuthError::InvalidInput("registration_disabled".into()));
        }
        let created = self
            .create_mailbox(address, password, client_ip, cancellation)
            .await?;
        Ok(RegisterResponse {
            id: created.id,
            address: created.address,
            message: "Registration successful. You can now log in.",
        })
    }

    pub async fn create_mailbox_api(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
    ) -> Result<CreatedMailbox, AuthError> {
        self.create_mailbox_api_with_cancellation(
            address,
            password,
            client_ip,
            &CancellationToken::new(),
        )
        .await
    }

    pub async fn create_mailbox_api_with_cancellation(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
        cancellation: &CancellationToken,
    ) -> Result<CreatedMailbox, AuthError> {
        self.create_mailbox(address, password, client_ip, cancellation)
            .await
    }

    pub async fn mailbox_exists(&self, address: &str) -> Result<bool, AuthError> {
        self.mailbox_exists_with_cancellation(address, &CancellationToken::new())
            .await
    }

    pub async fn mailbox_exists_with_cancellation(
        &self,
        address: &str,
        cancellation: &CancellationToken,
    ) -> Result<bool, AuthError> {
        let normalized = address.trim().to_lowercase();
        if normalized.is_empty() || normalized.len() > 4096 {
            return Ok(false);
        }
        self.db_mailbox_exists(&normalized, auth_deadline(), cancellation)
            .await
    }

    async fn create_mailbox(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
        cancellation: &CancellationToken,
    ) -> Result<CreatedMailbox, AuthError> {
        let deadline = auth_deadline();
        if address.trim().is_empty() {
            return Err(AuthError::InvalidInput("address_required".into()));
        }
        if password.encode_utf16().count() < 8 {
            return Err(AuthError::InvalidInput("password_too_short".into()));
        }
        let _registration_permit = bounded_auth_future(
            deadline,
            cancellation,
            "registration permit",
            self.registration_permit.clone().acquire_owned(),
        )
        .await?;
        if !self.can_register(client_ip).await {
            return Err(AuthError::InvalidInput("rate_limit_exceeded".into()));
        }
        let address = normalize_address(address)?;
        let domain = address
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or_default();
        let Some(receive_enabled) = self.registration_domains.get(domain) else {
            return Err(AuthError::InvalidInput(format!(
                "Domain not configured: {domain}"
            )));
        };
        if !receive_enabled {
            return Err(AuthError::InvalidInput(format!(
                "Domain does not accept mail: {domain}"
            )));
        }
        if self
            .db_mailbox_exists(&address, deadline, cancellation)
            .await?
        {
            return Err(AuthError::InvalidInput(format!(
                "Mailbox already exists: {address}"
            )));
        }
        let password_hash = self
            .hash_password(password.to_owned(), deadline, cancellation)
            .await?;
        let created_at = postgres_timestamp(Utc::now());
        let mut connection = AuthDatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = auth_database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(db_error)?;
                configure_auth_transaction_deadline(&transaction, deadline).await?;
                ensure_auth_active(&database_cancellation)?;
                transaction
                    .query_one(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
                        &[&address],
                    )
                    .await
                    .map_err(db_error)?;
                ensure_auth_active(&database_cancellation)?;
                let row = transaction
                    .query_one(
                        "INSERT INTO mailbox (address, password_hash, created_at) VALUES ($1,$2,$3) RETURNING id",
                        &[&address, &password_hash, &created_at],
                    )
                    .await
                    .map_err(|error| {
                        if error.code().is_some_and(|code| code.code() == "23505") {
                            AuthError::InvalidInput(format!(
                                "Mailbox already exists: {address}"
                            ))
                        } else {
                            db_error(error)
                        }
                    })?;
                let id = row.get::<_, i64>(0);
                start_auth_commit(deadline, &database_cancellation, &commit_started)?;
                transaction.commit().await.map_err(auth_commit_error)?;
                Ok(id)
            },
        )
        .await;
        let result = connection.finish(outcome);
        let id = match result {
            Ok(id) => id,
            Err(AuthError::OutcomeUnknown) => {
                match self
                    .reconcile_mailbox_creation(&address, &password_hash, created_at)
                    .await
                {
                    AuthCommitReconciliation::Committed(id) => id,
                    AuthCommitReconciliation::NotCommitted => {
                        return Err(AuthError::Unavailable);
                    }
                    AuthCommitReconciliation::OutcomeUnknown => {
                        self.record_registration(client_ip).await;
                        return Err(AuthError::OutcomeUnknown);
                    }
                }
            }
            Err(error) => return Err(error),
        };
        self.record_registration(client_ip).await;
        Ok(CreatedMailbox { id, address })
    }

    async fn reconcile_mailbox_creation(
        &self,
        address: &str,
        password_hash: &str,
        created_at: DateTime<Utc>,
    ) -> AuthCommitReconciliation<i64> {
        let row = match auth_reconciliation_query(
            &self.pool,
            address,
            "mailbox creation",
            "/* lmyzmail_auth_mailbox_commit_reconciliation */
                 SELECT id,password_hash,created_at FROM mailbox WHERE address=$1",
            &[&address],
        )
        .await
        {
            Ok(row) => row,
            Err(_) => return AuthCommitReconciliation::OutcomeUnknown,
        };
        let materialized = row.map(|row| {
            (
                row.get::<_, i64>(0),
                row.get::<_, String>(1),
                row.get::<_, DateTime<Utc>>(2),
            )
        });
        classify_mailbox_creation(materialized, password_hash, created_at)
    }

    pub async fn logout(&self, token: Option<&str>) -> Result<(), AuthError> {
        self.logout_with_cancellation(token, &CancellationToken::new())
            .await
    }

    pub async fn logout_with_cancellation(
        &self,
        token: Option<&str>,
        cancellation: &CancellationToken,
    ) -> Result<(), AuthError> {
        let Some(token) = token.filter(|value| !value.trim().is_empty()) else {
            return Ok(());
        };
        let deadline = auth_deadline();
        let hash = hash_token(token);
        let mut connection = AuthDatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = auth_database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(db_error)?;
                configure_auth_transaction_deadline(&transaction, deadline).await?;
                ensure_auth_active(&database_cancellation)?;
                transaction
                    .query_one(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
                        &[&hash],
                    )
                    .await
                    .map_err(db_error)?;
                ensure_auth_active(&database_cancellation)?;
                transaction
                    .execute("DELETE FROM user_session WHERE token_hash=$1", &[&hash])
                    .await
                    .map_err(db_error)?;
                start_auth_commit(deadline, &database_cancellation, &commit_started)?;
                transaction.commit().await.map_err(auth_commit_error)
            },
        )
        .await;
        match connection.finish(outcome) {
            Ok(()) => Ok(()),
            Err(AuthError::OutcomeUnknown) => {
                let row = auth_reconciliation_query(
                    &self.pool,
                    &hash,
                    "logout",
                    "/* lmyzmail_auth_logout_commit_reconciliation */
                     SELECT token_hash FROM user_session WHERE token_hash=$1",
                    &[&hash],
                )
                .await?;
                if row.is_none() {
                    Ok(())
                } else {
                    Err(AuthError::Unavailable)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub async fn validate_token(&self, token: &str) -> Result<Option<String>, AuthError> {
        self.validate_token_with_cancellation(token, &CancellationToken::new())
            .await
    }

    pub async fn validate_token_with_cancellation(
        &self,
        token: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<String>, AuthError> {
        if token.trim().is_empty() {
            return Ok(None);
        }
        let deadline = auth_deadline();
        let hash = hash_token(token);
        let mut connection = AuthDatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let mut pending_reconciliation = None;
        let outcome = auth_database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            async {
                let transaction = connection
                    .client_mut()
                    .transaction()
                    .await
                    .map_err(db_error)?;
                configure_auth_transaction_deadline(&transaction, deadline).await?;
                ensure_auth_active(&database_cancellation)?;
                transaction
                    .query_one(
                        "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
                        &[&hash],
                    )
                    .await
                    .map_err(db_error)?;
                ensure_auth_active(&database_cancellation)?;
                let row = transaction
                    .query_opt(
                        "SELECT mailbox_address, expires_at FROM user_session WHERE token_hash=$1",
                        &[&hash],
                    )
                    .await
                    .map_err(db_error)?;
                let Some(row) = row else {
                    transaction.rollback().await.map_err(db_error)?;
                    return Ok(None);
                };
                let address: String = row.get(0);
                let expires: DateTime<Utc> = row.get(1);
                if expires <= Utc::now() {
                    transaction
                        .execute("DELETE FROM user_session WHERE token_hash=$1", &[&hash])
                        .await
                        .map_err(db_error)?;
                    pending_reconciliation = Some(TokenValidationCommit::Expired {
                        address,
                        expires_at: expires,
                    });
                    start_auth_commit(deadline, &database_cancellation, &commit_started)?;
                    transaction.commit().await.map_err(auth_commit_error)?;
                    return Ok(None);
                }
                if self.track_last_used {
                    ensure_auth_active(&database_cancellation)?;
                    let used_at = postgres_timestamp(Utc::now());
                    transaction
                        .execute(
                            "UPDATE user_session SET last_used_at=$1 WHERE token_hash=$2",
                            &[&used_at, &hash],
                        )
                        .await
                        .map_err(db_error)?;
                    pending_reconciliation = Some(TokenValidationCommit::LastUsed {
                        address: address.clone(),
                        expires_at: expires,
                        used_at,
                    });
                    start_auth_commit(deadline, &database_cancellation, &commit_started)?;
                    transaction.commit().await.map_err(auth_commit_error)?;
                } else {
                    transaction.rollback().await.map_err(db_error)?;
                }
                Ok(Some(address))
            },
        )
        .await;
        match connection.finish(outcome) {
            Ok(result) => Ok(result),
            Err(AuthError::OutcomeUnknown) => {
                let Some(pending) = pending_reconciliation else {
                    return Err(AuthError::OutcomeUnknown);
                };
                match pending {
                    TokenValidationCommit::Expired {
                        address,
                        expires_at,
                    } => match self
                        .reconcile_expired_session(&hash, &address, expires_at)
                        .await
                    {
                        AuthCommitReconciliation::Committed(()) => Ok(None),
                        AuthCommitReconciliation::NotCommitted => Err(AuthError::Unavailable),
                        AuthCommitReconciliation::OutcomeUnknown => Err(AuthError::OutcomeUnknown),
                    },
                    TokenValidationCommit::LastUsed {
                        address,
                        expires_at,
                        used_at,
                    } => match self
                        .reconcile_last_used(&hash, &address, expires_at, used_at)
                        .await
                    {
                        AuthCommitReconciliation::Committed(()) => Ok(Some(address)),
                        AuthCommitReconciliation::NotCommitted => Err(AuthError::Unavailable),
                        AuthCommitReconciliation::OutcomeUnknown => Err(AuthError::OutcomeUnknown),
                    },
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn reconcile_expired_session(
        &self,
        token_hash: &str,
        address: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthCommitReconciliation<()> {
        let row = match auth_reconciliation_query(
            &self.pool,
            token_hash,
            "expired session deletion",
            "/* lmyzmail_auth_expired_session_commit_reconciliation */
             SELECT mailbox_address,expires_at FROM user_session WHERE token_hash=$1",
            &[&token_hash],
        )
        .await
        {
            Ok(row) => row,
            Err(_) => return AuthCommitReconciliation::OutcomeUnknown,
        };
        match row {
            None => AuthCommitReconciliation::Committed(()),
            Some(row)
                if row.get::<_, &str>(0) == address
                    && row.get::<_, DateTime<Utc>>(1) == expires_at =>
            {
                AuthCommitReconciliation::NotCommitted
            }
            Some(_) => AuthCommitReconciliation::OutcomeUnknown,
        }
    }

    async fn reconcile_last_used(
        &self,
        token_hash: &str,
        address: &str,
        expires_at: DateTime<Utc>,
        used_at: DateTime<Utc>,
    ) -> AuthCommitReconciliation<()> {
        let row = match auth_reconciliation_query(
            &self.pool,
            token_hash,
            "session last-used update",
            "/* lmyzmail_auth_last_used_commit_reconciliation */
             SELECT mailbox_address,expires_at,last_used_at
             FROM user_session WHERE token_hash=$1",
            &[&token_hash],
        )
        .await
        {
            Ok(row) => row,
            Err(_) => return AuthCommitReconciliation::OutcomeUnknown,
        };
        match row {
            Some(row)
                if row.get::<_, &str>(0) == address
                    && row.get::<_, DateTime<Utc>>(1) == expires_at
                    && row.get::<_, Option<DateTime<Utc>>>(2) == Some(used_at) =>
            {
                AuthCommitReconciliation::Committed(())
            }
            Some(row)
                if row.get::<_, &str>(0) == address
                    && row.get::<_, DateTime<Utc>>(1) == expires_at =>
            {
                AuthCommitReconciliation::NotCommitted
            }
            Some(_) | None => AuthCommitReconciliation::OutcomeUnknown,
        }
    }

    async fn db(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Object, AuthError> {
        bounded_auth_future(
            deadline,
            cancellation,
            "authentication pool",
            self.pool.get(),
        )
        .await
    }

    async fn db_query_mailbox(
        &self,
        address: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Option<(i64, String)>, AuthError> {
        let mut connection = AuthDatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = auth_database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            async {
                connection
                    .client_mut()
                    .query_opt(
                        "SELECT id, password_hash FROM mailbox WHERE address=$1",
                        &[&address],
                    )
                    .await
                    .map_err(db_error)
            },
        )
        .await;
        let row = connection.finish(outcome)?;
        Ok(row.map(|row| (row.get(0), row.get(1))))
    }

    async fn db_mailbox_exists(
        &self,
        address: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<bool, AuthError> {
        let mut connection = AuthDatabaseConnection::new(self.db(deadline, cancellation).await?);
        let cancel_token = connection.cancel_token();
        let commit_started = AtomicBool::new(false);
        let database_cancellation = cancellation.child_token();
        let outcome = auth_database_operation(
            deadline,
            &database_cancellation,
            &cancel_token,
            &commit_started,
            async {
                connection
                    .client_mut()
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM mailbox WHERE address=$1)",
                        &[&address],
                    )
                    .await
                    .map_err(db_error)
            },
        )
        .await;
        connection.finish(outcome).map(|row| row.get(0))
    }

    async fn hash_password(
        &self,
        password: String,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<String, AuthError> {
        let permit = bounded_auth_future(
            deadline,
            cancellation,
            "password hash permit",
            self.password_permits.clone().acquire_owned(),
        )
        .await?;
        run_bounded_password_task(
            &self.password_pool,
            deadline,
            cancellation,
            "password hash",
            move || {
                let _permit = permit;
                hash(password, PASSWORD_COST)
                    .map_err(|error| AuthError::Database(error.to_string()))
            },
        )
        .await
    }

    async fn verify_password(
        &self,
        password: String,
        password_hash: String,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<bool, AuthError> {
        let permit = bounded_auth_future(
            deadline,
            cancellation,
            "password verify permit",
            self.password_permits.clone().acquire_owned(),
        )
        .await?;
        run_bounded_password_task(
            &self.password_pool,
            deadline,
            cancellation,
            "password verify",
            move || {
                let _permit = permit;
                Ok::<bool, AuthError>(verify(password, &password_hash).unwrap_or(false))
            },
        )
        .await
    }

    pub async fn ban_expiry(&self, ip: &str) -> Option<DateTime<Utc>> {
        if !self.rate_enabled || ip.is_empty() {
            return None;
        }
        let now = std::time::Instant::now();
        let mut state = self.rate_limits.lock().await;
        if state.banned_ips.get(ip).is_some_and(|ban| ban.until <= now) {
            state.banned_ips.remove(ip);
        }
        if let Some(ban) = state.banned_ips.get(ip) {
            return Some(ban.expires_at);
        }
        if state
            .overflow_ban
            .as_ref()
            .is_some_and(|ban| ban.until <= now)
        {
            state.overflow_ban = None;
        }
        state.overflow_ban.as_ref().map(|ban| ban.expires_at)
    }

    async fn record_failure(&self, ip: &str, address: &str) -> bool {
        if !self.rate_enabled || ip.is_empty() {
            return false;
        }
        let now = std::time::Instant::now();
        let principal = format!("{ip}\0{address}");
        let mut state = self.rate_limits.lock().await;
        let ip_allowed = consume_bounded(
            &mut state.ip_login,
            ip,
            now,
            self.failed_login_limit,
            self.failed_login_window,
        );
        let principal_allowed = consume_bounded(
            &mut state.principal_login,
            &principal,
            now,
            self.failed_login_limit,
            self.failed_login_window,
        );
        if ip_allowed && principal_allowed {
            return false;
        }
        let ban = IpBan {
            until: now + self.ban_duration,
            expires_at: Utc::now()
                + ChronoDuration::from_std(self.ban_duration).unwrap_or(ChronoDuration::MAX),
        };
        insert_ban_bounded(&mut state, ip, ban, now, MAX_RATE_LIMIT_ENTRIES);
        state.ip_login.remove(ip);
        state.principal_login.remove(&principal);
        true
    }

    async fn clear_principal_failure(&self, ip: &str, address: &str) {
        self.rate_limits
            .lock()
            .await
            .principal_login
            .remove(&format!("{ip}\0{address}"));
    }

    async fn can_register(&self, ip: &str) -> bool {
        if !self.rate_enabled || ip.is_empty() {
            return true;
        }
        let now = std::time::Instant::now();
        let mut state = self.rate_limits.lock().await;
        if !state.registration.contains_key(ip)
            && state.registration.len() >= MAX_RATE_LIMIT_ENTRIES
        {
            state
                .registration
                .retain(|_, bucket| bucket.refill_at > now);
            if state.registration.len() >= MAX_RATE_LIMIT_ENTRIES {
                return false;
            }
        }
        state
            .registration
            .get(ip)
            .is_none_or(|bucket| bucket.remaining > 0 || now >= bucket.refill_at)
    }

    async fn record_registration(&self, ip: &str) {
        if !self.rate_enabled || ip.is_empty() {
            return;
        }
        let now = std::time::Instant::now();
        let mut state = self.rate_limits.lock().await;
        let _ = consume_bounded(
            &mut state.registration,
            ip,
            now,
            self.registration_limit,
            self.registration_window,
        );
    }
}

fn auth_deadline() -> Instant {
    Instant::now() + DB_TIMEOUT
}

fn postgres_timestamp(value: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(value.timestamp_micros())
        .expect("an existing UTC timestamp remains valid at microsecond precision")
}

fn classify_mailbox_creation(
    row: Option<(i64, String, DateTime<Utc>)>,
    password_hash: &str,
    created_at: DateTime<Utc>,
) -> AuthCommitReconciliation<i64> {
    match row {
        Some((id, stored_hash, stored_at))
            if stored_hash == password_hash && stored_at == created_at =>
        {
            AuthCommitReconciliation::Committed(id)
        }
        Some(_) => AuthCommitReconciliation::OutcomeUnknown,
        None => AuthCommitReconciliation::NotCommitted,
    }
}

async fn bounded_auth_future<T, E, F>(
    deadline: Instant,
    cancellation: &CancellationToken,
    label: &'static str,
    future: F,
) -> Result<T, AuthError>
where
    E: fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(AuthError::Cancelled),
        result = timeout_at(deadline, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(AuthError::Database(format!("{label}: {error}"))),
            Err(_) => Err(AuthError::Unavailable),
        },
    }
}

async fn run_bounded_password_task<T, F>(
    pool: &BoundedBlockingPool,
    deadline: Instant,
    cancellation: &CancellationToken,
    label: &'static str,
    work: F,
) -> Result<T, AuthError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, AuthError> + Send + 'static,
{
    let mut task = pool
        .submit(work)
        .map_err(|error| AuthError::Database(format!("{label}: {error}")))?;
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            if task.await.is_err() {
                eprintln!("lmyzmail {label} task panicked after cancellation");
            }
            Err(AuthError::Cancelled)
        }
        result = timeout_at(deadline, &mut task) => match result {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(AuthError::Database(format!("{label}: {error}"))),
            Err(_) => {
                eprintln!("lmyzmail {label} exceeded its soft deadline; waiting for completion");
                if task.await.is_err() {
                    eprintln!("lmyzmail {label} task panicked after its soft deadline");
                }
                Err(AuthError::Unavailable)
            }
        },
    }
}

struct AuthDatabaseOutcome<T> {
    result: Result<T, AuthError>,
    discard_connection: bool,
}

struct AuthDatabaseConnection {
    client: Option<Object>,
}

impl AuthDatabaseConnection {
    fn new(client: Object) -> Self {
        Self {
            client: Some(client),
        }
    }

    fn client_mut(&mut self) -> &mut Object {
        self.client
            .as_mut()
            .expect("authentication database connection is present")
    }

    fn cancel_token(&self) -> CancelToken {
        self.client
            .as_ref()
            .expect("authentication database connection is present")
            .cancel_token()
    }

    fn finish<T>(mut self, outcome: AuthDatabaseOutcome<T>) -> Result<T, AuthError> {
        let client = self
            .client
            .take()
            .expect("authentication database connection is present");
        if outcome.discard_connection {
            drop(Object::take(client));
        } else {
            drop(client);
        }
        outcome.result
    }
}

impl Drop for AuthDatabaseConnection {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            drop(Object::take(client));
        }
    }
}

async fn auth_reconciliation_query(
    pool: &Pool,
    lock_key: &str,
    operation: &str,
    query: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Option<Row>, AuthError> {
    let deadline = auth_deadline();
    let client = match timeout_at(deadline, pool.get()).await {
        Ok(Ok(client)) => client,
        _ => {
            eprintln!(
                "lmyzmail auth {operation} commit reconciliation could not acquire a database connection"
            );
            return Err(AuthError::OutcomeUnknown);
        }
    };
    let mut connection = AuthDatabaseConnection::new(client);
    let transaction = match timeout_at(deadline, connection.client_mut().transaction()).await {
        Ok(Ok(transaction)) => transaction,
        _ => {
            eprintln!(
                "lmyzmail auth {operation} commit reconciliation could not start a database transaction"
            );
            return Err(AuthError::OutcomeUnknown);
        }
    };
    if !matches!(
        timeout_at(
            deadline,
            configure_auth_transaction_deadline(&transaction, deadline)
        )
        .await,
        Ok(Ok(()))
    ) {
        eprintln!(
            "lmyzmail auth {operation} commit reconciliation could not configure its deadline"
        );
        return Err(AuthError::OutcomeUnknown);
    }
    if !matches!(
        timeout_at(
            deadline,
            transaction.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
                &[&lock_key],
            ),
        )
        .await,
        Ok(Ok(_))
    ) {
        eprintln!(
            "lmyzmail auth {operation} commit reconciliation could not order behind the mutation"
        );
        return Err(AuthError::OutcomeUnknown);
    }
    let row = match timeout_at(deadline, transaction.query_opt(query, params)).await {
        Ok(Ok(row)) => row,
        _ => {
            eprintln!("lmyzmail auth {operation} commit reconciliation query failed");
            return Err(AuthError::OutcomeUnknown);
        }
    };
    let discard_connection =
        !matches!(timeout_at(deadline, transaction.commit()).await, Ok(Ok(())));
    connection.finish(AuthDatabaseOutcome {
        result: Ok(row),
        discard_connection,
    })
}

async fn auth_database_operation<T, F>(
    deadline: Instant,
    cancellation: &CancellationToken,
    cancel_token: &CancelToken,
    commit_started: &AtomicBool,
    future: F,
) -> AuthDatabaseOutcome<T>
where
    F: Future<Output = Result<T, AuthError>>,
{
    tokio::pin!(future);
    let interruption = tokio::select! {
        biased;
        _ = cancellation.cancelled() => AuthError::Cancelled,
        result = timeout_at(deadline, future.as_mut()) => match result {
            Ok(result) => return completed_auth_database_outcome(result),
            Err(_) => AuthError::Unavailable,
        },
    };

    let recovery_deadline = Instant::now() + DB_CANCEL_DRAIN_TIMEOUT;
    if commit_started.load(Ordering::Acquire) {
        return match timeout_at(recovery_deadline, future.as_mut()).await {
            Ok(result) => completed_auth_database_outcome(result),
            Err(_) => AuthDatabaseOutcome {
                result: Err(AuthError::OutcomeUnknown),
                discard_connection: true,
            },
        };
    }

    cancellation.cancel();
    let recovery = timeout_at(recovery_deadline, async {
        tokio::join!(cancel_token.cancel_query(NoTls), future.as_mut())
    })
    .await;
    let discard_connection = match recovery {
        Ok((Ok(()), _)) => false,
        Ok((Err(_), _)) | Err(_) => true,
    };

    AuthDatabaseOutcome {
        result: Err(interruption),
        discard_connection,
    }
}

fn completed_auth_database_outcome<T>(result: Result<T, AuthError>) -> AuthDatabaseOutcome<T> {
    let discard_connection = matches!(result, Err(AuthError::OutcomeUnknown));
    AuthDatabaseOutcome {
        result,
        discard_connection,
    }
}

fn start_auth_commit(
    deadline: Instant,
    cancellation: &CancellationToken,
    commit_started: &AtomicBool,
) -> Result<(), AuthError> {
    ensure_auth_active(cancellation)?;
    if Instant::now() >= deadline {
        return Err(AuthError::Unavailable);
    }
    commit_started.store(true, Ordering::Release);
    Ok(())
}

async fn configure_auth_transaction_deadline(
    transaction: &deadpool_postgres::Transaction<'_>,
    deadline: Instant,
) -> Result<(), AuthError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let server_millis = (remaining.as_millis() / 2).clamp(1, i32::MAX as u128);
    let value = format!("{server_millis}ms");
    transaction
        .query_one("SELECT set_config('statement_timeout',$1,true)", &[&value])
        .await
        .map_err(db_error)?;
    Ok(())
}

fn ensure_auth_active(cancellation: &CancellationToken) -> Result<(), AuthError> {
    if cancellation.is_cancelled() {
        Err(AuthError::Cancelled)
    } else {
        Ok(())
    }
}

fn consume_bounded(
    buckets: &mut HashMap<String, TokenBucket>,
    key: &str,
    now: std::time::Instant,
    capacity: u32,
    window: Duration,
) -> bool {
    if !buckets.contains_key(key) && buckets.len() >= MAX_RATE_LIMIT_ENTRIES {
        buckets.retain(|_, bucket| bucket.refill_at > now);
        if buckets.len() >= MAX_RATE_LIMIT_ENTRIES {
            return false;
        }
    }
    buckets
        .entry(key.to_owned())
        .or_insert(TokenBucket {
            remaining: capacity,
            refill_at: now + window,
        })
        .consume(now, capacity, window)
}

fn insert_ban_bounded(
    state: &mut RateLimitState,
    ip: &str,
    ban: IpBan,
    now: std::time::Instant,
    limit: usize,
) {
    if !state.banned_ips.contains_key(ip) && state.banned_ips.len() >= limit {
        state.banned_ips.retain(|_, existing| existing.until > now);
    }
    if state.banned_ips.contains_key(ip) || state.banned_ips.len() < limit {
        state.banned_ips.insert(ip.to_owned(), ban);
    } else {
        state.overflow_ban = Some(ban);
    }
}

fn parse_u32(
    config: &RuntimeConfig,
    new: &str,
    legacy: &str,
    default: u32,
) -> Result<u32, AuthError> {
    config
        .preferred_value(new, legacy)
        .map_or(Ok(default), |value| {
            value
                .parse()
                .map_err(|_| AuthError::InvalidInput(format!("{new} is invalid")))
        })
}

fn parse_u64(
    config: &RuntimeConfig,
    new: &str,
    legacy: &str,
    default: u64,
) -> Result<u64, AuthError> {
    config
        .preferred_value(new, legacy)
        .map_or(Ok(default), |value| {
            value
                .parse()
                .map_err(|_| AuthError::InvalidInput(format!("{new} is invalid")))
        })
}

fn parse_bool(
    config: &RuntimeConfig,
    new: &str,
    legacy: &str,
    default: bool,
) -> Result<bool, AuthError> {
    config
        .preferred_value(new, legacy)
        .map_or(Ok(default), |value| {
            value
                .parse()
                .map_err(|_| AuthError::InvalidInput(format!("{new} is invalid")))
        })
}

fn bounded_minutes(value: u64) -> Result<Duration, AuthError> {
    value
        .checked_mul(60)
        .filter(|seconds| *seconds > 0 && *seconds <= 365 * 24 * 3600)
        .map(Duration::from_secs)
        .ok_or_else(|| AuthError::InvalidInput("rate limit window is outside safe bounds".into()))
}

fn bounded_hours(value: u64) -> Result<Duration, AuthError> {
    value
        .checked_mul(3600)
        .filter(|seconds| *seconds > 0 && *seconds <= 365 * 24 * 3600)
        .map(Duration::from_secs)
        .ok_or_else(|| AuthError::InvalidInput("rate limit duration is outside safe bounds".into()))
}

fn db_error(error: tokio_postgres::Error) -> AuthError {
    AuthError::Database(error.to_string())
}

fn auth_commit_error(error: tokio_postgres::Error) -> AuthError {
    if error.as_db_error().is_some() {
        db_error(error)
    } else {
        AuthError::OutcomeUnknown
    }
}

fn normalize_login_address(value: &str) -> Option<String> {
    let address = value.trim().to_lowercase();
    (!address.is_empty()
        && address.len() <= 4096
        && !address.bytes().any(|byte| byte < 0x20 || byte == 0x7f))
    .then_some(address)
}

fn normalize_address(value: &str) -> Result<String, AuthError> {
    let address = value.trim().to_lowercase();
    if address.is_empty()
        || address.len() > 255
        || address.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(AuthError::InvalidInput(
            "Invalid email address format".into(),
        ));
    }
    let Some((local, domain)) = address.split_once('@') else {
        return Err(AuthError::InvalidInput(
            "Invalid email address format".into(),
        ));
    };
    if domain.is_empty()
        || domain.contains('@')
        || local.is_empty()
        || local.encode_utf16().count() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
    {
        return Err(AuthError::InvalidInput(
            "Invalid email address format".into(),
        ));
    }
    if local.is_ascii()
        && !local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&byte))
    {
        return Err(AuthError::InvalidInput("Invalid mailbox name. Allowed: letters, numbers, dots, hyphens, underscores, and UTF-8 characters.".into()));
    }
    Ok(address)
}

fn generate_token() -> Result<String, AuthError> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    fill_random(&mut bytes).map_err(|error| AuthError::Database(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Properties;

    #[tokio::test]
    async fn bounded_future_prioritizes_ready_cancellation() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = bounded_auth_future(
            Instant::now() + Duration::from_secs(1),
            &cancellation,
            "ready test",
            async { Ok::<_, std::io::Error>(()) },
        )
        .await;
        assert!(matches!(result, Err(AuthError::Cancelled)));
    }

    #[tokio::test]
    async fn timed_out_password_task_is_joined_before_returning() {
        let pool = BoundedBlockingPool::new("lmyzmail-auth-test", 1, 1).unwrap();
        let finished = Arc::new(AtomicBool::new(false));
        let task_finished = Arc::clone(&finished);
        let result = run_bounded_password_task(
            &pool,
            Instant::now() + Duration::from_millis(1),
            &CancellationToken::new(),
            "join test",
            move || {
                std::thread::sleep(Duration::from_millis(20));
                task_finished.store(true, Ordering::Release);
                Ok(())
            },
        )
        .await;
        assert!(matches!(result, Err(AuthError::Unavailable)));
        assert!(finished.load(Ordering::Acquire));
    }

    #[test]
    fn normalizes_and_validates_mailbox_addresses() {
        assert_eq!(
            normalize_address(" QA@Example.Test ").unwrap(),
            "qa@example.test"
        );
        assert!(normalize_address("a..b@example.test").is_err());
        assert!(normalize_address("a@example.test\r\nX: y").is_err());
        assert!(normalize_address("a@other.test").is_ok());
        assert!(normalize_address(&format!("{}@example.test", "😀".repeat(32))).is_ok());
        assert!(normalize_address(&format!("{}@example.test", "😀".repeat(33))).is_err());
    }

    #[test]
    fn mailbox_receive_flag_accepts_legacy_alias_with_new_precedence() {
        let config = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.domains.main.receiveEnabled=false\n\
lmyzmail.domains.main.receive-enabled=true\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            parse_bool(
                &config,
                "lmyzmail.domains.main.receive-enabled",
                "botmail.domains.main.receiveEnabled",
                false,
            )
            .unwrap()
        );
    }

    #[test]
    fn token_hash_is_lower_hex_and_bcrypt_fixture_verifies() {
        assert_eq!(hash_token("abc").len(), 64);
        assert!(verify("BlackboxPass123!", DUMMY_BCRYPT).unwrap());
    }

    #[test]
    fn mailbox_creation_reconciliation_requires_an_exact_durable_identity() {
        let created_at = postgres_timestamp(Utc::now());
        assert_eq!(
            classify_mailbox_creation(Some((17, "hash".into(), created_at)), "hash", created_at,),
            AuthCommitReconciliation::Committed(17)
        );
        assert_eq!(
            classify_mailbox_creation(None, "hash", created_at),
            AuthCommitReconciliation::NotCommitted
        );
        assert_eq!(
            classify_mailbox_creation(
                Some((17, "other-hash".into(), created_at)),
                "hash",
                created_at,
            ),
            AuthCommitReconciliation::OutcomeUnknown
        );
        assert_eq!(
            classify_mailbox_creation(
                Some((
                    17,
                    "hash".into(),
                    created_at + ChronoDuration::microseconds(1)
                )),
                "hash",
                created_at,
            ),
            AuthCommitReconciliation::OutcomeUnknown
        );
    }

    #[test]
    fn interval_bucket_allows_capacity_then_refills_as_one_interval() {
        let now = std::time::Instant::now();
        let window = Duration::from_secs(300);
        let mut bucket = TokenBucket {
            remaining: 3,
            refill_at: now + window,
        };
        assert!(bucket.consume(now, 3, window));
        assert!(bucket.consume(now, 3, window));
        assert!(bucket.consume(now, 3, window));
        assert!(!bucket.consume(now, 3, window));
        assert!(bucket.consume(now + window, 3, window));
        assert_eq!(bucket.remaining, 2);
    }

    #[test]
    fn login_normalization_is_bounded_but_does_not_apply_registration_rules() {
        assert_eq!(
            normalize_login_address(" NOT-AN-EMAIL ").as_deref(),
            Some("not-an-email")
        );
        assert_eq!(normalize_login_address("\r\n"), None);
        assert_eq!(normalize_login_address(&"x".repeat(4097)), None);
    }

    #[test]
    fn saturated_ban_table_uses_fail_closed_overflow_without_growing() {
        let now = std::time::Instant::now();
        let make_ban = || IpBan {
            until: now + Duration::from_secs(60),
            expires_at: Utc::now() + ChronoDuration::seconds(60),
        };
        let mut state = RateLimitState::default();
        insert_ban_bounded(&mut state, "192.0.2.1", make_ban(), now, 2);
        insert_ban_bounded(&mut state, "192.0.2.2", make_ban(), now, 2);
        insert_ban_bounded(&mut state, "192.0.2.3", make_ban(), now, 2);
        assert_eq!(state.banned_ips.len(), 2);
        assert!(state.overflow_ban.is_some());
    }
}
