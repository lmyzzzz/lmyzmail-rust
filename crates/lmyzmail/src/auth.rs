use std::{collections::HashMap, fmt, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bcrypt::{hash, verify};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use deadpool_postgres::{
    Config as DatabasePoolConfig, ManagerConfig, Pool, PoolConfig, RecyclingMethod, Runtime,
};
use getrandom::fill as fill_random;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::{
    sync::{Mutex, Semaphore},
    task::spawn_blocking,
    time::timeout,
};
use tokio_postgres::NoTls;

use crate::config::RuntimeConfig;

const TOKEN_BYTES: usize = 32;
const TOKEN_PREFIX_BYTES: usize = 8;
const PASSWORD_COST: u32 = 10;
const DB_TIMEOUT: Duration = Duration::from_secs(8);
const DEFAULT_FAILURE_LIMIT: u32 = 10;
const DEFAULT_REGISTRATION_LIMIT: u32 = 5;
const MAX_RATE_LIMIT_ENTRIES: usize = 16_384;
const DUMMY_BCRYPT: &str = "$2a$10$KMejGNeOXWSJBM831XMwmeVrw.16AhD65yYCs7vxZIM0osXpoyPsm";

#[derive(Debug)]
pub enum AuthError {
    Database(String),
    InvalidInput(String),
    Unavailable,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(_) | Self::Unavailable => {
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LoginOutcome {
    Invalid { ip_banned: bool },
    Success,
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

#[derive(Clone)]
pub struct AuthService {
    pool: Pool,
    domain: Arc<str>,
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
    password_permits: Arc<Semaphore>,
    registration_permit: Arc<Semaphore>,
}

impl AuthService {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, AuthError> {
        let mut pool_config = DatabasePoolConfig::new();
        pool_config.host = Some(config.postgres.host.clone());
        pool_config.port = Some(config.postgres.port);
        pool_config.dbname = Some(config.postgres.database.clone());
        pool_config.user = Some(config.postgres.username.clone());
        pool_config.password = Some(config.postgres.password.clone());
        pool_config.connect_timeout = Some(DB_TIMEOUT);
        pool_config.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        pool_config.pool = Some(PoolConfig::new(config.limits.postgres_pool as usize));
        let pool = pool_config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|error| AuthError::Database(error.to_string()))?;

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
        Ok(Self {
            pool,
            domain: Arc::from(config.domain.to_ascii_lowercase()),
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
            password_permits: Arc::new(Semaphore::new(4)),
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
        let address = normalize_login_address(address).unwrap_or_default();
        let ip_banned = self.ban_expiry(client_ip).await.is_some();
        if ip_banned {
            return Ok((LoginOutcome::Invalid { ip_banned }, None));
        }
        let row = self.db_query_mailbox(&address).await?;
        let (mailbox_id, password_hash) = match row {
            Some(value) => (Some(value.0), value.1),
            None => (None, DUMMY_BCRYPT.to_owned()),
        };
        let valid = self
            .verify_password(password.to_owned(), password_hash)
            .await?;
        if !valid || mailbox_id.is_none() {
            let banned = self.record_failure(client_ip, &address).await;
            return Ok((LoginOutcome::Invalid { ip_banned: banned }, None));
        }
        self.clear_principal_failure(client_ip, &address).await;
        let token = generate_token()?;
        let token_hash = hash_token(&token);
        let now = Utc::now();
        let expires = now + ChronoDuration::days(self.session_expiry_days);
        let token_prefix = token[..TOKEN_PREFIX_BYTES.min(token.len())].to_owned();
        let user_agent = user_agent.map(|value| value.chars().take(500).collect::<String>());
        let mut client = self.db().await?;
        timeout(DB_TIMEOUT, async {
            let transaction = client.transaction().await?;
            transaction
                .query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))",
                    &[&address],
                )
                .await?;
            let rows = transaction
                .query(
                    "SELECT id FROM user_session WHERE mailbox_address=$1 AND expires_at>$2 ORDER BY created_at DESC",
                    &[&address, &now],
                )
                .await?;
            if rows.len() as i64 >= self.max_sessions_per_user {
                let remove = rows.len() as i64 - self.max_sessions_per_user + 1;
                for row in rows.into_iter().rev().take(remove as usize) {
                    let id: i64 = row.get(0);
                    transaction
                        .execute("DELETE FROM user_session WHERE id=$1", &[&id])
                        .await?;
                }
            }
            transaction.execute(
                "INSERT INTO user_session (mailbox_address, token_hash, token_prefix, created_at, expires_at, last_used_at, created_ip, user_agent) VALUES ($1,$2,$3,$4,$5,$4,$6,$7)",
                &[&address, &token_hash, &token_prefix, &now, &expires, &client_ip, &user_agent],
            ).await?;
            transaction.commit().await
        })
        .await
        .map_err(|_| AuthError::Unavailable)?
        .map_err(db_error)?;
        Ok((
            LoginOutcome::Success,
            Some(LoginResponse { token, address }),
        ))
    }

    pub async fn register(
        &self,
        address: &str,
        password: &str,
        client_ip: &str,
    ) -> Result<RegisterResponse, AuthError> {
        if !self.public_registration {
            return Err(AuthError::InvalidInput("registration_disabled".into()));
        }
        if address.trim().is_empty() {
            return Err(AuthError::InvalidInput("address_required".into()));
        }
        if password.chars().count() < 8 {
            return Err(AuthError::InvalidInput("password_too_short".into()));
        }
        let address = normalize_address(address)?;
        let domain = address
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or_default();
        if domain != self.domain.as_ref() {
            return Err(AuthError::InvalidInput(format!(
                "Domain not configured: {domain}"
            )));
        }
        let _registration_permit =
            timeout(DB_TIMEOUT, self.registration_permit.clone().acquire_owned())
                .await
                .map_err(|_| AuthError::Unavailable)?
                .map_err(|_| AuthError::Unavailable)?;
        if !self.can_register(client_ip).await {
            return Err(AuthError::InvalidInput("rate_limit_exceeded".into()));
        }
        if self.db_mailbox_exists(&address).await? {
            return Err(AuthError::InvalidInput(format!(
                "Mailbox already exists: {address}"
            )));
        }
        let password_hash = self.hash_password(password.to_owned()).await?;
        let client = self.db().await?;
        let result = timeout(DB_TIMEOUT, client.query_one(
            "INSERT INTO mailbox (address, password_hash, created_at) VALUES ($1,$2,$3) RETURNING id",
            &[&address, &password_hash, &Utc::now()],
        )).await.map_err(|_| AuthError::Unavailable)?;
        match result {
            Ok(row) => {
                self.record_registration(client_ip).await;
                Ok(RegisterResponse {
                    id: row.get::<_, i64>(0),
                    address,
                    message: "Registration successful. You can now log in.",
                })
            }
            Err(error) if error.code().is_some_and(|code| code.code() == "23505") => Err(
                AuthError::InvalidInput(format!("Mailbox already exists: {address}")),
            ),
            Err(error) => Err(AuthError::Database(error.to_string())),
        }
    }

    pub async fn logout(&self, token: Option<&str>) -> Result<(), AuthError> {
        let Some(token) = token.filter(|value| !value.trim().is_empty()) else {
            return Ok(());
        };
        let client = self.db().await?;
        let hash = hash_token(token);
        timeout(
            DB_TIMEOUT,
            client.execute("DELETE FROM user_session WHERE token_hash=$1", &[&hash]),
        )
        .await
        .map_err(|_| AuthError::Unavailable)?
        .map_err(db_error)?;
        Ok(())
    }

    pub async fn validate_token(&self, token: &str) -> Result<Option<String>, AuthError> {
        if token.trim().is_empty() {
            return Ok(None);
        }
        let client = self.db().await?;
        let hash = hash_token(token);
        let row = timeout(
            DB_TIMEOUT,
            client.query_opt(
                "SELECT mailbox_address, expires_at FROM user_session WHERE token_hash=$1",
                &[&hash],
            ),
        )
        .await
        .map_err(|_| AuthError::Unavailable)?
        .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let address: String = row.get(0);
        let expires: DateTime<Utc> = row.get(1);
        if expires <= Utc::now() {
            let _ = client
                .execute("DELETE FROM user_session WHERE token_hash=$1", &[&hash])
                .await;
            return Ok(None);
        }
        if self.track_last_used {
            client
                .execute(
                    "UPDATE user_session SET last_used_at=$1 WHERE token_hash=$2",
                    &[&Utc::now(), &hash],
                )
                .await
                .map_err(db_error)?;
        }
        Ok(Some(address))
    }

    async fn db(&self) -> Result<deadpool_postgres::Object, AuthError> {
        timeout(DB_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| AuthError::Unavailable)?
            .map_err(|error| AuthError::Database(error.to_string()))
    }

    async fn db_query_mailbox(&self, address: &str) -> Result<Option<(i64, String)>, AuthError> {
        let client = self.db().await?;
        let row = timeout(
            DB_TIMEOUT,
            client.query_opt(
                "SELECT id, password_hash FROM mailbox WHERE address=$1",
                &[&address],
            ),
        )
        .await
        .map_err(|_| AuthError::Unavailable)?
        .map_err(db_error)?;
        Ok(row.map(|row| (row.get(0), row.get(1))))
    }

    async fn db_mailbox_exists(&self, address: &str) -> Result<bool, AuthError> {
        let client = self.db().await?;
        timeout(
            DB_TIMEOUT,
            client.query_one(
                "SELECT EXISTS(SELECT 1 FROM mailbox WHERE address=$1)",
                &[&address],
            ),
        )
        .await
        .map_err(|_| AuthError::Unavailable)?
        .map(|row| row.get(0))
        .map_err(db_error)
    }

    async fn hash_password(&self, password: String) -> Result<String, AuthError> {
        let permit = timeout(DB_TIMEOUT, self.password_permits.clone().acquire_owned())
            .await
            .map_err(|_| AuthError::Unavailable)?
            .map_err(|_| AuthError::Unavailable)?;
        spawn_blocking(move || {
            let _permit = permit;
            hash(password, PASSWORD_COST).map_err(|error| AuthError::Database(error.to_string()))
        })
        .await
        .map_err(|error| AuthError::Database(error.to_string()))?
    }

    async fn verify_password(
        &self,
        password: String,
        password_hash: String,
    ) -> Result<bool, AuthError> {
        let permit = timeout(DB_TIMEOUT, self.password_permits.clone().acquire_owned())
            .await
            .map_err(|_| AuthError::Unavailable)?
            .map_err(|_| AuthError::Unavailable)?;
        spawn_blocking(move || {
            let _permit = permit;
            Ok(verify(password, &password_hash).unwrap_or(false))
        })
        .await
        .map_err(|error| AuthError::Database(error.to_string()))?
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
        || local.len() > 64
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

    #[test]
    fn normalizes_and_validates_mailbox_addresses() {
        assert_eq!(
            normalize_address(" QA@Example.Test ").unwrap(),
            "qa@example.test"
        );
        assert!(normalize_address("a..b@example.test").is_err());
        assert!(normalize_address("a@example.test\r\nX: y").is_err());
        assert!(normalize_address("a@other.test").is_ok());
    }

    #[test]
    fn token_hash_is_lower_hex_and_bcrypt_fixture_verifies() {
        assert_eq!(hash_token("abc").len(), 64);
        assert!(verify("BlackboxPass123!", DUMMY_BCRYPT).unwrap());
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
