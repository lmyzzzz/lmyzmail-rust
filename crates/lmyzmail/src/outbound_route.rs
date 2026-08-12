use std::{
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use deadpool_redis::{Pool, redis};
use hickory_resolver::{TokioResolver, config::LookupIpStrategy, net::NetError, proto::rr::RData};
use idna::domain_to_ascii_strict;
use moka::future::Cache;
use reqwest::{Client, redirect::Policy};
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::{OutboundRouteConfig, RuntimeConfig},
    outbound_smtp::{SmtpEndpoint, TlsMode, is_public_smtp_ip},
};

const MX_CACHE_PREFIX: &str = "dns:mx:";
const MTA_STS_CACHE_PREFIX: &str = "mta-sts:";
const FALLBACK_MARKER: &str = "\0FALLBACK\0";
const MAX_MX_HOSTS: usize = 64;
const MAX_ADDRESSES_PER_HOST: usize = 16;
const MAX_TXT_RECORDS: usize = 16;
const MAX_TXT_BYTES: usize = 4 * 1024;
const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_POLICY_PATTERNS: usize = 64;
const MAX_CACHE_VALUE_BYTES: usize = 128 * 1024;
const MAX_MTA_STS_AGE_SECONDS: u64 = 31_557_600;
const MAX_MTA_STS_CACHE_SECONDS: u64 = 7 * 24 * 60 * 60;
const MTA_STS_NEGATIVE_CACHE_SECONDS: u64 = 5 * 60;
const CACHE_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_IN_FLIGHT_ROUTES: usize = 1_024;
const MAX_POLICY_FETCHES: usize = 32;
const DNS_RESPONSE_CACHE_ENTRIES: u64 = 8_192;
const DNS_MAX_ACTIVE_REQUESTS: usize = 32;

const READ_BOUNDED_CACHE_SCRIPT: &str = r#"
local kind = redis.call('TYPE', KEYS[1])['ok']
if kind == 'none' then return {'MISSING'} end
if kind ~= 'string' then return {'INVALID'} end
local length = redis.call('STRLEN', KEYS[1])
if length > tonumber(ARGV[1]) then return {'INVALID'} end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 then return {'INVALID'} end
return {'VALUE', tostring(ttl), redis.call('GET', KEYS[1])}
"#;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteErrorKind {
    Configuration,
    Temporary,
    Permanent,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteError {
    pub kind: RouteErrorKind,
    pub message: String,
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RouteError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtaStsMode {
    Enforce,
    Testing,
    None,
}

impl MtaStsMode {
    fn serialized(self) -> &'static str {
        match self {
            Self::Enforce => "ENFORCE",
            Self::Testing => "TESTING",
            Self::None => "NONE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MtaStsPolicy {
    pub version: Option<String>,
    pub mode: MtaStsMode,
    pub mx_patterns: Vec<String>,
    pub max_age_seconds: u64,
    pub policy_id: Option<String>,
    pub fetched_at_epoch_millis: i64,
}

impl MtaStsPolicy {
    fn none(now_epoch_millis: i64) -> Self {
        Self {
            version: None,
            mode: MtaStsMode::None,
            mx_patterns: Vec::new(),
            max_age_seconds: 0,
            policy_id: None,
            fetched_at_epoch_millis: now_epoch_millis,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.mode != MtaStsMode::None
            && self.version.as_deref() == Some("STSv1")
            && !self.mx_patterns.is_empty()
    }

    pub fn matches_mx(&self, host: &str) -> bool {
        let Ok(host) = normalize_host(host) else {
            return false;
        };
        self.mx_patterns.iter().any(|pattern| {
            let pattern = pattern.to_ascii_lowercase();
            if let Some(suffix) = pattern.strip_prefix("*.") {
                host.strip_suffix(suffix).is_some_and(|prefix| {
                    prefix.ends_with('.')
                        && prefix.len() > 1
                        && !prefix[..prefix.len() - 1].contains('.')
                })
            } else {
                host == pattern
            }
        })
    }

    fn serialize_legacy(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.version.as_deref().unwrap_or_default(),
            self.mode.serialized(),
            self.mx_patterns.join(","),
            self.max_age_seconds,
            self.policy_id.as_deref().unwrap_or_default(),
            self.fetched_at_epoch_millis
        )
    }

    fn deserialize_legacy(value: &str) -> Option<Self> {
        if value.len() > MAX_CACHE_VALUE_BYTES {
            return None;
        }
        let parts: Vec<&str> = value.split('|').collect();
        if parts.len() != 6 {
            return None;
        }
        let mode = match parts[1] {
            "ENFORCE" => MtaStsMode::Enforce,
            "TESTING" => MtaStsMode::Testing,
            "NONE" => MtaStsMode::None,
            _ => return None,
        };
        let mx_patterns = if parts[2].is_empty() {
            Vec::new()
        } else {
            let values: Vec<String> = parts[2]
                .split(',')
                .map(|value| {
                    validate_mx_pattern(value).unwrap_or_else(|_| value.trim().to_ascii_lowercase())
                })
                .collect();
            if values.len() > MAX_POLICY_PATTERNS {
                return None;
            }
            values
        };
        let max_age_seconds = parts[3].parse::<u64>().ok()?;
        if max_age_seconds > MAX_MTA_STS_AGE_SECONDS {
            return None;
        }
        let fetched_at_epoch_millis = parts[5].parse::<i64>().ok()?;
        if fetched_at_epoch_millis <= 0 {
            return None;
        }
        Some(Self {
            version: (!parts[0].is_empty()).then(|| parts[0].to_owned()),
            mode,
            mx_patterns,
            max_age_seconds,
            policy_id: (!parts[4].is_empty()).then(|| parts[4].to_owned()),
            fetched_at_epoch_millis,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RouteCandidate {
    pub mx_host: String,
    pub connect_addr: SocketAddr,
    pub endpoint: SmtpEndpoint,
}

#[derive(Clone, Debug)]
pub struct DeliveryRoute {
    pub recipient_domain: String,
    pub policy: MtaStsPolicy,
    pub tls_mode: TlsMode,
    pub candidates: Vec<RouteCandidate>,
}

#[derive(Clone, Debug)]
struct MxAnswer {
    preference: u16,
    host: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnsFailure {
    NoRecords,
    Temporary,
    Cancelled,
}

trait DnsBackend: Send + Sync {
    fn mx<'a>(
        &'a self,
        name: &'a str,
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<MxAnswer>, DnsFailure>>;

    fn txt<'a>(
        &'a self,
        name: &'a str,
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>, DnsFailure>>;

    fn addresses<'a>(
        &'a self,
        name: &'a str,
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<IpAddr>, DnsFailure>>;
}

#[derive(Clone)]
struct HickoryDnsBackend {
    resolver: TokioResolver,
    query_timeout: Duration,
}

impl HickoryDnsBackend {
    fn new(query_timeout: Duration) -> Result<Self, RouteError> {
        let mut builder = TokioResolver::builder_tokio().map_err(|_| {
            route_error(
                RouteErrorKind::Configuration,
                "system DNS configuration is unavailable",
            )
        })?;
        builder.options_mut().timeout = query_timeout;
        builder.options_mut().attempts = 2;
        builder.options_mut().cache_size = DNS_RESPONSE_CACHE_ENTRIES;
        builder.options_mut().max_active_requests = DNS_MAX_ACTIVE_REQUESTS;
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        Ok(Self {
            resolver: builder.build().map_err(|_| {
                route_error(
                    RouteErrorKind::Configuration,
                    "system DNS resolver initialization failed",
                )
            })?,
            query_timeout,
        })
    }
}

impl DnsBackend for HickoryDnsBackend {
    fn mx<'a>(
        &'a self,
        name: &'a str,
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<MxAnswer>, DnsFailure>> {
        Box::pin(async move {
            let lookup = dns_query(
                self.resolver.mx_lookup(name),
                self.query_timeout,
                deadline,
                cancellation,
            )
            .await?;
            let mut answers: Vec<MxAnswer> = lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::MX(record) => Some(MxAnswer {
                        preference: record.preference,
                        host: record.exchange.to_utf8(),
                    }),
                    _ => None,
                })
                .collect();
            answers.sort_by_key(|answer| answer.preference);
            Ok(answers)
        })
    }

    fn txt<'a>(
        &'a self,
        name: &'a str,
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>, DnsFailure>> {
        Box::pin(async move {
            let lookup = dns_query(
                self.resolver.txt_lookup(name),
                self.query_timeout,
                deadline,
                cancellation,
            )
            .await?;
            let mut values = Vec::new();
            for record in lookup.answers() {
                let RData::TXT(record) = &record.data else {
                    continue;
                };
                let length: usize = record.txt_data.iter().map(|part| part.len()).sum();
                if values.len() >= MAX_TXT_RECORDS || length > MAX_TXT_BYTES {
                    return Err(DnsFailure::Temporary);
                }
                let mut value = Vec::with_capacity(length);
                for part in &record.txt_data {
                    value.extend_from_slice(part);
                }
                values.push(value);
            }
            Ok(values)
        })
    }

    fn addresses<'a>(
        &'a self,
        name: &'a str,
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<IpAddr>, DnsFailure>> {
        Box::pin(async move {
            let lookup = dns_query(
                self.resolver.lookup_ip(name),
                self.query_timeout,
                deadline,
                cancellation,
            )
            .await?;
            let addresses: Vec<IpAddr> = lookup.iter().collect();
            if addresses.is_empty() {
                Err(DnsFailure::NoRecords)
            } else {
                Ok(addresses)
            }
        })
    }
}

async fn dns_query<T>(
    future: impl Future<Output = Result<T, NetError>>,
    query_timeout: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<T, DnsFailure> {
    let operation_deadline = deadline.min(Instant::now() + query_timeout);
    tokio::select! {
        _ = cancellation.cancelled() => Err(DnsFailure::Cancelled),
        result = timeout_at(operation_deadline, future) => match result {
            Err(_) => Err(DnsFailure::Temporary),
            Ok(Err(error)) if error.is_no_records_found() => Err(DnsFailure::NoRecords),
            Ok(Err(_)) => Err(DnsFailure::Temporary),
            Ok(Ok(value)) => Ok(value),
        }
    }
}

#[derive(Clone, Debug)]
struct PolicyHttpResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

trait PolicyHttpBackend: Send + Sync {
    fn fetch<'a>(
        &'a self,
        domain: &'a str,
        addresses: &'a [IpAddr],
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<PolicyHttpResponse, RouteError>>;
}

#[derive(Clone)]
struct PinnedPolicyHttpBackend {
    fetch_timeout: Duration,
    permits: Arc<Semaphore>,
}

impl PolicyHttpBackend for PinnedPolicyHttpBackend {
    fn fetch<'a>(
        &'a self,
        domain: &'a str,
        addresses: &'a [IpAddr],
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<PolicyHttpResponse, RouteError>> {
        Box::pin(async move {
            let operation_deadline = deadline.min(Instant::now() + self.fetch_timeout);
            let _permit = tokio::select! {
                _ = cancellation.cancelled() => return Err(cancelled()),
                result = timeout_at(operation_deadline, self.permits.clone().acquire_owned()) => result
                    .map_err(|_| route_error(RouteErrorKind::Temporary, "MTA-STS HTTPS admission timed out"))?
                    .map_err(|_| route_error(RouteErrorKind::Configuration, "MTA-STS HTTPS admission closed"))?,
            };
            let host = format!("mta-sts.{domain}");
            let socket_addresses: Vec<SocketAddr> = addresses
                .iter()
                .map(|address| SocketAddr::new(*address, 443))
                .collect();
            let client = Client::builder()
                .no_proxy()
                .redirect(Policy::none())
                .https_only(true)
                .connect_timeout(self.fetch_timeout)
                .timeout(self.fetch_timeout)
                .resolve_to_addrs(&host, &socket_addresses)
                .build()
                .map_err(|_| {
                    route_error(
                        RouteErrorKind::Configuration,
                        "MTA-STS HTTPS client initialization failed",
                    )
                })?;
            let url = format!("https://{host}/.well-known/mta-sts.txt");
            let response = tokio::select! {
                _ = cancellation.cancelled() => return Err(cancelled()),
                result = timeout_at(
                    operation_deadline,
                    client.get(url).header("User-Agent", "lmyzmail-MTA-STS/1.0").send(),
                ) => result
                    .map_err(|_| route_error(RouteErrorKind::Temporary, "MTA-STS HTTPS fetch timed out"))?
                    .map_err(|_| route_error(RouteErrorKind::Temporary, "MTA-STS HTTPS fetch failed"))?,
            };
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            if response
                .content_length()
                .is_some_and(|length| length > MAX_POLICY_BYTES as u64)
            {
                return Err(route_error(
                    RouteErrorKind::Permanent,
                    "MTA-STS policy exceeds its byte budget",
                ));
            }
            let mut response = response;
            let mut body = Vec::new();
            loop {
                let chunk = tokio::select! {
                    _ = cancellation.cancelled() => return Err(cancelled()),
                    result = timeout_at(operation_deadline, response.chunk()) => result
                        .map_err(|_| route_error(RouteErrorKind::Temporary, "MTA-STS body read timed out"))?
                        .map_err(|_| route_error(RouteErrorKind::Temporary, "MTA-STS body read failed"))?,
                };
                let Some(chunk) = chunk else {
                    break;
                };
                if body.len().saturating_add(chunk.len()) > MAX_POLICY_BYTES {
                    return Err(route_error(
                        RouteErrorKind::Permanent,
                        "MTA-STS policy exceeds its byte budget",
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(PolicyHttpResponse {
                status,
                content_type,
                body,
            })
        })
    }
}

#[derive(Clone, Debug)]
struct MxCacheEntry {
    hosts: Vec<String>,
}

#[derive(Clone, Debug)]
struct PolicyCacheEntry {
    policy: MtaStsPolicy,
    expires_at_epoch_millis: i64,
    cacheable: bool,
}

#[derive(Clone)]
pub struct OutboundRouteResolver {
    redis_pool: Pool,
    dns: Arc<dyn DnsBackend>,
    http: Arc<dyn PolicyHttpBackend>,
    mx_cache: Cache<String, Result<MxCacheEntry, RouteError>>,
    policy_cache: Cache<String, Result<PolicyCacheEntry, RouteError>>,
    route_permits: Arc<Semaphore>,
    config: OutboundRouteConfig,
    mta_sts_enabled: bool,
}

impl OutboundRouteResolver {
    pub fn from_config(config: &RuntimeConfig, redis_pool: Pool) -> Result<Self, RouteError> {
        let dns = HickoryDnsBackend::new(Duration::from_secs(
            config.outbound_route.dns_query_timeout_seconds,
        ))?;
        let http = PinnedPolicyHttpBackend {
            fetch_timeout: Duration::from_millis(config.outbound_route.mta_sts_fetch_timeout_ms),
            permits: Arc::new(Semaphore::new(MAX_POLICY_FETCHES)),
        };
        Ok(Self::new(
            config.outbound_route.clone(),
            config.features.mta_sts,
            redis_pool,
            Arc::new(dns),
            Arc::new(http),
        ))
    }

    fn new(
        config: OutboundRouteConfig,
        mta_sts_enabled: bool,
        redis_pool: Pool,
        dns: Arc<dyn DnsBackend>,
        http: Arc<dyn PolicyHttpBackend>,
    ) -> Self {
        Self::new_with_route_limit(
            config,
            mta_sts_enabled,
            redis_pool,
            dns,
            http,
            MAX_IN_FLIGHT_ROUTES,
        )
    }

    fn new_with_route_limit(
        config: OutboundRouteConfig,
        mta_sts_enabled: bool,
        redis_pool: Pool,
        dns: Arc<dyn DnsBackend>,
        http: Arc<dyn PolicyHttpBackend>,
        max_in_flight_routes: usize,
    ) -> Self {
        assert!(max_in_flight_routes > 0);
        let mx_cache = Cache::builder()
            .max_capacity(config.mx_l1_max_entries)
            .time_to_live(Duration::from_secs(config.mx_l1_ttl_minutes * 60))
            .build();
        let policy_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(24 * 60 * 60))
            .build();
        Self {
            redis_pool,
            dns,
            http,
            mx_cache,
            policy_cache,
            route_permits: Arc::new(Semaphore::new(max_in_flight_routes)),
            config,
            mta_sts_enabled,
        }
    }

    pub async fn resolve(
        &self,
        recipient_domain: &str,
        cancellation: &CancellationToken,
    ) -> Result<DeliveryRoute, RouteError> {
        let _route_permit = self
            .route_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                route_error(
                    RouteErrorKind::Temporary,
                    "outbound route concurrency limit reached",
                )
            })?;
        let recipient_domain = normalize_host(recipient_domain)?;
        let deadline =
            Instant::now() + Duration::from_secs(self.config.resolution_deadline_seconds);
        let mx = self
            .load_mx(&recipient_domain, deadline, cancellation)
            .await?;
        let policy = self
            .load_policy(&recipient_domain, deadline, cancellation)
            .await?;
        let hosts: Vec<String> = if policy.mode == MtaStsMode::Enforce && policy.is_valid() {
            let filtered: Vec<String> = mx
                .hosts
                .iter()
                .filter(|host| policy.matches_mx(host))
                .cloned()
                .collect();
            if filtered.is_empty() {
                return Err(route_error(
                    RouteErrorKind::Permanent,
                    "MTA-STS enforce policy rejected every MX host",
                ));
            }
            filtered
        } else {
            mx.hosts
        };
        if hosts.is_empty() {
            return Err(route_error(
                RouteErrorKind::Permanent,
                "recipient domain publishes a null MX",
            ));
        }
        let mut candidates = Vec::with_capacity(hosts.len());
        let mut last_error = None;
        for host in hosts {
            match self
                .resolve_public_addresses(&host, deadline, cancellation)
                .await
            {
                Ok(addresses) => {
                    let connect_addr = SocketAddr::new(addresses[0], 25);
                    let endpoint =
                        SmtpEndpoint::public_mx(connect_addr, host.clone()).map_err(|_| {
                            route_error(
                                RouteErrorKind::Configuration,
                                "validated MX endpoint was rejected",
                            )
                        })?;
                    candidates.push(RouteCandidate {
                        mx_host: host,
                        connect_addr,
                        endpoint,
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }
        if candidates.is_empty() {
            return Err(last_error.unwrap_or_else(|| {
                route_error(
                    RouteErrorKind::Temporary,
                    "no MX address is currently available",
                )
            }));
        }
        let tls_mode = if policy.mode == MtaStsMode::Enforce && policy.is_valid() {
            TlsMode::Required
        } else {
            TlsMode::Opportunistic
        };
        Ok(DeliveryRoute {
            recipient_domain,
            policy,
            tls_mode,
            candidates,
        })
    }

    async fn load_mx(
        &self,
        domain: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<MxCacheEntry, RouteError> {
        let owner = self.clone();
        let domain_owned = domain.to_owned();
        let shared_load_cancellation = CancellationToken::new();
        let load = self.mx_cache.get_with(domain_owned.clone(), async move {
            owner
                .load_mx_uncached(&domain_owned, deadline, &shared_load_cancellation)
                .await
        });
        let result = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = timeout_at(deadline, load) => result.map_err(|_| {
                route_error(RouteErrorKind::Temporary, "MX route resolution timed out")
            })?,
        };
        if result.is_err() {
            self.mx_cache.invalidate(domain).await;
        }
        result
    }

    async fn load_mx_uncached(
        &self,
        domain: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<MxCacheEntry, RouteError> {
        let key = format!("{MX_CACHE_PREFIX}{domain}");
        if let Some((value, _)) = self.read_cache(&key, deadline, cancellation).await {
            if value == FALLBACK_MARKER {
                return Ok(MxCacheEntry {
                    hosts: vec![domain.to_owned()],
                });
            }
            if let Some(hosts) = deserialize_mx_hosts(&value) {
                return Ok(MxCacheEntry { hosts });
            }
        }
        let mut answers = match self.dns.mx(domain, deadline, cancellation).await {
            Ok(answers) => answers,
            Err(DnsFailure::Cancelled) => return Err(cancelled()),
            Err(DnsFailure::NoRecords | DnsFailure::Temporary) => Vec::new(),
        };
        if answers.len() > MAX_MX_HOSTS {
            return Err(route_error(
                RouteErrorKind::Temporary,
                "MX answer exceeds its host budget",
            ));
        }
        answers.sort_by_key(|answer| answer.preference);
        let null_mx_count = answers.iter().filter(|answer| answer.host == ".").count();
        if null_mx_count > 0 {
            if answers.len() == 1 {
                return Ok(MxCacheEntry { hosts: Vec::new() });
            }
            return Err(route_error(
                RouteErrorKind::Permanent,
                "recipient domain mixes null MX with ordinary MX records",
            ));
        }
        let mut hosts = Vec::with_capacity(answers.len().max(1));
        for answer in answers {
            hosts.push(normalize_host(&answer.host)?);
        }
        let fallback = hosts.is_empty();
        if fallback {
            hosts.push(domain.to_owned());
        }
        let value = if fallback {
            FALLBACK_MARKER.to_owned()
        } else {
            hosts.join(",")
        };
        let ttl = if fallback {
            self.config.mx_negative_ttl_minutes * 60
        } else {
            self.config.mx_l2_ttl_minutes * 60
        };
        self.write_cache(&key, &value, ttl, deadline, cancellation)
            .await;
        Ok(MxCacheEntry { hosts })
    }

    async fn load_policy(
        &self,
        domain: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<MtaStsPolicy, RouteError> {
        let now = now_epoch_millis()?;
        if !self.mta_sts_enabled {
            return Ok(MtaStsPolicy::none(now));
        }
        if let Some(result) = self.policy_cache.get(domain).await {
            match result {
                Ok(entry) if entry.expires_at_epoch_millis > now => return Ok(entry.policy),
                _ => self.policy_cache.invalidate(domain).await,
            }
        }
        let owner = self.clone();
        let domain_owned = domain.to_owned();
        let shared_load_cancellation = CancellationToken::new();
        let load = self
            .policy_cache
            .get_with(domain_owned.clone(), async move {
                owner
                    .load_policy_uncached(&domain_owned, deadline, &shared_load_cancellation)
                    .await
            });
        let result = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled()),
            result = timeout_at(deadline, load) => result.map_err(|_| {
                route_error(RouteErrorKind::Temporary, "MTA-STS resolution timed out")
            })?,
        };
        match result {
            Ok(entry) => {
                if !entry.cacheable {
                    self.policy_cache.invalidate(domain).await;
                }
                Ok(entry.policy)
            }
            Err(error) => {
                self.policy_cache.invalidate(domain).await;
                Err(error)
            }
        }
    }

    async fn load_policy_uncached(
        &self,
        domain: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<PolicyCacheEntry, RouteError> {
        let now = now_epoch_millis()?;
        let key = format!("{MTA_STS_CACHE_PREFIX}{domain}");
        if let Some((value, ttl_millis)) = self.read_cache(&key, deadline, cancellation).await
            && let Some(policy) = MtaStsPolicy::deserialize_legacy(&value)
            && policy.is_valid()
        {
            let semantic_expiry = policy.fetched_at_epoch_millis.saturating_add(
                (policy.max_age_seconds.min(MAX_MTA_STS_CACHE_SECONDS) * 1_000) as i64,
            );
            let redis_expiry = now.saturating_add(ttl_millis);
            let expires_at_epoch_millis = semantic_expiry.min(redis_expiry);
            if expires_at_epoch_millis > now {
                return Ok(PolicyCacheEntry {
                    policy,
                    expires_at_epoch_millis,
                    cacheable: true,
                });
            }
        }

        let record_name = format!("_mta-sts.{domain}");
        let policy_id = match self.dns.txt(&record_name, deadline, cancellation).await {
            Ok(records) => select_mta_sts_record(&records),
            Err(DnsFailure::Cancelled) => return Err(cancelled()),
            Err(DnsFailure::NoRecords | DnsFailure::Temporary) => None,
        };
        let mut policy = MtaStsPolicy::none(now);
        if let Some(policy_id) = policy_id {
            let policy_host = format!("mta-sts.{domain}");
            if let Ok(addresses) = self
                .resolve_public_addresses(&policy_host, deadline, cancellation)
                .await
                && let Ok(response) = self
                    .http
                    .fetch(domain, &addresses, deadline, cancellation)
                    .await
                && response.status == 200
                && is_plain_text(response.content_type.as_deref())
                && let Ok(text) = std::str::from_utf8(&response.body)
                && let Some(parsed) = parse_policy_file(text, &policy_id, now)
            {
                policy = parsed;
            }
        }
        let cacheable = !(policy.version.is_some() && policy.max_age_seconds == 0);
        let ttl_seconds = if policy.is_valid() {
            policy.max_age_seconds.min(MAX_MTA_STS_CACHE_SECONDS)
        } else {
            MTA_STS_NEGATIVE_CACHE_SECONDS
        };
        let expires_at_epoch_millis = now.saturating_add((ttl_seconds * 1_000) as i64);
        if cacheable {
            self.write_cache(
                &key,
                &policy.serialize_legacy(),
                ttl_seconds,
                deadline,
                cancellation,
            )
            .await;
        }
        Ok(PolicyCacheEntry {
            policy,
            expires_at_epoch_millis,
            cacheable,
        })
    }

    async fn resolve_public_addresses(
        &self,
        host: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Vec<IpAddr>, RouteError> {
        let addresses = self
            .dns
            .addresses(host, deadline, cancellation)
            .await
            .map_err(|failure| match failure {
                DnsFailure::Cancelled => cancelled(),
                DnsFailure::NoRecords | DnsFailure::Temporary => {
                    route_error(RouteErrorKind::Temporary, "MX address resolution failed")
                }
            })?;
        if addresses.is_empty() || addresses.len() > MAX_ADDRESSES_PER_HOST {
            return Err(route_error(
                RouteErrorKind::Temporary,
                "MX address answer exceeds its budget",
            ));
        }
        if addresses.iter().any(|address| !is_public_smtp_ip(*address)) {
            return Err(route_error(
                RouteErrorKind::Configuration,
                "MX address answer contains a non-public address",
            ));
        }
        Ok(addresses)
    }

    async fn read_cache(
        &self,
        key: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Option<(String, i64)> {
        let operation_deadline = deadline.min(Instant::now() + CACHE_OPERATION_TIMEOUT);
        let mut connection = tokio::select! {
            _ = cancellation.cancelled() => return None,
            result = timeout_at(operation_deadline, self.redis_pool.get()) => result.ok()?.ok()?,
        };
        let mut command = redis::cmd("EVAL");
        command
            .arg(READ_BOUNDED_CACHE_SCRIPT)
            .arg(1)
            .arg(key)
            .arg(MAX_CACHE_VALUE_BYTES);
        let values: Vec<String> = tokio::select! {
            _ = cancellation.cancelled() => return None,
            result = timeout_at(
                operation_deadline,
                command.query_async(&mut connection),
            ) => result.ok()?.ok()?,
        };
        if values.len() != 3 || values[0] != "VALUE" {
            return None;
        }
        let ttl_millis = values[1].parse::<i64>().ok().filter(|ttl| *ttl > 0)?;
        Some((values[2].clone(), ttl_millis))
    }

    async fn write_cache(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) {
        if value.len() > MAX_CACHE_VALUE_BYTES || ttl_seconds == 0 {
            return;
        }
        let operation_deadline = deadline.min(Instant::now() + CACHE_OPERATION_TIMEOUT);
        let mut connection = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = timeout_at(operation_deadline, self.redis_pool.get()) => match result {
                Ok(Ok(connection)) => connection,
                _ => return,
            },
        };
        let _: Result<Result<(), redis::RedisError>, _> = timeout_at(
            operation_deadline,
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("EX")
                .arg(ttl_seconds)
                .query_async(&mut connection),
        )
        .await;
    }
}

fn deserialize_mx_hosts(value: &str) -> Option<Vec<String>> {
    if value.is_empty() || value.len() > MAX_CACHE_VALUE_BYTES {
        return None;
    }
    let raw: Vec<&str> = value.split(',').collect();
    if raw.is_empty() || raw.len() > MAX_MX_HOSTS {
        return None;
    }
    raw.into_iter()
        .map(normalize_host)
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

fn select_mta_sts_record(records: &[Vec<u8>]) -> Option<String> {
    if records.len() > MAX_TXT_RECORDS
        || records.iter().map(Vec::len).sum::<usize>() > MAX_TXT_BYTES
    {
        return None;
    }
    let mut selected = None;
    for record in records {
        let Ok(record) = std::str::from_utf8(record) else {
            continue;
        };
        let Some(policy_id) = parse_mta_sts_record_id(record) else {
            continue;
        };
        if selected.is_some() {
            return None;
        }
        selected = Some(policy_id);
    }
    selected
}

fn parse_mta_sts_record_id(record: &str) -> Option<String> {
    if !record.is_ascii() || record.bytes().any(|byte| byte < 0x20 && byte != b'\t') {
        return None;
    }
    let (version, remainder) = record.split_once(';')?;
    if !version.starts_with("v=STSv1")
        || !version["v=STSv1".len()..]
            .bytes()
            .all(|byte| matches!(byte, b' ' | b'\t'))
    {
        return None;
    }
    let mut policy_id = None;
    let fields: Vec<&str> = remainder.split(';').collect();
    for (index, field) in fields.iter().enumerate() {
        let field = field.trim();
        if field.is_empty() {
            if index + 1 == fields.len() {
                continue;
            }
            return None;
        }
        let (name, value) = field.split_once('=')?;
        if value.is_empty() || value.contains('=') {
            return None;
        }
        if name == "id" {
            if value.len() > 32 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return None;
            }
            if policy_id.is_none() {
                policy_id = Some(value.to_owned());
            }
        } else if name.is_empty()
            || name.len() > 32
            || !name.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'_' | b'.' | b'-'))
            })
            || !value.bytes().all(|byte| {
                (0x21..=0x3a).contains(&byte) || byte == 0x3c || (0x3e..=0x7e).contains(&byte)
            })
        {
            return None;
        }
    }
    policy_id
}

fn parse_policy_file(text: &str, policy_id: &str, now: i64) -> Option<MtaStsPolicy> {
    if text.is_empty() || text.len() > MAX_POLICY_BYTES {
        return None;
    }
    let mut version = None;
    let mut mode = None;
    let mut max_age_seconds = None;
    let mut mx_patterns = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "version" if version.is_none() => {
                if !value.eq_ignore_ascii_case("STSv1") {
                    return None;
                }
                version = Some("STSv1".to_owned());
            }
            "mode" if mode.is_none() => {
                mode = Some(if value.eq_ignore_ascii_case("enforce") {
                    MtaStsMode::Enforce
                } else if value.eq_ignore_ascii_case("testing") {
                    MtaStsMode::Testing
                } else if value.eq_ignore_ascii_case("none") {
                    MtaStsMode::None
                } else {
                    return None;
                });
            }
            "mx" if !value.is_empty() => {
                if mx_patterns.len() >= MAX_POLICY_PATTERNS {
                    return None;
                }
                if let Ok(pattern) = validate_mx_pattern(value) {
                    mx_patterns.push(pattern);
                }
            }
            "max_age" if max_age_seconds.is_none() => {
                if value.is_empty()
                    || value.len() > 10
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return None;
                }
                max_age_seconds = Some(value.parse::<u64>().ok()?.min(MAX_MTA_STS_AGE_SECONDS));
            }
            _ => {}
        }
    }
    Some(MtaStsPolicy {
        version: Some(version?),
        mode: mode?,
        mx_patterns: (!mx_patterns.is_empty()).then_some(mx_patterns)?,
        max_age_seconds: max_age_seconds?,
        policy_id: Some(policy_id.to_owned()),
        fetched_at_epoch_millis: now,
    })
}

fn validate_mx_pattern(value: &str) -> Result<String, RouteError> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() || value.len() > MAX_POLICY_BYTES {
        return Err(route_error(
            RouteErrorKind::Permanent,
            "invalid MTA-STS MX pattern",
        ));
    }
    let normalized = if value.is_ascii() {
        value
    } else if let Some(suffix) = value.strip_prefix("*.") {
        format!(
            "*.{}",
            domain_to_ascii_strict(suffix).map_err(|_| {
                route_error(RouteErrorKind::Permanent, "invalid MTA-STS MX pattern")
            })?
        )
    } else {
        domain_to_ascii_strict(&value)
            .map_err(|_| route_error(RouteErrorKind::Permanent, "invalid MTA-STS MX pattern"))?
    };
    if let Some(suffix) = normalized.strip_prefix("*.") {
        if !suffix.is_empty() && suffix.contains('.') && !suffix.starts_with('.') {
            return Ok(normalized);
        }
    } else if normalized.contains('.') && !normalized.starts_with('.') && !normalized.ends_with('.')
    {
        return Ok(normalized);
    }
    Err(route_error(
        RouteErrorKind::Permanent,
        "invalid MTA-STS MX pattern",
    ))
}

fn normalize_host(value: &str) -> Result<String, RouteError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 || value.parse::<IpAddr>().is_ok() {
        return Err(route_error(
            RouteErrorKind::Permanent,
            "invalid outbound route hostname",
        ));
    }
    let ascii = domain_to_ascii_strict(&value)
        .map_err(|_| route_error(RouteErrorKind::Permanent, "invalid outbound route hostname"))?;
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(route_error(
            RouteErrorKind::Permanent,
            "invalid outbound route hostname",
        ));
    }
    Ok(ascii.to_ascii_lowercase())
}

fn is_plain_text(value: Option<&str>) -> bool {
    value
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/plain"))
}

fn now_epoch_millis() -> Result<i64, RouteError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| route_error(RouteErrorKind::Configuration, "system clock is invalid"))?
        .as_millis();
    i64::try_from(millis)
        .map_err(|_| route_error(RouteErrorKind::Configuration, "system clock is invalid"))
}

fn route_error(kind: RouteErrorKind, message: &str) -> RouteError {
    RouteError {
        kind,
        message: message.to_owned(),
    }
}

fn cancelled() -> RouteError {
    route_error(RouteErrorKind::Cancelled, "outbound route cancelled")
}

#[cfg(test)]
#[path = "outbound_route_tests.rs"]
mod tests;
