use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    net::SocketAddr,
    sync::{Arc, LazyLock},
    time::Duration,
};

use chrono::NaiveDate;
use deadpool_postgres::{Object, Pool};
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::{NetError, runtime::TokioRuntimeProvider},
    proto::rr::RData,
};
use regex::Regex;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{CancelToken, NoTls};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::config::ReportingConfig;

const DATABASE_DEADLINE: Duration = Duration::from_secs(8);
const DATABASE_CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_DEADLINE: Duration = Duration::from_secs(8);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_ATTEMPTS: usize = 2;
const DNS_MAX_ACTIVE_REQUESTS: usize = 32;
const DNS_MAX_TXT_RECORDS: usize = 32;
const DNS_MAX_TXT_BYTES: usize = 64 * 1024;
const MAX_RUA_ADDRESSES: usize = 10;

static RUA_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)rua=([^;]+)").expect("RUA regex is valid"));
static MAILTO_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)mailto:([^,\s]+)").expect("mailto regex is valid"));
static HTTPS_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)https://([^,\s]+)").expect("HTTPS regex is valid"));

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReportDomains {
    pub dmarc: Vec<String>,
    pub tls: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReportAddressLists {
    pub mailto: Vec<String>,
    pub https: Vec<String>,
}

impl ReportAddressLists {
    fn empty() -> Self {
        Self {
            mailto: Vec::new(),
            https: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.mailto.is_empty() && self.https.is_empty()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReportAddresses {
    pub dmarc: ReportAddressLists,
    pub tlsrpt: ReportAddressLists,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DomainDataPresence {
    pub dmarc: bool,
    pub tls: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReportingError {
    Cancelled,
    Timeout,
    Database(String),
    Dns(String),
}

impl fmt::Display for ReportingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("reporting operation cancelled"),
            Self::Timeout => formatter.write_str("reporting database deadline exceeded"),
            Self::Database(_) => formatter.write_str("reporting database unavailable"),
            Self::Dns(_) => formatter.write_str("reporting DNS unavailable"),
        }
    }
}

impl std::error::Error for ReportingError {}

#[derive(Clone)]
pub struct ReportingService {
    pool: Pool,
    config: ReportingConfig,
    resolver: TokioResolver,
    dns_permits: Arc<Semaphore>,
}

impl ReportingService {
    pub fn new(pool: Pool, config: ReportingConfig) -> Result<Self, ReportingError> {
        let resolver = build_dns_resolver(config.dns_server).map_err(|error| {
            ReportingError::Dns(format!("resolver initialization failed: {error}"))
        })?;
        Ok(Self {
            pool,
            config,
            resolver,
            dns_permits: Arc::new(Semaphore::new(DNS_MAX_ACTIVE_REQUESTS)),
        })
    }

    pub fn config(&self) -> &ReportingConfig {
        &self.config
    }

    pub async fn addresses(
        &self,
        domain: &str,
        cancellation: &CancellationToken,
    ) -> Result<ReportAddresses, ReportingError> {
        let Some(report_domain) = normalize_domain(domain) else {
            return Ok(ReportAddresses {
                dmarc: ReportAddressLists::empty(),
                tlsrpt: ReportAddressLists::empty(),
            });
        };
        let deadline = Instant::now() + DNS_DEADLINE;
        let dmarc = self
            .discover_dmarc(&report_domain, deadline, cancellation)
            .await?;
        let tlsrpt = self
            .discover_tlsrpt(&report_domain, deadline, cancellation)
            .await?;
        Ok(ReportAddresses { dmarc, tlsrpt })
    }

    async fn discover_dmarc(
        &self,
        report_domain: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<ReportAddressLists, ReportingError> {
        let records = match self
            .lookup_txt(&format!("_dmarc.{report_domain}."), deadline, cancellation)
            .await
        {
            Ok(records) => records,
            Err(DnsLookupError::Cancelled) => return Err(ReportingError::Cancelled),
            Err(_) => return Ok(ReportAddressLists::empty()),
        };
        let policies: Vec<&str> = records
            .iter()
            .map(String::as_str)
            .filter(|record| has_exact_first_version_tag(record, "v=DMARC1"))
            .collect();
        if policies.len() != 1 {
            return Ok(ReportAddressLists::empty());
        }
        let parsed = parse_rua_addresses(policies[0]);
        self.filter_authorized_dmarc(report_domain, parsed, deadline, cancellation)
            .await
    }

    async fn discover_tlsrpt(
        &self,
        report_domain: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<ReportAddressLists, ReportingError> {
        let records = match self
            .lookup_txt(
                &format!("_smtp._tls.{report_domain}."),
                deadline,
                cancellation,
            )
            .await
        {
            Ok(records) => records,
            Err(DnsLookupError::Cancelled) => return Err(ReportingError::Cancelled),
            Err(_) => return Ok(ReportAddressLists::empty()),
        };
        let policies: Vec<&str> = records
            .iter()
            .map(String::as_str)
            .filter(|record| has_exact_first_version_tag(record, "v=TLSRPTv1"))
            .collect();
        if policies.len() != 1 {
            return Ok(ReportAddressLists::empty());
        }
        Ok(parse_rua_addresses(policies[0]))
    }

    async fn filter_authorized_dmarc(
        &self,
        report_domain: &str,
        addresses: ReportAddressLists,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<ReportAddressLists, ReportingError> {
        if addresses.is_empty() {
            return Ok(ReportAddressLists::empty());
        }
        let mut authorized_mailto = Vec::new();
        let mut authorized_https = Vec::new();
        let mut authorization_cache = HashMap::<String, bool>::new();

        for email in addresses.mailto {
            if authorized_mailto.len() + authorized_https.len() >= MAX_RUA_ADDRESSES {
                break;
            }
            let Some(destination) = extract_email_domain(&email) else {
                continue;
            };
            if self
                .authorized(
                    report_domain,
                    &destination,
                    &mut authorization_cache,
                    deadline,
                    cancellation,
                )
                .await?
            {
                authorized_mailto.push(email);
            }
        }
        for endpoint in addresses.https {
            if authorized_mailto.len() + authorized_https.len() >= MAX_RUA_ADDRESSES {
                break;
            }
            let Some(destination) = extract_uri_host(&endpoint) else {
                continue;
            };
            if self
                .authorized(
                    report_domain,
                    &destination,
                    &mut authorization_cache,
                    deadline,
                    cancellation,
                )
                .await?
            {
                authorized_https.push(endpoint);
            }
        }
        Ok(ReportAddressLists {
            mailto: authorized_mailto,
            https: authorized_https,
        })
    }

    async fn authorized(
        &self,
        report_domain: &str,
        destination: &str,
        cache: &mut HashMap<String, bool>,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<bool, ReportingError> {
        let destination = destination.to_ascii_lowercase();
        if report_domain.eq_ignore_ascii_case(&destination) {
            return Ok(true);
        }
        if let Some(value) = cache.get(&destination) {
            return Ok(*value);
        }
        let query = format!("{report_domain}._report._dmarc.{destination}.");
        let authorized = match self.lookup_txt(&query, deadline, cancellation).await {
            Ok(records) => records
                .iter()
                .any(|record| has_exact_first_version_tag(record, "v=DMARC1")),
            Err(DnsLookupError::Cancelled) => return Err(ReportingError::Cancelled),
            Err(_) => false,
        };
        cache.insert(destination, authorized);
        Ok(authorized)
    }

    async fn lookup_txt(
        &self,
        name: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Vec<String>, DnsLookupError> {
        match self.lookup_txt_once(name, deadline, cancellation).await {
            Err(DnsLookupError::NoRecords) => {
                self.lookup_txt_once(name, deadline, cancellation).await
            }
            result => result,
        }
    }

    async fn lookup_txt_once(
        &self,
        name: &str,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Vec<String>, DnsLookupError> {
        let permit = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(DnsLookupError::Cancelled),
            result = timeout_at(deadline, self.dns_permits.clone().acquire_owned()) => {
                match result {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return Err(DnsLookupError::Unavailable),
                    Err(_) => return Err(DnsLookupError::Timeout),
                }
            }
        };
        let _permit = permit;
        let future = self.resolver.txt_lookup(name);
        let lookup = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(DnsLookupError::Cancelled),
            result = timeout_at(deadline, future) => {
                match result {
                    Ok(Ok(lookup)) => lookup,
                    Ok(Err(error)) if error.is_no_records_found() => return Err(DnsLookupError::NoRecords),
                    Ok(Err(_)) => return Err(DnsLookupError::Unavailable),
                    Err(_) => return Err(DnsLookupError::Timeout),
                }
            }
        };
        let mut records = Vec::new();
        let mut total_bytes = 0_usize;
        for record in lookup.answers() {
            let RData::TXT(txt) = &record.data else {
                continue;
            };
            if records.len() >= DNS_MAX_TXT_RECORDS {
                return Err(DnsLookupError::OverLimit);
            }
            let size = txt.txt_data.iter().map(|part| part.len()).sum::<usize>();
            total_bytes = total_bytes
                .checked_add(size)
                .ok_or(DnsLookupError::OverLimit)?;
            if total_bytes > DNS_MAX_TXT_BYTES {
                return Err(DnsLookupError::OverLimit);
            }
            let mut value = Vec::with_capacity(size);
            for part in &txt.txt_data {
                value.extend_from_slice(part);
            }
            let Ok(value) = String::from_utf8(value) else {
                continue;
            };
            records.push(value);
        }
        Ok(records)
    }

    pub async fn domains(
        &self,
        report_date: NaiveDate,
        cancellation: &CancellationToken,
    ) -> Result<ReportDomains, ReportingError> {
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let minimum = i64::from(self.config.min_volume_for_report);
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let dmarc_rows = connection
                .client()
                .query(
                    "SELECT header_from_domain \
                     FROM inbound_dmarc_log \
                     WHERE report_date = $1 AND header_from_domain IS NOT NULL \
                     GROUP BY header_from_domain \
                     HAVING COALESCE(SUM(message_count), 0) >= $2",
                    &[&report_date, &minimum],
                )
                .await
                .map_err(database_error)?;
            let tls_rows = connection
                .client()
                .query(
                    "SELECT recipient_domain \
                     FROM outbound_tls_log \
                     WHERE report_date = $1 AND recipient_domain IS NOT NULL \
                     GROUP BY recipient_domain \
                     HAVING COALESCE(SUM(connection_count), 0) >= $2",
                    &[&report_date, &minimum],
                )
                .await
                .map_err(database_error)?;
            Ok(ReportDomains {
                dmarc: non_blank_domains(dmarc_rows),
                tls: non_blank_domains(tls_rows),
            })
        })
        .await;
        connection.finish(outcome)
    }

    pub async fn domain_data_presence(
        &self,
        domain: &str,
        report_date: NaiveDate,
        cancellation: &CancellationToken,
    ) -> Result<DomainDataPresence, ReportingError> {
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let row = connection
                .client()
                .query_one(
                    "SELECT \
                       EXISTS(SELECT 1 FROM inbound_dmarc_log \
                              WHERE report_date = $1 AND header_from_domain = $2), \
                       EXISTS(SELECT 1 FROM outbound_tls_log \
                              WHERE report_date = $1 AND recipient_domain = $2)",
                    &[&report_date, &domain],
                )
                .await
                .map_err(database_error)?;
            Ok(DomainDataPresence {
                dmarc: row.get(0),
                tls: row.get(1),
            })
        })
        .await;
        connection.finish(outcome)
    }

    async fn client(
        &self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<Object, ReportingError> {
        wait_database(self.pool.get(), deadline, cancellation).await
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DnsLookupError {
    Cancelled,
    Timeout,
    NoRecords,
    Unavailable,
    OverLimit,
}

fn build_dns_resolver(server: Option<SocketAddr>) -> Result<TokioResolver, NetError> {
    let mut builder = if let Some(server) = server {
        let mut name_server = NameServerConfig::udp(server.ip());
        name_server.trust_negative_responses = false;
        for connection in &mut name_server.connections {
            connection.port = server.port();
        }
        let mut config = ResolverConfig::default();
        config.add_name_server(name_server);
        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
    } else {
        TokioResolver::builder_tokio()?
    };
    builder.options_mut().attempts = DNS_ATTEMPTS;
    builder.options_mut().timeout = DNS_QUERY_TIMEOUT;
    builder.options_mut().max_active_requests = DNS_MAX_ACTIVE_REQUESTS;
    builder.options_mut().num_concurrent_reqs = 1;
    // The frozen dnsjava oracle performs one explicit NXDOMAIN retry. Keep
    // this reporting-only resolver uncached so that the retry reaches DNS.
    builder.options_mut().cache_size = 0;
    builder.build()
}

fn normalize_domain(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 253
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'/' || byte == b'\\')
    {
        return None;
    }
    let value = value.trim_end_matches('.');
    if value.is_empty() {
        return None;
    }
    let ascii = idna::domain_to_ascii(value).ok()?.to_ascii_lowercase();
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
    {
        return None;
    }
    Some(ascii)
}

fn has_exact_first_version_tag(record: &str, expected: &str) -> bool {
    record
        .split_once(';')
        .map_or(record, |(first, _)| first)
        .trim()
        .eq_ignore_ascii_case(expected)
}

fn parse_rua_addresses(record: &str) -> ReportAddressLists {
    let Some(capture) = RUA_PATTERN.captures(record) else {
        return ReportAddressLists::empty();
    };
    let Some(value) = capture.get(1).map(|capture| capture.as_str()) else {
        return ReportAddressLists::empty();
    };
    let mut mailto = Vec::new();
    let mut https = Vec::new();
    let mut seen_mailto = HashSet::new();
    let mut seen_https = HashSet::new();
    for capture in MAILTO_PATTERN.captures_iter(value) {
        if mailto.len() + https.len() >= MAX_RUA_ADDRESSES {
            break;
        }
        let Some(raw) = capture.get(1).map(|capture| capture.as_str().trim()) else {
            continue;
        };
        let email = raw.split('!').next().unwrap_or_default().trim();
        if !email.is_empty() && seen_mailto.insert(email.to_owned()) {
            mailto.push(email.to_owned());
        }
    }
    for capture in HTTPS_PATTERN.captures_iter(value) {
        if mailto.len() + https.len() >= MAX_RUA_ADDRESSES {
            break;
        }
        let Some(host_and_path) = capture.get(1).map(|capture| capture.as_str().trim()) else {
            continue;
        };
        let endpoint = format!("https://{host_and_path}");
        if seen_https.insert(endpoint.clone()) {
            https.push(endpoint);
        }
    }
    ReportAddressLists { mailto, https }
}

fn extract_email_domain(value: &str) -> Option<String> {
    let domain = value.rsplit_once('@')?.1.trim();
    normalize_domain(domain)
}

fn extract_uri_host(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    normalize_domain(url.host_str()?)
}

fn non_blank_domains(rows: Vec<tokio_postgres::Row>) -> Vec<String> {
    rows.into_iter()
        .map(|row| row.get::<_, String>(0))
        .filter(|domain| !domain.trim().is_empty())
        .collect()
}

fn database_error(error: tokio_postgres::Error) -> ReportingError {
    ReportingError::Database(error.to_string())
}

async fn wait_database<T, E, F>(
    future: F,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<T, ReportingError>
where
    E: fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ReportingError::Cancelled),
        result = timeout_at(deadline, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(ReportingError::Database(error.to_string())),
            Err(_) => Err(ReportingError::Timeout),
        }
    }
}

struct DatabaseOutcome<T> {
    result: Result<T, ReportingError>,
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
            .expect("reporting database connection is present")
    }

    fn cancel_token(&self) -> CancelToken {
        self.client().cancel_token()
    }

    fn finish<T>(mut self, outcome: DatabaseOutcome<T>) -> Result<T, ReportingError> {
        let client = self
            .client
            .take()
            .expect("reporting database connection is present");
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
    F: Future<Output = Result<T, ReportingError>>,
{
    tokio::pin!(future);
    let interruption = tokio::select! {
        biased;
        _ = cancellation.cancelled() => ReportingError::Cancelled,
        result = timeout_at(deadline, future.as_mut()) => match result {
            Ok(result) => return DatabaseOutcome {
                result,
                discard_connection: false,
            },
            Err(_) => ReportingError::Timeout,
        },
    };

    let recovery = timeout_at(Instant::now() + DATABASE_CANCEL_DRAIN_TIMEOUT, async {
        tokio::join!(cancel_token.cancel_query(NoTls), future.as_mut())
    })
    .await;
    DatabaseOutcome {
        result: Err(interruption),
        discard_connection: !matches!(recovery, Ok((Ok(()), _))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reporting_error_does_not_expose_database_details() {
        let error = ReportingError::Database("password=secret".to_owned());
        assert_eq!(error.to_string(), "reporting database unavailable");

        let error = ReportingError::Dns("server=127.0.0.1:5353".to_owned());
        assert_eq!(error.to_string(), "reporting DNS unavailable");
    }

    #[test]
    fn version_tag_must_be_the_exact_first_tag() {
        assert!(has_exact_first_version_tag(
            " V=dmARC1 ; p=none",
            "v=DMARC1"
        ));
        assert!(!has_exact_first_version_tag(
            "v=DMARC10; p=none",
            "v=DMARC1"
        ));
        assert!(!has_exact_first_version_tag("p=none; v=DMARC1", "v=DMARC1"));
    }

    #[test]
    fn rua_parser_deduplicates_strips_size_and_gives_mailto_capacity_first() {
        let record = format!(
            "v=DMARC1; rua=mailto:first@example.test!10m,mailto:first@example.test,{},https://too-late.example/report",
            (0..12)
                .map(|index| format!("mailto:user-{index}@example.test"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let addresses = parse_rua_addresses(&record);
        assert_eq!(addresses.mailto.len(), MAX_RUA_ADDRESSES);
        assert_eq!(addresses.mailto[0], "first@example.test");
        assert_eq!(addresses.mailto[1], "user-0@example.test");
        assert!(addresses.https.is_empty());
    }

    #[test]
    fn domain_and_destination_parsing_is_bounded_and_normalized() {
        assert_eq!(
            normalize_domain("MiXeD.Example."),
            Some("mixed.example".into())
        );
        assert_eq!(
            extract_email_domain("person@MiXeD.Example"),
            Some("mixed.example".into())
        );
        assert_eq!(
            extract_uri_host("https://MiXeD.Example/report"),
            Some("mixed.example".into())
        );
        for invalid in ["", ".", "bad/domain", "-bad.example", "bad-.example"] {
            assert_eq!(normalize_domain(invalid), None, "accepted {invalid:?}");
        }
    }
}
