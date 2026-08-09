use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    io::{self, Write},
    net::SocketAddr,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{Days, NaiveDate, Utc};
use deadpool_postgres::{Object, Pool};
use flate2::{Compression, write::GzEncoder};
use getrandom::fill as fill_random;
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig},
    net::{NetError, runtime::TokioRuntimeProvider},
    proto::rr::RData,
};
use regex::Regex;
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_postgres::{CancelToken, NoTls};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    bounded_blocking::{BoundedBlockingPool, SubmitError},
    config::ReportingConfig,
    outbound::{AttachmentInput, OutboundError, OutboundService, SendRequest},
};

const DATABASE_DEADLINE: Duration = Duration::from_secs(8);
const DATABASE_CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_DEADLINE: Duration = Duration::from_secs(8);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_ATTEMPTS: usize = 2;
const DNS_MAX_ACTIVE_REQUESTS: usize = 32;
const DNS_MAX_TXT_RECORDS: usize = 32;
const DNS_MAX_TXT_BYTES: usize = 64 * 1024;
const MAX_RUA_ADDRESSES: usize = 10;
const MAX_AGGREGATE_RECORDS: i64 = 10_000;
const MAX_AGGREGATE_FIELD_BYTES: usize = 4 * 1024;
const MAX_AGGREGATE_INPUT_BYTES: i64 = 4 * 1024 * 1024;
const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;
const REPORT_RENDER_DEADLINE: Duration = Duration::from_secs(10);
const REPORT_RENDER_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const REPORT_RENDER_WORKERS: usize = 2;
const REPORT_RENDER_QUEUE: usize = 8;

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

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ReportDeliveryResult {
    pub success: bool,
    pub method: &'static str,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ProtocolReportResult {
    pub results: Vec<ReportDeliveryResult>,
    pub error: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct SingleDomainReportResult {
    pub domain: String,
    pub date: String,
    pub dmarc: ProtocolReportResult,
    pub tls: ProtocolReportResult,
}

#[derive(Debug, Clone)]
struct DmarcAggregateRow {
    source_ip: Option<String>,
    spf_result: Option<String>,
    dkim_result: Option<String>,
    disposition: Option<String>,
    count: i32,
    dkim_domain: Option<String>,
    dkim_selector: Option<String>,
    spf_domain: Option<String>,
    envelope_from_domain: Option<String>,
    dmarc_policy: Option<String>,
}

#[derive(Debug, Clone)]
struct TlsAggregateRow {
    mx_host: Option<String>,
    tls_success: bool,
    failure_type: Option<String>,
    count: i32,
    failure_reason: Option<String>,
    sts_policy_version: Option<String>,
    sts_policy_mode: Option<String>,
    sts_mx_patterns: Option<String>,
    sts_max_age: Option<i64>,
    target_ip: Option<String>,
    mta_sts_enforced: bool,
}

#[derive(Debug)]
struct GeneratedReport {
    report_id: String,
    filename: String,
    compressed: Vec<u8>,
    content_type: &'static str,
    success_count: i32,
    failure_count: i32,
    record_count: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReportingError {
    Cancelled,
    Timeout,
    Database(String),
    Dns(String),
    ResourceLimit,
    Render,
    Outbound,
}

impl fmt::Display for ReportingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("reporting operation cancelled"),
            Self::Timeout => formatter.write_str("reporting database deadline exceeded"),
            Self::Database(_) => formatter.write_str("reporting database unavailable"),
            Self::Dns(_) => formatter.write_str("reporting DNS unavailable"),
            Self::ResourceLimit => formatter.write_str("reporting resource limit exceeded"),
            Self::Render => formatter.write_str("report rendering failed"),
            Self::Outbound => formatter.write_str("report delivery unavailable"),
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
    render_pool: Arc<BoundedBlockingPool>,
}

impl ReportingService {
    pub fn new(pool: Pool, config: ReportingConfig) -> Result<Self, ReportingError> {
        let resolver = build_dns_resolver(config.dns_server).map_err(|error| {
            ReportingError::Dns(format!("resolver initialization failed: {error}"))
        })?;
        let render_pool = BoundedBlockingPool::new(
            "lmyzmail-report-render",
            REPORT_RENDER_WORKERS,
            REPORT_RENDER_QUEUE,
        )
        .map_err(|_| ReportingError::Render)?;
        Ok(Self {
            pool,
            config,
            resolver,
            dns_permits: Arc::new(Semaphore::new(DNS_MAX_ACTIVE_REQUESTS)),
            render_pool: Arc::new(render_pool),
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

    pub async fn generate_for_domain(
        &self,
        domain: &str,
        report_date: NaiveDate,
        our_domain: &str,
        outbound: &OutboundService,
        cancellation: &CancellationToken,
    ) -> Result<SingleDomainReportResult, ReportingError> {
        let dmarc = match self
            .generate_dmarc_for_domain(domain, report_date, our_domain, outbound, cancellation)
            .await
        {
            Ok(result) => result,
            Err(ReportingError::Cancelled) => return Err(ReportingError::Cancelled),
            Err(error) => ProtocolReportResult {
                results: Vec::new(),
                error: error.to_string(),
            },
        };
        let tls = match self
            .generate_tls_for_domain(domain, report_date, our_domain, outbound, cancellation)
            .await
        {
            Ok(result) => result,
            Err(ReportingError::Cancelled) => return Err(ReportingError::Cancelled),
            Err(error) => ProtocolReportResult {
                results: Vec::new(),
                error: error.to_string(),
            },
        };
        Ok(SingleDomainReportResult {
            domain: domain.to_owned(),
            date: report_date.to_string(),
            dmarc,
            tls,
        })
    }

    async fn generate_dmarc_for_domain(
        &self,
        domain: &str,
        report_date: NaiveDate,
        our_domain: &str,
        outbound: &OutboundService,
        cancellation: &CancellationToken,
    ) -> Result<ProtocolReportResult, ReportingError> {
        let rows = self.dmarc_rows(domain, report_date, cancellation).await?;
        if rows.is_empty() {
            return Ok(ProtocolReportResult {
                results: Vec::new(),
                error: "No DMARC data for this domain/date".into(),
            });
        }
        let report = self
            .render_dmarc(domain, report_date, our_domain, rows, cancellation)
            .await?;
        let deadline = Instant::now() + DNS_DEADLINE;
        let Some(report_domain) = normalize_domain(domain) else {
            return Ok(ProtocolReportResult {
                results: Vec::new(),
                error: "No DMARC RUA addresses found".into(),
            });
        };
        let addresses = self
            .discover_dmarc(&report_domain, deadline, cancellation)
            .await?;
        if addresses.is_empty() {
            return Ok(ProtocolReportResult {
                results: Vec::new(),
                error: "No DMARC RUA addresses found".into(),
            });
        }
        let mut results = Vec::with_capacity(addresses.mailto.len());
        for target in addresses.mailto {
            results.push(
                self.enqueue_report(
                    ReportKind::Dmarc,
                    &report,
                    domain,
                    our_domain,
                    &target,
                    outbound,
                    cancellation,
                )
                .await,
            );
        }
        Ok(ProtocolReportResult {
            results,
            error: "none".into(),
        })
    }

    async fn generate_tls_for_domain(
        &self,
        domain: &str,
        report_date: NaiveDate,
        our_domain: &str,
        outbound: &OutboundService,
        cancellation: &CancellationToken,
    ) -> Result<ProtocolReportResult, ReportingError> {
        let rows = self.tls_rows(domain, report_date, cancellation).await?;
        if rows.is_empty() {
            return Ok(ProtocolReportResult {
                results: Vec::new(),
                error: "No TLS data for this domain/date".into(),
            });
        }
        let report = self
            .render_tls(domain, report_date, our_domain, rows, cancellation)
            .await?;
        let deadline = Instant::now() + DNS_DEADLINE;
        let Some(report_domain) = normalize_domain(domain) else {
            return Ok(ProtocolReportResult {
                results: Vec::new(),
                error: "No TLSRPT RUA addresses found".into(),
            });
        };
        let addresses = self
            .discover_tlsrpt(&report_domain, deadline, cancellation)
            .await?;
        if addresses.is_empty() {
            return Ok(ProtocolReportResult {
                results: Vec::new(),
                error: "No TLSRPT RUA addresses found".into(),
            });
        }
        let capacity = addresses.mailto.len().saturating_add(addresses.https.len());
        let mut results = Vec::with_capacity(capacity);
        for target in addresses.mailto {
            results.push(
                self.enqueue_report(
                    ReportKind::Tls,
                    &report,
                    domain,
                    our_domain,
                    &target,
                    outbound,
                    cancellation,
                )
                .await,
            );
        }
        if self.config.http_delivery_enabled {
            for target in addresses.https {
                results.push(ReportDeliveryResult {
                    success: false,
                    method: "https",
                    target,
                    error: Some(ReportingError::Outbound.to_string()),
                });
            }
        }
        Ok(ProtocolReportResult {
            results,
            error: "none".into(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn enqueue_report(
        &self,
        kind: ReportKind,
        report: &GeneratedReport,
        domain: &str,
        our_domain: &str,
        target: &str,
        outbound: &OutboundService,
        cancellation: &CancellationToken,
    ) -> ReportDeliveryResult {
        let sender = match kind {
            ReportKind::Dmarc => self.config.dmarc_report_sender_address.as_deref(),
            ReportKind::Tls => self.config.tls_report_sender_address.as_deref(),
        };
        let Some(sender) = sender.filter(|value| !value.trim().is_empty()) else {
            return ReportDeliveryResult {
                success: false,
                method: "email",
                target: target.to_owned(),
                error: Some(match kind {
                    ReportKind::Dmarc => "DMARC report sender address not configured".into(),
                    ReportKind::Tls => "TLS report sender address not configured".into(),
                }),
            };
        };
        let subject = format!(
            "Report Domain: {domain} Submitter: {our_domain} Report-ID: {}",
            report.report_id
        );
        let period = Utc::now()
            .date_naive()
            .checked_sub_days(Days::new(1))
            .unwrap_or_else(|| Utc::now().date_naive());
        let body = match kind {
            ReportKind::Dmarc => format!(
                "This is an aggregate DMARC report for domain: {domain}\r\n\r\n\
                 Report Period: {period}\r\n\
                 Report ID: {}\r\n\
                 Submitter: {our_domain}\r\n\
                 Records: {}\r\n\r\n\
                 The report is attached as a gzip-compressed XML file.\r\n",
                report.report_id, report.record_count,
            ),
            ReportKind::Tls => format!(
                "This is a SMTP TLS Reporting report for domain: {domain}\r\n\r\n\
                 Report Period: {period}\r\n\
                 Report ID: {}\r\n\
                 Submitter: {our_domain}\r\n\
                 Successful Sessions: {}\r\n\
                 Failed Sessions: {}\r\n\r\n\
                 The report is attached as a gzip-compressed JSON file.\r\n",
                report.report_id, report.success_count, report.failure_count,
            ),
        };
        let request = SendRequest {
            from: Some(sender.to_owned()),
            password: None,
            to: vec![target.to_owned()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: Some(subject),
            text: Some(body),
            html: None,
            attachments: vec![AttachmentInput {
                filename: Some(report.filename.clone()),
                content_type: Some(report.content_type.into()),
                content_base64: Some(BASE64_STANDARD.encode(&report.compressed)),
                inline: false,
                content_id: None,
            }],
            in_reply_to: None,
            references: None,
            asynchronous: Some(true),
        };
        match outbound
            .enqueue_with_cancellation(request, None, cancellation)
            .await
        {
            Ok(_) => ReportDeliveryResult {
                success: true,
                method: "email",
                target: target.to_owned(),
                error: None,
            },
            Err(error) => ReportDeliveryResult {
                success: false,
                method: "email",
                target: target.to_owned(),
                error: Some(safe_outbound_error(&error)),
            },
        }
    }

    async fn dmarc_rows(
        &self,
        domain: &str,
        report_date: NaiveDate,
        cancellation: &CancellationToken,
    ) -> Result<Vec<DmarcAggregateRow>, ReportingError> {
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let rows = connection
                .client()
                .query(
                    "WITH aggregated AS MATERIALIZED (\
                       SELECT source_ip,spf_result,dkim_result,disposition,\
                              COALESCE(SUM(message_count),0)::text AS total_count,\
                              MIN(dkim_domain) AS dkim_domain,\
                              MIN(dkim_selector) AS dkim_selector,\
                              MIN(spf_domain) AS spf_domain,\
                              MIN(envelope_from_domain) AS envelope_from_domain,\
                              MIN(dmarc_policy) AS dmarc_policy \
                       FROM inbound_dmarc_log \
                       WHERE report_date=$1 AND header_from_domain=$2 \
                       GROUP BY source_ip,spf_result,dkim_result,disposition\
                     ), metrics AS (\
                       SELECT count(*)::bigint AS total_records,\
                              COALESCE(SUM(\
                                octet_length(COALESCE(source_ip,'')) +\
                                octet_length(COALESCE(spf_result,'')) +\
                                octet_length(COALESCE(dkim_result,'')) +\
                                octet_length(COALESCE(disposition,'')) +\
                                octet_length(total_count) +\
                                octet_length(COALESCE(dkim_domain,'')) +\
                                octet_length(COALESCE(dkim_selector,'')) +\
                                octet_length(COALESCE(spf_domain,'')) +\
                                octet_length(COALESCE(envelope_from_domain,'')) +\
                                octet_length(COALESCE(dmarc_policy,''))\
                              ),0)::bigint AS total_bytes \
                       FROM aggregated\
                     ) \
                     SELECT metrics.total_records,metrics.total_bytes,\
                            aggregated.source_ip,aggregated.spf_result,\
                            aggregated.dkim_result,aggregated.disposition,\
                            aggregated.total_count,aggregated.dkim_domain,\
                            aggregated.dkim_selector,aggregated.spf_domain,\
                            aggregated.envelope_from_domain,aggregated.dmarc_policy \
                     FROM metrics LEFT JOIN aggregated \
                       ON metrics.total_records <= $3 AND metrics.total_bytes <= $4",
                    &[
                        &report_date,
                        &domain,
                        &MAX_AGGREGATE_RECORDS,
                        &MAX_AGGREGATE_INPUT_BYTES,
                    ],
                )
                .await
                .map_err(database_error)?;
            decode_dmarc_rows(rows)
        })
        .await;
        connection.finish(outcome)
    }

    async fn tls_rows(
        &self,
        domain: &str,
        report_date: NaiveDate,
        cancellation: &CancellationToken,
    ) -> Result<Vec<TlsAggregateRow>, ReportingError> {
        let deadline = Instant::now() + DATABASE_DEADLINE;
        let client = self.client(deadline, cancellation).await?;
        let connection = DatabaseConnection::new(client);
        let cancel_token = connection.cancel_token();
        let outcome = database_read(deadline, cancellation, &cancel_token, async {
            let rows = connection
                .client()
                .query(
                    "WITH aggregated AS MATERIALIZED (\
                       SELECT mx_host,tls_success,failure_type,\
                              COALESCE(SUM(connection_count),0)::text AS total_count,\
                              MIN(failure_reason) AS failure_reason,\
                              MIN(sts_policy_version) AS sts_policy_version,\
                              MIN(sts_policy_mode) AS sts_policy_mode,\
                              MIN(sts_mx_patterns) AS sts_mx_patterns,\
                              MIN(sts_max_age) AS sts_max_age,\
                              MIN(target_ip) AS target_ip,\
                              BOOL_OR(mta_sts_enforced) AS mta_sts_enforced \
                       FROM outbound_tls_log \
                       WHERE report_date=$1 AND recipient_domain=$2 \
                       GROUP BY mx_host,tls_success,failure_type\
                     ), metrics AS (\
                       SELECT count(*)::bigint AS total_records,\
                              COALESCE(SUM(\
                                octet_length(COALESCE(mx_host,'')) +\
                                octet_length(COALESCE(failure_type,'')) +\
                                octet_length(total_count) +\
                                octet_length(COALESCE(failure_reason,'')) +\
                                octet_length(COALESCE(sts_policy_version,'')) +\
                                octet_length(COALESCE(sts_policy_mode,'')) +\
                                octet_length(COALESCE(sts_mx_patterns,'')) +\
                                octet_length(COALESCE(sts_max_age::text,'')) +\
                                octet_length(COALESCE(target_ip,''))\
                              ),0)::bigint AS total_bytes \
                       FROM aggregated\
                     ) \
                     SELECT metrics.total_records,metrics.total_bytes,\
                            aggregated.mx_host,aggregated.tls_success,\
                            aggregated.failure_type,aggregated.total_count,\
                            aggregated.failure_reason,aggregated.sts_policy_version,\
                            aggregated.sts_policy_mode,aggregated.sts_mx_patterns,\
                            aggregated.sts_max_age,aggregated.target_ip,\
                            aggregated.mta_sts_enforced \
                     FROM metrics LEFT JOIN aggregated \
                       ON metrics.total_records <= $3 AND metrics.total_bytes <= $4",
                    &[
                        &report_date,
                        &domain,
                        &MAX_AGGREGATE_RECORDS,
                        &MAX_AGGREGATE_INPUT_BYTES,
                    ],
                )
                .await
                .map_err(database_error)?;
            decode_tls_rows(rows)
        })
        .await;
        connection.finish(outcome)
    }

    async fn render_dmarc(
        &self,
        domain: &str,
        report_date: NaiveDate,
        our_domain: &str,
        rows: Vec<DmarcAggregateRow>,
        cancellation: &CancellationToken,
    ) -> Result<GeneratedReport, ReportingError> {
        let input = DmarcRenderInput {
            domain: domain.to_owned(),
            report_date,
            our_domain: our_domain.to_owned(),
            organization_name: self
                .config
                .organization_name
                .clone()
                .unwrap_or_else(|| "lmyzmail".into()),
            organization_email: self
                .config
                .organization_email
                .clone()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| self.config.dmarc_report_sender_address.clone())
                .unwrap_or_else(|| "postmaster@unknown".into()),
            rows,
        };
        self.run_render(cancellation, move |cancelled| {
            render_dmarc_report(input, cancelled)
        })
        .await
    }

    async fn render_tls(
        &self,
        domain: &str,
        report_date: NaiveDate,
        our_domain: &str,
        rows: Vec<TlsAggregateRow>,
        cancellation: &CancellationToken,
    ) -> Result<GeneratedReport, ReportingError> {
        let input = TlsRenderInput {
            domain: domain.to_owned(),
            report_date,
            our_domain: our_domain.to_owned(),
            organization_name: self
                .config
                .organization_name
                .clone()
                .unwrap_or_else(|| "lmyzmail".into()),
            organization_email: self
                .config
                .organization_email
                .clone()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| self.config.tls_report_sender_address.clone())
                .unwrap_or_else(|| "postmaster@unknown".into()),
            rows,
        };
        self.run_render(cancellation, move |cancelled| {
            render_tls_report(input, cancelled)
        })
        .await
    }

    async fn run_render<T, F>(
        &self,
        cancellation: &CancellationToken,
        render: F,
    ) -> Result<T, ReportingError>
    where
        T: Send + 'static,
        F: FnOnce(&AtomicBool) -> Result<T, ReportingError> + Send + 'static,
    {
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let mut receiver = self
            .render_pool
            .submit(move || render(&worker_cancelled))
            .map_err(|error| match error {
                SubmitError::Full => ReportingError::ResourceLimit,
                SubmitError::Closed => ReportingError::Render,
            })?;
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                cancelled.store(true, Ordering::Release);
                let _ = timeout(REPORT_RENDER_DRAIN_TIMEOUT, &mut receiver).await;
                Err(ReportingError::Cancelled)
            }
            result = timeout(REPORT_RENDER_DEADLINE, &mut receiver) => match result {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(ReportingError::Render),
                Err(_) => {
                    cancelled.store(true, Ordering::Release);
                    let _ = timeout(REPORT_RENDER_DRAIN_TIMEOUT, &mut receiver).await;
                    Err(ReportingError::Timeout)
                }
            }
        }
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
enum ReportKind {
    Dmarc,
    Tls,
}

struct DmarcRenderInput {
    domain: String,
    report_date: NaiveDate,
    our_domain: String,
    organization_name: String,
    organization_email: String,
    rows: Vec<DmarcAggregateRow>,
}

struct TlsRenderInput {
    domain: String,
    report_date: NaiveDate,
    our_domain: String,
    organization_name: String,
    organization_email: String,
    rows: Vec<TlsAggregateRow>,
}

fn decode_dmarc_rows(
    rows: Vec<tokio_postgres::Row>,
) -> Result<Vec<DmarcAggregateRow>, ReportingError> {
    let (total, bytes) = aggregate_metrics(&rows)?;
    if total > MAX_AGGREGATE_RECORDS || bytes > MAX_AGGREGATE_INPUT_BYTES {
        return Err(ReportingError::ResourceLimit);
    }
    if total == 0 {
        return Ok(Vec::new());
    }
    if usize::try_from(total).ok() != Some(rows.len()) {
        return Err(ReportingError::Database(
            "bounded DMARC aggregate cardinality changed".into(),
        ));
    }
    let mut decoded = Vec::with_capacity(rows.len());
    let mut input_bytes = 0_usize;
    for row in rows {
        verify_metrics(&row, total, bytes)?;
        decoded.push(DmarcAggregateRow {
            source_ip: bounded_field(&row, 2, &mut input_bytes)?,
            spf_result: bounded_field(&row, 3, &mut input_bytes)?,
            dkim_result: bounded_field(&row, 4, &mut input_bytes)?,
            disposition: bounded_field(&row, 5, &mut input_bytes)?,
            count: bounded_count(&row, 6)?,
            dkim_domain: bounded_field(&row, 7, &mut input_bytes)?,
            dkim_selector: bounded_field(&row, 8, &mut input_bytes)?,
            spf_domain: bounded_field(&row, 9, &mut input_bytes)?,
            envelope_from_domain: bounded_field(&row, 10, &mut input_bytes)?,
            dmarc_policy: bounded_field(&row, 11, &mut input_bytes)?,
        });
    }
    if input_bytes > MAX_AGGREGATE_INPUT_BYTES as usize {
        return Err(ReportingError::ResourceLimit);
    }
    Ok(decoded)
}

fn decode_tls_rows(rows: Vec<tokio_postgres::Row>) -> Result<Vec<TlsAggregateRow>, ReportingError> {
    let (total, bytes) = aggregate_metrics(&rows)?;
    if total > MAX_AGGREGATE_RECORDS || bytes > MAX_AGGREGATE_INPUT_BYTES {
        return Err(ReportingError::ResourceLimit);
    }
    if total == 0 {
        return Ok(Vec::new());
    }
    if usize::try_from(total).ok() != Some(rows.len()) {
        return Err(ReportingError::Database(
            "bounded TLS aggregate cardinality changed".into(),
        ));
    }
    let mut decoded = Vec::with_capacity(rows.len());
    let mut input_bytes = 0_usize;
    for row in rows {
        verify_metrics(&row, total, bytes)?;
        decoded.push(TlsAggregateRow {
            mx_host: bounded_field(&row, 2, &mut input_bytes)?,
            tls_success: row
                .try_get::<_, Option<bool>>(3)
                .map_err(database_error)?
                .unwrap_or(false),
            failure_type: bounded_field(&row, 4, &mut input_bytes)?,
            count: bounded_count(&row, 5)?,
            failure_reason: bounded_field(&row, 6, &mut input_bytes)?,
            sts_policy_version: bounded_field(&row, 7, &mut input_bytes)?,
            sts_policy_mode: bounded_field(&row, 8, &mut input_bytes)?,
            sts_mx_patterns: bounded_field(&row, 9, &mut input_bytes)?,
            sts_max_age: row.try_get::<_, Option<i64>>(10).map_err(database_error)?,
            target_ip: bounded_field(&row, 11, &mut input_bytes)?,
            mta_sts_enforced: row
                .try_get::<_, Option<bool>>(12)
                .map_err(database_error)?
                .unwrap_or(false),
        });
    }
    if input_bytes > MAX_AGGREGATE_INPUT_BYTES as usize {
        return Err(ReportingError::ResourceLimit);
    }
    Ok(decoded)
}

fn aggregate_metrics(rows: &[tokio_postgres::Row]) -> Result<(i64, i64), ReportingError> {
    let row = rows.first().ok_or_else(|| {
        ReportingError::Database("aggregate metrics query returned no row".into())
    })?;
    let total = row.try_get::<_, i64>(0).map_err(database_error)?;
    let bytes = row.try_get::<_, i64>(1).map_err(database_error)?;
    if total < 0 || bytes < 0 {
        return Err(ReportingError::Database(
            "aggregate metrics were negative".into(),
        ));
    }
    Ok((total, bytes))
}

fn verify_metrics(
    row: &tokio_postgres::Row,
    expected_total: i64,
    expected_bytes: i64,
) -> Result<(), ReportingError> {
    let total = row.try_get::<_, i64>(0).map_err(database_error)?;
    let bytes = row.try_get::<_, i64>(1).map_err(database_error)?;
    if total != expected_total || bytes != expected_bytes {
        return Err(ReportingError::Database(
            "aggregate metrics changed within one result".into(),
        ));
    }
    Ok(())
}

fn bounded_field(
    row: &tokio_postgres::Row,
    index: usize,
    input_bytes: &mut usize,
) -> Result<Option<String>, ReportingError> {
    let value = row
        .try_get::<_, Option<String>>(index)
        .map_err(database_error)?;
    if let Some(value) = value.as_deref() {
        if value.len() > MAX_AGGREGATE_FIELD_BYTES {
            return Err(ReportingError::ResourceLimit);
        }
        *input_bytes = input_bytes
            .checked_add(value.len())
            .ok_or(ReportingError::ResourceLimit)?;
    }
    Ok(value)
}

fn bounded_count(row: &tokio_postgres::Row, index: usize) -> Result<i32, ReportingError> {
    let value = row
        .try_get::<_, Option<String>>(index)
        .map_err(database_error)?
        .ok_or_else(|| ReportingError::Database("aggregate count was null".into()))?;
    let value = value
        .parse::<i64>()
        .map_err(|_| ReportingError::ResourceLimit)?;
    i32::try_from(value).map_err(|_| ReportingError::ResourceLimit)
}

fn safe_outbound_error(error: &OutboundError) -> String {
    error.to_string()
}

fn render_dmarc_report(
    input: DmarcRenderInput,
    cancelled: &AtomicBool,
) -> Result<GeneratedReport, ReportingError> {
    validate_render_identity(&input.domain, &input.our_domain)?;
    let report_id = new_uuid_v4()?;
    let begin = input
        .report_date
        .and_hms_opt(0, 0, 0)
        .ok_or(ReportingError::Render)?
        .and_utc()
        .timestamp();
    let end = input
        .report_date
        .checked_add_days(Days::new(1))
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .ok_or(ReportingError::Render)?
        .and_utc()
        .timestamp()
        .checked_sub(1)
        .ok_or(ReportingError::Render)?;
    let policy = input
        .rows
        .first()
        .and_then(|row| row.dmarc_policy.as_deref())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("none");
    let record_count = input.rows.len();
    let mut output = GzipReportWriter::new();
    output.text("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")?;
    output.text("<feedback xmlns=\"urn:ietf:params:xml:ns:dmarc-xml-report-1.0\">\n")?;
    output.text("  <report_metadata>\n")?;
    output.xml_element("    ", "org_name", Some(&input.organization_name))?;
    output.xml_element("    ", "email", Some(&input.organization_email))?;
    output.xml_element("    ", "report_id", Some(&report_id))?;
    output.text("    <date_range>\n")?;
    output.text(&format!("      <begin>{begin}</begin>\n"))?;
    output.text(&format!("      <end>{end}</end>\n"))?;
    output.text("    </date_range>\n")?;
    output.text("  </report_metadata>\n")?;
    output.text("  <policy_published>\n")?;
    output.xml_element("    ", "domain", Some(&input.domain))?;
    output.text("    <adkim>r</adkim>\n")?;
    output.text("    <aspf>r</aspf>\n")?;
    output.xml_element("    ", "p", Some(policy))?;
    output.xml_element("    ", "sp", Some(policy))?;
    output.text("    <pct>100</pct>\n")?;
    output.text("  </policy_published>\n")?;
    for row in &input.rows {
        check_render_cancelled(cancelled)?;
        let dkim_evaluated = match row.dkim_result.as_deref() {
            Some(value) if value.eq_ignore_ascii_case("pass") => "pass",
            Some(_) => "fail",
            None => "none",
        };
        let spf_evaluated = match row.spf_result.as_deref() {
            Some(value) if value.eq_ignore_ascii_case("pass") => "pass",
            Some(_) => "fail",
            None => "none",
        };
        output.text("  <record>\n")?;
        output.text("    <row>\n")?;
        output.xml_element("      ", "source_ip", row.source_ip.as_deref())?;
        output.text(&format!("      <count>{}</count>\n", row.count))?;
        output.text("      <policy_evaluated>\n")?;
        output.xml_element(
            "        ",
            "disposition",
            Some(row.disposition.as_deref().unwrap_or("none")),
        )?;
        output.xml_element("        ", "dkim", Some(dkim_evaluated))?;
        output.xml_element("        ", "spf", Some(spf_evaluated))?;
        output.text("      </policy_evaluated>\n")?;
        output.text("    </row>\n")?;
        output.text("    <identifiers>\n")?;
        output.xml_element("      ", "header_from", Some(&input.domain))?;
        if row.envelope_from_domain.is_some() {
            output.xml_element(
                "      ",
                "envelope_from",
                row.envelope_from_domain.as_deref(),
            )?;
        }
        output.text("    </identifiers>\n")?;
        output.text("    <auth_results>\n")?;
        if let Some(dkim_result) = row
            .dkim_result
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            let dkim_domain = row
                .dkim_domain
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(&input.domain);
            output.text("      <dkim>\n")?;
            output.xml_element("        ", "domain", Some(dkim_domain))?;
            if row.dkim_selector.is_some() {
                output.xml_element("        ", "selector", row.dkim_selector.as_deref())?;
            }
            output.xml_element("        ", "result", Some(dkim_result))?;
            output.text("      </dkim>\n")?;
        }
        if let Some(spf_result) = row
            .spf_result
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            let spf_domain = row
                .spf_domain
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    row.envelope_from_domain
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                })
                .unwrap_or(&input.domain);
            output.text("      <spf>\n")?;
            output.xml_element("        ", "domain", Some(spf_domain))?;
            output.xml_element("        ", "result", Some(spf_result))?;
            output.text("      </spf>\n")?;
        }
        output.text("    </auth_results>\n")?;
        output.text("  </record>\n")?;
    }
    output.text("</feedback>\n")?;
    let compressed = output.finish()?;
    Ok(GeneratedReport {
        report_id,
        filename: format!(
            "{}!{}!{}!{}.xml.gz",
            input.our_domain, input.domain, begin, end
        ),
        compressed,
        content_type: "application/gzip",
        success_count: 0,
        failure_count: 0,
        record_count,
    })
}

fn render_tls_report(
    input: TlsRenderInput,
    cancelled: &AtomicBool,
) -> Result<GeneratedReport, ReportingError> {
    validate_render_identity(&input.domain, &input.our_domain)?;
    let report_id = new_uuid_v4()?;
    let start = format!("{}T00:00:00Z", input.report_date);
    let end = format!("{}T23:59:59Z", input.report_date);
    let mut success_count = 0_i32;
    let mut failure_count = 0_i32;
    let mut groups: Vec<(String, Vec<TlsAggregateRow>)> = Vec::new();
    for row in input.rows {
        check_render_cancelled(cancelled)?;
        if row.tls_success {
            success_count = success_count
                .checked_add(row.count)
                .ok_or(ReportingError::ResourceLimit)?;
        } else {
            failure_count = failure_count
                .checked_add(row.count)
                .ok_or(ReportingError::ResourceLimit)?;
        }
        let policy_type = tls_policy_type(&row).to_owned();
        if let Some((_, rows)) = groups
            .iter_mut()
            .find(|(existing, _)| existing == &policy_type)
        {
            rows.push(row);
        } else {
            groups.push((policy_type, vec![row]));
        }
    }
    let mut output = GzipReportWriter::new();
    output.text("{\n  \"organization-name\" : ")?;
    output.json_string(&input.organization_name)?;
    output.text(",\n  \"date-range\" : {\n    \"start-datetime\" : ")?;
    output.json_string(&start)?;
    output.text(",\n    \"end-datetime\" : ")?;
    output.json_string(&end)?;
    output.text("\n  },\n  \"contact-info\" : ")?;
    output.json_string(&input.organization_email)?;
    output.text(",\n  \"report-id\" : ")?;
    output.json_string(&report_id)?;
    output.text(",\n  \"policies\" : [ ")?;
    for (group_index, (policy_type, rows)) in groups.iter().enumerate() {
        check_render_cancelled(cancelled)?;
        if group_index > 0 {
            output.text(", ")?;
        }
        render_tls_policy(&mut output, &input.domain, policy_type, rows)?;
    }
    output.text(" ]\n}")?;
    let compressed = output.finish()?;
    let basic_date = input.report_date.format("%Y%m%d").to_string();
    let record_count = groups.iter().map(|(_, rows)| rows.len()).sum();
    Ok(GeneratedReport {
        report_id,
        filename: format!(
            "{}!{}!{}!{}.json.gz",
            input.our_domain, input.domain, basic_date, basic_date
        ),
        compressed,
        content_type: "application/tlsrpt+gzip",
        success_count,
        failure_count,
        record_count,
    })
}

fn render_tls_policy(
    output: &mut GzipReportWriter,
    domain: &str,
    policy_type: &str,
    rows: &[TlsAggregateRow],
) -> Result<(), ReportingError> {
    let mut success = 0_i32;
    let mut failure = 0_i32;
    let mut mx_hosts = Vec::<&str>::new();
    for row in rows {
        if row.tls_success {
            success = success
                .checked_add(row.count)
                .ok_or(ReportingError::ResourceLimit)?;
        } else {
            failure = failure
                .checked_add(row.count)
                .ok_or(ReportingError::ResourceLimit)?;
        }
        if let Some(mx) = row
            .mx_host
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            && !mx_hosts.contains(&mx)
        {
            mx_hosts.push(mx);
        }
    }
    let policy_strings = tls_policy_strings(rows);
    output.text("{\n    \"policy\" : {\n      \"policy-type\" : ")?;
    output.json_string(policy_type)?;
    if !policy_strings.is_empty() {
        output.text(",\n      \"policy-string\" : ")?;
        output.json_string_array(&policy_strings)?;
    }
    output.text(",\n      \"policy-domain\" : ")?;
    output.json_string(domain)?;
    if !mx_hosts.is_empty() {
        output.text(",\n      \"mx-host\" : ")?;
        output.json_string_array(&mx_hosts)?;
    }
    output.text("\n    },\n    \"summary\" : {\n")?;
    output.text(&format!(
        "      \"total-successful-session-count\" : {success},\n"
    ))?;
    output.text(&format!(
        "      \"total-failure-session-count\" : {failure}\n"
    ))?;
    output.text("    }")?;
    let failures = rows
        .iter()
        .filter(|row| !row.tls_success)
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        output.text(",\n    \"failure-details\" : [ ")?;
        for (index, row) in failures.iter().enumerate() {
            if index > 0 {
                output.text(", ")?;
            }
            render_tls_failure(output, row)?;
        }
        output.text(" ]")?;
    }
    output.text("\n  }")
}

fn render_tls_failure(
    output: &mut GzipReportWriter,
    row: &TlsAggregateRow,
) -> Result<(), ReportingError> {
    output.text("{\n      \"result-type\" : ")?;
    output.json_string(map_failure_type(row.failure_type.as_deref()))?;
    if let Some(value) = row.mx_host.as_deref() {
        output.text(",\n      \"receiving-mx-hostname\" : ")?;
        output.json_string(value)?;
    }
    if let Some(value) = row.target_ip.as_deref() {
        output.text(",\n      \"receiving-ip\" : ")?;
        output.json_string(value)?;
    }
    output.text(&format!(
        ",\n      \"failed-session-count\" : {}",
        row.count
    ))?;
    if let Some(value) = row.failure_reason.as_deref() {
        output.text(",\n      \"additional-information\" : ")?;
        output.json_string(value)?;
    }
    output.text("\n    }")
}

fn tls_policy_type(row: &TlsAggregateRow) -> &'static str {
    if row
        .sts_policy_version
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || row.mta_sts_enforced
        || row.sts_policy_mode.as_deref().is_some_and(|value| {
            value.eq_ignore_ascii_case("enforce") || value.eq_ignore_ascii_case("testing")
        })
    {
        "sts"
    } else {
        "no-policy-found"
    }
}

fn tls_policy_strings(rows: &[TlsAggregateRow]) -> Vec<String> {
    let Some(sample) = rows.iter().find(|row| {
        row.sts_policy_version
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    }) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    if let Some(value) = sample.sts_policy_version.as_deref() {
        values.push(format!("version: {value}"));
    }
    if let Some(value) = sample.sts_policy_mode.as_deref() {
        values.push(format!("mode: {value}"));
    }
    if let Some(patterns) = sample.sts_mx_patterns.as_deref() {
        values.extend(
            patterns
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| format!("mx: {value}")),
        );
    }
    if let Some(value) = sample.sts_max_age.filter(|value| *value > 0) {
        values.push(format!("max_age: {value}"));
    }
    values
}

fn map_failure_type(value: Option<&str>) -> &'static str {
    match value.map(str::to_ascii_lowercase).as_deref() {
        Some("starttls_not_supported" | "starttls-not-supported") => "starttls-not-supported",
        Some("certificate_expired" | "certificate-expired") => "certificate-expired",
        Some("certificate_not_trusted" | "certificate-not-trusted") => "certificate-not-trusted",
        Some("certificate_host_mismatch" | "certificate-host-mismatch") => {
            "certificate-host-mismatch"
        }
        Some("handshake_failure" | "handshake-failure") => "handshake-failure",
        Some("connection_refused" | "connection-refused")
        | Some("connection_timeout" | "connection-timeout") => "connection-failure",
        Some("mta_sts_policy_invalid" | "sts-policy-invalid") => "sts-policy-invalid",
        Some("mta_sts_policy_fetch_error" | "sts-policy-fetch-error") => "sts-policy-fetch-error",
        Some("mta_sts_webpki_invalid" | "sts-webpki-invalid") => "sts-webpki-invalid",
        _ => "validation-failure",
    }
}

fn validate_render_identity(domain: &str, our_domain: &str) -> Result<(), ReportingError> {
    for value in [domain, our_domain] {
        if value.is_empty()
            || value.len() > MAX_AGGREGATE_FIELD_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ReportingError::ResourceLimit);
        }
    }
    Ok(())
}

fn check_render_cancelled(cancelled: &AtomicBool) -> Result<(), ReportingError> {
    if cancelled.load(Ordering::Acquire) {
        Err(ReportingError::Cancelled)
    } else {
        Ok(())
    }
}

fn new_uuid_v4() -> Result<String, ReportingError> {
    let mut bytes = [0_u8; 16];
    fill_random(&mut bytes).map_err(|_| ReportingError::Render)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
}

struct BoundedVec {
    bytes: Vec<u8>,
}

impl Write for BoundedVec {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("report output limit exceeded"))?;
        if length > MAX_REPORT_BYTES {
            return Err(io::Error::other("report output limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct GzipReportWriter {
    encoder: GzEncoder<BoundedVec>,
    uncompressed_bytes: usize,
}

impl GzipReportWriter {
    fn new() -> Self {
        Self {
            encoder: GzEncoder::new(
                BoundedVec {
                    bytes: Vec::with_capacity(16 * 1024),
                },
                Compression::default(),
            ),
            uncompressed_bytes: 0,
        }
    }

    fn text(&mut self, value: &str) -> Result<(), ReportingError> {
        self.uncompressed_bytes = self
            .uncompressed_bytes
            .checked_add(value.len())
            .ok_or(ReportingError::ResourceLimit)?;
        if self.uncompressed_bytes > MAX_REPORT_BYTES {
            return Err(ReportingError::ResourceLimit);
        }
        self.encoder
            .write_all(value.as_bytes())
            .map_err(|_| ReportingError::ResourceLimit)
    }

    fn xml_element(
        &mut self,
        indentation: &str,
        name: &str,
        value: Option<&str>,
    ) -> Result<(), ReportingError> {
        self.text(indentation)?;
        self.text("<")?;
        self.text(name)?;
        self.text(">")?;
        self.xml_text(value.unwrap_or_default())?;
        self.text("</")?;
        self.text(name)?;
        self.text(">\n")
    }

    fn xml_text(&mut self, value: &str) -> Result<(), ReportingError> {
        for character in value.chars() {
            match character {
                '&' => self.text("&amp;")?,
                '<' => self.text("&lt;")?,
                '>' => self.text("&gt;")?,
                '"' => self.text("&quot;")?,
                '\'' => self.text("&apos;")?,
                character => {
                    let mut buffer = [0_u8; 4];
                    self.text(character.encode_utf8(&mut buffer))?;
                }
            }
        }
        Ok(())
    }

    fn json_string(&mut self, value: &str) -> Result<(), ReportingError> {
        let value = serde_json::to_string(value).map_err(|_| ReportingError::Render)?;
        self.text(&value)
    }

    fn json_string_array<T: AsRef<str>>(&mut self, values: &[T]) -> Result<(), ReportingError> {
        self.text("[ ")?;
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                self.text(", ")?;
            }
            self.json_string(value.as_ref())?;
        }
        self.text(" ]")
    }

    fn finish(self) -> Result<Vec<u8>, ReportingError> {
        self.encoder
            .finish()
            .map(|output| output.bytes)
            .map_err(|_| ReportingError::ResourceLimit)
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
    use std::io::Read as _;

    use flate2::read::GzDecoder;

    use super::*;

    const SEEDED_REPORT_GOLDEN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../blackbox/golden/java/managed-reports-v12/observations/http/reports/seeded-delivery.json"
    ));

    fn report_date() -> NaiveDate {
        NaiveDate::from_ymd_opt(2024, 1, 1).expect("fixture date is valid")
    }

    fn gunzip(bytes: &[u8]) -> String {
        let mut decoder = GzDecoder::new(bytes);
        let mut output = String::new();
        decoder
            .read_to_string(&mut output)
            .expect("generated report is valid UTF-8 gzip");
        output
    }

    fn seeded_attachment(kind: &str) -> serde_json::Value {
        let golden: serde_json::Value =
            serde_json::from_str(SEEDED_REPORT_GOLDEN).expect("v12 report golden is valid JSON");
        golden["observation"]["maildir"]["messages"][kind]["attachment"].clone()
    }

    fn normalize_report_id(text: String, report_id: &str) -> String {
        assert_eq!(
            text.matches(report_id).count(),
            1,
            "generated report ID must appear exactly once"
        );
        text.replace(report_id, "<report-id>")
    }

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

    #[test]
    fn seeded_dmarc_render_matches_the_frozen_java_golden() {
        let report = render_dmarc_report(
            DmarcRenderInput {
                domain: "sender.example".into(),
                report_date: report_date(),
                our_domain: "example.test".into(),
                organization_name: "Blackbox Reports".into(),
                organization_email: "reports@example.test".into(),
                rows: vec![DmarcAggregateRow {
                    source_ip: Some("192.0.2.10".into()),
                    spf_result: Some("pass".into()),
                    dkim_result: Some("none".into()),
                    disposition: Some("none".into()),
                    count: 1,
                    dkim_domain: Some("sender.example".into()),
                    dkim_selector: Some("legacy".into()),
                    spf_domain: Some("sender.example".into()),
                    envelope_from_domain: Some("sender.example".into()),
                    dmarc_policy: Some("reject".into()),
                }],
            },
            &AtomicBool::new(false),
        )
        .expect("seeded DMARC report renders");
        let golden = seeded_attachment("dmarc");

        assert_eq!(
            normalize_report_id(gunzip(&report.compressed), &report.report_id),
            golden["decompressedText"].as_str().unwrap()
        );
        assert_eq!(report.filename, golden["filename"].as_str().unwrap());
        assert_eq!(report.content_type, golden["contentType"].as_str().unwrap());
        assert_eq!(report.record_count, 1);
        assert_eq!(report.success_count, 0);
        assert_eq!(report.failure_count, 0);
    }

    #[test]
    fn seeded_tls_render_matches_the_frozen_java_golden() {
        let report = render_tls_report(
            TlsRenderInput {
                domain: "recipient.example".into(),
                report_date: report_date(),
                our_domain: "example.test".into(),
                organization_name: "Blackbox Reports".into(),
                organization_email: "reports@example.test".into(),
                rows: vec![TlsAggregateRow {
                    mx_host: Some("mx.recipient.example".into()),
                    tls_success: true,
                    failure_type: None,
                    count: 1,
                    failure_reason: None,
                    sts_policy_version: Some("STSv1".into()),
                    sts_policy_mode: Some("enforce".into()),
                    sts_mx_patterns: Some("mx.recipient.example".into()),
                    sts_max_age: Some(604_800),
                    target_ip: Some("192.0.2.20".into()),
                    mta_sts_enforced: true,
                }],
            },
            &AtomicBool::new(false),
        )
        .expect("seeded TLS report renders");
        let golden = seeded_attachment("tls");

        assert_eq!(
            normalize_report_id(gunzip(&report.compressed), &report.report_id),
            golden["decompressedText"].as_str().unwrap()
        );
        assert_eq!(report.filename, golden["filename"].as_str().unwrap());
        assert_eq!(report.content_type, golden["contentType"].as_str().unwrap());
        assert_eq!(report.record_count, 1);
        assert_eq!(report.success_count, 1);
        assert_eq!(report.failure_count, 0);
    }

    #[test]
    fn dmarc_xml_writer_escapes_every_xml_metacharacter() {
        let mut output = GzipReportWriter::new();
        output
            .xml_element("", "value", Some("A&B<C>D\"E'F"))
            .expect("bounded XML renders");

        assert_eq!(
            gunzip(&output.finish().expect("gzip finishes")),
            "<value>A&amp;B&lt;C&gt;D&quot;E&apos;F</value>\n"
        );
    }

    #[test]
    fn report_writer_enforces_compressed_and_uncompressed_four_mib_limits() {
        let payload = vec![b'x'; MAX_REPORT_BYTES];
        let mut output = GzipReportWriter::new();
        output
            .text(std::str::from_utf8(&payload).unwrap())
            .expect("exact uncompressed budget is allowed");
        assert_eq!(output.text("x"), Err(ReportingError::ResourceLimit));

        let mut bounded = BoundedVec { bytes: Vec::new() };
        assert!(bounded.write_all(&payload).is_ok());
        assert!(bounded.write_all(b"x").is_err());
    }
}
