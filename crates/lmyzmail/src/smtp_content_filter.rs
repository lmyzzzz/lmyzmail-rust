use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use futures_util::future::join_all;
use hickory_resolver::{TokioResolver, proto::rr::RData};
use mail_parser::{
    MessageParser,
    decoders::{base64::base64_decode, quoted_printable::quoted_printable_decode},
};
use regex::Regex;
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout_at},
};

use crate::config::ContentFilterConfig;

pub(crate) const MAX_HEADER_BYTES: usize = 256 * 1024;
const MAX_HEADER_FIELDS: usize = 4_096;
const MAX_MIME_PARTS: usize = 4_096;
const MAX_MIME_BOUNDARIES: usize = 64;
const MAX_MIME_MESSAGE_DEPTH: usize = 64;
const MAX_MIME_DECODED_WORK_BYTES: usize = 64 * 1024 * 1024;
const MAX_MIME_BOUNDARY_BYTES: usize = 200;
const MAX_MIME_HEADER_BYTES: usize = 64 * 1024;
const MAX_MIME_HEADER_FIELDS: usize = 256;
const MAX_MIME_FIELD_BYTES: usize = 8 * 1024;
const MAX_MIME_FILENAME_BYTES: usize = 1_024;
const KEYWORD_MAX_LINE_UTF16: usize = 8_192;
const URL_MAX_LINE_UTF16: usize = 16_384;
const MAX_TRACKED_URLS: usize = 500;
const NEW_DOMAIN_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const NEW_DOMAIN_MAX_ACTIVE_REQUESTS: usize = 32;
const NEW_DOMAIN_CACHE_ENTRIES: u64 = 8_192;
const RBL_MAX_ACTIVE_REQUESTS: usize = 64;
const RBL_CACHE_ENTRIES: u64 = 8_192;

type RblLookupFuture<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

trait RblLookup: Send + Sync {
    fn is_listed<'a>(&'a self, query: &'a str) -> RblLookupFuture<'a>;
}

#[derive(Clone)]
struct HickoryRblLookup {
    resolver: TokioResolver,
}

impl HickoryRblLookup {
    fn new() -> Result<Self, String> {
        let mut builder = TokioResolver::builder_tokio()
            .map_err(|error| format!("system DNS configuration is unavailable: {error}"))?;
        builder.options_mut().attempts = 1;
        builder.options_mut().cache_size = RBL_CACHE_ENTRIES;
        builder.options_mut().max_active_requests = RBL_MAX_ACTIVE_REQUESTS;
        let resolver = builder
            .build()
            .map_err(|error| format!("system DNS resolver initialization failed: {error}"))?;
        Ok(Self { resolver })
    }
}

impl RblLookup for HickoryRblLookup {
    fn is_listed<'a>(&'a self, query: &'a str) -> RblLookupFuture<'a> {
        Box::pin(async move {
            let ipv4 = self.resolver.ipv4_lookup(query);
            let ipv6 = self.resolver.ipv6_lookup(query);
            tokio::pin!(ipv4, ipv6);
            tokio::select! {
                result = &mut ipv4 => {
                    if result.is_ok_and(|lookup| !lookup.answers().is_empty()) {
                        true
                    } else {
                        ipv6.await.is_ok_and(|lookup| !lookup.answers().is_empty())
                    }
                }
                result = &mut ipv6 => {
                    if result.is_ok_and(|lookup| !lookup.answers().is_empty()) {
                        true
                    } else {
                        ipv4.await.is_ok_and(|lookup| !lookup.answers().is_empty())
                    }
                }
            }
        })
    }
}

#[derive(Clone)]
pub(crate) struct RblScanner {
    backend: Arc<dyn RblLookup>,
    permits: Arc<Semaphore>,
}

impl RblScanner {
    pub(crate) fn new() -> Result<Self, String> {
        Ok(Self::with_backend(
            Arc::new(HickoryRblLookup::new()?),
            RBL_MAX_ACTIVE_REQUESTS,
        ))
    }

    fn with_backend(backend: Arc<dyn RblLookup>, max_active_requests: usize) -> Self {
        assert!(max_active_requests > 0);
        Self {
            backend,
            permits: Arc::new(Semaphore::new(max_active_requests)),
        }
    }

    pub(crate) async fn scan(&self, peer: IpAddr, config: &ContentFilterConfig) -> ContentScan {
        if !config.enabled
            || !config.rbl_check.enabled
            || !config.rbl.enabled
            || config.rbl.servers.is_empty()
            || java_private_ip(peer)
        {
            return ContentScan::default();
        }
        let reversed = reverse_ip(peer);
        let lookups = config.rbl.servers.iter().map(|server| {
            let query = format!("{reversed}.{server}");
            async move {
                let deadline = Instant::now() + config.rbl.timeout;
                let _permit = match timeout_at(deadline, self.permits.acquire()).await {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) | Err(_) => return false,
                };
                timeout_at(deadline, self.backend.is_listed(&query))
                    .await
                    .unwrap_or(false)
            }
        });
        let listed = join_all(lookups)
            .await
            .into_iter()
            .filter(|listed| *listed)
            .count();
        if listed == 0 {
            return ContentScan::default();
        }
        let score = ((listed as f64) * config.rbl.score_per_hit).min(config.rbl.max_score)
            * config.rbl_check.weight;
        ContentScan {
            total_score: score,
            hits: vec![RuleHit {
                name: "RBL_CHECK",
                score,
            }],
        }
    }
}

fn reverse_ip(peer: IpAddr) -> String {
    match peer {
        IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            format!("{d}.{c}.{b}.{a}")
        }
        IpAddr::V6(address) => {
            let mut reversed = String::with_capacity(63);
            for byte in address.octets().iter().rev() {
                if !reversed.is_empty() {
                    reversed.push('.');
                }
                reversed.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap());
                reversed.push('.');
                reversed.push(char::from_digit(u32::from(byte >> 4), 16).unwrap());
            }
            reversed
        }
    }
}

fn java_private_ip(peer: IpAddr) -> bool {
    match peer {
        IpAddr::V4(address) => java_private_ipv4(address),
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or_else(|| java_private_ipv6(address), java_private_ipv4),
    }
}

fn java_private_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    address.is_loopback()
        || address.is_unspecified()
        || (a == 10)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
}

fn java_private_ipv6(address: Ipv6Addr) -> bool {
    let first = address.segments()[0];
    address.is_loopback()
        || address.is_unspecified()
        || first & 0xffc0 == 0xfe80
        || first & 0xffc0 == 0xfec0
}

type SoaLookupFuture<'a> = Pin<Box<dyn Future<Output = Result<Option<u32>, ()>> + Send + 'a>>;

trait SoaLookup: Send + Sync {
    fn lookup_soa<'a>(&'a self, domain: &'a str) -> SoaLookupFuture<'a>;
}

#[derive(Clone)]
struct HickorySoaLookup {
    resolver: TokioResolver,
}

impl HickorySoaLookup {
    fn new() -> Result<Self, String> {
        let mut builder = TokioResolver::builder_tokio()
            .map_err(|error| format!("system DNS configuration is unavailable: {error}"))?;
        builder.options_mut().timeout = NEW_DOMAIN_QUERY_TIMEOUT;
        builder.options_mut().attempts = 1;
        builder.options_mut().cache_size = NEW_DOMAIN_CACHE_ENTRIES;
        builder.options_mut().max_active_requests = NEW_DOMAIN_MAX_ACTIVE_REQUESTS;
        let resolver = builder
            .build()
            .map_err(|error| format!("system DNS resolver initialization failed: {error}"))?;
        Ok(Self { resolver })
    }
}

impl SoaLookup for HickorySoaLookup {
    fn lookup_soa<'a>(&'a self, domain: &'a str) -> SoaLookupFuture<'a> {
        Box::pin(async move {
            match self.resolver.soa_lookup(domain).await {
                Ok(lookup) => Ok(lookup
                    .answers()
                    .iter()
                    .find_map(|record| match &record.data {
                        RData::SOA(soa) => Some(soa.serial),
                        _ => None,
                    })),
                Err(error) if error.is_no_records_found() => Ok(None),
                Err(_) => Err(()),
            }
        })
    }
}

#[derive(Clone)]
pub(crate) struct NewDomainScanner {
    backend: Arc<dyn SoaLookup>,
    permits: Arc<Semaphore>,
    query_timeout: Duration,
}

impl NewDomainScanner {
    pub(crate) fn new() -> Result<Self, String> {
        Ok(Self::with_backend(
            Arc::new(HickorySoaLookup::new()?),
            NEW_DOMAIN_MAX_ACTIVE_REQUESTS,
            NEW_DOMAIN_QUERY_TIMEOUT,
        ))
    }

    fn with_backend(
        backend: Arc<dyn SoaLookup>,
        max_active_requests: usize,
        query_timeout: Duration,
    ) -> Self {
        assert!(max_active_requests > 0);
        assert!(!query_timeout.is_zero());
        Self {
            backend,
            permits: Arc::new(Semaphore::new(max_active_requests)),
            query_timeout,
        }
    }

    pub(crate) async fn scan(
        &self,
        mail_from: Option<&str>,
        headers: &ParsedHeaders,
        config: &ContentFilterConfig,
    ) -> ContentScan {
        if !config.enabled || !config.new_domain.enabled {
            return ContentScan::default();
        }
        let Some(domain) = sender_domain(mail_from, headers) else {
            return ContentScan::default();
        };
        let base_domain = base_domain(&domain);
        let deadline = Instant::now() + self.query_timeout;
        let _permit = match timeout_at(deadline, self.permits.acquire()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) | Err(_) => return new_domain_hit(2.0, config),
        };
        let serial = match timeout_at(deadline, self.backend.lookup_soa(&base_domain)).await {
            Ok(Ok(serial)) => serial,
            Ok(Err(())) | Err(_) => None,
        };
        let score = match serial {
            None => 2.0,
            Some(serial) => match new_domain_score(serial, Utc::now()) {
                Some(score) => score,
                None => return ContentScan::default(),
            },
        };
        new_domain_hit(score, config)
    }
}

fn new_domain_hit(score: f64, config: &ContentFilterConfig) -> ContentScan {
    let score = score * config.new_domain.weight;
    ContentScan {
        total_score: score,
        hits: vec![RuleHit {
            name: "NEW_DOMAIN",
            score,
        }],
    }
}

fn sender_domain(mail_from: Option<&str>, headers: &ParsedHeaders) -> Option<String> {
    mail_from
        .and_then(extract_domain)
        .or_else(|| headers.first_raw("from").and_then(extract_domain))
        .filter(|domain| !domain.trim().is_empty())
}

fn extract_domain(mut address: &str) -> Option<String> {
    if address.contains('<') && address.contains('>') {
        let start = address.find('<')?.saturating_add(1);
        let end = address.find('>')?;
        if start < end {
            address = &address[start..end];
        }
    }
    let at = address.rfind('@')?;
    if at + 1 >= address.len() {
        return None;
    }
    Some(address[at + 1..].to_lowercase().trim().to_owned())
}

fn base_domain(domain: &str) -> String {
    let mut normalized = domain.to_lowercase();
    let trimmed = normalized.trim();
    if trimmed.len() != normalized.len() {
        normalized = trimmed.to_owned();
    }
    if normalized.ends_with('.') {
        normalized.pop();
    }
    let mut labels = normalized.split('.').collect::<Vec<_>>();
    while labels.last() == Some(&"") {
        labels.pop();
    }
    if labels.len() >= 2 {
        format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1])
    } else if let Some(label) = labels.first() {
        (*label).to_owned()
    } else {
        normalized
    }
}

fn new_domain_score(serial: u32, now: DateTime<Utc>) -> Option<f64> {
    let value = serial.to_string();
    if value.len() != 8 && value.len() != 10 {
        return None;
    }
    let year = value[0..4].parse::<i32>().ok()?;
    let month = value[4..6].parse::<u32>().ok()?;
    let day = value[6..8].parse::<u32>().ok()?;
    if year < 2000 || year > now.year().saturating_add(1) {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let days_old = now.date_naive().signed_duration_since(date).num_days();
    match days_old {
        i64::MIN..=-1 | 0..=1 => Some(3.0),
        2..=7 => Some(2.5),
        8..=30 => Some(1.5),
        31..=i64::MAX => None,
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum HeaderParseError {
    TooLarge,
    TooManyFields,
}

impl fmt::Display for HeaderParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(
                formatter,
                "SMTP header section exceeds {MAX_HEADER_BYTES} bytes"
            ),
            Self::TooManyFields => write!(
                formatter,
                "SMTP header section exceeds {MAX_HEADER_FIELDS} fields"
            ),
        }
    }
}

impl std::error::Error for HeaderParseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HeaderField {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedHeaders {
    fields: Vec<HeaderField>,
}

impl ParsedHeaders {
    pub(crate) fn parse(message: &[u8]) -> Result<Self, HeaderParseError> {
        let mut fields = Vec::new();
        let mut current: Option<HeaderField> = None;
        let mut offset = 0_usize;

        while offset < message.len() {
            let remaining = &message[offset..];
            let line_length = remaining
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(remaining.len(), |index| index + 1);
            let end = offset.saturating_add(line_length);
            if end > MAX_HEADER_BYTES {
                return Err(HeaderParseError::TooLarge);
            }
            let line = &message[offset..end];
            let content = line
                .strip_suffix(b"\n")
                .unwrap_or(line)
                .strip_suffix(b"\r")
                .unwrap_or_else(|| line.strip_suffix(b"\n").unwrap_or(line));

            if content.is_empty() {
                push_current(&mut fields, current.take())?;
                return Ok(Self { fields });
            }

            if matches!(line.first(), Some(b' ' | b'\t')) {
                if let Some(field) = current.as_mut() {
                    field.value.push_str(&String::from_utf8_lossy(line));
                }
            } else {
                push_current(&mut fields, current.take())?;
                current = line
                    .iter()
                    .position(|byte| *byte == b':')
                    .and_then(|colon| {
                        (colon > 0).then(|| HeaderField {
                            name: String::from_utf8_lossy(&line[..colon]).into_owned(),
                            value: String::from_utf8_lossy(&line[colon + 1..]).into_owned(),
                        })
                    });
            }

            if end == message.len() {
                break;
            }
            offset = end;
        }

        if message.len() > MAX_HEADER_BYTES {
            return Err(HeaderParseError::TooLarge);
        }
        push_current(&mut fields, current)?;
        Ok(Self { fields })
    }

    pub(crate) fn first_trimmed(&self, wanted: &str) -> Option<String> {
        self.first_raw(wanted).map(|value| value.trim().to_owned())
    }

    pub(crate) fn last_trimmed(&self, wanted: &str) -> Option<String> {
        self.fields
            .iter()
            .rev()
            .find(|field| field.name.eq_ignore_ascii_case(wanted))
            .map(|field| field.value.trim().to_owned())
    }

    fn first_raw(&self, wanted: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(wanted))
            .map(|field| field.value.as_str())
    }

    fn all_raw<'a>(&'a self, wanted: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |field| field.name.eq_ignore_ascii_case(wanted))
            .map(|field| field.value.as_str())
    }

    pub(crate) fn scan(
        &self,
        envelope_recipient_count: usize,
        config: &ContentFilterConfig,
    ) -> ContentScan {
        if !config.enabled {
            return ContentScan::default();
        }

        let mut hits = Vec::with_capacity(3);
        if config.missing_headers.enabled
            && let Some(score) = missing_headers_score(self)
        {
            hits.push(RuleHit {
                name: "MISSING_HEADERS",
                score: score * config.missing_headers.weight,
            });
        }
        if config.subject_encoding_trick.enabled
            && let Some(score) = subject_encoding_trick_score(self)
        {
            hits.push(RuleHit {
                name: "SUBJECT_ENCODING_TRICK",
                score: score * config.subject_encoding_trick.weight,
            });
        }
        if config.excessive_recipients.enabled
            && let Some(score) = excessive_recipient_score(self, envelope_recipient_count)
        {
            hits.push(RuleHit {
                name: "EXCESSIVE_RECIPIENTS",
                score: score * config.excessive_recipients.weight,
            });
        }

        let total_score = hits.iter().map(|hit| hit.score).sum();
        ContentScan { total_score, hits }
    }
}

fn push_current(
    fields: &mut Vec<HeaderField>,
    current: Option<HeaderField>,
) -> Result<(), HeaderParseError> {
    if let Some(field) = current {
        if fields.len() >= MAX_HEADER_FIELDS {
            return Err(HeaderParseError::TooManyFields);
        }
        fields.push(field);
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ContentScan {
    total_score: f64,
    hits: Vec<RuleHit>,
}

impl ContentScan {
    pub(crate) fn total_score(&self) -> f64 {
        self.total_score
    }

    pub(crate) fn is_suspicious(&self, config: &ContentFilterConfig) -> bool {
        self.total_score >= config.suspicious_threshold
    }

    pub(crate) fn hits(&self) -> impl Iterator<Item = (&'static str, f64)> + '_ {
        self.hits.iter().map(|hit| (hit.name, hit.score))
    }

    pub(crate) fn append(&mut self, mut other: Self) {
        self.total_score += other.total_score;
        self.hits.append(&mut other.hits);
    }
}

#[derive(Clone, Debug, PartialEq)]
struct RuleHit {
    name: &'static str,
    score: f64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum AttachmentScanError {
    TooManyParts,
    TooManyBoundaries,
    BoundaryTooLarge,
    InvalidBoundary,
    HeaderTooLarge,
    TooManyHeaderFields,
    HeaderFieldTooLarge,
}

impl fmt::Display for AttachmentScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooManyParts => "MIME attachment scan exceeded the part budget",
            Self::TooManyBoundaries => "MIME attachment scan exceeded the boundary budget",
            Self::BoundaryTooLarge => "MIME attachment boundary exceeded the byte budget",
            Self::InvalidBoundary => "MIME attachment boundary contained invalid bytes",
            Self::HeaderTooLarge => "MIME attachment scan exceeded the header budget",
            Self::TooManyHeaderFields => "MIME attachment scan exceeded the header field budget",
            Self::HeaderFieldTooLarge => "MIME attachment scan exceeded the field budget",
        })
    }
}

impl std::error::Error for AttachmentScanError {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum BodyScanError {
    TooManyParts,
    TooManyBoundaries,
    BoundaryTooLarge,
    InvalidBoundary,
    HeaderTooLarge,
    TooManyHeaderFields,
    HeaderFieldTooLarge,
    TooManyEmbeddedMessages,
    DecodedWorkTooLarge,
}

impl fmt::Display for BodyScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyParts => formatter.write_str("MIME body scan exceeded the part budget"),
            Self::TooManyBoundaries => {
                formatter.write_str("MIME body scan exceeded the boundary budget")
            }
            Self::BoundaryTooLarge => {
                formatter.write_str("MIME body boundary exceeded the byte budget")
            }
            Self::InvalidBoundary => {
                formatter.write_str("MIME body boundary contained invalid bytes")
            }
            Self::HeaderTooLarge => {
                formatter.write_str("MIME body scan exceeded the header budget")
            }
            Self::TooManyHeaderFields => {
                formatter.write_str("MIME body scan exceeded the header field budget")
            }
            Self::HeaderFieldTooLarge => {
                formatter.write_str("MIME body scan exceeded the field budget")
            }
            Self::TooManyEmbeddedMessages => {
                formatter.write_str("MIME body scan exceeded the embedded message depth budget")
            }
            Self::DecodedWorkTooLarge => {
                formatter.write_str("MIME body scan exceeded the decoded work budget")
            }
        }
    }
}

impl std::error::Error for BodyScanError {}

impl From<AttachmentScanError> for BodyScanError {
    fn from(value: AttachmentScanError) -> Self {
        match value {
            AttachmentScanError::TooManyParts => Self::TooManyParts,
            AttachmentScanError::TooManyBoundaries => Self::TooManyBoundaries,
            AttachmentScanError::BoundaryTooLarge => Self::BoundaryTooLarge,
            AttachmentScanError::InvalidBoundary => Self::InvalidBoundary,
            AttachmentScanError::HeaderTooLarge => Self::HeaderTooLarge,
            AttachmentScanError::TooManyHeaderFields => Self::TooManyHeaderFields,
            AttachmentScanError::HeaderFieldTooLarge => Self::HeaderFieldTooLarge,
        }
    }
}

#[derive(Default)]
struct MimeHeaderMetadata {
    mime_type: Option<String>,
    filename: Option<String>,
    boundary: Option<String>,
    transfer_encoding: MimeTransferEncoding,
    attachment_disposition: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum MimeTransferEncoding {
    #[default]
    Identity,
    Base64,
    QuotedPrintable,
}

impl MimeHeaderMetadata {
    fn is_multipart(&self) -> bool {
        self.mime_type
            .as_deref()
            .is_some_and(|value| value.starts_with("multipart/"))
    }

    fn is_embedded_message(&self) -> bool {
        self.mime_type.as_deref() == Some("message/rfc822")
    }

    fn is_multipart_digest(&self) -> bool {
        self.mime_type.as_deref() == Some("multipart/digest")
    }

    fn is_text_body(&self) -> bool {
        self.mime_type
            .as_deref()
            .is_none_or(|value| value.starts_with("text/") || value.contains("html"))
    }
}

#[derive(Default)]
struct AttachmentCounts {
    dangerous: usize,
    double_extension: usize,
    mismatch: usize,
    forbidden: usize,
}

#[derive(Default)]
struct MimeBoundaryStack {
    values: Vec<Vec<u8>>,
    digest_defaults: Vec<bool>,
    indices: HashMap<Vec<u8>, usize>,
}

impl MimeBoundaryStack {
    fn push(
        &mut self,
        boundary: Option<&str>,
        digest_default: bool,
    ) -> Result<(), AttachmentScanError> {
        let Some(boundary) = boundary.filter(|value| !value.is_empty()) else {
            return Ok(());
        };
        if boundary.len() > MAX_MIME_BOUNDARY_BYTES {
            return Err(AttachmentScanError::BoundaryTooLarge);
        }
        if boundary.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(AttachmentScanError::InvalidBoundary);
        }
        if self.values.len() >= MAX_MIME_BOUNDARIES {
            return Err(AttachmentScanError::TooManyBoundaries);
        }
        let value = boundary.as_bytes().to_vec();
        let index = self.values.len();
        self.values.push(value.clone());
        self.digest_defaults.push(digest_default);
        self.indices.insert(value, index);
        Ok(())
    }

    fn child_defaults_to_message(&self, boundary_index: usize) -> bool {
        self.digest_defaults
            .get(boundary_index)
            .copied()
            .unwrap_or(false)
    }

    fn matching(&self, line: &[u8]) -> Option<(usize, bool)> {
        if !line.starts_with(b"--") {
            return None;
        }
        let candidate = trim_mime_lwsp(&line[2..]);
        if let Some(index) = self.indices.get(candidate) {
            return Some((*index, false));
        }
        let boundary = candidate.strip_suffix(b"--")?;
        self.indices.get(boundary).map(|index| (*index, true))
    }

    fn truncate(&mut self, length: usize) {
        self.values.truncate(length);
        self.digest_defaults.truncate(length);
        self.indices.clear();
        for (index, value) in self.values.iter().enumerate() {
            self.indices.insert(value.clone(), index);
        }
    }
}

#[derive(Clone, Copy)]
enum MimeHeaderKind {
    Type,
    Disposition,
    TransferEncoding,
}

pub(crate) fn scan_body(
    message: &[u8],
    config: &ContentFilterConfig,
) -> Result<ContentScan, BodyScanError> {
    if !config.enabled
        || (!config.spam_keywords.enabled && !config.suspicious_url.enabled)
        || (!config.keywords.enabled && !config.url.enabled)
    {
        return Ok(ContentScan::default());
    }
    let mut keywords = KeywordBodyScanner::new(config);
    let mut urls = UrlBodyScanner::new(config);
    let mut budget = BodyScanBudget::default();
    scan_body_message(message, config, &mut keywords, &mut urls, &mut budget, 0)?;
    let mut result = keywords.finish(config);
    result.append(urls.finish(config));
    Ok(result)
}

pub(crate) fn has_first_mime_attachment(message: &[u8]) -> Result<bool, BodyScanError> {
    FirstAttachmentScan::default().scan(&message[..message.len().min(MAX_HEADER_BYTES)])
}

#[derive(Default)]
struct FirstAttachmentScan {
    budget: BodyScanBudget,
    body_part_count: usize,
}

#[derive(Clone, Copy)]
enum AttachmentSource {
    Original,
    Decoded(usize),
}

#[derive(Clone, Copy)]
struct AttachmentFrame {
    source: AttachmentSource,
    start: usize,
    end: usize,
    message_depth: usize,
    boundary_depth: usize,
    digest_default: bool,
    is_body_part: bool,
}

struct MultipartCursor {
    source: AttachmentSource,
    offset: usize,
    part_start: Option<usize>,
    end: usize,
    boundary: Vec<u8>,
    message_depth: usize,
    boundary_depth: usize,
    digest_default: bool,
    finished: bool,
}

enum AttachmentTask {
    Entity(AttachmentFrame),
    Multipart(MultipartCursor),
}

impl FirstAttachmentScan {
    fn scan(&mut self, message: &[u8]) -> Result<bool, BodyScanError> {
        let mut decoded_messages = Vec::<Vec<u8>>::new();
        let mut tasks = vec![AttachmentTask::Entity(AttachmentFrame {
            source: AttachmentSource::Original,
            start: 0,
            end: message.len(),
            message_depth: 0,
            boundary_depth: 0,
            digest_default: false,
            is_body_part: false,
        })];

        while let Some(task) = tasks.pop() {
            let frame = match task {
                AttachmentTask::Entity(frame) => frame,
                AttachmentTask::Multipart(mut cursor) => {
                    let range = {
                        let source = attachment_source(message, &decoded_messages, cursor.source);
                        cursor.next_part(source)
                    };
                    let Some((part_start, part_end)) = range else {
                        continue;
                    };
                    let child = AttachmentFrame {
                        source: cursor.source,
                        start: part_start,
                        end: part_end,
                        message_depth: cursor.message_depth,
                        boundary_depth: cursor.boundary_depth,
                        digest_default: cursor.digest_default,
                        is_body_part: true,
                    };
                    if !cursor.finished {
                        tasks.push(AttachmentTask::Multipart(cursor));
                    }
                    tasks.push(AttachmentTask::Entity(child));
                    continue;
                }
            };

            if frame.is_body_part {
                self.body_part_count = self.body_part_count.saturating_add(1);
                // HeaderOnlyExtractor keeps one global body-part count. Entering a
                // nested multipart therefore marks its first child as an attachment.
                if self.body_part_count > 1 {
                    return Ok(true);
                }
            }
            if frame.message_depth > MAX_MIME_MESSAGE_DEPTH {
                return Err(BodyScanError::TooManyEmbeddedMessages);
            }
            let (body_offset, mut metadata) = {
                let source = attachment_source(message, &decoded_messages, frame.source);
                parse_mime_headers(&source[frame.start..frame.end], 0)?
            };
            if frame.digest_default && metadata.mime_type.is_none() {
                metadata.mime_type = Some("message/rfc822".to_owned());
            }
            self.budget.parts = self.budget.parts.saturating_add(1);
            if self.budget.parts > MAX_MIME_PARTS {
                return Err(BodyScanError::TooManyParts);
            }
            if metadata.attachment_disposition {
                return Ok(true);
            }

            let body_start = frame.start.saturating_add(body_offset).min(frame.end);
            if metadata.is_multipart() {
                let Some(boundary) = metadata.boundary.as_deref() else {
                    continue;
                };
                if frame.boundary_depth >= MAX_MIME_BOUNDARIES {
                    return Err(BodyScanError::TooManyBoundaries);
                }
                let Some(boundary) = validated_attachment_boundary(boundary)? else {
                    continue;
                };
                tasks.push(AttachmentTask::Multipart(MultipartCursor {
                    source: frame.source,
                    offset: body_start,
                    part_start: None,
                    end: frame.end,
                    boundary,
                    message_depth: frame.message_depth,
                    boundary_depth: frame.boundary_depth.saturating_add(1),
                    digest_default: metadata.is_multipart_digest(),
                    finished: false,
                }));
                continue;
            }

            if metadata.is_embedded_message() {
                let next_depth = frame.message_depth.saturating_add(1);
                match metadata.transfer_encoding {
                    MimeTransferEncoding::Identity => {
                        tasks.push(AttachmentTask::Entity(AttachmentFrame {
                            start: body_start,
                            message_depth: next_depth,
                            digest_default: false,
                            is_body_part: false,
                            ..frame
                        }));
                    }
                    MimeTransferEncoding::Base64 | MimeTransferEncoding::QuotedPrintable => {
                        let decoded = {
                            let source =
                                attachment_source(message, &decoded_messages, frame.source);
                            let encoded = &source[body_start..frame.end];
                            match metadata.transfer_encoding {
                                MimeTransferEncoding::Base64 => base64_decode(encoded),
                                MimeTransferEncoding::QuotedPrintable => {
                                    quoted_printable_decode(encoded)
                                }
                                MimeTransferEncoding::Identity => unreachable!(),
                            }
                        };
                        let Some(decoded) = decoded else {
                            continue;
                        };
                        self.account_decoded_work(decoded.len())?;
                        let decoded_index = decoded_messages.len();
                        let decoded_len = decoded.len();
                        decoded_messages.push(decoded);
                        tasks.push(AttachmentTask::Entity(AttachmentFrame {
                            source: AttachmentSource::Decoded(decoded_index),
                            start: 0,
                            end: decoded_len,
                            message_depth: next_depth,
                            boundary_depth: frame.boundary_depth,
                            digest_default: false,
                            is_body_part: false,
                        }));
                    }
                }
                continue;
            }

            let mime_type = metadata.mime_type.as_deref().unwrap_or("text/plain");
            return Ok(!mime_type.starts_with("text/plain")
                && !mime_type.starts_with("text/html")
                && !mime_type.starts_with("multipart/"));
        }
        Ok(false)
    }

    fn account_decoded_work(&mut self, decoded_bytes: usize) -> Result<(), BodyScanError> {
        self.budget.decoded_work_bytes = self
            .budget
            .decoded_work_bytes
            .checked_add(decoded_bytes)
            .ok_or(BodyScanError::DecodedWorkTooLarge)?;
        if self.budget.decoded_work_bytes > MAX_MIME_DECODED_WORK_BYTES {
            return Err(BodyScanError::DecodedWorkTooLarge);
        }
        Ok(())
    }
}

impl MultipartCursor {
    fn next_part(&mut self, message: &[u8]) -> Option<(usize, usize)> {
        if self.finished {
            return None;
        }
        let end = self.end.min(message.len());
        let mut offset = self.offset.min(end);
        while let Some((line, next_offset)) = next_mime_line(&message[..end], offset) {
            let line_offset = offset;
            offset = next_offset;
            let Some(closing) = matching_mime_boundary(line, &self.boundary) else {
                continue;
            };
            let Some(start) = self.part_start else {
                if closing {
                    self.finished = true;
                    return None;
                }
                self.part_start = Some(next_offset);
                continue;
            };
            let part_end = trim_boundary_separator(message, start, line_offset);
            self.offset = next_offset;
            if closing {
                self.part_start = None;
                self.finished = true;
            } else {
                self.part_start = Some(next_offset);
            }
            return Some((start, part_end));
        }
        self.finished = true;
        self.part_start.take().map(|start| (start, end))
    }
}

fn validated_attachment_boundary(boundary: &str) -> Result<Option<Vec<u8>>, BodyScanError> {
    if boundary.is_empty() {
        return Ok(None);
    }
    if boundary.len() > MAX_MIME_BOUNDARY_BYTES {
        return Err(BodyScanError::BoundaryTooLarge);
    }
    if boundary.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(BodyScanError::InvalidBoundary);
    }
    Ok(Some(boundary.as_bytes().to_vec()))
}

fn matching_mime_boundary(line: &[u8], boundary: &[u8]) -> Option<bool> {
    if !line.starts_with(b"--") {
        return None;
    }
    let candidate = trim_mime_lwsp(&line[2..]);
    if candidate == boundary {
        return Some(false);
    }
    candidate
        .strip_suffix(b"--")
        .is_some_and(|value| value == boundary)
        .then_some(true)
}

fn attachment_source<'a>(
    original: &'a [u8],
    decoded_messages: &'a [Vec<u8>],
    source: AttachmentSource,
) -> &'a [u8] {
    match source {
        AttachmentSource::Original => original,
        AttachmentSource::Decoded(index) => decoded_messages[index].as_slice(),
    }
}

#[derive(Default)]
struct BodyScanBudget {
    parts: usize,
    decoded_work_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ActiveBody {
    #[default]
    None,
    Text(usize),
    EncodedMessage {
        start: usize,
        encoding: MimeTransferEncoding,
    },
}

fn scan_body_message(
    message: &[u8],
    config: &ContentFilterConfig,
    keywords: &mut KeywordBodyScanner,
    urls: &mut UrlBodyScanner,
    budget: &mut BodyScanBudget,
    message_depth: usize,
) -> Result<(), BodyScanError> {
    if message_depth > MAX_MIME_MESSAGE_DEPTH {
        return Err(BodyScanError::TooManyEmbeddedMessages);
    }
    let mut boundaries = MimeBoundaryStack::default();
    let (body_offset, metadata) = parse_mime_headers(message, 0)?;
    let mut active = ActiveBody::None;
    let mut offset = enter_body_entity(
        message,
        body_offset,
        metadata,
        &mut boundaries,
        budget,
        &mut active,
    )?;

    while let Some((line, next_offset)) = next_mime_line(message, offset) {
        let line_offset = offset;
        offset = next_offset;
        let Some((boundary_index, closing)) = boundaries.matching(line) else {
            continue;
        };
        finish_active_body(
            std::mem::take(&mut active),
            message,
            line_offset,
            true,
            config,
            keywords,
            urls,
            budget,
            message_depth,
        )?;
        if closing {
            boundaries.truncate(boundary_index);
            continue;
        }
        let child_defaults_to_message = boundaries.child_defaults_to_message(boundary_index);
        boundaries.truncate(boundary_index.saturating_add(1));
        let (body_offset, mut metadata) = parse_mime_headers(message, offset)?;
        if child_defaults_to_message && metadata.mime_type.is_none() {
            metadata.mime_type = Some("message/rfc822".to_owned());
        }
        offset = enter_body_entity(
            message,
            body_offset,
            metadata,
            &mut boundaries,
            budget,
            &mut active,
        )?;
    }
    finish_active_body(
        active,
        message,
        message.len(),
        false,
        config,
        keywords,
        urls,
        budget,
        message_depth,
    )
}

fn enter_body_entity(
    message: &[u8],
    mut body_offset: usize,
    mut metadata: MimeHeaderMetadata,
    boundaries: &mut MimeBoundaryStack,
    budget: &mut BodyScanBudget,
    active: &mut ActiveBody,
) -> Result<usize, BodyScanError> {
    loop {
        budget.parts = budget.parts.saturating_add(1);
        if budget.parts > MAX_MIME_PARTS {
            return Err(BodyScanError::TooManyParts);
        }
        if metadata.is_multipart() {
            if metadata.boundary.is_some() {
                boundaries.push(metadata.boundary.as_deref(), metadata.is_multipart_digest())?;
            }
            return Ok(body_offset);
        }
        if metadata.is_embedded_message() {
            if metadata.transfer_encoding != MimeTransferEncoding::Identity {
                *active = ActiveBody::EncodedMessage {
                    start: body_offset,
                    encoding: metadata.transfer_encoding,
                };
                return Ok(body_offset);
            }
            (body_offset, metadata) = parse_mime_headers(message, body_offset)?;
            continue;
        }
        if metadata.is_text_body() {
            *active = ActiveBody::Text(body_offset);
        }
        return Ok(body_offset);
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_active_body(
    active: ActiveBody,
    message: &[u8],
    end: usize,
    before_boundary: bool,
    config: &ContentFilterConfig,
    keywords: &mut KeywordBodyScanner,
    urls: &mut UrlBodyScanner,
    budget: &mut BodyScanBudget,
    message_depth: usize,
) -> Result<(), BodyScanError> {
    let start = match active {
        ActiveBody::None => return Ok(()),
        ActiveBody::Text(start) | ActiveBody::EncodedMessage { start, .. } => start,
    };
    let end = if before_boundary {
        trim_boundary_separator(message, start, end)
    } else {
        end
    };
    match active {
        ActiveBody::None => Ok(()),
        ActiveBody::Text(start) => {
            scan_body_text_part(message, start, end, config, keywords, urls);
            Ok(())
        }
        ActiveBody::EncodedMessage { start, encoding } => {
            let encoded = &message[start.min(end)..end];
            let decoded = match encoding {
                MimeTransferEncoding::Identity => return Ok(()),
                MimeTransferEncoding::Base64 => base64_decode(encoded),
                MimeTransferEncoding::QuotedPrintable => quoted_printable_decode(encoded),
            };
            let Some(decoded) = decoded else {
                return Ok(());
            };
            budget.decoded_work_bytes = budget
                .decoded_work_bytes
                .checked_add(decoded.len())
                .ok_or(BodyScanError::DecodedWorkTooLarge)?;
            if budget.decoded_work_bytes > MAX_MIME_DECODED_WORK_BYTES {
                return Err(BodyScanError::DecodedWorkTooLarge);
            }
            scan_body_message(
                &decoded,
                config,
                keywords,
                urls,
                budget,
                message_depth.saturating_add(1),
            )
        }
    }
}

fn trim_boundary_separator(message: &[u8], start: usize, mut end: usize) -> usize {
    if end >= start.saturating_add(2) && &message[end - 2..end] == b"\r\n" {
        end -= 2;
    } else if end > start && message[end - 1] == b'\n' {
        end -= 1;
    }
    end
}

fn scan_body_text_part(
    message: &[u8],
    start: usize,
    end: usize,
    config: &ContentFilterConfig,
    keywords: &mut KeywordBodyScanner,
    urls: &mut UrlBodyScanner,
) {
    let mut offset = start.min(end);
    while offset < end {
        // Mime4j's token stream exposes body data through a 4096-byte parser
        // buffer, then the configured observer buffer applies a second cap.
        let parser_chunk = 4_096 - (offset % 4_096);
        let length = parser_chunk
            .min(config.stream_buffer_size)
            .min(end - offset);
        let text = String::from_utf8_lossy(&message[offset..offset + length]);
        if config.spam_keywords.enabled && config.keywords.enabled {
            keywords.scan_chunk(&text);
        }
        if config.suspicious_url.enabled && config.url.enabled {
            urls.scan_chunk(&text);
        }
        offset += length;
    }
    if config.spam_keywords.enabled && config.keywords.enabled {
        keywords.finish_part();
    }
    if config.suspicious_url.enabled && config.url.enabled {
        urls.finish_part();
    }
}

struct KeywordBodyScanner {
    spam_keywords: HashSet<String>,
    phishing_keywords: HashSet<String>,
    line: Vec<u16>,
    total_chars: u64,
    spam_hits: u64,
    phishing_hits: u64,
}

impl KeywordBodyScanner {
    fn new(config: &ContentFilterConfig) -> Self {
        Self {
            spam_keywords: config
                .keywords
                .spam_keywords
                .iter()
                .map(|value| value.to_lowercase())
                .collect(),
            phishing_keywords: config
                .keywords
                .phishing_keywords
                .iter()
                .map(|value| value.to_lowercase())
                .collect(),
            line: Vec::with_capacity(KEYWORD_MAX_LINE_UTF16),
            total_chars: 0,
            spam_hits: 0,
            phishing_hits: 0,
        }
    }

    fn scan_chunk(&mut self, text: &str) {
        for value in text.encode_utf16() {
            self.total_chars = self.total_chars.saturating_add(1);
            if value == u16::from(b'\r') || value == u16::from(b'\n') {
                self.scan_line();
            } else if self.line.len() < KEYWORD_MAX_LINE_UTF16 {
                self.line.push(value);
            }
        }
    }

    fn finish_part(&mut self) {
        self.scan_line();
    }

    fn scan_line(&mut self) {
        if self.line.is_empty() {
            return;
        }
        let line = String::from_utf16_lossy(&self.line).to_lowercase();
        self.line.clear();
        self.spam_hits = self.spam_hits.saturating_add(
            self.spam_keywords
                .iter()
                .filter(|keyword| line.contains(keyword.as_str()))
                .count() as u64,
        );
        self.phishing_hits = self.phishing_hits.saturating_add(
            self.phishing_keywords
                .iter()
                .filter(|keyword| line.contains(keyword.as_str()))
                .count() as u64,
        );
    }

    fn finish(mut self, config: &ContentFilterConfig) -> ContentScan {
        self.scan_line();
        let total_hits = self.spam_hits.saturating_add(self.phishing_hits);
        if total_hits == 0 {
            return ContentScan::default();
        }
        let keyword = &config.keywords;
        let density = if self.total_chars == 0 {
            0.0
        } else {
            (total_hits as f64) / (self.total_chars as f64 / 100.0)
        };
        let mut score = ((self.spam_hits as f64) * 0.5).min(keyword.base_score);
        score += (self.phishing_hits as f64).min(keyword.base_score * 1.5);
        if density > keyword.density_threshold {
            score += (density - keyword.density_threshold) * 10.0;
        }
        score = score.min(keyword.max_score);
        if score < 0.5 {
            return ContentScan::default();
        }
        score *= config.spam_keywords.weight;
        ContentScan {
            total_score: score,
            hits: vec![RuleHit {
                name: "SPAM_KEYWORDS",
                score,
            }],
        }
    }
}

struct UrlBodyScanner {
    shorteners: HashSet<String>,
    suspicious_tlds: HashSet<String>,
    line: Vec<u16>,
    found_urls: HashSet<String>,
    shortener_count: usize,
    suspicious_tld_count: usize,
    ip_url_count: usize,
}

impl UrlBodyScanner {
    fn new(config: &ContentFilterConfig) -> Self {
        Self {
            shorteners: config
                .url
                .shortener_domains
                .iter()
                .map(|value| value.to_lowercase())
                .collect(),
            suspicious_tlds: config
                .url
                .suspicious_tlds
                .iter()
                .map(|value| value.to_lowercase())
                .collect(),
            line: Vec::with_capacity(URL_MAX_LINE_UTF16),
            found_urls: HashSet::with_capacity(MAX_TRACKED_URLS),
            shortener_count: 0,
            suspicious_tld_count: 0,
            ip_url_count: 0,
        }
    }

    fn scan_chunk(&mut self, text: &str) {
        for value in text.encode_utf16() {
            if value == u16::from(b'\r') || value == u16::from(b'\n') {
                self.scan_line();
            } else if self.line.len() < URL_MAX_LINE_UTF16 {
                self.line.push(value);
            }
        }
    }

    fn finish_part(&mut self) {
        self.scan_line();
    }

    fn scan_line(&mut self) {
        if self.line.is_empty() || self.found_urls.len() >= MAX_TRACKED_URLS {
            self.line.clear();
            return;
        }
        let line = String::from_utf16_lossy(&self.line);
        self.line.clear();
        for matched in body_url_pattern().find_iter(&line) {
            if self.found_urls.len() >= MAX_TRACKED_URLS {
                break;
            }
            let url = matched.as_str();
            if !self.found_urls.insert(url.to_owned()) {
                continue;
            }
            if body_ip_url_pattern().is_match(url) {
                self.ip_url_count = self.ip_url_count.saturating_add(1);
                continue;
            }
            let Some(domain) = body_domain_pattern()
                .captures(url)
                .and_then(|captures| captures.get(1))
                .map(|matched| matched.as_str().to_lowercase())
            else {
                continue;
            };
            if self.shorteners.iter().any(|shortener| {
                domain == *shortener
                    || domain
                        .strip_suffix(shortener)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }) {
                self.shortener_count = self.shortener_count.saturating_add(1);
                continue;
            }
            if let Some((_, tld)) = domain.rsplit_once('.')
                && !tld.is_empty()
                && self.suspicious_tlds.contains(tld)
            {
                self.suspicious_tld_count = self.suspicious_tld_count.saturating_add(1);
            }
        }
    }

    fn finish(mut self, config: &ContentFilterConfig) -> ContentScan {
        self.scan_line();
        if self.shortener_count == 0 && self.suspicious_tld_count == 0 && self.ip_url_count == 0 {
            return ContentScan::default();
        }
        let url = &config.url;
        let category_cap = url.max_score / 2.0;
        let mut score = ((self.shortener_count as f64) * url.shortener_score).min(category_cap);
        score += ((self.suspicious_tld_count as f64) * url.suspicious_tld_score).min(category_cap);
        score += ((self.ip_url_count as f64) * url.ip_url_score).min(category_cap);
        score = score.min(url.max_score);
        if score < 0.5 {
            return ContentScan::default();
        }
        score *= config.suspicious_url.weight;
        ContentScan {
            total_score: score,
            hits: vec![RuleHit {
                name: "SUSPICIOUS_URL",
                score,
            }],
        }
    }
}

fn body_url_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r#"(?i)https?://[^ \t\n\x0b\x0c\r<>"'\)\]]+"#).expect("body URL regex is valid")
    })
}

fn body_domain_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN
        .get_or_init(|| Regex::new(r"(?i)https?://([^/:]+)").expect("body domain regex is valid"))
}

fn body_ip_url_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"(?i)https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
            .expect("body IP URL regex is valid")
    })
}

pub(crate) fn scan_attachments(
    message: &[u8],
    config: &ContentFilterConfig,
) -> Result<ContentScan, AttachmentScanError> {
    if !config.enabled || !config.attachment.enabled {
        return Ok(ContentScan::default());
    }

    let mut counts = AttachmentCounts::default();
    let mut boundaries = MimeBoundaryStack::default();
    let mut parts = 0_usize;

    let (root_body_offset, root) = parse_mime_headers(message, 0)?;
    let mut offset = inspect_mime_entity(
        message,
        root_body_offset,
        root,
        config,
        &mut boundaries,
        &mut parts,
        &mut counts,
    )?;

    while let Some((line, next_offset)) = next_mime_line(message, offset) {
        offset = next_offset;
        let Some((boundary_index, closing)) = boundaries.matching(line) else {
            continue;
        };
        if closing {
            boundaries.truncate(boundary_index);
            continue;
        }
        let child_defaults_to_message = boundaries.child_defaults_to_message(boundary_index);
        boundaries.truncate(boundary_index.saturating_add(1));

        parts = parts.saturating_add(1);
        if parts > MAX_MIME_PARTS {
            return Err(AttachmentScanError::TooManyParts);
        }
        let (body_offset, mut metadata) = parse_mime_headers(message, offset)?;
        if child_defaults_to_message && metadata.mime_type.is_none() {
            metadata.mime_type = Some("message/rfc822".to_owned());
        }
        offset = inspect_mime_entity(
            message,
            body_offset,
            metadata,
            config,
            &mut boundaries,
            &mut parts,
            &mut counts,
        )?;
    }

    Ok(finish_attachment_scan(
        config,
        counts.dangerous,
        counts.double_extension,
        counts.mismatch,
        counts.forbidden,
    ))
}

fn inspect_mime_entity(
    message: &[u8],
    mut body_offset: usize,
    mut metadata: MimeHeaderMetadata,
    config: &ContentFilterConfig,
    boundaries: &mut MimeBoundaryStack,
    parts: &mut usize,
    counts: &mut AttachmentCounts,
) -> Result<usize, AttachmentScanError> {
    loop {
        inspect_mime_part(&metadata, config, counts);
        if metadata.is_multipart() {
            boundaries.push(metadata.boundary.as_deref(), metadata.is_multipart_digest())?;
            return Ok(body_offset);
        }
        if !metadata.is_embedded_message() {
            return Ok(body_offset);
        }

        *parts = parts.saturating_add(1);
        if *parts > MAX_MIME_PARTS {
            return Err(AttachmentScanError::TooManyParts);
        }
        (body_offset, metadata) = parse_mime_headers(message, body_offset)?;
    }
}

fn parse_mime_headers(
    message: &[u8],
    mut offset: usize,
) -> Result<(usize, MimeHeaderMetadata), AttachmentScanError> {
    let mut metadata = MimeHeaderMetadata::default();
    let mut current_kind = None;
    let mut current_value = Vec::new();
    let mut header_bytes = 0_usize;
    let mut field_count = 0_usize;

    while let Some((line, next_offset)) = next_mime_line(message, offset) {
        offset = next_offset;
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > MAX_MIME_HEADER_BYTES {
            return Err(AttachmentScanError::HeaderTooLarge);
        }
        if line.is_empty() {
            finish_mime_header(&mut metadata, current_kind, &current_value);
            return Ok((offset, metadata));
        }
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            if current_kind.is_some() {
                let continuation = line.iter().skip_while(|byte| matches!(byte, b' ' | b'\t'));
                current_value.push(b' ');
                current_value.extend(continuation);
                if current_value.len() > MAX_MIME_FIELD_BYTES {
                    return Err(AttachmentScanError::HeaderFieldTooLarge);
                }
            }
            continue;
        }
        finish_mime_header(&mut metadata, current_kind, &current_value);
        current_kind = None;
        current_value.clear();
        field_count = field_count.saturating_add(1);
        if field_count > MAX_MIME_HEADER_FIELDS {
            return Err(AttachmentScanError::TooManyHeaderFields);
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        current_kind = if line[..colon].eq_ignore_ascii_case(b"content-type") {
            Some(MimeHeaderKind::Type)
        } else if line[..colon].eq_ignore_ascii_case(b"content-disposition") {
            Some(MimeHeaderKind::Disposition)
        } else if line[..colon].eq_ignore_ascii_case(b"content-transfer-encoding") {
            Some(MimeHeaderKind::TransferEncoding)
        } else {
            None
        };
        if current_kind.is_some() {
            current_value.extend(line[colon + 1..].iter().copied());
            if current_value.len() > MAX_MIME_FIELD_BYTES {
                return Err(AttachmentScanError::HeaderFieldTooLarge);
            }
        }
    }

    finish_mime_header(&mut metadata, current_kind, &current_value);
    Ok((offset, metadata))
}

fn finish_mime_header(
    metadata: &mut MimeHeaderMetadata,
    kind: Option<MimeHeaderKind>,
    value: &[u8],
) {
    let Some(kind) = kind else {
        return;
    };
    let value = String::from_utf8_lossy(value);
    match kind {
        MimeHeaderKind::Type => {
            let mime_type = value
                .split(';')
                .next()
                .map(str::trim)
                .map(str::to_ascii_lowercase);
            metadata.mime_type = mime_type;
            if metadata.filename.is_none()
                && let Some(name) = extract_mime_parameter(&value, "name")
            {
                metadata.filename = decode_filename(name);
            }
            if let Some(boundary) = extract_mime_parameter(&value, "boundary") {
                metadata.boundary = Some(boundary.to_owned());
            }
        }
        MimeHeaderKind::Disposition => {
            let lower = value.to_ascii_lowercase();
            metadata.attachment_disposition =
                lower.contains("attachment") || lower.contains("inline");
            if let Some(filename) = extract_mime_parameter(&value, "filename") {
                metadata.filename = decode_filename(filename);
            }
        }
        MimeHeaderKind::TransferEncoding => {
            metadata.transfer_encoding = match value.trim().to_ascii_lowercase().as_str() {
                "base64" => MimeTransferEncoding::Base64,
                "quoted-printable" => MimeTransferEncoding::QuotedPrintable,
                _ => MimeTransferEncoding::Identity,
            };
        }
    }
}

fn next_mime_line(message: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    if offset >= message.len() {
        return None;
    }
    let relative_end = message[offset..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|index| index + 1)
        .unwrap_or(message.len() - offset);
    let next_offset = offset.saturating_add(relative_end);
    let mut line = &message[offset..next_offset];
    if line.last() == Some(&b'\n') {
        line = &line[..line.len() - 1];
    }
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    Some((line, next_offset))
}

fn extract_mime_parameter<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    let lower = header.to_ascii_lowercase();
    let plain = format!("{}=", name.to_ascii_lowercase());
    let encoded = format!("{}*=", name.to_ascii_lowercase());
    let (index, marker) = lower
        .find(&plain)
        .map(|index| (index, plain.len()))
        .or_else(|| lower.find(&encoded).map(|index| (index, encoded.len())))?;
    let start = index.saturating_add(marker);
    if start >= header.len() {
        return None;
    }
    if header.as_bytes()[start] == b'"' {
        let end = header[start + 1..].find('"')? + start + 1;
        return Some(&header[start + 1..end]);
    }
    let end = header[start..]
        .find(';')
        .map(|relative| start + relative)
        .unwrap_or(header.len());
    Some(header[start..end].trim())
}

fn decode_filename(value: &str) -> Option<String> {
    if value.len() > MAX_MIME_FILENAME_BYTES {
        return None;
    }
    let mut decoded = value.to_owned();
    if let Some(separator) = decoded.find("''") {
        let encoded = &decoded[separator + 2..];
        let mut bytes = Vec::with_capacity(encoded.len());
        let mut index = 0_usize;
        while index < encoded.len() {
            let byte = encoded.as_bytes()[index];
            if byte == b'+' {
                bytes.push(b' ');
                index += 1;
            } else if byte == b'%' {
                if index + 2 >= encoded.len()
                    || !encoded.as_bytes()[index + 1].is_ascii_hexdigit()
                    || !encoded.as_bytes()[index + 2].is_ascii_hexdigit()
                {
                    return Some(decoded);
                }
                bytes.push(
                    (hex_value(encoded.as_bytes()[index + 1]) << 4)
                        | hex_value(encoded.as_bytes()[index + 2]),
                );
                index += 3;
            } else {
                bytes.push(byte);
                index += 1;
            }
        }
        decoded = String::from_utf8_lossy(&bytes).into_owned();
        if decoded.len() > MAX_MIME_FILENAME_BYTES {
            return None;
        }
    }
    if decoded.contains("=?") && decoded.contains("?=") {
        let sanitized = decoded.replace(['\r', '\n'], " ");
        let synthetic = format!("Subject: {sanitized}\r\n\r\n");
        if let Some(subject) = MessageParser::default()
            .parse_headers(synthetic.as_bytes())
            .and_then(|message| message.subject().map(str::to_owned))
        {
            decoded = subject;
        }
    }
    Some(decoded)
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn trim_mime_lwsp(mut value: &[u8]) -> &[u8] {
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn inspect_mime_part(
    metadata: &MimeHeaderMetadata,
    config: &ContentFilterConfig,
    counts: &mut AttachmentCounts,
) {
    let Some(filename) = metadata
        .filename
        .as_deref()
        .filter(|value| !java_is_blank(value))
    else {
        return;
    };
    let extension = attachment_extension(filename);
    let dangerous = extension.is_some_and(|value| {
        config
            .attachment
            .dangerous_extensions
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(value))
    });
    if dangerous {
        counts.dangerous = counts.dangerous.saturating_add(1);
    }
    if has_dangerous_double_extension(filename, &config.attachment.dangerous_extensions) {
        counts.double_extension = counts.double_extension.saturating_add(1);
    }

    let mime_type = metadata.mime_type.as_deref().unwrap_or("text/plain");
    let Some(extension) = extension.map(str::to_ascii_lowercase) else {
        return;
    };
    if forbidden_mime_extensions(mime_type).contains(&extension.as_str()) {
        counts.mismatch = counts.mismatch.saturating_add(1);
        counts.forbidden = counts.forbidden.saturating_add(1);
    } else if let Some(expected) = expected_mime_extensions(mime_type)
        && !expected.contains(&extension.as_str())
        && dangerous
    {
        counts.mismatch = counts.mismatch.saturating_add(1);
    }
}

fn finish_attachment_scan(
    config: &ContentFilterConfig,
    dangerous_count: usize,
    double_extension_count: usize,
    mismatch_count: usize,
    forbidden_count: usize,
) -> ContentScan {
    let mut hits = Vec::with_capacity(3);
    if config.dangerous_extension.enabled && dangerous_count > 0 {
        let score = config.attachment.dangerous_extension_score
            + dangerous_count.saturating_sub(1) as f64 * 0.5;
        hits.push(RuleHit {
            name: "DANGEROUS_EXTENSION",
            score: score * config.dangerous_extension.weight,
        });
    }
    if config.double_extension.enabled && double_extension_count > 0 {
        let score = config.attachment.double_extension_score
            + double_extension_count.saturating_sub(1) as f64 * 0.5;
        hits.push(RuleHit {
            name: "DOUBLE_EXTENSION",
            score: score * config.double_extension.weight,
        });
    }
    if config.mime_type_mismatch.enabled && mismatch_count > 0 {
        let score = config.attachment.mime_type_mismatch_score + forbidden_count as f64 * 1.5;
        hits.push(RuleHit {
            name: "MIME_TYPE_MISMATCH",
            score: score * config.mime_type_mismatch.weight,
        });
    }
    let total_score = hits.iter().map(|hit| hit.score).sum();
    ContentScan { total_score, hits }
}

fn attachment_extension(filename: &str) -> Option<&str> {
    let last_dot = filename.rfind('.')?;
    (last_dot > 0 && last_dot + 1 < filename.len()).then(|| &filename[last_dot + 1..])
}

fn has_dangerous_double_extension(filename: &str, dangerous_extensions: &[String]) -> bool {
    let extensions = filename
        .split('.')
        .skip(1)
        .map(str::to_lowercase)
        .filter(|extension| (2..=5).contains(&extension.encode_utf16().count()))
        .collect::<Vec<_>>();
    if extensions.len() < 2 {
        return false;
    }
    let last = &extensions[extensions.len() - 1];
    dangerous_extensions
        .iter()
        .any(|configured| configured.eq_ignore_ascii_case(last))
}

fn forbidden_mime_extensions(mime_type: &str) -> &'static [&'static str] {
    match mime_type {
        "application/pdf" => &["exe", "bat", "cmd", "scr", "vbs", "js"],
        "image/jpeg" | "image/png" => &["exe", "bat", "cmd", "scr", "vbs", "js", "html"],
        "text/plain" => &["exe", "scr", "dll"],
        _ => &[],
    }
}

fn expected_mime_extensions(mime_type: &str) -> Option<&'static [&'static str]> {
    match mime_type {
        "application/pdf" => Some(&["pdf"]),
        "application/msword" => Some(&["doc", "dot"]),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            Some(&["docx"])
        }
        "application/vnd.ms-excel" => Some(&["xls", "xlt"]),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some(&["xlsx"]),
        "application/vnd.ms-powerpoint" => Some(&["ppt", "pps"]),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
            Some(&["pptx"])
        }
        "image/jpeg" => Some(&["jpg", "jpeg"]),
        "image/png" => Some(&["png"]),
        "image/gif" => Some(&["gif"]),
        "image/bmp" => Some(&["bmp"]),
        "image/webp" => Some(&["webp"]),
        "application/zip" => Some(&["zip"]),
        "application/x-rar-compressed" => Some(&["rar"]),
        "application/x-7z-compressed" => Some(&["7z"]),
        "application/gzip" => Some(&["gz", "gzip"]),
        "audio/mpeg" => Some(&["mp3"]),
        "video/mp4" => Some(&["mp4"]),
        "video/x-msvideo" => Some(&["avi"]),
        "application/x-msdownload" => Some(&["exe", "dll"]),
        "application/x-executable" => Some(&["exe"]),
        "application/x-msdos-program" => Some(&["exe", "com", "bat"]),
        _ => None,
    }
}

fn missing_headers_score(headers: &ParsedHeaders) -> Option<f64> {
    let checks = [
        ("From", 2.0_f64, true),
        ("Date", 1.5_f64, true),
        ("Message-ID", 1.0_f64, false),
        ("Subject", 0.5_f64, false),
    ];
    let mut score = 0.0;
    for (name, value, required) in checks {
        match headers.first_raw(name) {
            None => score += value,
            Some(raw) if java_is_blank(raw) => score += value,
            Some(raw) if required && malformed_required_header(name, raw) => {
                score += value * 0.5;
            }
            Some(_) => {}
        }
    }
    (score > 0.0).then_some(score)
}

fn malformed_required_header(name: &str, value: &str) -> bool {
    match name {
        "From" => !value.contains('@'),
        "Date" => value.encode_utf16().count() < 10,
        _ => false,
    }
}

fn subject_encoding_trick_score(headers: &ParsedHeaders) -> Option<f64> {
    let subject = headers.first_raw("Subject")?;
    if java_is_blank(subject) {
        return None;
    }

    let encoded_word = encoded_word_regex();
    let mut score = 0.0_f64;
    let mut charsets = HashSet::new();
    let mut encoded_words = Vec::new();
    let mut unnecessary_ascii = false;
    for captures in encoded_word.captures_iter(subject) {
        let charset = normalize_charset(&captures[1].to_ascii_lowercase());
        charsets.insert(charset);
        let encoded_text = captures[3].to_owned();
        if !unnecessary_ascii {
            unnecessary_ascii = has_unnecessary_ascii_encoding(&captures[2], &encoded_text);
        }
        encoded_words.push(encoded_text);
    }

    if charsets.len() > 1 {
        score += 1.5 * (charsets.len() - 1) as f64;
    }
    if unnecessary_ascii {
        score += 1.0;
    }

    let invisible_count = subject.chars().filter(|value| is_invisible(*value)).count();
    if invisible_count > 0 {
        score += (invisible_count as f64).min(4.0);
    }
    let homoglyph_count = subject.chars().filter(|value| is_homoglyph(*value)).count();
    if homoglyph_count > 0 {
        score += (homoglyph_count as f64 * 0.8).min(3.0);
    }
    if special_character_ratio(subject) > 0.3 {
        score += 1.5;
    }
    if has_repeating_encoded_words(&encoded_words) {
        score += 2.0;
    }

    (score > 0.0).then_some(score)
}

fn encoded_word_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"=\?([^?]+)\?([BbQq])\?([^?]*)\?=")
            .expect("frozen encoded-word regex must compile")
    })
}

fn q_escape_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX
        .get_or_init(|| Regex::new(r"=[0-9A-Fa-f]{2}").expect("frozen Q escape regex must compile"))
}

fn normalize_charset(value: &str) -> String {
    match value {
        "utf8" => "utf-8".to_owned(),
        "iso8859-1" | "latin1" => "iso-8859-1".to_owned(),
        "windows-1252" | "cp1252" => "windows-1252".to_owned(),
        _ => value.to_owned(),
    }
}

fn has_unnecessary_ascii_encoding(encoding: &str, text: &str) -> bool {
    let decoded = if encoding.eq_ignore_ascii_case("B") {
        let Ok(bytes) = BASE64_STANDARD.decode(text) else {
            return false;
        };
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        q_escape_regex()
            .replace_all(&text.replace('_', " "), "X")
            .into_owned()
    };
    decoded.encode_utf16().count() > 3
        && decoded
            .chars()
            .all(|character| (' '..='~').contains(&character))
}

fn has_repeating_encoded_words(words: &[String]) -> bool {
    let mut seen = HashSet::with_capacity(words.len());
    for word in words {
        if word.encode_utf16().count() > 2 && !seen.insert(word.as_str()) {
            return true;
        }
    }
    words.len() > 5 && words.iter().all(|word| word.encode_utf16().count() < 5)
}

fn special_character_ratio(subject: &str) -> f64 {
    let replaced = encoded_word_regex().replace_all(subject, "$3");
    let decoded = java_trim(replaced.as_ref());
    let units = decoded.encode_utf16().collect::<Vec<_>>();
    if units.is_empty() {
        return 0.0;
    }
    let special = units
        .iter()
        .filter(|unit| !java_letter_or_digit(**unit) && !is_common_punctuation(**unit))
        .count();
    special as f64 / units.len() as f64
}

fn java_letter_or_digit(value: u16) -> bool {
    char::from_u32(u32::from(value)).is_some_and(char::is_alphanumeric)
}

fn is_common_punctuation(value: u16) -> bool {
    value <= 0x7f && b" .,!?:;'-\"()[]{}@#$%&*+=/<>".contains(&(value as u8))
}

fn java_trim(value: &str) -> &str {
    value.trim_matches(|character| character <= '\u{20}')
}

fn java_is_blank(value: &str) -> bool {
    value.chars().all(java_is_whitespace)
}

fn java_is_whitespace(value: char) -> bool {
    matches!(
        value,
        '\u{0009}'..='\u{000d}'
            | '\u{001c}'..='\u{0020}'
            | '\u{1680}'
            | '\u{2000}'..='\u{2006}'
            | '\u{2008}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn is_invisible(value: char) -> bool {
    matches!(
        value,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{17b4}'
            | '\u{17b5}'
            | '\u{180b}'..='\u{180e}'
            | '\u{2000}'..='\u{200f}'
            | '\u{202a}'..='\u{202f}'
            | '\u{2060}'..='\u{2064}'
            | '\u{206a}'..='\u{206f}'
            | '\u{3000}'
            | '\u{feff}'
            | '\u{ffa0}'
    )
}

fn is_homoglyph(value: char) -> bool {
    matches!(
        value,
        '\u{0391}'
            | '\u{0392}'
            | '\u{0395}'
            | '\u{0396}'
            | '\u{0397}'
            | '\u{0399}'
            | '\u{039a}'
            | '\u{039c}'
            | '\u{039d}'
            | '\u{039f}'
            | '\u{03a1}'
            | '\u{03a4}'
            | '\u{03a5}'
            | '\u{03a7}'
            | '\u{0430}'
            | '\u{0435}'
            | '\u{043e}'
            | '\u{0440}'
            | '\u{0441}'
            | '\u{0443}'
            | '\u{0445}'
            | '\u{0500}'
            | '\u{0501}'
    )
}

fn excessive_recipient_score(
    headers: &ParsedHeaders,
    envelope_recipient_count: usize,
) -> Option<f64> {
    let header_count = ["To", "Cc", "Bcc"]
        .into_iter()
        .flat_map(|name| headers.all_raw(name))
        .map(count_addresses)
        .sum::<usize>();
    let total = envelope_recipient_count.max(header_count);
    if total < 20 {
        return None;
    }
    if total >= 50 {
        Some((2.0 + (total - 50) as f64 * 0.05).min(5.0))
    } else {
        Some(1.0 + (total - 20) as f64 * 0.05)
    }
}

fn count_addresses(value: &str) -> usize {
    if java_is_blank(value) {
        return 0;
    }
    let at_count = value.bytes().filter(|byte| *byte == b'@').count();
    if at_count > 0 {
        at_count
    } else {
        let commas = value.bytes().filter(|byte| *byte == b',').count();
        commas.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    };

    use chrono::TimeZone;
    use proptest::prelude::*;

    use super::*;
    use crate::config::{ContentFilterConfig, ContentFilterRuleConfig};

    fn config() -> ContentFilterConfig {
        ContentFilterConfig::default()
    }

    fn parse(message: &[u8]) -> ParsedHeaders {
        ParsedHeaders::parse(message).unwrap()
    }

    #[derive(Clone)]
    enum FakeSoaResponse {
        Ready(Result<Option<u32>, ()>),
        Pending,
    }

    struct FakeSoaLookup {
        response: FakeSoaResponse,
        calls: AtomicUsize,
    }

    impl FakeSoaLookup {
        fn new(response: FakeSoaResponse) -> Arc<Self> {
            Arc::new(Self {
                response,
                calls: AtomicUsize::new(0),
            })
        }
    }

    impl SoaLookup for FakeSoaLookup {
        fn lookup_soa<'a>(&'a self, _domain: &'a str) -> SoaLookupFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let response = self.response.clone();
            Box::pin(async move {
                match response {
                    FakeSoaResponse::Ready(result) => result,
                    FakeSoaResponse::Pending => std::future::pending().await,
                }
            })
        }
    }

    fn scanner(backend: Arc<dyn SoaLookup>) -> NewDomainScanner {
        NewDomainScanner::with_backend(backend, 1, Duration::from_millis(100))
    }

    #[derive(Clone)]
    enum FakeRblResponse {
        Listed(HashSet<String>),
        Pending,
    }

    struct FakeRblLookup {
        response: FakeRblResponse,
        queries: StdMutex<Vec<String>>,
    }

    impl FakeRblLookup {
        fn new(response: FakeRblResponse) -> Arc<Self> {
            Arc::new(Self {
                response,
                queries: StdMutex::new(Vec::new()),
            })
        }
    }

    impl RblLookup for FakeRblLookup {
        fn is_listed<'a>(&'a self, query: &'a str) -> RblLookupFuture<'a> {
            self.queries.lock().unwrap().push(query.to_owned());
            let response = self.response.clone();
            let query = query.to_owned();
            Box::pin(async move {
                match response {
                    FakeRblResponse::Listed(names) => names.contains(&query),
                    FakeRblResponse::Pending => std::future::pending().await,
                }
            })
        }
    }

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 8, 5, 12, 0, 0).unwrap()
    }

    fn attachment_message(parts: &[&str]) -> Vec<u8> {
        let mut message = concat!(
            "From: sender@external.test\r\n",
            "Date: Tue, 5 Aug 2025 12:00:00 GMT\r\n",
            "Subject: attachment unit test\r\n",
            "Message-ID: <attachment-unit@example.test>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=\"attachment-boundary\"\r\n",
            "\r\n",
            "--attachment-boundary\r\n",
            "Content-Type: text/plain; charset=us-ascii\r\n",
            "\r\n",
            "body\r\n",
        )
        .as_bytes()
        .to_vec();
        for part in parts {
            message.extend_from_slice(b"--attachment-boundary\r\n");
            message.extend_from_slice(part.as_bytes());
            message.extend_from_slice(
                b"Content-Transfer-Encoding: base64\r\n\r\nYXR0YWNobWVudAo=\r\n",
            );
        }
        message.extend_from_slice(b"--attachment-boundary--\r\n");
        message
    }

    fn body_message(content_type: &str, body: &str) -> Vec<u8> {
        format!(
            concat!(
                "From: sender@external.test\r\n",
                "Date: Tue, 5 Aug 2025 12:00:00 GMT\r\n",
                "Subject: body unit test\r\n",
                "Message-ID: <body-unit@example.test>\r\n",
                "MIME-Version: 1.0\r\n",
                "Content-Type: {}\r\n",
                "\r\n",
                "{}"
            ),
            content_type, body
        )
        .into_bytes()
    }

    #[test]
    fn rbl_ip_reversal_and_java_private_ranges_are_exact() {
        assert_eq!(reverse_ip("192.0.2.42".parse().unwrap()), "42.2.0.192");
        assert_eq!(
            reverse_ip("::1".parse().unwrap()),
            format!("1.{}", vec!["0"; 31].join("."))
        );
        for address in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "fe80::1",
            "fec0::1",
        ] {
            assert!(java_private_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["192.0.2.42", "172.32.0.1", "fc00::1", "2001:db8::1"] {
            assert!(!java_private_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[tokio::test]
    async fn rbl_parallel_hits_apply_cap_then_rule_weight() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let servers = ["listed-one.test", "absent.test", "listed-two.test"];
        let listed = [
            "9.113.0.203.listed-one.test".to_owned(),
            "9.113.0.203.listed-two.test".to_owned(),
        ]
        .into_iter()
        .collect();
        let backend = FakeRblLookup::new(FakeRblResponse::Listed(listed));
        let scanner = RblScanner::with_backend(backend.clone(), 3);
        let mut settings = config();
        settings.rbl.servers = servers.into_iter().map(str::to_owned).collect();
        settings.rbl.score_per_hit = 3.0;
        settings.rbl.max_score = 5.0;
        settings.rbl_check.weight = 1.5;
        let scan = scanner.scan(peer, &settings).await;
        assert_eq!(scan.hits().collect::<Vec<_>>(), [("RBL_CHECK", 7.5)]);
        assert_eq!(backend.queries.lock().unwrap().len(), 3);
        assert_eq!(scanner.permits.available_permits(), 3);
    }

    #[tokio::test]
    async fn rbl_private_skip_and_timeout_fail_open_without_leaking_permits() {
        let pending = FakeRblLookup::new(FakeRblResponse::Pending);
        let scanner = RblScanner::with_backend(pending.clone(), 1);
        let mut settings = config();
        settings.rbl.servers = vec!["listed.test".into()];
        settings.rbl.timeout = Duration::from_millis(10);
        assert_eq!(
            scanner.scan("127.0.0.1".parse().unwrap(), &settings).await,
            ContentScan::default()
        );
        assert!(pending.queries.lock().unwrap().is_empty());
        assert_eq!(
            scanner
                .scan("203.0.113.9".parse().unwrap(), &settings)
                .await,
            ContentScan::default()
        );
        assert_eq!(pending.queries.lock().unwrap().len(), 1);
        assert_eq!(scanner.permits.available_permits(), 1);
    }

    #[test]
    fn new_domain_extracts_java_sender_and_base_domain_shapes() {
        let headers = parse(b"From: Display <fallback@Sub.Example.COM.>\r\n\r\n");
        assert_eq!(
            sender_domain(Some("primary@Deep.Sub.Example.NET."), &headers),
            Some("deep.sub.example.net.".into())
        );
        assert_eq!(base_domain("deep.sub.example.net."), "example.net");
        assert_eq!(base_domain("a.example.com.."), "example.com");
        assert_eq!(
            sender_domain(Some(""), &headers),
            Some("sub.example.com.".into())
        );
        assert_eq!(base_domain("localhost"), "localhost");
        assert_eq!(
            sender_domain(Some("invalid"), &parse(b"Subject: x\r\n\r\n")),
            None
        );
    }

    #[test]
    fn new_domain_serial_age_bands_match_java() {
        let now = fixed_now();
        for (serial, expected) in [
            (2025080601, Some(3.0)),
            (20250805, Some(3.0)),
            (20250804, Some(3.0)),
            (20250803, Some(2.5)),
            (20250729, Some(2.5)),
            (20250728, Some(1.5)),
            (20250706, Some(1.5)),
            (20250705, None),
            (20251301, None),
            (19991231, None),
            (42, None),
        ] {
            assert_eq!(new_domain_score(serial, now), expected, "serial={serial}");
        }
    }

    #[tokio::test]
    async fn new_domain_absent_soa_and_weight_match_java() {
        let backend = FakeSoaLookup::new(FakeSoaResponse::Ready(Ok(None)));
        let scanner = scanner(backend.clone());
        let headers = parse(b"From: fallback@other.test\r\n\r\n");
        let mut settings = config();
        settings.new_domain.weight = 1.75;
        let scan = scanner
            .scan(Some("sender@sub.external.test"), &headers, &settings)
            .await;
        assert_eq!(scan.hits().collect::<Vec<_>>(), [("NEW_DOMAIN", 3.5)]);
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn new_domain_query_errors_match_java_no_soa_while_disabled_rules_do_not_hit() {
        let backend = FakeSoaLookup::new(FakeSoaResponse::Ready(Err(())));
        let scanner = scanner(backend.clone());
        let headers = parse(b"Subject: no sender\r\n\r\n");
        let failed = scanner
            .scan(Some("sender@external.test"), &headers, &config())
            .await;
        assert_eq!(failed.hits().collect::<Vec<_>>(), [("NEW_DOMAIN", 2.0)]);
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);

        let mut settings = config();
        settings.new_domain.enabled = false;
        assert_eq!(
            scanner
                .scan(Some("sender@external.test"), &headers, &settings)
                .await,
            ContentScan::default()
        );
        assert_eq!(
            scanner.scan(None, &headers, &config()).await,
            ContentScan::default()
        );
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn new_domain_timeout_and_saturation_are_bounded_and_score_no_soa() {
        let backend = FakeSoaLookup::new(FakeSoaResponse::Pending);
        let scanner = scanner(backend.clone());
        let headers = parse(b"From: sender@external.test\r\n\r\n");
        let first_scanner = scanner.clone();
        let first_headers = headers.clone();
        let first = tokio::spawn(async move {
            first_scanner
                .scan(Some("first@external.test"), &first_headers, &config())
                .await
        });
        while backend.calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let second = scanner
            .scan(Some("second@external.test"), &headers, &config())
            .await;
        assert_eq!(second.hits().collect::<Vec<_>>(), [("NEW_DOMAIN", 2.0)]);
        let first = first.await.unwrap();
        assert_eq!(first.hits().collect::<Vec<_>>(), [("NEW_DOMAIN", 2.0)]);
        assert!((1..=2).contains(&backend.calls.load(Ordering::SeqCst)));
        assert_eq!(scanner.permits.available_permits(), 1);
    }

    #[test]
    fn golden_header_rules_and_order_match_java() {
        let clean = parse(
            b"From: sender@external.test\r\nDate: Tue, 5 Aug 2025 12:00:00 GMT\r\nSubject: clean\r\nMessage-ID: <clean@example.test>\r\n\r\nbody",
        );
        assert_eq!(clean.scan(0, &config()), ContentScan::default());

        let missing = parse(b"Subject: missing\r\nMessage-ID: <missing@example.test>\r\n\r\n");
        assert_eq!(
            missing.scan(0, &config()).hits().collect::<Vec<_>>(),
            [("MISSING_HEADERS", 3.5)]
        );

        let malformed = parse(
            b"From: not-an-address\r\nDate: short\r\nSubject: malformed\r\nMessage-ID: <malformed@example.test>\r\n\r\n",
        );
        assert_eq!(
            malformed.scan(0, &config()).hits().collect::<Vec<_>>(),
            [("MISSING_HEADERS", 1.75)]
        );

        let encoded = parse(
            b"From: sender@external.test\r\nDate: Tue, 5 Aug 2025 12:00:00 GMT\r\nSubject: =?UTF-8?Q?FREE?= =?ISO-8859-1?Q?MONEY?=\r\nMessage-ID: <encoded@example.test>\r\n\r\n",
        );
        assert_eq!(
            encoded.scan(0, &config()).hits().collect::<Vec<_>>(),
            [("SUBJECT_ENCODING_TRICK", 2.5)]
        );

        let recipients = (0..50)
            .map(|index| format!("recipient-{index}@example.test"))
            .collect::<Vec<_>>()
            .join(", ");
        let message = format!(
            "From: sender@external.test\r\nDate: Tue, 5 Aug 2025 12:00:00 GMT\r\nSubject: recipients\r\nMessage-ID: <recipients@example.test>\r\nCc: {recipients}\r\n\r\n"
        );
        assert_eq!(
            parse(message.as_bytes())
                .scan(0, &config())
                .hits()
                .collect::<Vec<_>>(),
            [("EXCESSIVE_RECIPIENTS", 2.0)]
        );
    }

    #[test]
    fn parser_preserves_folded_raw_values_and_ignores_body_headers() {
        let headers = parse(
            b"From: sender@example.test\r\nDate: Tue, 5 Aug 2025 12:00:00 GMT\r\nSubject: ordinary\r\nMessage-ID: <fold@example.test>\r\nCc: first@example.test,\r\n second@example.test\r\n\r\nSubject: =?UTF-8?Q?FREE?=\r\n",
        );
        assert_eq!(
            headers.all_raw("Cc").next(),
            Some(" first@example.test,\r\n second@example.test\r\n")
        );
        assert_eq!(headers.scan(0, &config()), ContentScan::default());
    }

    #[test]
    fn configuration_disables_and_weights_rules_without_reordering() {
        let headers = parse(b"Subject: =?UTF-8?Q?FREE?=\r\nCc: a@x,b@y,c@z,d@x,e@y,f@z,g@x,h@y,i@z,j@x,k@y,l@z,m@x,n@y,o@z,p@x,q@y,r@z,s@x,t@y\r\n\r\n");
        let mut settings = config();
        settings.missing_headers.enabled = false;
        settings.subject_encoding_trick.weight = 2.0;
        settings.excessive_recipients = ContentFilterRuleConfig {
            enabled: true,
            weight: 0.5,
        };
        assert_eq!(
            headers.scan(0, &settings).hits().collect::<Vec<_>>(),
            [
                ("SUBJECT_ENCODING_TRICK", 2.0),
                ("EXCESSIVE_RECIPIENTS", 0.5)
            ]
        );
    }

    #[test]
    fn content_filter_body_keyword_density_base_cap_and_weight_match_java() {
        let mut settings = config();
        settings.keywords.density_threshold = 1_000.0;
        settings.spam_keywords.weight = 2.0;
        let message = body_message(
            "text/plain; charset=utf-8",
            "viagra viagra\r\nviagra\r\nverify your account\r\n",
        );
        assert_eq!(
            scan_body(&message, &settings)
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SPAM_KEYWORDS", 4.0)]
        );

        settings.keywords.density_threshold = 0.0;
        let capped = body_message("text/plain; charset=utf-8", "viagra");
        assert_eq!(
            scan_body(&capped, &settings)
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SPAM_KEYWORDS", 16.0)]
        );

        settings.keywords.base_score = 0.0;
        settings.keywords.density_threshold = 1_000.0;
        assert_eq!(
            scan_body(&capped, &settings).unwrap(),
            ContentScan::default()
        );
    }

    #[test]
    fn content_filter_body_url_exact_dedup_categories_caps_and_weight_match_java() {
        let mut settings = config();
        settings.suspicious_url.weight = 1.5;
        let message = body_message(
            "text/plain; charset=us-ascii",
            concat!(
                "https://bit.ly/a https://bit.ly/a\r\n",
                "https://sub.bit.ly/b\r\n",
                "https://bad.xyz/a https://evil.top/b\r\n",
                "http://203.0.113.10/a\r\n"
            ),
        );
        assert_eq!(
            scan_body(&message, &settings)
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SUSPICIOUS_URL", 12.0)]
        );

        settings.url.max_score = 20.0;
        settings.suspicious_url.weight = 1.0;
        let case_sensitive_dedup = body_message(
            "text/plain; charset=us-ascii",
            "https://bit.ly/a HTTPS://bit.ly/a\r\n",
        );
        assert_eq!(
            scan_body(&case_sensitive_dedup, &settings)
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SUSPICIOUS_URL", 3.0)]
        );
    }

    #[test]
    fn content_filter_body_skips_non_text_mime_and_honors_rule_gates() {
        let message = body_message(
            "application/octet-stream",
            "viagra https://bit.ly/offer\r\n",
        );
        assert_eq!(
            scan_body(&message, &config()).unwrap(),
            ContentScan::default()
        );

        let text = body_message(
            "text/plain; charset=us-ascii",
            "viagra https://bit.ly/offer\r\n",
        );
        let mut settings = config();
        settings.keywords.enabled = false;
        settings.url.enabled = false;
        assert_eq!(scan_body(&text, &settings).unwrap(), ContentScan::default());

        settings.keywords.enabled = true;
        settings.spam_keywords.enabled = false;
        settings.url.enabled = true;
        settings.suspicious_url.enabled = true;
        assert_eq!(
            scan_body(&text, &settings)
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SUSPICIOUS_URL", 1.5)]
        );
    }

    #[test]
    fn content_filter_body_scans_nested_rfc822_parts_in_java_order() {
        let nested = concat!(
            "From: sender@external.test\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=outer\r\n",
            "\r\n",
            "--outer\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From: nested@external.test\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=us-ascii\r\n",
            "\r\n",
            "viagra https://bad.xyz/path\r\n",
            "--outer--\r\n"
        );
        assert_eq!(
            scan_body(nested.as_bytes(), &config())
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SPAM_KEYWORDS", 8.0), ("SUSPICIOUS_URL", 2.0)]
        );
    }

    #[test]
    fn content_filter_body_scans_application_xhtml_like_java() {
        let message = body_message(
            "application/xhtml+xml; charset=utf-8",
            "<p>viagra https://bad.xyz/path</p>\r\n",
        );
        assert_eq!(
            scan_body(&message, &config())
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SPAM_KEYWORDS", 8.0), ("SUSPICIOUS_URL", 2.0)]
        );
    }

    #[test]
    fn content_filter_body_scans_raw_cte_and_utf8_bytes_like_java() {
        for message in [
            concat!(
                "Content-Type: text/plain; charset=utf-8\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "dmlhZ3Jh\r\n"
            )
            .as_bytes()
            .to_vec(),
            concat!(
                "Content-Type: text/plain; charset=utf-8\r\n",
                "Content-Transfer-Encoding: quoted-printable\r\n",
                "\r\n",
                "=76iagra\r\n"
            )
            .as_bytes()
            .to_vec(),
        ] {
            assert_eq!(
                scan_body(&message, &config()).unwrap(),
                ContentScan::default()
            );
        }

        let mut settings = config();
        settings.keywords.spam_keywords = vec!["genérico".into()];
        settings.keywords.phishing_keywords.clear();
        settings.suspicious_url.enabled = false;
        let mut latin1 = b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\ngen".to_vec();
        latin1.extend_from_slice(b"\xe9rico\r\n");
        assert_eq!(
            scan_body(&latin1, &settings).unwrap(),
            ContentScan::default()
        );
    }

    #[test]
    fn content_filter_body_recurses_deep_rfc822_but_skips_message_global() {
        let mut nested = Vec::new();
        for _ in 0..5 {
            nested.extend_from_slice(b"Content-Type: message/rfc822\r\n\r\n");
        }
        nested.extend_from_slice(b"Content-Type: text/plain\r\n\r\nviagra\r\n");
        assert_eq!(
            scan_body(&nested, &config())
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SPAM_KEYWORDS", 8.0)]
        );

        let mut encoded_nested = b"Content-Type: text/plain\r\n\r\nviagra\r\n".to_vec();
        for _ in 0..5 {
            encoded_nested = format!(
                "Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
                BASE64_STANDARD.encode(&encoded_nested)
            )
            .into_bytes();
        }
        assert_eq!(
            scan_body(&encoded_nested, &config())
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SPAM_KEYWORDS", 8.0)]
        );

        let encoded_raw_leaf = format!(
            "Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
            BASE64_STANDARD.encode(
                b"Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=76iagra\r\n"
            )
        );
        assert_eq!(
            scan_body(encoded_raw_leaf.as_bytes(), &config()).unwrap(),
            ContentScan::default()
        );

        let global = concat!(
            "Content-Type: message/global\r\n",
            "\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "viagra\r\n"
        );
        assert_eq!(
            scan_body(global.as_bytes(), &config()).unwrap(),
            ContentScan::default()
        );

        let digest = concat!(
            "Content-Type: multipart/digest; boundary=digest\r\n",
            "\r\n",
            "--digest\r\n",
            "\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "viagra\r\n",
            "--digest--\r\n"
        );
        assert_eq!(
            scan_body(digest.as_bytes(), &config())
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SPAM_KEYWORDS", 8.0)]
        );
    }

    #[test]
    fn content_filter_body_matches_java_headerless_and_malformed_multipart_shapes() {
        assert_eq!(
            scan_body(b"viagra\r\n", &config()).unwrap(),
            ContentScan::default()
        );
        for message in [b"\r\nviagra\r\n".as_slice(), b"garbage\r\n\r\nviagra\r\n"] {
            assert_eq!(
                scan_body(message, &config())
                    .unwrap()
                    .hits()
                    .collect::<Vec<_>>(),
                [("SPAM_KEYWORDS", 8.0)]
            );
        }
        for message in [
            b"Content-Type: multipart/mixed\r\n\r\nviagra\r\n".as_slice(),
            b"Content-Type: multipart/mixed; boundary=x\r\n\r\nviagra\r\n",
            b"Content-Type:\r\n\r\nviagra\r\n",
        ] {
            assert_eq!(
                scan_body(message, &config()).unwrap(),
                ContentScan::default()
            );
        }
    }

    #[test]
    fn content_filter_body_matches_mime4j_utf8_parser_chunk_boundaries() {
        let mut settings = config();
        settings.keywords.spam_keywords = vec!["é".into()];
        settings.keywords.phishing_keywords.clear();
        settings.keywords.density_threshold = 1_000.0;
        settings.suspicious_url.enabled = false;

        let prefix = body_message("text/plain; charset=utf-8", "");
        let mut intact = prefix.clone();
        intact.extend(std::iter::repeat_n(b'a', 4_094 - prefix.len()));
        intact.extend_from_slice("é".as_bytes());
        assert_eq!(
            scan_body(&intact, &settings)
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("SPAM_KEYWORDS", 0.5)]
        );

        let mut split = prefix.clone();
        split.extend(std::iter::repeat_n(b'a', 4_095 - prefix.len()));
        split.extend_from_slice("é".as_bytes());
        assert_eq!(
            scan_body(&split, &settings).unwrap(),
            ContentScan::default()
        );
    }

    #[test]
    fn content_filter_body_line_limits_count_java_utf16_code_units() {
        let settings = config();

        let mut accepted_keyword = KeywordBodyScanner::new(&settings);
        accepted_keyword.scan_chunk(&("\u{1f600}".repeat(4_093) + "viagra"));
        assert_eq!(
            accepted_keyword
                .finish(&settings)
                .hits()
                .collect::<Vec<_>>(),
            [("SPAM_KEYWORDS", 0.5)]
        );
        let mut truncated_keyword = KeywordBodyScanner::new(&settings);
        truncated_keyword.scan_chunk(&("\u{1f600}".repeat(4_096) + "viagra"));
        assert_eq!(truncated_keyword.finish(&settings), ContentScan::default());

        let url = "https://bit.ly/x";
        let mut accepted_url = UrlBodyScanner::new(&settings);
        accepted_url.scan_chunk(&("\u{1f600}".repeat((URL_MAX_LINE_UTF16 - url.len()) / 2) + url));
        assert_eq!(
            accepted_url.finish(&settings).hits().collect::<Vec<_>>(),
            [("SUSPICIOUS_URL", 1.5)]
        );
        let mut truncated_url = UrlBodyScanner::new(&settings);
        truncated_url.scan_chunk(&("\u{1f600}".repeat(URL_MAX_LINE_UTF16 / 2) + url));
        assert_eq!(truncated_url.finish(&settings), ContentScan::default());
    }

    #[test]
    fn content_filter_body_url_tracker_stops_at_exactly_five_hundred_unique_urls() {
        let settings = config();
        let clean_urls = |count: usize| {
            (0..count)
                .map(|index| format!("https://clean-{index}.example/path\n"))
                .collect::<String>()
        };

        let mut within_limit = UrlBodyScanner::new(&settings);
        within_limit.scan_chunk(&(clean_urls(MAX_TRACKED_URLS - 1) + "https://bad.xyz/final"));
        assert_eq!(
            within_limit.finish(&settings).hits().collect::<Vec<_>>(),
            [("SUSPICIOUS_URL", 2.0)]
        );

        let mut beyond_limit = UrlBodyScanner::new(&settings);
        beyond_limit.scan_chunk(&(clean_urls(MAX_TRACKED_URLS) + "https://bad.xyz/ignored"));
        assert_eq!(beyond_limit.finish(&settings), ContentScan::default());
    }

    #[test]
    fn content_filter_body_part_budget_is_an_error_not_fail_open() {
        let mut message = String::from(
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=parts\r\n\r\n",
        );
        for _ in 0..=MAX_MIME_PARTS {
            message.push_str(
                "--parts\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nviagra\r\n",
            );
        }
        message.push_str("--parts--\r\n");
        assert_eq!(
            scan_body(message.as_bytes(), &config()),
            Err(BodyScanError::TooManyParts)
        );
    }

    #[test]
    fn content_filter_body_parser_enforces_header_and_boundary_budgets() {
        let oversized_boundary = format!(
            "Content-Type: multipart/mixed; boundary={}\r\n\r\n",
            "x".repeat(MAX_MIME_BOUNDARY_BYTES + 1)
        );
        assert_eq!(
            scan_body(oversized_boundary.as_bytes(), &config()),
            Err(BodyScanError::BoundaryTooLarge)
        );

        let oversized_field = format!(
            "Content-Type: text/plain; x={}\r\n\r\n",
            "x".repeat(MAX_MIME_FIELD_BYTES)
        );
        assert_eq!(
            scan_body(oversized_field.as_bytes(), &config()),
            Err(BodyScanError::HeaderFieldTooLarge)
        );

        let mut too_many_fields = String::new();
        for index in 0..=MAX_MIME_HEADER_FIELDS {
            too_many_fields.push_str(&format!("X-{index}: value\r\n"));
        }
        too_many_fields.push_str("\r\n");
        assert_eq!(
            scan_body(too_many_fields.as_bytes(), &config()),
            Err(BodyScanError::TooManyHeaderFields)
        );

        let mut too_many_boundaries =
            String::from("Content-Type: multipart/mixed; boundary=b0\r\n\r\n");
        for index in 1..=MAX_MIME_BOUNDARIES {
            too_many_boundaries.push_str(&format!(
                "--b{}\r\nContent-Type: multipart/mixed; boundary=b{index}\r\n\r\n",
                index - 1
            ));
        }
        assert_eq!(
            scan_body(too_many_boundaries.as_bytes(), &config()),
            Err(BodyScanError::TooManyBoundaries)
        );

        let mut too_deep = b"Content-Type: text/plain\r\n\r\nviagra\r\n".to_vec();
        for _ in 0..=MAX_MIME_MESSAGE_DEPTH {
            let mut outer = b"Content-Type: message/rfc822\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n".to_vec();
            outer.extend_from_slice(&too_deep);
            too_deep = outer;
        }
        assert_eq!(
            scan_body(&too_deep, &config()),
            Err(BodyScanError::TooManyEmbeddedMessages)
        );
    }

    #[test]
    fn first_attachment_scan_decodes_embedded_messages_before_the_first_body() {
        let text_message = b"Content-Type: text/plain\r\n\r\nbody\r\n";
        let encoded_text = format!(
            "Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
            BASE64_STANDARD.encode(text_message)
        );
        assert!(!has_first_mime_attachment(encoded_text.as_bytes()).unwrap());

        let binary_message = b"Content-Type: application/octet-stream\r\n\r\ndata\r\n";
        let encoded_binary = format!(
            "Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
            BASE64_STANDARD.encode(binary_message)
        );
        assert!(has_first_mime_attachment(encoded_binary.as_bytes()).unwrap());

        let quoted_printable = concat!(
            "Content-Type: message/rfc822\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "Content-Type: text/plain\r\n\r\nbody\r\n",
        );
        assert!(!has_first_mime_attachment(quoted_printable.as_bytes()).unwrap());
    }

    #[test]
    fn first_attachment_scan_enforces_embedded_depth_and_decoded_work_budgets() {
        let mut too_deep = b"Content-Type: text/plain\r\n\r\nbody\r\n".to_vec();
        for _ in 0..=MAX_MIME_MESSAGE_DEPTH {
            let mut outer = b"Content-Type: message/rfc822\r\n\r\n".to_vec();
            outer.extend_from_slice(&too_deep);
            too_deep = outer;
        }
        assert_eq!(
            has_first_mime_attachment(&too_deep),
            Err(BodyScanError::TooManyEmbeddedMessages)
        );

        let mut scan = FirstAttachmentScan::default();
        assert_eq!(
            scan.account_decoded_work(MAX_MIME_DECODED_WORK_BYTES),
            Ok(())
        );
        assert_eq!(
            scan.account_decoded_work(1),
            Err(BodyScanError::DecodedWorkTooLarge)
        );
    }

    #[test]
    fn first_attachment_scan_matches_the_java_256_kib_index_window() {
        let mut message = b"Content-Type: multipart/mixed; boundary=bb\r\n\r\n".to_vec();
        message.resize(MAX_HEADER_BYTES, b'a');
        message.extend_from_slice(
            b"\r\n--bb\r\nContent-Type: application/octet-stream\r\n\r\ndata\r\n--bb--\r\n",
        );
        assert!(!has_first_mime_attachment(&message).unwrap());
    }

    #[test]
    fn first_attachment_scan_resumes_siblings_after_an_empty_multipart() {
        let empty_only = concat!(
            "Content-Type: multipart/mixed; boundary=outer\r\n\r\n",
            "--outer\r\n",
            "Content-Type: multipart/mixed; boundary=inner\r\n\r\n",
            "--inner--\r\n",
            "--outer--\r\n",
        );
        assert!(!has_first_mime_attachment(empty_only.as_bytes()).unwrap());

        let sibling_after_empty = concat!(
            "Content-Type: multipart/mixed; boundary=outer\r\n\r\n",
            "--outer\r\n",
            "Content-Type: multipart/mixed; boundary=inner\r\n\r\n",
            "--inner--\r\n",
            "--outer\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "body\r\n",
            "--outer--\r\n",
        );
        assert!(has_first_mime_attachment(sibling_after_empty.as_bytes()).unwrap());
    }

    #[test]
    fn golden_attachment_rules_and_order_match_java() {
        let cases = [
            (
                vec![concat!(
                    "Content-Type: application/pdf\r\n",
                    "Content-Disposition: attachment; filename=\"report.pdf\"\r\n",
                )],
                Vec::new(),
            ),
            (
                vec![concat!(
                    "Content-Type: application/octet-stream\r\n",
                    "Content-Disposition: attachment; filename=\"payload.exe\"\r\n",
                )],
                vec![("DANGEROUS_EXTENSION", 5.0)],
            ),
            (
                vec![concat!(
                    "Content-Type: application/pdf\r\n",
                    "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n",
                )],
                vec![
                    ("DANGEROUS_EXTENSION", 5.0),
                    ("DOUBLE_EXTENSION", 4.0),
                    ("MIME_TYPE_MISMATCH", 4.5),
                ],
            ),
            (
                vec![concat!(
                    "Content-Type: application/octet-stream\r\n",
                    "Content-Disposition: attachment; filename*=utf-8''payload%2Eps1\r\n",
                )],
                vec![("DANGEROUS_EXTENSION", 5.0)],
            ),
            (
                vec![
                    concat!(
                        "Content-Type: application/octet-stream\r\n",
                        "Content-Disposition: attachment; filename=\"first.exe\"\r\n",
                    ),
                    concat!(
                        "Content-Type: application/octet-stream\r\n",
                        "Content-Disposition: attachment; filename=\"second.js\"\r\n",
                    ),
                ],
                vec![("DANGEROUS_EXTENSION", 5.5)],
            ),
        ];

        for (parts, expected) in cases {
            let message = attachment_message(&parts);
            let scan = scan_attachments(&message, &config()).unwrap();
            assert_eq!(scan.hits().collect::<Vec<_>>(), expected);
            assert_eq!(
                scan.total_score(),
                expected.iter().map(|(_, score)| score).sum::<f64>()
            );
        }
    }

    #[test]
    fn attachment_rules_honor_global_rule_and_weight_configuration() {
        let message = attachment_message(&[concat!(
            "Content-Type: application/pdf\r\n",
            "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n",
        )]);

        let mut settings = config();
        settings.dangerous_extension.enabled = false;
        settings.double_extension.weight = 0.5;
        settings.mime_type_mismatch.weight = 2.0;
        assert_eq!(
            scan_attachments(&message, &settings)
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("DOUBLE_EXTENSION", 2.0), ("MIME_TYPE_MISMATCH", 9.0)]
        );

        settings.attachment.enabled = false;
        assert_eq!(
            scan_attachments(&message, &settings).unwrap(),
            ContentScan::default()
        );
        settings.attachment.enabled = true;
        settings.enabled = false;
        assert_eq!(
            scan_attachments(&message, &settings).unwrap(),
            ContentScan::default()
        );
    }

    #[test]
    fn malformed_mime_is_ignored_without_partial_hits() {
        let malformed = b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Disposition: attachment; filename=\"payload.exe";
        assert_eq!(
            scan_attachments(malformed, &config()).unwrap(),
            ContentScan::default()
        );
    }

    #[test]
    fn attachment_parser_preserves_java_parameter_and_utf16_boundaries() {
        let unicode = attachment_message(&[concat!(
            "Content-Type: application/pdf\r\n",
            "Content-Disposition: attachment; filename*=utf-8''invoice.%C3%A9.exe\r\n",
        )]);
        assert_eq!(
            scan_attachments(&unicode, &config())
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("DANGEROUS_EXTENSION", 5.0), ("MIME_TYPE_MISMATCH", 4.5)]
        );

        let continuation = attachment_message(&[concat!(
            "Content-Type: application/pdf\r\n",
            "Content-Disposition: attachment; filename*0=invoice.pdf.; filename*1=exe\r\n",
        )]);
        assert_eq!(
            scan_attachments(&continuation, &config()).unwrap(),
            ContentScan::default()
        );

        let content_type_name = attachment_message(&[concat!(
            "Content-Type: application/octet-stream; name=\"payload.exe\"\r\n",
            "Content-Disposition: attachment\r\n",
        )]);
        assert_eq!(
            scan_attachments(&content_type_name, &config())
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("DANGEROUS_EXTENSION", 5.0)]
        );

        let folded = attachment_message(&[concat!(
            "Content-Type: application/octet-stream\r\n",
            "Content-Disposition: attachment;\r\n filename=\"payload.exe\"\r\n",
        )]);
        assert_eq!(
            scan_attachments(&folded, &config())
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("DANGEROUS_EXTENSION", 5.0)]
        );

        let quoted_space_boundary = concat!(
            "Content-Type: multipart/mixed; boundary=\" quoted-boundary\"\r\n",
            "\r\n",
            "-- quoted-boundary\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Disposition: attachment; filename=\"payload.exe\"\r\n",
            "\r\n",
            "payload\r\n",
            "-- quoted-boundary--\r\n",
        );
        assert_eq!(
            scan_attachments(quoted_space_boundary.as_bytes(), &config())
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("DANGEROUS_EXTENSION", 5.0)]
        );

        let embedded_message = concat!(
            "Content-Type: multipart/mixed; boundary=outer\r\n",
            "\r\n",
            "--outer\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From: nested@external.test\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=inner\r\n",
            "\r\n",
            "--inner\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Disposition: attachment; filename=\"payload.exe\"\r\n",
            "\r\n",
            "payload\r\n",
            "--inner--\r\n",
            "--outer--\r\n",
        );
        assert_eq!(
            scan_attachments(embedded_message.as_bytes(), &config())
                .unwrap()
                .hits()
                .collect::<Vec<_>>(),
            [("DANGEROUS_EXTENSION", 5.0)]
        );

        let non_multipart_boundary = concat!(
            "Content-Type: text/plain; boundary=opaque\r\n",
            "\r\n",
            "--opaque\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Disposition: attachment; filename=\"payload.exe\"\r\n",
            "\r\n",
            "not-a-part\r\n",
            "--opaque--\r\n",
        );
        assert_eq!(
            scan_attachments(non_multipart_boundary.as_bytes(), &config()).unwrap(),
            ContentScan::default()
        );
    }

    #[test]
    fn attachment_parser_enforces_metadata_budgets() {
        let too_many_fields = [
            "X-Test: value\r\n".repeat(MAX_MIME_HEADER_FIELDS + 1),
            "\r\n".to_owned(),
        ]
        .concat();
        assert_eq!(
            scan_attachments(too_many_fields.as_bytes(), &config()),
            Err(AttachmentScanError::TooManyHeaderFields)
        );

        let oversized_header = ["X-Test: ", &"x".repeat(MAX_MIME_HEADER_BYTES + 1)].concat();
        assert_eq!(
            scan_attachments(oversized_header.as_bytes(), &config()),
            Err(AttachmentScanError::HeaderTooLarge)
        );

        let mut too_many_parts = concat!(
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=x\r\n",
            "\r\n",
        )
        .to_owned();
        for _ in 0..=MAX_MIME_PARTS {
            too_many_parts.push_str("--x\r\n\r\n");
        }
        assert_eq!(
            scan_attachments(too_many_parts.as_bytes(), &config()),
            Err(AttachmentScanError::TooManyParts)
        );

        let oversized_boundary = format!(
            "Content-Type: multipart/mixed; boundary=\"{}\"\r\n\r\n",
            "x".repeat(MAX_MIME_BOUNDARY_BYTES + 1)
        );
        assert_eq!(
            scan_attachments(oversized_boundary.as_bytes(), &config()),
            Err(AttachmentScanError::BoundaryTooLarge)
        );
    }

    #[test]
    fn parser_enforces_header_byte_and_field_budgets() {
        let oversized = vec![b'a'; MAX_HEADER_BYTES + 1];
        assert_eq!(
            ParsedHeaders::parse(&oversized),
            Err(HeaderParseError::TooLarge)
        );
        let too_many = "X:\r\n".repeat(MAX_HEADER_FIELDS + 1) + "\r\n";
        assert_eq!(
            ParsedHeaders::parse(too_many.as_bytes()),
            Err(HeaderParseError::TooManyFields)
        );
    }

    #[test]
    fn duplicate_header_accessors_preserve_wire_order() {
        let headers = parse(b"From: first@example.test\r\nFrom: second@example.test\r\n\r\n");
        assert_eq!(
            headers.first_trimmed("from").as_deref(),
            Some("first@example.test")
        );
        assert_eq!(
            headers.last_trimmed("FROM").as_deref(),
            Some("second@example.test")
        );
        assert_eq!(headers.last_trimmed("missing"), None);
    }

    #[test]
    fn java_blank_and_trim_boundaries_are_explicit() {
        assert!(java_is_blank(" \t\r\n\u{3000}"));
        assert!(!java_is_blank("\u{00a0}"));
        assert_eq!(java_trim("\r\n value \r\n"), "value");
        assert_eq!(java_trim("\u{3000}value\u{3000}"), "\u{3000}value\u{3000}");
    }

    proptest! {
        #[test]
        fn arbitrary_bounded_input_never_panics_and_scores_stay_finite(
            input in prop::collection::vec(any::<u8>(), 0..8192)
        ) {
            if let Ok(headers) = ParsedHeaders::parse(&input) {
                let scan = headers.scan(0, &config());
                prop_assert!(scan.total_score().is_finite());
                prop_assert!(scan.hits().count() <= 3);
            }
            if let Ok(attachment_scan) = scan_attachments(&input, &config()) {
                prop_assert!(attachment_scan.total_score().is_finite());
                prop_assert!(attachment_scan.hits().count() <= 3);
            }
        }
    }
}
