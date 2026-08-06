use std::{io, sync::Arc, time::Duration};

use chrono::Utc;
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::config::RuntimeConfig;

const DEFAULT_MAX_REQUEST_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_CONNECTIONS: usize = 256;
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Status {
    Ok,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    PayloadTooLarge,
    ServiceUnavailable,
}

impl Status {
    const fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::PayloadTooLarge => 413,
            Self::ServiceUnavailable => 503,
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::BadRequest => "Bad Request",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::ServiceUnavailable => "Service Unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ServerLimits {
    max_request_bytes: usize,
    max_connections: usize,
    request_deadline: Duration,
}

impl ServerLimits {
    fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            max_request_bytes: config
                .limits
                .max_http_request_bytes
                .max(DEFAULT_MAX_REQUEST_BYTES),
            max_connections: config
                .limits
                .max_http_connections
                .clamp(1, DEFAULT_MAX_CONNECTIONS * 16),
            request_deadline: Duration::from_millis(config.limits.http_deadline_ms),
        }
    }
}

pub async fn serve_http(
    config: Arc<RuntimeConfig>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let listener = TcpListener::bind((config.listen.host.as_str(), config.listen.http)).await?;
    let limits = ServerLimits::from_config(&config);
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let mut tasks = JoinSet::new();

    loop {
        reap_finished(&mut tasks);
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Some(permit) = permits.clone().try_acquire_owned().ok() else {
                    let _ = timeout(
                        limits.request_deadline,
                        write_response(stream, Status::ServiceUnavailable, b"service unavailable\n", "text/plain; charset=utf-8"),
                    ).await;
                    continue;
                };
                let config = Arc::clone(&config);
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = timeout(
                        limits.request_deadline,
                        handle_connection(stream, limits.max_request_bytes, &config),
                    )
                    .await;
                    match result {
                        Ok(Ok(())) | Err(_) => {}
                        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {}
                        Ok(Err(error)) => return Err(error),
                    }
                    Ok::<(), io::Error>(())
                });
            }
        }
    }

    tasks.abort_all();
    let _ = timeout(SHUTDOWN_DEADLINE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

fn reap_finished(tasks: &mut JoinSet<Result<(), io::Error>>) {
    while let Some(result) = tasks.try_join_next() {
        if let Ok(Err(error)) = result {
            eprintln!("lmyzmail HTTP connection failed: {error}");
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    max_request_bytes: usize,
    config: &RuntimeConfig,
) -> io::Result<()> {
    let request = read_headers(&mut stream, max_request_bytes).await?;
    let response = parse_request(&request, max_request_bytes, config);
    match response {
        ParsedRequest::Health => {
            let body = format!(
                "{{\"status\":\"healthy\",\"timestamp\":\"{}\"}}",
                Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            );
            write_response(
                stream,
                Status::Ok,
                body.as_bytes(),
                "application/json; charset=UTF-8",
            )
            .await
        }
        ParsedRequest::Skibidi => {
            let body = format!(
                "{{\"status\":\"skibidi\",\"lore\":\"{}\",\"timestamp\":\"{}\"}}",
                SKIBIDI_LORE,
                Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            );
            write_response(
                stream,
                Status::Ok,
                body.as_bytes(),
                "application/json; charset=UTF-8",
            )
            .await
        }
        ParsedRequest::ApiStatus => {
            let body = serde_json::to_vec(&ApiStatusResponse {
                status: "ok",
                message: "API connection successful",
                timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                version: "2.8.0",
                domains: ApiDomains {
                    receivable: [&config.domain],
                    sendable: [&config.domain],
                },
            })
            .map_err(io::Error::other)?;
            write_response(
                stream,
                Status::Ok,
                &body,
                "application/json; charset=UTF-8",
            )
            .await
        }
        ParsedRequest::WebDomains => {
            let body = serde_json::to_vec(&WebDomainsResponse {
                receivable: [&config.domain],
                registration_enabled: config.features.public_registration,
                sendable: [&config.domain],
            })
            .map_err(io::Error::other)?;
            write_response(
                stream,
                Status::Ok,
                &body,
                "application/json; charset=UTF-8",
            )
            .await
        }
        ParsedRequest::WebConfig => {
            let limits = &config.limits;
            let body = serde_json::to_vec(&WebConfigResponse {
                domains: [&config.domain],
                max_attachment_size_bytes: limits.max_attachment_size_bytes,
                max_attachment_size_mb: limits.max_attachment_size_bytes / (1024 * 1024),
                max_email_size_bytes: limits.max_email_size_bytes,
                max_email_size_mb: limits.max_email_size_bytes / (1024 * 1024),
                max_total_attachments_size_bytes: limits.max_total_attachments_size_bytes,
                sendable_domains: [&config.domain],
                show_internet_nl_badge: config.features.show_internet_nl_badge,
            })
            .map_err(io::Error::other)?;
            write_response(
                stream,
                Status::Ok,
                &body,
                "application/json; charset=UTF-8",
            )
            .await
        }
        ParsedRequest::CorsPreflight(origin) => write_cors_preflight(stream, &origin).await,
        ParsedRequest::CorsRejected => {
            write_response(
                stream,
                Status::Forbidden,
                br#"{"error":"cors_rejected"}"#,
                "application/json; charset=UTF-8",
            )
            .await
        }
        ParsedRequest::Unauthorized => {
            write_response(
                stream,
                Status::Unauthorized,
                br#"{"error":"invalid_api_key","message":"Missing or invalid API key. Please provide a valid X-API-Key header."}"#,
                "application/json; charset=UTF-8",
            )
            .await
        }
        ParsedRequest::Forbidden => {
            write_response(
                stream,
                Status::Forbidden,
                br#"{"error":"permission_denied","message":"This API key does not have read permission"}"#,
                "application/json; charset=UTF-8",
            )
            .await
        }
        ParsedRequest::NotFound => {
            write_response(
                stream,
                Status::NotFound,
                br#"{"error":"not_found"}"#,
                "application/json; charset=UTF-8",
            )
            .await
        }
        ParsedRequest::BadRequest => {
            write_response(
                stream,
                Status::BadRequest,
                b"bad request\n",
                "text/plain; charset=utf-8",
            )
            .await
        }
        ParsedRequest::PayloadTooLarge => {
            write_response(
                stream,
                Status::PayloadTooLarge,
                b"request too large\n",
                "text/plain; charset=utf-8",
            )
            .await
        }
    }
}

async fn read_headers(stream: &mut TcpStream, max_request_bytes: usize) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024.min(max_request_bytes));
    let mut chunk = [0_u8; 1024];
    loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Ok(request);
        }
        if request.len().saturating_add(count) > max_request_bytes {
            request.resize(max_request_bytes.saturating_add(1), 0);
            return Ok(request);
        }
        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ParsedRequest {
    Health,
    Skibidi,
    ApiStatus,
    WebDomains,
    WebConfig,
    CorsPreflight(String),
    CorsRejected,
    Unauthorized,
    Forbidden,
    NotFound,
    BadRequest,
    PayloadTooLarge,
}

fn parse_request(
    request: &[u8],
    max_request_bytes: usize,
    config: &RuntimeConfig,
) -> ParsedRequest {
    if request.len() > max_request_bytes {
        return ParsedRequest::PayloadTooLarge;
    }
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return ParsedRequest::BadRequest;
    };
    let header_bytes = &request[..header_end];
    let Ok(header_text) = std::str::from_utf8(header_bytes) else {
        return ParsedRequest::BadRequest;
    };
    let mut lines = header_text.split("\r\n");
    let Some(request_line) = lines.next() else {
        return ParsedRequest::BadRequest;
    };
    let mut fields = request_line.split(' ');
    let (Some(method), Some(path), Some(version), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return ParsedRequest::BadRequest;
    };
    if version != "HTTP/1.1" || path.bytes().any(|byte| byte <= 0x1f || byte == 0x7f) {
        return ParsedRequest::BadRequest;
    }

    let mut declared_length = None;
    let mut api_key = None;
    let mut origin = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return ParsedRequest::BadRequest;
        };
        if name.is_empty() || name.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f) {
            return ParsedRequest::BadRequest;
        }
        if value
            .bytes()
            .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n')
        {
            return ParsedRequest::BadRequest;
        }
        if name.eq_ignore_ascii_case("content-length") {
            let Ok(length) = value.trim().parse::<usize>() else {
                return ParsedRequest::BadRequest;
            };
            if declared_length.is_some_and(|previous| previous != length) {
                return ParsedRequest::BadRequest;
            }
            declared_length = Some(length);
        }
        if name.eq_ignore_ascii_case("x-api-key") {
            if api_key.is_some() {
                return ParsedRequest::BadRequest;
            }
            api_key = Some(value.trim());
        }
        if name.eq_ignore_ascii_case("origin") {
            if origin.is_some() {
                return ParsedRequest::BadRequest;
            }
            origin = Some(value.trim());
        }
    }
    if declared_length.unwrap_or(0) > max_request_bytes {
        return ParsedRequest::PayloadTooLarge;
    }
    if method == "OPTIONS"
        && let Some(origin) = origin
    {
        return if is_origin_allowed(config, origin) {
            ParsedRequest::CorsPreflight(origin.to_owned())
        } else {
            ParsedRequest::CorsRejected
        };
    }
    match (method, path) {
        ("GET", "/api/health") => ParsedRequest::Health,
        ("GET", "/api/skibidi") => ParsedRequest::Skibidi,
        ("GET", "/web/domains") => ParsedRequest::WebDomains,
        ("GET", "/web/config") => ParsedRequest::WebConfig,
        (_, "/api/health" | "/api/skibidi") => ParsedRequest::NotFound,
        _ if path.starts_with("/api/") => match api_read_permission(config, api_key) {
            ApiReadPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiReadPermission::Forbidden => ParsedRequest::Forbidden,
            ApiReadPermission::Granted if method == "POST" && path == "/api/status" => {
                ParsedRequest::ApiStatus
            }
            ApiReadPermission::Granted => ParsedRequest::NotFound,
        },
        // The frozen router returns its normal 404 for a syntactically valid
        // unsupported method before applying an endpoint's body contract.
        _ if method != "GET" => ParsedRequest::NotFound,
        _ if declared_length.unwrap_or(0) != 0 => ParsedRequest::BadRequest,
        _ => ParsedRequest::NotFound,
    }
}

fn is_origin_allowed(config: &RuntimeConfig, origin: &str) -> bool {
    config
        .allowed_origins
        .iter()
        .any(|pattern| origin_matches(origin, pattern))
}

fn origin_matches(origin: &str, pattern: &str) -> bool {
    if origin == pattern {
        return true;
    }
    let Some((scheme, suffix)) = pattern.split_once("://*.") else {
        return false;
    };
    let Ok(origin_url) = Url::parse(origin) else {
        return false;
    };
    let Ok(pattern_url) = Url::parse(&format!("{scheme}://wildcard.{suffix}")) else {
        return false;
    };
    if origin_url.scheme() != pattern_url.scheme()
        || origin_url.port_or_known_default() != pattern_url.port_or_known_default()
        || origin_url.path() != "/"
        || origin_url.query().is_some()
        || origin_url.fragment().is_some()
    {
        return false;
    }
    let (Some(origin_host), Some(pattern_host)) = (origin_url.host_str(), pattern_url.host_str())
    else {
        return false;
    };
    let suffix_host = pattern_host
        .strip_prefix("wildcard.")
        .unwrap_or(pattern_host);
    origin_host != suffix_host && origin_host.ends_with(&format!(".{suffix_host}"))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ApiReadPermission {
    Unauthorized,
    Forbidden,
    Granted,
}

fn api_read_permission(config: &RuntimeConfig, supplied: Option<&str>) -> ApiReadPermission {
    let Some(supplied) = supplied.filter(|value| !value.is_empty()) else {
        return ApiReadPermission::Unauthorized;
    };
    let mut matched = false;
    let mut granted = false;
    for configured in &config.api_keys {
        let is_match = configured.key.len() == supplied.len()
            && bool::from(configured.key.as_bytes().ct_eq(supplied.as_bytes()));
        matched |= is_match;
        granted |= is_match && configured.read;
    }
    if granted {
        ApiReadPermission::Granted
    } else if matched {
        ApiReadPermission::Forbidden
    } else {
        ApiReadPermission::Unauthorized
    }
}

#[derive(Serialize)]
struct ApiStatusResponse<'a> {
    status: &'static str,
    message: &'static str,
    timestamp: String,
    version: &'static str,
    domains: ApiDomains<'a>,
}

#[derive(Serialize)]
struct ApiDomains<'a> {
    receivable: [&'a str; 1],
    sendable: [&'a str; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebDomainsResponse<'a> {
    receivable: [&'a str; 1],
    registration_enabled: bool,
    sendable: [&'a str; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebConfigResponse<'a> {
    domains: [&'a str; 1],
    max_attachment_size_bytes: u64,
    #[serde(rename = "maxAttachmentSizeMB")]
    max_attachment_size_mb: u64,
    max_email_size_bytes: u64,
    #[serde(rename = "maxEmailSizeMB")]
    max_email_size_mb: u64,
    max_total_attachments_size_bytes: u64,
    sendable_domains: [&'a str; 1],
    show_internet_nl_badge: bool,
}

const SKIBIDI_LORE: &str =
    "The G-Man Toilet initiated a Skibidi dop dop dop yes yes attack on the city center.";

async fn write_response(
    mut stream: TcpStream,
    status: Status,
    body: &[u8],
    content_type: &str,
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\n\r\n",
        status.code(),
        status.reason(),
        content_type,
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await
}

async fn write_cors_preflight(mut stream: TcpStream, origin: &str) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
Access-Control-Allow-Origin: {origin}\r\n\
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n\
Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With, Accept, Origin, Access-Control-Request-Method, Access-Control-Request-Headers, X-API-Key, X-Session-Token\r\n\
Access-Control-Allow-Credentials: true\r\n\
Access-Control-Max-Age: 3600\r\n\
Content-Length: 0\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Properties, RuntimeConfig};

    fn config() -> RuntimeConfig {
        RuntimeConfig::from_properties(Properties::default()).unwrap()
    }

    fn config_with_api_keys() -> RuntimeConfig {
        RuntimeConfig::from_properties(
            Properties::parse(
                b"lmyzmail.api-keys[0].key=read-key\n\
lmyzmail.api-keys[0].read=true\n\
lmyzmail.api-keys[1].key=write-key\n\
lmyzmail.api-keys[1].read=false\n\
lmyzmail.allowed-origins[0]=http://127.0.0.1:18080\n\
lmyzmail.public-registration-enabled=true\n",
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn parse(request: &[u8], max_request_bytes: usize) -> ParsedRequest {
        parse_request(request, max_request_bytes, &config())
    }

    fn limits() -> ServerLimits {
        let config = config();
        ServerLimits::from_config(&config)
    }

    #[test]
    fn parser_accepts_crlf_request_line() {
        assert_eq!(
            parse(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n", 1024),
            ParsedRequest::Health
        );
    }

    #[test]
    fn parser_routes_public_skibidi_and_wrong_methods_to_not_found() {
        assert_eq!(
            parse(
                b"GET /api/skibidi HTTP/1.1\r\nHost: localhost\r\n\r\n",
                1024
            ),
            ParsedRequest::Skibidi
        );
        assert_eq!(
            parse(
                b"POST /api/health HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
                1024,
            ),
            ParsedRequest::NotFound
        );
    }

    #[test]
    fn api_status_distinguishes_invalid_and_insufficient_keys() {
        let config = config_with_api_keys();
        let request = |key: &str| {
            format!(
                "POST /api/status HTTP/1.1\r\nX-API-Key: {key}\r\nContent-Length: 2\r\n\r\n{{}}"
            )
        };
        assert_eq!(
            parse_request(request("missing").as_bytes(), 1024, &config),
            ParsedRequest::Unauthorized
        );
        assert_eq!(
            parse_request(request("write-key").as_bytes(), 1024, &config),
            ParsedRequest::Forbidden
        );
        assert_eq!(
            parse_request(request("read-key").as_bytes(), 1024, &config),
            ParsedRequest::ApiStatus
        );
    }

    #[test]
    fn cors_preflight_and_public_web_routes_follow_config() {
        let config = config_with_api_keys();
        assert_eq!(
            parse_request(
                b"OPTIONS /api/status HTTP/1.1\r\nOrigin: http://127.0.0.1:18080\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::CorsPreflight("http://127.0.0.1:18080".to_owned())
        );
        assert_eq!(
            parse_request(
                b"OPTIONS /api/status HTTP/1.1\r\nOrigin: https://evil.example\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::CorsRejected
        );
        assert_eq!(
            parse_request(b"GET /web/domains HTTP/1.1\r\n\r\n", 1024, &config),
            ParsedRequest::WebDomains
        );
        assert_eq!(
            parse_request(b"GET /web/config HTTP/1.1\r\n\r\n", 1024, &config),
            ParsedRequest::WebConfig
        );
        assert!(origin_matches(
            "https://mx.mail.example",
            "https://*.mail.example"
        ));
        assert!(!origin_matches(
            "https://mail.example.evil.test",
            "https://*.mail.example"
        ));
    }

    #[test]
    fn parser_rejects_invalid_utf8_and_oversized_content_length() {
        assert_eq!(
            parse(b"GET /api/health HTTP/1.1\r\nX: \xff\r\n\r\n", 1024),
            ParsedRequest::BadRequest
        );
        assert_eq!(
            parse(
                b"GET /api/health HTTP/1.1\r\nContent-Length: 2048\r\n\r\n",
                1024
            ),
            ParsedRequest::PayloadTooLarge
        );
        assert_eq!(
            parse(
                b"GET /api/health HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
                1024,
            ),
            ParsedRequest::BadRequest
        );
        assert_eq!(
            parse(&vec![b'x'; 1025], 1024),
            ParsedRequest::PayloadTooLarge
        );
    }

    #[test]
    fn limits_are_nonzero_and_bounded() {
        let value = limits();
        assert!(value.max_request_bytes >= DEFAULT_MAX_REQUEST_BYTES);
        assert!(value.max_connections <= DEFAULT_MAX_CONNECTIONS * 16);
        assert!(value.request_deadline <= Duration::from_secs(3600));
    }

    #[test]
    fn status_lines_are_constant() {
        assert_eq!(Status::Ok.reason(), "OK");
        assert_eq!(Status::PayloadTooLarge.code(), 413);
    }
}
