use std::{io, sync::Arc, time::Duration};

use chrono::Utc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::config::RuntimeConfig;

const DEFAULT_MAX_REQUEST_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_CONNECTIONS: usize = 256;
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Status {
    Ok,
    BadRequest,
    NotFound,
    PayloadTooLarge,
    ServiceUnavailable,
}

impl Status {
    const fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::PayloadTooLarge => 413,
            Self::ServiceUnavailable => 503,
        }
    }

    const fn reason(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::BadRequest => "Bad Request",
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
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = timeout(
                        limits.request_deadline,
                        handle_connection(stream, limits.max_request_bytes),
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

async fn handle_connection(mut stream: TcpStream, max_request_bytes: usize) -> io::Result<()> {
    let request = read_headers(&mut stream, max_request_bytes).await?;
    let response = parse_request(&request, max_request_bytes);
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ParsedRequest {
    Health,
    Skibidi,
    NotFound,
    BadRequest,
    PayloadTooLarge,
}

fn parse_request(request: &[u8], max_request_bytes: usize) -> ParsedRequest {
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
    }
    // The frozen router returns its normal 404 for a syntactically valid but
    // unsupported method before applying an endpoint's body contract.
    if method != "GET" {
        return ParsedRequest::NotFound;
    }
    if declared_length.unwrap_or(0) > max_request_bytes {
        return ParsedRequest::PayloadTooLarge;
    }
    if declared_length.unwrap_or(0) != 0 {
        return ParsedRequest::BadRequest;
    }
    match path {
        "/api/health" => ParsedRequest::Health,
        "/api/skibidi" => ParsedRequest::Skibidi,
        _ => ParsedRequest::NotFound,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Properties, RuntimeConfig};

    fn limits() -> ServerLimits {
        let config = RuntimeConfig::from_properties(Properties::default()).unwrap();
        ServerLimits::from_config(&config)
    }

    #[test]
    fn parser_accepts_crlf_request_line() {
        assert_eq!(
            parse_request(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n", 1024),
            ParsedRequest::Health
        );
    }

    #[test]
    fn parser_routes_public_skibidi_and_wrong_methods_to_not_found() {
        assert_eq!(
            parse_request(
                b"GET /api/skibidi HTTP/1.1\r\nHost: localhost\r\n\r\n",
                1024
            ),
            ParsedRequest::Skibidi
        );
        assert_eq!(
            parse_request(
                b"POST /api/health HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
                1024,
            ),
            ParsedRequest::NotFound
        );
    }

    #[test]
    fn parser_rejects_invalid_utf8_and_oversized_content_length() {
        assert_eq!(
            parse_request(b"GET /api/health HTTP/1.1\r\nX: \xff\r\n\r\n", 1024),
            ParsedRequest::BadRequest
        );
        assert_eq!(
            parse_request(
                b"GET /api/health HTTP/1.1\r\nContent-Length: 2048\r\n\r\n",
                1024
            ),
            ParsedRequest::PayloadTooLarge
        );
        assert_eq!(
            parse_request(
                b"GET /api/health HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
                1024,
            ),
            ParsedRequest::BadRequest
        );
        assert_eq!(
            parse_request(&vec![b'x'; 1025], 1024),
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
