use std::{
    collections::HashMap,
    io,
    net::Shutdown,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::config::{HtcpcpConfig, HtcpcpPotConfig, RuntimeConfig};

const INITIAL_LINE_LIMIT: usize = 4_096;
const HEADER_LIMIT: usize = 8_192;
const BODY_LIMIT: usize = 65_536;
const MAX_HEADERS: usize = 128;
const MAX_CHUNKS: usize = 4_096;
const READ_CHUNK: usize = 8_192;
const CONNECTION_BUFFER_LIMIT: usize = INITIAL_LINE_LIMIT + HEADER_LIMIT + BODY_LIMIT + READ_CHUNK;
const RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
const MAX_CONNECTIONS: usize = 1_024;
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_DEADLINE: Duration = Duration::from_secs(60);
const WRITE_DEADLINE: Duration = Duration::from_secs(10);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(20);
const ACCEPT_RETRY_MIN: Duration = Duration::from_millis(25);
const ACCEPT_RETRY_MAX: Duration = Duration::from_secs(1);

const CAPABILITY_ADDITIONS: &str = "Cream, Half-and-half, Whole-milk, Part-Skim, Skim, Non-Dairy, Vanilla, Almond, Raspberry, Chocolate, Whisky, Rum, Kahlua, Aquavit, Sugar, Xylitol, Stevia, *";
const ALLOWED_METHODS: &str = "BREW, POST, GET, HEAD, PROPFIND, WHEN, OPTIONS";
const INVALID_BODY: &str = "coffee-message-body must be \"start\" or \"stop\" per RFC 2324 §4";
const INVALID_CONTENT_TYPE: &str =
    "Content-Type must be message/coffeepot, application/coffee-pot-command, or message/teapot";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BeverageType {
    Coffee,
    Tea,
}

impl BeverageType {
    const fn name(self) -> &'static str {
        match self {
            Self::Coffee => "COFFEE",
            Self::Tea => "TEA",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrewingState {
    Idle,
    Brewing,
    Poured,
}

impl BrewingState {
    const fn name(self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Brewing => "BREWING",
            Self::Poured => "POURED",
        }
    }
}

#[derive(Clone, Debug)]
struct Addition {
    kind: String,
    parameters: Vec<(String, String)>,
}

impl Addition {
    fn wildcard(&self) -> bool {
        self.kind == "*"
    }

    fn milk(&self) -> bool {
        matches!(
            self.kind.to_ascii_lowercase().as_str(),
            "cream" | "half-and-half" | "whole-milk" | "part-skim" | "skim" | "non-dairy"
        )
    }
}

#[derive(Clone, Debug)]
struct BrewSession {
    state: BrewingState,
    generation: u64,
    beverage: Option<BeverageType>,
    tea_variety: Option<String>,
    started_at: Option<DateTime<Utc>>,
    ended_at: Option<DateTime<Utc>>,
    completes_at: Option<Instant>,
    scheduled_end_at: Option<DateTime<Utc>>,
    additions: Vec<Addition>,
    milk_pouring: bool,
}

impl Default for BrewSession {
    fn default() -> Self {
        Self {
            state: BrewingState::Idle,
            generation: 0,
            beverage: None,
            tea_variety: None,
            started_at: None,
            ended_at: None,
            completes_at: None,
            scheduled_end_at: None,
            additions: Vec::new(),
            milk_pouring: false,
        }
    }
}

struct Pot {
    id: String,
    supports_coffee: bool,
    supports_tea: bool,
    supported_additions: Vec<String>,
    tea_varieties: Vec<String>,
    session: Mutex<BrewSession>,
}

impl Pot {
    fn from_config(config: &HtcpcpPotConfig) -> Self {
        let pot_type = config.pot_type.to_ascii_lowercase();
        Self {
            id: config.id.clone(),
            supports_coffee: pot_type != "tea",
            supports_tea: matches!(pot_type.as_str(), "tea" | "both"),
            supported_additions: config.supported_additions.clone(),
            tea_varieties: config.tea_varieties.clone(),
            session: Mutex::new(BrewSession::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, BrewSession> {
        self.session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn refresh<'a>(&self, mut session: MutexGuard<'a, BrewSession>) -> MutexGuard<'a, BrewSession> {
        if session.state == BrewingState::Brewing
            && session
                .completes_at
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            if session.additions.iter().any(Addition::milk) {
                session.state = BrewingState::Poured;
                session.ended_at = session.scheduled_end_at.take().or_else(|| Some(Utc::now()));
                session.completes_at = None;
                session.milk_pouring = true;
            } else {
                *session = BrewSession::default();
            }
        }
        session
    }

    fn snapshot(&self) -> BrewSession {
        self.refresh(self.lock()).clone()
    }

    fn supports_addition(&self, addition: &str) -> bool {
        addition == "*"
            || self
                .supported_additions
                .iter()
                .any(|supported| supported.eq_ignore_ascii_case(addition))
    }

    fn has_variety(&self, variety: &str) -> bool {
        self.tea_varieties
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(variety))
    }
}

struct HtcpcpService {
    pots: Vec<Arc<Pot>>,
    pot_indices: HashMap<String, usize>,
    brew_time: Duration,
    next_generation: AtomicU64,
}

impl HtcpcpService {
    fn new(config: &HtcpcpConfig) -> Self {
        let pots: Vec<_> = config
            .pots
            .iter()
            .map(|pot| Arc::new(Pot::from_config(pot)))
            .collect();
        let pot_indices = pots
            .iter()
            .enumerate()
            .map(|(index, pot)| (pot.id.clone(), index))
            .collect();
        Self {
            pots,
            pot_indices,
            brew_time: Duration::from_secs(config.default_brew_time_seconds),
            next_generation: AtomicU64::new(1),
        }
    }

    fn take_generation(&self) -> u64 {
        self.next_generation.fetch_add(1, Ordering::Relaxed)
    }

    fn pot_for_path(&self, path: &str) -> Option<&Arc<Pot>> {
        if path.is_empty() || path == "/" {
            return self.pots.first();
        }
        let cleaned = path.strip_prefix('/').unwrap_or(path);
        let first = cleaned.split('/').next().unwrap_or_default();
        if let Some(index) = self.pot_indices.get(first) {
            return self.pots.get(*index);
        }
        self.pots.first().filter(|pot| pot.has_variety(first))
    }

    fn variety_for_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        if path.is_empty() || path == "/" {
            return None;
        }
        let cleaned = path.strip_prefix('/').unwrap_or(path);
        let mut segments = cleaned.split('/');
        let first = segments.next()?;
        if let Some(second) = segments.next() {
            return Some(second);
        }
        (!self.pot_indices.contains_key(first)).then_some(first)
    }

    fn global_alternates(&self) -> String {
        let multi = self.pots.len() > 1;
        let mut entries = Vec::new();
        if self.pots.iter().any(|pot| pot.supports_coffee) {
            entries.push("{\"/\" {type message/coffeepot}}".to_owned());
        }
        for pot in &self.pots {
            if !pot.supports_tea {
                continue;
            }
            let prefix = if multi {
                format!("/{}", pot.id)
            } else {
                String::new()
            };
            entries.extend(
                pot.tea_varieties
                    .iter()
                    .map(|variety| format!("{{\"{prefix}/{variety}\" {{type message/teapot}}}}")),
            );
        }
        entries.join(", ")
    }

    fn pot_alternates(&self, pot: &Pot) -> String {
        let multi = self.pots.len() > 1;
        let prefix = if multi {
            format!("/{}", pot.id)
        } else {
            String::new()
        };
        let mut entries = Vec::new();
        if pot.supports_coffee {
            let uri = if multi {
                format!("/{}", pot.id)
            } else {
                "/".to_owned()
            };
            entries.push(format!("{{\"{uri}\" {{type message/coffeepot}}}}"));
        }
        entries.extend(
            pot.tea_varieties
                .iter()
                .map(|variety| format!("{{\"{prefix}/{variety}\" {{type message/teapot}}}}")),
        );
        entries.join(", ")
    }
}

#[derive(Debug)]
struct Request {
    method: String,
    target: String,
    version: HttpVersion,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    keep_alive: bool,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    const fn wire(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

struct Response {
    version: HttpVersion,
    code: u16,
    reason: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    close: bool,
}

impl Response {
    fn text(request: &Request, code: u16, reason: &'static str, body: impl Into<Vec<u8>>) -> Self {
        let body = body.into();
        let mut response = Self {
            version: request.version,
            code,
            reason,
            headers: vec![
                ("content-type", "text/plain; charset=UTF-8".to_owned()),
                ("content-length", body.len().to_string()),
            ],
            body,
            close: !request.keep_alive,
        };
        response.add_connection_header(request);
        response
    }

    fn json(request: &Request, code: u16, reason: &'static str, body: Vec<u8>) -> Self {
        let mut response = Self {
            version: request.version,
            code,
            reason,
            headers: vec![
                ("content-type", "application/json; charset=UTF-8".to_owned()),
                ("content-length", body.len().to_string()),
            ],
            body,
            close: !request.keep_alive,
        };
        response.add_connection_header(request);
        response
    }

    fn add_header_before_connection(&mut self, name: &'static str, value: impl Into<String>) {
        let index = self
            .headers
            .iter()
            .position(|(candidate, _)| *candidate == "connection")
            .unwrap_or(self.headers.len());
        self.headers.insert(index, (name, value.into()));
    }

    fn add_connection_header(&mut self, request: &Request) {
        if !request.keep_alive {
            self.headers.push(("connection", "close".to_owned()));
        } else if request.version == HttpVersion::Http10 {
            self.headers.push(("connection", "keep-alive".to_owned()));
        }
    }

    fn head(request: &Request, code: u16, reason: &'static str, content_length: usize) -> Self {
        let mut response = Self {
            version: request.version,
            code,
            reason,
            headers: vec![
                ("content-type", "application/json; charset=UTF-8".to_owned()),
                ("content-length", content_length.to_string()),
            ],
            body: Vec::new(),
            close: !request.keep_alive,
        };
        response.add_connection_header(request);
        response
    }
}

enum ReadRequest {
    Request(Request),
    Respond(Response),
    Raw(Vec<u8>),
    Eof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyFraming {
    Fixed(usize),
    Chunked,
}

#[derive(Debug)]
enum ReadError {
    Io(io::Error),
    Cancelled,
    TimedOut,
    Malformed,
}

impl From<io::Error> for ReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub async fn serve_htcpcp(
    config: Arc<RuntimeConfig>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let listener = TcpListener::bind((config.listen.host.as_str(), config.listen.htcpcp)).await?;
    let service = Arc::new(HtcpcpService::new(&config.htcpcp));
    let max_connections = config.limits.max_http_connections.clamp(1, MAX_CONNECTIONS);
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut tasks = JoinSet::new();
    let mut retry_delay = ACCEPT_RETRY_MIN;
    let mut terminal_error = None;

    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Ok(Err(error)) = result {
                eprintln!("lmyzmail HTCPCP connection failed: {error}");
            }
        }
        let accepted = tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, _) = match accepted {
            Ok(value) => {
                retry_delay = ACCEPT_RETRY_MIN;
                value
            }
            Err(error) if retryable_accept_error(&error) => {
                eprintln!(
                    "lmyzmail HTCPCP accept failed; retrying in {} ms: {error}",
                    retry_delay.as_millis()
                );
                let delay = retry_delay;
                retry_delay = retry_delay.saturating_mul(2).min(ACCEPT_RETRY_MAX);
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    _ = tokio::time::sleep(delay) => continue,
                }
            }
            Err(error) => {
                terminal_error = Some(error);
                cancellation.cancel();
                break;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            let _ = reject_overloaded(stream, &cancellation).await;
            continue;
        };
        let child = cancellation.child_token();
        let service = Arc::clone(&service);
        tasks.spawn(async move { handle_connection(stream, service, child, permit).await });
    }

    if timeout(SHUTDOWN_DEADLINE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    terminal_error.map_or(Ok(()), Err)
}

async fn reject_overloaded(
    mut stream: TcpStream,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    let response = b"HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain; charset=UTF-8\r\ncontent-length: 19\r\nconnection: close\r\n\r\nService Unavailable";
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Ok(()),
        result = timeout(WRITE_DEADLINE, stream.write_all(response)) => {
            result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTCPCP overload response timed out"))?
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    service: Arc<HtcpcpService>,
    cancellation: CancellationToken,
    _permit: OwnedSemaphorePermit,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let shutdown = stream.into_std()?;
    shutdown.set_nonblocking(true)?;
    let shutdown_handle = shutdown.try_clone()?;
    stream = TcpStream::from_std(shutdown)?;
    let mut buffer = Vec::with_capacity(READ_CHUNK * 2);
    let mut buffer_deadline = None;

    loop {
        let request = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                let _ = shutdown_handle.shutdown(Shutdown::Both);
                return Ok(());
            }
            request = read_request(
                &mut stream,
                &mut buffer,
                &mut buffer_deadline,
                &cancellation,
                REQUEST_DEADLINE,
                READ_IDLE_TIMEOUT,
            ) => request,
        };
        let close = match request {
            Ok(ReadRequest::Eof) => return Ok(()),
            Ok(ReadRequest::Raw(bytes)) => {
                write_bytes(&mut stream, &bytes, &cancellation).await?;
                true
            }
            Ok(ReadRequest::Respond(response)) => {
                let close = response.close;
                write_response(&mut stream, response, &cancellation).await?;
                close
            }
            Ok(ReadRequest::Request(request)) => {
                let response = dispatch(&service, &request);
                let close = response.close;
                write_response(&mut stream, response, &cancellation).await?;
                close
            }
            Err(ReadError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(());
            }
            Err(ReadError::Cancelled | ReadError::TimedOut) => return Ok(()),
            Err(ReadError::Malformed) => {
                let bytes =
                    b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                write_bytes(&mut stream, bytes, &cancellation).await?;
                true
            }
            Err(ReadError::Io(error)) => return Err(error),
        };
        if close {
            let _ = stream.shutdown().await;
            let _ = shutdown_handle.shutdown(Shutdown::Both);
            return Ok(());
        }
    }
}

async fn read_request(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    buffer_deadline: &mut Option<Instant>,
    cancellation: &CancellationToken,
    request_timeout: Duration,
    read_idle_timeout: Duration,
) -> Result<ReadRequest, ReadError> {
    let mut continue_sent = false;
    if !buffer.is_empty() && buffer_deadline.is_none() {
        *buffer_deadline = Some(Instant::now() + request_timeout);
    }
    loop {
        if let Some(line_end) = find_crlf(buffer, 0) {
            if line_end > INITIAL_LINE_LIMIT {
                return Ok(ReadRequest::Raw(oversized_initial_response(buffer)));
            }
        } else if buffer.len() > INITIAL_LINE_LIMIT {
            return Ok(ReadRequest::Raw(oversized_initial_response(buffer)));
        }

        if let Some(header_end) = find_double_crlf(buffer) {
            let first_line_end = find_crlf(buffer, 0).ok_or(ReadError::Malformed)?;
            if header_end + 4 - first_line_end - 2 > HEADER_LIMIT {
                return Ok(ReadRequest::Raw(oversized_header_response(buffer)));
            }
            let head = parse_head(&buffer[..header_end + 4])?;
            let body_start = header_end + 4;
            let framing = match body_framing(&head.headers) {
                Ok(framing) => framing,
                Err(()) => {
                    buffer.clear();
                    *buffer_deadline = None;
                    return Ok(ReadRequest::Respond(framing_bad_request(&head)));
                }
            };
            if matches!(framing, BodyFraming::Fixed(length) if length > BODY_LIMIT) {
                buffer.clear();
                *buffer_deadline = None;
                return Ok(ReadRequest::Respond(payload_too_large(&head)));
            }
            if !continue_sent && expects_continue(&head.headers) {
                write_bytes(stream, b"HTTP/1.1 100 Continue\r\n\r\n", cancellation)
                    .await
                    .map_err(ReadError::Io)?;
                continue_sent = true;
            }

            match framing {
                BodyFraming::Chunked => {
                    if let Some((body, consumed)) = scan_chunked(&buffer[body_start..])? {
                        let total = body_start + consumed;
                        buffer.drain(..total);
                        if buffer.is_empty() {
                            *buffer_deadline = None;
                        }
                        return Ok(ReadRequest::Request(head.into_request(body)));
                    }
                }
                BodyFraming::Fixed(content_length)
                    if buffer.len() >= body_start + content_length =>
                {
                    let body = buffer[body_start..body_start + content_length].to_vec();
                    buffer.drain(..body_start + content_length);
                    if buffer.is_empty() {
                        *buffer_deadline = None;
                    }
                    return Ok(ReadRequest::Request(head.into_request(body)));
                }
                BodyFraming::Fixed(_) => {}
            }
        }

        if buffer.len() >= CONNECTION_BUFFER_LIMIT {
            return Err(ReadError::Malformed);
        }
        let mut chunk = [0_u8; READ_CHUNK];
        let read = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(ReadError::Cancelled),
            _ = wait_for_request_deadline(*buffer_deadline) => return Err(ReadError::TimedOut),
            result = timeout(read_idle_timeout, stream.read(&mut chunk)) => {
                result.map_err(|_| ReadError::TimedOut)??
            }
        };
        if read == 0 {
            return if buffer.is_empty() {
                Ok(ReadRequest::Eof)
            } else {
                Err(ReadError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "HTCPCP peer disconnected during a request",
                )))
            };
        }
        if buffer.len() + read > CONNECTION_BUFFER_LIMIT {
            return Err(ReadError::Malformed);
        }
        if buffer.is_empty() {
            *buffer_deadline = Some(Instant::now() + request_timeout);
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

async fn wait_for_request_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

struct ParsedHead {
    method: String,
    target: String,
    version: HttpVersion,
    headers: Vec<(String, String)>,
    keep_alive: bool,
}

impl ParsedHead {
    fn into_request(self, body: Vec<u8>) -> Request {
        Request {
            method: self.method,
            target: rewrite_coffee_uri(&self.target),
            version: self.version,
            headers: self.headers,
            body,
            keep_alive: self.keep_alive,
        }
    }
}

fn parse_head(bytes: &[u8]) -> Result<ParsedHead, ReadError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let status = request.parse(bytes).map_err(|_| ReadError::Malformed)?;
    if !status.is_complete() {
        return Err(ReadError::Malformed);
    }
    let method = request.method.ok_or(ReadError::Malformed)?.to_owned();
    let target = request.path.ok_or(ReadError::Malformed)?.to_owned();
    let version = match request.version {
        Some(0) => HttpVersion::Http10,
        Some(1) => HttpVersion::Http11,
        _ => return Err(ReadError::Malformed),
    };
    let headers: Vec<_> = request
        .headers
        .iter()
        .map(|header| {
            let value = std::str::from_utf8(header.value).map_err(|_| ReadError::Malformed)?;
            Ok::<_, ReadError>((header.name.to_owned(), value.trim().to_owned()))
        })
        .collect::<Result<_, _>>()?;
    let connection_tokens: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .collect();
    let keep_alive = match version {
        HttpVersion::Http11 => !connection_tokens
            .iter()
            .any(|token| token.eq_ignore_ascii_case("close")),
        HttpVersion::Http10 => connection_tokens
            .iter()
            .any(|token| token.eq_ignore_ascii_case("keep-alive")),
    };
    Ok(ParsedHead {
        method,
        target,
        version,
        headers,
        keep_alive,
    })
}

fn body_framing(headers: &[(String, String)]) -> Result<BodyFraming, ()> {
    let content_lengths: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim())
        .collect();
    if content_lengths.len() > 1 {
        return Err(());
    }
    let content_length = content_lengths
        .first()
        .map(|value| value.parse::<usize>().map_err(|_| ()))
        .transpose()?;

    let transfer_codings: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .collect();
    if !transfer_codings.is_empty() {
        if content_length.is_some()
            || transfer_codings.len() != 1
            || !transfer_codings[0].eq_ignore_ascii_case("chunked")
        {
            return Err(());
        }
        return Ok(BodyFraming::Chunked);
    }
    Ok(BodyFraming::Fixed(content_length.unwrap_or(0)))
}

fn expects_continue(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("expect") && value.eq_ignore_ascii_case("100-continue")
    })
}

fn scan_chunked(bytes: &[u8]) -> Result<Option<(Vec<u8>, usize)>, ReadError> {
    let mut offset = 0;
    let mut decoded_len = 0_usize;
    let mut ranges = Vec::new();
    loop {
        if ranges.len() >= MAX_CHUNKS {
            return Err(ReadError::Malformed);
        }
        let Some(line_end) = find_crlf(bytes, offset) else {
            return Ok(None);
        };
        if line_end - offset > 1_024 {
            return Err(ReadError::Malformed);
        }
        let size_text = std::str::from_utf8(&bytes[offset..line_end])
            .map_err(|_| ReadError::Malformed)?
            .split(';')
            .next()
            .ok_or(ReadError::Malformed)?
            .trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| ReadError::Malformed)?;
        offset = line_end + 2;
        if size == 0 {
            if bytes.len() < offset + 2 {
                return Ok(None);
            }
            let consumed = if &bytes[offset..offset + 2] == b"\r\n" {
                offset + 2
            } else {
                let Some(trailer_end) = find_double_crlf_from(bytes, offset) else {
                    if bytes.len().saturating_sub(offset) > HEADER_LIMIT {
                        return Err(ReadError::Malformed);
                    }
                    return Ok(None);
                };
                if trailer_end + 4 - offset > HEADER_LIMIT {
                    return Err(ReadError::Malformed);
                }
                trailer_end + 4
            };
            let mut decoded = Vec::with_capacity(decoded_len);
            for (start, end) in ranges {
                decoded.extend_from_slice(&bytes[start..end]);
            }
            return Ok(Some((decoded, consumed)));
        }
        decoded_len = decoded_len.checked_add(size).ok_or(ReadError::Malformed)?;
        if decoded_len > BODY_LIMIT {
            return Err(ReadError::Malformed);
        }
        if bytes.len() < offset + size + 2 {
            return Ok(None);
        }
        if &bytes[offset + size..offset + size + 2] != b"\r\n" {
            return Err(ReadError::Malformed);
        }
        ranges.push((offset, offset + size));
        offset += size + 2;
    }
}

fn payload_too_large(head: &ParsedHead) -> Response {
    let request = Request {
        method: head.method.clone(),
        target: head.target.clone(),
        version: head.version,
        headers: head.headers.clone(),
        body: Vec::new(),
        keep_alive: false,
    };
    let mut response = Response {
        version: request.version,
        code: 413,
        reason: "Request Entity Too Large",
        headers: vec![("content-length", "0".to_owned())],
        body: Vec::new(),
        close: true,
    };
    response.add_connection_header(&request);
    response
}

fn framing_bad_request(head: &ParsedHead) -> Response {
    Response {
        version: head.version,
        code: 400,
        reason: "Bad Request",
        headers: vec![
            ("content-length", "0".to_owned()),
            ("connection", "close".to_owned()),
        ],
        body: Vec::new(),
        close: true,
    }
}

fn oversized_initial_response(bytes: &[u8]) -> Vec<u8> {
    let target = request_line_target(bytes).unwrap_or("/");
    let body = if target == "/" {
        b"".as_slice()
    } else {
        b"Pot not found".as_slice()
    };
    format!(
        "HTTP/1.0 404 Not Found\r\ncontent-type: text/plain; charset=UTF-8\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

fn oversized_header_response(bytes: &[u8]) -> Vec<u8> {
    let target = request_line_target(bytes).unwrap_or("/");
    let body = if target == "/" {
        b"".as_slice()
    } else {
        b"Pot not found".as_slice()
    };
    format!(
        "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain; charset=UTF-8\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

fn request_line_target(bytes: &[u8]) -> Option<&str> {
    let end = find_crlf(bytes, 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .ok()?
        .split_whitespace()
        .nth(1)
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

fn find_double_crlf(bytes: &[u8]) -> Option<usize> {
    find_double_crlf_from(bytes, 0)
}

fn find_double_crlf_from(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| start + offset)
}

async fn write_response(
    stream: &mut TcpStream,
    response: Response,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(256 + response.body.len());
    bytes.extend_from_slice(response.version.wire().as_bytes());
    bytes.extend_from_slice(format!(" {} {}\r\n", response.code, response.reason).as_bytes());
    for (name, value) in response.headers {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&response.body);
    if bytes.len() > RESPONSE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTCPCP response exceeded its configured hard bound",
        ));
    }
    write_bytes(stream, &bytes, cancellation).await
}

async fn write_bytes(
    stream: &mut TcpStream,
    bytes: &[u8],
    cancellation: &CancellationToken,
) -> io::Result<()> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Ok(()),
        result = timeout(WRITE_DEADLINE, stream.write_all(bytes)) => {
            result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTCPCP response timed out"))?
        }
    }
}

fn dispatch(service: &HtcpcpService, request: &Request) -> Response {
    match request.method.as_str() {
        "BREW" | "POST" => handle_brew(service, request),
        "GET" => handle_get(service, request, false),
        "HEAD" => handle_get(service, request, true),
        "PROPFIND" => handle_propfind(service, request),
        "WHEN" => handle_when(service, request),
        "OPTIONS" => handle_options(request),
        method => Response::text(
            request,
            405,
            "Method Not Allowed",
            format!("Method Not Allowed: {method}").into_bytes(),
        ),
    }
}

fn handle_options(request: &Request) -> Response {
    let mut response = Response {
        version: request.version,
        code: 200,
        reason: "OK",
        headers: vec![
            ("allow", ALLOWED_METHODS.to_owned()),
            ("Accept-Additions", CAPABILITY_ADDITIONS.to_owned()),
            ("content-length", "0".to_owned()),
        ],
        body: Vec::new(),
        close: !request.keep_alive,
    };
    response.add_connection_header(request);
    response
}

fn handle_get(service: &HtcpcpService, request: &Request, head: bool) -> Response {
    let path = path_of(&request.target);
    let body = if path.is_empty() || path == "/" {
        list_pots_json(service)
    } else if let Some(pot) = service.pot_for_path(path) {
        pot_json(pot)
    } else if head {
        return Response::head(request, 404, "Not Found", 0);
    } else {
        return Response::text(request, 404, "Not Found", b"Pot not found".to_vec());
    };
    if head {
        Response::head(request, 200, "OK", java_string_length(&body))
    } else {
        Response::json(request, 200, "OK", body.into_bytes())
    }
}

fn handle_propfind(service: &HtcpcpService, request: &Request) -> Response {
    let path = path_of(&request.target);
    let Some(pot) = service.pot_for_path(path) else {
        return Response::text(request, 404, "Not Found", b"Pot not found".to_vec());
    };
    let body = propfind_xml(pot, path).into_bytes();
    let mut response = Response {
        version: request.version,
        code: 207,
        reason: "Multi-Status",
        headers: vec![
            ("content-type", "application/xml; charset=UTF-8".to_owned()),
            ("content-length", body.len().to_string()),
        ],
        body,
        close: !request.keep_alive,
    };
    response.add_connection_header(request);
    response
}

fn handle_when(service: &HtcpcpService, request: &Request) -> Response {
    let path = path_of(&request.target);
    let Some(pot) = service.pot_for_path(path) else {
        return Response::text(request, 404, "Not Found", b"Pot not found".to_vec());
    };
    let mut session = pot.refresh(pot.lock());
    let body = if session.milk_pouring {
        *session = BrewSession::default();
        "WHEN! Milk pouring stopped. Enjoy your beverage."
    } else {
        "No milk is currently being poured. Your beverage is ready."
    };
    drop(session);
    let mut response = Response::text(request, 200, "OK", body.as_bytes().to_vec());
    response.add_header_before_connection("Safe", "yes");
    response
}

fn handle_brew(service: &HtcpcpService, request: &Request) -> Response {
    let content_type = request
        .header("content-type")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let tea = content_type.starts_with("message/teapot");
    let coffee = content_type.starts_with("message/coffeepot")
        || content_type.starts_with("application/coffee-pot-command");
    if !tea && !coffee {
        return Response::text(
            request,
            415,
            "Unsupported Media Type",
            INVALID_CONTENT_TYPE.as_bytes().to_vec(),
        );
    }
    let path = path_of(&request.target);
    let Some(pot) = service.pot_for_path(path) else {
        return Response::text(request, 404, "Not Found", b"Pot not found".to_vec());
    };
    let body = String::from_utf8_lossy(&request.body);
    if body == "stop" {
        return stop_brew(request, pot);
    }
    if body != "start" {
        return Response::text(
            request,
            400,
            "Bad Request",
            INVALID_BODY.as_bytes().to_vec(),
        );
    }
    if coffee && pot.supports_tea && !pot.supports_coffee {
        return teapot_response(request, pot);
    }
    if tea && !pot.supports_tea {
        return Response::text(
            request,
            503,
            "Service Unavailable",
            b"This pot cannot brew tea".to_vec(),
        );
    }

    let mut additions = parse_additions(request.header("Accept-Additions"));
    additions.extend(parse_additions(query_of(&request.target)));
    let variety = service.variety_for_path(path);
    let root = path.is_empty() || path == "/";
    if tea && pot.supports_tea && variety.is_none() {
        let mut response = Response::text(
            request,
            300,
            "Multiple Choices",
            b"Multiple tea varieties available. See Alternates header.".to_vec(),
        );
        let alternatives = if root {
            service.global_alternates()
        } else {
            service.pot_alternates(pot)
        };
        response.add_header_before_connection("Alternates", alternatives);
        return response;
    }
    if let Some(variety) = variety
        && tea
        && !pot.has_variety(variety)
    {
        return Response::text(
            request,
            404,
            "Not Found",
            format!("Tea variety \"{variety}\" not available in pot {}", pot.id).into_bytes(),
        );
    }
    for addition in &additions {
        if !addition.wildcard() && !pot.supports_addition(&addition.kind) {
            return Response::text(
                request,
                406,
                "Not Acceptable",
                format!(
                    "Not Acceptable: addition \"{}\" is not available.\nAvailable additions: {}",
                    addition.kind,
                    pot.supported_additions.join(", ")
                )
                .into_bytes(),
            );
        }
    }
    if tea
        && let Some(variety) = variety
        && let Some(reason) = forbidden_addition(variety, &additions)
    {
        return Response::text(request, 403, "Forbidden", reason.into_bytes());
    }

    let beverage = if tea {
        BeverageType::Tea
    } else {
        BeverageType::Coffee
    };
    let mut session = pot.refresh(pot.lock());
    if session.state == BrewingState::Brewing {
        return Response::text(
            request,
            409,
            "Conflict",
            b"Pot is already brewing. Send \"stop\" first.".to_vec(),
        );
    }
    let generation = service.take_generation();
    let started_at = Utc::now();
    let scheduled_end_at = ChronoDuration::from_std(service.brew_time)
        .ok()
        .map(|duration| started_at + duration);
    *session = BrewSession {
        state: BrewingState::Brewing,
        generation,
        beverage: Some(beverage),
        tea_variety: variety.map(str::to_owned),
        started_at: Some(started_at),
        ended_at: None,
        completes_at: Some(Instant::now() + service.brew_time),
        scheduled_end_at,
        additions,
        milk_pouring: false,
    };
    drop(session);

    let message = match (beverage, variety) {
        (BeverageType::Tea, Some(variety)) => format!("Brewing tea ({variety})"),
        (BeverageType::Tea, None) => "Brewing tea".to_owned(),
        (BeverageType::Coffee, _) => "Brewing coffee".to_owned(),
    };
    let mut response = Response::text(request, 200, "OK", message.into_bytes());
    response.add_header_before_connection("Safe", "if-user-awake");
    if coffee && root && service.pots.iter().any(|candidate| candidate.supports_tea) {
        response.add_header_before_connection("Alternates", service.global_alternates());
    }
    response
}

fn stop_brew(request: &Request, pot: &Pot) -> Response {
    let mut session = pot.refresh(pot.lock());
    let message = if session.state == BrewingState::Brewing {
        session.state = BrewingState::Poured;
        session.ended_at = Some(Utc::now());
        session.completes_at = None;
        session.scheduled_end_at = None;
        session.milk_pouring = session.additions.iter().any(Addition::milk);
        if session.milk_pouring {
            "Brewing stopped. Milk is being poured — say WHEN to stop."
        } else {
            "Brewing stopped"
        }
    } else {
        "Pot is not currently brewing"
    };
    drop(session);
    let mut response = Response::text(request, 200, "OK", message.as_bytes().to_vec());
    response.add_header_before_connection("Safe", "yes");
    response
}

fn teapot_response(request: &Request, pot: &Pot) -> Response {
    let body = format!(
        "I'm a teapot.\n\nThis is a teapot, not a coffee pot.\nI'm short and stout.\nHere is my handle, here is my spout.\nWhen I get all steamed up, hear me shout:\n\"Tip me over and pour me out!\"\n\nPot: {}\n",
        pot.id
    );
    Response::text(request, 418, "I'm a Teapot", body.into_bytes())
}

fn path_of(target: &str) -> &str {
    target.split_once('?').map_or(target, |(path, _)| path)
}

fn query_of(target: &str) -> Option<&str> {
    let (_, query) = target.split_once('?')?;
    (!query.is_empty()).then_some(query)
}

fn parse_additions(value: Option<&str>) -> Vec<Addition> {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return Vec::new();
    };
    value
        .split(',')
        .filter_map(|entry| {
            let mut parts = entry.trim().split(';');
            let kind = parts.next()?.trim();
            if kind.is_empty() {
                return None;
            }
            let parameters = parts
                .filter_map(|parameter| {
                    let parameter = parameter.trim();
                    if parameter.is_empty() {
                        return None;
                    }
                    Some(match parameter.split_once('=') {
                        Some((key, value)) if !key.trim().is_empty() => {
                            (key.trim().to_owned(), value.trim().to_owned())
                        }
                        _ => (parameter.to_owned(), String::new()),
                    })
                })
                .collect();
            Some(Addition {
                kind: kind.to_owned(),
                parameters,
            })
        })
        .collect()
}

fn forbidden_addition(variety: &str, additions: &[Addition]) -> Option<String> {
    let forbidden: &[&str] = match variety.to_ascii_lowercase().as_str() {
        "green" | "oolong" | "jasmine" => &[
            "cream",
            "half-and-half",
            "whole-milk",
            "part-skim",
            "skim",
            "non-dairy",
            "whisky",
            "rum",
            "kahlua",
            "aquavit",
            "vanilla",
            "almond",
            "raspberry",
            "chocolate",
        ],
        "darjeeling" => &[
            "whisky",
            "rum",
            "kahlua",
            "aquavit",
            "vanilla",
            "almond",
            "raspberry",
            "chocolate",
        ],
        "earl-grey" | "english-breakfast" | "chamomile" => &["whisky", "rum", "kahlua", "aquavit"],
        "peppermint" => &[
            "cream",
            "half-and-half",
            "whole-milk",
            "part-skim",
            "skim",
            "non-dairy",
            "whisky",
            "rum",
            "kahlua",
            "aquavit",
        ],
        _ => &[],
    };
    additions.iter().find_map(|addition| {
        (!addition.wildcard()
            && forbidden
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(&addition.kind)))
        .then(|| {
            format!(
                "The combination of {variety} with {} is contrary to the sensibilities of a consensus of drinkers.",
                addition.kind
            )
        })
    })
}

fn pot_json(pot: &Pot) -> String {
    let session = pot.snapshot();
    let mut json = String::new();
    json.push('{');
    json_field(&mut json, "id", &pot.id);
    json.push_str(",\"state\":\"");
    json.push_str(session.state.name());
    json.push_str("\",\"generation\":");
    json.push_str(&session.generation.to_string());
    json.push_str(",\"supportedTypes\":[");
    let mut types = Vec::new();
    if pot.supports_coffee {
        types.push("\"COFFEE\"");
    }
    if pot.supports_tea {
        types.push("\"TEA\"");
    }
    json.push_str(&types.join(","));
    json.push(']');
    if let Some(beverage) = session.beverage {
        json.push_str(",\"currentBeverage\":\"");
        json.push_str(beverage.name());
        json.push('"');
    }
    if let Some(variety) = session.tea_variety.as_deref() {
        json.push_str(",\"currentTeaVariety\":");
        json_string(&mut json, variety);
    }
    if let Some(started) = session.started_at {
        json.push_str(",\"brewStartTime\":");
        json_string(&mut json, &instant_text(started));
    }
    if let Some(ended) = session.ended_at {
        json.push_str(",\"brewEndTime\":");
        json_string(&mut json, &instant_text(ended));
    }
    json.push_str(",\"milkPouring\":");
    json.push_str(if session.milk_pouring {
        "true"
    } else {
        "false"
    });
    json.push_str(",\"currentAdditions\":[");
    json_string_list(
        &mut json,
        session
            .additions
            .iter()
            .map(|addition| addition.kind.as_str()),
    );
    json.push_str("],\"supportedAdditions\":[");
    json_string_list(
        &mut json,
        pot.supported_additions.iter().map(String::as_str),
    );
    json.push_str("],\"teaVarieties\":[");
    json_string_list(&mut json, pot.tea_varieties.iter().map(String::as_str));
    json.push_str("]}");
    json
}

fn list_pots_json(service: &HtcpcpService) -> String {
    let mut json = String::from("{\"pots\":[");
    for (index, pot) in service.pots.iter().enumerate() {
        if index != 0 {
            json.push(',');
        }
        json.push_str(&pot_json(pot));
    }
    json.push_str("]}");
    json
}

fn json_field(output: &mut String, key: &str, value: &str) {
    json_string(output, key);
    output.push(':');
    json_string(output, value);
}

fn json_string_list<'a>(output: &mut String, values: impl Iterator<Item = &'a str>) {
    for (index, value) in values.enumerate() {
        if index != 0 {
            output.push(',');
        }
        json_string(output, value);
    }
}

fn json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value => output.push(value),
        }
    }
    output.push('"');
}

fn propfind_xml(pot: &Pot, path: &str) -> String {
    let session = pot.snapshot();
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<D:multistatus xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:htcpcp\">\n");
    xml.push_str("  <D:response>\n    <D:href>");
    xml.push_str(&xml_escape(path));
    xml.push_str("</D:href>\n    <D:propstat>\n      <D:prop>\n        <C:pot-id>");
    xml.push_str(&xml_escape(&pot.id));
    xml.push_str("</C:pot-id>\n        <C:state>");
    xml.push_str(session.state.name());
    xml.push_str("</C:state>\n        <C:generation>");
    xml.push_str(&session.generation.to_string());
    xml.push_str("</C:generation>\n        <C:supported-types>\n");
    if pot.supports_coffee {
        xml.push_str("          <C:type>COFFEE</C:type>\n");
    }
    if pot.supports_tea {
        xml.push_str("          <C:type>TEA</C:type>\n");
    }
    xml.push_str("        </C:supported-types>\n");
    if session.state != BrewingState::Idle {
        if let Some(beverage) = session.beverage {
            xml.push_str("        <C:current-beverage>");
            xml.push_str(beverage.name());
            xml.push_str("</C:current-beverage>\n");
        }
        if let Some(variety) = session.tea_variety.as_deref() {
            xml.push_str("        <C:tea-variety>");
            xml.push_str(&xml_escape(variety));
            xml.push_str("</C:tea-variety>\n");
        }
        if let Some(started) = session.started_at {
            xml.push_str("        <C:brew-start>");
            xml.push_str(&instant_text(started));
            xml.push_str("</C:brew-start>\n");
        }
        if let Some(ended) = session.ended_at {
            xml.push_str("        <C:brew-end>");
            xml.push_str(&instant_text(ended));
            xml.push_str("</C:brew-end>\n");
            if let Some(started) = session.started_at {
                xml.push_str("        <C:brew-duration-seconds>");
                xml.push_str(&(ended - started).num_seconds().to_string());
                xml.push_str("</C:brew-duration-seconds>\n");
            }
        }
        if !session.additions.is_empty() {
            xml.push_str("        <C:additions>\n");
            for addition in &session.additions {
                xml.push_str("          <C:addition type=\"");
                xml.push_str(&xml_escape(&addition.kind));
                xml.push('"');
                for (key, value) in &addition.parameters {
                    xml.push(' ');
                    xml.push_str(&xml_escape(key));
                    xml.push_str("=\"");
                    xml.push_str(&xml_escape(value));
                    xml.push('"');
                }
                xml.push_str("/>\n");
            }
            xml.push_str("        </C:additions>\n");
        }
        xml.push_str("        <C:milk-pouring>");
        xml.push_str(if session.milk_pouring {
            "true"
        } else {
            "false"
        });
        xml.push_str("</C:milk-pouring>\n");
    }
    xml.push_str("      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n</D:multistatus>\n");
    xml
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn instant_text(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn java_string_length(value: &str) -> usize {
    value.encode_utf16().count()
}

fn rewrite_coffee_uri(target: &str) -> String {
    let Some((scheme, rest)) = target.split_once(':') else {
        return target.to_owned();
    };
    if !valid_coffee_scheme(scheme) {
        return target.to_owned();
    }
    let rest = if let Some(authority) = rest.strip_prefix("//") {
        authority.find('/').map_or("/", |slash| &authority[slash..])
    } else if rest.is_empty() {
        "/"
    } else {
        rest
    };
    rest.to_owned()
}

fn valid_coffee_scheme(scheme: &str) -> bool {
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "koffie"
            | "q%c3%a6hv%c3%a6"
            | "%d9%82%d9%87%d9%88%d8%a9"
            | "akeita"
            | "koffee"
            | "kahva"
            | "kafe"
            | "caf%c3%e8"
            | "caf%c3%a8"
            | "%e5%92%96%e5%95%a1"
            | "kava"
            | "k%c3%a1va"
            | "kaffe"
            | "coffee"
            | "kafo"
            | "kohv"
            | "kahvi"
            | "%4baffee"
            | "%ce%ba%ce%b1%cf%86%ce%ad"
            | "%e0%a4%95%e0%a5%8c%e0%a4%ab%e0%a5%80"
            | "%e3%82%b3%e3%83%bc%e3%83%92%e3%83%bc"
            | "%ec%bb%a4%ed%94%bc"
            | "%d0%ba%d0%be%d1%84%d0%b5"
            | "%e0%b8%81%e0%b8%b2%e0%b9%81%e0%b8%9f"
    )
}

fn retryable_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
    ) || (cfg!(target_os = "linux")
        && matches!(
            error.raw_os_error(),
            Some(1 | 4 | 11 | 12 | 23 | 24 | 64 | 71 | 92 | 95 | 100 | 101 | 103 | 105 | 112 | 113)
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn service() -> HtcpcpService {
        HtcpcpService::new(&HtcpcpConfig {
            enabled: true,
            default_brew_time_seconds: 1,
            pots: vec![HtcpcpPotConfig {
                id: "pot-0".to_owned(),
                pot_type: "both".to_owned(),
                tea_varieties: vec!["green".to_owned(), "darjeeling".to_owned()],
                supported_additions: vec!["Cream".to_owned(), "Sugar".to_owned()],
            }],
        })
    }

    fn request(method: &str, target: &str, body: &[u8]) -> Request {
        Request {
            method: method.to_owned(),
            target: target.to_owned(),
            version: HttpVersion::Http11,
            headers: vec![("Content-Type".to_owned(), "message/coffeepot".to_owned())],
            body: body.to_vec(),
            keep_alive: false,
        }
    }

    #[test]
    fn request_state_machine_preserves_milk_when_semantics() {
        let service = service();
        let mut start = request("BREW", "/pot-0", b"start");
        start
            .headers
            .push(("Accept-Additions".to_owned(), "Cream;amount=2".to_owned()));
        assert_eq!(dispatch(&service, &start).code, 200);
        assert_eq!(dispatch(&service, &start).code, 409);
        assert_eq!(
            dispatch(&service, &request("BREW", "/pot-0", b"stop")).code,
            200
        );
        assert!(service.pots[0].snapshot().milk_pouring);
        assert_eq!(
            dispatch(&service, &request("WHEN", "/pot-0", b"")).code,
            200
        );
        assert_eq!(service.pots[0].snapshot().state, BrewingState::Idle);
    }

    #[test]
    fn chunked_decoder_is_bounded_and_preserves_trailing_pipeline() {
        let bytes = b"5\r\nstart\r\n0\r\n\r\nGET / HTTP/1.1\r\n\r\n";
        let (decoded, consumed) = scan_chunked(bytes).unwrap().unwrap();
        assert_eq!(decoded, b"start");
        assert_eq!(&bytes[consumed..], b"GET / HTTP/1.1\r\n\r\n");
        assert!(scan_chunked(format!("{:x}\r\n", BODY_LIMIT + 1).as_bytes()).is_err());
    }

    #[test]
    fn ambiguous_or_unsupported_http_body_framing_is_rejected() {
        let cases = [
            vec![
                ("Content-Length".to_owned(), "5".to_owned()),
                ("Content-Length".to_owned(), "5".to_owned()),
            ],
            vec![
                ("Content-Length".to_owned(), "5".to_owned()),
                ("Content-Length".to_owned(), "4".to_owned()),
            ],
            vec![
                ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
                ("Content-Length".to_owned(), "5".to_owned()),
            ],
            vec![("Transfer-Encoding".to_owned(), "gzip".to_owned())],
            vec![("Transfer-Encoding".to_owned(), "chunked, gzip".to_owned())],
            vec![
                ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
                ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
            ],
        ];
        for headers in cases {
            assert_eq!(body_framing(&headers), Err(()), "headers: {headers:?}");
        }
        assert_eq!(
            body_framing(&[("Transfer-Encoding".to_owned(), "ChUnKeD".to_owned())]),
            Ok(BodyFraming::Chunked)
        );
        assert_eq!(
            body_framing(&[("Content-Length".to_owned(), "5".to_owned())]),
            Ok(BodyFraming::Fixed(5))
        );
    }

    #[test]
    fn delayed_timer_observation_uses_the_scheduled_brew_end() {
        let service = service();
        let started_at = Utc::now() - ChronoDuration::seconds(10);
        let scheduled_end_at = started_at + ChronoDuration::seconds(1);
        {
            let mut session = service.pots[0].lock();
            *session = BrewSession {
                state: BrewingState::Brewing,
                generation: 1,
                beverage: Some(BeverageType::Coffee),
                tea_variety: None,
                started_at: Some(started_at),
                ended_at: None,
                completes_at: Some(Instant::now() - Duration::from_secs(1)),
                scheduled_end_at: Some(scheduled_end_at),
                additions: vec![Addition {
                    kind: "Cream".to_owned(),
                    parameters: Vec::new(),
                }],
                milk_pouring: false,
            };
        }

        let snapshot = service.pots[0].snapshot();
        assert_eq!(snapshot.state, BrewingState::Poured);
        assert_eq!(snapshot.ended_at, Some(scheduled_end_at));
        assert_eq!(
            snapshot.ended_at.unwrap() - snapshot.started_at.unwrap(),
            ChronoDuration::seconds(1)
        );
    }

    #[test]
    fn maximum_structural_configuration_has_a_bounded_response_footprint() {
        const RESPONSE_BUDGET: usize = 2_200_000;
        const PEAK_GENERATION_BUDGET: usize = 6 * 1024 * 1024;

        let repeated_value = |prefix: String| {
            let mut value = prefix;
            value.extend(std::iter::repeat_n('"', 128 - value.len()));
            value
        };
        let list = |kind: char| {
            (0..64)
                .map(|index| repeated_value(format!("{kind}{index:02}")))
                .collect::<Vec<_>>()
        };
        let config = HtcpcpConfig {
            enabled: true,
            default_brew_time_seconds: 86_400,
            pots: (0..64)
                .map(|index| HtcpcpPotConfig {
                    id: repeated_value(format!("pot-{index:02}")),
                    pot_type: "both".to_owned(),
                    tea_varieties: list('t'),
                    supported_additions: list('a'),
                })
                .collect(),
        };
        let service = HtcpcpService::new(&config);

        let list_response = list_pots_json(&service);
        let global_alternates = service.global_alternates();
        let largest_pot_json = service
            .pots
            .iter()
            .map(|pot| pot_json(pot).len())
            .max()
            .unwrap();
        let largest_propfind = service
            .pots
            .iter()
            .map(|pot| propfind_xml(pot, &format!("/{}", pot.id)).len())
            .max()
            .unwrap();

        for (name, size) in [
            ("pot list JSON", list_response.len()),
            ("global Alternates", global_alternates.len()),
            ("single pot JSON", largest_pot_json),
            ("single pot PROPFIND", largest_propfind),
        ] {
            assert!(size <= RESPONSE_BUDGET, "{name} used {size} bytes");
        }

        let list_peak = list_response.capacity() + largest_pot_json.next_power_of_two();
        let alternates_peak = global_alternates.capacity()
            + global_alternates.len()
            + (64 * 65) * std::mem::size_of::<String>();
        assert!(
            list_peak <= PEAK_GENERATION_BUDGET,
            "pot list generation used a {list_peak}-byte conservative working set"
        );
        assert!(
            alternates_peak <= PEAK_GENERATION_BUDGET,
            "Alternates generation used a {alternates_peak}-byte conservative working set"
        );
    }

    #[tokio::test]
    async fn request_deadline_starts_at_first_byte_and_is_absolute() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let mut deadline = None;
            let first = read_request(
                &mut stream,
                &mut buffer,
                &mut deadline,
                &cancellation,
                Duration::from_millis(300),
                Duration::from_secs(2),
            )
            .await;
            let second_started = Instant::now();
            let second = read_request(
                &mut stream,
                &mut buffer,
                &mut deadline,
                &cancellation,
                Duration::from_millis(300),
                Duration::from_secs(2),
            )
            .await;
            (first, second, second_started.elapsed())
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(450)).await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        client.write_all(b"G").await.unwrap();
        let writer = tokio::spawn(async move {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(75)).await;
                if client.write_all(b"x").await.is_err() {
                    break;
                }
            }
        });

        let (first, second, elapsed) = timeout(Duration::from_secs(2), server)
            .await
            .expect("server did not enforce the request deadline")
            .unwrap();
        writer.abort();
        let _ = writer.await;

        assert!(matches!(first, Ok(ReadRequest::Request(_))));
        assert!(matches!(second, Err(ReadError::TimedOut)));
        assert!(
            elapsed >= Duration::from_millis(200),
            "elapsed: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_millis(900), "elapsed: {elapsed:?}");
    }

    #[test]
    fn coffee_uri_and_additions_match_frozen_parser_rules() {
        assert_eq!(rewrite_coffee_uri("coffee:/pot-0?Sugar"), "/pot-0?Sugar");
        assert_eq!(
            rewrite_coffee_uri("kava://coffee.example/pot-0?*"),
            "/pot-0?*"
        );
        let additions = parse_additions(Some("Cream;q=0.9, Sugar;amount=2"));
        assert_eq!(additions.len(), 2);
        assert_eq!(
            additions[1].parameters,
            [("amount".to_owned(), "2".to_owned())]
        );
    }

    #[test]
    fn head_uses_java_utf16_string_length() {
        assert_eq!(java_string_length("ascii"), 5);
        assert_eq!(java_string_length("😀"), 2);
    }

    proptest! {
        #[test]
        fn chunked_round_trip_preserves_arbitrary_bounded_payloads(
            chunks in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..256),
                0..32,
            ),
        ) {
            let mut wire = Vec::new();
            let mut expected = Vec::new();
            for chunk in chunks {
                wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                wire.extend_from_slice(&chunk);
                wire.extend_from_slice(b"\r\n");
                expected.extend_from_slice(&chunk);
            }
            wire.extend_from_slice(b"0\r\n\r\n");
            wire.extend_from_slice(b"pipeline-tail");

            let (actual, consumed) = scan_chunked(&wire).unwrap().unwrap();
            prop_assert_eq!(actual, expected);
            prop_assert_eq!(&wire[consumed..], b"pipeline-tail");
        }
    }

    #[test]
    fn structured_fuzz_corpus_does_not_panic_or_escape_bounds() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for iteration in 0..4_096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = (state as usize ^ iteration) % 1_024;
            let mut input = Vec::with_capacity(length);
            for _ in 0..length {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                input.push(state as u8);
            }
            let _ = scan_chunked(&input);
            let _ = parse_head(&input);
            let text = String::from_utf8_lossy(&input);
            let _ = parse_additions(Some(&text));
            let rewritten = rewrite_coffee_uri(&text);
            assert!(rewritten.len() <= text.len().max(1));
        }
    }
}
