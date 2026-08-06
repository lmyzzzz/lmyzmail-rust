use std::{io, net::IpAddr, sync::Arc, time::Duration};

use chrono::Utc;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
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

use crate::{
    auth::{AuthError, AuthService, LoginOutcome},
    config::RuntimeConfig,
    mailbox::{AttachmentMeta, EmailDetail, MailboxError, MailboxService},
};

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
    TooManyRequests,
    ServiceUnavailable,
    Created,
    InternalServerError,
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
            Self::TooManyRequests => 429,
            Self::ServiceUnavailable => 503,
            Self::Created => 201,
            Self::InternalServerError => 500,
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
            Self::TooManyRequests => "Too Many Requests",
            Self::ServiceUnavailable => "Service Unavailable",
            Self::Created => "Created",
            Self::InternalServerError => "Internal Server Error",
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
    let auth = Arc::new(AuthService::from_config(&config).map_err(io::Error::other)?);
    let mailbox = Arc::new(MailboxService::from_config(&config).map_err(io::Error::other)?);
    let limits = ServerLimits::from_config(&config);
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let mut tasks = JoinSet::new();

    loop {
        reap_finished(&mut tasks);
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Some(permit) = permits.clone().try_acquire_owned().ok() else {
                    let _ = timeout(
                        limits.request_deadline,
                        write_response(stream, Status::ServiceUnavailable, b"service unavailable\n", "text/plain; charset=utf-8"),
                    ).await;
                    continue;
                };
                let config = Arc::clone(&config);
                let auth = Arc::clone(&auth);
                let mailbox = Arc::clone(&mailbox);
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = timeout(
                        limits.request_deadline,
                        handle_connection(
                            stream,
                            peer.ip(),
                            limits.max_request_bytes,
                            &config,
                            &auth,
                            &mailbox,
                        ),
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
    peer_ip: IpAddr,
    max_request_bytes: usize,
    config: &RuntimeConfig,
    auth: &AuthService,
    mailbox: &MailboxService,
) -> io::Result<()> {
    let request = read_request(&mut stream, max_request_bytes).await?;
    let client_ip = extract_client_ip(&request, peer_ip, config);
    let response = parse_request(&request, max_request_bytes, config);
    if let Some(expires_at) = auth.ban_expiry(&client_ip).await {
        let body = serde_json::to_vec(&IpBannedResponse {
            error: "ip_banned",
            message: "Your IP has been temporarily banned due to suspicious activity.",
            expires_at: &expires_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        })
        .map_err(io::Error::other)?;
        return write_response(
            stream,
            Status::Forbidden,
            &body,
            "application/json; charset=UTF-8",
        )
        .await;
    }
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
        ParsedRequest::WebLogin | ParsedRequest::WebRegister => {
            let body = request_body(&request).and_then(|body| serde_json::from_slice::<Credentials>(body).ok());
            let Some(credentials) = body else {
                return write_response(stream, Status::BadRequest, br#"{"error":"bad_request"}"#, "application/json; charset=UTF-8").await;
            };
            match response {
                ParsedRequest::WebLogin => {
                    let address = credentials.address.unwrap_or_default();
                    let password = credentials.password.unwrap_or_default();
                    match auth.login(&address, &password, &client_ip, None).await {
                        Ok((LoginOutcome::Success, Some(login))) => write_json_response(stream, Status::Ok, &login).await,
                        Ok((LoginOutcome::Invalid { ip_banned: true }, _)) => write_response(stream, Status::Forbidden, br#"{"error":"ip_banned","message":"Too many failed attempts. Please try again later."}"#, "application/json; charset=UTF-8").await,
                        Ok((LoginOutcome::Invalid { ip_banned: false }, _)) => write_response(stream, Status::Unauthorized, br#"{"error":"invalid_credentials"}"#, "application/json; charset=UTF-8").await,
                        Ok((LoginOutcome::Success, None)) => write_response(stream, Status::InternalServerError, br#"{"error":"login_failed"}"#, "application/json; charset=UTF-8").await,
                        Err(_) => write_response(stream, Status::InternalServerError, br#"{"error":"login_failed"}"#, "application/json; charset=UTF-8").await,
                    }
                }
                ParsedRequest::WebRegister => {
                    let address = credentials.address.unwrap_or_default();
                    let password = credentials.password.unwrap_or_default();
                    match auth.register(&address, &password, &client_ip).await {
                        Ok(register) => write_json_response(stream, Status::Created, &register).await,
                        Err(AuthError::InvalidInput(message)) if message == "registration_disabled" => write_response(stream, Status::Forbidden, br#"{"error":"registration_disabled","message":"Public registration is not available."}"#, "application/json; charset=UTF-8").await,
                        Err(AuthError::InvalidInput(message)) if message == "rate_limit_exceeded" => write_response(stream, Status::TooManyRequests, br#"{"error":"rate_limit_exceeded","message":"Too many registration attempts. Please try again later."}"#, "application/json; charset=UTF-8").await,
                        Err(AuthError::InvalidInput(message)) if message == "address_required" => write_response(stream, Status::BadRequest, br#"{"error":"address_required"}"#, "application/json; charset=UTF-8").await,
                        Err(AuthError::InvalidInput(message)) if message == "password_too_short" => write_response(stream, Status::BadRequest, br#"{"error":"password_too_short","message":"Password must be at least 8 characters."}"#, "application/json; charset=UTF-8").await,
                        Err(AuthError::InvalidInput(message)) => write_json_response(stream, Status::BadRequest, &RegistrationFailure { error: "registration_failed", message: &message }).await,
                        Err(_) => write_response(stream, Status::InternalServerError, br#"{"error":"registration_failed","message":"An error occurred."}"#, "application/json; charset=UTF-8").await,
                    }
                }
                _ => unreachable!(),
            }
        }
        ParsedRequest::WebLogout => {
            let token = request_header(&request, "x-session-token");
            let _ = auth.logout(token.as_deref()).await;
            write_response(stream, Status::Ok, br#"{"success":true}"#, "application/json; charset=UTF-8").await
        }
        ParsedRequest::SessionToken(token) => match auth.validate_token(&token).await {
            Ok(Some(address)) => {
                handle_authenticated_request(stream, &request, &address, mailbox).await
            }
            Ok(None) => write_invalid_session(stream).await,
            Err(_) => write_response(
                stream,
                Status::InternalServerError,
                br#"{"error":"session_validation_failed"}"#,
                "application/json; charset=UTF-8",
            )
            .await,
        },
        ParsedRequest::MultipartSession => write_empty_unauthorized(stream).await,
        ParsedRequest::InvalidSession => write_invalid_session(stream).await,
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
        ParsedRequest::ForbiddenRead => {
            write_response(
                stream,
                Status::Forbidden,
                br#"{"error":"permission_denied","message":"This API key does not have read permission"}"#,
                "application/json; charset=UTF-8",
            )
            .await
        }
        ParsedRequest::ForbiddenWrite => {
            write_response(
                stream,
                Status::Forbidden,
                br#"{"error":"permission_denied","message":"This API key does not have write permission"}"#,
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

#[derive(Debug, Clone, Eq, PartialEq)]
enum AuthenticatedRoute {
    List {
        folder: String,
        page: i32,
        size: i32,
        starred_only: bool,
    },
    Detail {
        folder: String,
        file: String,
    },
    Raw {
        folder: String,
        file: String,
    },
    Headers {
        folder: String,
        file: String,
    },
}

async fn handle_authenticated_request(
    stream: TcpStream,
    request: &[u8],
    mailbox_address: &str,
    mailbox: &MailboxService,
) -> io::Result<()> {
    let route = match authenticated_route(request) {
        Ok(Some(route)) => route,
        Ok(None) => {
            return write_response(
                stream,
                Status::NotFound,
                br#"{"error":"not_found"}"#,
                "application/json; charset=UTF-8",
            )
            .await;
        }
        Err(()) => {
            return write_response(
                stream,
                Status::BadRequest,
                br#"{"error":"bad_request"}"#,
                "application/json; charset=UTF-8",
            )
            .await;
        }
    };
    match route {
        AuthenticatedRoute::List {
            folder,
            page,
            size,
            starred_only,
        } => {
            match mailbox
                .list_folder(mailbox_address, &folder, page, size, starred_only)
                .await
            {
                Ok(page) => write_json_response(stream, Status::Ok, &page).await,
                Err(MailboxError::InvalidInput(message)) => {
                    write_invalid_input(stream, &message).await
                }
                Err(MailboxError::InvalidFileName) => write_not_found(stream).await,
                Err(_) => {
                    write_response(
                        stream,
                        Status::InternalServerError,
                        br#"{"error":"mailbox_unavailable"}"#,
                        "application/json; charset=UTF-8",
                    )
                    .await
                }
            }
        }
        AuthenticatedRoute::Detail { folder, file } => {
            match mailbox.read_detail(mailbox_address, &folder, &file).await {
                Ok(detail) => write_email_detail(stream, &folder, &file, detail).await,
                Err(MailboxError::InvalidInput(message)) => {
                    write_invalid_input(stream, &message).await
                }
                Err(MailboxError::InvalidFileName) => write_not_found(stream).await,
                Err(_) => {
                    write_response(
                        stream,
                        Status::NotFound,
                        br#"{"error":"not_found"}"#,
                        "application/json; charset=UTF-8",
                    )
                    .await
                }
            }
        }
        AuthenticatedRoute::Raw { folder, file } => {
            match mailbox.open_raw(mailbox_address, &folder, &file).await {
                Ok((body, length)) => write_raw_mail_response(stream, body, length).await,
                Err(MailboxError::InvalidInput(message)) => {
                    write_invalid_input(stream, &message).await
                }
                Err(MailboxError::InvalidFileName) => write_not_found(stream).await,
                Err(_) => {
                    write_response(
                        stream,
                        Status::NotFound,
                        br#"{"error":"not_found"}"#,
                        "application/json; charset=UTF-8",
                    )
                    .await
                }
            }
        }
        AuthenticatedRoute::Headers { folder, file } => {
            match mailbox.read_headers(mailbox_address, &folder, &file).await {
                Ok(raw_headers) => {
                    write_json_response(stream, Status::Ok, &RawHeadersResponse { raw_headers })
                        .await
                }
                Err(MailboxError::InvalidInput(message)) => {
                    write_invalid_input(stream, &message).await
                }
                Err(_) => {
                    write_response(
                        stream,
                        Status::NotFound,
                        br#"{"error":"not_found"}"#,
                        "application/json; charset=UTF-8",
                    )
                    .await
                }
            }
        }
    }
}

async fn write_invalid_input(stream: TcpStream, message: &str) -> io::Result<()> {
    write_json_response(
        stream,
        Status::BadRequest,
        &InvalidInputResponse {
            error: "invalid_input",
            message,
        },
    )
    .await
}

async fn write_not_found(stream: TcpStream) -> io::Result<()> {
    write_response(
        stream,
        Status::NotFound,
        br#"{"error":"not_found"}"#,
        "application/json; charset=UTF-8",
    )
    .await
}

async fn write_email_detail(
    stream: TcpStream,
    folder: &str,
    file: &str,
    detail: EmailDetail,
) -> io::Result<()> {
    let response = EmailDetailResponse {
        file_name: file,
        folder,
        subject: detail.subject,
        from: detail.from,
        reply_to: detail.reply_to,
        to: detail.to,
        cc: detail.cc,
        date: detail.date,
        text: detail.text,
        html: detail.html,
        message_id: detail.message_id,
        in_reply_to: detail.in_reply_to,
        references: detail.references,
        starred: detail.starred,
        labels: detail.labels,
        raw_headers: detail.raw_headers,
        attachments: detail.attachments,
    };
    write_json_response(stream, Status::Ok, &response).await
}

fn authenticated_route(request: &[u8]) -> Result<Option<AuthenticatedRoute>, ()> {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(())?;
    let line = std::str::from_utf8(&request[..header_end])
        .map_err(|_| ())?
        .lines()
        .next()
        .ok_or(())?;
    let mut fields = line.split(' ');
    let method = fields.next().ok_or(())?;
    let target = fields.next().ok_or(())?;
    if fields.next() != Some("HTTP/1.1") || fields.next().is_some() {
        return Err(());
    }
    let (path, query) = target.split_once('?').map_or((target, ""), |parts| parts);
    let segments = path.split('/').skip(1).collect::<Vec<_>>();
    let decode = |value: &str| {
        percent_decode_str(value)
            .decode_utf8()
            .map(|value| value.into_owned())
            .map_err(|_| ())
    };
    let parse_folder_file = |segments: &[&str]| -> Result<(String, String), ()> {
        if segments.len() != 5 {
            return Err(());
        }
        Ok((decode(segments[3])?, decode(segments[4])?))
    };
    match (method, segments.as_slice()) {
        ("GET", ["web", "mail", "list"]) => {
            let (page, size, starred_only) = list_query(query)?;
            Ok(Some(AuthenticatedRoute::List {
                folder: "inbox".into(),
                page,
                size,
                starred_only,
            }))
        }
        ("GET", ["web", "mail", "list", folder]) => {
            let (page, size, starred_only) = list_query(query)?;
            Ok(Some(AuthenticatedRoute::List {
                folder: decode(folder)?,
                page,
                size,
                starred_only,
            }))
        }
        ("GET", ["web", "mail", "detail", ..]) => {
            let (folder, file) = parse_folder_file(&segments)?;
            Ok(Some(AuthenticatedRoute::Detail { folder, file }))
        }
        ("GET", ["web", "mail", "raw", ..]) => {
            let (folder, file) = parse_folder_file(&segments)?;
            Ok(Some(AuthenticatedRoute::Raw { folder, file }))
        }
        ("GET", ["web", "mail", "headers", ..]) => {
            let (folder, file) = parse_folder_file(&segments)?;
            Ok(Some(AuthenticatedRoute::Headers { folder, file }))
        }
        _ => Ok(None),
    }
}

fn list_query(query: &str) -> Result<(i32, i32, bool), ()> {
    let mut page = 0_i32;
    let mut size = 50_i32;
    let mut starred_only = false;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "page" => page = value.parse().map_err(|_| ())?,
            "size" => size = value.parse().map_err(|_| ())?,
            "starredOnly" => starred_only = value.parse().map_err(|_| ())?,
            _ => {}
        }
    }
    Ok((page, size, starred_only))
}

async fn read_request(stream: &mut TcpStream, max_request_bytes: usize) -> io::Result<Vec<u8>> {
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
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let length = header_content_length(&request[..header_end]).unwrap_or(0);
            let required = header_end.saturating_add(4).saturating_add(length);
            if length > max_request_bytes || required > max_request_bytes.saturating_add(4 * 1024) {
                return Ok(vec![0; max_request_bytes.saturating_add(1)]);
            }
            if request.len() >= required {
                request.truncate(required);
                return Ok(request);
            }
        }
    }
}

fn header_content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

fn request_body(request: &[u8]) -> Option<&[u8]> {
    let index = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    request.get(index + 4..)
}

fn request_header(request: &[u8], wanted: &str) -> Option<String> {
    let index = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let text = std::str::from_utf8(&request[..index]).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(wanted)
            .then(|| value.trim().to_owned())
    })
}

fn extract_client_ip(request: &[u8], peer_ip: IpAddr, config: &RuntimeConfig) -> String {
    if !is_trusted_proxy(config, peer_ip) {
        return peer_ip.to_string();
    }
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return peer_ip.to_string();
    };
    let Ok(headers) = std::str::from_utf8(&request[..header_end]) else {
        return peer_ip.to_string();
    };
    let mut forwarded = Vec::new();
    let mut real_ip = None;
    for line in headers.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return peer_ip.to_string();
        };
        if name.eq_ignore_ascii_case("x-forwarded-for") {
            forwarded.push(value);
        } else if name.eq_ignore_ascii_case("x-real-ip") && real_ip.is_none() {
            real_ip = Some(value);
        }
    }
    if !forwarded.is_empty() {
        for value in forwarded.into_iter().rev() {
            for hop in value.split(',').rev() {
                let Some(hop) = normalize_ip_literal(hop) else {
                    return peer_ip.to_string();
                };
                if !is_trusted_proxy(config, hop) {
                    return hop.to_string();
                }
            }
        }
        return peer_ip.to_string();
    }
    real_ip
        .and_then(normalize_ip_literal)
        .unwrap_or(peer_ip)
        .to_string()
}

fn normalize_ip_literal(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    let value = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    value.parse().ok()
}

fn is_trusted_proxy(config: &RuntimeConfig, address: IpAddr) -> bool {
    config
        .trusted_proxies
        .iter()
        .any(|network| network.contains(&address))
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ParsedRequest {
    Health,
    Skibidi,
    ApiStatus,
    WebDomains,
    WebConfig,
    WebLogin,
    WebRegister,
    WebLogout,
    SessionToken(String),
    MultipartSession,
    InvalidSession,
    CorsPreflight(String),
    CorsRejected,
    Unauthorized,
    ForbiddenRead,
    ForbiddenWrite,
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
    let routing_path = path.split_once('?').map_or(path, |(path, _)| path);

    let mut declared_length = None;
    let mut api_key = None;
    let mut session_token = None;
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
        if name.eq_ignore_ascii_case("x-session-token") {
            if session_token.is_some() {
                return ParsedRequest::BadRequest;
            }
            session_token = Some(value.trim());
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
    match (method, routing_path) {
        ("GET", "/api/health") => ParsedRequest::Health,
        ("GET", "/api/skibidi") => ParsedRequest::Skibidi,
        ("GET", "/web/domains") => ParsedRequest::WebDomains,
        ("GET", "/web/config") => ParsedRequest::WebConfig,
        ("POST", "/web/login") => ParsedRequest::WebLogin,
        ("POST", "/web/register") => ParsedRequest::WebRegister,
        ("POST", "/web/logout") => ParsedRequest::WebLogout,
        _ if is_session_route(method, routing_path) => {
            if method == "POST" && routing_path == "/web/mail/send/multipart" {
                ParsedRequest::MultipartSession
            } else {
                session_token
                    .filter(|value| !value.is_empty())
                    .map_or(ParsedRequest::InvalidSession, |value| {
                        ParsedRequest::SessionToken(value.to_owned())
                    })
            }
        }
        (_, "/api/health" | "/api/skibidi") => ParsedRequest::NotFound,
        _ if routing_path.starts_with("/api/") => {
            match api_permission(config, api_key, is_api_write_route(method, routing_path)) {
                ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
                ApiPermission::Forbidden if is_api_write_route(method, routing_path) => {
                    ParsedRequest::ForbiddenWrite
                }
                ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
                ApiPermission::Granted if method == "POST" && path == "/api/status" => {
                    ParsedRequest::ApiStatus
                }
                ApiPermission::Granted => ParsedRequest::NotFound,
            }
        }
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

const SESSION_ROUTES: &[(&str, &str)] = &[
    ("GET", "/web/mail/list/{folder}"),
    ("GET", "/web/mail/list"),
    ("GET", "/web/mail/detail/{folder}/{file}"),
    ("GET", "/web/mail/raw/{folder}/{file}"),
    ("GET", "/web/mail/headers/{folder}/{file}"),
    ("GET", "/web/mail/attachment/{folder}/{file}/{index}"),
    ("POST", "/web/mail/send"),
    ("POST", "/web/mail/send/multipart"),
    ("GET", "/web/mail/send/status/{queueId}"),
    ("GET", "/web/mail/send/status/file/{fileName}"),
    ("DELETE", "/web/mail/{folder}/{file}"),
    ("POST", "/web/mail/star/{folder}/{file}"),
    ("GET", "/web/mail/quota"),
    ("GET", "/web/userdata/preferences"),
    ("POST", "/web/userdata/preferences"),
    ("GET", "/web/userdata/contacts"),
    ("POST", "/web/userdata/contacts"),
    ("PUT", "/web/userdata/contacts/{id}"),
    ("DELETE", "/web/userdata/contacts/{id}"),
    ("GET", "/web/userdata/stars/{folder}"),
    ("POST", "/web/userdata/stars/{folder}/{fileName}"),
    ("GET", "/web/userdata/labels"),
    ("POST", "/web/userdata/labels"),
    ("PUT", "/web/userdata/labels/{id}"),
    ("DELETE", "/web/userdata/labels/{id}"),
    ("GET", "/web/userdata/labels/email/{folder}/{fileName}"),
    (
        "POST",
        "/web/userdata/labels/email/{folder}/{fileName}/{labelId}",
    ),
    (
        "DELETE",
        "/web/userdata/labels/email/{folder}/{fileName}/{labelId}",
    ),
];

const API_WRITE_ROUTES: &[(&str, &str)] = &[
    ("POST", "/api/mailboxes"),
    ("POST", "/api/mail/send"),
    ("POST", "/api/reports/trigger"),
    ("POST", "/api/reports/domain/{domain}"),
    ("POST", "/api/stress/start"),
    ("POST", "/api/stress/reset"),
    ("POST", "/api/stress/cleanup"),
    ("POST", "/api/xdp-firewall/ban"),
    ("POST", "/api/xdp-firewall/unban"),
    ("POST", "/api/xdp-firewall/sync"),
    ("DELETE", "/api/xdp-firewall/clear"),
    ("POST", "/api/cringe-ips/decay"),
];

fn is_session_route(method: &str, path: &str) -> bool {
    SESSION_ROUTES
        .iter()
        .any(|(route_method, pattern)| *route_method == method && route_matches(pattern, path))
}

fn is_api_write_route(method: &str, path: &str) -> bool {
    API_WRITE_ROUTES
        .iter()
        .any(|(route_method, pattern)| *route_method == method && route_matches(pattern, path))
}

fn route_matches(pattern: &str, path: &str) -> bool {
    let mut expected = pattern.split('/');
    let mut actual = path.split('/');
    loop {
        match (expected.next(), actual.next()) {
            (None, None) => return true,
            (Some(expected), Some(actual))
                if expected == actual
                    || !actual.is_empty()
                        && expected.starts_with('{')
                        && expected.ends_with('}') => {}
            _ => return false,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ApiPermission {
    Unauthorized,
    Forbidden,
    Granted,
}

fn api_permission(
    config: &RuntimeConfig,
    supplied: Option<&str>,
    write_required: bool,
) -> ApiPermission {
    let Some(supplied) = supplied.filter(|value| !value.is_empty()) else {
        return ApiPermission::Unauthorized;
    };
    let mut matched = false;
    let mut granted = false;
    for configured in &config.api_keys {
        let is_match = configured.key.len() == supplied.len()
            && bool::from(configured.key.as_bytes().ct_eq(supplied.as_bytes()));
        matched |= is_match;
        granted |= is_match
            && if write_required {
                configured.write
            } else {
                configured.read
            };
    }
    if granted {
        ApiPermission::Granted
    } else if matched {
        ApiPermission::Forbidden
    } else {
        ApiPermission::Unauthorized
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

#[derive(Debug, Deserialize)]
struct Credentials {
    address: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegistrationFailure<'a> {
    error: &'static str,
    message: &'a str,
}

#[derive(Serialize)]
struct IpBannedResponse<'a> {
    error: &'static str,
    message: &'static str,
    expires_at: &'a str,
}

#[derive(Serialize)]
struct RawHeadersResponse {
    #[serde(rename = "rawHeaders")]
    raw_headers: String,
}

#[derive(Serialize)]
struct InvalidInputResponse<'a> {
    error: &'static str,
    message: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailDetailResponse<'a> {
    file_name: &'a str,
    folder: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<String>,
    to: Vec<String>,
    cc: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    in_reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    references: Option<String>,
    starred: bool,
    labels: Vec<i64>,
    raw_headers: String,
    attachments: Vec<AttachmentMeta>,
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

async fn write_json_response<T: Serialize>(
    stream: TcpStream,
    status: Status,
    value: &T,
) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    write_response(stream, status, &body, "application/json; charset=UTF-8").await
}

async fn write_raw_mail_response(
    mut stream: TcpStream,
    mut body: tokio::fs::File,
    length: u64,
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n",
        length
    );
    stream.write_all(head.as_bytes()).await?;
    let mut remaining = length;
    let mut buffer = [0_u8; 16 * 1024];
    while remaining > 0 {
        let to_read = remaining.min(buffer.len() as u64) as usize;
        let read = body.read(&mut buffer[..to_read]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "raw mail file ended before its declared length",
            ));
        }
        stream.write_all(&buffer[..read]).await?;
        remaining -= read as u64;
    }
    Ok(())
}

async fn write_invalid_session(stream: TcpStream) -> io::Result<()> {
    write_response(
        stream,
        Status::Unauthorized,
        br#"{"error":"invalid_token"}"#,
        "application/json; charset=UTF-8",
    )
    .await
}

async fn write_empty_unauthorized(mut stream: TcpStream) -> io::Result<()> {
    stream
        .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        .await
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
lmyzmail.api-keys[1].write=true\n\
lmyzmail.allowed-origins[0]=http://127.0.0.1:18080\n\
lmyzmail.http.trusted-proxies=127.0.0.1,10.0.0.0/8\n\
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
    fn parser_routes_auth_posts_and_keeps_body_bytes_separate() {
        let request = b"POST /web/login HTTP/1.1\r\nContent-Length: 35\r\n\r\n{\"address\":\"a\",\"password\":\"b\"}";
        assert_eq!(parse(request, 1024), ParsedRequest::WebLogin);
        assert_eq!(
            request_body(request),
            Some(b"{\"address\":\"a\",\"password\":\"b\"}".as_slice())
        );
        assert_eq!(
            parse(b"GET /web/login HTTP/1.1\r\n\r\n", 1024),
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
            ParsedRequest::ForbiddenRead
        );
        assert_eq!(
            parse_request(request("read-key").as_bytes(), 1024, &config),
            ParsedRequest::ApiStatus
        );
        let write_request =
            |key: &str| format!("POST /api/mailboxes HTTP/1.1\r\nX-API-Key: {key}\r\n\r\n");
        assert_eq!(
            parse_request(write_request("read-key").as_bytes(), 1024, &config),
            ParsedRequest::ForbiddenWrite
        );
        assert_eq!(
            parse_request(write_request("write-key").as_bytes(), 1024, &config),
            ParsedRequest::NotFound
        );
    }

    #[test]
    fn session_routes_require_and_capture_a_single_token() {
        assert_eq!(
            parse(b"GET /web/mail/list HTTP/1.1\r\n\r\n", 1024),
            ParsedRequest::InvalidSession
        );
        assert_eq!(
            parse(
                b"GET /web/mail/list?page=0&size=2 HTTP/1.1\r\nX-Session-Token: token\r\n\r\n",
                1024,
            ),
            ParsedRequest::SessionToken("token".to_owned())
        );
        assert_eq!(
            parse(
                b"GET /web/userdata/contacts HTTP/1.1\r\nX-Session-Token: token\r\n\r\n",
                1024,
            ),
            ParsedRequest::SessionToken("token".to_owned())
        );
        assert_eq!(
            parse(
                b"GET /web/userdata/contacts HTTP/1.1\r\nX-Session-Token: a\r\nX-Session-Token: b\r\n\r\n",
                1024,
            ),
            ParsedRequest::BadRequest
        );
        assert_eq!(
            parse(b"POST /web/mail/send/multipart HTTP/1.1\r\n\r\n", 1024,),
            ParsedRequest::MultipartSession
        );
    }

    #[test]
    fn authenticated_mail_routes_decode_paths_and_bound_pagination() {
        assert_eq!(
            authenticated_route(b"GET /web/mail/list/inbox?page=-2&size=500 HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::List {
                folder: "inbox".into(),
                page: -2,
                size: 500,
                starred_only: false,
            }))
        );
        assert_eq!(
            authenticated_route(b"GET /web/mail/detail/inbox/message%40one.eml HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::Detail {
                folder: "inbox".into(),
                file: "message@one.eml".into(),
            }))
        );
        assert!(
            authenticated_route(b"GET /web/mail/detail/inbox/%FF.eml HTTP/1.1\r\n\r\n").is_err()
        );
    }

    #[test]
    fn trusted_proxy_chain_walks_from_the_socket_side_and_fails_closed() {
        let trusted_config = config_with_api_keys();
        let peer = "127.0.0.1".parse().unwrap();
        assert_eq!(
            extract_client_ip(
                b"GET / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.7, 10.0.0.8\r\n\r\n",
                peer,
                &trusted_config,
            ),
            "198.51.100.7"
        );
        assert_eq!(
            extract_client_ip(
                b"GET / HTTP/1.1\r\nX-Forwarded-For: invalid\r\nX-Real-IP: 198.51.100.8\r\n\r\n",
                peer,
                &trusted_config,
            ),
            "127.0.0.1"
        );
        assert_eq!(
            extract_client_ip(
                b"GET / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.9\r\n\r\n",
                peer,
                &config(),
            ),
            "127.0.0.1"
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
