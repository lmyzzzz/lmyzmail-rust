use std::{
    future::Future,
    io,
    net::{IpAddr, Shutdown},
    path::PathBuf,
    sync::{Arc, LazyLock},
    time::Duration,
};

use bytes::Bytes;
use chrono::{DateTime, NaiveDate, Utc};
use deadpool_postgres::Pool;
use futures_util::{StreamExt, stream};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, Interest},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::{JoinHandle, JoinSet, spawn_blocking},
    time::{Instant, timeout, timeout_at},
};
use tokio_util::{io::ReaderStream, sync::CancellationToken};
use url::Url;

use crate::{
    auth::{AuthError, AuthService, CredentialOutcome, LoginOutcome},
    config::RuntimeConfig,
    cringe::{CringeError, CringeService, IpListQuery, PageQuery},
    cringe_decay::{self, DecayEstimateError},
    mailbox::{
        AttachmentData, AttachmentMeta, EmailDetail, MAX_API_RAW_BYTES, MailboxError,
        MailboxService,
    },
    outbound::{OutboundError, OutboundService, SendRequest},
    reporting::ReportingService,
    stress::{StressError, StressService},
    userdata::{ContactRecord, UserDataError, UserDataService},
    web_multipart::{self, WebMultipartError},
    web_static::{self, StaticAsset},
    xdp::XdpService,
    xdp_sync::XdpSyncService,
};

const DEFAULT_MAX_REQUEST_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_CONNECTIONS: usize = 256;
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const HTTP_FDS_PER_CONNECTION: u32 = 3;
const ACCEPT_RETRY_MIN_DELAY: Duration = Duration::from_millis(25);
const ACCEPT_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);
const PEER_CLOSE_POLL_DELAY: Duration = Duration::from_millis(25);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(20);
const CONTACT_RESPONSE_CONCURRENCY: usize = 4;
const JSON_STREAM_CHUNK_BYTES: usize = 16 * 1024;
const JSON_STREAM_CHANNEL_CHUNKS: usize = 4;
const MAX_CONTACT_WIRE_BYTES: usize = 6 * 16 * 1024 * 1024 + 2 * 1024 * 1024;
static CONTACT_RESPONSE_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(CONTACT_RESPONSE_CONCURRENCY)));

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
    Accepted,
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
            Self::Accepted => 202,
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
            Self::Accepted => "Accepted",
            Self::InternalServerError => "Internal Server Error",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ServerLimits {
    max_request_bytes: usize,
    max_multipart_request_bytes: usize,
    max_connections: usize,
    request_deadline: Duration,
}

struct ConnectionContext<'a> {
    config: &'a RuntimeConfig,
    auth: &'a AuthService,
    mailbox: &'a MailboxService,
    userdata: &'a UserDataService,
    outbound: &'a OutboundService,
    cringe: &'a CringeService,
    reporting: &'a ReportingService,
    xdp: &'a XdpService,
    xdp_sync: &'a XdpSyncService,
    stress: &'a StressService,
    cancellation: &'a CancellationToken,
}

#[derive(Debug, Clone, Copy)]
struct AcceptBackoff {
    next_delay: Duration,
}

struct AbortTaskOnDrop(JoinHandle<()>);

impl Drop for AbortTaskOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Default for AcceptBackoff {
    fn default() -> Self {
        Self {
            next_delay: ACCEPT_RETRY_MIN_DELAY,
        }
    }
}

impl AcceptBackoff {
    fn next_delay(&mut self) -> Duration {
        let delay = self.next_delay;
        self.next_delay = self
            .next_delay
            .saturating_mul(2)
            .min(ACCEPT_RETRY_MAX_DELAY);
        delay
    }

    fn reset(&mut self) {
        self.next_delay = ACCEPT_RETRY_MIN_DELAY;
    }
}

#[derive(Debug)]
enum AcceptOutcome<T> {
    Accepted(T),
    Retryable(io::Error),
    Terminal(io::Error),
    Cancelled,
}

#[derive(Debug)]
enum ConnectionSetupOutcome<T> {
    Ready(T),
    Retry,
    Cancelled,
}

impl ServerLimits {
    fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            max_request_bytes: config
                .limits
                .max_http_request_bytes
                .max(DEFAULT_MAX_REQUEST_BYTES),
            max_multipart_request_bytes: config.limits.max_http_multipart_bytes,
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
    database_pool: Pool,
    reporting: Arc<ReportingService>,
    outbound: Arc<OutboundService>,
    xdp: Arc<XdpService>,
    xdp_sync: Arc<XdpSyncService>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let listener = TcpListener::bind((config.listen.host.as_str(), config.listen.http)).await?;
    let auth = Arc::new(
        AuthService::from_config(&config, database_pool.clone()).map_err(io::Error::other)?,
    );
    let mailbox = Arc::new(MailboxService::from_config(&config, database_pool.clone()));
    let userdata = Arc::new(UserDataService::new(database_pool.clone()));
    let stress = Arc::new(
        StressService::from_config(
            &config,
            Arc::clone(&auth),
            Arc::clone(&mailbox),
            Arc::clone(&outbound),
            cancellation.child_token(),
        )
        .map_err(io::Error::other)?,
    );
    stress.recover_stale_state(&cancellation).await?;
    let cringe_pool = database_pool.clone();
    let cringe = Arc::new(CringeService::new(cringe_pool));
    let reconciliation_outbound = Arc::clone(&outbound);
    let reconciliation_cancellation = cancellation.clone();
    let mut reconciliation_task = tokio::spawn(async move {
        reconciliation_outbound
            .run_reconciler(reconciliation_cancellation)
            .await;
    });
    let limits = ServerLimits::from_config(&config);
    let connection_fd_permits = Arc::new(Semaphore::new(
        limits.max_connections * HTTP_FDS_PER_CONNECTION as usize,
    ));
    let mut tasks = JoinSet::new();
    let mut accept_backoff = AcceptBackoff::default();
    let mut terminal_accept_error = None;

    loop {
        reap_finished(&mut tasks);
        let (stream, peer) = match select_accept(&cancellation, listener.accept()).await {
            AcceptOutcome::Accepted(accepted) => accepted,
            AcceptOutcome::Retryable(error) => {
                let delay = accept_backoff.next_delay();
                eprintln!(
                    "lmyzmail HTTP accept failed; retrying in {} ms: {error}",
                    delay.as_millis(),
                );
                if !wait_for_accept_retry(&cancellation, delay).await {
                    break;
                }
                continue;
            }
            AcceptOutcome::Terminal(error) => {
                terminal_accept_error = Some(error);
                break;
            }
            AcceptOutcome::Cancelled => break,
        };
        let Some(permit) = connection_fd_permits
            .clone()
            .try_acquire_many_owned(HTTP_FDS_PER_CONNECTION)
            .ok()
        else {
            accept_backoff.reset();
            let cancelled = tokio::select! {
                biased;
                _ = cancellation.cancelled() => true,
                _ = timeout(
                    limits.request_deadline,
                    write_response(stream, Status::ServiceUnavailable, b"service unavailable\n", "text/plain; charset=utf-8"),
                ) => false,
            };
            if cancelled {
                break;
            }
            continue;
        };
        let (stream, shutdown_stream, peer_monitor) =
            match prepare_connection(&mut accept_backoff, &cancellation, || {
                socket_with_shutdown_handles(stream)
            })
            .await
            {
                ConnectionSetupOutcome::Ready(streams) => streams,
                ConnectionSetupOutcome::Retry => continue,
                ConnectionSetupOutcome::Cancelled => break,
            };
        let config = Arc::clone(&config);
        let auth = Arc::clone(&auth);
        let mailbox = Arc::clone(&mailbox);
        let userdata = Arc::clone(&userdata);
        let outbound = Arc::clone(&outbound);
        let cringe = Arc::clone(&cringe);
        let reporting = Arc::clone(&reporting);
        let xdp = Arc::clone(&xdp);
        let xdp_sync = Arc::clone(&xdp_sync);
        let stress = Arc::clone(&stress);
        let request_cancellation = cancellation.child_token();
        tasks.spawn(async move {
            let _permit = permit;
            let result = run_request_until_joined(
                handle_connection(
                    stream,
                    peer_monitor,
                    peer.ip(),
                    limits.max_request_bytes,
                    limits.max_multipart_request_bytes,
                    &ConnectionContext {
                        config: &config,
                        auth: &auth,
                        mailbox: &mailbox,
                        userdata: &userdata,
                        outbound: &outbound,
                        cringe: &cringe,
                        reporting: &reporting,
                        xdp: &xdp,
                        xdp_sync: &xdp_sync,
                        stress: &stress,
                        cancellation: &request_cancellation,
                    },
                ),
                &request_cancellation,
                limits.request_deadline,
                move || {
                    let _ = shutdown_stream.shutdown(Shutdown::Both);
                },
            )
            .await;
            match result {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
                Err(error) => return Err(error),
            }
            Ok::<(), io::Error>(())
        });
    }

    let shutdown_deadline = Instant::now() + SHUTDOWN_DEADLINE;
    if timeout_at(shutdown_deadline, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    match timeout_at(shutdown_deadline, &mut reconciliation_task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return Err(io::Error::other(format!(
                "lmyzmail outbound reconciliation failed during shutdown: {error}"
            )));
        }
        Err(_) => {
            reconciliation_task.abort();
            let _ = reconciliation_task.await;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "lmyzmail outbound reconciliation did not stop before stress cleanup",
            ));
        }
    }
    if !stress.shutdown(shutdown_deadline).await {
        eprintln!(
            "lmyzmail final shutdown could not reclaim stress blocking workers; aborting instead of detaching live file owners"
        );
        std::process::abort();
    }
    match terminal_accept_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn select_accept<T, F>(cancellation: &CancellationToken, accepted: F) -> AcceptOutcome<T>
where
    F: Future<Output = io::Result<T>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => AcceptOutcome::Cancelled,
        result = accepted => match result {
            Ok(value) => AcceptOutcome::Accepted(value),
            Err(error) if is_retryable_accept_error(&error) => {
                AcceptOutcome::Retryable(error)
            }
            Err(error) => {
                cancellation.cancel();
                AcceptOutcome::Terminal(error)
            }
        }
    }
}

fn is_retryable_accept_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
    ) {
        return true;
    }

    if cfg!(target_os = "linux") {
        // Linux accept(2) can surface pending network errors in addition to
        // process/system descriptor and socket-buffer exhaustion.
        return matches!(
            error.raw_os_error(),
            Some(
                1   // EPERM
                    | 4   // EINTR
                    | 11  // EAGAIN / EWOULDBLOCK
                    | 12  // ENOMEM
                    | 23  // ENFILE
                    | 24  // EMFILE
                    | 64  // ENONET
                    | 71  // EPROTO
                    | 92  // ENOPROTOOPT
                    | 95  // EOPNOTSUPP
                    | 100 // ENETDOWN
                    | 101 // ENETUNREACH
                    | 103 // ECONNABORTED
                    | 105 // ENOBUFS
                    | 112 // EHOSTDOWN
                    | 113 // EHOSTUNREACH
            )
        );
    }

    false
}

async fn wait_for_accept_retry(cancellation: &CancellationToken, delay: Duration) -> bool {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => false,
        _ = tokio::time::sleep(delay) => true,
    }
}

async fn prepare_connection<T, F>(
    backoff: &mut AcceptBackoff,
    cancellation: &CancellationToken,
    setup: F,
) -> ConnectionSetupOutcome<T>
where
    F: FnOnce() -> io::Result<T>,
{
    match setup() {
        Ok(value) => {
            backoff.reset();
            ConnectionSetupOutcome::Ready(value)
        }
        Err(error) => {
            let delay = backoff.next_delay();
            eprintln!(
                "lmyzmail HTTP connection setup failed; retrying in {} ms: {error}",
                delay.as_millis(),
            );
            if wait_for_accept_retry(cancellation, delay).await {
                ConnectionSetupOutcome::Retry
            } else {
                ConnectionSetupOutcome::Cancelled
            }
        }
    }
}

fn socket_with_shutdown_handles(
    stream: TcpStream,
) -> io::Result<(TcpStream, std::net::TcpStream, TcpStream)> {
    let stream = stream.into_std()?;
    let shutdown_stream = stream.try_clone()?;
    let peer_monitor = TcpStream::from_std(stream.try_clone()?)?;
    Ok((TcpStream::from_std(stream)?, shutdown_stream, peer_monitor))
}

async fn cancel_on_peer_close(stream: TcpStream, cancellation: CancellationToken) {
    loop {
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            result = stream.ready(Interest::READABLE) => result,
        };
        match result {
            Ok(ready) if ready.is_read_closed() => {
                if stream.take_error().ok().flatten().is_some() {
                    cancellation.cancel();
                }
                return;
            }
            Ok(_) => {
                if !wait_for_accept_retry(&cancellation, PEER_CLOSE_POLL_DELAY).await {
                    return;
                }
            }
            Err(_) => {
                cancellation.cancel();
                return;
            }
        }
    }
}

async fn run_request_until_joined<F, S>(
    request: F,
    cancellation: &CancellationToken,
    deadline: Duration,
    shutdown_socket: S,
) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
    S: FnOnce(),
{
    tokio::pin!(request);
    tokio::select! {
        biased;
        result = request.as_mut() => result,
        _ = cancellation.cancelled() => {
            shutdown_socket();
            request.await
        }
        _ = tokio::time::sleep(deadline) => {
            cancellation.cancel();
            shutdown_socket();
            request.await
        }
    }
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
    peer_monitor: TcpStream,
    peer_ip: IpAddr,
    max_request_bytes: usize,
    max_multipart_request_bytes: usize,
    context: &ConnectionContext<'_>,
) -> io::Result<()> {
    let ConnectionContext {
        config,
        auth,
        mailbox,
        userdata,
        outbound,
        cringe,
        reporting,
        xdp,
        xdp_sync,
        stress,
        cancellation,
    } = *context;
    let mut request = read_request_head(&mut stream, MAX_HTTP_HEADER_BYTES).await?;
    if is_web_multipart_form_request(&request) {
        return handle_web_multipart_connection(
            stream,
            peer_ip,
            request,
            max_multipart_request_bytes,
            config,
            auth,
            outbound,
            cancellation,
        )
        .await;
    }
    complete_request(&mut stream, &mut request, max_request_bytes).await?;
    let _peer_monitor = AbortTaskOnDrop(tokio::spawn(cancel_on_peer_close(
        peer_monitor,
        cancellation.clone(),
    )));
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
                    receivable: config.receivable_domains(),
                    sendable: config.sendable_domains(),
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
        ParsedRequest::StressStart => match stress.start().await {
            Ok(response) => write_json_response(stream, Status::Ok, &response).await,
            Err(StressError::Disabled) => {
                write_response(
                    stream,
                    Status::Forbidden,
                    br#"{"error":"disabled","message":"Stress test endpoint is disabled. Set 'lmyzmail.stress-test-enabled=true' to enable."}"#,
                    "application/json; charset=UTF-8",
                )
                .await
            }
            Err(StressError::Busy) => {
                write_response(
                    stream,
                    Status::ServiceUnavailable,
                    br#"{"error":"busy","message":"A stress test is already running."}"#,
                    "application/json; charset=UTF-8",
                )
                .await
            }
            Err(StressError::NoDomain | StressError::Cancelled | StressError::Backend) => {
                write_json_error(stream, Status::InternalServerError, "stress_unavailable").await
            }
        },
        ParsedRequest::StressReset => match stress.reset() {
            Ok(response) => write_json_response(stream, Status::Ok, &response).await,
            Err(StressError::Disabled) => {
                write_response(
                    stream,
                    Status::Forbidden,
                    br#"{"error":"disabled","message":"Stress test endpoint is disabled."}"#,
                    "application/json; charset=UTF-8",
                )
                .await
            }
            Err(_) => {
                write_json_error(stream, Status::InternalServerError, "stress_unavailable").await
            }
        },
        ParsedRequest::StressStatus => match stress.status() {
            Ok(response) => write_json_response(stream, Status::Ok, &response).await,
            Err(StressError::Disabled) => {
                write_response(
                    stream,
                    Status::Forbidden,
                    br#"{"error":"disabled","message":"Stress test endpoint is disabled."}"#,
                    "application/json; charset=UTF-8",
                )
                .await
            }
            Err(_) => {
                write_json_error(stream, Status::InternalServerError, "stress_unavailable").await
            }
        },
        ParsedRequest::StressCleanup => match stress.cleanup(cancellation).await {
            Ok(response) => write_json_response(stream, Status::Ok, &response).await,
            Err(StressError::Disabled) => {
                write_response(
                    stream,
                    Status::Forbidden,
                    br#"{"error":"disabled","message":"Stress test endpoint is disabled."}"#,
                    "application/json; charset=UTF-8",
                )
                .await
            }
            Err(StressError::Busy) => {
                write_response(
                    stream,
                    Status::ServiceUnavailable,
                    br#"{"error":"busy","message":"A stress test is already running."}"#,
                    "application/json; charset=UTF-8",
                )
                .await
            }
            Err(StressError::NoDomain) => {
                write_response(
                    stream,
                    Status::BadRequest,
                    br#"{"error":"No domain configured"}"#,
                    "application/json; charset=UTF-8",
                )
                .await
            }
            Err(_) => {
                write_json_error(stream, Status::InternalServerError, "stress_unavailable").await
            }
        },
        ParsedRequest::WebDomains => {
            let body = serde_json::to_vec(&WebDomainsResponse {
                receivable: config.receivable_domains(),
                registration_enabled: config.features.public_registration,
                sendable: config.sendable_domains(),
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
                domains: config.receivable_domains(),
                max_attachment_size_bytes: limits.max_attachment_size_bytes,
                max_attachment_size_mb: limits.max_attachment_size_bytes / (1024 * 1024),
                max_email_size_bytes: limits.max_email_size_bytes,
                max_email_size_mb: limits.max_email_size_bytes / (1024 * 1024),
                max_total_attachments_size_bytes: limits.max_total_attachments_size_bytes,
                sendable_domains: config.sendable_domains(),
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
        ParsedRequest::ApiCreateMailbox => {
            let credentials = match request_body(&request) {
                Some([]) => None,
                Some(body) => match serde_json::from_slice::<Option<Credentials>>(body) {
                    Ok(credentials) => credentials,
                    Err(_) => {
                        return write_json_error(
                            stream,
                            Status::InternalServerError,
                            "internal_error",
                        )
                        .await;
                    }
                },
                None => None,
            };
            let Some(Credentials {
                address: Some(address),
                password: Some(password),
            }) = credentials
            else {
                return write_response(
                    stream,
                    Status::BadRequest,
                    br#"{"error":"invalid_request","message":"Address and password are required."}"#,
                    "application/json; charset=UTF-8",
                )
                .await;
            };
            if address.trim().is_empty() || password.trim().is_empty() {
                return write_response(
                    stream,
                    Status::BadRequest,
                    br#"{"error":"invalid_request","message":"Address and password are required."}"#,
                    "application/json; charset=UTF-8",
                )
                .await;
            }
            if password.encode_utf16().count() < 8 {
                return write_response(
                    stream,
                    Status::BadRequest,
                    br#"{"error":"password_too_short","message":"Password must be at least 8 characters."}"#,
                    "application/json; charset=UTF-8",
                )
                .await;
            }
            match auth
                .create_mailbox_api_with_cancellation(
                    &address,
                    &password,
                    &client_ip,
                    cancellation,
                )
                .await
            {
                Ok(created) => {
                    write_json_response(
                        stream,
                        Status::Created,
                        &MailboxCreationResponse {
                            address: &created.address,
                            id: created.id,
                        },
                    )
                    .await
                }
                Err(AuthError::InvalidInput(message)) if message == "rate_limit_exceeded" => {
                    write_response(
                        stream,
                        Status::TooManyRequests,
                        br#"{"error":"rate_limit_exceeded","message":"Too many registration attempts. Please try again later."}"#,
                        "application/json; charset=UTF-8",
                    )
                    .await
                }
                Err(AuthError::InvalidInput(message)) => {
                    write_json_response(
                        stream,
                        Status::BadRequest,
                        &RegistrationFailure {
                            error: "creation_failed",
                            message: &message,
                        },
                    )
                    .await
                }
                Err(_) => {
                    write_response(
                        stream,
                        Status::InternalServerError,
                        br#"{"error":"internal_error","message":"An error occurred."}"#,
                        "application/json; charset=UTF-8",
                    )
                    .await
                }
            }
        }
        ParsedRequest::ApiMailboxExists(address) => {
            if address.trim().is_empty() {
                return write_json_error(stream, Status::BadRequest, "address_required").await;
            }
            match auth
                .mailbox_exists_with_cancellation(&address, cancellation)
                .await
            {
                Ok(exists) => {
                    write_json_response(
                        stream,
                        Status::Ok,
                        &MailboxExistsResponse {
                            address: &address,
                            exists,
                        },
                    )
                    .await
                }
                Err(_) => {
                    write_json_error(stream, Status::InternalServerError, "internal_error").await
                }
            }
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
                    match auth
                        .login_with_cancellation(
                            &address,
                            &password,
                            &client_ip,
                            None,
                            cancellation,
                        )
                        .await
                    {
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
                    match auth
                        .register_with_cancellation(&address, &password, &client_ip, cancellation)
                        .await
                    {
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
            let _ = auth
                .logout_with_cancellation(token.as_deref(), cancellation)
                .await;
            write_response(stream, Status::Ok, br#"{"success":true}"#, "application/json; charset=UTF-8").await
        }
        ParsedRequest::SessionToken(token) => match auth
            .validate_token_with_cancellation(&token, cancellation)
            .await
        {
            Ok(Some(address)) => {
                handle_authenticated_request(
                    stream,
                    &request,
                    &address,
                    mailbox,
                    userdata,
                    outbound,
                    cancellation,
                )
                .await
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
        ParsedRequest::MultipartSession => {
            write_json_error(stream, Status::InternalServerError, "internal_error").await
        }
        ParsedRequest::ApiSend => {
            let Some(input) = parse_json_body::<SendRequest>(&request) else {
                return write_json_error(stream, Status::BadRequest, "invalid_request").await;
            };
            match outbound
                .enqueue_with_cancellation(input, Some((auth, &client_ip)), cancellation)
                .await
            {
                Ok(result) => write_json_response(stream, Status::Accepted, &result).await,
                Err(error) => write_outbound_error(stream, error, true).await,
            }
        }
        ParsedRequest::ApiPoll => {
            let Some(input) = parse_json_body::<ApiPollRequest>(&request) else {
                return write_json_error(stream, Status::BadRequest, "invalid_request").await;
            };
            let address = match authenticate_api_mailbox(
                auth,
                input.address.as_deref(),
                input.password.as_deref(),
                &client_ip,
                cancellation,
            )
            .await
            {
                Ok(address) => address,
                Err(error) => return write_api_mailbox_error(stream, error, true).await,
            };
            let since = match input.since_epoch_millis {
                Some(value) => match DateTime::from_timestamp_millis(value) {
                    Some(value) => Some(value),
                    None if value >= 0 => Some(DateTime::<Utc>::MAX_UTC),
                    None => None,
                },
                None => None,
            };
            let limit = input.limit.filter(|value| *value > 0).unwrap_or(50) as i64;
            match mailbox.poll_emails(&address, since, limit).await {
                Ok(items) => write_json_response(stream, Status::Ok, &items).await,
                Err(MailboxError::InvalidInput(_)) => {
                    write_json_error(stream, Status::BadRequest, "invalid_request").await
                }
                Err(_) => write_json_error(stream, Status::InternalServerError, "internal_error").await,
            }
        }
        ParsedRequest::ApiRaw => {
            let Some(input) = parse_json_body::<ApiRawRequest>(&request) else {
                return write_json_error(stream, Status::BadRequest, "invalid_request").await;
            };
            let address = match authenticate_api_mailbox(
                auth,
                input.address.as_deref(),
                input.password.as_deref(),
                &client_ip,
                cancellation,
            )
            .await
            {
                Ok(address) => address,
                Err(error) => return write_api_mailbox_error(stream, error, false).await,
            };
            let Some(file) = input.file.as_deref().filter(|value| !value.trim().is_empty())
            else {
                return write_json_error(stream, Status::BadRequest, "invalid_request").await;
            };
            match mailbox
                .open_raw_limited(&address, "inbox", file, MAX_API_RAW_BYTES)
                .await
            {
                Ok((body, length)) => write_api_raw_mail_response(stream, body, length).await,
                Err(_) => write_not_found(stream).await,
            }
        }
        ParsedRequest::ApiRawDecoded => {
            let Some(input) = parse_json_body::<ApiRawDecodedRequest>(&request) else {
                return write_json_error(stream, Status::BadRequest, "invalid_request").await;
            };
            let address = match authenticate_api_mailbox(
                auth,
                input.address.as_deref(),
                input.password.as_deref(),
                &client_ip,
                cancellation,
            )
            .await
            {
                Ok(address) => address,
                Err(error) => return write_api_mailbox_error(stream, error, false).await,
            };
            let Some(file) = input.file.as_deref().filter(|value| !value.trim().is_empty())
            else {
                return write_json_error(stream, Status::BadRequest, "invalid_request").await;
            };
            match mailbox
                .read_decoded_text(&address, "inbox", file, input.html.unwrap_or(false))
                .await
            {
                Ok(decoded) => write_json_response(stream, Status::Ok, &decoded).await,
                Err(MailboxError::NotFound) => {
                    write_json_error(stream, Status::InternalServerError, "not found").await
                }
                Err(_) => write_json_error(stream, Status::InternalServerError, "internal_error").await,
            }
        }
        ParsedRequest::ApiStatusById(queue_id) => match outbound.api_status_by_id(queue_id).await {
            Ok(Some(result)) => write_json_response(stream, Status::Ok, &result).await,
            Ok(None) => write_not_found(stream).await,
            Err(_) => write_json_error(stream, Status::InternalServerError, "internal_error").await,
        },
        ParsedRequest::ApiStatusByMessage(message_id) => {
            match outbound.api_status_by_message_id(&message_id).await {
                Ok(Some(result)) => write_json_response(stream, Status::Ok, &result).await,
                Ok(None) => write_not_found(stream).await,
                Err(_) => write_json_error(stream, Status::InternalServerError, "internal_error").await,
            }
        }
        ParsedRequest::ApiQuota(address) => match outbound.remaining_quota(&address).await {
            Ok(remaining_quota) => write_json_response(
                stream,
                Status::Ok,
                &crate::outbound::QuotaResponse {
                    address: &address,
                    remaining_quota,
                },
            )
            .await,
            Err(OutboundError::InvalidInput(code)) => {
                write_json_error(stream, Status::BadRequest, code).await
            }
            Err(_) => write_json_error(stream, Status::InternalServerError, "outbound_unavailable").await,
        },
        ParsedRequest::ApiQuotaMissing => {
            write_json_error(stream, Status::BadRequest, "address_required").await
        }
        ParsedRequest::ReportStatus => {
            let reporting = reporting.config();
            write_json_response(
                stream,
                Status::Ok,
                &ReportingStatusResponse {
                    enabled: reporting.enabled,
                    auto_send_enabled: reporting.auto_send_enabled,
                    min_volume_for_report: reporting.min_volume_for_report,
                    dmarc_report_sender_address: reporting
                        .dmarc_report_sender_address
                        .as_deref()
                        .unwrap_or("not configured"),
                    tls_report_sender_address: reporting
                        .tls_report_sender_address
                        .as_deref()
                        .unwrap_or("not configured"),
                    organization_name: reporting
                        .organization_name
                        .as_deref()
                        .unwrap_or("not configured"),
                    http_delivery_enabled: reporting.http_delivery_enabled,
                },
            )
            .await
        }
        ParsedRequest::ReportAddresses(domain) => {
            match reporting.addresses(&domain, cancellation).await {
                Ok(addresses) => {
                    write_json_response(
                        stream,
                        Status::Ok,
                        &ReportAddressesResponse {
                            domain: &domain,
                            dmarc: ReportAddressListResponse {
                                mailto: &addresses.dmarc.mailto,
                                https: &addresses.dmarc.https,
                            },
                            tlsrpt: ReportAddressListResponse {
                                mailto: &addresses.tlsrpt.mailto,
                                https: &addresses.tlsrpt.https,
                            },
                        },
                    )
                    .await
                }
                Err(_) => {
                    write_json_error(stream, Status::InternalServerError, "internal_error").await
                }
            }
        }
        ParsedRequest::ReportDomains(date) => {
            let Some(date) = report_date(date.as_deref()) else {
                return write_json_error(stream, Status::BadRequest, "Invalid date format").await;
            };
            match reporting.domains(date, cancellation).await {
                Ok(domains) => {
                    let date_text = date.to_string();
                    write_json_response(
                        stream,
                        Status::Ok,
                        &ReportDomainsResponse {
                            date: &date_text,
                            min_volume: reporting.config().min_volume_for_report,
                            dmarc_domains: &domains.dmarc,
                            tls_domains: &domains.tls,
                        },
                    )
                    .await
                }
                Err(_) => {
                    write_json_error(stream, Status::InternalServerError, "internal_error").await
                }
            }
        }
        ParsedRequest::ReportTrigger(date) => {
            if !reporting.config().enabled {
                return write_response(
                    stream,
                    Status::BadRequest,
                    br#"{"error":"Report generation is disabled","message":"Set lmyzmail.reporting.enabled=true to enable"}"#,
                    "application/json; charset=UTF-8",
                )
                .await;
            }
            let Some(date) = report_date(date.as_deref()) else {
                return write_response(
                    stream,
                    Status::BadRequest,
                    br#"{"error":"Invalid date format","message":"Use ISO format: YYYY-MM-DD"}"#,
                    "application/json; charset=UTF-8",
                )
                .await;
            };
            match reporting
                .generate_all(date, &config.domain, outbound, cancellation)
                .await
            {
                Ok(summary) => {
                    let date_text = date.to_string();
                    write_json_response(
                        stream,
                        Status::Ok,
                        &ReportExecutionSummary {
                            date: &date_text,
                            dmarc_sent: summary.dmarc_sent,
                            dmarc_failed: summary.dmarc_failed,
                            tls_sent: summary.tls_sent,
                            tls_failed: summary.tls_failed,
                            error: summary.error.as_deref().unwrap_or("none"),
                        },
                    )
                    .await
                }
                Err(_) => {
                    write_json_error(stream, Status::InternalServerError, "internal_error").await
                }
            }
        }
        ParsedRequest::ReportDomain { domain, date } => {
            if !reporting.config().enabled {
                return write_json_error(
                    stream,
                    Status::BadRequest,
                    "Report generation is disabled",
                )
                .await;
            }
            let Some(date) = report_date(date.as_deref()) else {
                return write_json_error(stream, Status::BadRequest, "Invalid date format").await;
            };
            match reporting
                .generate_for_domain(
                    &domain,
                    date,
                    &config.domain,
                    outbound,
                    cancellation,
                )
                .await
            {
                Ok(result) => write_json_response(stream, Status::Ok, &result).await,
                Err(_) => {
                    write_json_error(stream, Status::InternalServerError, "internal_error").await
                }
            }
        }
        ParsedRequest::CringeInvalidInput => write_cringe_error(stream, CringeError::InvalidInput).await,
        ParsedRequest::CringeStats => {
            match cringe.stats(&config.cringe_decay, cancellation).await {
                Ok(stats) => write_json_response(stream, Status::Ok, &stats).await,
                Err(error) => write_cringe_error(stream, error).await,
            }
        }
        ParsedRequest::CringeList(query) => {
            match cringe.list(query, cancellation).await {
                Ok(mut page) => {
                    let ips = page.content.iter().map(|ip| clean_ip_address(&ip.ip_address)).collect();
                    match xdp.batch_status(ips, cancellation).await {
                        Ok(statuses) => {
                            for (ip, status) in page.content.iter_mut().zip(statuses) {
                                ip.xdp_banned = status.banned;
                                ip.whitelisted = status.whitelisted;
                            }
                            write_json_response(stream, Status::Ok, &page).await
                        }
                        Err(_) => write_json_error(stream, Status::InternalServerError, "internal_error").await,
                    }
                }
                Err(error) => write_cringe_error(stream, error).await,
            }
        }
        ParsedRequest::CringeAbove { min_score, current } => {
            match cringe.above_score(min_score, current, cancellation).await {
                Ok(items) => write_json_response(stream, Status::Ok, &items).await,
                Err(error) => write_cringe_error(stream, error).await,
            }
        }
        ParsedRequest::CringeInsults(query) => {
            match cringe.insults(query, cancellation).await {
                Ok(page) => write_json_response(stream, Status::Ok, &page).await,
                Err(error) => write_cringe_error(stream, error).await,
            }
        }
        ParsedRequest::CringeActivities {
            ip_address,
            page,
            size,
        } => {
            let cleaned = clean_ip_address(&ip_address);
            match cringe
                .activities(&cleaned, Some(&ip_address), page, size, cancellation)
                .await
            {
                Ok(page) => write_json_response(stream, Status::Ok, &page).await,
                Err(error) => write_cringe_error(stream, error).await,
            }
        }
        ParsedRequest::CringeExport {
            min_score,
            score_type,
        } => {
            let current = score_type.eq_ignore_ascii_case("current");
            match cringe.above_score(min_score, current, cancellation).await {
                Ok(items) => {
                    let mut body = format!(
                        "# Skibidi Cringe IP Export\n# Score Type: {score_type}\n# Min Score: {min_score}\n# Total IPs: {}\n# Format: IP<tab>TotalScore<tab>CurrentScore<tab>ActivityCount\n#\n",
                        items.len()
                    );
                    for item in items {
                        use std::fmt::Write as _;
                        let _ = writeln!(
                            body,
                            "{}\t{}\t{}\t{}",
                            clean_ip_address(&item.ip_address),
                            item.total_score,
                            item.current_score,
                            item.activity_count
                        );
                    }
                    write_response(
                        stream,
                        Status::Ok,
                        body.as_bytes(),
                        "text/plain; charset=UTF-8",
                    )
                    .await
                }
                Err(error) => write_cringe_error(stream, error).await,
            }
        }
        ParsedRequest::CringeDecay => {
            match cringe_decay::perform_decay(
                cringe,
                xdp_sync,
                &config.cringe_decay,
                cancellation,
            )
            .await
            {
                Ok(result) => write_json_response(stream, Status::Ok, &result).await,
                Err(error) => write_cringe_error(stream, error).await,
            }
        }
        ParsedRequest::CringeDecayConfig => {
            write_json_response(
                stream,
                Status::Ok,
                &cringe_decay::config_info(&config.cringe_decay),
            )
            .await
        }
        ParsedRequest::CringeDecayEstimate(ip_address) => {
            let cleaned = clean_ip_address(&ip_address);
            match cringe.current_score(&cleaned, cancellation).await {
                Ok(Some(current_score)) => {
                    match cringe_decay::estimate(
                        cleaned,
                        current_score,
                        &config.cringe_decay,
                    ) {
                        Ok(estimate) => {
                            write_json_response(stream, Status::Ok, &estimate).await
                        }
                        Err(DecayEstimateError::Disabled) => {
                            write_json_error(stream, Status::BadRequest, "decay_disabled").await
                        }
                        Err(DecayEstimateError::Overflow) => {
                            write_json_error(stream, Status::InternalServerError, "internal_error")
                                .await
                        }
                    }
                }
                Ok(None) => write_not_found(stream).await,
                Err(error) => write_cringe_error(stream, error).await,
            }
        }
        ParsedRequest::XdpStatus => {
            let status = xdp.status(cancellation).await;
            write_json_response(stream, Status::Ok, &status).await
        }
        ParsedRequest::XdpBan { ip, reason } => {
            let Ok(reason) = reason else {
                return write_json_error(stream, Status::InternalServerError, "internal_error")
                    .await;
            };
            if !xdp.ready() {
                return write_response(
                    stream,
                    Status::Ok,
                    br#"{"success":false,"message":"XDP Firewall is not ready"}"#,
                    "application/json; charset=UTF-8",
                )
                .await;
            }
            let Some(ip) = ip else {
                return write_json_error(stream, Status::InternalServerError, "internal_error")
                    .await;
            };
            match xdp.ban(&ip, reason, cancellation).await {
                Ok(success) => write_json_response(
                    stream,
                    Status::Ok,
                    &XdpBanResponse {
                        success,
                        ip: &ip,
                        reason,
                        message: if success {
                            "IP banned in XDP"
                        } else {
                            "Failed to ban IP"
                        },
                    },
                )
                .await,
                Err(_) => write_json_error(stream, Status::InternalServerError, "internal_error").await,
            }
        }
        ParsedRequest::XdpUnban(ip) => {
            if !xdp.ready() {
                return write_response(
                    stream,
                    Status::Ok,
                    br#"{"success":false,"message":"XDP Firewall is not ready"}"#,
                    "application/json; charset=UTF-8",
                )
                .await;
            }
            let Some(ip) = ip else {
                return write_json_error(stream, Status::InternalServerError, "internal_error")
                    .await;
            };
            match xdp.unban(&ip, cancellation).await {
                Ok(success) => write_json_response(
                    stream,
                    Status::Ok,
                    &XdpUnbanResponse {
                        success,
                        ip: &ip,
                        message: if success {
                            "IP unbanned from XDP"
                        } else {
                            "Failed to unban IP"
                        },
                    },
                )
                .await,
                Err(_) => write_json_error(stream, Status::InternalServerError, "internal_error").await,
            }
        }
        ParsedRequest::XdpCheck(ip) => {
            let Some(ip) = ip else {
                return write_json_error(stream, Status::InternalServerError, "internal_error")
                    .await;
            };
            match xdp.is_banned(&ip, cancellation).await {
                Ok(banned) => {
                    write_json_response(stream, Status::Ok, &XdpCheckResponse { ip: &ip, xdp_banned: banned }).await
                }
                Err(_) => write_json_error(stream, Status::InternalServerError, "internal_error").await,
            }
        }
        ParsedRequest::XdpWhitelistCheck(ip) => {
            let Some(ip) = ip else {
                return write_json_error(stream, Status::InternalServerError, "internal_error")
                    .await;
            };
            match xdp.is_whitelisted(&ip, cancellation).await {
                Ok(whitelisted) => write_json_response(
                    stream,
                    Status::Ok,
                    &XdpWhitelistResponse {
                        ip: &ip,
                        whitelisted,
                    },
                )
                .await,
                Err(_) => write_json_error(stream, Status::InternalServerError, "internal_error").await,
            }
        }
        ParsedRequest::XdpSync => match xdp_sync.perform_full_sync(cancellation).await {
            Ok(result) => write_json_response(stream, Status::Ok, &result).await,
            Err(_) => write_json_error(stream, Status::InternalServerError, "internal_error").await,
        },
        ParsedRequest::XdpClear => match xdp.clear_all(cancellation).await {
            Ok(cleared) => write_json_response(
                stream,
                Status::Ok,
                &XdpClearResponse {
                    cleared,
                    message: "All XDP bans cleared",
                },
            )
            .await,
            Err(_) => {
                write_json_error(stream, Status::InternalServerError, "internal_error").await
            }
        },
        ParsedRequest::XdpStats => match xdp.stats(cancellation).await {
            Ok(Some(stats)) => write_json_response(stream, Status::Ok, &stats).await,
            Ok(None) | Err(_) => write_not_found(stream).await,
        },
        ParsedRequest::Static(asset) => write_static_response(stream, asset).await,
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
    Send,
    WebStatusId(i64),
    WebStatusFile(String),
    WebQuota,
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
    Attachment {
        folder: String,
        file: String,
        index: i32,
    },
    Preferences,
    SavePreferences,
    Contacts,
    CreateContact,
    UpdateContact {
        id: i64,
    },
    DeleteContact {
        id: i64,
    },
    Stars {
        folder: String,
    },
    ToggleStar {
        folder: String,
        file: String,
    },
    DeleteEmail {
        folder: String,
        file: String,
    },
    Labels,
    CreateLabel,
    UpdateLabel {
        id: i64,
    },
    DeleteLabel {
        id: i64,
    },
    EmailLabels {
        folder: String,
        file: String,
    },
    AssignLabel {
        folder: String,
        file: String,
        label_id: i64,
    },
    RemoveLabel {
        folder: String,
        file: String,
        label_id: i64,
    },
}

async fn handle_authenticated_request(
    stream: TcpStream,
    request: &[u8],
    mailbox_address: &str,
    mailbox: &MailboxService,
    userdata: &UserDataService,
    outbound: &OutboundService,
    cancellation: &CancellationToken,
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
        AuthenticatedRoute::Send => {
            let Some(mut input) = parse_json_body::<SendRequest>(request) else {
                return write_json_error(stream, Status::BadRequest, "invalid_request").await;
            };
            input.from = Some(mailbox_address.to_owned());
            if input.to.is_empty() && input.cc.is_empty() && input.bcc.is_empty() {
                return write_json_error(stream, Status::BadRequest, "recipients_required").await;
            }
            match outbound
                .enqueue_with_cancellation(input, None, cancellation)
                .await
            {
                Ok(result) => {
                    write_json_response(
                        stream,
                        Status::Accepted,
                        &WebQueueSuccess {
                            queued: result.queued,
                            queue_id: result.queue_id,
                            message_id: &result.message_id,
                            status: result.status,
                            sent_file_name: Some(&result.sent_file_name),
                        },
                    )
                    .await
                }
                Err(error) => write_outbound_error(stream, error, false).await,
            }
        }
        AuthenticatedRoute::WebStatusId(queue_id) => {
            match outbound.web_status_by_id(queue_id, mailbox_address).await {
                Ok(Some(result)) => write_json_response(stream, Status::Ok, &result).await,
                Ok(None) => write_not_found(stream).await,
                Err(_) => {
                    write_json_error(stream, Status::InternalServerError, "internal_error").await
                }
            }
        }
        AuthenticatedRoute::WebStatusFile(file_name) => {
            match outbound
                .web_status_by_file(&file_name, mailbox_address)
                .await
            {
                Ok(Some(result)) => write_json_response(stream, Status::Ok, &result).await,
                Ok(None) => write_not_found(stream).await,
                Err(_) => {
                    write_json_error(stream, Status::InternalServerError, "internal_error").await
                }
            }
        }
        AuthenticatedRoute::WebQuota => match outbound.remaining_quota(mailbox_address).await {
            Ok(remaining_quota) => {
                write_json_response(
                    stream,
                    Status::Ok,
                    &crate::outbound::QuotaResponse {
                        address: mailbox_address,
                        remaining_quota,
                    },
                )
                .await
            }
            Err(_) => {
                write_json_error(stream, Status::InternalServerError, "outbound_unavailable").await
            }
        },
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
        AuthenticatedRoute::Attachment {
            folder,
            file,
            index,
        } => {
            match mailbox
                .read_attachment(mailbox_address, &folder, &file, index)
                .await
            {
                Ok(attachment) => write_attachment_response(stream, attachment).await,
                Err(MailboxError::InvalidInput(message)) => {
                    write_invalid_input(stream, &message).await
                }
                Err(MailboxError::InvalidFileName) => write_not_found(stream).await,
                Err(_) => write_not_found(stream).await,
            }
        }
        AuthenticatedRoute::Preferences => {
            match userdata
                .get_preferences(mailbox_address, cancellation)
                .await
            {
                Ok(preferences) => write_json_response(stream, Status::Ok, &preferences).await,
                Err(error) => write_userdata_error(stream, error).await,
            }
        }
        AuthenticatedRoute::SavePreferences => {
            let Some(Value::Object(preferences)) = parse_json_body::<Value>(request) else {
                return write_bad_request(stream).await;
            };
            match userdata
                .save_preferences(mailbox_address, preferences, cancellation)
                .await
            {
                Ok(()) => {
                    write_json_response(stream, Status::Ok, &SuccessResponse { success: true })
                        .await
                }
                Err(error) => write_userdata_error(stream, error).await,
            }
        }
        AuthenticatedRoute::Contacts => {
            let permit = tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "contact response cancelled"));
                }
                permit = Arc::clone(&CONTACT_RESPONSE_PERMITS).acquire_owned() => {
                    permit.map_err(|_| io::Error::other("contact response pool closed"))?
                }
            };
            match userdata.list_contacts(mailbox_address, cancellation).await {
                Ok(contacts) => {
                    write_contact_list_response(stream, contacts, permit, cancellation).await
                }
                Err(error) => write_userdata_error(stream, error).await,
            }
        }
        AuthenticatedRoute::CreateContact => {
            let Some(input) = parse_json_body::<ContactInput>(request) else {
                return write_bad_request(stream).await;
            };
            match userdata
                .add_contact(
                    mailbox_address,
                    input.name.as_deref(),
                    input.email.as_deref(),
                    input.notes.as_deref(),
                    cancellation,
                )
                .await
            {
                Ok(contact) => {
                    let Some(name) = contact.name.as_deref() else {
                        return write_userdata_error(
                            stream,
                            UserDataError::Database("created contact lacked a name".into()),
                        )
                        .await;
                    };
                    write_json_response(
                        stream,
                        Status::Created,
                        &ContactWriteResponse {
                            id: contact.id,
                            name,
                            email: &contact.email,
                        },
                    )
                    .await
                }
                Err(error) => write_userdata_error(stream, error).await,
            }
        }
        AuthenticatedRoute::UpdateContact { id } => {
            let Some(input) = parse_json_body::<ContactInput>(request) else {
                return write_bad_request(stream).await;
            };
            match userdata
                .update_contact(
                    mailbox_address,
                    id,
                    input.name.as_deref(),
                    input.email.as_deref(),
                    input.notes.as_deref(),
                    cancellation,
                )
                .await
            {
                Ok(contact) => {
                    let Some(name) = contact.name.as_deref() else {
                        return write_userdata_error(
                            stream,
                            UserDataError::Database("updated contact lacked a name".into()),
                        )
                        .await;
                    };
                    write_json_response(
                        stream,
                        Status::Ok,
                        &ContactWriteResponse {
                            id: contact.id,
                            name,
                            email: &contact.email,
                        },
                    )
                    .await
                }
                Err(error) => write_userdata_error(stream, error).await,
            }
        }
        AuthenticatedRoute::DeleteContact { id } => {
            match userdata
                .delete_contact(mailbox_address, id, cancellation)
                .await
            {
                Ok(()) => {
                    write_json_response(stream, Status::Ok, &SuccessResponse { success: true })
                        .await
                }
                Err(error) => write_userdata_error(stream, error).await,
            }
        }
        AuthenticatedRoute::Stars { folder } => {
            match mailbox.list_starred(mailbox_address, &folder).await {
                Ok(stars) => write_json_response(stream, Status::Ok, &stars).await,
                Err(MailboxError::InvalidInput(message)) => {
                    write_invalid_input(stream, &message).await
                }
                Err(_) => write_not_found(stream).await,
            }
        }
        AuthenticatedRoute::ToggleStar { folder, file } => {
            match mailbox.toggle_star(mailbox_address, &folder, &file).await {
                Ok(starred) => {
                    write_json_response(stream, Status::Ok, &StarResponse { starred }).await
                }
                Err(MailboxError::InvalidInput(message)) => {
                    write_invalid_input(stream, &message).await
                }
                Err(MailboxError::InvalidFileName) => write_not_found(stream).await,
                Err(_) => write_not_found(stream).await,
            }
        }
        AuthenticatedRoute::DeleteEmail { folder, file } => {
            match mailbox.delete_email(mailbox_address, &folder, &file).await {
                Ok(()) => {
                    write_json_response(
                        stream,
                        Status::Ok,
                        &DeleteResponse {
                            deleted: &file,
                            success: true,
                        },
                    )
                    .await
                }
                Err(MailboxError::InvalidInput(message)) => {
                    write_invalid_input(stream, &message).await
                }
                Err(MailboxError::InvalidFileName) => write_not_found(stream).await,
                Err(_) => write_not_found(stream).await,
            }
        }
        AuthenticatedRoute::Labels => match mailbox.list_labels(mailbox_address).await {
            Ok(labels) => write_json_response(stream, Status::Ok, &labels).await,
            Err(_) => write_not_found(stream).await,
        },
        AuthenticatedRoute::CreateLabel => {
            let Some(input) = parse_json_body::<LabelInput>(request) else {
                return write_bad_request(stream).await;
            };
            let Some(name) = input.name.as_deref() else {
                return write_invalid_input(stream, "Invalid label name").await;
            };
            match mailbox
                .create_label(mailbox_address, name, input.color.as_deref())
                .await
            {
                Ok(label) => {
                    write_json_response(
                        stream,
                        Status::Created,
                        &LabelWriteResponse {
                            name: &label.name,
                            id: label.id,
                            color: label.color.as_deref(),
                        },
                    )
                    .await
                }
                Err(MailboxError::InvalidInput(message)) => {
                    write_label_error(stream, &message).await
                }
                Err(_) => {
                    write_response(
                        stream,
                        Status::InternalServerError,
                        br#"{"error":"label_unavailable"}"#,
                        "application/json; charset=UTF-8",
                    )
                    .await
                }
            }
        }
        AuthenticatedRoute::UpdateLabel { id } => {
            let Some(input) = parse_json_body::<LabelInput>(request) else {
                return write_bad_request(stream).await;
            };
            let Some(name) = input.name.as_deref() else {
                return write_invalid_input(stream, "Invalid label name").await;
            };
            match mailbox
                .update_label(mailbox_address, id, name, input.color.as_deref())
                .await
            {
                Ok(label) => {
                    write_json_response(
                        stream,
                        Status::Ok,
                        &LabelWriteResponse {
                            name: &label.name,
                            id: label.id,
                            color: label.color.as_deref(),
                        },
                    )
                    .await
                }
                Err(MailboxError::InvalidInput(message)) => {
                    write_label_error(stream, &message).await
                }
                Err(_) => write_not_found(stream).await,
            }
        }
        AuthenticatedRoute::DeleteLabel { id } => {
            match mailbox.delete_label(mailbox_address, id).await {
                Ok(()) => {
                    write_json_response(stream, Status::Ok, &SuccessResponse { success: true })
                        .await
                }
                Err(MailboxError::InvalidInput(message)) => {
                    write_label_error(stream, &message).await
                }
                Err(_) => write_not_found(stream).await,
            }
        }
        AuthenticatedRoute::EmailLabels { folder, file } => {
            match mailbox.email_labels(mailbox_address, &folder, &file).await {
                Ok(labels) => write_json_response(stream, Status::Ok, &labels).await,
                Err(MailboxError::InvalidInput(message)) => {
                    write_invalid_input(stream, &message).await
                }
                Err(MailboxError::InvalidFileName) => write_not_found(stream).await,
                Err(_) => write_not_found(stream).await,
            }
        }
        AuthenticatedRoute::AssignLabel {
            folder,
            file,
            label_id,
        } => {
            match mailbox
                .assign_label(mailbox_address, &folder, &file, label_id)
                .await
            {
                Ok(()) => {
                    write_json_response(stream, Status::Ok, &SuccessResponse { success: true })
                        .await
                }
                Err(MailboxError::InvalidInput(message)) => {
                    write_label_error(stream, &message).await
                }
                Err(MailboxError::InvalidFileName) => write_not_found(stream).await,
                Err(_) => write_not_found(stream).await,
            }
        }
        AuthenticatedRoute::RemoveLabel {
            folder,
            file,
            label_id,
        } => {
            match mailbox
                .remove_label(mailbox_address, &folder, &file, label_id)
                .await
            {
                Ok(()) => {
                    write_json_response(stream, Status::Ok, &SuccessResponse { success: true })
                        .await
                }
                Err(MailboxError::InvalidInput(message)) => {
                    write_invalid_input(stream, &message).await
                }
                Err(MailboxError::InvalidFileName) => write_not_found(stream).await,
                Err(_) => write_not_found(stream).await,
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

async fn write_label_error(stream: TcpStream, message: &str) -> io::Result<()> {
    write_json_response(
        stream,
        Status::BadRequest,
        &LabelErrorResponse { error: message },
    )
    .await
}

async fn write_userdata_error(stream: TcpStream, error: UserDataError) -> io::Result<()> {
    match error {
        UserDataError::InvalidInput(message) => {
            write_json_response(
                stream,
                Status::BadRequest,
                &UserDataErrorResponse { error: &message },
            )
            .await
        }
        UserDataError::LimitExceeded => {
            write_json_error(
                stream,
                Status::ServiceUnavailable,
                "userdata_limit_exceeded",
            )
            .await
        }
        UserDataError::Cancelled | UserDataError::Database(_) | UserDataError::OutcomeUnknown => {
            write_json_error(stream, Status::InternalServerError, "userdata_unavailable").await
        }
    }
}

async fn write_bad_request(stream: TcpStream) -> io::Result<()> {
    write_response(
        stream,
        Status::BadRequest,
        br#"{"error":"bad_request"}"#,
        "application/json; charset=UTF-8",
    )
    .await
}

fn parse_json_body<T: for<'de> Deserialize<'de>>(request: &[u8]) -> Option<T> {
    serde_json::from_slice(request_body(request)?).ok()
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
        ("POST", ["web", "mail", "send"]) => Ok(Some(AuthenticatedRoute::Send)),
        ("GET", ["web", "mail", "send", "status", queue_id]) => Ok(Some(
            AuthenticatedRoute::WebStatusId(queue_id.parse().map_err(|_| ())?),
        )),
        ("GET", ["web", "mail", "send", "status", "file", file_name]) => {
            Ok(Some(AuthenticatedRoute::WebStatusFile(decode(file_name)?)))
        }
        ("GET", ["web", "mail", "quota"]) => Ok(Some(AuthenticatedRoute::WebQuota)),
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
        ("GET", ["web", "mail", "attachment", folder, file, index]) => {
            Ok(Some(AuthenticatedRoute::Attachment {
                folder: decode(folder)?,
                file: decode(file)?,
                index: index.parse().map_err(|_| ())?,
            }))
        }
        ("GET", ["web", "userdata", "preferences"]) => Ok(Some(AuthenticatedRoute::Preferences)),
        ("POST", ["web", "userdata", "preferences"]) => {
            Ok(Some(AuthenticatedRoute::SavePreferences))
        }
        ("GET", ["web", "userdata", "contacts"]) => Ok(Some(AuthenticatedRoute::Contacts)),
        ("POST", ["web", "userdata", "contacts"]) => Ok(Some(AuthenticatedRoute::CreateContact)),
        ("PUT", ["web", "userdata", "contacts", id]) => {
            Ok(Some(AuthenticatedRoute::UpdateContact {
                id: decode(id)?.parse().map_err(|_| ())?,
            }))
        }
        ("DELETE", ["web", "userdata", "contacts", id]) => {
            Ok(Some(AuthenticatedRoute::DeleteContact {
                id: decode(id)?.parse().map_err(|_| ())?,
            }))
        }
        ("GET", ["web", "userdata", "stars", folder]) => Ok(Some(AuthenticatedRoute::Stars {
            folder: decode(folder)?,
        })),
        ("POST", ["web", "mail", "star", ..]) => {
            let (folder, file) = parse_folder_file(&segments)?;
            Ok(Some(AuthenticatedRoute::ToggleStar { folder, file }))
        }
        ("DELETE", ["web", "mail", folder, file]) => Ok(Some(AuthenticatedRoute::DeleteEmail {
            folder: decode(folder)?,
            file: decode(file)?,
        })),
        ("GET", ["web", "userdata", "labels"]) => Ok(Some(AuthenticatedRoute::Labels)),
        ("POST", ["web", "userdata", "labels"]) => Ok(Some(AuthenticatedRoute::CreateLabel)),
        ("PUT", ["web", "userdata", "labels", id]) => Ok(Some(AuthenticatedRoute::UpdateLabel {
            id: id.parse().map_err(|_| ())?,
        })),
        ("DELETE", ["web", "userdata", "labels", id]) => {
            Ok(Some(AuthenticatedRoute::DeleteLabel {
                id: id.parse().map_err(|_| ())?,
            }))
        }
        ("GET", ["web", "userdata", "labels", "email", folder, file]) => {
            Ok(Some(AuthenticatedRoute::EmailLabels {
                folder: decode(folder)?,
                file: decode(file)?,
            }))
        }
        ("POST", ["web", "userdata", "labels", "email", folder, file, label_id]) => {
            Ok(Some(AuthenticatedRoute::AssignLabel {
                folder: decode(folder)?,
                file: decode(file)?,
                label_id: label_id.parse().map_err(|_| ())?,
            }))
        }
        ("DELETE", ["web", "userdata", "labels", "email", folder, file, label_id]) => {
            Ok(Some(AuthenticatedRoute::RemoveLabel {
                folder: decode(folder)?,
                file: decode(file)?,
                label_id: label_id.parse().map_err(|_| ())?,
            }))
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

fn parse_cringe_insults(path: &str) -> ParsedRequest {
    let query = path.split_once('?').map_or("", |(_, query)| query);
    let mut page = 0_i64;
    let mut size = 50_i64;
    let mut search = String::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "page" => match value.parse() {
                Ok(value) => page = value,
                Err(_) => return ParsedRequest::BadRequest,
            },
            "size" => match value.parse() {
                Ok(value) => size = value,
                Err(_) => return ParsedRequest::BadRequest,
            },
            "search" => search = value.into_owned(),
            _ => {}
        }
    }
    ParsedRequest::CringeInsults(PageQuery { page, size, search })
}

fn parse_cringe_list(path: &str) -> ParsedRequest {
    // The frozen request binder selects the first value and applies defaults to
    // both absent and empty parameters. Do not let a duplicate override it.
    let value = |key| query_value(path, key).filter(|value| !value.is_empty());
    let page = value("page").map_or(Ok(0), |value| value.parse());
    let size = value("size").map_or(Ok(50), |value| value.parse());
    let (Ok(page), Ok(size)) = (page, size) else {
        return ParsedRequest::CringeInvalidInput;
    };
    ParsedRequest::CringeList(IpListQuery {
        page,
        size,
        sort_by: value("sortBy").unwrap_or_else(|| "currentScore".into()),
        sort_dir: value("sortDir").unwrap_or_else(|| "desc".into()),
        search: value("search").unwrap_or_default(),
    })
}

fn query_value(path: &str, key: &str) -> Option<String> {
    let query = path.split_once('?').map(|(_, query)| query)?;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.into_owned())
}

fn report_domain_path(path: &str) -> Option<&str> {
    let domain = path.strip_prefix("/api/reports/domain/")?;
    (!domain.is_empty() && !domain.contains('/')).then_some(domain)
}

fn report_addresses_path(path: &str) -> Option<&str> {
    let domain = path.strip_prefix("/api/reports/addresses/")?;
    (!domain.is_empty() && !domain.contains('/')).then_some(domain)
}

fn report_date(value: Option<&str>) -> Option<NaiveDate> {
    match value {
        None => Utc::now().date_naive().pred_opt(),
        Some(value) if value.trim().is_empty() => Utc::now().date_naive().pred_opt(),
        Some(value) => NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .ok()
            .filter(|date| date.format("%Y-%m-%d").to_string() == value),
    }
}

fn parse_cringe_above_score(path: &str) -> ParsedRequest {
    let (route, query) = path.split_once('?').map_or((path, ""), |parts| parts);
    let Some(value) = route.strip_prefix("/api/cringe-ips/above-score/") else {
        return ParsedRequest::NotFound;
    };
    let Some(min_score) = percent_decode_str(value)
        .decode_utf8()
        .ok()
        .and_then(|v| v.parse().ok())
    else {
        return ParsedRequest::BadRequest;
    };
    let current = url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "scoreType")
        .is_some_and(|(_, value)| value.eq_ignore_ascii_case("current"));
    ParsedRequest::CringeAbove { min_score, current }
}

fn parse_cringe_export(path: &str) -> ParsedRequest {
    let query = path.split_once('?').map_or("", |(_, query)| query);
    let mut min_score = 50_i32;
    let mut score_type = "current".to_owned();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "minScore" => match value.parse() {
                Ok(value) => min_score = value,
                Err(_) => return ParsedRequest::BadRequest,
            },
            "scoreType" => score_type = value.into_owned(),
            _ => {}
        }
    }
    ParsedRequest::CringeExport {
        min_score,
        score_type,
    }
}

fn parse_cringe_ip_route(path: &str) -> ParsedRequest {
    let (route, _) = path.split_once('?').map_or((path, ""), |parts| parts);
    let suffix = route.strip_prefix("/api/cringe-ips/").unwrap_or_default();
    let parts = suffix.split('/').collect::<Vec<_>>();
    if parts.len() == 2 && parts[1] == "activities" {
        let Ok(ip_address) = percent_decode_str(parts[0]).decode_utf8() else {
            return ParsedRequest::BadRequest;
        };
        let query = path.split_once('?').map_or("", |(_, query)| query);
        let mut page = 0_i64;
        let mut size = 100_i64;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "page" => match value.parse() {
                    Ok(value) => page = value,
                    Err(_) => return ParsedRequest::BadRequest,
                },
                "size" => match value.parse() {
                    Ok(value) => size = value,
                    Err(_) => return ParsedRequest::BadRequest,
                },
                _ => {}
            }
        }
        return ParsedRequest::CringeActivities {
            ip_address: ip_address.into_owned(),
            page,
            size,
        };
    }
    if parts.len() == 2 && parts[1] == "decay-estimate" {
        return percent_decode_str(parts[0])
            .decode_utf8()
            .map(|ip_address| ParsedRequest::CringeDecayEstimate(ip_address.into_owned()))
            .unwrap_or(ParsedRequest::BadRequest);
    }
    ParsedRequest::NotFound
}

fn clean_ip_address(value: &str) -> String {
    let mut cleaned = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if character <= '\u{1f}' || character == '\u{7f}' {
            continue;
        }
        if character == '%' {
            for _ in 0..2 {
                if chars.peek().is_some_and(|next| next.is_ascii_hexdigit()) {
                    chars.next();
                } else {
                    break;
                }
            }
            continue;
        }
        cleaned.push(character);
    }
    cleaned
        .trim_matches(|character| u32::from(character) <= 0x20)
        .to_owned()
}

fn is_web_multipart_form_request(request: &[u8]) -> bool {
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let Ok(headers) = std::str::from_utf8(&request[..header_end]) else {
        return false;
    };
    let mut lines = headers.split("\r\n");
    let Some(request_line) = lines.next() else {
        return false;
    };
    let mut fields = request_line.split(' ');
    let (Some(method), Some(path), Some("HTTP/1.1"), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return false;
    };
    if method != "POST"
        || path.split_once('?').map_or(path, |(route, _)| route) != "/web/mail/send/multipart"
    {
        return false;
    }
    lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && value
                    .trim_start()
                    .get(.."multipart/form-data".len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("multipart/form-data"))
        })
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_web_multipart_connection(
    mut socket: TcpStream,
    peer_ip: IpAddr,
    request: Vec<u8>,
    max_multipart_request_bytes: usize,
    config: &RuntimeConfig,
    auth: &AuthService,
    outbound: &OutboundService,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    match parse_request(&request, max_multipart_request_bytes, config) {
        ParsedRequest::PayloadTooLarge => return write_empty_payload_too_large(socket).await,
        ParsedRequest::MultipartSession => {}
        ParsedRequest::BadRequest => {
            return write_json_error(socket, Status::BadRequest, "bad_request").await;
        }
        _ => return write_json_error(socket, Status::InternalServerError, "internal_error").await,
    }
    let client_ip = extract_client_ip(&request, peer_ip, config);
    if let Some(expires_at) = auth.ban_expiry(&client_ip).await {
        let body = serde_json::to_vec(&IpBannedResponse {
            error: "ip_banned",
            message: "Your IP has been temporarily banned due to suspicious activity.",
            expires_at: &expires_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        })
        .map_err(io::Error::other)?;
        return write_response(
            socket,
            Status::Forbidden,
            &body,
            "application/json; charset=UTF-8",
        )
        .await;
    }
    let Some(token) = request_header(&request, "x-session-token").filter(|value| !value.is_empty())
    else {
        return write_empty_unauthorized(socket).await;
    };
    let address = match auth
        .validate_token_with_cancellation(&token, cancellation)
        .await
    {
        Ok(Some(address)) => address,
        Ok(None) => return write_empty_unauthorized(socket).await,
        Err(_) => return write_empty_service_unavailable(socket).await,
    };
    let content_type = request_header(&request, "content-type").unwrap_or_default();
    let boundary = match web_multipart::boundary(&content_type) {
        Ok(boundary) => boundary,
        Err(_) => {
            return write_json_error(socket, Status::InternalServerError, "internal_error").await;
        }
    };
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return write_json_error(socket, Status::BadRequest, "bad_request").await;
    };
    let declared_length = header_content_length(&request[..header_end]).unwrap_or(0);
    let body_start = header_end + 4;
    let prefix_length = request
        .len()
        .saturating_sub(body_start)
        .min(declared_length);
    let prefix = Bytes::copy_from_slice(&request[body_start..body_start + prefix_length]);
    let remaining = declared_length - prefix_length;
    let prefix_stream = stream::once(async move { Ok::<Bytes, io::Error>(prefix) });
    let socket_stream = ReaderStream::new((&mut socket).take(remaining as u64));
    let body_stream = prefix_stream.chain(socket_stream);
    let upload_root = config
        .preferred_value(
            "lmyzmail.http.upload-temp-dir",
            "botmail.http.upload-temp-dir",
        )
        .map(PathBuf::from)
        .unwrap_or_else(|| config.maildir.join(".lmyzmail-upload"));
    let mut parsed = match web_multipart::parse(
        body_stream,
        boundary,
        &upload_root,
        max_multipart_request_bytes as u64,
        config.limits.max_attachment_size_bytes,
        config.limits.max_total_attachments_size_bytes,
    )
    .await
    {
        Ok(parsed) => parsed,
        Err(error) => return write_web_multipart_parse_error(socket, error).await,
    };
    let attachments = parsed.attachment_inputs();
    let mut input = parsed.take_request();
    input.from = Some(address);
    let result = outbound
        .enqueue_streaming_with_cancellation(input, attachments, cancellation)
        .await;
    drop(parsed);
    match result {
        Ok(result) => {
            write_json_response(
                socket,
                Status::Accepted,
                &WebQueueSuccess {
                    queued: result.queued,
                    queue_id: result.queue_id,
                    message_id: &result.message_id,
                    status: result.status,
                    sent_file_name: Some(&result.sent_file_name),
                },
            )
            .await
        }
        Err(error) => write_web_multipart_outbound_error(socket, error).await,
    }
}

async fn read_request_head(stream: &mut TcpStream, max_header_bytes: usize) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024.min(max_header_bytes));
    let mut chunk = [0_u8; 1024];
    loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Ok(request);
        }
        if request.len().saturating_add(count) > max_header_bytes.saturating_add(1024) {
            request.resize(max_header_bytes.saturating_add(1), 0);
            return Ok(request);
        }
        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
    }
}

async fn complete_request(
    stream: &mut TcpStream,
    request: &mut Vec<u8>,
    max_request_bytes: usize,
) -> io::Result<()> {
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(());
    };
    let length = header_content_length(&request[..header_end]).unwrap_or(0);
    let required = header_end.saturating_add(4).saturating_add(length);
    if length > max_request_bytes || required > max_request_bytes {
        request.clear();
        request.resize(max_request_bytes.saturating_add(1), 0);
        return Ok(());
    }
    request.truncate(request.len().min(required));
    let mut chunk = [0_u8; 1024];
    while request.len() < required {
        let to_read = (required - request.len()).min(chunk.len());
        let count = stream.read(&mut chunk[..to_read]).await?;
        if count == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..count]);
    }
    request.truncate(required);
    Ok(())
}

#[cfg(test)]
async fn read_request(stream: &mut TcpStream, max_request_bytes: usize) -> io::Result<Vec<u8>> {
    let mut request = read_request_head(stream, max_request_bytes).await?;
    complete_request(stream, &mut request, max_request_bytes).await?;
    Ok(request)
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
    Static(StaticAsset),
    Health,
    Skibidi,
    ApiStatus,
    ApiSend,
    ApiPoll,
    ApiRaw,
    ApiRawDecoded,
    ApiStatusById(i64),
    ApiStatusByMessage(String),
    ApiQuota(String),
    ApiQuotaMissing,
    StressStart,
    StressReset,
    StressStatus,
    StressCleanup,
    ReportStatus,
    ReportAddresses(String),
    ReportDomains(Option<String>),
    ReportTrigger(Option<String>),
    ReportDomain {
        domain: String,
        date: Option<String>,
    },
    CringeInvalidInput,
    CringeStats,
    CringeList(IpListQuery),
    CringeAbove {
        min_score: i32,
        current: bool,
    },
    CringeInsults(PageQuery),
    CringeActivities {
        ip_address: String,
        page: i64,
        size: i64,
    },
    CringeExport {
        min_score: i32,
        score_type: String,
    },
    CringeDecay,
    CringeDecayConfig,
    CringeDecayEstimate(String),
    XdpStatus,
    XdpBan {
        ip: Option<String>,
        reason: Result<i32, ()>,
    },
    XdpUnban(Option<String>),
    XdpCheck(Option<String>),
    XdpWhitelistCheck(Option<String>),
    XdpSync,
    XdpClear,
    XdpStats,
    ApiCreateMailbox,
    ApiMailboxExists(String),
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
    if method == "GET"
        && let Some(asset) = web_static::resolve(routing_path)
    {
        return ParsedRequest::Static(asset);
    }
    match (method, routing_path) {
        ("GET", "/api/health") => ParsedRequest::Health,
        ("GET", "/api/skibidi") => ParsedRequest::Skibidi,
        ("GET", "/web/domains") => ParsedRequest::WebDomains,
        ("GET", "/web/config") => ParsedRequest::WebConfig,
        ("POST", "/web/login") => ParsedRequest::WebLogin,
        ("POST", "/web/register") => ParsedRequest::WebRegister,
        ("POST", "/web/logout") => ParsedRequest::WebLogout,
        ("POST", "/api/mailboxes") => match api_permission(config, api_key, true) {
            ApiPermission::Granted => ParsedRequest::ApiCreateMailbox,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
        },
        ("GET", path) if mailbox_exists_path(path).is_some() => {
            match api_permission(config, api_key, false) {
                ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
                ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
                ApiPermission::Granted => {
                    percent_decode_str(mailbox_exists_path(path).unwrap_or_default())
                        .decode_utf8()
                        .map(|address| ParsedRequest::ApiMailboxExists(address.into_owned()))
                        .unwrap_or(ParsedRequest::BadRequest)
                }
            }
        }
        ("POST", "/api/mail/send") => match api_permission(config, api_key, true) {
            ApiPermission::Granted => ParsedRequest::ApiSend,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
        },
        ("POST", "/api/mail/poll") => match api_permission(config, api_key, false) {
            ApiPermission::Granted => ParsedRequest::ApiPoll,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
        },
        ("POST", "/api/mail/raw") => match api_permission(config, api_key, false) {
            ApiPermission::Granted => ParsedRequest::ApiRaw,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
        },
        ("POST", "/api/mail/rawDecoded") => match api_permission(config, api_key, false) {
            ApiPermission::Granted => ParsedRequest::ApiRawDecoded,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
        },
        ("GET", path) if path.starts_with("/api/mail/status/") => {
            match api_permission(config, api_key, false) {
                ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
                ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
                ApiPermission::Granted => {
                    let suffix = path.strip_prefix("/api/mail/status/").unwrap_or_default();
                    if let Some(value) = suffix.strip_prefix("message/") {
                        percent_decode_str(value)
                            .decode_utf8()
                            .map(|value| ParsedRequest::ApiStatusByMessage(value.into_owned()))
                            .unwrap_or(ParsedRequest::BadRequest)
                    } else {
                        suffix
                            .parse::<i64>()
                            .map(ParsedRequest::ApiStatusById)
                            .unwrap_or(ParsedRequest::BadRequest)
                    }
                }
            }
        }
        ("GET", "/api/mail/quota") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => {
                let address = path
                    .split_once('?')
                    .map(|(_, query)| query)
                    .unwrap_or_default();
                let value = url::form_urlencoded::parse(address.as_bytes())
                    .find(|(key, _)| key == "address")
                    .map(|(_, value)| value.into_owned());
                value
                    .filter(|value| !value.trim().is_empty())
                    .map_or(ParsedRequest::ApiQuotaMissing, ParsedRequest::ApiQuota)
            }
        },
        ("GET", "/api/reports/status") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => ParsedRequest::ReportStatus,
        },
        ("POST", "/api/stress/start") => match api_permission(config, api_key, true) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Granted => ParsedRequest::StressStart,
        },
        ("POST", "/api/stress/reset") => match api_permission(config, api_key, true) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Granted => ParsedRequest::StressReset,
        },
        ("POST", "/api/stress/status") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => ParsedRequest::StressStatus,
        },
        ("POST", "/api/stress/cleanup") => match api_permission(config, api_key, true) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Granted => ParsedRequest::StressCleanup,
        },
        ("GET", routing) if report_addresses_path(routing).is_some() => {
            match api_permission(config, api_key, false) {
                ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
                ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
                ApiPermission::Granted => {
                    let encoded = report_addresses_path(routing).unwrap_or_default();
                    percent_decode_str(encoded)
                        .decode_utf8()
                        .map(|domain| ParsedRequest::ReportAddresses(domain.into_owned()))
                        .unwrap_or(ParsedRequest::BadRequest)
                }
            }
        }
        ("GET", "/api/reports/domains") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => ParsedRequest::ReportDomains(query_value(path, "date")),
        },
        ("POST", "/api/reports/trigger") => match api_permission(config, api_key, true) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Granted => ParsedRequest::ReportTrigger(query_value(path, "date")),
        },
        ("POST", routing) if report_domain_path(routing).is_some() => {
            match api_permission(config, api_key, true) {
                ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
                ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
                ApiPermission::Granted => {
                    let encoded = report_domain_path(routing).unwrap_or_default();
                    percent_decode_str(encoded)
                        .decode_utf8()
                        .map(|domain| ParsedRequest::ReportDomain {
                            domain: domain.into_owned(),
                            date: query_value(path, "date"),
                        })
                        .unwrap_or(ParsedRequest::BadRequest)
                }
            }
        }
        ("GET", "/api/xdp-firewall/status") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => ParsedRequest::XdpStatus,
        },
        ("POST", "/api/xdp-firewall/ban") => match api_permission(config, api_key, true) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Granted => ParsedRequest::XdpBan {
                ip: query_value(path, "ip"),
                reason: query_value(path, "reason")
                    .map_or(Ok(0), |value| value.parse::<i32>().map_err(|_| ())),
            },
        },
        ("POST", "/api/xdp-firewall/unban") => match api_permission(config, api_key, true) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Granted => ParsedRequest::XdpUnban(query_value(path, "ip")),
        },
        ("GET", "/api/xdp-firewall/check") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => ParsedRequest::XdpCheck(query_value(path, "ip")),
        },
        ("GET", "/api/xdp-firewall/whitelist/check") => {
            match api_permission(config, api_key, false) {
                ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
                ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
                ApiPermission::Granted => ParsedRequest::XdpWhitelistCheck(query_value(path, "ip")),
            }
        }
        ("POST", "/api/xdp-firewall/sync") => match api_permission(config, api_key, true) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Granted => ParsedRequest::XdpSync,
        },
        ("DELETE", "/api/xdp-firewall/clear") => match api_permission(config, api_key, true) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Granted => ParsedRequest::XdpClear,
        },
        ("GET", "/api/xdp-firewall/stats") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => ParsedRequest::XdpStats,
        },
        ("GET", "/api/cringe-ips") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => parse_cringe_list(path),
        },
        ("GET", "/api/cringe-ips/insults") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => parse_cringe_insults(path),
        },
        ("GET", "/api/cringe-ips/stats") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => ParsedRequest::CringeStats,
        },
        ("GET", "/api/cringe-ips/export") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => parse_cringe_export(path),
        },
        ("POST", "/api/cringe-ips/decay") => match api_permission(config, api_key, true) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenWrite,
            ApiPermission::Granted => ParsedRequest::CringeDecay,
        },
        ("GET", "/api/cringe-ips/decay-config") => match api_permission(config, api_key, false) {
            ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
            ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
            ApiPermission::Granted => ParsedRequest::CringeDecayConfig,
        },
        ("GET", routing) if routing.starts_with("/api/cringe-ips/above-score/") => {
            match api_permission(config, api_key, false) {
                ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
                ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
                ApiPermission::Granted => parse_cringe_above_score(path),
            }
        }
        ("GET", routing) if routing.starts_with("/api/cringe-ips/") => {
            match api_permission(config, api_key, false) {
                ApiPermission::Unauthorized => ParsedRequest::Unauthorized,
                ApiPermission::Forbidden => ParsedRequest::ForbiddenRead,
                ApiPermission::Granted => parse_cringe_ip_route(path),
            }
        }
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

fn mailbox_exists_path(path: &str) -> Option<&str> {
    let address = path
        .strip_prefix("/api/mailboxes/")?
        .strip_suffix("/exists")?;
    (!address.is_empty() && !address.contains('/')).then_some(address)
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
#[serde(rename_all = "camelCase")]
struct ReportingStatusResponse<'a> {
    enabled: bool,
    auto_send_enabled: bool,
    min_volume_for_report: i32,
    dmarc_report_sender_address: &'a str,
    tls_report_sender_address: &'a str,
    organization_name: &'a str,
    http_delivery_enabled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportDomainsResponse<'a> {
    date: &'a str,
    min_volume: i32,
    dmarc_domains: &'a [String],
    tls_domains: &'a [String],
}

#[derive(Serialize)]
struct ReportAddressListResponse<'a> {
    mailto: &'a [String],
    https: &'a [String],
}

#[derive(Serialize)]
struct ReportAddressesResponse<'a> {
    domain: &'a str,
    dmarc: ReportAddressListResponse<'a>,
    tlsrpt: ReportAddressListResponse<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportExecutionSummary<'a> {
    date: &'a str,
    dmarc_sent: i32,
    dmarc_failed: i32,
    tls_sent: i32,
    tls_failed: i32,
    error: &'a str,
}

#[derive(Serialize)]
struct XdpBanResponse<'a> {
    success: bool,
    ip: &'a str,
    reason: i32,
    message: &'static str,
}

#[derive(Serialize)]
struct XdpUnbanResponse<'a> {
    success: bool,
    ip: &'a str,
    message: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct XdpCheckResponse<'a> {
    ip: &'a str,
    xdp_banned: bool,
}

#[derive(Serialize)]
struct XdpWhitelistResponse<'a> {
    ip: &'a str,
    whitelisted: bool,
}

#[derive(Serialize)]
struct XdpClearResponse {
    cleared: usize,
    message: &'static str,
}

#[derive(Serialize)]
struct ApiDomains<'a> {
    receivable: Vec<&'a str>,
    sendable: Vec<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebDomainsResponse<'a> {
    receivable: Vec<&'a str>,
    registration_enabled: bool,
    sendable: Vec<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebConfigResponse<'a> {
    domains: Vec<&'a str>,
    max_attachment_size_bytes: u64,
    #[serde(rename = "maxAttachmentSizeMB")]
    max_attachment_size_mb: u64,
    max_email_size_bytes: u64,
    #[serde(rename = "maxEmailSizeMB")]
    max_email_size_mb: u64,
    max_total_attachments_size_bytes: u64,
    sendable_domains: Vec<&'a str>,
    show_internet_nl_badge: bool,
}

#[derive(Debug, Deserialize)]
struct Credentials {
    address: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiPollRequest {
    address: Option<String>,
    password: Option<String>,
    since_epoch_millis: Option<i64>,
    limit: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct ApiRawRequest {
    address: Option<String>,
    password: Option<String>,
    file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiRawDecodedRequest {
    address: Option<String>,
    password: Option<String>,
    file: Option<String>,
    html: Option<bool>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ApiMailboxError {
    InvalidRequest,
    InvalidCredentials,
    IpBanned,
    Backend,
}

async fn authenticate_api_mailbox(
    auth: &AuthService,
    address: Option<&str>,
    password: Option<&str>,
    client_ip: &str,
    cancellation: &CancellationToken,
) -> Result<String, ApiMailboxError> {
    let Some(address) = address.filter(|value| !value.trim().is_empty()) else {
        return Err(ApiMailboxError::InvalidRequest);
    };
    let Some(password) = password.filter(|value| !value.trim().is_empty()) else {
        return Err(ApiMailboxError::InvalidRequest);
    };
    match auth
        .verify_mailbox_credentials_with_cancellation(address, password, client_ip, cancellation)
        .await
    {
        Ok(CredentialOutcome::Valid { address }) => Ok(address),
        Ok(CredentialOutcome::Invalid { ip_banned: true }) => Err(ApiMailboxError::IpBanned),
        Ok(CredentialOutcome::Invalid { ip_banned: false }) => {
            Err(ApiMailboxError::InvalidCredentials)
        }
        Err(_) => Err(ApiMailboxError::Backend),
    }
}

#[derive(Debug, Serialize)]
struct MailboxCreationResponse<'a> {
    id: i64,
    address: &'a str,
}

#[derive(Debug, Serialize)]
struct MailboxExistsResponse<'a> {
    address: &'a str,
    exists: bool,
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
struct StarResponse {
    starred: bool,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Serialize)]
struct DeleteResponse<'a> {
    deleted: &'a str,
    success: bool,
}

#[derive(Serialize)]
struct LabelWriteResponse<'a> {
    name: &'a str,
    id: i64,
    color: Option<&'a str>,
}

#[derive(Serialize)]
struct LabelErrorResponse<'a> {
    error: &'a str,
}

#[derive(Debug, Deserialize)]
struct LabelInput {
    name: Option<String>,
    color: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ContactInput {
    name: Option<String>,
    email: Option<String>,
    notes: Option<String>,
}

#[derive(Serialize)]
struct ContactWriteResponse<'a> {
    id: i64,
    name: &'a str,
    email: &'a str,
}

#[derive(Serialize)]
struct UserDataErrorResponse<'a> {
    error: &'a str,
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
    write_response_head(&mut stream, status, body.len(), content_type).await?;
    stream.write_all(body).await
}

async fn write_static_response(mut stream: TcpStream, asset: StaticAsset) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nContent-Type: {}\r\n\r\n",
        asset.body.len(),
        asset.content_type,
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(asset.body).await
}

async fn write_response_head(
    stream: &mut TcpStream,
    status: Status,
    content_length: usize,
    content_type: &str,
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\n\r\n",
        status.code(),
        status.reason(),
        content_type,
        content_length
    );
    stream.write_all(head.as_bytes()).await
}

async fn write_contact_list_response(
    mut stream: TcpStream,
    contacts: Vec<ContactRecord>,
    permit: OwnedSemaphorePermit,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    let (length_sender, length_receiver) = oneshot::channel();
    let (chunk_sender, mut chunk_receiver) = mpsc::channel::<Vec<u8>>(JSON_STREAM_CHANNEL_CHUNKS);
    let serialization_cancellation = cancellation.clone();
    let producer = spawn_blocking(move || -> io::Result<()> {
        let _permit = permit;
        let mut counter = CountingWriter::with_cancellation(serialization_cancellation.clone());
        serde_json::to_writer(&mut counter, &contacts).map_err(io::Error::other)?;
        length_sender
            .send(counter.length)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "HTTP response was dropped"))?;

        let mut writer = ChannelWriter::new(chunk_sender, Some(serialization_cancellation));
        serde_json::to_writer(&mut writer, &contacts).map_err(io::Error::other)?;
        io::Write::flush(&mut writer)
    });

    let content_length = match length_receiver.await {
        Ok(length) => length,
        Err(_) => return join_json_producer(producer).await,
    };
    if content_length > MAX_CONTACT_WIRE_BYTES {
        drop(chunk_receiver);
        let _ = join_json_producer(producer).await;
        return write_json_error(
            stream,
            Status::ServiceUnavailable,
            "userdata_limit_exceeded",
        )
        .await;
    }
    let write_result = async {
        write_response_head(
            &mut stream,
            Status::Ok,
            content_length,
            "application/json; charset=UTF-8",
        )
        .await?;
        while let Some(chunk) = chunk_receiver.recv().await {
            stream.write_all(&chunk).await?;
        }
        Ok::<(), io::Error>(())
    }
    .await;
    drop(chunk_receiver);
    let producer_result = join_json_producer(producer).await;
    write_result?;
    producer_result
}

async fn join_json_producer(producer: JoinHandle<io::Result<()>>) -> io::Result<()> {
    producer.await.map_err(io::Error::other)?
}

#[derive(Default)]
struct CountingWriter {
    length: usize,
    cancellation: Option<CancellationToken>,
}

impl CountingWriter {
    fn with_cancellation(cancellation: CancellationToken) -> Self {
        Self {
            length: 0,
            cancellation: Some(cancellation),
        }
    }
}

impl io::Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        ensure_serialization_active(self.cancellation.as_ref())?;
        self.length = self
            .length
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("JSON response length overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ChannelWriter {
    sender: mpsc::Sender<Vec<u8>>,
    buffer: Vec<u8>,
    cancellation: Option<CancellationToken>,
}

impl ChannelWriter {
    fn new(sender: mpsc::Sender<Vec<u8>>, cancellation: Option<CancellationToken>) -> Self {
        Self {
            sender,
            buffer: Vec::with_capacity(JSON_STREAM_CHUNK_BYTES),
            cancellation,
        }
    }

    fn send_buffer(&mut self) -> io::Result<()> {
        ensure_serialization_active(self.cancellation.as_ref())?;
        if self.buffer.is_empty() {
            return Ok(());
        }
        let chunk = std::mem::replace(
            &mut self.buffer,
            Vec::with_capacity(JSON_STREAM_CHUNK_BYTES),
        );
        self.sender
            .blocking_send(chunk)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "HTTP response was dropped"))
    }
}

impl io::Write for ChannelWriter {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        ensure_serialization_active(self.cancellation.as_ref())?;
        let total = bytes.len();
        while !bytes.is_empty() {
            let available = JSON_STREAM_CHUNK_BYTES - self.buffer.len();
            let count = available.min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.buffer.len() == JSON_STREAM_CHUNK_BYTES {
                self.send_buffer()?;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buffer()
    }
}

fn ensure_serialization_active(cancellation: Option<&CancellationToken>) -> io::Result<()> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "HTTP response cancelled",
        ))
    } else {
        Ok(())
    }
}

async fn write_json_response<T: Serialize>(
    stream: TcpStream,
    status: Status,
    value: &T,
) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    write_response(stream, status, &body, "application/json; charset=UTF-8").await
}

async fn write_json_error(
    stream: TcpStream,
    status: Status,
    error: &'static str,
) -> io::Result<()> {
    #[derive(Serialize)]
    struct ErrorResponse {
        error: &'static str,
    }
    write_json_response(stream, status, &ErrorResponse { error }).await
}

async fn write_cringe_error(stream: TcpStream, error: CringeError) -> io::Result<()> {
    match error {
        CringeError::InvalidInput => {
            write_json_error(stream, Status::BadRequest, "invalid_request").await
        }
        CringeError::Cancelled => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "cringe request cancelled",
        )),
        CringeError::Timeout
        | CringeError::OutcomeUnknown
        | CringeError::CapacityExceeded
        | CringeError::Database(_) => {
            write_json_error(stream, Status::InternalServerError, "internal_error").await
        }
    }
}

async fn write_outbound_error(
    stream: TcpStream,
    error: OutboundError,
    _api: bool,
) -> io::Result<()> {
    match error {
        OutboundError::InvalidInput(code) => {
            write_json_error(stream, Status::BadRequest, code).await
        }
        OutboundError::SendingNotAllowed(domain) => {
            write_web_queue_failure(stream, format!("Sending not allowed for domain: {domain}"))
                .await
        }
        OutboundError::InvalidCredentials => {
            write_json_response(
                stream,
                Status::Unauthorized,
                &QueueFailureResponse {
                    queued: false,
                    queue_id: None,
                    message_id: None,
                    status: "REJECTED",
                    error: "Invalid credentials",
                },
            )
            .await
        }
        OutboundError::AttachmentTooLarge(filename) => {
            write_web_queue_failure(
                stream,
                format!("Attachment '{filename}' exceeds size limit"),
            )
            .await
        }
        OutboundError::AttachmentsTooLarge => {
            write_web_queue_failure(stream, "Total attachments size exceeds limit".into()).await
        }
        OutboundError::RateLimited { remaining } => {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct RateLimitResponse {
                error: &'static str,
                remaining_quota: i64,
            }
            write_json_response(
                stream,
                Status::TooManyRequests,
                &RateLimitResponse {
                    error: "rate_limit_exceeded",
                    remaining_quota: remaining,
                },
            )
            .await
        }
        OutboundError::QueueFull => {
            write_json_error(stream, Status::TooManyRequests, "queue_full").await
        }
        OutboundError::SynchronousUnsupported => {
            write_json_error(
                stream,
                Status::InternalServerError,
                "synchronous_send_unavailable",
            )
            .await
        }
        OutboundError::Database(_) | OutboundError::Unavailable => {
            write_json_error(stream, Status::InternalServerError, "outbound_unavailable").await
        }
    }
}

async fn write_web_multipart_parse_error(
    stream: TcpStream,
    error: WebMultipartError,
) -> io::Result<()> {
    match error {
        WebMultipartError::AttachmentTooLarge(filename) => {
            write_web_queue_failure(
                stream,
                format!("Attachment '{filename}' exceeds size limit"),
            )
            .await
        }
        WebMultipartError::AttachmentsTooLarge => {
            write_web_queue_failure(stream, "Total attachments size exceeds limit".into()).await
        }
        WebMultipartError::Invalid | WebMultipartError::Unavailable => {
            write_json_error(stream, Status::InternalServerError, "internal_error").await
        }
    }
}

async fn write_web_multipart_outbound_error(
    stream: TcpStream,
    error: OutboundError,
) -> io::Result<()> {
    match error {
        OutboundError::AttachmentTooLarge(filename) => {
            write_web_queue_failure(
                stream,
                format!("Attachment '{filename}' exceeds size limit"),
            )
            .await
        }
        OutboundError::AttachmentsTooLarge => {
            write_web_queue_failure(stream, "Total attachments size exceeds limit".into()).await
        }
        error => write_outbound_error(stream, error, false).await,
    }
}

async fn write_web_queue_failure(stream: TcpStream, error: String) -> io::Result<()> {
    write_json_response(
        stream,
        Status::BadRequest,
        &QueueFailureResponse {
            queued: false,
            queue_id: None,
            message_id: None,
            status: "REJECTED",
            error: &error,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QueueFailureResponse<'a> {
    queued: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<&'a str>,
    status: &'static str,
    error: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebQueueSuccess<'a> {
    queued: bool,
    queue_id: i64,
    message_id: &'a str,
    status: &'static str,
    sent_file_name: Option<&'a str>,
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

async fn write_api_raw_mail_response(
    mut stream: TcpStream,
    mut body: tokio::fs::File,
    length: u64,
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {length}\r\n\r\n"
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

async fn write_api_mailbox_error(
    stream: TcpStream,
    error: ApiMailboxError,
    include_ban_message: bool,
) -> io::Result<()> {
    match error {
        ApiMailboxError::InvalidRequest => {
            write_json_error(stream, Status::BadRequest, "invalid_request").await
        }
        ApiMailboxError::InvalidCredentials => {
            write_json_error(stream, Status::Unauthorized, "invalid_credentials").await
        }
        ApiMailboxError::IpBanned if include_ban_message => write_response(
            stream,
            Status::Forbidden,
            br#"{"error":"ip_banned","message":"Too many failed attempts. Please try again later."}"#,
            "application/json; charset=UTF-8",
        )
        .await,
        ApiMailboxError::IpBanned => write_json_error(stream, Status::Forbidden, "ip_banned").await,
        ApiMailboxError::Backend => {
            write_json_error(stream, Status::InternalServerError, "internal_error").await
        }
    }
}

async fn write_attachment_response(
    mut stream: TcpStream,
    attachment: AttachmentData,
) -> io::Result<()> {
    let content_type = safe_attachment_content_type(attachment.content_type.as_deref());
    let disposition = attachment_disposition(&attachment.filename);
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
transfer-encoding: chunked\r\n\
Content-Type: {content_type}\r\n\
Content-Disposition: {disposition}\r\n\
X-Content-Type-Options: nosniff\r\n\
Content-Security-Policy: sandbox; default-src 'none'; frame-ancestors 'none'\r\n\
Referrer-Policy: no-referrer\r\n\
Cache-Control: private, no-store\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await?;
    for chunk in attachment.body.chunks(16 * 1024) {
        stream
            .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
            .await?;
        stream.write_all(chunk).await?;
        stream.write_all(b"\r\n").await?;
    }
    stream.write_all(b"0\r\n\r\n").await
}

fn safe_attachment_content_type(declared: Option<&str>) -> &str {
    const ACTIVE_TYPES: &[&str] = &[
        "text/html",
        "application/xhtml+xml",
        "image/svg+xml",
        "application/xml",
        "text/xml",
        "application/javascript",
        "text/javascript",
        "application/ecmascript",
        "text/ecmascript",
        "application/pdf",
    ];
    let Some(declared) = declared.filter(|value| !value.trim().is_empty()) else {
        return "application/octet-stream";
    };
    if declared.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f) {
        return "application/octet-stream";
    }
    let base_type = declared
        .split_once(';')
        .map_or(declared, |(base, _)| base)
        .trim()
        .to_ascii_lowercase();
    if ACTIVE_TYPES.contains(&base_type.as_str()) || base_type.ends_with("+xml") {
        "application/octet-stream"
    } else {
        declared
    }
}

fn attachment_disposition(filename: &str) -> String {
    let encoded = url::form_urlencoded::byte_serialize(filename.as_bytes())
        .collect::<String>()
        .replace('+', "%20");
    format!("attachment; filename*=UTF-8''{encoded}")
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

async fn write_empty_payload_too_large(mut stream: TcpStream) -> io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 413 Request Entity Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await
}

async fn write_empty_service_unavailable(mut stream: TcpStream) -> io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
lmyzmail.api-keys[2].key=admin-key\n\
lmyzmail.api-keys[2].read=true\n\
lmyzmail.api-keys[2].write=true\n\
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
    fn accept_backoff_grows_to_a_hard_cap_and_resets_after_success() {
        let mut backoff = AcceptBackoff::default();
        let delays = (0..8).map(|_| backoff.next_delay()).collect::<Vec<_>>();
        assert_eq!(
            delays,
            vec![
                Duration::from_millis(25),
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(400),
                Duration::from_millis(800),
                Duration::from_secs(1),
                Duration::from_secs(1),
            ]
        );

        backoff.reset();
        assert_eq!(backoff.next_delay(), ACCEPT_RETRY_MIN_DELAY);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_accept_resource_and_network_errors_are_retryable() {
        for code in [
            1, 4, 11, 12, 23, 24, 64, 71, 92, 95, 100, 101, 103, 105, 112, 113,
        ] {
            assert!(
                is_retryable_accept_error(&io::Error::from_raw_os_error(code)),
                "Linux errno {code} must not terminate the listener"
            );
        }
        for code in [9, 14, 22, 88] {
            assert!(
                !is_retryable_accept_error(&io::Error::from_raw_os_error(code)),
                "Linux errno {code} indicates a broken listener"
            );
        }
    }

    #[tokio::test]
    async fn accept_retry_delay_prioritizes_ready_cancellation() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let retry = timeout(
            Duration::from_millis(50),
            wait_for_accept_retry(&cancellation, Duration::ZERO),
        )
        .await
        .expect("pre-cancelled retry wait must finish promptly");
        assert!(!retry);
    }

    #[tokio::test]
    async fn cancelled_accept_wins_over_a_ready_connection() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let outcome =
            select_accept(&cancellation, std::future::ready(Ok::<_, io::Error>(42_u8))).await;
        assert!(matches!(outcome, AcceptOutcome::Cancelled));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fatal_accept_cancels_cleanup_before_returning_the_error() {
        let cancellation = CancellationToken::new();
        let outcome = select_accept(
            &cancellation,
            std::future::ready(Err::<(), _>(io::Error::from_raw_os_error(22))),
        )
        .await;
        assert!(matches!(
            outcome,
            AcceptOutcome::Terminal(error) if error.raw_os_error() == Some(22)
        ));
        assert!(cancellation.is_cancelled());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn repeated_setup_emfile_backoff_persists_until_setup_succeeds() {
        let cancellation = CancellationToken::new();
        let mut backoff = AcceptBackoff::default();
        let first = prepare_connection::<(), _>(&mut backoff, &cancellation, || {
            Err(io::Error::from_raw_os_error(24))
        })
        .await;
        assert!(matches!(first, ConnectionSetupOutcome::Retry));
        assert_eq!(backoff.next_delay, Duration::from_millis(50));

        let second = prepare_connection::<(), _>(&mut backoff, &cancellation, || {
            Err(io::Error::from_raw_os_error(24))
        })
        .await;
        assert!(matches!(second, ConnectionSetupOutcome::Retry));
        assert_eq!(backoff.next_delay, Duration::from_millis(100));

        let ready = prepare_connection(&mut backoff, &cancellation, || Ok(())).await;
        assert!(matches!(ready, ConnectionSetupOutcome::Ready(())));
        assert_eq!(backoff.next_delay, ACCEPT_RETRY_MIN_DELAY);
    }

    #[tokio::test]
    async fn request_deadline_cancels_and_joins_active_work() {
        let cancellation = CancellationToken::new();
        let observed_cancellation = cancellation.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicBool::new(false));
        let request_active = Arc::clone(&active);
        let request_finished = Arc::clone(&finished);
        let request = async move {
            request_active.fetch_add(1, Ordering::AcqRel);
            observed_cancellation.cancelled().await;
            tokio::task::spawn_blocking(move || {
                std::thread::sleep(Duration::from_millis(20));
                request_finished.store(true, Ordering::Release);
            })
            .await
            .map_err(io::Error::other)?;
            request_active.fetch_sub(1, Ordering::AcqRel);
            Ok(())
        };

        let socket_closed = Arc::new(AtomicBool::new(false));
        let closed = Arc::clone(&socket_closed);
        let result = run_request_until_joined(
            request,
            &cancellation,
            Duration::from_millis(2),
            move || closed.store(true, Ordering::Release),
        )
        .await;
        assert!(result.is_ok());
        assert!(cancellation.is_cancelled());
        assert!(socket_closed.load(Ordering::Acquire));
        assert!(finished.load(Ordering::Acquire));
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn peer_close_monitor_ignores_a_clean_fin() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let cancellation = CancellationToken::new();
        let monitor = tokio::spawn(cancel_on_peer_close(server, cancellation.clone()));

        drop(client);
        monitor.await.unwrap();
        assert!(!cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn peer_close_monitor_cancels_the_request_token_on_rst() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let cancellation = CancellationToken::new();
        let monitor = tokio::spawn(cancel_on_peer_close(server, cancellation.clone()));

        socket2::SockRef::from(&client)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(client);
        timeout(Duration::from_secs(1), cancellation.cancelled())
            .await
            .expect("peer RST must cancel the request token");
        monitor.await.unwrap();
    }

    #[tokio::test]
    async fn peer_close_monitor_does_not_cancel_an_active_connection() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let cancellation = CancellationToken::new();
        let monitor = tokio::spawn(cancel_on_peer_close(server, cancellation.clone()));

        client.write_all(b"x").await.unwrap();
        tokio::time::sleep(Duration::from_millis(75)).await;
        assert!(!cancellation.is_cancelled());

        cancellation.cancel();
        monitor.await.unwrap();
    }

    #[tokio::test]
    async fn peer_close_monitor_ignores_fin_behind_unread_bytes() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let cancellation = CancellationToken::new();
        let monitor = tokio::spawn(cancel_on_peer_close(server, cancellation.clone()));

        client.write_all(b"unread").await.unwrap();
        drop(client);
        monitor.await.unwrap();
        assert!(!cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn peer_close_monitor_ignores_request_write_half_close() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let cancellation = CancellationToken::new();
        let monitor = tokio::spawn(cancel_on_peer_close(server, cancellation.clone()));

        client.shutdown().await.unwrap();
        monitor.await.unwrap();
        assert!(!cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn request_deadline_shutdown_interrupts_partial_socket_read() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client
            .write_all(b"POST /web/userdata/preferences HTTP/1.1\r\nContent-Length: 100\r\n\r\n{")
            .await
            .unwrap();
        let (mut server, shutdown_stream, peer_monitor) =
            socket_with_shutdown_handles(server).unwrap();
        drop(peer_monitor);
        let cancellation = CancellationToken::new();
        let result = run_request_until_joined(
            async move {
                let request = read_request(&mut server, 1024).await?;
                assert!(request.len() < 100);
                Ok(())
            },
            &cancellation,
            Duration::from_millis(20),
            move || {
                let _ = shutdown_stream.shutdown(Shutdown::Both);
            },
        )
        .await;
        assert!(result.is_ok());
        assert!(cancellation.is_cancelled());
    }

    #[tokio::test]
    async fn multipart_payload_too_large_matches_java_status_line() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        write_empty_payload_too_large(server).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert_eq!(
            response,
            b"HTTP/1.1 413 Request Entity Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
    }

    #[test]
    fn contact_counting_writer_matches_exact_json_wire_length() {
        let contacts = vec![ContactRecord {
            id: i64::MIN,
            name: Some("Control \u{1} and quote \"".into()),
            email: "unicode-用户@example.test".into(),
            notes: Some("\n\\\t".repeat(1024)),
        }];
        let expected = serde_json::to_vec(&contacts).unwrap();
        let mut counter = CountingWriter::default();
        serde_json::to_writer(&mut counter, &contacts).unwrap();
        assert_eq!(counter.length, expected.len());
        assert!(counter.length <= MAX_CONTACT_WIRE_BYTES);
    }

    #[tokio::test]
    async fn contact_channel_writer_uses_fixed_bounded_chunks() {
        let payload = vec![b'x'; JSON_STREAM_CHUNK_BYTES * 2 + 7];
        let expected = payload.clone();
        let (sender, mut receiver) = mpsc::channel(1);
        let producer = spawn_blocking(move || {
            let mut writer = ChannelWriter::new(sender, None);
            io::Write::write_all(&mut writer, &payload)?;
            io::Write::flush(&mut writer)
        });
        let mut actual = Vec::new();
        while let Some(chunk) = receiver.recv().await {
            assert!(chunk.len() <= JSON_STREAM_CHUNK_BYTES);
            actual.extend_from_slice(&chunk);
        }
        producer.await.unwrap().unwrap();
        assert_eq!(actual, expected);
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
        for (path, expected) in [
            ("/api/mail/poll", ParsedRequest::ApiPoll),
            ("/api/mail/raw", ParsedRequest::ApiRaw),
            ("/api/mail/rawDecoded", ParsedRequest::ApiRawDecoded),
        ] {
            let request = |key: &str| {
                format!("POST {path} HTTP/1.1\r\nX-API-Key: {key}\r\nContent-Length: 2\r\n\r\n{{}}")
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
                expected
            );
        }
        let write_request =
            |key: &str| format!("POST /api/mailboxes HTTP/1.1\r\nX-API-Key: {key}\r\n\r\n");
        assert_eq!(
            parse_request(write_request("read-key").as_bytes(), 1024, &config),
            ParsedRequest::ForbiddenWrite
        );
        assert_eq!(
            parse_request(write_request("write-key").as_bytes(), 1024, &config),
            ParsedRequest::ApiCreateMailbox
        );
        assert_eq!(
            parse_request(
                b"GET /api/mailboxes/QA%40EXAMPLE.TEST/exists HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::ApiMailboxExists("QA@EXAMPLE.TEST".into())
        );
        assert_eq!(
            parse_request(
                b"GET /api/mailboxes/qa%40example.test/exists HTTP/1.1\r\nX-API-Key: write-key\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::ForbiddenRead
        );
    }

    #[test]
    fn stress_routes_preserve_java_read_write_permissions() {
        let config = config_with_api_keys();
        for (path, expected) in [
            ("/api/stress/start", ParsedRequest::StressStart),
            ("/api/stress/reset", ParsedRequest::StressReset),
            ("/api/stress/cleanup", ParsedRequest::StressCleanup),
        ] {
            let request = |key: &str| {
                format!("POST {path} HTTP/1.1\r\nX-API-Key: {key}\r\nContent-Length: 0\r\n\r\n")
            };
            assert_eq!(
                parse_request(request("missing").as_bytes(), 1024, &config),
                ParsedRequest::Unauthorized
            );
            assert_eq!(
                parse_request(request("read-key").as_bytes(), 1024, &config),
                ParsedRequest::ForbiddenWrite
            );
            assert_eq!(
                parse_request(request("write-key").as_bytes(), 1024, &config),
                expected
            );
        }

        let status = |key: &str| {
            format!(
                "POST /api/stress/status HTTP/1.1\r\nX-API-Key: {key}\r\nContent-Length: 0\r\n\r\n"
            )
        };
        assert_eq!(
            parse_request(status("write-key").as_bytes(), 1024, &config),
            ParsedRequest::ForbiddenRead
        );
        assert_eq!(
            parse_request(status("read-key").as_bytes(), 1024, &config),
            ParsedRequest::StressStatus
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
        assert_eq!(
            authenticated_route(b"GET /web/userdata/stars/inbox HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::Stars {
                folder: "inbox".into(),
            }))
        );
        assert_eq!(
            authenticated_route(b"GET /web/userdata/preferences HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::Preferences))
        );
        assert_eq!(
            authenticated_route(b"POST /web/userdata/preferences HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::SavePreferences))
        );
        assert_eq!(
            authenticated_route(b"GET /web/userdata/contacts HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::Contacts))
        );
        assert_eq!(
            authenticated_route(b"POST /web/userdata/contacts HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::CreateContact))
        );
        assert_eq!(
            authenticated_route(b"PUT /web/userdata/contacts/42 HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::UpdateContact { id: 42 }))
        );
        assert_eq!(
            authenticated_route(b"DELETE /web/userdata/contacts/42 HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::DeleteContact { id: 42 }))
        );
        assert_eq!(
            authenticated_route(b"PUT /web/userdata/contacts/%34%32 HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::UpdateContact { id: 42 }))
        );
        assert!(
            authenticated_route(b"PUT /web/userdata/contacts/not-a-number HTTP/1.1\r\n\r\n")
                .is_err()
        );
        assert_eq!(
            authenticated_route(b"POST /web/mail/star/inbox/legacy-root.eml HTTP/1.1\r\n\r\n",),
            Ok(Some(AuthenticatedRoute::ToggleStar {
                folder: "inbox".into(),
                file: "legacy-root.eml".into(),
            }))
        );
        assert_eq!(
            authenticated_route(
                b"GET /web/mail/attachment/inbox/message%40one.eml/3 HTTP/1.1\r\n\r\n"
            ),
            Ok(Some(AuthenticatedRoute::Attachment {
                folder: "inbox".into(),
                file: "message@one.eml".into(),
                index: 3,
            }))
        );
        assert_eq!(
            authenticated_route(b"GET /web/mail/attachment/inbox/message.eml/-1 HTTP/1.1\r\n\r\n"),
            Ok(Some(AuthenticatedRoute::Attachment {
                folder: "inbox".into(),
                file: "message.eml".into(),
                index: -1,
            }))
        );
    }

    #[test]
    fn attachment_headers_encode_filenames_and_downgrade_active_types() {
        assert_eq!(
            attachment_disposition("report 100%~.txt"),
            "attachment; filename*=UTF-8''report%20100%25%7E.txt"
        );
        assert_eq!(
            safe_attachment_content_type(Some("image/svg+xml")),
            "application/octet-stream"
        );
        assert_eq!(
            safe_attachment_content_type(Some("application/atom+xml")),
            "application/octet-stream"
        );
        assert_eq!(safe_attachment_content_type(Some("image/png")), "image/png");
        assert_eq!(
            safe_attachment_content_type(Some("image/png\r\nX-Evil: yes")),
            "application/octet-stream"
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
    fn cringe_api_routes_preserve_read_write_permissions_and_query_fields() {
        let config = config_with_api_keys();
        assert_eq!(
            parse_cringe_list(
                "/api/cringe-ips?page=&page=bad&size=&size=bad&sortBy=&sortBy=ipAddress&sortDir=&search=&search=hidden"
            ),
            parse_cringe_list("/api/cringe-ips")
        );
        assert_eq!(
            parse_request(
                b"GET /api/cringe-ips HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config
            ),
            ParsedRequest::CringeList(IpListQuery {
                page: 0,
                size: 50,
                sort_by: "currentScore".into(),
                sort_dir: "desc".into(),
                search: String::new()
            })
        );
        assert_eq!(
            parse_request(b"GET /api/cringe-ips?page=2&size=10&sortBy=totalScore&sortDir=ASC&search=+db8%25+ HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n", 4096, &config),
            ParsedRequest::CringeList(IpListQuery { page: 2, size: 10, sort_by: "totalScore".into(), sort_dir: "ASC".into(), search: " db8% ".into() })
        );
        assert_eq!(
            parse_request(b"GET /api/cringe-ips HTTP/1.1\r\n\r\n", 4096, &config),
            ParsedRequest::Unauthorized
        );
        assert_eq!(
            parse_request(
                b"GET /api/cringe-ips?page=bad HTTP/1.1\r\nX-API-Key: write-key\r\n\r\n",
                4096,
                &config
            ),
            ParsedRequest::ForbiddenRead
        );
        assert_eq!(
            parse_request(
                b"GET /api/cringe-ips?page=bad HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config
            ),
            ParsedRequest::CringeInvalidInput
        );
        for (headers, expected) in [
            ("X-API-Key: read-key\r\n", ParsedRequest::CringeStats),
            ("X-API-Key: write-key\r\n", ParsedRequest::ForbiddenRead),
            ("", ParsedRequest::Unauthorized),
        ] {
            let request = format!("GET /api/cringe-ips/stats HTTP/1.1\r\n{headers}\r\n");
            assert_eq!(parse_request(request.as_bytes(), 4096, &config), expected);
        }
        assert_eq!(
            parse_request(
                b"GET /api/cringe-ips/above-score/50?scoreType=current HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::CringeAbove {
                min_score: 50,
                current: true,
            }
        );
        assert_eq!(
            parse_request(
                b"GET /api/cringe-ips/insults?page=2&size=20&search=spoof HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::CringeInsults(PageQuery {
                page: 2,
                size: 20,
                search: "spoof".to_owned(),
            })
        );
        assert_eq!(
            parse_request(
                b"GET /api/cringe-ips/export?minScore=12&scoreType=TOTAL HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::CringeExport {
                min_score: 12,
                score_type: "TOTAL".to_owned(),
            }
        );
        assert_eq!(
            parse_request(
                b"POST /api/cringe-ips/decay HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::ForbiddenWrite
        );
        assert_eq!(
            parse_request(
                b"POST /api/cringe-ips/decay HTTP/1.1\r\nX-API-Key: write-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::CringeDecay
        );
        assert_eq!(
            parse_request(
                b"POST /api/cringe-ips/decay HTTP/1.1\r\nX-API-Key: admin-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::CringeDecay
        );
        assert_eq!(
            parse_request(
                b"GET /api/cringe-ips/decay-config HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::CringeDecayConfig
        );
        assert_eq!(
            parse_request(
                b"GET /api/cringe-ips/203.0.113.77/decay-estimate HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::CringeDecayEstimate("203.0.113.77".to_owned())
        );
        assert_eq!(
            parse_request(
                b"GET /api/cringe-ips/203.0.113.77/activities?page=1&size=25 HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::CringeActivities {
                ip_address: "203.0.113.77".to_owned(),
                page: 1,
                size: 25,
            }
        );
    }

    #[test]
    fn xdp_routes_preserve_permissions_and_controller_binding_shapes() {
        let config = config_with_api_keys();
        assert_eq!(
            parse_request(
                b"GET /api/xdp-firewall/status HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::XdpStatus
        );
        assert_eq!(
            parse_request(
                b"POST /api/xdp-firewall/ban?ip=203.0.113.77&reason=6 HTTP/1.1\r\nX-API-Key: write-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::XdpBan {
                ip: Some("203.0.113.77".into()),
                reason: Ok(6),
            }
        );
        assert_eq!(
            parse_request(
                b"POST /api/xdp-firewall/ban?ip=203.0.113.77&reason=nope HTTP/1.1\r\nX-API-Key: write-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::XdpBan {
                ip: Some("203.0.113.77".into()),
                reason: Err(()),
            }
        );
        assert_eq!(
            parse_request(
                b"POST /api/xdp-firewall/ban HTTP/1.1\r\nX-API-Key: write-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::XdpBan {
                ip: None,
                reason: Ok(0),
            }
        );
        assert_eq!(
            parse_request(
                b"GET /api/xdp-firewall/check HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::XdpCheck(None)
        );
        assert_eq!(
            parse_request(
                b"DELETE /api/xdp-firewall/clear HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                4096,
                &config,
            ),
            ParsedRequest::ForbiddenWrite
        );
    }

    #[test]
    fn report_routes_preserve_method_permissions_path_and_first_date_value() {
        let config = config_with_api_keys();
        assert_eq!(
            parse_request(
                b"GET /api/reports/status HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::ReportStatus
        );
        assert_eq!(
            parse_request(
                b"GET /api/reports/status HTTP/1.1\r\nX-API-Key: write-key\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::ForbiddenRead
        );
        assert_eq!(
            parse_request(
                b"GET /api/reports/addresses/MiXeD%2EExample HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::ReportAddresses("MiXeD.Example".to_owned())
        );
        assert_eq!(
            parse_request(
                b"GET /api/reports/addresses/mixed.example HTTP/1.1\r\nX-API-Key: write-key\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::ForbiddenRead
        );
        assert_eq!(
            parse_request(
                b"GET /api/reports/domains?date=2024-01-01&date=2024-02-02 HTTP/1.1\r\nX-API-Key: read-key\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::ReportDomains(Some("2024-01-01".to_owned()))
        );
        assert_eq!(
            parse_request(
                b"POST /api/reports/trigger?date=2024-01-01 HTTP/1.1\r\nX-API-Key: write-key\r\nContent-Length: 0\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::ReportTrigger(Some("2024-01-01".to_owned()))
        );
        assert_eq!(
            parse_request(
                b"POST /api/reports/trigger HTTP/1.1\r\nX-API-Key: read-key\r\nContent-Length: 0\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::ForbiddenWrite
        );
        assert_eq!(
            parse_request(
                b"POST /api/reports/domain/no-data%2Eexample?date=2024-01-02 HTTP/1.1\r\nX-API-Key: write-key\r\nContent-Length: 0\r\n\r\n",
                1024,
                &config,
            ),
            ParsedRequest::ReportDomain {
                domain: "no-data.example".to_owned(),
                date: Some("2024-01-02".to_owned()),
            }
        );
    }

    #[test]
    fn report_dates_are_strict_iso_with_blank_mean_yesterday() {
        assert_eq!(
            report_date(Some("2024-02-29")),
            NaiveDate::from_ymd_opt(2024, 2, 29)
        );
        for invalid in ["2024-02-30", "2024-1-01", " 2024-01-01", "not-a-date"] {
            assert_eq!(report_date(Some(invalid)), None, "accepted {invalid:?}");
        }
        let yesterday = Utc::now().date_naive().pred_opt();
        assert_eq!(report_date(None), yesterday);
        assert_eq!(report_date(Some(" \t")), yesterday);
    }

    #[test]
    fn cringe_ip_cleaning_removes_control_and_encoded_garbage() {
        assert_eq!(clean_ip_address(" 203.0.113.77%0d\n"), "203.0.113.77");
        assert_eq!(clean_ip_address("203.0.113.77\u{85}"), "203.0.113.77\u{85}");
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
