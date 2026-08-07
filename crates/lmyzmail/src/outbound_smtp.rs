use std::{
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use idna::domain_to_ascii_strict;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout_at},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::sync::CancellationToken;

const MAX_REPLY_LINE_BYTES: usize = 2_048;
const MAX_REPLY_BYTES: usize = 64 * 1024;
const MAX_REPLY_LINES: usize = 100;
const READ_CHUNK_BYTES: usize = 4 * 1024;
const MESSAGE_CHUNK_BYTES: usize = 16 * 1024;
const MAX_PIPELINE_BYTES: usize = 512 * 1024;
const MAX_RECIPIENTS: usize = 1_000;
const MAX_HOST_BYTES: usize = 253;
const MAX_ADDRESS_BYTES: usize = 254;
const MAX_REPLY_SUMMARY_CHARS: usize = 2_048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMode {
    Disabled,
    Opportunistic,
    Required,
}

#[derive(Clone, Debug)]
pub struct SmtpEndpoint {
    connect_addr: SocketAddr,
    tls_name: String,
}

impl SmtpEndpoint {
    pub fn public_mx(
        connect_addr: SocketAddr,
        tls_name: impl Into<String>,
    ) -> Result<Self, DeliveryError> {
        if !is_public_smtp_ip(connect_addr.ip()) {
            return Err(error(
                DeliveryErrorKind::Configuration,
                "outbound SMTP MX resolved to a non-public address",
            ));
        }
        Self::validated(connect_addr, tls_name.into())
    }

    /// For an administrator-controlled relay only; never use this with MX DNS results.
    pub fn trusted_relay(
        connect_addr: SocketAddr,
        tls_name: impl Into<String>,
    ) -> Result<Self, DeliveryError> {
        Self::validated(connect_addr, tls_name.into())
    }

    fn validated(connect_addr: SocketAddr, tls_name: String) -> Result<Self, DeliveryError> {
        if connect_addr.port() == 0 {
            return Err(error(
                DeliveryErrorKind::Configuration,
                "invalid outbound SMTP port",
            ));
        }
        validate_host(&tls_name)?;
        Ok(Self {
            connect_addr,
            tls_name,
        })
    }
}

#[derive(Clone)]
pub enum MessageSource {
    Bytes(Arc<[u8]>),
    File(PathBuf),
}

impl fmt::Debug for MessageSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("byte_count", &bytes.len())
                .finish(),
            Self::File(_) => formatter.write_str("File(<redacted>)"),
        }
    }
}

#[derive(Clone)]
pub struct DeliveryRequest {
    pub endpoint: SmtpEndpoint,
    pub hello_name: String,
    pub envelope_from: String,
    pub recipients: Vec<String>,
    pub message: MessageSource,
    pub tls_mode: TlsMode,
    pub max_message_bytes: u64,
}

impl fmt::Debug for DeliveryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryRequest")
            .field("endpoint", &self.endpoint)
            .field("hello_name", &self.hello_name)
            .field("envelope_from", &"<redacted>")
            .field("recipient_count", &self.recipients.len())
            .field("message", &self.message)
            .field("tls_mode", &self.tls_mode)
            .field("max_message_bytes", &self.max_message_bytes)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientStatus {
    Accepted,
    TemporaryFailure,
    PermanentFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientResult {
    pub recipient: String,
    pub status: RecipientStatus,
    pub code: u16,
    pub reply: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataStatus {
    Accepted,
    TemporaryFailure,
    PermanentFailure,
    NotAttempted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryResult {
    pub recipients: Vec<RecipientResult>,
    pub data_status: DataStatus,
    pub data_code: Option<u16>,
    pub data_reply: Option<String>,
    pub tls: bool,
    pub smtp_utf8: bool,
    pub pipelining: bool,
}

pub enum DeliveryPreparation {
    Complete(DeliveryResult),
    CommitReady(PreparedDelivery),
}

impl fmt::Debug for DeliveryPreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete(result) => formatter.debug_tuple("Complete").field(result).finish(),
            Self::CommitReady(_) => formatter.write_str("CommitReady(<SMTP transaction>)"),
        }
    }
}

pub struct PreparedDelivery {
    session: SmtpSession,
    recipients: Vec<RecipientResult>,
    tls: bool,
    smtp_utf8: bool,
    pipelining: bool,
}

impl fmt::Debug for PreparedDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDelivery")
            .field("recipient_count", &self.recipients.len())
            .field("tls", &self.tls)
            .field("smtp_utf8", &self.smtp_utf8)
            .field("pipelining", &self.pipelining)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryErrorKind {
    Configuration,
    Temporary,
    Permanent,
    Ambiguous,
    Protocol,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryStage {
    Request,
    Connect,
    Greeting,
    Ehlo,
    StartTls,
    Envelope,
    MessageSource,
    DataCommand,
    DataBody,
    DataFinal,
}

#[derive(Debug)]
pub struct DeliveryError {
    pub kind: DeliveryErrorKind,
    pub stage: DeliveryStage,
    pub smtp_code: Option<u16>,
    pub message: String,
    pub recipients: Vec<RecipientResult>,
}

impl DeliveryError {
    fn at(mut self, stage: DeliveryStage) -> Self {
        self.stage = stage;
        self
    }

    fn with_smtp_code(mut self, code: u16) -> Self {
        self.smtp_code = Some(code);
        self
    }
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DeliveryError {}

#[derive(Clone)]
pub struct OutboundSmtpClient {
    tls_config: Arc<ClientConfig>,
    connect_timeout: Duration,
    command_timeout: Duration,
    session_timeout: Duration,
}

impl Default for OutboundSmtpClient {
    fn default() -> Self {
        let native = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let _ = roots.add_parsable_certificates(native.certs);
        if roots.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let tls_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            tls_config: Arc::new(tls_config),
            connect_timeout: Duration::from_secs(10),
            command_timeout: Duration::from_secs(15),
            session_timeout: Duration::from_secs(90),
        }
    }
}

impl OutboundSmtpClient {
    pub fn new(
        tls_config: Arc<ClientConfig>,
        connect_timeout: Duration,
        command_timeout: Duration,
        session_timeout: Duration,
    ) -> Result<Self, DeliveryError> {
        if connect_timeout.is_zero()
            || command_timeout.is_zero()
            || session_timeout < connect_timeout
            || session_timeout < command_timeout
            || session_timeout > Duration::from_secs(15 * 60)
        {
            return Err(error(
                DeliveryErrorKind::Configuration,
                "invalid outbound SMTP deadlines",
            ));
        }
        Ok(Self {
            tls_config,
            connect_timeout,
            command_timeout,
            session_timeout,
        })
    }

    pub async fn deliver(
        &self,
        request: &DeliveryRequest,
        cancellation: &CancellationToken,
    ) -> Result<DeliveryResult, DeliveryError> {
        match self.prepare(request, cancellation).await? {
            DeliveryPreparation::Complete(result) => Ok(result),
            DeliveryPreparation::CommitReady(prepared) => prepared.commit().await,
        }
    }

    pub async fn prepare(
        &self,
        request: &DeliveryRequest,
        cancellation: &CancellationToken,
    ) -> Result<DeliveryPreparation, DeliveryError> {
        validate_request(request)?;
        let session_deadline = Instant::now() + self.session_timeout;
        self.prepare_with_tls_policy(request, cancellation, session_deadline)
            .await
    }

    async fn prepare_with_tls_policy(
        &self,
        request: &DeliveryRequest,
        cancellation: &CancellationToken,
        session_deadline: Instant,
    ) -> Result<DeliveryPreparation, DeliveryError> {
        let attempt_tls = request.tls_mode != TlsMode::Disabled;
        match self
            .prepare_once(request, cancellation, attempt_tls, session_deadline)
            .await
        {
            Err(failure)
                if request.tls_mode == TlsMode::Opportunistic
                    && failure.kind == DeliveryErrorKind::Temporary
                    && failure.stage == DeliveryStage::StartTls =>
            {
                self.prepare_once(request, cancellation, false, session_deadline)
                    .await
            }
            result => result,
        }
    }

    async fn prepare_once(
        &self,
        request: &DeliveryRequest,
        cancellation: &CancellationToken,
        attempt_tls: bool,
        session_deadline: Instant,
    ) -> Result<DeliveryPreparation, DeliveryError> {
        let stream = io_deadline(
            cancellation,
            self.connect_timeout,
            session_deadline,
            TcpStream::connect(request.endpoint.connect_addr),
            DeliveryErrorKind::Temporary,
            "SMTP connect",
        )
        .await
        .map_err(|failure| failure.at(DeliveryStage::Connect))?;
        stream.set_nodelay(true).map_err(|_| {
            error(
                DeliveryErrorKind::Temporary,
                "SMTP socket configuration failed",
            )
            .at(DeliveryStage::Connect)
        })?;
        let mut session = SmtpSession::new(
            stream,
            self.command_timeout,
            session_deadline,
            cancellation.clone(),
        );
        let greeting = session
            .read_reply(false)
            .await
            .map_err(|failure| failure.at(DeliveryStage::Greeting))?;
        if greeting.code != 220 {
            return Err(reply_error(
                DeliveryStage::Greeting,
                true,
                "SMTP greeting rejected",
                &greeting,
            ));
        }
        let mut extensions = session.ehlo(&request.hello_name).await?;
        let mut tls_active = false;
        if attempt_tls && extensions.has("STARTTLS") {
            let reply = session
                .command("STARTTLS")
                .await
                .map_err(|failure| failure.at(DeliveryStage::StartTls))?;
            if reply.code != 220 {
                return Err(error(
                    DeliveryErrorKind::Temporary,
                    format!("STARTTLS command rejected: {}", reply.summary()),
                )
                .at(DeliveryStage::StartTls)
                .with_smtp_code(reply.code));
            }
            let server_name =
                ServerName::try_from(request.endpoint.tls_name.clone()).map_err(|_| {
                    error(
                        DeliveryErrorKind::Configuration,
                        "invalid outbound SMTP TLS name",
                    )
                })?;
            session
                .start_tls(
                    TlsConnector::from(Arc::clone(&self.tls_config)),
                    server_name,
                )
                .await
                .map_err(|mut failure| {
                    failure.message = format!("STARTTLS negotiation failed: {}", failure.message);
                    failure.at(DeliveryStage::StartTls)
                })?;
            tls_active = true;
            extensions = session
                .ehlo(&request.hello_name)
                .await
                .map_err(|mut failure| {
                    failure.message = format!("post-STARTTLS EHLO failed: {}", failure.message);
                    failure.at(DeliveryStage::StartTls)
                })?;
        } else if request.tls_mode == TlsMode::Required {
            return Err(error(
                DeliveryErrorKind::Temporary,
                "STARTTLS required but not advertised",
            )
            .at(DeliveryStage::StartTls));
        }

        let envelope = prepare_envelope(
            &request.envelope_from,
            &request.recipients,
            extensions.has("SMTPUTF8"),
        )
        .map_err(|failure| failure.at(DeliveryStage::Envelope))?;
        let pipelining = extensions.has("PIPELINING");
        let (mail_reply, recipient_replies) = session
            .envelope(
                &envelope.sender,
                &envelope.recipients,
                envelope.smtp_utf8,
                pipelining,
            )
            .await
            .map_err(|failure| failure.at(DeliveryStage::Envelope))?;
        if mail_reply.code != 250 {
            return Err(if matches!(mail_reply.code / 100, 4 | 5) {
                reply_error(
                    DeliveryStage::Envelope,
                    false,
                    "MAIL FROM rejected",
                    &mail_reply,
                )
            } else {
                protocol_error(false, "unexpected MAIL FROM reply code")
                    .at(DeliveryStage::Envelope)
                    .with_smtp_code(mail_reply.code)
            });
        }
        let mut recipient_results = Vec::with_capacity(request.recipients.len());
        for (recipient, reply) in request.recipients.iter().zip(recipient_replies) {
            let Some(status) = recipient_status(reply.code) else {
                let mut failure = protocol_error(false, "unexpected RCPT TO reply code")
                    .at(DeliveryStage::Envelope)
                    .with_smtp_code(reply.code);
                failure.recipients = recipient_results;
                return Err(failure);
            };
            recipient_results.push(RecipientResult {
                recipient: recipient.clone(),
                status,
                code: reply.code,
                reply: reply.summary(),
            });
        }
        let accepted = recipient_results
            .iter()
            .filter(|result| result.status == RecipientStatus::Accepted)
            .count();
        if accepted == 0 {
            return Ok(DeliveryPreparation::Complete(DeliveryResult {
                recipients: recipient_results,
                data_status: DataStatus::NotAttempted,
                data_code: None,
                data_reply: None,
                tls: tls_active,
                smtp_utf8: envelope.smtp_utf8,
                pipelining,
            }));
        }

        let mut message = session
            .prepare_message(&request.message, request.max_message_bytes)
            .await
            .map_err(|mut failure| {
                failure.stage = DeliveryStage::MessageSource;
                failure.recipients = recipient_results.clone();
                failure
            })?;
        let data_ready = session.command("DATA").await.map_err(|mut failure| {
            failure.stage = DeliveryStage::DataCommand;
            failure.recipients = recipient_results.clone();
            failure
        })?;
        if data_ready.code != 354 {
            let Some(status) = rejected_data_status(data_ready.code) else {
                let mut failure = protocol_error(false, "unexpected DATA readiness reply code")
                    .at(DeliveryStage::DataCommand)
                    .with_smtp_code(data_ready.code);
                failure.recipients = recipient_results;
                return Err(failure);
            };
            return Ok(DeliveryPreparation::Complete(DeliveryResult {
                recipients: recipient_results,
                data_status: status,
                data_code: Some(data_ready.code),
                data_reply: Some(data_ready.summary()),
                tls: tls_active,
                smtp_utf8: envelope.smtp_utf8,
                pipelining,
            }));
        }
        session
            .write_message_body(&mut message, request.max_message_bytes)
            .await
            .map_err(|mut failure| {
                if failure.stage == DeliveryStage::Request {
                    failure.stage = DeliveryStage::DataBody;
                }
                failure.recipients = recipient_results.clone();
                failure
            })?;
        Ok(DeliveryPreparation::CommitReady(PreparedDelivery {
            session,
            recipients: recipient_results,
            tls: tls_active,
            smtp_utf8: envelope.smtp_utf8,
            pipelining,
        }))
    }
}

impl PreparedDelivery {
    pub async fn commit(mut self) -> Result<DeliveryResult, DeliveryError> {
        self.session
            .write_all(b".\r\n", true)
            .await
            .map_err(|mut failure| {
                failure.stage = DeliveryStage::DataFinal;
                failure.recipients = self.recipients.clone();
                failure
            })?;
        let data_result = self.session.read_reply(true).await.map_err(|mut failure| {
            failure.stage = DeliveryStage::DataFinal;
            failure.recipients = self.recipients.clone();
            failure
        })?;
        let Some(status) = final_data_status(data_result.code) else {
            let mut failure = protocol_error(true, "unexpected final DATA reply code")
                .at(DeliveryStage::DataFinal)
                .with_smtp_code(data_result.code);
            failure.recipients = self.recipients;
            return Err(failure);
        };
        let _ = self.session.command("QUIT").await;
        Ok(DeliveryResult {
            recipients: self.recipients,
            data_status: status,
            data_code: Some(data_result.code),
            data_reply: Some(data_result.summary()),
            tls: self.tls,
            smtp_utf8: self.smtp_utf8,
            pipelining: self.pipelining,
        })
    }
}

#[derive(Debug)]
struct Envelope {
    sender: String,
    recipients: Vec<String>,
    smtp_utf8: bool,
}

#[derive(Default)]
struct Extensions {
    names: Vec<String>,
}

impl Extensions {
    fn has(&self, name: &str) -> bool {
        self.names.iter().any(|value| value == name)
    }
}

struct Reply {
    code: u16,
    lines: Vec<Vec<u8>>,
}

impl Reply {
    fn summary(&self) -> String {
        let joined = self
            .lines
            .iter()
            .map(|line| String::from_utf8_lossy(&line[4..line.len() - 2]))
            .collect::<Vec<_>>()
            .join(" | ");
        joined
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .take(MAX_REPLY_SUMMARY_CHARS)
            .collect()
    }
}

enum Transport {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

enum PreparedMessage<'a> {
    Bytes(&'a [u8]),
    File(File),
}

struct SmtpSession {
    transport: Option<Transport>,
    read_buffer: Vec<u8>,
    command_timeout: Duration,
    session_deadline: Instant,
    cancellation: CancellationToken,
}

impl SmtpSession {
    fn new(
        stream: TcpStream,
        command_timeout: Duration,
        session_deadline: Instant,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            transport: Some(Transport::Plain(stream)),
            read_buffer: Vec::with_capacity(READ_CHUNK_BYTES),
            command_timeout,
            session_deadline,
            cancellation,
        }
    }

    async fn ehlo(&mut self, hello_name: &str) -> Result<Extensions, DeliveryError> {
        let reply = self
            .command(&format!("EHLO {hello_name}"))
            .await
            .map_err(|failure| failure.at(DeliveryStage::Ehlo))?;
        if reply.code != 250 {
            let helo = self
                .command(&format!("HELO {hello_name}"))
                .await
                .map_err(|failure| failure.at(DeliveryStage::Ehlo))?;
            if helo.code != 250 {
                return Err(reply_error(
                    DeliveryStage::Ehlo,
                    true,
                    "EHLO/HELO rejected",
                    &helo,
                ));
            }
            return Ok(Extensions::default());
        }
        let mut names = Vec::new();
        for line in &reply.lines {
            let value = &line[4..line.len() - 2];
            let name = value
                .split(|byte| byte.is_ascii_whitespace())
                .next()
                .unwrap_or_default();
            if !name.is_empty() && name.is_ascii() {
                names.push(String::from_utf8_lossy(name).to_ascii_uppercase());
            }
        }
        Ok(Extensions { names })
    }

    async fn envelope(
        &mut self,
        sender: &str,
        recipients: &[String],
        smtp_utf8: bool,
        pipelining: bool,
    ) -> Result<(Reply, Vec<Reply>), DeliveryError> {
        let mail = if smtp_utf8 {
            format!("MAIL FROM:<{sender}> SMTPUTF8\r\n")
        } else {
            format!("MAIL FROM:<{sender}>\r\n")
        };
        if pipelining {
            let mut commands = Vec::with_capacity(mail.len() + recipients.len() * 300);
            commands.extend_from_slice(mail.as_bytes());
            for recipient in recipients {
                commands.extend_from_slice(format!("RCPT TO:<{recipient}>\r\n").as_bytes());
                if commands.len() > MAX_PIPELINE_BYTES {
                    return Err(error(
                        DeliveryErrorKind::Configuration,
                        "SMTP command pipeline exceeds its byte budget",
                    ));
                }
            }
            self.write_all(&commands, false).await?;
            let mail_reply = self.read_reply(false).await?;
            let mut replies = Vec::with_capacity(recipients.len());
            for _ in recipients {
                replies.push(self.read_reply(false).await?);
            }
            Ok((mail_reply, replies))
        } else {
            self.write_all(mail.as_bytes(), false).await?;
            let mail_reply = self.read_reply(false).await?;
            let mut replies = Vec::with_capacity(recipients.len());
            if mail_reply.code / 100 == 2 {
                for recipient in recipients {
                    replies.push(self.command(&format!("RCPT TO:<{recipient}>")).await?);
                }
            } else {
                replies.resize_with(recipients.len(), || Reply {
                    code: 503,
                    lines: vec![b"503 5.5.1 MAIL FROM rejected\r\n".to_vec()],
                });
            }
            Ok((mail_reply, replies))
        }
    }

    async fn command(&mut self, command: &str) -> Result<Reply, DeliveryError> {
        if command.is_empty()
            || command.len() + 2 > MAX_REPLY_LINE_BYTES
            || command
                .bytes()
                .any(|value| matches!(value, b'\r' | b'\n' | 0))
        {
            return Err(error(
                DeliveryErrorKind::Configuration,
                "invalid outbound SMTP command",
            ));
        }
        let mut bytes = Vec::with_capacity(command.len() + 2);
        bytes.extend_from_slice(command.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        self.write_all(&bytes, false).await?;
        self.read_reply(false).await
    }

    async fn start_tls(
        &mut self,
        connector: TlsConnector,
        server_name: ServerName<'static>,
    ) -> Result<(), DeliveryError> {
        if !self.read_buffer.is_empty() {
            return Err(error(
                DeliveryErrorKind::Protocol,
                "SMTP server sent plaintext bytes after STARTTLS readiness",
            ));
        }
        let Some(Transport::Plain(stream)) = self.transport.take() else {
            return Err(error(
                DeliveryErrorKind::Protocol,
                "SMTP STARTTLS attempted in an invalid state",
            ));
        };
        let tls = io_deadline(
            &self.cancellation,
            self.command_timeout,
            self.session_deadline,
            connector.connect(server_name, stream),
            DeliveryErrorKind::Temporary,
            "SMTP TLS handshake",
        )
        .await?;
        self.transport = Some(Transport::Tls(Box::new(tls)));
        Ok(())
    }

    async fn read_reply(&mut self, after_data: bool) -> Result<Reply, DeliveryError> {
        let mut lines = Vec::new();
        let mut total = 0;
        let mut expected_code = None;
        loop {
            if lines.len() >= MAX_REPLY_LINES || total >= MAX_REPLY_BYTES {
                return Err(protocol_error(
                    after_data,
                    "SMTP reply exceeded its line or byte budget",
                ));
            }
            let line = self.read_line(after_data).await?;
            total += line.len();
            if total > MAX_REPLY_BYTES {
                return Err(protocol_error(
                    after_data,
                    "SMTP reply exceeded its line or byte budget",
                ));
            }
            if line.len() < 5
                || !line[..3].iter().all(u8::is_ascii_digit)
                || !matches!(line[3], b' ' | b'-')
            {
                return Err(protocol_error(after_data, "malformed SMTP reply"));
            }
            let code = u16::from(line[0] - b'0') * 100
                + u16::from(line[1] - b'0') * 10
                + u16::from(line[2] - b'0');
            if !(200..=599).contains(&code) || expected_code.is_some_and(|value| value != code) {
                return Err(protocol_error(after_data, "inconsistent SMTP reply code"));
            }
            expected_code = Some(code);
            let final_line = line[3] == b' ';
            lines.push(line);
            if final_line {
                return Ok(Reply { code, lines });
            }
        }
    }

    async fn read_line(&mut self, after_data: bool) -> Result<Vec<u8>, DeliveryError> {
        loop {
            if let Some(index) = self.read_buffer.iter().position(|value| *value == b'\n') {
                if index + 1 > MAX_REPLY_LINE_BYTES {
                    return Err(protocol_error(
                        after_data,
                        "SMTP reply line exceeded its byte budget",
                    ));
                }
                let line = self.read_buffer.drain(..=index).collect::<Vec<_>>();
                if !line.ends_with(b"\r\n") {
                    return Err(protocol_error(
                        after_data,
                        "SMTP reply did not use CRLF framing",
                    ));
                }
                return Ok(line);
            }
            if self.read_buffer.len() >= MAX_REPLY_LINE_BYTES {
                return Err(protocol_error(
                    after_data,
                    "SMTP reply line exceeded its byte budget",
                ));
            }
            let mut chunk = [0_u8; READ_CHUNK_BYTES];
            let read = self.read(&mut chunk, after_data).await?;
            if read == 0 {
                return Err(error(
                    if after_data {
                        DeliveryErrorKind::Ambiguous
                    } else {
                        DeliveryErrorKind::Temporary
                    },
                    if after_data {
                        "SMTP connection closed after DATA body"
                    } else {
                        "SMTP connection closed before transaction completion"
                    },
                ));
            }
            self.read_buffer.extend_from_slice(&chunk[..read]);
        }
    }

    async fn prepare_message<'a>(
        &self,
        source: &'a MessageSource,
        max_message_bytes: u64,
    ) -> Result<PreparedMessage<'a>, DeliveryError> {
        match source {
            MessageSource::Bytes(bytes) => {
                if bytes.len() as u64 > max_message_bytes {
                    return Err(error(
                        DeliveryErrorKind::Permanent,
                        "outbound message exceeds configured size",
                    ));
                }
                Ok(PreparedMessage::Bytes(bytes))
            }
            MessageSource::File(path) => {
                let metadata = self
                    .file_deadline(
                        tokio::fs::metadata(path),
                        "outbound message source metadata",
                    )
                    .await?;
                if !metadata.is_file() || metadata.len() > max_message_bytes {
                    return Err(error(
                        DeliveryErrorKind::Permanent,
                        "outbound message exceeds configured size",
                    ));
                }
                let file = self
                    .file_deadline(File::open(path), "outbound message source open")
                    .await?;
                let metadata = self
                    .file_deadline(file.metadata(), "outbound message source metadata")
                    .await?;
                if !metadata.is_file() || metadata.len() > max_message_bytes {
                    return Err(error(
                        DeliveryErrorKind::Permanent,
                        "outbound message exceeds configured size",
                    ));
                }
                Ok(PreparedMessage::File(file))
            }
        }
    }

    async fn write_message_body(
        &mut self,
        source: &mut PreparedMessage<'_>,
        max_message_bytes: u64,
    ) -> Result<(), DeliveryError> {
        let mut state = DotStuffState::default();
        match source {
            PreparedMessage::Bytes(bytes) => {
                state.input_bytes = bytes.len() as u64;
                self.write_dot_stuffed(bytes, &mut state).await?;
            }
            PreparedMessage::File(file) => {
                let mut buffer = [0_u8; MESSAGE_CHUNK_BYTES];
                loop {
                    let read = io_deadline(
                        &self.cancellation,
                        self.command_timeout,
                        self.session_deadline,
                        file.read(&mut buffer),
                        DeliveryErrorKind::Temporary,
                        "outbound message source read",
                    )
                    .await?;
                    if read == 0 {
                        break;
                    }
                    state.input_bytes = state.input_bytes.saturating_add(read as u64);
                    if state.input_bytes > max_message_bytes {
                        return Err(error(
                            DeliveryErrorKind::Permanent,
                            "outbound message exceeds configured size",
                        ));
                    }
                    self.write_dot_stuffed(&buffer[..read], &mut state).await?;
                }
            }
        }
        let mut ending = Vec::with_capacity(2);
        if state.pending_cr {
            ending.extend_from_slice(b"\r\n");
            state.at_line_start = true;
            state.pending_cr = false;
        }
        if state.wrote_anything && !state.at_line_start {
            ending.extend_from_slice(b"\r\n");
        }
        if !ending.is_empty() {
            self.write_all(&ending, false).await?;
        }
        Ok(())
    }

    async fn file_deadline<T, F>(&self, future: F, operation: &str) -> Result<T, DeliveryError>
    where
        F: Future<Output = std::io::Result<T>>,
    {
        let operation_deadline = (Instant::now() + self.command_timeout).min(self.session_deadline);
        tokio::select! {
            _ = self.cancellation.cancelled() => Err(error(
                DeliveryErrorKind::Cancelled,
                format!("{operation} cancelled"),
            ).at(DeliveryStage::MessageSource)),
            result = timeout_at(operation_deadline, future) => match result {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(failure)) => Err(error(
                    file_error_kind(failure.kind()),
                    format!("{operation} is unavailable"),
                ).at(DeliveryStage::MessageSource)),
                Err(_) => Err(error(
                    DeliveryErrorKind::Temporary,
                    format!("{operation} deadline exceeded"),
                ).at(DeliveryStage::MessageSource)),
            }
        }
    }

    async fn write_dot_stuffed(
        &mut self,
        input: &[u8],
        state: &mut DotStuffState,
    ) -> Result<(), DeliveryError> {
        let mut output = Vec::with_capacity(MESSAGE_CHUNK_BYTES + 2);
        for byte in input {
            state.wrote_anything = true;
            match *byte {
                b'\n' => {
                    output.extend_from_slice(b"\r\n");
                    state.at_line_start = true;
                    state.pending_cr = false;
                }
                b'\r' => {
                    if state.pending_cr {
                        output.extend_from_slice(b"\r\n");
                        state.at_line_start = true;
                    }
                    state.pending_cr = true;
                }
                value => {
                    if state.pending_cr {
                        output.extend_from_slice(b"\r\n");
                        state.at_line_start = true;
                        state.pending_cr = false;
                    }
                    if state.at_line_start && value == b'.' {
                        output.push(b'.');
                    }
                    output.push(value);
                    state.at_line_start = false;
                }
            }
            if output.len() >= MESSAGE_CHUNK_BYTES {
                self.write_all(&output, false).await?;
                output.clear();
            }
        }
        if !output.is_empty() {
            self.write_all(&output, false).await?;
        }
        Ok(())
    }

    async fn read(&mut self, buffer: &mut [u8], after_data: bool) -> Result<usize, DeliveryError> {
        let future = async {
            match self.transport.as_mut() {
                Some(Transport::Plain(stream)) => stream.read(buffer).await,
                Some(Transport::Tls(stream)) => stream.read(buffer).await,
                None => Err(std::io::Error::other("SMTP transport unavailable")),
            }
        };
        io_deadline(
            &self.cancellation,
            self.command_timeout,
            self.session_deadline,
            future,
            if after_data {
                DeliveryErrorKind::Ambiguous
            } else {
                DeliveryErrorKind::Temporary
            },
            "SMTP read",
        )
        .await
    }

    async fn write_all(&mut self, bytes: &[u8], after_data: bool) -> Result<(), DeliveryError> {
        let future = async {
            match self.transport.as_mut() {
                Some(Transport::Plain(stream)) => stream.write_all(bytes).await,
                Some(Transport::Tls(stream)) => stream.write_all(bytes).await,
                None => Err(std::io::Error::other("SMTP transport unavailable")),
            }
        };
        io_deadline(
            &self.cancellation,
            self.command_timeout,
            self.session_deadline,
            future,
            if after_data {
                DeliveryErrorKind::Ambiguous
            } else {
                DeliveryErrorKind::Temporary
            },
            "SMTP write",
        )
        .await
    }
}

struct DotStuffState {
    input_bytes: u64,
    at_line_start: bool,
    wrote_anything: bool,
    pending_cr: bool,
}

impl Default for DotStuffState {
    fn default() -> Self {
        Self {
            input_bytes: 0,
            at_line_start: true,
            wrote_anything: false,
            pending_cr: false,
        }
    }
}

fn validate_request(request: &DeliveryRequest) -> Result<(), DeliveryError> {
    validate_host(&request.endpoint.tls_name)?;
    validate_host(&request.hello_name)?;
    if request.max_message_bytes == 0
        || request.recipients.is_empty()
        || request.recipients.len() > MAX_RECIPIENTS
    {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP request bounds",
        ));
    }
    if !request.envelope_from.is_empty() {
        validate_address(&request.envelope_from)?;
    }
    for recipient in &request.recipients {
        validate_address(recipient)?;
    }
    Ok(())
}

pub(crate) fn is_public_smtp_ip(value: IpAddr) -> bool {
    match value {
        IpAddr::V4(value) => {
            let [first, second, third, _] = value.octets();
            !(value.is_unspecified()
                || value.is_loopback()
                || value.is_private()
                || value.is_link_local()
                || value.is_multicast()
                || value.is_broadcast()
                || value.is_documentation()
                || first == 0
                || (first == 100 && (64..=127).contains(&second))
                || (first == 192 && second == 0 && third == 0)
                || (first == 192 && second == 88 && third == 99)
                || (first == 198 && matches!(second, 18 | 19))
                || first >= 240)
        }
        IpAddr::V6(value) => {
            let segments = value.segments();
            if segments[0] & 0xe000 != 0x2000
                || (segments[0] == 0x2001 && matches!(segments[1], 0 | 0x0db8))
            {
                return false;
            }
            if segments[0] == 0x2002 {
                let embedded = std::net::Ipv4Addr::new(
                    (segments[1] >> 8) as u8,
                    segments[1] as u8,
                    (segments[2] >> 8) as u8,
                    segments[2] as u8,
                );
                return is_public_smtp_ip(IpAddr::V4(embedded));
            }
            true
        }
    }
}

fn validate_host(value: &str) -> Result<(), DeliveryError> {
    if value.is_empty()
        || value.len() > MAX_HOST_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP host name",
        ));
    }
    let domain = value.strip_suffix('.').unwrap_or(value);
    if domain.parse::<IpAddr>().is_err() && domain_to_ascii_strict(domain).is_err() {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP host name",
        ));
    }
    Ok(())
}

fn validate_address(value: &str) -> Result<(), DeliveryError> {
    let parts = value.rsplit_once('@');
    if value.is_empty()
        || value.len() > MAX_ADDRESS_BYTES
        || value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '<' | '>')
        })
        || parts.is_none()
    {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP envelope address",
        ));
    }
    let (local, domain) = parts.unwrap();
    let local_is_valid = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.chars().all(|character| {
            !character.is_ascii()
                || character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    '.' | '!'
                        | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '/'
                        | '='
                        | '?'
                        | '^'
                        | '_'
                        | '`'
                        | '{'
                        | '|'
                        | '}'
                        | '~'
                )
        });
    let ascii_domain = domain_to_ascii_strict(domain).ok();
    if !local_is_valid
        || domain.is_empty()
        || local.contains('@')
        || ascii_domain.as_deref().is_none_or(|domain| {
            !valid_ascii_domain(domain) || local.len() + 1 + domain.len() > MAX_ADDRESS_BYTES
        })
    {
        return Err(error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP envelope address",
        ));
    }
    Ok(())
}

fn valid_ascii_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn prepare_envelope(
    sender: &str,
    recipients: &[String],
    server_supports_smtp_utf8: bool,
) -> Result<Envelope, DeliveryError> {
    let needs_smtp_utf8 = !sender.is_ascii() || recipients.iter().any(|value| !value.is_ascii());
    if !needs_smtp_utf8 {
        return Ok(Envelope {
            sender: sender.to_owned(),
            recipients: recipients.to_vec(),
            smtp_utf8: false,
        });
    }
    if server_supports_smtp_utf8 {
        return Ok(Envelope {
            sender: sender.to_owned(),
            recipients: recipients.to_vec(),
            smtp_utf8: true,
        });
    }
    Ok(Envelope {
        sender: if sender.is_empty() {
            String::new()
        } else {
            downgrade_domain(sender)?
        },
        recipients: recipients
            .iter()
            .map(|value| downgrade_domain(value))
            .collect::<Result<_, _>>()?,
        smtp_utf8: false,
    })
}

fn downgrade_domain(address: &str) -> Result<String, DeliveryError> {
    let (local, domain) = address.rsplit_once('@').ok_or_else(|| {
        error(
            DeliveryErrorKind::Configuration,
            "invalid outbound SMTP envelope address",
        )
    })?;
    if !local.is_ascii() {
        return Err(error(
            DeliveryErrorKind::Permanent,
            "SMTPUTF8 is required for a non-ASCII local part",
        ));
    }
    let domain = domain_to_ascii_strict(domain).map_err(|_| {
        error(
            DeliveryErrorKind::Permanent,
            "internationalized envelope domain cannot be downgraded",
        )
    })?;
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

fn recipient_status(code: u16) -> Option<RecipientStatus> {
    match code {
        250..=252 => Some(RecipientStatus::Accepted),
        400..=499 => Some(RecipientStatus::TemporaryFailure),
        500..=599 => Some(RecipientStatus::PermanentFailure),
        _ => None,
    }
}

fn rejected_data_status(code: u16) -> Option<DataStatus> {
    match code {
        400..=499 => Some(DataStatus::TemporaryFailure),
        500..=599 => Some(DataStatus::PermanentFailure),
        _ => None,
    }
}

fn final_data_status(code: u16) -> Option<DataStatus> {
    match code {
        250 => Some(DataStatus::Accepted),
        400..=499 => Some(DataStatus::TemporaryFailure),
        500..=599 => Some(DataStatus::PermanentFailure),
        _ => None,
    }
}

fn reply_error(
    stage: DeliveryStage,
    endpoint_scoped: bool,
    context: &str,
    reply: &Reply,
) -> DeliveryError {
    error(
        if !endpoint_scoped && reply.code / 100 == 5 {
            DeliveryErrorKind::Permanent
        } else {
            DeliveryErrorKind::Temporary
        },
        format!("{context}: {}", reply.summary()),
    )
    .at(stage)
    .with_smtp_code(reply.code)
}

fn error(kind: DeliveryErrorKind, message: impl Into<String>) -> DeliveryError {
    DeliveryError {
        kind,
        stage: DeliveryStage::Request,
        smtp_code: None,
        message: message.into(),
        recipients: Vec::new(),
    }
}

fn file_error_kind(kind: std::io::ErrorKind) -> DeliveryErrorKind {
    match kind {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::PermissionDenied
        | std::io::ErrorKind::InvalidInput
        | std::io::ErrorKind::InvalidData => DeliveryErrorKind::Permanent,
        _ => DeliveryErrorKind::Temporary,
    }
}

fn protocol_error(after_data: bool, message: &'static str) -> DeliveryError {
    error(
        if after_data {
            DeliveryErrorKind::Ambiguous
        } else {
            DeliveryErrorKind::Protocol
        },
        message,
    )
}

async fn io_deadline<T, E, F>(
    cancellation: &CancellationToken,
    operation_timeout: Duration,
    session_deadline: Instant,
    future: F,
    failure_kind: DeliveryErrorKind,
    operation: &str,
) -> Result<T, DeliveryError>
where
    F: Future<Output = Result<T, E>>,
    E: fmt::Display,
{
    let operation_deadline = (Instant::now() + operation_timeout).min(session_deadline);
    tokio::select! {
        _ = cancellation.cancelled() => Err(error(
            if failure_kind == DeliveryErrorKind::Ambiguous {
                DeliveryErrorKind::Ambiguous
            } else {
                DeliveryErrorKind::Cancelled
            },
            format!("{operation} cancelled"),
        )),
        result = timeout_at(operation_deadline, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(failure)) => Err(error(failure_kind, format!("{operation} failed: {failure}"))),
            Err(_) => Err(error(failure_kind, format!("{operation} deadline exceeded"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_utf8_downgrades_only_domains() {
        let envelope =
            prepare_envelope("sender@例え.test", &["user@例え.test".into()], false).unwrap();
        assert_eq!(envelope.sender, "sender@xn--r8jz45g.test");
        assert_eq!(envelope.recipients, ["user@xn--r8jz45g.test"]);
        assert!(!envelope.smtp_utf8);
        let failure = prepare_envelope("送信@example.test", &["user@example.test".into()], false)
            .unwrap_err();
        assert_eq!(failure.kind, DeliveryErrorKind::Permanent);
    }

    #[test]
    fn smtp_utf8_is_preserved_when_advertised() {
        let envelope =
            prepare_envelope("送信@example.test", &["受信@example.test".into()], true).unwrap();
        assert_eq!(envelope.sender, "送信@example.test");
        assert!(envelope.smtp_utf8);
    }

    #[test]
    fn request_validation_rejects_command_injection() {
        let request = DeliveryRequest {
            endpoint: SmtpEndpoint::trusted_relay(([127, 0, 0, 1], 25).into(), "smtp.example.test")
                .unwrap(),
            hello_name: "mail.example.test".into(),
            envelope_from: "sender@example.test\r\nRCPT TO:<victim@example.test>".into(),
            recipients: vec!["user@example.test".into()],
            message: MessageSource::Bytes(Arc::from(&b"Subject: test\r\n\r\nbody\r\n"[..])),
            tls_mode: TlsMode::Disabled,
            max_message_bytes: 1_024,
        };
        assert_eq!(
            validate_request(&request).unwrap_err().kind,
            DeliveryErrorKind::Configuration
        );
    }

    #[test]
    fn public_mx_rejects_special_addresses_and_trusted_relay_is_explicit() {
        for address in [
            "0.0.0.1:25",
            "10.0.0.1:25",
            "100.64.0.1:25",
            "127.0.0.1:25",
            "169.254.1.1:25",
            "192.0.2.1:25",
            "198.18.0.1:25",
            "203.0.113.1:25",
            "[::1]:25",
            "[fc00::1]:25",
            "[fe80::1]:25",
            "[2001:db8::1]:25",
            "[2002:7f00:1::1]:25",
        ] {
            let failure =
                SmtpEndpoint::public_mx(address.parse().unwrap(), "smtp.example.test").unwrap_err();
            assert_eq!(failure.kind, DeliveryErrorKind::Configuration, "{address}");
        }
        for address in ["8.8.8.8:25", "[2606:4700:4700::1111]:25"] {
            SmtpEndpoint::public_mx(address.parse().unwrap(), "smtp.example.test").unwrap();
        }
        SmtpEndpoint::trusted_relay("127.0.0.1:2525".parse().unwrap(), "relay.example.test")
            .unwrap();
    }

    #[test]
    fn request_debug_redacts_message_path_addresses_and_bytes() {
        let request = DeliveryRequest {
            endpoint: SmtpEndpoint::trusted_relay(([127, 0, 0, 1], 25).into(), "smtp.example.test")
                .unwrap(),
            hello_name: "mail.example.test".into(),
            envelope_from: "secret-sender@example.test".into(),
            recipients: vec!["secret-recipient@example.test".into()],
            message: MessageSource::Bytes(Arc::from(&b"secret body"[..])),
            tls_mode: TlsMode::Required,
            max_message_bytes: 1_024,
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("byte_count: 11"));
        assert!(!rendered.contains("secret"));

        let rendered = format!(
            "{:?}",
            MessageSource::File(PathBuf::from("/private/spool/secret.eml"))
        );
        assert_eq!(rendered, "File(<redacted>)");
    }

    #[test]
    fn request_validation_rejects_invalid_mailbox_syntax() {
        for address in [
            ".user@example.test",
            "user..tag@example.test",
            "user@example-.test",
            "user@-example.test",
            "user@example/test",
            "user name@example.test",
        ] {
            assert_eq!(
                validate_address(address).unwrap_err().kind,
                DeliveryErrorKind::Configuration,
                "{address}"
            );
        }
        validate_address("user+tag@example.test").unwrap();
        validate_address("受信@example.test").unwrap();
    }

    #[test]
    fn file_errors_distinguish_missing_content_from_transient_resources() {
        assert_eq!(
            file_error_kind(std::io::ErrorKind::NotFound),
            DeliveryErrorKind::Permanent
        );
        assert_eq!(
            file_error_kind(std::io::ErrorKind::PermissionDenied),
            DeliveryErrorKind::Permanent
        );
        assert_eq!(
            file_error_kind(std::io::ErrorKind::WouldBlock),
            DeliveryErrorKind::Temporary
        );
        assert_eq!(
            file_error_kind(std::io::ErrorKind::Other),
            DeliveryErrorKind::Temporary
        );
    }
}
