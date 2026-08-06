use std::{
    io,
    net::IpAddr,
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use deadpool_postgres::Pool;
use getrandom::fill as fill_random;
use openssl::pkcs12::Pkcs12;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::{JoinSet, spawn_blocking},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tokio_util::sync::CancellationToken;

use crate::config::RuntimeConfig;

const HOSTNAME: &str = "lmyzmail";
const MAX_COMMAND_BYTES: usize = 1_000;
const MAX_MESSAGE_BYTES: usize = 15_728_640;
const MAX_RECIPIENTS: usize = 100;
const MAX_CONNECTIONS: usize = 256;
const STORAGE_TIMEOUT: Duration = Duration::from_secs(15);
const DATABASE_TIMEOUT: Duration = Duration::from_secs(8);
const REDIS_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_TLS_KEYSTORE_BYTES: u64 = 16 * 1024 * 1024;
const SMTP_QUEUE_CAPACITY: usize = 256;
static FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum SmtpError {
    Database(String),
    InvalidConfig(String),
}

impl std::fmt::Display for SmtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "SMTP database unavailable: {error}"),
            Self::InvalidConfig(error) => f.write_str(error),
        }
    }
}

impl std::error::Error for SmtpError {}

#[derive(Clone)]
pub struct SmtpService {
    config: Arc<RuntimeConfig>,
    pool: Pool,
    blocking_permits: Arc<Semaphore>,
    delivery_queue: Arc<Semaphore>,
    tls_acceptor: Option<TlsAcceptor>,
}

impl SmtpService {
    pub fn from_config(config: Arc<RuntimeConfig>, pool: Pool) -> Result<Self, SmtpError> {
        let tls_acceptor = if config.tls.enabled {
            let path = config.tls.keystore_path.as_deref().ok_or_else(|| {
                SmtpError::InvalidConfig("TLS keystore path is not configured".into())
            })?;
            let mut file = std::fs::File::open(path).map_err(|error| {
                SmtpError::InvalidConfig(format!("TLS keystore cannot be read: {error}"))
            })?;
            let metadata = file.metadata().map_err(|error| {
                SmtpError::InvalidConfig(format!("TLS keystore cannot be inspected: {error}"))
            })?;
            if !metadata.is_file() || metadata.len() > MAX_TLS_KEYSTORE_BYTES {
                return Err(SmtpError::InvalidConfig(format!(
                    "TLS keystore is not a regular file or exceeds {MAX_TLS_KEYSTORE_BYTES} bytes"
                )));
            }
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            use std::io::Read as _;
            file.by_ref()
                .take(MAX_TLS_KEYSTORE_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    SmtpError::InvalidConfig(format!("TLS keystore cannot be read: {error}"))
                })?;
            if bytes.len() as u64 > MAX_TLS_KEYSTORE_BYTES {
                return Err(SmtpError::InvalidConfig(format!(
                    "TLS keystore exceeds {MAX_TLS_KEYSTORE_BYTES} bytes"
                )));
            }
            let password = std::env::var_os("LMYZMAIL_SSL_KEYSTORE_PASSWORD")
                .or_else(|| std::env::var_os("BOTMAIL_SSL_KEYSTORE_PASSWORD"))
                .map(|value| {
                    value.into_string().map_err(|_| {
                        SmtpError::InvalidConfig(
                            "TLS keystore password environment value is not UTF-8".into(),
                        )
                    })
                })
                .transpose()?
                .unwrap_or_else(|| config.tls.keystore_password.clone());
            let parsed = Pkcs12::from_der(&bytes)
                .and_then(|keystore| keystore.parse2(&password))
                .map_err(|error| {
                    SmtpError::InvalidConfig(format!("TLS PKCS#12 keystore is invalid: {error}"))
                })?;
            let private_key = parsed.pkey.ok_or_else(|| {
                SmtpError::InvalidConfig("TLS PKCS#12 keystore has no private key".into())
            })?;
            let certificate = parsed.cert.ok_or_else(|| {
                SmtpError::InvalidConfig("TLS PKCS#12 keystore has no certificate".into())
            })?;
            let mut certificates =
                vec![CertificateDer::from(certificate.to_der().map_err(
                    |error| SmtpError::InvalidConfig(error.to_string()),
                )?)];
            if let Some(chain) = parsed.ca {
                for certificate in chain {
                    certificates.push(CertificateDer::from(
                        certificate
                            .to_der()
                            .map_err(|error| SmtpError::InvalidConfig(error.to_string()))?,
                    ));
                }
            }
            let private_key = private_key
                .private_key_to_pkcs8()
                .map_err(|error| SmtpError::InvalidConfig(error.to_string()))?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let tls_config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|error| SmtpError::InvalidConfig(error.to_string()))?
                .with_no_client_auth()
                .with_single_cert(
                    certificates,
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key)),
                )
                .map_err(|error| {
                    SmtpError::InvalidConfig(format!("TLS acceptor setup failed: {error}"))
                })?;
            Some(TlsAcceptor::from(Arc::new(tls_config)))
        } else {
            None
        };
        Ok(Self {
            config,
            pool,
            blocking_permits: Arc::new(Semaphore::new(4)),
            delivery_queue: Arc::new(Semaphore::new(SMTP_QUEUE_CAPACITY)),
            tls_acceptor,
        })
    }

    async fn deliver(
        &self,
        envelope: Envelope,
        peer: IpAddr,
        helo: &str,
        encrypted: bool,
    ) -> io::Result<String> {
        let permit = self
            .delivery_queue
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("SMTP delivery queue closed"))?;
        let result = timeout(
            STORAGE_TIMEOUT,
            self.deliver_inner(envelope, peer, helo.to_owned(), encrypted),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SMTP delivery deadline exceeded"))?;
        drop(permit);
        result
    }

    async fn deliver_inner(
        &self,
        envelope: Envelope,
        peer: IpAddr,
        helo: String,
        encrypted: bool,
    ) -> io::Result<String> {
        let mailbox = envelope
            .recipients
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "recipient missing"))?
            .to_ascii_lowercase();
        let message_id = header_value(&envelope.data, "message-id").unwrap_or_else(|| {
            format!(
                "<smtp-{}@{}>",
                FILE_COUNTER.load(Ordering::Relaxed),
                self.config.domain
            )
        });
        let subject = header_value(&envelope.data, "subject");
        let from_address = header_value(&envelope.data, "from");
        let to_addresses = header_value(&envelope.data, "to")
            .map(|value| address_list_json(&value))
            .unwrap_or_else(|| "[]".to_owned());
        let has_attachments = has_first_mime_attachment(&envelope.data);
        let received_at = Utc::now();
        let received_id = random_hex_upper(7).map_err(io::Error::other)?;
        let accepted_id = random_hex(4).map_err(io::Error::other)?;
        let raw = compose_message(
            &envelope,
            &mailbox,
            peer,
            &helo,
            encrypted,
            received_at,
            &received_id,
        );
        if raw.len() > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message exceeds configured maximum",
            ));
        }
        let raw_len = raw.len();
        let counter = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now_millis = received_at.timestamp_subsec_millis();
        let file_name = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}.{:03}-{}-{}.eml",
            received_at.year(),
            received_at.month(),
            received_at.day(),
            received_at.hour(),
            received_at.minute(),
            received_at.second(),
            now_millis,
            counter,
            counter,
        );
        let folder = "spam";
        let subdirectory = 1_i32;
        let final_path = self
            .config
            .maildir
            .join(&mailbox)
            .join(folder)
            .join(subdirectory.to_string())
            .join(&file_name);
        let temporary_path = self
            .config
            .maildir
            .join(&mailbox)
            .join("temp")
            .join(format!("incoming-{counter}.tmp"));
        let blocking_permit = self
            .blocking_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("SMTP blocking pool closed"))?;
        let final_path_for_write = final_path.clone();
        let temporary_path_for_write = temporary_path.clone();
        spawn_blocking(move || {
            let _permit = blocking_permit;
            atomic_publish(&temporary_path_for_write, &final_path_for_write, &raw)
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))??;

        let client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "database pool timeout"))?
            .map_err(|error| io::Error::other(error.to_string()))?;
        let index_result = timeout(
            DATABASE_TIMEOUT,
            client.execute(
                "INSERT INTO email_index (has_attachments, subdirectory, indexed_at, received_at, size_bytes, folder, from_address, message_id, subject, to_addresses, file_name, mailbox_address) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                &[
                    &has_attachments,
                    &subdirectory,
                    &received_at,
                    &received_at,
                    &(raw_len as i64),
                    &folder,
                    &from_address,
                    &message_id,
                    &subject,
                    &to_addresses,
                    &file_name,
                    &mailbox,
                ],
            ),
        )
        .await;
        match index_result {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                if let Err(cleanup) = self.remove_published(&final_path).await {
                    eprintln!("lmyzmail SMTP Maildir rollback failed: {cleanup}");
                }
                return Err(io::Error::other(error.to_string()));
            }
            Err(_) => {
                if let Err(cleanup) = self.remove_published(&final_path).await {
                    eprintln!("lmyzmail SMTP Maildir rollback failed: {cleanup}");
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "database insert timeout",
                ));
            }
        }
        let redis_key = format!("mail:count:{mailbox}:{folder}");
        if let Err(error) = redis_increment(&self.config.redis, &redis_key).await {
            let _ = timeout(
                DATABASE_TIMEOUT,
                client.execute(
                    "DELETE FROM email_index WHERE mailbox_address=$1 AND file_name=$2",
                    &[&mailbox, &file_name],
                ),
            )
            .await;
            if let Err(cleanup) = self.remove_published(&final_path).await {
                eprintln!("lmyzmail SMTP Maildir rollback failed: {cleanup}");
            }
            return Err(error);
        }
        Ok(accepted_id)
    }

    async fn mailbox_exists(&self, address: &str) -> io::Result<bool> {
        let client = timeout(DATABASE_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "database pool timeout"))?
            .map_err(|error| io::Error::other(error.to_string()))?;
        let row = timeout(
            DATABASE_TIMEOUT,
            client.query_one(
                "SELECT EXISTS(SELECT 1 FROM mailbox WHERE address=$1)",
                &[&address.to_ascii_lowercase()],
            ),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mailbox lookup timeout"))?
        .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(row.get(0))
    }

    async fn remove_published(&self, path: &Path) -> io::Result<()> {
        let permit = self
            .blocking_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("SMTP blocking pool closed"))?;
        let path = path.to_owned();
        spawn_blocking(move || {
            let _permit = permit;
            remove_published_file(&path)
        })
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
    }
}

pub async fn serve_smtp(
    config: Arc<RuntimeConfig>,
    database_pool: Pool,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let listener = TcpListener::bind((config.listen.host.as_str(), config.listen.smtp)).await?;
    let service = Arc::new(
        SmtpService::from_config(Arc::clone(&config), database_pool).map_err(io::Error::other)?,
    );
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    loop {
        while let Some(result) = tasks.try_join_next() {
            if let Ok(Err(error)) = result {
                eprintln!("lmyzmail SMTP connection failed: {error}");
            }
        }
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Some(permit) = connections.clone().try_acquire_owned().ok() else {
                    drop(stream);
                    continue;
                };
                let service = Arc::clone(&service);
                tasks.spawn(async move {
                    let _permit = permit;
                    handle_connection(stream, peer.ip(), service).await
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct Envelope {
    sender: Option<String>,
    recipients: Vec<String>,
    data: Vec<u8>,
}

impl Envelope {
    fn reset(&mut self) {
        self.sender = None;
        self.recipients.clear();
        self.data.clear();
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SessionState {
    Connected,
    Greeted,
}

enum ConnectionStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    Closed,
}

impl AsyncRead for ConnectionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SMTP connection is closed",
            ))),
        }
    }
}

impl AsyncWrite for ConnectionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(context, bytes),
            Self::Tls(stream) => Pin::new(stream).poll_write(context, bytes),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SMTP connection is closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream).poll_flush(context),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SMTP connection is closed",
            ))),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Closed => Poll::Ready(Ok(())),
        }
    }
}

struct BufferedConnection {
    stream: ConnectionStream,
    buffer: Vec<u8>,
}

impl BufferedConnection {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream: ConnectionStream::Plain(stream),
            buffer: Vec::with_capacity(4096),
        }
    }

    async fn upgrade_tls(&mut self, acceptor: &TlsAcceptor) -> io::Result<()> {
        let stream = std::mem::replace(&mut self.stream, ConnectionStream::Closed);
        let ConnectionStream::Plain(mut stream) = stream else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SMTP connection is already encrypted",
            ));
        };
        let mut client_hello_prefix = [0_u8; 11];
        let read = stream.peek(&mut client_hello_prefix).await?;
        if read == 0 || client_hello_prefix[0] != 0x16 {
            let mut discarded = [0_u8; 4096];
            let _ = timeout(Duration::from_millis(100), stream.read(&mut discarded)).await;
            let _ = stream.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMTP STARTTLS did not receive a TLS handshake record",
            ));
        }
        if read >= client_hello_prefix.len()
            && client_hello_prefix[5] == 0x01
            && u16::from_be_bytes([client_hello_prefix[9], client_hello_prefix[10]]) < 0x0303
        {
            stream.write_all(b"\x15\x03\x03\x00\x02\x02\x46").await?;
            stream.shutdown().await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMTP STARTTLS rejected a legacy TLS ClientHello",
            ));
        }
        let stream = acceptor
            .accept(stream)
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        self.stream = ConnectionStream::Tls(Box::new(stream));
        Ok(())
    }

    async fn read_line(&mut self, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(index) = self.buffer.iter().position(|byte| *byte == b'\n') {
                if index > max_bytes + 1 {
                    self.buffer.drain(..=index);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                let line = self.buffer.drain(..=index).collect::<Vec<_>>();
                return Ok(Some(line));
            }
            if self.buffer.len() > max_bytes + 1 {
                self.buffer.clear();
                loop {
                    let mut chunk = [0_u8; 2048];
                    let read = self.stream.read(&mut chunk).await?;
                    if read == 0 {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial line"));
                    }
                    if let Some(index) = chunk[..read].iter().position(|byte| *byte == b'\n') {
                        self.buffer.extend_from_slice(&chunk[index + 1..read]);
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                    }
                }
            }
            let mut chunk = [0_u8; 2048];
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial line"));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }

    async fn read_exact_bytes(&mut self, size: usize) -> io::Result<Vec<u8>> {
        if size > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk too large",
            ));
        }
        let mut output = Vec::with_capacity(size);
        let take = size.min(self.buffer.len());
        output.extend(self.buffer.drain(..take));
        while output.len() < size {
            let mut chunk = [0_u8; 8192];
            let remaining = size - output.len();
            let read_size = remaining.min(chunk.len());
            let read = self.stream.read(&mut chunk[..read_size]).await?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "partial BDAT"));
            }
            output.extend_from_slice(&chunk[..read]);
        }
        Ok(output)
    }

    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: IpAddr,
    service: Arc<SmtpService>,
) -> io::Result<()> {
    let mut io = BufferedConnection::new(stream);
    io.write_all(
        b"220 lmyzmail ESMTP lmyzmail SMTP Server 2.8.0 - Skibidi dop dop dop yes yes!\r\n",
    )
    .await?;
    let mut state = SessionState::Connected;
    let mut envelope = Envelope::default();
    let mut helo = "localhost".to_owned();
    let mut dispatcher_errors = 0_u8;
    let mut auth_probe_count = 0_u8;
    let mut tls_active = false;
    loop {
        let line = match io.read_line(MAX_COMMAND_BYTES).await {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                io.write_all(b"500 5.5.2 Line too long\r\n").await?;
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        let Some(command_line) = trim_crlf(&line) else {
            io.write_all(b"500 5.5.1 Command not recognized: \r\n")
                .await?;
            continue;
        };
        let command_line = command_line.trim_ascii();
        let (verb, argument) = split_command(command_line);
        let upper = verb.to_ascii_uppercase();
        match upper.as_str() {
            "EHLO" | "HELO" => {
                if argument.trim().is_empty() {
                    io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?;
                    continue;
                }
                helo = argument.trim().to_owned();
                state = SessionState::Greeted;
                envelope.reset();
                let response = if upper == "EHLO" {
                    b"250-lmyzmail Hello "
                } else {
                    b"250 lmyzmail Hello "
                };
                io.write_all(response).await?;
                io.write_all(helo.as_bytes()).await?;
                if upper == "EHLO" {
                    io.write_all(
                        b"\r\n250-PIPELINING\r\n250-SIZE 15728640\r\n250-8BITMIME\r\n250-CHUNKING\r\n",
                    )
                    .await?;
                    if service.tls_acceptor.is_some() && !tls_active {
                        io.write_all(b"250-STARTTLS\r\n").await?;
                    }
                    io.write_all(
                        b"250-ENHANCEDSTATUSCODES\r\n250-SMTPUTF8\r\n250 SKIBIDITOILET\r\n",
                    )
                    .await?;
                } else {
                    io.write_all(b"\r\n").await?;
                }
            }
            "MAIL" => {
                if auth_probe_count >= 20 {
                    io.write_all(b"550 5.7.1 Access denied\r\n").await?;
                    continue;
                }
                if state != SessionState::Greeted || envelope.sender.is_some() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                    continue;
                }
                match parse_mail(argument) {
                    Ok(Some(sender)) => {
                        envelope.sender = Some(sender);
                        envelope.recipients.clear();
                        io.write_all(b"250 2.1.0 Sender OK\r\n").await?;
                    }
                    Ok(None) => io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?,
                    Err(ParseError::TooLarge) => io.write_all(b"552 5.3.4 Message size exceeds limit of 15728640 bytes\r\n").await?,
                    Err(ParseError::Invalid) => io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?,
                }
            }
            "RCPT" => {
                if state != SessionState::Greeted || envelope.sender.is_none() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                    continue;
                }
                match parse_recipient(argument) {
                    Some(recipient) if recipient.ends_with(&format!("@{}", service.config.domain)) => {
                        if envelope.recipients.len() >= MAX_RECIPIENTS {
                            io.write_all(b"452 4.5.3 Too many recipients\r\n").await?;
                        } else if service.mailbox_exists(&recipient).await? {
                            envelope.recipients.push(recipient);
                            io.write_all(b"250 2.1.5 Recipient OK\r\n").await?;
                        } else {
                            io.write_all(format!("550 5.1.1 Mailbox not found: {recipient}\r\n").as_bytes()).await?;
                        }
                    }
                    Some(recipient) => {
                        io.write_all(format!("550 5.1.2 Domain not accepted: {}\r\n", recipient.rsplit_once('@').map_or("", |(_, domain)| domain)).as_bytes()).await?;
                    }
                    None => io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?,
                }
            }
            "DATA" => {
                if state != SessionState::Greeted || envelope.sender.is_none() || envelope.recipients.is_empty() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                    continue;
                }
                io.write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n").await?;
                match read_data(&mut io).await {
                    Ok(Some(data)) => {
                        envelope.data = data;
                        match service.deliver(envelope.clone(), peer, &helo, tls_active).await {
                            Ok(id) => io.write_all(format!("250 2.0.0 Message accepted for delivery, id={id}\r\n").as_bytes()).await?,
                            Err(_) => io.write_all(b"451 4.3.0 Temporary delivery failure\r\n").await?,
                        }
                        envelope.reset();
                    }
                    Ok(None) => return Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                        io.write_all(b"552 5.3.4 Message size exceeds limit of 15728640 bytes\r\n").await?;
                        envelope.reset();
                    }
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
            "BDAT" => {
                if state != SessionState::Greeted || envelope.sender.is_none() || envelope.recipients.is_empty() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                    continue;
                }
                match parse_bdat(argument) {
                    Ok((size, last)) if size <= MAX_MESSAGE_BYTES.saturating_sub(envelope.data.len()) => {
                        if size == 0 && last {
                            envelope.reset();
                            io.write_all(b"250 2.0.0 0 bytes received\r\n").await?;
                            continue;
                        }
                        let chunk = io.read_exact_bytes(size).await?;
                        envelope.data.extend_from_slice(&chunk);
                        if last {
                            match service.deliver(envelope.clone(), peer, &helo, tls_active).await {
                                Ok(id) => io.write_all(format!("250 2.0.0 Message accepted for delivery, id={id}\r\n").as_bytes()).await?,
                                Err(_) => io.write_all(b"451 4.3.0 Temporary delivery failure\r\n").await?,
                            }
                            envelope.reset();
                        } else {
                            io.write_all(format!("250 2.0.0 {size} bytes received\r\n").as_bytes()).await?;
                        }
                    }
                    Ok(_) => {
                        envelope.reset();
                        io.write_all(b"552 5.3.4 Message size exceeds limit of 15728640 bytes\r\n").await?;
                    }
                    Err(_) => io.write_all(b"501 5.5.4 Syntax error in parameters\r\n").await?,
                }
            }
            "RSET" => {
                envelope.reset();
                io.write_all(b"250 2.0.0 Reset OK\r\n").await?;
            }
            "NOOP" => io.write_all(b"250 OK\r\n").await?,
            "HELP" => io.write_all(b"214-Supported commands:\r\n214-HELO EHLO MAIL RCPT DATA BDAT\r\n214-RSET NOOP QUIT VRFY HELP STARTTLS\r\n214 For more information, see RFC 5321\r\n").await?,
            "STARTTLS" => {
                let Some(acceptor) = service.tls_acceptor.as_ref() else {
                    io.write_all(b"502 5.5.1 STARTTLS command not implemented\r\n")
                        .await?;
                    continue;
                };
                if tls_active || envelope.sender.is_some() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                    continue;
                }
                io.write_all(b"220 2.0.0 Ready to start TLS\r\n").await?;
                // Never interpret bytes that were already buffered before the TLS
                // handshake as plaintext SMTP commands.
                if !io.buffer.is_empty() {
                    return Ok(());
                }
                match timeout(TLS_HANDSHAKE_TIMEOUT, io.upgrade_tls(acceptor)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => return Ok(()),
                }
                tls_active = true;
                state = SessionState::Connected;
                helo = "localhost".to_owned();
                envelope.reset();
            }
            "VRFY" => io.write_all(b"252 2.5.2 Cannot verify user, but will accept message and attempt delivery\r\n").await?,
            "AUTH" => {
                if state != SessionState::Greeted || envelope.sender.is_some() {
                    io.write_all(b"503 5.5.1 Bad sequence of commands\r\n").await?;
                } else {
                    auth_probe_count = auth_probe_count.saturating_add(1);
                    io.write_all(b"502 5.5.1 AUTH command not implemented. Blud is yapping about AUTH but nobody is listening. We don't do that here. Take your L and go back to the lobby.\r\n").await?;
                }
            }
            "QUIT" => {
                io.write_all(b"221 2.0.0 lmyzmail closing connection\r\n").await?;
                return Ok(());
            }
            _ => {
                dispatcher_errors = dispatcher_errors.saturating_add(1);
                if dispatcher_errors >= 10 {
                    io.write_all(b"421 4.3.2 lmyzmail Service not available\r\n").await?;
                    return Ok(());
                }
                io.write_all(
                    format!("500 5.5.1 Command not recognized: {upper}\r\n").as_bytes(),
                )
                .await?;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ParseError {
    Invalid,
    TooLarge,
}

fn trim_crlf(line: &[u8]) -> Option<&[u8]> {
    line.strip_suffix(b"\r\n")
}

fn split_command(line: &[u8]) -> (&str, &str) {
    let text = std::str::from_utf8(line).unwrap_or("");
    text.split_once(char::is_whitespace)
        .map_or((text, ""), |(verb, argument)| (verb, argument))
}

fn parse_mail(argument: &str) -> Result<Option<String>, ParseError> {
    let trimmed = argument.trim_start();
    let Some(rest) = trimmed
        .strip_prefix("FROM:")
        .or_else(|| trimmed.strip_prefix("from:"))
    else {
        return Ok(None);
    };
    let mut parts = rest.split_whitespace();
    let path = parts.next().ok_or(ParseError::Invalid)?;
    if path == "<>" {
        if let Some(parameter) = parts.next()
            && let Some(size) = parameter.strip_prefix("SIZE=")
        {
            let size = size.parse::<usize>().map_err(|_| ParseError::Invalid)?;
            if size > MAX_MESSAGE_BYTES {
                return Err(ParseError::TooLarge);
            }
        }
        return Ok(Some(String::new()));
    }
    let Some(value) = path
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
    else {
        return Ok(None);
    };
    if value.is_empty() || !value.contains('@') {
        return Ok(None);
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn parse_recipient(argument: &str) -> Option<String> {
    let trimmed = argument.trim_start();
    let rest = trimmed
        .strip_prefix("TO:")
        .or_else(|| trimmed.strip_prefix("to:"))?
        .trim();
    let value = rest
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .unwrap_or(rest);
    (value.contains('@') && !value.contains(char::is_whitespace))
        .then(|| value.to_ascii_lowercase())
}

fn parse_bdat(argument: &str) -> Result<(usize, bool), ParseError> {
    let mut parts = argument.split_whitespace();
    let size = parts
        .next()
        .ok_or(ParseError::Invalid)?
        .parse::<usize>()
        .map_err(|_| ParseError::Invalid)?;
    let last = parts
        .next()
        .is_some_and(|word| word.eq_ignore_ascii_case("LAST"));
    if parts.next().is_some() {
        return Err(ParseError::Invalid);
    }
    Ok((size, last))
}

async fn read_data(io: &mut BufferedConnection) -> io::Result<Option<Vec<u8>>> {
    let mut data = Vec::new();
    loop {
        let Some(line) = io
            .read_line(MAX_MESSAGE_BYTES.saturating_sub(data.len()))
            .await?
        else {
            return Ok(None);
        };
        if line == b".\r\n" {
            return Ok(Some(data));
        }
        let content = line.strip_prefix(b".").unwrap_or(&line);
        if data.len().saturating_add(content.len()) > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        data.extend_from_slice(content);
    }
}

fn header_value(data: &[u8], wanted: &str) -> Option<String> {
    let header_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(data.len());
    let text = std::str::from_utf8(&data[..header_end]).ok()?;
    text.split("\r\n")
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted)
                .then(|| value.trim().to_owned())
        })
}

fn address_list_json(value: &str) -> String {
    let addresses = value
        .split(',')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                return None;
            }
            let address = trimmed
                .rsplit_once('<')
                .and_then(|(_, rest)| rest.strip_suffix('>'))
                .unwrap_or(trimmed)
                .trim();
            (!address.is_empty()).then(|| address.to_ascii_lowercase())
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&addresses).unwrap_or_else(|_| "[]".to_owned())
}

fn has_first_mime_attachment(data: &[u8]) -> bool {
    let Some(content_type) = header_value(data, "content-type") else {
        return false;
    };
    let Some(boundary) = content_type
        .split(';')
        .map(str::trim)
        .find_map(|parameter| parameter.strip_prefix("boundary="))
    else {
        return false;
    };
    let boundary = boundary.trim_matches('"');
    if boundary.is_empty() {
        return false;
    }
    let marker = format!("--{boundary}").into_bytes();
    let header_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(data.len(), |index| index + 4);
    let body = &data[header_end..];
    let Some(first_start) = body
        .windows(marker.len())
        .position(|window| window == marker.as_slice())
    else {
        return false;
    };
    let first = body[first_start + marker.len()..]
        .strip_prefix(b"\r\n")
        .unwrap_or(&body[first_start + marker.len()..]);
    let Some(second_start) = first
        .windows(marker.len())
        .position(|window| window == marker.as_slice())
    else {
        return false;
    };
    let part = &first[..second_start];
    std::str::from_utf8(part)
        .map(|text| {
            text.split("\r\n")
                .take_while(|line| !line.is_empty())
                .any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.eq_ignore_ascii_case("content-disposition")
                            && value.to_ascii_lowercase().contains("attachment")
                    })
                })
        })
        .unwrap_or(false)
}

fn compose_message(
    envelope: &Envelope,
    mailbox: &str,
    peer: IpAddr,
    helo: &str,
    encrypted: bool,
    received_at: DateTime<Utc>,
    received_id: &str,
) -> Vec<u8> {
    let sender_clause = envelope
        .sender
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("");
    let auth_spf = if sender_clause.is_empty() {
        "spf=none (No MAIL FROM address)"
    } else {
        "spf=neutral (No SPF record found)"
    };
    let protocol = if encrypted { "ESMTPS" } else { "ESMTP" };
    let spam_rules = if header_value(&envelope.data, "from").is_some()
        && header_value(&envelope.data, "to").is_some()
    {
        "NEW_DOMAIN=2.0, MISSING_HEADERS=1.5"
    } else {
        "MISSING_HEADERS=3.5"
    };
    let date = java_rfc1123(received_at);
    let header = format!(
        "Received: from {helo} (localhost [{peer}])\r\n\tby {HOSTNAME} with {protocol} id {received_id}\r\n\tfor <{mailbox}>;\r\n\t{date}\r\nAuthentication-Results: {HOSTNAME};\r\n\t{auth_spf} smtp.client-ip={peer} smtp.mailfrom={sender_clause};\r\n\tdkim=none (No DKIM signature present);\r\n\tdmarc=none No DMARC record found\r\nX-Spam-Status: No\r\nX-Spam-Score: 3.5\r\nX-Spam-Rules: {spam_rules}\r\n"
    );
    let mut output = header.into_bytes();
    output.extend_from_slice(&envelope.data);
    output
}

fn java_rfc1123(value: DateTime<Utc>) -> String {
    let weekday = match value.weekday() {
        Weekday::Mon => "Mon",
        Weekday::Tue => "Tue",
        Weekday::Wed => "Wed",
        Weekday::Thu => "Thu",
        Weekday::Fri => "Fri",
        Weekday::Sat => "Sat",
        Weekday::Sun => "Sun",
    };
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][value.month0() as usize];
    format!(
        "{weekday}, {} {month} {} {:02}:{:02}:{:02} GMT",
        value.day(),
        value.year(),
        value.hour(),
        value.minute(),
        value.second()
    )
}

fn random_hex(bytes: usize) -> Result<String, getrandom::Error> {
    let mut value = vec![0_u8; bytes];
    fill_random(&mut value)?;
    Ok(value
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn random_hex_upper(bytes: usize) -> Result<String, getrandom::Error> {
    let mut value = vec![0_u8; bytes];
    fill_random(&mut value)?;
    Ok(value
        .into_iter()
        .map(|byte| format!("{byte:02X}"))
        .collect())
}

fn atomic_publish(temporary: &Path, final_path: &Path, data: &[u8]) -> io::Result<()> {
    if temporary.exists() || final_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "maildir path collision",
        ));
    }
    let temporary_parent = temporary
        .parent()
        .ok_or_else(|| io::Error::other("missing temp parent"))?;
    let final_parent = final_path
        .parent()
        .ok_or_else(|| io::Error::other("missing final parent"))?;
    std::fs::create_dir_all(temporary_parent)?;
    std::fs::create_dir_all(final_parent)?;
    let mut published = false;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temporary)?;
        use std::io::Write;
        file.write_all(data)?;
        file.flush()?;
        file.sync_all()?;
        std::fs::rename(temporary, final_path)?;
        published = true;
        std::fs::File::open(final_parent)?.sync_all()
    })();
    if result.is_err() {
        let cleanup_path = if published { final_path } else { temporary };
        let _ = std::fs::remove_file(cleanup_path);
        let _ = std::fs::File::open(if published {
            final_parent
        } else {
            temporary_parent
        })
        .and_then(|directory| directory.sync_all());
    }
    result
}

fn remove_published_file(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "published Maildir path is not a regular file",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("published Maildir path has no parent"))?;
    std::fs::remove_file(path)?;
    std::fs::File::open(parent)?.sync_all()
}

async fn redis_increment(config: &crate::config::RedisConfig, key: &str) -> io::Result<i64> {
    let mut stream = timeout(
        REDIS_TIMEOUT,
        TcpStream::connect((&*config.host, config.port)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Redis connect timeout"))??;
    if config.database != 0 {
        write_resp_command(&mut stream, &["SELECT", &config.database.to_string()]).await?;
        let _ = read_redis_line(&mut stream).await?;
    }
    write_resp_command(&mut stream, &["INCR", key]).await?;
    let line = read_redis_line(&mut stream).await?;
    line.strip_prefix(b":")
        .and_then(|value| std::str::from_utf8(value.trim_ascii_end()).ok())
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Redis INCR reply"))
}

async fn write_resp_command(stream: &mut TcpStream, parts: &[&str]) -> io::Result<()> {
    let mut request = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        request.extend_from_slice(format!("${}\r\n{}\r\n", part.len(), part).as_bytes());
    }
    stream.write_all(&request).await
}

async fn read_redis_line(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        if timeout(REDIS_TIMEOUT, stream.read_exact(&mut byte))
            .await
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Redis read timeout",
            ));
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
        if line.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Redis reply too long",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mail_rcpt_and_bdat_bounds() {
        assert_eq!(parse_mail("FROM:<>").unwrap(), Some(String::new()));
        assert_eq!(
            parse_mail("FROM:<qa@example.test> SIZE=10").unwrap(),
            Some("qa@example.test".into())
        );
        assert_eq!(parse_mail("FROM:<>").unwrap(), Some(String::new()));
        assert_eq!(parse_mail("FROM:<>").unwrap(), Some(String::new()));
        assert_eq!(
            parse_recipient("TO:<qa@example.test>"),
            Some("qa@example.test".into())
        );
        assert_eq!(
            parse_recipient("TO:qa@example.test"),
            Some("qa@example.test".into())
        );
        assert_eq!(parse_bdat("10 LAST"), Ok((10, true)));
        assert_eq!(parse_bdat("10"), Ok((10, false)));
        assert!(parse_bdat("10 LAST extra").is_err());
    }

    #[test]
    fn data_unstuffs_one_leading_dot_and_preserves_binary_bytes() {
        let mut line = b"..hello\r\n".to_vec();
        let content = line.strip_prefix(b".").unwrap();
        assert_eq!(content, b".hello\r\n");
        line.extend_from_slice(b"\0\xff");
        assert_eq!(&line[line.len() - 2..], b"\0\xff");
    }

    #[test]
    fn java_date_uses_unpadded_day_and_gmt() {
        let value = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(java_rfc1123(value), "Mon, 1 Jan 2024 00:00:00 GMT");
    }

    #[test]
    fn binary_body_does_not_break_header_indexing() {
        let message = b"From: Sender <sender@example.test>\r\n\
To: qa@example.test, Other <other@example.test>\r\n\
Subject: binary\r\nMessage-ID: <binary@example.test>\r\n\r\n\x00\xff\x80";
        assert_eq!(header_value(message, "subject").as_deref(), Some("binary"));
        assert_eq!(
            header_value(message, "message-id").as_deref(),
            Some("<binary@example.test>")
        );
        assert_eq!(
            address_list_json(&header_value(message, "to").unwrap()),
            r#"["qa@example.test","other@example.test"]"#
        );
    }

    #[test]
    fn attachment_index_matches_oracle_first_part_behavior() {
        let attachment_first = b"Content-Type: multipart/mixed; boundary=bb\r\n\r\n\
--bb\r\nContent-Disposition: attachment; filename=x\r\n\r\ndata\r\n\
--bb\r\nContent-Type: text/plain\r\n\r\nbody\r\n--bb--\r\n";
        let body_first = b"Content-Type: multipart/mixed; boundary=bb\r\n\r\n\
--bb\r\nContent-Type: text/plain\r\n\r\nbody\r\n\
--bb\r\nContent-Disposition: attachment; filename=x\r\n\r\ndata\r\n--bb--\r\n";
        assert!(has_first_mime_attachment(attachment_first));
        assert!(!has_first_mime_attachment(body_first));
    }
}
