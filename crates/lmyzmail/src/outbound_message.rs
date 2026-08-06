use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use mail_auth::{
    common::{
        crypto::{RsaKey, Sha256},
        headers::HeaderWriter,
    },
    dkim::{Canonicalization, DkimSigner, Done},
};
use mail_builder::encoders::quoted_printable::quoted_printable_encode;
use openssl::pkey::PKey;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256 as Sha256Digest};

use crate::config::RuntimeConfig;

const SMALL_MESSAGE_THRESHOLD: u64 = 10 * 1024;
const MAX_DKIM_KEY_BYTES: u64 = 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 32 * 1024;

type RsaDkimSigner = DkimSigner<RsaKey<Sha256>, Done>;

#[derive(Clone)]
pub struct OutboundMessageBuilder {
    maildir: PathBuf,
    spool_dir: PathBuf,
    max_files_per_directory: usize,
    max_email_size: u64,
    list_unsubscribe_mailto: Option<String>,
    list_unsubscribe_url: Option<String>,
    dkim_signer: Option<Arc<RsaDkimSigner>>,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageAttachment {
    pub filename: String,
    pub content_type: String,
    pub content_base64: String,
    pub inline: bool,
    pub content_id: Option<String>,
}

#[derive(Debug)]
pub struct MessageInput {
    pub task_id: i64,
    pub sender: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<MessageAttachment>,
    pub message_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct MaterializedMessage {
    pub sent_file_name: String,
    pub sent_subdirectory: i32,
    pub sent_path: PathBuf,
    pub sent_created: bool,
    pub spool_path: PathBuf,
    pub spool_created: bool,
    pub message_bytes: u64,
    pub signed_content_base64: Option<String>,
}

#[derive(Debug)]
pub enum MessageBuildError {
    Cancelled,
    Configuration(String),
    InvalidInput(&'static str),
    Io(io::Error),
}

impl std::fmt::Display for MessageBuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("outbound message build cancelled"),
            Self::Configuration(message) => formatter.write_str(message),
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::Io(_) => formatter.write_str("outbound message storage failed"),
        }
    }
}

impl std::error::Error for MessageBuildError {}

impl From<io::Error> for MessageBuildError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl OutboundMessageBuilder {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, MessageBuildError> {
        let max_files_per_directory = config
            .preferred_value(
                "lmyzmail.maildir.max-files-per-directory",
                "botmail.maildir.max-files-per-directory",
            )
            .map(str::parse::<usize>)
            .transpose()
            .map_err(|_| {
                MessageBuildError::Configuration(
                    "maildir max-files-per-directory is invalid".into(),
                )
            })?
            .unwrap_or(10_000);
        if !(1..=1_000_000).contains(&max_files_per_directory) {
            return Err(MessageBuildError::Configuration(
                "maildir max-files-per-directory is outside the safe bound".into(),
            ));
        }
        let spool_dir = config
            .preferred_value("lmyzmail.outbound.spool-dir", "botmail.outbound.temp-dir")
            .map(PathBuf::from)
            .unwrap_or_else(|| config.maildir.join(".lmyzmail-outbound"));
        let dkim_path = config
            .preferred_value(
                "lmyzmail.domains.main.dkim-private-key-path",
                "botmail.domains.main.dkimPrivateKeyPath",
            )
            .filter(|value| !value.is_empty());
        let dkim_selector = config
            .preferred_value(
                "lmyzmail.domains.main.dkim-selector",
                "botmail.domains.main.dkimSelector",
            )
            .filter(|value| !value.is_empty());
        let dkim_signer = match (dkim_path, dkim_selector) {
            (None, None) => None,
            (Some(path), Some(selector)) => {
                Some(Arc::new(load_dkim_signer(path, &config.domain, selector)?))
            }
            _ => {
                return Err(MessageBuildError::Configuration(
                    "DKIM private key and selector must be configured together".into(),
                ));
            }
        };
        Ok(Self {
            maildir: config.maildir.clone(),
            spool_dir,
            max_files_per_directory,
            max_email_size: config.limits.max_email_size_bytes,
            list_unsubscribe_mailto: config
                .preferred_value(
                    "lmyzmail.domains.main.list-unsubscribe-mailto",
                    "botmail.domains.main.listUnsubscribeMailto",
                )
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            list_unsubscribe_url: config
                .preferred_value(
                    "lmyzmail.domains.main.list-unsubscribe-url",
                    "botmail.domains.main.listUnsubscribeUrl",
                )
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            dkim_signer,
        })
    }

    pub fn materialize(
        &self,
        input: &MessageInput,
        cancelled: &AtomicBool,
    ) -> Result<MaterializedMessage, MessageBuildError> {
        check_cancelled(cancelled)?;
        let spool_root = secure_directory(&self.spool_dir)?;
        let spool_path = spool_root.join(format!("message-{}.eml", input.task_id));
        if spool_path.exists() {
            validate_regular_file(&spool_path)?;
            return Err(MessageBuildError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "new outbound task spool already exists",
            )));
        }
        let spool_created = self.build_spool(input, &spool_root, &spool_path, cancelled)?;
        let result =
            self.materialize_from_spool(input, spool_path.clone(), spool_created, cancelled);
        if result.is_err() && spool_created {
            let _ = remove_regular_file(&spool_path);
        }
        result
    }

    pub fn cleanup_small_spool(&self, message: &MaterializedMessage) -> io::Result<()> {
        if message.signed_content_base64.is_some() && message.spool_created {
            remove_regular_file(&message.spool_path)?;
        }
        Ok(())
    }

    pub fn recover(
        &self,
        task_id: i64,
        sender: &str,
        sent_file_name: &str,
        sent_subdirectory: i32,
        cancelled: &AtomicBool,
    ) -> Result<MaterializedMessage, MessageBuildError> {
        check_cancelled(cancelled)?;
        validate_sent_file_name(sent_file_name)?;
        if task_id <= 0 || sent_subdirectory <= 0 {
            return Err(MessageBuildError::InvalidInput(
                "invalid_outbound_storage_reference",
            ));
        }
        let sent_root = secure_child_directory(&self.maildir, sender, "sent")?;
        let sent_dir = secure_numeric_directory(&sent_root, sent_subdirectory)?;
        let sent_path = sent_dir.join(sent_file_name);
        validate_regular_file(&sent_path)?;
        let message_bytes = fs::metadata(&sent_path)?.len();
        if message_bytes == 0 || message_bytes > self.max_email_size {
            return Err(MessageBuildError::InvalidInput("email_too_large"));
        }

        let spool_root = secure_directory(&self.spool_dir)?;
        let spool_path = spool_root.join(format!("message-{task_id}.eml"));
        let (spool_created, signed_content_base64) = if message_bytes < SMALL_MESSAGE_THRESHOLD {
            check_cancelled(cancelled)?;
            let mut bytes = Vec::with_capacity(message_bytes as usize);
            File::open(&sent_path)?.read_to_end(&mut bytes)?;
            (false, Some(BASE64_STANDARD.encode(bytes)))
        } else {
            let created = if spool_path.exists() {
                validate_regular_file(&spool_path)?;
                if !files_equal(&sent_path, &spool_path, cancelled)? {
                    return Err(MessageBuildError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "outbound spool differs from sent message",
                    )));
                }
                false
            } else {
                atomic_copy(&sent_path, &spool_path, self.max_email_size, cancelled)?;
                true
            };
            (created, None)
        };
        Ok(MaterializedMessage {
            sent_file_name: sent_file_name.to_owned(),
            sent_subdirectory,
            sent_path,
            sent_created: false,
            spool_path,
            spool_created,
            message_bytes,
            signed_content_base64,
        })
    }

    pub fn rollback_sent(&self, message: &MaterializedMessage) -> io::Result<()> {
        if message.sent_created {
            remove_regular_file(&message.sent_path)?;
        }
        Ok(())
    }

    pub fn rollback_unpublished(&self, message: &MaterializedMessage) -> io::Result<()> {
        let sent_result = self.rollback_sent(message);
        let spool_result = if message.spool_created {
            remove_regular_file(&message.spool_path)
        } else {
            Ok(())
        };
        sent_result.and(spool_result)
    }

    fn build_spool(
        &self,
        input: &MessageInput,
        spool_root: &Path,
        spool_path: &Path,
        cancelled: &AtomicBool,
    ) -> Result<bool, MessageBuildError> {
        let unsigned_path = spool_root.join(format!(".unsigned-{}.tmp", input.task_id));
        let signed_path = spool_root.join(format!(".signed-{}.tmp", input.task_id));
        cleanup_owned_temp(&unsigned_path)?;
        cleanup_owned_temp(&signed_path)?;
        let result: Result<(), MessageBuildError> = (|| {
            let unsigned = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&unsigned_path)?;
            let mut writer = BoundedWriter::new(BufWriter::new(unsigned), self.max_email_size);
            self.write_message(input, &mut writer, cancelled)?;
            let mut unsigned = writer.finish()?;
            unsigned.flush()?;
            unsigned.get_ref().sync_all()?;
            check_cancelled(cancelled)?;

            if let Some(signer) = self.dkim_signer.as_deref() {
                let mut signing_stream = signer.sign_streaming();
                let mut input_file =
                    BufReader::with_capacity(COPY_BUFFER_BYTES, File::open(&unsigned_path)?);
                let mut buffer = [0_u8; COPY_BUFFER_BYTES];
                loop {
                    check_cancelled(cancelled)?;
                    let count = input_file.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    signing_stream.write(&buffer[..count]);
                }
                let signature = signing_stream
                    .finish()
                    .map_err(|_| MessageBuildError::Configuration("DKIM signing failed".into()))?;
                let signed = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&signed_path)?;
                let mut writer = BoundedWriter::new(BufWriter::new(signed), self.max_email_size);
                writer.write_all(signature.to_header().as_bytes())?;
                copy_bounded(&mut File::open(&unsigned_path)?, &mut writer, cancelled)?;
                let mut signed = writer.finish()?;
                signed.flush()?;
                signed.get_ref().sync_all()?;
                publish_temp_file(&signed_path, spool_path)?;
                remove_regular_file(&unsigned_path)?;
            } else {
                publish_temp_file(&unsigned_path, spool_path)?;
            }
            File::open(spool_root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = cleanup_owned_temp(&unsigned_path);
            let _ = cleanup_owned_temp(&signed_path);
        }
        result?;
        Ok(true)
    }

    fn materialize_from_spool(
        &self,
        input: &MessageInput,
        spool_path: PathBuf,
        spool_created: bool,
        cancelled: &AtomicBool,
    ) -> Result<MaterializedMessage, MessageBuildError> {
        validate_regular_file(&spool_path)?;
        let message_bytes = fs::metadata(&spool_path)?.len();
        if message_bytes == 0 || message_bytes > self.max_email_size {
            return Err(MessageBuildError::InvalidInput("email_too_large"));
        }
        let sent_root = secure_child_directory(&self.maildir, &input.sender, "sent")?;
        let sent_subdirectory =
            select_subdirectory(&sent_root, self.max_files_per_directory, input.task_id)?;
        let sent_dir = secure_numeric_directory(&sent_root, sent_subdirectory)?;
        let sent_file_name = sent_file_name(input);
        let sent_path = sent_dir.join(&sent_file_name);
        let sent_created = if sent_path.exists() {
            validate_regular_file(&sent_path)?;
            if !files_equal(&spool_path, &sent_path, cancelled)? {
                return Err(MessageBuildError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "sent Maildir collision",
                )));
            }
            false
        } else {
            atomic_copy(&spool_path, &sent_path, self.max_email_size, cancelled)?;
            true
        };
        let signed_content_base64 = if message_bytes < SMALL_MESSAGE_THRESHOLD {
            check_cancelled(cancelled)?;
            let mut bytes = Vec::with_capacity(message_bytes as usize);
            File::open(&spool_path)?.read_to_end(&mut bytes)?;
            Some(BASE64_STANDARD.encode(bytes))
        } else {
            None
        };
        Ok(MaterializedMessage {
            sent_file_name,
            sent_subdirectory,
            sent_path,
            sent_created,
            spool_path,
            spool_created,
            message_bytes,
            signed_content_base64,
        })
    }

    fn write_message(
        &self,
        input: &MessageInput,
        output: &mut impl Write,
        cancelled: &AtomicBool,
    ) -> Result<(), MessageBuildError> {
        writeln_crlf(output, &format!("From: {}", input.sender))?;
        if !input.to.is_empty() {
            writeln_crlf(output, &format!("To: {}", input.to.join(", ")))?;
        }
        if !input.cc.is_empty() {
            writeln_crlf(output, &format!("Cc: {}", input.cc.join(", ")))?;
        }
        writeln_crlf(output, &format!("Subject: {}", input.subject))?;
        writeln_crlf(output, &format!("Date: {}", java_date(input.created_at)))?;
        writeln_crlf(output, &format!("Message-ID: {}", input.message_id))?;
        writeln_crlf(output, "MIME-Version: 1.0")?;
        let mut unsubscribe = Vec::new();
        if let Some(url) = self.list_unsubscribe_url.as_deref() {
            unsubscribe.push(format!("<{url}>"));
            writeln_crlf(output, "List-Unsubscribe-Post: List-Unsubscribe=One-Click")?;
        }
        if let Some(mailto) = self.list_unsubscribe_mailto.as_deref() {
            unsubscribe.push(format!("<mailto:{mailto}>"));
        }
        if !unsubscribe.is_empty() {
            writeln_crlf(
                output,
                &format!("List-Unsubscribe: {}", unsubscribe.join(", ")),
            )?;
        }

        let has_html = input
            .html
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let has_attachments = !input.attachments.is_empty();
        let has_inline = input.attachments.iter().any(|attachment| attachment.inline);
        if !has_attachments && !has_html {
            writeln_crlf(output, "Content-Type: text/plain; charset=UTF-8")?;
            writeln_crlf(output, "Content-Transfer-Encoding: quoted-printable")?;
            writeln_crlf(output, "")?;
            write_quoted_printable(input.text.as_deref().unwrap_or_default(), output)?;
            return Ok(());
        }

        let mixed = boundary(&input.message_id, "mixed");
        if !has_attachments {
            let alternative = boundary(&input.message_id, "alternative");
            writeln_crlf(
                output,
                &format!("Content-Type: multipart/alternative; boundary=\"{alternative}\""),
            )?;
            writeln_crlf(output, "")?;
            write_alternative(input, &alternative, output)?;
            return Ok(());
        }

        writeln_crlf(
            output,
            &format!("Content-Type: multipart/mixed; boundary=\"{mixed}\""),
        )?;
        writeln_crlf(output, "")?;
        if has_inline {
            let related = boundary(&input.message_id, "related");
            let alternative = boundary(&input.message_id, "alternative");
            write_boundary(output, &mixed, false)?;
            writeln_crlf(
                output,
                &format!("Content-Type: multipart/related; boundary=\"{related}\""),
            )?;
            writeln_crlf(output, "")?;
            write_boundary(output, &related, false)?;
            writeln_crlf(
                output,
                &format!("Content-Type: multipart/alternative; boundary=\"{alternative}\""),
            )?;
            writeln_crlf(output, "")?;
            write_alternative(input, &alternative, output)?;
            for attachment in input.attachments.iter().filter(|value| value.inline) {
                check_cancelled(cancelled)?;
                write_attachment(output, &related, attachment)?;
            }
            write_boundary(output, &related, true)?;
        } else if has_html {
            let alternative = boundary(&input.message_id, "alternative");
            write_boundary(output, &mixed, false)?;
            writeln_crlf(
                output,
                &format!("Content-Type: multipart/alternative; boundary=\"{alternative}\""),
            )?;
            writeln_crlf(output, "")?;
            write_alternative(input, &alternative, output)?;
        } else {
            write_boundary(output, &mixed, false)?;
            write_text_part(output, input.text.as_deref().unwrap_or_default())?;
        }
        for attachment in input.attachments.iter().filter(|value| !value.inline) {
            check_cancelled(cancelled)?;
            write_attachment(output, &mixed, attachment)?;
        }
        write_boundary(output, &mixed, true)?;
        Ok(())
    }
}

fn load_dkim_signer(
    path: &str,
    domain: &str,
    selector: &str,
) -> Result<RsaDkimSigner, MessageBuildError> {
    let metadata = fs::metadata(path)
        .map_err(|_| MessageBuildError::Configuration("DKIM private key cannot be read".into()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_DKIM_KEY_BYTES {
        return Err(MessageBuildError::Configuration(
            "DKIM private key is not a bounded regular file".into(),
        ));
    }
    let bytes = fs::read(path)
        .map_err(|_| MessageBuildError::Configuration("DKIM private key cannot be read".into()))?;
    let private_key = PKey::private_key_from_pem(&bytes)
        .and_then(|key| key.private_key_to_pkcs8())
        .map_err(|_| MessageBuildError::Configuration("DKIM private key is invalid".into()))?;
    let key =
        RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key)))
            .map_err(|_| MessageBuildError::Configuration("DKIM RSA key is invalid".into()))?;
    Ok(DkimSigner::from_key(key)
        .domain(domain)
        .selector(selector)
        .headers([
            "From",
            "To",
            "Cc",
            "Subject",
            "Date",
            "Message-ID",
            "Content-Type",
            "Content-Transfer-Encoding",
            "MIME-Version",
            "List-Unsubscribe",
            "List-Unsubscribe-Post",
        ])
        .header_canonicalization(Canonicalization::Relaxed)
        .body_canonicalization(Canonicalization::Relaxed))
}

fn write_alternative(
    input: &MessageInput,
    boundary: &str,
    output: &mut impl Write,
) -> io::Result<()> {
    write_boundary(output, boundary, false)?;
    write_text_part(output, input.text.as_deref().unwrap_or_default())?;
    write_boundary(output, boundary, false)?;
    writeln_crlf(output, "Content-Type: text/html; charset=UTF-8")?;
    writeln_crlf(output, "Content-Transfer-Encoding: quoted-printable")?;
    writeln_crlf(output, "")?;
    write_quoted_printable(input.html.as_deref().unwrap_or_default(), output)?;
    writeln_crlf(output, "")?;
    write_boundary(output, boundary, true)
}

fn write_text_part(output: &mut impl Write, text: &str) -> io::Result<()> {
    writeln_crlf(output, "Content-Type: text/plain; charset=UTF-8")?;
    writeln_crlf(output, "Content-Transfer-Encoding: quoted-printable")?;
    writeln_crlf(output, "")?;
    write_quoted_printable(text, output)?;
    writeln_crlf(output, "")
}

fn write_quoted_printable(text: &str, output: &mut impl Write) -> io::Result<()> {
    quoted_printable_encode(text.as_bytes(), output, true).map(|_| ())
}

fn write_attachment(
    output: &mut impl Write,
    boundary: &str,
    attachment: &MessageAttachment,
) -> io::Result<()> {
    write_boundary(output, boundary, false)?;
    writeln_crlf(
        output,
        &format!("Content-Type: {}", attachment.content_type),
    )?;
    writeln_crlf(output, "Content-Transfer-Encoding: base64")?;
    let disposition = if attachment.inline {
        "inline"
    } else {
        "attachment"
    };
    writeln_crlf(
        output,
        &format!(
            "Content-Disposition: {disposition}; filename*=UTF-8''{}",
            encode_filename(&attachment.filename)
        ),
    )?;
    if attachment.inline
        && let Some(content_id) = attachment.content_id.as_deref()
    {
        writeln_crlf(output, &format!("Content-ID: <{content_id}>"))?;
    }
    writeln_crlf(output, "")?;
    for chunk in attachment.content_base64.as_bytes().chunks(76) {
        output.write_all(chunk)?;
        output.write_all(b"\r\n")?;
    }
    writeln_crlf(output, "")
}

fn write_boundary(output: &mut impl Write, boundary: &str, final_boundary: bool) -> io::Result<()> {
    if final_boundary {
        writeln_crlf(output, &format!("--{boundary}--"))
    } else {
        writeln_crlf(output, &format!("--{boundary}"))
    }
}

fn writeln_crlf(output: &mut impl Write, value: &str) -> io::Result<()> {
    output.write_all(value.as_bytes())?;
    output.write_all(b"\r\n")
}

fn boundary(message_id: &str, label: &str) -> String {
    let digest = Sha256Digest::digest(format!("{message_id}:{label}").as_bytes());
    let suffix = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("=_lmyzmail_{suffix}")
}

fn encode_filename(filename: &str) -> String {
    let mut encoded = String::with_capacity(filename.len());
    for byte in filename.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

fn java_date(value: DateTime<Utc>) -> String {
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
        "{weekday}, {} {month} {} {:02}:{:02}:{:02} +0000",
        value.day(),
        value.year(),
        value.hour(),
        value.minute(),
        value.second()
    )
}

fn sent_file_name(input: &MessageInput) -> String {
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}.{:03}-lmyzmail-{}.eml",
        input.created_at.year(),
        input.created_at.month(),
        input.created_at.day(),
        input.created_at.hour(),
        input.created_at.minute(),
        input.created_at.second(),
        input.created_at.timestamp_subsec_millis(),
        input.task_id,
    )
}

fn secure_directory(path: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "storage directory is not a real directory",
        ));
    }
    fs::canonicalize(path)
}

fn secure_child_directory(base: &Path, address: &str, folder: &str) -> io::Result<PathBuf> {
    let base = secure_directory(base)?;
    let address_path = base.join(address);
    let address_path = secure_directory(&address_path)?;
    if !address_path.starts_with(&base) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mailbox directory escapes Maildir",
        ));
    }
    let folder_path = secure_directory(&address_path.join(folder))?;
    if !folder_path.starts_with(&address_path) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "folder directory escapes mailbox",
        ));
    }
    Ok(folder_path)
}

fn secure_numeric_directory(base: &Path, subdirectory: i32) -> io::Result<PathBuf> {
    let path = secure_directory(&base.join(subdirectory.to_string()))?;
    if !path.starts_with(base) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Maildir shard escapes sent folder",
        ));
    }
    Ok(path)
}

fn select_subdirectory(base: &Path, max_files: usize, task_id: i64) -> io::Result<i32> {
    let expected_name = format!("-lmyzmail-{task_id}.eml");
    let mut maximum = 0_i32;
    let mut maximum_files = 0_usize;
    for entry in fs::read_dir(base)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let Some(index) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| *value > 0)
        else {
            continue;
        };
        let mut count = 0_usize;
        for file in fs::read_dir(entry.path())? {
            let file = file?;
            let file_type = file.file_type()?;
            if file_type.is_file() && !file_type.is_symlink() {
                count = count.saturating_add(1);
                if file.file_name().to_string_lossy().ends_with(&expected_name) {
                    return Ok(index);
                }
            }
        }
        if index > maximum {
            maximum = index;
            maximum_files = count;
        }
    }
    if maximum == 0 {
        Ok(1)
    } else if maximum_files >= max_files {
        maximum
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Maildir shard index overflow"))
    } else {
        Ok(maximum)
    }
}

fn validate_regular_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message path is not a regular file",
        ));
    }
    Ok(())
}

fn validate_sent_file_name(value: &str) -> Result<(), MessageBuildError> {
    let mut components = Path::new(value).components();
    let valid_component = matches!(components.next(), Some(std::path::Component::Normal(_)));
    if value.is_empty()
        || value.len() > 255
        || value.chars().any(char::is_control)
        || !valid_component
        || components.next().is_some()
    {
        return Err(MessageBuildError::InvalidInput(
            "invalid_outbound_storage_reference",
        ));
    }
    Ok(())
}

fn cleanup_owned_temp(path: &Path) -> io::Result<()> {
    if path.exists() {
        remove_regular_file(path)?;
    }
    Ok(())
}

fn remove_regular_file(path: &Path) -> io::Result<()> {
    validate_regular_file(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("message file has no parent"))?;
    fs::remove_file(path)?;
    File::open(parent)?.sync_all()
}

fn atomic_copy(
    source: &Path,
    destination: &Path,
    max_bytes: u64,
    cancelled: &AtomicBool,
) -> io::Result<()> {
    validate_regular_file(source)?;
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("sent file has no parent"))?;
    let destination_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("sent filename is not UTF-8"))?;
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let nonce = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = parent.join(format!(".{destination_name}.{nonce}.tmp"));
    let result = (|| {
        let mut input = File::open(source)?;
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let mut output = BoundedWriter::new(BufWriter::new(output), max_bytes);
        copy_bounded(&mut input, &mut output, cancelled)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut output = output.finish()?;
        output.flush()?;
        output.get_ref().sync_all()?;
        publish_temp_file(&temporary, destination)
    })();
    if result.is_err() {
        let _ = cleanup_owned_temp(&temporary);
    }
    result
}

fn publish_temp_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    validate_regular_file(temporary)?;
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("published file has no parent"))?;
    fs::hard_link(temporary, destination)?;
    fs::remove_file(temporary)?;
    File::open(parent)?.sync_all()
}

fn files_equal(
    first: &Path,
    second: &Path,
    cancelled: &AtomicBool,
) -> Result<bool, MessageBuildError> {
    if fs::metadata(first)?.len() != fs::metadata(second)?.len() {
        return Ok(false);
    }
    let mut first = BufReader::with_capacity(COPY_BUFFER_BYTES, File::open(first)?);
    let mut second = BufReader::with_capacity(COPY_BUFFER_BYTES, File::open(second)?);
    let mut first_buffer = [0_u8; COPY_BUFFER_BYTES];
    let mut second_buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        check_cancelled(cancelled)?;
        let first_count = first.read(&mut first_buffer)?;
        let second_count = second.read(&mut second_buffer)?;
        if first_count != second_count
            || first_buffer[..first_count] != second_buffer[..second_count]
        {
            return Ok(false);
        }
        if first_count == 0 {
            return Ok(true);
        }
    }
}

fn copy_bounded(
    input: &mut impl Read,
    output: &mut impl Write,
    cancelled: &AtomicBool,
) -> Result<u64, MessageBuildError> {
    let mut copied = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        check_cancelled(cancelled)?;
        let count = input.read(&mut buffer)?;
        if count == 0 {
            return Ok(copied);
        }
        output.write_all(&buffer[..count])?;
        copied = copied.saturating_add(count as u64);
    }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), MessageBuildError> {
    if cancelled.load(Ordering::Acquire) {
        Err(MessageBuildError::Cancelled)
    } else {
        Ok(())
    }
}

struct BoundedWriter<W> {
    inner: W,
    written: u64,
    maximum: u64,
}

impl<W> BoundedWriter<W> {
    fn new(inner: W, maximum: u64) -> Self {
        Self {
            inner,
            written: 0,
            maximum,
        }
    }

    fn finish(self) -> io::Result<W> {
        Ok(self.inner)
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.maximum.saturating_sub(self.written);
        if remaining == 0 && !buffer.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "email exceeds configured size limit",
            ));
        }
        let allowed = buffer.len().min(remaining as usize);
        let count = self.inner.write(&buffer[..allowed])?;
        self.written = self.written.saturating_add(count as u64);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "lmyzmail-outbound-message-test-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn message() -> MessageInput {
        MessageInput {
            task_id: 42,
            sender: "qa@example.test".into(),
            to: vec!["user@remote.test".into()],
            cc: vec![],
            bcc: vec!["hidden@remote.test".into()],
            subject: "Hello".into(),
            text: Some("plain body".into()),
            html: Some("<p>HTML body</p>".into()),
            attachments: vec![MessageAttachment {
                filename: "proof.txt".into(),
                content_type: "text/plain".into(),
                content_base64: "aGVsbG8=".into(),
                inline: false,
                content_id: None,
            }],
            message_id: "<stable@example.test>".into(),
            created_at: Utc.with_ymd_and_hms(2026, 8, 6, 1, 2, 3).unwrap(),
        }
    }

    #[test]
    fn mime_writer_is_stable_and_omits_bcc() {
        let builder = OutboundMessageBuilder {
            maildir: PathBuf::from("/mail"),
            spool_dir: PathBuf::from("/spool"),
            max_files_per_directory: 10,
            max_email_size: 1024 * 1024,
            list_unsubscribe_mailto: None,
            list_unsubscribe_url: None,
            dkim_signer: None,
        };
        let mut first = Vec::new();
        builder
            .write_message(&message(), &mut first, &AtomicBool::new(false))
            .unwrap();
        let mut second = Vec::new();
        builder
            .write_message(&message(), &mut second, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(first, second);
        let text = String::from_utf8(first).unwrap();
        assert!(text.contains("Date: Thu, 6 Aug 2026 01:02:03 +0000\r\n"));
        assert!(text.contains("Content-Disposition: attachment"));
        assert!(text.contains("aGVsbG8=\r\n"));
        assert!(!text.contains("hidden@remote.test"));
        assert!(!text.contains("Bcc:"));
    }

    #[test]
    fn bounded_writer_fails_before_exceeding_limit() {
        let mut output = BoundedWriter::new(Vec::new(), 3);
        assert!(output.write_all(b"four").is_err());
        assert_eq!(output.written, 3);
    }

    #[test]
    fn recovery_uses_sent_for_small_messages_and_rebuilds_large_spools() {
        let root = TestDirectory::new();
        let builder = OutboundMessageBuilder {
            maildir: root.0.join("maildir"),
            spool_dir: root.0.join("spool"),
            max_files_per_directory: 10,
            max_email_size: 64 * 1024,
            list_unsubscribe_mailto: None,
            list_unsubscribe_url: None,
            dkim_signer: None,
        };
        let cancelled = AtomicBool::new(false);

        let mut small = message();
        small.html = None;
        small.attachments.clear();
        let small_message = builder.materialize(&small, &cancelled).unwrap();
        let expected_base64 = small_message.signed_content_base64.clone().unwrap();
        builder.cleanup_small_spool(&small_message).unwrap();
        assert!(!small_message.spool_path.exists());
        let recovered_small = builder
            .recover(
                small.task_id,
                &small.sender,
                &small_message.sent_file_name,
                small_message.sent_subdirectory,
                &cancelled,
            )
            .unwrap();
        assert_eq!(
            recovered_small.signed_content_base64.as_deref(),
            Some(expected_base64.as_str())
        );
        assert!(!recovered_small.spool_created);

        let mut large = message();
        large.task_id = 43;
        large.message_id = "<large@example.test>".into();
        large.text = Some("z".repeat(12 * 1024));
        large.html = None;
        large.attachments.clear();
        let large_message = builder.materialize(&large, &cancelled).unwrap();
        assert!(large_message.signed_content_base64.is_none());
        remove_regular_file(&large_message.spool_path).unwrap();
        let recovered_large = builder
            .recover(
                large.task_id,
                &large.sender,
                &large_message.sent_file_name,
                large_message.sent_subdirectory,
                &cancelled,
            )
            .unwrap();
        assert!(recovered_large.spool_created);
        assert!(
            files_equal(
                &recovered_large.sent_path,
                &recovered_large.spool_path,
                &cancelled
            )
            .unwrap()
        );
    }

    #[test]
    fn new_tasks_never_reuse_an_existing_spool() {
        let root = TestDirectory::new();
        let builder = OutboundMessageBuilder {
            maildir: root.0.join("maildir"),
            spool_dir: root.0.join("spool"),
            max_files_per_directory: 10,
            max_email_size: 64 * 1024,
            list_unsubscribe_mailto: None,
            list_unsubscribe_url: None,
            dkim_signer: None,
        };
        fs::create_dir_all(&builder.spool_dir).unwrap();
        fs::write(builder.spool_dir.join("message-42.eml"), b"stale message").unwrap();
        let error = builder
            .materialize(&message(), &AtomicBool::new(false))
            .unwrap_err();
        assert!(matches!(error, MessageBuildError::Io(_)));
    }
}
