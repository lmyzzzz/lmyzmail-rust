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
        crypto::{RsaKey, Sha256, SigningKey},
        headers::{HeaderStream, HeaderWriter, Writable},
    },
    dkim::{Canonicalization, DkimSigner, Done, Signature},
};
use mail_builder::encoders::base64::base64_encode as dkim_base64_encode;
use openssl::pkey::PKey;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256 as Sha256Digest};

use crate::{
    config::RuntimeConfig, outbound_coordinator::validate_and_maybe_remove_spool,
    outbound_delivery::OutboundSpoolRecord,
};

const SMALL_MESSAGE_THRESHOLD: u64 = 10 * 1024;
const MAX_DKIM_KEY_BYTES: u64 = 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 32 * 1024;

type RsaDkimSigner = DkimSigner<RsaKey<Sha256>, Done>;

struct DkimHeaderStream<'a> {
    message: &'a [u8],
    cursor: usize,
    header_start: usize,
}

impl<'a> DkimHeaderStream<'a> {
    fn new(message: &'a [u8]) -> Self {
        Self {
            message,
            cursor: 0,
            header_start: 0,
        }
    }
}

impl<'a> HeaderStream<'a> for DkimHeaderStream<'a> {
    fn next_header(&mut self) -> Option<(&'a [u8], &'a [u8])> {
        let mut colon = None;
        let mut previous = 0;

        while let Some(&byte) = self.message.get(self.cursor) {
            let position = self.cursor;
            self.cursor += 1;
            if colon.is_none() {
                match byte {
                    b':' => colon = Some(position),
                    b'\n' => {
                        if previous == b'\r' || self.header_start == position {
                            return None;
                        }
                        if self
                            .message
                            .get(self.cursor)
                            .is_none_or(|next| !b" \t".contains(next))
                        {
                            let name = self
                                .message
                                .get(self.header_start..=position)
                                .unwrap_or_default();
                            self.header_start = self.cursor;
                            return Some((name, b""));
                        }
                    }
                    _ => {}
                }
            } else if let Some(colon) = colon
                && byte == b'\n'
                && self
                    .message
                    .get(self.cursor)
                    .is_none_or(|next| !b" \t".contains(next))
            {
                let name = self
                    .message
                    .get(self.header_start..colon)
                    .unwrap_or_default();
                let value = self.message.get(colon + 1..=position).unwrap_or_default();
                self.header_start = self.cursor;
                return Some((name, value));
            }
            previous = byte;
        }
        None
    }

    fn body(&mut self) -> &'a [u8] {
        self.message.get(self.cursor..).unwrap_or_default()
    }
}

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

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageAttachment {
    pub filename: String,
    pub content_type: String,
    pub content_base64: String,
    pub inline: bool,
    pub content_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageStorageMode {
    Inline,
    Spool,
}

pub(crate) struct SystemMaterialization<'a> {
    pub(crate) task_id: i64,
    pub(crate) sender: &'a str,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) bytes: &'a [u8],
    pub(crate) storage_mode: MessageStorageMode,
    pub(crate) expected_sha256: &'a [u8; 32],
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
    pub cleanup_spool_after_publish: bool,
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
        if message.cleanup_spool_after_publish {
            remove_regular_file(&message.spool_path)?;
        }
        Ok(())
    }

    pub(crate) fn cleanup_owned_spool(
        &self,
        record: &OutboundSpoolRecord,
        cancelled: &AtomicBool,
    ) -> Result<(), MessageBuildError> {
        check_cancelled(cancelled)?;
        validate_and_maybe_remove_spool(
            record,
            &self.spool_dir,
            &self.maildir,
            self.max_email_size,
            true,
        )?;
        check_cancelled(cancelled)
    }

    pub(crate) fn prepare_system_bytes(
        &self,
        created_at: DateTime<Utc>,
        bytes: &[u8],
        expected_sha256: &[u8; 32],
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, MessageBuildError> {
        check_cancelled(cancelled)?;
        if bytes.is_empty() || bytes.len() as u64 > self.max_email_size {
            return Err(MessageBuildError::InvalidInput(
                "invalid_outbound_system_message",
            ));
        }
        if Sha256Digest::digest(bytes).as_slice() != expected_sha256 {
            return Err(MessageBuildError::InvalidInput(
                "outbound_system_message_digest_mismatch",
            ));
        }
        let prepared =
            if let Some(signer) = self.dkim_signer.as_deref() {
                let timestamp = u64::try_from(created_at.timestamp()).map_err(|_| {
                    MessageBuildError::InvalidInput("invalid_outbound_system_message_time")
                })?;
                let signature = sign_dkim_at(signer, bytes, timestamp)?;
                let header = signature.to_header();
                let prepared_len = header.len().checked_add(bytes.len()).ok_or(
                    MessageBuildError::InvalidInput("email_size_estimate_overflow"),
                )?;
                if prepared_len as u64 > self.max_email_size {
                    return Err(MessageBuildError::InvalidInput("email_too_large"));
                }
                let mut prepared = Vec::with_capacity(prepared_len);
                prepared.extend_from_slice(header.as_bytes());
                prepared.extend_from_slice(bytes);
                prepared
            } else {
                bytes.to_vec()
            };
        check_cancelled(cancelled)?;
        Ok(prepared)
    }

    /// Materialize authenticated, already-signed system-message bytes. Every
    /// publish is no-clobber; retries trust only the digest persisted by the
    /// token-fenced DSN outbox checkpoint.
    pub(crate) fn materialize_bytes(
        &self,
        request: SystemMaterialization<'_>,
        cancelled: &AtomicBool,
    ) -> Result<MaterializedMessage, MessageBuildError> {
        let SystemMaterialization {
            task_id,
            sender,
            created_at,
            bytes,
            storage_mode,
            expected_sha256,
        } = request;
        check_cancelled(cancelled)?;
        if task_id <= 0 || sender.is_empty() || bytes.is_empty() {
            return Err(MessageBuildError::InvalidInput(
                "invalid_outbound_system_message",
            ));
        }
        if bytes.len() as u64 > self.max_email_size {
            return Err(MessageBuildError::InvalidInput("email_too_large"));
        }
        let final_digest: [u8; 32] = Sha256Digest::digest(bytes).into();
        let prepared_matches = final_digest == *expected_sha256;
        let candidate_spool_path = self.spool_dir.join(format!("message-{task_id}.eml"));
        if !prepared_matches && !candidate_spool_path.exists() {
            return Err(MessageBuildError::InvalidInput(
                "outbound_system_signing_key_changed",
            ));
        }
        let spool_root = secure_directory(&self.spool_dir)?;
        let spool_path = spool_root.join(format!("message-{task_id}.eml"));
        let spool_created = if spool_path.exists() {
            validate_regular_file(&spool_path)?;
            if hash_regular_file(&spool_path, self.max_email_size, cancelled)? != *expected_sha256 {
                return Err(MessageBuildError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "outbound system spool digest mismatch",
                )));
            }
            false
        } else {
            debug_assert!(prepared_matches);
            match atomic_publish_bytes(&spool_root, &spool_path, bytes, self.max_email_size) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    validate_regular_file(&spool_path)?;
                    if hash_regular_file(&spool_path, self.max_email_size, cancelled)?
                        != *expected_sha256
                    {
                        return Err(MessageBuildError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "outbound system spool digest mismatch",
                        )));
                    }
                    false
                }
                Err(error) => return Err(error.into()),
            }
        };
        let message_bytes = fs::metadata(&spool_path)?.len();
        if message_bytes == 0 || message_bytes > self.max_email_size {
            return Err(MessageBuildError::InvalidInput("email_too_large"));
        }

        let sent_root = secure_child_directory(&self.maildir, sender, "sent")?;
        let sent_subdirectory =
            select_subdirectory(&sent_root, self.max_files_per_directory, task_id)?;
        let sent_dir = secure_numeric_directory(&sent_root, sent_subdirectory)?;
        let sent_file_name = sent_file_name_for(task_id, created_at);
        let sent_path = sent_dir.join(&sent_file_name);
        let sent_created = if sent_path.exists() {
            validate_regular_file(&sent_path)?;
            if hash_regular_file(&sent_path, self.max_email_size, cancelled)? != *expected_sha256 {
                return Err(MessageBuildError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "outbound system Sent digest mismatch",
                )));
            }
            false
        } else {
            match atomic_copy(&spool_path, &sent_path, self.max_email_size, cancelled) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    validate_regular_file(&sent_path)?;
                    if hash_regular_file(&sent_path, self.max_email_size, cancelled)?
                        != *expected_sha256
                    {
                        return Err(MessageBuildError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "outbound system Sent digest mismatch",
                        )));
                    }
                    false
                }
                Err(error) => return Err(error.into()),
            }
        };
        let signed_content_base64 = if storage_mode == MessageStorageMode::Inline {
            if prepared_matches {
                Some(BASE64_STANDARD.encode(bytes))
            } else {
                let mut persisted = Vec::with_capacity(message_bytes as usize);
                File::open(&spool_path)?.read_to_end(&mut persisted)?;
                if persisted.len() as u64 != message_bytes {
                    return Err(MessageBuildError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "outbound system spool changed while reading",
                    )));
                }
                Some(BASE64_STANDARD.encode(persisted))
            }
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
            cleanup_spool_after_publish: storage_mode == MessageStorageMode::Inline,
            message_bytes,
            signed_content_base64,
        })
    }

    pub fn recover(
        &self,
        task_id: i64,
        sender: &str,
        sent_file_name: &str,
        sent_subdirectory: i32,
        storage_mode: MessageStorageMode,
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
        let (spool_created, signed_content_base64) = match storage_mode {
            MessageStorageMode::Inline => {
                let owned_spool = if spool_path.exists() {
                    validate_regular_file(&spool_path)?;
                    if !files_equal(&sent_path, &spool_path, cancelled)? {
                        return Err(MessageBuildError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "outbound spool differs from sent message",
                        )));
                    }
                    true
                } else {
                    false
                };
                check_cancelled(cancelled)?;
                let mut bytes = Vec::with_capacity(message_bytes as usize);
                File::open(&sent_path)?.read_to_end(&mut bytes)?;
                (owned_spool, Some(BASE64_STANDARD.encode(bytes)))
            }
            MessageStorageMode::Spool => {
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
            }
        };
        Ok(MaterializedMessage {
            sent_file_name: sent_file_name.to_owned(),
            sent_subdirectory,
            sent_path,
            sent_created: false,
            spool_path,
            spool_created,
            cleanup_spool_after_publish: storage_mode == MessageStorageMode::Inline
                && spool_created,
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
        let signed_content_base64 = match java_storage_mode(
            input.text.as_deref(),
            input.html.as_deref(),
            &input.attachments,
        )? {
            MessageStorageMode::Inline => {
                check_cancelled(cancelled)?;
                let mut bytes = Vec::with_capacity(message_bytes as usize);
                File::open(&spool_path)?.read_to_end(&mut bytes)?;
                Some(BASE64_STANDARD.encode(bytes))
            }
            MessageStorageMode::Spool => None,
        };
        Ok(MaterializedMessage {
            sent_file_name,
            sent_subdirectory,
            sent_path,
            sent_created,
            spool_path,
            spool_created,
            cleanup_spool_after_publish: signed_content_base64.is_some(),
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

#[cfg(test)]
fn java_estimated_message_size(input: &MessageInput) -> Result<u64, MessageBuildError> {
    java_estimated_message_parts(
        input.text.as_deref(),
        input.html.as_deref(),
        &input.attachments,
    )
}

pub fn java_storage_mode(
    text: Option<&str>,
    html: Option<&str>,
    attachments: &[MessageAttachment],
) -> Result<MessageStorageMode, MessageBuildError> {
    if java_estimated_message_parts(text, html, attachments)? < SMALL_MESSAGE_THRESHOLD {
        Ok(MessageStorageMode::Inline)
    } else {
        Ok(MessageStorageMode::Spool)
    }
}

fn java_estimated_message_parts(
    text: Option<&str>,
    html: Option<&str>,
    attachments: &[MessageAttachment],
) -> Result<u64, MessageBuildError> {
    let mut size = 2_048_u64;
    for body in [text, html].into_iter().flatten() {
        size = size
            .checked_add(
                u64::try_from(body.len())
                    .map_err(|_| MessageBuildError::InvalidInput("email_size_estimate_overflow"))?,
            )
            .ok_or(MessageBuildError::InvalidInput(
                "email_size_estimate_overflow",
            ))?;
    }
    for attachment in attachments {
        let base64_bytes = attachment.content_base64.trim_end_matches('=').len();
        let decoded_bytes = u64::try_from(base64_bytes)
            .ok()
            .and_then(|value| value.checked_mul(3))
            .and_then(|value| value.checked_add(3))
            .map(|value| value / 4)
            .ok_or(MessageBuildError::InvalidInput(
                "email_size_estimate_overflow",
            ))?;
        let encoded_estimate = decoded_bytes
            .checked_mul(4)
            .map(|value| value / 3)
            .and_then(|value| value.checked_add(200))
            .ok_or(MessageBuildError::InvalidInput(
                "email_size_estimate_overflow",
            ))?;
        size = size
            .checked_add(encoded_estimate)
            .ok_or(MessageBuildError::InvalidInput(
                "email_size_estimate_overflow",
            ))?;
    }
    Ok(size)
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

fn sign_dkim_at(
    signer: &RsaDkimSigner,
    message: &[u8],
    timestamp: u64,
) -> Result<Signature, MessageBuildError> {
    let (body_len, canonical_headers, signed_headers, canonical_body) =
        signer.template.canonicalize(DkimHeaderStream::new(message));
    if signed_headers.is_empty() {
        return Err(MessageBuildError::Configuration(
            "DKIM signing found no eligible headers".into(),
        ));
    }
    let mut signature = signer.template.clone();
    let body_hash = signer.key.hash(canonical_body);
    signature.bh = dkim_base64_encode(body_hash.as_ref())
        .map_err(|_| MessageBuildError::Configuration("DKIM body hash failed".into()))?;
    signature.t = timestamp;
    signature.x = if signature.x > 0 {
        timestamp
            .checked_add(signature.x)
            .ok_or_else(|| MessageBuildError::Configuration("DKIM expiration overflowed".into()))?
    } else {
        0
    };
    signature.h = signed_headers;
    if signature.l > 0 {
        signature.l = body_len as u64;
    }

    let mut signable = Vec::new();
    canonical_headers.write(&mut signable);
    signature.write(&mut signable, false);
    let signature_bytes = signer
        .key
        .sign(signable.as_slice())
        .map_err(|_| MessageBuildError::Configuration("DKIM signing failed".into()))?;
    signature.b = dkim_base64_encode(&signature_bytes)
        .map_err(|_| MessageBuildError::Configuration("DKIM encoding failed".into()))?;
    Ok(signature)
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
    let mut line_length = 0_usize;
    for byte in text.bytes() {
        match byte {
            b'\r' => {}
            b'\n' => {
                output.write_all(b"\r\n")?;
                line_length = 0;
            }
            b'!'..=b'<' | b'>'..=b'~' | b' ' | b'\t' => {
                write_quoted_printable_unit(output, &mut line_length, &[byte])?;
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                let encoded = [b'=', HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]];
                write_quoted_printable_unit(output, &mut line_length, &encoded)?;
            }
        }
    }
    Ok(())
}

fn write_quoted_printable_unit(
    output: &mut impl Write,
    line_length: &mut usize,
    unit: &[u8],
) -> io::Result<()> {
    if line_length.saturating_add(unit.len()) > 75 {
        output.write_all(b"=\r\n")?;
        *line_length = 0;
    }
    output.write_all(unit)?;
    *line_length += unit.len();
    Ok(())
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
    sent_file_name_for(input.task_id, input.created_at)
}

fn sent_file_name_for(task_id: i64, created_at: DateTime<Utc>) -> String {
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}.{:03}-lmyzmail-{}.eml",
        created_at.year(),
        created_at.month(),
        created_at.day(),
        created_at.hour(),
        created_at.minute(),
        created_at.second(),
        created_at.timestamp_subsec_millis(),
        task_id,
    )
}

fn atomic_publish_bytes(
    parent: &Path,
    destination: &Path,
    bytes: &[u8],
    max_bytes: u64,
) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "system message exceeds configured size limit",
        ));
    }
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let nonce = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = parent.join(format!(".system-{nonce}.tmp"));
    let result = (|| {
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let mut writer = BufWriter::new(output);
        writer.write_all(bytes)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        match publish_temp_file(&temporary, destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
            Err(error) => Err(error),
        }
    })();
    if result.is_err() {
        let _ = cleanup_owned_temp(&temporary);
    }
    result
}

fn hash_regular_file(
    path: &Path,
    max_bytes: u64,
    cancelled: &AtomicBool,
) -> Result<[u8; 32], MessageBuildError> {
    validate_regular_file(path)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(MessageBuildError::InvalidInput("email_too_large"));
    }
    let mut input = BufReader::with_capacity(COPY_BUFFER_BYTES, File::open(path)?);
    let mut digest = Sha256Digest::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        check_cancelled(cancelled)?;
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
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
    fn quoted_printable_matches_frozen_java_line_folding() {
        let mut output = Vec::new();
        write_quoted_printable(&"a".repeat(76), &mut output).unwrap();
        assert_eq!(output, format!("{}=\r\na", "a".repeat(75)).as_bytes());

        output.clear();
        write_quoted_printable("a\r\nb\nc\rd\0", &mut output).unwrap();
        assert_eq!(output, b"a\r\nb\r\ncd=00");
    }

    #[test]
    fn bounded_writer_fails_before_exceeding_limit() {
        let mut output = BoundedWriter::new(Vec::new(), 3);
        assert!(output.write_all(b"four").is_err());
        assert_eq!(output.written, 3);
    }

    #[test]
    fn java_estimate_selects_memory_and_file_modes_at_the_10k_boundary() {
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
        let mut below = message();
        below.html = None;
        below.attachments.clear();
        below.text = Some("m".repeat(8_191));
        assert_eq!(java_estimated_message_size(&below).unwrap(), 10_239);
        assert_eq!(
            java_storage_mode(below.text.as_deref(), None, &[]).unwrap(),
            MessageStorageMode::Inline
        );
        let below = builder.materialize(&below, &cancelled).unwrap();
        assert!(below.signed_content_base64.is_some());
        builder.cleanup_small_spool(&below).unwrap();

        let mut boundary = message();
        boundary.task_id = 43;
        boundary.message_id = "<boundary@example.test>".into();
        boundary.html = None;
        boundary.attachments.clear();
        boundary.text = Some("f".repeat(8_192));
        assert_eq!(java_estimated_message_size(&boundary).unwrap(), 10_240);
        assert_eq!(
            java_storage_mode(boundary.text.as_deref(), None, &[]).unwrap(),
            MessageStorageMode::Spool
        );
        let boundary = builder.materialize(&boundary, &cancelled).unwrap();
        assert!(boundary.signed_content_base64.is_none());
        assert!(boundary.spool_path.is_file());
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
                MessageStorageMode::Inline,
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
                MessageStorageMode::Spool,
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
    fn java_storage_mode_counts_utf8_and_attachment_estimates() {
        let inline_unicode = "\u{754c}".repeat(2_730);
        let spool_unicode = "\u{754c}".repeat(2_731);
        assert_eq!(inline_unicode.len(), 8_190);
        assert_eq!(spool_unicode.len(), 8_193);
        assert_eq!(
            java_storage_mode(Some(&inline_unicode), None, &[]).unwrap(),
            MessageStorageMode::Inline
        );
        assert_eq!(
            java_storage_mode(Some(&spool_unicode), None, &[]).unwrap(),
            MessageStorageMode::Spool
        );

        let attachment = MessageAttachment {
            filename: "three.bin".into(),
            content_type: "application/octet-stream".into(),
            content_base64: "YWJj".into(),
            inline: false,
            content_id: None,
        };
        assert_eq!(
            java_storage_mode(
                Some(&"a".repeat(7_987)),
                None,
                std::slice::from_ref(&attachment),
            )
            .unwrap(),
            MessageStorageMode::Inline
        );
        assert_eq!(
            java_storage_mode(Some(&"a".repeat(7_988)), None, &[attachment]).unwrap(),
            MessageStorageMode::Spool
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

    fn system_message_bytes() -> &'static [u8] {
        b"From: mailer-daemon@example.test\r\n\
To: qa@example.test\r\n\
Subject: Delivery Status Notification (Failure)\r\n\
Date: Thu, 6 Aug 2026 01:02:03 +0000\r\n\
Message-ID: <dsn-42@example.test>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=UTF-8\r\n\r\n\
Delivery failed.\r\n"
    }

    fn system_digest(bytes: &[u8]) -> [u8; 32] {
        Sha256Digest::digest(bytes).into()
    }

    fn system_builder(
        root: &Path,
        dkim_signer: Option<Arc<RsaDkimSigner>>,
    ) -> OutboundMessageBuilder {
        OutboundMessageBuilder {
            maildir: root.join("maildir"),
            spool_dir: root.join("spool"),
            max_files_per_directory: 10,
            max_email_size: 64 * 1024,
            list_unsubscribe_mailto: None,
            list_unsubscribe_url: None,
            dkim_signer,
        }
    }

    fn system_materialization<'a>(
        task_id: i64,
        created_at: DateTime<Utc>,
        bytes: &'a [u8],
        storage_mode: MessageStorageMode,
        expected_sha256: &'a [u8; 32],
    ) -> SystemMaterialization<'a> {
        SystemMaterialization {
            task_id,
            sender: "qa@example.test",
            created_at,
            bytes,
            storage_mode,
            expected_sha256,
        }
    }

    fn generated_dkim_signer(root: &Path) -> RsaDkimSigner {
        let key = openssl::rsa::Rsa::generate(2_048).unwrap();
        let key = PKey::from_rsa(key).unwrap();
        let path = root.join("dkim-private.pem");
        fs::write(&path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        load_dkim_signer(path.to_str().unwrap(), "example.test", "test").unwrap()
    }

    #[test]
    fn materialize_bytes_retries_without_dkim_are_deterministic_and_no_clobber() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let bytes = system_message_bytes();
        let unsigned_sha256 = system_digest(bytes);
        let created_at = Utc.with_ymd_and_hms(2026, 8, 6, 1, 2, 3).unwrap();
        let cancelled = AtomicBool::new(false);
        let fresh_root = TestDirectory::new();
        let fresh_builder = system_builder(&fresh_root.0, None);
        let wrong_digest = [0_u8; 32];
        let error = fresh_builder
            .prepare_system_bytes(created_at, bytes, &wrong_digest, &cancelled)
            .unwrap_err();
        assert!(matches!(
            error,
            MessageBuildError::InvalidInput("outbound_system_message_digest_mismatch")
        ));
        let error = fresh_builder
            .materialize_bytes(
                system_materialization(
                    41,
                    created_at,
                    bytes,
                    MessageStorageMode::Spool,
                    &wrong_digest,
                ),
                &cancelled,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            MessageBuildError::InvalidInput("outbound_system_signing_key_changed")
        ));
        assert!(!fresh_builder.spool_dir.exists());
        assert!(!fresh_builder.maildir.exists());

        let prepared = builder
            .prepare_system_bytes(created_at, bytes, &unsigned_sha256, &cancelled)
            .unwrap();
        assert_eq!(prepared, bytes);
        let prepared_sha256 = system_digest(&prepared);

        let first = builder
            .materialize_bytes(
                system_materialization(
                    42,
                    created_at,
                    &prepared,
                    MessageStorageMode::Spool,
                    &prepared_sha256,
                ),
                &cancelled,
            )
            .unwrap();
        assert!(first.spool_created);
        assert!(first.sent_created);
        assert!(!first.cleanup_spool_after_publish);
        assert!(first.signed_content_base64.is_none());
        let spool_before = fs::read(&first.spool_path).unwrap();
        let sent_before = fs::read(&first.sent_path).unwrap();

        let retry = builder
            .materialize_bytes(
                system_materialization(
                    42,
                    created_at,
                    &prepared,
                    MessageStorageMode::Spool,
                    &prepared_sha256,
                ),
                &cancelled,
            )
            .unwrap();
        assert!(!retry.spool_created);
        assert!(!retry.sent_created);
        assert_eq!(retry.spool_path, first.spool_path);
        assert_eq!(retry.sent_path, first.sent_path);
        assert_eq!(fs::read(&retry.spool_path).unwrap(), spool_before);
        assert_eq!(fs::read(&retry.sent_path).unwrap(), sent_before);

        let error = builder
            .materialize_bytes(
                system_materialization(
                    42,
                    created_at,
                    &prepared,
                    MessageStorageMode::Spool,
                    &wrong_digest,
                ),
                &cancelled,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            MessageBuildError::Io(ref error) if error.kind() == io::ErrorKind::InvalidData
        ));
        assert_eq!(fs::read(&first.spool_path).unwrap(), spool_before);
        assert_eq!(fs::read(&first.sent_path).unwrap(), sent_before);

        let replacement = b"different system message\r\n";
        let replacement_unsigned_sha256 = system_digest(replacement);
        let replacement = builder
            .prepare_system_bytes(
                created_at,
                replacement,
                &replacement_unsigned_sha256,
                &cancelled,
            )
            .unwrap();
        let replacement_sha256 = system_digest(&replacement);
        let error = builder
            .materialize_bytes(
                system_materialization(
                    42,
                    created_at,
                    &replacement,
                    MessageStorageMode::Spool,
                    &replacement_sha256,
                ),
                &cancelled,
            )
            .unwrap_err();
        assert!(
            matches!(error, MessageBuildError::Io(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert_eq!(fs::read(&first.spool_path).unwrap(), spool_before);
        assert_eq!(fs::read(&first.sent_path).unwrap(), sent_before);
    }

    #[test]
    fn materialize_bytes_dkim_signing_is_present_and_retry_bytes_match() {
        let root = TestDirectory::new();
        let signer = Arc::new(generated_dkim_signer(&root.0));
        let builder = system_builder(&root.0, Some(signer));
        let unsigned = system_message_bytes();
        let unsigned_sha256 = system_digest(unsigned);
        let created_at = Utc.with_ymd_and_hms(2026, 8, 6, 1, 2, 3).unwrap();
        let cancelled = AtomicBool::new(false);
        let first_wall_clock_second = Utc::now().timestamp();
        let first_prepared = builder
            .prepare_system_bytes(created_at, unsigned, &unsigned_sha256, &cancelled)
            .unwrap();
        while Utc::now().timestamp() == first_wall_clock_second {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let second_wall_clock_second = Utc::now().timestamp();
        assert_ne!(first_wall_clock_second, second_wall_clock_second);
        let second_prepared = builder
            .prepare_system_bytes(created_at, unsigned, &unsigned_sha256, &cancelled)
            .unwrap();
        assert_eq!(first_prepared, second_prepared);
        assert!(first_prepared.starts_with(b"DKIM-Signature: "));
        let prepared_sha256 = system_digest(&first_prepared);

        let first = builder
            .materialize_bytes(
                system_materialization(
                    43,
                    created_at,
                    &first_prepared,
                    MessageStorageMode::Spool,
                    &prepared_sha256,
                ),
                &cancelled,
            )
            .unwrap();
        let first_bytes = fs::read(&first.sent_path).unwrap();
        assert!(first_bytes.starts_with(b"DKIM-Signature: "));
        assert!(String::from_utf8_lossy(&first_bytes).contains("DKIM-Signature:"));
        assert!(first.spool_created);
        assert!(first.sent_created);

        let retry = builder
            .materialize_bytes(
                system_materialization(
                    43,
                    created_at,
                    &second_prepared,
                    MessageStorageMode::Spool,
                    &prepared_sha256,
                ),
                &cancelled,
            )
            .unwrap();
        let retry_bytes = fs::read(&retry.sent_path).unwrap();
        assert!(!retry.spool_created);
        assert!(!retry.sent_created);
        assert_eq!(retry_bytes, first_bytes);
        assert_eq!(fs::read(&retry.spool_path).unwrap(), first_bytes);
    }

    #[test]
    fn durable_system_bytes_survive_dkim_key_rotation_before_spool_publish() {
        let root = TestDirectory::new();
        let old_builder = system_builder(&root.0, Some(Arc::new(generated_dkim_signer(&root.0))));
        let unsigned = system_message_bytes();
        let unsigned_sha256 = system_digest(unsigned);
        let created_at = Utc.with_ymd_and_hms(2026, 8, 6, 1, 2, 3).unwrap();
        let cancelled = AtomicBool::new(false);
        let durable_bytes = old_builder
            .prepare_system_bytes(created_at, unsigned, &unsigned_sha256, &cancelled)
            .unwrap();
        let durable_sha256 = system_digest(&durable_bytes);

        let rotated_builder =
            system_builder(&root.0, Some(Arc::new(generated_dkim_signer(&root.0))));
        let rotated_bytes = rotated_builder
            .prepare_system_bytes(created_at, unsigned, &unsigned_sha256, &cancelled)
            .unwrap();
        assert_ne!(rotated_bytes, durable_bytes);
        assert!(!rotated_builder.spool_dir.exists());

        let materialized = rotated_builder
            .materialize_bytes(
                system_materialization(
                    46,
                    created_at,
                    &durable_bytes,
                    MessageStorageMode::Spool,
                    &durable_sha256,
                ),
                &cancelled,
            )
            .unwrap();
        assert_eq!(fs::read(&materialized.spool_path).unwrap(), durable_bytes);
        assert_eq!(fs::read(&materialized.sent_path).unwrap(), durable_bytes);
    }

    #[test]
    fn materialize_bytes_storage_mode_controls_spool_ownership_and_cleanup() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let unsigned = system_message_bytes();
        let unsigned_sha256 = system_digest(unsigned);
        let created_at = Utc.with_ymd_and_hms(2026, 8, 6, 1, 2, 3).unwrap();
        let cancelled = AtomicBool::new(false);
        let prepared = builder
            .prepare_system_bytes(created_at, unsigned, &unsigned_sha256, &cancelled)
            .unwrap();
        let prepared_sha256 = system_digest(&prepared);

        let spooled = builder
            .materialize_bytes(
                system_materialization(
                    44,
                    created_at,
                    &prepared,
                    MessageStorageMode::Spool,
                    &prepared_sha256,
                ),
                &cancelled,
            )
            .unwrap();
        assert!(spooled.spool_created);
        assert!(!spooled.cleanup_spool_after_publish);
        builder.cleanup_small_spool(&spooled).unwrap();
        assert!(spooled.spool_path.is_file());

        let inline = builder
            .materialize_bytes(
                system_materialization(
                    45,
                    created_at,
                    &prepared,
                    MessageStorageMode::Inline,
                    &prepared_sha256,
                ),
                &cancelled,
            )
            .unwrap();
        assert!(inline.spool_created);
        assert!(inline.cleanup_spool_after_publish);
        assert!(inline.signed_content_base64.is_some());
        assert!(inline.spool_path.is_file());
        assert!(inline.sent_path.is_file());
        builder.cleanup_small_spool(&inline).unwrap();
        assert!(!inline.spool_path.exists());
        assert!(inline.sent_path.is_file());
        let inline_record = crate::outbound_delivery::OutboundSpoolRecord {
            task_id: 45,
            spool_path: inline.spool_path.to_string_lossy().into_owned(),
            kind: crate::outbound_delivery::OutboundSpoolKind::Rust,
            state: crate::outbound_delivery::OutboundSpoolState::Owned,
            sender_address: "qa@example.test".into(),
            sent_file_name: inline.sent_file_name.clone(),
            sent_subdirectory: inline.sent_subdirectory,
        };
        builder
            .cleanup_owned_spool(&inline_record, &cancelled)
            .unwrap();

        let conflicting_record = crate::outbound_delivery::OutboundSpoolRecord {
            spool_path: spooled.spool_path.to_string_lossy().into_owned(),
            ..inline_record
        };
        let error = builder
            .cleanup_owned_spool(&conflicting_record, &cancelled)
            .unwrap_err();
        assert!(matches!(
            error,
            MessageBuildError::Io(ref error)
                if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert!(spooled.spool_path.is_file());
    }
}
