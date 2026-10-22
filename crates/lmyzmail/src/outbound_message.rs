use std::{
    collections::{HashMap, VecDeque, hash_map::DefaultHasher},
    ffi::{OsStr, OsString},
    fs::{self, File},
    hash::{Hash, Hasher},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
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
    config::RuntimeConfig,
    durability::{fsync, sync_all},
    mailbox::{
        sanitize_address_for_path, secure_mailbox_folder, v1_sanitize_address_for_path,
        v2_sanitize_address_for_path,
    },
    outbound_coordinator::validate_and_maybe_remove_spool,
    outbound_delivery::OutboundSpoolRecord,
};

const SMALL_MESSAGE_THRESHOLD: u64 = 10 * 1024;
const MAX_DKIM_KEY_BYTES: u64 = 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 32 * 1024;
const QUARANTINE_SWEEP_DIRECTORIES: usize = 8_192;
const QUARANTINE_SWEEP_ENTRIES: usize = 16_384;
const QUARANTINE_SWEEP_DEADLINE: Duration = Duration::from_secs(2);
const STAGING_WRITER_LEASE_DEADLINE: Duration = Duration::from_millis(100);
const QUARANTINE_SWEEP_MAX_DEPTH: usize = 64;
const MAX_PENDING_PUBLICATION_INTENTS: usize = 256;
const SENT_SHARD_LOCKS: usize = 64;
const MAX_SENT_SHARD_CACHE_ENTRIES: usize = 4_096;
const MAX_SENT_SHARD_CACHE_ENTRIES_PER_LOCK: usize =
    MAX_SENT_SHARD_CACHE_ENTRIES / SENT_SHARD_LOCKS;
const MAX_PENDING_SENT_NAMES_PER_FOLDER: usize = 512;
const SENT_SHARD_RESCAN_INTERVAL: usize = 256;
const OWNERSHIP_RECEIPT_MAGIC: &[u8; 8] = b"LMYZOWN\0";
const OWNERSHIP_RECEIPT_VERSION: u8 = 1;
const OWNERSHIP_RECEIPT_HEADER_BYTES: usize = 100;
const MAX_OWNERSHIP_FILE_NAME_BYTES: usize = 4_096;
const MAX_OWNERSHIP_RECEIPT_BYTES: usize =
    OWNERSHIP_RECEIPT_HEADER_BYTES + MAX_OWNERSHIP_FILE_NAME_BYTES;
static STAGING_INSTANCE_ID: OnceLock<[u8; 16]> = OnceLock::new();
#[derive(Debug)]
struct OwnershipReceipt {
    device: u64,
    inode: u64,
    publication: Option<PublicationProof>,
    original_file_name: OsString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationKind {
    Spool,
    Sent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicationProof {
    task_id: i64,
    kind: PublicationKind,
    size: u64,
    sha256: [u8; 32],
    instance_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicationIntent {
    task_id: i64,
    kind: PublicationKind,
    instance_id: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RustSpoolPublicationProof {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) size: u64,
    pub(crate) sha256: [u8; 32],
    pub(crate) receipt_name: OsString,
    pub(crate) quarantine_name: OsString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingPublicationKind {
    Spool,
    Sent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingPublicationIntent {
    pub(crate) task_id: i64,
    pub(crate) kind: PendingPublicationKind,
    pub(crate) original_path: PathBuf,
    pub(crate) quarantine_directory: PathBuf,
    pub(crate) receipt_name: OsString,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) size: u64,
    pub(crate) sha256: [u8; 32],
    pub(crate) instance_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationDisposition {
    Delete,
    PreserveAndClear,
    PreserveSpoolProof,
}

impl PublicationIntent {
    fn spool(task_id: i64, instance_id: [u8; 16]) -> Self {
        Self {
            task_id,
            kind: PublicationKind::Spool,
            instance_id,
        }
    }

    fn sent(task_id: i64, instance_id: [u8; 16]) -> Self {
        Self {
            task_id,
            kind: PublicationKind::Sent,
            instance_id,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PublishedFileOwnership {
    path: PathBuf,
    parent: std::os::fd::OwnedFd,
    file_name: OsString,
    file: Option<std::os::fd::OwnedFd>,
    device: u64,
    inode: u64,
    cleanup_state: PublishedFileCleanupState,
    staging_lease: Option<std::os::fd::OwnedFd>,
    cleanup_temporary_on_drop: bool,
    armed: bool,
}

#[derive(Debug)]
enum PublishedFileCleanupState {
    Original,
    PreparedReceipt {
        quarantine: std::os::fd::OwnedFd,
        quarantine_path: PathBuf,
        quarantine_name: OsString,
        receipt_name: OsString,
        receipt_directory_synced: bool,
    },
    Quarantined {
        original_path: PathBuf,
        original_parent: std::os::fd::OwnedFd,
        original_file_name: OsString,
        receipt_name: OsString,
        quarantine_directory_synced: bool,
        original_directory_synced: bool,
    },
    Unlinked {
        original_parent: std::os::fd::OwnedFd,
        receipt_name: OsString,
        quarantine_directory_synced: bool,
        receipt_removed: bool,
    },
    Removed,
}

impl PublishedFileOwnership {
    fn from_parent(
        path: PathBuf,
        parent: std::os::fd::OwnedFd,
        file_name: OsString,
        file: Option<std::os::fd::OwnedFd>,
        device: u64,
        inode: u64,
    ) -> Self {
        Self {
            path,
            parent,
            file_name,
            file,
            device,
            inode,
            cleanup_state: PublishedFileCleanupState::Original,
            staging_lease: None,
            cleanup_temporary_on_drop: false,
            armed: true,
        }
    }

    fn expected_at(path: &Path, device: u64, inode: u64) -> io::Result<Self> {
        let parent_path = path
            .parent()
            .ok_or_else(|| io::Error::other("owned message has no parent"))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| io::Error::other("owned message has no filename"))?
            .to_os_string();
        Ok(Self::from_parent(
            path.to_path_buf(),
            open_bound_directory(parent_path)?,
            file_name,
            None,
            device,
            inode,
        ))
    }

    pub(crate) fn bind_existing(path: &Path) -> io::Result<Self> {
        let parent_path = path
            .parent()
            .ok_or_else(|| io::Error::other("owned message has no parent"))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| io::Error::other("owned message has no filename"))?
            .to_os_string();
        let parent = open_bound_directory(parent_path)?;
        let (file, stat) = open_owned_file(&parent, &file_name)?;
        Ok(Self::from_parent(
            path.to_path_buf(),
            parent,
            file_name,
            Some(file),
            stat.st_dev,
            stat.st_ino,
        ))
    }

    fn verify_and_pin(&mut self) -> io::Result<()> {
        let (file, stat) = open_owned_file(&self.parent, &self.file_name)?;
        if stat.st_dev != self.device || stat.st_ino != self.inode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published message path does not reference the owned inode",
            ));
        }
        self.file = Some(file);
        Ok(())
    }

    fn open_read(&self) -> io::Result<File> {
        let mut file = File::from(
            self.file
                .as_ref()
                .ok_or_else(|| io::Error::other("owned message inode is not pinned"))?
                .try_clone()?,
        );
        // `try_clone` shares the open-file-description offset with the pinned
        // descriptor, which may still be at EOF after the temporary writer.
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    fn content_proof(&self) -> io::Result<(u64, [u8; 32])> {
        self.content_proof_bounded(u64::MAX)
    }

    fn content_proof_bounded(&self, maximum: u64) -> io::Result<(u64, [u8; 32])> {
        let descriptor = self
            .file
            .as_ref()
            .ok_or_else(|| io::Error::other("published message inode is not pinned"))?;
        let stat = rustix::fs::fstat(descriptor).map_err(io::Error::from)?;
        if stat.st_dev != self.device
            || stat.st_ino != self.inode
            || stat.st_size < 0
            || stat.st_nlink != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published message source changed before intent creation",
            ));
        }
        let expected_size = stat.st_size as u64;
        if expected_size > maximum {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "published message source exceeds its configured bound",
            ));
        }
        let mut digest = Sha256Digest::new();
        let mut observed = 0_u64;
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        loop {
            let count =
                rustix::io::pread(descriptor, &mut buffer, observed).map_err(io::Error::from)?;
            if count == 0 {
                break;
            }
            observed = observed.checked_add(count as u64).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    "published message source size overflow",
                )
            })?;
            digest.update(&buffer[..count]);
        }
        if observed != expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published message source changed while hashing",
            ));
        }
        let after = rustix::fs::fstat(descriptor).map_err(io::Error::from)?;
        if after.st_dev != self.device
            || after.st_ino != self.inode
            || after.st_size != stat.st_size
            || after.st_nlink != stat.st_nlink
            || after.st_mtime != stat.st_mtime
            || after.st_mtime_nsec != stat.st_mtime_nsec
            || after.st_ctime != stat.st_ctime
            || after.st_ctime_nsec != stat.st_ctime_nsec
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published message source changed while hashing",
            ));
        }
        Ok((expected_size, digest.finalize().into()))
    }

    fn prepare_publication_intent(
        &mut self,
        intent: PublicationIntent,
        size: u64,
        sha256: [u8; 32],
    ) -> io::Result<()> {
        if !matches!(self.cleanup_state, PublishedFileCleanupState::Original)
            || intent.task_id <= 0
            || size == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid outbound publication intent state",
            ));
        }
        let quarantine = open_quarantine_directory(&self.parent)?;
        let quarantine_name =
            publication_quarantine_name(self.device, self.inode, intent.task_id, intent.kind)?;
        let receipt_name = publication_receipt_name(intent.task_id, intent.kind)?;
        create_ownership_receipt(
            &quarantine,
            &receipt_name,
            &self.file_name,
            self.device,
            self.inode,
            Some(PublicationProof {
                task_id: intent.task_id,
                kind: intent.kind,
                size,
                sha256,
                instance_id: intent.instance_id,
            }),
        )?;
        let quarantine_path = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".lmyzmail-quarantine")
            .join(&quarantine_name);
        self.cleanup_state = PublishedFileCleanupState::PreparedReceipt {
            quarantine,
            quarantine_path,
            quarantine_name,
            receipt_name,
            receipt_directory_synced: false,
        };
        let PublishedFileCleanupState::PreparedReceipt {
            quarantine,
            receipt_directory_synced,
            ..
        } = &mut self.cleanup_state
        else {
            unreachable!("publication intent state was just installed")
        };
        injected_test_fault("publication_intent_directory_fsync")?;
        fsync(quarantine).map_err(io::Error::from)?;
        *receipt_directory_synced = true;
        Ok(())
    }

    fn prepare_cleanup_intent(&mut self) -> io::Result<()> {
        if matches!(self.cleanup_state, PublishedFileCleanupState::Original) {
            let quarantine = open_quarantine_directory(&self.parent)?;
            let quarantine_name = ownership_quarantine_name(self.device, self.inode)?;
            let receipt_name = ownership_receipt_name(&quarantine_name)?;
            create_ownership_receipt(
                &quarantine,
                &receipt_name,
                &self.file_name,
                self.device,
                self.inode,
                None,
            )?;
            let quarantine_path = self
                .path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(".lmyzmail-quarantine")
                .join(&quarantine_name);
            self.cleanup_state = PublishedFileCleanupState::PreparedReceipt {
                quarantine,
                quarantine_path,
                quarantine_name,
                receipt_name,
                receipt_directory_synced: false,
            };
        }

        let PublishedFileCleanupState::PreparedReceipt {
            quarantine,
            receipt_directory_synced,
            ..
        } = &mut self.cleanup_state
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "outbound cleanup intent cannot be prepared from the current state",
            ));
        };
        if !*receipt_directory_synced {
            injected_test_fault("ownership_intent_directory_fsync")?;
            fsync(quarantine).map_err(io::Error::from)?;
            *receipt_directory_synced = true;
        }
        Ok(())
    }

    fn cancel_unpublished_intent(&mut self) -> io::Result<()> {
        let PublishedFileCleanupState::PreparedReceipt {
            quarantine,
            receipt_name,
            ..
        } = &self.cleanup_state
        else {
            self.armed = false;
            return Ok(());
        };
        remove_ownership_receipt(quarantine, receipt_name)?;
        self.cleanup_state = PublishedFileCleanupState::Removed;
        self.armed = false;
        Ok(())
    }

    fn preserve_after_commit(&mut self, retain_receipt: bool) -> io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        match &self.cleanup_state {
            PublishedFileCleanupState::Original => {}
            PublishedFileCleanupState::PreparedReceipt {
                quarantine,
                receipt_name,
                receipt_directory_synced: true,
                ..
            } => {
                let stat = rustix::fs::statat(
                    &self.parent,
                    &self.file_name,
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(io::Error::from)?;
                if !is_regular_stat(&stat)
                    || stat.st_dev != self.device
                    || stat.st_ino != self.inode
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "published message changed before intent settlement",
                    ));
                }
                if !retain_receipt {
                    remove_ownership_receipt(quarantine, receipt_name)?;
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "published message intent is not commit-settleable",
                ));
            }
        }
        self.armed = false;
        Ok(())
    }

    fn disarm(mut self) {
        self.armed = false;
    }

    pub(crate) fn remove_if_still_owned(mut self) -> io::Result<()> {
        self.try_remove_if_still_owned()
    }

    fn try_remove_if_still_owned(&mut self) -> io::Result<()> {
        use rustix::fs::{AtFlags, RenameFlags, renameat_with, statat, unlinkat};

        if !self.armed {
            return Ok(());
        }

        if matches!(
            self.cleanup_state,
            PublishedFileCleanupState::Original | PublishedFileCleanupState::PreparedReceipt { .. }
        ) {
            self.prepare_cleanup_intent()?;
        }

        if matches!(
            self.cleanup_state,
            PublishedFileCleanupState::PreparedReceipt { .. }
        ) {
            let state =
                std::mem::replace(&mut self.cleanup_state, PublishedFileCleanupState::Removed);
            let PublishedFileCleanupState::PreparedReceipt {
                quarantine,
                quarantine_path,
                quarantine_name,
                receipt_name,
                receipt_directory_synced: true,
            } = state
            else {
                unreachable!("outbound cleanup intent is not durable")
            };
            if let Err(error) = renameat_with(
                &self.parent,
                &self.file_name,
                &quarantine,
                &quarantine_name,
                RenameFlags::NOREPLACE,
            ) {
                self.cleanup_state = PublishedFileCleanupState::PreparedReceipt {
                    quarantine,
                    quarantine_path,
                    quarantine_name,
                    receipt_name,
                    receipt_directory_synced: true,
                };
                return Err(io::Error::from(error));
            }
            let original_path = std::mem::replace(&mut self.path, quarantine_path);
            let original_parent = std::mem::replace(&mut self.parent, quarantine);
            let original_file_name = std::mem::replace(&mut self.file_name, quarantine_name);
            self.cleanup_state = PublishedFileCleanupState::Quarantined {
                original_path,
                original_parent,
                original_file_name,
                receipt_name,
                quarantine_directory_synced: false,
                original_directory_synced: false,
            };
            injected_test_hook("ownership_after_quarantine");
        }

        if matches!(
            self.cleanup_state,
            PublishedFileCleanupState::Quarantined { .. }
        ) {
            let quarantined = statat(&self.parent, &self.file_name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io::Error::from);
            let owned = quarantined.as_ref().is_ok_and(|stat| {
                is_regular_stat(stat) && stat.st_dev == self.device && stat.st_ino == self.inode
            });
            if !owned {
                let reason = quarantined
                    .err()
                    .map_or_else(|| "ownership changed".to_owned(), |error| error.to_string());
                let PublishedFileCleanupState::Quarantined {
                    original_path,
                    original_parent,
                    original_file_name,
                    receipt_name,
                    ..
                } = &self.cleanup_state
                else {
                    unreachable!("quarantined ownership state changed unexpectedly")
                };
                restore_quarantined_replacement(
                    original_parent,
                    original_file_name,
                    &self.parent,
                    &self.file_name,
                    original_path,
                    &reason,
                )?;
                remove_ownership_receipt(&self.parent, receipt_name)?;
                self.cleanup_state = PublishedFileCleanupState::Removed;
                self.armed = false;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("owned message cleanup refused replacement: {reason}"),
                ));
            }

            let PublishedFileCleanupState::Quarantined {
                original_parent,
                quarantine_directory_synced,
                original_directory_synced,
                ..
            } = &mut self.cleanup_state
            else {
                unreachable!("quarantined ownership state changed unexpectedly")
            };
            if !*quarantine_directory_synced {
                injected_test_fault("ownership_rename_quarantine_fsync")?;
                fsync(&self.parent).map_err(io::Error::from)?;
                *quarantine_directory_synced = true;
            }
            if !*original_directory_synced {
                injected_test_fault("ownership_rename_parent_fsync")?;
                fsync(original_parent).map_err(io::Error::from)?;
                *original_directory_synced = true;
            }

            injected_test_fault("ownership_unlinkat")?;
            if let Err(error) = unlinkat(&self.parent, &self.file_name, AtFlags::empty()) {
                return Err(io::Error::other(format!(
                    "owned message retained in quarantine {} after unlink failure: {}",
                    self.path.display(),
                    io::Error::from(error),
                )));
            }
            let state =
                std::mem::replace(&mut self.cleanup_state, PublishedFileCleanupState::Removed);
            let PublishedFileCleanupState::Quarantined {
                original_parent,
                receipt_name,
                quarantine_directory_synced: true,
                original_directory_synced: true,
                ..
            } = state
            else {
                unreachable!("quarantined ownership state changed unexpectedly")
            };
            self.cleanup_state = PublishedFileCleanupState::Unlinked {
                original_parent,
                receipt_name,
                quarantine_directory_synced: false,
                receipt_removed: false,
            };
        }

        let PublishedFileCleanupState::Unlinked {
            original_parent,
            receipt_name,
            quarantine_directory_synced,
            receipt_removed,
        } = &mut self.cleanup_state
        else {
            return Err(io::Error::other("invalid outbound ownership cleanup state"));
        };
        let _ = original_parent;
        if !*quarantine_directory_synced {
            injected_test_fault("ownership_after_unlink")?;
            injected_test_fault("ownership_quarantine_fsync")?;
            fsync(&self.parent).map_err(io::Error::from)?;
            *quarantine_directory_synced = true;
        }
        if !*receipt_removed {
            injected_test_fault("ownership_receipt_unlink")?;
            match unlinkat(&self.parent, &*receipt_name, AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => *receipt_removed = true,
                Err(error) => return Err(io::Error::from(error)),
            }
        }
        injected_test_fault("ownership_receipt_directory_fsync")?;
        fsync(&self.parent).map_err(io::Error::from)?;
        self.cleanup_state = PublishedFileCleanupState::Removed;
        self.armed = false;
        Ok(())
    }
}

impl Drop for PublishedFileOwnership {
    fn drop(&mut self) {
        if self.armed
            && self.cleanup_temporary_on_drop
            && let Err(error) = self.try_remove_if_still_owned()
        {
            eprintln!("lmyzmail unpublished temporary drop retained durable evidence: {error}");
        }
    }
}

#[cfg(test)]
type TestHook = Option<(&'static str, Box<dyn FnOnce()>)>;

#[cfg(test)]
thread_local! {
    static TEST_FAULT: std::cell::Cell<Option<&'static str>> = const {
        std::cell::Cell::new(None)
    };
    static TEST_HOOK: std::cell::RefCell<TestHook> = std::cell::RefCell::new(None);
}

fn injected_test_fault(name: &'static str) -> io::Result<()> {
    #[cfg(test)]
    if TEST_FAULT.with(|fault| fault.get()) == Some(name) {
        return Err(io::Error::other(format!(
            "injected outbound message fault: {name}"
        )));
    }
    #[cfg(not(test))]
    let _ = name;
    Ok(())
}

fn injected_test_hook(name: &'static str) {
    #[cfg(test)]
    TEST_HOOK.with(|hook| {
        let callback = {
            let mut hook = hook.borrow_mut();
            match hook.as_ref() {
                Some((expected, _)) if *expected == name => {
                    hook.take().map(|(_, callback)| callback)
                }
                _ => None,
            }
        };
        if let Some(callback) = callback {
            callback();
        }
    });
    #[cfg(not(test))]
    let _ = name;
}

type RsaDkimSigner = DkimSigner<RsaKey<Sha256>, Done>;

#[derive(Clone, Default)]
struct MessagePolicy {
    list_unsubscribe_mailto: Option<String>,
    list_unsubscribe_url: Option<String>,
    dkim_signer: Option<Arc<RsaDkimSigner>>,
}

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
    domain_policies: Arc<HashMap<String, MessagePolicy>>,
    quarantine_cursor: Arc<Mutex<QuarantineSweepCursor>>,
    sent_shard_allocator: Arc<SentShardAllocator>,
    publication_instance: [u8; 16],
}

#[derive(Debug)]
struct SentShardState {
    current_shard: i32,
    allocated: usize,
    in_flight: usize,
    reservations_since_scan: usize,
    last_used: u64,
    pending_names: HashMap<String, PendingSentName>,
}

#[derive(Clone, Copy, Debug)]
struct PendingSentName {
    subdirectory: i32,
    holders: usize,
    durable: bool,
}

#[derive(Debug)]
struct SentShardAllocator {
    shards: [Mutex<HashMap<PathBuf, SentShardState>>; SENT_SHARD_LOCKS],
    clock: AtomicU64,
}

#[derive(Debug)]
pub(crate) struct SentShardReservation {
    allocator: Arc<SentShardAllocator>,
    shard_index: usize,
    key: PathBuf,
    sent_file_name: String,
    subdirectory: i32,
    preserve_allocation: bool,
}

#[derive(Debug)]
enum SentShardSelection {
    Existing(i32),
    Reserved(SentShardReservation),
}

impl Default for SentShardAllocator {
    fn default() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            clock: AtomicU64::new(1),
        }
    }
}

impl SentShardAllocator {
    fn reserve(
        self: &Arc<Self>,
        base: &Path,
        max_files: usize,
        sent_file_name: &str,
    ) -> io::Result<SentShardSelection> {
        if max_files == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Sent Maildir shard capacity must be positive",
            ));
        }
        let shard_index = sent_shard_lock_index(base);
        let mut states = self.shards[shard_index]
            .lock()
            .map_err(|_| io::Error::other("Sent Maildir shard allocator is poisoned"))?;
        let (existing, observed_shard, observed_path) =
            inspect_sent_subdirectories(base, sent_file_name)?;
        if let Some(existing) = existing {
            return Ok(SentShardSelection::Existing(existing));
        }

        let key = base.to_path_buf();
        let now = self.clock.fetch_add(1, Ordering::Relaxed);
        if !states.contains_key(&key) {
            let allocated = match observed_path.as_deref() {
                Some(path) => count_regular_files(path)?,
                None => 0,
            };
            if states.len() >= MAX_SENT_SHARD_CACHE_ENTRIES_PER_LOCK
                && let Some(evicted) = states
                    .iter()
                    .filter(|(_, state)| state.in_flight == 0)
                    .min_by_key(|(_, state)| state.last_used)
                    .map(|(key, _)| key.clone())
            {
                states.remove(&evicted);
            }
            if states.len() >= MAX_SENT_SHARD_CACHE_ENTRIES_PER_LOCK {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Sent Maildir shard cache partition is fully reserved",
                ));
            }
            states.insert(
                key.clone(),
                SentShardState {
                    current_shard: observed_shard.max(1),
                    allocated,
                    in_flight: 0,
                    reservations_since_scan: 0,
                    last_used: now,
                    pending_names: HashMap::new(),
                },
            );
        }

        let state = states.get_mut(&key).ok_or_else(|| {
            io::Error::other("Sent Maildir shard state disappeared while reserved")
        })?;
        if let Some(pending) = state.pending_names.get_mut(sent_file_name) {
            pending.holders = pending.holders.saturating_add(1);
            state.in_flight = state.in_flight.saturating_add(1);
            state.last_used = now;
            return Ok(SentShardSelection::Reserved(SentShardReservation {
                allocator: Arc::clone(self),
                shard_index,
                key,
                sent_file_name: sent_file_name.to_owned(),
                subdirectory: pending.subdirectory,
                preserve_allocation: false,
            }));
        }
        if observed_shard > state.current_shard
            || (observed_shard < state.current_shard && state.in_flight == 0)
        {
            state.current_shard = observed_shard.max(1);
            state.allocated = observed_path
                .as_deref()
                .map(count_regular_files)
                .transpose()?
                .unwrap_or(0);
            state.reservations_since_scan = 0;
        } else if state.reservations_since_scan >= SENT_SHARD_RESCAN_INTERVAL
            && state.in_flight == 0
        {
            let path = base.join(state.current_shard.to_string());
            state.allocated = match count_regular_files(&path) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
                Err(error) => return Err(error),
            };
            state.reservations_since_scan = 0;
        }
        if state.pending_names.len() >= MAX_PENDING_SENT_NAMES_PER_FOLDER {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Sent Maildir pending-name bound is exhausted",
            ));
        }
        if state.allocated >= max_files {
            state.current_shard = state
                .current_shard
                .checked_add(1)
                .ok_or_else(|| io::Error::other("Sent Maildir shard index overflow"))?;
            state.allocated = 0;
            state.reservations_since_scan = 0;
        }
        let selected = state.current_shard;
        state.allocated = state.allocated.saturating_add(1);
        state.in_flight = state.in_flight.saturating_add(1);
        state.reservations_since_scan = state.reservations_since_scan.saturating_add(1);
        state.last_used = now;
        state.pending_names.insert(
            sent_file_name.to_owned(),
            PendingSentName {
                subdirectory: selected,
                holders: 1,
                durable: false,
            },
        );
        Ok(SentShardSelection::Reserved(SentShardReservation {
            allocator: Arc::clone(self),
            shard_index,
            key,
            sent_file_name: sent_file_name.to_owned(),
            subdirectory: selected,
            preserve_allocation: false,
        }))
    }
}

impl SentShardSelection {
    fn subdirectory(&self) -> i32 {
        match self {
            Self::Existing(value) => *value,
            Self::Reserved(reservation) => reservation.subdirectory,
        }
    }

    fn into_reservation(self) -> Option<SentShardReservation> {
        match self {
            Self::Existing(_) => None,
            Self::Reserved(reservation) => Some(reservation),
        }
    }
}

impl SentShardReservation {
    fn mark_durable(&mut self) {
        self.preserve_allocation = true;
    }

    fn release_after_proven_cleanup(&mut self) {
        self.preserve_allocation = false;
    }
}

impl Drop for SentShardReservation {
    fn drop(&mut self) {
        if let Ok(mut states) = self.allocator.shards[self.shard_index].lock()
            && let Some(state) = states.get_mut(&self.key)
        {
            state.in_flight = state.in_flight.saturating_sub(1);
            let completed = state
                .pending_names
                .get_mut(&self.sent_file_name)
                .and_then(|pending| {
                    if pending.subdirectory != self.subdirectory {
                        return None;
                    }
                    pending.durable |= self.preserve_allocation;
                    pending.holders = pending.holders.saturating_sub(1);
                    (pending.holders == 0).then_some(pending.durable)
                });
            let release_allocation = completed.is_some_and(|durable| !durable);
            if completed.is_some() {
                state.pending_names.remove(&self.sent_file_name);
            }
            if release_allocation && state.current_shard == self.subdirectory {
                state.allocated = state.allocated.saturating_sub(1);
            }
            state.last_used = self.allocator.clock.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Default)]
struct QuarantineSweepCursor {
    roots: Vec<PathBuf>,
    next_root: usize,
    stack: Vec<QuarantineSweepFrame>,
    pending_publications: VecDeque<PendingPublicationIntent>,
}

struct QuarantineSweepFrame {
    path: PathBuf,
    entries: fs::ReadDir,
    kind: QuarantineSweepFrameKind,
}

enum QuarantineSweepFrameKind {
    Tree,
    Quarantine {
        descriptor: std::os::fd::OwnedFd,
        original_parent: std::os::fd::OwnedFd,
    },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageAttachment {
    pub filename: String,
    pub content_type: String,
    pub content_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
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
    pub(crate) text_file: Option<MessageTextFile>,
    pub html: Option<String>,
    pub attachments: Vec<MessageAttachment>,
    pub message_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub(crate) struct MessageTextFile {
    path: Option<PathBuf>,
    size: u64,
    ownership: Option<PublishedFileOwnership>,
}

impl MessageTextFile {
    #[cfg(test)]
    pub(crate) fn new(path: PathBuf, size: u64) -> Self {
        Self {
            path: Some(path),
            size,
            ownership: None,
        }
    }

    pub(crate) fn owned(path: PathBuf, size: u64, ownership: PublishedFileOwnership) -> Self {
        Self {
            path: Some(path),
            size,
            ownership: Some(ownership),
        }
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("message text path is armed")
    }
}

impl Drop for MessageTextFile {
    fn drop(&mut self) {
        self.path.take();
        if let Some(ownership) = self.ownership.take()
            && let Err(error) = ownership.remove_if_still_owned()
        {
            eprintln!("lmyzmail streaming text cleanup failed closed: {error}");
        }
    }
}

#[derive(Debug)]
pub struct MaterializedMessage {
    pub sent_file_name: String,
    pub sent_subdirectory: i32,
    pub sent_path: PathBuf,
    pub sent_created: bool,
    pub spool_path: PathBuf,
    pub spool_created: bool,
    pub cleanup_spool_after_publish: bool,
    pub message_bytes: u64,
    pub content_sha256: [u8; 32],
    pub signed_content_base64: Option<String>,
    pub(crate) sent_ownership: Option<PublishedFileOwnership>,
    pub(crate) spool_ownership: Option<PublishedFileOwnership>,
    pub(crate) sent_shard_reservation: Option<SentShardReservation>,
}

impl MaterializedMessage {
    fn cleanup_sent_ownership(&mut self) -> io::Result<()> {
        let result = cleanup_owned_slot(
            &mut self.sent_ownership,
            &mut self.sent_created,
            "sent message",
        );
        if result.is_ok() {
            if let Some(reservation) = self.sent_shard_reservation.as_mut() {
                reservation.release_after_proven_cleanup();
            }
            self.sent_shard_reservation.take();
        } else if let Some(reservation) = self.sent_shard_reservation.as_mut() {
            reservation.mark_durable();
        }
        result
    }

    fn cleanup_spool_ownership(&mut self) -> io::Result<()> {
        cleanup_owned_slot(
            &mut self.spool_ownership,
            &mut self.spool_created,
            "outbound spool",
        )
    }

    pub(crate) fn disarm_after_publish(&mut self) -> io::Result<()> {
        if let Some(reservation) = self.sent_shard_reservation.as_mut() {
            reservation.mark_durable();
        }
        if self.sent_created {
            self.sent_ownership
                .as_mut()
                .ok_or_else(|| io::Error::other("published Sent message has no ownership proof"))?
                .preserve_after_commit(false)?;
        }
        self.sent_created = false;
        self.sent_ownership.take();
        self.sent_shard_reservation.take();
        if !self.cleanup_spool_after_publish {
            if self.spool_created {
                self.spool_ownership
                    .as_mut()
                    .ok_or_else(|| {
                        io::Error::other("published outbound spool has no ownership proof")
                    })?
                    .preserve_after_commit(true)?;
            }
            self.spool_created = false;
            self.spool_ownership.take();
        }
        Ok(())
    }

    pub(crate) fn disarm_remaining_ownership(&mut self) {
        if let Some(reservation) = self.sent_shard_reservation.as_mut() {
            reservation.mark_durable();
        }
        self.sent_created = false;
        self.spool_created = false;
        disarm_optional_ownership(self.sent_ownership.take());
        disarm_optional_ownership(self.spool_ownership.take());
        self.sent_shard_reservation.take();
    }
}

#[derive(Debug)]
pub enum MessageBuildError {
    Cancelled,
    Configuration(String),
    InvalidInput(&'static str),
    Io(io::Error),
}

#[derive(Debug)]
struct RollbackUnknownError {
    context: &'static str,
    source: io::Error,
}

impl std::fmt::Display for RollbackUnknownError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.context, self.source)
    }
}

impl std::error::Error for RollbackUnknownError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl MessageBuildError {
    pub(crate) fn rollback_is_unknown(&self) -> bool {
        matches!(
            self,
            Self::Io(error)
                if error
                    .get_ref()
                    .is_some_and(|source| source.is::<RollbackUnknownError>())
        )
    }
}

fn rollback_unknown_io(context: &'static str, source: io::Error) -> io::Error {
    io::Error::other(RollbackUnknownError { context, source })
}

fn rollback_unknown(context: &'static str, source: io::Error) -> MessageBuildError {
    MessageBuildError::Io(rollback_unknown_io(context, source))
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
    #[cfg(test)]
    pub(crate) fn rollback_test_builder() -> Self {
        Self {
            maildir: PathBuf::new(),
            spool_dir: PathBuf::new(),
            max_files_per_directory: 1,
            max_email_size: 1,
            list_unsubscribe_mailto: None,
            list_unsubscribe_url: None,
            dkim_signer: None,
            domain_policies: Arc::new(HashMap::new()),
            quarantine_cursor: Arc::new(Mutex::new(QuarantineSweepCursor::default())),
            sent_shard_allocator: Arc::default(),
            publication_instance: [0x11; 16],
        }
    }

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
        let default_policy = MessagePolicy {
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
            dkim_signer: dkim_signer.clone(),
        };
        let mut domain_policies = HashMap::new();
        for domain in &config.domains {
            let policy = if domain.domain == config.domain.to_ascii_lowercase() {
                default_policy.clone()
            } else {
                let signer = match (&domain.dkim_private_key_path, &domain.dkim_selector) {
                    (None, None) => None,
                    (Some(path), Some(selector)) => Some(Arc::new(load_dkim_signer(
                        path.to_str().ok_or_else(|| {
                            MessageBuildError::Configuration("DKIM key path is not UTF-8".into())
                        })?,
                        &domain.domain,
                        selector,
                    )?)),
                    _ => {
                        return Err(MessageBuildError::Configuration(
                            "DKIM private key and selector must be configured together".into(),
                        ));
                    }
                };
                MessagePolicy {
                    list_unsubscribe_mailto: domain.list_unsubscribe_mailto.clone(),
                    list_unsubscribe_url: domain.list_unsubscribe_url.clone(),
                    dkim_signer: signer,
                }
            };
            domain_policies.insert(domain.domain.clone(), policy);
        }
        let mut publication_instance = [0_u8; 16];
        getrandom::fill(&mut publication_instance).map_err(|error| {
            MessageBuildError::Configuration(format!(
                "publication instance identity could not be generated: {error}"
            ))
        })?;
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
            domain_policies: Arc::new(domain_policies),
            quarantine_cursor: Arc::new(Mutex::new(QuarantineSweepCursor::default())),
            sent_shard_allocator: Arc::default(),
            publication_instance,
        })
    }

    fn policy_for_sender(&self, sender: &str) -> MessagePolicy {
        let domain = sender
            .rsplit_once('@')
            .map(|(_, value)| value)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        self.domain_policies
            .get(&domain)
            .cloned()
            .unwrap_or_else(|| MessagePolicy {
                list_unsubscribe_mailto: self.list_unsubscribe_mailto.clone(),
                list_unsubscribe_url: self.list_unsubscribe_url.clone(),
                dkim_signer: self.dkim_signer.clone(),
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
        let spool_ownership = self.build_spool(input, &spool_root, &spool_path, cancelled)?;
        let result = self.materialize_from_spool(input, &spool_ownership, true, cancelled);
        match result {
            Ok(mut message) => {
                message.spool_ownership = Some(spool_ownership);
                Ok(message)
            }
            Err(error) => {
                if let Err(cleanup_error) = injected_test_fault("materialize_cleanup")
                    .and_then(|()| spool_ownership.remove_if_still_owned())
                {
                    return Err(rollback_unknown(
                        "outbound spool cleanup after materialization failure",
                        cleanup_error,
                    ));
                }
                Err(error)
            }
        }
    }

    pub fn cleanup_small_spool(&self, message: &mut MaterializedMessage) -> io::Result<()> {
        if message.cleanup_spool_after_publish {
            let proof = message.spool_ownership.as_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "small spool cleanup has no ownership proof",
                )
            })?;
            proof.try_remove_if_still_owned()?;
            message.spool_created = false;
            disarm_optional_ownership(message.spool_ownership.take());
            message.cleanup_spool_after_publish = false;
        }
        Ok(())
    }

    /// Materialize the frozen PostgreSQL `body_text` value once, after MIME
    /// construction has streamed the caller-owned source file into the spool.
    pub(crate) fn materialize_persistence_text(
        &self,
        input: &mut MessageInput,
        cancelled: &AtomicBool,
    ) -> Result<(), MessageBuildError> {
        let Some(source) = input.text_file.take() else {
            return Ok(());
        };
        if input.text.is_some() {
            return Err(MessageBuildError::InvalidInput(
                "conflicting_outbound_text_sources",
            ));
        }
        let text = read_streaming_text(&source, self.max_email_size, cancelled)?;
        if text.trim().is_empty()
            && input
                .html
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
        {
            return Err(MessageBuildError::InvalidInput("body_required"));
        }
        input.text = Some(text);
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

    /// Legacy primary-domain helper retained for deterministic recovery tests
    /// and callers that already materialized system messages before the
    /// sender-domain policy path was introduced.
    #[allow(dead_code)]
    pub(crate) fn prepare_system_bytes(
        &self,
        created_at: DateTime<Utc>,
        bytes: &[u8],
        expected_sha256: &[u8; 32],
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, MessageBuildError> {
        self.prepare_system_bytes_with_policy(
            &MessagePolicy {
                list_unsubscribe_mailto: None,
                list_unsubscribe_url: None,
                dkim_signer: self.dkim_signer.clone(),
            },
            created_at,
            bytes,
            expected_sha256,
            cancelled,
        )
    }

    pub(crate) fn prepare_system_bytes_for_sender(
        &self,
        sender: &str,
        created_at: DateTime<Utc>,
        bytes: &[u8],
        expected_sha256: &[u8; 32],
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, MessageBuildError> {
        let policy = self.policy_for_sender(sender);
        self.prepare_system_bytes_with_policy(
            &policy,
            created_at,
            bytes,
            expected_sha256,
            cancelled,
        )
    }

    fn prepare_system_bytes_with_policy(
        &self,
        policy: &MessagePolicy,
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
            if let Some(signer) = policy.dkim_signer.as_deref() {
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
        if !prepared_matches {
            match fs::symlink_metadata(&self.spool_dir) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Err(MessageBuildError::InvalidInput(
                        "outbound_system_signing_key_changed",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
        }
        let spool_root = secure_directory(&self.spool_dir)?;
        let spool_path = spool_root.join(format!("message-{task_id}.eml"));
        let mut spool_created = false;
        let mut spool_ownership = match PublishedFileOwnership::bind_existing(&spool_path) {
            Ok(ownership) => {
                let (size, digest) = ownership.content_proof_bounded(self.max_email_size)?;
                if size == 0 || size > self.max_email_size || digest != *expected_sha256 {
                    return Err(MessageBuildError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "outbound system spool digest mismatch",
                    )));
                }
                Some(ownership)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && !prepared_matches => {
                return Err(MessageBuildError::InvalidInput(
                    "outbound_system_signing_key_changed",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => match atomic_publish_bytes(
                &spool_root,
                &spool_path,
                bytes,
                self.max_email_size,
                Some(PublicationIntent::spool(task_id, self.publication_instance)),
            ) {
                Ok(ownership) => {
                    spool_created = true;
                    Some(ownership)
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let ownership = PublishedFileOwnership::bind_existing(&spool_path)?;
                    let (size, digest) = ownership.content_proof_bounded(self.max_email_size)?;
                    if size == 0 || size > self.max_email_size || digest != *expected_sha256 {
                        return Err(MessageBuildError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "outbound system spool digest mismatch",
                        )));
                    }
                    Some(ownership)
                }
                Err(error) => return Err(error.into()),
            },
            Err(error) => return Err(error.into()),
        };
        let mut sent_ownership = None;
        let mut sent_shard_reservation = None;
        let result: Result<MaterializedMessage, MessageBuildError> = (|| {
            let spool = spool_ownership.as_ref().ok_or_else(|| {
                MessageBuildError::Io(io::Error::other("outbound system spool is not pinned"))
            })?;
            let (message_bytes, content_sha256) =
                spool.content_proof_bounded(self.max_email_size)?;
            if message_bytes == 0 || message_bytes > self.max_email_size {
                return Err(MessageBuildError::InvalidInput("email_too_large"));
            }
            if content_sha256 != *expected_sha256 {
                return Err(MessageBuildError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "outbound system spool digest mismatch",
                )));
            }

            let sent_root = secure_child_directory(&self.maildir, sender, "sent")?;
            let sent_file_name = sent_file_name_for(task_id, created_at);
            let sent_shard_selection = self.sent_shard_allocator.reserve(
                &sent_root,
                self.max_files_per_directory,
                &sent_file_name,
            )?;
            let sent_subdirectory = sent_shard_selection.subdirectory();
            let sent_dir = secure_numeric_directory(&sent_root, sent_subdirectory)?;
            let sent_path = sent_dir.join(&sent_file_name);
            sent_ownership = match PublishedFileOwnership::bind_existing(&sent_path) {
                Ok(sent) => {
                    if sent.content_proof_bounded(self.max_email_size)?
                        != (message_bytes, content_sha256)
                    {
                        return Err(MessageBuildError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "outbound system Sent digest mismatch",
                        )));
                    }
                    None
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => match atomic_copy(
                    spool,
                    &sent_path,
                    self.max_email_size,
                    cancelled,
                    Some(PublicationIntent::sent(task_id, self.publication_instance)),
                ) {
                    Ok(ownership) => Some(ownership),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        let sent = PublishedFileOwnership::bind_existing(&sent_path)?;
                        if sent.content_proof_bounded(self.max_email_size)?
                            != (message_bytes, content_sha256)
                        {
                            return Err(MessageBuildError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "outbound system Sent digest mismatch",
                            )));
                        }
                        None
                    }
                    Err(error) => return Err(error.into()),
                },
                Err(error) => return Err(error.into()),
            };
            let sent_created = sent_ownership.is_some();
            if sent_created {
                sent_shard_reservation = sent_shard_selection.into_reservation();
                if let Some(reservation) = sent_shard_reservation.as_mut() {
                    reservation.mark_durable();
                }
            }
            let signed_content_base64 = if storage_mode == MessageStorageMode::Inline {
                if prepared_matches {
                    Some(BASE64_STANDARD.encode(bytes))
                } else {
                    let persisted = read_pinned_bytes(
                        spool,
                        message_bytes,
                        content_sha256,
                        self.max_email_size,
                        cancelled,
                    )?;
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
                content_sha256,
                signed_content_base64,
                sent_ownership: sent_ownership.take(),
                spool_ownership: spool_ownership.take(),
                sent_shard_reservation: sent_shard_reservation.take(),
            })
        })();
        match result {
            Ok(message) => Ok(message),
            Err(error) => {
                let sent_cleanup = remove_optional_ownership(sent_ownership.take());
                if let Some(reservation) = sent_shard_reservation.as_mut() {
                    if sent_cleanup.is_ok() {
                        reservation.release_after_proven_cleanup();
                    } else {
                        reservation.mark_durable();
                    }
                }
                let spool_cleanup = if spool_created {
                    remove_optional_ownership(spool_ownership.take())
                } else {
                    disarm_optional_ownership(spool_ownership.take());
                    Ok(())
                };
                if let Err(cleanup_error) = sent_cleanup.and(spool_cleanup) {
                    return Err(rollback_unknown(
                        "system message cleanup after materialization failure",
                        cleanup_error,
                    ));
                }
                Err(error)
            }
        }
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
        let mut found = None;
        for address in [
            sanitize_address_for_path(sender),
            v2_sanitize_address_for_path(sender),
            PathBuf::from(v1_sanitize_address_for_path(sender)),
        ] {
            let path = self
                .maildir
                .join(address)
                .join("sent")
                .join(sent_subdirectory.to_string())
                .join(sent_file_name);
            match PublishedFileOwnership::bind_existing(&path) {
                Ok(file) => {
                    found = Some((path, file));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let (sent_path, sent) = found.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "recovery Sent file is absent")
        })?;
        let (message_bytes, content_sha256) = sent.content_proof_bounded(self.max_email_size)?;
        if message_bytes == 0 || message_bytes > self.max_email_size {
            return Err(MessageBuildError::InvalidInput("email_too_large"));
        }

        let spool_root = secure_directory(&self.spool_dir)?;
        let spool_path = spool_root.join(format!("message-{task_id}.eml"));
        let (spool_created, signed_content_base64, spool_ownership) = match storage_mode {
            MessageStorageMode::Inline => {
                let ownership = match PublishedFileOwnership::bind_existing(&spool_path) {
                    Ok(spool) => {
                        if spool.content_proof_bounded(self.max_email_size)?
                            != (message_bytes, content_sha256)
                        {
                            return Err(MessageBuildError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "outbound spool differs from sent message",
                            )));
                        }
                        Some(spool)
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error.into()),
                };
                check_cancelled(cancelled)?;
                let bytes = read_pinned_bytes(
                    &sent,
                    message_bytes,
                    content_sha256,
                    self.max_email_size,
                    cancelled,
                )?;
                (
                    ownership.is_some(),
                    Some(BASE64_STANDARD.encode(bytes)),
                    ownership,
                )
            }
            MessageStorageMode::Spool => {
                let (created, ownership) = match PublishedFileOwnership::bind_existing(&spool_path)
                {
                    Ok(spool) => {
                        if spool.content_proof_bounded(self.max_email_size)?
                            != (message_bytes, content_sha256)
                        {
                            return Err(MessageBuildError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "outbound spool differs from sent message",
                            )));
                        }
                        (false, spool)
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        match atomic_copy(
                            &sent,
                            &spool_path,
                            self.max_email_size,
                            cancelled,
                            Some(PublicationIntent::spool(task_id, self.publication_instance)),
                        ) {
                            Ok(spool) => (true, spool),
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                                let spool = PublishedFileOwnership::bind_existing(&spool_path)?;
                                if spool.content_proof_bounded(self.max_email_size)?
                                    != (message_bytes, content_sha256)
                                {
                                    return Err(MessageBuildError::Io(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "outbound spool differs from sent message",
                                    )));
                                }
                                (false, spool)
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                    Err(error) => return Err(error.into()),
                };
                (created, None, Some(ownership))
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
            content_sha256,
            signed_content_base64,
            sent_ownership: None,
            spool_ownership,
            sent_shard_reservation: None,
        })
    }

    pub fn rollback_sent(&self, message: &mut MaterializedMessage) -> io::Result<()> {
        message.cleanup_sent_ownership()
    }

    pub fn rollback_unpublished(&self, message: &mut MaterializedMessage) -> io::Result<()> {
        let sent_result = self.rollback_sent(message);
        let spool_result = message.cleanup_spool_ownership();
        sent_result.and(spool_result)
    }

    pub(crate) fn reconcile_owned_quarantines(&self, cancelled: &AtomicBool) -> io::Result<usize> {
        let roots = vec![self.spool_dir.clone(), self.maildir.clone()];
        let mut cursor = self
            .quarantine_cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cursor.roots != roots {
            *cursor = QuarantineSweepCursor {
                roots,
                ..QuarantineSweepCursor::default()
            };
        }
        sweep_owned_quarantine_cursor(
            &mut cursor,
            QUARANTINE_SWEEP_DIRECTORIES,
            QUARANTINE_SWEEP_ENTRIES,
            Instant::now() + QUARANTINE_SWEEP_DEADLINE,
            cancelled,
        )
    }

    pub(crate) fn take_pending_publication_intents(&self) -> Vec<PendingPublicationIntent> {
        let mut cursor = self
            .quarantine_cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cursor.pending_publications.drain(..).collect()
    }

    pub(crate) fn adopt_task_publication_intents(
        &self,
        task_id: i64,
        sender: &str,
        sent_subdirectory: i32,
    ) -> io::Result<Vec<PendingPublicationIntent>> {
        if task_id <= 0 || sender.is_empty() || sent_subdirectory <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid task publication receipt identity",
            ));
        }
        let mut adopted = Vec::new();
        {
            let mut cursor = self
                .quarantine_cursor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cursor.pending_publications.retain(|intent| {
                if intent.task_id == task_id {
                    adopted.push(intent.clone());
                    false
                } else {
                    true
                }
            });
        }

        let spool =
            read_task_publication_intent_at(&self.spool_dir, task_id, PublicationKind::Spool)?;
        merge_task_publication_intent(&mut adopted, spool)?;

        let mut sent_parents = vec![
            self.maildir
                .join(sanitize_address_for_path(sender))
                .join("sent")
                .join(sent_subdirectory.to_string()),
        ];
        for address in [
            v2_sanitize_address_for_path(sender),
            PathBuf::from(v1_sanitize_address_for_path(sender)),
        ] {
            let parent = self
                .maildir
                .join(address)
                .join("sent")
                .join(sent_subdirectory.to_string());
            if !sent_parents.contains(&parent) {
                sent_parents.push(parent);
            }
        }
        for parent in sent_parents {
            let intent = read_task_publication_intent_at(&parent, task_id, PublicationKind::Sent)?;
            merge_task_publication_intent(&mut adopted, intent)?;
        }
        Ok(adopted)
    }

    pub(crate) fn verify_committed_sent_for_spool_intent(
        &self,
        intent: &PendingPublicationIntent,
        sender: &str,
        sent_file_name: &str,
        sent_subdirectory: i32,
    ) -> io::Result<()> {
        use rustix::fs::{AtFlags, fstat, statat};

        if intent.kind != PendingPublicationKind::Spool
            || intent.task_id <= 0
            || intent.size == 0
            || sender.is_empty()
            || sent_subdirectory <= 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid committed Sent publication proof",
            ));
        }
        let mut sent_name_components = Path::new(sent_file_name).components();
        if !matches!(
            sent_name_components.next(),
            Some(std::path::Component::Normal(_))
        ) || sent_name_components.next().is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "committed Sent filename is not a single component",
            ));
        }
        let address_component = sanitize_address_for_path(sender);
        let mut address_components = Path::new(&address_component).components();
        if !matches!(
            address_components.next(),
            Some(std::path::Component::Normal(_))
        ) || address_components
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "committed Sent mailbox path is invalid",
            ));
        }
        // Search by the actual file, not just an existing directory: a takeover
        // can contain messages in both the Java and early Rust layouts.
        let mut opened = None;
        for address in [
            address_component,
            v2_sanitize_address_for_path(sender),
            PathBuf::from(v1_sanitize_address_for_path(sender)),
        ] {
            let sent_directory = self
                .maildir
                .join(address)
                .join("sent")
                .join(sent_subdirectory.to_string());
            let result = open_bound_directory(&sent_directory).and_then(|directory| {
                let (descriptor, before) = open_owned_file(&directory, OsStr::new(sent_file_name))?;
                Ok((directory, descriptor, before))
            });
            match result {
                Ok(value) => {
                    opened = Some(value);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let (directory, descriptor, before) = opened.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "committed Sent file is absent")
        })?;
        if before.st_size <= 0 || before.st_size as u64 != intent.size {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "committed Sent size does not match the spool publication proof",
            ));
        }
        let mut file = File::from(descriptor);
        let mut digest = Sha256Digest::new();
        let mut observed = 0_u64;
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            observed = observed.checked_add(count as u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::FileTooLarge, "committed Sent size overflow")
            })?;
            if observed > intent.size {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "committed Sent grew beyond the spool publication proof",
                ));
            }
            digest.update(&buffer[..count]);
        }
        let after = fstat(&file).map_err(io::Error::from)?;
        let linked = statat(&directory, sent_file_name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)?;
        let actual: [u8; 32] = digest.finalize().into();
        if observed != intent.size
            || actual != intent.sha256
            || !is_regular_stat(&after)
            || !is_regular_stat(&linked)
            || after.st_dev != before.st_dev
            || after.st_ino != before.st_ino
            || linked.st_dev != before.st_dev
            || linked.st_ino != before.st_ino
            || after.st_size != before.st_size
            || linked.st_size != before.st_size
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "committed Sent inode or content changed during verification",
            ));
        }
        Ok(())
    }

    pub(crate) fn resolve_publication_intent(
        &self,
        intent: &PendingPublicationIntent,
        disposition: PublicationDisposition,
    ) -> io::Result<()> {
        resolve_pending_publication_intent(intent, disposition)
    }

    fn build_spool(
        &self,
        input: &MessageInput,
        spool_root: &Path,
        spool_path: &Path,
        cancelled: &AtomicBool,
    ) -> Result<PublishedFileOwnership, MessageBuildError> {
        let (unsigned, unsigned_token) = create_owned_temporary(spool_root, "unsigned")?;
        let mut unsigned_ownership = Some(unsigned_token);
        let mut signed_ownership = None;
        let mut spool_ownership = None;
        let result: Result<(), MessageBuildError> = (|| {
            let mut writer = BoundedWriter::new(BufWriter::new(unsigned), self.max_email_size);
            self.write_message(input, &mut writer, cancelled)?;
            let mut unsigned = writer.finish()?;
            unsigned.flush()?;
            sync_all(unsigned.get_ref())?;
            check_cancelled(cancelled)?;

            if let Some(signer) = self.policy_for_sender(&input.sender).dkim_signer.as_deref() {
                let mut signing_stream = signer.sign_streaming();
                let mut input_file = BufReader::with_capacity(
                    COPY_BUFFER_BYTES,
                    unsigned_ownership
                        .as_ref()
                        .ok_or_else(|| io::Error::other("unsigned ownership is disarmed"))?
                        .open_read()?,
                );
                let mut buffer = [0_u8; COPY_BUFFER_BYTES];
                loop {
                    check_cancelled(cancelled)?;
                    let count = input_file.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    signing_stream.write(&buffer[..count]);
                }
                let signature = signing_stream.finish().map_err(dkim_streaming_error)?;
                let (signed, signed_token) = create_owned_temporary(spool_root, "signed")?;
                signed_ownership = Some(signed_token);
                let mut writer = BoundedWriter::new(BufWriter::new(signed), self.max_email_size);
                writer.write_all(signature.to_header().as_bytes())?;
                copy_bounded(
                    &mut unsigned_ownership
                        .as_ref()
                        .ok_or_else(|| io::Error::other("unsigned ownership is disarmed"))?
                        .open_read()?,
                    &mut writer,
                    cancelled,
                )?;
                let mut signed = writer.finish()?;
                signed.flush()?;
                sync_all(signed.get_ref())?;
                spool_ownership = Some(publish_temp_file(
                    signed_ownership
                        .take()
                        .ok_or_else(|| io::Error::other("signed ownership is disarmed"))?,
                    spool_path,
                    Some(PublicationIntent::spool(
                        input.task_id,
                        self.publication_instance,
                    )),
                )?);
                injected_test_fault("build_after_publish")?;
                unsigned_ownership
                    .take()
                    .ok_or_else(|| io::Error::other("unsigned ownership is disarmed"))?
                    .remove_if_still_owned()?;
            } else {
                spool_ownership = Some(publish_temp_file(
                    unsigned_ownership
                        .take()
                        .ok_or_else(|| io::Error::other("unsigned ownership is disarmed"))?,
                    spool_path,
                    Some(PublicationIntent::spool(
                        input.task_id,
                        self.publication_instance,
                    )),
                )?);
                injected_test_fault("build_after_publish")?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            let mut cleanup_error = None;
            if let Err(candidate) = remove_optional_ownership(unsigned_ownership.take()) {
                cleanup_error.get_or_insert(candidate);
            }
            if let Err(candidate) = remove_optional_ownership(signed_ownership.take()) {
                cleanup_error.get_or_insert(candidate);
            }
            if let Err(candidate) = remove_optional_ownership(spool_ownership.take()) {
                cleanup_error.get_or_insert(candidate);
            }
            if let Some(cleanup_error) = cleanup_error {
                return Err(rollback_unknown(
                    "outbound spool cleanup after build failure",
                    cleanup_error,
                ));
            }
            return Err(error);
        }
        spool_ownership.take().ok_or_else(|| {
            MessageBuildError::Io(io::Error::other(
                "outbound spool publish completed without ownership proof",
            ))
        })
    }

    fn materialize_from_spool(
        &self,
        input: &MessageInput,
        spool: &PublishedFileOwnership,
        spool_created: bool,
        cancelled: &AtomicBool,
    ) -> Result<MaterializedMessage, MessageBuildError> {
        let spool_path = spool.path.clone();
        let (message_bytes, content_sha256) = spool.content_proof_bounded(self.max_email_size)?;
        if message_bytes == 0 || message_bytes > self.max_email_size {
            return Err(MessageBuildError::InvalidInput("email_too_large"));
        }
        let sent_root = secure_child_directory(&self.maildir, &input.sender, "sent")?;
        let sent_file_name = sent_file_name(input);
        let sent_shard_selection = self.sent_shard_allocator.reserve(
            &sent_root,
            self.max_files_per_directory,
            &sent_file_name,
        )?;
        let sent_subdirectory = sent_shard_selection.subdirectory();
        let sent_dir = secure_numeric_directory(&sent_root, sent_subdirectory)?;
        let sent_path = sent_dir.join(&sent_file_name);
        let mut sent_ownership = match PublishedFileOwnership::bind_existing(&sent_path) {
            Ok(sent) => {
                if sent.content_proof_bounded(self.max_email_size)?
                    != (message_bytes, content_sha256)
                {
                    return Err(MessageBuildError::Io(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "sent Maildir collision",
                    )));
                }
                None
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => match atomic_copy(
                spool,
                &sent_path,
                self.max_email_size,
                cancelled,
                Some(PublicationIntent::sent(
                    input.task_id,
                    self.publication_instance,
                )),
            ) {
                Ok(sent) => Some(sent),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let sent = PublishedFileOwnership::bind_existing(&sent_path)?;
                    if sent.content_proof_bounded(self.max_email_size)?
                        != (message_bytes, content_sha256)
                    {
                        return Err(MessageBuildError::Io(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "sent Maildir collision",
                        )));
                    }
                    None
                }
                Err(error) => return Err(error.into()),
            },
            Err(error) => return Err(error.into()),
        };
        let sent_created = sent_ownership.is_some();
        let mut sent_shard_reservation = if sent_created {
            sent_shard_selection.into_reservation()
        } else {
            None
        };
        if let Some(reservation) = sent_shard_reservation.as_mut() {
            reservation.mark_durable();
        }
        let signed_content_base64 =
            match java_storage_mode_for_input(input).and_then(|mode| match mode {
                MessageStorageMode::Inline => {
                    check_cancelled(cancelled)?;
                    injected_test_fault("inline_read_after_sent_copy")?;
                    let bytes = read_pinned_bytes(
                        spool,
                        message_bytes,
                        content_sha256,
                        self.max_email_size,
                        cancelled,
                    )?;
                    Ok(Some(BASE64_STANDARD.encode(bytes)))
                }
                MessageStorageMode::Spool => Ok(None),
            }) {
                Ok(value) => value,
                Err(error) => {
                    let sent_cleanup = sent_ownership
                        .take()
                        .map_or(Ok(()), PublishedFileOwnership::remove_if_still_owned);
                    if let Some(reservation) = sent_shard_reservation.as_mut() {
                        if sent_cleanup.is_ok() {
                            reservation.release_after_proven_cleanup();
                        } else {
                            reservation.mark_durable();
                        }
                    }
                    if let Err(cleanup_error) = sent_cleanup {
                        return Err(rollback_unknown(
                            "sent cleanup after inline materialization failure",
                            cleanup_error,
                        ));
                    }
                    sent_shard_reservation.take();
                    return Err(error);
                }
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
            content_sha256,
            signed_content_base64,
            sent_ownership,
            spool_ownership: None,
            sent_shard_reservation,
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
        let policy = self.policy_for_sender(&input.sender);
        let mut unsubscribe = Vec::new();
        if let Some(url) = policy.list_unsubscribe_url.as_deref() {
            unsubscribe.push(format!("<{url}>"));
            writeln_crlf(output, "List-Unsubscribe-Post: List-Unsubscribe=One-Click")?;
        }
        if let Some(mailto) = policy.list_unsubscribe_mailto.as_deref() {
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
            self.write_text_content(input, output, cancelled)?;
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
            self.write_alternative(input, &alternative, output, cancelled)?;
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
            self.write_alternative(input, &alternative, output, cancelled)?;
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
            self.write_alternative(input, &alternative, output, cancelled)?;
        } else {
            write_boundary(output, &mixed, false)?;
            self.write_text_part(input, output, cancelled)?;
        }
        for attachment in input.attachments.iter().filter(|value| !value.inline) {
            check_cancelled(cancelled)?;
            write_attachment(output, &mixed, attachment)?;
        }
        write_boundary(output, &mixed, true)?;
        Ok(())
    }

    fn write_alternative(
        &self,
        input: &MessageInput,
        boundary: &str,
        output: &mut impl Write,
        cancelled: &AtomicBool,
    ) -> Result<(), MessageBuildError> {
        write_boundary(output, boundary, false)?;
        self.write_text_part(input, output, cancelled)?;
        write_boundary(output, boundary, false)?;
        writeln_crlf(output, "Content-Type: text/html; charset=UTF-8")?;
        writeln_crlf(output, "Content-Transfer-Encoding: quoted-printable")?;
        writeln_crlf(output, "")?;
        write_quoted_printable(input.html.as_deref().unwrap_or_default(), output)?;
        writeln_crlf(output, "")?;
        write_boundary(output, boundary, true)?;
        Ok(())
    }

    fn write_text_part(
        &self,
        input: &MessageInput,
        output: &mut impl Write,
        cancelled: &AtomicBool,
    ) -> Result<(), MessageBuildError> {
        writeln_crlf(output, "Content-Type: text/plain; charset=UTF-8")?;
        writeln_crlf(output, "Content-Transfer-Encoding: quoted-printable")?;
        writeln_crlf(output, "")?;
        self.write_text_content(input, output, cancelled)?;
        writeln_crlf(output, "")?;
        Ok(())
    }

    fn write_text_content(
        &self,
        input: &MessageInput,
        output: &mut impl Write,
        cancelled: &AtomicBool,
    ) -> Result<(), MessageBuildError> {
        match (&input.text, &input.text_file) {
            (Some(text), None) => {
                write_quoted_printable(text, output)?;
                Ok(())
            }
            (None, Some(source)) => {
                write_quoted_printable_file(source, self.max_email_size, output, cancelled)
            }
            (None, None) => Ok(()),
            (Some(_), Some(_)) => Err(MessageBuildError::InvalidInput(
                "conflicting_outbound_text_sources",
            )),
        }
    }
}

fn merge_task_publication_intent(
    adopted: &mut Vec<PendingPublicationIntent>,
    candidate: Option<PendingPublicationIntent>,
) -> io::Result<()> {
    let Some(candidate) = candidate else {
        return Ok(());
    };
    if adopted.contains(&candidate) {
        return Ok(());
    }
    if adopted.iter().any(|intent| intent.kind == candidate.kind) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "conflicting {:?} publication receipts retained for task {}",
                candidate.kind, candidate.task_id
            ),
        ));
    }
    adopted.push(candidate);
    Ok(())
}

fn read_task_publication_intent_at(
    original_parent: &Path,
    task_id: i64,
    kind: PublicationKind,
) -> io::Result<Option<PendingPublicationIntent>> {
    let quarantine_path = original_parent.join(".lmyzmail-quarantine");
    let quarantine = match open_bound_directory(&quarantine_path) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let receipt_name = publication_receipt_name(task_id, kind)?;
    match read_pending_publication_intent(&quarantine_path, &quarantine, &receipt_name) {
        Ok(intent) => Ok(intent),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
fn java_estimated_message_size(input: &MessageInput) -> Result<u64, MessageBuildError> {
    java_estimated_message_parts_with_file(
        input.text.as_deref(),
        input.text_file.as_ref().map(|source| source.size),
        input.html.as_deref(),
        &input.attachments,
    )
}

fn java_storage_mode_for_input(
    input: &MessageInput,
) -> Result<MessageStorageMode, MessageBuildError> {
    if java_estimated_message_parts_with_file(
        input.text.as_deref(),
        input.text_file.as_ref().map(|source| source.size),
        input.html.as_deref(),
        &input.attachments,
    )? < SMALL_MESSAGE_THRESHOLD
    {
        Ok(MessageStorageMode::Inline)
    } else {
        Ok(MessageStorageMode::Spool)
    }
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
    java_estimated_message_parts_with_file(text, None, html, attachments)
}

fn java_estimated_message_parts_with_file(
    text: Option<&str>,
    text_file_size: Option<u64>,
    html: Option<&str>,
    attachments: &[MessageAttachment],
) -> Result<u64, MessageBuildError> {
    if text.is_some() && text_file_size.is_some() {
        return Err(MessageBuildError::InvalidInput(
            "conflicting_outbound_text_sources",
        ));
    }
    let mut size = 2_048_u64;
    if let Some(text_file_size) = text_file_size {
        size = size
            .checked_add(text_file_size)
            .ok_or(MessageBuildError::InvalidInput(
                "email_size_estimate_overflow",
            ))?;
    }
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
        let decoded_bytes = if let Some(length) = attachment.content_length {
            length
        } else {
            let base64_bytes = attachment.content_base64.trim_end_matches('=').len();
            u64::try_from(base64_bytes)
                .ok()
                .and_then(|value| value.checked_mul(3))
                .and_then(|value| value.checked_add(3))
                .map(|value| value / 4)
                .ok_or(MessageBuildError::InvalidInput(
                    "email_size_estimate_overflow",
                ))?
        };
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

fn dkim_streaming_error(error: mail_auth::Error) -> MessageBuildError {
    let message = match error {
        mail_auth::Error::NoHeadersFound => "DKIM streaming signing found no eligible headers",
        mail_auth::Error::Base64 => "DKIM streaming encoding failed",
        mail_auth::Error::Crypto(_) => "DKIM streaming cryptographic signing failed",
        _ => "DKIM streaming signing failed",
    };
    MessageBuildError::Configuration(message.into())
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

fn write_quoted_printable(text: &str, output: &mut impl Write) -> io::Result<()> {
    let mut line_length = 0_usize;
    write_quoted_printable_bytes(text.as_bytes(), output, &mut line_length)
}

fn write_quoted_printable_bytes(
    bytes: &[u8],
    output: &mut impl Write,
    line_length: &mut usize,
) -> io::Result<()> {
    for &byte in bytes {
        match byte {
            b'\r' => {}
            b'\n' => {
                output.write_all(b"\r\n")?;
                *line_length = 0;
            }
            b'!'..=b'<' | b'>'..=b'~' | b' ' | b'\t' => {
                write_quoted_printable_unit(output, line_length, &[byte])?;
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                let encoded = [b'=', HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]];
                write_quoted_printable_unit(output, line_length, &encoded)?;
            }
        }
    }
    Ok(())
}

fn write_quoted_printable_file(
    source: &MessageTextFile,
    maximum: u64,
    output: &mut impl Write,
    cancelled: &AtomicBool,
) -> Result<(), MessageBuildError> {
    let mut input =
        BufReader::with_capacity(COPY_BUFFER_BYTES, open_streaming_text(source, maximum)?);
    let mut remaining = source.size;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    let mut line_length = 0_usize;
    let mut utf8 = Utf8StreamValidator::default();
    while remaining > 0 {
        check_cancelled(cancelled)?;
        let maximum_read = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))
            .expect("bounded read length fits usize");
        let count = input.read(&mut buffer[..maximum_read])?;
        if count == 0 {
            return Err(MessageBuildError::InvalidInput(
                "invalid_outbound_text_file",
            ));
        }
        utf8.consume(&buffer[..count])?;
        write_quoted_printable_bytes(&buffer[..count], output, &mut line_length)?;
        remaining -= count as u64;
    }
    check_cancelled(cancelled)?;
    if input.read(&mut buffer[..1])? != 0 {
        return Err(MessageBuildError::InvalidInput(
            "invalid_outbound_text_file",
        ));
    }
    utf8.finish()?;
    Ok(())
}

fn read_streaming_text(
    source: &MessageTextFile,
    maximum: u64,
    cancelled: &AtomicBool,
) -> Result<String, MessageBuildError> {
    check_cancelled(cancelled)?;
    let capacity = usize::try_from(source.size)
        .map_err(|_| MessageBuildError::InvalidInput("email_too_large"))?;
    let file = open_streaming_text(source, maximum)?;
    let mut text = String::with_capacity(capacity);
    let mut reader = CooperativeReader {
        inner: file,
        cancelled,
    };
    let count = (&mut reader)
        .take(source.size)
        .read_to_string(&mut text)
        .map_err(|error| {
            if cancelled.load(Ordering::Acquire) {
                MessageBuildError::Cancelled
            } else if error.kind() == io::ErrorKind::InvalidData {
                MessageBuildError::InvalidInput("invalid_outbound_text_file")
            } else {
                MessageBuildError::Io(error)
            }
        })?;
    let mut extra = [0_u8; 1];
    if count as u64 != source.size
        || reader.read(&mut extra).map_err(|error| {
            if cancelled.load(Ordering::Acquire) {
                MessageBuildError::Cancelled
            } else {
                MessageBuildError::Io(error)
            }
        })? != 0
    {
        return Err(MessageBuildError::InvalidInput(
            "invalid_outbound_text_file",
        ));
    }
    check_cancelled(cancelled)?;
    Ok(text)
}

fn open_streaming_text(source: &MessageTextFile, maximum: u64) -> Result<File, MessageBuildError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};

    if source.size > maximum {
        return Err(MessageBuildError::InvalidInput("email_too_large"));
    }
    let file = if let Some(ownership) = source.ownership.as_ref() {
        ownership.open_read()?
    } else {
        File::from(
            open(
                source.path(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(io::Error::from)?,
        )
    };
    let stat = fstat(&file).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_size < 0
        || stat.st_size as u64 != source.size
    {
        return Err(MessageBuildError::InvalidInput(
            "invalid_outbound_text_file",
        ));
    }
    Ok(file)
}

#[derive(Default)]
struct Utf8StreamValidator {
    trailing: [u8; 4],
    trailing_len: usize,
}

impl Utf8StreamValidator {
    fn consume(&mut self, mut bytes: &[u8]) -> Result<(), MessageBuildError> {
        if self.trailing_len != 0 {
            let width = utf8_sequence_width(self.trailing[0]).ok_or(
                MessageBuildError::InvalidInput("invalid_outbound_text_file"),
            )?;
            let appended = bytes.len().min(width - self.trailing_len);
            self.trailing[self.trailing_len..self.trailing_len + appended]
                .copy_from_slice(&bytes[..appended]);
            self.trailing_len += appended;
            bytes = &bytes[appended..];
            if self.trailing_len < width {
                return Ok(());
            }
            std::str::from_utf8(&self.trailing[..width])
                .map_err(|_| MessageBuildError::InvalidInput("invalid_outbound_text_file"))?;
            self.trailing_len = 0;
        }

        if let Err(error) = std::str::from_utf8(bytes) {
            if error.error_len().is_some() {
                return Err(MessageBuildError::InvalidInput(
                    "invalid_outbound_text_file",
                ));
            }
            let trailing = &bytes[error.valid_up_to()..];
            debug_assert!(!trailing.is_empty() && trailing.len() <= self.trailing.len());
            self.trailing[..trailing.len()].copy_from_slice(trailing);
            self.trailing_len = trailing.len();
        }
        Ok(())
    }

    fn finish(self) -> Result<(), MessageBuildError> {
        if self.trailing_len == 0 {
            Ok(())
        } else {
            Err(MessageBuildError::InvalidInput(
                "invalid_outbound_text_file",
            ))
        }
    }
}

fn utf8_sequence_width(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

struct CooperativeReader<'a, R> {
    inner: R,
    cancelled: &'a AtomicBool,
}

impl<R: Read> Read for CooperativeReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "outbound text read cancelled",
            ));
        }
        self.inner.read(buffer)
    }
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
    write_attachment_content(output, attachment)?;
    writeln_crlf(output, "")
}

fn write_attachment_content(
    output: &mut impl Write,
    attachment: &MessageAttachment,
) -> io::Result<()> {
    let Some(path) = attachment.source_path.as_deref() else {
        for chunk in attachment.content_base64.as_bytes().chunks(76) {
            output.write_all(chunk)?;
            output.write_all(b"\r\n")?;
        }
        return Ok(());
    };
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || attachment
            .content_length
            .is_none_or(|length| length != metadata.len())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound attachment source changed before materialization",
        ));
    }
    let mut input = BufReader::with_capacity(COPY_BUFFER_BYTES, File::open(path)?);
    let mut buffer = [0_u8; 57];
    let mut wrote_line = false;
    loop {
        let mut count = 0;
        while count < buffer.len() {
            let read = input.read(&mut buffer[count..])?;
            if read == 0 {
                break;
            }
            count += read;
        }
        if count == 0 {
            return Ok(());
        }
        if wrote_line {
            output.write_all(b"\r\n")?;
        }
        output.write_all(BASE64_STANDARD.encode(&buffer[..count]).as_bytes())?;
        wrote_line = true;
        if count < buffer.len() {
            return Ok(());
        }
    }
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
    let suffix = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "-=Part.0.{}.{}.{}=-",
        &suffix[..16],
        &suffix[16..27],
        &suffix[27..43]
    )
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

fn cleanup_owned_slot(
    ownership: &mut Option<PublishedFileOwnership>,
    created: &mut bool,
    description: &'static str,
) -> io::Result<()> {
    if !*created {
        disarm_optional_ownership(ownership.take());
        return Ok(());
    }
    let proof = ownership.as_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} cleanup has no ownership proof"),
        )
    })?;
    proof.try_remove_if_still_owned()?;
    *created = false;
    disarm_optional_ownership(ownership.take());
    Ok(())
}

fn remove_optional_ownership(ownership: Option<PublishedFileOwnership>) -> io::Result<()> {
    ownership.map_or(Ok(()), PublishedFileOwnership::remove_if_still_owned)
}

fn disarm_optional_ownership(ownership: Option<PublishedFileOwnership>) {
    if let Some(ownership) = ownership {
        ownership.disarm();
    }
}

fn is_regular_stat(stat: &rustix::fs::Stat) -> bool {
    rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::RegularFile
}

fn open_bound_directory(path: &Path) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags, fstat, openat2};

    let descriptor = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let stat = fstat(&descriptor).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owned message parent is not a directory",
        ));
    }
    Ok(descriptor)
}

fn open_owned_file(
    parent: &std::os::fd::OwnedFd,
    file_name: &OsStr,
) -> io::Result<(std::os::fd::OwnedFd, rustix::fs::Stat)> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, fstat, openat2};

    let descriptor = openat2(
        parent,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let stat = fstat(&descriptor).map_err(io::Error::from)?;
    if !is_regular_stat(&stat) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owned message is not a regular file",
        ));
    }
    Ok((descriptor, stat))
}

fn random_storage_name(kind: &str) -> io::Result<OsString> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let nonce = encode_hex_16(nonce);
    Ok(format!(".lmyzmail-{kind}-{nonce}.tmp").into())
}

fn encode_hex_16(value: [u8; 16]) -> String {
    value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn decode_hex_16(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let mut decoded = [0_u8; 16];
    for (index, output) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&value[offset..offset + 2], 16).ok()?;
    }
    Some(decoded)
}

fn staging_instance_id() -> io::Result<[u8; 16]> {
    if let Some(instance) = STAGING_INSTANCE_ID.get() {
        return Ok(*instance);
    }
    let mut generated = [0_u8; 16];
    getrandom::fill(&mut generated).map_err(io::Error::other)?;
    let _ = STAGING_INSTANCE_ID.set(generated);
    Ok(*STAGING_INSTANCE_ID
        .get()
        .expect("staging instance identity was just initialized"))
}

fn random_staging_name() -> io::Result<OsString> {
    let instance = encode_hex_16(staging_instance_id()?);
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    Ok(format!(".lmyzmail-stage-{instance}-{}.tmp", encode_hex_16(nonce)).into())
}

fn parse_staging_name(name: &OsStr) -> Option<([u8; 16], [u8; 16])> {
    let body = name
        .to_str()?
        .strip_prefix(".lmyzmail-stage-")?
        .strip_suffix(".tmp")?;
    let (instance, nonce) = body.split_once('-')?;
    if nonce.contains('-') {
        return None;
    }
    Some((decode_hex_16(instance)?, decode_hex_16(nonce)?))
}

fn ownership_quarantine_name(device: u64, inode: u64) -> io::Result<OsString> {
    random_storage_name(&format!("owned-{device:016x}-{inode:016x}"))
}

fn publication_quarantine_name(
    device: u64,
    inode: u64,
    task_id: i64,
    kind: PublicationKind,
) -> io::Result<OsString> {
    let task_id = u64::try_from(task_id).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid outbound publication task identity",
        )
    })?;
    let kind = match kind {
        PublicationKind::Spool => 1_u64,
        PublicationKind::Sent => 2_u64,
    };
    Ok(format!(".lmyzmail-owned-{device:016x}-{inode:016x}-{task_id:016x}{kind:016x}.tmp").into())
}

fn parse_ownership_quarantine_name(name: &OsStr) -> Option<(u64, u64)> {
    let value = name.to_str()?;
    let body = value
        .strip_prefix(".lmyzmail-owned-")?
        .strip_suffix(".tmp")?;
    let mut components = body.split('-');
    let device = components.next()?;
    let inode = components.next()?;
    let nonce = components.next()?;
    if components.next().is_some()
        || device.len() != 16
        || inode.len() != 16
        || nonce.len() != 32
        || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some((
        u64::from_str_radix(device, 16).ok()?,
        u64::from_str_radix(inode, 16).ok()?,
    ))
}

fn parse_publication_quarantine_name(name: &OsStr) -> Option<(u64, u64, i64, PublicationKind)> {
    let value = name.to_str()?;
    let body = value
        .strip_prefix(".lmyzmail-owned-")?
        .strip_suffix(".tmp")?;
    let mut components = body.split('-');
    let device = components.next()?;
    let inode = components.next()?;
    let nonce = components.next()?;
    if components.next().is_some() || device.len() != 16 || inode.len() != 16 || nonce.len() != 32 {
        return None;
    }
    let task_id = i64::try_from(u64::from_str_radix(&nonce[..16], 16).ok()?).ok()?;
    let kind = match u64::from_str_radix(&nonce[16..], 16).ok()? {
        1 => PublicationKind::Spool,
        2 => PublicationKind::Sent,
        _ => return None,
    };
    Some((
        u64::from_str_radix(device, 16).ok()?,
        u64::from_str_radix(inode, 16).ok()?,
        task_id,
        kind,
    ))
}

fn ownership_receipt_name(quarantine_name: &OsStr) -> io::Result<OsString> {
    let value = quarantine_name.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbound quarantine token is not ASCII",
        )
    })?;
    let body = value
        .strip_prefix(".lmyzmail-owned-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid outbound quarantine token",
            )
        })?;
    if parse_ownership_quarantine_name(quarantine_name).is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid outbound quarantine identity",
        ));
    }
    Ok(format!(".lmyzmail-intent-{body}.receipt").into())
}

fn publication_receipt_name(task_id: i64, kind: PublicationKind) -> io::Result<OsString> {
    let task_id = u64::try_from(task_id).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid outbound publication task identity",
        )
    })?;
    let kind = match kind {
        PublicationKind::Spool => "spool",
        PublicationKind::Sent => "sent",
    };
    Ok(format!(".lmyzmail-publish-{kind}-{task_id:016x}.receipt").into())
}

fn parse_publication_receipt_name(name: &OsStr) -> Option<(i64, PublicationKind)> {
    let value = name
        .to_str()?
        .strip_prefix(".lmyzmail-publish-")?
        .strip_suffix(".receipt")?;
    let (kind, task_id) = value.split_once('-')?;
    if task_id.len() != 16 || !task_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let task_id = i64::try_from(u64::from_str_radix(task_id, 16).ok()?).ok()?;
    let kind = match kind {
        "spool" => PublicationKind::Spool,
        "sent" => PublicationKind::Sent,
        _ => return None,
    };
    Some((task_id, kind))
}

fn parse_ownership_receipt_name(name: &OsStr) -> Option<(OsString, u64, u64)> {
    let value = name.to_str()?;
    let body = value
        .strip_prefix(".lmyzmail-intent-")?
        .strip_suffix(".receipt")?;
    let quarantine_name = OsString::from(format!(".lmyzmail-owned-{body}.tmp"));
    let (device, inode) = parse_ownership_quarantine_name(&quarantine_name)?;
    Some((quarantine_name, device, inode))
}

fn encode_ownership_receipt(
    original_file_name: &OsStr,
    device: u64,
    inode: u64,
    publication: Option<PublicationProof>,
) -> io::Result<Vec<u8>> {
    let name = original_file_name.as_bytes();
    if name.is_empty()
        || name.len() > MAX_OWNERSHIP_FILE_NAME_BYTES
        || name.contains(&b'/')
        || name.contains(&0)
        || matches!(name, b"." | b"..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid original filename in outbound ownership intent",
        ));
    }
    let name_len = u32::try_from(name.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbound ownership filename is too long",
        )
    })?;
    let mut encoded = Vec::with_capacity(OWNERSHIP_RECEIPT_HEADER_BYTES + name.len());
    encoded.extend_from_slice(OWNERSHIP_RECEIPT_MAGIC);
    encoded.push(OWNERSHIP_RECEIPT_VERSION);
    encoded.push(match publication.map(|proof| proof.kind) {
        None => 0,
        Some(PublicationKind::Spool) => 1,
        Some(PublicationKind::Sent) => 2,
    });
    encoded.extend_from_slice(&[0_u8; 6]);
    encoded.extend_from_slice(&device.to_be_bytes());
    encoded.extend_from_slice(&inode.to_be_bytes());
    encoded.extend_from_slice(&publication.map_or(0, |proof| proof.task_id).to_be_bytes());
    encoded.extend_from_slice(&publication.map_or(0, |proof| proof.size).to_be_bytes());
    encoded.extend_from_slice(&publication.map_or([0_u8; 32], |proof| proof.sha256));
    encoded.extend_from_slice(&publication.map_or([0_u8; 16], |proof| proof.instance_id));
    encoded.extend_from_slice(&name_len.to_be_bytes());
    encoded.extend_from_slice(name);
    Ok(encoded)
}

fn decode_ownership_receipt(encoded: &[u8]) -> io::Result<OwnershipReceipt> {
    if encoded.len() < OWNERSHIP_RECEIPT_HEADER_BYTES
        || encoded.len() > MAX_OWNERSHIP_RECEIPT_BYTES
        || &encoded[..8] != OWNERSHIP_RECEIPT_MAGIC
        || encoded[8] != OWNERSHIP_RECEIPT_VERSION
        || encoded[10..16] != [0_u8; 6]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid outbound ownership intent header",
        ));
    }
    let device = u64::from_be_bytes(encoded[16..24].try_into().expect("fixed receipt field"));
    let inode = u64::from_be_bytes(encoded[24..32].try_into().expect("fixed receipt field"));
    let task_id = i64::from_be_bytes(encoded[32..40].try_into().expect("fixed receipt field"));
    let size = u64::from_be_bytes(encoded[40..48].try_into().expect("fixed receipt field"));
    let sha256: [u8; 32] = encoded[48..80].try_into().expect("fixed receipt field");
    let instance_id: [u8; 16] = encoded[80..96].try_into().expect("fixed receipt field");
    let publication = match encoded[9] {
        0 if task_id == 0 && size == 0 && sha256 == [0_u8; 32] && instance_id == [0_u8; 16] => None,
        1 if task_id > 0 && size > 0 => Some(PublicationProof {
            task_id,
            kind: PublicationKind::Spool,
            size,
            sha256,
            instance_id,
        }),
        2 if task_id > 0 && size > 0 => Some(PublicationProof {
            task_id,
            kind: PublicationKind::Sent,
            size,
            sha256,
            instance_id,
        }),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid outbound ownership publication proof",
            ));
        }
    };
    let name_len = u32::from_be_bytes(encoded[96..100].try_into().expect("fixed receipt field"));
    let name_len = usize::try_from(name_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid outbound ownership filename length",
        )
    })?;
    if name_len == 0
        || name_len > MAX_OWNERSHIP_FILE_NAME_BYTES
        || encoded.len() != OWNERSHIP_RECEIPT_HEADER_BYTES + name_len
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid outbound ownership intent length",
        ));
    }
    let name = &encoded[OWNERSHIP_RECEIPT_HEADER_BYTES..];
    if name.contains(&b'/') || name.contains(&0) || matches!(name, b"." | b"..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid original filename in outbound ownership intent",
        ));
    }
    Ok(OwnershipReceipt {
        device,
        inode,
        publication,
        original_file_name: OsString::from_vec(name.to_vec()),
    })
}

fn create_ownership_receipt(
    quarantine: &std::os::fd::OwnedFd,
    receipt_name: &OsStr,
    original_file_name: &OsStr,
    device: u64,
    inode: u64,
    publication: Option<PublicationProof>,
) -> io::Result<()> {
    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, openat2, renameat_with, unlinkat,
    };

    let _staging_lease = acquire_staging_writer_lease(quarantine)?;
    let encoded = encode_ownership_receipt(original_file_name, device, inode, publication)?;
    for _ in 0..8 {
        let stage_name = random_staging_name()?;
        let descriptor = match openat2(
            quarantine,
            &stage_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(error) => return Err(io::Error::from(error)),
        };
        injected_test_hook("ownership_receipt_stage_created");
        let write_result = (|| {
            let mut file = File::from(descriptor);
            file.write_all(&encoded)?;
            sync_all(&file)?;
            injected_test_hook("ownership_receipt_stage_synced");
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = unlinkat(quarantine, &stage_name, AtFlags::empty());
            let _ = fsync(quarantine);
            return Err(error);
        }
        match renameat_with(
            quarantine,
            &stage_name,
            quarantine,
            receipt_name,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => return Ok(()),
            Err(error) => {
                let _ = unlinkat(quarantine, &stage_name, AtFlags::empty());
                let _ = fsync(quarantine);
                return Err(io::Error::from(error));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate an outbound ownership intent staging file",
    ))
}

fn read_ownership_receipt(
    quarantine: &std::os::fd::OwnedFd,
    receipt_name: &OsStr,
) -> io::Result<OwnershipReceipt> {
    use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, openat2};

    let descriptor = openat2(
        quarantine,
        receipt_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let receipt_stat = fstat(&descriptor).map_err(io::Error::from)?;
    let directory_stat = fstat(quarantine).map_err(io::Error::from)?;
    if FileType::from_raw_mode(receipt_stat.st_mode) != FileType::RegularFile
        || receipt_stat.st_uid != directory_stat.st_uid
        || receipt_stat.st_mode & 0o777 != 0o600
        || receipt_stat.st_nlink != 1
        || receipt_stat.st_size < OWNERSHIP_RECEIPT_HEADER_BYTES as i64
        || receipt_stat.st_size > MAX_OWNERSHIP_RECEIPT_BYTES as i64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound ownership intent is not a bounded private regular file",
        ));
    }
    let mut file = File::from(descriptor);
    let mut encoded = Vec::with_capacity(receipt_stat.st_size as usize);
    (&mut file)
        .take((MAX_OWNERSHIP_RECEIPT_BYTES + 1) as u64)
        .read_to_end(&mut encoded)?;
    if encoded.len() != receipt_stat.st_size as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound ownership intent changed while reading",
        ));
    }
    decode_ownership_receipt(&encoded)
}

pub(crate) fn read_rust_spool_publication_proof(
    quarantine: &std::os::fd::OwnedFd,
    task_id: i64,
    original_file_name: &OsStr,
) -> io::Result<RustSpoolPublicationProof> {
    if task_id <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Rust spool publication identity",
        ));
    }
    let receipt_name = publication_receipt_name(task_id, PublicationKind::Spool)?;
    let receipt = read_ownership_receipt(quarantine, &receipt_name)?;
    let quarantine_name = publication_quarantine_name(
        receipt.device,
        receipt.inode,
        task_id,
        PublicationKind::Spool,
    )?;
    let publication = receipt.publication.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Rust spool receipt is not a publication proof",
        )
    })?;
    if publication.task_id != task_id
        || publication.kind != PublicationKind::Spool
        || receipt.original_file_name != original_file_name
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Rust spool durable publication proof does not match its database identity",
        ));
    }
    Ok(RustSpoolPublicationProof {
        device: receipt.device,
        inode: receipt.inode,
        size: publication.size,
        sha256: publication.sha256,
        receipt_name,
        quarantine_name,
    })
}

pub(crate) fn remove_rust_spool_publication_proof(
    quarantine: &std::os::fd::OwnedFd,
    proof: &RustSpoolPublicationProof,
) -> io::Result<()> {
    remove_ownership_receipt(quarantine, &proof.receipt_name)
}

pub(crate) fn rust_spool_publication_quarantine_exists(
    quarantine: &std::os::fd::OwnedFd,
    task_id: i64,
) -> io::Result<bool> {
    if task_id <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Rust spool publication identity",
        ));
    }
    let mut entries = rustix::fs::Dir::read_from(quarantine).map_err(io::Error::from)?;
    let mut visited = 0_usize;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(io::Error::from)?;
        visited = visited.saturating_add(1);
        if visited > 100_000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "outbound quarantine exceeds its bounded publication scan",
            ));
        }
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if parse_publication_quarantine_name(name).is_some_and(|(_, _, observed_task_id, kind)| {
            observed_task_id == task_id && kind == PublicationKind::Spool
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_pending_publication_intent(
    quarantine_directory: &Path,
    quarantine: &std::os::fd::OwnedFd,
    receipt_name: &OsStr,
) -> io::Result<Option<PendingPublicationIntent>> {
    let Some((name_task_id, name_kind)) = parse_publication_receipt_name(receipt_name) else {
        return Ok(None);
    };
    let receipt = read_ownership_receipt(quarantine, receipt_name)?;
    let publication = receipt.publication.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "publication receipt contains a cleanup intent",
        )
    })?;
    if publication.task_id != name_task_id || publication.kind != name_kind {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "publication receipt identity conflicts with its deterministic name",
        ));
    }
    let original_parent = quarantine_directory.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "publication receipt has no original parent",
        )
    })?;
    Ok(Some(PendingPublicationIntent {
        task_id: publication.task_id,
        kind: match publication.kind {
            PublicationKind::Spool => PendingPublicationKind::Spool,
            PublicationKind::Sent => PendingPublicationKind::Sent,
        },
        original_path: original_parent.join(&receipt.original_file_name),
        quarantine_directory: quarantine_directory.to_path_buf(),
        receipt_name: receipt_name.to_os_string(),
        device: receipt.device,
        inode: receipt.inode,
        size: publication.size,
        sha256: publication.sha256,
        instance_id: publication.instance_id,
    }))
}

fn verify_publication_content(
    directory: &std::os::fd::OwnedFd,
    file_name: &OsStr,
    intent: &PendingPublicationIntent,
) -> io::Result<()> {
    let (descriptor, stat) = open_owned_file(directory, file_name)?;
    if stat.st_dev != intent.device
        || stat.st_ino != intent.inode
        || stat.st_size <= 0
        || stat.st_size as u64 != intent.size
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "publication data does not match its durable identity",
        ));
    }
    let mut file = File::from(descriptor);
    let mut digest = Sha256Digest::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        observed = observed.checked_add(count as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::FileTooLarge,
                "publication data size overflow",
            )
        })?;
        if observed > intent.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "publication data grew beyond its durable proof",
            ));
        }
        digest.update(&buffer[..count]);
    }
    let actual: [u8; 32] = digest.finalize().into();
    if observed != intent.size || actual != intent.sha256 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "publication data hash does not match its durable proof",
        ));
    }
    Ok(())
}

fn resolve_pending_publication_intent(
    intent: &PendingPublicationIntent,
    disposition: PublicationDisposition,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, RenameFlags, renameat_with, unlinkat};

    let original_parent_path = intent.original_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "pending publication has no original parent",
        )
    })?;
    let original_file_name = intent.original_path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "pending publication has no original filename",
        )
    })?;
    let original_parent = open_bound_directory(original_parent_path)?;
    let quarantine = open_bound_directory(&intent.quarantine_directory)?;
    let current = read_pending_publication_intent(
        &intent.quarantine_directory,
        &quarantine,
        &intent.receipt_name,
    )?
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "pending publication receipt changed type",
        )
    })?;
    if &current != intent {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pending publication receipt changed before reconciliation",
        ));
    }
    if disposition == PublicationDisposition::PreserveSpoolProof {
        // The coordinator may already have renamed this inode to its own
        // deterministic quarantine. Keep the proof intact and let the
        // database-owned cleanup state machine classify that name.
        return Ok(());
    }
    let publication_kind = match intent.kind {
        PendingPublicationKind::Spool => PublicationKind::Spool,
        PendingPublicationKind::Sent => PublicationKind::Sent,
    };
    let quarantine_name = publication_quarantine_name(
        intent.device,
        intent.inode,
        intent.task_id,
        publication_kind,
    )?;
    let mut original = probe_owned_path(
        &original_parent,
        original_file_name,
        intent.device,
        intent.inode,
    )?;
    let mut quarantined =
        probe_owned_path(&quarantine, &quarantine_name, intent.device, intent.inode)?;

    if disposition == PublicationDisposition::PreserveAndClear {
        match (original, quarantined) {
            (OwnedPathProbe::Owned, OwnedPathProbe::Missing) => {
                verify_publication_content(&original_parent, original_file_name, intent)?;
            }
            (OwnedPathProbe::Missing, OwnedPathProbe::Owned) => {
                verify_publication_content(&quarantine, &quarantine_name, intent)?;
                renameat_with(
                    &quarantine,
                    &quarantine_name,
                    &original_parent,
                    original_file_name,
                    RenameFlags::NOREPLACE,
                )
                .map_err(io::Error::from)?;
                fsync(&quarantine).map_err(io::Error::from)?;
                fsync(&original_parent).map_err(io::Error::from)?;
                verify_publication_content(&original_parent, original_file_name, intent)?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "committed publication intent conflicts with filesystem state",
                ));
            }
        }
        remove_ownership_receipt(&quarantine, &intent.receipt_name)?;
        return Ok(());
    }

    match (original, quarantined) {
        (OwnedPathProbe::Owned, OwnedPathProbe::Missing) => {
            verify_publication_content(&original_parent, original_file_name, intent)?;
            renameat_with(
                &original_parent,
                original_file_name,
                &quarantine,
                &quarantine_name,
                RenameFlags::NOREPLACE,
            )
            .map_err(io::Error::from)?;
            fsync(&quarantine).map_err(io::Error::from)?;
            fsync(&original_parent).map_err(io::Error::from)?;
            original = OwnedPathProbe::Missing;
            quarantined = OwnedPathProbe::Owned;
        }
        (OwnedPathProbe::Missing, OwnedPathProbe::Owned) => {
            verify_publication_content(&quarantine, &quarantine_name, intent)?;
            fsync(&quarantine).map_err(io::Error::from)?;
            fsync(&original_parent).map_err(io::Error::from)?;
        }
        (OwnedPathProbe::Missing, OwnedPathProbe::Missing) => {
            fsync(&quarantine).map_err(io::Error::from)?;
            fsync(&original_parent).map_err(io::Error::from)?;
            remove_ownership_receipt(&quarantine, &intent.receipt_name)?;
            return Ok(());
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "aborted publication intent conflicts with filesystem state",
            ));
        }
    }
    debug_assert_eq!(original, OwnedPathProbe::Missing);
    debug_assert_eq!(quarantined, OwnedPathProbe::Owned);
    verify_publication_content(&quarantine, &quarantine_name, intent)?;
    unlinkat(&quarantine, &quarantine_name, AtFlags::empty()).map_err(io::Error::from)?;
    fsync(&quarantine).map_err(io::Error::from)?;
    remove_ownership_receipt(&quarantine, &intent.receipt_name)?;
    Ok(())
}

fn remove_ownership_receipt(
    quarantine: &std::os::fd::OwnedFd,
    receipt_name: &OsStr,
) -> io::Result<()> {
    use rustix::fs::{AtFlags, unlinkat};

    match unlinkat(quarantine, receipt_name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(io::Error::from(error)),
    }
    fsync(quarantine).map_err(io::Error::from)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnedPathProbe {
    Missing,
    Owned,
    Conflict,
}

fn probe_owned_path(
    directory: &std::os::fd::OwnedFd,
    file_name: &OsStr,
    device: u64,
    inode: u64,
) -> io::Result<OwnedPathProbe> {
    use rustix::fs::{AtFlags, statat};

    match statat(directory, file_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if is_regular_stat(&stat) && stat.st_dev == device && stat.st_ino == inode => {
            Ok(OwnedPathProbe::Owned)
        }
        Ok(_) => Ok(OwnedPathProbe::Conflict),
        Err(rustix::io::Errno::NOENT) => Ok(OwnedPathProbe::Missing),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn recover_ownership_receipt(
    quarantine: &std::os::fd::OwnedFd,
    original_parent: &std::os::fd::OwnedFd,
    receipt_name: &OsStr,
) -> io::Result<usize> {
    use rustix::fs::{AtFlags, RenameFlags, renameat_with, unlinkat};

    let (quarantine_name, name_device, name_inode) = parse_ownership_receipt_name(receipt_name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid outbound ownership intent name",
            )
        })?;
    let receipt = read_ownership_receipt(quarantine, receipt_name)?;
    if receipt.device != name_device || receipt.inode != name_inode {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound ownership intent identity conflicts with its name",
        ));
    }
    if receipt.publication.is_some() {
        // Publication intents require PostgreSQL and Redis reconciliation.
        // The synchronous orphan scanner must never guess their outcome.
        return Ok(0);
    }
    let original = probe_owned_path(
        original_parent,
        &receipt.original_file_name,
        receipt.device,
        receipt.inode,
    )?;
    let quarantined =
        probe_owned_path(quarantine, &quarantine_name, receipt.device, receipt.inode)?;
    match (original, quarantined) {
        (OwnedPathProbe::Owned, OwnedPathProbe::Missing) => {
            renameat_with(
                original_parent,
                &receipt.original_file_name,
                quarantine,
                &quarantine_name,
                RenameFlags::NOREPLACE,
            )
            .map_err(io::Error::from)?;
            if probe_owned_path(quarantine, &quarantine_name, receipt.device, receipt.inode)?
                != OwnedPathProbe::Owned
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "outbound ownership changed while recovering its intent",
                ));
            }
            fsync(quarantine).map_err(io::Error::from)?;
            fsync(original_parent).map_err(io::Error::from)?;
        }
        (OwnedPathProbe::Missing, OwnedPathProbe::Owned) => {
            fsync(quarantine).map_err(io::Error::from)?;
            fsync(original_parent).map_err(io::Error::from)?;
        }
        (OwnedPathProbe::Missing, OwnedPathProbe::Missing) => {
            fsync(quarantine).map_err(io::Error::from)?;
            fsync(original_parent).map_err(io::Error::from)?;
            remove_ownership_receipt(quarantine, receipt_name)?;
            return Ok(0);
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "outbound ownership intent conflicts with an existing path",
            ));
        }
    }
    if probe_owned_path(quarantine, &quarantine_name, receipt.device, receipt.inode)?
        != OwnedPathProbe::Owned
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound quarantine changed before intent recovery unlink",
        ));
    }
    unlinkat(quarantine, &quarantine_name, AtFlags::empty()).map_err(io::Error::from)?;
    fsync(quarantine).map_err(io::Error::from)?;
    remove_ownership_receipt(quarantine, receipt_name)?;
    Ok(1)
}

fn recover_direct_quarantine_entry(
    quarantine: &std::os::fd::OwnedFd,
    original_parent: &std::os::fd::OwnedFd,
    quarantine_name: &OsStr,
    device: u64,
    inode: u64,
) -> io::Result<usize> {
    use rustix::fs::{AtFlags, statat, unlinkat};

    let receipt_name = ownership_receipt_name(quarantine_name)?;
    match statat(quarantine, &receipt_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => return Ok(0),
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(io::Error::from(error)),
    }
    match probe_owned_path(quarantine, quarantine_name, device, inode)? {
        OwnedPathProbe::Missing => return Ok(0),
        OwnedPathProbe::Owned => {}
        OwnedPathProbe::Conflict => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untracked outbound quarantine identity does not match its name",
            ));
        }
    }
    fsync(quarantine).map_err(io::Error::from)?;
    fsync(original_parent).map_err(io::Error::from)?;
    if probe_owned_path(quarantine, quarantine_name, device, inode)? != OwnedPathProbe::Owned {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untracked outbound quarantine changed before unlink",
        ));
    }
    unlinkat(quarantine, quarantine_name, AtFlags::empty()).map_err(io::Error::from)?;
    fsync(quarantine).map_err(io::Error::from)?;
    Ok(1)
}

fn recover_staging_entry(
    quarantine: &std::os::fd::OwnedFd,
    stage_name: &OsStr,
) -> io::Result<usize> {
    use rustix::fs::{
        AtFlags, FileType, Mode, OFlags, ResolveFlags, fstat, openat2, statat, unlinkat,
    };

    if parse_staging_name(stage_name).is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid outbound staging filename",
        ));
    }
    let descriptor = openat2(
        quarantine,
        stage_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let directory_stat = fstat(quarantine).map_err(io::Error::from)?;
    let opened = fstat(&descriptor).map_err(io::Error::from)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        || opened.st_uid != directory_stat.st_uid
        || opened.st_mode & 0o777 != 0o600
        || opened.st_nlink != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound staging entry is not a private unlinked owner file",
        ));
    }
    injected_test_hook("staging_before_unlink");
    let rebound =
        statat(quarantine, stage_name, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)?;
    if !is_regular_stat(&rebound)
        || rebound.st_dev != opened.st_dev
        || rebound.st_ino != opened.st_ino
        || rebound.st_uid != opened.st_uid
        || rebound.st_mode & 0o777 != 0o600
        || rebound.st_nlink != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound staging entry changed before recovery unlink",
        ));
    }
    unlinkat(quarantine, stage_name, AtFlags::empty()).map_err(io::Error::from)?;
    Ok(1)
}

fn sweep_owned_quarantine_cursor(
    cursor: &mut QuarantineSweepCursor,
    max_directories: usize,
    max_entries: usize,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<usize> {
    let mut visited_directories = 0_usize;
    let mut visited_entries = 0_usize;
    let mut removed = 0_usize;
    let mut first_error = None;
    let mut was_cancelled = false;

    loop {
        if cancelled.load(Ordering::Acquire) {
            was_cancelled = true;
            break;
        }
        if Instant::now() >= deadline
            || visited_directories >= max_directories
            || visited_entries >= max_entries
            || cursor.pending_publications.len() >= MAX_PENDING_PUBLICATION_INTENTS
        {
            break;
        }

        if cursor.stack.is_empty() {
            if cursor.next_root >= cursor.roots.len() {
                cursor.next_root = 0;
                break;
            }
            let root = cursor.roots[cursor.next_root].clone();
            cursor.next_root += 1;
            match fs::symlink_metadata(&root) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            }
            match fs::read_dir(&root) {
                Ok(entries) => {
                    cursor.stack.push(QuarantineSweepFrame {
                        path: root,
                        entries,
                        kind: QuarantineSweepFrameKind::Tree,
                    });
                    visited_directories += 1;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
            continue;
        }

        let mut pop_frame = false;
        let mut push_frame = None;
        let mut queued_publication = None;
        let stack_depth = cursor.stack.len();
        {
            let frame = cursor.stack.last_mut().expect("sweep stack is not empty");
            match &mut frame.kind {
                QuarantineSweepFrameKind::Tree => match frame.entries.next() {
                    None => pop_frame = true,
                    Some(Err(error)) => {
                        visited_entries += 1;
                        first_error.get_or_insert(error);
                    }
                    Some(Ok(entry)) => {
                        visited_entries += 1;
                        let file_type = match entry.file_type() {
                            Ok(file_type) => file_type,
                            Err(error) => {
                                first_error.get_or_insert(error);
                                continue;
                            }
                        };
                        if file_type.is_symlink() || !file_type.is_dir() {
                            continue;
                        }
                        if stack_depth >= QUARANTINE_SWEEP_MAX_DEPTH {
                            first_error.get_or_insert_with(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "outbound quarantine tree exceeds its depth bound",
                                )
                            });
                            continue;
                        }
                        let child = entry.path();
                        let kind = if entry.file_name() == OsStr::new(".lmyzmail-quarantine") {
                            let descriptor = match open_bound_directory(&child) {
                                Ok(descriptor) => descriptor,
                                Err(error) => {
                                    first_error.get_or_insert(error);
                                    continue;
                                }
                            };
                            let original_parent = match open_bound_directory(&frame.path) {
                                Ok(parent) => parent,
                                Err(error) => {
                                    first_error.get_or_insert(error);
                                    continue;
                                }
                            };
                            QuarantineSweepFrameKind::Quarantine {
                                descriptor,
                                original_parent,
                            }
                        } else {
                            QuarantineSweepFrameKind::Tree
                        };
                        let entries = match fs::read_dir(&child) {
                            Ok(entries) => entries,
                            Err(error) => {
                                first_error.get_or_insert(error);
                                continue;
                            }
                        };
                        push_frame = Some(QuarantineSweepFrame {
                            path: child,
                            entries,
                            kind,
                        });
                    }
                },
                QuarantineSweepFrameKind::Quarantine {
                    descriptor,
                    original_parent,
                    ..
                } => match frame.entries.next() {
                    None => {
                        if let Err(error) = fsync(descriptor).map_err(io::Error::from) {
                            first_error.get_or_insert(error);
                        }
                        if let Err(error) = fsync(original_parent).map_err(io::Error::from) {
                            first_error.get_or_insert(error);
                        }
                        pop_frame = true;
                    }
                    Some(Err(error)) => {
                        visited_entries += 1;
                        first_error.get_or_insert(error);
                    }
                    Some(Ok(entry)) => {
                        visited_entries += 1;
                        let file_name = entry.file_name();
                        let recognized = parse_staging_name(&file_name).is_some()
                            || parse_publication_receipt_name(&file_name).is_some()
                            || parse_ownership_receipt_name(&file_name).is_some()
                            || parse_publication_quarantine_name(&file_name).is_some()
                            || parse_ownership_quarantine_name(&file_name).is_some();
                        if !recognized {
                            continue;
                        }
                        let staging_entry = parse_staging_name(&file_name).is_some();
                        let staging_lease = match try_acquire_staging_recovery_lease(descriptor) {
                            Ok(Some(lease)) => lease,
                            Ok(None) => continue,
                            Err(error) => {
                                first_error.get_or_insert(error);
                                continue;
                            }
                        };
                        let mut recovery = if staging_entry {
                            Some(recover_staging_entry(descriptor, &file_name))
                        } else if parse_publication_receipt_name(&file_name).is_some() {
                            match read_pending_publication_intent(
                                &frame.path,
                                descriptor,
                                &file_name,
                            ) {
                                Ok(Some(intent)) => queued_publication = Some(intent),
                                Ok(None) => {}
                                Err(error) => {
                                    first_error.get_or_insert(error);
                                }
                            }
                            None
                        } else if parse_ownership_receipt_name(&file_name).is_some() {
                            Some(recover_ownership_receipt(
                                descriptor,
                                original_parent,
                                &file_name,
                            ))
                        } else if parse_publication_quarantine_name(&file_name).is_some() {
                            // Publication data is resolved only after durable
                            // PostgreSQL and Redis classification.
                            None
                        } else if let Some((device, inode)) =
                            parse_ownership_quarantine_name(&file_name)
                        {
                            Some(recover_direct_quarantine_entry(
                                descriptor,
                                original_parent,
                                &file_name,
                                device,
                                inode,
                            ))
                        } else {
                            None
                        };
                        drop(staging_lease);
                        if staging_entry && matches!(recovery, Some(Ok(_))) {
                            injected_test_hook("staging_after_recovery_lease");
                            if let Err(error) = fsync(descriptor).map_err(io::Error::from) {
                                recovery = Some(Err(error));
                            }
                        }
                        if let Some(recovery) = recovery {
                            match recovery {
                                Ok(count) => removed += count,
                                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                                Err(error) => {
                                    first_error.get_or_insert(error);
                                }
                            }
                        }
                    }
                },
            }
        }
        if pop_frame {
            cursor.stack.pop();
        }
        if let Some(frame) = push_frame {
            cursor.stack.push(frame);
            visited_directories += 1;
        }
        if let Some(intent) = queued_publication
            && !cursor.pending_publications.contains(&intent)
        {
            cursor.pending_publications.push_back(intent);
        }
    }

    if was_cancelled {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "outbound quarantine sweep cancelled",
        ))
    } else if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(removed)
    }
}

fn create_owned_temporary(
    parent_path: &Path,
    kind: &str,
) -> io::Result<(File, PublishedFileOwnership)> {
    use rustix::fs::{
        FileType, Mode, OFlags, RenameFlags, ResolveFlags, fstat, openat2, renameat_with,
    };

    let parent = open_bound_directory(parent_path)?;
    let quarantine = open_quarantine_directory(&parent)?;
    let staging_lease = acquire_staging_writer_lease(&quarantine)?;
    let quarantine_stat = fstat(&quarantine).map_err(io::Error::from)?;
    for _ in 0..8 {
        let file_name = random_storage_name(kind)?;
        let stage_name = random_staging_name()?;
        let descriptor = match openat2(
            &quarantine,
            &stage_name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::EXIST => continue,
            Err(error) => return Err(io::Error::from(error)),
        };
        injected_test_hook("temporary_stage_created");
        let stat = match injected_test_fault("temporary_fstat")
            .and_then(|()| fstat(&descriptor).map_err(io::Error::from))
        {
            Ok(stat) => stat,
            Err(error) => {
                drop(descriptor);
                return Err(error_after_creation_cleanup(
                    "created staging temporary initialization and cleanup failed",
                    error,
                    recover_staging_entry(&quarantine, &stage_name).map(|_| ()),
                ));
            }
        };
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != quarantine_stat.st_uid
            || stat.st_mode & 0o777 != 0o600
            || stat.st_nlink != 1
        {
            let error = io::Error::other("created outbound staging temporary is not private");
            drop(descriptor);
            return Err(error_after_creation_cleanup(
                "non-private staging temporary cleanup failed",
                error,
                recover_staging_entry(&quarantine, &stage_name).map(|_| ()),
            ));
        }
        let file = File::from(descriptor);
        let pin = match injected_test_fault("temporary_clone").and_then(|()| file.try_clone()) {
            Ok(pin) => pin,
            Err(error) => {
                drop(file);
                return Err(error_after_creation_cleanup(
                    "created staging temporary clone and cleanup failed",
                    error,
                    recover_staging_entry(&quarantine, &stage_name).map(|_| ()),
                ));
            }
        };

        let quarantine_name = ownership_quarantine_name(stat.st_dev, stat.st_ino)?;
        if let Err(error) = renameat_with(
            &quarantine,
            &stage_name,
            &quarantine,
            &quarantine_name,
            RenameFlags::NOREPLACE,
        ) {
            drop(pin);
            drop(file);
            let error = io::Error::from(error);
            let cleanup = recover_staging_entry(&quarantine, &stage_name).map(|_| ());
            if error.kind() == io::ErrorKind::AlreadyExists && cleanup.is_ok() {
                continue;
            }
            return Err(error_after_creation_cleanup(
                "staging temporary rename cleanup failed",
                error,
                cleanup,
            ));
        }
        injected_test_hook("temporary_stage_quarantined");
        if let Err(error) = fsync(&quarantine).map_err(io::Error::from) {
            drop(pin);
            drop(file);
            return Err(error_after_creation_cleanup(
                "quarantined temporary directory sync cleanup failed",
                error,
                recover_direct_quarantine_entry(
                    &quarantine,
                    &parent,
                    &quarantine_name,
                    stat.st_dev,
                    stat.st_ino,
                )
                .map(|_| ()),
            ));
        }

        let receipt_name = ownership_receipt_name(&quarantine_name)?;
        if let Err(error) = create_ownership_receipt(
            &quarantine,
            &receipt_name,
            &file_name,
            stat.st_dev,
            stat.st_ino,
            None,
        ) {
            drop(pin);
            drop(file);
            return Err(error_after_creation_cleanup(
                "temporary cleanup receipt creation rollback failed",
                error,
                recover_direct_quarantine_entry(
                    &quarantine,
                    &parent,
                    &quarantine_name,
                    stat.st_dev,
                    stat.st_ino,
                )
                .map(|_| ()),
            ));
        }
        injected_test_hook("temporary_receipt_created");
        if let Err(error) = injected_test_fault("ownership_intent_directory_fsync")
            .and_then(|()| fsync(&quarantine).map_err(io::Error::from))
        {
            drop(pin);
            drop(file);
            return Err(error_after_creation_cleanup(
                "temporary cleanup receipt sync rollback failed",
                error,
                recover_ownership_receipt(&quarantine, &parent, &receipt_name).map(|_| ()),
            ));
        }
        injected_test_hook("temporary_receipt_durable");

        if let Err(error) = renameat_with(
            &quarantine,
            &quarantine_name,
            &parent,
            &file_name,
            RenameFlags::NOREPLACE,
        ) {
            drop(pin);
            drop(file);
            let error = io::Error::from(error);
            let cleanup =
                recover_ownership_receipt(&quarantine, &parent, &receipt_name).map(|_| ());
            if error.kind() == io::ErrorKind::AlreadyExists && cleanup.is_ok() {
                continue;
            }
            return Err(error_after_creation_cleanup(
                "temporary publication collision rollback failed",
                error,
                cleanup,
            ));
        }
        injected_test_hook("temporary_moved_to_parent");
        let directory_sync = fsync(&quarantine)
            .and_then(|()| fsync(&parent))
            .map_err(io::Error::from);
        if let Err(error) = directory_sync {
            drop(pin);
            drop(file);
            return Err(error_after_creation_cleanup(
                "temporary publication directory sync rollback failed",
                error,
                recover_ownership_receipt(&quarantine, &parent, &receipt_name).map(|_| ()),
            ));
        }

        let path = parent_path.join(&file_name);
        let quarantine_path = parent_path
            .join(".lmyzmail-quarantine")
            .join(&quarantine_name);
        let mut ownership = PublishedFileOwnership::from_parent(
            path,
            parent,
            file_name,
            Some(pin.into()),
            stat.st_dev,
            stat.st_ino,
        );
        ownership.cleanup_state = PublishedFileCleanupState::PreparedReceipt {
            quarantine,
            quarantine_path,
            quarantine_name,
            receipt_name,
            receipt_directory_synced: true,
        };
        ownership.staging_lease = Some(staging_lease);
        ownership.cleanup_temporary_on_drop = true;
        return Ok((file, ownership));
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique outbound temporary",
    ))
}

fn error_after_creation_cleanup(
    context: &'static str,
    error: io::Error,
    cleanup: io::Result<()>,
) -> io::Error {
    match cleanup {
        Ok(()) => error,
        Err(cleanup_error) => rollback_unknown_io(
            context,
            io::Error::other(format!("{error}; {cleanup_error}")),
        ),
    }
}

fn open_quarantine_directory(parent: &std::os::fd::OwnedFd) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, mkdirat, openat2};

    const NAME: &str = ".lmyzmail-quarantine";
    match mkdirat(parent, NAME, Mode::RWXU) {
        Ok(()) => {}
        Err(error) if error == rustix::io::Errno::EXIST => {}
        Err(error) => return Err(io::Error::from(error)),
    }
    let descriptor = openat2(
        parent,
        NAME,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let parent_stat = fstat(parent).map_err(io::Error::from)?;
    let stat = fstat(&descriptor).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != parent_stat.st_uid
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound quarantine is not a private owner directory",
        ));
    }
    injected_test_fault("ownership_quarantine_parent_fsync")?;
    fsync(parent).map_err(io::Error::from)?;
    Ok(descriptor)
}

fn open_staging_lease_directory(
    quarantine: &std::os::fd::OwnedFd,
) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, openat2};

    let descriptor = openat2(
        quarantine,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let directory_stat = fstat(quarantine).map_err(io::Error::from)?;
    let stat = fstat(&descriptor).map_err(io::Error::from)?;
    // flock is supported on directory descriptors on Linux. A fresh open
    // description (not dup) keeps independent shared/exclusive leases while
    // leaving no permanent file in the externally observed Maildir tree.
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_dev != directory_stat.st_dev
        || stat.st_ino != directory_stat.st_ino
        || stat.st_uid != directory_stat.st_uid
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound staging lease is not the private quarantine directory",
        ));
    }
    Ok(descriptor)
}

fn verify_staging_lease_binding(
    quarantine: &std::os::fd::OwnedFd,
    descriptor: &std::os::fd::OwnedFd,
) -> io::Result<()> {
    use rustix::fs::{FileType, fstat};

    let opened = fstat(descriptor).map_err(io::Error::from)?;
    let bound = fstat(quarantine).map_err(io::Error::from)?;
    if FileType::from_raw_mode(bound.st_mode) != FileType::Directory
        || bound.st_dev != opened.st_dev
        || bound.st_ino != opened.st_ino
        || bound.st_uid != opened.st_uid
        || bound.st_mode & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "outbound staging lease changed while it was being locked",
        ));
    }
    Ok(())
}

fn acquire_staging_writer_lease(
    quarantine: &std::os::fd::OwnedFd,
) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{FlockOperation, flock};

    let descriptor = open_staging_lease_directory(quarantine)?;
    let deadline = Instant::now() + STAGING_WRITER_LEASE_DEADLINE;
    loop {
        match flock(&descriptor, FlockOperation::NonBlockingLockShared) {
            Ok(()) => {
                verify_staging_lease_binding(quarantine, &descriptor)?;
                return Ok(descriptor);
            }
            Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_micros(250));
            }
            Err(rustix::io::Errno::WOULDBLOCK) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "outbound staging recovery lease deadline elapsed",
                ));
            }
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

fn try_acquire_staging_recovery_lease(
    quarantine: &std::os::fd::OwnedFd,
) -> io::Result<Option<std::os::fd::OwnedFd>> {
    use rustix::fs::{FlockOperation, flock};

    let descriptor = open_staging_lease_directory(quarantine)?;
    match flock(&descriptor, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => return Ok(None),
        Err(error) => return Err(io::Error::from(error)),
    }
    verify_staging_lease_binding(quarantine, &descriptor)?;
    Ok(Some(descriptor))
}

fn restore_quarantined_replacement(
    parent: &std::os::fd::OwnedFd,
    file_name: &OsStr,
    quarantine: &std::os::fd::OwnedFd,
    quarantine_name: &OsStr,
    original_path: &Path,
    reason: &str,
) -> io::Result<()> {
    use rustix::fs::{RenameFlags, renameat_with};

    match renameat_with(
        quarantine,
        quarantine_name,
        parent,
        file_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            fsync(quarantine).map_err(io::Error::from)?;
            fsync(parent).map_err(io::Error::from)?;
            Ok(())
        }
        Err(restore_error) => Err(io::Error::other(format!(
            "owned message cleanup refused replacement ({reason}); retained quarantine {} for {}: {}",
            quarantine_name.to_string_lossy(),
            original_path.display(),
            io::Error::from(restore_error),
        ))),
    }
}

fn atomic_publish_bytes(
    parent: &Path,
    destination: &Path,
    bytes: &[u8],
    max_bytes: u64,
    publication: Option<PublicationIntent>,
) -> io::Result<PublishedFileOwnership> {
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "system message exceeds configured size limit",
        ));
    }
    let (output, ownership) = create_owned_temporary(parent, "system")?;
    let mut ownership = Some(ownership);
    let result = (|| {
        let mut writer = BufWriter::new(output);
        writer.write_all(bytes)?;
        writer.flush()?;
        sync_all(writer.get_ref())?;
        publish_temp_file(
            ownership
                .take()
                .ok_or_else(|| io::Error::other("system ownership is disarmed"))?,
            destination,
            publication,
        )
    })();
    if let Err(error) = result {
        if let Err(cleanup_error) = remove_optional_ownership(ownership.take()) {
            return Err(rollback_unknown_io(
                "system temporary cleanup after publish failure",
                cleanup_error,
            ));
        }
        return Err(error);
    }
    result
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
    secure_mailbox_folder(base, address, folder)
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

fn sent_shard_lock_index(base: &Path) -> usize {
    let mut hasher = DefaultHasher::new();
    base.hash(&mut hasher);
    (hasher.finish() as usize) % SENT_SHARD_LOCKS
}

fn inspect_sent_subdirectories(
    base: &Path,
    sent_file_name: &str,
) -> io::Result<(Option<i32>, i32, Option<PathBuf>)> {
    let mut directories = Vec::new();
    let mut maximum = 0_i32;
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
        let path = entry.path();
        directories.push((index, path));
        if index > maximum {
            maximum = index;
        }
    }
    // Probe the stable generated name directly in each shard. Only the newest
    // shard needs a full count to decide whether rollover is required.
    for (index, directory) in &directories {
        let candidate = directory.join(sent_file_name);
        match fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.file_type().is_file() => {
                return Ok((Some(*index), maximum, None));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let maximum_path = directories
        .iter()
        .find_map(|(index, path)| (*index == maximum).then_some(path.clone()));
    Ok((None, maximum, maximum_path))
}

fn count_regular_files(directory: &Path) -> io::Result<usize> {
    let mut count = 0_usize;
    for file in fs::read_dir(directory)? {
        let file = file?;
        let file_type = file.file_type()?;
        if file_type.is_file() && !file_type.is_symlink() {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

#[cfg(test)]
fn select_subdirectory(base: &Path, max_files: usize, sent_file_name: &str) -> io::Result<i32> {
    let allocator = Arc::new(SentShardAllocator::default());
    allocator
        .reserve(base, max_files, sent_file_name)
        .map(|selection| selection.subdirectory())
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

fn atomic_copy(
    source: &PublishedFileOwnership,
    destination: &Path,
    max_bytes: u64,
    cancelled: &AtomicBool,
    publication: Option<PublicationIntent>,
) -> io::Result<PublishedFileOwnership> {
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("sent file has no parent"))?;
    let (output, ownership) = create_owned_temporary(parent, "copy")?;
    let mut ownership = Some(ownership);
    let result = (|| {
        let before = source.content_proof_bounded(max_bytes)?;
        let mut input = source.open_read()?;
        input.seek(SeekFrom::Start(0))?;
        let mut output = BoundedWriter::new(BufWriter::new(output), max_bytes);
        copy_bounded(&mut input, &mut output, cancelled)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut output = output.finish()?;
        output.flush()?;
        sync_all(output.get_ref())?;
        if source.content_proof_bounded(max_bytes)? != before {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "outbound copy source changed while copying",
            ));
        }
        let published = publish_temp_file(
            ownership
                .take()
                .ok_or_else(|| io::Error::other("copy ownership is disarmed"))?,
            destination,
            publication,
        )?;
        if published.content_proof_bounded(max_bytes)? != before {
            let mismatch = io::Error::new(
                io::ErrorKind::InvalidData,
                "outbound copy destination differs from its pinned source",
            );
            published.remove_if_still_owned()?;
            return Err(mismatch);
        }
        Ok(published)
    })();
    if let Err(error) = result {
        if let Err(cleanup_error) = remove_optional_ownership(ownership.take()) {
            return Err(rollback_unknown_io(
                "copy temporary cleanup after publish failure",
                cleanup_error,
            ));
        }
        return Err(error);
    }
    result
}

fn read_pinned_bytes(
    source: &PublishedFileOwnership,
    expected_size: u64,
    expected_sha256: [u8; 32],
    maximum: u64,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>, MessageBuildError> {
    if expected_size > maximum {
        return Err(MessageBuildError::InvalidInput("email_too_large"));
    }
    let capacity = usize::try_from(expected_size)
        .map_err(|_| MessageBuildError::InvalidInput("email_too_large"))?;
    let descriptor = source
        .file
        .as_ref()
        .ok_or_else(|| io::Error::other("outbound message source is not pinned"))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut digest = Sha256Digest::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while offset < expected_size {
        check_cancelled(cancelled)?;
        let remaining = usize::try_from((expected_size - offset).min(buffer.len() as u64))
            .map_err(|_| MessageBuildError::InvalidInput("email_too_large"))?;
        let count = rustix::io::pread(descriptor, &mut buffer[..remaining], offset)
            .map_err(io::Error::from)?;
        if count == 0 {
            return Err(MessageBuildError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "outbound message source was truncated while reading",
            )));
        }
        bytes.extend_from_slice(&buffer[..count]);
        digest.update(&buffer[..count]);
        offset = offset
            .checked_add(count as u64)
            .ok_or(MessageBuildError::InvalidInput("email_too_large"))?;
    }
    let mut probe = [0_u8; 1];
    let observed_sha256: [u8; 32] = digest.finalize().into();
    if rustix::io::pread(descriptor, &mut probe, expected_size).map_err(io::Error::from)? != 0
        || observed_sha256 != expected_sha256
        || source.content_proof_bounded(maximum)? != (expected_size, expected_sha256)
    {
        return Err(MessageBuildError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound message source changed while reading",
        )));
    }
    Ok(bytes)
}

fn publish_temp_file(
    temporary: PublishedFileOwnership,
    destination: &Path,
    publication: Option<PublicationIntent>,
) -> io::Result<PublishedFileOwnership> {
    use rustix::fs::{AtFlags, linkat};

    let mut temporary = Some(temporary);
    let (source_device, source_inode, publication_proof) = {
        let source = temporary
            .as_ref()
            .ok_or_else(|| io::Error::other("temporary ownership is disarmed"))?;
        let publication_proof = publication
            .map(|intent| source.content_proof().map(|proof| (intent, proof)))
            .transpose()?;
        (source.device, source.inode, publication_proof)
    };
    let mut destination_ownership =
        match PublishedFileOwnership::expected_at(destination, source_device, source_inode) {
            Ok(ownership) => Some(ownership),
            Err(error) => {
                if let Err(cleanup_error) = remove_optional_ownership(temporary.take()) {
                    return Err(rollback_unknown_io(
                        "publish setup and temporary cleanup failed",
                        io::Error::other(format!("{error}; {cleanup_error}")),
                    ));
                }
                return Err(error);
            }
        };
    let mut linked = false;
    let result: io::Result<()> = (|| {
        let destination = destination_ownership
            .as_mut()
            .ok_or_else(|| io::Error::other("destination ownership is disarmed"))?;
        if let Some((intent, (size, sha256))) = publication_proof {
            destination.prepare_publication_intent(intent, size, sha256)?;
        }
        {
            let source = temporary
                .as_ref()
                .ok_or_else(|| io::Error::other("temporary ownership is disarmed"))?;
            linkat(
                &source.parent,
                &source.file_name,
                &destination.parent,
                &destination.file_name,
                AtFlags::empty(),
            )
            .map_err(io::Error::from)?;
        }
        linked = true;
        injected_test_hook("publish_after_link_before_verify");
        injected_test_fault("publish_after_link_before_verify")?;
        destination.verify_and_pin()?;
        injected_test_fault("publish_after_link")?;
        temporary
            .take()
            .ok_or_else(|| io::Error::other("temporary ownership is disarmed"))?
            .remove_if_still_owned()?;
        fsync(&destination.parent).map_err(io::Error::from)
    })();
    if let Err(error) = result {
        let destination_cleanup = if linked {
            remove_optional_ownership(destination_ownership.take())
        } else {
            destination_ownership
                .as_mut()
                .map_or(Ok(()), |ownership| ownership.cancel_unpublished_intent())
        };
        let temporary_cleanup = remove_optional_ownership(temporary.take());
        if let Err(cleanup_error) = destination_cleanup.and(temporary_cleanup) {
            return Err(rollback_unknown_io(
                "publish and ownership cleanup failed",
                io::Error::other(format!("{error}; {cleanup_error}")),
            ));
        }
        return Err(error);
    }
    destination_ownership
        .take()
        .ok_or_else(|| io::Error::other("published ownership is disarmed"))
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

    struct TestFaultGuard;

    impl TestFaultGuard {
        fn inject(name: &'static str) -> Self {
            TEST_FAULT.with(|fault| {
                assert!(fault.replace(Some(name)).is_none());
            });
            Self
        }
    }

    impl Drop for TestFaultGuard {
        fn drop(&mut self) {
            TEST_FAULT.with(|fault| fault.set(None));
        }
    }

    struct TestHookGuard;

    impl TestHookGuard {
        fn install(name: &'static str, hook: impl FnOnce() + 'static) -> Self {
            TEST_HOOK.with(|slot| {
                assert!(slot.replace(Some((name, Box::new(hook)))).is_none());
            });
            Self
        }
    }

    impl Drop for TestHookGuard {
        fn drop(&mut self) {
            TEST_HOOK.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }

    fn regular_file_count(root: &Path) -> usize {
        let Ok(entries) = fs::read_dir(root) else {
            return 0;
        };
        entries
            .filter_map(Result::ok)
            .map(|entry| {
                let Ok(kind) = entry.file_type() else {
                    return 0;
                };
                if kind.is_dir() {
                    regular_file_count(&entry.path())
                } else {
                    usize::from(kind.is_file())
                }
            })
            .sum()
    }

    fn sweep_test_root_to_quiescence(root: &Path) {
        let mut cursor = QuarantineSweepCursor {
            roots: vec![root.to_path_buf()],
            ..QuarantineSweepCursor::default()
        };
        for _ in 0..128 {
            let _ = sweep_owned_quarantine_cursor(
                &mut cursor,
                64,
                64,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            );
            if regular_file_count(root) == 0 {
                return;
            }
        }
        assert_eq!(regular_file_count(root), 0, "recovery did not quiesce");
    }

    fn create_test_staging_file(quarantine: &Path, bytes: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = quarantine.join(random_staging_name().unwrap());
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    fn sent_shard_selection_finds_exact_retry_in_an_older_shard() {
        let root = TestDirectory::new();
        let first = root.0.join("1");
        let second = root.0.join("2");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let name = "1722906123000-lmyzmail-42.eml";
        fs::write(first.join(name), b"retry").unwrap();
        fs::write(second.join("newer.eml"), b"newer").unwrap();

        assert_eq!(select_subdirectory(&root.0, 10, name).unwrap(), 1);
    }

    #[test]
    fn sent_shard_selection_counts_only_regular_files_for_rollover() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let first = root.0.join("1");
        fs::create_dir(&first).unwrap();
        fs::write(first.join("one.eml"), b"one").unwrap();
        fs::write(first.join("two.eml"), b"two").unwrap();
        symlink(first.join("one.eml"), first.join("ignored.eml")).unwrap();

        assert_eq!(
            select_subdirectory(&root.0, 2, "new-lmyzmail-43.eml").unwrap(),
            2
        );
    }

    #[test]
    fn sent_shard_selection_refuses_symlink_as_an_idempotent_retry() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let first = root.0.join("1");
        let second = root.0.join("2");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let name = "1722906123000-lmyzmail-42.eml";
        fs::write(second.join("incumbent.eml"), b"incumbent").unwrap();
        symlink(second.join("incumbent.eml"), first.join(name)).unwrap();

        assert_eq!(select_subdirectory(&root.0, 10, name).unwrap(), 2);
    }

    #[test]
    fn sent_shard_reservation_releases_capacity_after_failed_publication() {
        let root = TestDirectory::new();
        let allocator = Arc::new(SentShardAllocator::default());
        let first = allocator.reserve(&root.0, 1, "first.eml").unwrap();
        assert_eq!(first.subdirectory(), 1);
        drop(first);

        let second = allocator.reserve(&root.0, 1, "second.eml").unwrap();
        assert_eq!(second.subdirectory(), 1);
    }

    #[test]
    fn sent_shard_reservation_releases_only_after_proven_cleanup() {
        let root = TestDirectory::new();
        let allocator = Arc::new(SentShardAllocator::default());
        let mut visible = allocator
            .reserve(&root.0, 1, "visible.eml")
            .unwrap()
            .into_reservation()
            .unwrap();
        visible.mark_durable();
        fs::create_dir(root.0.join("1")).unwrap();
        fs::write(root.0.join("1/visible.eml"), b"visible").unwrap();
        drop(visible);
        assert_eq!(
            allocator
                .reserve(&root.0, 1, "next.eml")
                .unwrap()
                .subdirectory(),
            2
        );

        let another_root = TestDirectory::new();
        let mut removed = allocator
            .reserve(&another_root.0, 1, "removed.eml")
            .unwrap()
            .into_reservation()
            .unwrap();
        removed.mark_durable();
        removed.release_after_proven_cleanup();
        drop(removed);
        assert_eq!(
            allocator
                .reserve(&another_root.0, 1, "replacement.eml")
                .unwrap()
                .subdirectory(),
            1
        );
    }

    #[test]
    fn sent_shard_reservations_enforce_capacity_before_files_are_visible() {
        let root = TestDirectory::new();
        let allocator = Arc::new(SentShardAllocator::default());
        let mut selected = Vec::new();
        let mut reservations = Vec::new();
        for index in 0..5 {
            let selection = allocator
                .reserve(&root.0, 2, &format!("message-{index}.eml"))
                .unwrap();
            selected.push(selection.subdirectory());
            reservations.push(selection.into_reservation().unwrap());
        }
        assert_eq!(selected, [1, 1, 2, 2, 3]);
        drop(reservations);
    }

    #[test]
    fn concurrent_same_name_reservations_share_one_capacity_slot() {
        let root = TestDirectory::new();
        let allocator = Arc::new(SentShardAllocator::default());
        let first = allocator
            .reserve(&root.0, 1, "same.eml")
            .unwrap()
            .into_reservation()
            .unwrap();
        let mut second = allocator
            .reserve(&root.0, 1, "same.eml")
            .unwrap()
            .into_reservation()
            .unwrap();
        assert_eq!(first.subdirectory, 1);
        assert_eq!(second.subdirectory, 1);
        second.mark_durable();
        drop(first);
        fs::create_dir(root.0.join("1")).unwrap();
        fs::write(root.0.join("1/same.eml"), b"same").unwrap();
        drop(second);

        let next = allocator.reserve(&root.0, 1, "next.eml").unwrap();
        assert_eq!(next.subdirectory(), 2);
    }

    #[test]
    fn sent_shard_allocator_resynchronizes_after_external_cleanup() {
        let root = TestDirectory::new();
        let allocator = Arc::new(SentShardAllocator::default());
        let mut first = allocator
            .reserve(&root.0, 1, "first.eml")
            .unwrap()
            .into_reservation()
            .unwrap();
        assert_eq!(first.subdirectory, 1);
        fs::create_dir(root.0.join("1")).unwrap();
        fs::write(root.0.join("1/first.eml"), b"first").unwrap();
        first.mark_durable();
        drop(first);
        let mut second = allocator
            .reserve(&root.0, 1, "second.eml")
            .unwrap()
            .into_reservation()
            .unwrap();
        assert_eq!(second.subdirectory, 2);
        fs::create_dir(root.0.join("2")).unwrap();
        fs::write(root.0.join("2/second.eml"), b"second").unwrap();
        second.mark_durable();
        drop(second);

        fs::remove_dir_all(root.0.join("1")).unwrap();
        fs::remove_dir_all(root.0.join("2")).unwrap();

        let third = allocator.reserve(&root.0, 1, "third.eml").unwrap();
        assert_eq!(third.subdirectory(), 1);
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
            text_file: None,
            html: Some("<p>HTML body</p>".into()),
            attachments: vec![MessageAttachment {
                filename: "proof.txt".into(),
                content_type: "text/plain".into(),
                content_base64: "aGVsbG8=".into(),
                content_length: None,
                source_path: None,
                inline: false,
                content_id: None,
            }],
            message_id: "<stable@example.test>".into(),
            created_at: Utc.with_ymd_and_hms(2026, 8, 6, 1, 2, 3).unwrap(),
        }
    }

    #[test]
    fn dropping_materialized_message_preserves_sent_shard_capacity() {
        let root = TestDirectory::new();
        let mut builder = system_builder(&root.0, None);
        builder.max_files_per_directory = 1;

        let first = builder
            .materialize(&message(), &AtomicBool::new(false))
            .unwrap();
        assert!(first.sent_created);
        assert!(first.sent_shard_reservation.is_some());
        assert_eq!(first.sent_subdirectory, 1);
        let first_sent_path = first.sent_path.clone();
        drop(first);
        assert!(first_sent_path.is_file());

        let mut retry = message();
        retry.task_id = 43;
        retry.message_id = "<stable-43@example.test>".into();
        let second = builder
            .materialize(&retry, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(second.sent_subdirectory, 2);
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
            domain_policies: Arc::new(HashMap::new()),
            quarantine_cursor: Arc::new(Mutex::new(QuarantineSweepCursor::default())),
            sent_shard_allocator: Arc::default(),
            publication_instance: [0x22; 16],
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
    fn mime_headers_select_unsubscribe_policy_by_sender_domain_with_fallback() {
        let mut policies = HashMap::new();
        policies.insert(
            "secondary.test".into(),
            MessagePolicy {
                list_unsubscribe_mailto: Some("secondary-list@example.test".into()),
                list_unsubscribe_url: Some("https://secondary.example.test/unsubscribe".into()),
                dkim_signer: None,
            },
        );
        let builder = OutboundMessageBuilder {
            maildir: PathBuf::from("/mail"),
            spool_dir: PathBuf::from("/spool"),
            max_files_per_directory: 10,
            max_email_size: 1024 * 1024,
            list_unsubscribe_mailto: Some("primary-list@example.test".into()),
            list_unsubscribe_url: Some("https://example.test/unsubscribe".into()),
            dkim_signer: None,
            domain_policies: Arc::new(policies),
            quarantine_cursor: Arc::new(Mutex::new(QuarantineSweepCursor::default())),
            sent_shard_allocator: Arc::default(),
            publication_instance: [0x22; 16],
        };
        let mut secondary = message();
        secondary.sender = "qa@SECONDARY.TEST".into();
        let mut secondary_wire = Vec::new();
        builder
            .write_message(&secondary, &mut secondary_wire, &AtomicBool::new(false))
            .unwrap();
        let secondary_text = String::from_utf8(secondary_wire).unwrap();
        assert!(secondary_text.contains(
            "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\nList-Unsubscribe: <https://secondary.example.test/unsubscribe>, <mailto:secondary-list@example.test>\r\n"
        ));
        assert!(!secondary_text.contains("primary-list@example.test"));

        let mut unknown = message();
        unknown.sender = "qa@unknown.test".into();
        let mut unknown_wire = Vec::new();
        builder
            .write_message(&unknown, &mut unknown_wire, &AtomicBool::new(false))
            .unwrap();
        let unknown_text = String::from_utf8(unknown_wire).unwrap();
        assert!(unknown_text.contains(
            "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\nList-Unsubscribe: <https://example.test/unsubscribe>, <mailto:primary-list@example.test>\r\n"
        ));
    }

    #[test]
    fn streamed_attachment_base64_has_line_breaks_only_between_lines() {
        let directory = TestDirectory::new();
        let path = directory.0.join("attachment.bin");
        let payload = vec![b'a'; 58];
        fs::write(&path, &payload).unwrap();
        let attachment = MessageAttachment {
            filename: "attachment.bin".into(),
            content_type: "application/octet-stream".into(),
            content_base64: String::new(),
            content_length: Some(payload.len() as u64),
            source_path: Some(path),
            inline: false,
            content_id: None,
        };

        let mut output = Vec::new();
        write_attachment_content(&mut output, &attachment).unwrap();
        let expected = format!(
            "{}\r\n{}",
            BASE64_STANDARD.encode(&payload[..57]),
            BASE64_STANDARD.encode(&payload[57..])
        );
        assert_eq!(output, expected.as_bytes());
    }

    #[test]
    fn deterministic_boundary_matches_frozen_mime4j_wire_length() {
        let value = boundary("<stable@example.test>", "mixed");
        assert_eq!(value.len(), 56);
        assert!(value.starts_with("-=Part.0."));
        assert!(value.ends_with("=-"));
        assert_eq!(value, boundary("<stable@example.test>", "mixed"));
        assert_ne!(value, boundary("<stable@example.test>", "related"));
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
    fn streamed_text_matches_in_memory_mime_and_remains_caller_owned() {
        let root = TestDirectory::new();
        let path = root.0.join("stress-body.txt");
        let body = format!("{}\u{754c}\r\nend\n", "a".repeat(COPY_BUFFER_BYTES - 1));
        fs::write(&path, body.as_bytes()).unwrap();
        let builder = system_builder(&root.0, None);
        let cancelled = AtomicBool::new(false);

        let mut in_memory = message();
        in_memory.html = None;
        in_memory.attachments.clear();
        in_memory.text = Some(body.clone());
        let mut expected = Vec::new();
        builder
            .write_message(&in_memory, &mut expected, &cancelled)
            .unwrap();

        let mut streamed = message();
        streamed.html = None;
        streamed.attachments.clear();
        streamed.text = None;
        streamed.text_file = Some(MessageTextFile::new(path.clone(), body.len() as u64));
        let mut actual = Vec::new();
        builder
            .write_message(&streamed, &mut actual, &cancelled)
            .unwrap();
        assert_eq!(actual, expected);

        let mut materialized = builder.materialize(&streamed, &cancelled).unwrap();
        builder
            .materialize_persistence_text(&mut streamed, &cancelled)
            .unwrap();
        assert_eq!(streamed.text.as_deref(), Some(body.as_str()));
        assert!(streamed.text_file.is_none());
        assert!(path.is_file());
        builder.rollback_unpublished(&mut materialized).unwrap();
        assert!(path.is_file(), "outbound must not delete caller-owned text");
    }

    #[test]
    fn streamed_text_rejects_non_regular_changed_and_invalid_utf8_sources() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let cancelled = AtomicBool::new(false);
        let valid = root.0.join("valid.txt");
        fs::write(&valid, b"valid body").unwrap();

        let symlink_path = root.0.join("body-link.txt");
        symlink(&valid, &symlink_path).unwrap();
        let symlink_source = MessageTextFile::new(symlink_path, 10);
        assert!(
            write_quoted_printable_file(
                &symlink_source,
                builder.max_email_size,
                &mut Vec::new(),
                &cancelled,
            )
            .is_err()
        );

        let changed = MessageTextFile::new(valid, 9);
        assert!(matches!(
            write_quoted_printable_file(
                &changed,
                builder.max_email_size,
                &mut Vec::new(),
                &cancelled,
            ),
            Err(MessageBuildError::InvalidInput(
                "invalid_outbound_text_file"
            ))
        ));

        let invalid = root.0.join("invalid-utf8.txt");
        fs::write(&invalid, [b'a', 0xf0, 0x9f, 0x92]).unwrap();
        let invalid_source = MessageTextFile::new(invalid, 4);
        assert!(matches!(
            write_quoted_printable_file(
                &invalid_source,
                builder.max_email_size,
                &mut Vec::new(),
                &cancelled,
            ),
            Err(MessageBuildError::InvalidInput(
                "invalid_outbound_text_file"
            ))
        ));
    }

    #[test]
    fn streamed_text_size_drives_storage_mode_and_observes_cancellation() {
        let root = TestDirectory::new();
        let path = root.0.join("body.txt");
        fs::write(&path, b"body").unwrap();
        let mut input = message();
        input.text = None;
        input.html = None;
        input.attachments.clear();
        input.text_file = Some(MessageTextFile::new(path.clone(), 8_191));
        assert_eq!(java_estimated_message_size(&input).unwrap(), 10_239);
        assert_eq!(
            java_storage_mode_for_input(&input).unwrap(),
            MessageStorageMode::Inline
        );
        input.text_file = Some(MessageTextFile::new(path.clone(), 8_192));
        assert_eq!(java_estimated_message_size(&input).unwrap(), 10_240);
        assert_eq!(
            java_storage_mode_for_input(&input).unwrap(),
            MessageStorageMode::Spool
        );

        let cancelled = AtomicBool::new(true);
        let source = MessageTextFile::new(path, 4);
        assert!(matches!(
            write_quoted_printable_file(&source, 64 * 1024, &mut Vec::new(), &cancelled,),
            Err(MessageBuildError::Cancelled)
        ));
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
            domain_policies: Arc::new(HashMap::new()),
            quarantine_cursor: Arc::new(Mutex::new(QuarantineSweepCursor::default())),
            sent_shard_allocator: Arc::default(),
            publication_instance: [0x22; 16],
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
        let mut below = builder.materialize(&below, &cancelled).unwrap();
        assert!(below.signed_content_base64.is_some());
        builder.cleanup_small_spool(&mut below).unwrap();

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
            domain_policies: Arc::new(HashMap::new()),
            quarantine_cursor: Arc::new(Mutex::new(QuarantineSweepCursor::default())),
            sent_shard_allocator: Arc::default(),
            publication_instance: [0x22; 16],
        };
        let cancelled = AtomicBool::new(false);

        let mut small = message();
        small.html = None;
        small.attachments.clear();
        let mut small_message = builder.materialize(&small, &cancelled).unwrap();
        let expected_base64 = small_message.signed_content_base64.clone().unwrap();
        builder.cleanup_small_spool(&mut small_message).unwrap();
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

        // A pre-upgrade queue row still points at the same logical filename.
        // An existing new-layout directory must not hide its old encoded file.
        let old_parent = builder
            .maildir
            .join(v2_sanitize_address_for_path(&small.sender))
            .join("sent")
            .join(small_message.sent_subdirectory.to_string());
        fs::create_dir_all(&old_parent).unwrap();
        let old_path = old_parent.join(&small_message.sent_file_name);
        fs::rename(&small_message.sent_path, &old_path).unwrap();
        let old_recovered = builder
            .recover(
                small.task_id,
                &small.sender,
                &small_message.sent_file_name,
                small_message.sent_subdirectory,
                MessageStorageMode::Inline,
                &cancelled,
            )
            .unwrap();
        assert_eq!(old_recovered.sent_path, old_path);
        assert_eq!(
            old_recovered.signed_content_base64.as_deref(),
            Some(expected_base64.as_str())
        );

        let mut large = message();
        large.task_id = 43;
        large.message_id = "<large@example.test>".into();
        large.text = Some("z".repeat(12 * 1024));
        large.html = None;
        large.attachments.clear();
        let mut large_message = builder.materialize(&large, &cancelled).unwrap();
        assert!(large_message.signed_content_base64.is_none());
        large_message
            .spool_ownership
            .take()
            .unwrap()
            .remove_if_still_owned()
            .unwrap();
        large_message.spool_created = false;
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
        let sent = PublishedFileOwnership::bind_existing(&recovered_large.sent_path).unwrap();
        let spool = PublishedFileOwnership::bind_existing(&recovered_large.spool_path).unwrap();
        assert_eq!(
            sent.content_proof().unwrap(),
            spool.content_proof().unwrap()
        );
    }

    #[test]
    fn recovery_rejects_oversize_sent_before_creating_a_spool() {
        let root = TestDirectory::new();
        let mut builder = system_builder(&root.0, None);
        builder.max_email_size = 1_024;
        let sent_root =
            secure_child_directory(&builder.maildir, "qa@example.test", "sent").unwrap();
        let sent_dir = secure_numeric_directory(&sent_root, 1).unwrap();
        fs::write(sent_dir.join("oversize.eml"), vec![b'x'; 1_025]).unwrap();

        let failure = builder
            .recover(
                44,
                "qa@example.test",
                "oversize.eml",
                1,
                MessageStorageMode::Inline,
                &AtomicBool::new(false),
            )
            .unwrap_err();
        assert!(matches!(
            failure,
            MessageBuildError::Io(ref error) if error.kind() == io::ErrorKind::FileTooLarge
        ));
        assert!(!builder.spool_dir.exists());
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
            content_length: None,
            source_path: None,
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
            domain_policies: Arc::new(HashMap::new()),
            quarantine_cursor: Arc::new(Mutex::new(QuarantineSweepCursor::default())),
            sent_shard_allocator: Arc::default(),
            publication_instance: [0x22; 16],
        };
        fs::create_dir_all(&builder.spool_dir).unwrap();
        fs::write(builder.spool_dir.join("message-42.eml"), b"stale message").unwrap();
        let error = builder
            .materialize(&message(), &AtomicBool::new(false))
            .unwrap_err();
        assert!(matches!(error, MessageBuildError::Io(_)));
    }

    #[test]
    fn post_link_failure_removes_the_published_destination() {
        let root = TestDirectory::new();
        let temporary = root.0.join("message.tmp");
        let destination = root.0.join("message.eml");
        fs::write(&temporary, b"message").unwrap();
        let _fault = TestFaultGuard::inject("publish_after_link");
        let temporary = PublishedFileOwnership::bind_existing(&temporary).unwrap();
        assert!(publish_temp_file(temporary, &destination, None).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn ownership_cleanup_refuses_a_concurrently_replaced_destination() {
        let root = TestDirectory::new();
        let temporary = root.0.join("message.tmp");
        let destination = root.0.join("message.eml");
        let displaced = root.0.join("message.displaced");
        fs::write(&temporary, b"owned").unwrap();
        let temporary = PublishedFileOwnership::bind_existing(&temporary).unwrap();
        let ownership = publish_temp_file(temporary, &destination, None).unwrap();

        fs::rename(&destination, &displaced).unwrap();
        fs::write(&destination, b"replacement").unwrap();
        assert!(ownership.remove_if_still_owned().is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
        assert_eq!(fs::read(&displaced).unwrap(), b"owned");
    }

    #[test]
    fn ownership_quarantine_never_deletes_a_late_original_path_replacement() {
        let root = TestDirectory::new();
        let temporary_path = root.0.join("message.tmp");
        let destination = root.0.join("message.eml");
        fs::write(&temporary_path, b"owned").unwrap();
        let temporary = PublishedFileOwnership::bind_existing(&temporary_path).unwrap();
        let ownership = publish_temp_file(temporary, &destination, None).unwrap();
        let replacement_path = destination.clone();
        let _hook = TestHookGuard::install("ownership_after_quarantine", move || {
            fs::write(replacement_path, b"replacement").unwrap();
        });

        ownership.remove_if_still_owned().unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
    }

    #[test]
    fn ownership_cleanup_uses_bound_parent_after_path_parent_is_replaced() {
        let root = TestDirectory::new();
        let parent = root.0.join("parent");
        let moved_parent = root.0.join("moved-parent");
        fs::create_dir(&parent).unwrap();
        let temporary_path = parent.join("message.tmp");
        let destination = parent.join("message.eml");
        fs::write(&temporary_path, b"owned").unwrap();
        let temporary = PublishedFileOwnership::bind_existing(&temporary_path).unwrap();
        let ownership = publish_temp_file(temporary, &destination, None).unwrap();

        fs::rename(&parent, &moved_parent).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(parent.join("message.eml"), b"replacement").unwrap();
        ownership.remove_if_still_owned().unwrap();

        assert_eq!(
            fs::read(parent.join("message.eml")).unwrap(),
            b"replacement"
        );
        assert!(!moved_parent.join("message.eml").exists());
    }

    #[test]
    fn publish_verification_failure_preserves_the_replacement() {
        let root = TestDirectory::new();
        let temporary_path = root.0.join("message.tmp");
        let destination = root.0.join("message.eml");
        let displaced = root.0.join("message.displaced");
        fs::write(&temporary_path, b"owned").unwrap();
        let hook_destination = destination.clone();
        let hook_displaced = displaced.clone();
        let _hook = TestHookGuard::install("publish_after_link_before_verify", move || {
            fs::rename(&hook_destination, &hook_displaced).unwrap();
            fs::write(&hook_destination, b"replacement").unwrap();
        });
        let temporary = PublishedFileOwnership::bind_existing(&temporary_path).unwrap();

        assert!(publish_temp_file(temporary, &destination, None).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
        assert_eq!(fs::read(&displaced).unwrap(), b"owned");
    }

    #[test]
    fn temporary_cleanup_refuses_a_replaced_random_temporary() {
        let root = TestDirectory::new();
        let (file, ownership) = create_owned_temporary(&root.0, "race").unwrap();
        let temporary_path = ownership.path.clone();
        let displaced = root.0.join("temporary.displaced");
        drop(file);
        fs::write(&temporary_path, b"owned temporary").unwrap();
        fs::rename(&temporary_path, &displaced).unwrap();
        fs::write(&temporary_path, b"replacement temporary").unwrap();

        assert!(ownership.remove_if_still_owned().is_err());
        assert_eq!(fs::read(&temporary_path).unwrap(), b"replacement temporary");
        assert_eq!(fs::read(&displaced).unwrap(), b"owned temporary");
    }

    #[test]
    fn temporary_initialization_faults_remove_the_created_inode() {
        for fault in ["temporary_fstat", "temporary_clone"] {
            let root = TestDirectory::new();
            let _fault = TestFaultGuard::inject(fault);
            assert!(create_owned_temporary(&root.0, "fault").is_err());
            assert_eq!(regular_file_count(&root.0), 0, "fault={fault}");
        }
    }

    #[test]
    fn restart_sweep_recovers_every_pre_writer_crash_cutpoint() {
        for cutpoint in [
            "temporary_stage_created",
            "temporary_stage_quarantined",
            "ownership_receipt_stage_created",
            "ownership_receipt_stage_synced",
            "temporary_receipt_created",
            "temporary_receipt_durable",
            "temporary_moved_to_parent",
        ] {
            let root = TestDirectory::new();
            let hook = TestHookGuard::install(cutpoint, || panic!("simulated process crash"));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = create_owned_temporary(&root.0, "crash");
            }));
            drop(hook);
            assert!(result.is_err(), "cutpoint={cutpoint}");
            assert!(regular_file_count(&root.0) > 0, "cutpoint={cutpoint}");
            sweep_test_root_to_quiescence(&root.0);
        }
    }

    #[test]
    fn live_temporary_lease_blocks_restart_recovery_until_ownership_drops() {
        let root = TestDirectory::new();
        let (mut writer, ownership) = create_owned_temporary(&root.0, "live").unwrap();
        writer.write_all(b"still being written").unwrap();
        let temporary_path = ownership.path.clone();
        let receipt_path = root.0.join(".lmyzmail-quarantine").join(
            ownership_receipt_name(match &ownership.cleanup_state {
                PublishedFileCleanupState::PreparedReceipt {
                    quarantine_name, ..
                } => quarantine_name,
                _ => panic!("live temporary has no cleanup receipt"),
            })
            .unwrap(),
        );

        let mut cursor = QuarantineSweepCursor {
            roots: vec![root.0.clone()],
            ..QuarantineSweepCursor::default()
        };
        for _ in 0..8 {
            let _ = sweep_owned_quarantine_cursor(
                &mut cursor,
                64,
                64,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            );
        }
        assert_eq!(fs::read(&temporary_path).unwrap(), b"still being written");
        assert!(receipt_path.is_file());

        drop(writer);
        drop(ownership);
        assert!(!temporary_path.exists());
        assert!(!receipt_path.exists());
    }

    #[test]
    fn quarantine_parent_sync_failure_is_retried() {
        let root = TestDirectory::new();
        let parent = open_bound_directory(&root.0).unwrap();
        for _ in 0..2 {
            let fault = TestFaultGuard::inject("ownership_quarantine_parent_fsync");
            assert!(open_quarantine_directory(&parent).is_err());
            drop(fault);
        }

        assert!(open_quarantine_directory(&parent).is_ok());
    }

    #[test]
    fn staging_recovery_refuses_hardlinks_and_path_replacements() {
        let root = TestDirectory::new();
        let parent = open_bound_directory(&root.0).unwrap();
        let quarantine = open_quarantine_directory(&parent).unwrap();
        drop(quarantine);
        let quarantine_path = root.0.join(".lmyzmail-quarantine");

        let hardlinked = create_test_staging_file(&quarantine_path, b"hardlinked");
        let outside_link = root.0.join("outside-link");
        fs::hard_link(&hardlinked, &outside_link).unwrap();
        let mut hardlink_cursor = QuarantineSweepCursor {
            roots: vec![root.0.clone()],
            ..QuarantineSweepCursor::default()
        };
        assert!(
            sweep_owned_quarantine_cursor(
                &mut hardlink_cursor,
                64,
                64,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            )
            .is_err()
        );
        assert_eq!(fs::read(&hardlinked).unwrap(), b"hardlinked");
        assert_eq!(fs::read(&outside_link).unwrap(), b"hardlinked");
        fs::remove_file(&outside_link).unwrap();
        fs::remove_file(&hardlinked).unwrap();

        let replaced = create_test_staging_file(&quarantine_path, b"owned stage");
        let displaced = root.0.join("displaced-stage");
        let hook_path = replaced.clone();
        let hook_displaced = displaced.clone();
        let _hook = TestHookGuard::install("staging_before_unlink", move || {
            fs::rename(&hook_path, &hook_displaced).unwrap();
            fs::write(&hook_path, b"replacement stage").unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o600)).unwrap();
        });
        let mut replacement_cursor = QuarantineSweepCursor {
            roots: vec![root.0.clone()],
            ..QuarantineSweepCursor::default()
        };
        assert!(
            sweep_owned_quarantine_cursor(
                &mut replacement_cursor,
                64,
                64,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            )
            .is_err()
        );
        assert_eq!(fs::read(&replaced).unwrap(), b"replacement stage");
        assert_eq!(fs::read(&displaced).unwrap(), b"owned stage");
    }

    #[test]
    fn sweep_budget_never_retains_an_exclusive_staging_lease() {
        let root = TestDirectory::new();
        let parent = open_bound_directory(&root.0).unwrap();
        let quarantine = open_quarantine_directory(&parent).unwrap();
        let quarantine_path = root.0.join(".lmyzmail-quarantine");
        for index in 0..32 {
            create_test_staging_file(&quarantine_path, format!("stage-{index}").as_bytes());
        }

        let mut cursor = QuarantineSweepCursor {
            roots: vec![root.0.clone()],
            ..QuarantineSweepCursor::default()
        };
        let _ = sweep_owned_quarantine_cursor(
            &mut cursor,
            2,
            2,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        );
        assert!(acquire_staging_writer_lease(&quarantine).is_ok());
        sweep_test_root_to_quiescence(&root.0);
    }

    #[test]
    fn writer_waits_for_a_short_recovery_lease_without_false_failure() {
        let root = TestDirectory::new();
        let parent = open_bound_directory(&root.0).unwrap();
        let quarantine = open_quarantine_directory(&parent).unwrap();
        let recovery_lease = try_acquire_staging_recovery_lease(&quarantine)
            .unwrap()
            .expect("test owns the exclusive recovery lease");
        let writer_root = root.0.clone();
        let writer = std::thread::spawn(move || create_owned_temporary(&writer_root, "wait"));
        std::thread::sleep(Duration::from_millis(10));
        drop(recovery_lease);

        let (file, ownership) = writer.join().unwrap().unwrap();
        drop(file);
        drop(ownership);
        assert_eq!(regular_file_count(&root.0), 0);
    }

    #[test]
    fn staging_directory_sync_does_not_hold_the_recovery_lease() {
        let root = TestDirectory::new();
        let parent = open_bound_directory(&root.0).unwrap();
        let quarantine = open_quarantine_directory(&parent).unwrap();
        drop(quarantine);
        let quarantine_path = root.0.join(".lmyzmail-quarantine");
        create_test_staging_file(&quarantine_path, b"prior-instance-stage");

        let (reached_sender, reached_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let sweep_root = root.0.clone();
        let sweeper = std::thread::spawn(move || {
            let _hook = TestHookGuard::install("staging_after_recovery_lease", move || {
                reached_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
            });
            let mut cursor = QuarantineSweepCursor {
                roots: vec![sweep_root],
                ..QuarantineSweepCursor::default()
            };
            sweep_owned_quarantine_cursor(
                &mut cursor,
                4,
                4,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            )
        });

        reached_receiver.recv().unwrap();
        let (writer, ownership) = create_owned_temporary(&root.0, "admission").unwrap();
        drop(writer);
        drop(ownership);
        release_sender.send(()).unwrap();
        sweeper.join().unwrap().unwrap();
        sweep_test_root_to_quiescence(&root.0);
    }

    #[test]
    fn large_staging_sweep_allows_concurrent_temporary_admission() {
        let root = TestDirectory::new();
        let parent = open_bound_directory(&root.0).unwrap();
        let quarantine = open_quarantine_directory(&parent).unwrap();
        drop(quarantine);
        let quarantine_path = root.0.join(".lmyzmail-quarantine");
        for index in 0..512 {
            create_test_staging_file(
                &quarantine_path,
                format!("prior-instance-stage-{index}").as_bytes(),
            );
        }

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let sweep_root = root.0.clone();
        let sweep_barrier = Arc::clone(&barrier);
        let sweeper = std::thread::spawn(move || {
            let mut cursor = QuarantineSweepCursor {
                roots: vec![sweep_root],
                ..QuarantineSweepCursor::default()
            };
            sweep_barrier.wait();
            for _ in 0..512 {
                let _ = sweep_owned_quarantine_cursor(
                    &mut cursor,
                    4,
                    4,
                    Instant::now() + Duration::from_secs(1),
                    &AtomicBool::new(false),
                );
            }
        });

        barrier.wait();
        for index in 0..32 {
            let (mut writer, ownership) = create_owned_temporary(&root.0, "admission").unwrap();
            writer
                .write_all(format!("live-writer-{index}").as_bytes())
                .unwrap();
            drop(writer);
            drop(ownership);
        }
        sweeper.join().unwrap();
        sweep_test_root_to_quiescence(&root.0);
    }

    #[test]
    fn temporary_writer_is_not_exposed_before_its_cleanup_receipt_is_durable() {
        for kind in ["unsigned", "signed", "system", "copy"] {
            let root = TestDirectory::new();
            let (mut file, ownership) = create_owned_temporary(&root.0, kind).unwrap();
            let PublishedFileCleanupState::PreparedReceipt {
                receipt_name,
                receipt_directory_synced,
                ..
            } = &ownership.cleanup_state
            else {
                panic!("temporary {kind} has no durable cleanup intent")
            };
            assert!(*receipt_directory_synced, "kind={kind}");
            assert!(
                root.0
                    .join(".lmyzmail-quarantine")
                    .join(receipt_name)
                    .is_file(),
                "kind={kind}"
            );
            file.write_all(b"owned temporary").unwrap();
            drop(file);
            drop(ownership);
            assert_eq!(regular_file_count(&root.0), 0, "kind={kind}");
        }
    }

    #[test]
    fn temporary_guards_cleanup_during_panic_unwind() {
        for kind in ["unsigned", "signed", "copy"] {
            let root = TestDirectory::new();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (mut file, ownership) = create_owned_temporary(&root.0, kind).unwrap();
                file.write_all(b"panic-owned temporary").unwrap();
                let _ownership = ownership;
                panic!("injected temporary writer panic");
            }));
            assert!(result.is_err(), "kind={kind}");
            assert_eq!(regular_file_count(&root.0), 0, "kind={kind}");
        }
    }

    #[test]
    fn dropped_result_receiver_drops_and_cleans_the_owned_temporary() {
        let root = TestDirectory::new();
        let (file, ownership) = create_owned_temporary(&root.0, "copy").unwrap();
        drop(file);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        drop(receiver);
        assert!(sender.send(ownership).is_err());
        assert_eq!(regular_file_count(&root.0), 0);
    }

    #[test]
    fn publication_ownership_drop_preserves_file_and_durable_proof() {
        let root = TestDirectory::new();
        let destination = root.0.join("message-41.eml");
        let (mut file, temporary) = create_owned_temporary(&root.0, "unsigned").unwrap();
        file.write_all(b"committed or outcome-unknown message")
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
        let ownership = publish_temp_file(
            temporary,
            &destination,
            Some(PublicationIntent::spool(41, [0x41; 16])),
        )
        .unwrap();
        let receipt = root
            .0
            .join(".lmyzmail-quarantine")
            .join(publication_receipt_name(41, PublicationKind::Spool).unwrap());
        assert!(destination.is_file());
        assert!(receipt.is_file());

        drop(ownership);

        assert_eq!(
            fs::read(&destination).unwrap(),
            b"committed or outcome-unknown message"
        );
        assert!(receipt.is_file());
    }

    #[test]
    fn small_spool_sent_verification_fails_closed_for_missing_or_replaced_sent() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let materialized = builder
            .materialize(&message(), &AtomicBool::new(false))
            .unwrap();
        assert!(materialized.cleanup_spool_after_publish);
        let spool = materialized.spool_ownership.as_ref().unwrap();
        let (size, sha256) = spool.content_proof().unwrap();
        let intent = PendingPublicationIntent {
            task_id: 42,
            kind: PendingPublicationKind::Spool,
            original_path: materialized.spool_path.clone(),
            quarantine_directory: builder.spool_dir.join(".lmyzmail-quarantine"),
            receipt_name: publication_receipt_name(42, PublicationKind::Spool).unwrap(),
            device: spool.device,
            inode: spool.inode,
            size,
            sha256,
            instance_id: builder.publication_instance,
        };
        builder
            .verify_committed_sent_for_spool_intent(
                &intent,
                "qa@example.test",
                &materialized.sent_file_name,
                materialized.sent_subdirectory,
            )
            .unwrap();

        let displaced = root.0.join("sent.displaced");
        fs::rename(&materialized.sent_path, &displaced).unwrap();
        assert!(
            builder
                .verify_committed_sent_for_spool_intent(
                    &intent,
                    "qa@example.test",
                    &materialized.sent_file_name,
                    materialized.sent_subdirectory,
                )
                .is_err()
        );
        assert!(materialized.spool_path.is_file());

        let mut replacement = fs::read(&displaced).unwrap();
        replacement[0] ^= 1;
        fs::write(&materialized.sent_path, replacement).unwrap();
        assert!(
            builder
                .verify_committed_sent_for_spool_intent(
                    &intent,
                    "qa@example.test",
                    &materialized.sent_file_name,
                    materialized.sent_subdirectory,
                )
                .is_err()
        );
        assert!(materialized.spool_path.is_file());
    }

    #[test]
    fn materialize_cleanup_failure_is_explicitly_rollback_unknown() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let sent = secure_child_directory(&builder.maildir, "qa@example.test", "sent").unwrap();
        fs::write(sent.join("1"), b"not a directory").unwrap();
        let _fault = TestFaultGuard::inject("materialize_cleanup");

        let error = builder
            .materialize(&message(), &AtomicBool::new(false))
            .unwrap_err();
        assert!(error.rollback_is_unknown());
    }

    #[test]
    fn sender_paths_are_encoded_before_any_directory_creation() {
        let root = TestDirectory::new();
        let maildir = root.0.join("maildir");
        let outside = root.0.join("outside-must-not-be-created");
        let absolute_sender = format!("{}/user@example.test", outside.display());

        let sent = secure_child_directory(&maildir, &absolute_sender, "sent").unwrap();
        assert!(sent.starts_with(fs::canonicalize(&maildir).unwrap()));
        assert!(!outside.exists());
        assert!(
            maildir
                .join(sanitize_address_for_path(&absolute_sender))
                .join("sent")
                .is_dir()
        );

        let dotted = secure_child_directory(&maildir, "foo/./bar@example.test", "sent").unwrap();
        let doubled = secure_child_directory(&maildir, "foo//bar@example.test", "sent").unwrap();
        assert_ne!(dotted, doubled);
        assert!(dotted.is_dir());
        assert!(doubled.is_dir());
    }

    #[test]
    fn slash_sender_materialize_visibility_and_cleanup_share_one_mapping() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let mut input = message();
        input.sender = "foo/./bar@example.test".into();
        let mut materialized = builder
            .materialize(&input, &AtomicBool::new(false))
            .unwrap();
        let mailbox_root = builder
            .maildir
            .join(sanitize_address_for_path(&input.sender));

        assert!(
            materialized
                .sent_path
                .starts_with(mailbox_root.join("sent"))
        );
        assert!(materialized.sent_path.is_file());
        builder.cleanup_small_spool(&mut materialized).unwrap();
        assert!(!materialized.spool_path.exists());
        builder.rollback_sent(&mut materialized).unwrap();
        assert!(!materialized.sent_path.exists());
    }

    #[test]
    fn ownership_cleanup_preserves_symlink_and_missing_replacements() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let temporary_path = root.0.join("message.tmp");
        let destination = root.0.join("message.eml");
        let displaced = root.0.join("message.displaced");
        let target = root.0.join("target.eml");
        fs::write(&temporary_path, b"owned").unwrap();
        fs::write(&target, b"target").unwrap();
        let temporary = PublishedFileOwnership::bind_existing(&temporary_path).unwrap();
        let ownership = publish_temp_file(temporary, &destination, None).unwrap();
        fs::rename(&destination, &displaced).unwrap();
        symlink(&target, &destination).unwrap();

        assert!(ownership.remove_if_still_owned().is_err());
        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"target");
        assert_eq!(fs::read(&displaced).unwrap(), b"owned");

        let missing = PublishedFileOwnership::bind_existing(&displaced).unwrap();
        fs::remove_file(&displaced).unwrap();
        assert!(missing.remove_if_still_owned().is_err());
        assert_eq!(fs::read(&target).unwrap(), b"target");
    }

    #[test]
    fn restore_conflict_retains_the_quarantined_replacement() {
        let root = TestDirectory::new();
        let temporary_path = root.0.join("message.tmp");
        let destination = root.0.join("message.eml");
        let displaced = root.0.join("message.displaced");
        fs::write(&temporary_path, b"owned").unwrap();
        let temporary = PublishedFileOwnership::bind_existing(&temporary_path).unwrap();
        let ownership = publish_temp_file(temporary, &destination, None).unwrap();
        fs::rename(&destination, &displaced).unwrap();
        fs::write(&destination, b"first replacement").unwrap();
        let hook_destination = destination.clone();
        let _hook = TestHookGuard::install("ownership_after_quarantine", move || {
            fs::write(hook_destination, b"second replacement").unwrap();
        });

        let error = ownership.remove_if_still_owned().unwrap_err();
        assert!(error.to_string().contains("retained quarantine"));
        assert_eq!(fs::read(&destination).unwrap(), b"second replacement");
        let quarantine = root.0.join(".lmyzmail-quarantine");
        let retained = fs::read_dir(quarantine)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(parse_ownership_quarantine_name)
                    .is_some()
            })
            .unwrap();
        assert_eq!(fs::read(&retained).unwrap(), b"first replacement");
        let mut cursor = QuarantineSweepCursor {
            roots: vec![root.0.clone()],
            ..QuarantineSweepCursor::default()
        };
        let error = sweep_owned_quarantine_cursor(
            &mut cursor,
            32,
            32,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&retained).unwrap(), b"first replacement");
        assert_eq!(fs::read(&destination).unwrap(), b"second replacement");
        assert_eq!(fs::read(displaced).unwrap(), b"owned");
    }

    #[test]
    fn rollback_and_small_cleanup_preserve_replacements_and_are_idempotent() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let cancelled = AtomicBool::new(false);
        let mut materialized = builder.materialize(&message(), &cancelled).unwrap();
        let sent_displaced = root.0.join("sent.displaced");
        let spool_displaced = root.0.join("spool.displaced");
        fs::rename(&materialized.sent_path, &sent_displaced).unwrap();
        fs::rename(&materialized.spool_path, &spool_displaced).unwrap();
        fs::write(&materialized.sent_path, b"sent replacement").unwrap();
        fs::write(&materialized.spool_path, b"spool replacement").unwrap();

        assert!(builder.rollback_unpublished(&mut materialized).is_err());
        assert_eq!(
            fs::read(&materialized.sent_path).unwrap(),
            b"sent replacement"
        );
        assert_eq!(
            fs::read(&materialized.spool_path).unwrap(),
            b"spool replacement"
        );
        assert!(sent_displaced.is_file());
        assert!(spool_displaced.is_file());
        builder.rollback_unpublished(&mut materialized).unwrap();

        let mut inline_input = message();
        inline_input.task_id = 43;
        inline_input.message_id = "<replacement-43@example.test>".into();
        let mut inline = builder.materialize(&inline_input, &cancelled).unwrap();
        let inline_displaced = root.0.join("inline.displaced");
        fs::rename(&inline.spool_path, &inline_displaced).unwrap();
        fs::write(&inline.spool_path, b"inline replacement").unwrap();
        assert!(builder.cleanup_small_spool(&mut inline).is_err());
        assert_eq!(fs::read(&inline.spool_path).unwrap(), b"inline replacement");
        assert!(inline_displaced.is_file());
        builder.cleanup_small_spool(&mut inline).unwrap();
    }

    #[test]
    fn unlink_then_sync_failure_retries_from_the_quarantine_token() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let mut materialized = builder
            .materialize(&message(), &AtomicBool::new(false))
            .unwrap();
        {
            let _fault = TestFaultGuard::inject("ownership_after_unlink");
            assert!(builder.cleanup_small_spool(&mut materialized).is_err());
        }
        assert!(!materialized.spool_path.exists());
        builder.cleanup_small_spool(&mut materialized).unwrap();
    }

    #[test]
    fn quarantine_unlink_failure_keeps_an_updated_retryable_token() {
        let root = TestDirectory::new();
        let path = root.0.join("message.eml");
        fs::write(&path, b"owned").unwrap();
        let mut ownership = PublishedFileOwnership::bind_existing(&path).unwrap();
        let expected_device = ownership.device;
        let expected_inode = ownership.inode;

        {
            let _fault = TestFaultGuard::inject("ownership_unlinkat");
            assert!(ownership.try_remove_if_still_owned().is_err());
        }
        assert!(!path.exists());
        assert!(
            ownership
                .path
                .starts_with(root.0.join(".lmyzmail-quarantine"))
        );
        assert_eq!(ownership.device, expected_device);
        assert_eq!(ownership.inode, expected_inode);
        assert!(matches!(
            ownership.cleanup_state,
            PublishedFileCleanupState::Quarantined { .. }
        ));
        assert!(ownership.path.is_file());

        ownership.try_remove_if_still_owned().unwrap();
        assert!(!ownership.path.exists());
        assert!(matches!(
            ownership.cleanup_state,
            PublishedFileCleanupState::Removed
        ));
    }

    #[test]
    fn original_parent_sync_failure_is_idempotently_retryable() {
        let root = TestDirectory::new();
        let path = root.0.join("message.eml");
        fs::write(&path, b"owned").unwrap();
        let mut ownership = PublishedFileOwnership::bind_existing(&path).unwrap();

        {
            let _fault = TestFaultGuard::inject("ownership_rename_parent_fsync");
            assert!(ownership.try_remove_if_still_owned().is_err());
        }
        assert!(!path.exists());
        assert!(matches!(
            ownership.cleanup_state,
            PublishedFileCleanupState::Quarantined { .. }
        ));

        ownership.try_remove_if_still_owned().unwrap();
        assert!(matches!(
            ownership.cleanup_state,
            PublishedFileCleanupState::Removed
        ));
    }

    #[test]
    fn durable_quarantine_sweep_recovers_cleanup_without_a_database_row() {
        let root = TestDirectory::new();
        let path = root.0.join("message.eml");
        fs::write(&path, b"owned").unwrap();
        let mut ownership = PublishedFileOwnership::bind_existing(&path).unwrap();
        {
            let _fault = TestFaultGuard::inject("ownership_unlinkat");
            assert!(ownership.try_remove_if_still_owned().is_err());
        }
        let quarantined_path = ownership.path.clone();
        std::mem::forget(ownership);
        assert!(quarantined_path.is_file());

        let mut cursor = QuarantineSweepCursor {
            roots: vec![root.0.clone()],
            ..QuarantineSweepCursor::default()
        };
        assert_eq!(
            sweep_owned_quarantine_cursor(
                &mut cursor,
                32,
                32,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            )
            .unwrap(),
            1
        );
        assert!(!quarantined_path.exists());
    }

    #[test]
    fn quarantine_cursor_reaches_late_entries_past_a_permanent_prefix_item() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = TestDirectory::new();
        let early_parent = root.0.join("00-early");
        let early_quarantine = early_parent.join(".lmyzmail-quarantine");
        fs::create_dir_all(&early_quarantine).unwrap();
        fs::set_permissions(&early_quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        let identity_source = early_parent.join("identity-source");
        fs::write(&identity_source, b"different inode").unwrap();
        let identity = identity_source.metadata().unwrap();
        let retained = early_quarantine.join(format!(
            ".lmyzmail-owned-{:016x}-{:016x}-{}.tmp",
            identity.dev(),
            identity.ino(),
            "02".repeat(16)
        ));
        fs::write(&retained, b"must remain").unwrap();

        for index in 1..20 {
            fs::create_dir_all(root.0.join(format!("{index:02}-middle"))).unwrap();
        }
        let late_parent = root.0.join("99-late");
        fs::create_dir_all(&late_parent).unwrap();
        let late_path = late_parent.join("message.eml");
        fs::write(&late_path, b"owned late entry").unwrap();
        let mut ownership = PublishedFileOwnership::bind_existing(&late_path).unwrap();
        {
            let _fault = TestFaultGuard::inject("ownership_unlinkat");
            assert!(ownership.try_remove_if_still_owned().is_err());
        }
        let late_quarantine = ownership.path.clone();
        std::mem::forget(ownership);

        let mut cursor = QuarantineSweepCursor {
            roots: vec![root.0.clone()],
            ..QuarantineSweepCursor::default()
        };
        for _ in 0..256 {
            let _ = sweep_owned_quarantine_cursor(
                &mut cursor,
                2,
                1,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
            );
            if !late_quarantine.exists() {
                break;
            }
        }
        assert!(!late_quarantine.exists());
        assert_eq!(fs::read(retained).unwrap(), b"must remain");
    }

    #[test]
    fn task_receipt_adoption_bypasses_an_exhausted_scan_budget() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        fs::create_dir_all(&builder.spool_dir).unwrap();
        let sender = "qa@example.test";
        let sent_parent = builder
            .maildir
            .join(sanitize_address_for_path(sender))
            .join("sent/1");
        fs::create_dir_all(&sent_parent).unwrap();
        let sent_path = sent_parent.join("target.eml");
        fs::write(&sent_path, b"target publication").unwrap();
        let mut ownership = PublishedFileOwnership::bind_existing(&sent_path).unwrap();
        let (size, sha256) = ownership.content_proof().unwrap();
        ownership
            .prepare_publication_intent(
                PublicationIntent::sent(42, builder.publication_instance),
                size,
                sha256,
            )
            .unwrap();
        std::mem::forget(ownership);

        let mut cursor = builder.quarantine_cursor.lock().unwrap();
        for index in 0..MAX_PENDING_PUBLICATION_INTENTS {
            let task_id = 10_000 + index as i64;
            cursor
                .pending_publications
                .push_back(PendingPublicationIntent {
                    task_id,
                    kind: PendingPublicationKind::Spool,
                    original_path: root.0.join(format!("dummy-{task_id}")),
                    quarantine_directory: root.0.join("dummy-quarantine"),
                    receipt_name: publication_receipt_name(task_id, PublicationKind::Spool)
                        .unwrap(),
                    device: 1,
                    inode: task_id as u64,
                    size: 1,
                    sha256: [0x44; 32],
                    instance_id: [0x55; 16],
                });
        }
        drop(cursor);
        assert_eq!(
            builder
                .reconcile_owned_quarantines(&AtomicBool::new(false))
                .unwrap(),
            0
        );
        let adopted = builder
            .adopt_task_publication_intents(42, sender, 1)
            .unwrap();
        assert_eq!(adopted.len(), 1);
        assert_eq!(adopted[0].task_id, 42);
        assert_eq!(adopted[0].kind, PendingPublicationKind::Sent);
    }

    #[test]
    fn duplicate_v2_and_v1_task_receipts_fail_closed() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let sender = "qa@example.test";
        let parents = [
            builder
                .maildir
                .join(sanitize_address_for_path(sender))
                .join("sent/1"),
            builder
                .maildir
                .join(v1_sanitize_address_for_path(sender))
                .join("sent/1"),
        ];
        assert_ne!(parents[0], parents[1]);
        for (index, parent) in parents.iter().enumerate() {
            fs::create_dir_all(parent).unwrap();
            let path = parent.join(format!("duplicate-{index}.eml"));
            fs::write(&path, format!("duplicate publication {index}")).unwrap();
            let mut ownership = PublishedFileOwnership::bind_existing(&path).unwrap();
            let (size, sha256) = ownership.content_proof().unwrap();
            ownership
                .prepare_publication_intent(
                    PublicationIntent::sent(43, builder.publication_instance),
                    size,
                    sha256,
                )
                .unwrap();
            std::mem::forget(ownership);
        }
        assert!(
            builder
                .adopt_task_publication_intents(43, sender, 1)
                .is_err()
        );
        for parent in parents {
            assert!(
                parent
                    .join(".lmyzmail-quarantine")
                    .join(publication_receipt_name(43, PublicationKind::Sent).unwrap())
                    .is_file()
            );
        }
    }

    #[test]
    fn sent_atomic_copy_collision_preserves_the_incumbent() {
        let root = TestDirectory::new();
        let source = root.0.join("spool.eml");
        let destination = root.0.join("sent.eml");
        fs::write(&source, b"candidate").unwrap();
        fs::write(&destination, b"incumbent").unwrap();

        let source = PublishedFileOwnership::bind_existing(&source).unwrap();
        let error =
            atomic_copy(&source, &destination, 1024, &AtomicBool::new(false), None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&destination).unwrap(), b"incumbent");
    }

    #[test]
    fn build_failure_after_publish_removes_the_owned_spool() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let _fault = TestFaultGuard::inject("build_after_publish");
        assert!(
            builder
                .materialize(&message(), &AtomicBool::new(false))
                .is_err()
        );
        assert_eq!(regular_file_count(&builder.spool_dir), 0);
        assert_eq!(regular_file_count(&builder.maildir), 0);
    }

    #[test]
    fn inline_read_failure_removes_sent_and_spool_files() {
        let root = TestDirectory::new();
        let builder = system_builder(&root.0, None);
        let _fault = TestFaultGuard::inject("inline_read_after_sent_copy");
        assert!(
            builder
                .materialize(&message(), &AtomicBool::new(false))
                .is_err()
        );
        assert_eq!(regular_file_count(&builder.spool_dir), 0);
        assert_eq!(regular_file_count(&builder.maildir), 0);
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
            domain_policies: Arc::new(HashMap::new()),
            quarantine_cursor: Arc::new(Mutex::new(QuarantineSweepCursor::default())),
            sent_shard_allocator: Arc::default(),
            publication_instance: [0x22; 16],
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

    #[test]
    fn dropping_system_materialized_message_preserves_sent_shard_capacity() {
        let root = TestDirectory::new();
        let mut builder = system_builder(&root.0, None);
        builder.max_files_per_directory = 1;
        let bytes = system_message_bytes();
        let digest = system_digest(bytes);
        let created_at = Utc.with_ymd_and_hms(2026, 8, 6, 1, 2, 3).unwrap();
        let cancelled = AtomicBool::new(false);

        let first = builder
            .materialize_bytes(
                system_materialization(42, created_at, bytes, MessageStorageMode::Spool, &digest),
                &cancelled,
            )
            .unwrap();
        assert_eq!(first.sent_subdirectory, 1);
        assert!(first.sent_shard_reservation.is_some());
        let first_sent_path = first.sent_path.clone();
        drop(first);
        assert!(first_sent_path.is_file());

        let second = builder
            .materialize_bytes(
                system_materialization(43, created_at, bytes, MessageStorageMode::Spool, &digest),
                &cancelled,
            )
            .unwrap();
        assert_eq!(second.sent_subdirectory, 2);
    }

    fn generated_dkim_signer(root: &Path) -> RsaDkimSigner {
        generated_dkim_signer_for_domain(root, "example.test", "test")
    }

    fn generated_dkim_signer_for_domain(
        root: &Path,
        domain: &str,
        selector: &str,
    ) -> RsaDkimSigner {
        let key = openssl::rsa::Rsa::generate(2_048).unwrap();
        let key = PKey::from_rsa(key).unwrap();
        let path = root.join(format!("dkim-{domain}-{selector}.pem"));
        fs::write(&path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        load_dkim_signer(path.to_str().unwrap(), domain, selector).unwrap()
    }

    #[test]
    fn dkim_rsa_backend_matches_openssl_pkcs1v15_sha256_bytes() {
        let rsa = openssl::rsa::Rsa::generate(2_048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let private_key = pkey.private_key_to_pkcs8().unwrap();
        let key = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            private_key,
        )))
        .unwrap();
        let canonical = b"from:qa@example.test\r\nsubject:backend parity\r\n";

        let actual = key.sign(canonical.as_slice()).unwrap();
        let mut expected =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).unwrap();
        expected.update(canonical).unwrap();
        let expected = expected.sign_to_vec().unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn streaming_dkim_materializes_stress_sized_file_body() {
        let root = TestDirectory::new();
        let signer = Arc::new(generated_dkim_signer(&root.0));
        let builder = system_builder(&root.0, Some(signer));
        let body = root.0.join("stress-body.txt");
        let body_bytes = vec![b'x'; 10 * 1024];
        fs::write(&body, &body_bytes).unwrap();

        let mut input = message();
        input.html = None;
        input.attachments.clear();
        input.text = None;
        input.text_file = Some(MessageTextFile::new(body.clone(), body_bytes.len() as u64));
        let cancelled = AtomicBool::new(false);

        let mut materialized = builder.materialize(&input, &cancelled).unwrap();
        let wire = fs::read(&materialized.spool_path).unwrap();
        assert!(wire.starts_with(b"DKIM-Signature: "));
        builder.rollback_unpublished(&mut materialized).unwrap();
        assert_eq!(fs::read(body).unwrap(), body_bytes);
    }

    #[test]
    fn system_bytes_select_dkim_signer_by_sender_domain_with_primary_fallback() {
        let root = TestDirectory::new();
        let primary = Arc::new(generated_dkim_signer_for_domain(
            &root.0,
            "example.test",
            "primary",
        ));
        let secondary = Arc::new(generated_dkim_signer_for_domain(
            &root.0,
            "secondary.test",
            "secondary",
        ));
        let mut policies = HashMap::new();
        policies.insert(
            "secondary.test".into(),
            MessagePolicy {
                list_unsubscribe_mailto: None,
                list_unsubscribe_url: None,
                dkim_signer: Some(secondary),
            },
        );
        let builder = OutboundMessageBuilder {
            maildir: root.0.join("maildir"),
            spool_dir: root.0.join("spool"),
            max_files_per_directory: 10,
            max_email_size: 1024 * 1024,
            list_unsubscribe_mailto: None,
            list_unsubscribe_url: None,
            dkim_signer: Some(primary),
            domain_policies: Arc::new(policies),
            quarantine_cursor: Arc::new(Mutex::new(QuarantineSweepCursor::default())),
            sent_shard_allocator: Arc::default(),
            publication_instance: [0x22; 16],
        };
        let bytes = system_message_bytes();
        let digest = system_digest(bytes);
        let cancelled = AtomicBool::new(false);
        let secondary_bytes = builder
            .prepare_system_bytes_for_sender(
                "mailer-daemon@SECONDARY.TEST",
                Utc.with_ymd_and_hms(2026, 8, 6, 1, 2, 3).unwrap(),
                bytes,
                &digest,
                &cancelled,
            )
            .unwrap();
        let secondary_header = String::from_utf8_lossy(&secondary_bytes);
        assert!(secondary_header.starts_with("DKIM-Signature: "));
        assert!(secondary_header.contains("d=secondary.test"));
        assert!(secondary_header.contains("s=secondary"));

        let fallback_bytes = builder
            .prepare_system_bytes_for_sender(
                "mailer-daemon@unknown.test",
                Utc.with_ymd_and_hms(2026, 8, 6, 1, 2, 3).unwrap(),
                bytes,
                &digest,
                &cancelled,
            )
            .unwrap();
        let fallback_header = String::from_utf8_lossy(&fallback_bytes);
        assert!(fallback_header.contains("d=example.test"));
        assert!(fallback_header.contains("s=primary"));
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

        let mut spooled = builder
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
        builder.cleanup_small_spool(&mut spooled).unwrap();
        assert!(spooled.spool_path.is_file());

        let mut inline = builder
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
        builder.cleanup_small_spool(&mut inline).unwrap();
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
