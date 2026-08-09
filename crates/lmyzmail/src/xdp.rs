use std::{
    collections::{HashMap, HashSet},
    ffi::{CStr, CString},
    fmt,
    fs::File,
    io::{Seek, SeekFrom, Write},
    mem::{MaybeUninit, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use ipnet::IpNet;
use rustix::fs::{
    FlockOperation, MemfdFlags, Mode, OFlags, SealFlags, fcntl_add_seals, flock, memfd_create, open,
};
use serde::Serialize;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::{
    bounded_blocking::{BoundedBlockingPool, SubmitError},
    config::XdpConfig,
};

const XDP_VERSION: &str = "1.1.0";
const XDP_WORKERS: usize = 1;
const XDP_QUEUE_CAPACITY: usize = 64;
const XDP_OPERATION_DEADLINE: Duration = Duration::from_secs(8);
const XDP_INITIALIZATION_DEADLINE: Duration = Duration::from_secs(30);
const MAX_BANNED_IPS_PER_FAMILY: usize = 100_000;
const MAX_BANNED_IPS: usize = MAX_BANNED_IPS_PER_FAMILY * 2;
const MAX_PER_IP_STATS: usize = 100_000;
const XDP_LOCK_DIRECTORY: &str = "/run/lmyzmail";
const EMBEDDED_BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xdp_firewall.bpf.o"));

static NATIVE_OWNER: AtomicBool = AtomicBool::new(false);

struct NativeOwnerGuard<'a> {
    owner: &'a AtomicBool,
    armed: bool,
}

impl<'a> NativeOwnerGuard<'a> {
    fn acquire(owner: &'a AtomicBool) -> Result<Self, XdpError> {
        owner
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| XdpError::Native {
                code: ffi::ERR_ALREADY,
                message: "XDP native singleton is already initialized".into(),
            })?;
        Ok(Self { owner, armed: true })
    }

    fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for NativeOwnerGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.owner.store(false, Ordering::Release);
        }
    }
}

#[derive(Debug)]
pub enum XdpError {
    Cancelled,
    Timeout,
    Busy,
    Closed,
    InvalidInput(String),
    Io(std::io::Error),
    Native { code: i32, message: String },
}

impl fmt::Display for XdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("XDP operation cancelled"),
            Self::Timeout => formatter.write_str("XDP operation deadline exceeded"),
            Self::Busy => formatter.write_str("XDP operation queue is full"),
            Self::Closed => formatter.write_str("XDP operation worker is closed"),
            Self::InvalidInput(message) => write!(formatter, "invalid XDP input: {message}"),
            Self::Io(error) => write!(formatter, "XDP I/O failed: {error}"),
            Self::Native { code, message } => {
                write!(formatter, "XDP native operation failed ({code}): {message}")
            }
        }
    }
}

impl std::error::Error for XdpError {}

impl From<std::io::Error> for XdpError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rustix::io::Errno> for XdpError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XdpStats {
    pub packets_passed: u64,
    pub packets_dropped: u64,
    pub packets_total: u64,
    pub packets_syn: u64,
    pub packets_whitelisted: u64,
    pub banned_ips_count: u32,
    pub banned_ips_v6_count: u32,
    pub whitelist_count: u32,
    pub whitelist_v6_count: u32,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XdpPpsStats {
    pub pps: u64,
    pub syn_pps: u64,
    pub dropped_pps: u64,
    pub passed_pps: u64,
    pub timestamp_ns: u64,
    pub interval_ns: u64,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct XdpPerIpStats {
    pub packets: u64,
    pub syn_packets: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct XdpIpStatsEntry {
    pub ip: IpAddr,
    pub stats: XdpPerIpStats,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XdpStatus {
    pub ready: bool,
    pub version: &'static str,
    pub banned_count: usize,
    pub packets_passed: u64,
    pub packets_dropped: u64,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub(crate) struct XdpReconcileCounts {
    pub banned: usize,
    pub unbanned: usize,
    pub unchanged: usize,
    pub skipped_whitelist: usize,
    pub unbanned_whitelist: usize,
    pub unbanned_score: usize,
    pub unchanged_high: usize,
    pub unchanged_mid: usize,
}

struct SharedState {
    native: Mutex<NativeState>,
    ready: AtomicBool,
    last_error: Mutex<Option<String>>,
}

pub struct XdpService {
    config: XdpConfig,
    shared: Arc<SharedState>,
    pool: BoundedBlockingPool,
}

impl XdpService {
    pub fn from_config(config: &XdpConfig) -> Result<Self, XdpError> {
        Ok(Self {
            config: config.clone(),
            shared: Arc::new(SharedState {
                native: Mutex::new(NativeState::new(config.whitelist.clone())),
                ready: AtomicBool::new(false),
                last_error: Mutex::new(None),
            }),
            pool: BoundedBlockingPool::new("lmyzmail-xdp", XDP_WORKERS, XDP_QUEUE_CAPACITY)?,
        })
    }

    pub fn config(&self) -> &XdpConfig {
        &self.config
    }

    pub fn ready(&self) -> bool {
        self.shared.ready.load(Ordering::Acquire)
    }

    pub fn last_error(&self) -> Option<String> {
        self.shared
            .last_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub async fn initialize(&self, cancellation: &CancellationToken) {
        if !self.config.enabled {
            return;
        }
        let config = self.config.clone();
        match self.dispatch_initialization(config, cancellation).await {
            Ok(()) => {
                self.shared.ready.store(true, Ordering::Release);
                *self
                    .shared
                    .last_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            }
            Err(error) => {
                self.shared.ready.store(false, Ordering::Release);
                let message = error.to_string();
                eprintln!("lmyzmail XDP initialization failed: {message}");
                *self
                    .shared
                    .last_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(message);
            }
        }
    }

    pub async fn status(&self, cancellation: &CancellationToken) -> XdpStatus {
        if !self.ready() {
            return XdpStatus {
                ready: false,
                version: XDP_VERSION,
                banned_count: 0,
                packets_passed: 0,
                packets_dropped: 0,
            };
        }
        match self
            .dispatch(XDP_OPERATION_DEADLINE, cancellation, |state| state.status())
            .await
        {
            Ok(status) => status,
            Err(error) => {
                self.shared.ready.store(false, Ordering::Release);
                *self
                    .shared
                    .last_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error.to_string());
                XdpStatus {
                    ready: false,
                    version: XDP_VERSION,
                    banned_count: 0,
                    packets_passed: 0,
                    packets_dropped: 0,
                }
            }
        }
    }

    pub async fn ban(
        &self,
        ip: &str,
        reason: i32,
        cancellation: &CancellationToken,
    ) -> Result<bool, XdpError> {
        if !self.ready() {
            return Ok(false);
        }
        let ip = parse_ip(ip)?;
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, move |state| {
            state.ban(ip, reason as u32)
        })
        .await
    }

    pub async fn unban(
        &self,
        ip: &str,
        cancellation: &CancellationToken,
    ) -> Result<bool, XdpError> {
        if !self.ready() {
            return Ok(false);
        }
        let ip = parse_ip(ip)?;
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, move |state| {
            state.unban(ip)
        })
        .await
    }

    pub async fn is_banned(
        &self,
        ip: &str,
        cancellation: &CancellationToken,
    ) -> Result<bool, XdpError> {
        if !self.ready() {
            return Ok(false);
        }
        let ip = parse_ip(ip)?;
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, move |state| {
            Ok(state.banned.contains(&ip))
        })
        .await
    }

    pub async fn is_whitelisted(
        &self,
        ip: &str,
        cancellation: &CancellationToken,
    ) -> Result<bool, XdpError> {
        if !self.ready() {
            return Ok(false);
        }
        let ip = parse_ip(ip)?;
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, move |state| {
            Ok(state.configured_whitelist_contains(ip))
        })
        .await
    }

    pub async fn stats(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<XdpStats>, XdpError> {
        if !self.ready() {
            return Ok(None);
        }
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, |state| {
            state.native.stats().map(Some)
        })
        .await
    }

    pub async fn pps_stats(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<XdpPpsStats>, XdpError> {
        if !self.ready() {
            return Ok(None);
        }
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, |state| {
            state.native.pps_stats().map(Some)
        })
        .await
    }

    pub async fn all_ip_stats(
        &self,
        max_count: usize,
        cancellation: &CancellationToken,
    ) -> Result<Vec<XdpIpStatsEntry>, XdpError> {
        if !self.ready() {
            return Ok(Vec::new());
        }
        let max_count = max_count.clamp(1, MAX_PER_IP_STATS);
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, move |state| {
            state.native.all_ip_stats(max_count)
        })
        .await
    }

    pub async fn all_banned(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Vec<IpAddr>, XdpError> {
        if !self.ready() {
            return Ok(Vec::new());
        }
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, |state| {
            state.refresh_banned()
        })
        .await
    }

    pub async fn clear_all(&self, cancellation: &CancellationToken) -> Result<usize, XdpError> {
        if !self.ready() {
            return Ok(0);
        }
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, |state| {
            state.clear_all()
        })
        .await
    }

    pub(crate) async fn reconcile(
        &self,
        candidates: Vec<(IpAddr, i32)>,
        observed_existing: HashSet<IpAddr>,
        cancellation: &CancellationToken,
    ) -> Result<XdpReconcileCounts, XdpError> {
        if !self.ready() {
            return Ok(XdpReconcileCounts::default());
        }
        let ban_threshold = self.config.ban_threshold;
        let unban_threshold = self.config.unban_threshold;
        let reason = self.config.reason_code_default as u32;
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, move |state| {
            state.reconcile(
                candidates,
                observed_existing,
                ban_threshold,
                unban_threshold,
                reason,
            )
        })
        .await
    }

    pub async fn reset_pps_baseline(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<(), XdpError> {
        if !self.ready() {
            return Ok(());
        }
        self.dispatch(XDP_OPERATION_DEADLINE, cancellation, |state| {
            state.native.reset_pps_baseline();
            Ok(())
        })
        .await
    }

    pub async fn shutdown(&self) -> Result<(), XdpError> {
        self.shared.ready.store(false, Ordering::Release);
        let shared = Arc::clone(&self.shared);
        let receiver = self
            .pool
            .submit(move || {
                shared
                    .native
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .close()
            })
            .map_err(submit_error)?;
        let result = match timeout(XDP_OPERATION_DEADLINE, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(XdpError::Closed),
            Err(_) => Err(XdpError::Timeout),
        };
        if let Err(error) = &result {
            *self
                .shared
                .last_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error.to_string());
        }
        result
    }

    async fn dispatch<T, F>(
        &self,
        deadline: Duration,
        cancellation: &CancellationToken,
        operation: F,
    ) -> Result<T, XdpError>
    where
        T: Send + 'static,
        F: FnOnce(&mut NativeState) -> Result<T, XdpError> + Send + 'static,
    {
        let shared = Arc::clone(&self.shared);
        let receiver = self
            .pool
            .submit(move || {
                let mut state = shared
                    .native
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                operation(&mut state)
            })
            .map_err(submit_error)?;
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(XdpError::Cancelled),
            result = timeout(deadline, receiver) => match result {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(XdpError::Closed),
                Err(_) => Err(XdpError::Timeout),
            }
        }
    }

    async fn dispatch_initialization(
        &self,
        config: XdpConfig,
        cancellation: &CancellationToken,
    ) -> Result<(), XdpError> {
        let shared = Arc::clone(&self.shared);
        let job_cancellation = CancellationToken::new();
        let worker_cancellation = job_cancellation.clone();
        let receiver = self
            .pool
            .submit(move || {
                if worker_cancellation.is_cancelled() {
                    return Err(XdpError::Cancelled);
                }
                let mut state = shared
                    .native
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let result = state.initialize(&config);
                if worker_cancellation.is_cancelled() {
                    match state.close() {
                        Ok(()) => Err(XdpError::Cancelled),
                        Err(cleanup) => Err(cleanup_failure(XdpError::Cancelled, cleanup)),
                    }
                } else {
                    result
                }
            })
            .map_err(submit_error)?;
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                job_cancellation.cancel();
                self.cleanup_interrupted_initialization(XdpError::Cancelled).await
            }
            result = timeout(XDP_INITIALIZATION_DEADLINE, receiver) => match result {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(XdpError::Closed),
                Err(_) => {
                    job_cancellation.cancel();
                    self.cleanup_interrupted_initialization(XdpError::Timeout).await
                }
            }
        }
    }

    async fn cleanup_interrupted_initialization(&self, terminal: XdpError) -> Result<(), XdpError> {
        let shared = Arc::clone(&self.shared);
        let receiver = self
            .pool
            .submit(move || {
                shared
                    .native
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .close()
            })
            .map_err(submit_error)?;
        let cleanup = match timeout(XDP_INITIALIZATION_DEADLINE, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(XdpError::Closed),
            Err(_) => Err(XdpError::Timeout),
        };
        match cleanup {
            Ok(()) => Err(terminal),
            Err(error) => Err(cleanup_failure(terminal, error)),
        }
    }
}

fn submit_error(error: SubmitError) -> XdpError {
    match error {
        SubmitError::Closed => XdpError::Closed,
        SubmitError::Full => XdpError::Busy,
    }
}

fn parse_ip(value: &str) -> Result<IpAddr, XdpError> {
    value
        .trim()
        .parse()
        .map_err(|_| XdpError::InvalidInput(format!("invalid IP address: {value}")))
}

struct NativeState {
    native: NativeFirewall,
    banned: HashSet<IpAddr>,
    whitelist: Vec<IpNet>,
}

impl NativeState {
    fn new(whitelist: Vec<IpNet>) -> Self {
        Self {
            native: NativeFirewall::default(),
            banned: HashSet::new(),
            whitelist,
        }
    }

    fn initialize(&mut self, config: &XdpConfig) -> Result<(), XdpError> {
        self.native.initialize(config)?;
        if let Err(error) = self.refresh_banned() {
            return match self.close() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup_failure(error, cleanup)),
            };
        }
        Ok(())
    }

    fn status(&mut self) -> Result<XdpStatus, XdpError> {
        let stats = self.native.stats()?;
        Ok(XdpStatus {
            ready: true,
            version: XDP_VERSION,
            banned_count: self.banned.len(),
            packets_passed: stats.packets_passed,
            packets_dropped: stats.packets_dropped,
        })
    }

    fn ban(&mut self, ip: IpAddr, reason: u32) -> Result<bool, XdpError> {
        if self.configured_whitelist_contains(ip) {
            return Ok(false);
        }
        if self.banned.contains(&ip) {
            return Ok(true);
        }
        self.native.ban(ip, reason)?;
        self.banned.insert(ip);
        Ok(true)
    }

    fn unban(&mut self, ip: IpAddr) -> Result<bool, XdpError> {
        if !self.banned.contains(&ip) {
            return Ok(false);
        }
        self.native.unban(ip)?;
        self.banned.remove(&ip);
        Ok(true)
    }

    fn configured_whitelist_contains(&self, ip: IpAddr) -> bool {
        self.whitelist.iter().any(|network| network.contains(&ip))
    }

    fn refresh_banned(&mut self) -> Result<Vec<IpAddr>, XdpError> {
        let all = self.native.all_banned(MAX_BANNED_IPS)?;
        self.banned.clear();
        self.banned.extend(all.iter().copied());
        Ok(all)
    }

    fn clear_all(&mut self) -> Result<usize, XdpError> {
        let cleared = self.native.clear_all()?;
        self.banned.clear();
        Ok(cleared)
    }

    fn reconcile(
        &mut self,
        candidates: Vec<(IpAddr, i32)>,
        observed_existing: HashSet<IpAddr>,
        ban_threshold: i32,
        unban_threshold: i32,
        reason: u32,
    ) -> Result<XdpReconcileCounts, XdpError> {
        self.refresh_banned()?;
        let candidate_scores = candidates
            .into_iter()
            .filter(|(_, score)| *score >= unban_threshold)
            .collect::<HashMap<_, _>>();
        let mut counts = XdpReconcileCounts::default();
        let existing = self.banned.iter().copied().collect::<Vec<_>>();
        for ip in existing {
            if !observed_existing.contains(&ip) {
                counts.unchanged += 1;
                continue;
            }
            if self.configured_whitelist_contains(ip) {
                if self.unban(ip)? {
                    counts.unbanned += 1;
                    counts.unbanned_whitelist += 1;
                }
            } else if let Some(score) = candidate_scores.get(&ip) {
                counts.unchanged += 1;
                if *score >= ban_threshold {
                    counts.unchanged_high += 1;
                } else {
                    counts.unchanged_mid += 1;
                }
            } else if self.unban(ip)? {
                counts.unbanned += 1;
                counts.unbanned_score += 1;
            }
        }
        for (ip, score) in candidate_scores {
            if score < ban_threshold || self.banned.contains(&ip) {
                continue;
            }
            if self.configured_whitelist_contains(ip) {
                counts.skipped_whitelist += 1;
            } else if self.ban(ip, reason)? {
                counts.banned += 1;
            }
        }
        Ok(counts)
    }

    fn close(&mut self) -> Result<(), XdpError> {
        self.native.close()?;
        self.banned.clear();
        Ok(())
    }
}

#[derive(Default)]
struct NativeFirewall {
    initialized: bool,
    embedded_bpf: Option<File>,
    interface_lock: Option<File>,
    attachment: Option<XdpAttachment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct XdpAttachment {
    program_id: u32,
    interface_index: u32,
    flags: u32,
}

impl NativeFirewall {
    fn initialize(&mut self, config: &XdpConfig) -> Result<(), XdpError> {
        if self.initialized {
            return Err(XdpError::Native {
                code: ffi::ERR_ALREADY,
                message: "XDP native singleton is already initialized".into(),
            });
        }
        let owner_guard = NativeOwnerGuard::acquire(&NATIVE_OWNER)?;
        let interface = CString::new(config.interface_name.as_str())
            .map_err(|_| XdpError::InvalidInput("XDP interface contains NUL".into()))?;
        let interface_index = ffi::interface_index(&interface);
        if interface_index == 0 {
            return Err(XdpError::Native {
                code: ffi::ERR_NODEV,
                message: format!("Interface '{}' not found", config.interface_name),
            });
        }
        let interface_lock = acquire_interface_lock(interface_index)?;
        let pin_path = path_to_cstring(&config.pin_path)?;
        let existing = ffi::attached_programs(interface_index)?;
        let recovery = match existing.as_slice() {
            [] => {
                ffi::validate_pinned_maps(&pin_path, false)?;
                None
            }
            [attachment] => {
                if let Err(error) = ffi::validate_program(&pin_path, attachment.program_id) {
                    return Err(XdpError::Native {
                        code: ffi::ERR_ALREADY,
                        message: format!(
                            "refusing to replace foreign XDP program on '{}': {attachment:?}: {error}",
                            config.interface_name
                        ),
                    });
                }
                Some(*attachment)
            }
            _ => {
                return Err(XdpError::Native {
                    code: ffi::ERR_ALREADY,
                    message: format!(
                        "refusing multiple existing XDP programs on '{}': {existing:?}",
                        config.interface_name
                    ),
                });
            }
        };

        let (bpf_path, embedded_bpf) = match config.bpf_object_path.as_deref() {
            Some(path) => (path_to_cstring(path)?, None),
            None => {
                let file = embedded_bpf_file()?;
                let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
                    .map_err(|_| XdpError::InvalidInput("embedded BPF path contains NUL".into()))?;
                (path, Some(file))
            }
        };
        let options = ffi::XdpFwOpts {
            ifname: interface.as_ptr(),
            bpf_obj_path: bpf_path.as_ptr(),
            prog_name: std::ptr::null(),
            pin_base_path: pin_path.as_ptr(),
            verbose: i32::from(config.verbose),
            force_generic_mode: i32::from(config.force_generic_mode),
        };
        ffi::prepare_attach(interface_index, recovery)?;
        let recovery_program_id = recovery.map(|attachment| attachment.program_id);
        if let Some(program_id) = recovery_program_id
            && let Err(error) = ffi::stage_recovery_maps(&pin_path, program_id)
        {
            ffi::reset_attach_guard();
            return Err(error);
        }
        let code = ffi::init(&options);
        let recovery_cleanup = match recovery_program_id {
            Some(program_id) => ffi::unstage_recovery_maps(&pin_path, program_id),
            None => Ok(()),
        };
        if code != ffi::OK {
            ffi::reset_attach_guard();
            let error = native_error(code);
            return match recovery_cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup_failure(error, cleanup)),
            };
        }
        let owned_program_id = ffi::owned_program_id();
        let owned_interface_index = ffi::owned_program_ifindex();
        let owned_flags = ffi::owned_program_flags();
        if owned_program_id == 0 || owned_interface_index == 0 || owned_flags == 0 {
            ffi::close_without_detach();
            ffi::reset_attach_guard();
            return Err(XdpError::Native {
                code: ffi::ERR_ATTACH,
                message: "XDP attach guard did not record a complete owned attachment".into(),
            });
        }
        let attachment = XdpAttachment {
            program_id: owned_program_id,
            interface_index: owned_interface_index,
            flags: owned_flags,
        };
        self.embedded_bpf = embedded_bpf;
        self.interface_lock = Some(interface_lock);
        self.attachment = Some(attachment);
        self.initialized = true;
        owner_guard.commit();

        if let Err(error) = recovery_cleanup {
            return self.rollback(error);
        }

        if attachment.interface_index != interface_index {
            return self.rollback(XdpError::Native {
                code: ffi::ERR_ATTACH,
                message: format!(
                    "XDP attach guard used interface index {}, expected {interface_index}",
                    attachment.interface_index
                ),
            });
        }
        let attached = match ffi::attached_programs(interface_index) {
            Ok(attached) => attached,
            Err(error) => return self.rollback(error),
        };
        if attached.as_slice() != [attachment] {
            return self.rollback(XdpError::Native {
                code: ffi::ERR_ATTACH,
                message: format!(
                    "XDP initialization produced an invalid attachment set on '{}': {attached:?}",
                    config.interface_name
                ),
            });
        }
        if let Err(error) = ffi::validate_pinned_maps(&pin_path, true) {
            return self.rollback(error);
        }
        if let Err(error) = ffi::validate_program(&pin_path, attachment.program_id) {
            return self.rollback(error);
        }
        Ok(())
    }

    fn rollback<T>(&mut self, operation: XdpError) -> Result<T, XdpError> {
        match self.close() {
            Ok(()) => Err(operation),
            Err(cleanup) => Err(cleanup_failure(operation, cleanup)),
        }
    }

    fn ban(&mut self, ip: IpAddr, reason: u32) -> Result<(), XdpError> {
        match ip {
            IpAddr::V4(ip) => native_result(ffi::ban_v4(u32::from(ip), reason)),
            IpAddr::V6(ip) => native_result(ffi::ban_v6(&ip.octets(), reason)),
        }
    }

    fn unban(&mut self, ip: IpAddr) -> Result<(), XdpError> {
        match ip {
            IpAddr::V4(ip) => native_result(ffi::unban_v4(u32::from(ip))),
            IpAddr::V6(ip) => native_result(ffi::unban_v6(&ip.octets())),
        }
    }

    fn all_banned(&mut self, max_count: usize) -> Result<Vec<IpAddr>, XdpError> {
        let max_count = max_count.clamp(1, MAX_BANNED_IPS);
        let v4_capacity = max_count.min(MAX_BANNED_IPS_PER_FAMILY);
        let mut v4 = vec![0_u32; v4_capacity];
        let v4_count = ffi::banned_v4(&mut v4);
        if v4_count < 0 {
            return Err(native_error(v4_count));
        }
        let mut result = Vec::with_capacity(v4_count as usize);
        result.extend(
            v4.into_iter()
                .take(v4_count as usize)
                .map(|ip| IpAddr::V4(Ipv4Addr::from(ip))),
        );

        let v6_capacity = max_count
            .saturating_sub(result.len())
            .min(MAX_BANNED_IPS_PER_FAMILY);
        if v6_capacity > 0 {
            let mut v6 = vec![[0_u8; 16]; v6_capacity];
            let v6_count = ffi::banned_v6(&mut v6);
            if v6_count < 0 {
                return Err(native_error(v6_count));
            }
            result.extend(
                v6.into_iter()
                    .take(v6_count as usize)
                    .map(|ip| IpAddr::V6(Ipv6Addr::from(ip))),
            );
        }
        Ok(result)
    }

    fn clear_all(&mut self) -> Result<usize, XdpError> {
        let v4 = ffi::clear_v4();
        if v4 < 0 {
            return Err(native_error(v4));
        }
        let v6 = ffi::clear_v6();
        if v6 < 0 {
            return Err(native_error(v6));
        }
        Ok(v4 as usize + v6 as usize)
    }

    fn stats(&mut self) -> Result<XdpStats, XdpError> {
        let native = ffi::stats().map_err(native_error)?;
        Ok(XdpStats {
            packets_passed: native.packets_passed,
            packets_dropped: native.packets_dropped,
            packets_total: native.packets_total,
            packets_syn: native.packets_syn,
            packets_whitelisted: native.packets_whitelisted,
            banned_ips_count: native.banned_ips_count,
            banned_ips_v6_count: native.banned_ips_v6_count,
            whitelist_count: native.whitelist_count,
            whitelist_v6_count: native.whitelist_v6_count,
        })
    }

    fn pps_stats(&mut self) -> Result<XdpPpsStats, XdpError> {
        let native = ffi::pps_stats().map_err(native_error)?;
        Ok(XdpPpsStats {
            pps: native.pps,
            syn_pps: native.syn_pps,
            dropped_pps: native.dropped_pps,
            passed_pps: native.passed_pps,
            timestamp_ns: native.timestamp_ns,
            interval_ns: native.interval_ns,
        })
    }

    fn all_ip_stats(&mut self, max_count: usize) -> Result<Vec<XdpIpStatsEntry>, XdpError> {
        let mut v4 = vec![ffi::XdpFwIpStatsEntry::default(); max_count];
        let v4_count = ffi::all_ip_stats_v4(&mut v4);
        if v4_count < 0 {
            return Err(native_error(v4_count));
        }
        let mut result = Vec::with_capacity(v4_count as usize);
        result.extend(
            v4.into_iter()
                .take(v4_count as usize)
                .map(|entry| XdpIpStatsEntry {
                    ip: IpAddr::V4(Ipv4Addr::from(entry.ip)),
                    stats: XdpPerIpStats {
                        packets: entry.stats.packets,
                        syn_packets: entry.stats.syn_packets,
                    },
                }),
        );
        let remaining = max_count.saturating_sub(result.len());
        if remaining > 0 {
            let mut v6 = vec![ffi::XdpFwIp6StatsEntry::default(); remaining];
            let v6_count = ffi::all_ip_stats_v6(&mut v6);
            if v6_count < 0 {
                return Err(native_error(v6_count));
            }
            result.extend(
                v6.into_iter()
                    .take(v6_count as usize)
                    .map(|entry| XdpIpStatsEntry {
                        ip: IpAddr::V6(Ipv6Addr::from(entry.ip)),
                        stats: XdpPerIpStats {
                            packets: entry.stats.packets,
                            syn_packets: entry.stats.syn_packets,
                        },
                    }),
            );
        }
        Ok(result)
    }

    fn reset_pps_baseline(&mut self) {
        ffi::reset_pps_baseline();
    }

    fn close(&mut self) -> Result<(), XdpError> {
        if !self.initialized {
            return Ok(());
        }
        let expected = self
            .attachment
            .map_or(0, |attachment| attachment.program_id);
        let detach_code = ffi::detach_owned(expected);
        let still_owned = ffi::owned_program_id() != 0;
        if detach_code != ffi::OK && still_owned {
            return Err(XdpError::Native {
                code: detach_code,
                message: "conditional XDP detach failed; ownership and interface lock retained"
                    .into(),
            });
        }
        ffi::close_without_detach();
        ffi::reset_attach_guard();
        self.initialized = false;
        self.embedded_bpf = None;
        self.attachment = None;
        self.interface_lock = None;
        NATIVE_OWNER.store(false, Ordering::Release);
        if detach_code == ffi::OK {
            Ok(())
        } else {
            Err(XdpError::Native {
                code: detach_code,
                message: "owned XDP program was already absent or replaced; no foreign program was detached"
                    .into(),
            })
        }
    }
}

impl Drop for NativeFirewall {
    fn drop(&mut self) {
        if self.close().is_err()
            && let Some(interface_lock) = self.interface_lock.take()
        {
            std::mem::forget(interface_lock);
        }
    }
}

fn native_result(code: i32) -> Result<(), XdpError> {
    if code == ffi::OK {
        Ok(())
    } else {
        Err(native_error(code))
    }
}

fn native_error(code: i32) -> XdpError {
    XdpError::Native {
        code,
        message: ffi::last_error()
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| ffi::error_name(code)),
    }
}

fn cleanup_failure(operation: XdpError, cleanup: XdpError) -> XdpError {
    XdpError::Native {
        code: ffi::ERR_ATTACH,
        message: format!("{operation}; XDP cleanup failed: {cleanup}"),
    }
}

fn path_to_cstring(path: &Path) -> Result<CString, XdpError> {
    let path = path
        .to_str()
        .ok_or_else(|| XdpError::InvalidInput("XDP path is not UTF-8".into()))?;
    CString::new(path).map_err(|_| XdpError::InvalidInput("XDP path contains NUL".into()))
}

fn embedded_bpf_file() -> Result<File, XdpError> {
    let fd = memfd_create(
        c"lmyzmail-xdp-firewall.bpf.o",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?;
    let mut file = File::from(fd);
    file.write_all(EMBEDDED_BPF_OBJECT)?;
    file.flush()?;
    file.seek(SeekFrom::Start(0))?;
    fcntl_add_seals(
        &file,
        SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL,
    )?;
    Ok(file)
}

fn acquire_interface_lock(interface_index: u32) -> Result<File, XdpError> {
    std::fs::create_dir_all(XDP_LOCK_DIRECTORY)?;
    let directory = std::fs::symlink_metadata(XDP_LOCK_DIRECTORY)?;
    if !directory.is_dir()
        || directory.file_type().is_symlink()
        || directory.uid() != 0
        || directory.mode() & 0o022 != 0
    {
        return Err(XdpError::InvalidInput(format!(
            "XDP lock directory must be a root-owned non-writable real directory: {XDP_LOCK_DIRECTORY}"
        )));
    }
    let network_namespace = std::fs::metadata("/proc/thread-self/ns/net")?.ino();
    let path = Path::new(XDP_LOCK_DIRECTORY).join(format!(
        "xdp-netns-{network_namespace}-ifindex-{interface_index}.lock"
    ));
    let fd = open(
        &path,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR | Mode::RGRP,
    )?;
    let mut file = File::from(fd);
    flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if error == rustix::io::Errno::WOULDBLOCK {
            XdpError::Native {
                code: ffi::ERR_ALREADY,
                message: format!(
                    "another lmyzmail process owns XDP interface index {interface_index}"
                ),
            }
        } else {
            XdpError::Io(error.into())
        }
    })?;
    file.set_len(0)?;
    writeln!(
        file,
        "pid={} netns={} ifindex={interface_index}",
        std::process::id(),
        network_namespace
    )?;
    file.flush()?;
    Ok(file)
}

mod ffi {
    use super::{CStr, CString, IpAddr, IpNet, MaybeUninit, XdpAttachment, XdpError, size_of};
    use std::ffi::{c_char, c_int};

    pub(super) const OK: i32 = 0;
    pub(super) const ERR_NODEV: i32 = -2;
    pub(super) const ERR_ATTACH: i32 = -4;
    pub(super) const ERR_ALREADY: i32 = -7;
    const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
    const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
    const XDP_FLAGS_HW_MODE: u32 = 1 << 3;
    const ERR_OPERATION_NOT_SUPPORTED: i32 = -95;

    #[repr(C)]
    pub(super) struct XdpFwOpts {
        pub ifname: *const c_char,
        pub bpf_obj_path: *const c_char,
        pub prog_name: *const c_char,
        pub pin_base_path: *const c_char,
        pub verbose: c_int,
        pub force_generic_mode: c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub(super) struct XdpFwBanInfo {
        pub timestamp: u64,
        pub reason: u32,
        pub hit_count: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub(super) struct XdpFwStats {
        pub packets_passed: u64,
        pub packets_dropped: u64,
        pub packets_total: u64,
        pub packets_syn: u64,
        pub packets_whitelisted: u64,
        pub banned_ips_count: u32,
        pub banned_ips_v6_count: u32,
        pub whitelist_count: u32,
        pub whitelist_v6_count: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub(super) struct XdpFwPpsStats {
        pub pps: u64,
        pub syn_pps: u64,
        pub dropped_pps: u64,
        pub passed_pps: u64,
        pub timestamp_ns: u64,
        pub interval_ns: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub(super) struct XdpFwPerIpStats {
        pub packets: u64,
        pub syn_packets: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub(super) struct XdpFwIpStatsEntry {
        pub ip: u32,
        pub stats: XdpFwPerIpStats,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub(super) struct XdpFwIp6StatsEntry {
        pub ip: [u8; 16],
        pub stats: XdpFwPerIpStats,
    }

    unsafe extern "C" {
        fn if_nametoindex(ifname: *const c_char) -> u32;
        fn bpf_xdp_query_id(ifindex: c_int, flags: u32, program_id: *mut u32) -> c_int;
        fn lmyzmail_xdp_prepare_attach(
            ifindex: u32,
            recover_program_id: u32,
            recover_flags: u32,
        ) -> c_int;
        fn lmyzmail_xdp_reset_attach_guard();
        fn lmyzmail_xdp_set_expected_detach_program_id(program_id: u32);
        fn lmyzmail_xdp_owned_program_id() -> u32;
        fn lmyzmail_xdp_owned_program_ifindex() -> u32;
        fn lmyzmail_xdp_owned_program_flags() -> u32;
        fn lmyzmail_xdp_detach_owned(expected_program_id: u32) -> c_int;
        fn lmyzmail_xdp_validate_pinned_maps(pin_path: *const c_char, require_all: c_int) -> c_int;
        fn lmyzmail_xdp_validate_program(pin_path: *const c_char, program_id: u32) -> c_int;
        fn lmyzmail_xdp_stage_recovery_maps(pin_path: *const c_char, program_id: u32) -> c_int;
        fn lmyzmail_xdp_unstage_recovery_maps(pin_path: *const c_char, program_id: u32) -> c_int;
        fn xdp_fw_init(opts: *const XdpFwOpts) -> c_int;
        fn xdp_fw_close();
        fn xdp_fw_destroy();
        fn xdp_fw_is_initialized() -> c_int;
        fn xdp_fw_ban_ip(ip: u32, reason: u32) -> c_int;
        fn xdp_fw_unban_ip(ip: u32) -> c_int;
        fn xdp_fw_ban_ips_batch(ips: *const u32, count: c_int, reason: u32) -> c_int;
        fn xdp_fw_unban_ips_batch(ips: *const u32, count: c_int) -> c_int;
        fn xdp_fw_is_banned(ip: u32, info_out: *mut XdpFwBanInfo) -> c_int;
        fn xdp_fw_get_banned_ips(out_ips: *mut u32, max_count: c_int) -> c_int;
        fn xdp_fw_get_banned_count() -> c_int;
        fn xdp_fw_clear_all() -> c_int;
        fn xdp_fw_ban_ipv6(ip: *const u8, reason: u32) -> c_int;
        fn xdp_fw_unban_ipv6(ip: *const u8) -> c_int;
        fn xdp_fw_is_banned_ipv6(ip: *const u8, info_out: *mut XdpFwBanInfo) -> c_int;
        fn xdp_fw_get_banned_ipv6(out_ips: *mut [u8; 16], max_count: c_int) -> c_int;
        fn xdp_fw_get_banned_count_v6() -> c_int;
        fn xdp_fw_clear_all_v6() -> c_int;
        fn xdp_fw_whitelist_add(ip: u32, prefixlen: u32) -> c_int;
        fn xdp_fw_whitelist_remove(ip: u32, prefixlen: u32) -> c_int;
        fn xdp_fw_whitelist_check(ip: u32) -> c_int;
        fn xdp_fw_whitelist_count() -> c_int;
        fn xdp_fw_whitelist_clear() -> c_int;
        fn xdp_fw_whitelist_add_v6(ip: *const u8, prefixlen: u32) -> c_int;
        fn xdp_fw_whitelist_remove_v6(ip: *const u8, prefixlen: u32) -> c_int;
        fn xdp_fw_whitelist_check_v6(ip: *const u8) -> c_int;
        fn xdp_fw_whitelist_count_v6() -> c_int;
        fn xdp_fw_whitelist_clear_v6() -> c_int;
        fn xdp_fw_get_stats(stats_out: *mut XdpFwStats) -> c_int;
        fn xdp_fw_reset_stats() -> c_int;
        fn xdp_fw_get_pps(stats_out: *mut XdpFwPpsStats) -> c_int;
        fn xdp_fw_reset_pps_baseline();
        fn xdp_fw_get_all_ip_stats_v4(
            entries_out: *mut XdpFwIpStatsEntry,
            max_count: c_int,
        ) -> c_int;
        fn xdp_fw_get_all_ip_stats_v6(
            entries_out: *mut XdpFwIp6StatsEntry,
            max_count: c_int,
        ) -> c_int;
        fn xdp_fw_clear_per_ip_stats() -> c_int;
        fn xdp_fw_get_per_ip_stats_count() -> c_int;
        fn xdp_fw_check_permissions() -> c_int;
        fn xdp_fw_get_last_error() -> *const c_char;
        fn xdp_fw_strerror(error: c_int) -> *const c_char;
        fn xdp_fw_version() -> *const c_char;
        fn xdp_fw_ip_from_string(ip: *const c_char, ip_out: *mut u32) -> c_int;
        fn xdp_fw_ip_to_string(ip: u32, buffer: *mut c_char, length: c_int) -> *mut c_char;
    }

    pub(super) fn init(options: &XdpFwOpts) -> i32 {
        // SAFETY: all option pointers are valid NUL-terminated strings for this call.
        unsafe { xdp_fw_init(options) }
    }

    pub(super) fn interface_index(interface: &CString) -> u32 {
        // SAFETY: interface is a valid NUL-terminated interface name.
        unsafe { if_nametoindex(interface.as_ptr()) }
    }

    pub(super) fn attached_programs(interface_index: u32) -> Result<Vec<XdpAttachment>, XdpError> {
        let interface_index_c = i32::try_from(interface_index)
            .map_err(|_| XdpError::InvalidInput("XDP interface index exceeds the C ABI".into()))?;
        let mut attached = Vec::with_capacity(1);
        for flags in [XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE, XDP_FLAGS_HW_MODE] {
            let mut program_id = 0_u32;
            // SAFETY: program_id points to writable u32 storage and the flags
            // select exactly one kernel XDP attachment mode.
            let code = unsafe { bpf_xdp_query_id(interface_index_c, flags, &mut program_id) };
            if code == 0 {
                if program_id != 0 {
                    attached.push(XdpAttachment {
                        program_id,
                        interface_index,
                        flags,
                    });
                }
            } else if code != ERR_OPERATION_NOT_SUPPORTED {
                return Err(XdpError::Native {
                    code,
                    message: format!(
                        "failed to query XDP attachment mode {flags:#x} on interface index {interface_index}"
                    ),
                });
            }
        }
        Ok(attached)
    }

    pub(super) fn prepare_attach(
        interface_index: u32,
        recovery: Option<XdpAttachment>,
    ) -> Result<(), XdpError> {
        let (program_id, flags) = recovery.map_or((0, 0), |attachment| {
            (attachment.program_id, attachment.flags)
        });
        // SAFETY: the native guard stores scalar lifecycle expectations. The
        // Rust singleton and interface flock serialize this transition.
        let code = unsafe { lmyzmail_xdp_prepare_attach(interface_index, program_id, flags) };
        if code == OK {
            Ok(())
        } else {
            Err(XdpError::Native {
                code,
                message: "failed to prepare guarded XDP attach".into(),
            })
        }
    }

    pub(super) fn reset_attach_guard() {
        // SAFETY: reset is ignored by the guard while an owned program exists.
        unsafe { lmyzmail_xdp_reset_attach_guard() }
    }

    pub(super) fn set_expected_detach_program_id(program_id: u32) {
        // SAFETY: the native guard stores a scalar used only by the serialized
        // XDP close call.
        unsafe { lmyzmail_xdp_set_expected_detach_program_id(program_id) }
    }

    pub(super) fn owned_program_id() -> u32 {
        // SAFETY: the native guard returns one atomic scalar and performs no
        // memory access through Rust-owned pointers.
        unsafe { lmyzmail_xdp_owned_program_id() }
    }

    pub(super) fn owned_program_ifindex() -> u32 {
        // SAFETY: atomic scalar accessor.
        unsafe { lmyzmail_xdp_owned_program_ifindex() }
    }

    pub(super) fn owned_program_flags() -> u32 {
        // SAFETY: atomic scalar accessor.
        unsafe { lmyzmail_xdp_owned_program_flags() }
    }

    pub(super) fn detach_owned(program_id: u32) -> i32 {
        // SAFETY: the guard conditionally detaches only its recorded program.
        unsafe { lmyzmail_xdp_detach_owned(program_id) }
    }

    pub(super) fn validate_pinned_maps(
        pin_path: &CString,
        require_all: bool,
    ) -> Result<(), XdpError> {
        // SAFETY: pin_path is NUL-terminated and the native validator only
        // opens map pins and reads fixed kernel metadata.
        let code =
            unsafe { lmyzmail_xdp_validate_pinned_maps(pin_path.as_ptr(), i32::from(require_all)) };
        if code == 0 {
            Ok(())
        } else {
            Err(XdpError::Native {
                code,
                message: format!(
                    "XDP pinned map ABI validation failed for {} maps",
                    if require_all { "required" } else { "existing" }
                ),
            })
        }
    }

    pub(super) fn validate_program(pin_path: &CString, program_id: u32) -> Result<(), XdpError> {
        // SAFETY: the validator opens the program and maps by kernel ID and
        // reads fixed metadata; pin_path is NUL-terminated.
        let code = unsafe { lmyzmail_xdp_validate_program(pin_path.as_ptr(), program_id) };
        if code == OK {
            Ok(())
        } else {
            Err(XdpError::Native {
                code,
                message: "attached XDP program/map identity validation failed".into(),
            })
        }
    }

    pub(super) fn stage_recovery_maps(pin_path: &CString, program_id: u32) -> Result<(), XdpError> {
        // SAFETY: the validated recovery program remains attached while the
        // interface flock is held. The helper pins only its two non-persistent
        // maps at fixed names below pin_path.
        let code = unsafe { lmyzmail_xdp_stage_recovery_maps(pin_path.as_ptr(), program_id) };
        if code == OK {
            Ok(())
        } else {
            Err(XdpError::Native {
                code,
                message: "failed to stage recovery-only XDP map pins".into(),
            })
        }
    }

    pub(super) fn unstage_recovery_maps(
        pin_path: &CString,
        program_id: u32,
    ) -> Result<(), XdpError> {
        // SAFETY: the helper verifies every temporary pin against the
        // recovery program's map ID before unlinking it.
        let code = unsafe { lmyzmail_xdp_unstage_recovery_maps(pin_path.as_ptr(), program_id) };
        if code == OK {
            Ok(())
        } else {
            Err(XdpError::Native {
                code,
                message: "failed to remove recovery-only XDP map pins".into(),
            })
        }
    }

    pub(super) fn close_without_detach() {
        set_expected_detach_program_id(0);
        close();
    }

    pub(super) fn close() {
        // SAFETY: the Rust singleton serializes lifecycle calls.
        unsafe { xdp_fw_close() }
    }

    #[allow(dead_code)]
    pub(super) fn destroy() {
        // SAFETY: the Rust singleton serializes lifecycle calls.
        unsafe { xdp_fw_destroy() }
    }

    #[allow(dead_code)]
    pub(super) fn initialized() -> bool {
        // SAFETY: read-only query of native singleton state.
        unsafe { xdp_fw_is_initialized() != 0 }
    }

    pub(super) fn ban_v4(ip: u32, reason: u32) -> i32 {
        // SAFETY: scalar ABI matches the frozen header.
        unsafe { xdp_fw_ban_ip(ip, reason) }
    }

    pub(super) fn unban_v4(ip: u32) -> i32 {
        // SAFETY: scalar ABI matches the frozen header.
        unsafe { xdp_fw_unban_ip(ip) }
    }

    #[allow(dead_code)]
    pub(super) fn ban_v4_batch(ips: &[u32], reason: u32) -> i32 {
        let count = i32::try_from(ips.len()).unwrap_or(i32::MAX);
        // SAFETY: the slice is valid for `count` elements for the duration of the call.
        unsafe { xdp_fw_ban_ips_batch(ips.as_ptr(), count, reason) }
    }

    #[allow(dead_code)]
    pub(super) fn unban_v4_batch(ips: &[u32]) -> i32 {
        let count = i32::try_from(ips.len()).unwrap_or(i32::MAX);
        // SAFETY: the slice is valid for `count` elements for the duration of the call.
        unsafe { xdp_fw_unban_ips_batch(ips.as_ptr(), count) }
    }

    #[allow(dead_code)]
    pub(super) fn is_banned_v4(ip: u32) -> Result<Option<XdpFwBanInfo>, i32> {
        let mut info = MaybeUninit::uninit();
        // SAFETY: `info` points to writable storage matching the frozen C layout.
        let code = unsafe { xdp_fw_is_banned(ip, info.as_mut_ptr()) };
        match code {
            1 => {
                // SAFETY: the native function initializes `info` when it returns one.
                Ok(Some(unsafe { info.assume_init() }))
            }
            0 => Ok(None),
            error => Err(error),
        }
    }

    pub(super) fn banned_v4(output: &mut [u32]) -> i32 {
        let count = i32::try_from(output.len()).unwrap_or(i32::MAX);
        // SAFETY: the output slice is writable for `count` elements.
        unsafe { xdp_fw_get_banned_ips(output.as_mut_ptr(), count) }
    }

    #[allow(dead_code)]
    pub(super) fn banned_v4_count() -> i32 {
        // SAFETY: read-only native map query.
        unsafe { xdp_fw_get_banned_count() }
    }

    pub(super) fn clear_v4() -> i32 {
        // SAFETY: mutation is serialized by the Rust worker.
        unsafe { xdp_fw_clear_all() }
    }

    pub(super) fn ban_v6(ip: &[u8; 16], reason: u32) -> i32 {
        // SAFETY: the array has the exact 16-byte ABI required by C.
        unsafe { xdp_fw_ban_ipv6(ip.as_ptr(), reason) }
    }

    pub(super) fn unban_v6(ip: &[u8; 16]) -> i32 {
        // SAFETY: the array has the exact 16-byte ABI required by C.
        unsafe { xdp_fw_unban_ipv6(ip.as_ptr()) }
    }

    #[allow(dead_code)]
    pub(super) fn is_banned_v6(ip: &[u8; 16]) -> Result<Option<XdpFwBanInfo>, i32> {
        let mut info = MaybeUninit::uninit();
        // SAFETY: input and output storage match the frozen C layouts.
        let code = unsafe { xdp_fw_is_banned_ipv6(ip.as_ptr(), info.as_mut_ptr()) };
        match code {
            1 => {
                // SAFETY: the native function initializes `info` when it returns one.
                Ok(Some(unsafe { info.assume_init() }))
            }
            0 => Ok(None),
            error => Err(error),
        }
    }

    pub(super) fn banned_v6(output: &mut [[u8; 16]]) -> i32 {
        let count = i32::try_from(output.len()).unwrap_or(i32::MAX);
        // SAFETY: the output slice is writable for `count` 16-byte entries.
        unsafe { xdp_fw_get_banned_ipv6(output.as_mut_ptr(), count) }
    }

    #[allow(dead_code)]
    pub(super) fn banned_v6_count() -> i32 {
        // SAFETY: read-only native map query.
        unsafe { xdp_fw_get_banned_count_v6() }
    }

    pub(super) fn clear_v6() -> i32 {
        // SAFETY: mutation is serialized by the Rust worker.
        unsafe { xdp_fw_clear_all_v6() }
    }

    #[allow(dead_code)]
    pub(super) fn whitelist_add(network: IpNet) -> i32 {
        match network {
            IpNet::V4(network) => {
                // SAFETY: scalar ABI matches the frozen header.
                unsafe {
                    xdp_fw_whitelist_add(
                        u32::from(network.network()),
                        u32::from(network.prefix_len()),
                    )
                }
            }
            IpNet::V6(network) => {
                let ip = network.network().octets();
                // SAFETY: the array has the exact 16-byte ABI required by C.
                unsafe { xdp_fw_whitelist_add_v6(ip.as_ptr(), u32::from(network.prefix_len())) }
            }
        }
    }

    #[allow(dead_code)]
    pub(super) fn whitelist_remove(network: IpNet) -> i32 {
        match network {
            IpNet::V4(network) => {
                // SAFETY: scalar ABI matches the frozen header.
                unsafe {
                    xdp_fw_whitelist_remove(
                        u32::from(network.network()),
                        u32::from(network.prefix_len()),
                    )
                }
            }
            IpNet::V6(network) => {
                let ip = network.network().octets();
                // SAFETY: the array has the exact 16-byte ABI required by C.
                unsafe { xdp_fw_whitelist_remove_v6(ip.as_ptr(), u32::from(network.prefix_len())) }
            }
        }
    }

    #[allow(dead_code)]
    pub(super) fn whitelist_check(ip: IpAddr) -> i32 {
        match ip {
            IpAddr::V4(ip) => {
                // SAFETY: scalar ABI matches the frozen header.
                unsafe { xdp_fw_whitelist_check(u32::from(ip)) }
            }
            IpAddr::V6(ip) => {
                let ip = ip.octets();
                // SAFETY: the array has the exact 16-byte ABI required by C.
                unsafe { xdp_fw_whitelist_check_v6(ip.as_ptr()) }
            }
        }
    }

    #[allow(dead_code)]
    pub(super) fn whitelist_counts() -> (i32, i32) {
        // SAFETY: read-only native map queries.
        unsafe { (xdp_fw_whitelist_count(), xdp_fw_whitelist_count_v6()) }
    }

    #[allow(dead_code)]
    pub(super) fn whitelist_clear() -> (i32, i32) {
        // SAFETY: mutations are serialized by the Rust worker.
        unsafe { (xdp_fw_whitelist_clear(), xdp_fw_whitelist_clear_v6()) }
    }

    pub(super) fn stats() -> Result<XdpFwStats, i32> {
        let mut stats = MaybeUninit::uninit();
        // SAFETY: output storage matches the frozen C layout.
        let code = unsafe { xdp_fw_get_stats(stats.as_mut_ptr()) };
        if code == OK {
            // SAFETY: success guarantees the output was initialized.
            Ok(unsafe { stats.assume_init() })
        } else {
            Err(code)
        }
    }

    #[allow(dead_code)]
    pub(super) fn reset_stats() -> i32 {
        // SAFETY: mutation is serialized by the Rust worker.
        unsafe { xdp_fw_reset_stats() }
    }

    pub(super) fn pps_stats() -> Result<XdpFwPpsStats, i32> {
        let mut stats = MaybeUninit::uninit();
        // SAFETY: output storage matches the frozen C layout.
        let code = unsafe { xdp_fw_get_pps(stats.as_mut_ptr()) };
        if code == OK {
            // SAFETY: success guarantees the output was initialized.
            Ok(unsafe { stats.assume_init() })
        } else {
            Err(code)
        }
    }

    pub(super) fn reset_pps_baseline() {
        // SAFETY: mutation is serialized by the Rust worker.
        unsafe { xdp_fw_reset_pps_baseline() }
    }

    pub(super) fn all_ip_stats_v4(output: &mut [XdpFwIpStatsEntry]) -> i32 {
        let count = i32::try_from(output.len()).unwrap_or(i32::MAX);
        // SAFETY: output storage is writable and has the frozen C layout.
        unsafe { xdp_fw_get_all_ip_stats_v4(output.as_mut_ptr(), count) }
    }

    pub(super) fn all_ip_stats_v6(output: &mut [XdpFwIp6StatsEntry]) -> i32 {
        let count = i32::try_from(output.len()).unwrap_or(i32::MAX);
        // SAFETY: output storage is writable and has the frozen C layout.
        unsafe { xdp_fw_get_all_ip_stats_v6(output.as_mut_ptr(), count) }
    }

    #[allow(dead_code)]
    pub(super) fn clear_per_ip_stats() -> i32 {
        // SAFETY: mutation is serialized by the Rust worker.
        unsafe { xdp_fw_clear_per_ip_stats() }
    }

    #[allow(dead_code)]
    pub(super) fn per_ip_stats_count() -> i32 {
        // SAFETY: read-only native map query.
        unsafe { xdp_fw_get_per_ip_stats_count() }
    }

    #[allow(dead_code)]
    pub(super) fn permissions_available() -> bool {
        // SAFETY: read-only process capability query.
        unsafe { xdp_fw_check_permissions() != 0 }
    }

    pub(super) fn last_error() -> Option<String> {
        // SAFETY: the native function returns a static NUL-terminated buffer or null.
        let pointer = unsafe { xdp_fw_get_last_error() };
        (!pointer.is_null()).then(|| {
            // SAFETY: non-null pointer is owned by the native singleton and NUL-terminated.
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned()
        })
    }

    pub(super) fn error_name(error: i32) -> String {
        // SAFETY: the native function returns a static NUL-terminated string.
        let pointer = unsafe { xdp_fw_strerror(error) };
        if pointer.is_null() {
            return "unknown XDP error".into();
        }
        // SAFETY: non-null pointer is static and NUL-terminated.
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }

    #[allow(dead_code)]
    pub(super) fn version() -> String {
        // SAFETY: the native function returns a static NUL-terminated string.
        let pointer = unsafe { xdp_fw_version() };
        if pointer.is_null() {
            return String::new();
        }
        // SAFETY: non-null pointer is static and NUL-terminated.
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }

    #[allow(dead_code)]
    pub(super) fn parse_v4(value: &CStr) -> Result<u32, i32> {
        let mut output = 0_u32;
        // SAFETY: input is NUL-terminated and output points to valid writable storage.
        let code = unsafe { xdp_fw_ip_from_string(value.as_ptr(), &mut output) };
        if code == 0 { Ok(output) } else { Err(code) }
    }

    #[allow(dead_code)]
    pub(super) fn format_v4(ip: u32) -> Option<String> {
        let mut buffer = [0_i8; 16];
        // SAFETY: buffer is writable for the supplied length and matches C char storage.
        let result = unsafe { xdp_fw_ip_to_string(ip, buffer.as_mut_ptr(), buffer.len() as i32) };
        if result.is_null() {
            None
        } else {
            // SAFETY: successful native formatting NUL-terminates the buffer.
            Some(
                unsafe { CStr::from_ptr(buffer.as_ptr()) }
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }

    const _: () = assert!(size_of::<XdpFwOpts>() == 40);
    const _: () = assert!(size_of::<XdpFwBanInfo>() == 16);
    const _: () = assert!(size_of::<XdpFwStats>() == 56);
    const _: () = assert!(size_of::<XdpFwPpsStats>() == 48);
    const _: () = assert!(size_of::<XdpFwPerIpStats>() == 16);
    const _: () = assert!(size_of::<XdpFwIpStatsEntry>() == 24);
    const _: () = assert!(size_of::<XdpFwIp6StatsEntry>() == 32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_bpf_object_is_linux_elf_for_bpf() {
        assert_eq!(&EMBEDDED_BPF_OBJECT[..4], b"\x7fELF");
        assert_eq!(
            u16::from_le_bytes([EMBEDDED_BPF_OBJECT[18], EMBEDDED_BPF_OBJECT[19]]),
            247
        );
    }

    #[test]
    fn rust_layout_matches_frozen_x86_64_c_abi() {
        assert_eq!(size_of::<ffi::XdpFwOpts>(), 40);
        assert_eq!(std::mem::offset_of!(ffi::XdpFwOpts, verbose), 32);
        assert_eq!(std::mem::offset_of!(ffi::XdpFwOpts, force_generic_mode), 36);
        assert_eq!(size_of::<ffi::XdpFwStats>(), 56);
        assert_eq!(size_of::<ffi::XdpFwIpStatsEntry>(), 24);
    }

    #[test]
    fn configured_whitelist_supports_ipv4_and_ipv6_cidr() {
        let state = NativeState::new(vec![
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ]);
        assert!(state.configured_whitelist_contains("192.0.2.44".parse().unwrap()));
        assert!(state.configured_whitelist_contains("2001:db8::44".parse().unwrap()));
        assert!(!state.configured_whitelist_contains("198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn native_owner_guard_releases_failed_initialization() {
        let owner = AtomicBool::new(false);
        let guard = NativeOwnerGuard::acquire(&owner).unwrap();
        assert!(owner.load(Ordering::Acquire));
        drop(guard);
        assert!(!owner.load(Ordering::Acquire));

        let guard = NativeOwnerGuard::acquire(&owner).unwrap();
        guard.commit();
        assert!(owner.load(Ordering::Acquire));
    }

    #[test]
    fn ban_cache_budget_matches_both_frozen_native_maps() {
        assert_eq!(MAX_BANNED_IPS_PER_FAMILY, 100_000);
        assert_eq!(MAX_BANNED_IPS, 200_000);
    }
}
