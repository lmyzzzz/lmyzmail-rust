use std::{
    collections::{HashMap, HashSet},
    env,
    error::Error,
    ffi::{CStr, CString, c_char, c_int},
    fmt, fs,
    net::IpAddr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Output,
    time::Duration,
};

use lmyzmail::{
    config::{XdpConfig, XdpPpsMonitorConfig},
    xdp::{XdpService, XdpStats},
};
use serde_json::{Value, json};
use tokio::{process::Command, time::timeout};
use tokio_util::sync::CancellationToken;

const INTERFACE_DEFAULT: &str = "lmyz-xdp0";
const PEER_NAMESPACE_DEFAULT: &str = "lmyz-xdp-peer";
const IPV4_SOURCE: &str = "198.51.100.2";
const IPV4_TARGET: &str = "198.51.100.1";
const IPV6_SOURCE: &str = "2001:db8:1::2";
const IPV6_TARGET: &str = "2001:db8:1::1";
const COMMAND_DEADLINE: Duration = Duration::from_secs(10);

type CheckResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug)]
struct CheckFailure(String);

impl fmt::Display for CheckFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CheckFailure {}

#[derive(Clone, Copy)]
struct MapAbi {
    name: &'static str,
    kind: u32,
    key_size: u64,
    value_size: u64,
    max_entries: u64,
    pinned: bool,
}

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NativeMapInfo {
    id: u32,
    kind: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [c_char; 16],
}

const MAP_ABI: &[MapAbi] = &[
    MapAbi {
        name: "blocked_ips",
        kind: BPF_MAP_TYPE_HASH,
        key_size: 4,
        value_size: 16,
        max_entries: 100_000,
        pinned: true,
    },
    MapAbi {
        name: "blocked_ips_v6",
        kind: BPF_MAP_TYPE_HASH,
        key_size: 16,
        value_size: 16,
        max_entries: 100_000,
        pinned: true,
    },
    MapAbi {
        name: "whitelist_v4",
        kind: BPF_MAP_TYPE_LPM_TRIE,
        key_size: 8,
        value_size: 1,
        max_entries: 10_000,
        pinned: true,
    },
    MapAbi {
        name: "whitelist_v6",
        kind: BPF_MAP_TYPE_LPM_TRIE,
        key_size: 20,
        value_size: 1,
        max_entries: 10_000,
        pinned: true,
    },
    MapAbi {
        name: "stats",
        kind: BPF_MAP_TYPE_PERCPU_ARRAY,
        key_size: 4,
        value_size: 8,
        max_entries: 8,
        pinned: true,
    },
    MapAbi {
        name: "config_map",
        kind: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 16,
        max_entries: 1,
        pinned: false,
    },
    MapAbi {
        name: "per_ip_stats_v4",
        kind: BPF_MAP_TYPE_LRU_HASH,
        key_size: 4,
        value_size: 16,
        max_entries: 50_000,
        pinned: false,
    },
    MapAbi {
        name: "per_ip_stats_v6",
        kind: BPF_MAP_TYPE_LRU_HASH,
        key_size: 16,
        value_size: 16,
        max_entries: 50_000,
        pinned: false,
    },
];

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("lmyzmail privileged XDP check failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> CheckResult<()> {
    let interface =
        env::var("LMYZMAIL_XDP_CHECK_INTERFACE").unwrap_or_else(|_| INTERFACE_DEFAULT.to_owned());
    let peer_namespace = env::var("LMYZMAIL_XDP_CHECK_PEER_NAMESPACE")
        .unwrap_or_else(|_| PEER_NAMESPACE_DEFAULT.to_owned());
    let pin_path = env::var_os("LMYZMAIL_XDP_CHECK_PIN_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/sys/fs/bpf/lmyzmail-xdp-check"));

    verify_isolation(&interface, &peer_namespace, &pin_path).await?;
    let maps_before = map_ids()?;
    verify_failed_initialization_rolls_back(&interface, &pin_path).await?;

    let cancellation = CancellationToken::new();
    let first = XdpService::from_config(&xdp_config(&interface, pin_path.clone()))?;
    first.initialize(&cancellation).await;
    require_ready(&first, "first initialization")?;

    let first_program_id = attached_program_id(&interface)
        .await?
        .ok_or_else(|| failure("XDP program was not attached after initialization"))?;
    let runtime_maps = validate_runtime_map_abi(&maps_before, &pin_path)?;
    verify_ping(&peer_namespace, false, true).await?;
    verify_ping(&peer_namespace, true, true).await?;
    let passed = first
        .stats(&cancellation)
        .await?
        .ok_or_else(|| failure("XDP stats were unavailable after initialization"))?;
    require(
        passed.packets_passed >= 2,
        format!(
            "expected at least two passed packets, observed {}",
            passed.packets_passed
        ),
    )?;

    require(
        first.ban(IPV4_SOURCE, 0, &cancellation).await?,
        "IPv4 ban was rejected",
    )?;
    require(
        first.ban(IPV6_SOURCE, 0, &cancellation).await?,
        "IPv6 ban was rejected",
    )?;
    verify_ping(&peer_namespace, false, false).await?;
    verify_ping(&peer_namespace, true, false).await?;

    let dropped = first
        .stats(&cancellation)
        .await?
        .ok_or_else(|| failure("XDP stats disappeared after bans"))?;
    verify_drop_stats(passed, dropped)?;
    let ip_stats = first.all_ip_stats(32, &cancellation).await?;
    for expected in [IPV4_SOURCE, IPV6_SOURCE] {
        let expected: IpAddr = expected.parse()?;
        require(
            ip_stats
                .iter()
                .any(|entry| entry.ip == expected && entry.stats.packets >= 2),
            format!("missing per-IP kernel statistics for {expected}"),
        )?;
    }
    first.reset_pps_baseline(&cancellation).await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let pps = first
        .pps_stats(&cancellation)
        .await?
        .ok_or_else(|| failure("XDP PPS stats were unavailable"))?;
    require(pps.interval_ns > 0, "XDP PPS interval did not advance")?;

    let banned = first.all_banned(&cancellation).await?;
    require(
        banned.len() == 2
            && banned.contains(&IPV4_SOURCE.parse()?)
            && banned.contains(&IPV6_SOURCE.parse()?),
        format!("unexpected persisted ban set: {banned:?}"),
    )?;
    first.shutdown().await;
    require(
        attached_program_id(&interface).await?.is_none(),
        "XDP program remained attached after shutdown",
    )?;
    verify_pins_exist(&pin_path)?;
    drop(first);

    let second = XdpService::from_config(&xdp_config(&interface, pin_path.clone()))?;
    second.initialize(&cancellation).await;
    require_ready(&second, "restart initialization")?;
    let second_program_id = attached_program_id(&interface)
        .await?
        .ok_or_else(|| failure("XDP program was not attached after restart"))?;
    require(
        second_program_id != first_program_id,
        "restart unexpectedly reused the detached program ID",
    )?;
    let restored = second.all_banned(&cancellation).await?;
    require(
        restored.len() == 2
            && restored.contains(&IPV4_SOURCE.parse()?)
            && restored.contains(&IPV6_SOURCE.parse()?),
        format!("restart did not restore both pinned bans: {restored:?}"),
    )?;
    verify_ping(&peer_namespace, false, false).await?;
    verify_ping(&peer_namespace, true, false).await?;
    require(
        second.unban(IPV4_SOURCE, &cancellation).await?,
        "IPv4 unban failed after restart",
    )?;
    require(
        second.unban(IPV6_SOURCE, &cancellation).await?,
        "IPv6 unban failed after restart",
    )?;
    verify_ping(&peer_namespace, false, true).await?;
    verify_ping(&peer_namespace, true, true).await?;
    require(
        second.clear_all(&cancellation).await? == 0,
        "clear_all found unexpected bans after explicit unban",
    )?;
    second.shutdown().await;
    require(
        attached_program_id(&interface).await?.is_none(),
        "restarted XDP program remained attached after shutdown",
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "passed",
            "interface": interface,
            "pinPath": pin_path,
            "firstProgramId": first_program_id,
            "secondProgramId": second_program_id,
            "runtimeMaps": runtime_maps,
            "packetsPassed": passed.packets_passed,
            "packetsDropped": dropped.packets_dropped,
            "ipv4": "pass-ban-drop-restart-drop-unban-pass",
            "ipv6": "pass-ban-drop-restart-drop-unban-pass"
        }))?
    );
    Ok(())
}

async fn verify_isolation(
    interface: &str,
    peer_namespace: &str,
    pin_path: &Path,
) -> CheckResult<()> {
    require(
        env::var_os("LMYZMAIL_XDP_CHECK_ISOLATED").as_deref() == Some(std::ffi::OsStr::new("1")),
        "isolation marker is absent; use run-isolated.sh",
    )?;
    // SAFETY: geteuid has no arguments, no memory effects visible to Rust, and
    // the Linux x86_64 C ABI returns uid_t as u32.
    require(
        unsafe { libc_geteuid() } == 0,
        "privileged XDP check must run as root",
    )?;
    for namespace in ["net", "mnt"] {
        let current = fs::read_link(format!("/proc/self/ns/{namespace}"))?;
        let init = fs::read_link(format!("/proc/1/ns/{namespace}"))?;
        require(
            current != init,
            format!("process is still in PID 1's {namespace} namespace"),
        )?;
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let pin_mount = format!(" {} ", pin_path.display());
    let rollback_mount = format!(" {}.rollback ", pin_path.display());
    for (mount_path, label) in [
        (pin_mount.as_str(), "primary"),
        (rollback_mount.as_str(), "rollback"),
    ] {
        require(
            mountinfo.lines().any(|line| {
                line.contains(mount_path)
                    && line
                        .split(" - ")
                        .nth(1)
                        .is_some_and(|tail| tail.starts_with("bpf "))
            }),
            format!("{label} XDP pin path is not a private bpffs mount"),
        )?;
    }
    require(
        mountinfo.lines().any(|line| {
            line.contains(" /run/netns ")
                && line
                    .split(" - ")
                    .nth(1)
                    .is_some_and(|tail| tail.starts_with("tmpfs "))
        }),
        "/run/netns is not a private tmpfs mount",
    )?;
    require(
        interface == INTERFACE_DEFAULT && peer_namespace == PEER_NAMESPACE_DEFAULT,
        "checker interface or peer namespace does not use the reserved isolated names",
    )?;
    require(
        pin_path.starts_with("/sys/fs/bpf/") && !pin_path.starts_with("/sys/fs/bpf/botmail"),
        format!("unsafe or legacy XDP pin path: {}", pin_path.display()),
    )?;
    require(
        pin_path.is_dir() && fs::read_dir(pin_path)?.next().is_none(),
        format!(
            "XDP check pin path is absent or not empty: {}",
            pin_path.display()
        ),
    )?;
    for tool in ["ip", "ping"] {
        require(
            executable_in_path(tool),
            format!("required tool is unavailable: {tool}"),
        )?;
    }
    let link_args = ["-j", "link", "show", "dev", interface];
    require(
        run_output("ip", &link_args).await?.status.success(),
        format!("isolated interface {interface} is unavailable"),
    )?;
    let peer_args = [
        "netns",
        "exec",
        peer_namespace,
        "ip",
        "link",
        "show",
        "dev",
        "lmyz-xdp1",
    ];
    require(
        run_output("ip", &peer_args).await?.status.success(),
        format!("isolated peer namespace {peer_namespace} is unavailable"),
    )?;
    Ok(())
}

async fn verify_failed_initialization_rolls_back(
    interface: &str,
    pin_path: &Path,
) -> CheckResult<()> {
    let rollback_pin = pin_path.with_extension("rollback");
    let service = XdpService::from_config(&xdp_config(
        &format!("{interface}-missing"),
        rollback_pin.clone(),
    ))?;
    let cancellation = CancellationToken::new();
    service.initialize(&cancellation).await;
    require(
        !service.ready(),
        "invalid-interface initialization succeeded",
    )?;
    require(
        service
            .last_error()
            .is_some_and(|error| error.contains("not found")),
        format!(
            "invalid-interface initialization returned the wrong error: {:?}",
            service.last_error()
        ),
    )?;
    service.shutdown().await;
    drop(service);
    require(
        rollback_pin.is_dir() && fs::read_dir(&rollback_pin)?.next().is_none(),
        "failed initialization left pinned BPF objects behind",
    )?;
    Ok(())
}

fn xdp_config(interface: &str, pin_path: PathBuf) -> XdpConfig {
    XdpConfig {
        enabled: true,
        interface_name: interface.to_owned(),
        bpf_object_path: None,
        pin_path,
        ban_threshold: 100,
        unban_threshold: 50,
        force_generic_mode: true,
        verbose: false,
        sync_on_startup: false,
        whitelist: Vec::new(),
        reason_code_default: 0,
        pps_monitor: XdpPpsMonitorConfig {
            enabled: false,
            poll_interval_ms: 1_000,
            pps_warn_threshold: 50_000,
            pps_critical_threshold: 100_000,
            syn_pps_warn_threshold: 10_000,
            syn_pps_critical_threshold: 50_000,
            per_ip_pps_warn_threshold: 5_000,
            per_ip_pps_critical_threshold: 10_000,
            per_ip_syn_pps_warn_threshold: 1_000,
            per_ip_syn_pps_critical_threshold: 5_000,
            consecutive_exceed_count: 3,
            record_to_cringe: false,
            max_ips_per_poll: 10_000,
            ring_buffer_size: 60,
        },
    }
}

fn require_ready(service: &XdpService, phase: &str) -> CheckResult<()> {
    require(
        service.ready(),
        format!("{phase} failed: {:?}", service.last_error()),
    )
}

fn verify_drop_stats(before: XdpStats, after: XdpStats) -> CheckResult<()> {
    require(
        after.packets_dropped >= before.packets_dropped + 2,
        format!(
            "kernel drop counter did not include both banned packets: {} -> {}",
            before.packets_dropped, after.packets_dropped
        ),
    )?;
    require(
        after.packets_total >= before.packets_total + 2,
        format!(
            "kernel total counter did not advance for dropped packets: {} -> {}",
            before.packets_total, after.packets_total
        ),
    )?;
    require(
        after.banned_ips_count == 1 && after.banned_ips_v6_count == 1,
        format!(
            "kernel ban counts are wrong: v4={}, v6={}",
            after.banned_ips_count, after.banned_ips_v6_count
        ),
    )
}

async fn verify_ping(peer_namespace: &str, ipv6: bool, expected_success: bool) -> CheckResult<()> {
    let family = if ipv6 { "-6" } else { "-4" };
    let source = if ipv6 { IPV6_SOURCE } else { IPV4_SOURCE };
    let target = if ipv6 { IPV6_TARGET } else { IPV4_TARGET };
    let args = [
        "netns",
        "exec",
        peer_namespace,
        "ping",
        family,
        "-n",
        "-c",
        "1",
        "-W",
        "1",
        "-I",
        source,
        target,
    ];
    let output = run_output("ip", &args).await?;
    require(
        output.status.success() == expected_success,
        format!(
            "{family} ping from {source} to {target} was expected to {} but status was {}; stderr={}",
            if expected_success { "pass" } else { "drop" },
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    )
}

fn validate_runtime_map_abi(before: &HashSet<u64>, pin_path: &Path) -> CheckResult<Vec<String>> {
    let maps = map_infos()?;
    let mut by_name = HashMap::new();
    for info in maps {
        if before.contains(&u64::from(info.id)) {
            continue;
        }
        by_name.insert(map_name(&info)?, info);
    }
    for abi in MAP_ABI {
        let info = by_name
            .get(abi.name)
            .ok_or_else(|| failure(format!("new XDP object did not create map {}", abi.name)))?;
        validate_map(info, *abi)?;
    }
    require(
        by_name
            .keys()
            .filter(|name| MAP_ABI.iter().any(|abi| abi.name == name.as_str()))
            .count()
            == MAP_ABI.len(),
        "runtime XDP map name set is incomplete",
    )?;
    verify_pins_exist(pin_path)?;
    let mut names = MAP_ABI
        .iter()
        .map(|abi| abi.name.to_owned())
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

fn validate_map(info: &NativeMapInfo, expected: MapAbi) -> CheckResult<()> {
    require(
        info.kind == expected.kind,
        format!(
            "map {} type mismatch: expected {}, got {}",
            expected.name, expected.kind, info.kind
        ),
    )?;
    for (label, actual, expected_value) in [
        ("key size", u64::from(info.key_size), expected.key_size),
        (
            "value size",
            u64::from(info.value_size),
            expected.value_size,
        ),
        (
            "max entries",
            u64::from(info.max_entries),
            expected.max_entries,
        ),
    ] {
        require(
            actual == expected_value,
            format!(
                "map {} {label} mismatch: expected {expected_value}, got {actual}",
                expected.name
            ),
        )?;
    }
    Ok(())
}

fn verify_pins_exist(pin_path: &Path) -> CheckResult<()> {
    for abi in MAP_ABI.iter().filter(|abi| abi.pinned) {
        let path = pin_path.join(abi.name);
        require(
            path.exists(),
            format!("required pinned map is absent: {}", path.display()),
        )?;
        let info = map_info_by_pin(&path)?;
        validate_map(&info, *abi)?;
    }
    Ok(())
}

fn map_ids() -> CheckResult<HashSet<u64>> {
    Ok(map_infos()?.iter().map(|info| u64::from(info.id)).collect())
}

fn map_infos() -> CheckResult<Vec<NativeMapInfo>> {
    let mut infos = Vec::new();
    let mut current = 0_u32;
    loop {
        let mut next = 0_u32;
        // SAFETY: next points to writable u32 storage for the duration of the call.
        let code = unsafe { lmyz_xdp_map_get_next_id(current, &mut next) };
        match code {
            0 => break,
            1 => {
                infos.push(map_info_by_id(next)?);
                current = next;
            }
            error => return Err(failure(format!("BPF map enumeration failed: {error}"))),
        }
        require(
            infos.len() <= 65_536,
            "BPF map enumeration exceeded its hard limit",
        )?;
    }
    Ok(infos)
}

fn map_info_by_id(id: u32) -> CheckResult<NativeMapInfo> {
    let mut info = NativeMapInfo::default();
    // SAFETY: info points to writable storage with the layout asserted below.
    let code = unsafe { lmyz_xdp_map_info_by_id(id, &mut info) };
    require(code == 0, format!("BPF map {id} info query failed: {code}"))?;
    Ok(info)
}

fn map_info_by_pin(path: &Path) -> CheckResult<NativeMapInfo> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| failure("BPF pin path contains NUL"))?;
    let mut info = NativeMapInfo::default();
    // SAFETY: path is NUL-terminated and info is valid writable storage.
    let code = unsafe { lmyz_xdp_map_info_by_pin(path.as_ptr(), &mut info) };
    require(
        code == 0,
        format!("BPF pinned map info query failed: {code}"),
    )?;
    Ok(info)
}

fn map_name(info: &NativeMapInfo) -> CheckResult<String> {
    // SAFETY: the C shim zeroes the complete struct before copying the kernel's
    // fixed-width BPF object name, so the buffer is NUL-terminated.
    Ok(unsafe { CStr::from_ptr(info.name.as_ptr()) }
        .to_str()?
        .to_owned())
}

async fn attached_program_id(interface: &str) -> CheckResult<Option<u64>> {
    let args = ["-j", "-details", "link", "show", "dev", interface];
    let value = run_json("ip", &args).await?;
    let Some(info) = first_object(&value) else {
        return Ok(None);
    };
    let Some(xdp) = info.get("xdp") else {
        return Ok(None);
    };
    Ok(integer(xdp, &["prog_id", "id"]).or_else(|| find_integer(xdp, &["prog_id", "id"])))
}

fn first_object(value: &Value) -> Option<&Value> {
    match value {
        Value::Object(_) => Some(value),
        Value::Array(items) => items.iter().find(|item| item.is_object()),
        _ => None,
    }
}

fn find_integer(value: &Value, names: &[&str]) -> Option<u64> {
    if let Some(value) = integer(value, names) {
        return Some(value);
    }
    match value {
        Value::Array(items) => items.iter().find_map(|item| find_integer(item, names)),
        Value::Object(fields) => fields.values().find_map(|item| find_integer(item, names)),
        _ => None,
    }
}

fn integer(value: &Value, names: &[&str]) -> Option<u64> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_u64))
}

async fn run_json(program: &str, args: &[&str]) -> CheckResult<Value> {
    let output = run_output(program, args).await?;
    require(
        output.status.success(),
        format!(
            "{} {} failed with {}; stderr={}",
            program,
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    )?;
    Ok(serde_json::from_slice(&output.stdout)?)
}

async fn run_output(program: &str, args: &[&str]) -> CheckResult<Output> {
    timeout(
        COMMAND_DEADLINE,
        Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| failure(format!("{program} {} timed out", args.join(" "))))?
    .map_err(Into::into)
}

fn require(condition: bool, message: impl Into<String>) -> CheckResult<()> {
    if condition {
        Ok(())
    } else {
        Err(failure(message))
    }
}

fn failure(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(CheckFailure(message.into()))
}

fn executable_in_path(name: &str) -> bool {
    env::var_os("PATH").is_some_and(|path| {
        env::split_paths(&path).any(|directory| {
            let candidate = directory.join(name);
            candidate.is_file()
        })
    })
}

unsafe extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
    fn lmyz_xdp_map_get_next_id(start_id: u32, next_id: *mut u32) -> c_int;
    fn lmyz_xdp_map_info_by_id(id: u32, info: *mut NativeMapInfo) -> c_int;
    fn lmyz_xdp_map_info_by_pin(path: *const c_char, info: *mut NativeMapInfo) -> c_int;
}

const _: () = assert!(std::mem::size_of::<NativeMapInfo>() == 40);
