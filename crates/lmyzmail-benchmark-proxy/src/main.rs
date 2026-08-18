use lmyzmail_benchmark_proxy::{
    CalibrationConfig, CalibrationMode, DEFAULT_PROXY_MAX_CONNECTIONS,
    DEFAULT_PROXY_MEMORY_BUDGET_MIB, HEADROOM_NOFILE_RESERVE, HeadroomAttestationConfig,
    HeadroomEnvironment, ObserverHub, ObserverLimits, ProxyConfig, ProxyServer, ProxyTelemetry,
    formal_headroom_nofile_required, formal_headroom_tiers, hex_sha256,
    publish_headroom_attestation, run_calibration, run_headroom_attestation, serve_control,
};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::watch;

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), BoxError> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().ok_or_else(usage_error)?;
    let options = parse_options(arguments.collect())?;
    match command.as_str() {
        "proxy" => run_proxy_command(options).await,
        "calibrate" => run_calibration_command(options).await,
        "headroom-attest" => run_headroom_attestation_command(options).await,
        _ => Err(usage_error()),
    }
}

async fn run_headroom_attestation_command(
    options: BTreeMap<String, String>,
) -> Result<(), BoxError> {
    reject_unknown(
        &options,
        &[
            "--output-root",
            "--runner-sha256",
            "--source-tree-sha256",
            "--cgroup-parent",
            "--process-cgroup",
            "--benchmark-cpu",
            "--calibration-cpus",
            "--io-device",
            "--backing-device",
            "--io-bytes-per-second",
            "--memory-max-bytes",
            "--pids-max",
            "--nofile-soft-and-hard",
            "--minimum-product-headroom-ratio",
        ],
    )?;
    let output_root = PathBuf::from(required(&options, "--output-root")?);
    let runner_sha256 = required(&options, "--runner-sha256")?.to_owned();
    let source_tree_sha256 = required(&options, "--source-tree-sha256")?.to_owned();
    let cgroup_parent = PathBuf::from(required(&options, "--cgroup-parent")?);
    let process_cgroup = PathBuf::from(required(&options, "--process-cgroup")?);
    let benchmark_cpu = required(&options, "--benchmark-cpu")?.parse::<usize>()?;
    let calibration_cpus = required(&options, "--calibration-cpus")?.to_owned();
    let io_device = required(&options, "--io-device")?.to_owned();
    let backing_device = required(&options, "--backing-device")?.to_owned();
    let io_bytes_per_second_per_device =
        required(&options, "--io-bytes-per-second")?.parse::<u64>()?;
    let memory_max_bytes = required(&options, "--memory-max-bytes")?.parse::<u64>()?;
    let pids_max = required(&options, "--pids-max")?.parse::<u64>()?;
    let nofile_soft_and_hard = required(&options, "--nofile-soft-and-hard")?.parse::<u64>()?;
    let minimum_product_headroom_ratio =
        optional_parse(&options, "--minimum-product-headroom-ratio", 2.0_f64)?;
    // `/proc/self/exe` remains bound to the mapped executable inode even if
    // the workspace path is replaced while a long calibration is running.
    let binary_sha256 = hex_sha256(&fs::read("/proc/self/exe")?);
    let environment = collect_headroom_environment(
        benchmark_cpu,
        &calibration_cpus,
        &cgroup_parent,
        &process_cgroup,
        &io_device,
        &backing_device,
        io_bytes_per_second_per_device,
        memory_max_bytes,
        pids_max,
        nofile_soft_and_hard,
    )?;
    let report = run_headroom_attestation(
        HeadroomAttestationConfig {
            runner_sha256,
            binary_sha256,
            source_tree_sha256,
            environment,
            minimum_product_headroom_ratio,
            tiers: formal_headroom_tiers(),
        },
        ObserverLimits::default(),
    )
    .await?;
    if !report.proxy_headroom.passed {
        let tiers = report
            .proxy_headroom
            .tiers
            .iter()
            .map(|(label, tier)| {
                let on_gate_timings = tier
                    .gate_overhead_calibration
                    .on_rounds
                    .iter()
                    .map(|round| {
                        let gate = &round.observer.persistence_gate;
                        json!({
                            "round_duration_ns": round.measurement.duration_ns,
                            "gate_hold_ns": gate.gate_hold_ns,
                            "release_to_forwarding_started_ns": gate
                                .forwarding_started_at_proxy_monotonic_ns
                                .zip(gate.release_received_at_proxy_monotonic_ns)
                                .map(|(started, released)| started.saturating_sub(released)),
                            "forwarding_duration_ns": gate
                                .forwarding_completed_at_proxy_monotonic_ns
                                .zip(gate.forwarding_started_at_proxy_monotonic_ns)
                                .map(|(completed, started)| completed.saturating_sub(started)),
                        })
                    })
                    .collect::<Vec<_>>();
                (
                    label,
                    json!({
                        "passed": tier.passed,
                        "sustained_messages_per_second": tier.sustained_messages_per_second,
                        "raw": {
                            "qualification": tier.raw_calibration.qualification,
                            "proxy_to_direct_ratio": tier.raw_calibration.proxy_to_direct_ratio,
                            "minimum_proxy_to_direct_ratio": tier.raw_calibration.minimum_proxy_to_direct_ratio,
                            "direct_round_spread": tier.raw_calibration.direct_round_spread,
                            "proxied_round_spread": tier.raw_calibration.proxied_round_spread,
                            "maximum_round_spread": tier.raw_calibration.maximum_round_spread,
                            "observer_qualification": tier.raw_calibration.observer.qualification,
                            "observer_verified": tier.raw_calibration.observer.verified,
                            "proxy_failed_connections": tier.raw_calibration.proxy.failed_connections,
                            "proxy_peak_connections": tier.raw_calibration.proxy.peak_connections,
                        },
                        "persistence_gate": {
                            "qualification": tier.gate_overhead_calibration.qualification,
                            "median_on_to_off_ratio": tier.gate_overhead_calibration.median_on_to_off_ratio,
                            "minimum_median_on_to_off_ratio": tier.gate_overhead_calibration.minimum_median_on_to_off_ratio,
                            "paired_on_to_off_ratios": tier.gate_overhead_calibration.paired_on_to_off_ratios,
                            "minimum_paired_on_to_off_ratio": tier.gate_overhead_calibration.minimum_paired_on_to_off_ratio,
                            "off_round_spread": tier.gate_overhead_calibration.off_round_spread,
                            "on_round_spread": tier.gate_overhead_calibration.on_round_spread,
                            "maximum_round_spread": tier.gate_overhead_calibration.maximum_round_spread,
                            "on_gate_timings": on_gate_timings,
                        },
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "proxy-headroom-failed",
                "passed": report.proxy_headroom.passed,
                "semantic_transparency_passed": report.proxy_headroom.semantic_transparency_passed,
                "max_active_connections": report.proxy_headroom.max_active_connections,
                "minimum_product_headroom_ratio": report.proxy_headroom.minimum_product_headroom_ratio,
                "tiers": tiers,
            }))?
        );
        return Err("proxy headroom attestation did not qualify".into());
    }
    let published = publish_headroom_attestation(&output_root, &report)?;
    println!("{}", published.path.display());
    println!("{}", published.sha256);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_headroom_environment(
    benchmark_cpu: usize,
    calibration_cpus: &str,
    cgroup_parent: &Path,
    process_cgroup: &Path,
    io_device: &str,
    backing_device: &str,
    io_bytes_per_second_per_device: u64,
    memory_max_bytes: u64,
    pids_max: u64,
    nofile_soft_and_hard: u64,
) -> Result<HeadroomEnvironment, BoxError> {
    let cgroup_parent = cgroup_parent.canonicalize()?;
    let process_cgroup = process_cgroup.canonicalize()?;
    if !process_cgroup.starts_with(&cgroup_parent) {
        return Err("headroom process cgroup is outside its formal parent".into());
    }
    let self_cgroup = fs::read_to_string("/proc/self/cgroup")?;
    let unified = self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("unified process cgroup is unavailable")?;
    let actual_process_cgroup = Path::new("/sys/fs/cgroup")
        .join(unified.trim_start_matches('/'))
        .canonicalize()?;
    if actual_process_cgroup != process_cgroup {
        return Err("headroom producer is not running in its attested cgroup".into());
    }
    let cpuset_cpus_effective = read_trimmed(process_cgroup.join("cpuset.cpus.effective"))?;
    let self_status = fs::read_to_string("/proc/self/status")?;
    let status_cpus = self_status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:\t"))
        .map(str::trim)
        .ok_or("process CPU affinity is unavailable")?;
    if cpuset_cpus_effective != calibration_cpus || status_cpus != calibration_cpus {
        return Err("headroom producer CPU affinity differs from its cgroup cpuset".into());
    }
    let io_max_payload = fs::read(cgroup_parent.join("io.max"))?;
    let mut io_max_lines = String::from_utf8(io_max_payload.clone())?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    io_max_lines.sort();
    if read_trimmed(cgroup_parent.join("memory.max"))?.parse::<u64>()? != memory_max_bytes
        || read_trimmed(cgroup_parent.join("memory.swap.max"))?.parse::<u64>()? != 0
        || read_trimmed(cgroup_parent.join("pids.max"))?.parse::<u64>()? != pids_max
    {
        return Err("headroom producer inherited different memory or PID limits".into());
    }
    verify_nofile_limit(nofile_soft_and_hard)?;
    Ok(HeadroomEnvironment {
        host_boot_id: read_trimmed(PathBuf::from("/proc/sys/kernel/random/boot_id"))?,
        benchmark_cpu,
        calibration_cpus: calibration_cpus.to_owned(),
        cgroup_parent: cgroup_parent.display().to_string(),
        process_cgroup: process_cgroup.display().to_string(),
        cpuset_cpus_effective,
        io_bytes_per_second_per_device,
        io_device: io_device.to_owned(),
        backing_device: backing_device.to_owned(),
        io_max_lines,
        io_max_sha256: hex_sha256(&io_max_payload),
        memory_max_bytes,
        memory_swap_max_bytes: 0,
        pids_max,
        nofile_soft_and_hard,
        nofile_required: formal_headroom_nofile_required(),
        nofile_reserve: HEADROOM_NOFILE_RESERVE,
    })
}

fn read_trimmed(path: PathBuf) -> Result<String, BoxError> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn verify_nofile_limit(expected: u64) -> Result<(), BoxError> {
    let self_limits = fs::read_to_string("/proc/self/limits")?;
    let fields = self_limits
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .ok_or("process open-file limit is unavailable")?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if fields.len() < 5
        || fields[3].parse::<u64>()? != expected
        || fields[4].parse::<u64>()? != expected
    {
        return Err("headroom producer open-file limit differs from formal topology".into());
    }
    Ok(())
}

async fn run_proxy_command(options: BTreeMap<String, String>) -> Result<(), BoxError> {
    reject_unknown(
        &options,
        &[
            "--listen",
            "--backend",
            "--control",
            "--max-connections",
            "--memory-budget-mib",
        ],
    )?;
    let listen = required(&options, "--listen")?.parse::<SocketAddr>()?;
    let backend = required(&options, "--backend")?.parse::<SocketAddr>()?;
    let control = PathBuf::from(required(&options, "--control")?);
    let max_connections =
        optional_parse(&options, "--max-connections", DEFAULT_PROXY_MAX_CONNECTIONS)?;
    let memory_budget_mib = optional_parse(
        &options,
        "--memory-budget-mib",
        DEFAULT_PROXY_MEMORY_BUDGET_MIB,
    )?;
    let memory_budget_bytes = memory_budget_mib
        .checked_mul(1024 * 1024)
        .ok_or("proxy memory budget overflowed")?;
    let observer = ObserverHub::new(ObserverLimits::default())?;
    let telemetry = ProxyTelemetry::shared();
    let proxy = ProxyServer::bind(
        ProxyConfig {
            listen,
            backend,
            max_connections,
            memory_budget_bytes,
            shutdown_grace: Duration::from_secs(30),
        },
        observer.clone(),
        telemetry.clone(),
    )
    .await?;
    let local_addr = proxy.local_addr()?;
    let (proxy_shutdown_tx, proxy_shutdown_rx) = watch::channel(false);
    let proxy_shutdown_state = proxy_shutdown_rx.clone();
    let (control_shutdown_tx, control_shutdown_rx) = watch::channel(false);
    let (proxy_stopped_tx, proxy_stopped_rx) = watch::channel(false);
    let mut proxy_task = tokio::spawn(async move {
        let result = proxy.serve(proxy_shutdown_rx).await;
        proxy_stopped_tx.send(true).ok();
        result
    });
    let mut control_task = tokio::spawn(serve_control(
        control.clone(),
        observer,
        telemetry,
        proxy_shutdown_tx.clone(),
        control_shutdown_tx.clone(),
        control_shutdown_rx,
        proxy_stopped_rx,
    ));
    wait_for_control_socket(&control, &mut control_task).await?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "status": "ready",
            "listen": local_addr,
            "backend": backend,
            "control": control,
            "max_connections": max_connections,
            "memory_budget_bytes": memory_budget_bytes,
        }))?
    );
    std::io::stdout().flush()?;

    tokio::select! {
        proxy_result = &mut proxy_task => {
            if !*proxy_shutdown_state.borrow() {
                control_shutdown_tx.send(true).ok();
            }
            let proxy_result = proxy_result?;
            let control_result = (&mut control_task).await?;
            proxy_result?;
            control_result?;
        }
        control_result = &mut control_task => {
            proxy_shutdown_tx.send(true).ok();
            let control_result = control_result?;
            let proxy_result = (&mut proxy_task).await?;
            control_result?;
            proxy_result?;
        }
        signal_result = shutdown_signal() => {
            signal_result?;
            proxy_shutdown_tx.send(true).ok();
            control_shutdown_tx.send(true).ok();
            let proxy_result = (&mut proxy_task).await?;
            let control_result = (&mut control_task).await?;
            proxy_result?;
            control_result?;
        }
    }
    Ok(())
}

async fn shutdown_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        signal = terminate.recv() => signal
            .map(|_| ())
            .ok_or_else(|| std::io::Error::other("SIGTERM handler closed unexpectedly")),
    }
}

async fn run_calibration_command(options: BTreeMap<String, String>) -> Result<(), BoxError> {
    reject_unknown(
        &options,
        &[
            "--messages",
            "--message-bytes",
            "--concurrency",
            "--mode",
            "--minimum-ratio",
            "--rounds",
            "--maximum-spread",
            "--output",
        ],
    )?;
    let messages = optional_parse(&options, "--messages", 100_000_usize)?;
    let message_bytes = optional_parse(&options, "--message-bytes", 10 * 1_024_usize)?;
    let concurrency = optional_parse(&options, "--concurrency", 100_usize)?;
    let mode =
        CalibrationMode::from_str(options.get("--mode").map(String::as_str).unwrap_or("data"))?;
    let minimum_proxy_to_direct_ratio = optional_parse(&options, "--minimum-ratio", 0.90_f64)?;
    let rounds_per_arm = optional_parse(&options, "--rounds", 4_usize)?;
    let maximum_round_spread = optional_parse(&options, "--maximum-spread", 0.20_f64)?;
    let output = PathBuf::from(required(&options, "--output")?);
    let report = run_calibration(
        CalibrationConfig {
            messages,
            message_bytes,
            concurrency,
            mode,
            minimum_proxy_to_direct_ratio,
            rounds_per_arm,
            maximum_round_spread,
        },
        ObserverLimits::default(),
    )
    .await?;
    write_json_new(&output, &report)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": if report.qualification { "passed" } else { "failed" },
            "output": output,
            "proxy_to_direct_ratio": report.proxy_to_direct_ratio,
            "observer_verified": report.observer.verified,
        }))?
    );
    if report.qualification {
        Ok(())
    } else {
        Err("proxy calibration did not meet its qualification gate".into())
    }
}

fn parse_options(arguments: Vec<String>) -> Result<BTreeMap<String, String>, BoxError> {
    if !arguments.len().is_multiple_of(2) {
        return Err("every command option must have one value".into());
    }
    let mut output = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        if !pair[0].starts_with("--") {
            return Err(format!("invalid option name: {}", pair[0]).into());
        }
        if output.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err(format!("duplicate option: {}", pair[0]).into());
        }
    }
    Ok(output)
}

fn reject_unknown(options: &BTreeMap<String, String>, known: &[&str]) -> Result<(), BoxError> {
    if let Some(name) = options.keys().find(|name| !known.contains(&name.as_str())) {
        return Err(format!("unknown option: {name}").into());
    }
    Ok(())
}

fn required<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, BoxError> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required option: {name}").into())
}

fn optional_parse<T>(
    options: &BTreeMap<String, String>,
    name: &str,
    default: T,
) -> Result<T, BoxError>
where
    T: FromStr,
    T::Err: Error + Send + Sync + 'static,
{
    options
        .get(name)
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|error| Box::new(error) as BoxError)
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

async fn wait_for_control_socket(
    path: &Path,
    task: &mut tokio::task::JoinHandle<std::io::Result<()>>,
) -> Result<(), BoxError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if path.exists() {
            return Ok(());
        }
        if task.is_finished() {
            return match task.await {
                Ok(Ok(())) => Err("control server exited before creating its socket".into()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            };
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("control server did not create its socket before deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), BoxError> {
    if !path.is_absolute() {
        return Err("calibration output path must be absolute".into());
    }
    let parent = path
        .parent()
        .ok_or("calibration output path has no parent")?;
    if !parent.is_dir() {
        return Err("calibration output parent does not exist".into());
    }
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut output, value)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn usage_error() -> BoxError {
    "usage: lmyzmail-benchmark-proxy proxy --listen ADDR --backend ADDR --control PATH [--max-connections N] [--memory-budget-mib N]\n       lmyzmail-benchmark-proxy calibrate --output PATH [--messages N] [--message-bytes N] [--concurrency N] [--mode data|bdat] [--minimum-ratio R] [--rounds N] [--maximum-spread R]\n       lmyzmail-benchmark-proxy headroom-attest --output-root PATH --runner-sha256 SHA --source-tree-sha256 SHA --cgroup-parent PATH --process-cgroup PATH --benchmark-cpu N --calibration-cpus LIST --io-device MAJ:MIN --backing-device MAJ:MIN --io-bytes-per-second N --memory-max-bytes N --pids-max N --nofile-soft-and-hard N"
        .into()
}
