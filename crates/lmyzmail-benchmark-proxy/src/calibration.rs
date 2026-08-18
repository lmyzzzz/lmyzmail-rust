use crate::control::serve_control;
use crate::observer::{
    ObserverHub, ObserverLimits, PersistenceSnapshotEvidence, RoundSpec, RoundSummary,
};
use crate::proxy::{ProxyConfig, ProxyServer, ProxySnapshot, ProxyTelemetry, bind_tcp_listener};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{Barrier, watch};
use tokio::task::JoinSet;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub const RAW_CALIBRATION_SCHEMA_VERSION: u32 = 4;
const CALIBRATION_ROUND: u64 = 1;
const MAX_CALIBRATION_CONNECTIONS: usize = 2_048;
const CALIBRATION_STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const CALIBRATION_RUN_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const CALIBRATION_SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(35);
const CALIBRATION_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const CALIBRATION_MEMORY_BUDGET_BYTES: usize = 2 * 1024 * 1024 * 1024;
const GATE_CALIBRATION_ROUNDS_PER_MODE: usize = 4;
const MAXIMUM_GATE_CALIBRATION_SPREAD: f64 = 0.01;
const MINIMUM_GATE_CALIBRATION_MEDIAN_RATIO: f64 = 0.995;
const MINIMUM_GATE_CALIBRATION_PAIRED_RATIO: f64 = 0.99;
const MAXIMUM_GATE_HOLD_FRACTION: f64 = 0.01;
const MAXIMUM_GATE_RELEASE_TO_FORWARDING_NS: u64 = 5_000_000;
const MAXIMUM_GATE_FORWARDING_NS: u64 = 1_000_000;
static GATE_CALIBRATION_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CalibrationMode {
    Data,
    Bdat,
}

#[derive(Clone, Copy, Debug)]
enum CalibrationArm {
    Direct,
    Proxied,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum GateCalibrationArm {
    Off,
    On,
}

impl GateCalibrationArm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }
}

impl CalibrationArm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Proxied => "proxied",
        }
    }
}

impl FromStr for CalibrationMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "data" => Ok(Self::Data),
            "bdat" => Ok(Self::Bdat),
            _ => Err("calibration mode must be data or bdat".into()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CalibrationConfig {
    pub messages: usize,
    pub message_bytes: usize,
    pub concurrency: usize,
    pub mode: CalibrationMode,
    pub minimum_proxy_to_direct_ratio: f64,
    pub rounds_per_arm: usize,
    pub maximum_round_spread: f64,
}

impl CalibrationConfig {
    pub fn validate(&self, limits: &ObserverLimits) -> Result<(), String> {
        if self.messages == 0 || self.messages > 1_100_000 {
            return Err("calibration messages must be between 1 and 1100000".into());
        }
        if self.message_bytes < 1_024 || self.message_bytes > limits.max_message_bytes {
            return Err("calibration message size is outside [1 KiB, max_message_bytes]".into());
        }
        if self.concurrency == 0
            || self.concurrency > MAX_CALIBRATION_CONNECTIONS
            || self.concurrency > self.messages
        {
            return Err("calibration concurrency is outside its fixed bound".into());
        }
        let observed_messages = self
            .messages
            .checked_mul(self.rounds_per_arm)
            .ok_or_else(|| "calibration round message count overflowed".to_owned())?;
        if self.rounds_per_arm < 3 || self.rounds_per_arm > 9 || observed_messages > 1_100_000 {
            return Err(
                "calibration requires 3..=9 rounds per arm and at most 1100000 observed messages"
                    .into(),
            );
        }
        if !self.minimum_proxy_to_direct_ratio.is_finite()
            || !(0.5..=1.0).contains(&self.minimum_proxy_to_direct_ratio)
        {
            return Err("minimum calibration ratio must be finite and between 0.5 and 1.0".into());
        }
        if !self.maximum_round_spread.is_finite()
            || !(0.01..=1.0).contains(&self.maximum_round_spread)
        {
            return Err("maximum calibration round spread must be between 0.01 and 1.0".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CalibrationMeasurement {
    pub messages: usize,
    pub message_bytes: usize,
    pub duration_ns: u64,
    pub messages_per_second: f64,
    pub mebibytes_per_second: f64,
    pub process_scheduled_cpu_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CalibrationReport {
    pub schema_version: u32,
    pub control_topology: &'static str,
    pub observed_topology: &'static str,
    pub equal_tcp_hop_topology: bool,
    pub mode: CalibrationMode,
    pub messages: usize,
    pub message_bytes: usize,
    pub concurrency: usize,
    pub rounds_per_arm: usize,
    pub sequence: Vec<String>,
    pub direct_rounds: Vec<CalibrationMeasurement>,
    pub proxied_rounds: Vec<CalibrationMeasurement>,
    pub direct: CalibrationMeasurement,
    pub proxied: CalibrationMeasurement,
    pub proxy_to_direct_ratio: f64,
    pub direct_round_spread: f64,
    pub proxied_round_spread: f64,
    pub maximum_round_spread: f64,
    pub estimated_observer_cpu_ns_per_message: f64,
    pub minimum_proxy_to_direct_ratio: f64,
    pub control_proxy: ProxySnapshot,
    pub proxy: ProxySnapshot,
    pub observer: RoundSummary,
    pub qualification: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct GateCalibrationRound {
    pub mode: String,
    pub mode_ordinal: usize,
    pub sequence_index: usize,
    pub measurement: CalibrationMeasurement,
    pub proxy: ProxySnapshot,
    pub observer: RoundSummary,
}

#[derive(Clone, Debug, Serialize)]
pub struct GateOverheadCalibrationReport {
    pub schema_version: u32,
    pub profile: &'static str,
    pub qualification_basis: &'static str,
    pub synthetic_no_postgres_or_maildir: bool,
    pub messages: usize,
    pub message_bytes: usize,
    pub concurrency: usize,
    pub rounds_per_mode: usize,
    pub sequence: Vec<String>,
    pub off_rounds: Vec<GateCalibrationRound>,
    pub on_rounds: Vec<GateCalibrationRound>,
    pub off_median: CalibrationMeasurement,
    pub on_median: CalibrationMeasurement,
    pub off_round_spread: f64,
    pub on_round_spread: f64,
    pub median_on_to_off_ratio: f64,
    pub paired_on_to_off_ratios: Vec<f64>,
    pub maximum_round_spread: f64,
    pub minimum_median_on_to_off_ratio: f64,
    pub minimum_paired_on_to_off_ratio: f64,
    pub observed_maximum_gate_hold_fraction: f64,
    pub maximum_gate_hold_fraction: f64,
    pub observed_maximum_release_to_forwarding_ns: u64,
    pub maximum_release_to_forwarding_ns: u64,
    pub observed_maximum_forwarding_ns: u64,
    pub maximum_forwarding_ns: u64,
    pub binding: Value,
    pub qualification: bool,
}

pub async fn run_calibration(
    config: CalibrationConfig,
    limits: ObserverLimits,
) -> Result<CalibrationReport, BoxError> {
    limits.validate()?;
    config.validate(&limits)?;
    let (backend_addr, backend_shutdown, backend_task) = start_synthetic_backend().await?;
    let (control_addr, control_shutdown, control_task, control_telemetry) =
        match start_unobserved_control_proxy(
            backend_addr,
            config.concurrency.max(16),
            limits.clone(),
        )
        .await
        {
            Ok(control) => control,
            Err(error) => {
                let _ = stop_service(backend_shutdown, backend_task).await;
                return Err(error);
            }
        };
    let observer = match ObserverHub::new(limits) {
        Ok(observer) => observer,
        Err(error) => {
            let _ = stop_service(control_shutdown, control_task).await;
            let _ = stop_service(backend_shutdown, backend_task).await;
            return Err(error.into());
        }
    };
    if let Err(error) = observer.begin(RoundSpec {
        run_id: "synthetic-proxy-calibration".into(),
        expected_messages: config
            .messages
            .checked_mul(config.rounds_per_arm)
            .ok_or("calibration observed message count overflowed")?,
        message_bytes: config.message_bytes,
        expected_sender: crate::observer::DEFAULT_SENDER.into(),
        expected_receiver: crate::observer::DEFAULT_RECEIVER.into(),
    }) {
        let _ = stop_service(control_shutdown, control_task).await;
        let _ = stop_service(backend_shutdown, backend_task).await;
        return Err(error.into());
    }
    let telemetry = ProxyTelemetry::shared();
    let (proxy_shutdown, proxy_shutdown_rx) = watch::channel(false);
    let proxy = match ProxyServer::bind(
        ProxyConfig {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            backend: backend_addr,
            max_connections: config.concurrency.max(16),
            memory_budget_bytes: CALIBRATION_MEMORY_BUDGET_BYTES,
            shutdown_grace: Duration::from_secs(30),
        },
        observer.clone(),
        telemetry.clone(),
    )
    .await
    {
        Ok(proxy) => proxy,
        Err(error) => {
            let _ = stop_service(control_shutdown, control_task).await;
            let _ = stop_service(backend_shutdown, backend_task).await;
            return Err(error);
        }
    };
    let proxy_addr = match proxy.local_addr() {
        Ok(address) => address,
        Err(error) => {
            drop(proxy);
            let _ = stop_service(control_shutdown, control_task).await;
            let _ = stop_service(backend_shutdown, backend_task).await;
            return Err(error.into());
        }
    };
    let proxy_task = tokio::spawn(proxy.serve(proxy_shutdown_rx));
    let sequence = balanced_sequence(config.rounds_per_arm);
    let mut direct_rounds = Vec::with_capacity(config.rounds_per_arm);
    let mut proxied_rounds = Vec::with_capacity(config.rounds_per_arm);
    let mut proxied_index = 0_usize;
    for arm in &sequence {
        let result = match arm {
            CalibrationArm::Direct => run_load(control_addr, &config, 0, arm.as_str()).await,
            CalibrationArm::Proxied => {
                let offset = proxied_index * config.messages;
                proxied_index += 1;
                run_load(proxy_addr, &config, offset, arm.as_str()).await
            }
        };
        match result {
            Ok(measurement) => match arm {
                CalibrationArm::Direct => direct_rounds.push(measurement),
                CalibrationArm::Proxied => proxied_rounds.push(measurement),
            },
            Err(error) => {
                let _ = stop_service(proxy_shutdown, proxy_task).await;
                let _ = stop_service(control_shutdown, control_task).await;
                let _ = stop_service(backend_shutdown, backend_task).await;
                return Err(error);
            }
        }
        let arm_telemetry = match arm {
            CalibrationArm::Direct => &control_telemetry,
            CalibrationArm::Proxied => &telemetry,
        };
        if let Err(error) = wait_for_proxy_idle(arm_telemetry, arm.as_str()).await {
            let _ = stop_service(proxy_shutdown, proxy_task).await;
            let _ = stop_service(control_shutdown, control_task).await;
            let _ = stop_service(backend_shutdown, backend_task).await;
            return Err(error.into());
        }
    }
    let reached = observer.wait_until_expected(Duration::from_secs(30)).await;
    let proxy_result = stop_service(proxy_shutdown, proxy_task).await;
    let proxy_snapshot = telemetry.snapshot();
    let observer_summary = observer.finalize();
    let control_result = stop_service(control_shutdown, control_task).await;
    let control_snapshot = control_telemetry.snapshot();
    let backend_result = stop_service(backend_shutdown, backend_task).await;
    let observer_summary = observer_summary?;
    proxy_result?;
    control_result?;
    backend_result?;

    let direct = median_measurement(&direct_rounds)?;
    let proxied = median_measurement(&proxied_rounds)?;
    let ratio = if direct.messages_per_second > 0.0 {
        proxied.messages_per_second / direct.messages_per_second
    } else {
        0.0
    };
    let direct_spread = relative_spread(&direct_rounds, direct.messages_per_second);
    let proxied_spread = relative_spread(&proxied_rounds, proxied.messages_per_second);
    let estimated_observer_cpu_ns_per_message = proxied
        .process_scheduled_cpu_ns
        .saturating_sub(direct.process_scheduled_cpu_ns)
        as f64
        / config.messages as f64;
    let expected_connections: u64 = config
        .concurrency
        .checked_mul(config.rounds_per_arm)
        .ok_or("calibration connection count overflowed")?
        .try_into()?;
    let qualification = reached
        && observer_summary.qualification
        && control_snapshot.accepted_connections == expected_connections
        && control_snapshot.completed_connections == expected_connections
        && control_snapshot.failed_connections == 0
        && control_snapshot.active_connections == 0
        && control_snapshot.peak_connections == config.concurrency
        && proxy_snapshot.accepted_connections == expected_connections
        && proxy_snapshot.completed_connections == expected_connections
        && proxy_snapshot.failed_connections == 0
        && proxy_snapshot.active_connections == 0
        && proxy_snapshot.peak_connections == config.concurrency
        && ratio >= config.minimum_proxy_to_direct_ratio
        && direct_spread <= config.maximum_round_spread
        && proxied_spread <= config.maximum_round_spread;
    Ok(CalibrationReport {
        schema_version: RAW_CALIBRATION_SCHEMA_VERSION,
        control_topology: "bounded-unobserved-proxy",
        observed_topology: "bounded-observing-proxy",
        equal_tcp_hop_topology: true,
        mode: config.mode,
        messages: config.messages,
        message_bytes: config.message_bytes,
        concurrency: config.concurrency,
        rounds_per_arm: config.rounds_per_arm,
        sequence: sequence
            .into_iter()
            .map(|arm| arm.as_str().to_owned())
            .collect(),
        direct_rounds,
        proxied_rounds,
        direct,
        proxied,
        proxy_to_direct_ratio: ratio,
        direct_round_spread: direct_spread,
        proxied_round_spread: proxied_spread,
        maximum_round_spread: config.maximum_round_spread,
        estimated_observer_cpu_ns_per_message,
        minimum_proxy_to_direct_ratio: config.minimum_proxy_to_direct_ratio,
        control_proxy: control_snapshot,
        proxy: proxy_snapshot,
        observer: observer_summary,
        qualification,
    })
}

pub async fn run_gate_overhead_calibration(
    messages: usize,
    message_bytes: usize,
    concurrency: usize,
    limits: ObserverLimits,
    binding: Value,
) -> Result<GateOverheadCalibrationReport, BoxError> {
    limits.validate()?;
    if messages == 0
        || concurrency == 0
        || concurrency > messages
        || concurrency > MAX_CALIBRATION_CONNECTIONS
        || message_bytes < 1_024
        || message_bytes > limits.max_message_bytes
    {
        return Err("gate calibration shape is outside its fixed bounds".into());
    }
    const SEQUENCE: [GateCalibrationArm; 8] = [
        GateCalibrationArm::Off,
        GateCalibrationArm::On,
        GateCalibrationArm::On,
        GateCalibrationArm::Off,
        GateCalibrationArm::On,
        GateCalibrationArm::Off,
        GateCalibrationArm::Off,
        GateCalibrationArm::On,
    ];
    let config = CalibrationConfig {
        messages,
        message_bytes,
        concurrency,
        mode: CalibrationMode::Data,
        minimum_proxy_to_direct_ratio: 0.5,
        rounds_per_arm: GATE_CALIBRATION_ROUNDS_PER_MODE,
        maximum_round_spread: MAXIMUM_GATE_CALIBRATION_SPREAD,
    };
    let (backend_addr, backend_shutdown, backend_task) = start_synthetic_backend().await?;
    let mut off_rounds = Vec::with_capacity(GATE_CALIBRATION_ROUNDS_PER_MODE);
    let mut on_rounds = Vec::with_capacity(GATE_CALIBRATION_ROUNDS_PER_MODE);
    let mut off_ordinal = 0;
    let mut on_ordinal = 0;
    for (sequence_index, arm) in SEQUENCE.into_iter().enumerate() {
        let mode_ordinal = match arm {
            GateCalibrationArm::Off => {
                let ordinal = off_ordinal;
                off_ordinal += 1;
                ordinal
            }
            GateCalibrationArm::On => {
                let ordinal = on_ordinal;
                on_ordinal += 1;
                ordinal
            }
        };
        match run_gate_calibration_arm(
            backend_addr,
            &config,
            limits.clone(),
            arm,
            mode_ordinal,
            sequence_index,
        )
        .await
        {
            Ok(round) => match arm {
                GateCalibrationArm::Off => off_rounds.push(round),
                GateCalibrationArm::On => on_rounds.push(round),
            },
            Err(error) => {
                let _ = stop_service(backend_shutdown, backend_task).await;
                return Err(error);
            }
        }
    }
    stop_service(backend_shutdown, backend_task).await?;
    let off_measurements: Vec<CalibrationMeasurement> = off_rounds
        .iter()
        .map(|round| round.measurement.clone())
        .collect();
    let on_measurements: Vec<CalibrationMeasurement> = on_rounds
        .iter()
        .map(|round| round.measurement.clone())
        .collect();
    let off_median = median_measurement(&off_measurements)?;
    let on_median = median_measurement(&on_measurements)?;
    let off_round_spread = relative_spread(&off_measurements, off_median.messages_per_second);
    let on_round_spread = relative_spread(&on_measurements, on_median.messages_per_second);
    let median_on_to_off_ratio = on_median.messages_per_second / off_median.messages_per_second;
    let paired_on_to_off_ratios: Vec<f64> = (0..GATE_CALIBRATION_ROUNDS_PER_MODE)
        .map(|ordinal| {
            on_rounds[ordinal].measurement.messages_per_second
                / off_rounds[ordinal].measurement.messages_per_second
        })
        .collect();
    let gate_timings = on_rounds
        .iter()
        .map(gate_round_timing)
        .collect::<Result<Vec<_>, _>>()?;
    let observed_maximum_gate_hold_fraction = gate_timings
        .iter()
        .map(|timing| timing.hold_fraction)
        .fold(0.0_f64, f64::max);
    let observed_maximum_release_to_forwarding_ns = gate_timings
        .iter()
        .map(|timing| timing.release_to_forwarding_ns)
        .max()
        .unwrap_or(u64::MAX);
    let observed_maximum_forwarding_ns = gate_timings
        .iter()
        .map(|timing| timing.forwarding_ns)
        .max()
        .unwrap_or(u64::MAX);
    let qualification = off_rounds.len() == GATE_CALIBRATION_ROUNDS_PER_MODE
        && on_rounds.len() == GATE_CALIBRATION_ROUNDS_PER_MODE
        && off_rounds.iter().all(|round| {
            round.observer.qualification
                && !round.observer.persistence_gate.required
                && round.observer.persistence_gate.qualified
                && round.proxy.failed_connections == 0
                && round.proxy.active_connections == 0
        })
        && on_rounds.iter().all(|round| {
            round.observer.qualification
                && round.observer.persistence_gate.required
                && round.observer.persistence_gate.qualified
                && round.proxy.failed_connections == 0
                && round.proxy.active_connections == 0
        })
        && observed_maximum_gate_hold_fraction <= MAXIMUM_GATE_HOLD_FRACTION
        && observed_maximum_release_to_forwarding_ns <= MAXIMUM_GATE_RELEASE_TO_FORWARDING_NS
        && observed_maximum_forwarding_ns <= MAXIMUM_GATE_FORWARDING_NS;
    Ok(GateOverheadCalibrationReport {
        schema_version: 2,
        profile: "lmyzmail-persistence-gate-overhead-calibration-v2",
        qualification_basis: "direct-gate-timing",
        synthetic_no_postgres_or_maildir: true,
        messages,
        message_bytes,
        concurrency,
        rounds_per_mode: GATE_CALIBRATION_ROUNDS_PER_MODE,
        sequence: SEQUENCE
            .into_iter()
            .map(|arm| arm.as_str().to_owned())
            .collect(),
        off_rounds,
        on_rounds,
        off_median,
        on_median,
        off_round_spread,
        on_round_spread,
        median_on_to_off_ratio,
        paired_on_to_off_ratios,
        maximum_round_spread: MAXIMUM_GATE_CALIBRATION_SPREAD,
        minimum_median_on_to_off_ratio: MINIMUM_GATE_CALIBRATION_MEDIAN_RATIO,
        minimum_paired_on_to_off_ratio: MINIMUM_GATE_CALIBRATION_PAIRED_RATIO,
        observed_maximum_gate_hold_fraction,
        maximum_gate_hold_fraction: MAXIMUM_GATE_HOLD_FRACTION,
        observed_maximum_release_to_forwarding_ns,
        maximum_release_to_forwarding_ns: MAXIMUM_GATE_RELEASE_TO_FORWARDING_NS,
        observed_maximum_forwarding_ns,
        maximum_forwarding_ns: MAXIMUM_GATE_FORWARDING_NS,
        binding,
        qualification,
    })
}

struct GateRoundTiming {
    hold_fraction: f64,
    release_to_forwarding_ns: u64,
    forwarding_ns: u64,
}

fn gate_round_timing(round: &GateCalibrationRound) -> Result<GateRoundTiming, BoxError> {
    let gate = &round.observer.persistence_gate;
    let hold_ns = gate
        .gate_hold_ns
        .ok_or("gate round omitted its hold duration")?;
    let release_to_forwarding_ns = gate
        .forwarding_started_at_proxy_monotonic_ns
        .zip(gate.release_received_at_proxy_monotonic_ns)
        .map(|(started, released)| started.saturating_sub(released))
        .ok_or("gate round omitted its release-to-forwarding duration")?;
    let forwarding_ns = gate
        .forwarding_completed_at_proxy_monotonic_ns
        .zip(gate.forwarding_started_at_proxy_monotonic_ns)
        .map(|(completed, started)| completed.saturating_sub(started))
        .ok_or("gate round omitted its forwarding duration")?;
    if round.measurement.duration_ns == 0 {
        return Err("gate round duration was zero".into());
    }
    Ok(GateRoundTiming {
        hold_fraction: hold_ns as f64 / round.measurement.duration_ns as f64,
        release_to_forwarding_ns,
        forwarding_ns,
    })
}

async fn run_gate_calibration_arm(
    backend_addr: SocketAddr,
    config: &CalibrationConfig,
    limits: ObserverLimits,
    arm: GateCalibrationArm,
    mode_ordinal: usize,
    sequence_index: usize,
) -> Result<GateCalibrationRound, BoxError> {
    let observer = ObserverHub::new(limits)?;
    let telemetry = ProxyTelemetry::shared();
    let (proxy_shutdown_tx, proxy_shutdown_rx) = watch::channel(false);
    let (control_shutdown_tx, control_shutdown_rx) = watch::channel(false);
    let (proxy_stopped_tx, proxy_stopped_rx) = watch::channel(false);
    let proxy = ProxyServer::bind(
        ProxyConfig {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            backend: backend_addr,
            max_connections: config.concurrency.max(16),
            memory_budget_bytes: CALIBRATION_MEMORY_BUDGET_BYTES,
            shutdown_grace: Duration::from_secs(30),
        },
        observer.clone(),
        telemetry.clone(),
    )
    .await?;
    let proxy_addr = proxy.local_addr()?;
    let proxy_task = tokio::spawn(async move {
        let result = proxy.serve(proxy_shutdown_rx).await;
        proxy_stopped_tx.send(true).ok();
        result
    });
    let control_root = GateCalibrationControlRoot::new()?;
    let control_path = control_root.path.join("control.sock");
    let control_task = tokio::spawn(serve_control(
        control_path.clone(),
        observer.clone(),
        telemetry.clone(),
        proxy_shutdown_tx,
        control_shutdown_tx,
        control_shutdown_rx,
        proxy_stopped_rx,
    ));
    wait_for_gate_control(&control_path).await?;
    control_command(
        &control_path,
        json!({
            "command": "begin",
            "run_id": format!("gate-calibration-{}-{mode_ordinal}", arm.as_str()),
            "expected_messages": config.messages,
            "message_bytes": config.message_bytes,
            "expected_sender": crate::observer::DEFAULT_SENDER,
            "expected_receiver": crate::observer::DEFAULT_RECEIVER,
            "persistence_gate_required": matches!(arm, GateCalibrationArm::On),
        }),
        Duration::from_secs(5),
    )
    .await?;
    let gate_task = matches!(arm, GateCalibrationArm::On).then(|| {
        let control_path = control_path.clone();
        let expected_messages = config.messages;
        tokio::spawn(async move {
            let response = control_command(
                &control_path,
                json!({
                    "command": "wait_persistence_gate",
                    "timeout_millis": CALIBRATION_RUN_TIMEOUT.as_millis() as u64,
                }),
                CALIBRATION_RUN_TIMEOUT + Duration::from_secs(5),
            )
            .await?;
            let gate_id = response
                .get("persistence_gate")
                .and_then(|gate| gate.get("gate_id"))
                .and_then(Value::as_u64)
                .ok_or("gate calibration control omitted its gate id")?;
            control_command(
                &control_path,
                json!({
                    "command": "release_persistence_gate",
                    "gate_id": gate_id,
                    "snapshot": synthetic_gate_snapshot(expected_messages),
                }),
                Duration::from_secs(5),
            )
            .await?;
            Ok::<(), BoxError>(())
        })
    });
    let measurement_result = run_load(proxy_addr, config, 0, arm.as_str()).await;
    let gate_result = match gate_task {
        Some(task) => Some(task.await?),
        None => None,
    };
    let shutdown_result = control_command(
        &control_path,
        json!({"command": "shutdown"}),
        CALIBRATION_SERVICE_STOP_TIMEOUT,
    )
    .await;
    let proxy_result = tokio::time::timeout(CALIBRATION_SERVICE_STOP_TIMEOUT, proxy_task).await;
    let control_result = tokio::time::timeout(CALIBRATION_SERVICE_STOP_TIMEOUT, control_task).await;
    let measurement = measurement_result?;
    if let Some(result) = gate_result {
        result?;
    }
    shutdown_result?;
    proxy_result.map_err(|_| "gate calibration proxy did not stop")???;
    control_result.map_err(|_| "gate calibration control did not stop")???;
    let proxy = telemetry.snapshot();
    let observer = observer.finalize()?;
    Ok(GateCalibrationRound {
        mode: arm.as_str().to_owned(),
        mode_ordinal,
        sequence_index,
        measurement,
        proxy,
        observer,
    })
}

fn synthetic_gate_snapshot(expected_messages: usize) -> PersistenceSnapshotEvidence {
    PersistenceSnapshotEvidence {
        clock_id: "CLOCK_MONOTONIC".into(),
        snapshot_started_monotonic_ns: 1,
        snapshot_completed_monotonic_ns: 2,
        postgres_query_duration_ns: 0,
        maildir_snapshot_duration_ns: 0,
        transaction_isolation: "repeatable_read".into(),
        transaction_read_only: true,
        postgres_before_rows: 0,
        postgres_rows: expected_messages as i64,
        postgres_expected_rows: expected_messages as i64,
        postgres_row_delta: expected_messages as i64,
        expected_messages,
        maildir_atomic_rename_publications: expected_messages,
        qualified: true,
    }
}

async fn control_command(
    path: &Path,
    command: Value,
    timeout: Duration,
) -> Result<Value, BoxError> {
    let mut stream = tokio::time::timeout(timeout, UnixStream::connect(path)).await??;
    let payload = serde_json::to_vec(&command)?;
    if payload.len() > 64 * 1024 {
        return Err("gate calibration control command exceeded its fixed bound".into());
    }
    stream.write_all(&payload).await?;
    stream.write_all(b"\n").await?;
    let mut reader = BufReader::with_capacity(8 * 1024, stream);
    let mut response = Vec::with_capacity(8 * 1024);
    tokio::time::timeout(timeout, reader.read_until(b'\n', &mut response)).await??;
    if response.len() > 64 * 1024 || !response.ends_with(b"\n") {
        return Err("gate calibration control response was invalid".into());
    }
    let value: Value = serde_json::from_slice(&response[..response.len() - 1])?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("gate calibration control command failed: {value}").into());
    }
    Ok(value)
}

async fn wait_for_gate_control(path: &Path) -> Result<(), BoxError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if path.exists() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("gate calibration control socket did not become ready".into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

struct GateCalibrationControlRoot {
    path: PathBuf,
}

impl GateCalibrationControlRoot {
    fn new() -> io::Result<Self> {
        for _ in 0..1_000 {
            let nonce = GATE_CALIBRATION_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lmyzmail-gate-calibration-{}-{nonce}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique gate calibration control directory",
        ))
    }
}

impl Drop for GateCalibrationControlRoot {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.path.join("control.sock"));
        let _ = fs::remove_dir(&self.path);
    }
}

fn balanced_sequence(rounds_per_arm: usize) -> Vec<CalibrationArm> {
    const ABBA: [CalibrationArm; 4] = [
        CalibrationArm::Direct,
        CalibrationArm::Proxied,
        CalibrationArm::Proxied,
        CalibrationArm::Direct,
    ];
    let mut direct = 0;
    let mut proxied = 0;
    ABBA.into_iter()
        .cycle()
        .filter(|arm| match arm {
            CalibrationArm::Direct if direct < rounds_per_arm => {
                direct += 1;
                true
            }
            CalibrationArm::Proxied if proxied < rounds_per_arm => {
                proxied += 1;
                true
            }
            _ => false,
        })
        .take(rounds_per_arm * 2)
        .collect()
}

fn median_measurement(
    measurements: &[CalibrationMeasurement],
) -> Result<CalibrationMeasurement, BoxError> {
    let first = measurements
        .first()
        .ok_or("calibration arm produced no measurements")?;
    let mut durations: Vec<u64> = measurements.iter().map(|value| value.duration_ns).collect();
    let mut rates: Vec<f64> = measurements
        .iter()
        .map(|value| value.messages_per_second)
        .collect();
    let mut bandwidth: Vec<f64> = measurements
        .iter()
        .map(|value| value.mebibytes_per_second)
        .collect();
    let mut cpu: Vec<u64> = measurements
        .iter()
        .map(|value| value.process_scheduled_cpu_ns)
        .collect();
    durations.sort_unstable();
    rates.sort_by(f64::total_cmp);
    bandwidth.sort_by(f64::total_cmp);
    cpu.sort_unstable();
    Ok(CalibrationMeasurement {
        messages: first.messages,
        message_bytes: first.message_bytes,
        duration_ns: median_u64(&durations),
        messages_per_second: median_f64(&rates),
        mebibytes_per_second: median_f64(&bandwidth),
        process_scheduled_cpu_ns: median_u64(&cpu),
    })
}

fn median_u64(sorted: &[u64]) -> u64 {
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[middle]
    } else {
        sorted[middle - 1] / 2
            + sorted[middle] / 2
            + (sorted[middle - 1] % 2 + sorted[middle] % 2) / 2
    }
}

fn median_f64(sorted: &[f64]) -> f64 {
    let middle = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[middle]
    } else {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    }
}

fn relative_spread(measurements: &[CalibrationMeasurement], median: f64) -> f64 {
    if median <= 0.0 {
        return f64::INFINITY;
    }
    let minimum = measurements
        .iter()
        .map(|value| value.messages_per_second)
        .fold(f64::INFINITY, f64::min);
    let maximum = measurements
        .iter()
        .map(|value| value.messages_per_second)
        .fold(0.0_f64, f64::max);
    (maximum - minimum) / median
}

async fn stop_service(
    shutdown: watch::Sender<bool>,
    mut task: tokio::task::JoinHandle<io::Result<()>>,
) -> Result<(), BoxError> {
    let signal_result = shutdown.send(true);
    let task_result = match tokio::time::timeout(CALIBRATION_SERVICE_STOP_TIMEOUT, &mut task).await
    {
        Ok(result) => result,
        Err(_) => {
            task.abort();
            let _ = task.await;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "calibration service did not stop before its fixed deadline",
            )
            .into());
        }
    };
    task_result??;
    signal_result?;
    Ok(())
}

async fn start_unobserved_control_proxy(
    backend: SocketAddr,
    max_connections: usize,
    limits: ObserverLimits,
) -> Result<
    (
        SocketAddr,
        watch::Sender<bool>,
        tokio::task::JoinHandle<io::Result<()>>,
        Arc<ProxyTelemetry>,
    ),
    BoxError,
> {
    let observer = ObserverHub::disabled(limits)?;
    let telemetry = ProxyTelemetry::shared();
    let proxy = ProxyServer::bind(
        ProxyConfig {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            backend,
            max_connections,
            memory_budget_bytes: CALIBRATION_MEMORY_BUDGET_BYTES,
            shutdown_grace: Duration::from_secs(30),
        },
        observer,
        telemetry.clone(),
    )
    .await?;
    let address = proxy.local_addr()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(proxy.serve(shutdown_rx));
    Ok((address, shutdown_tx, task, telemetry))
}

async fn wait_for_proxy_idle(telemetry: &Arc<ProxyTelemetry>, arm: &str) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + CALIBRATION_IDLE_TIMEOUT;
    loop {
        let snapshot = telemetry.snapshot();
        if snapshot.active_connections == 0 {
            if snapshot.failed_connections != 0
                || snapshot.accepted_connections != snapshot.completed_connections
            {
                return Err(io::Error::other(format!(
                    "calibration {arm} proxy did not settle without failures"
                )));
            }
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "calibration {arm} proxy retained {} active connections after its round",
                    snapshot.active_connections
                ),
            ));
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn run_load(
    target: SocketAddr,
    config: &CalibrationConfig,
    index_offset: usize,
    arm: &str,
) -> Result<CalibrationMeasurement, BoxError> {
    let next_index = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(config.concurrency + 1));
    let connected_clients = Arc::new(AtomicUsize::new(0));
    let greeted_clients = Arc::new(AtomicUsize::new(0));
    let ehlo_clients = Arc::new(AtomicUsize::new(0));
    let mut clients = JoinSet::new();
    for _ in 0..config.concurrency {
        let next_index = next_index.clone();
        let barrier = barrier.clone();
        let connected_clients = connected_clients.clone();
        let greeted_clients = greeted_clients.clone();
        let ehlo_clients = ehlo_clients.clone();
        let config = config.clone();
        clients.spawn(async move {
            let stream = TcpStream::connect(target).await?;
            connected_clients.fetch_add(1, Ordering::Relaxed);
            stream.set_nodelay(true)?;
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::with_capacity(64 * 1024, reader);
            expect_code(&mut reader, 220).await?;
            greeted_clients.fetch_add(1, Ordering::Relaxed);
            writer.write_all(b"EHLO calibration.local\r\n").await?;
            expect_code(&mut reader, 250).await?;
            let mut message = CalibrationMessage::new(config.message_bytes)?;
            ehlo_clients.fetch_add(1, Ordering::Relaxed);
            barrier.wait().await;
            loop {
                let index = next_index.fetch_add(1, Ordering::Relaxed);
                if index >= config.messages {
                    break;
                }
                let message_index = index_offset
                    .checked_add(index)
                    .ok_or_else(|| io::Error::other("calibration message index overflowed"))?;
                message.set_index(message_index)?;
                writer
                    .write_all(
                        b"MAIL FROM:<stress-sender@lmyz.net>\r\nRCPT TO:<stress-receiver@lmyz.net>\r\n",
                    )
                    .await?;
                expect_code(&mut reader, 250).await?;
                expect_code(&mut reader, 250).await?;
                match config.mode {
                    CalibrationMode::Data => {
                        writer.write_all(b"DATA\r\n").await?;
                        expect_code(&mut reader, 354).await?;
                        writer.write_all(message.as_bytes()).await?;
                        writer.write_all(b".\r\n").await?;
                    }
                    CalibrationMode::Bdat => {
                        writer
                            .write_all(
                                format!("BDAT {} LAST\r\n", message.as_bytes().len()).as_bytes(),
                            )
                            .await?;
                        writer.write_all(message.as_bytes()).await?;
                    }
                }
                expect_code(&mut reader, 250).await?;
            }
            writer.write_all(b"QUIT\r\n").await?;
            expect_code(&mut reader, 221).await?;
            Ok::<(), io::Error>(())
        });
    }
    let startup_barrier = barrier.wait();
    let startup_deadline = tokio::time::sleep(CALIBRATION_STARTUP_TIMEOUT);
    tokio::pin!(startup_barrier);
    tokio::pin!(startup_deadline);
    tokio::select! {
        biased;
        _ = &mut startup_barrier => {}
        result = clients.join_next() => {
            clients.abort_all();
            while clients.join_next().await.is_some() {}
            let error = match result {
                Some(Ok(Err(error))) => io::Error::new(
                    error.kind(),
                    format!(
                        "synthetic calibration client failed before readiness: {error}"
                    ),
                ),
                Some(Err(error)) => io::Error::other(format!(
                    "synthetic calibration client task failed before readiness: {error}"
                )),
                Some(Ok(Ok(()))) => io::Error::other(
                    "synthetic calibration client exited before the shared readiness barrier",
                ),
                None => io::Error::other(
                    "synthetic calibration client set emptied before readiness",
                ),
            };
            return Err(error.into());
        }
        _ = &mut startup_deadline => {
            let open_fds = fs::read_dir("/proc/self/fd")?.count();
            let tcp_states = tcp_state_counts()?;
            clients.abort_all();
            while clients.join_next().await.is_some() {}
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "synthetic calibration clients did not become ready before deadline: \
                     arm={arm}, connected={}, greeted={}, ehlo={}, expected={}, \
                     open_fds={open_fds}, tcp_states={tcp_states:?}",
                    connected_clients.load(Ordering::Relaxed),
                    greeted_clients.load(Ordering::Relaxed),
                    ehlo_clients.load(Ordering::Relaxed),
                    config.concurrency,
                ),
            )
            .into());
        }
    }
    let cpu_started = process_scheduled_cpu_ns()?;
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + CALIBRATION_RUN_TIMEOUT;
    loop {
        match tokio::time::timeout_at(deadline, clients.join_next()).await {
            Ok(Some(result)) => result??,
            Ok(None) => break,
            Err(_) => {
                clients.abort_all();
                while clients.join_next().await.is_some() {}
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "synthetic calibration exceeded its fixed run deadline",
                )
                .into());
            }
        }
    }
    let duration = started.elapsed();
    let process_scheduled_cpu_ns = process_scheduled_cpu_ns()?.saturating_sub(cpu_started);
    let duration_ns: u64 = duration.as_nanos().try_into().unwrap_or(u64::MAX);
    let seconds = duration.as_secs_f64();
    Ok(CalibrationMeasurement {
        messages: config.messages,
        message_bytes: config.message_bytes,
        duration_ns,
        messages_per_second: config.messages as f64 / seconds,
        mebibytes_per_second: config.messages as f64 * config.message_bytes as f64
            / (1024.0 * 1024.0)
            / seconds,
        process_scheduled_cpu_ns,
    })
}

fn tcp_state_counts() -> io::Result<BTreeMap<String, usize>> {
    let mut counts = BTreeMap::new();
    for line in fs::read_to_string("/proc/self/net/tcp")?.lines().skip(1) {
        let state = line
            .split_ascii_whitespace()
            .nth(3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid TCP row"))?;
        *counts.entry(state.to_owned()).or_insert(0) += 1;
    }
    Ok(counts)
}

fn process_scheduled_cpu_ns() -> io::Result<u64> {
    let mut total = 0_u64;
    for entry in std::fs::read_dir("/proc/self/task")? {
        let schedstat = std::fs::read_to_string(entry?.path().join("schedstat"))?;
        let runtime = schedstat
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty task schedstat"))?
            .parse::<u64>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        total = total
            .checked_add(runtime)
            .ok_or_else(|| io::Error::other("process scheduled CPU accounting overflowed"))?;
    }
    Ok(total)
}

const CALIBRATION_INDEX_WIDTH: usize = 20;

struct CalibrationMessage {
    bytes: Vec<u8>,
    subject_index_offset: usize,
    message_id_index_offset: usize,
}

impl CalibrationMessage {
    fn new(target_bytes: usize) -> io::Result<Self> {
        let mut bytes = format!(
            "From: {}\r\nTo: {}\r\nSubject: Stress Test R{CALIBRATION_ROUND} #",
            crate::observer::DEFAULT_SENDER,
            crate::observer::DEFAULT_RECEIVER,
        )
        .into_bytes();
        let subject_index_offset = bytes.len();
        bytes.extend_from_slice(&[b'0'; CALIBRATION_INDEX_WIDTH]);
        bytes.extend_from_slice(b" - 1234\r\nMessage-ID: <calibration-");
        let message_id_index_offset = bytes.len();
        bytes.extend_from_slice(&[b'0'; CALIBRATION_INDEX_WIDTH]);
        bytes.extend_from_slice(b"@lmyz.net>\r\nContent-Type: text/plain\r\n\r\n");
        if bytes.len() + 2 > target_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "calibration target is smaller than its fixed headers",
            ));
        }
        bytes.resize(target_bytes - 2, b'x');
        bytes.extend_from_slice(b"\r\n");
        let mut message = Self {
            bytes,
            subject_index_offset,
            message_id_index_offset,
        };
        message.set_index(0)?;
        Ok(message)
    }

    fn set_index(&mut self, index: usize) -> io::Result<()> {
        let mut digits = [b'0'; CALIBRATION_INDEX_WIDTH];
        let mut remaining = index;
        for digit in digits.iter_mut().rev() {
            *digit = b'0' + (remaining % 10) as u8;
            remaining /= 10;
        }
        if remaining != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "calibration message index exceeded its fixed-width field",
            ));
        }
        self.bytes[self.subject_index_offset..self.subject_index_offset + digits.len()]
            .copy_from_slice(&digits);
        self.bytes[self.message_id_index_offset..self.message_id_index_offset + digits.len()]
            .copy_from_slice(&digits);
        Ok(())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

async fn expect_code<R>(reader: &mut R, expected: u16) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::with_capacity(256);
    let mut first_code = None;
    loop {
        line.clear();
        let bytes = reader.read_until(b'\n', &mut line).await?;
        if bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "synthetic SMTP peer closed before its reply",
            ));
        }
        if line.len() > 64 * 1024 || line.len() < 5 || !line[..3].iter().all(u8::is_ascii_digit) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic SMTP peer returned a malformed reply",
            ));
        }
        let code = std::str::from_utf8(&line[..3])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .parse::<u16>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let code_for_reply = *first_code.get_or_insert(code);
        if code_for_reply != expected || code != code_for_reply {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected SMTP {expected}, received {code}"),
            ));
        }
        if line[3] == b' ' {
            return Ok(());
        }
        if line[3] != b'-' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic SMTP multiline reply had an invalid separator",
            ));
        }
    }
}

async fn start_synthetic_backend() -> io::Result<(
    SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<io::Result<()>>,
)> {
    let listener = bind_tcp_listener(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        MAX_CALIBRATION_CONNECTIONS,
    )?;
    let address = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            let accepted = tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
                accepted = listener.accept() => accepted,
            };
            let (stream, _) = accepted?;
            connections.spawn(handle_synthetic_connection(stream));
            while let Some(result) = connections.try_join_next() {
                result.map_err(io::Error::other)??;
            }
        }
        while let Some(result) = connections.join_next().await {
            result.map_err(io::Error::other)??;
        }
        Ok(())
    });
    Ok((address, shutdown_tx, task))
}

async fn handle_synthetic_connection(stream: TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::with_capacity(64 * 1024, reader);
    writer.write_all(b"220 calibration ESMTP\r\n").await?;
    let mut line = Vec::with_capacity(512);
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            return Ok(());
        }
        if line.len() > 512 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic SMTP command exceeded line limit",
            ));
        }
        let command = line
            .split(|byte| byte.is_ascii_whitespace())
            .next()
            .unwrap_or_default();
        if command.eq_ignore_ascii_case(b"EHLO") {
            writer
                .write_all(b"250-calibration\r\n250-PIPELINING\r\n250 CHUNKING\r\n")
                .await?;
        } else if command.eq_ignore_ascii_case(b"DATA") {
            writer.write_all(b"354 send data\r\n").await?;
            consume_data_terminator(&mut reader).await?;
            writer.write_all(b"250 accepted\r\n").await?;
        } else if command.eq_ignore_ascii_case(b"BDAT") {
            let (size, _last) = parse_bdat_line(&line)?;
            let mut remaining = size;
            let mut buffer = [0_u8; 64 * 1024];
            while remaining > 0 {
                let take = remaining.min(buffer.len());
                reader.read_exact(&mut buffer[..take]).await?;
                remaining -= take;
            }
            writer.write_all(b"250 accepted\r\n").await?;
        } else if command.eq_ignore_ascii_case(b"QUIT") {
            writer.write_all(b"221 bye\r\n").await?;
            return Ok(());
        } else {
            writer.write_all(b"250 ok\r\n").await?;
        }
    }
}

async fn consume_data_terminator<R>(reader: &mut R) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
{
    const MARKER: &[u8] = b"\r\n.\r\n";
    const MAX_SYNTHETIC_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
    let mut tail = [0_u8; MARKER.len() - 1];
    let mut tail_len = 0_usize;
    let mut observed = 0_usize;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "synthetic SMTP DATA ended before terminator",
            ));
        }
        let prefix_len = available.len().min(MARKER.len());
        let mut boundary = [0_u8; MARKER.len() * 2 - 1];
        boundary[..tail_len].copy_from_slice(&tail[..tail_len]);
        boundary[tail_len..tail_len + prefix_len].copy_from_slice(&available[..prefix_len]);
        let boundary_len = tail_len + prefix_len;
        if let Some(position) = memchr::memmem::find(&boundary[..boundary_len], MARKER) {
            reader.consume(position + MARKER.len() - tail_len);
            return Ok(());
        }
        if let Some(position) = memchr::memmem::find(available, MARKER) {
            reader.consume(position + MARKER.len());
            return Ok(());
        }
        observed = observed.saturating_add(available.len());
        if observed > MAX_SYNTHETIC_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "synthetic SMTP DATA exceeded fixed calibration limit",
            ));
        }
        let tail_capacity = tail.len();
        if available.len() >= tail_capacity {
            tail.copy_from_slice(&available[available.len() - tail_capacity..]);
            tail_len = tail_capacity;
        } else {
            let retained = boundary_len.min(tail_capacity);
            tail[..retained].copy_from_slice(&boundary[boundary_len - retained..boundary_len]);
            tail_len = retained;
        }
        let consumed = available.len();
        reader.consume(consumed);
    }
}

fn parse_bdat_line(line: &[u8]) -> io::Result<(usize, bool)> {
    let mut fields = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let command = fields.next().unwrap_or_default();
    let size_field = fields.next().unwrap_or_default();
    let third = fields.next();
    if fields.next().is_some() || !command.eq_ignore_ascii_case(b"BDAT") || size_field.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic BDAT command had invalid fields",
        ));
    }
    let size = std::str::from_utf8(size_field)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .parse::<usize>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let last = third.is_some_and(|field| field.eq_ignore_ascii_case(b"LAST"));
    if third.is_some() && !last {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "synthetic BDAT third field was not LAST",
        ));
    }
    Ok((size, last))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_sequence_is_balanced_abba_with_three_or_more_rounds() {
        let sequence: Vec<&str> = balanced_sequence(3)
            .into_iter()
            .map(CalibrationArm::as_str)
            .collect();
        assert_eq!(
            sequence,
            [
                "direct", "proxied", "proxied", "direct", "direct", "proxied"
            ]
        );
    }

    #[test]
    fn calibration_message_reuses_one_fixed_size_buffer() {
        let mut message = CalibrationMessage::new(1_024).unwrap();
        let address = message.as_bytes().as_ptr();
        message.set_index(42).unwrap();
        assert_eq!(message.as_bytes().len(), 1_024);
        assert_eq!(message.as_bytes().as_ptr(), address);
        assert!(
            memchr::memmem::find(message.as_bytes(), b"#00000000000000000042 - 1234\r\n").is_some()
        );
        assert!(
            memchr::memmem::find(
                message.as_bytes(),
                b"Message-ID: <calibration-00000000000000000042@lmyz.net>"
            )
            .is_some()
        );
    }

    #[tokio::test]
    async fn synthetic_data_terminator_preserves_bytes_after_a_split_marker() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let writer_task = tokio::spawn(async move {
            for fragment in [
                b"body\r".as_slice(),
                b"\n.".as_slice(),
                b"\r".as_slice(),
                b"\nNEXT\r\n".as_slice(),
            ] {
                writer.write_all(fragment).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });
        let mut reader = BufReader::with_capacity(2, reader);
        consume_data_terminator(&mut reader).await.unwrap();
        let mut trailing = Vec::new();
        reader.read_to_end(&mut trailing).await.unwrap();
        writer_task.await.unwrap();
        assert_eq!(trailing, b"NEXT\r\n");
    }

    #[tokio::test]
    async fn smoke_calibration_exercises_real_proxy_and_data_observer() {
        let report = run_calibration(
            CalibrationConfig {
                messages: 16,
                message_bytes: 1_024,
                concurrency: 4,
                mode: CalibrationMode::Data,
                minimum_proxy_to_direct_ratio: 0.5,
                rounds_per_arm: 3,
                maximum_round_spread: 1.0,
            },
            ObserverLimits::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.schema_version, 4);
        assert_eq!(report.control_topology, "bounded-unobserved-proxy");
        assert!(report.observer.qualification, "{report:#?}");
        assert_eq!(report.observer.verified, 48);
        assert_eq!(report.control_proxy.accepted_connections, 12);
        assert_eq!(report.control_proxy.completed_connections, 12);
        assert_eq!(report.control_proxy.failed_connections, 0);
        assert_eq!(report.control_proxy.active_connections, 0);
        assert_eq!(report.control_proxy.peak_connections, 4);
        assert_eq!(report.proxy.accepted_connections, 12);
        assert_eq!(report.proxy.completed_connections, 12);
        assert_eq!(report.proxy.failed_connections, 0);
        assert_eq!(report.proxy.active_connections, 0);
        assert_eq!(report.proxy.peak_connections, 4);
        assert_eq!(report.direct_rounds.len(), 3);
        assert_eq!(report.proxied_rounds.len(), 3);
    }

    #[tokio::test]
    async fn smoke_calibration_exercises_bdat_observer() {
        let report = run_calibration(
            CalibrationConfig {
                messages: 8,
                message_bytes: 1_024,
                concurrency: 2,
                mode: CalibrationMode::Bdat,
                minimum_proxy_to_direct_ratio: 0.5,
                rounds_per_arm: 3,
                maximum_round_spread: 1.0,
            },
            ObserverLimits::default(),
        )
        .await
        .unwrap();
        assert!(report.observer.qualification, "{report:#?}");
        assert_eq!(report.observer.verified, 24);
    }
}
