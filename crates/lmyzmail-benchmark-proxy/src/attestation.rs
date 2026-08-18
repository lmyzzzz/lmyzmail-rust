use crate::calibration::{
    CalibrationConfig, CalibrationMode, CalibrationReport, GateOverheadCalibrationReport,
    RAW_CALIBRATION_SCHEMA_VERSION, run_calibration, run_gate_overhead_calibration,
};
use crate::observer::ObserverLimits;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub const HEADROOM_PROFILE: &str = "lmyzmail-smtp-proxy-headroom-v1";
pub const HEADROOM_NOFILE_RESERVE: u64 = 512;
pub const HEADROOM_FDS_PER_PROXIED_CONNECTION: u64 = 4;

#[derive(Clone, Debug, Serialize)]
pub struct HeadroomEnvironment {
    pub host_boot_id: String,
    pub benchmark_cpu: usize,
    pub calibration_cpus: String,
    pub cgroup_parent: String,
    pub process_cgroup: String,
    pub cpuset_cpus_effective: String,
    pub io_bytes_per_second_per_device: u64,
    pub io_device: String,
    pub backing_device: String,
    pub io_max_lines: Vec<String>,
    pub io_max_sha256: String,
    pub memory_max_bytes: u64,
    pub memory_swap_max_bytes: u64,
    pub pids_max: u64,
    pub nofile_soft_and_hard: u64,
    pub nofile_required: u64,
    pub nofile_reserve: u64,
}

#[derive(Clone, Debug)]
pub struct HeadroomTierConfig {
    pub label: String,
    pub calibration: CalibrationConfig,
}

#[derive(Clone, Debug)]
pub struct HeadroomAttestationConfig {
    pub runner_sha256: String,
    pub binary_sha256: String,
    pub source_tree_sha256: String,
    pub environment: HeadroomEnvironment,
    pub minimum_product_headroom_ratio: f64,
    pub tiers: Vec<HeadroomTierConfig>,
}

#[derive(Debug, Serialize)]
pub struct HeadroomTierReport {
    pub message_bytes: usize,
    pub messages_per_round: usize,
    pub concurrency: usize,
    pub rounds_per_arm: usize,
    pub sustained_messages_per_second: f64,
    pub raw_calibration_schema_version: u32,
    pub raw_calibration_sha256: String,
    pub raw_calibration: CalibrationReport,
    pub gate_overhead_calibration_schema_version: u32,
    pub gate_overhead_calibration_sha256: String,
    pub gate_overhead_calibration: GateOverheadCalibrationReport,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct ProxyHeadroomReport {
    pub runner_sha256: String,
    pub binary_sha256: String,
    pub source_tree_sha256: String,
    pub semantic_transparency_passed: bool,
    pub minimum_product_headroom_ratio: f64,
    pub max_active_connections: usize,
    pub calibration_bundle_sha256: String,
    pub tiers: BTreeMap<String, HeadroomTierReport>,
    pub environment: HeadroomEnvironment,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct HeadroomAttestation {
    pub schema_version: u32,
    pub profile: &'static str,
    pub started_at_unix_seconds: u64,
    pub completed_at_unix_seconds: u64,
    pub proxy_headroom: ProxyHeadroomReport,
}

#[derive(Clone, Debug)]
pub struct PublishedAttestation {
    pub path: PathBuf,
    pub sha256: String,
}

impl HeadroomAttestationConfig {
    fn validate(&self, limits: &ObserverLimits) -> Result<(), String> {
        for (name, digest) in [
            ("runner", &self.runner_sha256),
            ("binary", &self.binary_sha256),
            ("source tree", &self.source_tree_sha256),
        ] {
            if !is_sha256(digest) {
                return Err(format!("{name} SHA-256 is invalid"));
            }
        }
        if !self.minimum_product_headroom_ratio.is_finite()
            || self.minimum_product_headroom_ratio < 1.0
        {
            return Err("minimum product headroom ratio must be finite and >= 1".into());
        }
        let labels = self
            .tiers
            .iter()
            .map(|tier| tier.label.as_str())
            .collect::<BTreeSet<_>>();
        if labels != BTreeSet::from(["1KB", "10KB", "10MB"]) || labels.len() != self.tiers.len() {
            return Err("headroom attestation requires exactly 1KB, 10KB, and 10MB".into());
        }
        for tier in &self.tiers {
            tier.calibration.validate(limits)?;
        }
        if self.environment.io_device == self.environment.backing_device
            || self.environment.io_bytes_per_second_per_device == 0
            || self.environment.host_boot_id.len() != 36
            || self.environment.calibration_cpus.is_empty()
            || self.environment.cpuset_cpus_effective != self.environment.calibration_cpus
            || cpu_list_contains(
                &self.environment.calibration_cpus,
                self.environment.benchmark_cpu,
            )
            || !Path::new(&self.environment.cgroup_parent).is_absolute()
            || !Path::new(&self.environment.process_cgroup).is_absolute()
            || !Path::new(&self.environment.process_cgroup)
                .starts_with(&self.environment.cgroup_parent)
            || self.environment.memory_max_bytes == 0
            || self.environment.memory_swap_max_bytes != 0
            || self.environment.pids_max == 0
            || self.environment.nofile_soft_and_hard == 0
            || self.environment.nofile_reserve != HEADROOM_NOFILE_RESERVE
            || self.environment.nofile_required != formal_headroom_nofile_required()
            || self.environment.nofile_soft_and_hard < self.environment.nofile_required
        {
            return Err("headroom calibration environment is inconsistent".into());
        }
        if !io_max_lines_match(
            &self.environment.io_max_lines,
            [
                self.environment.io_device.as_str(),
                self.environment.backing_device.as_str(),
            ],
            self.environment.io_bytes_per_second_per_device,
        ) || !is_sha256(&self.environment.io_max_sha256)
        {
            return Err("headroom calibration I/O limit readback is invalid".into());
        }
        Ok(())
    }
}

fn io_max_lines_match<const N: usize>(
    lines: &[String],
    expected_devices: [&str; N],
    expected_bytes_per_second: u64,
) -> bool {
    if lines.len() != expected_devices.len() {
        return false;
    }
    let expected_devices = expected_devices.into_iter().collect::<BTreeSet<_>>();
    if expected_devices.len() != lines.len() {
        return false;
    }
    let mut observed_devices = BTreeSet::new();
    for line in lines {
        let mut fields = line.split_ascii_whitespace();
        let Some(device) = fields.next() else {
            return false;
        };
        if !expected_devices.contains(device) || !observed_devices.insert(device) {
            return false;
        }
        let mut limits = BTreeMap::new();
        for field in fields {
            let Some((name, value)) = field.split_once('=') else {
                return false;
            };
            if !matches!(name, "rbps" | "wbps" | "riops" | "wiops")
                || limits.insert(name, value).is_some()
            {
                return false;
            }
        }
        let expected = expected_bytes_per_second.to_string();
        if limits.get("rbps") != Some(&expected.as_str())
            || limits.get("wbps") != Some(&expected.as_str())
            || limits.get("riops").is_some_and(|value| *value != "max")
            || limits.get("wiops").is_some_and(|value| *value != "max")
        {
            return false;
        }
    }
    observed_devices == expected_devices
}

fn cpu_list_contains(value: &str, needle: usize) -> bool {
    value.split(',').any(|part| {
        let (start, end) = part
            .split_once('-')
            .map_or((part, part), |(start, end)| (start, end));
        match (start.parse::<usize>(), end.parse::<usize>()) {
            (Ok(start), Ok(end)) => start <= needle && needle <= end,
            _ => true,
        }
    })
}

pub fn formal_headroom_tiers() -> Vec<HeadroomTierConfig> {
    [
        ("10MB", 10 * 1_024 * 1_024, 2_000, 80),
        ("1KB", 1_024, 250_000, 1_500),
        ("10KB", 10 * 1_024, 250_000, 1_000),
    ]
    .into_iter()
    .map(
        |(label, message_bytes, messages, concurrency)| HeadroomTierConfig {
            label: label.to_owned(),
            calibration: CalibrationConfig {
                messages,
                message_bytes,
                concurrency,
                mode: CalibrationMode::Data,
                minimum_proxy_to_direct_ratio: 0.90,
                rounds_per_arm: 4,
                maximum_round_spread: 0.20,
            },
        },
    )
    .collect()
}

pub fn formal_headroom_nofile_required() -> u64 {
    let maximum_concurrency = formal_headroom_tiers()
        .into_iter()
        .map(|tier| tier.calibration.concurrency as u64)
        .max()
        .unwrap_or(0);
    maximum_concurrency
        .saturating_mul(HEADROOM_FDS_PER_PROXIED_CONNECTION)
        .saturating_add(HEADROOM_NOFILE_RESERVE)
}

pub async fn run_headroom_attestation(
    config: HeadroomAttestationConfig,
    limits: ObserverLimits,
) -> Result<HeadroomAttestation, BoxError> {
    limits.validate()?;
    config.validate(&limits)?;
    let started_at_unix_seconds = unix_seconds()?;
    let mut tiers = BTreeMap::new();
    let mut calibration_hashes = BTreeMap::new();
    let mut semantic_transparency_passed = true;
    let mut max_active_connections = 0;
    let gate_binding_common = serde_json::json!({
        "runner_sha256": config.runner_sha256.clone(),
        "binary_sha256": config.binary_sha256.clone(),
        "source_tree_sha256": config.source_tree_sha256.clone(),
        "host_boot_id": config.environment.host_boot_id.clone(),
        "benchmark_cpu": config.environment.benchmark_cpu,
        "calibration_cpus": config.environment.calibration_cpus.clone(),
        "cgroup_parent": config.environment.cgroup_parent.clone(),
        "process_cgroup": config.environment.process_cgroup.clone(),
        "io_max_sha256": config.environment.io_max_sha256.clone(),
        "nofile_soft_and_hard": config.environment.nofile_soft_and_hard,
    });
    for tier in config.tiers {
        let expected_observer_messages = tier
            .calibration
            .messages
            .checked_mul(tier.calibration.rounds_per_arm)
            .ok_or("headroom observer message count overflowed")?;
        let report = run_calibration(tier.calibration.clone(), limits.clone()).await?;
        let (gate_messages, gate_concurrency) = match tier.label.as_str() {
            "1KB" => (24_000, 1_500),
            "10KB" => (8_000, 1_000),
            "10MB" => (100, 20),
            _ => return Err("unknown gate calibration tier".into()),
        };
        let gate_binding = serde_json::json!({
            "common": gate_binding_common.clone(),
            "tier": tier.label.clone(),
            "message_bytes": tier.calibration.message_bytes,
            "messages": gate_messages,
            "concurrency": gate_concurrency,
        });
        let gate_overhead_calibration = run_gate_overhead_calibration(
            gate_messages,
            tier.calibration.message_bytes,
            gate_concurrency,
            limits.clone(),
            gate_binding,
        )
        .await?;
        let sustained_messages_per_second = report
            .proxied_rounds
            .iter()
            .map(|round| round.messages_per_second)
            .reduce(f64::min)
            .ok_or("headroom calibration produced no proxied rounds")?;
        let passed = report.qualification
            && report.schema_version == RAW_CALIBRATION_SCHEMA_VERSION
            && report.observer.qualification
            && report.observer.verified == expected_observer_messages
            && report.observer.missing == 0
            && report.observer.duplicates == 0
            && report.proxy.failed_connections == 0
            && gate_overhead_calibration.qualification
            && sustained_messages_per_second.is_finite()
            && sustained_messages_per_second > 0.0;
        let gate_overhead_calibration_sha256 = canonical_json_sha256(&gate_overhead_calibration)?;
        let raw_calibration_sha256 = canonical_json_sha256(&report)?;
        let tier_calibration_sha256 = canonical_json_sha256(&serde_json::json!({
            "raw_calibration_sha256": &raw_calibration_sha256,
            "gate_overhead_calibration_sha256": &gate_overhead_calibration_sha256,
        }))?;
        semantic_transparency_passed &= passed;
        max_active_connections = max_active_connections.max(report.proxy.peak_connections);
        let tier_report = HeadroomTierReport {
            message_bytes: tier.calibration.message_bytes,
            messages_per_round: tier.calibration.messages,
            concurrency: tier.calibration.concurrency,
            rounds_per_arm: tier.calibration.rounds_per_arm,
            sustained_messages_per_second,
            raw_calibration_schema_version: report.schema_version,
            raw_calibration_sha256: raw_calibration_sha256.clone(),
            raw_calibration: report,
            gate_overhead_calibration_schema_version: gate_overhead_calibration.schema_version,
            gate_overhead_calibration_sha256,
            gate_overhead_calibration,
            passed,
        };
        calibration_hashes.insert(tier.label.clone(), tier_calibration_sha256);
        if tiers.insert(tier.label, tier_report).is_some() {
            return Err("duplicate headroom tier label".into());
        }
    }
    let passed = semantic_transparency_passed
        && max_active_connections >= 1_500
        && tiers.len() == 3
        && tiers.values().all(|tier| tier.passed);
    let calibration_bundle_sha256 = canonical_json_sha256(&calibration_hashes)?;
    Ok(HeadroomAttestation {
        schema_version: 1,
        profile: HEADROOM_PROFILE,
        started_at_unix_seconds,
        completed_at_unix_seconds: unix_seconds()?,
        proxy_headroom: ProxyHeadroomReport {
            runner_sha256: config.runner_sha256,
            binary_sha256: config.binary_sha256,
            source_tree_sha256: config.source_tree_sha256,
            semantic_transparency_passed,
            minimum_product_headroom_ratio: config.minimum_product_headroom_ratio,
            max_active_connections,
            calibration_bundle_sha256,
            tiers,
            environment: config.environment,
            passed,
        },
    })
}

fn unix_seconds() -> Result<u64, BoxError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn canonical_json_sha256(value: &impl Serialize) -> Result<String, serde_json::Error> {
    let canonical = serde_json::to_value(value)?;
    serde_json::to_vec(&canonical).map(|payload| hex_sha256(&payload))
}

pub fn publish_headroom_attestation(
    root: &Path,
    report: &HeadroomAttestation,
) -> Result<PublishedAttestation, BoxError> {
    let mut payload = serde_json::to_vec(report)?;
    payload.push(b'\n');
    publish_content_addressed(root, &payload, 0, 0)
}

fn publish_content_addressed(
    root: &Path,
    payload: &[u8],
    expected_uid: u32,
    expected_gid: u32,
) -> Result<PublishedAttestation, BoxError> {
    if !root.is_absolute() {
        return Err("headroom attestation root must be absolute".into());
    }
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.file_type().is_dir()
        || root_metadata.uid() != expected_uid
        || root_metadata.gid() != expected_gid
        || root_metadata.permissions().mode() & 0o022 != 0
    {
        return Err("headroom attestation root is not immutable-owner controlled".into());
    }
    let digest = hex_sha256(payload);
    let target = root.join(format!("{digest}.json"));
    if target.exists() || fs::symlink_metadata(&target).is_ok() {
        verify_published(&target, payload, expected_uid, expected_gid)?;
        return Ok(PublishedAttestation {
            path: target,
            sha256: digest,
        });
    }
    let mut temporary = None;
    let mut output = None;
    for attempt in 0..16_u8 {
        let candidate = root.join(format!(".{digest}.{}.{}.tmp", std::process::id(), attempt));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some(candidate);
                output = Some(file);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let temporary = temporary.ok_or("could not allocate an attestation temporary file")?;
    let result = (|| -> Result<(), BoxError> {
        let mut output = output.ok_or("attestation temporary file was not opened")?;
        output.write_all(payload)?;
        output.sync_all()?;
        drop(output);
        match fs::hard_link(&temporary, &target) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                verify_published(&target, payload, expected_uid, expected_gid)?;
            }
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(&temporary)?;
        File::open(root)?.sync_all()?;
        verify_published(&target, payload, expected_uid, expected_gid)
    })();
    if temporary.exists() {
        let _ = fs::remove_file(&temporary);
        let _ = File::open(root).and_then(|directory| directory.sync_all());
    }
    result?;
    Ok(PublishedAttestation {
        path: target,
        sha256: digest,
    })
}

fn verify_published(
    path: &Path,
    payload: &[u8],
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), BoxError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o222 != 0
        || metadata.nlink() != 1
        || fs::read(path)? != payload
    {
        return Err("published headroom attestation is mutable or changed".into());
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn hex_sha256(payload: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(payload);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn config_with_nofile(nofile: u64) -> HeadroomAttestationConfig {
        HeadroomAttestationConfig {
            runner_sha256: "a".repeat(64),
            binary_sha256: "b".repeat(64),
            source_tree_sha256: "c".repeat(64),
            environment: HeadroomEnvironment {
                host_boot_id: "12345678-1234-4234-9234-123456789abc".into(),
                benchmark_cpu: 3,
                calibration_cpus: "0-2".into(),
                cgroup_parent: "/sys/fs/cgroup/formal".into(),
                process_cgroup: "/sys/fs/cgroup/formal/harness".into(),
                cpuset_cpus_effective: "0-2".into(),
                io_bytes_per_second_per_device: 500_000_000,
                io_device: "7:1".into(),
                backing_device: "7:0".into(),
                io_max_lines: vec![
                    "7:0 rbps=500000000 wbps=500000000".into(),
                    "7:1 rbps=500000000 wbps=500000000".into(),
                ],
                io_max_sha256: "d".repeat(64),
                memory_max_bytes: 8 * 1024 * 1024 * 1024,
                memory_swap_max_bytes: 0,
                pids_max: 8192,
                nofile_soft_and_hard: nofile,
                nofile_required: formal_headroom_nofile_required(),
                nofile_reserve: HEADROOM_NOFILE_RESERVE,
            },
            minimum_product_headroom_ratio: 2.0,
            tiers: formal_headroom_tiers(),
        }
    }

    #[test]
    fn formal_tiers_are_complete_and_bound_to_expected_sizes() {
        let tiers = formal_headroom_tiers();
        assert_eq!(tiers.len(), 3);
        assert_eq!(tiers[0].label, "10MB");
        assert_eq!(tiers[0].calibration.message_bytes, 10 * 1_024 * 1_024);
        assert_eq!(tiers[0].calibration.messages, 2_000);
        assert_eq!(tiers[1].label, "1KB");
        assert_eq!(tiers[1].calibration.message_bytes, 1_024);
        assert_eq!(tiers[2].label, "10KB");
        assert_eq!(tiers[2].calibration.message_bytes, 10 * 1_024);
        assert!(
            tiers
                .iter()
                .all(|tier| tier.calibration.rounds_per_arm == 4)
        );
        assert_eq!(formal_headroom_nofile_required(), 6_512);
    }

    #[test]
    fn nofile_formula_rejects_limit_below_1500_connection_requirement() {
        let limits = ObserverLimits::default();
        assert!(config_with_nofile(6_511).validate(&limits).is_err());
        assert!(config_with_nofile(6_512).validate(&limits).is_ok());
    }

    #[test]
    fn io_max_accepts_explicit_unlimited_iops_readback() {
        let limits = ObserverLimits::default();
        let mut config = config_with_nofile(6_512);
        config.environment.io_max_lines = vec![
            "7:0 rbps=500000000 wbps=500000000 riops=max wiops=max".into(),
            "7:1 rbps=500000000 wbps=500000000 riops=max wiops=max".into(),
        ];
        assert!(config.validate(&limits).is_ok());
    }

    #[test]
    fn io_max_rejects_unknown_duplicate_or_limited_iops_fields() {
        let limits = ObserverLimits::default();
        for lines in [
            vec![
                "7:0 rbps=500000000 wbps=500000000 extra=max".into(),
                "7:1 rbps=500000000 wbps=500000000".into(),
            ],
            vec![
                "7:0 rbps=500000000 wbps=500000000".into(),
                "7:0 rbps=500000000 wbps=500000000".into(),
            ],
            vec![
                "7:0 rbps=500000000 wbps=500000000 riops=1 wiops=max".into(),
                "7:1 rbps=500000000 wbps=500000000 riops=max wiops=max".into(),
            ],
        ] {
            let mut config = config_with_nofile(6_512);
            config.environment.io_max_lines = lines;
            assert!(config.validate(&limits).is_err());
        }
    }

    #[test]
    fn publication_is_content_addressed_immutable_and_idempotent() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let metadata = fs::metadata(&root).unwrap();
        let payload = b"{\"profile\":\"lmyzmail-smtp-proxy-headroom-v1\"}\n";
        let published =
            publish_content_addressed(&root, payload, metadata.uid(), metadata.gid()).unwrap();
        let expected_name = format!("{}.json", published.sha256);
        assert_eq!(
            published.path.file_name().unwrap(),
            std::ffi::OsStr::new(&expected_name)
        );
        let output_metadata = fs::metadata(&published.path).unwrap();
        assert_eq!(output_metadata.permissions().mode() & 0o777, 0o400);
        assert_eq!(output_metadata.nlink(), 1);
        let second =
            publish_content_addressed(&root, payload, metadata.uid(), metadata.gid()).unwrap();
        assert_eq!(second.path, published.path);
        assert!(fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn publication_rejects_mutable_existing_attestation() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let root_metadata = fs::metadata(&root).unwrap();
        let payload = b"{}\n";
        let published =
            publish_content_addressed(&root, payload, root_metadata.uid(), root_metadata.gid())
                .unwrap();
        fs::set_permissions(&published.path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            publish_content_addressed(&root, payload, root_metadata.uid(), root_metadata.gid(),)
                .is_err()
        );
    }
}
