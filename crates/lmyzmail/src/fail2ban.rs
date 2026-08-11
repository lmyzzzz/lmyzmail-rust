use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fs::{self, File, Metadata},
    io::{self, Read, Seek, SeekFrom},
    net::IpAddr,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::OnceLock,
    time::{Duration, Instant},
};

use futures_util::{StreamExt, stream};
use regex::Regex;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::{bounded_blocking::BoundedBlockingPool, config::Fail2BanConfig, cringe::CringeService};

const MAX_SCAN_BYTES: usize = 1_048_576;
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_EVENTS_PER_SCAN: usize = 8_192;
const MAX_FAILURE_TIMESTAMPS_PER_IP: usize = 4_096;
const MAX_PERSISTENCE_IN_FLIGHT: usize = 8;
const BLOCKING_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);
const SUMMARY_INTERVAL: Duration = Duration::from_secs(60 * 60);
const SCAN_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);
const MAX_SUMMARY_IPS: usize = 4_096;
const MAX_SUMMARY_USERNAMES: usize = 10;
const MAX_SUMMARY_SAMPLES: usize = 3;
const MAX_SUMMARY_SAMPLE_CHARS: usize = 80;
const MAX_SUMMARY_USERNAME_CHARS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug)]
struct FailureEvent {
    ip: IpAddr,
    line: String,
}

#[derive(Debug)]
struct Report {
    ip: IpAddr,
    fail_count: usize,
    metadata: String,
    sample: String,
}

#[derive(Debug)]
struct Tailer {
    paths: Vec<PathBuf>,
    current_path: PathBuf,
    identity: FileIdentity,
    offset: u64,
    partial_line: Vec<u8>,
    dropping_oversized_line: bool,
}

impl Tailer {
    fn open(paths: &[PathBuf]) -> io::Result<Option<Self>> {
        for path in paths {
            let Ok(file) = File::open(path) else {
                continue;
            };
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                continue;
            }
            return Ok(Some(Self {
                paths: paths.to_vec(),
                current_path: path.clone(),
                identity: FileIdentity::from_metadata(&metadata),
                offset: metadata.len(),
                partial_line: Vec::new(),
                dropping_oversized_line: false,
            }));
        }
        Ok(None)
    }

    fn switch_to_readable_alternative(&self) -> Option<Self> {
        self.paths
            .iter()
            .filter(|path| *path != &self.current_path)
            .find_map(|path| {
                let file = File::open(path).ok()?;
                let metadata = file.metadata().ok()?;
                metadata.is_file().then(|| Self {
                    paths: self.paths.clone(),
                    current_path: path.clone(),
                    identity: FileIdentity::from_metadata(&metadata),
                    offset: 0,
                    partial_line: Vec::new(),
                    dropping_oversized_line: false,
                })
            })
    }

    fn scan(mut self) -> (Self, io::Result<Vec<FailureEvent>>) {
        let result = self.scan_inner();
        (self, result)
    }

    fn scan_inner(&mut self) -> io::Result<Vec<FailureEvent>> {
        let metadata = fs::metadata(&self.current_path)?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "configured SSH log path is not a regular file",
            ));
        }
        let identity = FileIdentity::from_metadata(&metadata);
        if identity != self.identity || metadata.len() < self.offset {
            self.identity = identity;
            self.offset = 0;
            self.partial_line.clear();
            self.dropping_oversized_line = false;
        }
        if metadata.len() <= self.offset {
            return Ok(Vec::new());
        }

        let mut file = File::open(&self.current_path)?;
        file.seek(SeekFrom::Start(self.offset))?;
        let read_limit = (metadata.len() - self.offset).min(MAX_SCAN_BYTES as u64) as usize;
        let mut bytes = vec![0_u8; read_limit];
        let bytes_read = file.read(&mut bytes)?;
        bytes.truncate(bytes_read);

        let mut events = Vec::new();
        let mut segment_start = 0_usize;
        let mut consumed = 0_usize;
        for (index, byte) in bytes.iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }
            let line = &bytes[segment_start..index];
            self.complete_line(line, &mut events);
            consumed = index + 1;
            segment_start = index + 1;
            if events.len() >= MAX_EVENTS_PER_SCAN {
                break;
            }
        }

        if events.len() < MAX_EVENTS_PER_SCAN {
            self.retain_partial(&bytes[segment_start..]);
            consumed = bytes.len();
        }
        self.offset = self.offset.saturating_add(consumed as u64);
        Ok(events)
    }

    fn complete_line(&mut self, segment: &[u8], events: &mut Vec<FailureEvent>) {
        if self.dropping_oversized_line {
            self.dropping_oversized_line = false;
            self.partial_line.clear();
            return;
        }
        if self.partial_line.len().saturating_add(segment.len()) > MAX_LINE_BYTES {
            self.partial_line.clear();
            return;
        }
        let mut line = std::mem::take(&mut self.partial_line);
        line.extend_from_slice(segment);
        let line = String::from_utf8_lossy(&line);
        let line = line.trim_matches(|character: char| character <= '\u{20}');
        if line.is_empty() || !line.contains("sshd") {
            return;
        }
        if let Some(ip) = extract_failed_ip(line) {
            events.push(FailureEvent {
                ip,
                line: line.to_owned(),
            });
        }
    }

    fn retain_partial(&mut self, bytes: &[u8]) {
        if self.dropping_oversized_line {
            return;
        }
        if self.partial_line.len().saturating_add(bytes.len()) > MAX_LINE_BYTES {
            self.partial_line.clear();
            self.dropping_oversized_line = true;
            return;
        }
        self.partial_line.extend_from_slice(bytes);
    }
}

#[derive(Debug)]
struct FailureEntry {
    failures: VecDeque<Instant>,
    last_report: Option<Instant>,
    lru_generation: u64,
}

#[derive(Debug)]
struct FailureTracker {
    entries: HashMap<IpAddr, FailureEntry>,
    lru: BTreeSet<(u64, IpAddr)>,
    generation: u64,
    max_tracked_ips: usize,
    max_retries: usize,
    find_time: Duration,
    report_cooldown: Duration,
}

impl FailureTracker {
    fn new(config: &Fail2BanConfig) -> Self {
        Self {
            entries: HashMap::new(),
            lru: BTreeSet::new(),
            generation: 0,
            max_tracked_ips: config.max_tracked_ips,
            max_retries: config.max_retries,
            find_time: config.find_time,
            report_cooldown: config.report_cooldown,
        }
    }

    fn record(&mut self, ip: IpAddr, line: &str, now: Instant) -> Option<Report> {
        if !self.entries.contains_key(&ip) {
            self.evict_if_full();
            self.entries.insert(
                ip,
                FailureEntry {
                    failures: VecDeque::new(),
                    last_report: None,
                    lru_generation: 0,
                },
            );
        }
        self.touch(ip);
        let entry = self.entries.get_mut(&ip).expect("entry inserted above");
        let window_start = now.checked_sub(self.find_time).unwrap_or(now);
        while entry
            .failures
            .front()
            .is_some_and(|timestamp| *timestamp < window_start)
        {
            entry.failures.pop_front();
        }
        if entry.failures.len() >= MAX_FAILURE_TIMESTAMPS_PER_IP {
            entry.failures.pop_front();
        }
        entry.failures.push_back(now);
        let fail_count = entry.failures.len();
        let can_report = entry.last_report.is_none_or(|last| {
            last.checked_add(self.report_cooldown)
                .is_none_or(|deadline| now > deadline)
        });
        if fail_count < self.max_retries || !can_report {
            return None;
        }
        entry.failures.clear();
        entry.last_report = Some(now);
        let sample = truncate(line, 200);
        Some(Report {
            ip,
            fail_count,
            metadata: format_metadata(fail_count, self.find_time, &sample),
            sample,
        })
    }

    fn cleanup(&mut self, now: Instant) {
        let window_start = now.checked_sub(self.find_time).unwrap_or(now);
        let cooldown_start = now
            .checked_sub(self.report_cooldown.saturating_mul(2))
            .unwrap_or(now);
        let expired = self
            .entries
            .iter_mut()
            .filter_map(|(ip, entry)| {
                while entry
                    .failures
                    .front()
                    .is_some_and(|timestamp| *timestamp < window_start)
                {
                    entry.failures.pop_front();
                }
                if entry
                    .last_report
                    .is_some_and(|timestamp| timestamp < cooldown_start)
                {
                    entry.last_report = None;
                }
                (entry.failures.is_empty() && entry.last_report.is_none()).then_some(*ip)
            })
            .collect::<Vec<_>>();
        for ip in expired {
            self.remove(ip);
        }
    }

    fn evict_if_full(&mut self) {
        while self.entries.len() >= self.max_tracked_ips {
            let Some((generation, ip)) = self.lru.iter().next().copied() else {
                break;
            };
            self.lru.remove(&(generation, ip));
            self.entries.remove(&ip);
        }
    }

    fn touch(&mut self, ip: IpAddr) {
        self.generation = self.generation.wrapping_add(1).max(1);
        if let Some(entry) = self.entries.get_mut(&ip) {
            self.lru.remove(&(entry.lru_generation, ip));
            entry.lru_generation = self.generation;
            self.lru.insert((entry.lru_generation, ip));
        }
    }

    fn remove(&mut self, ip: IpAddr) {
        if let Some(entry) = self.entries.remove(&ip) {
            self.lru.remove(&(entry.lru_generation, ip));
        }
    }
}

#[derive(Debug, Default)]
struct SummaryStats {
    reports: u64,
    failures: u64,
}

#[derive(Debug, Default)]
struct HourlySummarizer {
    by_ip: BTreeMap<IpAddr, SummaryStats>,
    total_reports: u64,
    total_failures: u64,
    usernames: BTreeSet<String>,
    samples: Vec<String>,
    overflowed_ips: bool,
    first_info_printed: bool,
}

impl HourlySummarizer {
    fn record(&mut self, report: &Report) -> bool {
        let failures = u64::try_from(report.fail_count).unwrap_or(u64::MAX);
        self.total_reports = self.total_reports.saturating_add(1);
        self.total_failures = self.total_failures.saturating_add(failures);
        if let Some(stats) = self.by_ip.get_mut(&report.ip) {
            stats.reports = stats.reports.saturating_add(1);
            stats.failures = stats.failures.saturating_add(failures);
        } else if self.by_ip.len() < MAX_SUMMARY_IPS {
            self.by_ip.insert(
                report.ip,
                SummaryStats {
                    reports: 1,
                    failures,
                },
            );
        } else {
            self.overflowed_ips = true;
        }

        if let Some(username) = extract_username(&report.sample) {
            let username = truncate(username, MAX_SUMMARY_USERNAME_CHARS);
            if self.usernames.contains(&username) || self.usernames.len() < MAX_SUMMARY_USERNAMES {
                self.usernames.insert(username);
            }
        }
        if self.samples.len() < MAX_SUMMARY_SAMPLES {
            self.samples
                .push(truncate(&report.sample, MAX_SUMMARY_SAMPLE_CHARS));
        }

        let first = !self.first_info_printed;
        self.first_info_printed = true;
        first
    }

    fn generate_and_reset(&mut self, label: &str) -> Option<String> {
        let snapshot = std::mem::take(self);
        if snapshot.total_reports == 0 {
            return None;
        }
        let mut ips = snapshot.by_ip.into_iter().collect::<Vec<_>>();
        ips.sort_by(|(left_ip, left), (right_ip, right)| {
            right
                .failures
                .cmp(&left.failures)
                .then_with(|| left_ip.cmp(right_ip))
        });

        let ip_count = if snapshot.overflowed_ips {
            format!("{}+", ips.len())
        } else {
            ips.len().to_string()
        };
        let mut output = format!(
            "Fail2Ban: {label} \u{2014} {ip_count} IPs, {} reports, {} failures. IPs: ",
            snapshot.total_reports, snapshot.total_failures
        );
        for (index, (ip, stats)) in ips.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            output.push_str(&format!("{ip}({})", stats.failures));
        }
        if snapshot.overflowed_ips {
            if !ips.is_empty() {
                output.push_str(", ");
            }
            output.push_str("additional IP reports omitted");
        }
        output.push('.');

        if !snapshot.usernames.is_empty() {
            output.push_str(" Users: ");
            for (index, username) in snapshot.usernames.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(username);
            }
            output.push('.');
        }
        if !snapshot.samples.is_empty() {
            output.push_str(" Samples: ");
            for (index, sample) in snapshot.samples.iter().enumerate() {
                if index > 0 {
                    output.push_str(" | ");
                }
                output.push('[');
                output.push_str(sample);
                output.push(']');
            }
        }
        Some(output)
    }
}

pub async fn run(config: Fail2BanConfig, cringe: CringeService, cancellation: CancellationToken) {
    let paths = config.ssh_log_paths.clone();
    let Ok(blocking_pool) = BoundedBlockingPool::new("lmyzmail-fail2ban", 1, 1) else {
        eprintln!("lmyzmail Fail2Ban: failed to create bounded file worker");
        cancellation.cancelled().await;
        return;
    };
    let open_receiver = match blocking_pool.submit(move || Tailer::open(&paths)) {
        Ok(receiver) => receiver,
        Err(error) => {
            eprintln!("lmyzmail Fail2Ban: failed to queue startup scan: {error}");
            let _ = blocking_pool.shutdown(BLOCKING_SHUTDOWN_DEADLINE).await;
            return;
        }
    };
    let Some(mut tailer) = (tokio::select! {
        biased;
        _ = cancellation.cancelled() => None,
        result = open_receiver => result.ok().and_then(Result::ok).flatten(),
    }) else {
        let _ = blocking_pool.shutdown(BLOCKING_SHUTDOWN_DEADLINE).await;
        if !cancellation.is_cancelled() {
            eprintln!("lmyzmail Fail2Ban: no readable SSH log file found; service is disabled");
        }
        cancellation.cancelled().await;
        return;
    };
    let mut tracker = FailureTracker::new(&config);
    let mut summarizer = HourlySummarizer::default();
    let started_at = Instant::now();
    let mut last_cleanup = started_at;
    let mut last_summary = started_at;
    let mut last_scan_error_log = None;
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            _ = sleep(config.scan_interval) => {}
        }
        let receiver = match blocking_pool.submit(move || tailer.scan()) {
            Ok(receiver) => receiver,
            Err(error) => {
                eprintln!("lmyzmail Fail2Ban: failed to queue scan: {error}");
                break;
            }
        };
        let Some(result) = (tokio::select! {
            biased;
            _ = cancellation.cancelled() => None,
            result = receiver => result.ok(),
        }) else {
            break;
        };
        let (next_tailer, scan_result) = result;
        tailer = next_tailer;
        let events = match scan_result {
            Ok(events) => events,
            Err(error) => {
                let now = Instant::now();
                if last_scan_error_log
                    .is_none_or(|last| now.duration_since(last) >= SCAN_ERROR_LOG_INTERVAL)
                {
                    eprintln!("lmyzmail Fail2Ban: log scan failed: {error}");
                    last_scan_error_log = Some(now);
                }
                if let Some(switched) = tailer.switch_to_readable_alternative() {
                    tailer = switched;
                }
                run_periodic_maintenance(
                    &mut tracker,
                    &mut summarizer,
                    now,
                    config.cleanup_interval,
                    &mut last_cleanup,
                    &mut last_summary,
                );
                continue;
            }
        };
        let now = Instant::now();
        let reports = events
            .iter()
            .filter_map(|event| tracker.record(event.ip, &event.line, now))
            .collect::<Vec<_>>();
        for report in &reports {
            if summarizer.record(report) {
                eprintln!(
                    "Fail2Ban: SSH brute force activity detected (first: {} with {} failures). All further detections suppressed until the next hourly summary.",
                    report.ip, report.fail_count
                );
            }
        }
        run_periodic_maintenance(
            &mut tracker,
            &mut summarizer,
            now,
            config.cleanup_interval,
            &mut last_cleanup,
            &mut last_summary,
        );
        persist_reports(&cringe, &cancellation, reports).await;
    }
    if let Some(summary) = summarizer.generate_and_reset("Shutdown summary") {
        eprintln!("{summary}");
    }
    let _ = blocking_pool.shutdown(BLOCKING_SHUTDOWN_DEADLINE).await;
}

fn run_periodic_maintenance(
    tracker: &mut FailureTracker,
    summarizer: &mut HourlySummarizer,
    now: Instant,
    cleanup_interval: Duration,
    last_cleanup: &mut Instant,
    last_summary: &mut Instant,
) {
    if now.duration_since(*last_cleanup) >= cleanup_interval {
        tracker.cleanup(now);
        *last_cleanup = now;
    }
    if now.duration_since(*last_summary) >= SUMMARY_INTERVAL {
        if let Some(summary) = summarizer.generate_and_reset("Hourly summary") {
            eprintln!("{summary}");
        }
        *last_summary = now;
    }
}

async fn persist_reports(
    cringe: &CringeService,
    cancellation: &CancellationToken,
    reports: Vec<Report>,
) {
    stream::iter(reports)
        .map(|report| {
            let cringe = cringe.clone();
            let cancellation = cancellation.clone();
            async move {
                if let Err(error) = cringe
                    .record_ssh_bruteforce(report.ip, &report.metadata, &cancellation)
                    .await
                {
                    eprintln!(
                        "lmyzmail Fail2Ban: failed to persist SSH activity for {}: {error}",
                        report.ip
                    );
                }
            }
        })
        .buffer_unordered(MAX_PERSISTENCE_IN_FLIGHT)
        .collect::<Vec<_>>()
        .await;
}

fn patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"Failed (?:password|publickey) for (?:invalid user )?\S+ from ([\da-fA-F:.]+) port \d+",
            r"Invalid user \S+ from ([\da-fA-F:.]+) port \d+",
            r"pam_unix\(sshd:auth\): authentication failure;.*rhost=([\da-fA-F:.]+)",
            r"(?:Connection closed by|Disconnected from).*?([\da-fA-F:.]+) port \d+ \[preauth\]",
            r"maximum authentication attempts exceeded for \S+ from ([\da-fA-F:.]+)",
            r"Bad protocol version identification .* from ([\da-fA-F:.]+)",
            r"Did not receive identification string from ([\da-fA-F:.]+)",
            r"refused connect from ([\da-fA-F:.]+)",
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("static Fail2Ban regex must compile"))
        .collect()
    })
}

fn extract_failed_ip(line: &str) -> Option<IpAddr> {
    patterns()
        .iter()
        .find_map(|pattern| pattern.captures(line)?.get(1)?.as_str().parse().ok())
}

fn extract_username(line: &str) -> Option<&str> {
    static USER_PATTERNS: OnceLock<[Regex; 2]> = OnceLock::new();
    USER_PATTERNS
        .get_or_init(|| {
            [
                Regex::new(r"for (?:invalid user )?(\S+) from")
                    .expect("static Fail2Ban username regex must compile"),
                Regex::new(r"Invalid user (\S+) from")
                    .expect("static Fail2Ban username regex must compile"),
            ]
        })
        .iter()
        .find_map(|pattern| pattern.captures(line)?.get(1).map(|value| value.as_str()))
}

fn format_metadata(fail_count: usize, find_time: Duration, sample: &str) -> String {
    format!(
        "SSH brute force: {fail_count} failed attempts in {}. Sample: {}",
        format_java_duration(find_time),
        sample
    )
}

fn format_java_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let nanos = duration.subsec_nanos();
    if seconds == 0 {
        return format!("PT0.{}S", format_nanos(nanos));
    }
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let remainder = seconds % 60;
    let mut result = String::from("PT");
    if hours > 0 {
        result.push_str(&format!("{hours}H"));
    }
    if minutes > 0 {
        result.push_str(&format!("{minutes}M"));
    }
    if remainder > 0 || nanos > 0 || (hours == 0 && minutes == 0) {
        if nanos == 0 {
            result.push_str(&format!("{remainder}S"));
        } else {
            result.push_str(format!("{}.{:09}S", remainder, nanos).trim_end_matches('0'));
        }
    }
    result
}

fn format_nanos(nanos: u32) -> String {
    format!("{nanos:09}").trim_end_matches('0').to_owned()
}

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let result = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{result}...")
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Properties, RuntimeConfig},
        database,
    };
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };
    use tokio::time::timeout;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn config(path: PathBuf) -> Fail2BanConfig {
        Fail2BanConfig {
            enabled: true,
            ssh_log_paths: vec![path],
            scan_interval: Duration::from_millis(1),
            max_retries: 2,
            find_time: Duration::from_secs(60),
            report_cooldown: Duration::from_secs(5),
            max_tracked_ips: 2,
            cleanup_interval: Duration::from_secs(60),
        }
    }

    fn temp_path(label: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "lmyzmail-fail2ban-{label}-{}",
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("auth.log");
        (root, path)
    }

    #[test]
    fn tracker_reports_threshold_and_honors_cooldown() {
        let path = PathBuf::from("/tmp/auth.log");
        let mut tracker = FailureTracker::new(&config(path));
        let ip = "198.51.100.21".parse().unwrap();
        let start = Instant::now();
        assert!(tracker.record(ip, "first", start).is_none());
        let first = tracker.record(ip, "second", start + Duration::from_secs(1));
        assert_eq!(
            first.as_ref().map(|report| report.metadata.as_str()),
            Some("SSH brute force: 2 failed attempts in PT1M. Sample: second")
        );
        assert!(
            tracker
                .record(ip, "during", start + Duration::from_secs(2))
                .is_none()
        );
        assert!(
            tracker
                .record(ip, "after", start + Duration::from_secs(7))
                .is_some()
        );
    }

    #[test]
    fn cleanup_does_not_remove_an_active_report_cooldown() {
        let mut tracker = FailureTracker::new(&config(PathBuf::from("/tmp/auth.log")));
        let ip = "198.51.100.22".parse().unwrap();
        let start = Instant::now();
        assert!(tracker.record(ip, "first", start).is_none());
        assert!(
            tracker
                .record(ip, "threshold", start + Duration::from_secs(1))
                .is_some()
        );

        tracker.cleanup(start + Duration::from_secs(2));
        assert!(tracker.entries[&ip].last_report.is_some());
        assert!(
            tracker
                .record(ip, "during-one", start + Duration::from_secs(3))
                .is_none()
        );
        assert!(
            tracker
                .record(ip, "during-two", start + Duration::from_secs(4))
                .is_none()
        );
        let after = tracker
            .record(ip, "after", start + Duration::from_secs(7))
            .unwrap();
        assert_eq!(after.fail_count, 3);
    }

    #[test]
    fn periodic_cleanup_honors_the_configured_interval() {
        let mut tracker = FailureTracker::new(&config(PathBuf::from("/tmp/auth.log")));
        let ip = "198.51.100.24".parse().unwrap();
        let start = Instant::now();
        assert!(tracker.record(ip, "failure", start).is_none());
        let mut summarizer = HourlySummarizer::default();
        let mut last_cleanup = start;
        let mut last_summary = start;

        run_periodic_maintenance(
            &mut tracker,
            &mut summarizer,
            start + Duration::from_secs(61),
            Duration::from_secs(300),
            &mut last_cleanup,
            &mut last_summary,
        );
        assert!(tracker.entries.contains_key(&ip));
        run_periodic_maintenance(
            &mut tracker,
            &mut summarizer,
            start + Duration::from_secs(300),
            Duration::from_secs(300),
            &mut last_cleanup,
            &mut last_summary,
        );
        assert!(!tracker.entries.contains_key(&ip));
    }

    #[test]
    fn tailer_skips_startup_content_keeps_partial_and_resets_on_rotation() {
        let (root, path) = temp_path("tail");
        fs::write(&path, b"Aug 10 12:00:00 host sshd[1]: Failed password for root from 198.51.100.10 port 22 ssh2\n").unwrap();
        let mut tailer = Tailer::open(std::slice::from_ref(&path)).unwrap().unwrap();
        fs::write(&path, b"Aug 10 12:00:00 host sshd[1]: Failed password for root from 198.51.100.10 port 22 ssh2\nAug 10 12:00:01 host sshd[2]: Failed password for root from 198.51.100.40 port 22 ssh2").unwrap();
        let (next, events) = tailer.scan();
        tailer = next;
        assert_eq!(events.unwrap().len(), 0);
        let mut stream = fs::OpenOptions::new().append(true).open(&path).unwrap();
        use std::io::Write;
        writeln!(stream).unwrap();
        let (next, events) = tailer.scan();
        tailer = next;
        assert_eq!(events.unwrap().len(), 1);
        let rotated = root.join("auth.log.1");
        fs::rename(&path, &rotated).unwrap();
        fs::write(
            &path,
            b"Aug 10 12:00:02 host sshd[3]: Invalid user root from 198.51.100.41 port 22\n",
        )
        .unwrap();
        let (_next, events) = tailer.scan();
        assert_eq!(events.unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tailer_switches_to_the_next_readable_log_after_failure() {
        let (root, primary) = temp_path("fallback");
        let alternative = root.join("secure.log");
        fs::write(&primary, []).unwrap();
        fs::write(
            &alternative,
            b"Aug 10 12:00:02 host sshd[3]: Invalid user root from 198.51.100.42 port 22\n",
        )
        .unwrap();
        let tailer = Tailer::open(&[primary.clone(), alternative.clone()])
            .unwrap()
            .unwrap();
        assert_eq!(tailer.current_path, primary);
        fs::remove_file(&primary).unwrap();
        let (tailer, events) = tailer.scan();
        assert!(events.is_err());
        let switched = tailer.switch_to_readable_alternative().unwrap();
        assert_eq!(switched.current_path, alternative);
        let (_tailer, events) = switched.scan();
        assert_eq!(events.unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tracker_lru_is_bounded_and_deterministic() {
        let mut tracker = FailureTracker::new(&config(PathBuf::from("/tmp/auth.log")));
        let start = Instant::now();
        let first = "198.51.100.1".parse().unwrap();
        let second = "198.51.100.2".parse().unwrap();
        let third = "198.51.100.3".parse().unwrap();
        tracker.record(first, "first", start);
        tracker.record(second, "second", start + Duration::from_secs(1));
        tracker.record(first, "touch", start + Duration::from_secs(2));
        tracker.record(third, "evict", start + Duration::from_secs(3));
        assert!(tracker.entries.contains_key(&first));
        assert!(!tracker.entries.contains_key(&second));
        assert!(tracker.entries.contains_key(&third));
    }

    #[test]
    fn failure_timestamp_queue_has_a_hard_per_ip_limit() {
        let mut bounded = config(PathBuf::from("/tmp/auth.log"));
        bounded.max_retries = usize::MAX;
        let mut tracker = FailureTracker::new(&bounded);
        let ip = "198.51.100.23".parse().unwrap();
        let start = Instant::now();
        for offset in 0..(MAX_FAILURE_TIMESTAMPS_PER_IP + 17) {
            assert!(
                tracker
                    .record(
                        ip,
                        "failure",
                        start + Duration::from_millis(u64::try_from(offset).unwrap()),
                    )
                    .is_none()
            );
        }
        assert_eq!(
            tracker.entries[&ip].failures.len(),
            MAX_FAILURE_TIMESTAMPS_PER_IP
        );
    }

    #[test]
    fn all_java_failure_patterns_extract_ipv4_addresses() {
        let lines = [
            "Failed publickey for root from 198.51.100.30 port 22 ssh2",
            "Invalid user oracle from 198.51.100.31 port 2222",
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=198.51.100.32",
            "Connection closed by invalid user oracle 198.51.100.33 port 45822 [preauth]",
            "error: maximum authentication attempts exceeded for root from 198.51.100.34 port 22 ssh2",
            "Bad protocol version identification 'GET / HTTP/1.1' from 198.51.100.35 port 22",
            "Did not receive identification string from 198.51.100.36 port 22",
            "refused connect from 198.51.100.37",
        ];
        for (index, line) in lines.iter().enumerate() {
            let expected = format!("198.51.100.{}", 30 + index).parse().unwrap();
            assert_eq!(
                extract_failed_ip(line),
                Some(expected),
                "pattern {index} failed"
            );
        }
    }

    #[test]
    fn oversized_partial_lines_are_dropped_without_growing_state() {
        let (root, path) = temp_path("oversized");
        fs::write(&path, []).unwrap();
        let tailer = Tailer::open(std::slice::from_ref(&path)).unwrap().unwrap();
        let mut payload = vec![b'x'; MAX_LINE_BYTES + 1];
        payload.push(b'\n');
        payload.extend_from_slice(
            b"Aug 10 12:00:01 host sshd[9]: Invalid user root from 198.51.100.99 port 22\n",
        );
        fs::write(&path, payload).unwrap();
        let (tailer, events) = tailer.scan();
        assert_eq!(events.unwrap().len(), 1);
        assert!(tailer.partial_line.len() <= MAX_LINE_BYTES);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_event_limit_defers_complete_lines_without_dropping_them() {
        let (root, path) = temp_path("event-limit");
        fs::write(&path, []).unwrap();
        let tailer = Tailer::open(std::slice::from_ref(&path)).unwrap().unwrap();
        let line = b"Aug 10 12:00:01 host sshd[9]: Invalid user root from 198.51.100.99 port 22\n";
        fs::write(&path, line.repeat(MAX_EVENTS_PER_SCAN + 1)).unwrap();
        let (tailer, first) = tailer.scan();
        assert_eq!(first.unwrap().len(), MAX_EVENTS_PER_SCAN);
        let (_tailer, second) = tailer.scan();
        assert_eq!(second.unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hourly_summary_is_deterministic_and_resets_the_first_info_gate() {
        let mut summarizer = HourlySummarizer::default();
        let first = Report {
            ip: "198.51.100.2".parse().unwrap(),
            fail_count: 2,
            metadata: String::new(),
            sample: "Failed password for root from 198.51.100.2 port 22".into(),
        };
        let second = Report {
            ip: "198.51.100.1".parse().unwrap(),
            fail_count: 3,
            metadata: String::new(),
            sample: "Invalid user admin from 198.51.100.1 port 22".into(),
        };
        assert!(summarizer.record(&first));
        assert!(!summarizer.record(&second));
        assert_eq!(
            summarizer.generate_and_reset("Hourly summary").as_deref(),
            Some(
                "Fail2Ban: Hourly summary \u{2014} 2 IPs, 2 reports, 5 failures. IPs: \
                 198.51.100.1(3), 198.51.100.2(2). Users: admin,root. Samples: \
                 [Failed password for root from 198.51.100.2 port 22] | \
                 [Invalid user admin from 198.51.100.1 port 22]"
            )
        );
        assert!(summarizer.generate_and_reset("Hourly summary").is_none());
        assert!(summarizer.record(&first));
    }

    #[test]
    fn hourly_summary_ip_state_is_bounded() {
        let mut summarizer = HourlySummarizer::default();
        for index in 0..=MAX_SUMMARY_IPS {
            summarizer.record(&Report {
                ip: IpAddr::V4(std::net::Ipv4Addr::from(u32::try_from(index).unwrap())),
                fail_count: 2,
                metadata: String::new(),
                sample: "Invalid user bounded from 198.51.100.1 port 22".into(),
            });
        }
        assert_eq!(summarizer.by_ip.len(), MAX_SUMMARY_IPS);
        assert!(summarizer.overflowed_ips);
        let summary = summarizer.generate_and_reset("Hourly summary").unwrap();
        assert!(summary.contains("4096+ IPs"));
        assert!(summary.contains("additional IP reports omitted"));
    }

    #[tokio::test]
    async fn missing_log_waits_for_and_joins_cancellation() {
        let (root, path) = temp_path("missing-cancel");
        let runtime = RuntimeConfig::from_properties(Properties::default()).unwrap();
        let pool = database::create_pool(&runtime).unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run(
            config(path),
            CringeService::new(pool),
            cancellation.clone(),
        ));
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        cancellation.cancel();
        timeout(Duration::from_secs(3), task)
            .await
            .expect("Fail2Ban did not join cancellation")
            .expect("Fail2Ban task panicked");
        fs::remove_dir_all(root).unwrap();
    }
}
