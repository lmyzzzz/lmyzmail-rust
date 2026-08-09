use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    fmt,
    future::Future,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::time::{Interval, MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;

use crate::{
    config::XdpPpsMonitorConfig,
    cringe::{CringeError, CringeService, XdpTrafficActivity},
    xdp::{XdpError, XdpIpStatsEntry, XdpPpsStats, XdpService},
};

const IP_STATE_EXPIRY_MS: u64 = 300_000;
const EVENT_COOLDOWN_MS: u64 = 2_000;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum XdpTrafficKind {
    PpsOverlimit,
    SynFlood,
}

impl XdpTrafficKind {
    fn activity(self) -> XdpTrafficActivity {
        match self {
            Self::PpsOverlimit => XdpTrafficActivity::PpsOverlimit,
            Self::SynFlood => XdpTrafficActivity::SynFlood,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct XdpTrafficEvent {
    pub ip: IpAddr,
    pub kind: XdpTrafficKind,
    pub rate: u64,
    pub threshold: u64,
}

impl XdpTrafficEvent {
    fn metadata(self) -> String {
        match self.kind {
            XdpTrafficKind::PpsOverlimit => {
                format!("pps={},threshold={}", self.rate, self.threshold)
            }
            XdpTrafficKind::SynFlood => {
                format!("synPps={},threshold={}", self.rate, self.threshold)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GlobalRateAlert {
    Elevated,
    Critical,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct GlobalAlerts {
    pub pps: Option<GlobalRateAlert>,
    pub syn: Option<GlobalRateAlert>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct IpMonitorState {
    packets: u64,
    syn_packets: u64,
    last_seen_ms: u64,
    pps_exceed_count: u32,
    syn_exceed_count: u32,
    last_pps_event_ms: Option<u64>,
    last_syn_event_ms: Option<u64>,
}

impl IpMonitorState {
    const fn first(entry: XdpIpStatsEntry, now_ms: u64) -> Self {
        Self {
            packets: entry.stats.packets,
            syn_packets: entry.stats.syn_packets,
            last_seen_ms: now_ms,
            pps_exceed_count: 0,
            syn_exceed_count: 0,
            last_pps_event_ms: None,
            last_syn_event_ms: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PpsMonitorStatus {
    pub current_stats: Option<XdpPpsStats>,
    pub consecutive_pps_exceed: u32,
    pub consecutive_syn_exceed: u32,
    pub tracked_ip_count: usize,
    pub pps_exceed_ip_count: usize,
    pub syn_exceed_ip_count: usize,
    pub global_history_count: usize,
}

#[cfg(feature = "xdp-test-hooks")]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct PpsMonitorProgress {
    pub completed_polls: u64,
    pub observed_events: u64,
}

pub struct PpsMonitorState {
    config: XdpPpsMonitorConfig,
    consecutive_pps_exceed: u32,
    consecutive_syn_exceed: u32,
    current_stats: Option<XdpPpsStats>,
    global_history: VecDeque<XdpPpsStats>,
    ip_states: HashMap<IpAddr, IpMonitorState>,
    ip_recency: BTreeSet<(u64, IpAddr)>,
}

impl PpsMonitorState {
    pub fn new(config: XdpPpsMonitorConfig) -> Self {
        Self {
            global_history: VecDeque::with_capacity(config.ring_buffer_size as usize),
            ip_states: HashMap::with_capacity(config.max_ips_per_poll as usize),
            ip_recency: BTreeSet::new(),
            config,
            consecutive_pps_exceed: 0,
            consecutive_syn_exceed: 0,
            current_stats: None,
        }
    }

    pub fn observe_global(&mut self, stats: XdpPpsStats) -> GlobalAlerts {
        self.current_stats = Some(stats);
        if self.global_history.len() == self.config.ring_buffer_size as usize {
            self.global_history.pop_front();
        }
        self.global_history.push_back(stats);

        GlobalAlerts {
            pps: update_global_rate(
                &mut self.consecutive_pps_exceed,
                stats.pps,
                self.config.pps_warn_threshold,
                self.config.pps_critical_threshold,
                self.config.consecutive_exceed_count,
            ),
            syn: update_global_rate(
                &mut self.consecutive_syn_exceed,
                stats.syn_pps,
                self.config.syn_pps_warn_threshold,
                self.config.syn_pps_critical_threshold,
                self.config.consecutive_exceed_count,
            ),
        }
    }

    pub fn observe_ips(
        &mut self,
        entries: &[XdpIpStatsEntry],
        now_ms: u64,
    ) -> Vec<XdpTrafficEvent> {
        let mut events = Vec::new();
        let capacity = self.config.max_ips_per_poll as usize;
        for entry in entries.iter().copied().take(capacity) {
            if let Some(previous) = self.ip_states.get(&entry.ip).copied() {
                self.ip_recency.remove(&(previous.last_seen_ms, entry.ip));
                let pps = configured_rate(
                    entry.stats.packets.checked_sub(previous.packets),
                    self.config.poll_interval_ms,
                );
                let syn_pps = configured_rate(
                    entry.stats.syn_packets.checked_sub(previous.syn_packets),
                    self.config.poll_interval_ms,
                );
                let state = self
                    .ip_states
                    .get_mut(&entry.ip)
                    .expect("existing PPS state remains present");
                if let Some(event) = update_per_ip_rate(
                    entry.ip,
                    XdpTrafficKind::PpsOverlimit,
                    pps,
                    self.config.per_ip_pps_warn_threshold,
                    self.config.per_ip_pps_critical_threshold,
                    self.config.consecutive_exceed_count,
                    now_ms,
                    &mut state.pps_exceed_count,
                    &mut state.last_pps_event_ms,
                ) {
                    events.push(event);
                }
                if let Some(event) = update_per_ip_rate(
                    entry.ip,
                    XdpTrafficKind::SynFlood,
                    syn_pps,
                    self.config.per_ip_syn_pps_warn_threshold,
                    self.config.per_ip_syn_pps_critical_threshold,
                    self.config.consecutive_exceed_count,
                    now_ms,
                    &mut state.syn_exceed_count,
                    &mut state.last_syn_event_ms,
                ) {
                    events.push(event);
                }
                state.packets = entry.stats.packets;
                state.syn_packets = entry.stats.syn_packets;
                state.last_seen_ms = now_ms;
            } else {
                self.evict_for_insert(capacity);
                self.ip_states
                    .insert(entry.ip, IpMonitorState::first(entry, now_ms));
            }
            self.ip_recency.insert((now_ms, entry.ip));
        }
        self.expire_absent_states(now_ms);
        events
    }

    pub fn status(&self) -> PpsMonitorStatus {
        PpsMonitorStatus {
            current_stats: self.current_stats,
            consecutive_pps_exceed: self.consecutive_pps_exceed,
            consecutive_syn_exceed: self.consecutive_syn_exceed,
            tracked_ip_count: self.ip_states.len(),
            pps_exceed_ip_count: self
                .ip_states
                .values()
                .filter(|state| state.pps_exceed_count > 0)
                .count(),
            syn_exceed_ip_count: self
                .ip_states
                .values()
                .filter(|state| state.syn_exceed_count > 0)
                .count(),
            global_history_count: self.global_history.len(),
        }
    }

    fn evict_for_insert(&mut self, capacity: usize) {
        if self.ip_states.len() < capacity {
            return;
        }
        if let Some((last_seen, ip)) = self.ip_recency.pop_first() {
            let removed = self.ip_states.remove(&ip);
            debug_assert_eq!(removed.map(|state| state.last_seen_ms), Some(last_seen));
        }
    }

    fn expire_absent_states(&mut self, now_ms: u64) {
        loop {
            let Some((last_seen, ip)) = self.ip_recency.first().copied() else {
                break;
            };
            if now_ms.saturating_sub(last_seen) <= IP_STATE_EXPIRY_MS {
                break;
            }
            self.ip_recency.pop_first();
            self.ip_states.remove(&ip);
        }
    }
}

fn configured_rate(delta: Option<u64>, interval_ms: u64) -> u64 {
    let Some(delta) = delta else {
        return 0;
    };
    let scaled = u128::from(delta) * 1_000;
    (scaled / u128::from(interval_ms)).min(u128::from(u64::MAX)) as u64
}

fn update_global_rate(
    consecutive: &mut u32,
    rate: u64,
    warn_threshold: u64,
    critical_threshold: u64,
    required: u32,
) -> Option<GlobalRateAlert> {
    if rate >= critical_threshold {
        *consecutive = consecutive.saturating_add(1);
        (*consecutive >= required).then_some(GlobalRateAlert::Critical)
    } else if rate >= warn_threshold {
        *consecutive = consecutive.saturating_add(1);
        Some(GlobalRateAlert::Elevated)
    } else {
        *consecutive = 0;
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn update_per_ip_rate(
    ip: IpAddr,
    kind: XdpTrafficKind,
    rate: u64,
    warn_threshold: u64,
    critical_threshold: u64,
    required: u32,
    now_ms: u64,
    consecutive: &mut u32,
    last_event_ms: &mut Option<u64>,
) -> Option<XdpTrafficEvent> {
    if rate >= critical_threshold {
        *consecutive = consecutive.saturating_add(1);
        let cooldown_elapsed = last_event_ms.is_none_or(|last| {
            now_ms
                .checked_sub(last)
                .is_some_and(|elapsed| elapsed > EVENT_COOLDOWN_MS)
        });
        if *consecutive >= required && cooldown_elapsed {
            *last_event_ms = Some(now_ms);
            return Some(XdpTrafficEvent {
                ip,
                kind,
                rate,
                threshold: critical_threshold,
            });
        }
    } else if rate >= warn_threshold {
        *consecutive = consecutive.saturating_add(1);
    } else {
        *consecutive = 0;
    }
    None
}

pub async fn run_pps_monitor(
    xdp: Arc<XdpService>,
    cringe: CringeService,
    cancellation: CancellationToken,
) {
    run_pps_monitor_inner(xdp, cringe, cancellation, None).await;
}

#[cfg(feature = "xdp-test-hooks")]
pub async fn run_pps_monitor_observed(
    xdp: Arc<XdpService>,
    cringe: CringeService,
    cancellation: CancellationToken,
    progress: tokio::sync::watch::Sender<PpsMonitorProgress>,
) {
    run_pps_monitor_inner(xdp, cringe, cancellation, Some(progress)).await;
}

async fn run_pps_monitor_inner(
    xdp: Arc<XdpService>,
    cringe: CringeService,
    cancellation: CancellationToken,
    #[cfg(feature = "xdp-test-hooks")] progress: Option<
        tokio::sync::watch::Sender<PpsMonitorProgress>,
    >,
    #[cfg(not(feature = "xdp-test-hooks"))] _progress: Option<()>,
) {
    let config = xdp.config().pps_monitor.clone();
    if !xdp.config().enabled || !config.enabled {
        cancellation.cancelled().await;
        return;
    }
    let mut state = PpsMonitorState::new(config.clone());
    let mut ticker = fixed_rate_interval(Duration::from_millis(config.poll_interval_ms));
    #[cfg(feature = "xdp-test-hooks")]
    let mut current_progress = PpsMonitorProgress::default();

    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            _ = ticker.tick() => {}
        }
        if !xdp.ready() {
            continue;
        }
        match poll_once(&xdp, &cringe, &mut state, &cancellation).await {
            Ok(observed_events) => {
                #[cfg(not(feature = "xdp-test-hooks"))]
                let _ = observed_events;
                #[cfg(feature = "xdp-test-hooks")]
                if let Some(progress) = progress.as_ref() {
                    current_progress.completed_polls =
                        current_progress.completed_polls.saturating_add(1);
                    current_progress.observed_events = current_progress
                        .observed_events
                        .saturating_add(observed_events as u64);
                    progress.send_replace(current_progress);
                }
            }
            Err(error) => eprintln!("lmyzmail XDP PPS poll failed: {error}"),
        }
    }
}

fn fixed_rate_interval(period: Duration) -> Interval {
    let mut ticker = interval(period);
    // Spring's frozen fixedRate scheduler catches up delayed executions without overlap.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Burst);
    ticker
}

async fn poll_once(
    xdp: &XdpService,
    cringe: &CringeService,
    state: &mut PpsMonitorState,
    cancellation: &CancellationToken,
) -> Result<usize, PpsMonitorError> {
    observe_global_read(state, xdp.pps_stats(cancellation).await);
    let read = xdp
        .all_ip_stats_best_effort(state.config.max_ips_per_poll as usize, cancellation)
        .await?;
    if let Some(error) = read.v4_error {
        eprintln!("lmyzmail XDP IPv4 per-IP statistics read failed: {error}");
    }
    if let Some(error) = read.v6_error {
        eprintln!("lmyzmail XDP IPv6 per-IP statistics read failed: {error}");
    }
    let events = state.observe_ips(&read.entries, unix_time_ms());
    let observed_events = events.len();
    process_observed_events(
        state.config.record_to_cringe,
        events,
        xdp.config().ban_threshold,
        xdp.config().reason_code_pps_overlimit,
        xdp.config().reason_code_syn_flood,
        cancellation,
        |event, metadata, operation_cancellation| async move {
            cringe
                .record_xdp_traffic(
                    event.ip,
                    event.kind.activity(),
                    &metadata,
                    &operation_cancellation,
                )
                .await
        },
        |event, reason, operation_cancellation| async move {
            xdp.ban(&event.ip.to_string(), reason, &operation_cancellation)
                .await
        },
    )
    .await?;
    Ok(observed_events)
}

fn observe_global_read(state: &mut PpsMonitorState, read: Result<Option<XdpPpsStats>, XdpError>) {
    match read {
        Ok(Some(stats)) => {
            let alerts = state.observe_global(stats);
            log_global_alerts(alerts, stats, state);
        }
        Ok(None) => {}
        Err(error) => eprintln!("lmyzmail XDP global PPS read failed: {error}"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_observed_events<W, WFut, B, BFut>(
    record_to_cringe: bool,
    events: Vec<XdpTrafficEvent>,
    ban_threshold: i32,
    pps_reason: i32,
    syn_reason: i32,
    cancellation: &CancellationToken,
    mut write: W,
    mut ban: B,
) -> Result<(), CringeError>
where
    W: FnMut(XdpTrafficEvent, String, CancellationToken) -> WFut,
    WFut: Future<Output = Result<Option<i32>, CringeError>>,
    B: FnMut(XdpTrafficEvent, i32, CancellationToken) -> BFut,
    BFut: Future<Output = Result<bool, XdpError>>,
{
    if !record_to_cringe {
        return Ok(());
    }
    for event in events {
        let metadata = event.metadata();
        let Some(score) = write(event, metadata, cancellation.clone()).await? else {
            continue;
        };
        if score < ban_threshold {
            continue;
        }
        let reason = match event.kind {
            XdpTrafficKind::PpsOverlimit => pps_reason,
            XdpTrafficKind::SynFlood => syn_reason,
        };
        if let Err(error) = ban(event, reason, cancellation.clone()).await {
            eprintln!(
                "lmyzmail XDP automatic ban failed for {} after {:?}: {error}",
                event.ip, event.kind
            );
        }
    }
    Ok(())
}

fn log_global_alerts(alerts: GlobalAlerts, stats: XdpPpsStats, state: &PpsMonitorState) {
    match alerts.pps {
        Some(GlobalRateAlert::Critical) => eprintln!(
            "lmyzmail XDP global PPS critical: {} pps (threshold: {}, consecutive: {})",
            stats.pps, state.config.pps_critical_threshold, state.consecutive_pps_exceed
        ),
        Some(GlobalRateAlert::Elevated) => {
            eprintln!("lmyzmail XDP global PPS elevated: {} pps", stats.pps)
        }
        None => {}
    }
    match alerts.syn {
        Some(GlobalRateAlert::Critical) => eprintln!(
            "lmyzmail XDP global SYN flood: {} syn/s (threshold: {}, consecutive: {})",
            stats.syn_pps, state.config.syn_pps_critical_threshold, state.consecutive_syn_exceed
        ),
        Some(GlobalRateAlert::Elevated) => eprintln!(
            "lmyzmail XDP global SYN rate elevated: {} syn/s",
            stats.syn_pps
        ),
        None => {}
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[derive(Debug)]
enum PpsMonitorError {
    Xdp(XdpError),
    Cringe(CringeError),
}

impl fmt::Display for PpsMonitorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xdp(error) => write!(formatter, "XDP operation failed: {error}"),
            Self::Cringe(error) => write!(formatter, "Cringe write failed: {error}"),
        }
    }
}

impl From<XdpError> for PpsMonitorError {
    fn from(error: XdpError) -> Self {
        Self::Xdp(error)
    }
}

impl From<CringeError> for PpsMonitorError {
    fn from(error: CringeError) -> Self {
        Self::Cringe(error)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{Arc, Mutex},
    };

    use futures_util::FutureExt;
    use proptest::prelude::*;
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::{
        config::{Properties, RuntimeConfig},
        database,
        xdp::XdpPerIpStats,
    };

    fn config() -> XdpPpsMonitorConfig {
        XdpPpsMonitorConfig {
            enabled: true,
            poll_interval_ms: 500,
            pps_warn_threshold: 100,
            pps_critical_threshold: 200,
            syn_pps_warn_threshold: 10,
            syn_pps_critical_threshold: 20,
            per_ip_pps_warn_threshold: 10,
            per_ip_pps_critical_threshold: 20,
            per_ip_syn_pps_warn_threshold: 2,
            per_ip_syn_pps_critical_threshold: 4,
            consecutive_exceed_count: 2,
            record_to_cringe: true,
            max_ips_per_poll: 2,
            ring_buffer_size: 2,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fixed_rate_scheduler_catches_up_every_missed_oracle_tick() {
        let mut ticker = fixed_rate_interval(Duration::from_millis(10));
        ticker.tick().await;
        tokio::time::advance(Duration::from_millis(35)).await;

        for _ in 0..3 {
            assert!(ticker.tick().now_or_never().is_some());
        }
        assert!(ticker.tick().now_or_never().is_none());
    }

    fn entry(last_octet: u8, packets: u64, syn_packets: u64) -> XdpIpStatsEntry {
        XdpIpStatsEntry {
            ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, last_octet)),
            stats: XdpPerIpStats {
                packets,
                syn_packets,
            },
        }
    }

    #[test]
    fn warn_samples_contribute_to_the_frozen_consecutive_counter() {
        let mut state = PpsMonitorState::new(config());
        assert_eq!(
            state.observe_global(XdpPpsStats {
                pps: 100,
                syn_pps: 10,
                ..XdpPpsStats::default()
            }),
            GlobalAlerts {
                pps: Some(GlobalRateAlert::Elevated),
                syn: Some(GlobalRateAlert::Elevated),
            }
        );
        assert_eq!(
            state.observe_global(XdpPpsStats {
                pps: 200,
                syn_pps: 20,
                ..XdpPpsStats::default()
            }),
            GlobalAlerts {
                pps: Some(GlobalRateAlert::Critical),
                syn: Some(GlobalRateAlert::Critical),
            }
        );
        assert_eq!(state.status().global_history_count, 2);
        state.observe_global(XdpPpsStats::default());
        assert_eq!(state.status().global_history_count, 2);
        assert_eq!(state.status().consecutive_pps_exceed, 0);
    }

    #[test]
    fn configured_interval_and_pps_before_syn_match_the_oracle() {
        let mut state = PpsMonitorState::new(config());
        state.observe_ips(&[entry(1, 1_000, 100)], 1_000);
        assert!(state.observe_ips(&[entry(1, 1_005, 101)], 1_500).is_empty());
        let events = state.observe_ips(&[entry(1, 1_015, 103)], 2_000);
        assert_eq!(
            events,
            vec![
                XdpTrafficEvent {
                    ip: entry(1, 0, 0).ip,
                    kind: XdpTrafficKind::PpsOverlimit,
                    rate: 20,
                    threshold: 20,
                },
                XdpTrafficEvent {
                    ip: entry(1, 0, 0).ip,
                    kind: XdpTrafficKind::SynFlood,
                    rate: 4,
                    threshold: 4,
                },
            ]
        );
        assert_eq!(events[0].metadata(), "pps=20,threshold=20");
        assert_eq!(events[1].metadata(), "synPps=4,threshold=4");
    }

    #[test]
    fn cooldown_is_strictly_greater_than_two_seconds() {
        let mut state = PpsMonitorState::new(config());
        state.observe_ips(&[entry(1, 0, 0)], 0);
        state.observe_ips(&[entry(1, 10, 2)], 500);
        assert_eq!(state.observe_ips(&[entry(1, 20, 4)], 1_000).len(), 2);
        assert!(state.observe_ips(&[entry(1, 30, 6)], 3_000).is_empty());
        assert_eq!(state.observe_ips(&[entry(1, 40, 8)], 3_001).len(), 2);
    }

    #[test]
    fn counters_saturate_without_disabling_long_running_monitoring() {
        let mut state = PpsMonitorState::new(config());
        state.consecutive_pps_exceed = u32::MAX;
        assert_eq!(
            state
                .observe_global(XdpPpsStats {
                    pps: 200,
                    ..XdpPpsStats::default()
                })
                .pps,
            Some(GlobalRateAlert::Critical)
        );
        assert_eq!(state.consecutive_pps_exceed, u32::MAX);

        state.observe_ips(&[entry(1, 0, 0)], 0);
        let ip_state = state.ip_states.get_mut(&entry(1, 0, 0).ip).unwrap();
        ip_state.pps_exceed_count = u32::MAX;
        let events = state.observe_ips(&[entry(1, 10, 0)], 500);
        assert_eq!(events.len(), 1);
        assert_eq!(
            state.ip_states[&entry(1, 0, 0).ip].pps_exceed_count,
            u32::MAX
        );
    }

    #[test]
    fn global_read_failure_does_not_disable_per_ip_detection() {
        let mut state = PpsMonitorState::new(config());
        observe_global_read(
            &mut state,
            Err(XdpError::Native {
                code: -5,
                message: "injected global read failure".into(),
            }),
        );
        assert!(state.current_stats.is_none());
        state.observe_ips(&[entry(1, 0, 0)], 0);
        state.observe_ips(&[entry(1, 10, 2)], 500);
        assert_eq!(state.observe_ips(&[entry(1, 20, 4)], 1_000).len(), 2);
    }

    #[test]
    fn ip_state_and_cooldowns_are_evicted_as_one_bounded_unit() {
        let mut state = PpsMonitorState::new(config());
        state.observe_ips(&[entry(1, 0, 0), entry(2, 0, 0)], 1_000);
        state.observe_ips(&[entry(1, 10, 2)], 1_500);
        state.observe_ips(&[entry(1, 20, 4)], 2_000);
        assert_eq!(state.status().tracked_ip_count, 2);

        state.observe_ips(&[entry(3, 0, 0)], 2_001);
        assert_eq!(state.status().tracked_ip_count, 2);
        assert!(!state.ip_states.contains_key(&entry(2, 0, 0).ip));

        state.observe_ips(&[entry(2, 100, 100)], 2_002);
        assert_eq!(state.status().tracked_ip_count, 2);
        assert!(state.observe_ips(&[entry(2, 200, 200)], 2_003).is_empty());
    }

    #[tokio::test]
    async fn not_ready_monitor_waits_for_and_joins_cancellation() {
        let mut properties = Properties::default();
        properties
            .insert("lmyzmail.xdp.enabled".into(), "true".into())
            .unwrap();
        let runtime = RuntimeConfig::from_properties(properties).unwrap();
        let pool = database::create_pool(&runtime).unwrap();
        let xdp = Arc::new(XdpService::from_config(&runtime.xdp).unwrap());
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run_pps_monitor(
            xdp,
            CringeService::new(pool),
            cancellation.clone(),
        ));
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        cancellation.cancel();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("PPS monitor did not join cancellation")
            .expect("PPS monitor task panicked");
    }

    #[tokio::test]
    async fn record_disabled_has_no_writer_or_ban_side_effects() {
        let result = process_observed_events(
            false,
            vec![XdpTrafficEvent {
                ip: entry(1, 0, 0).ip,
                kind: XdpTrafficKind::PpsOverlimit,
                rate: 20,
                threshold: 20,
            }],
            80,
            5,
            6,
            &CancellationToken::new(),
            |_, _, _| async {
                panic!("record-to-cringe=false invoked the database writer");
                #[allow(unreachable_code)]
                Ok::<Option<i32>, CringeError>(None)
            },
            |_, _, _| async {
                panic!("record-to-cringe=false invoked the XDP ban path");
                #[allow(unreachable_code)]
                Ok::<bool, XdpError>(false)
            },
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn a_failed_ban_does_not_drop_later_detected_events() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let bans = Arc::new(Mutex::new(Vec::new()));
        let events = vec![
            XdpTrafficEvent {
                ip: entry(1, 0, 0).ip,
                kind: XdpTrafficKind::PpsOverlimit,
                rate: 20,
                threshold: 20,
            },
            XdpTrafficEvent {
                ip: entry(1, 0, 0).ip,
                kind: XdpTrafficKind::SynFlood,
                rate: 4,
                threshold: 4,
            },
        ];
        let write_events = Arc::clone(&writes);
        let ban_events = Arc::clone(&bans);
        process_observed_events(
            true,
            events,
            80,
            5,
            6,
            &CancellationToken::new(),
            move |event, _, _| {
                let write_events = Arc::clone(&write_events);
                async move {
                    write_events.lock().unwrap().push(event.kind);
                    Ok(Some(100))
                }
            },
            move |event, reason, _| {
                let ban_events = Arc::clone(&ban_events);
                async move {
                    ban_events.lock().unwrap().push((event.kind, reason));
                    if event.kind == XdpTrafficKind::PpsOverlimit {
                        Err(XdpError::Native {
                            code: -5,
                            message: "injected ban failure".into(),
                        })
                    } else {
                        Ok(true)
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(
            *writes.lock().unwrap(),
            vec![XdpTrafficKind::PpsOverlimit, XdpTrafficKind::SynFlood]
        );
        assert_eq!(
            *bans.lock().unwrap(),
            vec![
                (XdpTrafficKind::PpsOverlimit, 5),
                (XdpTrafficKind::SynFlood, 6)
            ]
        );
    }

    proptest! {
        #[test]
        fn counter_regression_never_creates_a_rate_event(
            packets in 0_u64..1_000_000,
            syn_packets in 0_u64..1_000_000,
        ) {
            let mut state = PpsMonitorState::new(config());
            state.observe_ips(&[entry(1, packets.saturating_add(1), syn_packets.saturating_add(1))], 1);
            let events = state.observe_ips(&[entry(1, packets, syn_packets)], 2);
            prop_assert!(events.is_empty());
        }
    }
}
