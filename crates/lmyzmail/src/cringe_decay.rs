use std::{future::Future, pin::Pin, str::FromStr, sync::Arc, time::Duration};

use chrono::{Local, LocalResult, NaiveDate, NaiveDateTime, TimeZone};
use serde::{Serialize, Serializer};
use serde_json::Number;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::{
    config::CringeDecayConfig,
    cringe::{CringeError, CringeService},
    xdp_sync::XdpSyncService,
};

const UNBAN_THRESHOLD: i32 = 30;
const MAX_LOCAL_DATE_SEARCH_DAYS: usize = 370;

type ScheduledJob<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

#[derive(Debug, Clone, Copy)]
struct DurationSeconds(Duration);

impl Serialize for DurationSeconds {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = format!("{}.{:09}", self.0.as_secs(), self.0.subsec_nanos());
        Number::from_str(&value)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecayConfigInfo {
    interval: DurationSeconds,
    amount: i32,
    check_interval: DurationSeconds,
    hourly_rate: f64,
    retention_days: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsDecayConfig {
    interval: String,
    amount: i32,
    hourly_rate: f64,
}

pub fn stats_config(config: &CringeDecayConfig) -> StatsDecayConfig {
    StatsDecayConfig {
        interval: java_duration(config.interval),
        amount: config.amount,
        hourly_rate: f64::from(config.amount) / (config.interval.as_millis() as f64 / 3_600_000.0),
    }
}

impl From<&CringeDecayConfig> for DecayConfigInfo {
    fn from(config: &CringeDecayConfig) -> Self {
        let interval_millis = config.interval.as_millis() as f64;
        Self {
            interval: DurationSeconds(config.interval),
            amount: config.amount,
            check_interval: DurationSeconds(config.check_interval),
            hourly_rate: f64::from(config.amount) / (interval_millis / 3_600_000.0),
            retention_days: config.activity_retention_days,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecayResult {
    #[serde(rename = "affectedIPs")]
    pub affected_ips: u64,
    pub message: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecayEstimate {
    current_score: i32,
    decay_config: DecayEstimateConfig,
    estimated_cycles: i32,
    estimated_time_to_unban: String,
    ip_address: String,
    score_to_decay: i32,
    unban_threshold: i32,
}

#[derive(Debug, Serialize)]
struct DecayEstimateConfig {
    interval: String,
    amount: i32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DecayEstimateError {
    Disabled,
    Overflow,
}

pub fn config_info(config: &CringeDecayConfig) -> DecayConfigInfo {
    DecayConfigInfo::from(config)
}

pub fn estimate(
    ip_address: String,
    current_score: i32,
    config: &CringeDecayConfig,
) -> Result<DecayEstimate, DecayEstimateError> {
    let score_to_decay = current_score.saturating_sub(UNBAN_THRESHOLD).max(0);
    if config.amount == 0 && score_to_decay > 0 {
        return Err(DecayEstimateError::Disabled);
    }
    let estimated_cycles = if score_to_decay == 0 {
        0
    } else {
        score_to_decay
            .checked_add(config.amount - 1)
            .ok_or(DecayEstimateError::Overflow)?
            / config.amount
    };
    let duration = config
        .interval
        .checked_mul(u32::try_from(estimated_cycles).map_err(|_| DecayEstimateError::Overflow)?)
        .ok_or(DecayEstimateError::Overflow)?;
    Ok(DecayEstimate {
        current_score,
        decay_config: DecayEstimateConfig {
            interval: java_duration(duration_for_config(config)),
            amount: config.amount,
        },
        estimated_cycles,
        estimated_time_to_unban: java_duration(duration),
        ip_address,
        score_to_decay,
        unban_threshold: UNBAN_THRESHOLD,
    })
}

fn duration_for_config(config: &CringeDecayConfig) -> Duration {
    config.interval
}

pub async fn perform_decay(
    cringe: &CringeService,
    xdp_sync: &XdpSyncService,
    config: &CringeDecayConfig,
    cancellation: &CancellationToken,
) -> Result<DecayResult, CringeError> {
    let affected_ips = cringe
        .perform_score_decay(config.interval, config.amount, cancellation)
        .await?;
    if let Err(error) = xdp_sync.perform_decay_unbans(cancellation).await {
        eprintln!("lmyzmail XDP decay unban sync failed: {error}");
    }
    Ok(DecayResult {
        affected_ips,
        message: "Decay completed",
    })
}

pub async fn run_scheduler(
    cringe: CringeService,
    xdp_sync: Arc<XdpSyncService>,
    config: CringeDecayConfig,
    cancellation: CancellationToken,
) {
    let decay = run_decay_scheduler(&cringe, &xdp_sync, &config, &cancellation);
    let cleanup = run_cleanup_scheduler(&cringe, &config, &cancellation);
    tokio::join!(decay, cleanup);
}

async fn run_decay_scheduler(
    cringe: &CringeService,
    xdp_sync: &XdpSyncService,
    config: &CringeDecayConfig,
    cancellation: &CancellationToken,
) {
    run_fixed_delay_until_cancelled(
        config.check_interval,
        config.check_interval,
        cancellation,
        || {
            Box::pin(async move {
                match perform_decay(cringe, xdp_sync, config, cancellation).await {
                    Ok(_) => {}
                    Err(CringeError::Cancelled) if cancellation.is_cancelled() => {}
                    Err(error) => eprintln!("lmyzmail scheduled cringe decay failed: {error}"),
                }
            })
        },
    )
    .await;
}

async fn run_fixed_delay_until_cancelled<'a>(
    initial_delay: Duration,
    interval: Duration,
    cancellation: &CancellationToken,
    mut operation: impl FnMut() -> ScheduledJob<'a>,
) {
    let mut delay = Box::pin(sleep(initial_delay));
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            () = &mut delay => operation().await,
        }
        if cancellation.is_cancelled() {
            break;
        }
        delay.as_mut().reset(tokio::time::Instant::now() + interval);
    }
}

async fn run_cleanup_scheduler(
    cringe: &CringeService,
    config: &CringeDecayConfig,
    cancellation: &CancellationToken,
) {
    let mut cleanup_delay = Box::pin(sleep(delay_until_next_cleanup()));
    loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break,
            () = &mut cleanup_delay => {
                match cringe.cleanup_old_activities(config.activity_retention_days, cancellation).await {
                    Ok(_) => {}
                    Err(CringeError::Cancelled) if cancellation.is_cancelled() => break,
                    Err(error) => eprintln!("lmyzmail scheduled cringe activity cleanup failed: {error}"),
                }
                cleanup_delay.as_mut().reset(tokio::time::Instant::now() + delay_until_next_cleanup());
            }
        }
    }
}

fn delay_until_next_cleanup() -> Duration {
    let now = Local::now();
    let Some(target) = next_cleanup_at(&now) else {
        return Duration::from_secs(60);
    };
    target
        .signed_duration_since(now)
        .to_std()
        .unwrap_or_else(|_| Duration::from_secs(1))
        .max(Duration::from_secs(1))
}

fn next_cleanup_at(now: &chrono::DateTime<Local>) -> Option<chrono::DateTime<Local>> {
    resolve_next_cleanup(now.date_naive(), now, |candidate| {
        Local.from_local_datetime(candidate)
    })
}

fn resolve_next_cleanup<T: Ord>(
    mut date: NaiveDate,
    now: &T,
    mut resolve: impl FnMut(&NaiveDateTime) -> LocalResult<T>,
) -> Option<T> {
    for _ in 0..=MAX_LOCAL_DATE_SEARCH_DAYS {
        let candidate = date.and_hms_opt(3, 0, 0).expect("03:00 is valid");
        match resolve(&candidate) {
            LocalResult::Single(result) if &result > now => return Some(result),
            LocalResult::Ambiguous(first, second) => {
                let (first, second) = if first <= second {
                    (first, second)
                } else {
                    (second, first)
                };
                if &first > now {
                    return Some(first);
                }
                if &second > now {
                    return Some(second);
                }
            }
            LocalResult::Single(_) | LocalResult::None => {}
        }
        date = date.succ_opt()?;
    }
    None
}

fn java_duration(duration: Duration) -> String {
    if duration.is_zero() {
        return "PT0S".into();
    }
    let mut seconds = duration.as_secs();
    let hours = seconds / 3_600;
    seconds %= 3_600;
    let minutes = seconds / 60;
    seconds %= 60;
    let nanos = duration.subsec_nanos();
    let mut value = String::from("PT");
    if hours > 0 {
        value.push_str(&format!("{hours}H"));
    }
    if minutes > 0 {
        value.push_str(&format!("{minutes}M"));
    }
    if seconds > 0 || nanos > 0 || (hours == 0 && minutes == 0) {
        if nanos == 0 {
            value.push_str(&format!("{seconds}S"));
        } else {
            let fraction = format!("{nanos:09}").trim_end_matches('0').to_owned();
            value.push_str(&format!("{seconds}.{fraction}S"));
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> CringeDecayConfig {
        CringeDecayConfig {
            interval: Duration::from_secs(86_400),
            amount: 10,
            check_interval: Duration::from_secs(3_600),
            activity_retention_days: 360,
        }
    }

    #[test]
    fn config_wire_preserves_java_duration_numbers() {
        assert_eq!(
            serde_json::to_string(&config_info(&default_config())).unwrap(),
            r#"{"interval":86400.000000000,"amount":10,"checkInterval":3600.000000000,"hourlyRate":0.4166666666666667,"retentionDays":360}"#
        );
    }

    #[test]
    fn result_wire_preserves_java_acronym_casing() {
        assert_eq!(
            serde_json::to_string(&DecayResult {
                affected_ips: 3,
                message: "Decay completed",
            })
            .unwrap(),
            r#"{"affectedIPs":3,"message":"Decay completed"}"#
        );
    }

    #[test]
    fn estimates_match_frozen_default_contract() {
        let high_estimate = estimate("203.0.113.10".into(), 47, &default_config()).unwrap();
        assert_eq!(
            serde_json::to_string(&high_estimate).unwrap(),
            r#"{"currentScore":47,"decayConfig":{"interval":"PT24H","amount":10},"estimatedCycles":2,"estimatedTimeToUnban":"PT48H","ipAddress":"203.0.113.10","scoreToDecay":17,"unbanThreshold":30}"#
        );
        let low_estimate = estimate("203.0.113.11".into(), 6, &default_config()).unwrap();
        assert_eq!(low_estimate.estimated_cycles, 0);
        assert_eq!(low_estimate.estimated_time_to_unban, "PT0S");
    }

    #[test]
    fn zero_amount_is_a_controlled_disabled_estimate() {
        let mut config = default_config();
        config.amount = 0;
        assert_eq!(
            estimate("203.0.113.10".into(), 47, &config).unwrap_err(),
            DecayEstimateError::Disabled
        );
        assert!(estimate("203.0.113.11".into(), 6, &config).is_ok());
    }

    #[test]
    fn java_duration_uses_hours_without_day_components() {
        assert_eq!(java_duration(Duration::from_secs(86_400)), "PT24H");
        assert_eq!(java_duration(Duration::from_secs(172_800)), "PT48H");
        assert_eq!(java_duration(Duration::from_millis(1_500)), "PT1.5S");
    }

    #[tokio::test(start_paused = true)]
    async fn fixed_delay_is_measured_from_completion_and_cancels_cleanly() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let operation_calls = Arc::clone(&calls);
        let cancellation = CancellationToken::new();
        let scheduler_cancellation = cancellation.clone();
        let scheduler = tokio::spawn(async move {
            run_fixed_delay_until_cancelled(
                Duration::from_secs(10),
                Duration::from_secs(10),
                &scheduler_cancellation,
                move || {
                    let operation_calls = Arc::clone(&operation_calls);
                    Box::pin(async move {
                        let call = operation_calls.fetch_add(1, Ordering::SeqCst);
                        if call == 0 {
                            sleep(Duration::from_secs(5)).await;
                        }
                    })
                },
            )
            .await;
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        cancellation.cancel();
        scheduler.await.unwrap();
    }

    #[test]
    fn nonexistent_local_cleanup_time_skips_to_the_next_matching_date() {
        let gap_date = NaiveDate::from_ymd_opt(2020, 3, 29).unwrap();
        let next_date = gap_date.succ_opt().unwrap();
        let resolved = resolve_next_cleanup(gap_date, &0_i64, |candidate| {
            if candidate.date() == gap_date {
                LocalResult::None
            } else {
                LocalResult::Single(10)
            }
        });
        assert_eq!(resolved, Some(10));
        assert_eq!(next_date, NaiveDate::from_ymd_opt(2020, 3, 30).unwrap());
    }

    #[test]
    fn ambiguous_local_cleanup_time_exposes_both_ordered_occurrences() {
        let overlap_date = NaiveDate::from_ymd_opt(2020, 10, 25).unwrap();
        assert_eq!(
            resolve_next_cleanup(overlap_date, &0_i64, |_| LocalResult::Ambiguous(10, 20)),
            Some(10)
        );
        assert_eq!(
            resolve_next_cleanup(overlap_date, &10_i64, |_| LocalResult::Ambiguous(10, 20)),
            Some(20)
        );
    }
}
