use memchr::memmem;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::sync::watch;

pub const DEFAULT_SENDER: &str = "stress-sender@lmyz.net";
pub const DEFAULT_RECEIVER: &str = "stress-receiver@lmyz.net";
const MAX_RETAINED_FAILURE_BYTES: usize = 256;
const MAX_RETAINED_SAMPLES: usize = 16;
const MAX_RETAINED_FAILURES: usize = 16;
const OBSERVER_BUFFER_INITIAL_BYTES: usize = 8 * 1024;
const MAX_OBSERVER_FEED_BYTES: usize = 64 * 1024;
const DATA_MARKER: &[u8; 5] = b"\r\n.\r\n";
const MAX_EXPECTED_MESSAGES: usize = 1_100_000;
const MESSAGE_ID_SET_ACCOUNTED_BYTES_PER_ENTRY: usize = 96;
const WIRE_ENCODING_ALLOWANCE_BYTES: usize = 256 * 1024;
const LATENCY_BUCKETS: usize = 64;
pub const PERSISTENCE_GATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObserverLimits {
    pub max_pending_replies: usize,
    pub max_line_bytes: usize,
    pub max_message_bytes: usize,
    pub header_prefix_bytes: usize,
    pub retained_samples: usize,
    pub retained_failures: usize,
}

impl Default for ObserverLimits {
    fn default() -> Self {
        Self {
            max_pending_replies: 1_024,
            max_line_bytes: 64 * 1024,
            max_message_bytes: 12 * 1024 * 1024,
            header_prefix_bytes: 64 * 1024,
            retained_samples: 8,
            retained_failures: 16,
        }
    }
}

impl ObserverLimits {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_pending_replies == 0 || self.max_pending_replies > 65_536 {
            return Err("max_pending_replies must be between 1 and 65536".into());
        }
        if self.max_line_bytes < 512 || self.max_line_bytes > 4 * 1024 * 1024 {
            return Err("max_line_bytes must be between 512 and 4 MiB".into());
        }
        if self.max_message_bytes == 0 || self.max_message_bytes > 64 * 1024 * 1024 {
            return Err("max_message_bytes must be between 1 and 64 MiB".into());
        }
        if self.header_prefix_bytes < 4 * 1024 || self.header_prefix_bytes > self.max_message_bytes
        {
            return Err("header_prefix_bytes must be between 4 KiB and max_message_bytes".into());
        }
        if self.retained_samples == 0 || self.retained_samples > MAX_RETAINED_SAMPLES {
            return Err(format!(
                "retained_samples must be between 1 and {MAX_RETAINED_SAMPLES}"
            ));
        }
        if self.retained_failures == 0 || self.retained_failures > MAX_RETAINED_FAILURES {
            return Err(format!(
                "retained_failures must be between 1 and {MAX_RETAINED_FAILURES}"
            ));
        }
        Ok(())
    }

    pub fn maximum_backend_reply_block_bytes(&self) -> Result<usize, String> {
        self.max_line_bytes
            .checked_add(MAX_OBSERVER_FEED_BYTES)
            .ok_or_else(|| "SMTP backend reply block limit overflowed".to_owned())
    }

    pub fn accounted_backend_reply_buffer_bytes(&self) -> Result<usize, String> {
        self.maximum_backend_reply_block_bytes()?
            .checked_next_power_of_two()
            .ok_or_else(|| "SMTP backend reply buffer accounting overflowed".to_owned())
    }

    pub fn accounted_connection_bytes(&self, pump_buffer_bytes: usize) -> Result<usize, String> {
        let parser_ceiling = self
            .maximum_backend_reply_block_bytes()?
            .checked_next_power_of_two()
            .ok_or_else(|| "observer parser memory accounting overflowed".to_owned())?;
        let parser_bytes = parser_ceiling
            .checked_mul(2)
            .ok_or_else(|| "observer parser memory accounting overflowed".to_owned())?;
        let pump_bytes = pump_buffer_bytes
            .checked_mul(2)
            .ok_or_else(|| "proxy pump memory accounting overflowed".to_owned())?;
        let reply_entry_bytes = std::mem::size_of::<ReplyExpectation>()
            .checked_add(std::mem::size_of::<BdatExchange>())
            .and_then(|value| value.checked_add(32))
            .ok_or_else(|| "SMTP reply entry memory accounting overflowed".to_owned())?;
        let reply_capacity = self
            .max_pending_replies
            .checked_next_power_of_two()
            .ok_or_else(|| "SMTP reply queue capacity accounting overflowed".to_owned())?;
        let reply_bytes = reply_capacity
            .checked_mul(reply_entry_bytes)
            .ok_or_else(|| "SMTP reply queue memory accounting overflowed".to_owned())?;
        let header_bytes = self
            .header_prefix_bytes
            .checked_next_power_of_two()
            .ok_or_else(|| "SMTP header prefix memory accounting overflowed".to_owned())?;
        let backend_reply_bytes = self.accounted_backend_reply_buffer_bytes()?;
        pump_bytes
            .checked_add(parser_bytes)
            .and_then(|value| value.checked_add(header_bytes))
            .and_then(|value| value.checked_add(reply_bytes))
            .and_then(|value| value.checked_add(backend_reply_bytes))
            .and_then(|value| value.checked_add(64 * 1024))
            .ok_or_else(|| "per-connection memory accounting overflowed".to_owned())
    }

    pub fn accounted_round_reserve_bytes(&self) -> Result<usize, String> {
        let seen = MAX_EXPECTED_MESSAGES
            .div_ceil(64)
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or_else(|| "observer index bitset accounting overflowed".to_owned())?;
        let message_ids = MAX_EXPECTED_MESSAGES
            .checked_mul(MESSAGE_ID_SET_ACCOUNTED_BYTES_PER_ENTRY)
            .ok_or_else(|| "observer Message-ID set accounting overflowed".to_owned())?;
        seen.checked_add(message_ids)
            .and_then(|value| value.checked_add(1024 * 1024))
            .ok_or_else(|| "observer round reserve accounting overflowed".to_owned())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RoundSpec {
    pub run_id: String,
    pub expected_messages: usize,
    pub message_bytes: usize,
    #[serde(default = "default_sender")]
    pub expected_sender: String,
    #[serde(default = "default_receiver")]
    pub expected_receiver: String,
}

fn default_sender() -> String {
    DEFAULT_SENDER.to_owned()
}

fn default_receiver() -> String {
    DEFAULT_RECEIVER.to_owned()
}

impl RoundSpec {
    pub fn validate(&self, limits: &ObserverLimits) -> Result<(), String> {
        if self.run_id.is_empty() || self.run_id.len() > 256 {
            return Err("run_id must contain between 1 and 256 bytes".into());
        }
        if self.expected_messages == 0 || self.expected_messages > MAX_EXPECTED_MESSAGES {
            return Err("expected_messages must be between 1 and 1100000".into());
        }
        if self.message_bytes == 0 || self.message_bytes > limits.max_message_bytes {
            return Err("message_bytes is outside the configured capture limit".into());
        }
        if self.expected_sender.is_empty() || self.expected_receiver.is_empty() {
            return Err("expected SMTP addresses must not be empty".into());
        }
        if self.expected_sender.len() > 512 || self.expected_receiver.len() > 512 {
            return Err("expected SMTP addresses must not exceed 512 bytes".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BeginAck {
    pub run_id: String,
    pub armed_at_monotonic_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct MessageSample {
    pub round: u64,
    pub index: usize,
    pub wire_bytes: usize,
    pub wire_sha256: String,
    pub message_id_sha256: String,
    pub accepted_at_monotonic_ns: u64,
    pub transaction_latency_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Final250Boundary {
    pub round: u64,
    pub index: usize,
    pub reply_code: u16,
    pub reply_bytes: usize,
    pub reply_sha256: String,
    pub completed_at_monotonic_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PersistenceSnapshotEvidence {
    pub clock_id: String,
    pub snapshot_started_monotonic_ns: u64,
    pub snapshot_completed_monotonic_ns: u64,
    pub postgres_query_duration_ns: u64,
    pub maildir_snapshot_duration_ns: u64,
    pub transaction_isolation: String,
    pub transaction_read_only: bool,
    pub postgres_before_rows: i64,
    pub postgres_rows: i64,
    pub postgres_expected_rows: i64,
    pub postgres_row_delta: i64,
    pub expected_messages: usize,
    pub maildir_atomic_rename_publications: usize,
    pub qualified: bool,
}

impl PersistenceSnapshotEvidence {
    fn validate(&self, expected_messages: usize) -> Result<(), String> {
        if self.clock_id != "CLOCK_MONOTONIC" {
            return Err("persistence snapshot clock must be CLOCK_MONOTONIC".into());
        }
        if self.snapshot_completed_monotonic_ns < self.snapshot_started_monotonic_ns {
            return Err("persistence snapshot timestamps were reversed".into());
        }
        if self.postgres_query_duration_ns
            > self
                .snapshot_completed_monotonic_ns
                .saturating_sub(self.snapshot_started_monotonic_ns)
        {
            return Err(
                "PostgreSQL query duration exceeded the persistence snapshot window".into(),
            );
        }
        if self.maildir_snapshot_duration_ns
            > self
                .snapshot_completed_monotonic_ns
                .saturating_sub(self.snapshot_started_monotonic_ns)
        {
            return Err(
                "Maildir snapshot duration exceeded the persistence snapshot window".into(),
            );
        }
        if self.transaction_isolation != "repeatable_read" || !self.transaction_read_only {
            return Err(
                "persistence snapshot did not use repeatable-read read-only isolation".into(),
            );
        }
        if self.expected_messages != expected_messages {
            return Err("persistence snapshot expected-message count changed".into());
        }
        let expected_rows = self
            .postgres_before_rows
            .checked_add(
                expected_messages
                    .try_into()
                    .map_err(|_| "expected-message count overflowed PostgreSQL row arithmetic")?,
            )
            .ok_or_else(|| "PostgreSQL expected-row arithmetic overflowed".to_owned())?;
        if self.postgres_expected_rows != expected_rows
            || self.postgres_row_delta
                != self.postgres_rows.saturating_sub(self.postgres_before_rows)
        {
            return Err("persistence snapshot PostgreSQL row arithmetic changed".into());
        }
        let exact = self.postgres_rows == expected_rows
            && self.postgres_row_delta == expected_messages as i64
            && self.maildir_atomic_rename_publications == expected_messages;
        if self.qualified != exact {
            return Err("persistence snapshot qualification did not match exact counts".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistenceGateEvidence {
    pub required: bool,
    pub proxy_clock_domain: String,
    pub status: String,
    pub gate_id: Option<u64>,
    pub triggered_at_proxy_monotonic_ns: Option<u64>,
    pub release_received_at_proxy_monotonic_ns: Option<u64>,
    pub forwarding_started_at_proxy_monotonic_ns: Option<u64>,
    pub forwarding_completed_at_proxy_monotonic_ns: Option<u64>,
    pub gate_hold_ns: Option<u64>,
    pub snapshot: Option<PersistenceSnapshotEvidence>,
    pub qualified: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistenceGateTrigger {
    pub gate_id: u64,
    pub triggered_at_proxy_monotonic_ns: u64,
    pub expected_messages: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SmtpFinalReplyCounts {
    pub success: u64,
    pub transient_failure: u64,
    pub permanent_failure: u64,
    pub other: u64,
}

impl SmtpFinalReplyCounts {
    fn record(&mut self, code: u16) {
        match code {
            200..=299 => self.success = self.success.saturating_add(1),
            400..=499 => self.transient_failure = self.transient_failure.saturating_add(1),
            500..=599 => self.permanent_failure = self.permanent_failure.saturating_add(1),
            _ => self.other = self.other.saturating_add(1),
        }
    }

    fn retry_responses(&self) -> u64 {
        self.transient_failure
            .saturating_add(self.permanent_failure)
            .saturating_add(self.other)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MessageLatencySummary {
    pub samples: u64,
    pub p50_ns_upper_bound: u64,
    pub p95_ns_upper_bound: u64,
    pub p99_ns_upper_bound: u64,
    pub maximum_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RoundSummary {
    pub run_id: String,
    pub expected: usize,
    pub verified: usize,
    pub missing: usize,
    pub missing_indexes: Vec<usize>,
    pub duplicates: u64,
    pub unique_message_ids: usize,
    pub observer_failure_count: u64,
    pub observer_failures: Vec<String>,
    pub qualification: bool,
    pub round: Option<u64>,
    pub armed_at_monotonic_ns: u64,
    pub duration_ns: Option<u64>,
    pub progress_duration_ns: Option<u64>,
    pub throughput_messages_per_second: Option<f64>,
    pub total_wire_bytes: u64,
    pub wire_digest_xor: String,
    pub wire_digest_sum_mod_2_256: String,
    pub record_stream_sha256: String,
    pub transaction_latency: MessageLatencySummary,
    pub first_samples: Vec<MessageSample>,
    pub last_samples: Vec<MessageSample>,
    pub final_250_boundary: Option<Final250Boundary>,
    pub persistence_gate: PersistenceGateEvidence,
    pub smtp_final_replies: SmtpFinalReplyCounts,
    pub retry_responses: u64,
}

#[derive(Clone)]
pub struct ObserverHub {
    inner: Arc<ObserverHubInner>,
}

struct ObserverHubInner {
    origin: Instant,
    limits: ObserverLimits,
    observation_enabled: bool,
    round: Mutex<Option<RoundState>>,
    epoch: AtomicU64,
    expected_notify: watch::Sender<u64>,
    forwarded_message_notify: watch::Sender<u64>,
    persistence_gate_notify: watch::Sender<u64>,
    persistence_gate_release_notify: watch::Sender<u64>,
}

impl ObserverHub {
    pub fn new(limits: ObserverLimits) -> Result<Self, String> {
        Self::with_observation(limits, true)
    }

    pub(crate) fn disabled(limits: ObserverLimits) -> Result<Self, String> {
        Self::with_observation(limits, false)
    }

    fn with_observation(limits: ObserverLimits, observation_enabled: bool) -> Result<Self, String> {
        limits.validate()?;
        let (expected_notify, _) = watch::channel(0);
        let (forwarded_message_notify, _) = watch::channel(0);
        let (persistence_gate_notify, _) = watch::channel(0);
        let (persistence_gate_release_notify, _) = watch::channel(0);
        Ok(Self {
            inner: Arc::new(ObserverHubInner {
                origin: Instant::now(),
                limits,
                observation_enabled,
                round: Mutex::new(None),
                epoch: AtomicU64::new(0),
                expected_notify,
                forwarded_message_notify,
                persistence_gate_notify,
                persistence_gate_release_notify,
            }),
        })
    }

    pub fn limits(&self) -> &ObserverLimits {
        &self.inner.limits
    }

    pub fn monotonic_ns(&self) -> u64 {
        self.inner
            .origin
            .elapsed()
            .as_nanos()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    pub fn begin(&self, spec: RoundSpec) -> Result<BeginAck, String> {
        self.begin_with_persistence_gate(spec, false)
    }

    pub fn begin_with_persistence_gate(
        &self,
        spec: RoundSpec,
        persistence_gate_required: bool,
    ) -> Result<BeginAck, String> {
        if !self.inner.observation_enabled {
            return Err("this observer is permanently disabled".into());
        }
        spec.validate(&self.inner.limits)?;
        let armed_at_monotonic_ns = self.monotonic_ns();
        let mut guard = lock_unpoisoned(&self.inner.round);
        if guard.is_some() {
            return Err(
                "this benchmark process has already consumed its only observer round".into(),
            );
        }
        let epoch = self.inner.epoch.load(Ordering::Relaxed).wrapping_add(1);
        *guard = Some(RoundState::new(
            spec.clone(),
            armed_at_monotonic_ns,
            epoch,
            persistence_gate_required,
        ));
        self.inner.epoch.store(epoch, Ordering::Release);
        Ok(BeginAck {
            run_id: spec.run_id,
            armed_at_monotonic_ns,
        })
    }

    pub fn finalize(&self) -> Result<RoundSummary, String> {
        let mut guard = lock_unpoisoned(&self.inner.round);
        let round = guard
            .as_mut()
            .ok_or_else(|| "no observer round is active".to_owned())?;
        if round.finalized {
            return Err("the observer round is already finalized".into());
        }
        round.finalized = true;
        Ok(round.summary())
    }

    pub fn summary(&self) -> Result<RoundSummary, String> {
        let guard = lock_unpoisoned(&self.inner.round);
        let round = guard
            .as_ref()
            .ok_or_else(|| "no observer round is active".to_owned())?;
        Ok(round.summary())
    }

    pub async fn wait_until_expected(&self, timeout: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut completion = self.inner.expected_notify.subscribe();
        loop {
            if lock_unpoisoned(&self.inner.round)
                .as_ref()
                .is_some_and(|round| round.verified == round.spec.expected_messages)
            {
                return true;
            }
            match tokio::time::timeout_at(deadline, completion.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return false,
            }
        }
    }

    pub async fn wait_for_persistence_gate(
        &self,
        timeout: std::time::Duration,
    ) -> Result<PersistenceGateTrigger, String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut notification = self.inner.persistence_gate_notify.subscribe();
        loop {
            {
                let guard = lock_unpoisoned(&self.inner.round);
                let round = guard
                    .as_ref()
                    .ok_or_else(|| "no observer round is active".to_owned())?;
                if !round.persistence_gate_required {
                    return Err("this observer round did not arm a persistence gate".into());
                }
                if let Some(gate) = round.persistence_gate.as_ref()
                    && let Some(triggered) = gate.triggered_at_proxy_monotonic_ns
                {
                    return Ok(PersistenceGateTrigger {
                        gate_id: gate.gate_id,
                        triggered_at_proxy_monotonic_ns: triggered,
                        expected_messages: round.spec.expected_messages,
                    });
                }
                if round.finalized {
                    return Err("observer round finalized before its persistence gate".into());
                }
            }
            match tokio::time::timeout_at(deadline, notification.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err("persistence gate notification channel closed".into()),
                Err(_) => return Err("timed out waiting for the persistence gate".into()),
            }
        }
    }

    pub fn release_persistence_gate(
        &self,
        gate_id: u64,
        snapshot: PersistenceSnapshotEvidence,
    ) -> Result<PersistenceGateEvidence, String> {
        let release_received_at_proxy_monotonic_ns = self.monotonic_ns();
        let evidence = {
            let mut guard = lock_unpoisoned(&self.inner.round);
            let round = guard
                .as_mut()
                .ok_or_else(|| "no observer round is active".to_owned())?;
            snapshot.validate(round.spec.expected_messages)?;
            if !snapshot.qualified {
                return Err("an unqualified persistence snapshot cannot release the gate".into());
            }
            let gate = round
                .persistence_gate
                .as_mut()
                .ok_or_else(|| "persistence gate was not triggered".to_owned())?;
            if gate.gate_id != gate_id {
                return Err("persistence gate identity changed".into());
            }
            if gate.release_received_at_proxy_monotonic_ns.is_some()
                || gate.aborted_reason.is_some()
            {
                return Err("persistence gate was already resolved".into());
            }
            if gate.triggered_at_proxy_monotonic_ns.is_none() {
                return Err("persistence gate was released before publication".into());
            }
            gate.release_received_at_proxy_monotonic_ns =
                Some(release_received_at_proxy_monotonic_ns);
            gate.snapshot = Some(snapshot);
            round.persistence_gate_evidence()
        };
        self.inner
            .persistence_gate_release_notify
            .send_modify(|generation| *generation = (*generation).wrapping_add(1));
        Ok(evidence)
    }

    pub fn abort_persistence_gate(&self, gate_id: u64, reason: String) -> Result<(), String> {
        let mut guard = lock_unpoisoned(&self.inner.round);
        let round = guard
            .as_mut()
            .ok_or_else(|| "no observer round is active".to_owned())?;
        let gate = round
            .persistence_gate
            .as_mut()
            .ok_or_else(|| "persistence gate was not triggered".to_owned())?;
        if gate.gate_id != gate_id {
            return Err("persistence gate identity changed".into());
        }
        if gate.release_received_at_proxy_monotonic_ns.is_some() || gate.aborted_reason.is_some() {
            return Err("persistence gate was already resolved".into());
        }
        let reason = truncate_failure(reason);
        gate.aborted_reason = Some(reason.clone());
        round.record_failure(
            format!("persistence gate aborted: {reason}"),
            self.inner.limits.retained_failures,
        );
        drop(guard);
        self.inner
            .persistence_gate_release_notify
            .send_modify(|generation| *generation = (*generation).wrapping_add(1));
        Ok(())
    }

    pub(crate) async fn wait_for_persistence_gate_release(
        &self,
        gate_id: u64,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut notification = self.inner.persistence_gate_release_notify.subscribe();
        loop {
            {
                let guard = lock_unpoisoned(&self.inner.round);
                let round = guard
                    .as_ref()
                    .ok_or_else(|| "no observer round is active".to_owned())?;
                let gate = round
                    .persistence_gate
                    .as_ref()
                    .ok_or_else(|| "persistence gate was not triggered".to_owned())?;
                if gate.gate_id != gate_id {
                    return Err("persistence gate identity changed".into());
                }
                if let Some(reason) = gate.aborted_reason.as_ref() {
                    return Err(format!("persistence gate was aborted: {reason}"));
                }
                if gate.release_received_at_proxy_monotonic_ns.is_some() {
                    return Ok(());
                }
            }
            match tokio::time::timeout_at(deadline, notification.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err("persistence gate release channel closed".into()),
                Err(_) => return Err("persistence gate release timed out".into()),
            }
        }
    }

    pub fn connection(&self) -> (ClientObserver, ServerObserver) {
        let (_, client, server) = self.scoped_connection();
        (client, server)
    }

    pub(crate) fn scoped_connection(&self) -> (u64, ClientObserver, ServerObserver) {
        let epoch = {
            let guard = lock_unpoisoned(&self.inner.round);
            let state_epoch = guard.as_ref().map_or(0, |round| round.epoch);
            let published_epoch = self.inner.epoch.load(Ordering::Acquire);
            debug_assert_eq!(published_epoch, state_epoch);
            if published_epoch == state_epoch {
                state_epoch
            } else {
                0
            }
        };
        let mut connection_state = ConnectionState::new(self.inner.limits.max_pending_replies);
        if !self.inner.observation_enabled {
            connection_state.disabled = true;
        }
        let shared = Arc::new(Mutex::new(connection_state));
        let lifetime = Arc::new(ConnectionLifetime {
            hub: self.clone(),
            shared: shared.clone(),
            epoch,
        });
        let mut client = ClientObserver::new(self.clone(), shared.clone(), lifetime.clone(), epoch);
        let mut server = ServerObserver::new(self.clone(), shared, lifetime, epoch);
        if !self.inner.observation_enabled {
            client.mode = ClientMode::Disabled;
            server.disabled = true;
        }
        (epoch, client, server)
    }

    fn record_failure(&self, message: impl Into<String>) {
        if let Some(round) = lock_unpoisoned(&self.inner.round).as_mut()
            && !round.finalized
        {
            round.record_failure(message.into(), self.inner.limits.retained_failures);
        }
    }

    pub(crate) fn mark_failure(&self, message: impl Into<String>) {
        self.record_failure(message);
    }

    pub(crate) fn mark_failure_for_epoch(&self, epoch: u64, message: impl Into<String>) {
        let mut guard = lock_unpoisoned(&self.inner.round);
        let Some(round) = guard.as_mut() else {
            return;
        };
        if round.epoch == epoch && !round.finalized {
            round.record_failure(message.into(), self.inner.limits.retained_failures);
        }
    }

    pub(crate) fn round_complete_without_failures(&self) -> bool {
        lock_unpoisoned(&self.inner.round)
            .as_ref()
            .is_some_and(|round| {
                !round.finalized
                    && round.verified == round.spec.expected_messages
                    && round.duplicates == 0
                    && round.failure_count == 0
            })
    }

    fn reserve_successful_final_for_epoch(&self, epoch: u64) -> Result<Option<u64>, String> {
        let gate_id = {
            let mut guard = lock_unpoisoned(&self.inner.round);
            let round = guard
                .as_mut()
                .ok_or_else(|| "no observer round is active".to_owned())?;
            if round.epoch != epoch || round.finalized {
                return Err("SMTP final reply belonged to an inactive observer epoch".into());
            }
            round.successful_final_reservations =
                round.successful_final_reservations.saturating_add(1);
            if round.successful_final_reservations > round.spec.expected_messages {
                return Err("successful SMTP final replies exceeded the observer target".into());
            }
            if round.persistence_gate_required
                && round.successful_final_reservations == round.spec.expected_messages
            {
                if round.persistence_gate.is_some() {
                    return Err("persistence gate was triggered more than once".into());
                }
                let gate_id = round.epoch;
                round.persistence_gate = Some(PersistenceGateState {
                    gate_id,
                    triggered_at_proxy_monotonic_ns: None,
                    release_received_at_proxy_monotonic_ns: None,
                    forwarding_started_at_proxy_monotonic_ns: None,
                    forwarding_completed_at_proxy_monotonic_ns: None,
                    snapshot: None,
                    aborted_reason: None,
                });
                Some(gate_id)
            } else {
                None
            }
        };
        Ok(gate_id)
    }

    pub(crate) async fn publish_persistence_gate_after_prior_forwards(
        &self,
        gate_id: u64,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut notification = self.inner.forwarded_message_notify.subscribe();
        loop {
            let ready = {
                let guard = lock_unpoisoned(&self.inner.round);
                let round = guard
                    .as_ref()
                    .ok_or_else(|| "no observer round is active".to_owned())?;
                let gate = round
                    .persistence_gate
                    .as_ref()
                    .ok_or_else(|| "persistence gate was not reserved".to_owned())?;
                if gate.gate_id != gate_id {
                    return Err("persistence gate identity changed".into());
                }
                if gate.aborted_reason.is_some() {
                    return Err("persistence gate was aborted before publication".into());
                }
                round.verified.saturating_add(1) == round.spec.expected_messages
            };
            if ready {
                let triggered = self.monotonic_ns();
                let mut guard = lock_unpoisoned(&self.inner.round);
                let round = guard
                    .as_mut()
                    .ok_or_else(|| "no observer round is active".to_owned())?;
                if round.verified.saturating_add(1) != round.spec.expected_messages {
                    continue;
                }
                let gate = round
                    .persistence_gate
                    .as_mut()
                    .ok_or_else(|| "persistence gate was not reserved".to_owned())?;
                if gate.gate_id != gate_id || gate.triggered_at_proxy_monotonic_ns.is_some() {
                    return Err("persistence gate publication state changed".into());
                }
                gate.triggered_at_proxy_monotonic_ns = Some(triggered);
                drop(guard);
                self.inner
                    .persistence_gate_notify
                    .send_modify(|generation| *generation = (*generation).wrapping_add(1));
                return Ok(());
            }
            match tokio::time::timeout_at(deadline, notification.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err("forwarded-message notification channel closed".into()),
                Err(_) => {
                    return Err(
                        "timed out waiting for earlier SMTP final replies before gate publication"
                            .into(),
                    );
                }
            }
        }
    }

    fn mark_persistence_gate_forwarding_started(&self, gate_id: u64) -> Result<(), String> {
        let started = self.monotonic_ns();
        let mut guard = lock_unpoisoned(&self.inner.round);
        let round = guard
            .as_mut()
            .ok_or_else(|| "no observer round is active".to_owned())?;
        let gate = round
            .persistence_gate
            .as_mut()
            .ok_or_else(|| "persistence gate was not triggered".to_owned())?;
        if gate.gate_id != gate_id {
            return Err("persistence gate identity changed".into());
        }
        if gate.aborted_reason.is_some() || gate.snapshot.is_none() {
            return Err("persistence gate lacked a qualified snapshot before forwarding".into());
        }
        let released = gate
            .release_received_at_proxy_monotonic_ns
            .ok_or_else(|| "persistence gate was not released before forwarding".to_owned())?;
        if gate.forwarding_started_at_proxy_monotonic_ns.is_some() {
            return Err("persistence gate forwarding started more than once".into());
        }
        if started < released {
            return Err("persistence gate forwarding preceded release".into());
        }
        gate.forwarding_started_at_proxy_monotonic_ns = Some(started);
        Ok(())
    }

    fn mark_persistence_gate_forwarding_completed(
        &self,
        gate_id: u64,
        completed_at_monotonic_ns: u64,
    ) -> Result<(), String> {
        let mut guard = lock_unpoisoned(&self.inner.round);
        let round = guard
            .as_mut()
            .ok_or_else(|| "no observer round is active".to_owned())?;
        let gate = round
            .persistence_gate
            .as_mut()
            .ok_or_else(|| "persistence gate was not triggered".to_owned())?;
        if gate.gate_id != gate_id {
            return Err("persistence gate identity changed".into());
        }
        let started = gate
            .forwarding_started_at_proxy_monotonic_ns
            .ok_or_else(|| "persistence gate forwarding completion lacked a start".to_owned())?;
        if completed_at_monotonic_ns < started {
            return Err("persistence gate forwarding timestamps were reversed".into());
        }
        if gate.forwarding_completed_at_proxy_monotonic_ns.is_some() {
            return Err("persistence gate forwarding completed more than once".into());
        }
        gate.forwarding_completed_at_proxy_monotonic_ns = Some(completed_at_monotonic_ns);
        Ok(())
    }

    fn record_message(&self, message: CapturedMessage, boundary: ReplyBoundary) {
        // Header parsing and hashing depend only on this completed capture.
        // Keep their allocations/CPU work outside the shared round lock; the
        // epoch, uniqueness and publication checks remain atomic below.
        let details = MessageDetails::parse(&message, &boundary);
        let mut guard = lock_unpoisoned(&self.inner.round);
        let Some(round) = guard.as_mut() else {
            return;
        };
        if message.epoch != round.epoch {
            return;
        }
        let verified_before = round.verified;
        let reached_expected = round.record_message(
            message,
            boundary,
            details,
            &self.inner.limits,
            self.inner.limits.retained_failures,
        );
        let forwarded_message = round.verified > verified_before;
        drop(guard);
        if forwarded_message {
            self.inner
                .forwarded_message_notify
                .send_modify(|generation| *generation = (*generation).wrapping_add(1));
        }
        if reached_expected {
            self.inner.expected_notify.send_modify(|generation| {
                *generation = (*generation).wrapping_add(1);
            });
        }
    }

    fn record_final_reply_for_epoch(&self, epoch: u64, code: u16) {
        let mut guard = lock_unpoisoned(&self.inner.round);
        let Some(round) = guard.as_mut() else {
            return;
        };
        if round.epoch == epoch && !round.finalized {
            round.record_final_reply(code);
        }
    }
}

struct RoundState {
    spec: RoundSpec,
    armed_at_monotonic_ns: u64,
    seen: Vec<u64>,
    message_ids: HashSet<[u8; 32]>,
    verified: usize,
    latest_accepted_at_monotonic_ns: Option<u64>,
    duplicates: u64,
    failure_count: u64,
    failures: Vec<String>,
    round_number: Option<u64>,
    total_wire_bytes: u64,
    digest_xor: [u8; 32],
    digest_sum: [u8; 32],
    record_stream: Sha256,
    transaction_latency_buckets: [u64; LATENCY_BUCKETS],
    maximum_transaction_latency_ns: u64,
    first_samples: Vec<MessageSample>,
    last_samples: VecDeque<MessageSample>,
    final_boundary: Option<Final250Boundary>,
    smtp_final_replies: SmtpFinalReplyCounts,
    successful_final_reservations: usize,
    persistence_gate_required: bool,
    persistence_gate: Option<PersistenceGateState>,
    finalized: bool,
    epoch: u64,
}

struct PersistenceGateState {
    gate_id: u64,
    triggered_at_proxy_monotonic_ns: Option<u64>,
    release_received_at_proxy_monotonic_ns: Option<u64>,
    forwarding_started_at_proxy_monotonic_ns: Option<u64>,
    forwarding_completed_at_proxy_monotonic_ns: Option<u64>,
    snapshot: Option<PersistenceSnapshotEvidence>,
    aborted_reason: Option<String>,
}

impl RoundState {
    fn new(
        spec: RoundSpec,
        armed_at_monotonic_ns: u64,
        epoch: u64,
        persistence_gate_required: bool,
    ) -> Self {
        let words = spec.expected_messages.div_ceil(64);
        let expected_messages = spec.expected_messages;
        Self {
            spec,
            armed_at_monotonic_ns,
            seen: vec![0; words],
            message_ids: HashSet::with_capacity(expected_messages),
            verified: 0,
            latest_accepted_at_monotonic_ns: None,
            duplicates: 0,
            failure_count: 0,
            failures: Vec::new(),
            round_number: None,
            total_wire_bytes: 0,
            digest_xor: [0; 32],
            digest_sum: [0; 32],
            record_stream: Sha256::new(),
            transaction_latency_buckets: [0; LATENCY_BUCKETS],
            maximum_transaction_latency_ns: 0,
            first_samples: Vec::new(),
            last_samples: VecDeque::new(),
            final_boundary: None,
            smtp_final_replies: SmtpFinalReplyCounts::default(),
            successful_final_reservations: 0,
            persistence_gate_required,
            persistence_gate: None,
            finalized: false,
            epoch,
        }
    }

    fn persistence_gate_evidence(&self) -> PersistenceGateEvidence {
        let Some(gate) = self.persistence_gate.as_ref() else {
            return PersistenceGateEvidence {
                required: self.persistence_gate_required,
                proxy_clock_domain: "observer_origin_elapsed".to_owned(),
                status: if self.persistence_gate_required {
                    "armed".to_owned()
                } else {
                    "disabled".to_owned()
                },
                gate_id: None,
                triggered_at_proxy_monotonic_ns: None,
                release_received_at_proxy_monotonic_ns: None,
                forwarding_started_at_proxy_monotonic_ns: None,
                forwarding_completed_at_proxy_monotonic_ns: None,
                gate_hold_ns: None,
                snapshot: None,
                qualified: !self.persistence_gate_required,
            };
        };
        let qualified = gate.aborted_reason.is_none()
            && gate.triggered_at_proxy_monotonic_ns.is_some()
            && gate
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.qualified)
            && gate.release_received_at_proxy_monotonic_ns.is_some()
            && gate.forwarding_started_at_proxy_monotonic_ns.is_some()
            && gate.forwarding_completed_at_proxy_monotonic_ns.is_some()
            && gate.triggered_at_proxy_monotonic_ns <= gate.release_received_at_proxy_monotonic_ns
            && gate.release_received_at_proxy_monotonic_ns
                <= gate.forwarding_started_at_proxy_monotonic_ns
            && gate.forwarding_started_at_proxy_monotonic_ns
                <= gate.forwarding_completed_at_proxy_monotonic_ns;
        let status = if gate.aborted_reason.is_some() {
            "aborted"
        } else if gate.forwarding_completed_at_proxy_monotonic_ns.is_some() {
            "forwarded"
        } else if gate.forwarding_started_at_proxy_monotonic_ns.is_some() {
            "forwarding"
        } else if gate.release_received_at_proxy_monotonic_ns.is_some() {
            "released"
        } else {
            "waiting_for_snapshot"
        };
        PersistenceGateEvidence {
            required: self.persistence_gate_required,
            proxy_clock_domain: "observer_origin_elapsed".to_owned(),
            status: status.to_owned(),
            gate_id: Some(gate.gate_id),
            triggered_at_proxy_monotonic_ns: gate.triggered_at_proxy_monotonic_ns,
            release_received_at_proxy_monotonic_ns: gate.release_received_at_proxy_monotonic_ns,
            forwarding_started_at_proxy_monotonic_ns: gate.forwarding_started_at_proxy_monotonic_ns,
            forwarding_completed_at_proxy_monotonic_ns: gate
                .forwarding_completed_at_proxy_monotonic_ns,
            gate_hold_ns: gate
                .release_received_at_proxy_monotonic_ns
                .zip(gate.triggered_at_proxy_monotonic_ns)
                .map(|(released, triggered)| released.saturating_sub(triggered)),
            snapshot: gate.snapshot.clone(),
            qualified,
        }
    }

    fn record_failure(&mut self, message: String, retained_failures: usize) {
        self.failure_count = self.failure_count.saturating_add(1);
        if self.failures.len() < retained_failures {
            self.failures.push(truncate_failure(message));
        }
    }

    fn record_final_reply(&mut self, code: u16) {
        self.smtp_final_replies.record(code);
    }

    fn record_message(
        &mut self,
        message: CapturedMessage,
        boundary: ReplyBoundary,
        details: Result<MessageDetails, String>,
        limits: &ObserverLimits,
        retained_failures: usize,
    ) -> bool {
        if self.finalized {
            return false;
        }
        let MessageDetails {
            headers,
            message_id_sha256,
            sample,
        } = match details {
            Ok(details) => details,
            Err(error) => {
                self.record_failure(error, retained_failures);
                return false;
            }
        };
        if !headers
            .from
            .trim()
            .eq_ignore_ascii_case(&self.spec.expected_sender)
        {
            self.record_failure(
                format!("SMTP From header changed: {:?}", headers.from),
                retained_failures,
            );
            return false;
        }
        if !headers
            .to
            .trim()
            .eq_ignore_ascii_case(&self.spec.expected_receiver)
        {
            self.record_failure(
                format!("SMTP To header changed: {:?}", headers.to),
                retained_failures,
            );
            return false;
        }
        if headers.message_id.is_empty() {
            self.record_failure("SMTP Message-ID header is empty".into(), retained_failures);
            return false;
        }
        if headers.index >= self.spec.expected_messages {
            self.record_failure(
                format!("SMTP stress index {} is outside the round", headers.index),
                retained_failures,
            );
            return false;
        }
        if self
            .round_number
            .is_some_and(|round| round != headers.round)
        {
            self.record_failure(
                format!(
                    "SMTP capture observed round {} after round {:?}",
                    headers.round, self.round_number
                ),
                retained_failures,
            );
            return false;
        }
        self.round_number.get_or_insert(headers.round);
        let minimum = self.spec.message_bytes;
        let maximum = maximum_wire_bytes(self.spec.message_bytes, limits);
        if message.wire_bytes < minimum || message.wire_bytes > maximum {
            self.record_failure(
                format!(
                    "SMTP wire size {} is outside [{minimum}, {maximum}]",
                    message.wire_bytes
                ),
                retained_failures,
            );
            return false;
        }
        let word = headers.index / 64;
        let mask = 1_u64 << (headers.index % 64);
        if self.seen[word] & mask != 0 {
            self.duplicates = self.duplicates.saturating_add(1);
            self.record_failure(
                format!("SMTP stress index {} was accepted twice", headers.index),
                retained_failures,
            );
            return false;
        }
        if !self.message_ids.insert(message_id_sha256) {
            self.record_failure(
                format!(
                    "SMTP Message-ID was accepted for more than one index: {:?}",
                    headers.message_id
                ),
                retained_failures,
            );
            return false;
        }
        self.seen[word] |= mask;
        self.verified += 1;
        self.latest_accepted_at_monotonic_ns = Some(
            self.latest_accepted_at_monotonic_ns
                .map_or(boundary.completed_at_monotonic_ns, |latest| {
                    latest.max(boundary.completed_at_monotonic_ns)
                }),
        );
        self.total_wire_bytes = self
            .total_wire_bytes
            .saturating_add(message.wire_bytes as u64);
        xor_digest(&mut self.digest_xor, &message.wire_sha256);
        add_digest(&mut self.digest_sum, &message.wire_sha256);
        self.record_stream.update(headers.round.to_be_bytes());
        self.record_stream
            .update((headers.index as u64).to_be_bytes());
        self.record_stream
            .update((message.wire_bytes as u64).to_be_bytes());
        self.record_stream.update(message.wire_sha256);
        self.record_stream.update(message_id_sha256);
        self.record_stream.update(boundary.code.to_be_bytes());
        self.record_stream.update(boundary.reply_sha256);
        record_latency(
            &mut self.transaction_latency_buckets,
            &mut self.maximum_transaction_latency_ns,
            sample.transaction_latency_ns,
        );
        if self.first_samples.len() < limits.retained_samples {
            self.first_samples.push(sample.clone());
        }
        if self.last_samples.len() == limits.retained_samples {
            self.last_samples.pop_front();
        }
        self.last_samples.push_back(sample);
        let reached = self.verified == self.spec.expected_messages;
        if reached {
            self.final_boundary = Some(Final250Boundary {
                round: headers.round,
                index: headers.index,
                reply_code: boundary.code,
                reply_bytes: boundary.reply_bytes,
                reply_sha256: encode_hex(boundary.reply_sha256),
                completed_at_monotonic_ns: boundary.completed_at_monotonic_ns,
            });
        }
        reached
    }

    fn summary(&self) -> RoundSummary {
        let mut missing_indexes = Vec::new();
        let missing = self.spec.expected_messages.saturating_sub(self.verified);
        if missing > 0 {
            for index in 0..self.spec.expected_messages {
                if self.seen[index / 64] & (1_u64 << (index % 64)) == 0 {
                    missing_indexes.push(index);
                    if missing_indexes.len() == 20 {
                        break;
                    }
                }
            }
        }
        let duration_ns = self
            .final_boundary
            .as_ref()
            .and(self.latest_accepted_at_monotonic_ns)
            .map(|completed_at| completed_at.saturating_sub(self.armed_at_monotonic_ns));
        let progress_duration_ns = self
            .latest_accepted_at_monotonic_ns
            .map(|completed_at| completed_at.saturating_sub(self.armed_at_monotonic_ns));
        let throughput_messages_per_second = duration_ns.and_then(|duration| {
            (duration > 0).then_some(self.verified as f64 * 1_000_000_000.0 / duration as f64)
        });
        let persistence_gate = self.persistence_gate_evidence();
        let persistence_gate_matches_final_boundary = !self.persistence_gate_required
            || (persistence_gate.qualified
                && persistence_gate.forwarding_completed_at_proxy_monotonic_ns
                    == self
                        .final_boundary
                        .as_ref()
                        .map(|boundary| boundary.completed_at_monotonic_ns));
        RoundSummary {
            run_id: self.spec.run_id.clone(),
            expected: self.spec.expected_messages,
            verified: self.verified,
            missing,
            missing_indexes,
            duplicates: self.duplicates,
            unique_message_ids: self.message_ids.len(),
            observer_failure_count: self.failure_count,
            observer_failures: self.failures.clone(),
            qualification: self.verified == self.spec.expected_messages
                && missing == 0
                && self.duplicates == 0
                && self.failure_count == 0
                && self.final_boundary.is_some()
                && persistence_gate_matches_final_boundary,
            round: self.round_number,
            armed_at_monotonic_ns: self.armed_at_monotonic_ns,
            duration_ns,
            progress_duration_ns,
            throughput_messages_per_second,
            total_wire_bytes: self.total_wire_bytes,
            wire_digest_xor: encode_hex(self.digest_xor),
            wire_digest_sum_mod_2_256: encode_hex(self.digest_sum),
            record_stream_sha256: encode_hex(self.record_stream.clone().finalize()),
            transaction_latency: latency_summary(
                &self.transaction_latency_buckets,
                self.maximum_transaction_latency_ns,
            ),
            first_samples: self.first_samples.clone(),
            last_samples: self.last_samples.iter().cloned().collect(),
            final_250_boundary: self.final_boundary.clone(),
            persistence_gate,
            smtp_final_replies: self.smtp_final_replies.clone(),
            retry_responses: self.smtp_final_replies.retry_responses(),
        }
    }
}

fn record_latency(buckets: &mut [u64; LATENCY_BUCKETS], maximum: &mut u64, nanos: u64) {
    let bucket = if nanos <= 1 {
        0
    } else {
        (u64::BITS - (nanos - 1).leading_zeros()) as usize
    }
    .min(LATENCY_BUCKETS - 1);
    buckets[bucket] = buckets[bucket].saturating_add(1);
    *maximum = (*maximum).max(nanos);
}

fn latency_summary(buckets: &[u64; LATENCY_BUCKETS], maximum_ns: u64) -> MessageLatencySummary {
    let samples = buckets.iter().copied().sum();
    MessageLatencySummary {
        samples,
        p50_ns_upper_bound: latency_percentile(buckets, samples, 50),
        p95_ns_upper_bound: latency_percentile(buckets, samples, 95),
        p99_ns_upper_bound: latency_percentile(buckets, samples, 99),
        maximum_ns,
    }
}

fn latency_percentile(buckets: &[u64; LATENCY_BUCKETS], samples: u64, percentile: u64) -> u64 {
    if samples == 0 {
        return 0;
    }
    let rank = samples.saturating_mul(percentile).div_ceil(100).max(1);
    let mut cumulative = 0_u64;
    for (index, count) in buckets.iter().enumerate() {
        cumulative = cumulative.saturating_add(*count);
        if cumulative >= rank {
            return if index == 0 {
                1
            } else if index == LATENCY_BUCKETS - 1 {
                u64::MAX
            } else {
                1_u64 << index
            };
        }
    }
    u64::MAX
}

fn maximum_wire_bytes(nominal: usize, limits: &ObserverLimits) -> usize {
    // Keep a conservative quoted-printable expansion budget independent of
    // the currently observed line wrapping, plus the full header allowance.
    nominal
        .saturating_add(nominal.div_ceil(16))
        .saturating_add(WIRE_ENCODING_ALLOWANCE_BYTES)
        .min(limits.max_message_bytes)
}

fn truncate_failure(mut message: String) -> String {
    const SUFFIX: &str = "...[truncated]";
    if message.len() <= MAX_RETAINED_FAILURE_BYTES {
        return message;
    }
    let mut end = MAX_RETAINED_FAILURE_BYTES - SUFFIX.len();
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message.push_str(SUFFIX);
    message
}

fn xor_digest(target: &mut [u8; 32], value: &[u8; 32]) {
    for (target, value) in target.iter_mut().zip(value) {
        *target ^= value;
    }
}

fn add_digest(target: &mut [u8; 32], value: &[u8; 32]) {
    let mut carry = 0_u16;
    for index in (0..32).rev() {
        let sum = target[index] as u16 + value[index] as u16 + carry;
        target[index] = sum as u8;
        carry = sum >> 8;
    }
}

fn encode_hex(value: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let value = value.as_ref();
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

struct MessageCapture {
    digest: Sha256,
    wire_bytes: usize,
    header_prefix: Vec<u8>,
    transaction_started_monotonic_ns: u64,
    epoch: u64,
}

impl MessageCapture {
    fn new(transaction_started_monotonic_ns: u64, epoch: u64) -> Self {
        Self {
            digest: Sha256::new(),
            wire_bytes: 0,
            header_prefix: Vec::new(),
            transaction_started_monotonic_ns,
            epoch,
        }
    }

    fn update(&mut self, value: &[u8], limits: &ObserverLimits) -> Result<(), String> {
        let next = self
            .wire_bytes
            .checked_add(value.len())
            .ok_or_else(|| "SMTP message byte count overflowed".to_owned())?;
        if next > limits.max_message_bytes {
            return Err(format!(
                "SMTP message exceeded {} byte capture ceiling",
                limits.max_message_bytes
            ));
        }
        self.digest.update(value);
        self.wire_bytes = next;
        if self.header_prefix.len() < limits.header_prefix_bytes {
            let remaining = limits.header_prefix_bytes - self.header_prefix.len();
            self.header_prefix
                .extend_from_slice(&value[..value.len().min(remaining)]);
        }
        Ok(())
    }

    fn finish(self) -> CapturedMessage {
        CapturedMessage {
            wire_sha256: self.digest.finalize().into(),
            wire_bytes: self.wire_bytes,
            header_prefix: self.header_prefix,
            transaction_started_monotonic_ns: self.transaction_started_monotonic_ns,
            epoch: self.epoch,
        }
    }
}

struct CapturedMessage {
    wire_sha256: [u8; 32],
    wire_bytes: usize,
    header_prefix: Vec<u8>,
    transaction_started_monotonic_ns: u64,
    epoch: u64,
}

struct ReplyBoundary {
    code: u16,
    reply_bytes: usize,
    reply_sha256: [u8; 32],
    completed_at_monotonic_ns: u64,
}

struct PendingDataFinal {
    code: u16,
    rejected: bool,
    capture: Box<MessageCapture>,
    boundary: ReplyBoundary,
    persistence_gate_id: Option<u64>,
}

enum ReplyExpectation {
    Simple,
    StartTls,
    Mail,
    Rset,
    DataPrompt,
    DataFinal(Box<MessageCapture>),
    Bdat(Arc<Mutex<BdatExchange>>),
}

struct BdatExchange {
    last: bool,
    payload_complete: bool,
    capture: Option<Box<MessageCapture>>,
    reply: Option<ReplyBoundary>,
    reply_forwarded: bool,
    processed: bool,
    persistence_gate_id: Option<u64>,
}

struct ConnectionState {
    pending: VecDeque<ReplyExpectation>,
    max_pending: usize,
    data_prompt_result: Option<bool>,
    transaction_poisoned: bool,
    transaction_final_seen: bool,
    transaction_started_monotonic_ns: Option<u64>,
    client_terminal_mode: Option<ClientTerminalMode>,
    client_terminal_residual: Option<&'static str>,
    server_terminal_residual: Option<&'static str>,
    disabled: bool,
}

impl ConnectionState {
    fn new(max_pending: usize) -> Self {
        Self {
            pending: VecDeque::new(),
            max_pending,
            data_prompt_result: None,
            transaction_poisoned: false,
            transaction_final_seen: false,
            transaction_started_monotonic_ns: None,
            client_terminal_mode: None,
            client_terminal_residual: None,
            server_terminal_residual: None,
            disabled: false,
        }
    }

    fn push(&mut self, expectation: ReplyExpectation) -> Result<(), String> {
        if self.disabled {
            return Ok(());
        }
        if self.pending.len() >= self.max_pending {
            self.disabled = true;
            self.pending.clear();
            return Err(format!(
                "SMTP pending reply ring exceeded {} entries",
                self.max_pending
            ));
        }
        self.pending.push_back(expectation);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientTerminalMode {
    Command,
    AwaitDataPrompt,
    Data,
    Bdat,
    AwaitTransactionFinal,
    Disabled,
}

struct ConnectionLifetime {
    hub: ObserverHub,
    shared: Arc<Mutex<ConnectionState>>,
    epoch: u64,
}

impl Drop for ConnectionLifetime {
    fn drop(&mut self) {
        let residuals = {
            let state = lock_unpoisoned(&self.shared);
            if state.disabled {
                return;
            }
            let legal_final_reply_after_client_half_close = state.client_terminal_mode
                == Some(ClientTerminalMode::AwaitTransactionFinal)
                && state.pending.is_empty()
                && state.transaction_final_seen;
            let legal_rejected_data_prompt_after_client_half_close = state.client_terminal_mode
                == Some(ClientTerminalMode::AwaitDataPrompt)
                && state.pending.is_empty()
                && state.data_prompt_result == Some(false);
            let mut residuals = Vec::new();
            if !state.pending.is_empty() {
                residuals.push(format!(
                    "{} pending SMTP command replies (including NOOP/QUIT)",
                    state.pending.len()
                ));
            }
            if let Some(residual) = state.client_terminal_residual {
                residuals.push(residual.to_owned());
            }
            if let Some(residual) = state.server_terminal_residual {
                residuals.push(residual.to_owned());
            }
            match state.client_terminal_mode {
                Some(ClientTerminalMode::AwaitDataPrompt)
                    if !legal_rejected_data_prompt_after_client_half_close =>
                {
                    residuals.push("client ended while awaiting the DATA prompt".to_owned());
                }
                Some(ClientTerminalMode::Data) => {
                    residuals.push("client ended inside a DATA body".to_owned());
                }
                Some(ClientTerminalMode::Bdat) => {
                    residuals.push("client ended inside a BDAT body".to_owned());
                }
                Some(ClientTerminalMode::AwaitTransactionFinal)
                    if !legal_final_reply_after_client_half_close =>
                {
                    residuals.push("client ended before the final transaction reply".to_owned());
                }
                None => residuals.push("client observer ended without terminal state".to_owned()),
                Some(ClientTerminalMode::Command)
                | Some(ClientTerminalMode::AwaitDataPrompt)
                | Some(ClientTerminalMode::AwaitTransactionFinal)
                | Some(ClientTerminalMode::Disabled) => {}
            }
            if state.data_prompt_result.is_some()
                && !legal_rejected_data_prompt_after_client_half_close
            {
                residuals.push("unconsumed DATA prompt result".to_owned());
            }
            if state.transaction_poisoned {
                residuals.push("rejected BDAT transaction was not reset".to_owned());
            }
            if state.transaction_final_seen && !legal_final_reply_after_client_half_close {
                residuals.push("unconsumed final transaction reply".to_owned());
            }
            if state.transaction_started_monotonic_ns.is_some()
                && !legal_final_reply_after_client_half_close
            {
                residuals.push("unfinished SMTP transaction".to_owned());
            }
            residuals
        };
        if !residuals.is_empty() {
            self.hub.mark_failure_for_epoch(
                self.epoch,
                format!(
                    "SMTP connection ended with residual observer state: {}",
                    residuals.join(", ")
                ),
            );
        }
    }
}

#[derive(Clone, Copy)]
enum ClientMode {
    Command,
    AwaitDataPrompt,
    Data,
    Bdat { remaining: usize, last: bool },
    AwaitTransactionFinal,
    Disabled,
}

pub struct ClientObserver {
    hub: ObserverHub,
    shared: Arc<Mutex<ConnectionState>>,
    _lifetime: Arc<ConnectionLifetime>,
    buffer: Vec<u8>,
    mode: ClientMode,
    current_capture: Option<MessageCapture>,
    current_bdat: Option<Arc<Mutex<BdatExchange>>>,
    epoch: u64,
}

impl ClientObserver {
    fn new(
        hub: ObserverHub,
        shared: Arc<Mutex<ConnectionState>>,
        lifetime: Arc<ConnectionLifetime>,
        epoch: u64,
    ) -> Self {
        Self {
            hub,
            shared,
            _lifetime: lifetime,
            buffer: Vec::with_capacity(OBSERVER_BUFFER_INITIAL_BYTES),
            mode: ClientMode::Command,
            current_capture: None,
            current_bdat: None,
            epoch,
        }
    }

    pub fn observe(&mut self, value: &[u8]) {
        if matches!(self.mode, ClientMode::Disabled) {
            return;
        }
        if lock_unpoisoned(&self.shared).disabled {
            self.mode = ClientMode::Disabled;
            self.buffer.clear();
            self.current_capture = None;
            self.current_bdat = None;
            return;
        }
        let maximum_buffered = self
            .hub
            .limits()
            .max_line_bytes
            .saturating_add(MAX_OBSERVER_FEED_BYTES);
        if value.len() > MAX_OBSERVER_FEED_BYTES
            || !matches!(self.mode, ClientMode::Data)
                && self.buffer.len().saturating_add(value.len()) > maximum_buffered
        {
            self.disable("SMTP client observer buffer exceeded its accounted ceiling".into());
            return;
        }

        // Backend replies can advance these modes without consuming client
        // bytes. Doing that before buffering keeps the normal DATA body path
        // on the streaming fast path after the required 354 response.
        if self.buffer.is_empty() {
            let result = match self.mode {
                ClientMode::AwaitDataPrompt => self.consume_data_prompt(),
                ClientMode::AwaitTransactionFinal => self.consume_transaction_final(),
                ClientMode::Bdat { remaining: 0, last } => self.consume_bdat(0, last),
                _ => Ok(false),
            };
            if let Err(error) = result {
                self.disable(error);
                return;
            }
        }

        let mut value = value;
        if matches!(self.mode, ClientMode::Data) {
            match self.consume_data_stream(value) {
                Ok(Some(consumed)) => value = &value[consumed..],
                Ok(None) => return,
                Err(error) => {
                    self.disable(error);
                    return;
                }
            }
        }
        if self.buffer.len().saturating_add(value.len()) > maximum_buffered {
            self.disable("SMTP client observer buffer exceeded its accounted ceiling".into());
            return;
        }
        self.buffer.extend_from_slice(value);
        loop {
            if lock_unpoisoned(&self.shared).disabled {
                self.mode = ClientMode::Disabled;
                self.buffer.clear();
                self.current_capture = None;
                self.current_bdat = None;
                return;
            }
            let result = match self.mode {
                ClientMode::Command => self.consume_command(),
                ClientMode::AwaitDataPrompt => self.consume_data_prompt(),
                ClientMode::Data => self.consume_data(),
                ClientMode::Bdat { remaining, last } => self.consume_bdat(remaining, last),
                ClientMode::AwaitTransactionFinal => self.consume_transaction_final(),
                ClientMode::Disabled => return,
            };
            match result {
                Ok(true) => continue,
                Ok(false) => break,
                Err(error) => {
                    self.disable(error);
                    break;
                }
            }
        }
    }

    pub fn observe_eof(&mut self) {
        // A server reply may arrive after the client write half closes. Only
        // local partial frames are invalid here; the shared lifetime audits
        // pending replies and transactions after both directions finish.
        self.observe(&[]);
        if matches!(self.mode, ClientMode::Data | ClientMode::Bdat { .. })
            || matches!(self.mode, ClientMode::Command) && self.current_capture.is_some()
        {
            self.disable("SMTP client half-closed with an incomplete message body".into());
            return;
        }
        if !self.buffer.is_empty() {
            self.disable("SMTP client half-closed with an incomplete observed frame".into());
        }
    }

    fn consume_command(&mut self) -> Result<bool, String> {
        let Some(end) = find_bytes(&self.buffer, b"\r\n") else {
            if self.buffer.len() > self.hub.limits().max_line_bytes {
                return Err("SMTP command line exceeded the fixed observer limit".into());
            }
            return Ok(false);
        };
        if end + 2 > self.hub.limits().max_line_bytes {
            return Err("SMTP command line exceeded the fixed observer limit".into());
        }
        let line: Vec<u8> = self.buffer.drain(..end + 2).collect();
        let command = line
            .split(|byte| byte.is_ascii_whitespace())
            .next()
            .unwrap_or_default();
        if command.eq_ignore_ascii_case(b"MAIL") {
            self.current_capture = None;
            self.current_bdat = None;
            let now = self.hub.monotonic_ns();
            let mut shared = lock_unpoisoned(&self.shared);
            shared.transaction_started_monotonic_ns = Some(now);
            shared.transaction_final_seen = false;
            shared.push(ReplyExpectation::Mail)?;
        } else if command.eq_ignore_ascii_case(b"RSET") {
            self.current_capture = None;
            self.current_bdat = None;
            let mut shared = lock_unpoisoned(&self.shared);
            shared.transaction_started_monotonic_ns = None;
            shared.transaction_final_seen = false;
            shared.data_prompt_result = None;
            shared.push(ReplyExpectation::Rset)?;
        } else if command.eq_ignore_ascii_case(b"DATA") {
            let mut shared = lock_unpoisoned(&self.shared);
            shared.data_prompt_result = None;
            shared.push(ReplyExpectation::DataPrompt)?;
            self.mode = ClientMode::AwaitDataPrompt;
        } else if command.eq_ignore_ascii_case(b"STARTTLS") {
            lock_unpoisoned(&self.shared).push(ReplyExpectation::StartTls)?;
        } else if command.eq_ignore_ascii_case(b"BDAT") {
            let (size, last) = parse_bdat(&line)?;
            if self.current_capture.is_none() {
                let started = lock_unpoisoned(&self.shared)
                    .transaction_started_monotonic_ns
                    .unwrap_or_else(|| self.hub.monotonic_ns());
                self.current_capture = Some(MessageCapture::new(started, self.epoch));
            }
            let exchange = Arc::new(Mutex::new(BdatExchange {
                last,
                payload_complete: false,
                capture: None,
                reply: None,
                reply_forwarded: false,
                processed: false,
                persistence_gate_id: None,
            }));
            lock_unpoisoned(&self.shared).push(ReplyExpectation::Bdat(exchange.clone()))?;
            self.current_bdat = Some(exchange);
            self.mode = ClientMode::Bdat {
                remaining: size,
                last,
            };
        } else {
            lock_unpoisoned(&self.shared).push(ReplyExpectation::Simple)?;
        }
        Ok(true)
    }

    fn consume_data_prompt(&mut self) -> Result<bool, String> {
        let result = lock_unpoisoned(&self.shared).data_prompt_result.take();
        match result {
            Some(true) => {
                let started = lock_unpoisoned(&self.shared)
                    .transaction_started_monotonic_ns
                    .unwrap_or_else(|| self.hub.monotonic_ns());
                self.current_capture = Some(MessageCapture::new(started, self.epoch));
                self.mode = ClientMode::Data;
                Ok(true)
            }
            Some(false) => {
                self.mode = ClientMode::Command;
                Ok(true)
            }
            None if self.buffer.is_empty() => Ok(false),
            None => Err("SMTP client sent DATA bytes before the backend 354 reply".into()),
        }
    }

    fn consume_data(&mut self) -> Result<bool, String> {
        if let Some(position) = find_bytes(&self.buffer, DATA_MARKER) {
            let payload_end = position + 2;
            self.current_capture
                .as_mut()
                .ok_or_else(|| "SMTP DATA capture state was missing".to_owned())?
                .update(&self.buffer[..payload_end], self.hub.limits())?;
            self.buffer.drain(..position + DATA_MARKER.len());
            self.finish_data_capture()?;
            return Ok(true);
        }
        let safe = self.buffer.len().saturating_sub(DATA_MARKER.len() - 1);
        if safe == 0 {
            return Ok(false);
        }
        self.current_capture
            .as_mut()
            .ok_or_else(|| "SMTP DATA capture state was missing".to_owned())?
            .update(&self.buffer[..safe], self.hub.limits())?;
        self.buffer.drain(..safe);
        Ok(false)
    }

    fn consume_data_stream(&mut self, value: &[u8]) -> Result<Option<usize>, String> {
        debug_assert!(matches!(self.mode, ClientMode::Data));
        debug_assert!(self.buffer.len() < DATA_MARKER.len());

        let tail_len = self.buffer.len();
        let prefix_len = value.len().min(DATA_MARKER.len());
        let mut boundary = [0_u8; DATA_MARKER.len() * 2 - 1];
        boundary[..tail_len].copy_from_slice(&self.buffer);
        boundary[tail_len..tail_len + prefix_len].copy_from_slice(&value[..prefix_len]);
        let boundary_len = tail_len + prefix_len;

        if boundary_len < DATA_MARKER.len() {
            self.buffer.extend_from_slice(value);
            return Ok(None);
        }

        if let Some(position) = memmem::find(&boundary[..boundary_len], DATA_MARKER) {
            self.current_capture
                .as_mut()
                .ok_or_else(|| "SMTP DATA capture state was missing".to_owned())?
                .update(&boundary[..position + 2], self.hub.limits())?;
            self.buffer.clear();
            self.finish_data_capture()?;
            return Ok(Some(position + DATA_MARKER.len() - tail_len));
        }

        if value.len() < DATA_MARKER.len() - 1 {
            let retained = boundary_len.min(DATA_MARKER.len() - 1);
            let safe = boundary_len - retained;
            if safe != 0 {
                self.current_capture
                    .as_mut()
                    .ok_or_else(|| "SMTP DATA capture state was missing".to_owned())?
                    .update(&boundary[..safe], self.hub.limits())?;
            }
            self.buffer.clear();
            self.buffer.extend_from_slice(&boundary[safe..boundary_len]);
            return Ok(None);
        }

        if tail_len != 0 {
            self.current_capture
                .as_mut()
                .ok_or_else(|| "SMTP DATA capture state was missing".to_owned())?
                .update(&self.buffer, self.hub.limits())?;
            self.buffer.clear();
        }

        if let Some(position) = memmem::find(value, DATA_MARKER) {
            self.current_capture
                .as_mut()
                .ok_or_else(|| "SMTP DATA capture state was missing".to_owned())?
                .update(&value[..position + 2], self.hub.limits())?;
            self.finish_data_capture()?;
            return Ok(Some(position + DATA_MARKER.len()));
        }

        let retained = value.len().min(DATA_MARKER.len() - 1);
        let safe = value.len() - retained;
        if safe != 0 {
            self.current_capture
                .as_mut()
                .ok_or_else(|| "SMTP DATA capture state was missing".to_owned())?
                .update(&value[..safe], self.hub.limits())?;
        }
        self.buffer.extend_from_slice(&value[safe..]);
        Ok(None)
    }

    fn finish_data_capture(&mut self) -> Result<(), String> {
        let capture = self
            .current_capture
            .take()
            .ok_or_else(|| "SMTP DATA capture state was missing".to_owned())?;
        lock_unpoisoned(&self.shared).push(ReplyExpectation::DataFinal(Box::new(capture)))?;
        self.mode = ClientMode::AwaitTransactionFinal;
        Ok(())
    }

    fn consume_bdat(&mut self, remaining: usize, last: bool) -> Result<bool, String> {
        if remaining > 0 && self.buffer.is_empty() {
            return Ok(false);
        }
        let consumed = remaining.min(self.buffer.len());
        if consumed > 0 {
            self.current_capture
                .as_mut()
                .ok_or_else(|| "SMTP BDAT capture state was missing".to_owned())?
                .update(&self.buffer[..consumed], self.hub.limits())?;
            self.buffer.drain(..consumed);
        }
        let remaining = remaining - consumed;
        if remaining > 0 {
            self.mode = ClientMode::Bdat { remaining, last };
            return Ok(false);
        }
        let capture = if last {
            self.current_capture.take().map(Box::new)
        } else {
            None
        };
        let exchange = self
            .current_bdat
            .take()
            .ok_or_else(|| "SMTP BDAT reply exchange state was missing".to_owned())?;
        {
            let mut exchange_guard = lock_unpoisoned(&exchange);
            if exchange_guard.last != last {
                return Err("SMTP BDAT exchange LAST state changed unexpectedly".into());
            }
            exchange_guard.capture = capture;
            exchange_guard.payload_complete = true;
        }
        resolve_bdat_exchange(&self.hub, &self.shared, self.epoch, &exchange)?;
        self.mode = if last {
            ClientMode::AwaitTransactionFinal
        } else {
            ClientMode::Command
        };
        Ok(true)
    }

    fn consume_transaction_final(&mut self) -> Result<bool, String> {
        let seen = {
            let mut shared = lock_unpoisoned(&self.shared);
            let seen = shared.transaction_final_seen;
            if seen {
                shared.transaction_final_seen = false;
                shared.transaction_started_monotonic_ns = None;
            }
            seen
        };
        if seen {
            self.mode = ClientMode::Command;
            Ok(true)
        } else if self.buffer.is_empty() {
            Ok(false)
        } else {
            Err("SMTP client sent a new transaction before the final acceptance reply".into())
        }
    }

    fn disable(&mut self, reason: String) {
        if matches!(self.mode, ClientMode::Disabled) {
            return;
        }
        self.mode = ClientMode::Disabled;
        self.buffer.clear();
        self.current_capture = None;
        self.current_bdat = None;
        let mut shared = lock_unpoisoned(&self.shared);
        shared.disabled = true;
        shared.pending.clear();
        drop(shared);
        self.hub.mark_failure_for_epoch(self.epoch, reason);
    }
}

impl Drop for ClientObserver {
    fn drop(&mut self) {
        let mut shared = lock_unpoisoned(&self.shared);
        if shared.disabled {
            return;
        }
        shared.client_terminal_mode = Some(match self.mode {
            ClientMode::Command => ClientTerminalMode::Command,
            ClientMode::AwaitDataPrompt => ClientTerminalMode::AwaitDataPrompt,
            ClientMode::Data => ClientTerminalMode::Data,
            ClientMode::Bdat { .. } => ClientTerminalMode::Bdat,
            ClientMode::AwaitTransactionFinal => ClientTerminalMode::AwaitTransactionFinal,
            ClientMode::Disabled => ClientTerminalMode::Disabled,
        });
        shared.client_terminal_residual = if !self.buffer.is_empty() {
            Some("client parser buffer was not empty")
        } else if self.current_capture.is_some() {
            Some("message capture ended without a final DATA/BDAT boundary")
        } else if self.current_bdat.is_some() {
            Some("BDAT exchange ended before its payload completed")
        } else {
            None
        };
    }
}

pub struct ServerObserver {
    hub: ObserverHub,
    shared: Arc<Mutex<ConnectionState>>,
    _lifetime: Arc<ConnectionLifetime>,
    buffer: Vec<u8>,
    multiline_code: Option<[u8; 3]>,
    multiline_digest: Sha256,
    multiline_bytes: usize,
    greeting_seen: bool,
    disabled: bool,
    epoch: u64,
    pending_data_final: Vec<PendingDataFinal>,
    pending_bdat_forward_acks: Vec<Arc<Mutex<BdatExchange>>>,
}

impl ServerObserver {
    fn new(
        hub: ObserverHub,
        shared: Arc<Mutex<ConnectionState>>,
        lifetime: Arc<ConnectionLifetime>,
        epoch: u64,
    ) -> Self {
        Self {
            hub,
            shared,
            _lifetime: lifetime,
            buffer: Vec::with_capacity(OBSERVER_BUFFER_INITIAL_BYTES),
            multiline_code: None,
            multiline_digest: Sha256::new(),
            multiline_bytes: 0,
            greeting_seen: false,
            disabled: false,
            epoch,
            pending_data_final: Vec::new(),
            pending_bdat_forward_acks: Vec::new(),
        }
    }

    pub fn observe(&mut self, value: &[u8]) {
        self.observe_pending(value);
        if let Err(error) = self.acknowledge_forwarded() {
            self.disable(error);
        }
    }

    pub(crate) fn observe_pending(&mut self, value: &[u8]) {
        if self.disabled {
            return;
        }
        if lock_unpoisoned(&self.shared).disabled {
            self.disabled = true;
            self.buffer.clear();
            self.multiline_code = None;
            self.multiline_digest = Sha256::new();
            self.multiline_bytes = 0;
            return;
        }
        let maximum_buffered = self
            .hub
            .limits()
            .max_line_bytes
            .saturating_add(MAX_OBSERVER_FEED_BYTES);
        if value.len() > MAX_OBSERVER_FEED_BYTES
            || self.buffer.len().saturating_add(value.len()) > maximum_buffered
        {
            self.disable("SMTP backend observer buffer exceeded its accounted ceiling".into());
            return;
        }
        self.buffer.extend_from_slice(value);
        loop {
            let Some(end) = find_bytes(&self.buffer, b"\r\n") else {
                if self.buffer.len() > self.hub.limits().max_line_bytes {
                    self.disable("SMTP reply line exceeded the fixed observer limit".into());
                }
                return;
            };
            if end + 2 > self.hub.limits().max_line_bytes {
                self.disable("SMTP reply line exceeded the fixed observer limit".into());
                return;
            }
            let line: Vec<u8> = self.buffer.drain(..end + 2).collect();
            if let Err(error) = self.consume_reply_line(&line) {
                self.disable(error);
                return;
            }
            if self.disabled {
                return;
            }
        }
    }

    pub(crate) fn maximum_reply_block_bytes(&self) -> usize {
        self.hub
            .limits()
            .maximum_backend_reply_block_bytes()
            .expect("validated observer limits must have a reply block ceiling")
    }

    pub(crate) fn is_disabled(&self) -> bool {
        self.disabled
    }

    pub(crate) fn maximum_reply_line_bytes(&self) -> usize {
        self.hub.limits().max_line_bytes
    }

    pub fn observe_eof(&mut self) {
        self.observe(&[]);
        if !self.buffer.is_empty() || self.multiline_code.is_some() {
            self.disable("SMTP backend half-closed with an incomplete reply".into());
        }
    }

    pub(crate) fn pending_persistence_gate_id(&self) -> Result<Option<u64>, String> {
        let mut gate_id = None;
        for candidate in self
            .pending_data_final
            .iter()
            .filter_map(|pending| pending.persistence_gate_id)
            .chain(
                self.pending_bdat_forward_acks
                    .iter()
                    .filter_map(|exchange| lock_unpoisoned(exchange).persistence_gate_id),
            )
        {
            if gate_id.replace(candidate).is_some() {
                return Err("one proxy write contained more than one persistence gate".into());
            }
        }
        Ok(gate_id)
    }

    pub(crate) async fn prepare_pending_persistence_gate(
        &self,
        gate_id: u64,
    ) -> Result<(), String> {
        self.hub
            .publish_persistence_gate_after_prior_forwards(gate_id, PERSISTENCE_GATE_TIMEOUT)
            .await?;
        self.hub
            .wait_for_persistence_gate_release(gate_id, PERSISTENCE_GATE_TIMEOUT)
            .await?;
        self.hub.mark_persistence_gate_forwarding_started(gate_id)
    }

    pub fn acknowledge_forwarded(&mut self) -> Result<(), String> {
        let completed_at_monotonic_ns = self.hub.monotonic_ns();
        for mut pending in self.pending_data_final.drain(..) {
            pending.boundary.completed_at_monotonic_ns = completed_at_monotonic_ns;
            if let Some(gate_id) = pending.persistence_gate_id {
                self.hub.mark_persistence_gate_forwarding_completed(
                    gate_id,
                    completed_at_monotonic_ns,
                )?;
            }
            self.hub
                .record_final_reply_for_epoch(self.epoch, pending.code);
            if pending.code == 250 && !pending.rejected {
                self.hub
                    .record_message((*pending.capture).finish(), pending.boundary);
            }
        }
        for exchange in self.pending_bdat_forward_acks.drain(..) {
            let persistence_gate_id;
            {
                let mut exchange = lock_unpoisoned(&exchange);
                exchange.reply_forwarded = true;
                persistence_gate_id = exchange.persistence_gate_id;
                if let Some(boundary) = exchange.reply.as_mut() {
                    boundary.completed_at_monotonic_ns = completed_at_monotonic_ns;
                }
            }
            if let Some(gate_id) = persistence_gate_id {
                self.hub.mark_persistence_gate_forwarding_completed(
                    gate_id,
                    completed_at_monotonic_ns,
                )?;
            }
            resolve_bdat_exchange(&self.hub, &self.shared, self.epoch, &exchange)?;
        }
        Ok(())
    }

    fn consume_reply_line(&mut self, line: &[u8]) -> Result<(), String> {
        if line.len() < 5 || !line[..3].iter().all(u8::is_ascii_digit) {
            return Err("SMTP backend emitted a malformed reply line".into());
        }
        let code_bytes: [u8; 3] = line[..3].try_into().expect("three-byte SMTP code");
        let code = std::str::from_utf8(&code_bytes)
            .map_err(|_| "SMTP reply code was not ASCII")?
            .parse::<u16>()
            .map_err(|_| "SMTP reply code was invalid")?;
        if let Some(expected) = self.multiline_code {
            if code_bytes != expected {
                return Err("SMTP multiline reply changed its status code".into());
            }
            if line[3] != b'-' && line[3] != b' ' {
                return Err("SMTP multiline reply separator was neither space nor hyphen".into());
            }
            self.multiline_digest.update(line);
            self.multiline_bytes = self.multiline_bytes.saturating_add(line.len());
            if line[3] == b' ' {
                let digest: [u8; 32] = self.multiline_digest.clone().finalize().into();
                let bytes = self.multiline_bytes;
                self.multiline_code = None;
                self.multiline_digest = Sha256::new();
                self.multiline_bytes = 0;
                self.complete_reply(code, bytes, digest)?;
            }
            return Ok(());
        }
        if line[3] == b'-' {
            self.multiline_code = Some(code_bytes);
            self.multiline_digest = Sha256::new();
            self.multiline_digest.update(line);
            self.multiline_bytes = line.len();
            return Ok(());
        }
        if line[3] != b' ' {
            return Err("SMTP reply separator was neither space nor hyphen".into());
        }
        let digest: [u8; 32] = Sha256::digest(line).into();
        self.complete_reply(code, line.len(), digest)
    }

    fn complete_reply(
        &mut self,
        code: u16,
        reply_bytes: usize,
        reply_sha256: [u8; 32],
    ) -> Result<(), String> {
        if !self.greeting_seen {
            self.greeting_seen = true;
            return Ok(());
        }
        let expectation = {
            let mut shared = lock_unpoisoned(&self.shared);
            if shared.disabled {
                return Ok(());
            }
            shared
                .pending
                .pop_front()
                .ok_or_else(|| "SMTP backend reply had no queued client command".to_owned())?
        };
        match expectation {
            ReplyExpectation::Simple => {}
            ReplyExpectation::StartTls => {
                if code == 220 {
                    self.hub.mark_failure_for_epoch(
                        self.epoch,
                        "SMTP STARTTLS entered opaque forwarding; observer qualification is false",
                    );
                    self.disabled = true;
                    self.buffer.clear();
                    self.multiline_code = None;
                    self.multiline_digest = Sha256::new();
                    self.multiline_bytes = 0;
                    let mut shared = lock_unpoisoned(&self.shared);
                    shared.disabled = true;
                    shared.pending.clear();
                }
            }
            ReplyExpectation::Mail | ReplyExpectation::Rset => {
                if code == 250 {
                    lock_unpoisoned(&self.shared).transaction_poisoned = false;
                }
            }
            ReplyExpectation::DataPrompt => {
                lock_unpoisoned(&self.shared).data_prompt_result = Some(code == 354);
            }
            ReplyExpectation::DataFinal(capture) => {
                let rejected = {
                    let mut shared = lock_unpoisoned(&self.shared);
                    shared.transaction_final_seen = true;
                    let rejected = shared.transaction_poisoned;
                    shared.transaction_poisoned = false;
                    rejected
                };
                let persistence_gate_id = if code == 250 && !rejected {
                    self.hub.reserve_successful_final_for_epoch(self.epoch)?
                } else {
                    None
                };
                self.pending_data_final.push(PendingDataFinal {
                    code,
                    rejected,
                    capture,
                    boundary: ReplyBoundary {
                        code,
                        reply_bytes,
                        reply_sha256,
                        completed_at_monotonic_ns: 0,
                    },
                    persistence_gate_id,
                });
            }
            ReplyExpectation::Bdat(exchange) => {
                let gate_candidate = {
                    let mut exchange = lock_unpoisoned(&exchange);
                    exchange.reply = Some(ReplyBoundary {
                        code,
                        reply_bytes,
                        reply_sha256,
                        completed_at_monotonic_ns: 0,
                    });
                    code == 250
                        && exchange.last
                        && exchange.payload_complete
                        && exchange.capture.is_some()
                };
                if gate_candidate {
                    let gate_id = self.hub.reserve_successful_final_for_epoch(self.epoch)?;
                    lock_unpoisoned(&exchange).persistence_gate_id = gate_id;
                }
                self.pending_bdat_forward_acks.push(exchange);
            }
        }
        Ok(())
    }

    fn disable(&mut self, reason: String) {
        if self.disabled {
            return;
        }
        self.disabled = true;
        self.buffer.clear();
        self.pending_data_final.clear();
        self.pending_bdat_forward_acks.clear();
        let mut shared = lock_unpoisoned(&self.shared);
        shared.disabled = true;
        shared.pending.clear();
        drop(shared);
        self.hub.mark_failure_for_epoch(self.epoch, reason);
    }
}

impl Drop for ServerObserver {
    fn drop(&mut self) {
        let mut shared = lock_unpoisoned(&self.shared);
        if shared.disabled {
            return;
        }
        shared.server_terminal_residual = if !self.buffer.is_empty() {
            Some("backend parser buffer was not empty")
        } else if self.multiline_code.is_some() {
            Some("backend multiline reply was incomplete")
        } else if !self.pending_data_final.is_empty() || !self.pending_bdat_forward_acks.is_empty()
        {
            Some("backend final reply was parsed but not forwarded")
        } else if !self.greeting_seen {
            Some("backend ended before its SMTP greeting")
        } else {
            None
        };
    }
}

fn resolve_bdat_exchange(
    hub: &ObserverHub,
    shared: &Arc<Mutex<ConnectionState>>,
    epoch: u64,
    exchange: &Arc<Mutex<BdatExchange>>,
) -> Result<(), String> {
    let resolved = {
        let mut exchange = lock_unpoisoned(exchange);
        if exchange.processed
            || !exchange.payload_complete
            || exchange.reply.is_none()
            || !exchange.reply_forwarded
        {
            return Ok(());
        }
        exchange.processed = true;
        (
            exchange.last,
            exchange.capture.take(),
            exchange.reply.take().expect("checked SMTP BDAT reply"),
        )
    };
    let (last, capture, boundary) = resolved;
    if last {
        hub.record_final_reply_for_epoch(epoch, boundary.code);
        let rejected = {
            let mut state = lock_unpoisoned(shared);
            state.transaction_final_seen = true;
            let rejected = state.transaction_poisoned;
            state.transaction_poisoned = false;
            rejected
        };
        if boundary.code == 250 && !rejected {
            let capture = capture
                .ok_or_else(|| "SMTP final BDAT reply had no completed capture".to_owned())?;
            hub.record_message((*capture).finish(), boundary);
        }
    } else if boundary.code != 250 {
        lock_unpoisoned(shared).transaction_poisoned = true;
        hub.mark_failure_for_epoch(
            epoch,
            format!(
                "SMTP backend rejected a non-final BDAT chunk with {}",
                boundary.code
            ),
        );
    }
    Ok(())
}

fn parse_bdat(line: &[u8]) -> Result<(usize, bool), String> {
    let trimmed = line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| "SMTP BDAT command had no CRLF".to_owned())?;
    let mut fields = trimmed
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let command = fields.next().unwrap_or_default();
    let size_field = fields.next().unwrap_or_default();
    let third = fields.next();
    if fields.next().is_some() || !command.eq_ignore_ascii_case(b"BDAT") || size_field.is_empty() {
        return Err("SMTP BDAT command had invalid fields".into());
    }
    let size = std::str::from_utf8(size_field)
        .map_err(|_| "SMTP BDAT size was not ASCII")?
        .parse::<usize>()
        .map_err(|_| "SMTP BDAT size was invalid")?;
    let last = third.is_some_and(|field| field.eq_ignore_ascii_case(b"LAST"));
    if third.is_some() && !last {
        return Err("SMTP BDAT third field was not LAST".into());
    }
    Ok((size, last))
}

struct StressHeaders {
    round: u64,
    index: usize,
    from: String,
    to: String,
    message_id: String,
}

struct MessageDetails {
    headers: StressHeaders,
    message_id_sha256: [u8; 32],
    sample: MessageSample,
}

impl MessageDetails {
    fn parse(message: &CapturedMessage, boundary: &ReplyBoundary) -> Result<Self, String> {
        let headers = parse_stress_headers(&message.header_prefix)?;
        let message_id_sha256 = Sha256::digest(headers.message_id.as_bytes()).into();
        let sample = MessageSample {
            round: headers.round,
            index: headers.index,
            wire_bytes: message.wire_bytes,
            wire_sha256: encode_hex(message.wire_sha256),
            message_id_sha256: encode_hex(message_id_sha256),
            accepted_at_monotonic_ns: boundary.completed_at_monotonic_ns,
            transaction_latency_ns: boundary
                .completed_at_monotonic_ns
                .saturating_sub(message.transaction_started_monotonic_ns),
        };
        Ok(Self {
            headers,
            message_id_sha256,
            sample,
        })
    }
}

fn parse_stress_headers(prefix: &[u8]) -> Result<StressHeaders, String> {
    let end = find_bytes(prefix, b"\r\n\r\n")
        .ok_or_else(|| "SMTP headers exceeded the fixed prefix capture".to_owned())?;
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in prefix[..end].split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line
            .first()
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            let (_, value) = fields
                .last_mut()
                .ok_or_else(|| "SMTP first header line was folded".to_owned())?;
            value.push(' ');
            value.push_str(String::from_utf8_lossy(line).trim());
            continue;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err("SMTP header line omitted its colon".into());
        };
        let name = String::from_utf8_lossy(&line[..colon]).to_ascii_lowercase();
        let value = String::from_utf8_lossy(&line[colon + 1..])
            .trim()
            .to_owned();
        fields.push((name, value));
    }
    let field = |name: &str| {
        fields
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    };
    let subject = field("subject");
    let subject = subject
        .strip_prefix("Stress Test R")
        .ok_or_else(|| format!("SMTP stress Subject changed: {subject:?}"))?;
    let (round, tail) = subject
        .split_once(" #")
        .ok_or_else(|| "SMTP stress Subject omitted its round separator".to_owned())?;
    let (index, millis) = tail
        .split_once(" - ")
        .ok_or_else(|| "SMTP stress Subject omitted its timestamp separator".to_owned())?;
    let round = round
        .parse::<u64>()
        .map_err(|_| "SMTP stress Subject round was invalid")?;
    let _millis = millis
        .parse::<u64>()
        .map_err(|_| "SMTP stress Subject timestamp was invalid")?;
    Ok(StressHeaders {
        round,
        index: index
            .parse()
            .map_err(|_| "SMTP stress Subject index was invalid")?,
        from: field("from"),
        to: field("to"),
        message_id: field("message-id"),
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memmem::find(haystack, needle)
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stress_headers_keep_first_duplicates_and_fold_only_their_own_lines() {
        let headers = parse_stress_headers(
            b"sUbJeCt: Stress Test R7 #12 - 1234\r\nFrom: first@lmyz.net\r\n\tcontinued\r\nFrom: second@lmyz.net\r\n ignored-duplicate\r\nX-Ignored: value\r\n folded-unknown\r\nTo: receiver@lmyz.net\r\nMessage-ID: <first>\r\nMessage-ID: <second>\r\n\r\nbody",
        ).unwrap();
        assert_eq!((headers.round, headers.index), (7, 12));
        assert_eq!(headers.from, "first@lmyz.net continued");
        assert_eq!(headers.to, "receiver@lmyz.net");
        assert_eq!(headers.message_id, "<first>");
    }

    #[test]
    fn unselected_headers_still_require_valid_syntax_and_a_fold_predecessor() {
        assert_eq!(
            parse_stress_headers(b" folded-first\r\n\r\n")
                .err()
                .as_deref(),
            Some("SMTP first header line was folded")
        );
        assert_eq!(
            parse_stress_headers(
                b"Subject: Stress Test R1 #0 - 1\r\nX-Unused: valid\r\ninvalid-unknown\r\n\r\n"
            )
            .err()
            .as_deref(),
            Some("SMTP header line omitted its colon")
        );
        let headers = parse_stress_headers(
            "Subject: Stress Test R1 #0 - 1\r\nFrom:\u{2003}sender@lmyz.net\u{2003}\r\n\r\n"
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(headers.from, "sender@lmyz.net");
        assert!(headers.to.is_empty());
        assert!(headers.message_id.is_empty());
    }

    fn spec(expected: usize, bytes: usize) -> RoundSpec {
        RoundSpec {
            run_id: "observer-test".into(),
            expected_messages: expected,
            message_bytes: bytes,
            expected_sender: DEFAULT_SENDER.into(),
            expected_receiver: DEFAULT_RECEIVER.into(),
        }
    }

    fn message(round: u64, index: usize, body_bytes: usize) -> Vec<u8> {
        let headers = format!(
            "From: {DEFAULT_SENDER}\r\nTo: {DEFAULT_RECEIVER}\r\nSubject: Stress Test R{round} #{index} - 1234\r\nMessage-ID: <{round}-{index}@lmyz.net>\r\n\r\n"
        );
        let mut value = headers.into_bytes();
        value.resize(value.len() + body_bytes, b'x');
        value.extend_from_slice(b"\r\n");
        value
    }

    fn maximum_wire_message_with_full_header(nominal: usize, limits: &ObserverLimits) -> Vec<u8> {
        const SOFT_WRAPPED_PRINTABLE: &[u8] =
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n";
        let mut value = format!(
            "From: {DEFAULT_SENDER}\r\nTo: {DEFAULT_RECEIVER}\r\nSubject: Stress Test R12 #0 - 1234\r\nMessage-ID: <12-0@lmyz.net>\r\nX-Pad: "
        )
        .into_bytes();
        assert!(value.len() + 4 <= limits.header_prefix_bytes);
        value.resize(limits.header_prefix_bytes - 4, b'h');
        value.extend_from_slice(b"\r\n\r\n");
        let target = maximum_wire_bytes(nominal, limits);
        while value.len() < target - 2 {
            let remaining = target - 2 - value.len();
            value.extend_from_slice(
                &SOFT_WRAPPED_PRINTABLE[..remaining.min(SOFT_WRAPPED_PRINTABLE.len())],
            );
        }
        value.extend_from_slice(b"\r\n");
        value
    }

    fn feed_fragmented(observer: &mut impl FnMut(&[u8]), value: &[u8]) {
        for byte in value {
            observer(std::slice::from_ref(byte));
        }
    }

    fn qualified_snapshot(expected_messages: usize) -> PersistenceSnapshotEvidence {
        PersistenceSnapshotEvidence {
            clock_id: "CLOCK_MONOTONIC".into(),
            snapshot_started_monotonic_ns: 10,
            snapshot_completed_monotonic_ns: 20,
            postgres_query_duration_ns: 5,
            maildir_snapshot_duration_ns: 1,
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

    fn pending_data_exchange(
        hub: &ObserverHub,
        round: u64,
        index: usize,
        body_bytes: usize,
    ) -> (ClientObserver, ServerObserver, usize) {
        let payload = message(round, index, body_bytes);
        let payload_len = payload.len();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 synthetic\r\n");
        client.observe(b"MAIL FROM:<stress-sender@lmyz.net>\r\nDATA\r\n");
        server.observe(b"250 ok\r\n354 send data\r\n");
        client.observe(&payload);
        client.observe(b".\r\n");
        server.observe_pending(b"250 accepted\r\n");
        (client, server, payload_len)
    }

    #[test]
    fn fragmented_pipelined_data_is_verified_at_final_250() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(7, 0, 1_024);
        hub.begin(spec(1, payload.len())).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 synthetic\r\n");
        client.observe(b"EHLO local\r\nMAIL FROM:<stress-sender@lmyz.net>\r\nRCPT TO:<stress-receiver@lmyz.net>\r\nDATA\r\n");
        server.observe(b"250-synthetic\r\n250 PIPELINING\r\n250 ok\r\n250 ok\r\n354 send data\r\n");
        let mut wire = payload.clone();
        wire.extend_from_slice(b".\r\n");
        feed_fragmented(&mut |chunk| client.observe(chunk), &wire);
        server.observe(b"250 accepted\r\n");
        let summary = hub.finalize().unwrap();
        assert!(summary.qualification, "{summary:#?}");
        assert_eq!(summary.verified, 1);
        assert_eq!(summary.transaction_latency.samples, 1);
        assert_eq!(summary.final_250_boundary.unwrap().reply_code, 250);
    }

    #[test]
    fn large_data_chunks_retain_only_the_marker_tail() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(8, 0, 256 * 1024);
        hub.begin(spec(1, payload.len())).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 synthetic\r\n");
        client.observe(
            b"MAIL FROM:<stress-sender@lmyz.net>\r\nRCPT TO:<stress-receiver@lmyz.net>\r\nDATA\r\n",
        );
        server.observe(b"250 ok\r\n250 ok\r\n354 send data\r\n");

        for chunk in payload.chunks(MAX_OBSERVER_FEED_BYTES) {
            client.observe(chunk);
            assert!(
                client.buffer.len() < DATA_MARKER.len(),
                "DATA fast path buffered {} bytes",
                client.buffer.len()
            );
        }
        client.observe(b".\r\n");
        server.observe(b"250 accepted\r\n");

        let summary = hub.finalize().unwrap();
        assert!(summary.qualification, "{summary:#?}");
        assert_eq!(summary.verified, 1);
        assert_eq!(summary.total_wire_bytes, payload.len() as u64);
    }

    #[test]
    fn delayed_final_250_client_write_does_not_complete_observation_early() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(7, 0, 1_024);
        hub.begin(spec(1, payload.len())).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 synthetic\r\n");
        client.observe(b"MAIL FROM:<stress-sender@lmyz.net>\r\nDATA\r\n");
        server.observe(b"250 ok\r\n354 send data\r\n");
        client.observe(&payload);
        client.observe(b".\r\n");

        server.observe_pending(b"250 accepted\r\n");
        let before_forward = hub.summary().unwrap();
        assert_eq!(before_forward.verified, 0);
        assert_eq!(before_forward.smtp_final_replies.success, 0);
        assert!(before_forward.final_250_boundary.is_none());

        server.acknowledge_forwarded().unwrap();
        let after_forward = hub.summary().unwrap();
        assert_eq!(after_forward.verified, 1);
        assert_eq!(after_forward.smtp_final_replies.success, 1);
        assert_eq!(after_forward.final_250_boundary.unwrap().reply_code, 250);
    }

    #[test]
    fn partial_summary_exposes_verified_progress_duration_before_final_250() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(18, 0, 1_024);
        hub.begin(spec(2, payload.len())).unwrap();
        let (_client, mut server, _) = pending_data_exchange(&hub, 18, 0, 1_024);
        server.acknowledge_forwarded().unwrap();

        let summary = hub.summary().unwrap();
        assert_eq!(summary.verified, 1);
        assert!(summary.final_250_boundary.is_none());
        assert!(summary.duration_ns.is_none());
        assert!(summary.progress_duration_ns.is_some_and(|value| value > 0));
    }

    #[test]
    fn out_of_order_final_reply_forwarding_keeps_progress_duration_monotonic() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload_len = message(22, 0, 1_024).len();
        hub.begin(spec(2, payload_len)).unwrap();
        let (_earlier_client, mut earlier_server, _) = pending_data_exchange(&hub, 22, 0, 1_024);
        std::thread::sleep(std::time::Duration::from_millis(1));
        let (_later_client, mut later_server, _) = pending_data_exchange(&hub, 22, 1, 1_024);

        later_server.acknowledge_forwarded().unwrap();
        let first_progress = hub.summary().unwrap().progress_duration_ns.unwrap();
        earlier_server.acknowledge_forwarded().unwrap();
        let summary = hub.finalize().unwrap();

        assert!(summary.qualification, "{summary:#?}");
        assert_eq!(summary.verified, 2);
        assert!(summary.progress_duration_ns.unwrap() >= first_progress);
        assert_eq!(summary.duration_ns, summary.progress_duration_ns);
    }

    #[tokio::test]
    async fn ordinal_n_gate_waits_for_out_of_order_prior_final_250_forward() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let first_payload = message(17, 0, 1_024);
        let second_payload = message(17, 1, 1_024);
        assert_eq!(first_payload.len(), second_payload.len());
        hub.begin_with_persistence_gate(spec(2, first_payload.len()), true)
            .unwrap();

        let (mut first_client, mut first_server) = hub.connection();
        let (mut second_client, mut second_server) = hub.connection();
        for server in [&mut first_server, &mut second_server] {
            server.observe(b"220 synthetic\r\n");
        }
        for (client, server, payload) in [
            (&mut first_client, &mut first_server, &first_payload),
            (&mut second_client, &mut second_server, &second_payload),
        ] {
            client.observe(b"MAIL FROM:<stress-sender@lmyz.net>\r\nDATA\r\n");
            server.observe(b"250 ok\r\n354 send data\r\n");
            client.observe(payload);
            client.observe(b".\r\n");
        }

        first_server.observe_pending(b"250 first\r\n");
        second_server.observe_pending(b"250 second\r\n");
        let gate_id = second_server
            .pending_persistence_gate_id()
            .unwrap()
            .expect("ordinal N must own the gate");
        let owner = tokio::spawn(async move {
            second_server
                .prepare_pending_persistence_gate(gate_id)
                .await
                .unwrap();
            second_server.acknowledge_forwarded().unwrap();
        });

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                hub.wait_for_persistence_gate(std::time::Duration::from_secs(1)),
            )
            .await
            .is_err(),
            "ordinal N gate was published before ordinal N-1 was forwarded"
        );
        first_server.acknowledge_forwarded().unwrap();
        let gate = hub
            .wait_for_persistence_gate(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(gate.gate_id, gate_id);
        hub.release_persistence_gate(gate_id, qualified_snapshot(2))
            .unwrap();
        owner.await.unwrap();

        let summary = hub.finalize().unwrap();
        assert!(summary.qualification, "{summary:#?}");
        assert!(summary.persistence_gate.qualified);
        assert_eq!(
            summary
                .persistence_gate
                .forwarding_completed_at_proxy_monotonic_ns,
            summary
                .final_250_boundary
                .map(|boundary| boundary.completed_at_monotonic_ns)
        );
    }

    #[tokio::test]
    async fn persistence_gate_is_single_use_and_rejects_release_before_publication() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload_len = message(18, 0, 1_024).len();
        hub.begin_with_persistence_gate(spec(2, payload_len), true)
            .unwrap();
        let (_first_client, mut first_server, _) = pending_data_exchange(&hub, 18, 0, 1_024);
        let (_second_client, mut second_server, _) = pending_data_exchange(&hub, 18, 1, 1_024);
        let gate_id = second_server
            .pending_persistence_gate_id()
            .unwrap()
            .unwrap();
        assert!(
            hub.release_persistence_gate(gate_id, qualified_snapshot(2))
                .unwrap_err()
                .contains("before publication")
        );

        let owner = tokio::spawn(async move {
            second_server
                .prepare_pending_persistence_gate(gate_id)
                .await
                .unwrap();
            second_server.acknowledge_forwarded().unwrap();
        });
        first_server.acknowledge_forwarded().unwrap();
        hub.wait_for_persistence_gate(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        hub.release_persistence_gate(gate_id, qualified_snapshot(2))
            .unwrap();
        assert!(
            hub.release_persistence_gate(gate_id, qualified_snapshot(2))
                .unwrap_err()
                .contains("already resolved")
        );
        owner.await.unwrap();
        assert!(hub.finalize().unwrap().qualification);
    }

    #[tokio::test]
    async fn unqualified_snapshot_and_abort_never_forward_the_gated_reply() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload_len = message(19, 0, 1_024).len();
        hub.begin_with_persistence_gate(spec(1, payload_len), true)
            .unwrap();
        let (_client, server, _) = pending_data_exchange(&hub, 19, 0, 1_024);
        let gate_id = server.pending_persistence_gate_id().unwrap().unwrap();
        let owner =
            tokio::spawn(async move { server.prepare_pending_persistence_gate(gate_id).await });
        hub.wait_for_persistence_gate(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        let mut unqualified = qualified_snapshot(1);
        unqualified.postgres_rows = 0;
        unqualified.postgres_row_delta = 0;
        unqualified.maildir_atomic_rename_publications = 0;
        unqualified.qualified = false;
        assert!(
            hub.release_persistence_gate(gate_id, unqualified)
                .unwrap_err()
                .contains("unqualified")
        );
        hub.abort_persistence_gate(gate_id, "snapshot mismatch".into())
            .unwrap();
        assert!(owner.await.unwrap().unwrap_err().contains("aborted"));
        let summary = hub.finalize().unwrap();
        assert!(!summary.qualification);
        assert!(summary.final_250_boundary.is_none());
        assert_eq!(summary.persistence_gate.status, "aborted");
    }

    #[tokio::test]
    async fn gate_timeout_and_write_failure_cannot_create_a_final_boundary() {
        let timeout_hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload_len = message(20, 0, 1_024).len();
        timeout_hub
            .begin_with_persistence_gate(spec(1, payload_len), true)
            .unwrap();
        let (_client, server, _) = pending_data_exchange(&timeout_hub, 20, 0, 1_024);
        let gate_id = server.pending_persistence_gate_id().unwrap().unwrap();
        timeout_hub
            .publish_persistence_gate_after_prior_forwards(
                gate_id,
                std::time::Duration::from_millis(10),
            )
            .await
            .unwrap();
        assert!(
            timeout_hub
                .wait_for_persistence_gate_release(gate_id, std::time::Duration::from_millis(1),)
                .await
                .unwrap_err()
                .contains("timed out")
        );
        let timed_out = timeout_hub.finalize().unwrap();
        assert!(!timed_out.qualification);
        assert!(timed_out.final_250_boundary.is_none());

        let write_hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        write_hub
            .begin_with_persistence_gate(spec(1, payload_len), true)
            .unwrap();
        let (_client, server, _) = pending_data_exchange(&write_hub, 21, 0, 1_024);
        let gate_id = server.pending_persistence_gate_id().unwrap().unwrap();
        write_hub
            .publish_persistence_gate_after_prior_forwards(
                gate_id,
                std::time::Duration::from_millis(10),
            )
            .await
            .unwrap();
        write_hub
            .release_persistence_gate(gate_id, qualified_snapshot(1))
            .unwrap();
        write_hub
            .wait_for_persistence_gate_release(gate_id, std::time::Duration::from_millis(10))
            .await
            .unwrap();
        write_hub
            .mark_persistence_gate_forwarding_started(gate_id)
            .unwrap();
        drop(server);
        let write_failed = write_hub.finalize().unwrap();
        assert!(!write_failed.qualification);
        assert!(write_failed.final_250_boundary.is_none());
        assert_eq!(write_failed.persistence_gate.status, "forwarding");
    }

    #[tokio::test]
    async fn completion_notification_reaches_all_concurrent_waiters() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(8, 0, 1_024);
        hub.begin(spec(1, payload.len())).unwrap();
        let first_hub = hub.clone();
        let first = tokio::spawn(async move {
            first_hub
                .wait_until_expected(std::time::Duration::from_secs(1))
                .await
        });
        let second_hub = hub.clone();
        let second = tokio::spawn(async move {
            second_hub
                .wait_until_expected(std::time::Duration::from_secs(1))
                .await
        });
        tokio::task::yield_now().await;
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 synthetic\r\n");
        client.observe(b"MAIL FROM:<stress-sender@lmyz.net>\r\n");
        server.observe(b"250 ok\r\n");
        client.observe(b"DATA\r\n");
        server.observe(b"354 go\r\n");
        client.observe(&payload);
        client.observe(b".\r\n");
        server.observe(b"250 accepted\r\n");
        assert!(first.await.unwrap());
        assert!(second.await.unwrap());
    }

    #[test]
    fn coalesced_bdat_chunks_are_hashed_as_one_message() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(9, 0, 1_024);
        hub.begin(spec(1, payload.len())).unwrap();
        let split = payload.len() / 2;
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 synthetic\r\n");
        client.observe(b"MAIL FROM:<stress-sender@lmyz.net>\r\n");
        server.observe(b"250 ok\r\n");
        let mut first = format!("BDAT {split}\r\n").into_bytes();
        first.extend_from_slice(&payload[..split]);
        client.observe(&first);
        server.observe(b"250 chunk\r\n");
        let mut last = format!("BDAT {} LAST\r\n", payload.len() - split).into_bytes();
        last.extend_from_slice(&payload[split..]);
        client.observe(&last);
        server.observe(b"250 accepted\r\n");
        let summary = hub.finalize().unwrap();
        assert!(summary.qualification, "{summary:#?}");
        assert_eq!(summary.total_wire_bytes, payload.len() as u64);
    }

    #[test]
    fn fragmented_bdat_command_and_payload_are_verified() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(11, 0, 1_024);
        hub.begin(spec(1, payload.len())).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 synthetic\r\n");
        client.observe(b"MAIL FROM:<stress-sender@lmyz.net>\r\n");
        server.observe(b"250 ok\r\n");
        let mut frame = format!("BDAT {} LAST\r\n", payload.len()).into_bytes();
        frame.extend_from_slice(&payload);
        feed_fragmented(&mut |chunk| client.observe(chunk), &frame);
        server.observe(b"250 accepted\r\n");
        let summary = hub.finalize().unwrap();
        assert!(summary.qualification, "{summary:#?}");
        assert_eq!(summary.total_wire_bytes, payload.len() as u64);
    }

    #[tokio::test]
    async fn bdat_last_success_uses_the_same_pre_final_250_gate() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(22, 0, 1_024);
        hub.begin_with_persistence_gate(spec(1, payload.len()), true)
            .unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 synthetic\r\n");
        client.observe(b"MAIL FROM:<stress-sender@lmyz.net>\r\n");
        server.observe(b"250 ok\r\n");
        let mut frame = format!("BDAT {} LAST\r\n", payload.len()).into_bytes();
        frame.extend_from_slice(&payload);
        client.observe(&frame);
        server.observe_pending(b"250 accepted\r\n");
        let gate_id = server.pending_persistence_gate_id().unwrap().unwrap();
        let owner = tokio::spawn(async move {
            server
                .prepare_pending_persistence_gate(gate_id)
                .await
                .unwrap();
            server.acknowledge_forwarded().unwrap();
        });
        hub.wait_for_persistence_gate(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        hub.release_persistence_gate(gate_id, qualified_snapshot(1))
            .unwrap();
        owner.await.unwrap();
        let summary = hub.finalize().unwrap();
        assert!(summary.qualification, "{summary:#?}");
        assert!(summary.persistence_gate.qualified);
    }

    #[test]
    fn rejected_rset_does_not_clear_a_rejected_bdat_transaction() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(13, 0, 1_024);
        hub.begin(spec(1, payload.len())).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 synthetic\r\n");
        client.observe(b"MAIL FROM:<stress-sender@lmyz.net>\r\n");
        server.observe(b"250 mail\r\n");
        client.observe(b"BDAT 3\r\nbad");
        server.observe(b"554 chunk rejected\r\n");
        client.observe(b"RSET\r\n");
        server.observe(b"550 reset rejected\r\n");
        client.observe(b"DATA\r\n");
        server.observe(b"354 go\r\n");
        client.observe(&payload);
        client.observe(b".\r\n");
        server.observe(b"250 accepted\r\n");
        client.observe(b"MAIL FROM:<stress-sender@lmyz.net>\r\n");
        server.observe(b"250 mail\r\n");
        let mut clean_last = format!("BDAT {} LAST\r\n", payload.len()).into_bytes();
        clean_last.extend_from_slice(&payload);
        client.observe(&clean_last);
        server.observe(b"250 accepted\r\n");
        let summary = hub.finalize().unwrap();
        assert!(!summary.qualification);
        assert_eq!(summary.verified, 1);
        assert_eq!(summary.duplicates, 0);
        assert_eq!(summary.unique_message_ids, 1);
    }

    #[test]
    fn ten_mebibyte_tier_accepts_conservative_qp_expansion_and_full_header() {
        let limits = ObserverLimits::default();
        let nominal = 10 * 1024 * 1024;
        let payload = maximum_wire_message_with_full_header(nominal, &limits);
        assert_eq!(
            payload.len(),
            nominal + nominal.div_ceil(16) + WIRE_ENCODING_ALLOWANCE_BYTES
        );
        assert!(payload.len() < limits.max_message_bytes);
        let hub = ObserverHub::new(limits).unwrap();
        hub.begin(spec(1, nominal)).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 synthetic\r\n");
        client.observe(b"MAIL FROM:<stress-sender@lmyz.net>\r\n");
        server.observe(b"250 ok\r\n");
        client.observe(b"DATA\r\n");
        server.observe(b"354 go\r\n");
        for chunk in payload.chunks(64 * 1024) {
            client.observe(chunk);
        }
        client.observe(b".\r\n");
        server.observe(b"250 accepted\r\n");
        let summary = hub.finalize().unwrap();
        assert!(summary.qualification, "{summary:#?}");
        assert_eq!(summary.total_wire_bytes, payload.len() as u64);
    }

    #[test]
    fn duplicate_index_fails_qualification_without_unbounded_state() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(1, 0, 1_024);
        hub.begin(spec(2, payload.len())).unwrap();
        for _ in 0..2 {
            let (mut client, mut server) = hub.connection();
            server.observe(b"220 synthetic\r\n");
            client.observe(b"MAIL FROM:<x>\r\n");
            server.observe(b"250 ok\r\n");
            client.observe(b"DATA\r\n");
            server.observe(b"354 go\r\n");
            client.observe(&payload);
            client.observe(b".\r\n");
            server.observe(b"250 accepted\r\n");
        }
        let summary = hub.finalize().unwrap();
        assert!(!summary.qualification);
        assert_eq!(summary.duplicates, 1);
        assert_eq!(summary.missing, 1);
    }

    #[test]
    fn duplicate_message_id_across_distinct_indexes_is_rejected() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let first = message(1, 0, 1_024);
        let mut second = message(1, 1, 1_024);
        let message_id = find_bytes(&second, b"<1-1@lmyz.net>").unwrap();
        second[message_id..message_id + 14].copy_from_slice(b"<1-0@lmyz.net>");
        hub.begin(spec(2, first.len())).unwrap();
        for payload in [first, second] {
            let (mut client, mut server) = hub.connection();
            server.observe(b"220 synthetic\r\n");
            client.observe(b"MAIL FROM:<x>\r\n");
            server.observe(b"250 ok\r\n");
            client.observe(b"DATA\r\n");
            server.observe(b"354 go\r\n");
            client.observe(&payload);
            client.observe(b".\r\n");
            server.observe(b"250 accepted\r\n");
        }
        let summary = hub.finalize().unwrap();
        assert!(!summary.qualification);
        assert_eq!(summary.verified, 1);
        assert_eq!(summary.unique_message_ids, 1);
        assert!(
            summary
                .observer_failures
                .iter()
                .any(|failure| failure.contains("Message-ID was accepted"))
        );
    }

    #[test]
    fn pending_ring_overflow_disables_only_observation() {
        let limits = ObserverLimits {
            max_pending_replies: 2,
            ..ObserverLimits::default()
        };
        let hub = ObserverHub::new(limits).unwrap();
        hub.begin(spec(1, 1_024)).unwrap();
        let (mut client, _) = hub.connection();
        client.observe(b"NOOP\r\nNOOP\r\nNOOP\r\n");
        let summary = hub.finalize().unwrap();
        assert!(!summary.qualification);
        assert_eq!(summary.observer_failure_count, 1);
        assert!(summary.observer_failures[0].contains("pending reply ring"));
    }

    #[test]
    fn one_direction_failure_disables_the_peer_observer_without_duplicate_failures() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        hub.begin(spec(1, 1_024)).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"malformed\r\n");
        let payload = vec![b'x'; 2 * 1024 * 1024];
        client.observe(&payload);
        assert!(matches!(client.mode, ClientMode::Disabled));
        let summary = hub.finalize().unwrap();
        assert_eq!(summary.observer_failure_count, 1);
        assert!(summary.observer_failures[0].contains("malformed reply"));
    }

    #[test]
    fn connection_created_before_begin_cannot_write_the_round() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(21, 0, 1_024);
        let (mut old_client, mut old_server) = hub.connection();
        hub.begin(spec(1, payload.len())).unwrap();
        old_server.observe(b"220 old\r\n");
        old_client.observe(b"MAIL FROM:<x>\r\n");
        old_server.observe(b"250 mail\r\n");
        old_client.observe(b"DATA\r\n");
        old_server.observe(b"354 go\r\n");
        old_client.observe(&payload);
        old_client.observe(b".\r\n");
        old_server.observe(b"250 accepted\r\n");

        let (mut client, mut server) = hub.connection();
        server.observe(b"220 current\r\n");
        client.observe(b"MAIL FROM:<x>\r\n");
        server.observe(b"250 mail\r\n");
        client.observe(b"DATA\r\n");
        server.observe(b"354 go\r\n");
        client.observe(&payload);
        client.observe(b".\r\n");
        server.observe(b"250 accepted\r\n");
        let summary = hub.finalize().unwrap();
        assert!(summary.qualification, "{summary:#?}");
        assert_eq!(summary.verified, 1);
    }

    #[test]
    fn permanently_disabled_hub_cannot_arm_and_bypasses_connection_parsers() {
        let hub = ObserverHub::disabled(ObserverLimits::default()).unwrap();
        assert_eq!(
            hub.begin(spec(1, 1_024)).unwrap_err(),
            "this observer is permanently disabled"
        );
        let (_, client, server) = hub.scoped_connection();
        assert!(matches!(client.mode, ClientMode::Disabled));
        assert!(server.is_disabled());
    }

    #[test]
    fn finalized_process_cannot_begin_a_second_round() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        hub.begin(spec(1, 1_024)).unwrap();
        let frozen = hub.finalize().unwrap();
        hub.mark_failure("must not mutate frozen evidence");
        assert_eq!(
            hub.summary().unwrap().observer_failure_count,
            frozen.observer_failure_count
        );
        assert!(hub.begin(spec(1, 1_024)).is_err());
        assert!(hub.finalize().is_err());
    }

    #[test]
    fn starttls_switches_to_opaque_forwarding_and_disqualifies_observation() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        hub.begin(spec(1, 1_024)).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 tls\r\n");
        client.observe(b"STARTTLS\r\n");
        server.observe(b"220 ready\r\n");
        client.observe(b"\x16\x03\x01\x00\x10opaque-client");
        server.observe(b"\x16\x03\x03\x00\x10opaque-server");
        let summary = hub.finalize().unwrap();
        assert!(!summary.qualification);
        assert_eq!(summary.observer_failure_count, 1);
        assert!(summary.observer_failures[0].contains("STARTTLS"));
    }

    #[test]
    fn mixed_code_multiline_reply_disables_without_consuming_a_later_reply() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        hub.begin(spec(1, 1_024)).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 mixed\r\n");
        client.observe(b"EHLO local\r\nNOOP\r\n");
        server.observe(b"250-first\r\n550 mismatch\r\n250 noop\r\n");
        let summary = hub.finalize().unwrap();
        assert!(!summary.qualification);
        assert_eq!(summary.observer_failure_count, 1);
        assert!(summary.observer_failures[0].contains("changed its status code"));
    }

    #[test]
    fn early_bdat_rejection_is_matched_before_payload_completion() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(22, 0, 1_024);
        hub.begin(spec(1, payload.len())).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 early\r\n");
        client.observe(b"MAIL FROM:<x>\r\n");
        server.observe(b"250 mail\r\n");
        let command = format!("BDAT {} LAST\r\n", payload.len());
        client.observe(command.as_bytes());
        client.observe(&payload[..17]);
        server.observe(b"554 rejected early\r\n");
        client.observe(&payload[17..]);
        client.observe(b"MAIL FROM:<x>\r\n");
        server.observe(b"250 mail\r\n");
        client.observe(b"DATA\r\n");
        server.observe(b"354 go\r\n");
        client.observe(&payload);
        client.observe(b".\r\n");
        server.observe(b"250 accepted\r\n");
        let summary = hub.finalize().unwrap();
        assert!(summary.qualification, "{summary:#?}");
        assert_eq!(summary.verified, 1);
    }

    #[test]
    fn client_half_close_while_waiting_for_final_reply_is_legal() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        let payload = message(23, 0, 1_024);
        hub.begin(spec(1, payload.len())).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 half-close\r\n");
        client.observe(b"MAIL FROM:<x>\r\n");
        server.observe(b"250 mail\r\n");
        client.observe(b"DATA\r\n");
        server.observe(b"354 go\r\n");
        client.observe(&payload);
        client.observe(b".\r\n");
        client.observe_eof();
        drop(client);
        server.observe(b"250 accepted\r\n");
        server.observe_eof();
        drop(server);
        let summary = hub.finalize().unwrap();
        assert!(summary.qualification, "{summary:#?}");
        assert_eq!(summary.verified, 1);
    }

    #[test]
    fn connection_lifetime_rejects_a_pending_noop_reply() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        hub.begin(spec(1, 1_024)).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 pending\r\n");
        client.observe(b"NOOP\r\n");
        client.observe_eof();
        server.observe_eof();
        drop(client);
        drop(server);
        let summary = hub.finalize().unwrap();
        assert!(!summary.qualification);
        assert!(
            summary
                .observer_failures
                .iter()
                .any(|failure| failure.contains("pending SMTP command replies"))
        );
    }

    #[test]
    fn client_half_close_while_waiting_for_noop_reply_is_legal() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        hub.begin(spec(1, 1_024)).unwrap();
        let (mut client, mut server) = hub.connection();
        server.observe(b"220 pending\r\n");
        client.observe(b"NOOP\r\n");
        client.observe_eof();
        drop(client);
        server.observe(b"250 noop\r\n");
        server.observe_eof();
        drop(server);
        let summary = hub.finalize().unwrap();
        assert_eq!(summary.observer_failure_count, 0, "{summary:#?}");
    }

    #[test]
    fn connection_end_audits_data_bdat_capture_and_transaction_residuals() {
        let data_hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        data_hub.begin(spec(1, 1_024)).unwrap();
        let (mut data_client, mut data_server) = data_hub.connection();
        data_server.observe(b"220 data\r\n");
        data_client.observe(b"MAIL FROM:<x>\r\nDATA\r\n");
        data_server.observe(b"250 mail\r\n354 go\r\n");
        data_client.observe(b"partial body");
        data_client.observe_eof();
        assert!(
            data_hub
                .summary()
                .unwrap()
                .observer_failures
                .iter()
                .any(|failure| failure.contains("incomplete message body"))
        );

        let bdat_hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        bdat_hub.begin(spec(1, 1_024)).unwrap();
        let (mut bdat_client, mut bdat_server) = bdat_hub.connection();
        bdat_server.observe(b"220 bdat\r\n");
        bdat_client.observe(b"MAIL FROM:<x>\r\n");
        bdat_server.observe(b"250 mail\r\n");
        bdat_client.observe(b"BDAT 3\r\nabc");
        bdat_server.observe(b"250 chunk\r\n");
        bdat_client.observe_eof();
        assert!(
            bdat_hub
                .summary()
                .unwrap()
                .observer_failures
                .iter()
                .any(|failure| failure.contains("incomplete message body"))
        );

        let transaction_hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        transaction_hub.begin(spec(1, 1_024)).unwrap();
        let (mut transaction_client, mut transaction_server) = transaction_hub.connection();
        transaction_server.observe(b"220 transaction\r\n");
        transaction_client.observe(b"MAIL FROM:<x>\r\n");
        transaction_server.observe(b"250 mail\r\n");
        transaction_client.observe_eof();
        transaction_server.observe_eof();
        drop(transaction_client);
        drop(transaction_server);
        assert!(
            transaction_hub
                .summary()
                .unwrap()
                .observer_failures
                .iter()
                .any(|failure| failure.contains("unfinished SMTP transaction"))
        );
    }

    #[test]
    fn complete_crlf_lines_still_obey_the_fixed_limit() {
        let limits = ObserverLimits {
            max_line_bytes: 512,
            ..ObserverLimits::default()
        };
        let client_hub = ObserverHub::new(limits.clone()).unwrap();
        client_hub.begin(spec(1, 1_024)).unwrap();
        let (mut client, _) = client_hub.connection();
        let mut command = vec![b'x'; 511];
        command.extend_from_slice(b"\r\n");
        client.observe(&command);
        assert_eq!(
            client_hub.summary().unwrap().observer_failure_count,
            1,
            "a complete oversize command line must not bypass the limit"
        );

        let server_hub = ObserverHub::new(limits).unwrap();
        server_hub.begin(spec(1, 1_024)).unwrap();
        let (_, mut server) = server_hub.connection();
        let mut reply = b"220 ".to_vec();
        reply.resize(511, b'x');
        reply.extend_from_slice(b"\r\n");
        server.observe(&reply);
        assert_eq!(
            server_hub.summary().unwrap().observer_failure_count,
            1,
            "a complete oversize reply line must not bypass the limit"
        );
    }

    #[test]
    fn digest_sum_wraps_modulo_256_bits() {
        let mut target = [0xff; 32];
        let mut value = [0; 32];
        value[31] = 1;
        add_digest(&mut target, &value);
        assert_eq!(target, [0; 32]);
    }

    #[test]
    fn retained_failures_have_a_fixed_byte_ceiling() {
        let hub = ObserverHub::new(ObserverLimits::default()).unwrap();
        hub.begin(spec(1, 1_024)).unwrap();
        hub.mark_failure("failure-".repeat(1_024));
        let summary = hub.finalize().unwrap();
        assert_eq!(summary.observer_failures.len(), 1);
        assert!(summary.observer_failures[0].len() <= MAX_RETAINED_FAILURE_BYTES);
        assert!(summary.observer_failures[0].ends_with("...[truncated]"));
    }

    #[test]
    fn retained_evidence_limits_preserve_the_control_response_ceiling() {
        let too_many_samples = ObserverLimits {
            retained_samples: MAX_RETAINED_SAMPLES + 1,
            ..ObserverLimits::default()
        };
        assert!(too_many_samples.validate().is_err());
        let too_many_failures = ObserverLimits {
            retained_failures: MAX_RETAINED_FAILURES + 1,
            ..ObserverLimits::default()
        };
        assert!(too_many_failures.validate().is_err());
    }

    #[test]
    fn transaction_latency_histogram_has_exact_power_of_two_bounds() {
        let mut buckets = [0_u64; LATENCY_BUCKETS];
        let mut maximum = 0;
        record_latency(&mut buckets, &mut maximum, 1);
        record_latency(&mut buckets, &mut maximum, 2);
        let summary = latency_summary(&buckets, maximum);
        assert_eq!(summary.samples, 2);
        assert_eq!(summary.p50_ns_upper_bound, 1);
        assert_eq!(summary.p99_ns_upper_bound, 2);
        assert_eq!(summary.maximum_ns, 2);
    }
}
