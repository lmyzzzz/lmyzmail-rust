use crate::observer::{ClientObserver, ObserverHub, ServerObserver};
use serde::Serialize;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

const PUMP_BUFFER_BYTES: usize = 64 * 1024;
const MEMORY_PERMIT_QUANTUM_BYTES: usize = 64 * 1024;
const LAG_BUCKETS: usize = 64;
pub const DEFAULT_PROXY_MAX_CONNECTIONS: usize = 224;
pub const DEFAULT_PROXY_MEMORY_BUDGET_MIB: usize = 384;

struct ProxyMemoryPlan {
    accounted_connection_bytes: usize,
    connection_permits: usize,
    budget_permits: usize,
    accounted_observer_reserve_bytes: usize,
    accounted_control_reserve_bytes: usize,
    required_memory_budget_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub backend: SocketAddr,
    pub max_connections: usize,
    pub memory_budget_bytes: usize,
    pub shutdown_grace: Duration,
}

impl ProxyConfig {
    fn memory_requirement(
        max_connections: usize,
        observer: &ObserverHub,
    ) -> Result<ProxyMemoryPlan, String> {
        if max_connections == 0 || max_connections > 65_536 {
            return Err("max_connections must be between 1 and 65536".into());
        }
        let connection_bytes = observer
            .limits()
            .accounted_connection_bytes(PUMP_BUFFER_BYTES)?;
        let connection_permits = connection_bytes.div_ceil(MEMORY_PERMIT_QUANTUM_BYTES);
        let observer_reserve_bytes = observer.limits().accounted_round_reserve_bytes()?;
        let observer_reserve_permits = observer_reserve_bytes.div_ceil(MEMORY_PERMIT_QUANTUM_BYTES);
        let control_reserve_bytes = crate::control::accounted_control_reserve_bytes()?;
        let control_reserve_permits = control_reserve_bytes.div_ceil(MEMORY_PERMIT_QUANTUM_BYTES);
        if connection_permits == 0 || connection_permits > u32::MAX as usize {
            return Err("per-connection memory weight is outside semaphore bounds".into());
        }
        let required_permits = max_connections
            .checked_mul(connection_permits)
            .and_then(|value| value.checked_add(observer_reserve_permits))
            .and_then(|value| value.checked_add(control_reserve_permits))
            .ok_or_else(|| "max_connections memory accounting overflowed".to_owned())?;
        if required_permits > Semaphore::MAX_PERMITS {
            return Err("required proxy memory is outside semaphore bounds".into());
        }
        let accounted_connection_bytes = connection_permits
            .checked_mul(MEMORY_PERMIT_QUANTUM_BYTES)
            .ok_or_else(|| "per-connection permit byte accounting overflowed".to_owned())?;
        let accounted_observer_reserve_bytes = observer_reserve_permits
            .checked_mul(MEMORY_PERMIT_QUANTUM_BYTES)
            .ok_or_else(|| "observer reserve permit byte accounting overflowed".to_owned())?;
        let accounted_control_reserve_bytes = control_reserve_permits
            .checked_mul(MEMORY_PERMIT_QUANTUM_BYTES)
            .ok_or_else(|| "control reserve permit byte accounting overflowed".to_owned())?;
        let required_memory_budget_bytes = required_permits
            .checked_mul(MEMORY_PERMIT_QUANTUM_BYTES)
            .ok_or_else(|| "required proxy memory byte accounting overflowed".to_owned())?;
        Ok(ProxyMemoryPlan {
            accounted_connection_bytes,
            connection_permits,
            budget_permits: 0,
            accounted_observer_reserve_bytes,
            accounted_control_reserve_bytes,
            required_memory_budget_bytes,
        })
    }

    pub fn required_memory_budget_bytes(
        max_connections: usize,
        observer: &ObserverHub,
    ) -> Result<usize, String> {
        Self::memory_requirement(max_connections, observer)
            .map(|plan| plan.required_memory_budget_bytes)
    }

    fn memory_plan(&self, observer: &ObserverHub) -> Result<ProxyMemoryPlan, String> {
        if self.shutdown_grace.is_zero() || self.shutdown_grace > Duration::from_secs(300) {
            return Err("shutdown_grace must be between 1 ns and 300 seconds".into());
        }
        let mut plan = Self::memory_requirement(self.max_connections, observer)?;
        plan.budget_permits = self.memory_budget_bytes / MEMORY_PERMIT_QUANTUM_BYTES;
        if plan.budget_permits == 0 || plan.budget_permits > Semaphore::MAX_PERMITS {
            return Err("proxy memory budget is outside semaphore bounds".into());
        }
        let required_permits = plan.required_memory_budget_bytes / MEMORY_PERMIT_QUANTUM_BYTES;
        if required_permits > plan.budget_permits {
            return Err(format!(
                "max_connections requires {required_permits} memory permits but budget provides {}",
                plan.budget_permits
            ));
        }
        Ok(plan)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ForwardingStallSummary {
    pub samples: u64,
    pub p50_ns_upper_bound: u64,
    pub p95_ns_upper_bound: u64,
    pub p99_ns_upper_bound: u64,
    pub maximum_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProxySnapshot {
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub failed_connections: u64,
    pub active_connections: usize,
    pub peak_connections: usize,
    pub client_to_backend_bytes: u64,
    pub backend_to_client_bytes: u64,
    pub client_to_backend_forwarding_stall: ForwardingStallSummary,
    pub backend_to_client_forwarding_stall: ForwardingStallSummary,
    pub pump_buffer_bytes: usize,
    pub configured_max_connections: usize,
    pub backend_reply_block_limit_bytes: usize,
    pub accounted_backend_reply_buffer_bytes: usize,
    pub memory_permit_quantum_bytes: usize,
    pub memory_budget_bytes: usize,
    pub usable_memory_budget_bytes: usize,
    pub required_memory_budget_bytes: usize,
    pub memory_budget_headroom_bytes: usize,
    pub accounted_connection_bytes: usize,
    pub active_accounted_connection_bytes: usize,
    pub peak_accounted_connection_bytes: usize,
    pub observer_round_reserve_bytes: usize,
    pub control_runtime_reserve_bytes: usize,
    pub active_total_accounted_bytes: usize,
    pub peak_total_accounted_bytes: usize,
    pub shutdown_grace_ns: u64,
    pub shutdown_wait_ns: u64,
    pub shutdown_grace_exceeded: bool,
    pub shutdown_forced_connections: usize,
}

pub struct ProxyServer {
    listener: TcpListener,
    backend: SocketAddr,
    max_connections: usize,
    connection_memory_permits: u32,
    memory_budget_permits: usize,
    shutdown_grace: Duration,
    observer: ObserverHub,
    telemetry: Arc<ProxyTelemetry>,
}

impl ProxyServer {
    pub async fn bind(
        config: ProxyConfig,
        observer: ObserverHub,
        telemetry: Arc<ProxyTelemetry>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let memory_plan = config.memory_plan(&observer)?;
        telemetry.configure_memory(&config, &memory_plan, &observer)?;
        let listener = bind_tcp_listener(config.listen, config.max_connections)?;
        Ok(Self {
            listener,
            backend: config.backend,
            max_connections: config.max_connections,
            connection_memory_permits: memory_plan
                .connection_permits
                .try_into()
                .map_err(|_| "per-connection memory permit conversion overflowed")?,
            memory_budget_permits: memory_plan.budget_permits,
            shutdown_grace: config.shutdown_grace,
            observer,
            telemetry,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        let permits = Arc::new(Semaphore::new(self.max_connections));
        let memory = Arc::new(Semaphore::new(self.memory_budget_permits));
        let mut connections = JoinSet::new();
        let mut accept_error = None;
        loop {
            if *shutdown.borrow_and_update() {
                break;
            }
            let permit = tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                    continue;
                }
                permit = permits.clone().acquire_owned() => {
                    permit.map_err(|_| io::Error::other("proxy connection semaphore closed"))?
                }
            };
            let memory_permit = tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    drop(permit);
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                    continue;
                }
                permit = memory.clone().acquire_many_owned(self.connection_memory_permits) => {
                    permit.map_err(|_| io::Error::other("proxy memory semaphore closed"))?
                }
            };
            let accepted = tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    drop(permit);
                    drop(memory_permit);
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                    continue;
                }
                accepted = self.listener.accept() => accepted,
            };
            let (client, _) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    drop(permit);
                    drop(memory_permit);
                    accept_error = Some(error);
                    break;
                }
            };
            self.telemetry
                .accepted_connections
                .fetch_add(1, Ordering::Relaxed);
            let active = self
                .telemetry
                .active_connections
                .fetch_add(1, Ordering::AcqRel)
                + 1;
            update_max(&self.telemetry.peak_connections, active);
            let backend = self.backend;
            let (epoch, client_observer, server_observer) = self.observer.scoped_connection();
            let observer = self.observer.clone();
            let telemetry = self.telemetry.clone();
            let active_guard = ActiveConnectionGuard::new(telemetry.clone());
            connections.spawn(async move {
                let _permit = permit;
                let _memory_permit = memory_permit;
                let _active = active_guard;
                if let Err(error) = handle_connection(
                    client,
                    backend,
                    client_observer,
                    server_observer,
                    telemetry.clone(),
                )
                .await
                {
                    telemetry.failed_connections.fetch_add(1, Ordering::Relaxed);
                    observer.mark_failure_for_epoch(
                        epoch,
                        format!("transparent proxy connection failed: {error}"),
                    );
                } else {
                    telemetry
                        .completed_connections
                        .fetch_add(1, Ordering::Relaxed);
                }
            });
            while let Some(result) = connections.try_join_next() {
                if let Err(error) = result {
                    self.telemetry
                        .failed_connections
                        .fetch_add(1, Ordering::Relaxed);
                    self.observer
                        .mark_failure(format!("transparent proxy task failed: {error}"));
                }
            }
        }
        drop(self.listener);
        let shutdown_started = Instant::now();
        let deadline = tokio::time::Instant::now() + self.shutdown_grace;
        loop {
            match tokio::time::timeout_at(deadline, connections.join_next()).await {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(error))) => {
                    self.telemetry
                        .failed_connections
                        .fetch_add(1, Ordering::Relaxed);
                    self.observer.mark_failure(format!(
                        "transparent proxy task failed during shutdown: {error}"
                    ));
                }
                Ok(None) => {
                    self.telemetry.shutdown_wait_ns.store(
                        duration_nanos(shutdown_started.elapsed()),
                        Ordering::Release,
                    );
                    break;
                }
                Err(_) => {
                    let residual_connections =
                        self.telemetry.active_connections.load(Ordering::Acquire);
                    self.telemetry.shutdown_wait_ns.store(
                        duration_nanos(shutdown_started.elapsed()),
                        Ordering::Release,
                    );
                    self.telemetry
                        .shutdown_grace_exceeded
                        .store(true, Ordering::Release);
                    self.telemetry
                        .shutdown_forced_connections
                        .store(residual_connections, Ordering::Release);
                    if !self.observer.round_complete_without_failures() {
                        self.observer.mark_failure(format!(
                            "transparent proxy connections exceeded {:?} shutdown grace",
                            self.shutdown_grace
                        ));
                    }
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                    break;
                }
            }
        }
        if let Some(error) = accept_error {
            self.observer
                .mark_failure(format!("transparent proxy accept failed: {error}"));
            Err(error)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn bind_tcp_listener(address: SocketAddr, backlog: usize) -> io::Result<TcpListener> {
    let backlog = u32::try_from(backlog)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "listener backlog overflowed"))?;
    if backlog == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "listener backlog must be positive",
        ));
    }
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(backlog)
}

fn duration_nanos(duration: Duration) -> u64 {
    duration.as_nanos().try_into().unwrap_or(u64::MAX)
}

async fn handle_connection(
    client: TcpStream,
    backend: SocketAddr,
    client_observer: ClientObserver,
    server_observer: ServerObserver,
    telemetry: Arc<ProxyTelemetry>,
) -> io::Result<()> {
    let server = TcpStream::connect(backend).await?;
    let (client_reader, client_writer) = client.into_split();
    let (server_reader, server_writer) = server.into_split();
    let client_to_backend = pump_client_to_backend(
        client_reader,
        server_writer,
        client_observer,
        telemetry.clone(),
    );
    let backend_to_client =
        pump_backend_to_client(server_reader, client_writer, server_observer, telemetry);
    tokio::pin!(client_to_backend);
    tokio::pin!(backend_to_client);
    tokio::select! {
        client_result = &mut client_to_backend => {
            client_result?;
            backend_to_client.await
        }
        backend_result = &mut backend_to_client => {
            backend_result?;
            client_to_backend.await
        }
    }
}

async fn pump_client_to_backend<R, W>(
    mut reader: R,
    mut writer: W,
    mut observer: ClientObserver,
    telemetry: Arc<ProxyTelemetry>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = Box::new([0_u8; PUMP_BUFFER_BYTES]);
    loop {
        let bytes = reader.read(&mut buffer[..]).await?;
        if bytes == 0 {
            observer.observe_eof();
            writer.shutdown().await?;
            return Ok(());
        }
        let started = Instant::now();
        observer.observe(&buffer[..bytes]);
        writer.write_all(&buffer[..bytes]).await?;
        telemetry
            .client_to_backend_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        telemetry.client_to_backend_lag.record(started.elapsed());
    }
}

async fn pump_backend_to_client<R, W>(
    mut reader: R,
    mut writer: W,
    mut observer: ServerObserver,
    telemetry: Arc<ProxyTelemetry>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = Box::new([0_u8; PUMP_BUFFER_BYTES]);
    let maximum_reply_block_bytes = observer.maximum_reply_block_bytes();
    let mut pending = Vec::with_capacity(maximum_reply_block_bytes);
    let mut opaque = observer.is_disabled();
    loop {
        let bytes = reader.read(&mut buffer[..]).await?;
        if bytes == 0 {
            if !opaque && !pending.is_empty() {
                observer.observe_pending(&pending);
            }
            observer.observe_eof();
            writer.shutdown().await?;
            return Ok(());
        }
        let started = Instant::now();
        if opaque {
            writer.write_all(&buffer[..bytes]).await?;
            telemetry
                .backend_to_client_bytes
                .fetch_add(bytes as u64, Ordering::Relaxed);
            telemetry.backend_to_client_lag.record(started.elapsed());
            continue;
        }
        let mut input = &buffer[..bytes];
        while !input.is_empty() && !opaque {
            let available = maximum_reply_block_bytes.saturating_sub(pending.len());
            if available == 0 {
                return Err(io::Error::other(
                    "SMTP backend multiline reply exceeded the proxy forwarding block limit",
                ));
            }
            let take = available.min(input.len());
            pending.extend_from_slice(&input[..take]);
            input = &input[take..];

            let mut consumed = 0_usize;
            let mut persistence_gate = None;
            while let Some(reply_bytes) = complete_smtp_reply_len(
                &pending[consumed..],
                observer.maximum_reply_line_bytes(),
                maximum_reply_block_bytes,
            )? {
                let end = consumed + reply_bytes;
                observer.observe_pending(&pending[consumed..end]);
                consumed = end;
                if observer.is_disabled() {
                    break;
                }
                persistence_gate = observer
                    .pending_persistence_gate_id()
                    .map_err(io::Error::other)?;
                if persistence_gate.is_some() {
                    break;
                }
            }
            if consumed > 0 {
                if let Some(gate_id) = persistence_gate {
                    observer
                        .prepare_pending_persistence_gate(gate_id)
                        .await
                        .map_err(io::Error::other)?;
                }
                writer.write_all(&pending[..consumed]).await?;
                writer.flush().await?;
                observer.acknowledge_forwarded().map_err(io::Error::other)?;
                telemetry
                    .backend_to_client_bytes
                    .fetch_add(consumed as u64, Ordering::Relaxed);
            }
            if observer.is_disabled() {
                if consumed < pending.len() {
                    writer.write_all(&pending[consumed..]).await?;
                    telemetry
                        .backend_to_client_bytes
                        .fetch_add((pending.len() - consumed) as u64, Ordering::Relaxed);
                }
                if !input.is_empty() {
                    writer.write_all(input).await?;
                    telemetry
                        .backend_to_client_bytes
                        .fetch_add(input.len() as u64, Ordering::Relaxed);
                }
                pending.clear();
                opaque = true;
                break;
            }
            if !opaque && consumed > 0 {
                pending.drain(..consumed);
            }
        }
        telemetry.backend_to_client_lag.record(started.elapsed());
    }
}

fn complete_smtp_reply_len(
    value: &[u8],
    maximum_line_bytes: usize,
    maximum_block_bytes: usize,
) -> io::Result<Option<usize>> {
    let Some(first_line_end) = value.windows(2).position(|window| window == b"\r\n") else {
        if value.len() > maximum_block_bytes {
            return Err(io::Error::other(
                "SMTP backend reply exceeded the proxy forwarding block limit",
            ));
        }
        if value.len() > maximum_line_bytes {
            return Err(io::Error::other(
                "SMTP backend reply exceeded the proxy forwarding line limit",
            ));
        }
        return Ok(None);
    };
    let first_line_bytes = first_line_end + 2;
    if first_line_bytes > maximum_block_bytes {
        return Err(io::Error::other(
            "SMTP backend reply exceeded the proxy forwarding block limit",
        ));
    }
    if first_line_bytes > maximum_line_bytes {
        return Err(io::Error::other(
            "SMTP backend reply exceeded the proxy forwarding line limit",
        ));
    }
    if first_line_bytes < 5 || !value[..3].iter().all(u8::is_ascii_digit) {
        return Ok(Some(first_line_bytes));
    }
    match value[3] {
        b' ' => Ok(Some(first_line_bytes)),
        b'-' => {
            let code = &value[..3];
            let mut offset = first_line_bytes;
            loop {
                let Some(relative_end) = value[offset..]
                    .windows(2)
                    .position(|window| window == b"\r\n")
                else {
                    if value.len().saturating_sub(offset) > maximum_line_bytes {
                        return Err(io::Error::other(
                            "SMTP backend multiline reply exceeded the proxy forwarding line limit",
                        ));
                    }
                    return Ok(None);
                };
                let line_bytes = relative_end + 2;
                if line_bytes > maximum_line_bytes {
                    return Err(io::Error::other(
                        "SMTP backend multiline reply exceeded the proxy forwarding line limit",
                    ));
                }
                let end = offset + line_bytes;
                if end > maximum_block_bytes {
                    return Err(io::Error::other(
                        "SMTP backend multiline reply exceeded the proxy forwarding block limit",
                    ));
                }
                if line_bytes < 5 || &value[offset..offset + 3] != code {
                    return Ok(Some(end));
                }
                match value[offset + 3] {
                    b' ' => return Ok(Some(end)),
                    b'-' => offset = end,
                    _ => return Ok(Some(end)),
                }
            }
        }
        _ => Ok(Some(first_line_bytes)),
    }
}

struct ActiveConnectionGuard(Arc<ProxyTelemetry>);

impl ActiveConnectionGuard {
    fn new(telemetry: Arc<ProxyTelemetry>) -> Self {
        let accounted = telemetry.accounted_connection_bytes.load(Ordering::Acquire);
        let active = telemetry
            .active_accounted_connection_bytes
            .fetch_add(accounted, Ordering::AcqRel)
            .saturating_add(accounted);
        update_max(&telemetry.peak_accounted_connection_bytes, active);
        Self(telemetry)
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::AcqRel);
        let accounted = self.0.accounted_connection_bytes.load(Ordering::Acquire);
        self.0
            .active_accounted_connection_bytes
            .fetch_sub(accounted, Ordering::AcqRel);
    }
}

pub struct ProxyTelemetry {
    accepted_connections: AtomicU64,
    completed_connections: AtomicU64,
    failed_connections: AtomicU64,
    active_connections: AtomicUsize,
    peak_connections: AtomicUsize,
    client_to_backend_bytes: AtomicU64,
    backend_to_client_bytes: AtomicU64,
    client_to_backend_lag: AtomicLagHistogram,
    backend_to_client_lag: AtomicLagHistogram,
    memory_budget_bytes: AtomicUsize,
    configured_max_connections: AtomicUsize,
    required_memory_budget_bytes: AtomicUsize,
    accounted_connection_bytes: AtomicUsize,
    backend_reply_block_limit_bytes: AtomicUsize,
    accounted_backend_reply_buffer_bytes: AtomicUsize,
    active_accounted_connection_bytes: AtomicUsize,
    peak_accounted_connection_bytes: AtomicUsize,
    observer_round_reserve_bytes: AtomicUsize,
    control_runtime_reserve_bytes: AtomicUsize,
    shutdown_grace_ns: AtomicU64,
    shutdown_wait_ns: AtomicU64,
    shutdown_grace_exceeded: AtomicBool,
    shutdown_forced_connections: AtomicUsize,
}

impl ProxyTelemetry {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self {
            accepted_connections: AtomicU64::new(0),
            completed_connections: AtomicU64::new(0),
            failed_connections: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            peak_connections: AtomicUsize::new(0),
            client_to_backend_bytes: AtomicU64::new(0),
            backend_to_client_bytes: AtomicU64::new(0),
            client_to_backend_lag: AtomicLagHistogram::new(),
            backend_to_client_lag: AtomicLagHistogram::new(),
            memory_budget_bytes: AtomicUsize::new(0),
            configured_max_connections: AtomicUsize::new(0),
            required_memory_budget_bytes: AtomicUsize::new(0),
            accounted_connection_bytes: AtomicUsize::new(0),
            backend_reply_block_limit_bytes: AtomicUsize::new(0),
            accounted_backend_reply_buffer_bytes: AtomicUsize::new(0),
            active_accounted_connection_bytes: AtomicUsize::new(0),
            peak_accounted_connection_bytes: AtomicUsize::new(0),
            observer_round_reserve_bytes: AtomicUsize::new(0),
            control_runtime_reserve_bytes: AtomicUsize::new(0),
            shutdown_grace_ns: AtomicU64::new(0),
            shutdown_wait_ns: AtomicU64::new(0),
            shutdown_grace_exceeded: AtomicBool::new(false),
            shutdown_forced_connections: AtomicUsize::new(0),
        })
    }

    fn configure_memory(
        &self,
        config: &ProxyConfig,
        memory_plan: &ProxyMemoryPlan,
        observer: &ObserverHub,
    ) -> Result<(), String> {
        let max_connections = config.max_connections;
        let budget_bytes = config.memory_budget_bytes;
        let required_memory_budget_bytes = memory_plan.required_memory_budget_bytes;
        let connection_bytes = memory_plan.accounted_connection_bytes;
        let backend_reply_block_limit_bytes =
            observer.limits().maximum_backend_reply_block_bytes()?;
        let accounted_backend_reply_buffer_bytes =
            observer.limits().accounted_backend_reply_buffer_bytes()?;
        let observer_reserve_bytes = memory_plan.accounted_observer_reserve_bytes;
        let control_reserve_bytes = memory_plan.accounted_control_reserve_bytes;
        self.shutdown_grace_ns.store(
            config
                .shutdown_grace
                .as_nanos()
                .try_into()
                .unwrap_or(u64::MAX),
            Ordering::Release,
        );
        self.configured_max_connections
            .compare_exchange(0, max_connections, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "proxy telemetry maximum connections was already configured".to_owned())?;
        self.memory_budget_bytes
            .compare_exchange(0, budget_bytes, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                self.configured_max_connections.store(0, Ordering::Release);
                "proxy telemetry memory budget was already configured".to_owned()
            })?;
        if self
            .required_memory_budget_bytes
            .compare_exchange(
                0,
                required_memory_budget_bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.configured_max_connections.store(0, Ordering::Release);
            self.memory_budget_bytes.store(0, Ordering::Release);
            return Err("proxy telemetry required memory was already configured".into());
        }
        if self
            .accounted_connection_bytes
            .compare_exchange(0, connection_bytes, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.configured_max_connections.store(0, Ordering::Release);
            self.memory_budget_bytes.store(0, Ordering::Release);
            self.required_memory_budget_bytes
                .store(0, Ordering::Release);
            return Err("proxy telemetry connection weight was already configured".into());
        }
        if self
            .backend_reply_block_limit_bytes
            .compare_exchange(
                0,
                backend_reply_block_limit_bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.configured_max_connections.store(0, Ordering::Release);
            self.memory_budget_bytes.store(0, Ordering::Release);
            self.required_memory_budget_bytes
                .store(0, Ordering::Release);
            self.accounted_connection_bytes.store(0, Ordering::Release);
            return Err("proxy telemetry reply block limit was already configured".into());
        }
        if self
            .accounted_backend_reply_buffer_bytes
            .compare_exchange(
                0,
                accounted_backend_reply_buffer_bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.configured_max_connections.store(0, Ordering::Release);
            self.memory_budget_bytes.store(0, Ordering::Release);
            self.required_memory_budget_bytes
                .store(0, Ordering::Release);
            self.accounted_connection_bytes.store(0, Ordering::Release);
            self.backend_reply_block_limit_bytes
                .store(0, Ordering::Release);
            return Err("proxy telemetry reply buffer weight was already configured".into());
        }
        if self
            .observer_round_reserve_bytes
            .compare_exchange(
                0,
                observer_reserve_bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.configured_max_connections.store(0, Ordering::Release);
            self.memory_budget_bytes.store(0, Ordering::Release);
            self.required_memory_budget_bytes
                .store(0, Ordering::Release);
            self.accounted_connection_bytes.store(0, Ordering::Release);
            self.backend_reply_block_limit_bytes
                .store(0, Ordering::Release);
            self.accounted_backend_reply_buffer_bytes
                .store(0, Ordering::Release);
            return Err("proxy telemetry observer reserve was already configured".into());
        }
        if self
            .control_runtime_reserve_bytes
            .compare_exchange(
                0,
                control_reserve_bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.configured_max_connections.store(0, Ordering::Release);
            self.memory_budget_bytes.store(0, Ordering::Release);
            self.required_memory_budget_bytes
                .store(0, Ordering::Release);
            self.accounted_connection_bytes.store(0, Ordering::Release);
            self.backend_reply_block_limit_bytes
                .store(0, Ordering::Release);
            self.accounted_backend_reply_buffer_bytes
                .store(0, Ordering::Release);
            self.observer_round_reserve_bytes
                .store(0, Ordering::Release);
            return Err("proxy telemetry control reserve was already configured".into());
        }
        Ok(())
    }

    pub fn snapshot(&self) -> ProxySnapshot {
        let observer_round_reserve_bytes =
            self.observer_round_reserve_bytes.load(Ordering::Acquire);
        let control_runtime_reserve_bytes =
            self.control_runtime_reserve_bytes.load(Ordering::Acquire);
        let active_accounted_connection_bytes = self
            .active_accounted_connection_bytes
            .load(Ordering::Acquire);
        let peak_accounted_connection_bytes =
            self.peak_accounted_connection_bytes.load(Ordering::Acquire);
        let memory_budget_bytes = self.memory_budget_bytes.load(Ordering::Acquire);
        let usable_memory_budget_bytes =
            memory_budget_bytes / MEMORY_PERMIT_QUANTUM_BYTES * MEMORY_PERMIT_QUANTUM_BYTES;
        let required_memory_budget_bytes =
            self.required_memory_budget_bytes.load(Ordering::Acquire);
        ProxySnapshot {
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            completed_connections: self.completed_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            peak_connections: self.peak_connections.load(Ordering::Relaxed),
            client_to_backend_bytes: self.client_to_backend_bytes.load(Ordering::Relaxed),
            backend_to_client_bytes: self.backend_to_client_bytes.load(Ordering::Relaxed),
            client_to_backend_forwarding_stall: self.client_to_backend_lag.summary(),
            backend_to_client_forwarding_stall: self.backend_to_client_lag.summary(),
            pump_buffer_bytes: PUMP_BUFFER_BYTES,
            configured_max_connections: self.configured_max_connections.load(Ordering::Acquire),
            backend_reply_block_limit_bytes: self
                .backend_reply_block_limit_bytes
                .load(Ordering::Acquire),
            accounted_backend_reply_buffer_bytes: self
                .accounted_backend_reply_buffer_bytes
                .load(Ordering::Acquire),
            memory_permit_quantum_bytes: MEMORY_PERMIT_QUANTUM_BYTES,
            memory_budget_bytes,
            usable_memory_budget_bytes,
            required_memory_budget_bytes,
            memory_budget_headroom_bytes: usable_memory_budget_bytes
                .saturating_sub(required_memory_budget_bytes),
            accounted_connection_bytes: self.accounted_connection_bytes.load(Ordering::Acquire),
            active_accounted_connection_bytes,
            peak_accounted_connection_bytes,
            observer_round_reserve_bytes,
            control_runtime_reserve_bytes,
            active_total_accounted_bytes: observer_round_reserve_bytes
                .saturating_add(control_runtime_reserve_bytes)
                .saturating_add(active_accounted_connection_bytes),
            peak_total_accounted_bytes: observer_round_reserve_bytes
                .saturating_add(control_runtime_reserve_bytes)
                .saturating_add(peak_accounted_connection_bytes),
            shutdown_grace_ns: self.shutdown_grace_ns.load(Ordering::Acquire),
            shutdown_wait_ns: self.shutdown_wait_ns.load(Ordering::Acquire),
            shutdown_grace_exceeded: self.shutdown_grace_exceeded.load(Ordering::Acquire),
            shutdown_forced_connections: self.shutdown_forced_connections.load(Ordering::Acquire),
        }
    }
}

struct AtomicLagHistogram {
    buckets: [AtomicU64; LAG_BUCKETS],
    maximum_ns: AtomicU64,
}

impl AtomicLagHistogram {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            maximum_ns: AtomicU64::new(0),
        }
    }

    fn record(&self, duration: Duration) {
        let nanos: u64 = duration.as_nanos().try_into().unwrap_or(u64::MAX);
        let bucket = if nanos <= 1 {
            0
        } else {
            (u64::BITS - (nanos - 1).leading_zeros()) as usize
        }
        .min(LAG_BUCKETS - 1);
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        update_max_u64(&self.maximum_ns, nanos);
    }

    fn summary(&self) -> ForwardingStallSummary {
        let counts: Vec<u64> = self
            .buckets
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
            .collect();
        let samples = counts.iter().sum();
        ForwardingStallSummary {
            samples,
            p50_ns_upper_bound: percentile_upper_bound(&counts, samples, 50, 100),
            p95_ns_upper_bound: percentile_upper_bound(&counts, samples, 95, 100),
            p99_ns_upper_bound: percentile_upper_bound(&counts, samples, 99, 100),
            maximum_ns: self.maximum_ns.load(Ordering::Relaxed),
        }
    }
}

fn percentile_upper_bound(counts: &[u64], samples: u64, numerator: u64, denominator: u64) -> u64 {
    if samples == 0 {
        return 0;
    }
    let rank = samples
        .saturating_mul(numerator)
        .div_ceil(denominator)
        .max(1);
    let mut cumulative = 0_u64;
    for (index, count) in counts.iter().enumerate() {
        cumulative = cumulative.saturating_add(*count);
        if cumulative >= rank {
            return if index == 0 {
                1
            } else if index == LAG_BUCKETS - 1 {
                u64::MAX
            } else {
                1_u64 << index
            };
        }
    }
    u64::MAX
}

fn update_max(value: &AtomicUsize, candidate: usize) {
    let mut current = value.load(Ordering::Relaxed);
    while candidate > current {
        match value.compare_exchange_weak(current, candidate, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

fn update_max_u64(value: &AtomicU64, candidate: u64) {
    let mut current = value.load(Ordering::Relaxed);
    while candidate > current {
        match value.compare_exchange_weak(current, candidate, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_and_multiline_replies_are_held_as_complete_blocks() {
        assert_eq!(
            complete_smtp_reply_len(b"250 frag", 64 * 1024, 128 * 1024).unwrap(),
            None
        );
        assert_eq!(
            complete_smtp_reply_len(b"250 fragmented\r\n", 64 * 1024, 128 * 1024).unwrap(),
            Some(b"250 fragmented\r\n".len())
        );
        let multiline = b"250-first capability\r\n250-second capability\r\n250 complete\r\n";
        assert_eq!(
            complete_smtp_reply_len(multiline, 64 * 1024, 128 * 1024).unwrap(),
            Some(multiline.len())
        );
    }

    #[test]
    fn coalesced_reply_blocks_are_split_at_protocol_boundaries() {
        let multiline = b"250-first capability\r\n250 complete\r\n";
        let prior = b"250 ordinal-n-minus-one\r\n";
        let gated = b"250 ordinal-n\r\n";
        let mut read = Vec::new();
        read.extend_from_slice(multiline);
        read.extend_from_slice(prior);
        read.extend_from_slice(gated);

        let first = complete_smtp_reply_len(&read, 64 * 1024, 128 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(&read[..first], multiline);
        let second = complete_smtp_reply_len(&read[first..], 64 * 1024, 128 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(&read[first..first + second], prior);
        let third = complete_smtp_reply_len(&read[first + second..], 64 * 1024, 128 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(&read[first + second..first + second + third], gated);
    }

    #[test]
    fn many_short_multiline_continuations_are_bounded_by_total_block_bytes() {
        let limits = crate::observer::ObserverLimits::default();
        let maximum_block_bytes = limits.maximum_backend_reply_block_bytes().unwrap();
        assert_eq!(maximum_block_bytes, 128 * 1024);
        assert_eq!(maximum_block_bytes % 8, 0);

        let mut exact = Vec::with_capacity(maximum_block_bytes);
        for _ in 0..(maximum_block_bytes / 8 - 1) {
            exact.extend_from_slice(b"250-xx\r\n");
        }
        exact.extend_from_slice(b"250 xx\r\n");
        assert_eq!(exact.len(), maximum_block_bytes);
        assert_eq!(
            complete_smtp_reply_len(&exact, limits.max_line_bytes, maximum_block_bytes).unwrap(),
            Some(maximum_block_bytes)
        );

        let mut over = exact[..maximum_block_bytes - 8].to_vec();
        over.extend_from_slice(b"250-xx\r\n250 xx\r\n");
        assert_eq!(over.len(), maximum_block_bytes + 8);
        assert!(
            complete_smtp_reply_len(&over, limits.max_line_bytes, maximum_block_bytes).is_err()
        );
    }

    #[test]
    fn connection_memory_accounting_includes_the_backend_reply_buffer() {
        let limits = crate::observer::ObserverLimits::default();
        let reply_buffer = limits.accounted_backend_reply_buffer_bytes().unwrap();
        assert_eq!(reply_buffer, 128 * 1024);
        let total = limits
            .accounted_connection_bytes(PUMP_BUFFER_BYTES)
            .unwrap();
        assert!(total >= reply_buffer + 2 * PUMP_BUFFER_BYTES);
    }

    #[test]
    fn lag_histogram_is_fixed_and_reports_upper_bounds() {
        let histogram = AtomicLagHistogram::new();
        histogram.record(Duration::from_nanos(1));
        histogram.record(Duration::from_nanos(10));
        histogram.record(Duration::from_nanos(1_000));
        let summary = histogram.summary();
        assert_eq!(summary.samples, 3);
        assert!(summary.p50_ns_upper_bound >= 10);
        assert!(summary.p99_ns_upper_bound >= 1_000);
        assert_eq!(summary.maximum_ns, 1_000);
    }

    #[test]
    fn lag_histogram_keeps_exact_power_of_two_upper_bounds() {
        let histogram = AtomicLagHistogram::new();
        histogram.record(Duration::from_nanos(1));
        histogram.record(Duration::from_nanos(2));
        let summary = histogram.summary();
        assert_eq!(summary.p50_ns_upper_bound, 1);
        assert_eq!(summary.p99_ns_upper_bound, 2);
    }

    #[test]
    fn global_memory_budget_rejects_a_max_connection_overcommit() {
        let observer = ObserverHub::new(crate::observer::ObserverLimits::default()).unwrap();
        let default_required =
            ProxyConfig::required_memory_budget_bytes(DEFAULT_PROXY_MAX_CONNECTIONS, &observer)
                .unwrap();
        assert!(default_required > 256 * 1024 * 1024);
        assert!(default_required <= DEFAULT_PROXY_MEMORY_BUDGET_MIB * 1024 * 1024);
        let mut default_config = ProxyConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            backend: SocketAddr::from(([127, 0, 0, 1], 25)),
            max_connections: DEFAULT_PROXY_MAX_CONNECTIONS,
            memory_budget_bytes: DEFAULT_PROXY_MEMORY_BUDGET_MIB * 1024 * 1024,
            shutdown_grace: Duration::from_secs(30),
        };
        assert!(default_config.memory_plan(&observer).is_ok());
        default_config.memory_budget_bytes = default_required;
        assert!(default_config.memory_plan(&observer).is_ok());
        default_config.memory_budget_bytes = default_required - 1;
        assert!(default_config.memory_plan(&observer).is_err());
        default_config.memory_budget_bytes = default_required;
        default_config.max_connections = usize::MAX;
        assert!(default_config.memory_plan(&observer).is_err());

        let formal_required = ProxyConfig::required_memory_budget_bytes(1_500, &observer).unwrap();
        assert!(formal_required <= 2 * 1024 * 1024 * 1024);
    }
}
