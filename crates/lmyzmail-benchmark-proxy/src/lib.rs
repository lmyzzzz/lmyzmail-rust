pub mod attestation;
pub mod calibration;
pub mod control;
pub mod observer;
pub mod proxy;

pub use attestation::{
    HEADROOM_NOFILE_RESERVE, HeadroomAttestation, HeadroomAttestationConfig, HeadroomEnvironment,
    PublishedAttestation, formal_headroom_nofile_required, formal_headroom_tiers, hex_sha256,
    publish_headroom_attestation, run_headroom_attestation,
};
pub use calibration::{
    CalibrationConfig, CalibrationMode, CalibrationReport, GateCalibrationRound,
    GateOverheadCalibrationReport, RAW_CALIBRATION_SCHEMA_VERSION, run_calibration,
    run_gate_overhead_calibration,
};
pub use control::serve_control;
pub use observer::{
    BeginAck, Final250Boundary, MessageLatencySummary, MessageSample, ObserverHub, ObserverLimits,
    PersistenceGateEvidence, PersistenceGateTrigger, PersistenceSnapshotEvidence, RoundSpec,
    RoundSummary,
};
pub use proxy::{
    DEFAULT_PROXY_MAX_CONNECTIONS, DEFAULT_PROXY_MEMORY_BUDGET_MIB, ProxyConfig, ProxyServer,
    ProxySnapshot, ProxyTelemetry,
};
