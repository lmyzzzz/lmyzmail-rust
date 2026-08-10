use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    fs::File,
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str,
    time::Duration,
};

use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

pub const MAX_CONFIG_BYTES: usize = 1_048_576;
const MAX_PROPERTY_COUNT: usize = 16_384;
const MAX_PROPERTY_KEY_BYTES: usize = 512;
const MAX_PROPERTY_VALUE_BYTES: usize = 1_048_576;
const MAX_HOST_BYTES: usize = 253;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_API_KEY_BYTES: usize = 4_096;
const MAX_ALLOWED_ORIGINS: usize = 256;
const MAX_TRUSTED_PROXIES: usize = 256;
const MAX_ORIGIN_BYTES: usize = 2_048;
const MAX_POOL_SIZE: u32 = 4_096;
const MAX_HONEYPOT_DELAY_MS: u64 = 3_600_000;
const MAX_HONEYPOTS: usize = 256;
const MAX_HTCPCP_POTS: usize = 64;
const MAX_HTCPCP_LIST_ITEMS: usize = 64;
const MAX_HTCPCP_BREW_SECONDS: u64 = 86_400;
const MAX_XDP_WHITELIST: usize = 256;
const MAX_MINECRAFT_STATUS_JSON_BYTES: usize = 32_767;
const MAX_MINECRAFT_PLAYERS: u32 = i32::MAX as u32;
const MAX_MINECRAFT_READ_TIMEOUT_SECONDS: u64 = 3_600;
const MAX_MINECRAFT_COMPRESSION_THRESHOLD: i32 = 2 * 1024 * 1024;
const MAX_MINECRAFT_VIEW_DISTANCE: u64 = 64;
const MAX_MINECRAFT_VIDEO_SESSIONS: u64 = 64;
const MAX_MINECRAFT_BLOCK_VIDEO_WIDTH: u64 = 256;
const MAX_MINECRAFT_VIDEO_FPS: u64 = 60;
const MAX_MINECRAFT_VIDEO_CLEAR_MARGIN: u64 = 64;
const MAX_MINECRAFT_VIDEO_SPAWN_PROTECT_RADIUS: u64 = 256;
const MAX_MINECRAFT_MAP_VIDEO_AXIS: u64 = 16;
const MAX_MINECRAFT_WORLD_COORDINATE: i32 = 30_000_000;
const MAX_MINECRAFT_WORLD_Y: i32 = 255;
const MAX_SMTP_ASCII_WIDTH: u64 = 2_048;
const MAX_SMTP_ASCII_FPS: f32 = 60.0;
const MIN_SMTP_ASCII_WIDTH: u64 = 10;
const MIN_SMTP_ASCII_FPS: f32 = 1.0;
const MIN_SMTP_ASCII_CONTRAST: f32 = 0.1;
const MAX_SMTP_ASCII_CONTRAST: f32 = 3.0;
const MIN_SMTP_ASCII_ASPECT: f32 = 0.1;
const MAX_SMTP_ASCII_ASPECT: f32 = 10.0;
const MAX_CONTENT_FILTER_THRESHOLD: f64 = 1_000_000.0;
const MAX_CONTENT_FILTER_RULE_WEIGHT: f64 = 100.0;
const MAX_CONTENT_FILTER_EXTENSIONS: usize = 256;
const MAX_CONTENT_FILTER_EXTENSION_BYTES: usize = 32;
const MAX_CONTENT_FILTER_RBL_SERVERS: usize = 32;
const MAX_CONTENT_FILTER_RBL_SERVER_BYTES: usize = 189;
const MAX_CONTENT_FILTER_RBL_TIMEOUT_MS: u64 = 60_000;
const MAX_MESSAGE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_CRINGE_DECAY_DURATION: Duration = Duration::from_secs(100 * 366 * 24 * 60 * 60);

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Utf8(str::Utf8Error),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "configuration I/O failed: {error}"),
            Self::Utf8(error) => write!(formatter, "configuration is not UTF-8: {error}"),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<str::Utf8Error> for ConfigError {
    fn from(error: str::Utf8Error) -> Self {
        Self::Utf8(error)
    }
}

/// A bounded Java/Spring-style properties map.
///
/// The old service uses `application.properties`, so this parser is kept
/// independent of Spring and deliberately preserves the last value for a
/// duplicate key, matching command-line/property-source overlay semantics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Properties {
    values: BTreeMap<String, String>,
}

impl Properties {
    pub fn parse(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid(format!(
                "configuration exceeds {MAX_CONFIG_BYTES} bytes"
            )));
        }
        let text = str::from_utf8(bytes)?;
        let mut properties = Self::default();
        let mut logical = String::new();
        for physical in text.split('\n') {
            let line = physical.strip_suffix('\r').unwrap_or(physical);
            if logical.is_empty() {
                logical.push_str(line);
            } else {
                logical.push_str(line.trim_start_matches([' ', '\t', '\u{000c}']));
            }
            if has_continuation(&logical) {
                logical.pop();
                continue;
            }
            properties.insert_line(&logical)?;
            logical.clear();
        }
        if !logical.is_empty() {
            properties.insert_line(&logical)?;
        }
        Ok(properties)
    }

    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(ConfigError::Invalid(format!(
                "configuration path is not a regular file: {}",
                path.display()
            )));
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take((MAX_CONFIG_BYTES as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Invalid(format!(
                "configuration exceeds {MAX_CONFIG_BYTES} bytes"
            )));
        }
        // CandidateRuntime emits a semantic JSON document. Convert it to the
        // same internal property map so overlays and legacy aliases retain one
        // precedence and validation path.
        if bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            == Some(b'{')
        {
            return parse_semantic_json(&bytes);
        }
        Self::parse(&bytes)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    pub fn insert(&mut self, key: String, value: String) -> Result<(), ConfigError> {
        validate_property_piece(&key, MAX_PROPERTY_KEY_BYTES, "property key")?;
        validate_property_value(&value)?;
        if !self.values.contains_key(&key) && self.values.len() >= MAX_PROPERTY_COUNT {
            return Err(ConfigError::Invalid(format!(
                "configuration contains more than {MAX_PROPERTY_COUNT} properties"
            )));
        }
        self.values.insert(key, value);
        Ok(())
    }

    pub fn overlay<I>(&mut self, entries: I) -> Result<(), ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        for (key, value) in entries {
            self.insert(key, value)?;
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    fn insert_line(&mut self, line: &str) -> Result<(), ConfigError> {
        let trimmed = line.trim_start_matches([' ', '\t', '\u{000c}']);
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            return Ok(());
        }
        let delimiter = find_delimiter(trimmed);
        let (raw_key, raw_value) = match delimiter {
            Some(index) => (&trimmed[..index], &trimmed[index + 1..]),
            None => (trimmed, ""),
        };
        let key = unescape_property(raw_key.trim_end_matches([' ', '\t', '\u{000c}']))?;
        let value = unescape_property(raw_value.trim_start_matches([' ', '\t', '\u{000c}']))?;
        if key.is_empty() {
            return Err(ConfigError::Invalid(
                "property key must not be empty".into(),
            ));
        }
        self.insert(key, value)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRuntimeConfig {
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    #[serde(default = "default_profile")]
    profile: String,
    listen: JsonListenConfig,
    postgres: JsonDatabaseConfig,
    redis: JsonRedisConfig,
    maildir: String,
    domain: String,
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default)]
    trusted_proxies: Vec<String>,
    #[serde(default)]
    api_keys: Vec<JsonApiKeyConfig>,
    #[serde(default)]
    features: JsonFeatureConfig,
    #[serde(default)]
    smtp: JsonSmtpConfig,
    #[serde(default)]
    content_filter: JsonContentFilterConfig,
    #[serde(default)]
    xdp: JsonXdpConfig,
    #[serde(default)]
    cringe: JsonCringeConfig,
    #[serde(default)]
    reporting: JsonReportingConfig,
    #[serde(default)]
    htcpcp: JsonHtcpcpConfig,
    #[serde(default)]
    minecraft: JsonMinecraftConfig,
    #[serde(default)]
    mail_render: JsonMailRenderConfig,
    #[serde(default)]
    tls: JsonTlsConfig,
    #[serde(default)]
    limits: JsonLimitConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonListenConfig {
    host: String,
    http: u16,
    smtp: u16,
    htcpcp: u16,
    minecraft: u16,
    #[serde(default)]
    honeypots: Vec<JsonHoneypotConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonHoneypotConfig {
    port: u16,
    protocol: String,
    label: String,
    #[serde(default)]
    bind_address: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonDatabaseConfig {
    host: String,
    port: u16,
    database: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRedisConfig {
    host: String,
    port: u16,
    database: u8,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    tls: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonApiKeyConfig {
    key: String,
    #[serde(default = "default_api_label")]
    label: String,
    #[serde(default = "default_true")]
    read: bool,
    #[serde(default)]
    write: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonFeatureConfig {
    #[serde(default)]
    public_registration: bool,
    #[serde(default = "default_skibidi_mode")]
    smtp_skibidi_mode: String,
    #[serde(default = "default_true")]
    smtp_skibidi_enable_avx512: bool,
    #[serde(default = "default_true")]
    smtp_skibidi_enable_simd_rng: bool,
    #[serde(default = "default_true")]
    spamhaus: bool,
    #[serde(default = "default_true")]
    tarpit: bool,
    #[serde(default = "default_true")]
    mta_sts: bool,
    #[serde(default)]
    xdp: bool,
    #[serde(default)]
    fail2ban: bool,
    #[serde(default = "default_true")]
    report_delivery: bool,
    #[serde(default)]
    show_internet_nl_badge: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonSmtpConfig {
    #[serde(default = "default_true")]
    skibidi_toilet_quiz_enabled: bool,
    #[serde(default)]
    asciiart: JsonSmtpAsciiConfig,
}

impl Default for JsonSmtpConfig {
    fn default() -> Self {
        Self {
            skibidi_toilet_quiz_enabled: true,
            asciiart: JsonSmtpAsciiConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonContentFilterConfig {
    enabled: bool,
    suspicious_threshold: f64,
    spam_threshold: f64,
    rules: JsonContentFilterRules,
    rbl: JsonContentFilterRbl,
    attachment: JsonContentFilterAttachment,
}

impl Default for JsonContentFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suspicious_threshold: 5.0,
            spam_threshold: 10.0,
            rules: JsonContentFilterRules::default(),
            rbl: JsonContentFilterRbl::default(),
            attachment: JsonContentFilterAttachment::default(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonContentFilterRules {
    rbl_check: JsonContentFilterRule,
    new_domain: JsonContentFilterRule,
    missing_headers: JsonContentFilterRule,
    subject_encoding_trick: JsonContentFilterRule,
    excessive_recipients: JsonContentFilterRule,
    dangerous_extension: JsonContentFilterRule,
    double_extension: JsonContentFilterRule,
    mime_type_mismatch: JsonContentFilterRule,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonContentFilterRbl {
    enabled: bool,
    servers: Vec<String>,
    timeout_ms: u64,
    score_per_hit: f64,
    max_score: f64,
}

impl Default for JsonContentFilterRbl {
    fn default() -> Self {
        let defaults = ContentFilterRblConfig::default();
        Self {
            enabled: defaults.enabled,
            servers: defaults.servers,
            timeout_ms: defaults.timeout.as_millis() as u64,
            score_per_hit: defaults.score_per_hit,
            max_score: defaults.max_score,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonContentFilterAttachment {
    enabled: bool,
    dangerous_extensions: Vec<String>,
    dangerous_extension_score: f64,
    double_extension_score: f64,
    mime_type_mismatch_score: f64,
}

impl Default for JsonContentFilterAttachment {
    fn default() -> Self {
        Self {
            enabled: true,
            dangerous_extensions: default_dangerous_attachment_extensions(),
            dangerous_extension_score: 5.0,
            double_extension_score: 4.0,
            mime_type_mismatch_score: 3.0,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonContentFilterRule {
    enabled: bool,
    weight: f64,
}

impl Default for JsonContentFilterRule {
    fn default() -> Self {
        Self {
            enabled: true,
            weight: 1.0,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonSmtpAsciiConfig {
    #[serde(default = "default_smtp_ascii_simd_mode")]
    simd_mode: String,
    #[serde(default = "default_smtp_ascii_max_width")]
    max_width: u32,
    #[serde(default = "default_smtp_ascii_max_fps")]
    max_fps: f32,
    #[serde(default = "default_smtp_ascii_default_width")]
    default_width: u32,
    #[serde(default = "default_smtp_ascii_default_fps")]
    default_fps: f32,
    #[serde(default = "default_smtp_ascii_default_contrast")]
    default_contrast: f32,
    #[serde(default = "default_smtp_ascii_char_aspect")]
    char_aspect: f32,
}

impl Default for JsonSmtpAsciiConfig {
    fn default() -> Self {
        Self {
            simd_mode: default_smtp_ascii_simd_mode(),
            max_width: default_smtp_ascii_max_width(),
            max_fps: default_smtp_ascii_max_fps(),
            default_width: default_smtp_ascii_default_width(),
            default_fps: default_smtp_ascii_default_fps(),
            default_contrast: default_smtp_ascii_default_contrast(),
            char_aspect: default_smtp_ascii_char_aspect(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonXdpConfig {
    interface_name: String,
    bpf_object_path: Option<String>,
    pin_path: String,
    ban_threshold: i32,
    unban_threshold: i32,
    force_generic_mode: bool,
    verbose: bool,
    sync_on_startup: bool,
    whitelist: Vec<String>,
    reason_code_default: i32,
    reason_code_pps_overlimit: i32,
    reason_code_syn_flood: i32,
    pps_monitor: JsonXdpPpsMonitorConfig,
}

impl Default for JsonXdpConfig {
    fn default() -> Self {
        Self {
            interface_name: "eth0".into(),
            bpf_object_path: None,
            pin_path: "/sys/fs/bpf/lmyzmail".into(),
            ban_threshold: 50,
            unban_threshold: -1,
            force_generic_mode: false,
            verbose: false,
            sync_on_startup: true,
            whitelist: vec!["127.0.0.1".into(), "::1".into()],
            reason_code_default: 0,
            reason_code_pps_overlimit: 5,
            reason_code_syn_flood: 6,
            pps_monitor: JsonXdpPpsMonitorConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonXdpPpsMonitorConfig {
    enabled: bool,
    poll_interval_ms: u64,
    pps_warn_threshold: u64,
    pps_critical_threshold: u64,
    syn_pps_warn_threshold: u64,
    syn_pps_critical_threshold: u64,
    per_ip_pps_warn_threshold: u64,
    per_ip_pps_critical_threshold: u64,
    per_ip_syn_pps_warn_threshold: u64,
    per_ip_syn_pps_critical_threshold: u64,
    consecutive_exceed_count: u32,
    record_to_cringe: bool,
    max_ips_per_poll: u32,
    ring_buffer_size: u32,
}

impl Default for JsonXdpPpsMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_ms: 1_000,
            pps_warn_threshold: 100_000,
            pps_critical_threshold: 200_000,
            syn_pps_warn_threshold: 10_000,
            syn_pps_critical_threshold: 20_000,
            per_ip_pps_warn_threshold: 1_000,
            per_ip_pps_critical_threshold: 5_000,
            per_ip_syn_pps_warn_threshold: 100,
            per_ip_syn_pps_critical_threshold: 500,
            consecutive_exceed_count: 3,
            record_to_cringe: true,
            max_ips_per_poll: 10_000,
            ring_buffer_size: 1_024,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonCringeConfig {
    decay: JsonCringeDecayConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonCringeDecayConfig {
    interval: String,
    amount: i32,
    check_interval: Option<String>,
    activity_retention_days: u32,
}

impl Default for JsonCringeDecayConfig {
    fn default() -> Self {
        Self {
            interval: "24h".into(),
            amount: 10,
            check_interval: None,
            activity_retention_days: 360,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JsonReportingConfig {
    enabled: bool,
    auto_send_enabled: bool,
    batch_size: u32,
    flush_interval_ms: u64,
    retention_days: u32,
    min_volume_for_report: i32,
    dmarc_report_sender_address: Option<String>,
    dmarc_report_sender_password: String,
    tls_report_sender_address: Option<String>,
    tls_report_sender_password: String,
    organization_name: Option<String>,
    organization_email: Option<String>,
    http_delivery_enabled: Option<bool>,
    http_delivery_timeout_seconds: u64,
    dns_server: Option<String>,
}

impl Default for JsonReportingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_send_enabled: false,
            batch_size: 500,
            flush_interval_ms: 2_000,
            retention_days: 90,
            min_volume_for_report: 10,
            dmarc_report_sender_address: None,
            dmarc_report_sender_password: String::new(),
            tls_report_sender_address: None,
            tls_report_sender_password: String::new(),
            organization_name: None,
            organization_email: None,
            http_delivery_enabled: None,
            http_delivery_timeout_seconds: 30,
            dns_server: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonHtcpcpConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_htcpcp_brew_seconds")]
    default_brew_time_seconds: u64,
    // Keep omission distinct from an explicitly empty array.  Omission uses
    // the production default pot; an empty array is rejected by the semantic
    // configuration boundary instead of silently falling back to that pot.
    #[serde(default)]
    pots: Option<Vec<JsonHtcpcpPotConfig>>,
}

impl Default for JsonHtcpcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_brew_time_seconds: default_htcpcp_brew_seconds(),
            pots: Some(default_json_htcpcp_pots()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonHtcpcpPotConfig {
    #[serde(default = "default_htcpcp_pot_id")]
    id: String,
    #[serde(default = "default_htcpcp_pot_type")]
    r#type: String,
    #[serde(default = "default_htcpcp_tea_varieties")]
    tea_varieties: Vec<String>,
    #[serde(default = "default_htcpcp_additions")]
    supported_additions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonMinecraftConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_true")]
    online_mode: bool,
    #[serde(default = "default_minecraft_compression_threshold")]
    compression_threshold: i32,
    #[serde(default = "default_minecraft_max_players")]
    max_players: u32,
    #[serde(default = "default_minecraft_motd")]
    motd: String,
    #[serde(default)]
    favicon: String,
    #[serde(default = "default_minecraft_read_timeout_seconds")]
    read_timeout_seconds: u64,
    #[serde(default = "default_minecraft_session_server_url")]
    session_server_url: String,
    #[serde(default = "default_minecraft_world_template")]
    world_template: String,
    #[serde(default = "default_minecraft_view_distance")]
    view_distance: u64,
    #[serde(default = "default_minecraft_max_concurrent_videos")]
    max_concurrent_videos: u32,
    #[serde(default)]
    spawn: JsonMinecraftSpawnConfig,
    #[serde(default)]
    video: JsonMinecraftVideoConfig,
    #[serde(default)]
    whitelist_enabled: bool,
    #[serde(default)]
    whitelist_players: Vec<String>,
    #[serde(default)]
    blacklist_players: Vec<String>,
    #[serde(default = "default_minecraft_auth_max_attempts")]
    auth_max_attempts: u32,
    #[serde(default = "default_minecraft_auth_lockout_seconds")]
    auth_lockout_seconds: u64,
    #[serde(default = "default_minecraft_auth_window_seconds")]
    auth_window_seconds: u64,
}

impl Default for JsonMinecraftConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            online_mode: true,
            compression_threshold: default_minecraft_compression_threshold(),
            max_players: default_minecraft_max_players(),
            motd: default_minecraft_motd(),
            favicon: String::new(),
            read_timeout_seconds: default_minecraft_read_timeout_seconds(),
            session_server_url: default_minecraft_session_server_url(),
            world_template: default_minecraft_world_template(),
            view_distance: default_minecraft_view_distance(),
            max_concurrent_videos: default_minecraft_max_concurrent_videos(),
            spawn: JsonMinecraftSpawnConfig::default(),
            video: JsonMinecraftVideoConfig::default(),
            whitelist_enabled: false,
            whitelist_players: Vec::new(),
            blacklist_players: Vec::new(),
            auth_max_attempts: default_minecraft_auth_max_attempts(),
            auth_lockout_seconds: default_minecraft_auth_lockout_seconds(),
            auth_window_seconds: default_minecraft_auth_window_seconds(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonMailRenderConfig {
    #[serde(default = "default_mail_render_simd_mode")]
    simd_mode: String,
}

impl Default for JsonMailRenderConfig {
    fn default() -> Self {
        Self {
            simd_mode: default_mail_render_simd_mode(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonMinecraftSpawnConfig {
    #[serde(default = "default_minecraft_spawn_x")]
    x: f64,
    #[serde(default = "default_minecraft_spawn_y")]
    y: f64,
    #[serde(default = "default_minecraft_spawn_z")]
    z: f64,
    #[serde(default)]
    yaw: f32,
    #[serde(default)]
    pitch: f32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonMinecraftVideoConfig {
    #[serde(default = "default_minecraft_video_center_x")]
    center_x: i32,
    #[serde(default = "default_minecraft_video_center_y")]
    center_y: i32,
    #[serde(default = "default_minecraft_video_wall_z")]
    wall_z: i32,
    #[serde(default = "default_minecraft_video_max_width")]
    max_width: u32,
    #[serde(default = "default_minecraft_video_max_fps")]
    max_fps: u32,
    #[serde(default = "default_minecraft_video_default_width")]
    default_width: u32,
    #[serde(default = "default_minecraft_video_default_fps")]
    default_fps: u32,
    #[serde(default = "default_minecraft_video_default_contrast")]
    default_contrast: f32,
    #[serde(default = "default_minecraft_video_spawn_protect_radius")]
    spawn_protect_radius: u32,
    #[serde(default = "default_minecraft_video_clear_margin")]
    clear_margin: u32,
    #[serde(default = "default_minecraft_map_center_x")]
    map_center_x: i32,
    #[serde(default = "default_minecraft_map_center_y")]
    map_center_y: i32,
    #[serde(default = "default_minecraft_map_center_z")]
    map_center_z: i32,
    #[serde(default = "default_minecraft_map_facing")]
    map_facing: String,
    #[serde(default = "default_minecraft_map_max_maps_x")]
    map_max_maps_x: u32,
    #[serde(default = "default_minecraft_map_max_maps_y")]
    map_max_maps_y: u32,
    #[serde(default = "default_minecraft_map_max_fps")]
    map_max_fps: u32,
    #[serde(default = "default_minecraft_map_default_maps_x")]
    map_default_maps_x: u32,
    #[serde(default = "default_minecraft_map_default_fps")]
    map_default_fps: u32,
    #[serde(default = "default_minecraft_map_default_contrast")]
    map_default_contrast: f32,
    #[serde(default = "default_minecraft_base_map_id")]
    base_map_id: i32,
    #[serde(default = "default_minecraft_base_entity_id")]
    base_entity_id: i32,
}

impl Default for JsonMinecraftVideoConfig {
    fn default() -> Self {
        Self {
            center_x: default_minecraft_video_center_x(),
            center_y: default_minecraft_video_center_y(),
            wall_z: default_minecraft_video_wall_z(),
            max_width: default_minecraft_video_max_width(),
            max_fps: default_minecraft_video_max_fps(),
            default_width: default_minecraft_video_default_width(),
            default_fps: default_minecraft_video_default_fps(),
            default_contrast: default_minecraft_video_default_contrast(),
            spawn_protect_radius: default_minecraft_video_spawn_protect_radius(),
            clear_margin: default_minecraft_video_clear_margin(),
            map_center_x: default_minecraft_map_center_x(),
            map_center_y: default_minecraft_map_center_y(),
            map_center_z: default_minecraft_map_center_z(),
            map_facing: default_minecraft_map_facing(),
            map_max_maps_x: default_minecraft_map_max_maps_x(),
            map_max_maps_y: default_minecraft_map_max_maps_y(),
            map_max_fps: default_minecraft_map_max_fps(),
            map_default_maps_x: default_minecraft_map_default_maps_x(),
            map_default_fps: default_minecraft_map_default_fps(),
            map_default_contrast: default_minecraft_map_default_contrast(),
            base_map_id: default_minecraft_base_map_id(),
            base_entity_id: default_minecraft_base_entity_id(),
        }
    }
}

impl Default for JsonMinecraftSpawnConfig {
    fn default() -> Self {
        Self {
            x: default_minecraft_spawn_x(),
            y: default_minecraft_spawn_y(),
            z: default_minecraft_spawn_z(),
            yaw: 0.0,
            pitch: 0.0,
        }
    }
}

impl Default for JsonFeatureConfig {
    fn default() -> Self {
        Self {
            public_registration: false,
            smtp_skibidi_mode: default_skibidi_mode(),
            smtp_skibidi_enable_avx512: true,
            smtp_skibidi_enable_simd_rng: true,
            spamhaus: true,
            tarpit: true,
            mta_sts: true,
            xdp: false,
            fail2ban: false,
            report_delivery: true,
            show_internet_nl_badge: false,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonTlsConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    keystore_path: String,
    #[serde(default)]
    keystore_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonLimitConfig {
    #[serde(default = "default_pool_size")]
    redis_pool: u32,
    #[serde(default = "default_pool_size")]
    postgres_pool: u32,
    #[serde(default = "default_http_request_bytes")]
    max_http_request_bytes: usize,
    #[serde(default = "default_http_connections")]
    max_http_connections: usize,
    #[serde(default = "default_http_deadline_ms")]
    http_deadline_ms: u64,
    #[serde(default = "default_honeypot_initial_delay_ms")]
    honeypot_initial_delay_ms: u64,
    #[serde(default = "default_honeypot_post_banner_timeout_ms")]
    honeypot_post_banner_timeout_ms: u64,
    #[serde(default = "default_max_honeypot_connections_per_trap")]
    max_honeypot_connections_per_trap: usize,
    #[serde(default = "default_max_honeypot_read_bytes")]
    max_honeypot_read_bytes: usize,
    #[serde(default = "default_max_email_size_bytes")]
    max_email_size_bytes: u64,
    #[serde(default = "default_max_attachment_size_bytes")]
    max_attachment_size_bytes: u64,
    #[serde(default = "default_max_total_attachments_size_bytes")]
    max_total_attachments_size_bytes: u64,
}

impl Default for JsonLimitConfig {
    fn default() -> Self {
        Self {
            redis_pool: default_pool_size(),
            postgres_pool: default_pool_size(),
            max_http_request_bytes: default_http_request_bytes(),
            max_http_connections: default_http_connections(),
            http_deadline_ms: default_http_deadline_ms(),
            honeypot_initial_delay_ms: default_honeypot_initial_delay_ms(),
            honeypot_post_banner_timeout_ms: default_honeypot_post_banner_timeout_ms(),
            max_honeypot_connections_per_trap: default_max_honeypot_connections_per_trap(),
            max_honeypot_read_bytes: default_max_honeypot_read_bytes(),
            max_email_size_bytes: default_max_email_size_bytes(),
            max_attachment_size_bytes: default_max_attachment_size_bytes(),
            max_total_attachments_size_bytes: default_max_total_attachments_size_bytes(),
        }
    }
}

fn default_schema_version() -> u32 {
    1
}

fn default_profile() -> String {
    "production".to_owned()
}

fn default_api_label() -> String {
    "api".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_skibidi_mode() -> String {
    "AUTO_SAFE".to_owned()
}

fn default_smtp_ascii_simd_mode() -> String {
    "AUTO".to_owned()
}

fn default_smtp_ascii_max_width() -> u32 {
    450
}

fn default_smtp_ascii_max_fps() -> f32 {
    20.0
}

fn default_smtp_ascii_default_width() -> u32 {
    120
}

fn default_smtp_ascii_default_fps() -> f32 {
    10.0
}

fn default_smtp_ascii_default_contrast() -> f32 {
    1.2
}

fn default_smtp_ascii_char_aspect() -> f32 {
    2.0
}

fn default_htcpcp_brew_seconds() -> u64 {
    30
}

fn default_htcpcp_pot_id() -> String {
    "pot-0".to_owned()
}

fn default_htcpcp_pot_type() -> String {
    "coffee".to_owned()
}

fn default_htcpcp_tea_varieties() -> Vec<String> {
    ["darjeeling", "earl-grey", "peppermint"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn default_htcpcp_additions() -> Vec<String> {
    [
        "Cream",
        "Half-and-half",
        "Whole-milk",
        "Part-Skim",
        "Skim",
        "Non-Dairy",
        "Vanilla",
        "Almond",
        "Raspberry",
        "Chocolate",
        "Whisky",
        "Rum",
        "Kahlua",
        "Aquavit",
        "Sugar",
        "Xylitol",
        "Stevia",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_json_htcpcp_pots() -> Vec<JsonHtcpcpPotConfig> {
    vec![JsonHtcpcpPotConfig {
        id: default_htcpcp_pot_id(),
        r#type: default_htcpcp_pot_type(),
        tea_varieties: default_htcpcp_tea_varieties(),
        supported_additions: default_htcpcp_additions(),
    }]
}

fn default_pool_size() -> u32 {
    32
}

fn default_http_request_bytes() -> usize {
    10 * 1024 * 1024
}

fn default_http_connections() -> usize {
    256
}

fn default_http_deadline_ms() -> u64 {
    10_000
}

fn default_honeypot_initial_delay_ms() -> u64 {
    1_500
}

fn default_honeypot_post_banner_timeout_ms() -> u64 {
    10_000
}

fn default_max_honeypot_connections_per_trap() -> usize {
    100
}

fn default_max_honeypot_read_bytes() -> usize {
    1_024
}

fn default_minecraft_max_players() -> u32 {
    20
}

fn default_minecraft_motd() -> String {
    "\u{00a7}6LMYZMAIL \u{00a7}7- Send emails in Minecraft".to_owned()
}

fn default_minecraft_read_timeout_seconds() -> u64 {
    30
}

fn default_minecraft_session_server_url() -> String {
    "https://sessionserver.mojang.com/session/minecraft/hasJoined".to_owned()
}

fn default_minecraft_world_template() -> String {
    "worlds/mailroom".to_owned()
}

fn default_minecraft_view_distance() -> u64 {
    32
}

fn default_minecraft_video_center_x() -> i32 {
    0
}

fn default_minecraft_video_center_y() -> i32 {
    180
}

fn default_minecraft_video_wall_z() -> i32 {
    -20
}

fn default_minecraft_video_max_width() -> u32 {
    64
}

fn default_minecraft_video_max_fps() -> u32 {
    20
}

fn default_minecraft_video_default_width() -> u32 {
    32
}

fn default_minecraft_video_default_fps() -> u32 {
    10
}

fn default_minecraft_video_default_contrast() -> f32 {
    1.2
}

fn default_minecraft_video_spawn_protect_radius() -> u32 {
    8
}

fn default_minecraft_video_clear_margin() -> u32 {
    2
}

fn default_minecraft_map_center_x() -> i32 {
    0
}

fn default_minecraft_map_center_y() -> i32 {
    180
}

fn default_minecraft_map_center_z() -> i32 {
    -20
}

fn default_minecraft_map_facing() -> String {
    "SOUTH".to_owned()
}

fn default_minecraft_map_max_maps_x() -> u32 {
    10
}

fn default_minecraft_map_max_maps_y() -> u32 {
    10
}

fn default_minecraft_map_max_fps() -> u32 {
    20
}

fn default_minecraft_map_default_maps_x() -> u32 {
    5
}

fn default_minecraft_map_default_fps() -> u32 {
    10
}

fn default_minecraft_map_default_contrast() -> f32 {
    1.2
}

fn default_minecraft_base_map_id() -> i32 {
    10_000
}

fn default_minecraft_base_entity_id() -> i32 {
    100_000
}

fn default_minecraft_auth_max_attempts() -> u32 {
    5
}

fn default_minecraft_auth_lockout_seconds() -> u64 {
    300
}

fn default_minecraft_auth_window_seconds() -> u64 {
    600
}

fn default_minecraft_max_concurrent_videos() -> u32 {
    2
}

fn default_minecraft_compression_threshold() -> i32 {
    256
}

fn default_mail_render_simd_mode() -> String {
    "AUTO".to_owned()
}

fn default_minecraft_spawn_x() -> f64 {
    0.5
}

fn default_minecraft_spawn_y() -> f64 {
    160.0
}

fn default_minecraft_spawn_z() -> f64 {
    0.5
}

fn default_max_email_size_bytes() -> u64 {
    15 * 1024 * 1024
}

fn default_max_attachment_size_bytes() -> u64 {
    10 * 1024 * 1024
}

fn default_max_total_attachments_size_bytes() -> u64 {
    15 * 1024 * 1024
}

fn default_dangerous_attachment_extensions() -> Vec<String> {
    [
        "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh", "msi",
        "msp", "hta", "cpl", "reg", "inf", "scf", "lnk", "ps1", "psm1", "jar",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn parse_semantic_json(bytes: &[u8]) -> Result<Properties, ConfigError> {
    let value: JsonRuntimeConfig = serde_json::from_slice(bytes).map_err(|error| {
        ConfigError::Invalid(format!("semantic JSON configuration is invalid: {error}"))
    })?;
    if value.schema_version != 1 {
        return Err(ConfigError::Invalid(format!(
            "unsupported configuration schema version: {}",
            value.schema_version
        )));
    }
    let JsonHtcpcpConfig {
        enabled: htcpcp_enabled,
        default_brew_time_seconds: htcpcp_brew_seconds,
        pots,
    } = value.htcpcp;
    let JsonSmtpConfig {
        skibidi_toilet_quiz_enabled,
        asciiart: smtp_ascii,
    } = value.smtp;
    let content_filter = value.content_filter;
    let htcpcp_pots = pots.unwrap_or_else(default_json_htcpcp_pots);
    if htcpcp_pots.is_empty() {
        return Err(ConfigError::Invalid(
            "HTCPCP semantic configuration must contain at least one pot".into(),
        ));
    }
    let mut properties = Properties::default();
    properties.insert("lmyzmail.profile".to_owned(), value.profile)?;
    let listen_host = value.listen.host.clone();
    properties.insert("lmyzmail.listen.host".to_owned(), listen_host.clone())?;
    properties.insert(
        "lmyzmail.http.port".to_owned(),
        value.listen.http.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.port".to_owned(),
        value.listen.smtp.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.skibidi-toilet-quiz-enabled".to_owned(),
        skibidi_toilet_quiz_enabled.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.asciiart.simd-mode".to_owned(),
        smtp_ascii.simd_mode,
    )?;
    properties.insert(
        "lmyzmail.smtp.asciiart.max-width".to_owned(),
        smtp_ascii.max_width.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.asciiart.max-fps".to_owned(),
        smtp_ascii.max_fps.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.asciiart.default-width".to_owned(),
        smtp_ascii.default_width.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.asciiart.default-fps".to_owned(),
        smtp_ascii.default_fps.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.asciiart.default-contrast".to_owned(),
        smtp_ascii.default_contrast.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.asciiart.char-aspect".to_owned(),
        smtp_ascii.char_aspect.to_string(),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.enabled".to_owned(),
        content_filter.enabled.to_string(),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.suspicious-threshold".to_owned(),
        content_filter.suspicious_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.spam-threshold".to_owned(),
        content_filter.spam_threshold.to_string(),
    )?;
    for (name, rule) in [
        ("RBL_CHECK", content_filter.rules.rbl_check),
        ("NEW_DOMAIN", content_filter.rules.new_domain),
        ("MISSING_HEADERS", content_filter.rules.missing_headers),
        (
            "SUBJECT_ENCODING_TRICK",
            content_filter.rules.subject_encoding_trick,
        ),
        (
            "EXCESSIVE_RECIPIENTS",
            content_filter.rules.excessive_recipients,
        ),
        (
            "DANGEROUS_EXTENSION",
            content_filter.rules.dangerous_extension,
        ),
        ("DOUBLE_EXTENSION", content_filter.rules.double_extension),
        (
            "MIME_TYPE_MISMATCH",
            content_filter.rules.mime_type_mismatch,
        ),
    ] {
        let prefix = format!("lmyzmail.contentfilter.rules.{name}");
        properties.insert(format!("{prefix}.enabled"), rule.enabled.to_string())?;
        properties.insert(format!("{prefix}.weight"), rule.weight.to_string())?;
    }
    properties.insert(
        "lmyzmail.contentfilter.rbl.enabled".to_owned(),
        content_filter.rbl.enabled.to_string(),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.rbl.servers".to_owned(),
        content_filter.rbl.servers.join(","),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.rbl.timeout-ms".to_owned(),
        content_filter.rbl.timeout_ms.to_string(),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.rbl.score-per-hit".to_owned(),
        content_filter.rbl.score_per_hit.to_string(),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.rbl.max-score".to_owned(),
        content_filter.rbl.max_score.to_string(),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.attachment.enabled".to_owned(),
        content_filter.attachment.enabled.to_string(),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.attachment.dangerous-extensions".to_owned(),
        content_filter.attachment.dangerous_extensions.join(","),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.attachment.dangerous-extension-score".to_owned(),
        content_filter
            .attachment
            .dangerous_extension_score
            .to_string(),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.attachment.double-extension-score".to_owned(),
        content_filter.attachment.double_extension_score.to_string(),
    )?;
    properties.insert(
        "lmyzmail.contentfilter.attachment.mime-type-mismatch-score".to_owned(),
        content_filter
            .attachment
            .mime_type_mismatch_score
            .to_string(),
    )?;
    properties.insert(
        "lmyzmail.htcpcp.port".to_owned(),
        value.listen.htcpcp.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.port".to_owned(),
        value.listen.minecraft.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.enabled".to_owned(),
        value.minecraft.enabled.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.online-mode".to_owned(),
        value.minecraft.online_mode.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.compression-threshold".to_owned(),
        value.minecraft.compression_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.max-players".to_owned(),
        value.minecraft.max_players.to_string(),
    )?;
    properties.insert("lmyzmail.minecraft.motd".to_owned(), value.minecraft.motd)?;
    properties.insert(
        "lmyzmail.minecraft.favicon".to_owned(),
        value.minecraft.favicon,
    )?;
    properties.insert(
        "lmyzmail.minecraft.read-timeout-seconds".to_owned(),
        value.minecraft.read_timeout_seconds.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.session-server-url".to_owned(),
        value.minecraft.session_server_url,
    )?;
    properties.insert(
        "lmyzmail.minecraft.world-template".to_owned(),
        value.minecraft.world_template,
    )?;
    properties.insert(
        "lmyzmail.minecraft.view-distance".to_owned(),
        value.minecraft.view_distance.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.max-concurrent-videos".to_owned(),
        value.minecraft.max_concurrent_videos.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.spawn.x".to_owned(),
        value.minecraft.spawn.x.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.spawn.y".to_owned(),
        value.minecraft.spawn.y.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.spawn.z".to_owned(),
        value.minecraft.spawn.z.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.spawn.yaw".to_owned(),
        value.minecraft.spawn.yaw.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.spawn.pitch".to_owned(),
        value.minecraft.spawn.pitch.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.video.center-x".to_owned(),
        value.minecraft.video.center_x.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.video.center-y".to_owned(),
        value.minecraft.video.center_y.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.video.wall-z".to_owned(),
        value.minecraft.video.wall_z.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.video.max-width".to_owned(),
        value.minecraft.video.max_width.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.video.max-fps".to_owned(),
        value.minecraft.video.max_fps.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.video.default-width".to_owned(),
        value.minecraft.video.default_width.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.video.default-fps".to_owned(),
        value.minecraft.video.default_fps.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.video.default-contrast".to_owned(),
        value.minecraft.video.default_contrast.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.video.spawn-protect-radius".to_owned(),
        value.minecraft.video.spawn_protect_radius.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.video.clear-margin".to_owned(),
        value.minecraft.video.clear_margin.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.center-x".to_owned(),
        value.minecraft.video.map_center_x.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.center-y".to_owned(),
        value.minecraft.video.map_center_y.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.center-z".to_owned(),
        value.minecraft.video.map_center_z.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.facing".to_owned(),
        value.minecraft.video.map_facing,
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.max-maps-x".to_owned(),
        value.minecraft.video.map_max_maps_x.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.max-maps-y".to_owned(),
        value.minecraft.video.map_max_maps_y.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.max-fps".to_owned(),
        value.minecraft.video.map_max_fps.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.default-maps-x".to_owned(),
        value.minecraft.video.map_default_maps_x.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.default-fps".to_owned(),
        value.minecraft.video.map_default_fps.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.default-contrast".to_owned(),
        value.minecraft.video.map_default_contrast.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.base-map-id".to_owned(),
        value.minecraft.video.base_map_id.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.map-video.base-entity-id".to_owned(),
        value.minecraft.video.base_entity_id.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.whitelist.enabled".to_owned(),
        value.minecraft.whitelist_enabled.to_string(),
    )?;
    for (index, player) in value.minecraft.whitelist_players.into_iter().enumerate() {
        properties.insert(
            format!("lmyzmail.minecraft.whitelist.players[{index}]"),
            player,
        )?;
    }
    for (index, player) in value.minecraft.blacklist_players.into_iter().enumerate() {
        properties.insert(
            format!("lmyzmail.minecraft.blacklist.players[{index}]"),
            player,
        )?;
    }
    properties.insert(
        "lmyzmail.minecraft.auth.max-attempts".to_owned(),
        value.minecraft.auth_max_attempts.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.auth.lockout-seconds".to_owned(),
        value.minecraft.auth_lockout_seconds.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.auth.window-seconds".to_owned(),
        value.minecraft.auth_window_seconds.to_string(),
    )?;
    properties.insert(
        "lmyzmail.mailrender.simd-mode".to_owned(),
        value.mail_render.simd_mode,
    )?;
    properties.insert(
        "lmyzmail.honeypot.enabled".to_owned(),
        (!value.listen.honeypots.is_empty()).to_string(),
    )?;
    for (index, trap) in value.listen.honeypots.into_iter().enumerate() {
        let prefix = format!("lmyzmail.honeypot.traps[{index}]");
        properties.insert(format!("{prefix}.port"), trap.port.to_string())?;
        properties.insert(format!("{prefix}.protocol"), trap.protocol)?;
        properties.insert(format!("{prefix}.label"), trap.label)?;
        properties.insert(
            format!("{prefix}.bind-address"),
            trap.bind_address.unwrap_or_else(|| listen_host.clone()),
        )?;
    }
    properties.insert("lmyzmail.postgres.host".to_owned(), value.postgres.host)?;
    properties.insert(
        "lmyzmail.postgres.port".to_owned(),
        value.postgres.port.to_string(),
    )?;
    properties.insert(
        "lmyzmail.postgres.database".to_owned(),
        value.postgres.database,
    )?;
    properties.insert(
        "lmyzmail.postgres.username".to_owned(),
        value.postgres.username,
    )?;
    properties.insert(
        "lmyzmail.postgres.password".to_owned(),
        value.postgres.password,
    )?;
    properties.insert("lmyzmail.redis.host".to_owned(), value.redis.host)?;
    properties.insert(
        "lmyzmail.redis.port".to_owned(),
        value.redis.port.to_string(),
    )?;
    properties.insert(
        "lmyzmail.redis.database".to_owned(),
        value.redis.database.to_string(),
    )?;
    if !value.redis.username.is_empty() {
        properties.insert("lmyzmail.redis.username".to_owned(), value.redis.username)?;
    }
    if !value.redis.password.is_empty() {
        properties.insert("lmyzmail.redis.password".to_owned(), value.redis.password)?;
    }
    properties.insert(
        "lmyzmail.redis.tls-enabled".to_owned(),
        value.redis.tls.to_string(),
    )?;
    properties.insert("lmyzmail.maildir.base".to_owned(), value.maildir)?;
    properties.insert("lmyzmail.domain".to_owned(), value.domain)?;
    for (index, origin) in value.allowed_origins.into_iter().enumerate() {
        properties.insert(format!("lmyzmail.allowed-origins[{index}]"), origin)?;
    }
    for (index, proxy) in value.trusted_proxies.into_iter().enumerate() {
        properties.insert(format!("lmyzmail.http.trusted-proxies[{index}]"), proxy)?;
    }
    for (index, api_key) in value.api_keys.into_iter().enumerate() {
        let prefix = format!("lmyzmail.api-keys[{index}]");
        properties.insert(format!("{prefix}.key"), api_key.key)?;
        properties.insert(format!("{prefix}.label"), api_key.label)?;
        properties.insert(format!("{prefix}.read"), api_key.read.to_string())?;
        properties.insert(format!("{prefix}.write"), api_key.write.to_string())?;
    }
    properties.insert(
        "lmyzmail.htcpcp.enabled".to_owned(),
        htcpcp_enabled.to_string(),
    )?;
    properties.insert(
        "lmyzmail.htcpcp.default-brew-time-seconds".to_owned(),
        htcpcp_brew_seconds.to_string(),
    )?;
    for (index, pot) in htcpcp_pots.into_iter().enumerate() {
        reject_semantic_json_csv_delimiters(index, "tea_varieties", &pot.tea_varieties)?;
        reject_semantic_json_csv_delimiters(
            index,
            "supported_additions",
            &pot.supported_additions,
        )?;
        let prefix = format!("lmyzmail.htcpcp.pots[{index}]");
        properties.insert(format!("{prefix}.id"), pot.id)?;
        properties.insert(format!("{prefix}.type"), pot.r#type)?;
        properties.insert(
            format!("{prefix}.tea-varieties"),
            pot.tea_varieties.join(","),
        )?;
        properties.insert(
            format!("{prefix}.supported-additions"),
            pot.supported_additions.join(","),
        )?;
    }
    properties.insert(
        "lmyzmail.public-registration-enabled".to_owned(),
        value.features.public_registration.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.skibidi-generator-mode".to_owned(),
        value.features.smtp_skibidi_mode,
    )?;
    properties.insert(
        "lmyzmail.smtp.skibidi-generator-enable-avx512".to_owned(),
        value.features.smtp_skibidi_enable_avx512.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.skibidi-generator-enable-simd-rng".to_owned(),
        value.features.smtp_skibidi_enable_simd_rng.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp-security.spamhaus-enabled".to_owned(),
        value.features.spamhaus.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp-security.tarpit-enabled".to_owned(),
        value.features.tarpit.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.mta-sts-enabled".to_owned(),
        value.features.mta_sts.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.enabled".to_owned(),
        value.features.xdp.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.interface-name".to_owned(),
        value.xdp.interface_name,
    )?;
    insert_optional_property(
        &mut properties,
        "lmyzmail.xdp.bpf-object-path",
        value.xdp.bpf_object_path,
    )?;
    properties.insert("lmyzmail.xdp.pin-path".to_owned(), value.xdp.pin_path)?;
    properties.insert(
        "lmyzmail.xdp.ban-threshold".to_owned(),
        value.xdp.ban_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.unban-threshold".to_owned(),
        value.xdp.unban_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.force-generic-mode".to_owned(),
        value.xdp.force_generic_mode.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.verbose".to_owned(),
        value.xdp.verbose.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.sync-on-startup".to_owned(),
        value.xdp.sync_on_startup.to_string(),
    )?;
    if value.xdp.whitelist.is_empty() {
        properties.insert("lmyzmail.xdp.whitelist".to_owned(), String::new())?;
    } else {
        for (index, network) in value.xdp.whitelist.into_iter().enumerate() {
            properties.insert(format!("lmyzmail.xdp.whitelist[{index}]"), network)?;
        }
    }
    properties.insert(
        "lmyzmail.xdp.reason-code-default".to_owned(),
        value.xdp.reason_code_default.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.reason-code-pps-overlimit".to_owned(),
        value.xdp.reason_code_pps_overlimit.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.reason-code-syn-flood".to_owned(),
        value.xdp.reason_code_syn_flood.to_string(),
    )?;
    let pps = value.xdp.pps_monitor;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.enabled".to_owned(),
        pps.enabled.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.poll-interval-ms".to_owned(),
        pps.poll_interval_ms.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.pps-warn-threshold".to_owned(),
        pps.pps_warn_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.pps-critical-threshold".to_owned(),
        pps.pps_critical_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.syn-pps-warn-threshold".to_owned(),
        pps.syn_pps_warn_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.syn-pps-critical-threshold".to_owned(),
        pps.syn_pps_critical_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.per-ip-pps-warn-threshold".to_owned(),
        pps.per_ip_pps_warn_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.per-ip-pps-critical-threshold".to_owned(),
        pps.per_ip_pps_critical_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.per-ip-syn-pps-warn-threshold".to_owned(),
        pps.per_ip_syn_pps_warn_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.per-ip-syn-pps-critical-threshold".to_owned(),
        pps.per_ip_syn_pps_critical_threshold.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.consecutive-exceed-count".to_owned(),
        pps.consecutive_exceed_count.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.record-to-cringe".to_owned(),
        pps.record_to_cringe.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.max-ips-per-poll".to_owned(),
        pps.max_ips_per_poll.to_string(),
    )?;
    properties.insert(
        "lmyzmail.xdp.pps-monitor.ring-buffer-size".to_owned(),
        pps.ring_buffer_size.to_string(),
    )?;
    properties.insert(
        "lmyzmail.cringe.decay.interval".to_owned(),
        value.cringe.decay.interval,
    )?;
    properties.insert(
        "lmyzmail.cringe.decay.amount".to_owned(),
        value.cringe.decay.amount.to_string(),
    )?;
    insert_optional_property(
        &mut properties,
        "lmyzmail.cringe.decay.check-interval",
        value.cringe.decay.check_interval,
    )?;
    properties.insert(
        "lmyzmail.cringe.decay.activity-retention-days".to_owned(),
        value.cringe.decay.activity_retention_days.to_string(),
    )?;
    properties.insert(
        "lmyzmail.fail2ban.enabled".to_owned(),
        value.features.fail2ban.to_string(),
    )?;
    properties.insert(
        "lmyzmail.reporting.http-delivery-enabled".to_owned(),
        value
            .reporting
            .http_delivery_enabled
            .unwrap_or(value.features.report_delivery)
            .to_string(),
    )?;
    properties.insert(
        "lmyzmail.reporting.enabled".to_owned(),
        value.reporting.enabled.to_string(),
    )?;
    properties.insert(
        "lmyzmail.reporting.auto-send-enabled".to_owned(),
        value.reporting.auto_send_enabled.to_string(),
    )?;
    properties.insert(
        "lmyzmail.reporting.batch-size".to_owned(),
        value.reporting.batch_size.to_string(),
    )?;
    properties.insert(
        "lmyzmail.reporting.flush-interval-ms".to_owned(),
        value.reporting.flush_interval_ms.to_string(),
    )?;
    properties.insert(
        "lmyzmail.reporting.retention-days".to_owned(),
        value.reporting.retention_days.to_string(),
    )?;
    properties.insert(
        "lmyzmail.reporting.min-volume-for-report".to_owned(),
        value.reporting.min_volume_for_report.to_string(),
    )?;
    insert_optional_property(
        &mut properties,
        "lmyzmail.reporting.dmarc-report-sender-address",
        value.reporting.dmarc_report_sender_address,
    )?;
    if !value.reporting.dmarc_report_sender_password.is_empty() {
        properties.insert(
            "lmyzmail.reporting.dmarc-report-sender-password".to_owned(),
            value.reporting.dmarc_report_sender_password,
        )?;
    }
    insert_optional_property(
        &mut properties,
        "lmyzmail.reporting.tls-report-sender-address",
        value.reporting.tls_report_sender_address,
    )?;
    if !value.reporting.tls_report_sender_password.is_empty() {
        properties.insert(
            "lmyzmail.reporting.tls-report-sender-password".to_owned(),
            value.reporting.tls_report_sender_password,
        )?;
    }
    insert_optional_property(
        &mut properties,
        "lmyzmail.reporting.organization-name",
        value.reporting.organization_name,
    )?;
    insert_optional_property(
        &mut properties,
        "lmyzmail.reporting.organization-email",
        value.reporting.organization_email,
    )?;
    insert_optional_property(
        &mut properties,
        "lmyzmail.reporting.dns-server",
        value.reporting.dns_server.map(|value| value.to_string()),
    )?;
    properties.insert(
        "lmyzmail.reporting.http-delivery-timeout-seconds".to_owned(),
        value.reporting.http_delivery_timeout_seconds.to_string(),
    )?;
    properties.insert(
        "lmyzmail.show-internet-nl-badge".to_owned(),
        value.features.show_internet_nl_badge.to_string(),
    )?;
    properties.insert(
        "lmyzmail.ssl.use-custom-certificate".to_owned(),
        value.tls.enabled.to_string(),
    )?;
    if !value.tls.keystore_path.is_empty() {
        properties.insert(
            "lmyzmail.ssl.keystore-path".to_owned(),
            value.tls.keystore_path,
        )?;
    }
    if !value.tls.keystore_password.is_empty() {
        properties.insert(
            "lmyzmail.ssl.keystore-password".to_owned(),
            value.tls.keystore_password,
        )?;
    }
    properties.insert(
        "lmyzmail.redis.pool.max-active".to_owned(),
        value.limits.redis_pool.to_string(),
    )?;
    properties.insert(
        "lmyzmail.postgres.pool.max-size".to_owned(),
        value.limits.postgres_pool.to_string(),
    )?;
    properties.insert(
        "lmyzmail.http.max-request-bytes".to_owned(),
        value.limits.max_http_request_bytes.to_string(),
    )?;
    properties.insert(
        "lmyzmail.http.max-connections".to_owned(),
        value.limits.max_http_connections.to_string(),
    )?;
    properties.insert(
        "lmyzmail.http.request-timeout-ms".to_owned(),
        value.limits.http_deadline_ms.to_string(),
    )?;
    properties.insert(
        "lmyzmail.honeypot.initial-delay-ms".to_owned(),
        value.limits.honeypot_initial_delay_ms.to_string(),
    )?;
    properties.insert(
        "lmyzmail.honeypot.post-banner-timeout-ms".to_owned(),
        value.limits.honeypot_post_banner_timeout_ms.to_string(),
    )?;
    properties.insert(
        "lmyzmail.honeypot.max-connections-per-trap".to_owned(),
        value.limits.max_honeypot_connections_per_trap.to_string(),
    )?;
    properties.insert(
        "lmyzmail.honeypot.max-read-bytes".to_owned(),
        value.limits.max_honeypot_read_bytes.to_string(),
    )?;
    properties.insert(
        "lmyzmail.max-email-size-bytes".to_owned(),
        value.limits.max_email_size_bytes.to_string(),
    )?;
    properties.insert(
        "lmyzmail.max-attachment-size-bytes".to_owned(),
        value.limits.max_attachment_size_bytes.to_string(),
    )?;
    properties.insert(
        "lmyzmail.max-total-attachments-size-bytes".to_owned(),
        value.limits.max_total_attachments_size_bytes.to_string(),
    )?;
    Ok(properties)
}

fn reject_semantic_json_csv_delimiters(
    pot_index: usize,
    field: &str,
    values: &[String],
) -> Result<(), ConfigError> {
    if values.iter().any(|value| value.contains(',')) {
        return Err(ConfigError::Invalid(format!(
            "HTCPCP semantic configuration pots[{pot_index}].{field} elements must not contain commas"
        )));
    }
    Ok(())
}

fn has_continuation(line: &str) -> bool {
    let mut slashes = 0;
    for byte in line.as_bytes().iter().rev() {
        if *byte == b'\\' {
            slashes += 1;
        } else {
            break;
        }
    }
    slashes % 2 == 1
}

fn find_delimiter(line: &str) -> Option<usize> {
    let mut escaped = false;
    for (index, byte) in line.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'=' | b':' | b' ' | b'\t' | 0x0c => return Some(index),
            _ => {}
        }
    }
    None
}

fn unescape_property(value: &str) -> Result<String, ConfigError> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        let escaped = chars
            .next()
            .ok_or_else(|| ConfigError::Invalid("property ends with an escape".into()))?;
        match escaped {
            't' => output.push('\t'),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            'f' => output.push('\u{000c}'),
            'u' => {
                let mut code = 0_u32;
                for _ in 0..4 {
                    let digit = chars
                        .next()
                        .and_then(|value| value.to_digit(16))
                        .ok_or_else(|| {
                            ConfigError::Invalid(
                                "property contains an invalid unicode escape".into(),
                            )
                        })?;
                    code = (code << 4) | digit;
                }
                let decoded = char::from_u32(code).ok_or_else(|| {
                    ConfigError::Invalid("property contains an invalid unicode scalar".into())
                })?;
                output.push(decoded);
            }
            other => output.push(other),
        }
    }
    Ok(output)
}

fn validate_property_piece(value: &str, max: usize, field: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > max
        || value
            .chars()
            .any(|character| character == '\0' || character == '\r' || character == '\n')
    {
        return Err(ConfigError::Invalid(format!(
            "{field} is empty, exceeds {max} bytes, or contains a line/control separator"
        )));
    }
    Ok(())
}

fn validate_property_value(value: &str) -> Result<(), ConfigError> {
    if value.len() > MAX_PROPERTY_VALUE_BYTES
        || value
            .chars()
            .any(|character| character == '\0' || character == '\r' || character == '\n')
    {
        return Err(ConfigError::Invalid(format!(
            "property value exceeds {MAX_PROPERTY_VALUE_BYTES} bytes or contains a line/control separator"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub schema_version: u32,
    pub profile: String,
    pub properties: Properties,
    pub listen: ListenConfig,
    pub postgres: DatabaseConfig,
    pub redis: RedisConfig,
    pub maildir: PathBuf,
    pub domain: String,
    pub allowed_origins: Vec<String>,
    pub trusted_proxies: Vec<IpNet>,
    pub api_keys: Vec<ApiKeyConfig>,
    pub outbound_route: OutboundRouteConfig,
    pub features: FeatureConfig,
    pub smtp_skibidi: SmtpSkibidiConfig,
    pub content_filter: ContentFilterConfig,
    pub xdp: XdpConfig,
    pub cringe_decay: CringeDecayConfig,
    pub reporting: ReportingConfig,
    pub htcpcp: HtcpcpConfig,
    pub minecraft: MinecraftConfig,
    pub mail_render: MailRenderConfig,
    pub tls: TlsConfig,
    pub limits: LimitConfig,
}

#[derive(Clone, Debug)]
pub struct ListenConfig {
    pub host: String,
    pub http: u16,
    pub smtp: u16,
    pub htcpcp: u16,
    pub minecraft: u16,
    pub honeypots: Vec<HoneypotConfig>,
}

#[derive(Clone, Debug)]
pub struct HoneypotConfig {
    pub port: u16,
    pub protocol: String,
    pub label: String,
    pub bind_address: String,
}

#[derive(Clone, Debug)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct RedisConfig {
    pub host: String,
    pub port: u16,
    pub database: u8,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
}

#[derive(Clone, Debug)]
pub struct ApiKeyConfig {
    pub key: String,
    pub label: String,
    pub read: bool,
    pub write: bool,
}

#[derive(Clone, Debug)]
pub struct OutboundRouteConfig {
    pub mx_l1_max_entries: u64,
    pub mx_l1_ttl_minutes: u64,
    pub mx_l2_ttl_minutes: u64,
    pub mx_negative_ttl_minutes: u64,
    pub dns_query_timeout_seconds: u64,
    pub mta_sts_fetch_timeout_ms: u64,
    pub resolution_deadline_seconds: u64,
}

#[derive(Clone, Debug)]
pub struct FeatureConfig {
    pub public_registration: bool,
    pub smtp_skibidi_mode: String,
    pub smtp_skibidi_enable_avx512: bool,
    pub smtp_skibidi_enable_simd_rng: bool,
    pub spamhaus: bool,
    pub tarpit: bool,
    pub mta_sts: bool,
    pub xdp: bool,
    pub fail2ban: bool,
    pub report_delivery: bool,
    pub show_internet_nl_badge: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SmtpSkibidiConfig {
    pub enabled: bool,
    pub ascii: SmtpAsciiConfig,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SmtpAsciiConfig {
    pub simd_mode: MailRenderSimdMode,
    pub max_width: u32,
    pub max_fps: f32,
    pub default_width: u32,
    pub default_fps: f32,
    pub default_contrast: f32,
    pub char_aspect: f32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ContentFilterConfig {
    pub enabled: bool,
    pub suspicious_threshold: f64,
    pub spam_threshold: f64,
    pub rbl_check: ContentFilterRuleConfig,
    pub rbl: ContentFilterRblConfig,
    pub new_domain: ContentFilterRuleConfig,
    pub missing_headers: ContentFilterRuleConfig,
    pub subject_encoding_trick: ContentFilterRuleConfig,
    pub excessive_recipients: ContentFilterRuleConfig,
    pub dangerous_extension: ContentFilterRuleConfig,
    pub double_extension: ContentFilterRuleConfig,
    pub mime_type_mismatch: ContentFilterRuleConfig,
    pub attachment: ContentFilterAttachmentConfig,
}

impl Default for ContentFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suspicious_threshold: 5.0,
            spam_threshold: 10.0,
            rbl_check: ContentFilterRuleConfig::default(),
            rbl: ContentFilterRblConfig::default(),
            new_domain: ContentFilterRuleConfig::default(),
            missing_headers: ContentFilterRuleConfig::default(),
            subject_encoding_trick: ContentFilterRuleConfig::default(),
            excessive_recipients: ContentFilterRuleConfig::default(),
            dangerous_extension: ContentFilterRuleConfig::default(),
            double_extension: ContentFilterRuleConfig::default(),
            mime_type_mismatch: ContentFilterRuleConfig::default(),
            attachment: ContentFilterAttachmentConfig::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ContentFilterRblConfig {
    pub enabled: bool,
    pub servers: Vec<String>,
    pub timeout: Duration,
    pub score_per_hit: f64,
    pub max_score: f64,
}

impl Default for ContentFilterRblConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            servers: vec!["zen.spamhaus.org".into(), "bl.spamcop.net".into()],
            timeout: Duration::from_millis(3_000),
            score_per_hit: 3.0,
            max_score: 6.0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ContentFilterAttachmentConfig {
    pub enabled: bool,
    pub dangerous_extensions: Vec<String>,
    pub dangerous_extension_score: f64,
    pub double_extension_score: f64,
    pub mime_type_mismatch_score: f64,
}

impl Default for ContentFilterAttachmentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dangerous_extensions: default_dangerous_attachment_extensions(),
            dangerous_extension_score: 5.0,
            double_extension_score: 4.0,
            mime_type_mismatch_score: 3.0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ContentFilterRuleConfig {
    pub enabled: bool,
    pub weight: f64,
}

impl Default for ContentFilterRuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            weight: 1.0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XdpConfig {
    pub enabled: bool,
    pub interface_name: String,
    pub bpf_object_path: Option<PathBuf>,
    pub pin_path: PathBuf,
    pub ban_threshold: i32,
    pub unban_threshold: i32,
    pub force_generic_mode: bool,
    pub verbose: bool,
    pub sync_on_startup: bool,
    pub whitelist: Vec<IpNet>,
    pub reason_code_default: i32,
    pub reason_code_pps_overlimit: i32,
    pub reason_code_syn_flood: i32,
    pub pps_monitor: XdpPpsMonitorConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XdpPpsMonitorConfig {
    pub enabled: bool,
    pub poll_interval_ms: u64,
    pub pps_warn_threshold: u64,
    pub pps_critical_threshold: u64,
    pub syn_pps_warn_threshold: u64,
    pub syn_pps_critical_threshold: u64,
    pub per_ip_pps_warn_threshold: u64,
    pub per_ip_pps_critical_threshold: u64,
    pub per_ip_syn_pps_warn_threshold: u64,
    pub per_ip_syn_pps_critical_threshold: u64,
    pub consecutive_exceed_count: u32,
    pub record_to_cringe: bool,
    pub max_ips_per_poll: u32,
    pub ring_buffer_size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CringeDecayConfig {
    pub interval: Duration,
    pub amount: i32,
    pub check_interval: Duration,
    pub activity_retention_days: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportingConfig {
    pub enabled: bool,
    pub auto_send_enabled: bool,
    pub batch_size: u32,
    pub flush_interval_ms: u64,
    pub retention_days: u32,
    pub min_volume_for_report: i32,
    pub dmarc_report_sender_address: Option<String>,
    pub dmarc_report_sender_password: String,
    pub tls_report_sender_address: Option<String>,
    pub tls_report_sender_password: String,
    pub organization_name: Option<String>,
    pub organization_email: Option<String>,
    pub http_delivery_enabled: bool,
    pub http_delivery_timeout_seconds: u64,
    pub dns_server: Option<SocketAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HtcpcpConfig {
    pub enabled: bool,
    pub default_brew_time_seconds: u64,
    pub pots: Vec<HtcpcpPotConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HtcpcpPotConfig {
    pub id: String,
    pub pot_type: String,
    pub tea_varieties: Vec<String>,
    pub supported_additions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MinecraftConfig {
    pub enabled: bool,
    pub online_mode: bool,
    pub compression_threshold: i32,
    pub max_players: u32,
    pub motd: String,
    pub favicon: String,
    pub read_timeout_seconds: u64,
    pub session_server_url: String,
    pub world_template: String,
    pub view_distance: u32,
    pub max_concurrent_videos: u32,
    pub spawn: MinecraftSpawnConfig,
    pub video: MinecraftVideoConfig,
    pub whitelist_enabled: bool,
    pub whitelist_players: Vec<String>,
    pub blacklist_players: Vec<String>,
    pub auth_max_attempts: u32,
    pub auth_lockout_seconds: u64,
    pub auth_window_seconds: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MinecraftSpawnConfig {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub yaw: f32,
    pub pitch: f32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MinecraftVideoConfig {
    pub center_x: i32,
    pub center_y: i32,
    pub wall_z: i32,
    pub max_width: u32,
    pub max_fps: u32,
    pub default_width: u32,
    pub default_fps: u32,
    pub default_contrast: f32,
    pub spawn_protect_radius: u32,
    pub clear_margin: u32,
    pub map_center_x: i32,
    pub map_center_y: i32,
    pub map_center_z: i32,
    pub map_facing: String,
    pub map_max_maps_x: u32,
    pub map_max_maps_y: u32,
    pub map_max_fps: u32,
    pub map_default_maps_x: u32,
    pub map_default_fps: u32,
    pub map_default_contrast: f32,
    pub base_map_id: i32,
    pub base_entity_id: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailRenderSimdMode {
    Auto,
    Scalar,
    Avx2,
    Avx512,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailRenderConfig {
    pub simd_mode: MailRenderSimdMode,
}

#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub enabled: bool,
    pub keystore_path: Option<PathBuf>,
    pub keystore_password: String,
}

#[derive(Clone, Debug)]
pub struct LimitConfig {
    pub redis_pool: u32,
    pub postgres_pool: u32,
    pub max_http_request_bytes: usize,
    pub max_http_connections: usize,
    pub http_deadline_ms: u64,
    pub honeypot_initial_delay_ms: u64,
    pub honeypot_post_banner_timeout_ms: u64,
    pub max_honeypot_connections_per_trap: usize,
    pub max_honeypot_read_bytes: usize,
    pub max_email_size_bytes: u64,
    pub max_attachment_size_bytes: u64,
    pub max_total_attachments_size_bytes: u64,
}

impl RuntimeConfig {
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        Self::from_properties(Properties::from_path(path)?)
    }

    pub fn from_properties(properties: Properties) -> Result<Self, ConfigError> {
        let listen_host = preferred(
            &properties,
            &["lmyzmail.listen.host"],
            &["botmail.smtp.bind-address"],
        )
        .unwrap_or("127.0.0.1")
        .to_owned();
        validate_host(&listen_host, "listen.host")?;

        let http = preferred_u16(
            &properties,
            &["lmyzmail.http.port", "lmyzmail.netty.http.port"],
            &["botmail.netty.http.port"],
            8080,
        )?;
        let smtp = preferred_u16(
            &properties,
            &["lmyzmail.smtp.port"],
            &["botmail.smtp.port"],
            25,
        )?;
        let htcpcp = preferred_u16(
            &properties,
            &["lmyzmail.htcpcp.port"],
            &["botmail.htcpcp.port"],
            8888,
        )?;
        let htcpcp_config = parse_htcpcp_config(&properties)?;
        let minecraft = preferred_u16(
            &properties,
            &["lmyzmail.minecraft.port"],
            &["botmail.minecraft.port"],
            25565,
        )?;
        let minecraft_config = parse_minecraft_config(&properties)?;
        let mail_render = MailRenderConfig {
            simd_mode: parse_mail_render_simd_mode(preferred(
                &properties,
                &["lmyzmail.mailrender.simd-mode"],
                &["botmail.mailrender.simd-mode"],
            )),
        };
        let smtp_skibidi = parse_smtp_skibidi_config(&properties)?;
        let content_filter = parse_content_filter_config(&properties)?;

        let datasource_url = preferred(
            &properties,
            &["lmyzmail.postgres.url"],
            &["spring.datasource.url"],
        );
        let parsed_datasource_url = datasource_url.and_then(parse_postgres_url);
        let postgres = DatabaseConfig {
            host: preferred(
                &properties,
                &["lmyzmail.postgres.host"],
                &["spring.datasource.host"],
            )
            .or_else(|| {
                parsed_datasource_url
                    .as_ref()
                    .and_then(|parts| parts.host.as_deref())
            })
            .unwrap_or("localhost")
            .to_owned(),
            port: preferred_u16(
                &properties,
                &["lmyzmail.postgres.port"],
                &["spring.datasource.port"],
                parsed_datasource_url
                    .as_ref()
                    .and_then(|parts| parts.port)
                    .unwrap_or(5432),
            )?,
            database: preferred(
                &properties,
                &["lmyzmail.postgres.database"],
                &["spring.datasource.database"],
            )
            .or_else(|| {
                parsed_datasource_url
                    .as_ref()
                    .and_then(|parts| parts.database.as_deref())
            })
            .unwrap_or("lmyzmail")
            .to_owned(),
            username: preferred(
                &properties,
                &["lmyzmail.postgres.username"],
                &["spring.datasource.username"],
            )
            .unwrap_or("lmyzmail")
            .to_owned(),
            password: preferred(
                &properties,
                &["lmyzmail.postgres.password"],
                &["spring.datasource.password"],
            )
            .unwrap_or("")
            .to_owned(),
        };
        validate_database(&postgres)?;

        let redis = RedisConfig {
            host: preferred(
                &properties,
                &["lmyzmail.redis.host"],
                &["spring.data.redis.host"],
            )
            .unwrap_or("localhost")
            .to_owned(),
            port: preferred_u16(
                &properties,
                &["lmyzmail.redis.port"],
                &["spring.data.redis.port"],
                6379,
            )?,
            database: preferred_u8(
                &properties,
                &["lmyzmail.redis.database"],
                &["spring.data.redis.database"],
                0,
            )?,
            username: preferred(
                &properties,
                &["lmyzmail.redis.username"],
                &["spring.data.redis.username", "spring.redis.username"],
            )
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
            password: preferred(
                &properties,
                &["lmyzmail.redis.password"],
                &["spring.data.redis.password", "spring.redis.password"],
            )
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
            tls: preferred_bool(
                &properties,
                &["lmyzmail.redis.tls-enabled", "lmyzmail.redis.ssl.enabled"],
                &["spring.data.redis.ssl.enabled", "spring.redis.ssl"],
                false,
            )?,
        };
        validate_redis(&redis)?;

        let maildir = preferred(
            &properties,
            &["lmyzmail.maildir.base"],
            &["botmail.maildir.base"],
        )
        .unwrap_or("/var/lib/lmyzmail/data/mail")
        .to_owned();
        validate_path(&maildir, "maildir")?;
        let domain = preferred(
            &properties,
            &["lmyzmail.domains.main.domain", "lmyzmail.domain"],
            &["botmail.domains.main.domain"],
        )
        .unwrap_or("lmyz.net")
        .to_owned();
        validate_host(&domain, "domain")?;
        let allowed_origins = parse_allowed_origins(&properties)?;
        let trusted_proxies = parse_trusted_proxies(&properties)?;

        let outbound_route = OutboundRouteConfig {
            mx_l1_max_entries: preferred_u64(
                &properties,
                &["lmyzmail.outbound.dns.mx.l1-max-entries"],
                &["dns.cache.mx.l1-max-size"],
                10_000,
            )?,
            mx_l1_ttl_minutes: preferred_u64(
                &properties,
                &["lmyzmail.outbound.dns.mx.l1-ttl-minutes"],
                &["dns.cache.mx.l1-ttl-minutes"],
                15,
            )?,
            mx_l2_ttl_minutes: preferred_u64(
                &properties,
                &["lmyzmail.outbound.dns.mx.l2-ttl-minutes"],
                &["dns.cache.mx.l2-ttl-minutes"],
                30,
            )?,
            mx_negative_ttl_minutes: preferred_u64(
                &properties,
                &["lmyzmail.outbound.dns.mx.negative-ttl-minutes"],
                &["dns.cache.mx.negative-ttl-minutes"],
                5,
            )?,
            dns_query_timeout_seconds: preferred_u64(
                &properties,
                &["lmyzmail.outbound.dns.query-timeout-seconds"],
                &["dns.cache.mx.query-timeout-seconds"],
                15,
            )?,
            mta_sts_fetch_timeout_ms: preferred_u64(
                &properties,
                &["lmyzmail.smtp.mta-sts-fetch-timeout-ms"],
                &["botmail.smtp.mta-sts-fetch-timeout-ms"],
                10_000,
            )?,
            resolution_deadline_seconds: preferred_u64(
                &properties,
                &["lmyzmail.outbound.route-deadline-seconds"],
                &[],
                30,
            )?,
        };
        validate_outbound_route(&outbound_route)?;
        let xdp = parse_xdp_config(&properties)?;
        let cringe_decay = parse_cringe_decay_config(&properties)?;

        let features = FeatureConfig {
            public_registration: preferred_bool(
                &properties,
                &["lmyzmail.public-registration-enabled"],
                &["botmail.public-registration-enabled"],
                false,
            )?,
            smtp_skibidi_mode: preferred(
                &properties,
                &["lmyzmail.smtp.skibidi-generator-mode"],
                &["botmail.smtp.skibidi-generator-mode"],
            )
            .unwrap_or("AUTO_SAFE")
            .to_owned(),
            smtp_skibidi_enable_avx512: preferred_bool(
                &properties,
                &["lmyzmail.smtp.skibidi-generator-enable-avx512"],
                &["botmail.smtp.skibidi-generator-enable-avx512"],
                true,
            )?,
            smtp_skibidi_enable_simd_rng: preferred_bool(
                &properties,
                &["lmyzmail.smtp.skibidi-generator-enable-simd-rng"],
                &["botmail.smtp.skibidi-generator-enable-simd-rng"],
                true,
            )?,
            spamhaus: preferred_bool(
                &properties,
                &["lmyzmail.smtp-security.spamhaus-enabled"],
                &["botmail.smtp-security.spamhaus-enabled"],
                true,
            )?,
            tarpit: preferred_bool(
                &properties,
                &["lmyzmail.smtp-security.tarpit-enabled"],
                &["botmail.smtp-security.tarpit-enabled"],
                true,
            )?,
            mta_sts: preferred_bool(
                &properties,
                &["lmyzmail.smtp.mta-sts-enabled"],
                &["botmail.smtp.mta-sts-enabled"],
                true,
            )?,
            xdp: xdp.enabled,
            fail2ban: preferred_bool(
                &properties,
                &["lmyzmail.fail2ban.enabled"],
                &["botmail.fail2ban.enabled"],
                false,
            )?,
            report_delivery: preferred_bool(
                &properties,
                &["lmyzmail.reporting.http-delivery-enabled"],
                &["botmail.reporting.http-delivery-enabled"],
                true,
            )?,
            show_internet_nl_badge: preferred_bool(
                &properties,
                &["lmyzmail.show-internet-nl-badge"],
                &["botmail.show-internet-nl-badge"],
                false,
            )?,
        };

        let reporting = ReportingConfig {
            enabled: preferred_bool(
                &properties,
                &["lmyzmail.reporting.enabled"],
                &["botmail.reporting.enabled"],
                false,
            )?,
            auto_send_enabled: preferred_bool(
                &properties,
                &["lmyzmail.reporting.auto-send-enabled"],
                &["botmail.reporting.auto-send-enabled"],
                false,
            )?,
            batch_size: parse_number(
                &properties,
                &["lmyzmail.reporting.batch-size"],
                &["botmail.reporting.batch-size"],
                500_u32,
                "reporting batch size",
            )?,
            flush_interval_ms: parse_number(
                &properties,
                &["lmyzmail.reporting.flush-interval-ms"],
                &["botmail.reporting.flush-interval-ms"],
                2_000_u64,
                "reporting flush interval",
            )?,
            retention_days: parse_number(
                &properties,
                &["lmyzmail.reporting.retention-days"],
                &["botmail.reporting.retention-days"],
                90_u32,
                "reporting retention",
            )?,
            min_volume_for_report: parse_number(
                &properties,
                &["lmyzmail.reporting.min-volume-for-report"],
                &["botmail.reporting.min-volume-for-report"],
                10_i32,
                "reporting minimum volume",
            )?,
            dmarc_report_sender_address: preferred(
                &properties,
                &["lmyzmail.reporting.dmarc-report-sender-address"],
                &["botmail.reporting.dmarc-report-sender-address"],
            )
            .map(str::to_owned),
            dmarc_report_sender_password: preferred(
                &properties,
                &["lmyzmail.reporting.dmarc-report-sender-password"],
                &["botmail.reporting.dmarc-report-sender-password"],
            )
            .unwrap_or_default()
            .to_owned(),
            tls_report_sender_address: preferred(
                &properties,
                &["lmyzmail.reporting.tls-report-sender-address"],
                &["botmail.reporting.tls-report-sender-address"],
            )
            .map(str::to_owned),
            tls_report_sender_password: preferred(
                &properties,
                &["lmyzmail.reporting.tls-report-sender-password"],
                &["botmail.reporting.tls-report-sender-password"],
            )
            .unwrap_or_default()
            .to_owned(),
            organization_name: preferred(
                &properties,
                &["lmyzmail.reporting.organization-name"],
                &["botmail.reporting.organization-name"],
            )
            .map(str::to_owned),
            organization_email: preferred(
                &properties,
                &["lmyzmail.reporting.organization-email"],
                &["botmail.reporting.organization-email"],
            )
            .map(str::to_owned),
            http_delivery_enabled: features.report_delivery,
            http_delivery_timeout_seconds: parse_number(
                &properties,
                &["lmyzmail.reporting.http-delivery-timeout-seconds"],
                &["botmail.reporting.http-delivery-timeout-seconds"],
                30_u64,
                "reporting HTTP delivery timeout",
            )?,
            dns_server: preferred(
                &properties,
                &["lmyzmail.reporting.dns-server"],
                &["botmail.reporting.dns-server", "dns.server"],
            )
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value.parse::<SocketAddr>().map_err(|_| {
                    ConfigError::Invalid(
                        "reporting DNS server must be a numeric IP:port socket address".into(),
                    )
                })
            })
            .transpose()?,
        };
        validate_reporting(&reporting)?;

        let tls_enabled = preferred_bool(
            &properties,
            &["lmyzmail.ssl.use-custom-certificate"],
            &["botmail.ssl.use-custom-certificate"],
            false,
        )?;
        let tls_keystore_path = preferred(
            &properties,
            &["lmyzmail.ssl.keystore-path"],
            &["botmail.ssl.keystore-path"],
        )
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
        if let Some(path) = tls_keystore_path.as_deref() {
            validate_path(
                path.to_str()
                    .ok_or_else(|| ConfigError::Invalid("TLS keystore path is not UTF-8".into()))?,
                "ssl.keystore-path",
            )?;
        }
        if tls_enabled && tls_keystore_path.is_none() {
            return Err(ConfigError::Invalid(
                "TLS is enabled but no PKCS#12 keystore path is configured".into(),
            ));
        }
        let tls = TlsConfig {
            enabled: tls_enabled,
            keystore_path: tls_keystore_path,
            keystore_password: preferred(
                &properties,
                &["lmyzmail.ssl.keystore-password"],
                &["botmail.ssl.keystore-password"],
            )
            .unwrap_or("")
            .to_owned(),
        };

        let limits = LimitConfig {
            redis_pool: preferred_u32(
                &properties,
                &["lmyzmail.redis.pool.max-active"],
                &["spring.data.redis.lettuce.pool.max-active"],
                32,
            )?,
            postgres_pool: preferred_u32(
                &properties,
                &["lmyzmail.postgres.pool.max-size"],
                &["spring.datasource.hikari.maximum-pool-size"],
                32,
            )?,
            max_http_request_bytes: preferred_usize(
                &properties,
                &[
                    "lmyzmail.http.max-request-bytes",
                    "lmyzmail.netty.http.max-content-length",
                ],
                &["botmail.netty.http.max-content-length"],
                10 * 1024 * 1024,
            )?,
            max_http_connections: preferred_usize(
                &properties,
                &["lmyzmail.http.max-connections"],
                &[],
                256,
            )?,
            http_deadline_ms: preferred_http_deadline_ms(&properties)?,
            honeypot_initial_delay_ms: preferred_u64(
                &properties,
                &["lmyzmail.honeypot.initial-delay-ms"],
                &["botmail.honeypot.initial-delay-ms"],
                1_500,
            )?,
            honeypot_post_banner_timeout_ms: preferred_u64(
                &properties,
                &["lmyzmail.honeypot.post-banner-timeout-ms"],
                &["botmail.honeypot.post-banner-timeout-ms"],
                10_000,
            )?,
            max_honeypot_connections_per_trap: preferred_usize(
                &properties,
                &["lmyzmail.honeypot.max-connections-per-trap"],
                &["botmail.honeypot.max-connections-per-trap"],
                default_max_honeypot_connections_per_trap(),
            )?,
            max_honeypot_read_bytes: preferred_usize(
                &properties,
                &["lmyzmail.honeypot.max-read-bytes"],
                &["botmail.honeypot.max-read-bytes"],
                default_max_honeypot_read_bytes(),
            )?,
            max_email_size_bytes: preferred_u64(
                &properties,
                &["lmyzmail.max-email-size-bytes"],
                &["botmail.max-email-size-bytes"],
                default_max_email_size_bytes(),
            )?,
            max_attachment_size_bytes: preferred_u64(
                &properties,
                &["lmyzmail.max-attachment-size-bytes"],
                &["botmail.max-attachment-size-bytes"],
                default_max_attachment_size_bytes(),
            )?,
            max_total_attachments_size_bytes: preferred_u64(
                &properties,
                &["lmyzmail.max-total-attachments-size-bytes"],
                &["botmail.max-total-attachments-size-bytes"],
                default_max_total_attachments_size_bytes(),
            )?,
        };
        validate_limits(&limits)?;

        let honeypots = parse_honeypots(&properties, &listen_host)?;
        let api_keys = parse_api_keys(&properties)?;
        let listen = ListenConfig {
            host: listen_host,
            http,
            smtp,
            htcpcp,
            minecraft,
            honeypots,
        };
        validate_ports(&listen)?;

        Ok(Self {
            schema_version: 1,
            profile: preferred(
                &properties,
                &["lmyzmail.profile"],
                &["spring.profiles.active"],
            )
            .unwrap_or("production")
            .to_owned(),
            properties,
            listen,
            postgres,
            redis,
            maildir: PathBuf::from(maildir),
            domain,
            allowed_origins,
            trusted_proxies,
            api_keys,
            outbound_route,
            features,
            smtp_skibidi,
            content_filter,
            xdp,
            cringe_decay,
            reporting,
            htcpcp: htcpcp_config,
            minecraft: minecraft_config,
            mail_render,
            tls,
            limits,
        })
    }

    pub fn preferred_value(&self, new_key: &str, legacy_key: &str) -> Option<&str> {
        preferred(&self.properties, &[new_key], &[legacy_key])
    }
}

fn insert_optional_property(
    properties: &mut Properties,
    key: &str,
    value: Option<String>,
) -> Result<(), ConfigError> {
    if let Some(value) = value {
        properties.insert(key.to_owned(), value)?;
    }
    Ok(())
}

fn preferred<'a>(
    properties: &'a Properties,
    new_keys: &[&str],
    legacy_keys: &[&str],
) -> Option<&'a str> {
    new_keys
        .iter()
        .find_map(|key| properties.get(key))
        .or_else(|| legacy_keys.iter().find_map(|key| properties.get(key)))
}

fn parse_minecraft_config(properties: &Properties) -> Result<MinecraftConfig, ConfigError> {
    let enabled = preferred_bool(
        properties,
        &["lmyzmail.minecraft.enabled"],
        &["botmail.minecraft.enabled"],
        false,
    )?;
    let online_mode = preferred_bool(
        properties,
        &["lmyzmail.minecraft.online-mode"],
        &["botmail.minecraft.online-mode"],
        true,
    )?;
    let compression_threshold = preferred(
        properties,
        &["lmyzmail.minecraft.compression-threshold"],
        &["botmail.minecraft.compression-threshold"],
    )
    .map(|value| {
        value.parse::<i32>().map_err(|_| {
            ConfigError::Invalid("minecraft compression-threshold is not a signed integer".into())
        })
    })
    .transpose()?
    .unwrap_or_else(default_minecraft_compression_threshold);
    if !(-1..=MAX_MINECRAFT_COMPRESSION_THRESHOLD).contains(&compression_threshold) {
        return Err(ConfigError::Invalid(format!(
            "minecraft compression-threshold must be between -1 and {MAX_MINECRAFT_COMPRESSION_THRESHOLD}"
        )));
    }
    let max_players = preferred_u64(
        properties,
        &["lmyzmail.minecraft.max-players"],
        &["botmail.minecraft.max-players"],
        u64::from(default_minecraft_max_players()),
    )?;
    let max_players = u32::try_from(max_players).map_err(|_| {
        ConfigError::Invalid("minecraft max-players exceeds the supported range".into())
    })?;
    if max_players > MAX_MINECRAFT_PLAYERS {
        return Err(ConfigError::Invalid(format!(
            "minecraft max-players must be at most {MAX_MINECRAFT_PLAYERS}"
        )));
    }
    let motd = preferred(
        properties,
        &["lmyzmail.minecraft.motd"],
        &["botmail.minecraft.motd"],
    )
    .map(str::to_owned)
    .unwrap_or_else(default_minecraft_motd);
    if motd.chars().any(char::is_control) {
        return Err(ConfigError::Invalid(
            "minecraft motd contains control characters".into(),
        ));
    }
    let favicon = preferred(
        properties,
        &["lmyzmail.minecraft.favicon"],
        &["botmail.minecraft.favicon"],
    )
    .map(str::to_owned)
    .unwrap_or_default();
    let escaped_motd = motd.replace('\\', "\\\\").replace('"', "\\\"");
    let favicon_field = if favicon.trim().is_empty() {
        String::new()
    } else {
        format!(",\"favicon\":\"data:image/png;base64,{}\"", favicon.trim())
    };
    let status_json = format!(
        "{{\"version\":{{\"name\":\"1.8.9\",\"protocol\":47}},\"players\":{{\"max\":{max_players},\"online\":0,\"sample\":[]}},\"description\":{{\"text\":\"{escaped_motd}\"}}{favicon_field}}}"
    );
    if status_json.len() > MAX_MINECRAFT_STATUS_JSON_BYTES {
        return Err(ConfigError::Invalid(format!(
            "minecraft status JSON exceeds {MAX_MINECRAFT_STATUS_JSON_BYTES} UTF-8 bytes"
        )));
    }
    let read_timeout_seconds = preferred_u64(
        properties,
        &["lmyzmail.minecraft.read-timeout-seconds"],
        &["botmail.minecraft.read-timeout-seconds"],
        default_minecraft_read_timeout_seconds(),
    )?;
    if !(1..=MAX_MINECRAFT_READ_TIMEOUT_SECONDS).contains(&read_timeout_seconds) {
        return Err(ConfigError::Invalid(format!(
            "minecraft read-timeout-seconds must be between 1 and {MAX_MINECRAFT_READ_TIMEOUT_SECONDS}"
        )));
    }
    let session_server_url = preferred(
        properties,
        &["lmyzmail.minecraft.session-server-url"],
        &["botmail.minecraft.session-server-url"],
    )
    .map(str::to_owned)
    .unwrap_or_else(default_minecraft_session_server_url);
    validate_minecraft_session_server_url(&session_server_url)?;
    let world_template = preferred(
        properties,
        &["lmyzmail.minecraft.world-template"],
        &["botmail.minecraft.world-template"],
    )
    .map(str::to_owned)
    .unwrap_or_else(default_minecraft_world_template);
    if world_template.is_empty()
        || world_template.len() > 255
        || world_template.chars().any(char::is_control)
    {
        return Err(ConfigError::Invalid(
            "minecraft world-template must be a bounded non-control path".into(),
        ));
    }
    let view_distance = preferred_u64(
        properties,
        &["lmyzmail.minecraft.view-distance"],
        &["botmail.minecraft.view-distance"],
        default_minecraft_view_distance(),
    )?;
    if view_distance > MAX_MINECRAFT_VIEW_DISTANCE {
        return Err(ConfigError::Invalid(format!(
            "minecraft view-distance must be at most {MAX_MINECRAFT_VIEW_DISTANCE}"
        )));
    }
    let max_concurrent_videos = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.max-concurrent-videos"],
        &["botmail.minecraft.max-concurrent-videos"],
        default_minecraft_max_concurrent_videos(),
        1,
        MAX_MINECRAFT_VIDEO_SESSIONS,
        "minecraft max-concurrent-videos",
    )?;
    let spawn = MinecraftSpawnConfig {
        x: preferred_f64(
            properties,
            &["lmyzmail.minecraft.spawn.x"],
            &["botmail.minecraft.spawn.x"],
            default_minecraft_spawn_x(),
            "minecraft spawn.x",
        )?,
        y: preferred_f64(
            properties,
            &["lmyzmail.minecraft.spawn.y"],
            &["botmail.minecraft.spawn.y"],
            default_minecraft_spawn_y(),
            "minecraft spawn.y",
        )?,
        z: preferred_f64(
            properties,
            &["lmyzmail.minecraft.spawn.z"],
            &["botmail.minecraft.spawn.z"],
            default_minecraft_spawn_z(),
            "minecraft spawn.z",
        )?,
        yaw: preferred_f32(
            properties,
            &["lmyzmail.minecraft.spawn.yaw"],
            &["botmail.minecraft.spawn.yaw"],
            0.0,
            "minecraft spawn.yaw",
        )?,
        pitch: preferred_f32(
            properties,
            &["lmyzmail.minecraft.spawn.pitch"],
            &["botmail.minecraft.spawn.pitch"],
            0.0,
            "minecraft spawn.pitch",
        )?,
    };
    let map_facing = preferred(
        properties,
        &["lmyzmail.minecraft.map-video.facing"],
        &["botmail.minecraft.map-video.facing"],
    )
    .map(|value| match value.trim().to_ascii_uppercase().as_str() {
        "SOUTH" => "SOUTH".to_owned(),
        "WEST" => "WEST".to_owned(),
        "NORTH" => "NORTH".to_owned(),
        "EAST" => "EAST".to_owned(),
        _ => default_minecraft_map_facing(),
    })
    .unwrap_or_else(default_minecraft_map_facing);
    let video_center_x = preferred_i32(
        properties,
        &["lmyzmail.minecraft.video.center-x"],
        &["botmail.minecraft.video.center-x"],
        default_minecraft_video_center_x(),
    )?;
    let video_center_y = preferred_i32(
        properties,
        &["lmyzmail.minecraft.video.center-y"],
        &["botmail.minecraft.video.center-y"],
        default_minecraft_video_center_y(),
    )?;
    let video_wall_z = preferred_i32(
        properties,
        &["lmyzmail.minecraft.video.wall-z"],
        &["botmail.minecraft.video.wall-z"],
        default_minecraft_video_wall_z(),
    )?;
    validate_minecraft_video_coordinate(video_center_x, "minecraft video.center-x", false)?;
    validate_minecraft_video_coordinate(video_center_y, "minecraft video.center-y", true)?;
    validate_minecraft_video_coordinate(video_wall_z, "minecraft video.wall-z", false)?;
    let video_max_width = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.video.max-width"],
        &["botmail.minecraft.video.max-width"],
        default_minecraft_video_max_width(),
        4,
        MAX_MINECRAFT_BLOCK_VIDEO_WIDTH,
        "minecraft video.max-width",
    )?;
    let video_max_fps = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.video.max-fps"],
        &["botmail.minecraft.video.max-fps"],
        default_minecraft_video_max_fps(),
        1,
        MAX_MINECRAFT_VIDEO_FPS,
        "minecraft video.max-fps",
    )?;
    let video_default_width = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.video.default-width"],
        &["botmail.minecraft.video.default-width"],
        default_minecraft_video_default_width(),
        4,
        u64::from(video_max_width),
        "minecraft video.default-width",
    )?;
    let video_default_fps = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.video.default-fps"],
        &["botmail.minecraft.video.default-fps"],
        default_minecraft_video_default_fps(),
        1,
        u64::from(video_max_fps),
        "minecraft video.default-fps",
    )?;
    let video_default_contrast = preferred_f32(
        properties,
        &["lmyzmail.minecraft.video.default-contrast"],
        &["botmail.minecraft.video.default-contrast"],
        default_minecraft_video_default_contrast(),
        "minecraft video.default-contrast",
    )?;
    validate_minecraft_contrast(video_default_contrast, "minecraft video.default-contrast")?;
    let video_spawn_protect_radius = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.video.spawn-protect-radius"],
        &["botmail.minecraft.video.spawn-protect-radius"],
        default_minecraft_video_spawn_protect_radius(),
        0,
        MAX_MINECRAFT_VIDEO_SPAWN_PROTECT_RADIUS,
        "minecraft video.spawn-protect-radius",
    )?;
    let video_clear_margin = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.video.clear-margin"],
        &["botmail.minecraft.video.clear-margin"],
        default_minecraft_video_clear_margin(),
        0,
        MAX_MINECRAFT_VIDEO_CLEAR_MARGIN,
        "minecraft video.clear-margin",
    )?;
    let map_center_x = preferred_i32(
        properties,
        &["lmyzmail.minecraft.map-video.center-x"],
        &["botmail.minecraft.map-video.center-x"],
        default_minecraft_map_center_x(),
    )?;
    let map_center_y = preferred_i32(
        properties,
        &["lmyzmail.minecraft.map-video.center-y"],
        &["botmail.minecraft.map-video.center-y"],
        default_minecraft_map_center_y(),
    )?;
    let map_center_z = preferred_i32(
        properties,
        &["lmyzmail.minecraft.map-video.center-z"],
        &["botmail.minecraft.map-video.center-z"],
        default_minecraft_map_center_z(),
    )?;
    validate_minecraft_video_coordinate(map_center_x, "minecraft map-video.center-x", false)?;
    validate_minecraft_video_coordinate(map_center_y, "minecraft map-video.center-y", true)?;
    validate_minecraft_video_coordinate(map_center_z, "minecraft map-video.center-z", false)?;
    let map_max_maps_x = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.map-video.max-maps-x"],
        &["botmail.minecraft.map-video.max-maps-x"],
        default_minecraft_map_max_maps_x(),
        2,
        MAX_MINECRAFT_MAP_VIDEO_AXIS,
        "minecraft map-video.max-maps-x",
    )?;
    let map_max_maps_y = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.map-video.max-maps-y"],
        &["botmail.minecraft.map-video.max-maps-y"],
        default_minecraft_map_max_maps_y(),
        1,
        MAX_MINECRAFT_MAP_VIDEO_AXIS,
        "minecraft map-video.max-maps-y",
    )?;
    let map_max_fps = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.map-video.max-fps"],
        &["botmail.minecraft.map-video.max-fps"],
        default_minecraft_map_max_fps(),
        1,
        MAX_MINECRAFT_VIDEO_FPS,
        "minecraft map-video.max-fps",
    )?;
    let map_default_maps_x = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.map-video.default-maps-x"],
        &["botmail.minecraft.map-video.default-maps-x"],
        default_minecraft_map_default_maps_x(),
        2,
        u64::from(map_max_maps_x),
        "minecraft map-video.default-maps-x",
    )?;
    let map_default_fps = preferred_minecraft_u32(
        properties,
        &["lmyzmail.minecraft.map-video.default-fps"],
        &["botmail.minecraft.map-video.default-fps"],
        default_minecraft_map_default_fps(),
        1,
        u64::from(map_max_fps),
        "minecraft map-video.default-fps",
    )?;
    let map_default_contrast = preferred_f32(
        properties,
        &["lmyzmail.minecraft.map-video.default-contrast"],
        &["botmail.minecraft.map-video.default-contrast"],
        default_minecraft_map_default_contrast(),
        "minecraft map-video.default-contrast",
    )?;
    validate_minecraft_contrast(map_default_contrast, "minecraft map-video.default-contrast")?;
    let base_map_id = preferred_i32(
        properties,
        &["lmyzmail.minecraft.map-video.base-map-id"],
        &["botmail.minecraft.map-video.base-map-id"],
        default_minecraft_base_map_id(),
    )?;
    let base_entity_id = preferred_i32(
        properties,
        &["lmyzmail.minecraft.map-video.base-entity-id"],
        &["botmail.minecraft.map-video.base-entity-id"],
        default_minecraft_base_entity_id(),
    )?;
    if base_map_id < 0 || base_entity_id < 0 {
        return Err(ConfigError::Invalid(
            "minecraft map-video IDs must be non-negative".into(),
        ));
    }
    let map_slots = u64::from(map_max_maps_x)
        .checked_mul(u64::from(map_max_maps_y))
        .ok_or_else(|| ConfigError::Invalid("minecraft map-video dimensions overflow".into()))?;
    if i64::from(base_map_id) + i64::try_from(map_slots).unwrap_or(i64::MAX) > i64::from(i32::MAX)
        || i64::from(base_entity_id) + i64::try_from(map_slots).unwrap_or(i64::MAX)
            > i64::from(i32::MAX)
    {
        return Err(ConfigError::Invalid(
            "minecraft map-video IDs exceed the supported range".into(),
        ));
    }
    let video = MinecraftVideoConfig {
        center_x: video_center_x,
        center_y: video_center_y,
        wall_z: video_wall_z,
        max_width: video_max_width,
        max_fps: video_max_fps,
        default_width: video_default_width,
        default_fps: video_default_fps,
        default_contrast: video_default_contrast,
        spawn_protect_radius: video_spawn_protect_radius,
        clear_margin: video_clear_margin,
        map_center_x,
        map_center_y,
        map_center_z,
        map_facing,
        map_max_maps_x,
        map_max_maps_y,
        map_max_fps,
        map_default_maps_x,
        map_default_fps,
        map_default_contrast,
        base_map_id,
        base_entity_id,
    };
    let whitelist_enabled = preferred_bool(
        properties,
        &["lmyzmail.minecraft.whitelist.enabled"],
        &["botmail.minecraft.whitelist.enabled"],
        false,
    )?;
    let whitelist_players = parse_minecraft_player_list(
        properties,
        "lmyzmail.minecraft.whitelist.players",
        "botmail.minecraft.whitelist.players",
        "minecraft whitelist",
    )?;
    let blacklist_players = parse_minecraft_player_list(
        properties,
        "lmyzmail.minecraft.blacklist.players",
        "botmail.minecraft.blacklist.players",
        "minecraft blacklist",
    )?;
    let auth_max_attempts = preferred_u64(
        properties,
        &["lmyzmail.minecraft.auth.max-attempts"],
        &["botmail.minecraft.auth.max-attempts"],
        u64::from(default_minecraft_auth_max_attempts()),
    )?;
    if !(1..=1_000).contains(&auth_max_attempts) {
        return Err(ConfigError::Invalid(
            "minecraft auth.max-attempts must be between 1 and 1000".into(),
        ));
    }
    let auth_lockout_seconds = preferred_u64(
        properties,
        &["lmyzmail.minecraft.auth.lockout-seconds"],
        &["botmail.minecraft.auth.lockout-seconds"],
        default_minecraft_auth_lockout_seconds(),
    )?;
    if !(1..=86_400).contains(&auth_lockout_seconds) {
        return Err(ConfigError::Invalid(
            "minecraft auth.lockout-seconds must be between 1 and 86400".into(),
        ));
    }
    let auth_window_seconds = preferred_u64(
        properties,
        &["lmyzmail.minecraft.auth.window-seconds"],
        &["botmail.minecraft.auth.window-seconds"],
        default_minecraft_auth_window_seconds(),
    )?;
    if !(1..=86_400).contains(&auth_window_seconds) {
        return Err(ConfigError::Invalid(
            "minecraft auth.window-seconds must be between 1 and 86400".into(),
        ));
    }
    Ok(MinecraftConfig {
        enabled,
        online_mode,
        compression_threshold,
        max_players,
        motd,
        favicon,
        read_timeout_seconds,
        session_server_url,
        world_template,
        view_distance: u32::try_from(view_distance).map_err(|_| {
            ConfigError::Invalid("minecraft view-distance exceeds the supported range".into())
        })?,
        max_concurrent_videos,
        spawn,
        video,
        whitelist_enabled,
        whitelist_players,
        blacklist_players,
        auth_max_attempts: u32::try_from(auth_max_attempts).map_err(|_| {
            ConfigError::Invalid("minecraft auth.max-attempts exceeds the supported range".into())
        })?,
        auth_lockout_seconds,
        auth_window_seconds,
    })
}

fn parse_mail_render_simd_mode(value: Option<&str>) -> MailRenderSimdMode {
    match value.map(str::to_ascii_uppercase).as_deref() {
        Some("SCALAR") => MailRenderSimdMode::Scalar,
        Some("AVX2") => MailRenderSimdMode::Avx2,
        Some("AVX512") => MailRenderSimdMode::Avx512,
        Some("AUTO") | Some(_) | None => MailRenderSimdMode::Auto,
    }
}

fn parse_smtp_skibidi_config(properties: &Properties) -> Result<SmtpSkibidiConfig, ConfigError> {
    let enabled = preferred_bool(
        properties,
        &["lmyzmail.smtp.skibidi-toilet-quiz-enabled"],
        &["botmail.smtp.skibidi-toilet-quiz-enabled"],
        true,
    )?;
    let max_width = preferred_minecraft_u32(
        properties,
        &["lmyzmail.smtp.asciiart.max-width"],
        &["botmail.smtp.asciiart.max-width"],
        default_smtp_ascii_max_width(),
        MIN_SMTP_ASCII_WIDTH,
        MAX_SMTP_ASCII_WIDTH,
        "smtp asciiart.max-width",
    )?;
    let max_fps = preferred_f32(
        properties,
        &["lmyzmail.smtp.asciiart.max-fps"],
        &["botmail.smtp.asciiart.max-fps"],
        default_smtp_ascii_max_fps(),
        "smtp asciiart.max-fps",
    )?;
    validate_smtp_ascii_fps(max_fps, "smtp asciiart.max-fps")?;
    let default_width = preferred_minecraft_u32(
        properties,
        &["lmyzmail.smtp.asciiart.default-width"],
        &["botmail.smtp.asciiart.default-width"],
        default_smtp_ascii_default_width(),
        MIN_SMTP_ASCII_WIDTH,
        u64::from(max_width),
        "smtp asciiart.default-width",
    )?;
    let default_fps = preferred_f32(
        properties,
        &["lmyzmail.smtp.asciiart.default-fps"],
        &["botmail.smtp.asciiart.default-fps"],
        default_smtp_ascii_default_fps(),
        "smtp asciiart.default-fps",
    )?;
    validate_smtp_ascii_fps(default_fps, "smtp asciiart.default-fps")?;
    if default_fps > max_fps {
        return Err(ConfigError::Invalid(
            "smtp asciiart.default-fps must not exceed smtp asciiart.max-fps".into(),
        ));
    }
    let default_contrast = preferred_f32(
        properties,
        &["lmyzmail.smtp.asciiart.default-contrast"],
        &["botmail.smtp.asciiart.default-contrast"],
        default_smtp_ascii_default_contrast(),
        "smtp asciiart.default-contrast",
    )?;
    validate_smtp_ascii_contrast(default_contrast, "smtp asciiart.default-contrast")?;
    let char_aspect = preferred_f32(
        properties,
        &["lmyzmail.smtp.asciiart.char-aspect"],
        &["botmail.smtp.asciiart.char-aspect"],
        default_smtp_ascii_char_aspect(),
        "smtp asciiart.char-aspect",
    )?;
    validate_smtp_ascii_aspect(char_aspect, "smtp asciiart.char-aspect")?;
    Ok(SmtpSkibidiConfig {
        enabled,
        ascii: SmtpAsciiConfig {
            simd_mode: parse_mail_render_simd_mode(preferred(
                properties,
                &["lmyzmail.smtp.asciiart.simd-mode"],
                &["botmail.smtp.asciiart.simd-mode"],
            )),
            max_width,
            max_fps,
            default_width,
            default_fps,
            default_contrast,
            char_aspect,
        },
    })
}

fn parse_content_filter_config(
    properties: &Properties,
) -> Result<ContentFilterConfig, ConfigError> {
    let suspicious_threshold = preferred_f64(
        properties,
        &["lmyzmail.contentfilter.suspicious-threshold"],
        &["botmail.contentfilter.suspicious-threshold"],
        5.0,
        "contentfilter suspicious-threshold",
    )?;
    validate_content_filter_number(
        suspicious_threshold,
        MAX_CONTENT_FILTER_THRESHOLD,
        "contentfilter suspicious-threshold",
    )?;
    let spam_threshold = preferred_f64(
        properties,
        &["lmyzmail.contentfilter.spam-threshold"],
        &["botmail.contentfilter.spam-threshold"],
        10.0,
        "contentfilter spam-threshold",
    )?;
    validate_content_filter_number(
        spam_threshold,
        MAX_CONTENT_FILTER_THRESHOLD,
        "contentfilter spam-threshold",
    )?;
    if spam_threshold < suspicious_threshold {
        return Err(ConfigError::Invalid(
            "contentfilter spam-threshold must not be below suspicious-threshold".into(),
        ));
    }
    let attachment = parse_content_filter_attachment(properties)?;
    Ok(ContentFilterConfig {
        enabled: preferred_bool(
            properties,
            &["lmyzmail.contentfilter.enabled"],
            &["botmail.contentfilter.enabled"],
            true,
        )?,
        suspicious_threshold,
        spam_threshold,
        rbl_check: parse_content_filter_rule(properties, "RBL_CHECK")?,
        rbl: parse_content_filter_rbl(properties)?,
        new_domain: parse_content_filter_rule(properties, "NEW_DOMAIN")?,
        missing_headers: parse_content_filter_rule(properties, "MISSING_HEADERS")?,
        subject_encoding_trick: parse_content_filter_rule(properties, "SUBJECT_ENCODING_TRICK")?,
        excessive_recipients: parse_content_filter_rule(properties, "EXCESSIVE_RECIPIENTS")?,
        dangerous_extension: parse_content_filter_rule(properties, "DANGEROUS_EXTENSION")?,
        double_extension: parse_content_filter_rule(properties, "DOUBLE_EXTENSION")?,
        mime_type_mismatch: parse_content_filter_rule(properties, "MIME_TYPE_MISMATCH")?,
        attachment,
    })
}

fn parse_content_filter_rbl(
    properties: &Properties,
) -> Result<ContentFilterRblConfig, ConfigError> {
    let defaults = ContentFilterRblConfig::default();
    let servers = preferred(
        properties,
        &["lmyzmail.contentfilter.rbl.servers"],
        &["botmail.contentfilter.rbl.servers"],
    )
    .map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
    })
    .unwrap_or(defaults.servers);
    if servers.len() > MAX_CONTENT_FILTER_RBL_SERVERS
        || servers.iter().any(|server| !valid_rbl_server(server))
    {
        return Err(ConfigError::Invalid(format!(
            "contentfilter RBL servers must contain at most {MAX_CONTENT_FILTER_RBL_SERVERS} bounded DNS names"
        )));
    }
    let timeout_ms = preferred_u64(
        properties,
        &["lmyzmail.contentfilter.rbl.timeout-ms"],
        &["botmail.contentfilter.rbl.timeout-ms"],
        defaults.timeout.as_millis() as u64,
    )?;
    if !(1..=MAX_CONTENT_FILTER_RBL_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(ConfigError::Invalid(format!(
            "contentfilter RBL timeout-ms must be between 1 and {MAX_CONTENT_FILTER_RBL_TIMEOUT_MS}"
        )));
    }
    let score_per_hit = preferred_f64(
        properties,
        &["lmyzmail.contentfilter.rbl.score-per-hit"],
        &["botmail.contentfilter.rbl.score-per-hit"],
        defaults.score_per_hit,
        "contentfilter RBL score-per-hit",
    )?;
    let max_score = preferred_f64(
        properties,
        &["lmyzmail.contentfilter.rbl.max-score"],
        &["botmail.contentfilter.rbl.max-score"],
        defaults.max_score,
        "contentfilter RBL max-score",
    )?;
    validate_content_filter_number(
        score_per_hit,
        MAX_CONTENT_FILTER_THRESHOLD,
        "contentfilter RBL score-per-hit",
    )?;
    validate_content_filter_number(
        max_score,
        MAX_CONTENT_FILTER_THRESHOLD,
        "contentfilter RBL max-score",
    )?;
    Ok(ContentFilterRblConfig {
        enabled: preferred_bool(
            properties,
            &["lmyzmail.contentfilter.rbl.enabled"],
            &["botmail.contentfilter.rbl.enabled"],
            defaults.enabled,
        )?,
        servers,
        timeout: Duration::from_millis(timeout_ms),
        score_per_hit,
        max_score,
    })
}

fn valid_rbl_server(server: &str) -> bool {
    if server.is_empty() || server.len() > MAX_CONTENT_FILTER_RBL_SERVER_BYTES {
        return false;
    }
    let name = server.strip_suffix('.').unwrap_or(server);
    !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn parse_content_filter_attachment(
    properties: &Properties,
) -> Result<ContentFilterAttachmentConfig, ConfigError> {
    let defaults = ContentFilterAttachmentConfig::default();
    let dangerous_extensions = preferred(
        properties,
        &["lmyzmail.contentfilter.attachment.dangerous-extensions"],
        &["botmail.contentfilter.attachment.dangerous-extensions"],
    )
    .map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase())
            .collect::<Vec<_>>()
    })
    .unwrap_or(defaults.dangerous_extensions);
    if dangerous_extensions.is_empty()
        || dangerous_extensions.len() > MAX_CONTENT_FILTER_EXTENSIONS
        || dangerous_extensions.iter().any(|extension| {
            extension.len() > MAX_CONTENT_FILTER_EXTENSION_BYTES
                || !extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        return Err(ConfigError::Invalid(
            "contentfilter dangerous extensions must be a non-empty bounded ASCII list".into(),
        ));
    }

    let dangerous_extension_score = preferred_f64(
        properties,
        &["lmyzmail.contentfilter.attachment.dangerous-extension-score"],
        &["botmail.contentfilter.attachment.dangerous-extension-score"],
        defaults.dangerous_extension_score,
        "contentfilter dangerous-extension-score",
    )?;
    let double_extension_score = preferred_f64(
        properties,
        &["lmyzmail.contentfilter.attachment.double-extension-score"],
        &["botmail.contentfilter.attachment.double-extension-score"],
        defaults.double_extension_score,
        "contentfilter double-extension-score",
    )?;
    let mime_type_mismatch_score = preferred_f64(
        properties,
        &["lmyzmail.contentfilter.attachment.mime-type-mismatch-score"],
        &["botmail.contentfilter.attachment.mime-type-mismatch-score"],
        defaults.mime_type_mismatch_score,
        "contentfilter mime-type-mismatch-score",
    )?;
    for (value, label) in [
        (
            dangerous_extension_score,
            "contentfilter dangerous-extension-score",
        ),
        (
            double_extension_score,
            "contentfilter double-extension-score",
        ),
        (
            mime_type_mismatch_score,
            "contentfilter mime-type-mismatch-score",
        ),
    ] {
        validate_content_filter_number(value, MAX_CONTENT_FILTER_THRESHOLD, label)?;
    }

    Ok(ContentFilterAttachmentConfig {
        enabled: preferred_bool(
            properties,
            &["lmyzmail.contentfilter.attachment.enabled"],
            &["botmail.contentfilter.attachment.enabled"],
            true,
        )?,
        dangerous_extensions,
        dangerous_extension_score,
        double_extension_score,
        mime_type_mismatch_score,
    })
}

fn parse_content_filter_rule(
    properties: &Properties,
    name: &str,
) -> Result<ContentFilterRuleConfig, ConfigError> {
    let new_prefix = format!("lmyzmail.contentfilter.rules.{name}");
    let legacy_prefix = format!("botmail.contentfilter.rules.{name}");
    let new_enabled = format!("{new_prefix}.enabled");
    let legacy_enabled = format!("{legacy_prefix}.enabled");
    let new_weight = format!("{new_prefix}.weight");
    let legacy_weight = format!("{legacy_prefix}.weight");
    let weight = preferred_f64(
        properties,
        &[new_weight.as_str()],
        &[legacy_weight.as_str()],
        1.0,
        &format!("contentfilter rule {name} weight"),
    )?;
    validate_content_filter_number(
        weight,
        MAX_CONTENT_FILTER_RULE_WEIGHT,
        &format!("contentfilter rule {name} weight"),
    )?;
    Ok(ContentFilterRuleConfig {
        enabled: preferred_bool(
            properties,
            &[new_enabled.as_str()],
            &[legacy_enabled.as_str()],
            true,
        )?,
        weight,
    })
}

fn validate_content_filter_number(
    value: f64,
    maximum: f64,
    label: &str,
) -> Result<(), ConfigError> {
    if !value.is_finite() || !(0.0..=maximum).contains(&value) {
        return Err(ConfigError::Invalid(format!(
            "{label} must be a finite value between 0 and {maximum}"
        )));
    }
    Ok(())
}

fn validate_smtp_ascii_fps(value: f32, label: &str) -> Result<(), ConfigError> {
    if !value.is_finite() || !(MIN_SMTP_ASCII_FPS..=MAX_SMTP_ASCII_FPS).contains(&value) {
        return Err(ConfigError::Invalid(format!(
            "{label} must be a finite value between {MIN_SMTP_ASCII_FPS} and {MAX_SMTP_ASCII_FPS}"
        )));
    }
    Ok(())
}

fn validate_smtp_ascii_contrast(value: f32, label: &str) -> Result<(), ConfigError> {
    if !value.is_finite() || !(MIN_SMTP_ASCII_CONTRAST..=MAX_SMTP_ASCII_CONTRAST).contains(&value) {
        return Err(ConfigError::Invalid(format!(
            "{label} must be a finite value between {MIN_SMTP_ASCII_CONTRAST} and {MAX_SMTP_ASCII_CONTRAST}"
        )));
    }
    Ok(())
}

fn validate_smtp_ascii_aspect(value: f32, label: &str) -> Result<(), ConfigError> {
    if !value.is_finite() || !(MIN_SMTP_ASCII_ASPECT..=MAX_SMTP_ASCII_ASPECT).contains(&value) {
        return Err(ConfigError::Invalid(format!(
            "{label} must be a finite value between {MIN_SMTP_ASCII_ASPECT} and {MAX_SMTP_ASCII_ASPECT}"
        )));
    }
    Ok(())
}

fn validate_minecraft_session_server_url(raw: &str) -> Result<(), ConfigError> {
    let parsed = Url::parse(raw)
        .map_err(|_| ConfigError::Invalid("minecraft session-server-url is invalid".into()))?;
    let host = parsed.host_str().ok_or_else(|| {
        ConfigError::Invalid("minecraft session-server-url requires a host".into())
    })?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        return Err(ConfigError::Invalid(
            "minecraft session-server-url must use HTTPS, except for loopback fixtures".into(),
        ));
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::Invalid(
            "minecraft session-server-url must not contain credentials, query, or fragment".into(),
        ));
    }
    Ok(())
}

fn preferred_f64(
    properties: &Properties,
    new_keys: &[&str],
    legacy_keys: &[&str],
    default: f64,
    label: &str,
) -> Result<f64, ConfigError> {
    preferred(properties, new_keys, legacy_keys)
        .map(|value| {
            value
                .parse::<f64>()
                .map_err(|_| ConfigError::Invalid(format!("{label} is not a double")))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn preferred_f32(
    properties: &Properties,
    new_keys: &[&str],
    legacy_keys: &[&str],
    default: f32,
    label: &str,
) -> Result<f32, ConfigError> {
    preferred(properties, new_keys, legacy_keys)
        .map(|value| {
            value
                .parse::<f32>()
                .map_err(|_| ConfigError::Invalid(format!("{label} is not a float")))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn parse_minecraft_player_list(
    properties: &Properties,
    new_prefix: &str,
    legacy_prefix: &str,
    label: &str,
) -> Result<Vec<String>, ConfigError> {
    let scalar_new = properties.get(new_prefix);
    let indexed_new = properties.get(&format!("{new_prefix}[0]")).is_some();
    let scalar_legacy = properties.get(legacy_prefix);
    let indexed_legacy = properties.get(&format!("{legacy_prefix}[0]")).is_some();

    let raw_values = if let Some(value) = scalar_new {
        split_minecraft_player_list(value)
    } else if indexed_new {
        indexed_minecraft_player_list(properties, new_prefix)
    } else if let Some(value) = scalar_legacy {
        split_minecraft_player_list(value)
    } else if indexed_legacy {
        indexed_minecraft_player_list(properties, legacy_prefix)
    } else {
        Vec::new()
    };
    let mut players = Vec::with_capacity(raw_values.len());
    for value in raw_values {
        let value = value.trim();
        if value.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "{label} contains an empty entry"
            )));
        }
        players.push(value.to_owned());
    }
    Ok(players)
}

fn split_minecraft_player_list(value: &str) -> Vec<&str> {
    if value.trim().is_empty() {
        Vec::new()
    } else {
        value.split(',').collect()
    }
}

fn indexed_minecraft_player_list<'a>(properties: &'a Properties, prefix: &str) -> Vec<&'a str> {
    (0..MAX_PROPERTY_COUNT)
        .map_while(|index| properties.get(&format!("{prefix}[{index}]")))
        .collect()
}

fn parse_htcpcp_config(properties: &Properties) -> Result<HtcpcpConfig, ConfigError> {
    let enabled = preferred_bool(
        properties,
        &["lmyzmail.htcpcp.enabled"],
        &["botmail.htcpcp.enabled"],
        false,
    )?;
    let default_brew_time_seconds = preferred_u64(
        properties,
        &["lmyzmail.htcpcp.default-brew-time-seconds"],
        &["botmail.htcpcp.default-brew-time-seconds"],
        default_htcpcp_brew_seconds(),
    )?;
    if default_brew_time_seconds > MAX_HTCPCP_BREW_SECONDS {
        return Err(ConfigError::Invalid(format!(
            "HTCPCP brew time must not exceed {MAX_HTCPCP_BREW_SECONDS} seconds"
        )));
    }

    let new_prefix = "lmyzmail.htcpcp.pots";
    let legacy_prefix = "botmail.htcpcp.pots";
    let has_new = properties
        .iter()
        .any(|(key, _)| key.starts_with(&format!("{new_prefix}[")));
    let has_legacy = properties
        .iter()
        .any(|(key, _)| key.starts_with(&format!("{legacy_prefix}[")));
    let pots = if has_new {
        parse_htcpcp_pots(properties, new_prefix)?
    } else if has_legacy {
        parse_htcpcp_pots(properties, legacy_prefix)?
    } else {
        vec![HtcpcpPotConfig {
            id: default_htcpcp_pot_id(),
            pot_type: default_htcpcp_pot_type(),
            tea_varieties: default_htcpcp_tea_varieties(),
            supported_additions: default_htcpcp_additions(),
        }]
    };
    Ok(HtcpcpConfig {
        enabled,
        default_brew_time_seconds,
        pots,
    })
}

fn parse_htcpcp_pots(
    properties: &Properties,
    prefix: &str,
) -> Result<Vec<HtcpcpPotConfig>, ConfigError> {
    let mut indices = HashSet::new();
    let marker = format!("{prefix}[");
    for (key, _) in properties
        .iter()
        .filter(|(key, _)| key.starts_with(&marker))
    {
        let rest = &key[marker.len()..];
        let (raw_index, suffix) = rest.split_once(']').ok_or_else(|| {
            ConfigError::Invalid(format!("invalid HTCPCP pot property key: {key}"))
        })?;
        if !suffix.starts_with('.') || suffix.len() == 1 {
            return Err(ConfigError::Invalid(format!(
                "invalid HTCPCP pot property key: {key}"
            )));
        }
        let index = raw_index.parse::<usize>().map_err(|_| {
            ConfigError::Invalid(format!("invalid HTCPCP pot index in property: {key}"))
        })?;
        if index >= MAX_HTCPCP_POTS {
            return Err(ConfigError::Invalid(format!(
                "HTCPCP config contains more than {MAX_HTCPCP_POTS} pots"
            )));
        }
        indices.insert(index);
    }
    if indices.is_empty() {
        return Err(ConfigError::Invalid(
            "HTCPCP pot configuration must contain at least one pot".into(),
        ));
    }
    let count = indices.iter().max().copied().unwrap_or(0) + 1;
    if indices.len() != count || (0..count).any(|index| !indices.contains(&index)) {
        return Err(ConfigError::Invalid(
            "HTCPCP pot indices must be contiguous starting at zero".into(),
        ));
    }

    let mut pots = Vec::with_capacity(count);
    let mut ids = HashSet::with_capacity(count);
    for index in 0..count {
        let pot_prefix = format!("{prefix}[{index}]");
        let id = properties
            .get(&format!("{pot_prefix}.id"))
            .unwrap_or("pot-0")
            .to_owned();
        validate_simple(&id, 128, &format!("htcpcp.pots[{index}].id"))?;
        if !ids.insert(id.clone()) {
            return Err(ConfigError::Invalid(format!(
                "HTCPCP pot id is duplicated: {id}"
            )));
        }
        let pot_type = properties
            .get(&format!("{pot_prefix}.type"))
            .unwrap_or("coffee")
            .to_ascii_lowercase();
        let type_field = format!("htcpcp.pots[{index}].type");
        validate_simple(&pot_type, 32, &type_field)?;
        if !matches!(pot_type.as_str(), "coffee" | "tea" | "both") {
            return Err(ConfigError::Invalid(format!(
                "{type_field} must be one of coffee, tea, or both"
            )));
        }
        let tea_varieties = parse_htcpcp_csv(
            properties.get(&format!("{pot_prefix}.tea-varieties")),
            default_htcpcp_tea_varieties,
            &format!("htcpcp.pots[{index}].tea-varieties"),
        )?;
        let supported_additions = parse_htcpcp_csv(
            properties.get(&format!("{pot_prefix}.supported-additions")),
            default_htcpcp_additions,
            &format!("htcpcp.pots[{index}].supported-additions"),
        )?;
        pots.push(HtcpcpPotConfig {
            id,
            pot_type,
            tea_varieties,
            supported_additions,
        });
    }
    Ok(pots)
}

fn parse_htcpcp_csv(
    value: Option<&str>,
    default: fn() -> Vec<String>,
    field: &str,
) -> Result<Vec<String>, ConfigError> {
    let Some(value) = value else {
        return Ok(default());
    };
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let items: Vec<String> = value
        .split(',')
        .map(|item| item.trim().to_owned())
        .collect();
    if items.len() > MAX_HTCPCP_LIST_ITEMS {
        return Err(ConfigError::Invalid(format!(
            "{field} contains more than {MAX_HTCPCP_LIST_ITEMS} values"
        )));
    }
    let mut unique = HashSet::with_capacity(items.len());
    for item in &items {
        validate_simple(item, 128, field)?;
        if !unique.insert(item.to_ascii_lowercase()) {
            return Err(ConfigError::Invalid(format!(
                "{field} contains a duplicate value: {item}"
            )));
        }
    }
    Ok(items)
}

#[derive(Debug, Clone)]
struct ParsedPostgresUrl {
    host: Option<String>,
    port: Option<u16>,
    database: Option<String>,
}

fn parse_postgres_url(raw: &str) -> Option<ParsedPostgresUrl> {
    let normalized = raw.strip_prefix("jdbc:").unwrap_or(raw);
    let url = Url::parse(normalized).ok()?;
    if !matches!(url.scheme(), "postgresql" | "postgres") {
        return None;
    }
    let host = url.host_str().map(str::to_owned);
    let database = url
        .path()
        .trim_start_matches('/')
        .split('/')
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Some(ParsedPostgresUrl {
        host,
        port: url.port(),
        database,
    })
}

fn parse_number<T: str::FromStr>(
    properties: &Properties,
    new_keys: &[&str],
    legacy_keys: &[&str],
    default: T,
    description: &str,
) -> Result<T, ConfigError> {
    let Some(value) = preferred(properties, new_keys, legacy_keys) else {
        return Ok(default);
    };
    value
        .parse::<T>()
        .map_err(|_| ConfigError::Invalid(format!("{description} is not a valid number")))
}

fn preferred_u8(
    properties: &Properties,
    new: &[&str],
    legacy: &[&str],
    default: u8,
) -> Result<u8, ConfigError> {
    parse_number(properties, new, legacy, default, "redis database")
}

fn preferred_i32(
    properties: &Properties,
    new_keys: &[&str],
    legacy_keys: &[&str],
    default: i32,
) -> Result<i32, ConfigError> {
    parse_number(
        properties,
        new_keys,
        legacy_keys,
        default,
        "minecraft video coordinate",
    )
}

fn preferred_minecraft_u32(
    properties: &Properties,
    new_keys: &[&str],
    legacy_keys: &[&str],
    default: u32,
    min: u64,
    max: u64,
    label: &str,
) -> Result<u32, ConfigError> {
    let parsed = preferred(properties, new_keys, legacy_keys)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| ConfigError::Invalid(format!("{label} is not an unsigned integer")))
        })
        .transpose()?
        .unwrap_or(u64::from(default));
    if !(min..=max).contains(&parsed) {
        return Err(ConfigError::Invalid(format!(
            "{label} must be between {min} and {max}"
        )));
    }
    u32::try_from(parsed)
        .map_err(|_| ConfigError::Invalid(format!("{label} exceeds the supported range")))
}

fn validate_minecraft_video_coordinate(
    value: i32,
    label: &str,
    vertical: bool,
) -> Result<(), ConfigError> {
    let valid = if vertical {
        (0..=MAX_MINECRAFT_WORLD_Y).contains(&value)
    } else {
        (-MAX_MINECRAFT_WORLD_COORDINATE..=MAX_MINECRAFT_WORLD_COORDINATE).contains(&value)
    };
    if !valid {
        let range = if vertical {
            format!("0 and {MAX_MINECRAFT_WORLD_Y}")
        } else {
            format!(
                "{} and {MAX_MINECRAFT_WORLD_COORDINATE}",
                -MAX_MINECRAFT_WORLD_COORDINATE
            )
        };
        return Err(ConfigError::Invalid(format!(
            "{label} must be between {range}"
        )));
    }
    Ok(())
}

fn validate_minecraft_contrast(value: f32, label: &str) -> Result<(), ConfigError> {
    if !value.is_finite() || !(0.1..=3.0).contains(&value) {
        return Err(ConfigError::Invalid(format!(
            "{label} must be a finite value between 0.1 and 3.0"
        )));
    }
    Ok(())
}

fn preferred_u16(
    properties: &Properties,
    new: &[&str],
    legacy: &[&str],
    default: u16,
) -> Result<u16, ConfigError> {
    parse_number(properties, new, legacy, default, "port")
}

fn preferred_u32(
    properties: &Properties,
    new: &[&str],
    legacy: &[&str],
    default: u32,
) -> Result<u32, ConfigError> {
    parse_number(properties, new, legacy, default, "pool size")
}

fn preferred_u64(
    properties: &Properties,
    new: &[&str],
    legacy: &[&str],
    default: u64,
) -> Result<u64, ConfigError> {
    parse_number(properties, new, legacy, default, "duration")
}

fn preferred_http_deadline_ms(properties: &Properties) -> Result<u64, ConfigError> {
    if let Some(value) = preferred(properties, &["lmyzmail.http.request-timeout-ms"], &[]) {
        return value.parse::<u64>().map_err(|_| {
            ConfigError::Invalid("lmyzmail.http.request-timeout-ms is not a valid number".into())
        });
    }
    let Some(seconds) = properties.get("botmail.netty.http.idle-timeout-seconds") else {
        return Ok(10_000);
    };
    seconds
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(1_000))
        .ok_or_else(|| {
            ConfigError::Invalid(
                "botmail.netty.http.idle-timeout-seconds is invalid or overflows milliseconds"
                    .into(),
            )
        })
}

fn preferred_usize(
    properties: &Properties,
    new: &[&str],
    legacy: &[&str],
    default: usize,
) -> Result<usize, ConfigError> {
    parse_number(properties, new, legacy, default, "limit")
}

fn preferred_bool(
    properties: &Properties,
    new: &[&str],
    legacy: &[&str],
    default: bool,
) -> Result<bool, ConfigError> {
    let Some(value) = preferred(properties, new, legacy) else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::Invalid(format!(
            "invalid boolean value: {value}"
        ))),
    }
}

fn parse_allowed_origins(properties: &Properties) -> Result<Vec<String>, ConfigError> {
    let mut origins = Vec::new();
    for index in 0..MAX_ALLOWED_ORIGINS {
        let new_key = format!("lmyzmail.allowed-origins[{index}]");
        let legacy_key = format!("botmail.allowed-origins[{index}]");
        let Some(origin) = preferred(properties, &[&new_key], &[&legacy_key]) else {
            break;
        };
        validate_origin_pattern(origin)?;
        origins.push(origin.to_owned());
    }
    Ok(origins)
}

fn parse_trusted_proxies(properties: &Properties) -> Result<Vec<IpNet>, ConfigError> {
    let scalar_new = preferred(
        properties,
        &[
            "lmyzmail.http.trusted-proxies",
            "lmyzmail.netty.http.trusted-proxies",
        ],
        &[],
    );
    let indexed_new = properties.get("lmyzmail.http.trusted-proxies[0]").is_some();
    let scalar_legacy = properties.get("botmail.netty.http.trusted-proxies");
    let indexed_legacy = properties
        .get("botmail.netty.http.trusted-proxies[0]")
        .is_some();

    let raw_values = if let Some(value) = scalar_new {
        if value.trim().is_empty() {
            Vec::new()
        } else {
            value.split(',').map(str::trim).collect::<Vec<_>>()
        }
    } else if indexed_new {
        (0..MAX_TRUSTED_PROXIES)
            .map_while(|index| properties.get(&format!("lmyzmail.http.trusted-proxies[{index}]")))
            .collect()
    } else if let Some(value) = scalar_legacy {
        if value.trim().is_empty() {
            Vec::new()
        } else {
            value.split(',').map(str::trim).collect::<Vec<_>>()
        }
    } else if indexed_legacy {
        (0..MAX_TRUSTED_PROXIES)
            .map_while(|index| {
                properties.get(&format!("botmail.netty.http.trusted-proxies[{index}]"))
            })
            .collect()
    } else {
        Vec::new()
    };
    if raw_values.len() > MAX_TRUSTED_PROXIES {
        return Err(ConfigError::Invalid(format!(
            "trusted proxy list exceeds {MAX_TRUSTED_PROXIES} entries"
        )));
    }
    let mut proxies = Vec::with_capacity(raw_values.len());
    for value in raw_values {
        if value.is_empty() {
            return Err(ConfigError::Invalid("trusted proxy entry is empty".into()));
        }
        let network = value
            .parse::<IpNet>()
            .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| ConfigError::Invalid(format!("invalid trusted proxy: {value}")))?;
        if !proxies.contains(&network) {
            proxies.push(network);
        }
    }
    Ok(proxies)
}

fn validate_origin_pattern(value: &str) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > MAX_ORIGIN_BYTES || value == "*" {
        return Err(ConfigError::Invalid(
            "allowed origin is empty, too long, or an unsafe wildcard".into(),
        ));
    }
    let normalized = if let Some((scheme, host)) = value.split_once("://*.") {
        if host.contains('*') || !host.contains('.') {
            return Err(ConfigError::Invalid(
                "allowed origin wildcard must cover a specific subdomain suffix".into(),
            ));
        }
        format!("{scheme}://wildcard.{host}")
    } else {
        if value.contains('*') {
            return Err(ConfigError::Invalid(
                "allowed origin contains an unsupported wildcard".into(),
            ));
        }
        value.to_owned()
    };
    let parsed = Url::parse(&normalized)
        .map_err(|_| ConfigError::Invalid("allowed origin is not a valid URL origin".into()))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::Invalid(
            "allowed origin must contain only an HTTP(S) scheme, host, and optional port".into(),
        ));
    }
    Ok(())
}

fn parse_api_keys(properties: &Properties) -> Result<Vec<ApiKeyConfig>, ConfigError> {
    let mut keys = Vec::new();
    for index in 0..MAX_HONEYPOTS {
        let prefix_new = format!("lmyzmail.api-keys[{index}].");
        let prefix_old = format!("botmail.api-keys[{index}].");
        let key = preferred(
            properties,
            &[&format!("{prefix_new}key")],
            &[&format!("{prefix_old}key")],
        );
        let Some(key) = key else {
            if index > 0 {
                let any_later = (index + 1..MAX_HONEYPOTS).any(|later| {
                    properties
                        .get(&format!("lmyzmail.api-keys[{later}].key"))
                        .is_some()
                        || properties
                            .get(&format!("botmail.api-keys[{later}].key"))
                            .is_some()
                });
                if !any_later {
                    break;
                }
            }
            continue;
        };
        if key.len() > MAX_API_KEY_BYTES || key.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "api key {index} is empty or too long"
            )));
        }
        let label = preferred(
            properties,
            &[&format!("{prefix_new}label")],
            &[&format!("{prefix_old}label")],
        )
        .unwrap_or("api")
        .to_owned();
        let read = preferred_bool(
            properties,
            &[
                &format!("{prefix_new}read"),
                &format!("{prefix_new}readEnabled"),
            ],
            &[
                &format!("{prefix_old}readEnabled"),
                &format!("{prefix_old}read"),
            ],
            true,
        )?;
        let write = preferred_bool(
            properties,
            &[
                &format!("{prefix_new}write"),
                &format!("{prefix_new}writeEnabled"),
            ],
            &[
                &format!("{prefix_old}writeEnabled"),
                &format!("{prefix_old}write"),
            ],
            false,
        )?;
        keys.push(ApiKeyConfig {
            key: key.to_owned(),
            label,
            read,
            write,
        });
    }
    let mut seen = HashSet::new();
    for (index, api_key) in keys.iter().enumerate() {
        if !seen.insert(api_key.key.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate API key at index {index}"
            )));
        }
    }
    Ok(keys)
}

fn parse_honeypots(
    properties: &Properties,
    default_bind_address: &str,
) -> Result<Vec<HoneypotConfig>, ConfigError> {
    if !preferred_bool(
        properties,
        &["lmyzmail.honeypot.enabled"],
        &["botmail.honeypot.enabled"],
        false,
    )? {
        return Ok(Vec::new());
    }
    let mut traps = Vec::new();
    for index in 0..MAX_HONEYPOTS {
        let new_prefix = format!("lmyzmail.honeypot.traps[{index}].");
        let old_prefix = format!("botmail.honeypot.traps[{index}].");
        let port = preferred(
            properties,
            &[&format!("{new_prefix}port")],
            &[&format!("{old_prefix}port")],
        );
        let Some(port) = port else {
            if index > 0 {
                break;
            }
            continue;
        };
        let port = port.parse::<u16>().map_err(|_| {
            ConfigError::Invalid(format!("honeypot {index} port is not a valid number"))
        })?;
        if port == 0 {
            return Err(ConfigError::Invalid(format!(
                "honeypot {index} port must not be zero"
            )));
        }
        let protocol = preferred(
            properties,
            &[
                &format!("{new_prefix}protocol"),
                &format!("{new_prefix}server-protocol"),
            ],
            &[
                &format!("{old_prefix}server-protocol"),
                &format!("{old_prefix}protocol"),
            ],
        )
        .unwrap_or("NONE")
        .to_ascii_uppercase();
        if !matches!(
            protocol.as_str(),
            "NONE" | "SMTP" | "SSH" | "FTP" | "MYSQL" | "POP3" | "IMAP" | "VNC"
        ) {
            return Err(ConfigError::Invalid(format!(
                "honeypot {index} server protocol is not supported: {protocol}"
            )));
        }
        let label = preferred(
            properties,
            &[&format!("{new_prefix}label")],
            &[&format!("{old_prefix}label")],
        )
        .unwrap_or("trap")
        .to_owned();
        let bind_address = preferred(
            properties,
            &[&format!("{new_prefix}bind-address")],
            &[&format!("{old_prefix}bind-address")],
        )
        .unwrap_or(default_bind_address)
        .to_owned();
        validate_host(&bind_address, &format!("honeypot[{index}].bind-address"))?;
        traps.push(HoneypotConfig {
            port,
            protocol,
            label,
            bind_address,
        });
    }
    Ok(traps)
}

fn parse_cringe_decay_config(properties: &Properties) -> Result<CringeDecayConfig, ConfigError> {
    let interval = preferred(
        properties,
        &["lmyzmail.cringe.decay.interval"],
        &["botmail.cringe.decay.interval"],
    )
    .map_or_else(
        || Ok(Duration::from_secs(24 * 60 * 60)),
        |value| parse_spring_duration(value, "cringe decay interval"),
    )?;
    let amount = parse_number(
        properties,
        &["lmyzmail.cringe.decay.amount"],
        &["botmail.cringe.decay.amount"],
        10_i32,
        "cringe decay amount",
    )?;
    if amount < 0 {
        return Err(ConfigError::Invalid(
            "cringe decay amount must not be negative".into(),
        ));
    }
    let configured_check_interval = preferred(
        properties,
        &[
            "lmyzmail.cringe.decay.check-interval",
            "lmyzmail.cringe.decay.checkInterval",
        ],
        &[
            "botmail.cringe.decay.check-interval",
            "botmail.cringe.decay.checkInterval",
        ],
    )
    .map(|value| parse_spring_duration(value, "cringe decay check interval"))
    .transpose()?;
    let check_interval = configured_check_interval.unwrap_or_else(|| {
        let quarter_millis = interval.as_millis() / 4;
        Duration::from_millis(quarter_millis.clamp(60_000, 3_600_000) as u64)
    });
    let activity_retention_days = parse_number(
        properties,
        &["lmyzmail.cringe.decay.activity-retention-days"],
        &[
            "botmail.cringe.decay.activity-retention-days",
            "botmail.cringe.decay.activityRetentionDays",
        ],
        360_u32,
        "cringe activity retention days",
    )?;
    if activity_retention_days > 36_500 {
        return Err(ConfigError::Invalid(
            "cringe activity retention days must not exceed 36500".into(),
        ));
    }
    Ok(CringeDecayConfig {
        interval,
        amount,
        check_interval,
        activity_retention_days,
    })
}

fn parse_spring_duration(value: &str, label: &str) -> Result<Duration, ConfigError> {
    let value = value.trim();
    let duration = if value
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.eq_ignore_ascii_case(&b'P'))
    {
        parse_iso_duration(value)
    } else {
        parse_simple_duration(value)
    }
    .ok_or_else(|| ConfigError::Invalid(format!("{label} is not a valid duration")))?;
    if duration < Duration::from_millis(1) || duration > MAX_CRINGE_DECAY_DURATION {
        return Err(ConfigError::Invalid(format!(
            "{label} must be between 1ms and 36600d"
        )));
    }
    Ok(duration)
}

fn parse_simple_duration(value: &str) -> Option<Duration> {
    let value = value.strip_prefix('+').unwrap_or(value);
    let digits = value.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let amount = value[..digits].parse::<u64>().ok()?;
    let multiplier = match value[digits..].to_ascii_lowercase().as_str() {
        "ns" => return Some(Duration::from_nanos(amount)),
        "us" => return Some(Duration::from_micros(amount)),
        "ms" | "" => return Some(Duration::from_millis(amount)),
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return None,
    };
    amount.checked_mul(multiplier).map(Duration::from_secs)
}

fn parse_iso_duration(value: &str) -> Option<Duration> {
    let uppercase = value.to_ascii_uppercase();
    let body = uppercase.strip_prefix('P')?;
    let (date, time) = body.split_once('T').map_or((body, ""), |parts| parts);
    let days = if date.is_empty() {
        0
    } else {
        date.strip_suffix('D')?.parse::<u64>().ok()?
    };
    let mut hours = 0_u64;
    let mut minutes = 0_u64;
    let mut seconds = 0_u64;
    let mut nanos = 0_u32;
    let mut remaining = time;
    if let Some(index) = remaining.find('H') {
        hours = remaining[..index].parse().ok()?;
        remaining = &remaining[index + 1..];
    }
    if let Some(index) = remaining.find('M') {
        minutes = remaining[..index].parse().ok()?;
        remaining = &remaining[index + 1..];
    }
    if let Some(raw_seconds) = remaining.strip_suffix('S') {
        let (whole, fraction) = raw_seconds
            .split_once('.')
            .map_or((raw_seconds, None), |(whole, fraction)| {
                (whole, Some(fraction))
            });
        seconds = whole.parse().ok()?;
        if let Some(fraction) = fraction {
            if fraction.is_empty()
                || fraction.len() > 9
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            let mut padded = fraction.to_owned();
            padded.extend(std::iter::repeat_n('0', 9 - fraction.len()));
            nanos = padded.parse().ok()?;
        }
        remaining = "";
    }
    if !remaining.is_empty() || (date.is_empty() && time.is_empty()) {
        return None;
    }
    let total_seconds = days
        .checked_mul(24 * 60 * 60)?
        .checked_add(hours.checked_mul(60 * 60)?)?
        .checked_add(minutes.checked_mul(60)?)?
        .checked_add(seconds)?;
    Some(Duration::new(total_seconds, nanos))
}

fn parse_xdp_config(properties: &Properties) -> Result<XdpConfig, ConfigError> {
    let enabled = preferred_bool(
        properties,
        &["lmyzmail.xdp.enabled"],
        &["botmail.xdp.enabled"],
        false,
    )?;
    let interface_name = preferred(
        properties,
        &["lmyzmail.xdp.interface-name"],
        &["botmail.xdp.interface-name"],
    )
    .unwrap_or("eth0")
    .to_owned();
    validate_simple(&interface_name, 15, "xdp.interface-name")?;

    let bpf_object_path = preferred(
        properties,
        &["lmyzmail.xdp.bpf-object-path"],
        &["botmail.xdp.bpf-object-path"],
    )
    .filter(|value| !value.trim().is_empty())
    .map(PathBuf::from);
    if let Some(path) = bpf_object_path.as_deref() {
        validate_path(
            path.to_str()
                .ok_or_else(|| ConfigError::Invalid("xdp.bpf-object-path is not UTF-8".into()))?,
            "xdp.bpf-object-path",
        )?;
    }

    let pin_path = preferred(
        properties,
        &["lmyzmail.xdp.pin-path"],
        &["botmail.xdp.pin-path"],
    )
    .unwrap_or("/sys/fs/bpf/lmyzmail");
    validate_xdp_pin_path(pin_path)?;
    let pin_path = PathBuf::from(pin_path);
    if !pin_path.is_absolute()
        || pin_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigError::Invalid(
            "xdp.pin-path must be an absolute path without parent traversal".into(),
        ));
    }

    let ban_threshold = preferred_xdp_i32(
        properties,
        "lmyzmail.xdp.ban-threshold",
        "botmail.xdp.ban-threshold",
        50,
    )?;
    let configured_unban_threshold = preferred_xdp_i32(
        properties,
        "lmyzmail.xdp.unban-threshold",
        "botmail.xdp.unban-threshold",
        -1,
    )?;
    if ban_threshold < 0 || configured_unban_threshold < -1 {
        return Err(ConfigError::Invalid(
            "xdp thresholds must be non-negative; unban-threshold may also be -1".into(),
        ));
    }
    let unban_threshold = if configured_unban_threshold == -1 {
        ban_threshold / 2
    } else {
        configured_unban_threshold
    };

    let pps_monitor = XdpPpsMonitorConfig {
        enabled: preferred_bool(
            properties,
            &["lmyzmail.xdp.pps-monitor.enabled"],
            &["botmail.xdp.pps-monitor.enabled"],
            true,
        )?,
        poll_interval_ms: preferred_u64(
            properties,
            &["lmyzmail.xdp.pps-monitor.poll-interval-ms"],
            &["botmail.xdp.pps-monitor.poll-interval-ms"],
            1_000,
        )?,
        pps_warn_threshold: preferred_u64(
            properties,
            &["lmyzmail.xdp.pps-monitor.pps-warn-threshold"],
            &["botmail.xdp.pps-monitor.pps-warn-threshold"],
            100_000,
        )?,
        pps_critical_threshold: preferred_u64(
            properties,
            &["lmyzmail.xdp.pps-monitor.pps-critical-threshold"],
            &["botmail.xdp.pps-monitor.pps-critical-threshold"],
            200_000,
        )?,
        syn_pps_warn_threshold: preferred_u64(
            properties,
            &["lmyzmail.xdp.pps-monitor.syn-pps-warn-threshold"],
            &["botmail.xdp.pps-monitor.syn-pps-warn-threshold"],
            10_000,
        )?,
        syn_pps_critical_threshold: preferred_u64(
            properties,
            &["lmyzmail.xdp.pps-monitor.syn-pps-critical-threshold"],
            &["botmail.xdp.pps-monitor.syn-pps-critical-threshold"],
            20_000,
        )?,
        per_ip_pps_warn_threshold: preferred_u64(
            properties,
            &["lmyzmail.xdp.pps-monitor.per-ip-pps-warn-threshold"],
            &["botmail.xdp.pps-monitor.per-ip-pps-warn-threshold"],
            1_000,
        )?,
        per_ip_pps_critical_threshold: preferred_u64(
            properties,
            &["lmyzmail.xdp.pps-monitor.per-ip-pps-critical-threshold"],
            &["botmail.xdp.pps-monitor.per-ip-pps-critical-threshold"],
            5_000,
        )?,
        per_ip_syn_pps_warn_threshold: preferred_u64(
            properties,
            &["lmyzmail.xdp.pps-monitor.per-ip-syn-pps-warn-threshold"],
            &["botmail.xdp.pps-monitor.per-ip-syn-pps-warn-threshold"],
            100,
        )?,
        per_ip_syn_pps_critical_threshold: preferred_u64(
            properties,
            &["lmyzmail.xdp.pps-monitor.per-ip-syn-pps-critical-threshold"],
            &["botmail.xdp.pps-monitor.per-ip-syn-pps-critical-threshold"],
            500,
        )?,
        consecutive_exceed_count: preferred_u32(
            properties,
            &["lmyzmail.xdp.pps-monitor.consecutive-exceed-count"],
            &["botmail.xdp.pps-monitor.consecutive-exceed-count"],
            3,
        )?,
        record_to_cringe: preferred_bool(
            properties,
            &["lmyzmail.xdp.pps-monitor.record-to-cringe"],
            &["botmail.xdp.pps-monitor.record-to-cringe"],
            true,
        )?,
        max_ips_per_poll: preferred_u32(
            properties,
            &["lmyzmail.xdp.pps-monitor.max-ips-per-poll"],
            &["botmail.xdp.pps-monitor.max-ips-per-poll"],
            10_000,
        )?,
        ring_buffer_size: preferred_u32(
            properties,
            &["lmyzmail.xdp.pps-monitor.ring-buffer-size"],
            &["botmail.xdp.pps-monitor.ring-buffer-size"],
            1_024,
        )?,
    };
    validate_xdp_pps_monitor(&pps_monitor)?;

    Ok(XdpConfig {
        enabled,
        interface_name,
        bpf_object_path,
        pin_path,
        ban_threshold,
        unban_threshold,
        force_generic_mode: preferred_bool(
            properties,
            &["lmyzmail.xdp.force-generic-mode"],
            &["botmail.xdp.force-generic-mode"],
            false,
        )?,
        verbose: preferred_bool(
            properties,
            &["lmyzmail.xdp.verbose"],
            &["botmail.xdp.verbose"],
            false,
        )?,
        sync_on_startup: preferred_bool(
            properties,
            &["lmyzmail.xdp.sync-on-startup"],
            &["botmail.xdp.sync-on-startup"],
            true,
        )?,
        whitelist: parse_xdp_whitelist(properties)?,
        reason_code_default: preferred_xdp_i32(
            properties,
            "lmyzmail.xdp.reason-code-default",
            "botmail.xdp.reason-code-default",
            0,
        )?,
        reason_code_pps_overlimit: preferred_xdp_i32(
            properties,
            "lmyzmail.xdp.reason-code-pps-overlimit",
            "botmail.xdp.reason-code-pps-overlimit",
            5,
        )?,
        reason_code_syn_flood: preferred_xdp_i32(
            properties,
            "lmyzmail.xdp.reason-code-syn-flood",
            "botmail.xdp.reason-code-syn-flood",
            6,
        )?,
        pps_monitor,
    })
}

fn preferred_xdp_i32(
    properties: &Properties,
    new_key: &str,
    legacy_key: &str,
    default: i32,
) -> Result<i32, ConfigError> {
    preferred(properties, &[new_key], &[legacy_key])
        .map(|value| {
            value
                .parse::<i32>()
                .map_err(|_| ConfigError::Invalid(format!("{new_key} is not a valid integer")))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn parse_xdp_whitelist(properties: &Properties) -> Result<Vec<IpNet>, ConfigError> {
    let scalar_new = properties.get("lmyzmail.xdp.whitelist");
    let indexed_new = properties.get("lmyzmail.xdp.whitelist[0]").is_some();
    let scalar_legacy = properties.get("botmail.xdp.whitelist");
    let indexed_legacy = properties.get("botmail.xdp.whitelist[0]").is_some();
    let raw_values = if let Some(value) = scalar_new {
        value.split(',').map(str::trim).collect::<Vec<_>>()
    } else if indexed_new {
        (0..MAX_XDP_WHITELIST)
            .map_while(|index| properties.get(&format!("lmyzmail.xdp.whitelist[{index}]")))
            .collect()
    } else if let Some(value) = scalar_legacy {
        value.split(',').map(str::trim).collect::<Vec<_>>()
    } else if indexed_legacy {
        (0..MAX_XDP_WHITELIST)
            .map_while(|index| properties.get(&format!("botmail.xdp.whitelist[{index}]")))
            .collect()
    } else {
        vec!["127.0.0.1", "::1"]
    };
    if raw_values.len() > MAX_XDP_WHITELIST {
        return Err(ConfigError::Invalid(format!(
            "xdp whitelist exceeds {MAX_XDP_WHITELIST} entries"
        )));
    }
    let mut whitelist = Vec::with_capacity(raw_values.len());
    for value in raw_values {
        if value.is_empty() {
            continue;
        }
        let network = value
            .parse::<IpNet>()
            .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| ConfigError::Invalid(format!("invalid xdp whitelist entry: {value}")))?;
        if !whitelist.contains(&network) {
            whitelist.push(network);
        }
    }
    Ok(whitelist)
}

fn validate_xdp_pps_monitor(value: &XdpPpsMonitorConfig) -> Result<(), ConfigError> {
    if value.poll_interval_ms == 0
        || value.poll_interval_ms > 60_000
        || value.consecutive_exceed_count == 0
        || value.consecutive_exceed_count > 10_000
        || value.max_ips_per_poll == 0
        || value.max_ips_per_poll > 100_000
        || value.ring_buffer_size == 0
        || value.ring_buffer_size > 1_000_000
    {
        return Err(ConfigError::Invalid(
            "xdp PPS monitor bounds are invalid".into(),
        ));
    }
    Ok(())
}

fn validate_xdp_pin_path(value: &str) -> Result<(), ConfigError> {
    validate_path(value, "xdp.pin-path")?;
    if value.len() > 255 {
        return Err(ConfigError::Invalid(
            "xdp.pin-path exceeds the native 255-byte limit".into(),
        ));
    }
    Ok(())
}

fn validate_database(value: &DatabaseConfig) -> Result<(), ConfigError> {
    validate_host(&value.host, "postgres.host")?;
    validate_port(value.port, "postgres.port", false)?;
    validate_simple(value.database.as_str(), 128, "postgres.database")?;
    validate_simple(value.username.as_str(), 128, "postgres.username")?;
    if value.password.contains(['\0', '\r', '\n']) {
        return Err(ConfigError::Invalid(
            "postgres.password contains a control separator".into(),
        ));
    }
    Ok(())
}

fn validate_redis(value: &RedisConfig) -> Result<(), ConfigError> {
    validate_host(&value.host, "redis.host")?;
    validate_port(value.port, "redis.port", false)?;
    if let Some(username) = value.username.as_deref() {
        validate_simple(username, 128, "redis.username")?;
    }
    if value
        .password
        .as_deref()
        .is_some_and(|password| password.contains(['\0', '\r', '\n']))
    {
        return Err(ConfigError::Invalid(
            "redis.password contains a control separator".into(),
        ));
    }
    Ok(())
}

fn validate_outbound_route(value: &OutboundRouteConfig) -> Result<(), ConfigError> {
    if value.mx_l1_max_entries == 0 || value.mx_l1_max_entries > 100_000 {
        return Err(ConfigError::Invalid(
            "outbound MX cache capacity is outside the safe bound".into(),
        ));
    }
    if value.mx_l1_ttl_minutes == 0
        || value.mx_l1_ttl_minutes > 24 * 60
        || value.mx_l2_ttl_minutes == 0
        || value.mx_l2_ttl_minutes > 7 * 24 * 60
        || value.mx_negative_ttl_minutes == 0
        || value.mx_negative_ttl_minutes > 24 * 60
    {
        return Err(ConfigError::Invalid(
            "outbound MX cache TTL is outside the safe bound".into(),
        ));
    }
    if value.dns_query_timeout_seconds == 0
        || value.dns_query_timeout_seconds > 5 * 60
        || value.mta_sts_fetch_timeout_ms == 0
        || value.mta_sts_fetch_timeout_ms > 5 * 60 * 1_000
        || value.resolution_deadline_seconds == 0
        || value.resolution_deadline_seconds > 15 * 60
    {
        return Err(ConfigError::Invalid(
            "outbound route deadline is outside the safe bound".into(),
        ));
    }
    Ok(())
}

fn validate_reporting(value: &ReportingConfig) -> Result<(), ConfigError> {
    if value.batch_size == 0 || value.batch_size > 100_000 {
        return Err(ConfigError::Invalid(
            "reporting batch size must be between 1 and 100000".into(),
        ));
    }
    if value.flush_interval_ms == 0 || value.flush_interval_ms > 60 * 60 * 1_000 {
        return Err(ConfigError::Invalid(
            "reporting flush interval must be between 1 and 3600000 ms".into(),
        ));
    }
    if value.retention_days > 36_500 {
        return Err(ConfigError::Invalid(
            "reporting retention must not exceed 36500 days".into(),
        ));
    }
    if value.http_delivery_timeout_seconds == 0 || value.http_delivery_timeout_seconds > 300 {
        return Err(ConfigError::Invalid(
            "reporting HTTP delivery timeout must be between 1 and 300 seconds".into(),
        ));
    }
    for (label, candidate, max) in [
        (
            "DMARC report sender address",
            value.dmarc_report_sender_address.as_deref(),
            320,
        ),
        (
            "TLS report sender address",
            value.tls_report_sender_address.as_deref(),
            320,
        ),
        (
            "reporting organization name",
            value.organization_name.as_deref(),
            512,
        ),
        (
            "reporting organization email",
            value.organization_email.as_deref(),
            320,
        ),
    ] {
        if candidate.is_some_and(|candidate| {
            candidate.len() > max
                || candidate
                    .chars()
                    .any(|character| matches!(character, '\0' | '\r' | '\n'))
        }) {
            return Err(ConfigError::Invalid(format!(
                "{label} exceeds {max} bytes or contains a control separator"
            )));
        }
    }
    Ok(())
}

fn validate_limits(value: &LimitConfig) -> Result<(), ConfigError> {
    if value.redis_pool == 0 || value.redis_pool > MAX_POOL_SIZE {
        return Err(ConfigError::Invalid(format!(
            "redis pool must be between 1 and {MAX_POOL_SIZE}"
        )));
    }
    if value.postgres_pool == 0 || value.postgres_pool > MAX_POOL_SIZE {
        return Err(ConfigError::Invalid(format!(
            "postgres pool must be between 1 and {MAX_POOL_SIZE}"
        )));
    }
    if value.max_http_request_bytes == 0 || value.max_http_request_bytes > MAX_CONFIG_BYTES * 16 {
        return Err(ConfigError::Invalid(
            "HTTP request limit is outside the safe bound".into(),
        ));
    }
    if value.max_http_connections == 0 || value.max_http_connections > MAX_POOL_SIZE as usize * 4 {
        return Err(ConfigError::Invalid(
            "HTTP connection limit is outside the safe bound".into(),
        ));
    }
    if value.http_deadline_ms == 0 || value.http_deadline_ms > 3_600_000 {
        return Err(ConfigError::Invalid(
            "HTTP deadline is outside the safe bound".into(),
        ));
    }
    if value.honeypot_initial_delay_ms == 0
        || value.honeypot_initial_delay_ms > MAX_HONEYPOT_DELAY_MS
        || value.honeypot_post_banner_timeout_ms == 0
        || value.honeypot_post_banner_timeout_ms > MAX_HONEYPOT_DELAY_MS
    {
        return Err(ConfigError::Invalid(format!(
            "honeypot deadlines must be between 1 and {MAX_HONEYPOT_DELAY_MS} ms"
        )));
    }
    if value.max_honeypot_connections_per_trap == 0
        || value.max_honeypot_connections_per_trap > 4_096
    {
        return Err(ConfigError::Invalid(
            "honeypot connection limit must be between 1 and 4096".into(),
        ));
    }
    if value.max_honeypot_read_bytes == 0 || value.max_honeypot_read_bytes > 65_536 {
        return Err(ConfigError::Invalid(
            "honeypot read limit must be between 1 and 65536 bytes".into(),
        ));
    }
    if value.max_email_size_bytes == 0
        || value.max_email_size_bytes > MAX_MESSAGE_BYTES
        || value.max_attachment_size_bytes == 0
        || value.max_attachment_size_bytes > value.max_email_size_bytes
        || value.max_total_attachments_size_bytes == 0
        || value.max_total_attachments_size_bytes > value.max_email_size_bytes
    {
        return Err(ConfigError::Invalid(
            "mail and attachment size limits are outside the safe bound".into(),
        ));
    }
    Ok(())
}

fn validate_ports(listen: &ListenConfig) -> Result<(), ConfigError> {
    validate_port(listen.http, "listen.http", false)?;
    let mut ports = HashSet::new();
    for (name, port) in [
        ("http", listen.http),
        ("smtp", listen.smtp),
        ("htcpcp", listen.htcpcp),
        ("minecraft", listen.minecraft),
    ] {
        if port != 0 && !ports.insert(port) {
            return Err(ConfigError::Invalid(format!(
                "listen port is duplicated: {name}={port}"
            )));
        }
        validate_port(port, name, true)?;
    }
    for (index, trap) in listen.honeypots.iter().enumerate() {
        validate_port(trap.port, &format!("honeypot[{index}].port"), false)?;
        validate_simple(&trap.protocol, 64, &format!("honeypot[{index}].protocol"))?;
        validate_simple(&trap.label, 128, &format!("honeypot[{index}].label"))?;
        if !ports.insert(trap.port) {
            return Err(ConfigError::Invalid(format!(
                "listen port is duplicated: honeypot[{index}]"
            )));
        }
    }
    Ok(())
}

fn validate_port(value: u16, field: &str, allow_zero: bool) -> Result<(), ConfigError> {
    if value == 0 && !allow_zero {
        return Err(ConfigError::Invalid(format!(
            "{field} must be between 1 and 65535"
        )));
    }
    Ok(())
}

fn validate_path(value: &str, field: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value
            .chars()
            .any(|character| character == '\0' || character == '\r' || character == '\n')
    {
        return Err(ConfigError::Invalid(format!(
            "{field} is empty, too long, or contains a control separator"
        )));
    }
    Ok(())
}

fn validate_simple(value: &str, max: usize, field: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > max
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ConfigError::Invalid(format!(
            "{field} is empty, too long, or contains whitespace/control"
        )));
    }
    Ok(())
}

fn validate_host(value: &str, field: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > MAX_HOST_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ConfigError::Invalid(format!(
            "{field} is empty, too long, or contains whitespace/control"
        )));
    }
    if value.parse::<IpAddr>().is_ok() || value == "localhost" || value == "::" {
        return Ok(());
    }
    let hostname = value
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(value);
    if hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            && !label.starts_with('-')
            && !label.ends_with('-')
    }) {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!("{field} is not a valid host")))
    }
}

/// Resolve a scalar using the new key first, then the frozen legacy alias.
pub fn resolve_alias<'a>(
    properties: &'a HashMap<String, String>,
    new_key: &str,
    legacy_key: &str,
    default: &'a str,
) -> &'a str {
    properties
        .get(new_key)
        .or_else(|| properties.get(legacy_key))
        .map(String::as_str)
        .unwrap_or(default)
}

pub fn resolve_u16(
    properties: &HashMap<String, String>,
    new_key: &str,
    legacy_key: &str,
    default: u16,
) -> Result<u16, ConfigError> {
    let value = resolve_alias(properties, new_key, legacy_key, "");
    if value.is_empty() {
        return Ok(default);
    }
    value.parse::<u16>().map_err(|_| {
        ConfigError::Invalid(format!(
            "{new_key} or {legacy_key} must be an unsigned 16-bit port"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn semantic_json_with_htcpcp(htcpcp: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "profile": "test",
            "listen": {
                "host": "localhost",
                "http": 18080,
                "smtp": 11025,
                "htcpcp": 18888,
                "minecraft": 25575
            },
            "postgres": {
                "host": "localhost",
                "port": 15432,
                "database": "lmyzmail",
                "username": "qa",
                "password": ""
            },
            "redis": {"host": "localhost", "port": 16379, "database": 0},
            "maildir": "/tmp/lmyzmail-mail",
            "domain": "example.test",
            "htcpcp": htcpcp
        }))
        .unwrap()
    }

    fn indexed_htcpcp_properties(count: usize) -> Properties {
        let mut text = String::new();
        for index in 0..count {
            text.push_str(&format!(
                "lmyzmail.htcpcp.pots[{index}].id=pot-{index}\n\
lmyzmail.htcpcp.pots[{index}].type=coffee\n\
lmyzmail.htcpcp.pots[{index}].tea-varieties=\n\
lmyzmail.htcpcp.pots[{index}].supported-additions=\n"
            ));
        }
        Properties::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn parses_comments_escapes_and_continuations() {
        let properties = Properties::parse(
            b"# comment\npath=/var/lib/lmyzmail\\ data\ncontinued=one\\\n  two\nunicode=\\u006cmyzmail\n",
        )
        .unwrap();
        assert_eq!(properties.get("path"), Some("/var/lib/lmyzmail data"));
        assert_eq!(properties.get("continued"), Some("onetwo"));
        assert_eq!(properties.get("unicode"), Some("lmyzmail"));
    }

    #[test]
    fn new_key_wins_even_when_legacy_is_present() {
        let properties = Properties::parse(
            b"botmail.netty.http.port=8080\nlmyzmail.http.port=18080\nbotmail.smtp.port=2525\n",
        )
        .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert_eq!(config.listen.http, 18080);
        assert_eq!(config.listen.smtp, 2525);
    }

    #[test]
    fn smtp_skibidi_ascii_defaults_match_java() {
        let config = RuntimeConfig::from_properties(Properties::default()).unwrap();
        assert_eq!(config.features.smtp_skibidi_mode, "AUTO_SAFE");
        assert!(config.features.smtp_skibidi_enable_avx512);
        assert!(config.features.smtp_skibidi_enable_simd_rng);
        assert!(config.smtp_skibidi.enabled);
        assert_eq!(
            config.smtp_skibidi.ascii.simd_mode,
            MailRenderSimdMode::Auto
        );
        assert_eq!(config.smtp_skibidi.ascii.max_width, 450);
        assert_eq!(config.smtp_skibidi.ascii.max_fps, 20.0);
        assert_eq!(config.smtp_skibidi.ascii.default_width, 120);
        assert_eq!(config.smtp_skibidi.ascii.default_fps, 10.0);
        assert_eq!(config.smtp_skibidi.ascii.default_contrast, 1.2);
        assert_eq!(config.smtp_skibidi.ascii.char_aspect, 2.0);
    }

    #[test]
    fn smtp_skibidi_accepts_legacy_values_and_prefers_new_keys() {
        let legacy = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.smtp.skibidi-toilet-quiz-enabled=false\n\
botmail.smtp.skibidi-generator-mode=JAVA\n\
botmail.smtp.skibidi-generator-enable-avx512=false\n\
botmail.smtp.skibidi-generator-enable-simd-rng=false\n\
botmail.smtp.asciiart.simd-mode=AVX512\n\
botmail.smtp.asciiart.max-width=980\n\
botmail.smtp.asciiart.max-fps=30\n\
botmail.smtp.asciiart.default-width=150\n\
botmail.smtp.asciiart.default-fps=12\n\
botmail.smtp.asciiart.default-contrast=1.4\n\
botmail.smtp.asciiart.char-aspect=1.5\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(legacy.features.smtp_skibidi_mode, "JAVA");
        assert!(!legacy.features.smtp_skibidi_enable_avx512);
        assert!(!legacy.features.smtp_skibidi_enable_simd_rng);
        assert!(!legacy.smtp_skibidi.enabled);
        assert_eq!(
            legacy.smtp_skibidi.ascii.simd_mode,
            MailRenderSimdMode::Avx512
        );
        assert_eq!(legacy.smtp_skibidi.ascii.max_width, 980);
        assert_eq!(legacy.smtp_skibidi.ascii.max_fps, 30.0);
        assert_eq!(legacy.smtp_skibidi.ascii.default_width, 150);
        assert_eq!(legacy.smtp_skibidi.ascii.default_fps, 12.0);
        assert_eq!(legacy.smtp_skibidi.ascii.default_contrast, 1.4);
        assert_eq!(legacy.smtp_skibidi.ascii.char_aspect, 1.5);

        let both = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.smtp.skibidi-toilet-quiz-enabled=false\n\
botmail.smtp.skibidi-generator-mode=JAVA\n\
botmail.smtp.skibidi-generator-enable-avx512=false\n\
botmail.smtp.skibidi-generator-enable-simd-rng=false\n\
botmail.smtp.asciiart.max-width=980\n\
botmail.smtp.asciiart.max-fps=30\n\
botmail.smtp.asciiart.default-width=150\n\
botmail.smtp.asciiart.default-fps=12\n\
botmail.smtp.asciiart.default-contrast=1.4\n\
botmail.smtp.asciiart.char-aspect=1.5\n\
lmyzmail.smtp.skibidi-toilet-quiz-enabled=true\n\
lmyzmail.smtp.skibidi-generator-mode=AUTO_SAFE\n\
lmyzmail.smtp.skibidi-generator-enable-avx512=true\n\
lmyzmail.smtp.skibidi-generator-enable-simd-rng=true\n\
lmyzmail.smtp.asciiart.simd-mode=SCALAR\n\
lmyzmail.smtp.asciiart.max-width=320\n\
lmyzmail.smtp.asciiart.max-fps=18\n\
lmyzmail.smtp.asciiart.default-width=80\n\
lmyzmail.smtp.asciiart.default-fps=9\n\
lmyzmail.smtp.asciiart.default-contrast=1.1\n\
lmyzmail.smtp.asciiart.char-aspect=2.5\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(both.features.smtp_skibidi_mode, "AUTO_SAFE");
        assert!(both.features.smtp_skibidi_enable_avx512);
        assert!(both.features.smtp_skibidi_enable_simd_rng);
        assert!(both.smtp_skibidi.enabled);
        assert_eq!(
            both.smtp_skibidi.ascii.simd_mode,
            MailRenderSimdMode::Scalar
        );
        assert_eq!(both.smtp_skibidi.ascii.max_width, 320);
        assert_eq!(both.smtp_skibidi.ascii.max_fps, 18.0);
        assert_eq!(both.smtp_skibidi.ascii.default_width, 80);
        assert_eq!(both.smtp_skibidi.ascii.default_fps, 9.0);
        assert_eq!(both.smtp_skibidi.ascii.default_contrast, 1.1);
        assert_eq!(both.smtp_skibidi.ascii.char_aspect, 2.5);
    }

    #[test]
    fn smtp_skibidi_semantic_json_uses_nested_shape() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&semantic_json_with_htcpcp(serde_json::json!({
                "enabled": false,
                "default_brew_time_seconds": 30,
                "pots": null
            })))
            .unwrap();
        value["smtp"] = serde_json::json!({
            "skibidi_toilet_quiz_enabled": false,
            "asciiart": {
                "simd_mode": "AVX2",
                "max_width": 980,
                "max_fps": 30.0,
                "default_width": 150,
                "default_fps": 12.0,
                "default_contrast": 1.4,
                "char_aspect": 1.5
            }
        });
        value["features"]["smtp_skibidi_enable_avx512"] = serde_json::json!(false);
        value["features"]["smtp_skibidi_enable_simd_rng"] = serde_json::json!(false);
        let properties = parse_semantic_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert!(!config.features.smtp_skibidi_enable_avx512);
        assert!(!config.features.smtp_skibidi_enable_simd_rng);
        assert!(!config.smtp_skibidi.enabled);
        assert_eq!(
            config.smtp_skibidi.ascii.simd_mode,
            MailRenderSimdMode::Avx2
        );
        assert_eq!(config.smtp_skibidi.ascii.max_width, 980);
        assert_eq!(config.smtp_skibidi.ascii.max_fps, 30.0);
        assert_eq!(config.smtp_skibidi.ascii.default_width, 150);
        assert_eq!(config.smtp_skibidi.ascii.default_fps, 12.0);
        assert_eq!(config.smtp_skibidi.ascii.default_contrast, 1.4);
        assert_eq!(config.smtp_skibidi.ascii.char_aspect, 1.5);
    }

    #[test]
    fn smtp_skibidi_ascii_values_are_bounded_and_finite() {
        for input in [
            b"lmyzmail.smtp.asciiart.max-width=9\n".as_slice(),
            b"lmyzmail.smtp.asciiart.max-width=2049\n".as_slice(),
            b"lmyzmail.smtp.asciiart.max-fps=0\n".as_slice(),
            b"lmyzmail.smtp.asciiart.max-fps=60.1\n".as_slice(),
            b"lmyzmail.smtp.asciiart.max-fps=NaN\n".as_slice(),
            b"lmyzmail.smtp.asciiart.max-fps=Infinity\n".as_slice(),
            b"lmyzmail.smtp.asciiart.default-width=451\n".as_slice(),
            b"lmyzmail.smtp.asciiart.default-fps=21\n".as_slice(),
            b"lmyzmail.smtp.asciiart.default-fps=NaN\n".as_slice(),
            b"lmyzmail.smtp.asciiart.default-contrast=0.09\n".as_slice(),
            b"lmyzmail.smtp.asciiart.default-contrast=3.1\n".as_slice(),
            b"lmyzmail.smtp.asciiart.default-contrast=NaN\n".as_slice(),
            b"lmyzmail.smtp.asciiart.char-aspect=0.09\n".as_slice(),
            b"lmyzmail.smtp.asciiart.char-aspect=10.1\n".as_slice(),
            b"lmyzmail.smtp.asciiart.char-aspect=Infinity\n".as_slice(),
        ] {
            assert!(
                RuntimeConfig::from_properties(Properties::parse(input).unwrap()).is_err(),
                "accepted unsafe SMTP ASCII configuration: {}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn content_filter_defaults_match_java_header_phase() {
        let config = RuntimeConfig::from_properties(Properties::default()).unwrap();
        assert!(config.content_filter.enabled);
        assert_eq!(config.content_filter.suspicious_threshold, 5.0);
        assert_eq!(config.content_filter.spam_threshold, 10.0);
        for rule in [
            &config.content_filter.rbl_check,
            &config.content_filter.new_domain,
            &config.content_filter.missing_headers,
            &config.content_filter.subject_encoding_trick,
            &config.content_filter.excessive_recipients,
            &config.content_filter.dangerous_extension,
            &config.content_filter.double_extension,
            &config.content_filter.mime_type_mismatch,
        ] {
            assert!(rule.enabled);
            assert_eq!(rule.weight, 1.0);
        }
        assert_eq!(config.content_filter.rbl, ContentFilterRblConfig::default());
        assert_eq!(
            config.content_filter.attachment,
            ContentFilterAttachmentConfig::default()
        );
    }

    #[test]
    fn content_filter_accepts_legacy_aliases_and_prefers_new_keys_per_field() {
        let config = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.contentfilter.enabled=false\n\
botmail.contentfilter.suspicious-threshold=4\n\
botmail.contentfilter.spam-threshold=9\n\
botmail.contentfilter.rules.RBL_CHECK.enabled=false\n\
botmail.contentfilter.rules.RBL_CHECK.weight=2.5\n\
botmail.contentfilter.rules.NEW_DOMAIN.enabled=false\n\
botmail.contentfilter.rules.NEW_DOMAIN.weight=3.5\n\
botmail.contentfilter.rules.MISSING_HEADERS.enabled=false\n\
botmail.contentfilter.rules.MISSING_HEADERS.weight=2.5\n\
botmail.contentfilter.rules.SUBJECT_ENCODING_TRICK.weight=3.0\n\
botmail.contentfilter.rules.DANGEROUS_EXTENSION.enabled=false\n\
botmail.contentfilter.rules.DANGEROUS_EXTENSION.weight=2.5\n\
botmail.contentfilter.rbl.enabled=false\n\
botmail.contentfilter.rbl.servers=legacy-one.test,legacy-two.test\n\
botmail.contentfilter.rbl.timeout-ms=900\n\
botmail.contentfilter.rbl.score-per-hit=4\n\
botmail.contentfilter.rbl.max-score=7\n\
botmail.contentfilter.attachment.enabled=false\n\
botmail.contentfilter.attachment.dangerous-extensions=exe,ps1\n\
botmail.contentfilter.attachment.dangerous-extension-score=7\n\
botmail.contentfilter.attachment.double-extension-score=8\n\
botmail.contentfilter.attachment.mime-type-mismatch-score=9\n\
lmyzmail.contentfilter.enabled=true\n\
lmyzmail.contentfilter.spam-threshold=8\n\
lmyzmail.contentfilter.rules.RBL_CHECK.weight=1.5\n\
lmyzmail.contentfilter.rules.NEW_DOMAIN.weight=1.75\n\
lmyzmail.contentfilter.rules.MISSING_HEADERS.weight=1.25\n\
lmyzmail.contentfilter.rules.EXCESSIVE_RECIPIENTS.enabled=false\n\
lmyzmail.contentfilter.rules.DANGEROUS_EXTENSION.weight=1.5\n\
lmyzmail.contentfilter.rbl.enabled=true\n\
lmyzmail.contentfilter.rbl.servers=preferred.test\n\
lmyzmail.contentfilter.rbl.score-per-hit=3\n\
lmyzmail.contentfilter.attachment.enabled=true\n\
lmyzmail.contentfilter.attachment.dangerous-extensions=cmd,js\n\
lmyzmail.contentfilter.attachment.dangerous-extension-score=6\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(config.content_filter.enabled);
        assert_eq!(config.content_filter.suspicious_threshold, 4.0);
        assert_eq!(config.content_filter.spam_threshold, 8.0);
        assert!(!config.content_filter.rbl_check.enabled);
        assert_eq!(config.content_filter.rbl_check.weight, 1.5);
        assert!(config.content_filter.rbl.enabled);
        assert_eq!(config.content_filter.rbl.servers, ["preferred.test"]);
        assert_eq!(
            config.content_filter.rbl.timeout,
            Duration::from_millis(900)
        );
        assert_eq!(config.content_filter.rbl.score_per_hit, 3.0);
        assert_eq!(config.content_filter.rbl.max_score, 7.0);
        assert!(!config.content_filter.new_domain.enabled);
        assert_eq!(config.content_filter.new_domain.weight, 1.75);
        assert!(!config.content_filter.missing_headers.enabled);
        assert_eq!(config.content_filter.missing_headers.weight, 1.25);
        assert_eq!(config.content_filter.subject_encoding_trick.weight, 3.0);
        assert!(!config.content_filter.excessive_recipients.enabled);
        assert!(!config.content_filter.dangerous_extension.enabled);
        assert_eq!(config.content_filter.dangerous_extension.weight, 1.5);
        assert!(config.content_filter.attachment.enabled);
        assert_eq!(
            config.content_filter.attachment.dangerous_extensions,
            ["cmd", "js"]
        );
        assert_eq!(
            config.content_filter.attachment.dangerous_extension_score,
            6.0
        );
        assert_eq!(config.content_filter.attachment.double_extension_score, 8.0);
        assert_eq!(
            config.content_filter.attachment.mime_type_mismatch_score,
            9.0
        );
    }

    #[test]
    fn content_filter_semantic_json_uses_bounded_nested_rules() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&semantic_json_with_htcpcp(serde_json::json!({
                "enabled": false,
                "default_brew_time_seconds": 30,
                "pots": null
            })))
            .unwrap();
        value["content_filter"] = serde_json::json!({
            "enabled": false,
            "suspicious_threshold": 6.0,
            "spam_threshold": 12.0,
            "rules": {
                "rbl_check": {"enabled": true, "weight": 1.25},
                "new_domain": {"enabled": false, "weight": 0.75},
                "missing_headers": {"enabled": false, "weight": 2.0},
                "subject_encoding_trick": {"enabled": true, "weight": 1.5},
                "excessive_recipients": {"enabled": true, "weight": 0.5},
                "dangerous_extension": {"enabled": true, "weight": 2.5},
                "double_extension": {"enabled": false, "weight": 3.0},
                "mime_type_mismatch": {"enabled": true, "weight": 3.5}
            },
            "rbl": {
                "enabled": true,
                "servers": ["listed-one.rbl.test", "listed-two.rbl.test"],
                "timeout_ms": 750,
                "score_per_hit": 2.5,
                "max_score": 4.5
            },
            "attachment": {
                "enabled": true,
                "dangerous_extensions": ["cmd", "js"],
                "dangerous_extension_score": 6.0,
                "double_extension_score": 7.0,
                "mime_type_mismatch_score": 8.0
            }
        });
        let properties = parse_semantic_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert!(!config.content_filter.enabled);
        assert_eq!(config.content_filter.suspicious_threshold, 6.0);
        assert_eq!(config.content_filter.spam_threshold, 12.0);
        assert_eq!(config.content_filter.rbl_check.weight, 1.25);
        assert_eq!(
            config.content_filter.rbl.servers,
            ["listed-one.rbl.test", "listed-two.rbl.test"]
        );
        assert_eq!(
            config.content_filter.rbl.timeout,
            Duration::from_millis(750)
        );
        assert_eq!(config.content_filter.rbl.score_per_hit, 2.5);
        assert_eq!(config.content_filter.rbl.max_score, 4.5);
        assert!(!config.content_filter.new_domain.enabled);
        assert_eq!(config.content_filter.new_domain.weight, 0.75);
        assert!(!config.content_filter.missing_headers.enabled);
        assert_eq!(config.content_filter.missing_headers.weight, 2.0);
        assert_eq!(config.content_filter.subject_encoding_trick.weight, 1.5);
        assert_eq!(config.content_filter.excessive_recipients.weight, 0.5);
        assert_eq!(config.content_filter.dangerous_extension.weight, 2.5);
        assert!(!config.content_filter.double_extension.enabled);
        assert_eq!(config.content_filter.mime_type_mismatch.weight, 3.5);
        assert_eq!(
            config.content_filter.attachment.dangerous_extensions,
            ["cmd", "js"]
        );
        assert_eq!(
            config.content_filter.attachment.dangerous_extension_score,
            6.0
        );
        assert_eq!(config.content_filter.attachment.double_extension_score, 7.0);
        assert_eq!(
            config.content_filter.attachment.mime_type_mismatch_score,
            8.0
        );
    }

    #[test]
    fn content_filter_rbl_configuration_is_strictly_bounded() {
        let too_many = (0..=MAX_CONTENT_FILTER_RBL_SERVERS)
            .map(|index| format!("rbl-{index}.example"))
            .collect::<Vec<_>>()
            .join(",");
        for input in [
            "lmyzmail.contentfilter.rbl.timeout-ms=0\n".to_owned(),
            format!(
                "lmyzmail.contentfilter.rbl.timeout-ms={}\n",
                MAX_CONTENT_FILTER_RBL_TIMEOUT_MS + 1
            ),
            "lmyzmail.contentfilter.rbl.servers=-invalid.example\n".to_owned(),
            "lmyzmail.contentfilter.rbl.servers=two..dots.example\n".to_owned(),
            format!("lmyzmail.contentfilter.rbl.servers={too_many}\n"),
            "lmyzmail.contentfilter.rbl.score-per-hit=NaN\n".to_owned(),
            "lmyzmail.contentfilter.rbl.max-score=-1\n".to_owned(),
        ] {
            assert!(
                RuntimeConfig::from_properties(Properties::parse(input.as_bytes()).unwrap())
                    .is_err(),
                "accepted unsafe RBL configuration: {input}"
            );
        }
    }

    #[test]
    fn content_filter_numbers_are_finite_ordered_and_bounded() {
        for input in [
            b"lmyzmail.contentfilter.suspicious-threshold=NaN\n".as_slice(),
            b"lmyzmail.contentfilter.spam-threshold=Infinity\n".as_slice(),
            b"lmyzmail.contentfilter.suspicious-threshold=-1\n".as_slice(),
            b"lmyzmail.contentfilter.suspicious-threshold=11\nlmyzmail.contentfilter.spam-threshold=10\n".as_slice(),
            b"lmyzmail.contentfilter.rules.NEW_DOMAIN.weight=Infinity\n".as_slice(),
            b"lmyzmail.contentfilter.rules.MISSING_HEADERS.weight=-0.1\n".as_slice(),
            b"lmyzmail.contentfilter.rules.SUBJECT_ENCODING_TRICK.weight=NaN\n".as_slice(),
            b"lmyzmail.contentfilter.rules.EXCESSIVE_RECIPIENTS.weight=101\n".as_slice(),
            b"lmyzmail.contentfilter.rules.DANGEROUS_EXTENSION.weight=Infinity\n".as_slice(),
            b"lmyzmail.contentfilter.attachment.dangerous-extensions=\n".as_slice(),
            b"lmyzmail.contentfilter.attachment.dangerous-extensions=exe,ps-1\n".as_slice(),
            b"lmyzmail.contentfilter.attachment.dangerous-extension-score=-0.1\n".as_slice(),
            b"lmyzmail.contentfilter.attachment.double-extension-score=NaN\n".as_slice(),
            b"lmyzmail.contentfilter.attachment.mime-type-mismatch-score=1000001\n".as_slice(),
        ] {
            assert!(
                RuntimeConfig::from_properties(Properties::parse(input).unwrap()).is_err(),
                "accepted unsafe content-filter configuration: {}",
                String::from_utf8_lossy(input)
            );
        }

        let too_many = format!(
            "lmyzmail.contentfilter.attachment.dangerous-extensions={}\n",
            (0..=MAX_CONTENT_FILTER_EXTENSIONS)
                .map(|index| format!("x{index}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(
            RuntimeConfig::from_properties(Properties::parse(too_many.as_bytes()).unwrap())
                .is_err()
        );
    }

    #[test]
    fn xdp_configuration_accepts_legacy_aliases_and_new_precedence() {
        let config = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.xdp.enabled=true\n\
botmail.xdp.interface-name=legacy0\n\
botmail.xdp.pin-path=/sys/fs/bpf/botmail\n\
botmail.xdp.ban-threshold=80\n\
botmail.xdp.unban-threshold=-1\n\
botmail.xdp.whitelist=192.0.2.0/24\n\
botmail.xdp.reason-code-pps-overlimit=15\n\
botmail.xdp.reason-code-syn-flood=16\n\
lmyzmail.xdp.interface-name=new0\n\
lmyzmail.xdp.ban-threshold=100\n\
lmyzmail.xdp.whitelist=198.51.100.0/24,2001:db8::/32\n\
lmyzmail.xdp.reason-code-pps-overlimit=5\n\
lmyzmail.xdp.pps-monitor.poll-interval-ms=250\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(config.xdp.enabled);
        assert!(config.features.xdp);
        assert_eq!(config.xdp.interface_name, "new0");
        assert_eq!(config.xdp.pin_path, PathBuf::from("/sys/fs/bpf/botmail"));
        assert_eq!(config.xdp.ban_threshold, 100);
        assert_eq!(config.xdp.unban_threshold, 50);
        assert_eq!(config.xdp.reason_code_pps_overlimit, 5);
        assert_eq!(config.xdp.reason_code_syn_flood, 16);
        assert_eq!(config.xdp.pps_monitor.poll_interval_ms, 250);
        assert_eq!(config.xdp.whitelist.len(), 2);
        assert!(config.xdp.whitelist[0].contains(&"198.51.100.44".parse::<IpAddr>().unwrap()));
        assert!(config.xdp.whitelist[1].contains(&"2001:db8::44".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn xdp_pin_path_respects_the_frozen_native_buffer() {
        let valid = format!("/{}", "a".repeat(254));
        let too_long = format!("/{}", "a".repeat(255));
        assert_eq!(valid.len(), 255);
        assert!(validate_xdp_pin_path(&valid).is_ok());
        assert!(matches!(
            validate_xdp_pin_path(&too_long),
            Err(ConfigError::Invalid(message))
                if message == "xdp.pin-path exceeds the native 255-byte limit"
        ));
    }

    #[test]
    fn outbound_route_accepts_frozen_dns_keys_with_new_precedence() {
        let properties = Properties::parse(
            b"dns.cache.mx.l1-max-size=111\n\
dns.cache.mx.l1-ttl-minutes=12\n\
dns.cache.mx.l2-ttl-minutes=23\n\
dns.cache.mx.negative-ttl-minutes=4\n\
dns.cache.mx.query-timeout-seconds=9\n\
botmail.smtp.mta-sts-fetch-timeout-ms=8000\n\
lmyzmail.outbound.dns.mx.l1-max-entries=222\n\
lmyzmail.outbound.dns.query-timeout-seconds=7\n\
lmyzmail.smtp.mta-sts-fetch-timeout-ms=6000\n",
        )
        .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert_eq!(config.outbound_route.mx_l1_max_entries, 222);
        assert_eq!(config.outbound_route.mx_l1_ttl_minutes, 12);
        assert_eq!(config.outbound_route.mx_l2_ttl_minutes, 23);
        assert_eq!(config.outbound_route.mx_negative_ttl_minutes, 4);
        assert_eq!(config.outbound_route.dns_query_timeout_seconds, 7);
        assert_eq!(config.outbound_route.mta_sts_fetch_timeout_ms, 6_000);
        assert_eq!(config.outbound_route.resolution_deadline_seconds, 30);

        let invalid = RuntimeConfig::from_properties(
            Properties::parse(b"lmyzmail.outbound.dns.mx.l1-max-entries=0\n").unwrap(),
        );
        assert!(invalid.is_err());
        for input in [
            b"lmyzmail.outbound.dns.mx.l1-ttl-minutes=0\n".as_slice(),
            b"lmyzmail.outbound.dns.mx.l2-ttl-minutes=10081\n".as_slice(),
            b"lmyzmail.outbound.dns.mx.negative-ttl-minutes=1441\n".as_slice(),
            b"lmyzmail.outbound.dns.query-timeout-seconds=301\n".as_slice(),
            b"lmyzmail.smtp.mta-sts-fetch-timeout-ms=300001\n".as_slice(),
            b"lmyzmail.outbound.route-deadline-seconds=901\n".as_slice(),
        ] {
            assert!(
                RuntimeConfig::from_properties(Properties::parse(input).unwrap()).is_err(),
                "accepted unsafe outbound route configuration: {}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn reporting_accepts_legacy_keys_with_new_precedence_and_safe_bounds() {
        let config = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.reporting.enabled=false\n\
botmail.reporting.auto-send-enabled=true\n\
botmail.reporting.batch-size=750\n\
botmail.reporting.flush-interval-ms=2500\n\
botmail.reporting.retention-days=120\n\
botmail.reporting.min-volume-for-report=-2\n\
botmail.reporting.dmarc-report-sender-address=legacy-dmarc@example.test\n\
botmail.reporting.tls-report-sender-address=legacy-tls@example.test\n\
botmail.reporting.organization-name=Legacy Org\n\
botmail.reporting.organization-email=legacy@example.test\n\
botmail.reporting.http-delivery-enabled=true\n\
botmail.reporting.http-delivery-timeout-seconds=45\n\
dns.server=127.0.0.1:5353\n\
botmail.reporting.dns-server=127.0.0.1:5354\n\
lmyzmail.reporting.enabled=true\n\
lmyzmail.reporting.dmarc-report-sender-address=\n\
lmyzmail.reporting.min-volume-for-report=10\n\
lmyzmail.reporting.http-delivery-enabled=false\n",
            )
            .unwrap(),
        )
        .unwrap();

        assert!(config.reporting.enabled);
        assert!(config.reporting.auto_send_enabled);
        assert_eq!(config.reporting.batch_size, 750);
        assert_eq!(config.reporting.flush_interval_ms, 2_500);
        assert_eq!(config.reporting.retention_days, 120);
        assert_eq!(config.reporting.min_volume_for_report, 10);
        assert_eq!(
            config.reporting.dmarc_report_sender_address.as_deref(),
            Some("")
        );
        assert_eq!(
            config.reporting.tls_report_sender_address.as_deref(),
            Some("legacy-tls@example.test")
        );
        assert_eq!(
            config.reporting.organization_name.as_deref(),
            Some("Legacy Org")
        );
        assert_eq!(
            config.reporting.organization_email.as_deref(),
            Some("legacy@example.test")
        );
        assert!(!config.reporting.http_delivery_enabled);
        assert_eq!(config.reporting.http_delivery_timeout_seconds, 45);
        assert_eq!(
            config.reporting.dns_server,
            Some("127.0.0.1:5354".parse().unwrap())
        );

        let new_dns_wins = RuntimeConfig::from_properties(
            Properties::parse(
                b"dns.server=127.0.0.1:5353\n\
botmail.reporting.dns-server=127.0.0.1:5354\n\
lmyzmail.reporting.dns-server=127.0.0.1:5355\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            new_dns_wins.reporting.dns_server,
            Some("127.0.0.1:5355".parse().unwrap())
        );

        for input in [
            b"lmyzmail.reporting.batch-size=0\n".as_slice(),
            b"lmyzmail.reporting.batch-size=100001\n".as_slice(),
            b"lmyzmail.reporting.flush-interval-ms=0\n".as_slice(),
            b"lmyzmail.reporting.flush-interval-ms=3600001\n".as_slice(),
            b"lmyzmail.reporting.retention-days=36501\n".as_slice(),
            b"lmyzmail.reporting.http-delivery-timeout-seconds=0\n".as_slice(),
            b"lmyzmail.reporting.http-delivery-timeout-seconds=301\n".as_slice(),
            b"lmyzmail.reporting.dns-server=dns.example.test:53\n".as_slice(),
        ] {
            assert!(
                RuntimeConfig::from_properties(Properties::parse(input).unwrap()).is_err(),
                "accepted unsafe reporting configuration: {}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn legacy_properties_are_accepted_without_api_keys() {
        let properties = Properties::parse(
            b"spring.datasource.url=jdbc:postgresql://db.internal:15432/old_db?sslmode=disable\nspring.datasource.username=old_user\nbotmail.maildir.base=/old/mail\nbotmail.smtp.bind-address=localhost\nbotmail.netty.http.worker-threads=0\nbotmail.netty.http.idle-timeout-seconds=60\n",
        )
        .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert_eq!(config.postgres.username, "old_user");
        assert_eq!(config.postgres.database, "old_db");
        assert_eq!(config.postgres.host, "db.internal");
        assert_eq!(config.postgres.port, 15432);
        assert_eq!(config.maildir, PathBuf::from("/old/mail"));
        assert_eq!(config.listen.host, "localhost");
        assert_eq!(config.limits.max_http_connections, 256);
        assert_eq!(config.limits.http_deadline_ms, 60_000);
        assert!(config.api_keys.is_empty());
    }

    #[test]
    fn redis_credentials_and_tls_accept_legacy_aliases_with_new_precedence() {
        let properties = Properties::parse(
            b"spring.data.redis.username=legacy-user\n\
spring.data.redis.password=legacy-password\n\
spring.data.redis.ssl.enabled=false\n\
lmyzmail.redis.username=new-user\n\
lmyzmail.redis.password=new-password\n\
lmyzmail.redis.tls-enabled=true\n",
        )
        .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert_eq!(config.redis.username.as_deref(), Some("new-user"));
        assert_eq!(config.redis.password.as_deref(), Some("new-password"));
        assert!(config.redis.tls);

        let legacy = RuntimeConfig::from_properties(
            Properties::parse(
                b"spring.data.redis.username=legacy-user\n\
spring.data.redis.password=legacy-password\n\
spring.data.redis.ssl.enabled=true\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(legacy.redis.username.as_deref(), Some("legacy-user"));
        assert_eq!(legacy.redis.password.as_deref(), Some("legacy-password"));
        assert!(legacy.redis.tls);
    }

    #[test]
    fn trusted_proxy_aliases_parse_cidr_and_new_config_wins() {
        let properties = Properties::parse(
            b"botmail.netty.http.trusted-proxies=192.0.2.0/24\n\
lmyzmail.http.trusted-proxies=127.0.0.1,10.0.0.0/8\n",
        )
        .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert_eq!(config.trusted_proxies.len(), 2);
        assert!(config.trusted_proxies[0].contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(config.trusted_proxies[1].contains(&"10.4.3.2".parse::<IpAddr>().unwrap()));
        assert!(!config.trusted_proxies[1].contains(&"192.0.2.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn malformed_or_oversized_input_is_rejected() {
        assert!(Properties::parse(&vec![b'x'; MAX_CONFIG_BYTES + 1]).is_err());
        assert!(Properties::parse(b"bad=\\u12zz\n").is_err());
        assert!(Properties::parse(b"bad=hello\0world\n").is_err());
    }

    #[test]
    fn semantic_json_is_converted_to_the_same_alias_map() {
        let json = br#"{
            "schema_version": 1,
            "profile": "test",
            "listen": {"host": "localhost", "http": 18080, "smtp": 11025, "htcpcp": 18888, "minecraft": 25575},
            "postgres": {"host": "localhost", "port": 15432, "database": "lmyzmail", "username": "qa", "password": ""},
            "redis": {"host": "localhost", "port": 16379, "database": 0},
            "maildir": "/tmp/lmyzmail-mail",
            "domain": "example.test",
            "trusted_proxies": ["127.0.0.1", "10.0.0.0/8"],
            "features": {"smtp_skibidi_mode": "JAVA", "xdp": true},
            "xdp": {
                "interface_name": "semantic0",
                "pin_path": "/sys/fs/bpf/lmyzmail-semantic",
                "ban_threshold": 80,
                "unban_threshold": 30,
                "force_generic_mode": true,
                "sync_on_startup": false,
                "whitelist": ["198.51.100.0/24", "2001:db8::/32"],
                "reason_code_default": 6,
                "reason_code_pps_overlimit": 15,
                "reason_code_syn_flood": 16,
                "pps_monitor": {
                    "poll_interval_ms": 250,
                    "record_to_cringe": false,
                    "max_ips_per_poll": 128,
                    "ring_buffer_size": 64
                }
            },
            "minecraft": {
                "enabled": true,
                "online_mode": false,
                "compression_threshold": 512,
                "max_players": 42,
                "motd": "semantic-status",
                "favicon": " cGl4ZWw= ",
                "read_timeout_seconds": 75,
                "session_server_url": "http://127.0.0.1:18081/session/minecraft/hasJoined",
                "world_template": "worlds/mailroom",
                "view_distance": 31,
                "max_concurrent_videos": 7,
                "spawn": {"x": -12.75, "y": 70.9, "z": 34.5, "yaw": 45.0, "pitch": -15.0},
                "video": {
                    "center_x": 16,
                    "center_y": 179,
                    "wall_z": -64,
                    "max_width": 80,
                    "max_fps": 24,
                    "default_width": 40,
                    "default_fps": 12,
                    "default_contrast": 1.4,
                    "spawn_protect_radius": 4,
                    "clear_margin": 3,
                    "map_center_x": 17,
                    "map_center_y": 181,
                    "map_center_z": -21,
                    "map_facing": "west",
                    "map_max_maps_x": 12,
                    "map_max_maps_y": 11,
                    "map_max_fps": 22,
                    "map_default_maps_x": 6,
                    "map_default_fps": 11,
                    "map_default_contrast": 1.3,
                    "base_map_id": 11000,
                    "base_entity_id": 110000
                },
                "whitelist_enabled": true,
                "whitelist_players": ["SemanticAllowed"],
                "blacklist_players": ["SemanticBlocked"]
            },
            "mail_render": {"simd_mode": "AVX2"},
            "limits": {"max_http_request_bytes": 65536}
        }"#;
        let properties = parse_semantic_json(json).unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert_eq!(config.profile, "test");
        assert_eq!(config.listen.http, 18080);
        assert_eq!(config.postgres.port, 15432);
        assert_eq!(config.redis.port, 16379);
        assert_eq!(config.limits.max_http_request_bytes, 65536);
        assert_eq!(config.trusted_proxies.len(), 2);
        assert!(config.xdp.enabled);
        assert_eq!(config.xdp.interface_name, "semantic0");
        assert_eq!(
            config.xdp.pin_path,
            PathBuf::from("/sys/fs/bpf/lmyzmail-semantic")
        );
        assert_eq!(config.xdp.ban_threshold, 80);
        assert_eq!(config.xdp.unban_threshold, 30);
        assert!(config.xdp.force_generic_mode);
        assert!(!config.xdp.sync_on_startup);
        assert_eq!(config.xdp.whitelist.len(), 2);
        assert_eq!(config.xdp.reason_code_default, 6);
        assert_eq!(config.xdp.reason_code_pps_overlimit, 15);
        assert_eq!(config.xdp.reason_code_syn_flood, 16);
        assert_eq!(config.xdp.pps_monitor.poll_interval_ms, 250);
        assert!(!config.xdp.pps_monitor.record_to_cringe);
        assert_eq!(config.xdp.pps_monitor.max_ips_per_poll, 128);
        assert_eq!(config.xdp.pps_monitor.ring_buffer_size, 64);
        assert!(config.minecraft.enabled);
        assert!(!config.minecraft.online_mode);
        assert_eq!(config.minecraft.compression_threshold, 512);
        assert_eq!(config.minecraft.max_players, 42);
        assert_eq!(config.minecraft.motd, "semantic-status");
        assert_eq!(config.minecraft.favicon, " cGl4ZWw= ");
        assert_eq!(config.minecraft.read_timeout_seconds, 75);
        assert_eq!(
            config.minecraft.session_server_url,
            "http://127.0.0.1:18081/session/minecraft/hasJoined"
        );
        assert_eq!(config.minecraft.world_template, "worlds/mailroom");
        assert_eq!(config.minecraft.view_distance, 31);
        assert_eq!(config.minecraft.max_concurrent_videos, 7);
        assert_eq!(config.minecraft.video.center_x, 16);
        assert_eq!(config.minecraft.video.center_y, 179);
        assert_eq!(config.minecraft.video.wall_z, -64);
        assert_eq!(config.minecraft.video.max_width, 80);
        assert_eq!(config.minecraft.video.max_fps, 24);
        assert_eq!(config.minecraft.video.default_width, 40);
        assert_eq!(config.minecraft.video.default_fps, 12);
        assert_eq!(config.minecraft.video.default_contrast, 1.4);
        assert_eq!(config.minecraft.video.spawn_protect_radius, 4);
        assert_eq!(config.minecraft.video.clear_margin, 3);
        assert_eq!(config.minecraft.video.map_center_x, 17);
        assert_eq!(config.minecraft.video.map_center_y, 181);
        assert_eq!(config.minecraft.video.map_center_z, -21);
        assert_eq!(config.minecraft.video.map_facing, "WEST");
        assert_eq!(config.minecraft.video.map_max_maps_x, 12);
        assert_eq!(config.minecraft.video.map_max_maps_y, 11);
        assert_eq!(config.minecraft.video.map_max_fps, 22);
        assert_eq!(config.minecraft.video.map_default_maps_x, 6);
        assert_eq!(config.minecraft.video.map_default_fps, 11);
        assert_eq!(config.minecraft.video.map_default_contrast, 1.3);
        assert_eq!(config.minecraft.video.base_map_id, 11_000);
        assert_eq!(config.minecraft.video.base_entity_id, 110_000);
        assert_eq!(config.minecraft.spawn.x, -12.75);
        assert_eq!(config.minecraft.spawn.y, 70.9);
        assert_eq!(config.minecraft.spawn.z, 34.5);
        assert_eq!(config.minecraft.spawn.yaw, 45.0);
        assert_eq!(config.minecraft.spawn.pitch, -15.0);
        assert!(config.minecraft.whitelist_enabled);
        assert_eq!(config.minecraft.whitelist_players, ["SemanticAllowed"]);
        assert_eq!(config.minecraft.blacklist_players, ["SemanticBlocked"]);
        assert_eq!(config.mail_render.simd_mode, MailRenderSimdMode::Avx2);
    }

    #[test]
    fn htcpcp_defaults_include_one_coffee_pot() {
        let config = RuntimeConfig::from_properties(Properties::default()).unwrap();
        assert!(!config.htcpcp.enabled);
        assert_eq!(config.htcpcp.default_brew_time_seconds, 30);
        assert_eq!(config.htcpcp.pots.len(), 1);
        assert_eq!(config.htcpcp.pots[0].id, "pot-0");
        assert_eq!(config.htcpcp.pots[0].pot_type, "coffee");
        assert_eq!(
            config.htcpcp.pots[0].tea_varieties,
            ["darjeeling", "earl-grey", "peppermint"]
        );
        assert!(!config.minecraft.enabled);
        assert!(config.minecraft.online_mode);
        assert_eq!(config.minecraft.compression_threshold, 256);
        assert_eq!(config.minecraft.max_players, 20);
        assert_eq!(
            config.minecraft.motd,
            "§6LMYZMAIL §7- Send emails in Minecraft"
        );
        assert_eq!(config.minecraft.read_timeout_seconds, 30);
        assert_eq!(
            config.minecraft.session_server_url,
            "https://sessionserver.mojang.com/session/minecraft/hasJoined"
        );
        assert_eq!(config.minecraft.world_template, "worlds/mailroom");
        assert_eq!(config.minecraft.view_distance, 32);
        assert_eq!(config.minecraft.max_concurrent_videos, 2);
        assert_eq!(config.minecraft.video.center_x, 0);
        assert_eq!(config.minecraft.video.center_y, 180);
        assert_eq!(config.minecraft.video.wall_z, -20);
        assert_eq!(config.minecraft.video.max_width, 64);
        assert_eq!(config.minecraft.video.max_fps, 20);
        assert_eq!(config.minecraft.video.default_width, 32);
        assert_eq!(config.minecraft.video.default_fps, 10);
        assert_eq!(config.minecraft.video.default_contrast, 1.2);
        assert_eq!(config.minecraft.video.spawn_protect_radius, 8);
        assert_eq!(config.minecraft.video.clear_margin, 2);
        assert_eq!(config.minecraft.video.map_center_x, 0);
        assert_eq!(config.minecraft.video.map_center_y, 180);
        assert_eq!(config.minecraft.video.map_center_z, -20);
        assert_eq!(config.minecraft.video.map_facing, "SOUTH");
        assert_eq!(config.minecraft.video.map_max_maps_x, 10);
        assert_eq!(config.minecraft.video.map_max_maps_y, 10);
        assert_eq!(config.minecraft.video.map_max_fps, 20);
        assert_eq!(config.minecraft.video.map_default_maps_x, 5);
        assert_eq!(config.minecraft.video.map_default_fps, 10);
        assert_eq!(config.minecraft.video.map_default_contrast, 1.2);
        assert_eq!(config.minecraft.video.base_map_id, 10_000);
        assert_eq!(config.minecraft.video.base_entity_id, 100_000);
        assert_eq!(config.mail_render.simd_mode, MailRenderSimdMode::Auto);
        assert!(config.minecraft.favicon.is_empty());
        assert_eq!(config.minecraft.spawn.x, 0.5);
        assert_eq!(config.minecraft.spawn.y, 160.0);
        assert_eq!(config.minecraft.spawn.z, 0.5);
        assert_eq!(config.minecraft.spawn.yaw, 0.0);
        assert_eq!(config.minecraft.spawn.pitch, 0.0);
        assert!(!config.minecraft.whitelist_enabled);
        assert!(config.minecraft.whitelist_players.is_empty());
        assert!(config.minecraft.blacklist_players.is_empty());
    }

    #[test]
    fn htcpcp_legacy_alias_and_new_keys_preserve_precedence() {
        let properties = Properties::parse(
            b"botmail.htcpcp.enabled=false\n\
botmail.htcpcp.default-brew-time-seconds=41\n\
botmail.htcpcp.pots[0].id=legacy-pot\n\
botmail.htcpcp.pots[0].type=tea\n\
botmail.htcpcp.pots[0].tea-varieties=legacy-tea\n\
lmyzmail.htcpcp.enabled=true\n\
lmyzmail.htcpcp.default-brew-time-seconds=42\n\
lmyzmail.htcpcp.pots[0].id=new-pot\n\
lmyzmail.htcpcp.pots[0].type=coffee\n\
lmyzmail.htcpcp.pots[0].tea-varieties=new-tea\n",
        )
        .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert!(config.htcpcp.enabled);
        assert_eq!(config.htcpcp.default_brew_time_seconds, 42);
        assert_eq!(config.htcpcp.pots[0].id, "new-pot");
        assert_eq!(config.htcpcp.pots[0].pot_type, "coffee");
        assert_eq!(config.htcpcp.pots[0].tea_varieties, ["new-tea"]);
    }

    #[test]
    fn minecraft_aliases_are_bounded_and_new_keys_win() {
        let properties = Properties::parse(
            b"botmail.minecraft.enabled=false\n\
botmail.minecraft.online-mode=true\n\
botmail.minecraft.compression-threshold=1024\n\
botmail.minecraft.max-players=40\n\
botmail.minecraft.motd=legacy\n\
botmail.minecraft.favicon=bGVnYWN5\n\
botmail.minecraft.read-timeout-seconds=45\n\
botmail.minecraft.session-server-url=https://legacy-session.example.test/hasJoined\n\
botmail.minecraft.world-template=legacy-world\n\
botmail.minecraft.view-distance=12\n\
botmail.minecraft.max-concurrent-videos=4\n\
botmail.minecraft.video.center-x=7\n\
botmail.minecraft.video.center-y=170\n\
botmail.minecraft.video.wall-z=-9\n\
botmail.minecraft.video.max-width=80\n\
botmail.minecraft.video.max-fps=25\n\
botmail.minecraft.video.default-width=40\n\
botmail.minecraft.video.default-fps=12\n\
botmail.minecraft.video.default-contrast=1.4\n\
botmail.minecraft.video.spawn-protect-radius=4\n\
botmail.minecraft.video.clear-margin=3\n\
botmail.minecraft.map-video.center-x=8\n\
botmail.minecraft.map-video.center-y=170\n\
botmail.minecraft.map-video.center-z=-19\n\
botmail.minecraft.map-video.facing=north\n\
botmail.minecraft.map-video.max-maps-x=12\n\
botmail.minecraft.map-video.max-maps-y=11\n\
botmail.minecraft.map-video.max-fps=25\n\
botmail.minecraft.map-video.default-maps-x=6\n\
botmail.minecraft.map-video.default-fps=12\n\
botmail.minecraft.map-video.default-contrast=1.4\n\
botmail.minecraft.map-video.base-map-id=9000\n\
botmail.minecraft.map-video.base-entity-id=90000\n\
botmail.minecraft.spawn.x=1.5\n\
botmail.minecraft.spawn.y=65.25\n\
botmail.minecraft.spawn.z=2.5\n\
botmail.minecraft.spawn.yaw=10.0\n\
botmail.minecraft.spawn.pitch=20.0\n\
botmail.minecraft.whitelist.enabled=false\n\
botmail.minecraft.whitelist.players=LegacyAllowed\n\
botmail.minecraft.blacklist.players=LegacyBlocked\n\
botmail.minecraft.auth.max-attempts=9\n\
botmail.minecraft.auth.lockout-seconds=100\n\
botmail.minecraft.auth.window-seconds=200\n\
lmyzmail.minecraft.enabled=true\n\
lmyzmail.minecraft.online-mode=false\n\
lmyzmail.minecraft.compression-threshold=256\n\
lmyzmail.minecraft.max-players=20\n\
lmyzmail.minecraft.motd=new\n\
lmyzmail.minecraft.favicon=bmV3\n\
lmyzmail.minecraft.read-timeout-seconds=30\n\
lmyzmail.minecraft.session-server-url=http://127.0.0.1:18081/hasJoined\n\
lmyzmail.minecraft.world-template=worlds/mailroom\n\
lmyzmail.minecraft.view-distance=32\n\
lmyzmail.minecraft.max-concurrent-videos=3\n\
lmyzmail.minecraft.video.center-x=0\n\
lmyzmail.minecraft.video.center-y=161\n\
lmyzmail.minecraft.video.wall-z=-50\n\
lmyzmail.minecraft.video.max-width=64\n\
lmyzmail.minecraft.video.max-fps=20\n\
lmyzmail.minecraft.video.default-width=32\n\
lmyzmail.minecraft.video.default-fps=10\n\
lmyzmail.minecraft.video.default-contrast=1.2\n\
lmyzmail.minecraft.video.spawn-protect-radius=1\n\
lmyzmail.minecraft.video.clear-margin=2\n\
lmyzmail.minecraft.map-video.center-x=1\n\
lmyzmail.minecraft.map-video.center-y=180\n\
lmyzmail.minecraft.map-video.center-z=-20\n\
lmyzmail.minecraft.map-video.facing=east\n\
lmyzmail.minecraft.map-video.max-maps-x=10\n\
lmyzmail.minecraft.map-video.max-maps-y=9\n\
lmyzmail.minecraft.map-video.max-fps=20\n\
lmyzmail.minecraft.map-video.default-maps-x=5\n\
lmyzmail.minecraft.map-video.default-fps=10\n\
lmyzmail.minecraft.map-video.default-contrast=1.2\n\
lmyzmail.minecraft.map-video.base-map-id=10000\n\
lmyzmail.minecraft.map-video.base-entity-id=100000\n\
lmyzmail.minecraft.spawn.x=-12.75\n\
lmyzmail.minecraft.spawn.y=70.9\n\
lmyzmail.minecraft.spawn.z=34.5\n\
lmyzmail.minecraft.spawn.yaw=45.0\n\
lmyzmail.minecraft.spawn.pitch=-15.0\n\
lmyzmail.minecraft.whitelist.enabled=true\n\
lmyzmail.minecraft.whitelist.players=NewAllowed, SecondAllowed\n\
lmyzmail.minecraft.whitelist.players[0]=IgnoredIndexedAllowed\n\
lmyzmail.minecraft.blacklist.players=NewBlocked\n\
lmyzmail.minecraft.auth.max-attempts=5\n\
lmyzmail.minecraft.auth.lockout-seconds=300\n\
lmyzmail.minecraft.auth.window-seconds=600\n",
        )
        .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert!(config.minecraft.enabled);
        assert!(!config.minecraft.online_mode);
        assert_eq!(config.minecraft.compression_threshold, 256);
        assert_eq!(config.minecraft.max_players, 20);
        assert_eq!(config.minecraft.motd, "new");
        assert_eq!(config.minecraft.favicon, "bmV3");
        assert_eq!(config.minecraft.read_timeout_seconds, 30);
        assert_eq!(
            config.minecraft.session_server_url,
            "http://127.0.0.1:18081/hasJoined"
        );
        assert_eq!(config.minecraft.world_template, "worlds/mailroom");
        assert_eq!(config.minecraft.view_distance, 32);
        assert_eq!(config.minecraft.max_concurrent_videos, 3);
        assert_eq!(config.minecraft.video.center_x, 0);
        assert_eq!(config.minecraft.video.center_y, 161);
        assert_eq!(config.minecraft.video.wall_z, -50);
        assert_eq!(config.minecraft.video.max_width, 64);
        assert_eq!(config.minecraft.video.max_fps, 20);
        assert_eq!(config.minecraft.video.default_width, 32);
        assert_eq!(config.minecraft.video.default_fps, 10);
        assert_eq!(config.minecraft.video.default_contrast, 1.2);
        assert_eq!(config.minecraft.video.spawn_protect_radius, 1);
        assert_eq!(config.minecraft.video.clear_margin, 2);
        assert_eq!(config.minecraft.video.map_center_x, 1);
        assert_eq!(config.minecraft.video.map_center_y, 180);
        assert_eq!(config.minecraft.video.map_center_z, -20);
        assert_eq!(config.minecraft.video.map_facing, "EAST");
        assert_eq!(config.minecraft.video.map_max_maps_x, 10);
        assert_eq!(config.minecraft.video.map_max_maps_y, 9);
        assert_eq!(config.minecraft.video.map_max_fps, 20);
        assert_eq!(config.minecraft.video.map_default_maps_x, 5);
        assert_eq!(config.minecraft.video.map_default_fps, 10);
        assert_eq!(config.minecraft.video.map_default_contrast, 1.2);
        assert_eq!(config.minecraft.video.base_map_id, 10_000);
        assert_eq!(config.minecraft.video.base_entity_id, 100_000);
        assert_eq!(config.minecraft.spawn.x, -12.75);
        assert_eq!(config.minecraft.spawn.y, 70.9);
        assert_eq!(config.minecraft.spawn.z, 34.5);
        assert_eq!(config.minecraft.spawn.yaw, 45.0);
        assert_eq!(config.minecraft.spawn.pitch, -15.0);
        assert!(config.minecraft.whitelist_enabled);
        assert_eq!(
            config.minecraft.whitelist_players,
            ["NewAllowed", "SecondAllowed"]
        );
        assert_eq!(config.minecraft.blacklist_players, ["NewBlocked"]);
        assert_eq!(config.minecraft.auth_max_attempts, 5);
        assert_eq!(config.minecraft.auth_lockout_seconds, 300);
        assert_eq!(config.minecraft.auth_window_seconds, 600);

        for value in [
            "lmyzmail.minecraft.max-players=2147483648\n",
            "lmyzmail.minecraft.compression-threshold=-2\n",
            "lmyzmail.minecraft.compression-threshold=2097153\n",
            "lmyzmail.minecraft.compression-threshold=nope\n",
            "lmyzmail.minecraft.spawn.x=nope\n",
            "lmyzmail.minecraft.spawn.yaw=nope\n",
            "lmyzmail.minecraft.read-timeout-seconds=0\n",
            "lmyzmail.minecraft.read-timeout-seconds=3601\n",
            "lmyzmail.minecraft.view-distance=65\n",
            "lmyzmail.minecraft.view-distance=-1\n",
            "lmyzmail.minecraft.max-concurrent-videos=0\n",
            "lmyzmail.minecraft.max-concurrent-videos=65\n",
            "lmyzmail.minecraft.video.center-x=nope\n",
            "lmyzmail.minecraft.video.center-y=256\n",
            "lmyzmail.minecraft.video.max-width=3\n",
            "lmyzmail.minecraft.video.max-width=257\n",
            "lmyzmail.minecraft.video.max-fps=0\n",
            "lmyzmail.minecraft.video.max-fps=61\n",
            "lmyzmail.minecraft.video.default-width=65\n",
            "lmyzmail.minecraft.video.default-fps=21\n",
            "lmyzmail.minecraft.video.default-contrast=NaN\n",
            "lmyzmail.minecraft.video.spawn-protect-radius=257\n",
            "lmyzmail.minecraft.video.clear-margin=65\n",
            "lmyzmail.minecraft.map-video.max-maps-x=1\n",
            "lmyzmail.minecraft.map-video.max-maps-x=17\n",
            "lmyzmail.minecraft.map-video.default-maps-x=11\n",
            "lmyzmail.minecraft.map-video.default-contrast=Infinity\n",
            "lmyzmail.minecraft.map-video.base-map-id=-1\n",
            "lmyzmail.minecraft.world-template=\n",
            "lmyzmail.minecraft.motd=bad\\u0009motd\n",
            "lmyzmail.minecraft.session-server-url=http://session.example.test/hasJoined\n",
            "lmyzmail.minecraft.session-server-url=https://session.example.test/hasJoined?bad=true\n",
            "lmyzmail.minecraft.session-server-url=https://user:pass@session.example.test/hasJoined\n",
            "lmyzmail.minecraft.auth.max-attempts=0\n",
            "lmyzmail.minecraft.auth.max-attempts=1001\n",
            "lmyzmail.minecraft.auth.lockout-seconds=0\n",
            "lmyzmail.minecraft.auth.lockout-seconds=86401\n",
            "lmyzmail.minecraft.auth.window-seconds=0\n",
            "lmyzmail.minecraft.auth.window-seconds=86401\n",
        ] {
            let properties = Properties::parse(value.as_bytes()).unwrap();
            assert!(RuntimeConfig::from_properties(properties).is_err());
        }

        let mut oversized = Properties::default();
        oversized
            .insert(
                "lmyzmail.minecraft.motd".to_owned(),
                "\\".repeat(MAX_MINECRAFT_STATUS_JSON_BYTES),
            )
            .unwrap();
        assert!(RuntimeConfig::from_properties(oversized).is_err());

        let legacy_indexed = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.minecraft.whitelist.players[0]=LegacyOne\n\
botmail.minecraft.whitelist.players[1]=LegacyTwo\n\
botmail.minecraft.blacklist.players[0]=LegacyBlocked\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            legacy_indexed.minecraft.whitelist_players,
            ["LegacyOne", "LegacyTwo"]
        );
        assert_eq!(
            legacy_indexed.minecraft.blacklist_players,
            ["LegacyBlocked"]
        );

        for value in [
            "lmyzmail.minecraft.whitelist.players=One,,Two\n",
            "lmyzmail.minecraft.blacklist.players=,\n",
        ] {
            let properties = Properties::parse(value.as_bytes()).unwrap();
            assert!(RuntimeConfig::from_properties(properties).is_err());
        }
    }

    #[test]
    fn mail_render_simd_alias_matches_java_fallback_and_new_key_precedence() {
        let config = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.mailrender.simd-mode=AVX512\n\
lmyzmail.mailrender.simd-mode=scalar\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(config.mail_render.simd_mode, MailRenderSimdMode::Scalar);

        for (value, expected) in [
            ("AVX2", MailRenderSimdMode::Avx2),
            ("avx512", MailRenderSimdMode::Avx512),
            ("AUTO", MailRenderSimdMode::Auto),
            (" AVX2 ", MailRenderSimdMode::Auto),
            ("unknown", MailRenderSimdMode::Auto),
        ] {
            let properties =
                Properties::parse(format!("botmail.mailrender.simd-mode={value}\n").as_bytes())
                    .unwrap();
            assert_eq!(
                RuntimeConfig::from_properties(properties)
                    .unwrap()
                    .mail_render
                    .simd_mode,
                expected
            );
        }
    }

    #[test]
    fn semantic_json_accepts_eight_valid_pots() {
        let pots: Vec<serde_json::Value> = (0..8)
            .map(|index| {
                let pot_type = match index % 3 {
                    0 => "coffee",
                    1 => "tea",
                    _ => "both",
                };
                serde_json::json!({
                    "id": format!("pot-{index}"),
                    "type": pot_type,
                    "tea_varieties": if pot_type == "coffee" {
                        serde_json::json!([])
                    } else {
                        serde_json::json!([format!("tea-{index}")])
                    },
                    "supported_additions": ["Sugar", format!("Addition-{index}")]
                })
            })
            .collect();
        let bytes = semantic_json_with_htcpcp(serde_json::json!({
            "enabled": true,
            "default_brew_time_seconds": MAX_HTCPCP_BREW_SECONDS,
            "pots": pots
        }));
        let config = RuntimeConfig::from_properties(parse_semantic_json(&bytes).unwrap()).unwrap();
        assert!(config.htcpcp.enabled);
        assert_eq!(
            config.htcpcp.default_brew_time_seconds,
            MAX_HTCPCP_BREW_SECONDS
        );
        assert_eq!(config.htcpcp.pots.len(), 8);
        assert_eq!(config.htcpcp.pots[1].pot_type, "tea");
        assert_eq!(config.htcpcp.pots[2].pot_type, "both");
        assert_eq!(config.htcpcp.pots[7].id, "pot-7");
    }

    #[test]
    fn semantic_json_empty_pots_are_rejected_but_omission_uses_default() {
        let omitted = semantic_json_with_htcpcp(serde_json::json!({"enabled": true}));
        let config =
            RuntimeConfig::from_properties(parse_semantic_json(&omitted).unwrap()).unwrap();
        assert_eq!(config.htcpcp.pots.len(), 1);
        assert_eq!(config.htcpcp.pots[0].id, "pot-0");

        let empty = semantic_json_with_htcpcp(serde_json::json!({
            "enabled": true,
            "pots": []
        }));
        assert!(parse_semantic_json(&empty).is_err());
    }

    #[test]
    fn semantic_json_htcpcp_lists_reject_embedded_csv_delimiters() {
        for (field, value) in [
            ("tea_varieties", "green,black"),
            ("supported_additions", "Sugar,Rum"),
        ] {
            let bytes = semantic_json_with_htcpcp(serde_json::json!({
                "enabled": true,
                "pots": [{
                    "id": "pot-0",
                    "type": "both",
                    "tea_varieties": if field == "tea_varieties" { vec![value] } else { vec!["green"] },
                    "supported_additions": if field == "supported_additions" { vec![value] } else { vec!["Sugar"] }
                }]
            }));
            let error = parse_semantic_json(&bytes).unwrap_err().to_string();
            assert!(error.contains(field), "unexpected error: {error}");
            assert!(
                error.contains("must not contain commas"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn htcpcp_rejects_gaps_and_duplicate_ids() {
        let gap = Properties::parse(
            b"lmyzmail.htcpcp.pots[0].id=pot-0\n\
lmyzmail.htcpcp.pots[0].type=coffee\n\
lmyzmail.htcpcp.pots[2].id=pot-2\n\
lmyzmail.htcpcp.pots[2].type=coffee\n",
        )
        .unwrap();
        assert!(RuntimeConfig::from_properties(gap).is_err());

        let duplicate = Properties::parse(
            b"lmyzmail.htcpcp.pots[0].id=same\n\
lmyzmail.htcpcp.pots[0].type=coffee\n\
lmyzmail.htcpcp.pots[1].id=same\n\
lmyzmail.htcpcp.pots[1].type=tea\n",
        )
        .unwrap();
        assert!(RuntimeConfig::from_properties(duplicate).is_err());
    }

    #[test]
    fn htcpcp_rejects_invalid_pot_type_and_duplicate_list_values() {
        for pot_type in ["espresso", "water"] {
            let properties = Properties::parse(
                format!(
                    "lmyzmail.htcpcp.pots[0].id=pot-0\n\
lmyzmail.htcpcp.pots[0].type={pot_type}\n"
                )
                .as_bytes(),
            )
            .unwrap();
            assert!(RuntimeConfig::from_properties(properties).is_err());
        }

        let duplicate_tea = Properties::parse(
            b"lmyzmail.htcpcp.pots[0].type=tea\n\
lmyzmail.htcpcp.pots[0].tea-varieties=darjeeling,Darjeeling\n",
        )
        .unwrap();
        assert!(RuntimeConfig::from_properties(duplicate_tea).is_err());

        let duplicate_addition =
            Properties::parse(b"lmyzmail.htcpcp.pots[0].supported-additions=Sugar,sugar\n")
                .unwrap();
        assert!(RuntimeConfig::from_properties(duplicate_addition).is_err());
    }

    #[test]
    fn htcpcp_enforces_maximum_pots_list_items_and_brew_seconds() {
        let max_pots = RuntimeConfig::from_properties(indexed_htcpcp_properties(64)).unwrap();
        assert_eq!(max_pots.htcpcp.pots.len(), MAX_HTCPCP_POTS);
        assert!(
            RuntimeConfig::from_properties(indexed_htcpcp_properties(MAX_HTCPCP_POTS + 1)).is_err()
        );

        let list_64 = (0..MAX_HTCPCP_LIST_ITEMS)
            .map(|index| format!("item-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let list_65 = (0..=MAX_HTCPCP_LIST_ITEMS)
            .map(|index| format!("item-{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let accepted_list = Properties::parse(
            format!(
                "lmyzmail.htcpcp.pots[0].tea-varieties={list_64}\n\
lmyzmail.htcpcp.pots[0].type=tea\n"
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            RuntimeConfig::from_properties(accepted_list)
                .unwrap()
                .htcpcp
                .pots[0]
                .tea_varieties
                .len(),
            MAX_HTCPCP_LIST_ITEMS
        );
        let rejected_list = Properties::parse(
            format!("lmyzmail.htcpcp.pots[0].tea-varieties={list_65}\n").as_bytes(),
        )
        .unwrap();
        assert!(RuntimeConfig::from_properties(rejected_list).is_err());

        let accepted_brew = Properties::parse(
            format!("lmyzmail.htcpcp.default-brew-time-seconds={MAX_HTCPCP_BREW_SECONDS}\n")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            RuntimeConfig::from_properties(accepted_brew)
                .unwrap()
                .htcpcp
                .default_brew_time_seconds,
            MAX_HTCPCP_BREW_SECONDS
        );
        let rejected_brew = Properties::parse(
            format!(
                "lmyzmail.htcpcp.default-brew-time-seconds={}\n",
                MAX_HTCPCP_BREW_SECONDS + 1
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(RuntimeConfig::from_properties(rejected_brew).is_err());
    }

    #[test]
    fn duplicate_ports_are_rejected() {
        let properties =
            Properties::parse(b"lmyzmail.http.port=8080\nlmyzmail.smtp.port=8080\n").unwrap();
        assert!(RuntimeConfig::from_properties(properties).is_err());
    }

    #[test]
    fn honeypot_aliases_are_bounded_and_new_keys_win() {
        let properties = Properties::parse(
            b"botmail.honeypot.enabled=true\n\
botmail.honeypot.max-connections-per-trap=100\n\
botmail.honeypot.max-read-bytes=1024\n\
botmail.honeypot.traps[0].port=3306\n\
botmail.honeypot.traps[0].server-protocol=mysql\n\
botmail.honeypot.traps[0].label=legacy\n\
botmail.honeypot.traps[0].bind-address=0.0.0.0\n\
lmyzmail.honeypot.max-connections-per-trap=4\n\
lmyzmail.honeypot.max-read-bytes=2048\n\
lmyzmail.honeypot.traps[0].label=current\n\
lmyzmail.honeypot.traps[0].bind-address=127.0.0.1\n",
        )
        .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert_eq!(config.listen.honeypots.len(), 1);
        assert_eq!(config.listen.honeypots[0].protocol, "MYSQL");
        assert_eq!(config.listen.honeypots[0].label, "current");
        assert_eq!(config.listen.honeypots[0].bind_address, "127.0.0.1");
        assert_eq!(config.limits.max_honeypot_connections_per_trap, 4);
        assert_eq!(config.limits.max_honeypot_read_bytes, 2048);

        let disabled = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.honeypot.enabled=true\n\
lmyzmail.honeypot.enabled=false\n\
botmail.honeypot.traps[0].port=3306\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(disabled.listen.honeypots.is_empty());
    }

    #[test]
    fn semantic_honeypot_config_and_limits_are_supported() {
        let json = br#"{
            "schema_version": 1,
            "profile": "test",
            "listen": {
                "host": "127.0.0.1",
                "http": 18080,
                "smtp": 11025,
                "htcpcp": 18888,
                "minecraft": 25575,
                "honeypots": [
                    {"port": 13306, "protocol": "MYSQL", "label": "mysql-trap"}
                ]
            },
            "postgres": {"host": "localhost", "port": 15432, "database": "lmyzmail", "username": "qa", "password": ""},
            "redis": {"host": "localhost", "port": 16379, "database": 0},
            "maildir": "/tmp/lmyzmail-mail",
            "domain": "example.test",
            "limits": {
                "max_honeypot_connections_per_trap": 4,
                "max_honeypot_read_bytes": 1024
            }
        }"#;
        let config = RuntimeConfig::from_properties(parse_semantic_json(json).unwrap()).unwrap();
        assert_eq!(config.listen.honeypots[0].bind_address, "127.0.0.1");
        assert_eq!(config.limits.max_honeypot_connections_per_trap, 4);
        assert_eq!(config.limits.max_honeypot_read_bytes, 1024);
    }

    #[test]
    fn invalid_honeypot_protocols_deadlines_and_limits_are_rejected() {
        for input in [
            b"lmyzmail.honeypot.enabled=true\nlmyzmail.honeypot.traps[0].port=3306\nlmyzmail.honeypot.traps[0].protocol=HTTP\n".as_slice(),
            b"lmyzmail.honeypot.initial-delay-ms=0\n".as_slice(),
            b"lmyzmail.honeypot.post-banner-timeout-ms=0\n".as_slice(),
            b"lmyzmail.honeypot.max-connections-per-trap=0\n".as_slice(),
            b"lmyzmail.honeypot.max-read-bytes=65537\n".as_slice(),
        ] {
            assert!(
                RuntimeConfig::from_properties(Properties::parse(input).unwrap()).is_err(),
                "accepted invalid honeypot configuration: {}",
                String::from_utf8_lossy(input),
            );
        }
    }

    #[test]
    fn web_limits_and_allowed_origins_accept_legacy_aliases_with_new_precedence() {
        let properties = Properties::parse(
            b"botmail.allowed-origins[0]=https://old.example\n\
lmyzmail.allowed-origins[0]=https://mail.example\n\
botmail.max-email-size-bytes=20971520\n\
botmail.max-attachment-size-bytes=5242880\n\
botmail.max-total-attachments-size-bytes=10485760\n\
botmail.show-internet-nl-badge=true\n",
        )
        .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert_eq!(config.allowed_origins, ["https://mail.example"]);
        assert_eq!(config.limits.max_email_size_bytes, 20 * 1024 * 1024);
        assert_eq!(config.limits.max_attachment_size_bytes, 5 * 1024 * 1024);
        assert_eq!(
            config.limits.max_total_attachments_size_bytes,
            10 * 1024 * 1024
        );
        assert!(config.features.show_internet_nl_badge);
        assert!(
            Properties::parse(b"lmyzmail.allowed-origins[0]=*\n")
                .and_then(RuntimeConfig::from_properties)
                .is_err()
        );
    }

    #[test]
    fn cringe_decay_defaults_aliases_and_duration_styles_match_spring() {
        let defaults = RuntimeConfig::from_properties(Properties::default()).unwrap();
        assert_eq!(defaults.cringe_decay.interval, Duration::from_secs(86_400));
        assert_eq!(defaults.cringe_decay.amount, 10);
        assert_eq!(
            defaults.cringe_decay.check_interval,
            Duration::from_secs(3_600)
        );
        assert_eq!(defaults.cringe_decay.activity_retention_days, 360);

        let config = RuntimeConfig::from_properties(
            Properties::parse(
                b"botmail.cringe.decay.interval=PT3H\n\
botmail.cringe.decay.amount=2\n\
botmail.cringe.decay.check-interval=30m\n\
botmail.cringe.decay.activity-retention-days=90\n\
lmyzmail.cringe.decay.interval=PT90M\n\
lmyzmail.cringe.decay.amount=4\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(config.cringe_decay.interval, Duration::from_secs(5_400));
        assert_eq!(config.cringe_decay.amount, 4);
        assert_eq!(
            config.cringe_decay.check_interval,
            Duration::from_secs(1_800)
        );
        assert_eq!(config.cringe_decay.activity_retention_days, 90);
    }

    #[test]
    fn cringe_decay_semantic_json_and_invalid_bounds_are_checked() {
        let json = br#"{
            "schema_version": 1,
            "profile": "test",
            "listen": {"host":"127.0.0.1","http":18080,"smtp":1025,"htcpcp":18888,"minecraft":25575},
            "postgres": {"host":"localhost","port":15432,"database":"lmyzmail","username":"qa","password":""},
            "redis": {"host":"localhost","port":16379,"database":0},
            "maildir": "/tmp/lmyzmail-mail",
            "domain": "example.test",
            "cringe": {"decay":{"interval":"PT6H","amount":3,"check_interval":"45m","activity_retention_days":30}}
        }"#;
        let config = RuntimeConfig::from_properties(parse_semantic_json(json).unwrap()).unwrap();
        assert_eq!(config.cringe_decay.interval, Duration::from_secs(21_600));
        assert_eq!(config.cringe_decay.amount, 3);
        assert_eq!(
            config.cringe_decay.check_interval,
            Duration::from_secs(2_700)
        );
        assert_eq!(config.cringe_decay.activity_retention_days, 30);

        for input in [
            b"lmyzmail.cringe.decay.interval=0ms\n".as_slice(),
            b"lmyzmail.cringe.decay.interval=P1M\n".as_slice(),
            b"lmyzmail.cringe.decay.amount=-1\n".as_slice(),
            b"lmyzmail.cringe.decay.check-interval=0s\n".as_slice(),
            b"lmyzmail.cringe.decay.activity-retention-days=36501\n".as_slice(),
        ] {
            assert!(
                RuntimeConfig::from_properties(Properties::parse(input).unwrap()).is_err(),
                "accepted invalid cringe decay config: {}",
                String::from_utf8_lossy(input),
            );
        }
    }

    #[test]
    fn hashmap_alias_helpers_preserve_new_precedence() {
        let properties = HashMap::from([
            ("botmail.netty.http.port".into(), "8080".into()),
            ("lmyzmail.http.port".into(), "18080".into()),
        ]);
        assert_eq!(
            resolve_alias(
                &properties,
                "lmyzmail.http.port",
                "botmail.netty.http.port",
                "1"
            ),
            "18080"
        );
        assert_eq!(
            resolve_u16(
                &properties,
                "lmyzmail.http.port",
                "botmail.netty.http.port",
                1
            )
            .unwrap(),
            18080
        );
    }

    #[test]
    fn tls_pkcs12_configuration_accepts_legacy_aliases_with_new_precedence() {
        let properties = Properties::parse(
            b"botmail.ssl.use-custom-certificate=false\n\
botmail.ssl.keystore-path=/legacy/server.pfx\n\
lmyzmail.ssl.use-custom-certificate=true\n\
lmyzmail.ssl.keystore-path=/new/server.p12\n\
lmyzmail.ssl.keystore-password=test-password\n",
        )
        .unwrap();
        let config = RuntimeConfig::from_properties(properties).unwrap();
        assert!(config.tls.enabled);
        assert_eq!(
            config.tls.keystore_path,
            Some(PathBuf::from("/new/server.p12"))
        );
        assert_eq!(config.tls.keystore_password, "test-password");

        let missing_path = Properties::parse(b"botmail.ssl.use-custom-certificate=true\n")
            .and_then(RuntimeConfig::from_properties);
        assert!(missing_path.is_err());
    }
}
