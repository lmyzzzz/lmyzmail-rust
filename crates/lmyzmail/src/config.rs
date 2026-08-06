use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    fs::File,
    io::{self, Read},
    net::IpAddr,
    path::{Path, PathBuf},
    str,
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
const MAX_MESSAGE_BYTES: u64 = 1024 * 1024 * 1024;

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
    spamhaus: bool,
    #[serde(default = "default_true")]
    tarpit: bool,
    #[serde(default = "default_true")]
    mta_sts: bool,
    #[serde(default)]
    xdp: bool,
    #[serde(default)]
    fail2ban: bool,
    #[serde(default)]
    report_delivery: bool,
    #[serde(default)]
    show_internet_nl_badge: bool,
}

impl Default for JsonFeatureConfig {
    fn default() -> Self {
        Self {
            public_registration: false,
            smtp_skibidi_mode: default_skibidi_mode(),
            spamhaus: true,
            tarpit: true,
            mta_sts: true,
            xdp: false,
            fail2ban: false,
            report_delivery: false,
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

fn default_max_email_size_bytes() -> u64 {
    15 * 1024 * 1024
}

fn default_max_attachment_size_bytes() -> u64 {
    10 * 1024 * 1024
}

fn default_max_total_attachments_size_bytes() -> u64 {
    15 * 1024 * 1024
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
    let mut properties = Properties::default();
    properties.insert("lmyzmail.profile".to_owned(), value.profile)?;
    properties.insert("lmyzmail.listen.host".to_owned(), value.listen.host)?;
    properties.insert(
        "lmyzmail.http.port".to_owned(),
        value.listen.http.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.port".to_owned(),
        value.listen.smtp.to_string(),
    )?;
    properties.insert(
        "lmyzmail.htcpcp.port".to_owned(),
        value.listen.htcpcp.to_string(),
    )?;
    properties.insert(
        "lmyzmail.minecraft.port".to_owned(),
        value.listen.minecraft.to_string(),
    )?;
    for (index, trap) in value.listen.honeypots.into_iter().enumerate() {
        let prefix = format!("lmyzmail.honeypot.traps[{index}]");
        properties.insert(format!("{prefix}.port"), trap.port.to_string())?;
        properties.insert(format!("{prefix}.protocol"), trap.protocol)?;
        properties.insert(format!("{prefix}.label"), trap.label)?;
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
        "lmyzmail.public-registration-enabled".to_owned(),
        value.features.public_registration.to_string(),
    )?;
    properties.insert(
        "lmyzmail.smtp.skibidi-generator-mode".to_owned(),
        value.features.smtp_skibidi_mode,
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
        "lmyzmail.fail2ban.enabled".to_owned(),
        value.features.fail2ban.to_string(),
    )?;
    properties.insert(
        "lmyzmail.reporting.http-delivery-enabled".to_owned(),
        value.features.report_delivery.to_string(),
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
    pub features: FeatureConfig,
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
}

#[derive(Clone, Debug)]
pub struct ApiKeyConfig {
    pub key: String,
    pub label: String,
    pub read: bool,
    pub write: bool,
}

#[derive(Clone, Debug)]
pub struct FeatureConfig {
    pub public_registration: bool,
    pub smtp_skibidi_mode: String,
    pub spamhaus: bool,
    pub tarpit: bool,
    pub mta_sts: bool,
    pub xdp: bool,
    pub fail2ban: bool,
    pub report_delivery: bool,
    pub show_internet_nl_badge: bool,
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
        let minecraft = preferred_u16(
            &properties,
            &["lmyzmail.minecraft.port"],
            &["botmail.minecraft.port"],
            25565,
        )?;

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
        };
        validate_host(&redis.host, "redis.host")?;

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
            xdp: preferred_bool(
                &properties,
                &["lmyzmail.xdp.enabled"],
                &["botmail.xdp.enabled"],
                false,
            )?,
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
                false,
            )?,
            show_internet_nl_badge: preferred_bool(
                &properties,
                &["lmyzmail.show-internet-nl-badge"],
                &["botmail.show-internet-nl-badge"],
                false,
            )?,
        };

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

        let honeypots = parse_honeypots(&properties)?;
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
            features,
            tls,
            limits,
        })
    }

    pub fn preferred_value(&self, new_key: &str, legacy_key: &str) -> Option<&str> {
        preferred(&self.properties, &[new_key], &[legacy_key])
    }
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

fn parse_honeypots(properties: &Properties) -> Result<Vec<HoneypotConfig>, ConfigError> {
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
        .to_owned();
        let label = preferred(
            properties,
            &[&format!("{new_prefix}label")],
            &[&format!("{old_prefix}label")],
        )
        .unwrap_or("trap")
        .to_owned();
        traps.push(HoneypotConfig {
            port,
            protocol,
            label,
        });
    }
    Ok(traps)
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
    if value.honeypot_initial_delay_ms > MAX_HONEYPOT_DELAY_MS
        || value.honeypot_post_banner_timeout_ms > MAX_HONEYPOT_DELAY_MS
    {
        return Err(ConfigError::Invalid(format!(
            "honeypot deadlines must not exceed {MAX_HONEYPOT_DELAY_MS} ms"
        )));
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
            "features": {"smtp_skibidi_mode": "JAVA"},
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
    }

    #[test]
    fn duplicate_ports_are_rejected() {
        let properties =
            Properties::parse(b"lmyzmail.http.port=8080\nlmyzmail.smtp.port=8080\n").unwrap();
        assert!(RuntimeConfig::from_properties(properties).is_err());
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
