//! Configuration model, parsing, and validation.
//!
//! Parsing is strict: unknown keys are rejected so a typo cannot silently
//! disable a protection (FR-219). A configuration that fails validation is a
//! hard startup error, never a silent fallback to defaults.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Record detections, enforce nothing. Default on a new install (FR-116).
    #[default]
    Observe,
    /// Apply blocks through the enforcement backend.
    Enforce,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Observe => f.write_str("observe"),
            Mode::Enforce => f.write_str("enforce"),
        }
    }
}

/// How long a block lasts, or permanence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockDuration {
    Temporary(i64),
    Permanent,
}

impl BlockDuration {
    pub fn secs(self) -> Option<i64> {
        match self {
            BlockDuration::Temporary(s) => Some(s),
            BlockDuration::Permanent => None,
        }
    }
}

impl FromStr for BlockDuration {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.trim().to_ascii_lowercase();
        if s == "permanent" || s == "forever" || s == "inf" {
            return Ok(BlockDuration::Permanent);
        }
        let (num, unit) = s.split_at(
            s.find(|c: char| !c.is_ascii_digit())
                .ok_or_else(|| format!("duration {s:?} needs a unit (s, m, h, d, w)"))?,
        );
        let n: i64 = num
            .parse()
            .map_err(|_| format!("invalid number in duration {s:?}"))?;
        if n <= 0 {
            return Err(format!("duration {s:?} must be positive"));
        }
        let mult = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3_600,
            "d" => 86_400,
            "w" => 604_800,
            _ => return Err(format!("unknown duration unit {unit:?} in {s:?}")),
        };
        Ok(BlockDuration::Temporary(n * mult))
    }
}

impl std::fmt::Display for BlockDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockDuration::Permanent => f.write_str("permanent"),
            BlockDuration::Temporary(secs) => {
                for (unit, div) in [("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1)] {
                    if secs % div == 0 && *secs >= div {
                        return write!(f, "{}{unit}", secs / div);
                    }
                }
                write!(f, "{secs}s")
            }
        }
    }
}

impl Serialize for BlockDuration {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BlockDuration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        BlockDuration::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub config_version: u32,
    pub mode: Mode,
    #[serde(default)]
    pub general: General,
    #[serde(default)]
    pub capture: Capture,
    #[serde(default)]
    pub enforcement: Enforcement,
    #[serde(default)]
    pub ladder: Ladder,
    #[serde(default)]
    pub detection: Detection,
    #[serde(default)]
    pub logs: Logs,
    #[serde(default)]
    pub geo: Geo,
    #[serde(default)]
    pub alerts: Alerts,
    #[serde(default)]
    pub allowlist: AllowlistCfg,
    #[serde(default)]
    pub retention: Retention,
    #[serde(default)]
    pub web: Web,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct General {
    /// Overrides the default state directory when set.
    pub data_dir: Option<PathBuf>,
    pub log_level: String,
}

impl Default for General {
    fn default() -> Self {
        General {
            data_dir: None,
            log_level: "info".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    /// Interface names, or the single value `auto` to follow the default route.
    pub interfaces: Vec<String>,
    pub snaplen: usize,
    /// Kernel receive buffer; larger survives bursts better.
    pub rcvbuf_bytes: usize,
}

impl Default for Capture {
    fn default() -> Self {
        Capture {
            interfaces: vec!["auto".into()],
            snaplen: 2048,
            rcvbuf_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enforcement {
    pub table: String,
    /// nftables input-hook priority. Lower runs earlier.
    pub priority: i32,
    /// Delete the RustIPS table on `flush`; also used by uninstall docs.
    pub chain_hook: String,
}

impl Default for Enforcement {
    fn default() -> Self {
        Enforcement {
            table: "rustips".into(),
            priority: -10,
            chain_hook: "input".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ladder {
    pub steps: Vec<BlockDuration>,
    pub strike_decay_days: u64,
    #[serde(default)]
    pub unblock_effect: UnblockEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum UnblockEffect {
    /// Manual unblock leaves the strike history untouched.
    #[default]
    Keep,
    /// Manual unblock resets the strike count to zero.
    Reset,
}

impl Default for Ladder {
    fn default() -> Self {
        Ladder {
            steps: vec![
                BlockDuration::Temporary(3_600),
                BlockDuration::Temporary(86_400),
                BlockDuration::Temporary(172_800),
                BlockDuration::Temporary(604_800),
                BlockDuration::Permanent,
            ],
            strike_decay_days: 90,
            unblock_effect: UnblockEffect::Keep,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detection {
    /// Sliding window shared by the packet detectors.
    pub window_secs: u64,
    /// One event per (detector, source) per cooldown (FR-114).
    pub cooldown_secs: u64,
    pub max_tracked_sources: usize,
    pub scan_ports: usize,
    pub sweep_hosts: usize,
    pub stealth_packets: usize,
    pub ack_packets: usize,
    pub udp_ports: usize,
    pub icmp_hosts: usize,
    pub icmp_echo_per_sec: usize,
    pub syn_per_sec: usize,
    /// Percent of SYNs that must remain unanswered to call it a flood.
    pub syn_unanswered_pct: u8,
    /// New TCP connections in `window_secs` before DET-08 fires.
    pub conn_rate: usize,
    /// New SSH connections in 60 s before DET-10 fires.
    pub ssh_conns_per_min: usize,
    /// Ports declared unused. One connection is enough for DET-09.
    #[serde(default)]
    pub tarpit_ports: Vec<u16>,
    /// Clear-text HTTP ports inspected by DET-11…15.
    #[serde(default = "default_http_ports")]
    pub http_ports: Vec<u16>,
    /// Path substrings that trigger DET-12 immediately.
    #[serde(default = "default_http_bad_paths")]
    pub http_bad_paths: Vec<String>,
    /// Path substrings considered login endpoints for DET-13.
    #[serde(default = "default_http_login_paths")]
    pub http_login_paths: Vec<String>,
    #[serde(default = "default_http_scan_404")]
    pub http_scan_404: usize,
    #[serde(default = "default_http_scan_paths")]
    pub http_scan_paths: usize,
    #[serde(default = "default_http_scan_window")]
    pub http_scan_window_secs: u64,
    #[serde(default = "default_http_auth_failures")]
    pub http_auth_failures: usize,
    #[serde(default = "default_http_auth_window")]
    pub http_auth_window_secs: u64,
    #[serde(default = "default_http_anomalies")]
    pub http_anomalies: usize,
    #[serde(default = "default_http_anomaly_window")]
    pub http_anomaly_window_secs: u64,
    #[serde(default = "default_http_flood_requests")]
    pub http_flood_requests: usize,
    #[serde(default = "default_http_flood_window")]
    pub http_flood_window_secs: u64,
    /// DET-20: unique destination ports in the long window.
    #[serde(default = "default_slow_scan_ports")]
    pub slow_scan_ports: usize,
    #[serde(default = "default_slow_scan_window")]
    pub slow_scan_window_secs: u64,
    /// A scan is "slow" when it stays at or below this many ports per short
    /// detection window.
    #[serde(default = "default_slow_scan_max")]
    pub slow_scan_max_per_window: usize,
    #[serde(default = "default_slow_scan_cooldown")]
    pub slow_scan_cooldown_secs: u64,
    /// DET-26: enable the honeypot listener check. Disabled by default.
    #[serde(default)]
    pub honeypot_enabled: bool,
    /// DET-26: TCP/UDP ports that should never receive legitimate traffic.
    #[serde(default)]
    pub honeypot_ports: Vec<u16>,
    /// DET-26: contacts in the shared window before the detector fires.
    #[serde(default = "default_honeypot_hits")]
    pub honeypot_hits: usize,
}

fn default_honeypot_hits() -> usize {
    3
}

fn default_slow_scan_ports() -> usize {
    30
}
fn default_slow_scan_window() -> u64 {
    600
}
fn default_slow_scan_max() -> usize {
    10
}
fn default_slow_scan_cooldown() -> u64 {
    600
}

fn default_http_ports() -> Vec<u16> {
    vec![80, 8080, 8000, 8888]
}

fn default_http_bad_paths() -> Vec<String> {
    [
        "/.env",
        "/.git",
        "wp-login",
        "wp-admin",
        "phpmyadmin",
        "cgi-bin",
        "xmlrpc.php",
        "/actuator",
        "/manager/html",
        "/vendor/phpunit",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_http_login_paths() -> Vec<String> {
    [
        "/login",
        "/signin",
        "/admin",
        "/wp-login",
        "/auth",
        "/user/login",
        "/api/login",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_http_scan_404() -> usize {
    15
}
fn default_http_scan_paths() -> usize {
    20
}
fn default_http_scan_window() -> u64 {
    30
}
fn default_http_auth_failures() -> usize {
    10
}
fn default_http_auth_window() -> u64 {
    60
}
fn default_http_anomalies() -> usize {
    3
}
fn default_http_anomaly_window() -> u64 {
    60
}
fn default_http_flood_requests() -> usize {
    100
}
fn default_http_flood_window() -> u64 {
    10
}

impl Default for Detection {
    fn default() -> Self {
        Detection {
            window_secs: 10,
            cooldown_secs: 60,
            max_tracked_sources: 16_384,
            scan_ports: 20,
            sweep_hosts: 20,
            stealth_packets: 3,
            ack_packets: 10,
            udp_ports: 20,
            icmp_hosts: 20,
            icmp_echo_per_sec: 50,
            syn_per_sec: 200,
            syn_unanswered_pct: 80,
            conn_rate: 120,
            ssh_conns_per_min: 10,
            tarpit_ports: Vec::new(),
            http_ports: default_http_ports(),
            http_bad_paths: default_http_bad_paths(),
            http_login_paths: default_http_login_paths(),
            http_scan_404: default_http_scan_404(),
            http_scan_paths: default_http_scan_paths(),
            http_scan_window_secs: default_http_scan_window(),
            http_auth_failures: default_http_auth_failures(),
            http_auth_window_secs: default_http_auth_window(),
            http_anomalies: default_http_anomalies(),
            http_anomaly_window_secs: default_http_anomaly_window(),
            http_flood_requests: default_http_flood_requests(),
            http_flood_window_secs: default_http_flood_window(),
            slow_scan_ports: default_slow_scan_ports(),
            slow_scan_window_secs: default_slow_scan_window(),
            slow_scan_max_per_window: default_slow_scan_max(),
            slow_scan_cooldown_secs: default_slow_scan_cooldown(),
            honeypot_enabled: false,
            honeypot_ports: Vec::new(),
            honeypot_hits: default_honeypot_hits(),
        }
    }
}

/// GeoIP/ASN enrichment (FR-160…169). Disposition-only: never a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Geo {
    /// Off by default so a fresh install makes no external requests.
    pub enabled: bool,
    /// Automatic update interval. `0` disables automatic checks.
    pub update_hours: u64,
    /// Release base, e.g. `.../download/latest`; filenames are appended.
    pub country_base_url: String,
    pub asn_base_url: String,
    /// Checksum release base, e.g. `.../download/checksum`.
    pub checksum_base_url: String,
}

impl Default for Geo {
    fn default() -> Self {
        Geo {
            enabled: false,
            update_hours: 24,
            country_base_url:
                "https://github.com/sapics/ip-location-db/releases/download/latest/user-country"
                    .into(),
            asn_base_url:
                "https://github.com/sapics/ip-location-db/releases/download/latest/origin-asn"
                    .into(),
            checksum_base_url:
                "https://github.com/sapics/ip-location-db/releases/download/checksum".into(),
        }
    }
}

/// Generic outbound webhook (FR-204/204a). Disabled by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    pub enabled: bool,
    pub url: String,
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub queue_max: usize,
    /// Suppress duplicate detector+source+action alerts inside this window.
    pub rate_limit_secs: u64,
    /// Minimum winning-rule severity to send: info, warning or critical.
    pub min_severity: String,
    /// Delivered/failed queue rows are pruned after this many days.
    pub retention_days: u64,
}

impl Default for Alerts {
    fn default() -> Self {
        Alerts {
            enabled: false,
            url: String::new(),
            timeout_secs: 5,
            max_retries: 5,
            queue_max: 1000,
            rate_limit_secs: 60,
            min_severity: "warning".into(),
            retention_days: 7,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AllowlistCfg {
    /// Static entries, in addition to the always-on loopback/RFC1918 set.
    pub entries: Vec<String>,
}

/// Host-log ingestion (journald first; file sources in a later slice).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Logs {
    /// Ingest the system journal. Failure is isolated from packet capture.
    pub enabled: bool,
    /// First start: how far back to read. Later starts resume by cursor.
    pub backfill_secs: u64,
    /// Messages are truncated to this many bytes before storage.
    pub max_message_bytes: usize,
    /// Global and per-parser ingestion caps (FR-307).
    pub max_events_per_sec: u32,
    pub max_events_per_parser_per_sec: u32,
    /// Raw-event retention: days or bytes, whichever is reached first.
    pub raw_retention_days: u64,
    pub raw_max_bytes: u64,
    /// Store the bounded raw message. Detection provenance is stored either way.
    pub store_raw: bool,
    /// Extra literal substrings to redact from stored messages.
    #[serde(default)]
    pub redact: Vec<String>,
    #[serde(default)]
    pub journal: JournalCfg,
    #[serde(default)]
    pub detection: LogDetection,
}

impl Default for Logs {
    fn default() -> Self {
        Logs {
            enabled: true,
            backfill_secs: 900,
            max_message_bytes: 1024,
            max_events_per_sec: 10_000,
            max_events_per_parser_per_sec: 2_000,
            raw_retention_days: 7,
            raw_max_bytes: 128 * 1024 * 1024,
            store_raw: true,
            redact: Vec::new(),
            journal: JournalCfg::default(),
            detection: LogDetection::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalCfg {
    /// Empty = all units. Non-empty = only these units.
    #[serde(default)]
    pub include_units: Vec<String>,
    #[serde(default)]
    pub exclude_units: Vec<String>,
    /// Empty = all identifiers. Non-empty = only these identifiers.
    #[serde(default)]
    pub include_identifiers: Vec<String>,
    #[serde(default)]
    pub exclude_identifiers: Vec<String>,
}

impl Default for JournalCfg {
    fn default() -> Self {
        JournalCfg {
            include_units: Vec::new(),
            // DET-24 still sees systemd's message about this unit; only the
            // daemon's own identifier is excluded to prevent a feedback loop.
            exclude_units: Vec::new(),
            include_identifiers: Vec::new(),
            exclude_identifiers: vec!["rustips".into()],
        }
    }
}

impl JournalCfg {
    pub fn allows(&self, unit: Option<&str>, identifier: Option<&str>) -> bool {
        let matches = |list: &[String], value: Option<&str>| {
            let Some(value) = value else { return false };
            list.iter().any(|item| item.eq_ignore_ascii_case(value))
        };
        if !self.include_units.is_empty() && !matches(&self.include_units, unit) {
            return false;
        }
        if !self.include_identifiers.is_empty() && !matches(&self.include_identifiers, identifier) {
            return false;
        }
        if matches(&self.exclude_units, unit) || matches(&self.exclude_identifiers, identifier) {
            return false;
        }
        true
    }
}

/// Thresholds for the log detectors. Window defaults to the DET-16/21/22
/// ten-minute window.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogDetection {
    pub window_secs: u64,
    pub cooldown_secs: u64,
    pub ssh_failures: u32,
    pub pam_failures: u32,
    pub sudo_failures: u32,
    pub max_tracked_sources: usize,
    pub detect_security_changes: bool,
    pub detect_account_changes: bool,
    /// DET-23: HTTP access-log path/404 scan thresholds.
    #[serde(default = "default_log_http_paths")]
    pub http_scan_paths: u32,
    #[serde(default = "default_log_http_404")]
    pub http_scan_404: u32,
    #[serde(default = "default_log_http_window")]
    pub http_scan_window_secs: u64,
}

fn default_log_http_paths() -> u32 {
    20
}
fn default_log_http_404() -> u32 {
    15
}
fn default_log_http_window() -> u64 {
    30
}

impl Default for LogDetection {
    fn default() -> Self {
        LogDetection {
            window_secs: 600,
            cooldown_secs: 300,
            ssh_failures: 5,
            pam_failures: 5,
            sudo_failures: 3,
            max_tracked_sources: 16_384,
            detect_security_changes: true,
            detect_account_changes: true,
            http_scan_paths: default_log_http_paths(),
            http_scan_404: default_log_http_404(),
            http_scan_window_secs: default_log_http_window(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    pub detections_days: u64,
    pub blocks_days: u64,
    #[serde(default = "default_audit_days")]
    pub audit_days: u64,
}

fn default_audit_days() -> u64 {
    365
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            detections_days: 30,
            blocks_days: 365,
            audit_days: default_audit_days(),
        }
    }
}

/// Embedded web UI and PAM authentication (FR-180…190, FR-182).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web {
    pub enabled: bool,
    /// Loopback by default. Any other address is an explicit, confirmed change.
    pub bind: String,
    pub port: u16,
    /// PAM service name under `/etc/pam.d/`.
    pub pam_service: String,
    /// Group membership is the only authorisation grant (Q13).
    pub admin_group: String,
    pub session_idle_mins: u64,
    pub session_absolute_mins: u64,
    /// How often an existing session's account is revalidated.
    pub revalidate_mins: u64,
}

impl Default for Web {
    fn default() -> Self {
        Web {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 10707,
            pam_service: "rustips".into(),
            admin_group: "rustips-admin".into(),
            session_idle_mins: 30,
            session_absolute_mins: 720,
            revalidate_mins: 5,
        }
    }
}

impl Config {
    /// The built-in defaults, used for reset-to-default in the Detectors UI.
    pub fn defaults() -> Config {
        Config::parse(Path::new("default"), DEFAULT_CONFIG_TOML)
            .expect("the built-in default configuration is valid")
    }

    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::ConfigMissing {
                path: path.to_path_buf(),
            },
            _ => Error::Io(e),
        })?;
        Config::parse(path, &text)
    }

    pub fn parse(path: &Path, text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text).map_err(|e| {
            let line = e
                .span()
                .map(|span| text[..span.start.min(text.len())].lines().count().max(1))
                .unwrap_or(1);
            Error::ConfigInvalid {
                path: path.to_path_buf(),
                line,
                message: e.message().to_string(),
            }
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.config_version != CONFIG_VERSION {
            return Err(Error::Config(format!(
                "config_version {} is not supported (expected {CONFIG_VERSION})",
                self.config_version
            )));
        }
        if self.capture.interfaces.is_empty() {
            return Err(Error::Config("capture.interfaces must not be empty".into()));
        }
        if self.capture.snaplen < 64 {
            return Err(Error::Config("capture.snaplen must be >= 64".into()));
        }
        if self.ladder.steps.is_empty() {
            return Err(Error::Config("ladder.steps must not be empty".into()));
        }
        let d = &self.detection;
        if d.window_secs == 0 || d.cooldown_secs == 0 {
            return Err(Error::Config(
                "detection.window_secs and detection.cooldown_secs must be > 0".into(),
            ));
        }
        if d.max_tracked_sources < 1024 {
            return Err(Error::Config(
                "detection.max_tracked_sources must be >= 1024".into(),
            ));
        }
        if d.syn_unanswered_pct > 100 {
            return Err(Error::Config(
                "detection.syn_unanswered_pct must be 0..=100".into(),
            ));
        }
        if d.http_ports.contains(&0) {
            return Err(Error::Config(
                "detection.http_ports must be 1..=65535".into(),
            ));
        }
        if d.honeypot_ports.contains(&0) {
            return Err(Error::Config(
                "detection.honeypot_ports must be 1..=65535".into(),
            ));
        }
        if d.honeypot_enabled && d.honeypot_ports.is_empty() {
            return Err(Error::Config(
                "detection.honeypot_enabled requires at least one honeypot port".into(),
            ));
        }
        if d.honeypot_hits == 0 {
            return Err(Error::Config(
                "detection.honeypot_hits must be at least 1".into(),
            ));
        }
        for (name, value) in [
            ("detection.http_scan_404", d.http_scan_404),
            ("detection.http_scan_paths", d.http_scan_paths),
            ("detection.http_auth_failures", d.http_auth_failures),
            ("detection.http_anomalies", d.http_anomalies),
            ("detection.http_flood_requests", d.http_flood_requests),
        ] {
            if value == 0 {
                return Err(Error::Config(format!("{name} must be > 0")));
            }
        }
        for (name, value) in [
            ("detection.http_scan_window_secs", d.http_scan_window_secs),
            ("detection.http_auth_window_secs", d.http_auth_window_secs),
            (
                "detection.http_anomaly_window_secs",
                d.http_anomaly_window_secs,
            ),
            ("detection.http_flood_window_secs", d.http_flood_window_secs),
        ] {
            if value == 0 {
                return Err(Error::Config(format!("{name} must be > 0")));
            }
        }
        for (name, value) in [
            ("geo.country_base_url", &self.geo.country_base_url),
            ("geo.asn_base_url", &self.geo.asn_base_url),
            ("geo.checksum_base_url", &self.geo.checksum_base_url),
        ] {
            if value.is_empty()
                || value.chars().any(|c| c.is_whitespace() || c.is_control())
                || !(value.starts_with("https://") || value.starts_with("http://"))
            {
                return Err(Error::Config(format!(
                    "{name} must be an http(s) URL without whitespace"
                )));
            }
        }
        if self.geo.enabled && self.geo.update_hours > 24 * 30 {
            return Err(Error::Config(
                "geo.update_hours must be 0 or at most 720".into(),
            ));
        }
        if self.logs.detection.http_scan_paths == 0
            || self.logs.detection.http_scan_404 == 0
            || self.logs.detection.http_scan_window_secs == 0
        {
            return Err(Error::Config(
                "logs.detection.http_scan_* values must be > 0".into(),
            ));
        }
        let alerts = &self.alerts;
        if alerts.enabled {
            if alerts.url.is_empty()
                || alerts
                    .url
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
                || !(alerts.url.starts_with("https://") || alerts.url.starts_with("http://"))
            {
                return Err(Error::Config(
                    "alerts.url must be an http(s) URL without whitespace".into(),
                ));
            }
            if alerts.timeout_secs == 0 || alerts.timeout_secs > 60 {
                return Err(Error::Config("alerts.timeout_secs must be 1..=60".into()));
            }
            if alerts.max_retries > 20 {
                return Err(Error::Config("alerts.max_retries must be 0..=20".into()));
            }
            if alerts.queue_max == 0 {
                return Err(Error::Config("alerts.queue_max must be > 0".into()));
            }
            if alerts.rate_limit_secs == 0 {
                return Err(Error::Config("alerts.rate_limit_secs must be > 0".into()));
            }
            match alerts.min_severity.as_str() {
                "info" | "warning" | "critical" => {}
                _ => {
                    return Err(Error::Config(
                        "alerts.min_severity must be info, warning or critical".into(),
                    ));
                }
            }
        }
        for entry in &self.allowlist.entries {
            crate::net::Cidr::parse(entry)
                .map_err(|e| Error::Config(format!("allowlist entry {entry:?}: {e}")))?;
        }
        if !self
            .enforcement
            .table
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(Error::Config(
                "enforcement.table must be alphanumeric/underscore".into(),
            ));
        }
        self.web.bind.parse::<std::net::IpAddr>().map_err(|_| {
            Error::Config(format!("web.bind {:?} is not an IP address", self.web.bind))
        })?;
        if self.web.port == 0 {
            return Err(Error::Config("web.port must be 1..=65535".into()));
        }
        for (name, value) in [
            ("web.pam_service", &self.web.pam_service),
            ("web.admin_group", &self.web.admin_group),
        ] {
            if value.is_empty()
                || !value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(Error::Config(format!("{name} is not a valid name")));
            }
        }
        if self.web.session_idle_mins == 0 || self.web.session_absolute_mins == 0 {
            return Err(Error::Config(
                "web.session_idle_mins and web.session_absolute_mins must be > 0".into(),
            ));
        }
        let logs = &self.logs;
        if !(64..=65_536).contains(&logs.max_message_bytes) {
            return Err(Error::Config(
                "logs.max_message_bytes must be 64..=65536".into(),
            ));
        }
        if logs.backfill_secs > 604_800 {
            return Err(Error::Config(
                "logs.backfill_secs must be 0..=604800 (7 days)".into(),
            ));
        }
        if logs.max_events_per_sec == 0 || logs.max_events_per_parser_per_sec == 0 {
            return Err(Error::Config(
                "logs.max_events_per_sec and logs.max_events_per_parser_per_sec must be > 0".into(),
            ));
        }
        if logs.raw_retention_days == 0 || logs.raw_max_bytes == 0 {
            return Err(Error::Config(
                "logs.raw_retention_days and logs.raw_max_bytes must be > 0".into(),
            ));
        }
        let ld = &logs.detection;
        if ld.window_secs == 0 || ld.cooldown_secs == 0 {
            return Err(Error::Config(
                "logs.detection.window_secs and logs.detection.cooldown_secs must be > 0".into(),
            ));
        }
        if ld.ssh_failures == 0 || ld.pam_failures == 0 || ld.sudo_failures == 0 {
            return Err(Error::Config(
                "logs.detection thresholds must be > 0".into(),
            ));
        }
        if ld.max_tracked_sources < 1024 {
            return Err(Error::Config(
                "logs.detection.max_tracked_sources must be >= 1024".into(),
            ));
        }
        for pattern in &logs.redact {
            if pattern.is_empty() {
                return Err(Error::Config(
                    "logs.redact entries must not be empty".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn ladder_step(&self, strike: u32) -> BlockDuration {
        let idx = (strike.saturating_sub(1) as usize).min(self.ladder.steps.len() - 1);
        self.ladder.steps[idx]
    }

    pub fn cooldown_secs(&self) -> u64 {
        self.detection.cooldown_secs
    }
}

/// The file written by `rustips setup`. Kept as a literal so it can carry
/// comments; a test asserts it parses and validates.
pub const DEFAULT_CONFIG_TOML: &str = r#"# RustIPS configuration.
# Written by `rustips setup`. Validated strictly: unknown keys are errors.
config_version = 1

# observe = record detections, enforce nothing (safe default).
# enforce = apply blocks through nftables.
mode = "observe"

[general]
log_level = "info"

[capture]
# "auto" follows the interface holding the default route.
interfaces = ["auto"]
snaplen = 2048
rcvbuf_bytes = 8388608

[enforcement]
table = "rustips"
priority = -10
chain_hook = "input"

[ladder]
# Strike 1..5. After the last step, repeat the last step.
steps = ["1h", "24h", "48h", "7d", "permanent"]
strike_decay_days = 90
# keep = a manual unblock does not clear strikes.
unblock_effect = "keep"

[detection]
window_secs = 10
cooldown_secs = 60
max_tracked_sources = 16384
scan_ports = 20
sweep_hosts = 20
stealth_packets = 3
ack_packets = 10
udp_ports = 20
icmp_hosts = 20
icmp_echo_per_sec = 50
syn_per_sec = 200
syn_unanswered_pct = 80
# DET-08: new TCP connections per source in window_secs (0 disables).
conn_rate = 120
# DET-10: new SSH connections per source per minute (0 disables).
ssh_conns_per_min = 10
# DET-09: ports that should never receive a connection, e.g. [23, 2323].
tarpit_ports = []
# DET-11…15: clear-text HTTP ports inspected by the packet HTTP detectors.
http_ports = [80, 8080, 8000, 8888]
http_bad_paths = ["/.env", "/.git", "wp-login", "wp-admin", "phpmyadmin", "cgi-bin", "xmlrpc.php", "/actuator", "/manager/html", "/vendor/phpunit"]
http_login_paths = ["/login", "/signin", "/admin", "/wp-login", "/auth", "/user/login", "/api/login"]
http_scan_404 = 15
http_scan_paths = 20
http_scan_window_secs = 30
http_auth_failures = 10
http_auth_window_secs = 60
http_anomalies = 3
http_anomaly_window_secs = 60
http_flood_requests = 100
http_flood_window_secs = 10
# DET-20: long-window slow scan. A source touching this many unique ports in
# the long window while staying quiet in the short window is a slow scan.
slow_scan_ports = 30
slow_scan_window_secs = 600
slow_scan_max_per_window = 10
slow_scan_cooldown_secs = 600
# DET-26: honeypot. Disabled by default. List TCP/UDP ports that no real
# service uses; any contact from another host triggers an alert-only detection.
honeypot_enabled = false
honeypot_ports = []
# Contacts in the shared detection window before DET-26 fires.
honeypot_hits = 3

[logs]
# Host-log ingestion is on by default (FR-300). If journal access fails,
# packet capture and enforcement keep running; the Logs view reports degraded.
enabled = true
# First start only: how far back to backfill. Later starts resume by cursor.
backfill_secs = 900
max_message_bytes = 1024
max_events_per_sec = 10000
max_events_per_parser_per_sec = 2000
# Raw events are kept for 7 days or 128 MB, whichever is reached first.
raw_retention_days = 7
raw_max_bytes = 134217728
store_raw = true
# Literal substrings to redact from stored messages, e.g. ["token=", "password="].
redact = []

[logs.journal]
# Empty include lists mean "all units" / "all identifiers".
include_units = []
exclude_units = []
include_identifiers = []
# RustIPS's own messages are excluded to prevent an ingestion feedback loop.
exclude_identifiers = ["rustips"]

[logs.detection]
window_secs = 600
cooldown_secs = 300
ssh_failures = 5
pam_failures = 5
sudo_failures = 3
max_tracked_sources = 16384
detect_security_changes = true
detect_account_changes = true
# DET-23: HTTP access-log path scan / 404 burst.
http_scan_paths = 20
http_scan_404 = 15
http_scan_window_secs = 30

[geo]
# Disposition-only GeoIP/ASN enrichment. Off by default: enabling it makes
# external requests to the configured release endpoints.
enabled = false
update_hours = 24
country_base_url = "https://github.com/sapics/ip-location-db/releases/download/latest/user-country"
asn_base_url = "https://github.com/sapics/ip-location-db/releases/download/latest/origin-asn"
checksum_base_url = "https://github.com/sapics/ip-location-db/releases/download/checksum"

[alerts]
# Generic outbound webhook. Disabled by default; JSON POST only.
enabled = false
url = ""
timeout_secs = 5
max_retries = 5
queue_max = 1000
rate_limit_secs = 60
min_severity = "warning"
retention_days = 7

[web]
# The UI binds loopback-only by default. Changing this requires confirmation
# in Settings and a restart, and shows a persistent warning banner.
enabled = true
bind = "127.0.0.1"
port = 10707
pam_service = "rustips"
admin_group = "rustips-admin"
session_idle_mins = 30
session_absolute_mins = 720
revalidate_mins = 5

[allowlist]
# The always-on set (loopback, RFC1918, link-local, host addresses) is
# implicit. Add extra static networks here if you need them before first run.
entries = []

[retention]
detections_days = 30
blocks_days = 365
audit_days = 365
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_file_parses_and_validates() {
        let cfg = Config::parse(Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
        assert_eq!(cfg.mode, Mode::Observe);
        assert_eq!(cfg.ladder.steps.len(), 5);
    }

    #[test]
    fn unknown_key_is_rejected() {
        let text = DEFAULT_CONFIG_TOML.replace("snaplen = 2048", "snaplen = 2048\nnope = 1");
        let err = Config::parse(Path::new("test.toml"), &text).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn duration_parsing() {
        assert_eq!("1h".parse::<BlockDuration>().unwrap().secs(), Some(3600));
        assert_eq!("7d".parse::<BlockDuration>().unwrap().secs(), Some(604_800));
        assert!(
            "permanent"
                .parse::<BlockDuration>()
                .unwrap()
                .secs()
                .is_none()
        );
        assert!("10x".parse::<BlockDuration>().is_err());
        assert!("5".parse::<BlockDuration>().is_err());
    }

    #[test]
    fn bad_ladder_entry_reports_line() {
        let text = DEFAULT_CONFIG_TOML.replace(r#""7d""#, r#""7x""#);
        let err = Config::parse(Path::new("test.toml"), &text).unwrap_err();
        assert!(matches!(err, Error::ConfigInvalid { .. }), "{err}");
    }

    #[test]
    fn web_section_defaults_loopback() {
        let cfg = Config::parse(Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
        assert!(cfg.web.enabled);
        assert_eq!(cfg.web.bind, "127.0.0.1");
        assert_eq!(cfg.web.port, 10707);
        assert_eq!(cfg.web.admin_group, "rustips-admin");
    }

    #[test]
    fn older_config_without_web_section_still_parses() {
        let start = DEFAULT_CONFIG_TOML.find("[web]").unwrap();
        let end = DEFAULT_CONFIG_TOML.find("[allowlist]").unwrap();
        let text = format!(
            "{}{}",
            &DEFAULT_CONFIG_TOML[..start],
            &DEFAULT_CONFIG_TOML[end..]
        );
        let cfg = Config::parse(Path::new("test.toml"), &text).unwrap();
        assert_eq!(cfg.web.bind, "127.0.0.1");
    }

    #[test]
    fn web_bind_must_be_an_ip() {
        let text = DEFAULT_CONFIG_TOML.replace(r#"bind = "127.0.0.1""#, r#"bind = "localhost""#);
        let err = Config::parse(Path::new("test.toml"), &text).unwrap_err();
        assert!(err.to_string().contains("web.bind"), "{err}");
    }

    #[test]
    fn logs_defaults_and_filters() {
        let cfg = Config::parse(Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
        assert!(cfg.logs.enabled);
        assert_eq!(cfg.logs.backfill_secs, 900);
        assert_eq!(cfg.logs.detection.ssh_failures, 5);
        // The daemon's own identifier is excluded, systemd's messages are not.
        assert!(
            !cfg.logs
                .journal
                .allows(Some("rustips.service"), Some("rustips"))
        );
        assert!(
            cfg.logs
                .journal
                .allows(Some("rustips.service"), Some("systemd"))
        );
        assert!(cfg.logs.journal.allows(None, Some("sshd")));
    }

    #[test]
    fn logs_validation_rejects_zero_caps() {
        let text =
            DEFAULT_CONFIG_TOML.replace("max_events_per_sec = 10000", "max_events_per_sec = 0");
        let err = Config::parse(Path::new("test.toml"), &text).unwrap_err();
        assert!(err.to_string().contains("max_events_per_sec"), "{err}");
    }
}
