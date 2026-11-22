//! Editable detection parameters and DB override application.
//!
//! Detector thresholds/lists live in the configuration file. The Detectors
//! page can override individual keys in SQLite; overrides are applied on the
//! next daemon start. This module is the single registry of editable keys,
//! their types/defaults and validation, and converts overrides to typed TOML
//! before deserialising a validated `Config`.

use std::collections::BTreeMap;

use crate::config::Config;

#[derive(Debug, Clone, Copy)]
pub enum ParamKind {
    Number {
        min: u64,
        max: u64,
    },
    Bool,
    /// Comma-separated TCP/UDP ports.
    PortList,
    /// Comma-separated free-form items (HTTP paths, units, identifiers).
    TextList,
}

#[derive(Debug, Clone, Copy)]
pub struct ParamSpec {
    pub key: &'static str,
    pub label: &'static str,
    pub kind: ParamKind,
    pub help: &'static str,
}

pub const SPECS: &[ParamSpec] = &[
    // shared packet/HTTP
    ParamSpec {
        key: "detection.window_secs",
        label: "Window (seconds)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "Shared short sliding window for packet detectors.",
    },
    ParamSpec {
        key: "detection.cooldown_secs",
        label: "Cooldown (seconds)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "One event per detector and source per cooldown.",
    },
    ParamSpec {
        key: "detection.max_tracked_sources",
        label: "Max tracked sources",
        kind: ParamKind::Number {
            min: 1024,
            max: 1_000_000,
        },
        help: "Per-engine source table cap; oldest entries are evicted.",
    },
    // packet
    ParamSpec {
        key: "detection.scan_ports",
        label: "Scan ports",
        kind: ParamKind::Number {
            min: 1,
            max: 65_535,
        },
        help: "DET-01 distinct destination ports per window.",
    },
    ParamSpec {
        key: "detection.sweep_hosts",
        label: "Sweep hosts",
        kind: ParamKind::Number {
            min: 1,
            max: 65_535,
        },
        help: "DET-02 distinct local hosts per port.",
    },
    ParamSpec {
        key: "detection.stealth_packets",
        label: "Stealth packets",
        kind: ParamKind::Number {
            min: 1,
            max: 10_000,
        },
        help: "DET-03 malformed flag packets per window.",
    },
    ParamSpec {
        key: "detection.ack_packets",
        label: "ACK ports",
        kind: ParamKind::Number {
            min: 1,
            max: 65_535,
        },
        help: "DET-04 distinct ACK-only destination ports.",
    },
    ParamSpec {
        key: "detection.udp_ports",
        label: "UDP ports",
        kind: ParamKind::Number {
            min: 1,
            max: 65_535,
        },
        help: "DET-05 distinct empty UDP destination ports.",
    },
    ParamSpec {
        key: "detection.icmp_hosts",
        label: "ICMP hosts",
        kind: ParamKind::Number {
            min: 1,
            max: 65_535,
        },
        help: "DET-06 distinct ICMP echo destinations.",
    },
    ParamSpec {
        key: "detection.icmp_echo_per_sec",
        label: "ICMP echo/sec",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-06 echo rate per second.",
    },
    ParamSpec {
        key: "detection.syn_per_sec",
        label: "SYN/sec",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-07 SYN rate per second.",
    },
    ParamSpec {
        key: "detection.syn_unanswered_pct",
        label: "SYN unanswered %",
        kind: ParamKind::Number { min: 0, max: 100 },
        help: "DET-07 minimum unanswered-handshake ratio.",
    },
    ParamSpec {
        key: "detection.conn_rate",
        label: "Connections/window",
        kind: ParamKind::Number {
            min: 0,
            max: 1_000_000,
        },
        help: "DET-08 new connections per window; 0 disables.",
    },
    ParamSpec {
        key: "detection.ssh_conns_per_min",
        label: "SSH conns/min",
        kind: ParamKind::Number {
            min: 0,
            max: 1_000_000,
        },
        help: "DET-10 TCP/22 connections per minute; 0 disables.",
    },
    ParamSpec {
        key: "detection.tarpit_ports",
        label: "Tarpit ports",
        kind: ParamKind::PortList,
        help: "DET-09 ports that should never receive a connection.",
    },
    // HTTP packet
    ParamSpec {
        key: "detection.http_ports",
        label: "HTTP ports",
        kind: ParamKind::PortList,
        help: "Clear-text ports inspected by DET-11…15.",
    },
    ParamSpec {
        key: "detection.http_bad_paths",
        label: "Bad paths",
        kind: ParamKind::TextList,
        help: "DET-12 lower-case substrings; one match alerts.",
    },
    ParamSpec {
        key: "detection.http_login_paths",
        label: "Login paths",
        kind: ParamKind::TextList,
        help: "DET-13 paths whose 401/403 responses count.",
    },
    ParamSpec {
        key: "detection.http_scan_paths",
        label: "Unique paths",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-11 unique paths in the scan window.",
    },
    ParamSpec {
        key: "detection.http_scan_404",
        label: "404/403 count",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-11 404/403 responses in the scan window.",
    },
    ParamSpec {
        key: "detection.http_scan_window_secs",
        label: "Scan window (s)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "DET-11 window.",
    },
    ParamSpec {
        key: "detection.http_auth_failures",
        label: "Auth failures",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-13 401/403 responses on login paths.",
    },
    ParamSpec {
        key: "detection.http_auth_window_secs",
        label: "Auth window (s)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "DET-13 window.",
    },
    ParamSpec {
        key: "detection.http_anomalies",
        label: "Anomalies",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-14 method/request anomalies.",
    },
    ParamSpec {
        key: "detection.http_anomaly_window_secs",
        label: "Anomaly window (s)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "DET-14 window.",
    },
    ParamSpec {
        key: "detection.http_flood_requests",
        label: "Flood requests",
        kind: ParamKind::Number {
            min: 1,
            max: 10_000_000,
        },
        help: "DET-15 requests in the flood window.",
    },
    ParamSpec {
        key: "detection.http_flood_window_secs",
        label: "Flood window (s)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "DET-15 window.",
    },
    // slow scan
    ParamSpec {
        key: "detection.slow_scan_ports",
        label: "Slow-scan ports",
        kind: ParamKind::Number {
            min: 1,
            max: 65_535,
        },
        help: "DET-20 unique ports in the long window.",
    },
    ParamSpec {
        key: "detection.slow_scan_window_secs",
        label: "Slow-scan window (s)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "DET-20 long window.",
    },
    ParamSpec {
        key: "detection.slow_scan_max_per_window",
        label: "Slow-scan short max",
        kind: ParamKind::Number {
            min: 1,
            max: 65_535,
        },
        help: "DET-20 maximum ports in the short window to qualify as slow.",
    },
    ParamSpec {
        key: "detection.slow_scan_cooldown_secs",
        label: "Slow-scan cooldown (s)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "DET-20 cooldown.",
    },
    // honeypot
    ParamSpec {
        key: "detection.honeypot_enabled",
        label: "Enable honeypot",
        kind: ParamKind::Bool,
        help: "DET-26: watch the listed ports for any contact. Disabled by default.",
    },
    ParamSpec {
        key: "detection.honeypot_ports",
        label: "Honeypot ports",
        kind: ParamKind::PortList,
        help: "TCP/UDP ports no real service uses; any contact triggers DET-26.",
    },
    ParamSpec {
        key: "detection.honeypot_hits",
        label: "Contacts before block",
        kind: ParamKind::Number {
            min: 1,
            max: 10_000,
        },
        help: "DET-26 contacts in the detection window before the default rule blocks.",
    },
    // shared log
    ParamSpec {
        key: "logs.detection.window_secs",
        label: "Log window (seconds)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "Shared window for log detectors.",
    },
    ParamSpec {
        key: "logs.detection.cooldown_secs",
        label: "Log cooldown (seconds)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "One event per log detector and source per cooldown.",
    },
    ParamSpec {
        key: "logs.detection.max_tracked_sources",
        label: "Log max sources",
        kind: ParamKind::Number {
            min: 1024,
            max: 1_000_000,
        },
        help: "Log engine source table cap.",
    },
    ParamSpec {
        key: "logs.detection.ssh_failures",
        label: "SSH failures",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-16 failures per window.",
    },
    ParamSpec {
        key: "logs.detection.pam_failures",
        label: "PAM failures",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-21 failures per window.",
    },
    ParamSpec {
        key: "logs.detection.sudo_failures",
        label: "sudo failures",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-22 denials per window.",
    },
    ParamSpec {
        key: "logs.detection.detect_security_changes",
        label: "Detect security changes",
        kind: ParamKind::Bool,
        help: "DET-24 enable/disable.",
    },
    ParamSpec {
        key: "logs.detection.detect_account_changes",
        label: "Detect account changes",
        kind: ParamKind::Bool,
        help: "DET-25 enable/disable.",
    },
    ParamSpec {
        key: "logs.detection.http_scan_paths",
        label: "HTTP log paths",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-23 unique paths in the log scan window.",
    },
    ParamSpec {
        key: "logs.detection.http_scan_404",
        label: "HTTP log 404/403",
        kind: ParamKind::Number {
            min: 1,
            max: 1_000_000,
        },
        help: "DET-23 404/403 responses in the log scan window.",
    },
    ParamSpec {
        key: "logs.detection.http_scan_window_secs",
        label: "HTTP log window (s)",
        kind: ParamKind::Number {
            min: 1,
            max: 86_400,
        },
        help: "DET-23 window.",
    },
];

pub const SHARED_PACKET: &[&str] = &[
    "detection.window_secs",
    "detection.cooldown_secs",
    "detection.max_tracked_sources",
];
pub const SHARED_HTTP: &[&str] = &["detection.http_ports"];
pub const HONEYPOT: &[&str] = &[
    "detection.honeypot_enabled",
    "detection.honeypot_ports",
    "detection.honeypot_hits",
];
pub const SHARED_LOG: &[&str] = &[
    "logs.detection.window_secs",
    "logs.detection.cooldown_secs",
    "logs.detection.max_tracked_sources",
];

pub fn spec(key: &str) -> Option<&'static ParamSpec> {
    SPECS.iter().find(|spec| spec.key == key)
}

pub fn keys_for(id: &str) -> &'static [&'static str] {
    match id {
        "shared-packet" => SHARED_PACKET,
        "shared-http" => SHARED_HTTP,
        "shared-log" => SHARED_LOG,
        "honeypot" => HONEYPOT,
        "DET-01" => &["detection.scan_ports"],
        "DET-02" => &["detection.sweep_hosts"],
        "DET-03" => &["detection.stealth_packets"],
        "DET-04" => &["detection.ack_packets"],
        "DET-05" => &["detection.udp_ports"],
        "DET-06" => &["detection.icmp_hosts", "detection.icmp_echo_per_sec"],
        "DET-07" => &["detection.syn_per_sec", "detection.syn_unanswered_pct"],
        "DET-08" => &["detection.conn_rate"],
        "DET-09" => &["detection.tarpit_ports"],
        "DET-10" => &["detection.ssh_conns_per_min"],
        "DET-11" => &[
            "detection.http_scan_paths",
            "detection.http_scan_404",
            "detection.http_scan_window_secs",
        ],
        "DET-12" => &["detection.http_bad_paths"],
        "DET-13" => &[
            "detection.http_auth_failures",
            "detection.http_auth_window_secs",
            "detection.http_login_paths",
        ],
        "DET-14" => &[
            "detection.http_anomalies",
            "detection.http_anomaly_window_secs",
        ],
        "DET-15" => &[
            "detection.http_flood_requests",
            "detection.http_flood_window_secs",
        ],
        "DET-16" => &["logs.detection.ssh_failures"],
        "DET-17" => &[],
        "DET-20" => &[
            "detection.slow_scan_ports",
            "detection.slow_scan_window_secs",
            "detection.slow_scan_max_per_window",
            "detection.slow_scan_cooldown_secs",
        ],
        "DET-21" => &["logs.detection.pam_failures"],
        "DET-23" => &[
            "logs.detection.http_scan_paths",
            "logs.detection.http_scan_404",
            "logs.detection.http_scan_window_secs",
        ],
        "DET-26" => &["detection.honeypot_ports", "detection.honeypot_hits"],
        _ => &[],
    }
}

pub fn value(cfg: &Config, key: &str) -> String {
    let Ok(value) = toml::Value::try_from(cfg) else {
        return String::new();
    };
    let Some(value) = get_path(&value, key) else {
        return String::new();
    };
    format_value(value)
}

pub fn default_value(key: &str) -> String {
    static DEFAULTS: std::sync::OnceLock<Config> = std::sync::OnceLock::new();
    value(DEFAULTS.get_or_init(Config::defaults), key)
}

fn format_value(value: &toml::Value) -> String {
    match value {
        toml::Value::String(text) => text.clone(),
        toml::Value::Integer(number) => number.to_string(),
        toml::Value::Boolean(flag) => flag.to_string(),
        toml::Value::Array(items) => items
            .iter()
            .map(format_value)
            .collect::<Vec<_>>()
            .join(", "),
        toml::Value::Float(number) => number.to_string(),
        _ => String::new(),
    }
}

fn get_path<'a>(mut value: &'a toml::Value, key: &str) -> Option<&'a toml::Value> {
    for part in key.split('.') {
        value = value.get(part)?;
    }
    Some(value)
}

/// Validate and canonicalise one raw form value.
pub fn normalize(spec: &ParamSpec, raw: &str) -> Result<String, String> {
    match spec.kind {
        ParamKind::Number { min, max } => {
            let number: u64 = raw
                .trim()
                .parse()
                .map_err(|_| format!("{} must be a number", spec.label))?;
            if number < min || number > max {
                return Err(format!("{} must be {min}..={max}", spec.label));
            }
            Ok(number.to_string())
        }
        ParamKind::Bool => match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Ok("true".into()),
            "false" | "no" | "off" | "0" | "" => Ok("false".into()),
            _ => Err(format!("{} must be true or false", spec.label)),
        },
        ParamKind::PortList => {
            let mut ports = Vec::new();
            for item in raw.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                let port: u16 = item
                    .parse()
                    .map_err(|_| format!("{}: {item:?} is not a port", spec.label))?;
                if port == 0 {
                    return Err(format!("{}: ports must be 1-65535", spec.label));
                }
                if !ports.contains(&port) {
                    ports.push(port);
                }
            }
            ports.sort_unstable();
            Ok(ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", "))
        }
        ParamKind::TextList => {
            let mut items = Vec::new();
            for item in raw.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                if item.chars().count() > 256 || item.chars().any(char::is_control) {
                    return Err(format!(
                        "{}: item is too long or contains controls",
                        spec.label
                    ));
                }
                if !items.contains(&item.to_string()) {
                    items.push(item.to_string());
                }
            }
            Ok(items.join(", "))
        }
    }
}

fn parse_toml(spec: &ParamSpec, raw: &str) -> Result<toml::Value, String> {
    Ok(match spec.kind {
        ParamKind::Number { .. } => toml::Value::Integer(
            raw.parse::<i64>()
                .map_err(|_| format!("{} is not a number", spec.label))?,
        ),
        ParamKind::Bool => toml::Value::Boolean(raw == "true"),
        ParamKind::PortList => toml::Value::Array(
            raw.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| {
                    item.parse::<i64>()
                        .map(toml::Value::Integer)
                        .map_err(|_| format!("{}: {item:?} is not a port", spec.label))
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        ParamKind::TextList => toml::Value::Array(
            raw.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|item| toml::Value::String(item.to_string()))
                .collect(),
        ),
    })
}

fn set_path(root: &mut toml::Value, key: &str, value: toml::Value) -> Result<(), String> {
    let parts: Vec<&str> = key.split('.').collect();
    let (last, parents) = parts
        .split_last()
        .ok_or_else(|| "empty parameter key".to_string())?;
    let mut current = root;
    for part in parents {
        let table = current
            .as_table_mut()
            .ok_or_else(|| format!("{key}: parent is not a table"))?;
        current = table
            .entry((*part).to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    }
    let table = current
        .as_table_mut()
        .ok_or_else(|| format!("{key}: parent is not a table"))?;
    table.insert((*last).to_string(), value);
    Ok(())
}

/// Apply stored overrides to a config, then validate the complete result.
pub fn apply_overrides(
    cfg: &mut Config,
    overrides: &BTreeMap<String, String>,
) -> Result<(), String> {
    if overrides.is_empty() {
        return Ok(());
    }
    let mut root = toml::Value::try_from(&*cfg).map_err(|e| e.to_string())?;
    for (key, raw) in overrides {
        let spec = spec(key).ok_or_else(|| format!("unknown detection override {key:?}"))?;
        let normalized = normalize(spec, raw)?;
        set_path(&mut root, key, parse_toml(spec, &normalized)?)?;
    }
    let next: Config = root
        .try_into()
        .map_err(|e: toml::de::Error| e.to_string())?;
    next.validate().map_err(|e| e.to_string())?;
    *cfg = next;
    Ok(())
}

pub fn all_keys() -> Vec<&'static str> {
    SPECS.iter().map(|spec| spec.key).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_parses_values() {
        let spec = self::spec("detection.http_ports").unwrap();
        assert_eq!(normalize(spec, "8080, 80,80").unwrap(), "80, 8080");
        assert_eq!(
            normalize(
                self::spec("detection.http_bad_paths").unwrap(),
                "/.env, wp-login"
            )
            .unwrap(),
            "/.env, wp-login"
        );
        assert!(normalize(spec, "0").is_err());
        assert!(normalize(self::spec("detection.scan_ports").unwrap(), "0").is_err());
    }

    #[test]
    fn honeypot_default_values_render_cleanly() {
        let cfg = Config::defaults();
        assert_eq!(value(&cfg, "detection.honeypot_enabled"), "false");
        assert_eq!(value(&cfg, "detection.honeypot_ports"), "");
        assert_eq!(value(&cfg, "detection.honeypot_hits"), "3");
    }

    #[test]
    fn overrides_apply_to_config() {
        let mut cfg = Config::defaults();
        let mut overrides = BTreeMap::new();
        overrides.insert("detection.scan_ports".into(), "25".into());
        overrides.insert("detection.http_bad_paths".into(), "/.env, /custom".into());
        overrides.insert(
            "logs.detection.detect_account_changes".into(),
            "false".into(),
        );
        overrides.insert("detection.honeypot_enabled".into(), "true".into());
        overrides.insert("detection.honeypot_ports".into(), "2323, 9999".into());
        overrides.insert("detection.honeypot_hits".into(), "5".into());
        apply_overrides(&mut cfg, &overrides).unwrap();
        assert_eq!(cfg.detection.scan_ports, 25);
        assert_eq!(cfg.detection.http_bad_paths, vec!["/.env", "/custom"]);
        assert!(!cfg.logs.detection.detect_account_changes);
        assert!(cfg.detection.honeypot_enabled);
        assert_eq!(cfg.detection.honeypot_ports, vec![2323, 9999]);
        assert_eq!(cfg.detection.honeypot_hits, 5);
        assert_eq!(value(&cfg, "detection.scan_ports"), "25");
        assert_eq!(default_value("detection.scan_ports"), "20");
    }

    #[test]
    fn every_editable_key_has_a_spec_and_default() {
        for key in all_keys() {
            let spec = self::spec(key).expect("spec exists");
            assert!(!spec.label.is_empty(), "{key}");
            if key != "detection.tarpit_ports" && key != "detection.honeypot_ports" {
                assert!(!default_value(key).is_empty(), "{key}");
            }
        }
        for group in ["shared-packet", "shared-http", "shared-log", "honeypot"] {
            for key in keys_for(group) {
                assert!(self::spec(key).is_some(), "{group}: {key}");
            }
        }
        for detector in crate::model::Detector::ALL {
            for key in keys_for(detector.as_str()) {
                assert!(self::spec(key).is_some(), "{}: {key}", detector);
            }
        }
        assert!(keys_for("DET-12").contains(&"detection.http_bad_paths"));
        assert!(keys_for("DET-13").contains(&"detection.http_login_paths"));
    }

    #[test]
    fn invalid_override_is_rejected_and_original_config_kept() {
        let mut cfg = Config::defaults();
        let mut overrides = BTreeMap::new();
        overrides.insert("detection.scan_ports".into(), "not-a-number".into());
        assert!(apply_overrides(&mut cfg, &overrides).is_err());
        assert_eq!(cfg.detection.scan_ports, 20);

        let mut overrides = BTreeMap::new();
        overrides.insert("detection.http_bad_paths".into(), "/new".into());
        apply_overrides(&mut cfg, &overrides).unwrap();
        assert_eq!(cfg.detection.http_bad_paths, vec!["/new"]);
    }
}
