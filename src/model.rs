//! Core domain types shared by detectors, the disposition engine, storage,
//! and the CLI.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Packet detectors implemented through 0.2.x (DET-01…10). The identifier is
/// stored on every detection and every block so evidence stays attributable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectorCategory {
    Packet,
    Http,
    Log,
}

impl DetectorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            DetectorCategory::Packet => "packet",
            DetectorCategory::Http => "http",
            DetectorCategory::Log => "log",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Detector {
    #[serde(rename = "DET-01")]
    VerticalScan,
    #[serde(rename = "DET-02")]
    HorizontalScan,
    #[serde(rename = "DET-03")]
    StealthScan,
    #[serde(rename = "DET-04")]
    AckScan,
    #[serde(rename = "DET-05")]
    UdpScan,
    #[serde(rename = "DET-06")]
    IcmpSweep,
    #[serde(rename = "DET-07")]
    SynFlood,
    #[serde(rename = "DET-08")]
    ConnectionRate,
    #[serde(rename = "DET-09")]
    TarpitPort,
    #[serde(rename = "DET-10")]
    SshBruteForce,
    #[serde(rename = "DET-11")]
    HttpPathScan,
    #[serde(rename = "DET-12")]
    HttpBadPath,
    #[serde(rename = "DET-13")]
    HttpAuthBrute,
    #[serde(rename = "DET-14")]
    HttpAnomaly,
    #[serde(rename = "DET-15")]
    HttpFlood,
    #[serde(rename = "DET-16")]
    SshAuthFailures,
    #[serde(rename = "DET-17")]
    SshSuccessAfterFailures,
    #[serde(rename = "DET-20")]
    SlowScan,
    #[serde(rename = "DET-21")]
    PamFailureBurst,
    #[serde(rename = "DET-22")]
    SudoDenial,
    #[serde(rename = "DET-23")]
    HttpLogScan,
    #[serde(rename = "DET-24")]
    SystemSecurityChange,
    #[serde(rename = "DET-25")]
    AccountModification,
    #[serde(rename = "DET-26")]
    Honeypot,
}

impl Detector {
    pub fn as_str(self) -> &'static str {
        match self {
            Detector::VerticalScan => "DET-01",
            Detector::HorizontalScan => "DET-02",
            Detector::StealthScan => "DET-03",
            Detector::AckScan => "DET-04",
            Detector::UdpScan => "DET-05",
            Detector::IcmpSweep => "DET-06",
            Detector::SynFlood => "DET-07",
            Detector::ConnectionRate => "DET-08",
            Detector::TarpitPort => "DET-09",
            Detector::SshBruteForce => "DET-10",
            Detector::HttpPathScan => "DET-11",
            Detector::HttpBadPath => "DET-12",
            Detector::HttpAuthBrute => "DET-13",
            Detector::HttpAnomaly => "DET-14",
            Detector::HttpFlood => "DET-15",
            Detector::SshAuthFailures => "DET-16",
            Detector::SshSuccessAfterFailures => "DET-17",
            Detector::SlowScan => "DET-20",
            Detector::PamFailureBurst => "DET-21",
            Detector::SudoDenial => "DET-22",
            Detector::HttpLogScan => "DET-23",
            Detector::SystemSecurityChange => "DET-24",
            Detector::AccountModification => "DET-25",
            Detector::Honeypot => "DET-26",
        }
    }

    /// Parse a detector ID, including retired internal detectors that may
    /// still appear in historical detections and stored rules. Retired IDs are
    /// not part of [`Detector::ALL`] and are never emitted.
    pub fn from_id(id: &str) -> Option<Detector> {
        if let Some(detector) = Detector::ALL
            .iter()
            .copied()
            .find(|detector| detector.as_str().eq_ignore_ascii_case(id.trim()))
        {
            return Some(detector);
        }
        match id.trim().to_ascii_uppercase().as_str() {
            "DET-22" => Some(Detector::SudoDenial),
            "DET-24" => Some(Detector::SystemSecurityChange),
            "DET-25" => Some(Detector::AccountModification),
            _ => None,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Detector::VerticalScan => "TCP SYN vertical port scan",
            Detector::HorizontalScan => "TCP SYN horizontal scan / host sweep",
            Detector::StealthScan => "TCP stealth scan (NULL/FIN/XMAS)",
            Detector::AckScan => "TCP ACK scan / unsolicited ACK",
            Detector::UdpScan => "UDP port scan",
            Detector::IcmpSweep => "ICMP host sweep or ping flood",
            Detector::SynFlood => "SYN flood / half-open exhaustion",
            Detector::ConnectionRate => "Connection-rate abuse",
            Detector::TarpitPort => "Connection to an unused (tarpit) port",
            Detector::SshBruteForce => "SSH connection-rate brute-force proxy",
            Detector::HttpPathScan => "HTTP path scan / 404 burst",
            Detector::HttpBadPath => "HTTP known-bad path probe",
            Detector::HttpAuthBrute => "HTTP authentication brute force",
            Detector::HttpAnomaly => "HTTP method or request-line anomaly",
            Detector::HttpFlood => "HTTP request flood / scraper burst",
            Detector::SshAuthFailures => "SSH authentication failures",
            Detector::SshSuccessAfterFailures => "SSH login after authentication failures",
            Detector::SlowScan => "Slow / low-and-slow port scan",
            Detector::PamFailureBurst => "PAM/system authentication failure burst",
            Detector::SudoDenial => "sudo denial or repeated wrong password",
            Detector::HttpLogScan => "HTTP access-log path scan / 404 burst",
            Detector::SystemSecurityChange => "Security-relevant system change",
            Detector::AccountModification => "Account or privilege modification",
            Detector::Honeypot => "Honeypot port contact",
        }
    }

    pub fn category(self) -> DetectorCategory {
        match self {
            Detector::HttpPathScan
            | Detector::HttpBadPath
            | Detector::HttpAuthBrute
            | Detector::HttpAnomaly
            | Detector::HttpFlood => DetectorCategory::Http,
            Detector::SshAuthFailures
            | Detector::SshSuccessAfterFailures
            | Detector::PamFailureBurst
            | Detector::SudoDenial
            | Detector::HttpLogScan
            | Detector::SystemSecurityChange
            | Detector::AccountModification => DetectorCategory::Log,
            _ => DetectorCategory::Packet,
        }
    }

    /// Human-readable description of what the detector looks for. Thresholds
    /// and lists are shown separately from the live configuration.
    pub fn description(self) -> &'static str {
        match self {
            Detector::VerticalScan => {
                "Counts distinct destination TCP ports from one source in the shared detection window; a SYN scan fires at scan_ports (default 20)."
            }
            Detector::HorizontalScan => {
                "Counts distinct local destination hosts for one destination port; a sweep fires at sweep_hosts (default 20)."
            }
            Detector::StealthScan => {
                "Counts NULL, FIN-only, XMAS and invalid SYN/terminator flag combinations; fires at stealth_packets (default 3)."
            }
            Detector::AckScan => {
                "Counts distinct destination ports receiving ACK-only empty packets; fires at ack_packets (default 10)."
            }
            Detector::UdpScan => {
                "Counts empty UDP datagrams to distinct destination ports; fires at udp_ports (default 20)."
            }
            Detector::IcmpSweep => {
                "Counts ICMP echo destinations or echo rate; fires at icmp_hosts (default 20) or icmp_echo_per_sec (default 50)."
            }
            Detector::SynFlood => {
                "Measures SYN rate and the unanswered-handshake ratio; fires at syn_per_sec (default 200) and syn_unanswered_pct (default 80%)."
            }
            Detector::ConnectionRate => {
                "Counts new TCP connections per source in window_secs; fires at conn_rate (default 120)."
            }
            Detector::TarpitPort => {
                "Fires on one SYN to a port listed in tarpit_ports. The list is empty (detector disabled) by default."
            }
            Detector::SshBruteForce => {
                "Counts TCP/22 connections per source per minute; fires at ssh_conns_per_min (default 10). This is a network-side proxy for SSH brute force."
            }
            Detector::HttpPathScan => {
                "HTTP path scan: 20 unique paths or 15 responses with 404/403 in http_scan_window_secs (default 30) per source."
            }
            Detector::HttpBadPath => {
                "Fires on one HTTP request whose path contains a substring from http_bad_paths (for example .env, wp-login, phpmyadmin, cgi-bin, .git)."
            }
            Detector::HttpAuthBrute => {
                "HTTP login brute force: 10 responses with 401/403 on a path containing one of http_login_paths in http_auth_window_secs (default 60)."
            }
            Detector::HttpAnomaly => {
                "HTTP method/request anomaly: TRACE or unknown methods, malformed request line, missing Host on HTTP/1.1, suspicious Host or path traversal; fires at 3 anomalies in 60s."
            }
            Detector::HttpFlood => {
                "HTTP request flood: 100 requests in http_flood_window_secs (default 10) per source on http_ports."
            }
            Detector::SshAuthFailures => {
                "SSH authentication failures: 5 failures in 10 minutes from one source. The two lines OpenSSH writes for one attempt are counted once."
            }
            Detector::SshSuccessAfterFailures => {
                "SSH login success after one or more failures from the same source. Alert only; it never auto-blocks."
            }
            Detector::SlowScan => {
                "Slow scan: 30 unique destination ports in 10 minutes while staying at or below 10 ports in the short window. Alert only by default."
            }
            Detector::PamFailureBurst => {
                "PAM/system authentication failure burst for any service except sshd: 5 failures in 10 minutes from one source."
            }
            Detector::SudoDenial => {
                "sudo denial or repeated wrong password: 3 events in 10 minutes for one user and source. Uses the ladder when a source is known."
            }
            Detector::HttpLogScan => {
                "HTTP access-log scan: 20 unique paths or 15 responses with 404/403 in 30s from common/combined access lines that reach the journal."
            }
            Detector::SystemSecurityChange => {
                "Security-relevant system change: nftables ruleset change, RustIPS service stopped, or audit/journald disabled. Alert only."
            }
            Detector::AccountModification => {
                "Account or privilege modification: useradd, usermod, userdel, groupadd, sudoers change or a new authorized_keys entry. Alert only."
            }
            Detector::Honeypot => {
                "Honeypot port contact: a TCP SYN or UDP datagram from another host to any port listed in detection.honeypot_ports. Three contacts in the detection window trigger DET-26; the shipped disposition rule blocks after that threshold. The honeypot is disabled by default."
            }
        }
    }

    /// Detections that must never auto-block. They are recorded and audited so
    /// an operator can act, but the source is left alone (DET-17/20).
    pub fn is_alert_only(self) -> bool {
        matches!(
            self,
            Detector::SshSuccessAfterFailures
                | Detector::SlowScan
                | Detector::SystemSecurityChange
                | Detector::AccountModification
        )
    }

    /// Detectors fed by the host log pipeline rather than packet capture.
    pub fn is_log(self) -> bool {
        matches!(
            self,
            Detector::SshAuthFailures
                | Detector::SshSuccessAfterFailures
                | Detector::PamFailureBurst
                | Detector::SudoDenial
                | Detector::HttpLogScan
                | Detector::SystemSecurityChange
                | Detector::AccountModification
        )
    }

    pub const ALL: [Detector; 21] = [
        Detector::VerticalScan,
        Detector::HorizontalScan,
        Detector::StealthScan,
        Detector::AckScan,
        Detector::UdpScan,
        Detector::IcmpSweep,
        Detector::SynFlood,
        Detector::ConnectionRate,
        Detector::TarpitPort,
        Detector::SshBruteForce,
        Detector::HttpPathScan,
        Detector::HttpBadPath,
        Detector::HttpAuthBrute,
        Detector::HttpAnomaly,
        Detector::HttpFlood,
        Detector::SshAuthFailures,
        Detector::SlowScan,
        Detector::SshSuccessAfterFailures,
        Detector::PamFailureBurst,
        Detector::HttpLogScan,
        Detector::Honeypot,
    ];
}

impl std::fmt::Display for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    /// A host-log event rather than a network packet.
    Log,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Icmpv6 => "icmp6",
            Proto::Log => "log",
        }
    }
}

/// A detection event: `(detector, source, destination, protocol, count,
/// window, first_seen, last_seen, metadata)` per §6.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub detector: Detector,
    pub src: IpAddr,
    pub dst: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub proto: Proto,
    pub count: u64,
    pub window_secs: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub metadata: serde_json::Value,
    /// Set for log-derived detections: the `log_events` row that triggered it.
    pub evidence_log_id: Option<i64>,
    pub id: Option<i64>,
}

impl Detection {
    pub fn summary(&self) -> String {
        let src = if self.src.is_unspecified() {
            "unknown".to_string()
        } else {
            self.src.to_string()
        };
        match (self.dst_port, self.dst) {
            (Some(port), Some(dst)) => format!(
                "{} {} -> {}:{} ({} in {}s)",
                self.detector, src, dst, port, self.count, self.window_secs
            ),
            (None, Some(dst)) => format!(
                "{} {} -> {} ({} in {}s)",
                self.detector, src, dst, self.count, self.window_secs
            ),
            _ => format!(
                "{} {} ({} in {}s)",
                self.detector, src, self.count, self.window_secs
            ),
        }
    }

    /// True when the event carried no usable source address. Such detections
    /// are recorded and audited, never blocked.
    pub fn has_source(&self) -> bool {
        !self.src.is_unspecified()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockState {
    Active,
    /// Outlived its expiry while the daemon was down (FR-145).
    ExpiredPendingRemoval,
    Expired,
    ManualUnblocked,
}

impl BlockState {
    pub fn as_str(self) -> &'static str {
        match self {
            BlockState::Active => "active",
            BlockState::ExpiredPendingRemoval => "expired_pending_removal",
            BlockState::Expired => "expired",
            BlockState::ManualUnblocked => "manual_unblocked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub id: i64,
    pub src: IpAddr,
    pub reason: String,
    pub detector: Option<Detector>,
    pub detection_id: Option<i64>,
    /// Disposition rule that produced the action (FR-122).
    pub rule_id: Option<u32>,
    pub started_at: DateTime<Utc>,
    /// `None` = permanent.
    pub expires_at: Option<DateTime<Utc>>,
    pub state: BlockState,
    pub strike: u32,
}

impl Block {
    pub fn is_permanent(&self) -> bool {
        self.expires_at.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Strike {
    pub src: IpAddr,
    pub count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    pub id: i64,
    pub cidr: String,
    pub label: String,
    pub implicit: bool,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

/// Who caused an audited action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Actor {
    System,
    Cli,
    Admin(String),
    /// A login attempt that has not (yet) produced an admin session.
    Login(String),
}

impl Actor {
    pub fn as_str(&self) -> String {
        match self {
            Actor::System => "system".into(),
            Actor::Cli => "cli".into(),
            Actor::Admin(user) => format!("admin:{user}"),
            Actor::Login(user) => format!("login:{user}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_ids_are_stable() {
        assert_eq!(Detector::VerticalScan.to_string(), "DET-01");
        assert_eq!(Detector::SynFlood.to_string(), "DET-07");
        assert_eq!(Detector::ConnectionRate.to_string(), "DET-08");
        assert_eq!(Detector::TarpitPort.to_string(), "DET-09");
        assert_eq!(Detector::SshBruteForce.to_string(), "DET-10");
        assert_eq!(Detector::HttpPathScan.to_string(), "DET-11");
        assert_eq!(Detector::HttpFlood.to_string(), "DET-15");
        assert_eq!(Detector::SshAuthFailures.to_string(), "DET-16");
        assert_eq!(Detector::SlowScan.to_string(), "DET-20");
        assert_eq!(Detector::AccountModification.to_string(), "DET-25");
        assert_eq!(Detector::ALL.len(), 21);
        assert!(Detector::SshSuccessAfterFailures.is_alert_only());
        assert!(Detector::SshAuthFailures.is_log());
        assert!(!Detector::VerticalScan.is_log());
        assert_eq!(Detector::Honeypot.to_string(), "DET-26");
        assert!(!Detector::Honeypot.is_alert_only());
    }

    #[test]
    fn retired_internal_detectors_parse_but_are_not_in_the_catalog() {
        assert_eq!(Detector::from_id("DET-22"), Some(Detector::SudoDenial));
        assert_eq!(
            Detector::from_id("DET-24"),
            Some(Detector::SystemSecurityChange)
        );
        assert_eq!(
            Detector::from_id("DET-25"),
            Some(Detector::AccountModification)
        );
        assert!(!Detector::ALL.contains(&Detector::SudoDenial));
        assert!(!Detector::ALL.contains(&Detector::SystemSecurityChange));
        assert!(!Detector::ALL.contains(&Detector::AccountModification));
    }

    #[test]
    fn detector_serialises_as_id() {
        let json = serde_json::to_string(&Detector::UdpScan).unwrap();
        assert_eq!(json, "\"DET-05\"");
    }
}
