//! Optional host-firewall mode.
//!
//! The always-on enforcement path only drops sources that RustIPS has already
//! blocked. This module builds the *second* layer: a default-deny input policy
//! that is enabled by the administrator, with allow rules generated from the
//! services actually listening on the host (plus explicitly configured and
//! honeypot ports). The final rule logs to DET-27 before dropping or rejecting.
//!
//! Discovery reads `/proc/net/{tcp,tcp6,udp,udp6}` rather than shelling out, so
//! it works on a minimal host and in tests. A service that is not listening yet
//! is invisible until the next refresh; that is why the admin can also pin
//! extra ports in the UI/configuration.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{Config, Detection, Firewall};
use crate::db::{AdminDropRow, Db, FirewallServiceRow};
use crate::error::{Error, Result};
use crate::model::Proto;
use crate::net::Cidr;

/// nftables log prefix. The journal parser keys the new DET-27 detector on it.
pub const LOG_PREFIX: &str = "rustips-fw-drop";

/// Database key holding the live UI-managed firewall settings.
pub const SETTINGS_KEY: &str = "firewall.settings";

/// One listening socket discovered on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListeningSocket {
    pub proto: Proto,
    pub port: u16,
    /// `None` means a wildcard bind (all local addresses).
    pub addr: Option<IpAddr>,
}

/// One allow rule in the generated firewall policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRule {
    pub proto: Proto,
    pub port: u16,
    pub addr: Option<IpAddr>,
}

/// Protocol matcher for an administrator-defined drop rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropProto {
    Any,
    Tcp,
    Udp,
    Icmp,
    Icmp6,
}

impl DropProto {
    pub fn parse(value: &str) -> Option<DropProto> {
        match value.trim().to_ascii_lowercase().as_str() {
            "any" | "" => Some(DropProto::Any),
            "tcp" => Some(DropProto::Tcp),
            "udp" => Some(DropProto::Udp),
            "icmp" => Some(DropProto::Icmp),
            "icmp6" | "icmpv6" => Some(DropProto::Icmp6),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DropProto::Any => "any",
            DropProto::Tcp => "tcp",
            DropProto::Udp => "udp",
            DropProto::Icmp => "icmp",
            DropProto::Icmp6 => "icmp6",
        }
    }

    pub fn has_port(self) -> bool {
        matches!(self, DropProto::Tcp | DropProto::Udp)
    }
}

/// One explicit drop rule evaluated before established connections and the
/// generated service allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropRule {
    pub src: Option<Cidr>,
    pub dst: Option<Cidr>,
    pub proto: DropProto,
    pub port: Option<u16>,
}

/// The complete desired state of the optional firewall layer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FirewallPlan {
    pub enabled: bool,
    pub allow: Vec<AllowRule>,
    pub drops: Vec<DropRule>,
    pub log_drops: bool,
    pub reject: bool,
}

impl FirewallPlan {
    pub fn allow_count(&self) -> usize {
        self.allow.len()
    }

    pub fn drop_count(&self) -> usize {
        self.drops.len()
    }
}

/// The effective settings: the database override when present, otherwise the
/// configuration file.
pub fn settings(db: &Db, cfg: &Config) -> Firewall {
    match db.get_setting(SETTINGS_KEY) {
        Ok(Some(value)) => serde_json::from_value(value).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "stored firewall settings are invalid; using the config file");
            cfg.firewall.clone()
        }),
        Ok(None) => cfg.firewall.clone(),
        Err(e) => {
            tracing::warn!(error = %e, "cannot read firewall settings; using the config file");
            cfg.firewall.clone()
        }
    }
}

/// Persist the live UI settings. They take effect on the next scheduler check.
pub fn save_settings(db: &Db, value: &Firewall) -> Result<()> {
    db.set_setting(SETTINGS_KEY, &serde_json::to_value(value)?)
}

/// Discover listening TCP/UDP services.
///
/// `/proc/net/tcp` and `tcp6` only expose `LISTEN` sockets (`st == 0A`).
/// `/proc/net/udp` and `udp6` have no listen state, so an unconnected socket is
/// one whose remote address is all zeroes. Loopback-only binds are returned as
/// well; the caller omits them because the loopback rule already accepts them.
pub fn discover() -> Result<Vec<ListeningSocket>> {
    let mut sockets = Vec::new();
    let mut readable = false;

    for (path, proto, tcp) in [
        ("/proc/net/tcp", Proto::Tcp, true),
        ("/proc/net/tcp6", Proto::Tcp, true),
        ("/proc/net/udp", Proto::Udp, false),
        ("/proc/net/udp6", Proto::Udp, false),
    ] {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                readable = true;
                for socket in parse_proc_net(&text, proto, tcp) {
                    if !sockets.contains(&socket) {
                        sockets.push(socket);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(path, error = %e, "cannot read listening-socket table");
            }
        }
    }

    if !readable {
        return Err(Error::Other(
            "cannot read /proc/net socket tables for service discovery".into(),
        ));
    }
    Ok(sockets)
}

/// Parse one `/proc/net/{tcp,udp}{,6}` table. Exposed for deterministic tests.
pub fn parse_proc_net(text: &str, proto: Proto, tcp: bool) -> Vec<ListeningSocket> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(local), Some(remote), Some(state)) =
            (fields.get(1), fields.get(2), fields.get(3))
        else {
            continue;
        };
        if tcp && !state.eq_ignore_ascii_case("0A") {
            continue;
        }
        if !tcp && !remote_unspecified(remote) {
            // A connected UDP socket is a client, not a service.
            continue;
        }
        let Some((addr_hex, port_hex)) = local.split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        let Some(addr) = parse_proc_addr(addr_hex) else {
            continue;
        };
        let addr = if addr.is_unspecified() {
            None
        } else {
            Some(addr)
        };
        let socket = ListeningSocket { proto, port, addr };
        if !out.contains(&socket) {
            out.push(socket);
        }
    }
    out
}

fn remote_unspecified(remote: &str) -> bool {
    remote
        .split_once(':')
        .map(|(addr, _port)| addr.chars().all(|c| c == '0'))
        .unwrap_or(false)
}

fn parse_proc_addr(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => {
            let value = u32::from_str_radix(hex, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(value.to_le_bytes())))
        }
        32 => {
            let mut bytes = [0_u8; 16];
            for (chunk, word) in hex.as_bytes().chunks(8).enumerate() {
                let text = std::str::from_utf8(word).ok()?;
                let value = u32::from_str_radix(text, 16).ok()?;
                let start = chunk * 4;
                bytes[start..start + 4].copy_from_slice(&value.to_le_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Build the desired plan. Listening sockets already include the honeypot and
/// pinned ports when they are bound; the union keeps the rules complete when a
/// service is down or has not started yet.
pub fn plan(
    settings: &Firewall,
    detection: &Detection,
    listening: &[ListeningSocket],
    admin: &[AdminDropRow],
    service_states: &[FirewallServiceRow],
) -> FirewallPlan {
    if !settings.enabled {
        return FirewallPlan::default();
    }
    let mut allow = Vec::new();
    let mut drops = Vec::new();
    let mut push_allow = |proto: Proto, port: u16, addr: Option<IpAddr>| {
        if port == 0 {
            return;
        }
        let rule = AllowRule { proto, port, addr };
        if !allow.contains(&rule) {
            allow.push(rule);
        }
    };
    let mut push_drop = |rule: DropRule| {
        if !drops.contains(&rule) {
            drops.push(rule);
        }
    };

    // Administrator rules are explicit and run before the service allows.
    for rule in admin.iter().filter(|rule| rule.enabled) {
        let Some(proto) = DropProto::parse(&rule.proto) else {
            tracing::warn!(proto = %rule.proto, "ignoring admin drop with unknown protocol");
            continue;
        };
        let src = match rule.src.as_deref() {
            Some(value) => match Cidr::parse(value) {
                Ok(cidr) => Some(cidr),
                Err(e) => {
                    tracing::warn!(value, error = %e, "ignoring admin drop with invalid source");
                    continue;
                }
            },
            None => None,
        };
        let dst = match rule.dst.as_deref() {
            Some(value) => match Cidr::parse(value) {
                Ok(cidr) => Some(cidr),
                Err(e) => {
                    tracing::warn!(value, error = %e, "ignoring admin drop with invalid destination");
                    continue;
                }
            },
            None => None,
        };
        push_drop(DropRule {
            src,
            dst,
            proto,
            port: if proto.has_port() { rule.port } else { None },
        });
    }

    for port in &settings.allow_tcp_ports {
        push_allow(Proto::Tcp, *port, None);
    }
    for port in &settings.allow_udp_ports {
        push_allow(Proto::Udp, *port, None);
    }
    if settings.include_honeypot && detection.honeypot_enabled {
        for port in &detection.honeypot_ports {
            push_allow(Proto::Tcp, *port, None);
            push_allow(Proto::Udp, *port, None);
        }
    }
    if settings.discover_services {
        for socket in listening {
            if socket.addr.is_some_and(|addr| addr.is_loopback()) {
                // The loopback rule covers local-only services.
                continue;
            }
            let dropped = service_states
                .iter()
                .find(|state| {
                    state.proto.eq_ignore_ascii_case(socket.proto.as_str())
                        && state.port == socket.port
                        && state.addr == socket.addr
                })
                .is_some_and(|state| state.dropped);
            if dropped {
                let dst = socket.addr.map(|addr| Cidr {
                    addr,
                    prefix: if addr.is_ipv4() { 32 } else { 128 },
                });
                push_drop(DropRule {
                    src: None,
                    dst,
                    proto: match socket.proto {
                        Proto::Tcp => DropProto::Tcp,
                        Proto::Udp => DropProto::Udp,
                        _ => continue,
                    },
                    port: Some(socket.port),
                });
                continue;
            }
            push_allow(socket.proto, socket.port, socket.addr);
        }
    }

    allow.sort_by(|a, b| {
        a.proto
            .as_str()
            .cmp(b.proto.as_str())
            .then(a.port.cmp(&b.port))
            .then(a.addr.cmp(&b.addr))
    });
    FirewallPlan {
        enabled: true,
        allow,
        drops,
        log_drops: settings.log_drops,
        reject: settings.reject,
    }
}

/// Friendly names for common ports, used only in the UI.
pub fn service_name(port: u16, proto: Proto) -> &'static str {
    match (port, proto) {
        (22, Proto::Tcp) => "ssh",
        (25, Proto::Tcp) => "smtp",
        (53, Proto::Tcp | Proto::Udp) => "dns",
        (80, Proto::Tcp) => "http",
        (123, Proto::Udp) => "ntp",
        (443, Proto::Tcp) => "https",
        (445, Proto::Tcp) => "smb",
        (853, Proto::Tcp | Proto::Udp) => "dns-over-tls",
        (3306, Proto::Tcp) => "mysql",
        (5432, Proto::Tcp) => "postgresql",
        (6379, Proto::Tcp) => "redis",
        (8080, Proto::Tcp) => "http-alt",
        (8443, Proto::Tcp) => "https-alt",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 2
   2: 00000000:01BB 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 3 3
";

    const UDP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4 4
   1: 0100007F:9C40 0100007F:0035 01 00000000:00000000 00:00000000 00000000     0        0 5 5
";

    #[test]
    fn parses_listening_tcp_and_udp_only() {
        let tcp = parse_proc_net(TCP, Proto::Tcp, true);
        assert!(tcp.contains(&ListeningSocket {
            proto: Proto::Tcp,
            port: 22,
            addr: None
        }));
        assert!(tcp.contains(&ListeningSocket {
            proto: Proto::Tcp,
            port: 8080,
            addr: Some("127.0.0.1".parse().unwrap())
        }));
        // The established socket must not be treated as a listener.
        assert!(!tcp.iter().any(|socket| socket.port == 443));

        let udp = parse_proc_net(UDP, Proto::Udp, false);
        assert!(udp.contains(&ListeningSocket {
            proto: Proto::Udp,
            port: 53,
            addr: None
        }));
        assert!(!udp.iter().any(|socket| socket.port == 40000));
    }

    #[test]
    fn parses_ipv6_proc_addresses() {
        let text = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6 6
";
        let sockets = parse_proc_net(text, Proto::Tcp, true);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].addr, Some("::1".parse().unwrap()));
        assert_eq!(sockets[0].port, 22);
    }

    #[test]
    fn plan_unions_manual_honeypot_and_discovered_services() {
        let settings = Firewall {
            enabled: true,
            discover_services: true,
            allow_tcp_ports: vec![8080],
            allow_udp_ports: vec![51820],
            include_honeypot: true,
            log_drops: true,
            reject: false,
            ..Firewall::default()
        };
        let detection = Detection {
            honeypot_enabled: true,
            honeypot_ports: vec![2323],
            ..Detection::default()
        };
        let listening = vec![
            ListeningSocket {
                proto: Proto::Tcp,
                port: 22,
                addr: None,
            },
            ListeningSocket {
                proto: Proto::Tcp,
                port: 80,
                addr: Some("127.0.0.1".parse().unwrap()),
            },
        ];
        let plan = plan(&settings, &detection, &listening, &[], &[]);
        assert!(plan.enabled);
        assert!(plan.allow.contains(&AllowRule {
            proto: Proto::Tcp,
            port: 22,
            addr: None
        }));
        assert!(plan.allow.contains(&AllowRule {
            proto: Proto::Tcp,
            port: 8080,
            addr: None
        }));
        assert!(plan.allow.contains(&AllowRule {
            proto: Proto::Udp,
            port: 51820,
            addr: None
        }));
        assert!(plan.allow.contains(&AllowRule {
            proto: Proto::Tcp,
            port: 2323,
            addr: None
        }));
        assert!(plan.allow.contains(&AllowRule {
            proto: Proto::Udp,
            port: 2323,
            addr: None
        }));
        // Loopback-only binds are left to the loopback rule.
        assert!(!plan.allow.iter().any(|rule| rule.port == 80));
    }

    #[test]
    fn admin_and_service_drops_override_allows() {
        let settings = Firewall {
            enabled: true,
            ..Firewall::default()
        };
        let detection = Detection::default();
        let listening = vec![
            ListeningSocket {
                proto: Proto::Tcp,
                port: 22,
                addr: None,
            },
            ListeningSocket {
                proto: Proto::Tcp,
                port: 80,
                addr: None,
            },
        ];
        let now = chrono::Utc::now();
        let admin = vec![crate::db::AdminDropRow {
            id: 1,
            src: Some("203.0.113.0/24".into()),
            dst: None,
            proto: "tcp".into(),
            port: Some(22),
            enabled: true,
            created_at: now,
            updated_at: now,
            created_by: "admin".into(),
        }];
        let states = vec![crate::db::FirewallServiceRow {
            proto: "tcp".into(),
            port: 80,
            addr: None,
            first_seen: now,
            last_seen: now,
            dropped: true,
            acknowledged: true,
        }];
        let plan = plan(&settings, &detection, &listening, &admin, &states);
        assert!(plan.drops.contains(&DropRule {
            src: Some(Cidr::parse("203.0.113.0/24").unwrap()),
            dst: None,
            proto: DropProto::Tcp,
            port: Some(22),
        }));
        assert!(plan.drops.contains(&DropRule {
            src: None,
            dst: None,
            proto: DropProto::Tcp,
            port: Some(80),
        }));
        assert!(!plan.allow.iter().any(|rule| rule.port == 80));
        assert!(plan.allow.iter().any(|rule| rule.port == 22));
    }

    #[test]
    fn disabled_plan_is_empty() {
        let plan = plan(
            &Firewall::default(),
            &Detection::default(),
            &[ListeningSocket {
                proto: Proto::Tcp,
                port: 22,
                addr: None,
            }],
            &[],
            &[],
        );
        assert!(!plan.enabled);
        assert!(plan.allow.is_empty());
    }
}
