//! Enforcement backend: nftables only (Q3).
//!
//! * The table is RustIPS-owned; no other tool's rules are touched.
//! * Blocks are plain set elements with **no kernel timeout** — expiry is owned
//!   by the daemon (DM-07) so a crash cannot lift a block.
//! * Every mutation is a single `nft -f -` transaction, so the blocked set is
//!   never observed half-applied.

use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::firewall::{FirewallPlan, LOG_PREFIX};

pub trait Enforcer: Send + Sync {
    /// Create table/chain/sets if missing. Idempotent.
    fn ensure(&self) -> Result<()>;
    fn add(&self, ip: IpAddr) -> Result<()>;
    fn remove(&self, ip: IpAddr) -> Result<()>;
    /// Replace the blocked set atomically (startup reconciliation).
    fn restore(&self, ips: &[IpAddr]) -> Result<()>;
    /// Replace the optional service-allow/default-drop layer. A plan with
    /// `enabled = false` restores the always-on blocked-source-only chain.
    fn apply_firewall(&self, plan: &FirewallPlan) -> Result<()>;
    /// Remove all RustIPS state from the kernel.
    fn flush(&self) -> Result<()>;
    fn available(&self) -> bool;
    fn describe(&self) -> String;
}

pub struct NftEnforcer {
    table: String,
    hook: String,
    priority: i32,
    bin: PathBuf,
    /// Last successfully applied optional firewall plan, used by `ensure` to
    /// repair drift without re-writing the chain on every check.
    firewall_plan: Mutex<Option<FirewallPlan>>,
    /// Serialise every `nft -f -` invocation from concurrent threads.
    script_lock: Mutex<()>,
}

impl NftEnforcer {
    pub fn new(table: &str, hook: &str, priority: i32) -> NftEnforcer {
        let bin = ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from("nft"));
        NftEnforcer {
            table: table.to_string(),
            hook: hook.to_string(),
            priority,
            bin,
            firewall_plan: Mutex::new(None),
            script_lock: Mutex::new(()),
        }
    }

    fn set(&self, ip: IpAddr) -> &'static str {
        if ip.is_ipv4() {
            "blocked_v4"
        } else {
            "blocked_v6"
        }
    }

    fn run(&self, args: &[&str]) -> Result<std::process::Output> {
        let out = Command::new(&self.bin)
            .args(args)
            .output()
            .map_err(|e| Error::Enforce(format!("cannot run {}: {e}", self.bin.display())))?;
        Ok(out)
    }

    fn exists(&self, args: &[&str]) -> bool {
        self.run(args).map(|o| o.status.success()).unwrap_or(false)
    }

    fn script(&self, script: &str) -> Result<()> {
        let _guard = self
            .script_lock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut child = Command::new(&self.bin)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Enforce(format!("cannot run {}: {e}", self.bin.display())))?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| Error::Enforce(format!("nft stdin: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| Error::Enforce(format!("nft wait: {e}")))?;
        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(Error::Enforce(format!(
            "nft rejected the transaction: {}",
            stderr.trim()
        )))
    }

    /// Build the full chain contents. Blocked sources always win, then the
    /// optional service/default-deny layer is appended.
    fn firewall_script(&self, plan: &FirewallPlan) -> String {
        let t = &self.table;
        let hook = &self.hook;
        let mut script = format!("flush chain inet {t} {hook}\n");
        script.push_str(&format!(
            "add rule inet {t} {hook} ip saddr @blocked_v4 drop\n\
             add rule inet {t} {hook} ip6 saddr @blocked_v6 drop\n"
        ));
        if !plan.enabled {
            return script;
        }

        // Never break replies to connections this host initiated, and keep
        // loopback (the UI, local services) working.
        // Loopback is accepted before admin drops so a bad source/destination
        // rule cannot lock the administrator out of the local UI.
        script.push_str(&format!("add rule inet {t} {hook} iif \"lo\" accept\n"));
        for rule in &plan.drops {
            let mut parts: Vec<String> = Vec::new();
            if let Some(src) = rule.src {
                let family = if src.addr.is_ipv4() { "ip" } else { "ip6" };
                parts.push(format!("{family} saddr {src}"));
            }
            if let Some(dst) = rule.dst {
                let family = if dst.addr.is_ipv4() { "ip" } else { "ip6" };
                parts.push(format!("{family} daddr {dst}"));
            }
            if let Some(port) = rule.port {
                if rule.proto.has_port() {
                    parts.push(format!("{} dport {port}", rule.proto.as_str()));
                }
            } else {
                match rule.proto {
                    crate::firewall::DropProto::Any => {}
                    crate::firewall::DropProto::Tcp => parts.push("meta l4proto tcp".into()),
                    crate::firewall::DropProto::Udp => parts.push("meta l4proto udp".into()),
                    crate::firewall::DropProto::Icmp => parts.push("meta l4proto icmp".into()),
                    crate::firewall::DropProto::Icmp6 => {
                        parts.push("meta l4proto ipv6-icmp".into())
                    }
                }
            }
            let matcher = if parts.is_empty() {
                String::new()
            } else {
                format!("{} ", parts.join(" "))
            };
            script.push_str(&format!(
                "add rule inet {t} {hook} {matcher}drop comment \"rustips-fw-admin\"\n"
            ));
        }
        script.push_str(&format!(
            "add rule inet {t} {hook} ct state established,related accept\n"
        ));
        // IPv6 needs neighbour discovery and router advertisements, and DHCP
        // clients need their server replies; without these the host can lose
        // connectivity even though its services are allowed.
        script.push_str(&format!(
            "add rule inet {t} {hook} icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }} accept\n\
             add rule inet {t} {hook} udp sport 67 udp dport 68 accept\n\
             add rule inet {t} {hook} udp sport 547 udp dport 546 accept\n"
        ));

        for proto in [crate::model::Proto::Tcp, crate::model::Proto::Udp] {
            let mut groups: std::collections::BTreeMap<Option<IpAddr>, Vec<u16>> =
                std::collections::BTreeMap::new();
            for rule in plan.allow.iter().filter(|rule| rule.proto == proto) {
                groups.entry(rule.addr).or_default().push(rule.port);
            }
            for (addr, mut ports) in groups {
                ports.sort_unstable();
                ports.dedup();
                let list = ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let prefix = match addr {
                    None => String::new(),
                    Some(ip) if ip.is_ipv4() => format!("ip daddr {ip} "),
                    Some(ip) => format!("ip6 daddr {ip} "),
                };
                script.push_str(&format!(
                    "add rule inet {t} {hook} {prefix}{} dport {{ {list} }} accept\n",
                    proto.as_str()
                ));
            }
        }

        if plan.log_drops {
            // Bound journal volume; the detector still sees a usable sample.
            script.push_str(&format!(
                "add rule inet {t} {hook} limit rate 10/second burst 20 packets \
                 log prefix \"{LOG_PREFIX} \" level warn\n"
            ));
        }
        let verb = if plan.reject { "reject" } else { "drop" };
        script.push_str(&format!(
            "add rule inet {t} {hook} {verb} comment \"rustips-fw\"\n"
        ));
        script
    }
}

impl Enforcer for NftEnforcer {
    fn ensure(&self) -> Result<()> {
        let t = &self.table;
        if !self.exists(&["list", "table", "inet", t]) {
            return self.script(&format!(
                "add table inet {t}\n\
                 add chain inet {t} {hook} {{ type filter hook {hook} priority {prio}; policy accept; }}\n\
                 add set inet {t} blocked_v4 {{ type ipv4_addr; }}\n\
                 add set inet {t} blocked_v6 {{ type ipv6_addr; }}\n\
                 add rule inet {t} {hook} ip saddr @blocked_v4 drop\n\
                 add rule inet {t} {hook} ip6 saddr @blocked_v6 drop\n",
                hook = self.hook,
                prio = self.priority
            ));
        }

        // Partial state: repair missing pieces without touching existing sets.
        let mut script = String::new();
        if !self.exists(&["list", "chain", "inet", t, &self.hook]) {
            script.push_str(&format!(
                "add chain inet {t} {hook} {{ type filter hook {hook} priority {prio}; policy accept; }}\n",
                hook = self.hook,
                prio = self.priority
            ));
        }
        if !self.exists(&["list", "set", "inet", t, "blocked_v4"]) {
            script.push_str(&format!(
                "add set inet {t} blocked_v4 {{ type ipv4_addr; }}\n"
            ));
        }
        if !self.exists(&["list", "set", "inet", t, "blocked_v6"]) {
            script.push_str(&format!(
                "add set inet {t} blocked_v6 {{ type ipv6_addr; }}\n"
            ));
        }
        if !script.is_empty() {
            self.script(&script)?;
        }
        // Re-assert the drop rules only when the chain lacks them.
        let listing = self
            .run(&["list", "chain", "inet", t, &self.hook])
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let mut rules = String::new();
        if !listing.contains("@blocked_v4") {
            rules.push_str(&format!(
                "add rule inet {t} {} ip saddr @blocked_v4 drop\n",
                self.hook
            ));
        }
        if !listing.contains("@blocked_v6") {
            rules.push_str(&format!(
                "add rule inet {t} {} ip6 saddr @blocked_v6 drop\n",
                self.hook
            ));
        }
        if !rules.is_empty() {
            self.script(&rules)?;
        }

        // Repair a chain that was flushed or edited out-of-band while the
        // optional firewall layer is enabled.
        let plan = self
            .firewall_plan
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();
        if let Some(plan) = plan {
            if plan.enabled {
                let listing = self
                    .run(&["list", "chain", "inet", t, &self.hook])
                    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                    .unwrap_or_default();
                let has_deny = listing.contains("comment \"rustips-fw\"");
                let has_log = !plan.log_drops || listing.contains(LOG_PREFIX);
                let has_drops =
                    plan.drops.is_empty() || listing.contains("comment \"rustips-fw-admin\"");
                if !has_deny || !has_log || !has_drops {
                    self.script(&self.firewall_script(&plan))?;
                }
            }
        }
        Ok(())
    }

    fn add(&self, ip: IpAddr) -> Result<()> {
        self.script(&format!(
            "add element inet {} {} {{ {} }}\n",
            self.table,
            self.set(ip),
            ip
        ))
        .or_else(|e| {
            // Already present is success: the database is authoritative.
            if e.to_string().contains("File exists") || e.to_string().contains("already exists") {
                Ok(())
            } else {
                Err(e)
            }
        })
    }

    fn remove(&self, ip: IpAddr) -> Result<()> {
        self.script(&format!(
            "delete element inet {} {} {{ {} }}\n",
            self.table,
            self.set(ip),
            ip
        ))
        .or_else(|e| {
            if e.to_string().contains("No such file") || e.to_string().contains("does not exist") {
                Ok(())
            } else {
                Err(e)
            }
        })
    }

    fn restore(&self, ips: &[IpAddr]) -> Result<()> {
        let mut v4 = String::new();
        let mut v6 = String::new();
        for ip in ips {
            if ip.is_ipv4() {
                v4.push_str(&format!("{ip}, "));
            } else {
                v6.push_str(&format!("{ip}, "));
            }
        }
        let t = &self.table;
        let mut script = format!("flush set inet {t} blocked_v4\nflush set inet {t} blocked_v6\n");
        if !v4.is_empty() {
            script.push_str(&format!(
                "add element inet {t} blocked_v4 {{ {} }}\n",
                v4.trim_end_matches(", ")
            ));
        }
        if !v6.is_empty() {
            script.push_str(&format!(
                "add element inet {t} blocked_v6 {{ {} }}\n",
                v6.trim_end_matches(", ")
            ));
        }
        self.script(&script)
    }

    fn apply_firewall(&self, plan: &FirewallPlan) -> Result<()> {
        let mut last = self
            .firewall_plan
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if last.as_ref() == Some(plan) {
            return Ok(());
        }
        self.script(&self.firewall_script(plan))?;
        *last = Some(plan.clone());
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        if !self.exists(&["list", "table", "inet", &self.table]) {
            return Ok(());
        }
        self.script(&format!("delete table inet {}\n", self.table))
    }

    fn available(&self) -> bool {
        self.bin.is_file() || which(&self.bin)
    }

    fn describe(&self) -> String {
        format!("nftables inet {} (hook {})", self.table, self.hook)
    }
}

fn which(path: &std::path::Path) -> bool {
    if path.components().count() > 1 {
        return path.is_file();
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(path).is_file()))
        .unwrap_or(false)
}

/// Observe mode: record what would have happened, enforce nothing.
pub struct DryRunEnforcer;

impl Enforcer for DryRunEnforcer {
    fn ensure(&self) -> Result<()> {
        Ok(())
    }
    fn add(&self, ip: IpAddr) -> Result<()> {
        tracing::info!(%ip, "observe mode: would block");
        Ok(())
    }
    fn remove(&self, ip: IpAddr) -> Result<()> {
        tracing::info!(%ip, "observe mode: would unblock");
        Ok(())
    }
    fn restore(&self, ips: &[IpAddr]) -> Result<()> {
        tracing::info!(count = ips.len(), "observe mode: would restore blocked set");
        Ok(())
    }
    fn apply_firewall(&self, plan: &FirewallPlan) -> Result<()> {
        if plan.enabled {
            tracing::info!(
                allow_rules = plan.allow_count(),
                log_drops = plan.log_drops,
                reject = plan.reject,
                "observe mode: would apply the service firewall"
            );
        } else {
            tracing::info!("observe mode: would disable the service firewall");
        }
        Ok(())
    }
    fn flush(&self) -> Result<()> {
        tracing::info!("observe mode: would flush");
        Ok(())
    }
    fn available(&self) -> bool {
        true
    }
    fn describe(&self) -> String {
        "observe mode (no enforcement)".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{AllowRule, DropProto, DropRule};
    use crate::model::Proto;
    use crate::net::Cidr;

    #[test]
    fn firewall_script_orders_blocks_allows_and_final_log_drop() {
        let enforcer = NftEnforcer::new("rustips", "input", -10);
        let plan = FirewallPlan {
            enabled: true,
            allow: vec![
                AllowRule {
                    proto: Proto::Tcp,
                    port: 22,
                    addr: None,
                },
                AllowRule {
                    proto: Proto::Tcp,
                    port: 443,
                    addr: Some("192.0.2.5".parse().unwrap()),
                },
                AllowRule {
                    proto: Proto::Udp,
                    port: 53,
                    addr: None,
                },
            ],
            drops: vec![DropRule {
                src: Some(Cidr::parse("203.0.113.0/24").unwrap()),
                dst: None,
                proto: DropProto::Tcp,
                port: Some(22),
            }],
            log_drops: true,
            reject: false,
        };
        let script = enforcer.firewall_script(&plan);
        let blocked = script.find("blocked_v4 drop").unwrap();
        let loopback = script.find("iif \"lo\" accept").unwrap();
        let admin = script
            .find("ip saddr 203.0.113.0/24 tcp dport 22 drop comment \"rustips-fw-admin\"")
            .unwrap();
        let established = script.find("ct state established,related accept").unwrap();
        let tcp = script.find("tcp dport { 22 } accept").unwrap();
        let tcp_addr = script
            .find("ip daddr 192.0.2.5 tcp dport { 443 } accept")
            .unwrap();
        let udp = script.find("udp dport { 53 } accept").unwrap();
        assert!(script.contains("icmpv6 type { nd-neighbor-solicit"));
        assert!(script.contains("udp sport 67 udp dport 68 accept"));
        assert!(script.contains("udp sport 547 udp dport 546 accept"));
        let log = script.find(LOG_PREFIX).unwrap();
        let drop = script.find("drop comment \"rustips-fw\"").unwrap();
        assert!(blocked < loopback);
        assert!(loopback < admin);
        assert!(admin < established);
        assert!(established < tcp);
        assert!(tcp < tcp_addr);
        assert!(tcp_addr < udp);
        assert!(udp < log);
        assert!(log < drop);
    }

    #[test]
    fn disabled_plan_only_keeps_blocked_sources() {
        let enforcer = NftEnforcer::new("rustips", "input", -10);
        let script = enforcer.firewall_script(&FirewallPlan::default());
        assert!(script.contains("blocked_v4 drop"));
        assert!(!script.contains("rustips-fw"));
        assert!(!script.contains("ct state established"));
    }

    #[test]
    fn reject_plan_uses_reject_and_still_logs() {
        let enforcer = NftEnforcer::new("rustips", "input", -10);
        let plan = FirewallPlan {
            enabled: true,
            allow: Vec::new(),
            drops: Vec::new(),
            log_drops: true,
            reject: true,
        };
        let script = enforcer.firewall_script(&plan);
        assert!(script.contains(LOG_PREFIX));
        assert!(script.contains("reject comment \"rustips-fw\""));
    }
}
