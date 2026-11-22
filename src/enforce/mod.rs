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

use crate::error::{Error, Result};

pub trait Enforcer: Send + Sync {
    /// Create table/chain/sets if missing. Idempotent.
    fn ensure(&self) -> Result<()>;
    fn add(&self, ip: IpAddr) -> Result<()>;
    fn remove(&self, ip: IpAddr) -> Result<()>;
    /// Replace the blocked set atomically (startup reconciliation).
    fn restore(&self, ips: &[IpAddr]) -> Result<()>;
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
