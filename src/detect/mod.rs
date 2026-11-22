//! Packet detectors DET-01…DET-10 plus slow-scan DET-20 and honeypot DET-26.
//!
//! Design constraints that shape this module:
//!
//! * Per-source state is bounded (FR-110): a hard source cap with eviction and
//!   capped per-source sets, so a spoofed-source flood costs memory, not the
//!   process.
//! * Only traffic *to this host* is considered for connection-based detectors
//!   (FR-112). Outbound SYNs from a browser must never look like a scan.
//! * One event per `(detector, source)` per cooldown (FR-114), while activity
//!   keeps counting.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::config::Detection as DetectionCfg;
use crate::decode::{Packet, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG};
use crate::model::{Detector, Proto};

mod http;
use http::HttpEngine;

#[derive(Debug, Clone)]
pub struct Observation {
    pub detector: Detector,
    pub src: IpAddr,
    pub dst: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub proto: Proto,
    pub count: u64,
    pub window_secs: u64,
    pub metadata: serde_json::Value,
}

pub struct Engine {
    cfg: DetectionCfg,
    local: HashSet<IpAddr>,
    sources: SourceTable,
    http: HttpEngine,
}

impl Engine {
    pub fn new(cfg: &DetectionCfg, local: Vec<IpAddr>) -> Engine {
        Engine {
            cfg: cfg.clone(),
            local: local
                .into_iter()
                .map(crate::net::normalise)
                .collect::<HashSet<_>>(),
            sources: SourceTable::new(cfg.max_tracked_sources, cfg.window_secs as usize),
            http: HttpEngine::new(cfg),
        }
    }

    pub fn set_local(&mut self, addrs: Vec<IpAddr>) {
        self.local = addrs.into_iter().map(crate::net::normalise).collect();
    }

    pub fn local_addrs(&self) -> &HashSet<IpAddr> {
        &self.local
    }

    pub fn observe(&mut self, pkt: &Packet<'_>, now: DateTime<Utc>) -> Vec<Observation> {
        let secs = now.timestamp().max(0) as u64;
        let mut out = Vec::new();
        let src_local = self.local.contains(&pkt.src);
        let dst_local = self.local.contains(&pkt.dst);

        // Outbound packets are not attacks, but HTTP responses are needed to
        // score 404/401/403 outcomes. Attribute those detections to the client
        // address, never the server.
        if src_local {
            out.extend(self.http.observe_response(pkt, now));
            if let Some(tcp) = pkt.tcp {
                if tcp.is_syn_ack() {
                    self.sources.note_syn_ack(pkt.dst, secs);
                }
            }
            return out;
        }

        // ICMP is evaluated even when the destination is not local, because a
        // sweep observed on the wire may be aimed at a range. Other detectors
        // require the destination to be this host.
        if !dst_local && pkt.proto != Proto::Icmp && pkt.proto != Proto::Icmpv6 {
            return out;
        }

        out.extend(self.http.observe_request(pkt, now));

        let window = self.cfg.window_secs.max(1);
        let cooldown = self.cfg.cooldown_secs.max(1);
        let Some(state) = self.sources.get(pkt.src, secs) else {
            return out;
        };

        // DET-26: honeypot. Any TCP connection attempt or UDP datagram to a
        // configured honeypot port is suspicious by definition. The detector
        // fires only when the source reaches honeypot_hits contacts in the
        // shared window, so the shipped disposition rule can require 3.
        if self.cfg.honeypot_enabled {
            let hit = match pkt.proto {
                Proto::Tcp => pkt
                    .tcp
                    .filter(|tcp| tcp.is_syn() && !tcp.is_syn_ack())
                    .map(|tcp| (tcp.dst_port, "tcp")),
                Proto::Udp => pkt.udp.map(|udp| (udp.dst_port, "udp")),
                Proto::Icmp | Proto::Icmpv6 | Proto::Log => None,
            };
            if let Some((port, protocol)) = hit
                && self.cfg.honeypot_ports.contains(&port)
            {
                state.honeypot.add(secs, 1);
                let hits = state.honeypot.sum(secs);
                if hits as usize >= self.cfg.honeypot_hits
                    && state.emit(Detector::Honeypot, secs, cooldown)
                {
                    out.push(Observation {
                        detector: Detector::Honeypot,
                        src: pkt.src,
                        dst: Some(pkt.dst),
                        dst_port: Some(port),
                        proto: pkt.proto,
                        count: hits as u64,
                        window_secs: window,
                        metadata: serde_json::json!({
                            "port": port,
                            "protocol": protocol,
                            "contacts": hits,
                            "threshold": self.cfg.honeypot_hits,
                            "honeypot": true,
                        }),
                    });
                }
            }
        }

        match pkt.proto {
            Proto::Tcp => {
                let tcp = pkt.tcp.unwrap();
                let flags = tcp.flags;

                // DET-03: NULL / FIN / XMAS / invalid flag combinations.
                let null = flags == 0;
                let fin_only = flags == TCP_FIN;
                let xmas = flags & (TCP_FIN | TCP_PSH | TCP_URG) == (TCP_FIN | TCP_PSH | TCP_URG);
                let syn_with_terminator = flags & TCP_SYN != 0 && flags & (TCP_FIN | TCP_RST) != 0;
                if null || fin_only || xmas || syn_with_terminator {
                    state.stealth.add(secs, 1);
                    let n = state.stealth.sum(secs);
                    if n >= self.cfg.stealth_packets as u32
                        && state.emit(Detector::StealthScan, secs, cooldown)
                    {
                        out.push(Observation {
                            detector: Detector::StealthScan,
                            src: pkt.src,
                            dst: Some(pkt.dst),
                            dst_port: Some(tcp.dst_port),
                            proto: Proto::Tcp,
                            count: n as u64,
                            window_secs: window,
                            metadata: serde_json::json!({
                                "flags": flags,
                                "classification": if null { "null" }
                                    else if fin_only { "fin" }
                                    else if xmas { "xmas" }
                                    else { "invalid" },
                            }),
                        });
                    }
                }

                // DET-01: vertical scan — many destination ports, one host.
                if tcp.is_syn() && !tcp.is_syn_ack() {
                    state.syn_ports.add(tcp.dst_port, secs);
                    state.slow_ports.add(tcp.dst_port, secs);
                    state.syns.add(secs, 1);

                    // DET-20: a slow scan accumulates unique ports over a long
                    // window while staying below the short-window scan rate.
                    let slow_ports = state
                        .slow_ports
                        .count_recent(secs, self.cfg.slow_scan_window_secs);
                    let recent_ports = state.syn_ports.count_recent(secs, window);
                    if slow_ports >= self.cfg.slow_scan_ports
                        && recent_ports <= self.cfg.slow_scan_max_per_window
                        && state.emit(Detector::SlowScan, secs, self.cfg.slow_scan_cooldown_secs)
                    {
                        out.push(Observation {
                            detector: Detector::SlowScan,
                            src: pkt.src,
                            dst: Some(pkt.dst),
                            dst_port: Some(tcp.dst_port),
                            proto: Proto::Tcp,
                            count: slow_ports as u64,
                            window_secs: self.cfg.slow_scan_window_secs,
                            metadata: serde_json::json!({
                                "unique_ports": slow_ports,
                                "recent_ports": recent_ports,
                                "long_window_secs": self.cfg.slow_scan_window_secs,
                                "threshold": self.cfg.slow_scan_ports,
                                "max_recent": self.cfg.slow_scan_max_per_window,
                            }),
                        });
                    }
                    state.outstanding = state.outstanding.saturating_add(1);
                    state.conns.add(secs, 1);
                    state.ssh_conns.add(secs, 1);

                    // DET-08: connection-rate abuse — a source opening many
                    // new connections in the shared window.
                    if self.cfg.conn_rate > 0 {
                        let conns = state.conns.sum(secs);
                        if conns >= self.cfg.conn_rate as u32
                            && state.emit(Detector::ConnectionRate, secs, cooldown)
                        {
                            out.push(Observation {
                                detector: Detector::ConnectionRate,
                                src: pkt.src,
                                dst: Some(pkt.dst),
                                dst_port: Some(tcp.dst_port),
                                proto: Proto::Tcp,
                                count: conns as u64,
                                window_secs: window,
                                metadata: serde_json::json!({
                                    "new_connections": conns,
                                    "threshold": self.cfg.conn_rate,
                                }),
                            });
                        }
                    }

                    // DET-09: a connection to a port declared unused. One is
                    // enough; the cooldown still prevents an event flood.
                    if self.cfg.tarpit_ports.contains(&tcp.dst_port)
                        && state.emit(Detector::TarpitPort, secs, cooldown)
                    {
                        out.push(Observation {
                            detector: Detector::TarpitPort,
                            src: pkt.src,
                            dst: Some(pkt.dst),
                            dst_port: Some(tcp.dst_port),
                            proto: Proto::Tcp,
                            count: 1,
                            window_secs: window,
                            metadata: serde_json::json!({
                                "port": tcp.dst_port,
                                "declared_unused": true,
                            }),
                        });
                    }

                    // DET-10: SSH connection-rate brute-force proxy. The
                    // journal detector arrives with log ingestion (0.3.0);
                    // this one can act before the handshake completes.
                    if self.cfg.ssh_conns_per_min > 0 && tcp.dst_port == 22 {
                        let conns = state.ssh_conns.sum(secs);
                        if conns >= self.cfg.ssh_conns_per_min as u32
                            && state.emit(Detector::SshBruteForce, secs, cooldown)
                        {
                            out.push(Observation {
                                detector: Detector::SshBruteForce,
                                src: pkt.src,
                                dst: Some(pkt.dst),
                                dst_port: Some(tcp.dst_port),
                                proto: Proto::Tcp,
                                count: conns as u64,
                                window_secs: 60,
                                metadata: serde_json::json!({
                                    "ssh_connections_60s": conns,
                                    "threshold": self.cfg.ssh_conns_per_min,
                                }),
                            });
                        }
                    }

                    let ports = state.syn_ports.count_recent(secs, window);
                    if ports >= self.cfg.scan_ports
                        && state.emit(Detector::VerticalScan, secs, cooldown)
                    {
                        out.push(Observation {
                            detector: Detector::VerticalScan,
                            src: pkt.src,
                            dst: Some(pkt.dst),
                            dst_port: Some(tcp.dst_port),
                            proto: Proto::Tcp,
                            count: ports as u64,
                            window_secs: window,
                            metadata: serde_json::json!({
                                "unique_ports": ports,
                                "sample_ports": state.syn_ports.sample(8),
                            }),
                        });
                    }

                    // DET-02: horizontal scan — one port, many hosts.
                    let dsts = state
                        .syn_dsts
                        .entry(tcp.dst_port)
                        .or_insert_with(|| TimedSet::new(256));
                    dsts.add(pkt.dst, secs);
                    let hosts = dsts.count_recent(secs, window);
                    if hosts >= self.cfg.sweep_hosts
                        && state.emit(Detector::HorizontalScan, secs, cooldown)
                    {
                        out.push(Observation {
                            detector: Detector::HorizontalScan,
                            src: pkt.src,
                            dst: Some(pkt.dst),
                            dst_port: Some(tcp.dst_port),
                            proto: Proto::Tcp,
                            count: hosts as u64,
                            window_secs: window,
                            metadata: serde_json::json!({
                                "unique_hosts": hosts,
                                "port": tcp.dst_port,
                            }),
                        });
                    }

                    // DET-07: SYN flood — rate plus unanswered-handshake ratio.
                    let last_sec = state.syns.last_sec(secs);
                    if last_sec >= self.cfg.syn_per_sec as u32 {
                        let unanswered = state.outstanding.max(0) as u64;
                        let ratio = if last_sec == 0 {
                            0
                        } else {
                            (unanswered * 100 / last_sec as u64).min(100)
                        };
                        if ratio >= self.cfg.syn_unanswered_pct as u64
                            && state.emit(Detector::SynFlood, secs, cooldown)
                        {
                            out.push(Observation {
                                detector: Detector::SynFlood,
                                src: pkt.src,
                                dst: Some(pkt.dst),
                                dst_port: Some(tcp.dst_port),
                                proto: Proto::Tcp,
                                count: last_sec as u64,
                                window_secs: 1,
                                metadata: serde_json::json!({
                                    "syns_last_sec": last_sec,
                                    "unanswered_pct": ratio,
                                    "outstanding": unanswered,
                                }),
                            });
                        }
                    }
                } else if tcp.is_ack_only() && pkt.is_empty_payload() {
                    // DET-04: ACK scan. Require many distinct ports: ordinary
                    // ACK-only traffic reuses a small set of ports.
                    state.ack_ports.add(tcp.dst_port, secs);
                    let ports = state.ack_ports.count_recent(secs, window);
                    if ports >= self.cfg.ack_packets
                        && state.emit(Detector::AckScan, secs, cooldown)
                    {
                        out.push(Observation {
                            detector: Detector::AckScan,
                            src: pkt.src,
                            dst: Some(pkt.dst),
                            dst_port: Some(tcp.dst_port),
                            proto: Proto::Tcp,
                            count: ports as u64,
                            window_secs: window,
                            metadata: serde_json::json!({
                                "unique_ports": ports,
                                "sample_ports": state.ack_ports.sample(8),
                            }),
                        });
                    }
                }
            }

            Proto::Udp => {
                let udp = pkt.udp.unwrap();
                // A UDP scan sends empty datagrams; normal services rarely do.
                if pkt.is_empty_payload() {
                    state.udp_ports.add(udp.dst_port, secs);
                    let ports = state.udp_ports.count_recent(secs, window);
                    if ports >= self.cfg.udp_ports && state.emit(Detector::UdpScan, secs, cooldown)
                    {
                        out.push(Observation {
                            detector: Detector::UdpScan,
                            src: pkt.src,
                            dst: Some(pkt.dst),
                            dst_port: Some(udp.dst_port),
                            proto: Proto::Udp,
                            count: ports as u64,
                            window_secs: window,
                            metadata: serde_json::json!({
                                "unique_ports": ports,
                                "sample_ports": state.udp_ports.sample(8),
                            }),
                        });
                    }
                }
            }

            Proto::Icmp | Proto::Icmpv6 => {
                if pkt.is_echo_request() {
                    state.icmp_dsts.add(pkt.dst, secs);
                    state.echo.add(secs, 1);
                    let hosts = state.icmp_dsts.count_recent(secs, window);
                    let rate = state.echo.last_sec(secs);
                    if (hosts >= self.cfg.icmp_hosts || rate >= self.cfg.icmp_echo_per_sec as u32)
                        && state.emit(Detector::IcmpSweep, secs, cooldown)
                    {
                        out.push(Observation {
                            detector: Detector::IcmpSweep,
                            src: pkt.src,
                            dst: Some(pkt.dst),
                            dst_port: None,
                            proto: pkt.proto,
                            count: hosts.max(rate as usize) as u64,
                            window_secs: window,
                            metadata: serde_json::json!({
                                "unique_hosts": hosts,
                                "echo_per_sec": rate,
                            }),
                        });
                    }
                }
            }
            // Not a wire protocol; log events never reach the packet engine.
            Proto::Log => {}
        }

        out
    }
}

// ---------------------------------------------------------------- per-source state

struct SourceState {
    last_seen: u64,
    syn_ports: TimedSet<u16>,
    slow_ports: TimedSet<u16>,
    syn_dsts: HashMap<u16, TimedSet<IpAddr>>,
    ack_ports: TimedSet<u16>,
    udp_ports: TimedSet<u16>,
    icmp_dsts: TimedSet<IpAddr>,
    stealth: WindowCounter,
    echo: WindowCounter,
    syns: WindowCounter,
    conns: WindowCounter,
    ssh_conns: WindowCounter,
    honeypot: WindowCounter,
    outstanding: i64,
    emitted: HashMap<Detector, u64>,
}

impl SourceState {
    fn new(window: usize) -> SourceState {
        SourceState {
            last_seen: 0,
            syn_ports: TimedSet::new(1024),
            slow_ports: TimedSet::new(256),
            syn_dsts: HashMap::new(),
            ack_ports: TimedSet::new(1024),
            udp_ports: TimedSet::new(1024),
            icmp_dsts: TimedSet::new(256),
            stealth: WindowCounter::new(window),
            echo: WindowCounter::new(window),
            syns: WindowCounter::new(window),
            conns: WindowCounter::new(window),
            ssh_conns: WindowCounter::new(60),
            honeypot: WindowCounter::new(window),
            outstanding: 0,
            emitted: HashMap::new(),
        }
    }

    /// Returns true when this detector may emit now.
    fn emit(&mut self, detector: Detector, secs: u64, cooldown: u64) -> bool {
        match self.emitted.get(&detector) {
            Some(&last) if secs.saturating_sub(last) < cooldown => false,
            _ => {
                self.emitted.insert(detector, secs);
                true
            }
        }
    }
}

struct SourceTable {
    map: HashMap<IpAddr, SourceState>,
    order: VecDeque<(IpAddr, u64)>,
    cap: usize,
    window: usize,
}

impl SourceTable {
    fn new(cap: usize, window: usize) -> SourceTable {
        SourceTable {
            map: HashMap::new(),
            order: VecDeque::new(),
            cap: cap.max(1),
            window,
        }
    }

    fn get(&mut self, src: IpAddr, secs: u64) -> Option<&mut SourceState> {
        if !self.map.contains_key(&src) {
            self.map.insert(src, SourceState::new(self.window.max(1)));
            self.order.push_back((src, secs));
            while self.map.len() > self.cap {
                let Some((old, at)) = self.order.pop_front() else {
                    break;
                };
                if let Some(entry) = self.map.get(&old) {
                    if entry.last_seen == at {
                        self.map.remove(&old);
                    }
                }
            }
        }
        let state = self.map.get_mut(&src)?;
        state.last_seen = secs;
        Some(state)
    }

    fn note_syn_ack(&mut self, client: IpAddr, secs: u64) {
        if let Some(state) = self.map.get_mut(&client) {
            state.outstanding = state.outstanding.saturating_sub(1);
            state.last_seen = secs;
        }
    }
}

// ------------------------------------------------------------------ small helpers

/// Timestamped set with a hard capacity. Old entries are pruned on demand.
struct TimedSet<T> {
    map: HashMap<T, u64>,
    cap: usize,
}

impl<T: Eq + Hash + Copy> TimedSet<T> {
    fn new(cap: usize) -> TimedSet<T> {
        TimedSet {
            map: HashMap::new(),
            cap,
        }
    }

    fn add(&mut self, key: T, secs: u64) {
        if self.map.len() >= self.cap && !self.map.contains_key(&key) {
            // Drop everything stale first; if nothing is stale, clear the set.
            // Losing history beats unbounded memory under a spoofed flood.
            self.map.retain(|_, ts| secs.saturating_sub(*ts) < 10);
            if self.map.len() >= self.cap {
                self.map.clear();
            }
        }
        self.map.insert(key, secs);
    }

    fn count_recent(&mut self, secs: u64, window: u64) -> usize {
        self.map.retain(|_, ts| secs.saturating_sub(*ts) < window);
        self.map.len()
    }

    fn sample(&self, n: usize) -> Vec<T> {
        self.map.keys().take(n).copied().collect()
    }
}

/// Sliding-window counter with one bucket per second.
struct WindowCounter {
    buckets: Vec<u32>,
    epoch: u64,
}

impl WindowCounter {
    fn new(window: usize) -> WindowCounter {
        WindowCounter {
            buckets: vec![0; window.max(1)],
            epoch: u64::MAX,
        }
    }

    fn add(&mut self, secs: u64, n: u32) {
        self.advance(secs);
        let len = self.buckets.len();
        let idx = (secs as usize) % len;
        self.buckets[idx] += n;
    }

    fn advance(&mut self, secs: u64) {
        if self.epoch == u64::MAX {
            self.epoch = secs;
            return;
        }
        if secs <= self.epoch {
            return;
        }
        let len = self.buckets.len() as u64;
        let gap = (secs - self.epoch).min(len);
        for i in 1..=gap {
            let idx = ((self.epoch + i) as usize) % self.buckets.len();
            self.buckets[idx] = 0;
        }
        self.epoch = secs;
    }

    fn sum(&mut self, secs: u64) -> u32 {
        self.advance(secs);
        self.buckets.iter().sum()
    }

    fn last_sec(&mut self, secs: u64) -> u32 {
        self.advance(secs);
        let idx = (secs as usize) % self.buckets.len();
        self.buckets[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{LinkType, TCP_SYN, decode};
    use crate::net::Cidr;

    const HOST: [u8; 4] = [10, 0, 0, 9];

    fn syn_frame(src: [u8; 4], dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 14];
        p[12] = 0x08;
        p[13] = 0x00;
        p.extend_from_slice(&[0x45, 0, 0, 0x28, 0, 0, 0x40, 0, 64, 6, 0, 0]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&HOST);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 8]); // sequence + acknowledgement
        p.push(0x50);
        p.push(TCP_SYN);
        p.extend_from_slice(&[0; 6]);
        p
    }

    fn http_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut p = vec![0u8; 14];
        p[12] = 0x08;
        p[13] = 0x00;
        p.extend_from_slice(&[
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0x40,
            0,
            64,
            6,
            0,
            0,
        ]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 8]);
        p.push(0x50);
        p.push(0x18); // PSH | ACK
        p.extend_from_slice(&[0; 6]);
        p.extend_from_slice(payload);
        p
    }

    fn engine() -> Engine {
        let cfg = DetectionCfg {
            window_secs: 10,
            cooldown_secs: 60,
            // Generic tests should not also accumulate DET-20 state.
            slow_scan_ports: 1_000_000,
            ..DetectionCfg::default()
        };
        Engine::new(&cfg, vec![HOST.into()])
    }

    fn slow_engine() -> Engine {
        Engine::new(&DetectionCfg::default(), vec![HOST.into()])
    }

    #[test]
    fn vertical_scan_fires_at_threshold() {
        let mut e = engine();
        let mut fired = 0;
        let base = Utc::now();
        for port in 1..=25u16 {
            let frame = syn_frame([203, 0, 113, 7], 1000 + port);
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            fired += e.observe(&pkt, base).len();
        }
        assert_eq!(fired, 1, "one event per cooldown");
        // Still inside the cooldown: no second event.
        let frame = syn_frame([203, 0, 113, 7], 2000);
        let pkt = decode(LinkType::Ethernet, &frame).unwrap();
        assert!(e.observe(&pkt, base).is_empty());
        // After the cooldown, continued scanning produces a new event.
        let later = base + chrono::Duration::seconds(61);
        let mut fired = 0;
        for port in 1..=20u16 {
            let frame = syn_frame([203, 0, 113, 7], 3000 + port);
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            fired += e.observe(&pkt, later).len();
        }
        assert_eq!(fired, 1, "cooldown expired, still scanning");
    }

    #[test]
    fn slow_scan_fires_after_a_long_low_rate_window() {
        let mut e = slow_engine();
        let base = Utc::now();
        let mut fired = 0;
        for port in 0..30u16 {
            let frame = syn_frame([203, 0, 113, 50], 20000 + port);
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            fired += e
                .observe(&pkt, base + chrono::Duration::seconds(port as i64 * 20))
                .iter()
                .filter(|obs| obs.detector == Detector::SlowScan)
                .count();
        }
        assert_eq!(fired, 1);
    }

    #[test]
    fn fast_scan_does_not_fire_det20() {
        let mut e = slow_engine();
        let base = Utc::now();
        let mut fired = 0;
        for port in 0..30u16 {
            let frame = syn_frame([203, 0, 113, 51], 25000 + port);
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            fired += e
                .observe(&pkt, base)
                .iter()
                .filter(|obs| obs.detector == Detector::SlowScan)
                .count();
        }
        assert_eq!(fired, 0);
    }

    #[test]
    fn honeypot_fires_on_configured_port_only() {
        let cfg = DetectionCfg {
            window_secs: 10,
            cooldown_secs: 60,
            slow_scan_ports: 1_000_000,
            honeypot_enabled: true,
            honeypot_ports: vec![2323],
            ..DetectionCfg::default()
        };
        let mut e = Engine::new(&cfg, vec![HOST.into()]);
        let base = Utc::now();

        let frame = syn_frame([203, 0, 113, 60], 8080);
        let pkt = decode(LinkType::Ethernet, &frame).unwrap();
        assert!(
            e.observe(&pkt, base)
                .iter()
                .all(|obs| obs.detector != Detector::Honeypot)
        );

        let frame = syn_frame([203, 0, 113, 60], 2323);
        let pkt = decode(LinkType::Ethernet, &frame).unwrap();
        // Two contacts are below the default threshold of three.
        for _ in 0..2 {
            assert!(
                e.observe(&pkt, base)
                    .iter()
                    .all(|obs| obs.detector != Detector::Honeypot)
            );
        }
        let out = e.observe(&pkt, base);
        let hit = out
            .iter()
            .find(|obs| obs.detector == Detector::Honeypot)
            .expect("honeypot detection");
        assert_eq!(hit.dst_port, Some(2323));
        assert_eq!(hit.count, 3);
        assert_eq!(hit.metadata["port"], 2323);
        assert_eq!(hit.metadata["contacts"], 3);

        // Cooldown suppresses a second alert once the threshold is reached.
        let out = e.observe(&pkt, base + chrono::Duration::seconds(1));
        assert!(out.iter().all(|obs| obs.detector != Detector::Honeypot));
    }

    #[test]
    fn disabled_honeypot_stays_silent() {
        let cfg = DetectionCfg {
            slow_scan_ports: 1_000_000,
            honeypot_ports: vec![2323],
            ..DetectionCfg::default()
        };
        let mut e = Engine::new(&cfg, vec![HOST.into()]);
        let frame = syn_frame([203, 0, 113, 61], 2323);
        let pkt = decode(LinkType::Ethernet, &frame).unwrap();
        assert!(
            e.observe(&pkt, Utc::now())
                .iter()
                .all(|obs| obs.detector != Detector::Honeypot)
        );
    }

    #[test]
    fn http_path_scan_fires_through_the_engine() {
        let mut e = engine();
        let base = Utc::now();
        let mut fired = 0;
        for i in 0..20 {
            let payload = format!("GET /p{i} HTTP/1.1\r\nHost: example.test\r\n\r\n");
            let frame = http_frame([203, 0, 113, 40], HOST, 40000, 80, payload.as_bytes());
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            fired += e
                .observe(&pkt, base + chrono::Duration::seconds(i))
                .iter()
                .filter(|obs| obs.detector == Detector::HttpPathScan)
                .count();
        }
        assert_eq!(fired, 1);
    }

    #[test]
    fn http_login_failures_fire_through_the_engine() {
        let mut e = engine();
        let base = Utc::now();
        let request = b"GET /login HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let frame = http_frame([203, 0, 113, 41], HOST, 40001, 80, request);
        let pkt = decode(LinkType::Ethernet, &frame).unwrap();
        assert!(e.observe(&pkt, base).is_empty());
        let response = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        let mut fired = 0;
        for i in 0..10 {
            let frame = http_frame(HOST, [203, 0, 113, 41], 80, 40001, response);
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            fired += e
                .observe(&pkt, base + chrono::Duration::seconds(i + 1))
                .iter()
                .filter(|obs| obs.detector == Detector::HttpAuthBrute)
                .count();
        }
        assert_eq!(fired, 1);
    }

    #[test]
    fn outbound_traffic_is_not_an_attack() {
        let mut e = engine();
        let base = Utc::now();
        // The host itself opening many connections must not alert.
        for port in 1..=50u16 {
            let mut frame = syn_frame([10, 0, 0, 9], 5000 + port);
            // Outbound: the packet's source is the host, the peer is remote.
            frame[26..30].copy_from_slice(&HOST);
            frame[30..34].copy_from_slice(&[203, 0, 113, 7]);
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            assert!(e.observe(&pkt, base).is_empty());
        }
    }

    #[test]
    fn established_acks_do_not_trigger_ack_scan() {
        let mut e = engine();
        let base = Utc::now();
        for _ in 0..50 {
            let mut frame = syn_frame([203, 0, 113, 8], 443);
            // ACK only, same port.
            frame[47] = 0x10;
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            assert!(e.observe(&pkt, base).is_empty());
        }
    }

    #[test]
    fn source_table_is_bounded() {
        let cfg = DetectionCfg {
            max_tracked_sources: 16,
            ..DetectionCfg::default()
        };
        let mut e = Engine::new(&cfg, vec![HOST.into()]);
        let base = Utc::now();
        for i in 0..1000u32 {
            let src = [198, 51, 100, (i % 250) as u8];
            let frame = syn_frame(src, 22);
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            let _ = e.observe(&pkt, base);
        }
        assert!(e.sources.map.len() <= 16, "{}", e.sources.map.len());
        let _ = Cidr::parse("10.0.0.0/8");
    }

    #[test]
    fn connection_rate_fires_at_threshold() {
        let cfg = DetectionCfg {
            window_secs: 10,
            cooldown_secs: 60,
            scan_ports: 1000,
            sweep_hosts: 1000,
            conn_rate: 5,
            ..DetectionCfg::default()
        };
        let mut e = Engine::new(&cfg, vec![HOST.into()]);
        let base = Utc::now();
        let mut fired = 0;
        for port in 1..=5u16 {
            let frame = syn_frame([203, 0, 113, 20], 1000 + port);
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            for obs in e.observe(&pkt, base) {
                if obs.detector == Detector::ConnectionRate {
                    fired += 1;
                    assert_eq!(obs.count, 5);
                }
            }
        }
        assert_eq!(fired, 1);
    }

    #[test]
    fn tarpit_port_fires_on_one_connection() {
        let cfg = DetectionCfg {
            tarpit_ports: vec![4444],
            scan_ports: 1000,
            ..DetectionCfg::default()
        };
        let mut e = Engine::new(&cfg, vec![HOST.into()]);
        let base = Utc::now();
        let frame = syn_frame([203, 0, 113, 21], 4444);
        let pkt = decode(LinkType::Ethernet, &frame).unwrap();
        let observations = e.observe(&pkt, base);
        assert!(
            observations
                .iter()
                .any(|o| o.detector == Detector::TarpitPort),
            "{observations:?}"
        );

        // A normal port does not fire it.
        let frame = syn_frame([203, 0, 113, 21], 8443);
        let pkt = decode(LinkType::Ethernet, &frame).unwrap();
        assert!(
            e.observe(&pkt, base)
                .iter()
                .all(|o| o.detector != Detector::TarpitPort)
        );
    }

    #[test]
    fn ssh_connection_rate_fires() {
        let cfg = DetectionCfg {
            window_secs: 10,
            cooldown_secs: 60,
            scan_ports: 1000,
            sweep_hosts: 1000,
            conn_rate: 0,
            ssh_conns_per_min: 10,
            ..DetectionCfg::default()
        };
        let mut e = Engine::new(&cfg, vec![HOST.into()]);
        let base = Utc::now();
        let mut fired = 0;
        for _ in 0..10 {
            let frame = syn_frame([203, 0, 113, 22], 22);
            let pkt = decode(LinkType::Ethernet, &frame).unwrap();
            for obs in e.observe(&pkt, base) {
                if obs.detector == Detector::SshBruteForce {
                    fired += 1;
                    assert_eq!(obs.count, 10);
                    assert_eq!(obs.window_secs, 60);
                }
            }
        }
        assert_eq!(fired, 1);
    }
}
