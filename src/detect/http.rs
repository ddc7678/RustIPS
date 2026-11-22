//! Packet HTTP detectors DET-11…15.
//!
//! Capture sees clear-text HTTP on the configured ports. Requests are parsed
//! from the first complete request head in a flow buffer; responses are parsed
//! from their status line and correlated back to the request by the client
//! tuple. This is a bounded, edge-triggered parser, not a full TCP reassembler:
//! one request per connection is enough for the scanners and brute-force
//! tools these detectors target, and a keep-alive burst may undercount.
//!
//! Every buffer and table is capped. Malformed input is counted as an anomaly,
//! never parsed unbounded or interpreted as a format string.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use super::{Observation, WindowCounter};
use crate::config::Detection;
use crate::decode::Packet;
use crate::model::{Detector, Proto};

const MAX_HEAD: usize = 2 * 1024;
const MAX_PATH: usize = 512;
const MAX_FLOWS: usize = 16_384;
const FLOW_IDLE_SECS: u64 = 30;

pub struct HttpEngine {
    cfg: HttpConfig,
    flows: HashMap<FlowKey, Flow>,
    clients: HashMap<IpAddr, ClientState>,
    last_prune: u64,
}

struct HttpConfig {
    ports: HashSet<u16>,
    bad_paths: Vec<String>,
    login_paths: Vec<String>,
    scan_404: u32,
    scan_paths: u32,
    scan_window: u64,
    auth_failures: u32,
    auth_window: u64,
    anomalies: u32,
    anomaly_window: u64,
    flood_requests: u32,
    flood_window: u64,
    cooldown: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    client: IpAddr,
    client_port: u16,
    server_port: u16,
}

struct Flow {
    data: Vec<u8>,
    last_seen: u64,
    request: Option<RequestInfo>,
}

struct RequestInfo {
    path: String,
    login: bool,
}

struct ClientState {
    last_seen: u64,
    paths: TimedPaths,
    flood: WindowCounter,
    not_found: WindowCounter,
    auth_fail: WindowCounter,
    anomalies: WindowCounter,
    emitted: HashMap<Detector, u64>,
}

impl ClientState {
    fn new(cfg: &HttpConfig) -> ClientState {
        ClientState {
            last_seen: 0,
            paths: TimedPaths::new(4096),
            flood: WindowCounter::new(cfg.flood_window as usize),
            not_found: WindowCounter::new(cfg.scan_window as usize),
            auth_fail: WindowCounter::new(cfg.auth_window as usize),
            anomalies: WindowCounter::new(cfg.anomaly_window as usize),
            emitted: HashMap::new(),
        }
    }

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

/// Bounded unique-path set with timestamps.
struct TimedPaths {
    map: HashMap<String, u64>,
    cap: usize,
}

impl TimedPaths {
    fn new(cap: usize) -> TimedPaths {
        TimedPaths {
            map: HashMap::new(),
            cap,
        }
    }

    fn add(&mut self, path: &str, secs: u64) {
        if self.map.len() >= self.cap && !self.map.contains_key(path) {
            self.map.retain(|_, ts| secs.saturating_sub(*ts) < 60);
            if self.map.len() >= self.cap {
                self.map.clear();
            }
        }
        self.map.insert(path.to_string(), secs);
    }

    fn count_recent(&mut self, secs: u64, window: u64) -> usize {
        self.map.retain(|_, ts| secs.saturating_sub(*ts) < window);
        self.map.len()
    }
}

impl HttpEngine {
    pub fn new(cfg: &Detection) -> HttpEngine {
        HttpEngine {
            cfg: HttpConfig {
                ports: cfg.http_ports.iter().copied().collect(),
                bad_paths: cfg
                    .http_bad_paths
                    .iter()
                    .map(|path| path.to_ascii_lowercase())
                    .collect(),
                login_paths: cfg
                    .http_login_paths
                    .iter()
                    .map(|path| path.to_ascii_lowercase())
                    .collect(),
                scan_404: cfg.http_scan_404 as u32,
                scan_paths: cfg.http_scan_paths as u32,
                scan_window: cfg.http_scan_window_secs.max(1),
                auth_failures: cfg.http_auth_failures as u32,
                auth_window: cfg.http_auth_window_secs.max(1),
                anomalies: cfg.http_anomalies as u32,
                anomaly_window: cfg.http_anomaly_window_secs.max(1),
                flood_requests: cfg.http_flood_requests as u32,
                flood_window: cfg.http_flood_window_secs.max(1),
                cooldown: cfg.cooldown_secs.max(1),
            },
            flows: HashMap::new(),
            clients: HashMap::new(),
            last_prune: 0,
        }
    }

    pub fn observe_request(&mut self, pkt: &Packet<'_>, now: DateTime<Utc>) -> Vec<Observation> {
        let Some(tcp) = pkt.tcp else {
            return Vec::new();
        };
        if !self.cfg.ports.contains(&tcp.dst_port) || pkt.payload.is_empty() {
            return Vec::new();
        }
        let secs = now.timestamp().max(0) as u64;
        self.prune(secs);
        let key = FlowKey {
            client: pkt.src,
            client_port: tcp.src_port,
            server_port: tcp.dst_port,
        };
        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            data: Vec::with_capacity(1024),
            last_seen: secs,
            request: None,
        });
        flow.last_seen = secs;
        if flow.data.len() < MAX_HEAD {
            let room = MAX_HEAD - flow.data.len();
            let take = pkt.payload.len().min(room);
            flow.data.extend_from_slice(&pkt.payload[..take]);
        }
        if !looks_like_http(&flow.data) {
            if flow.data.len() >= 8 {
                flow.data.clear();
            }
            return Vec::new();
        }
        let Some(head_end) = find_head_end(&flow.data) else {
            if flow.data.len() < MAX_HEAD {
                return Vec::new();
            }
            // Oversized head: treat as one malformed request.
            flow.data.clear();
            return self.anomaly(pkt, tcp.dst_port, secs, "oversized request head", None);
        };
        let head = flow.data[..head_end].to_vec();
        flow.data.clear();
        let Some(mut request) = parse_request(&head) else {
            return self.anomaly(pkt, tcp.dst_port, secs, "malformed request line", None);
        };
        let lower_path = request.path.to_ascii_lowercase();
        request.login = self
            .cfg
            .login_paths
            .iter()
            .any(|needle| lower_path.contains(needle));
        request.bad_path = self
            .cfg
            .bad_paths
            .iter()
            .find(|needle| lower_path.contains(needle.as_str()))
            .cloned();
        flow.request = Some(RequestInfo {
            path: request.path.clone(),
            login: request.login,
        });

        let mut out = Vec::new();
        let fresh = ClientState::new(&self.cfg);
        let client = self.clients.entry(pkt.src).or_insert(fresh);
        client.last_seen = secs;

        if request.anomaly && request.anomaly_reason.is_some() {
            client.anomalies.add(secs, 1);
            let count = client.anomalies.sum(secs);
            if count >= self.cfg.anomalies
                && client.emit(Detector::HttpAnomaly, secs, self.cfg.cooldown)
            {
                out.push(Observation {
                    detector: Detector::HttpAnomaly,
                    src: pkt.src,
                    dst: Some(pkt.dst),
                    dst_port: Some(tcp.dst_port),
                    proto: Proto::Tcp,
                    count: count as u64,
                    window_secs: self.cfg.anomaly_window,
                    metadata: serde_json::json!({
                        "reason": request.anomaly_reason.clone().unwrap_or_default(),
                        "method": request.method,
                        "target": truncate(&request.path, 256),
                        "host": request.host.as_deref().map(|h| truncate(h, 128)),
                    }),
                });
            }
        }

        if let Some(needle) = request.bad_path {
            if client.emit(Detector::HttpBadPath, secs, self.cfg.cooldown) {
                out.push(Observation {
                    detector: Detector::HttpBadPath,
                    src: pkt.src,
                    dst: Some(pkt.dst),
                    dst_port: Some(tcp.dst_port),
                    proto: Proto::Tcp,
                    count: 1,
                    window_secs: 1,
                    metadata: serde_json::json!({
                        "path": truncate(&request.path, 256),
                        "matched": needle,
                        "method": request.method,
                    }),
                });
            }
        }

        client.paths.add(&request.path, secs);
        let unique = client.paths.count_recent(secs, self.cfg.scan_window);
        if unique >= self.cfg.scan_paths as usize
            && client.emit(Detector::HttpPathScan, secs, self.cfg.cooldown)
        {
            out.push(Observation {
                detector: Detector::HttpPathScan,
                src: pkt.src,
                dst: Some(pkt.dst),
                dst_port: Some(tcp.dst_port),
                proto: Proto::Tcp,
                count: unique as u64,
                window_secs: self.cfg.scan_window,
                metadata: serde_json::json!({
                    "unique_paths": unique,
                    "threshold": self.cfg.scan_paths,
                    "window_secs": self.cfg.scan_window,
                }),
            });
        }

        client.flood.add(secs, 1);
        let requests = client.flood.sum(secs);
        if requests >= self.cfg.flood_requests
            && client.emit(Detector::HttpFlood, secs, self.cfg.cooldown)
        {
            out.push(Observation {
                detector: Detector::HttpFlood,
                src: pkt.src,
                dst: Some(pkt.dst),
                dst_port: Some(tcp.dst_port),
                proto: Proto::Tcp,
                count: requests as u64,
                window_secs: self.cfg.flood_window,
                metadata: serde_json::json!({
                    "requests": requests,
                    "threshold": self.cfg.flood_requests,
                    "window_secs": self.cfg.flood_window,
                    "note": "keep-alive requests on one connection are counted once",
                }),
            });
        }

        out
    }

    pub fn observe_response(&mut self, pkt: &Packet<'_>, now: DateTime<Utc>) -> Vec<Observation> {
        let Some(tcp) = pkt.tcp else {
            return Vec::new();
        };
        if !self.cfg.ports.contains(&tcp.src_port) || pkt.payload.is_empty() {
            return Vec::new();
        }
        let Some(status) = parse_status(pkt.payload) else {
            return Vec::new();
        };
        let secs = now.timestamp().max(0) as u64;
        let key = FlowKey {
            client: pkt.dst,
            client_port: tcp.dst_port,
            server_port: tcp.src_port,
        };
        let path_login = match self.flows.get_mut(&key) {
            Some(flow) => {
                flow.last_seen = secs;
                flow.request
                    .as_ref()
                    .map(|request| (request.path.clone(), request.login))
            }
            None => None,
        };
        let (path, login) = path_login.unwrap_or_default();
        let fresh = ClientState::new(&self.cfg);
        let client = self.clients.entry(pkt.dst).or_insert(fresh);
        client.last_seen = secs;
        let mut out = Vec::new();

        if matches!(status, 403 | 404) {
            client.not_found.add(secs, 1);
            let count = client.not_found.sum(secs);
            if count >= self.cfg.scan_404
                && client.emit(Detector::HttpPathScan, secs, self.cfg.cooldown)
            {
                out.push(Observation {
                    detector: Detector::HttpPathScan,
                    src: pkt.dst,
                    dst: Some(pkt.src),
                    dst_port: Some(tcp.src_port),
                    proto: Proto::Tcp,
                    count: count as u64,
                    window_secs: self.cfg.scan_window,
                    metadata: serde_json::json!({
                        "status": status,
                        "not_found": count,
                        "threshold": self.cfg.scan_404,
                        "window_secs": self.cfg.scan_window,
                        "path": truncate(&path, 256),
                    }),
                });
            }
        }

        if login && matches!(status, 401 | 403) {
            client.auth_fail.add(secs, 1);
            let count = client.auth_fail.sum(secs);
            if count >= self.cfg.auth_failures
                && client.emit(Detector::HttpAuthBrute, secs, self.cfg.cooldown)
            {
                out.push(Observation {
                    detector: Detector::HttpAuthBrute,
                    src: pkt.dst,
                    dst: Some(pkt.src),
                    dst_port: Some(tcp.src_port),
                    proto: Proto::Tcp,
                    count: count as u64,
                    window_secs: self.cfg.auth_window,
                    metadata: serde_json::json!({
                        "status": status,
                        "failures": count,
                        "threshold": self.cfg.auth_failures,
                        "window_secs": self.cfg.auth_window,
                        "path": truncate(&path, 256),
                    }),
                });
            }
        }

        out
    }

    fn anomaly(
        &mut self,
        pkt: &Packet<'_>,
        server_port: u16,
        secs: u64,
        reason: &str,
        path: Option<&str>,
    ) -> Vec<Observation> {
        let fresh = ClientState::new(&self.cfg);
        let client = self.clients.entry(pkt.src).or_insert(fresh);
        client.last_seen = secs;
        client.anomalies.add(secs, 1);
        let count = client.anomalies.sum(secs);
        if count < self.cfg.anomalies
            || !client.emit(Detector::HttpAnomaly, secs, self.cfg.cooldown)
        {
            return Vec::new();
        }
        vec![Observation {
            detector: Detector::HttpAnomaly,
            src: pkt.src,
            dst: Some(pkt.dst),
            dst_port: Some(server_port),
            proto: Proto::Tcp,
            count: count as u64,
            window_secs: self.cfg.anomaly_window,
            metadata: serde_json::json!({
                "reason": reason,
                "path": path.map(|p| truncate(p, 256)),
            }),
        }]
    }

    fn prune(&mut self, secs: u64) {
        if secs.saturating_sub(self.last_prune) < 5 && self.flows.len() < MAX_FLOWS {
            return;
        }
        self.last_prune = secs;
        self.flows
            .retain(|_, flow| secs.saturating_sub(flow.last_seen) < FLOW_IDLE_SECS);
        if self.flows.len() > MAX_FLOWS {
            self.flows.clear();
        }
        if self.clients.len() > MAX_FLOWS {
            self.clients
                .retain(|_, client| secs.saturating_sub(client.last_seen) < 120);
            if self.clients.len() > MAX_FLOWS {
                self.clients.clear();
            }
        }
    }
}

struct Request {
    method: String,
    path: String,
    host: Option<String>,
    login: bool,
    bad_path: Option<String>,
    anomaly: bool,
    anomaly_reason: Option<String>,
}

fn looks_like_http(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let first_space = data.iter().position(|b| *b == b' ');
    if let Some(space) = first_space {
        if (2..=10).contains(&space) && data[..space].iter().all(|b| b.is_ascii_uppercase()) {
            return true;
        }
    }
    data.windows(5).any(|window| window == b"HTTP/")
}

fn find_head_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .or_else(|| {
            data.windows(2)
                .position(|window| window == b"\n\n")
                .map(|pos| pos + 2)
        })
}

fn parse_request(head: &[u8]) -> Option<Request> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.lines();
    let request_line = lines.next()?.trim_end_matches('\r');
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("");
    let mut anomaly = false;
    let mut anomaly_reason = None;

    let known_method = matches!(
        method.as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "OPTIONS" | "PATCH" | "CONNECT"
    );
    if !known_method {
        anomaly = true;
        anomaly_reason = Some(format!("method {method:?}"));
    }
    if !version.starts_with("HTTP/1.") {
        anomaly = true;
        anomaly_reason = Some("request version".into());
    }
    let path = normalize_path(&target);
    if path.is_empty() || path.chars().any(|c| c.is_control()) {
        anomaly = true;
        anomaly_reason = Some("request target".into());
    }
    if path.to_ascii_lowercase().contains("..") {
        anomaly = true;
        anomaly_reason = Some("path traversal".into());
    }

    let mut host = None;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                let value = value.trim();
                if value.is_empty()
                    || value.chars().any(|c| c.is_whitespace() || c.is_control())
                    || value.contains("..")
                {
                    anomaly = true;
                    anomaly_reason = Some("suspicious Host header".into());
                }
                host = Some(value.chars().take(256).collect());
            }
        }
    }
    if version == "HTTP/1.1" && host.is_none() {
        anomaly = true;
        anomaly_reason = Some("missing Host header".into());
    }

    Some(Request {
        method,
        path,
        host,
        login: false,
        bad_path: None,
        anomaly,
        anomaly_reason,
    })
}

fn normalize_path(target: &str) -> String {
    let target = if let Some(rest) = target.strip_prefix("http://") {
        rest.find('/').map(|i| &rest[i..]).unwrap_or("/")
    } else if let Some(rest) = target.strip_prefix("https://") {
        rest.find('/').map(|i| &rest[i..]).unwrap_or("/")
    } else {
        target
    };
    let path = target.split(['?', '#']).next().unwrap_or(target);
    path.chars().take(MAX_PATH).collect()
}

fn parse_status(payload: &[u8]) -> Option<u16> {
    if !payload.starts_with(b"HTTP/") {
        return None;
    }
    let end = payload
        .windows(2)
        .position(|window| window == b"\r\n")
        .or_else(|| payload.iter().position(|b| *b == b'\n'))
        .unwrap_or(payload.len().min(64));
    let line = String::from_utf8_lossy(&payload[..end]);
    let mut parts = line.split_whitespace();
    let _version = parts.next()?;
    parts.next()?.parse::<u16>().ok()
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Detection;
    use crate::decode::{TCP_ACK, TCP_PSH, TcpInfo};

    fn request_packet<'a>(payload: &'a [u8], sport: u16, dport: u16) -> Packet<'a> {
        Packet {
            src: "203.0.113.40".parse().unwrap(),
            dst: "192.0.2.1".parse().unwrap(),
            proto: Proto::Tcp,
            tcp: Some(TcpInfo {
                src_port: sport,
                dst_port: dport,
                flags: TCP_PSH | TCP_ACK,
            }),
            udp: None,
            icmp_type: None,
            payload_len: payload.len(),
            payload,
        }
    }

    fn response_packet<'a>(payload: &'a [u8], sport: u16, dport: u16) -> Packet<'a> {
        Packet {
            src: "192.0.2.1".parse().unwrap(),
            dst: "203.0.113.40".parse().unwrap(),
            proto: Proto::Tcp,
            tcp: Some(TcpInfo {
                src_port: sport,
                dst_port: dport,
                flags: TCP_PSH | TCP_ACK,
            }),
            udp: None,
            icmp_type: None,
            payload_len: payload.len(),
            payload,
        }
    }

    fn request(path: &str) -> Vec<u8> {
        format!("GET {path} HTTP/1.1\r\nHost: example.test\r\n\r\n").into_bytes()
    }

    fn response(status: u16) -> Vec<u8> {
        format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n").into_bytes()
    }

    #[test]
    fn bad_path_probe_fires_once() {
        let mut engine = HttpEngine::new(&Detection::default());
        let payload = request("/wp-login.php");
        let pkt = request_packet(&payload, 40000, 80);
        let found = engine.observe_request(&pkt, Utc::now());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].detector, Detector::HttpBadPath);
        assert_eq!(found[0].src, "203.0.113.40".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn unique_paths_fire_det11() {
        let mut engine = HttpEngine::new(&Detection::default());
        let start = Utc::now();
        let mut found = Vec::new();
        for i in 0..20 {
            let payload = request(&format!("/p{i}"));
            let pkt = request_packet(&payload, 40001, 80);
            found.extend(engine.observe_request(&pkt, start + chrono::Duration::seconds(i)));
        }
        assert!(
            found
                .iter()
                .any(|o| o.detector == Detector::HttpPathScan && o.metadata["unique_paths"] == 20)
        );
    }

    #[test]
    fn request_flood_fires_det15() {
        let mut engine = HttpEngine::new(&Detection::default());
        let start = Utc::now();
        let mut found = Vec::new();
        for i in 0..100 {
            let payload = request("/same");
            let pkt = request_packet(&payload, 40002, 80);
            found.extend(
                engine.observe_request(&pkt, start + chrono::Duration::milliseconds(i * 20)),
            );
        }
        assert!(found.iter().any(|o| o.detector == Detector::HttpFlood));
    }

    #[test]
    fn login_failures_fire_det13() {
        let mut engine = HttpEngine::new(&Detection::default());
        let start = Utc::now();
        let payload = request("/login");
        engine.observe_request(&request_packet(&payload, 40003, 80), start);
        let mut found = Vec::new();
        for i in 0..10 {
            let payload = response(401);
            found.extend(engine.observe_response(
                &response_packet(&payload, 80, 40003),
                start + chrono::Duration::seconds(i + 1),
            ));
        }
        assert!(found.iter().any(|o| o.detector == Detector::HttpAuthBrute));
        assert_eq!(found[0].src, "203.0.113.40".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn not_found_burst_fires_det11_from_responses() {
        let mut engine = HttpEngine::new(&Detection::default());
        let start = Utc::now();
        let payload = request("/x");
        engine.observe_request(&request_packet(&payload, 40004, 80), start);
        let mut found = Vec::new();
        for i in 0..15 {
            let payload = response(404);
            found.extend(engine.observe_response(
                &response_packet(&payload, 80, 40004),
                start + chrono::Duration::seconds(i + 1),
            ));
        }
        assert!(
            found
                .iter()
                .any(|o| o.detector == Detector::HttpPathScan && o.metadata["not_found"] == 15)
        );
    }

    #[test]
    fn method_anomalies_fire_det14() {
        let mut engine = HttpEngine::new(&Detection::default());
        let start = Utc::now();
        let payload = b"TRACE / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut found = Vec::new();
        for i in 0..3 {
            found.extend(engine.observe_request(
                &request_packet(payload, 40005, 80),
                start + chrono::Duration::seconds(i),
            ));
        }
        assert!(found.iter().any(|o| o.detector == Detector::HttpAnomaly));
    }

    #[test]
    fn random_payloads_are_bounded_and_do_not_panic() {
        let mut engine = HttpEngine::new(&Detection::default());
        let base = Utc::now();
        let mut state = 0x1234_5678_9abc_def0u64;
        for i in 0..2_000u32 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let len = (state % 300) as usize;
            let mut payload = vec![0u8; len];
            for byte in &mut payload {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *byte = (state >> 17) as u8;
            }
            let port = 40000 + (i % 200) as u16;
            let pkt = request_packet(&payload, port, 80);
            let _ = engine.observe_request(&pkt, base + chrono::Duration::seconds(i as i64));
            let pkt = response_packet(&payload, 80, port);
            let _ = engine.observe_response(&pkt, base + chrono::Duration::seconds(i as i64));
            assert!(engine.flows.len() <= MAX_FLOWS);
            assert!(engine.clients.len() <= MAX_FLOWS);
        }
    }

    #[test]
    fn non_http_payload_is_ignored() {
        let mut engine = HttpEngine::new(&Detection::default());
        let payload = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert!(
            engine
                .observe_request(&request_packet(&payload, 40006, 80), Utc::now())
                .is_empty()
        );
    }
}
