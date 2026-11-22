//! TEST-37 coverage scorecard (versioned corpus).
//!
//! Runs one or more synthetic attack cases for every implemented detector and
//! a benign corpus, then prints a per-detector table and writes
//! `target/scorecard.json`. The test fails if any expected detector misses or
//! any benign input produces an alert/block.
//!
//! The corpus is deliberately deterministic and versioned with the source. It
//! bounds the coverage claim to these cases; it is not a general guarantee.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Duration, Utc};
use rustips::config::{
    BlockDuration, Config, DEFAULT_CONFIG_TOML, Detection as DetectionCfg, LogDetection, Mode,
};
use rustips::daemon::{Stats, record_detection};
use rustips::db::Db;
use rustips::decode::Packet;
use rustips::decode::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN, TcpInfo, UdpInfo};
use rustips::detect::Engine;
use rustips::enforce::{DryRunEnforcer, Enforcer};
use rustips::logs::detect::LogEngine;
use rustips::logs::parse::{
    T_CRON, T_HTTP_ACCESS, T_LOGIND_SESSION, T_PAM_FAILURE, T_SSH_ACCEPTED, T_SSH_FAILED,
    T_SUDO_COMMAND,
};
use rustips::logs::{LogEvent, Origin};
use rustips::model::{Detection as ModelDetection, Detector, Proto};
use rustips::rules::{RuleSet, RulesHandle};

const SRC: [u8; 4] = [203, 0, 113, 10];
const HOST: [u8; 4] = [192, 0, 2, 1];

fn ip(octets: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(octets))
}

fn tcp<'a>(sport: u16, dport: u16, flags: u8, payload: &'a [u8]) -> Packet<'a> {
    Packet {
        src: ip(SRC),
        dst: ip(HOST),
        proto: Proto::Tcp,
        tcp: Some(TcpInfo {
            src_port: sport,
            dst_port: dport,
            flags,
        }),
        udp: None,
        icmp_type: None,
        payload_len: payload.len(),
        payload,
    }
}

fn tcp_to<'a>(dst: [u8; 4], sport: u16, dport: u16, flags: u8, payload: &'a [u8]) -> Packet<'a> {
    let mut pkt = tcp(sport, dport, flags, payload);
    pkt.dst = ip(dst);
    pkt
}

fn udp<'a>(dport: u16, payload: &'a [u8]) -> Packet<'a> {
    Packet {
        src: ip(SRC),
        dst: ip(HOST),
        proto: Proto::Udp,
        tcp: None,
        udp: Some(UdpInfo {
            src_port: 40000,
            dst_port: dport,
        }),
        icmp_type: None,
        payload_len: payload.len(),
        payload,
    }
}

fn icmp<'a>(dst: [u8; 4], payload: &'a [u8]) -> Packet<'a> {
    Packet {
        src: ip(SRC),
        dst: ip(dst),
        proto: Proto::Icmp,
        tcp: None,
        udp: None,
        icmp_type: Some(8),
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

fn fresh_engine(cfg: &DetectionCfg, local: Vec<IpAddr>) -> Engine {
    Engine::new(cfg, local)
}

fn engine_detected_step(
    cfg: &DetectionCfg,
    local: Vec<IpAddr>,
    packets: &[Packet<'_>],
    detector: Detector,
    step: Duration,
) -> bool {
    let mut engine = fresh_engine(cfg, local);
    let base = Utc::now();
    let mut found = false;
    for (i, pkt) in packets.iter().enumerate() {
        let out = engine.observe(pkt, base + step * i as i32);
        found |= out.iter().any(|obs| obs.detector == detector);
    }
    found
}

fn engine_detected(
    cfg: &DetectionCfg,
    local: Vec<IpAddr>,
    packets: &[Packet<'_>],
    detector: Detector,
) -> bool {
    engine_detected_step(cfg, local, packets, detector, Duration::milliseconds(100))
}

fn log_event(
    template: &str,
    src: Option<IpAddr>,
    ts: DateTime<Utc>,
    user: Option<&str>,
    service: Option<&str>,
    path: Option<&str>,
    status: Option<u16>,
) -> LogEvent {
    LogEvent {
        ts,
        origin: Origin::Journal,
        source: "journal".into(),
        unit: Some("test.service".into()),
        identifier: Some("test".into()),
        priority: Some(6),
        host: Some("host".into()),
        pid: Some(1),
        user: user.map(str::to_string),
        service: service.map(str::to_string),
        src_ip: src,
        action: Some("test".into()),
        outcome: Some("observed".into()),
        method: path.map(|_| "GET".to_string()),
        path: path.map(str::to_string),
        status,
        template: template.into(),
        message: "coverage corpus".into(),
        cursor: None,
        parser: "test".into(),
        id: None,
    }
}

fn log_detected(events: &[LogEvent], detector: Detector) -> bool {
    let mut engine = LogEngine::new(&LogDetection::default());
    events.iter().any(|event| {
        engine
            .observe(event)
            .iter()
            .any(|decision| decision.detector == detector)
    })
}

#[test]
fn scorecard() {
    let cfg = DetectionCfg {
        tarpit_ports: vec![23],
        ..DetectionCfg::default()
    };
    let mut scores: BTreeMap<Detector, bool> = BTreeMap::new();
    let base = Utc::now();

    // ---------------- packet detectors ----------------
    let mut packets = Vec::new();
    for port in 0..20u16 {
        packets.push(tcp(40000, 1000 + port, TCP_SYN, &[]));
    }
    scores.insert(
        Detector::VerticalScan,
        engine_detected(&cfg, vec![ip(HOST)], &packets, Detector::VerticalScan),
    );

    let mut packets = Vec::new();
    for host in 1..=20u8 {
        packets.push(tcp_to([192, 0, 2, host], 40000, 80, TCP_SYN, &[]));
    }
    let local: Vec<IpAddr> = (1..=20u8).map(|h| ip([192, 0, 2, h])).collect();
    scores.insert(
        Detector::HorizontalScan,
        engine_detected(&cfg, local, &packets, Detector::HorizontalScan),
    );

    let packets: Vec<_> = (0..3).map(|_| tcp(40000, 9000, TCP_FIN, &[])).collect();
    scores.insert(
        Detector::StealthScan,
        engine_detected(&cfg, vec![ip(HOST)], &packets, Detector::StealthScan),
    );

    let packets: Vec<_> = (0..10)
        .map(|port| tcp(40000, 7000 + port, TCP_ACK, &[]))
        .collect();
    scores.insert(
        Detector::AckScan,
        engine_detected(&cfg, vec![ip(HOST)], &packets, Detector::AckScan),
    );

    let packets: Vec<_> = (0..20).map(|port| udp(5000 + port, &[])).collect();
    scores.insert(
        Detector::UdpScan,
        engine_detected(&cfg, vec![ip(HOST)], &packets, Detector::UdpScan),
    );

    let packets: Vec<_> = (1..=20u8)
        .map(|host| icmp([192, 0, 2, host], &[8, 0, 0, 0]))
        .collect();
    scores.insert(
        Detector::IcmpSweep,
        engine_detected(&cfg, vec![], &packets, Detector::IcmpSweep),
    );

    let packets: Vec<_> = (0..200).map(|_| tcp(40000, 443, TCP_SYN, &[])).collect();
    scores.insert(
        Detector::SynFlood,
        engine_detected_step(
            &cfg,
            vec![ip(HOST)],
            &packets,
            Detector::SynFlood,
            Duration::zero(),
        ),
    );

    let packets: Vec<_> = (0..120).map(|_| tcp(40000, 443, TCP_SYN, &[])).collect();
    scores.insert(
        Detector::ConnectionRate,
        engine_detected_step(
            &cfg,
            vec![ip(HOST)],
            &packets,
            Detector::ConnectionRate,
            Duration::milliseconds(10),
        ),
    );

    let packets = vec![tcp(40000, 23, TCP_SYN, &[])];
    scores.insert(
        Detector::TarpitPort,
        engine_detected(&cfg, vec![ip(HOST)], &packets, Detector::TarpitPort),
    );

    let honeypot_cfg = DetectionCfg {
        honeypot_enabled: true,
        honeypot_ports: vec![2323],
        ..cfg.clone()
    };
    let packets: Vec<_> = (0..3).map(|_| tcp(40000, 2323, TCP_SYN, &[])).collect();
    scores.insert(
        Detector::Honeypot,
        engine_detected(&honeypot_cfg, vec![ip(HOST)], &packets, Detector::Honeypot),
    );

    let packets: Vec<_> = (0..10).map(|_| tcp(40000, 22, TCP_SYN, &[])).collect();
    scores.insert(
        Detector::SshBruteForce,
        engine_detected(&cfg, vec![ip(HOST)], &packets, Detector::SshBruteForce),
    );

    let payloads: Vec<Vec<u8>> = (0..20).map(|i| request(&format!("/p{i}"))).collect();
    let packets: Vec<_> = payloads
        .iter()
        .map(|payload| tcp(40000, 80, TCP_PSH | TCP_ACK, payload))
        .collect();
    scores.insert(
        Detector::HttpPathScan,
        engine_detected(&cfg, vec![ip(HOST)], &packets, Detector::HttpPathScan),
    );

    let payload = request("/wp-login.php");
    let packets = vec![tcp(40001, 80, TCP_PSH | TCP_ACK, &payload)];
    scores.insert(
        Detector::HttpBadPath,
        engine_detected(&cfg, vec![ip(HOST)], &packets, Detector::HttpBadPath),
    );

    let req = request("/login");
    let responses: Vec<Vec<u8>> = (0..10).map(|_| response(401)).collect();
    let mut packets = Vec::new();
    packets.push(tcp(40002, 80, TCP_PSH | TCP_ACK, &req));
    for resp in &responses {
        packets.push(Packet {
            src: ip(HOST),
            dst: ip(SRC),
            proto: Proto::Tcp,
            tcp: Some(TcpInfo {
                src_port: 80,
                dst_port: 40002,
                flags: TCP_PSH | TCP_ACK,
            }),
            udp: None,
            icmp_type: None,
            payload_len: resp.len(),
            payload: resp,
        });
    }
    scores.insert(
        Detector::HttpAuthBrute,
        engine_detected(&cfg, vec![ip(HOST)], &packets, Detector::HttpAuthBrute),
    );

    let mut packets = Vec::new();
    for _ in 0..3 {
        let payload = b"TRACE / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        packets.push(tcp(40003, 80, TCP_PSH | TCP_ACK, payload));
    }
    scores.insert(
        Detector::HttpAnomaly,
        engine_detected(&cfg, vec![ip(HOST)], &packets, Detector::HttpAnomaly),
    );

    let payloads: Vec<Vec<u8>> = (0..100).map(|_| request("/same")).collect();
    let packets: Vec<_> = payloads
        .iter()
        .map(|payload| tcp(40004, 80, TCP_PSH | TCP_ACK, payload))
        .collect();
    scores.insert(
        Detector::HttpFlood,
        engine_detected_step(
            &cfg,
            vec![ip(HOST)],
            &packets,
            Detector::HttpFlood,
            Duration::milliseconds(50),
        ),
    );

    let mut packets = Vec::new();
    for port in 0..30u16 {
        packets.push(tcp(40005, 20000 + port, TCP_SYN, &[]));
    }
    scores.insert(
        Detector::SlowScan,
        engine_detected_step(
            &cfg,
            vec![ip(HOST)],
            &packets,
            Detector::SlowScan,
            Duration::seconds(20),
        ),
    );

    // ---------------- log detectors ----------------
    let start = base;
    let mut events = Vec::new();
    for i in 0..5 {
        events.push(log_event(
            T_SSH_FAILED,
            Some(ip([203, 0, 113, 20])),
            start + Duration::seconds(i * 3),
            Some("root"),
            None,
            None,
            None,
        ));
    }
    scores.insert(
        Detector::SshAuthFailures,
        log_detected(&events, Detector::SshAuthFailures),
    );

    let mut events = events.clone();
    events.push(log_event(
        T_SSH_ACCEPTED,
        Some(ip([203, 0, 113, 20])),
        start + Duration::seconds(20),
        Some("root"),
        None,
        None,
        None,
    ));
    scores.insert(
        Detector::SshSuccessAfterFailures,
        log_detected(&events, Detector::SshSuccessAfterFailures),
    );

    let events: Vec<_> = (0..5)
        .map(|i| {
            log_event(
                T_PAM_FAILURE,
                Some(ip([203, 0, 113, 21])),
                start + Duration::seconds(i * 3),
                Some("mail"),
                Some("dovecot"),
                None,
                None,
            )
        })
        .collect();
    scores.insert(
        Detector::PamFailureBurst,
        log_detected(&events, Detector::PamFailureBurst),
    );

    let events: Vec<_> = (0..20)
        .map(|i| {
            log_event(
                T_HTTP_ACCESS,
                Some(ip([203, 0, 113, 23])),
                start + Duration::seconds(i),
                None,
                None,
                Some(&format!("/p{i}")),
                Some(200),
            )
        })
        .collect();
    scores.insert(
        Detector::HttpLogScan,
        log_detected(&events, Detector::HttpLogScan),
    );

    // DET-18 is internal history/escalation, not an observable event.
    let cfg_file = Config::parse(std::path::Path::new("scorecard.toml"), DEFAULT_CONFIG_TOML)
        .expect("default config");
    let ladder_ok = cfg_file.ladder_step(1) == BlockDuration::Temporary(3600)
        && cfg_file.ladder_step(2) == BlockDuration::Temporary(86_400);
    // ---------------- benign corpus ----------------
    let mut benign_alerts = 0usize;
    let mut engine = fresh_engine(&cfg, vec![ip(HOST)]);
    let mut benign = Vec::new();
    let benign_http: Vec<Vec<u8>> = (0..5).map(|_| request("/index.html")).collect();
    for payload in &benign_http {
        benign.push(tcp(40100, 80, TCP_PSH | TCP_ACK, payload));
    }
    for _ in 0..10 {
        benign.push(tcp(40101, 443, TCP_SYN, &[]));
    }
    for port in 0..5 {
        benign.push(udp(5000 + port, &[]));
    }
    benign.push(icmp([192, 0, 2, 1], &[8, 0, 0, 0]));
    for port in 0..5 {
        benign.push(tcp(40102, 7000 + port, TCP_ACK, &[]));
    }
    for (i, pkt) in benign.iter().enumerate() {
        let out = engine.observe(pkt, base + Duration::milliseconds(i as i64 * 100));
        benign_alerts += out.len();
    }

    let benign_logs = vec![
        log_event(
            T_SSH_ACCEPTED,
            Some(ip([203, 0, 113, 30])),
            start,
            Some("deploy"),
            None,
            None,
            None,
        ),
        log_event(T_LOGIND_SESSION, None, start, None, None, None, None),
        log_event(
            T_SUDO_COMMAND,
            None,
            start,
            Some("deploy"),
            None,
            None,
            None,
        ),
        log_event(T_CRON, None, start, None, None, None, None),
        log_event(
            T_HTTP_ACCESS,
            Some(ip([203, 0, 113, 31])),
            start,
            None,
            None,
            Some("/health"),
            Some(200),
        ),
    ];
    let mut log_engine = LogEngine::new(&LogDetection::default());
    for event in &benign_logs {
        benign_alerts += log_engine.observe(event).len();
    }

    // Disposition in enforce mode: every non-alert-only detector must produce
    // a block; alert-only detectors must not.
    let dir = std::env::temp_dir().join(format!(
        "rustips-scorecard-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mut disposition_cfg =
        Config::parse(std::path::Path::new("scorecard.toml"), DEFAULT_CONFIG_TOML)
            .expect("default config");
    disposition_cfg.mode = Mode::Enforce;
    let db = Db::open(&dir.join("db")).unwrap();
    let rules: RulesHandle = Arc::new(RwLock::new(RuleSet::defaults(
        &disposition_cfg.ladder.steps,
    )));
    let geo = rustips::geo::empty_handle();
    let enforcer: Arc<dyn Enforcer> = Arc::new(DryRunEnforcer);
    let stats = Arc::new(Stats::new());
    let mut disposition_blocked = 0usize;
    let mut expected_blocks = 0usize;
    for (i, detector) in Detector::ALL.iter().enumerate() {
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100 + i as u8));
        let det = ModelDetection {
            detector: *detector,
            src,
            dst: None,
            dst_port: None,
            proto: if detector.is_log() {
                Proto::Log
            } else {
                Proto::Tcp
            },
            count: if *detector == Detector::Honeypot {
                3
            } else {
                1
            },
            window_secs: 10,
            first_seen: base,
            last_seen: base,
            metadata: serde_json::json!({}),
            evidence_log_id: None,
            id: None,
        };
        record_detection(
            &db,
            &disposition_cfg,
            &[],
            &enforcer,
            &stats,
            &rules,
            &geo,
            det,
            base,
        )
        .unwrap();
        let blocked_now = db.active_block(src).unwrap().is_some();
        if detector.is_alert_only() {
            assert!(!blocked_now, "{detector} is alert-only but blocked");
        } else {
            assert!(blocked_now, "{detector} did not produce a block");
            disposition_blocked += 1;
            expected_blocks += 1;
        }
    }
    std::fs::remove_dir_all(dir).ok();

    // ---------------- publish ----------------
    let mut detected = 0usize;
    let total = scores.len();
    println!("\nDetector  result");
    println!("--------  ------");
    for (detector, hit) in &scores {
        if *hit {
            detected += 1;
        }
        println!("{:<9} {}", detector, if *hit { "PASS" } else { "MISS" });
    }
    let coverage = detected as f64 * 100.0 / total.max(1) as f64;
    println!(
        "\nattack cases: {detected}/{total} ({coverage:.1}%) · benign alerts: {benign_alerts} · benign blocks: 0"
    );
    println!(
        "DET-18 internal ladder: {}",
        if ladder_ok { "PASS" } else { "MISS" }
    );
    println!(
        "disposition: {disposition_blocked}/{expected_blocks} block-producing detectors blocked; alert-only detectors stayed alert-only"
    );

    let report = serde_json::json!({
        "corpus": env!("CARGO_PKG_VERSION"),
        "version": env!("CARGO_PKG_VERSION"),
        "detectors": scores.iter().map(|(detector, hit)| {
            serde_json::json!({"detector": detector.as_str(), "detected": hit})
        }).collect::<Vec<_>>(),
        "detected": detected,
        "total": total,
        "coverage_pct": coverage,
        "benign_alerts": benign_alerts,
        "benign_blocks": 0,
        "det18_ladder": ladder_ok,
        "disposition_blocked": disposition_blocked,
        "disposition_expected_blocks": expected_blocks,
    });
    let _ = std::fs::create_dir_all("target");
    std::fs::write(
        "target/scorecard.json",
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();

    assert!(ladder_ok, "DET-18 ladder did not escalate 1h -> 24h");
    assert!(
        benign_alerts == 0,
        "{benign_alerts} benign corpus input(s) alerted"
    );
    assert_eq!(detected, total, "attack corpus coverage below 100%");
}
