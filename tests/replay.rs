//! End-to-end replay: pcap → decode → detect → SQLite, in observe mode.
//!
//! The destination is 127.0.0.1, which the daemon always treats as local, so
//! the test does not depend on the machine having a particular interface
//! address. Sources are TEST-NET addresses.

use std::net::IpAddr;

use chrono::Utc;
use rustips::capture::pcap::write_pcap;
use rustips::config::{Config, DEFAULT_CONFIG_TOML, Mode};
use rustips::daemon;
use rustips::db::Db;
use rustips::paths::Layout;

fn ipv4(addr: [u8; 4]) -> Vec<u8> {
    addr.to_vec()
}

fn tcp_frame(src: [u8; 4], dst: [u8; 4], dport: u16, flags: u8) -> Vec<u8> {
    let mut p = vec![0u8; 14];
    p[12] = 0x08;
    p[13] = 0x00;
    p.extend_from_slice(&[0x45, 0, 0, 0x28, 0, 0, 0x40, 0, 64, 6, 0, 0]);
    p.extend_from_slice(&ipv4(src));
    p.extend_from_slice(&ipv4(dst));
    p.extend_from_slice(&40000u16.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&[0; 8]);
    p.push(0x50);
    p.push(flags);
    p.extend_from_slice(&[0; 6]);
    p
}

fn udp_frame(src: [u8; 4], dst: [u8; 4], dport: u16) -> Vec<u8> {
    let mut p = vec![0u8; 14];
    p[12] = 0x08;
    p[13] = 0x00;
    p.extend_from_slice(&[0x45, 0, 0, 0x1c, 0, 0, 0x40, 0, 64, 17, 0, 0]);
    p.extend_from_slice(&ipv4(src));
    p.extend_from_slice(&ipv4(dst));
    p.extend_from_slice(&41000u16.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&8u16.to_be_bytes());
    p.extend_from_slice(&[0; 2]);
    p
}

#[test]
fn replay_records_detections_and_blocks_nothing_in_observe_mode() {
    let dir = std::env::temp_dir().join(format!(
        "rustips-replay-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let layout = Layout {
        config: dir.join("config.toml"),
        state_dir: dir.join("state"),
        db: dir.join("state/rustips.db"),
        backups: dir.join("state/backups"),
    };
    std::fs::create_dir_all(&layout.state_dir).unwrap();

    let host = [127, 0, 0, 1];
    let now = Utc::now();
    let mut packets = Vec::new();
    for port in 1..=25u16 {
        packets.push((now, tcp_frame([203, 0, 113, 7], host, 1000 + port, 0x02)));
    }
    for port in 1..=25u16 {
        packets.push((
            now + chrono::Duration::seconds(1),
            udp_frame([198, 51, 100, 5], host, 2000 + port),
        ));
    }
    let pcap_path = dir.join("scan.pcap");
    std::fs::write(&pcap_path, write_pcap(&packets, 1)).unwrap();

    let cfg = Config::parse(std::path::Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
    assert_eq!(cfg.mode, Mode::Observe);

    daemon::run(
        &layout,
        cfg,
        daemon::Options {
            pcap: Some(pcap_path),
            fast_replay: true,
            force_observe: false,
            no_web: true,
            web_bind: None,
            web_port: None,
        },
    )
    .unwrap();

    let db = Db::open(&layout.db).unwrap();
    let detections = db.recent_detections(10).unwrap();
    let ids: Vec<&str> = detections.iter().map(|d| d.detector.as_str()).collect();
    assert!(ids.contains(&"DET-01"), "detections: {ids:?}");
    assert!(ids.contains(&"DET-05"), "detections: {ids:?}");
    assert_eq!(
        db.active_block_count().unwrap(),
        0,
        "observe mode must not block"
    );

    let src: IpAddr = "203.0.113.7".parse().unwrap();
    assert!(db.active_block(src).unwrap().is_none());

    std::fs::remove_dir_all(dir).ok();
}
