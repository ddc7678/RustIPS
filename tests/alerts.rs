//! Webhook delivery behaviour (TEST-41): bounded retries, dedupe, persistence
//! and a failed-forever state. A local TCP server plays the endpoint.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use rustips::alerts;
use rustips::config::{Config, DEFAULT_CONFIG_TOML};
use rustips::daemon::Stats;
use rustips::db::Db;
use rustips::model::{Detection, Detector, Proto};
use rustips::rules::{Decision, DecisionAction, Severity};

struct Server {
    url: String,
    bodies: Arc<Mutex<Vec<String>>>,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn start_server(fail_first: bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let bodies_thread = bodies.clone();
    let requests_thread = requests.clone();
    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let n = requests_thread.fetch_add(1, Ordering::Relaxed);
                    let success = !(fail_first && n == 0);
                    if let Some(body) = handle_connection(stream, success) {
                        bodies_thread.lock().unwrap().push(body);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    Server {
        url,
        bodies,
        requests,
        stop,
        handle: Some(handle),
    }
}

fn handle_connection(mut stream: TcpStream, success: bool) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&raw[..header_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while raw.len() < header_end + length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&raw[header_end..]).to_string();
    let response = if success {
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    } else {
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    };
    let _ = stream.write_all(response.as_bytes());
    Some(body)
}

fn config(url: &str, max_retries: u32) -> Config {
    let mut cfg = Config::parse(std::path::Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
    cfg.alerts.enabled = true;
    cfg.alerts.url = url.into();
    cfg.alerts.timeout_secs = 2;
    cfg.alerts.max_retries = max_retries;
    cfg.alerts.queue_max = 10;
    cfg.alerts.rate_limit_secs = 60;
    cfg.alerts.min_severity = "info".into();
    cfg
}

fn detection(src: &str) -> Detection {
    Detection {
        detector: Detector::VerticalScan,
        src: src.parse().unwrap(),
        dst: Some("192.0.2.1".parse().unwrap()),
        dst_port: Some(22),
        proto: Proto::Tcp,
        count: 20,
        window_secs: 10,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        metadata: serde_json::json!({}),
        evidence_log_id: None,
        id: Some(1),
    }
}

fn decision() -> Decision {
    Decision {
        matched: vec![3],
        rule_id: Some(3),
        rule_name: Some("Packet detections escalate".into()),
        severity: Severity::Warning,
        action: DecisionAction::Alert,
        tags: Vec::new(),
        dry_run: false,
    }
}

fn add_target(db: &Db, cfg: &Config) {
    let now = Utc::now();
    db.save_alert_target(
        &rustips::db::AlertTarget {
            id: 0,
            name: "test".into(),
            enabled: true,
            url: cfg.alerts.url.clone(),
            events: "all".into(),
            min_severity: cfg.alerts.min_severity.clone(),
            timeout_secs: cfg.alerts.timeout_secs,
            max_retries: cfg.alerts.max_retries,
            rate_limit_secs: cfg.alerts.rate_limit_secs,
            queue_max: cfg.alerts.queue_max,
            created_at: now,
            updated_at: now,
            updated_by: "test".into(),
        },
        "test",
    )
    .unwrap();
}

fn temp_db(name: &str) -> (Db, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "rustips-alerts-{}-{}-{}",
        std::process::id(),
        name,
        Utc::now().timestamp_nanos_opt().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = Db::open(&dir.join("db")).unwrap();
    (db, dir)
}

fn curl_available() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[test]
fn retries_dedupes_and_survives_reopen() {
    if !curl_available() {
        eprintln!("curl is not installed; skipping webhook delivery test");
        return;
    }
    let server = start_server(true);
    let cfg = config(&server.url, 2);
    let (db, dir) = temp_db("retry");
    add_target(&db, &cfg);
    let stats = Arc::new(Stats::new());
    let now = Utc::now();
    let det = detection("203.0.113.70");
    let decision = decision();

    assert_eq!(
        alerts::enqueue_detection(
            &db,
            &det,
            &decision,
            "alert",
            &rustips::geo::GeoInfo::default(),
            now,
        )
        .unwrap(),
        1
    );
    // Same detector/source/action in the same rate-limit bucket.
    assert_eq!(
        alerts::enqueue_detection(
            &db,
            &det,
            &decision,
            "alert",
            &rustips::geo::GeoInfo::default(),
            now,
        )
        .unwrap(),
        0
    );

    // The first endpoint response is a 500: one retry is scheduled.
    alerts::deliver_due(&db, &stats, now).unwrap();
    let stats_now = db.alert_stats().unwrap();
    assert_eq!(stats_now.pending, 1);
    assert_eq!(stats_now.delivered, 0);
    assert!(db.due_alerts(now, 10).unwrap().is_empty());

    // The retry succeeds.
    let later = now + chrono::Duration::seconds(6);
    alerts::deliver_due(&db, &stats, later).unwrap();
    let stats_later = db.alert_stats().unwrap();
    assert_eq!(stats_later.pending, 0);
    assert_eq!(stats_later.delivered, 1);
    assert_eq!(stats.alerts_sent.load(Ordering::Relaxed), 1);
    assert_eq!(server.requests.load(Ordering::Relaxed), 2);

    let bodies = server.bodies.lock().unwrap();
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("\"detector\":\"DET-01\""))
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("\"action\":\"alert\""))
    );

    // A delivered row is not replayed after reopening the database.
    drop(bodies);
    let reopened = Db::open(&dir.join("db")).unwrap();
    assert!(reopened.due_alerts(later, 10).unwrap().is_empty());
    assert_eq!(reopened.alert_stats().unwrap().delivered, 1);
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn permanent_failure_is_recorded_not_retried_forever() {
    if !curl_available() {
        eprintln!("curl is not installed; skipping webhook failure test");
        return;
    }
    let mut cfg = config("http://127.0.0.1:1/unreachable", 0);
    cfg.alerts.timeout_secs = 1;
    let (db, dir) = temp_db("fail");
    add_target(&db, &cfg);
    let stats = Arc::new(Stats::new());
    let now = Utc::now();
    let det = detection("203.0.113.71");
    let decision = decision();
    alerts::enqueue_detection(
        &db,
        &det,
        &decision,
        "alert",
        &rustips::geo::GeoInfo::default(),
        now,
    )
    .unwrap();
    alerts::deliver_due(&db, &stats, now).unwrap();
    let stats_now = db.alert_stats().unwrap();
    assert_eq!(stats_now.pending, 0);
    assert_eq!(stats_now.failed, 1);
    assert!(!stats_now.last_error.is_empty());
    assert!(
        db.due_alerts(now + chrono::Duration::seconds(600), 10)
            .unwrap()
            .is_empty()
    );
    std::fs::remove_dir_all(dir).ok();
}
