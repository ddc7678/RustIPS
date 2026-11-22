//! Generic outbound webhook alerting (FR-204/204a).
//!
//! Enqueue happens synchronously in the detection path but only writes a small
//! SQLite row; delivery runs in its own thread and never blocks capture,
//! detection or enforcement. The queue is persisted, deduplicated by a
//! detector/source/action time bucket, and bounded by `alerts.queue_max`.
//! Delivery uses `curl` (the same optional runtime dependency as geo updates),
//! so HTTPS works without adding a TLS stack to the binary.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::daemon::Stats;
use crate::db::{AlertJob, Db};
use crate::error::{Error, Result};
use crate::geo::GeoInfo;
use crate::model::Detection;
use crate::rules::{Decision, Severity};

fn rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 1,
        Severity::Warning => 2,
        Severity::Critical => 3,
    }
}

fn min_rank(value: &str) -> u8 {
    match value {
        "critical" => 3,
        "warning" => 2,
        _ => 1,
    }
}

/// Build and enqueue a detection alert for every matching target. Returns the
/// number of queue rows added.
#[allow(clippy::too_many_arguments)]
pub fn enqueue_detection(
    db: &Db,
    det: &Detection,
    decision: &Decision,
    action: &str,
    geo: &GeoInfo,
    now: DateTime<Utc>,
) -> Result<u32> {
    let targets = db.enabled_alert_targets()?;
    if targets.is_empty() {
        return Ok(0);
    }
    let payload = serde_json::json!({
        "event": "detection",
        "version": crate::VERSION,
        "timestamp": now,
        "detection_id": det.id,
        "detector": det.detector.as_str(),
        "detector_title": det.detector.title(),
        "severity": decision.severity.as_str(),
        "src": det.src.to_string(),
        "dst": det.dst.map(|dst| dst.to_string()),
        "dst_port": det.dst_port,
        "proto": det.proto.as_str(),
        "count": det.count,
        "window_secs": det.window_secs,
        "action": action,
        "rule_id": decision.rule_id,
        "rule_name": decision.rule_name,
        "matched_rules": decision.matched,
        "tags": decision.tags,
        "dry_run": decision.dry_run,
        "country": geo.country,
        "asn": geo.asn,
        "first_seen": det.first_seen,
        "last_seen": det.last_seen,
    });
    let payload = serde_json::to_string(&payload)?;
    let mut queued = 0;
    for target in targets {
        if !target.events_allows("detection") {
            continue;
        }
        if rank(decision.severity) < min_rank(&target.min_severity) {
            continue;
        }
        let bucket = now.timestamp().max(0) / target.rate_limit_secs.max(1) as i64;
        let dedupe = format!(
            "det|{}|{}|{}|{}|{}",
            target.id, det.detector, det.src, action, bucket
        );
        if db.enqueue_alert(Some(target.id), &dedupe, &payload, now, target.queue_max)? {
            queued += 1;
        }
    }
    Ok(queued)
}

/// Operational alert (geo/job failures, FR-205). Not filtered by severity.
pub fn enqueue_operational(db: &Db, kind: &str, message: &str, now: DateTime<Utc>) -> Result<u32> {
    let targets = db.enabled_alert_targets()?;
    if targets.is_empty() {
        return Ok(0);
    }
    let bucket = now.timestamp().max(0) / 300;
    let payload = serde_json::json!({
        "event": "operational",
        "version": crate::VERSION,
        "timestamp": now,
        "kind": kind,
        "message": message.chars().take(1024).collect::<String>(),
    });
    let payload = serde_json::to_string(&payload)?;
    let mut queued = 0;
    for target in targets {
        if !target.events_allows("operational") {
            continue;
        }
        let dedupe = format!("op|{}|{kind}|{bucket}", target.id);
        if db.enqueue_alert(Some(target.id), &dedupe, &payload, now, target.queue_max)? {
            queued += 1;
        }
    }
    Ok(queued)
}

/// Enqueue a one-off test event (UI button). Sent to every enabled target.
pub fn enqueue_test(db: &Db, now: DateTime<Utc>) -> Result<u32> {
    let targets = db.enabled_alert_targets()?;
    if targets.is_empty() {
        return Ok(0);
    }
    let unique = now.timestamp_nanos_opt().unwrap_or_else(|| now.timestamp());
    let payload = serde_json::json!({
        "event": "test",
        "version": crate::VERSION,
        "timestamp": now,
        "message": "RustIPS webhook test",
    });
    let payload = serde_json::to_string(&payload)?;
    let mut queued = 0;
    for target in targets {
        let dedupe = format!("test|{}|{unique}", target.id);
        if db.enqueue_alert(Some(target.id), &dedupe, &payload, now, target.queue_max)? {
            queued += 1;
        }
    }
    Ok(queued)
}

/// Start the delivery worker.
pub fn spawn(db_path: PathBuf, stop: Arc<AtomicBool>, stats: Arc<Stats>) -> JoinHandle<()> {
    thread::spawn(move || {
        let db = match Db::open(&db_path) {
            Ok(db) => db,
            Err(e) => {
                tracing::error!("alert worker cannot open the database: {e}");
                return;
            }
        };
        while !stop.load(Ordering::Relaxed) {
            if let Err(e) = deliver_due(&db, &stats, Utc::now()) {
                tracing::warn!("alert delivery pass failed: {e}");
            }
            sleep_unless_stopped(&stop, 1);
        }
    })
}

/// One delivery pass. Public so tests can drive it deterministically.
pub fn deliver_due(db: &Db, stats: &Arc<Stats>, now: DateTime<Utc>) -> Result<usize> {
    let jobs = db.due_alerts(now, 10)?;
    let mut delivered = 0;
    for AlertJob {
        id,
        target_id: _,
        target_name,
        url,
        timeout_secs,
        max_retries,
        attempts,
        payload,
    } in jobs
    {
        match send_webhook(&url, &payload, timeout_secs) {
            Ok(()) => {
                db.mark_alert_delivered(id, now)?;
                stats.alerts_sent.fetch_add(1, Ordering::Relaxed);
                delivered += 1;
            }
            Err(error) => {
                let attempts = attempts.saturating_add(1);
                let message = error.to_string();
                if attempts >= max_retries.saturating_add(1) {
                    db.fail_alert(id, attempts, &message)?;
                    stats.alerts_failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        alert = id,
                        target = %target_name,
                        attempts,
                        error = %message,
                        "webhook alert failed permanently"
                    );
                } else {
                    let delay = backoff_secs(attempts);
                    db.retry_alert(
                        id,
                        attempts,
                        now + chrono::Duration::seconds(delay as i64),
                        &message,
                    )?;
                    tracing::warn!(
                        alert = id,
                        target = %target_name,
                        attempts,
                        retry_in_secs = delay,
                        error = %message,
                        "webhook alert retry scheduled"
                    );
                }
            }
        }
    }
    Ok(delivered)
}

fn backoff_secs(attempts: u32) -> u64 {
    let exp = attempts.saturating_sub(1).min(6);
    5u64.saturating_mul(1u64 << exp).min(300)
}

fn send_webhook(url: &str, payload: &str, timeout_secs: u64) -> Result<()> {
    if url.is_empty()
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
        || !(url.starts_with("https://") || url.starts_with("http://"))
    {
        return Err(Error::Config("invalid webhook URL".into()));
    }
    let timeout = timeout_secs.clamp(1, 60).to_string();
    let mut child = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            &timeout,
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
        ])
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Other(format!("cannot run curl: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload.as_bytes())
            .map_err(|e| Error::Other(format!("cannot write webhook payload: {e}")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| Error::Other(format!("curl wait failed: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(Error::Other(format!(
        "webhook returned {}: {}",
        output.status,
        stderr.trim()
    )))
}

fn sleep_unless_stopped(stop: &Arc<AtomicBool>, secs: u64) {
    let mut remaining = secs * 4;
    while remaining > 0 && !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(250));
        remaining -= 1;
    }
}
