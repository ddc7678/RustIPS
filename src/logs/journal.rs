//! Supervised `journalctl -f -o json` reader (FR-301/302/303/311).
//!
//! The reader is deliberately outside the packet path: it owns its SQLite
//! connection, detects failures, reports degraded state, and retries with
//! backoff. A journal outage never stops capture or enforcement.
//!
//! Resume is by `__CURSOR`. The cursor is checkpointed after every processed
//! entry. If a crash happens between the event insert and the checkpoint, the
//! unique cursor index makes the replayed insert a no-op, so detections are not
//! duplicated.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::config::Config;
use crate::daemon::{Stats, record_detection};
use crate::db::Db;
use crate::enforce::Enforcer;
use crate::geo::GeoHandle;
use crate::logs::{LogEngine, parse};
use crate::net::Cidr;
use crate::rules::RulesHandle;

/// A single journal JSON line can legitimately be large; anything beyond this
/// is truncated and counted rather than allowed to grow without bound.
const MAX_LINE_BYTES: usize = 1024 * 1024;

pub struct JournalHandle {
    handle: Option<JoinHandle<()>>,
}

impl JournalHandle {
    pub fn join(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub fn spawn(
    db_path: PathBuf,
    cfg: Config,
    enforcer: Arc<dyn Enforcer>,
    rules: RulesHandle,
    geo: GeoHandle,
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
) -> JournalHandle {
    let handle = thread::spawn(move || run(db_path, cfg, enforcer, rules, geo, stop, stats));
    JournalHandle {
        handle: Some(handle),
    }
}

fn run(
    db_path: PathBuf,
    cfg: Config,
    enforcer: Arc<dyn Enforcer>,
    rules: RulesHandle,
    geo: GeoHandle,
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
) {
    let db = match Db::open(&db_path) {
        Ok(db) => db,
        Err(e) => {
            tracing::error!("log ingestion cannot open the database: {e}");
            return;
        }
    };
    let mut engine = LogEngine::new(&cfg.logs.detection);
    let mut rate = RateLimiter::new(
        cfg.logs.max_events_per_sec,
        cfg.logs.max_events_per_parser_per_sec,
    );
    let mut allow: Vec<Cidr> = db.allowlist_matcher().unwrap_or_default();
    let mut allow_loaded = Instant::now();
    let mut backoff = 1u64;
    let mut cursor_failures = 0u32;

    while !stop.load(Ordering::Relaxed) {
        let cursor = match db.journal_cursor() {
            Ok(cursor) => cursor,
            Err(e) => {
                tracing::error!("cannot read the journal cursor: {e}");
                sleep_unless_stopped(&stop, 5);
                continue;
            }
        };

        let mut command = Command::new("journalctl");
        command
            .arg("-f")
            .arg("-o")
            .arg("json")
            .arg("--no-pager")
            .env("SYSTEMD_COLORS", "0")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cursor) = &cursor {
            command.arg("--after-cursor").arg(cursor);
        } else if cfg.logs.backfill_secs > 0 {
            command
                .arg("--since")
                .arg(format!("-{}s", cfg.logs.backfill_secs));
        } else {
            command.arg("--since").arg("now");
        }

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                tracing::error!(error = %e, "cannot start journalctl; log ingestion is degraded");
                let _ = db.set_log_state(
                    "journal.status",
                    &serde_json::json!({
                        "state": "degraded",
                        "error": e.to_string(),
                        "at": Utc::now(),
                    }),
                );
                sleep_unless_stopped(&stop, backoff);
                backoff = (backoff * 2).min(60);
                continue;
            }
        };

        let _ = db.set_log_state(
            "journal.status",
            &serde_json::json!({
                "state": "running",
                "resumed": cursor.is_some(),
                "backfill_secs": cfg.logs.backfill_secs,
                "started_at": Utc::now(),
            }),
        );
        tracing::info!(
            resumed = cursor.is_some(),
            backfill_secs = cfg.logs.backfill_secs,
            "journal ingestion started"
        );

        let (tx, rx) = sync_channel::<Vec<u8>>(4096);
        let stdout = child.stdout.take();
        let reader = thread::spawn(move || {
            if let Some(stdout) = stdout {
                read_lines(stdout, MAX_LINE_BYTES, |line| tx.send(line).is_ok());
            }
        });
        let stderr = child.stderr.take();
        let errors = thread::spawn(move || {
            let mut text = String::new();
            if let Some(mut stderr) = stderr {
                let _ = stderr.read_to_string(&mut text);
            }
            text
        });

        let mut processed = 0u64;
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(line) => {
                    processed += 1;
                    if let Err(e) = handle_line(
                        &db,
                        &cfg,
                        &mut engine,
                        &mut rate,
                        &mut allow,
                        &mut allow_loaded,
                        &enforcer,
                        &rules,
                        &geo,
                        &stats,
                        &line,
                    ) {
                        tracing::error!(error = %e, "journal event processing failed");
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        let error = errors.join().unwrap_or_default();
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let error = error.trim();
        if processed == 0 {
            cursor_failures += 1;
            if cursor.is_some() && cursor_failures >= 3 {
                let _ = db.clear_journal_cursor();
                let _ = db.set_log_state(
                    "journal.gap",
                    &serde_json::json!({
                        "at": Utc::now(),
                        "reason": "stored cursor could not be resumed; backfilling",
                    }),
                );
                cursor_failures = 0;
                backoff = 1;
                tracing::warn!("journal cursor could not be resumed; falling back to backfill");
            }
        } else {
            cursor_failures = 0;
            backoff = 1;
        }

        let _ = db.set_log_state(
            "journal.status",
            &serde_json::json!({
                "state": "degraded",
                "processed": processed,
                "error": if error.is_empty() { "journalctl exited" } else { error },
                "at": Utc::now(),
            }),
        );
        tracing::warn!(processed, error = %error, "journal ingestion stopped; retrying");
        sleep_unless_stopped(&stop, backoff);
        backoff = (backoff * 2).min(60);
    }

    let _ = db.set_log_state(
        "journal.status",
        &serde_json::json!({ "state": "stopped", "at": Utc::now() }),
    );
    tracing::info!("journal ingestion stopped");
}

#[allow(clippy::too_many_arguments)]
fn handle_line(
    db: &Db,
    cfg: &Config,
    engine: &mut LogEngine,
    rate: &mut RateLimiter,
    allow: &mut Vec<Cidr>,
    allow_loaded: &mut Instant,
    enforcer: &Arc<dyn Enforcer>,
    rules: &RulesHandle,
    geo: &GeoHandle,
    stats: &Arc<Stats>,
    line: &[u8],
) -> Result<(), crate::error::Error> {
    let Some(record) = parse::journal_record(line) else {
        stats.log_parse_errors.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    };

    // Advance the cursor even for excluded or dropped entries, otherwise they
    // would be replayed forever after a restart.
    let checkpoint = |cursor: &Option<String>| -> Result<(), crate::error::Error> {
        if let Some(cursor) = cursor {
            db.set_journal_cursor(cursor)?;
        }
        Ok(())
    };

    if !cfg
        .logs
        .journal
        .allows(record.unit.as_deref(), record.identifier.as_deref())
    {
        return checkpoint(&record.cursor);
    }

    let mut event = parse::event_from_record(&record, cfg.logs.max_message_bytes, &cfg.logs.redact);
    if !cfg.logs.store_raw {
        event.message.clear();
    }

    if !rate.allow(&event.parser, event.ts) {
        stats.log_dropped.fetch_add(1, Ordering::Relaxed);
        return checkpoint(&record.cursor);
    }

    if allow_loaded.elapsed() > Duration::from_secs(10) {
        if let Ok(fresh) = db.allowlist_matcher() {
            *allow = fresh;
        }
        *allow_loaded = Instant::now();
    }

    match db.insert_log_event(&event)? {
        Some(id) => {
            event.id = Some(id);
            stats.log_events.fetch_add(1, Ordering::Relaxed);
            for det in engine.observe(&event) {
                record_detection(db, cfg, allow, enforcer, stats, rules, geo, det, event.ts)?;
            }
        }
        None => {
            // Cursor already stored: a replay race after a crash. The event
            // was processed the first time, so do not detect twice.
        }
    }

    checkpoint(&record.cursor)
}

struct RateLimiter {
    second: i64,
    global: u32,
    by_parser: HashMap<String, u32>,
    global_max: u32,
    parser_max: u32,
}

impl RateLimiter {
    fn new(global_max: u32, parser_max: u32) -> RateLimiter {
        RateLimiter {
            second: -1,
            global: 0,
            by_parser: HashMap::new(),
            global_max,
            parser_max,
        }
    }

    fn allow(&mut self, parser: &str, now: DateTime<Utc>) -> bool {
        let second = now.timestamp();
        if second != self.second {
            self.second = second;
            self.global = 0;
            self.by_parser.clear();
        }
        if self.global >= self.global_max {
            return false;
        }
        let count = self.by_parser.entry(parser.to_string()).or_insert(0);
        if *count >= self.parser_max {
            return false;
        }
        *count += 1;
        self.global += 1;
        true
    }
}

fn sleep_unless_stopped(stop: &Arc<AtomicBool>, secs: u64) {
    let mut remaining = secs * 4;
    while remaining > 0 && !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(250));
        remaining -= 1;
    }
}

/// Read newline-delimited input with a hard per-line cap. An overlong line is
/// truncated and still delivered once, never buffered without bound.
fn read_lines<R: Read>(reader: R, max: usize, mut on_line: impl FnMut(Vec<u8>) -> bool) {
    let mut reader = BufReader::with_capacity(64 * 1024, reader);
    let mut line = Vec::with_capacity(1024);
    let mut truncated = false;
    while let Ok(buf) = reader.fill_buf() {
        if buf.is_empty() {
            if !line.is_empty() || truncated {
                on_line(std::mem::take(&mut line));
            }
            break;
        }
        let mut consumed = 0;
        for &byte in buf {
            consumed += 1;
            if byte == b'\n' {
                if !truncated && line.last() == Some(&b'\r') {
                    line.pop();
                }
                if !on_line(std::mem::take(&mut line)) {
                    return;
                }
                truncated = false;
            } else if !truncated {
                if line.len() < max {
                    line.push(byte);
                } else {
                    truncated = true;
                }
            }
        }
        reader.consume(consumed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Mutex;

    #[test]
    fn reads_lines_and_caps_overlong_input() {
        let input = b"one\r\ntwo\nthis line is far too long\nthree";
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        read_lines(Cursor::new(input.to_vec()), 8, |line| {
            sink.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&line).into_owned());
            true
        });
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0], "one");
        assert_eq!(seen[1], "two");
        assert_eq!(seen[2], "this lin");
        assert_eq!(seen[3], "three");
    }

    #[test]
    fn rate_limiter_resets_each_second_and_per_parser() {
        let mut rate = RateLimiter::new(3, 2);
        let now = Utc::now();
        assert!(rate.allow("sshd", now));
        assert!(rate.allow("sshd", now));
        assert!(!rate.allow("sshd", now));
        assert!(rate.allow("sudo", now));
        assert!(!rate.allow("kernel", now));
        let next = now + chrono::Duration::seconds(1);
        assert!(rate.allow("sshd", next));
    }
}
