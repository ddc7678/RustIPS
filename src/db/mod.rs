//! SQLite storage: schema, migrations, and the queries the daemon needs.
//!
//! The database is authoritative for blocks. nftables is derived state and is
//! rebuilt from here at every start (FR-142).

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{Connection, OptionalExtension, params};

use crate::config::{BlockDuration, Config};
use crate::error::Result;
use crate::logs::{LogEvent, Origin};
use crate::model::{Actor, AllowlistEntry, Block, BlockState, Detection, Detector, Proto, Strike};
use crate::net::{self, Cidr};
use crate::rules::{Rule, RuleRevision};

const SCHEMA_VERSION: i64 = 12;

/// `(timestamp, actor, action, subject)` for the recent-activity view.
pub type AuditRow = (DateTime<Utc>, String, String, String);
/// `(timestamp, actor, action, subject, detail)` for the audit page.
pub type AuditDetailRow = (DateTime<Utc>, String, String, String, String);

/// One sampled resource point for the dashboard graphs.
#[derive(Debug, Clone, Copy)]
pub struct SystemPoint {
    pub ts: DateTime<Utc>,
    pub cpu_pct: f64,
    pub rss_mb: f64,
    pub db_mb: f64,
}

#[derive(Debug, Clone)]
pub struct AlertJob {
    pub id: i64,
    pub target_id: i64,
    pub target_name: String,
    pub url: String,
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub attempts: u32,
    pub payload: String,
}

/// A persisted webhook destination, editable through the Alerts page.
/// An administrator-defined firewall drop rule.
#[derive(Debug, Clone)]
pub struct AdminDropRow {
    pub id: i64,
    /// Canonical CIDR/IP, or `None` for any source.
    pub src: Option<String>,
    /// Canonical CIDR/IP, or `None` for any destination.
    pub dst: Option<String>,
    /// `any`, `tcp`, `udp`, `icmp` or `icmp6`.
    pub proto: String,
    pub port: Option<u16>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
}

/// Persistent state for one discovered listening service.
#[derive(Debug, Clone)]
pub struct FirewallServiceRow {
    pub proto: String,
    pub port: u16,
    /// `None` is a wildcard bind; otherwise the specific local address.
    pub addr: Option<IpAddr>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub dropped: bool,
    pub acknowledged: bool,
}

#[derive(Debug, Clone)]
pub struct AlertTarget {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub url: String,
    /// `all`, `detection` or `operational`.
    pub events: String,
    pub min_severity: String,
    pub timeout_secs: u64,
    pub max_retries: u32,
    pub rate_limit_secs: u64,
    pub queue_max: usize,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
}

impl AlertTarget {
    pub fn events_allows(&self, event: &str) -> bool {
        self.events == "all" || self.events == event
    }
}

#[derive(Debug, Clone, Default)]
pub struct AlertStats {
    pub pending: i64,
    pub delivered: i64,
    pub failed: i64,
    pub oldest_pending: Option<DateTime<Utc>>,
    pub last_error: String,
    pub last_failure: Option<DateTime<Utc>>,
}

/// One row for the Alerts page.
#[derive(Debug, Clone)]
pub struct AlertRecord {
    pub id: i64,
    pub target_id: Option<i64>,
    pub target_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub next_attempt: DateTime<Utc>,
    pub attempts: u32,
    pub state: String,
    pub payload: String,
    pub last_error: String,
    pub delivered_at: Option<DateTime<Utc>>,
}

pub struct Db {
    conn: Connection,
}

fn ms(dt: DateTime<Utc>) -> i64 {
    dt.timestamp_millis()
}

fn from_ms(v: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(v)
        .single()
        .unwrap_or_else(Utc::now)
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut db = Db { conn };
        db.migrate()?;
        // Defense in depth: the state directory is 0700, but the database
        // should not be group/world-readable either.
        let _ = crate::paths::set_mode(path, 0o600);
        Ok(db)
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    pub fn open_readonly(path: &Path) -> Result<Db> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        Ok(Db { conn })
    }

    fn migrate(&mut self) -> Result<()> {
        let current: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if current > SCHEMA_VERSION {
            return Err(crate::error::Error::Config(format!(
                "database schema {current} is newer than this binary ({SCHEMA_VERSION}); upgrade RustIPS"
            )));
        }
        if current == SCHEMA_VERSION {
            return Ok(());
        }
        // Serialise migrations across the daemon, CLI and web server. A second
        // opener waits here and then sees the committed user_version.
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if current == SCHEMA_VERSION {
            return Ok(());
        }
        if current > SCHEMA_VERSION {
            return Err(crate::error::Error::Config(format!(
                "database schema {current} is newer than this binary ({SCHEMA_VERSION}); upgrade RustIPS"
            )));
        }
        if current < 1 {
            tx.execute_batch(
                r#"
                CREATE TABLE detections (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_ms         INTEGER NOT NULL,
                    last_seen_ms  INTEGER NOT NULL,
                    detector      TEXT    NOT NULL,
                    src           TEXT    NOT NULL,
                    dst           TEXT,
                    dst_port      INTEGER,
                    proto         TEXT    NOT NULL,
                    count         INTEGER NOT NULL,
                    window_s      INTEGER NOT NULL,
                    metadata_json TEXT    NOT NULL
                );
                CREATE INDEX detections_ts ON detections(ts_ms);
                CREATE INDEX detections_src ON detections(src, ts_ms);

                CREATE TABLE blocks (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    src           TEXT    NOT NULL,
                    ip_version    INTEGER NOT NULL,
                    reason        TEXT    NOT NULL,
                    detector      TEXT,
                    detection_id  INTEGER,
                    started_at_ms INTEGER NOT NULL,
                    expires_at_ms INTEGER,
                    state         TEXT    NOT NULL,
                    strike        INTEGER NOT NULL DEFAULT 0,
                    enforced      INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX blocks_src ON blocks(src, started_at_ms);
                CREATE INDEX blocks_state ON blocks(state, expires_at_ms);
                CREATE UNIQUE INDEX blocks_one_active ON blocks(src) WHERE state = 'active';

                CREATE TABLE strikes (
                    src           TEXT PRIMARY KEY,
                    count         INTEGER NOT NULL,
                    first_seen_ms INTEGER NOT NULL,
                    last_seen_ms  INTEGER NOT NULL,
                    last_reason   TEXT NOT NULL
                );
                CREATE INDEX strikes_last_seen ON strikes(last_seen_ms);

                CREATE TABLE allowlist (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    cidr          TEXT NOT NULL UNIQUE,
                    label         TEXT NOT NULL DEFAULT '',
                    implicit      INTEGER NOT NULL DEFAULT 0,
                    created_at_ms INTEGER NOT NULL,
                    created_by    TEXT NOT NULL
                );

                CREATE TABLE audit (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_ms     INTEGER NOT NULL,
                    actor     TEXT NOT NULL,
                    action    TEXT NOT NULL,
                    subject   TEXT NOT NULL DEFAULT '',
                    detail    TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX audit_ts ON audit(ts_ms);

                CREATE TABLE settings (
                    key           TEXT PRIMARY KEY,
                    value_json    TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );
                "#,
            )?;
        }
        if current < 2 {
            tx.execute_batch(
                r#"
                ALTER TABLE detections ADD COLUMN evidence_log_id INTEGER;

                CREATE TABLE log_events (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_ms         INTEGER NOT NULL,
                    origin        TEXT    NOT NULL,
                    source        TEXT    NOT NULL,
                    unit          TEXT,
                    identifier    TEXT,
                    priority      INTEGER,
                    host          TEXT,
                    pid           INTEGER,
                    user          TEXT,
                    service       TEXT,
                    src_ip        TEXT,
                    action        TEXT,
                    outcome       TEXT,
                    template      TEXT    NOT NULL,
                    message       TEXT    NOT NULL DEFAULT '',
                    cursor        TEXT,
                    parser        TEXT    NOT NULL
                );
                CREATE INDEX log_events_ts ON log_events(ts_ms);
                CREATE INDEX log_events_origin ON log_events(origin, ts_ms);
                CREATE INDEX log_events_source ON log_events(source, ts_ms);
                -- Journal cursors are unique, so a crash between the row insert
                -- and the cursor checkpoint cannot create a duplicate on resume.
                CREATE UNIQUE INDEX log_events_cursor ON log_events(cursor)
                    WHERE cursor IS NOT NULL;

                CREATE TABLE log_state (
                    key           TEXT PRIMARY KEY,
                    value_json    TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );
                "#,
            )?;
        }
        if current < 3 {
            tx.execute_batch(
                r#"
                ALTER TABLE blocks ADD COLUMN rule_id INTEGER;

                CREATE TABLE rules (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    name          TEXT    NOT NULL,
                    enabled       INTEGER NOT NULL DEFAULT 1,
                    priority      INTEGER NOT NULL DEFAULT 100,
                    severity      TEXT    NOT NULL DEFAULT 'info',
                    revision      INTEGER NOT NULL DEFAULT 1,
                    rule_json     TEXT    NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    updated_by    TEXT    NOT NULL DEFAULT ''
                );
                CREATE INDEX rules_order ON rules(priority DESC, id ASC);

                CREATE TABLE rule_revisions (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id       INTEGER NOT NULL,
                    revision      INTEGER NOT NULL,
                    changed_at_ms INTEGER NOT NULL,
                    changed_by    TEXT    NOT NULL DEFAULT '',
                    action        TEXT    NOT NULL,
                    note          TEXT    NOT NULL DEFAULT '',
                    document_json TEXT    NOT NULL
                );
                CREATE INDEX rule_revisions_rule ON rule_revisions(rule_id, changed_at_ms);

                CREATE TABLE rules_meta (
                    key           TEXT PRIMARY KEY,
                    value_json    TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );
                "#,
            )?;
        }
        if current < 5 {
            tx.execute_batch(
                r#"
                -- Asynchronous, persisted webhook queue (FR-204a).
                CREATE TABLE alert_queue (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at_ms   INTEGER NOT NULL,
                    next_attempt_ms INTEGER NOT NULL,
                    attempts        INTEGER NOT NULL DEFAULT 0,
                    state           TEXT NOT NULL DEFAULT 'pending',
                    dedupe_key      TEXT NOT NULL UNIQUE,
                    payload_json    TEXT NOT NULL,
                    last_error      TEXT NOT NULL DEFAULT '',
                    delivered_at_ms INTEGER
                );
                CREATE INDEX alert_queue_due ON alert_queue(state, next_attempt_ms);

                -- Long-term daily aggregates survive raw-detection pruning.
                CREATE TABLE detection_daily (
                    day      TEXT NOT NULL,
                    detector TEXT NOT NULL,
                    count    INTEGER NOT NULL,
                    PRIMARY KEY(day, detector)
                );
                "#,
            )?;
        }
        if current < 6 {
            tx.execute_batch(
                r#"
                CREATE TABLE alert_targets (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT NOT NULL UNIQUE,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    url             TEXT NOT NULL,
                    events          TEXT NOT NULL DEFAULT 'all',
                    min_severity    TEXT NOT NULL DEFAULT 'warning',
                    timeout_secs    INTEGER NOT NULL DEFAULT 5,
                    max_retries     INTEGER NOT NULL DEFAULT 5,
                    rate_limit_secs INTEGER NOT NULL DEFAULT 60,
                    queue_max       INTEGER NOT NULL DEFAULT 1000,
                    created_at_ms   INTEGER NOT NULL,
                    updated_at_ms   INTEGER NOT NULL,
                    updated_by      TEXT NOT NULL DEFAULT ''
                );
                ALTER TABLE alert_queue ADD COLUMN target_id INTEGER;
                CREATE INDEX alert_queue_target ON alert_queue(target_id);
                "#,
            )?;
        }
        if current < 7 {
            tx.execute_batch(
                r#"
                ALTER TABLE log_events ADD COLUMN method TEXT;
                ALTER TABLE log_events ADD COLUMN path TEXT;
                ALTER TABLE log_events ADD COLUMN status INTEGER;
                "#,
            )?;
        }
        if current < 10 {
            tx.execute_batch(
                r#"
                CREATE TABLE system_samples (
                    ts_ms   INTEGER PRIMARY KEY,
                    cpu_pct REAL NOT NULL,
                    rss_mb  REAL NOT NULL,
                    db_mb   REAL NOT NULL
                );
                "#,
            )?;
        }
        if current < 12 {
            tx.execute_batch(
                r#"
                CREATE TABLE firewall_admin_rules (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    src           TEXT,
                    dst           TEXT,
                    proto         TEXT NOT NULL,
                    port          INTEGER,
                    enabled       INTEGER NOT NULL DEFAULT 1,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    created_by    TEXT NOT NULL DEFAULT '',
                    updated_by    TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE firewall_services (
                    proto          TEXT NOT NULL,
                    port           INTEGER NOT NULL,
                    addr           TEXT NOT NULL DEFAULT '',
                    first_seen_ms  INTEGER NOT NULL,
                    last_seen_ms   INTEGER NOT NULL,
                    dropped        INTEGER NOT NULL DEFAULT 0,
                    acknowledged   INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (proto, port, addr)
                );
                CREATE INDEX firewall_services_last_seen ON firewall_services(last_seen_ms);
                "#,
            )?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        if current < 3 {
            // A default set preserves the hard-coded 0.3.0 disposition policy
            // and satisfies FR-128. Later edits replace it through the UI/CLI.
            self.seed_rules_if_empty()?;
        }
        if current < 4 {
            // Data-only migration: give an existing 0.3.1 rule set a rule for
            // the new packet HTTP detectors. Fresh installs already have it in
            // the shipped packet rule, so this is a no-op there.
            let _ = self.ensure_http_rule()?;
        }
        if current < 5 {
            // Data-only migration for the 0.3.3 slow-scan detector.
            let _ = self.ensure_slow_scan_rule()?;
        }
        if current < 7 {
            // Data-only migration for the 0.3.4 HTTP access-log detector.
            let _ = self.ensure_http_log_rule()?;
        }
        if current < 8 {
            // Data-only migration for the 0.3.10 honeypot detector.
            let _ = self.ensure_honeypot_rule()?;
        }
        if current < 9 {
            // Retired internal detectors are no longer emitted; remove them
            // from stored rule match lists so the UI matches the catalog.
            let _ = self.strip_retired_detectors()?;
        }
        if current < 11 {
            // Data-only migration for the optional service firewall detector.
            let _ = self.ensure_firewall_rule()?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- detections

    pub fn insert_detection(&self, det: &Detection) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO detections
             (ts_ms, last_seen_ms, detector, src, dst, dst_port, proto, count, window_s, metadata_json, evidence_log_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                ms(det.first_seen),
                ms(det.last_seen),
                det.detector.as_str(),
                det.src.to_string(),
                det.dst.map(|d| d.to_string()),
                det.dst_port,
                det.proto.as_str(),
                det.count as i64,
                det.window_secs as i64,
                det.metadata.to_string(),
                det.evidence_log_id,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn detection_count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM detections", [], |r| r.get(0))?)
    }

    pub fn recent_detections(&self, limit: u32) -> Result<Vec<Detection>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts_ms, last_seen_ms, detector, src, dst, dst_port, proto, count, window_s, metadata_json, evidence_log_id
             FROM detections ORDER BY ts_ms DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], detection_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All stored detections for one source, newest first.
    pub fn detections_for_src(&self, src: IpAddr, limit: u32) -> Result<Vec<Detection>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts_ms, last_seen_ms, detector, src, dst, dst_port, proto, count, window_s, metadata_json, evidence_log_id
             FROM detections WHERE src = ?1 ORDER BY ts_ms DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![src.to_string(), limit], detection_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn detection_count_for_src(&self, src: IpAddr) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM detections WHERE src = ?1",
            [src.to_string()],
            |r| r.get(0),
        )?)
    }

    /// One page of detections, optionally restricted to one detector.
    pub fn detections_page(
        &self,
        limit: u32,
        offset: u32,
        detector: Option<&str>,
    ) -> Result<Vec<Detection>> {
        if let Some(detector) = detector {
            let mut stmt = self.conn.prepare(
                "SELECT id, ts_ms, last_seen_ms, detector, src, dst, dst_port, proto, count, window_s, metadata_json, evidence_log_id
                 FROM detections WHERE detector = ?3 ORDER BY ts_ms DESC LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt.query_map(params![limit, offset, detector], detection_from_row)?;
            return Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?);
        }
        let mut stmt = self.conn.prepare(
            "SELECT id, ts_ms, last_seen_ms, detector, src, dst, dst_port, proto, count, window_s, metadata_json, evidence_log_id
             FROM detections ORDER BY ts_ms DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit, offset], detection_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn detection_count_filtered(&self, detector: Option<&str>) -> Result<i64> {
        match detector {
            Some(detector) => Ok(self.conn.query_row(
                "SELECT COUNT(*) FROM detections WHERE detector = ?1",
                [detector],
                |r| r.get(0),
            )?),
            None => self.detection_count(),
        }
    }

    /// Detections recorded since `since`, for the dashboard counter.
    pub fn detections_since(&self, since: DateTime<Utc>) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM detections WHERE ts_ms >= ?1",
            [ms(since)],
            |r| r.get(0),
        )?)
    }

    /// Blocks started since `since`, for the dashboard counter.
    pub fn blocks_since(&self, since: DateTime<Utc>) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM blocks WHERE started_at_ms >= ?1",
            [ms(since)],
            |r| r.get(0),
        )?)
    }

    pub fn top_sources(&self, since: DateTime<Utc>, limit: u32) -> Result<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT src, COUNT(*) AS n FROM detections WHERE ts_ms >= ?1
             GROUP BY src ORDER BY n DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![ms(since), limit], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn top_ports(&self, since: DateTime<Utc>, limit: u32) -> Result<Vec<(i64, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT dst_port, COUNT(*) AS n FROM detections
             WHERE ts_ms >= ?1 AND dst_port IS NOT NULL
             GROUP BY dst_port ORDER BY n DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![ms(since), limit], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    // -------------------------------------------------------------------- blocks

    pub fn active_block(&self, src: IpAddr) -> Result<Option<Block>> {
        let block = self
            .conn
            .query_row(
                "SELECT id, src, reason, detector, detection_id, started_at_ms, expires_at_ms, state, strike, rule_id
                 FROM blocks WHERE src = ?1 AND state = 'active'",
                [src.to_string()],
                block_from_row,
            )
            .optional()?;
        Ok(block)
    }

    /// Insert a new block or extend the existing one (FR-134). Extension is
    /// idempotent: the longer expiry wins and permanence is absorbing.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_block(
        &self,
        src: IpAddr,
        duration: BlockDuration,
        strike: u32,
        reason: &str,
        detector: Option<Detector>,
        detection_id: Option<i64>,
        now: DateTime<Utc>,
    ) -> Result<(Block, bool)> {
        self.upsert_block_with_rule(
            src,
            duration,
            strike,
            reason,
            detector,
            detection_id,
            None,
            now,
        )
    }

    /// As [`Db::upsert_block`], with the disposition rule recorded on the row.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_block_with_rule(
        &self,
        src: IpAddr,
        duration: BlockDuration,
        strike: u32,
        reason: &str,
        detector: Option<Detector>,
        detection_id: Option<i64>,
        rule_id: Option<u32>,
        now: DateTime<Utc>,
    ) -> Result<(Block, bool)> {
        if let Some(existing) = self.active_block(src)? {
            let new_expiry = match (existing.expires_at, duration) {
                (None, _) | (_, BlockDuration::Permanent) => None,
                (Some(old), BlockDuration::Temporary(secs)) => {
                    let candidate = now + chrono::Duration::seconds(secs);
                    Some(old.max(candidate))
                }
            };
            self.conn.execute(
                "UPDATE blocks SET expires_at_ms = ?1, strike = MAX(strike, ?2), reason = ?3,
                                   detector = COALESCE(?4, detector),
                                   rule_id = COALESCE(?5, rule_id)
                 WHERE id = ?6",
                params![
                    new_expiry.map(ms),
                    strike as i64,
                    reason,
                    detector.map(|d| d.as_str()),
                    rule_id,
                    existing.id
                ],
            )?;
            let mut updated = existing;
            updated.expires_at = new_expiry;
            updated.rule_id = rule_id.or(updated.rule_id);
            updated.strike = updated.strike.max(strike);
            updated.reason = reason.to_string();
            return Ok((updated, false));
        }

        let expires = duration.secs().map(|s| now + chrono::Duration::seconds(s));
        self.conn.execute(
            "INSERT INTO blocks
             (src, ip_version, reason, detector, detection_id, started_at_ms, expires_at_ms, state, strike, enforced, rule_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, 0, ?9)",
            params![
                src.to_string(),
                if src.is_ipv4() { 4 } else { 6 },
                reason,
                detector.map(|d| d.as_str()),
                detection_id,
                ms(now),
                expires.map(ms),
                strike as i64,
                rule_id,
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        Ok((
            Block {
                id,
                src,
                reason: reason.to_string(),
                detector,
                detection_id,
                rule_id,
                started_at: now,
                expires_at: expires,
                state: BlockState::Active,
                strike,
            },
            true,
        ))
    }

    pub fn mark_block_state(&self, id: i64, state: BlockState) -> Result<()> {
        self.conn.execute(
            "UPDATE blocks SET state = ?1 WHERE id = ?2",
            params![state.as_str(), id],
        )?;
        Ok(())
    }

    /// Used by `flush`: every active block becomes manual-unblocked.
    pub fn unblock_all(&self) -> Result<usize> {
        let n = self.conn.execute(
            "UPDATE blocks SET state = 'manual_unblocked' WHERE state = 'active'",
            [],
        )?;
        Ok(n)
    }

    pub fn set_enforced(&self, id: i64, enforced: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE blocks SET enforced = ?1 WHERE id = ?2",
            params![i64::from(enforced), id],
        )?;
        Ok(())
    }

    pub fn list_active_blocks(&self) -> Result<Vec<Block>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, src, reason, detector, detection_id, started_at_ms, expires_at_ms, state, strike, rule_id
             FROM blocks WHERE state = 'active' ORDER BY started_at_ms DESC",
        )?;
        let rows = stmt.query_map([], block_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Active blocks that were recorded but never applied (nftables was
    /// unavailable when the decision was made). The scheduler retries these.
    pub fn list_unenforced(&self) -> Result<Vec<Block>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, src, reason, detector, detection_id, started_at_ms, expires_at_ms, state, strike, rule_id
             FROM blocks WHERE state = 'active' AND enforced = 0 ORDER BY started_at_ms ASC",
        )?;
        let rows = stmt.query_map([], block_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn list_block_history(&self, limit: u32) -> Result<Vec<Block>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, src, reason, detector, detection_id, started_at_ms, expires_at_ms, state, strike, rule_id
             FROM blocks ORDER BY started_at_ms DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], block_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All stored blocks for one source, newest first.
    pub fn blocks_for_src(&self, src: IpAddr, limit: u32) -> Result<Vec<Block>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, src, reason, detector, detection_id, started_at_ms, expires_at_ms, state, strike, rule_id
             FROM blocks WHERE src = ?1 ORDER BY started_at_ms DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![src.to_string(), limit], block_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn block_count_for_src(&self, src: IpAddr) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM blocks WHERE src = ?1",
            [src.to_string()],
            |r| r.get(0),
        )?)
    }

    /// Blocks whose expiry has passed. Used by the scheduler and at startup to
    /// report overdue blocks from an outage (FR-145).
    pub fn expired_blocks(&self, now: DateTime<Utc>, limit: u32) -> Result<Vec<Block>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, src, reason, detector, detection_id, started_at_ms, expires_at_ms, state, strike, rule_id
             FROM blocks WHERE state = 'active' AND expires_at_ms IS NOT NULL AND expires_at_ms <= ?1
             ORDER BY expires_at_ms ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![ms(now), limit], block_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn active_block_count(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM blocks WHERE state = 'active'",
            [],
            |r| r.get(0),
        )?)
    }

    // ------------------------------------------------------------------- strikes

    pub fn bump_strike(&self, src: IpAddr, reason: &str, now: DateTime<Utc>) -> Result<u32> {
        self.conn.execute(
            "INSERT INTO strikes (src, count, first_seen_ms, last_seen_ms, last_reason)
             VALUES (?1, 1, ?2, ?2, ?3)
             ON CONFLICT(src) DO UPDATE SET
                 count = count + 1,
                 last_seen_ms = ?2,
                 last_reason = ?3",
            params![src.to_string(), ms(now), reason],
        )?;
        self.strike_count(src)
    }

    pub fn strike_count(&self, src: IpAddr) -> Result<u32> {
        let count: Option<i64> = self
            .conn
            .query_row(
                "SELECT count FROM strikes WHERE src = ?1",
                [src.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(count.unwrap_or(0).max(0) as u32)
    }

    /// Last time the source was struck, for rule history conditions.
    pub fn strike_last_seen(&self, src: IpAddr) -> Result<Option<DateTime<Utc>>> {
        let last: Option<i64> = self
            .conn
            .query_row(
                "SELECT last_seen_ms FROM strikes WHERE src = ?1",
                [src.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(last.map(from_ms))
    }

    pub fn reset_strike(&self, src: IpAddr) -> Result<()> {
        self.conn
            .execute("DELETE FROM strikes WHERE src = ?1", [src.to_string()])?;
        Ok(())
    }

    /// Restore an exact strike count (used by import).
    pub fn set_strike(
        &self,
        src: IpAddr,
        count: u32,
        last_seen: DateTime<Utc>,
        reason: &str,
    ) -> Result<()> {
        if count == 0 {
            return self.reset_strike(src);
        }
        self.conn.execute(
            "INSERT INTO strikes (src, count, first_seen_ms, last_seen_ms, last_reason)
             VALUES (?1, ?2, ?3, ?3, ?4)
             ON CONFLICT(src) DO UPDATE SET count = ?2, last_seen_ms = ?3, last_reason = ?4",
            params![src.to_string(), count as i64, ms(last_seen), reason],
        )?;
        Ok(())
    }

    pub fn list_strikes(&self) -> Result<Vec<Strike>> {
        let mut stmt = self.conn.prepare(
            "SELECT src, count, first_seen_ms, last_seen_ms, last_reason FROM strikes ORDER BY last_seen_ms DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Strike {
                src: r
                    .get::<_, String>(0)?
                    .parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                count: r.get::<_, i64>(1)?.max(0) as u32,
                first_seen: from_ms(r.get(2)?),
                last_seen: from_ms(r.get(3)?),
                last_reason: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn strike_for_src(&self, src: IpAddr) -> Result<Option<Strike>> {
        let strike = self
            .conn
            .query_row(
                "SELECT src, count, first_seen_ms, last_seen_ms, last_reason
                 FROM strikes WHERE src = ?1",
                [src.to_string()],
                |r| {
                    Ok(Strike {
                        src: r
                            .get::<_, String>(0)?
                            .parse()
                            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                        count: r.get::<_, i64>(1)?.max(0) as u32,
                        first_seen: from_ms(r.get(2)?),
                        last_seen: from_ms(r.get(3)?),
                        last_reason: r.get(4)?,
                    })
                },
            )
            .optional()?;
        Ok(strike)
    }

    pub fn count_strikes(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM strikes", [], |r| r.get(0))?)
    }

    /// Decay one strike for sources that have been clean for `days`.
    pub fn decay_strikes(&self, days: u64, now: DateTime<Utc>) -> Result<usize> {
        let cutoff = ms(now) - (days as i64) * 86_400_000;
        let n = self.conn.execute(
            "UPDATE strikes SET count = count - 1, last_seen_ms = ?1
             WHERE count > 0 AND last_seen_ms < ?2",
            params![ms(now), cutoff],
        )?;
        self.conn
            .execute("DELETE FROM strikes WHERE count <= 0", [])?;
        Ok(n)
    }

    // ----------------------------------------------------------------- allowlist

    pub fn add_allowlist(&self, cidr: &Cidr, label: &str, implicit: bool, by: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO allowlist (cidr, label, implicit, created_at_ms, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(cidr) DO UPDATE SET label = excluded.label",
            params![
                cidr.to_string(),
                label,
                i64::from(implicit),
                ms(Utc::now()),
                by
            ],
        )?;
        Ok(())
    }

    /// Remove an entry. Implicit entries cannot be removed (FR-154).
    pub fn remove_allowlist(&self, cidr: &str) -> Result<bool> {
        let implicit: Option<i64> = self
            .conn
            .query_row(
                "SELECT implicit FROM allowlist WHERE cidr = ?1",
                [cidr],
                |r| r.get(0),
            )
            .optional()?;
        match implicit {
            None => Ok(false),
            Some(1) => Err(crate::error::Error::Invalid(
                "this entry is implicit and cannot be removed".into(),
            )),
            Some(_) => {
                self.conn
                    .execute("DELETE FROM allowlist WHERE cidr = ?1", [cidr])?;
                Ok(true)
            }
        }
    }

    pub fn list_allowlist(&self) -> Result<Vec<AllowlistEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, cidr, label, implicit, created_at_ms, created_by
             FROM allowlist ORDER BY implicit DESC, cidr",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AllowlistEntry {
                id: row.get(0)?,
                cidr: row.get(1)?,
                label: row.get(2)?,
                implicit: row.get::<_, i64>(3)? != 0,
                created_at: from_ms(row.get(4)?),
                created_by: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Seed the implicit set: loopback, RFC1918, link-local and the host's own
    /// addresses. Idempotent; runs at every start so a moved host is covered.
    pub fn seed_implicit_allowlist(&self) -> Result<()> {
        let mut entries: Vec<Cidr> = vec![
            Cidr::parse("127.0.0.0/8").unwrap(),
            Cidr::parse("::1/128").unwrap(),
            Cidr::parse("10.0.0.0/8").unwrap(),
            Cidr::parse("172.16.0.0/12").unwrap(),
            Cidr::parse("192.168.0.0/16").unwrap(),
            Cidr::parse("169.254.0.0/16").unwrap(),
            Cidr::parse("fe80::/10").unwrap(),
            Cidr::parse("fc00::/7").unwrap(),
        ];
        for ip in net::host_addresses() {
            let cidr = if ip.is_ipv4() {
                Cidr {
                    addr: ip,
                    prefix: 32,
                }
            } else {
                Cidr {
                    addr: ip,
                    prefix: 128,
                }
            };
            entries.push(cidr);
        }
        for cidr in entries {
            self.add_allowlist(&cidr, "implicit", true, "system")?;
        }
        Ok(())
    }

    /// Load the allowlist as a matcher, including the implicit set even if the
    /// table was tampered with.
    pub fn allowlist_matcher(&self) -> Result<Vec<Cidr>> {
        let mut out = Vec::new();
        for entry in self.list_allowlist()? {
            if let Ok(c) = Cidr::parse(&entry.cidr) {
                out.push(c);
            }
        }
        Ok(out)
    }

    // --------------------------------------------------------------------- audit

    pub fn audit(&self, actor: &Actor, action: &str, subject: &str, detail: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit (ts_ms, actor, action, subject, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ms(Utc::now()), actor.as_str(), action, subject, detail],
        )?;
        Ok(())
    }

    pub fn recent_audit(&self, limit: u32) -> Result<Vec<AuditRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts_ms, actor, action, subject FROM audit ORDER BY ts_ms DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            Ok((from_ms(r.get(0)?), r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn recent_audit_full(&self, limit: u32) -> Result<Vec<AuditDetailRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts_ms, actor, action, subject, detail FROM audit ORDER BY ts_ms DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            Ok((
                from_ms(r.get(0)?),
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
            ))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    // ------------------------------------------------------------------ settings

    pub fn set_setting(&self, key: &str, value: &serde_json::Value) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value_json, updated_at_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                            updated_at_ms = excluded.updated_at_ms",
            params![key, value.to_string(), ms(Utc::now())],
        )?;
        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<serde_json::Value>> {
        let v: Option<String> = self
            .conn
            .query_row(
                "SELECT value_json FROM settings WHERE key = ?1",
                [key],
                |r| r.get(0),
            )
            .optional()?;
        Ok(v.and_then(|s| serde_json::from_str(&s).ok()))
    }

    /// Remove a UI override so the config file / built-in default applies.
    pub fn delete_setting(&self, key: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM settings WHERE key = ?1", [key])?;
        Ok(())
    }

    pub fn list_settings(&self) -> Result<Vec<(String, serde_json::Value)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value_json FROM settings ORDER BY key")?;
        let rows = stmt.query_map([], |r| {
            let key: String = r.get(0)?;
            let raw: String = r.get(1)?;
            Ok((
                key,
                serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null),
            ))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    // --------------------------------------------------------------- log events

    /// Insert one normalised event. Returns `None` when the journal cursor was
    /// already stored (a restart race), so detection cannot run twice.
    pub fn insert_log_event(&self, event: &LogEvent) -> Result<Option<i64>> {
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO log_events
             (ts_ms, origin, source, unit, identifier, priority, host, pid, user, service,
              src_ip, action, outcome, method, path, status, template, message, cursor, parser)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                ms(event.ts),
                event.origin.as_str(),
                event.source,
                event.unit,
                event.identifier,
                event.priority,
                event.host,
                event.pid,
                event.user,
                event.service,
                event.src_ip.map(|ip| ip.to_string()),
                event.action,
                event.outcome,
                event.method,
                event.path,
                event.status.map(|status| status as i64),
                event.template,
                event.message,
                event.cursor,
                event.parser,
            ],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        Ok(Some(self.conn.last_insert_rowid()))
    }

    pub fn recent_log_events(&self, limit: u32) -> Result<Vec<(LogEvent, Option<String>)>> {
        self.log_events_page(limit, 0, None, None)
    }

    pub fn log_event_count(&self, origin: Option<&str>, search: Option<&str>) -> Result<i64> {
        let pattern = search_pattern(search);
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM log_events
             WHERE (?1 IS NULL OR origin = ?1)
               AND (?2 IS NULL OR unit LIKE ?2 ESCAPE '\\'
                    OR identifier LIKE ?2 ESCAPE '\\'
                    OR source LIKE ?2 ESCAPE '\\'
                    OR template LIKE ?2 ESCAPE '\\'
                    OR message LIKE ?2 ESCAPE '\\')",
            params![origin, pattern],
            |r| r.get(0),
        )?)
    }

    /// One page of the Logs view. The second tuple element is the detector of
    /// the resulting detection, when this event produced one.
    pub fn log_events_page(
        &self,
        limit: u32,
        offset: u32,
        origin: Option<&str>,
        search: Option<&str>,
    ) -> Result<Vec<(LogEvent, Option<String>)>> {
        let pattern = search_pattern(search);
        let mut stmt = self.conn.prepare(
            "SELECT l.id, l.ts_ms, l.origin, l.source, l.unit, l.identifier, l.priority,
                    l.host, l.pid, l.user, l.service, l.src_ip, l.action, l.outcome,
                    l.method, l.path, l.status, l.template, l.message, l.cursor, l.parser,
                    (SELECT d.detector FROM detections d
                     WHERE d.evidence_log_id = l.id LIMIT 1)
             FROM log_events l
             WHERE (?1 IS NULL OR l.origin = ?1)
               AND (?2 IS NULL OR l.unit LIKE ?2 ESCAPE '\\'
                    OR l.identifier LIKE ?2 ESCAPE '\\'
                    OR l.source LIKE ?2 ESCAPE '\\'
                    OR l.template LIKE ?2 ESCAPE '\\'
                    OR l.message LIKE ?2 ESCAPE '\\')
             ORDER BY l.ts_ms DESC, l.id DESC
             LIMIT ?3 OFFSET ?4",
        )?;
        let rows = stmt.query_map(params![origin, pattern, limit, offset], log_event_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All stored log events for one source, newest first.
    pub fn log_events_for_src(
        &self,
        src: IpAddr,
        limit: u32,
    ) -> Result<Vec<(LogEvent, Option<String>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT l.id, l.ts_ms, l.origin, l.source, l.unit, l.identifier, l.priority,
                    l.host, l.pid, l.user, l.service, l.src_ip, l.action, l.outcome,
                    l.method, l.path, l.status, l.template, l.message, l.cursor, l.parser,
                    (SELECT d.detector FROM detections d
                     WHERE d.evidence_log_id = l.id LIMIT 1)
             FROM log_events l
             WHERE l.src_ip = ?1
             ORDER BY l.ts_ms DESC, l.id DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![src.to_string(), limit], log_event_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn log_event_count_for_src(&self, src: IpAddr) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM log_events WHERE src_ip = ?1",
            [src.to_string()],
            |r| r.get(0),
        )?)
    }

    pub fn set_journal_cursor(&self, cursor: &str) -> Result<()> {
        self.set_log_state("journal.cursor", &serde_json::json!(cursor))
    }

    pub fn journal_cursor(&self) -> Result<Option<String>> {
        Ok(self
            .log_state("journal.cursor")?
            .and_then(|v| v.as_str().map(str::to_string)))
    }

    pub fn clear_journal_cursor(&self) -> Result<()> {
        self.conn
            .execute("DELETE FROM log_state WHERE key = 'journal.cursor'", [])?;
        Ok(())
    }

    pub fn set_log_state(&self, key: &str, value: &serde_json::Value) -> Result<()> {
        self.conn.execute(
            "INSERT INTO log_state (key, value_json, updated_at_ms) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                            updated_at_ms = excluded.updated_at_ms",
            params![key, value.to_string(), ms(Utc::now())],
        )?;
        Ok(())
    }

    pub fn log_state(&self, key: &str) -> Result<Option<serde_json::Value>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value_json FROM log_state WHERE key = ?1",
                [key],
                |r| r.get(0),
            )
            .optional()?;
        Ok(raw.and_then(|s| serde_json::from_str(&s).ok()))
    }

    pub fn list_log_state(&self) -> Result<Vec<(String, serde_json::Value)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value_json FROM log_state ORDER BY key")?;
        let rows = stmt.query_map([], |r| {
            let key: String = r.get(0)?;
            let raw: String = r.get(1)?;
            Ok((
                key,
                serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null),
            ))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Prune raw events by age, then by approximate stored bytes (FR-306).
    pub fn prune_logs(&self, days: u64, max_bytes: u64, now: DateTime<Utc>) -> Result<usize> {
        let cutoff = ms(now) - (days as i64) * 86_400_000;
        let mut deleted = self
            .conn
            .execute("DELETE FROM log_events WHERE ts_ms < ?1", [cutoff])?;
        let bytes: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(length(message) + length(template) + length(source)
                                  + length(COALESCE(cursor, '')) + 64), 0)
             FROM log_events",
            [],
            |r| r.get(0),
        )?;
        if bytes > max_bytes as i64 {
            let count: i64 = self
                .conn
                .query_row("SELECT COUNT(*) FROM log_events", [], |r| r.get(0))?;
            let average = (bytes / count.max(1)).max(1);
            let excess = bytes - max_bytes as i64;
            let remove = ((excess / average) + 1).min(count);
            deleted += self.conn.execute(
                "DELETE FROM log_events WHERE id IN
                 (SELECT id FROM log_events ORDER BY id ASC LIMIT ?1)",
                [remove],
            )?;
        }
        Ok(deleted)
    }

    // ---------------------------------------------------------------------- rules

    pub fn list_rules(&self) -> Result<Vec<Rule>> {
        let mut stmt = self
            .conn
            .prepare("SELECT rule_json FROM rules ORDER BY priority DESC, id ASC")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let raw = row?;
            let rule: Rule = serde_json::from_str(&raw)
                .map_err(|e| crate::error::Error::Config(format!("stored rule is invalid: {e}")))?;
            out.push(rule);
        }
        Ok(out)
    }

    pub fn get_rule(&self, id: u32) -> Result<Option<Rule>> {
        let raw: Option<String> = self
            .conn
            .query_row("SELECT rule_json FROM rules WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        match raw {
            Some(raw) => serde_json::from_str(&raw).map(Some).map_err(|e| {
                crate::error::Error::Config(format!("stored rule {id} is invalid: {e}"))
            }),
            None => Ok(None),
        }
    }

    pub fn enabled_rule_count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM rules WHERE enabled = 1", [], |r| {
                r.get(0)
            })?)
    }

    /// Insert or update one rule and append a revision (FR-120).
    pub fn save_rule(&self, rule: &Rule, by: &str, note: &str) -> Result<Rule> {
        let mut stored = rule.clone();
        let existing: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT revision, enabled FROM rules WHERE id = ?1",
                [stored.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((_, enabled)) = existing {
            if enabled != 0 && !stored.enabled && self.enabled_rule_count()? <= 1 {
                return Err(crate::error::Error::Invalid(
                    "cannot disable the last enabled rule".into(),
                ));
            }
        }
        let revision = existing.map(|(r, _)| r as u32 + 1).unwrap_or(1);
        let now = Utc::now();
        let tx = self.conn.unchecked_transaction()?;
        if existing.is_some() {
            tx.execute(
                "UPDATE rules SET name = ?1, enabled = ?2, priority = ?3, severity = ?4,
                                  revision = ?5, rule_json = ?6, updated_at_ms = ?7, updated_by = ?8
                 WHERE id = ?9",
                params![
                    stored.name,
                    stored.enabled as i64,
                    stored.priority as i64,
                    stored.severity.as_str(),
                    revision as i64,
                    serde_json::to_string(&stored)?,
                    ms(now),
                    by,
                    stored.id,
                ],
            )?;
        } else {
            tx.execute(
                "INSERT INTO rules
                 (name, enabled, priority, severity, revision, rule_json, updated_at_ms, updated_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    stored.name,
                    stored.enabled as i64,
                    stored.priority as i64,
                    stored.severity.as_str(),
                    revision as i64,
                    serde_json::to_string(&stored)?,
                    ms(now),
                    by,
                ],
            )?;
            stored.id = tx.last_insert_rowid().max(0) as u32;
            tx.execute(
                "UPDATE rules SET rule_json = ?1 WHERE id = ?2",
                params![serde_json::to_string(&stored)?, stored.id],
            )?;
        }
        tx.execute(
            "INSERT INTO rule_revisions
             (rule_id, revision, changed_at_ms, changed_by, action, note, document_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                stored.id,
                revision as i64,
                ms(now),
                by,
                if existing.is_some() {
                    "update"
                } else {
                    "create"
                },
                note,
                serde_json::to_string(&stored)?,
            ],
        )?;
        Self::bump_rules_version_tx(&tx, now)?;
        tx.commit()?;
        Ok(stored)
    }

    /// Delete a rule, refusing to remove the last enabled one (FR-126).
    pub fn delete_rule(&self, id: u32, by: &str) -> Result<bool> {
        let rule = match self.get_rule(id)? {
            Some(rule) => rule,
            None => return Ok(false),
        };
        if rule.enabled && self.enabled_rule_count()? <= 1 {
            return Err(crate::error::Error::Invalid(
                "cannot delete the last enabled rule".into(),
            ));
        }
        let revision: i64 = self
            .conn
            .query_row("SELECT revision FROM rules WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(0);
        let now = Utc::now();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM rules WHERE id = ?1", [id])?;
        tx.execute(
            "INSERT INTO rule_revisions
             (rule_id, revision, changed_at_ms, changed_by, action, note, document_json)
             VALUES (?1, ?2, ?3, ?4, 'delete', '', ?5)",
            params![id, revision + 1, ms(now), by, serde_json::to_string(&rule)?,],
        )?;
        Self::bump_rules_version_tx(&tx, now)?;
        tx.commit()?;
        Ok(true)
    }

    /// Replace the whole rule set (import). The caller must validate first.
    pub fn replace_rules(&self, rules: &[Rule], by: &str, note: &str) -> Result<()> {
        if rules.is_empty() {
            return Err(crate::error::Error::Invalid(
                "an imported rule set needs at least one rule".into(),
            ));
        }
        let now = Utc::now();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM rules", [])?;
        for candidate in rules {
            let mut stored = candidate.clone();
            let revision: i64 = tx.query_row(
                "SELECT COALESCE(MAX(revision), 0) + 1 FROM rule_revisions WHERE rule_id = ?1",
                [stored.id],
                |r| r.get(0),
            )?;
            if stored.id == 0 {
                tx.execute(
                    "INSERT INTO rules
                     (name, enabled, priority, severity, revision, rule_json, updated_at_ms, updated_by)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        stored.name,
                        stored.enabled as i64,
                        stored.priority as i64,
                        stored.severity.as_str(),
                        revision,
                        serde_json::to_string(&stored)?,
                        ms(now),
                        by,
                    ],
                )?;
                stored.id = tx.last_insert_rowid().max(0) as u32;
                tx.execute(
                    "UPDATE rules SET rule_json = ?1 WHERE id = ?2",
                    params![serde_json::to_string(&stored)?, stored.id],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO rules
                     (id, name, enabled, priority, severity, revision, rule_json, updated_at_ms, updated_by)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        stored.id,
                        stored.name,
                        stored.enabled as i64,
                        stored.priority as i64,
                        stored.severity.as_str(),
                        revision,
                        serde_json::to_string(&stored)?,
                        ms(now),
                        by,
                    ],
                )?;
                tx.execute(
                    "UPDATE rules SET rule_json = ?1 WHERE id = ?2",
                    params![serde_json::to_string(&stored)?, stored.id],
                )?;
            }
            tx.execute(
                "INSERT INTO rule_revisions
                 (rule_id, revision, changed_at_ms, changed_by, action, note, document_json)
                 VALUES (?1, ?2, ?3, ?4, 'import', ?5, ?6)",
                params![
                    stored.id,
                    revision,
                    ms(now),
                    by,
                    note,
                    serde_json::to_string(&stored)?,
                ],
            )?;
        }
        Self::bump_rules_version_tx(&tx, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Insert sample/informational rules whose names are not already present.
    /// The samples are disabled; repeated clicks do not create duplicates.
    pub fn add_rules_if_missing(&self, rules: &[Rule], by: &str, note: &str) -> Result<usize> {
        let existing: std::collections::HashSet<String> = self
            .list_rules()?
            .into_iter()
            .map(|rule| rule.name)
            .collect();
        let mut added = 0;
        for rule in rules {
            if existing.contains(&rule.name) {
                continue;
            }
            let mut copy = rule.clone();
            copy.id = 0;
            self.save_rule(&copy, by, note)?;
            added += 1;
        }
        Ok(added)
    }

    pub fn rule_revisions(&self, rule_id: Option<u32>, limit: u32) -> Result<Vec<RuleRevision>> {
        let mut out = Vec::new();
        match rule_id {
            Some(id) => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, rule_id, revision, changed_at_ms, changed_by, action, note, document_json
                     FROM rule_revisions WHERE rule_id = ?1 ORDER BY revision DESC LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![id, limit], revision_from_row)?;
                for row in rows {
                    out.push(row?);
                }
            }
            None => {
                let mut stmt = self.conn.prepare(
                    "SELECT id, rule_id, revision, changed_at_ms, changed_by, action, note, document_json
                     FROM rule_revisions ORDER BY changed_at_ms DESC, id DESC LIMIT ?1",
                )?;
                let rows = stmt.query_map([limit], revision_from_row)?;
                for row in rows {
                    out.push(row?);
                }
            }
        }
        Ok(out)
    }

    pub fn rules_version(&self) -> Result<u64> {
        let value: Option<String> = self
            .conn
            .query_row(
                "SELECT value_json FROM rules_meta WHERE key = 'rules.version'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(value
            .and_then(|raw| serde_json::from_str::<u64>(&raw).ok())
            .unwrap_or(0))
    }

    fn bump_rules_version_tx(tx: &rusqlite::Transaction<'_>, now: DateTime<Utc>) -> Result<()> {
        let current: Option<String> = tx
            .query_row(
                "SELECT value_json FROM rules_meta WHERE key = 'rules.version'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let next = current
            .and_then(|raw| serde_json::from_str::<u64>(&raw).ok())
            .unwrap_or(0)
            .saturating_add(1);
        tx.execute(
            "INSERT INTO rules_meta (key, value_json, updated_at_ms) VALUES ('rules.version', ?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                            updated_at_ms = excluded.updated_at_ms",
            params![serde_json::to_string(&next)?, ms(now)],
        )?;
        Ok(())
    }

    /// Seed the shipped defaults when the table is empty (FR-128).
    /// Existing installations predate the packet HTTP detectors. Add one new
    /// rule for them unless an operator already referenced any DET-11…15.
    pub fn ensure_http_rule(&mut self) -> Result<bool> {
        self.ensure_rule_for_detectors(
            &["DET-11", "DET-12", "DET-13", "DET-14", "DET-15"],
            "HTTP detectors escalate",
            "DET-11…15 escalate through the configured ladder.",
            100,
            crate::rules::Severity::Warning,
            crate::rules::RuleAction::Escalate { ladder: Vec::new() },
            None,
            "added for 0.3.2 packet HTTP detectors",
        )
    }

    pub fn ensure_http_log_rule(&mut self) -> Result<bool> {
        self.ensure_rule_for_detectors(
            &["DET-23"],
            "HTTP access-log scan escalate",
            "DET-23 HTTP access-log path/404 scan; ladder by default.",
            200,
            crate::rules::Severity::Warning,
            crate::rules::RuleAction::Escalate { ladder: Vec::new() },
            None,
            "added for 0.3.4 HTTP access-log detector",
        )
    }

    pub fn ensure_slow_scan_rule(&mut self) -> Result<bool> {
        self.ensure_rule_for_detectors(
            &["DET-20"],
            "Slow scan alert",
            "DET-20 long-window low-rate port scan; alert only by default.",
            150,
            crate::rules::Severity::Warning,
            crate::rules::RuleAction::Alert,
            None,
            "added for 0.3.3 slow-scan detector",
        )
    }

    pub fn ensure_honeypot_rule(&mut self) -> Result<bool> {
        self.ensure_rule_for_detectors(
            &["DET-26"],
            "Honeypot block after 3 contacts",
            "DET-26: after 3 contacts to a honeypot port, block the source through the ladder.",
            250,
            crate::rules::Severity::Critical,
            crate::rules::RuleAction::Escalate { ladder: Vec::new() },
            Some(3),
            "added for 0.3.10 honeypot detector",
        )
    }

    pub fn ensure_firewall_rule(&mut self) -> Result<bool> {
        self.ensure_rule_for_detectors(
            &["DET-27"],
            "Firewall default-drop alert",
            "DET-27: the optional service firewall dropped or rejected an inbound packet. Alert only; the packet is already denied.",
            160,
            crate::rules::Severity::Warning,
            crate::rules::RuleAction::Alert,
            None,
            "added for the optional service firewall",
        )
    }

    /// Remove DET-22/24/25 from stored rule match lists after those detectors
    /// were retired. A rule whose only detectors were retired is disabled
    /// rather than becoming a catch-all.
    pub fn strip_retired_detectors(&mut self) -> Result<usize> {
        const RETIRED: [&str; 3] = ["DET-22", "DET-24", "DET-25"];
        let rules = self.list_rules()?;
        let mut changed = 0;
        for mut rule in rules {
            let before = rule.when.detectors.len();
            let kept: Vec<String> = rule
                .when
                .detectors
                .iter()
                .filter(|id| {
                    !RETIRED
                        .iter()
                        .any(|retired| id.eq_ignore_ascii_case(retired))
                })
                .cloned()
                .collect();
            if kept.len() == before {
                continue;
            }
            if kept.is_empty() {
                // Do not turn a single-retired-detector rule into a catch-all.
                continue;
            }
            rule.when.detectors = kept;
            if rule.name == "Log authentication failures" {
                rule.description = "DET-16/21/23 escalate through the configured ladder.".into();
            } else if rule.name == "Log alert-only detections" {
                rule.description = "DET-17 is visible but never auto-blocks.".into();
            }
            self.save_rule(&rule, "system", "removed retired DET-22/24/25 references")?;
            changed += 1;
        }
        Ok(changed)
    }

    /// Add one rule unless an operator already references any of `detectors`.
    /// The check and insert share an immediate transaction, so concurrent
    /// database opens cannot both add the rule.
    #[allow(clippy::too_many_arguments)]
    fn ensure_rule_for_detectors(
        &mut self,
        detectors: &[&str],
        name: &str,
        description: &str,
        priority: i32,
        severity: crate::rules::Severity,
        action: crate::rules::RuleAction,
        min_count: Option<u64>,
        note: &str,
    ) -> Result<bool> {
        let wanted: Vec<String> = detectors.iter().map(|id| (*id).to_string()).collect();
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        {
            let mut stmt = tx.prepare("SELECT rule_json FROM rules")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                let raw = row?;
                if let Ok(rule) = serde_json::from_str::<Rule>(&raw) {
                    if rule.when.detectors.iter().any(|id| wanted.contains(id)) {
                        return Ok(false);
                    }
                }
            }
        }
        let now = Utc::now();
        let mut rule = Rule {
            id: 0,
            name: name.to_string(),
            description: description.to_string(),
            enabled: true,
            priority,
            severity,
            dry_run: false,
            when: crate::rules::RuleMatch {
                detectors: wanted,
                min_count,
                ..crate::rules::RuleMatch::default()
            },
            action,
        };
        tx.execute(
            "INSERT INTO rules
             (name, enabled, priority, severity, revision, rule_json, updated_at_ms, updated_by)
             VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, 'system')",
            params![
                rule.name,
                rule.enabled as i64,
                rule.priority as i64,
                rule.severity.as_str(),
                serde_json::to_string(&rule)?,
                ms(now),
            ],
        )?;
        rule.id = tx.last_insert_rowid().max(0) as u32;
        tx.execute(
            "UPDATE rules SET rule_json = ?1 WHERE id = ?2",
            params![serde_json::to_string(&rule)?, rule.id],
        )?;
        tx.execute(
            "INSERT INTO rule_revisions
             (rule_id, revision, changed_at_ms, changed_by, action, note, document_json)
             VALUES (?1, 1, ?2, 'system', 'create', ?3, ?4)",
            params![rule.id, ms(now), note, serde_json::to_string(&rule)?],
        )?;
        Self::bump_rules_version_tx(&tx, now)?;
        tx.commit()?;
        Ok(true)
    }

    pub fn seed_rules_if_empty(&self) -> Result<()> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM rules", [], |r| r.get(0))?;
        if count > 0 {
            return Ok(());
        }
        let rules = crate::rules::default_rule_documents();
        let tx = self.conn.unchecked_transaction()?;
        let now = Utc::now();
        for rule in rules {
            tx.execute(
                "INSERT INTO rules
                 (id, name, enabled, priority, severity, revision, rule_json, updated_at_ms, updated_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, 'system')",
                params![
                    rule.id,
                    rule.name,
                    rule.enabled as i64,
                    rule.priority as i64,
                    rule.severity.as_str(),
                    serde_json::to_string(&rule)?,
                    ms(now),
                ],
            )?;
            tx.execute(
                "INSERT INTO rule_revisions
                 (rule_id, revision, changed_at_ms, changed_by, action, note, document_json)
                 VALUES (?1, 1, ?2, 'system', 'create', 'shipped default', ?3)",
                params![rule.id, ms(now), serde_json::to_string(&rule)?],
            )?;
        }
        Self::bump_rules_version_tx(&tx, now)?;
        tx.commit()?;
        Ok(())
    }

    /// Merge tags into a stored detection's metadata (rule `tag` action).
    pub fn add_detection_tags(&self, id: i64, tags: &[String]) -> Result<()> {
        if tags.is_empty() {
            return Ok(());
        }
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT metadata_json FROM detections WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(raw) = raw else { return Ok(()) };
        let mut metadata: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null);
        if !metadata.is_object() {
            metadata = serde_json::json!({});
        }
        let existing = metadata
            .get("tags")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        let mut merged: Vec<serde_json::Value> = existing;
        for tag in tags {
            if !merged
                .iter()
                .any(|value| value.as_str().map(|s| s == tag).unwrap_or(false))
            {
                merged.push(serde_json::json!(tag));
            }
        }
        if let Some(object) = metadata.as_object_mut() {
            object.insert("tags".into(), serde_json::Value::Array(merged));
        }
        self.conn.execute(
            "UPDATE detections SET metadata_json = ?1 WHERE id = ?2",
            params![metadata.to_string(), id],
        )?;
        Ok(())
    }

    // --------------------------------------------------------------------- alerts

    // ----------------------------------------------------------- alert targets

    pub fn alert_target_count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM alert_targets", [], |r| r.get(0))?)
    }

    pub fn list_alert_targets(&self) -> Result<Vec<AlertTarget>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, enabled, url, events, min_severity, timeout_secs,
                    max_retries, rate_limit_secs, queue_max, created_at_ms, updated_at_ms,
                    updated_by
             FROM alert_targets ORDER BY name ASC",
        )?;
        let rows = stmt.query_map([], target_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn enabled_alert_targets(&self) -> Result<Vec<AlertTarget>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, enabled, url, events, min_severity, timeout_secs,
                    max_retries, rate_limit_secs, queue_max, created_at_ms, updated_at_ms,
                    updated_by
             FROM alert_targets WHERE enabled = 1 ORDER BY name ASC",
        )?;
        let rows = stmt.query_map([], target_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_alert_target(&self, id: i64) -> Result<Option<AlertTarget>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, name, enabled, url, events, min_severity, timeout_secs,
                        max_retries, rate_limit_secs, queue_max, created_at_ms, updated_at_ms,
                        updated_by
                 FROM alert_targets WHERE id = ?1",
                [id],
                target_from_row,
            )
            .optional()?)
    }

    pub fn save_alert_target(&self, target: &AlertTarget, by: &str) -> Result<AlertTarget> {
        let now = Utc::now();
        let tx = self.conn.unchecked_transaction()?;
        let mut stored = target.clone();
        stored.updated_at = now;
        stored.updated_by = by.to_string();
        if stored.id == 0 {
            tx.execute(
                "INSERT INTO alert_targets
                 (name, enabled, url, events, min_severity, timeout_secs, max_retries,
                  rate_limit_secs, queue_max, created_at_ms, updated_at_ms, updated_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11)",
                params![
                    stored.name,
                    stored.enabled as i64,
                    stored.url,
                    stored.events,
                    stored.min_severity,
                    stored.timeout_secs as i64,
                    stored.max_retries as i64,
                    stored.rate_limit_secs as i64,
                    stored.queue_max as i64,
                    ms(now),
                    by,
                ],
            )?;
            stored.id = tx.last_insert_rowid();
            stored.created_at = now;
        } else {
            tx.execute(
                "UPDATE alert_targets SET name = ?1, enabled = ?2, url = ?3, events = ?4,
                        min_severity = ?5, timeout_secs = ?6, max_retries = ?7,
                        rate_limit_secs = ?8, queue_max = ?9, updated_at_ms = ?10, updated_by = ?11
                 WHERE id = ?12",
                params![
                    stored.name,
                    stored.enabled as i64,
                    stored.url,
                    stored.events,
                    stored.min_severity,
                    stored.timeout_secs as i64,
                    stored.max_retries as i64,
                    stored.rate_limit_secs as i64,
                    stored.queue_max as i64,
                    ms(now),
                    by,
                    stored.id,
                ],
            )?;
            if !stored.enabled {
                tx.execute(
                    "DELETE FROM alert_queue WHERE target_id = ?1 AND state = 'pending'",
                    [stored.id],
                )?;
            }
        }
        tx.commit()?;
        Ok(stored)
    }

    pub fn delete_alert_target(&self, id: i64) -> Result<bool> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM alert_queue WHERE target_id = ?1 AND state = 'pending'",
            [id],
        )?;
        let changed = tx.execute("DELETE FROM alert_targets WHERE id = ?1", [id])?;
        tx.commit()?;
        Ok(changed > 0)
    }

    /// One-time migration: turn the legacy `[alerts]` config into a DB target.
    /// The marker means deleting all UI targets never recreates it.
    pub fn bootstrap_alert_target(&self, cfg: &Config) -> Result<bool> {
        if self
            .get_setting("alerts.bootstrapped")?
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
        {
            return Ok(false);
        }
        let bootstrapped = if self.alert_target_count()? == 0 && !cfg.alerts.url.trim().is_empty() {
            let now = Utc::now();
            let target = AlertTarget {
                id: 0,
                name: "Default webhook".into(),
                enabled: cfg.alerts.enabled,
                url: cfg.alerts.url.clone(),
                events: "all".into(),
                min_severity: cfg.alerts.min_severity.clone(),
                timeout_secs: cfg.alerts.timeout_secs,
                max_retries: cfg.alerts.max_retries,
                rate_limit_secs: cfg.alerts.rate_limit_secs,
                queue_max: cfg.alerts.queue_max,
                created_at: now,
                updated_at: now,
                updated_by: "system".into(),
            };
            let stored = self.save_alert_target(&target, "system")?;
            // Rows written before schema v6 had no target. Assign pending ones
            // to the bootstrap target so an upgrade does not strand them.
            let _ = self.conn.execute(
                "UPDATE alert_queue SET target_id = ?1
                 WHERE target_id IS NULL AND state = 'pending'",
                [stored.id],
            );
            true
        } else {
            false
        };
        self.set_setting("alerts.bootstrapped", &serde_json::json!(true))?;
        Ok(bootstrapped)
    }

    /// Enqueue one webhook payload. The dedupe key suppresses duplicates; the
    /// queue is capped by dropping the oldest pending rows for the target.
    pub fn enqueue_alert(
        &self,
        target_id: Option<i64>,
        dedupe_key: &str,
        payload: &str,
        now: DateTime<Utc>,
        queue_max: usize,
    ) -> Result<bool> {
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO alert_queue
             (created_at_ms, next_attempt_ms, attempts, state, dedupe_key, payload_json, target_id)
             VALUES (?1, ?1, 0, 'pending', ?2, ?3, ?4)",
            params![ms(now), dedupe_key, payload, target_id],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        let pending: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alert_queue WHERE state = 'pending'
             AND (?1 IS NULL OR target_id = ?1)",
            [target_id],
            |r| r.get(0),
        )?;
        if pending > queue_max as i64 {
            let excess = pending - queue_max as i64;
            self.conn.execute(
                "DELETE FROM alert_queue WHERE id IN
                 (SELECT id FROM alert_queue WHERE state = 'pending'
                  AND (?1 IS NULL OR target_id = ?1) ORDER BY id ASC LIMIT ?2)",
                params![target_id, excess],
            )?;
        }
        Ok(true)
    }

    pub fn due_alerts(&self, now: DateTime<Utc>, limit: u32) -> Result<Vec<AlertJob>> {
        let mut stmt = self.conn.prepare(
            "SELECT q.id, t.id, t.name, t.url, t.timeout_secs, t.max_retries,
                    q.attempts, q.payload_json
             FROM alert_queue q JOIN alert_targets t ON t.id = q.target_id
             WHERE q.state = 'pending' AND q.next_attempt_ms <= ?1 AND t.enabled = 1
             ORDER BY q.next_attempt_ms ASC, q.id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![ms(now), limit], |row| {
            Ok(AlertJob {
                id: row.get(0)?,
                target_id: row.get(1)?,
                target_name: row.get(2)?,
                url: row.get(3)?,
                timeout_secs: row.get::<_, i64>(4)?.max(1) as u64,
                max_retries: row.get::<_, i64>(5)?.max(0) as u32,
                attempts: row.get::<_, i64>(6)?.max(0) as u32,
                payload: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn mark_alert_delivered(&self, id: i64, now: DateTime<Utc>) -> Result<()> {
        self.conn.execute(
            "UPDATE alert_queue SET state = 'delivered', delivered_at_ms = ?1,
                                    last_error = ''
             WHERE id = ?2",
            params![ms(now), id],
        )?;
        Ok(())
    }

    pub fn retry_alert(
        &self,
        id: i64,
        attempts: u32,
        next_attempt: DateTime<Utc>,
        error: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE alert_queue SET attempts = ?1, next_attempt_ms = ?2, last_error = ?3
             WHERE id = ?4",
            params![attempts as i64, ms(next_attempt), error, id],
        )?;
        Ok(())
    }

    pub fn fail_alert(&self, id: i64, attempts: u32, error: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE alert_queue SET state = 'failed', attempts = ?1, last_error = ?2
             WHERE id = ?3",
            params![attempts as i64, error, id],
        )?;
        Ok(())
    }

    pub fn alert_stats(&self) -> Result<AlertStats> {
        let pending: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alert_queue WHERE state = 'pending'",
            [],
            |r| r.get(0),
        )?;
        let delivered: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alert_queue WHERE state = 'delivered'",
            [],
            |r| r.get(0),
        )?;
        let failed: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM alert_queue WHERE state = 'failed'",
            [],
            |r| r.get(0),
        )?;
        let oldest: Option<i64> = self.conn.query_row(
            "SELECT MIN(created_at_ms) FROM alert_queue WHERE state = 'pending'",
            [],
            |r| r.get(0),
        )?;
        let (last_error, last_failure): (Option<String>, Option<i64>) = self
            .conn
            .query_row(
                "SELECT last_error, created_at_ms FROM alert_queue
                 WHERE state = 'failed' ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or((None, None));
        Ok(AlertStats {
            pending,
            delivered,
            failed,
            oldest_pending: oldest.map(from_ms),
            last_error: last_error.unwrap_or_default(),
            last_failure: last_failure.map(from_ms),
        })
    }

    pub fn list_alerts(&self, limit: u32) -> Result<Vec<AlertRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT q.id, q.created_at_ms, q.next_attempt_ms, q.attempts, q.state,
                    q.payload_json, q.last_error, q.delivered_at_ms, q.target_id, t.name
             FROM alert_queue q LEFT JOIN alert_targets t ON t.id = q.target_id
             ORDER BY q.id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok(AlertRecord {
                id: row.get(0)?,
                created_at: from_ms(row.get(1)?),
                next_attempt: from_ms(row.get(2)?),
                attempts: row.get::<_, i64>(3)?.max(0) as u32,
                state: row.get(4)?,
                payload: row.get(5)?,
                last_error: row.get(6)?,
                delivered_at: row.get::<_, Option<i64>>(7)?.map(from_ms),
                target_id: row.get(8)?,
                target_name: row.get(9)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Put a pending/failed alert at the front of the queue. A failed row gets
    /// a fresh retry budget.
    pub fn requeue_alert(&self, id: i64, now: DateTime<Utc>) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE alert_queue
             SET state = 'pending', next_attempt_ms = ?1,
                 attempts = CASE WHEN state = 'failed' THEN 0 ELSE attempts END
             WHERE id = ?2 AND state IN ('pending', 'failed')
               AND target_id IN (SELECT id FROM alert_targets WHERE enabled = 1)",
            params![ms(now), id],
        )?;
        Ok(changed > 0)
    }

    pub fn delete_alert(&self, id: i64) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM alert_queue WHERE id = ?1", [id])?
            > 0)
    }

    pub fn clear_finished_alerts(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM alert_queue WHERE state IN ('delivered', 'failed')",
            [],
        )?)
    }

    pub fn prune_alerts(&self, days: u64, now: DateTime<Utc>) -> Result<usize> {
        let cutoff = ms(now) - (days as i64) * 86_400_000;
        Ok(self.conn.execute(
            "DELETE FROM alert_queue
             WHERE state IN ('delivered', 'failed') AND created_at_ms < ?1",
            [cutoff],
        )?)
    }

    /// SQLite housekeeping after the daily prune.
    pub fn optimize(&self) -> Result<()> {
        let _ = self.conn.execute_batch("PRAGMA optimize;");
        let _ = self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        Ok(())
    }

    // ------------------------------------------------------ detection overrides

    pub fn detection_overrides(&self) -> Result<std::collections::BTreeMap<String, String>> {
        let value = self.get_setting("detection.overrides")?;
        Ok(value
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default())
    }

    pub fn set_detection_overrides(
        &self,
        changes: &std::collections::BTreeMap<String, String>,
        remove: &[String],
    ) -> Result<()> {
        let mut overrides = self.detection_overrides()?;
        for key in remove {
            overrides.remove(key);
        }
        for (key, value) in changes {
            overrides.insert(key.clone(), value.clone());
        }
        if overrides.is_empty() {
            self.delete_setting("detection.overrides")
        } else {
            self.set_setting("detection.overrides", &serde_json::to_value(overrides)?)
        }
    }

    pub fn clear_detection_overrides(&self, keys: &[String]) -> Result<()> {
        self.set_detection_overrides(&std::collections::BTreeMap::new(), keys)
    }

    pub fn clear_all_detection_overrides(&self) -> Result<()> {
        self.delete_setting("detection.overrides")
    }

    // ---------------------------------------------------------- detector toggles

    pub fn disabled_detectors(&self) -> Result<std::collections::HashSet<String>> {
        let value = self.get_setting("detection.disabled")?;
        let values: Vec<String> = value
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default();
        Ok(values.into_iter().collect())
    }

    pub fn is_detector_disabled(&self, detector: Detector) -> Result<bool> {
        Ok(self.disabled_detectors()?.contains(detector.as_str()))
    }

    pub fn set_detector_enabled(&self, detector: Detector, enabled: bool) -> Result<()> {
        let mut disabled = self.disabled_detectors()?;
        if enabled {
            disabled.remove(detector.as_str());
        } else {
            disabled.insert(detector.as_str().to_string());
        }
        let mut values: Vec<String> = disabled.into_iter().collect();
        values.sort();
        self.set_setting("detection.disabled", &serde_json::json!(values))
    }

    // ------------------------------------------------- firewall admin rules

    pub fn firewall_admin_rules(&self) -> Result<Vec<AdminDropRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, src, dst, proto, port, enabled, created_at_ms, updated_at_ms, created_by
             FROM firewall_admin_rules ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AdminDropRow {
                id: row.get(0)?,
                src: row.get(1)?,
                dst: row.get(2)?,
                proto: row.get(3)?,
                port: row.get::<_, Option<i64>>(4)?.map(|port| port as u16),
                enabled: row.get::<_, i64>(5)? != 0,
                created_at: from_ms(row.get(6)?),
                updated_at: from_ms(row.get(7)?),
                created_by: row.get(8)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn firewall_admin_rule(&self, id: i64) -> Result<Option<AdminDropRow>> {
        Ok(self
            .firewall_admin_rules()?
            .into_iter()
            .find(|rule| rule.id == id))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save_firewall_admin_rule(
        &self,
        id: i64,
        src: Option<&str>,
        dst: Option<&str>,
        proto: &str,
        port: Option<u16>,
        enabled: bool,
        actor: &str,
    ) -> Result<i64> {
        let now = ms(Utc::now());
        if id == 0 {
            self.conn.execute(
                "INSERT INTO firewall_admin_rules
                 (src, dst, proto, port, enabled, created_at_ms, updated_at_ms, created_by, updated_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?7)",
                params![
                    src,
                    dst,
                    proto,
                    port.map(i64::from),
                    enabled as i64,
                    now,
                    actor
                ],
            )?;
            Ok(self.conn.last_insert_rowid())
        } else {
            self.conn.execute(
                "UPDATE firewall_admin_rules
                 SET src = ?1, dst = ?2, proto = ?3, port = ?4, enabled = ?5,
                     updated_at_ms = ?6, updated_by = ?7
                 WHERE id = ?8",
                params![
                    src,
                    dst,
                    proto,
                    port.map(i64::from),
                    enabled as i64,
                    now,
                    actor,
                    id
                ],
            )?;
            Ok(id)
        }
    }

    pub fn set_firewall_admin_rule_enabled(
        &self,
        id: i64,
        enabled: bool,
        actor: &str,
    ) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE firewall_admin_rules
             SET enabled = ?1, updated_at_ms = ?2, updated_by = ?3
             WHERE id = ?4",
            params![enabled as i64, ms(Utc::now()), actor, id],
        )? > 0)
    }

    pub fn delete_firewall_admin_rule(&self, id: i64) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM firewall_admin_rules WHERE id = ?1", [id])?
            > 0)
    }

    // ---------------------------------------------------- firewall services

    pub fn upsert_firewall_services(
        &self,
        services: &[(String, u16, Option<IpAddr>)],
        now: DateTime<Utc>,
    ) -> Result<()> {
        let now = ms(now);
        let mut stmt = self.conn.prepare(
            "INSERT INTO firewall_services
             (proto, port, addr, first_seen_ms, last_seen_ms, dropped, acknowledged)
             VALUES (?1, ?2, ?3, ?4, ?4, 0, 0)
             ON CONFLICT(proto, port, addr) DO UPDATE SET last_seen_ms = excluded.last_seen_ms",
        )?;
        for (proto, port, addr) in services {
            stmt.execute(params![
                proto,
                *port as i64,
                addr.map(|addr| addr.to_string()).unwrap_or_default(),
                now
            ])?;
        }
        Ok(())
    }

    pub fn firewall_services(&self) -> Result<Vec<FirewallServiceRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT proto, port, addr, first_seen_ms, last_seen_ms, dropped, acknowledged
             FROM firewall_services ORDER BY port ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let addr_text: String = row.get(2)?;
            Ok(FirewallServiceRow {
                proto: row.get(0)?,
                port: row.get::<_, i64>(1)? as u16,
                addr: if addr_text.is_empty() {
                    None
                } else {
                    addr_text.parse::<IpAddr>().ok()
                },
                first_seen: from_ms(row.get(3)?),
                last_seen: from_ms(row.get(4)?),
                dropped: row.get::<_, i64>(5)? != 0,
                acknowledged: row.get::<_, i64>(6)? != 0,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn set_firewall_service_dropped(
        &self,
        proto: &str,
        port: u16,
        addr: Option<IpAddr>,
        dropped: bool,
    ) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE firewall_services
             SET dropped = ?1, acknowledged = 1
             WHERE proto = ?2 AND port = ?3 AND addr = ?4",
            params![
                dropped as i64,
                proto,
                port as i64,
                addr.map(|addr| addr.to_string()).unwrap_or_default()
            ],
        )? > 0)
    }

    pub fn acknowledge_firewall_services(&self) -> Result<usize> {
        Ok(self
            .conn
            .execute("UPDATE firewall_services SET acknowledged = 1", [])?)
    }

    pub fn prune_firewall_services(&self, before: DateTime<Utc>) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM firewall_services WHERE last_seen_ms < ?1",
            [ms(before)],
        )?)
    }

    // --------------------------------------------------------------- maintenance

    pub fn prune(&self, cfg: &Config, now: DateTime<Utc>) -> Result<(usize, usize)> {
        let det_cutoff = ms(now) - (cfg.retention.detections_days as i64) * 86_400_000;
        let blocks_cutoff = ms(now) - (cfg.retention.blocks_days as i64) * 86_400_000;
        let audit_cutoff = ms(now) - (cfg.retention.audit_days as i64) * 86_400_000;
        // Preserve long-term daily counts before raw detections are pruned.
        self.conn.execute(
            "INSERT INTO detection_daily(day, detector, count)
             SELECT date(ts_ms / 1000, 'unixepoch'), detector, COUNT(*)
             FROM detections WHERE ts_ms < ?1 GROUP BY 1, 2
             ON CONFLICT(day, detector) DO UPDATE SET count = count + excluded.count",
            [det_cutoff],
        )?;
        let d = self
            .conn
            .execute("DELETE FROM detections WHERE ts_ms < ?1", [det_cutoff])?;
        let b = self.conn.execute(
            "DELETE FROM blocks WHERE state != 'active' AND started_at_ms < ?1",
            [blocks_cutoff],
        )?;
        self.conn
            .execute("DELETE FROM audit WHERE ts_ms < ?1", [audit_cutoff])?;
        Ok((d, b))
    }

    pub fn db_size_bytes(path: &Path) -> u64 {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }

    // ------------------------------------------------------- resource samples

    pub fn insert_system_sample(
        &self,
        ts: DateTime<Utc>,
        cpu_pct: f64,
        rss_mb: f64,
        db_mb: f64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO system_samples (ts_ms, cpu_pct, rss_mb, db_mb)
             VALUES (?1, ?2, ?3, ?4)",
            params![ms(ts), cpu_pct, rss_mb, db_mb],
        )?;
        Ok(())
    }

    pub fn system_samples_since(&self, since: DateTime<Utc>) -> Result<Vec<SystemPoint>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts_ms, cpu_pct, rss_mb, db_mb
             FROM system_samples WHERE ts_ms >= ?1 ORDER BY ts_ms ASC",
        )?;
        let rows = stmt.query_map([ms(since)], |row| {
            Ok(SystemPoint {
                ts: from_ms(row.get(0)?),
                cpu_pct: row.get(1)?,
                rss_mb: row.get(2)?,
                db_mb: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn prune_system_samples(&self, before: DateTime<Utc>) -> Result<usize> {
        Ok(self
            .conn
            .execute("DELETE FROM system_samples WHERE ts_ms < ?1", [ms(before)])?)
    }
}

fn origin_from_str(s: &str) -> Origin {
    match s {
        "file" => Origin::File,
        _ => Origin::Journal,
    }
}

fn search_pattern(search: Option<&str>) -> Option<String> {
    let search = search?.trim();
    if search.is_empty() {
        return None;
    }
    let escaped = search
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    Some(format!("%{escaped}%"))
}

fn detection_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Detection> {
    let detector: String = row.get(3)?;
    let src: String = row.get(4)?;
    let dst: Option<String> = row.get(5)?;
    let proto: String = row.get(7)?;
    let meta: String = row.get(10)?;
    Ok(Detection {
        id: Some(row.get(0)?),
        first_seen: from_ms(row.get(1)?),
        last_seen: from_ms(row.get(2)?),
        detector: detector_from_str(&detector),
        src: src
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        dst: dst.and_then(|d| d.parse().ok()),
        dst_port: row.get(6)?,
        proto: proto_from_str(&proto),
        count: row.get::<_, i64>(8)? as u64,
        window_secs: row.get::<_, i64>(9)? as u64,
        metadata: serde_json::from_str(&meta).unwrap_or(serde_json::Value::Null),
        evidence_log_id: row.get(11)?,
    })
}

fn log_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(LogEvent, Option<String>)> {
    Ok((
        LogEvent {
            id: Some(row.get(0)?),
            ts: from_ms(row.get(1)?),
            origin: origin_from_str(&row.get::<_, String>(2)?),
            source: row.get(3)?,
            unit: row.get(4)?,
            identifier: row.get(5)?,
            priority: row.get::<_, Option<i64>>(6)?.map(|v| v as u8),
            host: row.get(7)?,
            pid: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
            user: row.get(9)?,
            service: row.get(10)?,
            src_ip: row
                .get::<_, Option<String>>(11)?
                .and_then(|s| s.parse().ok()),
            action: row.get(12)?,
            outcome: row.get(13)?,
            method: row.get(14)?,
            path: row.get(15)?,
            status: row.get::<_, Option<i64>>(16)?.map(|v| v as u16),
            template: row.get(17)?,
            message: row.get(18)?,
            cursor: row.get(19)?,
            parser: row.get(20)?,
        },
        row.get(21)?,
    ))
}

fn block_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Block> {
    let detector: Option<String> = row.get(3)?;
    let state: String = row.get(7)?;
    Ok(Block {
        id: row.get(0)?,
        src: row
            .get::<_, String>(1)?
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        reason: row.get(2)?,
        detector: detector.as_deref().and_then(detector_from_opt),
        detection_id: row.get(4)?,
        started_at: from_ms(row.get(5)?),
        expires_at: row.get::<_, Option<i64>>(6)?.map(from_ms),
        state: match state.as_str() {
            "active" => BlockState::Active,
            "expired_pending_removal" => BlockState::ExpiredPendingRemoval,
            "manual_unblocked" => BlockState::ManualUnblocked,
            _ => BlockState::Expired,
        },
        strike: row.get::<_, i64>(8)?.max(0) as u32,
        rule_id: row.get::<_, Option<i64>>(9)?.map(|v| v.max(0) as u32),
    })
}

fn target_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertTarget> {
    Ok(AlertTarget {
        id: row.get(0)?,
        name: row.get(1)?,
        enabled: row.get::<_, i64>(2)? != 0,
        url: row.get(3)?,
        events: row.get(4)?,
        min_severity: row.get(5)?,
        timeout_secs: row.get::<_, i64>(6)?.max(1) as u64,
        max_retries: row.get::<_, i64>(7)?.max(0) as u32,
        rate_limit_secs: row.get::<_, i64>(8)?.max(1) as u64,
        queue_max: row.get::<_, i64>(9)?.max(1) as usize,
        created_at: from_ms(row.get(10)?),
        updated_at: from_ms(row.get(11)?),
        updated_by: row.get(12)?,
    })
}

fn revision_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RuleRevision> {
    let raw: String = row.get(7)?;
    let document: Rule = serde_json::from_str(&raw).unwrap_or_else(|_| Rule {
        id: row.get::<_, i64>(1).unwrap_or(0).max(0) as u32,
        name: "(unreadable revision)".into(),
        description: raw,
        enabled: false,
        priority: 0,
        severity: crate::rules::Severity::Info,
        dry_run: true,
        when: crate::rules::RuleMatch::default(),
        action: crate::rules::RuleAction::Alert,
    });
    Ok(RuleRevision {
        id: row.get(0)?,
        rule_id: row.get::<_, i64>(1)?.max(0) as u32,
        revision: row.get::<_, i64>(2)?.max(0) as u32,
        changed_at: from_ms(row.get(3)?),
        changed_by: row.get(4)?,
        action: row.get(5)?,
        note: row.get(6)?,
        document,
    })
}

fn detector_from_str(s: &str) -> Detector {
    Detector::from_id(s).unwrap_or(Detector::VerticalScan)
}

fn detector_from_opt(s: &str) -> Option<Detector> {
    Detector::from_id(s)
}

fn proto_from_str(s: &str) -> Proto {
    match s {
        "udp" => Proto::Udp,
        "icmp" => Proto::Icmp,
        "icmp6" => Proto::Icmpv6,
        "log" => Proto::Log,
        _ => Proto::Tcp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DB: AtomicU64 = AtomicU64::new(0);

    fn temp_db() -> (Db, std::path::PathBuf) {
        let unique = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rustips-test-{}-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap(),
            unique
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.db");
        let db = Db::open(&path).unwrap();
        (db, dir)
    }

    #[test]
    fn block_insert_and_extend() {
        let (db, dir) = temp_db();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let now = Utc::now();
        let (b1, created) = db
            .upsert_block(
                ip,
                BlockDuration::Temporary(3600),
                1,
                "test",
                None,
                None,
                now,
            )
            .unwrap();
        assert!(created);
        assert_eq!(b1.strike, 1);

        let (b2, created) = db
            .upsert_block(
                ip,
                BlockDuration::Temporary(86400),
                2,
                "test",
                None,
                None,
                now,
            )
            .unwrap();
        assert!(!created);
        assert_eq!(b2.id, b1.id);
        assert!(b2.expires_at.unwrap() > b1.expires_at.unwrap());
        assert_eq!(b2.strike, 2);

        // Permanence is absorbing.
        let (b3, _) = db
            .upsert_block(ip, BlockDuration::Permanent, 3, "test", None, None, now)
            .unwrap();
        assert!(b3.is_permanent());
        let (b4, _) = db
            .upsert_block(ip, BlockDuration::Temporary(60), 4, "test", None, None, now)
            .unwrap();
        assert!(b4.is_permanent());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn strikes_bump_and_decay() {
        let (db, dir) = temp_db();
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        assert_eq!(db.bump_strike(ip, "x", Utc::now()).unwrap(), 1);
        assert_eq!(db.bump_strike(ip, "x", Utc::now()).unwrap(), 2);
        let later = Utc::now() + chrono::Duration::days(100);
        assert_eq!(db.decay_strikes(90, later).unwrap(), 1);
        assert_eq!(db.strike_count(ip).unwrap(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn implicit_allowlist_cannot_be_removed() {
        let (db, dir) = temp_db();
        db.seed_implicit_allowlist().unwrap();
        assert!(db.remove_allowlist("10.0.0.0/8").is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn log_events_are_deduped_by_cursor_and_paged() {
        let (db, dir) = temp_db();
        let mut event = LogEvent {
            ts: Utc::now(),
            origin: crate::logs::Origin::Journal,
            source: "journal".into(),
            unit: Some("ssh.service".into()),
            identifier: Some("sshd".into()),
            priority: Some(6),
            host: Some("host".into()),
            pid: Some(1),
            user: Some("root".into()),
            service: None,
            src_ip: Some("203.0.113.7".parse().unwrap()),
            action: Some("http.request".into()),
            outcome: Some("not_found".into()),
            method: Some("GET".into()),
            path: Some("/missing".into()),
            status: Some(404),
            template: "http.access".into(),
            message: "Failed password for root".into(),
            cursor: Some("s=1".into()),
            parser: "sshd".into(),
            id: None,
        };
        assert!(db.insert_log_event(&event).unwrap().is_some());
        // Replaying the same cursor after a crash must be a no-op.
        assert!(db.insert_log_event(&event).unwrap().is_none());
        event.cursor = Some("s=2".into());
        assert!(db.insert_log_event(&event).unwrap().is_some());

        assert_eq!(db.log_event_count(None, None).unwrap(), 2);
        assert_eq!(db.log_event_count(Some("journal"), None).unwrap(), 2);
        assert_eq!(db.log_event_count(None, Some("failed")).unwrap(), 2);
        let rows = db.log_events_page(10, 0, None, None).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0.src_ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(rows[0].0.method.as_deref(), Some("GET"));
        assert_eq!(rows[0].0.path.as_deref(), Some("/missing"));
        assert_eq!(rows[0].0.status, Some(404));

        db.set_journal_cursor("s=2").unwrap();
        assert_eq!(db.journal_cursor().unwrap().as_deref(), Some("s=2"));
        db.clear_journal_cursor().unwrap();
        assert!(db.journal_cursor().unwrap().is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn old_log_events_are_pruned() {
        let (db, dir) = temp_db();
        let old = Utc::now() - chrono::Duration::days(30);
        let event = LogEvent {
            ts: old,
            origin: crate::logs::Origin::Journal,
            source: "journal".into(),
            unit: None,
            identifier: None,
            priority: None,
            host: None,
            pid: None,
            user: None,
            service: None,
            src_ip: None,
            action: None,
            outcome: None,
            method: None,
            path: None,
            status: None,
            template: "generic".into(),
            message: "x".into(),
            cursor: Some("s=old".into()),
            parser: "generic".into(),
            id: None,
        };
        db.insert_log_event(&event).unwrap();
        assert_eq!(db.prune_logs(7, 128 * 1024 * 1024, Utc::now()).unwrap(), 1);
        assert_eq!(db.log_event_count(None, None).unwrap(), 0);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn prune_keeps_active_blocks() {
        let (db, dir) = temp_db();
        let cfg =
            Config::parse(Path::new("test.toml"), crate::config::DEFAULT_CONFIG_TOML).unwrap();
        let old = Utc::now() - chrono::Duration::days(800);
        let det = Detection {
            detector: Detector::VerticalScan,
            src: "203.0.113.11".parse().unwrap(),
            dst: None,
            dst_port: None,
            proto: Proto::Tcp,
            count: 1,
            window_secs: 10,
            first_seen: old,
            last_seen: old,
            metadata: serde_json::json!({}),
            evidence_log_id: None,
            id: None,
        };
        db.insert_detection(&det).unwrap();
        db.audit(&Actor::System, "old", "", "").unwrap();
        let block_ip: IpAddr = "203.0.113.12".parse().unwrap();
        db.upsert_block(
            block_ip,
            BlockDuration::Permanent,
            1,
            "test",
            None,
            None,
            old,
        )
        .unwrap();

        let (detections, _) = db.prune(&cfg, Utc::now()).unwrap();
        assert_eq!(detections, 1);
        assert_eq!(db.detection_count().unwrap(), 0);
        assert_eq!(db.active_block_count().unwrap(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rules_seed_save_history_and_delete() {
        let (db, dir) = temp_db();
        let seeded = db.list_rules().unwrap();
        assert_eq!(seeded.len(), 7);
        assert!(db.rules_version().unwrap() >= 1);
        let mut rule = seeded[0].clone();
        let id = rule.id;
        rule.name = "edited rule".into();
        let saved = db.save_rule(&rule, "tester", "changed name").unwrap();
        assert_eq!(saved.id, id);
        assert_eq!(saved.name, "edited rule");
        let revisions = db.rule_revisions(Some(id), 10).unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].action, "update");
        assert_eq!(revisions[0].changed_by, "tester");
        assert!(db.delete_rule(id, "tester").unwrap());
        assert!(db.get_rule(id).unwrap().is_none());
        let revisions = db.rule_revisions(Some(id), 10).unwrap();
        assert_eq!(revisions[0].action, "delete");
        std::fs::remove_dir_all(dir).ok();
    }

    fn test_rule(id: u32, name: &str) -> Rule {
        Rule {
            id,
            name: name.into(),
            description: String::new(),
            enabled: true,
            priority: 100,
            severity: crate::rules::Severity::Warning,
            dry_run: false,
            when: crate::rules::RuleMatch::default(),
            action: crate::rules::RuleAction::BlockTemp {
                duration: "1h".into(),
            },
        }
    }

    #[test]
    fn rules_import_replaces_the_set() {
        let (db, dir) = temp_db();
        db.replace_rules(&[test_rule(10, "only")], "tester", "import")
            .unwrap();
        let rules = db.list_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, 10);
        assert_eq!(rules[0].name, "only");
        let revisions = db.rule_revisions(Some(10), 10).unwrap();
        assert_eq!(revisions[0].action, "import");
        assert!(db.replace_rules(&[], "tester", "empty").is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn last_enabled_rule_is_protected() {
        let (db, dir) = temp_db();
        db.replace_rules(&[test_rule(1, "only")], "tester", "import")
            .unwrap();
        assert!(db.delete_rule(1, "tester").is_err());
        let mut rule = db.get_rule(1).unwrap().unwrap();
        rule.enabled = false;
        assert!(db.save_rule(&rule, "tester", "disable").is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn http_rule_is_added_to_an_old_rule_set() {
        let (mut db, dir) = temp_db();
        let mut packet = db
            .list_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.name == "Packet detections escalate")
            .unwrap();
        packet.when.detectors = vec!["DET-01".into()];
        db.save_rule(&packet, "tester", "trim").unwrap();
        assert!(db.ensure_http_rule().unwrap());
        let rules = db.list_rules().unwrap();
        assert!(
            rules
                .iter()
                .any(|rule| rule.when.detectors.iter().any(|id| id == "DET-11"))
        );
        assert!(!db.ensure_http_rule().unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn http_log_rule_is_added_to_an_old_rule_set() {
        let (mut db, dir) = temp_db();
        let mut log_rule = db
            .list_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.name == "Log authentication failures")
            .unwrap();
        log_rule.when.detectors = vec!["DET-16".into()];
        db.save_rule(&log_rule, "tester", "trim").unwrap();
        assert!(db.ensure_http_log_rule().unwrap());
        assert!(
            db.list_rules().unwrap().iter().any(|rule| rule
                .when
                .detectors
                .iter()
                .any(|id| id == "DET-23"))
        );
        assert!(!db.ensure_http_log_rule().unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn slow_scan_rule_is_added_to_an_old_rule_set() {
        let (mut db, dir) = temp_db();
        let slow = db
            .list_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.name == "Slow scan alert")
            .unwrap();
        db.delete_rule(slow.id, "tester").unwrap();
        assert!(db.ensure_slow_scan_rule().unwrap());
        assert!(
            db.list_rules().unwrap().iter().any(|rule| rule
                .when
                .detectors
                .iter()
                .any(|id| id == "DET-20"))
        );
        assert!(!db.ensure_slow_scan_rule().unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn honeypot_rule_is_added_to_an_old_rule_set() {
        let (mut db, dir) = temp_db();
        let honeypot = db
            .list_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.name == "Honeypot block after 3 contacts")
            .unwrap();
        db.delete_rule(honeypot.id, "tester").unwrap();
        assert!(db.ensure_honeypot_rule().unwrap());
        let added = db
            .list_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.when.detectors.iter().any(|id| id == "DET-26"))
            .expect("honeypot rule");
        assert_eq!(added.when.min_count, Some(3));
        assert!(!db.ensure_honeypot_rule().unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn firewall_rule_is_added_to_an_old_rule_set() {
        let (mut db, dir) = temp_db();
        let firewall = db
            .list_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.name == "Firewall default-drop alert")
            .unwrap();
        db.delete_rule(firewall.id, "tester").unwrap();
        assert!(db.ensure_firewall_rule().unwrap());
        let added = db
            .list_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.when.detectors.iter().any(|id| id == "DET-27"))
            .expect("firewall rule");
        assert_eq!(added.action, crate::rules::RuleAction::Alert);
        assert!(!db.ensure_firewall_rule().unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn firewall_admin_rules_and_services_roundtrip() {
        let (db, dir) = temp_db();
        let id = db
            .save_firewall_admin_rule(
                0,
                Some("203.0.113.0/24"),
                None,
                "tcp",
                Some(22),
                true,
                "tester",
            )
            .unwrap();
        let rule = db.firewall_admin_rule(id).unwrap().unwrap();
        assert_eq!(rule.src.as_deref(), Some("203.0.113.0/24"));
        assert_eq!(rule.port, Some(22));
        assert!(rule.enabled);
        assert!(
            db.set_firewall_admin_rule_enabled(id, false, "tester")
                .unwrap()
        );
        assert!(!db.firewall_admin_rule(id).unwrap().unwrap().enabled);
        assert!(db.delete_firewall_admin_rule(id).unwrap());

        let socket: IpAddr = "192.0.2.10".parse().unwrap();
        let start = Utc::now() - chrono::Duration::hours(1);
        db.upsert_firewall_services(&[("tcp".into(), 22, None)], start)
            .unwrap();
        db.upsert_firewall_services(&[("tcp".into(), 22, None)], Utc::now())
            .unwrap();
        let service = db
            .firewall_services()
            .unwrap()
            .into_iter()
            .find(|row| row.proto == "tcp" && row.port == 22)
            .unwrap();
        assert!(!service.dropped);
        assert!(!service.acknowledged);
        assert!(service.last_seen >= service.first_seen);
        assert!(
            db.set_firewall_service_dropped("tcp", 22, None, true)
                .unwrap()
        );
        let service = db
            .firewall_services()
            .unwrap()
            .into_iter()
            .find(|row| row.proto == "tcp" && row.port == 22)
            .unwrap();
        assert!(service.dropped);
        assert!(service.acknowledged);

        db.upsert_firewall_services(&[("tcp".into(), 443, Some(socket))], Utc::now())
            .unwrap();
        assert_eq!(db.acknowledge_firewall_services().unwrap(), 2);
        assert!(
            db.firewall_services()
                .unwrap()
                .iter()
                .all(|row| row.acknowledged)
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn retired_detectors_are_removed_from_rules() {
        let (mut db, dir) = temp_db();
        let mut rule = db
            .list_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.name == "Log authentication failures")
            .unwrap();
        rule.when.detectors = vec!["DET-16".into(), "DET-22".into(), "DET-24".into()];
        db.save_rule(&rule, "tester", "inject retired ids").unwrap();
        assert_eq!(db.strip_retired_detectors().unwrap(), 1);
        let stored = db.get_rule(rule.id).unwrap().unwrap();
        assert_eq!(stored.when.detectors, vec!["DET-16"]);
        assert!(!stored.description.contains("DET-22"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn system_samples_roundtrip_and_prune() {
        let (db, dir) = temp_db();
        let now = Utc::now();
        db.insert_system_sample(now - chrono::Duration::hours(2), 1.5, 2.5, 3.5)
            .unwrap();
        db.insert_system_sample(now, 4.5, 5.5, 6.5).unwrap();
        let points = db
            .system_samples_since(now - chrono::Duration::hours(3))
            .unwrap();
        assert_eq!(points.len(), 2);
        assert!((points[1].cpu_pct - 4.5).abs() < 0.001);
        let removed = db
            .prune_system_samples(now - chrono::Duration::hours(1))
            .unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            db.system_samples_since(now - chrono::Duration::hours(3))
                .unwrap()
                .len(),
            1
        );
        std::fs::remove_dir_all(dir).ok();
    }

    fn test_alert_target() -> AlertTarget {
        let now = Utc::now();
        AlertTarget {
            id: 0,
            name: "test".into(),
            enabled: true,
            url: "http://127.0.0.1:1/hook".into(),
            events: "all".into(),
            min_severity: "info".into(),
            timeout_secs: 1,
            max_retries: 2,
            rate_limit_secs: 60,
            queue_max: 10,
            created_at: now,
            updated_at: now,
            updated_by: "test".into(),
        }
    }

    #[test]
    fn detection_overrides_roundtrip() {
        let (db, dir) = temp_db();
        let mut changes = std::collections::BTreeMap::new();
        changes.insert("detection.scan_ports".into(), "25".into());
        changes.insert("detection.http_bad_paths".into(), "/.env, /custom".into());
        db.set_detection_overrides(&changes, &[]).unwrap();
        let overrides = db.detection_overrides().unwrap();
        assert_eq!(overrides.get("detection.scan_ports").unwrap(), "25");
        db.clear_detection_overrides(&["detection.scan_ports".to_string()])
            .unwrap();
        assert!(
            !db.detection_overrides()
                .unwrap()
                .contains_key("detection.scan_ports")
        );
        db.clear_all_detection_overrides().unwrap();
        assert!(db.detection_overrides().unwrap().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn detectors_can_be_disabled_and_enabled() {
        let (db, dir) = temp_db();
        assert!(!db.is_detector_disabled(Detector::HttpBadPath).unwrap());
        db.set_detector_enabled(Detector::HttpBadPath, false)
            .unwrap();
        assert!(db.is_detector_disabled(Detector::HttpBadPath).unwrap());
        assert!(!db.is_detector_disabled(Detector::VerticalScan).unwrap());
        db.set_detector_enabled(Detector::HttpBadPath, true)
            .unwrap();
        assert!(!db.is_detector_disabled(Detector::HttpBadPath).unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn alert_targets_are_crud() {
        let (db, dir) = temp_db();
        let target = db
            .save_alert_target(&test_alert_target(), "tester")
            .unwrap();
        assert!(target.id > 0);
        assert_eq!(db.list_alert_targets().unwrap().len(), 1);
        let mut edited = db.get_alert_target(target.id).unwrap().unwrap();
        edited.name = "edited".into();
        edited.enabled = false;
        db.save_alert_target(&edited, "tester").unwrap();
        assert!(!db.get_alert_target(target.id).unwrap().unwrap().enabled);
        assert!(db.delete_alert_target(target.id).unwrap());
        assert!(db.list_alert_targets().unwrap().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn alert_queue_dedupes_caps_and_prunes() {
        let (db, dir) = temp_db();
        let now = Utc::now();
        let target = db
            .save_alert_target(&test_alert_target(), "tester")
            .unwrap();
        assert!(
            db.enqueue_alert(Some(target.id), "a", "{}", now, 10)
                .unwrap()
        );
        assert!(
            !db.enqueue_alert(Some(target.id), "a", "{}", now, 10)
                .unwrap()
        );
        assert!(
            db.enqueue_alert(Some(target.id), "b", "{}", now, 10)
                .unwrap()
        );
        assert!(
            db.enqueue_alert(Some(target.id), "c", "{}", now, 2)
                .unwrap()
        );
        let stats = db.alert_stats().unwrap();
        assert_eq!(stats.pending, 2);
        let jobs = db.due_alerts(now, 10).unwrap();
        assert_eq!(jobs.len(), 2);
        let id = jobs[0].id;
        db.mark_alert_delivered(id, now).unwrap();
        assert_eq!(db.alert_stats().unwrap().delivered, 1);
        let id = jobs[1].id;
        db.retry_alert(id, 1, now + chrono::Duration::seconds(60), "boom")
            .unwrap();
        assert!(db.due_alerts(now, 10).unwrap().is_empty());
        db.fail_alert(id, 2, "boom").unwrap();
        let stats = db.alert_stats().unwrap();
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.last_error, "boom");
        assert_eq!(
            db.prune_alerts(0, now + chrono::Duration::days(1)).unwrap(),
            2
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn alert_rows_can_be_listed_requeued_and_cleared() {
        let (db, dir) = temp_db();
        let now = Utc::now();
        let target = db
            .save_alert_target(&test_alert_target(), "tester")
            .unwrap();
        assert!(
            db.enqueue_alert(Some(target.id), "a", "{\"event\":\"test\"}", now, 10)
                .unwrap()
        );
        let rows = db.list_alerts(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, "pending");
        assert!(db.requeue_alert(rows[0].id, now).unwrap());
        db.mark_alert_delivered(rows[0].id, now).unwrap();
        assert_eq!(db.list_alerts(10).unwrap()[0].state, "delivered");
        assert_eq!(db.clear_finished_alerts().unwrap(), 1);
        assert!(db.list_alerts(10).unwrap().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn detection_prune_keeps_daily_aggregates() {
        let (db, dir) = temp_db();
        let cfg =
            Config::parse(Path::new("test.toml"), crate::config::DEFAULT_CONFIG_TOML).unwrap();
        let old = Utc::now() - chrono::Duration::days(800);
        for _ in 0..2 {
            let det = Detection {
                detector: Detector::VerticalScan,
                src: "203.0.113.33".parse().unwrap(),
                dst: None,
                dst_port: None,
                proto: Proto::Tcp,
                count: 1,
                window_secs: 10,
                first_seen: old,
                last_seen: old,
                metadata: serde_json::json!({}),
                evidence_log_id: None,
                id: None,
            };
            db.insert_detection(&det).unwrap();
        }
        db.prune(&cfg, Utc::now()).unwrap();
        let count: i64 = db
            .conn
            .query_row(
                "SELECT count FROM detection_daily WHERE detector = 'DET-01'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn sample_rules_are_added_once() {
        let (db, dir) = temp_db();
        let samples = crate::rules::sample_geo_rules();
        assert_eq!(
            db.add_rules_if_missing(&samples, "tester", "samples")
                .unwrap(),
            samples.len()
        );
        assert_eq!(
            db.add_rules_if_missing(&samples, "tester", "samples")
                .unwrap(),
            0
        );
        assert_eq!(db.list_rules().unwrap().len(), 7 + samples.len());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn detection_tags_are_merged() {
        let (db, dir) = temp_db();
        let det = Detection {
            detector: Detector::VerticalScan,
            src: "203.0.113.20".parse().unwrap(),
            dst: None,
            dst_port: None,
            proto: Proto::Tcp,
            count: 1,
            window_secs: 10,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            metadata: serde_json::json!({}),
            evidence_log_id: None,
            id: None,
        };
        let id = db.insert_detection(&det).unwrap();
        db.add_detection_tags(id, &["a".into(), "b".into()])
            .unwrap();
        db.add_detection_tags(id, &["b".into(), "c".into()])
            .unwrap();
        let stored = db.recent_detections(1).unwrap();
        let tags = stored[0]
            .metadata
            .get("tags")
            .and_then(|value| value.as_array())
            .unwrap();
        let tags: Vec<&str> = tags.iter().filter_map(|value| value.as_str()).collect();
        assert_eq!(tags, vec!["a", "b", "c"]);
        std::fs::remove_dir_all(dir).ok();
    }
}
