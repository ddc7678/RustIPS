//! The daemon: capture → decode → detect → dispose → enforce, plus the
//! maintenance threads that make the failure policy real.
//!
//! Ownership rules:
//! * One `Db` per thread (SQLite WAL, independent connections).
//! * One enforcer, shared.
//! * Expiry, drift repair and overdue reporting live in the scheduler thread,
//!   not the packet path.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::capture::pcap::PcapReader;
use crate::capture::{AfPacket, RawPacket, local_addresses};
use crate::config::{Config, Mode};
use crate::db::Db;
use crate::decode;
use crate::detect::Engine;
use crate::enforce::{DryRunEnforcer, Enforcer, NftEnforcer};
use crate::error::{Error, Result};
use crate::geo::GeoHandle;
use crate::model::{Actor, BlockState, Detection};
use crate::net::{self, Cidr};
use crate::paths::Layout;
use crate::rules::{DecisionAction, History, RuleSet, RulesHandle};

pub struct Options {
    pub pcap: Option<PathBuf>,
    /// Ignore capture timestamps and replay as fast as possible.
    pub fast_replay: bool,
    pub force_observe: bool,
    /// Do not start the embedded web UI.
    pub no_web: bool,
    pub web_bind: Option<String>,
    pub web_port: Option<u16>,
}

pub struct Stats {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    pub decode_errors: AtomicU64,
    pub detections: AtomicU64,
    /// Detections suppressed because the detector is disabled in the UI.
    pub detections_suppressed: AtomicU64,
    pub blocks: AtomicU64,
    pub observed: AtomicU64,
    /// Capture drops and kernel-delivered packets, sampled from AF_PACKET.
    pub drops: AtomicU64,
    pub kernel_packets: AtomicU64,
    /// Host-log ingestion counters (journald slice).
    pub log_events: AtomicU64,
    pub log_dropped: AtomicU64,
    pub log_parse_errors: AtomicU64,
    /// Webhook alerting counters.
    pub alerts_queued: AtomicU64,
    pub alerts_sent: AtomicU64,
    pub alerts_failed: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Stats::new()
    }
}

impl Stats {
    /// Fresh counters, shared by the capture threads, the scheduler and the UI.
    pub fn new() -> Stats {
        Stats {
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            decode_errors: AtomicU64::new(0),
            detections: AtomicU64::new(0),
            detections_suppressed: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            observed: AtomicU64::new(0),
            drops: AtomicU64::new(0),
            kernel_packets: AtomicU64::new(0),
            log_events: AtomicU64::new(0),
            log_dropped: AtomicU64::new(0),
            log_parse_errors: AtomicU64::new(0),
            alerts_queued: AtomicU64::new(0),
            alerts_sent: AtomicU64::new(0),
            alerts_failed: AtomicU64::new(0),
        }
    }
}

pub fn run(layout: &Layout, cfg: Config, opts: Options) -> Result<()> {
    let mut cfg = cfg;
    if opts.force_observe {
        cfg.mode = Mode::Observe;
    }

    let db = Db::open(&layout.db)?;
    db.seed_implicit_allowlist()?;
    db.set_setting(
        "daemon.last_start",
        &serde_json::json!(Utc::now().to_rfc3339()),
    )?;
    db.set_setting("daemon.mode", &serde_json::json!(cfg.mode.to_string()))?;

    let enforcer: Arc<dyn Enforcer> = match cfg.mode {
        Mode::Enforce => {
            let e = NftEnforcer::new(
                &cfg.enforcement.table,
                &cfg.enforcement.chain_hook,
                cfg.enforcement.priority,
            );
            if !e.available() {
                return Err(Error::Enforce(
                    "nftables is not installed; enforce mode requires the nft binary".into(),
                ));
            }
            e.ensure()?;
            Arc::new(e)
        }
        Mode::Observe => Arc::new(DryRunEnforcer),
    };

    let stop = Arc::new(AtomicBool::new(false));
    install_signal_handlers(&stop)?;

    // Startup reconciliation: overdue blocks first, then the full blocked set.
    let overdue = db.expired_blocks(Utc::now(), 10_000)?;
    if !overdue.is_empty() {
        tracing::warn!(
            count = overdue.len(),
            "blocks outlived their expiry while the daemon was down; removing now"
        );
        for block in &overdue {
            let _ = enforcer.remove(block.src);
            db.mark_block_state(block.id, BlockState::Expired)?;
        }
        db.audit(
            &Actor::System,
            "startup.overdue_removed",
            "",
            &format!("{} blocks expired during outage", overdue.len()),
        )?;
    }

    let active = db.list_active_blocks()?;
    let ips: Vec<IpAddr> = active.iter().map(|b| b.src).collect();
    if let Err(e) = enforcer.restore(&ips) {
        tracing::error!("failed to restore the blocked set: {e}");
    } else {
        for b in &active {
            db.set_enforced(b.id, true)?;
        }
        if !ips.is_empty() {
            tracing::info!(
                count = ips.len(),
                "restored the blocked set from the database"
            );
        }
    }

    let mut engine = Engine::new(&cfg.detection, local_addrs());
    let mut allow: Vec<Cidr> = db.allowlist_matcher()?;
    let mut allow_loaded = Instant::now();

    let stats = Arc::new(Stats::new());
    let rules: RulesHandle = Arc::new(RwLock::new(load_rules(&db, &cfg)));
    let geo: GeoHandle = Arc::new(RwLock::new(crate::geo::load_from_dir(&layout.state_dir)));

    let mut web = if opts.no_web || !cfg.web.enabled {
        None
    } else {
        match crate::web::start(
            &cfg,
            layout,
            stats.clone(),
            enforcer.clone(),
            geo.clone(),
            crate::web::WebOptions {
                bind: opts.web_bind.clone(),
                port: opts.web_port,
            },
        ) {
            Ok(handle) => Some(handle),
            Err(e) => {
                tracing::error!("web UI disabled: {e}");
                None
            }
        }
    };

    let scheduler = {
        let db_path = layout.db.clone();
        let enforcer = enforcer.clone();
        let cfg = cfg.clone();
        let stop = stop.clone();
        let stats = stats.clone();
        let rules = rules.clone();
        std::thread::spawn(move || scheduler_loop(db_path, enforcer, cfg, stop, stats, rules))
    };

    let mut journal = if cfg.logs.enabled {
        Some(crate::logs::journal::spawn(
            layout.db.clone(),
            cfg.clone(),
            enforcer.clone(),
            rules.clone(),
            geo.clone(),
            stop.clone(),
            stats.clone(),
        ))
    } else {
        None
    };

    let geo_updater = crate::geo::update::spawn(
        layout.db.clone(),
        layout.state_dir.clone(),
        cfg.clone(),
        geo.clone(),
        stop.clone(),
    );
    if let Err(e) = db.bootstrap_alert_target(&cfg) {
        tracing::warn!("cannot bootstrap the legacy webhook target: {e}");
    }
    let alerts = crate::alerts::spawn(layout.db.clone(), stop.clone(), stats.clone());

    tracing::info!(
        mode = %cfg.mode,
        enforcement = %enforcer.describe(),
        interface = ?cfg.capture.interfaces,
        logs = cfg.logs.enabled,
        "RustIPS started"
    );

    match opts.pcap {
        Some(path) => {
            let mut reader = PcapReader::open(&path)?;
            tracing::info!(path = %path.display(), "replaying capture");
            let start_wall = Instant::now();
            let start_ts = Utc::now();
            let mut link_logged = false;
            while !stop.load(Ordering::Relaxed) {
                let Some(pkt) = reader.next_packet()? else {
                    break;
                };
                if !link_logged {
                    tracing::info!(link = ?pkt.link, "capture link type");
                    link_logged = true;
                }
                if !opts.fast_replay {
                    if let Some(ts) = pkt.ts {
                        let due = (ts - start_ts).num_microseconds().unwrap_or(0).max(0) as u64;
                        let elapsed = start_wall.elapsed().as_micros() as u64;
                        if due > elapsed {
                            std::thread::sleep(Duration::from_micros(due - elapsed));
                        }
                    }
                }
                handle_packet(
                    &db,
                    &cfg,
                    &mut engine,
                    &mut allow,
                    &mut allow_loaded,
                    &enforcer,
                    &stats,
                    &rules,
                    &geo,
                    pkt,
                )?;
            }
        }
        None => {
            let interfaces = crate::capture::resolve_interfaces(&cfg.capture.interfaces)?;
            let (tx, rx) = sync_channel::<RawPacket>(8192);
            let mut handles = Vec::new();
            for ifname in interfaces {
                let tx = tx.clone();
                let stop = stop.clone();
                let snaplen = cfg.capture.snaplen;
                let rcvbuf = cfg.capture.rcvbuf_bytes;
                let stats = stats.clone();
                handles.push(std::thread::spawn(move || {
                    capture_thread(&ifname, snaplen, rcvbuf, tx, stop, stats)
                }));
            }
            drop(tx);

            while !stop.load(Ordering::Relaxed) {
                match rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(pkt) => handle_packet(
                        &db,
                        &cfg,
                        &mut engine,
                        &mut allow,
                        &mut allow_loaded,
                        &enforcer,
                        &stats,
                        &rules,
                        &geo,
                        pkt,
                    )?,
                    Err(RecvTimeoutError::Timeout) => {
                        if allow_loaded.elapsed() > Duration::from_secs(10) {
                            allow = db.allowlist_matcher()?;
                            allow_loaded = Instant::now();
                        }
                        engine.set_local(local_addrs());
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
            for h in handles {
                let _ = h.join();
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    if let Some(mut journal) = journal.take() {
        journal.join();
    }
    if let Some(mut web) = web.take() {
        web.stop();
    }
    let _ = scheduler.join();
    let _ = geo_updater.join();
    let _ = alerts.join();
    db.audit(
        &Actor::System,
        "daemon.stop",
        "",
        &format!(
            "packets={} detections={} suppressed={} blocks={} log_events={} log_dropped={} alerts_sent={} alerts_failed={}",
            stats.packets.load(Ordering::Relaxed),
            stats.detections.load(Ordering::Relaxed),
            stats.detections_suppressed.load(Ordering::Relaxed),
            stats.blocks.load(Ordering::Relaxed),
            stats.log_events.load(Ordering::Relaxed),
            stats.log_dropped.load(Ordering::Relaxed),
            stats.alerts_sent.load(Ordering::Relaxed),
            stats.alerts_failed.load(Ordering::Relaxed)
        ),
    )?;
    tracing::info!(
        packets = stats.packets.load(Ordering::Relaxed),
        detections = stats.detections.load(Ordering::Relaxed),
        blocks = stats.blocks.load(Ordering::Relaxed),
        log_events = stats.log_events.load(Ordering::Relaxed),
        log_dropped = stats.log_dropped.load(Ordering::Relaxed),
        "RustIPS stopped"
    );
    Ok(())
}

fn local_addrs() -> Vec<IpAddr> {
    let mut addrs = local_addresses();
    addrs.push("127.0.0.1".parse().unwrap());
    addrs.push("::1".parse().unwrap());
    addrs
}

fn capture_thread(
    ifname: &str,
    snaplen: usize,
    rcvbuf: usize,
    tx: std::sync::mpsc::SyncSender<RawPacket>,
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
) {
    let mut src = match AfPacket::open(ifname, snaplen, rcvbuf) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("capture on {ifname} failed: {e}");
            return;
        }
    };
    tracing::info!(ifname, "capturing");
    let mut last_kernel = Instant::now();
    let mut delivered: u64 = 0;
    let mut dropped: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        match src.next_packet() {
            Ok(Some(pkt)) => {
                if tx.send(pkt).is_err() {
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("capture error on {ifname}: {e}");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        if last_kernel.elapsed() >= Duration::from_secs(5) {
            last_kernel = Instant::now();
            let snapshot = src.kernel_stats();
            stats.kernel_packets.fetch_add(
                snapshot.received.saturating_sub(delivered),
                Ordering::Relaxed,
            );
            stats
                .drops
                .fetch_add(snapshot.dropped.saturating_sub(dropped), Ordering::Relaxed);
            delivered = snapshot.received;
            dropped = snapshot.dropped;
        }
    }
    let snapshot = src.kernel_stats();
    stats.kernel_packets.fetch_add(
        snapshot.received.saturating_sub(delivered),
        Ordering::Relaxed,
    );
    stats
        .drops
        .fetch_add(snapshot.dropped.saturating_sub(dropped), Ordering::Relaxed);
    tracing::info!(
        ifname,
        received = snapshot.received,
        dropped = snapshot.dropped,
        "capture stopped"
    );
    if snapshot.dropped > 0 {
        tracing::warn!(
            ifname,
            dropped = snapshot.dropped,
            "the kernel dropped packets; raise capture.rcvbuf_bytes"
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_packet(
    db: &Db,
    cfg: &Config,
    engine: &mut Engine,
    allow: &mut Vec<Cidr>,
    allow_loaded: &mut Instant,
    enforcer: &Arc<dyn Enforcer>,
    stats: &Arc<Stats>,
    rules: &RulesHandle,
    geo: &GeoHandle,
    raw: RawPacket,
) -> Result<()> {
    stats.packets.fetch_add(1, Ordering::Relaxed);
    stats
        .bytes
        .fetch_add(raw.data.len() as u64, Ordering::Relaxed);
    let Some(pkt) = decode::decode(raw.link, &raw.data) else {
        stats.decode_errors.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    };
    let now = raw.ts.unwrap_or_else(Utc::now);

    // Refresh the allowlist lazily when replaying, and every 10 s live.
    if allow_loaded.elapsed() > Duration::from_secs(10) {
        if let Ok(fresh) = db.allowlist_matcher() {
            *allow = fresh;
        }
        *allow_loaded = Instant::now();
    }

    for obs in engine.observe(&pkt, now) {
        let det = Detection {
            detector: obs.detector,
            src: obs.src,
            dst: obs.dst,
            dst_port: obs.dst_port,
            proto: obs.proto,
            count: obs.count,
            window_secs: obs.window_secs,
            first_seen: now - chrono::Duration::seconds(obs.window_secs as i64),
            last_seen: now,
            metadata: obs.metadata,
            evidence_log_id: None,
            id: None,
        };
        record_detection(db, cfg, &allow[..], enforcer, stats, rules, geo, det, now)?;
    }
    Ok(())
}

/// Load and validate the stored rule set, falling back to the shipped
/// defaults if the database is empty, unreadable or invalid (FR-126).
fn load_rules(db: &Db, cfg: &Config) -> RuleSet {
    match db.list_rules() {
        Ok(rules) if !rules.is_empty() => match RuleSet::compile(rules, &cfg.ladder.steps) {
            Ok(set) => set,
            Err(errors) => {
                let detail = errors
                    .iter()
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                tracing::error!(errors = %detail, "stored rules failed validation; using shipped defaults");
                let _ = db.audit(&Actor::System, "rules.load_failed", "", &detail);
                RuleSet::defaults(&cfg.ladder.steps)
            }
        },
        Ok(_) => {
            if let Err(e) = db.seed_rules_if_empty() {
                tracing::error!("cannot seed default rules: {e}");
            }
            match db.list_rules() {
                Ok(rules) if !rules.is_empty() => RuleSet::compile(rules, &cfg.ladder.steps)
                    .unwrap_or_else(|_| RuleSet::defaults(&cfg.ladder.steps)),
                _ => RuleSet::defaults(&cfg.ladder.steps),
            }
        }
        Err(e) => {
            tracing::error!("cannot read rules: {e}; using shipped defaults");
            RuleSet::defaults(&cfg.ladder.steps)
        }
    }
}

/// Shared detection disposition for packet and log detectors (FR-309, FR-120).
///
/// Order matters: record the evidence first, then evaluate rules, apply tags,
/// check implicit/allowlisted sources, then observe/dry-run and enforcement.
/// Log detections without a derivable source address never block, whatever the
/// rules say. The rule engine is pure; this function supplies the history
/// snapshot and owns the side effects.
#[allow(clippy::too_many_arguments)]
pub fn record_detection(
    db: &Db,
    cfg: &Config,
    allow: &[Cidr],
    enforcer: &Arc<dyn Enforcer>,
    stats: &Arc<Stats>,
    rules: &RulesHandle,
    geo: &GeoHandle,
    mut det: Detection,
    now: DateTime<Utc>,
) -> Result<()> {
    if db.is_detector_disabled(det.detector)? {
        stats.detections_suppressed.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    stats.detections.fetch_add(1, Ordering::Relaxed);
    let id = db.insert_detection(&det)?;
    det.id = Some(id);
    tracing::info!(detection = %det.summary(), "detection");

    let history = if det.has_source() {
        History {
            strikes: db.strike_count(det.src)?,
            blocked: db.active_block(det.src)?.is_some(),
            last_strike_seen: db.strike_last_seen(det.src)?,
        }
    } else {
        History::default()
    };
    let geo_info = {
        let data = geo.read().unwrap_or_else(|poison| poison.into_inner());
        data.lookup(det.src)
    };
    let decision = {
        let set = rules.read().unwrap_or_else(|poison| poison.into_inner());
        set.evaluate(&det, &history, &geo_info)
    };
    if !decision.tags.is_empty() {
        let _ = db.add_detection_tags(id, &decision.tags);
    }

    let matched = decision.matched_label();
    let winner = decision
        .rule_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "-".into());
    let winner_name = decision.rule_name.clone().unwrap_or_else(|| "-".into());
    let rule_detail = format!("rules={matched} winner={winner} ({winner_name})");
    let notify = |action: &str| match crate::alerts::enqueue_detection(
        db, &det, &decision, action, &geo_info, now,
    ) {
        Ok(count) => {
            stats
                .alerts_queued
                .fetch_add(count as u64, Ordering::Relaxed);
        }
        Err(e) => tracing::warn!("cannot enqueue webhook alert: {e}"),
    };

    if !det.has_source() {
        notify("alert_no_source");
        db.audit(
            &Actor::System,
            "detection.alert",
            det.detector.as_str(),
            &format!("{}; {rule_detail}", det.summary()),
        )?;
        return Ok(());
    }

    let allowed = net::is_implicitly_allowed(det.src) || allow.iter().any(|c| c.contains(det.src));
    if allowed {
        notify("allowed");
        db.audit(
            &Actor::System,
            "detection.allowed",
            &det.src.to_string(),
            &format!("{}; {rule_detail}", det.summary()),
        )?;
        return Ok(());
    }

    match &decision.action {
        DecisionAction::Allow => {
            notify("allow");
            db.audit(
                &Actor::System,
                "rule.allow",
                &det.src.to_string(),
                &rule_detail,
            )?;
            return Ok(());
        }
        DecisionAction::Alert => {
            notify("alert");
            db.audit(
                &Actor::System,
                "rule.alert",
                &det.src.to_string(),
                &format!("{}; {rule_detail}", det.summary()),
            )?;
            return Ok(());
        }
        DecisionAction::Tag(tag) => {
            notify("tag");
            db.audit(
                &Actor::System,
                "rule.tag",
                &det.src.to_string(),
                &format!("tag={tag}; {rule_detail}"),
            )?;
            return Ok(());
        }
        DecisionAction::Block { .. } => {}
    }
    let DecisionAction::Block {
        duration,
        escalated,
    } = decision.action
    else {
        unreachable!("block action checked above")
    };

    if decision.dry_run || cfg.mode == Mode::Observe {
        stats.observed.fetch_add(1, Ordering::Relaxed);
        notify(if decision.dry_run {
            "dry_run"
        } else {
            "observed"
        });
        let action = if decision.dry_run {
            "rule.dry_run"
        } else {
            "detection.would_block"
        };
        db.audit(
            &Actor::System,
            action,
            &det.src.to_string(),
            &format!(
                "{rule_detail} duration={duration} escalated={escalated} detector={}",
                det.detector
            ),
        )?;
        return Ok(());
    }

    let strike = db.bump_strike(det.src, &det.summary(), now)?;
    let (block, created) = db.upsert_block_with_rule(
        det.src,
        duration,
        strike,
        &format!("{}: {}", det.detector, det.detector.title()),
        Some(det.detector),
        det.id,
        decision.rule_id,
        now,
    )?;
    let enforced = match enforcer.add(det.src) {
        Ok(()) => {
            db.set_enforced(block.id, true)?;
            true
        }
        Err(e) => {
            tracing::error!(ip = %det.src, error = %e, "failed to apply block; will retry");
            db.set_enforced(block.id, false)?;
            false
        }
    };
    if created {
        stats.blocks.fetch_add(1, Ordering::Relaxed);
    }
    notify("blocked");
    db.audit(
        &Actor::System,
        if created {
            "block.create"
        } else {
            "block.extend"
        },
        &det.src.to_string(),
        &format!(
            "strike={strike} duration={duration} escalated={escalated} enforced={enforced} detector={} {rule_detail}",
            det.detector
        ),
    )?;
    tracing::warn!(
        ip = %det.src,
        strike,
        %duration,
        enforced,
        detector = %det.detector,
        rule = winner,
        rule_name = %winner_name,
        "{}",
        if created { "blocked" } else { "extended block" }
    );
    Ok(())
}

/// Expiry, retry of unapplied blocks, decay, prune and drift repair.
fn scheduler_loop(
    db_path: PathBuf,
    enforcer: Arc<dyn Enforcer>,
    cfg: Config,
    stop: Arc<AtomicBool>,
    _stats: Arc<Stats>,
    rules: RulesHandle,
) {
    let db = match Db::open(&db_path) {
        Ok(db) => db,
        Err(e) => {
            tracing::error!("scheduler cannot open database: {e}");
            return;
        }
    };
    let mut last_decay = Instant::now();
    let mut last_prune = Instant::now();
    let mut last_drift = Instant::now();
    let mut rules_version = db.rules_version().unwrap_or(0);
    let mut sampler = crate::system::Sampler::new();
    let mut last_sample = Instant::now();
    let mut first_sample = true;

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(500));

        if first_sample || last_sample.elapsed() >= Duration::from_secs(30) {
            let sample = sampler.sample(&db_path);
            if let Err(e) =
                db.insert_system_sample(Utc::now(), sample.cpu_pct, sample.rss_mb, sample.db_mb)
            {
                tracing::warn!("resource sample store failed: {e}");
            }
            // Keep a week so the 24-hour dialog has margin for clock skew.
            let _ = db.prune_system_samples(Utc::now() - chrono::Duration::days(7));
            last_sample = Instant::now();
            first_sample = false;
        }

        // Pick up rule edits made by the UI or CLI. A failed load keeps the
        // last-good in-memory set and records why (FR-126).
        let current_version = db.rules_version().unwrap_or(rules_version);
        if current_version != rules_version {
            match db.list_rules() {
                Ok(list) if !list.is_empty() => match RuleSet::compile(list, &cfg.ladder.steps) {
                    Ok(set) => {
                        *rules.write().unwrap_or_else(|poison| poison.into_inner()) = set;
                        tracing::info!(version = current_version, "rules reloaded");
                    }
                    Err(errors) => {
                        let detail = errors
                            .iter()
                            .map(|error| error.to_string())
                            .collect::<Vec<_>>()
                            .join("; ");
                        tracing::error!(errors = %detail, "rule reload rejected; keeping the last-good set");
                        let _ = db.audit(&Actor::System, "rules.load_failed", "", &detail);
                    }
                },
                Ok(_) => {
                    let _ = db.seed_rules_if_empty();
                    let _ = db.audit(
                        &Actor::System,
                        "rules.reload",
                        "",
                        "no stored rules; shipped defaults restored",
                    );
                }
                Err(e) => {
                    tracing::error!("cannot read rules during reload: {e}");
                }
            }
            rules_version = current_version;
        }

        // Expiry: remove from the kernel first, then mark the row. If the
        // kernel call fails the block stays active and is retried.
        match db.expired_blocks(Utc::now(), 512) {
            Ok(blocks) => {
                for b in blocks {
                    match enforcer.remove(b.src) {
                        Ok(()) => {
                            let _ = db.mark_block_state(b.id, BlockState::Expired);
                            let _ = db.audit(
                                &Actor::System,
                                "block.expire",
                                &b.src.to_string(),
                                "expiry reached",
                            );
                            tracing::info!(ip = %b.src, "block expired");
                        }
                        Err(e) => {
                            tracing::warn!(ip = %b.src, error = %e, "expiry failed; will retry");
                        }
                    }
                }
            }
            Err(e) => tracing::error!("expiry query failed: {e}"),
        }

        // Blocks recorded but not applied (nftables was down when decided).
        if let Ok(pending) = db.list_unenforced() {
            for b in pending {
                match enforcer.add(b.src) {
                    Ok(()) => {
                        let _ = db.set_enforced(b.id, true);
                        tracing::info!(ip = %b.src, "applied previously unenforced block");
                    }
                    Err(e) => {
                        tracing::warn!(ip = %b.src, error = %e, "retrying unenforced block failed");
                        break;
                    }
                }
            }
        }

        if last_decay.elapsed() > Duration::from_secs(3600) {
            last_decay = Instant::now();
            if cfg.ladder.strike_decay_days > 0 {
                match db.decay_strikes(cfg.ladder.strike_decay_days, Utc::now()) {
                    Ok(n) if n > 0 => tracing::info!(count = n, "strike decay applied"),
                    Ok(_) => {}
                    Err(e) => tracing::error!("strike decay failed: {e}"),
                }
            }
        }

        if last_prune.elapsed() > Duration::from_secs(86_400) {
            last_prune = Instant::now();
            match db.prune(&cfg, Utc::now()) {
                Ok((d, b)) => tracing::info!(detections = d, blocks = b, "retention prune"),
                Err(e) => tracing::error!("prune failed: {e}"),
            }
            match db.prune_logs(
                cfg.logs.raw_retention_days,
                cfg.logs.raw_max_bytes,
                Utc::now(),
            ) {
                Ok(n) if n > 0 => {
                    tracing::info!(events = n, "log retention prune");
                    // Persist a cumulative count so the Logs page can show how
                    // many raw events retention has discarded (FR-306).
                    let total = db
                        .log_state("log.pruned")
                        .ok()
                        .flatten()
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        .saturating_add(n as u64);
                    let _ = db.set_log_state("log.pruned", &serde_json::json!(total));
                }
                Ok(_) => {}
                Err(e) => tracing::error!("log prune failed: {e}"),
            }
            let alert_days = db
                .get_setting("alerts.retention_days")
                .ok()
                .flatten()
                .and_then(|value| value.as_u64())
                .unwrap_or(cfg.alerts.retention_days);
            match db.prune_alerts(alert_days, Utc::now()) {
                Ok(n) if n > 0 => tracing::info!(alerts = n, "alert queue prune"),
                Ok(_) => {}
                Err(e) => tracing::error!("alert queue prune failed: {e}"),
            }
            if let Err(e) = db.optimize() {
                tracing::warn!("database optimisation skipped: {e}");
            }
        }

        if last_drift.elapsed() > Duration::from_secs(30) {
            last_drift = Instant::now();
            if let Err(e) = enforcer.ensure() {
                tracing::error!("enforcement table check failed: {e}");
            }
        }
    }
}

fn install_signal_handlers(stop: &Arc<AtomicBool>) -> Result<()> {
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, stop.clone())
            .map_err(|e| Error::Other(format!("cannot install signal handler: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_CONFIG_TOML;
    use crate::model::Proto;
    use crate::rules::{Rule, RuleAction, RuleMatch, Severity};
    use std::path::Path;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rustips-daemon-{}-{}-{}",
            std::process::id(),
            name,
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn detection(src: &str) -> Detection {
        Detection {
            detector: crate::model::Detector::VerticalScan,
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
            id: None,
        }
    }

    fn rule(id: u32, action: RuleAction, dry_run: bool) -> Rule {
        Rule {
            id,
            name: format!("rule {id}"),
            description: String::new(),
            enabled: true,
            priority: 100,
            severity: Severity::Warning,
            dry_run,
            when: RuleMatch::default(),
            action,
        }
    }

    #[test]
    fn a_rule_block_is_recorded_with_provenance() {
        let dir = temp_dir("block");
        let mut cfg = Config::parse(Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
        cfg.mode = Mode::Enforce;
        let db = Db::open(&dir.join("db")).unwrap();
        let set = RuleSet::compile(
            vec![rule(
                7,
                RuleAction::BlockTemp {
                    duration: "2h".into(),
                },
                false,
            )],
            &cfg.ladder.steps,
        )
        .unwrap();
        let rules: RulesHandle = Arc::new(RwLock::new(set));
        let stats = Arc::new(Stats::new());
        let enforcer: Arc<dyn Enforcer> = Arc::new(DryRunEnforcer);
        let geo = crate::geo::empty_handle();
        record_detection(
            &db,
            &cfg,
            &[],
            &enforcer,
            &stats,
            &rules,
            &geo,
            detection("203.0.113.30"),
            Utc::now(),
        )
        .unwrap();
        let block = db
            .active_block("203.0.113.30".parse().unwrap())
            .unwrap()
            .expect("block");
        assert_eq!(block.rule_id, Some(7));
        assert_eq!(block.strike, 1);
        let audit = db.recent_audit_full(5).unwrap();
        assert!(audit.iter().any(
            |(_, _, action, _, detail)| action == "block.create" && detail.contains("rules=7")
        ));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn allow_and_dry_run_never_block() {
        for (name, action, dry_run, expected) in [
            ("allow", RuleAction::Allow, false, "rule.allow"),
            ("dry", RuleAction::BlockPermanent, true, "rule.dry_run"),
        ] {
            let dir = temp_dir(name);
            let mut cfg = Config::parse(Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
            cfg.mode = Mode::Enforce;
            let db = Db::open(&dir.join("db")).unwrap();
            let set = RuleSet::compile(vec![rule(9, action, dry_run)], &cfg.ladder.steps).unwrap();
            let rules: RulesHandle = Arc::new(RwLock::new(set));
            let stats = Arc::new(Stats::new());
            let enforcer: Arc<dyn Enforcer> = Arc::new(DryRunEnforcer);
            let geo = crate::geo::empty_handle();
            record_detection(
                &db,
                &cfg,
                &[],
                &enforcer,
                &stats,
                &rules,
                &geo,
                detection("203.0.113.31"),
                Utc::now(),
            )
            .unwrap();
            assert!(
                db.active_block("203.0.113.31".parse().unwrap())
                    .unwrap()
                    .is_none()
            );
            let audit = db.recent_audit_full(5).unwrap();
            assert!(
                audit.iter().any(|(_, _, action, _, _)| action == expected),
                "{audit:?}"
            );
            std::fs::remove_dir_all(dir).ok();
        }
    }

    #[test]
    fn disabled_detector_records_nothing() {
        let dir = temp_dir("disabled");
        let mut cfg = Config::parse(Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
        cfg.mode = Mode::Enforce;
        let db = Db::open(&dir.join("db")).unwrap();
        let rules: RulesHandle = Arc::new(RwLock::new(RuleSet::defaults(&cfg.ladder.steps)));
        let geo = crate::geo::empty_handle();
        let enforcer: Arc<dyn Enforcer> = Arc::new(DryRunEnforcer);
        let stats = Arc::new(Stats::new());
        db.set_detector_enabled(crate::model::Detector::VerticalScan, false)
            .unwrap();
        record_detection(
            &db,
            &cfg,
            &[],
            &enforcer,
            &stats,
            &rules,
            &geo,
            detection("203.0.113.46"),
            Utc::now(),
        )
        .unwrap();
        assert_eq!(db.detection_count().unwrap(), 0);
        assert!(
            db.active_block("203.0.113.46".parse().unwrap())
                .unwrap()
                .is_none()
        );
        assert_eq!(stats.detections_suppressed.load(Ordering::Relaxed), 1);

        db.set_detector_enabled(crate::model::Detector::VerticalScan, true)
            .unwrap();
        record_detection(
            &db,
            &cfg,
            &[],
            &enforcer,
            &stats,
            &rules,
            &geo,
            detection("203.0.113.47"),
            Utc::now(),
        )
        .unwrap();
        assert_eq!(db.detection_count().unwrap(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn repeat_detection_escalates_the_ladder() {
        let dir = temp_dir("escalate");
        let mut cfg = Config::parse(Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
        cfg.mode = Mode::Enforce;
        let db = Db::open(&dir.join("db")).unwrap();
        let rules: RulesHandle = Arc::new(RwLock::new(RuleSet::defaults(&cfg.ladder.steps)));
        let geo = crate::geo::empty_handle();
        let enforcer: Arc<dyn Enforcer> = Arc::new(DryRunEnforcer);
        let stats = Arc::new(Stats::new());
        let now = Utc::now();
        for offset in [0, 1] {
            record_detection(
                &db,
                &cfg,
                &[],
                &enforcer,
                &stats,
                &rules,
                &geo,
                detection("203.0.113.44"),
                now + chrono::Duration::seconds(offset),
            )
            .unwrap();
        }
        let block = db
            .active_block("203.0.113.44".parse().unwrap())
            .unwrap()
            .expect("block");
        assert_eq!(block.strike, 2);
        let remaining = block.expires_at.unwrap() - now;
        assert!(remaining >= chrono::Duration::hours(23));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn allowlisted_detection_never_blocks() {
        let dir = temp_dir("allowed");
        let mut cfg = Config::parse(Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
        cfg.mode = Mode::Enforce;
        let db = Db::open(&dir.join("db")).unwrap();
        let rules: RulesHandle = Arc::new(RwLock::new(RuleSet::defaults(&cfg.ladder.steps)));
        let geo = crate::geo::empty_handle();
        let enforcer: Arc<dyn Enforcer> = Arc::new(DryRunEnforcer);
        let stats = Arc::new(Stats::new());
        let allow = vec![crate::net::Cidr::parse("203.0.113.0/24").unwrap()];
        record_detection(
            &db,
            &cfg,
            &allow,
            &enforcer,
            &stats,
            &rules,
            &geo,
            detection("203.0.113.45"),
            Utc::now(),
        )
        .unwrap();
        assert!(
            db.active_block("203.0.113.45".parse().unwrap())
                .unwrap()
                .is_none()
        );
        let audit = db.recent_audit_full(5).unwrap();
        assert!(
            audit
                .iter()
                .any(|(_, _, action, _, _)| action == "detection.allowed")
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn observe_mode_records_but_does_not_strike() {
        let dir = temp_dir("observe");
        let mut cfg = Config::parse(Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
        cfg.mode = Mode::Observe;
        let db = Db::open(&dir.join("db")).unwrap();
        let rules: RulesHandle = Arc::new(RwLock::new(RuleSet::defaults(&cfg.ladder.steps)));
        let stats = Arc::new(Stats::new());
        let enforcer: Arc<dyn Enforcer> = Arc::new(DryRunEnforcer);
        let geo = crate::geo::empty_handle();
        record_detection(
            &db,
            &cfg,
            &[],
            &enforcer,
            &stats,
            &rules,
            &geo,
            detection("203.0.113.32"),
            Utc::now(),
        )
        .unwrap();
        assert!(
            db.active_block("203.0.113.32".parse().unwrap())
                .unwrap()
                .is_none()
        );
        assert_eq!(db.strike_count("203.0.113.32".parse().unwrap()).unwrap(), 0);
        assert_eq!(stats.observed.load(Ordering::Relaxed), 1);
        std::fs::remove_dir_all(dir).ok();
    }
}
