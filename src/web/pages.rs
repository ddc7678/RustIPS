//! Server-rendered HTML. Every value that comes from storage or a request is
//! escaped, and no page emits inline script or style, so a strict
//! Content-Security-Policy applies everywhere (FR-187).
//!
//! The pages are plain functions returning `String`; the HTTP layer in
//! `mod.rs` decides the status code and headers.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};

use crate::config::{BlockDuration, Config, Mode, UnblockEffect};
use crate::countries::{CountryColor, CountryColors};
use crate::db::SystemPoint;
use crate::geo::GeoData;
use crate::logs::LogEvent;
use crate::model::{AllowlistEntry, Block, BlockState, Detection, Detector, Strike};
use crate::params::{self, ParamKind};
use crate::rules::{Decision, DecisionAction, Rule, RuleError, RuleForm, RuleRevision};

/// Per-request identity shared by every page and fragment.
pub struct Page<'a> {
    pub user: &'a str,
    pub csrf: &'a str,
    pub breakglass: bool,
    pub mode: Mode,
    pub bind: SocketAddr,
    pub version: &'a str,
}

impl Page<'_> {
    fn non_loopback(&self) -> bool {
        !self.bind.ip().is_loopback()
    }
}

/// Data shown on the dashboard. The live fields are refreshed by `app.js`.
pub struct Dash<'a> {
    pub packets: u64,
    pub bytes: u64,
    /// Persisted detections, matching the Recent detections table.
    pub detections: u64,
    /// Detections observed by this daemon process.
    pub detections_run: u64,
    pub blocks: u64,
    pub active_blocks: i64,
    pub detections_last_min: i64,
    pub blocks_last_min: i64,
    pub drops: u64,
    pub kernel_packets: u64,
    pub uptime_secs: u64,
    pub recent: &'a [Detection],
    pub top_sources: &'a [(String, i64)],
    pub top_ports: &'a [(i64, i64)],
    pub system_hour: &'a [SystemPoint],
}

pub fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn time(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Render a source address as a button that opens the per-IP history dialog.
pub fn ip_link(ip: IpAddr) -> String {
    if ip.is_unspecified() {
        return esc(&ip.to_string());
    }
    let text = esc(&ip.to_string());
    format!(r#"<button type="button" class="ip-link" data-ip="{text}">{text}</button>"#)
}

pub fn ip_text_or_link(value: &str) -> String {
    match value.parse::<IpAddr>() {
        Ok(ip) => ip_link(ip),
        Err(_) => esc(value),
    }
}

/// Country badge used next to source addresses. The default styles come from
/// the same `.tag` class as detector IDs; custom colors are generated from
/// Settings in `/assets/country-colors.css`.
pub fn country_badge(code: &str) -> String {
    let code = code.trim();
    if code.is_empty() {
        return String::new();
    }
    let code = esc(code);
    format!(r#"<span class="tag country-tag country-{code}">{code}</span>"#)
}

pub fn ip_with_country(ip: IpAddr, geo: &GeoData) -> String {
    let mut out = ip_link(ip);
    if let Some(country) = geo.lookup(ip).country {
        out.push(' ');
        out.push_str(&country_badge(&country));
    }
    out
}

pub fn ip_text_with_country(value: &str, geo: &GeoData) -> String {
    match value.parse::<IpAddr>() {
        Ok(ip) => ip_with_country(ip, geo),
        Err(_) => esc(value),
    }
}

fn duration_label(duration: BlockDuration) -> String {
    match duration {
        BlockDuration::Permanent => "permanent".into(),
        BlockDuration::Temporary(secs) => {
            if secs % 86_400 == 0 {
                format!("{}d", secs / 86_400)
            } else if secs % 3_600 == 0 {
                format!("{}h", secs / 3_600)
            } else if secs % 60 == 0 {
                format!("{}m", secs / 60)
            } else {
                format!("{secs}s")
            }
        }
    }
}

fn human_bytes(bytes: u64) -> String {
    let mut value = bytes as f64;
    let mut unit = "B";
    for next in ["KiB", "MiB", "GiB", "TiB"] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    if unit == "B" {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {unit}")
    }
}

fn csrf_input(page: &Page<'_>) -> String {
    format!(
        r#"<input type="hidden" name="csrf" value="{}">"#,
        esc(page.csrf)
    )
}

fn remaining(block: &Block, now: DateTime<Utc>) -> String {
    match block.expires_at {
        None => "permanent".into(),
        Some(expiry) if expiry <= now => "expiring".into(),
        Some(expiry) => {
            let secs = (expiry - now).num_seconds().max(0);
            if secs >= 86_400 {
                format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3_600)
            } else if secs >= 3_600 {
                format!("{}h {}m", secs / 3_600, (secs % 3_600) / 60)
            } else {
                format!("{}m", (secs / 60).max(1))
            }
        }
    }
}

fn short_metadata(det: &Detection) -> String {
    let mut text = serde_json::to_string(&det.metadata).unwrap_or_default();
    if text.len() > 160 {
        text.truncate(157);
        text.push_str("...");
    }
    text
}

// ------------------------------------------------------------------- layout

fn nav_item(active: &str, href: &str, label: &str) -> String {
    let class = if active == href { "active" } else { "" };
    format!(
        r#"<a href="{href}" class="{class}">{label}</a>"#,
        href = esc(href),
        class = class,
        label = label
    )
}

fn nav_group(active: &str, label: &str, items: &[(&str, &str)]) -> String {
    let links: Vec<String> = items
        .iter()
        .map(|(href, text)| nav_item(active, href, text))
        .collect();
    format!(
        r#"<details class="nav-group" open><summary class="nav-head">{}</summary><div class="nav-links">{}</div></details>"#,
        esc(label),
        links.join("")
    )
}

fn shell(page: &Page<'_>, active: &str, title: &str, body: &str) -> String {
    let mut banners = String::new();
    if page.non_loopback() {
        let _ = write!(
            banners,
            r#"<div class="banner danger"><strong>Remote binding.</strong> This UI is listening on <span class="mono">{bind}</span>, not loopback. Use an SSH tunnel or put TLS in front of it.</div>"#,
            bind = esc(&page.bind.to_string())
        );
    }
    if page.mode == Mode::Observe {
        banners.push_str(
            r#"<div class="banner warn"><strong>Observe mode.</strong> Detections are recorded but nothing is blocked.</div>"#,
        );
    }
    if page.breakglass {
        banners.push_str(
            r#"<div class="banner danger"><strong>Break-glass session.</strong> PAM was bypassed. Restore authentication and log in normally.</div>"#,
        );
    }

    let who = if page.breakglass {
        format!(
            "{} <span class=\"tag danger\">break-glass</span>",
            esc(page.user)
        )
    } else {
        esc(page.user)
    };

    let nav = [
        nav_group(
            active,
            "Monitoring",
            &[
                ("/", "Dashboard"),
                ("/detections", "Detections"),
                ("/logs", "Logs"),
            ],
        ),
        nav_group(
            active,
            "Detection",
            &[("/detectors", "Detectors"), ("/rules", "Disposition rules")],
        ),
        nav_group(
            active,
            "Enforcement",
            &[
                ("/blocks", "Active blocks"),
                ("/history", "History"),
                ("/strikes", "Strikes"),
                ("/allowlist", "Allowlist"),
            ],
        ),
        nav_group(
            active,
            "System",
            &[
                ("/alerts", "Alerts"),
                ("/settings", "Settings"),
                ("/audit", "Audit"),
            ],
        ),
    ]
    .join("\n");

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — RustIPS</title>
<script src="/assets/theme.js"></script>
<link rel="stylesheet" href="/assets/app.css">
<link rel="stylesheet" href="/assets/country-colors.css">
<script src="/assets/app.js" defer></script>
</head>
<body data-live="1">
<div class="layout">
<aside class="sidebar">
<a class="brand" href="/">RustIPS</a>
<nav class="side-nav">
{nav}
</nav>
<div class="sidebar-foot">RustIPS: {version}</div>
</aside>
<div class="content">
<header class="topbar">
<div class="whoami">
<span>{who}</span>
<button type="button" id="theme-toggle" class="small ghost" aria-label="Toggle theme">theme</button>
<form method="post" action="/logout" class="inline">{csrf}<button class="small ghost">Log out</button></form>
</div>
</header>
{banners}
<main>
{body}
</main>
<footer><a href="/healthz">health</a> · <a href="/readyz">readiness</a></footer>
</div>
</div>
<dialog id="ip-dialog" class="ip-dialog" aria-labelledby="ip-dialog-title">
<div class="ip-dialog-head">
<h2 id="ip-dialog-title">IP history</h2>
<button type="button" class="small ghost" data-ip-close>Close</button>
</div>
<div id="ip-dialog-body" class="ip-dialog-body"><p class="hint">Loading…</p></div>
</dialog>
<dialog id="system-dialog" class="ip-dialog system-dialog" aria-labelledby="system-dialog-title">
<div class="ip-dialog-head">
<h2 id="system-dialog-title">RustIPS resources — last 24 hours</h2>
<button type="button" class="small ghost" data-system-close>Close</button>
</div>
<div id="system-dialog-body" class="ip-dialog-body"><p class="hint">Loading…</p></div>
</dialog>
</body>
</html>
"#,
        title = esc(title),
        version = esc(page.version),
        nav = nav,
        who = who,
        csrf = csrf_input(page),
        banners = banners,
        body = body,
    )
}

pub fn message(page: &Page<'_>, title: &str, text: &str, status_hint: &str) -> String {
    let body = format!(
        r#"<section class="panel"><h1>{title}</h1><p>{text}</p><p class="hint">{hint}</p></section>"#,
        title = esc(title),
        text = esc(text),
        hint = esc(status_hint)
    );
    shell(page, "", title, &body)
}

// -------------------------------------------------------------------- login

pub fn login(
    version: &str,
    service: &str,
    pam_ready: bool,
    error: Option<&str>,
    notice: Option<&str>,
) -> String {
    let mut notes = String::new();
    if let Some(text) = error {
        let _ = write!(notes, r#"<p class="flash bad">{}</p>"#, esc(text));
    }
    if let Some(text) = notice {
        let _ = write!(notes, r#"<p class="flash">{}</p>"#, esc(text));
    }
    if !pam_ready {
        let _ = write!(
            notes,
            r#"<p class="flash warn">PAM service <span class="mono">{}</span> is not installed. Only a break-glass token can log in until it is.</p>"#,
            esc(service)
        );
    }

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log in — RustIPS</title>
<script src="/assets/theme.js"></script>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body class="login-body">
<main class="login">
<h1>RustIPS <span class="version">{version}</span></h1>
<p class="hint">Sign in with your <strong>system account</strong>. Membership of the
administrator group is required.</p>
{notes}
<form method="post" action="/login" autocomplete="on">
<label for="user">Username</label>
<input id="user" name="user" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus>
<label for="pass">Password</label>
<input id="pass" name="pass" type="password" autocomplete="current-password">
<details class="breakglass">
<summary>Break-glass token</summary>
<label for="token">One-time root token</label>
<input id="token" name="token" autocomplete="off" spellcheck="false" class="mono">
<p class="hint">Created on the host with <span class="mono">sudo rustips auth breakglass</span>.
Leave the password empty when using a token.</p>
</details>
<button class="primary" type="submit">Log in</button>
</form>
<footer>Bound loopback by default · use an SSH tunnel · RustIPS {version}</footer>
</main>
</body>
</html>
"#,
        version = esc(version),
        notes = notes,
    )
}

// ---------------------------------------------------------------- dashboard

fn stat(label: &str, field: &str, value: &str, hint: &str) -> String {
    format!(
        r#"<div class="stat"><div class="stat-label">{label}</div>
<div class="stat-value" data-field="{field}">{value}</div>
<div class="stat-hint">{hint}</div></div>"#,
        label = esc(label),
        field = esc(field),
        value = esc(value),
        hint = esc(hint)
    )
}

fn downsample(points: &[SystemPoint], max: usize) -> Vec<SystemPoint> {
    if points.len() <= max {
        return points.to_vec();
    }
    let bucket = points.len().div_ceil(max);
    points
        .chunks(bucket)
        .map(|chunk| {
            let n = chunk.len() as f64;
            SystemPoint {
                ts: chunk.last().map(|point| point.ts).unwrap_or_else(Utc::now),
                cpu_pct: chunk.iter().map(|point| point.cpu_pct).sum::<f64>() / n,
                rss_mb: chunk.iter().map(|point| point.rss_mb).sum::<f64>() / n,
                db_mb: chunk.iter().map(|point| point.db_mb).sum::<f64>() / n,
            }
        })
        .collect()
}

fn system_card(
    points: &[SystemPoint],
    label: &str,
    unit: &str,
    value: fn(&SystemPoint) -> f64,
    class: &str,
    range_label: &str,
    expanded: bool,
) -> String {
    let samples = downsample(points, if expanded { 240 } else { 60 });
    let current = samples.last().map(value).unwrap_or(0.0);
    let peak = samples.iter().map(value).fold(0.0, f64::max);
    let max = if class == "cpu" {
        (peak.max(10.0) * 1.1).ceil()
    } else {
        (peak.max(1.0) * 1.15).max(1.0)
    };
    let mut coords = Vec::with_capacity(samples.len());
    for (index, point) in samples.iter().enumerate() {
        let x = if samples.len() <= 1 {
            50.0
        } else {
            index as f64 / (samples.len() - 1) as f64 * 100.0
        };
        let y = 100.0 - (value(point) / max * 100.0).clamp(0.0, 100.0);
        coords.push(format!("{x:.2},{y:.2}"));
    }
    let line = coords.join(" ");
    let area = if line.is_empty() {
        String::new()
    } else {
        format!("0,100 {line} 100,100")
    };
    let current_text = if unit == "%" {
        format!("{current:.1}%")
    } else {
        format!("{current:.1} MB")
    };
    let peak_text = if unit == "%" {
        format!("{peak:.1}%")
    } else {
        format!("{peak:.1} MB")
    };
    let body = if samples.is_empty() {
        format!(
            r#"<div class="system-card-head"><span>{label}</span><strong>—</strong></div>
<div class="system-empty hint">No samples yet; the daemon records one every 30 seconds.</div>"#
        )
    } else {
        format!(
            r#"<div class="system-card-head"><span>{label}</span><strong>{current_text}</strong></div>
<svg class="spark" viewBox="0 0 100 100" preserveAspectRatio="none" role="img" aria-label="{label} last {range_label}">
<polygon class="spark-area spark-{class}" points="{area}"></polygon>
<polyline class="spark-line spark-{class}" points="{line}"></polyline>
</svg>
<div class="hint">last {range_label} · peak {peak_text}</div>"#
        )
    };
    if expanded {
        format!(r#"<div class="system-card system-card-large">{body}</div>"#)
    } else {
        format!(
            r#"<button type="button" class="system-card" data-system-dialog="24">{body}</button>"#
        )
    }
}

pub fn system_graphs(points: &[SystemPoint], range_label: &str, expanded: bool) -> String {
    format!(
        r#"<div class="system-grid">
{}{}{}
</div>"#,
        system_card(
            points,
            "CPU",
            "%",
            |point| point.cpu_pct,
            "cpu",
            range_label,
            expanded
        ),
        system_card(
            points,
            "Memory",
            "MB",
            |point| point.rss_mb,
            "mem",
            range_label,
            expanded
        ),
        system_card(
            points,
            "Database storage",
            "MB",
            |point| point.db_mb,
            "db",
            range_label,
            expanded
        ),
    )
}

pub fn system_history(points: &[SystemPoint], hours: u64) -> String {
    let range = match (points.first(), points.last()) {
        (Some(first), Some(last)) => format!("{} → {}", time(first.ts), time(last.ts)),
        _ => "no samples yet".into(),
    };
    format!(
        r#"<div class="system-history">
<p class="hint">Sampled every 30 seconds · {range}</p>
{graphs}
<p class="hint">CPU is process CPU time as a percentage of one core; memory is the
resident set; database storage includes the main SQLite file and its WAL/SHM
sidecars.</p>
</div>"#,
        graphs = system_graphs(points, &format!("{hours} hours"), true),
    )
}

pub fn dashboard(page: &Page<'_>, dash: &Dash<'_>, geo: &GeoData) -> String {
    let mut body = String::new();
    let _ = write!(
        body,
        r#"<section class="stats">
{packets}
{bandwidth}
{detections}
{active}
{drops}
{uptime}
</section>"#,
        packets = stat(
            "Packets captured",
            "packets",
            &dash.packets.to_string(),
            "total since start"
        ),
        bandwidth = stat(
            "Throughput",
            "bandwidth",
            &human_bytes(dash.bytes),
            "total captured; live rate after the first poll"
        ),
        detections = stat(
            "Detections",
            "detections",
            &dash.detections.to_string(),
            &format!("{} in the last minute", dash.detections_last_min)
        ),
        active = stat(
            "Active blocks",
            "active-blocks",
            &dash.active_blocks.to_string(),
            &format!(
                "{} total since start · {} started in the last minute",
                dash.blocks, dash.blocks_last_min
            )
        ),
        drops = stat(
            "Capture drops",
            "drops",
            &dash.drops.to_string(),
            &format!("{} packets seen by the kernel", dash.kernel_packets)
        ),
        uptime = stat(
            "Uptime",
            "uptime",
            &format!("{}m", dash.uptime_secs / 60),
            &format!("mode: {}", page.mode)
        ),
    );

    let _ = write!(
        body,
        r#"<section class="panel">
<h2>RustIPS resources <span class="hint">last hour</span></h2>
<div id="system-graphs">{graphs}</div>
<p class="hint">Click a graph for the expanded 24-hour view. Samples are recorded every 30 seconds.</p>
</section>"#,
        graphs = system_graphs(dash.system_hour, "hour", false),
    );

    let _ = write!(
        body,
        r#"<section class="panel">
<h2>Live</h2>
<p class="hint">Detections since start: <span data-field="detections-run">{det_run}</span> ·
detections per minute: <span data-field="det-per-min">{det_min}</span> ·
blocks per minute: <span data-field="blocks-per-min">{block_min}</span> ·
packets per second: <span data-field="pps">—</span> ·
kernel packets: <span class="mono" data-field="kernel-packets">{kernel}</span></p>
</section>"#,
        det_run = dash.detections_run,
        det_min = dash.detections_last_min,
        block_min = dash.blocks_last_min,
        kernel = esc(&dash.kernel_packets.to_string()),
    );

    let mut recent = String::new();
    for det in dash.recent {
        let _ = write!(
            recent,
            r#"<tr><td class="mono">{ts}</td><td><span class="tag">{id}</span> {title}</td><td class="mono">{src}</td><td class="mono">{dst}</td><td>{count}</td></tr>"#,
            ts = esc(&time(det.first_seen)),
            id = det.detector,
            title = esc(det.detector.title()),
            src = ip_with_country(det.src, geo),
            dst = esc(&det.dst.map(|d| d.to_string()).unwrap_or_default()),
            count = det.count,
        );
    }
    let _ = write!(
        body,
        r#"<section class="panel">
<h2>Recent detections</h2>
<div class="scroll"><table>
<thead><tr><th>Time (UTC)</th><th>Detector</th><th>Source</th><th>Destination</th><th>Count</th></tr></thead>
<tbody id="recent-detections">{recent}</tbody>
</table></div>
</section>"#,
        recent = recent
    );

    let mut sources = String::new();
    for (src, count) in dash.top_sources {
        let _ = write!(
            sources,
            r#"<li><span class="mono">{}</span><span class="num">{}</span></li>"#,
            ip_text_with_country(src, geo),
            count
        );
    }
    let mut ports = String::new();
    for (port, count) in dash.top_ports {
        let _ = write!(
            ports,
            r#"<li><span class="mono">{}</span><span class="num">{}</span></li>"#,
            port, count
        );
    }
    let _ = write!(
        body,
        r#"<section class="grid2">
<div class="panel"><h2>Top sources <span class="hint">last hour</span></h2><ul class="rank" id="top-sources">{sources}</ul></div>
<div class="panel"><h2>Top targeted ports <span class="hint">last hour</span></h2><ul class="rank" id="top-ports">{ports}</ul></div>
</section>"#,
        sources = sources,
        ports = ports
    );

    let _ = write!(
        body,
        r#"<section class="panel"><h2>Health</h2>
<ul class="plain">
<li>Capture: kernel delivered <span class="mono">{kernel}</span> packets, dropped <span class="mono">{drops}</span>. A non-zero drop count means <span class="mono">capture.rcvbuf_bytes</span> should be raised.</li>
<li>GeoIP/ASN: managed under Rules. Country and ASN data are disposition-only and never used for detection.</li>
<li>Enforcement: {enforcement}.</li>
</ul></section>"#,
        kernel = esc(&dash.kernel_packets.to_string()),
        drops = esc(&dash.drops.to_string()),
        enforcement = if page.mode == Mode::Enforce {
            "nftables, input hook"
        } else {
            "dry run (observe mode)"
        }
    );

    shell(page, "/", "Dashboard", &body)
}

// --------------------------------------------------------------- detections

/// Data shown in the per-IP history dialog.
pub struct IpHistory<'a> {
    pub ip: IpAddr,
    pub country: Option<&'a str>,
    pub asn: Option<u32>,
    pub geo_loaded: bool,
    pub allowlisted: Option<&'a AllowlistEntry>,
    pub active_block: Option<&'a Block>,
    pub strike: Option<&'a Strike>,
    pub detections: &'a [Detection],
    pub detection_total: i64,
    pub blocks: &'a [Block],
    pub block_total: i64,
    pub log_events: &'a [(LogEvent, Option<String>)],
    pub log_total: i64,
    pub now: DateTime<Utc>,
}

pub fn ip_history(page: &Page<'_>, history: &IpHistory<'_>) -> String {
    let ip_text = history.ip.to_string();
    let country = match history.country {
        Some(code) => format!(r#"<span class="mono">{}</span>"#, esc(code)),
        None if history.geo_loaded => "unknown".to_string(),
        None => "GeoIP index not loaded".to_string(),
    };
    let asn = history
        .asn
        .map(|asn| format!(r#"<span class="mono">AS{asn}</span>"#))
        .unwrap_or_else(|| "unknown".into());

    let status = if let Some(block) = history.active_block {
        format!(
            r#"<div class="banner warn"><strong>Active block.</strong> {} · {}, strike {}</div>"#,
            esc(&remaining(block, history.now)),
            esc(block.reason.as_str()),
            block.strike
        )
    } else if let Some(entry) = history.allowlisted {
        format!(
            r#"<div class="banner warn"><strong>Allowlisted.</strong> {} ({})</div>"#,
            esc(&entry.label),
            if entry.implicit {
                "implicit"
            } else {
                "explicit"
            }
        )
    } else {
        String::new()
    };

    let already_permanent = history
        .active_block
        .map(|block| block.is_permanent())
        .unwrap_or(false);
    let block_action = if history.ip.is_unspecified()
        || history.allowlisted.is_some()
        || already_permanent
    {
        String::new()
    } else {
        format!(
            r#"<form method="post" action="/blocks/add" class="inline" data-confirm="Permanently block {ip}?">
{csrf}<input type="hidden" name="src" value="{ip}">
<input type="hidden" name="minutes" value="0">
<input type="hidden" name="reason" value="permanent block from IP history">
<button class="danger small">Permanently block</button></form>"#,
            ip = esc(&ip_text),
            csrf = csrf_input(page),
        )
    };

    let mut detection_rows = String::new();
    for det in history.detections {
        let dst = match (det.dst, det.dst_port) {
            (Some(dst), Some(port)) => format!("{dst}:{port}"),
            (Some(dst), None) => dst.to_string(),
            (None, _) => "—".into(),
        };
        let _ = write!(
            detection_rows,
            r#"<tr><td class="mono">{ts}</td><td><span class="tag">{id}</span> {title}</td>
<td class="mono">{dst}</td><td>{proto}</td><td>{count} / {window}s</td></tr>"#,
            ts = esc(&time(det.first_seen)),
            id = det.detector,
            title = esc(det.detector.title()),
            dst = esc(&dst),
            proto = det.proto.as_str(),
            count = det.count,
            window = det.window_secs,
        );
    }
    if detection_rows.is_empty() {
        detection_rows.push_str(
            r#"<tr><td colspan="5" class="hint">No stored detections for this address.</td></tr>"#,
        );
    }

    let mut block_rows = String::new();
    for block in history.blocks {
        let expiry = block
            .expires_at
            .map(time)
            .unwrap_or_else(|| "permanent".into());
        let _ = write!(
            block_rows,
            r#"<tr><td class="mono">{started}</td><td class="mono">{expiry}</td>
<td>{reason}</td><td>{detector}</td><td>{strike}</td><td>{state}</td>
<td class="mono">{rule}</td></tr>"#,
            started = esc(&time(block.started_at)),
            expiry = esc(&expiry),
            reason = esc(&block.reason),
            detector = block
                .detector
                .map(|detector| esc(detector.as_str()))
                .unwrap_or_else(|| "—".into()),
            strike = block.strike,
            state = esc(block.state.as_str()),
            rule = block
                .rule_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "—".into()),
        );
    }
    if block_rows.is_empty() {
        block_rows.push_str(
            r#"<tr><td colspan="7" class="hint">No stored blocks for this address.</td></tr>"#,
        );
    }

    let strike_section = match history.strike {
        Some(strike) => format!(
            r#"<table><thead><tr><th>Strikes</th><th>First seen (UTC)</th><th>Last seen (UTC)</th><th>Last reason</th></tr></thead>
<tbody><tr><td>{count}</td><td class="mono">{first}</td><td class="mono">{last}</td><td>{reason}</td></tr></tbody></table>"#,
            count = strike.count,
            first = esc(&time(strike.first_seen)),
            last = esc(&time(strike.last_seen)),
            reason = esc(&strike.last_reason),
        ),
        None => r#"<p class="hint">No strike history for this address.</p>"#.to_string(),
    };

    let mut log_rows = String::new();
    for (event, detector) in history.log_events {
        let identity = event
            .unit
            .as_deref()
            .or(event.identifier.as_deref())
            .unwrap_or("—");
        let message: String = event.message.chars().take(180).collect();
        let detection = detector
            .as_deref()
            .map(|id| format!(r#"<span class="tag">{}</span>"#, esc(id)))
            .unwrap_or_else(|| "—".into());
        let _ = write!(
            log_rows,
            r#"<tr><td class="mono">{ts}</td><td><span class="mono">{template}</span></td>
<td>{identity}</td><td>{user}</td><td>{message}</td><td>{detection}</td></tr>"#,
            ts = esc(&time(event.ts)),
            template = esc(&event.template),
            identity = esc(identity),
            user = esc(event.user.as_deref().unwrap_or("—")),
            message = esc(&message),
            detection = detection,
        );
    }
    if log_rows.is_empty() {
        log_rows.push_str(
            r#"<tr><td colspan="6" class="hint">No stored log events for this address.</td></tr>"#,
        );
    }

    let header_badge = history.country.map(country_badge).unwrap_or_default();
    format!(
        r#"<div class="ip-history">
<h2 class="mono">{ip} {header_badge}</h2>
{status}
<div class="ip-summary">
<div><span class="stat-label">Country (ISO)</span><div>{country}</div></div>
<div><span class="stat-label">ASN</span><div>{asn}</div></div>
<div><span class="stat-label">Detections</span><div>{detections_total}</div></div>
<div><span class="stat-label">Blocks</span><div>{blocks_total}</div></div>
<div><span class="stat-label">Log events</span><div>{logs_total}</div></div>
<div><span class="stat-label">Strikes</span><div>{strikes}</div></div>
</div>
{block_action}
<h3>Detections <span class="hint">latest {detection_shown} of {detections_total}</span></h3>
<div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Detector</th><th>Destination</th><th>Proto</th><th>Count</th></tr></thead>
<tbody>{detection_rows}</tbody></table></div>
<h3>Blocks <span class="hint">latest {block_shown} of {blocks_total}</span></h3>
<div class="scroll"><table><thead><tr><th>Started (UTC)</th><th>Expiry (UTC)</th><th>Reason</th><th>Detector</th><th>Strike</th><th>State</th><th>Rule</th></tr></thead>
<tbody>{block_rows}</tbody></table></div>
<h3>Strikes</h3>
{strike_section}
<h3>Log events <span class="hint">latest {log_shown} of {logs_total}</span></h3>
<div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Template</th><th>Unit / identifier</th><th>User</th><th>Message</th><th>Detection</th></tr></thead>
<tbody>{log_rows}</tbody></table></div>
</div>"#,
        ip = esc(&ip_text),
        status = status,
        country = country,
        asn = asn,
        detections_total = history.detection_total,
        blocks_total = history.block_total,
        logs_total = history.log_total,
        strikes = history.strike.map(|strike| strike.count).unwrap_or(0),
        block_action = block_action,
        detection_shown = history.detections.len(),
        block_shown = history.blocks.len(),
        log_shown = history.log_events.len(),
        detection_rows = detection_rows,
        block_rows = block_rows,
        strike_section = strike_section,
        log_rows = log_rows,
    )
}

pub fn detection_rows(page: &Page<'_>, rows: &[Detection], geo: &GeoData) -> String {
    let mut out = String::new();
    for det in rows {
        let dst = match (det.dst, det.dst_port) {
            (Some(dst), Some(port)) => format!("{dst}:{port}"),
            (Some(dst), None) => dst.to_string(),
            _ => "—".into(),
        };
        let has_source = det.has_source();
        let src_text = if has_source {
            det.src.to_string()
        } else {
            "—".into()
        };
        let src_display = if has_source {
            ip_with_country(det.src, geo)
        } else {
            "—".into()
        };
        let action = if has_source && !det.detector.is_alert_only() {
            format!(
                r#"<form method="post" action="/blocks/add" class="inline" data-confirm="Block {src} for one hour?">
{csrf}<input type="hidden" name="src" value="{src_raw}">
<input type="hidden" name="minutes" value="60">
<input type="hidden" name="reason" value="manual block from detections">
<button class="small">Block 1h</button></form>"#,
                src = esc(&src_text),
                src_raw = esc(&src_text),
                csrf = csrf_input(page),
            )
        } else {
            r#"<span class="hint">alert only</span>"#.to_string()
        };
        let _ = write!(
            out,
            r#"<tr>
<td class="mono">{ts}</td>
<td><span class="tag">{id}</span> {title}</td>
<td class="mono">{src}</td>
<td class="mono">{dst}</td>
<td>{proto}</td>
<td>{count} / {window}s</td>
<td><details><summary class="small">evidence</summary><code>{meta}</code></details></td>
<td>{action}</td>
</tr>"#,
            ts = esc(&time(det.first_seen)),
            id = det.detector,
            title = esc(det.detector.title()),
            src = src_display,
            dst = esc(&dst),
            proto = det.proto.as_str(),
            count = det.count,
            window = det.window_secs,
            meta = esc(&short_metadata(det)),
            action = action,
        );
    }
    out
}

pub fn detections(
    page: &Page<'_>,
    rows: &[Detection],
    page_no: u32,
    pages: u32,
    total: i64,
    detector: &str,
    geo: &GeoData,
) -> String {
    let mut options = String::from(r#"<option value="">All detectors</option>"#);
    for d in Detector::ALL {
        let selected = if d.as_str() == detector {
            " selected"
        } else {
            ""
        };
        let _ = write!(
            options,
            r#"<option value="{id}"{selected}>{id} — {title}</option>"#,
            id = d,
            selected = selected,
            title = esc(d.title())
        );
    }

    let mut pager = String::new();
    if page_no > 1 {
        let _ = write!(
            pager,
            r#"<a class="button small" href="/detections?detector={d}&page={p}">Previous</a>"#,
            d = esc(detector),
            p = page_no - 1
        );
    }
    if page_no < pages {
        let _ = write!(
            pager,
            r#"<a class="button small" href="/detections?detector={d}&page={p}">Next</a>"#,
            d = esc(detector),
            p = page_no + 1
        );
    }

    let body = format!(
        r#"<section class="panel">
<h1>Detections</h1>
<form method="get" action="/detections" class="filters">
<label for="detector">Detector</label>
<select id="detector" name="detector">{options}</select>
<button class="small">Apply</button>
<span class="hint">{total} matching events · page {page_no} of {pages}</span>
</form>
<div class="scroll"><table id="live-table-wrap">
<thead><tr><th>Time (UTC)</th><th>Detector</th><th>Source</th><th>Destination</th><th>Proto</th><th>Count</th><th>Evidence</th><th></th></tr></thead>
<tbody id="live-table">{rows}</tbody>
</table></div>
<div class="pager">{pager}</div>
<p class="hint">This table refreshes every 2 seconds.</p>
</section>"#,
        options = options,
        total = total,
        page_no = page_no,
        pages = pages,
        rows = detection_rows(page, rows, geo),
        pager = pager
    );
    shell(page, "/detections", "Detections", &body)
}

// ---------------------------------------------------------------------- logs

fn qs(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            b' ' => out.push('+'),
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

/// Runtime log-ingestion health and counters for the Logs page.
pub struct LogStatus<'a> {
    pub journal: Option<&'a serde_json::Value>,
    pub gap: Option<&'a serde_json::Value>,
    pub events_run: u64,
    pub dropped: u64,
    pub parse_errors: u64,
    pub pruned: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn logs(
    page: &Page<'_>,
    rows: &[(LogEvent, Option<String>)],
    page_no: u32,
    pages: u32,
    total: i64,
    origin: &str,
    search: &str,
    status: &LogStatus<'_>,
    geo: &GeoData,
) -> String {
    let mut body_rows = String::new();
    for (event, detector) in rows {
        let identity = event
            .unit
            .as_deref()
            .or(event.identifier.as_deref())
            .unwrap_or("—");
        let user = event.user.as_deref().unwrap_or("—");
        let source = event
            .src_ip
            .map(|ip| ip_with_country(ip, geo))
            .unwrap_or_else(|| "—".into());
        let priority = event
            .priority
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".into());
        let message: String = event.message.chars().take(180).collect();
        let http = match (&event.method, &event.path, event.status) {
            (Some(method), Some(path), Some(status)) => format!("{method} {path} {status}"),
            (None, Some(path), Some(status)) => format!("{path} {status}"),
            (Some(method), Some(path), None) => format!("{method} {path}"),
            (None, None, Some(status)) => status.to_string(),
            _ => "—".into(),
        };
        let detection = match detector {
            Some(detector) => format!(r#"<span class="tag">{}</span>"#, esc(detector)),
            None => "—".into(),
        };
        let _ = write!(
            body_rows,
            r#"<tr>
<td class="mono">{ts}</td>
<td>{origin}</td>
<td>{parser}</td>
<td><span class="mono">{template}</span></td>
<td>{identity}</td>
<td>{priority}</td>
<td>{user}</td>
<td class="mono">{source}</td>
<td class="mono">{http}</td>
<td>{message}</td>
<td>{detection}</td>
</tr>"#,
            ts = esc(&time(event.ts)),
            origin = event.origin.as_str(),
            parser = esc(&event.parser),
            template = esc(&event.template),
            identity = esc(identity),
            priority = priority,
            user = esc(user),
            source = esc(&source),
            http = esc(&http),
            message = esc(&message),
            detection = detection,
        );
    }

    let origin_option = |value: &str, label: &str| {
        format!(
            r#"<option value="{value}"{selected}>{label}</option>"#,
            value = value,
            label = label,
            selected = if origin == value { " selected" } else { "" }
        )
    };
    let mut pager = String::new();
    if page_no > 1 {
        let _ = write!(
            pager,
            r#"<a class="button small" href="/logs?origin={origin}&q={q}&page={p}">Previous</a>"#,
            origin = esc(origin),
            q = qs(search),
            p = page_no - 1
        );
    }
    if page_no < pages {
        let _ = write!(
            pager,
            r#"<a class="button small" href="/logs?origin={origin}&q={q}&page={p}">Next</a>"#,
            origin = esc(origin),
            q = qs(search),
            p = page_no + 1
        );
    }

    let health = match status.journal {
        Some(state) => {
            let status = state
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let error = state.get("error").and_then(|v| v.as_str()).unwrap_or("");
            if error.is_empty() {
                format!("journal ingestion: {status}")
            } else {
                format!("journal ingestion: {status} — {error}")
            }
        }
        None => "journal ingestion: no status recorded".into(),
    };
    let counters = format!(
        "this process: {} events stored · {} rate-limited · {} parse errors · {} pruned by retention (cumulative)",
        status.events_run, status.dropped, status.parse_errors, status.pruned
    );
    let gap = status
        .gap
        .and_then(|value| value.get("reason").and_then(|v| v.as_str()))
        .map(|reason| {
            format!(
                r#"<div class="banner warn">Cursor gap: {}</div>"#,
                esc(reason)
            )
        })
        .unwrap_or_default();

    let body = format!(
        r#"<section class="panel">
<h1>Host logs</h1>
<p class="hint">{health}</p>
<p class="hint">{counters}</p>
{gap}
<form method="get" action="/logs" class="filters">
<label for="origin">Origin</label>
<select id="origin" name="origin">
{all}{journal}{file}
</select>
<label for="q">Search</label>
<input id="q" name="q" value="{q}" placeholder="unit, identifier, template, message">
<button class="small">Apply</button>
<span class="hint">{total} matching events · page {page_no} of {pages}</span>
</form>
<div class="scroll"><table>
<thead><tr><th>Time (UTC)</th><th>Origin</th><th>Parser</th><th>Template</th><th>Unit / identifier</th><th>Pri</th><th>User</th><th>Source</th><th>HTTP</th><th>Message</th><th>Detection</th></tr></thead>
<tbody>{rows}</tbody>
</table></div>
<div class="pager">{pager}</div>
<p class="hint">Raw messages are truncated and redacted before storage. Detections link to the Logs evidence through their metadata.</p>
</section>"#,
        health = esc(&health),
        counters = esc(&counters),
        gap = gap,
        all = origin_option("", "All origins"),
        journal = origin_option("journal", "Journal"),
        file = origin_option("file", "File"),
        q = esc(search),
        total = total,
        page_no = page_no,
        pages = pages,
        rows = body_rows,
        pager = pager,
    );
    shell(page, "/logs", "Logs", &body)
}

// --------------------------------------------------------------------- rules

fn action_field_label(action: &DecisionAction) -> String {
    match action {
        DecisionAction::Allow => "allow".into(),
        DecisionAction::Alert => "alert".into(),
        DecisionAction::Tag(tag) => format!("tag {tag}"),
        DecisionAction::Block {
            duration,
            escalated,
        } => {
            if *escalated {
                format!("escalate → {duration}")
            } else {
                format!("block {duration}")
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn rules(
    page: &Page<'_>,
    rows: &[Rule],
    revisions: &[RuleRevision],
    geo: &crate::geo::GeoStatus,
    notice: Option<&str>,
    error: Option<&str>,
) -> String {
    let mut body = String::new();
    for rule in rows {
        let state = format!(
            r#"<form method="post" action="/rules/toggle" class="inline">
{csrf}<input type="hidden" name="id" value="{id}">
<input type="hidden" name="enable" value="{next}">
<button class="state-toggle {class}" title="{title}" aria-pressed="{pressed}">{label}</button>
</form>"#,
            csrf = csrf_input(page),
            id = rule.id,
            next = if rule.enabled { "no" } else { "yes" },
            class = if rule.enabled {
                "state-on"
            } else {
                "state-off"
            },
            title = if rule.enabled {
                "Click to disable this rule"
            } else {
                "Click to enable this rule"
            },
            pressed = rule.enabled,
            label = if rule.enabled { "Enabled" } else { "Disabled" },
        );
        let _ = write!(
            body,
            r#"<tr>
<td class="mono">{id}</td>
<td>{name}<div class="hint">{description}</div></td>
<td class="mono">{priority}</td>
<td>{severity}</td>
<td>{state}</td>
<td>{action}</td>
<td>{matched}</td>
<td class="mono">{updated}</td>
<td><a class="button small" href="/rules/edit?id={id}">Edit</a>
<a class="button small ghost" href="/rules/history?id={id}">History</a>
<form method="post" action="/rules/delete" class="inline" data-confirm="Delete rule {id}?">
{csrf}<input type="hidden" name="id" value="{id}">
<button class="small danger">Delete</button></form></td>
</tr>"#,
            id = rule.id,
            name = esc(&rule.name),
            description = esc(&rule.description),
            priority = rule.priority,
            severity = esc(rule.severity.as_str()),
            state = state,
            action = esc(&rule.action_label()),
            matched = esc(&rule.match_label()),
            updated = revisions
                .iter()
                .find(|revision| revision.rule_id == rule.id)
                .map(|revision| time(revision.changed_at))
                .unwrap_or_else(|| "—".into()),
            csrf = csrf_input(page),
        );
    }
    if rows.is_empty() {
        body.push_str(r#"<tr><td colspan="9" class="hint">No rules are stored; the shipped defaults will apply on the next start.</td></tr>"#);
    }

    let mut revision_rows = String::new();
    for revision in revisions.iter().take(20) {
        let _ = write!(
            revision_rows,
            r#"<tr><td class="mono">{ts}</td><td class="mono">{rule}</td><td>{rev}</td>
<td>{action}</td><td>{by}</td><td>{note}</td></tr>"#,
            ts = esc(&time(revision.changed_at)),
            rule = revision.rule_id,
            rev = revision.revision,
            action = esc(&revision.action),
            by = esc(&revision.changed_by),
            note = esc(&revision.note),
        );
    }

    let flash = notice
        .map(|text| format!(r#"<p class="flash">{}</p>"#, esc(text)))
        .unwrap_or_default();
    let failure = error
        .map(|text| format!(r#"<div class="banner danger">{}</div>"#, esc(text)))
        .unwrap_or_default();

    let geo_line = |label: &str, index: &Option<crate::geo::GeoIndexStatus>| match index {
        Some(index) => format!(
            "{label}: loaded (v4 {}, v6 {}, {}, sha256 {}, loaded {})",
            index.v4,
            index.v6,
            human_bytes(index.bytes),
            &index.sha256[..12.min(index.sha256.len())],
            time(index.loaded_at)
        ),
        None => format!("{label}: not configured"),
    };
    let geo_failure = geo
        .last_error
        .as_ref()
        .map(|error| format!("<br><strong>last error:</strong> {}", esc(error)))
        .unwrap_or_default();
    let geo_body = format!(
        r#"<p class="hint">{country}<br>{asn}<br>last check: {check}; last success: {success}; next check: {next}{failure}</p>
<form method="post" action="/rules/geo/check" class="inline">
{csrf}<button class="small">Check now</button></form>
<p class="hint">Country/ASN conditions are disposition-only and match only after a real detection.
The update runs in the background; refresh this page in a few seconds.</p>"#,
        country = esc(&geo_line("country", &geo.country)),
        asn = esc(&geo_line("asn", &geo.asn)),
        check = geo.last_check.map(time).unwrap_or_else(|| "never".into()),
        success = geo.last_success.map(time).unwrap_or_else(|| "never".into()),
        next = geo
            .next_check
            .map(time)
            .unwrap_or_else(|| "not scheduled".into()),
        failure = geo_failure,
        csrf = csrf_input(page),
    );

    let mut sample_rows = String::new();
    for sample in crate::rules::sample_geo_rules() {
        let _ = write!(
            sample_rows,
            r#"<tr><td>{name}</td><td>{action}</td><td>{matched}</td></tr>"#,
            name = esc(&sample.name),
            action = esc(&sample.action_label()),
            matched = esc(&sample.match_label()),
        );
    }
    let sample_body = format!(
        r#"<p class="hint">Five examples for country/ASN conditions. They are disabled on load
and only apply after a real detection. Review and enable them one at a time.</p>
<div class="scroll"><table><thead><tr><th>Name</th><th>Action</th><th>Match</th></tr></thead>
<tbody>{rows}</tbody></table></div>
<form method="post" action="/rules/samples/geo" class="inline">
{csrf}<button class="small">Load sample geo rules</button></form>"#,
        rows = sample_rows,
        csrf = csrf_input(page),
    );

    let page_body = format!(
        r#"<section class="panel">
<h1>Disposition rules</h1>
{flash}{failure}
<p class="hint">Every enabled rule is evaluated; matching actions combine by severity
(allow, then the longest block, then alert, then tag). Ties break on severity,
priority and the lowest rule ID. {count} rule(s) stored.</p>
<p><a class="button primary" href="/rules/new">New rule</a>
<a class="button small" href="/rules/check">Dry-run against recent detections</a>
<a class="button small ghost" href="/rules/export">Export JSON</a>
<a class="button small ghost" href="/rules/history">All revisions</a></p>
<div class="scroll"><table class="rules-table">
<thead><tr><th>ID</th><th>Name</th><th>Priority</th><th>Severity</th><th>State</th><th>Action</th><th>Match</th><th>Last change (UTC)</th><th></th></tr></thead>
<tbody>{body}</tbody></table></div>
</section>
<section class="panel">
<h2>GeoIP / ASN enrichment</h2>
{geo_body}
</section>
<section class="panel">
<h2>Sample geo rules</h2>
{sample_body}
</section>
<section class="panel">
<h2>Import rules</h2>
<p class="hint">Paste an exported rules document or a bare JSON array. The whole set is
validated before it replaces the stored rules.</p>
<form method="post" action="/rules/import">
{csrf}
<textarea name="document" rows="8" class="mono wide" placeholder='{{"format":"rustips-rules","version":1,"rules":[...]}}' required></textarea>
<button class="primary">Validate and import</button>
</form>
</section>
<section class="panel">
<h2>Recent revisions</h2>
<div class="scroll"><table>
<thead><tr><th>Time (UTC)</th><th>Rule</th><th>Rev</th><th>Action</th><th>By</th><th>Note</th></tr></thead>
<tbody>{revision_rows}</tbody></table></div>
</section>"#,
        flash = flash,
        failure = failure,
        count = rows.len(),
        body = body,
        csrf = csrf_input(page),
        revision_rows = revision_rows,
        geo_body = geo_body,
        sample_body = sample_body,
    );
    shell(page, "/rules", "Rules", &page_body)
}

pub fn rule_form(page: &Page<'_>, form: &RuleForm, error: Option<&str>) -> String {
    let checked = |value: bool| if value { " checked" } else { "" };
    let selected = |value: &str, current: &str| {
        if value == current { " selected" } else { "" }
    };
    let failure = error
        .map(|text| format!(r#"<div class="banner danger">{}</div>"#, esc(text)))
        .unwrap_or_default();
    let title = if form.id == 0 {
        "New rule".to_string()
    } else {
        format!("Edit rule {}", form.id)
    };
    let body = format!(
        r#"<section class="panel">
<h1>{title}</h1>
{failure}
<form method="post" action="/rules/save">
{csrf}
<input type="hidden" name="id" value="{id}">
<div class="row-form">
<label>Name <input name="name" value="{name}" maxlength="120" required></label>
<label>Priority <input name="priority" value="{priority}" class="short" required></label>
<label>Severity <select name="severity">
<option value="info"{sel_info}>info</option>
<option value="warning"{sel_warning}>warning</option>
<option value="critical"{sel_critical}>critical</option>
</select></label>
<label class="check"><input type="checkbox" name="enabled" value="yes"{enabled}>
Enabled</label>
<label class="check"><input type="checkbox" name="dry_run" value="yes"{dry_run}>
Dry run (never enforce this rule)</label>
</div>
<label>Description <textarea name="description" rows="2" class="wide">{description}</textarea></label>
<h2>Match</h2>
<div class="row-form">
<label>Detectors <input name="detectors" value="{detectors}" placeholder="DET-01, DET-16" class="wide"></label>
<label>Source CIDRs <input name="sources" value="{sources}" placeholder="203.0.113.0/24" class="wide"></label>
<label>Exclude CIDRs <input name="not_sources" value="{not_sources}" class="wide"></label>
<label>Ports <input name="ports" value="{ports}" placeholder="22, 8000-8100"></label>
<label>Protocols <input name="protocols" value="{protocols}" placeholder="tcp, udp"></label>
<label>Min count <input name="min_count" value="{min_count}" class="short"></label>
<label>Min strikes <input name="min_strikes" value="{min_strikes}" class="short"></label>
<label>Last strike within <input name="last_seen_within" value="{last_seen_within}" placeholder="90d" class="short"></label>
<label>Tags <input name="tags" value="{tags}" placeholder="prod, ssh"></label>
<label>Countries <input name="countries" value="{countries}" placeholder="CN, RU" class="wide"></label>
<label>Exclude countries <input name="not_countries" value="{not_countries}" class="wide"></label>
<label>ASNs <input name="asns" value="{asns}" placeholder="64500, 13335" class="wide"></label>
<label>Exclude ASNs <input name="not_asns" value="{not_asns}" class="wide"></label>
<label>UTC days <input name="days" value="{days}" placeholder="1,2,3,4,5 (0=Sun)" class="short"></label>
<label>Start (HH:MM) <input name="start" value="{start}" placeholder="08:00" class="short"></label>
<label>End (HH:MM) <input name="end" value="{end}" placeholder="18:00" class="short"></label>
<label class="check"><input type="checkbox" name="only_if_blocked" value="yes"{only_if_blocked}>
Only if already blocked</label>
</div>
<h2>Action</h2>
<div class="row-form">
<label>Action <select name="action">
<option value="alert"{sel_alert}>alert</option>
<option value="tag"{sel_tag}>tag</option>
<option value="allow"{sel_allow}>allow</option>
<option value="block_temp"{sel_block_temp}>block (temporary)</option>
<option value="block_permanent"{sel_block_perm}>block (permanent)</option>
<option value="escalate"{sel_escalate}>escalate (ladder)</option>
</select></label>
<label>Duration <input name="duration" value="{duration}" placeholder="1h" class="short"></label>
<label>Tag <input name="tag" value="{tag}" placeholder="suspect"></label>
<label>Ladder override <input name="ladder" value="{ladder}" placeholder="24h, 48h, permanent" class="wide"></label>
</div>
<p class="hint">For <span class="mono">escalate</span>, an empty ladder uses the configured
global ladder. For <span class="mono">block_temp</span>, use a duration such as
<span class="mono">1h</span>. Country/ASN conditions only match when the geo database is
loaded; they never trigger a detection by themselves.</p>
<div class="row-form">
<label>Revision note <input name="note" value="" placeholder="why this changed" class="wide"></label>
<button class="primary">Save rule</button>
<a class="button small ghost" href="/rules">Cancel</a>
</div>
</form>
</section>"#,
        title = esc(&title),
        failure = failure,
        csrf = csrf_input(page),
        id = form.id,
        name = esc(&form.name),
        priority = esc(&form.priority),
        description = esc(&form.description),
        detectors = esc(&form.detectors),
        sources = esc(&form.sources),
        not_sources = esc(&form.not_sources),
        ports = esc(&form.ports),
        protocols = esc(&form.protocols),
        min_count = esc(&form.min_count),
        min_strikes = esc(&form.min_strikes),
        last_seen_within = esc(&form.last_seen_within),
        tags = esc(&form.tags),
        countries = esc(&form.countries),
        not_countries = esc(&form.not_countries),
        asns = esc(&form.asns),
        not_asns = esc(&form.not_asns),
        days = esc(&form.days),
        start = esc(&form.start),
        end = esc(&form.end),
        duration = esc(&form.duration),
        tag = esc(&form.tag),
        ladder = esc(&form.ladder),
        sel_info = selected("info", &form.severity),
        sel_warning = selected("warning", &form.severity),
        sel_critical = selected("critical", &form.severity),
        sel_alert = selected("alert", &form.action),
        sel_tag = selected("tag", &form.action),
        sel_allow = selected("allow", &form.action),
        sel_block_temp = selected("block_temp", &form.action),
        sel_block_perm = selected("block_permanent", &form.action),
        sel_escalate = selected("escalate", &form.action),
        enabled = checked(form.enabled),
        dry_run = checked(form.dry_run),
        only_if_blocked = checked(form.only_if_blocked),
    );
    shell(page, "/rules", &title, &body)
}

pub fn rule_history(page: &Page<'_>, rule_id: Option<u32>, revisions: &[RuleRevision]) -> String {
    let mut rows = String::new();
    for revision in revisions {
        let document =
            serde_json::to_string_pretty(&revision.document).unwrap_or_else(|_| "{}".into());
        let _ = write!(
            rows,
            r#"<tr><td class="mono">{ts}</td><td class="mono">{rule}</td><td>{rev}</td>
<td>{action}</td><td>{by}</td><td>{note}</td>
<td><details><summary class="small">document</summary><code>{document}</code></details></td></tr>"#,
            ts = esc(&time(revision.changed_at)),
            rule = revision.rule_id,
            rev = revision.revision,
            action = esc(&revision.action),
            by = esc(&revision.changed_by),
            note = esc(&revision.note),
            document = esc(&document),
        );
    }
    if revisions.is_empty() {
        rows.push_str(r#"<tr><td colspan="7" class="hint">No revisions recorded.</td></tr>"#);
    }
    let title = match rule_id {
        Some(id) => format!("Rule {id} history"),
        None => "Rule revisions".into(),
    };
    let body = format!(
        r#"<section class="panel">
<h1>{title}</h1>
<p><a class="button small ghost" href="/rules">Back to rules</a></p>
<div class="scroll"><table>
<thead><tr><th>Time (UTC)</th><th>Rule</th><th>Rev</th><th>Action</th><th>By</th><th>Note</th><th>Document</th></tr></thead>
<tbody>{rows}</tbody></table></div>
</section>"#,
        title = esc(&title),
        rows = rows,
    );
    shell(page, "/rules", &title, &body)
}

pub fn rule_check(
    page: &Page<'_>,
    rows: &[(Detection, Decision)],
    errors: &[RuleError],
    geo: &GeoData,
) -> String {
    let failure = if errors.is_empty() {
        String::new()
    } else {
        let text = errors
            .iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        format!(r#"<div class="banner danger">{}</div>"#, esc(&text))
    };
    let mut body = String::new();
    for (detection, decision) in rows {
        let _ = write!(
            body,
            r#"<tr>
<td class="mono">{ts}</td>
<td class="mono">{detector}</td>
<td class="mono">{src}</td>
<td>{count}</td>
<td class="mono">{matched}</td>
<td>{winner}</td>
<td>{action}</td>
<td>{dry}</td>
</tr>"#,
            ts = esc(&time(detection.last_seen)),
            detector = detection.detector,
            src = ip_with_country(detection.src, geo),
            count = detection.count,
            matched = esc(&decision.matched_label()),
            winner = decision
                .rule_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "—".into()),
            action = esc(&action_field_label(&decision.action)),
            dry = if decision.dry_run { "yes" } else { "no" },
        );
    }
    if rows.is_empty() {
        body.push_str(
            r#"<tr><td colspan="8" class="hint">No recent detections to evaluate.</td></tr>"#,
        );
    }
    let body = format!(
        r#"<section class="panel">
<h1>Rule check</h1>
{failure}
<p class="hint">The stored rules are evaluated against up to 100 recent detections with their
current strike/block history. Nothing is written or enforced.</p>
<p><a class="button small ghost" href="/rules">Back to rules</a></p>
<div class="scroll"><table>
<thead><tr><th>Time (UTC)</th><th>Detector</th><th>Source</th><th>Count</th><th>Matched rules</th><th>Winner</th><th>Action</th><th>Dry run</th></tr></thead>
<tbody>{body}</tbody></table></div>
</section>"#,
        failure = failure,
        body = body,
    );
    shell(page, "/rules", "Rule check", &body)
}

// ------------------------------------------------------------- alert targets

pub fn alert_target_form(
    page: &Page<'_>,
    target: &crate::db::AlertTarget,
    error: Option<&str>,
) -> String {
    let checked = |value: bool| if value { " checked" } else { "" };
    let selected = |value: &str, current: &str| {
        if value == current { " selected" } else { "" }
    };
    let failure = error
        .map(|text| format!(r#"<div class="banner danger">{}</div>"#, esc(text)))
        .unwrap_or_default();
    let title = if target.id == 0 {
        "Add webhook target".to_string()
    } else {
        format!("Edit webhook target: {}", target.name)
    };
    let body = format!(
        r#"<section class="panel">
<h1>{title}</h1>
{failure}
<p class="hint">RustIPS sends a JSON POST to every enabled target. Delivery is asynchronous
and retries with backoff. The URL may contain a secret token.</p>
<form method="post" action="/alerts/target/save">
{csrf}
<input type="hidden" name="id" value="{id}">
<div class="row-form">
<label>Name <input name="name" value="{name}" maxlength="120" required></label>
<label>URL <input name="url" value="{url}" placeholder="https://example.net/rustips" class="wide" required></label>
<label>Events <select name="events">
<option value="all"{sel_all}>all</option>
<option value="detection"{sel_detection}>detections only</option>
<option value="operational"{sel_operational}>operational only</option>
</select></label>
<label class="check"><input type="checkbox" name="enabled" value="yes"{enabled}>Enabled</label>
</div>
<div class="row-form">
<label>Minimum severity <select name="min_severity">
<option value="info"{sel_info}>info</option>
<option value="warning"{sel_warning}>warning</option>
<option value="critical"{sel_critical}>critical</option>
</select></label>
<label>Timeout (s) <input name="timeout_secs" value="{timeout}" class="short" required></label>
<label>Max retries <input name="max_retries" value="{retries}" class="short" required></label>
<label>Dedupe window (s) <input name="rate_limit_secs" value="{rate}" class="short" required></label>
<label>Queue max <input name="queue_max" value="{queue}" class="short" required></label>
</div>
<div class="row-form">
<button class="primary">Save target</button>
<a class="button small ghost" href="/alerts">Cancel</a>
</div>
</form>
</section>"#,
        title = esc(&title),
        failure = failure,
        csrf = csrf_input(page),
        id = target.id,
        name = esc(&target.name),
        url = esc(&target.url),
        timeout = target.timeout_secs,
        retries = target.max_retries,
        rate = target.rate_limit_secs,
        queue = target.queue_max,
        sel_all = selected("all", &target.events),
        sel_detection = selected("detection", &target.events),
        sel_operational = selected("operational", &target.events),
        sel_info = selected("info", &target.min_severity),
        sel_warning = selected("warning", &target.min_severity),
        sel_critical = selected("critical", &target.min_severity),
        enabled = checked(target.enabled),
    );
    shell(page, "/alerts", &title, &body)
}

// ------------------------------------------------------------------ detectors

fn detector_config_lines(det: Detector, cfg: &Config) -> Vec<String> {
    let d = &cfg.detection;
    let l = &cfg.logs.detection;
    match det {
        Detector::VerticalScan => vec![
            format!("scan_ports = {}", d.scan_ports),
            format!("window_secs = {}", d.window_secs),
        ],
        Detector::HorizontalScan => vec![
            format!("sweep_hosts = {}", d.sweep_hosts),
            format!("window_secs = {}", d.window_secs),
        ],
        Detector::StealthScan => vec![
            format!("stealth_packets = {}", d.stealth_packets),
            format!("window_secs = {}", d.window_secs),
        ],
        Detector::AckScan => vec![
            format!("ack_packets = {}", d.ack_packets),
            format!("window_secs = {}", d.window_secs),
        ],
        Detector::UdpScan => vec![
            format!("udp_ports = {}", d.udp_ports),
            format!("window_secs = {}", d.window_secs),
        ],
        Detector::IcmpSweep => vec![
            format!("icmp_hosts = {}", d.icmp_hosts),
            format!("icmp_echo_per_sec = {}", d.icmp_echo_per_sec),
            format!("window_secs = {}", d.window_secs),
        ],
        Detector::SynFlood => vec![
            format!("syn_per_sec = {}", d.syn_per_sec),
            format!("syn_unanswered_pct = {}%", d.syn_unanswered_pct),
        ],
        Detector::ConnectionRate => vec![
            format!("conn_rate = {}", d.conn_rate),
            format!("window_secs = {}", d.window_secs),
        ],
        Detector::TarpitPort => vec![format!(
            "tarpit_ports = {}",
            if d.tarpit_ports.is_empty() {
                "[] (detector disabled)".to_string()
            } else {
                d.tarpit_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        )],
        Detector::SshBruteForce => vec![format!("ssh_conns_per_min = {}", d.ssh_conns_per_min)],
        Detector::HttpPathScan => vec![
            format!("http_ports = {:?}", d.http_ports),
            format!("http_scan_paths = {}", d.http_scan_paths),
            format!("http_scan_404 = {}", d.http_scan_404),
            format!("http_scan_window_secs = {}", d.http_scan_window_secs),
        ],
        Detector::HttpBadPath => vec![format!("http_bad_paths = {}", d.http_bad_paths.join(", "))],
        Detector::HttpAuthBrute => vec![
            format!("http_auth_failures = {}", d.http_auth_failures),
            format!("http_auth_window_secs = {}", d.http_auth_window_secs),
            format!("http_login_paths = {}", d.http_login_paths.join(", ")),
        ],
        Detector::HttpAnomaly => vec![
            format!("http_anomalies = {}", d.http_anomalies),
            format!("http_anomaly_window_secs = {}", d.http_anomaly_window_secs),
        ],
        Detector::HttpFlood => vec![
            format!("http_ports = {:?}", d.http_ports),
            format!("http_flood_requests = {}", d.http_flood_requests),
            format!("http_flood_window_secs = {}", d.http_flood_window_secs),
        ],
        Detector::SshAuthFailures => vec![
            format!("ssh_failures = {}", l.ssh_failures),
            format!("window_secs = {}", l.window_secs),
            format!("cooldown_secs = {}", l.cooldown_secs),
        ],
        Detector::SshSuccessAfterFailures => {
            vec!["one success after at least one prior failure; alert only".into()]
        }
        Detector::SlowScan => vec![
            format!("slow_scan_ports = {}", d.slow_scan_ports),
            format!("slow_scan_window_secs = {}", d.slow_scan_window_secs),
            format!("slow_scan_max_per_window = {}", d.slow_scan_max_per_window),
            format!("slow_scan_cooldown_secs = {}", d.slow_scan_cooldown_secs),
        ],
        Detector::PamFailureBurst => vec![
            format!("pam_failures = {}", l.pam_failures),
            format!("window_secs = {}", l.window_secs),
            "sshd PAM lines are handled by DET-16".into(),
        ],
        Detector::SudoDenial => vec![
            format!("sudo_failures = {}", l.sudo_failures),
            format!("window_secs = {}", l.window_secs),
        ],
        Detector::HttpLogScan => vec![
            format!("http_scan_paths = {}", l.http_scan_paths),
            format!("http_scan_404 = {}", l.http_scan_404),
            format!("http_scan_window_secs = {}", l.http_scan_window_secs),
            "source: common/combined access lines that reach the journal".into(),
        ],
        Detector::SystemSecurityChange => {
            vec!["one event: nftables ruleset change, RustIPS stop, audit/journald disable".into()]
        }
        Detector::AccountModification => {
            vec!["one event: useradd/usermod/groupadd/sudoers/authorized_keys change".into()]
        }
        Detector::Honeypot => vec![
            format!("honeypot_enabled = {}", d.honeypot_enabled),
            format!(
                "honeypot_ports = {}",
                if d.honeypot_ports.is_empty() {
                    "[] (no honeypot ports configured)".to_string()
                } else {
                    d.honeypot_ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
            "configure in Settings; one TCP SYN or UDP datagram is enough".into(),
        ],
    }
}

fn param_field(key: &str, cfg: &Config, overrides: &BTreeMap<String, String>) -> String {
    let Some(spec) = params::spec(key) else {
        return String::new();
    };
    let current = params::value(cfg, key);
    let default = params::default_value(key);
    let modified = overrides.contains_key(key);
    let id = format!("param-{}", key.replace('.', "-"));
    let input = match spec.kind {
        ParamKind::Bool => format!(
            r#"<input type="hidden" name="p:{key}" value="false">
<label class="check"><input type="checkbox" id="{id}" name="p:{key}" value="true"{checked}> enabled</label>"#,
            checked = if current == "true" { " checked" } else { "" },
        ),
        ParamKind::Number { min, max } => format!(
            r#"<input type="number" id="{id}" name="p:{key}" value="{value}" min="{min}" max="{max}">"#,
            value = esc(&current),
        ),
        ParamKind::PortList | ParamKind::TextList => format!(
            r#"<input type="text" id="{id}" name="p:{key}" value="{value}" size="60">"#,
            value = esc(&current),
        ),
    };
    let tag = if modified {
        r#" <span class="tag warn">modified</span>"#
    } else {
        ""
    };
    let stored = overrides
        .get(key)
        .map(|value| {
            format!(
                r#"<div class="hint">stored override: <span class="mono">{}</span> (applies after restart)</div>"#,
                esc(value)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<div class="param">
<label for="{id}">{label}{tag}</label>
{input}
{stored}
<div class="hint">built-in default: <span class="mono">{default}</span> · {help}</div>
<button class="small ghost" name="reset_key" value="{key}" formnovalidate>Reset to default</button>
</div>"#,
        label = esc(spec.label),
        stored = stored,
        default = esc(&default),
        help = esc(spec.help),
    )
}

fn params_form(
    page: &Page<'_>,
    scope: &str,
    keys: &[&str],
    cfg: &Config,
    overrides: &BTreeMap<String, String>,
    return_to: Option<&str>,
) -> String {
    let mut fields = String::new();
    for key in keys {
        fields.push_str(&param_field(key, cfg, overrides));
    }
    let return_field = return_to
        .map(|value| {
            format!(
                r#"<input type="hidden" name="return" value="{}">"#,
                esc(value)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<form method="post" action="/detectors/params" class="params">
{csrf}<input type="hidden" name="scope" value="{scope}">{return_field}
<div class="param-grid">{fields}</div>
<div class="actions">
<button class="primary small" name="action" value="save">Save parameters</button>
<button class="ghost small" name="action" value="reset_scope" data-confirm="Reset every parameter for {scope} to its built-in default?">Reset this group to defaults</button>
</div>
</form>"#,
        csrf = csrf_input(page),
        scope = esc(scope),
        return_field = return_field,
        fields = fields,
    )
}

pub fn detectors(
    page: &Page<'_>,
    cfg: &Config,
    disabled: &HashSet<String>,
    overrides: &BTreeMap<String, String>,
    notice: Option<&str>,
) -> String {
    let flash = notice
        .map(|text| format!(r#"<p class="flash">{}</p>"#, esc(text)))
        .unwrap_or_default();
    let override_banner = if overrides.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="banner warn"><strong>{count} parameter override(s) active.</strong>
Stored overrides replace the configuration file at daemon start. Changes saved here
take effect after a RustIPS restart.</div>"#,
            count = overrides.len()
        )
    };
    let mut rows = String::new();
    for detector in Detector::ALL {
        let enabled = !disabled.contains(detector.as_str());
        let state = format!(
            r#"<form method="post" action="/detectors/toggle" class="inline">
{csrf}<input type="hidden" name="id" value="{id}">
<input type="hidden" name="enable" value="{next}">
<button class="state-toggle {class}" title="{title}" aria-pressed="{pressed}">{label}</button>
</form>"#,
            csrf = csrf_input(page),
            id = detector,
            next = if enabled { "no" } else { "yes" },
            class = if enabled { "state-on" } else { "state-off" },
            title = if enabled {
                "Click to disable this detector"
            } else {
                "Click to enable this detector"
            },
            pressed = enabled,
            label = if enabled { "Enabled" } else { "Disabled" },
        );
        let mut details = String::new();
        for line in detector_config_lines(detector, cfg) {
            let _ = write!(details, "<li>{}</li>", esc(&line));
        }
        let disposition = if detector == Detector::Honeypot {
            "blocked by the shipped honeypot rule after 3 contacts; tune it on Disposition rules"
        } else if detector.is_alert_only() {
            "alert only by default; never auto-blocks"
        } else {
            "strike ladder by default; policy is controlled on Disposition rules"
        };
        let keys = params::keys_for(detector.as_str());
        let tuning = if keys.is_empty() {
            r#"<p class="hint">No tunable parameters for this detector.</p>"#.to_string()
        } else {
            params_form(page, detector.as_str(), keys, cfg, overrides, None)
        };
        let _ = write!(
            rows,
            r#"<tr>
<td class="mono">{id}</td>
<td>{title}<div class="hint">{category}</div></td>
<td>{state}</td>
<td>{description}
<details><summary class="small">details and parameters</summary>
<ul class="plain">{details}<li>Disposition: {disposition}</li></ul>
{tuning}
</details></td>
</tr>"#,
            id = detector,
            title = esc(detector.title()),
            category = esc(detector.category().as_str()),
            state = state,
            description = esc(detector.description()),
            details = details,
            disposition = esc(disposition),
            tuning = tuning,
        );
    }
    let enabled_count = Detector::ALL
        .iter()
        .filter(|detector| !disabled.contains(detector.as_str()))
        .count();
    let body = format!(
        r#"<section class="panel">
<h1>Detectors</h1>
{flash}
{override_banner}
<p class="hint">{enabled_count} of {total} detectors enabled. Disabling a detector stops new
detections of that type from being recorded or blocked; existing blocks/strikes are not removed.
Changes apply to the next detection without a restart.</p>
<p class="hint"><strong>Parameters:</strong> every detector's thresholds and lists can be
edited below. Saving stores an override in SQLite; resetting removes it and restores the
configured value. Parameter changes need a daemon restart (detector enable/disable does not).</p>
<p class="hint"><strong>Modularity:</strong> detection logic is compiled Rust and is not
scriptable from the UI. Administrators can enable/disable detectors, tune thresholds and lists, and
build data-driven disposition rules on the Disposition rules page. Custom signature or pattern-based
detection is future work.</p>
<div class="filters">
<form method="post" action="/detectors/params" class="inline">
{csrf}<button class="small danger" name="action" value="reset_all"
data-confirm="Remove every stored detection parameter override? All detectors return to built-in defaults after a restart.">Reset all overrides</button>
</form></div>
<div class="scroll"><table>
<thead><tr><th>ID</th><th>Detector</th><th>State</th><th>What it looks for</th></tr></thead>
<tbody>{rows}</tbody></table></div>
</section>
<section class="panel">
<h2>Shared packet parameters</h2>
<p class="hint">Sliding window, cooldown and source-table cap shared by packet and HTTP detectors.</p>
{packet_form}
</section>
<section class="panel">
<h2>Shared HTTP parameters</h2>
<p class="hint">Clear-text ports inspected by DET-11…15. Edit per-detector paths and thresholds in its row above.</p>
{http_form}
</section>
<section class="panel">
<h2>Shared log parameters</h2>
<p class="hint">Sliding window, cooldown and source-table cap shared by log detectors.</p>
{log_form}
</section>"#,
        flash = flash,
        override_banner = override_banner,
        enabled_count = enabled_count,
        total = Detector::ALL.len(),
        csrf = csrf_input(page),
        rows = rows,
        packet_form = params_form(
            page,
            "shared-packet",
            params::SHARED_PACKET,
            cfg,
            overrides,
            None
        ),
        http_form = params_form(
            page,
            "shared-http",
            params::SHARED_HTTP,
            cfg,
            overrides,
            None
        ),
        log_form = params_form(page, "shared-log", params::SHARED_LOG, cfg, overrides, None),
    );
    shell(page, "/detectors", "Detectors", &body)
}

// --------------------------------------------------------------------- alerts

pub fn alerts(
    page: &Page<'_>,
    targets: &[crate::db::AlertTarget],
    retention_days: u64,
    stats: &crate::db::AlertStats,
    rows: &[crate::db::AlertRecord],
    notice: Option<&str>,
    geo: &GeoData,
) -> String {
    let flash = notice
        .map(|text| format!(r#"<p class="flash">{}</p>"#, esc(text)))
        .unwrap_or_default();
    let disabled = if targets.iter().any(|target| target.enabled) {
        String::new()
    } else {
        r#"<div class="banner warn"><strong>Alerting is disabled.</strong> Add and enable at
least one webhook target below.</div>"#
            .to_string()
    };

    let mut target_rows = String::new();
    for target in targets {
        let _ = write!(
            target_rows,
            r#"<tr>
<td>{name}</td><td>{enabled}</td><td class="mono">{url}</td><td>{events}</td>
<td>{severity}</td><td>{timeout}s / {retries} / {rate}s</td><td>{queue}</td>
<td>{updated}</td>
<td><a class="button small" href="/alerts/target/edit?id={id}">Edit</a>
<form method="post" action="/alerts/target/delete" class="inline" data-confirm="Delete target {name}? Pending alerts for it will be dropped.">
{csrf}<input type="hidden" name="id" value="{id}"><button class="small danger">Delete</button></form></td>
</tr>"#,
            name = esc(&target.name),
            enabled = if target.enabled { "yes" } else { "no" },
            url = esc(&target.url),
            events = esc(&target.events),
            severity = esc(&target.min_severity),
            timeout = target.timeout_secs,
            retries = target.max_retries,
            rate = target.rate_limit_secs,
            queue = target.queue_max,
            updated = esc(&time(target.updated_at)),
            id = target.id,
            csrf = csrf_input(page),
        );
    }
    if target_rows.is_empty() {
        target_rows.push_str(r#"<tr><td colspan="9" class="hint">No webhook targets. Add one to start alerting.</td></tr>"#);
    }

    let mut body = String::new();
    for row in rows {
        let value: serde_json::Value =
            serde_json::from_str(&row.payload).unwrap_or(serde_json::Value::Null);
        let kind = value
            .get("detector")
            .and_then(|v| v.as_str())
            .map(|detector| {
                let title = value
                    .get("detector_title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                format!("{detector} {title}")
            })
            .or_else(|| {
                value
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .map(|kind| format!("operational: {kind}"))
            })
            .unwrap_or_else(|| "event".into());
        let src = value.get("src").and_then(|v| v.as_str()).unwrap_or("—");
        let action = value.get("action").and_then(|v| v.as_str()).unwrap_or("—");
        let rule = value
            .get("rule_name")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let pretty = serde_json::to_string_pretty(&value).unwrap_or_else(|_| row.payload.clone());
        let target = row.target_name.as_deref().unwrap_or("deleted target");
        let actions = match row.state.as_str() {
            "pending" => format!(
                r#"<form method="post" action="/alerts/requeue" class="inline">
{csrf}<input type="hidden" name="id" value="{id}"><button class="small">Send now</button></form>"#,
                csrf = csrf_input(page),
                id = row.id
            ),
            "failed" => format!(
                r#"<form method="post" action="/alerts/requeue" class="inline">
{csrf}<input type="hidden" name="id" value="{id}"><button class="small">Retry</button></form>
<form method="post" action="/alerts/delete" class="inline" data-confirm="Delete alert {id}?">
{csrf}<input type="hidden" name="id" value="{id}"><button class="small danger">Delete</button></form>"#,
                csrf = csrf_input(page),
                id = row.id
            ),
            _ => format!(
                r#"<form method="post" action="/alerts/delete" class="inline" data-confirm="Delete alert {id}?">
{csrf}<input type="hidden" name="id" value="{id}"><button class="small danger">Delete</button></form>"#,
                csrf = csrf_input(page),
                id = row.id
            ),
        };
        let _ = write!(
            body,
            r#"<tr>
<td class="mono">{id}</td>
<td class="mono">{created}</td>
<td><span class="tag">{state}</span></td>
<td>{target}</td>
<td>{attempts}</td>
<td class="mono">{next}</td>
<td>{kind}<div class="hint">src {src} · action {action} · rule {rule}</div>
<details><summary class="small">payload</summary><code>{pretty}</code></details></td>
<td>{error}</td>
<td>{actions}</td>
</tr>"#,
            id = row.id,
            created = esc(&time(row.created_at)),
            state = esc(&row.state),
            target = esc(target),
            attempts = row.attempts,
            next = esc(&time(row.next_attempt)),
            kind = esc(&kind),
            src = ip_text_with_country(src, geo),
            action = esc(action),
            rule = esc(rule),
            pretty = esc(&pretty),
            error = if row.last_error.is_empty() {
                "—".to_string()
            } else {
                esc(&row.last_error)
            },
            actions = actions,
        );
    }
    if rows.is_empty() {
        body.push_str(r#"<tr><td colspan="9" class="hint">No alerts have been queued.</td></tr>"#);
    }

    let test = if targets.iter().any(|target| target.enabled) {
        format!(
            r#"<form method="post" action="/alerts/test" class="inline">
{csrf}<button class="primary">Send test alert</button></form>"#,
            csrf = csrf_input(page)
        )
    } else {
        r#"<span class="hint">Add and enable a target to send a test.</span>"#.to_string()
    };

    let page_body = format!(
        r#"<section class="panel">
<h1>Alerts</h1>
{flash}{disabled}
<p class="hint">Webhook: <span class="mono">{status}</span> · <span class="mono">{url}</span> target(s)
· {pending} pending · {delivered} delivered · {failed} failed</p>
<p>{test}
<form method="post" action="/alerts/clear" class="inline" data-confirm="Delete all delivered and failed alerts?">
{csrf}<button class="small">Clear delivered/failed</button></form></p>
</section>
<section class="panel">
<h2>Webhook targets</h2>
<p><a class="button primary" href="/alerts/target/new">Add target</a></p>
<div class="scroll"><table>
<thead><tr><th>Name</th><th>Enabled</th><th>URL</th><th>Events</th><th>Min severity</th><th>Timeout/retries/rate</th><th>Queue max</th><th>Updated (UTC)</th><th></th></tr></thead>
<tbody>{target_rows}</tbody></table></div>
<form method="post" action="/alerts/settings" class="row-form">
{csrf}
<label>Queue retention (days) <input name="retention_days" type="number" min="1" max="3650" value="{retention_days}" class="short" required></label>
<button class="small">Save queue settings</button>
</form>
</section>
<section class="panel">
<h2>Delivery queue</h2>
<div class="scroll"><table>
<thead><tr><th>ID</th><th>Created (UTC)</th><th>State</th><th>Target</th><th>Attempts</th><th>Next attempt</th><th>Summary</th><th>Last error</th><th></th></tr></thead>
<tbody>{body}</tbody></table></div>
</section>"#,
        flash = flash,
        disabled = disabled,
        status = if targets.iter().any(|target| target.enabled) {
            "enabled"
        } else {
            "disabled"
        },
        url = targets.len(),
        pending = stats.pending,
        delivered = stats.delivered,
        failed = stats.failed,
        test = test,
        csrf = csrf_input(page),
        target_rows = target_rows,
        retention_days = retention_days,
        body = body,
    );
    shell(page, "/alerts", "Alerts", &page_body)
}

// -------------------------------------------------------------------- blocks

pub fn block_rows(page: &Page<'_>, rows: &[Block], now: DateTime<Utc>, geo: &GeoData) -> String {
    let mut out = String::new();
    for block in rows {
        let _ = write!(
            out,
            r#"<tr>
<td class="mono">{src}</td>
<td>{reason}</td>
<td>{detector}</td>
<td>{strike}</td>
<td class="mono">{started}</td>
<td>{expiry}</td>
<td><form method="post" action="/blocks/remove" class="inline" data-confirm="Unblock {src_text}?">
{csrf}<input type="hidden" name="src" value="{src_raw}">
<button class="small danger">Unblock</button></form></td>
</tr>"#,
            src = ip_with_country(block.src, geo),
            src_text = esc(&block.src.to_string()),
            src_raw = esc(&block.src.to_string()),
            reason = esc(&block.reason),
            detector = block
                .detector
                .map(|d| esc(d.as_str()))
                .unwrap_or_else(|| "—".into()),
            strike = block.strike,
            started = esc(&time(block.started_at)),
            expiry = esc(&remaining(block, now)),
            csrf = csrf_input(page),
        );
    }
    out
}

pub fn blocks(page: &Page<'_>, rows: &[Block], notice: Option<&str>, geo: &GeoData) -> String {
    let flash = notice
        .map(|n| format!(r#"<p class="flash">{}</p>"#, esc(n)))
        .unwrap_or_default();
    let body = format!(
        r#"<section class="panel">
<h1>Active blocks</h1>
{flash}
<p class="hint">Enforcement: {enforcement}. Blocks are owned by the daemon; expiry is applied from the database, never by a kernel timeout.</p>
<div class="scroll"><table>
<thead><tr><th>Source</th><th>Reason</th><th>Detector</th><th>Strike</th><th>Started (UTC)</th><th>Remaining</th><th></th></tr></thead>
<tbody id="live-table">{rows}</tbody>
</table></div>
<p class="hint">This table refreshes every 2 seconds.</p>
</section>
<section class="panel">
<h2>Manual block</h2>
<form method="post" action="/blocks/add" class="row-form">
{csrf}
<label>Source <input name="src" placeholder="203.0.113.7" required class="mono"></label>
<label>Minutes <input name="minutes" type="number" min="0" value="60" class="short"></label>
<label>Reason <input name="reason" value="manual block" maxlength="200"></label>
<button class="primary">Block</button>
</form>
<p class="hint">Zero minutes means permanent. Loopback, private and the host's own addresses cannot be blocked.</p>
</section>"#,
        flash = flash,
        enforcement = if page.mode == Mode::Enforce {
            "nftables"
        } else {
            "dry run (observe mode) — the block is recorded but not applied"
        },
        rows = block_rows(page, rows, Utc::now(), geo),
        csrf = csrf_input(page)
    );
    shell(page, "/blocks", "Active blocks", &body)
}

pub fn history(page: &Page<'_>, rows: &[Block], geo: &GeoData) -> String {
    let mut body = String::new();
    for block in rows {
        let _ = write!(
            body,
            r#"<tr><td class="mono">{src}</td><td>{reason}</td><td>{detector}</td>
<td class="mono">{started}</td><td class="mono">{expiry}</td><td>{state}</td><td>{strike}</td></tr>"#,
            src = ip_with_country(block.src, geo),
            reason = esc(&block.reason),
            detector = block
                .detector
                .map(|d| esc(d.as_str()))
                .unwrap_or_else(|| "—".into()),
            started = esc(&time(block.started_at)),
            expiry = block
                .expires_at
                .map(|e| esc(&time(e)))
                .unwrap_or_else(|| "permanent".into()),
            state = esc(block.state.as_str()),
            strike = block.strike,
        );
    }
    let page_body = format!(
        r#"<section class="panel">
<h1>Block history</h1>
<p class="hint">The most recent 500 rows. States: {states}.</p>
<div class="scroll"><table>
<thead><tr><th>Source</th><th>Reason</th><th>Detector</th><th>Started (UTC)</th><th>Expiry (UTC)</th><th>Outcome</th><th>Strike</th></tr></thead>
<tbody>{body}</tbody></table></div>
</section>"#,
        states = BlockState::Active.as_str().to_string()
            + ", "
            + BlockState::Expired.as_str()
            + ", "
            + BlockState::ManualUnblocked.as_str()
            + ", "
            + BlockState::ExpiredPendingRemoval.as_str(),
        body = body
    );
    shell(page, "/history", "Block history", &page_body)
}

// ------------------------------------------------------------------- strikes

pub fn strikes(page: &Page<'_>, rows: &[Strike], cfg: &Config, geo: &GeoData) -> String {
    let mut body = String::new();
    let steps = &cfg.ladder.steps;
    for strike in rows {
        let next = if steps.is_empty() {
            "—".to_string()
        } else {
            let index = (strike.count as usize).min(steps.len() - 1);
            duration_label(steps[index])
        };
        let _ = write!(
            body,
            r#"<tr><td class="mono">{src}</td><td>{count}</td><td class="mono">{first}</td>
<td class="mono">{last}</td><td>{reason}</td><td>{next}</td></tr>"#,
            src = ip_with_country(strike.src, geo),
            count = strike.count,
            first = esc(&time(strike.first_seen)),
            last = esc(&time(strike.last_seen)),
            reason = esc(&strike.last_reason),
            next = esc(&next),
        );
    }
    let page_body = format!(
        r#"<section class="panel">
<h1>Strikes / repeat offenders</h1>
<p class="hint">Strikes decay after {} days. A manual unblock {} the strike count.</p>
<div class="scroll"><table>
<thead><tr><th>Source</th><th>Strikes</th><th>First seen (UTC)</th><th>Last seen (UTC)</th><th>Last reason</th><th>Next penalty</th></tr></thead>
<tbody>{body}</tbody></table></div>
</section>"#,
        cfg.ladder.strike_decay_days,
        if cfg.ladder.unblock_effect == UnblockEffect::Reset {
            "resets"
        } else {
            "keeps"
        },
        body = body
    );
    shell(page, "/strikes", "Strikes", &page_body)
}

// ----------------------------------------------------------------- allowlist

pub fn allowlist(page: &Page<'_>, rows: &[AllowlistEntry], notice: Option<&str>) -> String {
    let mut body = String::new();
    for entry in rows {
        let action = if entry.implicit {
            r#"<span class="hint">implicit</span>"#.to_string()
        } else {
            format!(
                r#"<form method="post" action="/allowlist/remove" class="inline" data-confirm="Remove {cidr} from the allowlist?">
{csrf}<input type="hidden" name="cidr" value="{cidr_raw}">
<button class="small danger">Remove</button></form>"#,
                cidr = esc(&entry.cidr),
                cidr_raw = esc(&entry.cidr),
                csrf = csrf_input(page)
            )
        };
        let _ = write!(
            body,
            r#"<tr><td class="mono">{cidr}</td><td>{label}</td><td>{implicit}</td>
<td class="mono">{created}</td><td>{by}</td><td>{action}</td></tr>"#,
            cidr = esc(&entry.cidr),
            label = esc(&entry.label),
            implicit = if entry.implicit { "yes" } else { "no" },
            created = esc(&time(entry.created_at)),
            by = esc(&entry.created_by),
            action = action,
        );
    }
    let flash = notice
        .map(|n| format!(r#"<p class="flash">{}</p>"#, esc(n)))
        .unwrap_or_default();
    let page_body = format!(
        r#"<section class="panel">
<h1>Allowlist</h1>
{flash}
<p class="hint">Allowlisted sources are never blocked. The implicit set (loopback, link-local,
private ranges and the host's own addresses) cannot be removed.</p>
<div class="scroll"><table>
<thead><tr><th>CIDR</th><th>Label</th><th>Implicit</th><th>Created (UTC)</th><th>By</th><th></th></tr></thead>
<tbody>{body}</tbody></table></div>
</section>
<section class="panel">
<h2>Add an entry</h2>
<form method="post" action="/allowlist/add" class="row-form">
{csrf}
<label>CIDR <input name="cidr" placeholder="192.0.2.0/24" required class="mono"></label>
<label>Label <input name="label" maxlength="120" placeholder="monitoring"></label>
<button class="primary">Add</button>
</form>
</section>"#,
        flash = flash,
        body = body,
        csrf = csrf_input(page)
    );
    shell(page, "/allowlist", "Allowlist", &page_body)
}

// ------------------------------------------------------------------ settings

#[allow(clippy::too_many_arguments)]
pub fn settings(
    page: &Page<'_>,
    cfg: &Config,
    overrides: &[(String, serde_json::Value)],
    detection_overrides: &BTreeMap<String, String>,
    country_colors: &CountryColors,
    country_default: &CountryColor,
    country_loaded: bool,
    edit_code: &str,
    edit_background: &str,
    edit_foreground: &str,
    users: &[String],
    bind_value: &str,
    port_value: u16,
    alerts: &crate::db::AlertStats,
    alert_targets: usize,
    notice: Option<&str>,
) -> String {
    let flash = notice
        .map(|n| format!(r#"<p class="flash">{}</p>"#, esc(n)))
        .unwrap_or_default();

    let mut override_rows = String::new();
    for (key, value) in overrides.iter().filter(|(k, _)| k.starts_with("web.")) {
        let _ = write!(
            override_rows,
            r#"<tr><td class="mono">{}</td><td class="mono">{}</td></tr>"#,
            esc(key),
            esc(&value.to_string())
        );
    }
    if override_rows.is_empty() {
        override_rows.push_str(r#"<tr><td colspan="2" class="hint">No runtime overrides; the configuration file is in use.</td></tr>"#);
    }

    let mut country_rows = format!(
        r##"<tr><td><span class="tag country-tag">Default</span></td>
<td class="mono">{background}</td><td class="mono">{foreground}</td>
<td><a class="button small ghost" href="#country-default">Edit</a></td></tr>"##,
        background = esc(&country_default.background),
        foreground = esc(&country_default.foreground),
    );
    for (code, color) in country_colors {
        let _ = write!(
            country_rows,
            r#"<tr><td>{badge}</td><td class="mono">{background}</td><td class="mono">{foreground}</td>
<td><a class="button small ghost" href="/settings?edit={code}#country-colors">Edit</a>
<form method="post" action="/settings/geo-colors/delete" class="inline" data-confirm="Remove the custom color for {code}?">
{csrf}<input type="hidden" name="code" value="{code}">
<button class="small danger">Remove</button></form></td></tr>"#,
            badge = country_badge(code),
            background = esc(&color.background),
            foreground = esc(&color.foreground),
            code = esc(code),
            csrf = csrf_input(page),
        );
    }
    if country_colors.is_empty() {
        country_rows.push_str(r#"<tr><td colspan="4" class="hint">No country overrides yet; every country uses the default badge.</td></tr>"#);
    }
    let edit_button = if edit_code.is_empty() {
        "Save country colors"
    } else {
        "Update country colors"
    };
    let cancel_edit = if edit_code.is_empty() {
        String::new()
    } else {
        r#"<a class="button small ghost" href="/settings#country-colors">Cancel edit</a>"#
            .to_string()
    };

    let mut users_list = String::new();
    if users.is_empty() {
        users_list.push_str(r#"<li class="hint">No members found. Add the administrator to the group before logging in.</li>"#);
    } else {
        for user in users {
            let _ = write!(users_list, r#"<li class="mono">{}</li>"#, esc(user));
        }
    }

    let mut ladder = String::new();
    for (i, step) in cfg.ladder.steps.iter().enumerate() {
        let _ = write!(
            ladder,
            r#"<li>Strike {}: {}</li>"#,
            i + 1,
            esc(&duration_label(*step))
        );
    }

    let body = format!(
        r##"<section class="panel">
<h1>Settings</h1>
{flash}
<p class="hint">Effective binding: <span class="mono">{bind}</span>. Changes are saved to the
database and applied on the next restart. A non-loopback address needs the confirmation
below; if RustIPS cannot bind at startup it deletes the override and falls back to the
configuration file (FR-186).</p>
<form method="post" action="/settings/web" class="row-form">
{csrf}
<label>Bind address <input name="bind" value="{bind_value}" class="mono" required></label>
<label>Port <input name="port" type="number" min="1" max="65535" value="{port}" class="short" required></label>
<label class="check"><input type="checkbox" name="confirm_remote" value="yes">
I understand that binding to a non-loopback address exposes the UI to the network.</label>
<button class="primary">Save</button>
</form>
<form method="post" action="/settings/reset" class="row-form">
{csrf}<button class="small">Remove bind/port override</button>
</form>
<div class="scroll"><table><thead><tr><th>Override</th><th>Value</th></tr></thead><tbody>{overrides}</tbody></table></div>
</section>

<section class="grid2">
<div class="panel"><h2>Authentication</h2>
<ul class="plain">
<li>PAM service: <span class="mono">{pam}</span> (<span class="mono">/etc/pam.d/{pam}</span>)</li>
<li>Administrator group: <span class="mono">{group}</span></li>
<li>Session idle timeout: {idle} minutes; absolute timeout: {absolute} minutes.</li>
<li>Revalidation: every {revalidate} minutes and on every privileged action.</li>
</ul>
<h3>Users with access</h3>
<ul class="plain">{users}</ul>
</div>
<div class="panel"><h2>Remote access</h2>
<p>Keep the listener on loopback and use an SSH tunnel:</p>
<pre>ssh -L {port}:127.0.0.1:{port} your-user@this-host</pre>
<p class="hint">Then open <span class="mono">http://127.0.0.1:{port}</span> on your workstation.
There is exactly one authority level: every authenticated administrator is a full admin.</p>
</div>
</section>

<section class="panel"><h2>Detection and escalation</h2>
<div class="grid2">
<div>
<ul class="plain">
<li>Window: {window}s · cooldown: {cooldown}s</li>
<li>Scan ports: {scan_ports} · sweep hosts: {sweep_hosts}</li>
<li>Stealth packets: {stealth} · ACK packets: {ack}</li>
<li>UDP ports: {udp} · ICMP hosts: {icmp_hosts} · echo/s: {echo}</li>
<li>SYN/s: {syn} ({unanswered}% unanswered)</li>
<li>New connections/window: {conn_rate} · SSH connections/min: {ssh}</li>
<li>Tarpit ports: <span class="mono">{tarpit}</span></li>
</ul>
</div>
<div><h3>Ladder</h3><ol class="plain">{ladder}</ol>
<p class="hint">Strike decay: {decay} days. Unblock effect: {effect}.</p></div>
</div>
</section>

<section class="panel"><h2>Honeypot</h2>
<p class="hint">DET-26 watches a list of TCP/UDP ports that no real service uses.
A TCP SYN or UDP datagram to any listed port triggers an alert-only detection
(the source is not blocked unless you add a Disposition rule for DET-26).
Disabled by default. Changes apply after a RustIPS restart.</p>
{honeypot_form}
<p class="hint">Choose ports that are closed and not used by SSH, the web UI,
or any real service. Do not list the RustIPS web port. See
<a href="/detectors">Detectors</a> for the DET-26 catalog entry.</p>
</section>

<section class="panel"><h2>Country badge colors</h2>
<p class="hint">When the GeoIP country index is loaded, every source address shows its
two-letter country tag. The default badge is black with white text unless changed
below. Country overrides accept one or more comma-separated ISO codes and share
one background/text color pair.</p>
{country_note}
<div class="scroll"><table><thead><tr><th>Preview</th><th>Background</th><th>Text</th><th></th></tr></thead>
<tbody>{country_rows}</tbody></table></div>

<h3 id="country-default">Default badge</h3>
<form method="post" action="/settings/geo-colors/default" class="row-form">
{csrf}
<label>Background <input name="background" type="color" value="{default_background}" required></label>
<label>Text <input name="foreground" type="color" value="{default_foreground}" required></label>
<button class="primary">Save default</button>
</form>

<h3 id="country-colors">Country overrides</h3>
<form method="post" action="/settings/geo-colors" class="row-form">
{csrf}
<label>Country codes <input name="code" maxlength="64" value="{edit_code}" placeholder="CN, RU, KP" required class="mono"></label>
<label>Background <input name="background" type="color" value="{edit_background}" required></label>
<label>Text <input name="foreground" type="color" value="{edit_foreground}" required></label>
<button class="primary">{edit_button}</button>
{cancel_edit}
</form>
<p class="hint">Use comma-separated two-letter ISO 3166-1 codes. Re-saving a code
updates it. Colors are stored in SQLite and apply immediately.</p>
</section>

<section class="panel"><h2>Storage and runtime</h2>
<ul class="plain">
<li>Mode: <span class="mono">{mode}</span> · capture interfaces: <span class="mono">{ifaces}</span></li>
<li>Retention: detections {det_days}d · blocks {block_days}d · audit {audit_days}d</li>
<li>Memory budget: 512 MB default (systemd <span class="mono">MemoryMax</span>)</li>
</ul>
</section>

<section class="panel"><h2>Webhook alerts</h2>
<ul class="plain">
<li>Targets: <span class="mono">{alert_targets}</span> · status: <span class="mono">{alert_status}</span></li>
<li>Queue: {alert_pending} pending · {alert_delivered} delivered · {alert_failed} failed</li>
<li>Oldest pending: {alert_oldest} · last error: {alert_error}</li>
</ul>
<p class="hint">Add, edit and remove webhook targets on the <a href="/alerts">Alerts</a> page.
Delivery is asynchronous and uses the system <span class="mono">curl</span>.</p>
</section>"##,
        flash = flash,
        bind = esc(&page.bind.to_string()),
        bind_value = esc(bind_value),
        port = port_value,
        csrf = csrf_input(page),
        overrides = override_rows,
        pam = esc(&cfg.web.pam_service),
        group = esc(&cfg.web.admin_group),
        idle = cfg.web.session_idle_mins,
        absolute = cfg.web.session_absolute_mins,
        revalidate = cfg.web.revalidate_mins,
        users = users_list,
        window = cfg.detection.window_secs,
        cooldown = cfg.detection.cooldown_secs,
        scan_ports = cfg.detection.scan_ports,
        sweep_hosts = cfg.detection.sweep_hosts,
        stealth = cfg.detection.stealth_packets,
        ack = cfg.detection.ack_packets,
        udp = cfg.detection.udp_ports,
        icmp_hosts = cfg.detection.icmp_hosts,
        echo = cfg.detection.icmp_echo_per_sec,
        syn = cfg.detection.syn_per_sec,
        unanswered = cfg.detection.syn_unanswered_pct,
        conn_rate = cfg.detection.conn_rate,
        ssh = cfg.detection.ssh_conns_per_min,
        tarpit = if cfg.detection.tarpit_ports.is_empty() {
            "none".to_string()
        } else {
            cfg.detection
                .tarpit_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        },
        ladder = ladder,
        country_note = if country_loaded {
            r#"<p class="hint"><strong>GeoIP country index loaded.</strong></p>"#
        } else {
            r#"<div class="banner warn"><strong>GeoIP country index is not loaded.</strong> Country tags will appear after a successful <span class="mono">rustips geo update</span>.</div>"#
        },
        country_rows = country_rows,
        default_background = esc(&country_default.background),
        default_foreground = esc(&country_default.foreground),
        edit_code = esc(edit_code),
        edit_background = esc(edit_background),
        edit_foreground = esc(edit_foreground),
        edit_button = edit_button,
        cancel_edit = cancel_edit,
        honeypot_form = params_form(
            page,
            "honeypot",
            params::HONEYPOT,
            cfg,
            detection_overrides,
            Some("settings"),
        ),
        decay = cfg.ladder.strike_decay_days,
        effect = if cfg.ladder.unblock_effect == UnblockEffect::Reset {
            "reset strikes"
        } else {
            "keep strikes"
        },
        mode = cfg.mode,
        ifaces = esc(&cfg.capture.interfaces.join(", ")),
        det_days = cfg.retention.detections_days,
        block_days = cfg.retention.blocks_days,
        audit_days = cfg.retention.audit_days,
        alert_status = if alert_targets > 0 {
            "configured"
        } else {
            "no targets"
        },
        alert_targets = alert_targets,
        alert_pending = alerts.pending,
        alert_delivered = alerts.delivered,
        alert_failed = alerts.failed,
        alert_oldest = alerts
            .oldest_pending
            .map(time)
            .unwrap_or_else(|| "—".into()),
        alert_error = esc(if alerts.last_error.is_empty() {
            "—"
        } else {
            &alerts.last_error
        }),
    );
    shell(page, "/settings", "Settings", &body)
}

// --------------------------------------------------------------------- audit

pub fn audit(page: &Page<'_>, rows: &[crate::db::AuditDetailRow]) -> String {
    let mut body = String::new();
    for (ts, actor, action, subject, detail) in rows {
        let _ = write!(
            body,
            r#"<tr><td class="mono">{ts}</td><td>{actor}</td><td class="mono">{action}</td>
<td class="mono">{subject}</td><td>{detail}</td></tr>"#,
            ts = esc(&time(*ts)),
            actor = esc(actor),
            action = esc(action),
            subject = esc(subject),
            detail = esc(detail),
        );
    }
    let page_body = format!(
        r#"<section class="panel">
<h1>Audit log</h1>
<p class="hint">Every login attempt, configuration change, block and unblock, with actor
(<span class="mono">system</span>, <span class="mono">admin:&lt;user&gt;</span> or
<span class="mono">login:&lt;user&gt;</span>). The most recent 500 rows.</p>
<div class="scroll"><table>
<thead><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Subject</th><th>Detail</th></tr></thead>
<tbody>{body}</tbody></table></div>
</section>"#,
        body = body
    );
    shell(page, "/audit", "Audit log", &page_body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_dangerous_characters() {
        assert_eq!(
            esc(r#"<script>alert("x&y")</script>"#),
            "&lt;script&gt;alert(&quot;x&amp;y&quot;)&lt;/script&gt;"
        );
        assert_eq!(esc("it's"), "it&#39;s");
    }

    #[test]
    fn durations_are_human_readable() {
        assert_eq!(duration_label(BlockDuration::Temporary(3_600)), "1h");
        assert_eq!(duration_label(BlockDuration::Temporary(86_400)), "1d");
        assert_eq!(duration_label(BlockDuration::Permanent), "permanent");
    }

    #[test]
    fn detection_rows_escape_stored_values() {
        let page = Page {
            user: "alice",
            csrf: "token",
            breakglass: false,
            mode: Mode::Observe,
            bind: "127.0.0.1:10707".parse().unwrap(),
            version: "0.3.0",
        };
        let det = Detection {
            detector: Detector::VerticalScan,
            src: "203.0.113.7".parse().unwrap(),
            dst: Some("192.0.2.1".parse().unwrap()),
            dst_port: Some(22),
            proto: crate::model::Proto::Tcp,
            count: 20,
            window_secs: 10,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            metadata: serde_json::json!({"note": "<b>owned</b>"}),
            evidence_log_id: None,
            id: Some(1),
        };
        let geo = crate::geo::GeoData::default();
        let html = detection_rows(&page, std::slice::from_ref(&det), &geo);
        assert!(!html.contains("<b>owned</b>"));
        assert!(html.contains("&lt;b&gt;owned&lt;/b&gt;"));
        assert!(html.contains("DET-01"));
    }

    #[test]
    fn ip_history_shows_country_and_permanent_block() {
        let page = Page {
            user: "alice",
            csrf: "token",
            breakglass: false,
            mode: Mode::Enforce,
            bind: "127.0.0.1:10707".parse().unwrap(),
            version: "0.3.11",
        };
        let html = ip_history(
            &page,
            &IpHistory {
                ip: "203.0.113.7".parse().unwrap(),
                country: Some("US"),
                asn: Some(64_500),
                geo_loaded: true,
                allowlisted: None,
                active_block: None,
                strike: None,
                detections: &[],
                detection_total: 0,
                blocks: &[],
                block_total: 0,
                log_events: &[],
                log_total: 0,
                now: Utc::now(),
            },
        );
        assert!(html.contains("203.0.113.7"));
        assert!(html.contains("US"));
        assert!(html.contains("AS64500"));
        assert!(html.contains("Permanently block"));
        assert!(html.contains("name=\"minutes\" value=\"0\""));
        assert!(html.contains("No stored detections"));
    }
}
