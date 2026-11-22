//! Download, verify and hot-swap the GeoIP/ASN indexes (FR-163…168).
//!
//! Downloads are performed with `curl` (no TLS stack is linked into the
//! binary). The published `.sha256` file is fetched and checked before an
//! index is built, and a failed build never replaces the live files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::{
    BuildStats, GeoData, GeoHandle, GeoIndexStatus, GeoKind, GeoStatus, build_index, index_status,
    install, load_from_dir, sha256, to_hex,
};
use crate::config::Config;
use crate::db::Db;
use crate::error::{Error, Result};

const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct LocalFiles {
    pub country_v4: PathBuf,
    pub country_v6: PathBuf,
    pub asn_v4: PathBuf,
    pub asn_v6: PathBuf,
}

#[derive(Debug, Default)]
pub struct UpdateReport {
    pub country: Option<BuildStats>,
    pub asn: Option<BuildStats>,
    /// SHA-256 of each source CSV from this check.
    pub sources: BTreeMap<String, String>,
    /// True when the published checksums match the last install and no build
    /// was needed (FR-163: do not download the CSVs when nothing changed).
    pub unchanged: bool,
}

type Sources = (String, &'static str);

/// Run a checksum → (download) → build → install cycle. When the published
/// checksums match the previous install, the large CSVs are not fetched.
pub fn update_from_network(
    cfg: &Config,
    state_dir: &Path,
    previous: &GeoStatus,
) -> Result<UpdateReport> {
    let geo = &cfg.geo;
    let temp = TempDir::new(state_dir)?;
    let country: Vec<Sources> = vec![
        (
            format!("{}-ipv4.csv", geo.country_base_url.trim_end_matches('/')),
            "user-country-ipv4.csv",
        ),
        (
            format!("{}-ipv6.csv", geo.country_base_url.trim_end_matches('/')),
            "user-country-ipv6.csv",
        ),
    ];
    let asn: Vec<Sources> = vec![
        (
            format!("{}-ipv4.csv", geo.asn_base_url.trim_end_matches('/')),
            "origin-asn-ipv4.csv",
        ),
        (
            format!("{}-ipv6.csv", geo.asn_base_url.trim_end_matches('/')),
            "origin-asn-ipv6.csv",
        ),
    ];
    let mut sources = fetch_checksums(&temp.path, &geo.checksum_base_url, &country)?;
    sources.extend(fetch_checksums(&temp.path, &geo.checksum_base_url, &asn)?);
    let dir = state_dir.join("geo");
    if previous.sources == sources
        && dir.join(GeoKind::Country.filename()).exists()
        && dir.join(GeoKind::Asn.filename()).exists()
    {
        return Ok(UpdateReport {
            sources,
            unchanged: true,
            ..UpdateReport::default()
        });
    }

    let country_paths = download_pair(&temp.path, &country, &sources)?;
    let country_stats = build_and_install(
        state_dir,
        &temp.path,
        GeoKind::Country,
        &country_paths.0,
        &country_paths.1,
    )?;
    let asn_paths = download_pair(&temp.path, &asn, &sources)?;
    let asn_stats = build_and_install(
        state_dir,
        &temp.path,
        GeoKind::Asn,
        &asn_paths.0,
        &asn_paths.1,
    )?;
    Ok(UpdateReport {
        country: Some(country_stats),
        asn: Some(asn_stats),
        sources,
        unchanged: false,
    })
}

type Pair = (PathBuf, PathBuf);

fn fetch_checksums(
    temp: &Path,
    checksum_base: &str,
    files: &[Sources],
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (_, filename) in files {
        let checksum_url = format!("{}/{filename}.sha256", checksum_base.trim_end_matches('/'));
        let checksum_path = temp.join(format!("{filename}.sha256"));
        download(&checksum_url, &checksum_path)?;
        out.insert((*filename).to_string(), read_checksum(&checksum_path)?);
    }
    Ok(out)
}

fn download_pair(
    temp: &Path,
    files: &[Sources],
    expected: &BTreeMap<String, String>,
) -> Result<Pair> {
    let mut paths = Vec::new();
    for (url, filename) in files {
        let path = temp.join(filename);
        download(url, &path)?;
        let actual = to_hex(&sha256(&std::fs::read(&path)?));
        let wanted = expected
            .get(*filename)
            .ok_or_else(|| Error::Other(format!("no checksum for {filename}")))?;
        if !actual.eq_ignore_ascii_case(wanted) {
            return Err(Error::Config(format!(
                "checksum mismatch for {filename}: expected {wanted}, got {actual}"
            )));
        }
        paths.push(path);
    }
    if paths.len() != 2 {
        return Err(Error::Other("geo download pair is incomplete".into()));
    }
    Ok((paths.remove(0), paths.remove(0)))
}

fn build_and_install(
    state_dir: &Path,
    temp: &Path,
    kind: GeoKind,
    v4: &Path,
    v6: &Path,
) -> Result<BuildStats> {
    let temp_bin = temp.join(format!("{}-new.bin", kind.as_str()));
    let stats = build_index(kind, v4, v6, &temp_bin)?;
    install(state_dir, kind, &temp_bin)?;
    Ok(stats)
}

/// Build both indexes from local CSV files (offline update / air-gapped host).
pub fn update_from_files(state_dir: &Path, files: &LocalFiles) -> Result<UpdateReport> {
    let temp = TempDir::new(state_dir)?;
    let country = build_and_install(
        state_dir,
        &temp.path,
        GeoKind::Country,
        &files.country_v4,
        &files.country_v6,
    )?;
    let asn = build_and_install(
        state_dir,
        &temp.path,
        GeoKind::Asn,
        &files.asn_v4,
        &files.asn_v6,
    )?;
    Ok(UpdateReport {
        country: Some(country),
        asn: Some(asn),
        sources: BTreeMap::new(),
        unchanged: false,
    })
}

fn download(url: &str, out: &Path) -> Result<()> {
    if url.is_empty()
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
        || !(url.starts_with("https://") || url.starts_with("http://"))
    {
        return Err(Error::Config(format!("refusing invalid geo URL {url:?}")));
    }
    let max_bytes = MAX_DOWNLOAD_BYTES.to_string();
    let status = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "180",
            "--max-filesize",
            &max_bytes,
            "--output",
        ])
        .arg(out)
        .arg(url)
        .status()
        .map_err(|e| Error::Other(format!("cannot run curl: {e}")))?;
    if !status.success() {
        return Err(Error::Other(format!(
            "curl failed for {url} ({status}); geo data is unchanged"
        )));
    }
    Ok(())
}

fn read_checksum(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)?;
    let token = text
        .split_whitespace()
        .find(|token| token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| Error::Config(format!("{}: no SHA-256 digest found", path.display())))?;
    Ok(token.to_ascii_lowercase())
}

pub fn read_status(db: &Db) -> GeoStatus {
    db.get_setting("geo.status")
        .ok()
        .flatten()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

pub fn write_status(db: &Db, status: &GeoStatus) -> Result<()> {
    db.set_setting("geo.status", &serde_json::to_value(status)?)
}

pub fn status_from_data(data: &GeoData, previous: &GeoStatus) -> GeoStatus {
    let now = Utc::now();
    let mut status = previous.clone();
    status.country = data.country.as_ref().map(|index| index_status(index, now));
    status.asn = data.asn.as_ref().map(|index| index_status(index, now));
    status
}

/// Background updater. It also honours a manual `geo.request` setting written
/// by the UI/CLI, even when automatic updates are disabled.
pub fn spawn(
    db_path: PathBuf,
    state_dir: PathBuf,
    cfg: Config,
    geo: GeoHandle,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let db = match Db::open(&db_path) {
            Ok(db) => db,
            Err(e) => {
                tracing::error!("geo updater cannot open the database: {e}");
                return;
            }
        };
        let mut status = read_status(&db);
        let mut last_request = request_value(&db);
        let mut last_reload = reload_value(&db);
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let now = Utc::now();
            let reload = reload_value(&db);
            if reload.is_some() && reload != last_reload {
                let data = load_from_dir(&state_dir);
                *geo.write().unwrap_or_else(|poison| poison.into_inner()) = data;
                status = status_from_data(
                    &geo.read().unwrap_or_else(|poison| poison.into_inner()),
                    &status,
                );
                let _ = write_status(&db, &status);
                last_reload = reload;
                tracing::info!("geo indexes reloaded from disk");
            }
            let request = request_value(&db);
            let forced = request.is_some() && request != last_request;
            let due = cfg.geo.enabled
                && cfg.geo.update_hours > 0
                && status.next_check.map(|next| now >= next).unwrap_or(true);
            if forced || due {
                status.last_check = Some(now);
                match update_from_network(&cfg, &state_dir, &status) {
                    Ok(report) => {
                        if !report.unchanged {
                            let data = load_from_dir(&state_dir);
                            *geo.write().unwrap_or_else(|poison| poison.into_inner()) = data;
                            status.country = report
                                .country
                                .as_ref()
                                .map(|stats| stats_status(stats, now));
                            status.asn = report.asn.as_ref().map(|stats| stats_status(stats, now));
                        }
                        status.sources = report.sources;
                        status.last_success = Some(now);
                        status.last_error = None;
                        status.next_check =
                            Some(now + chrono::Duration::hours(cfg.geo.update_hours.max(1) as i64));
                        tracing::info!(unchanged = report.unchanged, "geo check complete");
                    }
                    Err(e) => {
                        status.last_error = Some(e.to_string());
                        status.next_check = Some(now + chrono::Duration::minutes(15));
                        let _ = crate::alerts::enqueue_operational(
                            &db,
                            "geo.update_failed",
                            &e.to_string(),
                            now,
                        );
                        tracing::warn!("geo update failed: {e}");
                    }
                }
                let _ = write_status(&db, &status);
                last_request = request;
            }
            sleep_unless_stopped(&stop, 5);
        }
    })
}

pub fn stats_status(stats: &BuildStats, at: DateTime<Utc>) -> GeoIndexStatus {
    GeoIndexStatus {
        sha256: stats.sha256.clone(),
        v4: stats.v4,
        v6: stats.v6,
        bytes: stats.bytes,
        loaded_at: at,
    }
}

fn reload_value(db: &Db) -> Option<String> {
    db.get_setting("geo.reload")
        .ok()
        .flatten()
        .and_then(|value| value.as_str().map(str::to_string))
}

fn request_value(db: &Db) -> Option<String> {
    db.get_setting("geo.request")
        .ok()
        .flatten()
        .and_then(|value| value.as_str().map(str::to_string))
}

fn sleep_unless_stopped(stop: &Arc<AtomicBool>, secs: u64) {
    let mut remaining = secs * 4;
    while remaining > 0 && !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(250));
        remaining -= 1;
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(state_dir: &Path) -> Result<TempDir> {
        let path = state_dir.join("geo").join(format!(
            "tmp-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
