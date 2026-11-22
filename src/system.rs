//! Lightweight resource sampling for the dashboard.
//!
//! Values come from `/proc` and the state directory; there is no dependency on
//! a system-monitoring crate. The sampler is driven by the scheduler thread, so
//! the web UI only reads stored points.

use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, Copy, Default)]
pub struct Sample {
    pub cpu_pct: f64,
    pub rss_mb: f64,
    pub db_mb: f64,
}

pub struct Sampler {
    last_ticks: Option<u64>,
    last_at: Instant,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

impl Sampler {
    pub fn new() -> Sampler {
        Sampler {
            last_ticks: None,
            last_at: Instant::now(),
        }
    }

    pub fn sample(&mut self, db_path: &Path) -> Sample {
        let now = Instant::now();
        let ticks = cpu_ticks();
        let cpu_pct = match (self.last_ticks, ticks) {
            (Some(previous), Some(current)) if current >= previous => {
                let elapsed = now.duration_since(self.last_at).as_secs_f64();
                let hz = clock_ticks();
                if elapsed > 0.0 && hz > 0.0 {
                    ((current - previous) as f64 / hz / elapsed * 100.0).clamp(0.0, 100_000.0)
                } else {
                    0.0
                }
            }
            _ => 0.0,
        };
        self.last_ticks = ticks;
        self.last_at = now;
        Sample {
            cpu_pct,
            rss_mb: rss_mb(),
            db_mb: db_mb(db_path),
        }
    }
}

fn clock_ticks() -> f64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 { ticks as f64 } else { 100.0 }
}

/// User + system CPU ticks from `/proc/self/stat`.
fn cpu_ticks() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/stat").ok()?;
    let close = text.rfind(')')?;
    let rest = &text[close + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let utime = fields.get(11)?.parse::<u64>().ok()?;
    let stime = fields.get(12)?.parse::<u64>().ok()?;
    Some(utime.saturating_add(stime))
}

fn rss_mb() -> f64 {
    let Ok(text) = std::fs::read_to_string("/proc/self/status") else {
        return 0.0;
    };
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            let kb = value
                .split_whitespace()
                .next()
                .and_then(|number| number.parse::<f64>().ok())
                .unwrap_or(0.0);
            return kb / 1024.0;
        }
    }
    0.0
}

/// Database storage includes the main file plus the WAL/SHM sidecars.
fn db_mb(path: &Path) -> f64 {
    let mut bytes = 0_u64;
    if let Ok(metadata) = std::fs::metadata(path) {
        bytes = bytes.saturating_add(metadata.len());
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = format!("{}{suffix}", path.display());
        if let Ok(metadata) = std::fs::metadata(sidecar) {
            bytes = bytes.saturating_add(metadata.len());
        }
    }
    bytes as f64 / (1024.0 * 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampler_reads_process_and_database_size() {
        let dir = std::env::temp_dir().join(format!(
            "rustips-system-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("db");
        std::fs::write(&path, vec![0_u8; 1024 * 1024]).unwrap();
        let mut sampler = Sampler::new();
        let sample = sampler.sample(&path);
        assert!(sample.rss_mb > 0.0, "VmRSS should be available on Linux");
        assert!(sample.db_mb >= 1.0);
        assert!(sample.cpu_pct >= 0.0);
        std::fs::remove_dir_all(dir).ok();
    }
}
