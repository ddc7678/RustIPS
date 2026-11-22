//! Filesystem layout.
//!
//! Everything RustIPS writes lives under two roots:
//!
//! * `/etc/rustips/`     — configuration (presence decides first run, FR-217)
//! * `/var/lib/rustips/` — database, backups, runtime state
//!
//! Both can be overridden for tests and non-system installs with the
//! `RUSTIPS_CONFIG` and `RUSTIPS_STATE_DIR` environment variables.

use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG: &str = "/etc/rustips/config.toml";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/rustips";

#[derive(Debug, Clone)]
pub struct Layout {
    pub config: PathBuf,
    pub state_dir: PathBuf,
    pub db: PathBuf,
    pub backups: PathBuf,
}

impl Layout {
    pub fn resolve(config_override: Option<PathBuf>) -> Layout {
        Layout::with_overrides(config_override, None)
    }

    pub fn with_overrides(
        config_override: Option<PathBuf>,
        state_override: Option<PathBuf>,
    ) -> Layout {
        let config = config_override
            .or_else(|| std::env::var_os("RUSTIPS_CONFIG").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));

        let state_dir = state_override
            .or_else(|| std::env::var_os("RUSTIPS_STATE_DIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));

        Layout {
            db: state_dir.join("rustips.db"),
            backups: state_dir.join("backups"),
            config,
            state_dir,
        }
    }

    /// Configuration file present and readable?
    pub fn has_config(&self) -> bool {
        self.config.is_file()
    }

    /// State database present? Presence matters even if the config is gone:
    /// that combination is "recovery", never "fresh install" (FR-218).
    pub fn has_state(&self) -> bool {
        self.db.is_file() || self.state_dir.join("rustips.db-wal").is_file()
    }

    /// What kind of start is this?
    pub fn startup(&self) -> Startup {
        match (self.has_config(), self.has_state()) {
            (true, _) => Startup::Normal,
            (false, false) => Startup::Unconfigured,
            (false, true) => Startup::Recovery,
        }
    }

    pub fn ensure_state_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.state_dir)?;
        set_mode(&self.state_dir, 0o700)
    }

    pub fn ensure_config_dir(&self) -> std::io::Result<()> {
        if let Some(parent) = self.config.parent() {
            let existed = parent.exists();
            std::fs::create_dir_all(parent)?;
            // Never chmod a pre-existing parent (for example /tmp or a user's
            // home directory) when the config path is overridden for a test.
            if !existed {
                set_mode(parent, 0o755)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Startup {
    /// Config present: normal start (validation still applies).
    Normal,
    /// No config, no state: a real first run.
    Unconfigured,
    /// No config but state exists: refuse, offer recovery.
    Recovery,
}

/// Best-effort permission tightening. Failure is not fatal here; the
/// subsequent open will report the real problem.
pub fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config_and_state_is_unconfigured() {
        let layout = Layout {
            config: PathBuf::from("/nonexistent/config.toml"),
            state_dir: PathBuf::from("/nonexistent/state"),
            db: PathBuf::from("/nonexistent/state/rustips.db"),
            backups: PathBuf::from("/nonexistent/state/backups"),
        };
        assert_eq!(layout.startup(), Startup::Unconfigured);
    }

    #[test]
    fn existing_config_parent_mode_is_not_changed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "rustips-paths-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let layout = Layout {
            config: dir.join("config.toml"),
            state_dir: dir.join("state"),
            db: dir.join("state/rustips.db"),
            backups: dir.join("state/backups"),
        };
        layout.ensure_config_dir().unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o1777);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn state_without_config_is_recovery_not_a_fresh_install() {
        let dir = std::env::temp_dir().join(format!(
            "rustips-paths-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rustips.db"), b"not a real database").unwrap();
        let layout = Layout {
            config: dir.join("config.toml"),
            state_dir: dir.clone(),
            db: dir.join("rustips.db"),
            backups: dir.join("backups"),
        };
        assert_eq!(layout.startup(), Startup::Recovery);
        std::fs::remove_dir_all(dir).ok();
    }
}
