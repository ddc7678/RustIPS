//! Host-log ingestion: normalised events, parsers, and log detectors.
//!
//! The journal is the first origin (0.3.0 slice A). File sources reuse the
//! same [`LogEvent`] shape and the same detection pipeline.
//!
//! Everything in this module treats log text as untrusted: messages are
//! length-capped, control characters are neutralised, and no field is ever
//! interpolated into a shell command or an HTML template without escaping.

pub mod detect;
pub mod journal;
pub mod parse;

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use detect::LogEngine;
pub use journal::JournalHandle;

/// Where an event came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Journal,
    File,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Journal => "journal",
            Origin::File => "file",
        }
    }
}

/// One normalised host-log event (FR-304). Raw text is bounded before it ever
/// reaches this struct; the parser adds only derived fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub ts: DateTime<Utc>,
    pub origin: Origin,
    /// Origin name: `journal` today, a path for file sources.
    pub source: String,
    pub unit: Option<String>,
    pub identifier: Option<String>,
    pub priority: Option<u8>,
    pub host: Option<String>,
    pub pid: Option<u32>,
    pub user: Option<String>,
    /// Service name from a `pam_unix(<service>:auth)` line, when present.
    pub service: Option<String>,
    pub src_ip: Option<IpAddr>,
    /// Coarse action, e.g. `ssh.auth`, `pam.auth`, `sudo`, `system.change`.
    pub action: Option<String>,
    /// `failure`, `success`, `denied`, `observed`.
    pub outcome: Option<String>,
    /// HTTP method, target path and status for access-log events.
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    /// Stable parser template, e.g. `sshd.failed_password`.
    pub template: String,
    /// Bounded, redacted message. Empty when `logs.store_raw = false`.
    pub message: String,
    /// Journal cursor for provenance and exact resume (FR-302/310).
    pub cursor: Option<String>,
    pub parser: String,
    pub id: Option<i64>,
}

impl LogEvent {
    pub fn origin(&self) -> &'static str {
        self.origin.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&Origin::Journal).unwrap(),
            "\"journal\""
        );
    }
}
