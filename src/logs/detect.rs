//! Log-derived detectors DET-16/17/21/23.
//!
//! State is bounded exactly like the packet engine: per-source windows are
//! capped, old entries are pruned on every observation, and a source cap
//! clears the tables rather than growing without limit (FR-110 spirit).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};

use super::LogEvent;
use super::parse::{
    T_FIREWALL_DROP, T_HTTP_ACCESS, T_PAM_FAILURE, T_SSH_ACCEPTED, T_SSH_FAILED, T_SSH_INVALID,
};
use crate::config::LogDetection;
use crate::model::{Detection, Detector, Proto};

pub struct LogEngine {
    cfg: LogDetection,
    ssh_failures: HashMap<IpAddr, VecDeque<DateTime<Utc>>>,
    pam_failures: HashMap<IpAddr, VecDeque<DateTime<Utc>>>,
    http_paths: HashMap<IpAddr, HashMap<String, DateTime<Utc>>>,
    http_status: HashMap<IpAddr, VecDeque<DateTime<Utc>>>,
    firewall_drops: HashMap<IpAddr, VecDeque<DateTime<Utc>>>,
    /// Last SSH failure line keyed by source and user. The flag is true when
    /// the last line was `Invalid user`; OpenSSH can emit both `Invalid user`
    /// and `Failed password` for one attempt, so the following failure line is
    /// not counted twice.
    recent_ssh: HashMap<(IpAddr, String), (bool, DateTime<Utc>)>,
    cooldown: HashMap<(Detector, String), DateTime<Utc>>,
}

/// `Invalid user` followed by `Failed password` within this interval belongs
/// to one authentication attempt.
const SSH_ATTEMPT_DEDUPE_SECS: i64 = 2;

impl LogEngine {
    pub fn new(cfg: &LogDetection) -> LogEngine {
        LogEngine {
            cfg: cfg.clone(),
            ssh_failures: HashMap::new(),
            pam_failures: HashMap::new(),
            http_paths: HashMap::new(),
            http_status: HashMap::new(),
            firewall_drops: HashMap::new(),
            recent_ssh: HashMap::new(),
            cooldown: HashMap::new(),
        }
    }

    /// Feed one normalised event and return detections. `event.ts` is used as
    /// "now" so backfilled and clock-skewed entries keep their own window.
    pub fn observe(&mut self, event: &LogEvent) -> Vec<Detection> {
        let now = event.ts;
        let mut out = Vec::new();
        match event.template.as_str() {
            T_SSH_FAILED | T_SSH_INVALID => {
                if let Some(ip) = event.src_ip {
                    let key = (ip, event.user.as_deref().unwrap_or("").to_ascii_lowercase());
                    // Only the `Failed password` line directly following an
                    // `Invalid user` line is the same attempt. Distinct rapid
                    // attempts still count, whether the user is valid or not.
                    let duplicate = event.template == T_SSH_FAILED
                        && self
                            .recent_ssh
                            .get(&key)
                            .map(|(was_invalid, ts)| {
                                *was_invalid && (now - *ts).num_seconds() < SSH_ATTEMPT_DEDUPE_SECS
                            })
                            .unwrap_or(false);
                    let was_invalid = event.template == T_SSH_INVALID;
                    self.recent_ssh.insert(key, (was_invalid, now));
                    if !duplicate {
                        let n = window_push(
                            &mut self.ssh_failures,
                            ip,
                            now,
                            self.cfg.window_secs,
                            self.cfg.max_tracked_sources,
                        );
                        if n as u32 >= self.cfg.ssh_failures
                            && self.ready(Detector::SshAuthFailures, &ip.to_string(), now)
                        {
                            out.push(self.make(Detector::SshAuthFailures, event, ip, n));
                        }
                    }
                    if self.recent_ssh.len() > self.cfg.max_tracked_sources {
                        let cutoff = now - Duration::seconds(SSH_ATTEMPT_DEDUPE_SECS);
                        self.recent_ssh.retain(|_, (_, ts)| *ts >= cutoff);
                        if self.recent_ssh.len() > self.cfg.max_tracked_sources {
                            self.recent_ssh.clear();
                        }
                    }
                }
            }
            T_SSH_ACCEPTED => {
                if let Some(ip) = event.src_ip {
                    let failures = self
                        .ssh_failures
                        .get(&ip)
                        .map(|q| live_count(q, now, self.cfg.window_secs))
                        .unwrap_or(0);
                    if failures > 0
                        && self.ready(Detector::SshSuccessAfterFailures, &ip.to_string(), now)
                    {
                        out.push(self.make(Detector::SshSuccessAfterFailures, event, ip, failures));
                        // One success report per failure burst.
                        self.ssh_failures.remove(&ip);
                    }
                }
            }
            T_PAM_FAILURE => {
                // SSH PAM failures are already DET-16; DET-21 is for the other
                // services ("any service" minus the one with a dedicated rule).
                let ssh_service = event
                    .service
                    .as_deref()
                    .map(|s| s.eq_ignore_ascii_case("sshd"))
                    .unwrap_or(false)
                    || event
                        .identifier
                        .as_deref()
                        .map(|s| s.eq_ignore_ascii_case("sshd"))
                        .unwrap_or(false);
                if let Some(ip) = event.src_ip {
                    if !ssh_service {
                        let n = window_push(
                            &mut self.pam_failures,
                            ip,
                            now,
                            self.cfg.window_secs,
                            self.cfg.max_tracked_sources,
                        );
                        if n as u32 >= self.cfg.pam_failures
                            && self.ready(Detector::PamFailureBurst, &ip.to_string(), now)
                        {
                            out.push(self.make(Detector::PamFailureBurst, event, ip, n));
                        }
                    }
                }
            }
            T_FIREWALL_DROP => {
                if let Some(ip) = event.src_ip {
                    let n = window_push(
                        &mut self.firewall_drops,
                        ip,
                        now,
                        self.cfg.window_secs,
                        self.cfg.max_tracked_sources,
                    );
                    // Rate-limited at the firewall, and cooldown-limited here so
                    // a drop storm does not flood detections or webhooks.
                    if self.ready(Detector::FirewallDrop, &ip.to_string(), now) {
                        out.push(self.make(Detector::FirewallDrop, event, ip, n));
                    }
                }
            }
            T_HTTP_ACCESS => {
                if let Some(ip) = event.src_ip {
                    let window = self.cfg.http_scan_window_secs.max(1) as i64;
                    if let Some(path) = &event.path {
                        let paths = self.http_paths.entry(ip).or_default();
                        paths.retain(|_, ts| (now - *ts).num_seconds() < window);
                        paths.insert(path.clone(), now);
                        if paths.len() > 256 {
                            paths.clear();
                        }
                        let unique = paths.len();
                        if unique as u32 >= self.cfg.http_scan_paths
                            && self.ready(Detector::HttpLogScan, &ip.to_string(), now)
                        {
                            out.push(self.make(Detector::HttpLogScan, event, ip, unique));
                        }
                    }
                    if matches!(event.status, Some(403) | Some(404)) {
                        let statuses = self.http_status.entry(ip).or_default();
                        statuses.push_back(now);
                        let cutoff = now - Duration::seconds(window);
                        while statuses.front().is_some_and(|ts| *ts < cutoff) {
                            statuses.pop_front();
                        }
                        if statuses.len() > 4096 {
                            statuses.clear();
                        }
                        let not_found = statuses.len();
                        if not_found as u32 >= self.cfg.http_scan_404
                            && self.ready(Detector::HttpLogScan, &ip.to_string(), now)
                        {
                            out.push(self.make(Detector::HttpLogScan, event, ip, not_found));
                        }
                    }
                    if self.http_paths.len() > self.cfg.max_tracked_sources {
                        self.http_paths.clear();
                        self.http_status.clear();
                    }
                }
            }
            _ => {}
        }
        out
    }

    fn ready(&mut self, detector: Detector, key: &str, now: DateTime<Utc>) -> bool {
        let map_key = (detector, key.to_string());
        if let Some(previous) = self.cooldown.get(&map_key) {
            if (now - *previous).num_seconds() < self.cfg.cooldown_secs as i64 {
                return false;
            }
        }
        self.cooldown.insert(map_key.clone(), now);
        if self.cooldown.len() > self.cfg.max_tracked_sources.saturating_mul(2) {
            self.cooldown.clear();
            self.cooldown.insert(map_key, now);
        }
        true
    }

    fn make(&self, detector: Detector, event: &LogEvent, src: IpAddr, count: usize) -> Detection {
        let window = self.cfg.window_secs.max(1);
        let evidence: String = event.message.chars().take(256).collect();
        Detection {
            detector,
            src,
            dst: None,
            dst_port: None,
            proto: Proto::Log,
            count: count as u64,
            window_secs: window,
            first_seen: event.ts - Duration::seconds(window as i64),
            last_seen: event.ts,
            metadata: serde_json::json!({
                "origin": event.origin.as_str(),
                "source": event.source,
                "unit": event.unit,
                "identifier": event.identifier,
                "service": event.service,
                "priority": event.priority,
                "user": event.user,
                "action": event.action,
                "outcome": event.outcome,
                "method": event.method,
                "path": event.path,
                "status": event.status,
                "template": event.template,
                "cursor": event.cursor,
                "evidence": evidence,
            }),
            evidence_log_id: event.id,
            id: None,
        }
    }
}

fn live_count(queue: &VecDeque<DateTime<Utc>>, now: DateTime<Utc>, window: u64) -> usize {
    let cutoff = now - Duration::seconds(window as i64);
    queue.iter().filter(|ts| **ts >= cutoff).count()
}

fn window_push<K: Eq + Hash + Clone>(
    map: &mut HashMap<K, VecDeque<DateTime<Utc>>>,
    key: K,
    now: DateTime<Utc>,
    window: u64,
    cap: usize,
) -> usize {
    let len = {
        let queue = map.entry(key).or_default();
        queue.push_back(now);
        let cutoff = now - Duration::seconds(window as i64);
        while let Some(front) = queue.front() {
            if *front < cutoff {
                queue.pop_front();
            } else {
                break;
            }
        }
        queue.len()
    };
    if map.len() > cap.max(1) {
        map.clear();
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::Origin;

    fn event(template: &str, src: Option<IpAddr>, ts: DateTime<Utc>) -> LogEvent {
        LogEvent {
            ts,
            origin: Origin::Journal,
            source: "journal".into(),
            unit: Some("ssh.service".into()),
            identifier: Some("sshd".into()),
            priority: Some(6),
            host: Some("host".into()),
            pid: Some(1),
            user: Some("root".into()),
            service: None,
            src_ip: src,
            action: Some("ssh.auth".into()),
            outcome: Some("failure".into()),
            method: None,
            path: None,
            status: None,
            template: template.into(),
            message: "evidence".into(),
            cursor: Some("s=1".into()),
            parser: "sshd".into(),
            id: Some(7),
        }
    }

    #[test]
    fn ssh_failures_fire_once_per_cooldown() {
        let cfg = LogDetection {
            window_secs: 600,
            cooldown_secs: 300,
            ..LogDetection::default()
        };
        let mut engine = LogEngine::new(&cfg);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let start = Utc::now();
        let mut found = Vec::new();
        for i in 0..8 {
            // Distinct attempts, spaced beyond the two-line dedupe window.
            let e = event(T_SSH_FAILED, Some(ip), start + Duration::seconds(i * 3));
            found.extend(engine.observe(&e));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].detector, Detector::SshAuthFailures);
        assert_eq!(found[0].count, 5);
        assert_eq!(found[0].proto, Proto::Log);
        assert_eq!(found[0].evidence_log_id, Some(7));
    }

    #[test]
    fn one_ssh_attempt_with_two_lines_counts_once() {
        let cfg = LogDetection {
            window_secs: 600,
            cooldown_secs: 300,
            ssh_failures: 5,
            ..LogDetection::default()
        };
        let mut engine = LogEngine::new(&cfg);
        let ip: IpAddr = "203.0.113.12".parse().unwrap();
        let start = Utc::now();
        let mut found = Vec::new();
        for attempt in 0..5 {
            let base = start + Duration::seconds(attempt * 3);
            // OpenSSH writes both lines for a single rejected attempt.
            found.extend(engine.observe(&event(T_SSH_INVALID, Some(ip), base)));
            found.extend(engine.observe(&event(
                T_SSH_FAILED,
                Some(ip),
                base + Duration::milliseconds(300),
            )));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].detector, Detector::SshAuthFailures);
        assert_eq!(found[0].count, 5);
    }

    #[test]
    fn rapid_invalid_user_attempts_each_count() {
        let cfg = LogDetection {
            window_secs: 600,
            cooldown_secs: 300,
            ssh_failures: 5,
            ..LogDetection::default()
        };
        let mut engine = LogEngine::new(&cfg);
        let ip: IpAddr = "203.0.113.13".parse().unwrap();
        let start = Utc::now();
        let mut found = Vec::new();
        for attempt in 0..5 {
            found.extend(engine.observe(&event(
                T_SSH_INVALID,
                Some(ip),
                start + Duration::milliseconds(attempt * 200),
            )));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].count, 5);
    }

    #[test]
    fn ssh_success_after_failures_alerts_only() {
        let mut engine = LogEngine::new(&LogDetection::default());
        let ip: IpAddr = "203.0.113.8".parse().unwrap();
        let start = Utc::now();
        for i in 0..5 {
            engine.observe(&event(
                T_SSH_FAILED,
                Some(ip),
                start + Duration::seconds(i * 3),
            ));
        }
        let found = engine.observe(&event(
            T_SSH_ACCEPTED,
            Some(ip),
            start + Duration::seconds(16),
        ));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].detector, Detector::SshSuccessAfterFailures);
        assert!(found[0].detector.is_alert_only());
        // A second success does not repeat the alert.
        assert!(
            engine
                .observe(&event(
                    T_SSH_ACCEPTED,
                    Some(ip),
                    start + Duration::seconds(17)
                ))
                .is_empty()
        );
    }

    #[test]
    fn pam_failures_skip_ssh_but_fire_for_other_services() {
        let mut engine = LogEngine::new(&LogDetection::default());
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let start = Utc::now();
        let mut e = event(T_PAM_FAILURE, Some(ip), start);
        e.service = Some("sshd".into());
        for _ in 0..5 {
            assert!(engine.observe(&e).is_empty());
        }
        let mut e = event(T_PAM_FAILURE, Some(ip), start);
        e.service = Some("sudo".into());
        e.identifier = Some("sudo".into());
        let mut found = Vec::new();
        for _ in 0..5 {
            found.extend(engine.observe(&e));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].detector, Detector::PamFailureBurst);
    }

    #[test]
    fn retired_internal_templates_do_not_emit_detections() {
        use crate::logs::parse::{T_ACCOUNT_CHANGE, T_SECURITY_CHANGE, T_SUDO_DENIED};
        let mut engine = LogEngine::new(&LogDetection::default());
        let start = Utc::now();
        for (i, template) in [T_SUDO_DENIED, T_SECURITY_CHANGE, T_ACCOUNT_CHANGE]
            .iter()
            .enumerate()
        {
            let mut e = event(template, None, start + Duration::seconds(i as i64));
            e.identifier = Some("sudo".into());
            assert!(
                engine.observe(&e).is_empty(),
                "{template} still emits a retired detector"
            );
        }
    }

    #[test]
    fn firewall_drops_fire_det27_once_per_cooldown() {
        let cfg = LogDetection {
            window_secs: 60,
            cooldown_secs: 300,
            ..LogDetection::default()
        };
        let mut engine = LogEngine::new(&cfg);
        let ip: IpAddr = "203.0.113.70".parse().unwrap();
        let start = Utc::now();
        let mut found = Vec::new();
        for i in 0..4 {
            found.extend(engine.observe(&event(
                T_FIREWALL_DROP,
                Some(ip),
                start + Duration::seconds(i),
            )));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].detector, Detector::FirewallDrop);
        assert!(found[0].detector.is_alert_only());
        assert_eq!(found[0].count, 1);
        // A later drop inside the cooldown is silent; later still fires again.
        assert!(
            engine
                .observe(&event(
                    T_FIREWALL_DROP,
                    Some(ip),
                    start + Duration::seconds(30)
                ))
                .is_empty()
        );
        let later = engine.observe(&event(
            T_FIREWALL_DROP,
            Some(ip),
            start + Duration::seconds(400),
        ));
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].detector, Detector::FirewallDrop);
    }

    #[test]
    fn http_access_log_path_scan_and_404_burst_fire_det23() {
        let mut engine = LogEngine::new(&LogDetection::default());
        let ip: IpAddr = "203.0.113.80".parse().unwrap();
        let start = Utc::now();
        let mut found = Vec::new();
        for i in 0..20 {
            let mut e = event(T_HTTP_ACCESS, Some(ip), start + Duration::seconds(i));
            e.method = Some("GET".into());
            e.path = Some(format!("/p{i}"));
            e.status = Some(200);
            found.extend(engine.observe(&e));
        }
        assert!(found.iter().any(|d| d.detector == Detector::HttpLogScan));

        let mut engine = LogEngine::new(&LogDetection::default());
        let mut found = Vec::new();
        for i in 0..15 {
            let mut e = event(T_HTTP_ACCESS, Some(ip), start + Duration::seconds(i));
            e.method = Some("GET".into());
            e.path = Some("/missing".into());
            e.status = Some(404);
            found.extend(engine.observe(&e));
        }
        assert!(found.iter().any(|d| d.detector == Detector::HttpLogScan));
    }

    #[test]
    fn benign_http_access_log_does_not_fire() {
        let mut engine = LogEngine::new(&LogDetection::default());
        let ip: IpAddr = "203.0.113.81".parse().unwrap();
        let start = Utc::now();
        for i in 0..20 {
            let mut e = event(T_HTTP_ACCESS, Some(ip), start + Duration::seconds(i));
            e.method = Some("GET".into());
            e.path = Some("/health".into());
            e.status = Some(200);
            assert!(engine.observe(&e).is_empty());
        }
    }

    #[test]
    fn source_table_is_capped_instead_of_growing() {
        let cfg = LogDetection {
            max_tracked_sources: 4,
            ..LogDetection::default()
        };
        let mut engine = LogEngine::new(&cfg);
        let start = Utc::now();
        for i in 0..200u32 {
            let ip: IpAddr = format!("203.0.113.{}", (i % 200) + 1).parse().unwrap();
            engine.observe(&event(
                T_SSH_FAILED,
                Some(ip),
                start + Duration::seconds(i as i64),
            ));
            assert!(
                engine.ssh_failures.len() <= 4,
                "table grew past the cap at iteration {i}"
            );
        }
    }

    #[test]
    fn failures_outside_the_window_do_not_count() {
        let cfg = LogDetection {
            window_secs: 60,
            cooldown_secs: 300,
            ssh_failures: 5,
            ..LogDetection::default()
        };
        let mut engine = LogEngine::new(&cfg);
        let ip: IpAddr = "203.0.113.11".parse().unwrap();
        let start = Utc::now();
        // Five failures an hour apart never reach the five-per-minute rule.
        for i in 0..5 {
            let found = engine.observe(&event(
                T_SSH_FAILED,
                Some(ip),
                start + Duration::seconds(i * 3600),
            ));
            assert!(found.is_empty());
        }
    }
}
