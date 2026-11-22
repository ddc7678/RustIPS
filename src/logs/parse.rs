//! Journal record decoding and the parser registry.
//!
//! Parsers are keyed by journal identifier first (`sshd`, `sudo`, …) and by
//! message shape second (PAM lines arrive under the calling unit's identifier).
//! All matching is linear string scanning: there are no user-supplied regular
//! expressions in this slice (FR-308).

use std::net::IpAddr;

use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

use super::{LogEvent, Origin};

pub const T_SSH_FAILED: &str = "sshd.failed_password";
pub const T_SSH_INVALID: &str = "sshd.invalid_user";
pub const T_SSH_ACCEPTED: &str = "sshd.accepted";
pub const T_SSH_OTHER: &str = "sshd.other";
pub const T_PAM_FAILURE: &str = "pam.auth_failure";
pub const T_SUDO_COMMAND: &str = "sudo.command";
pub const T_SUDO_DENIED: &str = "sudo.denied";
pub const T_SUDO_AUTH_FAILURE: &str = "sudo.auth_failure";
pub const T_LOGIND_SESSION: &str = "logind.session";
pub const T_KERNEL: &str = "kernel.log";
pub const T_CRON: &str = "cron.job";
pub const T_SECURITY_CHANGE: &str = "system.security_change";
pub const T_ACCOUNT_CHANGE: &str = "account.modification";
pub const T_HTTP_ACCESS: &str = "http.access";
pub const T_GENERIC: &str = "generic";

/// A decoded `journalctl -o json` record before parser classification.
#[derive(Debug, Clone)]
pub struct JournalRecord {
    pub cursor: Option<String>,
    pub ts: DateTime<Utc>,
    pub unit: Option<String>,
    pub identifier: Option<String>,
    pub priority: Option<u8>,
    pub host: Option<String>,
    pub pid: Option<u32>,
    pub message: String,
}

/// Decode one JSON line. Returns `None` for non-JSON or non-object input;
/// callers count that as a parse failure rather than panicking.
pub fn journal_record(line: &[u8]) -> Option<JournalRecord> {
    let value: Value = serde_json::from_slice(line).ok()?;
    let object = value.as_object()?;
    let message = object
        .get("MESSAGE")
        .and_then(json_text)
        .unwrap_or_default();
    Some(JournalRecord {
        cursor: object.get("__CURSOR").and_then(json_text),
        ts: object
            .get("__REALTIME_TIMESTAMP")
            .and_then(json_text)
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(|us| Utc.timestamp_micros(us).single())
            .unwrap_or_else(Utc::now),
        unit: object
            .get("_SYSTEMD_UNIT")
            .and_then(json_text)
            .or_else(|| object.get("_SYSTEMD_USER_UNIT").and_then(json_text))
            .filter(|s| !s.is_empty()),
        identifier: object
            .get("SYSLOG_IDENTIFIER")
            .and_then(json_text)
            .or_else(|| object.get("_COMM").and_then(json_text))
            .filter(|s| !s.is_empty()),
        priority: object
            .get("PRIORITY")
            .and_then(json_text)
            .and_then(|s| s.parse::<u8>().ok()),
        host: object
            .get("_HOSTNAME")
            .and_then(json_text)
            .filter(|s| !s.is_empty()),
        pid: object
            .get("_PID")
            .and_then(json_text)
            .and_then(|s| s.parse::<u32>().ok()),
        message,
    })
}

/// journald encodes non-UTF-8 fields as arrays of byte values.
fn json_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => {
            if items.iter().all(|item| item.is_u64()) {
                let bytes: Vec<u8> = items
                    .iter()
                    .filter_map(|item| item.as_u64().map(|n| n as u8))
                    .collect();
                Some(String::from_utf8_lossy(&bytes).into_owned())
            } else {
                Some(
                    items
                        .iter()
                        .filter_map(|item| item.as_str())
                        .collect::<String>(),
                )
            }
        }
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[derive(Debug, Default)]
struct Fields {
    template: &'static str,
    parser: &'static str,
    user: Option<String>,
    src_ip: Option<IpAddr>,
    action: Option<String>,
    outcome: Option<String>,
    service: Option<String>,
    method: Option<String>,
    path: Option<String>,
    status: Option<u16>,
}

/// Classify one journal record and copy its bounded message into a
/// [`LogEvent`]. `max_message` and `redact` come from `[logs]`.
pub fn event_from_record(
    record: &JournalRecord,
    max_message: usize,
    redact: &[String],
) -> LogEvent {
    let fields = classify(record);
    let message = sanitize_message(&record.message, max_message, redact);
    LogEvent {
        ts: record.ts,
        origin: Origin::Journal,
        source: "journal".into(),
        unit: record.unit.clone(),
        identifier: record.identifier.clone(),
        priority: record.priority,
        host: record.host.clone(),
        pid: record.pid,
        user: fields.user,
        service: fields.service,
        src_ip: fields.src_ip,
        action: fields.action,
        outcome: fields.outcome,
        method: fields.method,
        path: fields.path,
        status: fields.status,
        template: fields.template.into(),
        message,
        cursor: record.cursor.clone(),
        parser: fields.parser.into(),
        id: None,
    }
}

fn classify(record: &JournalRecord) -> Fields {
    let message = record.message.as_str();
    let lower = message.to_ascii_lowercase();
    let identifier = record.identifier.as_deref().unwrap_or("");
    let id = identifier.to_ascii_lowercase();

    if let Some(http) = parse_access_log(message) {
        return http;
    }

    // PAM messages are emitted under the calling unit's identifier.
    if lower.contains("pam_unix(") || (lower.contains("pam_") && lower.contains("authentication")) {
        return classify_pam(message, &lower);
    }

    // OpenSSH 9.8+ on Debian 13 logs through `sshd-session`, `sshd-auth`
    // and `sshd`; all three carry the same message formats.
    if id == "sshd" || id.starts_with("sshd") {
        return classify_sshd(message, &lower);
    }
    if id.contains("systemd-logind") {
        return Fields {
            template: T_LOGIND_SESSION,
            parser: "systemd-logind",
            action: Some("session".into()),
            outcome: Some(
                if lower.contains("new session") || lower.contains("opened") {
                    "opened".into()
                } else if lower.contains("logged out") || lower.contains("closed") {
                    "closed".into()
                } else {
                    "observed".into()
                },
            ),
            ..Fields::default()
        };
    }
    if id == "cron" || id == "crond" || id.contains("anacron") {
        return Fields {
            template: T_CRON,
            parser: "cron",
            action: Some("cron".into()),
            outcome: Some("observed".into()),
            user: bracket_user(message),
            ..Fields::default()
        };
    }

    // DET-24/25: security-relevant changes are recognised before the generic
    // system/kernel fallbacks so they are never hidden by a parser label.
    if security_change(&lower, identifier, record.unit.as_deref()) {
        return Fields {
            template: T_SECURITY_CHANGE,
            parser: "system",
            user: bracket_user(message),
            src_ip: extract_ip(message),
            action: Some("system.change".into()),
            outcome: Some("observed".into()),
            ..Fields::default()
        };
    }
    if account_change(&lower) {
        return Fields {
            template: T_ACCOUNT_CHANGE,
            parser: if id == "sudo" { "sudo" } else { "system" },
            user: sudo_user(message).or_else(|| bracket_user(message)),
            src_ip: extract_ip(message),
            action: Some("account.change".into()),
            outcome: Some("observed".into()),
            ..Fields::default()
        };
    }

    if id == "sudo" {
        return classify_sudo(message, &lower);
    }

    if id == "kernel" || id == "audit" || id == "auditd" {
        return Fields {
            template: T_KERNEL,
            parser: "kernel",
            src_ip: extract_ip(message),
            action: Some("kernel".into()),
            outcome: Some("observed".into()),
            ..Fields::default()
        };
    }

    Fields {
        template: T_GENERIC,
        parser: "generic",
        src_ip: extract_ip(message),
        action: Some("log".into()),
        outcome: Some("observed".into()),
        ..Fields::default()
    }
}

/// Common/combined HTTP access-log line:
/// `IP - user [date] "METHOD /path HTTP/1.1" STATUS bytes "referer" "agent"`.
fn parse_access_log(message: &str) -> Option<Fields> {
    let mut tokens = message.split_whitespace();
    let src = tokens.next()?.trim();
    let src_ip: IpAddr = src.parse().ok()?;
    let _ident = tokens.next();
    let user = match tokens.next().unwrap_or("-") {
        "-" | "" => None,
        value => clean_user(value),
    };
    let quote = message.find('"')?;
    let rest = &message[quote + 1..];
    let end = rest.find('"')?;
    let request = &rest[..end];
    let mut request_parts = request.split_whitespace();
    let method = request_parts.next()?;
    let target = request_parts.next()?;
    let version = request_parts.next().unwrap_or("");
    if method.len() < 2
        || method.len() > 10
        || !method.chars().all(|c| c.is_ascii_uppercase())
        || !version.starts_with("HTTP/")
    {
        return None;
    }
    let path = target
        .split(['?', '#'])
        .next()
        .unwrap_or(target)
        .chars()
        .take(512)
        .collect::<String>();
    if !path.starts_with('/') && path != "*" {
        return None;
    }
    let status = rest[end + 1..]
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<u16>().ok())?;
    if !(100..=599).contains(&status) {
        return None;
    }
    let outcome = match status {
        200..=399 => "success",
        401 | 403 => "denied",
        404 => "not_found",
        400..=499 => "failure",
        _ => "error",
    };
    Some(Fields {
        template: T_HTTP_ACCESS,
        parser: "http",
        user,
        src_ip: Some(src_ip),
        action: Some("http.request".into()),
        outcome: Some(outcome.into()),
        method: Some(method.chars().take(16).collect()),
        path: Some(path),
        status: Some(status),
        ..Fields::default()
    })
}

fn classify_sshd(message: &str, lower: &str) -> Fields {
    let user = ssh_user(message);
    let src_ip = extract_ip(message);
    let (template, outcome) = if lower.contains("connection closed")
        || lower.contains("connection reset")
        || lower.contains("disconnected from")
        || lower.contains("received disconnect")
        || lower.contains("banner exchange")
    {
        // Session teardown, not a new authentication attempt. Counting
        // "Connection closed by invalid user" as a failure would double every
        // pre-auth rejection.
        (T_SSH_OTHER, "observed")
    } else if lower.contains("failed password")
        || lower.contains("authentication failure")
        || lower.contains("failed publickey")
        || lower.contains("failed keyboard-interactive")
    {
        (T_SSH_FAILED, "failure")
    } else if lower.contains("invalid user") {
        (T_SSH_INVALID, "failure")
    } else if lower.contains("accepted password")
        || lower.contains("accepted publickey")
        || lower.contains("accepted keyboard-interactive")
    {
        (T_SSH_ACCEPTED, "success")
    } else {
        (T_SSH_OTHER, "observed")
    };
    Fields {
        template,
        parser: "sshd",
        user,
        src_ip,
        action: Some("ssh.auth".into()),
        outcome: Some(outcome.into()),
        ..Fields::default()
    }
}

fn classify_pam(message: &str, lower: &str) -> Fields {
    let service = pam_service(message);
    let failure = lower.contains("authentication failure")
        || lower.contains("conversation failed")
        || lower.contains("auth could not identify password")
        || lower.contains("authentication could not")
        || lower.contains("failed");
    let user = field_value(message, "user=")
        .and_then(clean_user)
        .or_else(|| bracket_user(message))
        .or_else(|| field_value(message, "ruser=").and_then(clean_user));
    Fields {
        template: if failure { T_PAM_FAILURE } else { T_GENERIC },
        parser: "pam",
        user,
        src_ip: field_value(message, "rhost=")
            .and_then(parse_ip_token)
            .or_else(|| extract_ip(message)),
        action: Some("pam.auth".into()),
        outcome: Some(if failure { "failure" } else { "observed" }.into()),
        service,
        ..Fields::default()
    }
}

fn classify_sudo(message: &str, lower: &str) -> Fields {
    let user = sudo_user(message);
    let src_ip = extract_ip(message);
    if lower.contains("not in sudoers")
        || lower.contains("not allowed to")
        || lower.contains("command not allowed")
        || lower.contains("incorrect password")
        || lower.contains("authentication failure")
        || lower.contains("conversation failed")
        || lower.contains("auth could not identify password")
    {
        let denied = !(lower.contains("incorrect password")
            || lower.contains("authentication failure")
            || lower.contains("conversation failed")
            || lower.contains("auth could not identify password"));
        return Fields {
            template: if denied {
                T_SUDO_DENIED
            } else {
                T_SUDO_AUTH_FAILURE
            },
            parser: "sudo",
            user,
            src_ip,
            action: Some("sudo".into()),
            outcome: Some(if denied { "denied" } else { "failure" }.into()),
            ..Fields::default()
        };
    }
    Fields {
        template: T_SUDO_COMMAND,
        parser: "sudo",
        user,
        src_ip,
        action: Some("sudo".into()),
        outcome: Some("allowed".into()),
        ..Fields::default()
    }
}

fn security_change(lower: &str, identifier: &str, unit: Option<&str>) -> bool {
    let id = identifier.to_ascii_lowercase();
    let about_rustips = lower.contains("rustips")
        && (unit == Some("rustips.service")
            || id == "systemd"
            || lower.contains("stopped rustips.service"));
    if about_rustips
        && (lower.contains("stopped")
            || lower.contains("stopping")
            || lower.contains("failed")
            || lower.contains("deactivated"))
    {
        return true;
    }
    if (id == "audit" || id == "auditd" || id == "systemd")
        && lower.contains("audit")
        && (lower.contains("disabled")
            || lower.contains("stopped")
            || lower.contains("shutdown")
            || lower.contains("failure"))
    {
        return true;
    }
    if id == "systemd-journald"
        && (lower.contains("stopped") || lower.contains("failed") || lower.contains("shutting"))
    {
        return true;
    }
    if (lower.contains("nftables") || lower.contains("nf_tables"))
        && (lower.contains("ruleset")
            || lower.contains("flush")
            || lower.contains("apply")
            || lower.contains("change")
            || lower.contains("delete"))
    {
        return true;
    }
    false
}

fn account_change(lower: &str) -> bool {
    [
        "useradd",
        "usermod",
        "userdel",
        "adduser",
        "deluser",
        "groupadd",
        "groupmod",
        "groupdel",
        "visudo",
        "/etc/sudoers",
        "authorized_keys",
        "chpasswd",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn ssh_user(message: &str) -> Option<String> {
    // `Invalid user` is capitalised in OpenSSH's pre-auth line; search a
    // lowercased copy so every marker matches, then slice the original.
    let lower = message.to_ascii_lowercase();
    for marker in [
        "for invalid user ",
        "invalid user ",
        "for user ",
        "authenticating user ",
        "for ",
    ] {
        if let Some(index) = lower.find(marker) {
            let rest = &message[index + marker.len()..];
            if let Some(token) = rest.split_whitespace().next() {
                if token != "invalid" && token != "user" {
                    return clean_user(token);
                }
            }
        }
    }
    None
}

fn sudo_user(message: &str) -> Option<String> {
    let rest = message
        .split_once("sudo:")
        .map(|(_, r)| r)
        .unwrap_or(message);
    let rest = rest.trim_start();
    let end = rest.find(" :").unwrap_or(rest.len());
    let token = rest[..end]
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(|c: char| c == ':' || c == ',' || c == ';');
    clean_user(token)
}

fn pam_service(message: &str) -> Option<String> {
    let start = message.find("pam_unix(")? + "pam_unix(".len();
    let rest = &message[start..];
    let end = rest.find(':')?;
    let service = rest[..end].trim();
    if service.is_empty() {
        None
    } else {
        Some(service.to_string())
    }
}

fn bracket_user(message: &str) -> Option<String> {
    let start = message.rfind('[')? + 1;
    let end = message[start..].find(']')? + start;
    clean_user(&message[start..end])
}

fn field_value<'a>(message: &'a str, key: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(relative) = message[from..].find(key) {
        let index = from + relative;
        // `user=` must not match inside `ruser=`. A field starts at the
        // beginning of the message or after whitespace.
        let boundary = index == 0 || message.as_bytes()[index - 1].is_ascii_whitespace();
        if boundary {
            let start = index + key.len();
            let rest = &message[start..];
            let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            return Some(&rest[..end]);
        }
        from = index + key.len();
    }
    None
}

fn clean_user(raw: &str) -> Option<String> {
    let user: String = raw.chars().filter(|c| !c.is_control()).take(128).collect();
    let user = user.trim_matches(|c: char| {
        c == '"' || c == '\'' || c == ',' || c == ';' || c == ':' || c == '[' || c == ']'
    });
    if user.is_empty() || user == "invalid" || user == "user" {
        None
    } else {
        Some(user.to_string())
    }
}

fn extract_ip(message: &str) -> Option<IpAddr> {
    for marker in [
        " from ",
        "rhost=",
        " by authenticating user ",
        " client ",
        "addr=",
    ] {
        if let Some((_, rest)) = message.split_once(marker) {
            // `by authenticating user <name> <ip>` carries the IP in the
            // token after the user name.
            let tokens: Vec<&str> = rest.split_whitespace().take(3).collect();
            for token in tokens {
                if let Some(ip) = parse_ip_token(token) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

fn parse_ip_token(token: &str) -> Option<IpAddr> {
    let token = token.trim_matches(|c: char| {
        c == ','
            || c == ';'
            || c == '"'
            || c == '\''
            || c == '('
            || c == ')'
            || c == '['
            || c == ']'
    });
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Some(ip);
    }
    // `1.2.3.4:2222` (never split an IPv6 literal before trying it whole).
    if let Some((host, _port)) = token.rsplit_once(':') {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

/// Neutralise control characters, apply literal redactions and cap by bytes.
pub fn sanitize_message(text: &str, max: usize, redact: &[String]) -> String {
    let mut out = String::with_capacity(text.len().min(max));
    for c in text.chars() {
        if out.len() >= max {
            break;
        }
        match c {
            '\0' => out.push_str("\\0"),
            '\r' | '\n' | '\t' => out.push(' '),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    for pattern in redact {
        if !pattern.is_empty() {
            out = out.replace(pattern, "[redacted]");
        }
    }
    if out.len() > max {
        truncate_utf8(&mut out, max);
    }
    out
}

fn truncate_utf8(text: &mut String, max: usize) {
    if text.len() <= max {
        return;
    }
    let mut cut = max;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(message: &str, identifier: &str) -> JournalRecord {
        JournalRecord {
            cursor: Some("s=1".into()),
            ts: Utc::now(),
            unit: Some("ssh.service".into()),
            identifier: Some(identifier.into()),
            priority: Some(6),
            host: Some("host".into()),
            pid: Some(10),
            message: message.into(),
        }
    }

    #[test]
    fn parses_journal_json_and_message_array() {
        let line = br#"{"__CURSOR":"s=abc","__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"6","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","_HOSTNAME":"h","_PID":"42","MESSAGE":["h","i"]}"#;
        let rec = journal_record(line).unwrap();
        assert_eq!(rec.cursor.as_deref(), Some("s=abc"));
        assert_eq!(rec.message, "hi");
        assert_eq!(rec.pid, Some(42));
        assert_eq!(rec.ts.timestamp(), 1_700_000_000);
    }

    #[test]
    fn http_access_log_is_parsed() {
        let rec = record(
            "203.0.113.5 - bob [21/Nov/2026:00:00:00 +0000] \"GET /admin?x=1 HTTP/1.1\" 404 123 \"-\" \"curl/8\"",
            "nginx",
        );
        let event = event_from_record(&rec, 1024, &[]);
        assert_eq!(event.template, T_HTTP_ACCESS);
        assert_eq!(event.parser, "http");
        assert_eq!(event.src_ip, Some("203.0.113.5".parse().unwrap()));
        assert_eq!(event.user.as_deref(), Some("bob"));
        assert_eq!(event.method.as_deref(), Some("GET"));
        assert_eq!(event.path.as_deref(), Some("/admin"));
        assert_eq!(event.status, Some(404));
    }

    #[test]
    fn ssh_failed_password_extracts_source_and_user() {
        let rec = record(
            "Failed password for invalid user bob from 203.0.113.7 port 5555 ssh2",
            "sshd",
        );
        let event = event_from_record(&rec, 1024, &[]);
        assert_eq!(event.template, T_SSH_FAILED);
        assert_eq!(event.src_ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(event.user.as_deref(), Some("bob"));
        assert_eq!(event.action.as_deref(), Some("ssh.auth"));
        assert_eq!(event.outcome.as_deref(), Some("failure"));
    }

    #[test]
    fn ssh_accept_is_recognised() {
        let rec = record(
            "Accepted publickey for deploy from 198.51.100.4 port 40000 ssh2",
            "sshd",
        );
        let event = event_from_record(&rec, 1024, &[]);
        assert_eq!(event.template, T_SSH_ACCEPTED);
        assert_eq!(event.src_ip, Some("198.51.100.4".parse().unwrap()));
        assert_eq!(event.user.as_deref(), Some("deploy"));
    }

    #[test]
    fn newer_sshd_session_identifier_is_parsed() {
        // Debian 13 / OpenSSH 9.8 logs pre-auth lines as `sshd-session`.
        let rec = record(
            "Invalid user bob from 203.0.113.10 port 4000",
            "sshd-session",
        );
        let event = event_from_record(&rec, 1024, &[]);
        assert_eq!(event.template, T_SSH_INVALID);
        assert_eq!(event.parser, "sshd");
        assert_eq!(event.src_ip, Some("203.0.113.10".parse().unwrap()));
        assert_eq!(event.user.as_deref(), Some("bob"));
    }

    #[test]
    fn ssh_connection_closed_is_not_a_failure() {
        let rec = record(
            "Connection closed by invalid user bob 203.0.113.10 port 4000 [preauth]",
            "sshd-session",
        );
        let event = event_from_record(&rec, 1024, &[]);
        assert_eq!(event.template, T_SSH_OTHER);
        assert_eq!(event.outcome.as_deref(), Some("observed"));
    }

    #[test]
    fn pam_failure_is_parsed_before_the_sshd_parser() {
        let rec = record(
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.8  user=root",
            "sshd",
        );
        let event = event_from_record(&rec, 1024, &[]);
        assert_eq!(event.template, T_PAM_FAILURE);
        assert_eq!(event.parser, "pam");
        assert_eq!(event.user.as_deref(), Some("root"));
        assert_eq!(event.src_ip, Some("203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn sudo_denial_and_account_change() {
        let rec = record(
            "bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id",
            "sudo",
        );
        assert_eq!(event_from_record(&rec, 1024, &[]).template, T_SUDO_DENIED);
        let rec = record(
            "bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/useradd eve",
            "sudo",
        );
        assert_eq!(
            event_from_record(&rec, 1024, &[]).template,
            T_ACCOUNT_CHANGE
        );
    }

    #[test]
    fn rustips_stop_is_a_security_change_but_own_logs_are_not_special() {
        let mut rec = record(
            "Stopped rustips.service - RustIPS intrusion prevention system.",
            "systemd",
        );
        rec.unit = Some("rustips.service".into());
        assert_eq!(
            event_from_record(&rec, 1024, &[]).template,
            T_SECURITY_CHANGE
        );
        let rec = record("detection DET-01 1.2.3.4", "rustips");
        assert_eq!(event_from_record(&rec, 1024, &[]).template, T_GENERIC);
    }

    #[test]
    fn messages_are_bounded_and_redacted() {
        let text = format!("password=hunter2 {}", "x".repeat(200));
        let out = sanitize_message(&text, 64, &["password=hunter2".to_string()]);
        assert!(out.len() <= 64);
        assert!(out.starts_with("[redacted]"));
        assert_eq!(sanitize_message("a\0b\nc", 64, &[]), "a\\0b c");
    }

    #[test]
    fn ipv4_with_port_is_accepted_but_ipv6_is_not_split() {
        assert_eq!(
            parse_ip_token("198.51.100.9:2222"),
            Some("198.51.100.9".parse().unwrap())
        );
        assert_eq!(
            parse_ip_token("[2001:db8::1]"),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn malformed_and_non_object_json_is_ignored() {
        assert!(journal_record(b"not json").is_none());
        assert!(journal_record(b"[1,2,3]").is_none());
        assert!(journal_record(b"\xff\xfe").is_none());
        // A JSON object without any recognised fields is still a valid record.
        let rec = journal_record(br#"{"MESSAGE":"ok"}"#).unwrap();
        assert_eq!(rec.message, "ok");
    }

    #[test]
    fn invalid_utf8_message_bytes_are_replaced() {
        let line = br#"{"MESSAGE":[255,65,254]}"#;
        let rec = journal_record(line).unwrap();
        assert!(rec.message.contains('\u{fffd}'));
        assert!(rec.message.contains('A'));
    }

    #[test]
    fn oversized_and_multibyte_messages_stay_on_char_boundaries() {
        let out = sanitize_message(&"é".repeat(1000), 33, &[]);
        assert!(out.len() <= 33);
        assert!(out.is_char_boundary(out.len()));
        assert!(out.chars().all(|c| c == 'é'));
        // A truncation point in the middle of a multi-byte char is pulled back.
        let out = sanitize_message(&"aé".repeat(100), 4, &[]);
        assert!(out.len() <= 4);
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn control_characters_are_neutralised_not_interpreted() {
        let out = sanitize_message("a\u{1b}[31mred\r\nb\0c\ttab", 128, &[]);
        assert!(!out.chars().any(|c| c.is_control()));
        assert!(out.contains('['));
        assert!(out.contains("\\0"));
        // Markup is stored verbatim and escaped by the renderer, not here.
        let out = sanitize_message("<script>alert(1)</script>", 128, &[]);
        assert_eq!(out, "<script>alert(1)</script>");
    }
}
