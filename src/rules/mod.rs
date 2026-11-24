//! Disposition rules (FR-120…FR-139).
//!
//! Rules are data: they are stored as JSON in SQLite, edited through the UI or
//! imported from a document, and compiled into a validated in-memory set before
//! use. Evaluation is **accumulating**, not first-match: every enabled rule that
//! matches is collected, then the actions combine by severity — `allow` wins,
//! then the longest block (permanent absorbs everything), then `alert`, then
//! `tag`. Ties break on severity, priority and finally the lowest rule ID
//! (FR-121, FR-123).
//!
//! The engine itself never touches the database, the clock or nftables. The
//! caller supplies a [`History`] snapshot and decides whether the resulting
//! action is enforced, observed or dry-run.

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};

use crate::config::BlockDuration;
use crate::model::{Detection, Detector, Proto};
use crate::net::Cidr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Result<Severity, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "warning" | "warn" => Ok(Severity::Warning),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(format!(
                "severity must be info, warning or critical (got {other:?})"
            )),
        }
    }
}

/// One disposition rule. `id` 0 means "assign on save".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub when: RuleMatch,
    pub action: RuleAction,
}

fn default_true() -> bool {
    true
}

fn default_priority() -> i32 {
    100
}

impl Rule {
    pub fn action_label(&self) -> String {
        match &self.action {
            RuleAction::Alert => "alert".into(),
            RuleAction::Tag { tag } => format!("tag {tag}"),
            RuleAction::Allow => "allow".into(),
            RuleAction::BlockTemp { duration } => format!("block {duration}"),
            RuleAction::BlockPermanent => "block permanent".into(),
            RuleAction::Escalate { ladder } if ladder.is_empty() => "escalate (global)".into(),
            RuleAction::Escalate { ladder } => format!("escalate {}", ladder.join(" -> ")),
        }
    }

    pub fn match_label(&self) -> String {
        let mut parts = Vec::new();
        if !self.when.detectors.is_empty() {
            parts.push(self.when.detectors.join(","));
        }
        if !self.when.sources.is_empty() {
            parts.push(format!("src {}", self.when.sources.join(",")));
        }
        if !self.when.not_sources.is_empty() {
            parts.push(format!("not {}", self.when.not_sources.join(",")));
        }
        if !self.when.ports.is_empty() {
            parts.push(format!("port {}", self.when.ports.join(",")));
        }
        if !self.when.protocols.is_empty() {
            parts.push(self.when.protocols.join(","));
        }
        if let Some(min) = self.when.min_count {
            parts.push(format!("count>={min}"));
        }
        if let Some(min) = self.when.min_strikes {
            parts.push(format!("strikes>={min}"));
        }
        if self.when.only_if_blocked {
            parts.push("already blocked".into());
        }
        if let Some(window) = &self.when.last_seen_within {
            parts.push(format!("last strike within {window}"));
        }
        if !self.when.tags.is_empty() {
            parts.push(format!("tags {}", self.when.tags.join(",")));
        }
        if !self.when.countries.is_empty() {
            parts.push(format!("country {}", self.when.countries.join(",")));
        }
        if !self.when.not_countries.is_empty() {
            parts.push(format!("not country {}", self.when.not_countries.join(",")));
        }
        if !self.when.asns.is_empty() {
            parts.push(format!(
                "asn {}",
                self.when
                    .asns
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if !self.when.not_asns.is_empty() {
            parts.push(format!(
                "not asn {}",
                self.when
                    .not_asns
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if !self.when.days.is_empty() {
            parts.push(format!(
                "days {}",
                self.when
                    .days
                    .iter()
                    .map(|day| day.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if let (Some(start), Some(end)) = (&self.when.start, &self.when.end) {
            parts.push(format!("{start}-{end} UTC"));
        }
        if parts.is_empty() {
            "any detection".into()
        } else {
            parts.join(" · ")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct RuleMatch {
    /// Detector IDs, e.g. `["DET-01", "DET-16"]`. Empty = any.
    pub detectors: Vec<String>,
    /// CIDRs; a source must match at least one. Empty = any.
    pub sources: Vec<String>,
    /// CIDRs that never match.
    pub not_sources: Vec<String>,
    /// Destination ports or ranges, e.g. `["22", "8000-8100"]`. Empty = any.
    pub ports: Vec<String>,
    /// `tcp`, `udp`, `icmp`, `icmp6`, `log`. Empty = any.
    pub protocols: Vec<String>,
    /// Minimum detection count in its window.
    pub min_count: Option<u64>,
    /// Minimum existing strike count for the source.
    pub min_strikes: Option<u32>,
    /// Only match when the source already has an active block.
    pub only_if_blocked: bool,
    /// Match when the source's last strike was within this duration.
    pub last_seen_within: Option<String>,
    /// Free-form tags carried in detection metadata; all must be present.
    pub tags: Vec<String>,
    /// ISO country codes from the disposition-only geo database.
    pub countries: Vec<String>,
    pub not_countries: Vec<String>,
    /// Autonomous system numbers from the disposition-only ASN database.
    pub asns: Vec<u32>,
    pub not_asns: Vec<u32>,
    /// UTC weekdays (0 = Sunday … 6 = Saturday). Empty = any day.
    pub days: Vec<u8>,
    /// Optional UTC time window, `"HH:MM"`; both sides required.
    pub start: Option<String>,
    pub end: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleAction {
    Alert,
    Tag {
        tag: String,
    },
    /// Exempt the source from blocking when this rule wins.
    Allow,
    BlockTemp {
        duration: String,
    },
    BlockPermanent,
    /// Use the configured ladder; `ladder` overrides it when non-empty.
    Escalate {
        #[serde(default)]
        ladder: Vec<String>,
    },
}

/// Editable form values, kept as strings so invalid input can be shown back to
/// the operator with a precise error.
#[derive(Debug, Clone)]
pub struct RuleForm {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: String,
    pub severity: String,
    pub dry_run: bool,
    pub detectors: String,
    pub sources: String,
    pub not_sources: String,
    pub ports: String,
    pub protocols: String,
    pub min_count: String,
    pub min_strikes: String,
    pub only_if_blocked: bool,
    pub last_seen_within: String,
    pub tags: String,
    pub countries: String,
    pub not_countries: String,
    pub asns: String,
    pub not_asns: String,
    pub days: String,
    pub start: String,
    pub end: String,
    pub action: String,
    pub duration: String,
    pub tag: String,
    pub ladder: String,
}

impl Default for RuleForm {
    fn default() -> Self {
        RuleForm {
            id: 0,
            name: String::new(),
            description: String::new(),
            enabled: true,
            priority: "100".into(),
            severity: "warning".into(),
            dry_run: false,
            detectors: String::new(),
            sources: String::new(),
            not_sources: String::new(),
            ports: String::new(),
            protocols: String::new(),
            min_count: String::new(),
            min_strikes: String::new(),
            only_if_blocked: false,
            last_seen_within: String::new(),
            tags: String::new(),
            countries: String::new(),
            not_countries: String::new(),
            asns: String::new(),
            not_asns: String::new(),
            days: String::new(),
            start: String::new(),
            end: String::new(),
            action: "alert".into(),
            duration: "1h".into(),
            tag: String::new(),
            ladder: String::new(),
        }
    }
}

impl RuleForm {
    pub fn from_rule(rule: &Rule) -> RuleForm {
        let (action, duration, tag, ladder) = match &rule.action {
            RuleAction::Alert => (
                "alert".to_string(),
                String::new(),
                String::new(),
                String::new(),
            ),
            RuleAction::Tag { tag } => {
                ("tag".to_string(), String::new(), tag.clone(), String::new())
            }
            RuleAction::Allow => (
                "allow".to_string(),
                String::new(),
                String::new(),
                String::new(),
            ),
            RuleAction::BlockTemp { duration } => (
                "block_temp".to_string(),
                duration.clone(),
                String::new(),
                String::new(),
            ),
            RuleAction::BlockPermanent => (
                "block_permanent".to_string(),
                String::new(),
                String::new(),
                String::new(),
            ),
            RuleAction::Escalate { ladder } => (
                "escalate".to_string(),
                String::new(),
                String::new(),
                ladder.join(", "),
            ),
        };
        RuleForm {
            id: rule.id,
            name: rule.name.clone(),
            description: rule.description.clone(),
            enabled: rule.enabled,
            priority: rule.priority.to_string(),
            severity: rule.severity.as_str().into(),
            dry_run: rule.dry_run,
            detectors: rule.when.detectors.join(", "),
            sources: rule.when.sources.join(", "),
            not_sources: rule.when.not_sources.join(", "),
            ports: rule.when.ports.join(", "),
            protocols: rule.when.protocols.join(", "),
            min_count: rule
                .when
                .min_count
                .map(|v| v.to_string())
                .unwrap_or_default(),
            min_strikes: rule
                .when
                .min_strikes
                .map(|v| v.to_string())
                .unwrap_or_default(),
            only_if_blocked: rule.when.only_if_blocked,
            last_seen_within: rule.when.last_seen_within.clone().unwrap_or_default(),
            tags: rule.when.tags.join(", "),
            countries: rule.when.countries.join(", "),
            not_countries: rule.when.not_countries.join(", "),
            asns: rule
                .when
                .asns
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            not_asns: rule
                .when
                .not_asns
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            days: rule
                .when
                .days
                .iter()
                .map(|day| day.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            start: rule.when.start.clone().unwrap_or_default(),
            end: rule.when.end.clone().unwrap_or_default(),
            action,
            duration,
            tag,
            ladder,
        }
    }

    pub fn to_rule(&self) -> Result<Rule, String> {
        let id: u32 = if self.id == 0 { 0 } else { self.id };
        let priority: i32 = self
            .priority
            .trim()
            .parse()
            .map_err(|_| format!("priority {:?} is not a number", self.priority))?;
        let severity = Severity::parse(&self.severity)?;
        let min_count = parse_optional(&self.min_count, "min_count")?;
        let min_strikes = parse_optional(&self.min_strikes, "min_strikes")?;
        let days = split_list(&self.days)
            .into_iter()
            .map(|day| {
                day.parse::<u8>()
                    .map_err(|_| format!("day {day:?} is not 0-6"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let action = match self.action.as_str() {
            "alert" => RuleAction::Alert,
            "tag" => RuleAction::Tag {
                tag: self.tag.trim().to_string(),
            },
            "allow" => RuleAction::Allow,
            "block_temp" => RuleAction::BlockTemp {
                duration: self.duration.trim().to_string(),
            },
            "block_permanent" => RuleAction::BlockPermanent,
            "escalate" => RuleAction::Escalate {
                ladder: split_list(&self.ladder),
            },
            other => return Err(format!("unknown action {other:?}")),
        };
        Ok(Rule {
            id,
            name: self.name.trim().to_string(),
            description: self.description.trim().to_string(),
            enabled: self.enabled,
            priority,
            severity,
            dry_run: self.dry_run,
            when: RuleMatch {
                detectors: split_list(&self.detectors),
                sources: split_list(&self.sources),
                not_sources: split_list(&self.not_sources),
                ports: split_list(&self.ports),
                protocols: split_list(&self.protocols),
                min_count,
                min_strikes,
                only_if_blocked: self.only_if_blocked,
                last_seen_within: Some(self.last_seen_within.trim().to_string())
                    .filter(|value| !value.is_empty()),
                tags: split_list(&self.tags),
                countries: split_list(&self.countries)
                    .into_iter()
                    .map(|code| code.to_ascii_uppercase())
                    .collect(),
                not_countries: split_list(&self.not_countries)
                    .into_iter()
                    .map(|code| code.to_ascii_uppercase())
                    .collect(),
                asns: parse_asns(&self.asns)?,
                not_asns: parse_asns(&self.not_asns)?,
                days,
                start: Some(self.start.trim().to_string()).filter(|value| !value.is_empty()),
                end: Some(self.end.trim().to_string()).filter(|value| !value.is_empty()),
            },
            action,
        })
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_countries(values: &[String], field: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for value in values {
        let code = value.trim().to_ascii_uppercase();
        if code.is_empty() {
            continue;
        }
        if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(format!(
                "{field}: country code {value:?} must be two ASCII letters"
            ));
        }
        if !out.contains(&code) {
            out.push(code);
        }
    }
    Ok(out)
}

fn parse_asns(value: &str) -> Result<Vec<u32>, String> {
    let mut out = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let asn: u32 = part
            .strip_prefix("AS")
            .unwrap_or(part)
            .parse()
            .map_err(|_| format!("ASN {part:?} is not a number"))?;
        if asn == 0 {
            return Err("ASN must be greater than zero".into());
        }
        if !out.contains(&asn) {
            out.push(asn);
        }
    }
    Ok(out)
}

fn parse_optional<T: std::str::FromStr>(value: &str, field: &str) -> Result<Option<T>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| format!("{field} {value:?} is not a number"))
}

/// A stored rule revision for the UI history (FR-120).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRevision {
    pub id: i64,
    pub rule_id: u32,
    pub revision: u32,
    pub changed_at: DateTime<Utc>,
    pub changed_by: String,
    /// `create`, `update`, `delete` or `import`.
    pub action: String,
    pub note: String,
    pub document: Rule,
}

/// A source's history at evaluation time.
#[derive(Debug, Clone, Default)]
pub struct History {
    pub strikes: u32,
    pub blocked: bool,
    pub last_strike_seen: Option<DateTime<Utc>>,
}

/// The combined result of every matching rule.
#[derive(Debug, Clone)]
pub struct Decision {
    /// All matching rule IDs, in evaluation order (priority then ID).
    pub matched: Vec<u32>,
    /// The rule whose action won.
    pub rule_id: Option<u32>,
    /// The winning rule's name, for the audit log.
    pub rule_name: Option<String>,
    /// The winning rule's severity (info when nothing matched).
    pub severity: Severity,
    pub action: DecisionAction,
    /// Tags contributed by matching `tag` rules, even when a block wins.
    pub tags: Vec<String>,
    /// When the winning block rule is marked dry-run.
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionAction {
    Allow,
    Alert,
    Tag(String),
    Block {
        duration: BlockDuration,
        escalated: bool,
    },
}

impl Decision {
    pub fn matched_label(&self) -> String {
        if self.matched.is_empty() {
            "no match".into()
        } else {
            self.matched
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        }
    }
}

#[derive(Debug)]
struct CompiledRule {
    rule: Rule,
    detectors: Vec<Detector>,
    sources: Vec<Cidr>,
    not_sources: Vec<Cidr>,
    ports: Vec<(u16, u16)>,
    protocols: Vec<Proto>,
    countries: Vec<String>,
    not_countries: Vec<String>,
    asns: Vec<u32>,
    not_asns: Vec<u32>,
    last_seen_within: Option<chrono::Duration>,
    start_min: Option<u16>,
    end_min: Option<u16>,
    action: CompiledAction,
}

#[derive(Debug)]
enum CompiledAction {
    Alert,
    Tag(String),
    Allow,
    Block(BlockDuration),
    Escalate(Vec<BlockDuration>),
}

/// A validated, ordered rule set ready for evaluation.
#[derive(Debug)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
}

/// Shared rule set. The scheduler swaps it after a validated reload.
pub type RulesHandle = std::sync::Arc<std::sync::RwLock<RuleSet>>;

#[derive(Debug, Clone)]
pub struct RuleError {
    pub rule_id: u32,
    pub rule_name: String,
    pub message: String,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.rule_id == 0 {
            write!(f, "rule {:?}: {}", self.rule_name, self.message)
        } else {
            write!(
                f,
                "rule {} ({:?}): {}",
                self.rule_id, self.rule_name, self.message
            )
        }
    }
}

impl RuleSet {
    /// Validate and compile every rule. `global_ladder` is the configured
    /// ladder used by `escalate` rules without their own override.
    pub fn compile(
        rules: Vec<Rule>,
        global_ladder: &[BlockDuration],
    ) -> Result<RuleSet, Vec<RuleError>> {
        let mut errors = Vec::new();
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            let id = rule.id;
            let name = rule.name.clone();
            match compile_rule(rule, global_ladder) {
                Ok(rule) => compiled.push(rule),
                Err(message) => errors.push(RuleError {
                    rule_id: id,
                    rule_name: name,
                    message,
                }),
            }
        }
        if errors.is_empty() && compiled.is_empty() {
            errors.push(RuleError {
                rule_id: 0,
                rule_name: "rule set".into(),
                message: "at least one rule is required".into(),
            });
        }
        if errors.is_empty() {
            let mut seen = std::collections::HashSet::new();
            for rule in &compiled {
                if rule.rule.id != 0 && !seen.insert(rule.rule.id) {
                    errors.push(RuleError {
                        rule_id: rule.rule.id,
                        rule_name: rule.rule.name.clone(),
                        message: "duplicate rule id".into(),
                    });
                }
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        compiled.sort_by(|a, b| {
            b.rule
                .priority
                .cmp(&a.rule.priority)
                .then(a.rule.id.cmp(&b.rule.id))
        });
        Ok(RuleSet { rules: compiled })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate every rule and combine the actions (FR-121/123).
    pub fn evaluate(
        &self,
        det: &Detection,
        history: &History,
        geo: &crate::geo::GeoInfo,
    ) -> Decision {
        let mut matched = Vec::new();
        // id, duration, escalated, dry_run, severity
        let mut block: Option<(u32, BlockDuration, bool, bool, Severity)> = None;
        let mut tags = Vec::new();
        let mut tag_rule = None;
        let mut allow_rule = None;
        let mut alert = false;

        for compiled in &self.rules {
            if !compiled.rule.enabled || !compiled.matches(det, history, geo) {
                continue;
            }
            let id = compiled.rule.id;
            matched.push(id);
            match &compiled.action {
                CompiledAction::Allow => {
                    allow_rule.get_or_insert(id);
                }
                CompiledAction::Alert => alert = true,
                CompiledAction::Tag(tag) => {
                    tag_rule.get_or_insert(id);
                    if !tags.contains(tag) {
                        tags.push(tag.clone());
                    }
                }
                CompiledAction::Block(duration) => {
                    consider_block(&mut block, compiled, id, *duration, false);
                }
                CompiledAction::Escalate(ladder) => {
                    let strike = history.strikes.saturating_add(1);
                    let duration = ladder_step(ladder, strike);
                    consider_block(&mut block, compiled, id, duration, true);
                }
            }
        }

        if let Some(id) = allow_rule {
            return Decision {
                matched,
                rule_id: Some(id),
                rule_name: self.name_of(id),
                severity: self.severity_of(id),
                action: DecisionAction::Allow,
                tags,
                dry_run: false,
            };
        }
        if let Some((id, duration, escalated, dry_run, severity)) = block {
            return Decision {
                matched,
                rule_id: Some(id),
                rule_name: self.name_of(id),
                severity,
                action: DecisionAction::Block {
                    duration,
                    escalated,
                },
                tags,
                dry_run,
            };
        }
        if !alert {
            if let Some(tag) = tags.first() {
                let rule_id = tag_rule.unwrap_or(0);
                return Decision {
                    matched,
                    rule_id: Some(rule_id),
                    rule_name: self.name_of(rule_id),
                    severity: self.severity_of(rule_id),
                    action: DecisionAction::Tag(tag.clone()),
                    tags,
                    dry_run: false,
                };
            }
        }
        let rule_id = self.winning_alert_rule(&matched);
        Decision {
            matched,
            rule_id,
            rule_name: rule_id.and_then(|id| self.name_of(id)),
            severity: rule_id
                .map(|id| self.severity_of(id))
                .unwrap_or(Severity::Info),
            action: DecisionAction::Alert,
            tags,
            dry_run: false,
        }
    }

    fn severity_of(&self, id: u32) -> Severity {
        self.rules
            .iter()
            .find(|rule| rule.rule.id == id)
            .map(|rule| rule.rule.severity)
            .unwrap_or(Severity::Info)
    }

    fn name_of(&self, id: u32) -> Option<String> {
        self.rules
            .iter()
            .find(|rule| rule.rule.id == id)
            .map(|rule| rule.rule.name.clone())
    }

    fn winning_alert_rule(&self, matched: &[u32]) -> Option<u32> {
        self.rules
            .iter()
            .find(|rule| {
                matched.contains(&rule.rule.id) && matches!(rule.action, CompiledAction::Alert)
            })
            .map(|rule| rule.rule.id)
            .or_else(|| matched.first().copied())
    }

    /// The shipped default set: current 0.3.0 behaviour expressed as rules.
    pub fn defaults(global_ladder: &[BlockDuration]) -> RuleSet {
        match RuleSet::compile(default_rule_documents(), global_ladder) {
            Ok(set) => set,
            Err(errors) => {
                tracing::error!("shipped default rules are invalid: {:?}", errors);
                RuleSet { rules: Vec::new() }
            }
        }
    }
}

/// The default rules as persistent documents (FR-128).
pub fn default_rule_documents() -> Vec<Rule> {
    let packet: Vec<String> = Detector::ALL
        .iter()
        .filter(|det| !det.is_log() && !det.is_alert_only() && **det != Detector::Honeypot)
        .map(|det| det.as_str().to_string())
        .collect();
    let log_block: Vec<String> = Detector::ALL
        .iter()
        .filter(|det| det.is_log() && !det.is_alert_only())
        .map(|det| det.as_str().to_string())
        .collect();
    let log_alert: Vec<String> = Detector::ALL
        .iter()
        .filter(|det| det.is_log() && det.is_alert_only() && **det != Detector::FirewallDrop)
        .map(|det| det.as_str().to_string())
        .collect();
    let mut rules = vec![
        Rule {
            id: 1,
            name: "Log authentication failures".into(),
            description: "DET-16/21/23 escalate through the configured ladder.".into(),
            enabled: true,
            priority: 200,
            severity: Severity::Critical,
            dry_run: false,
            when: RuleMatch {
                detectors: log_block,
                ..RuleMatch::default()
            },
            action: RuleAction::Escalate { ladder: Vec::new() },
        },
        Rule {
            id: 2,
            name: "Log alert-only detections".into(),
            description: "DET-17 is visible but never auto-blocks.".into(),
            enabled: true,
            priority: 200,
            severity: Severity::Warning,
            dry_run: false,
            when: RuleMatch {
                detectors: log_alert,
                ..RuleMatch::default()
            },
            action: RuleAction::Alert,
        },
        Rule {
            id: 3,
            name: "Packet detections escalate".into(),
            description: "DET-01…15 escalate through the configured ladder.".into(),
            enabled: true,
            priority: 100,
            severity: Severity::Warning,
            dry_run: false,
            when: RuleMatch {
                detectors: packet,
                ..RuleMatch::default()
            },
            action: RuleAction::Escalate { ladder: Vec::new() },
        },
        Rule {
            id: 4,
            name: "Slow scan alert".into(),
            description: "DET-20 long-window low-rate port scan; alert only by default.".into(),
            enabled: true,
            priority: 150,
            severity: Severity::Warning,
            dry_run: false,
            when: RuleMatch {
                detectors: vec!["DET-20".into()],
                ..RuleMatch::default()
            },
            action: RuleAction::Alert,
        },
        Rule {
            id: 5,
            name: "Default alert".into(),
            description: "Catch-all for detectors without a specific rule; alert only.".into(),
            enabled: true,
            priority: 0,
            severity: Severity::Info,
            dry_run: false,
            when: RuleMatch::default(),
            action: RuleAction::Alert,
        },
        Rule {
            id: 6,
            name: "Honeypot block after 3 contacts".into(),
            description:
                "DET-26: after 3 contacts to a honeypot port in the detection window, block the source through the ladder."
                    .into(),
            enabled: true,
            priority: 250,
            severity: Severity::Critical,
            dry_run: false,
            when: RuleMatch {
                detectors: vec!["DET-26".into()],
                min_count: Some(3),
                ..RuleMatch::default()
            },
            action: RuleAction::Escalate { ladder: Vec::new() },
        },
        Rule {
            id: 7,
            name: "Firewall default-drop alert".into(),
            description:
                "DET-27: the optional service firewall dropped or rejected an inbound packet. Alert only; the packet is already denied."
                    .into(),
            enabled: true,
            priority: 160,
            severity: Severity::Warning,
            dry_run: false,
            when: RuleMatch {
                detectors: vec!["DET-27".into()],
                ..RuleMatch::default()
            },
            action: RuleAction::Alert,
        },
    ];
    rules.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.id.cmp(&b.id)));
    rules
}

/// Example country/ASN disposition rules. They are **disabled** by default
/// (FR-138: no country rule is enabled by default) and are intended to be
/// loaded through the UI/CLI, reviewed, then enabled one at a time.
pub fn sample_geo_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: 0,
            name: "Geo alert: China".into(),
            description:
                "Sample only. Alert on any detection whose source country is CN. Disabled by default."
                    .into(),
            enabled: false,
            priority: 300,
            severity: Severity::Warning,
            dry_run: false,
            when: RuleMatch {
                countries: vec!["CN".into()],
                ..RuleMatch::default()
            },
            action: RuleAction::Alert,
        },
        Rule {
            id: 0,
            name: "Geo block 24h: high-risk list".into(),
            description:
                "Sample only. Block a detected source for 24h when its country is CN, RU, KP or IR. Disabled by default."
                    .into(),
            enabled: false,
            priority: 280,
            severity: Severity::Critical,
            dry_run: false,
            when: RuleMatch {
                countries: vec!["CN".into(), "RU".into(), "KP".into(), "IR".into()],
                ..RuleMatch::default()
            },
            action: RuleAction::BlockTemp {
                duration: "24h".into(),
            },
        },
        Rule {
            id: 0,
            name: "Geo allow: partner ASNs".into(),
            description:
                "Sample only. Allow Cloudflare/Google example ASNs after a detection. Disabled by default."
                    .into(),
            enabled: false,
            priority: 400,
            severity: Severity::Info,
            dry_run: false,
            when: RuleMatch {
                asns: vec![13335, 15169],
                ..RuleMatch::default()
            },
            action: RuleAction::Allow,
        },
        Rule {
            id: 0,
            name: "Geo escalate: hosting ASNs".into(),
            description:
                "Sample only. Use a 24h -> 48h -> permanent ladder for example hosting ASNs. Disabled by default."
                    .into(),
            enabled: false,
            priority: 260,
            severity: Severity::Warning,
            dry_run: false,
            when: RuleMatch {
                asns: vec![16509, 14618, 8075],
                ..RuleMatch::default()
            },
            action: RuleAction::Escalate {
                ladder: vec!["24h".into(), "48h".into(), "permanent".into()],
            },
        },
        Rule {
            id: 0,
            name: "Geo alert: outside expected countries".into(),
            description:
                "Sample only. Alert when a detection comes from outside US/GB/DE/CA/AU. Disabled by default."
                    .into(),
            enabled: false,
            priority: 200,
            severity: Severity::Info,
            dry_run: false,
            when: RuleMatch {
                not_countries: vec![
                    "US".into(),
                    "GB".into(),
                    "DE".into(),
                    "CA".into(),
                    "AU".into(),
                ],
                ..RuleMatch::default()
            },
            action: RuleAction::Alert,
        },
    ]
}

impl CompiledRule {
    fn matches(&self, det: &Detection, history: &History, geo: &crate::geo::GeoInfo) -> bool {
        if !self.detectors.is_empty() && !self.detectors.contains(&det.detector) {
            return false;
        }
        if !self.sources.is_empty()
            && (det.src.is_unspecified() || !self.sources.iter().any(|cidr| cidr.contains(det.src)))
        {
            return false;
        }
        if self.not_sources.iter().any(|cidr| cidr.contains(det.src)) {
            return false;
        }
        if !self.ports.is_empty() {
            let Some(port) = det.dst_port else {
                return false;
            };
            if !self
                .ports
                .iter()
                .any(|(lo, hi)| (*lo..=*hi).contains(&port))
            {
                return false;
            }
        }
        if !self.protocols.is_empty() && !self.protocols.contains(&det.proto) {
            return false;
        }
        if let Some(min) = self.rule.when.min_count {
            if det.count < min {
                return false;
            }
        }
        if let Some(min) = self.rule.when.min_strikes {
            if history.strikes < min {
                return false;
            }
        }
        if self.rule.when.only_if_blocked && !history.blocked {
            return false;
        }
        if let Some(window) = self.last_seen_within {
            match history.last_strike_seen {
                Some(last) if det.last_seen >= last && det.last_seen - last <= window => {}
                _ => return false,
            }
        }
        if !self.rule.when.tags.is_empty() {
            let tags = det
                .metadata
                .get("tags")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default();
            let present = |needle: &String| {
                tags.iter()
                    .filter_map(|tag| tag.as_str())
                    .any(|tag| tag.eq_ignore_ascii_case(needle))
            };
            if !self.rule.when.tags.iter().all(present) {
                return false;
            }
        }
        if !self.countries.is_empty() || !self.not_countries.is_empty() {
            let Some(country) = geo.country.as_deref() else {
                return false;
            };
            if !self.countries.is_empty()
                && !self
                    .countries
                    .iter()
                    .any(|code| code.eq_ignore_ascii_case(country))
            {
                return false;
            }
            if self
                .not_countries
                .iter()
                .any(|code| code.eq_ignore_ascii_case(country))
            {
                return false;
            }
        }
        if !self.asns.is_empty() || !self.not_asns.is_empty() {
            let Some(asn) = geo.asn else {
                return false;
            };
            if !self.asns.is_empty() && !self.asns.contains(&asn) {
                return false;
            }
            if self.not_asns.contains(&asn) {
                return false;
            }
        }
        if !self.rule.when.days.is_empty() {
            let day = det.last_seen.weekday().num_days_from_sunday() as u8;
            if !self.rule.when.days.contains(&day) {
                return false;
            }
        }
        if let (Some(start), Some(end)) = (self.start_min, self.end_min) {
            let minute = (det.last_seen.hour() * 60 + det.last_seen.minute()) as u16;
            let inside = if start < end {
                minute >= start && minute < end
            } else {
                minute >= start || minute < end
            };
            if !inside {
                return false;
            }
        }
        true
    }
}

fn consider_block(
    current: &mut Option<(u32, BlockDuration, bool, bool, Severity)>,
    compiled: &CompiledRule,
    id: u32,
    duration: BlockDuration,
    escalated: bool,
) {
    let candidate = (rank_duration(duration), compiled.rule.severity);
    let better = match current {
        None => true,
        Some((_, other_duration, _, _, other_severity)) => {
            candidate > (rank_duration(*other_duration), *other_severity)
        }
    };
    if better {
        *current = Some((
            id,
            duration,
            escalated,
            compiled.rule.dry_run,
            compiled.rule.severity,
        ));
    }
}

fn rank_duration(duration: BlockDuration) -> i128 {
    match duration {
        BlockDuration::Permanent => i128::MAX,
        BlockDuration::Temporary(secs) => secs as i128,
    }
}

fn ladder_step(ladder: &[BlockDuration], strike: u32) -> BlockDuration {
    let idx = (strike.saturating_sub(1) as usize).min(ladder.len().saturating_sub(1));
    ladder.get(idx).copied().unwrap_or(BlockDuration::Permanent)
}

fn compile_rule(rule: Rule, global_ladder: &[BlockDuration]) -> Result<CompiledRule, String> {
    if rule.name.trim().is_empty() {
        return Err("name is required".into());
    }
    if rule.name.chars().count() > 120 {
        return Err("name must be at most 120 characters".into());
    }
    if rule.description.chars().count() > 2000 {
        return Err("description must be at most 2000 characters".into());
    }
    if !(-10_000..=10_000).contains(&rule.priority) {
        return Err("priority must be between -10000 and 10000".into());
    }

    let mut detectors = Vec::new();
    for id in &rule.when.detectors {
        let id = id.trim();
        if id.is_empty() {
            continue;
        }
        let det = Detector::from_id(id).ok_or_else(|| format!("unknown detector {id:?}"))?;
        if !detectors.contains(&det) {
            detectors.push(det);
        }
    }

    let sources = parse_cidrs(&rule.when.sources, "sources")?;
    let not_sources = parse_cidrs(&rule.when.not_sources, "not_sources")?;
    let mut ports = Vec::new();
    for spec in &rule.when.ports {
        ports.push(parse_port(spec)?);
    }
    let mut protocols = Vec::new();
    for name in &rule.when.protocols {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let proto = parse_proto(name)?;
        if !protocols.contains(&proto) {
            protocols.push(proto);
        }
    }

    if rule.when.min_count == Some(0) {
        return Err("min_count must be at least 1".into());
    }
    if rule.when.min_strikes == Some(0) {
        return Err("min_strikes must be at least 1".into());
    }
    let last_seen_within = match &rule.when.last_seen_within {
        Some(text) if !text.trim().is_empty() => {
            let duration: BlockDuration =
                text.parse().map_err(|e| format!("last_seen_within: {e}"))?;
            match duration {
                BlockDuration::Temporary(secs) => Some(chrono::Duration::seconds(secs)),
                BlockDuration::Permanent => {
                    return Err("last_seen_within must be a finite duration".into());
                }
            }
        }
        _ => None,
    };

    let mut days = Vec::new();
    for day in &rule.when.days {
        if *day > 6 {
            return Err("days must be 0 (Sunday) through 6 (Saturday)".into());
        }
        if !days.contains(day) {
            days.push(*day);
        }
    }
    let (start_min, end_min) = match (&rule.when.start, &rule.when.end) {
        (None, None) => (None, None),
        (Some(start), Some(end)) => {
            let start = parse_time(start)?;
            let end = parse_time(end)?;
            if start == end {
                return Err("start and end must differ".into());
            }
            (Some(start), Some(end))
        }
        _ => return Err("start and end must both be set or both empty".into()),
    };

    let countries = parse_countries(&rule.when.countries, "countries")?;
    let not_countries = parse_countries(&rule.when.not_countries, "not_countries")?;
    let asns = rule.when.asns.clone();
    let not_asns = rule.when.not_asns.clone();
    if asns.contains(&0) || not_asns.contains(&0) {
        return Err("ASN must be greater than zero".into());
    }

    let action = match &rule.action {
        RuleAction::Alert => CompiledAction::Alert,
        RuleAction::Tag { tag } => {
            if tag.trim().is_empty() {
                return Err("tag action needs a non-empty tag".into());
            }
            if tag.chars().count() > 64 {
                return Err("tag must be at most 64 characters".into());
            }
            CompiledAction::Tag(tag.trim().to_string())
        }
        RuleAction::Allow => CompiledAction::Allow,
        RuleAction::BlockTemp { duration } => {
            let parsed: BlockDuration = duration
                .parse()
                .map_err(|e| format!("block_temp duration: {e}"))?;
            match parsed {
                BlockDuration::Temporary(secs) if secs > 0 => {
                    CompiledAction::Block(BlockDuration::Temporary(secs))
                }
                BlockDuration::Temporary(_) => {
                    return Err("block_temp duration must be positive".into());
                }
                BlockDuration::Permanent => {
                    return Err("use block_permanent for a permanent block".into());
                }
            }
        }
        RuleAction::BlockPermanent => CompiledAction::Block(BlockDuration::Permanent),
        RuleAction::Escalate { ladder } => {
            let mut steps = Vec::new();
            for step in ladder {
                let parsed: BlockDuration =
                    step.parse().map_err(|e| format!("escalate ladder: {e}"))?;
                steps.push(parsed);
            }
            if steps.is_empty() {
                steps = global_ladder.to_vec();
            }
            if steps.is_empty() {
                return Err("escalate needs at least one ladder step".into());
            }
            CompiledAction::Escalate(steps)
        }
    };

    let normalized_when = RuleMatch {
        detectors: detectors.iter().map(|d| d.as_str().to_string()).collect(),
        sources: sources.iter().map(|c| c.to_string()).collect(),
        not_sources: not_sources.iter().map(|c| c.to_string()).collect(),
        ports: ports
            .iter()
            .map(|(lo, hi)| {
                if lo == hi {
                    lo.to_string()
                } else {
                    format!("{lo}-{hi}")
                }
            })
            .collect(),
        protocols: protocols.iter().map(|p| p.as_str().to_string()).collect(),
        min_count: rule.when.min_count,
        min_strikes: rule.when.min_strikes,
        only_if_blocked: rule.when.only_if_blocked,
        last_seen_within: rule.when.last_seen_within,
        tags: rule.when.tags,
        countries: countries.clone(),
        not_countries: not_countries.clone(),
        asns: asns.clone(),
        not_asns: not_asns.clone(),
        days,
        start: rule.when.start,
        end: rule.when.end,
    };

    Ok(CompiledRule {
        rule: Rule {
            id: rule.id,
            name: rule.name,
            description: rule.description,
            enabled: rule.enabled,
            priority: rule.priority,
            severity: rule.severity,
            dry_run: rule.dry_run,
            when: normalized_when,
            action: rule.action,
        },
        detectors,
        sources,
        not_sources,
        ports,
        protocols,
        countries,
        not_countries,
        asns,
        not_asns,
        last_seen_within,
        start_min,
        end_min,
        action,
    })
}

fn parse_cidrs(values: &[String], field: &str) -> Result<Vec<Cidr>, String> {
    let mut out = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let cidr = Cidr::parse(value).map_err(|e| format!("{field}: {e}"))?;
        if !out.contains(&cidr) {
            out.push(cidr);
        }
    }
    Ok(out)
}

fn parse_port(spec: &str) -> Result<(u16, u16), String> {
    let spec = spec.trim();
    let (lo, hi) = match spec.split_once('-') {
        Some((lo, hi)) => {
            let lo: u16 = lo
                .trim()
                .parse()
                .map_err(|_| format!("invalid port {lo:?}"))?;
            let hi: u16 = hi
                .trim()
                .parse()
                .map_err(|_| format!("invalid port {hi:?}"))?;
            (lo, hi)
        }
        None => {
            let port: u16 = spec.parse().map_err(|_| format!("invalid port {spec:?}"))?;
            (port, port)
        }
    };
    if lo == 0 || hi == 0 {
        return Err("ports must be 1-65535".into());
    }
    if lo > hi {
        return Err(format!("port range {spec:?} is reversed"));
    }
    Ok((lo, hi))
}

fn parse_proto(name: &str) -> Result<Proto, String> {
    match name.to_ascii_lowercase().as_str() {
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        "icmp" => Ok(Proto::Icmp),
        "icmp6" | "icmpv6" => Ok(Proto::Icmpv6),
        "log" => Ok(Proto::Log),
        other => Err(format!(
            "protocol must be tcp, udp, icmp, icmp6 or log (got {other:?})"
        )),
    }
}

fn parse_time(value: &str) -> Result<u16, String> {
    let (hour, minute) = value
        .trim()
        .split_once(':')
        .ok_or_else(|| format!("time {value:?} must be HH:MM"))?;
    let hour: u16 = hour
        .parse()
        .map_err(|_| format!("invalid hour in {value:?}"))?;
    let minute: u16 = minute
        .parse()
        .map_err(|_| format!("invalid minute in {value:?}"))?;
    if hour > 23 || minute > 59 {
        return Err(format!("time {value:?} is out of range"));
    }
    Ok(hour * 60 + minute)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Detection;
    use chrono::TimeZone;

    fn ladder() -> Vec<BlockDuration> {
        vec![
            BlockDuration::Temporary(3_600),
            BlockDuration::Temporary(86_400),
            BlockDuration::Permanent,
        ]
    }

    fn det(detector: Detector) -> Detection {
        Detection {
            detector,
            src: "203.0.113.7".parse().unwrap(),
            dst: Some("192.0.2.1".parse().unwrap()),
            dst_port: Some(22),
            proto: Proto::Tcp,
            count: 20,
            window_secs: 10,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            metadata: serde_json::json!({}),
            evidence_log_id: None,
            id: Some(1),
        }
    }

    #[test]
    fn defaults_preserve_pre_rule_behaviour() {
        let set = RuleSet::defaults(&ladder());
        let history = History::default();

        let out = set.evaluate(
            &det(Detector::VerticalScan),
            &history,
            &crate::geo::GeoInfo::default(),
        );
        assert_eq!(out.matched, vec![3, 5]);
        assert_eq!(
            out.action,
            DecisionAction::Block {
                duration: BlockDuration::Temporary(3_600),
                escalated: true
            }
        );

        let out = set.evaluate(
            &det(Detector::Honeypot),
            &history,
            &crate::geo::GeoInfo::default(),
        );
        assert!(out.matched.contains(&6));
        assert_eq!(
            out.action,
            DecisionAction::Block {
                duration: BlockDuration::Temporary(3_600),
                escalated: true
            }
        );

        let out = set.evaluate(
            &det(Detector::SshSuccessAfterFailures),
            &history,
            &crate::geo::GeoInfo::default(),
        );
        assert_eq!(out.action, DecisionAction::Alert);
        assert_eq!(out.rule_id, Some(2));

        let out = set.evaluate(
            &det(Detector::SshAuthFailures),
            &history,
            &crate::geo::GeoInfo::default(),
        );
        assert_eq!(
            out.action,
            DecisionAction::Block {
                duration: BlockDuration::Temporary(3_600),
                escalated: true
            }
        );
    }

    #[test]
    fn longer_block_and_allow_win() {
        let rules = vec![
            Rule {
                id: 1,
                name: "short".into(),
                description: String::new(),
                enabled: true,
                priority: 100,
                severity: Severity::Info,
                dry_run: false,
                when: RuleMatch::default(),
                action: RuleAction::BlockTemp {
                    duration: "1h".into(),
                },
            },
            Rule {
                id: 2,
                name: "long".into(),
                description: String::new(),
                enabled: true,
                priority: 100,
                severity: Severity::Info,
                dry_run: false,
                when: RuleMatch::default(),
                action: RuleAction::BlockTemp {
                    duration: "24h".into(),
                },
            },
            Rule {
                id: 3,
                name: "allow".into(),
                description: String::new(),
                enabled: true,
                priority: 50,
                severity: Severity::Info,
                dry_run: false,
                when: RuleMatch::default(),
                action: RuleAction::Allow,
            },
        ];
        let set = RuleSet::compile(rules, &ladder()).unwrap();
        let out = set.evaluate(
            &det(Detector::VerticalScan),
            &History::default(),
            &crate::geo::GeoInfo::default(),
        );
        assert_eq!(out.action, DecisionAction::Allow);
    }

    #[test]
    fn per_rule_ladder_override_and_history() {
        let rules = vec![Rule {
            id: 7,
            name: "geo-style".into(),
            description: String::new(),
            enabled: true,
            priority: 100,
            severity: Severity::Critical,
            dry_run: false,
            when: RuleMatch {
                min_count: Some(10),
                ..RuleMatch::default()
            },
            action: RuleAction::Escalate {
                ladder: vec!["24h".into(), "48h".into(), "permanent".into()],
            },
        }];
        let set = RuleSet::compile(rules, &ladder()).unwrap();
        let out = set.evaluate(
            &det(Detector::VerticalScan),
            &History {
                strikes: 1,
                ..History::default()
            },
            &crate::geo::GeoInfo::default(),
        );
        assert_eq!(
            out.action,
            DecisionAction::Block {
                duration: BlockDuration::Temporary(172_800),
                escalated: true
            }
        );
    }

    #[test]
    fn source_port_protocol_and_time_filters() {
        let when = RuleMatch {
            sources: vec!["203.0.113.0/24".into()],
            ports: vec!["22".into(), "8000-8100".into()],
            protocols: vec!["tcp".into()],
            days: vec![1, 2, 3, 4, 5],
            start: Some("08:00".into()),
            end: Some("18:00".into()),
            ..RuleMatch::default()
        };
        let mut rule = Rule {
            id: 9,
            name: "business-hours SSH".into(),
            description: String::new(),
            enabled: true,
            priority: 100,
            severity: Severity::Warning,
            dry_run: false,
            when,
            action: RuleAction::Alert,
        };
        let set = RuleSet::compile(vec![rule.clone()], &ladder()).unwrap();
        let monday = Utc.with_ymd_and_hms(2026, 11, 16, 9, 30, 0).unwrap();
        let mut d = det(Detector::VerticalScan);
        d.last_seen = monday;
        d.first_seen = monday;
        assert_eq!(
            set.evaluate(&d, &History::default(), &crate::geo::GeoInfo::default())
                .action,
            DecisionAction::Alert
        );
        d.last_seen = Utc.with_ymd_and_hms(2026, 11, 16, 20, 30, 0).unwrap();
        assert!(
            set.evaluate(&d, &History::default(), &crate::geo::GeoInfo::default())
                .matched
                .is_empty()
        );

        rule.when.sources = vec!["198.51.100.0/24".into()];
        let set = RuleSet::compile(vec![rule], &ladder()).unwrap();
        d.last_seen = monday;
        assert!(
            set.evaluate(&d, &History::default(), &crate::geo::GeoInfo::default())
                .matched
                .is_empty()
        );
    }

    #[test]
    fn dry_run_flag_is_surfaced() {
        let rules = vec![Rule {
            id: 1,
            name: "dry".into(),
            description: String::new(),
            enabled: true,
            priority: 100,
            severity: Severity::Warning,
            dry_run: true,
            when: RuleMatch::default(),
            action: RuleAction::BlockTemp {
                duration: "1h".into(),
            },
        }];
        let set = RuleSet::compile(rules, &ladder()).unwrap();
        let out = set.evaluate(
            &det(Detector::VerticalScan),
            &History::default(),
            &crate::geo::GeoInfo::default(),
        );
        assert!(out.dry_run);
    }

    #[test]
    fn invalid_rules_are_rejected_with_context() {
        let bad = Rule {
            id: 5,
            name: "bad".into(),
            description: String::new(),
            enabled: true,
            priority: 100,
            severity: Severity::Info,
            dry_run: false,
            when: RuleMatch {
                detectors: vec!["DET-99".into()],
                ..RuleMatch::default()
            },
            action: RuleAction::Alert,
        };
        let errors = RuleSet::compile(vec![bad], &ladder()).unwrap_err();
        assert_eq!(errors[0].rule_id, 5);
        assert!(errors[0].message.contains("DET-99"));

        let no_rules = RuleSet::compile(Vec::new(), &ladder()).unwrap_err();
        assert!(no_rules[0].message.contains("at least one rule"));
    }

    #[test]
    fn disabled_rules_do_not_match() {
        let rules = vec![Rule {
            id: 1,
            name: "off".into(),
            description: String::new(),
            enabled: false,
            priority: 100,
            severity: Severity::Info,
            dry_run: false,
            when: RuleMatch::default(),
            action: RuleAction::BlockPermanent,
        }];
        let set = RuleSet::compile(rules, &ladder()).unwrap();
        let out = set.evaluate(
            &det(Detector::VerticalScan),
            &History::default(),
            &crate::geo::GeoInfo::default(),
        );
        assert!(out.matched.is_empty());
        assert_eq!(out.action, DecisionAction::Alert);
    }

    #[test]
    fn form_roundtrip_preserves_a_rule() {
        let rule = Rule {
            id: 12,
            name: "form rule".into(),
            description: "desc".into(),
            enabled: true,
            priority: 75,
            severity: Severity::Critical,
            dry_run: true,
            when: RuleMatch {
                detectors: vec!["DET-16".into()],
                sources: vec!["203.0.113.0/24".into()],
                not_sources: Vec::new(),
                ports: vec!["22".into(), "8000-8100".into()],
                protocols: vec!["tcp".into()],
                min_count: Some(5),
                min_strikes: Some(2),
                only_if_blocked: false,
                last_seen_within: Some("90d".into()),
                tags: vec!["auth".into()],
                countries: vec!["CN".into()],
                not_countries: Vec::new(),
                asns: vec![64500],
                not_asns: Vec::new(),
                days: vec![1, 2],
                start: Some("08:00".into()),
                end: Some("18:00".into()),
            },
            action: RuleAction::Escalate {
                ladder: vec!["24h".into(), "permanent".into()],
            },
        };
        let form = RuleForm::from_rule(&rule);
        let roundtrip = form.to_rule().unwrap();
        assert_eq!(roundtrip, rule);
    }

    #[test]
    fn form_rejects_bad_values() {
        let form = RuleForm {
            name: "bad".into(),
            action: "block_temp".into(),
            duration: "permanent".into(),
            ..RuleForm::default()
        };
        let rule = form.to_rule().unwrap();
        assert!(RuleSet::compile(vec![rule], &ladder()).is_err());

        let form = RuleForm {
            name: "bad".into(),
            priority: "high".into(),
            ..RuleForm::default()
        };
        assert!(form.to_rule().unwrap_err().contains("priority"));
    }

    #[test]
    fn sample_geo_rules_are_valid_and_disabled() {
        let samples = sample_geo_rules();
        assert_eq!(samples.len(), 5);
        assert!(samples.iter().all(|rule| !rule.enabled));
        assert!(samples.iter().any(|rule| !rule.when.countries.is_empty()));
        assert!(samples.iter().any(|rule| !rule.when.asns.is_empty()));
        assert!(RuleSet::compile(samples, &ladder()).is_ok());
    }

    #[test]
    fn country_and_asn_conditions_need_geo_data() {
        let rule = Rule {
            id: 1,
            name: "geo".into(),
            description: String::new(),
            enabled: true,
            priority: 100,
            severity: Severity::Warning,
            dry_run: false,
            when: RuleMatch {
                countries: vec!["CN".into()],
                asns: vec![64500],
                ..RuleMatch::default()
            },
            action: RuleAction::Alert,
        };
        let set = RuleSet::compile(vec![rule], &ladder()).unwrap();
        let detection = det(Detector::VerticalScan);
        let no_geo = crate::geo::GeoInfo::default();
        assert!(
            set.evaluate(&detection, &History::default(), &no_geo)
                .matched
                .is_empty()
        );

        let cn = crate::geo::GeoInfo {
            country: Some("CN".into()),
            asn: Some(64_500),
        };
        assert_eq!(
            set.evaluate(&detection, &History::default(), &cn).action,
            DecisionAction::Alert
        );
        let us = crate::geo::GeoInfo {
            country: Some("US".into()),
            asn: Some(64_500),
        };
        assert!(
            set.evaluate(&detection, &History::default(), &us)
                .matched
                .is_empty()
        );
    }
}
