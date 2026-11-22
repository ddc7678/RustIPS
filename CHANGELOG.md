# Changelog

All notable changes to RustIPS are recorded here. The project follows
`MAJOR.MINOR.PATCH`; pre-1.0 minor releases are iterations, and patch releases
are fixes within an iteration.

## [Unreleased]

### Added

- GitHub release workflow for `v*` tags: builds the Linux x86_64 binary, runs
  the coverage scorecard, and publishes the binary, checksum and scorecard as
  release assets.

### Changed

- Roadmap renumbered to stay on the 0.3.x line: rules platform 0.3.1,
  Geo + HTTP 0.3.2, hardening + performance 0.3.3, coverage gate 0.3.4,
  distribution + first run 0.3.5, release candidate 0.3.6, detector
  catalog/sidebar 0.3.7, detector scope/parameters 0.3.8,
  navigation/theme/honeypot 0.3.9, menu/state cleanup 0.3.10, IP history
  0.3.11, the 0.3.12 Active-blocks fix, 0.3.13 resource graphs and the 0.3.14
  rules-table layout fix. A 0.4.x line is opened only on an explicit decision
  (`requirements.md` §14).

## [0.3.14] — 2026-11-22

### Fixed

- Disposition rules: the Name column now has a 28% width and 260 px minimum,
  with normal wrapping. The Match column has a 20% width and 180 px minimum.
  The rules table has a 980 px minimum and remains horizontally scrollable on
  narrow screens, so long rule names and descriptions no longer get squished.

### Verified

- 160 tests pass (146 library, 6 CLI, 2 webhook, 1 replay, 3 robustness,
  1 scorecard, 1 web); clippy/fmt clean.
- Web test asserts the rules table carries the `rules-table` class.
- No schema or configuration change.

## [0.3.13] — 2026-11-22

Dashboard resource monitoring.

### Added

- Dashboard **RustIPS resources** panel with last-hour sparklines for process
  CPU %, resident memory (MB) and database storage (MB).
- Clicking a graph or the panel opens a 24-hour history dialog with larger
  graphs, current values, peaks and the sampled time range.
- `system_samples` table (schema v10) populated every 30 seconds by the
  scheduler thread and pruned after 7 days.
- `GET /api/system?hours=1|24&compact=1` authenticated fragment endpoint; the
  dashboard refreshes its small graphs every 30 seconds without a page reload.
- Lightweight `/proc` sampler for CPU ticks, VmRSS and DB/WAL/SHM size.

### Changed

- `docs/iterations/0.3.13.md` and `docs/coverage/0.3.13.{md,json}`.
- Cargo version is now 0.3.13.

### Verified

- 160 tests pass (146 library, 6 CLI, 2 webhook, 1 replay, 3 robustness,
  1 scorecard, 1 web); clippy/fmt clean.
- Web test seeds a sample and checks the dashboard sparklines, compact API and
  24-hour dialog fragment; sample DB round-trip/prune and sampler unit tests.
- Lab VM: schema v10, dashboard graphs render live CPU/Memory/DB values, the
  24-hour dialog loads, and `readyz` remains healthy.

## [0.3.12] — 2026-11-21

### Fixed

- Active blocks: the Unblock confirmation attribute no longer contains the
  clickable IP button markup. The source cell uses `ip_link`, while
  `data-confirm` and the hidden form value use the plain escaped address. This
  fixes the broken `…?"> Unblock` rendering.

### Verified

- 158 tests pass (144 library, 6 CLI, 2 webhook, 1 replay, 3 robustness,
  1 scorecard, 1 web); clippy/fmt clean.
- Web test asserts the Active blocks row has
  `data-confirm="Unblock 203.0.113.99?"`, no nested button in the attribute,
  and a clickable `data-ip` source.
- Lab VM: creating a temporary block renders a valid confirmation attribute and
  the Unblock form; the test block was removed afterwards.
- No schema or configuration change.

## [0.3.11] — 2026-11-21

Clickable per-source IP history with country/ASN and permanent blocking.

### Added

- Source addresses across Dashboard, Detections, Logs, Active blocks, Block
  history, Strikes and rule dry-run results are buttons that open an IP history
  dialog.
- `GET /api/ip?ip=…` returns a server-rendered fragment with:
  - country (ISO code) and ASN from the GeoIP/ASN indexes;
  - totals for detections, blocks, log events and strikes;
  - latest detections, blocks, the strike record and related log events;
  - allowlist/active-block status;
  - a **Permanently block** action when the address is blockable.
- DB queries for detections, blocks, strikes and log events by source.
- `docs/iterations/0.3.11.md` and `docs/coverage/0.3.11.{md,json}`.

### Changed

- The dialog is loaded by `app.js` with the existing CSRF-protected block form.
- No schema change; schema remains v9.
- Cargo version is now 0.3.11.

### Verified

- 158 tests pass (144 library, 6 CLI, 2 webhook, 1 replay, 3 robustness,
  1 scorecard, 1 web); clippy/fmt clean.
- Web test opens `/api/ip` for a seeded source, checks detection/log history and
  the permanent-block form, and verifies the endpoint requires authentication.
- Page test checks country/ASN rendering and the permanent-block button.
- Lab VM: API returns the live country code and history; dialog values render;
  permanent block is available for an eligible address.

## [0.3.10] — 2026-11-21

Menu, state-toggle and internal-detector cleanup, plus the honeypot block rule.

### Added

- `detection.honeypot_hits` (default 3) and a shipped **Honeypot block after 3
  contacts** Disposition rule (DET-26, `min_count=3`, escalate/block).
- Schema v8/v9 data-only migrations that add the honeypot rule and strip retired
detector IDs from stored rules
  sets unless one already references DET-26.
- `POST /rules/toggle` for single-button rule enable/disable.

### Changed

- Sidebar category headings are the same size as links, blue, and collapsible
  (`<details>`); open/closed state is remembered in localStorage.
- Removed the detector scope column/filter and retired the internal detectors
  DET-22 (sudo), DET-24 (system changes) and DET-25 (account changes). Their IDs
  still decode in history/rules but are not emitted or selectable.
- Detectors and Disposition rules now use one green **Enabled** / red
  **Disabled** state button instead of a label plus a separate action button.
- DET-26 is no longer alert-only: it fires after 3 contacts and blocks through
  the shipped rule. The generic packet rule excludes DET-26.
- Cargo version is now 0.3.10.
- `docs/iterations/0.3.10.md` and `docs/coverage/0.3.10.{md,json}`.

### Verified

- 157 tests pass (143 library, 6 CLI, 2 webhook, 1 replay, 3 robustness,
  1 scorecard, 1 web); clippy/fmt clean.
- Scorecard: 21/21 detectors, 19/19 blocking, 2 alert-only (DET-17/20), zero
  benign alerts/blocks.
- Web test covers collapsible categories, internal detectors absent, green/red
  single-button toggles for detectors and rules, and honeypot hits.
- Lab VM: categories/toggles render, DET-22/24/25 gone, honeypot migration
  added the new rule, `readyz` healthy.

## [0.3.9] — 2026-11-21

Navigation, flash-free theme loading and the optional honeypot detector.

### Added

- **DET-26 Honeypot port contact**: a TCP SYN or UDP datagram from another host
  to any port in `detection.honeypot_ports`. Disabled by default, alert-only by
  default, with a Settings panel for the enable switch and port list.
- `detection.honeypot_enabled` / `detection.honeypot_ports` config fields and
  editable overrides; the honeypot requires at least one port when enabled.
- `docs/iterations/0.3.9.md` and `docs/coverage/0.3.9.{md,json}`.

### Changed

- Sidebar navigation is grouped into **Monitoring** (Dashboard, Detections,
  Logs), **Detection** (Detectors, Disposition rules), **Enforcement** (Active
  blocks, History, Strikes, Allowlist) and **System** (Alerts, Settings, Audit).
- The Rules menu label is now **Disposition rules**. The page and route are
  unchanged.
- The sidebar brand no longer shows the version; the sidebar footer shows
  `RustIPS: <version>`. The main-page footer no longer repeats the version and
  keeps only health/readiness links.
- The saved theme is applied by `/assets/theme.js` in `<head>` before the
  stylesheet/body paint, so navigation no longer flashes the default light
  theme.
- Cargo version is now 0.3.9. No database schema change (v7).

### Verified

- 155 tests pass (141 library, 6 CLI, 2 webhook, 1 replay, 3 robustness,
  1 scorecard, 1 web); clippy/fmt clean.
- Scorecard is 24/24 detector cases, 19/19 blocking detectors, 0 benign
  alerts/blocks; DET-26 alert-only behaviour is asserted.
- Web test covers grouped navigation, version placement, theme.js delivery,
  honeypot validation (enabled without ports is rejected), save, and reset.
- Lab VM: grouped sidebar/theme load without flash; honeypot saved, survived
  restart, and reset; existing rules, geo and alert state preserved.

## [0.3.8] — 2026-11-21

Detector scope and editable parameters. Every detector is classified as
external (network/auth evidence) or internal (local privileged activity), and
every threshold/path list can be edited in the web UI with per-field, per-group
and global reset. Detection logic remains compiled Rust.

### Added

- `DetectorScope` (`external`/`internal`) and `Detector::scope()`; the
  Detectors page shows the scope column, counts and an external/internal
  filter.
- A central parameter registry (`src/params.rs`) with typed specs, labels,
  help text, ranges and normalization for every editable detection key.
- Editable parameter forms on `/detectors` for each detector plus shared
  packet, HTTP and log panels. Values are validated before storage.
- `detection.overrides` in SQLite: a key→value map applied after the config
  file at daemon start and re-validated as a complete `Config`.
- Per-field **Reset to default**, per-detector/group reset and **Reset all
  overrides** actions, each audited.
- `modified` tags and stored-override previews on the page, with a
  restart-required notice.
- `check`/`diagnose` report stored overrides; invalid overrides fail `check`.
- `docs/iterations/0.3.8.md` and `docs/coverage/0.3.8.{md,json}`.

### Changed

- `http_ports` is edited once in the shared HTTP panel rather than in each
  HTTP detector, because it is shared by DET-11…15.
- `docs/detectors.md` documents scope, parameter overrides, validation and
  reset behaviour.
- Cargo version is now 0.3.8. No database schema change (v7).

### Verified

- 153 tests pass (139 library, 6 CLI, 2 webhook, 1 replay, 3 robustness,
  1 scorecard, 1 web); clippy/fmt clean.
- Web test edits/resets `http_bad_paths` (DET-12) and `http_login_paths`
  (DET-13), rejects an out-of-range value, and verifies reset-one,
  reset-group and reset-all.
- CLI test proves stored overrides change `check`, and an invalid stored
  override fails `check`.
- Lab VM: external/internal columns render; DET-12 path edit persists,
  survives restart, and resets; release artifact checksum verified.

## [0.3.7] — 2026-11-21

Detector catalog and left-sidebar navigation. Administrators can inspect what
each detector looks for, see its live thresholds/path lists, and enable or
disable it without a restart. Detection logic remains compiled Rust; custom
detection signatures are not scriptable.

### Added

- **Detectors** page: category, description, live configuration, default
  disposition and an enable/disable button for every detector.
- Detector catalog metadata (`DetectorCategory`, `Detector::category()`,
  `Detector::description()`).
- DB-backed `detection.disabled` setting; `record_detection` skips disabled
  detectors before storing evidence. Toggles are audited and apply immediately.
- `rustips_detections_suppressed_total` and `detections_suppressed` counters.
- `docs/detectors.md`: detector vs disposition-rule layers, HTTP detector
  details, enabling/disabling, and the custom-detection modularity answer.
- `docs/coverage/0.3.7.{md,json}` (corpus unchanged from 0.3.6).

### Changed

- Navigation moved from the top bar to a left sidebar; the signed-in user,
  theme toggle and logout remain in the top bar. The layout becomes a
  horizontal/wrapping nav at ≤820 px.
- Detector descriptions now state exactly what each HTTP/log/packet detector
  looks for, including the current bad-path/login-path lists.

### Verified

- 146 tests pass (133 library, 5 CLI, 2 webhook, 1 replay, 3 robustness,
  1 scorecard, 1 web); clippy/fmt clean.
- Web test covers DET-12 details, toggling DET-12 off/on, and the sidebar.
- Daemon test verifies a disabled detector stores no detection and creates no
  block, then works after re-enabling.
- Lab VM: Detectors page/shows live HTTP lists; UI toggle persisted; sidebar
  and top-bar controls render. No schema change.

## [0.3.6] — 2026-11-21

Release candidate. No detector features; this iteration hardens the service,
validates the complete install/upgrade path, publishes the 0.3.6 coverage
scorecard and records a security review and short soak.

### Added

- `docs/security-review.md`: threat model, findings (two low-severity fixes),
  accepted risks, dependency review and verification commands.
- `scripts/lab/soak.sh`: memory/CPU/restarts/DB/drops/log/alert sampler with
  JSONL output and short-soak gates.
- `docs/soak/0.3.6.md` and JSONL samples; `docs/coverage/0.3.6.{md,json}`.
- `scripts/scorecard.sh` publishes by the current version; `scripts/release.sh`
  includes the current scorecard.

### Changed

- SQLite database mode is forced to 0600 (state dir remains 0700).
- `setup` no longer chmods a pre-existing config parent (for example `/tmp`)
  when an override path is used; only a newly created parent is set to 0755.
  Regression test added after RC validation exposed the `/tmp` mode change.
- Service unit hardening: `UMask=0077`, `PrivateDevices`, kernel tunable/module/
  control-group/clock/hostname protection, `RestrictSUIDSGID`,
  `RestrictRealtime`, `RestrictNamespaces`, `LockPersonality`,
  `SystemCallArchitectures=native` and restricted address families
  (`AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET`).
- `systemd-analyze security` improves from 6.5 MEDIUM to 4.1 OK.
- `scripts/scorecard.sh`/`release.sh` no longer hard-code the coverage version.

### Verified

- 144 tests pass (131 library, 5 CLI, 2 webhook, 1 replay, 3 robustness,
  1 scorecard, 1 web); clippy/fmt clean.
- `cargo audit`: 0 vulnerabilities; 1 unmaintained warning (`chrono`, no fixed
  upgrade).
- Clean Debian 13 VM: only the binary copied, `setup --install-service` +
  `systemctl enable --now` ready in **9 s**; scripted replay produced **4 active
  nftables blocks**.
- Upgrade 0.3.5 → 0.3.6 → rollback → 0.3.6 preserved 12 rules, 67 detections,
  geo indexes and logs; hardened unit reinstalled and verified.
- Lab acceptance `run-tests.sh --install`: **28/28** checks.
- Short soak: 300 s, RSS 43.3 MiB, 1.10% of one core, 0 restarts, 0 capture
  drops, journal running; 120 s DB sample 3.73 MiB flat.
- 0.3.6 scorecard: 23/23 detectors, 19/19 block-producing detectors blocked,
  4/4 alert-only stayed alert-only, 0 benign alerts/blocks.

## [0.3.5] — 2026-11-21

Distribution and first-run experience. `setup --install-service` now installs
the binary itself, with `diagnose`, `/readyz`, first-run/recovery tests, a
checksummed release script and an operator runbook. No new crates.

### Added

- `setup --install-service` copies the running binary atomically to
  `/usr/local/bin/rustips` (0755) and points the systemd unit there, so a
  binary copied to `/tmp` is sufficient for installation.
- `rustips diagnose`: effective paths, root state, capture resolution, web/PAM,
  nftables, DB size, detections/logs, rules, journal, geo, alerts and recent
  audit.
- `GET /readyz`: component readiness (database, journal, geo, nftables, PAM,
  alert queue, capture counters) beside the minimal `/healthz`.
- `rustips config check` alias for `check`.
- `tests/cli.rs`: setup idempotency, `--dry-run`, recovery with an existing DB,
  `--fresh` confirmation/archive, invalid-config hard error and install preview.
- `scripts/release.sh` (versioned binary + SHA-256) and
  `scripts/lab/first-run.sh` (TEST-39 flow on a clean host).
- `docs/runbook.md`: install, first-run, upgrade/rollback, day-2 checks, failure
  handling and uninstall.

### Verified

- 143 tests pass (130 library, 5 CLI, 2 webhook, 1 replay, 3 robustness,
  1 scorecard, 1 web); `cargo clippy --all-targets` and `cargo fmt --check`
  are clean.
- Lab VM `scripts/lab/run-tests.sh --install`: **28/28 checks pass**, including
  setup/recovery/fresh safety, `/usr/local/bin/rustips` installation, unit
  `ExecStart`, PAM no-replace, `config check`, `diagnose`, replay and web UI.
- Lab VM `diagnose`/`/readyz`: schema v7, geo loaded, journal running, PAM and
  nftables available, `ready: true`.
- `setup --dry-run --install-service` previews the binary, unit and PAM paths
  without writing.

## [0.3.4] — 2026-11-21

Coverage gate. Adds the last missing detector (DET-23 HTTP access-log scan), a
versioned attack/benign scorecard, and the published TEST-37 result. The
defined corpus is 100% covered with zero benign blocks, so the Snort fork is
not triggered. No new crates.

### Added

- DET-23 HTTP access-log scan: common/combined access lines are parsed into
  method/path/status fields; 20 unique paths or 15 404/403 responses in 30 s
  per source; ladder rule. The Logs page shows an HTTP column.
- Schema v7 adds `log_events.method`, `.path` and `.status`; a one-time
  "HTTP access-log scan escalate" rule is added to existing rule sets.
- `[logs.detection]` HTTP thresholds (`http_scan_paths`, `http_scan_404`,
  `http_scan_window_secs`) with defaults 20/15/30.
- `tests/scorecard.rs`, `scripts/scorecard.sh`, `docs/coverage/0.3.4.md` and
  `docs/coverage/0.3.4.json`: the versioned TEST-37 corpus and published result.
- Daemon tests for DET-18 escalation (1h → 24h) and allowlisted detections
  never blocking.

### Verified

- 137 tests pass (129 library, 2 webhook, 1 replay, 3 robustness, 1 scorecard,
  1 end-to-end web); `cargo clippy --all-targets` and `cargo fmt --check` are
  clean.
- Scorecard: 23/23 defined detectors detected (100%), 19/19 blocking
detectors produced a block in enforce mode, 4/4 alert-only detectors stayed
alert-only, 0 benign alerts/blocks, DET-18 escalation PASS.
- Snort fork decision: not triggered; mainline remains the detection engine.
- DET-23 additionally verified with 20 unique access-log paths and a 15 × 404
  burst in unit tests; benign 200 access logs do not alert.

## [0.3.3] — 2026-11-21

Hardening, alerting and slow-scan detection. A generic JSON webhook with a
persisted bounded queue, DET-20 long-window scan detection, five disabled
sample GeoIP/ASN rules, daily retention aggregation and fuzz-like robustness
tests. No new crates.

### Added

- Generic outbound webhook alerting (`[alerts]`): persisted `alert_queue`,
  asynchronous delivery through `curl`, deduplication by detector/source/action
  time bucket, bounded exponential retries, permanent-failure state, queue cap
  and retention pruning. Detection and enforcement never wait for delivery.
- Webhook visibility and management: a dedicated **Alerts** page for adding,
  editing and removing targets, queue rows/payloads, retry/send-now/delete,
  clearing finished rows, queue retention and sending a test; `rustips status`,
  `rustips check`, Settings status, `/api/summary` and `/metrics`.
- `scripts/webhook-email-bridge.py` and `docs/webhooks.md`: a standard-library
  SMTP/sendmail bridge with `--self-test`, `--dry-run` and `--once`.
- DET-20 slow scan: unique destination ports over a long window while the
  short-window rate stays low; configurable thresholds/cooldown; alert-only
  shipped rule so an operator opts into blocking.
- Five disabled sample country/ASN rules (`rustips rules samples`, Rules page
  panel, `docs/examples/geo-rules.json`, `docs/geo-rules.md`). Repeated loads
  do not duplicate by name.
- Schema v6: `alert_targets`, `alert_queue.target_id`, `alert_queue`,
  `detection_daily`; a one-time DET-20 rule addition for existing rule sets
  (idempotent under concurrent opens).
- Retention/maintenance: daily detection aggregation before raw pruning, alert
  queue pruning, `PRAGMA optimize` and WAL checkpoint.
- Robustness tests for packet decoders, journal JSON, message sanitization and
  the HTTP parser (deterministic random inputs), plus webhook retry/persistence
  integration tests.

### Changed

- `rustips import` accepts a `rustips-rules` document or a bare JSON array in
  addition to a full `rustips-export` file.
- `rustips rules samples --json` emits an importable rules document.

### Verified

- 130 tests pass (123 library, 2 webhook, 1 replay, 3 robustness, 1 end-to-end
  web); `cargo clippy --all-targets` and `cargo fmt --check` are clean.
- Lab VM upgrade v4 → v6; DET-20 rule added, geo indexes loaded, check/status OK.
- Webhook validation: a local endpoint returned 500 on the first POST and 200
  on the retry; the daemon logged the 5 s retry and ended with 2 delivered,
  0 pending, 0 failed. The Alerts UI added, edited and deleted a target and
  delivered a test alert; pending rows for a deleted target were dropped.
- DET-20 validation: with temporary 5-port/120 s thresholds, a 5-port slow
  `nmap` produced `DET-20 count=5`; defaults restored.
- Sample geo rules loaded through the UI: five rules, all disabled.

## [0.3.2] — 2026-11-20

GeoIP/ASN disposition enrichment and packet HTTP detectors. Rules can now use
country and ASN conditions, and clear-text HTTP is inspected for scans,
known-bad paths, login brute force, method anomalies and request floods. Geo
data is compact, checksum-verified and hot-swapped; the HTTP engine is bounded
and only runs on configured ports. No new crates.

### Added

- `src/geo`: a compact sorted range index for IPv4 and IPv6 country/ASN data,
  a pure-Rust SHA-256 verifier, atomic install with a `.prev` generation, and a
  shared `RwLock` hot-swap handle.
- `rustips geo update` downloads the four small `ip-location-db` SHA-256 files
  first, fetches the CSVs only when a checksum changed, verifies them, builds
  the indexes and installs them;
  four `--*-v4`/`--*-v6 FILE` options support offline/air-gapped updates.
  `geo status` shows generations and timestamps; `geo lookup IP` prints one
  address.
- Background geo updater with the configured cadence and manual "check now"
  requests; the daemon reloads CLI-installed indexes without a restart.
- Rules gain `countries`/`not_countries` and `asns`/`not_asns` conditions. Geo
  data is consulted only after a real detection and never creates one.
- Rules UI shows country/ASN index status, the last update result and a
  "Check now" button; the rule form exposes country and ASN fields.
- Packet HTTP parsing for DET-11…15 on `detection.http_ports`:
  - DET-11: 20 unique paths or 15 404/403 responses in 30 s;
  - DET-12: configured known-bad path on the first request;
  - DET-13: 10 401/403 responses on login paths in 60 s;
  - DET-14: 3 method/request-line/Host anomalies in 60 s;
  - DET-15: 100 requests in 10 s.
  Requests and responses are correlated by client tuple; buffers, flows and
  client tables are bounded.
- Schema v4 data migration adds an "HTTP detectors escalate" rule to an
  existing 0.3.1 rule set unless a rule already references DET-11…15. Fresh
  installs include the detectors in the shipped packet rule.
- `[geo]` configuration and HTTP detector thresholds/path lists in
  `[detection]`, with serde defaults so old configs parse unchanged.

### Fixed

- Geo migration is idempotent under concurrent `Db::open` calls: the rule
  check and insert share an immediate transaction, so the daemon and CLI
  cannot both add the HTTP rule.
- `Db::open` on a v3 database now performs the data migration exactly once;
  subsequent opens no longer re-add rules.

### Verified

- 115 tests pass (113 library, 1 replay, 1 end-to-end web); `cargo clippy
  --all-targets` and `cargo fmt --check` are clean.
- Built the real `ip-location-db` indexes: 597,824 country records
  (13.1 MB) and 576,023 ASN records (10.0 MB), 23.1 MB total, in ~0.3 s from
  local CSVs; network update with SHA-256 verification took ~10 s.
- Lab VM: geo update/reload, `geo lookup 1.0.1.5` → CN, `8.8.8.8` → US/15169,
  and a temporary `country=CN` rule matched a synthetic `1.0.1.5` detection in
  the rules check view.
- Lab VM HTTP: all five detectors fired against a guest Python server —
  DET-11 (20 unique paths), DET-12 (`wp-login`), DET-13 (10 × 401), DET-14
  (3 × TRACE), DET-15 (100 requests). The allowlisted LAN source produced
  `detection.allowed` audit entries with the HTTP rule as winner and no block.

## [0.3.1] — 2026-11-20

The disposition rules platform. Detections are now turned into actions by
data-driven rules stored in SQLite, with validation, revisions, dry-run,
import/export and a UI editor. The shipped defaults reproduce the hard-coded
0.3.0 policy, so an upgrade changes no disposition until an operator edits a
rule. No new crates.

### Added

- Rule model and accumulating engine: detector, source/exclude CIDR, port and
  port-range, protocol, minimum count, minimum strikes, already-blocked, last
  strike window, tags, UTC day/time filters; actions `alert`, `tag`, `allow`,
  `block_temp`, `block_permanent` and `escalate` with per-rule ladder
  overrides. `allow` wins, then the longest block, then alert, then tag, with
  deterministic severity/priority/ID tie-breaks.
- Schema v3: `rules`, `rule_revisions`, `rules_meta` and
  `blocks.rule_id`; v1/v2 databases migrate in place. Four default rules are
  seeded on migration: log auth failures and packet detectors escalate,
  DET-17/24/25 alert, and a catch-all alerts.
- Rule CRUD with precise validation, per-rule revision history (create,
  update, delete, import), audit entries, and guards against deleting or
  disabling the last enabled rule.
- Rules UI: list, create/edit forms with all match/action fields, revision
  history, import/export, and a "dry-run against recent detections" view that
  shows matching rules and the resulting action without writing anything.
- `rustips rules check` and `rustips rules list`; `rustips check` now validates
  the stored rules; `rustips status` shows the rule count.
- `rustips export` now includes the rule set (export version 2);
  `rustips import` validates the whole set before replacing rules and maps
  imported block rule IDs.
- Rule `tag` actions are merged into detection metadata; blocks record the
  winning `rule_id`; every disposition audit line names all matching rules and
  the winner.
- Dry-run rules and global observe mode both record a `would_block` audit line
  without striking or enforcing.
- The daemon reloads validated rule changes within about a second and keeps the
  last-good set when a reload is rejected (FR-126).

### Changed

- `record_detection` is now rule-driven; the hard-coded alert-only list remains
  only as the source of the shipped defaults.
- `status`, `export`, `allowlist` and `detections` open the database read/write
  so a schema upgrade is applied before the first query (fixes an upgrade
  verification race seen on the lab VM).

### Verified

- 101 tests pass (99 library, 1 replay, 1 end-to-end web); `cargo clippy
  --all-targets` and `cargo fmt --check` are clean.
- Lab VM upgrade from 0.3.0: schema v3 migration, four default rules, `check`
  reports `rules: OK`, and the service keeps running.
- Live UI edit: a 3-hour `block_temp` rule for DET-21 was saved, the daemon
  logged `rules reloaded`, five synthetic PAM failures matched `rules=5,1,4
  winner=5`, and observe mode recorded `detection.would_block` with the 3h
  duration and no block. Deleting the rule restored the defaults.

## [0.3.0] — 2026-11-20

Host logs as a first-class input. The journald slice adds supervised
ingestion, cursor resume, SSH/PAM/sudo/systemd parsers, DET-16/17/21/22/24/25,
the Logs view, schema v2 and `rustips logs test`. File sources, DET-23 and the
mail/HTTP/syslog parsers are the next slice. No new crates.

### Added

- Journald ingestion through a supervised `journalctl -f -o json` child on its
  own thread, with isolated failure and backoff, capped lines, rate limits and
  degraded-health reporting. Packet capture and enforcement are unaffected by
  a journal outage.
- Cursor checkpoint after every event, exact resume on restart, a 15-minute
  first-start backfill, a partial unique index on `log_events(cursor)` against
  crash replay, and a `Cursor gap` banner when continuity is lost.
- Parser registry and normalised event shape for sshd (`sshd`, `sshd-session`,
  `sshd-auth`), PAM, sudo, systemd-logind, kernel/audit, cron and system
  changes. Messages are bounded, control characters neutralised and literal
  redactions applied before storage.
- Log detectors: DET-16 SSH failure burst (ladder), DET-17 success after
  failures (alert only), DET-21 non-sshd PAM burst (ladder), DET-22 sudo
  denial/wrong password (ladder when a source is present; local events have no
  source and never block), DET-24 security-relevant system change (alert only)
  and DET-25 account/privilege change (alert only).
- Detections from logs use the shared `record_detection` path, with journal
  cursor, identifier, template and bounded evidence stored as provenance; a
  no-source detection uses `0.0.0.0` and never blocks.
- `/logs` page: origin filter, free-text search, parser/template/unit/
  priority/user/source/message columns, resulting-detection tag, journal health,
  this-process stored/rate-limited/parse-error counters, a cumulative
  retention-prune count and a cursor-gap banner. Detection rows label
  alert-only/no-source results instead of offering a block action.
- `rustips logs test --since 10m [--limit N] [--json]` parser dry run; `status`
  reports stored log events and journal state.
- `[logs]`, `[logs.journal]` and `[logs.detection]` configuration with strict
  validation and defaults; schema v2 adds `log_events`, `log_state` and
  `detections.evidence_log_id`, migrating v1 databases in place.
- Log retention: 7 days or 128 MiB by default, oldest-first pruning.
- `docs/logs.md` operator guide (privileges, privacy, retention, tuning,
  troubleshooting) and `docs/iterations/0.3.0.md`.

### Changed

- `record_detection` is now shared by packet and log detectors; observe mode,
  allowlist precedence, alert-only policy and the strike ladder apply to both.
- Disable ANSI escape codes when stderr is not a terminal, so the daemon's own
  journal lines are clean.
- `sshd-session` and capitalised `Invalid user` lines are recognised on
  Debian 13's OpenSSH 9.8.

### Fixed

- `scripts/lab/vm.sh`: `ip` no longer presents the LAN MAC as if the second NIC
  were attached when the VM is NAT-only, and now warns when the bridged NIC has
  no IPv4 address. `start --bridged` checks the bridge, the setuid
  `qemu-bridge-helper` and `/etc/qemu/bridge.conf` before launching QEMU, and
  the selected NAT/bridged mode is saved so `status` and `restart` follow the
  running configuration.
- `capture.interfaces = ["auto"]` now chooses the lowest-metric default route
  instead of the first `/proc/net/route` entry, so a bridged LAN NIC wins over
  the QEMU NAT NIC when both are present at startup.
- Dashboard: the `Detections` card now shows the persisted total so it matches
  the Recent detections table; the Live panel shows the current process's
  since-start count separately. `/api/summary` exposes both values.

### Tooling

- `scripts/lab/vm.sh`: plain-QEMU Debian 13 lab lifecycle (create, start,
  stop, status, SSH, serial console, provision, snapshots, restore, destroy)
  with user-mode NAT by default and an optional bridged NIC. `create-vm.sh`
  remains as a compatibility wrapper.
- `scripts/lab/guest-provision.sh`: idempotent guest provisioning for the
  TEST-10…TEST-13 package set, PAM test users and key-only SSH.
- `scripts/deploy.sh`: SSH deployment to Debian 13 with first install,
  upgrade, automatic/manual rollback, backups and health verification.
- `docs/testing.md`: consolidated guide to the test layers — unit and
  integration tests, synthetic pcap replay and benchmark, the acceptance
  script, the lab VM and snapshots, live attacks and deployment validation.

### Verified

- 85 tests pass (83 library, 1 replay, 1 end-to-end web); `cargo clippy
  --all-targets` and `cargo fmt --check` are clean.
- Lab VM: journal ingestion, cursor resume across `systemctl restart rustips`,
  `rustips logs test`, and live DET-16/17/21/22/24/25 detections with cursor
  provenance. Observe mode recorded detections with no blocks or strikes.

## [0.2.0] — 2026-11-18

First administrator interface. The sensor core from 0.1.0 gains an embedded
loopback UI, PAM authentication with group authorisation, break-glass recovery,
DET-08…10, live capture-health counters and a settings path for bind/port. No
new crates; log ingestion, GeoIP, rules and webhooks remain future work.

### Added

- Embedded HTTP/1.1 UI served from the single binary, bound to
  `127.0.0.1:10707` by default. Dashboard, detections (filter/pagination/
  evidence), active blocks, block history, strikes, allowlist, settings and
  audit log. Dark/light theme, tablet layout, 2-second polling and fragment
  refreshes.
- PAM authentication through `/etc/pam.d/rustips` (`dlopen`, conversation
  callback, password zeroisation, `pam_acct_mgmt`) and native NSS group
  authorisation (`rustips-admin`). No second password store.
- In-memory sessions with `HttpOnly`/`SameSite=Strict` cookies, CSRF tokens on
  every POST, 30-minute idle and 12-hour absolute timeouts, logout, fresh token
  on login, and PAM/group revalidation every 5 minutes and on privileged
  actions.
- Root-only one-time break-glass token (`rustips auth breakglass`, 0600,
  default 30 min) for PAM outages; `rustips auth test --user NAME` exercises
  PAM and group checks from the CLI.
- Login limiter: 5 failures per username and per source in 10 minutes → 15
  minute lockout, with every attempt audited.
- DET-08 connection-rate abuse, DET-09 connections to configured tarpit ports,
  DET-10 SSH connection-rate proxy.
- Manual block/unblock and allowlist CRUD in the UI, all audited with the
  authenticated actor; allowlist and implicit-address protections still win.
- Settings for bind address/port with validation, a bind test, a non-loopback
  confirmation, a persistent warning banner, storage in the database, restart
  to apply, and automatic revert if a saved override cannot bind.
- `/healthz` (public, minimal) and loopback-only `/metrics` (Prometheus text).
- Host-header allowlist (`421` on mismatch) against DNS rebinding; strict CSP
  with no inline script/style; 64-connection, 16 KB header and 8 KB body caps.
- Budget: 512 MB default via `MemoryMax=512M` in the systemd unit.
- Capture threads now publish AF_PACKET delivered/dropped counters every 5 s.
- Documentation: `docs/iterations/0.2.0.md`, plus README, changelog and
  third-party updates.

### Changed

- `rustips check` reports the web binding, PAM service, admin group and PAM
  availability; a missing PAM file is a warning, not a startup failure.
- `rustips setup` prints the SSH tunnel, `usermod -aG rustips-admin`, check/
  status and break-glass steps.
- `rustips run` accepts `--no-web`, `--web-bind` and `--web-port`.
- Break-glass default TTL is 30 minutes (FR-216).

### Verified

- 54 tests pass (52 library, 1 replay, 1 end-to-end web); `cargo clippy
  --all-targets` and `cargo fmt` are clean.
- End-to-end web test: health/assets/login, `421` Host guard, PAM failure,
  break-glass login, dashboard, summary API, CSRF `403`, manual block and
  audit, implicit-address refusal, logout invalidation.
- Release smoke test: `/healthz`, login page, tunnel-only redirect, CSS,
  `/metrics`, break-glass session, stored detections, manual block and audit.
- 4.8 MB release binary; ≈ 7.3 MB RSS for replay plus UI.

### Known limitations

- Rules and log views, GeoIP and webhook are not implemented.
- Settings edits cover bind/port only; other values are read-only.
- No API bearer token; no TLS listener (use an SSH tunnel).
- Real PAM password login was not exercised on the development host (no root,
  no `/etc/pam.d/rustips`); the failure and break-glass paths were.
- Observe mode still does not accrue strikes.

## [0.1.0] — 2026-11-18

Sensor core. The first working release: capture, decode, detection DET-01…07,
strike ladder, nftables enforcement, SQLite storage, CLI and observe mode.
CLI-only; no web UI, PAM, log ingestion or GeoIP yet.

### Added

- AF_PACKET live capture with a kernel BPF filter (IPv4/IPv6/VLAN), snap
  length, receive buffer and kernel drop statistics.
- Classic pcap replay with capture timestamps, for tests and lab runs.
- Decoder for Ethernet (up to two VLAN tags), Linux SLL, raw IP, IPv4, IPv6
  (extension headers, first fragments), TCP, UDP, ICMP and ICMPv6.
- Detectors DET-01…07 with bounded per-source state, sliding windows,
  per-detector cooldowns and JSON evidence.
- Strike tracking and the configurable ladder (1h → 24h → 48h → 7d →
  permanent), strike decay, and idempotent block extension.
- nftables enforcement in an `inet rustips` input chain with separate IPv4/IPv6
  sets, no kernel timeouts, batched transactions, startup reconciliation and
  retry of un-enforced blocks.
- Expiry scheduler, startup overdue-block handling, and failure policy:
  fail-static for committed blocks, fail-open for new decisions.
- SQLite storage (WAL, schema v1) for detections, blocks, strikes, allowlist,
  audit and settings, with daily retention pruning of detections, inactive
  blocks and audit rows.
- Implicit allowlist (loopback, RFC1918, link-local, multicast, host
  addresses); the allowlist has precedence over every block.
- CLI: `setup` (`--dry-run`, `--recover`, `--fresh`, `--install-service`,
  `--non-interactive`), `check`, `run` (`--pcap`, `--fast-replay`,
  `--observe`), `status`, `block`, `unblock`, `allow`, `allowlist`,
  `detections`, `export`, `import`, `flush`.
- Strict TOML configuration with unknown-key rejection, duration parsing and
  path/line diagnostics; first-run/recovery detection based on config **and**
  database presence.
- systemd unit and `/etc/pam.d/rustips` installation that never overwrites
  existing files; `rustips-admin` group creation.
- Lab assets: QEMU Debian 13 VM creation, in-VM acceptance script, attack
  driver, synthetic and benchmark capture generators.
- Documentation: `README.md`, this changelog, `THIRD_PARTY.md` and
  `docs/iterations/0.1.0.md`.

### Verified

- 26 tests pass (`cargo test`); `cargo clippy --all-targets` is clean.
- Replay baseline on an AMD Ryzen Threadripper 3960X: 500,000 packets in
  0.34 s CPU (≈ 1.47 M packets/s), 4.4 MB release binary.
- Synthetic capture produces DET-01, DET-03, DET-05 and DET-06 with expected
  evidence; observe mode records detections and creates no blocks.

### Known limitations

- No UI, PAM authentication, log ingestion, GeoIP or webhook yet.
- Observe mode does not accrue strikes.
- Pcap replay holds the capture file in memory.
- Kernel drop counters are logged only when capture stops.
