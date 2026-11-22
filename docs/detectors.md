# Detectors and their rules

RustIPS has two separate layers:

1. **Detectors** — compiled Rust code that recognises an attack pattern and
   emits a detection. The **Detectors** page describes each one, shows its live
   thresholds/paths, and lets an administrator enable or disable it and edit
   its parameters.
2. **Disposition rules** — data-driven rules on the **Rules** page that decide
   what happens to a detection: alert, tag, allow, block for a duration, or
   escalate through the ladder. Rules can also use country/ASN conditions.

A detector being enabled does not mean it blocks. The shipped rules decide
whether a detector alerts or enters the ladder; DET-17/20/24/25 are alert-only
by default.

## Detector catalog

| ID | Category | What it looks for | Default disposition |
|---|---|---|---|
| DET-01 | packet | Vertical TCP SYN scan: distinct destination ports ≥ `scan_ports` (20) in the window | ladder |
| DET-02 | packet | Horizontal SYN sweep: distinct local hosts ≥ `sweep_hosts` (20) for one port | ladder |
| DET-03 | packet | NULL/FIN/XMAS/invalid flag packets ≥ `stealth_packets` (3) | ladder |
| DET-04 | packet | ACK-only packets to distinct ports ≥ `ack_packets` (10) | ladder |
| DET-05 | packet | Empty UDP datagrams to distinct ports ≥ `udp_ports` (20) | ladder |
| DET-06 | packet | ICMP echo destinations ≥ `icmp_hosts` (20) or rate ≥ `icmp_echo_per_sec` (50) | ladder |
| DET-07 | packet | SYN rate ≥ `syn_per_sec` (200) with unanswered ratio ≥ `syn_unanswered_pct` (80%) | ladder |
| DET-08 | packet | New connections per source ≥ `conn_rate` (120) in `window_secs` | ladder |
| DET-09 | packet | One SYN to a port in `tarpit_ports` (empty/disabled by default) | ladder |
| DET-10 | packet | TCP/22 connections per minute ≥ `ssh_conns_per_min` (10) | ladder |
| DET-11 | HTTP | 20 unique paths or 15 × 404/403 in `http_scan_window_secs` (30) | ladder |
| DET-12 | HTTP | Path contains a substring in `http_bad_paths` (`.env`, `wp-login`, `phpmyadmin`, `cgi-bin`, `.git`, …) | ladder |
| DET-13 | HTTP | 10 × 401/403 on a path containing `http_login_paths` in `http_auth_window_secs` (60) | ladder |
| DET-14 | HTTP | 3 method/request-line/Host anomalies in `http_anomaly_window_secs` (60) | ladder |
| DET-15 | HTTP | 100 requests in `http_flood_window_secs` (10) per source | ladder |
| DET-16 | log | 5 SSH auth failures / 10 min per source (one count per attempt) | ladder |
| DET-17 | log | SSH success after one or more failures from the same source | alert only |
| DET-20 | packet | 30 unique ports / 10 min while ≤10 ports in the short window | alert only |
| DET-21 | log | 5 PAM failures / 10 min per source, excluding `sshd` | ladder |
| DET-23 | log | 20 unique paths or 15 × 404/403 in 30 s from journal access logs | ladder |
| DET-26 | packet | 3 TCP SYNs or UDP datagrams to a port in `detection.honeypot_ports` in the window; disabled by default | block after 3 contacts |

The Detectors page shows the **live** values from the configuration, not just
the defaults. For example, DET-12 lists the exact `http_bad_paths` currently
loaded, and DET-11 shows the configured HTTP ports, unique-path threshold,
404/403 threshold and window.

## Enabling and disabling

* The Detectors page has one state button per detector: green **Enabled** or
  red **Disabled**. Click it to toggle the detector.
* The choice is stored in SQLite (`detection.disabled`) and applies to the next
  detection without a restart.
* A disabled detector records nothing and cannot block. Existing blocks and
  strikes are **not** removed; use Active blocks/Rules for those.
* The state change is audited as `detector.enable`/`detector.disable`.
* The shipped default is all detectors enabled.
* Disabling is a local operator choice, not a detection rule. It is not
  replicated by export/import (which covers blocks/strikes/allowlist/rules).

## Editing parameters

Every detector exposes its tunable thresholds and lists in its row. Shared
packet, HTTP and log settings are edited in the panels below the table.

* **Save** stores an override in SQLite (`detection.overrides`) as a JSON map
  of key → value. The value is validated before it is stored: numbers are
  range-checked, ports must be 1–65535, lists are trimmed/deduplicated, and
  unknown keys are rejected.
* **Reset to default** on one field removes just that override, so the
  configuration file value applies after restart.
* **Reset this group to defaults** removes every override for that detector or
  shared panel.
* **Reset all overrides** removes every stored detection override.
* A field whose submitted value matches the running configuration is left
  unchanged, so saving one field does not create overrides for the whole group.
  A different value is stored even if it equals the built-in default, because
  the configuration file may have customised it.
* Overrides are applied **at daemon start**, after the configuration file, and
  the complete result is re-validated. Parameter changes therefore need a
  `systemctl restart rustips`; detector enable/disable still applies live.
* The page shows the running value, a `modified` tag, and the stored override
  that will apply after restart. Each field also shows its built-in default.
* Save and reset actions are audited as `detection.params.save` and
  `detection.params.reset`.

Examples:

* Add `/xmlrpc.php, /wp-json/wp/v2/users` to DET-12 `http_bad_paths`.
* Change DET-13 `http_login_paths` to your real login endpoint and raise or
  lower the 401/403 threshold.
* Change `detection.http_ports` once to cover all HTTP detectors.
* Raise `detection.scan_ports` for a busy host or lower it for a stricter
  posture.
* Enable the honeypot and list unused ports on the Settings page (or edit
  `detection.honeypot_*` in the DET-26 row; the feature switch lives in
  Settings). See below.

Overrides are **not** written back to `config.toml`. They are local state, like
detector enable/disable, and are not included in export/import. Removing an
override falls back to the configuration file value (the page labels the
built-in default separately).

## Honeypot (DET-26)

The honeypot is **disabled by default**. Configure it in **Settings → Honeypot**:

* tick **Enable honeypot**
* enter a comma-separated list of TCP/UDP ports that no real service uses

Three TCP SYNs (new connection attempts) or UDP datagrams from another host to
the listed ports within the detection window trigger DET-26. It does not need a
listener on the port; the packet sensor sees the attempts on the wire. The
shipped **Honeypot block after 3 contacts** disposition rule then blocks the
source through the configured ladder. A source emits at most one detection per
detector cooldown.

Guidance:

* use ports that are closed and not used by any real service;
* do not list 22, the RustIPS web port, or any active service port;
* the list is validated as ports 1–65535 and at least one port is required
  when the honeypot is enabled;
* the contact threshold defaults to 3 and is editable on Settings;
* changes apply after `systemctl restart rustips`.

## HTTP detector specifics

DET-11…15 parse clear-text HTTP on `detection.http_ports` (default
80, 8080, 8000, 8888). The request head is capped at 2 KB and one request per
connection is counted, so keep-alive bursts may undercount.

* **DET-11** — path scan or 404/403 burst. The 404/403 count comes from
  responses correlated to the request.
* **DET-12** — immediate known-bad probe. Edit `http_bad_paths` to add or remove
  needles; matching is lower-case substring matching on the path.
* **DET-13** — login brute force. Edit `http_login_paths` for your login
  endpoints; only 401/403 responses count.
* **DET-14** — TRACE/unknown method, malformed request line, missing Host on
  HTTP/1.1, suspicious Host, path traversal.
* **DET-15** — request flood per source.

DET-23 is the log-side equivalent of DET-11 and parses common/combined access
lines that reach the journal. File-only access logs still require the deferred
file-source slice.

## Is the detection engine modular?

Internally, yes:

* packet detectors live in `src/detect/` with a bounded per-source engine;
* HTTP detectors live in `src/detect/http.rs`;
* log detectors live in `src/logs/` with a separate normaliser/parser/engine;
* disposition is a separate data-driven rule engine in `src/rules/`;
* every detector is registered in `Detector::ALL` and exposed through the
  Detectors page/catalog.

The detection **logic is compiled**, not interpreted from admin input. This is
deliberate: no `eval`, no embedded scripting, no untrusted regex engine or
signature interpreter in the privileged data path. Adding a detector in code
means:

1. add a `Detector` variant and catalog description;
2. implement the bounded detector in the packet/HTTP/log engine;
3. add config fields with defaults and validation;
4. add a shipped disposition rule (or rely on the catch-all alert);
5. add unit/corpus tests and a scorecard case;
6. update the Detectors page and docs.

Administrators can customise **what is detected** today through:

* enable/disable per detector;
* packet/HTTP/log thresholds and path lists, edited in the UI (stored overrides);
* journal unit/identifier include/exclude lists;
* redaction and retention;
* disposition rules, per-rule ladders, country/ASN conditions;
* allowlist and alert targets.

Administrators **cannot** create new detection logic or signature scripts in
0.3.10. A future custom-detection feature would need a bounded, linear-time
pattern matcher (no backtracking regex), strict length caps, a validation/
dry-run screen, and a clear security review before it is enabled in the
privileged path. That is intentionally deferred rather than exposing an
untrusted code/signature engine.

## Troubleshooting

* Detector shows disabled but still appears in old detections: disabling does
  not delete historical rows.
* DET-12 does not fire: check the current `http_bad_paths` on the Detectors
  page and confirm traffic hits `http_ports` in clear text.
* DET-13 does not fire: your login path must match `http_login_paths`, and the
  server must return 401/403 (not a 200 login page with an error message).
* DET-23 does not fire: access logs must reach the journal; file-only logs need
  file tailing.
* DET-20 is alert-only: add a block rule on the Rules page if you want the
  ladder.
