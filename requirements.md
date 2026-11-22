# RustIPS — Requirements Specification

| Field | Value |
|---|---|
| Project | RustIPS (Rust Intrusion Prevention System) |
| Document | `requirements.md` |
| Status | Draft for review |
| Version | 0.2.0 (document revision 8) |
| Date | 2026-11-18 |
| Source | `draft_requirements.md` (original notes, retained as input) |
| Reference repos | `repos/suricata/`, `repos/ip-location-db/`, `repos/psad/`, `repos/fwsnort/`, `repos/snort3/` |

**Revision 8** settles the authorisation model. Q13: authorisation is **group-only** — membership of
`rustips-admin` is the single grant, with no per-user allowlist layered on top. Q22: there is **no
read-only role, viewer account, or reduced-permission token**; RustIPS is an administrative tool,
every authenticated admin has full authority, and the API token (FR-189) is an admin credential for
monitoring rather than a second role. The result is one authorisation path, no permission matrix,
and no read-only surface to test or document.

**Revision 7** makes RustIPS a **single-binary product with a first-run setup path**. Q12: the
supported artefact is the binary itself; there is no `.deb` requirement. On start, the presence of
`/etc/rustips/config.toml` decides whether this is a new install, and the binary must refuse to
treat a missing config plus an existing database as a fresh setup (FR-217…219d). Q3 is confirmed as
**nftables only** (no iptables/ipset backend). Q11 is confirmed as **webhook only** — SMTP, chat,
and push are downstream integrations the administrator builds from the webhook. Q10 is closed: the
**512 MB default disk ceiling** (DB 256 MB, raw logs 128 MB, geo ~80 MB, headroom ~48 MB) is
accepted as the default, with every cap configurable and pruning enforced before the limit is
reached (NFR-108/116).

**Revision 6** keeps Snort **out of the mainline product**. RustIPS must first reach a fully
working, fast, minimal state installable in minutes; adding Snort as a second daemon would work
against that. The Snort design is preserved in §19 as a **post-1.0 fork**, started only if the
built-in detectors miss the **≥ 97% coverage** gate (G-08, TEST-37). Q8 (`user-country`, daily) and
Q28 (geo updates performed by RustIPS; no signature feed in 0.x) are resolved. Q10 is answered as a
design principle rather than a number: minimum disk/CPU/memory, expressed as a 512 MB default cap
with enforced per-table limits (NFR-108/116). §6.12 is therefore removed from the mainline
functional requirements.

**Revision 5** added the Snort 3 detection module (§6.12, FR-400…454). That design is now
deferred in full to §19.

**Revision 4** resolved Q16: log ingestion covers the systemd journal **and** configured file
sources, so services that only write to files (nginx, apache, application logs) are first-class.
That adds an inode/offset checkpoint model, rotation/truncation handling, and bounded line parsing
alongside the journal cursor model (§6.2.2).

**Revision 3** resolved Q4: the failure policy is fail-open for new dispositions while existing
nftables blocks persist, with expiry performed by the daemon rather than the kernel (§7.5). That
explicitly rules out fail-closed/quarantine mode (NG-11) and per-element nftables timeouts.

---

## 1. Purpose of this document

`draft_requirements.md` describes intent and a set of system wishes. This document turns that intent
into numbered, testable requirements, records the assumptions needed to make the draft
unambiguous, and captures the open questions that must be answered before implementation of the
affected feature.

Requirement IDs are stable. Each requirement is either:

- **MUST** — required for the release it is assigned to.
- **SHOULD** — expected, may be deferred with a documented reason.
- **MAY** — optional / nice to have.

Anything marked **[ASSUMPTION]** is a decision made while writing this document that the owner
should confirm or reject. Anything in §17 (Open Questions) is unresolved. Decisions confirmed by the
owner in revisions 2–3 are marked **[CONFIRMED]**.

---

## 2. Vision

RustIPS is a small, fast, low-overhead intrusion prevention system for a **single internet-facing
host**. It monitors the host's network traffic, detects the common, noisy, automated attacks that
account for the large majority of real-world attempts (port scans, service probing, HTTP path
scanning, credential brute force), and applies fast, rules-driven blocking with escalating
penalties.

It also consumes the host's system logs — the complete systemd journal plus any configured file
sources — so that events which are invisible on the wire (SSH authentication failures,
PAM/`sudo` denials, firewall tampering, web-server scans) are first-class detections using the same
detection → disposition → enforcement path as packet detections.

The problem being solved is deployment friction, not detection depth. Suricata
(`repos/suricata/`) is a capable but heavy IDS/IPS with a large configuration surface and no
first-class management UI. RustIPS deliberately trades breadth for:

1. A single binary plus a config file that can be installed and running in minutes.
2. Predictable, measurable resource use (target: < 100 MB binary, minimal CPU/RSS).
3. A real-time web UI for monitoring, rules, and block management.
4. A small, explainable rule model that an administrator can read and reason about.

---

## 3. Goals

| ID | Goal |
|---|---|
| G-01 | Detect and block the top 15–20 automated attack methods against a single host, quickly. |
| G-02 | Keep per-packet work minimal: no full DPI, no signature engine, no file extraction, no stream reassembly beyond what a detector needs. |
| G-03 | Ship as one self-contained binary with an embedded web UI, installable on a stock Debian 13 host. |
| G-04 | Escalate repeat offenders automatically (temporary → longer → permanent). |
| G-05 | Never block a whitelisted host/network, and never lock the administrator out. |
| G-06 | Provide a complete, auditable history of detections, blocks, and configuration changes. |
| G-07 | Be operable by one administrator with no external services, no cloud dependency, and no telemetry. |
| G-08 | **Detect and block ≥ 97%** of the defined attack corpus, with zero false-positive blocks on the benign corpus, using only built-in detectors — so no external engine is needed. |
| G-09 | Install and reach first useful protection in **minutes** on a stock Debian 13 host: one binary, one service, no external daemon, no rule subscription. |
| G-10 | Keep the footprint genuinely small: minimal disk, CPU, and memory, with every limit enforced rather than aspirational (NFR-102…109). |

---

## 4. Non-goals (explicitly out of scope)

These are **not** required and must not be used as arguments to increase complexity in 0.x.

| ID | Non-goal |
|---|---|
| NG-01 | Deep packet inspection, file carving, malware/AV signatures, YARA, or a signature engine **inside RustIPS**. A separate Snort fork is deferred design work, not a mainline exception (§19). |
| NG-02 | Full stream reassembly or protocol normalization across arbitrary protocols. |
| NG-03 | TLS decryption or TLS fingerprint analysis. |
| NG-04 | Suricata rule-set compatibility or importing `repos/suricata/rules/*`. Snort 3 rule support is deferred to the fork (§19). |
| NG-05 | Acting as a firewall, router, NAT device, or VPN endpoint. |
| NG-06 | Multi-sensor management, distributed correlation, HA clustering. |
| NG-07 | Windows/macOS support. Linux only. |
| NG-08 | Protecting the host from an attacker who already has local/root access. |
| NG-09 | Outbound/DLP/egress monitoring. Scope is inbound (and locally terminated) traffic. |
| NG-10 | Full Application-layer inspection (bodies, uploads, JS, WebSocket frames). |
| NG-11 | Failure-closed/quarantine mode (drop new inbound traffic when RustIPS is unhealthy). Explicitly rejected: an outage must never remove reachability. See §7.5. |
| NG-12 | Re-implementing Snort or bundling a signature engine in mainline RustIPS. Any signature support arrives only in the fork described in §19. |
| NG-13 | Rule authoring as a first-class product feature; local rules are supported as files, not through a visual IDE. |

**Note on NG-01/NG-04 vs HTTP scanning:** detecting "HTTP scans" requires reading the HTTP request
line and headers (method, path, status code). That is a *bounded* L7 parse (≤ 2 KB of payload,
no bodies, no reassembly of multi-request streams beyond a per-connection parser) and is in scope.
It is not the same thing as a signature engine, and this boundary should be stated in the README so
expectations are set correctly.

---

## 5. Deployment model and assumptions

| ID | Requirement |
|---|---|
| DM-01 | RustIPS runs **on** the protected host (not inline on a separate sensor), inspecting the traffic of one or more configured interfaces. **[ASSUMPTION]** |
| DM-02 | **[CONFIRMED]** The host does not forward traffic and will not act as a gateway. RustIPS protects only the host it runs on; enforcement is installed only in the `input` hook. The `forward` hook is explicitly out of scope. |
| DM-03 | The service runs as root or with `CAP_NET_RAW` + `CAP_NET_ADMIN`; no other elevated privileges. PAM authentication requires the privileged helper described in FR-182f. |
| DM-04 | Target platform: Debian 13 (trixie) x86_64, systemd, nftables. Other distributions are best-effort only in 0.x. |
| DM-05 | The host is assumed to have a working NTP-synchronised clock; all stored times are UTC. |
| DM-06 | IPv4 **and** IPv6 are both in scope. Any feature that works for one must have defined behaviour for the other. |
| DM-07 | **[CONFIRMED]** Failure policy is **fail-open for new decisions, fail-static for enforcement**: during an outage no new block/unblock/escalation occurs, and every block already in nftables stays. Expiry/removal is a daemon responsibility and therefore pauses during the outage. See §7.5. |
| DM-08 | If the host is behind NAT, all external sources appear as the NAT address; RustIPS does not attempt to defeat that. |
| DM-09 | **[CONFIRMED]** RustIPS consumes the complete systemd journal from the local host **and** any configured file-based logs (Q16). Remote syslog ingestion from other hosts remains out of scope for 0.x. |
| DM-10 | **[CONFIRMED]** Blocking is always a full source-IP block (all traffic from that address). Port- or protocol-scoped blocking is not required. |
| DM-11 | **[CONFIRMED]** Snort is **out of scope for mainline 0.x**. A separate fork may add Snort as the network detection engine after RustIPS is fully working and only if built-in coverage misses the 97% gate (§19). Mainline shipping, installation, and support never depend on Snort. |
| DM-12 | **[CONFIRMED]** Distribution is the **single binary**. No `.deb`, tarball, container, or external installer is required in 0.x. First-run state is determined by the presence of `/etc/rustips/config.toml`; the binary creates the rest of the layout (FR-217…219d). |

---

## 6. Functional requirements

### 6.1 Packet acquisition and data plane

| ID | Pri | Requirement |
|---|---|---|
| FR-100 | MUST | Capture packets from one or more configured interfaces with a minimal BPF filter (IP, TCP, UDP, ICMP/ICMPv6 only) and a short snap length; payload beyond the HTTP parse limit is not copied to userland. |
| FR-101 | MUST | Support promiscuous and non-promiscuous modes; default non-promiscuous for a host sensor. |
| FR-102 | MUST | Report capture statistics (received, dropped, filtered) and expose them in the UI and metrics. Dropped packets must be surfaced, never silently ignored. |
| FR-103 | MUST | Ignore loopback and the management interface by default, with explicit opt-in. |
| FR-104 | SHOULD | Support multi-queue capture (RSS/fanout) so detection scales with cores without changing detection semantics. |
| FR-105 | MUST | Never send traffic, never modify packets in flight, and never act as a proxy. Enforcement is via the host firewall only. |
| FR-106 | MUST | Operate correctly on fragmented traffic: either reassemble minimal IP fragments for header inspection or explicitly ignore and count them. Silent partial parsing is not acceptable. |

### 6.2 Detection engine

The engine consumes a stream of decoded packets and produces **detection events**. A detection
event is `(detector_id, source_ip, destination, protocol, count, window, first_seen, last_seen,
metadata)`.

| ID | Pri | Requirement |
|---|---|---|
| FR-110 | MUST | Maintain per-source state in a bounded, evictable structure (LRU/TTL) so that a spoofed-source flood cannot exhaust memory. Define the maximum tracked sources and the eviction policy. |
| FR-111 | MUST | Support vertical (many destinations ports, one host) and horizontal (one port, many hosts) scan detection. |
| FR-112 | MUST | Distinguish "new connection attempts" from established/return traffic so normal request/response traffic is never counted as a scan. |
| FR-113 | MUST | Apply thresholds as *rate over a sliding window*, configurable per detector, with sane defaults. |
| FR-114 | MUST | Emit at most one event per `(detector, source)` per cooldown period to prevent event floods, while still counting subsequent activity for escalation. |
| FR-115 | MUST | Tag each event with the detector, matched rule(s), and enough context for an admin to verify the decision (ports, paths, counts, window, geo, ASN). |
| FR-116 | MUST | Support a **monitor-only (observe) mode** where detections are recorded but nothing is blocked. This must be the default for a freshly installed system. |
| FR-117 | SHOULD | Support bounded HTTP request-line/header parsing (≤ 2 KB) for HTTP-based detectors, with a hard cap on parser state per connection. |
| FR-118 | MUST | **[CONFIRMED]** Detectors must not use GeoIP/ASN as an input. GeoIP and ASN are disposition-only enrichment (§6.3). A detection must stand on its own before geography is considered. |
| FR-119 | MUST | Correlate packet- and log-derived detections for the same source: deduplicate within a cooldown so one attack produces one block, while preserving both sources as evidence on the block record. |

#### 6.2.1 Detection catalog (initial scope)

This is the concrete "top 15–20" list. Thresholds are starting defaults and must be tunable.
Phases refer to §14.2. Rows marked "logs" depend on §6.2.2.

| ID | Detection | Data source | Default signal | Default action | Phase |
|---|---|---|---|---|---|
| DET-01 | TCP SYN vertical port scan | packets | ≥ 20 unique dst ports / 10 s from one source | block (ladder) | 0.1 |
| DET-02 | TCP SYN horizontal scan / host sweep | packets | same dst port to ≥ 20 dst hosts / 10 s | block (ladder) | 0.1 |
| DET-03 | TCP stealth scan (NULL, FIN, XMAS, invalid flag combos) | packets | ≥ 3 malformed/flag-anomalous packets / 10 s | block longer (ladder +1) | 0.1 |
| DET-04 | TCP ACK scan / unsolicited ACK | packets | ≥ 10 ACKs with no matching session / 10 s | block (ladder) | 0.1 |
| DET-05 | UDP port scan | packets | ≥ 20 unique dst ports / 10 s (or ICMP port-unreachable burst) | block (ladder) | 0.1 |
| DET-06 | ICMP/ICMPv6 host sweep or ping flood | packets | ≥ 20 destinations or ≥ 50 echo req/s | rate-limit + block on repeat | 0.1 |
| DET-07 | SYN flood / half-open exhaustion | packets | ≥ 200 SYNs/s with ≥ 80% unanswered handshakes | block + alert | 0.1 |
| DET-08 | Connection-rate abuse | packets | new connections/s per source above threshold | rate-limit + block on repeat | 0.2 |
| DET-09 | Hit on closed/unused ("tarpit") port | packets | ≥ 1 connection to a port declared unused | block immediately | 0.2 |
| DET-10 | SSH connection-rate brute-force proxy | packets | ≥ 10 new conns to 22 / 60 s from one source | block (ladder) | 0.2 |
| DET-11 | HTTP path scan (404/403 burst) | HTTP parse | ≥ 15 × 404/403 or ≥ 20 unique paths / 30 s | block (ladder) | 0.3.2 |
| DET-12 | HTTP known-bad path probe (`.env`, `wp-login`, `phpmyadmin`, `cgi-bin`, …) | HTTP parse | ≥ 1 match from default list | block immediately | 0.3.2 |
| DET-13 | HTTP auth brute force | HTTP parse | ≥ 10 × 401/403 on login-ish paths / 60 s | block (ladder) | 0.3.2 |
| DET-14 | HTTP method/request anomaly (TRACE, arbitrary methods, malformed request line, suspicious Host) | HTTP parse | ≥ 3 / 60 s | block (ladder) | 0.3.2 |
| DET-15 | HTTP request flood / scraper burst | HTTP parse | ≥ 100 req / 10 s from one source | rate-limit, then block | 0.3.2 |
| DET-16 | SSH authentication failures | logs | ≥ 5 failures / 10 min from one source | block (ladder) | 0.3 |
| DET-17 | SSH login success after failures | logs | 1 event | alert only, never auto-block | 0.3 |
| DET-18 | Repeat offender (strike escalation) | internal history | strike count increments | escalate ladder | 0.1 |
| DET-19 | GeoIP/ASN country attribute | *not a detector* | — | available to disposition rules only (§6.3) | 0.3.2 |
| DET-20 | Slow / low-and-slow distributed scan | packets + correlation | long-window (≥ 10 min) port diversity | alert, optional block | 0.3.3 |
| DET-21 | PAM/system authentication failure burst | logs | ≥ 5 failures / 10 min from one source, any service | block (ladder) | 0.3 |
| DET-22 | `sudo` denial / repeated wrong password | logs | ≥ 3 events / 10 min for one user+source | alert; block source on repeat | 0.3 |
| DET-23 | HTTP access-log scan (parity with DET-11) | logs | same thresholds as DET-11, from nginx/apache access logs | block (ladder) | 0.3 |
| DET-24 | Security-relevant system change (nftables ruleset change, RustIPS service stopped, audit/journald disabled) | logs | 1 event | alert only; optional block for the initiating source | 0.3 |
| DET-25 | Account/privilege modification (`useradd`, `usermod`, `groupadd`, sudoers change, new `authorized_keys`) | logs | 1 event | alert only, never auto-block | 0.3 |

**DET-16/17 note:** **[CONFIRMED]** SSH authentication happens *inside* an encrypted channel after
key exchange, so failed passwords are never visible on the wire. SSH brute force is detected from
the system journal (§6.2.2), with DET-10 kept as a network-side proxy that can act before logs are
parsed.

#### 6.2.2 Host log ingestion (journald + files)

**[CONFIRMED]** The owner requires all system logs to be streamed into RustIPS, from the journal
**and** from files (Q16), because services such as nginx or apache commonly write to files rather
than to journald. Log ingestion is a first-class input, not an SSH-only special case, and it must be
held to the same resource and reliability standards as the packet path.

There are two checkpoint models, and they must share one normalised event pipeline:
**journal cursor** for the systemd journal, and **file identity + byte offset** for tailed files.

| ID | Pri | Requirement |
|---|---|---|
| FR-300 | MUST | Ingest **all** systemd journal entries by default (all units, all priorities, all facilities), with an include/exclude configuration for units and identifiers. |
| FR-301 | MUST | Access the journal through a supported interface (libsystemd `sd-journal`, preferred, or a supervised `journalctl -f -o json` stream). Document the required privilege: root or membership in `systemd-journal`. |
| FR-302 | MUST | Checkpoint by journal cursor (`__CURSOR`). On restart, resume exactly after the last processed entry; on first start, backfill a configurable window (default 15 min). Never duplicate or lose entries across restarts. |
| FR-303 | MUST | Handle late/clock-skewed entries, `journalctl` gaps, and journal vacuuming without stalling; report a cursor gap in the UI when continuity is lost. |
| FR-304 | MUST | Normalise entries from every origin into one event shape: timestamp, origin (journal/file), source name, unit/identifier, priority, host, pid, user, source IP (when derivable), action/outcome, and a bounded message template. Raw messages are stored separately (FR-306) under a strict cap. |
| FR-305 | MUST | Implement a parser registry keyed by journal identifier and by file format; at minimum: `sshd`, `pam_unix`/PAM, `sudo`, `systemd-logind`, kernel (netfilter/audit/OOM), `cron`, `dovecot`/`postfix`, nginx/apache access+error, RFC 5424/3164 syslog, and JSON-lines. Unparsed input is counted and sampled per source, never silently discarded. |
| FR-306 | MUST | Bound raw-log storage: default 7 days or 128 MB, whichever is hit first, oldest-first pruning, with the drop count displayed. Parsed detections live in `detections` under their own retention (§8). |
| FR-307 | MUST | Rate-limit ingestion per parser and globally (default 2,000 events/s per parser, 10,000 events/s total); excess is dropped with counters, and a sustained breach raises an operational alert. |
| FR-308 | MUST | Treat every log field as untrusted input: fixed-size parsing, linear-time regexes only (no backtracking blow-ups), no format-string interpolation, no shell execution, and UI rendering that cannot inject HTML. |
| FR-309 | MUST | Log-derived detections must enter the same detection → disposition → enforcement pipeline as packet detections (FR-119 deduplication applies). No side-channel blocking. |
| FR-310 | MUST | Record provenance for each log-derived detection: journal cursor, identifier, timestamp, and the matched template, so an admin can verify the evidence. |
| FR-311 | MUST | Failure isolation: if journal access fails, parsing panics in a worker, or the journal disappears, packet capture and existing enforcement must keep running. Ingestion restarts with backoff and reports degraded health. |
| FR-312 | MUST | Secret hygiene: never store full command lines or environment dumps by default; apply configurable redaction patterns; truncate messages (default 1 KB) before storage. |
| FR-313 | MUST | Provide a Logs view in the UI: filter by origin (journal/file), source/file, unit, identifier, priority, user, source IP, parser, and time; show parse status, per-file state (following/rotated/missing/denied), and a link to the resulting detection. |
| FR-314 | MUST | Configurable: ingest on/off, journal include/exclude units, file sources (path/glob, format, position), enabled parsers, backfill window, raw retention/cap, rate limits — all editable in the UI and audited. |
| FR-315 | MUST | Document the privacy implication: journals contain usernames, paths, IPs, and sometimes secrets; default retention is deliberately short. |
| FR-316 | SHOULD | `rustips logs test --since 10m` dry-run mode that shows what each parser extracted without writing to the DB, for rule/parser development. |
| FR-317 | SHOULD | Detect and report if another entity is consuming the journal at a rate that indicates log flooding (helps identify a compromised service before disk fills). |
| FR-318 | MUST | Prevent self-ingestion feedback loops: RustIPS's own log identifier is excluded by default, and a detection must not be able to generate a log line that creates another detection (no unbounded amplification). PAM's own journal entries are still ingested, so UI brute force is visible. |

##### File sources (FR-319…FR-335)

| ID | Pri | Requirement |
|---|---|---|
| FR-319 | MUST | Support a configurable list of file sources: path or glob, parser/format, optional label, enabled flag, and initial position (start / end / last N bytes). Default initial position is **end**, so installing RustIPS does not re-scan a year of history. |
| FR-320 | MUST | Checkpoint per file **identity**, not per path: `(device, inode)` plus byte offset and the last complete line. Path-only checkpoints break on rotation and inode reuse. |
| FR-321 | MUST | Handle rotation without loss or duplication: reopen on rename+create, on `copytruncate` (detect size < offset and resume from 0 after recording a gap), on unlink, on inode reuse, and on a file appearing later (glob watch). |
| FR-322 | MUST | Never emit a partial line: buffer until newline, cap the partial buffer (default 64 KB) and emit a truncated record with a flag instead of growing without bound. |
| FR-323 | MUST | Support multi-line records for known formats (e.g. Java/Python stack traces): bounded continuation-line joining (default max 8 KB / 32 lines) with a configurable continuation pattern; never join unbounded input. |
| FR-324 | MUST | Discover new files matching a glob and stop following files that disappear; report per-file state (following, rotated, missing, permission denied, unparsable) in the UI. |
| FR-325 | MUST | Support at minimum these formats: nginx combined access, nginx error, apache combined access, apache error, RFC 5424/3164-style syslog lines, and JSON-lines. Unknown formats fall back to the generic parser and are counted as unparsed. |
| FR-326 | MUST | Handle encoding defensively: invalid UTF-8 is replaced, NUL bytes and control characters are escaped, and CRLF is normalised. Line length is capped (default 8 KB) before parsing. |
| FR-327 | MUST | Per-file and global rate caps (same limits as FR-307), plus a per-file "read at most N MB/s" budget so one runaway file cannot monopolise ingestion. |
| FR-328 | MUST | Poll with a cheap stat-based watcher (default 1 s, configurable) or inotify; correctness must not depend on inotify (it can overflow and is unreliable over NFS). |
| FR-329 | MUST | Skip compressed and already-rotated artefacts (`.gz`, `.xz`, `.zst`, `.1`, `.old`) by default; following compressed files is out of scope. |
| FR-330 | MUST | Do not follow files on network filesystems by default (NFS/CIFS semantics break inode/offset tracking); require an explicit override with a warning. |
| FR-331 | MUST | Document the privilege requirement: privileged log files need the daemon to run as root or as a member of the relevant group; a permission error is surfaced per file, not silently ignored. |
| FR-332 | MUST | Deduplicate the same logical line arriving from two sources (e.g. a service that logs to both file and journal) within a short window, keyed on `(source, timestamp, template, field hash)`, so one event does not produce two detections. |
| FR-333 | MUST | Custom line formats, if supported, use a linear-time regex engine with length caps and no backtracking blow-ups; a user-supplied pattern is untrusted input (FR-308). |
| FR-334 | SHOULD | `rustips logs test --file <path> --format <fmt>` to preview parsing of an existing file without ingesting it. |
| FR-335 | SHOULD | Report per-file bytes read, lines parsed, parse failures, rotation count, and current lag (bytes behind the end) so a stalled or misconfigured tail is obvious. |

### 6.3 Disposition engine (rules)

The disposition engine receives a detection event plus enrichment (GeoIP, ASN, strike history,
current block state, time) and decides an action.

| ID | Pri | Requirement |
|---|---|---|
| FR-120 | MUST | Rules are data, not code: loaded from a file and editable through the UI, stored in the database with a revision history. |
| FR-121 | MUST | Rule evaluation is deterministic and priority-ordered; ties break on rule ID. Document whether rules are first-match or accumulate — see FR-123. |
| FR-122 | MUST | Every rule match records which rule ID produced the action, on the block record and in the audit log. |
| FR-123 | MUST | Multiple matching rules combine by severity: the longest block and the most severe action win. |
| FR-124 | MUST | Actions: `alert`, `block_temp(duration)`, `block_permanent`, `escalate`, `allow` (whitelist override), `tag`. `tarpit` is deferred. |
| FR-125 | MUST | Support a rule `dry_run` flag and a global dry-run/observe mode; a dry-run rule logs "would block" without enforcing. |
| FR-126 | MUST | Validate rules on save, reject invalid ones with a precise error, and never leave the system with zero valid rules loaded (fall back to last-good rule set). |
| FR-127 | SHOULD | Support importing/exporting the rule set as a single YAML/JSON document for backup and version control. |
| FR-128 | MUST | Support a default rule set shipped with the binary and applied on first install. |

#### 6.3.1 Rule match attributes (minimum set)

- `detector`: detector ID(s) and/or severity.
- `source`: IP, CIDR (v4 + v6), geo country list/invert, ASN list, "not in allowlist".
- `destination`: port(s), port range, protocol.
- `event`: count ≥ N, unique ports ≥ N, path matches glob/regex-lite, status code.
- `history`: strike count ≥ N, currently blocked (bool), last seen within duration.
- `time`: optional day/time window.
- `tags`: free-form labels from detectors.

#### 6.3.2 Rule action attributes

- `action` (see FR-124), `duration`, `escalate_ladder`, `alert_channels`, `reason`/`description`,
  `severity`, `dry_run`, `enabled`, `priority`.

#### 6.3.3 Escalation ladder

| ID | Pri | Requirement |
|---|---|---|
| FR-130 | MUST | Maintain a per-source strike record (source, first strike, last strike, count, reasons). Strikes are keyed by IP and are **global across detectors** by default. |
| FR-131 | MUST | Default ladder: 1st → 1 h, 2nd → 24 h, 3rd → 48 h, 4th → 7 d, 5th → permanent. The ladder is configurable. |
| FR-132 | MUST | Support per-rule ladder overrides, e.g. geo-deny rules may use 24 h → 48 h → permanent as in the draft. |
| FR-133 | MUST | Support strike decay: a source that stays clean for a configurable period (default 90 days) loses one strike; decay is configurable and can be disabled. |
| FR-134 | MUST | A re-detection while already blocked extends/upgrades the block rather than creating a duplicate; extension is idempotent. |
| FR-135 | MUST | Administrator unblocking has a configurable effect on strikes: `keep` (default), `reset`, or `keep-but-decay`. |
| FR-136 | SHOULD | A permanent block requires explicit policy (rule-set default) and is always listed and reversible in the UI. |
| FR-137 | MUST | **[CONFIRMED]** GeoIP/ASN data is available **only** to the disposition engine. No detector may consume it, and a geo-matched source with no prior detection is never blocked. |
| FR-138 | MUST | Country-based actions are configured per country (or country group) by the administrator as ordinary disposition rules, e.g. "if detected and country = CN → block 24 h" or "→ block permanent". No country rule is enabled by default. |
| FR-139 | MUST | A geo rule applies on top of a real detection and participates in the normal ladder, deduplication, allowlist, and audit rules; it may lengthen or shorten a block, never fabricate one. |

### 6.4 Enforcement (blocking)

| ID | Pri | Requirement |
|---|---|---|
| FR-140 | MUST | **[CONFIRMED]** Enforce via **nftables only**, in the `input` hook (DM-02). No iptables or ipset backend is implemented. Use dedicated RustIPS-owned tables/sets, never rewrite another tool's rules. Do not shell out per packet; batch updates. nftables is derived state; the database is authoritative. |
| FR-141 | MUST | **[CONFIRMED]** Every block is a full source-IP block covering all traffic from that address. Port/protocol-scoped blocking is not implemented; the offending port/protocol is still recorded on the block as evidence. |
| FR-142 | MUST | **[CONFIRMED]** Temporary blocks have **no kernel-side timeout**. They remain in nftables until the daemon removes them, so an outage cannot lift a block. Expiry is enforced by a daemon scheduler at `expires_at` (FR-142a). |
| FR-142a | MUST | A monotonic-time scheduler removes each temporary block at its `expires_at` while the daemon is running. Permanent blocks are removed only by an explicit action. |
| FR-142b | MUST | On startup, prune blocks whose `expires_at` passed during the outage, apply blocks that were recorded but not enforced, and record the outage window and the number of overdue blocks in the audit log. |
| FR-142c | SHOULD | Optional safety cap (`block_max_overstay`, default disabled, recommended 7 d) that bounds how long a temporary block may outlive its expiry if the daemon never returns. Disabled by default to honour the chosen policy; enabling it requires a warning because it re-introduces daemon-independent removal. |
| FR-143 | MUST | On startup, reconcile nftables with the database: re-apply unexpired blocks (including after a table flush or reboot), remove orphans and overdue entries, and log every reconciliation change. Reconciliation must touch only RustIPS-owned tables/sets. |
| FR-144 | MUST | Blocks survive a clean shutdown and `systemctl stop` (no removal on stop); they are removed only by expiry, manual action, the optional safety cap (FR-142c), or `rustips flush`. Uninstall must run `flush` and document that normal removal is not automatic. |
| FR-145 | MUST | Never block: loopback ranges, link-local, the host's own addresses, configured management sources, and allowlisted hosts/networks. |
| FR-146 | MUST | Never block the administrator's *current* session: established/related connections are exempt, and a rule that would match the admin's source IP requires explicit confirmation. |
| FR-147 | MUST | Handle IPv4 and IPv6 blocks with separate sets and correct prefix handling. |
| FR-148 | MUST | Emit a block/unblock audit event for every change, including automatic ones, with the triggering rule and detection. |
| FR-149 | SHOULD | Support a manual block with a free-text reason and optional expiry. |

### 6.5 Allowlist (whitelist)

| ID | Pri | Requirement |
|---|---|---|
| FR-150 | MUST | Allowlist entries: single IP, CIDR (v4/v6), with optional label and expiry. |
| FR-151 | MUST | An allowlisted source is exempt from **blocking**. Whether it is also exempt from **detection** is configurable; default is "detect but never block" so noise is still visible. |
| FR-152 | MUST | Allowlist has higher precedence than every rule, including geo-deny and permanent blocks. |
| FR-153 | MUST | Adding an allowlist entry does not automatically unblock an existing block; offer a "unblock now" checkbox in the UI (default off). |
| FR-154 | MUST | Prevent self-lockout: RFC1918/link-local/loopback and the host's own IPs are implicitly allowlisted and cannot be removed without an explicit override. |
| FR-155 | SHOULD | Warn when an allowlist entry is broader than /16 (v4) or /48 (v6) and require confirmation. |

### 6.6 GeoIP enrichment (disposition-only)

GeoIP is an enrichment input for the disposition engine (FR-137). It is never a detection source.

| ID | Pri | Requirement |
|---|---|---|
| FR-160 | MUST | **[CONFIRMED]** Use the `user-country` database from `repos/ip-location-db/` (PDDL licensed, updated daily). No MaxMind/GeoLite licence dependency. |
| FR-161 | MUST | Ship as a compact, memory-mappable format. Either use the provided MMDB assets via a read-only mmap, or build a sorted binary range index at download time. Do **not** load the CSV into memory as strings. |
| FR-162 | MUST | Memory budget for geo data: ≤ 25 MB RSS for IPv4+IPv6 combined. Reference: 301,307 IPv4 ranges + 292,817 IPv6 ranges; a compact `(start, end/prefix, cc)` index is ≈ 3 MB (v4) + ≈ 10 MB (v6). |
| FR-163 | MUST | Check for updates on a configurable interval (default 24 h; the draft's 1 h is allowed but not the default). Use HTTP conditional requests (`ETag`/`Last-Modified`) and a checksum, not a full file download every hour. |
| FR-164 | MUST | Download → verify SHA-256 → validate parse → atomic swap. Never replace a working database with a failed/corrupt download; keep the previous generation for rollback. |
| FR-165 | MUST | Update hot-swap with **zero blocking downtime** and no dropped detections; lookups during swap must remain consistent. |
| FR-166 | MUST | Record last successful update, current database generation/hash, next scheduled check, and last error; display in the UI. |
| FR-167 | MUST | Work fully offline: if a database is present, no network access is required. If absent, geo rules are disabled with a clear warning (not a crash). |
| FR-168 | SHOULD | Expose a manual "check now" / "upload database file" action in the UI for air-gapped hosts. |
| FR-169 | SHOULD | Optional ASN enrichment from the same project (`origin-asn`, daily, PDDL) for ASN-based rules. |

### 6.7 Persistence

| ID | Pri | Requirement |
|---|---|---|
| FR-170 | MUST | Store detections, blocks, strikes, config revisions, allowlist, geo-update history, log events (raw + parsed, journal and files), and admin audit events in a single embedded database (SQLite assumed). |
| FR-171 | MUST | Use WAL mode and survive `SIGKILL` / power loss without corruption; on corruption, start in a safe degraded mode and report it. |
| FR-172 | MUST | Define retention per table with configurable limits (defaults proposed in §9) and a pruning job; unbounded growth is a defect. |
| FR-173 | MUST | Aggregate traffic statistics into time buckets (default 1 min) for the dashboard, with their own retention. |
| FR-174 | SHOULD | Provide `rustips export` / `rustips import` for blocks, allowlist, and rule sets, for migration and backup. |
| FR-175 | SHOULD | Support a configurable database path, with a documented backup procedure (or a built-in `rustips backup`). |

### 6.8 Web UI

| ID | Pri | Requirement |
|---|---|---|
| FR-180 | MUST | Bind to `127.0.0.1:10707` by default. Binding to any other address must be an explicit, confirmed configuration change with a warning. |
| FR-181 | MUST | Serve an embedded UI from the single binary (no Node toolchain or asset directory required at runtime). |
| FR-182 | MUST | **[CONFIRMED]** Authenticate administrators against the host's **PAM** stack through a dedicated service file `/etc/pam.d/rustips`. There is no second password store and no local user database; the username is the system account name. |
| FR-182a | MUST | Use a PAM conversation callback: never echo, log, hash, or retain the password, and zeroise the input buffer after the call. Fail closed on any PAM error. |
| FR-182b | MUST | Enforce PAM account controls by calling `pam_acct_mgmt` (expired/locked accounts, password aging) — authentication alone is not sufficient. |
| FR-182c | MUST | **[CONFIRMED]** Authorise by group membership after successful authentication: only members of a configured group (default `rustips-admin`) may use the UI/API. A valid system password without the group is a denial, and is audited as such. There is **no per-user allowlist and no second authorisation layer**: group membership is the only grant, and every member has full admin authority (Q13). |
| FR-182d | MUST | The login page and audit log must distinguish "bad credentials", "account locked/expired", and "authenticated but not authorised" without leaking which accounts exist to unauthenticated users. |
| FR-182e | MUST | **Break-glass access**: if PAM or its backing store (SSSD/LDAP/`sssd` outage, NSS failure) is unavailable, provide one documented recovery path — a root-only one-time bootstrap token file (mode 0600, `rustips auth breakglass`) and/or a local fallback account definition. Never fall back to unauthenticated access, and never silently ignore a PAM outage. |
| FR-182f | MUST | If the daemon drops privileges, PAM calls go through a minimal privileged helper with a narrow IPC interface (length-prefixed messages, no shell, no arbitrary command execution). PAM in-process is acceptable only if the process remains privileged. |
| FR-182g | MUST | Re-validate the session's backing account periodically (default every 5 min) and on each privileged action, so disabling or locking a system account invalidates existing sessions. |
| FR-182h | MUST | Sessions use an HttpOnly, SameSite=Strict cookie with CSRF tokens on all state-changing requests, absolute and idle timeouts, explicit logout, and rotation on login. |
| FR-183 | MUST | Rate-limit and lock out repeated failed logins (per username and per source) in addition to any PAM/`pam_faillock` policy; audit every attempt with username, source, and result. |
| FR-183a | SHOULD | Provide a "users with access" view derived from the configured group, so the admin can see who can log in without querying the OS. |
| FR-184 | MUST | Provide these views: |
| | | (a) **Dashboard** — current pps/bandwidth, detections and blocks per minute, top sources, top targeted ports, current block count, dropped-packet health, geo-db status. |
| | | (b) **Detections** — filterable, paginated event list with drill-down (ports, paths, rule, geo/ASN, evidence source: packets or logs). |
| | | (c) **Active blocks** — source, reason, rule, start, expiry/remaining, hit counts, unblock action. |
| | | (d) **Block history** — searchable past blocks with outcome and duration. |
| | | (e) **Strikes / repeat offenders** — source, strike count, first/last seen, next penalty. |
| | | (f) **Allowlist** — CRUD, labels, expiry, import/export. |
| | | (g) **Rules** — CRUD, ordering, enable/disable, dry-run, validation, diff/history, import/export. |
| | | (h) **Settings** — bind address/port, capture interfaces, detection thresholds, escalation ladder and decay, retention, geo update interval/source, webhook URL and alert rules, log ingestion (journal units, file sources/parsers, retention), PAM group, failure policy. |
| | | (i) **Audit log** — every config change, every login attempt, and every block/unblock with actor (`system`, `admin:<username>`, or `api:<token>`). |
| | | (j) **Logs** — journal and file entries with parse status, per-file state, filters (origin, source/file, unit, identifier, priority, user, source IP, parser), and a link to any resulting detection. |
| FR-185 | MUST | Live views update at least every 2 s without a full page reload (SSE or polling is acceptable; WebSockets optional). |
| FR-186 | MUST | Changing bind address/port validates the new value, warns on non-loopback, applies via a controlled rebind or requires a restart, and reverts automatically if the new bind fails. |
| FR-187 | MUST | All UI text/API responses must be safe against injection; no raw HTML from stored fields. |
| FR-188 | SHOULD | Support dark/light theme and keyboard navigation; be usable on a tablet-width viewport (admins often use a tunnel + browser). |
| FR-189 | SHOULD | **[CONFIRMED]** Support **one authority level: admin**. There is no read-only role, viewer account, or reduced-permission token — RustIPS is an administrative tool, not a shared dashboard (Q22). A bearer token may be issued for monitoring/integration, but it carries full admin authority: created by a PAM-authenticated admin, stored hashed, revocable, every use audited, and it never bypasses authorisation checks. |
| FR-189a | MUST | Non-loopback binding requires a second confirmation, a clear warning, and (recommended) TLS or a tunnel; the UI must display a persistent banner while bound to a non-loopback address. |
| FR-190 | MAY | Provide a one-click `ssh -L 10707:127.0.0.1:10707` command snippet in Settings. |

### 6.9 Configuration

| ID | Pri | Requirement |
|---|---|---|
| FR-195 | MUST | Single primary config file (`/etc/rustips/config.toml`) with documented precedence: CLI flag > env var > database/UI value > config file > built-in default. |
| FR-196 | MUST | Live-editable settings are persisted to the database so they survive restarts, and are shown with their source (file/UI/default). |
| FR-197 | MUST | Validate the entire config on load and on change; on invalid config, refuse to start (or start read-only) with a precise error rather than guessing. |
| FR-198 | MUST | Config file permissions are 0600. No plaintext secret is ever written to logs or the database: UI credentials live in PAM, API tokens are stored hashed, and unused legacy password fields must not exist. |
| FR-199 | SHOULD | Support a `rustips config check` command and a documented "factory reset" that preserves the database unless `--purge` is given. |

### 6.10 Observability, logging, alerting

| ID | Pri | Requirement |
|---|---|---|
| FR-200 | MUST | Structured logs (JSON option) to stdout/journald, with configurable level; no secrets, no payload contents, no full URLs with query strings by default. |
| FR-201 | MUST | Log rotation-safe operation; if writing files, rotate and cap total size. |
| FR-202 | MUST | `/metrics`-style counters: packets seen/dropped, log entries ingested/dropped by origin and parser, files followed/lag/rotation count, detections by detector and source (packet/log), blocks active/total, geo-db age, DB size, auth failures, uptime. Protect or bind to loopback. |
| FR-203 | MUST | A health endpoint reporting readiness (capture running, journal cursor advancing, file sources not lagging, DB writable, geo db loaded, nftables access OK, PAM stack usable, failure policy in force). |
| FR-204 | SHOULD | Alert channel: a **generic outbound webhook** (JSON POST) and nothing else. SMTP, chat, push, and syslog are out of scope; document how to bridge the webhook to them. Alerts must be rate-limited and deduplicated. |
| FR-204a | MUST | Alert delivery is asynchronous and best-effort: bounded retries with backoff, a persisted queue, no blocking of detection, disposition, or enforcement, and delivery failures surfaced in health/metrics rather than retried forever. |
| FR-204b | SHOULD | Ship a documented, tested example that converts a webhook into e-mail (or chat) via a small external script/bridge, so an administrator who wants SMTP has a working starting point without RustIPS embedding an SMTP client. |
| FR-205 | SHOULD | Alert on operational failures (capture dropped > 1%, journal ingestion stalled or dropped > 1%, geo update failed, DB errors, nftables write failed, PAM unavailable), not only on attacks. |

### 6.11 CLI and operations

| ID | Pri | Requirement |
|---|---|---|
| FR-210 | MUST | Subcommands: `run` (default), `setup`, `check` (validate config/rules/permissions/PAM), `status`, `block`, `unblock`, `allow`, `allowlist` (list), `rules check`, `geo update`, `logs test`, `auth breakglass`, `auth test`, `export`, `import`, `flush`, `--version`. |
| FR-211 | MUST | Ship a `systemd` unit embedded in the binary and installed by `rustips setup --install-service`, with hardening (`NoNewPrivileges` where compatible, `ProtectSystem=strict`, `ReadWritePaths` for state, `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`, `SupplementaryGroups=systemd-journal` when not running as root). |
| FR-212 | MUST | Graceful shutdown on `SIGTERM`: flush pending DB writes, stop capture, leave blocks in place (FR-144). |
| FR-213 | MUST | Startup must be fast (target < 2 s to ready, excluding geo index load) and must not require network access. |
| FR-214 | SHOULD | `rustips diagnose` to dump effective config, privileges, interface state, nftables table state, journal-cursor state, PAM configuration, and geo-db status for support requests. |
| FR-215 | MUST | `rustips auth test --user <name>` exercises the PAM stack and reports which stage failed (auth, account, group) without requiring the UI. |
| FR-216 | MUST | `rustips auth breakglass` creates/renews the one-time bootstrap token with mode 0600 and a fixed short TTL (default 30 min), and prints it exactly once. |
| FR-217 | MUST | **First-run detection.** On start, decide state from configuration and state presence: config present and valid → normal start; config absent and no database in `/var/lib/rustips/` → setup mode, where `rustips run` refuses to start, prints the exact `rustips setup` command, and exits non-zero; config absent but a database exists → recovery mode (FR-218); config present but invalid → hard error (FR-219). Never infer "new install" from config absence alone. |
| FR-218 | MUST | If the config is missing but a state database exists, refuse to start and explain that existing state was found. Offer `rustips setup --recover` (regenerate a default config, keep the DB) and `--fresh` (only with explicit confirmation, archiving the old state first). An accidental `rm /etc/rustips/config.toml` must never initialise a new database over existing blocks and history. |
| FR-219 | MUST | A config that exists but is unreadable or invalid is a hard startup error with a precise path/line message; never silently fall back to defaults and never partially apply it. `rustips check` performs identical validation without touching capture. |
| FR-219a | MUST | `rustips setup` (root only) writes `/etc/rustips/config.toml` (0600, root-owned) with minimal safe defaults — bind `127.0.0.1:10707`, observe mode, journal and file ingestion enabled, geo enabled — creates `/var/lib/rustips/` (0700) and `/etc/rustips/` (0755), and exits without starting capture. It must refuse to overwrite an existing config unless `--force` is given. |
| FR-219b | MUST | `rustips setup --install-service` (root) writes `/etc/systemd/system/rustips.service`, runs `systemctl daemon-reload`, creates the `rustips-admin` group if missing, and installs `/etc/pam.d/rustips` **only if absent**. It never modifies an existing PAM file or unit: it shows a diff and requires `--force`. Every action is idempotent and audit-logged. |
| FR-219c | SHOULD | `rustips setup --non-interactive` accepts flags or config on stdin with the same validation and safety rules, and `--dry-run` prints every file it would write without writing it. |
| FR-219d | MUST | Setup never enables enforce mode and never starts capture. The first run is observe mode. After setup, print the bind URL, the SSH-tunnel command for remote access, how to add the first admin to `rustips-admin`, and the first `rustips check`/`status` commands. |


## 7. Non-functional requirements

### 7.1 Performance (measured on the lab VM, §14)

| ID | Pri | Requirement |
|---|---|---|
| NFR-100 | MUST | Sustain ≥ 100,000 pps of mixed TCP/UDP traffic with < 1% capture drop on a 2 vCPU VM. |
| NFR-101 | MUST | p99 detection-to-block latency < 100 ms for packet-based detectors. |
| NFR-102 | MUST | Idle CPU < 2% of one core; CPU at 100k pps < 25% of one modern core. |
| NFR-103 | MUST | Steady-state RSS < 150 MB with geo data loaded; idle RSS < 60 MB. |
| NFR-104 | MUST | Release binary < 100 MB after strip + LTO. Reference target 15–40 MB; exceeding 60 MB requires justification. |
| NFR-105 | MUST | Block/allowlist lookups are O(log n) or O(1); no linear scans in the packet path. |
| NFR-106 | MUST | Dashboard remains responsive (< 300 ms page load, < 1 s data query) with 30 days of retained events at 1M-event scale; if exceeded, aggregation/archival must kick in. |
| NFR-107 | SHOULD | A documented benchmark harness reproduces every number above (no hand-waved performance claims). |
| NFR-108 | MUST | **[CONFIRMED]** Default steady-state disk use ≤ **512 MB** in total (database, raw logs, geo generations, one backup set), measured on the lab VM; no table or file grows without a cap. |
| NFR-109 | MUST | Every background activity (geo download, aggregation, pruning, log parsing) must be able to idle at near-zero CPU; no polling loop may prevent the process from reaching the idle target (NFR-102). |

### 7.2 Reliability and safety

| ID | Pri | Requirement |
|---|---|---|
| NFR-110 | MUST | No crash on malformed/truncated/hostile packets or log lines; both parsers are fuzzed. |
| NFR-111 | MUST | Bounded queues everywhere: capture ring, journal reader, event channel, DB writer, alert sender. Overflow policy is explicit (drop oldest + count). |
| NFR-112 | MUST | Automatic recovery: capture and journal-ingestion failures restart with backoff and alert; nftables failure is retried and surfaced. |
| NFR-113 | MUST | Disk-full, read-only filesystem, and DB-busy conditions degrade gracefully (keep enforcing existing blocks, stop writing, alert). |
| NFR-114 | MUST | Do not block on disk I/O in the detection path; all persistence is asynchronous. |
| NFR-115 | MUST | Time-zone/DST changes must not shift or extend blocks; all expiry math is monotonic/UTC. |
| NFR-116 | MUST | **[CONFIRMED]** Enforce a **minimal default disk budget of 512 MB total**: DB 256 MB, raw logs 128 MB, geo generations ~80 MB, backup/headroom ~48 MB. Each cap is configurable; oldest-first pruning happens before the limit is reached, with a visible "approaching limit" warning. |
| NFR-117 | MUST | Log ingestion must not starve packet processing: separate worker(s) with independent bounded channels and a lower scheduling priority than the data plane. |
| NFR-118 | MUST | Disk-full or read-only filesystem: keep detection and enforcement working, stop non-essential writes, alert once, and resume automatically when space returns. Never corrupt the database or lose the active block set. |

### 7.3 Security of RustIPS itself

| ID | Pri | Requirement |
|---|---|---|
| NFR-120 | MUST | Least privilege: only the capabilities actually needed; drop the rest after setup where the kernel allows it. |
| NFR-121 | MUST | No remote listening sockets other than the UI and optional metrics, both loopback by default. |
| NFR-122 | MUST | All state-changing API/UI actions require auth + CSRF protection; parameterised DB access only. |
| NFR-123 | MUST | Dependencies are audited (`cargo-deny`, `cargo-audit`) in CI; no known-critical advisories at release. |
| NFR-124 | MUST | Release artefacts are checksummed and, ideally, signed. In 0.x the update path is **manual binary replacement** (no self-update), with automatic pre-migration backup of config and database, schema migration on first start, and a documented rollback to the previous binary. |
| NFR-125 | MUST | Outbound network egress limited to the configured geo/ASN update endpoint and configured alert endpoints. No telemetry. |
| NFR-126 | MUST | The UI must not be usable as an SSRF proxy or arbitrary file reader (host interfaces, DB paths, and uploads are validated). |
| NFR-127 | SHOULD | Optional TLS termination for the UI if an admin ever binds non-loopback, or a hard requirement to use the SSH tunnel. |
| NFR-128 | MUST | The PAM helper (FR-182f) must be the only component holding authentication privilege, must validate message length/type, must time out, and must never pass user-controlled data to a shell. |
| NFR-129 | MUST | Journal content is untrusted input: parsed fields are stored as data, never rendered as HTML, interpolated into rules, or used to build file paths or commands. |

### 7.4 Usability / operability

| ID | Pri | Requirement |
|---|---|---|
| NFR-130 | MUST | Install in ≤ 3 steps; document them in the README. |
| NFR-131 | MUST | Every default threshold and rule has an inline explanation of what it does and what breaks if it is changed. |
| NFR-132 | MUST | First-run experience: wizard covering interface, allowlist (with a "detect my current SSH source" helper), journal access check, PAM group check, observe mode, geo db download, then explicit "enable enforcement". |
| NFR-133 | MUST | No action in the UI may silently change enforcement behaviour; changes are confirmed and audited. |
| NFR-134 | MUST | The UI must show, permanently and unambiguously, whether enforcement is on, in observe mode, or degraded (block removal paused). |

### 7.5 Failure policy (decided)

**[CONFIRMED]** If RustIPS fails:

1. **No new disposition takes place.** No new blocks, no unblocking, no escalation, no block extension.
2. **Everything already committed to nftables stays in force.** Enforcement persists without the daemon.
3. **Expiry/removal pauses.** Because block removal is performed by the daemon, a temporary block can outlive its nominal expiry during the outage. This is accepted: the bias is toward staying blocked, and the overstay is corrected on recovery.

The decision has one mechanical consequence that must be respected in the implementation:
**do not put per-element timeouts on nftables blocks.** An nftables element timeout is enforced by
the kernel and would expire the block while the daemon is dead — exactly the behaviour that was
rejected. The database owns `expires_at`; the kernel holds state; the daemon is the only thing that
removes a block.

| Failure | Resulting behaviour |
|---|---|
| Daemon crashes / is stopped | No new decisions. All existing blocks stay, indefinitely. No expiry. Attack traffic still reaches *unblocked* services. |
| Host reboots | Blocks are gone with the kernel, unless restored. On startup the daemon rebuilds them from the DB (FR-143), so the blocked set is restored within seconds. |
| Daemon running, nftables write fails | Existing blocks stay; new dispositions are queued and retried with backoff; degradation is alerted. |
| DB unavailable | Cannot record new decisions; existing kernel blocks stay; enforcement continues unchanged; alert. |
| nftables table flushed by an operator | Detected by periodic drift check; the daemon re-applies the blocked set and logs it. |
| Geo DB missing / journal down / PAM down | Unrelated to existing blocks; those subsystems degrade independently (§6.2.2, §6.6, §6.8). |
| Invalid config | Refuse to start; blocks left as the kernel has them; alert. |

Operational obligations that follow from this choice:

- The service must come back quickly, because a crash suspends expiry. `Restart=always` with a
  short `RestartSec` (default 2 s) and a bounded start limit are part of the unit (FR-211).
- A block that outlives its expiry is visible: the UI shows "expired, removal pending", the
  degraded banner names the count and the outage start, and `rustips status` reports the same.
- If the service is stopped deliberately (`systemctl stop`) or uninstalled, blocks remain. This is
  intentional and must be documented (FR-144).
- Overstay is bounded only if the optional safety cap (FR-142c) is enabled. With it disabled, a
  temporary block can become permanent by accident if the daemon never returns.

| ID | Pri | Requirement |
|---|---|---|
| NFR-140 | MUST | Implement exactly the three-point policy above. There is no fail-closed/quarantine mode (NG-11). |
| NFR-141 | MUST | A failed health check stops new dispositions but must never remove, shorten, or expire an existing block. |
| NFR-142 | MUST | The blocked set is restored from the DB on every start, including after a reboot, and repaired if nftables has been flushed or edited out-of-band. |
| NFR-143 | MUST | Degraded operation is surfaced within one dashboard refresh: banner, `/metrics`, `rustips status`, audit entry, and the configured alert channel. |
| NFR-144 | MUST | The unit uses `Restart=always`, `RestartSec=2` (configurable), and a start limit that prevents a crash loop from masking a configuration error. |
| NFR-145 | MUST | Blocks past expiry are listed separately from active blocks, with the reason ("removal pending after outage"), and are removed as soon as the daemon recovers. |
| NFR-146 | MUST | The README states plainly: stopping RustIPS does not unblock anyone; only expiry, manual action, or `flush` does. |
| NFR-147 | MUST | After start, the full blocked set is restored within 10 s (configurable); exceeding it is a health failure and raises an alert. |

---

## 8. Data model (minimum tables)

| Table | Key fields | Retention default |
|---|---|---|
| `detections` | id, ts, detector, source_kind (packet/log), src_ip, dst_ip, dst_port, proto, count, window_s, metadata_json, rule_id, severity, evidence_ref | 30 days |
| `log_events` | id, cursor or (dev, inode, offset), origin (journal/file), source_name, ts, unit, identifier, priority, host, pid, uid/user, src_ip, parser, template_id, fields_json, parse_status, message (truncated) | 7 days or 128 MB |
| `log_checkpoints` | journal: last_cursor, last_ts, gaps; file: (dev, inode), path, offset, last_line_hash, rotated_count, last_error | n/a |
| `blocks` | id, src_ip, ip_version, reason, rule_id, detection_id, started_at, expires_at (NULL = permanent), state (active/expired_pending_removal/expired/manual_unblocked), enforced_by | keep 1 year |
| `strikes` | src_ip, count, first_seen, last_seen, last_reason, next_penalty | keep 1 year, decay job |
| `allowlist` | id, cidr, ip_version, label, created_at, expires_at, created_by | permanent |
| `rules` | id, priority, enabled, dry_run, match_json, action_json, reason, revision, created_at, updated_at | keep all revisions |
| `settings` | key, value_json, source, updated_at | n/a |
| `geo_updates` | ts, source_url, sha256, ranges_v4, ranges_v6, result, error | 90 days |
| `traffic_stats` | bucket_ts (1 min), pps, bps, conns, detections, blocks, log_events | 14 days raw, 1 year hourly rollup |
| `audit` | id, ts, actor (system/admin:<user>/api:<token>), action, target, detail_json | 1 year |

`fields_json` and `metadata_json` must be size-capped (e.g. 4 KB) so a single hostile request or
log line cannot bloat the DB. `message` is truncated to 1 KB (FR-312).

---

## 9. Default configuration (proposed)

| Setting | Default | Notes |
|---|---|---|
| Bind | `127.0.0.1:10707` | |
| Mode | `observe` | Must be explicitly switched to `enforce` |
| Auth | PAM via `/etc/pam.d/rustips`, group `rustips-admin` | no local password store; group-only, no roles (Q13/Q22) |
| Interfaces | auto-detect default route interface | loopback excluded |
| Escalation ladder | 1 h, 24 h, 48 h, 7 d, permanent | matches draft intent |
| Strike decay | 90 days, 1 strike | |
| Unblock effect on strikes | keep | |
| Block scope | full source IP | confirmed, no port scoping |
| Geo update interval | 24 h | hourly allowed but wasteful |
| Geo db | `user-country` | PDDL; daily; disposition-only (confirmed) |
| Geo rules | none enabled | admin opts in per country |
| Journal ingestion | enabled, all units + configured files | raw 7 days / 128 MB, 2k eps per parser |
| File sources | none by default; wizard suggests nginx/apache | start at end of file |
| Block expiry | no kernel timeout; DB-owned expiry (§7.5) | blocks survive daemon outage |
| Failure policy | fail-open for decisions, fail-static for blocks | §7.5 |
| Block overstay cap | disabled (`block_max_overstay`) | recommended 7 d if you want a bound |
| Service restart | `Restart=always`, `RestartSec=2` | keeps expiry pause short |
| Retention | per §8 | |
| Disk budget | 512 MB total (confirmed ceiling) | DB 256 MB, raw logs 128 MB, geo ~80 MB, headroom ~48 MB; all configurable |
| Allowlist defaults | loopback, RFC1918, link-local, host IPs | non-removable |
| Alert channels | none configured | generic webhook only; SMTP/chat are your own bridge |
| Setup state | `/etc/rustips/config.toml` presence | absent + no DB = first run; absent + DB = recovery, never re-init |
| Rule updates | geo only: daily `user-country` fetch, handled by RustIPS | no signature feed in 0.x (§19) |

---

## 10. External interfaces

| ID | Pri | Requirement |
|---|---|---|
| IF-10 | MUST | HTTP API under `/api/v1/` mirroring every UI capability; JSON; documented. Versioned; breaking changes require a new version. |
| IF-11 | MUST | Auth: session cookie for the UI, bearer token for API clients (token created in the UI, stored hashed). |
| IF-12 | MUST | `GET /api/v1/health` and `GET /metrics` (loopback) for integration with systemd/monitoring. |
| IF-13 | SHOULD | Geo update source configurable (URL template) so a mirror can be used. |
| IF-14 | SHOULD | Webhook payload schema documented and stable, including event type, source, rule, action, severity, timestamps. |

---

## 11. Architecture (proposed, non-binding)

The following is a suggestion to make the requirements concrete; the requirement set does not
mandate crate choices.

```
   ┌──────────────┐   ┌───────────────┐   ┌──────────────────┐   ┌──────────────┐
NIC│ capture      │──▶│ decode + flow │──▶│ detectors        │──▶│ disposition  │
───▶│ (AF_PACKET / │   │ state (LRU)   │   │ (windowed        │   │ rules +      │
   │  eBPF/XDP)   │   │               │   │  counters)       │   │ strikes      │
   └──────────────┘   └───────────────┘   └──────────────────┘   └──────┬───────┘
   ┌──────────────┐   ┌───────────────┐            ▲                    │ act
   │ journald     │──▶│ cursor/offset │────────────┘                    │
   │ + log files  │   │ reader+parsers│                                 │
   └──────────────┘   └───────────────┘   ┌──────────────┐   ┌──────────▼───────┐
                                          │ async writer │◀──│ nftables sets    │
                                          │ (SQLite WAL) │   │ (DB-owned expiry)│
                                          └──────┬───────┘   └──────────────────┘
                                                 │
                                    ┌────────────▼─────────────┐   ┌──────────────┐
                                    │ Axum web UI + API        │◀─▶│ PAM helper   │
                                    │ (embedded assets, SSE)   │   │ (privileged) │
                                    └──────────────────────────┘   └──────────────┘
```

Suggested crates: `axum` + `tokio` (UI/API), `tokio` tasks or dedicated threads for capture,
`etherparse`/`pnet` for decoding, `maxminddb` or a custom binary index for geo,
`rusqlite` (WAL) for storage, `arc-swap` for hot-swapped read-only data, `rust-embed` for assets,
`nftables` crate or a thin `nft`-JSON wrapper for enforcement, `libsystemd`/`sd-journal` bindings
(preferred) or a supervised `journalctl` child for logs, and a PAM binding (or a tiny privileged
helper) for authentication.

Three decisions worth making early:
1. **Enforcement layer.** nftables sets are the pragmatic choice: atomic batch updates, no
   per-packet userland work, and a readable ruleset. Expiry is daemon-owned by decision (§7.5), so
   blocks must be rebuilt from the DB at startup. Pure-XDP blocking is faster but far more complex
   to make dynamic and auditable; treat it as a later optimisation, not the 0.1 design.
2. **Capture API.** AF_PACKET with `PACKET_FANOUT` is sufficient for a single host and is much
   simpler than AF_XDP. Only move to XDP/TC if measurements show it is needed.
3. **PAM boundary.** Decide early whether the daemon stays privileged (in-process PAM) or drops
   privileges and uses a helper. Retrofitting a helper later touches auth, packaging, and systemd
   together.
4. **Log tailing.** Correctness comes from stat-polling and `(dev, inode, offset)` checkpoints;
   inotify is only a latency optimisation. One ingestion pipeline with two readers (journal, file)
   keeps the detection side unaware of the origin.

There is deliberately no external detection process in this architecture. The deferred Snort
variant adds one out-of-process reader to the same pipeline (§19); the mainline has a single
process, a single config, and no second daemon to install, monitor, or license.

---

## 12. Reference material usage

| ID | Requirement |
|---|---|
| REF-01 | `repos/suricata/` is a reference for rule-file shape, protocol parsing edge cases, and detector semantics — **not** a dependency, and not a source of rule compatibility requirements. |
| REF-02 | `repos/ip-location-db/` is the reference for geo data format, licensing, download URLs, and checksum locations. |
| REF-03 | **[CONFIRMED]** Suricata is a **semantics reference only**. No code may be copied, linked, or vendored: Suricata is GPLv2 and RustIPS is not. Study detector behaviour, rule-file shape, and protocol edge cases; record anything actually borrowed (data formats, constants, algorithms) in `NOTICE`/`THIRD_PARTY.md` with its license. |
| REF-04 | `repos/psad/` is a **semantics reference only** for danger levels, signature cataloguing, and "what an iptables-log-based detector can and cannot see". GPLv2: no code copying, no vendoring. Its `signatures` file (~200 approximate Snort rules) is a useful checklist of historical attack classes for the mainline detector catalog, not a rule source. |
| REF-05 | `repos/fwsnort/` is a **negative reference**: it demonstrates that translating Snort rules to a packet filter is inherently lossy (`pcre`, `flow`, session state, normalisation have no equivalent). It is cited in §19 to justify running Snort itself in the fork instead of translating rules. GPLv2, no code copying. |
| REF-06 | `repos/snort3/` is fork reference material for **alert output formats (`alert_json`), rule syntax, rule-option coverage**, and the semantics of `HOME_NET` and `flow`. Not used by mainline 0.x. The Snort 3 Community Ruleset is GPLv2 and needs no registration, but no rules are ever bundled with RustIPS (FR-433); the fork downloads them at runtime. Snort itself is an external dependency, not vendored. |

---

## 13. Testing and validation

### 13.1 Lab environment

| ID | Pri | Requirement |
|---|---|---|
| TEST-10 | MUST | Scripts to create, start, snapshot, and destroy a Debian 13 KVM guest on the dev host, non-interactive and idempotent. |
| TEST-11 | MUST | Guest provisioning via cloud-init/preseed: base packages (`nftables`, `nmap`, `hydra`, `gobuster`/`nikto`, `hping3`, `tcpdump`, `tcpreplay`, `jq`), plus a test PAM user in the `rustips-admin` group and one outside it. Disabled root login, SSH key only. |
| TEST-12 | MUST | A `snapshot`/`restore` workflow so any test starts from a known-clean state. |
| TEST-13 | MUST | Documentation of host prerequisites (KVM/libvirt, bridge/network mode, whether the VM is NATed or bridged — NAT affects source-IP realism). |
| TEST-14 | MUST | A deterministic log-generation harness: fixtures that inject known journal entries (sshd failures, PAM denials, sudo, nginx 404 bursts) and write known lines to test files, so log detectors are tested without waiting for real attacks. |

### 13.2 Test levels

| ID | Level | Requirement |
|---|---|---|
| TEST-20 | Unit | Every detector: threshold boundaries, window edges, LRU eviction, IPv4/IPv6 parity; every log parser against fixtures. |
| TEST-21 | Golden pcap | Recorded attack traffic per detector (nmap scan types, hydra SSH, gobuster path scan, hping3 flood) replayed with `tcpreplay`; assert exact detections and no false positives on a clean traffic capture. |
| TEST-22 | Integration | Full stack: capture → detection → rule → nftables set → block actually drops traffic; verify with a second client. Same for a log-only path (inject sshd failures → block appears). |
| TEST-23 | False-positive suite | Ordinary browsing, package updates, HTTP/2, large downloads, monitoring probes, administrative SSH sessions, legitimate `sudo` use, and normal `nginx` 404s must produce zero blocks. |
| TEST-24 | Performance | §7.1 numbers measured and recorded per release; regression threshold gates the release. Include a journal-flood run (10k events/s for 10 min) proving packet processing is unaffected. |
| TEST-25 | Chaos | `kill -9` mid-write, disk full, corrupt DB, network loss during geo download, nftables unavailable, journal vacuum/corruption, clock jump, interface down/up. |
| TEST-26 | Security | Fuzzing of packet/HTTP/log parsers; auth/CSRF tests; PAM bypass attempts; log-injection attempts (fake "Failed password" lines from an attacker-controlled service); dependency audit; attempt to make the UI read arbitrary files. |
| TEST-27 | Upgrade | Replace the binary in place (the 0.x upgrade path) and verify DB schema migration with an automatic backup, config compatibility, preserved blocks/strikes/rules/allowlist/journal cursor/PAM config, and rollback to the previous binary if migration fails. Also verify the config-missing-with-DB recovery path (FR-218) and that a failed migration never starts capturing. |
| TEST-28 | Authentication | PAM valid/invalid/locked/expired account; correct password but wrong group; PAM unavailable → break-glass path only; session invalidation after account lock; login lockout and audit entries. Every authorised login receives **full admin authority** — assert no read-only, viewer, or reduced-permission login or token path exists (Q22), and that a token created in the UI is revocable and audited. |
| TEST-29 | Failure policy | Kill -9 the daemon, stop the unit, and reboot. Verify: no new blocks, no blocks removed, expiry paused, blocks restored on restart, overdue blocks pruned, and restoration within the configured threshold. Also verify a deliberate `flush` removes everything. |
| TEST-30 | Log integrity | Verify cursor resume (kill/restart loses and duplicates nothing), backfill bounds, parse-status reporting, truncation, redaction, and per-parser rate caps under flood. |
| TEST-31 | File tailing | Rotation by rename+create, `copytruncate`, unlink, inode reuse, glob arrival, partial last line, 1 MB single line, invalid UTF-8, NUL bytes, multi-line stack trace, permission denied, file on NFS (must refuse by default), and a `logrotate` run in the middle of a write — no lost or duplicated lines beyond declared gaps. |
| TEST-32 | Dual-source dedupe | A service logging to both file and journal produces one detection, not two, and both sources remain visible as evidence. |
| TEST-37 | **Coverage scorecard (release gate)** | Maintain a versioned attack corpus covering every DET row (nmap scan types, hydra SSH, gobuster/nikto paths, hping3 flood, slow scan, log-injection variants) and a benign corpus. Each release publishes, per detector: attacks detected, attacks missed, benign events that alerted, benign events that blocked. Gate: **≥ 97% of the attack corpus detected and blocked** in enforce mode, and zero false-positive blocks on the benign corpus. The corpus bounds the claim: results are reported as "of the defined corpus", never as a general detection guarantee. Results are recorded in the iteration summary (§14.3) and are the input to the §19 fork decision. |
| TEST-38 | Footprint | Measure idle and loaded CPU, steady-state RSS, binary size, and 30-day projected disk use on the lab VM; assert NFR-102/103/104/108/116 and record the numbers per release. A 30-day accelerated time run must not exceed the 512 MB default budget. |
| TEST-39 | First-run experience | On a clean Debian 13 VM with only the RustIPS binary copied, `sudo ./rustips setup` followed by `--install-service` and a service start must give a working loopback UI and a first block of a scripted attack in **under 10 minutes**, following the README only. No package manager, external daemon, account, feed, or build step may be required. |
| TEST-40 | First-run safety | With the config deleted but the DB present, startup must enter recovery and must not create a fresh DB (FR-218). With an invalid config, startup must fail with a path/line message and not partially start (FR-219). Setup is idempotent, refuses to overwrite an existing config without `--force`, never modifies an existing `/etc/pam.d/rustips`, never enables enforce mode, and `--dry-run` writes nothing (FR-219a…219d). |
| TEST-41 | Webhook delivery | With the endpoint absent, slow, or returning 5xx: alerts are retried with bounded backoff, duplicates are suppressed, the queue survives a restart without duplicating delivered events, and detection/enforcement latency is unchanged. The shipped SMTP bridge example is exercised end to end (FR-204/204a/204b). |

### 13.3 Release acceptance

A release is done when: all MUST requirements for its phase are met, the full test suite passes,
performance numbers are recorded, and a summary document exists (§14.3). From 0.3.4 onward, the
TEST-37 coverage scorecard is part of acceptance, and from 0.3.5 onward so is the TEST-39
install-in-minutes check.

---

## 14. Versioning, roadmap, and iteration summary

### 14.1 Versioning policy

- `0.MINOR.PATCH`: `MINOR` = a feature set; `PATCH` = iterations/fixes within that feature set.
- The project stays on the `0.3.x` line for the remaining pre-1.0 iterations:
  `0.3.1` rules, `0.3.2` Geo + HTTP, `0.3.3` hardening + perf, `0.3.4` coverage
  gate, `0.3.5` distribution + first run, `0.3.6` release candidate, `0.3.7`
  detector catalog/sidebar, `0.3.8` detector scope/parameters, `0.3.9`
  navigation/theme/honeypot, `0.3.10` menu/state/internal-detector cleanup,
  `0.3.11` IP history, `0.3.12` Active-blocks HTML fix, `0.3.13` resource graphs
  and `0.3.14` rules-table layout fix. Do not open a `0.4.x` line unless the
  owner explicitly decides to; new work is the next `0.3.PATCH`.
- No `1.0.0` until the system has run in production for a defined soak period and every
  `0.3.x` MUST requirement is validated.
- `1.0.0` entry criteria (proposed): 30 days continuous production operation with no
  data-plane crash, no unplanned block outage, < 1% capture drop, a completed restore test
  from backup, and a passed TEST-37 scorecard (**≥ 97% attack coverage, zero benign
  false-positive blocks**) on the released build.

### 14.2 Proposed roadmap

| Version | Theme | Contents |
|---|---|---|
| 0.1.x | Sensor core | Capture, decode, DET-01…07, strikes/ladder, nftables enforcement, SQLite, CLI, observe mode, lab VM scripts, perf baseline, failure-policy plumbing. |
| 0.2.x | First UI + auth | Embedded UI: dashboard, detections, active blocks, block history, allowlist, settings (bind/port); PAM authentication, group authorisation, break-glass, audit log; packet DET-08/09/10. |
| 0.3.0 | Host logs | Full ingestion: journald (cursor, parsers, caps, Logs view) **and** file tailing (inode/offset, rotation, formats, caps), DET-16/17/21/22/23/24/25, dual-source dedupe, log-injection hardening. |
| 0.3.1 | Rules platform | Rule editor with validation/diff/history, dry-run against recent events, import/export, default rule-set review. |
| 0.3.2 | Geo + HTTP | Geo db download/verify/hot-swap, disposition-only country/ASN rules (FR-137…139), packet HTTP detectors DET-11…15. |
| 0.3.3 | Hardening + perf | Fuzzing, chaos tests, aggregation/retention tuning, optional eBPF/XDP capture path, DET-20 slow scan, webhook alerting. |
| 0.3.4 | Coverage gate | Run and publish the TEST-37 scorecard across the full detector catalog, tune thresholds, fix missed detections; require ≥ 97% attack coverage and zero benign false-positive blocks. This is the decision point for the Snort fork. |
| 0.3.5 | Distribution + first run | Single-binary release, `rustips setup` and `--install-service`, recovery/fresh-install safety, install-in-minutes documentation (TEST-39/40), upgrade-by-binary-replacement with DB migration, operational runbooks. |
| 0.3.6 | Release candidate | Documentation, distribution validation, upgrade path, security review, production soak. |
| 0.3.7 | Detector catalog + sidebar | `/detectors` catalog with live thresholds/paths, per-detector enable/disable persisted in SQLite, suppressed counters, left-sidebar navigation, detector/rules documentation. |
| 0.3.8 | Detector scope + parameters | External/internal scope, editable thresholds/path lists for every detector, validated SQLite overrides applied at daemon start, reset per field/group/all, override diagnostics. |
| 0.3.9 | Navigation, theme, honeypot | Grouped sidebar with Disposition rules label, version moved into the sidebar footer, flash-free theme application, optional DET-26 honeypot with Settings-managed unused TCP/UDP ports. |
| 0.3.10 | Menu/state cleanup | Blue collapsible navigation categories, all detectors external (DET-22/24/25 retired), green/red single-button state toggles for detectors and disposition rules, and a default honeypot block rule at 3 contacts. |
| 0.3.11 | IP history | Clickable source addresses with an authenticated history dialog: country/ASN, detections, blocks, strikes, log events, allowlist/block status and a permanent-block action. |
| 0.3.12 | Active-blocks fix | Separate clickable source markup from the Unblock confirmation attribute and hidden form value. |
| 0.3.13 | Resource graphs | Dashboard CPU/memory/database-storage sparklines, 30-second sampling, 24-hour dialog and schema v10 `system_samples`. |
| 0.3.14 | Rules layout fix | Give the Disposition rules Name and Match columns explicit width/minimums with wrapping and horizontal scroll fallback. |
| 1.0.0 | Stable | After soak criteria in §14.1. |
| Post-1.0 | Snort fork (separate repository) | Decision recorded at the 0.3.4 gate; the fork itself starts only after 1.0 is stable, and only if the gate was missed. See §19; not part of this document's deliverables. |

### 14.3 Iteration summary

| ID | Pri | Requirement |
|---|---|---|
| FR-220 | MUST | Each iteration ends with a written summary: what changed, requirement IDs completed/deferred, test results, perf numbers, known issues, and upgrade notes. |
| FR-221 | MUST | Summaries live in `docs/iterations/0.X.Y.md` and `CHANGELOG.md` is kept current. |

---

## 15. Risks

| ID | Risk | Mitigation |
|---|---|---|
| R-01 | False positives block legitimate users (shared NAT, monitoring, CDN/proxy egress, corporate scanners). | Observe mode default, conservative thresholds, allowlist, dry-run rules, easy unblock, per-detector tuning. |
| R-02 | Blocking a spoofed source IP punishes an innocent host. | Prefer rate-limit + short first block; never escalate on purely spoofable signals (e.g. SYN with invalid handshake) without a second signal. |
| R-03 | SSH brute force is invisible on the wire. | Log-based detection (0.3.0) + network proxy detector; documented as a known limitation until logs land. |
| R-04 | Geo deny-lists are blunt and politically/operationally risky. | Geo applies only after a detection (FR-137), ships disabled, requires explicit opt-in, allowlist exceptions, and a dry-run volume preview. |
| R-05 | Memory/CPU blow-up from hostile traffic (state exhaustion). | Bounded LRU state, per-source caps, explicit eviction, fuzz + flood tests. |
| R-06 | Admin locks themselves out. | Established-connection exemption, management allowlist, confirmation on dangerous rules, config-revert on bad bind, PAM break-glass. |
| R-07 | Geo download dependency breaks/rate-limits. | Conditional GET, checksums, last-good retention, manual upload, 24 h cadence. |
| R-08 | Scope creep toward becoming Suricata. | Non-goals §4, phase gating, "would this survive a single-host admin?" test. |
| R-09 | Data loss on crash/power failure. | SQLite WAL, startup reconciliation from DB, restore test. Note: blocks live only in the kernel, so a reboot clears them until the daemon restores them (FR-142/FR-143). |
| R-10 | UI compromise = root-equivalent firewall control. | PAM auth + group check, CSRF, loopback bind, no self-update, audit log, dependency hygiene. |
| R-11 | PAM/SSSD/LDAP outage locks the admin out of the UI. | Break-glass token (FR-182e), local root CLI (`rustips auth test`), and a documented recovery procedure. |
| R-12 | "All logs" floods the disk or starves the packet path. | Per-parser and global rate caps, 128 MB raw cap, separate worker/priority, flood detection (FR-317), operational alerts. |
| R-13 | Journal content leaks secrets or PII, or is used for log injection. | No full command lines by default, redaction patterns, 1 KB truncation, 7-day retention, untrusted-input handling (FR-308, NFR-129). |
| R-14 | Blocks outlive their expiry while the daemon is down (by design), so a temporary block can become effectively permanent if the service never returns. | Accepted policy; short `RestartSec`, degraded banner listing overdue blocks, optional `block_max_overstay` cap, documented `flush` on uninstall. |
| R-14a | A reboot clears nftables before the daemon restores blocks, leaving a detection gap. | Rebuild from DB at startup, `After=nftables.service`, alert if restoration takes longer than a configured threshold (default 10 s). |
| R-15 | Log-derived false positives (e.g. a legitimate monitoring script failing auth). | Thresholds with windows, per-user/per-source keys, alert-only defaults for DET-22/24/25, allowlist applies to log detections too. |
| R-16 | Self-ingestion feedback loop (RustIPS logs a block, ingests its own log, logs again). | Exclude own identifier, cap per-detector log output, test for amplification (FR-318). |
| R-17 | File tailing loses or duplicates lines across rotation, truncation, or inode reuse. | Checkpoint on `(dev, inode, offset)` + last-line hash; explicit gap records; TEST-31 rotation matrix. |
| R-18 | A single runaway file (debug logging, huge lines) swamps ingestion or disk. | Per-file MB/s budget, line caps, partial-buffer caps, global 10k eps, disk budget with pruning. |
| R-19 | Misconfigured file source silently ingests nothing (wrong path, permissions, glob). | Per-file state in the UI (following/rotated/missing/denied), lag metric, "no data" health warning after a configured interval. |
| R-20 | Coverage is measured late, so a shortfall is discovered after 1.0 and forces an unplanned redesign. | TEST-37 scorecard is produced from 0.3.1 onward, not only at 0.3.4; corpus is versioned; 0.3.4 is an explicit gate before distribution work. |
| R-21 | Resource creep: features quietly push disk, RSS, or CPU past the "minimal" goal. | NFR-102/103/104/108/116 are release gates measured by TEST-38; every table has a cap; pruning is tested, not assumed. |
| R-22 | "Minimum footprint" conflicts with useful evidence retention (30-day detections vs 512 MB). | Priority order is enforcement state > blocks/strikes/audit > detections > raw logs; aggregation and oldest-first pruning; operator can raise caps explicitly. |
| R-23 | Binary-only distribution means no package manager to enforce upgrades; admins can run stale, vulnerable versions. | Prominent `--version`/UI version, optional update check that is offline-safe, changelog, documented replacement procedure, DB migration with automatic backup and rollback (TEST-27). |
| R-24 | A deleted or renamed config looks like a fresh install and could clobber existing blocks and history. | Setup state is decided from config **and** DB presence: missing config + existing DB enters recovery, never re-init (FR-218, TEST-40); `--fresh` archives old state first. |
| R-25 | Setup runs as root and writes `/etc/pam.d` and a systemd unit; a bug could weaken host authentication or boot. | Never modify an existing PAM file/unit (diff + `--force`), back up before writing, `--dry-run`, idempotent actions, and tests that assert the no-overwrite behaviour (FR-219b, TEST-40). |

---

## 16. Gaps identified in the draft (summary of changes made here)

1. **"SSH failed logins" cannot be detected from packets** (encrypted). Resolved as a log-based
   detector (DET-16/17), with the network-rate proxy (DET-10) as an early substitute. Revision 2
   expanded this into full journal ingestion (§6.2.2).
2. **IPv6 was not mentioned.** Added as first-class throughout (capture, detection, geo, blocks,
   allowlist).
3. **Enforcement mechanism was unspecified.** Added nftables-based enforcement, startup
   reconciliation, drift repair, and self-lockout protections. Expiry is daemon-owned by decision
   (§7.5), so there are no kernel element timeouts. Enforcement is `input`-only because the host
   does not forward (DM-02, confirmed).
4. **"Not DPI" vs "detect HTTP scans"** needed a boundary. Defined the bounded HTTP parse (≤ 2 KB)
   and wrote non-goals accordingly.
5. **Escalation semantics were underspecified.** Added strike model, decay, extension behaviour,
   per-rule ladders, and the effect of manual unblock.
6. **Geo database operational details were missing**: checksum verification, atomic swap, hot
   reload, last-good retention, offline behaviour, memory footprint (§6.6), and the fact that the
   CSV is ~26 MB / 594k rows — naive loading would blow the memory budget.
7. **Hourly geo polling** could rate-limit or waste bandwidth; changed default to 24 h with
   conditional requests (hourly is still allowed).
8. **Whitelist semantics** were ambiguous (never block vs never detect? does adding one unblock?).
   Defined precedence, detection behaviour, and self-lockout rules.
9. **Web UI had no auth story.** Revision 1 proposed a local account; revision 2 replaces it with
   PAM (system accounts, group authorisation, break-glass), session/CSRF controls, login lockout,
   and the bind-change safety procedure. Revision 8 fixes the authorisation model to a single
   level: group membership, with no roles, viewer accounts, or reduced-permission tokens (Q13/Q22).
10. **No failure-mode policy.** Decided in revision 3: fail-open for new decisions, fail-static for
    enforcement, with daemon-owned expiry (§7.5). This forced the removal of kernel-side block
    timeouts and added startup restoration, drift repair, and overdue-block reporting.
11. **No concrete performance targets.** Added pps/CPU/RSS/latency/binary-size numbers and a
    benchmark harness requirement (binary size alone is not a useful goal).
12. **No retention/growth policy.** Added per-table retention, a 512 MB default disk cap, and aggregation.
13. **No false-positive or regression testing plan.** Added golden pcaps, clean-traffic suite,
    journal fixtures, fuzz and chaos tests.
14. **No upgrade/backup story.** Added upgrade test, export/import, restore test, and 1.0 soak
    criteria.
15. **Scope of DET list was undefined** ("top 15–20"). Wrote the actual catalog with sources,
    defaults, and phases.
16. **Naming**: "Intusion" → "Intrusion"; "Project Code: Rust" is ambiguous and is replaced by the
    concrete identifiers `rustips` (binary/service), `/etc/rustips/`, `/var/lib/rustips/`.
17. **"All system logs" is broader than SSH.** Journal ingestion is a first-class subsystem:
    cursor checkpointing, parser registry, rate caps, 128 MB/7-day raw retention, truncation and
    redaction, and a Logs UI. Revision 4 added file tailing because Debian services such as
    nginx/apache log to files, not the journal. That needs a second checkpoint model
    (`dev, inode, offset`), rotation/truncation handling, and format parsers. Without the caps
    either source alone could fill a disk.
18. **Log content is attacker-influenced.** An attacker who controls any service can write
    arbitrary text into the journal; parsers and the UI must treat it as untrusted
    (log-injection tests, no shell, no HTML).
19. **PAM was not in the draft; it changes the security model.** There is no password store to
    protect, but there is now a dependency on PAM/SSSD and a lockout path, so break-glass, group
    checks, and session revalidation are mandatory.
20. **Full-IP blocking removes a safety valve.** Port-scoped blocks were the obvious mitigation
    for a false positive on a busy NAT address; with full-IP blocks, quality control shifts to
    observe mode, thresholds, the allowlist, and dry-run rules (confirmed decision: full IP).
21. **Geo moved out of detection.** Removed it from the detector catalog (DET-19 reclassified) so
    geography can only amplify a real detection, never substitute for one.
22. **Fixed internal cross-references** (§18 → §17, phase pointers → §14.2, summary pointer → §14.3).
23. **File logs need different correctness rules than the journal.** The journal gives you a cursor
    and never rewrites history; a file can be rotated, truncated, replaced, or shared over NFS. The
    requirements therefore use file identity + offset + last-line hash, record gaps explicitly, and
    refuse network filesystems by default.
24. **An external signature engine is a separate product decision, not a mainline feature.** The
    draft's implied "adopt the Snort community rules" would have added a second daemon, a daily
    rule supply chain, extra memory/CPU, and a harder install. The owner's decision is to keep
    mainline RustIPS fast, minimal, and installable in minutes, prove the built-in detectors reach
    ≥ 97% coverage (TEST-37), and only then evaluate a **separate fork** that adds Snort (§19).
    Nothing in 0.x depends on Snort, and NG-01 remains absolute for mainline.
25. **Installation was never specified, and "config missing" is not the same as "new install".**
    The decision is a single-binary product with no package manager requirement (DM-12). That
    makes first-run detection a safety-critical branch: config absent plus an existing database
    must enter recovery, never initialise a fresh one (FR-217…219d). Setup also writes
    `/etc/pam.d/rustips` and a systemd unit as root, so it must never overwrite an existing PAM
    file or unit without an explicit diff and `--force` (TEST-40).

---

## 17. Open questions

### 17.1 Resolved decisions

| # | Decision | Effect in this document |
|---|---|---|
| Q1 | All system logs are streamed to RustIPS. | Full journald ingestion is a MUST (§6.2.2, FR-300…317); SSH detectors move to 0.3.0. |
| Q2 | Auth is required and must use the system's authentication/PAM. | PAM service, group authorisation, break-glass, session revalidation (FR-182…182h); no local password store. |
| Q5 | GeoIP applies only in the disposition phase; the admin chooses per-country actions (e.g. CN → 24 h or permanent). | FR-137…139; DET-19 reclassified as a disposition attribute; no geo detector, no default country rule. |
| Q6 | The host will not forward traffic; RustIPS protects only the host it runs on. | DM-02, `input`-hook enforcement only, no forward-chain requirements. |
| Q7 | A detection results in a full-IP block. | DM-10, FR-141; port-scoped blocking removed. |
| Q4 | On failure: no new disposition, existing nftables blocks persist, expiry pauses. | DM-07, FR-142/142a-142c, §7.5; nftables element timeouts prohibited; fail-closed removed (NG-11). |
| Q16 | Log scope is journald **and** file tailing, so file-only services are covered. | DM-09, FR-319…335; two checkpoint models, rotation-safe, dual-source dedupe. |
| Q8 | Geo dataset is **`user-country`** (PDDL, updated daily). | FR-160/163; no MaxMind licence dependency; 24 h default check. |
| Q10 | The owner sets **no fixed disk budget**; RustIPS must use the minimum disk/CPU/memory possible. The proposed **512 MB default cap** (DB 256 MB, raw logs 128 MB, geo ~80 MB, headroom ~48 MB) is accepted as the ceiling, with every cap configurable. | Footprint is a design goal (G-10): 512 MB default cap with per-table limits (NFR-108/116), pruning and aggregation, TEST-38. It is a ceiling, not a target. |
| Q28 | In mainline, the **only rule update is the daily `user-country` geo fetch, performed by RustIPS**. Signature-rule updates are a fork concern. | §9 "Rule updates"; FR-163…165; no PulledPork/Oinkmaster dependency in 0.x. |
| Q3 | Enforcement is **nftables only**; no iptables/ipset compatibility backend. | FR-140; Debian 13 default; legacy tooling is out of scope. |
| Q11 | Alerting is a **generic webhook only**. SMTP, chat, and push are implemented by the administrator on top of the webhook. | FR-204/204a, IF-14; no mail configuration, no SMTP secrets, no delivery dependency in the daemon. |
| Q12 | Distribution is the **single binary**. No `.deb`, tarball, or container is required; `/etc/rustips/config.toml` presence defines first run. | DM-12, FR-210/211, FR-217…219d, TEST-39/40; binary replacement is the 0.x upgrade path. |
| Q13 | Authorisation is **group-only**: membership of `rustips-admin` is the single grant, with **no per-user allowlist** on top. | FR-182c; PAM plus one group, one authorisation path, no duplicate user list to keep in sync. |
| Q22 | **No read-only role, viewer account, or reduced-permission token.** Every authenticated admin has full authority; RustIPS is an administrative tool. | FR-189, TEST-28; no role model, no permission matrix in the UI or API; audit distinguishes `admin:<user>` from `api:<token>`. |
| — | Suricata is a semantics reference only. | REF-03: no code copying, GPLv2 boundary explicit. |
| — | Snort is **deferred to a post-1.0 fork**, gated on the 97% coverage result. | DM-11, G-08, §19; mainline has one process, no external engine, no rule feed. |

### 17.2 Still open

| # | Question | Recommended default |
|---|---|---|
| Q9 | Confirm no geo rule ships enabled (the admin creates their own per-country rules after opting in). | None enabled; wizard offers templates, dry-run first. |
| Q14 | Does a manual unblock reset the strike count? | Keep strikes (configurable). |
| Q15 | Target throughput: is 1 Gbps / 100k pps the real ceiling, or should 10 Gbps be planned? | Design for 1 Gbps single host; revisit in 0.3.3 with measurements. |
| Q17 | Break-glass mechanism: root-only one-time token, a local fallback account, or both? | Root-only one-time token with 30 min TTL; local account only if you want it. |
| Q18 | PAM group name: create `rustips-admin`, or reuse an existing group such as `sudo`? | Dedicated `rustips-admin`; never `sudo` (too broad). |
| Q19 | Raw log retention: 7 days / 128 MB, or longer? Longer retention is useful for investigation but stores usernames, paths, and IPs. | 7 days / 128 MB; parsed evidence keeps the 30-day detection history. |
| Q20 | Do you ever want remote syslog ingestion from other hosts? | No (single-host scope); leave the parser interface pluggable. |
| Q21 | Should log-derived detections be allowed to block by default, or start alert-only? | Block for DET-16/21/23; alert-only for DET-17/22/24/25. |
| Q23 | Should log ingestion also capture `auditd` events (if installed)? They are richer than journald for account/file changes but add a second input path. | Journald's own audit records in 0.3.0; native auditd socket in 0.3.3 if you use `auditd`. |
| Q24 | Which file formats do you need first? Defaults proposed: nginx/apache access+error, JSON-lines, RFC 5424/3164. | Those four in 0.3.0. |
| Q25 | Support custom (user-supplied) line formats, or built-in formats only? Custom patterns are useful but add a parsing/DoS surface. | Built-in formats in 0.3.0; custom linear-time regex in 0.3.3 behind a warning. |

---

## 18. Glossary

| Term | Meaning |
|---|---|
| Detection | An event produced by a detector from observed traffic or logs. |
| Disposition | The decision (alert/block/escalate/allow) taken for a detection by the rules engine. |
| Strike | A persisted count of prior detections for a source IP, driving escalation. |
| Allowlist | Sources that are never blocked (may still be detected). |
| Observe mode | Detections and rule matches are recorded, but no enforcement is applied. |
| Ladder | The ordered list of block durations applied as strikes accumulate. |
| Fail-open (decisions) | On failure, no new block/unblock/escalation decision is made. |
| Fail-static (enforcement) | On failure, blocks already in nftables remain in force, and expiry pauses until recovery. See §7.5. |
| Overdue block | A temporary block whose `expires_at` passed while the daemon was unavailable; reported and removed on recovery. |
| PAM | Pluggable Authentication Modules — the host's authentication stack, used for UI login. |
| Journal cursor | The opaque `__CURSOR` position in the systemd journal, used for lossless resumption. |
| File identity | `(device, inode)` pair identifying a log file; survives renames, changes on replace/rotate. |
| Tail checkpoint | Persisted `(file identity, byte offset, last-line hash)` used to resume a file source. |
| Rotation | Replacement of a log file (`rename`+create, or `copytruncate`), which must not cause loss or duplication. |
| Log injection | An attacker-controlled log line crafted to corrupt parsing, storage, or UI rendering. |
| Hot swap | Replacing the geo database at runtime without dropping detections or restarting. |

---

## 19. Appendix — deferred Snort 3 fork (post-1.0)

**Status: out of scope for 0.x.** The mainline product must first reach a fully working, fast,
minimal state that a single administrator can install and use in minutes. Only then is a
**separate fork** considered that adds Snort as the network detection engine. Nothing in this
appendix is a requirement of mainline RustIPS, and none of its FR-4xx identifiers may be used to
justify complexity in 0.x (NG-01 still applies).

**Fork decision gate.** The fork is started only if the mainline fails the coverage gate
(TEST-37): fewer than **97%** of the defined attack corpus detected, or false positives above the
agreed ceiling, after tuning. If the built-in detectors reach the target, the fork is not pursued —
a second daemon, extra memory, an additional install step, and a daily rule-supply chain are not
justified for marginal coverage.

The design below is retained because it has already been researched and reviewed, so the fork does
not start from zero. Every requirement in it is a fork requirement.

### 19.1 Sidecar vs native interpreter

The fork adds two detections to the catalog:

| ID | Detection | Data source | Default signal | Default action |
|---|---|---|---|---|
| DET-26 | External signature alert (Snort rules) | snort `alert_json` | rule match by `gid`/`sid`/`classtype` | per disposition rule; alert-only by default |
| DET-27 | Network scan via Snort `port_scan` inspector (TCP/UDP/IP scan, decoy, distributed, sweep, filtered) | snort `alert_json` | inspector alert type + priority | block (ladder) once mapped; alert-only during tuning |

Two implementation strategies were considered. Q26 chose **A**, and §19.2–§19.5 are written for
it; §19.6 applies only if that decision is reversed.

The division is: Snort detects network traffic (signature rules plus its `port_scan` inspector);
RustIPS remains the disposition, enforcement, and management plane, and the detection engine for
host logs, which Snort cannot see. Snort has no notion of persistence, escalation, or the
allowlist and must never block (FR-402).

| Approach | Coverage | Effort / risk | Resource cost | Recommendation |
|---|---|---|---|---|
| **A. Snort 3 sidecar** — run Snort in IDS (`alert`) mode, consume its `alert_json` stream, treat each alert as a detection event. RustIPS keeps all disposition and enforcement. | Full community rule set, including DPI, stream reassembly, HTTP/TLS/DNS normalization. | Low RustIPS effort; medium deployment effort (Snort must exist on the host). | Extra process: roughly 100–300 MB RSS and real CPU per Gbit; base install unaffected when disabled. | **Recommended** |
| **B. Native subset interpreter** — parse a defined subset of Snort 3 rule syntax and match it in RustIPS. | Partial. Without stream reassembly, `flow:to_server,established` + `content` rules only match within a single packet; many rules never fire. | High, ongoing: track Snort syntax, sticky buffers, `pcre`, `byte_*`; every unsupported option is a silently missing detection. | Modest, but adds matching cost to the hot path. | **Rejected (Q26)**; retained as the documented fallback only. |

**Why A is recommended:** a rule is not just a pattern. Most community rules depend on `flow`
tracking, reassembly, and protocol parsers (`http_uri`, `http_header`, `tls_sni`, `dns_query`).
Re-implementing that is re-implementing Snort, which is exactly the complexity this project exists
to avoid. A sidecar gets the full rule set on day one and keeps the fast path clean. The trade is a
second daemon, which is an acceptable, explicit, opt-in cost.

The engine boundary is absolute: **RustIPS's own data plane still performs no DPI** (NG-01).
When the module is enabled, Snort is the only signature and deep-inspection path; it runs
out-of-process, has no enforcement capability, and never drops traffic. RustIPS stays the sole
writer of nftables state.

### 19.2 Module boundary and lifecycle

| ID | Pri | Requirement |
|---|---|---|
| FR-400 | MUST | The Snort module is **optional and disabled by default**. The base install, resource budgets (NFR-100…108), and binary size must be unaffected when it is off. The installer and UI must state plainly that a Snort-backed install has materially better network coverage. |
| FR-401 | MUST | Core detectors, blocking, allowlist, and the UI must work identically with the module absent, stopped, crashed, or misconfigured. Failures are isolated and reported, never fatal. |
| FR-402 | MUST | Snort runs in **IDS/alert mode only**. It must never be configured inline, in IPS mode, or with `drop`/`reject`/`rewrite` actions; RustIPS alone decides and applies blocks. Snort rules with non-`alert` actions are converted to `alert` or skipped, and the conversion is recorded. |
| FR-403 | MUST | `rustips snort enable` verifies a Snort 3 binary and compatible alert format, then generates a minimal config. Missing dependencies produce instructions, not a failed base install. RustIPS must not bundle or redistribute Snort binaries. |
| FR-404 | MUST | Detect and report the Snort version and alert-format version at start; refuse to ingest an incompatible format with a specific error rather than parsing garbage. |
| FR-405 | SHOULD | Support running Snort in a separate cgroup/unit with its own memory/CPU limits so it cannot starve the data plane. |
| FR-406 | MUST | Two deployment profiles exist and are selectable without reinstalling: **Standalone** (RustIPS built-in packet detectors only) and **Snort-backed** (Snort is the network detection engine, built-ins optional). The profile and its coverage consequences must be visible in the UI, not buried in config. |
| FR-407 | MUST | When Snort is enabled, built-in packet detectors remain enabled by default as an independent, dependency-free baseline, and may be disabled individually where they duplicate a Snort alert. Each detector's enabled/disabled state and the reason are recorded. |
| FR-408 | MUST | Enable Snort's `port_scan` inspector by default in the Snort-backed profile, with its own thresholds exposed in the UI, and map its alerts to DET-27. Snort's scan alerts and RustIPS's DET-01/02/11 must deduplicate rather than double-count a strike (FR-413). |

### 19.3 Alert ingestion

| ID | Pri | Requirement |
|---|---|---|
| FR-410 | MUST | Ingest Snort's `alert_json` output (preferred) as its own file source, reusing the inode/offset checkpoint, rotation, truncation, and line-cap machinery from §6.2.2. `alert_fast` may be supported as a fallback with a documented loss of fields. |
| FR-411 | MUST | Normalise each alert into a detection event with `source=signature`, plus `gid`, `sid`, `rev`, `msg`, `classtype`, `priority`, `action`, `proto`, `src`, `dst`, ports, and the alert timestamp. Provenance must allow an admin to open the exact rule text. |
| FR-412 | MUST | Guard against replay and duplication: deduplicate on `(gid, sid, rev, src, dst, alert_ts)` within a window, and never re-block from a re-read alert file after a restart. |
| FR-413 | MUST | Correlate with native detections (FR-119): a source already being blocked is not double-counted, but the signature SID is appended as supporting evidence. |
| FR-414 | MUST | Bound signature-driven load: per-SID and global alert rate caps, collapse repeated `(sid, src)` alerts within a cooldown into one event, and cap the number of new blocks per minute from signature alerts. |
| FR-415 | MUST | Health must distinguish "Snort running, zero alerts" from "Snort not running / no data / parse failures". Silence is never treated as proof of safety. |
| FR-416 | MUST | If Snort is configured but has produced no output for a configurable interval while traffic is flowing, raise a degraded-state alert. |

### 19.4 Disposition mapping

| ID | Pri | Requirement |
|---|---|---|
| FR-420 | MUST | Signature alerts are ordinary detections: they pass through the same rule engine, escalation ladder, allowlist, observe mode, audit, and failure policy. There is no signature-specific blocking path. |
| FR-421 | MUST | Disposition rules can match on `signature.gid`, `signature.sid`, `signature.rev`, `signature.classtype`, `signature.priority`, and a `signature.msg` prefix/glob. |
| FR-422 | MUST | Ship a conservative default mapping by `classtype`/priority: `attempted-recon`, `attempted-dos`, and high-priority exploit classes may block on the normal ladder; policy/social/anomaly classes are alert-only until the admin opts in. Snort `port_scan` inspector alerts (DET-27) use the same ladder as DET-01/02/11. |
| FR-423 | MUST | Signature rules default to **alert-only in observe mode**, and the module cannot enable enforcement by itself; switching to enforce is the same explicit global action as everywhere else. |
| FR-424 | SHOULD | Provide a per-classtype and per-SID toggle in the UI that generates a disable list, so tuning survives rule updates (FR-437). |
| FR-425 | SHOULD | Show, for each signature, first/last seen, alert count, sources, and the block decisions it produced, so noisy rules are identifiable. |

### 19.5 Rule acquisition, licensing, and updates

| ID | Pri | Requirement |
|---|---|---|
| FR-430 | MUST | Fetch the **Snort 3 Community Ruleset** from the official no-registration endpoint (GPLv2, updated daily). Default cadence: daily, with HTTP conditional requests; manual "update now". |
| FR-431 | MUST | Verify the download against the published checksum, reject archives containing absolute paths, `..`, symlinks, or unexpected file types, and extract into a fresh directory before activation (no in-place overwrite). |
| FR-432 | MUST | Run Snort's own config test (`snort -T -c …`) against the new rule set before activation. On failure, keep the last-good rule set, do not restart into a broken state, and alert with the failing rule/SID. |
| FR-433 | MUST | **Never distribute Snort rules with RustIPS.** They are downloaded at runtime by the administrator's installation. Cached copies retain the licence/attribution files from the tarball. |
| FR-434 | MUST | Support an optional registered/subscriber mode: configurable rule URL plus an `oinkcode` stored as a secret (0600, never logged, never exported). The UI must state the licence difference: community = GPLv2; registered = free but 30 days delayed and under the Snort Subscriber Rules License; subscription = paid, per-sensor, no redistribution. |
| FR-435 | MUST | If RustIPS is ever distributed commercially, subscriber rules require a separate Cisco commercial agreement — this must be documented in `THIRD_PARTY.md`, and the feature must not be presented as included. |
| FR-436 | MUST | Record rule-set version/date, source URL, hash, rule count, enabled/disabled counts, and last successful activation; show rule-set age prominently. |
| FR-437 | MUST | Keep user tuning (disabled SIDs, overrides, local rules) in RustIPS-owned files that updates never overwrite. |
| FR-438 | MUST | Support a local rules directory (e.g. `/etc/rustips/snort/local.rules`) for site-specific signatures, with clear precedence over downloaded rules. |
| FR-439 | SHOULD | Alert when the rule set is older than a configurable threshold (default 7 days), mirroring the geo-db freshness behaviour. |

### 19.6 Fallback: native subset interpreter (rejected by Q26; retained for reference)

| ID | Pri | Requirement |
|---|---|---|
| FR-440 | MUST | Parse only a **declared** subset: rule header (action, proto, src/dst, ports, direction), `msg`, `sid`, `rev`, `gid`, `classtype`, `priority`, `reference`, `metadata`, `flow`, `flags`, `dsize`, `content`/`nocase`/`depth`/`offset`/`distance`/`within`, `uricontent`/`http_uri`/`http_method`/`http_header`, `threshold`/`detection_filter`, `byte_test`. |
| FR-441 | MUST | Reject, never ignore, unsupported options. A rule with an unsupported option is skipped as a whole and listed in a coverage report with the reason. Partial enforcement of a rule is forbidden. |
| FR-442 | MUST | Publish a coverage report: total rules, supported, skipped by option, skipped by protocol. If coverage is below a configurable floor (default 60%), the UI must state that the adapter is not a substitute for Snort. |
| FR-443 | MUST | Document the semantic gap explicitly: no stream reassembly, so `flow:to_server,established` content rules match only within a single packet; results will differ from Snort and must not be described as equivalent. |
| FR-444 | MUST | Content matching uses multi-pattern search (Aho-Corasick or equivalent) with bounded memory; PCRE, if supported at all, uses a linear-time engine or a match-limited PCRE2 and is off by default. |
| FR-445 | SHOULD | Golden tests compare adapter output against Snort's `alert_json` for the same pcaps, producing a per-SID agreement report. |

### 19.7 Configuration, UI, and diagnostics

| ID | Pri | Requirement |
|---|---|---|
| FR-450 | MUST | Settings: enable/disable, interface(s), Snort binary path, config path, rule source (community/registered/subscriber/custom), `oinkcode`, alert output path, update interval, alert caps, per-classtype defaults. |
| FR-451 | MUST | Generate `HOME_NET` from the host's actual addresses and `EXTERNAL_NET` as `!HOME_NET`. A misconfigured `HOME_NET` makes directional rules silently not fire, so it must be derived, shown, and validated, not hand-typed by default. |
| FR-452 | MUST | A **Signatures** view: rule-set status/age, coverage (for the interpreter), per-SID enable/disable, alert volume by SID, top noisy rules, and the raw rule text for any alert. |
| FR-453 | MUST | `rustips snort check` validates binary, version, config, rule set, alert output, and permissions without starting enforcement; `rustips snort update` fetches and validates. |
| FR-454 | SHOULD | Provide a one-command rollback to the previous rule-set generation. |

### 19.8 Fork test plan

These tests belong to the fork, not to mainline acceptance.

| ID | Level | Requirement |
|---|---|---|
| TEST-33 | Snort detection engine | A `tcpreplay` pcap that triggers known SIDs produces matching detections with `gid`/`sid`/`rev`/`classtype` preserved; the `port_scan` inspector fires DET-27 on an nmap scan and does not double-count DET-01; replaying the same alert file after a restart produces no duplicate blocks (FR-412); a malformed or truncated alert line does not stall ingestion; killing Snort leaves core detectors, log detection, and enforcement working (FR-401) and flips health to degraded (FR-415/416). |
| TEST-34 | Ruleset update/rollback | Fetch a community ruleset, verify checksum, fail a corrupted archive (path traversal, symlink, wrong type), activate, then corrupt the next generation so `snort -T` fails — the last-good set must stay active and an alert must name the failing SID; rollback to the previous generation works. |
| TEST-35 | Community-rule baseline | Replay clean-traffic captures through Snort with only the community ruleset and record every alert; the release must ship with a documented baseline and a default mapping that keeps low-confidence classes alert-only (FR-422). Any new noisy SID blocks tuning from surviving updates (FR-437). |
| TEST-36 | Interpreter coverage (only if Q26 is reversed) | Generate the coverage report over the full community ruleset, assert every skipped rule states a reason, and assert the subset never silently partially enforces a rule (FR-441). Golden per-SID agreement vs Snort `alert_json` (FR-445). |

### 19.9 Fork risks

| ID | Risk | Mitigation |
|---|---|---|
| R-120 | Snort 3 is not packaged for Debian 13; enabling the module means building from source or running a container, which many admins will not do. | Module is optional and off by default; `rustips snort check` gives exact remediation; document source-build and container paths; never make installation depend on it (§17, Q27). |
| R-121 | Double capture cost: Snort re-reads the same traffic RustIPS already decodes, roughly doubling CPU per Gbit. | Snort in its own cgroup with CPU/memory limits (FR-405); benchmark with the module on and off; document the ceiling; recommend it only where the host has headroom. |
| R-122 | Community rules produce false positives (policy/social/anomaly rules fire on ordinary traffic) and are refreshed daily, silently changing behaviour. | Default mapping keeps low-confidence classtypes alert-only (FR-422); per-SID disable list that survives updates (FR-437); noise report per SID (FR-425); ruleset-age and change alerting (FR-436/439). |
| R-123 | Licensing drift: an admin enables registered or subscriber rules and later redistributes them, or RustIPS is commercialised with them included. | Community = GPLv2/no registration is the default; `oinkcode` stored as a secret; explicit licence text in the UI (FR-434) and `THIRD_PARTY.md` (FR-435); rules never bundled (FR-433). |
| R-124 | `HOME_NET` misconfiguration makes directional rules silently never fire, giving false confidence in coverage. | Derive `HOME_NET` from the host's addresses, show it, validate it on every start, and warn when alerts are implausibly low for the observed traffic (FR-451, FR-415/416). |
| R-125 | Profile confusion: an admin believes they have Snort-backed coverage when the module silently failed to start, or vice versa. | Profile and per-source health shown prominently (FR-406, FR-415/416); degraded banner names which detection source is down and what coverage is lost. |

### 19.10 Glossary (fork)

| Term | Meaning |
|---|---|
| Signature | A rule match produced by an external rule engine (Snort) rather than a built-in RustIPS detector. |
| SID / GID | Snort's rule identifier (`sid`) and generator identifier (`gid`); `gid:sid:rev` uniquely identifies a rule revision. |
| Classtype | Snort's rule classification (e.g. `attempted-recon`, `web-application-attack`), used for default disposition mapping. |
| HOME_NET | Snort's definition of the defended network, derived from the host's own addresses; a wrong value makes directional rules silently not fire. |
| Sidecar | The Snort process in IDS mode, observing the same traffic and reporting events to RustIPS with no enforcement authority. |
| Signature event source | Ingested `alert_json` lines treated as detections with `source=signature`, using the same disposition, escalation, allowlist, and audit path as native detections. |
