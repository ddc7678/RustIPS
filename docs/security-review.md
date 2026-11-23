# Security review — 0.3.6 release candidate

**Scope:** RustIPS 0.3.6, single-host sensor/UI, systemd unit, setup/deploy
tooling, webhook and geo egress.
**Date:** 2026-11-21.
**Method:** code review of the attack surface, `cargo audit`, `cargo clippy`,
the test suite and scorecard, lab VM checks, and `systemd-analyze security`.

This is a focused review for a single-admin tool, not a formal third-party
audit. It records what was checked, what was fixed, and what is knowingly
accepted.

## Summary

RustIPS is a root-privileged host IPS with a loopback-only UI. The main risks
are the privileged network path, the web authentication surface, untrusted
packet/log input and optional outbound webhook/geo requests. The 0.3.6 review
found no open high-severity code defect. Three hardening changes were made:

1. the SQLite database is forced to mode 0600 (the state directory is 0700);
2. `setup` no longer chmods a pre-existing config parent (for example `/tmp`)
   when the config path is overridden; only a newly created parent is set to
   0755;
3. the systemd unit gained `UMask=0077`, `PrivateDevices`, kernel/control-group/
   clock/hostname protection, `RestrictSUIDSGID`, `RestrictRealtime`,
   `RestrictNamespaces`, `LockPersonality`, native syscall ABI and a restricted
   address-family set.

`cargo audit` reports no known vulnerabilities. It reports one unmaintained
crate warning for `chrono` (RUSTSEC-2026-0543); there is no fixed upgrade, and
`chrono` is used only for timestamps/durations, not parsing untrusted code.

## Assets and trust boundaries

| Asset | Boundary |
|---|---|
| nftables blocked sets | Only the root daemon writes them; the DB is authoritative. |
| SQLite DB (detections, blocks, rules, logs, alert queue) | Root-owned, state dir 0700, DB now 0600. |
| PAM password | Never stored; passed to `pam_authenticate` in-process and zeroed. |
| Web sessions / CSRF tokens | In-memory, HttpOnly/SameSite cookies, 30 min idle / 12 h absolute. |
| Break-glass token | Root-created 0600 file, one use, max 24 h, consumed on login. |
| Webhook URL/credentials | Admin-configured; config 0600 and DB settings; UI shows to admins only. |
| Geo indexes | Optional, checksum-verified, state dir 0700. |

## Authentication and authorisation

* PAM through `/etc/pam.d/rustips`, followed by `pam_acct_mgmt`; group
  membership in `rustips-admin` is the only grant. No second password store.
* Password buffers are not echoed/logged/hashed and are zeroed after `pam_end`.
* Login limiter: 5 failures per username and per source in 10 minutes → 15
  minute lockout; attempts are audited.
* Sessions: `HttpOnly`, `SameSite=Strict`, `Path=/`; CSRF token on every POST;
  idle and absolute timeouts; fresh token on login; PAM/group revalidation every
  5 minutes and on privileged actions.
* Break-glass bypasses the password limiter deliberately; it is root-only, one
  use, short-lived and visibly marked in the UI/audit.
* No API bearer token exists yet (FR-189 SHOULD); the UI is the only remote
  interface.

Reviewed: session fixation (new token on login), CSRF missing/stale (403),
logout invalidation, Host-header DNS-rebinding guard (`421`), unauthorised
redirects, login notice allowlist, no user enumeration before a correct password.
The 0.3.7 detector enable/disable action and the 0.3.8 parameter save/reset
actions use the same authenticated, CSRF-protected POST path and are audited.
Parameter values are normalized and range-checked before storage; unknown keys
are rejected, and the merged configuration is re-validated at daemon start, so
stored overrides cannot introduce arbitrary TOML or bypass config validation.
The 0.3.9 honeypot adds no listener or service: it only classifies inbound
TCP SYN/UDP packets against a validated port list, and is disabled by default.
The 0.3.10 rule state toggle uses the same authenticated, CSRF-protected POST
path and is audited (`rules.enable`/`rules.disable`); it still enforces the
last-enabled-rule protection. The 0.3.11 `/api/ip` history endpoint is
authenticated and read-only, escapes all stored fields, and loads its country/
ASN data from the in-memory indexes. Its permanent-block button submits the
existing CSRF-protected `/blocks/add` form. The 0.3.13 `/api/system` resource
graphs endpoint is likewise authenticated and read-only; it serves only
aggregated process CPU/memory and database-size samples.

The 0.3.15 country-badge colors are accepted only as a two-letter ISO code and
`#rrggbb` values. They are emitted as a generated same-origin stylesheet rather
than inline styles, so the strict CSP remains in force; malformed stored entries
are skipped.

## Network and web exposure

* Loopback bind by default; a non-loopback bind requires an explicit checkbox,
  logs a warning and shows a persistent banner. There is no TLS listener; the
  documented deployment is an SSH tunnel.
* Strict CSP (`default-src 'none'`; self-hosted CSS/JS; no inline script/style),
  `X-Frame-Options: DENY`, `nosniff`, `no-referrer`.
* Header cap 16 KB, body cap 8 KB (256 KB only for the rules import endpoint),
  connection cap 64, read/write timeouts.
* `/healthz` and `/readyz` are public; `/metrics` is served only while the
  listener is on loopback.
* `/readyz` exposes component status (DB/journal/geo/nftables/PAM/alert/capture
  counters), not secrets; reviewed as acceptable for a monitoring endpoint.

## Input handling

* Packet decoding is fixed-size, bounded and has fuzz-like random-input tests;
  no unbounded allocation from header lengths.
* HTTP parsing caps request heads at 2 KB and flows/clients at fixed sizes;
  malformed/oversized input is counted, not expanded.
* Log fields are untrusted: messages are truncated to 1 KB, control characters
  neutralised, CRLF normalised, literal secrets optionally redacted, and every
  rendered value HTML-escaped. No regex, format string, shell interpolation or
  `eval`.
* Rules are JSON data, validated before use; no code execution, no shell, no
  path interpolation. Import is bounded to 256 KB and a validated set; the last
  good set is kept on a failed reload.
* SQL uses parameterised statements throughout.
* External commands (`nft`, `journalctl`, `curl`, `groupadd`, `systemctl`,
  `sendmail` bridge) receive fixed arguments or validated values. No
  user-controlled shell string is executed.
* Webhook and geo URLs are validated as `http(s)` without whitespace. They are
  admin-controlled; SSRF into internal services is an accepted admin capability.

## Privileges and filesystem

* The daemon runs as root with `CAP_NET_RAW`/`CAP_NET_ADMIN` (capture and
  nftables) and `systemd-journal` supplementary group.
* Unit hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp`, `PrivateDevices`, kernel tunable/module/control-group/clock/
  hostname protection, `RestrictSUIDSGID`, `RestrictRealtime`,
  `RestrictNamespaces`, `LockPersonality`, `SystemCallArchitectures=native`,
  restricted address families, `ReadWritePaths=/var/lib/rustips`, `MemoryMax=512M`,
  `LimitNOFILE=65536`, and `UMask=0077`.
* Config 0600; state dir 0700; DB 0600; break-glass 0600; PAM file 0644 (PAM
  requires readability); unit 0644.
* `setup` never enables enforce mode or starts capture, never overwrites an
  existing PAM file/unit without `--force`, and `--fresh` archives state first.
* `flush` is explicit; stopping the daemon leaves blocks in place by design.

## Secrets and logging

* No plaintext secrets are written to logs or the DB. PAM credentials are not
  stored. Break-glass tokens are 0600 files printed once.
* Detection/alert payloads exclude raw log messages, HTTP bodies, command lines
  and environment dumps. The webhook URL is treated as a secret; config is 0600.
* The e-mail bridge reads SMTP credentials from an environment file; the
  documented unit uses `EnvironmentFile` mode 0600.

## Availability and resource bounds

* Per-source tables, log-event caps, HTTP flow/client caps, geo index size,
  webhook queue cap and DB busy timeout are bounded.
* Rate limits: journal per parser/global, HTTP flood detection, login limiter,
  alert dedupe/backoff, capture buffer caps.
* Retention: detections 30 days, raw logs 7 days/128 MB, audit 365 days, alert
  rows 7 days, with daily aggregation and `PRAGMA optimize`/WAL checkpoint.
* Capture/journal/webhook failures are isolated; capture and enforcement keep
  running when logs or alerts fail.

## Supply chain and dependencies

* 11 direct crates, 101 locked dependencies. `cargo audit` (2026-11-21):
  **0 vulnerabilities**; 1 warning: `chrono 0.4.45` unmaintained
  (RUSTSEC-2026-0543), no fixed upgrade. Accepted for timestamp/duration use;
  revisit when a maintained successor is practical.
* No new crates were added in 0.3.5/0.3.6. `curl` is an optional runtime tool
  for geo/webhooks; `journalctl`/`nft` are required system tools.
* Release artefacts are SHA-256 checksummed; they are **not signed** (NFR-124
  SHOULD, accepted for the RC).
* No telemetry or update beacon.

## Audit and monitoring

* Every login attempt, config change, block/unblock, allowlist/rule/target
  change, setup/import/export and privileged action is audited with actor.
* `/metrics` exposes packets, drops, detections, blocks, logs, alert queue and
  geo counters; `/readyz` reports component readiness; `rustips diagnose` dumps
  the effective state for support.
* The daily prune and alert delivery failures are logged and surfaced.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | Low | DB file inherited umask (state dir 0700 mitigated) | Fixed: DB mode 0600 |
| 2 | Medium | `setup` with an overridden config path chmodded a pre-existing parent (for example `/tmp`) to 0755, dropping the sticky bit | Fixed: only newly created parents are chmodded; regression test added |
| 3 | Low | Systemd `UMask` was unset; default-created files could be group/world-readable | Fixed: `UMask=0077` plus unit hardening |
| 4 | Low | `chrono` is unmaintained (RUSTSEC-2026-0543) | Accepted; no fixed upgrade |
| 5 | Info | No TLS listener for a non-loopback bind | Accepted; SSH tunnel documented |
| 6 | Info | Webhook/geo URLs are admin-controlled and can target internal hosts (SSRF) | Accepted; full-admin capability, documented |
| 7 | Info | Release artefacts are checksummed but not signed | Accepted for RC |
| 8 | Info | Daemon runs as root (needed for capture/nftables) | Accepted; capability bounding and unit hardening |
| 9 | Info | `/readyz` is public on a non-loopback bind | Accepted; no secrets, monitoring endpoint |

## Verification

```sh
cargo fmt --check
cargo clippy --all-targets
cargo test
cargo audit
scripts/scorecard.sh
scripts/lab/run-tests.sh --install
systemd-analyze security rustips
```

Results at review time:

* clippy/fmt clean; 144 tests pass; scorecard 23/23, 0 benign alerts/blocks.
* `cargo audit`: 0 vulnerabilities, 1 unmaintained warning (`chrono`).
* lab acceptance: 28/28 checks, including install-service, PAM no-replace,
  recovery/fresh safety and UI health.
* `systemd-analyze security`: improved from **6.5 MEDIUM** before the unit
  hardening to **4.1 OK** with the 0.3.6 unit (see the RC soak record).
* Soak: 300 s at RSS 43.3 MiB, 1.10% of one core, 0 restarts, 0 capture drops;
  120 s DB sample 3.73 MiB with flat growth. See `docs/soak/0.3.6.md`.
* Clean Debian 13 VM first run: install/service ready in 9 s; a scripted replay
  produced 4 active nftables blocks.

## Accepted risks and follow-ups

* Sign release artefacts (minisign/Sigstore) and add TLS termination guidance if
  a non-loopback UI becomes common.
* Revisit `chrono` when the ecosystem has a maintained replacement.
* Add an API bearer token with least-privilege read-only monitoring if requested
  (FR-189 SHOULD).
* File sources, dual-source dedupe, auditd socket and optional eBPF/XDP remain
  future work with their own input/privilge review.
* A third-party penetration test and a 30-day soak are still recommended before
  a 1.0 declaration.
