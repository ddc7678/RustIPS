# Host logs

RustIPS ingests the system journal and turns authentication and system-change
lines into detections. This page covers the 0.3.0 journald slice: privileges,
what is stored, retention and privacy, the detectors, and day-to-day
troubleshooting. File sources (nginx/apache access and error logs, arbitrary
paths) and DET-23 are a later slice.

## How ingestion works

The daemon starts a supervised `journalctl -f -o json --no-pager` child as a
separate thread. Each JSON line is decoded, normalised into one `LogEvent`,
bounded and redacted, written to SQLite, and passed to the log detectors. The
event is then handed to the same `record_detection` disposition path as packet
detections, so allowlist precedence, observe mode, the strike ladder and nftables
enforcement behave identically.

Ingestion is isolated from capture:

* a missing `journalctl`, a denied journal, an exited child or a parse failure
  marks the journal `degraded` and retries with exponential backoff (1 s up to
  60 s);
* packet capture, blocks and enforcement keep running;
* the Logs page and `rustips status` show the current state.

The child is killed and joined on shutdown; a clean stop records `stopped`.

### Cursor, backfill and gaps

Every processed entry advances the journal cursor. The cursor is persisted
**after each event**, so a restart resumes exactly after the last processed
entry (FR-302). A partial unique index on `log_events(cursor)` makes a replay of
the same cursor a no-op, which covers a crash between the row insert and the
cursor checkpoint.

On the **first** start (no stored cursor) the reader backfills
`logs.backfill_secs` (default 900 seconds = 15 minutes). Set it to `0` to start
at the current end of the journal.

If the stored cursor cannot be resumed (for example the journal was vacuumed),
the reader retries, then clears the cursor, records a `journal.gap` entry and
falls back to the configured backfill. The Logs page shows a **Cursor gap**
banner with the reason. Late or clock-skewed entries are normalised with their
own timestamp and are accepted as-is.

## Privileges

Reading the journal needs one of:

* the daemon running as **root** (the default systemd unit), or
* membership in the **`systemd-journal`** group for a foreground run.

The shipped unit already includes `SupplementaryGroups=systemd-journal`, so a
normal systemd install needs no extra work. For a manual run:

```sh
sudo usermod -aG systemd-journal your-user
# log out and back in, then:
rustips logs test --since 5m
```

If access is denied, the Logs page shows `journal ingestion: degraded` and the
error text, and `rustips status` prints `journal: degraded`. Nothing is
silently skipped. File sources will have the same per-source permission
reporting when they land (FR-331).

## What is ingested

By default every journal unit, identifier, priority and facility is read, then
filtered by `[logs.journal]`:

```toml
[logs.journal]
include_units = []        # empty = all
exclude_units = []
include_identifiers = []  # empty = all
exclude_identifiers = ["rustips"]
```

The daemon's own identifier (`rustips`) is excluded to prevent a feedback loop:
a detection must not create a log line that creates another detection (FR-318).
systemd's messages *about* `rustips.service` are still ingested, so stopping or
crashing the service remains visible as log evidence (the old DET-24 detector
was retired in 0.3.10). PAM's own journal entries are also ingested, so UI
brute force is visible.

### Parsers and templates

Parsing is a linear scan with bounded fields; no regex, shell or format-string
interpolation is used. The current registry:

| Identifier / pattern | Parser | Templates |
|---|---|---|
| `pam_unix(...)` / `pam_*` | `pam` | `pam.auth_failure`, `generic` |
| `sshd`, `sshd-session`, `sshd-auth` | `sshd` | `sshd.failed_password`, `sshd.invalid_user`, `sshd.accepted`, `sshd.other` |
| `sudo` | `sudo` | `sudo.command`, `sudo.denied`, `sudo.auth_failure`, `account.modification` |
| `systemd-logind` | `systemd-logind` | `logind.session` |
| `cron`, `crond`, `anacron` | `cron` | `cron.job` |
| `kernel`, `audit`, `auditd` | `kernel` | `kernel.log` |
| systemd security/account changes | `system` | `system.security_change`, `account.modification` |
| everything else | `generic` | `generic` |

`sshd-session` is the identifier used by OpenSSH 9.8+ on Debian 13 for
pre-authentication lines; it is handled the same as `sshd`. `dovecot`,
`postfix`, nginx and apache lines currently fall back to the generic parser
(the PAM prefix is still recognised). Dedicated file formats arrive with the
file-source slice.

Each event carries timestamp, origin, source, unit, identifier, priority, host,
pid, user, service, source IP (when derivable), action, outcome, template,
bounded message, parser name and journal cursor.

### Exactly-once detection

Detections are derived only when a **new** `log_events` row is inserted. If a
cursor is replayed, the insert is ignored and the detector is not run again, so
a restart cannot double-count a strike. Detection provenance stores the journal
cursor, identifier, template, user, service, source and a bounded evidence
line in the detection metadata (FR-310); the Logs page links the event to the
detection it produced.

## Log detectors

| ID | Behaviour | Threshold (default) | Disposition |
|---|---|---|---|
| DET-16 | SSH authentication failures from one source | 5 / 10 min | strike ladder |
| DET-17 | SSH success after failures from the same source | 1 success after ≥ 1 failure | alert only |
| DET-21 | PAM failure burst for any non-`sshd` service | 5 / 10 min per source | strike ladder |
| DET-23 | HTTP access-log path scan / 404 burst | 20 unique paths or 15 × 404/403 in 30 s | strike ladder |

DET-22 (sudo denial), DET-24 (system security change) and DET-25 (account
change) were retired in 0.3.10. Their templates are still parsed and stored as
log evidence, but they no longer emit detections or appear in the catalog.

Notes:

* DET-21 deliberately ignores PAM failures whose service or identifier is
  `sshd`; DET-16 already covers those, and counting both would double the
  strikes for one event.
* DET-16 counts `Invalid user` and `Failed password` lines as failures, but
  suppresses the `Failed password` line that follows an `Invalid user` line
  within two seconds for the same source and user, because both describe one
  attempt. Session-teardown lines (`Connection closed`, `Disconnected from`)
  are classified as `sshd.other`, so rapid distinct attempts still count.
* DET-17 clears that source's failure window after reporting, so one success
  does not produce a stream of alerts.
* Detections with no source (`0.0.0.0`) never block, even in enforce mode.

Thresholds and the shared window/cooldown live in `[logs.detection]`:

```toml
[logs.detection]
window_secs = 600
cooldown_secs = 300
ssh_failures = 5
pam_failures = 5
sudo_failures = 3
max_tracked_sources = 16384
detect_security_changes = true
detect_account_changes = true
```

`max_tracked_sources` bounds the per-source tables. If it is exceeded the
tables are cleared rather than grown without limit, matching the packet
engine's memory policy.

## Raw storage, retention and privacy

Journals contain usernames, paths, IP addresses and sometimes secrets. RustIPS
treats every log field as untrusted and deliberately limits what it keeps:

* messages are truncated to `max_message_bytes` (default 1024) **before** they
  are stored; control characters are neutralised and CRLF is normalised;
* `logs.store_raw = false` keeps the structured event and detection provenance
  but stores an empty message;
* `logs.redact` adds literal substrings to replace with `[redacted]`;
* raw events are pruned daily by `raw_retention_days` (default 7) and then by
  `raw_max_bytes` (default 128 MiB), oldest first;
* detections keep their own, longer retention under `[retention]`;
* no raw journal payload is stored beyond the bounded fields above, and full
  command lines/environment dumps are not stored by default.

The default retention is intentionally short. Increase it only if you accept
the privacy implications, and restrict access to `/var/lib/rustips/rustips.db`
(the file is root-owned by the unit).

## Viewing and debugging

The **Logs** page (`/logs`) lists newest first with filters for origin and a
free-text search over unit, identifier, source, template and message. Each row
shows the parser, template, unit/identifier, priority, user, source IP, the
bounded message and the detector name when the event produced one. The page
also shows journal health, this-process stored/rate-limited/parse-error
counters, a cumulative retention-prune count and a cursor-gap banner.

`rustips status` prints the stored log-event count and the journal state.
`rustips logs test` is the parser dry run and writes nothing:

```sh
sudo rustips logs test --since 10m
sudo rustips logs test --since 1h --limit 50
sudo rustips logs test --since "2026-11-19 12:00" --json | jq .
```

The `--since` value accepts the journal forms (`10m`, `1h`, `2d`) or an
absolute timestamp. The command exits non-zero if `journalctl` fails, with a
reminder about root/`systemd-journal`.

Useful checks on a live host:

```sh
journalctl -u ssh -n 20 --no-pager    # what sshd actually wrote
journalctl -t sudo -n 20 --no-pager   # sudo lines
sudo rustips detections --limit 20    # what RustIPS recorded
sudo rustips logs test --since 10m    # how the parsers see it
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `journal: degraded`, `journalctl: permission denied` | not root and not in `systemd-journal` | run under systemd, or `usermod -aG systemd-journal` and re-login |
| No new events after a restart | cursor is at the end; nothing new was logged | generate a login or use `logs test`; `backfill_secs` only applies on first start |
| `Cursor gap` banner | journal vacuumed or cursor invalid | expected; the reader has already fallen back to backfill. New events resume normally |
| DET-16 does not fire | failures are below 5 in 10 min, or the source is missing from the line | check `logs test`; adjust `ssh_failures`/`window_secs` |
| DET-21 does not fire for SSH | intentional: SSH PAM failures belong to DET-16 | none |
| `log events` grows but no detections | benign lines, or a threshold is too high | inspect templates on the Logs page; tune `[logs.detection]` |
| Database grows quickly | noisy unit or very long retention | add an `exclude_units` entry, lower `raw_retention_days`/`raw_max_bytes`, or set `store_raw = false` |

Rate limits are global (default 10,000 events/s) and per parser (default 2,000
events/s). When a limit is hit the event is dropped, counted in
`log_dropped`, and the cursor still advances, so a flood cannot stall
ingestion. A sustained breach should be treated as an operational signal even
before the dedicated FR-317 alert lands.

## Deferred in this slice

* file sources, inode/offset checkpoints, rotation and multi-line records
  (FR-319…335);
* DET-23 HTTP access-log scanning;
* dedicated dovecot/postfix/nginx/apache/syslog/JSON-lines parsers;
* the full filter set in the Logs page (priority, user, source IP, parser,
  time) and UI editing of `[logs]` (FR-313/314);
* the FR-317 log-flood detector;
* dual-source dedupe between journald and files (FR-332).
