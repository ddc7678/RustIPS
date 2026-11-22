# Webhook alerts

RustIPS speaks one outbound alert channel: a generic JSON `POST` webhook
(FR-204). SMTP, chat and push integrations are intentionally built outside the
daemon; `scripts/webhook-email-bridge.py` is a working e-mail bridge.

## Targets

Webhook destinations are managed entirely in the UI under **Alerts**:

* **Add target** — name, URL, events (`all`, `detections` or `operational`),
  minimum severity, timeout, retries, dedupe window and queue cap.
* **Edit** — change any field; disabling a target drops its pending rows.
* **Delete** — removes the target and its pending rows; delivered/failed
  history remains with the target name if it still exists.
* Each enabled target gets its own queue rows, retries and dedupe bucket.

Targets are stored in SQLite (`alert_targets`). The `[alerts]` config section is
now a one-time bootstrap plus a global retention default:

```toml
[alerts]
enabled = false        # bootstrap only
url = ""               # if set on first start, seeds "Default webhook"
retention_days = 7     # default for delivered/failed row pruning
```

On the first start after upgrading, a non-empty `[alerts].url` creates a
"Default webhook" target using the other `[alerts]` values. After that the UI
is authoritative; deleting all targets does not recreate them from the file.
The retention value can be changed on the Alerts page (stored as an override).

Per-target fields:

| Field | Meaning |
|---|---|
| `events` | `all`, `detection` or `operational` |
| `min_severity` | compared with the winning disposition rule's severity; no-match alerts are `info` |
| `timeout_secs` | per-POST timeout (1–60) |
| `max_retries` | retries after the first attempt (0–20) |
| `rate_limit_secs` | dedupe bucket for `detector + source + action` |
| `queue_max` | pending rows for this target; oldest dropped first |

Delivery uses the system `curl` binary, so HTTPS works without adding a TLS
stack to RustIPS. `rustips check` warns if enabled targets exist but `curl` is
missing.

## Payload

Detection example:

```json
{
  "event": "detection",
  "version": "0.3.3",
  "timestamp": "2026-11-21T00:00:00Z",
  "detection_id": 123,
  "detector": "DET-12",
  "detector_title": "HTTP known-bad path probe",
  "severity": "warning",
  "src": "203.0.113.50",
  "dst": "192.0.2.10",
  "dst_port": 80,
  "proto": "tcp",
  "count": 1,
  "window_secs": 1,
  "action": "blocked",
  "rule_id": 6,
  "rule_name": "HTTP detectors escalate",
  "matched_rules": [6, 5],
  "tags": [],
  "dry_run": false,
  "country": "CN",
  "asn": 64500,
  "first_seen": "2026-11-20T23:59:59Z",
  "last_seen": "2026-11-21T00:00:00Z"
}
```

`action` is one of `blocked`, `observed` (global observe mode), `dry_run`,
`alert`, `allow`, `tag`, `allowed` (allowlisted source), `alert_no_source` or
`alert_no_match`. Raw log messages and full detection metadata are **not** in
the payload; they remain in the local Logs/Detections views.

Operational alerts use the same channel:

```json
{
  "event": "operational",
  "version": "0.3.3",
  "timestamp": "2026-11-21T00:00:00Z",
  "kind": "geo.update_failed",
  "message": "curl failed for ..."
}
```

## Queue and retry semantics

* Enqueue is a small SQLite insert in the detection path, one row per enabled
  matching target; delivery runs in its own thread and never blocks capture,
  detection or enforcement.
* The queue survives restarts. Delivered rows are marked and are not selected
  again. Delivery is at-least-once: a crash after the remote endpoint accepted
  a POST but before the local mark can resend that event.
* A failed POST increments `attempts` and schedules a retry with exponential
  backoff (5 s, 10 s, 20 s, 40 s, 80 s, capped at 300 s) until that target's
  `max_retries` is exhausted. After that the row is marked `failed` and is not
  retried forever.
* Duplicate detector/source/action events inside a target's `rate_limit_secs`
  share one dedupe key and produce one alert for that target.
* Delivered/failed rows are pruned after the UI retention setting (default
  from `[alerts].retention_days`); pending rows are bounded per target by
  `queue_max`.

## Visibility

* The **Alerts** page manages targets (add/edit/delete), lists
  pending/delivered/failed rows with payloads, and lets an operator send a
  test, retry/send-now, delete a row, clear delivered/failed history, or change
  queue retention.
* `rustips status` prints pending/delivered/failed queue counts.
* `/metrics` exports `rustips_alerts_pending`, `rustips_alerts_failed`,
  `rustips_alerts_sent_total` and `rustips_alerts_queued_total`.
* `/api/summary` includes `alerts_pending`, `alerts_failed`, `alerts_sent` and
  `alerts_queued`.
* Settings shows the webhook status, URL, threshold, queue counts and last
  error. `rustips check` warns when alerting is enabled but `curl` is missing.

## E-mail bridge

`scripts/webhook-email-bridge.py` is a small Python 3 (standard library only)
HTTP service that accepts the webhook and sends e-mail through SMTP or a local
`sendmail`:

```sh
RUSTIPS_EMAIL_TO=admin@example.net \
RUSTIPS_EMAIL_FROM=rustips@example.net \
RUSTIPS_SMTP_HOST=mail.example.net \
RUSTIPS_SMTP_PORT=587 \
RUSTIPS_SMTP_USER=rustips \
RUSTIPS_SMTP_PASS='...' \
  ./scripts/webhook-email-bridge.py
```

It listens on `127.0.0.1:9090/hook` by default; set `RUSTIPS_BRIDGE_LISTEN` to
change that. Point `[alerts].url` at the bridge. The script supports:

```sh
./scripts/webhook-email-bridge.py --self-test      # print a sample message
./scripts/webhook-email-bridge.py --dry-run --once # one request, no e-mail
```

Example systemd unit (run as a dedicated unprivileged user, keep secrets in an
`EnvironmentFile` with mode 0600):

```ini
[Unit]
Description=RustIPS webhook to e-mail bridge
After=network-online.target

[Service]
Type=simple
User=rustips-bridge
EnvironmentFile=/etc/rustips/bridge.env
ExecStart=/opt/rustips/scripts/webhook-email-bridge.py
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

## Security notes

* The bridge binds loopback by default. If it must listen elsewhere, put TLS
  and authentication in front of it; RustIPS does not sign payloads and the
  webhook URL may contain a bearer token.
* Treat the webhook URL as a secret. The config file is 0600; the Settings page
  shows the URL to authenticated administrators.
* The payload excludes raw log lines, full HTTP request bodies, credentials and
  command lines.

## Testing

`tests/alerts.rs` exercises the queue against a local server: the first POST
returns 500, the retry succeeds, the delivered row survives reopening the
database, dedupe suppresses a duplicate, and a permanently failing endpoint is
marked failed rather than retried forever. Run it with:

```sh
cargo test --test alerts
```

For an end-to-end check on the lab VM, point `[alerts].url` at the bridge or a
local listener, enable alerting, restart RustIPS, generate a detection, and
watch the queue drain in Settings/`rustips status`.
