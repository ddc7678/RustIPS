# Operator runbook

This is the operational guide for a single-host RustIPS deployment: install,
first run, upgrades, recovery, day-2 checks and failure handling.

## Release artefact

RustIPS ships as one dynamically-linked Linux binary (Debian 13/x86-64 in the
lab). Build a checksummed artefact with:

```sh
scripts/release.sh
# dist/rustips-0.3.6-linux-x86_64
# dist/rustips-0.3.6-linux-x86_64.sha256
```

Verify before copying:

```sh
sha256sum -c rustips-0.3.6-linux-x86_64.sha256
```

## Install in ten minutes (TEST-39)

On a clean Debian 13 host with the binary copied to `/tmp/rustips`:

```sh
sudo /tmp/rustips setup --non-interactive --install-service
sudo systemctl enable --now rustips
sudo rustips check
sudo rustips status
```

`setup --install-service`:

* writes `/etc/rustips/config.toml` (0600) and `/var/lib/rustips` (0700);
* installs the running binary at `/usr/local/bin/rustips` (0755) so the copied
  `/tmp` file is no longer needed;
* installs `/etc/systemd/system/rustips.service`, creates `rustips-admin` if
  missing, and installs `/etc/pam.d/rustips` only if absent;
* never enables enforce mode and never starts the service itself.

The unit starts in **observe mode** (detections recorded, nothing blocked).
Open the loopback UI through a tunnel:

```sh
ssh -L 10707:127.0.0.1:10707 user@host
# browse http://127.0.0.1:10707/
```

Add an administrator, log out/in, and sign in with the system password:

```sh
sudo usermod -aG rustips-admin your-user
```

Review `rustips detections` and the dashboard. Generate a benign test detection
(e.g. `sudo useradd rustips-test` then `sudo userdel rustips-test`, or an SSH
failure burst) and confirm it appears. Only after review:

```sh
sudo sed -i 's/^mode = "observe"/mode = "enforce"/' /etc/rustips/config.toml
sudo systemctl restart rustips
```

Expected timing on the lab VM (no package manager or network needed): setup < 5
seconds, service ready < 2 seconds, UI health < 5 seconds. The ten-minute gate is
dominated by SSH/tunnel setup and admin-group login.

If PAM is unavailable, `sudo rustips auth breakglass` prints a one-time token;
paste it into the login page with the password empty.

### First-run safety (TEST-40)

* `setup --dry-run` writes nothing and prints every file it would write.
* A second `setup` refuses to overwrite an existing config unless `--force`.
* Missing config + existing database enters **recovery**; `rustips run` refuses
  to start and points at `setup --recover`. `--fresh` requires `--force` and
  archives the old DB under `state/backups/pre-fresh-*` first.
* An existing invalid config is a hard error with the path/line.
* `setup` never enables enforce mode or starts capture; it never overwrites an
  existing PAM file or systemd unit without `--force`.

Non-root automated checks: `cargo test --test cli`.

## Upgrade by binary replacement

Preferred (over SSH, with key-based sudo):

```sh
scripts/deploy.sh upgrade user@host
```

`deploy.sh` stages the binary, stops the service, backs up the binary, config,
unit, PAM file and database under `/var/backups/rustips/<stamp>`, installs
atomically, starts the service and verifies `status`, `check` and `/healthz`.
A failed verification rolls back automatically.

Manual equivalent:

```sh
sha256sum -c rustips-0.3.6-linux-x86_64.sha256
sudo systemctl stop rustips
sudo cp /usr/local/bin/rustips /usr/local/bin/rustips.prev
sudo install -m 0755 rustips-0.3.6-linux-x86_64 /usr/local/bin/rustips
sudo systemctl start rustips
sudo rustips check && sudo rustips status
```

Database migrations run automatically on first open (schema v10 since 0.3.13) inside
an immediate transaction. Back up `/var/lib/rustips/rustips.db` before a manual
upgrade. To roll back, stop the service, restore `rustips.prev` and the backup
DB if the downgrade refuses the schema, then start it.

## Day-2 checks

```sh
sudo rustips status
sudo rustips check
sudo rustips diagnose
curl -s http://127.0.0.1:10707/readyz | jq .
curl -s http://127.0.0.1:10707/metrics | grep rustips_
```

`diagnose` prints effective paths, root state, capture resolution, PAM,
nftables, DB size, rule/geo/alert state and recent audit. `readyz` reports
component readiness (database, journal, geo, nftables, PAM, alert queue,
capture counters); `/healthz` is the minimal liveness probe.

| Area | Routine |
|---|---|
| Detections/blocks | Inspect `rustips detections`, dashboard, active blocks and strikes; unblock false positives and allowlist known sources. |
| Rules | `rustips rules check` after edits; use `/rules/check` against recent detections before enabling a block rule. |
| Logs | Check `/logs` health and cursor gaps; `rustips logs test --since 10m` previews parsing. |
| Geo | `rustips geo status`; the updater runs every `[geo].update_hours` or on **Alerts → Check now**. |
| Alerts | **Alerts** page: target CRUD, queue depth, retries/failures, test alert. |
| Retention | Settings/Alerts show retention; daily prune aggregates detection counts and prunes raw logs/alerts. |
| Disk | `rustips status` DB size; raw log cap 128 MB, detection retention 30 days by default. |

## Failure runbook

### Service will not start

```sh
sudo systemctl status rustips --no-pager
sudo journalctl -u rustips -n 100 --no-pager
sudo rustips check
sudo rustips diagnose
```

Common causes: invalid config (path/line in the error), missing state dir or
permissions, nftables missing in enforce mode, recovery state (config deleted),
or a port conflict on the UI. Fix the cause; do not delete the DB to "reset"
unless you have a backup.

### UI unreachable

The UI is loopback-only by default. Confirm the unit is running, the configured
bind/port, and use an SSH tunnel. A non-loopback bind requires an explicit
confirmation; a saved override that cannot bind is removed on restart and the
file value is used (audited). If PAM is broken, use break-glass.

### Changing detection parameters

The Detectors page stores parameter overrides in SQLite. They are validated
before storage and applied after `config.toml` at daemon start, so:

```sh
sudo systemctl restart rustips
sudo rustips check          # prints "overrides: N applied"
```

Use **Reset to default** on one field, **Reset this group** on a detector/shared
panel, or **Reset all overrides** to fall back to the configuration file. If an
override is invalid, `rustips check` and daemon start fail with a
`stored detection overrides: …` message; reset it in the UI or remove the
`detection.overrides` setting from SQLite after taking a backup.

### Honeypot

Honeypot mode is disabled by default. Configure it in **Settings → Honeypot**:
tick **Enable honeypot** and list unused TCP/UDP ports. After 3 TCP SYN/UDP
contacts in the detection window, DET-26 fires and the shipped
**Honeypot block after 3 contacts** disposition rule blocks the source through
the ladder. Edit the contact threshold on the same Settings panel. Changes
apply after `sudo systemctl restart rustips`. Do not list active service ports
or the RustIPS web port.

### Journal degraded / no log events

```sh
sudo systemctl status systemd-journald
sudo journalctl -u rustips -n 30 --no-pager | grep -i journal
sudo -u root rustips logs test --since 10m
```

The unit has `SupplementaryGroups=systemd-journal`; a foreground run needs root
or that group. Packet capture and enforcement continue while the journal is
degraded. A cursor-gap banner means the journal was vacuumed or the stored
cursor was invalid; the reader falls back to the configured backfill.

### Enforce mode but no blocks

`rustips check` shows nftables availability. Blocks are derived from SQLite and
reapplied at startup; check `rustips detections`, the `detections.allowed` /
`would_block` audit, and the active/allowlist state. A missing `nft` is a hard
failure only in enforce mode.

### PAM outage / lockout

`sudo rustips auth test --user NAME` identifies the failing stage. Use
`sudo rustips auth breakglass` for a one-time UI session, repair PAM/SSSD, then
log in normally. Break-glass sessions are marked in the UI and audited.

### Database corruption or full disk

Stop the service, copy the DB/WAL/SHM aside, and restore the most recent
`/var/backups/rustips/*/rustips.db` or `state/backups/pre-fresh-*`. Start the
service and run `rustips check`. Prune via retention or lower
`raw_retention_days`/`raw_max_bytes`; the default budget is 512 MB.

### Uninstall

```sh
sudo systemctl disable --now rustips
sudo rustips flush --yes          # removes blocks; required before removing the binary
sudo rm -f /etc/systemd/system/rustips.service
sudo systemctl daemon-reload
# keep /etc/rustips and /var/lib/rustips if you may reinstall
```

`flush` is explicit because stopping the service leaves blocks in place by
design (fail-static).

## Release checklist

1. `cargo fmt --check && cargo clippy --all-targets && cargo test`.
2. `scripts/scorecard.sh` and publish `docs/coverage/<version>.{md,json}`.
3. `scripts/release.sh`; record size and checksum.
4. Lab VM: clean install or upgrade, `check`, `status`, `/readyz`, UI login,
   one detection, one alert target, one geo lookup.
5. Update `CHANGELOG.md`, `docs/iterations/<version>.md`, README status/links.
6. For a binary upgrade, verify rollback with `scripts/deploy.sh rollback`.
