# Testing RustIPS

This guide covers the test and validation tools that ship with the repository.
They are layered so that most checks run on a workstation and only the checks
that genuinely need a guest kernel, PAM or nftables move into the lab VM.

| Layer | Tool | Needs root? | Needs a network? | Proves |
|---|---|---|---|---|
| Unit + integration | `cargo test` | no | loopback only | detectors, config, auth, sessions, replay, web UI |
| Synthetic replay | `scripts/gen_test_pcap.py` + `rustips run --pcap` | no | no | decode → detect → SQLite for DET-01/03/05/06 |
| Acceptance | `scripts/lab/run-tests.sh` | only `--install` | loopback only | setup/check/replay/UI/manual block against a release binary |
| Lab VM | `scripts/lab/vm.sh` | no on the host | NAT or bridged | first boot, PAM login, nftables, packaging |
| Live attacks | `scripts/lab/attack.sh` | yes (raw sockets) | same L2 segment | detector behaviour on real packets and enforcement |
| Deployment | `scripts/deploy.sh` | target sudo | SSH | install, upgrade, backup, rollback, service health |

Start with `cargo test` and `run-tests.sh`; use the VM only for the rows that
need it. `scripts/lab/README.md` is the detailed VM and deployment manual; this
document is the testing workflow.

## 1. Unit and integration tests

```sh
cargo test
cargo clippy --all-targets
cargo fmt --check
```

The suite is currently 160 tests: 146 library tests, one pcap replay test
(`tests/replay.rs`), three robustness tests (`tests/robustness.rs`), two
webhook delivery tests (`tests/alerts.rs`), six CLI first-run/recovery/override
tests (`tests/cli.rs`), one coverage scorecard (`tests/scorecard.rs`) and one
web UI test (`tests/web.rs`). The integration tests
use throwaway SQLite files and a loopback listener, so they do not touch
`/etc/rustips`, `/var/lib/rustips`, PAM or nftables.

The web test exercises the break-glass path, so it runs without
`/etc/pam.d/rustips`. A real PAM password login is covered only in the lab VM.
It also seeds a log event and log detection and asserts the Logs page renders
and escapes them, exercises webhook target add/edit/delete plus the Alerts
queue and test button, and checks the Detectors page, DET-12 details,
single-button detector state toggles, editing and resetting
`http_bad_paths`/`http_login_paths`, rejection of an out-of-range value, the
reset-one/group/all actions, collapsible grouped navigation, flash-free theme
delivery, single-button detector/rule state toggles, honeypot
validation/save/reset, the clickable IP-history API/dialog, resource-graph
sampling/API and the left sidebar.

To run just one area:

```sh
cargo test detect
cargo test rules
cargo test geo
cargo test detect::http
cargo test config
cargo test --test cli
cargo test --test replay
cargo test --test robustness
cargo test --test alerts
cargo test --test scorecard -- --nocapture
cargo test --test web
```

Use `RUSTIPS_CONFIG` and `RUSTIPS_STATE_DIR` for manual experiments that must
not touch an installed instance:

```sh
export RUSTIPS_CONFIG=/tmp/rustips-test/config.toml
export RUSTIPS_STATE_DIR=/tmp/rustips-test/state
```

## 2. Deterministic packet replay (no VM)

`scripts/gen_test_pcap.py` builds a capture with four known attacks from
TEST-NET sources:

| Traffic | Detector |
|---|---|
| 25-port TCP SYN scan | DET-01 |
| 25-port empty-payload UDP scan | DET-05 |
| Five FIN-only probes | DET-03 |
| 20-host ICMP echo sweep | DET-06 |

The TCP and UDP detectors only look at traffic addressed to the local machine,
so the destination must be one of this host's addresses:

```sh
WORK="$(mktemp -d /tmp/rustips-replay.XXXXXX)"
export RUSTIPS_CONFIG="$WORK/config.toml"
export RUSTIPS_STATE_DIR="$WORK/state"
DEST="$(hostname -I | awk '{print $1}')"

cargo run -- setup --non-interactive
python3 scripts/gen_test_pcap.py "$WORK/scan.pcap" "$DEST"
cargo run -- run --pcap "$WORK/scan.pcap" --fast-replay --no-web

cargo run -- detections --limit 20
cargo run -- status
```

`--fast-replay` ignores capture timestamps and finishes immediately. Without
it the daemon keeps the file's timing; the acceptance script works around that
by rewriting the timestamps into the future when it needs the UI to stay up.

Expected result: DET-01, DET-03, DET-05 and DET-06 appear in `detections`, and
`status` shows 0 active blocks because the fresh configuration is in
`observe` mode.

For a throughput baseline, `scripts/gen_bench_pcap.py` emits a large benign
capture (default 500,000 packets) that exercises decode and the bounded source
table without triggering detectors:

```sh
python3 scripts/gen_bench_pcap.py "$WORK/bench.pcap" "$DEST" 200000
time cargo run --release -- run --pcap "$WORK/bench.pcap" --fast-replay --no-web
```

## 3. Lab acceptance script

`scripts/lab/run-tests.sh` runs the 0.2.x acceptance checks against a release
binary. It writes everything to a throwaway directory under `/tmp`, so it is
safe on a host with an existing installation.

```sh
cargo build --release
scripts/lab/run-tests.sh ./target/release/rustips
```

Inside the VM, from the repository root:

```sh
scripts/lab/run-tests.sh /usr/local/bin/rustips
```

It checks:

1. `setup` creates the config (mode `0600`), state directory and database.
2. `check` passes.
3. A missing config with an existing database refuses to start.
4. Replay of the generated capture produces DET-01/03/05/06 and records no
   blocks in observe mode.
5. The UI on `127.0.0.1:10710` returns health, login page, an unauthenticated
   `303`, a `421` for a foreign `Host`, CSS and metrics.
6. A manual block is recorded, removed, and refused for an allowlisted range.

Pass `--install` as the second argument to also exercise
`setup --install-service` (this needs `sudo`):

```sh
scripts/lab/run-tests.sh /usr/local/bin/rustips --install
```

The `--install` section verifies the systemd unit, the PAM service file, the
`rustips-admin` group and `systemd-analyze verify`.

The script prints `PASS`/`FAIL` per check and a summary; the exit status is
non-zero if any check failed. It requires `python3` and `curl`.

## 4. Live attacks against the VM

The replay checks use synthetic packets. To see real packets on a real
interface, give the VM a bridged NIC and attack it from another host on the
same segment (`scripts/lab/README.md` explains the bridge setup):

```sh
scripts/lab/vm.sh create --bridged --bridge br0 --start
# another host on the LAN:
sudo scripts/lab/attack.sh <vm-lan-ip>
```

The bridge and the unprivileged QEMU helper must already be set up (the
NetworkManager recipe and `bridge.conf` are in `scripts/lab/README.md`);
`vm.sh start --bridged` stops with the exact missing command if they are not.
An existing NAT-only VM can be restarted with `--bridged`; it does not need to
be recreated.

The guest keeps `10.0.2.15` on its NAT NIC even when bridged. That address is
never reachable from the host. The LAN address is the second IPv4 address, on
the interface whose MAC matches `vm.sh ip`'s `LAN MAC`.

`capture.interfaces = ["auto"]` is resolved once at daemon start. If the LAN
DHCP lease arrives after `rustips` starts, restart the service so `auto` picks
the LAN default route; the log line should say `capturing ifname="enp0s4"`.

`attack.sh` needs `nmap` and uses raw sockets (`-sS`, `-sU`, `-sF`, `-sX`,
`-sN`, `-sA`), so run it as root or with `CAP_NET_RAW`. `hping3` is used for the
echo flood when present. Modes:

| Mode | Detector(s) |
|---|---|
| `syn` (or `all`) | DET-01 |
| `udp` | DET-05 |
| `stealth` | DET-03 |
| `ack` | DET-04 |
| `icmp` | DET-06 |

Inspect the sensor inside the VM:

```sh
sudo rustips status
sudo rustips detections --limit 50
```

Observe mode records detections and applies nothing. To test enforcement,
switch the VM to enforce mode, restart, attack again, then check the block set:

```sh
sudo sed -i 's/^mode = "observe"/mode = "enforce"/' /etc/rustips/config.toml
sudo systemctl restart rustips
sudo nft list set inet rustips blocked_v4
sudo rustips status
```

QEMU user-mode NAT cannot be reached from the LAN; use it for replay and UI
tests, not for source-address realism or live attacks. The VM keeps SSH on the
NAT NIC (`127.0.0.1:2222` by default) even in bridged mode.

### Host-log validation

Journal ingestion is on by default after the upgrade, so the deployed daemon
already reads the guest journal. Check the state and preview the parsers:

```sh
ssh -p 2222 rustips@127.0.0.1 'sudo rustips status'
ssh -p 2222 rustips@127.0.0.1 'sudo rustips logs test --since 10m'
ssh -p 2222 rustips@127.0.0.1 'sudo journalctl -u rustips -n 10 --no-pager'
```

The startup line should include `logs=true` and
`journal ingestion started resumed=true` after the first start.

Generate real log events from the host:

```sh
# DET-16: five bad SSH users from the bridged host address
for i in 1 2 3 4 5; do
  ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      baduser@<vm-lan-ip> true
done

# DET-17: a successful key login from the same source
ssh rustips@<vm-lan-ip> true
```

PAM failures for non-ssh services are easiest to inject synthetically in the
guest, because the parsed source comes from `rhost=`:

```sh
for i in 1 2 3 4 5; do
  logger -p auth.warning -t dovecot \
    'pam_unix(dovecot:auth): authentication failure; rhost=203.0.113.50 user=mail'
done
```

DET-23 fires on access-log path scans when the access log reaches the journal.
The old internal DET-22/24/25 detectors were retired in 0.3.10. Then inspect:

```sh
sudo rustips detections --limit 20
sudo rustips logs test --since 5m
```

In observe mode no block should appear (`blocks: 0`, `strikes: 0`) even for
DET-16/21. Restart the service and confirm the next start says `resumed=true`
without duplicating cursor rows. The Logs page shows the same events and a
`Cursor gap` banner only when the stored cursor could not be resumed; see
`docs/logs.md` for the full operator guide.

### Rule validation

After upgrading, confirm the schema migration seeded the defaults and that the
daemon and CLI agree:

```sh
sudo rustips rules check
sudo rustips rules list
sudo rustips status | grep rules
```

`rules check` exits non-zero with a precise rule/field error if the stored set
is invalid. Exercise the editor through the tunnel, or from the VM:

```sh
TOKEN=$(sudo rustips auth breakglass --minutes 5 | grep -Eo '[0-9a-f]{64}' | head -1)
curl -s -c /tmp/r.c -d "user=root&token=$TOKEN" http://127.0.0.1:10707/login
CSRF=$(curl -s -b /tmp/r.c http://127.0.0.1:10707/rules \
  | grep -o 'name="csrf" value="[a-f0-9]*"' | head -1 | sed 's/.*value="//;s/"//')
curl -s -b /tmp/r.c -d "id=0&name=VM+test&priority=500&severity=critical&enabled=yes&detectors=DET-21&action=block_temp&duration=3h&csrf=$CSRF" \
  http://127.0.0.1:10707/rules/save
sleep 2
sudo journalctl -u rustips -n 5 --no-pager | grep "rules reloaded"
```

Generate a DET-21 burst (the synthetic `logger` lines above) and check the audit
detail: in observe mode it should say `detection.would_block` with
`rules=<ids> winner=<test rule id>` and the 3-hour duration. Delete the rule
afterwards; the four defaults are unaffected.

The rule "dry-run against recent detections" page (`/rules/check`) evaluates the
last 100 stored detections with their current history and writes nothing. Use it
after editing thresholds to see false positives before enforcing.

### HTTP and geo validation

The HTTP detectors need a clear-text server on a configured port
(`detection.http_ports`, default 80/8080/8000/8888). On the lab guest, a small
Python handler can return 401 for `/login`, 404 for `/missing*` and 200
otherwise. Start it detached so it survives the SSH command:

```sh
setsid --fork python3 /tmp/httpsrv.py >/tmp/httpsrv.log 2>&1 </dev/null
```

From the bridged host, generate the five patterns:

```sh
H=192.168.12.153
for i in $(seq 0 19); do curl -s -o /dev/null "http://$H:8000/p$i"; done   # DET-11
curl -s -o /dev/null "http://$H:8000/wp-login.php"                         # DET-12
for i in $(seq 1 10); do curl -s -o /dev/null "http://$H:8000/login"; done # DET-13
for i in 1 2 3; do curl -s -o /dev/null -X TRACE "http://$H:8000/"; done   # DET-14
for i in $(seq 1 110); do curl -s -o /dev/null "http://$H:8000/flood" & done; wait # DET-15
```

Then `sudo rustips detections | grep DET-1` and inspect the audit disposition.
A LAN source is implicitly allowlisted, so expect `detection.allowed` with the
HTTP rule as winner and no block in observe mode. Stop the server afterwards.

For geo:

```sh
sudo rustips geo update             # downloads + verifies + builds
sudo rustips geo status
sudo rustips geo lookup 1.0.1.5     # CN
sudo rustips geo lookup 8.8.8.8     # US / ASN 15169
```

The daemon reloads a CLI-installed index within a few seconds (`geo indexes
reloaded from disk`). Build a temporary `country=CN` rule, insert a synthetic
detection for `1.0.1.5` (or use `/rules/check`), and confirm the rule wins;
delete the rule and synthetic row afterwards. `docs/iterations/0.3.2.md` has the
full lab record.

### Webhook, slow-scan and sample validation

**Webhook.** Run a local receiver that returns 500 on the first POST and 200
afterwards, then add and enable a target on **Alerts** with
`http://127.0.0.1:19090/hook`, events `all`, minimum severity `info`, and
generate a detection (an SSH/PAM burst is easy). The target is stored in SQLite;
no restart is needed. After a few seconds:

```sh
sudo rustips status | grep alerts
sudo journalctl -u rustips --since 2m --no-pager | grep webhook
```

Expect a retry line, then `0 pending · N delivered · 0 failed`. The receiver
should have two bodies for the first event (500 then 200). Disable/delete the
target and remove the temporary receiver afterwards. `tests/alerts.rs` is the
automated delivery check; `tests/web.rs` covers target add/edit/delete through
the UI.

**DET-20.** The production thresholds (30 ports / 600 s) are intentionally
slow to test. Temporarily set `slow_scan_ports = 5`,
`slow_scan_window_secs = 120`, `slow_scan_max_per_window = 10` in
`[detection]`, restart, and run from the host:

```sh
nmap -sT -Pn -p 2001-2005 --scan-delay 2s 192.168.12.153
```

Then `sudo rustips detections | grep DET-20`. Restore the defaults and restart.
The unit tests cover both the slow and fast cases.

**Sample geo rules.** Open **Rules → Sample geo rules → Load sample geo rules**
(or `rustips rules samples --json > /tmp/geo-rules.json` and import it). The
five rules appear disabled; `rustips rules list` shows `enabled=no`. They do
not change enforcement until enabled. See `docs/geo-rules.md`.

### Coverage scorecard (TEST-37)

```sh
scripts/scorecard.sh
# or:
cargo test --test scorecard -- --nocapture
```

The scorecard runs deterministic attack cases for every implemented detector
plus a benign corpus. It prints a per-detector PASS/MISS table, writes
`target/scorecard.json`, and fails if any case misses or a benign input alerts.
The published result is `docs/coverage/0.3.4.md` / `.json`; update both for
each release. The corpus lives in `tests/scorecard.rs` and is intentionally
versioned with the source.

The gate is "≥ 97% of the defined corpus detected and blocked, zero benign
false-positive blocks". The 0.3.4 run reports 23/23 defined detectors, 0 benign
alerts and 0 blocks; DET-18 escalation is verified separately in the daemon
tests. Keep the caveats in the published scorecard: synthetic corpus, DET-23
requires access logs in the journal, and DET-02 only sees local destinations.

## 5. VM lifecycle and clean state

The usual lab loop is: create, provision, snapshot, test, restore. Full details
are in `scripts/lab/README.md`; the commands used by tests are:

```sh
scripts/lab/vm.sh create --start          # download image, boot, wait for SSH
scripts/lab/vm.sh ssh                     # sudo user: rustips
scripts/lab/vm.sh credentials             # labadmin/labuser PAM passwords
scripts/lab/vm.sh stop
scripts/lab/vm.sh snapshot clean          # offline qcow2 snapshot
scripts/lab/vm.sh restore clean --start   # safety snapshot taken first
```

Take the `clean` snapshot after provisioning and before a destructive test
(enforce mode, service install, upgrades). `restore` requires the VM to be
stopped and creates a `pre-restore-<timestamp>` snapshot unless `--no-safety`
is given.

Guest test accounts:

* `labadmin` — member of `rustips-admin`; can sign in to the UI.
* `labuser` — outside the group; PAM succeeds but authorisation is denied.

## 6. Deployment validation

### First-run install (TEST-39)

On a clean host/snapshot with no `/etc/rustips/config.toml`:

```sh
scripts/lab/first-run.sh --binary target/release/rustips user@host
```

The script copies the binary to `/tmp`, runs `setup --non-interactive
--install-service`, starts the unit, waits for `/healthz`, runs `check`/`status`
and fails if the elapsed time reaches 600 s. It refuses a host that already has
a config. `setup` installs the binary at `/usr/local/bin/rustips`, so the
`/tmp` copy is not referenced by the unit.

The 0.3.6 RC run on a newly created Debian 13 VM completed in **9 s**.
For the first-block half of the gate, switch to enforce mode, replay a pcap
with `rustips run --pcap FILE --fast-replay --no-web`, restart the service and
check `nft list set inet rustips blocked_v4`; the RC run created four active
blocks.

### Soak sampling

```sh
scripts/lab/soak.sh --duration 300 --interval 15
```

Run on the sensor host (root or passwordless sudo). It writes JSONL and fails
on RSS >512 MiB, any service restart, capture drops >1%, or a 30-day DB
projection >256 MiB. The 0.3.6 record is `docs/soak/0.3.6.md`; it is a short lab
soak, not the 30-day 1.0 soak.


`scripts/deploy.sh` is also a test tool: it verifies the first-install path,
upgrades and rollback against a real host. Begin with a dry run, which does not
contact the host:

```sh
scripts/deploy.sh --dry-run rustips@127.0.0.1 --ssh-port 2222
```

Then install, re-run the acceptance checks against the installed binary, and
exercise the upgrade and rollback paths:

```sh
scripts/deploy.sh --build rustips@127.0.0.1 --ssh-port 2222
scp -P 2222 -r scripts rustips@127.0.0.1:/home/rustips/
ssh -p 2222 rustips@127.0.0.1 \
    '/home/rustips/scripts/lab/run-tests.sh /usr/local/bin/rustips --install'

scripts/deploy.sh upgrade rustips@127.0.0.1 --ssh-port 2222
scripts/deploy.sh backups rustips@127.0.0.1 --ssh-port 2222
scripts/deploy.sh rollback rustips@127.0.0.1 --ssh-port 2222
scripts/deploy.sh status rustips@127.0.0.1 --ssh-port 2222
```

An upgrade stops the service, backs up the binary, configuration, unit, PAM
file and database under `/var/backups/rustips/<stamp>`, replaces the binary and
verifies the service. A failed health check rolls back automatically unless
`--no-auto-rollback` is given. The configuration is preserved across upgrades.

A failed verification (for example, the UI health endpoint never becomes
ready) is the rollback path worth exercising on a lab host: the script restores
the previous binary, configuration and database before exiting non-zero.
`--no-restart` installs without starting the service, which is useful when
validating packaging only.

## 7. Choosing a workflow

| Goal | Run |
|---|---|
| Change detector, config, session or page code | `cargo test` |
| Check a capture end to end | `gen_test_pcap.py` + `run --pcap` |
| Check the whole binary without a VM | `scripts/lab/run-tests.sh` |
| Check PAM login, nftables, systemd, packaging | lab VM + `--install` |
| Check real packet handling and blocks | bridged VM + `attack.sh` |
| Check install/upgrade/rollback over SSH | `scripts/deploy.sh` |
| Measure throughput | `gen_bench_pcap.py` |

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| Replay reports no detections | Destination IP is not a local address; regenerate with `hostname -I` |
| Replay exits immediately | Normal: offline replay stops at EOF; it is not a crash |
| Guest has only `enp0s2` / `10.0.2.15` | VM is NAT-only: `vm.sh status`; restart with `--bridged` after creating `br0` |
| `ping 10.0.2.15` fails from the host | Expected: that address is inside QEMU user-mode NAT; use `vm.sh ssh` or `127.0.0.1:2222` |
| Detections counter stays 0 after bridging | The daemon resolved `auto` before the LAN DHCP lease arrived. Restart it (`sudo systemctl restart rustips`) and check the log says `capturing ifname="enp0s4"` |
| Recent detections shows rows but the live counter is 0 | Rows persist across restarts; the "since start" value is for the current daemon. The dashboard card now shows the stored total and the Live panel shows the since-start count |
| `--bridged` refuses to start | Missing `br0`, setuid helper, or `allow br0` in `/etc/qemu/bridge.conf` |
| `br0` is `DOWN` or stuck "getting IP configuration" | Uplink profile was modified but not reactivated; `bridge link show` is empty. Run `nmcli connection down "<uplink>"`, then `nmcli connection up br0` |
| `run-tests.sh` UI checks fail | Port 10710 is in use, or `curl` is missing |
| `run-tests.sh --install` fails | Not running under `sudo`, or `systemd-analyze` is absent |
| `attack.sh` reports no packets | Target is on QEMU NAT; use a bridged NIC |
| `attack.sh` gets permission errors | Raw scans need root or `CAP_NET_RAW` |
| `deploy.sh` refuses the host | Not Debian 13, no passwordless sudo, or `--allow-unsupported-os` not set |
| Rollback says no usable backup | No upgrade has run yet, or `--to` names a directory without `backup.tar.gz` |
| PAM login denied in the VM | User is not in `rustips-admin`, or the session predates the group change (log out and back in) |

## 9. Cleanup and safety

`run-tests.sh` and the replay examples use temporary directories and remove
them on exit. Remove a manual `WORK` directory when finished. Tear down the VM
with:

```sh
scripts/lab/vm.sh destroy --yes          # keep the shared base image
scripts/lab/vm.sh destroy --yes --base   # remove the image too
```

Only run `attack.sh` against your own lab VM or an address you are authorised
to test. The generated pcaps use reserved ranges (TEST-NET sources and the
`198.18.0.0/15` benchmarking range) and are safe to replay anywhere.
