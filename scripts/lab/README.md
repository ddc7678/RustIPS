# RustIPS lab VM

A disposable Debian 13 VM for the acceptance checks that cannot run on a
workstation: live packet capture, nftables enforcement, PAM login and the
first-run experience.

For the overall test workflow — unit tests, pcap replay, acceptance checks,
live attacks and deployment validation — see `docs/testing.md`. This document
focuses on the VM lifecycle and its networking.

The VM is plain QEMU plus `qemu-img`; there is no libvirt daemon. Guests use
user-mode NAT by default, with an optional second bridged NIC for attacks from
another host.

## 1. Host prerequisites

Required on the host running QEMU:

* `qemu-system-x86_64`, `qemu-img`
* `cloud-localds` (from `cloud-image-utils`) or `genisoimage`/`mkisofs`
* `curl`, `openssl`, `ssh`, `python3`
* an SSH key pair; `~/.ssh/id_ed25519` is used by default

`/dev/kvm` is recommended. Without it QEMU falls back to TCG, which is slow but
adequate for replay tests:

```sh
ls -l /dev/kvm                    # optional, but much faster
qemu-system-x86_64 --version
```

For bridged testing you also need an existing host bridge (default `br0`),
permission for QEMU's unprivileged bridge helper, and an uplink port on the
bridge. How the bridge is created is host-specific; on a NetworkManager host,
from a local console (not over the interface you are about to enslave):

```sh
LAN_IF=enp69s0          # find it with: ip -br link
LAN_CON="$(nmcli -t -f NAME,DEVICE connection show --active |
    awk -F: -v d="$LAN_IF" '$2 == d { print $1; exit }')"

sudo nmcli connection add type bridge ifname br0 con-name br0 stp no \
    ipv4.method auto ipv6.method auto
if [[ -n "$LAN_CON" ]]; then
    sudo nmcli connection modify "$LAN_CON" master br0
    # The master change only takes effect when the port is reactivated.
    sudo nmcli connection down "$LAN_CON"
fi
sudo nmcli connection up br0

# br0 needs an IPv4 address from the LAN and must list the uplink as a port:
ip -br addr show br0
bridge link show
```

If `br0` stays `DOWN` or stuck at "getting IP configuration" with no port
listed, the uplink was modified while it was active and never re-attached;
deactivate it and bring the bridge up again. To undo the bridge, clear the
master on the uplink profile and reactivate it.

This briefly interrupts connectivity on the uplink. If the uplink uses a
static address, move that configuration to `br0` rather than relying on DHCP.
Do not attach a physical interface to a bridge over the SSH connection you are
using without understanding the topology first.

QEMU runs unprivileged, so the bridge helper must be setuid root and the
bridge must be allowed explicitly:

```sh
sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper
echo 'allow br0' | sudo tee /etc/qemu/bridge.conf
```

`vm.sh start --bridged` checks the bridge, the helper and `bridge.conf` before
launching QEMU and prints the missing command instead of failing inside QEMU.
The existing VM does not need to be recreated; `vm.sh start --bridged` adds the
second NIC using the stored MAC and cloud-init network config.

## 2. Quick start

Create and boot a disposable NAT VM:

```sh
scripts/lab/vm.sh create --start
scripts/lab/vm.sh ssh
```

`create` downloads the Debian 13 genericcloud image, makes a qcow2 overlay,
generates a cloud-init seed, and creates the `rustips` sudo user (passwordless
sudo, key-only SSH). SSH is forwarded to `127.0.0.1:2222`.

The guest is provisioned on first boot with:

* `nftables`, `nmap`, `hydra`, `tcpdump`, `tcpreplay`, `jq`, `curl`,
  `python3`
* `hping3`, `gobuster`, `nikto` when the release ships them
* `rustips-admin` group, PAM test user `labadmin` in it, and `labuser` outside it
* key-only SSH, root login disabled

The generated password for both test users is in
`$HOME/.local/share/rustips-lab/rustips-lab/credentials.env` (mode `0600`):

```sh
scripts/lab/vm.sh credentials
```

The UI is loopback-only. Tunnel it from the host:

```sh
ssh -p 2222 -L 10707:127.0.0.1:10707 rustips@127.0.0.1
# browse http://127.0.0.1:10707/ and sign in as labadmin
```

## 3. Lifecycle commands

| Command | Purpose |
|---|---|
| `vm.sh create [--start] [--bridged]` | Download the image and create the VM |
| `vm.sh start [--bridged\|--nat]` | Boot and wait for SSH; remembers the stored network mode |
| `vm.sh stop [--force]` | Ask the guest to power off, then QMP/signal fallback |
| `vm.sh restart` | `stop` followed by `start` |
| `vm.sh status` | PID, network mode, disk size and snapshots |
| `vm.sh ssh [--] ARGS...` | SSH into the guest |
| `vm.sh ip` | Show guest addresses and the NAT/LAN MAC addresses |
| `vm.sh console` | Attach to the serial console; Ctrl-] detaches, guest keeps running |
| `vm.sh provision [--skip-apt]` | Re-run the guest provisioner over SSH |
| `vm.sh snapshot [NAME]` | Offline qcow2 snapshot (default `clean`) |
| `vm.sh restore [NAME] [--start]` | Restore an offline snapshot; takes a safety snapshot first |
| `vm.sh snapshots` / `delete-snapshot NAME` | Inspect or remove snapshots |
| `vm.sh destroy [--yes] [--base]` | Delete the disk/state; `--base` also deletes the shared image |
| `vm.sh credentials` | Print the generated credentials file |
| `vm.sh list` | List VMs under the VM root |

Options can be given in any order after the command. The defaults are:

| Setting | Default |
|---|---|
| VM name | `rustips-lab` |
| VM root | `$HOME/.local/share/rustips-lab` |
| vCPUs / memory / disk | 2 / 2G / 10G |
| SSH | `127.0.0.1:2222`, user `rustips` |
| Network | user-mode NAT |

Environment variables such as `VM_NAME`, `VM_DIR`, `CPUS`, `MEM`, `DISK_SIZE`,
`SSH_PORT`, `SSH_KEY`, `BRIDGED` and `BRIDGE` override the defaults. Use
`--name`/`--dir` to keep more than one VM. Each VM needs its own `--ssh-port`.

`create` is idempotent: if the disk already exists it prints the summary and
does not touch it. Use `create --force --yes` to destroy and recreate it.

The old `scripts/lab/create-vm.sh --launch` entry point still works as a
wrapper for `vm.sh create --start`.

## 4. NAT vs bridged networking

### User-mode NAT (default)

The guest is behind QEMU's `10.0.2.0/24` and is not reachable from the LAN. This
is the reproducible mode for replay tests and the UI. Host port forwards:

* `127.0.0.1:2222` → guest `:22`
* the UI is reached through the SSH tunnel above, not a separate forward

NAT rewrites source addresses, so it is not suitable for testing which real
source address triggered a block.

### Bridged second NIC

Create with a bridged NIC:

```sh
scripts/lab/vm.sh create --bridged --bridge br0 --start
```

The NAT NIC remains for management and SSH forwarding. The second NIC is
attached to the bridge and gets an address from the LAN's DHCP. The guest
network config gives the LAN NIC the lower route metric, so `capture.interfaces
= ["auto"]` follows the LAN default route automatically.

If the LAN does not provide a default route, or `auto` still picks the NAT NIC,
find the interface name and configure it explicitly:

```sh
scripts/lab/vm.sh ip
# inside the VM:
sudo sed -i 's/^interfaces = .*/interfaces = ["enp0s3"]/' /etc/rustips/config.toml
sudo systemctl restart rustips
```

`vm.sh status` and `vm.sh ip` print both MAC addresses. The LAN MAC is the one
to look for in `ip -br link`; the generated values are also in
`credentials.env`.

On boot, cloud-init sets DHCP on both NICs; the LAN NIC is optional, so a
missing bridge does not block boot. If you add bridging to an existing VM, check
that the guest has the second interface and bring it up with `dhclient`/`nmcli`
or re-run `vm.sh provision` after attaching it. `capture.interfaces = ["auto"]`
is resolved once when the daemon starts; if the LAN lease arrives after that,
restart `rustips` (or set the LAN interface explicitly) so the sensor follows
the LAN default route instead of the NAT NIC.

## 5. Deploy RustIPS into the VM

From the host, with the VM running:

```sh
scripts/deploy.sh rustips@127.0.0.1 --ssh-port 2222
```

The deploy script builds or reuses `target/release/rustips`, uploads it,
installs it at `/usr/local/bin/rustips`, runs `setup --install-service` on the
first install, enables and starts the systemd unit, and verifies the version,
`rustips status`, `rustips check` and the loopback `/healthz` endpoint.

Useful forms:

```sh
scripts/deploy.sh --build rustips@127.0.0.1 --ssh-port 2222
scripts/deploy.sh status rustips@127.0.0.1 --ssh-port 2222
scripts/deploy.sh upgrade rustips@127.0.0.1 --ssh-port 2222
scripts/deploy.sh rollback rustips@127.0.0.1 --ssh-port 2222
scripts/deploy.sh backups rustips@127.0.0.1 --ssh-port 2222
```

The first install leaves the default observe mode and loopback-only UI alone.
Upgrades stop the service, back up the binary, config, unit, PAM file and
database to `/var/backups/rustips/<stamp>`, replace the binary, restart and
verify. A failed verification rolls back automatically. The existing
configuration is never overwritten on upgrade.

See `scripts/deploy.sh --help` for `--prefix`, `--backup-dir`, `--keep`,
`--no-restart` and `--no-auto-rollback`.

## 6. Replay checks (no root, no network)

Copy the acceptance script into the VM (the deploy script only installs the
binary):

```sh
scp -P 2222 -r scripts rustips@127.0.0.1:/home/rustips/
ssh -p 2222 rustips@127.0.0.1
chmod +x /home/rustips/scripts/lab/run-tests.sh
/home/rustips/scripts/lab/run-tests.sh /usr/local/bin/rustips
```

This runs `setup`, `check`, the first-run recovery check, a synthetic capture
through DET-01/03/05/06, manual block/unblock, and loopback UI checks (health,
login page, unauthenticated redirect, Host guard, CSS and metrics) against a
throwaway state directory. Add `--install` as the second argument to exercise
`setup --install-service` (needs `sudo`).

The authenticated UI path (real PAM login, CSRF, manual block from the browser)
needs the system install and an account in `rustips-admin`. The lab provisioner
already created `labadmin`; use its password from `vm.sh credentials`.

## 7. Live capture and enforcement

With the VM bridged (see above), attack it from another host on the same L2
segment:

```sh
scripts/lab/attack.sh <vm-lan-ip>
```

Then inspect the sensor inside the VM:

```sh
sudo rustips status
sudo rustips detections --limit 50
```

The default is observe mode. Review detections, then switch to enforcement:

```sh
sudo sed -i 's/^mode = "observe"/mode = "enforce"/' /etc/rustips/config.toml
sudo systemctl restart rustips
scripts/lab/attack.sh <vm-lan-ip>
sudo nft list set inet rustips blocked_v4
sudo rustips status
```

Expected: DET-01/03/04/05/06 detections, one block per attacking source that
escalates through the ladder, and `nft list set` showing the blocked addresses.
The block survives `systemctl stop rustips` (failure policy) and is removed by
the daemon only after expiry.

## 8. Snapshot and restore

Take a snapshot after provisioning or after a known-good deployment:

```sh
scripts/lab/vm.sh stop
scripts/lab/vm.sh snapshot clean
```

Restore before a disruptive test:

```sh
scripts/lab/vm.sh restore clean --start
```

Snapshots are qcow2 internal snapshots and require the VM to be stopped; this
keeps the disk consistent. `restore` takes a `pre-restore-<timestamp>` safety
snapshot unless `--no-safety` is given. Use `vm.sh snapshots` to list them and
`vm.sh delete-snapshot NAME` to remove one. `snapshot --force` replaces an
existing name.

## 9. Reset

Delete one VM:

```sh
scripts/lab/vm.sh destroy --yes
```

The shared base image is kept for the next VM. Remove it too with `destroy
--base --yes`. To remove everything:

```sh
rm -rf "$HOME/.local/share/rustips-lab"
```

## 10. Troubleshooting

| Symptom | Check |
|---|---|
| `create` says the disk exists | Use `create --force --yes`, or set `--name`/`--dir` |
| `start` says port 2222 is in use | Give this VM a distinct `--ssh-port` |
| QEMU exits immediately | `vm.sh status`, `qemu.log` in the VM state directory |
| SSH never becomes ready | `vm.sh console`; check cloud-init and `ssh` in the guest |
| Bridged start fails | Bridge name/`ip link show br0`; QEMU bridge helper permissions |
| Guest has no LAN address | DHCP on the bridge; `vm.sh ip`; bring the second NIC up |
| UI not reachable | Use the SSH tunnel; the UI binds `127.0.0.1:10707` only |
| PAM login fails | Use `labadmin` and the password in `credentials.env`; check `getent group rustips-admin` |
| `rustips check` has no nftables | `sudo apt-get install nftables` in the guest |
| Host key changed after recreate | `rm .ssh/known_hosts` in the VM state dir, or destroy/recreate the state |

`vm.sh` falls back to TCG when `/dev/kvm` is unavailable. Boot and package
installation will be much slower; increase `SSH_WAIT` if needed.
