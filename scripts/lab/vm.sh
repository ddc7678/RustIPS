#!/usr/bin/env bash
# Lifecycle management for the RustIPS Debian 13 lab VM.
#
# Plain QEMU/qemu-img: no libvirt, no daemon, no root on the host. Guests use
# user-mode NAT by default (SSH on 127.0.0.1:$SSH_PORT) and can optionally get
# a second, bridged NIC for live attacks.
#
# Usage: scripts/lab/vm.sh COMMAND [options]
#
# Run `scripts/lab/vm.sh help` for the command list and examples.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# --------------------------------------------------------------- defaults
VM_NAME="${VM_NAME:-rustips-lab}"
VM_DIR="${VM_DIR:-$HOME/.local/share/rustips-lab}"
CPUS="${CPUS:-2}"
MEM="${MEM:-2G}"
DISK_SIZE="${DISK_SIZE:-${DISK:-10G}}"
IMAGE_URL="${IMAGE_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}"
SSH_USER="${SSH_USER:-rustips}"

SSH_PORT_ENV="${SSH_PORT:-}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_PORT_FLAG=0
BRIDGED_ENV="${BRIDGED:-}"
BRIDGED="${BRIDGED:-0}"
BRIDGED_FLAG=0
BRIDGE_ENV="${BRIDGE:-}"
BRIDGE="${BRIDGE:-br0}"
BRIDGE_FLAG=0
SSH_KEY_ENV="${SSH_KEY:-}"
SSH_KEY_FILE="${SSH_KEY:-}"
SSH_KEY_FLAG=0
SSH_WAIT="${SSH_WAIT:-300}"
STOP_WAIT="${STOP_WAIT:-90}"

LAB_ADMIN_USER_ENV="${LAB_ADMIN_USER:-}"
LAB_ADMIN_USER="${LAB_ADMIN_USER:-labadmin}"
LAB_USER_ENV="${LAB_USER:-}"
LAB_USER="${LAB_USER:-labuser}"
LAB_PASSWORD_ENV="${LAB_PASSWORD:-}"
LAB_PASSWORD="${LAB_PASSWORD:-}"

START=0
FORCE=0
YES=0
VERIFY=1
WAIT=1
SKIP_APT=0
CLOUD_INIT_WAIT=1
SAFETY=1
DELETE_BASE=0

POSITIONAL=()

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

confirm() {
    local prompt="$1"
    if (( YES )); then
        return 0
    fi
    if [[ ! -t 0 ]]; then
        die "$prompt (pass --yes to continue non-interactively)"
    fi
    local reply
    read -r -p "$prompt [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

usage() {
    cat <<EOF
RustIPS lab VM lifecycle (plain QEMU, no libvirt)

Usage:
  scripts/lab/vm.sh COMMAND [options]

Commands:
  create              Download the Debian 13 image and create a VM
  start               Boot the VM and wait for SSH
  stop                Shut the guest down (QMP fallback, then signals)
  restart             stop + start
  status              Show process, network, disk and snapshot state
  ssh [--] ARGS...    SSH into the guest (extra args go to ssh)
  ip                  Show the guest's addresses and interfaces
  console             Attach to the serial console (Ctrl-] detaches)
  provision           Re-run the guest provisioner over SSH
  snapshot [NAME]     Take an offline qcow2 snapshot (default: clean)
  restore [NAME]      Restore an offline snapshot (default: clean)
  snapshots           List snapshots
  delete-snapshot NAME
  destroy             Delete the VM disk and state (base image kept)
  credentials         Print the generated lab credentials
  list                List VMs under $VM_DIR
  help                This text

Options:
  --name NAME         VM name (default $VM_NAME)
  --dir DIR           VM root directory (default $VM_DIR)
  --cpus N            vCPUs (default 2)
  --mem SIZE          Memory, e.g. 2G (default 2G)
  --disk SIZE         Disk size (default 10G)
  --ssh-port PORT     Host port forwarded to guest :22 (default 2222)
  --ssh-key PATH      SSH public or private key (default ~/.ssh/id_ed25519)
  --bridged           Add a bridged NIC for live attacks
  --nat               Force user-mode NAT (overrides stored mode)
  --bridge NAME       Host bridge for --bridged (default br0)
  --password PASS     Password for the labadmin/labuser PAM accounts
  --no-verify         Do not verify the downloaded image checksum
  --start             Start after create/restore
  --no-wait           Do not wait for SSH after start
  --skip-apt          Skip apt in 'provision'
  --no-cloud-init-wait
                      Do not wait for cloud-init in 'provision'
  --no-safety         Do not take a pre-restore snapshot
  --force             Recreate the disk / replace a snapshot
  --yes, -y           Do not ask for confirmation
  --base              With destroy: also remove the shared base image
  -h, --help          This text

Environment:
  VM_NAME VM_DIR CPUS MEM DISK_SIZE IMAGE_URL SSH_PORT SSH_USER
  SSH_KEY BRIDGED BRIDGE SSH_WAIT STOP_WAIT LAB_PASSWORD
  LAB_ADMIN_USER LAB_USER

Examples:
  scripts/lab/vm.sh create --start
  scripts/lab/vm.sh ssh
  scripts/lab/vm.sh provision
  scripts/lab/vm.sh snapshot clean
  scripts/lab/vm.sh restore clean --start
  scripts/lab/vm.sh destroy --yes

The RustIPS UI is loopback-only. Tunnel it with:
  ssh -p 2222 -L 10707:127.0.0.1:10707 rustips@127.0.0.1
EOF
}

# ------------------------------------------------------------- option parse
if [[ $# -gt 0 && "$1" != -* ]]; then
    COMMAND="$1"
    shift
else
    COMMAND="help"
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) VM_NAME="$2"; shift 2 ;;
        --dir) VM_DIR="$2"; shift 2 ;;
        --cpus) CPUS="$2"; shift 2 ;;
        --mem) MEM="$2"; shift 2 ;;
        --disk) DISK_SIZE="$2"; shift 2 ;;
        --ssh-port) SSH_PORT="$2"; SSH_PORT_FLAG=1; shift 2 ;;
        --ssh-key) SSH_KEY_FILE="$2"; SSH_KEY_FLAG=1; shift 2 ;;
        --bridged) BRIDGED=1; BRIDGED_FLAG=1; shift ;;
        --nat | --no-bridged) BRIDGED=0; BRIDGED_FLAG=1; shift ;;
        --bridge) BRIDGE="$2"; BRIDGE_FLAG=1; shift 2 ;;
        --password) LAB_PASSWORD="$2"; shift 2 ;;
        --no-verify) VERIFY=0; shift ;;
        --start | --launch) START=1; shift ;;
        --no-wait) WAIT=0; shift ;;
        --skip-apt) SKIP_APT=1; shift ;;
        --no-cloud-init-wait) CLOUD_INIT_WAIT=0; shift ;;
        --no-safety) SAFETY=0; shift ;;
        --force) FORCE=1; shift ;;
        --yes | -y) YES=1; shift ;;
        --base) DELETE_BASE=1; shift ;;
        --help | -h) usage; exit 0 ;;
        --) shift; POSITIONAL+=("$@"); break ;;
        -*) if [[ "$COMMAND" == "ssh" ]]; then POSITIONAL+=("$1"); shift; else die "unknown option: $1 (try --help)"; fi ;;
        *) POSITIONAL+=("$1"); shift ;;
    esac
done

VM_DIR="${VM_DIR%/}"
[[ -n "$VM_DIR" ]] || die "VM_DIR must not be empty"
[[ "$VM_NAME" =~ ^[A-Za-z0-9._-]+$ && "$VM_NAME" != "." && "$VM_NAME" != ".." ]] ||
    die "invalid VM name: $VM_NAME"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "SSH_PORT must be a number"
[[ "$BRIDGED" == "0" || "$BRIDGED" == "1" ]] || die "BRIDGED must be 0 or 1"
STATE_DIR="$VM_DIR/$VM_NAME"
BASE_DIR="$VM_DIR/base"
BASE_IMAGE="$BASE_DIR/$(basename "$IMAGE_URL")"
DISK="$STATE_DIR/disk.qcow2"
SEED_DIR="$STATE_DIR/seed"
SEED_ISO="$STATE_DIR/seed.iso"
PIDFILE="$STATE_DIR/qemu.pid"
QMP_SOCK="$STATE_DIR/qmp.sock"
SERIAL_SOCK="$STATE_DIR/serial.sock"
CONSOLE_LOG="$STATE_DIR/console.log"
QEMU_LOG="$STATE_DIR/qemu.log"
CREDS="$STATE_DIR/credentials.env"
KNOWN_HOSTS="$STATE_DIR/known_hosts"

SSH_PUB_FILE=""
SSH_IDENTITY=""
PUBKEY=""
SSH_CMD=()

cred_get() {
    [[ -f "$CREDS" ]] || return 0
    (
        set -a
        # shellcheck disable=SC1090
        . "$CREDS" >/dev/null 2>&1 || exit 0
        eval "printf '%s' \"\${$1:-}\""
    )
}

load_credentials() {
    local value
    if [[ -z "$SSH_PORT_ENV" && "$SSH_PORT_FLAG" == "0" ]]; then
        value="$(cred_get SSH_PORT)"
        if [[ -n "$value" ]]; then SSH_PORT="$value"; fi
    fi
    if [[ -z "$BRIDGED_ENV" && "$BRIDGED_FLAG" == "0" ]]; then
        value="$(cred_get BRIDGED)"
        if [[ -n "$value" ]]; then BRIDGED="$value"; fi
    fi
    if [[ -z "$BRIDGE_ENV" && "$BRIDGE_FLAG" == "0" ]]; then
        value="$(cred_get BRIDGE)"
        if [[ -n "$value" ]]; then BRIDGE="$value"; fi
    fi
    if [[ -z "$SSH_KEY_ENV" && "$SSH_KEY_FLAG" == "0" ]]; then
        value="$(cred_get SSH_KEY_FILE)"
        if [[ -n "$value" ]]; then SSH_KEY_FILE="$value"; fi
    fi
    if [[ -z "$LAB_PASSWORD_ENV" ]]; then
        value="$(cred_get LAB_PASSWORD)"
        if [[ -n "$value" ]]; then LAB_PASSWORD="$value"; fi
    fi
    if [[ -z "$LAB_ADMIN_USER_ENV" ]]; then
        value="$(cred_get LAB_ADMIN_USER)"
        if [[ -n "$value" ]]; then LAB_ADMIN_USER="$value"; fi
    fi
    if [[ -z "$LAB_USER_ENV" ]]; then
        value="$(cred_get LAB_USER)"
        if [[ -n "$value" ]]; then LAB_USER="$value"; fi
    fi
}

load_credentials

for lab_user in "$SSH_USER" "$LAB_ADMIN_USER" "$LAB_USER"; do
    [[ "$lab_user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] ||
        die "invalid user name: $lab_user"
done
[[ "$LAB_ADMIN_USER" != "$LAB_USER" ]] ||
    die "LAB_ADMIN_USER and LAB_USER must differ"

# Stable MAC addresses keep the cloud-init network config valid across boots.
mac_hash="$(printf '%s' "$VM_NAME" | sha256sum | cut -c1-12)"
MAC_NAT="52:54:00:${mac_hash:0:2}:${mac_hash:2:2}:${mac_hash:4:2}"
MAC_LAN="52:54:00:${mac_hash:6:2}:${mac_hash:8:2}:${mac_hash:10:2}"

if (( ${#QMP_SOCK} > 100 )); then
    die "state path is too long for a UNIX socket ($QMP_SOCK); use --dir with a shorter path"
fi

# ------------------------------------------------------------------- ssh
resolve_ssh_key() {
    if [[ -z "$SSH_KEY_FILE" ]]; then
        local candidate
        for candidate in "$HOME/.ssh/id_ed25519" "$HOME/.ssh/id_rsa"; do
            if [[ -f "$candidate" || -f "$candidate.pub" ]]; then
                SSH_KEY_FILE="$candidate"
                break
            fi
        done
    fi

    if [[ -z "$SSH_KEY_FILE" ]]; then
        die "no SSH key found; set SSH_KEY or pass --ssh-key"
    fi

    if [[ "$SSH_KEY_FILE" == *.pub ]]; then
        SSH_PUB_FILE="$SSH_KEY_FILE"
        SSH_IDENTITY="${SSH_KEY_FILE%.pub}"
    else
        SSH_IDENTITY="$SSH_KEY_FILE"
        if [[ -f "$SSH_KEY_FILE.pub" ]]; then
            SSH_PUB_FILE="$SSH_KEY_FILE.pub"
        fi
    fi

    if [[ -n "$SSH_PUB_FILE" ]]; then
        [[ -f "$SSH_PUB_FILE" ]] || die "SSH public key not found: $SSH_PUB_FILE"
        PUBKEY="$(cat "$SSH_PUB_FILE")"
    else
        [[ -f "$SSH_IDENTITY" ]] ||
            die "SSH public key not found; pass the .pub file with --ssh-key"
        command -v ssh-keygen >/dev/null 2>&1 ||
            die "ssh-keygen is needed to derive the public key from $SSH_IDENTITY"
        PUBKEY="$(ssh-keygen -y -f "$SSH_IDENTITY" 2>/dev/null)" ||
            die "could not derive a public key from $SSH_IDENTITY; pass the .pub file"
    fi

    if [[ ! -f "$SSH_IDENTITY" ]]; then
        warn "private key $SSH_IDENTITY not found; ssh may rely on an agent"
    fi
}

build_ssh_cmd() {
    SSH_CMD=(
        ssh
        -o BatchMode=yes
        -o StrictHostKeyChecking=accept-new
        -o "UserKnownHostsFile=$KNOWN_HOSTS"
        -o ConnectTimeout=3
        -p "$SSH_PORT"
    )
    if [[ -f "$SSH_IDENTITY" ]]; then
        SSH_CMD+=(-i "$SSH_IDENTITY" -o IdentitiesOnly=yes)
    fi
    SSH_CMD+=("$SSH_USER@127.0.0.1")
}

# --------------------------------------------------------------- lifecycle
is_running() {
    [[ -f "$PIDFILE" ]] || return 1
    local pid
    pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    kill -0 "$pid" 2>/dev/null
}

port_busy() {
    (exec 3<>"/dev/tcp/127.0.0.1/$SSH_PORT") 2>/dev/null
}

cleanup_runtime() {
    rm -f "$PIDFILE" "$QMP_SOCK" "$SERIAL_SOCK"
}

qmp_send() {
    local command="$1"
    command -v python3 >/dev/null 2>&1 || return 1
    [[ -S "$QMP_SOCK" ]] || return 1
    python3 - "$QMP_SOCK" "$command" <<'PY'
import json
import socket
import sys

path, command = sys.argv[1], sys.argv[2]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(3)
try:
    sock.connect(path)
    stream = sock.makefile("rwb", buffering=0)

    def send(obj):
        stream.write((json.dumps(obj) + "\n").encode())
        return stream.readline()

    stream.readline()  # QMP greeting
    send({"execute": "qmp_capabilities"})
    reply = send({"execute": command})
    sys.stdout.write(reply.decode(errors="replace"))
except Exception as exc:  # noqa: BLE001 - best effort fallback path
    sys.stderr.write(f"{exc}\n")
    sys.exit(1)
PY
}

wait_for_ssh() {
    local deadline=$((SECONDS + SSH_WAIT))
    while (( SECONDS < deadline )); do
        if ! is_running; then
            echo "--- $QEMU_LOG ---" >&2
            tail -n 30 "$QEMU_LOG" 2>/dev/null || true
            die "QEMU exited while the guest was booting"
        fi
        if "${SSH_CMD[@]}" true >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    die "SSH did not become ready in ${SSH_WAIT}s (try: $0 console)"
}

write_network_config() {
    cat >"$SEED_DIR/network-config" <<EOF
version: 2
ethernets:
  nat0:
    match:
      macaddress: "$MAC_NAT"
    dhcp4: true
    dhcp4-overrides:
      route-metric: 200
    optional: true
  lan0:
    match:
      macaddress: "$MAC_LAN"
    dhcp4: true
    dhcp4-overrides:
      route-metric: 100
    optional: true
EOF
}

write_seed() {
    local guest_script="$SCRIPT_DIR/guest-provision.sh"
    [[ -f "$guest_script" ]] || die "missing $guest_script"

    if [[ "$LAB_PASSWORD" == *:* || "$LAB_PASSWORD" == *$'\n'* ]]; then
        die "LAB_PASSWORD must not contain ':' or newlines"
    fi

    mkdir -p "$SEED_DIR"
    chmod 700 "$SEED_DIR"
    write_network_config

    local hostname instance_id password_q admin_q user_q
    hostname="$(printf '%s' "$VM_NAME" | tr '[:upper:]' '[:lower:]' |
        tr -c 'a-z0-9-' '-' | sed 's/-\+$//' | cut -c1-63)"
    [[ -n "$hostname" ]] || hostname="rustips-lab"
    instance_id="$(date -u +%Y%m%d%H%M%S)-$RANDOM"
    printf -v password_q '%q' "$LAB_PASSWORD"
    printf -v admin_q '%q' "$LAB_ADMIN_USER"
    printf -v user_q '%q' "$LAB_USER"

    {
        cat <<EOF
#cloud-config
users:
  - default
  - name: $SSH_USER
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $PUBKEY
ssh_pwauth: false
disable_root: true
package_update: false
package_upgrade: false
timezone: UTC
write_files:
  - path: /etc/rustips-lab.env
    owner: root:root
    permissions: '0600'
    content: |
      LAB_PASSWORD=$password_q
      LAB_ADMIN_USER=$admin_q
      LAB_USER=$user_q
  - path: /usr/local/sbin/rustips-lab-provision
    owner: root:root
    permissions: '0755'
    content: |
EOF
        sed 's/^/      /' "$guest_script"
        cat <<'EOF'
runcmd:
  - [systemctl, enable, --now, ssh]
  - |
    set -a
    . /etc/rustips-lab.env
    /usr/local/sbin/rustips-lab-provision
EOF
    } >"$SEED_DIR/user-data"

    cat >"$SEED_DIR/meta-data" <<EOF
instance-id: $instance_id
local-hostname: $hostname
EOF

    rm -f "$SEED_ISO"
    if command -v cloud-localds >/dev/null 2>&1; then
        cloud-localds --network-config="$SEED_DIR/network-config" \
            "$SEED_ISO" "$SEED_DIR/user-data" "$SEED_DIR/meta-data"
    elif command -v genisoimage >/dev/null 2>&1; then
        genisoimage -quiet -output "$SEED_ISO" -volid cidata -joliet -rock \
            "$SEED_DIR/user-data" "$SEED_DIR/meta-data" "$SEED_DIR/network-config"
    elif command -v mkisofs >/dev/null 2>&1; then
        mkisofs -quiet -output "$SEED_ISO" -volid cidata -joliet -rock \
            "$SEED_DIR/user-data" "$SEED_DIR/meta-data" "$SEED_DIR/network-config"
    else
        die "need cloud-localds, genisoimage or mkisofs to build the cloud-init seed"
    fi
}

write_credentials() {
    local created
    created="$(cred_get CREATED)"
    [[ -n "$created" ]] || created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    umask 077
    {
        echo "# Generated by scripts/lab/vm.sh -- safe to source in bash."
        printf 'VM_NAME=%q\n' "$VM_NAME"
        printf 'VM_DIR=%q\n' "$VM_DIR"
        printf 'SSH_HOST=%q\n' "127.0.0.1"
        printf 'SSH_PORT=%q\n' "$SSH_PORT"
        printf 'SSH_USER=%q\n' "$SSH_USER"
        printf 'SSH_KEY_FILE=%q\n' "${SSH_IDENTITY:-$SSH_PUB_FILE}"
        printf 'LAB_ADMIN_USER=%q\n' "$LAB_ADMIN_USER"
        printf 'LAB_USER=%q\n' "$LAB_USER"
        printf 'LAB_PASSWORD=%q\n' "$LAB_PASSWORD"
        printf 'BRIDGED=%q\n' "$BRIDGED"
        printf 'BRIDGE=%q\n' "$BRIDGE"
        printf 'MAC_NAT=%q\n' "$MAC_NAT"
        printf 'MAC_LAN=%q\n' "$MAC_LAN"
        printf 'CREATED=%q\n' "$created"
    } >"$CREDS"
    chmod 600 "$CREDS"
}

download_base() {
    mkdir -p "$BASE_DIR"
    chmod 700 "$BASE_DIR"

    if [[ ! -f "$BASE_IMAGE" ]]; then
        need curl
        echo "downloading $IMAGE_URL"
        if ! curl -fL --retry 3 --retry-delay 2 -o "$BASE_IMAGE.part" "$IMAGE_URL"; then
            rm -f "$BASE_IMAGE.part"
            die "image download failed"
        fi
        mv "$BASE_IMAGE.part" "$BASE_IMAGE"

        if (( VERIFY )); then
            local sums_url sums_file entry
            sums_url="$(dirname "$IMAGE_URL")/SHA512SUMS"
            sums_file="$BASE_DIR/SHA512SUMS"
            if curl -fsSL --retry 2 -o "$sums_file.part" "$sums_url"; then
                mv "$sums_file.part" "$sums_file"
                entry="$(awk -v name="$(basename "$BASE_IMAGE")" '$2 == name { print }' "$sums_file")"
                if [[ -n "$entry" ]]; then
                    printf '%s\n' "$entry" >"$BASE_IMAGE.sha512"
                    (cd "$BASE_DIR" && sha512sum -c "$BASE_IMAGE.sha512") ||
                        die "base image checksum mismatch"
                else
                    warn "no SHA512 entry for $(basename "$BASE_IMAGE"); continuing"
                fi
            else
                rm -f "$sums_file.part"
                warn "could not download $sums_url; continuing without verification"
            fi
        fi
    elif (( VERIFY )) && [[ -f "$BASE_IMAGE.sha512" ]]; then
        (cd "$BASE_DIR" && sha512sum -c "$BASE_IMAGE.sha512") ||
            die "cached base image checksum mismatch; remove $BASE_IMAGE"
    fi
}

print_summary() {
    local ssh_line="ssh -p $SSH_PORT"
    if [[ -f "$SSH_IDENTITY" ]]; then
        ssh_line+=" -i $SSH_IDENTITY"
    fi
    ssh_line+=" $SSH_USER@127.0.0.1"

    cat <<EOF

VM:          $VM_NAME
state:       $STATE_DIR
disk:        $DISK
network:     $([[ "$BRIDGED" == "1" ]] && echo "NAT + bridge $BRIDGE" || echo "user-mode NAT")
ssh:         $ssh_line
ui tunnel:   ssh -p $SSH_PORT -L 10707:127.0.0.1:10707 $SSH_USER@127.0.0.1
credentials: $CREDS
console:     $0 console

Next:
  $0 start
  scripts/deploy.sh $SSH_USER@127.0.0.1 --ssh-port $SSH_PORT
EOF
}

create_vm() {
    need qemu-system-x86_64
    need qemu-img
    need ssh-keygen
    need openssl
    resolve_ssh_key

    if [[ -f "$DISK" ]]; then
        if (( ! FORCE )); then
            echo "VM already exists: $DISK"
            if (( START )); then
                start_vm
            else
                print_summary
            fi
            return 0
        fi
        confirm "delete the existing disk for $VM_NAME?"
        if is_running; then
            stop_vm
        fi
        rm -rf "$STATE_DIR"
    fi

    if [[ -z "$LAB_PASSWORD" ]]; then
        LAB_PASSWORD="$(openssl rand -hex 16)"
    fi

    mkdir -p "$STATE_DIR"
    chmod 700 "$VM_DIR" "$STATE_DIR"

    download_base

    echo "creating $DISK ($DISK_SIZE, backing $BASE_IMAGE)"
    qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$DISK" "$DISK_SIZE" >/dev/null

    write_seed
    write_credentials

    echo "wrote $SEED_ISO"
    echo "wrote $CREDS (mode 0600)"

    if (( START )); then
        start_vm
    else
        print_summary
    fi
}

bridge_helper_path() {
    local helper
    for helper in /usr/lib/qemu/qemu-bridge-helper /usr/libexec/qemu-bridge-helper; do
        if [[ -x "$helper" ]]; then
            printf '%s\n' "$helper"
            return 0
        fi
    done
    return 1
}

check_bridge_ready() {
    if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
        die "bridge $BRIDGE does not exist; create it (see scripts/lab/README.md) or pass --bridge NAME"
    fi
    if [[ ! -e /dev/net/tun ]]; then
        die "/dev/net/tun is missing; load the tun module (sudo modprobe tun)"
    fi
    if (( EUID == 0 )); then
        return 0
    fi

    local helper
    helper="$(bridge_helper_path)" ||
        die "qemu-bridge-helper not found; install qemu-system-common"
    if [[ ! -u "$helper" ]] &&
        ! { getcap "$helper" 2>/dev/null | grep -q 'cap_net_admin'; }; then
        die "$helper is not setuid root and has no CAP_NET_ADMIN; run: sudo chmod u+s $helper"
    fi

    local conf=/etc/qemu/bridge.conf
    if [[ ! -r "$conf" ]]; then
        die "$conf is missing; run: echo 'allow $BRIDGE' | sudo tee $conf"
    fi
    if ! grep -Eq "^[[:space:]]*allow[[:space:]]+($BRIDGE|all)([[:space:]]|$)" "$conf"; then
        die "$conf does not allow $BRIDGE; add: allow $BRIDGE"
    fi
}

start_vm() {
    need qemu-system-x86_64
    need qemu-img
    resolve_ssh_key
    build_ssh_cmd

    if is_running; then
        echo "VM is already running (pid $(cat "$PIDFILE"))"
        if (( WAIT )); then
            wait_for_ssh
        fi
        return 0
    fi
    cleanup_runtime
    [[ -f "$DISK" ]] || die "no disk at $DISK; run: $0 create"
    [[ -f "$SEED_ISO" ]] || die "no cloud-init seed at $SEED_ISO; run: $0 create --force"

    if port_busy; then
        die "127.0.0.1:$SSH_PORT is already in use; pass --ssh-port"
    fi

    local qemu=()
    qemu+=(
        qemu-system-x86_64
        -name "$VM_NAME"
        -machine "q35,accel=kvm:tcg"
        -cpu max
        -smp "$CPUS"
        -m "$MEM"
        -drive "file=$DISK,if=virtio,cache=writeback,discard=unmap"
        -drive "file=$SEED_ISO,if=virtio,readonly=on"
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22"
        -device "virtio-net-pci,netdev=net0,mac=$MAC_NAT"
        -device virtio-rng-pci
        -display none
        -chardev "socket,id=serial0,path=$SERIAL_SOCK,server=on,wait=off,logfile=$CONSOLE_LOG,logappend=on"
        -serial chardev:serial0
        -qmp "unix:$QMP_SOCK,server=on,wait=off"
        -pidfile "$PIDFILE"
        -daemonize
        -D "$QEMU_LOG"
    )

    if [[ "$BRIDGED" == "1" ]]; then
        check_bridge_ready
        qemu+=(
            -netdev "bridge,id=net1,br=$BRIDGE"
            -device "virtio-net-pci,netdev=net1,mac=$MAC_LAN"
        )
    fi

    echo "starting $VM_NAME ($([[ "$BRIDGED" == "1" ]] && echo "NAT + $BRIDGE" || echo "NAT"))"
    if ! "${qemu[@]}"; then
        echo "--- $QEMU_LOG ---" >&2
        tail -n 40 "$QEMU_LOG" 2>/dev/null || true
        die "QEMU failed to start"
    fi

    local waited=0
    while ! is_running && (( waited < 50 )); do
        sleep 0.1
        waited=$((waited + 1))
    done
    is_running || die "QEMU did not write a live pid to $PIDFILE"

    echo "qemu pid $(cat "$PIDFILE")"
    if ! write_credentials; then
        echo "warning: could not update $CREDS" >&2
    fi
    if (( WAIT )); then
        echo "waiting for SSH on 127.0.0.1:$SSH_PORT ..."
        wait_for_ssh
        echo "SSH is ready"
    fi
}

stop_vm() {
    if ! is_running; then
        cleanup_runtime
        echo "VM is not running"
        return 0
    fi

    local pid missing_key=0 polite=0
    pid="$(cat "$PIDFILE")"

    if (( FORCE )); then
        echo "sending SIGTERM to qemu pid $pid"
        kill "$pid" 2>/dev/null || true
    elif ( resolve_ssh_key && build_ssh_cmd && "${SSH_CMD[@]}" true ) >/dev/null 2>&1; then
        resolve_ssh_key
        build_ssh_cmd
        echo "asking the guest to power off"
        "${SSH_CMD[@]}" "sudo -n systemctl poweroff" >/dev/null 2>&1 || true
        polite=1
    else
        echo "SSH is not ready; using the QEMU monitor"
        missing_key=1
    fi

    if (( polite )); then
        local deadline=$((SECONDS + STOP_WAIT))
        while is_running && (( SECONDS < deadline )); do
            sleep 1
        done
    elif (( missing_key )); then
        sleep 1
    fi

    if is_running; then
        echo "guest did not power off; sending QMP quit"
        qmp_send quit >/dev/null 2>&1 || true
        local timeout=10
        (( polite )) || timeout=5
        local deadline=$((SECONDS + timeout))
        while is_running && (( SECONDS < deadline )); do
            sleep 1
        done
    fi

    if is_running; then
        echo "terminating qemu pid $pid"
        kill "$pid" 2>/dev/null || true
        sleep 2
    fi
    if is_running; then
        kill -9 "$pid" 2>/dev/null || true
    fi

    cleanup_runtime
    echo "VM stopped"
}

status_vm() {
    echo "VM:       $VM_NAME"
    echo "state:    $STATE_DIR"
    echo "network:  $([[ "$BRIDGED" == "1" ]] && echo "NAT + bridge $BRIDGE" || echo "user-mode NAT")"

    if is_running; then
        local qmp_status=""
        qmp_status="$(qmp_send query-status 2>/dev/null | sed -n 's/.*"status": "\([^"]*\)".*/\1/p' | head -1 || true)"
        echo "process:  running (pid $(cat "$PIDFILE")${qmp_status:+, $qmp_status})"
        echo "ssh:      ssh -p $SSH_PORT $SSH_USER@127.0.0.1"
        echo "ui:       ssh -p $SSH_PORT -L 10707:127.0.0.1:10707 $SSH_USER@127.0.0.1"
    else
        echo "process:  stopped"
    fi

    if [[ -f "$DISK" ]]; then
        echo "disk:     $DISK"
        echo "size:     $(qemu-img info -U "$DISK" 2>/dev/null | awk '/virtual size/ { print $3, $4; exit }' || true)"
    else
        echo "disk:     missing (run: $0 create)"
    fi

    if [[ -f "$DISK" ]]; then
        local count
        count="$(qemu-img snapshot -U -l "$DISK" 2>/dev/null | awk 'NR > 2 && NF > 0 { n++ } END { print n + 0 }' || true)"
        echo "snapshots: ${count:-0}"
        qemu-img snapshot -U -l "$DISK" 2>/dev/null | awk 'NR > 2 && NF > 0 { printf "          %s\n", $2 }' || true
    fi
    echo "credentials: $CREDS"
}

snapshot_exists() {
    local name="$1"
    qemu-img snapshot -l "$DISK" 2>/dev/null |
        awk -v name="$name" 'NR > 2 && $2 == name { found = 1 } END { exit !found }'
}

snapshot_vm() {
    need qemu-img
    local name="${POSITIONAL[0]:-clean}"
    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid snapshot name: $name"
    [[ -f "$DISK" ]] || die "no disk at $DISK"
    if is_running; then
        die "stop the VM before taking an offline snapshot: $0 stop"
    fi

    if snapshot_exists "$name"; then
        if (( ! FORCE )); then
            die "snapshot $name already exists; pass --force to replace it"
        fi
        qemu-img snapshot -d "$name" "$DISK"
    fi
    qemu-img snapshot -c "$name" "$DISK"
    echo "created snapshot $name"
}

restore_vm() {
    need qemu-img
    local name="${POSITIONAL[0]:-clean}"
    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid snapshot name: $name"
    [[ -f "$DISK" ]] || die "no disk at $DISK"
    if is_running; then
        die "stop the VM before restoring a snapshot: $0 stop"
    fi
    snapshot_exists "$name" || die "snapshot $name does not exist (try: $0 snapshots)"

    if (( SAFETY )); then
        local safety
        safety="pre-restore-$(date -u +%Y%m%dT%H%M%SZ)"
        qemu-img snapshot -c "$safety" "$DISK"
        echo "safety snapshot: $safety"
    fi

    qemu-img snapshot -a "$name" "$DISK"
    echo "restored snapshot $name"
    if (( START )); then
        start_vm
    fi
}

delete_snapshot_vm() {
    need qemu-img
    local name="${POSITIONAL[0]:-}"
    [[ -n "$name" ]] || die "usage: $0 delete-snapshot NAME"
    [[ -f "$DISK" ]] || die "no disk at $DISK"
    if is_running; then
        die "stop the VM before deleting a snapshot"
    fi
    snapshot_exists "$name" || die "snapshot $name does not exist"
    qemu-img snapshot -d "$name" "$DISK"
    echo "deleted snapshot $name"
}

provision_vm() {
    resolve_ssh_key
    build_ssh_cmd
    is_running || die "VM is not running; run: $0 start"

    wait_for_ssh

    if (( CLOUD_INIT_WAIT )); then
        echo "waiting for cloud-init (use --no-cloud-init-wait to skip)"
        if ! timeout 600 "${SSH_CMD[@]}" "sudo -n cloud-init status --wait" >/dev/null 2>&1; then
            warn "cloud-init did not report success; continuing with live provisioning"
        fi
    fi

    local remote="/tmp/rustips-lab-provision.$$"
    "${SSH_CMD[@]}" "cat > '$remote.sh'" <"$SCRIPT_DIR/guest-provision.sh"
    "${SSH_CMD[@]}" "cat > '$remote.env' && chmod 600 '$remote.env'" <<EOF
LAB_PASSWORD=$(printf '%q' "$LAB_PASSWORD")
LAB_ADMIN_USER=$(printf '%q' "$LAB_ADMIN_USER")
LAB_USER=$(printf '%q' "$LAB_USER")
SKIP_APT=$(printf '%q' "$SKIP_APT")
EOF

    echo "running guest provisioner"
    if ! "${SSH_CMD[@]}" \
        "sudo -n bash -c 'set -a; . \"$remote.env\"; bash \"$remote.sh\"'"; then
        "${SSH_CMD[@]}" "rm -f '$remote.sh' '$remote.env'" || true
        die "guest provisioning failed"
    fi
    "${SSH_CMD[@]}" "rm -f '$remote.sh' '$remote.env'" || true
}

ssh_vm() {
    resolve_ssh_key
    build_ssh_cmd
    is_running || die "VM is not running; run: $0 start"
    exec "${SSH_CMD[@]}" "${POSITIONAL[@]}"
}

ip_vm() {
    resolve_ssh_key
    build_ssh_cmd
    is_running || die "VM is not running; run: $0 start"
    wait_for_ssh
    echo "NAT MAC: $MAC_NAT"
    if [[ "$BRIDGED" == "1" ]]; then
        echo "LAN MAC: $MAC_LAN (bridge $BRIDGE)"
    else
        echo "LAN MAC: $MAC_LAN (not attached; VM is NAT-only)"
    fi
    "${SSH_CMD[@]}" "hostname -I; echo; ip -br addr"
    if [[ "$BRIDGED" == "1" ]]; then
        local lan_state
        lan_state="$("${SSH_CMD[@]}" "
            state=missing
            for i in /sys/class/net/*; do
                name=\${i##*/}
                addr=\$(cat \"\$i/address\" 2>/dev/null) || continue
                [ \"\$addr\" = \"$MAC_LAN\" ] || continue
                if ip -4 -o addr show dev \"\$name\" | grep -q 'inet '; then
                    state=ok
                else
                    state=no-ip
                fi
                break
            done
            printf '%s\n' \"\$state\"
        " 2>/dev/null || echo unknown)"
        case "$lan_state" in
            missing)
                echo "warning: LAN NIC $MAC_LAN is not present in the guest; check the $BRIDGE port and reboot the guest" >&2
                ;;
            no-ip)
                echo "warning: LAN NIC has no IPv4 address; check the $BRIDGE uplink and DHCP (bridge link show, ip -br addr show $BRIDGE)" >&2
                ;;
        esac
        echo "note: 10.0.2.15 remains the NAT management address; attack the LAN address, not the NAT address" >&2
    else
        echo "note: 10.0.2.15 is inside user-mode NAT and cannot be pinged from the host; use 'vm.sh ssh'" >&2
    fi
}

console_vm() {
    need python3
    is_running || die "VM is not running; run: $0 start"
    [[ -S "$SERIAL_SOCK" ]] || die "serial socket missing: $SERIAL_SOCK"
    [[ -t 0 ]] || die "console needs an interactive terminal"
    echo "attaching to $VM_NAME serial console; Ctrl-] detaches (the guest keeps running)"
    python3 - "$SERIAL_SOCK" <<'PY'
import os
import select
import socket
import sys
import termios
import tty

path = sys.argv[1]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
fd = sys.stdin.fileno()
saved = termios.tcgetattr(fd)
try:
    tty.setraw(fd)
    while True:
        readable, _, _ = select.select([fd, sock], [], [])
        if fd in readable:
            data = os.read(fd, 1024)
            if not data:
                break
            if b"\x1d" in data:  # Ctrl-]
                break
            sock.sendall(data)
        if sock in readable:
            data = sock.recv(4096)
            if not data:
                break
            os.write(sys.stdout.fileno(), data)
except (KeyboardInterrupt, OSError):
    pass
finally:
    termios.tcsetattr(fd, termios.TCSANOW, saved)
    sock.close()
PY
}

destroy_vm() {
    if [[ ! -d "$STATE_DIR" ]]; then
        echo "nothing to destroy for $VM_NAME"
        return 0
    fi
    confirm "delete $STATE_DIR and the VM disk?"
    if is_running; then
        stop_vm
    fi
    rm -rf "$STATE_DIR"
    echo "removed $STATE_DIR"

    if (( DELETE_BASE )); then
        confirm "also delete the shared base image directory $BASE_DIR?"
        rm -rf "$BASE_DIR"
        echo "removed $BASE_DIR"
    fi
}

list_vms() {
    local found=0 disk name state
    for disk in "$VM_DIR"/*/disk.qcow2; do
        [[ -f "$disk" ]] || continue
        found=1
        name="$(basename "$(dirname "$disk")")"
        if [[ -f "$(dirname "$disk")/qemu.pid" ]] &&
            kill -0 "$(cat "$(dirname "$disk")/qemu.pid" 2>/dev/null)" 2>/dev/null; then
            state="running"
        else
            state="stopped"
        fi
        printf '%-24s %-8s %s\n' "$name" "$state" "$disk"
    done
    (( found )) || echo "no VMs under $VM_DIR"
}

# -------------------------------------------------------------------- main
case "$COMMAND" in
    create) create_vm ;;
    start) start_vm ;;
    stop) stop_vm ;;
    restart)
        if [[ "$BRIDGED" == "1" ]]; then
            check_bridge_ready
        fi
        stop_vm
        start_vm
        ;;
    status) status_vm ;;
    ssh) ssh_vm ;;
    ip) ip_vm ;;
    console) console_vm ;;
    provision) provision_vm ;;
    snapshot) snapshot_vm ;;
    restore) restore_vm ;;
    snapshots)
        need qemu-img
        [[ -f "$DISK" ]] || die "no disk at $DISK"
        qemu-img snapshot -l "$DISK"
        ;;
    delete-snapshot) delete_snapshot_vm ;;
    destroy) destroy_vm ;;
    credentials)
        [[ -f "$CREDS" ]] || die "no credentials at $CREDS"
        cat "$CREDS"
        ;;
    list) list_vms ;;
    help | --help | -h) usage ;;
    *) die "unknown command: $COMMAND (try: $0 help)" ;;
esac
