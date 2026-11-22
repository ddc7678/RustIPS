#!/usr/bin/env bash
# Install, upgrade or roll back RustIPS on a remote Debian 13 host over SSH.
#
# The script builds or reuses a release binary, uploads it to a staging path,
# installs it atomically at /usr/local/bin/rustips, keeps the existing
# configuration and database, and verifies the service and loopback UI.
#
# Requirements on the target host:
#   - Debian 13 (trixie), systemd
#   - key-based SSH access with non-interactive sudo (`sudo -n true`)
#   - nftables for enforce mode
#
# Usage:
#   scripts/deploy.sh [COMMAND] [options] [user@]host
#
# Commands:
#   deploy    Install or upgrade automatically (default)
#   install   Require a clean host (no existing binary/config)
#   upgrade   Require an existing installation
#   rollback  Restore the latest backup, or --to STAMP
#   backups   List backups on the host
#   status    Show service, version and UI health
#
# Run `scripts/deploy.sh --help` for all options.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

COMMAND="deploy"
TARGET=""
BINARY="${BINARY:-$PROJECT_DIR/target/release/rustips}"
BINARY_SET=0
BUILD=0
SSH_PORT="${SSH_PORT:-22}"
IDENTITY="${SSH_IDENTITY:-}"
PREFIX="${PREFIX:-/usr/local/bin}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/rustips}"
SERVICE="${SERVICE:-rustips}"
KEEP="${KEEP:-5}"
TO="${TO:-}"
DRY_RUN=0
NO_RESTART=0
AUTO_ROLLBACK=1
SKIP_CHECK=0
ALLOW_OS=0
FORCE=0

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

step() {
    printf '\n==> %s\n' "$*"
}

usage() {
    cat <<'EOF'
Deploy RustIPS to a remote Debian 13 host over SSH

Usage:
  scripts/deploy.sh [COMMAND] [options] [user@]host

Commands:
  deploy              Install or upgrade automatically (default)
  install             Refuse to run if RustIPS is already installed
  upgrade             Refuse to run if RustIPS is not installed
  rollback            Restore the most recent backup
  backups             List backups on the host
  status              Show installed version, service state and UI health

Options:
  --binary PATH       Release binary to install (default target/release/rustips)
  --build             Run `cargo build --release` before deploying
  --ssh-port PORT     SSH port (default 22)
  --identity PATH     SSH private key (default: ssh config/agent)
  --prefix DIR        Install directory (default /usr/local/bin)
  --backup-dir DIR    Remote backup directory (default /var/backups/rustips)
  --service NAME      systemd unit name (default rustips)
  --keep N            Keep N upgrade backups (default 5)
  --to STAMP          With rollback: restore this backup instead of latest
  --no-restart        Install the binary but do not start the service
  --no-auto-rollback  Do not roll back automatically when verification fails
  --skip-check        Skip `rustips check` during verification
  --allow-unsupported-os
                      Permit non-Debian-13 targets
  --force             With install: replace an existing installation
  --rollback          Alias for the rollback command
  --dry-run           Print the plan; do not contact the host
  -h, --help          This text

Environment:
  BINARY SSH_PORT SSH_IDENTITY PREFIX BACKUP_DIR SERVICE KEEP

Examples:
  scripts/deploy.sh --build root@192.0.2.10
  scripts/deploy.sh upgrade rustips@lab --ssh-port 2222
  scripts/deploy.sh rollback rustips@lab --ssh-port 2222
  scripts/deploy.sh rollback rustips@lab --to 20261118T101500Z-1234
  scripts/deploy.sh status rustips@lab --ssh-port 2222

The first install runs:
  rustips setup --install-service --non-interactive
then enables and starts the systemd unit. Upgrades stop the service, back up
the binary, configuration, unit, PAM file and database, replace the binary,
restart, and verify. The configuration is never overwritten on upgrade.
EOF
}

# ------------------------------------------------------------- option parse
if [[ $# -gt 0 && "$1" =~ ^(deploy|install|upgrade|rollback|backups|status)$ ]]; then
    COMMAND="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary) BINARY="$2"; BINARY_SET=1; shift 2 ;;
        --build) BUILD=1; shift ;;
        --ssh-port) SSH_PORT="$2"; shift 2 ;;
        --identity) IDENTITY="$2"; shift 2 ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --backup-dir) BACKUP_DIR="$2"; shift 2 ;;
        --service) SERVICE="$2"; shift 2 ;;
        --keep) KEEP="$2"; shift 2 ;;
        --to) TO="$2"; shift 2 ;;
        --no-restart) NO_RESTART=1; shift ;;
        --no-auto-rollback) AUTO_ROLLBACK=0; shift ;;
        --skip-check) SKIP_CHECK=1; shift ;;
        --allow-unsupported-os) ALLOW_OS=1; shift ;;
        --force) FORCE=1; shift ;;
        --rollback) COMMAND="rollback"; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --help | -h) usage; exit 0 ;;
        --) shift; TARGET="${1:-}"; shift || true ;;
        -*) die "unknown option: $1 (try --help)" ;;
        *)
            if [[ -n "$TARGET" ]]; then
                die "unexpected argument: $1"
            fi
            TARGET="$1"
            shift
            ;;
    esac
done

[[ -n "$TARGET" ]] || die "missing target; usage: $0 [COMMAND] [options] [user@]host"
[[ "$KEEP" =~ ^[0-9]+$ && "$KEEP" -ge 1 ]] || die "--keep must be a positive integer"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "--ssh-port must be a number"
[[ "$PREFIX" == /* && "$PREFIX" =~ ^/[A-Za-z0-9._/-]+$ ]] ||
    die "--prefix must be an absolute path without shell metacharacters"
[[ "$BACKUP_DIR" == /* && "$BACKUP_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] ||
    die "--backup-dir must be an absolute path without shell metacharacters"
[[ "$SERVICE" =~ ^[A-Za-z0-9_.@-]+$ ]] || die "--service contains invalid characters"
[[ -z "$TO" || "$TO" =~ ^[A-Za-z0-9._-]+$ ]] || die "--to contains invalid characters"

PREFIX="${PREFIX%/}"
BACKUP_DIR="${BACKUP_DIR%/}"

SSH_OPTS=(
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=4
    -o StrictHostKeyChecking=accept-new
)
if [[ -n "$IDENTITY" ]]; then
    [[ -f "$IDENTITY" ]] || die "identity file not found: $IDENTITY"
    SSH_OPTS+=(-i "$IDENTITY" -o IdentitiesOnly=yes)
fi
SSH=(ssh "${SSH_OPTS[@]}" -p "$SSH_PORT")

ssh_run() {
    "${SSH[@]}" "$TARGET" "$@"
}

REMOTE_UID=""
REMOTE_ID=""
REMOTE_VERSION=""
REMOTE_ARCH=""

root_script() {
    # Usage: root_script KEY=value... <<'EOS' ... EOS
    local envs=()
    while [[ $# -gt 0 && "$1" == *=* ]]; do
        envs+=("$1")
        shift
    done
    local cmd
    if [[ "$REMOTE_UID" == "0" ]]; then
        cmd="env"
    else
        cmd="sudo -n env"
    fi
    local quoted item
    for item in "${envs[@]}"; do
        printf -v quoted '%q' "$item"
        cmd+=" $quoted"
    done
    cmd+=" bash -s"
    "${SSH[@]}" "$TARGET" "$cmd"
}

preflight() {
    local info
    if ! info="$("${SSH[@]}" "$TARGET" 'bash -s' <<'EOS'
. /etc/os-release 2>/dev/null || true
printf 'id=%s\n' "${ID:-unknown}"
printf 'version=%s\n' "${VERSION_ID:-unknown}"
printf 'arch=%s\n' "$(uname -m)"
printf 'uid=%s\n' "$(id -u)"
EOS
    )"; then
        die "cannot connect to $TARGET over SSH (key-based auth is required)"
    fi

    REMOTE_ID="$(printf '%s\n' "$info" | sed -n 's/^id=//p')"
    REMOTE_VERSION="$(printf '%s\n' "$info" | sed -n 's/^version=//p')"
    REMOTE_ARCH="$(printf '%s\n' "$info" | sed -n 's/^arch=//p')"
    REMOTE_UID="$(printf '%s\n' "$info" | sed -n 's/^uid=//p')"

    [[ -n "$REMOTE_UID" ]] || die "could not determine the remote user id"

    if [[ "$REMOTE_UID" != "0" ]]; then
        ssh_run "command -v sudo >/dev/null 2>&1" ||
            die "sudo is not installed on $TARGET"
        ssh_run "sudo -n true" >/dev/null 2>&1 ||
            die "passwordless sudo is required (sudo -n true failed for $TARGET)"
    fi

    ssh_run "command -v systemctl >/dev/null 2>&1" ||
        die "systemd is not available on $TARGET"

    if [[ "$REMOTE_ID" != "debian" || "$REMOTE_VERSION" != "13" ]]; then
        if (( ALLOW_OS )); then
            warn "$TARGET is ${REMOTE_ID} ${REMOTE_VERSION}, not Debian 13"
        else
            die "$TARGET is ${REMOTE_ID} ${REMOTE_VERSION}; RustIPS targets Debian 13 (pass --allow-unsupported-os)"
        fi
    fi

    if [[ "$REMOTE_ARCH" != "$(uname -m)" ]]; then
        warn "local arch $(uname -m) differs from remote arch $REMOTE_ARCH"
    fi

    if ! ssh_run "command -v nft >/dev/null 2>&1"; then
        warn "nft is not installed on $TARGET; enforce mode will not work until nftables is installed"
    fi
}

prepare_binary() {
    if (( BINARY_SET )); then
        [[ -f "$BINARY" ]] || die "binary not found: $BINARY"
        [[ -x "$BINARY" ]] || die "binary is not executable: $BINARY"
    fi

    if (( BUILD )) || [[ ! -x "$BINARY" ]]; then
        if ! command -v cargo >/dev/null 2>&1; then
            if [[ -f "$HOME/.cargo/env" ]]; then
                # shellcheck disable=SC1091
                . "$HOME/.cargo/env"
            fi
        fi
        command -v cargo >/dev/null 2>&1 ||
            die "cargo not found; install Rust or pass --binary PATH"

        local locked=()
        [[ -f "$PROJECT_DIR/Cargo.lock" ]] && locked=(--locked)
        step "Building release binary"
        (cd "$PROJECT_DIR" && cargo build --release "${locked[@]}")
    fi

    [[ -x "$BINARY" ]] || die "binary is not executable: $BINARY"
    BINARY="$(readlink -f "$BINARY")"
    VERSION_NEW="$("$BINARY" --version 2>/dev/null | awk '{ print $2 }')"
    [[ -n "$VERSION_NEW" ]] || die "could not read the local binary version"
    SHA_NEW="$(sha256sum "$BINARY" | cut -d' ' -f1)"
}

remote_state() {
    ssh_run "if [ -x '$PREFIX/rustips' ]; then echo binary=yes; else echo binary=no; fi
if [ -f /etc/rustips/config.toml ]; then echo config=yes; else echo config=no; fi
if [ -f /etc/systemd/system/$SERVICE.service ]; then echo unit=yes; else echo unit=no; fi"
}

remote_version() {
    ssh_run "if [ -x '$PREFIX/rustips' ]; then '$PREFIX/rustips' --version 2>/dev/null || true; fi" |
        awk 'NR == 1 { print $2 }'
}

dry_run_plan() {
    cat <<EOF
Deploy plan (no host contact)

  command:     $COMMAND
  target:      $TARGET
  ssh port:    $SSH_PORT
  identity:    ${IDENTITY:-ssh config/agent}
  install dir: $PREFIX
  service:     $SERVICE
  backups:     $BACKUP_DIR (keep $KEEP)
  binary:      $BINARY
  version:     ${VERSION_NEW:-<built on deploy>}
  sha256:      ${SHA_NEW:-<built on deploy>}

  deploy/install:
    1. check SSH, Debian 13, systemd and passwordless sudo
    2. upload the binary to /tmp and verify its SHA-256
    3. install it atomically at $PREFIX/rustips
    4. run 'rustips setup --install-service' when config/unit/PAM are missing
    5. enable and start $SERVICE, then check status, check and /healthz

  upgrade:
    stop $SERVICE, back up binary+config+unit+PAM+database to
    $BACKUP_DIR/<stamp>, replace the binary, restart and verify.
    A failed verification rolls back automatically unless --no-auto-rollback.

  rollback:
    stop $SERVICE, restore the selected backup tar, reload systemd, start and
    verify. --to selects a stamp; otherwise the most recent backup is used.
EOF
}

stage_binary() {
    STAGE="/tmp/rustips-deploy-$STAMP-$$"
    ssh_run "mkdir -p '$STAGE' && chmod 700 '$STAGE'" ||
        die "could not create $STAGE on $TARGET"

    if ! "${SSH[@]}" "$TARGET" "cat > '$STAGE/rustips' && chmod 600 '$STAGE/rustips'" <"$BINARY"; then
        die "binary upload failed"
    fi

    local remote_sha
    remote_sha="$(ssh_run "sha256sum '$STAGE/rustips' | cut -d' ' -f1")"
    [[ "$remote_sha" == "$SHA_NEW" ]] ||
        die "uploaded binary checksum mismatch (local $SHA_NEW, remote $remote_sha)"
    echo "staged $STAGE/rustips ($SHA_NEW)"
}

prepare_remote() {
    local mode="$1"
    local version_old="$2"

    root_script \
        "MODE=$mode" \
        "STAGE=$STAGE" \
        "PREFIX=$PREFIX" \
        "BACKUP_DIR=$BACKUP_DIR" \
        "SERVICE=$SERVICE" \
        "KEEP=$KEEP" \
        "STAMP=$STAMP" \
        "VERSION_OLD=$version_old" \
        "VERSION_NEW=$VERSION_NEW" \
        "SHA_NEW=$SHA_NEW" <<'EOS'
set -euo pipefail
umask 077

config=/etc/rustips/config.toml
state_dir=/var/lib/rustips
unit="/etc/systemd/system/${SERVICE}.service"
pam="/etc/pam.d/${SERVICE}"

install -d -m 0755 "$PREFIX"
install -d -m 0700 "$BACKUP_DIR"

if [ "$MODE" = "upgrade" ]; then
    backup="$BACKUP_DIR/$STAMP"
    install -d -m 0700 "$backup"

    if systemctl is-active --quiet "$SERVICE"; then
        echo "stopping $SERVICE for a consistent backup"
        systemctl stop "$SERVICE"
    fi

    files=()
    add() {
        local path="${1#/}"
        if [ -e "/$path" ]; then
            files+=("$path")
        fi
    }
    add "$PREFIX/rustips"
    add /etc/rustips
    add "$unit"
    add "$pam"
    add "$state_dir/rustips.db"
    add "$state_dir/rustips.db-wal"
    add "$state_dir/rustips.db-shm"

    if [ "${#files[@]}" -eq 0 ]; then
        echo "nothing to back up" >&2
        exit 1
    fi
    tar -C / -czf "$backup/backup.tar.gz" "${files[@]}"

    {
        echo "version=$VERSION_OLD"
        echo "new_version=$VERSION_NEW"
        echo "created=$STAMP"
        echo "phase=upgrade"
        echo "sha256=$SHA_NEW"
    } >"$backup/manifest"
    cp -a "$backup/manifest" "$BACKUP_DIR/latest.manifest"

    # Keep the newest $KEEP backups. Names sort chronologically.
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' |
        sort -r |
        tail -n +$((KEEP + 1)) |
        while read -r old; do
            rm -rf "$BACKUP_DIR/$old"
        done
    echo "backup: $backup"
fi

echo "installing $PREFIX/rustips ($VERSION_NEW)"
install -m 0755 -o root -g root "$STAGE/rustips" "$PREFIX/.rustips.new"
mv -f "$PREFIX/.rustips.new" "$PREFIX/rustips"

# setup --install-service is the only supported way to generate the unit (it
# embeds the current executable path). On upgrade, preserve a custom config.
need_setup=0
[ -f "$unit" ] || need_setup=1
[ -f "$pam" ] || need_setup=1
[ -f "$config" ] || need_setup=1
if [ "$need_setup" -eq 1 ]; then
    if [ -f "$config" ]; then
        saved="$BACKUP_DIR/config.preserve.$STAMP"
        cp -a "$config" "$saved"
        "$PREFIX/rustips" setup --install-service --force --non-interactive
        cp -a "$saved" "$config"
        chmod 600 "$config"
        rm -f "$saved"
    elif [ -f "$state_dir/rustips.db" ]; then
        "$PREFIX/rustips" setup --install-service --recover --non-interactive
    else
        "$PREFIX/rustips" setup --install-service --non-interactive
    fi
else
    systemctl daemon-reload
fi

systemctl enable "$SERVICE" >/dev/null
rm -rf "$STAGE"
echo "PREPARED mode=$MODE version=$VERSION_NEW"
EOS
}

verify_remote() {
    local expected_version="$1"

    root_script \
        "PREFIX=$PREFIX" \
        "SERVICE=$SERVICE" \
        "VERSION_NEW=$expected_version" \
        "SKIP_CHECK=$SKIP_CHECK" <<'EOS'
set -euo pipefail

if ! systemctl is-active --quiet "$SERVICE"; then
    systemctl start "$SERVICE" || true
fi

ready=0
for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$SERVICE"; then
        ready=1
        break
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "service $SERVICE is not active" >&2
    journalctl -u "$SERVICE" -n 60 --no-pager || true
    exit 1
fi

installed="$("$PREFIX/rustips" --version | awk '{ print $2 }')"
echo "installed version: $installed"
if [ -n "$VERSION_NEW" ] && [ "$installed" != "$VERSION_NEW" ]; then
    echo "version mismatch: expected $VERSION_NEW, got $installed" >&2
    exit 1
fi

"$PREFIX/rustips" status
if [ "$SKIP_CHECK" != "1" ]; then
    "$PREFIX/rustips" check
fi

config=/etc/rustips/config.toml
if [ -f "$config" ]; then
    enabled="$(awk -F= '/^\[web\]/{w=1;next} /^\[/{w=0} w && $1 ~ /^[ \t]*enabled[ \t]*$/ {gsub(/[ \t"]/,"",$2); print $2; exit}' "$config")"
    port="$(awk -F= '/^\[web\]/{w=1;next} /^\[/{w=0} w && $1 ~ /^[ \t]*port[ \t]*$/ {gsub(/[ \t"]/,"",$2); print $2; exit}' "$config")"
    port="${port:-10707}"
    if [ "$enabled" != "false" ]; then
        healthy=0
        for _ in $(seq 1 20); do
            body=""
            if command -v curl >/dev/null 2>&1; then
                body="$(curl -fsS --max-time 5 "http://127.0.0.1:$port/healthz" 2>/dev/null)" || body=""
            elif command -v python3 >/dev/null 2>&1; then
                body="$(python3 -c 'import sys,urllib.request; print(urllib.request.urlopen("http://127.0.0.1:"+sys.argv[1]+"/healthz", timeout=5).read().decode())' "$port" 2>/dev/null)" || body=""
            else
                echo "health check skipped: curl and python3 are unavailable"
                healthy=1
                break
            fi
            if printf '%s' "$body" | grep -q '"status":"ok"'; then
                healthy=1
                break
            fi
            sleep 1
        done
        if [ "$healthy" -ne 1 ]; then
            echo "UI health endpoint on 127.0.0.1:$port did not become ready" >&2
            journalctl -u "$SERVICE" -n 60 --no-pager || true
            exit 1
        fi
        echo "UI health: OK on 127.0.0.1:$port"
    fi
fi
EOS
}

rollback_deploy() {
    local stamp="$1"
    preflight

    step "Rolling back${stamp:+ to $stamp}"
    root_script \
        "BACKUP_DIR=$BACKUP_DIR" \
        "SERVICE=$SERVICE" \
        "PREFIX=$PREFIX" \
        "TO=$stamp" <<'EOS'
set -euo pipefail

if [ -n "${TO:-}" ]; then
    backup="$BACKUP_DIR/$TO"
else
    backup="$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | sed -n '1p' || true)"
fi

if [ -z "${backup:-}" ] || [ ! -f "$backup/backup.tar.gz" ]; then
    echo "no usable backup found under $BACKUP_DIR${TO:+ (wanted $TO)}" >&2
    exit 1
fi

echo "restoring $backup"
cat "$backup/manifest" 2>/dev/null || true

if systemctl is-active --quiet "$SERVICE"; then
    systemctl stop "$SERVICE"
fi

# The archive is authoritative. If it contains a database, drop the live
# database's SQLite sidecars first so a newer WAL cannot be applied to the
# restored file. A binary-only backup must leave the live database in place.
archive="$backup/backup.tar.gz"
members="$(tar -tzf "$archive")"
if grep -qx 'var/lib/rustips/rustips.db' <<<"$members"; then
    rm -f /var/lib/rustips/rustips.db-wal /var/lib/rustips/rustips.db-shm
fi
tar -xzf "$archive" -C /
systemctl daemon-reload
systemctl start "$SERVICE"
echo "restored $(basename "$backup")"
EOS

    verify_remote ""
}

deploy() {
    preflight

    local state phase version_old
    state="$(remote_state)"
    phase="deploy"
    if grep -q '^binary=yes$' <<<"$state" || grep -q '^config=yes$' <<<"$state"; then
        phase="upgrade"
    else
        phase="install"
    fi

    case "$COMMAND" in
        install)
            if [[ "$phase" == "upgrade" && "$FORCE" != "1" ]]; then
                die "RustIPS already exists on $TARGET; use 'upgrade' or pass --force"
            fi
            ;;
        upgrade)
            [[ "$phase" == "upgrade" ]] ||
                die "RustIPS is not installed on $TARGET; use 'install' or 'deploy'"
            ;;
    esac

    version_old="$(remote_version)"
    prepare_binary

    echo "target:  $TARGET"
    echo "phase:   $phase"
    echo "version: ${version_old:-none} -> $VERSION_NEW"
    echo "binary:  $BINARY"

    STAMP="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    stage_binary
    if ! prepare_remote "$phase" "$version_old"; then
        warn "remote preparation failed"
        ssh_run "rm -rf '$STAGE'" >/dev/null 2>&1 || true
        if [[ "$phase" == "upgrade" && "$AUTO_ROLLBACK" == "1" ]]; then
            rollback_deploy "$STAMP" || die "preparation failed and rollback also failed"
        fi
        die "preparation failed; inspect the host before retrying"
    fi

    if (( NO_RESTART )); then
        echo
        echo "Binary installed and unit enabled; the service was not started (--no-restart)."
        echo "Start it with: sudo systemctl start $SERVICE"
        return 0
    fi

    step "Starting and verifying"
    if verify_remote "$VERSION_NEW"; then
        cat <<EOF

Deployed RustIPS $VERSION_NEW to $TARGET.
  service: $SERVICE
  config:  /etc/rustips/config.toml
  binary:  $PREFIX/rustips
  backups: $BACKUP_DIR

Open the UI through a tunnel:
  ssh -p $SSH_PORT -L 10707:127.0.0.1:10707 $TARGET
EOF
        return 0
    fi

    if [[ "$phase" == "upgrade" && "$AUTO_ROLLBACK" == "1" ]]; then
        warn "verification failed; rolling back to $STAMP"
        rollback_deploy "$STAMP"
        die "deployment failed; host was rolled back to the previous version"
    fi

    root_script "SERVICE=$SERVICE" <<'EOS' || true
systemctl stop "$SERVICE" || true
journalctl -u "$SERVICE" -n 80 --no-pager || true
EOS
    die "deployment verification failed"
}

show_status() {
    preflight
    root_script \
        "PREFIX=$PREFIX" \
        "SERVICE=$SERVICE" \
        "BACKUP_DIR=$BACKUP_DIR" <<'EOS'
set -euo pipefail

echo "host:     $(hostname)"
active="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
enabled="$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)"
echo "service:  $SERVICE ($active, $enabled)"

if [ -x "$PREFIX/rustips" ]; then
    "$PREFIX/rustips" --version
    "$PREFIX/rustips" status || true
else
    echo "binary:   not installed at $PREFIX/rustips"
fi

config=/etc/rustips/config.toml
if [ -f "$config" ]; then
    port="$(awk -F= '/^\[web\]/{w=1;next} /^\[/{w=0} w && $1 ~ /^[ \t]*port[ \t]*$/ {gsub(/[ \t"]/,"",$2); print $2; exit}' "$config")"
    port="${port:-10707}"
    if command -v curl >/dev/null 2>&1; then
        body="$(curl -fsS --max-time 5 "http://127.0.0.1:$port/healthz" 2>/dev/null || true)"
        if printf '%s' "$body" | grep -q '"status":"ok"'; then
            echo "health:   OK (127.0.0.1:$port)"
        else
            echo "health:   unavailable (127.0.0.1:$port)"
        fi
    fi
else
    echo "config:   missing ($config)"
fi

echo "backups:  $BACKUP_DIR"
if [ -d "$BACKUP_DIR" ]; then
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | sed -n '1,5p' |
        while read -r dir; do
            if [ -f "$dir/manifest" ]; then
                printf '  %s  %s\n' "$(basename "$dir")" "$(tr '\n' ' ' <"$dir/manifest")"
            else
                printf '  %s\n' "$(basename "$dir")"
            fi
        done
fi
EOS
}

show_backups() {
    preflight
    root_script "BACKUP_DIR=$BACKUP_DIR" <<'EOS'
set -euo pipefail
found=0
while read -r dir; do
    found=1
    name="$(basename "$dir")"
    if [ -f "$dir/manifest" ]; then
        version="$(sed -n 's/^version=//p' "$dir/manifest")"
        created="$(sed -n 's/^created=//p' "$dir/manifest")"
        printf '%s  version=%s  created=%s\n' "$name" "${version:-unknown}" "${created:-unknown}"
    else
        printf '%s  (incomplete: no manifest)\n' "$name"
    fi
done < <(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r)
if [ "$found" -eq 0 ]; then
    echo "no backups under $BACKUP_DIR"
fi
EOS
}

case "$COMMAND" in
    deploy | install | upgrade)
        if (( DRY_RUN )); then
            if (( BINARY_SET )) && [[ ! -x "$BINARY" ]]; then
                die "binary is missing or not executable: $BINARY"
            fi
            if [[ -x "$BINARY" ]]; then
                VERSION_NEW="$("$BINARY" --version 2>/dev/null | awk '{ print $2 }')"
                SHA_NEW="$(sha256sum "$BINARY" | cut -d' ' -f1)"
            fi
            dry_run_plan
        else
            deploy
        fi
        ;;
    rollback)
        if (( DRY_RUN )); then
            dry_run_plan
        else
            rollback_deploy "$TO"
            echo
            echo "Rollback complete."
        fi
        ;;
    backups)
        if (( DRY_RUN )); then
            dry_run_plan
        else
            show_backups
        fi
        ;;
    status)
        if (( DRY_RUN )); then
            dry_run_plan
        else
            show_status
        fi
        ;;
    *)
        die "unknown command: $COMMAND (try --help)"
        ;;
esac
