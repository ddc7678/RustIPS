#!/usr/bin/env bash
# Provision a Debian 13 lab guest for the RustIPS acceptance checks.
#
# Runs as root inside the guest. cloud-init embeds this script in the seed and
# `scripts/lab/vm.sh provision` re-runs it over SSH, so it is idempotent.
#
# Environment:
#   LAB_ADMIN_USER  PAM test user in the rustips-admin group (default labadmin)
#   LAB_USER        PAM test user outside the group       (default labuser)
#   LAB_PASSWORD    password for both test users (empty: leave passwords alone)
#   SKIP_APT        1 = do not run apt-get (packages already present)
set -euo pipefail

LAB_ADMIN_USER="${LAB_ADMIN_USER:-labadmin}"
LAB_USER="${LAB_USER:-labuser}"
LAB_PASSWORD="${LAB_PASSWORD:-}"
SKIP_APT="${SKIP_APT:-0}"
export DEBIAN_FRONTEND=noninteractive

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

if [[ "$(id -u)" != "0" ]]; then
    echo "guest-provision.sh must run as root" >&2
    exit 1
fi

# ------------------------------------------------------------------ packages
if [[ "$SKIP_APT" != "1" ]]; then
    log "updating apt metadata"
    for attempt in 1 2 3; do
        if apt-get update -qq; then
            break
        fi
        if [[ "$attempt" == "3" ]]; then
            echo "apt-get update failed after 3 attempts" >&2
            exit 1
        fi
        sleep 5
    done

    required=(
        nftables
        nmap
        hydra
        tcpdump
        tcpreplay
        jq
        curl
        ca-certificates
        sudo
        openssh-server
        python3
    )
    log "installing base packages"
    apt-get install -y --no-install-recommends "${required[@]}"

    # TEST-11 names gobuster/nikto and hping3; keep going if a release does not
    # ship one of them so the rest of the guest remains usable.
    for package in hping3 gobuster nikto; do
        if apt-cache show "$package" >/dev/null 2>&1; then
            log "installing optional package $package"
            if ! apt-get install -y --no-install-recommends "$package"; then
                warn "could not install $package"
            fi
        else
            warn "optional package $package is not in this release"
        fi
    done
else
    log "skipping apt (SKIP_APT=1)"
fi

# --------------------------------------------------------------------- users
groupadd -f rustips-admin

ensure_user() {
    local user="$1"
    local extra_group="${2:-}"

    if ! id -u "$user" >/dev/null 2>&1; then
        log "creating user $user"
        useradd --create-home --shell /bin/bash "$user"
    fi
    if [[ -n "$extra_group" ]]; then
        usermod -aG "$extra_group" "$user"
    fi
    if [[ -n "$LAB_PASSWORD" ]]; then
        printf '%s:%s\n' "$user" "$LAB_PASSWORD" | chpasswd
    else
        warn "no LAB_PASSWORD; left password for $user unchanged"
    fi
}

ensure_user "$LAB_ADMIN_USER" rustips-admin
ensure_user "$LAB_USER"

# --------------------------------------------------------------- ssh policy
log "hardening ssh (key-only, no root login)"
install -d -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-rustips-lab.conf <<'EOF'
# Managed by the RustIPS lab provisioner.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
EOF

if sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
else
    warn "sshd rejected the generated configuration; left the old one running"
fi

# The cloud image ships root unlocked but without a password; lock the account
# as well so a console login cannot fall back to it.
if passwd -S root 2>/dev/null | awk '{print $2}' | grep -qv '^L$'; then
    passwd -l root >/dev/null 2>&1 || true
fi

# -------------------------------------------------------------------- report
echo
log "provisioning complete"
echo "  admin user: $LAB_ADMIN_USER (group rustips-admin)"
echo "  plain user: $LAB_USER"
for package in nftables nmap hydra tcpdump tcpreplay jq hping3 gobuster nikto; do
    if command -v "$package" >/dev/null 2>&1 || dpkg -s "$package" >/dev/null 2>&1; then
        echo "  package:    $package"
    fi
done
