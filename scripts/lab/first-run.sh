#!/usr/bin/env bash
# TEST-39 first-run check on a CLEAN Debian 13 host over SSH.
#
# Usage: scripts/lab/first-run.sh [--port 22] [--binary PATH] user@host
#
# The host must not already have /etc/rustips/config.toml. The script copies
# the binary to /tmp, runs setup --install-service, starts the unit, waits for
# /healthz, and prints the elapsed install time. It does not enable enforce
# mode or start an attack; see docs/runbook.md for the review step.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
PORT=22
BINARY="$PROJECT_DIR/target/release/rustips"
TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        --binary) BINARY="$2"; shift 2 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) TARGET="$1"; shift ;;
    esac
done
[[ -n "$TARGET" ]] || { echo "usage: $0 [--port N] [--binary PATH] user@host" >&2; exit 1; }
[[ -x "$BINARY" ]] || { echo "binary not found: $BINARY" >&2; exit 1; }

ssh_run() { ssh -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" "$@"; }

if ssh_run 'test -e /etc/rustips/config.toml'; then
    echo "refusing: $TARGET already has /etc/rustips/config.toml" >&2
    echo "run this on a clean host or snapshot" >&2
    exit 1
fi

start="$(date +%s)"
echo "copying binary..."
scp -P "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$BINARY" "$TARGET:/tmp/rustips-first-run"
echo "setup + install-service..."
ssh_run 'sudo /tmp/rustips-first-run setup --non-interactive --install-service'
echo "starting the service..."
ssh_run 'sudo systemctl enable --now rustips'

echo "waiting for /healthz..."
for _ in $(seq 1 60); do
    if ssh_run 'curl -fsS http://127.0.0.1:10707/healthz >/dev/null 2>&1'; then
        break
    fi
    sleep 1
done
ssh_run 'curl -fsS http://127.0.0.1:10707/healthz'
echo
ssh_run 'sudo rustips check'
ssh_run 'sudo rustips status | head -20'
end="$(date +%s)"
elapsed=$((end - start))
echo
echo "first run completed in ${elapsed}s (gate: <600s)"
[[ "$elapsed" -lt 600 ]]
