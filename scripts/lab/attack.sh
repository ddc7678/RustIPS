#!/usr/bin/env bash
# Drive the detection catalog from a second host on the same L2 segment.
#
# Usage: scripts/lab/attack.sh TARGET_IP [MODE]
#   MODE: all (default), syn, udp, stealth, ack, icmp
#
# The VM needs a bridged/tap network for this; QEMU user-mode networking
# (10.0.2.0/24) cannot be reached from the host. For the deterministic,
# network-free checks use run-tests.sh instead.
#
# Requires nmap; hping3 is used for the ping flood when available.
set -euo pipefail

TARGET="${1:-}"
MODE="${2:-all}"
if [[ -z "$TARGET" ]]; then
    echo "usage: $0 TARGET_IP [all|syn|udp|stealth|ack|icmp]" >&2
    exit 2
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "nmap is required" >&2
    exit 1
fi

run() {
    local name="$1"
    shift
    echo "== $name =="
    "$@" || true
}

case "$MODE" in
    all | syn)
        run "DET-01 vertical SYN scan" nmap -sS -Pn -p 1-100 "$TARGET"
        ;;
esac
case "$MODE" in
    all | udp)
        run "DET-05 UDP scan" nmap -sU -Pn --top-ports 25 "$TARGET"
        ;;
esac
case "$MODE" in
    all | stealth)
        run "DET-03 FIN scan" nmap -sF -Pn -p 1-30 "$TARGET"
        run "DET-03 XMAS scan" nmap -sX -Pn -p 31-60 "$TARGET"
        run "DET-03 NULL scan" nmap -sN -Pn -p 61-90 "$TARGET"
        ;;
esac
case "$MODE" in
    all | ack)
        run "DET-04 ACK scan" nmap -sA -Pn -p 1-40 "$TARGET"
        ;;
esac
case "$MODE" in
    all | icmp)
        run "DET-06 ping sweep" nmap -sn "$TARGET/24"
        if command -v hping3 >/dev/null 2>&1; then
            run "DET-06 echo flood" hping3 --flood --icmp -c 200 "$TARGET"
        fi
        ;;
esac

cat <<EOF

Now check the sensor (inside the VM):
  sudo rustips status
  sudo rustips detections --limit 50

In enforce mode the source should appear under active blocks, and the
nftables set should match:
  sudo nft list set inet rustips blocked_v4
EOF
