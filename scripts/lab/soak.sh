#!/usr/bin/env bash
# Short production-soak sampler for an installed RustIPS host.
#
# Run on the sensor host (as root or with passwordless sudo):
#   scripts/lab/soak.sh --duration 300 --interval 10
#
# It samples service memory/CPU/restarts, DB size, packet/drop counters, log
# state and alert queue every interval, writes JSONL and prints a summary with
# a 30-day disk-growth projection. It fails if RSS exceeds 512 MB, the service
# restarted, or capture drops exceed 1% of newly delivered packets.
set -euo pipefail

DURATION=300
INTERVAL=10
OUT=""
RUSTIPS="${RUSTIPS_BIN:-/usr/local/bin/rustips}"
METRICS="${RUSTIPS_METRICS:-http://127.0.0.1:10707/metrics}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --rustips) RUSTIPS="$2"; shift 2 ;;
        --metrics) METRICS="$2"; shift 2 ;;
        -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done
[[ "$DURATION" =~ ^[0-9]+$ && "$DURATION" -gt 0 ]] || { echo "invalid --duration" >&2; exit 1; }
[[ "$INTERVAL" =~ ^[0-9]+$ && "$INTERVAL" -gt 0 ]] || { echo "invalid --interval" >&2; exit 1; }
[[ -n "$OUT" ]] || OUT="/tmp/rustips-soak-$(date -u +%Y%m%dT%H%M%SZ).jsonl"
SUDO=""
if [[ "$(id -u)" != "0" ]]; then
    SUDO="sudo -n"
fi

value() {
    awk -v key="$1" '$1 == key { print $2; found=1 } END { if (!found) print 0 }' <<<"$2"
}
number() {
    tr -cd '0-9' <<<"${1:-0}" | head -c 24
}

echo "soak: ${DURATION}s at ${INTERVAL}s intervals -> $OUT"
: >"$OUT"
start=$SECONDS
end=$((start + DURATION))
while [[ $SECONDS -lt $end ]]; do
    ts="$(date -u +%FT%TZ)"
    mem="$(number "$(systemctl show rustips -p MemoryCurrent --value 2>/dev/null || echo 0)")"
    cpu="$(number "$(systemctl show rustips -p CPUUsageNSec --value 2>/dev/null || echo 0)")"
    restarts="$(number "$(systemctl show rustips -p NRestarts --value 2>/dev/null || echo 0)")"
    db="$(number "$($SUDO stat -c %s /var/lib/rustips/rustips.db 2>/dev/null || echo 0)")"
    metrics="$(curl -fsS "$METRICS" 2>/dev/null || true)"
    packets="$(value rustips_packets_total "$metrics")"
    drops="$(value rustips_capture_drops_total "$metrics")"
    detections="$(value rustips_detections_stored "$metrics")"
    alerts_pending="$(value rustips_alerts_pending "$metrics")"
    alerts_failed="$(value rustips_alerts_failed "$metrics")"
    status="$($SUDO "$RUSTIPS" status 2>/dev/null || true)"
    log_events="$(awk '/^log events:/ {print $3}' <<<"$status" | tail -1)"
    journal="$(awk '/^journal:/ {print $2}' <<<"$status" | tail -1)"
    printf '{"ts":"%s","rss_bytes":%s,"cpu_ns":%s,"restarts":%s,"db_bytes":%s,"packets":%s,"drops":%s,"detections":%s,"log_events":%s,"alerts_pending":%s,"alerts_failed":%s,"journal":"%s"}\n' \
        "$ts" "${mem:-0}" "${cpu:-0}" "${restarts:-0}" "${db:-0}" "${packets:-0}" "${drops:-0}" \
        "${detections:-0}" "${log_events:-0}" "${alerts_pending:-0}" "${alerts_failed:-0}" "${journal:-unknown}" >>"$OUT"
    sleep "$INTERVAL"
done

python3 - "$OUT" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
if len(rows) < 2:
    print("not enough samples")
    raise SystemExit(2)
first, last = rows[0], rows[-1]
wall = max((__import__("datetime").datetime.fromisoformat(last["ts"].replace("Z", "+00:00")) -
            __import__("datetime").datetime.fromisoformat(first["ts"].replace("Z", "+00:00"))).total_seconds(), 1)
cpu = max(last["cpu_ns"] - first["cpu_ns"], 0) / 1e9
rss_max = max(row["rss_bytes"] for row in rows)
db_growth = last["db_bytes"] - first["db_bytes"]
packets = last["packets"] - first["packets"]
drops = last["drops"] - first["drops"]
projection = (db_growth / wall) * 86400 * 30
print(f"samples: {len(rows)} over {wall:.0f}s")
print(f"RSS max: {rss_max/1024/1024:.1f} MiB (cap 512 MiB)")
print(f"CPU used: {cpu:.2f}s over {wall:.0f}s ({cpu/wall*100:.2f}% of one core)")
print(f"service restarts: {last['restarts'] - first['restarts']}")
print(f"packets: {packets} · capture drops: {drops}")
print(f"detections: {last['detections']} · log events: {last['log_events']} · journal: {last['journal']}")
print(f"alert queue: {last['alerts_pending']} pending · {last['alerts_failed']} failed")
print(f"DB: {last['db_bytes']/1024/1024:.2f} MiB · 30-day projection: {projection/1024/1024:.1f} MiB")
fail = []
if rss_max > 512 * 1024 * 1024:
    fail.append("RSS exceeded 512 MiB")
if last["restarts"] != first["restarts"]:
    fail.append("service restarted during soak")
if packets > 0 and drops * 100 > packets:
    fail.append("capture drops exceeded 1%")
if projection > 256 * 1024 * 1024:
    fail.append("30-day DB projection exceeds 256 MiB")
if fail:
    print("FAIL:", "; ".join(fail))
    raise SystemExit(1)
print("PASS: soak gates met")
PY
