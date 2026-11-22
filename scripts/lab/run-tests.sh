#!/usr/bin/env bash
# Lab acceptance checks for the 0.2.x sensor and web UI, run inside the Debian 13 VM.
#
# Usage: scripts/lab/run-tests.sh [PATH-TO-RUSTIPS-BINARY]
#
# Everything runs against a throwaway state directory under /tmp, so an
# existing installation is never touched. The replay checks need no root and
# no network. Pass --install to also exercise `setup --install-service`.
set -euo pipefail

BINARY="${1:-./target/release/rustips}"
if [[ ! -x "$BINARY" ]]; then
    echo "binary not found: $BINARY" >&2
    exit 1
fi
BINARY="$(readlink -f "$BINARY")"

INSTALL=0
[[ "${2:-}" == "--install" ]] && INSTALL=1

WORK="$(mktemp -d /tmp/rustips-lab.XXXXXX)"
export RUSTIPS_CONFIG="$WORK/config.toml"
export RUSTIPS_STATE_DIR="$WORK/state"
WEB_PID=""
trap '[[ -n "$WEB_PID" ]] && kill "$WEB_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

pass=0
fail=0
check() {
    local name="$1"
    shift
    if "$@"; then
        echo "PASS  $name"
        pass=$((pass + 1))
    else
        echo "FAIL  $name"
        fail=$((fail + 1))
    fi
}

echo "== setup =="
"$BINARY" setup --non-interactive
check "setup created config" test -f "$RUSTIPS_CONFIG"
check "setup created state" test -f "$RUSTIPS_STATE_DIR/rustips.db"
check "config is 0600" test "$(stat -c %a "$RUSTIPS_CONFIG")" = "600"
if "$BINARY" setup --non-interactive >/dev/null 2>&1; then
    echo "FAIL  second setup must refuse to overwrite config"
    fail=$((fail + 1))
else
    echo "PASS  second setup refuses to overwrite config"
    pass=$((pass + 1))
fi
check "config check alias" "$BINARY" config check
check "diagnose runs" bash -c "'$BINARY' diagnose | grep -q 'RustIPS'"

echo
echo "== check =="
"$BINARY" check

echo
echo "== first-run safety =="
mv "$RUSTIPS_CONFIG" "$WORK/config.saved"
if "$BINARY" run --pcap /dev/null >/dev/null 2>&1; then
    echo "FAIL  missing config with existing DB must refuse to start"
    fail=$((fail + 1))
else
    echo "PASS  missing config with existing DB refuses to start"
    pass=$((pass + 1))
fi
mv "$WORK/config.saved" "$RUSTIPS_CONFIG"

echo
echo "== replay =="
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to generate the test capture" >&2
    exit 1
fi
DEST="$(hostname -I | awk '{print $1}')"
python3 "$(dirname "$0")/../gen_test_pcap.py" "$WORK/scan.pcap" "$DEST"
"$BINARY" run --pcap "$WORK/scan.pcap" --fast-replay --no-web
"$BINARY" detections --limit 20 >"$WORK/detections.txt"
cat "$WORK/detections.txt"

for detector in DET-01 DET-03 DET-05 DET-06; do
    if grep -q "$detector" "$WORK/detections.txt"; then
        echo "PASS  $detector detected"
        pass=$((pass + 1))
    else
        echo "FAIL  $detector not detected"
        fail=$((fail + 1))
    fi
done
check "observe mode recorded no blocks" \
    test "$("$BINARY" status | awk '/^blocks:/ {print $2}')" = "0"

echo
echo "== web UI =="
# Build a capture whose timestamps are in the future, so the daemon stays up
# long enough to query while replaying it.
python3 - "$WORK/scan.pcap" "$WORK/slow.pcap" <<'PY'
import struct, sys, time
src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
off, i = 24, 0
base = int(time.time()) + 5
out = bytearray(data[:24])
while off < len(data):
    _sec, _usec, caplen, _wire = struct.unpack("<IIII", data[off:off + 16])
    rec = bytearray(data[off:off + 16 + caplen])
    struct.pack_into("<II", rec, 0, base + i, 0)
    out.extend(rec)
    off += 16 + caplen
    i += 1
open(dst, "wb").write(out)
PY
"$BINARY" run --pcap "$WORK/slow.pcap" --web-port 10710 >"$WORK/web.log" 2>&1 &
WEB_PID=$!
UP=0
for _ in $(seq 1 40); do
    if curl -fsS "http://127.0.0.1:10710/healthz" >"$WORK/health.json" 2>/dev/null; then
        UP=1
        break
    fi
    sleep 0.25
done
if [[ "$UP" == "1" ]]; then
    echo "PASS  healthz is up"
    pass=$((pass + 1))
else
    echo "FAIL  web UI did not become ready"
    fail=$((fail + 1))
    cat "$WORK/web.log"
fi
check "healthz reports the version" grep -q '"status":"ok"' "$WORK/health.json"
check "login page is served" bash -c "curl -fsS http://127.0.0.1:10710/login | grep -q 'system account'"
check "unauthenticated page redirects" bash -c "test \"$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:10710/detections)\" = 303"
check "foreign Host is rejected" bash -c "test \"$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: attacker.example' http://127.0.0.1:10710/healthz)\" = 421"
check "css is served" bash -c "test \"$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:10710/assets/app.css)\" = 200"
check "metrics are served on loopback" bash -c "curl -fsS http://127.0.0.1:10710/metrics | grep -q rustips_packets_total"
kill "$WEB_PID" 2>/dev/null || true
wait "$WEB_PID" 2>/dev/null || true
WEB_PID=""

echo
echo "== manual block =="
"$BINARY" block 203.0.113.99 --duration 1h --reason "lab test"
check "block recorded" test "$("$BINARY" status | awk '/^blocks:/ {print $2}')" = "1"
"$BINARY" unblock 203.0.113.99
check "block removed" test "$("$BINARY" status | awk '/^blocks:/ {print $2}')" = "0"
check "allowlist blocks manual block" bash -c "! '$BINARY' block 10.1.2.3 2>/dev/null"

if [[ "$INSTALL" == "1" ]]; then
    echo
    echo "== system install =="
    sudo env RUSTIPS_CONFIG="$RUSTIPS_CONFIG" RUSTIPS_STATE_DIR="$RUSTIPS_STATE_DIR" \
        "$BINARY" setup --install-service --force
    check "binary installed" test -x /usr/local/bin/rustips
    check "unit points at /usr/local/bin" grep -q 'ExecStart=/usr/local/bin/rustips run' /etc/systemd/system/rustips.service
    check "unit installed" test -f /etc/systemd/system/rustips.service
    check "pam service installed" test -f /etc/pam.d/rustips
    check "admin group exists" getent group rustips-admin
    check "unit is valid" systemd-analyze verify /etc/systemd/system/rustips.service
fi

echo
echo "== result: $pass passed, $fail failed =="
[[ "$fail" == "0" ]]
