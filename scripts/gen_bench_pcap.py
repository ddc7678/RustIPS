#!/usr/bin/env python3
"""Generate a large benign pcap for a throughput baseline.

Usage: scripts/gen_bench_pcap.py OUT.pcap DESTINATION_IP [COUNT]

Every source sends a handful of SYNs to distinct ports on one destination, so
the file exercises decode, per-source state and the bounded source table
without producing detections. Count defaults to 500000.
"""

import random
import struct
import sys
import time

ETH_P_IP = 0x0800


def ip_bytes(addr):
    return bytes(int(part) for part in addr.split("."))


def tcp_frame(src, dst, sport, dport):
    payload = b""
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x02, 8192, 0, 0)
    total_len = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0x4000, 64, 6, 0,
        ip_bytes(src), ip_bytes(dst),
    )
    return b"\x02" * 6 + b"\x04" * 6 + struct.pack("!H", ETH_P_IP) + ip_hdr + tcp_hdr + payload


def main():
    if len(sys.argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    out_path, dst = sys.argv[1], sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 500_000

    rng = random.Random(1234)
    now = int(time.time())
    with open(out_path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(count):
            # 198.18.0.0/15 is the benchmarking range.
            src = "198.%d.%d.%d" % (18 + (i // 65536) % 2, (i // 256) % 256, i % 256)
            sport = 40000 + rng.randrange(20000)
            dport = 1000 + (i % 10)
            frame = tcp_frame(src, dst, sport, dport)
            f.write(struct.pack("<IIII", now, 0, len(frame), len(frame)))
            f.write(frame)
    print("wrote %s (%d packets)" % (out_path, count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
