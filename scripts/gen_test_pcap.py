#!/usr/bin/env python3
"""Generate a synthetic pcap that exercises the 0.1 detectors.

Usage: scripts/gen_test_pcap.py OUT.pcap DESTINATION_IP

The file contains, from three public sources:
  * a 25-port TCP SYN scan          -> DET-01
  * a 25-port empty-payload UDP scan -> DET-05
  * five FIN-only TCP probes         -> DET-03
  * a 20-host ICMP echo sweep        -> DET-06

`DESTINATION_IP` should be one of this host's addresses, because the TCP and
UDP detectors only consider traffic addressed to the machine.
"""

import struct
import sys
import time

ETH_P_IP = 0x0800


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_bytes(addr):
    return bytes(int(part) for part in addr.split("."))


def eth_ipv4(src, dst, proto, payload, ident=0):
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ident & 0xFFFF,
        0x4000,
        64,
        proto,
        0,
        ip_bytes(src),
        ip_bytes(dst),
    )
    csum = checksum(header)
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    frame = b"\x02" * 6 + b"\x04" * 6 + struct.pack("!H", ETH_P_IP) + header + payload
    return frame


def tcp(src, dst, sport, dport, flags, seq=0, payload=b""):
    offset = 5 << 4
    hdr = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, 0, offset, flags, 8192, 0, 0
    )
    return eth_ipv4(src, dst, 6, hdr + payload)


def udp(src, dst, sport, dport, payload=b""):
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    return eth_ipv4(src, dst, 17, hdr + payload)


def icmp_echo(src, dst, ident, seq):
    body = b"rustips-test"
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    csum = checksum(hdr + body)
    hdr = struct.pack("!BBHHH", 8, 0, csum, ident, seq)
    return eth_ipv4(src, dst, 1, hdr + body)


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    out_path, host = sys.argv[1], sys.argv[2]

    now = int(time.time())
    packets = []

    scanner = "203.0.113.7"
    for i, port in enumerate(range(1001, 1026)):
        packets.append((now, tcp(scanner, host, 40000, port, 0x02, seq=i)))

    udp_scanner = "198.51.100.5"
    for port in range(2001, 2026):
        packets.append((now + 1, udp(udp_scanner, host, 41000, port)))

    stealth = "192.0.2.9"
    for port in range(1, 6):
        packets.append((now + 2, tcp(stealth, host, 42000, port, 0x01)))

    sweep = "198.51.100.77"
    for last in range(1, 21):
        packets.append((now + 3, icmp_echo(sweep, "203.0.113.%d" % last, 7, last)))

    with open(out_path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            f.write(struct.pack("<IIII", ts, 0, len(frame), len(frame)))
            f.write(frame)

    print("wrote %s (%d packets)" % (out_path, len(packets)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
