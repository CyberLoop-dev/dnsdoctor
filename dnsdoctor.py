#!/usr/bin/env python3
"""dnsdoctor: ask several DNS resolvers the same question and spot the mismatch.

    python dnsdoctor.py example.com
    python dnsdoctor.py example.com -t MX,TXT
    python dnsdoctor.py 1.1.1.1                 # reverse lookup (PTR)
    python dnsdoctor.py example.com -s 192.0.2.53   # add your own resolver
"""
import argparse
import ipaddress
import json
import os
import random
import re
import socket
import struct
import sys
import time

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
NAMES = {v: k for k, v in TYPES.items()}
RCODES = {0: "OK", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
PUBLIC = [("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Quad9", "9.9.9.9")]
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def col(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


def build_query(name, qtype):
    tid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # recursion desired
    qname = b"".join(bytes([len(p)]) + p for p in (l.encode("idna") for l in name.rstrip(".").split("."))) + b"\0"
    return tid, header + qname + struct.pack(">HH", qtype, 1)


def read_name(buf, off):
    labels, end, hops = [], None, 0
    while True:
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | buf[off + 1]
            hops += 1
            if hops > 40:
                raise ValueError("compression loop")
            continue
        off += 1
        labels.append(buf[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels), (end if end is not None else off)


def parse_rdata(buf, off, rtype, rdlen):
    raw = buf[off:off + rdlen]
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntoa(raw)
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    if rtype in (2, 5, 12):
        return read_name(buf, off)[0]
    if rtype == 15:
        return f"{struct.unpack('>H', raw[:2])[0]} {read_name(buf, off + 2)[0]}"
    if rtype == 16:
        parts, i = [], 0
        while i < len(raw):
            ln = raw[i]
            parts.append(raw[i + 1:i + 1 + ln].decode("utf-8", "replace"))
            i += 1 + ln
        return "".join(parts)
    if rtype == 6:
        m, o = read_name(buf, off)
        r, o = read_name(buf, o)
        serial = struct.unpack(">I", buf[o:o + 4])[0]
        return f"{m} {r} serial={serial}"
    if rtype == 257 and rdlen > 2:
        tag_len = raw[1]
        return f"{raw[0]} {raw[2:2 + tag_len].decode()} \"{raw[2 + tag_len:].decode('utf-8', 'replace')}\""
    return raw.hex()


def parse_response(buf, tid):
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", buf[:12])
    if rid != tid:
        raise ValueError("transaction id mismatch")
    off = 12
    for _ in range(qd):
        _, off = read_name(buf, off)
        off += 4
    answers = []
    for _ in range(an):
        _, off = read_name(buf, off)
        rtype, _, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        answers.append({"type": NAMES.get(rtype, str(rtype)), "ttl": ttl, "value": parse_rdata(buf, off, rtype, rdlen)})
        off += rdlen
    return flags, answers


def ask(server, name, qtype, timeout):
    tid, pkt = build_query(name, qtype)
    t0 = time.time()
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(pkt, (server, 53))
        buf, _ = s.recvfrom(4096)
    flags, answers = parse_response(buf, tid)
    if flags & 0x200:  # truncated: retry over TCP
        with socket.create_connection((server, 53), timeout) as s:
            s.sendall(struct.pack(">H", len(pkt)) + pkt)
            ln = struct.unpack(">H", s.recv(2))[0]
            data = b""
            while len(data) < ln:
                chunk = s.recv(ln - len(data))
                if not chunk:
                    break
                data += chunk
        flags, answers = parse_response(data, tid)
    return flags & 0xF, answers, (time.time() - t0) * 1000


def system_resolvers():
    found = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                m = re.match(r"\s*nameserver\s+(\S+)", line)
                if m and not m.group(1).startswith("127.") and m.group(1) != "::1":
                    found.append(("System", m.group(1)))
    except OSError:
        pass
    return found[:2]


def main():
    ap = argparse.ArgumentParser(description="Query DNS records across several resolvers.")
    ap.add_argument("name", help="domain name, or an IP address for a reverse lookup")
    ap.add_argument("-t", "--types", default="A,AAAA,MX,NS,TXT", help="comma-separated record types")
    ap.add_argument("-s", "--server", action="append", default=[], help="extra resolver IP (repeatable)")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    name, types = a.name, [t.strip().upper() for t in a.types.split(",") if t.strip()]
    try:
        ip = ipaddress.ip_address(name)
        name, types = ip.reverse_pointer, ["PTR"]
    except ValueError:
        pass
    for t in types:
        if t not in TYPES:
            sys.exit(f"dnsdoctor: unknown type {t} (known: {', '.join(TYPES)})")

    resolvers = system_resolvers() + PUBLIC + [("Custom", s) for s in a.server]
    report, mismatch = {}, False
    for t in types:
        rows, sets = [], []
        for label, ip in resolvers:
            try:
                rcode, answers, ms = ask(ip, name, TYPES[t], a.timeout)
                vals = sorted(r["value"] for r in answers if r["type"] == t)
                ttl = min((r["ttl"] for r in answers), default=None)
                rows.append({"resolver": label, "ip": ip, "rcode": RCODES.get(rcode, str(rcode)), "ms": round(ms), "ttl": ttl, "values": vals})
                if rcode == 0:
                    sets.append(tuple(vals))
            except (OSError, ValueError, struct.error) as e:
                rows.append({"resolver": label, "ip": ip, "rcode": "ERROR", "ms": None, "ttl": None, "values": [], "error": str(e)})
        consistent = len(set(sets)) <= 1
        mismatch |= not consistent
        report[t] = {"consistent": consistent, "results": rows}

    if a.json:
        print(json.dumps(report, indent=2))
        return
    print(col("1", f"\n{name}"))
    for t, info in report.items():
        flag = col("32", "consistent") if info["consistent"] else col("1;31", "MISMATCH between resolvers")
        print(f"\n{col('1;36', t)}  {flag}")
        for r in info["results"]:
            ms = f"{r['ms']}ms" if r["ms"] is not None else "-"
            head = f"  {r['resolver']:<11}{r['ip']:<16}{r['rcode']:<9}{ms:<8}"
            body = ("; ".join(r["values"]) or col("2", r.get("error", "(no records)")))
            ttl = col("2", f"  ttl {r['ttl']}") if r["ttl"] is not None else ""
            print(head + body + ttl)
    if mismatch:
        print(col("2", "\nTip: differing answers right after a DNS change usually mean it is still propagating (watch the TTLs). "
                       "Round-robin A records can also differ legitimately."))
    sys.exit(1 if mismatch else 0)


if __name__ == "__main__":
    main()
