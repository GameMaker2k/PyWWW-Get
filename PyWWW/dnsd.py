#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import socket
import struct
import threading
import argparse
import time
import random

try:
    # Py3
    from urllib.request import Request, urlopen
    from urllib.parse import urlencode
except ImportError:
    # Py2
    from urllib2 import Request, urlopen
    from urllib import urlencode

# -----------------------------
# Root server IPs (a subset)
# -----------------------------
ROOT_SERVERS = [
    "198.41.0.4",     # a.root-servers.net
    "199.9.14.201",   # b.root-servers.net
    "192.33.4.12",    # c.root-servers.net
    "199.7.91.13",    # d.root-servers.net
    "192.203.230.10", # e.root-servers.net
]

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
QCLASS_IN = 1

# -----------------------------
# Runtime-configurable options (CLI)
# -----------------------------
UPSTREAM_TIMEOUT = 2.0
CACHE_TTL_CAP = 0          # 0 = no cap
LOG_QUERIES = False
BLOCKLIST = set()

def load_roots(path):
    """Load root server IPs from a file (one IP per line; # comments allowed)."""
    if not path:
        return ROOT_SERVERS
    try:
        ips = []
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ips.append(line.split()[0])
        return ips or ROOT_SERVERS
    except Exception:
        return ROOT_SERVERS

def load_blocklist(path):
    """Load blocklist domains (one per line; # comments allowed)."""
    out = set()
    if not path:
        return out
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                dom = line.split()[0].lower().rstrip(".")
                if dom:
                    out.add(dom)
    except Exception:
        pass
    return out

def is_blocked(qname):
    """Exact or suffix match against BLOCKLIST."""
    d = (qname or "").strip().lower().rstrip(".")
    if not d:
        return False
    if d in BLOCKLIST:
        return True
    while "." in d:
        d = d.split(".", 1)[1]
        if d in BLOCKLIST:
            return True
    return False

def _byte_at(b, i):
    v = b[i]
    return v if isinstance(v, int) else ord(v)

def encode_qname(name):
    name = name.strip().rstrip(".")
    if not name:
        return b"\x00"
    out = []
    for part in name.split("."):
        pb = part.encode("utf-8") if not isinstance(part, bytes) else part
        out.append(struct.pack("!B", len(pb)) + pb)
    out.append(b"\x00")
    return b"".join(out)

def decode_name(msg, off):
    labels = []
    jumped = False
    orig = off
    seen = set()
    while True:
        if off >= len(msg):
            raise ValueError("name out of bounds")
        if off in seen:
            raise ValueError("compression loop")
        seen.add(off)

        ln = _byte_at(msg, off)
        if ln == 0:
            off += 1
            break
        if (ln & 0xC0) == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("truncated pointer")
            b2 = _byte_at(msg, off + 1)
            ptr = ((ln & 0x3F) << 8) | b2
            if not jumped:
                orig = off + 2
                jumped = True
            off = ptr
            continue

        off += 1
        lab = msg[off:off + ln]
        try:
            labels.append(lab.decode("utf-8"))
        except Exception:
            labels.append("".join(chr(_byte_at(lab, i)) for i in range(len(lab))))
        off += ln

    return ".".join(labels), (orig if jumped else off)

def build_query(qname, qtype, rd=False):
    tid = random.randint(0, 0xFFFF)
    flags = 0x0000
    if rd:
        flags |= 0x0100  # RD
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    q = encode_qname(qname) + struct.pack("!HH", qtype, QCLASS_IN)
    return tid, header + q

def parse_header(msg):
    if len(msg) < 12:
        raise ValueError("short header")
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", msg[:12])
    tc = bool(flags & 0x0200)
    rcode = flags & 0x000F
    return tid, flags, qd, an, ns, ar, tc, rcode

def skip_questions(msg, off, qd):
    for _ in range(qd):
        _, off = decode_name(msg, off)
        if off + 4 > len(msg):
            raise ValueError("truncated question")
        off += 4
    return off

def parse_rr(msg, off):
    name, off = decode_name(msg, off)
    if off + 10 > len(msg):
        raise ValueError("truncated rr header")
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
    off += 10
    rdata_off = off
    if off + rdlen > len(msg):
        raise ValueError("truncated rdata")
    rdata = msg[off:off + rdlen]
    off += rdlen
    return {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "rdlen": rdlen,
        "rdata": rdata,
        "rdata_off": rdata_off,
    }, off

def parse_sections(msg):
    tid, flags, qd, an, ns, ar, tc, rcode = parse_header(msg)
    off = 12
    off = skip_questions(msg, off, qd)

    answers = []
    for _ in range(an):
        rr, off = parse_rr(msg, off)
        answers.append(rr)

    authority = []
    for _ in range(ns):
        rr, off = parse_rr(msg, off)
        authority.append(rr)

    additional = []
    for _ in range(ar):
        rr, off = parse_rr(msg, off)
        additional.append(rr)

    return {
        "tid": tid,
        "flags": flags,
        "rcode": rcode,
        "tc": tc,
        "answers": answers,
        "authority": authority,
        "additional": additional,
        "raw": msg,
    }

def rr_ip_from_additional(rr):
    # A glue only (AAAA glue requires IPv6 socket support; intentionally skipped)
    if rr["type"] == QTYPE["A"] and rr["rdlen"] == 4:
        b = bytearray(rr["rdata"])
        return "%d.%d.%d.%d" % (b[0], b[1], b[2], b[3])
    return None

def udp_exchange(server_ip, wire_query, timeout=2, port=53):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(float(timeout))
    try:
        s.sendto(wire_query, (server_ip, int(port)))
        data, _ = s.recvfrom(4096)
        return data
    finally:
        s.close()

def iterative_resolve(qname, qtype, timeout=2, max_steps=25):
    """
    Returns a DNS response message (bytes) from the last server contacted.
    Follows referrals iteratively from the root.
    """
    next_servers = list(ROOT_SERVERS)
    random.shuffle(next_servers)
    last_msg = None

    for _step in range(max_steps):
        if not next_servers:
            break

        server = next_servers.pop(0)

        _tid, wire = build_query(qname, qtype, rd=False)
        try:
            resp = udp_exchange(server, wire, timeout=timeout)
        except Exception:
            continue

        last_msg = resp
        parsed = parse_sections(resp)

        # If got answers, done (CNAME may be returned as-is)
        if parsed["answers"]:
            return resp

        # Follow referral: NS in authority + glue in additional
        ns_names = []
        for rr in parsed["authority"]:
            if rr["type"] == QTYPE["NS"]:
                nsn, _ = decode_name(resp, rr["rdata_off"])
                ns_names.append(nsn)

        glue_ips = []
        for rr in parsed["additional"]:
            ip = rr_ip_from_additional(rr)
            if ip:
                glue_ips.append(ip)

        if glue_ips:
            random.shuffle(glue_ips)
            next_servers = glue_ips + next_servers
            continue

        # No glue: resolve NS name A using recursion of *this* iterative resolver
        if ns_names:
            random.shuffle(ns_names)
            resolved_ns_ips = []
            for nsn in ns_names[:3]:
                ns_resp = iterative_resolve(nsn, QTYPE["A"], timeout=timeout, max_steps=max_steps)
                if not ns_resp:
                    continue
                ns_parsed = parse_sections(ns_resp)
                for a_rr in ns_parsed["answers"]:
                    if a_rr["type"] == QTYPE["A"] and a_rr["rdlen"] == 4:
                        b = bytearray(a_rr["rdata"])
                        resolved_ns_ips.append("%d.%d.%d.%d" % (b[0], b[1], b[2], b[3]))
                if resolved_ns_ips:
                    break
            if resolved_ns_ips:
                random.shuffle(resolved_ns_ips)
                next_servers = resolved_ns_ips + next_servers
                continue

        return resp

    return last_msg

# -----------------------------
# Simple cache (positive only)
# -----------------------------
class Cache(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._store = {}  # key -> (expires_at, wire_response)

    def get(self, key):
        now = time.time()
        with self._lock:
            v = self._store.get(key)
            if not v:
                return None
            exp, msg = v
            if exp <= now:
                del self._store[key]
                return None
            return msg

    def put(self, key, msg, ttl=30):
        exp = time.time() + max(1, int(ttl))
        with self._lock:
            self._store[key] = (exp, msg)

CACHE = Cache()

# -----------------------------
# Stub resolver server (UDP + TCP)
# -----------------------------
def extract_question(msg):
    # returns (qname, qtype, qclass)
    _tid, _flags, qd, _an, _ns, _ar, _tc, _rcode = parse_header(msg)
    if qd < 1:
        raise ValueError("no question")
    off = 12
    qname, off = decode_name(msg, off)
    if off + 4 > len(msg):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack("!HH", msg[off:off + 4])
    return qname, qtype, qclass

def min_ttl_from_answers(resp_msg):
    try:
        p = parse_sections(resp_msg)
        ttls = [rr["ttl"] for rr in p["answers"]] or [30]
        return max(1, min(ttls))
    except Exception:
        return 30

def make_servfail(query_wire):
    # Minimal SERVFAIL response echoing question section
    if len(query_wire) < 12:
        return b"\x00\x00" + struct.pack("!H", 0x8002) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    tid = query_wire[:2]
    hdr = tid + struct.pack("!H", 0x8002) + struct.pack("!HHHH", 1, 0, 0, 0)
    return hdr + query_wire[12:]

def make_nxdomain(query_wire):
    # Minimal NXDOMAIN response echoing question section
    if len(query_wire) < 12:
        return b"\x00\x00" + struct.pack("!H", 0x8003) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    tid = query_wire[:2]
    hdr = tid + struct.pack("!H", 0x8003) + struct.pack("!HHHH", 1, 0, 0, 0)
    return hdr + query_wire[12:]

def handle_query_wire(query_wire, client_addr=None):
    qname, qtype, qclass = extract_question(query_wire)

    if LOG_QUERIES:
        who = ("%s:%s" % client_addr) if client_addr else "-"
        print("[DNS] from=%s qname=%s qtype=%d" % (who, qname, qtype))

    if is_blocked(qname):
        if LOG_QUERIES:
            print("[DNS] BLOCKED %s" % qname)
        return make_nxdomain(query_wire)

    key = (qname.lower(), qtype, qclass)

    cached = CACHE.get(key)
    if cached:
        return cached

    resp = iterative_resolve(qname, qtype, timeout=UPSTREAM_TIMEOUT)

    ttl = min_ttl_from_answers(resp)

    if CACHE_TTL_CAP and CACHE_TTL_CAP > 0:
        ttl = min(ttl, int(CACHE_TTL_CAP))

    CACHE.put(key, resp, ttl=ttl)
    return resp

def udp_server(bind_ip="127.0.0.1", port=5353):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind_ip, port))
    print("UDP DNS stub listening on %s:%d" % (bind_ip, port))
    while True:
        data, addr = s.recvfrom(4096)
        try:
            resp = handle_query_wire(data, client_addr=addr)
        except Exception:
            resp = make_servfail(data)
        s.sendto(resp, addr)

def tcp_server(bind_ip="127.0.0.1", port=5353):
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ss.bind((bind_ip, port))
    ss.listen(50)
    print("TCP DNS stub listening on %s:%d" % (bind_ip, port))
    while True:
        conn, _addr = ss.accept()
        threading.Thread(target=_tcp_client, args=(conn,), daemon=True).start()

def _recvn(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def _tcp_client(conn):
    try:
        hdr = _recvn(conn, 2)
        if not hdr:
            return
        (ln,) = struct.unpack("!H", hdr)
        q = _recvn(conn, ln)
        if not q:
            return
        try:
            resp = handle_query_wire(q)
        except Exception:
            resp = make_servfail(q)
        conn.sendall(struct.pack("!H", len(resp)) + resp)
    finally:
        try:
            conn.close()
        except Exception:
            pass

def run_stub(bind_ip="127.0.0.1", port=5353):
    t1 = threading.Thread(target=udp_server, args=(bind_ip, port))
    t2 = threading.Thread(target=tcp_server, args=(bind_ip, port))
    t1.daemon = True
    t2.daemon = True
    t1.start()
    t2.start()
    while True:
        time.sleep(3600)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple iterative DNS stub resolver (UDP + TCP)"
    )

    # Listener
    parser.add_argument("--bind", default="127.0.0.1",
                        help="IP address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5353,
                        help="Port to listen on (default: 5353)")

    # Upstream
    parser.add_argument("--upstream-timeout", type=float, default=2.0,
                        help="Timeout (seconds) per upstream hop (default: 2.0)")
    parser.add_argument("--timeout", type=float, default=None,
                        help="Alias for --upstream-timeout")

    # Cache control
    parser.add_argument("--cache-ttl-cap", type=int, default=0,
                        help="Max TTL to cache in seconds; 0=no cap (default: 0)")

    # Features
    parser.add_argument("--log-queries", action="store_true",
                        help="Log queries to stdout")
    parser.add_argument("--blocklist", type=str, default=None,
                        help="Path to blocklist file (one domain per line)")
    parser.add_argument("--roots", type=str, default=None,
                        help="Path to root server IP list (one IP per line)")

    args = parser.parse_args()

    # Apply runtime config
    UPSTREAM_TIMEOUT = float(args.upstream_timeout)
    if args.timeout is not None:
        UPSTREAM_TIMEOUT = float(args.timeout)

    CACHE_TTL_CAP = int(args.cache_ttl_cap) if args.cache_ttl_cap else 0
    LOG_QUERIES = bool(args.log_queries)

    if args.blocklist:
        BLOCKLIST = load_blocklist(args.blocklist)

    if args.roots:
        ROOT_SERVERS = load_roots(args.roots)

    print("Starting DNS stub on %s:%d" % (args.bind, args.port))
    print("Upstream timeout: %.2fs" % UPSTREAM_TIMEOUT)
    if CACHE_TTL_CAP:
        print("Cache TTL cap: %ds" % CACHE_TTL_CAP)
    if args.blocklist:
        print("Blocklist: %s (%d entries)" % (args.blocklist, len(BLOCKLIST)))
    if args.roots:
        print("Roots: %s (%d IPs)" % (args.roots, len(ROOT_SERVERS)))
    if LOG_QUERIES:
        print("Query logging: ON")

    run_stub(args.bind, args.port)
