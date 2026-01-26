#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import socket
import struct
import threading
import time
import random
import ssl

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

def _bchr(x):
    # py2/3
    return bytes(bytearray([x]))

def _byte_at(b, i):
    v = b[i]
    return v if isinstance(v, int) else ord(v)

def encode_qname(name):
    name = name.strip().rstrip('.')
    if not name:
        return b"\x00"
    out = []
    for part in name.split('.'):
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
            b2 = _byte_at(msg, off + 1)
            ptr = ((ln & 0x3F) << 8) | b2
            if not jumped:
                orig = off + 2
                jumped = True
            off = ptr
            continue

        off += 1
        lab = msg[off:off+ln]
        try:
            labels.append(lab.decode("utf-8"))
        except Exception:
            # best-effort
            labels.append("".join(chr(_byte_at(lab, i)) for i in range(len(lab))))
        off += ln

    return ".".join(labels), (orig if jumped else off)

def build_query(qname, qtype, rd=False, dnssec_do=False):
    tid = random.randint(0, 0xFFFF)
    flags = 0x0000
    if rd:
        flags |= 0x0100  # RD
    # We are not implementing EDNS0 fully here; dnssec_do placeholder is kept.
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
        off += 4
    return off

def parse_rr(msg, off):
    name, off = decode_name(msg, off)
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", msg[off:off+10])
    off += 10
    rdata_off = off
    rdata = msg[off:off+rdlen]
    off += rdlen
    return {
        "name": name, "type": rtype, "class": rclass, "ttl": ttl,
        "rdlen": rdlen, "rdata": rdata, "rdata_off": rdata_off
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
        "tid": tid, "flags": flags, "rcode": rcode, "tc": tc,
        "answers": answers, "authority": authority, "additional": additional,
        "raw": msg
    }

def rr_ip_from_additional(rr):
    # A or AAAA glue
    if rr["type"] == QTYPE["A"] and rr["rdlen"] == 4:
        b = bytearray(rr["rdata"])
        return "%d.%d.%d.%d" % (b[0], b[1], b[2], b[3])
    if rr["type"] == QTYPE["AAAA"] and rr["rdlen"] == 16:
        # simple hextets (no compression)
        b = bytearray(rr["rdata"])
        hextets = []
        for i in range(0, 16, 2):
            hextets.append("%02x%02x" % (b[i], b[i+1]))
        return ":".join(hextets)
    return None

def udp_exchange(server_ip, wire_query, timeout=2, port=53):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(wire_query, (server_ip, port))
        data, _ = s.recvfrom(4096)
        return data
    finally:
        s.close()

def iterative_resolve(qname, qtype, timeout=2, max_steps=25):
    """
    Returns a full DNS response message (bytes) from the final authoritative.
    If it cannot fully resolve, returns the last response received.
    """
    # Start at root
    next_servers = list(ROOT_SERVERS)
    last_msg = None

    for _step in range(max_steps):
        if not next_servers:
            break

        server = next_servers[0]
        next_servers = next_servers[1:]

        tid, wire = build_query(qname, qtype, rd=False)
        try:
            resp = udp_exchange(server, wire, timeout=timeout)
        except Exception:
            continue

        last_msg = resp
        parsed = parse_sections(resp)

        # If got answers, done (could be CNAME; this simple version returns as-is)
        if parsed["answers"]:
            return resp

        # Otherwise follow referral using NS in authority + glue in additional
        ns_names = []
        for rr in parsed["authority"]:
            if rr["type"] == QTYPE["NS"]:
                # NS rdata is a domain name; decode from msg at rdata_off
                nsn, _ = decode_name(resp, rr["rdata_off"])
                ns_names.append(nsn)

        glue_ips = []
        for rr in parsed["additional"]:
            ip = rr_ip_from_additional(rr)
            if ip:
                glue_ips.append(ip)

        if glue_ips:
            # Use glue
            next_servers = glue_ips + next_servers
            continue

        # No glue: resolve NS name A using recursion of *this* iterative resolver
        # (bootstraps by resolving ns hostnames)
        if ns_names:
            resolved_ns_ips = []
            for nsn in ns_names[:3]:
                # resolve NS hostname to A via iterative
                ns_resp = iterative_resolve(nsn, QTYPE["A"], timeout=timeout, max_steps=max_steps)
                ns_parsed = parse_sections(ns_resp)
                for a_rr in ns_parsed["answers"]:
                    if a_rr["type"] == QTYPE["A"] and a_rr["rdlen"] == 4:
                        b = bytearray(a_rr["rdata"])
                        resolved_ns_ips.append("%d.%d.%d.%d" % (b[0], b[1], b[2], b[3]))
                if resolved_ns_ips:
                    break
            if resolved_ns_ips:
                next_servers = resolved_ns_ips + next_servers
                continue

        # If we got here: cannot progress, return what we have
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
    # returns (qname, qtype, qclass, q_off_end)
    tid, flags, qd, an, ns, ar, tc, rcode = parse_header(msg)
    off = 12
    qname, off = decode_name(msg, off)
    qtype, qclass = struct.unpack("!HH", msg[off:off+4])
    off += 4
    return qname, qtype, qclass

def min_ttl_from_answers(resp_msg):
    try:
        p = parse_sections(resp_msg)
        ttls = [rr["ttl"] for rr in p["answers"]] or [30]
        return max(1, min(ttls))
    except Exception:
        return 30

def handle_query_wire(query_wire):
    qname, qtype, qclass = extract_question(query_wire)
    key = (qname.lower(), qtype, qclass)

    cached = CACHE.get(key)
    if cached:
        return cached

    # Iterative upstream (UDP) by default
    resp = iterative_resolve(qname, qtype)

    # Cache based on min TTL in answer section
    ttl = min_ttl_from_answers(resp)
    CACHE.put(key, resp, ttl=ttl)
    return resp

def udp_server(bind_ip="127.0.0.1", port=5353):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind_ip, port))
    print("UDP DNS stub listening on %s:%d" % (bind_ip, port))
    while True:
        data, addr = s.recvfrom(4096)
        try:
            resp = handle_query_wire(data)
        except Exception:
            # SERVFAIL minimal
            tid = data[:2] if len(data) >= 2 else b"\x00\x00"
            # flags: QR=1, RCODE=2
            resp = tid + struct.pack("!H", 0x8002) + b"\x00\x01\x00\x00\x00\x00\x00\x00" + data[12:]
        s.sendto(resp, addr)

def tcp_server(bind_ip="127.0.0.1", port=5353):
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ss.bind((bind_ip, port))
    ss.listen(50)
    print("TCP DNS stub listening on %s:%d" % (bind_ip, port))
    while True:
        conn, addr = ss.accept()
        threading.Thread(target=_tcp_client, args=(conn,), daemon=False).start()

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
    run_stub("127.0.0.1", 5353)
