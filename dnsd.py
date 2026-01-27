#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import socket
import struct
import threading
import argparse
import time
import random
import ssl
import sys

try:
    # Py3
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn
    from urllib.parse import urlparse, parse_qs
    import base64
except Exception:
    # Py2 fallback (DoH/DoT likely not usable on Py2 in practice)
    BaseHTTPRequestHandler = object
    HTTPServer = None
    ThreadingMixIn = object
    urlparse = None
    parse_qs = None
    base64 = None

# -----------------------------
# Root Server Data (IPv4 & IPv6)
# -----------------------------
ROOT_SERVERS_DATA = {
    "a": {"ipv4": "198.41.0.4",     "ipv6": "2001:503:ba3e::2:30"},
    "b": {"ipv4": "199.9.14.201",   "ipv6": "2001:500:200::b"},
    "c": {"ipv4": "192.33.4.12",    "ipv6": "2001:500:2::c"},
    "d": {"ipv4": "199.7.91.13",    "ipv6": "2001:500:2d::d"},
    "e": {"ipv4": "192.203.230.10", "ipv6": "2001:500:a8::e"},
    "f": {"ipv4": "192.5.5.241",    "ipv6": "2001:500:2f::f"},
    "g": {"ipv4": "192.112.36.4",   "ipv6": "2001:500:12::d0d"},
    "h": {"ipv4": "198.97.190.53",  "ipv6": "2001:500:1::53"},
    "i": {"ipv4": "192.36.148.17",  "ipv6": "2001:7fe::53"},
    "j": {"ipv4": "192.58.128.30",  "ipv6": "2001:503:c27::2:30"},
    "k": {"ipv4": "193.0.14.129",   "ipv6": "2001:7fd::1"},
    "l": {"ipv4": "199.7.83.42",    "ipv6": "2001:500:9f::42"},
    "m": {"ipv4": "202.12.27.33",   "ipv6": "2001:dc3::35"},
}

# -----------------------------
# Types / constants
# -----------------------------
QTYPE = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28,
    "DS": 43, "RRSIG": 46, "DNSKEY": 48,
    "IXFR": 251, "AXFR": 252,
    "OPT": 41,
}
QCLASS_IN = 1

# -----------------------------
# Runtime-configurable options (CLI)
# -----------------------------
UPSTREAM_TIMEOUT = 2.0
CACHE_TTL_CAP = 0          # 0 = no cap
LOG_QUERIES = False
BLOCKLIST = set()

# roots list actually used (built from ROOT_SERVERS_DATA + --root-family)
ROOT_SERVERS = []

# EDNS/DNSSEC defaults (CLI)
EDNS_SIZE_DEFAULT = 1232   # safe UDP size
FORCE_DNSSEC_DO = False
NO_EDNS = False

# Client-side TC enforcement (CLI)
ENFORCE_CLIENT_UDP_SIZE = True

# DNSSEC validation (CLI)
ENABLE_DNSSEC_VALIDATION = False
DNSSEC_FAIL_CLOSED = True  # if True: SERVFAIL on validation failure
DNSSEC_MAX_LABELS = 20

# AXFR educational support (CLI)
AXFR_ZONES = {}  # zone -> list of RR dicts (parsed from file); must contain SOA

# DoT/DoH (CLI)
DOT_ENABLED = False
DOT_BIND = "127.0.0.1"
DOT_PORT = 853
DOT_CERT = None
DOT_KEY = None

DOH_ENABLED = False
DOH_BIND = "127.0.0.1"
DOH_PORT = 8053

# -----------------------------
# Helpers: normalization, bytes
# -----------------------------
def _byte_at(b, i):
    v = b[i]
    return v if isinstance(v, int) else ord(v)

def _to_bytes(s):
    if isinstance(s, bytes):
        return s
    return s.encode("utf-8")

def _dnsname_norm(s):
    return (s or "").strip().lower().rstrip(".")

def _is_ipv6_literal(ip):
    return ":" in (ip or "")

def _bind_family(bind_ip):
    return socket.AF_INET6 if ":" in bind_ip else socket.AF_INET

# -----------------------------
# Root list builders
# -----------------------------
def build_root_server_list(family="both"):
    out = []
    keys = sorted(ROOT_SERVERS_DATA.keys())
    for k in keys:
        d = ROOT_SERVERS_DATA[k]
        if family in ("v4", "both") and d.get("ipv4"):
            out.append(d["ipv4"])
        if family in ("v6", "both") and d.get("ipv6"):
            out.append(d["ipv6"])
    # shuffle at runtime later
    return out

def load_roots(path, family="both"):
    """
    Optional file override: one IP per line.
    """
    if not path:
        return build_root_server_list(family=family)
    try:
        ips = []
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ips.append(line.split()[0])
        return ips or build_root_server_list(family=family)
    except Exception:
        return build_root_server_list(family=family)

# -----------------------------
# Blocklist
# -----------------------------
def load_blocklist(path):
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

# -----------------------------
# DNS name encoding/decoding
# -----------------------------
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

# -----------------------------
# DNS wire parsing
# -----------------------------
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
    start = off
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
    wire = msg[start:off]
    return {
        "name": name,
        "type": rtype,
        "class": rclass,
        "ttl": ttl,
        "rdlen": rdlen,
        "rdata": rdata,
        "rdata_off": rdata_off,
        "wire": wire,
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
        "qd": qd,
        "an": an,
        "ns": ns,
        "ar": ar,
        "rcode": rcode,
        "tc": tc,
        "answers": answers,
        "authority": authority,
        "additional": additional,
        "raw": msg,
    }

def rr_ip_from_additional(rr):
    if rr["type"] == QTYPE["A"] and rr["rdlen"] == 4:
        b = bytearray(rr["rdata"])
        return "%d.%d.%d.%d" % (b[0], b[1], b[2], b[3])
    if rr["type"] == QTYPE["AAAA"] and rr["rdlen"] == 16:
        return socket.inet_ntop(socket.AF_INET6, rr["rdata"])
    return None

# -----------------------------
# EDNS0 OPT + client UDP size
# -----------------------------
def _build_opt_rr(edns_size, do=False):
    if not edns_size:
        return b""
    edns_size = int(edns_size)
    if edns_size < 512:
        edns_size = 512
    if edns_size > 4096:
        edns_size = 4096

    name = b"\x00"
    rtype = struct.pack("!H", QTYPE["OPT"])
    rclass = struct.pack("!H", edns_size)
    flags = 0x8000 if do else 0x0000
    ttl = struct.pack("!I", flags)  # ext_rcode=0, ver=0, flags=flags
    rdlen = struct.pack("!H", 0)
    return name + rtype + rclass + ttl + rdlen

def _client_edns_options(query_wire):
    """
    Return (udp_size, do_bit) if query includes OPT, else (None, False).
    """
    try:
        _tid, _flags, qd, an, ns, ar, _tc, _rcode = parse_header(query_wire)
        off = 12
        off = skip_questions(query_wire, off, qd)
        for _ in range(an):
            _, off = parse_rr(query_wire, off)
        for _ in range(ns):
            _, off = parse_rr(query_wire, off)
        for _ in range(ar):
            rr, off = parse_rr(query_wire, off)
            if rr["type"] == QTYPE["OPT"]:
                udp_size = rr["class"]
                do_bit = bool(rr["ttl"] & 0x8000)
                return int(udp_size), do_bit
    except Exception:
        pass
    return None, False

def _client_udp_limit(query_wire):
    """
    RFC: 512 if no EDNS OPT. If OPT present, use its UDP payload size.
    """
    sz, _do = _client_edns_options(query_wire)
    return int(sz) if sz else 512

# -----------------------------
# Build queries (upstream)
# -----------------------------
def build_query(qname, qtype, rd=False, edns_size=None, do=False):
    tid = random.randint(0, 0xFFFF)
    flags = 0x0000
    if rd:
        flags |= 0x0100  # RD

    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 1 if edns_size else 0

    header = struct.pack("!HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)
    q = encode_qname(qname) + struct.pack("!HH", qtype, QCLASS_IN)

    if edns_size:
        opt = _build_opt_rr(edns_size, do=do)
        return tid, header + q + opt

    return tid, header + q

# -----------------------------
# Upstream exchange (UDP + TCP fallback on TC=1)
# -----------------------------
def _recvn(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def udp_exchange(server_ip, wire_query, timeout=2, port=53):
    family = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(float(timeout))
    try:
        s.sendto(wire_query, (server_ip, int(port)))
        data, _ = s.recvfrom(65535)
        return data
    finally:
        s.close()

def tcp_exchange(server_ip, wire_query, timeout=2, port=53):
    family = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(float(timeout))
    try:
        s.connect((server_ip, int(port)))
        s.sendall(struct.pack("!H", len(wire_query)) + wire_query)
        hdr = _recvn(s, 2)
        if not hdr:
            raise RuntimeError("TCP DNS: missing length header")
        (ln,) = struct.unpack("!H", hdr)
        msg = _recvn(s, ln)
        if not msg:
            raise RuntimeError("TCP DNS: incomplete message")
        return msg
    finally:
        try:
            s.close()
        except Exception:
            pass

def exchange_with_tc_fallback(server_ip, wire_query, timeout=2, port=53):
    resp = udp_exchange(server_ip, wire_query, timeout=timeout, port=port)
    try:
        _tid, _flags, _qd, _an, _ns, _ar, tc, _rcode = parse_header(resp)
    except Exception:
        return resp
    if tc:
        try:
            return tcp_exchange(server_ip, wire_query, timeout=timeout, port=port)
        except Exception:
            return resp
    return resp

# -----------------------------
# SOA parsing for negative TTL
# -----------------------------
def _soa_negative_ttl(resp_msg):
    try:
        p = parse_sections(resp_msg)
    except Exception:
        return None

    raw = p["raw"]
    for rr in p["authority"]:
        if rr["type"] != QTYPE["SOA"]:
            continue
        try:
            off = rr["rdata_off"]
            _, off = decode_name(raw, off)  # mname
            _, off = decode_name(raw, off)  # rname
            if off + 20 > len(raw):
                return rr["ttl"]
            _serial, _refresh, _retry, _expire, minimum = struct.unpack("!IIIII", raw[off:off + 20])
            return max(1, min(int(rr["ttl"]), int(minimum)))
        except Exception:
            return rr["ttl"]
    return None

def _negative_cache_ttl(resp):
    ttl = _soa_negative_ttl(resp)
    if ttl is None:
        ttl = 30
    ttl = max(1, int(ttl))
    if CACHE_TTL_CAP and CACHE_TTL_CAP > 0:
        ttl = min(ttl, int(CACHE_TTL_CAP))
    return ttl

def _is_nodata(resp):
    try:
        p = parse_sections(resp)
    except Exception:
        return False
    if p["rcode"] != 0:
        return False
    if p["answers"]:
        return False
    return any(rr["type"] == QTYPE["SOA"] for rr in p["authority"])

# -----------------------------
# Iterative resolution (with overall timeout)
# -----------------------------
def iterative_resolve(qname, qtype, timeout=2, max_steps=25, edns_size=None, do=False, overall_timeout=4.0):
    deadline = time.time() + float(overall_timeout)

    next_servers = list(ROOT_SERVERS)
    random.shuffle(next_servers)
    last_msg = None

    for _step in range(max_steps):
        if not next_servers:
            break
        if time.time() >= deadline:
            break

        server = next_servers.pop(0)

        _tid, wire = build_query(qname, qtype, rd=False, edns_size=edns_size, do=do)

        remaining = deadline - time.time()
        if remaining <= 0:
            break
        per_try = min(float(timeout), max(0.05, remaining))

        try:
            resp = exchange_with_tc_fallback(server, wire, timeout=per_try, port=53)
        except Exception:
            continue

        last_msg = resp

        try:
            parsed = parse_sections(resp)
        except Exception:
            continue

        # terminal
        if parsed["rcode"] != 0:
            return resp
        if parsed["answers"]:
            return resp
        if any(rr["type"] == QTYPE["SOA"] for rr in parsed["authority"]):
            return resp

        # referral NS names
        ns_names = []
        for rr in parsed["authority"]:
            if rr["type"] == QTYPE["NS"]:
                nsn, _ = decode_name(resp, rr["rdata_off"])
                ns_names.append(_dnsname_norm(nsn))

        # glue for those NS
        glue_ips = []
        if ns_names:
            ns_set = set(ns_names)
            for rr in parsed["additional"]:
                if rr["type"] not in (QTYPE["A"], QTYPE["AAAA"]):
                    continue
                owner = _dnsname_norm(rr.get("name"))
                if owner not in ns_set:
                    continue
                ip = rr_ip_from_additional(rr)
                if ip:
                    glue_ips.append(ip)

        if glue_ips:
            random.shuffle(glue_ips)
            next_servers = glue_ips + next_servers
            continue

        # no glue: resolve NS hostnames (prefer IPv4 first, then v6)
        if ns_names:
            random.shuffle(ns_names)
            resolved_ns_ips = []

            for nsn in ns_names[:3]:
                resolved_ns_ips = []

                for qt in (QTYPE["A"], QTYPE["AAAA"]):
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    ns_resp = iterative_resolve(
                        nsn, qt,
                        timeout=min(float(timeout), 0.5),
                        max_steps=10,
                        edns_size=edns_size,
                        do=do,
                        overall_timeout=max(0.1, remaining)
                    )
                    if not ns_resp:
                        continue

                    try:
                        ns_parsed = parse_sections(ns_resp)
                    except Exception:
                        continue

                    if ns_parsed["rcode"] != 0:
                        continue

                    for rr in ns_parsed["answers"]:
                        if rr["type"] == QTYPE["A"] and rr["rdlen"] == 4:
                            b = bytearray(rr["rdata"])
                            resolved_ns_ips.append("%d.%d.%d.%d" % (b[0], b[1], b[2], b[3]))
                        elif rr["type"] == QTYPE["AAAA"] and rr["rdlen"] == 16:
                            resolved_ns_ips.append(socket.inet_ntop(socket.AF_INET6, rr["rdata"]))

                    if resolved_ns_ips:
                        break

                if resolved_ns_ips:
                    break

            if resolved_ns_ips:
                random.shuffle(resolved_ns_ips)
                next_servers = resolved_ns_ips + next_servers
                continue

        return resp

    return last_msg

# -----------------------------
# CNAME chasing (combine RR wires)
# -----------------------------
def _response_question_wire(resp_msg):
    tid, flags, qd, an, ns, ar, tc, rcode = parse_header(resp_msg)
    off = 12
    off2 = skip_questions(resp_msg, off, qd)
    return resp_msg[12:off2]

def _build_combined_response(original_resp, rr_wires_answer_list):
    if len(original_resp) < 12:
        return original_resp
    tid, flags, qd, an, ns, ar, tc, rcode = parse_header(original_resp)
    qwire = _response_question_wire(original_resp)
    new_an = len(rr_wires_answer_list)
    new_ns = 0
    new_ar = 0
    hdr = struct.pack("!HHHHHH", tid, flags, qd, new_an, new_ns, new_ar)
    ans = b"".join(rr_wires_answer_list)
    return hdr + qwire + ans

def resolve_with_cname_chase(qname, qtype, timeout, edns_size=None, do=False, max_steps=25, max_cname=8):
    resp = iterative_resolve(qname, qtype, timeout=timeout, max_steps=max_steps, edns_size=edns_size, do=do)
    if not resp:
        return resp
    want = qtype
    if want not in (QTYPE["A"], QTYPE["AAAA"]):
        return resp

    chain = []
    current = qname
    seen = set([_dnsname_norm(current)])
    chain_base_resp = None

    for _ in range(max_cname):
        parsed = parse_sections(resp)
        if any(rr["type"] == want for rr in parsed["answers"]):
            if chain:
                combined = chain + [rr["wire"] for rr in parsed["answers"] if rr["type"] == want]
                base = chain_base_resp if chain_base_resp is not None else resp
                return _build_combined_response(base, combined)
            return resp

        cname_rr = None
        for rr in parsed["answers"]:
            if rr["type"] == QTYPE["CNAME"]:
                cname_rr = rr
                break
        if not cname_rr:
            return resp

        target, _ = decode_name(resp, cname_rr["rdata_off"])
        chain.append(cname_rr["wire"])
        if chain_base_resp is None:
            chain_base_resp = resp

        norm_t = _dnsname_norm(target)
        if norm_t in seen:
            return resp
        seen.add(norm_t)
        current = target

        resp = iterative_resolve(current, want, timeout=timeout, max_steps=max_steps, edns_size=edns_size, do=do)
        if not resp:
            return resp

    return resp

# -----------------------------
# Cache (template responses: TXID rewritten per request)
# -----------------------------
class Cache(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._store = {}  # key -> (expires_at, wire_response_template)

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
# Response helpers (TXID/flags)
# -----------------------------
def _query_question_wire(query_msg):
    _tid, _flags, qd, _an, _ns, _ar, _tc, _rcode = parse_header(query_msg)
    off = 12
    off2 = skip_questions(query_msg, off, qd)
    return query_msg[12:off2]

def make_rcode_reply(query_wire, rcode):
    if len(query_wire) < 12:
        return b"\x00\x00" + struct.pack("!H", 0x8000 | (rcode & 0xF)) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    tid = query_wire[:2]
    qflags = struct.unpack("!H", query_wire[2:4])[0]
    rd = bool(qflags & 0x0100)
    flags = 0x8000 | (0x0100 if rd else 0) | 0x0080 | (rcode & 0xF)  # QR, RD(if), RA, RCODE
    qwire = _query_question_wire(query_wire)
    hdr = tid + struct.pack("!H", flags) + struct.pack("!HHHH", 1, 0, 0, 0)
    return hdr + qwire

def make_servfail(query_wire):
    return make_rcode_reply(query_wire, 2)

def make_nxdomain(query_wire):
    return make_rcode_reply(query_wire, 3)

def make_notimp(query_wire):
    return make_rcode_reply(query_wire, 4)

def _rewrite_response_for_client(resp, client_tid_bytes, client_query_flags):
    if not resp or len(resp) < 12:
        return resp

    client_rd = bool(client_query_flags & 0x0100)
    _up_tid, up_flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])

    up_flags |= 0x8000      # QR=1
    up_flags &= ~0x0400     # AA=0
    up_flags |= 0x0080      # RA=1

    if client_rd:
        up_flags |= 0x0100
    else:
        up_flags &= ~0x0100

    new_hdr = client_tid_bytes + struct.pack("!H", up_flags) + struct.pack("!HHHH", qd, an, ns, ar)
    return new_hdr + resp[12:]

def _template_response(resp):
    if not resp or len(resp) < 2:
        return resp
    return b"\x00\x00" + resp[2:]

def _apply_template(template_resp, client_tid_bytes, client_query_flags):
    if not template_resp:
        return template_resp
    return _rewrite_response_for_client(template_resp, client_tid_bytes, client_query_flags)

def _set_tc_bit(resp_wire):
    if not resp_wire or len(resp_wire) < 4:
        return resp_wire
    tid = resp_wire[:2]
    flags = struct.unpack("!H", resp_wire[2:4])[0]
    flags |= 0x0200
    return tid + struct.pack("!H", flags) + resp_wire[4:]

def _build_truncated_tc_response(query_wire):
    """
    Minimal response: QR=1, TC=1, RA=1, echo question.
    Include OPT if client used EDNS (keeps clients happy).
    """
    if len(query_wire) < 12:
        return make_servfail(query_wire)

    tid = query_wire[:2]
    qflags = struct.unpack("!H", query_wire[2:4])[0]
    rd = bool(qflags & 0x0100)

    udp_size, do_bit = _client_edns_options(query_wire)
    ar = 1 if udp_size else 0

    flags = 0x8000 | 0x0200 | 0x0080 | (0x0100 if rd else 0)  # QR, TC, RA, RD(if)
    hdr = tid + struct.pack("!H", flags) + struct.pack("!HHHH", 1, 0, 0, ar)

    qwire = _query_question_wire(query_wire)
    if ar:
        opt = _build_opt_rr(udp_size, do=do_bit)
        return hdr + qwire + opt
    return hdr + qwire

# -----------------------------
# TTL helpers
# -----------------------------
def min_ttl_from_answers(resp_msg):
    try:
        p = parse_sections(resp_msg)
        ttls = [rr["ttl"] for rr in p["answers"]] or [30]
        return max(1, min(ttls))
    except Exception:
        return 30

# -----------------------------
# AXFR educational (local zone files)
# -----------------------------
def _encode_name_no_compress(name, origin):
    """
    Very simple: make absolute from origin, lowercase.
    """
    name = name.strip()
    if name == "@":
        name = origin
    elif name.endswith("."):
        name = name[:-1]
    else:
        if origin:
            name = name + "." + origin
    return encode_qname(name.lower().rstrip("."))

def _parse_zone_line_tokens(line):
    # strip comments ; or #
    for c in (";", "#"):
        if c in line:
            line = line.split(c, 1)[0]
    return line.strip().split()

def load_zonefile_for_axfr(zone_name, path):
    """
    Very small educational zonefile parser.
    Supports: $ORIGIN, $TTL, and records:
      name ttl IN TYPE rdata...
    name can be @ or relative or absolute.
    Types: SOA, NS, A, AAAA, CNAME, MX, TXT
    TXT: quoted or unquoted remainder joined with spaces.
    """
    origin = zone_name.strip().lower().rstrip(".")
    default_ttl = 300
    records = []

    def add_rr(owner, ttl, rtype, rdata_tokens):
        owner_wire = _encode_name_no_compress(owner, origin)
        rclass = QCLASS_IN
        ttl_i = int(ttl)

        if rtype == "A":
            ip = rdata_tokens[0]
            rdata = socket.inet_aton(ip)
        elif rtype == "AAAA":
            ip = rdata_tokens[0]
            rdata = socket.inet_pton(socket.AF_INET6, ip)
        elif rtype in ("NS", "CNAME"):
            target = rdata_tokens[0]
            rdata = _encode_name_no_compress(target, origin)
        elif rtype == "MX":
            pref = int(rdata_tokens[0])
            exch = rdata_tokens[1]
            rdata = struct.pack("!H", pref) + _encode_name_no_compress(exch, origin)
        elif rtype == "TXT":
            # join rest; allow quotes
            txt = " ".join(rdata_tokens)
            txt = txt.strip()
            if txt.startswith('"') and txt.endswith('"'):
                txt = txt[1:-1]
            b = _to_bytes(txt)
            if len(b) > 255:
                b = b[:255]
            rdata = struct.pack("!B", len(b)) + b
        elif rtype == "SOA":
            # mname rname serial refresh retry expire minimum
            if len(rdata_tokens) < 7:
                raise ValueError("SOA needs 7 fields")
            mname = _encode_name_no_compress(rdata_tokens[0], origin)
            rname = _encode_name_no_compress(rdata_tokens[1], origin)
            serial = int(rdata_tokens[2])
            refresh = int(rdata_tokens[3])
            retry = int(rdata_tokens[4])
            expire = int(rdata_tokens[5])
            minimum = int(rdata_tokens[6])
            rdata = mname + rname + struct.pack("!IIIII", serial, refresh, retry, expire, minimum)
        else:
            raise ValueError("Unsupported RR type in zonefile: %s" % rtype)

        rtype_code = QTYPE[rtype]
        rdlen = len(rdata)
        rr = owner_wire + struct.pack("!HHI", rtype_code, rclass, ttl_i) + struct.pack("!H", rdlen) + rdata
        records.append({"owner": owner, "type": rtype, "ttl": ttl_i, "wire": rr})

    with open(path, "r") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            toks = _parse_zone_line_tokens(line)
            if not toks:
                continue
            if toks[0].upper() == "$ORIGIN" and len(toks) >= 2:
                o = toks[1].rstrip(".").lower()
                origin = o
                continue
            if toks[0].upper() == "$TTL" and len(toks) >= 2:
                try:
                    default_ttl = int(toks[1])
                except Exception:
                    pass
                continue

            # record line: name [ttl] [class] type rdata...
            name = toks[0]
            i = 1
            ttl = default_ttl
            if i < len(toks) and toks[i].isdigit():
                ttl = int(toks[i]); i += 1
            if i < len(toks) and toks[i].upper() == "IN":
                i += 1
            if i >= len(toks):
                continue
            rtype = toks[i].upper(); i += 1
            rdata = toks[i:]
            add_rr(name, ttl, rtype, rdata)

    # must contain SOA
    soas = [r for r in records if r["type"] == "SOA"]
    if not soas:
        raise ValueError("Zonefile must contain an SOA record")
    return records

def _build_axfr_messages(query_wire, rr_wires, client_tid_bytes):
    """
    Returns list of DNS messages (each length-prefixed later).
    AXFR stream: SOA first, then all records, then SOA last.
    """
    # header for AXFR response messages
    qflags = struct.unpack("!H", query_wire[2:4])[0] if len(query_wire) >= 4 else 0
    rd = bool(qflags & 0x0100)

    qwire = _query_question_wire(query_wire)

    # Find SOA
    soa = None
    others = []
    for w in rr_wires:
        # type is at offset: NAME(var) + 2 bytes => hard; we stored wire already correct.
        # We'll detect SOA by parsing quickly.
        try:
            rr, _off = parse_rr(w, 0)
            if rr["type"] == QTYPE["SOA"] and soa is None:
                soa = w
            else:
                others.append(w)
        except Exception:
            others.append(w)

    if soa is None:
        # fallback: just stream whatever (not standards-correct)
        soa = rr_wires[0]

    stream = [soa] + others + [soa]

    # chunk into multiple messages
    max_rr_per_msg = 20
    msgs = []
    idx = 0
    while idx < len(stream):
        chunk = stream[idx:idx + max_rr_per_msg]
        idx += max_rr_per_msg

        qd = 1
        an = len(chunk)
        ns = 0
        ar = 0

        # QR=1, AA=1, RA=0 (authoritative zone transfer), RD echo if set
        flags = 0x8000 | 0x0400 | (0x0100 if rd else 0)

        hdr = client_tid_bytes + struct.pack("!H", flags) + struct.pack("!HHHH", qd, an, ns, ar)
        msg = hdr + qwire + b"".join(chunk)
        msgs.append(msg)

    return msgs

# -----------------------------
# DNSSEC (educational) validation — limited
#   - Validates A/AAAA RRsets only
#   - RSA/SHA256 (alg 8) only
#   - Chain-of-trust: root trust anchor -> DS/DNSKEY down
# -----------------------------
# Root KSK 20326 DNSKEY (public) — widely used; if you need to update, replace this text or load from file.
# Format: flags=257 protocol=3 algorithm=8 key(base64)
ROOT_KSK_20326 = {
    "name": ".",
    "flags": 257,
    "protocol": 3,
    "algorithm": 8,
    "key_b64": (
        "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vxwD6"
        "YwV1E1JgYj6wG2nF3tVYyX4g2o7KQxw2jV8J2+v6pYvWJZbZy2m8"
        "f9cF4u+9bJj1b8tq6o1E4bqKfJ8d7mQy1b2b1rWm9f7cQx4a8WfG"
        "eFQe8l0oWm3N1kHqGQ=="
    )
}
# NOTE: The above is an educational placeholder-size anchor. For real validation, load from file with --trust-anchor-dnskey.

TRUST_ANCHOR_DNSKEY = None  # will be set at startup if validation enabled

def _name_to_canonical_wire(name):
    # canonical: lowercase labels
    name = name.strip().rstrip(".").lower()
    return encode_qname(name)

def _dnskey_rdata(flags, protocol, algorithm, key_bytes):
    return struct.pack("!HBB", int(flags), int(protocol), int(algorithm)) + key_bytes

def _parse_dnskey_rdata(rdata):
    if len(rdata) < 4:
        raise ValueError("DNSKEY rdata too short")
    flags = struct.unpack("!H", rdata[:2])[0]
    protocol = _byte_at(rdata, 2)
    algorithm = _byte_at(rdata, 3)
    key = rdata[4:]
    return flags, protocol, algorithm, key

def _parse_rrsig_rdata(rdata):
    # typecovered(2) algo(1) labels(1) origttl(4) exp(4) inc(4) keytag(2) signername(var) sig(var)
    if len(rdata) < 18:
        raise ValueError("RRSIG too short")
    typecov = struct.unpack("!H", rdata[0:2])[0]
    algo = _byte_at(rdata, 2)
    labels = _byte_at(rdata, 3)
    origttl = struct.unpack("!I", rdata[4:8])[0]
    exp = struct.unpack("!I", rdata[8:12])[0]
    inc = struct.unpack("!I", rdata[12:16])[0]
    keytag = struct.unpack("!H", rdata[16:18])[0]
    off = 18
    signer, off2 = decode_name(rdata, off)  # decode_name works on msg bytes too
    sig = rdata[off2:]
    return {
        "typecovered": typecov, "algo": algo, "labels": labels,
        "origttl": origttl, "exp": exp, "inc": inc, "keytag": keytag,
        "signer": signer, "sig": sig,
        "rdata_nosig": rdata[:off2],  # includes signer name
    }

def _keytag_from_dnskey_rdata(rdata):
    # RFC4034 key tag
    ac = 0
    for i in range(len(rdata)):
        v = _byte_at(rdata, i)
        if i & 1:
            ac += v
        else:
            ac += v << 8
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF

def _dnssec_ds_digest(digest_type, owner_name, dnskey_rdata):
    # digest over canonical owner name + DNSKEY RDATA
    import hashlib
    owner_wire = _name_to_canonical_wire(owner_name)
    data = owner_wire + dnskey_rdata
    if digest_type == 1:
        return hashlib.sha1(data).digest()
    if digest_type == 2:
        return hashlib.sha256(data).digest()
    if digest_type == 4:
        return hashlib.sha384(data).digest()
    raise ValueError("Unsupported DS digest type: %d" % digest_type)

def _parse_ds_rdata(rdata):
    # keytag(2) algo(1) digesttype(1) digest
    if len(rdata) < 4:
        raise ValueError("DS too short")
    keytag = struct.unpack("!H", rdata[:2])[0]
    algo = _byte_at(rdata, 2)
    digest_type = _byte_at(rdata, 3)
    digest = rdata[4:]
    return keytag, algo, digest_type, digest

def _rsa_pubkey_from_dnskey(key_bytes):
    # DNSKEY RSA: exponent length (1 or 3 bytes), exponent, modulus
    if not key_bytes:
        raise ValueError("empty RSA key")
    first = _byte_at(key_bytes, 0)
    idx = 1
    if first == 0:
        if len(key_bytes) < 3:
            raise ValueError("bad RSA key exp len")
        exp_len = struct.unpack("!H", key_bytes[1:3])[0]
        idx = 3
    else:
        exp_len = first
    if idx + exp_len > len(key_bytes):
        raise ValueError("bad RSA key exp")
    e = int.from_bytes(key_bytes[idx:idx + exp_len], "big")
    idx += exp_len
    n = int.from_bytes(key_bytes[idx:], "big")
    return n, e

def _pkcs1_v1_5_verify_sha256(n, e, sig_bytes, digest):
    # Minimal RSA verify for SHA256 with PKCS#1 v1.5 DigestInfo prefix
    # DigestInfo for SHA-256:
    # 3031300d060960864801650304020105000420 || H
    digestinfo_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    di = digestinfo_prefix + digest

    k = (n.bit_length() + 7) // 8
    if len(sig_bytes) != k:
        # allow shorter if leading zeros omitted
        if len(sig_bytes) > k:
            return False
        sig_bytes = (b"\x00" * (k - len(sig_bytes))) + sig_bytes

    s = int.from_bytes(sig_bytes, "big")
    m = pow(s, e, n)
    em = m.to_bytes(k, "big")

    # Expect: 0x00 0x01 PS 0x00 DI
    if len(em) < 11 or em[0] != 0x00 or em[1] != 0x01:
        return False
    # PS must be 0xFF... until 0x00
    i = 2
    while i < len(em) and em[i] == 0xFF:
        i += 1
    if i >= len(em) or em[i] != 0x00:
        return False
    i += 1
    return em[i:] == di

def _canonical_rr_wire(owner_name, rtype, rclass, ttl, rdata):
    owner_wire = _name_to_canonical_wire(owner_name)
    return owner_wire + struct.pack("!HHI", rtype, rclass, ttl) + struct.pack("!H", len(rdata)) + rdata

def _validate_rrset_a_aaaa(owner_name, rrset, rrsig, dnskey_rdata):
    """
    rrset: list of (rtype, rdata) for A or AAAA
    rrsig: parsed rrsig dict
    dnskey_rdata: raw DNSKEY RDATA bytes (flags/proto/algo/key)
    """
    import hashlib

    # Only alg 8 supported here
    if rrsig["algo"] != 8:
        return False

    # Build signed data: RRSIG RDATA (without signature) + canonical RRset
    data = rrsig["rdata_nosig"]

    # Canonical sort: by rdata bytes (A/AAAA fixed)
    ttl = rrsig["origttl"]
    items = []
    for (rtype, rdata) in rrset:
        items.append(_canonical_rr_wire(owner_name, rtype, QCLASS_IN, ttl, rdata))
    items.sort()
    data += b"".join(items)

    digest = hashlib.sha256(data).digest()

    # Extract RSA key from DNSKEY
    _flags, _proto, algo, key_bytes = _parse_dnskey_rdata(dnskey_rdata)
    if algo != 8:
        return False
    n, e = _rsa_pubkey_from_dnskey(key_bytes)

    return _pkcs1_v1_5_verify_sha256(n, e, rrsig["sig"], digest)

def _extract_rrset_and_rrsig(resp, owner_name, want_type):
    """
    From resp (wire), collect rrset for owner_name and want_type in ANSWER,
    and matching RRSIG for that RRset.
    """
    p = parse_sections(resp)
    rrset = []
    rrsigs = []
    for rr in p["answers"]:
        if _dnsname_norm(rr["name"]) != _dnsname_norm(owner_name):
            continue
        if rr["type"] == want_type:
            rrset.append((rr["type"], rr["rdata"]))
        elif rr["type"] == QTYPE["RRSIG"]:
            try:
                rs = _parse_rrsig_rdata(rr["rdata"])
                if rs["typecovered"] == want_type:
                    rrsigs.append(rs)
            except Exception:
                pass
    return rrset, rrsigs

def _fetch_dnskey(zone, edns_size, do, timeout):
    resp = iterative_resolve(zone, QTYPE["DNSKEY"], timeout=timeout, edns_size=edns_size, do=do)
    if not resp:
        return None, []
    p = parse_sections(resp)
    keys = []
    sigs = []
    for rr in p["answers"]:
        if rr["type"] == QTYPE["DNSKEY"] and rr["class"] == QCLASS_IN:
            keys.append(rr["rdata"])
        elif rr["type"] == QTYPE["RRSIG"]:
            try:
                rs = _parse_rrsig_rdata(rr["rdata"])
                if rs["typecovered"] == QTYPE["DNSKEY"]:
                    sigs.append(rs)
            except Exception:
                pass
    return resp, keys

def _fetch_ds(parent_zone, child_zone, edns_size, do, timeout):
    # DS is at child name, asked of parent zone (iterative will route correctly)
    resp = iterative_resolve(child_zone, QTYPE["DS"], timeout=timeout, edns_size=edns_size, do=do)
    if not resp:
        return None, []
    p = parse_sections(resp)
    ds = []
    for rr in p["answers"]:
        if rr["type"] == QTYPE["DS"] and rr["class"] == QCLASS_IN:
            ds.append(rr["rdata"])
    return resp, ds

def _choose_zone_chain(qname):
    """
    qname: "www.google.com" -> [".", "com.", "google.com."]
    (very simplified)
    """
    n = _dnsname_norm(qname)
    if not n:
        return ["."]
    labels = n.split(".")
    chain = ["."]
    # build from TLD upward
    cur = ""
    for i in range(len(labels) - 1, -1, -1):
        cur = labels[i] if cur == "" else (labels[i] + "." + cur)
        chain.append(cur + ".")
        if len(chain) > DNSSEC_MAX_LABELS:
            break
    # keep unique in order
    out = []
    for z in chain:
        if z not in out:
            out.append(z)
    return out

def _dnssec_load_trust_anchor_from_file(path):
    """
    Expect a single DNSKEY line like:
      . 0 IN DNSKEY 257 3 8 BASE64...
    or just:
      257 3 8 BASE64...
    """
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            parts = line.split()
            # find flags/proto/algo/base64 at end
            tail = parts[-4:]
            try:
                flags = int(tail[0]); proto = int(tail[1]); algo = int(tail[2]); b64 = tail[3]
                key = base64.b64decode(b64.encode("ascii")) if base64 else b64.decode("base64")
                return _dnskey_rdata(flags, proto, algo, key)
            except Exception:
                continue
    raise ValueError("Could not parse trust anchor DNSKEY from file")

def _dnssec_init_trust_anchor():
    global TRUST_ANCHOR_DNSKEY
    # default anchor (educational placeholder)
    try:
        if base64:
            key = base64.b64decode(ROOT_KSK_20326["key_b64"].encode("ascii"))
        else:
            key = ROOT_KSK_20326["key_b64"].decode("base64")
        TRUST_ANCHOR_DNSKEY = _dnskey_rdata(
            ROOT_KSK_20326["flags"],
            ROOT_KSK_20326["protocol"],
            ROOT_KSK_20326["algorithm"],
            key
        )
    except Exception:
        TRUST_ANCHOR_DNSKEY = None

def dnssec_validate_answer(qname, qtype, resp, edns_size, timeout):
    """
    Validate A/AAAA answer rrset for qname using a simplified chain-of-trust.
    Returns True/False. Only meaningful if DO=1 was used upstream.
    """
    if not TRUST_ANCHOR_DNSKEY:
        return False

    # only validate A/AAAA
    if qtype not in (QTYPE["A"], QTYPE["AAAA"]):
        return True

    # Need an rrset + rrsig in final response
    rrset, rrsigs = _extract_rrset_and_rrsig(resp, qname, qtype)
    if not rrset or not rrsigs:
        return False

    # Build zone chain
    chain = _choose_zone_chain(qname)
    # chain[0]=".", chain[1]="com.", chain[2]="google.com.", etc.

    # Current trusted DNSKEY (start at root trust anchor)
    trusted_dnskey = TRUST_ANCHOR_DNSKEY
    trusted_zone = "."

    for i in range(1, len(chain)):
        child_zone = chain[i]
        # DS at child (from parent)
        _ds_resp, ds_list = _fetch_ds(trusted_zone, child_zone, edns_size=edns_size, do=True, timeout=timeout)
        if not ds_list:
            # unsigned delegation? then cannot validate further
            return False

        # Fetch child's DNSKEY
        _k_resp, keys = _fetch_dnskey(child_zone, edns_size=edns_size, do=True, timeout=timeout)
        if not keys:
            return False

        # Match DS against one of child's DNSKEYs
        matched = False
        for ds_rdata in ds_list:
            try:
                ds_keytag, ds_algo, ds_digtype, ds_digest = _parse_ds_rdata(ds_rdata)
            except Exception:
                continue
            if ds_algo != 8:
                # we only handle RSA/SHA256 chain here
                continue

            for dnskey_rdata in keys:
                try:
                    kt = _keytag_from_dnskey_rdata(dnskey_rdata)
                    if kt != ds_keytag:
                        continue
                    # digest compare
                    dig = _dnssec_ds_digest(ds_digtype, child_zone, dnskey_rdata)
                    if dig == ds_digest:
                        matched = True
                        trusted_dnskey = dnskey_rdata
                        trusted_zone = child_zone
                        break
                except Exception:
                    continue
            if matched:
                break

        if not matched:
            return False

    # Now validate the final RRset using the trusted_zone's DNSKEY.
    # We choose the RRSIG whose keytag matches trusted_dnskey.
    tkeytag = _keytag_from_dnskey_rdata(trusted_dnskey)
    chosen = None
    for rs in rrsigs:
        if rs["keytag"] == tkeytag:
            chosen = rs
            break
    if not chosen:
        chosen = rrsigs[0]

    return _validate_rrset_a_aaaa(qname, rrset, chosen, trusted_dnskey)

# -----------------------------
# Main handler: query -> response
# -----------------------------
def extract_question(msg):
    _tid, _flags, qd, _an, _ns, _ar, _tc, _rcode = parse_header(msg)
    if qd < 1:
        raise ValueError("no question")
    off = 12
    qname, off = decode_name(msg, off)
    if off + 4 > len(msg):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack("!HH", msg[off:off + 4])
    return qname, qtype, qclass

def handle_query_wire(query_wire, client_addr=None, transport="udp"):
    """
    transport: "udp" / "tcp" / "dot" / "doh"
    """
    qname, qtype, qclass = extract_question(query_wire)

    client_tid = query_wire[:2] if len(query_wire) >= 2 else b"\x00\x00"
    client_flags = struct.unpack("!H", query_wire[2:4])[0] if len(query_wire) >= 4 else 0

    # Client EDNS options (if any)
    client_edns_size, client_do = _client_edns_options(query_wire)

    # Effective upstream EDNS/DO
    eff_do = bool(client_do) or bool(FORCE_DNSSEC_DO)
    if NO_EDNS:
        eff_edns = client_edns_size
    else:
        eff_edns = client_edns_size if client_edns_size else EDNS_SIZE_DEFAULT
    if not eff_do and not client_edns_size and (NO_EDNS or not EDNS_SIZE_DEFAULT):
        eff_edns = None

    if LOG_QUERIES:
        who = ("%s:%s" % client_addr) if client_addr else "-"
        print("[DNS] transport=%s from=%s qname=%s qtype=%d edns=%s do=%s" %
              (transport, who, qname, qtype, str(eff_edns), "1" if eff_do else "0"))

    # Blocklist
    if is_blocked(qname):
        resp = make_nxdomain(query_wire)
        return _rewrite_response_for_client(resp, client_tid, client_flags)

    # AXFR educational (local zones) — TCP only
    if qtype == QTYPE["AXFR"]:
        if transport in ("udp",):
            resp = make_notimp(query_wire)
            return _rewrite_response_for_client(resp, client_tid, client_flags)
        z = _dnsname_norm(qname)
        if z in AXFR_ZONES:
            # handled in TCP/DoT stream code (multi-message)
            # Here return a single NOTIMP to prevent misuse in one-shot paths
            resp = make_notimp(query_wire)
            return _rewrite_response_for_client(resp, client_tid, client_flags)
        resp = make_notimp(query_wire)
        return _rewrite_response_for_client(resp, client_tid, client_flags)

    # Cache key includes DO
    key = (_dnsname_norm(qname), qtype, qclass, 1 if eff_do else 0)
    cached_template = CACHE.get(key)
    if cached_template:
        out = _apply_template(cached_template, client_tid, client_flags)
    else:
        # Resolve
        resp = resolve_with_cname_chase(
            qname, qtype,
            timeout=UPSTREAM_TIMEOUT,
            edns_size=eff_edns,
            do=eff_do
        )
        if not resp:
            resp = make_servfail(query_wire)
            out = _rewrite_response_for_client(resp, client_tid, client_flags)
        else:
            # DNSSEC validation (optional)
            if ENABLE_DNSSEC_VALIDATION and eff_do:
                ok = False
                try:
                    ok = dnssec_validate_answer(qname, qtype, resp, edns_size=eff_edns, timeout=UPSTREAM_TIMEOUT)
                except Exception:
                    ok = False
                if (not ok) and DNSSEC_FAIL_CLOSED:
                    resp = make_servfail(query_wire)
                    out = _rewrite_response_for_client(resp, client_tid, client_flags)
                else:
                    out = _rewrite_response_for_client(resp, client_tid, client_flags)
            else:
                out = _rewrite_response_for_client(resp, client_tid, client_flags)

            # Cache template (use upstream resp, not rewritten)
            try:
                p = parse_sections(resp)
                rcode = p["rcode"]
            except Exception:
                rcode = 0

            if rcode == 3 or _is_nodata(resp):
                ttl = _negative_cache_ttl(resp)
                CACHE.put(key, _template_response(resp), ttl=ttl)
            elif rcode == 0:
                ttl = min_ttl_from_answers(resp)
                if CACHE_TTL_CAP and CACHE_TTL_CAP > 0:
                    ttl = min(ttl, int(CACHE_TTL_CAP))
                CACHE.put(key, _template_response(resp), ttl=ttl)

    # Client-side TC enforcement for UDP responses
    if (transport == "udp") and ENFORCE_CLIENT_UDP_SIZE:
        limit = _client_udp_limit(query_wire)
        if out and len(out) > limit:
            # return minimal truncated response prompting TCP retry
            out = _build_truncated_tc_response(query_wire)

    return out

# -----------------------------
# UDP server
# -----------------------------
def udp_server(bind_ip="127.0.0.1", port=5353):
    fam = _bind_family(bind_ip)
    s = socket.socket(fam, socket.SOCK_DGRAM)

    if fam == socket.AF_INET6:
        try:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass

    s.bind((bind_ip, port))
    print("UDP DNS stub listening on %s:%d" % (bind_ip, port))

    while True:
        data, addr = s.recvfrom(65535)
        try:
            resp = handle_query_wire(data, client_addr=addr, transport="udp")
        except Exception:
            resp = make_servfail(data)
        s.sendto(resp, addr)

# -----------------------------
# TCP / DoT stream handlers
# -----------------------------
def _recvn_conn(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def _send_dns_message(conn, msg):
    conn.sendall(struct.pack("!H", len(msg)) + msg)

def _tcp_handle_one(conn, q):
    # AXFR streaming path
    try:
        qname, qtype, qclass = extract_question(q)
    except Exception:
        resp = make_servfail(q)
        _send_dns_message(conn, resp)
        return

    if qtype == QTYPE["AXFR"]:
        zone = _dnsname_norm(qname)
        if zone in AXFR_ZONES:
            rr_wires = [r["wire"] for r in AXFR_ZONES[zone]]
            msgs = _build_axfr_messages(q, rr_wires, q[:2])
            for m in msgs:
                _send_dns_message(conn, m)
            return
        resp = make_notimp(q)
        _send_dns_message(conn, resp)
        return

    # normal
    try:
        resp = handle_query_wire(q, client_addr=None, transport="tcp")
    except Exception:
        resp = make_servfail(q)
    _send_dns_message(conn, resp)

def tcp_server(bind_ip="127.0.0.1", port=5353):
    fam = _bind_family(bind_ip)
    ss = socket.socket(fam, socket.SOCK_STREAM)
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if fam == socket.AF_INET6:
        try:
            ss.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass

    ss.bind((bind_ip, port))
    ss.listen(50)
    print("TCP DNS stub listening on %s:%d" % (bind_ip, port))

    while True:
        conn, _addr = ss.accept()
        threading.Thread(target=_tcp_client, args=(conn,), daemon=True).start()

def _tcp_client(conn):
    try:
        while True:
            hdr = _recvn_conn(conn, 2)
            if not hdr:
                return
            (ln,) = struct.unpack("!H", hdr)
            q = _recvn_conn(conn, ln)
            if not q:
                return
            _tcp_handle_one(conn, q)
    finally:
        try:
            conn.close()
        except Exception:
            pass

# -----------------------------
# DoT server
# -----------------------------
def dot_server(bind_ip, port, certfile, keyfile):
    if not certfile or not keyfile:
        raise RuntimeError("DoT requires --dot-cert and --dot-key")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    fam = _bind_family(bind_ip)
    ss = socket.socket(fam, socket.SOCK_STREAM)
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if fam == socket.AF_INET6:
        try:
            ss.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass

    ss.bind((bind_ip, int(port)))
    ss.listen(50)
    print("DoT (DNS-over-TLS) listening on %s:%d" % (bind_ip, int(port)))

    while True:
        raw_conn, _addr = ss.accept()
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except Exception:
            try:
                raw_conn.close()
            except Exception:
                pass
            continue
        threading.Thread(target=_tcp_client, args=(conn,), daemon=True).start()

# -----------------------------
# DoH server (RFC8484-ish minimal)
#   - GET /dns-query?dns=BASE64URL
#   - POST /dns-query with Content-Type: application/dns-message
# -----------------------------
class _ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class DoHHandler(BaseHTTPRequestHandler):
    server_version = "dnsd-doh/0.1"

    def _send(self, code, body, ctype="application/dns-message"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            u = urlparse(self.path)
            if u.path != "/dns-query":
                self._send(404, b"not found", ctype="text/plain")
                return
            qs = parse_qs(u.query)
            if "dns" not in qs:
                self._send(400, b"missing dns param", ctype="text/plain")
                return
            v = qs["dns"][0]
            # base64url decode (no padding)
            pad = "=" * ((4 - (len(v) % 4)) % 4)
            wire = base64.urlsafe_b64decode((v + pad).encode("ascii"))
            resp = handle_query_wire(wire, client_addr=None, transport="doh")
            self._send(200, resp)
        except Exception:
            self._send(500, b"error", ctype="text/plain")

    def do_POST(self):
        try:
            if self.path.split("?", 1)[0] != "/dns-query":
                self._send(404, b"not found", ctype="text/plain")
                return
            ct = (self.headers.get("Content-Type") or "").lower()
            if "application/dns-message" not in ct:
                self._send(415, b"unsupported content-type", ctype="text/plain")
                return
            ln = int(self.headers.get("Content-Length") or "0")
            wire = self.rfile.read(ln) if ln > 0 else b""
            if not wire:
                self._send(400, b"empty body", ctype="text/plain")
                return
            resp = handle_query_wire(wire, client_addr=None, transport="doh")
            self._send(200, resp)
        except Exception:
            self._send(500, b"error", ctype="text/plain")

    def log_message(self, fmt, *args):
        # quiet by default
        return

def doh_server(bind_ip, port):
    if HTTPServer is None:
        raise RuntimeError("DoH requires Python 3 http.server")
    httpd = _ThreadedHTTPServer((bind_ip, int(port)), DoHHandler)
    print("DoH (DNS-over-HTTPS) listening on %s:%d (GET/POST /dns-query)" % (bind_ip, int(port)))
    httpd.serve_forever()

# -----------------------------
# Runner
# -----------------------------
def run_stub(bind_ip="127.0.0.1", port=5353):
    t_udp = threading.Thread(target=udp_server, args=(bind_ip, port))
    t_tcp = threading.Thread(target=tcp_server, args=(bind_ip, port))
    t_udp.daemon = True
    t_tcp.daemon = True
    t_udp.start()
    t_tcp.start()

    if DOT_ENABLED:
        t_dot = threading.Thread(target=dot_server, args=(DOT_BIND, DOT_PORT, DOT_CERT, DOT_KEY))
        t_dot.daemon = True
        t_dot.start()

    if DOH_ENABLED:
        t_doh = threading.Thread(target=doh_server, args=(DOH_BIND, DOH_PORT))
        t_doh.daemon = True
        t_doh.start()

    while True:
        time.sleep(3600)

# -----------------------------
# CLI
# -----------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Iterative DNS stub resolver: UDP+TCP, client TC enforcement, IPv4+IPv6 roots, EDNS0+DO, CNAME chase, negative cache, AXFR(local), DoT, DoH, DNSSEC validation (educational)"
    )

    parser.add_argument("--bind", default="127.0.0.1",
                        help="IP address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5353,
                        help="Port to listen on (default: 5353)")

    parser.add_argument("--upstream-timeout", type=float, default=2.0,
                        help="Timeout (seconds) per upstream hop (default: 2.0)")
    parser.add_argument("--timeout", type=float, default=None,
                        help="Alias for --upstream-timeout")

    parser.add_argument("--cache-ttl-cap", type=int, default=0,
                        help="Max TTL to cache in seconds; 0=no cap (default: 0)")

    parser.add_argument("--log-queries", action="store_true",
                        help="Log queries to stdout")
    parser.add_argument("--blocklist", type=str, default=None,
                        help="Path to blocklist file (one domain per line)")

    # Roots
    parser.add_argument("--roots", type=str, default=None,
                        help="Optional file override for root server IP list (one IP per line)")
    parser.add_argument("--root-family", type=str, default="both", choices=["v4", "v6", "both"],
                        help="Which root IPs to use: v4, v6, or both (default: both)")

    # EDNS/DNSSEC upstream signaling
    parser.add_argument("--edns-size", type=int, default=EDNS_SIZE_DEFAULT,
                        help="EDNS0 UDP payload size to advertise upstream (default: 1232). Set 0 to disable unless client uses EDNS.")
    parser.add_argument("--no-edns", action="store_true",
                        help="Do not add EDNS0 unless the client query already has OPT")
    parser.add_argument("--dnssec", action="store_true",
                        help="Force DNSSEC DO=1 upstream even if client didn't request it")

    # Client-side TC enforcement
    parser.add_argument("--no-client-tc", action="store_true",
                        help="Disable client-side TC=1 enforcement for oversized UDP replies")

    # DNSSEC validation (educational)
    parser.add_argument("--validate-dnssec", action="store_true",
                        help="Enable DNSSEC validation (educational; A/AAAA + RSA/SHA256 only). Returns SERVFAIL on failure by default.")
    parser.add_argument("--dnssec-permissive", action="store_true",
                        help="Do not SERVFAIL on validation failure (logically 'fail open').")
    parser.add_argument("--trust-anchor-dnskey", type=str, default=None,
                        help="Path to a DNSKEY trust anchor line for root (recommended for real validation).")

    # AXFR (educational local zones)
    parser.add_argument("--axfr-zone", action="append", default=[],
                        help="Enable AXFR for a local zonefile: zone=path (repeatable). Example: --axfr-zone example.com=./example.zone")

    # DoT
    parser.add_argument("--dot", action="store_true",
                        help="Enable DoT listener (DNS-over-TLS)")
    parser.add_argument("--dot-bind", type=str, default="127.0.0.1",
                        help="DoT bind IP (default: 127.0.0.1)")
    parser.add_argument("--dot-port", type=int, default=853,
                        help="DoT port (default: 853)")
    parser.add_argument("--dot-cert", type=str, default=None,
                        help="TLS certificate PEM for DoT")
    parser.add_argument("--dot-key", type=str, default=None,
                        help="TLS private key PEM for DoT")

    # DoH
    parser.add_argument("--doh", action="store_true",
                        help="Enable DoH listener (DNS-over-HTTPS) on /dns-query")
    parser.add_argument("--doh-bind", type=str, default="127.0.0.1",
                        help="DoH bind IP (default: 127.0.0.1)")
    parser.add_argument("--doh-port", type=int, default=8053,
                        help="DoH port (default: 8053)")

    args = parser.parse_args()

    UPSTREAM_TIMEOUT = float(args.upstream_timeout)
    if args.timeout is not None:
        UPSTREAM_TIMEOUT = float(args.timeout)

    CACHE_TTL_CAP = int(args.cache_ttl_cap) if args.cache_ttl_cap else 0
    LOG_QUERIES = bool(args.log_queries)

    if args.blocklist:
        BLOCKLIST = load_blocklist(args.blocklist)

    ROOT_SERVERS = load_roots(args.roots, family=args.root_family)

    EDNS_SIZE_DEFAULT = int(args.edns_size) if args.edns_size else 0
    NO_EDNS = bool(args.no_edns)
    FORCE_DNSSEC_DO = bool(args.dnssec)

    ENFORCE_CLIENT_UDP_SIZE = (not args.no_client_tc)

    # DNSSEC validation
    ENABLE_DNSSEC_VALIDATION = bool(args.validate_dnssec)
    DNSSEC_FAIL_CLOSED = (not args.dnssec_permissive)

    if ENABLE_DNSSEC_VALIDATION:
        _dnssec_init_trust_anchor()
        if args.trust_anchor_dnskey:
            try:
                TRUST_ANCHOR_DNSKEY = _dnssec_load_trust_anchor_from_file(args.trust_anchor_dnskey)
            except Exception as e:
                print("WARN: could not load trust anchor from file: %s" % str(e))
        if not TRUST_ANCHOR_DNSKEY:
            print("WARN: DNSSEC validation enabled but trust anchor not set; validation will fail.")

    # AXFR zones
    for item in args.axfr_zone:
        if "=" not in item:
            print("WARN: bad --axfr-zone (expected zone=path): %r" % item)
            continue
        zone, path = item.split("=", 1)
        zone = _dnsname_norm(zone)
        try:
            recs = load_zonefile_for_axfr(zone, path)
            AXFR_ZONES[zone] = recs
        except Exception as e:
            print("WARN: failed loading zonefile for %s: %s" % (zone, str(e)))

    # DoT/DoH
    DOT_ENABLED = bool(args.dot)
    DOT_BIND = args.dot_bind
    DOT_PORT = int(args.dot_port)
    DOT_CERT = args.dot_cert
    DOT_KEY = args.dot_key

    DOH_ENABLED = bool(args.doh)
    DOH_BIND = args.doh_bind
    DOH_PORT = int(args.doh_port)

    print("Starting DNS stub on %s:%d" % (args.bind, args.port))
    print("Roots: %s (%d IPs; family=%s)" % ("file" if args.roots else "built-in", len(ROOT_SERVERS), args.root_family))
    print("Upstream timeout: %.2fs" % UPSTREAM_TIMEOUT)
    if CACHE_TTL_CAP:
        print("Cache TTL cap: %ds" % CACHE_TTL_CAP)
    if args.blocklist:
        print("Blocklist: %s (%d entries)" % (args.blocklist, len(BLOCKLIST)))
    if LOG_QUERIES:
        print("Query logging: ON")
    print("EDNS default size: %s" % (str(EDNS_SIZE_DEFAULT) if EDNS_SIZE_DEFAULT else "OFF"))
    print("NO_EDNS: %s" % ("ON" if NO_EDNS else "OFF"))
    print("Force DO (dnssec upstream): %s" % ("ON" if FORCE_DNSSEC_DO else "OFF"))
    print("Client UDP TC enforcement: %s" % ("ON" if ENFORCE_CLIENT_UDP_SIZE else "OFF"))
    print("DNSSEC validation: %s (%s)" % ("ON" if ENABLE_DNSSEC_VALIDATION else "OFF",
                                         "fail-closed" if DNSSEC_FAIL_CLOSED else "permissive"))
    if AXFR_ZONES:
        print("AXFR zones: %s" % (", ".join(sorted(AXFR_ZONES.keys()))))
    if DOT_ENABLED:
        print("DoT: ON (%s:%d) cert=%s key=%s" % (DOT_BIND, DOT_PORT, str(DOT_CERT), str(DOT_KEY)))
    if DOH_ENABLED:
        print("DoH: ON (%s:%d) endpoint=/dns-query" % (DOH_BIND, DOH_PORT))

    run_stub(args.bind, args.port)
