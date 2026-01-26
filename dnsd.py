#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import socket
import struct
import threading
import argparse
import time
import random

# -----------------------------
# Root server IPs
# -----------------------------
ROOT_SERVERS = [
    "198.41.0.4",     # a.root-servers.net
    "199.9.14.201",   # b.root-servers.net
    "192.33.4.12",    # c.root-servers.net
    "199.7.91.13",    # d.root-servers.net
    "192.203.230.10", # e.root-servers.net
    "192.5.5.241",    # f.root-servers.net
    "192.112.36.4",   # g.root-servers.net
    "198.97.190.53",  # h.root-servers.net
    "192.36.148.17",  # i.root-servers.net
    "192.58.128.30",  # j.root-servers.net
    "193.0.14.129",   # k.root-servers.net
    "199.7.83.42",    # l.root-servers.net
    "202.12.27.33",   # m.root-servers.net
]

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "OPT": 41}
QCLASS_IN = 1

# -----------------------------
# Runtime-configurable options (CLI)
# -----------------------------
UPSTREAM_TIMEOUT = 2.0
CACHE_TTL_CAP = 0          # 0 = no cap
LOG_QUERIES = False
BLOCKLIST = set()

# EDNS/DNSSEC defaults (CLI)
EDNS_SIZE_DEFAULT = 1232   # good modern UDP size; avoids fragmentation
FORCE_DNSSEC_DO = False
NO_EDNS = False


# -----------------------------
# Helpers for loading lists
# -----------------------------
def load_roots(path):
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
# DNS wire helpers
# -----------------------------
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


def _dnsname_norm(s):
    return (s or "").strip().lower().rstrip(".")


def _is_in_bailiwick(ns_host, zone):
    ns_host = _dnsname_norm(ns_host)
    zone = _dnsname_norm(zone)
    if not ns_host or not zone:
        return False
    return ns_host == zone or ns_host.endswith("." + zone)


# -----------------------------
# EDNS0 (OPT) + DO bit
# -----------------------------
def _build_opt_rr(edns_size, do=False):
    """
    Build an OPT RR (RFC6891):
      NAME=.
      TYPE=41
      CLASS=UDP payload size
      TTL=ext_rcode(8) | version(8) | flags(16)  (DO bit is 0x8000 in flags)
      RDLEN=0 (no options)
    """
    if not edns_size:
        return b""
    edns_size = int(edns_size)
    if edns_size < 512:
        edns_size = 512
    if edns_size > 4096:
        # you can raise this if you want, but 4096 is a reasonable cap for most networks
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
    If client included OPT in Additional section, return (udp_size, do_bit).
    Else (None, False).
    """
    try:
        _tid, _flags, qd, an, ns, ar, _tc, _rcode = parse_header(query_wire)
        off = 12
        off = skip_questions(query_wire, off, qd)
        # skip any answer/authority in query (normally 0)
        for _ in range(an):
            _, off = parse_rr(query_wire, off)
        for _ in range(ns):
            _, off = parse_rr(query_wire, off)
        for _ in range(ar):
            rr, off = parse_rr(query_wire, off)
            if rr["type"] == QTYPE["OPT"]:
                udp_size = rr["class"]          # for OPT, CLASS is udp payload size
                do_bit = bool(rr["ttl"] & 0x8000)
                return int(udp_size), do_bit
    except Exception:
        pass
    return None, False


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
# SOA parsing for negative caching TTL (RFC2308-ish)
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


# -----------------------------
# Upstream transport (UDP + TCP fallback on TC=1)
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
# Iterative resolution (with bailiwick glue)
# -----------------------------
def iterative_resolve(qname, qtype, timeout=2, max_steps=25, edns_size=None, do=False):
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

        _tid, wire = build_query(qname, qtype, rd=False, edns_size=edns_size, do=do)
        try:
            resp = exchange_with_tc_fallback(server, wire, timeout=timeout, port=53)
        except Exception:
            continue

        last_msg = resp
        parsed = parse_sections(resp)

        # If got answers, done
        if parsed["answers"]:
            return resp

        # Referral: authority NS + additional glue
        ns_names = []
        bailiwick_zone = None
        for rr in parsed["authority"]:
            if rr["type"] == QTYPE["NS"]:
                bailiwick_zone = rr["name"]  # delegation zone
                nsn, _ = decode_name(resp, rr["rdata_off"])
                ns_names.append(nsn)

        glue_ips = []
        if bailiwick_zone:
            for rr in parsed["additional"]:
                if rr["type"] not in (QTYPE["A"], QTYPE["AAAA"]):
                    continue
                if not _is_in_bailiwick(rr.get("name"), bailiwick_zone):
                    continue
                ip = rr_ip_from_additional(rr)
                if ip:
                    glue_ips.append(ip)

        if glue_ips:
            random.shuffle(glue_ips)
            next_servers = glue_ips + next_servers
            continue

        # No usable glue: resolve NS hostnames (AAAA first, then A)
        if ns_names:
            random.shuffle(ns_names)
            resolved_ns_ips = []

            for nsn in ns_names[:3]:
                resolved_ns_ips = []
                for qt in (QTYPE["AAAA"], QTYPE["A"]):
                    ns_resp = iterative_resolve(
                        nsn, qt, timeout=timeout, max_steps=max_steps,
                        edns_size=edns_size, do=do
                    )
                    if not ns_resp:
                        continue
                    ns_parsed = parse_sections(ns_resp)
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
# CNAME chasing (build combined response)
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

    for _ in range(max_cname):
        parsed = parse_sections(resp)
        if any(rr["type"] == want for rr in parsed["answers"]):
            if chain:
                combined = chain + [rr["wire"] for rr in parsed["answers"] if rr["type"] == want]
                base = chain_base_resp if "chain_base_resp" in locals() else resp
                out = _build_combined_response(base, combined)
                return out
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
        if "chain_base_resp" not in locals():
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
# Server response helpers
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


def min_ttl_from_answers(resp_msg):
    try:
        p = parse_sections(resp_msg)
        ttls = [rr["ttl"] for rr in p["answers"]] or [30]
        return max(1, min(ttls))
    except Exception:
        return 30


def make_servfail(query_wire):
    if len(query_wire) < 12:
        return b"\x00\x00" + struct.pack("!H", 0x8002) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    tid = query_wire[:2]
    hdr = tid + struct.pack("!H", 0x8002) + struct.pack("!HHHH", 1, 0, 0, 0)
    return hdr + query_wire[12:]


def make_nxdomain(query_wire):
    if len(query_wire) < 12:
        return b"\x00\x00" + struct.pack("!H", 0x8003) + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    tid = query_wire[:2]
    hdr = tid + struct.pack("!H", 0x8003) + struct.pack("!HHHH", 1, 0, 0, 0)
    return hdr + query_wire[12:]


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


def handle_query_wire(query_wire, client_addr=None):
    qname, qtype, qclass = extract_question(query_wire)

    client_tid = query_wire[:2] if len(query_wire) >= 2 else b"\x00\x00"
    client_flags = struct.unpack("!H", query_wire[2:4])[0] if len(query_wire) >= 4 else 0

    # Client EDNS options (if any)
    client_edns_size, client_do = _client_edns_options(query_wire)

    # Effective upstream EDNS/DO policy
    eff_do = bool(client_do) or bool(FORCE_DNSSEC_DO)

    if NO_EDNS:
        # only honor client EDNS if they sent it
        eff_edns = client_edns_size
    else:
        # prefer client size if present, else default
        eff_edns = client_edns_size if client_edns_size else EDNS_SIZE_DEFAULT

    # If nothing needs EDNS, disable OPT
    if not eff_do and not client_edns_size and (NO_EDNS or not EDNS_SIZE_DEFAULT):
        eff_edns = None

    if LOG_QUERIES:
        who = ("%s:%s" % client_addr) if client_addr else "-"
        print("[DNS] from=%s qname=%s qtype=%d edns=%s do=%s" %
              (who, qname, qtype, str(eff_edns), "1" if eff_do else "0"))

    if is_blocked(qname):
        if LOG_QUERIES:
            print("[DNS] BLOCKED %s" % qname)
        resp = make_nxdomain(query_wire)
        return _rewrite_response_for_client(resp, client_tid, client_flags)

    # Cache key must include DO flag (DNSSEC responses differ)
    key = (_dnsname_norm(qname), qtype, qclass, 1 if eff_do else 0)

    cached_template = CACHE.get(key)
    if cached_template:
        return _apply_template(cached_template, client_tid, client_flags)

    resp = resolve_with_cname_chase(
        qname, qtype,
        timeout=UPSTREAM_TIMEOUT,
        edns_size=eff_edns,
        do=eff_do
    )

    if not resp:
        resp = make_servfail(query_wire)
        return _rewrite_response_for_client(resp, client_tid, client_flags)

    try:
        p = parse_sections(resp)
        rcode = p["rcode"]
    except Exception:
        rcode = 0

    if rcode == 3:  # NXDOMAIN
        ttl = _negative_cache_ttl(resp)
        CACHE.put(key, _template_response(resp), ttl=ttl)
        return _rewrite_response_for_client(resp, client_tid, client_flags)

    if _is_nodata(resp):
        ttl = _negative_cache_ttl(resp)
        CACHE.put(key, _template_response(resp), ttl=ttl)
        return _rewrite_response_for_client(resp, client_tid, client_flags)

    ttl = min_ttl_from_answers(resp)
    if CACHE_TTL_CAP and CACHE_TTL_CAP > 0:
        ttl = min(ttl, int(CACHE_TTL_CAP))

    CACHE.put(key, _template_response(resp), ttl=ttl)
    return _rewrite_response_for_client(resp, client_tid, client_flags)


# -----------------------------
# UDP + TCP servers (IPv4/IPv6 bind)
# -----------------------------
def _bind_family(bind_ip):
    return socket.AF_INET6 if ":" in bind_ip else socket.AF_INET


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
            resp = handle_query_wire(data, client_addr=addr)
        except Exception:
            resp = make_servfail(data)
        s.sendto(resp, addr)


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


def _recvn_conn(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _tcp_client(conn):
    try:
        hdr = _recvn_conn(conn, 2)
        if not hdr:
            return
        (ln,) = struct.unpack("!H", hdr)
        q = _recvn_conn(conn, ln)
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
        description="Iterative DNS stub resolver: UDP+TCP, TXID rewrite, upstream TCP fallback on TC=1, IPv6, CNAME chase, negative cache, bailiwick glue, EDNS0+DO"
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
    parser.add_argument("--roots", type=str, default=None,
                        help="Path to root server IP list (one IP per line)")

    # EDNS/DNSSEC
    parser.add_argument("--edns-size", type=int, default=EDNS_SIZE_DEFAULT,
                        help="EDNS0 UDP payload size to advertise upstream (default: 1232). Set 0 to disable unless client uses EDNS.")
    parser.add_argument("--no-edns", action="store_true",
                        help="Do not add EDNS0 unless the client query already has OPT")
    parser.add_argument("--dnssec", action="store_true",
                        help="Force DNSSEC DO=1 upstream even if client didn't request it")

    args = parser.parse_args()

    UPSTREAM_TIMEOUT = float(args.upstream_timeout)
    if args.timeout is not None:
        UPSTREAM_TIMEOUT = float(args.timeout)

    CACHE_TTL_CAP = int(args.cache_ttl_cap) if args.cache_ttl_cap else 0
    LOG_QUERIES = bool(args.log_queries)

    if args.blocklist:
        BLOCKLIST = load_blocklist(args.blocklist)

    if args.roots:
        ROOT_SERVERS = load_roots(args.roots)

    EDNS_SIZE_DEFAULT = int(args.edns_size) if args.edns_size else 0
    NO_EDNS = bool(args.no_edns)
    FORCE_DNSSEC_DO = bool(args.dnssec)

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
    print("EDNS default size: %s" % (str(EDNS_SIZE_DEFAULT) if EDNS_SIZE_DEFAULT else "OFF"))
    print("NO_EDNS: %s" % ("ON" if NO_EDNS else "OFF"))
    print("Force DO (dnssec): %s" % ("ON" if FORCE_DNSSEC_DO else "OFF"))

    run_stub(args.bind, args.port)
