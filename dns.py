#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import socket
import struct
import argparse
import random
import sys
import time
import ssl
import hashlib

try:
    # Py3
    from urllib.parse import urlparse, parse_qs
    import urllib.request as urllib_request
    import urllib.error as urllib_error
    import base64
except Exception:
    # Py2
    from urlparse import urlparse, parse_qs
    import urllib2 as urllib_request
    import urllib2 as urllib_error
    import base64


# -----------------------------
# DNS record types / classes
# -----------------------------
QTYPE = {
    'A': 1,
    'NS': 2,
    'CNAME': 5,
    'SOA': 6,
    'MX': 15,
    'TXT': 16,
    'AAAA': 28,
    'DS': 43,
    'RRSIG': 46,
    'DNSKEY': 48,
    'NSEC': 47,
    'NSEC3': 50,
    'OPT': 41,
    'IXFR': 251,
    'AXFR': 252,
}
QCLASS_IN = 1

RCODE_MAP = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

OPCODE_MAP = {
    0: "QUERY",
    1: "IQUERY",
    2: "STATUS",
    4: "NOTIFY",
    5: "UPDATE",
}

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

def default_root_servers(family="both"):
    fam = (family or "both").lower()
    out = []
    if fam == "auto":
        fam = "ipv6" if getattr(socket, "has_ipv6", False) else "ipv4"
    keys = sorted(ROOT_SERVERS_DATA.keys())
    if fam in ("both", "ipv6"):
        for k in keys:
            ip6 = ROOT_SERVERS_DATA[k].get("ipv6")
            if ip6:
                out.append(ip6)
    if fam in ("both", "ipv4"):
        for k in keys:
            ip4 = ROOT_SERVERS_DATA[k].get("ipv4")
            if ip4:
                out.append(ip4)
    if not out:
        for k in keys:
            ip4 = ROOT_SERVERS_DATA[k].get("ipv4")
            if ip4:
                out.append(ip4)
    return out

def load_roots_file(path):
    if not path:
        return None
    ips = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                ips.append(line.split()[0])
    except Exception:
        return None
    return ips or None

# -----------------------------
# Basic helpers
# -----------------------------
def _to_bytes(s):
    if isinstance(s, bytes):
        return s
    return s.encode('utf-8')

def _byte_at(b, i):
    v = b[i]
    return v if isinstance(v, int) else ord(v)

def _split_ipv6_zone(host):
    if "%" in host:
        addr, zone = host.split("%", 1)
        return addr, zone
    return host, None

def _scope_id_from_zone(zone):
    if zone is None:
        return 0
    if zone.isdigit():
        try:
            return int(zone)
        except Exception:
            return 0
    if hasattr(socket, "if_nametoindex"):
        try:
            return socket.if_nametoindex(zone)
        except Exception:
            return 0
    return 0

def _is_ipv6_literal(s):
    return ":" in s

def _looks_like_ipv4_literal(s):
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        for p in parts:
            if p == "":
                return False
            v = int(p)
            if v < 0 or v > 255:
                return False
        return True
    except Exception:
        return False

def _is_ip_literal(s):
    return _is_ipv6_literal(s) or _looks_like_ipv4_literal(s)

def _addr_tuple(host, port):
    port = int(port)
    if _is_ipv6_literal(host):
        addr, zone = _split_ipv6_zone(host)
        scopeid = _scope_id_from_zone(zone)
        return (addr, port, 0, scopeid)
    return (host, port)

def _iter_server_addrs(dns_server, port, prefer_ipv6=True):
    port = int(port)
    if _is_ip_literal(dns_server):
        yield _addr_tuple(dns_server, port)
        return
    try:
        infos = socket.getaddrinfo(
            dns_server, port, socket.AF_UNSPEC, 0, 0, socket.AI_ADDRCONFIG
        )
    except Exception:
        infos = socket.getaddrinfo(dns_server, port, socket.AF_UNSPEC)

    def _rank(info):
        fam = info[0]
        if prefer_ipv6:
            return 0 if fam == socket.AF_INET6 else 1
        return 0 if fam == socket.AF_INET else 1

    seen = set()
    for fam, socktype, proto, canonname, sockaddr in sorted(infos, key=_rank):
        if sockaddr in seen:
            continue
        seen.add(sockaddr)
        yield sockaddr

def _resolve_all_server_ips(dns_server, prefer_ipv6=True):
    if not dns_server:
        return []
    if _is_ip_literal(dns_server):
        if "%" in dns_server:
            return [dns_server.split("%", 1)[0]]
        return [dns_server]
    ips = []
    try:
        infos = socket.getaddrinfo(dns_server, 0, socket.AF_UNSPEC, 0, 0)
        for fam, _socktype, _proto, _canon, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        return []
    def _rank_ip(ip):
        is_v6 = ":" in ip
        if prefer_ipv6:
            return 0 if is_v6 else 1
        return 0 if (not is_v6) else 1
    ips.sort(key=_rank_ip)
    return ips

def _dnsname_norm(s):
    return (s or "").strip().lower().rstrip(".")

def _ipv6_to_str(packed16):
    b = bytes(bytearray(packed16))
    if hasattr(socket, 'inet_ntop'):
        try:
            return socket.inet_ntop(socket.AF_INET6, b)
        except Exception:
            pass
    ba = bytearray(packed16)
    hextets = []
    for i in range(0, 16, 2):
        hextets.append("%02x%02x" % (ba[i], ba[i + 1]))
    return ":".join(hextets)

# -----------------------------
# DNS name encode/decode
# -----------------------------
def encode_qname(domain):
    domain = domain.strip().rstrip('.')
    if not domain:
        return b'\x00'
    out = []
    for part in domain.split('.'):
        pb = _to_bytes(part)
        if len(pb) == 0:
            raise ValueError("Invalid domain (empty label)")
        if len(pb) > 63:
            raise ValueError("Label too long (>63 bytes): %r" % part)
        out.append(struct.pack('!B', len(pb)) + pb)
    out.append(b'\x00')
    return b''.join(out)

def encode_qname_canonical(domain):
    return encode_qname((domain or "").strip().lower())

def decode_domain_name(msg, offset):
    labels = []
    jumped = False
    original_offset = offset
    seen_offsets = set()

    while True:
        if offset >= len(msg):
            raise ValueError("Offset out of bounds while decoding name")
        if offset in seen_offsets:
            raise ValueError("Compression pointer loop detected")
        seen_offsets.add(offset)

        length = _byte_at(msg, offset)
        if length == 0:
            offset += 1
            break

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(msg):
                raise ValueError("Truncated compression pointer")
            b2 = _byte_at(msg, offset + 1)
            pointer = ((length & 0x3F) << 8) | b2
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        offset += 1
        if offset + length > len(msg):
            raise ValueError("Truncated label in name")
        label_bytes = msg[offset:offset + length]
        try:
            label = label_bytes.decode('utf-8')
        except Exception:
            if len(label_bytes) and not isinstance(label_bytes[0], int):  # Py2 bytes
                label = ''.join(chr(ord(c)) for c in label_bytes)
            else:
                label = ''.join(chr(c) for c in label_bytes)
        labels.append(label)
        offset += length

    return '.'.join(labels), (original_offset if jumped else offset)

def skip_question_section(msg, offset, qdcount):
    for _ in range(qdcount):
        _, offset = decode_domain_name(msg, offset)
        if offset + 4 > len(msg):
            raise ValueError("Truncated question section")
        offset += 4
    return offset

def parse_rr(msg, offset):
    name, offset = decode_domain_name(msg, offset)
    if offset + 10 > len(msg):
        raise ValueError("Truncated RR header")

    rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', msg[offset:offset + 10])
    offset += 10

    if offset + rdlength > len(msg):
        raise ValueError("Truncated RDATA")
    rdata_offset = offset
    rdata = msg[offset:offset + rdlength]
    offset += rdlength

    return {
        'name': name,
        'type': rtype,
        'class': rclass,
        'ttl': ttl,
        'rdlength': rdlength,
        'rdata': rdata,
        'rdata_offset': rdata_offset,
    }, offset

# -----------------------------
# Header parse
# -----------------------------
def _parse_header_fields(msg):
    if len(msg) < 12:
        raise ValueError("Incomplete DNS header")
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', msg[:12])
    tc = bool(flags & 0x0200)
    rcode = flags & 0x000F
    opcode = (flags >> 11) & 0x0F
    aa = bool(flags & 0x0400)
    return tid, flags, qdcount, ancount, nscount, arcount, tc, rcode, opcode, aa

def _get_txid(wire_msg):
    if not wire_msg or len(wire_msg) < 2:
        return None
    return wire_msg[:2]

def _recvn(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# -----------------------------
# EDNS0 + DO
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
    flags = 0x8000 if do else 0x0000  # DO bit in TTL
    ttl = struct.pack("!I", flags)
    rdlen = struct.pack("!H", 0)
    return name + rtype + rclass + ttl + rdlen

def build_dns_query(domain, record_type, rd=True, edns_size=None, do=False, cd=False):
    txid = random.randint(0, 0xFFFF)
    tid = struct.pack('!H', txid)

    flags_val = 0x0000
    if rd:
        flags_val |= 0x0100
    if cd:
        flags_val |= 0x0010  # CD bit
    flags = struct.pack('!H', flags_val)

    qdcount = struct.pack('!H', 1)
    ancount = struct.pack('!H', 0)
    nscount = struct.pack('!H', 0)
    arcount = struct.pack('!H', 1 if edns_size else 0)

    qname = encode_qname(domain)
    qtype = struct.pack('!H', QTYPE[record_type])
    qclass = struct.pack('!H', QCLASS_IN)

    header = tid + flags + qdcount + ancount + nscount + arcount
    question = qname + qtype + qclass

    if edns_size:
        opt = _build_opt_rr(edns_size, do=do)
        return header + question + opt, tid
    return header + question, tid

# -----------------------------
# UDP/TCP/DoT/DoH query
# -----------------------------
def query_tcp(dns_server, query, port, timeout, prefer_ipv6=True, strict_txid=True):
    expected = _get_txid(query)
    last_err = None
    for sockaddr in _iter_server_addrs(dns_server, port, prefer_ipv6=prefer_ipv6):
        fam = socket.AF_INET6 if len(sockaddr) == 4 else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(float(timeout))
        try:
            sock.connect(sockaddr)
            sock.sendall(struct.pack("!H", len(query)) + query)

            hdr = _recvn(sock, 2)
            if hdr is None:
                raise RuntimeError("TCP DNS: no length header")
            (msg_len,) = struct.unpack("!H", hdr)
            msg = _recvn(sock, msg_len)
            if msg is None:
                raise RuntimeError("TCP DNS: incomplete message")
            if strict_txid and (_get_txid(msg) != expected):
                raise RuntimeError("TXID mismatch")
            return msg, sockaddr
        except Exception as e:
            last_err = e
        finally:
            try: sock.close()
            except Exception: pass
    raise last_err if last_err else RuntimeError("TCP query failed")

def query_udp(dns_server, query, port, timeout, prefer_ipv6=True, strict_txid=True):
    expected = _get_txid(query)
    last_err = None
    for sockaddr in _iter_server_addrs(dns_server, port, prefer_ipv6=prefer_ipv6):
        fam = socket.AF_INET6 if len(sockaddr) == 4 else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.settimeout(float(timeout))
        try:
            sock.sendto(query, sockaddr)
            while True:
                resp, _ = sock.recvfrom(65535)
                if (not strict_txid) or (_get_txid(resp) == expected):
                    return resp, sockaddr
        except Exception as e:
            last_err = e
        finally:
            try: sock.close()
            except Exception: pass
    raise last_err if last_err else RuntimeError("UDP query failed")

def exchange_with_tc_enforcement(dns_server, query_wire, port, timeout, prefer_ipv6,
                                 strict_txid, tcp_fallback=True, enforce_tc=True):
    msg, sockaddr = query_udp(dns_server, query_wire, port, timeout, prefer_ipv6, strict_txid)
    try:
        tc = bool(_parse_header_fields(msg)[6])
    except Exception:
        tc = False
    if tc and (tcp_fallback or enforce_tc):
        msg2, sockaddr2 = query_tcp(dns_server, query_wire, port, timeout, prefer_ipv6, strict_txid)
        return msg2, sockaddr2, "TCP"
    return msg, sockaddr, "UDP"

def query_dot(dns_server, query, port, timeout, prefer_ipv6=True, strict_txid=True,
              verify=True, sni=None, cafile=None):
    expected = _get_txid(query)
    last_err = None

    context = ssl.create_default_context()
    if cafile:
        context.load_verify_locations(cafile)
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    for sockaddr in _iter_server_addrs(dns_server, port, prefer_ipv6=prefer_ipv6):
        fam = socket.AF_INET6 if len(sockaddr) == 4 else socket.AF_INET
        raw = socket.socket(fam, socket.SOCK_STREAM)
        raw.settimeout(float(timeout))
        try:
            raw.connect(sockaddr)
            tls = context.wrap_socket(raw, server_hostname=(sni or (dns_server if not _is_ip_literal(dns_server) else None)))
            tls.sendall(struct.pack("!H", len(query)) + query)
            hdr = _recvn(tls, 2)
            if not hdr:
                raise RuntimeError("DoT: missing length header")
            (ln,) = struct.unpack("!H", hdr)
            msg = _recvn(tls, ln)
            if not msg:
                raise RuntimeError("DoT: incomplete message")
            if strict_txid and (_get_txid(msg) != expected):
                raise RuntimeError("TXID mismatch (DoT)")
            return msg, sockaddr
        except Exception as e:
            last_err = e
        finally:
            try: raw.close()
            except Exception: pass
    raise last_err if last_err else RuntimeError("DoT query failed")

def _b64url_encode_nopad(b):
    s = base64.urlsafe_b64encode(b).decode("ascii")
    return s.rstrip("=")

def query_doh(doh_url, query_wire, timeout):
    u = urlparse(doh_url)
    use_get = (u.query != "") or doh_url.endswith("/dns-query")
    headers = {"Accept": "application/dns-message"}

    if use_get:
        qs = parse_qs(u.query)
        qs["dns"] = [_b64url_encode_nopad(query_wire)]
        qparts = []
        for k in sorted(qs.keys()):
            for v in qs[k]:
                qparts.append("%s=%s" % (k, v))
        new_query = "&".join(qparts)
        url = u._replace(query=new_query).geturl()
        req = urllib_request.Request(url, headers=headers)
        resp = urllib_request.urlopen(req, timeout=float(timeout)).read()
        return resp, None

    headers["Content-Type"] = "application/dns-message"
    req = urllib_request.Request(doh_url, data=query_wire, headers=headers)
    resp = urllib_request.urlopen(req, timeout=float(timeout)).read()
    return resp, None

# -----------------------------
# AXFR support (TCP stream)
# -----------------------------
def _tcp_read_one_message(sock):
    hdr = _recvn(sock, 2)
    if not hdr:
        return None
    (ln,) = struct.unpack("!H", hdr)
    msg = _recvn(sock, ln)
    return msg

def axfr_tcp(dns_server, domain, port, timeout, prefer_ipv6=True, strict_txid=True,
             edns_size=None, do=False, cd=False):
    query, _txid = build_dns_query(domain, "AXFR", rd=False, edns_size=edns_size, do=do, cd=cd)
    expected = _get_txid(query)

    last_err = None
    for sockaddr in _iter_server_addrs(dns_server, port, prefer_ipv6=prefer_ipv6):
        fam = socket.AF_INET6 if len(sockaddr) == 4 else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(float(timeout))
        try:
            sock.connect(sockaddr)
            sock.sendall(struct.pack("!H", len(query)) + query)

            msgs = []
            soa_seen = 0

            while True:
                msg = _tcp_read_one_message(sock)
                if not msg:
                    break
                if strict_txid and (_get_txid(msg) != expected):
                    raise RuntimeError("TXID mismatch in AXFR stream")
                msgs.append(msg)

                try:
                    tid, flags, qd, an, ns, ar, tc, rcode, opcode, aa = _parse_header_fields(msg)
                    off = 12
                    off = skip_question_section(msg, off, qd)
                    for _ in range(an):
                        rr, off = parse_rr(msg, off)
                        if rr["type"] == QTYPE["SOA"]:
                            soa_seen += 1
                    if soa_seen >= 2:
                        break
                except Exception:
                    pass

            return msgs, sockaddr

        except Exception as e:
            last_err = e
        finally:
            try: sock.close()
            except Exception: pass

    raise last_err if last_err else RuntimeError("AXFR failed for all addresses")

# -----------------------------
# Minimal RRset parsing (for recursion + DNSSEC)
# -----------------------------
def _parse_sections_basic(msg):
    tid, flags, qd, an, ns, ar, tc, rcode, opcode, aa = _parse_header_fields(msg)
    off = 12
    off = skip_question_section(msg, off, qd)

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
        "tid": tid, "flags": flags, "qd": qd, "an": an, "ns": ns, "ar": ar,
        "tc": tc, "rcode": rcode, "opcode": opcode, "aa": aa,
        "answers": answers, "authority": authority, "additional": additional, "raw": msg
    }

def _rr_ip_from_additional(rr):
    if rr["type"] == QTYPE["A"] and rr["rdlength"] == 4:
        b = bytearray(rr["rdata"])
        return "%d.%d.%d.%d" % (b[0], b[1], b[2], b[3])
    if rr["type"] == QTYPE["AAAA"] and rr["rdlength"] == 16:
        return _ipv6_to_str(rr["rdata"])
    return None

# -----------------------------
# Client-side iterative resolver (RD=0)
# -----------------------------
def _udp_exchange_ip(server_ip, wire_query, timeout, strict_txid=True, port=53):
    expected = _get_txid(wire_query)
    fam = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_DGRAM)
    sock.settimeout(float(timeout))
    try:
        sock.sendto(wire_query, (server_ip, int(port)))
        while True:
            resp, _ = sock.recvfrom(65535)
            if (not strict_txid) or (_get_txid(resp) == expected):
                return resp
    finally:
        try: sock.close()
        except Exception: pass

def _tcp_exchange_ip(server_ip, wire_query, timeout, strict_txid=True, port=53):
    expected = _get_txid(wire_query)
    fam = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_STREAM)
    sock.settimeout(float(timeout))
    try:
        sock.connect((server_ip, int(port)))
        sock.sendall(struct.pack("!H", len(wire_query)) + wire_query)
        hdr = _recvn(sock, 2)
        if not hdr:
            raise RuntimeError("TCP DNS: missing length header")
        (ln,) = struct.unpack("!H", hdr)
        msg = _recvn(sock, ln)
        if not msg:
            raise RuntimeError("TCP DNS: incomplete message")
        if strict_txid and (_get_txid(msg) != expected):
            raise RuntimeError("TXID mismatch (TCP)")
        return msg
    finally:
        try: sock.close()
        except Exception: pass

def _exchange_tc_fallback_ip(server_ip, wire_query, timeout, strict_txid=True, port=53, enforce_tc=True):
    resp = _udp_exchange_ip(server_ip, wire_query, timeout, strict_txid=strict_txid, port=port)
    try:
        tc = bool(_parse_header_fields(resp)[6])
    except Exception:
        tc = False
    if tc and enforce_tc:
        try:
            return _tcp_exchange_ip(server_ip, wire_query, timeout, strict_txid=strict_txid, port=port)
        except Exception:
            return resp
    return resp

def iterative_resolve(qname, qtype_code, roots, timeout, strict_txid=True,
                      max_steps=25, overall_timeout=6.0, port=53,
                      edns_size=None, do=False, cd=False, enforce_tc=True):
    deadline = time.time() + float(overall_timeout)
    next_servers = list(roots)
    random.shuffle(next_servers)
    last_msg = None

    def _rtype_from_code(code):
        for k, v in QTYPE.items():
            if v == code:
                return k
        return None

    qtype_str = _rtype_from_code(qtype_code)
    if not qtype_str:
        raise ValueError("Unsupported qtype code: %r" % qtype_code)

    for _ in range(max_steps):
        if time.time() >= deadline:
            break
        if not next_servers:
            break

        server_ip = next_servers.pop(0)
        wire, _ = build_dns_query(qname, qtype_str, rd=False, edns_size=edns_size, do=do, cd=cd)

        remaining = deadline - time.time()
        if remaining <= 0:
            break
        per_try = min(float(timeout), max(0.05, remaining))

        try:
            resp = _exchange_tc_fallback_ip(server_ip, wire, per_try, strict_txid=strict_txid, port=port, enforce_tc=enforce_tc)
        except Exception:
            continue

        last_msg = resp
        try:
            parsed = _parse_sections_basic(resp)
        except Exception:
            continue

        if parsed["rcode"] != 0:
            return resp

        if parsed["answers"]:
            return resp

        # referral
        ns_names = []
        for rr in parsed["authority"]:
            if rr["type"] == QTYPE["NS"]:
                try:
                    nsn, _ = decode_domain_name(resp, rr["rdata_offset"])
                    ns_names.append(_dnsname_norm(nsn))
                except Exception:
                    pass

        glue_ips = []
        if ns_names:
            ns_set = set(ns_names)
            for rr in parsed["additional"]:
                if rr["type"] not in (QTYPE["A"], QTYPE["AAAA"]):
                    continue
                owner = _dnsname_norm(rr.get("name"))
                if owner not in ns_set:
                    continue
                ip = _rr_ip_from_additional(rr)
                if ip:
                    glue_ips.append(ip)

        if glue_ips:
            random.shuffle(glue_ips)
            next_servers = glue_ips + next_servers
            continue

        # no glue => resolve NS hostnames
        if ns_names:
            random.shuffle(ns_names)
            resolved = []
            for nsn in ns_names[:3]:
                for qt in (QTYPE["A"], QTYPE["AAAA"]):
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    ns_resp = iterative_resolve(
                        nsn, qt, roots,
                        timeout=min(float(timeout), 0.6),
                        strict_txid=strict_txid,
                        max_steps=12,
                        overall_timeout=max(0.2, remaining),
                        port=port,
                        edns_size=edns_size,
                        do=do,
                        cd=cd,
                        enforce_tc=enforce_tc
                    )
                    if not ns_resp:
                        continue
                    try:
                        ns_parsed = _parse_sections_basic(ns_resp)
                    except Exception:
                        continue
                    if ns_parsed["rcode"] != 0:
                        continue
                    for rr in ns_parsed["answers"]:
                        if rr["type"] == QTYPE["A"] and rr["rdlength"] == 4:
                            b = bytearray(rr["rdata"])
                            resolved.append("%d.%d.%d.%d" % (b[0], b[1], b[2], b[3]))
                        elif rr["type"] == QTYPE["AAAA"] and rr["rdlength"] == 16:
                            resolved.append(_ipv6_to_str(rr["rdata"]))
                    if resolved:
                        break
                if resolved:
                    break

            if resolved:
                random.shuffle(resolved)
                next_servers = resolved + next_servers
                continue

        return resp

    return last_msg

def resolve_with_cname_chase(qname, qtype_code, roots, timeout, strict_txid=True,
                            max_steps=25, overall_timeout=6.0, max_cname=8, port=53,
                            edns_size=None, do=False, cd=False, enforce_tc=True):
    if qtype_code not in (QTYPE["A"], QTYPE["AAAA"]):
        return iterative_resolve(qname, qtype_code, roots, timeout, strict_txid=strict_txid,
                                max_steps=max_steps, overall_timeout=overall_timeout, port=port,
                                edns_size=edns_size, do=do, cd=cd, enforce_tc=enforce_tc)

    current = qname
    seen = set([_dnsname_norm(current)])
    want = qtype_code
    resp = None

    for _ in range(max_cname):
        resp = iterative_resolve(current, want, roots, timeout, strict_txid=strict_txid,
                                max_steps=max_steps, overall_timeout=overall_timeout, port=port,
                                edns_size=edns_size, do=do, cd=cd, enforce_tc=enforce_tc)
        if not resp:
            return resp
        try:
            parsed = _parse_sections_basic(resp)
        except Exception:
            return resp

        if any(rr["type"] == want for rr in parsed["answers"]):
            return resp

        cname_target = None
        for rr in parsed["answers"]:
            if rr["type"] == QTYPE["CNAME"]:
                try:
                    cname_target, _ = decode_domain_name(resp, rr["rdata_offset"])
                except Exception:
                    cname_target = None
                break
        if not cname_target:
            return resp

        nt = _dnsname_norm(cname_target)
        if nt in seen:
            return resp
        seen.add(nt)
        current = cname_target

    return resp

# -----------------------------
# DIY DNSSEC validation (RSA-only, educational)
#   - Works best with --recursive + --do
#   - Full RFC-complete DNSSEC is big; this validates common RSA algorithms.
# -----------------------------
_DIGESTINFO_PREFIX = {
    # PKCS#1 v1.5 DigestInfo prefixes (DER) for hash algorithms
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414") if hasattr(bytes, "fromhex") else "".decode("hex"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420") if hasattr(bytes, "fromhex") else "".decode("hex"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440") if hasattr(bytes, "fromhex") else "".decode("hex"),
}

def _u16(b, off):
    return struct.unpack("!H", b[off:off+2])[0]

def _u32(b, off):
    return struct.unpack("!I", b[off:off+4])[0]

def _rrsig_parse(msg, rr):
    # RRSIG RDATA:
    # type_covered(2) alg(1) labels(1) orig_ttl(4) sig_exp(4) sig_inc(4) key_tag(2) signer_name(variable) signature(rest)
    r = rr["rdata"]
    if len(r) < 18:
        return None
    type_cov = _u16(r, 0)
    alg = _byte_at(r, 2)
    labels = _byte_at(r, 3)
    orig_ttl = _u32(r, 4)
    sig_exp = _u32(r, 8)
    sig_inc = _u32(r, 12)
    key_tag = _u16(r, 16)
    signer, off = decode_domain_name(msg, rr["rdata_offset"] + 18)
    signer_wire_len = off - (rr["rdata_offset"] + 18)
    sig_off = 18 + signer_wire_len
    sig = r[sig_off:]
    return {
        "type_covered": type_cov,
        "alg": alg,
        "labels": labels,
        "orig_ttl": orig_ttl,
        "sig_exp": sig_exp,
        "sig_inc": sig_inc,
        "key_tag": key_tag,
        "signer_name": signer,
        "signature": sig,
        "rdata_without_sig": r[:sig_off],
    }

def _dnskey_parse(rr):
    r = rr["rdata"]
    if len(r) < 4:
        return None
    flags = _u16(r, 0)
    protocol = _byte_at(r, 2)
    alg = _byte_at(r, 3)
    pub = r[4:]
    return {"flags": flags, "protocol": protocol, "alg": alg, "public_key": pub, "rdata": r}

def _ds_parse(rr):
    r = rr["rdata"]
    if len(r) < 4:
        return None
    key_tag = _u16(r, 0)
    alg = _byte_at(r, 2)
    digest_type = _byte_at(r, 3)
    digest = r[4:]
    return {"key_tag": key_tag, "alg": alg, "digest_type": digest_type, "digest": digest, "rdata": r}

def _dnskey_keytag(dnskey_rdata_bytes):
    # RFC4034 Appendix B
    ac = 0
    for i, b in enumerate(bytearray(dnskey_rdata_bytes)):
        if i & 1:
            ac += b
        else:
            ac += b << 8
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF

def _dnskey_to_rsa_params(dnskey_pub_bytes):
    # RSA exponent length: 1 byte, or 0 + 2 bytes
    if not dnskey_pub_bytes:
        return None
    b = bytearray(dnskey_pub_bytes)
    if b[0] == 0:
        if len(b) < 3:
            return None
        elen = (b[1] << 8) | b[2]
        e_start = 3
    else:
        elen = b[0]
        e_start = 1
    e_end = e_start + elen
    if e_end > len(b):
        return None
    e = int.from_bytes(bytes(b[e_start:e_end]), "big") if hasattr(int, "from_bytes") else int(bytes(b[e_start:e_end]).encode("hex"), 16)
    n = int.from_bytes(bytes(b[e_end:]), "big") if hasattr(int, "from_bytes") else int(bytes(b[e_end:]).encode("hex"), 16)
    return n, e

def _hash_for_alg(alg):
    # RSA DNSSEC algorithm numbers:
    # 5=RSASHA1, 7=RSASHA1-NSEC3-SHA1, 8=RSASHA256, 10=RSASHA512
    if alg in (5, 7):
        return "sha1"
    if alg == 8:
        return "sha256"
    if alg == 10:
        return "sha512"
    return None

def _rsa_pkcs1_v1_5_verify(n, e, sig_bytes, msg_bytes, hash_name):
    if hash_name not in _DIGESTINFO_PREFIX:
        return False
    h = getattr(hashlib, hash_name)(msg_bytes).digest()
    t = _DIGESTINFO_PREFIX[hash_name] + h

    # RSA verify: m = sig^e mod n, then check PKCS#1 v1.5 structure
    s = int.from_bytes(sig_bytes, "big") if hasattr(int, "from_bytes") else int(sig_bytes.encode("hex"), 16)
    k = (n.bit_length() + 7) // 8
    m = pow(s, e, n)
    em = m.to_bytes(k, "big") if hasattr(int, "to_bytes") else (("%0" + str(k*2) + "x") % m).decode("hex")

    # EM = 0x00 0x01 PS 0x00 T, where PS is 0xff*8 or more
    if len(em) < 11:
        return False
    if _byte_at(em, 0) != 0x00 or _byte_at(em, 1) != 0x01:
        return False
    i = 2
    while i < len(em) and _byte_at(em, i) == 0xFF:
        i += 1
    if i < 10:  # need at least 8 bytes of 0xFF padding
        return False
    if i >= len(em) or _byte_at(em, i) != 0x00:
        return False
    i += 1
    return em[i:] == t

def _rr_canonical_rdata(msg, rr):
    # Canonicalize RDATA for a small set of types.
    # For DS/DNSKEY/A/AAAA: bytes are already canonical.
    # For name-containing rdata types (NS/CNAME): lower-case domain.
    # For MX: preference + canonical name.
    # For SOA: mname + rname canonical + rest.
    t = rr["type"]
    r = rr["rdata"]
    off = rr["rdata_offset"]

    if t in (QTYPE["A"], QTYPE["AAAA"], QTYPE["DS"], QTYPE["DNSKEY"]):
        return r

    if t in (QTYPE["NS"], QTYPE["CNAME"]):
        d, _ = decode_domain_name(msg, off)
        return encode_qname_canonical(d)

    if t == QTYPE["MX"]:
        if len(r) < 2:
            return r
        pref = r[:2]
        d, _ = decode_domain_name(msg, off + 2)
        return pref + encode_qname_canonical(d)

    if t == QTYPE["SOA"]:
        # mname, rname, then 5x32-bit
        mname, p = decode_domain_name(msg, off)
        rname, p2 = decode_domain_name(msg, p)
        tail = msg[p2:off + rr["rdlength"]]
        return encode_qname_canonical(mname) + encode_qname_canonical(rname) + tail

    # fallback: raw bytes (not fully canonical for some types)
    return r

def _name_to_wire_canonical(owner):
    return encode_qname_canonical(owner.rstrip("."))

def _rrset_canonical(owner, rtype, rclass, orig_ttl, rr_list, msg_for_names):
    # For each RR:
    # owner|type|class|ttl(orig_ttl)|rdlength|rdata(canonical)
    items = []
    for rr in rr_list:
        rdata_can = _rr_canonical_rdata(msg_for_names, rr)
        wire = (
            _name_to_wire_canonical(owner) +
            struct.pack("!H", rtype) +
            struct.pack("!H", rclass) +
            struct.pack("!I", orig_ttl) +
            struct.pack("!H", len(rdata_can)) +
            rdata_can
        )
        items.append(wire)
    items.sort()
    return b"".join(items)

def _rrset_find(msg, owner_norm, rtype):
    p = _parse_sections_basic(msg)
    out = []
    for rr in (p["answers"] + p["authority"] + p["additional"]):
        if _dnsname_norm(rr.get("name")) == owner_norm and rr.get("type") == rtype and rr.get("class") == QCLASS_IN:
            out.append(rr)
    return out

def _rrsig_find_covering(msg, owner_norm, type_covered):
    p = _parse_sections_basic(msg)
    out = []
    for rr in (p["answers"] + p["authority"] + p["additional"]):
        if rr.get("type") != QTYPE["RRSIG"]:
            continue
        if _dnsname_norm(rr.get("name")) != owner_norm:
            continue
        info = _rrsig_parse(msg, rr)
        if not info:
            continue
        if info["type_covered"] == type_covered:
            out.append((rr, info))
    return out

def _rrsig_signed_data(owner, rrsig_info, rrset_wire):
    # Signed data = RRSIG_RDATA(without signature) + RRset
    # RRSIG RDATA(without signature) uses signer name in canonical wire form, so we must rebuild it.
    # We parse original rdata_without_sig which already includes signer name wire from message.
    # To be safe, rebuild: fixed fields + signer_name canonical wire.
    r = rrsig_info
    fixed = struct.pack("!HBBIIIH",
                        r["type_covered"], r["alg"], r["labels"], r["orig_ttl"],
                        r["sig_exp"], r["sig_inc"], r["key_tag"])
    signer_wire = _name_to_wire_canonical(r["signer_name"])
    return fixed + signer_wire + rrset_wire

def _ds_compute(owner_name, dnskey_rdata, digest_type):
    # DS digest input = canonical owner name + DNSKEY RDATA
    data = _name_to_wire_canonical(owner_name) + dnskey_rdata
    if digest_type == 1:
        return hashlib.sha1(data).digest()
    if digest_type == 2:
        return hashlib.sha256(data).digest()
    if digest_type == 4:
        return hashlib.sha384(data).digest()
    return None

def _verify_rrsig_rsa(owner, rrset_rrs, rrsig_info, dnskey_rrs, msg_for_names):
    # Find DNSKEY with matching key_tag + alg and verify signature
    hash_name = _hash_for_alg(rrsig_info["alg"])
    if not hash_name:
        return False, "Unsupported DNSSEC algorithm (only RSA 5/7/8/10 supported)"
    wanted_tag = rrsig_info["key_tag"]
    wanted_alg = rrsig_info["alg"]

    # Build canonical RRset using original TTL from RRSIG
    rrset_wire = _rrset_canonical(owner, rrsig_info["type_covered"], QCLASS_IN, rrsig_info["orig_ttl"], rrset_rrs, msg_for_names)
    signed = _rrsig_signed_data(owner, rrsig_info, rrset_wire)

    sig = rrsig_info["signature"]

    for krr in dnskey_rrs:
        k = _dnskey_parse(krr)
        if not k:
            continue
        if k["alg"] != wanted_alg:
            continue
        tag = _dnskey_keytag(k["rdata"])
        if tag != wanted_tag:
            continue
        rsa = _dnskey_to_rsa_params(k["public_key"])
        if not rsa:
            continue
        n, e = rsa
        ok = _rsa_pkcs1_v1_5_verify(n, e, sig, signed, hash_name)
        if ok:
            return True, None

    return False, "No matching DNSKEY verified RRSIG (or crypto failed)"

def _zone_chain(domain):
    # yields zones from root -> ... -> closest zone for domain
    d = _dnsname_norm(domain)
    labels = d.split(".") if d else []
    zones = [""]  # root
    for i in range(len(labels)):
        zones.append(".".join(labels[i:]))
    # root "", then TLD, etc, ending at full domain (may not be a zone cut)
    return zones

def _read_trust_anchor_file(path):
    """
    Supported:
      - DNSKEY line: DNSKEY <flags> <protocol> <alg> <base64>
      - DS line: DS <keytag> <alg> <digesttype> <hex_or_base16_digest>
    Returns dict { "type": "dnskey"/"ds", "owner": ".", ... }
    """
    if not path:
        return None
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                # allow optional owner at front
                if parts[0].upper() in ("DNSKEY", "DS"):
                    owner = "."
                    rec = parts
                else:
                    owner = parts[0]
                    rec = parts[1:]
                if not rec:
                    continue
                if rec[0].upper() == "DNSKEY" and len(rec) >= 5:
                    flags = int(rec[1]); proto = int(rec[2]); alg = int(rec[3])
                    b64 = rec[4]
                    pub = base64.b64decode(b64.encode("ascii"))
                    rdata = struct.pack("!HBB", flags, proto, alg) + pub
                    return {"type": "dnskey", "owner": owner, "rdata": rdata, "alg": alg, "key_tag": _dnskey_keytag(rdata)}
                if rec[0].upper() == "DS" and len(rec) >= 5:
                    keytag = int(rec[1]); alg = int(rec[2]); dtyp = int(rec[3])
                    digest_hex = rec[4].replace(":", "").lower()
                    digest = bytes.fromhex(digest_hex) if hasattr(bytes, "fromhex") else digest_hex.decode("hex")
                    return {"type": "ds", "owner": owner, "key_tag": keytag, "alg": alg, "digest_type": dtyp, "digest": digest}
    except Exception:
        return None
    return None

def dnssec_validate_chain_and_answer(qname, qtype_code, final_msg, roots, timeout,
                                    strict_txid=True, overall_timeout=10.0, port=53,
                                    edns_size=1232, enforce_tc=True,
                                    trust_anchor=None,
                                    verbose=False):
    """
    Educational DNSSEC validation:
      - Builds chain from root using DS/DNSKEY.
      - Validates DNSKEY RRset signatures (RSA only).
      - Validates answer RRset RRSIG (if present).
    NOTE: Without a trust anchor, this runs in "TOFU-ish" mode (not real chain-of-trust).
    Returns: (ok_bool, notes_list[str])
    """
    notes = []
    deadline = time.time() + float(overall_timeout)

    def _time_left():
        return max(0.05, deadline - time.time())

    # Always request DNSSEC data
    do = True
    cd = False

    # Cache trusted DNSKEY rrsets by zone name
    trusted_dnskeys = {}  # zone_norm -> list[dnskey_rr]
    trusted_mode = "tofu"
    if trust_anchor:
        trusted_mode = "anchored"
        notes.append("Trust anchor loaded: %s (type=%s)" % (trust_anchor.get("owner", "."), trust_anchor.get("type")) )
    else:
        notes.append("No trust anchor provided: running in TOFU/self-consistency mode (educational, NOT strong security).")

    zones = _zone_chain(qname)

    # Step 1: get and (optionally) validate root DNSKEY RRset
    root_zone = ""  # root
    root_owner = "."
    root_dnskey_msg = iterative_resolve(root_zone, QTYPE["DNSKEY"], roots, timeout,
                                        strict_txid=strict_txid, overall_timeout=min(3.0, _time_left()),
                                        port=port, edns_size=edns_size, do=do, cd=cd, enforce_tc=enforce_tc)
    if not root_dnskey_msg:
        return False, notes + ["Failed to fetch root DNSKEY"]

    root_dnskeys = _rrset_find(root_dnskey_msg, _dnsname_norm(root_owner), QTYPE["DNSKEY"])
    root_rrsigs = _rrsig_find_covering(root_dnskey_msg, _dnsname_norm(root_owner), QTYPE["DNSKEY"])
    if not root_dnskeys:
        return False, notes + ["Root DNSKEY RRset missing"]

    # Anchor check: if anchor is DNSKEY, accept only if present and keytag matches. If anchor is DS, match to some DNSKEY.
    anchored_key_ok = True
    if trust_anchor:
        if trust_anchor["type"] == "dnskey":
            want_tag = trust_anchor["key_tag"]
            anchored_key_ok = any(_dnskey_keytag(_dnskey_parse(rr)["rdata"]) == want_tag for rr in root_dnskeys if _dnskey_parse(rr))
            if not anchored_key_ok:
                return False, notes + ["Root DNSKEY did not match provided DNSKEY trust anchor (keytag=%d)" % want_tag]
        elif trust_anchor["type"] == "ds":
            anchored_key_ok = False
            for rr in root_dnskeys:
                k = _dnskey_parse(rr)
                if not k:
                    continue
                tag = _dnskey_keytag(k["rdata"])
                if tag != trust_anchor["key_tag"] or k["alg"] != trust_anchor["alg"]:
                    continue
                d = _ds_compute(root_owner, k["rdata"], trust_anchor["digest_type"])
                if d and d == trust_anchor["digest"]:
                    anchored_key_ok = True
                    break
            if not anchored_key_ok:
                return False, notes + ["Root DNSKEY did not match provided DS trust anchor"]

    # Verify root DNSKEY RRset RRSIG if we can (RSA only) using some DNSKEY in the same RRset.
    # In anchored mode, this is meaningful; in TOFU it’s self-signed but still checks crypto correctness.
    root_sig_ok = False
    root_sig_err = None
    for rr, info in root_rrsigs:
        ok, err = _verify_rrsig_rsa(root_owner, root_dnskeys, info, root_dnskeys, root_dnskey_msg)
        if ok:
            root_sig_ok = True
            break
        root_sig_err = err
    if not root_sig_ok:
        return False, notes + ["Root DNSKEY RRSIG verification failed: %s" % (root_sig_err or "unknown")]

    trusted_dnskeys[_dnsname_norm(root_owner)] = root_dnskeys
    notes.append("Root DNSKEY RRset verified (%s)" % trusted_mode)

    # Walk down zones, validating DS at parent and DNSKEY at child
    parent_zone = root_owner
    for zone in zones[1:]:
        if time.time() >= deadline:
            return False, notes + ["DNSSEC validation timed out building chain"]

        child_zone = zone if zone else root_owner
        child_owner = child_zone if child_zone else root_owner

        parent_norm = _dnsname_norm(parent_zone if parent_zone != "" else root_owner)
        child_norm = _dnsname_norm(child_owner)

        # Fetch DS at parent for child (query at parent's zone name: child is owner)
        ds_msg = iterative_resolve(child_owner, QTYPE["DS"], roots, timeout,
                                  strict_txid=strict_txid, overall_timeout=min(3.0, _time_left()),
                                  port=port, edns_size=edns_size, do=do, cd=cd, enforce_tc=enforce_tc)
        if not ds_msg:
            notes.append("No DS response for %s" % (child_owner or "."))
            parent_zone = child_owner
            continue

        ds_rrs = _rrset_find(ds_msg, child_norm, QTYPE["DS"])
        ds_sigs = _rrsig_find_covering(ds_msg, child_norm, QTYPE["DS"])
        # Some zones are unsigned -> DS empty or NODATA; treat as "insecure delegation"
        if not ds_rrs:
            notes.append("No DS RRset for %s (insecure delegation or NODATA)" % (child_owner or "."))
            parent_zone = child_owner
            continue

        # Verify DS RRset using parent's DNSKEY
        parent_keys = trusted_dnskeys.get(parent_norm)
        if not parent_keys:
            notes.append("Missing trusted DNSKEY for parent zone %s; cannot verify DS for %s" % (parent_norm, child_owner))
            parent_zone = child_owner
            continue

        ds_ok = False
        for rr, info in ds_sigs:
            ok, err = _verify_rrsig_rsa(child_owner, ds_rrs, info, parent_keys, ds_msg)
            if ok:
                ds_ok = True
                break
        if not ds_ok:
            return False, notes + ["DS RRset for %s failed verification" % (child_owner or ".")]

        # Fetch child DNSKEY and verify it matches DS + validate its self-signature (RRSIG(DNSKEY))
        dnskey_msg = iterative_resolve(child_owner, QTYPE["DNSKEY"], roots, timeout,
                                       strict_txid=strict_txid, overall_timeout=min(3.0, _time_left()),
                                       port=port, edns_size=edns_size, do=do, cd=cd, enforce_tc=enforce_tc)
        if not dnskey_msg:
            return False, notes + ["Failed to fetch DNSKEY for %s" % (child_owner or ".")]

        child_keys = _rrset_find(dnskey_msg, child_norm, QTYPE["DNSKEY"])
        child_sigs = _rrsig_find_covering(dnskey_msg, child_norm, QTYPE["DNSKEY"])
        if not child_keys:
            return False, notes + ["DNSKEY RRset missing for %s" % (child_owner or ".")]

        # DS->DNSKEY match
        ds_list = [ _ds_parse(rr) for rr in ds_rrs ]
        ds_list = [d for d in ds_list if d]
        match = False
        for krr in child_keys:
            k = _dnskey_parse(krr)
            if not k:
                continue
            kt = _dnskey_keytag(k["rdata"])
            for d in ds_list:
                if d["key_tag"] != kt or d["alg"] != k["alg"]:
                    continue
                comp = _ds_compute(child_owner, k["rdata"], d["digest_type"])
                if comp and comp == d["digest"]:
                    match = True
                    break
            if match:
                break
        if not match:
            return False, notes + ["DNSKEY for %s did not match DS from parent" % (child_owner or ".")]

        # Verify DNSKEY RRset signature using child DNSKEYs (self-signed)
        keyset_ok = False
        keyset_err = None
        for rr, info in child_sigs:
            ok, err = _verify_rrsig_rsa(child_owner, child_keys, info, child_keys, dnskey_msg)
            if ok:
                keyset_ok = True
                break
            keyset_err = err
        if not keyset_ok:
            return False, notes + ["DNSKEY RRset for %s failed verification: %s" % ((child_owner or "."), (keyset_err or "unknown"))]

        trusted_dnskeys[child_norm] = child_keys
        notes.append("Zone DNSKEY verified: %s" % (child_owner or "."))

        parent_zone = child_owner

    # Finally: validate the requested RRset RRSIG in final response (if present)
    owner_norm = _dnsname_norm(qname)
    rrset_rrs = _rrset_find(final_msg, owner_norm, qtype_code)
    rrsigs = _rrsig_find_covering(final_msg, owner_norm, qtype_code)
    if not rrset_rrs:
        # not necessarily failure (NXDOMAIN etc)
        notes.append("No answer RRset to validate for %s type=%d" % (qname, qtype_code))
        return True, notes

    if not rrsigs:
        notes.append("No RRSIG for answer RRset (maybe upstream stripped DNSSEC or unsigned RRset).")
        return False, notes

    # Use signer name in RRSIG to pick zone DNSKEY
    any_ok = False
    last_err = None
    for rr, info in rrsigs:
        signer_norm = _dnsname_norm(info["signer_name"] or "")
        keys = trusted_dnskeys.get(signer_norm)
        if not keys:
            # try fall back to closest parent we have
            keys = trusted_dnskeys.get(_dnsname_norm("."))
        ok, err = _verify_rrsig_rsa(qname, rrset_rrs, info, keys or [], final_msg)
        if ok:
            any_ok = True
            break
        last_err = err

    if any_ok:
        notes.append("Answer RRset RRSIG verified (RSA).")
        return True, notes
    return False, notes + ["Answer RRset verification failed: %s" % (last_err or "unknown")]


# -----------------------------
# Dig-like output
# -----------------------------
def _dig_flags_string(flags):
    names = []
    if flags & 0x8000: names.append("qr")
    if flags & 0x0400: names.append("aa")
    if flags & 0x0200: names.append("tc")
    if flags & 0x0100: names.append("rd")
    if flags & 0x0080: names.append("ra")
    if flags & 0x0020: names.append("ad")
    if flags & 0x0010: names.append("cd")
    return " ".join(names)

def _server_pretty(dns_server, port, sockaddr_used):
    ip = None
    try:
        ip = sockaddr_used[0] if sockaddr_used else None
    except Exception:
        ip = None
    if ip is None:
        ip = dns_server
    return "%s#%d(%s)" % (dns_server, int(port), ip)

def _print_dig_banner(dns_server, port, domain, dig_version):
    print("; <<>> DiG %s <<>> @%s -p %d %s" % (dig_version, dns_server, int(port), domain))
    print("; (1 server found)")
    print(";; global options: +cmd")

def _print_trailer_like_dig(dns_server, port, elapsed_ms, msg, sockaddr_used, transport):
    when_str = time.strftime("%a %b %d %H:%M:%S %Z %Y", time.localtime())
    server_str = _server_pretty(dns_server, port, sockaddr_used)
    print(";; Query time: %d msec" % int(elapsed_ms))
    print(";; SERVER: %s (%s)" % (server_str, transport))
    print(";; WHEN: %s" % when_str)
    print(";; MSG SIZE  rcvd: %d" % (len(msg) if msg else 0))

def decode_sections_for_dig(msg, wanted_type, show_all=False, include_authority=False, include_additional=False):
    tid, flags, qdcount, ancount, nscount, arcount, tc, rcode, opcode, aa = _parse_header_fields(msg)
    offset = 12
    offset = skip_question_section(msg, offset, qdcount)

    def rr_to_dig(rr):
        rtype = rr['type']
        ttl = rr['ttl']
        rdata = rr['rdata']
        owner = rr.get('name', '').rstrip(".")

        if rtype == QTYPE['A'] and rr['rdlength'] == 4:
            ip = "%d.%d.%d.%d" % tuple(bytearray(rdata))
            return ["%s.\t\t%d\tIN\tA\t%s" % (owner, ttl, ip)]
        if rtype == QTYPE['AAAA'] and rr['rdlength'] == 16:
            ip6 = _ipv6_to_str(rdata)
            return ["%s.\t\t%d\tIN\tAAAA\t%s" % (owner, ttl, ip6)]
        if rtype in (QTYPE['CNAME'], QTYPE['NS']):
            target, _ = decode_domain_name(msg, rr['rdata_offset'])
            tname = "CNAME" if rtype == QTYPE['CNAME'] else "NS"
            return ["%s.\t\t%d\tIN\t%s\t%s." % (owner, ttl, tname, target.rstrip("."))]
        if rtype == QTYPE['MX']:
            if rr['rdlength'] < 3:
                return []
            pref = struct.unpack('!H', rdata[:2])[0]
            exchange, _ = decode_domain_name(msg, rr['rdata_offset'] + 2)
            return ["%s.\t\t%d\tIN\tMX\t%d %s." % (owner, ttl, pref, exchange.rstrip("."))]
        if rtype == QTYPE['TXT']:
            if rr['rdlength'] >= 1:
                ln = _byte_at(rdata, 0)
                txt = rdata[1:1+ln]
                try:
                    txts = txt.decode("utf-8", "replace")
                except Exception:
                    txts = str(txt)
                return ["%s.\t\t%d\tIN\tTXT\t\"%s\"" % (owner, ttl, txts)]
        if rtype == QTYPE["RRSIG"]:
            info = _rrsig_parse(msg, rr)
            if info:
                return ["%s.\t\t%d\tIN\tRRSIG\t(type=%d alg=%d tag=%d signer=%s)" %
                        (owner, ttl, info["type_covered"], info["alg"], info["key_tag"], info["signer_name"].rstrip("."))]
            return ["%s.\t\t%d\tIN\tRRSIG\t(...)" % (owner, ttl)]
        if rtype == QTYPE["DNSKEY"]:
            k = _dnskey_parse(rr)
            if k:
                tag = _dnskey_keytag(k["rdata"])
                return ["%s.\t\t%d\tIN\tDNSKEY\t(flags=%d alg=%d keytag=%d)" % (owner, ttl, k["flags"], k["alg"], tag)]
        if rtype == QTYPE["DS"]:
            d = _ds_parse(rr)
            if d:
                return ["%s.\t\t%d\tIN\tDS\t(tag=%d alg=%d digest=%d ...)" % (owner, ttl, d["key_tag"], d["alg"], d["digest_type"])]
        return []

    def collect(count, offset):
        out = []
        for _ in range(count):
            rr, offset2 = parse_rr(msg, offset)
            offset = offset2
            if (not show_all) and rr['type'] != wanted_type:
                continue
            out.extend(rr_to_dig(rr))
        return out, offset

    ans, offset = collect(ancount, offset)

    auth = []
    if include_authority:
        auth, offset = collect(nscount, offset)
    else:
        for _ in range(nscount):
            _, offset = parse_rr(msg, offset)

    add = []
    if include_additional:
        add, offset = collect(arcount, offset)
    else:
        for _ in range(arcount):
            _, offset = parse_rr(msg, offset)

    return {
        "header": {
            "tid": tid,
            "flags": flags,
            "qdcount": qdcount,
            "ancount": ancount,
            "nscount": nscount,
            "arcount": arcount,
            "tc": tc,
            "rcode": rcode,
            "opcode": opcode,
            "aa": aa,
        },
        "answer": ans,
        "authority": auth,
        "additional": add,
    }

def _print_dig_like(sections, domain, record_type, dns_server, port,
                    elapsed_ms, msg, sockaddr_used, transport,
                    include_banner=False, dig_version="9.20.x"):
    if include_banner:
        _print_dig_banner(dns_server, port, domain, dig_version)
        print("")

    h = sections["header"]
    status = RCODE_MAP.get(h["rcode"], str(h["rcode"]))
    opcode_name = OPCODE_MAP.get(h["opcode"], str(h["opcode"]))
    flags_str = _dig_flags_string(h["flags"])

    print(";; Got answer:")
    print(";; ->>HEADER<<- opcode: %s, status: %s, id: %d" % (opcode_name, status, h["tid"]))
    print(";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d" %
          (flags_str, h["qdcount"], h["ancount"], h["nscount"], h["arcount"]))
    print("")
    print(";; QUESTION SECTION:")
    print(";%s.\t\t\tIN\t%s" % (domain.rstrip("."), record_type))
    print("")
    print(";; ANSWER SECTION:")
    if sections["answer"]:
        for line in sections["answer"]:
            print(line)
    else:
        print(";; (no answer records)")
    print("")
    if sections["authority"]:
        print(";; AUTHORITY SECTION:")
        for line in sections["authority"]:
            print(line)
        print("")
    if sections["additional"]:
        print(";; ADDITIONAL SECTION:")
        for line in sections["additional"]:
            print(line)
        print("")
    _print_trailer_like_dig(dns_server, port, elapsed_ms, msg, sockaddr_used, transport)


# -----------------------------
# Main query path
# -----------------------------
def query_once(dns_server, domain, record_type, port, timeout,
               prefer_ipv6=True, strict_txid=True,
               tcp_fallback=True, enforce_tc=True,
               edns_size=None, do=False, cd=False,
               transport_mode="dns",
               doh_url=None,
               dot_verify=True, dot_sni=None, dot_cafile=None):
    query, _txid = build_dns_query(domain, record_type, rd=True, edns_size=edns_size, do=do, cd=cd)

    t0 = time.time()
    sockaddr_used = None
    transport_used = "UDP"

    if transport_mode == "doh":
        msg, sockaddr_used = query_doh(doh_url, query, timeout)
        transport_used = "DoH"
    elif transport_mode == "dot":
        msg, sockaddr_used = query_dot(
            dns_server, query, port, timeout,
            prefer_ipv6=prefer_ipv6,
            strict_txid=strict_txid,
            verify=dot_verify,
            sni=dot_sni,
            cafile=dot_cafile
        )
        transport_used = "DoT"
    else:
        msg, sockaddr_used, transport_used = exchange_with_tc_enforcement(
            dns_server, query, port, timeout, prefer_ipv6,
            strict_txid, tcp_fallback=tcp_fallback, enforce_tc=enforce_tc
        )

    elapsed_ms = (time.time() - t0) * 1000.0
    return msg, elapsed_ms, sockaddr_used, transport_used


# -----------------------------
# CLI
# -----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="DNS client: UDP+TCP (TC=1 enforced), AXFR(TCP), DoT, DoH, EDNS0+DO/CD, client-side iterative recursion, and DIY DNSSEC validation (RSA-only educational)"
    )

    parser.add_argument('--dns-server', type=str,
                        help='DNS server address (IPv4, IPv6, IPv6%%zone, or hostname)')
    parser.add_argument('--domain', type=str, help='Domain to look up (e.g., example.com)')
    parser.add_argument('--record-type', type=str, default='A',
                        help='DNS record type (A, AAAA, MX, CNAME, NS, TXT, SOA, DS, DNSKEY, RRSIG, AXFR)')
    parser.add_argument('--port', type=int, default=53, help='DNS server port number (default 53)')
    parser.add_argument('--timeout', type=float, default=2, help='Per-try timeout in seconds (default 2)')

    parser.add_argument('--prefer-ipv4', action='store_true',
                        help='Prefer IPv4 first when --dns-server is a hostname')
    parser.add_argument('--prefer-ipv6', action='store_true',
                        help='Prefer IPv6 first when --dns-server is a hostname (default)')

    parser.add_argument('--no-strict-txid', action='store_true',
                        help='Disable TXID validation (debug only)')

    parser.add_argument('--no-tcp-fallback', action='store_true',
                        help='Disable TCP fallback (still retries TCP on TC=1 unless you also set --no-tc-enforce)')
    parser.add_argument('--no-tc-enforce', action='store_true',
                        help='Disable TC=1 enforcement (do NOT retry TCP when TC=1)')

    parser.add_argument('--edns-size', type=int, default=1232,
                        help='Include EDNS0 OPT with this UDP payload size (default 1232). Set 0 to disable.')
    parser.add_argument('--do', action='store_true',
                        help='Set DO=1 (request DNSSEC records like RRSIG)')
    parser.add_argument('--cd', action='store_true',
                        help='Set CD=1 (checking disabled)')

    parser.add_argument('--dig-style', action='store_true',
                        help='Print output similar to dig (includes trailer)')
    parser.add_argument('--dig-banner', action='store_true',
                        help='Also print the first 3 dig banner lines')
    parser.add_argument('--dig-version', type=str, default="9.20.x",
                        help='Version string to show in the dig banner (default: 9.20.x)')
    parser.add_argument('--show-all', action='store_true',
                        help='(dig-style) include all RR types (prints more if decoder supports)')
    parser.add_argument('--include-authority', action='store_true',
                        help='(dig-style) include Authority section')
    parser.add_argument('--include-additional', action='store_true',
                        help='(dig-style) include Additional section')
    parser.add_argument('--quiet', action='store_true', help='Less header/debug output')

    # Client-side iterative recursion
    parser.add_argument('--recursive', action='store_true',
                        help='Client-side iterative resolve starting from root servers (ignores --dns-server)')
    parser.add_argument('--roots-family', type=str, default="both",
                        choices=["both", "ipv4", "ipv6", "auto"],
                        help='Which built-in root addresses to use (both|ipv4|ipv6|auto). Default: both')
    parser.add_argument('--roots', type=str, default=None,
                        help='Root server IP list file (one IP per line). Overrides built-in root table')
    parser.add_argument('--roots-port', type=int, default=53,
                        help='Port for root/TLD/authoritative servers (default: 53)')
    parser.add_argument('--overall-timeout', type=float, default=8.0,
                        help='Overall time budget (seconds) for --recursive mode (default: 8.0)')

    # DNSSEC validation
    parser.add_argument('--dnssec-validate', action='store_true',
                        help='DIY DNSSEC validation (RSA-only). Best with --recursive and DO.')
    parser.add_argument('--trust-anchor', type=str, default=None,
                        help='Trust anchor file (DNSKEY/DS line). If omitted, runs in TOFU/self-consistency mode (educational).')

    # DoT / DoH
    parser.add_argument('--dot', action='store_true',
                        help='Use DNS-over-TLS (DoT) to talk to --dns-server')
    parser.add_argument('--dot-no-verify', action='store_true',
                        help='DoT: disable certificate verification (dev only)')
    parser.add_argument('--dot-sni', type=str, default=None,
                        help='DoT: override SNI/hostname')
    parser.add_argument('--dot-cafile', type=str, default=None,
                        help='DoT: CA file to trust')
    parser.add_argument('--doh', type=str, default=None,
                        help='Use DNS-over-HTTPS (DoH) to this URL. Overrides --dns-server')

    args = parser.parse_args()

    try:
        _input = raw_input  # noqa
    except NameError:
        _input = input

    dns_server = args.dns_server or _input("Enter the DNS server IP/host (e.g., 8.8.8.8 or ::1): ")
    domain = args.domain or _input("Enter the domain to look up (e.g., example.com): ")
    record_type = (args.record_type or _input("Enter the record type: ")).strip().upper()

    if record_type not in QTYPE:
        print("Error: Unsupported record type: %s" % record_type)
        sys.exit(1)

    prefer_ipv6 = True
    if args.prefer_ipv4:
        prefer_ipv6 = False
    if args.prefer_ipv6:
        prefer_ipv6 = True

    strict_txid = (not args.no_strict_txid)
    tcp_fallback = (not args.no_tcp_fallback)
    enforce_tc = (not args.no_tc_enforce)

    verbose = (not args.quiet)

    edns_size = int(args.edns_size) if args.edns_size else 0
    do = bool(args.do)
    cd = bool(args.cd)

    # If DNSSEC validation requested, force DO so we actually get RRSIGs
    if args.dnssec_validate:
        do = True

    # roots selection for --recursive
    roots = None
    if args.recursive or args.dnssec_validate:
        roots = load_roots_file(args.roots) if args.roots else None
        if not roots:
            roots = default_root_servers(args.roots_family)

    # transport selection
    transport_mode = "dns"
    doh_url = None
    if args.doh:
        transport_mode = "doh"
        doh_url = args.doh
    elif args.dot:
        transport_mode = "dot"

    dot_verify = (not args.dot_no_verify)
    dot_sni = args.dot_sni
    dot_cafile = args.dot_cafile

    trust_anchor = _read_trust_anchor_file(args.trust_anchor) if args.trust_anchor else None

    try:
        # AXFR
        if record_type == "AXFR":
            if args.recursive:
                print("Error: AXFR is not supported in --recursive mode.")
                sys.exit(1)
            t0 = time.time()
            msgs, sockaddr_used = axfr_tcp(
                dns_server=dns_server, domain=domain, port=args.port, timeout=args.timeout,
                prefer_ipv6=prefer_ipv6, strict_txid=strict_txid,
                edns_size=(edns_size if edns_size else None), do=do, cd=cd
            )
            elapsed_ms = (time.time() - t0) * 1000.0
            if args.dig_style:
                for i, m in enumerate(msgs):
                    sections = decode_sections_for_dig(
                        m, wanted_type=QTYPE["AXFR"], show_all=True,
                        include_authority=args.include_authority,
                        include_additional=args.include_additional
                    )
                    _print_dig_like(
                        sections, domain, record_type,
                        dns_server, args.port, elapsed_ms, m, sockaddr_used, "TCP(AXFR)",
                        include_banner=(bool(args.dig_banner) and i == 0),
                        dig_version=args.dig_version
                    )
                    print("")
                return
            total = sum(len(m) for m in msgs)
            print("AXFR complete: %d messages, %d bytes received in %d ms" % (len(msgs), total, int(elapsed_ms)))
            return

        # -------------------------
        # Choose resolution method
        # -------------------------
        if args.recursive:
            t0 = time.time()
            msg = resolve_with_cname_chase(
                qname=domain,
                qtype_code=QTYPE[record_type],
                roots=roots,
                timeout=args.timeout,
                strict_txid=strict_txid,
                overall_timeout=float(args.overall_timeout),
                port=int(args.roots_port),
                edns_size=(edns_size if edns_size else None),
                do=do,
                cd=cd,
                enforce_tc=enforce_tc
            )
            elapsed_ms = (time.time() - t0) * 1000.0
            sockaddr_used = (roots[0], int(args.roots_port)) if roots else None
            transport = "ITER"
            dns_server_for_print = "root-hints"
            port_for_print = int(args.roots_port)
        else:
            msg, elapsed_ms, sockaddr_used, transport = query_once(
                dns_server=dns_server,
                domain=domain,
                record_type=record_type,
                port=args.port,
                timeout=args.timeout,
                prefer_ipv6=prefer_ipv6,
                strict_txid=strict_txid,
                tcp_fallback=tcp_fallback,
                enforce_tc=enforce_tc,
                edns_size=(edns_size if edns_size else None),
                do=do,
                cd=cd,
                transport_mode=transport_mode,
                doh_url=doh_url,
                dot_verify=dot_verify, dot_sni=dot_sni, dot_cafile=dot_cafile
            )
            dns_server_for_print = dns_server
            port_for_print = int(args.port)

        # -------------------------
        # DNSSEC validation
        # -------------------------
        if args.dnssec_validate:
            if not roots:
                roots = default_root_servers("both")
            ok, notes = dnssec_validate_chain_and_answer(
                qname=domain,
                qtype_code=QTYPE[record_type],
                final_msg=msg,
                roots=roots,
                timeout=args.timeout,
                strict_txid=strict_txid,
                overall_timeout=max(10.0, float(args.overall_timeout)),
                port=int(args.roots_port) if args.recursive else 53,
                edns_size=(edns_size if edns_size else 1232),
                enforce_tc=enforce_tc,
                trust_anchor=trust_anchor,
                verbose=verbose
            )
            print(";; DNSSEC DIY validation:", "OK" if ok else "FAILED")
            for n in notes:
                print(";;   -", n)
            print("")

        # -------------------------
        # Output formatting
        # -------------------------
        if args.dig_style:
            wanted_type = QTYPE.get(record_type, QTYPE["A"])
            dig_sections = decode_sections_for_dig(
                msg,
                wanted_type=wanted_type,
                show_all=args.show_all,
                include_authority=args.include_authority,
                include_additional=args.include_additional,
            )
            _print_dig_like(
                dig_sections,
                domain, record_type,
                dns_server_for_print, port_for_print,
                elapsed_ms, msg, sockaddr_used, transport,
                include_banner=bool(args.dig_banner),
                dig_version=args.dig_version
            )
            return

        # Classic minimal output
        if verbose:
            tid, flags, qd, an, ns, ar, tc, rcode, opcode, aa = _parse_header_fields(msg)
            print("Flags: %04x (%s)" % (flags, _dig_flags_string(flags)))
            print("Answers:", an, "Authority:", ns, "Additional:", ar, "RCODE:", RCODE_MAP.get(rcode, rcode))

        # Print A/AAAA/TXT in classic view
        parsed = _parse_sections_basic(msg)
        want = QTYPE[record_type]
        rrset = [rr for rr in parsed["answers"] if rr["type"] == want and _dnsname_norm(rr["name"]) == _dnsname_norm(domain)]
        if not rrset:
            print("No %s records found for %s." % (record_type, domain))
            return
        print("The %s records for %s are:" % (record_type, domain))
        for rr in rrset:
            if rr["type"] == QTYPE["A"] and rr["rdlength"] == 4:
                b = bytearray(rr["rdata"])
                ip = "%d.%d.%d.%d" % (b[0], b[1], b[2], b[3])
                print("%s\t%d\tIN\tA\t%s" % (rr["name"].rstrip(".") + ".", rr["ttl"], ip))
            elif rr["type"] == QTYPE["AAAA"] and rr["rdlength"] == 16:
                ip6 = _ipv6_to_str(rr["rdata"])
                print("%s\t%d\tIN\tAAAA\t%s" % (rr["name"].rstrip(".") + ".", rr["ttl"], ip6))
            elif rr["type"] == QTYPE["TXT"]:
                ln = _byte_at(rr["rdata"], 0) if rr["rdlength"] >= 1 else 0
                txt = rr["rdata"][1:1+ln]
                try:
                    txts = txt.decode("utf-8", "replace")
                except Exception:
                    txts = str(txt)
                print("%s\t%d\tIN\tTXT\t\"%s\"" % (rr["name"].rstrip(".") + ".", rr["ttl"], txts))
            else:
                print("%s\t%d\tIN\tTYPE%d\t(%d bytes)" % (rr["name"].rstrip(".") + ".", rr["ttl"], rr["type"], rr["rdlength"]))

    except socket.timeout:
        print("Error: DNS query timed out.")
        sys.exit(1)
    except urllib_error.URLError as e:
        print("Error (DoH):", e)
        sys.exit(1)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
