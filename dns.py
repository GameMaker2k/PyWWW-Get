#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import socket
import struct
import argparse
import random
import sys
import time

# DNS record types
QTYPE = {
    'A': 1,
    'NS': 2,
    'CNAME': 5,
    'MX': 15,
    'TXT': 16,
    'AAAA': 28,
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

    # IP literal path (IPv6 includes %zone)
    if _is_ip_literal(dns_server):
        yield _addr_tuple(dns_server, port)
        return

    # Hostname path
    try:
        infos = socket.getaddrinfo(
            dns_server,
            port,
            socket.AF_UNSPEC,
            0,
            0,
            socket.AI_ADDRCONFIG
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


def encode_qname(domain):
    domain = domain.strip().rstrip('.')
    if not domain:
        raise ValueError("Empty domain")
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


def build_dns_query(domain, record_type, rd=True):
    """
    Returns (wire_query, txid_bytes).
    rd=True -> recursion desired bit set.
    """
    txid = random.randint(0, 0xFFFF)
    tid = struct.pack('!H', txid)
    flags_val = 0x0100 if rd else 0x0000
    flags = struct.pack('!H', flags_val)
    qdcount = struct.pack('!H', 1)
    ancount = struct.pack('!H', 0)
    nscount = struct.pack('!H', 0)
    arcount = struct.pack('!H', 0)

    qname = encode_qname(domain)
    qtype = struct.pack('!H', QTYPE[record_type])
    qclass = struct.pack('!H', QCLASS_IN)

    header = tid + flags + qdcount + ancount + nscount + arcount
    question = qname + qtype + qclass
    return header + question, tid


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


def _hex_dump(b):
    if hasattr(b, "hex"):
        return b.hex()
    return "".join("%02x" % ord(c) for c in b)


def _recvn(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _get_txid(wire_msg):
    if not wire_msg or len(wire_msg) < 2:
        return None
    return wire_msg[:2]


def query_tcp(dns_server, query, port, timeout, prefer_ipv6=True, strict_txid=True):
    expected = _get_txid(query)
    if strict_txid and expected is None:
        raise ValueError("Query too short to contain TXID")

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
            sock.close()

    raise last_err if last_err else RuntimeError("TCP query failed for all addresses")


def _parse_header_fields(msg):
    if len(msg) < 12:
        raise ValueError("Incomplete DNS header")
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', msg[:12])
    tc = bool(flags & 0x0200)
    rcode = flags & 0x000F
    opcode = (flags >> 11) & 0x0F
    aa = bool(flags & 0x0400)
    return tid, flags, qdcount, ancount, nscount, arcount, tc, rcode, opcode, aa


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


def _extract_addresses_and_aa_from_answer(msg):
    tid, flags, qdcount, ancount, nscount, arcount, tc, rcode, opcode, aa = _parse_header_fields(msg)
    offset = 12
    offset = skip_question_section(msg, offset, qdcount)

    a = []
    aaaa = []

    for _ in range(ancount):
        rr, offset = parse_rr(msg, offset)
        if rr["type"] == QTYPE["A"] and rr["rdlength"] == 4:
            ip = "%d.%d.%d.%d" % tuple(bytearray(rr["rdata"]))
            a.append(ip)
        elif rr["type"] == QTYPE["AAAA"] and rr["rdlength"] == 16:
            aaaa.append(_ipv6_to_str(rr["rdata"]))

    return a, aaaa, rcode, aa


# -----------------------------
# NEW: Iterative/recursive resolver mode (client-side)
# -----------------------------
def _dnsname_norm(s):
    return (s or "").strip().lower().rstrip(".")

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
        try:
            sock.close()
        except Exception:
            pass

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
        try:
            sock.close()
        except Exception:
            pass

def _exchange_tc_fallback_ip(server_ip, wire_query, timeout, strict_txid=True, port=53):
    resp = _udp_exchange_ip(server_ip, wire_query, timeout, strict_txid=strict_txid, port=port)
    try:
        _tid, _flags, _qd, _an, _ns, _ar, tc, _rcode, _op, _aa = _parse_header_fields(resp)
    except Exception:
        return resp
    if tc:
        try:
            return _tcp_exchange_ip(server_ip, wire_query, timeout, strict_txid=strict_txid, port=port)
        except Exception:
            return resp
    return resp

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

def iterative_resolve(qname, qtype_code, roots, timeout, strict_txid=True,
                      max_steps=25, overall_timeout=6.0, port=53):
    """
    Client-side iterative resolver:
      - Sends RD=0
      - Follows referrals from root
      - Uses TCP fallback on TC=1
      - If no glue, resolves NS names recursively (A then AAAA)
    Returns the final wire response (bytes) or last response seen.
    """
    deadline = time.time() + float(overall_timeout)
    next_servers = list(roots)
    random.shuffle(next_servers)
    last_msg = None

    # Turn qtype_code into record_type string for building queries
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

        # Build RD=0 query for iterative step
        wire, _ = build_dns_query(qname, qtype_str, rd=False)

        remaining = deadline - time.time()
        if remaining <= 0:
            break
        per_try = min(float(timeout), max(0.05, remaining))

        try:
            resp = _exchange_tc_fallback_ip(server_ip, wire, per_try, strict_txid=strict_txid, port=port)
        except Exception:
            continue

        last_msg = resp
        try:
            parsed = _parse_sections_basic(resp)
        except Exception:
            continue

        # terminal rcode
        if parsed["rcode"] != 0:
            return resp

        # answers present => done (may include CNAME)
        if parsed["answers"]:
            return resp

        # referral: NS in authority + glue in additional
        ns_names = []
        for rr in parsed["authority"]:
            if rr["type"] == QTYPE["NS"]:
                try:
                    nsn, _ = decode_domain_name(resp, rr["rdata_offset"])
                    ns_names.append(_dnsname_norm(nsn))
                except Exception:
                    pass

        # glue (A/AAAA) for those NS names
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

        # no glue => resolve NS hostnames (A then AAAA)
        if ns_names:
            random.shuffle(ns_names)
            resolved = []
            for nsn in ns_names[:3]:
                for qt in (QTYPE["A"], QTYPE["AAAA"]):
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    # recurse with smaller budgets to avoid runaway
                    ns_resp = iterative_resolve(
                        nsn, qt, roots,
                        timeout=min(float(timeout), 0.6),
                        strict_txid=strict_txid,
                        max_steps=12,
                        overall_timeout=max(0.2, remaining),
                        port=port
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
                            max_steps=25, overall_timeout=6.0, max_cname=8, port=53):
    """
    If qtype is A/AAAA: chase CNAME until A/AAAA found, returning the final response.
    For other qtypes: just iterative_resolve().
    """
    if qtype_code not in (QTYPE["A"], QTYPE["AAAA"]):
        return iterative_resolve(qname, qtype_code, roots, timeout, strict_txid=strict_txid,
                                max_steps=max_steps, overall_timeout=overall_timeout, port=port)

    current = qname
    seen = set([_dnsname_norm(current)])
    want = qtype_code

    for _ in range(max_cname):
        resp = iterative_resolve(current, want, roots, timeout, strict_txid=strict_txid,
                                max_steps=max_steps, overall_timeout=overall_timeout, port=port)
        if not resp:
            return resp

        try:
            parsed = _parse_sections_basic(resp)
        except Exception:
            return resp

        # if we got desired answers, done
        if any(rr["type"] == want for rr in parsed["answers"]):
            return resp

        # try find a CNAME
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
# Single query (normal mode)
# -----------------------------
def query_once(dns_server, domain, record_type, port, timeout,
               prefer_ipv6=True, tcp_fallback=True, strict_txid=True):
    query, _txid = build_dns_query(domain, record_type, rd=True)
    expected = _get_txid(query)

    t0 = time.time()
    last_err = None
    msg = None
    sockaddr_used = None
    transport = "UDP"

    for sockaddr in _iter_server_addrs(dns_server, port, prefer_ipv6=prefer_ipv6):
        fam = socket.AF_INET6 if len(sockaddr) == 4 else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.settimeout(float(timeout))
        try:
            sock.sendto(query, sockaddr)
            while True:
                resp, _ = sock.recvfrom(4096)
                if (not strict_txid) or (_get_txid(resp) == expected):
                    msg = resp
                    sockaddr_used = sockaddr
                    break
        except Exception as e:
            last_err = e
        finally:
            sock.close()
        if msg is not None:
            break

    if msg is None:
        raise last_err if last_err else RuntimeError("UDP query failed for all addresses")

    elapsed_ms = (time.time() - t0) * 1000.0

    tc = bool(_parse_header_fields(msg)[6])
    if tc and tcp_fallback:
        transport = "TCP"
        t1 = time.time()
        msg2, sockaddr2 = query_tcp(
            dns_server, query, port, timeout,
            prefer_ipv6=prefer_ipv6, strict_txid=strict_txid
        )
        elapsed_ms = (time.time() - t1) * 1000.0
        msg = msg2
        sockaddr_used = sockaddr2

    return msg, elapsed_ms, sockaddr_used, transport


def _print_nslookup_error(domain, rcode):
    status = RCODE_MAP.get(rcode, "UNKNOWN")
    print("** server can't find %s: %s" % (domain, status))


def _print_nslookup_like(dns_server, port, domain, prefer_ipv6, timeout,
                         tcp_fallback, strict_txid,
                         server_name_display=None,
                         resolve_server_name=False,
                         nslookup_default_header=False,
                         recursive=False,
                         roots=None,
                         roots_port=53):
    rcode_any = 0
    aa_any = False
    a_list = []
    aaaa_list = []
    used = None

    def _run_one(rt):
        if recursive:
            msg = resolve_with_cname_chase(domain, QTYPE[rt], roots, timeout,
                                           strict_txid=strict_txid, port=roots_port)
            return msg, None, "UDP"  # iterative uses many hops; this is a placeholder
        msg, _ms, sockaddr, transport = query_once(
            dns_server, domain, rt, port, timeout,
            prefer_ipv6=prefer_ipv6, tcp_fallback=tcp_fallback, strict_txid=strict_txid
        )
        return msg, sockaddr, transport

    try:
        msg_a, sockaddr_a, _transport_a = _run_one("A")
        a_list, _aaaa_dummy, rcode_a, aa_a = _extract_addresses_and_aa_from_answer(msg_a)
        rcode_any = rcode_a
        aa_any = aa_any or aa_a
        used = sockaddr_a
    except Exception:
        pass

    try:
        msg_aaaa, sockaddr_aaaa, _transport_aaaa = _run_one("AAAA")
        _a_dummy, aaaa_list, rcode_aaaa, aa_aaaa = _extract_addresses_and_aa_from_answer(msg_aaaa)
        rcode_any = rcode_any or rcode_aaaa
        aa_any = aa_any or aa_aaaa
        if used is None:
            used = sockaddr_aaaa
    except Exception:
        pass

    server_line = server_name_display if server_name_display else dns_server

    if recursive:
        # nslookup-like header for recursive mode: show "Server" as "root-hints" to avoid lying
        server_line = server_name_display if server_name_display else "root-hints"
        server_ips = []
        if roots:
            # show 1st root only for header compactness
            server_ips = [roots[0]]
        else:
            server_ips = ["(none)"]
    else:
        if resolve_server_name:
            server_ips = _resolve_all_server_ips(dns_server, prefer_ipv6=prefer_ipv6)
            if not server_ips and used:
                server_ips = [used[0]]
            if not server_ips:
                server_ips = [dns_server]
        else:
            if used:
                server_ips = [used[0]]
            else:
                one = _resolve_all_server_ips(dns_server, prefer_ipv6=prefer_ipv6)
                server_ips = one[:1] if one else [dns_server]

    if nslookup_default_header:
        print("Default server:\t%s" % server_line)
        for ip in server_ips:
            print("Address:\t%s#%d" % (ip, int(port if not recursive else roots_port)))
    else:
        print("Server:\t\t%s" % server_line)
        for ip in server_ips[:1]:
            print("Address:\t%s#%d" % (ip, int(port if not recursive else roots_port)))

    print("")

    if (not a_list) and (not aaaa_list):
        _print_nslookup_error(domain, rcode_any)
        return

    print(("Authoritative answer:" if aa_any else "Non-authoritative answer:"))
    print("Name:\t%s" % domain)
    for ip in a_list:
        print("Address:\t%s" % ip)
    for ip6 in aaaa_list:
        print("Address:\t%s" % ip6)


def main():
    parser = argparse.ArgumentParser(
        description="DNS Query Script: strict TXID validation + IPv6 + dig/nslookup styles + optional client-side iterative recursion"
    )
    parser.add_argument('--dns-server', type=str,
                        help='DNS server address (IPv4, IPv6, IPv6%%zone, or hostname)')
    parser.add_argument('--domain', type=str, help='Domain to look up (e.g., example.com)')
    parser.add_argument('--record-type', type=str, default='A',
                        help='DNS record type (A, AAAA, MX, CNAME, NS, TXT)')
    parser.add_argument('--port', type=int, default=53, help='DNS server port number (default 53)')
    parser.add_argument('--timeout', type=float, default=2, help='Timeout in seconds (default 2)')
    parser.add_argument('--no-tcp-fallback', action='store_true',
                        help='Disable TCP fallback on truncated UDP response')

    parser.add_argument('--show-all', action='store_true',
                        help='(dig-style) include all RR types (still only prints A/AAAA/MX/NS/CNAME)')
    parser.add_argument('--include-authority', action='store_true',
                        help='(dig-style) include Authority section')
    parser.add_argument('--include-additional', action='store_true',
                        help='(dig-style) include Additional section')

    parser.add_argument('--prefer-ipv4', action='store_true',
                        help='Prefer IPv4 first when --dns-server is a hostname')
    parser.add_argument('--prefer-ipv6', action='store_true',
                        help='Prefer IPv6 first when --dns-server is a hostname (default)')

    parser.add_argument('--no-strict-txid', action='store_true',
                        help='Disable TXID validation (debug only)')

    # Output modes
    parser.add_argument('--dig-style', action='store_true',
                        help='Print output similar to dig (includes trailer)')
    parser.add_argument('--dig-banner', action='store_true',
                        help='Also print the first 3 dig banner lines')
    parser.add_argument('--dig-version', type=str, default="9.20.x",
                        help='Version string to show in the dig banner (default: 9.20.x)')

    parser.add_argument('--classic-trailer', action='store_true',
                        help='In classic output, also print dig-like trailer')

    parser.add_argument('--nslookup', action='store_true',
                        help='Print nslookup-like output (queries both A and AAAA)')
    parser.add_argument('--nslookup-default-header', action='store_true',
                        help='Use "Default server:" / "Address:" header style (like common nslookup)')
    parser.add_argument('--nslookup-server-name', type=str, default=None,
                        help='Override the name printed on the "Server:"/"Default server:" line (e.g. dns.google)')
    parser.add_argument('--nslookup-resolve-server', action='store_true',
                        help='Resolve the server hostname and print ALL server IPs in the header (display only)')

    parser.add_argument('--quiet', action='store_true', help='Less header/debug output (classic mode)')

    # NEW: client-side iterative recursion mode
    parser.add_argument('--recursive', action='store_true',
                        help='Client-side recursive/iterative resolve starting from root servers (ignores --dns-server)')
    parser.add_argument('--roots-family', type=str, default="both",
                        choices=["both", "ipv4", "ipv6", "auto"],
                        help='Which built-in root addresses to use (both|ipv4|ipv6|auto). Default: both')
    parser.add_argument('--roots', type=str, default=None,
                        help='Root server IP list file (one IP per line). Overrides built-in root table')
    parser.add_argument('--roots-port', type=int, default=53,
                        help='Port for root/TLD/authoritative servers (default: 53)')
    parser.add_argument('--overall-timeout', type=float, default=6.0,
                        help='Overall time budget (seconds) for --recursive mode (default: 6.0)')

    args = parser.parse_args()

    try:
        _input = raw_input  # noqa
    except NameError:
        _input = input

    dns_server = args.dns_server or _input("Enter the DNS server IP/host (e.g., 8.8.8.8 or ::1): ")
    domain = args.domain or _input("Enter the domain to look up (e.g., example.com): ")
    record_type = (args.record_type or _input("Enter the record type (A, AAAA, MX, CNAME, NS, TXT): ")).strip().upper()

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
    verbose = (not args.quiet)

    # roots selection for --recursive
    roots = None
    if args.recursive:
        roots = load_roots_file(args.roots) if args.roots else None
        if not roots:
            roots = default_root_servers(args.roots_family)

    try:
        if args.nslookup:
            _print_nslookup_like(
                dns_server=dns_server,
                port=args.port,
                domain=domain,
                prefer_ipv6=prefer_ipv6,
                timeout=args.timeout,
                tcp_fallback=tcp_fallback,
                strict_txid=strict_txid,
                server_name_display=args.nslookup_server_name,
                resolve_server_name=bool(args.nslookup_resolve_server),
                nslookup_default_header=bool(args.nslookup_default_header),
                recursive=bool(args.recursive),
                roots=roots,
                roots_port=args.roots_port,
            )
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
            )
            elapsed_ms = (time.time() - t0) * 1000.0
            sockaddr_used = (roots[0], int(args.roots_port)) if roots else None
            transport = "UDP"
            # In recursive mode, "dns_server" in trailers should not claim a real server the user didn't set
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
                tcp_fallback=tcp_fallback,
                strict_txid=strict_txid,
            )
            dns_server_for_print = dns_server
            port_for_print = int(args.port)

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

        # Classic mode
        if verbose:
            print("Raw %s response: %s" % (transport, _hex_dump(msg)))
            tid, flags, qd, an, ns, ar, tc, rcode, opcode, aa = _parse_header_fields(msg)
            print("Transaction ID: %04x" % tid)
            print("Flags: %04x" % flags)
            print("Questions: %d" % qd)
            print("Answer RRs: %d" % an)
            print("Authority RRs: %d" % ns)
            print("Additional RRs: %d" % ar)

        tid, flags, qd, an, ns, ar, tc, rcode, opcode, aa = _parse_header_fields(msg)
        offset = 12
        offset = skip_question_section(msg, offset, qd)

        lines = []
        want = QTYPE.get(record_type, QTYPE["A"])
        for _ in range(an):
            rr, offset = parse_rr(msg, offset)
            if rr["type"] != want:
                continue
            owner = rr["name"].rstrip(".") + "."
            ttl = rr["ttl"]
            if rr["type"] == QTYPE["A"] and rr["rdlength"] == 4:
                ip = "%d.%d.%d.%d" % tuple(bytearray(rr["rdata"]))
                lines.append("%s\t\t%d\tIN\tA\t%s" % (owner, ttl, ip))
            elif rr["type"] == QTYPE["AAAA"] and rr["rdlength"] == 16:
                ip6 = _ipv6_to_str(rr["rdata"])
                lines.append("%s\t\t%d\tIN\tAAAA\t%s" % (owner, ttl, ip6))

        if lines:
            print("The %s records for %s are:" % (record_type, domain))
            for ln in lines:
                print(ln)
        else:
            print("No %s records found for %s." % (record_type, domain))

        if args.classic_trailer:
            _print_trailer_like_dig(dns_server_for_print, port_for_print, elapsed_ms, msg, sockaddr_used, transport)

    except socket.timeout:
        print("Error: DNS query timed out.")
        sys.exit(1)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
