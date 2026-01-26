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


def _resolve_one_ip(host, prefer_ipv6=True):
    """
    Best-effort resolve hostname -> one IP string (display only).
    Returns None on failure.
    """
    if not host:
        return None
    if _is_ip_literal(host):
        if "%" in host:
            return host.split("%", 1)[0]
        return host
    try:
        infos = socket.getaddrinfo(host, 0, socket.AF_UNSPEC, 0, 0)
        best = None
        for fam, _socktype, _proto, _canon, sockaddr in infos:
            ip = sockaddr[0]
            if best is None:
                best = ip
            if prefer_ipv6 and fam == socket.AF_INET6:
                return ip
            if (not prefer_ipv6) and fam == socket.AF_INET:
                return ip
        return best
    except Exception:
        return None


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


def build_dns_query(domain, record_type):
    """
    Returns (wire_query, txid_bytes).
    """
    txid = random.randint(0, 0xFFFF)
    tid = struct.pack('!H', txid)
    flags = struct.pack('!H', 0x0100)  # RD=1
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


def query_once(dns_server, domain, record_type, port, timeout,
               prefer_ipv6=True, tcp_fallback=True, strict_txid=True):
    query, _txid = build_dns_query(domain, record_type)
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
                         resolve_server_name=False):
    rcode_any = 0
    aa_any = False
    a_list = []
    aaaa_list = []
    used = None

    try:
        msg_a, _ms_a, sockaddr_a, _transport_a = query_once(
            dns_server, domain, "A", port, timeout,
            prefer_ipv6=prefer_ipv6, tcp_fallback=tcp_fallback, strict_txid=strict_txid
        )
        a_list, _aaaa_dummy, rcode_a, aa_a = _extract_addresses_and_aa_from_answer(msg_a)
        rcode_any = rcode_a
        aa_any = aa_any or aa_a
        used = sockaddr_a
    except Exception:
        pass

    try:
        msg_aaaa, _ms_aaaa, sockaddr_aaaa, _transport_aaaa = query_once(
            dns_server, domain, "AAAA", port, timeout,
            prefer_ipv6=prefer_ipv6, tcp_fallback=tcp_fallback, strict_txid=strict_txid
        )
        _a_dummy, aaaa_list, rcode_aaaa, aa_aaaa = _extract_addresses_and_aa_from_answer(msg_aaaa)
        rcode_any = rcode_any or rcode_aaaa
        aa_any = aa_any or aa_aaaa
        if used is None:
            used = sockaddr_aaaa
    except Exception:
        pass

    server_line = server_name_display if server_name_display else dns_server

    if resolve_server_name and (not _is_ip_literal(dns_server)):
        used_ip = _resolve_one_ip(dns_server, prefer_ipv6=prefer_ipv6) or (used[0] if used else dns_server)
    else:
        used_ip = used[0] if used else dns_server

    print("Server:\t\t%s" % server_line)
    print("Address:\t%s#%d" % (used_ip, int(port)))
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
        description="DNS Query Script: strict TXID validation + IPv6 + dig/nslookup styles"
    )
    parser.add_argument('--dns-server', type=str,
                        help='DNS server address (IPv4, IPv6, IPv6%zone, or hostname)')
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
    parser.add_argument('--nslookup-server-name', type=str, default=None,
                        help='Override the name printed on the "Server:" line (e.g. dns.google)')
    parser.add_argument('--nslookup-resolve-server', action='store_true',
                        help='Resolve the server hostname for the "Address:" line (display only)')

    parser.add_argument('--quiet', action='store_true', help='Less header/debug output (classic mode)')

    args = parser.parse_args()

    try:
        _input = raw_input  # noqa
    except NameError:
        _input = input

    dns_server = args.dns_server or _input("Enter the DNS server IP/host (e.g., 8.8.8.8 or ::1): ")
    domain = args.domain or _input("Enter the domain to look up (e.g., example.com): ")
    record_type = (args.record_type or _input("Enter the record type (A, AAAA, MX, CNAME, NS, TXT): ")).strip().upper()

    prefer_ipv6 = True
    if args.prefer_ipv4:
        prefer_ipv6 = False
    if args.prefer_ipv6:
        prefer_ipv6 = True

    strict_txid = (not args.no_strict_txid)
    tcp_fallback = (not args.no_tcp_fallback)
    verbose = (not args.quiet)

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
            )
            return

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
                dns_server, args.port,
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

        # Print answer records in dig-ish single-line format
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
            _print_trailer_like_dig(dns_server, args.port, elapsed_ms, msg, sockaddr_used, transport)

    except socket.timeout:
        print("Error: DNS query timed out.")
        sys.exit(1)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
