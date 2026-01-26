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
    if _is_ipv6_literal(dns_server) or dns_server.replace(".", "").isdigit():
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


def decode_txt_rdata(rdata):
    out = []
    i = 0
    while i < len(rdata):
        ln = _byte_at(rdata, i)
        i += 1
        chunk = rdata[i:i + ln]
        i += ln
        try:
            out.append(chunk.decode('utf-8'))
        except Exception:
            if len(chunk) and not isinstance(chunk[0], int):  # Py2 bytes
                out.append(''.join(chr(ord(c)) for c in chunk))
            else:
                out.append(''.join(chr(c) for c in chunk))
    return out


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


def _type_name_from_code(code):
    for k, v in QTYPE.items():
        if v == code:
            return k
    return "TYPE%d" % code


def rr_to_strings_classic(msg, rr):
    rtype = rr['type']
    ttl = rr['ttl']
    rdata = rr['rdata']
    tname = _type_name_from_code(rtype)

    if rtype == QTYPE['A'] and rr['rdlength'] == 4:
        ip = "%d.%d.%d.%d" % tuple(bytearray(rdata))
        return ["A: %s (TTL=%d)" % (ip, ttl)]

    if rtype == QTYPE['AAAA'] and rr['rdlength'] == 16:
        ip6 = _ipv6_to_str(rdata)
        return ["AAAA: %s (TTL=%d)" % (ip6, ttl)]

    if rtype in (QTYPE['CNAME'], QTYPE['NS']):
        target, _ = decode_domain_name(msg, rr['rdata_offset'])
        return ["%s: %s (TTL=%d)" % (tname, target, ttl)]

    if rtype == QTYPE['MX']:
        if rr['rdlength'] < 3:
            return []
        pref = struct.unpack('!H', rdata[:2])[0]
        exchange, _ = decode_domain_name(msg, rr['rdata_offset'] + 2)
        return ["MX: preference=%d exchange=%s (TTL=%d)" % (pref, exchange, ttl)]

    if rtype == QTYPE['TXT']:
        chunks = decode_txt_rdata(rdata)
        return ["TXT: %s (TTL=%d)" % (c, ttl) for c in chunks]

    return ["%s: rdlength=%d (TTL=%d)" % (tname, rr['rdlength'], ttl)]


def rr_to_strings_dig(msg, rr):
    rtype = rr['type']
    ttl = rr['ttl']
    rdata = rr['rdata']
    tname = _type_name_from_code(rtype)
    owner = rr.get('name', '').rstrip(".")

    if rtype == QTYPE['A'] and rr['rdlength'] == 4:
        ip = "%d.%d.%d.%d" % tuple(bytearray(rdata))
        return ["%s.\t\t%d\tIN\tA\t%s" % (owner, ttl, ip)]

    if rtype == QTYPE['AAAA'] and rr['rdlength'] == 16:
        ip6 = _ipv6_to_str(rdata)
        return ["%s.\t\t%d\tIN\tAAAA\t%s" % (owner, ttl, ip6)]

    if rtype in (QTYPE['CNAME'], QTYPE['NS']):
        target, _ = decode_domain_name(msg, rr['rdata_offset'])
        return ["%s.\t\t%d\tIN\t%s\t%s." % (owner, ttl, tname, target.rstrip("."))]

    if rtype == QTYPE['MX']:
        if rr['rdlength'] < 3:
            return []
        pref = struct.unpack('!H', rdata[:2])[0]
        exchange, _ = decode_domain_name(msg, rr['rdata_offset'] + 2)
        return ["%s.\t\t%d\tIN\tMX\t%d %s." % (owner, ttl, pref, exchange.rstrip("."))]

    if rtype == QTYPE['TXT']:
        chunks = decode_txt_rdata(rdata)
        return ['%s.\t\t%d\tIN\tTXT\t"%s"' % (owner, ttl, c.replace('"', r'\"')) for c in chunks]

    return ["%s.\t\t%d\tIN\t%s\t<rdlength=%d>" % (owner, ttl, tname, rr['rdlength'])]


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
    return tid, flags, qdcount, ancount, nscount, arcount, tc, rcode, opcode


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


def decode_sections(msg, wanted_type=None, show_all=False,
                    include_authority=False, include_additional=False,
                    rr_formatter=rr_to_strings_classic):
    tid, flags, qdcount, ancount, nscount, arcount, tc, rcode, opcode = _parse_header_fields(msg)
    offset = 12
    offset = skip_question_section(msg, offset, qdcount)

    def collect(count, offset):
        out = []
        for _ in range(count):
            rr, offset2 = parse_rr(msg, offset)
            offset = offset2
            if wanted_type is not None and (not show_all) and rr['type'] != wanted_type:
                continue
            out.extend(rr_formatter(msg, rr))
        return out, offset

    ans, offset = collect(ancount, offset)

    if include_authority:
        auth, offset = collect(nscount, offset)
    else:
        for _ in range(nscount):
            _, offset = parse_rr(msg, offset)
        auth = []

    if include_additional:
        add, offset = collect(arcount, offset)
    else:
        for _ in range(arcount):
            _, offset = parse_rr(msg, offset)
        add = []

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
        },
        "answer": ans,
        "authority": auth,
        "additional": add,
    }


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


def _print_dig_like(sections, domain, record_type, dns_server, port,
                    elapsed_ms, msg, sockaddr_used, transport):
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


def perform_dns_query(dns_server, domain, record_type='A',
                      port=53, timeout=2,
                      tcp_fallback=True,
                      prefer_ipv6=True,
                      strict_txid=True):
    record_type = record_type.strip().upper()
    if record_type not in QTYPE:
        raise ValueError("Unsupported record type: %r" % record_type)

    query, _txid = build_dns_query(domain, record_type)
    expected = _get_txid(query)

    # UDP first
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

    # TCP fallback if TC=1
    tc = bool(_parse_header_fields(msg)[6])
    if tc and tcp_fallback:
        transport = "TCP"
        t1 = time.time()
        msg2, sockaddr2 = query_tcp(dns_server, query, port, timeout,
                                   prefer_ipv6=prefer_ipv6, strict_txid=strict_txid)
        elapsed_ms = (time.time() - t1) * 1000.0
        msg = msg2
        sockaddr_used = sockaddr2

    return msg, elapsed_ms, sockaddr_used, transport


def main():
    parser = argparse.ArgumentParser(
        description="DNS Query Script (Python 2/3): strict TXID validation, IPv6/hostname server, dig-like output, classic output preserved"
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
                        help='Show all RR types in selected sections (not only requested type)')
    parser.add_argument('--include-authority', action='store_true',
                        help='Also show Authority section')
    parser.add_argument('--include-additional', action='store_true',
                        help='Also show Additional section')

    parser.add_argument('--prefer-ipv4', action='store_true',
                        help='Prefer IPv4 first when --dns-server is a hostname')
    parser.add_argument('--prefer-ipv6', action='store_true',
                        help='Prefer IPv6 first when --dns-server is a hostname (default)')

    parser.add_argument('--no-strict-txid', action='store_true',
                        help='Disable TXID validation (debug only)')

    parser.add_argument('--dig-style', action='store_true',
                        help='Print output similar to dig (includes trailer lines)')
    parser.add_argument('--dig-banner', action='store_true',
                        help='Also print the first 3 dig banner lines')
    parser.add_argument('--dig-version', type=str, default="9.20.x",
                        help='Version string to show in the dig banner (default: 9.20.x)')

    # NEW: classic trailer (dig-like footer without switching formats)
    parser.add_argument('--classic-trailer', action='store_true',
                        help='In classic output, also print dig-like trailer (Query time / SERVER / WHEN / MSG SIZE)')

    parser.add_argument('--quiet', action='store_true', help='Less header/debug output')

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
    verbose = (not args.quiet)

    try:
        msg, elapsed_ms, sockaddr_used, transport = perform_dns_query(
            dns_server=dns_server,
            domain=domain,
            record_type=record_type,
            port=args.port,
            timeout=args.timeout,
            tcp_fallback=(not args.no_tcp_fallback),
            prefer_ipv6=prefer_ipv6,
            strict_txid=strict_txid
        )

        if args.dig_style:
            dig_sections = decode_sections(
                msg,
                wanted_type=QTYPE[record_type],
                show_all=args.show_all,
                include_authority=args.include_authority,
                include_additional=args.include_additional,
                rr_formatter=rr_to_strings_dig
            )
            if args.dig_banner:
                _print_dig_banner(dns_server, args.port, domain, args.dig_version)
                print("")
            _print_dig_like(dig_sections, domain, record_type, dns_server, args.port,
                            elapsed_ms, msg, sockaddr_used, transport)
            return

        # Classic (old) output path
        if verbose:
            print("Raw %s response: %s" % (transport, _hex_dump(msg)))
            tid, flags, qd, an, ns, ar, tc, rcode, opcode = _parse_header_fields(msg)
            print("Transaction ID: %04x" % tid)
            print("Flags: %04x" % flags)
            print("Questions: %d" % qd)
            print("Answer RRs: %d" % an)
            print("Authority RRs: %d" % ns)
            print("Additional RRs: %d" % ar)

        classic_sections = decode_sections(
            msg,
            wanted_type=QTYPE[record_type],
            show_all=args.show_all,
            include_authority=args.include_authority,
            include_additional=args.include_additional,
            rr_formatter=rr_to_strings_classic
        )

        recs = classic_sections["answer"]
        if recs:
            label = ("records" if args.show_all else ("%s records" % record_type))
            print("The %s for %s are:" % (label, domain))
            for r in recs:
                print(r)
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
