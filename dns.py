#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import socket
import struct
import argparse
import random
import sys

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


def _to_bytes(s):
    """Return bytes for both Py2 and Py3."""
    if isinstance(s, bytes):
        return s
    return s.encode('utf-8')


def _byte_at(b, i):
    """Get integer value of byte at index i for Py2/Py3."""
    v = b[i]
    return v if isinstance(v, int) else ord(v)


def _sock_family_for_server(host):
    # If it contains ':' treat as IPv6 literal (including IPv6%zone)
    return socket.AF_INET6 if ":" in host else socket.AF_INET

def _split_ipv6_zone(host):
    """
    Split IPv6 address and zone-id if present:
      'fe80::1%wlan0' -> ('fe80::1', 'wlan0')
      '::1' -> ('::1', None)
    """
    if "%" in host:
        addr, zone = host.split("%", 1)
        return addr, zone
    return host, None

def _scope_id_from_zone(zone):
    """
    Convert zone string to numeric scope id.
    - If zone is digits, use it directly.
    - Else try socket.if_nametoindex(zone) (Linux/Android usually supports this).
    """
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
    # crude but effective: IPv6 literals contain ':'
    return ":" in s

def _addr_tuple(host, port):
    """
    Return a sockaddr suitable for sendto/connect:
      IPv4: (host, port)
      IPv6: (addr, port, flowinfo, scopeid)

    Supports IPv6 zone IDs like 'fe80::1%wlan0'.
    """
    port = int(port)
    if _is_ipv6_literal(host):
        addr, zone = _split_ipv6_zone(host)
        scopeid = _scope_id_from_zone(zone)
        return (addr, port, 0, scopeid)
    return (host, port)

def _iter_server_addrs(dns_server, port):
    """
    Yield sockaddr tuples to try, in a good order.
    - If dns_server is an IP literal (v4 or v6%zone), just yield that.
    - If it's a hostname, resolve with getaddrinfo and yield all candidates.
    """
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
        # fallback without AI_ADDRCONFIG
        infos = socket.getaddrinfo(dns_server, port, socket.AF_UNSPEC)

    # Prefer IPv6 first, then IPv4 (you can flip this if you want)
    def _rank(info):
        fam = info[0]
        return 0 if fam == socket.AF_INET6 else 1

    seen = set()
    for fam, socktype, proto, canonname, sockaddr in sorted(infos, key=_rank):
        # sockaddr can be 2-tuple (v4) or 4-tuple (v6)
        if sockaddr in seen:
            continue
        seen.add(sockaddr)
        yield sockaddr


def encode_qname(domain):
    """
    Encode a domain name into DNS QNAME format:
      "example.com" -> b"\\x07example\\x03com\\x00"
    """
    domain = domain.strip().rstrip('.')
    if not domain:
        raise ValueError("Empty domain")

    parts = domain.split('.')
    out = []
    for part in parts:
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
    Build a standard DNS query message for one question.
    """
    tid = struct.pack('!H', random.randint(0, 0xFFFF))
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
    return header + question


def decode_domain_name(msg, offset):
    """
    Decode a possibly-compressed DNS name starting at offset.
    Returns (name, new_offset).
    """
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

        # End of name
        if length == 0:
            offset += 1
            break

        # compression pointer
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

        # label
        offset += 1
        if offset + length > len(msg):
            raise ValueError("Truncated label in name")
        label_bytes = msg[offset:offset + length]
        try:
            label = label_bytes.decode('utf-8')
        except Exception:
            # fallback: best-effort byte->char
            if len(label_bytes) and not isinstance(label_bytes[0], int):  # Py2 bytes
                label = ''.join(chr(ord(c)) for c in label_bytes)
            else:
                label = ''.join(chr(c) for c in label_bytes)
        labels.append(label)
        offset += length

    return '.'.join(labels), (original_offset if jumped else offset)


def skip_question_section(msg, offset, qdcount):
    """
    Skip qdcount questions starting at offset.
    Each question: QNAME + QTYPE(2) + QCLASS(2)
    """
    for _ in range(qdcount):
        _, offset = decode_domain_name(msg, offset)
        if offset + 4 > len(msg):
            raise ValueError("Truncated question section")
        offset += 4
    return offset


def parse_rr(msg, offset):
    """
    Parse one Resource Record and return (rr_dict, new_offset).
    rr_dict includes rdata_offset (start index of rdata).
    """
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
    """
    TXT RDATA is one or more <length byte><text> chunks.
    Return list[str].
    """
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
    """
    Convert 16-byte IPv6 into a compressed textual representation.
    Uses inet_ntop when available, else manual zero-compression.
    """
    b = bytes(bytearray(packed16))  # Py2/3 safe

    if hasattr(socket, 'inet_ntop'):
        try:
            return socket.inet_ntop(socket.AF_INET6, b)
        except Exception:
            pass

    # Manual formatting with :: compression
    hextets = []
    ba = bytearray(packed16)
    for i in range(0, 16, 2):
        hextets.append((ba[i] << 8) | ba[i + 1])

    # Find longest run of zeros (length >= 2) for compression
    best_start = -1
    best_len = 0
    cur_start = -1
    cur_len = 0
    for i, h in enumerate(hextets):
        if h == 0:
            if cur_start == -1:
                cur_start = i
                cur_len = 1
            else:
                cur_len += 1
        else:
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
            cur_start, cur_len = -1, 0
    if cur_len > best_len:
        best_start, best_len = cur_start, cur_len

    if best_len < 2:
        best_start = -1
        best_len = 0

    parts = []
    i = 0
    while i < 8:
        if i == best_start:
            parts.append('')
            i += best_len
            if i >= 8:
                parts.append('')
            continue
        parts.append('%x' % hextets[i])
        i += 1

    s = ':'.join(parts)
    # Normalize possible leading/trailing single colon cases
    if s.startswith(':') and not s.startswith('::'):
        s = ':' + s
    if s.endswith(':') and not s.endswith('::'):
        s = s + ':'
    if s == '':
        s = '::'
    return s


def _type_name_from_code(code):
    for k, v in QTYPE.items():
        if v == code:
            return k
    return "TYPE%d" % code


def rr_to_strings(msg, rr):
    """
    Convert one RR into one or more human-readable lines.
    """
    rtype = rr['type']
    ttl = rr['ttl']
    rdata = rr['rdata']
    tname = _type_name_from_code(rtype)

    # A
    if rtype == QTYPE['A'] and rr['rdlength'] == 4:
        ip = "%d.%d.%d.%d" % tuple(bytearray(rdata))
        return ["A: %s (TTL=%d)" % (ip, ttl)]

    # AAAA
    if rtype == QTYPE['AAAA'] and rr['rdlength'] == 16:
        ip6 = _ipv6_to_str(rdata)
        return ["AAAA: %s (TTL=%d)" % (ip6, ttl)]

    # CNAME / NS: domain name in rdata
    if rtype in (QTYPE['CNAME'], QTYPE['NS']):
        target, _ = decode_domain_name(msg, rr['rdata_offset'])
        return ["%s: %s (TTL=%d)" % (tname, target, ttl)]

    # MX: preference + exchange name
    if rtype == QTYPE['MX']:
        if rr['rdlength'] < 3:
            return []
        pref = struct.unpack('!H', rdata[:2])[0]
        exchange, _ = decode_domain_name(msg, rr['rdata_offset'] + 2)
        return ["MX: preference=%d exchange=%s (TTL=%d)" % (pref, exchange, ttl)]

    # TXT: one or more chunks
    if rtype == QTYPE['TXT']:
        chunks = decode_txt_rdata(rdata)
        return ["TXT: %s (TTL=%d)" % (c, ttl) for c in chunks]

    # Other types (shown only if user requests show-all or includes other sections)
    return ["%s: rdlength=%d (TTL=%d)" % (tname, rr['rdlength'], ttl)]


def _hex_dump(b):
    if hasattr(b, "hex"):  # Py3.5+
        return b.hex()
    return "".join("%02x" % ord(c) for c in b)  # Py2


def _recvn(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def query_udp(dns_server, query, port, timeout):
    last_err = None
    for sockaddr in _iter_server_addrs(dns_server, port):
        fam = socket.AF_INET6 if len(sockaddr) == 4 else socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.settimeout(float(timeout))
        try:
            sock.sendto(query, sockaddr)
            msg, _ = sock.recvfrom(4096)
            return msg
        except Exception as e:
            last_err = e
        finally:
            sock.close()
    raise last_err if last_err else RuntimeError("UDP query failed for all addresses")


def query_tcp(dns_server, query, port, timeout):
    last_err = None
    for sockaddr in _iter_server_addrs(dns_server, port):
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
            return msg
        except Exception as e:
            last_err = e
        finally:
            sock.close()
    raise last_err if last_err else RuntimeError("TCP query failed for all addresses")


def decode_dns_message(msg, wanted_type=None, show_all=False,
                       include_authority=False, include_additional=False,
                       verbose=True):
    """
    Decode a DNS message and return:
      (records, truncated_flag, header_dict)

    Filtering:
      - If show_all=False and wanted_type is set, only returns matching RR types.
      - If show_all=True, returns all RR types included by chosen sections.
    Sections:
      - Answers always parsed
      - Authority parsed if include_authority
      - Additional parsed if include_additional
    """
    if len(msg) < 12:
        raise ValueError("Incomplete DNS header")

    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', msg[:12])

    tc = bool(flags & 0x0200)          # Truncation
    rcode = flags & 0x000F

    if verbose:
        print("Transaction ID: %04x" % tid)
        print("Flags: %04x" % flags)
        print("Questions: %d" % qdcount)
        print("Answer RRs: %d" % ancount)
        print("Authority RRs: %d" % nscount)
        print("Additional RRs: %d" % arcount)
        if rcode != 0:
            print("DNS error rcode=%d" % rcode)
        if tc:
            print("Note: TC=1 (UDP response truncated)")

    offset = 12
    offset = skip_question_section(msg, offset, qdcount)

    def collect(section_name, count, offset):
        out = []
        for _ in range(count):
            rr, offset2 = parse_rr(msg, offset)
            offset = offset2

            if wanted_type is not None and (not show_all) and rr['type'] != wanted_type:
                continue

            lines = rr_to_strings(msg, rr)
            if lines:
                if verbose and section_name:
                    # Optional: prefix section name
                    # Keep output clean: only prefix for non-answer sections
                    if section_name != "ANSWER":
                        lines = ["%s: %s" % (section_name, ln) for ln in lines]
                out.extend(lines)
        return out, offset

    records = []

    # Answers
    ans_records, offset = collect("ANSWER", ancount, offset)
    records.extend(ans_records)

    # Authority
    if include_authority:
        auth_records, offset = collect("AUTHORITY", nscount, offset)
        records.extend(auth_records)
    else:
        # Skip authority RRs
        for _ in range(nscount):
            _, offset = parse_rr(msg, offset)

    # Additional
    if include_additional:
        add_records, offset = collect("ADDITIONAL", arcount, offset)
        records.extend(add_records)
    else:
        # Skip additional RRs
        for _ in range(arcount):
            _, offset = parse_rr(msg, offset)

    return records, tc, {
        'tid': tid,
        'flags': flags,
        'qdcount': qdcount,
        'ancount': ancount,
        'nscount': nscount,
        'arcount': arcount,
        'rcode': rcode,
        'tc': tc,
    }


def perform_dns_query(dns_server, domain, record_type='A',
                      port=53, timeout=2,
                      tcp_fallback=True,
                      show_all=False,
                      include_authority=False,
                      include_additional=False,
                      verbose=True):
    record_type = record_type.strip().upper()
    if record_type not in QTYPE:
        raise ValueError("Unsupported record type: %r (use %s)" %
                         (record_type, ", ".join(sorted(QTYPE.keys()))))

    query = build_dns_query(domain, record_type)

    # UDP first
    msg = query_udp(dns_server, query, port, timeout)
    if verbose:
        print("Raw UDP response: %s" % _hex_dump(msg))

    wanted_type = QTYPE[record_type]
    records, truncated, _ = decode_dns_message(
        msg,
        wanted_type=wanted_type,
        show_all=show_all,
        include_authority=include_authority,
        include_additional=include_additional,
        verbose=verbose
    )

    # TCP fallback if truncated
    if truncated and tcp_fallback:
        if verbose:
            print("Retrying over TCP due to truncation...")
        msg2 = query_tcp(dns_server, query, port, timeout)
        if verbose:
            print("Raw TCP response: %s" % _hex_dump(msg2))
        records, _, _ = decode_dns_message(
            msg2,
            wanted_type=wanted_type,
            show_all=show_all,
            include_authority=include_authority,
            include_additional=include_additional,
            verbose=verbose
        )

    return records


def main():
    parser = argparse.ArgumentParser(
        description="DNS Query Script (Python 2/3): A/AAAA/MX/CNAME/NS/TXT, TCP fallback, optional authority/additional"
    )
    parser.add_argument('--dns-server', type=str,
    help='DNS server address (IPv4, IPv6, IPv6%zone, or hostname; e.g. 8.8.8.8, ::1, fe80::1%wlan0, localhost)')
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
                        help='Also parse/show Authority section (NSCOUNT)')
    parser.add_argument('--include-additional', action='store_true',
                        help='Also parse/show Additional section (ARCOUNT)')
    parser.add_argument('--quiet', action='store_true', help='Less header/debug output')
    parser.add_argument('--prefer-ipv4', action='store_true',
                    help='Prefer IPv4 addresses first when --dns-server is a hostname')
    parser.add_argument('--prefer-ipv6', action='store_true',
                    help='Prefer IPv6 addresses first when --dns-server is a hostname (default)')
    args = parser.parse_args()

    # Python 2 input compatibility
    try:
        _input = raw_input  # noqa
    except NameError:
        _input = input

    dns_server = args.dns_server or _input("Enter the DNS server IP (e.g., 8.8.8.8): ")
    domain = args.domain or _input("Enter the domain to look up (e.g., example.com): ")
    record_type = (args.record_type or _input("Enter the record type (A, AAAA, MX, CNAME, NS, TXT): ")).strip().upper()

    verbose = (not args.quiet)

    # Default preference is IPv6 first (unless user prefers IPv4)
    prefer_ipv6 = True
    if args.prefer_ipv4:
        prefer_ipv6 = False
    if args.prefer_ipv6:
        prefer_ipv6 = True


    try:
        records = perform_dns_query(
            dns_server=dns_server,
            domain=domain,
            record_type=record_type,
            port=args.port,
            timeout=args.timeout,
            tcp_fallback=(not args.no_tcp_fallback),
            show_all=args.show_all,
            include_authority=args.include_authority,
            include_additional=args.include_additional,
            verbose=verbose,
            prefer_ipv6=prefer_ipv6,
        )

        if records:
            label = ("records" if args.show_all else ("%s records" % record_type))
            print("The %s for %s are:" % (label, domain))
            for r in records:
                print(r)
        else:
            if args.show_all:
                print("No records found for %s." % domain)
            else:
                print("No %s records found for %s." % (record_type, domain))

    except socket.timeout:
        print("Error: DNS query timed out.")
        sys.exit(1)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

