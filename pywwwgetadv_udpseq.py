
# pywwwgetadv_udpseq.py
# Lightweight sequence-numbered UDP transfer with optional retransmit
# Compatible with Python 2 & 3, same high-level API style as pywwwgetadv

from __future__ import absolute_import, division, print_function
import socket, struct, time, sys, os

# ---- UDP SEQ PROTOCOL ----
# Header: magic(4) ver(1) flags(1) seq(u32) total(u32)
# flags: 0x01=data, 0x02=done, 0x04=ack
_MAGIC = b"PWGS"
_VER = 1
_HDR = "!4sBBII"
_HDR_LEN = struct.calcsize(_HDR)

FLAG_DATA = 0x01
FLAG_DONE = 0x02
FLAG_ACK  = 0x04

DEFAULT_CHUNK = 1024

def _now():
    return time.time()

def _send(sock, pkt, addr=None):
    if addr:
        sock.sendto(pkt, addr)
    else:
        sock.send(pkt)

def udp_send_fileobj(fileobj, host, port, chunk=DEFAULT_CHUNK, retries=5, window=8, timeout=0.5, progress=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    addr = (host, int(port))
    seq = 0
    inflight = {}
    eof = False
    sent_bytes = 0

    try:
        while not eof or inflight:
            # fill window
            while not eof and len(inflight) < window:
                data = fileobj.read(chunk)
                if not data:
                    eof = True
                    break
                hdr = struct.pack(_HDR, _MAGIC, _VER, FLAG_DATA, seq, 0)
                pkt = hdr + data
                _send(sock, pkt, addr)
                inflight[seq] = (_now(), pkt, 0)
                sent_bytes += len(data)
                seq += 1

            # send DONE when eof and nothing new to queue
            if eof and not inflight:
                done = struct.pack(_HDR, _MAGIC, _VER, FLAG_DONE, seq, sent_bytes)
                for _ in range(3):
                    _send(sock, done, addr)
                break

            # wait for ACKs
            try:
                data, _ = sock.recvfrom(1024)
            except socket.timeout:
                # retransmit timed-out packets
                for s,(t,p,c) in list(inflight.items()):
                    if _now() - t > timeout:
                        if c < retries:
                            _send(sock, p, addr)
                            inflight[s] = (_now(), p, c+1)
                        else:
                            raise IOError("UDP retransmit limit reached")
                continue

            if len(data) >= _HDR_LEN:
                magic, ver, flags, aseq, total = struct.unpack(_HDR, data[:_HDR_LEN])
                if magic == _MAGIC and flags & FLAG_ACK:
                    inflight.pop(aseq, None)
                    if progress:
                        sys.stdout.write("\rSent %d bytes" % sent_bytes)
                        sys.stdout.flush()
    finally:
        sock.close()
    return sent_bytes

def udp_recv_to_file(bind, port, outfile, timeout=1.0, progress=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, int(port)))
    sock.settimeout(timeout)

    expected = 0
    received = {}
    total = None

    try:
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                if total is not None and expected >= total:
                    break
                continue

            if len(data) < _HDR_LEN:
                continue
            magic, ver, flags, seq, ttotal = struct.unpack(_HDR, data[:_HDR_LEN])
            if magic != _MAGIC:
                continue

            if flags & FLAG_DATA:
                payload = data[_HDR_LEN:]
                if seq not in received:
                    received[seq] = payload
                    # send ACK
                    ack = struct.pack(_HDR, _MAGIC, _VER, FLAG_ACK, seq, 0)
                    sock.sendto(ack, addr)

                # write in order
                while expected in received:
                    chunk = received.pop(expected)
                    outfile.write(chunk)
                    expected += 1
                    if progress:
                        sys.stdout.write("\rRecv chunks: %d" % expected)
                        sys.stdout.flush()

            elif flags & FLAG_DONE:
                total = expected
                break
    finally:
        sock.close()
    return expected

__all__ = ["udp_send_fileobj", "udp_recv_to_file"]
