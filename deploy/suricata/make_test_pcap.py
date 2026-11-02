"""Test pcap: HTTP orqali bitta setup.exe (PE) yuklanishi. Root/tcpdump talab qilmaydi.

usage: python3 make_test_pcap.py <out.pcap>   (stdout: faylning sha256)
"""
import struct, sys, time

out = sys.argv[1]
body = b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + bytes(range(256)) * 8
CLI, SRV = (bytes([10, 254, 1, 50]), 51000), (bytes([93, 184, 216, 34]), 80)


def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def pkt(src, dst, seq, ack, flags, payload=b""):
    sip, sport = src
    dip, dport = dst
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = sip + dip + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, sip, dip)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip + tcp


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
req = b"GET /setup.exe HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: "
        + str(len(body)).encode() + b"\r\nContent-Disposition: attachment; filename=\"setup.exe\"\r\n\r\n" + body)
c, s = 1000, 5000
pkts = [
    pkt(CLI, SRV, c, 0, SYN),
    pkt(SRV, CLI, s, c + 1, SYN | ACK),
    pkt(CLI, SRV, c + 1, s + 1, ACK),
    pkt(CLI, SRV, c + 1, s + 1, PSH | ACK, req),
    pkt(SRV, CLI, s + 1, c + 1 + len(req), ACK),
]
off = 0
while off < len(resp):
    chunk = resp[off:off + 1400]
    pkts.append(pkt(SRV, CLI, s + 1 + off, c + 1 + len(req), PSH | ACK, chunk))
    off += len(chunk)
pkts.append(pkt(CLI, SRV, c + 1 + len(req), s + 1 + len(resp), ACK))
pkts.append(pkt(SRV, CLI, s + 1 + len(resp), c + 1 + len(req), FIN | ACK))
pkts.append(pkt(CLI, SRV, c + 1 + len(req), s + 2 + len(resp), FIN | ACK))
pkts.append(pkt(SRV, CLI, s + 2 + len(resp), c + 2 + len(req), ACK))

with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    t = int(time.time())
    for i, p in enumerate(pkts):
        f.write(struct.pack("<IIII", t, i * 1000, len(p), len(p)) + p)
import hashlib
print(hashlib.sha256(body).hexdigest())
