"""Generate tiny deterministic pcaps (stdlib only) that trigger the lab Suricata rules.

  python -m tools.make_pcaps rules/pcaps_out

Each pcap contains one complete TCP session (handshake, request, response, FIN) or one UDP DNS query, with valid
IPv4/TCP/UDP checksums, so Suricata's stream and app-layer engines treat it like real traffic.
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

CLIENT_MAC, SERVER_MAC = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")
CLIENT_IP, SERVER_IP = "10.42.0.50", "10.42.0.10"


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
    return hdr + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def _tcp(src, dst, sport, dport, seq, ack, flags, payload=b"", ident=1) -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
    cs = _csum(_pseudo(src, dst, 6, len(seg)) + seg)
    seg = seg[:16] + struct.pack("!H", cs) + seg[18:]
    return _ip(src, dst, 6, seg, ident)


def _udp(src, dst, sport, dport, payload, ident=1) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    cs = _csum(_pseudo(src, dst, 17, len(seg)) + seg) or 0xFFFF
    seg = seg[:6] + struct.pack("!H", cs) + seg[8:]
    return _ip(src, dst, 17, seg, ident)


def _eth(ip_pkt: bytes, to_server: bool) -> bytes:
    dst, src = (SERVER_MAC, CLIENT_MAC) if to_server else (CLIENT_MAC, SERVER_MAC)
    return dst + src + struct.pack("!H", 0x0800) + ip_pkt


def write_pcap(path: Path, frames: list[bytes], t0: int = 1_760_000_000) -> None:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", t0, i * 1000, len(f), len(f)) + f
    path.write_bytes(out)


def http_session(request: bytes, response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") -> list[bytes]:
    c, s, sp, dp = CLIENT_IP, SERVER_IP, 40000, 80
    cseq, sseq = 1000, 5000
    f = []
    f.append(_eth(_tcp(c, s, sp, dp, cseq, 0, 0x02, ident=1), True))                              # SYN
    f.append(_eth(_tcp(s, c, dp, sp, sseq, cseq + 1, 0x12, ident=2), False))                       # SYN/ACK
    f.append(_eth(_tcp(c, s, sp, dp, cseq + 1, sseq + 1, 0x10, ident=3), True))                    # ACK
    f.append(_eth(_tcp(c, s, sp, dp, cseq + 1, sseq + 1, 0x18, request, ident=4), True))           # PSH/ACK request
    f.append(_eth(_tcp(s, c, dp, sp, sseq + 1, cseq + 1 + len(request), 0x10, ident=5), False))    # ACK
    f.append(_eth(_tcp(s, c, dp, sp, sseq + 1, cseq + 1 + len(request), 0x18, response, ident=6), False))
    f.append(_eth(_tcp(c, s, sp, dp, cseq + 1 + len(request), sseq + 1 + len(response), 0x11, ident=7), True))  # FIN
    f.append(_eth(_tcp(s, c, dp, sp, sseq + 1 + len(response), cseq + 2 + len(request), 0x11, ident=8), False))
    f.append(_eth(_tcp(c, s, sp, dp, cseq + 2 + len(request), sseq + 2 + len(response), 0x10, ident=9), True))
    return f


def dns_query(name: str) -> list[bytes]:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    return [_eth(_udp(CLIENT_IP, SERVER_IP, 41000, 53, query), True)]


def http_get(uri: str, ua: str = "curl/8.5.0") -> bytes:
    return f"GET {uri} HTTP/1.1\r\nHost: lab.test\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n".encode()


PCAPS = {
    "traversal.pcap": lambda: http_session(http_get("/download?file=../../etc/passwd")),
    "sqlmap.pcap": lambda: http_session(http_get("/index.php?id=1", ua="sqlmap/1.7.2#stable (https://sqlmap.org)")),
    "dns_c2.pcap": lambda: dns_query("beacon.lab-c2.test"),
    "benign.pcap": lambda: http_session(http_get("/index.html")) + dns_query("example.com"),
}


def main(argv: list[str]) -> int:
    out = Path(argv[1] if len(argv) > 1 else "rules/pcaps_out")
    out.mkdir(parents=True, exist_ok=True)
    for name, make in PCAPS.items():
        write_pcap(out / name, make())
        print(f"wrote {out / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
