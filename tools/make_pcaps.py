"""Generate tiny deterministic pcaps that trigger the lab Suricata rules (packets are built with Scapy).

  python -m tools.make_pcaps rules/pcaps_out

Each pcap contains one complete TCP session (handshake, request, response, FIN) or one UDP DNS query. Scapy fills in
the IPv4/TCP/UDP lengths and checksums, so Suricata's stream and app-layer engines treat it like real traffic.
(Replaces ~90 lines of hand-rolled struct/checksum code; Scapy is the standard tool for crafting packets.)
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

CLIENT = ("02:00:00:00:00:01", "10.42.0.50")
SERVER = ("02:00:00:00:00:02", "10.42.0.10")
T0 = 1_760_000_000  # fixed capture time -> byte-identical pcaps on every run


def _l3(to_server: bool, ident: int) -> Packet:
    (smac, sip), (dmac, dip) = (CLIENT, SERVER) if to_server else (SERVER, CLIENT)
    return Ether(src=smac, dst=dmac) / IP(src=sip, dst=dip, id=ident, flags="DF", ttl=64)


def http_session(request: bytes, response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") -> list[Packet]:
    sport, dport, cseq, sseq = 40000, 80, 1000, 5000
    n, m = len(request), len(response)

    def seg(to_server: bool, flags: str, seq: int, ack: int, payload: bytes = b"") -> Packet:
        src, dst = (sport, dport) if to_server else (dport, sport)
        pkt = _l3(to_server, ident=len(frames) + 1) / TCP(sport=src, dport=dst, flags=flags, seq=seq, ack=ack, window=64240)
        return pkt / Raw(payload) if payload else pkt

    frames: list[Packet] = []
    for args in (
        (True, "S", cseq, 0),                                    # SYN
        (False, "SA", sseq, cseq + 1),                           # SYN/ACK
        (True, "A", cseq + 1, sseq + 1),                         # ACK
        (True, "PA", cseq + 1, sseq + 1, request),               # request
        (False, "A", sseq + 1, cseq + 1 + n),                    # ACK
        (False, "PA", sseq + 1, cseq + 1 + n, response),         # response
        (True, "FA", cseq + 1 + n, sseq + 1 + m),                # FIN
        (False, "FA", sseq + 1 + m, cseq + 2 + n),               # FIN
        (True, "A", cseq + 2 + n, sseq + 2 + m),                 # last ACK
    ):
        frames.append(seg(*args))
    return frames


def dns_query(name: str) -> list[Packet]:
    return [_l3(True, ident=1) / UDP(sport=41000, dport=53) / DNS(id=0x1234, rd=1, qd=DNSQR(qname=name))]


def http_get(uri: str, ua: str = "curl/8.5.0") -> bytes:
    return f"GET {uri} HTTP/1.1\r\nHost: lab.test\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n".encode()


PCAPS: dict[str, Callable[[], list[Packet]]] = {
    "traversal.pcap": lambda: http_session(http_get("/download?file=../../etc/passwd")),
    "sqlmap.pcap": lambda: http_session(http_get("/index.php?id=1", ua="sqlmap/1.7.2#stable (https://sqlmap.org)")),
    "dns_c2.pcap": lambda: dns_query("beacon.lab-c2.test"),
    "benign.pcap": lambda: http_session(http_get("/index.html")) + dns_query("example.com"),
}


def write_pcap(path: Path, frames: list[Packet], t0: int = T0) -> None:
    for i, frame in enumerate(frames):
        frame.time = t0 + i * 0.001
    wrpcap(str(path), frames)


def main(argv: list[str]) -> int:
    out = Path(argv[1] if len(argv) > 1 else "rules/pcaps_out")
    out.mkdir(parents=True, exist_ok=True)
    for name, make in PCAPS.items():
        write_pcap(out / name, make())
        print(f"wrote {out / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
