"""Glue between Scapy packets and the Engine."""
from __future__ import annotations

import threading
import time

from .engine import Engine


def feed_packet(engine: Engine, pkt) -> None:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Padding

    if IP in pkt:
        ip = pkt[IP]
        if ip.frag or ip.flags.MF:  # fragments are rare for the protocols we read
            return
    elif IPv6 in pkt:
        ip = pkt[IPv6]
    else:
        return
    l4 = ip.payload
    # `type() is` rather than `in`: ICMP errors embed a quoted TCP/UDP header.
    if type(l4) not in (TCP, UDP):
        return
    payload = bytes(l4.payload)
    pad = l4.getlayer(Padding)
    if pad is not None:  # Ethernet trailer, not application data
        payload = payload[:len(payload) - len(bytes(pad))]
    if type(l4) is TCP:
        engine.feed_tcp(ip.src, l4.sport, ip.dst, l4.dport, l4.seq, int(l4.flags), payload)
    else:
        engine.feed_udp(ip.src, l4.sport, ip.dst, l4.dport, payload)


def _load_layers() -> None:
    # Scapy picks the link-layer decoder when a reader/socket is opened, from
    # whatever layers are imported at that moment. Without these, every packet
    # is decoded as Raw and nothing is found.
    import scapy.layers.inet  # noqa: F401
    import scapy.layers.inet6  # noqa: F401
    import scapy.layers.l2  # noqa: F401


def read_pcap(engine: Engine, path: str, realtime: bool = False,
              stop: threading.Event | None = None) -> int:
    _load_layers()
    from scapy.utils import PcapReader

    count = 0
    last = None
    with PcapReader(path) as reader:
        for pkt in reader:
            if stop is not None and stop.is_set():
                break
            if realtime and last is not None:
                time.sleep(min(max(float(pkt.time - last), 0), 2.0))
            last = pkt.time
            feed_packet(engine, pkt)
            count += 1
    return count


def sniff_live(engine: Engine, iface: str | None, bpf: str | None) -> None:
    _load_layers()
    from scapy.sendrecv import sniff

    sniff(iface=iface, filter=bpf, prn=lambda p: feed_packet(engine, p), store=False)
