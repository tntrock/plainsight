"""Packet sources: pcap files and live capture, fed into the Engine.

Live capture has two backends:
- "npcap": Scapy + libpcap (Npcap on Windows). Sees Ethernet frames, IPv4 and
  IPv6, supports BPF filters.
- "rawsocket": Windows' built-in raw sockets (SIO_RCVALL). Needs no driver
  install, only administrator rights; IPv4 only.
"""
from __future__ import annotations

import os
import select
import socket
import sys
import threading
import time

from .engine import Engine

NPCAP_DLL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll")


def npcap_installed() -> bool:
    """True where libpcap is usable (always assumed outside Windows)."""
    return sys.platform != "win32" or os.path.exists(NPCAP_DLL)


def is_admin() -> bool:
    if sys.platform == "win32":
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False
    return os.geteuid() == 0


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


def sniff_live(engine: Engine, ifaces: list[str] | None, bpf: str | None) -> None:
    """Capture on one or several interfaces (None = system default)."""
    _load_layers()
    from scapy.sendrecv import sniff

    iface = ifaces[0] if ifaces and len(ifaces) == 1 else (ifaces or None)
    sniff(iface=iface, filter=bpf, prn=lambda p: feed_packet(engine, p), store=False)


def open_raw_sockets(ips: list[str]) -> list[socket.socket]:
    """One promiscuous raw IPv4 socket per local address (Windows only, needs admin)."""
    socks = []
    try:
        for ip in ips:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            socks.append(s)
            s.bind((ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # every packet through this NIC, both directions
    except OSError:
        for s in socks:
            s.close()
        raise
    return socks


def sniff_raw(engine: Engine, socks: list[socket.socket], stop: threading.Event | None = None) -> None:
    _load_layers()
    from scapy.layers.inet import IP

    try:
        while stop is None or not stop.is_set():
            ready, _, _ = select.select(socks, [], [], 0.5)  # timeout keeps Ctrl+C responsive
            for s in ready:
                try:
                    data = s.recv(65535)
                except OSError:
                    continue
                if data and data[0] >> 4 == 4:
                    feed_packet(engine, IP(data))
    finally:
        for s in socks:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except (OSError, AttributeError):  # AttributeError: not Windows (tests)
                pass
            s.close()
