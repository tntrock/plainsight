"""Engine: tracks TCP connections and routes their bytes to protocol analyzers."""
from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Callable

from .analyzers import PORT_ANALYZERS, NullAnalyzer, StreamAnalyzer, sniff_analyzer
from .analyzers.dns import UDP_PORTS, parse_dns_query
from .events import Finding, Stats
from .stream import MASK, DirectionReassembler

log = logging.getLogger(__name__)

FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


def endpoint(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


class _Session:
    __slots__ = ("client", "server", "c2s", "s2c", "analyzer", "fins")

    def __init__(self, client: tuple[str, int], server: tuple[str, int]) -> None:
        self.client = client
        self.server = server
        self.c2s = DirectionReassembler()
        self.s2c = DirectionReassembler()
        self.analyzer: StreamAnalyzer | None = None
        self.fins: set[bool] = set()


class Engine:
    MAX_SESSIONS = 4096

    def __init__(self, emit: Callable[[Finding], object], stats: Stats | None = None) -> None:
        self.emit = emit
        self.stats = stats or Stats()
        self.sessions: OrderedDict[tuple, _Session] = OrderedDict()

    # ---- TCP --------------------------------------------------------------
    def feed_tcp(self, src: str, sport: int, dst: str, dport: int,
                 seq: int, flags: int, payload: bytes) -> None:
        self.stats.add_packet(len(payload))
        a, b = (src, sport), (dst, dport)
        key = (a, b) if a < b else (b, a)
        sess = self.sessions.get(key)
        if sess is None:
            if flags & SYN:
                client, server = (b, a) if flags & ACK else (a, b)
            else:
                client, server = self._guess_roles(a, b)
            sess = self.sessions[key] = _Session(client, server)
            if len(self.sessions) > self.MAX_SESSIONS:
                self.sessions.popitem(last=False)
        else:
            self.sessions.move_to_end(key)

        from_client = a == sess.client
        stream = sess.c2s if from_client else sess.s2c
        if flags & SYN:
            stream.syn(seq)
            seq = (seq + 1) & MASK  # data on a SYN (TCP Fast Open) follows it
        data = stream.feed(seq, payload)
        if data:
            self._dispatch(sess, from_client, data)

        if flags & RST:
            self.sessions.pop(key, None)
        elif flags & FIN:
            sess.fins.add(from_client)
            if len(sess.fins) == 2:
                self.sessions.pop(key, None)

    @staticmethod
    def _guess_roles(a, b):
        """Mid-stream capture without a SYN: the well-known port is the server."""
        if b[1] in PORT_ANALYZERS and a[1] not in PORT_ANALYZERS:
            return a, b
        if a[1] in PORT_ANALYZERS and b[1] not in PORT_ANALYZERS:
            return b, a
        return (a, b) if a[1] >= b[1] else (b, a)

    def _dispatch(self, sess: _Session, from_client: bool, data: bytes) -> None:
        if sess.analyzer is None:
            factory = sniff_analyzer(data) if from_client else None
            if factory is None:
                factory = PORT_ANALYZERS.get(sess.server[1])
            if factory is None:
                if not from_client:
                    return  # unknown protocol: wait for the client to speak
                factory = NullAnalyzer
            sess.analyzer = factory(endpoint(*sess.client), endpoint(*sess.server))
            self.stats.add_session(sess.analyzer.protocol, sess.analyzer.encrypted)
        try:
            analyzer = sess.analyzer
            findings = analyzer.on_client(data) if from_client else analyzer.on_server(data)
        except Exception:
            log.exception("analyzer %s failed; ignoring rest of connection", type(sess.analyzer).__name__)
            sess.analyzer = NullAnalyzer(sess.analyzer.client, sess.analyzer.server)
            return
        for f in findings:
            self.emit(f)

    # ---- UDP --------------------------------------------------------------
    def feed_udp(self, src: str, sport: int, dst: str, dport: int, payload: bytes) -> None:
        self.stats.add_packet(len(payload))
        proto = UDP_PORTS.get(dport)
        if not proto:
            return
        q = parse_dns_query(payload)
        if not q or not q[0]:
            return
        name, qtype = q
        self.stats.add("dns_queries")
        self.emit(Finding(
            protocol=proto, kind="dns", severity="info",
            title=f"{proto} 查詢：{name}",
            src=endpoint(src, sport), dst=endpoint(dst, dport),
            details={"查詢網域": name, "類型": qtype, "DNS 伺服器": dst},
            excerpt=f"{proto} query  {name}  {qtype}",
            dedup=f"dns|{src}|{name}|{qtype}",
        ))
