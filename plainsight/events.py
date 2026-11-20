"""Finding: one thing an eavesdropper learned from the traffic."""
from __future__ import annotations

import itertools
import threading
import time
from collections import Counter
from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "info")

_ids = itertools.count(1)


@dataclass
class Finding:
    protocol: str
    kind: str  # credential, session, token, url, dns, sni, email, command, file, form, upgrade
    severity: str
    title: str
    src: str = ""
    dst: str = ""
    secrets: dict[str, str] = field(default_factory=dict)
    details: dict[str, str] = field(default_factory=dict)
    excerpt: str = ""
    # True when the data travelled over TLS and was decrypted by a MITM proxy.
    encrypted_channel: bool = False
    # Findings with the same non-empty dedup key are only reported once.
    dedup: str = ""
    ts: float = field(default_factory=time.time)
    id: int = field(default_factory=lambda: next(_ids))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts,
            "protocol": self.protocol,
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "src": self.src,
            "dst": self.dst,
            "secrets": dict(self.secrets),
            "details": dict(self.details),
            "excerpt": self.excerpt,
            "encrypted_channel": self.encrypted_channel,
        }


class Stats:
    """Traffic counters shown on the dashboard. Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.packets = 0
        self.bytes = 0
        self.sessions: Counter[str] = Counter()
        self.encrypted_sessions = 0
        self.plaintext_sessions = 0
        self.dns_queries = 0
        self.mitm_flows = 0

    def add_packet(self, size: int) -> None:
        with self._lock:
            self.packets += 1
            self.bytes += size

    def add_session(self, protocol: str, encrypted: bool | None) -> None:
        """encrypted=None means the protocol is unknown to us."""
        with self._lock:
            self.sessions[protocol] += 1
            if encrypted is True:
                self.encrypted_sessions += 1
            elif encrypted is False:
                self.plaintext_sessions += 1

    def add(self, name: str, n: int = 1) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + n)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "packets": self.packets,
                "bytes": self.bytes,
                "sessions": dict(self.sessions),
                "encrypted_sessions": self.encrypted_sessions,
                "plaintext_sessions": self.plaintext_sessions,
                "dns_queries": self.dns_queries,
                "mitm_flows": self.mitm_flows,
            }
