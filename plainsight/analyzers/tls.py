"""TLS: the content is encrypted, but the ClientHello still leaks the domain (SNI)."""
from __future__ import annotations

import os
import struct

from ..events import Finding
from .base import StreamAnalyzer, host_of

EXT_SNI, EXT_ALPN, EXT_SUPPORTED_VERSIONS, EXT_ECH = 0, 16, 43, 0xFE0D
MAX_RECORD = 16384 + 2048


def looks_like_tls(data: bytes) -> bool:
    return len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03


def parse_client_hello(hs: bytes) -> dict | None:
    """Parse a handshake message; returns {'sni', 'alpn', 'tls13', 'ech'} or None."""
    try:
        if hs[0] != 1:  # not a ClientHello
            return None
        p = 4 + 2 + 32  # header, legacy_version, random
        p += 1 + hs[p]  # session id
        p += 2 + struct.unpack_from("!H", hs, p)[0]  # cipher suites
        p += 1 + hs[p]  # compression methods
        if p + 2 > len(hs):
            return {"sni": "", "alpn": [], "tls13": False, "ech": False}
        end = p + 2 + struct.unpack_from("!H", hs, p)[0]
        p += 2
        info = {"sni": "", "alpn": [], "tls13": False, "ech": False}
        while p + 4 <= end:
            etype, elen = struct.unpack_from("!HH", hs, p)
            body = hs[p + 4:p + 4 + elen]
            p += 4 + elen
            if etype == EXT_SNI and len(body) >= 5 and body[2] == 0:
                nlen = struct.unpack_from("!H", body, 3)[0]
                info["sni"] = body[5:5 + nlen].decode("ascii", "replace")
            elif etype == EXT_ALPN and len(body) >= 2:
                q = 2
                while q < len(body):
                    n = body[q]
                    info["alpn"].append(body[q + 1:q + 1 + n].decode("ascii", "replace"))
                    q += 1 + n
            elif etype == EXT_SUPPORTED_VERSIONS:
                info["tls13"] = b"\x03\x04" in body
            elif etype == EXT_ECH:
                info["ech"] = True
        return info
    except (IndexError, struct.error):
        return None


def build_client_hello(sni: str, alpn: tuple[str, ...] = ("h2", "http/1.1")) -> bytes:
    """A minimal but valid TLS 1.3 ClientHello record (used by tests)."""
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", EXT_SNI, len(name) + 5, len(name) + 3, 0, len(name)) + name
    protos = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
    alpn_ext = struct.pack("!HHH", EXT_ALPN, len(protos) + 2, len(protos)) + protos
    sv_ext = struct.pack("!HHB", EXT_SUPPORTED_VERSIONS, 3, 2) + b"\x03\x04"
    exts = sni_ext + alpn_ext + sv_ext
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
            + b"\x00\x04\x13\x01\x13\x02" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


class TlsAnalyzer(StreamAnalyzer):
    protocol = "TLS"
    encrypted = True

    def __init__(self, client: str, server: str) -> None:
        super().__init__(client, server)
        self.buf = b""
        self.done = False

    def on_client(self, data: bytes) -> list[Finding]:
        if self.done:
            return []
        self.buf += data
        if len(self.buf) < 5:
            return []
        if not looks_like_tls(self.buf):
            self.done = True
            return []
        rec_len = struct.unpack_from("!H", self.buf, 3)[0]
        if len(self.buf) < 5 + rec_len:
            if len(self.buf) > MAX_RECORD:
                self.done = True
            return []
        self.done = True
        info = parse_client_hello(self.buf[5:5 + rec_len])
        self.buf = b""
        if not info or not info["sni"]:
            return []
        sni = info["sni"]
        details = {
            "SNI 網域": sni,
            "伺服器": self.server,
            "TLS 1.3": "是" if info["tls13"] else "否",
        }
        if info["alpn"]:
            details["ALPN"] = ", ".join(info["alpn"])
        if info["ech"]:
            details["ECH"] = "有（此 SNI 可能只是外層公開名稱）"
        return [self.finding(
            kind="sni", severity="info",
            title=f"加密連線，但網域外洩：{sni}",
            details=details, excerpt=f"TLS ClientHello → server_name = {sni}",
            dedup=f"sni|{host_of(self.client)}|{sni}",
        )]
