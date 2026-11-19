from __future__ import annotations

import base64
import re

from ..events import Finding


def b64text(s: str) -> str:
    """Decode base64 leniently; returns '' if it is not base64."""
    s = s.strip()
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except ValueError:
        return ""
    return raw.decode("utf-8", "replace")


def host_of(endpoint: str) -> str:
    """'1.2.3.4:80' -> '1.2.3.4', '[::1]:80' -> '::1'."""
    host = endpoint.rsplit(":", 1)[0]
    return host[1:-1] if host.startswith("[") else host


class StreamAnalyzer:
    """Receives the reassembled bytes of one TCP connection."""

    protocol = "TCP"
    # True: payload is encrypted, False: plaintext, None: unknown protocol.
    encrypted: bool | None = False

    def __init__(self, client: str, server: str) -> None:
        self.client = client
        self.server = server

    def on_client(self, data: bytes) -> list[Finding]:
        return []

    def on_server(self, data: bytes) -> list[Finding]:
        return []

    def finding(self, **kw) -> Finding:
        kw.setdefault("protocol", self.protocol)
        return Finding(src=self.client, dst=self.server, **kw)


class NullAnalyzer(StreamAnalyzer):
    protocol = "其他"
    encrypted = None


STARTTLS_RE = re.compile(r"^(?:\S+\s+)?(?:STARTTLS|STLS|AUTH\s+TLS|AUTH\s+SSL)\s*$", re.I)


class LineAnalyzer(StreamAnalyzer):
    """Base for line-oriented protocols (FTP, SMTP, POP3, IMAP)."""

    MAX_LINE = 8192
    in_data = False  # inside a message body, where commands are not commands

    def __init__(self, client: str, server: str) -> None:
        super().__init__(client, server)
        self._buf = {True: b"", False: b""}
        self.upgraded = False

    def on_client(self, data: bytes) -> list[Finding]:
        return self._feed(True, data)

    def on_server(self, data: bytes) -> list[Finding]:
        return self._feed(False, data)

    def _feed(self, is_client: bool, data: bytes) -> list[Finding]:
        if self.upgraded:  # the rest of the connection is TLS
            return []
        buf = self._buf[is_client] + data
        out: list[Finding] = []
        while not self.upgraded:
            i = buf.find(b"\n")
            if i < 0:
                break
            line, buf = buf[:i], buf[i + 1:]
            text = line.rstrip(b"\r").decode("utf-8", "replace")
            if is_client and not self.in_data and STARTTLS_RE.match(text):
                self.upgraded = True
                out.append(self.finding(
                    kind="upgrade", severity="info",
                    title=f"{self.protocol} 連線升級為 TLS 加密（{text.strip()}）",
                    excerpt=text,
                ))
                break
            out.extend(self.client_line(text) if is_client else self.server_line(text))
        self._buf[is_client] = buf[-self.MAX_LINE:]
        return out

    def client_line(self, line: str) -> list[Finding]:
        return []

    def server_line(self, line: str) -> list[Finding]:
        return []

    def credential(self, user: str, password: str, excerpt: str, how: str = "", **extra) -> Finding:
        secrets = {"username": user, "password": password, **extra}
        details = {"伺服器": self.server}
        if how:
            details["驗證方式"] = how
        return self.finding(
            kind="credential", severity="critical",
            title=f"{self.protocol} 明文帳號密碼：{user or '(未知帳號)'}",
            secrets=secrets, details=details, excerpt=excerpt,
            dedup=f"cred|{self.protocol}|{self.server}|{user}|{password}",
        )
