"""HTTP/1.x: URLs, Basic auth, cookies, tokens and form posts."""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlsplit

from ..events import Finding
from .base import StreamAnalyzer, b64text, host_of
from .tls import TlsAnalyzer

_METHODS = rb"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)"
REQ_START = re.compile(_METHODS + rb" \S+ HTTP/\d")
RESP_START = re.compile(rb"HTTP/1\.[01] \d{3}")
MAX_BODY = 256 * 1024
MAX_EXCERPT = 3000

STATIC_EXT = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|css|js|mjs|map|woff2?|ttf|otf|webp|avif|mp4|webm)$", re.I)
PASS_KEY = re.compile(r"pass|pwd|secret|passcode|^pin$", re.I)
USER_KEY = re.compile(r"user|login|e-?mail|account|acct|^uid$|^name$|^id$", re.I)
TOKEN_KEY = re.compile(r"token|api[_-]?key|apikey|access[_-]?key|^auth|session|^sid$|jwt|^code$", re.I)


def looks_like_http_request(data: bytes) -> bool:
    return REQ_START.match(data) is not None


def _dechunk(data: bytes) -> tuple[bytes, int] | None:
    """Decode a chunked body. Returns (body, bytes consumed) or None if incomplete."""
    body = bytearray()
    p = 0
    while True:
        eol = data.find(b"\r\n", p)
        if eol < 0:
            return None
        try:
            size = int(data[p:eol].split(b";")[0], 16)
        except ValueError:
            return bytes(body), len(data)
        p = eol + 2
        if size == 0:
            end = data.find(b"\r\n", p)
            return (bytes(body), end + 2) if end >= 0 else None
        if len(data) < p + size + 2:
            return None
        body += data[p:p + size]
        p += size + 2


def _parse_head(head: bytes) -> tuple[str, list[tuple[str, str]]]:
    lines = head.decode("utf-8", "replace").replace("\r\n", "\n").split("\n")
    headers = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers.append((name.strip(), value.strip()))
    return lines[0], headers


def _flatten_json(obj, prefix: str = "") -> list[tuple[str, str]]:
    if isinstance(obj, dict):
        out = []
        for k, v in obj.items():
            out += _flatten_json(v, str(k))
        return out
    if isinstance(obj, list):
        return [kv for v in obj for kv in _flatten_json(v, prefix)]
    if obj is None or isinstance(obj, bool):
        return []
    return [(prefix, str(obj))]


def _multipart_fields(body: bytes) -> list[tuple[str, str]]:
    fields = []
    for m in re.finditer(rb'name="([^"]*)"(?:; filename="[^"]*")?\r\n(?:[^\r\n]+\r\n)*\r\n(.*?)\r\n--', body, re.S):
        fields.append((m.group(1).decode("utf-8", "replace"), m.group(2)[:200].decode("utf-8", "replace")))
    return fields


class HttpAnalyzer(StreamAnalyzer):
    protocol = "HTTP"

    def __init__(self, client: str, server: str, decrypted: bool = False) -> None:
        super().__init__(client, server)
        self.decrypted = decrypted
        if decrypted:
            self.protocol = "HTTPS"
        self.cbuf = b""
        self.sbuf = b""
        self.host = host_of(server)
        self.tunnel: TlsAnalyzer | None = None

    # ---- client -> server -------------------------------------------------
    def on_client(self, data: bytes) -> list[Finding]:
        if self.tunnel is not None:
            return self.tunnel.on_client(data)
        self.cbuf += data
        out: list[Finding] = []
        while True:
            m = REQ_START.search(self.cbuf)
            if not m:
                self.cbuf = self.cbuf[-256:]
                break
            if m.start():
                self.cbuf = self.cbuf[m.start():]
            end, sep = self.cbuf.find(b"\r\n\r\n"), 4
            if end < 0:
                end, sep = self.cbuf.find(b"\n\n"), 2
            if end < 0:
                if len(self.cbuf) > 65536:  # absurd header block: give up on it
                    self.cbuf = b""
                break
            request_line, headers = _parse_head(self.cbuf[:end])
            rest = self.cbuf[end + sep:]
            hdr = {k.lower(): v for k, v in headers}
            if "chunked" in hdr.get("transfer-encoding", "").lower():
                res = _dechunk(rest)
                if res is None:
                    if len(rest) < MAX_BODY:
                        break
                    res = rest[:MAX_BODY], len(rest)
                body, used = res
            else:
                try:
                    length = max(0, int(hdr.get("content-length", "0")))
                except ValueError:
                    length = 0
                if len(rest) < length:
                    if len(rest) < MAX_BODY:
                        break
                    length = len(rest)  # too large to wait for; analyze what we have
                body, used = rest[:length], length
            self.cbuf = rest[used:]
            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                continue
            method, target = parts[0].upper(), parts[1]
            head_text = self._head_text(request_line, headers)
            out += self.analyze_request(method, target, headers, body, head_text)
            if method == "CONNECT":
                # Everything after CONNECT is a TLS tunnel through the proxy.
                self.tunnel = TlsAnalyzer(self.client, target)
                rest, self.cbuf = self.cbuf, b""
                if rest:
                    out += self.tunnel.on_client(rest)
                break
        return out

    @staticmethod
    def _head_text(request_line: str, headers: list[tuple[str, str]]) -> str:
        return "\n".join([request_line] + [f"{k}: {v}" for k, v in headers])

    def analyze_request(self, method: str, target: str, headers: list[tuple[str, str]],
                        body: bytes, head_text: str) -> list[Finding]:
        hdr = {k.lower(): v for k, v in headers}
        host = hdr.get("host") or self.host
        scheme = "https" if self.decrypted else "http"
        if target.startswith(("http://", "https://")):  # request to a proxy
            url = target
            host = urlsplit(target).netloc or host
        else:
            url = f"{scheme}://{host}{target}"
        self.host = host
        body_text = body[:MAX_EXCERPT].decode("utf-8", "replace")
        excerpt = head_text + (f"\n\n{body_text}" if body else "")
        common = {"excerpt": excerpt[:MAX_EXCERPT], "encrypted_channel": self.decrypted}
        out: list[Finding] = []

        if method == "CONNECT":
            return [self.finding(
                kind="url", severity="info", title=f"透過代理伺服器建立加密通道：{target}",
                details={"方法": method, "目標": target}, **common,
            )]

        split = urlsplit(url)
        if not STATIC_EXT.search(split.path):
            details = {"方法": method, "網址": url}
            if "user-agent" in hdr:
                details["User-Agent"] = hdr["user-agent"]
            if "referer" in hdr:
                details["Referer"] = hdr["referer"]
            out.append(self.finding(
                kind="url", severity="info", title=f"{method} {url}", details=details,
                dedup=f"url|{host_of(self.client)}|{method}|{url}", **common,
            ))

        auth_scheme, _, cred = hdr.get("authorization", "").partition(" ")
        cred = cred.strip()
        if auth_scheme.lower() == "basic" and cred:
            user, _, password = b64text(cred).partition(":")
            out.append(self.finding(
                kind="credential", severity="critical",
                title=f"HTTP Basic 認證帳密：{user} @ {host}",
                secrets={"username": user, "password": password, "encoded": cred},
                details={"網址": url, "說明": "Base64 只是編碼，不是加密，任何人都能還原"},
                dedup=f"basic|{host}|{cred}", **common,
            ))
        elif auth_scheme.lower() == "bearer" and cred:
            out.append(self.finding(
                kind="token", severity="high", title=f"Bearer 存取權杖 @ {host}",
                secrets={"token": cred}, details={"網址": url},
                dedup=f"bearer|{host}|{cred}", **common,
            ))
        elif auth_scheme.lower() == "digest":
            m = re.search(r'username="([^"]*)"', cred)
            out.append(self.finding(
                kind="credential", severity="medium",
                title=f"HTTP Digest 認證 @ {host}（雜湊值，可離線暴力破解）",
                secrets={"username": m.group(1) if m else ""}, details={"網址": url},
                dedup=f"digest|{host}|{cred}", **common,
            ))

        cookie = hdr.get("cookie", "")
        if cookie:
            out.append(self.finding(
                kind="session", severity="high", title=f"送出 Cookie @ {host}（可用來冒用登入狀態）",
                secrets={"cookie": cookie}, details={"網址": url},
                dedup=f"cookie|{host}|{cookie}", **common,
            ))

        if body:
            ctype = hdr.get("content-type", "").lower()
            fields: list[tuple[str, str]] = []
            text = body.decode("utf-8", "replace")
            if "x-www-form-urlencoded" in ctype or (not ctype and "=" in text and "\n" not in text.strip()):
                fields = parse_qsl(text, keep_blank_values=True)
            elif "json" in ctype:
                try:
                    fields = _flatten_json(json.loads(text))
                except ValueError:
                    pass
            elif "multipart/form-data" in ctype:
                fields = _multipart_fields(body)
            out += self._fields(fields, url, host, "表單", common)

        if split.query:
            sensitive = [(k, v) for k, v in parse_qsl(split.query) if v and (PASS_KEY.search(k) or TOKEN_KEY.search(k))]
            if sensitive:
                out.append(self.finding(
                    kind="token", severity="high", title=f"網址參數中帶有敏感資料 @ {host}",
                    secrets=dict(sensitive), details={"網址": url, "說明": "網址會留在瀏覽紀錄、代理伺服器日誌與 Referer 中"},
                    dedup=f"query|{url}", **common,
                ))
        return out

    def _fields(self, fields, url, host, label, common) -> list[Finding]:
        fields = [(k, v) for k, v in fields if v][:30]
        if not fields:
            return []
        passwords = [(k, v) for k, v in fields if PASS_KEY.search(k)]
        users = [(k, v) for k, v in fields if USER_KEY.search(k) and not PASS_KEY.search(k)]
        tokens = [(k, v) for k, v in fields if TOKEN_KEY.search(k) and not PASS_KEY.search(k)]
        path = urlsplit(url).path
        if passwords:
            secrets = dict(users + passwords)
            return [self.finding(
                kind="credential", severity="critical",
                title=f"{label}送出明文密碼：{host}{path}",
                secrets=secrets, details={"網址": url},
                dedup=f"form|{url}|{sorted(secrets.items())}", **common,
            )]
        if tokens:
            return [self.finding(
                kind="token", severity="high", title=f"{label}中帶有權杖：{host}{path}",
                secrets=dict(tokens), details={"網址": url}, **common,
            )]
        return [self.finding(
            kind="form", severity="medium", title=f"明文{label}資料：{host}{path}",
            secrets=dict(fields), details={"網址": url, "欄位": ", ".join(k for k, _ in fields)}, **common,
        )]

    # ---- server -> client -------------------------------------------------
    def on_server(self, data: bytes) -> list[Finding]:
        if self.tunnel is not None:
            return []
        self.sbuf += data
        out: list[Finding] = []
        while True:
            # Bodies are skipped by searching for the next status line.
            m = RESP_START.search(self.sbuf)
            if not m:
                self.sbuf = self.sbuf[-64:]
                break
            end = self.sbuf.find(b"\r\n\r\n", m.start())
            if end < 0:
                self.sbuf = self.sbuf[m.start():]
                if len(self.sbuf) > 65536:
                    self.sbuf = b""
                break
            head = self.sbuf[m.start():end]
            self.sbuf = self.sbuf[end + 4:]
            out += self.analyze_response(head)
        return out

    def analyze_response(self, head: bytes) -> list[Finding]:
        status_line, headers = _parse_head(head)
        out = []
        for name, value in headers:
            if name.lower() != "set-cookie":
                continue
            pair, _, attrs = value.partition(";")
            cname, _, cvalue = pair.partition("=")
            cname, cvalue = cname.strip(), cvalue.strip()
            if not cvalue:
                continue
            lower = attrs.lower()
            flags = [f for f in ("Secure", "HttpOnly") if f.lower() in lower]
            details = {
                "Cookie 名稱": cname,
                "屬性": attrs.strip() or "(無)",
                "Secure 旗標": "有" if "Secure" in flags else "沒有（會在 HTTP 明文中傳送）",
                "HttpOnly 旗標": "有" if "HttpOnly" in flags else "沒有（JavaScript 可讀取）",
            }
            out.append(self.finding(
                kind="session", severity="high",
                title=f"伺服器發下 Cookie「{cname}」@ {self.host}",
                secrets={"cookie": cvalue}, details=details,
                excerpt=f"{status_line}\nSet-Cookie: {value}",
                encrypted_channel=self.decrypted,
                dedup=f"setcookie|{self.host}|{cname}|{cvalue}",
            ))
        return out
