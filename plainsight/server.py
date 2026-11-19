"""Dashboard web server: static page, JSON API, Server-Sent Events, MITM ingest."""
from __future__ import annotations

import base64
import json
import queue
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .analyzers.http import HttpAnalyzer
from .hub import Hub

WEB_DIR = Path(__file__).parent / "web"
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}
SECURITY_HEADERS = {
    # Packet data is attacker-controlled: never let it run as script.
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
MAX_INGEST = 4 * 1024 * 1024
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def ingest(hub: Hub, data: dict) -> int:
    """Analyze one HTTP exchange forwarded by the mitmproxy addon."""
    request = base64.b64decode(data.get("request", ""))
    response = base64.b64decode(data.get("response_head", ""))
    analyzer = HttpAnalyzer(str(data.get("client", "?")), str(data.get("server", "?")),
                            decrypted=bool(data.get("tls")))
    findings = analyzer.on_client(request)
    if response:
        findings += analyzer.on_server(response)
    hub.stats.add("mitm_flows")
    return sum(hub.publish(f) for f in findings)


def make_server(hub: Hub, host: str, port: int, meta: dict) -> ThreadingHTTPServer:
    token = secrets.token_urlsafe(24)
    meta = dict(meta, ingest_token=token)

    class Handler(BaseHTTPRequestHandler):
        server_version = "PlainSight"
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:
            pass

        def _host_ok(self) -> bool:
            # Blocks DNS-rebinding: a web page can't make us answer for its domain.
            if host not in LOOPBACK:
                return True
            h = self.headers.get("Host", "")
            name = h.rsplit(":", 1)[0] if not h.endswith("]") else h
            return name.strip("[]") in LOOPBACK

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def do_GET(self) -> None:
            if not self._host_ok():
                return self._send(403, b"forbidden", "text/plain")
            path = urlsplit(self.path).path
            if path in STATIC:
                name, ctype = STATIC[path]
                return self._send(200, (WEB_DIR / name).read_bytes(), ctype)
            if path == "/api/findings":
                return self._json(hub.snapshot())
            if path == "/api/stats":
                return self._json({**hub.stats.snapshot(), **meta, "redacted": not hub.show_secrets})
            if path == "/events":
                return self._events()
            self._send(404, b"not found", "text/plain")

        do_HEAD = do_GET

        def _events(self) -> None:
            q, history = hub.subscribe()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                for item in history:
                    self._event(item)
                while True:
                    try:
                        self._event(q.get(timeout=15))
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass
            finally:
                hub.unsubscribe(q)

        def _event(self, item: dict) -> None:
            self.wfile.write(b"data: " + json.dumps(item, ensure_ascii=False).encode() + b"\n\n")
            self.wfile.flush()

        def do_POST(self) -> None:
            if not self._host_ok() or urlsplit(self.path).path != "/api/ingest":
                return self._send(404, b"not found", "text/plain")
            if not secrets.compare_digest(self.headers.get("X-PlainSight-Token", ""), token):
                return self._send(403, b"bad token", "text/plain")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 < length <= MAX_INGEST:
                return self._send(413, b"bad length", "text/plain")
            try:
                data = json.loads(self.rfile.read(length))
                n = ingest(hub, data)
            except (ValueError, TypeError, AttributeError) as e:
                return self._send(400, f"bad request: {e}".encode(), "text/plain")
            self._json({"findings": n})

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv
