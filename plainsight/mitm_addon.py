"""mitmproxy addon: forwards decrypted HTTP(S) exchanges to the PlainSight dashboard.

Usage (in a lab you control):
    plainsight mitm                      # starts the dashboard
    mitmdump -s path/to/mitm_addon.py    # path is printed by `plainsight mitm`

This file only uses the standard library, so it runs inside mitmproxy's own
Python even when PlainSight is not installed there.
Set PLAINSIGHT_URL if the dashboard is not on http://127.0.0.1:8765.
"""
from __future__ import annotations

import base64
import json
import os
import threading
import urllib.error
import urllib.request

BASE_URL = os.environ.get("PLAINSIGHT_URL", "http://127.0.0.1:8765").rstrip("/")
SKIP_HEADERS = {"content-length", "transfer-encoding", "content-encoding"}


def _head(first_line: str, headers, extra: list[str]) -> str:
    lines = [first_line]
    for k, v in headers.items(multi=True):
        if k.lower() in SKIP_HEADERS or k.startswith(":"):
            continue
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines + extra) + "\r\n\r\n"


class PlainSightForwarder:
    def __init__(self) -> None:
        self.token: str | None = None

    def _get_token(self) -> str:
        if self.token is None:
            with urllib.request.urlopen(f"{BASE_URL}/api/stats", timeout=2) as r:
                self.token = json.load(r)["ingest_token"]
        return self.token

    def _post(self, payload: dict) -> None:
        data = json.dumps(payload).encode()
        for _ in range(2):  # the dashboard may have restarted with a new token
            try:
                req = urllib.request.Request(
                    f"{BASE_URL}/api/ingest", data=data, method="POST",
                    headers={"Content-Type": "application/json", "X-PlainSight-Token": self._get_token()},
                )
                urllib.request.urlopen(req, timeout=3).close()
                return
            except urllib.error.HTTPError as e:
                if e.code != 403:
                    return
                self.token = None
            except OSError:
                return

    def response(self, flow) -> None:
        req, resp = flow.request, flow.response
        body = req.get_content(strict=False) or b""
        extra = [] if "host" in req.headers else [f"Host: {req.pretty_host}"]
        if body:
            extra.append(f"Content-Length: {len(body)}")
        raw_req = _head(f"{req.method} {req.path} HTTP/1.1", req.headers, extra).encode("utf-8", "replace") + body
        raw_resp = b""
        if resp is not None:
            raw_resp = _head(f"HTTP/1.1 {resp.status_code} {resp.reason or ''}", resp.headers, []).encode(
                "utf-8", "replace")
        peer = flow.client_conn.peername or ("?", 0)
        payload = {
            "client": f"{peer[0]}:{peer[1]}",
            "server": f"{req.host}:{req.port}",
            "tls": req.scheme == "https",
            "request": base64.b64encode(raw_req).decode(),
            "response_head": base64.b64encode(raw_resp).decode(),
        }
        threading.Thread(target=self._post, args=(payload,), daemon=True).start()


addons = [PlainSightForwarder()]
