"""Download and launch the official Npcap installer.

Npcap's free edition may not be redistributed (that needs the paid OEM
license), so PlainSight cannot ship it inside the exe. Instead it fetches the
current installer from npcap.com, checks its Authenticode signature and starts
it; the user clicks through Npcap's own setup and license.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import urllib.request
from typing import Callable
from urllib.parse import urljoin

SITE = "https://npcap.com/"
# Publisher of Nmap / Npcap (older releases were signed as Insecure.Com LLC).
SIGNERS = ("CN=Nmap Software LLC,", "CN=Insecure.Com LLC,")
USER_AGENT = "PlainSight (+https://github.com/tntrock/plainsight)"


def _get(url: str, timeout: float = 20):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}), timeout=timeout)


def latest_installer_url() -> str:
    with _get(SITE) as r:
        html = r.read().decode("utf-8", "replace")
    m = re.search(r"dist/npcap-\d+(?:\.\d+)+\.exe", html)
    if not m:
        raise RuntimeError("在 npcap.com 找不到安裝檔連結，請手動到 https://npcap.com 下載")
    return urljoin(SITE, m.group(0))


def download(url: str, progress: Callable[[int, int], None] | None = None) -> str:
    dest = os.path.join(tempfile.gettempdir(), url.rsplit("/", 1)[-1])
    with _get(url, timeout=60) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while chunk := r.read(64 * 1024):
            f.write(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)
    return dest


def verify_signature(path: str) -> str:
    """Raise unless the file carries a valid Authenticode signature from Npcap's publisher."""
    script = ("$s = Get-AuthenticodeSignature -LiteralPath $env:PS_TARGET; "
              "Write-Output $s.Status; Write-Output $s.SignerCertificate.Subject")
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=60, env={**os.environ, "PS_TARGET": path},
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    ).stdout.strip().splitlines()
    status, subject = (out + ["", ""])[:2]
    if status.strip() != "Valid" or not subject.startswith(SIGNERS):
        raise RuntimeError(f"安裝檔數位簽章驗證失敗（{status or '無簽章'}；{subject or '未知簽署者'}），已停止安裝")
    return subject


def launch_installer(path: str) -> None:
    os.startfile(path)  # Npcap's installer asks for administrator rights itself (UAC)
