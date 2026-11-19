"""Masking of secrets before they reach the dashboard."""
from __future__ import annotations

from urllib.parse import quote, quote_plus

from .events import Finding

WITHHELD = "（遮蔽模式下不顯示原文；以 --show-secrets 啟動可查看）"


def mask(value: str) -> str:
    """Keep just enough of a secret to show that it was captured."""
    n = len(value)
    if n <= 2:
        return "*" * n
    if n <= 6:
        return value[0] + "*" * (n - 1)
    stars = "*" * min(n - 4, 12)
    if n - 4 > 12:  # long free text: show its size instead of a wall of stars
        stars += f"（共 {n} 字）"
    return value[:2] + stars + value[-2:]


def redact(finding: Finding) -> dict:
    data = finding.to_dict()
    data["redacted"] = True
    values = sorted({v for v in finding.secrets.values() if v}, key=len, reverse=True)
    data["secrets"] = {k: mask(v) for k, v in finding.secrets.items()}
    if finding.excerpt_sensitive:
        data["excerpt"] = WITHHELD
        return data
    excerpt = finding.excerpt
    for v in values:
        masked = mask(v)
        # Form bodies carry the URL-encoded form of the value.
        for form in {v, quote(v, safe=""), quote_plus(v)}:
            excerpt = excerpt.replace(form, masked)
    data["excerpt"] = excerpt
    return data
