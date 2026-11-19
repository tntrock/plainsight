"""Telnet: every keystroke crosses the network in the clear."""
from __future__ import annotations

import re

from ..events import Finding
from .base import StreamAnalyzer

IAC, SB, SE = 255, 250, 240
PASSWORD_PROMPT = re.compile(r"(pass(word|code)?|密碼)\s*[:：]?\s*$", re.I)
USER_PROMPT = re.compile(r"(login|user(name| name)?|帳號)\s*[:：]?\s*$", re.I)


def strip_iac(data: bytes) -> tuple[bytes, bytes]:
    """Remove telnet option negotiation. Returns (text, incomplete tail)."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b != IAC:
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:
            return bytes(out), data[i:]
        c = data[i + 1]
        if c == IAC:
            out.append(IAC)
            i += 2
        elif 251 <= c <= 254:  # WILL / WONT / DO / DONT <option>
            if i + 2 >= n:
                return bytes(out), data[i:]
            i += 3
        elif c == SB:
            end = data.find(bytes((IAC, SE)), i + 2)
            if end < 0:
                return bytes(out), data[i:]
            i = end + 2
        else:
            i += 2
    return bytes(out), b""


class TelnetAnalyzer(StreamAnalyzer):
    protocol = "Telnet"

    def __init__(self, client: str, server: str) -> None:
        super().__init__(client, server)
        self._cpend = b""
        self._spend = b""
        self.screen = ""
        self.line: list[str] = []
        self.prompt = ""
        self.user = ""

    def on_server(self, data: bytes) -> list[Finding]:
        text, self._spend = strip_iac(self._spend + data)
        self.screen = (self.screen + text.decode("utf-8", "replace"))[-500:]
        return []

    def on_client(self, data: bytes) -> list[Finding]:
        text, self._cpend = strip_iac(self._cpend + data)
        out: list[Finding] = []
        for ch in text.decode("utf-8", "replace"):
            if ch in "\r\n":
                if self.line:
                    out.extend(self._line_done("".join(self.line)))
                    self.line = []
            elif ch in "\x08\x7f":
                if self.line:
                    self.line.pop()
            elif ch >= " ":
                if not self.line:
                    # Snapshot the prompt before the server echoes our typing.
                    lines = self.screen.rstrip().splitlines()
                    self.prompt = lines[-1].strip() if lines else ""
                self.line.append(ch)
        return out

    def _line_done(self, line: str) -> list[Finding]:
        prompt = self.prompt
        if PASSWORD_PROMPT.search(prompt):
            return [self.finding(
                kind="credential", severity="critical",
                title=f"Telnet 登入密碼：{self.user or '(未知帳號)'}（逐字元明文傳送）",
                secrets={"username": self.user, "password": line},
                details={"提示字元": prompt}, excerpt=f"{prompt} {line}",
                dedup=f"cred|telnet|{self.server}|{self.user}|{line}",
            )]
        if USER_PROMPT.search(prompt):
            self.user = line
            return []
        return [self.finding(
            kind="command", severity="medium",
            title=f"Telnet 指令：{line[:80]}",
            details={"提示字元": prompt, "指令": line}, excerpt=f"{prompt} {line}",
        )]
