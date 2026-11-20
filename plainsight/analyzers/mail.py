"""SMTP and IMAP: logins and email contents."""
from __future__ import annotations

import email
import email.policy
import re

from ..events import Finding
from .base import LineAnalyzer, b64text


def _sasl_plain(encoded: str) -> tuple[str, str]:
    """SASL PLAIN is base64('authzid\\0user\\0password')."""
    parts = b64text(encoded).split("\x00")
    if len(parts) < 3:
        return "", ""
    return parts[1], parts[2]


class SmtpAnalyzer(LineAnalyzer):
    protocol = "SMTP"
    MAX_DATA_LINES = 2000

    def __init__(self, client: str, server: str) -> None:
        super().__init__(client, server)
        self.auth_state: str | None = None
        self.auth_user = ""
        self.auth_user_b64 = ""
        self.in_data = False
        self.data_lines: list[str] = []
        self.mail_from = ""
        self.rcpt: list[str] = []

    def client_line(self, line: str) -> list[Finding]:
        if self.in_data:
            if line == ".":
                self.in_data = False
                return [self._email()]
            if len(self.data_lines) < self.MAX_DATA_LINES:
                self.data_lines.append(line[1:] if line.startswith("..") else line)
            return []

        state, self.auth_state = self.auth_state, None
        if state == "plain":
            return self._plain(line.strip())
        if state == "login_user":
            self.auth_user, self.auth_user_b64 = b64text(line), line.strip()
            self.auth_state = "login_pass"
            return []
        if state == "login_pass":
            return [self.credential(
                self.auth_user, b64text(line),
                f"AUTH LOGIN\n{self.auth_user_b64}\n{line.strip()}", "AUTH LOGIN（Base64 編碼，不是加密）",
                encoded_user=self.auth_user_b64, encoded_password=line.strip(),
            )]

        upper = line.upper()
        if upper.startswith("AUTH PLAIN"):
            rest = line[10:].strip()
            if rest:
                return self._plain(rest)
            self.auth_state = "plain"
        elif upper.startswith("AUTH LOGIN"):
            rest = line[10:].strip()
            if rest:
                self.auth_user, self.auth_user_b64 = b64text(rest), rest
                self.auth_state = "login_pass"
            else:
                self.auth_state = "login_user"
        elif upper.startswith("MAIL FROM:"):
            self.mail_from = line[10:].strip()
        elif upper.startswith("RCPT TO:"):
            self.rcpt.append(line[8:].strip())
        elif upper == "DATA":
            self.in_data = True
            self.data_lines = []
        return []

    def _plain(self, encoded: str) -> list[Finding]:
        user, password = _sasl_plain(encoded)
        if not password:
            return []
        return [self.credential(user, password, f"AUTH PLAIN {encoded}",
                                "AUTH PLAIN（Base64 編碼，不是加密）", encoded=encoded)]

    def _email(self) -> Finding:
        raw = "\n".join(self.data_lines)
        subject = sender = to = body = ""
        try:
            msg = email.message_from_string(raw, policy=email.policy.default)
            subject = str(msg.get("subject", ""))
            sender = str(msg.get("from", ""))
            to = str(msg.get("to", ""))
            part = msg.get_body(preferencelist=("plain", "html"))
            if part is not None:
                body = part.get_content().strip()
        except Exception:  # malformed mail: still show the raw text
            body = raw
        details = {
            "寄件者": sender or self.mail_from,
            "收件者": to or ", ".join(self.rcpt),
            "主旨": subject,
        }
        self.rcpt = []
        return self.finding(
            kind="email", severity="high",
            title=f"明文電子郵件：{subject or '(無主旨)'}",
            secrets={"body": body[:1000]}, details=details,
            excerpt="\n".join(self.data_lines[:60]),
        )


_ASTRING = r'("(?:[^"\\]|\\.)*"|\S+)'
LOGIN_RE = re.compile(rf"^\S+\s+LOGIN\s+{_ASTRING}\s+{_ASTRING}\s*$", re.I)
AUTH_PLAIN_RE = re.compile(r"^\S+\s+AUTHENTICATE\s+PLAIN(?:\s+(\S+))?\s*$", re.I)


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return re.sub(r"\\(.)", r"\1", s[1:-1])
    return s


class ImapAnalyzer(LineAnalyzer):
    protocol = "IMAP"

    def __init__(self, client: str, server: str) -> None:
        super().__init__(client, server)
        self.expect_plain = False

    def client_line(self, line: str) -> list[Finding]:
        if self.expect_plain:
            self.expect_plain = False
            return self._plain(line.strip())
        m = LOGIN_RE.match(line)
        if m:
            user, password = _unquote(m.group(1)), _unquote(m.group(2))
            return [self.credential(user, password, line, "LOGIN 指令")]
        m = AUTH_PLAIN_RE.match(line)
        if m:
            if m.group(1):
                return self._plain(m.group(1))
            self.expect_plain = True
        return []

    def _plain(self, encoded: str) -> list[Finding]:
        user, password = _sasl_plain(encoded)
        if not password:
            return []
        return [self.credential(user, password, encoded, "AUTHENTICATE PLAIN（Base64 編碼）", encoded=encoded)]
