"""FTP and POP3: both log in with plain `USER` / `PASS` commands."""
from __future__ import annotations

from ..events import Finding
from .base import LineAnalyzer


class UserPassAnalyzer(LineAnalyzer):
    def __init__(self, client: str, server: str, protocol: str) -> None:
        super().__init__(client, server)
        self.protocol = protocol
        self.user = ""

    def client_line(self, line: str) -> list[Finding]:
        cmd, _, arg = line.strip().partition(" ")
        cmd = cmd.upper()
        if cmd == "USER":
            self.user = arg
        elif cmd == "PASS":
            return [self.credential(self.user, arg, f"USER {self.user}\nPASS {arg}", "USER / PASS 指令")]
        elif cmd == "APOP":
            user, _, digest = arg.partition(" ")
            return [self.finding(
                kind="credential", severity="medium",
                title=f"POP3 APOP 登入：{user}（MD5 雜湊，可離線暴力破解）",
                secrets={"username": user}, details={"雜湊": digest}, excerpt=line,
            )]
        elif self.protocol == "FTP" and cmd in ("RETR", "STOR"):
            action = "下載" if cmd == "RETR" else "上傳"
            return [self.finding(
                kind="file", severity="medium",
                title=f"FTP {action}檔案：{arg}",
                details={"動作": action, "檔名": arg}, excerpt=line,
            )]
        return []
