"""Synthetic lab traffic, so the tool can be shown without capturing anyone.

All hosts use reserved documentation addresses (RFC 5737) and the reserved
`.example` top-level domain; all accounts and passwords are made up.
"""
from __future__ import annotations

import base64
import os
import random

from .analyzers.dns import build_dns_query
from .analyzers.tls import build_client_hello

GATEWAY_MAC = "02:00:00:00:00:01"
LAPTOP = ("192.168.50.23", "02:00:00:00:00:23")   # Alice's laptop
PHONE = ("192.168.50.31", "02:00:00:00:00:31")    # Bob's phone
PC = ("192.168.50.40", "02:00:00:00:00:40")       # office PC
DNS_SERVER = "192.168.50.1"


class _Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def tick(self, dt: float = 0.004) -> float:
        self.t += dt
        return self.t


class Conversation:
    """Builds the packets of one TCP connection, with correct sequence numbers."""

    def __init__(self, clock: _Clock, client: tuple[str, str], server_ip: str, server_port: int) -> None:
        self.clock = clock
        self.cip, self.cmac = client
        self.sip, self.sport = server_ip, server_port
        self.cport = random.randint(49152, 65000)
        self.cseq = random.getrandbits(32)
        self.sseq = random.getrandbits(32)
        self.packets: list = []

    def _pkt(self, from_client: bool, flags: str, payload: bytes = b"") -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        if from_client:
            eth = Ether(src=self.cmac, dst=GATEWAY_MAC)
            ip = IP(src=self.cip, dst=self.sip)
            tcp = TCP(sport=self.cport, dport=self.sport, flags=flags, seq=self.cseq, ack=self.sseq)
        else:
            eth = Ether(src=GATEWAY_MAC, dst=self.cmac)
            ip = IP(src=self.sip, dst=self.cip)
            tcp = TCP(sport=self.sport, dport=self.cport, flags=flags, seq=self.sseq, ack=self.cseq)
        p = eth / ip / tcp
        if payload:
            p = p / Raw(payload)
        p.time = self.clock.tick()
        self.packets.append(p)

    def open(self) -> "Conversation":
        self._pkt(True, "S")
        self.cseq = (self.cseq + 1) & 0xFFFFFFFF
        self._pkt(False, "SA")
        self.sseq = (self.sseq + 1) & 0xFFFFFFFF
        self._pkt(True, "A")
        return self

    def send(self, from_client: bool, data: bytes | str, mss: int = 1200) -> "Conversation":
        if isinstance(data, str):
            data = data.encode()
        for i in range(0, len(data), mss):
            seg = data[i:i + mss]
            self._pkt(from_client, "PA", seg)
            if from_client:
                self.cseq = (self.cseq + len(seg)) & 0xFFFFFFFF
            else:
                self.sseq = (self.sseq + len(seg)) & 0xFFFFFFFF
        return self

    def c(self, data, mss: int = 1200) -> "Conversation":
        return self.send(True, data, mss)

    def s(self, data, mss: int = 1200) -> "Conversation":
        return self.send(False, data, mss)

    def close(self) -> list:
        self._pkt(True, "FA")
        self.cseq = (self.cseq + 1) & 0xFFFFFFFF
        self._pkt(False, "FA")
        self.sseq = (self.sseq + 1) & 0xFFFFFFFF
        self._pkt(True, "A")
        return self.packets


def _dns(clock: _Clock, client: tuple[str, str], name: str, qtype: int = 1) -> list:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    p = (Ether(src=client[1], dst=GATEWAY_MAC) / IP(src=client[0], dst=DNS_SERVER)
         / UDP(sport=random.randint(49152, 65000), dport=53)
         / Raw(build_dns_query(name, qtype, random.getrandbits(16))))
    p.time = clock.tick()
    return [p]


def _http_ok(body: str, extra: str = "") -> str:
    data = body.encode()
    return (f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n{extra}"
            f"Content-Length: {len(data)}\r\n\r\n{body}")


def _tls_session(clock: _Clock, client, server_ip: str, sni: str) -> list:
    conv = Conversation(clock, client, server_ip, 443).open()
    conv.c(build_client_hello(sni))
    conv.s(b"\x16\x03\x03\x00\x7a\x02" + os.urandom(0x79))  # ServerHello
    conv.s(b"\x17\x03\x03\x04\x00" + os.urandom(1024))      # encrypted application data
    conv.c(b"\x17\x03\x03\x01\x40" + os.urandom(320))
    conv.s(b"\x17\x03\x03\x05\x00" + os.urandom(1280))
    return conv.close()


def build_scenes() -> list[tuple[str, list]]:
    """Returns [(narration, packets)] in playback order."""
    clock = _Clock(1_763_600_000.0)
    scenes: list[tuple[str, list]] = []

    # 1. A login form on a site without HTTPS
    pkts = _dns(clock, LAPTOP, "forum.example")
    conv = Conversation(clock, LAPTOP, "203.0.113.10", 80).open()
    conv.c("GET /login HTTP/1.1\r\nHost: forum.example\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0) Firefox/140.0\r\n"
           "Accept: text/html\r\n\r\n")
    conv.s(_http_ok("<html><body><form method=post action=/login>...</form></body></html>"))
    form = "username=alice&password=Sup3rS3cret%21&remember=1"
    conv.c(f"POST /login HTTP/1.1\r\nHost: forum.example\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0) Firefox/140.0\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\nReferer: http://forum.example/login\r\n"
           f"Content-Length: {len(form)}\r\n\r\n{form}", mss=90)
    conv.s("HTTP/1.1 302 Found\r\nLocation: /home\r\nSet-Cookie: PHPSESSID=8f14e45fceea167a5a36dedd4bea2543; path=/\r\n"
           "Content-Length: 0\r\n\r\n")
    conv.c("GET /home HTTP/1.1\r\nHost: forum.example\r\nCookie: PHPSESSID=8f14e45fceea167a5a36dedd4bea2543\r\n\r\n")
    conv.s(_http_ok("<html><body>歡迎回來，alice！</body></html>"))
    scenes.append(("Alice 在沒有 HTTPS 的論壇登入（HTTP 表單 + Session Cookie）", pkts + conv.close()))

    # 2. Router admin page with HTTP Basic auth
    basic = base64.b64encode(b"admin:admin1234").decode()
    conv = Conversation(clock, PC, "192.168.50.1", 80).open()
    conv.c(f"GET /cgi-bin/status HTTP/1.1\r\nHost: 192.168.50.1\r\nAuthorization: Basic {basic}\r\n\r\n")
    conv.s(_http_ok("<html>Router status</html>"))
    scenes.append(("辦公室電腦登入路由器管理頁（HTTP Basic 認證）", conv.close()))

    # 3. HTTPS: content protected, domain still visible
    pkts = _dns(clock, PHONE, "bank.example") + _dns(clock, PHONE, "bank.example", 65)
    pkts += _tls_session(clock, PHONE, "198.51.100.20", "bank.example")
    scenes.append(("Bob 用手機開網路銀行（HTTPS：內容加密，但 DNS 與 SNI 透露了網域）", pkts))

    # 4. FTP
    conv = Conversation(clock, PC, "203.0.113.21", 21).open()
    conv.s("220 FTP server ready\r\n")
    conv.c("USER bob\r\n").s("331 Password required\r\n")
    conv.c("PASS ftpPass2026\r\n").s("230 Login successful\r\n")
    conv.c("RETR 2026-Q4-財務報表.xlsx\r\n").s("150 Opening data connection\r\n226 Transfer complete\r\n")
    conv.c("QUIT\r\n").s("221 Goodbye\r\n")
    scenes.append(("辦公室電腦用 FTP 下載財務報表", conv.close()))

    # 5. SMTP with AUTH LOGIN and an email
    u, p = base64.b64encode(b"carol@mail.example").decode(), base64.b64encode(b"MailPw!99").decode()
    mail = ("From: Carol <carol@mail.example>\r\nTo: Dave <dave@corp.example>\r\n"
            "Subject: =?UTF-8?B?" + base64.b64encode("下週會議資料與 VPN 帳號".encode()).decode() + "?=\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
            "Dave 你好，\r\n\r\n附上下週會議資料。新的 VPN 帳號是 dave.w，臨時密碼 Vpn#2026temp，\r\n"
            "登入後請立即修改。\r\n\r\nCarol\r\n")
    conv = Conversation(clock, LAPTOP, "203.0.113.25", 587).open()
    conv.s("220 mail.example ESMTP\r\n")
    conv.c("EHLO laptop\r\n").s("250-mail.example\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n")
    conv.c("AUTH LOGIN\r\n").s("334 VXNlcm5hbWU6\r\n")
    conv.c(u + "\r\n").s("334 UGFzc3dvcmQ6\r\n")
    conv.c(p + "\r\n").s("235 Authentication successful\r\n")
    conv.c("MAIL FROM:<carol@mail.example>\r\n").s("250 OK\r\n")
    conv.c("RCPT TO:<dave@corp.example>\r\n").s("250 OK\r\n")
    conv.c("DATA\r\n").s("354 End data with <CR><LF>.<CR><LF>\r\n")
    conv.c(mail + ".\r\n").s("250 Queued\r\n")
    scenes.append(("Carol 用沒有加密的 SMTP 寄信（帳密只是 Base64，信件內容全部可讀）", conv.close()))

    # 6. Telnet to a switch, typed one key at a time
    conv = Conversation(clock, PC, "192.168.50.2", 23).open()
    conv.s(b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18")  # option negotiation
    conv.c(b"\xff\xfd\x01\xff\xfd\x03\xff\xfb\x18")
    conv.s("\r\nCore-Switch\r\n\r\nUsername: ")
    for ch in "netadmin":
        conv.c(ch).s(ch)
    conv.c("\r\n").s("\r\nPassword: ")
    for ch in "Sw1tch!pass":
        conv.c(ch)  # no echo for passwords
    conv.c("\r\n").s("\r\nCore-Switch# ")
    for ch in "show running-config":
        conv.c(ch).s(ch)
    conv.c("\r\n").s("\r\nhostname Core-Switch\r\nsnmp-server community public RO\r\n...\r\nCore-Switch# ")
    scenes.append(("網管用 Telnet 登入核心交換器（每個按鍵都是明文）", conv.close()))

    # 7. POP3 and IMAP mail checks
    conv = Conversation(clock, PHONE, "203.0.113.25", 110).open()
    conv.s("+OK POP3 ready\r\n").c("USER bob@mail.example\r\n").s("+OK\r\n")
    conv.c("PASS bobmail123\r\n").s("+OK 3 messages\r\n").c("QUIT\r\n").s("+OK bye\r\n")
    pkts = conv.close()
    conv = Conversation(clock, LAPTOP, "203.0.113.25", 143).open()
    conv.s("* OK IMAP4rev1 ready\r\n")
    conv.c('a1 LOGIN "alice@mail.example" "Imap pass 7"\r\n').s("a1 OK LOGIN completed\r\n")
    conv.c("a2 SELECT INBOX\r\n").s("* 12 EXISTS\r\na2 OK\r\n")
    scenes.append(("手機與筆電用 POP3 / IMAP 收信（明文登入）", pkts + conv.close()))

    # 8. A mail client doing it right: STARTTLS before logging in
    conv = Conversation(clock, LAPTOP, "203.0.113.26", 143).open()
    conv.s("* OK IMAP4rev1 ready\r\n").c("a1 STARTTLS\r\n").s("a1 OK Begin TLS negotiation\r\n")
    conv.c(build_client_hello("imap.secure.example"))  # from here on it's TLS
    conv.c(b"\x17\x03\x03\x00\xc8" + os.urandom(200))
    scenes.append(("對照組：郵件軟體先用 STARTTLS 升級加密再登入", conv.close()))

    # 9. Mobile app calling an API over plain HTTP with a bearer token
    pkts = _dns(clock, PHONE, "api.fitness.example")
    body = '{"steps": 8412, "heart_rate": 72, "location": {"lat": 25.0330, "lng": 121.5654}}'
    conv = Conversation(clock, PHONE, "203.0.113.40", 8080).open()
    conv.c(f"POST /v1/sync HTTP/1.1\r\nHost: api.fitness.example:8080\r\n"
           f"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IifQ.Kp3vZ8xQm2\r\n"
           f"Content-Type: application/json\r\nContent-Length: {len(body.encode())}\r\n\r\n{body}")
    conv.s('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"ok":true}')
    scenes.append(("健身 App 用 HTTP 同步資料（Bearer 權杖與定位外洩）", pkts + conv.close()))

    # 10. More background HTTPS browsing
    pkts = []
    for name, ip in (("news.example", "198.51.100.30"), ("video.example", "198.51.100.31"),
                     ("chat.example", "198.51.100.32")):
        pkts += _dns(clock, LAPTOP, name) + _tls_session(clock, LAPTOP, ip, name)
    scenes.append(("背景中的一般 HTTPS 瀏覽", pkts))
    return scenes


def all_packets() -> list:
    return [p for _, pkts in build_scenes() for p in pkts]
