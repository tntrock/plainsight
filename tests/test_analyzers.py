import base64

import pytest

from plainsight.analyzers.dns import build_dns_query, parse_dns_query
from plainsight.analyzers.tls import build_client_hello, parse_client_hello
from plainsight.engine import ACK, FIN, SYN, Engine

CLIENT, SERVER = "10.0.0.5", "10.0.0.1"


class Wire:
    """Drives one TCP connection through the engine."""

    def __init__(self, port, sport=50000):
        self.found = []
        self.engine = Engine(self.found.append)
        self.port, self.sport = port, sport
        self.cseq, self.sseq = 1000, 9000
        self.engine.feed_tcp(CLIENT, sport, SERVER, port, self.cseq, SYN, b"")
        self.engine.feed_tcp(SERVER, port, CLIENT, sport, self.sseq, SYN | ACK, b"")
        self.cseq += 1
        self.sseq += 1

    def c(self, data, chunk=None):
        data = data.encode() if isinstance(data, str) else data
        for i in range(0, len(data), chunk or len(data) or 1):
            seg = data[i:i + (chunk or len(data))]
            self.engine.feed_tcp(CLIENT, self.sport, SERVER, self.port, self.cseq, ACK, seg)
            self.cseq += len(seg)
        return self

    def s(self, data):
        data = data.encode() if isinstance(data, str) else data
        self.engine.feed_tcp(SERVER, self.port, CLIENT, self.sport, self.sseq, ACK, data)
        self.sseq += len(data)
        return self

    def kinds(self, kind):
        return [f for f in self.found if f.kind == kind]


def test_http_form_login_split_across_segments():
    body = "username=alice&password=p%40ss+word"
    w = Wire(80).c(
        f"POST /login HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}", chunk=7)
    [cred] = w.kinds("credential")
    assert cred.secrets == {"username": "alice", "password": "p@ss word"}
    assert cred.severity == "critical"
    assert "shop.example/login" in cred.title
    assert [f.title for f in w.kinds("url")] == ["POST http://shop.example/login"]


def test_http_basic_auth_cookie_and_set_cookie():
    token = base64.b64encode(b"admin:hunter22").decode()
    w = Wire(8080).c(f"GET /admin HTTP/1.1\r\nHost: r.example\r\nAuthorization: Basic {token}\r\n"
                     "Cookie: sid=abc123\r\n\r\n")
    w.s("HTTP/1.1 200 OK\r\nSet-Cookie: sid=newvalue99; Path=/; HttpOnly\r\nContent-Length: 2\r\n\r\nok")
    [cred] = w.kinds("credential")
    assert cred.secrets["username"] == "admin" and cred.secrets["password"] == "hunter22"
    sessions = w.kinds("session")
    assert {f.secrets["cookie"] for f in sessions} == {"sid=abc123", "newvalue99"}
    set_cookie = [f for f in sessions if f.secrets["cookie"] == "newvalue99"][0]
    assert set_cookie.details["Secure 旗標"].startswith("沒有")


def test_http_pipelined_requests_and_static_assets_skipped():
    w = Wire(80).c("GET /a.css HTTP/1.1\r\nHost: x.example\r\n\r\nGET /page?token=s3cr3t HTTP/1.1\r\nHost: x.example\r\n\r\n")
    assert [f.title for f in w.kinds("url")] == ["GET http://x.example/page?token=s3cr3t"]
    [tok] = w.kinds("token")
    assert tok.secrets == {"token": "s3cr3t"}


def test_http_json_body_and_chunked():
    body = '{"user": {"email": "a@b.example", "password": "pw12345"}}'
    chunked = f"{len(body):x}\r\n{body}\r\n0\r\n\r\n"
    w = Wire(80).c("POST /api/login HTTP/1.1\r\nHost: api.example\r\nContent-Type: application/json\r\n"
                   f"Transfer-Encoding: chunked\r\n\r\n{chunked}")
    [cred] = w.kinds("credential")
    assert cred.secrets == {"email": "a@b.example", "password": "pw12345"}


def test_http_on_unusual_port_detected_by_content():
    w = Wire(5000).c("GET / HTTP/1.1\r\nHost: odd.example\r\n\r\n")
    assert w.kinds("url")


def test_connect_tunnel_reports_sni():
    w = Wire(3128).c("CONNECT bank.example:443 HTTP/1.1\r\nHost: bank.example:443\r\n\r\n")
    w.s("HTTP/1.1 200 Connection established\r\n\r\n")
    w.c(build_client_hello("bank.example"))
    assert [f.details["SNI 網域"] for f in w.kinds("sni")] == ["bank.example"]


def test_ftp_login_and_file():
    w = Wire(21).s("220 hi\r\n").c("USER bob\r\n").s("331\r\n").c("PASS secret!\r\n").c("RETR a.txt\r\n")
    [cred] = w.kinds("credential")
    assert cred.secrets == {"username": "bob", "password": "secret!"}
    assert w.kinds("file")[0].details["檔名"] == "a.txt"


def test_pop3_login():
    w = Wire(110).c("USER carol\r\nPASS pop-pw\r\n")
    [cred] = w.kinds("credential")
    assert cred.protocol == "POP3" and cred.secrets["password"] == "pop-pw"


def test_smtp_auth_login_and_email():
    u, p = base64.b64encode(b"me@x.example").decode(), base64.b64encode(b"mailpw").decode()
    w = Wire(587).c(f"EHLO a\r\nAUTH LOGIN\r\n{u}\r\n{p}\r\nMAIL FROM:<me@x.example>\r\nRCPT TO:<you@y.example>\r\n"
                    "DATA\r\nSubject: hello\r\nFrom: me@x.example\r\n\r\nbody text\r\n..dot line\r\n.\r\n")
    [cred] = w.kinds("credential")
    assert cred.secrets["username"] == "me@x.example" and cred.secrets["password"] == "mailpw"
    [mail] = w.kinds("email")
    assert mail.details["主旨"] == "hello"
    assert "body text" in mail.secrets["body"]


def test_smtp_auth_plain_inline():
    enc = base64.b64encode(b"\x00user1\x00pw1").decode()
    w = Wire(25).c(f"AUTH PLAIN {enc}\r\n")
    assert w.kinds("credential")[0].secrets["password"] == "pw1"


def test_starttls_stops_parsing():
    w = Wire(143).c("a1 STARTTLS\r\n").c('a2 LOGIN "u" "p"\r\n')
    assert w.kinds("upgrade") and not w.kinds("credential")


def test_imap_quoted_login():
    w = Wire(143).c('a1 LOGIN "alice@x.example" "pa ss\\"word"\r\n')
    assert w.kinds("credential")[0].secrets == {"username": "alice@x.example", "password": 'pa ss"word'}


def test_telnet_keystrokes():
    w = Wire(23).s(b"\xff\xfb\x01login: ")
    for ch in "root":
        w.c(ch).s(ch)
    w.c("\r\n").s("\r\nPassword: ")
    for ch in "toorX":
        w.c(ch)
    w.c("\x7f\r\n").s("\r\n# ")  # backspace removes the X
    for ch in "ls -la":
        w.c(ch).s(ch)
    w.c("\r\n")
    [cred] = w.kinds("credential")
    assert cred.secrets == {"username": "root", "password": "toor"}
    assert w.kinds("command")[0].details["指令"] == "ls -la"


def test_tls_sni_split_across_segments_and_dedup_key():
    hello = build_client_hello("very-long-subdomain.example") + b"\x00" * 0  # noqa
    w = Wire(443).c(hello, chunk=10)
    [f] = w.kinds("sni")
    assert f.details["SNI 網域"] == "very-long-subdomain.example"
    assert f.dedup == "sni|10.0.0.5|very-long-subdomain.example"


def test_parse_client_hello_rejects_garbage():
    assert parse_client_hello(b"\x02garbage") is None
    assert parse_client_hello(b"\x01") is None


def test_dns_query_roundtrip_and_engine():
    q = build_dns_query("www.example", 28)
    assert parse_dns_query(q) == ("www.example", "AAAA")
    response = bytearray(q)
    response[2] |= 0x80
    assert parse_dns_query(bytes(response)) is None
    found = []
    Engine(found.append).feed_udp(CLIENT, 5555, SERVER, 53, q)
    assert found[0].kind == "dns" and found[0].details["查詢網域"] == "www.example"


def test_out_of_order_and_retransmitted_segments():
    found = []
    e = Engine(found.append)
    e.feed_tcp(CLIENT, 40000, SERVER, 21, 100, SYN, b"")
    e.feed_tcp(CLIENT, 40000, SERVER, 21, 109, ACK, b"PASS pw\r\n")   # arrives early
    e.feed_tcp(CLIENT, 40000, SERVER, 21, 101, ACK, b"USER u\r\n")
    e.feed_tcp(CLIENT, 40000, SERVER, 21, 101, ACK, b"USER u\r\n")    # retransmission
    assert [f.secrets for f in found] == [{"username": "u", "password": "pw"}]


def test_midstream_capture_without_syn():
    found = []
    e = Engine(found.append)
    e.feed_tcp(CLIENT, 40001, SERVER, 110, 5000, ACK, b"USER a\r\nPASS b\r\n")
    assert found and found[0].src == f"{CLIENT}:40001"


def test_session_stats():
    w = Wire(443).c(build_client_hello("a.example"))
    Wire(21)  # no data yet: not counted
    snap = w.engine.stats.snapshot()
    assert snap["encrypted_sessions"] == 1 and snap["sessions"] == {"TLS": 1}


def test_fin_closes_session():
    w = Wire(21).c("USER x\r\n")
    w.engine.feed_tcp(CLIENT, w.sport, SERVER, 21, w.cseq, FIN | ACK, b"")
    w.engine.feed_tcp(SERVER, 21, CLIENT, w.sport, w.sseq, FIN | ACK, b"")
    assert not w.engine.sessions


@pytest.mark.parametrize("payload", [b"", b"\x16", b"\x16\x03\x01\xff\xff" + b"A" * 30000, b"\xff" * 50])
def test_junk_does_not_crash(payload):
    for port in (21, 23, 25, 80, 143, 443):
        Wire(port).c(payload)
