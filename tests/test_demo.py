import pytest

pytest.importorskip("scapy")

from plainsight.capture import feed_packet, read_pcap  # noqa: E402
from plainsight.demo import all_packets  # noqa: E402
from plainsight.engine import Engine  # noqa: E402
from plainsight.hub import Hub  # noqa: E402


def _run(feed):
    hub = Hub(show_secrets=True)
    engine = Engine(hub.publish, hub.stats)
    feed(engine)
    return hub.snapshot(), hub.stats.snapshot()


def _check(findings):
    creds = {(f["protocol"], f["secrets"].get("password")) for f in findings if f["kind"] == "credential"}
    assert creds >= {
        ("HTTP", "Sup3rS3cret!"), ("HTTP", "admin1234"), ("FTP", "ftpPass2026"), ("SMTP", "MailPw!99"),
        ("Telnet", "Sw1tch!pass"), ("POP3", "bobmail123"), ("IMAP", "Imap pass 7"),
    }
    kinds = {f["kind"] for f in findings}
    assert kinds >= {"url", "session", "token", "dns", "sni", "email", "command", "file", "upgrade"}
    mail = [f for f in findings if f["kind"] == "email"][0]
    assert mail["details"]["主旨"] == "下週會議資料與 VPN 帳號"
    assert "imap.secure.example" not in {f["details"].get("SNI 網域") for f in findings}


def test_demo_end_to_end():
    def feed(engine):
        for p in all_packets():
            feed_packet(engine, p)
    findings, stats = _run(feed)
    _check(findings)
    assert stats["encrypted_sessions"] >= 4 and stats["plaintext_sessions"] >= 8


def test_demo_pcap_roundtrip(tmp_path):
    from scapy.utils import wrpcap

    path = tmp_path / "demo.pcap"
    wrpcap(str(path), all_packets())
    findings, _ = _run(lambda engine: read_pcap(engine, str(path)))
    _check(findings)
