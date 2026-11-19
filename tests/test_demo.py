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


def test_read_pcap_in_fresh_interpreter(tmp_path):
    """Regression: reading a pcap before any scapy layer was imported decoded nothing."""
    import subprocess
    import sys
    from scapy.utils import wrpcap

    path = tmp_path / "demo.pcap"
    wrpcap(str(path), all_packets())
    code = ("import sys; from plainsight.engine import Engine; from plainsight.capture import read_pcap; "
            "found = []; read_pcap(Engine(found.append), sys.argv[1]); print(len(found))")
    out = subprocess.run([sys.executable, "-c", code, str(path)], capture_output=True, text=True, check=True)
    assert int(out.stdout.strip()) > 20


def test_cli_writes_demo_pcap(tmp_path):
    from plainsight.cli import main

    out = tmp_path / "d.pcap"
    assert main(["demo", "--write-pcap", str(out)]) == 0
    findings, _ = _run(lambda engine: read_pcap(engine, str(out)))
    _check(findings)
