import socket
import subprocess
import sys
import threading

import pytest

pytest.importorskip("scapy")

from traffic import all_packets  # noqa: E402

from plainsight.capture import feed_packet, read_pcap, sniff_raw  # noqa: E402
from plainsight.engine import Engine  # noqa: E402
from plainsight.hub import Hub  # noqa: E402


def _run(feed):
    hub = Hub()
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
    assert "Vpn#2026temp" in mail["secrets"]["body"]
    assert "imap.secure.example" not in {f["details"].get("SNI 網域") for f in findings}


@pytest.fixture(scope="module")
def pcap_file(tmp_path_factory):
    from scapy.utils import wrpcap

    path = tmp_path_factory.mktemp("pcap") / "lab.pcap"
    wrpcap(str(path), all_packets())
    return path


def test_packets_end_to_end():
    def feed(engine):
        for p in all_packets():
            feed_packet(engine, p)
    findings, stats = _run(feed)
    _check(findings)
    assert stats["encrypted_sessions"] >= 4 and stats["plaintext_sessions"] >= 8


def test_pcap_roundtrip(pcap_file):
    findings, _ = _run(lambda engine: read_pcap(engine, str(pcap_file)))
    _check(findings)


def test_read_pcap_in_fresh_interpreter(pcap_file):
    """Regression: reading a pcap before any scapy layer was imported decoded nothing."""
    code = ("import sys; from plainsight.engine import Engine; from plainsight.capture import read_pcap; "
            "found = []; read_pcap(Engine(found.append), sys.argv[1]); print(len(found))")
    out = subprocess.run([sys.executable, "-c", code, str(pcap_file)], capture_output=True, text=True, check=True)
    assert int(out.stdout.strip()) > 20


def test_cli_report_prints_secrets_and_exits(pcap_file, capsys):
    from plainsight.cli import main

    assert main(["pcap", str(pcap_file), "--report"]) == 0
    out = capsys.readouterr().out
    assert "[嚴重] HTTP" in out and "密碼：Sup3rS3cret!" in out and "密碼：Sw1tch!pass" in out
    assert "DNS 查詢" not in out and "瀏覽足跡" in out
    assert main(["pcap", str(pcap_file), "--report", "--info"]) == 0
    assert "DNS 查詢：forum.example" in capsys.readouterr().out


def test_sniff_raw_reads_ip_packets_from_sockets():
    """The Windows raw-socket backend hands whole IPv4 packets to the engine.

    A UDP socket pair stands in for the raw socket (one datagram = one packet),
    so this runs without administrator rights on any OS.
    """
    from scapy.layers.inet import IP, TCP

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pkts = [IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=40000, dport=21, flags="PA", seq=1, ack=1) / data
            for data in (b"USER eve\r\n", b"PASS rawpw\r\n")]
    pkts[1][TCP].seq = 1 + len(b"USER eve\r\n")

    hub = Hub()
    stop = threading.Event()
    reader = threading.Thread(target=sniff_raw, args=(Engine(hub.publish, hub.stats), [rx], stop))
    reader.start()
    tx.sendto(b"\x60not-ipv4", rx.getsockname())  # IPv6 / junk is skipped
    for p in pkts:
        tx.sendto(bytes(p), rx.getsockname())
    for _ in range(50):
        if hub.snapshot():
            break
        threading.Event().wait(0.05)
    stop.set()
    reader.join(5)
    tx.close()
    creds = [f for f in hub.snapshot() if f["kind"] == "credential"]
    assert creds and creds[0]["secrets"] == {"username": "eve", "password": "rawpw"}
