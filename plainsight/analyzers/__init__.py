"""Protocol analyzers. Each one turns a reassembled TCP stream into Findings."""
from __future__ import annotations

from .base import NullAnalyzer, StreamAnalyzer
from .ftp import UserPassAnalyzer
from .http import HttpAnalyzer, looks_like_http_request
from .mail import ImapAnalyzer, SmtpAnalyzer
from .telnet import TelnetAnalyzer
from .tls import TlsAnalyzer, looks_like_tls


def _userpass(protocol: str):
    return lambda client, server: UserPassAnalyzer(client, server, protocol)


PORT_ANALYZERS = {
    80: HttpAnalyzer, 8000: HttpAnalyzer, 8008: HttpAnalyzer, 8080: HttpAnalyzer, 8888: HttpAnalyzer,
    21: _userpass("FTP"),
    23: TelnetAnalyzer,
    25: SmtpAnalyzer, 587: SmtpAnalyzer, 2525: SmtpAnalyzer,
    110: _userpass("POP3"),
    143: ImapAnalyzer,
    443: TlsAnalyzer, 465: TlsAnalyzer, 853: TlsAnalyzer, 993: TlsAnalyzer, 995: TlsAnalyzer, 8443: TlsAnalyzer,
}


def sniff_analyzer(first_client_data: bytes):
    """Pick an analyzer from the content, so HTTP on odd ports is still found."""
    if looks_like_http_request(first_client_data):
        return HttpAnalyzer
    if looks_like_tls(first_client_data):
        return TlsAnalyzer
    return None


__all__ = ["PORT_ANALYZERS", "NullAnalyzer", "StreamAnalyzer", "HttpAnalyzer", "TlsAnalyzer",
           "sniff_analyzer"]
