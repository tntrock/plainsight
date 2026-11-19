"""DNS / mDNS / LLMNR queries: which names a device is looking up."""
from __future__ import annotations

import struct

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
UDP_PORTS = {53: "DNS", 5353: "mDNS", 5355: "LLMNR"}


def _read_name(data: bytes, p: int) -> tuple[str, int]:
    labels = []
    end = None
    for _ in range(128):  # guards against compression loops
        n = data[p]
        if n == 0:
            p += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = p + 2
            p = struct.unpack_from("!H", data, p)[0] & 0x3FFF
            continue
        labels.append(data[p + 1:p + 1 + n].decode("utf-8", "replace"))
        p += 1 + n
    return ".".join(labels), (end if end is not None else p)


def parse_dns_query(data: bytes) -> tuple[str, str] | None:
    """Return (name, qtype) for a DNS query packet, None for responses or junk."""
    try:
        if len(data) < 12:
            return None
        flags, qdcount = struct.unpack_from("!HH", data, 2)
        if flags & 0x8000 or qdcount < 1:
            return None
        name, p = _read_name(data, 12)
        qtype = struct.unpack_from("!H", data, p)[0]
        return name, QTYPES.get(qtype, str(qtype))
    except (IndexError, struct.error):
        return None


def build_dns_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)
