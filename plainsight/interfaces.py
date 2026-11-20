"""Listing and choosing capture interfaces.

Scapy lists every adapter Windows knows about, including dozens of filter
drivers and WAN Miniports. This module keeps the ones worth capturing on,
numbers them, and lets users pick by number or name (several at once).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Windows exposes each NDIS filter driver as its own "adapter", e.g.
# "乙太網路-WFP Native MAC Layer LightWeight Filter-0000".
FILTER_DRIVER = re.compile(r"-[^-]*(Filter|Scheduler|Extension)[^-]*-\d{4}$", re.I)

LABEL_ORDER = ["行動熱點", "無線網卡", "有線網卡", "虛擬網卡", "本機迴路"]
# Matched against name + description (Windows adapters, VPN clients).
_VIRTUAL_WORDS = ("hyper-v", "vethernet", "vswitch", "virtualbox", "vmware", "wsl", "docker", "wan miniport",
                  "vpn", "teredo", "6to4", "ip-https", "pseudo", "zerotier", "tailscale", "wireguard",
                  "kernel debug", "tap-windows")
# Matched against the start of Linux / macOS interface names.
_VIRTUAL_PREFIXES = ("docker", "veth", "virbr", "br-", "tap", "tun", "utun", "bridge", "vmnet", "awdl", "llw")


@dataclass
class Iface:
    name: str
    description: str = ""
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    mac: str = ""
    is_default: bool = False
    number: int = 0  # 1-based position in the usable list; 0 = hidden

    @property
    def label(self) -> str:
        text = f"{self.name} {self.description}".lower()
        if "loopback" in text or self.name in ("lo", "lo0") or any(ip.startswith("127.") for ip in self.ipv4):
            return "本機迴路"
        # Windows "Mobile hotspot" uses a Wi-Fi Direct adapter on 192.168.137.0/24.
        if "wi-fi direct" in text or any(ip.startswith("192.168.137.") for ip in self.ipv4):
            return "行動熱點"
        if any(k in text for k in _VIRTUAL_WORDS) or self.name.lower().startswith(_VIRTUAL_PREFIXES):
            return "虛擬網卡"
        if any(k in text for k in ("wi-fi", "wifi", "wireless", "wlan", "802.11")) or self.name.startswith("wl"):
            return "無線網卡"
        return "有線網卡"

    @property
    def usable(self) -> bool:
        if FILTER_DRIVER.search(self.name):
            return False
        return bool(self.ipv4 or [ip for ip in self.ipv6 if not ip.lower().startswith("fe80")])


def arrange(ifaces: list[Iface]) -> list[Iface]:
    """Number the usable interfaces: default first, then hotspot, Wi-Fi, wired…"""
    usable = [i for i in ifaces if i.usable]
    usable.sort(key=lambda i: (not i.is_default, LABEL_ORDER.index(i.label), i.name.lower()))
    for n, i in enumerate(usable, 1):
        i.number = n
    hidden = sorted((i for i in ifaces if not i.usable), key=lambda i: i.name.lower())
    for i in hidden:
        i.number = 0
    return usable + hidden


def load() -> list[Iface]:
    """All interfaces Scapy knows about, arranged and numbered."""
    from scapy.all import conf  # importing scapy.all fills conf.ifaces for this platform

    default = conf.iface
    default_name = getattr(default, "name", default)
    out = []
    for i in conf.ifaces.values():
        ips = getattr(i, "ips", {}) or {}
        out.append(Iface(
            name=i.name, description=getattr(i, "description", "") or "",
            ipv4=list(ips.get(4, [])), ipv6=list(ips.get(6, [])),
            mac=getattr(i, "mac", "") or "", is_default=i.name == default_name,
        ))
    return arrange(out)


def resolve(specs: list[str] | None, ifaces: list[Iface]) -> list[str]:
    """Turn user input ('2', '1,3', '乙太網路') into Scapy interface names."""
    return [i.name for i in pick(specs, ifaces)]


def pick(specs: list[str] | None, ifaces: list[Iface]) -> list[Iface]:
    """Like resolve(), but returns the Iface objects."""
    if not specs:
        return []
    by_number = {i.number: i for i in ifaces if i.number}
    by_name = {i.name.lower(): i for i in ifaces}
    names: list[Iface] = []
    for spec in specs:
        spec = spec.strip().strip('"').strip("'")
        # An exact name wins, so a name that happens to contain a comma still works.
        parts = [spec] if spec.lower() in by_name else [p.strip().strip('"') for p in spec.split(",")]
        for part in filter(None, parts):
            if part.isdigit():
                if int(part) not in by_number:
                    raise ValueError(f"沒有編號 {part} 的網卡（可用編號：1-{len(by_number)}）")
                names.append(by_number[int(part)])
            elif part.lower() in by_name:
                names.append(by_name[part.lower()])
            else:
                raise ValueError(f"找不到網卡「{part}」，請用 `plainsight ifaces` 查看編號與名稱")
    return list({i.name: i for i in names}.values())  # drop duplicates, keep order


def _width(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def _cell(s: str, width: int) -> str:
    if _width(s) > width:
        while _width(s + "…") > width:
            s = s[:-1]
        s += "…"
    return s + " " * (width - _width(s))


def format_table(ifaces: list[Iface], show_all: bool = False) -> str:
    rows = [i for i in ifaces if show_all or i.number]
    lines = [f"  {_cell('編號', 4)}  {_cell('網卡名稱', 30)}  {_cell('類型', 8)}  {_cell('IPv4', 16)}  說明"]
    lines.append("  " + "-" * 92)
    for i in rows:
        num = str(i.number) if i.number else "-"
        name = i.name + (" *" if i.is_default else "")
        lines.append(f"  {_cell(num, 4)}  {_cell(name, 30)}  {_cell(i.label, 8)}  "
                     f"{_cell(', '.join(i.ipv4) or '-', 16)}  {_cell(i.description, 34)}")
    if not rows:
        lines.append("  （沒有找到有 IP 位址的網卡；用 --all 查看全部）")
    lines.append("")
    lines.append("  * = 系統預設網卡。用編號或名稱選擇，例如：plainsight live -i 1  或  -i 1,3（同時擷取多張）")
    if not show_all:
        hidden = sum(1 for i in ifaces if not i.number)
        if hidden:
            lines.append(f"  另有 {hidden} 個沒有 IP 的網卡或系統篩選驅動程式已隱藏，用 `plainsight ifaces --all` 查看。")
    return "\n".join(lines)
