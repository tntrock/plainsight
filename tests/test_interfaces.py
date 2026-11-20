import pytest

from plainsight.interfaces import Iface, arrange, format_table, resolve


def windows_like():
    """Shaped after a real Windows 11 machine with WSL and the mobile hotspot on."""
    return arrange([
        Iface("乙太網路", "Intel(R) Ethernet Connection (17) I219-V", ["140.124.1.9"], mac="10:7c:61:bb:65:63",
              is_default=True),
        Iface("乙太網路-WFP Native MAC Layer LightWeight Filter-0000", "Intel(R) Ethernet", ["140.124.1.9"]),
        Iface("乙太網路-QoS Packet Scheduler-0000", "Intel(R) Ethernet"),
        Iface("vEthernet (WSL (Hyper-V firewall))", "Hyper-V Virtual Ethernet Adapter", ["172.30.176.1"]),
        Iface("Loopback Pseudo-Interface 1", "Software Loopback Interface 1", ["127.0.0.1"], ["::1"]),
        Iface("區域連線* 10", "Microsoft Wi-Fi Direct Virtual Adapter #2", ["192.168.137.1"]),
        Iface("Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz", ["192.168.1.20"]),
        Iface("區域連線* 6", "WAN Miniport (IP)"),
        Iface("Teredo Tunneling Pseudo-Interface", "Microsoft Teredo Tunneling Adapter", [], ["fe80::1"]),
    ])


def test_arrange_hides_filter_drivers_and_orders_by_usefulness():
    numbered = [(i.number, i.name, i.label) for i in windows_like() if i.number]
    assert numbered == [
        (1, "乙太網路", "有線網卡"),
        (2, "區域連線* 10", "行動熱點"),
        (3, "Wi-Fi", "無線網卡"),
        (4, "vEthernet (WSL (Hyper-V firewall))", "虛擬網卡"),
        (5, "Loopback Pseudo-Interface 1", "本機迴路"),
    ]


def test_linux_labels():
    labels = {i.name: i.label for i in arrange([
        Iface("eth0", ipv4=["10.0.0.2"]), Iface("wlan0", ipv4=["10.0.1.2"]), Iface("lo", ipv4=["127.0.0.1"]),
        Iface("docker0", ipv4=["172.17.0.1"]), Iface("tun0", ipv4=["10.8.0.2"]),
    ])}
    assert labels == {"eth0": "有線網卡", "wlan0": "無線網卡", "lo": "本機迴路", "docker0": "虛擬網卡", "tun0": "虛擬網卡"}


def test_resolve_numbers_names_and_multiple():
    ifs = windows_like()
    assert resolve(None, ifs) == []
    assert resolve(["2"], ifs) == ["區域連線* 10"]
    assert resolve(["1, 2"], ifs) == ["乙太網路", "區域連線* 10"]
    assert resolve(["wi-fi", "3", '"區域連線* 6"'], ifs) == ["Wi-Fi", "區域連線* 6"]  # dedup; hidden by name ok
    assert resolve(["2,乙太網路"], ifs) == ["區域連線* 10", "乙太網路"]


@pytest.mark.parametrize("spec, msg", [("9", "沒有編號 9"), ("nope", "找不到網卡")])
def test_resolve_errors(spec, msg):
    with pytest.raises(ValueError, match=msg):
        resolve([spec], windows_like())


def test_format_table_aligns_cjk_and_mentions_hidden():
    text = format_table(windows_like())
    rows = [line for line in text.splitlines() if line.startswith("  ") and line.strip()[:1].isdigit()]
    assert len(rows) == 5
    assert "乙太網路 *" in rows[0]
    assert "另有 4 個" in text
    assert "QoS" in format_table(windows_like(), show_all=True)
