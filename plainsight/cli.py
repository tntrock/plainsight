"""Command line entry point."""
from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
import webbrowser
from pathlib import Path

from . import __version__
from .engine import Engine
from .hub import Hub
from .server import LOOPBACK, make_server

BANNER = r"""
  ____  _       _       ____  _       _     _
 |  _ \| | __ _(_)_ __ / ___|(_) __ _| |__ | |_
 | |_) | |/ _` | | '_ \\___ \| |/ _` | '_ \| __|
 |  __/| | (_| | | | | |___) | | (_| | | | | |_
 |_|   |_|\__,_|_|_| |_|____/|_|\__, |_| |_|\__|
        明文透視 v{version}             |___/   教育用途
"""

LIVE_WARNING = """
==================================================================
  即時擷取前請確認：
  - 只能在你擁有、或已取得管理者「書面授權」的網路上使用。
  - 未經同意擷取他人通訊，可能觸犯刑法妨害秘密罪（§315-1）、
    妨害電腦使用罪（§358-§363）與個人資料保護法。
  - 本工具只被動觀察「經過這台電腦網卡」的流量，不會發動
    ARP 欺騙等主動攻擊。在交換器網路上，你通常只看得到自己
    與廣播的流量，這是正常的。
==================================================================
"""

MODES = {"demo": "示範模式", "pcap": "離線分析", "live": "即時擷取", "mitm": "MITM 代理"}


def _console_safe() -> None:
    if sys.platform == "win32":
        try:  # a double-clicked exe gets a legacy code page console
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            encoding = "utf-8"
        except (AttributeError, OSError):
            encoding = None
    else:
        encoding = None
    for stream in (sys.stdout, sys.stderr):
        try:
            if encoding:
                stream.reconfigure(encoding=encoding, errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def _start_dashboard(args, mode: str, source: str) -> tuple[Hub, Engine, str]:
    hub = Hub(show_secrets=args.show_secrets)
    engine = Engine(hub.publish, hub.stats)
    meta = {
        "mode": mode, "mode_label": MODES[mode], "source": source, "version": __version__,
        "addon_path": str(Path(__file__).with_name("mitm_addon.py")),
    }
    for port in range(args.port, args.port + 10):
        try:
            srv = make_server(hub, args.host, port, meta)
            break
        except OSError:  # port in use, e.g. a second copy is already running
            continue
    else:
        raise SystemExit(f"埠號 {args.port}-{args.port + 9} 都被占用，請用 --port 指定其他埠號。")
    if srv.server_address[1] != 8765 and mode == "mitm":
        print(f"  [注意] 儀表板不在預設埠 8765，執行 mitmdump 前請設定 PLAINSIGHT_URL=http://127.0.0.1:{srv.server_address[1]}")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    shown = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    url = f"http://{shown}:{srv.server_address[1]}/"
    print(BANNER.format(version=__version__))
    print(f"  儀表板：{url}")
    print(f"  模式：{MODES[mode]}  {source}")
    print(f"  機密遮蔽：{'關閉（顯示完整內容）' if args.show_secrets else '開啟（只顯示頭尾字元）'}")
    if args.host not in LOOPBACK:
        print("\n  [注意] 儀表板對外開放，同網路的人都能看到擷取結果！")
    print()
    if not args.no_browser:
        webbrowser.open(url)
    return hub, engine, url


def _wait_forever() -> None:
    print("  儀表板持續開啟中，按 Ctrl+C 結束。")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def cmd_demo(args) -> int:
    from .capture import feed_packet
    from .demo import all_packets, build_scenes

    if args.write_pcap:
        from scapy.utils import wrpcap
        wrpcap(args.write_pcap, all_packets())
        print(f"已寫出示範封包：{args.write_pcap}（可用 Wireshark 開啟對照）")
        return 0

    _, engine, _ = _start_dashboard(args, "demo", "內建模擬流量")
    time.sleep(1.5 / args.speed)  # give the browser a moment to connect
    try:
        while True:
            for i, (narration, packets) in enumerate(build_scenes(), 1):
                print(f"  [{i:02d}] {narration}")
                for p in packets:
                    feed_packet(engine, p)
                    time.sleep(0.01 / args.speed)
                time.sleep(2.5 / args.speed)
            if not args.loop:
                break
            engine.sessions.clear()
    except KeyboardInterrupt:
        return 0
    print("\n  示範流量播放完畢。")
    _wait_forever()
    return 0


def cmd_pcap(args) -> int:
    from .capture import read_pcap

    path = Path(args.file)
    if not path.is_file():
        print(f"找不到檔案：{path}", file=sys.stderr)
        return 2
    _, engine, _ = _start_dashboard(args, "pcap", path.name)
    try:
        n = read_pcap(engine, str(path), realtime=args.realtime)
    except KeyboardInterrupt:
        return 0
    except Exception as e:  # scapy raises plain Scapy_Exception for bad files
        print(f"讀取 pcap 失敗：{e}", file=sys.stderr)
        return 1
    print(f"  已分析 {n} 個封包。")
    _wait_forever()
    return 0


def cmd_live(args) -> int:
    from . import interfaces

    try:
        names = interfaces.resolve(args.iface, interfaces.load())
    except ValueError as e:
        print(f"  {e}", file=sys.stderr)
        return 2
    print(LIVE_WARNING)
    if not args.yes:
        try:
            answer = input("  我確認擁有此網路或已取得授權，並了解相關法律責任 [y/N]：")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("  已取消。")
            return 1
    from .capture import sniff_live

    _, engine, _ = _start_dashboard(args, "live", " + ".join(names) or "預設網卡")
    print(f"  擷取中：{'、'.join(names) or '系統預設網卡'}（按 Ctrl+C 結束）")
    try:
        sniff_live(engine, names, args.bpf)
    except KeyboardInterrupt:
        pass
    except (PermissionError, OSError, RuntimeError) as e:
        print(f"\n  無法擷取封包：{e}", file=sys.stderr)
        if sys.platform == "win32":
            print("  Windows 需要先安裝 Npcap（https://npcap.com），並以系統管理員身分執行。", file=sys.stderr)
        else:
            print("  請以 sudo 執行，或給 python 設定 cap_net_raw,cap_net_admin 權限。", file=sys.stderr)
        return 1
    return 0


def cmd_mitm(args) -> int:
    _, _, url = _start_dashboard(args, "mitm", "等待 mitmproxy 送入資料")
    addon = Path(__file__).with_name("mitm_addon.py")
    print("  在另一個終端機執行（需先 pip install mitmproxy）：")
    print(f'    mitmdump -s "{addon}" --listen-port 8080')
    if args.port != 8765 or args.host != "127.0.0.1":
        print(f"  並設定環境變數 PLAINSIGHT_URL={url.rstrip('/')}")
    print("  接著把「你自己的實驗裝置」的 HTTP 代理設為本機 IP:8080，")
    print("  再到 http://mitm.it 安裝憑證（實驗結束務必移除！）。詳見 docs/lab-guide.md\n")
    _wait_forever()
    return 0


def cmd_ifaces(args) -> int:
    from . import interfaces

    try:
        found = interfaces.load()
    except Exception as e:
        print(f"無法列出網卡：{e}", file=sys.stderr)
        return 1
    print()
    print(interfaces.format_table(found, show_all=getattr(args, "all", False)))
    print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", default="127.0.0.1", help="儀表板監聽位址（預設只限本機）")
    common.add_argument("--port", type=int, default=8765, help="儀表板埠號（預設 8765）")
    common.add_argument("--show-secrets", action="store_true",
                        help="顯示完整密碼等機密（預設只顯示頭尾字元）")
    common.add_argument("--no-browser", action="store_true", help="不要自動開啟瀏覽器")

    p = argparse.ArgumentParser(prog="plainsight", description="PlainSight 明文透視：看看未加密的流量洩漏了什麼（教育用途）")
    p.add_argument("--version", action="version", version=f"plainsight {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="指令")

    d = sub.add_parser("demo", parents=[common], help="播放內建模擬流量（不需權限，適合課堂）")
    d.add_argument("--speed", type=float, default=1.0, help="播放速度倍率")
    d.add_argument("--loop", action="store_true", help="重複播放")
    d.add_argument("--write-pcap", metavar="FILE", help="只把示範封包寫成 pcap 檔後結束")
    d.set_defaults(func=cmd_demo)

    r = sub.add_parser("pcap", parents=[common], help="分析 pcap / pcapng 檔案")
    r.add_argument("file")
    r.add_argument("--realtime", action="store_true", help="依原始時間間隔播放")
    r.set_defaults(func=cmd_pcap)

    lv = sub.add_parser("live", parents=[common], help="即時擷取網卡流量（需授權與管理員權限）")
    lv.add_argument("-i", "--iface", action="append", metavar="網卡",
                    help="網卡編號或名稱（用 `plainsight ifaces` 查詢）；多張可用逗號分隔或重複 -i")
    lv.add_argument("--bpf", default="tcp or udp port 53 or udp port 5353 or udp port 5355",
                    help="BPF 擷取過濾條件")
    lv.add_argument("--yes", action="store_true", help="略過授權確認提示")
    lv.set_defaults(func=cmd_live)

    m = sub.add_parser("mitm", parents=[common], help="搭配 mitmproxy 展示 HTTPS 被中間人解密")
    m.set_defaults(func=cmd_mitm)

    i = sub.add_parser("ifaces", help="列出可擷取的網卡")
    i.add_argument("--all", action="store_true", help="也顯示沒有 IP 的網卡與系統篩選驅動程式")
    i.set_defaults(func=cmd_ifaces)
    return p


MENU = """
  請選擇要做什麼：

    1. 示範模式    播放內建模擬流量（推薦第一次使用、課堂展示）
    2. 分析 pcap   開啟 Wireshark / tcpdump 錄下的封包檔
    3. 即時擷取    擷取這台電腦網卡的流量（需 Npcap 與授權）
    4. MITM 代理   搭配 mitmproxy 示範 HTTPS 被解密
    5. 列出網卡
    0. 離開

  小技巧：把 .pcap / .pcapng 檔案直接拖到 PlainSight.exe 上就會開始分析。
"""


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def _pick_interfaces() -> list[str]:
    from . import interfaces

    found = interfaces.load()
    print()
    print(interfaces.format_table(found))
    while True:
        print()
        answer = _ask("  要擷取哪張網卡？輸入編號（多張用逗號分隔，直接按 Enter 用預設網卡）：")
        if not answer:
            return []
        try:
            interfaces.resolve([answer], found)  # validate before leaving the menu
        except ValueError as e:
            print(f"  {e}")
            continue
        return ["-i", answer]


def interactive_argv() -> list[str] | None:
    """Menu shown when the program is started without arguments (double-click)."""
    print(BANNER.format(version=__version__))
    print(MENU)
    while True:
        choice = _ask("  請輸入編號：")
        if choice == "1":
            return ["demo"]
        if choice == "2":
            path = _ask("  請輸入檔案路徑（也可以把檔案拖進這個視窗）：").strip('"').strip("'")
            if path:
                return ["pcap", path]
        elif choice == "3":
            return ["live"] + _pick_interfaces()
        elif choice == "4":
            return ["mitm"]
        elif choice == "5":
            cmd_ifaces(None)
        elif choice in ("0", "q", "exit"):
            return None


def main(argv: list[str] | None = None) -> int:
    _console_safe()
    interactive = False
    if argv is None:
        argv = sys.argv[1:]
        if not argv:
            interactive = True
            argv = interactive_argv()
            if argv is None:
                return 0
        elif len(argv) == 1 and not argv[0].startswith("-") and Path(argv[0]).is_file():
            argv = ["pcap", argv[0]]  # a file dropped onto the exe
            interactive = True
    try:
        return _run(argv)
    finally:
        if interactive and getattr(sys, "frozen", False):
            print()
            _ask("  按 Enter 關閉視窗…")  # keep errors readable before the console closes


def _run(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    if args.cmd != "live":  # "no libpcap provider" only matters for live capture
        logging.getLogger("scapy").setLevel(logging.ERROR)
    if getattr(args, "speed", 1.0) <= 0:
        args.speed = 1.0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
