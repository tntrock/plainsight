"""Command line entry point."""
from __future__ import annotations

import argparse
import logging
import os
import subprocess
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

MODES = {"pcap": "離線分析", "live": "即時擷取", "mitm": "MITM 代理"}
SEVERITY = {"critical": "嚴重", "high": "高", "medium": "中", "info": "資訊"}
SECRET_LABEL = {"username": "帳號", "password": "密碼", "encoded": "線路原文", "encoded_user": "帳號(Base64)",
                "encoded_password": "密碼(Base64)", "token": "權杖", "cookie": "Cookie", "body": "內文"}


def _console_safe() -> None:
    encoding = None
    if sys.platform == "win32":
        try:  # a double-clicked exe gets a legacy code page console
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            encoding = "utf-8"
        except (AttributeError, OSError):
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            if encoding:
                stream.reconfigure(encoding=encoding, errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def _start_dashboard(args, mode: str, source: str) -> tuple[Hub, Engine, str]:
    hub = Hub()
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
    if args.host not in LOOPBACK:
        print("\n  [注意] 儀表板對外開放，同網路的人都能看到擷取到的帳號密碼！")
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


# ---------------------------------------------------------------- pcap
def _print_report(hub: Hub, packets: int, show_info: bool) -> None:
    order = list(SEVERITY)
    items = sorted(hub.snapshot(), key=lambda f: (order.index(f["severity"]), f["id"]))
    counts = {s: sum(f["severity"] == s for f in items) for s in order}
    print(f"\n  共 {packets} 個封包，{len(items)} 筆發現："
          + "、".join(f"{SEVERITY[s]} {n}" for s, n in counts.items()) + "\n")
    for f in items:
        if f["severity"] == "info" and not show_info:
            continue
        print(f"  [{SEVERITY[f['severity']]}] {f['protocol']:<6} {f['title']}")
        print(f"           {f['src']} → {f['dst']}")
        for k, v in f["secrets"].items():
            if v:
                print(f"           {SECRET_LABEL.get(k, k)}：{v if len(v) <= 200 else v[:200] + '…'}")
    if counts["info"] and not show_info:
        print(f"\n  另有 {counts['info']} 筆瀏覽足跡（網址、DNS、SNI），加上 --info 一併列出。")


def cmd_pcap(args) -> int:
    from .capture import read_pcap

    path = Path(args.file)
    if not path.is_file():
        print(f"找不到檔案：{path}", file=sys.stderr)
        return 2
    if args.report:
        hub = Hub()
        engine = Engine(hub.publish, hub.stats)
    else:
        hub, engine, _ = _start_dashboard(args, "pcap", path.name)
    try:
        n = read_pcap(engine, str(path), realtime=args.realtime and not args.report)
    except KeyboardInterrupt:
        return 0
    except Exception as e:  # scapy raises plain Scapy_Exception for bad files
        print(f"讀取 pcap 失敗：{e}", file=sys.stderr)
        return 1
    if args.report:
        _print_report(hub, n, args.info)
        return 0
    print(f"  已分析 {n} 個封包。")
    _wait_forever()
    return 0


# ---------------------------------------------------------------- live
def _relaunch_as_admin(argv: list[str]) -> bool:
    """Start this program again with a UAC prompt. True if the new process started."""
    import ctypes

    if getattr(sys, "frozen", False):
        params = argv
    else:
        params = ["-m", "plainsight", *argv]
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                             subprocess.list2cmdline(params), os.getcwd(), 1)
    return rc > 32


def cmd_live(args) -> int:
    from . import capture, interfaces

    try:
        found = interfaces.load()
        chosen = interfaces.pick(args.iface, found)
    except ValueError as e:
        print(f"  {e}", file=sys.stderr)
        return 2
    targets = chosen or [i for i in found if i.is_default][:1]

    backend = args.backend
    if backend == "auto":
        backend = "npcap" if capture.npcap_installed() else "raw"
    if sys.platform != "win32" and backend == "raw":
        print("  --backend raw 只支援 Windows。", file=sys.stderr)
        return 2
    if backend == "npcap" and not capture.npcap_installed():
        print("  尚未安裝 Npcap。執行 `plainsight install-npcap` 安裝，或改用 --backend raw（Windows 內建擷取）。",
              file=sys.stderr)
        return 2
    if backend == "raw":
        missing = [i.name for i in targets if not i.ipv4]
        if not targets or missing:
            print(f"  Windows 內建擷取需要有 IPv4 位址的網卡：{'、'.join(missing) or '找不到預設網卡'}", file=sys.stderr)
            return 2

    print(LIVE_WARNING)
    if not args.yes and _ask("  我確認擁有此網路或已取得授權，並了解相關法律責任 [y/N]：").lower() not in ("y", "yes"):
        print("  已取消。")
        return 1

    if backend == "raw" and not capture.is_admin():
        reason = "使用" if args.backend == "raw" else "未安裝 Npcap，改用"
        print(f"\n  {reason} Windows 內建擷取，這需要系統管理員權限。")
        if _ask("  要以系統管理員身分重新開啟嗎？（會跳出 UAC 確認）[Y/n]：").lower() in ("", "y", "yes"):
            if _relaunch_as_admin([*args.argv, "--yes", "--keep-open"]):
                print("  已在新視窗以系統管理員身分啟動，這個視窗可以關閉。")
                return 0
            print("  未取得系統管理員權限。", file=sys.stderr)
        return 1

    names = [i.name for i in targets]
    label = " + ".join(names) or "系統預設網卡"
    if backend == "raw":
        try:
            socks = capture.open_raw_sockets([i.ipv4[0] for i in targets])
        except OSError as e:
            print(f"\n  無法開始擷取：{e}", file=sys.stderr)
            return 1
        _, engine, _ = _start_dashboard(args, "live", f"{label}（Windows 內建擷取）")
        print("  擷取引擎：Windows 內建（僅 IPv4）。安裝 Npcap 可擷取 IPv6 與完整乙太網路封包。")
        print(f"  擷取中：{label}（按 Ctrl+C 結束）")
        try:
            capture.sniff_raw(engine, socks)
        except KeyboardInterrupt:
            pass
        return 0

    _, engine, _ = _start_dashboard(args, "live", label)
    print(f"  擷取中：{label}（按 Ctrl+C 結束）")
    try:
        capture.sniff_live(engine, names, args.bpf)
    except KeyboardInterrupt:
        pass
    except (PermissionError, OSError, RuntimeError) as e:
        print(f"\n  無法擷取封包：{e}", file=sys.stderr)
        if sys.platform == "win32":
            print("  請以系統管理員身分執行，或改用 --backend raw。", file=sys.stderr)
        else:
            print("  請以 sudo 執行，或給 python 設定 cap_net_raw,cap_net_admin 權限。", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------- other commands
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


def _capture_engine_line() -> str:
    from .capture import npcap_installed

    if sys.platform != "win32":
        return "  擷取引擎：libpcap"
    if npcap_installed():
        return "  擷取引擎：Npcap（已安裝）"
    return ("  擷取引擎：Windows 內建（未安裝 Npcap；僅 IPv4、需系統管理員）。"
            "執行 `plainsight install-npcap` 可取得完整功能。")


def cmd_ifaces(args) -> int:
    from . import interfaces

    try:
        found = interfaces.load()
    except Exception as e:
        print(f"無法列出網卡：{e}", file=sys.stderr)
        return 1
    print()
    print(interfaces.format_table(found, show_all=getattr(args, "all", False)))
    print(_capture_engine_line())
    print()
    return 0


def cmd_install_npcap(args) -> int:
    from . import npcap
    from .capture import npcap_installed

    if sys.platform != "win32":
        print("只有 Windows 需要 Npcap；Linux / macOS 已內建 libpcap。")
        return 0
    if npcap_installed() and not args.force:
        print("Npcap 已安裝。（要重新安裝請加 --force）")
        return 0
    print("\n  Npcap 免費版的授權不允許隨程式重新散布，所以由這裡向官方網站 npcap.com")
    print("  下載最新安裝檔、驗證數位簽章後啟動安裝程式。安裝時請閱讀並同意 Npcap 的授權條款。\n")

    def progress(done: int, total: int) -> None:
        pct = f"{done * 100 // total:3d}%" if total else f"{done // 1024} KB"
        print(f"\r  下載中… {pct}", end="", flush=True)

    try:
        url = npcap.latest_installer_url()
        print(f"  {url}")
        path = npcap.download(url, progress)
        print()
        signer = npcap.verify_signature(path)
        print(f"  數位簽章有效：{signer.split(',')[0].removeprefix('CN=')}")
        npcap.launch_installer(path)
    except Exception as e:
        print(f"\n  安裝失敗：{e}", file=sys.stderr)
        print("  也可以手動到 https://npcap.com 下載安裝。", file=sys.stderr)
        return 1
    print("  已開啟 Npcap 安裝程式，請依畫面完成安裝（建議保留預設選項）。")
    print("  安裝完成後重新啟動 PlainSight，即時擷取就會自動改用 Npcap。")
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", default="127.0.0.1", help="儀表板監聽位址（預設只限本機）")
    common.add_argument("--port", type=int, default=8765, help="儀表板埠號（預設 8765）")
    common.add_argument("--no-browser", action="store_true", help="不要自動開啟瀏覽器")

    p = argparse.ArgumentParser(prog="plainsight", description="PlainSight 明文透視：看看未加密的流量洩漏了什麼（教育用途）")
    p.add_argument("--version", action="version", version=f"plainsight {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="指令")

    r = sub.add_parser("pcap", parents=[common], help="分析 pcap / pcapng 檔案")
    r.add_argument("file")
    r.add_argument("--realtime", action="store_true", help="依原始時間間隔播放")
    r.add_argument("--report", action="store_true", help="不開儀表板，直接在終端機列出結果後結束")
    r.add_argument("--info", action="store_true", help="報告中也列出網址、DNS、SNI 等瀏覽足跡")
    r.set_defaults(func=cmd_pcap)

    lv = sub.add_parser("live", parents=[common], help="即時擷取網卡流量（需授權）")
    lv.add_argument("-i", "--iface", action="append", metavar="網卡",
                    help="網卡編號或名稱（用 `plainsight ifaces` 查詢）；多張可用逗號分隔或重複 -i")
    lv.add_argument("--backend", choices=("auto", "npcap", "raw"), default="auto",
                    help="擷取引擎：auto（預設，有 Npcap 就用）、npcap、raw（Windows 內建，僅 IPv4）")
    lv.add_argument("--bpf", default="tcp or udp port 53 or udp port 5353 or udp port 5355",
                    help="BPF 擷取過濾條件（僅 npcap 引擎）")
    lv.add_argument("--yes", action="store_true", help="略過授權確認提示")
    lv.add_argument("--keep-open", action="store_true", help=argparse.SUPPRESS)
    lv.set_defaults(func=cmd_live)

    m = sub.add_parser("mitm", parents=[common], help="搭配 mitmproxy 展示 HTTPS 被中間人解密")
    m.set_defaults(func=cmd_mitm)

    i = sub.add_parser("ifaces", help="列出可擷取的網卡")
    i.add_argument("--all", action="store_true", help="也顯示沒有 IP 的網卡與系統篩選驅動程式")
    i.set_defaults(func=cmd_ifaces)

    n = sub.add_parser("install-npcap", help="從官方網站下載並安裝 Npcap（Windows）")
    n.add_argument("--force", action="store_true", help="已安裝也重新安裝")
    n.set_defaults(func=cmd_install_npcap)
    return p


# ---------------------------------------------------------------- menu
def _menu_text() -> str:
    from .capture import npcap_installed

    npcap_line = ""
    if sys.platform == "win32":
        state = "已安裝" if npcap_installed() else "未安裝，即時擷取會改用 Windows 內建方式"
        npcap_line = f"\n    5. 安裝 Npcap  從官方網站下載安裝（目前：{state}）"
    return f"""
  請選擇要做什麼：

    1. 分析 pcap   開啟 Wireshark / tcpdump 錄下的封包檔
    2. 即時擷取    擷取這台電腦網卡的流量（需授權）
    3. MITM 代理   搭配 mitmproxy 示範 HTTPS 被解密
    4. 列出網卡{npcap_line}
    0. 離開

  小技巧：把 .pcap / .pcapng 檔案直接拖到 PlainSight.exe 上就會開始分析。
"""


def _pick_interfaces() -> list[str]:
    from . import interfaces

    found = interfaces.load()
    print()
    print(interfaces.format_table(found))
    print(_capture_engine_line())
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
    print(_menu_text())
    while True:
        choice = _ask("  請輸入編號：")
        if choice == "1":
            path = _ask("  請輸入檔案路徑（也可以把檔案拖進這個視窗）：").strip('"').strip("'")
            if path:
                return ["pcap", path]
        elif choice == "2":
            return ["live"] + _pick_interfaces()
        elif choice == "3":
            return ["mitm"]
        elif choice == "4":
            cmd_ifaces(None)
        elif choice == "5" and sys.platform == "win32":
            return ["install-npcap"]
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
    keep_open = interactive or "--keep-open" in argv
    try:
        return _run(argv)
    finally:
        if keep_open and getattr(sys, "frozen", False):
            print()
            _ask("  按 Enter 關閉視窗…")  # keep errors readable before the console closes


def _run(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    args.argv = argv
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    # Scapy's "no libpcap provider" warning is noise: we fall back to raw sockets.
    logging.getLogger("scapy").setLevel(logging.ERROR)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
