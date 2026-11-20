# 實驗指南

所有實驗都只能在**你自己的裝置與網路**上進行。建議準備一支專門做實驗的舊手機或虛擬機，
並使用**測試帳號**，不要拿真實帳號密碼來示範。

---

## 實驗 1：讓電腦成為中繼節點（行動熱點）

這個實驗重現「惡意熱點 / 咖啡廳 Wi-Fi 業者」的視角：所有連上熱點的裝置流量都會經過你的電腦。

### Windows

1. （選用）安裝 Npcap：PlainSight 選單選「安裝 Npcap」。不裝也可以，程式會改用 Windows 內建擷取並要求系統管理員權限。
2. 設定 → 網路和網際網路 → 行動熱點 → 開啟。
3. 用**自己的實驗手機**連上這個熱點。
4. 開啟終端機（或直接雙擊 PlainSight.exe 選「即時擷取」）：
   ```powershell
   plainsight ifaces          # 熱點網卡會標示為「行動熱點」，IP 通常是 192.168.137.1
   plainsight live -i 2       # 用上一步看到的編號
   ```
   也可以直接雙擊 PlainSight.exe → 選 3「即時擷取」，從清單輸入編號。
   想同時看熱點與電腦本身的流量，可輸入多個編號，例如 `-i 1,2`。
5. 在手機上瀏覽 HTTP 測試網站（例如 `http://testphp.vulnweb.com`、`http://neverssl.com`），並用**假帳號**登入。

### Linux

```bash
# 以 NetworkManager 建立熱點（wlan0 為無線網卡）
nmcli dev wifi hotspot ifname wlan0 ssid PlainSight-Lab password "lab-only-123"
sudo plainsight live -i wlan0
```

### 觀察重點

- 儀表板右上「連線加密比例」：現今多數流量是 HTTPS（綠色），但 DNS 和 SNI 仍會洩漏網域。
- 開幾個 App，看看哪些還在用明文 HTTP。
- 若手機啟用了「私人 DNS」（DoT），DNS 查詢就會消失——這就是防護生效。

---

## 實驗 2：HTTPS 為什麼也會被解密（mitmproxy）

HTTPS 的安全建立在「裝置只信任正當的憑證機構」上。這個實驗示範：只要受害者被誘導安裝一張根憑證，
中間人就能看到所有 HTTPS 內容。

1. 安裝 mitmproxy（可以裝在獨立的虛擬環境）：
   ```bash
   pip install mitmproxy
   ```
2. 啟動儀表板：
   ```bash
   plainsight mitm
   ```
   終端機會印出 addon 的完整路徑。
3. 另開終端機啟動代理：
   ```bash
   mitmdump -s "<上一步印出的 mitm_addon.py 路徑>" --listen-port 8080
   ```
   若儀表板不是預設的 `127.0.0.1:8765`，先設定環境變數 `PLAINSIGHT_URL=http://127.0.0.1:<埠號>`。
4. 實驗手機的 Wi-Fi 設定 → 代理伺服器 → 手動 → 主機填電腦的區網 IP，埠號 `8080`。
   （Windows 防火牆可能需要允許 8080 埠的連入。）
5. 手機瀏覽器開啟 `http://mitm.it`，依指示下載並**信任**憑證：
   - iOS：設定 → 一般 → VPN 與裝置管理 → 安裝描述檔；再到 設定 → 一般 → 關於本機 → 憑證信任設定 → 開啟完全信任。
   - Android：設定 → 安全性 → 加密與憑證 → 安裝憑證 → CA 憑證。（Android 7 以後，多數 App 預設不信任使用者安裝的 CA，只有瀏覽器會受影響——這也是一種防護。）
6. 在手機上用測試帳號登入任何 HTTPS 網站，儀表板會出現紫色的「MITM 解密」標記。
7. **實驗結束後，務必移除憑證並關閉代理設定！**

### 討論題

- 為什麼銀行 App 在這個實驗中通常會連不上？（Certificate Pinning）
- 為什麼有些網站即使裝了憑證，瀏覽器仍然不讓你略過警告？（HSTS Preload）
- 公司電腦上的「SSL 檢測」和這個實驗的原理有什麼一樣、有什麼不一樣？

---

## 實驗 3：離線分析 pcap

```bash
plainsight pcap capture.pcapng
plainsight pcap capture.pcapng --realtime   # 依照原本的時間間隔播放
plainsight pcap capture.pcapng --report     # 不開儀表板，直接列出結果
```

可使用：

- 自己用 Wireshark / tcpdump 在**自己的網路**上錄下的檔案
- [Wireshark 官方範例檔](https://wiki.wireshark.org/SampleCaptures)（例如 `http.cap`、`telnet-raw.pcap`、`smtp.pcap`）
- CTF 題目提供的 pcap

---

## 常見問題

**Q：`live` 在家裡只看得到自己的流量？**
正常。交換器只把封包送到目的地的連接埠，Wi-Fi 的每個裝置也有各自的加密金鑰。要看到別人的流量，
必須成為中繼節點（熱點、路由器、代理），或用 ARP 欺騙等主動攻擊——後者 PlainSight 刻意不提供。

**Q：沒有安裝 Npcap 可以擷取嗎？**
可以。PlainSight 會改用 Windows 內建的原始通訊端擷取（只有 IPv4，需要系統管理員權限，程式會跳出 UAC 詢問）。
需要 IPv6 或完整乙太網路封包時，再從選單安裝 Npcap 即可。

**Q：可以讓別台電腦看儀表板嗎？**
可以用 `--host 0.0.0.0`，但同網段的任何人都能看到擷取到的完整帳號密碼，請只在受控的教室網路使用。
