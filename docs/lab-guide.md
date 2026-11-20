# 實驗指南

所有實驗都只能在**你自己的裝置與網路**上進行。建議準備一支專門做實驗的舊手機或虛擬機，
並使用**測試帳號**，不要拿真實帳號密碼來示範。

---

## 實驗 0：示範模式（課堂首選）

```bash
plainsight demo --speed 0.5      # 放慢一點，邊播邊講解
```

終端機會依序顯示 10 個情境的旁白，儀表板同步出現對應的發現：

| # | 情境 | 想讓學生看到的重點 |
|---|---|---|
| 1 | 在 HTTP 論壇登入 | 表單密碼原文、Session Cookie 被看到就能冒用 |
| 2 | 路由器管理頁 Basic 認證 | Base64 是編碼不是加密 |
| 3 | 用 HTTPS 開網路銀行 | 內容加密了，但 DNS 與 SNI 仍透露「你去了哪」 |
| 4 | FTP 下載報表 | 帳密與檔名全部明文 |
| 5 | SMTP 寄信 | 信件內容（含信中的 VPN 密碼）全部可讀 |
| 6 | Telnet 登入交換器 | 每個按鍵都是一個封包，密碼一樣逐字外洩 |
| 7 | POP3 / IMAP 收信 | 老協定的明文登入 |
| 8 | STARTTLS（對照組） | 正確升級加密後，後續內容就看不到了 |
| 9 | 健身 App 走 HTTP | App 也會犯錯：權杖與 GPS 定位外洩 |
| 10 | 一般 HTTPS 瀏覽 | 對照：只看得到網域 |

想在 Wireshark 對照同一批封包：

```bash
plainsight demo --write-pcap demo.pcap
```

---

## 實驗 1：讓電腦成為中繼節點（行動熱點）

這個實驗重現「惡意熱點 / 咖啡廳 Wi-Fi 業者」的視角：所有連上熱點的裝置流量都會經過你的電腦。

### Windows

1. 安裝 [Npcap](https://npcap.com)（使用預設選項即可）。
2. 設定 → 網路和網際網路 → 行動熱點 → 開啟。
3. 用**自己的實驗手機**連上這個熱點。
4. 以**系統管理員**身分開啟終端機：
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

**Q：Windows 出現 `No libpcap provider available`？**
請安裝 [Npcap](https://npcap.com)，並以系統管理員身分執行。

**Q：可以讓別台電腦看儀表板嗎？**
可以用 `--host 0.0.0.0`，但同網段的任何人都能看到擷取結果，請只在受控的教室網路使用，並保持遮蔽模式開啟。
