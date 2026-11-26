# zinc

**免費、自架的「長網址產生器」。** 把任何連結變成 `https://quiet-fox-lake-dew.trycloudflare.com/kR3x9QmZpL2w`
這種長長的網址，並附一個終端機儀表板：看誰點開、換目標、銷毀。不用註冊、不用伺服器、不用網域，
全部跑在你自己的電腦上，靠 [Cloudflare Quick Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/)。

每條連結最後一定會跳到你指定的原始網頁。`/` 後面那串隨機字就是暗號，沒有暗號的人只會看到 404，
跟那裡什麼都沒有一模一樣。

> English: [README.md](README.md)

## 功能一覽

| | |
|---|---|
| **玩法**（訪客被轉走之前看到什麼） | `plain` 直接跳、`note` 先看一張紙條、`count` 「你是第 N 位」、`box` 盲盒、`door` 選門（可加 `!` 陷阱門） |
| **分流**（可疊加） | A/B 加權（同一個人永遠分到同一邊）、依國家／洲、依瀏覽器語言、依裝置（iOS／Android／手機／電腦）；規則比對的先後順序可調 |
| **語系適配** | 可選：把訪客送到目標網站*自己的*在地化頁面（先看頁面宣告的 `hreflang`，再用小型規則表），絕不亂猜 `/zh-tw` |
| **限制** | 存活時間、人數上限、通關次數上限（一次性連結）、開放時間（「明天 09:00 才開」）、密碼 |
| **儀表板** | 開啟／不重複／通關／機器人、迷你折線、各國各洲人數、A/B 成績；匯出 CSV + JSON；終端機 QR，或存成 PNG／SVG |
| **安全檢查** | 內建本機檢查一定會跑；可填你自己的免費 API key：VirusTotal、Google Safe Browsing、abuse.ch URLhaus。被標記的目標預設拒絕建立（可強制） |
| **Webhook** | 有人開啟／通關／連結死亡時通知 Discord、Slack 或通用 JSON（HMAC 簽章）。絕不送出 IP、暗號或目標網址 |
| **設定** | 約 70 項，分「基本／進階／專家」三層，每項一句白話說明；有預設組合、可單條連結覆寫、可用環境變數 |

## 安裝

需要 **Python 3.10 以上** 和 **cloudflared**。

### 方式 1：pip（PyPI）

```bash
# 1) cloudflared（Cloudflare 的隧道程式）
#    macOS:   brew install cloudflared
#    Windows: winget install --id Cloudflare.cloudflared
#    Linux:   https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/

# 2) zinc
pip install zinc-link        # 或 pipx install zinc-link
zinc
```

### 方式 2：獨立執行檔（不需 Python）

到 [Releases](../../releases) 下載你 OS 的單一執行檔，一樣需要先裝 cloudflared。

- **Windows**：`zinc-windows-x64.exe`
- **macOS（Apple Silicon）**：`zinc-macos-arm64`
- **Linux（x86_64）**：`zinc-linux-x64`

執行檔沒有簽章：Windows SmartScreen 會說「未知的發行者」（更多資訊 → 仍要執行）；macOS 先執行
`xattr -d com.apple.quarantine ./zinc-macos-arm64`；Linux／macOS 要先 `chmod +x`。每個 Release 都附 SHA-256 清單
（`SHA256SUMS.txt`）。

### 方式 3：Debian/Ubuntu（.deb）

```bash
wget https://github.com/zien0709/zinc/releases/download/v0.1.1/zinc_0.1.1_amd64.deb
sudo dpkg -i zinc_0.1.1_amd64.deb
zinc
```

### 方式 4：winget（Windows）

```powershell
winget install zien0709.zinc
```

找不到 cloudflared？設環境變數 `ZINC_CLOUDFLARED=/path/to/cloudflared`，或到 `k` 設定裡填路徑。
安裝 cloudflared 即表示你接受 Cloudflare 的授權與條款。

## 使用

1. 按 **n**，貼上目標網址，選玩法，Enter。
2. 幾秒後該列變成 `● 運作`，網址出現。**c** 複製、**q** 看 QR。
3. 看訪客進來。**e** 延長 10 分鐘、**p** 暫停、**t** 改目標（網址不變）、**y** 分身（新網址）、
   **x** 匯出統計、**d** 軟銷毀（訪客看到墓碑）、**D** 立刻殺掉隧道。

表單語法：

```
https://a.example https://b.example*3      A/B，B 的機率是三倍
https://a.example !                         一扇真門、一扇陷阱門
規則：asia=網址; TW=網址; lang:ja=網址; device:ios=網址
```

指令列：

```bash
zinc --help-settings basic     # 列出該層級所有設定與白話說明（basic | advanced | expert）
zinc --config-path             # 設定檔位置
zinc --version
```

### 設定

按 `k`：可搜尋、空白鍵切換開關、Enter 編輯、套用預設組合（`safe`、`fun`、`minimal`…）。
只有和預設不同的值會寫進設定檔（`~/.config/zinc/config.json`；Windows 是 `%APPDATA%\zinc\config.json`；
Unix 上權限為私人）。任何設定都能用環境變數 `ZINC_<名稱>` 指定。標示「每條連結」的設定，可以在表單的
進階區（`名稱=值; 名稱=值`）為單一連結覆寫。

API key（VirusTotal、Safe Browsing、URLhaus、webhook 密鑰）只存在設定檔或環境變數裡，畫面上會遮蔽，
任何錯誤訊息都會先洗掉。

## 安全承諾（以及不可調的底線）

- 本機伺服器只綁 `127.0.0.1`，唯一入口是隧道。
- 暗號錯、沒暗號、方法不對、路徑不存在：全部回同一個 404 假頁。
- 連結預覽機器人（Slack、Discord、WhatsApp…）只看到通用卡片，不算人數，也看不到目標。
- 密碼閘門：PBKDF2-SHA256（12 萬次）、恆定時間比對、每位訪客與每條連結都有猜測次數上限，密碼不會出現在任何網址。
- 預覽目標用的掃描器會拒絕私有、本機、link-local、CGNAT 與 NAT64 包裝的位址，每一跳轉址與每個 DNS 答案都重驗，
  並限制大小、時間與跳數。
- 訪客頁面使用嚴格的 CSP（每次回應一個 nonce），目標頁面的文字一律 HTML 跳脫。
- 絕不儲存訪客 IP，只存「每條連結各自加鹽」的雜湊。匯出與 webhook 不含 IP、暗號、目標網址。
- 轉址只用 302/303/307（301/308 會被瀏覽器快取，導致不計數）。

它**不是**匿名工具，也不是用來藏釣魚頁的：zinc 會掃描目標、拒絕被標惡意的網址，訪客頁也會顯示他們要去哪。
請不要拿來欺騙別人。

## 從 Cloudflare Quick Tunnel 繼承的限制

依 Cloudflare 官方文件（2026 年 11 月查證）：Quick Tunnel「僅供測試與開發」、**不保證可用時間**、
**同時最多 200 個進行中的請求**（超過回 429）、**不支援 Server-Sent Events**，而且
`~/.cloudflared/config.yaml` 存在時無法使用（zinc 會提醒你）。`trycloudflare.com` 網址是隨機的，每次都不同。
zinc 每條連結各開一個 tunnel 程序，幾十條沒問題，上百條未測過。

## 平台與驗證狀況

| | 狀態 |
|---|---|
| Linux、Python 3.10／3.11／3.12／3.13 | 整套自動測試（約 700 個，並做過突變檢查）在每個版本都通過；用宣告的最低相依版本（aiohttp 3.14.4、Textual 4.0.0、rich 13.9.4、segno 1.6.1）在 3.13 也通過 |
| Windows、macOS | 純 Python 程式碼，除了設定路徑與檔案權限外無 OS 特定呼叫。**已在 CI 驗證**：測試套件（700+ 測試）在 windows-latest（Python 3.12）與 macos-latest（Python 3.12）上每個 tag release 都會跑。各平台也會建置並 smoke-test 自己的執行檔。 |
| 真實 `cloudflared` | 隧道處理只用擬真的假程式測過；Quick Tunnel 上是否真有 `CF-IPCountry` 等行為，第一次使用請確認 |
| VirusTotal／Safe Browsing／URLhaus | 只對假伺服器測過；URLhaus 的端點與欄位名稱是憑記憶寫的，程式碼內標了 `UNVERIFIED` |
| 語系規則表（google／youtube／microsoft／wikipedia／apple） | 憑記憶寫的，標為 `UNVERIFIED_RULES`；永遠先試目標自己的 `hreflang` |

## 打包成單一執行檔

```bash
pip install pyinstaller
python tools/build_binary.py --tool pyinstaller --mode onefile --name zinc     # -> dist/zinc（Windows 是 dist/zinc.exe），約 25 MB
python tools/smoke.py -- dist/zinc                                              # 啟動、畫出介面、退出；結束碼 0 = 正常
```

`tools/build_binary.py` 包裝了驗證過的作法（`packaging/entry.py` 是啟動器；zinc 用相對匯入，PyInstaller 需要它）。
`--tool nuitka` 也接好了（`pip install "nuitka==4.3.5" ordered-set zstandard`，需要 C 編譯器），但**屬實驗性：
旗標只對照過 `--help`，作者從沒實際跑過**。推薦 PyInstaller：已用 Textual 驗證、不用編譯器，而 zinc 瓶頸在網路，
Nuitka 的加速看不出來。兩者都不能交叉編譯，所以每個作業系統各自打包，CI 就是這樣做。

## CI 與發版（`.github/workflows/ci.yml`）

單一 workflow，由 `tools/ci_plan.py` 決定跑什麼。

| 觸發 | 做什麼 |
|---|---|
| push 到 `main`、pull request | 便宜版：Linux、Python 3.10 與 3.13 的測試 |
| 推 `v*` 標籤（`git tag v0.1.0 && git push --tags`） | **全部**（見下），最後產生 **草稿** GitHub Release |
| *Actions → Run workflow* | 只跑你勾的；結果是可下載的 `release-bundle` |

發版跑的內容：Python 3.10–3.13 + Windows + macOS + pyproject 允許的**最舊**相依版本（另做已知漏洞掃描）的測試；突變測試；
真實 `cloudflared` 檢查（`tools/live_check.py`，會用下表的選用 secrets）；bandit／pip-audit／vermin／SBOM；wheel + sdist
（`twine check`、裝進乾淨環境、冒煙測試）；各作業系統的 PyInstaller（單檔＋資料夾）與實驗性 Nuitka，每個都冒煙測試。
最後 `tools/report.py` 寫出 **`REPORT.md`**（每個面向 ✅／⚠️／❌、「這份報告不能證明什麼」、每個檔案的 SHA-256）；
草稿 Release 內有報告、`SHA256SUMS.txt`、所有執行檔、wheel/sdist、SBOM、`zinc-reports.zip`（全部原始報告）。
你看完報告再按 *Publish*。

儲存庫設定（全部選用）：

| 名稱 | 種類 | 作用 |
|---|---|---|
| `ZINC_VT_KEY`、`ZINC_GSB_KEY`、`ZINC_URLHAUS_KEY` | secret | 真實檢查也會去問這些服務 |
| `ZINC_WEBHOOK_URL`（＋變數 `ZINC_WEBHOOK_FORMAT`） | secret | 真實檢查會送一則測試通知 |
| `ZINC_RELEASE_SKIP` | variable | 省分鐘數用，例如 `mutation,macos`（可用詞：`mutation live nuitka pyinstaller security floor windows macos`） |
| `PUBLISH_PYPI` = `true` | variable | 報告為 **ready** 後也上傳 PyPI（需設定 PyPI trusted publisher 與 `pypi` environment，建議把自己設為必須審核者） |

Actions 分鐘數：公開儲存庫免費；私有儲存庫 Windows ×2、macOS ×10，突變測試最久，乾跑請用 `ZINC_RELEASE_SKIP` 或手動表單。
workflow 以 actionlint + shellcheck 檢查，並在本機演練過。
第一次跑預期要修點東西（最可能是 Windows／macOS 測試或 Nuitka）。

## 開發

```bash
pip install -e ".[dev]"
pytest -q                       # 約 700 個測試，約 2 分鐘
python tools/mutate.py          # 故意弄壞程式、一次一處；每個「突變」都必須被測試抓到
python tools/mutate.py --list
```

`tools/mutate.py` 會在拋棄式副本裡套用約 160 個小小的刻意錯誤（差一、少跳脫、放寬 workflow 閘門…），要求測試對每一個都失敗。
出現 `SURVIVED` 就代表有一種行為沒人在檢查。

## 授權

MIT，見 [LICENSE](LICENSE)。
