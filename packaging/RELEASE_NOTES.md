# zinc v0.1.0 — First Release

## English

A free, self-hosted "long URL" generator. zinc turns any link into a secret URL on a Cloudflare Quick Tunnel and gives you a terminal dashboard to see who opened it, change where it goes, and destroy it. No account, no server, no domain.

### Features
- **Gates**: plain (straight through), note (typed message first), count (you are visitor #N), box (a gift to open), door (pick a door; add `!` trap doors)
- **Routing** (stackable): A/B splits with weights (sticky per visitor), by country or continent, by browser language, by device (iOS/Android/mobile/desktop). Rule order is a setting.
- **Adaptive locale**: optionally send a visitor to the target's own localized page (via declared `hreflang`, then a small rule table) — never a guessed `/zh-tw`.
- **Limits**: lifetime, max visitors, max passes (one-time links), start time ("opens tomorrow 09:00"), password.
- **Dashboard**: opens / unique / passes / bots, sparkline, per-country and per-continent counts, A/B results. Export to CSV + JSON. QR code in the terminal, or saved as PNG/SVG.

### Install
- Download the binary for your OS from the release assets (no Python needed)
- `pip install zinc-link` (PyPI, when enabled)
- `winget install zien0709.zinc` (after winget submission)
- `sudo dpkg -i zinc_0.1.0_amd64.deb` (Debian/Ubuntu)

### Assets
| File | Description |
|------|-------------|
| `zinc-linux-x64` | Linux x86_64 binary |
| `zinc-linux-x64-folder.zip` | Linux x86_64 (onedir) |
| `zinc-macos-arm64` | macOS Apple Silicon binary |
| `zinc-macos-arm64-folder.zip` | macOS (onedir) |
| `zinc-windows-x64.exe` | Windows x86_64 binary |
| `zinc-windows-x64-folder.zip` | Windows (onedir) |
| `zinc-nuitka-*` | Nuitka-built variants (experimental) |
| `zinc_link-0.1.0-py3-none-any.whl` | Python wheel |
| `zinc_link-0.1.0.tar.gz` | Python sdist |
| `zinc_0.1.0_amd64.deb` | Debian/Ubuntu package |
| `REPORT.md` | Full CI report |
| `SHA256SUMS.txt` | Checksums |
| `sbom.cdx.json` | Software Bill of Materials |

---

## 繁體中文

**zinc v0.1.0 — 第一版發行**

免費、自架的「長網址」產生器。zinc 把任何連結變成 Cloudflare Quick Tunnel 上的祕密網址，並提供終端機儀表板讓你查看誰打開了它、更改目的地、或銷毀它。不需帳號、伺服器或網域。

### 功能
- **關卡**：plain（直接跳轉）、note（紙條打字機）、count（第 N 位發現者）、box（禮物盒）、door（選門，可加 `!` 陷阱門）
- **路由**（可堆疊）：A/B 分流（每位訪客固定）、依國家/大洲、依瀏覽器語言、依裝置（iOS/Android/行動/桌面）。規則嘗試順序可設定。
- **自適應語系**：可選擇送訪客到目標頁面自己的在地化版本（透過宣告的 `hreflang`，再用小型規則表）— 永遠不猜 `/zh-tw`。
- **限制**：有效期、最大訪客數、最大通過數（一次性連結）、開始時間（「明天 09:00 開放」）、密碼。
- **儀表板**：開啟/不重複/通過/機器人、sparkline、各國與各大洲計數、A/B 結果。匯出 CSV + JSON。終端機 QR 碼或儲存為 PNG/SVG。

### 安裝方式
- 從 release 資產下載你 OS 的執行檔（不需 Python）
- `pip install zinc-link`（PyPI，啟用後）
- `winget install zien0709.zinc`（winget 送審後）
- `sudo dpkg -i zinc_0.1.0_amd64.deb`（Debian/Ubuntu）

### 資產說明
| 檔案 | 說明 |
|------|------|
| `zinc-linux-x64` | Linux x86_64 執行檔 |
| `zinc-linux-x64-folder.zip` | Linux x86_64（onedir） |
| `zinc-macos-arm64` | macOS Apple Silicon 執行檔 |
| `zinc-macos-arm64-folder.zip` | macOS（onedir） |
| `zinc-windows-x64.exe` | Windows x86_64 執行檔 |
| `zinc-windows-x64-folder.zip` | Windows（onedir） |
| `zinc-nuitka-*` | Nuitka 建置版本（實驗性） |
| `zinc_link-0.1.0-py3-none-any.whl` | Python wheel |
| `zinc_link-0.1.0.tar.gz` | Python sdist |
| `zinc_0.1.0_amd64.deb` | Debian/Ubuntu 套件 |
| `REPORT.md` | 完整 CI 報告 |
| `SHA256SUMS.txt` | 校驗碼 |
| `sbom.cdx.json` | 軟體物料清單 (SBOM) |