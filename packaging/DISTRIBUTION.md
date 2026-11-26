# zinc — Distribution Channels / 發行管道

## pip (PyPI) — Python package

**Status:** Ready in CI. Disabled by default.

**What the workflow does:**
- Builds `zinc_link-*.whl` + `*.tar.gz` via `python -m build`
- Runs `twine check --strict`
- Smoke-tests the installed wheel
- Uploads to PyPI via OIDC trusted publishing (no API token)

**What you need to provide:**
1. A PyPI account at https://pypi.org
2. Create the project name `zinc-link` (or claim it) on PyPI
3. Configure a **trusted publisher** at https://pypi.org/manage/account/publishing/
   - Repository: `zien0709/zinc`
   - Workflow: `ci.yml`
   - Environment: `pypi`
4. Set the GitHub repo variable `PUBLISH_PYPI` = `true` (Settings → Secrets and variables → Actions → Variables)
5. Re-tag (e.g. `v0.1.1`) to trigger the upload

**Status / 狀態:** CI ready. Waiting for PyPI trusted publisher config.
**需要你提供：** PyPI 帳號、trusted publisher 設定、repo variable `PUBLISH_PYPI=true`

---

## apt (Debian/Ubuntu) — .deb package

**Status:** .deb build added to CI (attached to GitHub Release). No PPA yet.

**What the workflow does:**
- Builds `zinc_<version>_amd64.deb` from the Linux PyInstaller binary
- Installs to `/usr/local/bin/zinc`
- Attached to the draft release automatically

**Install (after release):**
```bash
wget https://github.com/zien0709/zinc/releases/download/v0.1.0/zinc_0.1.0_amd64.deb
sudo dpkg -i zinc_0.1.0_amd64.deb
```

**What you need to provide (for a real PPA on Launchpad):**
1. A Launchpad account (https://launchpad.net)
2. A GPG key for package signing
3. PPA creation and upload credentials
Without a PPA, the .deb is still available via GitHub Releases.

**Status / 狀態:** .deb on GitHub Releases. PPA optional.
**需要你提供：** Launchpad 帳號 + GPG key（僅 PPA 需要；GitHub release .deb 不需要）

---

## winget (Windows Package Manager)

**Status:** Manifest template created. Manual submission required.

**What you need to do:**
1. Fork `microsoft/winget-pkgs`
2. Fill in `InstallerSha256` in `packaging/winget/zinc.yaml` (SHA256 of `zinc-windows-x64.exe`)
3. Submit a PR to `microsoft/winget-pkgs` with the manifest
4. Or use `wingetcreate`:
   ```powershell
   wingetcreate new https://github.com/zien0709/zinc/releases/download/v0.1.0/zinc-windows-x64.exe
   wingetcreate submit --token <GITHUB_PAT> .\zien0709.zinc.yaml
   ```

**After submission:** Users can `winget install zien0709.zinc`

**Status / 狀態:** Manifest ready. Needs SHA256 fill + PR submission.
**需要你提供：** GitHub PAT（for wingetcreate）或手動送 PR

---

## Release Notes (bilingual) / 發行說明（雙語）

### English

**zinc v0.1.0 — First Release**

A free, self-hosted "long URL" generator. zinc turns any link into a secret URL on a Cloudflare Quick Tunnel and gives you a terminal dashboard to see who opened it, change where it goes, and destroy it. No account, no server, no domain.

**Features:**
- Gates: plain, note, count, box, door (with trap doors)
- Routing: A/B splits, by country/continent, by language, by device
- Adaptive locale: sends visitors to the target's own localized page
- Limits: lifetime, max visitors, max passes, start time, password
- Dashboard: opens/uniques/passes/bots, sparkline, per-country counts, A/B results
- Export to CSV + JSON, QR code in terminal or as PNG/SVG
- Single static binary for Linux, macOS, Windows (no Python needed)
- Python package on PyPI (when enabled)

**Install:**
- Download the binary for your OS from the release assets
- `pip install zinc-link` (when PyPI is enabled)
- `winget install zien0709.zinc` (after winget submission)
- `sudo dpkg -i zinc_0.1.0_amd64.deb` (Debian/Ubuntu)

### 繁體中文

**zinc v0.1.0 — 第一版發行**

免費、自架的「長網址」產生器。zinc 把任何連結變成 Cloudflare Quick Tunnel 上的祕密網址，並提供終端機儀表板讓你查看誰打開了它、更改目的地、或銷毀它。不需帳號、伺服器或網域。

**功能：**
- 關卡：plain（直接跳轉）、note（紙條）、count（第 N 位發現者）、box（禮物盒）、door（選門，可加陷阱門）
- 路由：A/B 分流、依國家/大洲、依語言、依裝置
- 自適應語系：送訪客到目標頁面自己的在地化版本
- 限制：有效期、最大訪客數、最大通過數、開始時間、密碼
- 儀表板：開啟/不重複/通過/機器人、sparkline、各國計數、A/B 結果
- 匯出 CSV + JSON、終端機 QR 碼或儲存為 PNG/SVG
- Linux、macOS、Windows 單一靜態執行檔（不需 Python）
- Python 套件（PyPI，啟用後）

**安裝方式：**
- 從 release 資產下載你 OS 的執行檔
- `pip install zinc-link`（PyPI 啟用後）
- `winget install zien0709.zinc`（winget 送審後）
- `sudo dpkg -i zinc_0.1.0_amd64.deb`（Debian/Ubuntu）