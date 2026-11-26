# zinc

**A free, self-hosted "long URL" generator.** zinc turns any link into something like
`https://quiet-fox-lake-dew.trycloudflare.com/kR3x9QmZpL2w` — and gives you a terminal dashboard to see who opened it,
change where it goes, and destroy it. No account, no server, no domain: it runs on your own computer through
[Cloudflare Quick Tunnels](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/).

Every link still ends at the page you pointed it at. The random suffix after the `/` is the secret: anyone without it
gets a plain 404, exactly as if nothing lived there.

> 繁體中文說明：[README.zh-Hant.md](README.zh-Hant.md)

```
┌ zinc ────────────────────────────────────────────────────────────────────────────┐
│ #  網域                          名稱     玩法   人   狀態     剩餘               │
│ 1  quiet-fox-lake-dew            promo    count  12   ● 運作   23:41             │
│ 2  mild-owl-tree-sky             note     note   3    ◐ 軟死   00:09             │
└──────────────────────────────────────────────────────────────────────────────────┘
 n 新增  d 軟銷毀  D 硬銷毀  e +10分  p 暫停  c 複製  q QR  y 分身  t 改目標  x 匯出  k 設定
```

## What you can do

| | |
|---|---|
| **Gates** (what a visitor sees before being redirected) | `plain` (straight through), `note` (a typed message first), `count` ("you are visitor #N"), `box` (a gift to open), `door` (pick a door; add `!` trap doors) |
| **Routing** (stackable) | A/B splits with weights (sticky per visitor), by country or continent, by browser language, by device (iOS / Android / mobile / desktop). The order the rules are tried in is a setting. |
| **Adaptive locale** | Optionally send a visitor to the target's *own* localized page (via the page's declared `hreflang`, then a small rule table) — never a guessed `/zh-tw`. |
| **Limits** | Lifetime, max visitors, max passes (one-time links), a start time ("opens tomorrow 09:00"), a password. |
| **Dashboard** | Opens / unique / passes / bots, a sparkline, per-country and per-continent counts, A/B results. Export to CSV + JSON. QR code in the terminal, or saved as PNG/SVG. |
| **Safety checks** | Built-in local checks always run. Optionally add your own free API keys: VirusTotal, Google Safe Browsing, abuse.ch URLhaus. A flagged target is refused unless you override. |
| **Webhooks** | Discord, Slack or generic JSON (HMAC-signed) when someone opens, passes, or a link dies. No IPs, no tokens, no target URLs are ever sent. |
| **Settings** | ~70 settings in three levels (Basic / Advanced / Expert), each with a one-line plain-language explanation, presets, per-link overrides, environment variables. Nothing hard-coded that should not be. |

## Install

You need **Python 3.10 or newer** and **cloudflared**.

### Option 1: pip (PyPI)

```bash
# 1) cloudflared (the Cloudflare tunnel client)
#    macOS:   brew install cloudflared
#    Windows: winget install --id Cloudflare.cloudflared
#    Linux:   https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/

# 2) zinc
pip install zinc-link          # or:  pipx install zinc-link
zinc
```

### Option 2: Standalone binary (no Python needed)

Download a single-file executable for Windows, macOS or Linux from the
[Releases](../../releases) page. You still need `cloudflared`.

- **Windows**: `zinc-windows-x64.exe`
- **macOS (Apple Silicon)**: `zinc-macos-arm64`
- **Linux (x86_64)**: `zinc-linux-x64`

The executables are unsigned: Windows SmartScreen says "unknown publisher" (More info → Run anyway); on macOS run
`xattr -d com.apple.quarantine ./zinc-macos-arm64`; on Linux/macOS `chmod +x` it first. Each release lists SHA-256
checksums (`SHA256SUMS.txt`).

### Option 3: Debian/Ubuntu (.deb)

```bash
wget https://github.com/zien0709/zinc/releases/download/v0.1.2/zinc_0.1.2_amd64.deb
sudo dpkg -i zinc_0.1.1_amd64.deb
zinc
```

### Option 4: winget (Windows)

```powershell
winget install zien0709.zinc
```

Not on PATH? `export ZINC_CLOUDFLARED=/path/to/cloudflared` (or set it under `k` → Settings).
Installing `cloudflared` means you accept Cloudflare's license and terms.

### Run from a checkout

```bash
git clone <this repo> && cd zinc
pip install -e ".[dev]"
python -m zinc
```

## Using it

1. Press **n**. Paste a target (`https://example.com`). Pick a gate. **Enter**.
2. A few seconds later the row turns `● 運作` and the URL is shown. **c** copies it, **q** shows a QR.
3. Watch visitors arrive. **e** adds 10 minutes, **p** pauses, **t** changes the target without changing the URL,
   **y** clones the link with a new URL, **x** exports the stats, **d** ends it gracefully (visitors see a tombstone),
   **D** kills the tunnel right now.

Target syntax in the form:

```
https://a.example https://b.example*3        A/B, B three times as likely
https://a.example !                           one real door and one trap
Rules:  asia=URL; TW=URL; lang:ja=URL; device:ios=URL
```

Command line:

```bash
zinc --help-settings basic      # every setting at that level, in plain words (basic | advanced | expert)
zinc --config-path              # where your settings file lives
zinc --version
```

### Settings

`k` opens the settings screen: search, press space to flip a switch, Enter to edit, a preset to apply a bundle
(`safe`, `fun`, `minimal`, ...). Only values that differ from the default are written to the config file
(`~/.config/zinc/config.json`, or `%APPDATA%\zinc\config.json` on Windows; private permissions on Unix).
Any setting can also be set with an environment variable `ZINC_<NAME>`. Settings marked *per link* can be overridden
for a single link in the form's Advanced section (`name=value; name=value`).

API keys (VirusTotal, Safe Browsing, URLhaus, webhook secret) are stored only in that file or your environment, are
masked on screen and are scrubbed from every error message.

## How it stays safe

What zinc guarantees, and what is **not** adjustable:

- The local server binds to `127.0.0.1` only; the only way in is the tunnel.
- Wrong or missing suffix, wrong method, unknown path: the same 404 "decoy".
- Link-preview bots (Slack, Discord, WhatsApp, ...) get a generic card and are not counted as visitors; they never see the target.
- Password gate: PBKDF2-SHA256 (120k iterations), constant-time comparison, per-visitor and per-link guess limits, no password in any URL.
- The scanner that previews your targets refuses private, loopback, link-local, CGNAT and NAT64-wrapped addresses, re-checks every redirect hop and every DNS answer, and caps size, time and hops.
- Visitor pages use a strict Content-Security-Policy with a per-response nonce; all text from the target page is HTML-escaped.
- Visitor IPs are never stored: only a per-link salted hash. Exports and webhooks contain no IPs, tokens or target URLs.
- Redirects use 302/303/307 only (301/308 are cached by browsers and would skip counting).

What it is **not**: zinc is not an anonymity tool and not a way to hide a phishing page. It scans your targets, refuses
the ones flagged as malicious, and the visitor page shows where they are going. Do not use it to deceive people.

## Limits you inherit from Cloudflare Quick Tunnels

From Cloudflare's documentation (checked November 2026): quick tunnels are "intended for testing and development only",
have **no uptime guarantee**, allow **200 in-flight requests** (more get HTTP 429), and **do not support Server-Sent
Events**. They also do not work while `~/.cloudflared/config.yaml` exists (zinc warns you). The `trycloudflare.com`
address is random and changes every time. Each link in zinc runs its own tunnel process, so a few dozen links is
fine; hundreds is untested.

## Platforms and what has been verified

| | Status |
|---|---|
| Linux, Python 3.10 / 3.11 / 3.12 / 3.13 | The whole automated suite (~700 tests, mutation-checked) passes on each. Also passes on the declared minimum dependency versions (aiohttp 3.14.4, Textual 4.0.0, rich 13.9.4, segno 1.6.1) on 3.13. |
| Windows, macOS | Pure-Python code, no OS-specific calls except the config path and file permissions. **Verified in CI**: the test suite (700+ tests) runs on windows-latest (Python 3.12) and macos-latest (Python 3.12) on every tag release. Each platform also builds and smoke-tests its own binary. |
| Real `cloudflared` | The tunnel handling is tested against a faithful fake. Real quick-tunnel behaviour (e.g. `CF-IPCountry` on quick tunnels) should be confirmed on first use. |
| VirusTotal / Safe Browsing / URLhaus | Tested against fakes. URLhaus's endpoint and field names are from memory and flagged `UNVERIFIED` in the code. |
| Locale rule table (google / youtube / microsoft / wikipedia / apple) | From memory, marked `UNVERIFIED_RULES`; the target's own `hreflang` is always tried first. |

## Build a standalone executable

```bash
pip install pyinstaller
python tools/build_binary.py --tool pyinstaller --mode onefile --name zinc     # -> dist/zinc  (dist/zinc.exe on Windows), ~25 MB
python tools/smoke.py -- dist/zinc                                              # starts it, draws the UI, quits; exit 0 = fine
```

`tools/build_binary.py` wraps the verified recipe (`packaging/entry.py` is the launcher; PyInstaller needs one because
zinc uses relative imports). `--tool nuitka` is also wired in (`pip install "nuitka==4.3.5" ordered-set zstandard`, needs a
C compiler) but is **experimental: its flags were checked against `--help`, never run by the author**. PyInstaller is the
recommendation: verified here with Textual, no compiler needed, and zinc is network-bound so Nuitka's speed-up is invisible.
Neither tool cross-compiles, so each operating system builds its own binary; CI does exactly that.

## CI and releases (`.github/workflows/ci.yml`)

One workflow; `tools/ci_plan.py` decides what runs.

| Trigger | What happens |
|---|---|
| push to `main`, pull request | cheap: tests on Linux, Python 3.10 and 3.13 |
| push a tag `v*` (`git tag v0.1.0 && git push --tags`) | **everything** (below), ending in a **draft** GitHub release |
| *Actions → Run workflow* | only what you tick; result is a downloadable `release-bundle` artifact |

A release run does: tests on Python 3.10–3.13 + Windows + macOS + the *oldest* dependency versions pyproject allows
(also audited for known vulnerabilities); mutation testing; a real-`cloudflared` check (`tools/live_check.py`, uses the
optional secrets below); bandit / pip-audit / vermin / SBOM; wheel + sdist (`twine check`, installed in a clean
environment and smoke-tested); PyInstaller (onefile + folder) and experimental Nuitka executables per OS, each
smoke-tested. Then `tools/report.py` writes **`REPORT.md`** (a ✅/⚠️/❌ verdict per area, what it does *not* prove, SHA-256
of every file); the draft release holds the report, `SHA256SUMS.txt`, every executable, the wheel/sdist, the SBOM and
`zinc-reports.zip` (all raw reports). You read the report, then press *Publish*.

Repository settings (all optional):

| Name | Kind | Effect |
|---|---|---|
| `ZINC_VT_KEY`, `ZINC_GSB_KEY`, `ZINC_URLHAUS_KEY` | secret | the real-world check also queries those providers |
| `ZINC_WEBHOOK_URL` (+ variable `ZINC_WEBHOOK_FORMAT`) | secret | the real-world check sends one test notification |
| `ZINC_RELEASE_SKIP` | variable | leave jobs out to save minutes, e.g. `mutation,macos` (`mutation live nuitka pyinstaller security floor windows macos`) |
| `PUBLISH_PYPI` = `true` | variable | also upload to PyPI after a **ready** report (needs a PyPI trusted publisher and a `pypi` environment; add yourself as required reviewer there) |

Actions minutes: public repositories are free. On a private repository Windows counts ×2 and macOS ×10, and mutation
testing is the longest job; use `ZINC_RELEASE_SKIP` or the manual form for dry runs. The workflow itself was linted
Actions minutes: public repositories are free. On a private repository Windows counts ?2 and macOS ?10, and mutation
testing is the longest job; use ZINC_RELEASE_SKIP or the manual form for dry runs. The workflow itself was linted
with actionlint + shellcheck and its glue rehearsed locally.
to fix something on the first run (most likely Windows/macOS tests or Nuitka).

## Develop

```bash
pip install -e ".[dev]"
pytest -q                       # ~700 tests, about 2 minutes
python tools/mutate.py          # break the code on purpose, one change at a time; every mutant must be caught
python tools/mutate.py --list
```

`tools/mutate.py` applies ~160 small deliberate bugs (an off-by-one here, a missing escape there, a loosened workflow
gate) in throw-away copies and requires the tests to fail for each one. A "SURVIVED" line means a behaviour nobody was checking.

## License

MIT — see [LICENSE](LICENSE).
