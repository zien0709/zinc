"""Mutation check: break the code on purpose, one small change at a time, and confirm the tests notice.

    python tools/mutate.py            # run every mutation (about 10 minutes)
    python tools/mutate.py S4 K1      # only these ids
    python tools/mutate.py --list
    python tools/mutate.py --report reports/mutation.json     (machine-readable result; MUTATE_JOBS=4 to run 4 at once)

A mutant that SURVIVES (all tests still pass) means a behaviour nobody is checking. Each run happens in a
throw-away copy of the project, so the real files are never touched.
"""
from __future__ import annotations

import concurrent.futures as cf
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAST = ["tests/test_core.py", "tests/test_server.py", "tests/test_scan_locale.py", "tests/test_reputation.py",
        "tests/test_options.py", "tests/test_qr.py", "tests/test_tunnel_manager.py", "tests/test_settings_wiring.py",
        "tests/test_features.py", "tests/test_notify_edit.py", "tests/test_gaps.py", "tests/test_fuzz_settings.py"]
ADMIN = ["tests/test_admin_features.py"]
TUI = ["tests/test_tui.py", "tests/test_tui_settings.py"]
GAPS = ["tests/test_gaps.py"]
TOOLS = ["tests/test_tools.py"]
WFT = ["tests/test_workflows.py"]

# (id, file, old, new, what a good test suite would say, test files)
M: list[tuple[str, str, str, str, str, list[str]]] = [
    # ---- server: who gets in, what they see ----
    ("S1", "zinc/server.py", ' or request.match_info.get("token") != link.token:', ":", "a wrong secret suffix still works", FAST),
    ("S2", "zinc/server.py", "return bool(re.search(o.bot_regex, ua[:300], re.I))", "return False", "link-preview bots are served like humans", FAST),
    ("S3", "zinc/server.py", 'if not store.has_hit(link.id, vid, "open"):       # skipping', 'if False:       # skipping', "/go works without opening the gate first", FAST),
    ("S4", "zinc/server.py", "ok = await asyncio.get_running_loop().run_in_executor(None, check_password, pw, link.spec.pw_hash)", "ok = True", "any password unlocks", FAST),
    ("S5", "zinc/server.py", "if len(mine) >= o.unlock_tries or", "if len(mine) > o.unlock_tries or", "one extra password guess allowed", FAST),
    ("S6", "zinc/server.py", "if spec.pw_hash and vid not in unlocked:", "if spec.pw_hash and False:", "the password gate is skipped", FAST),
    ("S7", "zinc/server.py", 'store.count_hits(link.id, "pass") >= link.spec.max_passes', 'store.count_hits(link.id, "pass") > link.spec.max_passes', "one pass too many", FAST),
    ("S8", "zinc/server.py", "\"base-uri 'none'; form-action 'none'; frame-ancestors 'none'\")", "\"base-uri 'none'; frame-ancestors 'none'\")", "CSP loses form-action", FAST),
    ("S9", "zinc/server.py", "script = f\"script-src 'nonce-{nonce}'\" if nonce else \"script-src 'none'\"", "script = \"script-src 'unsafe-inline'\"", "CSP allows any inline script", FAST),
    ("S10", "zinc/server.py", 'resp.headers["Cache-Control"] = "no-store"', "pass", "pages become cacheable", FAST),
    ("S11", "zinc/server.py", '        if link.status in ("starting", "live", "paused"):\n            store.set_status(link.id, "soft_dead"', '        if False:\n            store.set_status(link.id, "soft_dead"', "lazy death never happens", FAST),
    ("S12", "zinc/server.py", '        if not admitted:\n            tell("open", link, geo)', '        if True:\n            tell("open", link, geo)', "refreshing re-announces to the webhook", FAST),
    ("S14", "zinc/server.py", 'store.add_hit(link.id, "open", vid, geo.country, geo.continent, lang_of(request), now=now)', 'store.add_hit(link.id, "open", vid, None, None, lang_of(request), now=now)', "region stats lose the country", FAST),
    ("S15", "zinc/server.py", "status=int(o.redirect_status)", "status=302", "redirect_status ignored", FAST),
    ("S16", "zinc/server.py", "        if passes_used_up(link):                      # that was the last allowed pass", "        if False:                      # that was the last allowed pass", "the link survives its last allowed pass", FAST),
    ("S17", "zinc/server.py", " or len(link_attempts) >= max(30, o.unlock_tries * 10)", "", "no per-link cap on password guessing", FAST),
    ("S18", "zinc/server.py", "if spec.starts_at and now < spec.starts_at:", "if False:", "the start time is ignored", FAST),
    ("S19", "zinc/server.py", 'key_ip, key_ua = ("" if o.unique_by == "ua" else ip), ("" if o.unique_by == "ip" else ua)', "key_ip, key_ua = ip, ua", "unique_by ignored", FAST),
    ("S20", "zinc/server.py", "unlocked.add(vid)", "pass", "a correct password does not unlock", FAST),
    ("S21", "zinc/server.py", 'app.router.add_route("*", "/{tail:.*}", root)', 'app.router.add_get("/{tail:.*}", root)', "other methods get 405 instead of the decoy", FAST),
    ("S22", "zinc/server.py", "mine = attempts.get(vid) or deque()", "mine = attempts.setdefault(vid, deque())", "refused unlock requests grow memory without bound", GAPS),
    ("S23", "zinc/server.py", "if len(attempts) > 1000:", "if len(attempts) > 10**9:", "the attempt table is never pruned", GAPS),
    ("S24", "zinc/server.py", "        attempts[vid] = mine\n", "", "password attempts are never remembered per visitor", FAST),
    ("W1", "zinc/reputation.py", 'return self.skip(f"VirusTotal 提交失敗 HTTP {r.status}")', "pass", "a failed VT submit continues with a bogus id", GAPS),
    ("W2", "zinc/reputation.py", "            if not await self.throttle.acquire():\n                break", "            if False:\n                break", "VT polling ignores the budget", GAPS),
    ("W3", "zinc/reputation.py", 'if r.status in (401, 403):\n                return self.skip("URLhaus Auth-Key 無效")', 'if False:\n                return self.skip("URLhaus Auth-Key 無效")', "URLhaus bad key is misread", GAPS),
    ("W4", "zinc/tunnel.py", "self.proc.kill()", "pass", "a hung cloudflared is never killed", GAPS),
    ("W5", "zinc/manager.py", "            self.store.set_scan(link_id, dump_scans(scans))\n            self.store.set_verdict(link_id, dump_verdicts(await self.reputation.check_all(urls, scans)))", "            pass", "rescan does nothing", GAPS),
    ("W6", "zinc/manager.py", 'self.errors["_ticker"] = str(e)', "raise", "one bad tick kills the ticker loop", GAPS),
    ("W7", "zinc/geo.py", 'return code if _ALPHA2.match(code) else None', "return code or None", "offline geo DB can return junk country codes", GAPS),
    ("W8", "zinc/config.py", 'if sys.platform == "win32" and env.get("APPDATA"):', 'if env.get("APPDATA"):', "APPDATA is used on non-Windows systems", GAPS),
    ("W9", "zinc/options.py", 'if p.username or p.password:', 'if False:', "webhook URLs with embedded credentials are accepted", GAPS),
    ("W10", "zinc/scan.py", "uniq = list(dict.fromkeys(u for u in urls if u))", "uniq = [u for u in urls if u]", "duplicate targets are scanned twice", GAPS),
    ("W11", "zinc/server.py", '        if is_bot(o, ua):\n            return decoy(o)\n        if effective_state(link, now, store.count_opens(link.id), admitted=True) == "dead":', '        if False:\n            return decoy(o)\n        if effective_state(link, now, store.count_opens(link.id), admitted=True) == "dead":', "bots can use the unlock endpoint", GAPS),
    # ---- routing ----
    ("R1", "zinc/resolver.py", 'digest = hashlib.sha256(f"{salt}:{vid}".encode()).digest()', 'digest = hashlib.sha256(f"{vid}".encode()).digest()', "A/B split ignores the per-link salt", FAST),
    ("R2", "zinc/resolver.py", "if geo.country and geo.country in by_match:", "if False:", "a country rule loses to its continent", FAST),
    ("R3", "zinc/resolver.py", "for key in (t, t.split(\"-\")[0]):", "for key in (t.split(\"-\")[0], t):", "zh beats zh-tw", FAST),
    ("R4", "zinc/resolver.py", "if any(k in ua for k in _IOS):", "if False:", "iPhones are not detected", FAST),
    ("R5", "zinc/resolver.py", 'device in ("ios", "android")', 'device in ("android",)', "mobile rule skips iOS", FAST),
    ("R6", "zinc/geo.py", "if not _ALPHA2.match(raw) or raw.upper() in _UNKNOWN_CODES:", "if not _ALPHA2.match(raw):", "unknown country codes XX/T1 count as places", FAST),
    # ---- scanner (SSRF) ----
    ("C1", "zinc/scan.py", "or addr.is_reserved or addr.is_unspecified or not addr.is_global)", "or addr.is_reserved or addr.is_unspecified)", "CGNAT 100.64/10 and other non-global ranges look public", FAST),
    ("C8", "zinc/scan.py", "elif addr in _NAT64:", "elif False:", "64:ff9b::7f00:1 (NAT64 around 127.0.0.1) looks public", FAST),
    ("C9", "zinc/scan.py", '("64:ff9b:1::/48", "fec0::/10")', '("64:ff9b:1::/48",)', "site-local IPv6 looks public", FAST),
    ("C2", "zinc/scan.py", ' or h.endswith(".local") or h.endswith(".internal")', "", ".local/.internal hosts are fetched", FAST),
    ("C3", "zinc/scan.py", "if ip_is_public(i[4][0])]", "if True]", "DNS answers are not filtered", FAST),
    ("C4", "zinc/scan.py", "if not allow_private and literal_host_blocked(parts.hostname):", "if False:", "literal private hosts are fetched", FAST),
    ("C5", "zinc/scan.py", "for _ in range(max_hops + 1):", "for _ in range(max_hops + 2):", "one redirect too many", FAST),
    ("C6", "zinc/scan.py", 'if urlsplit(v).scheme in ("http", "https")}', "if True}", "javascript: hreflang links accepted", FAST),
    ("C7", "zinc/scan.py", "await resp.content.read(max_bytes)", "await resp.content.read()", "no body size cap", FAST),
    # ---- safety checks ----
    ("P1", "zinc/reputation.py", 'return bool(domain) and (host == domain or host.endswith("." + domain))', "return bool(domain) and host.endswith(domain)", "look-alike domains match the allow/blocklist", FAST),
    ("P2", "zinc/reputation.py", "    if p.username or p.password:\n        return True", "    if False:\n        return True", "user:pass@ urls are sent to third parties", FAST),
    ("P3", "zinc/reputation.py", "k.lower() in _SECRET_KEYS", "k in _SECRET_KEYS", "TOKEN= (upper case) is not recognised as a secret", FAST),
    ("P4", "zinc/reputation.py", "if len(self._day) >= self.per_day:", "if len(self._day) > self.per_day:", "daily quota off by one", FAST),
    ("P5", "zinc/reputation.py", "if len(self._window) >= self.per_minute:", "if len(self._window) > self.per_minute:", "per-minute quota off by one", FAST),
    ("P6", "zinc/reputation.py", 'level = max((f.level for f in findings), key=ORDER.__getitem__, default="ok")', 'level = min((f.level for f in findings), key=ORDER.__getitem__, default="ok")', "best finding wins instead of the worst", FAST),
    ("P7", "zinc/reputation.py", "elif has_secret_params(url) and not self.s.send_secret_urls:", "elif False:", "token-like urls are sent to third parties", FAST),
    ("P8", "zinc/reputation.py", 'if res.level != "skip" and self.cache_ttl > 0:', "if self.cache_ttl > 0:", "failed lookups are cached", FAST),
    ("P9", "zinc/reputation.py", 'if _in_domain(host, "trycloudflare.com"):', "if False:", "tunnel loops are not flagged", FAST),
    # ---- settings / secrets ----
    ("F1", "zinc/config.py", '            text = text.replace(s, "***")', "            pass", "API keys survive scrubbing", FAST),
    ("F2", "zinc/config.py", 'return key[:4] + "…" + key[-4:] if len(key) > 10 else "•" * len(key)', "return key", "keys are shown in full", FAST + TUI),
    ("F3", "zinc/config.py", "os.chmod(path, 0o600)", "os.chmod(path, 0o644)", "the key file is world-readable", FAST),
    ("K1", "zinc/secret.py", "return hmac.compare_digest(got.hex(), want)", "return True", "every password matches", FAST),
    ("K2", "zinc/secret.py", "    if not is_hash(stored):\n        return False\n    _, iters", "    _, iters", "malformed hashes raise", FAST),
    # ---- model rules ----
    ("M1", "zinc/models.py", 'or token in (".", "..")', "", "a vanity suffix of '..' is accepted", FAST),
    ("M2", "zinc/models.py", "len(token) > 64", "len(token) > 640", "over-long suffix accepted", FAST),
    ("M3", "zinc/models.py", "0 <= spec.max_passes <= 1_000_000", "0 <= spec.max_passes <= 10_000_000", "pass limit range", FAST),
    ("M4", "zinc/lifecycle.py", "human_opens >= link.max_opens", "human_opens > link.max_opens", "max_opens allows one extra visitor", FAST),
    ("M5", "zinc/lifecycle.py", "not admitted and human_opens", "human_opens", "admitted visitors are locked out at the last step", FAST),
    ("M6", "zinc/lifecycle.py", "now >= link.expires_at", "now > link.expires_at", "expiry boundary", FAST),
    # ---- manager ----
    ("N1", "zinc/manager.py", 'if w and w[1].level == "block" and self.settings.block_on_malicious and not force:', "if False:", "malicious targets are never blocked", FAST),
    ("N2", "zinc/manager.py", 'if w and w[1].level == "block" and self.settings.block_on_malicious and not force:', 'if w and w[1].level == "block" and self.settings.block_on_malicious:', "force override does nothing", FAST),
    ("N3", "zinc/manager.py", "        spec.token = link.token\n", "", "editing a link can change its secret suffix", FAST),
    ("N4", "zinc/manager.py", "if rt and spec.pw_hash != link.spec.pw_hash:", "if False:", "old unlocks survive a password change", FAST),
    ("N5", "zinc/manager.py", 'elif link.status == "soft_dead" and link.grace_until is not None and now >= link.grace_until:', "elif False:", "soft-dead links never get hard-killed", FAST),
    ("N6", "zinc/manager.py", "if ttl_s is not None:  # the clock starts", "if False:  # the clock starts", "links never expire", FAST),
    ("N7", "zinc/manager.py", "scans, verdicts, note = await self._vet(spec, force)\n        self.store.set_spec", "scans, verdicts, note = {}, {}, ''\n        self.store.set_spec", "edits skip the safety checks", FAST),
    # ---- webhooks ----
    ("Y1", "zinc/notify.py", "if v is not None and k in _FIELDS}", "if v is not None}", "webhook bodies can carry arbitrary fields (IP, token...)", FAST),
    ("Y2", "zinc/notify.py", "hmac.new(s.webhook_secret.encode(), body, hashlib.sha256)", "hmac.new(s.webhook_secret.encode(), b'', hashlib.sha256)", "signature does not cover the body", FAST),
    ("Y3", "zinc/notify.py", '"allowed_mentions": {"parse": []}', '"allowed_mentions": {"parse": ["everyone"]}', "a label can ping @everyone", FAST),
    ("Y4", "zinc/notify.py", 'self.last_error = f"webhook 送不出去：{type(e).__name__}"', 'self.last_error = f"webhook 送不出去：{e}"', "error text leaks the secret webhook host", FAST),
    ("Y5", "zinc/notify.py", "allow_redirects=False,", "allow_redirects=True,", "webhook redirects are followed", FAST),
    ("Y6", "zinc/notify.py", "if len(self._recent) >= self.s.webhook_max_per_min:", "if len(self._recent) > self.s.webhook_max_per_min:", "rate cap off by one", FAST),
    # ---- export / view ----
    ("X1", "zinc/export.py", 'return "\'" + text if text[:1] in ("=", "+", "-", "@", "\\t", "\\r") else text', "return text", "CSV formula injection", FAST + ADMIN),
    ("X2", "zinc/export.py", '(row["vid"] or "")[:8]', '(row["vid"] or "")', "full visitor ids in the export", ADMIN),
    ("V1", "zinc/view.py", "    if when <= now:", "    if False:", "past start times accepted", ADMIN),
    ("V2", "zinc/view.py", "        if n <= 0:", "        if False:", "+0 start time accepted", ADMIN),
    # ---- adaptive locale ----
    ("L1", "zinc/locale.py", "        if q > 0:\n", "        if q >= 0:\n", "q=0 ('not acceptable') languages are accepted", FAST),
    ("L2", "zinc/locale.py", "items.append((-q, i, tag))", "items.append((-q, -i, tag))", "equal-q languages come out reversed", FAST),
    ("L3", "zinc/locale.py", 'if tag.lower() == "zh" and country in _ZH_COUNTRY:', "if False:", "bare 'zh' is not refined by country", FAST),
    ("L4", "zinc/locale.py", "if not out and country in _COUNTRY_LANG:", "if country in _COUNTRY_LANG:", "country overrides the browser's own language list", FAST),
    ("L5", "zinc/locale.py", "if not (t.lower() in seen or seen.add(t.lower()))]", "if not (t in seen or seen.add(t))]", "zh-TW and zh-tw are tried twice", FAST),
    ("L6", "zinc/locale.py", "if key in hreflang and is_http_url(hreflang[key]):", "if key in hreflang:", "a javascript: hreflang can become the redirect", FAST),
    ("L7", "zinc/locale.py", 'for key in [low, *_ALIASES.get(low, []), low.split("-")[0]]:', 'for key in [low.split("-")[0], low, *_ALIASES.get(low, [])]:', "bare language beats the exact regional tag", FAST),
    ("L8", "zinc/locale.py", "keep_blank_values=True) if k != key]", "keep_blank_values=True) if True]", "?hl= is duplicated instead of replaced", FAST),
    ("L9", "zinc/locale.py", '    if p.path not in ("", "/"):\n        return None                       # article', '    if False:\n        return None                       # article', "wikipedia article links are rewritten to the portal", FAST),
    ("L10", "zinc/locale.py", 'or not country or country == "US":', "or not country:", "apple.com US visitors get /us/", FAST),
    ("L11", "zinc/locale.py", 'if host == base or host.endswith("." + base):', "if host == base or host.endswith(base):", "notgoogle.com is treated as google.com", FAST),
    ("L12", "zinc/locale.py", "if not auto_locale or not is_http_url(url):", "if not auto_locale:", "non-http urls are rewritten", FAST),
    ("L13", "zinc/locale.py", "if scan and scan.hreflang:", "if False:", "the target's own hreflang is ignored", FAST),
    ("L14", "zinc/locale.py", 'return (new, f"rule:{tag}") if new != url else (url, None)', 'return (new, f"rule:{tag}")', "a no-op rewrite is reported as a rule hit", FAST),
    ("L15", "zinc/locale.py", "            if new is None:                      # this rule has nothing for that language: try the visitor's next one\n                continue\n", "", "a rule with nothing for the first language gives up instead of trying the next", FAST),
    # ---- stats / identity ----
    ("T3", "zinc/store.py", "\"SELECT COUNT(DISTINCT vid) n FROM hits WHERE link_id=? AND kind='open'\",", "\"SELECT COUNT(vid) n FROM hits WHERE link_id=? AND kind='open'\",", "unique visitors count repeat visits", FAST),
    ("T4", "zinc/store.py", "idx = minutes - 1 - int((now - t) // 60)", "idx = minutes - int((now - t) // 60)", "sparkline is shifted a minute", FAST),
    ("T5", "zinc/store.py", 'r["country"] or "??"', 'r["country"] or "XX"', "unknown-country bucket renamed", FAST),
    ("T6", "zinc/resolver.py", 'f"{salt}|{ip}|{user_agent}"', 'f"{ip}|{user_agent}"', "visitor ids can be joined across links", FAST),
    ("T7", "zinc/store.py", 'if kind not in ("open", "pass", "bot"):', "if False:", "bad hit kinds are stored", FAST),
    # ---- settings values / form parsing ----
    ("O1", "zinc/options.py", "(self.min is not None and num < self.min)", "(self.min is not None and num <= self.min)", "minimum value rejected", FAST),
    ("O2", "zinc/options.py", "(self.max is not None and num > self.max)", "(self.max is not None and num >= self.max)", "maximum value rejected", FAST),
    ("O3", "zinc/options.py", "if not math.isfinite(num):", "if False:", "NaN/inf pass every range check", FAST),
    ("O4", "zinc/options.py", '            if isinstance(raw, bool):\n                raise ValueError(f"「{name}」要是數字', '            if False:\n                raise ValueError(f"「{name}」要是數字', "true/false accepted as 1/0", FAST),
    ("O5", "zinc/options.py", "                bad = [i for i in out if i not in self.choices]", "                bad = []", "unknown list items accepted", FAST),
    ("V3", "zinc/view.py", "            if tail.isdigit():", "            if True:", "a url containing * crashes the form", FAST + ADMIN),
    ("V4", "zinc/view.py", 'name = chr(ord("A") + i) if i < 26 else f"V{i}"', 'name = chr(ord("A") + i) if i <= 26 else f"V{i}"', "the 27th target is named '['", FAST + ADMIN),
    ("V6", "zinc/view.py", 'f"*{v.weight}" if v.weight > 1 else ""', 'f"*{v.weight}" if v.weight >= 1 else ""', "weight 1 is written out as *1", FAST + ADMIN),
    # ---- release tooling ----
    ('J1', 'tools/ci_plan.py', 'release = ref.startswith("refs/tags/v")', 'release = ref.startswith("refs/tags/")', 'any tag, not just v-tags, publishes a release', TOOLS),
    ('J2', 'tools/ci_plan.py', 'pyinstaller = truthy(env.get("PYINSTALLER"), manual)', 'pyinstaller = truthy(env.get("PYINSTALLER"), True)', 'every push builds executables (burns the Actions quota)', TOOLS),
    ('J3', 'tools/ci_plan.py', 'cov=p == "3.13")', 'cov=True)', 'every test job measures coverage', TOOLS),
    ('J4', 'tools/ci_plan.py', 'if "macos" in chosen:', 'if True:', 'macOS (10x minutes) is always in the test matrix', TOOLS),
    ('J5', 'tools/ci_plan.py', 'nuitka = pyinstaller = mutation = live = True', 'nuitka = pyinstaller = mutation = live = False', 'a release run skips its checks', TOOLS),
    ('J6', 'tools/report.py', 'verdict = BAD if (failed or missing) else OK', 'verdict = BAD if failed else OK', 'a test job that never finished is not noticed', TOOLS),
    ('J7', 'tools/report.py', 'state, note = (WARN if exp else BAD), "not built (build failed or job did not run)"', 'state, note = OK, "not built (build failed or job did not run)"', 'a missing executable is not noticed', TOOLS),
    ('J8', 'tools/report.py', 'return (WARN if survivors else OK), summary, body', 'return OK, summary, body', 'surviving mutants are hidden', TOOLS),
    ('J9', 'tools/report.py', 'str(text).replace("|", "\\\\|").replace("\\n", " ")', 'str(text).replace("\\n", " ")', 'table cells containing | break the layout', TOOLS),
    ('J10', 'tools/report.py', 'overall = "NOT READY — fix the ❌ items first" if blockers else (', 'overall = "Ready" if True else (', 'blockers do not change the verdict', TOOLS),
    ('J11', 'tools/smoke.py', '"ok": all(r["status"] != "failed" for r in results) and any(r["status"] == "passed" for r in results)', '"ok": all(r["status"] != "failed" for r in results)', 'a run where everything was skipped counts as passing', TOOLS),
    ('J12', 'tools/smoke.py', 'ok = r.returncode == 0 and re.match', 'ok = re.match', 'a --version that crashes still passes', TOOLS),
    ('J13', 'tools/smoke.py', 'return drew and proc.returncode == 0, f"drew', 'return drew, f"drew', 'a UI that crashes on quit still passes', TOOLS),
    ('J14', 'tools/live_check.py', 'return scrub(str(text), self.secrets)[:400]', 'return str(text)[:400]', 'live-check output can leak API keys', TOOLS),
    ('J15', 'tools/live_check.py', 'if not rep.facts.get("public_url_answered"):', 'if False:', 'the destroy check passes vacuously', TOOLS),
    ('J16', 'tools/build_binary.py', 'if folder_build != args.name.endswith(".zip"):', 'if False:', 'folder builds can be given a single-file name', TOOLS),
    ('J17', 'tools/ci_plan.py', '"label": "ubuntu-floor" if floor else os_name}', '"label": os_name}', 'the oldest-dependencies job gets the same report name as the normal job', TOOLS),
    ('J18', 'tools/ci_plan.py', 'if tests == "full" and "floor" not in skip:', 'if True:', 'the oldest-dependencies job runs on every push', TOOLS),
    ('J19', 'tools/report.py', 'label = job.get("label", job["os"])', 'label = job["os"]', 'a missing oldest-dependencies report is not noticed', TOOLS),
    ('J20', 'tools/ci_plan.py', 'if os.environ.get("PLAN_JSON"):', 'if False:', 'the plan file for the report is never written', TOOLS),
    ('J21', 'tools/assemble.py', 'KINDS = {"reports-": "reports", "dist-": "assets"}', 'KINDS = {"reports-": "assets", "dist-": "assets"}', 'reports are attached to the release as if they were downloads', TOOLS),
    ('J22', 'tools/assemble.py', 'return result\n    for art in sorted', 'return {}\n    for art in sorted', 'a missing bundle crashes the report step', TOOLS),
    ('J23', 'tools/assemble.py', 'if filecmp.cmp(f, dest, shallow=False):', 'if True:', 'two different files with one name silently overwrite each other', TOOLS),
    ('J24', 'tools/assemble.py', 'dest = targets[kind] / f.name', 'dest = targets[kind] / f.relative_to(art)', 'files keep their artifact sub-folder and the report cannot find them', TOOLS),
    ('J25', 'tools/ci_plan.py', '    if unknown:\n        raise SystemExit(f"unknown SKIP', '    if False:\n        raise SystemExit(f"unknown SKIP', 'a typo in ZINC_RELEASE_SKIP is silently ignored and the expensive job runs anyway', TOOLS),
    ('J26', 'tools/ci_plan.py', 'chosen = [p for p in PLATFORM_SETS[platforms] if p not in skip]', 'chosen = [p for p in PLATFORM_SETS[platforms]]', 'skipping macOS/Windows has no effect', TOOLS),
    ('J27', 'tools/ci_plan.py', '"run_security": (release or manual) and "security" not in skip,', '"run_security": True,', 'security scans run on every push', TOOLS),
    ('J28', 'tools/ci_plan.py', '"run_package": release or manual,', '"run_package": True,', 'the package is built on every push', TOOLS),
    ('J29', 'tools/report.py', 'if not plan.get("run_package"):', 'if False:', 'an unrequested package build is reported as a failure', TOOLS),
    ('J30', 'tools/report.py', 'f.write(f"ready={\'false\' if info[\'blockers\'] else \'true\'}', 'f.write(f"ready={\'true\'}', 'PyPI would publish a release the report called NOT READY', TOOLS),
    ('J31', 'tools/report.py', '("pip-audit-floor", "pip-audit-floor.json")', '("pip-audit-floor", "pip-audit.json")', 'a vulnerable dependency floor is never reported', TOOLS),
    ('J32', 'tools/report.py', 'if plan.get("skipped"):', 'if False:', 'the report hides what was left out on purpose', TOOLS),
    ('J33', 'tools/floor_requirements.py', 'if not m:\n            raise SystemExit(f"cannot turn', 'if False:\n            raise SystemExit(f"cannot turn', 'a floor that cannot be pinned is silently mangled', TOOLS),
    ('J34', 'tools/report.py', 'if smoke is None:\n        problems.append("the wheel was not smoke-tested")', 'if False:\n        problems.append("the wheel was not smoke-tested")', 'an untested wheel passes', TOOLS),
    ('K9', 'zinc/store.py', 'unknown = set(cols) - self._UPDATABLE', 'unknown = set()', 'a column name in a link update is not checked against the allow-list (SQL injection if a caller ever passes user text)', GAPS),
    ('J35', 'tools/mutate.py', '    if unknown:\n        print(f"error: unknown mutant', '    if False:\n        print(f"error: unknown mutant', 'a mistyped mutant id is a green 0/0 run', TOOLS),
    ('J36', 'tools/mutate.py', 'i = argv.index("--report")\n        if i + 1 >= len(argv) or', 'i = argv.index("--report")\n        if False and i + 1 >= len(argv) or', '--report without a file name crashes with a traceback', TOOLS),
    ('WF1', '.github/workflows/ci.yml', "cancel-in-progress: ${{ !startsWith(github.ref, 'refs/tags/') }}", 'cancel-in-progress: true', 'a second push cancels a release that is being built', WFT),
    ('WF2', '.github/workflows/ci.yml', "if: ${{ !cancelled() && needs.plan.outputs.run_release == 'true' && needs.report.result == 'success' }}", "if: ${{ !cancelled() && needs.report.result == 'success' }}", 'every manual run creates a GitHub release', WFT),
    ('WF3', '.github/workflows/ci.yml', " && needs.report.outputs.ready == 'true' && needs.package.result", ' && needs.package.result', 'PyPI publishes a release the report called NOT READY', WFT),
    ('WF4', '.github/workflows/ci.yml', 'flags=(--draft --title', 'flags=(--title', 'the release is published immediately instead of as a draft', WFT),
    ('WF5', '.github/workflows/ci.yml', '--no-deps\n          .floor/bin/python -m pip install "pytest', '\n          .floor/bin/python -m pip install "pytest', 'the oldest-dependency environment is quietly upgraded by pip', WFT),
    ('WF6', '.github/workflows/ci.yml', 'timeout-minutes: 150', 'timeout-minutes: ${{ vars.T }}', 'the mutation job can hang for six hours', WFT),
    ('WF7', '.github/workflows/ci.yml', 'pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086 # release/v1 (v1.14.3)', 'pypa/gh-action-pypi-publish@release/v1', 'the PyPI upload action is a moving target', WFT),
    ('WF8', '.github/workflows/ci.yml', 'run: python tools/build_binary.py --tool "$TOOL"', 'run: python tools/build_binary.py --compiler "$TOOL"', 'the build step passes a flag build_binary does not have', WFT),
    ('WF9', '.github/workflows/ci.yml', 'path: dist/${{ matrix.name }}', 'path: dist/', 'the whole dist folder, not the one executable, is attached', WFT),
    ('WF11', '.github/workflows/ci.yml', '          SKIP: ${{ vars.ZINC_RELEASE_SKIP }}\n', "          SKIP: ''\n", 'the ZINC_RELEASE_SKIP variable no longer reaches the planner', WFT),
    ('WF12', '.github/workflows/ci.yml', 'PYTHONUTF8: "1"', 'PYTHONUTF8: "0"', "Windows crashes printing the report's emoji", WFT),
    ('WF13', '.github/workflows/ci.yml', '        if: ${{ !matrix.floor }}\n', '        if: ${{ matrix.floor }}\n', 'the normal tests install the oldest dependencies', WFT),
    ('WF14', '.github/workflows/ci.yml', "if: ${{ needs.plan.outputs.run_release == 'true' && github.event.repository.private == false }}", "if: ${{ needs.plan.outputs.run_release == 'true' && github.event.repository.private == true }}", 'attestation attempted only where it cannot work', WFT),
    ('WF15', '.github/workflows/ci.yml', "ATTESTED: ${{ steps.attest.outcome == 'success' }}", "ATTESTED: ${{ steps.attest.outcome != 'skipped' }}", 'the report claims attestation when it failed', WFT),
    ('WF16', '.github/workflows/ci.yml', 'fromJSON(needs.plan.outputs.build_matrix)', 'fromJSON(needs.plan.outputs.test_matrix)', 'executables are built from the test matrix', WFT),
    ('WF17', '.github/workflows/ci.yml', '          LABEL: ${{ matrix.label }}\n', '          LABEL: ${{ matrix.os }}\n', "the oldest-dependency report gets the normal job's file name", WFT),
    ('WF18', '.github/workflows/ci.yml', '          persist-credentials: false\n      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7\n        with:\n          python-version: "3.12"\n      - name: Decide what to run', '          persist-credentials: true\n      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7\n        with:\n          python-version: "3.12"\n      - name: Decide what to run', 'the checkout leaves a write token in the workspace', WFT),
    # ---- misc ----
    ("Q1", "zinc/qr.py", 'dark="#000000", light="#ffffff"', 'dark="#ffffff", light="#000000"', "QR exports are inverted (unscannable)", FAST),
    ("T1", "zinc/tunnel.py", '_NOT_TUNNEL = {"api"}', "_NOT_TUNNEL = set()", "api.trycloudflare.com is mistaken for the tunnel", FAST),
    ("T2", "zinc/tunnel.py", 'return configured or os.environ.get("ZINC_CLOUDFLARED") or shutil.which("cloudflared")', 'return os.environ.get("ZINC_CLOUDFLARED") or configured or shutil.which("cloudflared")', "env var beats the setting", FAST),
    ("I1", "zinc/i18n.py", 'return "zh-Hant" if tags[0].split("-")[0] == "zh" else "en"', 'return "zh-Hant" if tags[0].split("-")[0] != "zh" else "en"', "languages swapped", FAST),
    ("G1", "zinc/pages.py", '<div class="t">{escape(title)}</div>', '<div class="t">{title}</div>', "scanned page titles are not escaped (XSS)", FAST),
    ("G2", "zinc/pages.py", 'data-text="{escape(message, quote=True)}"', 'data-text="{message}"', "note text is not escaped (XSS)", FAST),
    ("U1", "zinc/urlutil.py", "if k not in have]", "if True]", "utm parameters overwrite the target's own", FAST),
    ("U2", "zinc/urlutil.py", 'quote(token, safe="")', 'quote(token, safe="/")', "slashes in a suffix are not encoded", FAST),
    ("D1", "zinc/store.py", "secrets.token_urlsafe(token_length * 3 // 4 + 1)[:token_length]", "secrets.token_urlsafe(token_length * 3 // 4 + 1)[:token_length + 1]", "suffix length is off by one", FAST),
]


def run_one(item) -> tuple[str, str, str]:
    mid, rel, old, new, what, tests = item
    src = (ROOT / rel).read_text(encoding="utf-8")
    if src.count(old) != 1:
        return mid, "BROKEN", f"pattern found {src.count(old)} times in {rel}"
    with tempfile.TemporaryDirectory(prefix=f"mut-{mid}-") as tmp:
        work = Path(tmp)
        shutil.copytree(ROOT / "zinc", work / "zinc", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(ROOT / "tests", work / "tests", ignore=shutil.ignore_patterns("__pycache__"))
        for extra in ("tools", "packaging", ".github"):
            if (ROOT / extra).exists():
                shutil.copytree(ROOT / extra, work / extra, ignore=shutil.ignore_patterns("__pycache__"))
        for extra in ("pyproject.toml", "README.md", "README.zh-Hant.md", "LICENSE"):
            if (ROOT / extra).exists():
                shutil.copy2(ROOT / extra, work / extra)
        (work / rel).write_text(src.replace(old, new), encoding="utf-8")
        try:
            r = subprocess.run([sys.executable, "-I", "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *tests],
                               cwd=work, capture_output=True, text=True, timeout=240)
        except subprocess.TimeoutExpired:
            return mid, "killed", "timeout (a hang counts as caught)"
        out = r.stdout + r.stderr
        if r.returncode == 0:
            return mid, "SURVIVED", what
        first = next((ln for ln in out.splitlines() if ln.startswith("FAILED") or ln.startswith("ERROR")), "failed")
        return mid, "killed", first[:110]


USAGE = """usage: python tools/mutate.py [ID ...] [--report FILE] [--list]

Break the code on purpose, one small change at a time, and require the tests to notice each one.
  ID ...         only these mutants (default: all)           --list     show every mutant and the bug it plants
  --report FILE  also write the results as JSON              MUTATE_JOBS=N   run N at a time (default 2)
Exit status 1 if any mutant SURVIVED (an unchecked behaviour) or is BROKEN (its pattern no longer matches the code),
2 for a bad command line (an unknown ID is an error, never a silent "0 of 0 caught")."""


def main(argv: list[str]) -> int:
    import json
    import os
    argv = list(argv)
    if "-h" in argv or "--help" in argv:
        print(USAGE)
        return 0
    report = None
    if "--report" in argv:
        i = argv.index("--report")
        if i + 1 >= len(argv) or argv[i + 1].startswith("-"):
            print("error: --report needs a file name\n" + USAGE, file=sys.stderr)
            return 2
        report = Path(argv[i + 1])
        del argv[i:i + 2]
    if "--list" in argv:
        for mid, rel, _o, _n, what, _t in M:
            print(f"{mid:4} {rel:22} {what}")
        return 0
    want = set(argv)
    unknown = sorted(want - {m[0] for m in M})
    if unknown:
        print(f"error: unknown mutant id(s): {', '.join(unknown)}  (see --list)", file=sys.stderr)
        return 2
    items = [m for m in M if not want or m[0] in want]
    meta = {m[0]: (m[1], m[4]) for m in M}
    results, bad = [], 0
    jobs = max(1, int(os.environ.get("MUTATE_JOBS", "2")))
    with cf.ThreadPoolExecutor(max_workers=jobs) as pool:
        for mid, status, info in pool.map(run_one, items):
            print(f"{mid:4} {status:9} {info}", flush=True)
            results.append({"id": mid, "status": status, "info": info, "file": meta[mid][0], "bug": meta[mid][1]})
            bad += status in ("SURVIVED", "BROKEN")
    print(f"\n{len(items) - bad}/{len(items)} mutants caught" + ("" if not bad else f"  ·  {bad} need attention"))
    if report:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps({"total": len(items), "caught": len(items) - bad, "needs_attention": bad,
                                      "results": results}, indent=1, ensure_ascii=False), encoding="utf-8")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
