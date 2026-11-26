"""Check zinc against the REAL world: a real cloudflared quick tunnel and (when keys are given) the real providers.

Everything the automated tests could only check against fakes is checked here, and written down as facts:

  * does a quick tunnel start, answer from the public internet, redirect correctly, count visitors once?
  * does Cloudflare's CF-IPCountry header arrive through a quick tunnel (region stats depend on it)?
  * do several tunnels at once work, and how much memory does that take?
  * does a hard-destroyed link really stop answering?
  * do VirusTotal / Google Safe Browsing / URLhaus answer in the shape zinc expects?      (needs keys)
  * does a Discord / Slack webhook accept zinc's message?                                (needs a webhook URL)

Keys come from the same ZINC_* environment variables the app reads (ZINC_VT_KEY, ZINC_GSB_KEY, ZINC_URLHAUS_KEY,
ZINC_WEBHOOK_URL, ZINC_WEBHOOK_FORMAT). Nothing secret is ever printed or written: every text goes through scrub().

    python tools/live_check.py --json reports/live-check.json          (exit code is 0 unless --strict)

Run it where cloudflared is installed and the network is open (a GitHub Actions runner is perfect).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Optional

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zinc.config import load_settings_with_warnings, scrub                      # noqa: E402
from zinc.manager import Manager                                                 # noqa: E402
from zinc.models import LinkSpec, Variant                                        # noqa: E402
from zinc.notify import Notifier                                                 # noqa: E402
from zinc.reputation import SafeBrowsing, URLhaus, VirusTotal                    # noqa: E402
from zinc.store import Store                                                     # noqa: E402
from zinc.tunnel import TunnelError, find_cloudflared                            # noqa: E402

TARGET = "https://example.com/"
SAFE_BROWSING_TEST_URL = "https://testsafebrowsing.appspot.com/s/malware.html"   # Google's documented test page
BOT_UA = "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"
HUMAN_UA = "Mozilla/5.0 (X11; Linux x86_64) zinc-live-check"


class Report:
    def __init__(self, secrets: list[str]):
        self.secrets, self.steps, self.facts = secrets, [], {}

    def clean(self, text) -> str:
        return scrub(str(text), self.secrets)[:400]

    async def step(self, name: str, fn: Callable[[], Awaitable[tuple]]) -> bool:
        """fn returns (status, detail); status is passed | failed | info | skipped. A crash counts as failed."""
        began = time.monotonic()
        try:
            status, detail = await fn()
        except Exception as e:
            status, detail = "failed", f"{type(e).__name__}: {e}"
        self.steps.append({"name": name, "status": status, "detail": self.clean(detail),
                           "seconds": round(time.monotonic() - began, 1)})
        print(f"{ {'passed': '✅', 'failed': '❌', 'info': 'ℹ️ ', 'skipped': '⏭ '}[status] } {name:<26} {self.steps[-1]['detail']}",
              flush=True)
        return status == "passed"

    def result(self) -> dict:
        return {"when": datetime.now(timezone.utc).isoformat(timespec="seconds"), "steps": self.steps,
                "facts": self.facts, "ok": not any(s["status"] == "failed" for s in self.steps)}


# ---- the tunnel part -----------------------------------------------------------------------------------
async def fetch(session: aiohttp.ClientSession, url: str, ua: str = HUMAN_UA, lang: str = "en") -> tuple[int, str, str]:
    async with session.get(url, headers={"User-Agent": ua, "Accept-Language": lang}, allow_redirects=False) as r:
        return r.status, r.headers.get("Location", ""), (await r.text())[:4000]


async def reachable(session, url: str, within: float) -> Optional[float]:
    """Seconds until the public URL first answers with something other than a Cloudflare error, or None."""
    began = time.monotonic()
    while time.monotonic() - began < within:
        try:
            status, _, _ = await fetch(session, url)
            if status in (200, 302, 303, 307):
                return time.monotonic() - began
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass
        await asyncio.sleep(1.5)
    return None


async def tunnel_checks(rep: Report, settings, links: int, reach_within: float) -> None:
    store = Store()
    mgr = Manager(store, settings=settings, tunnel_timeout=settings.tunnel_timeout_s)
    spec = lambda: LinkSpec(mode="plain", variants=[Variant("A", TARGET)])             # noqa: E731
    made = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
        try:
            async def start():
                began = time.monotonic()
                link = await mgr.create(spec(), ttl_s=600, force=True)
                made.append(link)
                rep.facts["tunnel_start_s"] = round(time.monotonic() - began, 1)
                return "passed", f"{link.hostname} in {rep.facts['tunnel_start_s']}s"
            if not await rep.step("tunnel-starts", start):
                return
            link = made[0]
            url = Manager.public_url(link)

            async def scan():
                row = store.get_link(link.id)
                ok = "Example Domain" in (row.scan or "")
                return ("passed" if ok else "failed"), "the real scanner read example.com's title" if ok else "title not found in scan result"
            await rep.step("target-scan-real-site", scan)

            async def redirect():
                took = await reachable(session, url, reach_within)
                if took is None:
                    return "failed", f"{url} never answered within {reach_within:.0f}s"
                rep.facts["first_reachable_s"] = round(took, 1)
                s2, loc, _ = await fetch(session, url)
                rep.facts["public_url_answered"] = True
                return ("passed" if (s2, loc) == (302, TARGET) else "failed"), f"HTTP {s2} -> {loc or '(none)'}; reachable after {took:.1f}s"
            if not await rep.step("public-redirect", redirect):
                return

            async def decoy():
                a, b = await fetch(session, f"https://{link.hostname}/"), await fetch(session, f"https://{link.hostname}/nope")
                same = a[0] == b[0] == 404 and a[2] == b[2]
                return ("passed" if same else "failed"), f"/ -> {a[0]}, /nope -> {b[0]}, identical bodies: {a[2] == b[2]}"
            await rep.step("decoy-404", decoy)

            async def bot():
                status, loc, body = await fetch(session, url, ua=BOT_UA)
                clean = status == 200 and not loc and "example.com" not in body
                return ("passed" if clean else "failed"), f"HTTP {status}, target hidden: {'example.com' not in body}"
            await rep.step("link-preview-bot-card", bot)

            async def counted():
                for _ in range(2):
                    await fetch(session, url)                                   # same client, same UA
                rows = [r for r in store.all_hits(link.id) if r["kind"] == "open"]
                uniq = len({r["vid"] for r in rows})
                ok = len(rows) >= 3 and uniq == 1
                return ("passed" if ok else "failed"), f"{len(rows)} opens from {uniq} distinct visitor(s) (expected 1: the client IP header must be stable)"
            await rep.step("visitor-identity", counted)

            async def country():
                values = [r["country"] for r in store.all_hits(link.id) if r["kind"] == "open"]
                got = next((c for c in values if c), None)
                rep.facts["cf_ipcountry_through_quick_tunnel"] = bool(got)
                rep.facts["observed_country"] = got
                if got and len(got) == 2:
                    return "passed", f"CF-IPCountry arrived ({got})"
                return "info", "no country header seen: region stats need a local GeoIP DB (settings: geoip_db)"
            await rep.step("country-header", country)

            async def many():
                if links <= 1:
                    return "skipped", "--links 1"
                extra = await asyncio.gather(*[mgr.create(spec(), ttl_s=600, force=True) for _ in range(links - 1)],
                                             return_exceptions=True)
                good = [x for x in extra if not isinstance(x, BaseException)]
                made.extend(good)
                answered = await asyncio.gather(*[reachable(session, Manager.public_url(x), reach_within) for x in good])
                rep.facts["tunnels_tested"] = 1 + len(good)
                rep.facts["peak_rss_mb"] = peak_memory_mb()
                bad = (len(extra) - len(good)) + sum(a is None for a in answered)
                return ("passed" if bad == 0 else "failed"), f"{1 + len(good) - sum(a is None for a in answered)}/{links} tunnels answered; peak memory (zinc + cloudflared) ~{rep.facts['peak_rss_mb']} MB"
            await rep.step("several-tunnels", many)
        finally:
            async def destroy():
                if not made:
                    return "skipped", "no link was created"
                urls = [Manager.public_url(x) for x in made]
                await asyncio.gather(*[mgr.hard_destroy(x.id) for x in made])
                if not rep.facts.get("public_url_answered"):
                    return "skipped", "the public URL never answered in the first place, so there is nothing to compare"
                await asyncio.sleep(3)
                still = 0
                for u in urls:
                    try:
                        status, _, _ = await fetch(session, u)
                        still += status in (200, 302, 303, 307)
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                        pass
                return ("passed" if still == 0 and mgr._rt == {} else "failed"), f"{still} of {len(urls)} still answering after hard destroy"
            await rep.step("hard-destroy-stops-answering", destroy)
            await mgr.shutdown()


def peak_memory_mb() -> int:
    try:
        import resource
        kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss + resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        return round(kb / (1024 * 1024 if sys.platform == "darwin" else 1024))
    except Exception:
        return -1


# ---- cloudflared and providers ---------------------------------------------------------------------------
async def cloudflared_check(rep: Report, settings) -> bool:
    async def version():
        path = find_cloudflared(settings.cloudflared_path)
        if not path:
            return "failed", "cloudflared not found (install it, or set ZINC_CLOUDFLARED)"
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=20)
        rep.facts["cloudflared_version"] = (out.stdout or out.stderr).strip().splitlines()[0][:120]
        return ("passed" if out.returncode == 0 else "failed"), rep.facts["cloudflared_version"]
    return await rep.step("cloudflared-installed", version)


async def provider_checks(rep: Report, settings) -> None:
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=settings.provider_timeout_s)) as session:
        for name, key_name, provider, url in (
                ("virustotal", "vt_key", VirusTotal(settings), TARGET),
                ("safe-browsing", "gsb_key", SafeBrowsing(settings), SAFE_BROWSING_TEST_URL),
                ("urlhaus", "urlhaus_key", URLhaus(settings), TARGET)):
            async def one(provider=provider, url=url, key_name=key_name, name=name):
                if not getattr(settings, key_name):
                    return "skipped", f"no key (set ZINC_{key_name.upper()} as a repository secret)"
                finding = await provider.check(url, session)
                rep.facts[f"{name}_level"] = finding.level
                if finding.level == "skip":
                    return "failed", f"provider did not answer in the expected shape: {finding.text}"
                return "passed", f"answered with level '{finding.level}' for {url}: {finding.text}"
            await rep.step(f"provider-{name}", one)


async def webhook_check(rep: Report, settings) -> None:
    async def send():
        if not settings.webhook_url:
            return "skipped", "no webhook URL (set ZINC_WEBHOOK_URL)"
        notifier = Notifier(settings)
        notifier.submit("open", {"link_id": "livecheck", "label": "zinc live check", "mode": "plain",
                                 "host": "example.trycloudflare.com", "country": "TW"})
        await notifier.flush()
        await notifier.close()
        return ("passed" if notifier.sent == 1 and not notifier.last_error else "failed"), \
               f"sent={notifier.sent} dropped={notifier.dropped} error={notifier.last_error or 'none'} (format {settings.webhook_format})"
    await rep.step("webhook-accepts-message", send)


async def run(args) -> dict:
    with tempfile.TemporaryDirectory(prefix="zinc-live-") as empty:          # a settings file that does not exist
        settings, warnings = load_settings_with_warnings(Path(args.config) if args.config else Path(empty) / "none.json")
    if args.cloudflared:
        settings.cloudflared_path = args.cloudflared
    rep = Report(settings.secrets() + ([settings.webhook_url] if settings.webhook_url else []))
    rep.facts["python"] = sys.version.split()[0]
    for w in warnings:
        print("warning:", rep.clean(w))
    if not args.skip_tunnel and await cloudflared_check(rep, settings):
        await tunnel_checks(rep, settings, args.links, args.reach_within)
    if not args.skip_providers:
        await provider_checks(rep, settings)
        await webhook_check(rep, settings)
    return rep.result()


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", help="write the result here")
    ap.add_argument("--links", type=int, default=3, help="how many tunnels to open at once (default 3)")
    ap.add_argument("--reach-within", type=float, default=90.0, help="seconds to wait for a new tunnel to answer")
    ap.add_argument("--cloudflared", default="", help="path to cloudflared (default: env ZINC_CLOUDFLARED, then PATH)")
    ap.add_argument("--config", default="", help="settings file to read (default: none, environment variables only)")
    ap.add_argument("--skip-tunnel", action="store_true")
    ap.add_argument("--skip-providers", action="store_true")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any step failed")
    args = ap.parse_args(argv)
    result = asyncio.run(run(args))
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    return 1 if (args.strict and not result["ok"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
