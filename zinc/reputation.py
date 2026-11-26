"""Safety checks for link targets.

L0  local checks: no network, no key. Always run.
L1  providers (VirusTotal, Google Safe Browsing, URLhaus): the user supplies their own API key.
Results are aggregated into ok / info / warn / block. "ok" means *nothing found*, never "safe".

Privacy: provider lookups send the target URL to a third party. URLs that carry token-like
parameters are not sent unless the user opted in, and VirusTotal submission is off by default.
Provider response shapes follow each vendor's public docs; the URLhaus endpoint could not be
confirmed against its official page (robots-blocked) and is marked UNVERIFIED.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Awaitable, Callable, Optional, Sequence
from urllib.parse import parse_qsl, urlsplit

import aiohttp

from .config import Settings, scrub
from .scan import ScanResult

ORDER = {"skip": -1, "ok": 0, "info": 1, "warn": 2, "block": 3}
_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rebrand.ly", "t.ly"}
_SECRET_KEYS = {"token", "access_token", "auth", "key", "apikey", "api_key", "sig", "signature", "secret",
                "password", "pwd", "session", "sid", "code", "x-amz-signature", "x-amz-credential"}


@dataclass
class Finding:
    source: str          # "local", "virustotal", "safebrowsing", "urlhaus", "privacy"
    level: str           # skip | ok | info | warn | block
    text: str


@dataclass
class Verdict:
    level: str = "ok"
    findings: list[Finding] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)   # providers that really answered (not skipped)
    at: float = 0.0

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @staticmethod
    def from_json(raw: str) -> "Verdict":
        d = json.loads(raw)
        return Verdict(d["level"], [Finding(**f) for f in d["findings"]], d["checked"], d["at"])

    def reasons(self, at_least: str = "warn") -> list[str]:
        return [f"{f.source}: {f.text}" for f in self.findings if ORDER[f.level] >= ORDER[at_least]]


def dump_verdicts(v: dict[str, Verdict]) -> str:
    return json.dumps({u: json.loads(x.to_json()) for u, x in v.items()}, ensure_ascii=False)


def load_verdicts(raw: Optional[str]) -> dict[str, Verdict]:
    if not raw:
        return {}
    try:
        return {u: Verdict.from_json(json.dumps(d)) for u, d in json.loads(raw).items()}
    except (ValueError, KeyError, TypeError, AttributeError):
        return {}


def aggregate(findings: list[Finding], now: float) -> Verdict:
    level = max((f.level for f in findings), key=ORDER.__getitem__, default="ok")
    if level == "skip":
        level = "ok"
    checked = sorted({f.source for f in findings if f.level != "skip" and f.source != "privacy"})
    return Verdict(level, findings, checked, now)


def has_secret_params(url: str) -> bool:
    p = urlsplit(url)
    if p.username or p.password:
        return True
    return any(k.lower() in _SECRET_KEYS for k, _ in parse_qsl(p.query, keep_blank_values=True))


def _in_domain(host: str, domain: str) -> bool:
    host, domain = host.lower().rstrip("."), domain.lower().lstrip("*.").rstrip(".")
    return bool(domain) and (host == domain or host.endswith("." + domain))


# ---- L0 -----------------------------------------------------------------------------------
L0_IDS = ("https", "ip_literal", "punycode", "userinfo", "tunnel_loop", "blocklist", "shortener",
          "long_url", "scan_error", "redirects")


def local_checks(url: str, scan: Optional[ScanResult], blocklist: Sequence[str] = (),
                 off: Sequence[str] = (), levels: Optional[dict] = None) -> list[Finding]:
    """Built-in checks, no network. `off` silences a check by id; `levels` re-grades one
    (a level of "ok" silences it as well). Unknown ids are ignored."""
    levels = levels or {}
    f: list[Finding] = []
    p = urlsplit(url)
    host = (p.hostname or "").lower()

    def add(cid: str, level: str, text: str) -> None:
        if cid in off:
            return
        level = levels.get(cid, level)
        if level in ORDER and level not in ("ok", "skip"):
            f.append(Finding("local", level, text))

    if p.scheme != "https":
        add("https", "warn", "目標不是 HTTPS")
    if host.replace(".", "").isdigit() or ":" in host:
        add("ip_literal", "warn", "網址用 IP 而不是網域")
    if any(lbl.startswith("xn--") for lbl in host.split(".")):
        try:
            shown = host.encode().decode("idna")
        except UnicodeError:
            shown = host
        add("punycode", "warn", f"國際化網域（punycode）：{shown}，可能是同形字偽裝")
    if p.username:
        add("userinfo", "warn", "網址含 user@ 前綴，常用來偽裝成別的網站")
    if _in_domain(host, "trycloudflare.com"):
        add("tunnel_loop", "block", "目標本身是 trycloudflare 網址（迴圈或疊加隧道）")
    if any(_in_domain(host, d) for d in blocklist):
        add("blocklist", "block", "命中本地黑名單")
    if host in _SHORTENERS:
        add("shortener", "info", "目標本身是短網址服務")
    if len(url) > 2000:
        add("long_url", "warn", "網址過長（>2000 字元）")
    if scan is not None:
        if scan.error:
            add("scan_error", "warn", f"掃描失敗：{scan.error}")
        elif scan.status is not None and scan.status >= 400:
            add("scan_error", "warn", f"目標回應 HTTP {scan.status}")
        if len(scan.chain) > 4:
            add("redirects", "warn", f"跳轉 {len(scan.chain) - 1} 次")
        hosts = [urlsplit(u).hostname for u in scan.chain]
        if len({h for h in hosts if h}) > 1:
            add("redirects", "info", f"跳轉到不同網域：{hosts[0]} → {hosts[-1]}")
    if not any(x.level in ("warn", "block") for x in f):
        f.append(Finding("local", "ok", "基礎檢查通過"))
    return f


# ---- rate limiting ------------------------------------------------------------------------
class Throttle:
    """Sliding per-minute window plus a per-run daily budget (resets on restart, so it can
    under-count: a real 429 from the provider is still handled)."""

    def __init__(self, per_minute: int, per_day: int, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], Awaitable] = asyncio.sleep):
        self.per_minute, self.per_day, self.clock, self.sleep = per_minute, per_day, clock, sleep
        self._window: deque[float] = deque()
        self._day: deque[float] = deque()

    async def acquire(self, max_wait: float = 20.0) -> bool:
        now = self.clock()
        while self._day and now - self._day[0] >= 86400:
            self._day.popleft()
        if len(self._day) >= self.per_day:
            return False
        while self._window and now - self._window[0] >= 60:
            self._window.popleft()
        if len(self._window) >= self.per_minute:
            wait = 60 - (now - self._window[0])
            if wait > max_wait:
                return False
            await self.sleep(wait)
            now = self.clock()
            while self._window and now - self._window[0] >= 60:
                self._window.popleft()
        self._window.append(now)
        self._day.append(now)
        return True


# ---- providers ----------------------------------------------------------------------------
class Provider:
    name = "provider"

    def __init__(self, settings: Settings):
        self.s = settings

    async def check(self, url: str, session: aiohttp.ClientSession) -> Finding:
        raise NotImplementedError

    def skip(self, text: str) -> Finding:
        return Finding(self.name, "skip", text)


class VirusTotal(Provider):
    name = "virustotal"

    def __init__(self, settings: Settings, base_url: str = "https://www.virustotal.com/api/v3",
                 throttle: Optional[Throttle] = None, sleep: Callable[[float], Awaitable] = asyncio.sleep):
        super().__init__(settings)
        self.base, self.sleep = base_url, sleep
        self._own_throttle = throttle is None
        self.throttle = throttle or Throttle(settings.vt_per_minute, settings.vt_per_day)

    @staticmethod
    def url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def _verdict(self, stats: dict) -> Finding:
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        rest = int(stats.get("harmless", 0)) + int(stats.get("undetected", 0))
        text = f"{mal} 家引擎判惡意、{sus} 家可疑、{rest} 家未發現問題"
        if mal >= self.s.vt_malicious_block:
            return Finding(self.name, "block", text)
        if mal >= 1 or sus >= 1:
            return Finding(self.name, "warn", text)
        return Finding(self.name, "ok", text)

    async def check(self, url: str, session: aiohttp.ClientSession) -> Finding:
        if not self.s.vt_key:
            return self.skip("未設定 key")
        headers = {"x-apikey": self.s.vt_key}
        if self._own_throttle:      # the limits are settings: a change applies to the next check
            self.throttle.per_minute, self.throttle.per_day = self.s.vt_per_minute, self.s.vt_per_day
        if not await self.throttle.acquire():
            return self.skip("VirusTotal 額度或限流用完，稍後重掃")
        async with session.get(f"{self.base}/urls/{self.url_id(url)}", headers=headers) as r:
            if r.status == 200:
                data = await r.json(content_type=None)
                stats = (data.get("data", {}).get("attributes", {}) or {}).get("last_analysis_stats")
                return self._verdict(stats) if stats else self.skip("VirusTotal 回應沒有分析統計")
            if r.status in (401, 403):
                return self.skip("VirusTotal key 無效或沒有權限")
            if r.status == 429:
                return self.skip("VirusTotal 限流（429）")
            if r.status != 404:
                return self.skip(f"VirusTotal 回應 HTTP {r.status}")
        if not self.s.vt_submit_unknown:
            return self.skip("VirusTotal 沒有這個網址的紀錄（未提交：提交會讓網址對社群可見）")
        if not await self.throttle.acquire():
            return self.skip("VirusTotal 額度或限流用完，稍後重掃")
        async with session.post(f"{self.base}/urls", headers=headers, data={"url": url}) as r:
            if r.status != 200:
                return self.skip(f"VirusTotal 提交失敗 HTTP {r.status}")
            analysis_id = (await r.json(content_type=None)).get("data", {}).get("id")
        for _ in range(3):
            await self.sleep(5)
            if not await self.throttle.acquire():
                break
            async with session.get(f"{self.base}/analyses/{analysis_id}", headers=headers) as r:
                if r.status == 200:
                    attrs = (await r.json(content_type=None)).get("data", {}).get("attributes", {})
                    if attrs.get("status") == "completed" and attrs.get("stats"):
                        return self._verdict(attrs["stats"])
        return self.skip("VirusTotal 還在分析中，稍後重掃")


class SafeBrowsing(Provider):
    name = "safebrowsing"
    THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]

    def __init__(self, settings: Settings, base_url: str = "https://safebrowsing.googleapis.com/v4"):
        super().__init__(settings)
        self.base = base_url

    async def check(self, url: str, session: aiohttp.ClientSession) -> Finding:
        if not self.s.gsb_key:
            return self.skip("未設定 key")
        body = {"client": {"clientId": "zinc", "clientVersion": "1.0"},
                "threatInfo": {"threatTypes": self.THREATS, "platformTypes": ["ANY_PLATFORM"],
                               "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
        async with session.post(f"{self.base}/threatMatches:find", params={"key": self.s.gsb_key}, json=body) as r:
            if r.status == 200:
                matches = (await r.json(content_type=None)).get("matches") or []
                if matches:
                    kinds = sorted({m.get("threatType", "?") for m in matches})
                    return Finding(self.name, "block", "Google Safe Browsing 列為：" + "、".join(kinds))
                return Finding(self.name, "ok", "Google Safe Browsing 未列入")
            if r.status in (400, 403):
                return self.skip("Safe Browsing key 無效或該專案沒啟用 API")
            if r.status == 429:
                return self.skip("Safe Browsing 額度用完（429）")
            return self.skip(f"Safe Browsing 回應 HTTP {r.status}")


class URLhaus(Provider):
    """UNVERIFIED: endpoint and field names are from memory; the official page blocks fetching."""
    name = "urlhaus"

    def __init__(self, settings: Settings, base_url: str = "https://urlhaus-api.abuse.ch/v1"):
        super().__init__(settings)
        self.base = base_url

    async def check(self, url: str, session: aiohttp.ClientSession) -> Finding:
        if not self.s.urlhaus_key:
            return self.skip("未設定 Auth-Key")
        async with session.post(f"{self.base}/url/", data={"url": url}, headers={"Auth-Key": self.s.urlhaus_key}) as r:
            if r.status in (401, 403):
                return self.skip("URLhaus Auth-Key 無效")
            if r.status != 200:
                return self.skip(f"URLhaus 回應 HTTP {r.status}")
            data = await r.json(content_type=None)
        status = data.get("query_status")
        if status == "no_results":
            return Finding(self.name, "ok", "URLhaus 沒有紀錄")
        if status == "ok":
            threat = data.get("threat") or "malware_download"
            if data.get("url_status") == "online":
                return Finding(self.name, "block", f"URLhaus 標記為仍在線上的惡意網址（{threat}）")
            return Finding(self.name, "warn", f"URLhaus 曾標記為惡意（{threat}），目前離線")
        return self.skip(f"URLhaus 回應無法解讀：{status}")


# ---- orchestration ------------------------------------------------------------------------
class Reputation:
    def __init__(self, settings: Settings, providers: Optional[Sequence[Provider]] = None,
                 clock: Callable[[], float] = time.time, cache_ttl: Optional[float] = None):
        self.s, self.clock, self._cache_ttl = settings, clock, cache_ttl
        self.providers = list(providers) if providers is not None else [
            VirusTotal(settings), SafeBrowsing(settings), URLhaus(settings)]
        self._cache: dict[tuple[str, str], tuple[float, Finding]] = {}

    @property
    def cache_ttl(self) -> float:
        return self._cache_ttl if self._cache_ttl is not None else self.s.cache_ttl_h * 3600

    def active(self) -> list[Provider]:
        return [p for p in self.providers if p.name in self.s.providers]

    def allowed(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return any(_in_domain(host, d) for d in self.s.allowlist)

    async def _ask(self, p: Provider, url: str, session: aiohttp.ClientSession) -> Finding:
        key = (p.name, url)
        hit = self._cache.get(key)
        if hit and self.clock() - hit[0] < self.cache_ttl:
            return hit[1]
        try:
            res = await p.check(url, session)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            return Finding(p.name, "skip", scrub(f"{p.name} 連線失敗：{type(e).__name__}", self.s.secrets()))
        if res.level != "skip" and self.cache_ttl > 0:
            self._cache[key] = (self.clock(), res)
        res.text = scrub(res.text, self.s.secrets())
        return res

    async def check_all(self, urls: Sequence[str], scans: dict[str, ScanResult]) -> dict[str, Verdict]:
        out: dict[str, Verdict] = {}
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.s.provider_timeout_s)) as session:
            for url in dict.fromkeys(u for u in urls if u):
                findings = local_checks(url, scans.get(url), self.s.blocklist,
                                        self.s.l0_off, self.s.l0_levels)
                if self.allowed(url):
                    findings.append(Finding("privacy", "info", "網域在白名單內，未送第三方檢查"))
                elif has_secret_params(url) and not self.s.send_secret_urls:
                    findings.append(Finding("privacy", "info",
                                            "網址含 token 類參數，未送第三方檢查（可在設定開啟）"))
                else:
                    findings += await asyncio.gather(*(self._ask(p, url, session) for p in self.active()))
                out[url] = aggregate(findings, self.clock())
        return out


def worst(verdicts: dict[str, Verdict]) -> Optional[tuple[str, Verdict]]:
    if not verdicts:
        return None
    return max(verdicts.items(), key=lambda kv: ORDER[kv[1].level])
