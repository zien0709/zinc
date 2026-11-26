"""Target scanner: fetch a URL safely once, extract what the visitor page shows.

Everything scanned is untrusted input. SSRF is blocked in two places: the literal host is
checked before each hop, and the connector's resolver only ever returns public addresses, so a
DNS-rebinding answer cannot sneak a private IP in between check and connect.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from dataclasses import dataclass, field, asdict
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

MAX_BYTES = 512 * 1024
MAX_HOPS = 5
TIMEOUT_S = 5


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
# Python still calls these "global", but they are not somewhere a stranger's link should make us connect to.
_V6_NEVER = [ipaddress.ip_network(n) for n in ("64:ff9b:1::/48", "fec0::/10")]


def ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:                                    # ::ffff:10.0.0.1 is really 10.0.0.1
            addr = addr.ipv4_mapped
        elif addr in _NAT64:                                    # 64:ff9b::7f00:1 translates to 127.0.0.1
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        elif any(addr in net for net in _V6_NEVER):
            return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_reserved or addr.is_unspecified or not addr.is_global)


def literal_host_blocked(host: str) -> bool:
    """True when the host is an IP literal that is not public, or an obviously local name."""
    h = host.strip("[]").lower()
    if h in ("localhost",) or h.endswith(".localhost") or h.endswith(".local") or h.endswith(".internal"):
        return True
    try:
        ipaddress.ip_address(h)
    except ValueError:
        return False  # a normal hostname: the resolver guard handles it
    return not ip_is_public(h)


class SafeResolver(AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_INET):
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        out = [{"hostname": host, "host": i[4][0], "port": port, "family": i[0], "proto": 0,
                "flags": socket.AI_NUMERICHOST} for i in infos if ip_is_public(i[4][0])]
        if not out:
            raise OSError(f"{host} resolves only to non-public addresses")
        return out

    async def close(self) -> None:
        return None


@dataclass
class ScanResult:
    url: str
    ok: bool = False
    status: Optional[int] = None
    final_url: Optional[str] = None
    chain: list[str] = field(default_factory=list)
    title: str = ""
    description: str = ""
    favicon: str = ""
    html_lang: str = ""
    hreflang: dict[str, str] = field(default_factory=dict)   # lowercase tag -> absolute url
    https: bool = False
    elapsed_ms: int = 0
    error: str = ""
    scanned_at: float = 0.0


class _Extractor(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.title = ""
        self._in_title = False
        self.meta: dict[str, str] = {}
        self.icons: list[tuple[str, str]] = []
        self.hreflang: dict[str, str] = {}
        self.html_lang = ""

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html" and a.get("lang"):
            self.html_lang = a["lang"]
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = (a.get("property") or a.get("name") or "").lower()
            if key and a.get("content") and key not in self.meta:
                self.meta[key] = a["content"]
        elif tag == "link":
            rels = a.get("rel", "").lower().split()
            href = a.get("href", "")
            if not href:
                return
            if "icon" in rels:
                self.icons.append((a.get("rel", ""), urljoin(self.base, href)))
            if "alternate" in rels and a.get("hreflang"):
                self.hreflang.setdefault(a["hreflang"].lower(), urljoin(self.base, href))

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 300:
            self.title += data


def parse_html(text: str, base_url: str) -> dict:
    p = _Extractor(base_url)
    try:
        p.feed(text)
    except Exception:  # malformed markup must never crash a scan
        pass
    icon = p.icons[0][1] if p.icons else urljoin(base_url, "/favicon.ico")
    return {
        "title": " ".join((p.meta.get("og:title") or p.title).split())[:200],
        "description": " ".join((p.meta.get("og:description") or p.meta.get("description", "")).split())[:300],
        "favicon": icon if urlsplit(icon).scheme in ("http", "https") else "",
        "html_lang": p.html_lang[:20],
        "hreflang": {k: v for k, v in p.hreflang.items()
                     if urlsplit(v).scheme in ("http", "https")},
    }


async def scan_url(url: str, *, allow_private: bool = False, session: Optional[aiohttp.ClientSession] = None,
                   max_bytes: int = MAX_BYTES, max_hops: int = MAX_HOPS, timeout_s: float = TIMEOUT_S,
                   user_agent: str = "zinc-scanner/1.0") -> ScanResult:
    """`allow_private` exists for tests against a loopback server only."""
    res = ScanResult(url=url, scanned_at=time.time())
    t0 = time.monotonic()
    own = session is None
    if own:
        connector = aiohttp.TCPConnector(resolver=None if allow_private else SafeResolver())
        session = aiohttp.ClientSession(connector=connector,
                                        timeout=aiohttp.ClientTimeout(total=timeout_s))
    try:
        current = url
        for _ in range(max_hops + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                res.error = "not an http(s) url"
                return res
            if not allow_private and literal_host_blocked(parts.hostname):
                res.error = "blocked: private or local address"
                return res
            res.chain.append(current)
            async with session.get(current, allow_redirects=False,
                                   headers={"User-Agent": user_agent}) as resp:
                res.status = resp.status
                if resp.status in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
                    current = urljoin(current, resp.headers["Location"])
                    continue
                body = await resp.content.read(max_bytes)
                charset = resp.charset or "utf-8"
                info = parse_html(body.decode(charset, errors="replace"), current)
                res.final_url = current
                res.https = urlsplit(current).scheme == "https"
                res.ok = resp.status < 400
                res.title, res.description = info["title"], info["description"]
                res.favicon, res.html_lang, res.hreflang = (
                    info["favicon"], info["html_lang"], info["hreflang"])
                return res
        res.error = f"too many redirects (> {max_hops})"
        return res
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, LookupError) as e:
        res.error = f"{type(e).__name__}: {e}"[:200]
        return res
    finally:
        res.elapsed_ms = int((time.monotonic() - t0) * 1000)
        if own:
            await session.close()


def dump_scans(scans: dict[str, "ScanResult"]) -> str:
    return json.dumps({u: asdict(r) for u, r in scans.items()}, ensure_ascii=False)


def load_scans(raw: Optional[str]) -> dict[str, "ScanResult"]:
    if not raw:
        return {}
    try:
        return {u: ScanResult(**d) for u, d in json.loads(raw).items()}
    except (ValueError, TypeError, AttributeError):
        return {}  # a corrupt cache (bad JSON or wrong shape) must never take a link down


async def scan_all(urls: list[str], **kw) -> dict[str, ScanResult]:
    uniq = list(dict.fromkeys(u for u in urls if u))
    results = await asyncio.gather(*(scan_url(u, **kw) for u in uniq))
    return dict(zip(uniq, results))
