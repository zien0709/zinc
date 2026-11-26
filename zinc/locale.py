"""Adaptive locale: turn (Accept-Language, country) into the *target site's own* localized URL.

Never guess `/zh-tw` blindly (google.com/zh-tw is a 404). Order: the target's declared hreflang
alternates from the scan -> a small built-in rule table -> leave the URL untouched.
The rule table is from memory and NOT verified against the live sites: see UNVERIFIED_RULES.
"""
from __future__ import annotations

from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import is_http_url
from .scan import ScanResult

_COUNTRY_LANG = {"TW": "zh-TW", "HK": "zh-HK", "MO": "zh-HK", "CN": "zh-CN", "SG": "zh-CN",
                 "JP": "ja", "KR": "ko", "DE": "de", "AT": "de", "FR": "fr", "ES": "es",
                 "IT": "it", "PT": "pt", "BR": "pt-BR", "RU": "ru", "TH": "th", "VN": "vi",
                 "ID": "id", "NL": "nl", "PL": "pl", "TR": "tr", "GB": "en-GB", "US": "en-US"}
_ZH_COUNTRY = {"TW": "zh-TW", "HK": "zh-HK", "MO": "zh-HK", "CN": "zh-CN", "SG": "zh-CN"}
# hreflang spellings that mean the same thing as the BCP47 tag on the left
_ALIASES = {"zh-tw": ["zh-hant-tw", "zh-hant"], "zh-hk": ["zh-hant-hk", "zh-hant"],
            "zh-cn": ["zh-hans-cn", "zh-hans"], "zh-sg": ["zh-hans-sg", "zh-hans"]}


def parse_accept_language(header: str) -> list[str]:
    """'zh-TW,zh;q=0.9,en;q=0.8' -> ['zh-TW','zh','en'] ordered by q (stable)."""
    items: list[tuple[float, int, str]] = []
    for i, part in enumerate((header or "").split(",")):
        tag, _, params = part.strip().partition(";")
        tag = tag.strip()
        if not tag or tag == "*":
            continue
        q = 1.0
        if params.strip().startswith("q="):
            try:
                q = float(params.strip()[2:])
            except ValueError:
                q = 0.0
        if q > 0:
            items.append((-q, i, tag))
    return [t for _, _, t in sorted(items)]


def candidate_locales(accept_language: str, country: Optional[str]) -> list[str]:
    """Most specific first. Bare 'zh' is refined by the visitor's country (TW -> zh-TW)."""
    out: list[str] = []
    for tag in parse_accept_language(accept_language):
        if tag.lower() == "zh" and country in _ZH_COUNTRY:
            out.append(_ZH_COUNTRY[country])
        out.append(tag)
    if not out and country in _COUNTRY_LANG:
        out.append(_COUNTRY_LANG[country])
    seen: set[str] = set()
    return [t for t in out if not (t.lower() in seen or seen.add(t.lower()))]


def match_hreflang(candidates: list[str], hreflang: dict[str, str]) -> Optional[tuple[str, str]]:
    """First candidate that the page declares, exact tag, alias, then bare language."""
    for tag in candidates:
        low = tag.lower()
        for key in [low, *_ALIASES.get(low, []), low.split("-")[0]]:
            if key in hreflang and is_http_url(hreflang[key]):
                return key, hreflang[key]
    return None


# ---- built-in rules (UNVERIFIED against live sites) -----------------------------------------
def _set_query(url: str, key: str, value: str) -> str:
    p = urlsplit(url)
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != key]
    q.append((key, value))
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))


def _rule_hl(url: str, locale: str, country: Optional[str]) -> Optional[str]:
    return _set_query(url, "hl", locale)                                   # google, youtube


def _rule_ms(url: str, locale: str, country: Optional[str]) -> Optional[str]:
    p = urlsplit(url)
    if "-" not in locale or p.path.count("/") > 1 and not p.path.startswith("/en-us"):
        return None                                                        # only root / /en-us/…
    rest = p.path[len("/en-us"):] if p.path.startswith("/en-us") else p.path
    return urlunsplit((p.scheme, p.netloc, f"/{locale.lower()}{rest or '/'}", p.query, p.fragment))


def _rule_wikipedia(url: str, locale: str, country: Optional[str]) -> Optional[str]:
    p = urlsplit(url)
    if p.path not in ("", "/"):
        return None                       # article titles differ per language: only the portal root
    lang = {"zh-tw": "zh", "zh-hk": "zh", "zh-cn": "zh"}.get(locale.lower(), locale.split("-")[0].lower())
    return urlunsplit((p.scheme, f"{lang}.wikipedia.org", "/", p.query, p.fragment))


def _rule_apple(url: str, locale: str, country: Optional[str]) -> Optional[str]:
    p = urlsplit(url)
    if p.path not in ("", "/") or not country or country == "US":
        return None
    return urlunsplit((p.scheme, p.netloc, f"/{country.lower()}/", p.query, p.fragment))


UNVERIFIED_RULES = {
    "google.com": _rule_hl, "youtube.com": _rule_hl, "microsoft.com": _rule_ms,
    "wikipedia.org": _rule_wikipedia, "apple.com": _rule_apple,
}


def _rule_for(host: str):
    host = host.lower()
    for base, fn in UNVERIFIED_RULES.items():
        if host == base or host.endswith("." + base):
            return fn
    return None


def finalize_url(url: str, *, auto_locale: bool, accept_language: str, country: Optional[str],
                 scans: dict[str, ScanResult]) -> tuple[str, Optional[str]]:
    """Return (url_to_redirect_to, why). `why` is None when the URL was left untouched."""
    if not auto_locale or not is_http_url(url):
        return url, None
    cands = candidate_locales(accept_language, country)
    if not cands:
        return url, None
    scan = scans.get(url)
    if scan and scan.hreflang:
        hit = match_hreflang(cands, scan.hreflang)
        if hit:
            return hit[1], f"hreflang:{hit[0]}"
    rule = _rule_for(urlsplit(url).hostname or "")
    if rule:
        for tag in cands:
            new = rule(url, tag, country)
            if new is None:                      # this rule has nothing for that language: try the visitor's next one
                continue
            # The visitor's first usable language decides. If the URL already speaks it, leave it alone
            # (do not fall through to a lower-priority language and override what the link's author chose).
            return (new, f"rule:{tag}") if new != url else (url, None)
    return url, None
