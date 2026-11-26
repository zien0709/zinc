"""Decision engine: geo rule -> variant group -> sticky weighted A/B pick."""
from __future__ import annotations

import hashlib
import random
from typing import Optional, Sequence

from .geo import Geo
from .models import LinkSpec, Variant


_IOS = ("iphone", "ipad", "ipod")


def detect_device(user_agent: str) -> str:
    """'ios' | 'android' | 'mobile' | 'desktop' from the User-Agent (iPadOS in desktop mode looks like a Mac: not detectable)."""
    ua = user_agent.lower()
    if any(k in ua for k in _IOS):
        return "ios"
    if "android" in ua:
        return "android"
    if "mobile" in ua or "opera mini" in ua or "windows phone" in ua:
        return "mobile"
    return "desktop"


def _by_geo(spec: LinkSpec, geo: Geo) -> Optional[tuple[str, list[Variant]]]:
    by_match = {r.match: r for r in spec.geo_rules}       # most specific wins: country, then continent
    if geo.country and geo.country in by_match:
        return geo.country, by_match[geo.country].variants
    if geo.continent and geo.continent in by_match:
        return geo.continent, by_match[geo.continent].variants
    return None


def _by_lang(spec: LinkSpec, tags: Sequence[str]) -> Optional[tuple[str, list[Variant]]]:
    by = {r.match: r for r in spec.route_rules if r.kind == "lang"}
    for tag in tags:                                      # the visitor's own preference order decides
        t = tag.lower()
        for key in (t, t.split("-")[0]):                  # exact (zh-tw) before the bare language (zh)
            if key in by:
                return f"lang:{key}", by[key].variants
    return None


def _by_device(spec: LinkSpec, device: str) -> Optional[tuple[str, list[Variant]]]:
    for r in spec.route_rules:                            # spec order: put "ios" before "mobile" to prefer it
        if r.kind == "device" and (r.match == device or (r.match == "mobile" and device in ("ios", "android"))):
            return f"device:{r.match}", r.variants
    return None


def select_group(spec: LinkSpec, geo: Geo, *, lang_tags: Sequence[str] = (), device: str = "desktop",
                 order: Sequence[str] = ("geo", "lang", "device")) -> tuple[str, list[Variant]]:
    """First kind in `order` that has a matching rule wins; kinds not listed are ignored; else the default group."""
    for kind in order:
        hit = (_by_geo(spec, geo) if kind == "geo" else _by_lang(spec, lang_tags) if kind == "lang"
               else _by_device(spec, device) if kind == "device" else None)
        if hit:
            return hit
    return "default", spec.variants


def pick_sticky(variants: list[Variant], vid: str, salt: str) -> Variant:
    """Weighted pick that is stable for one visitor: refreshing never flips A to B."""
    total = sum(v.weight for v in variants)
    digest = hashlib.sha256(f"{salt}:{vid}".encode()).digest()
    point = int.from_bytes(digest[:8], "big") % total
    for v in variants:
        if point < v.weight:
            return v
        point -= v.weight
    return variants[-1]  # unreachable: point < total


def pick_random(variants: list[Variant], rng: Optional[random.Random] = None) -> Variant:
    """Box mode: a fresh weighted draw on every open."""
    return (rng or random).choices(variants, weights=[v.weight for v in variants], k=1)[0]


def visitor_id(salt: str, ip: str, user_agent: str) -> str:
    """Per-link salted hash: raw IP is never stored, and ids cannot be joined across links."""
    return hashlib.sha256(f"{salt}|{ip}|{user_agent}".encode()).hexdigest()[:16]
