"""Link specification: what a link *is*, independent of tunnels and pages."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import urlsplit

from .geo import is_valid_match
from .options import validate_overrides
from .secret import is_hash

MODES = ("plain", "note", "count", "box", "door")
STATUSES = ("starting", "live", "paused", "soft_dead", "dead", "failed")
MAX_VARIANTS = 6
MAX_LABEL = 40
ROUTE_KINDS = ("geo", "lang", "device")
DEVICES = ("ios", "android", "mobile", "desktop")
_LANG_TAG = re.compile(r"^[a-z]{2,3}(-[a-z0-9]{2,8})*$")


@dataclass
class Variant:
    name: str
    url: str          # "" = trap door (door mode only) -> tombstone
    weight: int = 1


@dataclass
class GeoRule:
    match: str        # "TW" (country) or "asia" (continent)
    variants: list[Variant]


@dataclass
class RouteRule:
    """A non-geo routing rule: by visitor language ("ja", "zh-tw") or device ("ios", "android", "mobile", "desktop")."""
    kind: str         # "lang" | "device"
    match: str
    variants: list[Variant]


@dataclass
class LinkSpec:
    mode: str = "plain"
    variants: list[Variant] = field(default_factory=list)       # default group
    geo_rules: list[GeoRule] = field(default_factory=list)      # country > continent > default
    auto_locale: bool = False
    message: str = ""                                           # note mode text
    token: str = ""                                             # vanity path suffix; "" = random
    options: dict = field(default_factory=dict)                 # per-link overrides of per_link settings
    route_rules: list[RouteRule] = field(default_factory=list)  # language / device rules (order = priority within a kind)
    label: str = ""                                             # a name only the host sees
    pw_hash: str = ""                                           # password gate (pbkdf2 hash; "" = no password)
    max_passes: int = 0                                         # redirect only the first N visitors (0 = unlimited)
    starts_at: float = 0.0                                      # epoch seconds; before this the link says "not open yet"

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @staticmethod
    def from_json(raw: str) -> "LinkSpec":
        d: dict[str, Any] = json.loads(raw)
        return LinkSpec(
            mode=d["mode"],
            variants=[Variant(**v) for v in d["variants"]],
            geo_rules=[GeoRule(r["match"], [Variant(**v) for v in r["variants"]])
                       for r in d.get("geo_rules", [])],
            auto_locale=d.get("auto_locale", False),
            message=d.get("message", ""),
            token=d.get("token", ""),
            route_rules=[RouteRule(r["kind"], r["match"], [Variant(**v) for v in r["variants"]])
                         for r in d.get("route_rules", [])],
            label=d.get("label", ""),
            pw_hash=d.get("pw_hash", ""),
            max_passes=int(d.get("max_passes", 0)),
            starts_at=float(d.get("starts_at", 0.0)),
            options={**d.get("options", {}),
                     **({"show_preview": False} if d.get("reveal_preview") is False else {})},  # pre-registry rows
        )

    def groups(self) -> list[list[Variant]]:
        return [self.variants] + [r.variants for r in self.geo_rules] + [r.variants for r in self.route_rules]


def is_http_url(url: str) -> bool:
    p = urlsplit(url)
    return p.scheme in ("http", "https") and bool(p.hostname)


_BAD_TOKEN = re.compile(r"[/?#%\s\\]")


def validate_token(token: str) -> None:
    """A vanity token ('' = random). Unicode is fine (/今天不想上班); anything that breaks a URL path is not."""
    if token == "":
        return
    if len(token) > 64 or _BAD_TOKEN.search(token) or token in (".", ".."):
        raise ValueError("自訂後綴最多 64 字，不能有 / ? # % 空白")


def validate_spec(spec: LinkSpec) -> None:
    """Raise ValueError with a human message on the first problem."""
    if spec.mode not in MODES:
        raise ValueError(f"unknown mode: {spec.mode!r}")
    if spec.mode == "note" and not spec.message.strip():
        raise ValueError("note mode needs a message")
    validate_token(spec.token)
    spec.options = validate_overrides(spec.options)
    if len(spec.label) > MAX_LABEL or any(ord(c) < 32 for c in spec.label):
        raise ValueError(f"名稱最多 {MAX_LABEL} 字，不能有換行")
    if spec.pw_hash and not is_hash(spec.pw_hash):
        raise ValueError("密碼要先雜湊再存（內部錯誤：不能存明文）")
    if not isinstance(spec.max_passes, int) or isinstance(spec.max_passes, bool) or not 0 <= spec.max_passes <= 1_000_000:
        raise ValueError("通關上限要是 0（不限）到 1000000 的整數")
    if not isinstance(spec.starts_at, (int, float)) or isinstance(spec.starts_at, bool) or spec.starts_at < 0:
        raise ValueError("開放時間不能是負的")
    if not spec.variants:
        raise ValueError("need at least one default target")
    seen: set[str] = set()
    for rule in spec.geo_rules:
        if not is_valid_match(rule.match):
            raise ValueError(f"bad geo match {rule.match!r} (use e.g. 'TW' or 'asia')")
        if rule.match in seen:
            raise ValueError(f"duplicate geo rule for {rule.match!r}")
        seen.add(rule.match)
    seen_route: set[tuple[str, str]] = set()
    for rr in spec.route_rules:
        if rr.kind not in ("lang", "device"):
            raise ValueError(f"規則種類只有 lang 和 device（收到 {rr.kind!r}）")
        rr.match = rr.match.strip().lower()
        if rr.kind == "device" and rr.match not in DEVICES:
            raise ValueError(f"裝置只能是 {'、'.join(DEVICES)}（收到 {rr.match!r}）")
        if rr.kind == "lang" and not _LANG_TAG.match(rr.match):
            raise ValueError(f"語言要像 ja 或 zh-tw（收到 {rr.match!r}）")
        if (rr.kind, rr.match) in seen_route:
            raise ValueError(f"重複的規則：{rr.kind}:{rr.match}")
        seen_route.add((rr.kind, rr.match))
    for group in spec.groups():
        if not group or len(group) > MAX_VARIANTS:
            raise ValueError(f"each group needs 1..{MAX_VARIANTS} variants")
        if spec.mode == "door" and len(group) < 2:
            raise ValueError("door mode needs at least 2 doors per group")
        real = 0
        for v in group:
            if v.weight < 1:
                raise ValueError("weight must be >= 1")
            if v.url == "":
                if spec.mode != "door":
                    raise ValueError("empty url (trap door) only allowed in door mode")
                continue
            if not is_http_url(v.url):
                raise ValueError(f"not an http(s) url: {v.url!r}")
            real += 1
        if real == 0:
            raise ValueError("a group cannot be all trap doors")
