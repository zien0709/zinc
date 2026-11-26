"""Pure presentation helpers for the TUI (no Textual import, so they are unit-testable)."""
from __future__ import annotations

import math
from typing import Optional

from rich.text import Text

from .lifecycle import effective_state
from datetime import datetime

from .models import GeoRule, RouteRule, Variant
from .options import LEVEL_LABELS, OPTIONS, Opt, validate_overrides
from .reputation import ORDER, load_verdicts
from .scan import load_scans
from .store import Link

_SPARK = "▁▂▃▄▅▆▇█"


def spark(values: list[int]) -> str:
    peak = max(values, default=0)
    if peak == 0:
        return _SPARK[0] * len(values)
    return "".join(_SPARK[0] if v <= 0 else _SPARK[max(1, round(v / peak * 7))] for v in values)


def bars(data: dict[str, int], width: int = 12, top: int = 5) -> list[str]:
    """'TW ██████ 5' lines, longest first; anything beyond `top` is folded into 'other'."""
    items = sorted(data.items(), key=lambda kv: (-kv[1], kv[0]))
    if len(items) > top:
        rest = sum(n for _, n in items[top:])
        items = items[:top] + [("other", rest)]
    peak = max((n for _, n in items), default=0)
    label_w = max((len(k) for k, _ in items), default=0)
    return [f"{k:<{label_w}} {'█' * max(1, math.ceil(n / peak * width))} {n}" for k, n in items if n > 0]


def fmt_remaining(seconds: Optional[float]) -> str:
    if seconds is None:
        return "∞"
    s = int(max(0, seconds))
    return f"{s // 3600}h{s % 3600 // 60:02d}m" if s >= 3600 else f"{s // 60:02d}:{s % 60:02d}"


def state_label(link: Link, now: float, opens: int) -> str:
    if link.status == "failed":
        return "✗ 失敗"
    if link.status == "dead":
        return "✝ 死亡"
    if link.status in ("starting", "live") and link.spec.starts_at and now < link.spec.starts_at:
        return "⏳ 未開放"
    eff = effective_state(link, now, opens)
    if link.status == "soft_dead" or (eff == "dead" and link.expires_at is not None and now >= link.expires_at):
        return "◐ 軟死"
    if eff == "dead":
        return "◍ 額滿"
    if link.status == "paused":
        return "⏸ 暫停"
    return "… 啟動" if link.status == "starting" else "● 運作"


def short_host(link: Link, width: int = 26) -> str:
    h = (link.hostname or "（未連線）").replace(".trycloudflare.com", "")
    return h if len(h) <= width else h[: width - 1] + "…"


# ---- creation-form mini syntax ----------------------------------------------------------------
def parse_targets(text: str) -> list[Variant]:
    """'https://a.example https://b.example*3 !' -> A(w1) B(w3) trap. '!' is a trap door."""
    out: list[Variant] = []
    for i, tok in enumerate(text.split()):
        name = chr(ord("A") + i) if i < 26 else f"V{i}"
        if tok == "!":
            out.append(Variant(name, ""))
            continue
        url, weight = tok, 1
        if "*" in tok:
            head, _, tail = tok.rpartition("*")
            if tail.isdigit():
                url, weight = head, int(tail)
        out.append(Variant(name, url, weight))
    return out


def parse_geo(text: str) -> list[GeoRule]:
    """'asia=https://a.example https://b.example; TW=https://tw.example' -> two rules."""
    rules = []
    for chunk in filter(None, (c.strip() for c in text.split(";"))):
        match, _, rest = chunk.partition("=")
        if not rest.strip():
            raise ValueError(f"規則缺少網址：{chunk!r}")
        rules.append(GeoRule(match.strip(), parse_targets(rest)))
    return rules


def parse_rules(text: str) -> tuple[list[GeoRule], list[RouteRule]]:
    """'asia=URL; TW=URL URL; lang:ja=URL; device:ios=URL' -> (geo rules, language/device rules).
    No prefix = a place (country code or continent name)."""
    geo: list[GeoRule] = []
    route: list[RouteRule] = []
    for chunk in filter(None, (c.strip() for c in text.split(";"))):
        match, _, rest = chunk.partition("=")
        if not rest.strip():
            raise ValueError(f"規則缺少網址：{chunk!r}")
        key = match.strip()
        kind, colon, value = key.partition(":")
        if colon:
            if kind.lower() not in ("lang", "device"):
                raise ValueError(f"規則前綴只有 lang: 和 device:（收到 {kind!r}）")
            route.append(RouteRule(kind.lower(), value.strip(), parse_targets(rest)))
        else:
            geo.append(GeoRule(key, parse_targets(rest)))
    return geo, route


def format_targets(variants: list[Variant]) -> str:
    return " ".join("!" if not v.url else v.url + (f"*{v.weight}" if v.weight > 1 else "") for v in variants)


def format_rules(spec) -> str:
    """Inverse of parse_rules (for cloning / editing a link)."""
    parts = [f"{r.match}={format_targets(r.variants)}" for r in spec.geo_rules]
    parts += [f"{r.kind}:{r.match}={format_targets(r.variants)}" for r in spec.route_rules]
    return "; ".join(parts)


def format_overrides(options: dict) -> str:
    out = []
    for k, v in options.items():
        text = ", ".join(map(str, v)) if isinstance(v, list) else str(v)
        out.append(f"{k}={text}")
    return "; ".join(out)


def form_values(spec) -> dict:
    """What to pre-fill in the creation form when cloning or editing `spec` (the password hash is never shown)."""
    return {"targets": format_targets(spec.variants), "mode": spec.mode, "message": spec.message,
            "geo": format_rules(spec), "locale": spec.auto_locale, "label": spec.label,
            "max_passes": str(spec.max_passes) if spec.max_passes else "",
            "starts": "", "ovr": format_overrides(spec.options), "has_password": bool(spec.pw_hash)}


def parse_start(text: str, now: float) -> float:
    """'' -> 0 (open at once) | '+30' / '+30m' / '+2h' / '+1d' from now | 'YYYY-MM-DD HH:MM' in local time."""
    text = text.strip()
    if not text:
        return 0.0
    if text.startswith("+"):
        body = text[1:].strip().lower()
        unit = body[-1] if body and body[-1] in "mhd" else "m"
        num = body[:-1] if body and body[-1] in "mhd" else body
        try:
            n = float(num)
        except ValueError:
            raise ValueError(f"開放時間看不懂：{text!r}（例：+30m、+2h、+1d、2026-12-25 09:00）") from None
        if n <= 0:
            raise ValueError("開放時間要在未來")
        return now + n * {"m": 60, "h": 3600, "d": 86400}[unit]
    try:
        when = datetime.strptime(text, "%Y-%m-%d %H:%M").timestamp()
    except ValueError:
        raise ValueError(f"開放時間看不懂：{text!r}（例：+30m、+2h、+1d、2026-12-25 09:00）") from None
    if when <= now:
        raise ValueError("開放時間已經過了，請填未來的時間")
    return when


# ---- detail panel -----------------------------------------------------------------------------
def detail_text(link: Link, stats: dict, public_url: Optional[str], now: float,
                error: Optional[str] = None) -> Text:
    t = Text()
    h = lambda s: t.append(s + "\n", style="bold")  # noqa: E731
    h(public_url or "（沒有公開網址）")
    spec = link.spec
    if spec.label:
        t.append(f"📛 {spec.label}\n")
    flags = []
    if spec.pw_hash:
        flags.append("🔒 有密碼")
    if spec.max_passes:
        flags.append(f"🎟 通關上限 {spec.max_passes}")
    if spec.starts_at and spec.starts_at > now:
        flags.append("⏳ 開放於 " + datetime.fromtimestamp(spec.starts_at).strftime("%m-%d %H:%M"))
    if flags:
        t.append("　".join(flags) + "\n")
    t.append(f"玩法 {spec.mode}　剩餘 {fmt_remaining(link.remaining(now))}"
             + (f"　上限 {link.max_opens} 人" if link.max_opens else "")
             + ("　🌐 自適應語系" if spec.auto_locale else "") + "\n\n")
    h("目標")
    for v in spec.variants:
        t.append(f"  {v.name}  {v.url or '💀 陷阱門'}" + (f"  ×{v.weight}" if v.weight > 1 else "") + "\n")
    for r in spec.geo_rules:
        t.append(f"  📍{r.match}\n")
        for v in r.variants:
            t.append(f"     {v.name}  {v.url or '💀 陷阱門'}\n")
    for r in spec.route_rules:
        t.append(f"  {'🈯' if r.kind == 'lang' else '📱'}{r.kind}:{r.match}\n")
        for v in r.variants:
            t.append(f"     {v.name}  {v.url or '💀 陷阱門'}\n")
    t.append("\n")
    h("統計")
    t.append(f"  開啟 {stats['opens']}　不重複 {stats['uniques']}　通關 {stats['passes']}　機器人 {stats['bots']}\n")
    if stats["uniques"]:
        t.append(f"  轉換率 {stats['pass_uniques'] * 100 // stats['uniques']}%（通關的不重複訪客 / 不重複訪客）\n")
    t.append(f"  近 20 分鐘 {spark(stats['spark'])}\n")
    if stats["by_continent"]:
        t.append("\n")
        h("地區（不重複訪客）")
        for line in bars(stats["by_continent"], top=7):
            t.append(f"  {line}\n")
        t.append("\n")
        for line in bars(stats["by_country"]):
            t.append(f"  {line}\n")
    if stats["by_variant"]:
        t.append("\n")
        h("各目標通關")
        for line in bars(stats["by_variant"]):
            t.append(f"  {line}\n")
    verdicts = load_verdicts(link.verdict)
    flagged = [(u, f) for u, v in verdicts.items() for f in v.findings if ORDER[f.level] >= ORDER["warn"]]
    t.append("\n")
    h("安全檢查")
    if not verdicts:
        t.append("  （沒有結果）\n")
    elif not flagged:
        names = sorted({n for v in verdicts.values() for n in v.checked if n != "local"})
        t.append("  ✅ 未發現威脅　已檢查：" + ("、".join(names) if names else "僅內建基礎檢查") + "\n")
    for u, f in flagged:
        t.append(f"  {'⛔' if f.level == 'block' else '⚠️'} {f.source}: {f.text}\n"
                 f"     {u}\n", style="red" if f.level == "block" else "yellow")
    scans = load_scans(link.scan)
    if scans:
        t.append("\n")
        h("目標掃描")
        for u, s in scans.items():
            if s.ok:
                t.append(f"  ✓ {s.status}　{s.title[:40] or '（無標題）'}　{s.elapsed_ms}ms"
                         + (f"　語系 {len(s.hreflang)} 種" if s.hreflang else "") + "\n")
            else:
                t.append(f"  ✗ {s.error or s.status}\n", style="yellow")
    if error:
        t.append(f"\n⚠️ {error}\n", style="red")
    return t


def parse_overrides(text: str) -> dict:
    """'theme=dark; accent=#e11d48' (or space separated) -> validated per-link overrides.
    Raises ValueError in plain Chinese for a bad name or value."""
    text = text.strip()
    if not text:
        return {}
    chunks = [c.strip() for c in (text.split(";") if ";" in text else text.split()) if c.strip()]
    raw: dict = {}
    for chunk in chunks:
        key, sep, val = chunk.partition("=")
        if not sep:
            raise ValueError(f"覆寫的格式是 名稱=值（錯在 {chunk!r}）")
        raw[key.strip()] = val.strip()
    return validate_overrides(raw)


def opt_display(opt: Opt, value, width: int = 28) -> str:
    """How a value looks in the settings list. Secrets are always masked."""
    from .config import mask
    if opt.secret:
        text = mask(value)
    elif opt.kind == "bool":
        text = "開" if value else "關"
    elif opt.kind == "list":
        text = ", ".join(map(str, value)) or "（空）"
    elif opt.kind == "map":
        text = ", ".join(f"{k}={v}" for k, v in value.items()) or "（空）"
    else:
        text = str(value).replace("\n", "\\n") if str(value) != "" else "（空）"
    return text if len(text) <= width else text[: width - 1] + "…"


def opt_text(opt: Opt, value) -> str:
    """The editable text for a value (what goes into the input box). Secrets start blank."""
    if opt.secret:
        return ""
    if opt.kind == "bool":
        return "開" if value else "關"
    if opt.kind == "list":
        return ", ".join(map(str, value))
    if opt.kind == "map":
        return ", ".join(f"{k}={v}" for k, v in value.items())
    return str(value).replace("\n", "\\n")


def opt_from_text(opt: Opt, text: str):
    """Inverse of opt_text (only the multi-line escape needs help; Opt.coerce does the rest)."""
    if opt.kind == "str":
        return text.replace("\\n", "\n")
    return text


def opt_help(opt: Opt) -> Text:
    t = Text()
    t.append(f"{opt.label}", style="bold")
    t.append(f"　[{LEVEL_LABELS[opt.level]}]{'　可每條連結單獨設定' if opt.per_link else ''}\n", style="dim")
    t.append(opt.help + "\n")
    bits = [f"預設：{opt_display(opt, opt.default, 40)}"]
    if opt.choices:
        bits.append("可選：" + " / ".join(map(str, opt.choices)))
    if opt.min is not None or opt.max is not None:
        bits.append(f"範圍：{opt.min:g}–{opt.max:g}")
    if opt.example:
        bits.append(f"例：{opt.example}")
    t.append("　".join(bits), style="dim")
    return t


def build_from_form(*, mode: str, targets: str, message: str = "", geo: str = "", auto_locale: bool = False,
                    ttl_min: str = "", max_opens: str = "", token: str = "", overrides: str = "",
                    label: str = "", password: str = "", max_passes: str = "", starts: str = "",
                    keep_hash: str = "", now: Optional[float] = None):
    """Turn the creation form's strings into (spec, ttl_seconds, max_opens). Raises ValueError in Chinese.
    `keep_hash`: when editing a locked link, a blank password keeps the old hash."""
    import time as _time

    from .models import LinkSpec, validate_spec
    from .secret import hash_password

    variants = parse_targets(targets)
    if not variants:
        raise ValueError("至少要一個目標網址")
    geo_rules, route_rules = parse_rules(geo)
    mp = max_passes.strip()
    if mp and not (mp.isdigit() and int(mp) >= 1):
        raise ValueError("通關上限要是大於 0 的整數（留空 = 不限）")
    if password and len(password) > 200:
        raise ValueError("密碼最長 200 字")
    spec = LinkSpec(mode=mode, variants=variants, geo_rules=geo_rules, route_rules=route_rules,
                    auto_locale=auto_locale, message=message.strip(), token=token.strip(),
                    options=parse_overrides(overrides), label=label.strip(),
                    pw_hash=hash_password(password) if password else keep_hash,
                    max_passes=int(mp) if mp else 0,
                    starts_at=parse_start(starts, _time.time() if now is None else now))
    validate_spec(spec)
    ttl_s: Optional[float] = None
    if ttl_min.strip():
        try:
            ttl_s = float(ttl_min) * 60
        except ValueError:
            raise ValueError("存活分鐘要是數字") from None
        if ttl_s <= 0:
            raise ValueError("存活分鐘要大於 0（留空 = 不限時）")
    cap: Optional[int] = None
    if max_opens.strip():
        if not max_opens.strip().isdigit() or int(max_opens) < 1:
            raise ValueError("人數上限要是正整數（留空 = 不限）")
        cap = int(max_opens)
    return spec, ttl_s, cap
