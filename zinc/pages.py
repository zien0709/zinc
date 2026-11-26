"""Visitor-facing HTML. Every dynamic value is escaped: scanned titles are untrusted input.

Pages work without JavaScript (every action is a plain link); JS only adds the show.
Look and timing come from the effective settings `o` (global settings + this link's overrides).
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from html import escape
from typing import Optional
from urllib.parse import urlsplit

from .i18n import epitaphs, tr
from .options import Settings
from .reputation import ORDER, Verdict
from .scan import ScanResult
from .urlutil import quote_token

_LIGHT = "--bg:#f6f5f1;--fg:#16181d;--mut:#6b7280;--card:#fff;--line:#e4e2da;--acc:#0f766e"
_DARK = "--bg:#0e1116;--fg:#e8eaed;--mut:#8b93a1;--card:#161b22;--line:#262d38;--acc:#2dd4bf"
CSS = ":root{" + _LIGHT + "}@media(prefers-color-scheme:dark){:root{" + _DARK + "}}" \
      ":root[data-theme=dark]{" + _DARK + "}:root[data-theme=light]{" + _LIGHT + """}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100dvh;display:flex;flex-direction:column;background:var(--bg);color:var(--fg);
font:16px/1.5 system-ui,-apple-system,"Segoe UI","Noto Sans TC",sans-serif}
header,footer{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;color:var(--mut);font-size:13px}
.brand{font-weight:700;letter-spacing:.04em;color:var(--fg)}.brand i{color:var(--acc);font-style:normal}
main{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:28px;padding:16px 20px;width:100%;max-width:560px;margin:0 auto}
.stage{min-height:140px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;gap:10px;width:100%}
.typed{font-size:clamp(24px,7vw,36px);font-weight:600;line-height:1.35;word-break:break-word}
.typed::after{content:"▍";color:var(--acc);animation:blink 1s steps(2) infinite}
.big{font-size:clamp(44px,16vw,84px);font-weight:800;font-variant-numeric:tabular-nums;color:var(--acc)}
.sub{color:var(--mut)}
.gift{font-size:96px;text-decoration:none;display:inline-block;animation:bob 2.4s ease-in-out infinite}
.gift.shake{animation:shake .5s}
.doors{display:flex;gap:14px;flex-wrap:wrap;justify-content:center}
.door{width:84px;height:132px;border-radius:42px 42px 6px 6px;background:var(--card);border:2px solid var(--line);
display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:700;text-decoration:none;color:var(--fg);transition:transform .15s}
.door:hover,.door:focus-visible{transform:translateY(-6px);border-color:var(--acc)}
.card{width:100%;display:flex;gap:12px;align-items:center;padding:12px 14px;background:var(--card);border:1px solid var(--line);border-radius:14px}
.card img{width:32px;height:32px;border-radius:8px;flex:none;background:var(--line)}
.card .t{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card .m{font-size:12px;color:var(--mut)}.card div{min-width:0}
.go{display:inline-block;padding:12px 28px;border-radius:999px;background:var(--acc);color:var(--bg);font-weight:700;text-decoration:none}
a:focus-visible{outline:3px solid var(--acc);outline-offset:3px}
.dead{background:#0b0b0d;color:#d8d8dc}.dead .big{color:#8a8a93;font-size:72px}
form{display:flex;gap:10px;width:100%;justify-content:center;flex-wrap:wrap}
input{flex:1;min-width:140px;max-width:260px;padding:12px 16px;border-radius:999px;border:1px solid var(--line);background:var(--card);color:var(--fg);font:inherit}
input:focus-visible{outline:3px solid var(--acc);outline-offset:2px}button.go{border:0;cursor:pointer;font:inherit;font-weight:700}
@keyframes blink{50%{opacity:0}}@keyframes bob{50%{transform:translateY(-10px)}}
@keyframes shake{20%{transform:rotate(-14deg)}40%{transform:rotate(12deg)}60%{transform:rotate(-8deg)}80%{transform:rotate(6deg)}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""

JS = """
(()=>{const $=s=>document.querySelector(s),b=document.body,go=$('a.go'),rm=matchMedia('(prefers-reduced-motion: reduce)').matches;
const num=(k,d)=>{const v=parseInt(b.dataset[k],10);return isNaN(v)?d:v};
const e=+b.dataset.expires,el=$('#ttl');
if(e&&el){const f=()=>{const s=Math.max(0,Math.round((e-Date.now())/1000));
el.textContent='⏳ '+Math.floor(s/60)+':'+String(s%60).padStart(2,'0');if(!s)location.reload()};f();setInterval(f,1000)}
const m=b.dataset.mode;
if(m==='note'){const t=$('#typed'),c=Array.from(t.dataset.text),sp=num('speed',70),dl=num('delay',1600);let i=0;
if(rm){t.textContent=c.join('');setTimeout(()=>location.href=go.href,dl)}
else{const k=()=>{t.textContent=c.slice(0,++i).join('');i<c.length?setTimeout(k,sp):setTimeout(()=>location.href=go.href,dl)};k()}}
if(m==='count'){let n=num('count',3);const d=$('#cd');const k=()=>{d.textContent=n;if(!n--)return location.href=go.href;setTimeout(k,1000)};k()}
document.querySelectorAll('time[datetime]').forEach(t=>{const d=new Date(t.getAttribute('datetime'));if(!isNaN(d))t.textContent=d.toLocaleString()});
if(m==='wait'){const d=+b.dataset.starts-Date.now();setTimeout(()=>location.reload(),Math.max(1000,Math.min(d,2147483000)))}
if(m==='lock'){const f=$('#lf'),p=$('#pw'),msg=$('#lm');f.addEventListener('submit',async ev=>{ev.preventDefault();msg.textContent='';
try{const r=await fetch(b.dataset.unlock,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({p:p.value}),credentials:'omit'});
if(r.ok)return location.reload();msg.textContent=r.status===429?b.dataset.wait:b.dataset.wrong;p.select()}catch(_){msg.textContent=b.dataset.net}})}
if(m==='box'){const g=$('a.gift');g.addEventListener('click',ev=>{ev.preventDefault();g.classList.add('shake');setTimeout(()=>location.href=g.href,650)})}
})();
"""


def _shell(*, title: str, body: str, nonce: str, expires_ms: Optional[int], mode: str, o: Settings,
           cls: str = "", footer: str = "", lang: str = "zh-Hant", data: str = "") -> str:
    theme = f' data-theme="{o.theme}"' if o.theme != "auto" else ""
    style = f' style="--acc:{escape(o.accent, quote=True)}"' if o.accent else ""   # registry guarantees #hex
    counting = bool(expires_ms and o.show_countdown)
    exp = f' data-expires="{expires_ms}"' if counting else ""
    brand = f'<span class="brand">{escape(o.brand)}<i>.</i></span>' if o.brand else "<span></span>"
    ttl = '<span id="ttl"></span>' if counting else "<span></span>"
    sign = escape(o.brand) if o.brand else ""
    return (
        f'<!doctype html><html lang="{escape(lang)}"{theme}><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer">'
        f"<title>{escape(title)}</title><style>{CSS}</style></head>"
        f'<body class="{cls}" data-mode="{escape(mode)}" data-speed="{o.type_speed_ms}" '
        f'data-delay="{o.redirect_delay_ms}" data-count="{o.count_seconds}"{exp}{data}{style}>'
        f"<header>{brand}{ttl}</header>"
        f"<main>{body}</main><footer><span>{footer}</span><span>{sign}</span></footer>"
        f'<script nonce="{nonce}">{JS}</script></body></html>'
    )


_NAMES = {"virustotal": "VirusTotal", "safebrowsing": "Google Safe Browsing", "urlhaus": "URLhaus"}


def safety_line(verdict: Optional[Verdict], lang: str = "zh-Hant") -> str:
    """One honest line: warnings always show; 'nothing found' only when a third party really answered.
    Finding texts are written for the host (Chinese), so other languages get the generic sentence instead."""
    if verdict is None:
        return ""
    worst_f = [f for f in verdict.findings if f.level in ("block", "warn")]
    if worst_f:
        top = max(worst_f, key=lambda f: ORDER[f.level])
        text = tr(lang, "risky" if top.level == "block" else "caution", text=top.text)
        return f'<div class="m">{escape(text)}</div>'
    outside = [_NAMES.get(n, n) for n in verdict.checked if n != "local"]
    if outside:
        return f'<div class="m">{escape(tr(lang, "clean", names=("、" if lang == "zh-Hant" else ", ").join(outside)))}</div>'
    return ""


def preview_card(scan: Optional[ScanResult], fallback_url: str, auto_locale: bool,
                 verdict: Optional[Verdict] = None, lang: str = "zh-Hant") -> str:
    host = urlsplit(fallback_url).hostname or ""
    if scan and scan.ok:
        title = scan.title or host
        icon = (f'<img src="{escape(scan.favicon, quote=True)}" alt="" referrerpolicy="no-referrer">'
                if scan.favicon else '<img alt="">')
        lock = tr(lang, "https_ok" if scan.https else "https_no")
        hops = tr(lang, "hops", n=len(scan.chain) - 1) if len(scan.chain) > 1 else ""
        meta = f"{escape(urlsplit(scan.final_url or fallback_url).hostname or host)} · {lock}{hops} · {scan.elapsed_ms}ms"
    else:
        title = host
        icon = '<img alt="">'
        meta = escape(tr(lang, "unscanned" if not scan else "scan_failed", host=host))
    loc = f'<div class="m">{tr(lang, "locale_note")}</div>' if auto_locale else ""
    return (f'<div class="card">{icon}<div><div class="t">{escape(title)}</div>'
            f'<div class="m">{meta}</div>{safety_line(verdict, lang)}{loc}</div></div>')


def _go(token: str) -> str:
    return f"/{escape(quote_token(token))}/go"


def page_note(*, token: str, message: str, card: str, nonce: str, expires_ms, rank: int, o: Settings,
              lang: str = "zh-Hant") -> str:
    body = (f'<div class="stage"><div id="typed" class="typed" data-text="{escape(message, quote=True)}"></div></div>'
            f'{card}<a class="go" href="{_go(token)}">{tr(lang, "go")}</a>')
    return _shell(title=tr(lang, "note_title"), body=body, nonce=nonce, expires_ms=expires_ms, mode="note", o=o,
                  footer=tr(lang, "reader_n", n=rank) if o.show_rank else "", lang=lang)


def page_count(*, token: str, rank: int, card: str, nonce: str, expires_ms, o: Settings, lang: str = "zh-Hant") -> str:
    cd = f'<span id="cd">{o.count_seconds}</span>'
    body = (f'<div class="stage"><div class="sub">{tr(lang, "count_pre")}</div><div class="big">{rank}</div>'
            f'<div class="sub">{tr(lang, "count_post", cd=cd)}</div></div>'
            f'{card}<a class="go" href="{_go(token)}">{tr(lang, "count_go")}</a>')
    return _shell(title=tr(lang, "count_title", n=rank), body=body, nonce=nonce, expires_ms=expires_ms, mode="count",
                  o=o, footer=tr(lang, "count_footer"), lang=lang)


def page_box(*, token: str, nonce: str, expires_ms, o: Settings, lang: str = "zh-Hant") -> str:
    body = (f'<div class="stage"><a class="gift" href="{_go(token)}" aria-label="{escape(tr(lang, "box_open"))}">🎁</a>'
            f'<div class="sub">{tr(lang, "box_hint")}</div></div>')
    return _shell(title=tr(lang, "box_title"), body=body, nonce=nonce, expires_ms=expires_ms, mode="box", o=o,
                  footer=tr(lang, "box_footer"), lang=lang)


def page_door(*, token: str, count: int, nonce: str, expires_ms, o: Settings, lang: str = "zh-Hant") -> str:
    doors = "".join(f'<a class="door" href="{_go(token)}?d={i}" aria-label="{escape(tr(lang, "door_n", n=i + 1))}">{i + 1}</a>'
                    for i in range(count))
    body = f'<div class="stage"><div class="sub">{tr(lang, "door_pick")}</div><div class="doors">{doors}</div></div>'
    return _shell(title=tr(lang, "door_title"), body=body, nonce=nonce, expires_ms=expires_ms, mode="door", o=o,
                  footer=tr(lang, "door_footer"), lang=lang)


def page_dead(*, link_id: str, lived_s: float, opens: int, nonce: str, o: Settings, trap: bool = False,
              lang: str = "zh-Hant") -> str:
    epi = epitaphs(lang)
    pick = int(hashlib.sha256(link_id.encode()).hexdigest(), 16) % len(epi)
    mins = int(lived_s // 60)
    life = tr(lang, "life_min", m=mins) if mins else tr(lang, "life_sec", s=int(lived_s))
    head = tr(lang, "trap_head" if trap else "dead_head")
    epitaph = o.tombstone_text or epi[pick]
    body = (f'<div class="stage"><div class="big">🪦</div><div class="typed" style="font-size:24px">{escape(head)}</div>'
            f'<div class="sub">{escape(epitaph)}</div>'
            f'<div class="sub">{escape(tr(lang, "dead_life", life=life, n=opens))}</div></div>')
    return _shell(title=tr(lang, "dead_title"), body=body, nonce=nonce, expires_ms=None, mode="dead", cls="dead", o=o,
                  footer="410 Gone", lang=lang)


def page_paused(nonce: str, o: Settings, lang: str = "zh-Hant") -> str:
    return _shell(title=tr(lang, "paused_title"),
                  body=f'<div class="stage"><div class="big">⏸</div><div class="sub">{tr(lang, "paused_text")}</div></div>',
                  nonce=nonce, expires_ms=None, mode="paused", o=o, lang=lang)


def page_locked(*, token: str, nonce: str, o: Settings, lang: str = "zh-Hant") -> str:
    """The password gate. Shows nothing about the target. Needs JavaScript (the CSP forbids plain form posts)."""
    data = (f' data-unlock="/{escape(quote_token(token))}/unlock" data-wrong="{escape(tr(lang, "lock_wrong"), quote=True)}"'
            f' data-wait="{escape(tr(lang, "lock_wait"), quote=True)}" data-net="{escape(tr(lang, "lock_net"), quote=True)}"')
    body = (f'<div class="stage"><div class="big">🔒</div><div class="sub">{tr(lang, "lock_text")}</div>'
            f'<form id="lf" autocomplete="off"><input id="pw" type="password" maxlength="200" required autofocus '
            f'placeholder="{escape(tr(lang, "lock_placeholder"), quote=True)}" aria-label="{escape(tr(lang, "lock_placeholder"), quote=True)}">'
            f'<button class="go" type="submit">{tr(lang, "lock_button")}</button></form>'
            f'<div id="lm" class="sub" role="alert"></div><noscript><div class="sub">{tr(lang, "lock_nojs")}</div></noscript></div>')
    return _shell(title=tr(lang, "lock_title"), body=body, nonce=nonce, expires_ms=None, mode="lock", o=o,
                  footer=tr(lang, "lock_footer"), lang=lang, data=data)


def page_waiting(*, starts_at: float, nonce: str, o: Settings, lang: str = "zh-Hant") -> str:
    when = datetime.fromtimestamp(starts_at, tz=timezone.utc)
    stamp = f'<time datetime="{when.isoformat()}">{when:%Y-%m-%d %H:%M} UTC</time>'
    body = (f'<div class="stage"><div class="big">⏳</div><div class="sub">{tr(lang, "wait_text")}</div>'
            f'<div class="sub">{tr(lang, "wait_at", when=stamp)}</div></div>')
    return _shell(title=tr(lang, "wait_title"), body=body, nonce=nonce, expires_ms=None, mode="wait", o=o,
                  footer=tr(lang, "wait_footer"), lang=lang, data=f' data-starts="{int(starts_at * 1000)}"')


def page_bot(lang: str = "zh-Hant") -> str:
    """Link-preview crawlers get a generic card: it must not leak the target or count as a visit."""
    return (f'<!doctype html><html lang="{escape(lang)}"><head><meta charset="utf-8">'
            f'<meta property="og:title" content="{escape(tr(lang, "bot_title"), quote=True)}">'
            f'<meta property="og:description" content="{escape(tr(lang, "bot_desc"), quote=True)}">'
            '<meta property="og:site_name" content="zinc"><title>zinc</title></head>'
            '<body>zinc</body></html>')


def text_curl(target_url: str, expires_in: Optional[int], locked: bool = False) -> str:
    if locked:
        return "\n  zinc.  (curl detected)\n\n  this link is locked: open it in a browser and enter the password.\n\n"
    ttl = "" if expires_in is None else f"expires in : {expires_in // 60}m{expires_in % 60:02d}s\n"
    return ("\n  zinc.  (curl detected, no animation for you)\n\n"
            f"  target     : {target_url}\n  {ttl}\n  follow it : curl -L <this-url>/go\n\n")
