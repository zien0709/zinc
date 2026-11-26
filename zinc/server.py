"""Per-link origin server. One instance per tunnel; it only ever listens on 127.0.0.1.

Every request reads the *effective* settings for its link (global settings + the link's own
overrides), so a change in the settings screen applies to the next visitor without a restart.
"""
from __future__ import annotations

import asyncio
import random
import re
import secrets
import time
from collections import deque
from typing import Callable, Optional, Sequence

from aiohttp import web

from . import pages
from .geo import Resolver, client_ip, header_resolver, resolve_geo
from .i18n import pick_lang
from .lifecycle import effective_state
from .locale import finalize_url, parse_accept_language
from .options import Settings
from .resolver import detect_device, pick_random, pick_sticky, select_group, visitor_id
from .reputation import load_verdicts
from .scan import load_scans
from .secret import check_password
from .store import Link, Store
from .urlutil import append_params, quote_token

# Typed keys for the things other modules reach into (aiohttp warns about plain-string keys).
UNLOCKED: "web.AppKey[set]" = web.AppKey("unlocked", set)
ATTEMPTS: "web.AppKey[dict]" = web.AppKey("unlock_attempts", dict)

_TEXT_UA = re.compile(r"^(curl|wget|httpie)/", re.I)
Emit = Callable[[str, dict], None]


def make_app(store: Store, link_id: str, *, settings: Optional[Settings] = None,
             clock: Callable[[], float] = time.time,
             geo_chain: Sequence[Resolver] = (header_resolver,),
             rng: Optional[random.Random] = None, emit: Optional[Emit] = None) -> web.Application:
    base = settings if settings is not None else Settings()
    unlocked: set[str] = set()                    # visitors who entered the password (in memory: dies with the process)
    attempts: dict[str, deque] = {}               # visitor -> recent password attempt times
    link_attempts: deque = deque()                # all visitors together: caps distributed guessing

    def tell(event: str, link: Link, geo, **extra) -> None:
        if emit:
            emit(event, {"link_id": link.id, "label": link.spec.label, "mode": link.spec.mode,
                         "country": geo.country if geo else None, **extra})

    def decoy(o: Settings) -> web.Response:
        return web.Response(status=404, text=o.decoy_text)

    def secure(resp: web.Response, nonce: str = "", referrer: str = "no-referrer", connect: bool = False) -> web.Response:
        script = f"script-src 'nonce-{nonce}'" if nonce else "script-src 'none'"
        conn = "connect-src 'self'; " if connect else ""
        resp.headers["Content-Security-Policy"] = (
            f"default-src 'none'; style-src 'unsafe-inline'; {script}; {conn}img-src https: http: data:; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        resp.headers["Referrer-Policy"] = referrer
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    def html(body: str, nonce: str = "", status: int = 200, connect: bool = False, **headers) -> web.Response:
        resp = web.Response(text=body, status=status, content_type="text/html")
        resp.headers.update(headers)
        return secure(resp, nonce, connect=connect)

    def ctx(request: web.Request, link: Link, o: Settings):
        ua = request.headers.get("User-Agent", "")
        ip = client_ip(request.headers, request.remote or "")
        geo = resolve_geo(request.headers, ip, geo_chain)
        key_ip, key_ua = ("" if o.unique_by == "ua" else ip), ("" if o.unique_by == "ip" else ua)
        return ua, geo, visitor_id(link.salt, key_ip, key_ua)

    def lang_tags(request: web.Request) -> list[str]:
        return parse_accept_language(request.headers.get("Accept-Language", ""))

    def lang_of(request: web.Request) -> Optional[str]:
        tags = lang_tags(request)
        return tags[0][:12] if tags else None

    def page_lang(request: web.Request, o: Settings) -> str:
        return pick_lang(o.language, request.headers.get("Accept-Language", ""))

    def is_bot(o: Settings, ua: str) -> bool:
        return bool(re.search(o.bot_regex, ua[:300], re.I))

    def group_for(request: web.Request, link: Link, o: Settings, geo, ua: str):
        return select_group(link.spec, geo, lang_tags=lang_tags(request), device=detect_device(ua), order=o.rule_order)

    def passes_used_up(link: Link) -> bool:
        return bool(link.spec.max_passes) and store.count_hits(link.id, "pass") >= link.spec.max_passes

    def kill_softly(link: Link, now: float, o: Settings, geo, reason: str) -> None:
        """Lazy soft death: the first request to notice flips the state (and tells the host exactly once)."""
        if link.status in ("starting", "live", "paused"):
            store.set_status(link.id, "soft_dead", grace_until=now + o.grace_s)
            tell("dead", link, geo, reason=reason)

    def dead_response(link: Link, now: float, nonce: str, o: Settings, lang: str, geo=None) -> web.Response:
        expired = link.expires_at is not None and now >= link.expires_at
        # Real expiry or a used-up pass limit kills the link. A full link (max_opens) still lets admitted visitors finish.
        if expired:
            kill_softly(link, now, o, geo, "expired")
        elif passes_used_up(link):
            kill_softly(link, now, o, geo, "passes")
        if o.tombstone_status == "404":
            return decoy(o)                      # "pretend there was never anything here" (trap doors never come here)
        died = link.expires_at if expired else now
        return html(pages.page_dead(link_id=link.id, lived_s=max(0.0, min(now, died or now) - link.created_at),
                                    opens=store.count_opens(link.id), nonce=nonce, o=o, lang=lang),
                    nonce, status=410)

    def loaded(request: web.Request):
        link = store.get_link(link_id)
        if link is None or request.match_info.get("token") != link.token:
            return None, base
        return link, base.for_link(link.spec.options)

    async def root(request: web.Request) -> web.Response:
        return decoy(base)

    async def entry(request: web.Request) -> web.Response:
        link, o = loaded(request)
        if link is None:
            return decoy(o)
        now, nonce = clock(), secrets.token_urlsafe(12)
        ua, geo, vid = ctx(request, link, o)
        lang, spec = page_lang(request, o), link.spec
        if request.method == "HEAD" or is_bot(o, ua):
            if request.method != "HEAD" and o.count_bots:
                store.add_hit(link.id, "bot", vid, now=now)
            return decoy(o) if o.bot_response == "404" else html(pages.page_bot(lang))
        admitted = store.has_hit(link.id, vid, "open")
        state = effective_state(link, now, store.count_opens(link.id), admitted)
        if state == "dead" or passes_used_up(link):
            return dead_response(link, now, nonce, o, lang, geo)
        if state == "paused":
            return html(pages.page_paused(nonce, o, lang), nonce, status=503)
        if spec.starts_at and now < spec.starts_at:           # not counted: nobody has seen the link yet
            return html(pages.page_waiting(starts_at=spec.starts_at, nonce=nonce, o=o, lang=lang), nonce, status=503,
                        **{"Retry-After": str(max(1, int(spec.starts_at - now)))})
        if spec.pw_hash and vid not in unlocked:              # nothing about the target is revealed before this
            if o.curl_mode and _TEXT_UA.match(ua):
                return secure(web.Response(text=pages.text_curl("", None, locked=True), content_type="text/plain"))
            return html(pages.page_locked(token=link.token, nonce=nonce, o=o, lang=lang), nonce, connect=True)

        _, variants = group_for(request, link, o, geo, ua)
        sticky = pick_sticky(variants, vid, link.salt)
        store.add_hit(link.id, "open", vid, geo.country, geo.continent, lang_of(request), now=now)
        if not admitted:
            tell("open", link, geo)

        if o.curl_mode and (_TEXT_UA.match(ua) or request.query.get("raw") == "1"):
            target = sticky.url if spec.mode in ("plain", "note", "count") else "(a surprise)"
            left = None if link.expires_at is None else int(link.expires_at - now)
            return secure(web.Response(text=pages.text_curl(target, left), content_type="text/plain"))

        if spec.mode == "plain":
            return await _pass_through(request, link, o, vid, geo, now, ua)

        rank = store.visitor_rank(link.id, vid)
        expires_ms = None if link.expires_at is None else int(link.expires_at * 1000)
        card = ""
        if o.show_preview and spec.mode in ("note", "count"):
            card = pages.preview_card(load_scans(link.scan).get(sticky.url), sticky.url, spec.auto_locale,
                                      load_verdicts(link.verdict).get(sticky.url), lang)
        if spec.mode == "note":
            body = pages.page_note(token=link.token, message=spec.message, card=card, nonce=nonce,
                                   expires_ms=expires_ms, rank=rank, o=o, lang=lang)
        elif spec.mode == "count":
            body = pages.page_count(token=link.token, rank=rank, card=card, nonce=nonce,
                                    expires_ms=expires_ms, o=o, lang=lang)
        elif spec.mode == "box":
            body = pages.page_box(token=link.token, nonce=nonce, expires_ms=expires_ms, o=o, lang=lang)
        else:  # door
            body = pages.page_door(token=link.token, count=len(variants), nonce=nonce,
                                   expires_ms=expires_ms, o=o, lang=lang)
        return html(body, nonce)

    async def _pass_through(request, link: Link, o: Settings, vid: str, geo, now: float, ua: str, *,
                            door: Optional[int] = None) -> web.Response:
        _, variants = group_for(request, link, o, geo, ua)
        if door is not None:
            variant = variants[door]
        elif link.spec.mode == "box":
            variant = pick_random(variants, rng)
        else:
            variant = pick_sticky(variants, vid, link.salt)
        final, _why = finalize_url(variant.url, auto_locale=link.spec.auto_locale,
                                   accept_language=request.headers.get("Accept-Language", ""),
                                   country=geo.country, scans=load_scans(link.scan))
        final = append_params(final, o.utm)
        store.add_hit(link.id, "pass", vid, geo.country, geo.continent, lang_of(request),
                      variant.name, now=now)
        tell("pass", link, geo, variant=variant.name)
        if passes_used_up(link):                      # that was the last allowed pass: the link dies for everyone else
            kill_softly(link, now, o, geo, "passes")
        return secure(web.Response(status=int(o.redirect_status), headers={"Location": final}),
                      referrer=o.referrer_policy)

    async def go(request: web.Request) -> web.Response:
        link, o = loaded(request)
        if link is None:
            return decoy(o)
        now, nonce = clock(), secrets.token_urlsafe(12)
        ua, geo, vid = ctx(request, link, o)
        lang = page_lang(request, o)
        if is_bot(o, ua) or request.method == "HEAD":
            return decoy(o) if o.bot_response == "404" else html(pages.page_bot(lang))
        if not store.has_hit(link.id, vid, "open"):       # skipping the gate must not count as a pass
            return secure(web.Response(status=302, headers={"Location": f"/{quote_token(link.token)}"}))
        if effective_state(link, now, store.count_opens(link.id), admitted=True) != "live" or passes_used_up(link):
            return dead_response(link, now, nonce, o, lang, geo)
        door = None
        if link.spec.mode == "door":
            _, variants = group_for(request, link, o, geo, ua)
            raw = request.query.get("d", "")
            if not raw.isdigit() or int(raw) >= len(variants):
                return secure(web.Response(status=400, text="bad door\n"))
            door = int(raw)
            if variants[door].url == "":      # trap door: a tombstone, the link itself stays alive
                return html(pages.page_dead(link_id=link.id, lived_s=now - link.created_at,
                                            opens=store.count_opens(link.id), nonce=nonce, o=o, trap=True, lang=lang),
                            nonce)
        return await _pass_through(request, link, o, vid, geo, now, ua, door=door)

    async def unlock(request: web.Request) -> web.Response:
        link, o = loaded(request)
        if link is None or not link.spec.pw_hash:
            return decoy(o)
        now = clock()
        ua, geo, vid = ctx(request, link, o)
        if is_bot(o, ua):
            return decoy(o)
        if effective_state(link, now, store.count_opens(link.id), admitted=True) == "dead":
            return secure(web.json_response({"ok": False}, status=410))
        mine = attempts.get(vid) or deque()           # not stored yet: refused requests must not grow the table
        for q in (mine, link_attempts):
            while q and now - q[0] >= 60:
                q.popleft()
        if len(mine) >= o.unlock_tries or len(link_attempts) >= max(30, o.unlock_tries * 10):
            return secure(web.json_response({"ok": False}, status=429))
        try:
            data = await request.json()
            pw = data.get("p") if isinstance(data, dict) else None
        except ValueError:
            pw = None
        if not isinstance(pw, str) or len(pw) > 200:
            return secure(web.json_response({"ok": False}, status=400))
        mine.append(now)
        link_attempts.append(now)
        attempts[vid] = mine
        if len(attempts) > 1000:                       # only guessers that were let through get here, so this stays small
            for k in [k for k, q in attempts.items() if not q or now - q[-1] >= 60]:
                del attempts[k]
        ok = await asyncio.get_running_loop().run_in_executor(None, check_password, pw, link.spec.pw_hash)
        if not ok:
            return secure(web.json_response({"ok": False}, status=401))
        unlocked.add(vid)
        mine.clear()
        return secure(web.json_response({"ok": True}))

    app = web.Application()
    app[UNLOCKED] = unlocked
    app[ATTEMPTS] = attempts                          # exposed for tests: it must never grow with refused requests
    app.router.add_get("/", root)
    app.router.add_get("/{token}", entry)
    app.router.add_get("/{token}/go", go)
    app.router.add_post("/{token}/unlock", unlock)
    app.router.add_route("*", "/{tail:.*}", root)     # every other path and method: the 404 decoy
    return app
