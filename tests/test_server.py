import asyncio
import random
from contextlib import asynccontextmanager

from aiohttp.test_utils import TestClient, TestServer

from zinc.models import GeoRule, LinkSpec, Variant
from zinc.scan import ScanResult, dump_scans
from zinc.server import make_app
from zinc.store import Store

A, B = "https://a.example/", "https://b.example/"
NOW = 1_000_000.0


def V(name, url, w=1):
    return Variant(name, url, w)


def setup(spec=None, *, ttl=600, max_opens=None, rng=None, now=NOW, clock=None):
    spec = spec or LinkSpec(mode="plain", variants=[V("A", A)])
    store = Store()
    link = store.create_link(spec, ttl_s=ttl, max_opens=max_opens, now=now)
    store.set_status(link.id, "live")
    app = make_app(store, link.id, clock=clock or (lambda: now), rng=rng)
    return store, link, app


@asynccontextmanager
async def client(app):
    async with TestClient(TestServer(app)) as c:
        yield c


def hdr(ip="1.1.1.1", country=None, ua="Mozilla/5.0 Test", lang=None):
    h = {"CF-Connecting-IP": ip, "User-Agent": ua}
    if country:
        h["CF-IPCountry"] = country
    if lang:
        h["Accept-Language"] = lang
    return h


def run(coro):
    return asyncio.run(coro)


def test_decoy_root_and_wrong_token_do_not_count():
    store, link, app = setup()

    async def go():
        async with client(app) as c:
            for path in ("/", "/nope", f"/{link.token}x", "/a/b/c"):
                r = await c.get(path, headers=hdr(), allow_redirects=False)
                assert r.status == 404 and "page not found" in await r.text()
    run(go())
    assert store.stats(link.id)["opens"] == 0


def test_plain_redirects_and_counts_open_and_pass():
    store, link, app = setup()

    async def go():
        async with client(app) as c:
            r = await c.get(f"/{link.token}", headers=hdr(), allow_redirects=False)
            assert r.status == 302 and r.headers["Location"] == A
            assert r.headers["Cache-Control"] == "no-store"
    run(go())
    s = store.stats(link.id)
    assert (s["opens"], s["passes"], s["uniques"]) == (1, 1, 1)


def test_geo_rules_country_beats_continent_beats_default():
    spec = LinkSpec(mode="plain", variants=[V("D", "https://d.example/")], geo_rules=[
        GeoRule("asia", [V("AS", "https://as.example/")]), GeoRule("TW", [V("TW", "https://tw.example/")])])
    store, link, app = setup(spec)

    async def loc(c, ip, country):
        r = await c.get(f"/{link.token}", headers=hdr(ip, country), allow_redirects=False)
        return r.headers["Location"]

    async def go():
        async with client(app) as c:
            assert await loc(c, "1.0.0.1", "TW") == "https://tw.example/"
            assert await loc(c, "1.0.0.2", "JP") == "https://as.example/"
            assert await loc(c, "1.0.0.3", "DE") == "https://d.example/"
            assert await loc(c, "1.0.0.4", "XX") == "https://d.example/"
            assert await loc(c, "1.0.0.5", None) == "https://d.example/"
    run(go())
    st = store.stats(link.id)
    assert st["by_country"] == {"TW": 1, "JP": 1, "DE": 1, "??": 2}
    assert st["by_continent"]["asia"] == 2 and st["by_continent"]["europe"] == 1


def test_bots_get_generic_card_not_counted_as_visit_and_never_leak_target():
    store, link, app = setup(LinkSpec(mode="plain", variants=[V("A", "https://secret-target.example/")]))

    async def go():
        async with client(app) as c:
            for ua in ("Slackbot-LinkExpanding 1.0", "facebookexternalhit/1.1;line-poker/1.0", "Discordbot/2.0"):
                r = await c.get(f"/{link.token}", headers=hdr(ua=ua), allow_redirects=False)
                text = await r.text()
                assert r.status == 200 and "og:title" in text and "secret-target" not in text
    run(go())
    s = store.stats(link.id)
    assert s["opens"] == 0 and s["passes"] == 0 and s["bots"] == 3


def test_expired_link_shows_tombstone_410_and_goes_soft_dead():
    store, link, app = setup(ttl=60, clock=lambda: NOW + 61)

    async def go():
        async with client(app) as c:
            r = await c.get(f"/{link.token}", headers=hdr(), allow_redirects=False)
            assert r.status == 410 and "已死亡" in await r.text()
    run(go())
    got = store.get_link(link.id)
    assert got.status == "soft_dead" and got.grace_until == NOW + 61 + 120
    assert store.stats(link.id)["opens"] == 0


def test_max_opens_blocks_newcomers_but_not_admitted_visitor_finishing():
    spec = LinkSpec(mode="note", message="hi", variants=[V("A", A)])
    store, link, app = setup(spec, max_opens=1)

    async def go():
        async with client(app) as c:
            r1 = await c.get(f"/{link.token}", headers=hdr("9.9.9.1"), allow_redirects=False)
            assert r1.status == 200
            r2 = await c.get(f"/{link.token}", headers=hdr("9.9.9.2"), allow_redirects=False)
            assert r2.status == 410
            r3 = await c.get(f"/{link.token}/go", headers=hdr("9.9.9.1"), allow_redirects=False)
            assert r3.status == 302 and r3.headers["Location"] == A
            r4 = await c.get(f"/{link.token}", headers=hdr("9.9.9.1"), allow_redirects=False)
            assert r4.status == 200  # a returning visitor is not locked out by their own visit
    run(go())


def test_go_without_open_does_not_count_a_pass():
    spec = LinkSpec(mode="note", message="hi", variants=[V("A", A)])
    store, link, app = setup(spec)

    async def go():
        async with client(app) as c:
            r = await c.get(f"/{link.token}/go", headers=hdr(), allow_redirects=False)
            assert r.status == 302 and r.headers["Location"] == f"/{link.token}"
    run(go())
    assert store.stats(link.id)["passes"] == 0


def test_ab_is_sticky_per_visitor_and_respects_weights():
    spec = LinkSpec(mode="plain", variants=[V("A", A, 9), V("B", B, 1)])
    store, link, app = setup(spec)
    seen_by_visitor, count_a = {}, 0

    async def go():
        nonlocal count_a
        async with client(app) as c:
            for i in range(300):
                ip = f"2.0.{i // 250}.{i % 250 + 1}"
                loc = None
                for _ in range(3):
                    r = await c.get(f"/{link.token}", headers=hdr(ip), allow_redirects=False)
                    assert loc in (None, r.headers["Location"]), "same visitor flipped variant"
                    loc = r.headers["Location"]
                seen_by_visitor[ip] = loc
                count_a += loc == A
    run(go())
    assert 230 <= count_a <= 290 and count_a < 300  # ~90% A, but B does occur


def test_box_draws_fresh_each_time_from_the_group_only():
    spec = LinkSpec(mode="box", variants=[V("A", A), V("B", B)])
    store, link, app = setup(spec, rng=random.Random(7))
    locs = []

    async def go():
        async with client(app) as c:
            await c.get(f"/{link.token}", headers=hdr(), allow_redirects=False)
            for _ in range(40):
                r = await c.get(f"/{link.token}/go", headers=hdr(), allow_redirects=False)
                locs.append(r.headers["Location"])
    run(go())
    assert set(locs) == {A, B}


def test_door_picks_by_index_rejects_bad_index_and_trap_is_tombstone_without_pass():
    spec = LinkSpec(mode="door", variants=[V("d1", A), V("d2", B), V("trap", "")])
    store, link, app = setup(spec)

    async def go():
        async with client(app) as c:
            page = await c.get(f"/{link.token}", headers=hdr(), allow_redirects=False)
            assert (await page.text()).count('class="door"') == 3
            r = await c.get(f"/{link.token}/go?d=1", headers=hdr(), allow_redirects=False)
            assert r.headers["Location"] == B
            for bad in ("", "x", "3", "-1"):
                r = await c.get(f"/{link.token}/go?d={bad}", headers=hdr(), allow_redirects=False)
                assert r.status == 400
            r = await c.get(f"/{link.token}/go?d=2", headers=hdr(), allow_redirects=False)
            assert r.status == 200 and "Location" not in r.headers and "陷阱" in await r.text()
    run(go())
    assert store.stats(link.id)["passes"] == 1


def test_auto_locale_uses_scanned_hreflang_and_off_leaves_url_alone():
    scans = {A: ScanResult(url=A, ok=True, hreflang={"zh-hant-tw": "https://a.example/tw/"})}
    for on, expect in ((True, "https://a.example/tw/"), (False, A)):
        spec = LinkSpec(mode="plain", variants=[V("A", A)], auto_locale=on)
        store, link, app = setup(spec)
        store.set_scan(link.id, dump_scans(scans))

        async def go():
            async with client(app) as c:
                r = await c.get(f"/{link.token}", headers=hdr(country="TW", lang="zh-TW,zh;q=0.9"),
                                allow_redirects=False)
                assert r.headers["Location"] == expect
        run(go())


def test_pages_escape_untrusted_text_and_csp_nonce_matches():
    evil = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    spec = LinkSpec(mode="note", message=evil, variants=[V("A", A)])
    store, link, app = setup(spec)
    store.set_scan(link.id, dump_scans({A: ScanResult(url=A, ok=True, title=evil, final_url=A,
                                                      chain=[A], favicon='https://x/"onerror="y')}))

    async def go():
        async with client(app) as c:
            r = await c.get(f"/{link.token}", headers=hdr(), allow_redirects=False)
            text = await r.text()
            assert "<script>alert" not in text and "<img src=x" not in text
            assert 'onerror="y' not in text
            nonce = r.headers["Content-Security-Policy"].split("'nonce-")[1].split("'")[0]
            assert f'<script nonce="{nonce}">' in text
            assert text.count("<script") == 1
    run(go())


def test_curl_gets_plain_text_and_mystery_modes_do_not_spoil():
    for mode, spoils in (("note", True), ("box", False)):
        spec = LinkSpec(mode=mode, message="m", variants=[V("A", A), V("B", B)])
        store, link, app = setup(spec)

        async def go():
            async with client(app) as c:
                r = await c.get(f"/{link.token}", headers=hdr(ua="curl/8.5.0"), allow_redirects=False)
                text = await r.text()
                assert r.content_type == "text/plain"
                assert (("a.example" in text) or ("b.example" in text)) == spoils
        run(go())
    assert store.stats(link.id)["opens"] == 1


def test_paused_link_serves_503_and_does_not_count():
    store, link, app = setup()
    store.set_status(link.id, "paused")

    async def go():
        async with client(app) as c:
            r = await c.get(f"/{link.token}", headers=hdr(), allow_redirects=False)
            assert r.status == 503
    run(go())
    assert store.stats(link.id)["opens"] == 0
