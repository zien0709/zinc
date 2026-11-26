"""One behaviour test per setting that the server, scanner, safety checks or tunnel consume:
change the value -> the observable behaviour changes (and the default behaviour is the control)."""
import asyncio
import os
import stat
import sys
from pathlib import Path

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

import zinc.manager as manager_mod
from tests.test_reputation import Counting, Fake, vt_stats, with_fake
from tests.test_server import A, B, NOW, V, client, hdr, run
from tests.test_tunnel_manager import FAKE, fake_cmd, noscan, plain_spec
from zinc.config import Settings
from zinc.manager import Manager
from zinc.models import LinkSpec
from zinc.reputation import L0_IDS, Finding, Reputation, VirusTotal, local_checks
from zinc.scan import ScanResult, scan_url
from zinc.server import make_app
from zinc.store import Store
from zinc.tunnel import Tunnel, default_cmd, find_cloudflared, preflight


def serve(spec=None, settings=None, *, ttl=600, max_opens=None, now=NOW, clock=None):
    spec = spec or LinkSpec(mode="plain", variants=[V("A", A)])
    store = Store()
    link = store.create_link(spec, ttl_s=ttl, max_opens=max_opens, now=now)
    store.set_status(link.id, "live")
    return store, link, make_app(store, link.id, settings=settings, clock=clock or (lambda: now))


async def get(app, path, headers=None, **kw):
    async with client(app) as c:
        r = await c.get(path, headers=headers or hdr(), allow_redirects=False, **kw)
        return r.status, dict(r.headers), await r.text()


def gets(app, *requests):
    """Several requests against ONE app in one event loop (an aiohttp app is bound to its loop)."""
    async def go():
        out = []
        async with client(app) as c:
            for path, headers in requests:
                r = await c.get(path, headers=headers or hdr(), allow_redirects=False)
                out.append((r.status, dict(r.headers), await r.text()))
        return out
    return run(go())


def note(**kw):
    return LinkSpec(mode="note", message="hi", variants=[V("A", A)], **kw)


# ---- visitor page ---------------------------------------------------------------------------------
def test_animation_timings_reach_the_page_and_a_link_can_override_them():
    s = Settings(type_speed_ms=40, redirect_delay_ms=2500, count_seconds=5)
    store, link, app = serve(note(), s)
    _, _, body = run(get(app, f"/{link.token}"))
    assert 'data-speed="40"' in body and 'data-delay="2500"' in body and 'data-count="5"' in body
    store, link, app = serve(note(options={"type_speed_ms": 200, "redirect_delay_ms": 0, "count_seconds": 0}), s)
    _, _, body = run(get(app, f"/{link.token}"))
    assert 'data-speed="200"' in body and 'data-delay="0"' in body and 'data-count="0"' in body


def test_countdown_clock_only_when_enabled_and_the_link_has_an_expiry():
    for flag, ttl, expect in ((True, 600, True), (False, 600, False), (True, None, False)):
        store, link, app = serve(note(), Settings(show_countdown=flag), ttl=ttl)
        _, _, body = run(get(app, f"/{link.token}"))
        assert ("data-expires=" in body) is expect, (flag, ttl)


def test_custom_tombstone_text_replaces_the_epitaph_and_is_escaped():
    store, link, app = serve(settings=Settings(tombstone_text="活動已結束 <b>bye</b>"), ttl=60, clock=lambda: NOW + 61)
    status, _, body = run(get(app, f"/{link.token}"))
    assert status == 410 and "活動已結束" in body and "<b>bye</b>" not in body and "&lt;b&gt;bye" in body
    store, link, app = serve(settings=Settings(), ttl=60, clock=lambda: NOW + 61)
    assert "活動已結束" not in run(get(app, f"/{link.token}"))[2]


def test_tombstone_status_404_pretends_nothing_was_ever_here_but_traps_still_show_a_tombstone():
    store, link, app = serve(settings=Settings(tombstone_status="404", decoy_text="nothing\n"), ttl=60,
                             clock=lambda: NOW + 61)
    status, _, body = run(get(app, f"/{link.token}"))
    assert status == 404 and body == "nothing\n" and "已死亡" not in body
    assert store.get_link(link.id).status == "soft_dead"                # it still dies, just quietly
    door = LinkSpec(mode="door", variants=[V("A", A), V("trap", "")])
    store, link, app = serve(door, Settings(tombstone_status="404"))

    async def go():
        async with client(app) as c:
            await c.get(f"/{link.token}", headers=hdr(), allow_redirects=False)
            r = await c.get(f"/{link.token}/go?d=1", headers=hdr(), allow_redirects=False)
            return r.status, await r.text()
    status, body = run(go())
    assert status == 200 and "陷阱" in body


# ---- redirect behaviour -----------------------------------------------------------------------------
def test_permanent_redirect_codes_are_refused_because_browsers_would_cache_them_and_skip_the_count():
    for bad in ("301", "308"):
        with pytest.raises(ValueError, match="只能選"):
            Settings(redirect_status=bad)


@pytest.mark.parametrize("code", ["302", "303", "307"])
def test_redirect_status_is_used_for_plain_and_for_go(code):
    store, link, app = serve(settings=Settings(redirect_status=code))
    status, headers, _ = run(get(app, f"/{link.token}"))
    assert status == int(code) and headers["Location"] == A
    store, link, app = serve(note(), Settings(redirect_status=code))

    async def go():
        async with client(app) as c:
            await c.get(f"/{link.token}", headers=hdr(), allow_redirects=False)
            return (await c.get(f"/{link.token}/go", headers=hdr(), allow_redirects=False)).status
    assert run(go()) == int(code)


def test_utm_is_appended_but_never_overwrites_what_the_target_already_has():
    spec = LinkSpec(mode="plain", variants=[V("A", "https://a.example/p?utm_source=keep&x=1#frag")])
    store, link, app = serve(spec, Settings(utm="utm_source=zinc&utm_medium=link"))
    _, headers, _ = run(get(app, f"/{link.token}"))
    assert headers["Location"] == "https://a.example/p?utm_source=keep&x=1&utm_medium=link#frag"
    store, link, app = serve(spec, Settings())
    assert run(get(app, f"/{link.token}"))[1]["Location"] == "https://a.example/p?utm_source=keep&x=1#frag"
    store, link, app = serve(spec, Settings(utm="?utm_source=other"))                 # nothing new -> untouched
    assert run(get(app, f"/{link.token}"))[1]["Location"] == "https://a.example/p?utm_source=keep&x=1#frag"


@pytest.mark.parametrize("policy", ["no-referrer", "same-origin", "origin", "strict-origin-when-cross-origin"])
def test_referrer_policy_header_follows_the_setting(policy):
    store, link, app = serve(settings=Settings(referrer_policy=policy))
    assert run(get(app, f"/{link.token}"))[1]["Referrer-Policy"] == policy


# ---- who counts as a visitor --------------------------------------------------------------------------
def test_bot_response_card_or_404_and_count_bots_switch():
    spec = LinkSpec(mode="plain", variants=[V("A", "https://secret-target.example/")])
    ua = hdr(ua="Slackbot-LinkExpanding 1.0")
    store, link, app = serve(spec, Settings())
    status, _, body = run(get(app, f"/{link.token}", ua))
    assert status == 200 and "og:title" in body and store.stats(link.id)["bots"] == 1
    store, link, app = serve(spec, Settings(bot_response="404", decoy_text="gone\n"))
    (status, _, body), (status2, _, body2) = gets(app, (f"/{link.token}", ua), (f"/{link.token}/go", ua))
    assert status == 404 and body == "gone\n" and "secret-target" not in body
    assert status2 == 404 and body2 == "gone\n"                                      # /go follows the same rule
    store, link, app = serve(spec, Settings(count_bots=False))
    run(get(app, f"/{link.token}", ua))
    assert store.stats(link.id)["bots"] == 0


def test_bot_regex_is_what_decides_who_is_a_bot():
    spec = LinkSpec(mode="plain", variants=[V("A", A)])
    store, link, app = serve(spec, Settings(bot_regex="mycrawler"))
    (status, _, _), (status2, headers, _) = gets(app, (f"/{link.token}", hdr(ua="MyCrawler/2.0")),
                                                 (f"/{link.token}", hdr(ua="Slackbot 1.0")))
    assert status == 200 and status2 == 302 and headers["Location"] == A          # custom rule replaced the default
    assert store.stats(link.id)["opens"] == 1 and store.stats(link.id)["bots"] == 1


@pytest.mark.parametrize("by,expect", [("ip+ua", 4), ("ip", 2), ("ua", 2)])
def test_unique_by_decides_how_visitors_are_told_apart(by, expect):
    store, link, app = serve(settings=Settings(unique_by=by))

    async def go():
        async with client(app) as c:
            for ip in ("9.9.9.1", "9.9.9.2"):
                for ua in ("Mozilla/5.0 One", "Mozilla/5.0 Two"):
                    await c.get(f"/{link.token}", headers=hdr(ip, ua=ua), allow_redirects=False)
    run(go())
    assert store.stats(link.id)["uniques"] == expect


def test_decoy_text_is_what_strangers_see_and_it_is_always_404():
    store, link, app = serve(settings=Settings(decoy_text="Welcome to nginx!\n"))
    for status, _, body in gets(app, *[(p, None) for p in ("/", "/nope", f"/{link.token}x")]):
        assert (status, body) == (404, "Welcome to nginx!\n")
    assert store.stats(link.id)["opens"] == 0


# ---- scanner limits ---------------------------------------------------------------------------------------
async def with_site(handler, fn):
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    srv = TestServer(app)
    await srv.start_server()
    try:
        return await fn(str(srv.make_url("")).rstrip("/"))
    finally:
        await srv.close()


def test_scan_limits_and_user_agent_are_parameters_not_constants():
    seen = []

    async def handler(request):
        seen.append(request.headers.get("User-Agent"))
        if request.path.startswith("/hop/"):
            n = int(request.path.split("/")[2])
            if n < 3:
                raise web.HTTPFound(f"/hop/{n + 1}")
        if request.path == "/slow":
            await asyncio.sleep(1.5)
        body = "<title>t</title>" + "x" * 5000 + "<link rel=alternate hreflang=de href=/de>"
        return web.Response(text=body, content_type="text/html")

    async def go(base):
        assert (await scan_url(base + "/hop/0", allow_private=True, max_hops=3)).ok         # 3 hops fit
        r = await scan_url(base + "/hop/0", allow_private=True, max_hops=2)
        assert not r.ok and "too many redirects (> 2)" in r.error
        small = await scan_url(base + "/", allow_private=True, max_bytes=1024)               # tag past the cap unseen
        assert small.title == "t" and small.hreflang == {}
        big = await scan_url(base + "/", allow_private=True, max_bytes=64 * 1024)
        assert "de" in big.hreflang
        slow = await scan_url(base + "/slow", allow_private=True, timeout_s=0.3)
        assert not slow.ok and "Timeout" in slow.error
        seen.clear()
        await scan_url(base + "/", allow_private=True, user_agent="MyAgent/9")
        await scan_url(base + "/", allow_private=True)
        assert seen == ["MyAgent/9", "zinc-scanner/1.0"]
    run(with_site(handler, go))


def test_manager_feeds_the_scan_settings_to_the_scanner_and_scan_enabled_turns_it_off(monkeypatch):
    calls = []

    async def fake_scan_all(urls, **kw):
        calls.append(kw)
        return {u: ScanResult(url=u, ok=True, title="T") for u in urls}
    monkeypatch.setattr(manager_mod, "scan_all", fake_scan_all)
    s = Settings(scan_max_kb=64, scan_max_hops=2, scan_timeout_s=7, scan_user_agent="UA/1")

    async def go():
        m = Manager(Store(), fake_cmd, settings=s)
        assert (await m._scan([A])) != {}
        assert calls == [{"max_bytes": 64 * 1024, "max_hops": 2, "timeout_s": 7, "user_agent": "UA/1"}]
        s.scan_max_kb = 128                                                                 # live change
        await m._scan([A])
        assert calls[-1]["max_bytes"] == 128 * 1024
        s.scan_enabled = False
        n = len(calls)
        assert await m._scan([A]) == {} and len(calls) == n                                 # nothing fetched at all
        link = await m.create(plain_spec(), ttl_s=600)                                      # and links still work
        assert link.status == "live" and m.store.get_link(link.id).scan in (None, "{}", "")
        await m.shutdown()
    run(go())


# ---- built-in (L0) checks -----------------------------------------------------------------------------------
L0_CASES = {   # id -> (url, scan) that triggers it with its default severity
    "https": ("http://example.com/", None),
    "ip_literal": ("https://203.0.113.9/", None),
    "punycode": ("https://xn--pple-43d.com/", None),
    "userinfo": ("https://google.com@evil.example/", None),
    "tunnel_loop": ("https://abc-def.trycloudflare.com/", None),
    "blocklist": ("https://bad.example/", None),
    "shortener": ("https://bit.ly/abc", None),
    "long_url": ("https://example.com/" + "a" * 2100, None),
    "scan_error": ("https://example.com/", ScanResult(url="x", error="boom")),
    "redirects": ("https://a.example/", ScanResult(url="x", ok=True, chain=["https://a.example/", "https://b.example/"])),
}


def test_the_l0_id_list_matches_the_registry_and_every_id_has_a_trigger():
    from zinc.options import OPTIONS
    assert set(L0_IDS) == set(L0_CASES) == set(OPTIONS["l0_off"].choices) == set(OPTIONS["l0_levels"].key_choices)


@pytest.mark.parametrize("cid", list(L0_CASES))
def test_each_l0_check_can_be_switched_off_and_regraded(cid):
    url, scan = L0_CASES[cid]
    bl = ["bad.example"]
    base = local_checks(url, scan, bl)
    noisy = [f for f in base if f.level != "ok"]
    assert noisy, f"{cid} never fires"
    assert all(f.level == "ok" for f in local_checks(url, scan, bl, off=[cid]))              # off -> silent
    assert all(f.level == "ok" for f in local_checks(url, scan, bl, levels={cid: "ok"}))      # "ok" -> silent too
    worst = max((f.level for f in local_checks(url, scan, bl, levels={cid: "block"})), key=["ok", "info", "warn", "block"].index)
    assert worst == "block"
    others = [i for i in L0_IDS if i != cid]
    only_this = local_checks(url, scan, bl, off=others)                                         # everything else off
    assert any(f.level != "ok" for f in only_this)                                              # still fires on its own
    assert local_checks(url, scan, bl, off=["not-a-real-id"]) == base                          # unknown ids are ignored


def test_regrading_one_check_does_not_touch_the_others():
    url = "http://bit.ly/abc"                                                                   # https(warn) + shortener(info)
    got = {f.text: f.level for f in local_checks(url, None, levels={"shortener": "block"})}
    assert got["目標不是 HTTPS"] == "warn" and got["目標本身是短網址服務"] == "block"
    got = {f.text: f.level for f in local_checks(url, None, off=["https"])}
    assert list(got.values()) == ["info", "ok"]                                                  # https silenced, rest unchanged


def test_l0_settings_decide_the_verdict_end_to_end():
    async def verdict(**kw):
        rep = Reputation(Settings(**kw), providers=[])
        return (await rep.check_all(["http://example.com/"], {}))["http://example.com/"]
    assert run(verdict()).level == "warn"
    assert run(verdict(l0_levels={"https": "block"})).level == "block"
    assert run(verdict(l0_off=["https"])).level == "ok"


# ---- third-party providers ----------------------------------------------------------------------------------
def named(name, s, result=None):
    p = Counting(s, result=result or Finding(name, "ok", "clean"))
    p.name = name
    return p


def test_providers_setting_chooses_who_is_asked():
    s = Settings(providers=["urlhaus"])
    vt, gsb, uh = named("virustotal", s), named("safebrowsing", s), named("urlhaus", s)
    run(Reputation(s, providers=[vt, gsb, uh]).check_all([A], {}))
    assert (vt.n, gsb.n, uh.n) == (0, 0, 1)
    s.providers = ["virustotal", "safebrowsing"]                                               # live change
    rep = Reputation(s, providers=[vt, gsb, uh])
    run(rep.check_all([B], {}))
    assert (vt.n, gsb.n, uh.n) == (1, 1, 1)
    s.providers = []
    run(rep.check_all(["https://c.example/"], {}))
    assert (vt.n, gsb.n, uh.n) == (1, 1, 1)


def test_allowlist_skips_third_parties_for_that_domain_and_its_subdomains_only():
    s = Settings(allowlist=["mycompany.com"])
    p = named("virustotal", s)

    async def go():
        rep = Reputation(s, providers=[p])
        out = await rep.check_all(["https://mycompany.com/a", "https://app.mycompany.com/b",
                                   "https://notmycompany.com/c", "https://mycompany.com.evil.example/d"], {})
        return out
    out = run(go())
    assert p.n == 2                                                                             # only the two look-alikes
    assert any(f.source == "privacy" and "白名單" in f.text for f in out["https://app.mycompany.com/b"].findings)
    assert not any("白名單" in f.text for f in out["https://notmycompany.com/c"].findings)
    mine = out["https://mycompany.com/a"]
    assert mine.level == "info" and any(f.source == "local" and f.level == "ok" for f in mine.findings)   # L0 still ran


def test_allowlist_does_not_switch_off_the_built_in_checks():
    s = Settings(allowlist=["bad.example"], blocklist=["bad.example"])
    out = run(Reputation(s, providers=[named("virustotal", s)]).check_all(["https://bad.example/"], {}))
    assert out["https://bad.example/"].level == "block"


def test_cache_ttl_hours_controls_how_long_a_result_is_reused():
    t = [1000.0]
    for hours, second_call_after, calls in ((1, 3599, 1), (1, 3601, 2), (0, 1, 2), (24, 86000, 1)):
        s = Settings(cache_ttl_h=hours)
        p = named("virustotal", s)
        rep = Reputation(s, providers=[p], clock=lambda: t[0])
        t[0] = 1000.0
        run(rep.check_all([A], {}))
        t[0] += second_call_after
        run(rep.check_all([A], {}))
        assert p.n == calls, (hours, second_call_after)


def test_explicit_cache_ttl_argument_still_overrides_the_setting():
    s = Settings(cache_ttl_h=24)
    p = named("virustotal", s)
    rep = Reputation(s, providers=[p], cache_ttl=0)
    run(rep.check_all([A], {}))
    run(rep.check_all([A], {}))
    assert p.n == 2


def test_virustotal_rate_limits_come_from_the_settings_and_follow_live_changes():
    fake = Fake()
    for u in (A, B, "https://c.example/"):
        fake.routes[("GET", f"/v3/urls/{VirusTotal.url_id(u)}")] = (200, vt_stats())
    s = Settings(vt_key="k" * 12, vt_per_minute=1, vt_per_day=500)

    async def go(base, session):
        vt = VirusTotal(s, base + "/v3")
        first = await vt.check(A, session)
        second = await vt.check(B, session)                       # over the per-minute budget: skipped, no request
        n_after_two = len(fake.calls)
        s.vt_per_minute = 5                                       # raised by the user: applies to the next check
        third = await vt.check("https://c.example/", session)
        return first, second, third, n_after_two, len(fake.calls)
    first, second, third, n2, n3 = run(with_fake(fake, go))
    assert first.level == "ok" and second.level == "skip" and "限流" in second.text
    assert n2 == 1 and third.level == "ok" and n3 == 2


def test_virustotal_daily_limit_comes_from_the_settings():
    fake = Fake()
    fake.routes[("GET", f"/v3/urls/{VirusTotal.url_id(A)}")] = (200, vt_stats())
    s = Settings(vt_key="k" * 12, vt_per_minute=100, vt_per_day=1)

    async def go(base, session):
        vt = VirusTotal(s, base + "/v3")
        return await vt.check(A, session), await vt.check(A, session), len(fake.calls)
    one, two, calls = run(with_fake(fake, go))
    assert one.level == "ok" and two.level == "skip" and calls == 1


def test_an_injected_throttle_is_left_alone():
    from zinc.reputation import Throttle
    th = Throttle(7, 70)
    vt = VirusTotal(Settings(vt_per_minute=1, vt_per_day=1), throttle=th)
    assert vt.throttle is th and (th.per_minute, th.per_day) == (7, 70)


def test_provider_timeout_comes_from_the_settings():
    async def slow(request):
        await asyncio.sleep(1.0)
        return web.json_response({})

    async def go(base):
        s = Settings(vt_key="k" * 12)
        s.__dict__["provider_timeout_s"] = 0.2                       # below the user-facing minimum: only for speed
        vt = VirusTotal(s, base + "/v3")
        out = await Reputation(s, providers=[vt]).check_all([A], {})
        return out[A]
    v = run(with_site(slow, go))
    assert any(f.level == "skip" and "TimeoutError" in f.text for f in v.findings) and v.level == "ok"


# ---- tunnel ---------------------------------------------------------------------------------------------
def test_find_cloudflared_priority_is_setting_then_env_then_path(monkeypatch):
    monkeypatch.setenv("ZINC_CLOUDFLARED", "/from/env")
    assert find_cloudflared("/from/setting") == "/from/setting"
    assert find_cloudflared("") == "/from/env"
    monkeypatch.delenv("ZINC_CLOUDFLARED")
    monkeypatch.setattr("shutil.which", lambda name: "/from/path" if name == "cloudflared" else None)
    assert find_cloudflared("") == "/from/path"
    assert preflight(Path("/nonexistent-home"), "") == []
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert any("找不到 cloudflared" in p for p in preflight(Path("/nonexistent-home"), ""))
    assert preflight(Path("/nonexistent-home"), "/from/setting") == []


def test_default_cmd_uses_the_configured_path_and_appends_extra_args():
    cmd = default_cmd(8123, "/opt/cf", ["--protocol", "http2"])
    assert cmd == ["/opt/cf", "tunnel", "--no-autoupdate", "--url", "http://127.0.0.1:8123", "--protocol", "http2"]
    assert default_cmd(1, "/opt/cf")[-2:] == ["--url", "http://127.0.0.1:1"]


@pytest.mark.skipif(sys.platform == "win32", reason="needs a shell wrapper")
def test_configured_path_and_extra_args_really_reach_the_process(tmp_path, monkeypatch):
    log = tmp_path / "args.txt"
    wrapper = tmp_path / "my-cloudflared"
    wrapper.write_text(f'#!/bin/sh\necho "$@" > "{log}"\nexec "{sys.executable}" "{FAKE}" "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("ZINC_CLOUDFLARED", "/definitely/not/here")          # the setting must win over the env var
    s = Settings(cloudflared_path=str(wrapper), tunnel_extra_args=["--protocol", "http2"])

    async def go():
        m = Manager(Store(), scanner=noscan, settings=s)
        link = await m.create(plain_spec(), ttl_s=600)
        assert link.status == "live"
        await m.shutdown()
    run(go())
    args = log.read_text().split()
    assert args[:2] == ["tunnel", "--no-autoupdate"] and args[-2:] == ["--protocol", "http2"]


def test_tunnel_timeout_setting_is_what_the_manager_waits_for(monkeypatch):
    waited = []

    async def fake_start(self, timeout=20.0):
        waited.append(timeout)
        return "quiet-fox-lake-moss.trycloudflare.com"
    monkeypatch.setattr(Tunnel, "start", fake_start)

    async def go(settings, **kw):
        m = Manager(Store(), fake_cmd, scanner=noscan, settings=settings, **kw)
        await m.create(plain_spec(), ttl_s=60)
        await m.shutdown()
    run(go(Settings(tunnel_timeout_s=33)))
    run(go(Settings(tunnel_timeout_s=33), tunnel_timeout=4.5))                     # explicit argument wins (tests rely on it)
    assert waited == [33, 4.5]
