"""Tests for the places the coverage report showed nobody was looking."""
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import types
from collections import deque
from pathlib import Path

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from tests.test_features import PW, locked_spec
from tests.test_reputation import KEY, URL, Fake, Throttle, with_fake
from tests.test_server import A, NOW, V, client, hdr, run
from tests.test_settings_wiring import gets, serve
from tests.test_tui import Fixed, drive, make_link, until
from tests.test_tunnel_manager import FAKE, Clock, fake_cmd, mgr, noscan, plain_spec
from zinc.config import Settings, config_path
from zinc.geo import mmdb_resolver
from zinc.models import LinkSpec
from zinc.notify import Notifier
from zinc.options import OPTIONS
from zinc.reputation import URLhaus, VirusTotal, Finding, Verdict, dump_verdicts
from zinc.scan import ScanResult, dump_scans, scan_all
from zinc.server import ATTEMPTS, UNLOCKED, make_app
from zinc.store import Store
from zinc.tunnel import Tunnel
from zinc.view import detail_text, opt_from_text, opt_text

ROOT = Path(__file__).resolve().parent.parent


# ---- password guessing: refused requests must not cost memory ---------------------------------
def test_refused_unlock_requests_never_grow_the_attempt_table():
    store, link, app = serve(locked_spec(), Settings(unlock_tries=3))
    path = f"/{link.token}/unlock"

    async def go():
        async with client(app) as c:
            for i in range(35):                               # use up the per-link budget (30/min)
                await c.post(path, json={"p": "x"}, headers=hdr(f"5.5.{i}.1"))
            size = len(app[ATTEMPTS])
            for i in range(300):                               # a flood of new faces, all refused
                r = await c.post(path, json={"p": "x"}, headers=hdr("6.6.6.6", ua=f"Mozilla/5.0 flood-{i}"))
                assert r.status == 429
            assert len(app[ATTEMPTS]) == size <= 30
    run(go())


def test_stale_guessers_are_forgotten_so_the_table_stays_small_over_hours():
    t = [NOW]
    store, link, app = serve(locked_spec(), Settings(unlock_tries=3), clock=lambda: t[0], ttl=10**6)
    path = f"/{link.token}/unlock"

    async def go():
        async with client(app) as c:
            seen = set()
            for minute in range(40):                          # 40 minutes x 30 new visitors = 1200 distinct guessers
                for i in range(30):
                    r = await c.post(path, json={"p": "x"}, headers=hdr(f"7.{minute}.{i}.1"))
                    seen.add(r.status)
                t[0] += 61
            assert seen == {401}                              # every guess was really evaluated (not throttled or dead)
            assert len(app[ATTEMPTS]) <= 1000
    run(go())


def test_bots_cannot_use_the_unlock_endpoint_even_with_the_right_password():
    store, link, app = serve(locked_spec())
    async def go():
        async with client(app) as c:
            r = await c.post(f"/{link.token}/unlock", json={"p": PW}, headers=hdr(ua="Slackbot-LinkExpanding 1.0"))
            assert r.status == 404
    run(go())
    assert app[UNLOCKED] == set()


def test_an_app_for_a_link_that_does_not_exist_answers_everything_with_the_decoy():
    app = make_app(Store(), "nosuchid")
    out = gets(app, ("/", None), ("/abc", None), ("/abc/go", None))
    assert {o[0] for o in out} == {404}


def test_count_mode_shows_each_visitors_rank_and_only_redirects_through_go():
    spec = LinkSpec(mode="count", variants=[V("A", "https://secret-target.example/")])
    store, link, app = serve(spec)
    out = gets(app, (f"/{link.token}", hdr("1.1.1.1")), (f"/{link.token}", hdr("2.2.2.2")))
    assert [o[0] for o in out] == [200, 200]
    assert 'class="big">1<' in out[0][2] and 'class="big">2<' in out[1][2]
    assert all(f'href="/{link.token}/go"' in o[2] for o in out)         # the only way on is the counted /go step


# ---- providers: the unhappy paths ------------------------------------------------------------
def test_vt_submit_failure_is_a_skip_not_a_crash():
    fake = Fake()
    fake.routes[("POST", "/v3/urls")] = (500, {})

    async def go(base, s):
        return await VirusTotal(Settings(vt_key=KEY, vt_submit_unknown=True), base + "/v3",
                                throttle=Throttle(100, 100)).check(URL, s)
    f = run(with_fake(fake, go))
    assert f.level == "skip" and "提交失敗" in f.text and "500" in f.text


def test_vt_stops_when_the_daily_budget_runs_out_before_submitting():
    fake = Fake()

    async def go(base, s):
        return await VirusTotal(Settings(vt_key=KEY, vt_submit_unknown=True), base + "/v3",
                                throttle=Throttle(100, 1)).check(URL, s)
    f = run(with_fake(fake, go))
    assert f.level == "skip" and "額度" in f.text
    assert [c[0] for c in fake.calls] == ["GET"]              # the lookup used the only call; nothing was submitted


def test_vt_gives_up_polling_when_the_budget_runs_out_mid_analysis():
    fake = Fake()
    fake.routes[("POST", "/v3/urls")] = (200, {"data": {"id": "an-1"}})
    fake.routes[("GET", "/v3/analyses/an-1")] = (200, {"data": {"attributes": {"status": "queued"}}})

    async def nosleep(_):
        return None

    async def go(base, s):
        return await VirusTotal(Settings(vt_key=KEY, vt_submit_unknown=True), base + "/v3",
                                throttle=Throttle(100, 3), sleep=nosleep).check(URL, s)
    f = run(with_fake(fake, go))
    assert f.level == "skip" and "分析中" in f.text
    assert sum(c[1] == "/v3/analyses/an-1" for c in fake.calls) == 1      # lookup, submit, ONE poll, then the budget is gone


@pytest.mark.parametrize("status,needle", [(401, "無效"), (403, "無效"), (500, "500")])
def test_urlhaus_errors_become_skips(status, needle):
    fake = Fake()
    fake.routes[("POST", "/v1/url/")] = (status, {})

    async def go(base, s):
        return await URLhaus(Settings(urlhaus_key=KEY), base + "/v1").check(URL, s)
    f = run(with_fake(fake, go))
    assert f.level == "skip" and needle in f.text


# ---- manager: rescan, ticker ------------------------------------------------------------------
def test_rescan_replaces_the_stored_scan_and_verdict_and_ignores_unknown_ids():
    async def go():
        calls = []

        async def scanner(urls):
            calls.append(list(urls))
            return {u: ScanResult(url=u, ok=True, status=200, title=f"scan #{len(calls)}") for u in urls}
        m = mgr(Clock(), scanner=scanner)
        link = await m.create(plain_spec())
        changed = []
        m.on_change = lambda: changed.append(1)
        await m.rescan(link.id)
        await m.rescan("nosuchid")
        from zinc.scan import load_scans
        assert load_scans(m.store.get_link(link.id).scan)["https://a.example/"].title == "scan #2"
        assert len(calls) == 2 and calls[1] == ["https://a.example/"]
        assert m.store.get_link(link.id).verdict
        await m.shutdown()
    run(go())


def test_a_crashing_tick_is_reported_and_the_ticker_keeps_running():
    async def go():
        m = mgr(Clock())
        calls = []

        async def bad_tick():
            calls.append(1)
            raise RuntimeError("boom")
        m.tick = bad_tick
        task = asyncio.create_task(m.run_ticker(interval=0.01))
        await asyncio.sleep(0.15)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert len(calls) >= 3 and m.errors["_ticker"] == "boom"
    run(go())


def test_a_cloudflared_that_ignores_sigterm_is_killed(monkeypatch):
    if sys.platform == "win32":
        pytest.skip("terminate() is already a hard kill on Windows")
    monkeypatch.setenv("FAKE_CF_MODE", "ignore_term")

    async def go():
        t = Tunnel(fake_cmd(1), term_grace=0.3)
        await t.start(timeout=5)
        proc = t.proc
        began = time.monotonic()
        await asyncio.wait_for(t.stop(), 5)                                 # a broken kill must fail the test, not hang it
        assert proc.returncode == -signal.SIGKILL                           # SIGTERM was ignored, so it had to be SIGKILL
        assert time.monotonic() - began >= 0.3                              # ...and only after the grace period
    run(go())


# ---- scanning: many targets, de-duplicated ----------------------------------------------------
def test_scan_all_scans_each_distinct_url_once_and_skips_blanks():
    hits = []

    async def page(request):
        hits.append(request.path)
        return web.Response(text="<title>hi</title>", content_type="text/html")
    app = web.Application()
    app.router.add_get("/{p:.*}", page)

    async def go():
        srv = TestServer(app)
        await srv.start_server()
        try:
            u1, u2 = str(srv.make_url("/a")), str(srv.make_url("/b"))
            return await scan_all([u1, u2, u1, ""], allow_private=True), u1, u2
        finally:
            await srv.close()
    out, u1, u2 = run(go())
    assert list(out) == [u1, u2] and all(r.ok and r.title == "hi" for r in out.values())
    assert sorted(hits) == ["/a", "/b"]


# ---- small contracts --------------------------------------------------------------------------
def test_mmdb_resolver_reads_country_codes_and_never_raises(monkeypatch):
    class Reader:
        def get(self, ip):
            if ip == "bad":
                raise ValueError("nope")
            return {"1.1.1.1": {"country": {"iso_code": "au"}}, "2.2.2.2": {"country": {"iso_code": "ZZZ"}},
                    "3.3.3.3": {}}.get(ip)
    fake = types.ModuleType("maxminddb")
    fake.open_database = lambda path: Reader()
    monkeypatch.setitem(sys.modules, "maxminddb", fake)
    r = mmdb_resolver("db.mmdb")
    assert [r({}, ip) for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "bad")] == ["AU", None, None, None, None]


def test_config_path_follows_each_platforms_convention(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert config_path({"XDG_CONFIG_HOME": "/x"}) == Path("/x/zinc/config.json")
    assert config_path({}) == Path.home() / ".config" / "zinc" / "config.json"
    assert config_path({"APPDATA": "/win"}) == Path.home() / ".config" / "zinc" / "config.json"    # APPDATA is Windows-only
    monkeypatch.setattr(sys, "platform", "win32")
    assert config_path({"APPDATA": "/win"}) == Path("/win/zinc/config.json")
    assert config_path({"XDG_CONFIG_HOME": "/x"}) == Path("/x/zinc/config.json")                    # no APPDATA: fall back


def test_url_settings_refuse_credentials_and_absurd_length():
    s = Settings()
    with pytest.raises(ValueError, match="帳密"):
        s.apply({"webhook_url": "https://user:pw@hooks.example/x"})
    with pytest.raises(ValueError, match="太長"):
        s.apply({"webhook_url": "https://hooks.example/" + "a" * 600})
    s.apply({"webhook_url": "https://hooks.example/" + "a" * 400})
    assert s.webhook_url.endswith("a" * 400)


def test_a_webhook_url_removed_while_a_message_is_queued_sends_nothing():
    async def go():
        s = Settings(webhook_url="http://127.0.0.1:9/hook", webhook_events=["open"])
        n = Notifier(s)
        assert n.submit("open", {"link_id": "abcd1234"})
        s.apply({"webhook_url": ""})
        await n.flush()
        await n.close()
        assert n.sent == 0 and n.last_error == ""
    run(go())


def test_detail_view_lists_flagged_urls_and_scan_results_and_failures():
    store = Store()
    link = store.create_link(LinkSpec(mode="plain", variants=[V("A", A)]), now=NOW)
    store.set_scan(link.id, dump_scans({
        "https://ok.example/": ScanResult(url="https://ok.example/", ok=True, status=200, title="Hello", elapsed_ms=42,
                                          hreflang={"ja": "https://ok.example/ja"}),
        "https://down.example/": ScanResult(url="https://down.example/", ok=False, error="連不上"),
    }))
    store.set_verdict(link.id, dump_verdicts({"https://bad.example/": Verdict(
        level="block", findings=[Finding("urlhaus", "block", "線上惡意網址")], checked=["local", "urlhaus"])}))
    text = detail_text(store.get_link(link.id), store.stats(link.id), "https://x.trycloudflare.com/t", NOW).plain
    assert "目標掃描" in text and "✓ 200" in text and "Hello" in text and "42ms" in text and "語系 1 種" in text
    assert "✗ 連不上" in text
    assert "⛔ urlhaus: 線上惡意網址" in text and "https://bad.example/" in text


def test_list_and_map_settings_round_trip_through_their_text_form():
    for key, value in (("rule_order", ["geo", "lang", "device"]), ("webhook_events", ["open", "dead"])):
        o = OPTIONS[key]
        assert o.coerce(opt_from_text(o, opt_text(o, value))) == value
    maps = [o for o in OPTIONS.values() if o.kind == "map"]
    assert maps, "the registry has map settings"
    for o in maps:
        assert o.coerce(opt_from_text(o, opt_text(o, o.default))) == o.default
    note = OPTIONS["decoy_text"]
    assert opt_from_text(note, opt_text(note, "a\nb\n")) == "a\nb\n"


# ---- command line -----------------------------------------------------------------------------
def run_cli(*args, env=None):
    e = {**os.environ, "PYTHONPATH": str(ROOT), **(env or {})}
    return subprocess.run([sys.executable, "-m", "zinc", *args], cwd=ROOT, env=e, capture_output=True, text=True,
                          timeout=60)


def test_cli_prints_the_version_the_config_path_and_the_settings_help(tmp_path):
    v = run_cli("--version")
    assert v.returncode == 0 and v.stdout.strip().startswith("zinc ")
    c = run_cli("--config-path", env={"XDG_CONFIG_HOME": str(tmp_path), "APPDATA": str(tmp_path)})
    assert c.stdout.strip() == str(tmp_path / "zinc" / "config.json")            # XDG on POSIX, APPDATA on Windows
    basic, expert = run_cli("--help-settings", "basic"), run_cli("--help-settings")
    assert basic.returncode == expert.returncode == 0
    assert 0 < len(basic.stdout) < len(expert.stdout)
    assert all(o.label in expert.stdout for o in OPTIONS.values())
    bad = run_cli("--help-settings", "nonsense")
    assert bad.returncode == 2 and "invalid choice" in bad.stderr


# ---- TUI: the corners ---------------------------------------------------------------------------
def test_escape_backs_out_of_dialogs_without_doing_anything(tmp_path):
    async def body(app, pilot, store, m, s):
        link = await make_link(app, pilot, store)
        await pilot.press("D")                                   # hard destroy asks first
        await pilot.pause()
        from zinc.tui import Confirm, NewLink
        assert isinstance(app.screen, Confirm)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, Confirm) and store.get_link(link.id).status == "live"
        await pilot.press("n")
        await pilot.pause()
        assert isinstance(app.screen, NewLink)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, NewLink) and len(store.list_links()) == 1
    drive(body, tmp_path)


def test_qr_screen_in_a_tiny_terminal_explains_itself_instead_of_drawing_a_broken_code(tmp_path):
    async def body(app, pilot, store, m, s):
        await m.create(plain_spec())
        await pilot.pause(0.5)
        await pilot.press("q")
        await pilot.pause()
        from zinc.tui import QRScreen
        assert isinstance(app.screen, QRScreen)
        assert not app.screen.query("#qrfull")
        assert "終端機太小" in str(app.screen.query("Static").first().render())
    drive(body, tmp_path, size=(40, 14))


def test_copy_rescan_and_a_failed_qr_save_each_tell_the_user(tmp_path):
    async def body(app, pilot, store, m, s):
        link = await make_link(app, pilot, store)
        await pilot.press("c")
        await pilot.pause()
        assert any("已複製" in n.message for n in app._notifications)
        seen = []

        async def fake_rescan(link_id):
            seen.append(link_id)
        m.rescan = fake_rescan
        await pilot.press("r")
        await pilot.pause(0.3)
        assert seen == [link.id]
        blocker = tmp_path / "not-a-folder"
        blocker.write_text("x")
        s.apply({"qr_export_dir": str(blocker / "sub")})            # cannot mkdir under a regular file
        await pilot.press("s")
        await pilot.pause()
        assert any("存檔失敗" in n.message for n in app._notifications)
    drive(body, tmp_path)


def test_a_tunnel_failure_on_create_is_shown_and_leaves_nothing_behind(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_CF_MODE", "fail")

    async def body(app, pilot, store, m, s):
        await pilot.press("n")
        await pilot.pause()
        app.screen.query_one("#targets").value = "https://example.com"
        await pilot.click("#ok")
        assert await until(lambda: any(n.severity == "error" for n in app._notifications), pilot, tries=150)
        assert [l.status for l in store.list_links()] == ["failed"]        # recorded as failed, nothing serving
    drive(body, tmp_path)


def test_editing_into_a_blocked_target_asks_first_and_declining_changes_nothing(tmp_path):
    async def body(app, pilot, store, m, s):
        link = await m.create(plain_spec(), force=True)
        await pilot.pause(0.5)
        from zinc.tui import Confirm
        for answer, expect in (("#no", "https://a.example/"), ("#yes", "https://new.example/")):
            await pilot.press("t")
            await pilot.pause()
            app.screen.query_one("#targets").value = "https://new.example/"
            await pilot.click("#ok")
            assert await until(lambda: isinstance(app.screen, Confirm), pilot)
            assert "安全檢查擋下" in str(app.screen.query_one("#confirm-text").render())
            await pilot.click(answer)
            await pilot.pause(0.5)
            assert store.get_link(link.id).spec.variants[0].url == expect
    drive(body, tmp_path, level="block")


# ---- adaptive locale: precedence rules the first tests did not pin down -------------------------
def test_a_declared_exact_tag_beats_its_alias_which_beats_the_bare_language():
    from zinc.locale import match_hreflang
    page = {"zh": "https://x/zh", "zh-hant": "https://x/hant", "zh-tw": "https://x/tw"}
    assert match_hreflang(["zh-TW"], page) == ("zh-tw", "https://x/tw")
    del page["zh-tw"]
    assert match_hreflang(["zh-TW"], page) == ("zh-hant", "https://x/hant")
    del page["zh-hant"]
    assert match_hreflang(["zh-TW"], page) == ("zh", "https://x/zh")


def test_a_url_that_already_speaks_the_visitors_first_language_is_left_alone():
    from zinc.locale import finalize_url
    kw = dict(auto_locale=True, country="JP", scans={})
    # the author already chose hl=ja; the visitor prefers ja then fr: do not drift to the lower-priority fr
    assert finalize_url("https://www.google.com/?hl=ja", accept_language="ja,fr;q=0.8", **kw) == (
        "https://www.google.com/?hl=ja", None)


def test_a_rule_with_nothing_for_the_first_language_tries_the_next_one():
    from zinc.locale import finalize_url
    url, why = finalize_url("https://www.microsoft.com/", auto_locale=True, accept_language="ja,de-DE;q=0.8",
                            country=None, scans={})            # the microsoft rule needs a regional tag: 'ja' has none
    assert url == "https://www.microsoft.com/de-de/" and why == "rule:de-DE"


@pytest.mark.parametrize("url", ["ftp://www.google.com/", "javascript:alert(1)", "mailto:a@google.com"])
def test_non_http_urls_are_never_rewritten(url):
    from zinc.locale import finalize_url
    assert finalize_url(url, auto_locale=True, accept_language="ja", country="JP", scans={}) == (url, None)


def test_target_names_run_a_to_z_then_v26_v27():
    from zinc.view import parse_targets
    names = [v.name for v in parse_targets(" ".join(f"https://t{i}.example" for i in range(28)))]
    assert names[:3] == ["A", "B", "C"] and names[25] == "Z" and names[26:] == ["V26", "V27"]


def test_link_updates_only_touch_known_columns_so_a_column_name_can_never_inject_sql():
    st = Store()
    link = st.create_link(LinkSpec(mode="plain", variants=[V("A", A)]), now=NOW)
    for bad in ({"status=1, token": "x"}, {"token": "x"}, {"id": "x"}, {}):
        with pytest.raises(ValueError, match="cannot update link column"):
            st._update(link.id, **bad)
    assert st.get_link(link.id).status == link.status and st.get_link(link.id).token == link.token
    st.set_status(link.id, "paused")
    assert st.get_link(link.id).status == "paused"
