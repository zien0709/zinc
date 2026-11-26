import asyncio
import base64
import os
import stat
import sys

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from zinc import pages
from zinc.config import Settings, load_settings, mask, save_settings, scrub
from zinc.manager import BlockedError, Manager
from zinc.models import LinkSpec, Variant
from zinc.reputation import (Finding, Provider, Reputation, SafeBrowsing, Throttle, URLhaus, Verdict,
                             VirusTotal, aggregate, has_secret_params, local_checks)
from zinc.scan import ScanResult
from zinc.store import Store

KEY = "k3y-SECRET-0123456789"
URL = "https://example.com/page"


def run(coro):
    return asyncio.run(coro)


async def noscan(urls):
    return {}


def lv(findings, source=None):
    return {f.level for f in findings if source in (None, f.source)}


# ---- L0 ------------------------------------------------------------------------------------
@pytest.mark.parametrize("url,level,needle", [
    ("http://example.com/", "warn", "HTTPS"),
    ("https://203.0.113.9/x", "warn", "IP"),
    ("https://xn--pple-43d.com/", "warn", "punycode"),
    ("https://google.com@evil.example/", "warn", "user@"),
    ("https://abc-def.trycloudflare.com/x", "block", "trycloudflare"),
    ("https://bit.ly/abc", "info", "短網址"),
    ("https://example.com/" + "a" * 2100, "warn", "過長"),
])
def test_local_checks_flag_the_obvious(url, level, needle):
    hits = [f for f in local_checks(url, None) if needle in f.text]
    assert hits and hits[0].level == level


def test_local_checks_clean_url_is_ok_and_lookalikes_are_not_flagged():
    assert lv(local_checks("https://example.com/", None)) == {"ok"}
    assert "block" not in lv(local_checks("https://nottrycloudflare.com/", None))
    assert "block" not in lv(local_checks("https://trycloudflare.com.evil.example/", None))


def test_blocklist_matches_domain_and_subdomains_only():
    bl = ["evil.example"]
    assert "block" in lv(local_checks("https://evil.example/", None, bl))
    assert "block" in lv(local_checks("https://a.b.evil.example/", None, bl))
    assert "block" not in lv(local_checks("https://notevil.example/", None, bl))


def test_scan_results_feed_local_checks():
    bad = ScanResult(url=URL, status=404, chain=[URL], ok=False)
    assert "warn" in lv(local_checks(URL, bad))
    err = ScanResult(url=URL, error="boom")
    assert "warn" in lv(local_checks(URL, err))
    hops = ScanResult(url=URL, status=200, ok=True, chain=[f"https://h{i}.example/" for i in range(6)])
    assert any("跳轉 5 次" in f.text for f in local_checks(URL, hops))
    cross = ScanResult(url=URL, status=200, ok=True, chain=["https://a.example/", "https://b.example/"])
    assert any(f.level == "info" and "不同網域" in f.text for f in local_checks("https://a.example/", cross))


def test_aggregate_orders_levels_ignores_skips_and_privacy_in_checked():
    f = [Finding("local", "ok", "x"), Finding("virustotal", "skip", "no key"),
         Finding("urlhaus", "warn", "w"), Finding("safebrowsing", "block", "b"), Finding("privacy", "info", "p")]
    v = aggregate(f, 5.0)
    assert v.level == "block" and v.checked == ["local", "safebrowsing", "urlhaus"]
    assert aggregate([Finding("virustotal", "skip", "x")], 0).level == "ok"
    assert aggregate([], 0).level == "ok"
    assert Verdict.from_json(v.to_json()) == v


def test_corrupt_verdict_cache_never_crashes():
    from zinc.reputation import load_verdicts
    for bad in (None, "", "not json", "[1,2]", '{"u": 5}', '{"u": {"level": "ok"}}'):
        assert load_verdicts(bad) == {}


def test_secret_params_detection():
    assert has_secret_params("https://x.example/?a=1&Token=abc")
    assert has_secret_params("https://x.example/?X-Amz-Signature=abc")
    assert has_secret_params("https://user:pw@x.example/")
    assert not has_secret_params("https://x.example/?page=2&q=cats")


# ---- fake provider servers -------------------------------------------------------------------
class Fake:
    """One aiohttp app impersonating a provider; records every request it receives."""

    def __init__(self):
        self.calls = []          # (method, path, headers, query, body)
        self.routes = {}         # (method, path) -> (status, json)
        self.app = web.Application()
        self.app.router.add_route("*", "/{tail:.*}", self.handle)

    async def handle(self, request):
        body = await request.post() if request.method == "POST" and request.content_type.startswith(
            "application/x-www-form") else (await request.json() if request.can_read_body else None)
        self.calls.append((request.method, request.path, dict(request.headers), dict(request.query), body))
        status, data = self.routes.get((request.method, request.path), (404, {}))
        if callable(data):
            data = data(len(self.calls))
        return web.json_response(data, status=status)


async def with_fake(fake, fn):
    srv = TestServer(fake.app)
    await srv.start_server()
    try:
        async with aiohttp.ClientSession() as s:
            return await fn(str(srv.make_url("")).rstrip("/"), s)
    finally:
        await srv.close()


def vt_stats(**k):
    base = {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 5}
    return {"data": {"attributes": {"last_analysis_stats": {**base, **k}}}}


# ---- VirusTotal ------------------------------------------------------------------------------
def test_vt_url_id_is_urlsafe_base64_without_padding():
    url = "https://x.example/?a=>>>??&b=~~~"
    std = base64.b64encode(url.encode()).decode()
    assert any(c in std for c in "+/=")                    # the input really exercises the alphabet
    got = VirusTotal.url_id(url)
    assert not any(c in got for c in "+/=") and base64.urlsafe_b64decode(got + "=" * (-len(got) % 4)) == url.encode()


@pytest.mark.parametrize("stats,level", [({"malicious": 5}, "block"), ({"malicious": 3}, "block"),
                                         ({"malicious": 2}, "warn"), ({"suspicious": 1}, "warn"), ({}, "ok")])
def test_vt_thresholds(stats, level):
    fake = Fake()
    fake.routes[("GET", f"/v3/urls/{VirusTotal.url_id(URL)}")] = (200, vt_stats(**stats))

    async def go(base, s):
        return await VirusTotal(Settings(vt_key=KEY), base + "/v3").check(URL, s)
    f = run(with_fake(fake, go))
    assert f.level == level and fake.calls[0][2]["x-apikey"] == KEY


def test_vt_without_key_makes_no_request():
    fake = Fake()

    async def go(base, s):
        return await VirusTotal(Settings(), base + "/v3").check(URL, s)
    assert run(with_fake(fake, go)).level == "skip" and fake.calls == []


@pytest.mark.parametrize("status,needle", [(401, "無效"), (403, "無效"), (429, "限流"), (500, "500")])
def test_vt_errors_become_skips(status, needle):
    fake = Fake()
    fake.routes[("GET", f"/v3/urls/{VirusTotal.url_id(URL)}")] = (status, {})

    async def go(base, s):
        return await VirusTotal(Settings(vt_key=KEY), base + "/v3").check(URL, s)
    f = run(with_fake(fake, go))
    assert f.level == "skip" and needle in f.text


def test_vt_unknown_url_is_not_submitted_by_default():
    fake = Fake()

    async def go(base, s):
        return await VirusTotal(Settings(vt_key=KEY), base + "/v3").check(URL, s)
    f = run(with_fake(fake, go))
    assert f.level == "skip" and "未提交" in f.text
    assert [c[0] for c in fake.calls] == ["GET"]           # privacy: a lookup only, never a POST


def test_vt_submit_flow_and_still_analysing():
    for finished, expect in ((True, "block"), (False, "skip")):
        fake = Fake()
        fake.routes[("POST", "/v3/urls")] = (200, {"data": {"id": "an-1"}})
        done = {"data": {"attributes": {"status": "completed", "stats": {"malicious": 4, "harmless": 1}}}}
        queued = {"data": {"attributes": {"status": "queued"}}}
        fake.routes[("GET", "/v3/analyses/an-1")] = (200, done if finished else queued)

        async def nosleep(_):
            return None

        async def go(base, s):
            vt = VirusTotal(Settings(vt_key=KEY, vt_submit_unknown=True), base + "/v3",
                            throttle=Throttle(100, 100), sleep=nosleep)
            return await vt.check(URL, s)
        f = run(with_fake(fake, go))
        assert f.level == expect
        assert [c[0] for c in fake.calls][:2] == ["GET", "POST"]
        if not finished:
            assert sum(c[1] == "/v3/analyses/an-1" for c in fake.calls) == 3 and "分析中" in f.text


# ---- throttle --------------------------------------------------------------------------------
def test_throttle_per_minute_waits_then_per_day_cuts_off():
    t = [0.0]
    slept = []

    async def sleep(d):
        slept.append(d)
        t[0] += d

    async def go():
        th = Throttle(4, 6, clock=lambda: t[0], sleep=sleep)
        assert [await th.acquire() for _ in range(4)] == [True] * 4 and slept == []
        t[0] = 10
        assert await th.acquire() is False and slept == []        # default patience (20s) < the 50s wait
        assert await th.acquire(max_wait=60) is True and slept == [50]   # waited out the minute window
        # a refused call must not have eaten the daily budget: 5 used so far, so exactly 1 more is left
        t[0] += 1
        assert await th.acquire() is True                         # 6th of the day
        assert await th.acquire() is False                        # day budget spent
        t[0] += 86400
        assert await th.acquire() is True                         # window rolled over
        th2 = Throttle(1, 100, clock=lambda: t[0], sleep=sleep)
        await th2.acquire()
        assert await th2.acquire(max_wait=5) is False             # would wait ~60s: give up instead
    run(go())


# ---- Safe Browsing ---------------------------------------------------------------------------
def test_sb_match_no_match_and_request_shape():
    fake = Fake()
    hit = {"matches": [{"threatType": "MALWARE"}, {"threatType": "SOCIAL_ENGINEERING"}, {"threatType": "MALWARE"}]}
    fake.routes[("POST", "/v4/threatMatches:find")] = (200, lambda n: hit if n == 1 else {})

    async def go(base, s):
        sb = SafeBrowsing(Settings(gsb_key=KEY), base + "/v4")
        return await sb.check(URL, s), await sb.check(URL, s)
    a, b = run(with_fake(fake, go))
    assert a.level == "block" and "MALWARE" in a.text and "SOCIAL_ENGINEERING" in a.text
    assert b.level == "ok"
    _, _, _, query, body = fake.calls[0]
    assert query == {"key": KEY}
    assert body["threatInfo"]["threatEntries"] == [{"url": URL}]
    assert body["threatInfo"]["threatEntryTypes"] == ["URL"] and "MALWARE" in body["threatInfo"]["threatTypes"]


@pytest.mark.parametrize("status", [400, 403, 429, 500])
def test_sb_errors_are_skips(status):
    fake = Fake()
    fake.routes[("POST", "/v4/threatMatches:find")] = (status, {})

    async def go(base, s):
        return await SafeBrowsing(Settings(gsb_key=KEY), base + "/v4").check(URL, s)
    assert run(with_fake(fake, go)).level == "skip"


# ---- URLhaus ---------------------------------------------------------------------------------
@pytest.mark.parametrize("resp,level", [({"query_status": "no_results"}, "ok"),
                                        ({"query_status": "ok", "url_status": "online", "threat": "malware_download"}, "block"),
                                        ({"query_status": "ok", "url_status": "offline"}, "warn"),
                                        ({"query_status": "invalid_url"}, "skip")])
def test_urlhaus_statuses_and_auth_header(resp, level):
    fake = Fake()
    fake.routes[("POST", "/v1/url/")] = (200, resp)

    async def go(base, s):
        return await URLhaus(Settings(urlhaus_key=KEY), base + "/v1").check(URL, s)
    assert run(with_fake(fake, go)).level == level
    assert fake.calls[0][2]["Auth-Key"] == KEY and fake.calls[0][4]["url"] == URL


# ---- orchestration ---------------------------------------------------------------------------
class Counting(Provider):
    name = "virustotal"

    def __init__(self, s, result=None, exc=None):
        super().__init__(s)
        self.n, self.result, self.exc = 0, result or Finding("virustotal", "ok", "clean"), exc

    async def check(self, url, session):
        self.n += 1
        if self.exc:
            raise self.exc
        return self.result


def test_urls_with_secrets_are_never_sent_to_third_parties_unless_opted_in():
    p = Counting(Settings())
    secret = "https://x.example/share?token=abc123"

    async def go(opt_in):
        rep = Reputation(Settings(send_secret_urls=opt_in), providers=[p])
        return (await rep.check_all([secret, "https://user:pw@y.example/"], {}))
    out = run(go(False))
    assert p.n == 0 and all(any(f.source == "privacy" for f in v.findings) for v in out.values())
    run(go(True))
    assert p.n == 2


def test_cache_hits_skip_provider_but_skips_are_retried():
    ok = Counting(Settings())
    sk = Counting(Settings(), result=Finding("virustotal", "skip", "rate limited"))

    async def go():
        for prov, want in ((ok, 1), (sk, 2)):
            rep = Reputation(Settings(), providers=[prov])
            await rep.check_all([URL], {})
            await rep.check_all([URL], {})
            assert prov.n == want
    run(go())


def test_provider_failures_never_leak_the_key_and_do_not_break_other_providers():
    leaky = Counting(Settings(vt_key=KEY), exc=aiohttp.ClientError(f"GET https://x/?key={KEY} failed"))
    fine = Counting(Settings(), result=Finding("safebrowsing", "ok", "clean"))
    fine.name = "safebrowsing"

    async def go():
        return await Reputation(Settings(vt_key=KEY), providers=[leaky, fine]).check_all([URL], {})
    v = run(go())[URL]
    blob = v.to_json()
    assert KEY not in blob and "ClientError" in blob
    assert "safebrowsing" in v.checked and v.level == "ok"


def test_keys_in_provider_text_are_scrubbed():
    p = Counting(Settings(), result=Finding("virustotal", "warn", f"echoed {KEY} back"))
    v = run(Reputation(Settings(vt_key=KEY), providers=[p]).check_all([URL], {}))[URL]
    assert KEY not in v.to_json() and "***" in v.to_json()


# ---- gating in Manager.create ----------------------------------------------------------------
FAKE_CF = os.path.join(os.path.dirname(__file__), "fake_cloudflared.py")


def make_manager(settings, finding):
    p = Counting(settings, result=finding)
    store = Store()
    m = Manager(store, lambda port: [sys.executable, FAKE_CF, "tunnel", "--url", f"http://127.0.0.1:{port}"],
                scanner=noscan, settings=settings, reputation=Reputation(settings, providers=[p]))
    return m, store


def spec():
    return LinkSpec(mode="plain", variants=[Variant("A", URL)])


def test_blocked_target_creates_nothing_but_force_overrides():
    async def go():
        m, store = make_manager(Settings(), Finding("virustotal", "block", "5 家引擎判惡意"))
        with pytest.raises(BlockedError, match="5 家引擎判惡意"):
            await m.create(spec(), ttl_s=60)
        assert store.list_links() == [] and m._rt == {}
        link = await m.create(spec(), ttl_s=60, force=True)
        assert link.status == "live"
        await m.shutdown()
        m2, store2 = make_manager(Settings(block_on_malicious=False), Finding("virustotal", "block", "x"))
        assert (await m2.create(spec(), ttl_s=60)).status == "live"
        await m2.shutdown()
    run(go())


def test_warn_does_not_block_and_verdict_is_stored():
    async def go():
        m, store = make_manager(Settings(), Finding("virustotal", "warn", "1 家可疑"))
        link = await m.create(spec(), ttl_s=60)
        v = Verdict.from_json(__import__("json").dumps(__import__("json").loads(link.verdict)[URL]))
        assert v.level == "warn" and "virustotal" in v.checked
        await m.shutdown()
    run(go())


# ---- settings --------------------------------------------------------------------------------
def test_settings_file_is_private_roundtrips_and_env_overrides(tmp_path):
    p = tmp_path / "zinc" / "config.json"
    save_settings(Settings(vt_key=KEY, blocklist=["evil.example"], vt_malicious_block=5), p)
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    got = load_settings(p, env={})
    assert (got.vt_key, got.blocklist, got.vt_malicious_block) == (KEY, ["evil.example"], 5)
    assert load_settings(p, env={"ZINC_VT_KEY": "from-env"}).vt_key == "from-env"
    p.write_text('{"vt_key": "x", "bogus": 1}')
    assert load_settings(p, env={}).vt_key == "x"
    p.write_text("not json")
    assert load_settings(p, env={}).vt_key == ""


def test_mask_and_scrub():
    assert KEY not in mask(KEY) and mask(KEY).startswith(KEY[:4]) and mask("") != ""
    assert scrub(f"a {KEY} b {KEY}", [KEY, ""]) == "a *** b ***"


# ---- visitor page line -----------------------------------------------------------------------
def card(verdict):
    return pages.preview_card(None, URL, False, verdict)


def test_safety_line_is_honest_and_escaped():
    assert "🛡" not in card(None) and "⚠️" not in card(None)
    local_only = aggregate([Finding("local", "ok", "基礎檢查通過")], 0)
    assert "🛡" not in card(local_only)                       # nothing external answered: claim nothing
    checked = aggregate([Finding("local", "ok", "x"), Finding("virustotal", "ok", "0"),
                         Finding("safebrowsing", "ok", "0")], 0)
    assert "已檢查：Google Safe Browsing、VirusTotal・未發現威脅" in card(checked)
    warn = aggregate([Finding("local", "warn", "<b>x</b>")], 0)
    assert "⚠️ 注意" in card(warn) and "<b>x</b>" not in card(warn)
    blk = aggregate([Finding("local", "warn", "w"), Finding("urlhaus", "block", "bad")], 0)
    assert "掃描判定有風險：bad" in card(blk)
