import asyncio

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from zinc.locale import (candidate_locales, finalize_url, match_hreflang, parse_accept_language)
from zinc.scan import (SafeResolver, ScanResult, dump_scans, ip_is_public, literal_host_blocked,
                       load_scans, parse_html, scan_url, MAX_BYTES)


def run(coro):
    return asyncio.run(coro)


# ---- SSRF guards -----------------------------------------------------------------------------
@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "93.184.216.34"])
def test_public_ips(ip):
    assert ip_is_public(ip)


@pytest.mark.parametrize("ip", ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "172.16.0.1",
                                "100.64.0.1", "::1", "fe80::1", "fc00::1", "0.0.0.0", "::ffff:10.0.0.1",
                                "::ffff:127.0.0.1", "224.0.0.1", "240.0.0.1", "not-an-ip", ""])
def test_non_public_ips_are_refused(ip):
    assert not ip_is_public(ip)


@pytest.mark.parametrize("ip", ["64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1",
                                "fec0::1", "feff::1"])
def test_ipv6_wrappers_around_private_addresses_are_refused(ip):
    """NAT64 (64:ff9b::/96 = 127.0.0.1, 10.0.0.1, 169.254.169.254...) and deprecated site-local space."""
    assert not ip_is_public(ip)


def test_nat64_around_a_public_address_is_still_public():
    assert ip_is_public("64:ff9b::808:808")                 # 8.8.8.8 through a NAT64 gateway


@pytest.mark.parametrize("host,blocked", [("localhost", True), ("LOCALHOST", True), ("a.localhost", True),
                                          ("printer.local", True), ("db.internal", True), ("127.0.0.1", True),
                                          ("[::1]", True), ("169.254.169.254", True), ("10.1.2.3", True),
                                          ("8.8.8.8", False), ("example.com", False), ("localhost.example.com", False)])
def test_literal_host_blocklist(host, blocked):
    assert literal_host_blocked(host) is blocked


def test_resolver_refuses_names_that_resolve_to_private_addresses():
    async def go():
        with pytest.raises(OSError, match="non-public"):
            await SafeResolver().resolve("localhost", 80)
    run(go())


def test_scan_refuses_loopback_and_bad_schemes_without_connecting():
    async def go():
        for url, needle in (("http://127.0.0.1:9/", "blocked"), ("http://[::1]/", "blocked"),
                            ("http://localhost/", "blocked"), ("ftp://example.com/", "not an http"),
                            ("javascript:alert(1)", "not an http"), ("http:///nohost", "not an http")):
            r = await scan_url(url)
            assert not r.ok and needle in r.error and r.status is None, url
    run(go())


# ---- HTML extraction -------------------------------------------------------------------------
def test_parse_html_prefers_og_normalises_and_absolutises():
    html = """<html lang="en-GB"><head><title>  Plain
        Title </title><meta property="og:title" content="OG   Title"><meta name="description" content="d1">
        <meta property="og:description" content="og desc"><link rel="shortcut icon" href="/f.ico">
        <link rel="alternate" hreflang="ZH-Hant-TW" href="/tw/"><link rel="alternate" hreflang="ja" href="javascript:x">
        <link rel="alternate" hreflang="fr" href="https://fr.example/">
        <link rel="alternate" href="/no-hreflang/"></head></html>"""
    r = parse_html(html, "https://site.example/a/b")
    assert r["title"] == "OG Title" and r["description"] == "og desc" and r["html_lang"] == "en-GB"
    assert r["favicon"] == "https://site.example/f.ico"
    assert r["hreflang"] == {"zh-hant-tw": "https://site.example/tw/", "fr": "https://fr.example/"}


def test_parse_html_fallbacks_and_hostile_input():
    r = parse_html("<title>T</title>", "https://x.example/p")
    assert (r["title"], r["description"], r["favicon"]) == ("T", "", "https://x.example/favicon.ico")
    assert parse_html("<link rel=icon href='javascript:evil()'>", "https://x.example/")["favicon"] == ""
    assert len(parse_html("<title>" + "x" * 5000 + "</title>", "https://x.example/")["title"]) <= 200
    for junk in ("", "<<<>>>", "<title", "<meta name=description content=", "\x00\x01<title>ok</title>"):
        parse_html(junk, "https://x.example/")      # must never raise


# ---- scanning a real local page --------------------------------------------------------------
def test_scan_follows_redirects_reports_the_chain_and_limits_hops():
    async def go():
        app = web.Application()

        async def page(r):
            return web.Response(text="<title>Home</title><link rel=alternate hreflang=ja href=/ja>", content_type="text/html")

        async def hop(r):
            n = int(r.match_info["n"])
            raise web.HTTPFound(f"/hop/{n + 1}" if n < 9 else "/")
        app.router.add_get("/", page)
        async def r1(r):
            raise web.HTTPFound("/r2")

        async def r2(r):
            raise web.HTTPFound("/")
        app.router.add_get("/r1", r1)
        app.router.add_get("/r2", r2)
        app.router.add_get("/hop/{n}", hop)
        async def gone(r):
            return web.Response(status=404, text="<title>nope</title>", content_type="text/html")
        app.router.add_get("/gone", gone)
        srv = TestServer(app)
        await srv.start_server()
        try:
            base = str(srv.make_url("")).rstrip("/")
            ok = await scan_url(base + "/r1", allow_private=True)
            assert ok.ok and ok.status == 200 and len(ok.chain) == 3 and ok.title == "Home"
            assert ok.hreflang == {"ja": base + "/ja"} and ok.final_url == base + "/" and not ok.https
            loop = await scan_url(base + "/hop/0", allow_private=True)
            assert not loop.ok and "too many redirects" in loop.error
            gone = await scan_url(base + "/gone", allow_private=True)
            assert gone.status == 404 and not gone.ok and gone.title == "nope"
        finally:
            await srv.close()
    run(go())


def test_scan_reads_at_most_the_byte_cap():
    async def go():
        app = web.Application()
        big = "<title>early</title>" + "x" * (MAX_BYTES + 5000) + "<link rel=alternate hreflang=de href=/de>"
        async def huge(r):
            return web.Response(text=big, content_type="text/html")
        app.router.add_get("/", huge)
        srv = TestServer(app)
        await srv.start_server()
        try:
            r = await scan_url(str(srv.make_url("/")), allow_private=True)
            assert r.title == "early" and r.hreflang == {}          # tag beyond the cap is never read
        finally:
            await srv.close()
    run(go())


def test_scan_unreachable_host_reports_an_error_not_an_exception():
    r = run(scan_url("http://127.0.0.1:1/", allow_private=True))
    assert not r.ok and r.error and r.status is None


def test_scan_cache_roundtrip_and_corruption_tolerance():
    s = {"https://a.example/": ScanResult(url="https://a.example/", ok=True, title="T", hreflang={"ja": "https://j/"})}
    assert load_scans(dump_scans(s)) == s
    for bad in (None, "", "not json", '{"u": {"nope": 1}}', "[1,2]"):
        assert load_scans(bad) == {}


# ---- locale ----------------------------------------------------------------------------------
def test_accept_language_parsing():
    assert parse_accept_language("zh-TW,zh;q=0.9,en;q=0.8") == ["zh-TW", "zh", "en"]
    assert parse_accept_language("en;q=0.5, fr;q=0.9, de") == ["de", "fr", "en"]
    assert parse_accept_language("en;q=0, fr, *;q=0.1") == ["fr"]
    assert parse_accept_language("en;q=oops, fr") == ["fr"] and parse_accept_language("") == []


def test_candidate_locales_refine_bare_zh_and_fall_back_to_country():
    assert candidate_locales("zh,en;q=0.5", "TW") == ["zh-TW", "zh", "en"]
    assert candidate_locales("zh", "CN")[0] == "zh-CN" and candidate_locales("zh", "DE") == ["zh"]
    assert candidate_locales("", "JP") == ["ja"] and candidate_locales("", "XX") == [] and candidate_locales("", None) == []
    assert candidate_locales("EN-us,en-US", None) == ["EN-us"]            # case-insensitive de-dup


def test_hreflang_matching_exact_alias_bare_and_unsafe():
    h = {"zh-hant-tw": "https://x/tw", "ja": "https://x/ja", "fr-ca": "https://x/frca", "de": "javascript:alert(1)"}
    assert match_hreflang(["zh-TW"], h) == ("zh-hant-tw", "https://x/tw")
    assert match_hreflang(["ja-JP"], h) == ("ja", "https://x/ja")            # bare language fallback
    assert match_hreflang(["fr-CA", "fr"], h) == ("fr-ca", "https://x/frca")
    assert match_hreflang(["de"], h) is None                                 # unsafe scheme ignored
    assert match_hreflang(["ko"], h) is None and match_hreflang([], h) is None
    assert match_hreflang(["zh-CN"], {"zh-hant": "https://x/t"}) is None      # traditional page != zh-CN


def fin(url, lang="zh-TW", country="TW", scans=None, on=True):
    return finalize_url(url, auto_locale=on, accept_language=lang, country=country, scans=scans or {})


@pytest.mark.parametrize("url,expect", [
    ("https://www.google.com/", "https://www.google.com/?hl=zh-TW"),
    ("https://www.google.com/search?q=cats&hl=en", None),                      # rewritten, checked below
    ("https://www.youtube.com/", "https://www.youtube.com/?hl=zh-TW"),
    ("https://www.microsoft.com/", "https://www.microsoft.com/zh-tw/"),
    ("https://www.microsoft.com/en-us/windows", "https://www.microsoft.com/zh-tw/windows"),
    ("https://www.microsoft.com/foo/bar", "https://www.microsoft.com/foo/bar"),    # deep path: do not guess
    ("https://wikipedia.org/", "https://zh.wikipedia.org/"),
    ("https://en.wikipedia.org/wiki/Cat", "https://en.wikipedia.org/wiki/Cat"),    # titles differ per language
    ("https://www.apple.com/", "https://www.apple.com/tw/"),
    ("https://unknown.example/", "https://unknown.example/"),
    ("https://notgoogle.com/", "https://notgoogle.com/"), ("https://google.com.evil.example/", "https://google.com.evil.example/"),
])
def test_builtin_rules(url, expect):
    got, why = fin(url)
    if expect is None:
        assert got.count("hl=") == 1 and "hl=zh-TW" in got and "q=cats" in got
    else:
        assert got == expect and ((why is None) == (got == url))


def test_off_switch_no_candidates_and_us_apple_leave_url_untouched():
    assert fin("https://www.google.com/", on=False) == ("https://www.google.com/", None)
    assert fin("https://www.google.com/", lang="", country=None) == ("https://www.google.com/", None)
    assert fin("https://www.apple.com/", lang="en-US", country="US") == ("https://www.apple.com/", None)
    assert fin("ftp://x.example/") == ("ftp://x.example/", None)


def test_scanned_hreflang_beats_the_rule_table():
    scan = ScanResult(url="https://www.google.com/", ok=True, hreflang={"zh-hant-tw": "https://www.google.com.tw/"})
    got, why = fin("https://www.google.com/", scans={"https://www.google.com/": scan})
    assert got == "https://www.google.com.tw/" and why == "hreflang:zh-hant-tw"
    miss = ScanResult(url="https://www.google.com/", ok=True, hreflang={"fr": "https://www.google.fr/"})
    assert fin("https://www.google.com/", scans={"https://www.google.com/": miss})[1] == "rule:zh-TW"
