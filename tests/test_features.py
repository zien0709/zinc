"""Password gate, pass limits, start time, language/device rules, bilingual pages, spec validation."""
import json
import re

import pytest

from tests.test_server import A, B, NOW, V, client, hdr, run
from tests.test_settings_wiring import gets, serve
from zinc import pages
from zinc.config import Settings
from zinc.geo import Geo
from zinc.i18n import LANGS, STR, epitaphs, pick_lang, tr
from zinc.models import GeoRule, LinkSpec, RouteRule, Variant, validate_spec
from zinc.resolver import detect_device, select_group
from zinc.secret import check_password, hash_password, is_hash
from zinc.server import make_app
from zinc.store import Store

CJK = re.compile(r"[㐀-鿿]")
PW = "open sesame"


def locked_spec(mode="plain", **kw):
    return LinkSpec(mode=mode, variants=[V("A", "https://secret-target.example/")],
                    message="hi" if mode == "note" else "", pw_hash=hash_password(PW, iterations=1000), **kw)


def posts(app, path, *bodies, headers=None):
    """POST several bodies to ONE app in one event loop. A body of ("raw", text) is sent as-is."""
    async def go():
        out = []
        async with client(app) as c:
            for body in bodies:
                data = body[1] if isinstance(body, tuple) else json.dumps(body)
                r = await c.post(path, data=data, headers={**(headers or hdr()), "Content-Type": "application/json"},
                                 allow_redirects=False)
                out.append((r.status, await r.text()))
        return out
    return run(go())


def post(app, path, body, headers=None):
    return posts(app, path, body, headers=headers)[0]


# ---- password hashing -------------------------------------------------------------------------
def test_password_hash_is_salted_slow_and_checks_in_constant_time_form():
    h1, h2 = hash_password("pw"), hash_password("pw")
    assert h1 != h2 and is_hash(h1) and "pw" not in h1.split("$")[3]
    assert check_password("pw", h1) and check_password("pw", h2)
    assert not check_password("pW", h1) and not check_password("", h1) and not check_password("pw ", h1)
    assert h1.split("$")[1] == "120000"


@pytest.mark.parametrize("bad", ["", "pw", "pbkdf2$x$00$00", "pbkdf2$1000$zz$00", "md5$1$00$00", "pbkdf2$0$00$00",
                                 "pbkdf2$99999999999$00$00", "a$b"])
def test_malformed_stored_hashes_never_match_and_never_raise(bad):
    assert not is_hash(bad) and check_password("pw", bad) is False


# ---- the gate ----------------------------------------------------------------------------------
def test_locked_page_reveals_nothing_counts_nothing_and_allows_fetch_only_for_itself():
    store, link, app = serve(locked_spec())
    (status, headers, body), = gets(app, (f"/{link.token}", None))
    assert status == 200 and "secret-target" not in body and 'type="password"' in body
    assert "connect-src 'self'" in headers["Content-Security-Policy"] and "form-action 'none'" in headers["Content-Security-Policy"]
    s = store.stats(link.id)
    assert (s["opens"], s["passes"]) == (0, 0)
    store, link, app = serve(LinkSpec(mode="plain", variants=[V("A", A)]))                 # an ordinary page has no connect-src
    assert "connect-src" not in gets(app, (f"/{link.token}", None))[0][1]["Content-Security-Policy"]


def test_wrong_password_is_refused_and_right_one_opens_the_door_for_that_visitor_only():
    store, link, app = serve(locked_spec())
    path = f"/{link.token}"

    async def go():
        async with client(app) as c:
            async def unlock(pw, ip="1.1.1.1"):
                r = await c.post(f"{path}/unlock", json={"p": pw}, headers=hdr(ip))
                return r.status, await r.json()
            assert await unlock("nope") == (401, {"ok": False})
            assert (await c.get(path, headers=hdr(), allow_redirects=False)).status == 200       # still the lock page
            assert (await c.get(f"{path}/go", headers=hdr(), allow_redirects=False)).headers["Location"] == path
            assert await unlock(PW) == (200, {"ok": True})
            r = await c.get(path, headers=hdr(), allow_redirects=False)
            assert r.status == 302 and r.headers["Location"] == "https://secret-target.example/"
            other = await c.get(path, headers=hdr("2.2.2.2"), allow_redirects=False)            # someone else is still locked
            assert other.status == 200 and "secret-target" not in await other.text()
    run(go())
    s = store.stats(link.id)
    assert (s["opens"], s["passes"], s["uniques"]) == (1, 1, 1)


def test_guessing_is_throttled_per_visitor_and_per_link_and_recovers_after_a_minute():
    t = [NOW]
    store, link, app = serve(locked_spec(), Settings(unlock_tries=3), clock=lambda: t[0])
    path = f"/{link.token}/unlock"

    async def go():
        async with client(app) as c:
            async def unlock(pw, ip="1.1.1.1"):
                return (await c.post(path, json={"p": pw}, headers=hdr(ip))).status
            assert [await unlock("x") for _ in range(3)] == [401, 401, 401]
            assert await unlock(PW) == 429                       # even the right password: the guess budget is spent
            assert await unlock(PW, "2.2.2.2") == 200            # another visitor has their own budget
            t[0] += 61
            assert await unlock(PW) == 200                       # a minute later it is allowed again
            for i in range(40):                                   # many visitors together hit the per-link cap
                await unlock("x", f"9.9.{i}.1")
            assert await unlock("x", "8.8.8.8") == 429
    run(go())


def test_malformed_unlock_requests_are_rejected_without_counting_as_a_guess():
    store, link, app = serve(locked_spec(), Settings(unlock_tries=2))
    path = f"/{link.token}/unlock"
    bad = [("raw", "not json"), {"p": 123}, {"q": "x"}, ["x"], {"p": "x" * 201}]
    got = posts(app, path, *bad, {"p": "wrong"}, {"p": "wrong"}, {"p": PW})
    assert [g[0] for g in got] == [400] * 5 + [401, 401, 429]          # the 400s used none of the 2-guess budget


def test_unlock_endpoint_is_invisible_on_links_without_a_password_and_for_wrong_tokens():
    store, link, app = serve(LinkSpec(mode="plain", variants=[V("A", A)]))
    assert post(app, f"/{link.token}/unlock", {"p": "x"})[0] == 404
    store, link, app = serve(locked_spec())
    assert post(app, f"/wrongtoken/unlock", {"p": "x"})[0] == 404


def test_bots_and_curl_never_see_the_password_page_content():
    store, link, app = serve(locked_spec(), Settings(bot_response="card"))
    (st, _, body), (_, _, curl_body) = gets(app, (f"/{link.token}", hdr(ua="Slackbot-LinkExpanding 1.0")),
                                            (f"/{link.token}", hdr("2.2.2.2", ua="curl/8.0")))
    assert st == 200 and "secret-target" not in body and 'type="password"' not in body
    assert "locked" in curl_body and "secret-target" not in curl_body
    assert store.stats(link.id)["opens"] == 0


def test_a_locked_link_that_is_dead_says_so_instead_of_asking_for_a_password():
    store, link, app = serve(locked_spec(), ttl=60, clock=lambda: NOW + 61)
    (st, _, body), = gets(app, (f"/{link.token}", None))
    assert st == 410 and "password" not in body.lower()
    store, link, app = serve(locked_spec(), ttl=60, clock=lambda: NOW + 61)
    assert post(app, f"/{link.token}/unlock", {"p": PW})[0] == 410


def test_password_is_not_stored_in_clear_anywhere():
    store, link, app = serve(locked_spec())
    raw = store._db.execute("SELECT spec FROM links").fetchone()[0]
    assert PW not in raw and "pbkdf2$" in raw


def test_gate_works_in_every_mode_before_anything_about_the_target_is_shown():
    for mode in ("note", "count", "box", "door"):
        spec = locked_spec(mode)
        if mode == "door":
            spec.variants = [V("A", "https://secret-target.example/"), V("B", B)]
        store, link, app = serve(spec)
        (st, _, body), = gets(app, (f"/{link.token}", None))
        assert st == 200 and 'type="password"' in body and "secret-target" not in body and "🎁" not in body, mode


# ---- one-time links ---------------------------------------------------------------------------
def test_max_passes_lets_only_the_first_n_through_then_the_link_dies():
    events = []
    spec = LinkSpec(mode="plain", variants=[V("A", A)], max_passes=2)
    store = Store()
    link = store.create_link(spec, ttl_s=600, max_opens=None, now=NOW)
    store.set_status(link.id, "live")
    app = make_app(store, link.id, clock=lambda: NOW, emit=lambda e, d: events.append((e, d)))
    out = gets(app, *[(f"/{link.token}", hdr(f"7.7.7.{i}")) for i in (1, 2, 3, 4)])
    assert [o[0] for o in out] == [302, 302, 410, 410]
    assert store.stats(link.id)["passes"] == 2 and store.get_link(link.id).status == "soft_dead"
    assert [d.get("reason") for e, d in events if e == "dead"] == ["passes"]         # announced exactly once


def test_one_time_link_in_a_gate_mode_the_second_person_loses_the_race_at_go():
    spec = LinkSpec(mode="note", message="hi", variants=[V("A", A)], max_passes=1)
    store, link, app = serve(spec)
    path = f"/{link.token}"

    async def go():
        async with client(app) as c:
            for ip in ("1.1.1.1", "2.2.2.2"):
                assert (await c.get(path, headers=hdr(ip), allow_redirects=False)).status == 200
            assert (await c.get(f"{path}/go", headers=hdr("1.1.1.1"), allow_redirects=False)).status == 302
            late = await c.get(f"{path}/go", headers=hdr("2.2.2.2"), allow_redirects=False)
            assert late.status == 410
    run(go())
    assert store.stats(link.id)["passes"] == 1


def test_the_last_allowed_pass_kills_the_link_immediately_and_tells_the_host_once():
    """Not lazily at the next visitor: the host should see it die the moment the last person goes through."""
    events = []
    spec = LinkSpec(mode="plain", variants=[V("A", A)], max_passes=1)
    store = Store()
    link = store.create_link(spec, ttl_s=600, max_opens=None, now=NOW)
    store.set_status(link.id, "live")
    app = make_app(store, link.id, clock=lambda: NOW, emit=lambda e, d: events.append((e, d)))
    assert gets(app, (f"/{link.token}", hdr("7.7.7.1")))[0][0] == 302
    assert store.get_link(link.id).status == "soft_dead"                 # no second request was needed
    assert [d.get("reason") for e, d in events if e == "dead"] == ["passes"]


def test_zero_max_passes_means_unlimited():
    store, link, app = serve(LinkSpec(mode="plain", variants=[V("A", A)], max_passes=0))
    assert [o[0] for o in gets(app, *[(f"/{link.token}", hdr(f"7.7.7.{i}")) for i in range(1, 8)])] == [302] * 7


# ---- start time -------------------------------------------------------------------------------
def test_link_is_not_open_before_its_start_time_and_nothing_is_counted():
    t = [NOW]
    spec = LinkSpec(mode="plain", variants=[V("A", "https://secret-target.example/")], starts_at=NOW + 3600)
    store, link, app = serve(spec, clock=lambda: t[0], ttl=7200)
    path = f"/{link.token}"

    async def go():
        async with client(app) as c:
            early = await c.get(path, headers=hdr(), allow_redirects=False)
            early_go = await c.get(f"{path}/go", headers=hdr(), allow_redirects=False)
            t[0] = NOW + 3601
            late = await c.get(path, headers=hdr(), allow_redirects=False)
            return early.status, dict(early.headers), await early.text(), early_go.status, late.status
    st, headers, body, st2, late = run(go())
    assert st == 503 and headers["Retry-After"] == "3600" and "secret-target" not in body
    assert "<time datetime=" in body and "UTC" in body and f'data-starts="{int((NOW + 3600) * 1000)}"' in body
    assert st2 == 302 and late == 302
    assert store.stats(link.id)["opens"] == 1                       # only the visit after the start counted


# ---- language / device routing -------------------------------------------------------------------
@pytest.mark.parametrize("ua,device", [
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit Mobile/15E148", "ios"),
    ("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)", "ios"),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/120 Mobile Safari/537.36", "android"),
    ("Mozilla/5.0 (Linux; Android 13; SM-X700) Chrome/120 Safari/537.36", "android"),
    ("Mozilla/5.0 (Windows Phone 10.0) Mobile", "mobile"), ("Opera/9.80 (J2ME/MIDP; Opera Mini/9)", "mobile"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120", "desktop"), ("", "desktop"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605", "desktop")])
def test_device_detection(ua, device):
    assert detect_device(ua) == device


def rules_spec(*rules, geo=()):
    return LinkSpec(mode="plain", variants=[V("D", "https://d.example/")],
                    geo_rules=[GeoRule(m, [V(n, u)]) for m, n, u in geo],
                    route_rules=[RouteRule(k, m, [V(n, u)]) for k, m, n, u in rules])


TW = Geo("TW", "asia")


def test_language_rules_follow_the_visitors_own_preference_order_exact_before_bare():
    spec = rules_spec(("lang", "zh", "ZH", "https://zh.example/"), ("lang", "zh-tw", "TW", "https://tw.example/"),
                      ("lang", "ja", "JA", "https://ja.example/"))
    name = lambda tags: select_group(spec, Geo(None, None), lang_tags=tags)[1][0].name  # noqa: E731
    assert name(["zh-tw", "en"]) == "TW"                  # exact beats bare
    assert name(["zh-cn"]) == "ZH"                        # bare language catches the rest
    assert name(["en", "ja"]) == "JA"                     # first language that has a rule
    assert name(["ja", "zh-tw"]) == "JA"                  # the visitor's own order decides, not the rule list
    assert name(["fr"]) == "D" and name([]) == "D"
    assert select_group(spec, Geo(None, None), lang_tags=["ja"])[0] == "lang:ja"


def test_device_rules_use_spec_order_and_mobile_covers_ios_and_android():
    spec = rules_spec(("device", "ios", "IOS", "https://ios.example/"), ("device", "mobile", "MOB", "https://m.example/"),
                      ("device", "desktop", "DESK", "https://pc.example/"))
    name = lambda dev: select_group(spec, Geo(None, None), device=dev)[1][0].name  # noqa: E731
    assert (name("ios"), name("android"), name("mobile"), name("desktop")) == ("IOS", "MOB", "MOB", "DESK")
    flipped = rules_spec(("device", "mobile", "MOB", "https://m.example/"), ("device", "ios", "IOS", "https://ios.example/"))
    assert select_group(flipped, Geo(None, None), device="ios")[1][0].name == "MOB"        # first match wins


def test_rule_order_decides_who_wins_and_unlisted_kinds_are_ignored():
    spec = rules_spec(("lang", "ja", "JA", "https://ja.example/"), ("device", "ios", "IOS", "https://ios.example/"),
                      geo=[("TW", "GEO", "https://tw.example/")])
    pick = lambda order: select_group(spec, TW, lang_tags=["ja"], device="ios", order=order)[1][0].name  # noqa: E731
    assert pick(["geo", "lang", "device"]) == "GEO"
    assert pick(["device", "geo", "lang"]) == "IOS"
    assert pick(["lang", "device", "geo"]) == "JA"
    assert pick(["lang"]) == "JA" and pick(["device"]) == "IOS" and pick(["geo"]) == "GEO"
    assert pick([]) == "D"                                # nothing enabled: the default group


def test_the_server_applies_language_device_rules_and_the_rule_order_setting():
    spec = rules_spec(("lang", "ja", "JA", "https://ja.example/"), ("device", "ios", "IOS", "https://ios.example/"),
                      geo=[("TW", "GEO", "https://tw.example/")])
    ios_ja_tw = hdr(country="TW", lang="ja,en;q=0.5", ua="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)")
    for order, want in ((["geo", "lang", "device"], "tw"), (["device", "lang", "geo"], "ios"), (["lang", "geo"], "ja")):
        store, link, app = serve(spec, Settings(rule_order=order))
        assert gets(app, (f"/{link.token}", ios_ja_tw))[0][1]["Location"] == f"https://{want}.example/", order
    store, link, app = serve(spec, Settings(rule_order=["geo", "lang", "device"]),)
    store2, link2, app2 = serve(LinkSpec(**{**spec.__dict__, "options": {"rule_order": ["device"]}}), Settings())  # per link
    assert gets(app2, (f"/{link2.token}", ios_ja_tw))[0][1]["Location"] == "https://ios.example/"
    assert store2.stats(link2.id)["by_variant"] == {"IOS": 1}


# ---- bilingual pages -------------------------------------------------------------------------------
def test_both_languages_have_the_same_keys_and_the_same_placeholders():
    zh, en = STR["zh-Hant"], STR["en"]
    assert set(zh) == set(en) and len(epitaphs("zh-Hant")) == len(epitaphs("en"))
    for key in zh:
        if key == "epitaphs":
            continue
        ph = lambda text: sorted(re.findall(r"\{(\w+)\}", text))  # noqa: E731
        if key in ("risky", "caution"):          # English deliberately drops the host-side (Chinese) finding text
            assert ph(zh[key]) == ["text"] and ph(en[key]) == [], key
        else:
            assert ph(zh[key]) == ph(en[key]), key
        assert CJK.search(zh[key]) or key in ("https_ok", "hops"), key             # zh really is Chinese...
        assert not CJK.search(en[key]), key                                         # ...and en really is not


@pytest.mark.parametrize("setting,header,want", [
    ("auto", "en-US,en;q=0.9", "en"), ("auto", "zh-TW,zh;q=0.9,en;q=0.5", "zh-Hant"), ("auto", "ja", "en"),
    ("auto", "", "zh-Hant"), ("auto", "*", "zh-Hant"), ("en", "zh-TW", "en"), ("zh-Hant", "en", "zh-Hant")])
def test_language_choice(setting, header, want):
    assert pick_lang(setting, header) == want


def test_every_visitor_page_is_fully_english_for_english_visitors_and_chinese_for_chinese():
    o, n = Settings(), "nonce"
    en = {
        "note": pages.page_note(token="t", message="hello", card="", nonce=n, expires_ms=None, rank=3, o=o, lang="en"),
        "count": pages.page_count(token="t", rank=3, card="", nonce=n, expires_ms=None, o=o, lang="en"),
        "box": pages.page_box(token="t", nonce=n, expires_ms=None, o=o, lang="en"),
        "door": pages.page_door(token="t", count=3, nonce=n, expires_ms=None, o=o, lang="en"),
        "dead": pages.page_dead(link_id="x", lived_s=130, opens=4, nonce=n, o=o, lang="en"),
        "trap": pages.page_dead(link_id="x", lived_s=5, opens=4, nonce=n, o=o, trap=True, lang="en"),
        "paused": pages.page_paused(n, o, "en"), "locked": pages.page_locked(token="t", nonce=n, o=o, lang="en"),
        "waiting": pages.page_waiting(starts_at=NOW, nonce=n, o=o, lang="en"), "bot": pages.page_bot("en"),
    }
    for name, body in en.items():
        visible = re.sub(r"<script.*?</script>|<style.*?</style>", "", body, flags=re.S)
        assert not CJK.search(visible), (name, CJK.findall(visible)[:5])
        assert 'lang="en"' in body
    assert "Lived 2 min" in en["dead"] and "opened 4 times" in en["dead"] and "Lived 5 s" in en["trap"]
    zh = pages.page_dead(link_id="x", lived_s=130, opens=4, nonce=n, o=o)
    assert 'lang="zh-Hant"' in zh and "存活 2 分鐘" in zh


def test_the_english_safety_line_never_shows_host_side_chinese_findings():
    from zinc.reputation import Finding, Verdict
    v = Verdict("block", [Finding("local", "block", "命中本地黑名單")], [], 0)
    assert "命中本地黑名單" in pages.safety_line(v) and not CJK.search(pages.safety_line(v, "en"))
    card = pages.preview_card(None, "https://x.example/", True, v, "en")
    assert not CJK.search(card) and "risky" in card


def test_the_server_picks_the_page_language_from_the_visitor_and_the_setting():
    spec = LinkSpec(mode="box", variants=[V("A", A)])
    store, link, app = serve(spec, Settings())
    en, zh, ja = gets(app, (f"/{link.token}", hdr(lang="en-US")), (f"/{link.token}", hdr("2.2.2.2", lang="zh-TW")),
                      (f"/{link.token}", hdr("3.3.3.3", lang="ja")))
    assert "Mystery box" in en[2] and "盲盒" in zh[2] and "Mystery box" in ja[2]
    store, link, app = serve(spec, Settings(language="zh-Hant"))
    assert "盲盒" in gets(app, (f"/{link.token}", hdr(lang="en-US")))[0][2]
    store, link, app = serve(LinkSpec(mode="box", variants=[V("A", A)], options={"language": "en"}), Settings())
    assert "Mystery box" in gets(app, (f"/{link.token}", hdr(lang="zh-TW")))[0][2]


# ---- decoy for everything unknown ------------------------------------------------------------------
def test_unknown_paths_and_methods_all_get_the_same_404_decoy():
    store, link, app = serve()

    async def go():
        async with client(app) as c:
            out = []
            for method, path in (("POST", "/"), ("PUT", f"/{link.token}"), ("DELETE", "/x"), ("POST", f"/{link.token}"),
                                 ("POST", "/a/b/c"), ("OPTIONS", "/"), ("POST", f"/{link.token}/go"), ("GET", "/x/unlock"),
                                 ("PATCH", f"/{link.token}/unlock")):
                r = await c.request(method, path, headers=hdr(), allow_redirects=False)
                out.append((method, path, r.status, (await r.text()) if method != "HEAD" else ""))
            return out
    for method, path, status, body in run(go()):
        assert status == 404 and "page not found" in body, (method, path, status)


# ---- spec validation -------------------------------------------------------------------------------
def base_spec(**kw):
    return LinkSpec(mode="plain", variants=[V("A", A)], **kw)


@pytest.mark.parametrize("kw,needle", [
    ({"label": "x" * 41}, "名稱"), ({"label": "a\nb"}, "名稱"), ({"pw_hash": "plaintext"}, "雜湊"),
    ({"max_passes": -1}, "通關上限"), ({"max_passes": 1_000_001}, "通關上限"), ({"max_passes": True}, "通關上限"),
    ({"max_passes": 1.5}, "通關上限"), ({"starts_at": -1}, "開放時間"), ({"starts_at": True}, "開放時間"),
    ({"route_rules": [RouteRule("geo", "TW", [V("A", A)])]}, "lang 和 device"),
    ({"route_rules": [RouteRule("device", "toaster", [V("A", A)])]}, "裝置"),
    ({"route_rules": [RouteRule("lang", "not a tag!", [V("A", A)])]}, "語言"),
    ({"route_rules": [RouteRule("lang", "ja", [V("A", A)]), RouteRule("lang", "JA", [V("B", B)])]}, "重複"),
    ({"route_rules": [RouteRule("lang", "ja", [])]}, "variants"),
    ({"route_rules": [RouteRule("lang", "ja", [V("A", "ftp://x")])]}, "http"),
])
def test_bad_new_fields_are_rejected_in_plain_words(kw, needle):
    with pytest.raises(ValueError, match=needle):
        validate_spec(base_spec(**kw))


def test_good_new_fields_are_accepted_and_normalised_and_roundtrip_through_json():
    spec = base_spec(label="給小明", pw_hash=hash_password("x", iterations=1000), max_passes=3, starts_at=NOW,
                     route_rules=[RouteRule("lang", " ZH-TW ", [V("A", A)]), RouteRule("device", "iOS", [V("B", B)])])
    validate_spec(spec)
    assert [r.match for r in spec.route_rules] == ["zh-tw", "ios"]
    back = LinkSpec.from_json(spec.to_json())
    assert back == spec and back.label == "給小明" and back.max_passes == 3 and back.starts_at == NOW


def test_old_rows_without_the_new_fields_still_load_with_safe_defaults():
    old = json.dumps({"mode": "plain", "variants": [{"name": "A", "url": A, "weight": 1}], "geo_rules": []})
    spec = LinkSpec.from_json(old)
    assert (spec.label, spec.pw_hash, spec.max_passes, spec.starts_at, spec.route_rules) == ("", "", 0, 0.0, [])
    validate_spec(spec)


def test_route_rule_targets_are_scanned_and_counted_like_any_other_group():
    spec = base_spec(route_rules=[RouteRule("lang", "ja", [V("J", "https://ja.example/")])])
    assert [v.url for g in spec.groups() for v in g] == [A, "https://ja.example/"]


def test_a_door_link_needs_two_doors_in_rule_groups_too():
    spec = LinkSpec(mode="door", variants=[V("A", A), V("B", B)],
                    route_rules=[RouteRule("lang", "ja", [V("J", "https://ja.example/")])])
    with pytest.raises(ValueError, match="door"):
        validate_spec(spec)


# ---- vanity suffix rules -----------------------------------------------------------------------
def test_vanity_suffix_length_boundary_and_dot_segments():
    from zinc.models import validate_token
    validate_token("a" * 64)                                   # the longest allowed
    validate_token("今天不想上班")
    validate_token("")                                         # blank = random
    for bad in ("a" * 65, ".", "..", "a/b", "a?b", "a#b", "a%b", "a b"):
        with pytest.raises(ValueError):
            validate_token(bad)                                # browsers fold /.. into /, so it would never reach us


def test_quote_token_encodes_everything_that_could_break_a_url_path():
    from zinc.urlutil import quote_token
    assert quote_token("a/b?c#d e") == "a%2Fb%3Fc%23d%20e"
    assert quote_token("今天") == "%E4%BB%8A%E5%A4%A9"
    assert quote_token("Ab-_9") == "Ab-_9"
