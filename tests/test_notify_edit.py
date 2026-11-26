"""Webhooks (formats, signatures, privacy, reliability) and editing a live link."""
import asyncio
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from tests.test_server import A, B, NOW, V, client, hdr
from tests.test_tunnel_manager import fake_cmd, fetch, noscan, plain_spec, run
from zinc.config import Settings
from zinc.manager import BlockedError, Manager
from zinc.models import LinkSpec
from zinc.notify import Notifier, build_request, describe, verify_signature
from zinc.reputation import Finding, Provider, Reputation
from zinc.secret import hash_password
from zinc.store import Store

SECRET = "whsec-0123456789"


# ---- message building ---------------------------------------------------------------------------
DATA = {"link_id": "abcd1234", "label": "給小明", "mode": "note", "country": "TW", "host": "quiet-fox.trycloudflare.com"}


def body_of(fmt="json", event="open", data=DATA, **kw):
    s = Settings(webhook_format=fmt, **kw)
    raw, headers = build_request(event, data, s, 1_700_000_000.4)
    return json.loads(raw), raw, headers


def test_json_format_has_event_text_time_and_only_the_safe_fields():
    obj, raw, headers = body_of()
    assert obj["event"] == "open" and obj["ts"] == 1_700_000_000 and obj["country"] == "TW" and obj["label"] == "給小明"
    assert "有人打開了" in obj["text"] and headers["X-Zinc-Event"] == "open" and headers["Content-Type"] == "application/json"
    assert set(obj) <= {"event", "text", "ts", "link_id", "label", "mode", "country", "host", "variant", "reason"}
    assert "X-Zinc-Signature" not in headers                                      # no secret configured, no signature


def test_signature_verifies_only_for_the_exact_body_and_secret():
    _, raw, headers = body_of(webhook_secret=SECRET)
    sig = headers["X-Zinc-Signature"]
    assert sig.startswith("sha256=") and verify_signature(SECRET, raw, sig)
    assert not verify_signature(SECRET, raw + b" ", sig) and not verify_signature("other", raw, sig)
    assert not verify_signature(SECRET, raw, "") and not verify_signature(SECRET, raw, "sha256=" + "0" * 64)


def test_signature_is_only_for_the_json_format_and_the_secret_never_appears_in_any_body():
    for fmt in ("discord", "slack"):
        obj, raw, headers = body_of(fmt, webhook_secret=SECRET)
        assert "X-Zinc-Signature" not in headers and SECRET.encode() not in raw
    assert SECRET.encode() not in body_of(webhook_secret=SECRET)[1]


def test_discord_and_slack_get_chat_shaped_bodies_and_discord_cannot_ping_everyone():
    obj, _, _ = body_of("discord", data={**DATA, "label": "@everyone 快來"})
    assert set(obj) == {"content", "allowed_mentions"} and obj["allowed_mentions"] == {"parse": []}
    assert "@everyone" in obj["content"]                                          # shown as text, but pings nothing
    obj, _, _ = body_of("slack")
    assert set(obj) == {"text"} and "TW" in obj["text"]
    assert len(body_of("discord", data={**DATA, "label": "x" * 5000})[0]["content"]) <= 1900


def test_country_can_be_left_out_entirely():
    for fmt in ("json", "discord", "slack"):
        _, raw, _ = body_of(fmt, webhook_country=False)
        assert b"TW" not in raw and "country" not in raw.decode()


def test_messages_never_carry_ip_token_or_targets_even_if_a_caller_passes_them():
    leaky = {**DATA, "ip": "203.0.113.9", "token": "SECRET-TOKEN", "url": "https://target.example/", "vid": "VID-XYZ",
             "ua": "Mozilla/5.0 Secret", "variant": "A"}
    for fmt in ("json", "discord", "slack"):
        _, raw, _ = body_of(fmt, data=leaky)
        for needle in (b"203.0.113.9", b"SECRET-TOKEN", b"target.example", b"VID-XYZ", b"Secret"):
            assert needle not in raw, (fmt, needle)
    obj, _, _ = body_of(data=leaky)
    assert obj["variant"] == "A" and "ip" not in obj and "token" not in obj and "url" not in obj


@pytest.mark.parametrize("event,data,needle", [
    ("open", {"link_id": "abcd1234", "host": "x.trycloudflare.com"}, "x"),
    ("pass", {"link_id": "abcd1234", "variant": "B", "country": "JP"}, "→ B"),
    ("dead", {"link_id": "abcd1234", "reason": "passes"}, "名額用完"),
    ("dead", {"link_id": "abcd1234", "reason": "expired"}, "時間到"),
    ("weird", {"link_id": "abcd1234"}, "weird")])
def test_describe_each_event(event, data, needle):
    assert needle in describe(event, data)


# ---- sending ------------------------------------------------------------------------------------
class Receiver:
    def __init__(self, status=200, delay=0.0):
        self.got, self.status, self.delay = [], status, delay
        self.app = web.Application()
        self.app.router.add_post("/hook", self.handle)

    async def handle(self, request):
        if self.delay:
            await asyncio.sleep(self.delay)
        self.got.append((await request.read(), dict(request.headers)))
        return web.Response(status=self.status)


async def with_receiver(fn, **kw):
    rcv = Receiver(**kw)
    srv = TestServer(rcv.app)
    await srv.start_server()
    try:
        return await fn(rcv, f"http://localhost:{srv.port}/hook")
    finally:
        await srv.close()


def test_notifier_posts_only_wanted_events_and_does_nothing_without_a_url():
    async def go(rcv, url):
        n = Notifier(Settings(webhook_url=url, webhook_events=["open", "dead"], webhook_secret=SECRET))
        assert n.submit("open", DATA) and n.submit("dead", {**DATA, "reason": "expired"})
        assert not n.submit("pass", DATA)                                       # not subscribed
        await n.flush()
        await n.close()
        assert [json.loads(b)["event"] for b, _ in rcv.got] == ["open", "dead"] and n.sent == 2
        assert all(verify_signature(SECRET, b, h["X-Zinc-Signature"]) for b, h in rcv.got)
        silent = Notifier(Settings())
        assert not silent.submit("open", DATA) and silent._task is None
    run(with_receiver(go))


def test_submit_outside_an_event_loop_is_a_quiet_no_op():
    assert Notifier(Settings(webhook_url="https://example.com/h")).submit("open", DATA) is False


def test_a_failing_receiver_is_reported_without_ever_leaking_the_secret_url():
    secret_url = "https://discord.example/api/webhooks/123/TOP-SECRET-TOKEN"

    async def go():
        s = Settings(webhook_url=secret_url, webhook_timeout_s=1)
        n = Notifier(s)
        n.submit("open", DATA)
        await n.flush(5)
        await n.close()
        return n.last_error, n.sent
    err, sent = run(go())
    assert sent == 0 and err and "TOP-SECRET-TOKEN" not in err and "discord.example" not in err


@pytest.mark.parametrize("status", [400, 404, 500, 429])
def test_non_2xx_is_an_error_message_and_recovers_on_the_next_success(status):
    async def go(rcv, url):
        n = Notifier(Settings(webhook_url=url))
        n.submit("open", DATA)
        await n.flush()
        bad = n.last_error
        rcv.status = 204
        n.submit("open", DATA)
        await n.flush()
        await n.close()
        return bad, n.last_error, n.sent
    bad, after, sent = run(with_receiver(go, status=status))
    assert str(status) in bad and after == "" and sent == 1


def test_a_slow_receiver_times_out_without_blocking_the_caller():
    async def go(rcv, url):
        n = Notifier(Settings(webhook_url=url))
        n.s.__dict__["webhook_timeout_s"] = 0.2
        t0 = asyncio.get_running_loop().time()
        assert n.submit("open", DATA)
        assert asyncio.get_running_loop().time() - t0 < 0.05                      # submit itself never waits
        await n.flush(3)
        await n.close()
        return n.last_error
    assert "Timeout" in run(with_receiver(go, delay=1.0))


def test_a_flood_is_capped_per_minute_and_counted_as_dropped():
    t = [1000.0]

    async def go(rcv, url):
        n = Notifier(Settings(webhook_url=url, webhook_max_per_min=3), clock=lambda: t[0])
        results = [n.submit("open", DATA) for _ in range(6)]
        assert results == [True] * 3 + [False] * 3 and n.dropped == 3 and "略過 3 則" in n.last_error
        await n.flush()
        t[0] += 61
        assert n.submit("open", DATA)                                              # a minute later it works again
        await n.flush()
        await n.close()
        return len(rcv.got)
    assert run(with_receiver(go)) == 4


def test_queue_overflow_drops_instead_of_growing():
    async def go(rcv, url):
        n = Notifier(Settings(webhook_url=url, webhook_max_per_min=600))
        n.s.__dict__["webhook_timeout_s"] = 5
        ok = sum(n.submit("open", DATA) for _ in range(Notifier.MAX_QUEUE + 30))
        await n.close(0.1)
        return ok, n.dropped
    ok, dropped = run(with_receiver(go, delay=0.5))
    assert ok <= Notifier.MAX_QUEUE + 1 and dropped >= 29


def test_redirects_from_the_receiver_are_not_followed():
    async def go():
        app = web.Application()
        hits = []

        async def start(request):
            raise web.HTTPFound("/elsewhere")

        async def elsewhere(request):
            hits.append(1)
            return web.Response()
        app.router.add_post("/hook", start)
        app.router.add_post("/elsewhere", elsewhere)
        app.router.add_get("/elsewhere", elsewhere)
        srv = TestServer(app)
        await srv.start_server()
        try:
            n = Notifier(Settings(webhook_url=f"http://localhost:{srv.port}/hook"))
            n.submit("open", DATA)
            await n.flush()
            await n.close()
            return hits, n.last_error
        finally:
            await srv.close()
    hits, err = run(go())
    assert hits == [] and "302" in err


# ---- manager integration ---------------------------------------------------------------------------
def test_visitors_trigger_webhooks_and_the_receiver_sees_no_visitor_identity():
    async def go(rcv, url):
        s = Settings(webhook_url=url, webhook_events=["open", "pass", "dead"], webhook_secret=SECRET)
        m = Manager(Store(), fake_cmd, scanner=noscan, settings=s, tunnel_timeout=5)
        spec = LinkSpec(mode="plain", variants=[V("A", A)], label="給小明")
        link = await m.create(spec, ttl_s=600)
        h = {"CF-Connecting-IP": "203.0.113.77", "CF-IPCountry": "JP", "User-Agent": "Mozilla/5.0 Test"}
        import aiohttp
        async with aiohttp.ClientSession() as sess:
            for _ in range(3):                                                           # refreshing must not re-announce
                async with sess.get(f"http://127.0.0.1:{link.port}/{link.token}", headers=h, allow_redirects=False):
                    pass
        m.soft_destroy(link.id)
        await m.shutdown()
        return link, [(json.loads(b), hh) for b, hh in rcv.got], [b for b, _ in rcv.got]
    link, got, raw = run(with_receiver(go))
    events = [o["event"] for o, _ in got]
    assert events.count("open") == 1 and events.count("pass") == 3 and events[-1] == "dead"
    first = next(o for o, _ in got if o["event"] == "open")
    assert first["country"] == "JP" and first["host"] == link.hostname and first["label"] == "給小明"
    passed = next(o for o, _ in got if o["event"] == "pass")
    assert passed["variant"] == "A" and next(o for o, _ in got if o["event"] == "dead")["reason"] == "manual"
    blob = b"".join(raw)
    for needle in (b"a.example", b"203.0.113.77", link.token.encode(), b"Mozilla"):
        assert needle not in blob, needle


def test_expiry_and_full_links_announce_their_death_once_with_the_right_reason():
    async def go(rcv, url):
        t = [1_000_000.0]
        s = Settings(webhook_url=url, webhook_events=["dead"])
        m = Manager(Store(), fake_cmd, scanner=noscan, settings=s, clock=lambda: t[0], tunnel_timeout=5)
        link = await m.create(plain_spec(), ttl_s=60)
        t[0] += 61
        await m.tick()
        await m.tick()
        await asyncio.sleep(0.2)
        await m.shutdown()
        return [json.loads(b) for b, _ in rcv.got]
    got = run(with_receiver(go))
    assert [g["event"] for g in got] == ["dead"] and got[0]["reason"] == "expired"


def test_a_broken_webhook_shows_up_in_manager_errors_and_never_breaks_visitors():
    async def go():
        s = Settings(webhook_url="http://localhost:1/hook", webhook_events=["open", "pass"], webhook_timeout_s=1)
        m = Manager(Store(), fake_cmd, scanner=noscan, settings=s, tunnel_timeout=5)
        link = await m.create(plain_spec(), ttl_s=600)
        status, loc, _ = await fetch(link.port, f"/{link.token}")
        await m.notifier.flush(3)
        m._emit("open", {"link_id": link.id})                                           # surfaces the failure
        err = m.errors.get("_webhook", "")
        await m.shutdown()
        return status, loc, err
    status, loc, err = run(go())
    assert (status, loc) == (302, "https://a.example/") and "webhook" in err and "localhost:1" not in err


# ---- editing a live link ------------------------------------------------------------------------------
class Verdicts(Provider):
    name = "urlhaus"

    def __init__(self, s, bad=()):
        super().__init__(s)
        self.bad = set(bad)

    async def check(self, url, session):
        return Finding("urlhaus", "block" if url in self.bad else "ok", "bad" if url in self.bad else "clean")


def edit_mgr(bad=()):
    s = Settings()
    return Manager(Store(), fake_cmd, scanner=noscan, settings=s, tunnel_timeout=5,
                   reputation=Reputation(s, providers=[Verdicts(s, bad)]))


def test_editing_targets_keeps_the_url_the_token_and_the_stats_but_changes_behaviour_at_once():
    async def go():
        m = edit_mgr()
        link = await m.create(plain_spec(), ttl_s=600)
        assert (await fetch(link.port, f"/{link.token}"))[1] == "https://a.example/"
        new = LinkSpec(mode="plain", variants=[V("A", B)], token="ignored-new-token", label="v2")
        got = await m.update_spec(link.id, new)
        assert got.token == link.token and got.hostname == link.hostname and got.port == link.port
        assert got.spec.label == "v2" and got.spec.token == link.token                   # a new token is ignored
        assert (await fetch(link.port, f"/{link.token}"))[1] == B
        assert m.store.stats(link.id)["opens"] == 2                                      # stats continue across the edit
        await m.shutdown()
    run(go())


def test_edit_runs_the_safety_checks_and_a_blocked_edit_changes_nothing():
    async def go():
        m = edit_mgr(bad=["https://evil.example/"])
        link = await m.create(plain_spec(), ttl_s=600)
        before = m.store.get_link(link.id).spec.to_json()
        with pytest.raises(BlockedError):
            await m.update_spec(link.id, LinkSpec(mode="plain", variants=[V("A", "https://evil.example/")]))
        assert m.store.get_link(link.id).spec.to_json() == before
        assert (await fetch(link.port, f"/{link.token}"))[1] == "https://a.example/"
        got = await m.update_spec(link.id, LinkSpec(mode="plain", variants=[V("A", "https://evil.example/")]), force=True)
        assert got.spec.variants[0].url == "https://evil.example/"                         # explicit override
        await m.shutdown()
    run(go())


def test_edit_validates_and_refuses_ended_or_unknown_links():
    async def go():
        m = edit_mgr()
        link = await m.create(plain_spec(), ttl_s=600)
        with pytest.raises(ValueError, match="http"):
            await m.update_spec(link.id, LinkSpec(mode="plain", variants=[V("A", "ftp://x")]))
        with pytest.raises(ValueError, match="找不到"):
            await m.update_spec("nope", plain_spec())
        await m.hard_destroy(link.id)
        with pytest.raises(ValueError, match="結束"):
            await m.update_spec(link.id, plain_spec())
        await m.shutdown()
    run(go())


def test_changing_the_password_forgets_everyone_who_unlocked_with_the_old_one():
    async def go():
        import aiohttp
        m = edit_mgr()
        old = LinkSpec(mode="plain", variants=[V("A", A)], pw_hash=hash_password("old", iterations=1000))
        link = await m.create(old, ttl_s=600)
        h = {"CF-Connecting-IP": "1.2.3.4", "User-Agent": "Mozilla/5.0 Test"}
        async with aiohttp.ClientSession() as sess:
            base = f"http://127.0.0.1:{link.port}/{link.token}"
            async with sess.post(base + "/unlock", json={"p": "old"}, headers=h) as r:
                assert r.status == 200
            async with sess.get(base, headers=h, allow_redirects=False) as r:
                assert r.status == 302
            await m.update_spec(link.id, LinkSpec(mode="plain", variants=[V("A", A)],
                                                  pw_hash=hash_password("new", iterations=1000)))
            async with sess.get(base, headers=h, allow_redirects=False) as r:
                assert r.status == 200                                                     # locked again
            async with sess.post(base + "/unlock", json={"p": "old"}, headers=h) as r:
                assert r.status == 401
            async with sess.post(base + "/unlock", json={"p": "new"}, headers=h) as r:
                assert r.status == 200
        await m.shutdown()
    run(go())


def test_an_edit_that_keeps_the_same_password_hash_keeps_visitors_unlocked():
    async def go():
        import aiohttp
        m = edit_mgr()
        spec = LinkSpec(mode="plain", variants=[V("A", A)], pw_hash=hash_password("pw", iterations=1000))
        link = await m.create(spec, ttl_s=600)
        h = {"CF-Connecting-IP": "1.2.3.4", "User-Agent": "Mozilla/5.0 Test"}
        async with aiohttp.ClientSession() as sess:
            base = f"http://127.0.0.1:{link.port}/{link.token}"
            async with sess.post(base + "/unlock", json={"p": "pw"}, headers=h):
                pass
            await m.update_spec(link.id, LinkSpec(mode="plain", variants=[V("A", B)], pw_hash=spec.pw_hash))
            async with sess.get(base, headers=h, allow_redirects=False) as r:
                assert r.status == 302 and r.headers["Location"] == B
        await m.shutdown()
    run(go())
