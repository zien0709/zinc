import asyncio
import socket
import sys
from pathlib import Path

import aiohttp
import pytest

from zinc.manager import Manager
from zinc.models import LinkSpec, Variant
from zinc.store import Store
from zinc.tunnel import Tunnel, TunnelError, parse_hostname, preflight

FAKE = str(Path(__file__).with_name("fake_cloudflared.py"))
H = {"CF-Connecting-IP": "1.2.3.4", "User-Agent": "Mozilla/5.0"}


def run(coro):
    return asyncio.run(coro)


def fake_cmd(port):
    return [sys.executable, FAKE, "tunnel", "--url", f"http://127.0.0.1:{port}"]


async def noscan(urls):
    return {}


def port_open(port):
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def plain_spec():
    return LinkSpec(mode="plain", variants=[Variant("A", "https://a.example/")])


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def mgr(clock=None, scanner=noscan, timeout=5.0):
    return Manager(Store(), fake_cmd, clock=clock or Clock(), scanner=scanner, tunnel_timeout=timeout)


async def fetch(port, path, **kw):
    async with aiohttp.ClientSession() as s:
        async with s.get(f"http://127.0.0.1:{port}{path}", headers=H, allow_redirects=False, **kw) as r:
            return r.status, r.headers.get("Location"), await r.text()


# ---- parsing -------------------------------------------------------------------------------
def test_parse_hostname_takes_the_tunnel_not_the_api_host():
    assert parse_hostname("|  https://Mild-Owl-Tree-Sky.trycloudflare.com   |") == "mild-owl-tree-sky.trycloudflare.com"
    assert parse_hostname("ERR Post https://api.trycloudflare.com/tunnel: timeout") is None
    assert parse_hostname("see https://api.trycloudflare.com and https://real-one.trycloudflare.com") == "real-one.trycloudflare.com"
    assert parse_hostname("https://trycloudflare.com/") is None
    assert parse_hostname("https://x.trycloudflare.com.evil.com/") is None       # lookalike suffix
    assert parse_hostname("Visit https://ok-one.trycloudflare.com.") == "ok-one.trycloudflare.com"


def test_preflight_flags_config_yaml(tmp_path, monkeypatch):
    monkeypatch.setenv("ZINC_CLOUDFLARED", FAKE)
    assert preflight(tmp_path) == []
    (tmp_path / ".cloudflared").mkdir()
    (tmp_path / ".cloudflared" / "config.yaml").write_text("x")
    assert any("config.yaml" in p for p in preflight(tmp_path))


# ---- raw tunnel ----------------------------------------------------------------------------
def test_tunnel_start_stop(monkeypatch):
    async def go():
        t = Tunnel(fake_cmd(1))
        host = await t.start(5)
        assert host.endswith(".trycloudflare.com") and t.proc.returncode is None
        await t.stop()
        assert t.proc.returncode is not None
    run(go())


@pytest.mark.parametrize("mode,needle", [("fail", "提前結束"), ("silent", "沒拿到"), ("api_only", "沒拿到")])
def test_tunnel_failures_are_reported(monkeypatch, mode, needle):
    monkeypatch.setenv("FAKE_CF_MODE", mode)

    async def go():
        t = Tunnel(fake_cmd(1))
        with pytest.raises(TunnelError, match=needle):
            await t.start(1.0)
        assert t.proc.returncode is not None  # never leaves a child behind
    run(go())


# ---- manager -------------------------------------------------------------------------------
def test_create_serves_then_hard_destroy_closes_everything():
    async def go():
        m = mgr()
        link = await m.create(plain_spec(), ttl_s=600)
        assert link.status == "live" and link.hostname.endswith(".trycloudflare.com")
        assert m.public_url(link) == f"https://{link.hostname}/{link.token}"
        status, loc, _ = await fetch(link.port, f"/{link.token}")
        assert (status, loc) == (302, "https://a.example/")
        proc = m._rt[link.id].tunnel.proc
        await m.hard_destroy(link.id)
        assert m.store.get_link(link.id).status == "dead"
        assert proc.returncode is not None and not port_open(link.port)
    run(go())


def test_ttl_soft_then_hard_death_with_tombstone_in_between():
    async def go():
        clock = Clock()
        m = mgr(clock)
        link = await m.create(plain_spec(), ttl_s=60)
        clock.t += 61
        await m.tick()
        assert m.store.get_link(link.id).status == "soft_dead"
        status, _, body = await fetch(link.port, f"/{link.token}")
        assert status == 410 and "已死亡" in body          # tombstone is served during the grace window
        clock.t += 60
        await m.tick()
        assert m.store.get_link(link.id).status == "soft_dead" and port_open(link.port)
        clock.t += 61
        await m.tick()
        assert m.store.get_link(link.id).status == "dead" and not port_open(link.port)
    run(go())


def test_extend_revives_a_soft_dead_link_but_not_a_dead_one():
    async def go():
        clock = Clock()
        m = mgr(clock)
        link = await m.create(plain_spec(), ttl_s=60)
        clock.t += 61
        await m.tick()
        m.extend(link.id, 600)
        got = m.store.get_link(link.id)
        assert got.status == "live" and got.expires_at == clock.t + 600
        assert (await fetch(link.port, f"/{link.token}"))[0] == 302
        m.soft_destroy(link.id, grace_s=0)
        await m.tick()
        assert m.store.get_link(link.id).status == "dead"
        m.extend(link.id, 600)
        assert m.store.get_link(link.id).status == "dead"
    run(go())


def test_ttl_clock_starts_when_link_goes_live_not_when_created():
    """cloudflared can take many seconds to hand out a URL; that wait must not eat the link's life."""
    async def go():
        clock = Clock()

        def slow_cloudflared(port):
            clock.t += 30                    # called after the link row exists but before it is reachable
            return fake_cmd(port)
        m = Manager(Store(), slow_cloudflared, clock=clock, scanner=noscan, tunnel_timeout=5.0)
        created_at = clock.t
        link = await m.create(plain_spec(), ttl_s=60)
        assert link.expires_at == created_at + 30 + 60 == clock.t + 60
        assert link.created_at == created_at
        await m.shutdown()
    run(go())


def test_unexpected_tunnel_death_marks_link_dead_and_frees_the_port(monkeypatch):
    monkeypatch.setenv("FAKE_CF_MODE", "die_after_1")

    async def go():
        m = mgr()
        link = await m.create(plain_spec(), ttl_s=600)
        for _ in range(40):
            await asyncio.sleep(0.1)
            if m.store.get_link(link.id).status == "dead":
                break
        assert m.store.get_link(link.id).status == "dead"
        assert "意外結束" in m.errors[link.id]
        await asyncio.sleep(0.3)
        assert not port_open(link.port)
    run(go())


def test_failed_create_leaves_no_server_or_process(monkeypatch):
    monkeypatch.setenv("FAKE_CF_MODE", "fail")

    async def go():
        m = mgr()
        with pytest.raises(TunnelError):
            await m.create(plain_spec(), ttl_s=600)
        (link,) = m.store.list_links()
        assert link.status == "failed" and m._rt == {}
    run(go())


def test_scan_failure_does_not_block_creation():
    async def boom(urls):
        raise RuntimeError("scanner exploded")

    async def go():
        m = mgr(scanner=boom)
        link = await m.create(plain_spec(), ttl_s=600)
        assert link.status == "live" and "scanner exploded" in m.errors[link.id]
        await m.shutdown()
    run(go())


def test_full_link_is_soft_killed_only_after_last_visitor_had_time_to_finish():
    async def go():
        clock = Clock()
        m = mgr(clock)
        spec = LinkSpec(mode="note", message="hi", variants=[Variant("A", "https://a.example/")])
        link = await m.create(spec, ttl_s=6000, max_opens=1)
        await fetch(link.port, f"/{link.token}")
        await m.tick()
        assert m.store.get_link(link.id).status == "live"
        clock.t += 100
        await m.tick()
        assert m.store.get_link(link.id).status == "live"
        clock.t += 21
        await m.tick()
        assert m.store.get_link(link.id).status == "soft_dead"
        await m.shutdown()
    run(go())


def test_pause_resume_and_recover_after_restart():
    async def go():
        m = mgr()
        link = await m.create(plain_spec(), ttl_s=600)
        m.pause(link.id)
        assert (await fetch(link.port, f"/{link.token}"))[0] == 503
        m.resume(link.id)
        assert (await fetch(link.port, f"/{link.token}"))[0] == 302
        # simulate a restart: a fresh manager on the same store has no running tunnels
        m2 = Manager(m.store, fake_cmd, scanner=noscan)
        m2.recover()
        assert m.store.get_link(link.id).status == "dead"
        await m.shutdown()
    run(go())
