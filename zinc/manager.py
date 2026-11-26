"""Lifecycle orchestration: one origin server + one cloudflared process per link."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, Sequence

from aiohttp import web

from .geo import Resolver, header_resolver
from .notify import Notifier
from .options import Settings
from .models import LinkSpec, validate_spec
from .reputation import Reputation, Verdict, dump_verdicts, worst
from .scan import dump_scans, scan_all
from .server import UNLOCKED, make_app
from .store import Link, Store
from .tunnel import Tunnel, TunnelError, default_cmd
from .urlutil import quote_token


class BlockedError(Exception):
    """Raised when the safety checks reject a target. `verdicts` maps url -> Verdict."""

    def __init__(self, verdicts: dict[str, Verdict]):
        self.verdicts = verdicts
        url, v = worst(verdicts)  # type: ignore[misc]
        super().__init__(f"{url} 被安全檢查擋下：" + "；".join(v.reasons("block")))


@dataclass
class _Runtime:
    runner: web.AppRunner
    tunnel: Tunnel


class Manager:
    def __init__(self, store: Store, cmd_factory: Optional[Callable[[int], list[str]]] = None, *,
                 clock: Callable[[], float] = time.time,
                 scanner: Optional[Callable[[list], Awaitable[dict]]] = None,
                 geo_chain: Sequence[Resolver] = (header_resolver,),
                 tunnel_timeout: Optional[float] = None,
                 on_change: Optional[Callable[[], None]] = None,
                 settings: Optional[Settings] = None,
                 reputation: Optional[Reputation] = None):
        self.settings = settings or Settings()
        self.reputation = reputation or Reputation(self.settings)
        self.store, self.clock = store, clock
        self.cmd_factory = cmd_factory or (lambda port: default_cmd(
            port, self.settings.cloudflared_path, self.settings.tunnel_extra_args))
        self._scanner, self.geo_chain = scanner, geo_chain
        self._tunnel_timeout, self.on_change = tunnel_timeout, on_change
        self.errors: dict[str, str] = {}
        self._rt: dict[str, _Runtime] = {}
        self.notifier = Notifier(self.settings, clock)

    def _emit(self, event: str, data: dict) -> None:
        """Server -> webhook. Adds the public hostname; the visitor's IP never gets this far."""
        link = self.store.get_link(data.get("link_id", ""))
        self.notifier.submit(event, {**data, "host": link.hostname if link else None})
        if self.notifier.last_error:
            self.errors["_webhook"] = self.notifier.last_error
        else:
            self.errors.pop("_webhook", None)
        self._changed()

    def _changed(self) -> None:
        if self.on_change:
            self.on_change()

    @staticmethod
    def public_url(link: Link) -> Optional[str]:
        return f"https://{link.hostname}/{quote_token(link.token)}" if link.hostname else None

    async def _scan(self, urls: list) -> dict:
        """Scan targets with the user's limits. A custom `scanner` (tests) bypasses the settings."""
        s = self.settings
        if not s.scan_enabled:
            return {}
        if self._scanner:
            return await self._scanner(urls)
        return await scan_all(urls, max_bytes=s.scan_max_kb * 1024, max_hops=s.scan_max_hops,
                              timeout_s=s.scan_timeout_s, user_agent=s.scan_user_agent)

    def grace_for(self, link: Link) -> float:
        return self.settings.for_link(link.spec.options).grace_s

    def recover(self) -> None:
        """After a restart no tunnel survives, so anything that claims to be alive is stale."""
        for link in self.store.list_links():
            if link.status in ("starting", "live", "paused", "soft_dead") and link.id not in self._rt:
                self.store.set_status(link.id, "dead")

    async def _vet(self, spec: LinkSpec, force: bool) -> tuple[dict, dict, str]:
        """Scan the targets and run the safety checks. Raises BlockedError before anything is created or changed."""
        urls = [v.url for g in spec.groups() for v in g if v.url]
        scans: dict = {}
        verdicts: dict[str, Verdict] = {}
        note = ""
        try:  # scan and checks are best effort: a slow or hostile target must never wedge creation
            scans = await self._scan(urls)
            verdicts = await self.reputation.check_all(urls, scans)
        except Exception as e:  # noqa: BLE001
            note = f"掃描或安全檢查失敗：{e}"
        w = worst(verdicts)
        if w and w[1].level == "block" and self.settings.block_on_malicious and not force:
            raise BlockedError(verdicts)
        return scans, verdicts, note

    async def create(self, spec: LinkSpec, ttl_s: Optional[float] = None,
                     max_opens: Optional[int] = None, force: bool = False) -> Link:
        validate_spec(spec)
        scans, verdicts, note = await self._vet(spec, force)   # nothing is created if this raises
        link = self.store.create_link(spec, ttl_s, max_opens, now=self.clock(),
                                      token_length=self.settings.token_length)
        if note:
            self.errors[link.id] = note
        self.store.set_scan(link.id, dump_scans(scans))
        self.store.set_verdict(link.id, dump_verdicts(verdicts))
        runner = web.AppRunner(make_app(self.store, link.id, settings=self.settings, clock=self.clock,
                                        geo_chain=self.geo_chain, emit=self._emit),
                               access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", 0).start()
        port = runner.addresses[0][1]
        tunnel = Tunnel(self.cmd_factory(port), on_exit=lambda code, lid=link.id: self._tunnel_exited(lid, code))
        self._rt[link.id] = _Runtime(runner, tunnel)
        try:
            host = await tunnel.start(self._tunnel_timeout if self._tunnel_timeout is not None
                                      else self.settings.tunnel_timeout_s)
        except TunnelError as e:
            self.errors[link.id] = str(e)
            await self._teardown(link.id)
            self.store.set_status(link.id, "failed")
            self._changed()
            raise
        self.store.set_tunnel(link.id, host, port)
        if ttl_s is not None:  # the clock starts when the link becomes reachable, not when you pressed n
            self.store.set_expiry(link.id, self.clock() + ttl_s)
        self.store.set_status(link.id, "live")
        self._changed()
        return self.store.get_link(link.id)  # type: ignore[return-value]

    def _tunnel_exited(self, link_id: str, code: int) -> None:
        link = self.store.get_link(link_id)
        if link and link.status != "dead":
            self.errors[link_id] = f"cloudflared 意外結束（exit {code}），網址已失效"
            self.store.set_status(link_id, "dead")
            asyncio.get_running_loop().create_task(self._teardown(link_id))
            self._changed()

    async def _teardown(self, link_id: str) -> None:
        rt = self._rt.pop(link_id, None)
        if rt:
            await rt.tunnel.stop()
            await rt.runner.cleanup()

    # ---- user actions -------------------------------------------------------------------
    def soft_destroy(self, link_id: str, grace_s: Optional[float] = None, reason: str = "manual") -> None:
        link = self.store.get_link(link_id)
        if link and link.status in ("starting", "live", "paused"):
            grace = self.grace_for(link) if grace_s is None else grace_s
            self.store.set_status(link_id, "soft_dead", grace_until=self.clock() + grace)
            self._emit("dead", {"link_id": link_id, "label": link.spec.label, "mode": link.spec.mode, "reason": reason})
            self._changed()

    async def hard_destroy(self, link_id: str) -> None:
        await self._teardown(link_id)
        link = self.store.get_link(link_id)
        if link and link.status != "failed":
            self.store.set_status(link_id, "dead")
        self._changed()

    def pause(self, link_id: str) -> None:
        link = self.store.get_link(link_id)
        if link and link.status == "live":
            self.store.set_status(link_id, "paused")
            self._changed()

    def resume(self, link_id: str) -> None:
        link = self.store.get_link(link_id)
        if link and link.status == "paused":
            self.store.set_status(link_id, "live")
            self._changed()

    def extend(self, link_id: str, seconds: float) -> None:
        """Add time; a soft-dead link whose tunnel is still up comes back to life."""
        link = self.store.get_link(link_id)
        if not link or link.id not in self._rt:
            return
        self.store.extend(link_id, seconds, now=self.clock())
        if link.status == "soft_dead":
            self.store.set_status(link_id, "live")
        self._changed()

    async def update_spec(self, link_id: str, spec: LinkSpec, force: bool = False) -> Link:
        """Change what a live link does (targets, mode, rules, password, label...) without changing its URL.
        The secret path suffix and the visitor stats stay; the safety checks run again on the new targets."""
        link = self.store.get_link(link_id)
        if link is None:
            raise ValueError("找不到這條連結")
        if link.status not in ("starting", "live", "paused", "soft_dead"):
            raise ValueError("這條連結已經結束，不能再改")
        spec.token = link.token
        validate_spec(spec)
        scans, verdicts, note = await self._vet(spec, force)
        self.store.set_spec(link_id, spec)
        self.store.set_scan(link_id, dump_scans(scans))
        self.store.set_verdict(link_id, dump_verdicts(verdicts))
        if note:
            self.errors[link_id] = note
        else:
            self.errors.pop(link_id, None)
        rt = self._rt.get(link_id)
        if rt and spec.pw_hash != link.spec.pw_hash:
            rt.runner.app[UNLOCKED].clear()      # a new password must not honour the old one's unlocks
        self._changed()
        return self.store.get_link(link_id)  # type: ignore[return-value]

    async def rescan(self, link_id: str) -> None:
        link = self.store.get_link(link_id)
        if link:
            urls = [v.url for g in link.spec.groups() for v in g if v.url]
            scans = await self._scan(urls)
            self.store.set_scan(link_id, dump_scans(scans))
            self.store.set_verdict(link_id, dump_verdicts(await self.reputation.check_all(urls, scans)))
            self._changed()

    # ---- background ---------------------------------------------------------------------
    async def tick(self) -> None:
        now = self.clock()
        for link in self.store.list_links():
            if link.id not in self._rt:
                continue
            if link.status in ("starting", "live", "paused"):
                if link.expires_at is not None and now >= link.expires_at:
                    self.soft_destroy(link.id, reason="expired")
                elif link.max_opens is not None and self.store.count_opens(link.id) >= link.max_opens:
                    last = self.store.last_open_ts(link.id)
                    if last is not None and now - last >= self.grace_for(link):
                        self.soft_destroy(link.id, reason="full")
            elif link.status == "soft_dead" and link.grace_until is not None and now >= link.grace_until:
                await self.hard_destroy(link.id)

    async def run_ticker(self, interval: float = 1.0) -> None:
        while True:
            try:
                await self.tick()
            except Exception as e:  # noqa: BLE001  a bad tick must not stop the loop
                self.errors["_ticker"] = str(e)
            await asyncio.sleep(interval)

    async def shutdown(self) -> None:
        for link_id in list(self._rt):
            await self.hard_destroy(link_id)
        await self.notifier.close()
