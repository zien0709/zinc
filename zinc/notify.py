"""Webhook notifications: tell the host (Discord, Slack, or their own server) when something happens.

Privacy: a message carries the link's own name/id, the event, and (optionally) the visitor's country.
Never a visitor IP, never the secret path suffix, never a target URL.
Reliability: sending is queued and best effort. It can never slow a visitor down, and a dead or slow
receiver only costs a dropped message. Webhook URLs often contain a secret token, so error text never
includes the URL.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from collections import deque
from typing import Callable, Optional

import aiohttp

from .config import Settings

_FIELDS = ("link_id", "label", "mode", "country", "host", "variant", "reason")
_REASONS = {"expired": "時間到了", "passes": "名額用完了", "manual": "你手動銷毀", "full": "人數額滿"}


def describe(event: str, data: dict) -> str:
    name = data.get("label") or str(data.get("link_id", "?"))[:4]
    host = (data.get("host") or "").replace(".trycloudflare.com", "")
    who = f"{name}（{host}）" if host and data.get("label") else (host or name)
    where = f"（{data['country']}）" if data.get("country") else ""
    if event == "open":
        return f"👀 有人打開了 {who}{where}"
    if event == "pass":
        to = f" → {data['variant']}" if data.get("variant") else ""
        return f"✅ 有人通關了 {who}{to}{where}"
    if event == "dead":
        return f"🪦 {who} 已死亡：{_REASONS.get(data.get('reason', ''), data.get('reason', ''))}"
    return f"{event} {who}"


def build_request(event: str, data: dict, s: Settings, now: float) -> tuple[bytes, dict]:
    """(body, headers) for the configured format."""
    data = {k: v for k, v in data.items() if v is not None and k in _FIELDS}      # allow-list: nothing else can leak
    if not s.webhook_country:
        data.pop("country", None)
    text = describe(event, data)
    headers = {"Content-Type": "application/json", "User-Agent": "zinc-webhook/1.0", "X-Zinc-Event": event}
    if s.webhook_format == "discord":
        payload: dict = {"content": text[:1900], "allowed_mentions": {"parse": []}}    # a label can't ping @everyone
    elif s.webhook_format == "slack":
        payload = {"text": text[:3000]}
    else:
        payload = {"event": event, "text": text, "ts": int(now), **data}
    body = json.dumps(payload, ensure_ascii=False).encode()
    if s.webhook_format == "json" and s.webhook_secret:
        headers["X-Zinc-Signature"] = "sha256=" + hmac.new(s.webhook_secret.encode(), body, hashlib.sha256).hexdigest()
    return body, headers


def verify_signature(secret: str, body: bytes, header: str) -> bool:
    """What a receiving server should do. Constant-time."""
    want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header or "")


class Notifier:
    MAX_QUEUE = 50

    def __init__(self, settings: Settings, clock: Callable[[], float] = time.time):
        self.s, self.clock = settings, clock
        self.last_error = ""
        self.sent = 0
        self.dropped = 0
        self._q: Optional[asyncio.Queue] = None
        self._task: Optional[asyncio.Task] = None
        self._recent: deque = deque()

    def wants(self, event: str) -> bool:
        return bool(self.s.webhook_url) and event in self.s.webhook_events

    def submit(self, event: str, data: dict) -> bool:
        """Queue one message. Never raises, never blocks. False = not sent (off, filtered, capped, no loop)."""
        if not self.wants(event):
            return False
        now = self.clock()
        while self._recent and now - self._recent[0] >= 60:
            self._recent.popleft()
        if len(self._recent) >= self.s.webhook_max_per_min:
            self.dropped += 1
            self.last_error = f"通知太頻繁，已略過 {self.dropped} 則（上限每分鐘 {self.s.webhook_max_per_min} 則）"
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return False
        if self._q is None:
            self._q = asyncio.Queue(self.MAX_QUEUE)
        if self._task is None or self._task.done():
            self._task = loop.create_task(self._worker())
        try:
            self._q.put_nowait((event, dict(data), now))
        except asyncio.QueueFull:
            self.dropped += 1
            return False
        self._recent.append(now)
        return True

    async def _worker(self) -> None:
        assert self._q is not None
        timeout = aiohttp.ClientTimeout(total=self.s.webhook_timeout_s)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            while True:
                event, data, ts = await self._q.get()
                try:
                    await self._post(session, event, data, ts)
                finally:
                    self._q.task_done()

    async def _post(self, session: aiohttp.ClientSession, event: str, data: dict, ts: float) -> None:
        url = self.s.webhook_url
        if not url:
            return
        body, headers = build_request(event, data, self.s, ts)
        try:
            async with session.post(url, data=body, headers=headers, allow_redirects=False,
                                    timeout=aiohttp.ClientTimeout(total=self.s.webhook_timeout_s)) as r:
                if 200 <= r.status < 300:
                    self.sent += 1
                    self.last_error = ""
                else:
                    self.last_error = f"webhook 對方回 HTTP {r.status}"
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            self.last_error = f"webhook 送不出去：{type(e).__name__}"      # class only: the URL holds a secret

    async def flush(self, timeout: float = 3.0) -> None:
        if self._q is not None and self._task is not None and not self._task.done():
            try:
                await asyncio.wait_for(self._q.join(), timeout)
            except asyncio.TimeoutError:
                pass

    async def close(self, timeout: float = 2.0) -> None:
        await self.flush(timeout)
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
