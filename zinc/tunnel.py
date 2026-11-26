"""cloudflared quick-tunnel child process: start, read the public hostname, stop."""
from __future__ import annotations

import asyncio
import os
import re
import shutil
from pathlib import Path
from typing import Callable, Optional

# cloudflared also prints https://api.trycloudflare.com/... in errors: that is NOT our tunnel.
_URL = re.compile(r"https://([a-z0-9][a-z0-9-]*)\.trycloudflare\.com(?![a-z0-9-]|\.[a-z0-9])", re.I)
_NOT_TUNNEL = {"api"}


class TunnelError(RuntimeError):
    pass


def parse_hostname(line: str) -> Optional[str]:
    for m in _URL.finditer(line):
        if m.group(1).lower() not in _NOT_TUNNEL:
            return f"{m.group(1).lower()}.trycloudflare.com"
    return None


def find_cloudflared(configured: str = "") -> Optional[str]:
    """Setting `cloudflared_path` wins, then env ZINC_CLOUDFLARED, then PATH."""
    return configured or os.environ.get("ZINC_CLOUDFLARED") or shutil.which("cloudflared")


def preflight(home: Optional[Path] = None, configured: str = "") -> list[str]:
    """Human-readable problems that would stop quick tunnels from working."""
    problems = []
    if not find_cloudflared(configured):
        problems.append("找不到 cloudflared：請安裝，或設環境變數 ZINC_CLOUDFLARED 指向它。")
    cfg = (home or Path.home()) / ".cloudflared" / "config.yaml"
    if cfg.exists():
        problems.append(f"{cfg} 存在：官方說明有這個檔案時 Quick Tunnel 可能無法使用，請暫時改名。")
    return problems


def default_cmd(port: int, configured: str = "", extra=()) -> list[str]:
    exe = find_cloudflared(configured) or "cloudflared"
    return [exe, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}", *extra]


class Tunnel:
    def __init__(self, cmd: list[str], on_exit: Optional[Callable[[int], None]] = None, term_grace: float = 3.0):
        self.cmd = cmd
        self.on_exit = on_exit
        self.term_grace = term_grace      # seconds cloudflared gets to exit after SIGTERM before it is killed
        self.hostname: Optional[str] = None
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.log: list[str] = []          # last lines, for diagnostics in the TUI
        self._stopping = False
        self._tasks: list[asyncio.Task] = []

    async def start(self, timeout: float = 20.0) -> str:
        self.proc = await asyncio.create_subprocess_exec(
            *self.cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        found: asyncio.Future[str] = asyncio.get_running_loop().create_future()

        async def pump() -> None:
            assert self.proc and self.proc.stdout
            async for raw in self.proc.stdout:
                line = raw.decode(errors="replace").rstrip()
                self.log = (self.log + [line])[-30:]
                host = parse_hostname(line)
                if host and not found.done():
                    found.set_result(host)

        async def watch() -> None:
            assert self.proc
            code = await self.proc.wait()
            if not found.done():
                found.set_exception(TunnelError(f"cloudflared 提前結束（exit {code}）：{' | '.join(self.log[-3:])}"))
            if not self._stopping and self.on_exit:
                self.on_exit(code)

        self._tasks = [asyncio.create_task(pump()), asyncio.create_task(watch())]
        try:
            self.hostname = await asyncio.wait_for(found, timeout)
        except asyncio.TimeoutError:
            await self.stop()
            raise TunnelError(f"{timeout:.0f} 秒內沒拿到 trycloudflare 網址：{' | '.join(self.log[-3:])}") from None
        except TunnelError:
            await self.stop()
            raise
        return self.hostname

    async def stop(self) -> None:
        self._stopping = True
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), self.term_grace)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        if self._tasks:
            # The output reader ends by itself at EOF once the process is gone; let it, so asyncio can close the
            # pipe transports cleanly. Only a straggler is cancelled.
            _, pending = await asyncio.wait(self._tasks, timeout=1.0)
            for t in pending:
                t.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
        transport = getattr(self.proc, "_transport", None)       # no public API for this; harmless if it is ever absent
        if transport is not None and not transport.is_closing():
            transport.close()
