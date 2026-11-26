"""Smoke-test a zinc command: does it start, print its version/settings, and open and close the terminal UI?

    python tools/smoke.py -- python -m zinc
    python tools/smoke.py --json reports/smoke-linux.json -- dist/zinc
    python tools/smoke.py --no-tui -- dist\\zinc.exe        (Windows has no pty, so the UI step is skipped there)

Exit code 0 only if every step that ran passed. A skipped step is reported as skipped, never as passed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional


def run(cmd: list[str], args: list[str], env: dict[str, str], timeout: float = 120.0) -> subprocess.CompletedProcess:
    return subprocess.run([*cmd, *args], env=env, capture_output=True, text=True, timeout=timeout,
                          stdin=subprocess.DEVNULL)


def step_version(cmd, env, _tmp):
    r = run(cmd, ["--version"], env)
    ok = r.returncode == 0 and re.match(r"zinc \d+\.\d+", r.stdout.strip()) is not None
    return ok, r.stdout.strip() or r.stderr.strip()[-200:]


def step_help_settings(cmd, env, _tmp):
    basic, expert = run(cmd, ["--help-settings", "basic"], env), run(cmd, ["--help-settings", "expert"], env)
    ok = basic.returncode == 0 == expert.returncode and 5 < len(basic.stdout) < len(expert.stdout)
    return ok, f"basic {len(basic.stdout.splitlines())} lines, expert {len(expert.stdout.splitlines())} lines"


def step_config_path(cmd, env, tmp):
    r = run(cmd, ["--config-path"], env)
    got = r.stdout.strip()
    return r.returncode == 0 and got.startswith(str(tmp)) and got.endswith("config.json"), got


def step_bad_argument(cmd, env, _tmp):
    r = run(cmd, ["--help-settings", "nonsense"], env)
    return r.returncode == 2, f"exit {r.returncode}"


def step_tui(cmd, env, tmp, start_timeout: float = 45.0, quit_timeout: float = 15.0):
    """Open the UI in a pseudo-terminal, wait until it has drawn something, press Ctrl+Q, expect a clean exit."""
    if sys.platform == "win32":
        return None, "skipped: no pty on Windows"
    import fcntl
    import pty
    import select
    import struct
    import termios
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    env = {**env, "TERM": "xterm-256color", "COLUMNS": "120", "LINES": "40"}
    proc = subprocess.Popen(cmd, env=env, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    seen = b""

    def pump(seconds: float) -> None:
        nonlocal seen
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([master], [], [], 0.2)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                seen += chunk
            if proc.poll() is not None:
                return

    try:
        began = time.monotonic()
        while time.monotonic() - began < start_timeout and len(seen) < 300 and proc.poll() is None:
            pump(0.5)
        drew = len(seen) >= 300 and b"\x1b[" in seen
        pump(1.0)                                              # let it settle before quitting
        os.write(master, b"\x11")                              # Ctrl+Q
        end = time.monotonic() + quit_timeout
        while proc.poll() is None and time.monotonic() < end:
            pump(0.3)
        if proc.poll() is None:
            proc.kill()
            proc.wait()
            return False, f"did not quit on Ctrl+Q ({len(seen)} bytes drawn)"
        return drew and proc.returncode == 0, f"drew {len(seen)} bytes, exit {proc.returncode}"
    finally:
        try:
            os.close(master)
        except OSError:
            pass
        if proc.poll() is None:
            proc.kill()


STEPS: list[tuple[str, Callable]] = [
    ("version", step_version), ("help-settings", step_help_settings), ("config-path", step_config_path),
    ("bad-argument", step_bad_argument), ("tui-start-and-quit", step_tui),
]


def run_steps(cmd: list[str], steps=STEPS, skip: tuple[str, ...] = ()) -> dict:
    results = []
    with tempfile.TemporaryDirectory(prefix="zinc-smoke-") as tmp:
        env = {**os.environ, "XDG_CONFIG_HOME": tmp, "APPDATA": tmp, "HOME": tmp, "USERPROFILE": tmp}
        for name, fn in steps:
            if name in skip:
                results.append({"name": name, "status": "skipped", "detail": "skipped by request", "seconds": 0})
                continue
            began = time.monotonic()
            try:
                ok, detail = fn(cmd, env, Path(tmp))
            except Exception as e:                                       # a crashing step is a failing step
                ok, detail = False, f"{type(e).__name__}: {e}"
            status = "skipped" if ok is None else ("passed" if ok else "failed")
            results.append({"name": name, "status": status, "detail": str(detail)[:300],
                            "seconds": round(time.monotonic() - began, 1)})
    return {"cmd": cmd, "ok": all(r["status"] != "failed" for r in results) and any(r["status"] == "passed" for r in results),
            "steps": results}


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", help="write the result here")
    ap.add_argument("--no-tui", action="store_true", help="skip the terminal-UI step")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- followed by the command to test")
    args = ap.parse_args(argv)
    cmd = [c for c in args.cmd if c != "--"] if args.cmd and args.cmd[0] == "--" else args.cmd
    if not cmd:
        ap.error("give the command to test after --")
    result = run_steps(cmd, skip=("tui-start-and-quit",) if args.no_tui else ())
    for s in result["steps"]:
        mark = {"passed": "✅", "failed": "❌", "skipped": "⏭"}[s["status"]]
        print(f"{mark} {s['name']:<20} {s['seconds']:>5}s  {s['detail']}")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
