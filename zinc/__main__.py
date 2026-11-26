"""python -m zinc  -> start the TUI.   python -m zinc --help-settings [basic|advanced|expert]  -> list every setting."""
from __future__ import annotations

import argparse

from . import __version__
from .config import config_path, load_settings_with_warnings
from .manager import Manager
from .options import LEVELS, help_all
from .store import Store


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="zinc", description="Free, self-hosted long-URL generator on Cloudflare Quick Tunnels.")
    ap.add_argument("--help-settings", nargs="?", const="expert", choices=LEVELS, metavar="LEVEL",
                    help="print every setting with its plain-language help, then exit (LEVEL: basic/advanced/expert)")
    ap.add_argument("--config-path", action="store_true", help="print where the settings file lives, then exit")
    ap.add_argument("--version", action="version", version=f"zinc {__version__}")
    args = ap.parse_args(argv)
    if args.help_settings:
        try:
            text = help_all(args.help_settings)
        except Exception as e:  # pragma: no cover - defensive for frozen builds
            import sys as _sys
            _sys.stderr.write(f"help_all({args.help_settings!r}) raised: {e!r}\n")
            text = f"help-settings unavailable for {args.help_settings}"
        # Write UTF-8 bytes directly: a frozen Windows build's sys.stdout may be
        # cp950 even with PYTHONUTF8=1, which makes print() emit undecodable bytes
        # and lets the smoke test's UTF-8 decode fail with 0 captured lines.
        import sys as _sys
        _sys.stdout.buffer.write(text.encode("utf-8", errors="replace") + b"\n")
        _sys.stdout.buffer.flush()
        return
    if args.config_path:
        print(config_path())
        return
    from .tui import ZincApp
    settings, warnings = load_settings_with_warnings()
    store = Store(":memory:")   # links die with the process (tunnels do too), so no file is kept
    ZincApp(store, Manager(store, settings=settings), settings, warnings=warnings).run()


if __name__ == "__main__":
    main()
