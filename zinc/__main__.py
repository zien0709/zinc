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
        print(help_all(args.help_settings))
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
