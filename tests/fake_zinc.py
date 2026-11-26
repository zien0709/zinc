"""Stand-in for the zinc executable, for testing tools/smoke.py. FAKE_ZINC_BREAK picks one thing to get wrong:
version | version_exit | help | config | argument | tui_hang | tui_crash | tui_silent | tui_exit"""
import os
import sys
import time

broken = os.environ.get("FAKE_ZINC_BREAK", "")
args = sys.argv[1:]
if args == ["--version"]:
    print("zinc oops" if broken == "version" else "zinc 9.9.9")
    sys.exit(1 if broken == "version_exit" else 0)
elif args[:1] == ["--help-settings"]:
    if len(args) > 1 and args[1] not in ("basic", "advanced", "expert"):
        sys.exit(2 if broken != "argument" else 0)
    n = 30 if args[1:] == ["expert"] else 8
    n = 8 if broken == "help" else n
    print("\n".join(f"setting {i}: does something useful" for i in range(n if broken != "help" else 40)))
elif args == ["--config-path"]:
    base = os.environ.get("XDG_CONFIG_HOME") or os.environ.get("APPDATA") or "."
    print(os.path.join(base, "zinc", "config.json") if broken != "config" else "/somewhere/else.json")
elif not args:
    if broken == "tui_crash":
        sys.exit(1)
    import termios
    import tty
    tty.setraw(sys.stdin.fileno())                                  # a real TUI is raw, so Ctrl+Q reaches it
    if broken != "tui_silent":
        sys.stdout.write("\x1b[2J\x1b[H" + "zinc " * 100)
        sys.stdout.flush()
    if broken == "tui_hang":
        time.sleep(60)
    while sys.stdin.read(1) != "\x11":
        pass
    sys.exit(1 if broken == "tui_exit" else 0)
