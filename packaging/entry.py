"""Launcher used by PyInstaller / Nuitka.

Freezers need a plain script as their entry point; zinc/__main__.py uses package-relative imports, so it
cannot be the script itself. This file imports it as a package instead.
"""
from zinc.__main__ import main

if __name__ == "__main__":
    main()
