"""Print the OLDEST dependency versions pyproject.toml still allows, as pinned requirements (one per line).

    python tools/floor_requirements.py > floor.txt && pip install -r floor.txt

`aiohttp>=3.14.4` becomes `aiohttp==3.14.4`. CI installs these, runs the whole test suite and audits them for known
vulnerabilities, so the minimums written in pyproject.toml are checked facts, not guesses. Only plain `name>=version`
lines are understood; anything else is an error (a floor nobody can test is not a floor).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def floors(text: str) -> list[str]:
    block = re.search(r"^dependencies\s*=\s*\[(.*?)^\]", text, re.S | re.M)
    if not block:
        raise SystemExit("no `dependencies = [...]` list found in pyproject.toml")
    pins = []
    for raw in re.findall(r'"([^"]+)"', re.sub(r"#.*", "", block.group(1))):
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)\s*>=\s*([0-9][0-9A-Za-z.]*)", raw.strip())
        if not m:
            raise SystemExit(f"cannot turn {raw!r} into a pinned floor; write dependencies as `name>=version`")
        pins.append(f"{m.group(1)}=={m.group(2)}")
    return pins


def main() -> None:
    print("\n".join(floors(PYPROJECT.read_text(encoding="utf-8"))))


if __name__ == "__main__":
    main()
