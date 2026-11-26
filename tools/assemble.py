"""Gather what the separate CI jobs uploaded into the two flat folders `tools/report.py` reads.

Every job uploads its files as an artifact named `reports-<something>` (JSON/XML/TXT reports) or `dist-<something>`
(files that will be attached to the release: executables, the wheel, the sdist). GitHub downloads each artifact into
its own sub-folder of `--bundle`; this copies them side by side:

    bundle/reports-test-ubuntu-latest-3.13/junit-ubuntu-latest-3.13.xml   ->  reports/junit-ubuntu-latest-3.13.xml
    bundle/dist-zinc-linux-x64/zinc-linux-x64                              ->  assets/zinc-linux-x64

It does not matter how deep a file sits inside its artifact (the upload action's folder layout depends on the paths
given to it), only its name counts. Two different files with the same name are an error, never a silent overwrite.

    python tools/assemble.py --bundle bundle --reports reports --assets assets
"""
from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path

KINDS = {"reports-": "reports", "dist-": "assets"}


class Collision(Exception):
    pass


def assemble(bundle: Path, reports: Path, assets: Path) -> dict[str, list[str]]:
    targets = {"reports": reports, "assets": assets}
    for t in targets.values():
        t.mkdir(parents=True, exist_ok=True)
    result: dict[str, list[str]] = {"reports": [], "assets": [], "ignored": []}
    if not bundle.is_dir():
        return result
    for art in sorted(p for p in bundle.iterdir() if p.is_dir()):
        kind = next((k for prefix, k in KINDS.items() if art.name.startswith(prefix)), None)
        for f in sorted(p for p in art.rglob("*") if p.is_file()):
            if kind is None:
                result["ignored"].append(f"{art.name}/{f.relative_to(art).as_posix()}")
                continue
            dest = targets[kind] / f.name
            if dest.exists():
                if filecmp.cmp(f, dest, shallow=False):
                    continue                                   # the same file arrived twice: harmless
                raise Collision(f"two different files are both called {f.name!r} (second one is in artifact {art.name})")
            shutil.copy2(f, dest)
            result[kind].append(f.name)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", default="bundle")
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--assets", default="assets")
    a = ap.parse_args(argv)
    try:
        got = assemble(Path(a.bundle), Path(a.reports), Path(a.assets))
    except Collision as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"reports: {len(got['reports'])} file(s); release assets: {len(got['assets'])} file(s)")
    for name in got["assets"]:
        print(f"  asset  {name}")
    for name in got["ignored"]:
        print(f"  (ignored: {name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
