"""Build one standalone zinc executable (or folder) with PyInstaller or Nuitka, and describe the result.

    python tools/build_binary.py --tool pyinstaller --mode onefile    --name zinc-linux-x64
    python tools/build_binary.py --tool pyinstaller --mode onedir     --name zinc-linux-x64-folder.zip
    python tools/build_binary.py --tool nuitka      --mode onefile    --name zinc-nuitka-linux-x64
    python tools/build_binary.py --tool nuitka      --mode standalone --name zinc-nuitka-linux-x64-folder.zip
    add --dry-run to print the commands without running anything

Results: dist/<name>  and  reports/build-<name>.json  (and `exe=` / `asset=` in $GITHUB_OUTPUT, for the smoke test).
Freezers cannot cross-compile: run this on the operating system you are building for.
The PyInstaller recipe is the one verified on Linux; the Nuitka flags are checked against `nuitka --help` of the
pinned version, but a full Nuitka build has NOT been run by the author.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRY = ROOT / "packaging" / "entry.py"
NUITKA_PIN = "nuitka==4.3.5"            # the version whose command-line flags were checked
IS_WINDOWS = sys.platform == "win32"


def exe_name() -> str:
    return "zinc.exe" if IS_WINDOWS else "zinc"


def plan(tool: str, mode: str, work: Path, python: str = sys.executable, jobs: int | None = None,
         has_maxmind: bool | None = None) -> dict:
    """The command to run, and where the result will be (`exe`, plus `folder` when it is a folder build)."""
    if has_maxmind is None:
        has_maxmind = importlib.util.find_spec("maxminddb") is not None
    jobs = jobs or os.cpu_count() or 2
    if tool == "pyinstaller":
        if mode not in ("onefile", "onedir"):
            raise SystemExit("pyinstaller supports --mode onefile | onedir")
        cmd = [python, "-m", "PyInstaller", "--noconfirm", "--clean", f"--{mode}", "--name", "zinc",
               "--collect-all", "textual", "--collect-all", "segno",
               "--distpath", str(work / "dist"), "--workpath", str(work / "build"), "--specpath", str(work)]
        if has_maxmind:
            cmd += ["--hidden-import", "maxminddb"]
        cmd.append(str(ENTRY))
        if mode == "onefile":
            return {"cmd": cmd, "exe": work / "dist" / exe_name(), "folder": None}
        return {"cmd": cmd, "exe": work / "dist" / "zinc" / exe_name(), "folder": work / "dist" / "zinc"}
    if tool == "nuitka":
        if mode not in ("onefile", "standalone"):
            raise SystemExit("nuitka supports --mode onefile | standalone")
        out = work / "nuitka"
        cmd = [python, "-m", "nuitka", f"--mode={mode}", "--assume-yes-for-downloads", "--remove-output",
               "--lto=no", f"--jobs={jobs}", f"--output-dir={out}", f"--output-filename={exe_name()}",
               "--include-package=zinc", "--include-package=textual", "--include-package-data=textual",
               "--include-package=rich", "--include-package=segno",
               "--include-distribution-metadata=textual", "--include-distribution-metadata=rich"]
        if has_maxmind:
            cmd.append("--include-module=maxminddb")
        cmd.append(str(ENTRY))
        if mode == "onefile":
            return {"cmd": cmd, "exe": out / exe_name(), "folder": None}
        return {"cmd": cmd, "exe": out / "entry.dist" / exe_name(), "folder": out / "entry.dist"}
    raise SystemExit("--tool must be pyinstaller or nuitka")


def zip_folder(folder: Path, zip_path: Path, top: str = "zinc") -> None:
    """Zip `folder` as `top/...`, keeping executable permission bits."""
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                z.write(path, f"{top}/{path.relative_to(folder).as_posix()}")


def tool_version(tool: str, python: str) -> str:
    try:
        if tool == "pyinstaller":
            return subprocess.run([python, "-c", "import PyInstaller; print(PyInstaller.__version__)"],
                                  capture_output=True, text=True, timeout=60).stdout.strip()
        return subprocess.run([python, "-m", "nuitka", "--version"], capture_output=True, text=True,
                              timeout=120).stdout.splitlines()[0].strip()
    except Exception:                                                         # a version string is a nicety
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tool", required=True, choices=["pyinstaller", "nuitka"])
    ap.add_argument("--mode", required=True, choices=["onefile", "onedir", "standalone"])
    ap.add_argument("--name", required=True, help="asset file name; end it with .zip for folder builds")
    ap.add_argument("--out", default="dist", help="where the finished asset goes")
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--work", default="build-binary", help="scratch folder")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    work, out, reports = Path(args.work).resolve(), Path(args.out).resolve(), Path(args.reports).resolve()
    p = plan(args.tool, args.mode, work)
    folder_build = p["folder"] is not None
    if folder_build != args.name.endswith(".zip"):
        raise SystemExit("folder builds (onedir/standalone) must be named *.zip; single-file builds must not be")
    if args.dry_run:
        print(json.dumps({"cmd": p["cmd"], "exe": str(p["exe"]), "folder": str(p["folder"]) if p["folder"] else None},
                         indent=1))
        return 0

    work.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    began = time.monotonic()
    print("+", " ".join(p["cmd"]), flush=True)
    rc = subprocess.run(p["cmd"], cwd=ROOT).returncode
    if rc != 0 or not p["exe"].exists():
        print(f"build failed (exit {rc}); expected {p['exe']}", file=sys.stderr)
        return rc or 1

    asset = out / args.name
    exe = p["exe"]
    if folder_build:
        zip_folder(p["folder"], asset)
    else:
        shutil.copy2(exe, asset)
        asset.chmod(0o755)
    info = {"name": args.name, "tool": args.tool, "tool_version": tool_version(args.tool, sys.executable),
            "mode": args.mode, "size_bytes": asset.stat().st_size, "seconds": round(time.monotonic() - began, 1),
            "python": sys.version.split()[0], "platform": sys.platform, "exe": str(exe)}
    (reports / f"build-{args.name}.json").write_text(json.dumps(info, indent=1), encoding="utf-8")
    gh = os.environ.get("GITHUB_OUTPUT")
    if gh:
        with open(gh, "a", encoding="utf-8") as f:
            f.write(f"exe={exe}\nasset={asset}\n")
    print(json.dumps(info))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
