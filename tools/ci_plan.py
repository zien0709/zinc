"""Decide what a GitHub Actions run should do, from the event and the manual-run inputs.

Reads environment variables, writes `key=value` lines to $GITHUB_OUTPUT (or stdout):

    EVENT      github.event_name            (push | pull_request | workflow_dispatch)
    REF        github.ref                   (refs/tags/v1.2.3 means "release")
    PLATFORMS  linux | linux+windows | all  (manual runs; releases always use "all")
    TESTS      min | full
    NUITKA, MUTATION, LIVE, PYINSTALLER, EXTRA_ARM    "true" / "false"
    SKIP       comma list of things to leave out even on a release (a repository variable, so no YAML edit):
               mutation, live, nuitka, pyinstaller, security, floor, windows, macos        (e.g. "mutation,macos")
    PLAN_JSON  optional path: also write the whole plan there as JSON (the final report reads it)

Keeping this logic in a script (not in YAML expressions) means it can be unit-tested and read like normal code.
"""
from __future__ import annotations

import json
import os
import sys

PLATFORM_OS = {            # platform id -> (runner label, asset suffix, exe extension)
    "linux": ("ubuntu-latest", "linux-x64", ""),
    "windows": ("windows-latest", "windows-x64", ".exe"),
    "macos": ("macos-latest", "macos-arm64", ""),
    "linux-arm": ("ubuntu-24.04-arm", "linux-arm64", ""),
}
PLATFORM_SETS = {"linux": ["linux"], "linux+windows": ["linux", "windows"], "all": ["linux", "windows", "macos"]}
TEST_PYTHONS = ["3.10", "3.11", "3.12", "3.13"]
SKIPPABLE = ("mutation", "live", "nuitka", "pyinstaller", "security", "floor", "windows", "macos")


def parse_skip(text: str | None) -> list[str]:
    """`"mutation, macos"` -> ["mutation", "macos"]; a typo is an error, never a silently ignored word."""
    words = [w.strip().lower() for w in (text or "").replace(";", ",").replace(" ", ",").split(",") if w.strip()]
    unknown = [w for w in words if w not in SKIPPABLE]
    if unknown:
        raise SystemExit(f"unknown SKIP word(s) {unknown}; choose from {list(SKIPPABLE)}")
    return sorted(set(words))


def truthy(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _job(os_name: str, python: str, cov: bool = False, floor: bool = False) -> dict[str, object]:
    """One test job. `label` names its report file: junit-<label>-<python>.xml."""
    return {"os": os_name, "python": python, "cov": cov, "floor": floor,
            "label": "ubuntu-floor" if floor else os_name}


def plan(env: dict[str, str]) -> dict[str, object]:
    ref, event = env.get("REF", ""), env.get("EVENT", "")
    release = ref.startswith("refs/tags/v")
    manual = event == "workflow_dispatch"

    if release:
        platforms, tests = "all", "full"
        nuitka = pyinstaller = mutation = live = True
        extra_arm = truthy(env.get("EXTRA_ARM"), False)
    else:
        platforms = env.get("PLATFORMS") or "linux"
        tests = env.get("TESTS") or "min"
        nuitka = truthy(env.get("NUITKA"), False)
        pyinstaller = truthy(env.get("PYINSTALLER"), manual)
        mutation = truthy(env.get("MUTATION"), False)
        live = truthy(env.get("LIVE"), manual)
        extra_arm = truthy(env.get("EXTRA_ARM"), False)
    if platforms not in PLATFORM_SETS:
        raise SystemExit(f"unknown PLATFORMS {platforms!r}; choose one of {sorted(PLATFORM_SETS)}")
    if tests not in ("min", "full"):
        raise SystemExit(f"unknown TESTS {tests!r}; choose min or full")
    skip = parse_skip(env.get("SKIP"))
    nuitka, pyinstaller, mutation, live = (flag and name not in skip for flag, name in
                                           ((nuitka, "nuitka"), (pyinstaller, "pyinstaller"), (mutation, "mutation"),
                                            (live, "live")))
    chosen = [p for p in PLATFORM_SETS[platforms] if p not in skip]

    # ---- test matrix --------------------------------------------------------------------------------
    pythons = TEST_PYTHONS if tests == "full" else ["3.10", "3.13"]
    test_matrix = [_job("ubuntu-latest", p, cov=p == "3.13") for p in pythons]
    if "windows" in chosen:
        test_matrix.append(_job("windows-latest", "3.12"))
    if "macos" in chosen:
        test_matrix.append(_job("macos-latest", "3.12"))
    if tests == "full" and "floor" not in skip:                       # the oldest dependency versions we still claim to support, audited too
        test_matrix.append(_job("ubuntu-latest", "3.13", floor=True))

    # ---- build matrix: one job per (platform, tool, mode) ------------------------------------------------
    build = []
    plats = chosen + (["linux-arm"] if extra_arm else [])
    for plat in plats:
        runner, suffix, ext = PLATFORM_OS[plat]
        if pyinstaller:
            build.append({"os": runner, "tool": "pyinstaller", "mode": "onefile", "name": f"zinc-{suffix}{ext}",
                          "experimental": plat == "linux-arm"})
            build.append({"os": runner, "tool": "pyinstaller", "mode": "onedir", "name": f"zinc-{suffix}-folder.zip",
                          "experimental": plat == "linux-arm"})
        if nuitka:
            build.append({"os": runner, "tool": "nuitka", "mode": "onefile", "name": f"zinc-nuitka-{suffix}{ext}",
                          "experimental": True})
            build.append({"os": runner, "tool": "nuitka", "mode": "standalone", "name": f"zinc-nuitka-{suffix}-folder.zip",
                          "experimental": True})
    return {
        "mode": "release" if release else ("manual" if manual else "ci"),
        "test_matrix": test_matrix,
        "build_matrix": build,
        "has_builds": bool(build),
        "run_mutation": mutation,
        "run_live": live,
        "run_security": (release or manual) and "security" not in skip,
        "run_package": release or manual,
        "run_release": release,
        "skipped": skip,
        "expected_assets": [b["name"] for b in build],
    }


def write_outputs(result: dict[str, object], path: str | None) -> None:
    lines = []
    for key, value in result.items():
        text = json.dumps(value, separators=(",", ":")) if not isinstance(value, str) else value
        if isinstance(value, bool):
            text = "true" if value else "false"
        lines.append(f"{key}={text}")
    out = "\n".join(lines) + "\n"
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(out)
    else:
        sys.stdout.write(out)


def main() -> None:
    result = plan(dict(os.environ))
    write_outputs(result, os.environ.get("GITHUB_OUTPUT"))
    if os.environ.get("PLAN_JSON"):
        with open(os.environ["PLAN_JSON"], "w", encoding="utf-8") as f:
            json.dump(result, f, indent=1)


if __name__ == "__main__":
    main()
