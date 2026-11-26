"""Turn everything a release run produced into one honest REPORT.md (and SHA256SUMS.txt).

    python tools/report.py --reports reports --assets assets --plan reports/plan.json \\
        --out REPORT.md --sums SHA256SUMS.txt --tag v0.1.0 --sha abc123 --repo me/zinc --run-url https://...

Inputs it understands (all optional; a missing one is reported as "not run", never silently as "fine"):
    reports/junit-<os>-<python>.xml     one per test job            reports/coverage.json     coverage.py json
    reports/build-<asset>.json          from build_binary.py        reports/smoke-<asset>.json  from smoke.py
    reports/mutation.json               from mutate.py              reports/live-check.json     from live_check.py
    reports/bandit.json  reports/pip-audit.json  reports/pip-audit-floor.json  reports/vermin.txt  reports/sbom.cdx.json
    reports/smoke-wheel.json            from smoke.py run on the installed wheel
    assets/*                            the files that will be attached to the release
    reports/plan.json                   from ci_plan.py (which assets and test jobs were expected)
"""
from __future__ import annotations

import argparse
import os
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

OK, WARN, BAD, SKIP = "✅", "⚠️", "❌", "⏭"


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def cell(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def table(header: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def human_size(n: int) -> str:
    return f"{n / 1_048_576:.1f} MB" if n >= 1_048_576 else f"{n / 1024:.0f} KB"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---- sections: each returns (verdict emoji, one-line summary, markdown body) ------------------------------
def section_tests(reports: Path, plan: dict):
    rows, total, failed, missing = [], 0, 0, []
    seen = set()
    for f in sorted(reports.glob("junit-*.xml")):
        m = re.match(r"junit-(.+)-(\d+\.\d+)\.xml$", f.name)
        osname, py = (m.group(1), m.group(2)) if m else (f.stem, "?")
        try:
            root = ET.parse(f).getroot()
        except ET.ParseError:
            rows.append([osname, py, "unreadable report", "", "", BAD])
            failed += 1
            continue
        suite = root if root.tag == "testsuite" else (root.find("testsuite") if root.find("testsuite") is not None else root)
        n = int(suite.get("tests", 0))
        bad = int(suite.get("failures", 0)) + int(suite.get("errors", 0))
        skipped = int(suite.get("skipped", 0))
        seen.add((osname, py))
        total += n
        failed += bad
        rows.append([osname, py, n - bad - skipped, bad, skipped, OK if bad == 0 and n else BAD])
    for job in plan.get("test_matrix", []):
        label = job.get("label", job["os"])
        if (label, job["python"]) not in seen:
            missing.append(f"{label} / py{job['python']}")
            rows.append([label, job["python"], "–", "–", "–", f"{BAD} no report (job did not finish)"])
    cov = load_json(reports / "coverage.json")
    pct = cov.get("totals", {}).get("percent_covered") if cov else None
    if not rows:
        return SKIP, "no test results found", "_No JUnit reports were found._"
    verdict = BAD if (failed or missing) else OK
    summary = f"{total} test runs across {len(seen)} job(s), {failed} failed" + (f", line+branch coverage {pct:.1f}%" if pct else "")
    body = table(["OS", "Python", "passed", "failed", "skipped", ""], rows)
    if pct:
        body += f"\n\nCoverage (Linux, Python 3.13, branches included): **{pct:.1f}%**."
    return verdict, summary, body


def section_binaries(reports: Path, assets: Path, plan: dict):
    expected = plan.get("expected_assets") or sorted(p.name for p in assets.glob("*") if p.is_file() and p.name not in
                                                     ("REPORT.md", "SHA256SUMS.txt"))
    experimental = {b["name"] for b in plan.get("build_matrix", []) if b.get("experimental")}
    if not expected:
        return SKIP, "no binaries were requested", "_This run did not build executables._"
    rows, hard_fail, soft_fail = [], 0, 0
    for name in expected:
        file = assets / name
        build = load_json(reports / f"build-{name}.json") or {}
        smoke = load_json(reports / f"smoke-{name}.json")
        failed_steps = [s["name"] for s in (smoke or {}).get("steps", []) if s["status"] == "failed"]
        skipped_steps = [s["name"] for s in (smoke or {}).get("steps", []) if s["status"] == "skipped"]
        exp = name in experimental or name.startswith("zinc-nuitka")
        if not file.exists():
            state, note = (WARN if exp else BAD), "not built (build failed or job did not run)"
        elif smoke is None:
            state, note = (WARN if exp else BAD), "built, but no smoke-test result"
        elif failed_steps or not smoke.get("ok"):
            state, note = (WARN if exp else BAD), "smoke test failed: " + ", ".join(failed_steps or ["no step passed"])
        else:
            state, note = OK, "smoke test passed" + (f" (skipped: {', '.join(skipped_steps)})" if skipped_steps else "")
        hard_fail += state == BAD
        soft_fail += state == WARN
        rows.append([name, (build.get("tool", "?") + " " + build.get("tool_version", "")).strip(),
                     human_size(file.stat().st_size) if file.exists() else "–", f"{build.get('seconds', '–')}s", state + " " + note])
    verdict = BAD if hard_fail else (WARN if soft_fail else OK)
    summary = f"{len(expected) - hard_fail - soft_fail}/{len(expected)} executables built and smoke-tested"
    body = table(["file", "built with", "size", "build time", "result"], rows)
    body += ("\n\nNuitka builds and the Linux-arm build are **experimental**: the author has not run them, so a failure there "
             "is a warning, not a blocker. Executables are built per operating system (no cross-compiling).")
    return verdict, summary, body


def section_package(reports: Path, assets: Path, plan: dict):
    if not plan.get("run_package"):
        return SKIP, "not requested", "_This run did not build the Python package (wheel + sdist)._"
    wheels, sdists = sorted(assets.glob("*.whl")), sorted(assets.glob("*.tar.gz"))
    smoke = load_json(reports / "smoke-wheel.json")
    failed = [s["name"] for s in (smoke or {}).get("steps", []) if s["status"] == "failed"]
    rows = [[p.name, human_size(p.stat().st_size)] for p in wheels + sdists]
    problems = []
    if not wheels:
        problems.append("no wheel was built")
    if not sdists:
        problems.append("no sdist was built")
    if smoke is None:
        problems.append("the wheel was not smoke-tested")
    elif failed or not smoke.get("ok"):
        problems.append("the installed wheel failed its smoke test: " + ", ".join(failed or ["no step passed"]))
    body = (table(["file", "size"], rows) + "\n\n" if rows else "") + (
        "Each file was checked with `twine check`, installed into a clean virtual environment, and that installed `zinc` "
        "ran the same smoke test as the executables." if not problems else "Problems: " + "; ".join(problems) + ".")
    if problems:
        return BAD, "; ".join(problems), body
    return OK, f"wheel + sdist built, installed in a clean environment and smoke-tested", body


def section_mutation(reports: Path, plan: dict):
    data = load_json(reports / "mutation.json")
    if not data:
        return SKIP, "not run" if not plan.get("run_mutation") else "was requested but produced no result", \
            "_Mutation testing did not run in this release._"
    survivors = [r for r in data["results"] if r["status"] in ("SURVIVED", "BROKEN")]
    summary = f"{data['caught']}/{data['total']} deliberate bugs were caught by the tests"
    body = f"{summary}. Each \"mutant\" is the code with one small deliberate bug; a surviving mutant means no test notices that bug."
    if survivors:
        body += "\n\n" + table(["id", "file", "the bug nobody noticed", "status"],
                               [[r["id"], r["file"], r["bug"], r["status"]] for r in survivors])
    return (WARN if survivors else OK), summary, body


def section_live(reports: Path, plan: dict):
    data = load_json(reports / "live-check.json")
    if not data:
        return SKIP, "not run" if not plan.get("run_live") else "was requested but produced no result", \
            "_The real-world check did not run in this release._"
    icon = {"passed": OK, "failed": BAD, "info": "ℹ️", "skipped": SKIP}
    rows = [[s["name"], icon.get(s["status"], s["status"]) + " " + s["status"], s["detail"], f"{s['seconds']}s"] for s in data["steps"]]
    failed = [s for s in data["steps"] if s["status"] == "failed"]
    passed = [s for s in data["steps"] if s["status"] == "passed"]
    body = table(["check", "result", "what happened", "time"], rows)
    facts = data.get("facts", {})
    if facts:
        body += "\n\n**Facts measured on a real quick tunnel:**\n\n" + "\n".join(f"- `{k}`: {v}" for k, v in facts.items())
    verdict = WARN if failed else (OK if passed else SKIP)
    summary = f"{len(passed)} passed, {len(failed)} failed, {sum(s['status'] == 'skipped' for s in data['steps'])} skipped"
    if failed:
        body += ("\n\nA failure here is a **warning, not a release blocker**: quick tunnels are a free best-effort service and "
                 "can fail for reasons unrelated to zinc. Re-run before drawing conclusions.")
    return verdict, summary, body


def section_security(reports: Path):
    lines, short, worst = [], [], OK                      # `lines`: bullets with their detail lines right below them
    bandit = load_json(reports / "bandit.json")
    if bandit is not None:
        sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in bandit.get("results", []):
            sev[r.get("issue_severity", "LOW")] = sev.get(r.get("issue_severity", "LOW"), 0) + 1
        lines.append(f"- **bandit** (static security scan of zinc's own code): high {sev['HIGH']}, medium {sev['MEDIUM']}, low {sev['LOW']}")
        short.append(f"bandit {sev['HIGH']} high / {sev['MEDIUM']} medium")
        if sev["HIGH"] or sev["MEDIUM"]:
            worst = WARN
            lines += [f"  - `{r['filename']}:{r['line_number']}` {r['test_id']} {r['issue_text']}" for r in bandit["results"]
                      if r.get("issue_severity") in ("HIGH", "MEDIUM")][:15]
    for label, fname in (("pip-audit", "pip-audit.json"), ("pip-audit-floor", "pip-audit-floor.json")):
        audit = load_json(reports / fname)
        if audit is None:
            continue
        deps = audit.get("dependencies", audit) if isinstance(audit, dict) else audit
        vulns = [(d.get("name"), d.get("version"), [v.get("id") for v in d.get("vulns", [])]) for d in deps if d.get("vulns")]
        what = ("known vulnerabilities in the newest dependencies a user installs" if label == "pip-audit" else
                "known vulnerabilities in the OLDEST dependency versions pyproject still allows")
        lines.append(f"- **{label}** ({what}): {len(vulns)} affected package(s) out of {len(deps)}")
        short.append(f"{label} {len(vulns)} vulnerable")
        if vulns:
            worst = WARN
            lines += [f"  - {n} {v}: {', '.join(ids[:6])}{' …' if len(ids) > 6 else ''}" for n, v, ids in vulns]
    vermin = reports / "vermin.txt"
    if vermin.exists():
        m = re.search(r"Minimum required versions?:\s*(.+)", vermin.read_text(encoding="utf-8", errors="replace"))
        found = m.group(1).strip() if m else "see vermin.txt"
        lines.append(f"- **vermin** (oldest Python the code can run on, judged by syntax and standard-library use): {found}")
        short.append(f"vermin {found}")
    if (reports / "sbom.cdx.json").exists():
        lines.append("- **SBOM** (list of every dependency, CycloneDX JSON): attached as `sbom.cdx.json`")
        short.append("SBOM")
    if not lines:
        return SKIP, "not run", "_No security scans were produced._"
    return worst, " · ".join(short), "\n".join(lines)


# ---- the whole report ---------------------------------------------------------------------------------------
def build_report(reports: Path, assets: Path, plan: dict, meta: dict) -> tuple[str, dict]:
    sections = [
        ("Tests", *section_tests(reports, plan)),
        ("Python package", *section_package(reports, assets, plan)),
        ("Executables", *section_binaries(reports, assets, plan)),
        ("Mutation testing", *section_mutation(reports, plan)),
        ("Real-world check", *section_live(reports, plan)),
        ("Security scans", *section_security(reports)),
    ]
    verdicts = {name: v for name, v, _s, _b in sections}
    blockers = [n for n, v in verdicts.items() if v == BAD]
    overall = "NOT READY — fix the ❌ items first" if blockers else (
        "Ready, with warnings to read" if WARN in verdicts.values() else "Ready")
    head = f"# zinc {meta.get('tag') or ''} — release report".replace("  ", " ")
    info = [f"- commit: `{(meta.get('sha') or 'unknown')[:12]}`", f"- generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}"]
    if meta.get("run_url"):
        info.append(f"- workflow run: {meta['run_url']}")
    if plan.get("skipped"):
        info.append(f"- left out on purpose (ZINC_RELEASE_SKIP): {', '.join(plan['skipped'])}")
    out = [head, "", "\n".join(info), "", f"## Verdict: {overall}", "",
           table(["area", "", "summary"], [[n, v, s] for n, v, s, _b in sections]), ""]
    for name, _v, _s, body in sections:
        out += [f"## {name}", "", body, ""]
    files = sorted(p for p in assets.glob("*") if p.is_file())
    if files:
        out += ["## Downloads and checksums", "",
                table(["file", "size", "sha256"], [[p.name, human_size(p.stat().st_size), f"`{sha256_of(p)}`"] for p in files]), "",
                "Verify a download: `sha256sum -c SHA256SUMS.txt` (macOS: `shasum -a 256 -c SHA256SUMS.txt`; "
                "Windows PowerShell: `Get-FileHash <file>`)."]
        if meta.get("repo") and meta.get("attested"):
            out += [f"Build provenance is attested: `gh attestation verify <file> -R {meta['repo']}`."]
        out += [""]
    out += ["## What this report does not prove", "",
            "- Nobody has used the terminal UI by hand on Windows or macOS; the smoke test only starts it and quits it.",
            "- Long-running behaviour (days of uptime, hundreds of tunnels) is untested.",
            "- Passing mutation tests means the *known* bugs are caught, not that no bugs exist.",
            "- Cloudflare quick tunnels are a free, best-effort, testing-grade service with no uptime guarantee.", ""]
    return "\n".join(out), {"verdicts": verdicts, "overall": overall, "blockers": blockers}


def write_sums(assets: Path, out: Path) -> None:
    lines = [f"{sha256_of(p)}  {p.name}" for p in sorted(assets.glob("*")) if p.is_file()]
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--assets", default="assets")
    ap.add_argument("--plan", default="")
    ap.add_argument("--out", default="REPORT.md")
    ap.add_argument("--sums", default="SHA256SUMS.txt")
    ap.add_argument("--tag", default="")
    ap.add_argument("--sha", default="")
    ap.add_argument("--repo", default="")
    ap.add_argument("--run-url", default="")
    ap.add_argument("--attested", action="store_true")
    ap.add_argument("--strict", action="store_true", help="exit 1 when the verdict has a blocker")
    a = ap.parse_args(argv)
    reports, assets = Path(a.reports), Path(a.assets)
    assets.mkdir(parents=True, exist_ok=True)
    plan = (load_json(Path(a.plan)) if a.plan else None) or {}
    write_sums(assets, Path(a.sums))
    text, info = build_report(reports, assets, plan, {"tag": a.tag, "sha": a.sha, "repo": a.repo, "run_url": a.run_url,
                                                        "attested": a.attested})
    Path(a.out).write_text(text, encoding="utf-8")
    print(text)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"ready={'false' if info['blockers'] else 'true'}\noverall={info['overall']}\n")
    return 1 if (a.strict and info["blockers"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
