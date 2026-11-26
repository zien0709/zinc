"""The release tooling (tools/*.py) is code too: it gets tests, because a broken CI run costs real minutes."""
import asyncio
import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import assemble              # noqa: E402
import build_binary          # noqa: E402
import ci_plan               # noqa: E402
import floor_requirements    # noqa: E402
import live_check            # noqa: E402
import mutate                # noqa: E402
import report                # noqa: E402
import smoke                 # noqa: E402

FAKE_ZINC = [sys.executable, str(ROOT / "tests" / "fake_zinc.py")]
FAKE_CF = ROOT / "tests" / "fake_cloudflared.py"


# ======================================== ci_plan ========================================
def plan(**env):
    return ci_plan.plan({k.upper(): v for k, v in env.items()})


def test_a_version_tag_turns_everything_on_whatever_the_inputs_say():
    p = plan(event="push", ref="refs/tags/v1.2.3", platforms="linux", nuitka="false", mutation="false", live="false")
    assert p["mode"] == "release" and p["run_release"] and p["run_mutation"] and p["run_live"]
    assert [j["os"] for j in p["test_matrix"]].count("ubuntu-latest") == 5            # 4 Pythons + the oldest-dependencies job
    assert {"windows-latest", "macos-latest"} <= {j["os"] for j in p["test_matrix"]}
    assert len(p["build_matrix"]) == 12 and len(set(p["expected_assets"])) == 12
    assert {b["tool"] for b in p["build_matrix"]} == {"pyinstaller", "nuitka"}


def test_only_v_tags_are_releases_and_exactly_one_test_job_measures_coverage():
    assert not plan(event="push", ref="refs/tags/nightly")["run_release"]
    assert plan(event="push", ref="refs/tags/v0")["run_release"]
    for ref in ("refs/tags/v1.0.0", "refs/heads/main"):
        jobs = plan(event="push", ref=ref)["test_matrix"]
        assert [(j["os"], j["python"]) for j in jobs if j["cov"]] == [("ubuntu-latest", "3.13")]


def test_the_oldest_dependencies_are_tested_only_on_full_runs_and_have_their_own_report_name():
    full = plan(event="push", ref="refs/tags/v1.0.0")["test_matrix"]
    floors = [j for j in full if j["floor"]]
    assert len(floors) == 1 and floors[0]["label"] == "ubuntu-floor" and not floors[0]["cov"]
    assert all(j["label"] == j["os"] and not j["floor"] for j in full if not j["floor"])
    for ref, kw in (("refs/heads/main", {}), ("refs/heads/main", {"tests": "min"})):
        assert not any(j["floor"] for j in plan(event="push", ref=ref, **kw)["test_matrix"])
    manual = plan(event="workflow_dispatch", ref="refs/heads/main", tests="full")["test_matrix"]
    assert sum(j["floor"] for j in manual) == 1


def test_the_plan_can_also_be_written_as_json_for_the_final_report(tmp_path, monkeypatch):
    for k in ("PLAN_JSON", "GITHUB_OUTPUT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("EVENT", "push")
    monkeypatch.setenv("REF", "refs/tags/v2.0.0")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    ci_plan.main()
    assert not (tmp_path / "plan.json").exists()
    monkeypatch.setenv("PLAN_JSON", str(tmp_path / "plan.json"))
    ci_plan.main()
    saved = json.loads((tmp_path / "plan.json").read_text())
    assert saved["run_release"] is True and saved["test_matrix"] == plan(event="push", ref="refs/tags/v2.0.0")["test_matrix"]
    assert "run_release=true" in (tmp_path / "out.txt").read_text()


def test_skip_leaves_things_out_even_on_a_release_and_a_typo_is_an_error():
    p = plan(event="push", ref="refs/tags/v1.0.0", skip="mutation, macos;nuitka")
    assert p["skipped"] == ["macos", "mutation", "nuitka"] and p["run_release"] and p["run_live"]
    assert not p["run_mutation"] and "macos-latest" not in {j["os"] for j in p["test_matrix"]}
    assert {b["tool"] for b in p["build_matrix"]} == {"pyinstaller"} and "macos-latest" not in {b["os"] for b in p["build_matrix"]}
    q = plan(event="push", ref="refs/tags/v1.0.0", skip="floor,windows,security,pyinstaller,live")
    assert not q["run_security"] and not q["run_live"] and not any(j["floor"] for j in q["test_matrix"])
    assert {j["os"] for j in q["test_matrix"]} == {"ubuntu-latest", "macos-latest"}
    assert {b["tool"] for b in q["build_matrix"]} == {"nuitka"} and {b["os"] for b in q["build_matrix"]} == {"ubuntu-latest", "macos-latest"}
    with pytest.raises(SystemExit, match="mutatoin"):
        plan(event="push", ref="refs/tags/v1.0.0", skip="mutatoin")
    assert plan(event="push", ref="refs/heads/main", skip="")["skipped"] == []


def test_security_scans_and_the_package_check_run_on_releases_and_manual_runs_but_not_on_every_push():
    assert [(plan(event=e, ref=r)["run_security"], plan(event=e, ref=r)["run_package"]) for e, r in (
        ("push", "refs/heads/main"), ("pull_request", "refs/pull/1/merge"), ("push", "refs/tags/v1.0.0"),
        ("workflow_dispatch", "refs/heads/main"))] == [(False, False), (False, False), (True, True), (True, True)]


def test_a_plain_push_is_cheap_and_builds_nothing():
    p = plan(event="push", ref="refs/heads/main")
    assert p["mode"] == "ci" and not p["has_builds"] and not p["run_release"] and not p["run_mutation"]
    assert [j["os"] for j in p["test_matrix"]] == ["ubuntu-latest", "ubuntu-latest"]


def test_a_manual_run_does_only_what_was_ticked():
    p = plan(event="workflow_dispatch", ref="refs/heads/main", platforms="linux+windows", tests="full", nuitka="true",
             mutation="true", live="false")
    assert p["mode"] == "manual" and not p["run_release"] and p["run_mutation"] and not p["run_live"]
    assert {b["os"] for b in p["build_matrix"]} == {"ubuntu-latest", "windows-latest"}      # no macOS (costs 10x)
    assert len(p["build_matrix"]) == 8
    q = plan(event="workflow_dispatch", ref="refs/heads/main")                              # nothing ticked
    assert q["has_builds"] and {b["tool"] for b in q["build_matrix"]} == {"pyinstaller"} and q["run_live"]


def test_extra_arm_builds_are_marked_experimental():
    p = plan(event="workflow_dispatch", ref="refs/heads/x", extra_arm="true")
    arm = [b for b in p["build_matrix"] if b["os"] == "ubuntu-24.04-arm"]
    assert arm and all(b["experimental"] for b in arm)


@pytest.mark.parametrize("bad", [{"platforms": "beos"}, {"tests": "some"}])
def test_nonsense_choices_stop_the_run_early(bad):
    with pytest.raises(SystemExit):
        plan(event="workflow_dispatch", ref="refs/heads/x", **bad)


def test_every_planned_build_is_something_build_binary_accepts():
    p = plan(event="push", ref="refs/tags/v0.0.1")
    for b in p["build_matrix"]:
        assert b["name"].endswith(".zip") == (b["mode"] in ("onedir", "standalone"))
        assert b["name"].endswith(".exe") == (b["os"] == "windows-latest" and not b["name"].endswith(".zip"))
        build_binary.plan(b["tool"], b["mode"], Path("/w"))                    # raises SystemExit on a bad combination


def test_outputs_are_written_as_key_value_lines_with_compact_json(tmp_path):
    out = tmp_path / "gh_output"
    ci_plan.write_outputs(plan(event="push", ref="refs/tags/v1.0.0"), str(out))
    kv = dict(line.split("=", 1) for line in out.read_text().splitlines())
    assert kv["run_release"] == "true" and kv["mode"] == "release"
    assert json.loads(kv["test_matrix"])[0]["python"] == "3.10" and " " not in kv["test_matrix"]


# ======================================== build_binary ========================================
def test_pyinstaller_recipe_is_the_verified_one():
    p = build_binary.plan("pyinstaller", "onefile", Path("/w"), python="py", has_maxmind=False)
    cmd = p["cmd"]
    assert cmd[:3] == ["py", "-m", "PyInstaller"] and "--onefile" in cmd
    assert cmd[cmd.index("--collect-all") + 1] == "textual" and "segno" in cmd
    assert cmd[-1].endswith(os.path.join("packaging", "entry.py")) and Path(cmd[-1]).exists()
    assert "maxminddb" not in " ".join(cmd)
    assert "maxminddb" in " ".join(build_binary.plan("pyinstaller", "onedir", Path("/w"), has_maxmind=True)["cmd"])


def test_the_launcher_imports_zinc_as_a_package_so_relative_imports_work():
    text = (ROOT / "packaging" / "entry.py").read_text()
    assert "from zinc.__main__ import main" in text
    assert "from ." in (ROOT / "zinc" / "__main__.py").read_text()          # that is WHY the launcher exists


def test_nuitka_recipe_uses_the_current_flag_style_and_includes_the_ui_toolkit():
    for mode in ("onefile", "standalone"):
        cmd = build_binary.plan("nuitka", mode, Path("/w"), python="py", jobs=3, has_maxmind=False)["cmd"]
        assert f"--mode={mode}" in cmd and "--onefile" not in cmd and "--standalone" not in cmd     # old style is gone
        assert {"--include-package=textual", "--include-package-data=textual", "--include-package=zinc",
                "--assume-yes-for-downloads", "--jobs=3"} <= set(cmd)
    assert build_binary.NUITKA_PIN.startswith("nuitka==")


def test_folder_builds_are_zipped_under_one_folder_keeping_the_executable_bit(tmp_path):
    folder = tmp_path / "dist"
    (folder / "lib").mkdir(parents=True)
    exe = folder / "zinc"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    (folder / "lib" / "x.bin").write_bytes(b"1")
    build_binary.zip_folder(folder, tmp_path / "out" / "zinc.zip")
    with zipfile.ZipFile(tmp_path / "out" / "zinc.zip") as z:
        assert sorted(z.namelist()) == ["zinc/lib/x.bin", "zinc/zinc"]
        assert stat.S_IMODE(z.getinfo("zinc/zinc").external_attr >> 16) & 0o111


def test_names_must_agree_with_the_build_mode(tmp_path):
    for name, mode in (("zinc-x.zip", "onefile"), ("zinc-x", "onedir")):
        with pytest.raises(SystemExit):
            build_binary.main(["--tool", "pyinstaller", "--mode", mode, "--name", name, "--dry-run",
                               "--work", str(tmp_path)])


# ======================================== assemble ========================================
def put(root, rel, data=b"x"):
    f = root / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(data)


def test_artifacts_are_sorted_into_reports_and_release_assets_whatever_their_folder_depth(tmp_path):
    b = tmp_path / "bundle"
    put(b, "reports-test-a/junit-a-3.13.xml")
    put(b, "reports-test-a/reports/coverage.json")                  # nested one level deeper: still just a name
    put(b, "dist-zinc-linux-x64/zinc-linux-x64", b"BIN")
    put(b, "dist-package/zinc_link-0.1.0-py3-none-any.whl")
    put(b, "plan/plan.json")                                        # not ours: left alone, but mentioned
    got = assemble.assemble(b, tmp_path / "r", tmp_path / "a")
    assert sorted(p.name for p in (tmp_path / "r").iterdir()) == ["coverage.json", "junit-a-3.13.xml"]
    assert sorted(p.name for p in (tmp_path / "a").iterdir()) == ["zinc-linux-x64", "zinc_link-0.1.0-py3-none-any.whl"]
    assert (tmp_path / "a" / "zinc-linux-x64").read_bytes() == b"BIN"
    assert got["ignored"] == ["plan/plan.json"] and "plan.json" not in {p.name for p in (tmp_path / "r").iterdir()}


def test_two_different_files_with_one_name_are_an_error_but_a_duplicate_is_fine(tmp_path, capsys):
    b = tmp_path / "bundle"
    put(b, "dist-one/zinc", b"A")
    put(b, "dist-two/zinc", b"B")
    with pytest.raises(assemble.Collision, match="'zinc'"):
        assemble.assemble(b, tmp_path / "r", tmp_path / "a")
    assert assemble.main(["--bundle", str(b), "--reports", str(tmp_path / "r2"), "--assets", str(tmp_path / "a2")]) == 2
    assert "two different files" in capsys.readouterr().err
    (b / "dist-two" / "zinc").write_bytes(b"A")                    # identical now: not a conflict
    assert assemble.main(["--bundle", str(b), "--reports", str(tmp_path / "r3"), "--assets", str(tmp_path / "a3")]) == 0
    assert (tmp_path / "a3" / "zinc").read_bytes() == b"A"


def test_an_empty_or_missing_bundle_gives_empty_folders_not_a_crash(tmp_path):
    for name in ("nope", "empty"):
        (tmp_path / "empty").mkdir(exist_ok=True)
        got = assemble.assemble(tmp_path / name, tmp_path / f"r-{name}", tmp_path / f"a-{name}")
        assert got == {"reports": [], "assets": [], "ignored": []}
        assert (tmp_path / f"r-{name}").is_dir() and (tmp_path / f"a-{name}").is_dir()


# ======================================== smoke ========================================
def test_smoke_passes_a_well_behaved_program():
    r = smoke.run_steps(FAKE_ZINC)
    assert [(s["name"], s["status"]) for s in r["steps"]] == [
        ("version", "passed"), ("help-settings", "passed"), ("config-path", "passed"), ("bad-argument", "passed"),
        ("tui-start-and-quit", "passed" if sys.platform != "win32" else "skipped")], r
    assert r["ok"]


@pytest.mark.parametrize("what,failing", [("version", "version"), ("version_exit", "version"), ("tui_exit", "tui-start-and-quit"),
                                          ("help", "help-settings"), ("config", "config-path"),
                                          ("argument", "bad-argument"), ("tui_crash", "tui-start-and-quit"),
                                          ("tui_silent", "tui-start-and-quit")])
@pytest.mark.skipif(sys.platform == "win32", reason="the UI step needs a pty")
def test_smoke_notices_each_kind_of_breakage(monkeypatch, what, failing):
    monkeypatch.setenv("FAKE_ZINC_BREAK", what)
    r = smoke.run_steps(FAKE_ZINC)
    assert [s["name"] for s in r["steps"] if s["status"] == "failed"] == [failing] and not r["ok"]


@pytest.mark.skipif(sys.platform == "win32", reason="the UI step needs a pty")
def test_smoke_does_not_hang_on_a_program_that_ignores_ctrl_q(monkeypatch):
    monkeypatch.setenv("FAKE_ZINC_BREAK", "tui_hang")
    with __import__("tempfile").TemporaryDirectory() as tmp:
        ok, detail = smoke.step_tui(FAKE_ZINC, {**os.environ, "XDG_CONFIG_HOME": tmp}, Path(tmp),
                                    start_timeout=3, quit_timeout=2)
    assert ok is False and "did not quit" in detail


def test_a_skipped_step_is_never_counted_as_a_pass():
    only_skipped = smoke.run_steps(FAKE_ZINC, steps=[("x", lambda *a: (None, "no pty"))])
    assert only_skipped["steps"][0]["status"] == "skipped" and only_skipped["ok"] is False
    mixed = smoke.run_steps(FAKE_ZINC, steps=[("a", lambda *a: (True, "")), ("b", lambda *a: (None, ""))])
    assert mixed["ok"] is True


def test_a_crashing_step_is_a_failing_step_not_a_crash():
    r = smoke.run_steps(FAKE_ZINC, steps=[("boom", lambda *a: 1 / 0)])
    assert r["steps"][0]["status"] == "failed" and "ZeroDivisionError" in r["steps"][0]["detail"]


@pytest.mark.skipif(sys.platform == "win32", reason="the UI step needs a pty")
def test_the_real_zinc_passes_its_own_smoke_test():
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "smoke.py"), "--", sys.executable, "-m", "zinc"],
                       cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.count("✅") == 5


# ======================================== live_check ========================================
def test_a_crashing_check_and_a_leaked_secret_are_both_contained():
    async def go():
        rep = live_check.Report(["hunter2-secret"])

        async def crashes():
            raise RuntimeError("could not reach https://api.example/?key=hunter2-secret")
        await rep.step("crash", crashes)
        await rep.step("fine", lambda: asyncio.sleep(0, ("passed", "all good")))
        return rep.result()
    r = asyncio.run(go())
    assert [s["status"] for s in r["steps"]] == ["failed", "passed"] and r["ok"] is False
    assert "hunter2-secret" not in json.dumps(r) and "***" in r["steps"][0]["detail"]


@pytest.mark.skipif(sys.platform == "win32", reason="uses a shell-script stand-in for cloudflared")
def test_live_check_survives_a_cloudflared_whose_tunnels_never_answer_and_never_leaks_keys(tmp_path):
    wrapper = tmp_path / "cloudflared"
    wrapper.write_text(f'#!/bin/sh\nexec {sys.executable} {FAKE_CF} "$@"\n')
    wrapper.chmod(0o755)
    out = tmp_path / "live.json"
    env = {**os.environ, "ZINC_VT_KEY": "vt-secret-key-123", "ZINC_PROVIDER_TIMEOUT_S": "3",
           "ZINC_WEBHOOK_URL": "https://hooks.example/very-secret-path"}
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "live_check.py"), "--cloudflared", str(wrapper),
                        "--reach-within", "3", "--links", "2", "--json", str(out)],
                       env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr                            # never fails the build unless --strict
    data = json.loads(out.read_text())
    status = {s["name"]: s["status"] for s in data["steps"]}
    assert status["cloudflared-installed"] == "passed" and status["tunnel-starts"] == "passed"
    assert status["public-redirect"] == "failed"                             # the fake hostname does not exist
    assert status["hard-destroy-stops-answering"] == "skipped"               # nothing to compare when it never answered
    assert status["provider-safe-browsing"] == "skipped" and status["provider-urlhaus"] == "skipped"
    blob = r.stdout + r.stderr + out.read_text()
    assert "vt-secret-key-123" not in blob and "very-secret-path" not in blob
    strict = subprocess.run([sys.executable, str(ROOT / "tools" / "live_check.py"), "--skip-tunnel",
                             "--skip-providers", "--strict"], env=env, capture_output=True, text=True, timeout=60)
    assert strict.returncode == 0                                            # nothing ran, nothing failed


# ======================================== report ========================================
def fixture_run(tmp_path, *, test_fail=False, drop_windows=False, nuitka_ok=False, survivors=False, live_fail=True):
    reports, assets = tmp_path / "reports", tmp_path / "assets"
    reports.mkdir()
    assets.mkdir()

    def junit(name, tests, failures=0, skipped=0):
        (reports / name).write_text(f'<?xml version="1.0"?><testsuites><testsuite name="pytest" tests="{tests}" '
                                    f'failures="{failures}" errors="0" skipped="{skipped}"/></testsuites>')
    junit("junit-ubuntu-latest-3.13.xml", 584, failures=2 if test_fail else 0, skipped=1)
    if not drop_windows:
        junit("junit-windows-latest-3.12.xml", 580)
    (reports / "coverage.json").write_text(json.dumps({"totals": {"percent_covered": 96.4}}))
    plan_ = {"test_matrix": [{"os": "ubuntu-latest", "python": "3.13"}, {"os": "windows-latest", "python": "3.12"}],
             "expected_assets": ["zinc-linux-x64", "zinc-nuitka-linux-x64"],
             "build_matrix": [{"name": "zinc-linux-x64", "experimental": False}, {"name": "zinc-nuitka-linux-x64", "experimental": True}],
             "run_mutation": True, "run_live": True}
    (assets / "zinc-linux-x64").write_bytes(b"binary" * 1000)
    (reports / "build-zinc-linux-x64.json").write_text(json.dumps({"tool": "pyinstaller", "tool_version": "6.1", "seconds": 61}))
    good = {"ok": True, "steps": [{"name": "version", "status": "passed", "detail": "", "seconds": 1}]}
    (reports / "smoke-zinc-linux-x64.json").write_text(json.dumps(good))
    if nuitka_ok:
        (assets / "zinc-nuitka-linux-x64").write_bytes(b"n" * 10)
        (reports / "smoke-zinc-nuitka-linux-x64.json").write_text(json.dumps(good))
    res = [{"id": "S1", "status": "killed", "info": "", "file": "zinc/server.py", "bug": "wrong suffix works"}]
    if survivors:
        res.append({"id": "L7", "status": "SURVIVED", "info": "", "file": "zinc/locale.py", "bug": "a | b order"})
    (reports / "mutation.json").write_text(json.dumps({"total": len(res), "caught": 1, "needs_attention": len(res) - 1, "results": res}))
    steps = [{"name": "tunnel-starts", "status": "passed", "detail": "ok", "seconds": 5},
             {"name": "country-header", "status": "info", "detail": "none", "seconds": 0}]
    if live_fail:
        steps.append({"name": "public-redirect", "status": "failed", "detail": "never answered", "seconds": 90})
    (reports / "live-check.json").write_text(json.dumps({"steps": steps, "facts": {"tunnel_start_s": 4.2}}))
    (reports / "bandit.json").write_text(json.dumps({"results": [
        {"issue_severity": "MEDIUM", "filename": "zinc/x.py", "line_number": 3, "test_id": "B108", "issue_text": "tmp"}]}))
    (reports / "pip-audit.json").write_text(json.dumps({"dependencies": [{"name": "aiohttp", "version": "3.9", "vulns": []}]}))
    (reports / "vermin.txt").write_text("Minimum required versions: 3.8\n")
    return reports, assets, plan_


def test_a_job_is_recognised_by_its_label_not_by_its_runner(tmp_path):
    reports, assets, plan_ = fixture_run(tmp_path)
    plan_["test_matrix"].append({"os": "ubuntu-latest", "python": "3.13", "label": "ubuntu-floor", "floor": True})
    text, info = report.build_report(reports, assets, plan_, {})
    assert info["verdicts"]["Tests"] == "❌" and "| ubuntu-floor | 3.13 | – |" in text and "no report (job did not finish)" in text
    (reports / "junit-ubuntu-floor-3.13.xml").write_text('<testsuites><testsuite tests="580" failures="0" errors="0" skipped="0"/></testsuites>')
    text, info = report.build_report(reports, assets, plan_, {})
    assert info["verdicts"]["Tests"] == "✅" and "| ubuntu-floor | 3.13 | 580 |" in text and "no report" not in text


def test_the_python_package_is_checked_when_it_was_requested(tmp_path):
    reports, assets, plan_ = fixture_run(tmp_path)
    assert report.build_report(reports, assets, plan_, {})[1]["verdicts"]["Python package"] == report.SKIP       # not requested
    plan_["run_package"] = True
    text, info = report.build_report(reports, assets, plan_, {})
    assert info["verdicts"]["Python package"] == "❌"
    assert "no wheel was built" in text and "no sdist was built" in text and "not smoke-tested" in text
    (assets / "zinc_link-0.1.0-py3-none-any.whl").write_bytes(b"w")
    (assets / "zinc_link-0.1.0.tar.gz").write_bytes(b"s")
    (reports / "smoke-wheel.json").write_text(json.dumps({"ok": False, "steps": [
        {"name": "tui-start-and-quit", "status": "failed", "detail": "", "seconds": 1}]}))
    text, info = report.build_report(reports, assets, plan_, {})
    assert info["verdicts"]["Python package"] == "❌" and "failed its smoke test: tui-start-and-quit" in text
    assert "no wheel" not in text and "zinc_link-0.1.0-py3-none-any.whl" in text
    (reports / "smoke-wheel.json").write_text(json.dumps({"ok": True, "steps": [
        {"name": "version", "status": "passed", "detail": "", "seconds": 1}]}))
    text, info = report.build_report(reports, assets, plan_, {})
    assert info["verdicts"]["Python package"] == "✅" and "Problems" not in text


def test_a_vulnerable_old_dependency_floor_is_reported_by_name(tmp_path):
    reports, assets, plan_ = fixture_run(tmp_path)
    (reports / "pip-audit-floor.json").write_text(json.dumps({"dependencies": [
        {"name": "aiohttp", "version": "3.10.11", "vulns": [{"id": f"PYSEC-{i}"} for i in range(9)]},
        {"name": "rich", "version": "13.9.4", "vulns": []}]}))
    text, _ = report.build_report(reports, assets, plan_, {})
    assert "OLDEST dependency versions" in text and "1 affected package(s) out of 2" in text
    assert "aiohttp 3.10.11: PYSEC-0, PYSEC-1, PYSEC-2, PYSEC-3, PYSEC-4, PYSEC-5 …" in text


def test_the_report_header_names_what_was_left_out_on_purpose(tmp_path):
    reports, assets, plan_ = fixture_run(tmp_path)
    assert "left out on purpose" not in report.build_report(reports, assets, plan_, {})[0]
    plan_["skipped"] = ["macos", "mutation"]
    assert "left out on purpose (ZINC_RELEASE_SKIP): macos, mutation" in report.build_report(reports, assets, plan_, {})[0]


def test_the_report_tells_github_whether_the_release_is_ready(tmp_path, monkeypatch):
    for broken, expect in ((True, "ready=false"), (False, "ready=true")):
        d = sub(tmp_path, f"run-{broken}")
        reports, assets, plan_ = fixture_run(d, test_fail=broken)
        (reports / "plan.json").write_text(json.dumps(plan_))
        out = d / "gh-output"
        monkeypatch.setenv("GITHUB_OUTPUT", str(out))
        assert report.main(["--reports", str(reports), "--assets", str(assets), "--plan", str(reports / "plan.json"),
                            "--out", str(d / "REPORT.md"), "--sums", str(d / "SUMS")]) == 0
        lines = out.read_text().splitlines()
        assert expect in lines and any(l.startswith("overall=") for l in lines)
        assert ("NOT READY" in out.read_text()) == broken


def sub(tmp_path, name):
    (tmp_path / name).mkdir()
    return tmp_path / name


def verdicts(tmp_path, **kw):
    reports, assets, plan_ = fixture_run(tmp_path, **kw)
    text, info = report.build_report(reports, assets, plan_, {"tag": "v0.1.0", "sha": "abcdef1234567890", "repo": "me/zinc",
                                                              "attested": True})
    return text, info


def test_report_marks_each_area_and_the_overall_verdict(tmp_path):
    text, info = verdicts(tmp_path)
    assert info["verdicts"] == {"Tests": "✅", "Python package": "⏭", "Executables": "⚠️", "Mutation testing": "✅",
                                "Real-world check": "⚠️", "Security scans": "⚠️"}
    assert info["overall"] == "Ready, with warnings to read" and info["blockers"] == []
    assert "96.4%" in text and "bandit" in text and "3.8" in text and "gh attestation verify" in text
    assert "zinc-nuitka-linux-x64" in text and "not built" in text and "What this report does not prove" in text


def test_a_failing_test_or_a_missing_test_job_blocks_the_release(tmp_path):
    _, info = verdicts(tmp_path, test_fail=True)
    assert info["verdicts"]["Tests"] == "❌" and info["blockers"] == ["Tests"] and info["overall"].startswith("NOT READY")
    text, info = verdicts(sub(tmp_path, "b"), drop_windows=True)
    assert info["verdicts"]["Tests"] == "❌" and "no report (job did not finish)" in text


def test_an_executable_that_is_not_experimental_must_exist_and_pass_its_smoke_test(tmp_path):
    reports, assets, plan_ = fixture_run(tmp_path)
    (assets / "zinc-linux-x64").unlink()
    assert report.build_report(reports, assets, plan_, {})[1]["verdicts"]["Executables"] == "❌"
    (assets / "zinc-linux-x64").write_bytes(b"x")
    (reports / "smoke-zinc-linux-x64.json").write_text(json.dumps({"ok": False, "steps": [
        {"name": "tui-start-and-quit", "status": "failed", "detail": "", "seconds": 1}]}))
    text, info = report.build_report(reports, assets, plan_, {})
    assert info["verdicts"]["Executables"] == "❌" and "tui-start-and-quit" in text


def test_surviving_mutants_and_failed_live_steps_are_warnings_listed_by_name(tmp_path):
    text, info = verdicts(tmp_path, survivors=True)
    assert info["verdicts"]["Mutation testing"] == "⚠️" and "L7" in text and "a \\| b order" in text   # pipe escaped
    assert "warning, not a release blocker" in text
    _, info = verdicts(sub(tmp_path, "ok"), live_fail=False, nuitka_ok=True)
    assert info["verdicts"]["Real-world check"] == "✅" and info["verdicts"]["Executables"] == "✅"


def test_an_empty_run_is_reported_as_not_run_never_as_fine(tmp_path):
    (tmp_path / "reports").mkdir()
    text, info = report.build_report(tmp_path / "reports", tmp_path / "assets", {}, {})
    assert set(info["verdicts"].values()) == {"⏭"} and info["blockers"] == []
    assert "not run" in text.lower() or "No JUnit" in text


def test_checksums_cover_every_asset_and_match(tmp_path):
    import hashlib
    reports, assets, plan_ = fixture_run(tmp_path)
    (assets / "b.zip").write_bytes(b"hello")
    sums = tmp_path / "SHA256SUMS.txt"
    report.write_sums(assets, sums)
    lines = dict(reversed(l.split("  ")) for l in sums.read_text().splitlines())
    assert lines["b.zip"] == hashlib.sha256(b"hello").hexdigest() and set(lines) == {"b.zip", "zinc-linux-x64"}
    assert lines["b.zip"] in report.build_report(reports, assets, plan_, {})[0]
    assert report.main(["--reports", str(reports), "--assets", str(assets), "--plan", str(tmp_path / "none.json"),
                        "--out", str(tmp_path / "R.md"), "--sums", str(tmp_path / "S.txt"), "--strict"]) in (0, 1)


# ======================================== floor_requirements ========================================
def test_floors_become_exact_pins_and_comments_are_ignored():
    text = ('[project]\nname = "x"\ndependencies = [\n    "aiohttp>=3.14.4",   # fixes CVEs\n    "Rich >= 13.9.4",\n]\n'
            '[project.optional-dependencies]\ndev = ["pytest>=8"]\n')
    assert floor_requirements.floors(text) == ["aiohttp==3.14.4", "Rich==13.9.4"]


@pytest.mark.parametrize("dep", ["aiohttp", "aiohttp>3.1", "aiohttp~=3.1", "aiohttp[speedups]>=3.1", "aiohttp>=3.1,<4"])
def test_a_dependency_that_is_not_a_plain_minimum_is_refused(dep):
    with pytest.raises(SystemExit, match="cannot turn"):
        floor_requirements.floors(f'dependencies = [\n    "{dep}",\n]\n')


def test_a_pyproject_without_a_dependency_list_is_refused():
    with pytest.raises(SystemExit, match="no `dependencies"):
        floor_requirements.floors("[project]\nname = 'x'\n")


def test_the_real_pyproject_floors_are_all_pinnable():
    pins = floor_requirements.floors((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert {p.split("==")[0] for p in pins} == {"aiohttp", "textual", "rich", "segno"}
    assert all(p.count("==") == 1 for p in pins)


# ======================================== mutate.py command line ========================================
def test_the_mutation_runner_refuses_nonsense_instead_of_reporting_a_green_zero(capsys):
    assert mutate.main(["J99"]) == 2
    assert "unknown mutant id(s): J99" in capsys.readouterr().err
    assert mutate.main(["--report"]) == 2 and "--report needs a file name" in capsys.readouterr().err
    assert mutate.main(["--report", "--list"]) == 2
    assert mutate.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "--report FILE" in out and "--list" in out and "MUTATE_JOBS" in out
    assert mutate.main(["--list"]) == 0 and "J1 " in capsys.readouterr().out
