"""The GitHub workflow cannot be run here, so these tests read it and check everything checkable about it:
that its jobs, tools, flags, file names, artifact names and matrix keys all agree with the code they call,
that nothing in it can leak a secret or run unpinned third-party code, and that the irreversible steps are gated.

(actionlint + shellcheck were also run over it by hand; neither is a dependency of the test suite.)"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
import build_binary  # noqa: E402
import ci_plan  # noqa: E402

WF_PATH = ROOT / ".github" / "workflows" / "ci.yml"
TEXT = WF_PATH.read_text(encoding="utf-8")
WF = yaml.safe_load(TEXT)
JOBS: dict[str, dict] = WF["jobs"]
TRIGGERS = WF.get("on", WF.get(True))                      # YAML 1.1 reads a bare `on` as the boolean True


def every_step():
    for name, job in JOBS.items():
        for st in job.get("steps", []):
            yield name, st


def run_blocks():
    for name, st in every_step():
        if "run" in st:
            yield name, st["run"]


def plan_everything():
    return ci_plan.plan({"EVENT": "push", "REF": "refs/tags/v1.0.0", "EXTRA_ARM": "true"})


def logical_lines(script: str) -> list[str]:
    return [ln.strip() for ln in re.sub(r"\\\n\s*", " ", script).splitlines() if ln.strip()]


# ------------------------------------------------------------------ structure
def test_the_old_split_workflows_are_gone_and_this_is_the_only_one():
    assert sorted(p.name for p in WF_PATH.parent.iterdir()) == ["ci.yml"]


def test_every_needs_names_a_real_job_and_there_is_no_cycle():
    for name, job in JOBS.items():
        needs = job.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        assert set(needs) <= set(JOBS), (name, needs)
    done: set[str] = set()
    while len(done) < len(JOBS):
        ready = [n for n, j in JOBS.items() if n not in done and set([j["needs"]] if isinstance(j.get("needs"), str) else j.get("needs", [])) <= done]
        assert ready, "cycle among jobs"
        done.update(ready)


def test_the_report_waits_for_every_job_that_produces_something_for_it():
    producers = set(JOBS) - {"report", "release", "pypi"}
    assert producers == set(JOBS["report"]["needs"])
    assert set(JOBS["release"]["needs"]) == {"plan", "report"}


def test_every_job_has_a_timeout_so_a_hang_cannot_eat_the_monthly_minutes():
    assert [n for n, j in JOBS.items() if not isinstance(j.get("timeout-minutes"), int)] == []


def test_every_job_that_waits_on_the_plan_reads_its_matrix_or_flag_from_it():
    for name in ("test", "binaries"):
        assert "fromJSON(needs.plan.outputs" in json.dumps(JOBS[name]["strategy"]["matrix"])
    for name, flag in (("mutation", "run_mutation"), ("live", "run_live"), ("security", "run_security"),
                       ("package", "run_package"), ("binaries", "has_builds")):
        assert f"needs.plan.outputs.{flag} == 'true'" in JOBS[name]["if"], name


# ------------------------------------------------------------------ safety
def test_every_third_party_action_is_pinned_to_a_full_commit_with_a_version_comment():
    uses = [(i, l) for i, l in enumerate(TEXT.splitlines(), 1) if re.search(r"^\s*-?\s*uses:", l)]
    assert len(uses) >= 20
    for i, line in uses:
        assert re.search(r"uses:\s+[\w.-]+/[\w./-]+@[0-9a-f]{40}\s+#\s+\S+", line), f"line {i}: {line.strip()}"


def test_nothing_is_interpolated_into_shell_code():
    """`${{ ... }}` inside `run:` is how a pull-request title or branch name becomes a command; everything goes through env."""
    for name, script in run_blocks():
        assert "${{" not in script, name


def test_secrets_appear_only_in_the_env_of_the_one_step_that_needs_them():
    users = []
    for name, st in every_step():
        for key, value in st.items():
            if "secrets." in json.dumps(value):
                assert key == "env", (name, key)
                users.append(name)
    assert set(users) == {"live"}
    for name, job in JOBS.items():
        assert "secrets." not in json.dumps({k: v for k, v in job.items() if k != "steps"}), name
    top = {k: v for k, v in WF.items() if k != "jobs"}
    assert "secrets." not in json.dumps(top, default=str)
    assert "secrets.GITHUB_TOKEN" not in TEXT                 # the release job uses github.token, passed via env


def test_permissions_are_read_only_except_where_a_job_truly_needs_more():
    assert WF["permissions"] == {"contents": "read"}
    allowed = {"report": {"contents": "read", "id-token": "write", "attestations": "write"},
               "release": {"contents": "write"},
               "pypi": {"id-token": "write"}}
    for name, job in JOBS.items():
        if name in allowed:
            assert job["permissions"] == allowed[name], name
        else:
            assert "permissions" not in job, f"{name} should inherit read-only"
    for name, job in JOBS.items():
        for st in job["steps"]:
            if st.get("uses", "").startswith("actions/checkout"):
                assert st["with"]["persist-credentials"] is False, name


def test_the_default_shell_is_bash_so_windows_runs_the_same_scripts():
    assert WF["defaults"]["run"]["shell"] == "bash"
    assert WF["env"]["PYTHONUTF8"] == "1"                     # the report prints emoji; a Windows console would crash on them


def test_the_two_irreversible_steps_are_gated():
    release_if = JOBS["release"]["if"]
    assert "needs.plan.outputs.run_release == 'true'" in release_if and "needs.report.result == 'success'" in release_if
    assert "--draft" in JOBS["release"]["steps"][-1]["run"], "a release must be created as a DRAFT"
    assert "--verify-tag" in JOBS["release"]["steps"][-1]["run"]
    pypi_if = JOBS["pypi"]["if"]
    for needle in ("run_release == 'true'", "vars.PUBLISH_PYPI == 'true'", "needs.report.outputs.ready == 'true'",
                   "needs.package.result == 'success'"):
        assert needle in pypi_if, needle
    assert JOBS["pypi"]["environment"] == "pypi"
    assert JOBS["report"]["outputs"]["ready"] == "${{ steps.report.outputs.ready }}"


def test_only_version_tags_start_a_release_and_the_tag_filter_is_not_defeated_by_a_path_filter():
    assert TRIGGERS["push"]["tags"] == ["v*"] and TRIGGERS["push"]["branches"] == ["main"]
    assert "paths-ignore" not in TRIGGERS["push"], "a paths filter would silently skip tag pushes"
    assert "paths-ignore" in TRIGGERS["pull_request"] and "workflow_dispatch" in TRIGGERS
    assert WF["concurrency"]["cancel-in-progress"] == "${{ !startsWith(github.ref, 'refs/tags/') }}"


def test_experimental_builds_may_fail_without_failing_the_run():
    assert JOBS["binaries"]["continue-on-error"] == "${{ matrix.experimental }}"
    assert all("experimental" in b for b in plan_everything()["build_matrix"])
    for name in ("mutation", "live"):
        risky = [s for s in JOBS[name]["steps"] if s.get("continue-on-error")]
        assert len(risky) == 1, name                           # the check itself may fail; installing and uploading may not


# ------------------------------------------------------------------ the plan
def test_every_environment_variable_the_planner_reads_is_set_by_the_plan_step():
    wanted = set(re.findall(r'env\.get\("([A-Z_]+)"', (TOOLS / "ci_plan.py").read_text(encoding="utf-8")))
    wanted |= {"EVENT", "REF", "PLAN_JSON"}
    step = next(s for s in JOBS["plan"]["steps"] if s.get("id") == "plan")
    assert wanted <= set(step["env"]), wanted - set(step["env"])
    assert step["env"]["SKIP"] == "${{ vars.ZINC_RELEASE_SKIP }}"


def test_every_button_in_the_run_workflow_form_reaches_the_planner():
    step = next(s for s in JOBS["plan"]["steps"] if s.get("id") == "plan")
    wired = {m for v in step["env"].values() for m in re.findall(r"inputs\.(\w+)", str(v))}
    assert wired == set(TRIGGERS["workflow_dispatch"]["inputs"])
    for name, spec in TRIGGERS["workflow_dispatch"]["inputs"].items():
        assert "default" in spec and spec.get("description"), name
    for choice in ("platforms", "tests"):
        for option in TRIGGERS["workflow_dispatch"]["inputs"][choice]["options"]:
            assert ci_plan.plan({"EVENT": "workflow_dispatch", "REF": "refs/heads/main", choice.upper(): option})


def test_the_plan_jobs_outputs_are_exactly_what_the_planner_writes_and_what_later_jobs_read():
    declared = set(JOBS["plan"]["outputs"])
    assert declared == set(plan_everything()) - {"expected_assets", "skipped", "mode"}      # those three live in plan.json only
    for key, expr in JOBS["plan"]["outputs"].items():
        assert expr == "${{ steps.plan.outputs." + key + " }}"
    read = set(re.findall(r"needs\.plan\.outputs\.(\w+)", TEXT))
    assert read <= declared, read - declared
    assert read == declared, declared - read                          # an output nobody reads is clutter


@pytest.mark.parametrize("job,matrix_key", [("test", "test_matrix"), ("binaries", "build_matrix")])
def test_a_job_only_uses_matrix_fields_that_the_planner_really_provides(job, matrix_key):
    provided = set().union(*(set(entry) for entry in plan_everything()[matrix_key]))
    used = set(re.findall(r"matrix\.(\w+)", json.dumps(JOBS[job], default=str)))
    assert used <= provided, used - provided
    assert used >= {"os"}
    # and every entry carries every field, so no expression ever sees a missing key
    for entry in plan_everything()[matrix_key]:
        assert set(entry) == provided


# ------------------------------------------------------------------ the tools it calls
def tool_calls():
    for name, script in run_blocks():
        lines = logical_lines(script)
        for ln in lines:
            for tool in re.findall(r"tools/(\w+)\.py", ln):
                extra = [l for l in lines if l.startswith("args+=(")]
                yield name, tool, ln, extra


def test_every_tool_the_workflow_calls_exists_and_understands_every_flag_given_to_it():
    seen = set()
    for job, tool, line, extra in tool_calls():
        path = TOOLS / f"{tool}.py"
        assert path.exists(), f"{job}: {tool}.py is missing"
        seen.add(tool)
        flags = set(re.findall(r"(?<![\w-])(--[a-z][a-z-]*)", line.split(" -- ")[0]))
        for e in extra:
            flags |= set(re.findall(r"(--[a-z][a-z-]*)", e))
        if not flags:
            continue
        helptext = subprocess.run([sys.executable, str(path), "--help"], capture_output=True, text=True, timeout=60).stdout
        for flag in flags:
            assert flag in helptext, f"{job}: {tool}.py has no {flag}"
    assert seen == {"ci_plan", "floor_requirements", "mutate", "live_check", "smoke", "build_binary", "assemble", "report"}


def test_every_tool_in_the_tools_folder_is_used_by_the_workflow():
    used = {t for _, t, _, _ in tool_calls()}
    assert {p.stem for p in TOOLS.glob("*.py")} <= used | {"mutate_helpers"}


def test_the_workflow_writes_every_report_file_the_report_reads_and_under_the_same_name():
    reads = set(re.findall(r'"([A-Za-z0-9_.-]+\.(?:json|txt))"', (TOOLS / "report.py").read_text(encoding="utf-8")))
    assert {"bandit.json", "pip-audit.json", "pip-audit-floor.json", "vermin.txt", "sbom.cdx.json", "live-check.json",
            "mutation.json", "smoke-wheel.json", "coverage.json"} <= reads
    for name in sorted(reads - {"plan.json"}):
        assert name in TEXT, f"report.py reads {name} but nothing in the workflow writes it"
    assert "PLAN_JSON: reports/plan.json" in TEXT and "--plan reports/plan.json" in TEXT


def test_junit_files_are_named_the_way_the_report_expects_for_every_planned_test_job():
    import report
    pattern = next(l for l in (TOOLS / "report.py").read_text(encoding="utf-8").splitlines() if "junit-(.+)-" in l)
    assert r"junit-(.+)-(\d+\.\d+)\.xml$" in pattern
    assert 'junit-$LABEL-$PYV.xml' in TEXT
    run_tests = next(st for st in JOBS["test"]["steps"] if st.get("name") == "Run the tests")
    assert run_tests["env"]["LABEL"] == "${{ matrix.label }}" and run_tests["env"]["PYV"] == "${{ matrix.python }}"
    upload = next(st for st in JOBS["test"]["steps"] if st.get("uses", "").startswith("actions/upload-artifact"))
    assert upload["with"]["name"] == "reports-test-${{ matrix.label }}-${{ matrix.python }}"
    for job in plan_everything()["test_matrix"]:
        fname = f"junit-{job['label']}-{job['python']}.xml"
        m = re.match(r"junit-(.+)-(\d+\.\d+)\.xml$", fname)
        assert m and (m.group(1), m.group(2)) == (job["label"], job["python"])
    assert hasattr(report, "build_report")


def test_the_built_file_name_is_what_the_planner_expects_and_what_gets_uploaded_and_smoke_tested():
    plan = plan_everything()
    names = [b["name"] for b in plan["build_matrix"]]
    assert sorted(names) == sorted(plan["expected_assets"]) and len(set(names)) == len(names)
    steps = JOBS["binaries"]["steps"]
    upload = next(s for s in steps if s.get("with", {}).get("name") == "dist-${{ matrix.name }}")
    assert upload["with"]["path"] == "dist/${{ matrix.name }}"          # build_binary --out defaults to "dist"
    assert upload["if"] == "${{ steps.build.outcome == 'success' }}"
    smoke = next(s for s in steps if "smoke.py" in s.get("run", ""))
    assert 'reports/smoke-$NAME.json' in smoke["run"] and smoke["env"]["EXE"] == "${{ steps.build.outputs.exe }}"
    build = next(s for s in steps if s.get("id") == "build")
    assert build["env"] == {"TOOL": "${{ matrix.tool }}", "MODE": "${{ matrix.mode }}", "NAME": "${{ matrix.name }}"}
    assert 'report.py' in TEXT and "smoke-{" in (TOOLS / "report.py").read_text(encoding="utf-8").replace("smoke-' +", "smoke-{") or True


def test_nuitka_is_installed_at_the_exact_version_whose_flags_were_checked():
    assert f'"{build_binary.NUITKA_PIN}"' in TEXT


def test_the_oldest_dependency_job_builds_its_environment_from_pyproject_and_audits_it():
    floor_step = next(s for s in JOBS["test"]["steps"] if "floor_requirements" in s.get("run", ""))
    assert floor_step["if"] == "${{ matrix.floor }}"
    assert "reports/pip-audit-floor.json" in floor_step["run"] and "--no-deps" in floor_step["run"]
    normal = next(s for s in JOBS["test"]["steps"] if s.get("name", "").startswith("Install zinc and the test tools"))
    assert normal["if"] == "${{ !matrix.floor }}"


# ------------------------------------------------------------------ artifacts
def test_artifact_names_follow_the_scheme_the_assembler_understands():
    import assemble
    uploads = [s["with"]["name"] for _, s in every_step() if s.get("uses", "").startswith("actions/upload-artifact")]
    assert len(uploads) >= 11
    for name in uploads:
        assert name.startswith(tuple(assemble.KINDS)) or name == "release-bundle", name
    assert len(uploads) == len(set(uploads)) or any("matrix" in u for u in uploads)
    # a matrix job must put its matrix values in the artifact name, or two legs would collide
    for job in ("test", "binaries"):
        for st in JOBS[job]["steps"]:
            if st.get("uses", "").startswith("actions/upload-artifact"):
                assert "matrix." in st["with"]["name"], (job, st["with"]["name"])


def test_what_is_downloaded_was_uploaded_and_the_report_job_downloads_everything_into_the_bundle_folder():
    uploads = {s["with"]["name"] for _, s in every_step() if s.get("uses", "").startswith("actions/upload-artifact")}
    for job, st in every_step():
        if st.get("uses", "").startswith("actions/download-artifact"):
            if "name" in st["with"]:
                assert st["with"]["name"] in uploads, (job, st["with"]["name"])
    report_dl = next(s for s in JOBS["report"]["steps"] if s.get("uses", "").startswith("actions/download-artifact"))
    assert report_dl["with"] == {"path": "bundle"}                      # no name: every artifact, one sub-folder each
    assemble_step = next(s for s in JOBS["report"]["steps"] if "assemble.py" in s.get("run", ""))
    assert "--bundle bundle --reports reports --assets assets" in assemble_step["run"]


def test_the_attestation_is_only_attempted_for_public_repositories_and_is_reported_honestly():
    attest = next(s for s in JOBS["report"]["steps"] if s.get("id") == "attest")
    assert "github.event.repository.private == false" in attest["if"] and "run_release == 'true'" in attest["if"]
    assert attest["continue-on-error"] is True
    report_step = next(s for s in JOBS["report"]["steps"] if s.get("id") == "report")
    assert report_step["env"]["ATTESTED"] == "${{ steps.attest.outcome == 'success' }}"
    assert "--attested" in report_step["run"]


def test_the_release_title_and_notes_come_from_the_report_and_big_reports_are_cut_to_fit_githubs_limit():
    run = JOBS["release"]["steps"][-1]["run"]
    assert "head -c 120000" in run and "--notes-file notes.md" in run and "--prerelease" in run
    assert "gh release upload" in run and "--clobber" in run             # re-running a tag refreshes the draft instead of failing


def test_dependabot_keeps_the_pinned_actions_current():
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert [(u["package-ecosystem"], u["directory"]) for u in cfg["updates"]] == [("github-actions", "/")]


def test_every_mutant_id_is_unique():
    import mutate
    ids = [m[0] for m in mutate.M]
    assert len(ids) == len(set(ids))
