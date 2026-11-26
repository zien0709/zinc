"""Form parsing for the new fields, CSV/JSON export, and the clone / edit / export TUI flows."""
import csv
import io
import json
import time
from datetime import datetime

import pytest

from tests.test_server import A, B
from tests.test_tui import cell, drive, make_link, until
from tests.test_tui_settings import click, notes
from zinc.export import COLUMNS, export_link, safe_cell
from zinc.models import LinkSpec, Variant
from zinc.secret import check_password, hash_password
from zinc.store import Store
from zinc.view import (build_from_form, form_values, format_rules, format_targets, parse_rules, parse_start)

NOW = 1_800_000_000.0


# ---- rule syntax ---------------------------------------------------------------------------------
def test_rules_syntax_mixes_places_languages_and_devices():
    geo, route = parse_rules("asia=https://a.example; TW=https://b.example*3 !; lang:ja=https://j.example; Device:IOS=https://i.example")
    assert [(r.match, [v.url for v in r.variants]) for r in geo] == [
        ("asia", ["https://a.example"]), ("TW", ["https://b.example", ""])]
    assert geo[1].variants[0].weight == 3
    assert [(r.kind, r.match) for r in route] == [("lang", "ja"), ("device", "IOS")]
    assert parse_rules("") == ([], []) and parse_rules(" ; ; ") == ([], [])


@pytest.mark.parametrize("bad,needle", [("TW=", "缺少網址"), ("lang:ja", "缺少網址"), ("os:ios=https://x.example", "只有 lang: 和 device:"),
                                        ("browser:fx=https://x.example", "只有 lang: 和 device:")])
def test_bad_rules_say_what_is_wrong(bad, needle):
    with pytest.raises(ValueError, match=needle):
        parse_rules(bad)


def test_form_to_spec_and_back_is_lossless_for_everything_the_form_can_express():
    spec, ttl, cap = build_from_form(
        mode="door", targets="https://a.example https://b.example*2 !", message="", auto_locale=True, ttl_min="15",
        max_opens="9", geo="asia=https://c.example https://d.example; lang:ja=https://e.example https://f.example; device:ios=https://g.example !",
        overrides="theme=dark; accent=#E11D48", label="給小明", max_passes="3", now=NOW)
    assert (ttl, cap) == (900, 9)
    again, _, _ = build_from_form(mode=spec.mode, targets=format_targets(spec.variants), geo=format_rules(spec),
                                  auto_locale=spec.auto_locale, overrides="theme=dark; accent=#e11d48",
                                  label=spec.label, max_passes="3", now=NOW)
    assert again == spec
    vals = form_values(spec)
    assert vals["targets"] == "https://a.example https://b.example*2 !" and vals["label"] == "給小明"
    assert vals["max_passes"] == "3" and vals["locale"] is True and vals["has_password"] is False
    assert "pw_hash" not in vals and "pbkdf2" not in json.dumps(vals)


# ---- start time ----------------------------------------------------------------------------------
@pytest.mark.parametrize("text,delta", [("", None), ("+30", 1800), ("+30m", 1800), ("+2h", 7200), ("+1d", 86400), ("+0.5h", 1800),
                                        (" +10M ", 600)])
def test_relative_start_times(text, delta):
    assert parse_start(text, NOW) == (0.0 if delta is None else NOW + delta)


def test_absolute_start_time_is_local_time_and_must_be_in_the_future():
    future = datetime.fromtimestamp(NOW + 86400 * 3)
    text = future.strftime("%Y-%m-%d %H:%M")
    assert parse_start(text, NOW) == datetime.strptime(text, "%Y-%m-%d %H:%M").timestamp()
    past = datetime.fromtimestamp(NOW - 86400).strftime("%Y-%m-%d %H:%M")
    with pytest.raises(ValueError, match="已經過了"):
        parse_start(past, NOW)


@pytest.mark.parametrize("bad", ["tomorrow", "+x", "+", "+-5", "+0", "12/25 09:00", "2026-13-40 99:00", "+5x"])
def test_unreadable_start_times_explain_the_accepted_formats(bad):
    with pytest.raises(ValueError, match="開放時間"):
        parse_start(bad, NOW)


# ---- form validation for the other new fields --------------------------------------------------------------
def test_password_is_hashed_in_the_spec_and_blank_keeps_the_old_hash_only_when_asked():
    spec, _, _ = build_from_form(mode="plain", targets=A, password="hunter2")
    assert spec.pw_hash.startswith("pbkdf2$") and "hunter2" not in spec.pw_hash and check_password("hunter2", spec.pw_hash)
    old = hash_password("old", iterations=1000)
    kept, _, _ = build_from_form(mode="plain", targets=A, keep_hash=old)
    assert kept.pw_hash == old
    replaced, _, _ = build_from_form(mode="plain", targets=A, password="new", keep_hash=old)
    assert check_password("new", replaced.pw_hash) and not check_password("old", replaced.pw_hash)
    assert build_from_form(mode="plain", targets=A)[0].pw_hash == ""
    with pytest.raises(ValueError, match="200"):
        build_from_form(mode="plain", targets=A, password="x" * 201)


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "1.5", " 2x"])
def test_max_passes_must_be_a_positive_whole_number(bad):
    with pytest.raises(ValueError, match="通關上限"):
        build_from_form(mode="plain", targets=A, max_passes=bad)


def test_label_limits_and_start_flow_into_the_spec():
    spec, _, _ = build_from_form(mode="plain", targets=A, label="  小明  ", starts="+1h", now=NOW)
    assert spec.label == "小明" and spec.starts_at == NOW + 3600
    with pytest.raises(ValueError, match="名稱"):
        build_from_form(mode="plain", targets=A, label="x" * 41)


# ---- export ---------------------------------------------------------------------------------------------------
def test_export_writes_a_csv_a_summary_and_no_identity(tmp_path):
    store = Store()
    spec = LinkSpec(mode="box", variants=[Variant("A", A), Variant("B", B)], label="給小明", token="SECRET-SUFFIX")
    link = store.create_link(spec, ttl_s=600, max_opens=None, now=NOW)
    store.add_hit(link.id, "open", "vidvidvidvid", "TW", "asia", "zh-tw", now=NOW + 1)
    store.add_hit(link.id, "pass", "vidvidvidvid", "TW", "asia", "zh-tw", "A", now=NOW + 2)
    store.add_hit(link.id, "open", "other-visitor", "JP", "asia", "ja", now=NOW + 3)
    store.add_hit(link.id, "bot", "botbotbot", None, None, None, now=NOW + 4)
    paths = export_link(store, store.get_link(link.id), tmp_path / "out" / "deep", NOW + 10)
    assert [p.name for p in paths] == [f"zinc-{link.id}-hits.csv", f"zinc-{link.id}-summary.json"] and all(p.exists() for p in paths)
    raw = paths[0].read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")                                         # BOM so Excel reads UTF-8
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
    assert tuple(rows[0]) == COLUMNS and len(rows) == 5
    assert rows[1][:3] == ["2027-01-15 08:00:01", "open", "TW"] and rows[2][1] == "pass" and rows[2][5] == "A"
    assert rows[1][6] == "vidvidvi" and len(rows[1][6]) == 8 and rows[4][1] == "bot"       # a short hash, not the full id
    summary = json.loads(paths[1].read_text(encoding="utf-8"))
    assert summary["label"] == "給小明" and summary["stats"]["opens"] == 2 and summary["stats"]["uniques"] == 2
    assert summary["stats"]["by_country"] == {"TW": 1, "JP": 1} and summary["stats"]["passes"] == 1
    blob = raw.decode("utf-8-sig") + paths[1].read_text(encoding="utf-8")
    for needle in ("SECRET-SUFFIX", A, B, "other-visitor", "vidvidvidvid", link.salt):
        assert needle not in blob, needle


def test_export_neutralises_spreadsheet_formulas(tmp_path):
    for evil in ("=HYPERLINK(\"http://x\")", "+1+1", "-2", "@SUM(A1)", "\tcmd", "\rcmd"):
        assert safe_cell(evil).startswith("'") and safe_cell(evil)[1:] == evil
    assert safe_cell("TW") == "TW" and safe_cell(None) == "" and safe_cell(5) == "5" and safe_cell("a=b") == "a=b"
    store = Store()
    link = store.create_link(LinkSpec(mode="plain", variants=[Variant("A", A)]), 600, None, now=NOW)
    store.add_hit(link.id, "open", "v", "=cmd|' /C calc'!A0", "asia", "@evil", "-x", now=NOW)
    out = export_link(store, store.get_link(link.id), tmp_path, NOW)[0].read_text(encoding="utf-8-sig")
    cells = [c for r in csv.reader(io.StringIO(out)) for c in r]
    assert not any(c[:1] in "=+-@" for c in cells if c)                               # no cell can start a formula


def test_export_of_a_link_with_no_visitors_is_still_valid(tmp_path):
    store = Store()
    link = store.create_link(LinkSpec(mode="plain", variants=[Variant("A", A)]), None, None, now=NOW)
    csv_path, json_path = export_link(store, store.get_link(link.id), tmp_path, NOW)
    assert csv_path.read_text(encoding="utf-8-sig").strip() == ",".join(COLUMNS)
    assert json.loads(json_path.read_text())["stats"]["opens"] == 0 and json.loads(json_path.read_text())["expires_utc"] is None


def test_exporting_twice_overwrites_instead_of_piling_up(tmp_path):
    store = Store()
    link = store.create_link(LinkSpec(mode="plain", variants=[Variant("A", A)]), 600, None, now=NOW)
    export_link(store, link, tmp_path, NOW)
    store.add_hit(link.id, "open", "v", "TW", "asia", None, now=NOW)
    export_link(store, link, tmp_path, NOW)
    assert len(list(tmp_path.iterdir())) == 2 and len(list(csv.reader(open(tmp_path / f"zinc-{link.id}-hits.csv", encoding="utf-8-sig")))) == 2


# ---- TUI flows -------------------------------------------------------------------------------------------------
def test_export_key_uses_the_export_dir_setting_and_falls_back_to_the_working_folder(tmp_path):
    async def t(app, pilot, store, mgr, s):
        link = await make_link(app, pilot, store)
        store.add_hit(link.id, "open", "v1", "TW", "asia")
        await pilot.press("x")
        await pilot.pause(0.3)
        assert (tmp_path / f"zinc-{link.id}-hits.csv").exists()                      # default: the app's folder
        s.export_dir = str(tmp_path / "custom" / "exports")
        await pilot.press("x")
        await pilot.pause(0.3)
        assert (tmp_path / "custom" / "exports" / f"zinc-{link.id}-summary.json").exists()
        assert any("已匯出" in m and "custom" in m for m in notes(app))
        blocker = tmp_path / "not-a-folder"                                       # a file where a folder is needed: unwritable on every OS
        blocker.write_text("x")
        s.export_dir = str(blocker / "exports")
        await pilot.press("x")
        await pilot.pause(0.3)
        assert any("匯出失敗" in m for m in notes(app))
    drive(t, tmp_path)


def test_clone_prefills_everything_but_the_password_and_makes_a_new_url(tmp_path):
    async def t(app, pilot, store, mgr, s):
        await pilot.press("n")
        await pilot.pause()
        f = app.screen
        f.query_one("#targets").value = "https://a.example https://b.example*2"
        f.query_one("#geo").value = "TW=https://tw.example; lang:ja=https://ja.example"
        f.query_one("#name").value = "給小明"
        f.query_one("#password").value = "hunter2"
        f.query_one("#passes").value = "5"
        f.query_one("#ovr").value = "theme=dark"
        await pilot.click("#ok")
        assert await until(lambda: any(l.status == "live" for l in store.list_links()), pilot)
        original = store.list_links()[0]
        await pilot.press("y")
        await pilot.pause()
        f = app.screen
        assert f.kind == "clone"
        assert f.query_one("#targets").value == "https://a.example https://b.example*2"
        assert f.query_one("#geo").value == "TW=https://tw.example; lang:ja=https://ja.example"
        assert (f.query_one("#name").value, f.query_one("#passes").value, f.query_one("#ovr").value) == ("給小明", "5", "theme=dark")
        assert f.query_one("#password").value == "" and f.query_one("#token").disabled is False
        await pilot.click("#ok")
        assert await until(lambda: len([l for l in store.list_links() if l.status == "live"]) == 2, pilot)
        clone = [l for l in store.list_links() if l.id != original.id][0]
        assert clone.token != original.token and clone.hostname != original.hostname
        assert clone.spec.pw_hash == "" and clone.spec.label == "給小明" and clone.spec.max_passes == 5
        assert clone.spec.options == {"theme": "dark"}
    drive(t, tmp_path)


def test_edit_changes_targets_in_place_keeps_a_password_unless_changed_or_removed(tmp_path):
    async def t(app, pilot, store, mgr, s):
        await pilot.press("n")
        await pilot.pause()
        app.screen.query_one("#targets").value = A
        app.screen.query_one("#password").value = "hunter2"
        await pilot.click("#ok")
        assert await until(lambda: any(l.status == "live" for l in store.list_links()), pilot)
        link = store.list_links()[0]
        # 1) change the target, leave the password blank -> same URL, same password
        await pilot.press("t")
        await pilot.pause()
        f = app.screen
        assert f.kind == "edit" and f.query_one("#ttl").disabled and f.query_one("#maxo").disabled and f.query_one("#token").disabled
        assert f.query_one("#targets").value == A and f.query_one("#password").value == "" and f.query_one("#nopw") is not None
        f.query_one("#targets").value = B
        await pilot.click("#ok")
        assert await until(lambda: store.get_link(link.id).spec.variants[0].url == B, pilot)
        now = store.get_link(link.id)
        assert (now.token, now.hostname) == (link.token, link.hostname) and check_password("hunter2", now.spec.pw_hash)
        # 2) a new password replaces it
        await pilot.press("t")
        await pilot.pause()
        app.screen.query_one("#password").value = "second"
        await pilot.click("#ok")
        assert await until(lambda: check_password("second", store.get_link(link.id).spec.pw_hash), pilot)
        assert not check_password("hunter2", store.get_link(link.id).spec.pw_hash)
        # 3) the remove switch drops it
        await pilot.press("t")
        await pilot.pause()
        app.screen.query_one("#nopw").value = True
        await pilot.click("#ok")
        assert await until(lambda: store.get_link(link.id).spec.pw_hash == "", pilot)
        assert store.get_link(link.id).token == link.token
    drive(t, tmp_path)


def test_edit_shows_plain_errors_and_refuses_ended_links(tmp_path):
    async def t(app, pilot, store, mgr, s):
        link = await make_link(app, pilot, store)
        await pilot.press("t")
        await pilot.pause()
        app.screen.query_one("#targets").value = "ftp://nope"
        await pilot.click("#ok")
        await pilot.pause(0.3)
        assert app.screen.kind == "edit" and "http" in app.screen.query_one("#err").render().plain
        await click(pilot, "#cancel")
        assert store.get_link(link.id).spec.variants[0].url == link.spec.variants[0].url
        await mgr.hard_destroy(link.id)
        app.refresh_all()
        await pilot.press("t")
        await pilot.pause()
        assert not hasattr(app.screen, "kind") and any("已經結束" in m for m in notes(app))
    drive(t, tmp_path)


def test_new_form_collapses_the_advanced_fields_until_they_are_used(tmp_path):
    async def t(app, pilot, store, mgr, s):
        from textual.widgets import Collapsible
        await pilot.press("n")
        await pilot.pause()
        assert app.screen.query_one(Collapsible).collapsed is True
        await click(pilot, "#cancel")
        await make_link(app, pilot, store)
        await pilot.press("y")
        await pilot.pause()
        assert app.screen.query_one(Collapsible).collapsed is True                      # nothing advanced was used
    drive(t, tmp_path)


def test_table_shows_the_name_and_marks_not_yet_open_links(tmp_path):
    async def t(app, pilot, store, mgr, s):
        await pilot.press("n")
        await pilot.pause()
        app.screen.query_one("#targets").value = A
        app.screen.query_one("#name").value = "給小明的驚喜"
        app.screen.query_one("#starts").value = "+1h"
        await pilot.click("#ok")
        assert await until(lambda: any(l.status == "live" for l in store.list_links()), pilot)
        app.refresh_all()
        assert cell(app, "名稱") == "給小明的驚喜" and cell(app, "狀態") == "⏳ 未開放"
        detail = app._detail.render().plain
        assert "📛 給小明的驚喜" in detail and "⏳ 開放於" in detail
    drive(t, tmp_path)


def test_a_failing_webhook_shows_in_the_top_bar(tmp_path):
    async def t(app, pilot, store, mgr, s):
        mgr.errors["_webhook"] = "webhook 對方回 HTTP 500"
        app.refresh_all()
        assert "⚠ webhook 對方回 HTTP 500" in app._top.render().plain
        mgr.errors.pop("_webhook")
        app.refresh_all()
        assert "webhook" not in app._top.render().plain
    drive(t, tmp_path)
