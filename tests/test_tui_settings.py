"""The registry-driven settings screen, plus every setting the TUI itself consumes."""
import json
import os
import stat
import sys

import segno
from PIL import Image
from textual.widgets import Select

from tests.test_qr import decode, render
from tests.test_tui import drive, make_link, until
from zinc.options import OPTIONS, options_for
from zinc.qr import qr_matrix, qr_text
from zinc.tui import NewLink, SettingsScreen


async def open_settings(app, pilot):
    await pilot.press("k")
    await pilot.pause()
    assert isinstance(app.screen, SettingsScreen)
    return app.screen


async def pick(screen, pilot, key):
    """Show every level, filter to `key`, put the cursor on it."""
    screen.query_one("#level", Select).value = "expert"
    await pilot.pause()
    screen.query_one("#search").value = key
    await pilot.pause()
    keys = [rk.value for rk in screen._table.rows]
    screen._table.move_cursor(row=keys.index(key))
    await pilot.pause()
    assert screen.key == key


async def type_value(screen, pilot, text, submit=True):
    box = screen.query_one("#value")
    box.value = text
    if submit:
        box.focus()
        await pilot.pause()
        await pilot.press("enter")
    await pilot.pause()


async def click(pilot, selector):
    await pilot.click(selector)
    await pilot.pause(0.4)    # Textual ignores clicks on a Button for 0.2s after a press


def notes(app):
    return [n.message for n in app._notifications]


def test_edits_are_staged_until_save_then_applied_in_place_and_written_privately(tmp_path):
    async def t(app, pilot, store, mgr, s):
        screen = await open_settings(app, pilot)
        await pick(screen, pilot, "vt_key")
        await type_value(screen, pilot, "VT-KEY-1234567890")
        assert s.vt_key == "" and not (tmp_path / "cfg.json").exists()       # staged only
        await pick(screen, pilot, "blocklist")
        await type_value(screen, pilot, "evil.example, bad.example")
        await click(pilot, "#ok")
        assert not isinstance(app.screen, SettingsScreen)
        assert (s.vt_key, s.blocklist) == ("VT-KEY-1234567890", ["evil.example", "bad.example"])
        assert mgr.settings is s and mgr.reputation.s is s                   # providers see it without a restart
        cfg = tmp_path / "cfg.json"
        saved = json.loads(cfg.read_text())
        assert saved["vt_key"] == "VT-KEY-1234567890" and saved["blocklist"] == ["evil.example", "bad.example"]
        if sys.platform != "win32":
            assert stat.S_IMODE(os.stat(cfg).st_mode) == 0o600
    drive(t, tmp_path)


def test_blank_secret_keeps_the_old_key_and_the_key_is_never_shown_in_the_list(tmp_path):
    async def t(app, pilot, store, mgr, s):
        s.vt_key = "VT-KEY-1234567890"
        screen = await open_settings(app, pilot)
        await pick(screen, pilot, "vt_key")
        assert screen.query_one("#value").value == ""                          # not pre-filled with the secret
        cells = " ".join(str(c) for c in screen._table.get_row("vt_key"))
        assert "VT-KEY-1234567890" not in cells and "VT-K" in cells           # masked, still recognisable
        await type_value(screen, pilot, "")
        await click(pilot, "#ok")
        assert s.vt_key == "VT-KEY-1234567890"
    drive(t, tmp_path)


def test_cancel_discards_everything(tmp_path):
    async def t(app, pilot, store, mgr, s):
        screen = await open_settings(app, pilot)
        await pick(screen, pilot, "token_length")
        await type_value(screen, pilot, "30")
        await click(pilot, "#cancel")
        assert s.token_length == 12 and not (tmp_path / "cfg.json").exists()
    drive(t, tmp_path)


def test_bad_value_gets_a_plain_message_and_blocks_saving(tmp_path):
    async def t(app, pilot, store, mgr, s):
        screen = await open_settings(app, pilot)
        await pick(screen, pilot, "token_length")
        await type_value(screen, pilot, "abc")
        assert "要是整數" in screen.query_one("#msg").render().plain and screen.draft == {}
        await type_value(screen, pilot, "9999", submit=False)                # typed, not yet Enter
        await click(pilot, "#ok")
        assert isinstance(app.screen, SettingsScreen)                         # pending bad text keeps it open
        assert "之間" in screen.query_one("#msg").render().plain and s.token_length == 12
    drive(t, tmp_path)


def test_text_typed_but_not_confirmed_is_not_lost_on_save(tmp_path):
    async def t(app, pilot, store, mgr, s):
        screen = await open_settings(app, pilot)
        await pick(screen, pilot, "grace_s")
        await type_value(screen, pilot, "300", submit=False)
        await click(pilot, "#ok")
        assert s.grace_s == 300
    drive(t, tmp_path)


def test_space_flips_a_switch_and_cycles_a_choice(tmp_path):
    async def t(app, pilot, store, mgr, s):
        screen = await open_settings(app, pilot)
        await pick(screen, pilot, "show_preview")
        screen._table.focus()
        await pilot.pause()
        await pilot.press("space")
        assert screen.draft == {"show_preview": False}
        await pilot.press("space")                                            # back to the saved value: no change left
        assert screen.draft == {}
        await pick(screen, pilot, "theme")
        screen._table.focus()
        await pilot.pause()
        await pilot.press("space")
        assert screen.draft == {"theme": "light"}
        for _ in range(2):
            await pilot.press("space")
        assert screen.draft == {}                                              # auto -> light -> dark -> auto
        await pick(screen, pilot, "token_length")
        screen._table.focus()
        await pilot.press("space")
        assert "輸入框" in screen.query_one("#msg").render().plain and screen.draft == {}
    drive(t, tmp_path)


def test_reset_puts_the_default_back_and_the_file_forgets_it(tmp_path):
    async def t(app, pilot, store, mgr, s):
        s.token_length = 20
        screen = await open_settings(app, pilot)
        await pick(screen, pilot, "token_length")
        assert screen._table.get_row("token_length")[0].startswith("●")      # changed-from-default marker
        await click(pilot, "#reset")
        await click(pilot, "#ok")
        assert s.token_length == 12
        assert "token_length" not in json.loads((tmp_path / "cfg.json").read_text())
    drive(t, tmp_path)


def test_levels_and_search_filter_the_list(tmp_path):
    async def t(app, pilot, store, mgr, s):
        screen = await open_settings(app, pilot)
        shown = lambda: {rk.value for rk in screen._table.rows}  # noqa: E731
        assert shown() == {o.key for o in options_for("basic")}               # starts simple
        assert "vt_key" not in shown() and "theme" in shown()
        screen.query_one("#level", Select).value = "advanced"
        await pilot.pause()
        assert shown() == {o.key for o in options_for("advanced")} and "vt_key" in shown()
        screen.query_one("#level", Select).value = "expert"
        await pilot.pause()
        assert shown() == set(OPTIONS)
        screen.query_one("#search").value = "QR"
        await pilot.pause()
        assert shown() == {o.key for o in options_for("expert", query="QR")} and "qr_error_level" in shown()
        screen.query_one("#search").value = "zzz-nothing-matches"
        await pilot.pause()
        assert shown() == set() and "沒有符合" in screen.query_one("#help").render().plain
        await click(pilot, "#ok")                                              # an empty list must not crash saving
        assert not isinstance(app.screen, SettingsScreen)
    drive(t, tmp_path)


def test_preset_stages_only_what_would_change_and_is_a_no_op_the_second_time(tmp_path):
    async def t(app, pilot, store, mgr, s):
        s.show_rank = False                           # minimal wants this already: it must not be listed
        screen = await open_settings(app, pilot)
        screen.query_one("#preset", Select).value = "minimal"
        await click(pilot, "#apply-preset")
        assert "show_rank" not in screen.draft and screen.draft["show_preview"] is False
        assert screen.draft["curl_mode"] is False and "改了" in screen.query_one("#msg").render().plain
        await click(pilot, "#ok")
        assert s.show_preview is False and s.curl_mode is False and s.brand == ""
        screen = await open_settings(app, pilot)
        screen.query_one("#preset", Select).value = "minimal"
        await click(pilot, "#apply-preset")
        assert screen.draft == {} and "一樣" in screen.query_one("#msg").render().plain
        await click(pilot, "#apply-preset")
        await click(pilot, "#cancel")
    drive(t, tmp_path)


def test_preset_without_a_choice_asks_for_one(tmp_path):
    async def t(app, pilot, store, mgr, s):
        screen = await open_settings(app, pilot)
        await click(pilot, "#apply-preset")
        assert "先" in screen.query_one("#msg").render().plain and screen.draft == {}
    drive(t, tmp_path)


# ---- new-link form: defaults come from the settings -------------------------------------------
def test_new_link_form_starts_from_the_default_settings(tmp_path):
    async def t(app, pilot, store, mgr, s):
        await pilot.press("n")
        await pilot.pause()
        f = app.screen
        assert (f.query_one("#mode").value, f.query_one("#ttl").value, f.query_one("#maxo").value) == ("plain", "30", "")
        await click(pilot, "#cancel")
        s.default_mode, s.default_ttl_min, s.default_max_opens = "box", 0, 5
        await pilot.press("n")
        await pilot.pause()
        f = app.screen
        assert (f.query_one("#mode").value, f.query_one("#ttl").value, f.query_one("#maxo").value) == ("box", "", "5")
        s.default_ttl_min = 7.5
        await click(pilot, "#cancel")
        await pilot.press("n")
        await pilot.pause()
        assert app.screen.query_one("#ttl").value == "7.5"
    drive(t, tmp_path)


def test_form_accepts_a_vanity_token_and_per_link_overrides(tmp_path):
    async def t(app, pilot, store, mgr, s):
        await pilot.press("n")
        await pilot.pause()
        app.screen.query_one("#targets").value = "https://example.com"
        app.screen.query_one("#token").value = "hello-zien"
        app.screen.query_one("#ovr").value = "theme=dark; accent=#E11D48"
        await pilot.click("#ok")
        assert await until(lambda: any(l.status == "live" for l in store.list_links()), pilot)
        link = store.list_links()[0]
        assert link.token == "hello-zien" and link.spec.options == {"theme": "dark", "accent": "#e11d48"}
        assert mgr.public_url(link).endswith("/hello-zien")
    drive(t, tmp_path)


def test_form_rejects_bad_overrides_and_bad_tokens_in_plain_words(tmp_path):
    async def t(app, pilot, store, mgr, s):
        await pilot.press("n")
        await pilot.pause()
        app.screen.query_one("#targets").value = "https://example.com"
        for field, text, expect in (("#ovr", "nonsense=1", "沒有這個設定"), ("#ovr", "bit_length", "名稱=值"),
                                    ("#ovr", "token_length=20", "不能每條連結單獨設定"),
                                    ("#ovr", "theme=neon", "只能選"), ("#token", "a/b", "後綴")):
            app.screen.query_one("#ovr").value = ""
            app.screen.query_one("#token").value = ""
            app.screen.query_one(field).value = text
            await click(pilot, "#ok")
            assert isinstance(app.screen, NewLink), text
            assert expect in app.screen.query_one("#err").render().plain, (text, app.screen.query_one("#err").render().plain)
        assert store.list_links() == []
    drive(t, tmp_path)


# ---- settings the TUI consumes ------------------------------------------------------------------
def test_auto_copy_off_leaves_the_clipboard_alone(tmp_path):
    async def t(app, pilot, store, mgr, s):
        s.auto_copy = False
        app.copy_to_clipboard("previous")
        link = await make_link(app, pilot, store)
        assert app.clipboard == "previous"
        assert any("已建立" in m and mgr.public_url(link) in m and "按 c" in m for m in notes(app))
    drive(t, tmp_path)


def test_toast_and_bell_on_open_follow_their_settings(tmp_path):
    async def t(app, pilot, store, mgr, s):
        rang = []
        app.bell = lambda: rang.append(1)
        link = await make_link(app, pilot, store)
        s.toast_on_open, s.bell_on_open = True, False
        store.add_hit(link.id, "open", "v1", "TW", "asia")
        assert await until(lambda: any("有人打開了" in m and "TW" in m for m in notes(app)), pilot, 40)
        assert rang == []
        s.toast_on_open, s.bell_on_open = False, True
        before = len(notes(app))
        store.add_hit(link.id, "open", "v2", "JP", "asia")
        store.add_hit(link.id, "open", "v3", "JP", "asia")
        assert await until(lambda: rang, pilot, 40)
        assert len(notes(app)) == before                                      # bell only, no toast
        s.toast_on_open, s.bell_on_open = True, False
        store.add_hit(link.id, "open", "v4", "DE", "europe")
        store.add_hit(link.id, "open", "v5", "DE", "europe")
        assert await until(lambda: any("有 2 人打開了" in m and "DE" in m for m in notes(app)), pilot, 40)
        store.add_hit(link.id, "bot", "b1")                                    # bots never count as someone
        await pilot.pause(1.4)
        assert not any("未知" in m for m in notes(app))
    drive(t, tmp_path)


def test_qr_settings_change_the_saved_files_and_the_panel(tmp_path):
    async def t(app, pilot, store, mgr, s):
        folder = tmp_path / "out" / "qr"
        s.qr_export_dir, s.qr_error_level, s.qr_export_scale, s.qr_export_border, s.qr_terminal_border = (
            str(folder), "H", 5, 2, 3)
        link = await make_link(app, pilot, store)
        url = mgr.public_url(link)
        await pilot.press("s")
        await pilot.pause(0.5)
        png = folder / f"zinc-{link.id}.png"
        assert png.exists() and (folder / f"zinc-{link.id}.svg").exists()      # folder was created
        size = len(qr_matrix(url, 2, "H"))
        assert Image.open(png).size == (size * 5, size * 5)
        assert decode(Image.open(png).convert("L")) == url
        assert app._qr.render().plain == qr_text(url, 3, "H")                    # the side panel follows too
        assert qr_text(url, 3, "H") != qr_text(url, 2, "L")
        assert decode(render(app._qr.render().plain)) == url
    drive(t, tmp_path)


def test_cloudflared_path_setting_is_what_preflight_reports(tmp_path):
    async def t(app, pilot, store, mgr, s):
        from zinc.tunnel import preflight
        s.cloudflared_path = "/some/where/cloudflared"
        assert preflight(tmp_path, s.cloudflared_path) == []
        assert segno  # keep the import honest
    drive(t, tmp_path)
