"""Textual front end: a link list on the left, details + QR on the right."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Collapsible, DataTable, Footer, Input, Label, Select, Static, Switch

import copy

from .config import save_settings
from .manager import BlockedError, Manager
from .options import LEVEL_LABELS, LEVELS, OPTIONS, PRESETS, Settings, options_for, preset_diff
from .export import export_link
from .qr import export_qr, qr_size, qr_text
from .store import Store
from .tunnel import TunnelError, preflight
from .view import (build_from_form, detail_text, fmt_remaining, form_values, opt_display, opt_from_text, opt_help,
                   opt_text, short_host, state_label)

MODES = [("plain　直接跳轉", "plain"), ("note　紙條（打字機）", "note"), ("count　第 N 位發現者", "count"),
         ("box　盲盒（隨機抽目標）", "box"), ("door　選一扇門", "door")]


class Confirm(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "no", "取消")]

    def __init__(self, text: str, yes: str = "確定"):
        super().__init__()
        self.text, self.yes = text, yes

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(self.text, id="confirm-text")
            with Horizontal(classes="buttons"):
                yield Button(self.yes, id="yes", variant="error", compact=True)
                yield Button("取消", id="no", compact=True)

    def on_button_pressed(self, e: Button.Pressed) -> None:
        self.dismiss(e.button.id == "yes")

    def action_no(self) -> None:
        self.dismiss(False)


class NewLink(ModalScreen[Optional[dict]]):
    """The creation form. `kind`: "new" | "clone" (prefilled, gets a new URL) | "edit" (a live link: URL, token and
    stats stay, only what it does changes)."""
    BINDINGS = [Binding("escape", "cancel", "取消")]
    TITLES = {"new": "新增長連結", "clone": "複製連結（會有新網址）", "edit": "改目標（網址不變）"}

    def __init__(self, settings: Optional[Settings] = None, prefill: Optional[dict] = None, kind: str = "new",
                 keep_hash: str = ""):
        super().__init__()
        self.s, self.pre, self.kind, self.keep_hash = settings or Settings(), prefill or {}, kind, keep_hash

    def compose(self) -> ComposeResult:
        s, pre, edit = self.s, self.pre, self.kind == "edit"
        ttl = "" if s.default_ttl_min == 0 else f"{s.default_ttl_min:g}"
        cap = "" if s.default_max_opens == 0 else str(s.default_max_opens)
        advanced_used = any(pre.get(k) for k in ("label", "max_passes", "ovr", "has_password"))
        with Vertical(classes="dialog wide"):
            yield Label(self.TITLES[self.kind], classes="title")
            with VerticalScroll(classes="fields"):
                yield Label("目標網址（多個用空格：A/B、盲盒、門；加 *3 = 權重；! = 陷阱門）")
                yield Input(value=pre.get("targets", ""), placeholder="https://example.com", id="targets", compact=True)
                yield Label("玩法")
                yield Select(MODES, value=pre.get("mode", s.default_mode), allow_blank=False, id="mode", compact=True)
                yield Label("紙條內容（僅 note）")
                yield Input(value=pre.get("message", ""), id="message", compact=True)
                yield Label("規則（例：asia=網址; TW=網址; lang:ja=網址; device:ios=網址）")
                yield Input(value=pre.get("geo", ""), id="geo", compact=True)
                with Horizontal(classes="row"):
                    yield Label("自適應語系後綴")
                    yield Switch(value=bool(pre.get("locale")), id="locale")
                yield Label("存活分鐘（留空 = 不限）" + ("　（改目標時不變；要加時間按 e）" if edit else ""))
                yield Input(value=ttl, id="ttl", compact=True, disabled=edit)
                yield Label("人數上限（留空 = 不限）" + ("　（改目標時不變）" if edit else ""))
                yield Input(value=cap, id="maxo", compact=True, disabled=edit)
                with Collapsible(title="進階：名稱、密碼、限通關、開放時間、後綴、設定覆寫", collapsed=not advanced_used):
                    yield Label("名稱（只有你看得到）")
                    yield Input(value=pre.get("label", ""), id="name", compact=True)
                    yield Label("密碼（訪客要輸入才看得到目標）" + ("　留空 = 維持原密碼" if edit and pre.get("has_password") else ""))
                    yield Input(id="password", password=True, compact=True)
                    if edit and pre.get("has_password"):
                        with Horizontal(classes="row"):
                            yield Label("移除密碼")
                            yield Switch(id="nopw")
                    yield Label("通關上限（只讓前 N 位通關，之後連結就死；留空 = 不限）")
                    yield Input(value=pre.get("max_passes", ""), id="passes", compact=True)
                    yield Label("開放時間（例：+30m、+2h、+1d、2026-12-25 09:00；留空 = 立刻）")
                    yield Input(id="starts", compact=True)
                    yield Label("自訂後綴（留空 = 隨機暗號）" + ("　（改目標時不變）" if edit else ""))
                    yield Input(id="token", compact=True, disabled=edit)
                    yield Label("本條連結的設定覆寫（例：theme=dark; accent=#e11d48）")
                    yield Input(value=pre.get("ovr", ""), id="ovr", compact=True)
            yield Static("", id="err")
            with Horizontal(classes="buttons"):
                yield Button("儲存" if edit else "建立", id="ok", variant="success", compact=True)
                yield Button("取消", id="cancel", compact=True)

    def on_button_pressed(self, e: Button.Pressed) -> None:
        if e.button.id == "cancel":
            self.dismiss(None)   # no `return self.dismiss(...)`: Textual would await it inside the handler
            return
        q = lambda i: self.query_one(f"#{i}")  # noqa: E731
        keep = ""
        if self.kind == "edit" and not (self.query("#nopw") and q("nopw").value):
            keep = self.keep_hash
        try:
            spec, ttl, cap = build_from_form(
                mode=q("mode").value, targets=q("targets").value, message=q("message").value, geo=q("geo").value,
                auto_locale=q("locale").value, ttl_min=q("ttl").value, max_opens=q("maxo").value,
                token=q("token").value, overrides=q("ovr").value, label=q("name").value,
                password=q("password").value, max_passes=q("passes").value, starts=q("starts").value, keep_hash=keep)
        except ValueError as err:
            q("err").update(Text(f"✗ {err}", style="red"))
            return
        self.dismiss({"spec": spec, "ttl": ttl, "max": cap})

    def action_cancel(self) -> None:
        self.dismiss(None)


class QRScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "close", "返回"), Binding("q", "close", "返回"), Binding("s", "save", "存檔")]

    def __init__(self, url: str, link_id: str):
        super().__init__()
        self.url, self.link_id = url, link_id

    def compose(self) -> ComposeResult:
        st = self.app.settings  # type: ignore[attr-defined]
        self._border, self._err = st.qr_terminal_border, st.qr_error_level
        cols, lines = qr_size(self.url, self._border, self._err)
        with Vertical(classes="qrbox"):
            if self.app.size.width < cols + 4 or self.app.size.height < lines + 6:
                yield Static(f"終端機太小（需要 {cols}×{lines + 6}），按 s 存成圖片。")
            else:
                yield Static(Text(qr_text(self.url, self._border, self._err), style="black on white", no_wrap=True), id="qrfull")
            yield Static(self.url, id="qrurl")
            yield Static("s 存成 PNG/SVG　esc 返回")

    def action_close(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        self.app.save_qr(self.url, self.link_id)  # type: ignore[attr-defined]


class SettingsScreen(ModalScreen[Optional[dict]]):
    """Every registered option, generated from the registry. Edits are staged in `draft` and only
    reach the live settings (and the config file) when the user presses 儲存."""
    BINDINGS = [Binding("escape", "cancel", "取消"), Binding("space", "cycle", "切換開關／選項")]

    def __init__(self, s: Settings, level: str = "basic"):
        super().__init__()
        self.s, self.level = s, level
        self.query_text = ""
        self.draft: dict = {}
        self.key: Optional[str] = None

    def value_of(self, key: str):
        return self.draft.get(key, getattr(self.s, key))

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            with Horizontal(classes="row2"):
                yield Select([(LEVEL_LABELS[lv], lv) for lv in LEVELS], value=self.level, allow_blank=False,
                             id="level", compact=True)
                yield Input(placeholder="搜尋設定（名稱或說明）", id="search", compact=True)
            yield DataTable(id="opts", cursor_type="row", zebra_stripes=True)
            yield Static(id="help")
            with Horizontal(classes="row2"):
                yield Input(id="value", compact=True)
                yield Button("還原預設", id="reset", compact=True)
            yield Static("", id="msg")
            with Horizontal(classes="row2"):
                yield Select([(f"{name}　{desc}", name) for name, (desc, _) in PRESETS.items()],
                             prompt="預設組合…", id="preset", compact=True)
                yield Button("套用組合", id="apply-preset", compact=True)
            with Horizontal(classes="buttons"):
                yield Button("儲存", id="ok", variant="success", compact=True)
                yield Button("取消", id="cancel", compact=True)

    def on_mount(self) -> None:
        self._table = t = self.query_one("#opts", DataTable)
        t.add_columns("設定", "目前值")
        self._fill()
        t.focus()

    # ---- list ------------------------------------------------------------------------------
    def _fill(self) -> None:
        t = self._table
        keep = self.key
        t.clear()
        opts = options_for(self.level, query=self.query_text)
        for o in opts:
            t.add_row(self._label(o.key), opt_display(o, self.value_of(o.key)), key=o.key)
        keys = [o.key for o in opts]
        if keep in keys:
            t.move_cursor(row=keys.index(keep))
        self.key = keys[t.cursor_row] if keys and 0 <= t.cursor_row < len(keys) else None
        if not keys:
            self.query_one("#help", Static).update(Text("沒有符合的設定。試試別的關鍵字，或切到「專家」看全部。", style="dim"))
            self.query_one("#value", Input).value = ""
        else:
            self._show()

    def _label(self, key: str) -> str:
        o = OPTIONS[key]
        return ("● " if self.value_of(key) != o.default else "  ") + o.label

    def _show(self) -> None:
        if self.key is None:
            return
        o = OPTIONS[self.key]
        self.query_one("#help", Static).update(opt_help(o))
        box = self.query_one("#value", Input)
        box.password = o.secret
        box.placeholder = "（留空 = 不變；要清除請按「還原預設」）" if o.secret else ""
        box.value = opt_text(o, self.value_of(self.key))

    def _msg(self, text: str, ok: bool = False) -> None:
        self.query_one("#msg", Static).update(Text(text, style="green" if ok else "red"))

    def _stage(self, key: str, value) -> None:
        if value == getattr(self.s, key):
            self.draft.pop(key, None)
        else:
            self.draft[key] = value
        if key in self._table.rows:
            o = OPTIONS[key]
            self._table.update_cell(key, self._table.ordered_columns[0].key, self._label(key))
            self._table.update_cell(key, self._table.ordered_columns[1].key, opt_display(o, self.value_of(key)))

    def _commit(self) -> bool:
        """Validate the text box into the draft. False (and a message) when it is invalid."""
        if self.key is None:
            return True
        o = OPTIONS[self.key]
        raw = self.query_one("#value", Input).value
        if o.secret and not raw.strip():
            return True
        if raw == opt_text(o, self.value_of(self.key)):
            return True
        try:
            self._stage(self.key, o.coerce(opt_from_text(o, raw)))
        except ValueError as e:
            self._msg(f"✗ {e}")
            return False
        self._msg("✓ 已暫存，按「儲存」才會生效", ok=True)
        return True

    # ---- events ----------------------------------------------------------------------------
    def on_data_table_row_highlighted(self, e: DataTable.RowHighlighted) -> None:
        if e.row_key is not None and e.row_key.value != self.key:
            self.key = e.row_key.value
            self.query_one("#msg", Static).update("")
            self._show()

    def on_select_changed(self, e: Select.Changed) -> None:
        if e.select.id == "level" and e.value != self.level and isinstance(e.value, str):
            self.level = e.value
            self._fill()

    def on_input_changed(self, e: Input.Changed) -> None:
        if e.input.id == "search" and e.value != self.query_text:
            self.query_text = e.value
            self._fill()

    def on_input_submitted(self, e: Input.Submitted) -> None:
        if e.input.id == "value":
            self._commit()

    def action_cycle(self) -> None:
        if self.key is None or not isinstance(self.focused, DataTable):
            return
        o = OPTIONS[self.key]
        cur = self.value_of(self.key)
        if o.kind == "bool":
            self._stage(self.key, not cur)
        elif o.kind == "choice":
            ch = list(o.choices)
            self._stage(self.key, ch[(ch.index(cur) + 1) % len(ch)] if cur in ch else ch[0])
        else:
            self._msg("這項請在下方輸入框打字，按 Enter 暫存", ok=True)
            return
        self._show()
        self._msg("✓ 已暫存，按「儲存」才會生效", ok=True)

    def on_button_pressed(self, e: Button.Pressed) -> None:
        bid = e.button.id
        if bid == "cancel":
            self.dismiss(None)   # no `return self.dismiss(...)`: Textual would await it inside the handler
        elif bid == "ok":
            if self._commit():
                self.dismiss(dict(self.draft))
        elif bid == "reset" and self.key:
            self._stage(self.key, copy.deepcopy(OPTIONS[self.key].default))
            self._show()
            self._msg("✓ 已改回預設，按「儲存」才會生效", ok=True)
        elif bid == "apply-preset":
            name = self.query_one("#preset", Select).value
            if not isinstance(name, str):          # nothing chosen (Textual's blank sentinel)
                self._msg("先在左邊選一個預設組合")
                return
            tmp = Settings()
            tmp.apply({**self.s.to_dict(), **self.draft})
            diff = preset_diff(tmp, name)
            for k, _old, new in diff:
                self._stage(k, new)
            self._fill()
            self._msg(f"✓ 「{name}」改了 {len(diff)} 項：" + "、".join(OPTIONS[k].label for k, *_ in diff[:4])
                      + ("…" if len(diff) > 4 else "") + "（按「儲存」才生效）" if diff else
                      f"「{name}」跟你目前的設定一樣，沒有要改的", ok=True)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ZincApp(App):
    TITLE = "zinc"
    CSS = """
    #top{height:1;padding:0 1;background:$boost}
    #layout{height:1fr}
    #table{width:1fr;min-width:44}
    #side{width:62;border-left:solid $primary-darken-2;padding:0 1}
    .narrow #layout{layout:vertical}.narrow #side{width:100%;border-left:none;height:50%}.narrow #qr{display:none}
    #qr{margin-top:1;width:auto;height:auto}
    ModalScreen{align:center middle}
    .dialog{width:70;height:auto;max-height:100%;border:round $primary;background:$surface;padding:0 2}
    .dialog.wide{width:86;max-width:100%}
    .fields{height:auto;max-height:16}
    .title{text-style:bold}.buttons{height:1;margin-top:1}.buttons Button{margin-right:2}
    .row{height:1}.row Label{width:1fr}.row Switch{height:1;border:none;padding:0 1}
    #err{height:auto}
    .row2{height:1}.row2 Select{width:1fr}#level{width:14}#search{width:1fr}#value{width:1fr}#reset{width:14;margin-left:1}
    #opts{height:8}#help{height:4;margin-top:1}#msg{height:1}
    .qrbox{width:auto;height:auto;background:white;color:black;padding:1 2}
    #qrurl{color:black}
    """
    BINDINGS = [Binding("n", "new", "新增"), Binding("d", "soft", "銷毀"), Binding("D", "hard", "硬銷毀"),
                Binding("e", "extend", "+10分"), Binding("p", "pause", "暫停/恢復"), Binding("c", "copy", "複製"),
                Binding("q", "qr", "QR"), Binding("s", "save", "存QR"), Binding("r", "rescan", "重掃"),
                Binding("y", "clone", "分身"), Binding("t", "edit", "改目標"), Binding("x", "export", "匯出"),
                Binding("k", "keys", "設定"), Binding("ctrl+q", "quit", "離開")]

    def __init__(self, store: Store, manager: Manager, settings: Settings, qr_dir: Optional[Path] = None,
                 settings_path: Optional[Path] = None, warnings: Optional[list] = None):
        super().__init__()
        self.store, self.manager, self.settings = store, manager, settings
        self.qr_dir, self.settings_path = qr_dir or Path.cwd(), settings_path
        self.warnings = list(warnings or [])
        self._ids: list[str] = []
        self._seen_opens: dict[str, int] = {}

    def compose(self) -> ComposeResult:
        yield Static(id="top")
        with Horizontal(id="layout"):
            yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
            with VerticalScroll(id="side"):
                yield Static(id="detail")
                yield Static(id="qr")
        yield Footer()

    def on_mount(self) -> None:
        # Keep references: while a modal is open, self.query_one() searches the modal, not this screen.
        self._table = t = self.query_one(DataTable)
        self._detail, self._qr, self._top = self.query_one("#detail", Static), self.query_one("#qr", Static), self.query_one("#top", Static)
        t.add_columns("#", "網域", "名稱", "玩法", "人", "狀態", "剩餘")
        self.manager.on_change = self.refresh_all
        self.manager.recover()
        self.run_worker(self.manager.run_ticker(), name="ticker", group="ticker")
        self.set_interval(1.0, self.refresh_all)
        for problem in [*preflight(configured=self.settings.cloudflared_path), *self.warnings]:
            self.notify(problem, severity="warning", timeout=12)
        self.refresh_all()

    def on_resize(self) -> None:
        self.set_class(self.size.width < 100, "narrow")

    # ---- selection / rendering --------------------------------------------------------------
    def selected(self):
        t = self._table
        if not self._ids or not (0 <= t.cursor_row < len(self._ids)):
            return None
        return self.store.get_link(self._ids[t.cursor_row])

    def refresh_all(self) -> None:
        now = time.time()
        t = self._table
        keep = self._ids[t.cursor_row] if self._ids and 0 <= t.cursor_row < len(self._ids) else None
        links = self.store.list_links()
        t.clear()
        self._ids = [lk.id for lk in links]
        for lk in links:
            st = self.store.stats(lk.id, now)
            t.add_row(lk.id[:4], short_host(lk), lk.spec.label[:10], lk.spec.mode, str(st["uniques"]),
                      state_label(lk, now, st["opens"]), fmt_remaining(lk.remaining(now)), key=lk.id)
        if keep in self._ids:
            t.move_cursor(row=self._ids.index(keep))
        self._announce_opens(links, now)
        live = sum(1 for lk in links if lk.status == "live")
        total = sum(self.store.stats(lk.id, now)["uniques"] for lk in links)
        warn = self.manager.errors.get("_webhook")
        self._top.update(f" zinc · 長連結　運作 {live} · 總人數 {total}" + (f"　⚠ {warn}" if warn else ""))
        self.refresh_detail()

    def _announce_opens(self, links, now: float) -> None:
        """Toast / bell when a link got new opens since the last refresh (settings: toast_on_open, bell_on_open)."""
        for lk in links:
            opens = self.store.stats(lk.id, now)["opens"]
            new = opens - self._seen_opens.get(lk.id, 0)
            self._seen_opens[lk.id] = opens
            if new <= 0:
                continue
            if self.settings.toast_on_open:
                country = self.store.last_open_country(lk.id)
                where = "未知地區" if not country or country == "??" else country
                who = "有人" if new == 1 else f"有 {new} 人"
                self.notify(f"👀 {who}打開了 {short_host(lk)}（{where}）", timeout=6)
            if self.settings.bell_on_open:
                self.bell()

    def refresh_detail(self) -> None:
        now = time.time()
        lk = self.selected()
        detail, qr = self._detail, self._qr
        if lk is None:
            detail.update(Text("按 n 新增第一條長連結。\n\n每條連結 = 一個臨時的 trycloudflare 網址。", style="dim"))
            qr.update("")
            return
        url = self.manager.public_url(lk)
        detail.update(detail_text(lk, self.store.stats(lk.id, now), url, now, self.manager.errors.get(lk.id)))
        qr.update(Text(qr_text(url, self.settings.qr_terminal_border, self.settings.qr_error_level),
                       style="black on white", no_wrap=True) if url and lk.status in ("live", "paused") else "")

    def on_data_table_row_highlighted(self) -> None:
        self.refresh_detail()   # not refresh_all: rebuilding rows would re-fire this event forever

    # ---- actions ----------------------------------------------------------------------------
    def action_new(self) -> None:
        self.push_screen(NewLink(self.settings), lambda form: form and self.run_worker(self._create(form, False)))

    async def _create(self, form: dict, force: bool) -> None:
        self.notify("建立中：掃描目標、安全檢查、開隧道…", timeout=4)
        try:
            link = await self.manager.create(form["spec"], form["ttl"], form["max"], force=force)
        except BlockedError as e:
            self.push_screen(Confirm("⛔ 安全檢查擋下了這個目標：\n\n" + "\n".join(
                f"{u}\n  " + "\n  ".join(v.reasons("block")) for u, v in e.verdicts.items()
                if v.reasons("block")) + "\n\n仍要建立？", yes="仍要建立"),
                lambda ok: ok and self.run_worker(self._create(form, True)))
            return
        except (ValueError, TunnelError) as e:
            self.notify(str(e), severity="error", timeout=12)
            return
        url = self.manager.public_url(link) or ""
        if self.settings.auto_copy:
            self.copy_to_clipboard(url)
            self.notify(f"已建立並複製：{url}", timeout=8)
        else:
            self.notify(f"已建立：{url}（按 c 複製）", timeout=8)
        self.refresh_all()

    def action_clone(self) -> None:
        if lk := self.selected():
            self.push_screen(NewLink(self.settings, form_values(lk.spec), "clone"),
                             lambda form: form and self.run_worker(self._create(form, False)))

    def action_edit(self) -> None:
        lk = self.selected()
        if lk is None:
            return
        if lk.status in ("dead", "failed"):
            self.notify("這條連結已經結束，不能改（可以按 y 複製一條新的）", severity="warning")
            return
        self.push_screen(NewLink(self.settings, form_values(lk.spec), "edit", keep_hash=lk.spec.pw_hash),
                         lambda form: form and self.run_worker(self._edit(lk.id, form, False)))

    async def _edit(self, link_id: str, form: dict, force: bool) -> None:
        self.notify("更新中：掃描新目標、安全檢查…", timeout=4)
        try:
            await self.manager.update_spec(link_id, form["spec"], force=force)
        except BlockedError as e:
            self.push_screen(Confirm("⛔ 安全檢查擋下了新的目標：\n\n" + "\n".join(
                f"{u}\n  " + "\n  ".join(v.reasons("block")) for u, v in e.verdicts.items()
                if v.reasons("block")) + "\n\n仍要套用？", yes="仍要套用"),
                lambda ok: ok and self.run_worker(self._edit(link_id, form, True)))
            return
        except ValueError as e:
            self.notify(str(e), severity="error", timeout=12)
            return
        self.notify("已更新，網址、暗號和統計都沒變", timeout=6)
        self.refresh_all()

    def action_export(self) -> None:
        lk = self.selected()
        if lk is None:
            return
        st = self.settings
        folder = Path(st.export_dir).expanduser() if st.export_dir else self.qr_dir
        try:
            paths = export_link(self.store, lk, folder, time.time())
        except OSError as e:
            self.notify(f"匯出失敗：{e}", severity="error", timeout=10)
            return
        self.notify("已匯出：\n" + "\n".join(str(p) for p in paths), timeout=10)

    def action_soft(self) -> None:
        if lk := self.selected():
            self.manager.soft_destroy(lk.id)
            self.notify(f"軟銷毀：訪客會看到墓碑，{self.manager.grace_for(lk):g} 秒後隧道關閉（按 e 可復活）")

    def action_hard(self) -> None:
        lk = self.selected()
        if lk:
            self.push_screen(Confirm("硬銷毀會立刻殺掉隧道，訪客看到的是 Cloudflare 的錯誤頁。", yes="硬銷毀"),
                             lambda ok: ok and self.run_worker(self.manager.hard_destroy(lk.id)))

    def action_extend(self) -> None:
        if lk := self.selected():
            self.manager.extend(lk.id, 600)

    def action_pause(self) -> None:
        if lk := self.selected():
            (self.manager.resume if lk.status == "paused" else self.manager.pause)(lk.id)

    def action_copy(self) -> None:
        lk = self.selected()
        url = lk and self.manager.public_url(lk)
        if url:
            self.copy_to_clipboard(url)
            self.notify(f"已複製：{url}")

    def action_qr(self) -> None:
        lk = self.selected()
        url = lk and self.manager.public_url(lk)
        if url:
            self.push_screen(QRScreen(url, lk.id))

    def action_save(self) -> None:
        lk = self.selected()
        url = lk and self.manager.public_url(lk)
        if url:
            self.save_qr(url, lk.id)

    def save_qr(self, url: str, link_id: str) -> None:
        st = self.settings
        folder = Path(st.qr_export_dir).expanduser() if st.qr_export_dir else self.qr_dir
        opts = dict(error=st.qr_error_level, border=st.qr_export_border, scale=st.qr_export_scale)
        try:
            folder.mkdir(parents=True, exist_ok=True)
            png = export_qr(url, str(folder / f"zinc-{link_id}.png"), **opts)
            export_qr(url, str(folder / f"zinc-{link_id}.svg"), **opts)
            self.notify(f"已存：{png}（和同名 .svg）", timeout=8)
        except OSError as e:
            self.notify(f"存檔失敗：{e}", severity="error")

    def action_rescan(self) -> None:
        if lk := self.selected():
            self.notify("重新掃描並檢查中…")
            self.run_worker(self.manager.rescan(lk.id))

    def action_keys(self) -> None:
        def apply(new: Optional[dict]) -> None:
            if not new:
                return
            try:
                self.settings.apply(new)     # in place: the manager and providers hold this same object
                path = save_settings(self.settings, self.settings_path) if self.settings_path else save_settings(self.settings)
            except (ValueError, OSError) as e:
                self.notify(f"設定沒存成：{e}", severity="error", timeout=10)
                return
            self.notify(f"已儲存 {len(new)} 項設定：{path}", timeout=6)
        self.push_screen(SettingsScreen(self.settings), apply)

    async def action_quit(self) -> None:
        await self.manager.shutdown()
        self.exit()
