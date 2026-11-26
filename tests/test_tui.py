import asyncio
import os
import stat
import sys
from pathlib import Path

import pytest
from PIL import Image

from tests.test_qr import decode, render
from zinc.config import Settings
from zinc.manager import Manager
from zinc.reputation import Finding, Provider, Reputation
from zinc.store import Store
from zinc.tui import Confirm, NewLink, QRScreen, SettingsScreen, ZincApp

FAKE = str(Path(__file__).with_name("fake_cloudflared.py"))


async def noscan(urls):
    return {}


class Fixed(Provider):
    name = "urlhaus"

    def __init__(self, s, level):
        super().__init__(s)
        self.level = level

    async def check(self, url, session):
        return Finding("urlhaus", self.level, "bad thing")


def drive(coro_fn, tmp_path, *, size=(120, 40), level=None):
    """Run `coro_fn(app, pilot, store, manager, settings)` inside a headless Textual app."""
    os.environ["ZINC_CLOUDFLARED"] = FAKE

    async def main():
        store, settings = Store(), Settings()
        rep = Reputation(settings, providers=[Fixed(settings, level)]) if level else None
        mgr = Manager(store, lambda p: [sys.executable, FAKE, "tunnel", "--url", f"http://127.0.0.1:{p}"],
                      scanner=noscan, settings=settings, reputation=rep)
        app = ZincApp(store, mgr, settings, qr_dir=tmp_path, settings_path=tmp_path / "cfg.json")
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            try:
                await coro_fn(app, pilot, store, mgr, settings)
            finally:
                await mgr.shutdown()
    asyncio.run(asyncio.wait_for(main(), 60))


async def until(pred, pilot, tries=80):
    for _ in range(tries):
        if pred():
            return True
        await pilot.pause(0.1)
    return False


async def make_link(app, pilot, store, targets="https://example.com"):
    await pilot.press("n")
    await pilot.pause()
    app.screen.query_one("#targets").value = targets
    await pilot.click("#ok")
    assert await until(lambda: any(l.status == "live" for l in store.list_links()), pilot)
    await pilot.pause(0.3)
    return store.list_links()[0]


def row(app):
    return app._table.get_row_at(0)


def cell(app, header):
    """A cell of the first row by its column title (so adding a column never silently shifts the assertions)."""
    names = [str(c.label) for c in app._table.ordered_columns]
    return app._table.get_row_at(0)[names.index(header)]


def test_empty_state_hint(tmp_path):
    async def t(app, pilot, *_):
        assert "按 n 新增" in app._detail.render().plain
    drive(t, tmp_path)


def test_create_copies_url_and_shows_a_scannable_qr(tmp_path):
    async def t(app, pilot, store, mgr, _s):
        link = await make_link(app, pilot, store)
        url = mgr.public_url(link)
        assert app.clipboard == url and app._table.row_count == 1
        assert link.hostname in app._detail.render().plain
        assert decode(render(app._qr.render().plain)) == url   # what the panel shows really scans
    drive(t, tmp_path)


def test_form_validation_keeps_dialog_open(tmp_path):
    async def t(app, pilot, store, *_):
        await pilot.press("n")
        await pilot.pause()
        await pilot.click("#ok")
        await pilot.pause(0.4)   # Textual ignores clicks on a Button for 0.2s after a press (its active effect)
        assert isinstance(app.screen, NewLink) and "至少要一個目標網址" in app.screen.query_one("#err").render().plain
        app.screen.query_one("#targets").value = "ftp://nope.example"
        await pilot.click("#ok")
        await pilot.pause(0.4)
        assert isinstance(app.screen, NewLink) and "http" in app.screen.query_one("#err").render().plain
        assert store.list_links() == []
    drive(t, tmp_path)


def test_blocked_target_asks_then_creates_only_when_confirmed(tmp_path):
    async def t(app, pilot, store, *_):
        await pilot.press("n")
        await pilot.pause()
        app.screen.query_one("#targets").value = "https://example.com"
        await pilot.click("#ok")
        assert await until(lambda: isinstance(app.screen, Confirm), pilot)
        assert "bad thing" in app.screen.query_one("#confirm-text").render().plain
        await app.screen.dismiss(False)                                    # reliable on Windows: Esc/click don't consistently dismiss the modal
        await pilot.pause(0.5)
        assert store.list_links() == []                      # declined: nothing exists
        await pilot.press("n")
        await pilot.pause()
        app.screen.query_one("#targets").value = "https://example.com"
        await pilot.click("#ok")
        assert await until(lambda: isinstance(app.screen, Confirm), pilot)
        await pilot.click("#yes")
        assert await until(lambda: any(l.status == "live" for l in store.list_links()), pilot)
    drive(t, tmp_path, level="block")


def test_keys_soft_extend_pause_and_confirmed_hard_destroy(tmp_path):
    async def t(app, pilot, store, mgr, _s):
        link = await make_link(app, pilot, store)
        assert cell(app, "狀態") == "● 運作"
        await pilot.press("d")
        await pilot.pause(0.3)
        assert cell(app, "狀態") == "◐ 軟死"
        await pilot.press("e")
        await pilot.pause(0.3)
        assert cell(app, "狀態") == "● 運作"                       # extend revives a soft-dead link
        await pilot.press("p")
        await pilot.pause(0.3)
        assert cell(app, "狀態") == "⏸ 暫停"
        await pilot.press("p")
        await pilot.pause(0.3)
        assert cell(app, "狀態") == "● 運作"
        await pilot.press("D")
        await pilot.pause()
        assert isinstance(app.screen, Confirm)
        await pilot.click("#no")
        await pilot.pause(0.3)
        assert store.get_link(link.id).status == "live"      # declined: still alive
        await pilot.press("D")
        await pilot.pause()
        await pilot.click("#yes")
        assert await until(lambda: store.get_link(link.id).status == "dead", pilot)
        await pilot.pause(0.3)
        assert cell(app, "狀態") == "✝ 死亡"
    drive(t, tmp_path)


def test_fullscreen_qr_and_save_to_png(tmp_path):
    async def t(app, pilot, store, mgr, _s):
        link = await make_link(app, pilot, store)
        url = mgr.public_url(link)
        await pilot.press("q")
        await pilot.pause()
        assert isinstance(app.screen, QRScreen)
        assert decode(render(app.screen.query_one("#qrfull").render().plain)) == url
        await pilot.press("s")
        await pilot.pause(0.3)
        png = tmp_path / f"zinc-{link.id}.png"
        assert png.exists() and (tmp_path / f"zinc-{link.id}.svg").exists()
        assert decode(Image.open(png).convert("L")) == url
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, QRScreen)
    drive(t, tmp_path)


def test_narrow_terminal_hides_qr_and_wide_shows_it(tmp_path):
    async def narrow(app, pilot, store, *_):
        await make_link(app, pilot, store)
        assert app.has_class("narrow") and app._qr.styles.display == "none"
    drive(narrow, tmp_path, size=(80, 30))

    async def wide(app, pilot, store, *_):
        await make_link(app, pilot, store)
        assert not app.has_class("narrow") and app._qr.styles.display != "none"
    drive(wide, tmp_path, size=(120, 40))


def test_region_stats_and_visitor_counts_show_up(tmp_path):
    async def t(app, pilot, store, mgr, _s):
        link = await make_link(app, pilot, store)
        for i, (c, k) in enumerate([("TW", "asia"), ("TW", "asia"), ("JP", "asia"), ("DE", "europe")]):
            store.add_hit(link.id, "open", f"v{i}", c, k)
        store.add_hit(link.id, "pass", "v0", "TW", "asia", variant="A")
        app.refresh_all()
        await pilot.pause(0.2)
        text = app._detail.render().plain
        assert "asia" in text and "europe" in text and "TW" in text and "JP" in text and "DE" in text
        assert "開啟 4　不重複 4　通關 1" in text and "轉換率 25%" in text
        assert cell(app, "人") == "4"
    drive(t, tmp_path)


def test_dialog_buttons_stay_on_screen_in_a_24_row_terminal(tmp_path):
    """Regression: the form used to grow past the screen so its buttons were unreachable."""
    async def t(app, pilot, *_):
        for key, screen_type in (("n", NewLink), ("k", SettingsScreen)):
            await pilot.press(key)
            await pilot.pause()
            assert isinstance(app.screen, screen_type)
            for button in ("#ok", "#cancel"):
                assert app.screen.region.contains_region(app.screen.query_one(button).region), (key, button)
            if key == "n":     # an error line appearing must not push the buttons off screen either
                await pilot.click("#ok")
                await pilot.pause(0.4)
                assert app.screen.region.contains_region(app.screen.query_one("#ok").region)
            await pilot.click("#cancel")
            await pilot.pause()
    drive(t, tmp_path, size=(80, 24))
