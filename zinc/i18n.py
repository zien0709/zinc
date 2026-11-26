"""Visitor-page wording in two languages. Host-side screens (the TUI) stay in Traditional Chinese.

`pick_lang("auto", accept_language)`: any Chinese -> zh-Hant, any other language -> en, no header -> zh-Hant.
Simplified Chinese visitors get Traditional text (there is no zh-Hans table yet).
"""
from __future__ import annotations

from typing import Optional

from .locale import parse_accept_language

LANGS = ("zh-Hant", "en")

_EPI_ZH = ["它來過，被點過，然後消失了。", "死於 TTL，享年不長。", "這條連結不是壞了，是畢業了。",
           "此處原有一個網址，願它安息。", "你來晚了一步，剛剛好。", "沒有 404，只有 410：它是刻意死的。"]
_EPI_EN = ["It came, it was clicked, it vanished.", "Died of TTL, aged very young.",
           "This link isn't broken. It graduated.", "A URL once lived here. Rest in peace.",
           "You're one step late. Just on time.", "Not a 404. A 410: it was meant to die."]

STR: dict[str, dict] = {
    "zh-Hant": {
        "note_title": "一張紙條", "go": "前往 →", "reader_n": "第 {n} 位讀者",
        "count_pre": "你是第", "count_post": "位發現者 · {cd} 秒後出發", "count_go": "現在就走 →",
        "count_title": "第 {n} 位", "count_footer": "限時事件",
        "box_title": "盲盒", "box_open": "開箱", "box_hint": "點一下，看看裡面是什麼", "box_footer": "盲盒",
        "door_title": "選一扇門", "door_pick": "選一扇門", "door_n": "第 {n} 扇門", "door_footer": "三思而後行",
        "dead_title": "已死亡", "dead_head": "這條連結已死亡", "trap_head": "💀 這是陷阱門",
        "dead_life": "存活 {life} · 被打開 {n} 次", "life_min": "{m} 分鐘", "life_sec": "{s} 秒",
        "paused_title": "暫停中", "paused_text": "這條連結暫時休息中，晚點再來。",
        "bot_title": "有人傳了一個連結給你", "bot_desc": "點開看看。限時存活，過期即消失。",
        "https_ok": "🔒 HTTPS", "https_no": "⚠️ 非 HTTPS", "hops": " · 轉址 {n} 次",
        "unscanned": "{host} · 尚未掃描", "scan_failed": "{host} · 掃描失敗", "locale_note": "🌐 會依你的語言前往",
        "risky": "⚠️ 掃描判定有風險：{text}", "caution": "⚠️ 注意：{text}",
        "clean": "🛡 已檢查：{names}・未發現威脅",
        "lock_title": "需要密碼", "lock_text": "這條連結上了鎖，輸入密碼才能繼續。", "lock_placeholder": "密碼",
        "lock_button": "解鎖", "lock_wrong": "密碼不對", "lock_wait": "試太多次了，請稍等一分鐘",
        "lock_net": "連線失敗，再試一次", "lock_nojs": "解鎖需要開啟 JavaScript。", "lock_footer": "🔒 受保護的連結",
        "wait_title": "還沒開放", "wait_text": "這條連結還沒開放。", "wait_at": "開放時間：{when}",
        "wait_footer": "再等一下",
        "epitaphs": _EPI_ZH,
    },
    "en": {
        "note_title": "A little note", "go": "Continue →", "reader_n": "Reader #{n}",
        "count_pre": "You are visitor", "count_post": "· leaving in {cd} s", "count_go": "Go now →",
        "count_title": "Visitor #{n}", "count_footer": "Limited-time event",
        "box_title": "Mystery box", "box_open": "Open the box", "box_hint": "Tap to see what's inside",
        "box_footer": "Mystery box",
        "door_title": "Pick a door", "door_pick": "Pick a door", "door_n": "Door {n}", "door_footer": "Choose wisely",
        "dead_title": "Gone", "dead_head": "This link is dead", "trap_head": "💀 A trap door",
        "dead_life": "Lived {life} · opened {n} times", "life_min": "{m} min", "life_sec": "{s} s",
        "paused_title": "Paused", "paused_text": "This link is taking a break. Come back later.",
        "bot_title": "Someone sent you a link", "bot_desc": "Open it. It is temporary and disappears when it expires.",
        "https_ok": "🔒 HTTPS", "https_no": "⚠️ Not HTTPS", "hops": " · {n} redirects",
        "unscanned": "{host} · not scanned yet", "scan_failed": "{host} · scan failed",
        "locale_note": "🌐 Opens in your language",
        "risky": "⚠️ The scan flagged this destination as risky", "caution": "⚠️ Heads up: the scan found some warnings",
        "clean": "🛡 Checked by {names} · no threats found",
        "lock_title": "Password needed", "lock_text": "This link is locked. Enter the password to continue.",
        "lock_placeholder": "Password", "lock_button": "Unlock", "lock_wrong": "Wrong password",
        "lock_wait": "Too many tries. Please wait a minute.", "lock_net": "Connection failed. Try again.",
        "lock_nojs": "JavaScript is needed to unlock.", "lock_footer": "🔒 Protected link",
        "wait_title": "Not open yet", "wait_text": "This link isn't open yet.", "wait_at": "Opens at: {when}",
        "wait_footer": "Hang tight",
        "epitaphs": _EPI_EN,
    },
}


def tr(lang: str, key: str, **kw) -> str:
    table = STR.get(lang) or STR["zh-Hant"]
    text = table.get(key) or STR["zh-Hant"][key]
    return text.format(**kw) if kw else text


def epitaphs(lang: str) -> list[str]:
    return (STR.get(lang) or STR["zh-Hant"])["epitaphs"]


def pick_lang(setting: str, accept_language: Optional[str]) -> str:
    """`setting` is the registry value: auto | zh-Hant | en."""
    if setting in LANGS:
        return setting
    tags = parse_accept_language(accept_language or "")
    if not tags:
        return "zh-Hant"
    return "zh-Hant" if tags[0].split("-")[0] == "zh" else "en"
