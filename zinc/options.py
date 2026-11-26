"""The single source of truth for every adjustable setting.

One `Opt` declares a setting once: plain-language label and help, default, range, which level
shows it (basic / advanced / expert), and whether a single link may override it. The settings file
validation, the TUI settings screen, `--help-settings`, per-link overrides and the tests are all
generated from this table, so adding a feature = adding one entry here (and using it in code).

Deliberately NOT here (security invariants): the SSRF guard on scanned URLs, binding the origin to
127.0.0.1, the 404 decoy on "/", API-key scrubbing, QR codes being black-on-white.
"""
from __future__ import annotations

import copy
import math
import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlsplit

LEVELS = ("basic", "advanced", "expert")
LEVEL_LABELS = {"basic": "簡單", "advanced": "進階", "expert": "專家"}
GROUP_LABELS = {"visitor": "訪客頁面", "redirect": "轉址行為", "safety": "安全檢查", "ops": "營運與連結",
                "tunnel": "隧道", "qr": "QR Code", "notify": "通知 Webhook"}
_TRUE = {"1", "true", "yes", "on", "y", "是", "開", "開啟"}
_FALSE = {"0", "false", "no", "off", "n", "否", "關", "關閉"}
_HEX = re.compile(r"^#(?:[0-9a-f]{3}|[0-9a-f]{6})$")


@dataclass(frozen=True)
class Opt:
    key: str
    group: str
    level: str
    kind: str                       # bool int float str choice color regex list map secret url
    default: Any
    label: str
    help: str                       # one plain-language sentence
    example: str = ""
    min: Optional[float] = None
    max: Optional[float] = None
    choices: tuple = ()             # allowed values (for map: allowed VALUES)
    key_choices: tuple = ()         # map only: allowed KEYS
    per_link: bool = False
    maxlen: int = 500

    @property
    def secret(self) -> bool:
        return self.kind == "secret"

    def coerce(self, raw: Any) -> Any:
        """Validate and normalise one value; raise ValueError with a human sentence on failure."""
        k, name = self.kind, self.label
        if k == "bool":
            if isinstance(raw, bool):
                return raw
            s = str(raw).strip().lower()
            if s in _TRUE:
                return True
            if s in _FALSE:
                return False
            raise ValueError(f"「{name}」要填 開 或 關（收到 {raw!r}）")
        if k in ("int", "float"):
            if isinstance(raw, bool):
                raise ValueError(f"「{name}」要是數字（收到 {raw!r}）")
            try:
                num = int(raw) if k == "int" and str(raw).strip().lstrip("-").isdigit() else float(raw)
                if k == "int":
                    if num != int(num):
                        raise ValueError
                    num = int(num)
            except (TypeError, ValueError):
                raise ValueError(f"「{name}」要是{'整數' if k == 'int' else '數字'}（收到 {raw!r}）") from None
            if not math.isfinite(num):
                raise ValueError(f"「{name}」要是有限的數字（收到 {raw!r}）")
            if (self.min is not None and num < self.min) or (self.max is not None and num > self.max):
                raise ValueError(f"「{name}」要在 {self.min} 到 {self.max} 之間（收到 {num}）")
            return num
        if k == "choice":
            s = str(raw).strip()
            by_lower = {str(c).lower(): c for c in self.choices}
            if s.lower() in by_lower:
                return by_lower[s.lower()]
            raise ValueError(f"「{name}」只能選：{'、'.join(map(str, self.choices))}（收到 {raw!r}）")
        if k == "color":
            s = str(raw).strip().lower()
            if s and not _HEX.match(s):
                raise ValueError(f"「{name}」要是顏色碼，例如 #0f766e（留空 = 預設）；收到 {raw!r}")
            return s
        if k == "regex":
            s = str(raw)
            if len(s) > self.maxlen:
                raise ValueError(f"「{name}」太長（上限 {self.maxlen} 字元）")
            try:
                re.compile(s)
            except re.error as e:
                raise ValueError(f"「{name}」不是合法的正規表示式：{e}") from None
            return s
        if k == "list":
            items = raw if isinstance(raw, (list, tuple)) else re.split(r"[,\s]+", str(raw))
            out = [str(i).strip() for i in items if str(i).strip()]
            if self.choices:
                bad = [i for i in out if i not in self.choices]
                if bad:
                    raise ValueError(f"「{name}」不認得：{'、'.join(bad)}；可用：{'、'.join(map(str, self.choices))}")
            return out
        if k == "map":
            if isinstance(raw, dict):
                pairs = [(str(a).strip(), str(b).strip()) for a, b in raw.items()]
            else:
                pairs = []
                for chunk in filter(None, (c.strip() for c in re.split(r"[,;\n]", str(raw)))):
                    a, sep, b = chunk.partition("=")
                    if not sep:
                        raise ValueError(f"「{name}」格式是 名稱=值，用逗號分隔（錯在 {chunk!r}）")
                    pairs.append((a.strip(), b.strip()))
            bad_k = [a for a, _ in pairs if self.key_choices and a not in self.key_choices]
            if bad_k:
                raise ValueError(f"「{name}」不認得的名稱：{'、'.join(bad_k)}；可用：{'、'.join(self.key_choices)}")
            bad_v = [b for _, b in pairs if self.choices and b not in self.choices]
            if bad_v:
                raise ValueError(f"「{name}」的值只能是：{'、'.join(map(str, self.choices))}（錯在 {'、'.join(bad_v)}）")
            return dict(pairs)
        if k == "url":
            s = str(raw).strip()
            if s == "":
                return ""
            p = urlsplit(s)
            loopback = (p.hostname or "") in ("localhost", "127.0.0.1", "::1")
            if p.scheme not in ("http", "https") or not p.hostname or (p.scheme == "http" and not loopback):
                raise ValueError(f"「{name}」要是 https:// 開頭的網址（只有本機 localhost 可以用 http）；收到 {raw!r}")
            if p.username or p.password:
                raise ValueError(f"「{name}」不要把帳密寫在網址裡")
            if len(s) > self.maxlen:
                raise ValueError(f"「{name}」太長（上限 {self.maxlen} 字元）")
            return s
        s = str(raw)  # str / secret
        if len(s) > self.maxlen:
            raise ValueError(f"「{name}」太長（上限 {self.maxlen} 字元）")
        return s.strip() if k == "secret" else s


def _o(key, group, level, kind, default, label, help, example="", **kw) -> Opt:
    return Opt(key, group, level, kind, default, label, help, example, **kw)


_L0_IDS = ("https", "ip_literal", "punycode", "userinfo", "tunnel_loop", "blocklist", "shortener", "long_url",
           "scan_error", "redirects")
_PROVIDERS = ("virustotal", "safebrowsing", "urlhaus")
BOT_REGEX = (r"bot|crawl|spider|preview|slurp|facebookexternalhit|line-poker|whatsapp|telegram|discord|slack|"
             r"skype|embedly|pinterest|vkshare|headless")

_ALL = [
    # ---- visitor page ----------------------------------------------------------------------
    _o("theme", "visitor", "basic", "choice", "auto", "主題", "訪客頁用亮色、暗色，還是跟著訪客的系統。",
       "auto / light / dark", choices=("auto", "light", "dark"), per_link=True),
    _o("language", "visitor", "basic", "choice", "auto", "訪客頁語言", "auto = 看訪客瀏覽器的語言（中文用中文，其他語言用英文）；也可以固定一種。",
       choices=("auto", "zh-Hant", "en"), per_link=True),
    _o("show_preview", "visitor", "basic", "bool", True, "顯示目標預覽卡", "在玩法頁顯示目標網站的標題、圖示和安全檢查結果。",
       per_link=True),
    _o("accent", "visitor", "advanced", "color", "", "強調色", "按鈕和數字的顏色；留空用預設。", "#e11d48", per_link=True),
    _o("type_speed_ms", "visitor", "advanced", "int", 70, "打字速度（毫秒/字）", "紙條玩法每個字之間隔多久，越小越快。", "40",
       min=10, max=500, per_link=True),
    _o("redirect_delay_ms", "visitor", "advanced", "int", 1600, "自動跳轉等待（毫秒）", "紙條打完後等多久才自動前往目標。0 = 立刻。",
       "2500", min=0, max=30000, per_link=True),
    _o("count_seconds", "visitor", "advanced", "int", 3, "倒數秒數", "「第 N 位」玩法倒數幾秒後出發。0 = 不倒數直接走。", "5",
       min=0, max=30, per_link=True),
    _o("show_countdown", "visitor", "advanced", "bool", True, "顯示剩餘時間", "訪客頁右上角顯示連結還剩多久。", per_link=True),
    _o("show_rank", "visitor", "advanced", "bool", True, "顯示「第 N 位讀者」", "紙條頁底部顯示訪客是第幾位。", per_link=True),
    _o("brand", "visitor", "advanced", "str", "zinc", "品牌字樣", "訪客頁左上角的名字；留空 = 不顯示。", "我的小站", per_link=True, maxlen=40),
    _o("tombstone_text", "visitor", "advanced", "str", "", "墓碑文字", "連結死亡後顯示的話；留空 = 隨機墓誌銘。", "活動已結束，謝謝參與",
       per_link=True, maxlen=200),
    _o("tombstone_status", "visitor", "advanced", "choice", "410", "墓碑的 HTTP 狀態", "410 = 顯示墓碑頁，明說已消失；404 = 假裝這裡從沒有過東西（不顯示墓碑頁）。",
       choices=("410", "404"), per_link=True),
    # ---- redirect --------------------------------------------------------------------------
    _o("rule_order", "redirect", "advanced", "list", ["geo", "lang", "device"], "規則優先順序",
       "地區、語言、裝置三種規則同時命中時，誰排前面誰說了算；沒列出的種類不會生效。", "device, geo",
       choices=("geo", "lang", "device"), per_link=True),
    _o("redirect_status", "redirect", "advanced", "choice", "302", "轉址狀態碼",
       "302 最通用；307 會保留請求方法。不提供 301/308，因為瀏覽器會永久快取，臨時連結不該被記住。",
       choices=("302", "303", "307"), per_link=True),
    _o("utm", "redirect", "advanced", "str", "", "附加追蹤參數", "自動加到目標網址（網址已有的同名參數不會被蓋掉）。",
       "utm_source=zinc&utm_medium=link", per_link=True, maxlen=300),
    _o("referrer_policy", "redirect", "expert", "choice", "no-referrer", "Referrer 政策",
       "目標網站能不能看到訪客是從哪來的。預設完全不告訴它。",
       choices=("no-referrer", "origin", "same-origin", "strict-origin-when-cross-origin"), per_link=True),
    # ---- safety ----------------------------------------------------------------------------
    _o("block_on_malicious", "safety", "basic", "bool", True, "判定惡意就擋下", "安全檢查認為目標是惡意網址時，拒絕建立連結（可手動強制）。"),
    _o("vt_key", "safety", "advanced", "secret", "", "VirusTotal 金鑰", "填了才會用 VirusTotal 檢查目標。免費額度只限非商業用途。",
       "（到 virustotal.com 申請）"),
    _o("gsb_key", "safety", "advanced", "secret", "", "Google Safe Browsing 金鑰", "填了才會用 Google Safe Browsing 檢查。免費僅限非營利用途。"),
    _o("urlhaus_key", "safety", "advanced", "secret", "", "URLhaus Auth-Key", "填了才會用 abuse.ch 的 URLhaus 檢查（需免費註冊）。"),
    _o("providers", "safety", "advanced", "list", list(_PROVIDERS), "啟用的檢查服務", "只有列在這裡的服務會被使用。", "virustotal safebrowsing",
       choices=_PROVIDERS),
    _o("vt_malicious_block", "safety", "advanced", "int", 3, "VirusTotal 擋下門檻", "幾家引擎判惡意才擋下；比這少但至少 1 家 = 警告。", "1",
       min=1, max=70),
    _o("vt_submit_unknown", "safety", "advanced", "bool", False, "VirusTotal 查不到時提交", "提交後網址會對 VirusTotal 社群可見，預設關閉。"),
    _o("send_secret_urls", "safety", "advanced", "bool", False, "含 token 的網址也送第三方", "網址帶 token／簽章／密碼時，預設不送出去檢查。"),
    _o("blocklist", "safety", "advanced", "list", [], "黑名單網域", "命中的網域（含子網域）一律擋下。", "evil.example bad.example"),
    _o("allowlist", "safety", "advanced", "list", [], "白名單網域", "你信任的網域：跳過所有第三方檢查。", "mycompany.com"),
    _o("scan_enabled", "safety", "advanced", "bool", True, "建立時掃描目標", "抓取目標頁面的標題、圖示、語系資訊。關掉會少很多功能。"),
    _o("scan_timeout_s", "safety", "advanced", "float", 5.0, "掃描逾時（秒）", "目標太慢就放棄。", "10", min=1, max=60),
    _o("l0_off", "safety", "expert", "list", [], "關閉的內建檢查", "逐項關掉內建（不連網）檢查。", ",".join(_L0_IDS[:3]), choices=_L0_IDS),
    _o("l0_levels", "safety", "expert", "map", {}, "內建檢查嚴重度", "改某項內建檢查的嚴重程度：ok／info／warn／block。", "https=block,shortener=warn",
       choices=("ok", "info", "warn", "block"), key_choices=_L0_IDS),
    _o("scan_max_kb", "safety", "expert", "int", 512, "掃描讀取上限（KB）", "每個目標最多讀多少內容。", "1024", min=16, max=4096),
    _o("scan_max_hops", "safety", "expert", "int", 5, "掃描最多跟幾次跳轉", "超過視為跳轉迴圈。", "10", min=0, max=15),
    _o("scan_user_agent", "safety", "expert", "str", "zinc-scanner/1.0", "掃描器 User-Agent", "有些網站會擋陌生的 UA。", maxlen=200),
    _o("vt_per_minute", "safety", "expert", "int", 4, "VirusTotal 每分鐘上限", "免費金鑰是 4；付費金鑰可以調高。", min=1, max=1000),
    _o("vt_per_day", "safety", "expert", "int", 500, "VirusTotal 每日上限", "免費金鑰是 500；付費金鑰可以調高。", min=1, max=1000000),
    _o("provider_timeout_s", "safety", "expert", "float", 25.0, "檢查服務逾時（秒）", "整批第三方檢查的總時限。", min=3, max=120),
    _o("cache_ttl_h", "safety", "expert", "float", 24.0, "檢查結果快取（小時）", "同一網址多久內不重查，省額度。", min=0, max=720),
    # ---- ops -------------------------------------------------------------------------------
    _o("default_mode", "ops", "basic", "choice", "plain", "預設玩法", "新增連結時預設選哪種玩法。",
       choices=("plain", "note", "count", "box", "door")),
    _o("default_ttl_min", "ops", "basic", "float", 30.0, "預設存活（分鐘）", "新增連結時預設活多久；0 = 不限時。", "60", min=0, max=525600),
    _o("auto_copy", "ops", "basic", "bool", True, "建立後自動複製網址", "連結建好就放進剪貼簿。"),
    _o("default_max_opens", "ops", "advanced", "int", 0, "預設人數上限", "新增連結時預設最多幾人可打開；0 = 不限。", "10", min=0, max=1000000),
    _o("grace_s", "ops", "advanced", "int", 120, "死亡寬限期（秒）", "連結過期後隧道再撐多久，讓訪客看到墓碑而不是 Cloudflare 的錯誤頁。",
       "300", min=0, max=3600, per_link=True),
    _o("token_length", "ops", "advanced", "int", 12, "暗號長度", "網址後面那串隨機暗號的字元數；越長越難猜。", "20", min=6, max=40),
    _o("bot_response", "ops", "advanced", "choice", "card", "機器人看到什麼", "link 預覽爬蟲（LINE、Discord…）來訪時：card = 給通用預覽卡；404 = 假裝沒東西。",
       choices=("card", "404")),
    _o("count_bots", "ops", "advanced", "bool", True, "統計機器人", "把預覽爬蟲另外記一欄，不計入人數。"),
    _o("curl_mode", "ops", "advanced", "bool", True, "curl 彩蛋", "用 curl 或 wget 打開時回純文字，而不是動畫頁。", per_link=True),
    _o("bot_regex", "ops", "expert", "regex", BOT_REGEX, "機器人判斷規則", "User-Agent 符合這個正規表示式就當機器人。"),
    _o("unique_by", "ops", "expert", "choice", "ip+ua", "不重複訪客的算法", "ip+ua 較細；ip 對同一個辦公室的人比較保守。",
       choices=("ip+ua", "ip", "ua")),
    _o("decoy_text", "ops", "expert", "str", "404 page not found\n", "誘餌頁文字", "有人亂打網址（或只打根路徑）時看到的內容，永遠是 404。", maxlen=300),
    _o("toast_on_open", "ops", "advanced", "bool", True, "有人打開時提示", "TUI 右下角跳出「有人打開了 …（國家）」。"),
    _o("bell_on_open", "ops", "advanced", "bool", False, "有人打開時響鈴", "有人打開連結時，終端機發出一聲提示音。"),
    _o("unlock_tries", "ops", "expert", "int", 5, "密碼每分鐘可試幾次", "同一個訪客一分鐘內最多試幾次密碼，超過就先擋下來，防止猜密碼。", min=1, max=100),
    _o("export_dir", "ops", "advanced", "str", "", "統計匯出資料夾", "按 x 匯出 CSV／JSON 的位置；留空 = 目前所在資料夾。", "~/Documents"),
    # ---- notify (webhook) ------------------------------------------------------------------
    _o("webhook_url", "notify", "advanced", "url", "", "Webhook 網址", "有事發生時 POST 到這裡（Discord、Slack 或你自己的伺服器）；留空 = 不通知。",
       "https://discord.com/api/webhooks/...", maxlen=500),
    _o("webhook_format", "notify", "advanced", "choice", "json", "Webhook 格式", "json = 通用格式（可驗簽章）；discord、slack = 直接貼成聊天訊息。",
       choices=("json", "discord", "slack")),
    _o("webhook_events", "notify", "advanced", "list", ["open"], "通知哪些事件", "open = 有人打開、pass = 有人通關、dead = 連結死亡。", "open, dead",
       choices=("open", "pass", "dead")),
    _o("webhook_secret", "notify", "expert", "secret", "", "Webhook 簽章金鑰", "填了之後，json 格式會附上 X-Zinc-Signature（HMAC-SHA256），讓你的伺服器確認訊息真的來自 zinc。"),
    _o("webhook_timeout_s", "notify", "expert", "float", 5.0, "Webhook 逾時（秒）", "對方太慢就放棄這一則（不會拖慢訪客）。", min=1, max=30),
    _o("webhook_max_per_min", "notify", "expert", "int", 20, "Webhook 每分鐘上限", "超過就略過，避免被狂刷時洗版（Discord 自己也有限流）。", min=1, max=600),
    _o("webhook_country", "notify", "expert", "bool", True, "通知附上國家", "訊息裡帶訪客的國家代碼；關掉則完全不帶任何訪客資訊。"),
    # ---- tunnel ----------------------------------------------------------------------------
    _o("cloudflared_path", "tunnel", "advanced", "str", "", "cloudflared 路徑", "留空 = 自動找（環境變數 ZINC_CLOUDFLARED 或 PATH）。", "/usr/local/bin/cloudflared"),
    _o("tunnel_timeout_s", "tunnel", "advanced", "float", 20.0, "隧道啟動逾時（秒）", "多久內沒拿到 trycloudflare 網址就判失敗。", "40", min=5, max=180),
    _o("tunnel_extra_args", "tunnel", "expert", "list", [], "額外 cloudflared 參數", "原樣加在 tunnel 指令後面。", "--protocol http2"),
    # ---- qr --------------------------------------------------------------------------------
    _o("qr_error_level", "qr", "advanced", "choice", "M", "QR 糾錯等級", "L 最小、H 最耐髒；印在貼紙上建議 Q 或 H。", choices=("L", "M", "Q", "H")),
    _o("qr_export_dir", "qr", "advanced", "str", "", "QR 存檔資料夾", "留空 = 目前所在資料夾。", "~/Pictures"),
    _o("qr_terminal_border", "qr", "expert", "int", 2, "終端機 QR 留白", "QR 外圍空白的格數；少於 2 手機可能掃不到。", min=1, max=8),
    _o("qr_export_border", "qr", "expert", "int", 4, "匯出 QR 留白", "標準是 4 格。", min=2, max=16),
    _o("qr_export_scale", "qr", "expert", "int", 12, "匯出 QR 放大倍率", "每個格子幾個像素。", "20", min=2, max=60),
]

OPTIONS: dict[str, Opt] = {o.key: o for o in _ALL}
assert len(OPTIONS) == len(_ALL), "duplicate option key"


def options_for(level: str = "expert", group: Optional[str] = None, query: str = "", per_link: Optional[bool] = None):
    """Options visible at `level` (basic < advanced < expert), optionally filtered."""
    rank = LEVELS.index(level)
    q = query.strip().lower()
    out = []
    for o in _ALL:
        if LEVELS.index(o.level) > rank or (group and o.group != group):
            continue
        if per_link is not None and o.per_link != per_link:
            continue
        if q and q not in f"{o.key} {o.label} {o.help} {GROUP_LABELS[o.group]}".lower():
            continue
        out.append(o)
    return out


def describe(key: str) -> str:
    o = OPTIONS[key]
    bits = [f"{o.label}（{o.key}）", f"  {o.help}"]
    rng = f"{o.min}–{o.max}" if o.min is not None or o.max is not None else ""
    extra = "、".join(x for x in (f"可選 {'/'.join(map(str, o.choices))}" if o.choices else "", f"範圍 {rng}" if rng else "",
                                  "可每條連結單獨設定" if o.per_link else "") if x)
    bits.append(f"  預設：{o.default!r}" + (f"　{extra}" if extra else "") + (f"　例：{o.example}" if o.example else ""))
    return "\n".join(bits)


def help_all(level: str = "expert") -> str:
    parts = []
    for g, glabel in GROUP_LABELS.items():
        opts = options_for(level, group=g)
        if opts:
            parts.append(f"■ {glabel}\n" + "\n".join(f"[{LEVEL_LABELS[o.level]}] " + describe(o.key) for o in opts))
    return "\n\n".join(parts)


class Settings:
    """Attribute-style access to every registered option; assignment is validated."""

    def __init__(self, **values: Any):
        for o in _ALL:
            self.__dict__[o.key] = copy.deepcopy(o.default)
        if values:
            self.apply(values)

    def __setattr__(self, name: str, value: Any) -> None:
        if name not in OPTIONS:
            raise AttributeError(f"沒有這個設定：{name}")
        self.__dict__[name] = OPTIONS[name].coerce(value)

    def apply(self, changes: dict) -> None:
        """All-or-nothing: if any value is invalid nothing changes."""
        staged = {}
        for k, v in changes.items():
            if k not in OPTIONS:
                raise ValueError(f"沒有這個設定：{k}")
            staged[k] = OPTIONS[k].coerce(v)
        self.__dict__.update(staged)

    def to_dict(self, only_changed: bool = False) -> dict:
        return {k: copy.deepcopy(self.__dict__[k]) for k, o in OPTIONS.items()
                if not only_changed or self.__dict__[k] != o.default}

    def is_default(self, key: str) -> bool:
        return self.__dict__[key] == OPTIONS[key].default

    def reset(self, key: str) -> None:
        self.__dict__[key] = copy.deepcopy(OPTIONS[key].default)

    def secrets(self) -> list[str]:
        return [self.__dict__[k] for k, o in OPTIONS.items() if o.secret and self.__dict__[k]]

    def for_link(self, overrides: Optional[dict]) -> "Settings":
        """A copy with one link's overrides applied. Only per_link options may be overridden."""
        eff = Settings()
        eff.__dict__.update(copy.deepcopy({k: v for k, v in self.__dict__.items() if k in OPTIONS}))
        if overrides:
            eff.__dict__.update(validate_overrides(overrides))
        return eff

    def __repr__(self) -> str:   # never print secrets
        changed = {k: ("***" if OPTIONS[k].secret else v) for k, v in self.to_dict(True).items()}
        return f"Settings({changed})"


def validate_overrides(overrides: dict) -> dict:
    """Coerce a per-link override dict; raises ValueError for unknown or non-overridable keys."""
    out = {}
    for k, v in overrides.items():
        o = OPTIONS.get(k)
        if o is None:
            raise ValueError(f"沒有這個設定：{k}")
        if not o.per_link:
            raise ValueError(f"「{o.label}」不能每條連結單獨設定，請改全域設定")
        out[k] = o.coerce(v)
    return out


# ---- presets: a bundle of changes applied on top of the current settings -------------------------
PRESETS: dict[str, tuple[str, dict]] = {
    "safe": ("安全優先：任何可疑就警告，連 HTTP 都擋", {
        "block_on_malicious": True, "vt_malicious_block": 1, "send_secret_urls": False, "vt_submit_unknown": False,
        "l0_levels": {"https": "block", "ip_literal": "block", "punycode": "block"}, "token_length": 20,
        "bot_response": "card", "show_preview": True}),
    "fun": ("好玩優先：慢一點、誇張一點", {
        "type_speed_ms": 90, "redirect_delay_ms": 2500, "count_seconds": 5, "show_rank": True,
        "show_countdown": True, "show_preview": True, "tombstone_text": ""}),
    "minimal": ("極簡：訪客頁只剩必要的東西", {
        "show_preview": False, "show_countdown": False, "show_rank": False, "brand": "", "redirect_delay_ms": 0,
        "count_seconds": 0, "curl_mode": False}),
}


def preset_diff(settings: Settings, name: str) -> list[tuple[str, Any, Any]]:
    """[(key, current, new)] for the values a preset would actually change."""
    _, changes = PRESETS[name]
    return [(k, getattr(settings, k), OPTIONS[k].coerce(v)) for k, v in changes.items()
            if getattr(settings, k) != OPTIONS[k].coerce(v)]
