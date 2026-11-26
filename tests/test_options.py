import json
import math
import os
import stat
import sys

import pytest

from zinc.config import (load_settings, load_settings_with_warnings, save_settings)
from zinc.options import (GROUP_LABELS, LEVELS, OPTIONS, PRESETS, Settings, describe, help_all, options_for,
                          preset_diff, validate_overrides)


# ---- the registry itself ---------------------------------------------------------------------
@pytest.mark.parametrize("key", list(OPTIONS))
def test_every_option_is_well_formed(key):
    o = OPTIONS[key]
    assert o.key == key and o.group in GROUP_LABELS and o.level in LEVELS
    assert len(o.label) >= 2 and len(o.help) >= 8, "plain-language help is mandatory"
    assert o.coerce(o.default) == o.default, "the default must be a valid value"
    assert o.coerce(o.coerce(o.default)) == o.coerce(o.default)
    if o.kind == "choice":
        assert o.default in o.choices
    if o.min is not None and o.max is not None:
        assert o.min <= o.default <= o.max if o.kind in ("int", "float") else True
    if o.secret:
        assert o.default == "" and not o.per_link


def test_levels_nest_and_basic_stays_small():
    basic, adv, exp = (set(o.key for o in options_for(lv)) for lv in LEVELS)
    assert basic < adv < exp and 5 <= len(basic) <= 12
    assert len(exp) == len(OPTIONS) >= 50


def test_search_and_group_filters():
    assert {o.key for o in options_for("expert", query="key")} >= {"vt_key", "gsb_key", "urlhaus_key"}
    assert {o.key for o in options_for("expert", query="金鑰")} >= {"vt_key", "gsb_key"}
    assert all(o.group == "qr" for o in options_for("expert", group="qr"))
    assert options_for("expert", query="zzzz-no-such") == []
    assert all(o.per_link for o in options_for("expert", per_link=True))


def test_descriptions_and_help_mention_every_option():
    text = help_all()
    assert all(o.label in text for o in OPTIONS.values())
    assert "預設：" in describe("theme") and "auto / light / dark" in describe("theme")
    assert "可每條連結單獨設定" in describe("theme") and "可每條連結單獨設定" not in describe("vt_key")


# ---- coercion --------------------------------------------------------------------------------
@pytest.mark.parametrize("key,raw,want", [
    ("show_preview", "off", False), ("show_preview", "是", True), ("show_preview", True, True), ("show_preview", "OFF", False),
    ("type_speed_ms", "40", 40), ("type_speed_ms", 40.0, 40), ("scan_timeout_s", "7", 7.0),
    ("theme", "DARK", "dark"), ("accent", "#ABC", "#abc"), ("accent", "", ""), ("accent", " #0F766E ", "#0f766e"),
    ("providers", "virustotal urlhaus", ["virustotal", "urlhaus"]), ("providers", "virustotal, urlhaus", ["virustotal", "urlhaus"]),
    ("blocklist", ["a.example", " b.example "], ["a.example", "b.example"]), ("blocklist", "", []),
    ("l0_levels", "https=block, shortener=warn", {"https": "block", "shortener": "warn"}), ("l0_levels", {"https": "block"}, {"https": "block"}),
    ("vt_key", "  secret  ", "secret"),
])
def test_coerce_accepts(key, raw, want):
    assert OPTIONS[key].coerce(raw) == want


@pytest.mark.parametrize("key,raw,needle", [
    ("show_preview", "maybe", "開 或 關"), ("type_speed_ms", "abc", "整數"), ("type_speed_ms", "3.5", "整數"),
    ("type_speed_ms", 5, "10 到 500"), ("type_speed_ms", 501, "10 到 500"), ("type_speed_ms", True, "數字"),
    ("scan_timeout_s", "nan", "有限"), ("scan_timeout_s", "inf", "有限"), ("scan_timeout_s", 0.5, "1"),
    ("theme", "pink", "auto、light、dark"), ("accent", "red", "顏色碼"), ("accent", "#12345", "顏色碼"),
    ("bot_regex", "(unclosed", "正規表示式"), ("bot_regex", "x" * 501, "太長"),
    ("providers", "virustotal bogus", "bogus"), ("l0_off", "nope", "nope"), ("l0_levels", "no-equals-sign", "名稱=值"),
    ("brand", "x" * 41, "太長"),
    ("l0_levels", "nope=block", "不認得的名稱"), ("l0_levels", "https=maybe", "值只能是"),
])
def test_coerce_rejects_with_a_human_message(key, raw, needle):
    with pytest.raises(ValueError, match=needle):
        OPTIONS[key].coerce(raw)


def test_range_edges_are_inclusive():
    o = OPTIONS["type_speed_ms"]
    assert o.coerce(10) == 10 and o.coerce(500) == 500
    assert math.isfinite(OPTIONS["cache_ttl_h"].coerce(0))


# ---- Settings object -------------------------------------------------------------------------
def test_defaults_assignment_validation_and_unknown_names():
    s = Settings()
    assert s.theme == "auto" and s.type_speed_ms == 70 and s.block_on_malicious is True
    s.theme = "DARK"
    assert s.theme == "dark"
    with pytest.raises(ValueError):
        s.theme = "pink"
    assert s.theme == "dark"
    with pytest.raises(AttributeError):
        s.nonsense = 1
    with pytest.raises(ValueError, match="沒有這個設定"):
        Settings(nonsense=1)
    assert Settings(vt_key="k", blocklist="a.example").blocklist == ["a.example"]


def test_apply_is_all_or_nothing():
    s = Settings()
    with pytest.raises(ValueError):
        s.apply({"theme": "dark", "type_speed_ms": 1})
    assert s.theme == "auto" and s.type_speed_ms == 70
    s.apply({"theme": "dark", "type_speed_ms": 100})
    assert (s.theme, s.type_speed_ms) == ("dark", 100)


def test_changed_only_reset_defaults_and_secret_handling():
    s = Settings(theme="dark", vt_key="TOPSECRET123")
    assert s.to_dict(only_changed=True) == {"theme": "dark", "vt_key": "TOPSECRET123"}
    assert not s.is_default("theme") and s.is_default("accent")
    assert s.secrets() == ["TOPSECRET123"] and "TOPSECRET123" not in repr(s) and "theme" in repr(s)
    s.reset("theme")
    assert s.is_default("theme") and s.to_dict(True) == {"vt_key": "TOPSECRET123"}


def test_defaults_are_not_shared_between_instances():
    a, b = Settings(), Settings()
    a.blocklist.append("x.example")
    a.l0_levels["https"] = "block"
    assert b.blocklist == [] and Settings().blocklist == [] and OPTIONS["blocklist"].default == []
    assert Settings().l0_levels == {}


# ---- per-link overrides ----------------------------------------------------------------------
def test_for_link_applies_only_per_link_options_and_never_mutates_the_global():
    g = Settings(theme="dark", blocklist=["a.example"])
    eff = g.for_link({"theme": "light", "type_speed_ms": "40"})
    assert (eff.theme, eff.type_speed_ms) == ("light", 40) and (g.theme, g.type_speed_ms) == ("dark", 70)
    eff.blocklist.append("zzz.example")
    assert g.blocklist == ["a.example"]                      # deep copy: lists are not shared
    assert g.for_link(None).theme == "dark" and g.for_link({}).theme == "dark"
    with pytest.raises(ValueError, match="全域"):
        g.for_link({"vt_key": "x"})
    with pytest.raises(ValueError, match="沒有這個設定"):
        validate_overrides({"nope": 1})
    with pytest.raises(ValueError):
        validate_overrides({"theme": "pink"})


def test_secrets_and_security_critical_options_cannot_be_overridden_per_link():
    for o in OPTIONS.values():
        if o.secret or o.key in ("block_on_malicious", "blocklist", "allowlist", "send_secret_urls", "providers",
                                 "bot_regex", "decoy_text", "scan_enabled"):
            assert not o.per_link, o.key


# ---- presets ---------------------------------------------------------------------------------
@pytest.mark.parametrize("name", list(PRESETS))
def test_presets_are_valid_and_diff_shows_only_real_changes(name):
    title, changes = PRESETS[name]
    assert title and changes
    s = Settings()
    diff = {k: new for k, _old, new in preset_diff(s, name)}
    assert set(diff) <= set(changes)
    s.apply(changes)
    assert preset_diff(s, name) == []                        # applying twice changes nothing more
    assert all(getattr(s, k) == OPTIONS[k].coerce(v) for k, v in changes.items())


def test_minimal_and_safe_presets_do_what_they_say():
    s = Settings()
    s.apply(PRESETS["minimal"][1])
    assert (s.show_preview, s.show_countdown, s.brand) == (False, False, "")
    s = Settings()
    s.apply(PRESETS["safe"][1])
    assert s.vt_malicious_block == 1 and s.l0_levels["https"] == "block"


# ---- settings file + environment -------------------------------------------------------------
def test_file_stores_only_changes_privately_and_roundtrips(tmp_path):
    p = tmp_path / "z" / "config.json"
    save_settings(Settings(theme="dark", vt_key="K" * 12, l0_levels={"https": "block"}), p)
    data = json.loads(p.read_text())
    assert data == {"_version": 1, "theme": "dark", "vt_key": "K" * 12, "l0_levels": {"https": "block"}}
    if sys.platform != "win32":
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    s, warns = load_settings_with_warnings(p, env={})
    assert (s.theme, s.vt_key, s.l0_levels, warns) == ("dark", "K" * 12, {"https": "block"}, [])


def test_bad_file_values_fall_back_to_default_with_a_warning(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"theme": "pink", "type_speed_ms": 80, "mystery": 1, "_version": 1}))
    s, warns = load_settings_with_warnings(p, env={})
    assert s.theme == "auto" and s.type_speed_ms == 80
    assert any("pink" in w for w in warns) and any("mystery" in w for w in warns) and len(warns) == 2
    for body, needle in (("not json", "讀不了"), ("[1, 2]", "JSON 物件")):
        p.write_text(body)
        s, warns = load_settings_with_warnings(p, env={})
        assert s.to_dict(True) == {} and needle in warns[0]
    s, warns = load_settings_with_warnings(tmp_path / "missing.json", env={})
    assert warns == [] and s.to_dict(True) == {}


def test_every_option_can_come_from_the_environment_and_bad_env_is_ignored(tmp_path):
    s, warns = load_settings_with_warnings(tmp_path / "x.json", env={"ZINC_THEME": "dark", "ZINC_TYPE_SPEED_MS": "30"})
    assert (s.theme, s.type_speed_ms, warns) == ("dark", 30, [])
    s, warns = load_settings_with_warnings(tmp_path / "x.json", env={"ZINC_THEME": "pink", "ZINC_VT_KEY": "abc"})
    assert s.theme == "auto" and s.vt_key == "abc" and len(warns) == 1 and "ZINC_THEME" in warns[0]
    p = tmp_path / "y.json"
    p.write_text(json.dumps({"theme": "light"}))
    assert load_settings(p, env={"ZINC_THEME": "dark"}).theme == "dark"       # env beats file
    assert load_settings(p, env={"ZINC_THEME": ""}).theme == "light"           # empty env var is not an override


def test_every_option_is_read_by_real_code():
    """An option nobody reads is a lie in the settings screen. Each key must appear in some module
    other than the registry and the config loader (which only store it)."""
    import re
    from pathlib import Path
    root = Path(__file__).parent.parent / "zinc"
    code = {p.name: p.read_text(encoding="utf-8") for p in root.glob("*.py") if p.name not in ("options.py", "config.py")}
    dead = [k for k in OPTIONS if not any(re.search(rf"\b{k}\b", src) for src in code.values())]
    assert dead == []


def test_every_option_has_a_behaviour_test_somewhere():
    """Adding an option without a test that exercises it fails here, so a setting can't ship unproven."""
    import re
    from pathlib import Path
    tests = {p.name: p.read_text(encoding="utf-8") for p in Path(__file__).parent.glob("test_*.py")
             if p.name != "test_options.py"}
    untested = [k for k in OPTIONS if not any(re.search(rf"\b{k}\b", t) for t in tests.values())]
    assert untested == []
