"""Settings persistence: a 0600 JSON file (only non-default values) plus ZINC_<KEY> environment overrides."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Mapping, Optional

from .options import OPTIONS, Settings

__all__ = ["Settings", "config_path", "load_settings", "load_settings_with_warnings", "save_settings", "mask", "scrub"]


def config_path(env: Optional[Mapping[str, str]] = None) -> Path:
    env = os.environ if env is None else env
    if sys.platform == "win32" and env.get("APPDATA"):
        return Path(env["APPDATA"]) / "zinc" / "config.json"
    base = env.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "zinc" / "config.json"


def load_settings_with_warnings(path: Optional[Path] = None,
                                env: Optional[Mapping[str, str]] = None) -> tuple[Settings, list[str]]:
    """File first, then ZINC_<KEY> environment variables override. A bad value never stops startup:
    it is ignored (the default stays) and reported in the returned warnings."""
    env = os.environ if env is None else env
    path = path or config_path(env)
    s, warnings = Settings(), []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("設定檔最外層要是 JSON 物件")
    except FileNotFoundError:
        data = {}
    except (OSError, ValueError) as e:
        data = {}
        warnings.append(f"設定檔讀不了，已用預設值（{path}）：{e}")
    for key, raw in data.items():
        if key.startswith("_"):
            continue
        if key not in OPTIONS:
            warnings.append(f"設定檔有不認得的項目，已忽略：{key}")
            continue
        try:
            setattr(s, key, raw)
        except ValueError as e:
            warnings.append(f"設定檔的 {e}；這項改用預設值")
    for key in OPTIONS:
        raw = env.get("ZINC_" + key.upper())
        if raw not in (None, ""):
            try:
                setattr(s, key, raw)
            except ValueError as e:
                warnings.append(f"環境變數 ZINC_{key.upper()}：{e}；已忽略")
    return s, warnings


def load_settings(path: Optional[Path] = None, env: Optional[Mapping[str, str]] = None) -> Settings:
    return load_settings_with_warnings(path, env)[0]


def save_settings(s: Settings, path: Optional[Path] = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # never world-readable, even briefly
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"_version": 1, **s.to_dict(only_changed=True)}, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    if sys.platform != "win32":
        os.chmod(path, 0o600)
    return path


def mask(key: str) -> str:
    if not key:
        return "（未設定）"
    return key[:4] + "…" + key[-4:] if len(key) > 10 else "•" * len(key)


def scrub(text: str, secrets: list[str]) -> str:
    """Remove API keys from any string that might reach the screen or a log."""
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text
