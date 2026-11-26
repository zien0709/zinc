"""QR rendering. Terminal output is forced black-on-white: scanners need dark modules on a
light background, and a dark-theme terminal would otherwise invert the code into something unscannable."""
from __future__ import annotations

from pathlib import Path

import segno

_HALF = {(False, False): " ", (True, False): "▀", (False, True): "▄", (True, True): "█"}


def qr_matrix(url: str, border: int = 2, error: str = "m") -> list[list[bool]]:
    code = segno.make(url, error=error.lower(), micro=False)
    rows = [[bool(b) for b in row] for row in code.matrix]
    width = len(rows[0]) + 2 * border
    blank = [False] * width
    framed = [list(blank) for _ in range(border)]
    framed += [[False] * border + r + [False] * border for r in rows]
    framed += [list(blank) for _ in range(border)]
    return framed


def qr_text(url: str, border: int = 2, error: str = "m") -> str:
    """Half-block art: two module rows per text line, so the code stays roughly square."""
    m = qr_matrix(url, border, error)
    if len(m) % 2:
        m.append([False] * len(m[0]))
    return "\n".join("".join(_HALF[(top, bottom)] for top, bottom in zip(m[i], m[i + 1]))
                     for i in range(0, len(m), 2))


def qr_size(url: str, border: int = 2, error: str = "m") -> tuple[int, int]:
    """(columns, lines) the text rendering needs, to decide whether the terminal is big enough."""
    m = qr_matrix(url, border, error)
    return len(m[0]), (len(m) + 1) // 2


def export_qr(url: str, path: str, *, error: str = "m", border: int = 4, scale: int = 12) -> str:
    """Save .svg or .png. Colours are fixed black on white on purpose: a scanner needs that."""
    p = Path(path)
    kind = p.suffix.lower().lstrip(".")
    if kind not in ("svg", "png"):
        raise ValueError("use a .svg or .png filename")
    segno.make(url, error=error.lower(), micro=False).save(
        str(p), kind=kind, scale=scale, border=border, dark="#000000", light="#ffffff")
    return str(p)
