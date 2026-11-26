import pytest
import zxingcpp
from PIL import Image

from zinc.qr import export_qr, qr_matrix, qr_size, qr_text

URL = "https://mild-owl-tree-sky.trycloudflare.com/k7Qm9ZpXa1Bc"


def render(text: str, scale: int = 6) -> Image.Image:
    """Rasterise the half-block text exactly as a black-on-white terminal draws it."""
    lines = text.split("\n")
    w = len(lines[0])
    img = Image.new("L", (w * scale, len(lines) * 2 * scale), 255)
    px = img.load()
    for y, line in enumerate(lines):
        for x, ch in enumerate(line):
            top, bottom = {"█": (1, 1), "▀": (1, 0), "▄": (0, 1), " ": (0, 0)}[ch]
            for half, dark in enumerate((top, bottom)):
                if dark:
                    for dy in range(scale):
                        for dx in range(scale):
                            px[x * scale + dx, (y * 2 + half) * scale + dy] = 0
    return img


def decode(img):
    res = zxingcpp.read_barcodes(img)
    return res[0].text if res else None


def test_terminal_art_round_trips_through_a_real_decoder():
    assert decode(render(qr_text(URL))) == URL


def test_tall_and_short_urls_both_round_trip():
    for url in ("https://a.trycloudflare.com/x", URL + "/" + "z" * 60):
        assert decode(render(qr_text(url))) == url


def test_size_matches_the_text_and_quiet_zone_is_blank():
    text = qr_text(URL)
    cols, lines = qr_size(URL)
    rows = text.split("\n")
    assert (len(rows[0]), len(rows)) == (cols, lines)
    m = qr_matrix(URL, border=2)
    assert not any(m[0]) and not any(m[1]) and not any(r[0] or r[1] for r in m)


@pytest.mark.parametrize("ext", ["png", "svg"])
def test_export_is_print_ready(tmp_path, ext):
    out = export_qr(URL, str(tmp_path / f"q.{ext}"))
    if ext == "png":
        img = Image.open(out).convert("L")
        assert decode(img) == URL
        assert img.getpixel((0, 0)) == 255  # white quiet zone, not transparent or dark
    else:
        svg = open(out).read()
        # segno shortens colours to #fff/#000. Need an opaque white full-size background and black modules.
        assert 'fill="#fff"' in svg and 'stroke="#000"' in svg
        assert svg.index('fill="#fff"') < svg.index('stroke="#000"')  # background is painted first


def test_export_rejects_other_formats(tmp_path):
    with pytest.raises(ValueError):
        export_qr(URL, str(tmp_path / "q.jpg"))
