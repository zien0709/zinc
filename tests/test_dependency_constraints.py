from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_qr_decoder_dependency_keeps_python_310_wheel_support():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"zxing-cpp>=3.1.1,<3.2"' in pyproject
