"""Password gate hashing. The plaintext never reaches the database, the logs or the settings file."""
from __future__ import annotations

import hashlib
import hmac
import secrets

_ITER = 120_000
_PREFIX = "pbkdf2"


def hash_password(password: str, *, iterations: int = _ITER) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{_PREFIX}${iterations}${salt.hex()}${digest.hex()}"


def is_hash(stored: str) -> bool:
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] != _PREFIX or not parts[1].isdigit():
        return False
    try:
        bytes.fromhex(parts[2])
        bytes.fromhex(parts[3])
    except ValueError:
        return False
    return 1 <= int(parts[1]) <= 10_000_000


def check_password(password: str, stored: str) -> bool:
    """Constant-time compare. A malformed stored value never matches (and never raises)."""
    if not is_hash(stored):
        return False
    _, iters, salt, want = stored.split("$")
    got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
    return hmac.compare_digest(got.hex(), want)
