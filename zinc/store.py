"""SQLite persistence: links and hits. Only country codes and salted hashes are stored, never IPs."""
from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .models import LinkSpec, STATUSES, validate_spec

SCHEMA = """
CREATE TABLE IF NOT EXISTS links(
  id TEXT PRIMARY KEY, token TEXT NOT NULL, spec TEXT NOT NULL, status TEXT NOT NULL,
  created_at REAL NOT NULL, expires_at REAL, max_opens INTEGER, hostname TEXT, port INTEGER,
  salt TEXT NOT NULL, scan TEXT, grace_until REAL, verdict TEXT);
CREATE TABLE IF NOT EXISTS hits(
  id INTEGER PRIMARY KEY AUTOINCREMENT, link_id TEXT NOT NULL, ts REAL NOT NULL,
  kind TEXT NOT NULL, vid TEXT NOT NULL, country TEXT, continent TEXT, lang TEXT, variant TEXT);
CREATE INDEX IF NOT EXISTS hits_link ON hits(link_id, kind);
"""


@dataclass
class Link:
    id: str
    token: str
    spec: LinkSpec
    status: str
    created_at: float
    expires_at: Optional[float]
    max_opens: Optional[int]
    hostname: Optional[str]
    port: Optional[int]
    salt: str
    scan: Optional[str]
    grace_until: Optional[float]
    verdict: Optional[str] = None

    def remaining(self, now: float) -> Optional[float]:
        return None if self.expires_at is None else max(0.0, self.expires_at - now)


class Store:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
            cols = {r["name"] for r in self._db.execute("PRAGMA table_info(links)")}
            if "verdict" not in cols:  # databases created before the safety checks existed
                self._db.execute("ALTER TABLE links ADD COLUMN verdict TEXT")
            self._db.commit()

    # ---- links -------------------------------------------------------------------------
    def create_link(self, spec: LinkSpec, ttl_s: Optional[float] = None,
                    max_opens: Optional[int] = None, now: Optional[float] = None,
                    token_length: int = 12) -> Link:
        validate_spec(spec)
        now = time.time() if now is None else now
        link_id = secrets.token_hex(4)
        # the path secret; "/" is a decoy. A vanity token trades secrecy for a memorable link.
        token = spec.token or secrets.token_urlsafe(token_length * 3 // 4 + 1)[:token_length]
        with self._lock:
            self._db.execute(
                "INSERT INTO links(id,token,spec,status,created_at,expires_at,max_opens,salt)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (link_id, token, spec.to_json(), "starting", now,
                 None if ttl_s is None else now + ttl_s, max_opens, secrets.token_hex(8)))
            self._db.commit()
        return self.get_link(link_id)  # type: ignore[return-value]

    def get_link(self, link_id: str) -> Optional[Link]:
        with self._lock:
            row = self._db.execute("SELECT * FROM links WHERE id=?", (link_id,)).fetchone()
        return self._link(row) if row else None

    def list_links(self) -> list[Link]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM links ORDER BY created_at DESC").fetchall()
        return [self._link(r) for r in rows]

    @staticmethod
    def _link(r: sqlite3.Row) -> Link:
        return Link(r["id"], r["token"], LinkSpec.from_json(r["spec"]), r["status"],
                    r["created_at"], r["expires_at"], r["max_opens"], r["hostname"], r["port"],
                    r["salt"], r["scan"], r["grace_until"], r["verdict"])

    # The only columns the setters below may touch. Column names cannot be bound as SQL parameters, so they are
    # checked against this list instead; values always are bound.
    _UPDATABLE = frozenset({"status", "grace_until", "hostname", "port", "scan", "verdict", "expires_at"})

    def _update(self, link_id: str, **cols: object) -> None:
        unknown = set(cols) - self._UPDATABLE
        if not cols or unknown:
            raise ValueError(f"cannot update link column(s) {sorted(unknown) or '(none given)'}")
        keys = ", ".join(f"{k}=?" for k in cols)
        with self._lock:
            self._db.execute(f"UPDATE links SET {keys} WHERE id=?", (*cols.values(), link_id))  # nosec B608 - names are allow-listed above
            self._db.commit()

    def set_status(self, link_id: str, status: str, grace_until: Optional[float] = None) -> None:
        if status not in STATUSES:
            raise ValueError(f"bad status {status!r}")
        self._update(link_id, status=status, grace_until=grace_until)

    def set_tunnel(self, link_id: str, hostname: str, port: int) -> None:
        self._update(link_id, hostname=hostname, port=port)

    def set_scan(self, link_id: str, scan_json: str) -> None:
        self._update(link_id, scan=scan_json)

    def set_verdict(self, link_id: str, verdict_json: str) -> None:
        self._update(link_id, verdict=verdict_json)

    def set_expiry(self, link_id: str, expires_at: Optional[float]) -> None:
        self._update(link_id, expires_at=expires_at)

    def extend(self, link_id: str, seconds: float, now: Optional[float] = None) -> None:
        link = self.get_link(link_id)
        if link is None:
            raise KeyError(link_id)
        base = max(link.expires_at or 0.0, time.time() if now is None else now)
        self._update(link_id, expires_at=base + seconds)

    # ---- hits --------------------------------------------------------------------------
    def add_hit(self, link_id: str, kind: str, vid: str, country: Optional[str] = None,
                continent: Optional[str] = None, lang: Optional[str] = None,
                variant: Optional[str] = None, now: Optional[float] = None) -> None:
        if kind not in ("open", "pass", "bot"):
            raise ValueError(f"bad hit kind {kind!r}")
        with self._lock:
            self._db.execute(
                "INSERT INTO hits(link_id,ts,kind,vid,country,continent,lang,variant)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (link_id, time.time() if now is None else now, kind, vid, country, continent,
                 lang, variant))
            self._db.commit()

    def visitor_rank(self, link_id: str, vid: str) -> int:
        """1-based order in which this visitor first opened the link."""
        with self._lock:
            rows = self._db.execute(
                "SELECT vid FROM hits WHERE link_id=? AND kind='open' GROUP BY vid"
                " ORDER BY MIN(id)", (link_id,)).fetchall()
        for i, r in enumerate(rows, 1):
            if r["vid"] == vid:
                return i
        return len(rows) + 1

    def has_hit(self, link_id: str, vid: str, kind: str) -> bool:
        with self._lock:
            return self._db.execute(
                "SELECT 1 FROM hits WHERE link_id=? AND vid=? AND kind=? LIMIT 1",
                (link_id, vid, kind)).fetchone() is not None

    def last_open_ts(self, link_id: str) -> Optional[float]:
        with self._lock:
            row = self._db.execute("SELECT MAX(ts) t FROM hits WHERE link_id=? AND kind='open'",
                                   (link_id,)).fetchone()
        return row["t"]

    def count_opens(self, link_id: str) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM hits WHERE link_id=? AND kind='open'",
                                    (link_id,)).fetchone()[0]

    def set_spec(self, link_id: str, spec: LinkSpec) -> None:
        with self._lock:
            self._db.execute("UPDATE links SET spec=? WHERE id=?", (spec.to_json(), link_id))
            self._db.commit()

    def all_hits(self, link_id: str) -> list:
        with self._lock:
            return self._db.execute("SELECT ts,kind,vid,country,continent,lang,variant FROM hits "
                                    "WHERE link_id=? ORDER BY id", (link_id,)).fetchall()

    def count_hits(self, link_id: str, kind: str) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) n FROM hits WHERE link_id=? AND kind=?",
                                    (link_id, kind)).fetchone()["n"]

    def last_open_country(self, link_id: str) -> Optional[str]:
        with self._lock:
            row = self._db.execute("SELECT country FROM hits WHERE link_id=? AND kind='open' "
                                   "ORDER BY id DESC LIMIT 1", (link_id,)).fetchone()
        return row["country"] if row else None

    def stats(self, link_id: str, now: Optional[float] = None, minutes: int = 20) -> dict:
        now = time.time() if now is None else now
        q = lambda sql, *a: self._db.execute(sql, a).fetchall()  # noqa: E731
        with self._lock:
            kinds = {r["kind"]: r["n"] for r in q(
                "SELECT kind, COUNT(*) n FROM hits WHERE link_id=? GROUP BY kind", link_id)}
            uniques = q("SELECT COUNT(DISTINCT vid) n FROM hits WHERE link_id=? AND kind='open'",
                        link_id)[0]["n"]
            pass_uniques = q("SELECT COUNT(DISTINCT vid) n FROM hits WHERE link_id=? AND kind='pass'",
                             link_id)[0]["n"]
            by_country = {r["country"] or "??": r["n"] for r in q(
                "SELECT country, COUNT(DISTINCT vid) n FROM hits WHERE link_id=? AND kind='open'"
                " GROUP BY country ORDER BY n DESC", link_id)}
            by_continent = {r["continent"] or "unknown": r["n"] for r in q(
                "SELECT continent, COUNT(DISTINCT vid) n FROM hits WHERE link_id=? AND kind='open'"
                " GROUP BY continent ORDER BY n DESC", link_id)}
            by_variant = {r["variant"]: r["n"] for r in q(
                "SELECT variant, COUNT(*) n FROM hits WHERE link_id=? AND kind='pass'"
                " AND variant IS NOT NULL GROUP BY variant ORDER BY n DESC", link_id)}
            ts = [r["ts"] for r in q(
                "SELECT ts FROM hits WHERE link_id=? AND kind='open' AND ts>=?",
                link_id, now - minutes * 60)]
        spark = [0] * minutes
        for t in ts:
            idx = minutes - 1 - int((now - t) // 60)
            if 0 <= idx < minutes:
                spark[idx] += 1
        return {"opens": kinds.get("open", 0), "uniques": uniques, "passes": kinds.get("pass", 0),
                "pass_uniques": pass_uniques, "bots": kinds.get("bot", 0),
                "by_country": by_country, "by_continent": by_continent,
                "by_variant": by_variant, "spark": spark}
