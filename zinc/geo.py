"""Visitor geography: country -> continent table and a resolver chain.

Continent names are lowercase words ("asia"), countries are UPPERCASE ISO codes ("TW").
They never share a namespace on purpose: ISO has AS/AF/NA/SA (American Samoa, Afghanistan,
Namibia, Saudi Arabia) which would collide with two-letter continent codes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Sequence

_CONTINENT_CODES = {
    "asia": "AE AF AM AZ BD BH BN BT CN GE HK ID IL IN IQ IR JO JP KG KH KP KR KW KZ LA LB LK "
            "MM MN MO MV MY NP OM PH PK PS QA SA SG SY TH TJ TL TM TR TW UZ VN YE",
    "europe": "AD AL AT AX BA BE BG BY CH CY CZ DE DK EE ES FI FO FR GB GG GI GR HR HU IE IM IS "
              "IT JE LI LT LU LV MC MD ME MK MT NL NO PL PT RO RS RU SE SI SJ SK SM UA VA XK",
    "north_america": "AG AI AW BB BL BM BQ BS BZ CA CR CU CW DM DO GD GL GP GT HN HT JM KN KY LC "
                     "MF MQ MS MX NI PA PM PR SV SX TC TT US VC VG VI",
    "south_america": "AR BO BR CL CO EC FK GF GY PE PY SR UY VE",
    "africa": "AO BF BI BJ BW CD CF CG CI CM CV DJ DZ EG EH ER ET GA GH GM GN GQ GW KE KM LR LS "
              "LY MA MG ML MR MU MW MZ NA NE NG RE RW SC SD SL SN SO SS ST SZ TD TG TN TZ UG YT "
              "ZA ZM ZW",
    "oceania": "AS AU CK FJ FM GU KI MH MP NC NF NR NU NZ PF PG PN PW SB TK TO TV VU WF WS",
    "antarctica": "AQ BV GS HM TF",
}

CONTINENTS = tuple(_CONTINENT_CODES)
COUNTRY_TO_CONTINENT: dict[str, str] = {
    code: continent for continent, codes in _CONTINENT_CODES.items() for code in codes.split()
}

_ALPHA2 = re.compile(r"^[A-Za-z]{2}$")
_UNKNOWN_CODES = {"XX", "T1"}  # Cloudflare: no data / Tor


def continent_of(country: Optional[str]) -> Optional[str]:
    return COUNTRY_TO_CONTINENT.get((country or "").upper())


def is_valid_match(token: str) -> bool:
    """A geo-rule key is either an UPPERCASE known country code or a lowercase continent name."""
    return token in CONTINENTS or token in COUNTRY_TO_CONTINENT


@dataclass(frozen=True)
class Geo:
    country: Optional[str] = None
    continent: Optional[str] = None
    source: str = "none"


Resolver = Callable[[Mapping[str, str], str], Optional[str]]  # (headers, ip) -> country code


def header_resolver(headers: Mapping[str, str], ip: str) -> Optional[str]:
    raw = (headers.get("CF-IPCountry") or "").strip()
    if not _ALPHA2.match(raw) or raw.upper() in _UNKNOWN_CODES:
        return None
    return raw.upper()


def mmdb_resolver(path: str) -> Resolver:
    """Optional offline fallback (DB-IP / GeoLite2 country .mmdb). Needs `pip install maxminddb`."""
    import maxminddb  # imported lazily: optional dependency

    reader = maxminddb.open_database(path)

    def resolve(headers: Mapping[str, str], ip: str) -> Optional[str]:
        try:
            rec = reader.get(ip) or {}
        except (ValueError, OSError):
            return None
        code = ((rec.get("country") or {}).get("iso_code") or "").upper()
        return code if _ALPHA2.match(code) else None

    return resolve


def resolve_geo(headers: Mapping[str, str], ip: str,
                chain: Sequence[Resolver] = (header_resolver,)) -> Geo:
    for fn in chain:
        country = fn(headers, ip)
        if country:
            return Geo(country, continent_of(country), getattr(fn, "__name__", "resolver"))
    return Geo()


def client_ip(headers: Mapping[str, str], peer: str) -> str:
    """Origin only listens on 127.0.0.1 behind cloudflared, so Cloudflare's headers are trusted."""
    ip = (headers.get("CF-Connecting-IP") or "").strip()
    if ip:
        return ip
    xff = (headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return xff or peer
