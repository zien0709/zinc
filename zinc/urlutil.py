"""Small URL helpers shared by the server and the manager."""
from __future__ import annotations

from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit


def append_params(url: str, extra: str) -> str:
    """Add `a=1&b=2` to a URL's query. Keys the URL already has are left alone (never overwritten)."""
    extra = extra.strip().lstrip("?&")
    if not extra:
        return url
    p = urlsplit(url)
    have = {k for k, _ in parse_qsl(p.query, keep_blank_values=True)}
    new = [(k, v) for k, v in parse_qsl(extra, keep_blank_values=True) if k not in have]
    if not new:
        return url
    query = (p.query + "&" if p.query else "") + urlencode(new)
    return urlunsplit((p.scheme, p.netloc, p.path, query, p.fragment))


def quote_token(token: str) -> str:
    """Percent-encode a path token so vanity tokens like /今天不想上班 are valid in links and Location headers."""
    return quote(token, safe="")
