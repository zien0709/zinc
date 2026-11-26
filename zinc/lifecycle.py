"""When is a link allowed to serve? One function, shared by the server and the tunnel manager."""
from __future__ import annotations

from .store import Link


def effective_state(link: Link, now: float, human_opens: int, admitted: bool = False) -> str:
    """'live' | 'paused' | 'dead'.

    `admitted`: this visitor already opened the link, so hitting max_opens afterwards must not
    lock them out of the very last step (/go).
    """
    if link.status in ("soft_dead", "dead", "failed"):
        return "dead"
    if link.expires_at is not None and now >= link.expires_at:
        return "dead"
    if link.max_opens is not None and not admitted and human_opens >= link.max_opens:
        return "dead"
    if link.status == "paused":
        return "paused"
    return "live"
