"""Provenance: tag content by Source and keep a per-session history of tagged content.

"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from policyguard.compat import Source  # frozen types.py exports SourceLabel, not Source


@dataclass
class TaggedContent:
    content: str
    source: Source
    ts: float = field(default_factory=time.time)


_HISTORY: dict[str, list[TaggedContent]] = {}


def tag(session_id: str, content: str, source: Source) -> TaggedContent:
    """Tag `content` with its `source` and append it to the session history."""
    item = TaggedContent(content=content, source=source)
    _HISTORY.setdefault(session_id, []).append(item)
    return item


def history(session_id: str) -> list[TaggedContent]:
    """All tagged content seen so far in this session, oldest first."""
    return list(_HISTORY.get(session_id, []))


def sources_for(session_id: str) -> list[Source]:
    """Distinct sources seen so far in the session; feeds Action.sources."""
    seen: list[Source] = []
    for item in _HISTORY.get(session_id, []):
        if item.source not in seen:
            seen.append(item.source)
    return seen


def reset(session_id: str | None = None) -> None:
    """Clear one session (or all if None)."""
    if session_id is None:
        _HISTORY.clear()
    else:
        _HISTORY.pop(session_id, None)
