"""Fake session store (demo fixture)."""

SESSIONS: dict[str, str] = {}


def start_session(token: str, username: str) -> None:
    SESSIONS[token] = username


def end_session(token: str) -> None:
    SESSIONS.pop(token, None)
