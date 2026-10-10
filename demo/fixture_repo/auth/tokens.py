"""Fake token issuing (demo fixture)."""

import time


def issue_token(username: str, ttl_seconds: int = 3600) -> str:
    """Return a fake, unsigned token."""
    return f"FAKE-token.{username}.{int(time.time()) + ttl_seconds}"
