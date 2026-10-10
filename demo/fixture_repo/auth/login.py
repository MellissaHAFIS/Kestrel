"""Fake login handler (demo fixture)."""

from auth.tokens import issue_token

FAKE_USERS = {"alice": "FAKE-password-alice", "bob": "FAKE-password-bob"}


def login(username: str, password: str) -> str | None:
    """Return a token if the credentials match, else None."""
    # BUG (for the demo task): plain string comparison, not constant time.
    if FAKE_USERS.get(username) == password:
        return issue_token(username)
    return None
