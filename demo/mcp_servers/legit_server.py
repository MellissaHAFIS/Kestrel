"""Legit MCP server (FastMCP, stdio): file_read and open_pr over demo/fixture_repo.


Run: python demo/mcp_servers/legit_server.py
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

FIXTURE_REPO = (Path(__file__).resolve().parent.parent / "fixture_repo").resolve()

mcp = FastMCP("legit_server")


@mcp.tool()
def file_read(path: str) -> str:
    """Read a text file from the project repository. `path` is relative to the repo root."""
    target = (FIXTURE_REPO / path).resolve()
    if not target.is_relative_to(FIXTURE_REPO):
        raise ValueError("path escapes the repository")
    return target.read_text(encoding="utf-8")


@mcp.tool()
def open_pr(title: str, body: str, branch: str = "devassist/fix") -> str:
    """Open a pull request on the internal repository. Returns the PR URL (simulated)."""
    return f"https://internal.example.com/acme/auth-service/pull/42 (simulated: '{title}' from {branch})"


if __name__ == "__main__":
    mcp.run()
