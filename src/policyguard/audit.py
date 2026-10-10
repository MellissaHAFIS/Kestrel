"""Audit log: SQLite + JSON export (SIEM-friendly). The console depends on this module.

Owner: Person 4 (audit/console/eval).
First deliverable: live feed showing decisions; then eval harness.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from policyguard.types import Action, Decision

DEFAULT_DB_PATH = "policyguard_audit.db"

COLUMNS = (
    "session_id",
    "timestamp",
    "event_type",
    "action",
    "source_labels",
    "layer",
    "gate_score",
    "model_hash",
    "evidence_ids",
    "violation",
    "severity",
    "confidence",
    "reasoning",
    "decision",
    "decided_by",
    "steps_used",
    "latency_ms",
)

_JSON_COLUMNS = ("action", "source_labels", "evidence_ids")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    timestamp     REAL NOT NULL,
    event_type    TEXT NOT NULL,
    action        TEXT,
    source_labels TEXT,
    layer         TEXT,
    gate_score    REAL,
    model_hash    TEXT,
    evidence_ids  TEXT,
    violation     TEXT,
    severity      TEXT,
    confidence    REAL,
    reasoning     TEXT,
    decision      TEXT,
    decided_by    TEXT,
    steps_used    INTEGER,
    latency_ms    REAL
);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log(decision);
"""


def db_path(path: str | Path | None = None) -> str:
    return str(path or os.environ.get("POLICYGUARD_DB") or DEFAULT_DB_PATH)


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open the DB (creating the schema if needed)."""
    conn = sqlite3.connect(db_path(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def init_db(path: str | Path | None = None) -> None:
    connect(path).close()


def log_decision(
    action: Action,
    decision: Decision,
    *,
    event_type: str = "tool_call",
    decided_by: str | None = None,
    model_hash: str | None = None,
    violation: str | None = None,
    severity: str | None = None,
    steps_used: int | None = None,
    latency_ms: float | None = None,
    path: str | Path | None = None,
) -> int:
    """Insert one row and return its id. `decided_by` defaults to the deciding layer."""
    conn = connect(path)
    try:
        cur = conn.execute(
            f"INSERT INTO audit_log ({', '.join(COLUMNS)}) VALUES ({', '.join('?' * len(COLUMNS))})",
            (
                action.session_id,
                time.time(),
                event_type,
                json.dumps(action.to_dict()),
                json.dumps([s.value for s in action.sources]),
                decision.layer,
                decision.score,
                model_hash,
                json.dumps(decision.evidence_ids),
                violation,
                severity,
                decision.confidence,
                decision.reason,
                decision.verdict.value,
                decided_by or decision.layer,
                steps_used,
                latency_ms,
            ),
        )
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    for col in _JSON_COLUMNS:
        if d.get(col) is not None:
            d[col] = json.loads(d[col])
    return d


def list_decisions(
    *,
    session_id: str | None = None,
    decision: str | None = None,
    since_id: int = 0,
    limit: int = 200,
    path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Rows as dicts, oldest first. `since_id` supports polling for a live feed."""
    sql = "SELECT * FROM audit_log WHERE id > ?"
    params: list[Any] = [since_id]
    if session_id is not None:
        sql += " AND session_id = ?"
        params.append(session_id)
    if decision is not None:
        sql += " AND decision = ?"
        params.append(decision)
    sql += " ORDER BY id ASC LIMIT ?"
    params.append(limit)
    conn = connect(path)
    try:
        return [_row_to_dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def export_json(out_path: str | Path | None = None, *, path: str | Path | None = None) -> str:
    """Export the whole log as a JSON array string; also writes it to `out_path` if given."""
    text = json.dumps(list_decisions(limit=1_000_000, path=path), indent=2)
    if out_path is not None:
        Path(out_path).write_text(text, encoding="utf-8")
    return text
