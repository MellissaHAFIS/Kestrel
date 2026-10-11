"""Audit log: async SQLite (aiosqlite) + JSON/CSV export (SIEM-friendly).


Single table "events" whose columns map 1-to-1 to `AuditEntry` fields. The list
fields (`source_labels`, `evidence_ids`) are stored as JSON strings; `timestamp`
is stored as an ISO-8601 string so it round-trips through pydantic.

Usage:
    from policyguard.audit import audit_log
    await audit_log.init()            # once at startup
    await audit_log.log(entry)
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from typing import Any

import aiosqlite

from policyguard.types import AuditEntry

DEFAULT_DB_PATH = "policyguard_audit.db"

#: Column order used by every INSERT and by the CSV export. 1-to-1 with AuditEntry.
COLUMNS: tuple[str, ...] = (
    "id",
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

#: Columns persisted as JSON strings.
_JSON_COLUMNS: tuple[str, ...] = ("source_labels", "evidence_ids")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    action        TEXT NOT NULL,
    source_labels TEXT NOT NULL,
    layer         TEXT NOT NULL,
    gate_score    REAL,
    model_hash    TEXT,
    evidence_ids  TEXT NOT NULL,
    violation     INTEGER NOT NULL DEFAULT 0,
    severity      TEXT NOT NULL DEFAULT 'low',
    confidence    REAL,
    reasoning     TEXT NOT NULL DEFAULT '',
    decision      TEXT NOT NULL DEFAULT 'pending',
    decided_by    TEXT NOT NULL DEFAULT 'system',
    steps_used    INTEGER NOT NULL DEFAULT 0,
    latency_ms    REAL NOT NULL DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision);
"""


def _to_row(entry: AuditEntry) -> tuple[Any, ...]:
    """Flatten an AuditEntry into a row tuple matching COLUMNS."""
    d = entry.model_dump()
    d["timestamp"] = entry.timestamp.isoformat()
    d["violation"] = int(entry.violation)
    for col in _JSON_COLUMNS:
        d[col] = json.dumps(d[col])
    return tuple(d[col] for col in COLUMNS)


def _from_row(row: aiosqlite.Row) -> AuditEntry:
    """Rebuild an AuditEntry from a DB row."""
    d = dict(row)
    for col in _JSON_COLUMNS:
        d[col] = json.loads(d[col])
    d["violation"] = bool(d["violation"])
    return AuditEntry.model_validate(d)


class AuditLog:
    """
    Single SQLite table "events" — columns map 1-to-1 to AuditEntry fields.
    Lists (source_labels, evidence_ids) are stored as JSON strings.
    """

    def __init__(self) -> None:
        self.db_path: str = DEFAULT_DB_PATH

    async def init(self, db_path: str = DEFAULT_DB_PATH) -> None:
        """Create the table if it doesn't exist. Store db_path on self."""
        self.db_path = db_path
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(_SCHEMA)
            await db.commit()

    async def log(self, entry: AuditEntry) -> None:
        """
        INSERT one AuditEntry row.
        Never raises: catch all exceptions and print a warning.
        """
        try:
            placeholders = ", ".join("?" * len(COLUMNS))
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES ({placeholders})",
                    _to_row(entry),
                )
                await db.commit()
        except Exception as exc:  # noqa: BLE001 - the audit log must never break the guard
            print(f"[audit] WARNING: failed to log entry {getattr(entry, 'id', '?')}: {exc!r}")

    async def _query(self, sql: str, params: tuple[Any, ...]) -> list[AuditEntry]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(sql, params) as cur:
                rows = await cur.fetchall()
        return [_from_row(r) for r in rows]

    async def get_session(self, session_id: str) -> list[AuditEntry]:
        """Return all entries for session_id, ordered by timestamp asc."""
        return await self._query(
            "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )

    async def get_escalations(self, session_id: str) -> list[AuditEntry]:
        """Return entries where decision == 'escalate', ordered by timestamp desc."""
        return await self._query(
            "SELECT * FROM events WHERE session_id = ? AND decision = 'escalate' "
            "ORDER BY timestamp DESC",
            (session_id,),
        )

    async def update_decision(
        self,
        entry_id: str,
        decision: str,
        decided_by: str,
        reasoning: str,
    ) -> None:
        """
        UPDATE a single row by id.
        Used when the human analyst clicks Approve or Block in the console.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE events SET decision = ?, decided_by = ?, reasoning = ? WHERE id = ?",
                (decision, decided_by, reasoning, entry_id),
            )
            await db.commit()

    async def get_all_escalations(self, limit: int = 50) -> list[AuditEntry]:
        """Escalations across every session, newest first.

        The console runs in its own process with its own session id, so it cannot
        use `get_escalations(session_id)` to find the agent's incidents.
        """
        return await self._query(
            "SELECT * FROM events WHERE decision = 'escalate' ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )

    async def is_session_killed(self, session_id: str) -> bool:
        """True once a session_kill event has been logged for `session_id`.

        The guard calls this before every action so the analyst's kill switch
        actually stops the agent.
        """
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    "SELECT 1 FROM events WHERE session_id = ? "
                    "AND (event_type = 'session_kill' OR decision = 'killed') LIMIT 1",
                    (session_id,),
                ) as cur:
                    return await cur.fetchone() is not None
        except Exception as exc:  # noqa: BLE001 - fail closed: treat as killed if unknown
            print(f"[audit] WARNING: kill-switch check failed, failing closed: {exc!r}")
            return True

    async def export_json(self, session_id: str, path: str) -> None:
        """Write a JSON array of AuditEntry.model_dump() to path."""
        entries = await self.get_session(session_id)
        rows = [e.model_dump(mode="json") for e in entries]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)

    async def export_csv(self, session_id: str, path: str) -> None:
        """Write a CSV (csv.DictWriter) of the same rows to path."""
        entries = await self.get_session(session_id)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(COLUMNS))
            writer.writeheader()
            for entry in entries:
                row = entry.model_dump(mode="json")
                for col in _JSON_COLUMNS:
                    row[col] = json.dumps(row[col])
                writer.writerow(row)


# Module-level singleton — call `await audit_log.init()` once at startup.
audit_log = AuditLog()
