"""Audit log: async SQLite (aiosqlite) + JSON/CSV export (SIEM-friendly).

Owner: Person 4 (audit/console/eval).
First deliverable: live feed showing decisions; then eval harness.

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
import hashlib
import json
from datetime import datetime
from typing import Any

import aiosqlite

from policyguard.types import AuditEntry

DEFAULT_DB_PATH = "policyguard_audit.db"

#: `prev_hash` of the first row. A fixed, non-empty label so an empty string
#: cannot be mistaken for "genesis" by a row that simply failed to be hashed.
GENESIS_HASH = "policyguard-audit-genesis"

#: Event type written when an analyst changes a decision. Reuses the frozen
#: contract's existing `human_decision` literal rather than inventing a new one:
#: `AuditEntry.event_type` is a closed Literal in types.py, which is a frozen
#: contract requiring all four owners to agree before it changes. An amendment
#: *is* a human decision, so no new type is needed.
AMENDMENT_EVENT = "human_decision"

#: Key inside an amendment event's `action` payload. Its presence is what marks
#: a `human_decision` row as amending another row, since the event type alone
#: cannot carry that distinction.
AMENDS_KEY = "amends"

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
    latency_ms    REAL NOT NULL DEFAULT 0.0,
    prev_hash     TEXT NOT NULL DEFAULT '',
    row_hash      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision);
"""

#: Columns added after the first schema shipped. SQLite's
#: `CREATE TABLE IF NOT EXISTS` is a no-op on an existing table, so a database
#: created before the hash chain would silently keep the old shape and every
#: INSERT would fail. Added explicitly at init.
_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("prev_hash", "ALTER TABLE events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"),
    ("row_hash", "ALTER TABLE events ADD COLUMN row_hash TEXT NOT NULL DEFAULT ''"),
)


# --------------------------------------------------------------------------
# Tamper-evident hash chain
# --------------------------------------------------------------------------
# Each row stores the hash of the row before it, so the log is append-only in
# practice: changing or deleting any row invalidates every hash after it, and
# that is detectable by replaying the chain (`verify_chain`).
#
# What this does and does not buy us, stated plainly because it is easy to
# oversell: it makes tampering *detectable*, not impossible. Anyone who can
# write the database can also recompute the whole chain. Detection only becomes
# a real guarantee once a digest is published somewhere the attacker does not
# control; periodically anchoring one is a roadmap item, deliberately not
# implemented here (see CLAUDE.md on why we are not putting this on a chain).
#
# `update_decision` is the awkward case: an analyst clicking Approve genuinely
# changes a row that has already been hashed. Rather than re-signing it (which
# would require rewriting every later row and would make tampering and
# legitimate edits indistinguishable), the stored `row_hash` is left frozen and
# the amendment is written as its own chained event. So:
#   * a row whose content no longer matches its frozen hash *and* which has a
#     matching chained amendment  -> a legitimate analyst decision;
#   * the same mismatch with no amendment                    -> tampering.
# `verify_chain` reports those two cases separately.


def _canonical(row: tuple[Any, ...]) -> str:
    """Stable serialisation of a row for hashing.

    `sort_keys` and a fixed separator make this independent of column order and
    of dict iteration order, so a hash computed today still verifies tomorrow.
    """
    payload = {col: value for col, value in zip(COLUMNS, row, strict=True)}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_row_hash(row: tuple[Any, ...], prev_hash: str) -> str:
    """SHA-256 over the previous hash and this row's canonical form.

    Including `prev_hash` in the digest is what makes it a chain rather than a
    set of independent checksums: a row cannot be moved, duplicated or removed
    without breaking every digest downstream.
    """
    return hashlib.sha256(f"{prev_hash}\n{_canonical(row)}".encode()).hexdigest()


def _to_row(entry: AuditEntry) -> tuple[Any, ...]:
    """Flatten an AuditEntry into a row tuple matching COLUMNS."""
    d = entry.model_dump()
    d["timestamp"] = entry.timestamp.isoformat()
    d["violation"] = int(entry.violation)
    for col in _JSON_COLUMNS:
        d[col] = json.dumps(d[col])
    return tuple(d[col] for col in COLUMNS)


def _from_row(row: aiosqlite.Row) -> AuditEntry:
    """Rebuild an AuditEntry from a DB row.

    Restricted to `COLUMNS` on purpose: the table also carries `prev_hash` and
    `row_hash`, which are storage metadata for the tamper-evident chain and are
    deliberately not part of the frozen `AuditEntry` contract in types.py.
    """
    d = {col: row[col] for col in COLUMNS}
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
        """Create the table if it doesn't exist, then apply column migrations."""
        self.db_path = db_path
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(_SCHEMA)
            async with db.execute("PRAGMA table_info(events)") as cur:
                existing = {row[1] for row in await cur.fetchall()}
            for column, statement in _MIGRATIONS:
                if column not in existing:
                    await db.execute(statement)
            await db.commit()

    async def log(self, entry: AuditEntry) -> None:
        """
        INSERT one AuditEntry row, linked to the previous one by hash.
        Never raises: catch all exceptions and print a warning.
        """
        try:
            placeholders = ", ".join("?" * (len(COLUMNS) + 2))
            columns = ", ".join((*COLUMNS, "prev_hash", "row_hash"))
            async with aiosqlite.connect(self.db_path) as db:
                # IMMEDIATE takes the write lock before we read the tail of the
                # chain. Without it two concurrent writers can read the same
                # `prev_hash` and produce a fork that verification would report
                # as tampering. The guard logs from several layers per action,
                # so this is a real race, not a theoretical one.
                await db.execute("BEGIN IMMEDIATE")
                async with db.execute(
                    "SELECT row_hash FROM events ORDER BY rowid DESC LIMIT 1"
                ) as cur:
                    tail = await cur.fetchone()
                prev_hash = (tail[0] if tail and tail[0] else GENESIS_HASH)
                row = _to_row(entry)
                await db.execute(
                    f"INSERT INTO events ({columns}) VALUES ({placeholders})",
                    (*row, prev_hash, compute_row_hash(row, prev_hash)),
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
        UPDATE a single row by id, and record the amendment as a chained event.

        The row is updated so the console shows the analyst's decision, which
        means its content no longer matches its frozen `row_hash`. That is
        expected and is why the amendment is *also* appended as its own hashed
        event: the pair is what lets `verify_chain` tell a legitimate human
        decision apart from someone editing the database directly. Without the
        amendment event, an approval and a forgery look identical.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT session_id, decision FROM events WHERE id = ?", (entry_id,)
            ) as cur:
                target = await cur.fetchone()
            if target is None:
                print(f"[audit] WARNING: cannot amend unknown entry {entry_id!r}")
                return
            await db.execute(
                "UPDATE events SET decision = ?, decided_by = ?, reasoning = ? WHERE id = ?",
                (decision, decided_by, reasoning, entry_id),
            )
            await db.commit()
            previous = target["decision"]
            session_id = target["session_id"]

        await self.log(
            AuditEntry(
                session_id=session_id,
                event_type=AMENDMENT_EVENT,
                # `action` carries the amendment payload: which entry changed,
                # from what, to what, and who did it. Parsed back by
                # `_amended_entry_ids`. The analyst's identity lives here rather
                # than in `decided_by`, which the frozen contract restricts to
                # system/investigator/human.
                action=json.dumps(
                    {
                        AMENDS_KEY: entry_id,
                        "from": previous,
                        "to": decision,
                        "by": decided_by,
                    },
                    sort_keys=True,
                ),
                layer="human",
                decision=decision,
                decided_by="human",
                reasoning=reasoning,
                source_labels=["user"],
                severity="low",
            )
        )

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

    async def verify_chain(self) -> dict[str, Any]:
        """Replay the hash chain and report every inconsistency.

        Returns a dict with:
          * ``ok``            -- True when nothing unexplained was found;
          * ``rows``          -- number of rows checked;
          * ``broken_links``  -- rows whose `prev_hash` does not match the
            previous row's stored hash. This is what insertion, deletion or
            reordering looks like;
          * ``tampered``      -- rows whose content no longer matches their own
            stored hash and which have *no* amendment event to explain it;
          * ``amended``       -- the same mismatch, but explained by a chained
            amendment written by `update_decision`. Legitimate; reported so an
            auditor can see every human override rather than having it hidden;
          * ``unhashed``      -- rows written before the chain existed, or by a
            writer that failed to hash. Not tampering, but not covered either,
            so they are surfaced instead of being silently treated as valid.

        Read-only: verification never writes, so running it cannot repair (or
        quietly destroy) the evidence it is checking.
        """
        amended_ids = await self._amended_entry_ids()
        report: dict[str, Any] = {
            "ok": True,
            "rows": 0,
            "broken_links": [],
            "tampered": [],
            "amended": [],
            "unhashed": [],
        }
        prev_hash = GENESIS_HASH
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM events ORDER BY rowid ASC") as cur:
                async for row in cur:
                    report["rows"] += 1
                    stored = row["row_hash"]
                    entry_id = row["id"]
                    if not stored:
                        report["unhashed"].append(entry_id)
                        continue
                    if row["prev_hash"] != prev_hash:
                        report["broken_links"].append(entry_id)
                    recomputed = compute_row_hash(
                        tuple(row[col] for col in COLUMNS), row["prev_hash"]
                    )
                    if recomputed != stored:
                        bucket = "amended" if entry_id in amended_ids else "tampered"
                        report[bucket].append(entry_id)
                    # Chain on the *stored* hash: it is the link the next row
                    # committed to. Using the recomputed value would let a single
                    # edited row hide itself by re-linking the rest of the chain.
                    prev_hash = stored
        report["ok"] = not (
            report["broken_links"] or report["tampered"] or report["unhashed"]
        )
        return report

    async def _amended_entry_ids(self) -> set[str]:
        """Ids of entries that a chained amendment event legitimately changed."""
        ids: set[str] = set()
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    "SELECT action FROM events WHERE event_type = ?", (AMENDMENT_EVENT,)
                ) as cur:
                    for (action,) in await cur.fetchall():
                        try:
                            amends = json.loads(action).get(AMENDS_KEY)
                        except (json.JSONDecodeError, TypeError, AttributeError):
                            # A plain `human_decision` row that is not an
                            # amendment: its `action` is prose, not JSON.
                            continue
                        if amends:
                            ids.add(amends)
        except Exception as exc:  # noqa: BLE001 - verification must not raise
            print(f"[audit] WARNING: could not read amendment events: {exc!r}")
        return ids

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
