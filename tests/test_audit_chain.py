"""Tests for the tamper-evident audit chain.

Each row stores the hash of the row before it, so editing, deleting or
reordering any row breaks every digest after it. The point of these tests is to
attack the log the way someone covering their tracks would — with direct SQL,
not through the API — and check that `verify_chain` says so.

What the chain does and does not claim, since the tests should not imply more
than the design gives:

* It makes tampering **detectable**, not impossible. Anyone who can write the
  database can recompute the whole chain. Detection becomes a guarantee only
  once a digest is anchored somewhere the attacker does not control, which is
  explicitly a roadmap item and not implemented.
* `update_decision` legitimately changes a row that is already hashed, so a
  mismatch alone cannot mean "tampering". The amendment is appended as its own
  chained event, and `verify_chain` separates "explained by an amendment" from
  "unexplained". `test_a_forged_approval_is_detected` is the test that matters:
  it is the difference between a log an auditor can rely on and a log that
  merely looks official.
"""

from __future__ import annotations

import json

import pytest
import aiosqlite

from policyguard.audit import (
    AMENDMENT_EVENT,
    COLUMNS,
    GENESIS_HASH,
    AuditLog,
    compute_row_hash,
)
from policyguard.types import AuditEntry


@pytest.fixture
async def log(tmp_path):
    """A fresh audit log in its own database file."""
    instance = AuditLog()
    await instance.init(str(tmp_path / "audit.db"))
    return instance


def _entry(session_id: str = "s-1", **kwargs) -> AuditEntry:
    """A valid AuditEntry. `event_type` and `layer` are closed Literals in the
    frozen contract (types.py), so these values are not arbitrary."""
    defaults = {
        "session_id": session_id,
        "event_type": "tool_call",
        "action": "docs_helper.search_docs",
        "source_labels": ["mcp_description"],
        "layer": "invariant",
        "decision": "block",
        "reasoning": "canary in args",
    }
    return AuditEntry(**{**defaults, **kwargs})


async def _write(log: AuditLog, count: int, session_id: str = "s-1") -> list[AuditEntry]:
    entries = [_entry(session_id, reasoning=f"step {i}") for i in range(count)]
    for entry in entries:
        await log.log(entry)
    return entries


# ── a clean chain verifies ────────────────────────────────────────────────


async def test_an_empty_log_verifies(log) -> None:
    report = await log.verify_chain()
    assert report["ok"] is True
    assert report["rows"] == 0


async def test_a_written_chain_verifies(log) -> None:
    await _write(log, 5)
    report = await log.verify_chain()
    assert report["ok"] is True, report
    assert report["rows"] == 5
    assert report["tampered"] == []
    assert report["broken_links"] == []
    assert report["unhashed"] == []


async def test_the_first_row_links_to_genesis(log) -> None:
    await _write(log, 1)
    async with aiosqlite.connect(log.db_path) as db:
        async with db.execute("SELECT prev_hash, row_hash FROM events") as cur:
            prev_hash, row_hash = await cur.fetchone()
    assert prev_hash == GENESIS_HASH
    assert row_hash and row_hash != GENESIS_HASH


async def test_each_row_links_to_the_one_before(log) -> None:
    """The property the whole design rests on."""
    await _write(log, 4)
    async with aiosqlite.connect(log.db_path) as db:
        async with db.execute(
            "SELECT prev_hash, row_hash FROM events ORDER BY rowid ASC"
        ) as cur:
            rows = await cur.fetchall()
    for (_, previous_hash), (next_prev, _) in zip(rows, rows[1:], strict=False):
        assert next_prev == previous_hash


async def test_hashes_are_unique_per_row(log) -> None:
    """Identical content at different positions must still hash differently."""
    for _ in range(3):
        await log.log(_entry(reasoning="identical"))
    async with aiosqlite.connect(log.db_path) as db:
        async with db.execute("SELECT row_hash FROM events") as cur:
            hashes = [h for (h,) in await cur.fetchall()]
    assert len(set(hashes)) == 3, "chaining must disambiguate identical rows"


# ── tampering is detected ─────────────────────────────────────────────────


async def test_editing_a_row_is_detected(log) -> None:
    """The basic case: someone rewrites the reasoning on a recorded decision."""
    entries = await _write(log, 3)
    target = entries[1].id
    async with aiosqlite.connect(log.db_path) as db:
        await db.execute(
            "UPDATE events SET reasoning = ? WHERE id = ?", ("nothing to see here", target)
        )
        await db.commit()

    report = await log.verify_chain()
    assert report["ok"] is False
    assert target in report["tampered"]
    assert report["amended"] == [], "an unexplained edit is not an amendment"


async def test_flipping_a_block_to_an_allow_is_detected(log) -> None:
    """The edit someone would actually make to hide a blocked exfiltration."""
    entries = await _write(log, 2)
    target = entries[0].id
    async with aiosqlite.connect(log.db_path) as db:
        await db.execute("UPDATE events SET decision = 'allow' WHERE id = ?", (target,))
        await db.commit()

    report = await log.verify_chain()
    assert report["ok"] is False
    assert target in report["tampered"]


async def test_deleting_a_row_is_detected(log) -> None:
    """Removing an incident must not leave a log that verifies."""
    entries = await _write(log, 4)
    async with aiosqlite.connect(log.db_path) as db:
        await db.execute("DELETE FROM events WHERE id = ?", (entries[1].id,))
        await db.commit()

    report = await log.verify_chain()
    assert report["ok"] is False
    assert report["broken_links"], "a deletion must break a link"
    assert report["rows"] == 3


async def test_deleting_the_last_row_is_not_detectable(log) -> None:
    """An honest negative result, documented rather than hidden.

    Truncating the tail leaves a chain that is internally consistent, so this
    design cannot detect it. Detecting it needs an external anchor (a published
    digest or a counter the writer does not control), which is the roadmap item.
    A test pins the limitation so nobody later claims the log is append-only
    proof against a writer who can delete.
    """
    entries = await _write(log, 3)
    async with aiosqlite.connect(log.db_path) as db:
        await db.execute("DELETE FROM events WHERE id = ?", (entries[-1].id,))
        await db.commit()

    report = await log.verify_chain()
    assert report["ok"] is True
    assert report["rows"] == 2


async def test_a_row_inserted_by_hand_is_detected(log) -> None:
    """Fabricating an approval cannot be done by copying a valid row's shape."""
    await _write(log, 2)
    forged = _entry(decision="allow", reasoning="approved by nobody")
    row = tuple(
        json.dumps(v) if c in ("source_labels", "evidence_ids") else v
        for c, v in zip(
            COLUMNS,
            (
                forged.id, forged.session_id, forged.timestamp.isoformat(), "tool_call",
                forged.action, [], "invariant", None, None, [], 0, "low", None,
                forged.reasoning, "allow", "system", 0, 0.0,
            ),
            strict=True,
        )
    )
    async with aiosqlite.connect(log.db_path) as db:
        placeholders = ", ".join("?" * (len(COLUMNS) + 2))
        await db.execute(
            f"INSERT INTO events ({', '.join((*COLUMNS, 'prev_hash', 'row_hash'))}) "
            f"VALUES ({placeholders})",
            (*row, "made-up-prev", "made-up-hash"),
        )
        await db.commit()

    report = await log.verify_chain()
    assert report["ok"] is False
    assert forged.id in report["broken_links"] or forged.id in report["tampered"]


async def test_rehashing_one_row_in_place_still_breaks_the_chain(log) -> None:
    """The attacker's obvious next move: edit a row and fix *its* hash.

    Verification deliberately chains on the stored hash, so re-signing a single
    row leaves the following row's `prev_hash` pointing at the old value.
    """
    entries = await _write(log, 3)
    target = entries[1].id
    async with aiosqlite.connect(log.db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM events WHERE id = ?", (target,)) as cur:
            row = await cur.fetchone()
        patched = {col: row[col] for col in COLUMNS}
        patched["decision"] = "allow"
        new_hash = compute_row_hash(
            tuple(patched[col] for col in COLUMNS), row["prev_hash"]
        )
        await db.execute(
            "UPDATE events SET decision = 'allow', row_hash = ? WHERE id = ?",
            (new_hash, target),
        )
        await db.commit()

    report = await log.verify_chain()
    assert report["ok"] is False
    assert report["broken_links"], "the next row still commits to the old hash"


# ── legitimate amendments are explained, forgeries are not ────────────────


async def test_an_analyst_decision_keeps_the_log_verifiable(log) -> None:
    """Clicking Approve must not make the log look tampered with."""
    entries = await _write(log, 2)
    target = entries[0].id
    await log.update_decision(target, "allow", "analyst@acme", "reviewed, false positive")

    report = await log.verify_chain()
    assert report["ok"] is True, report
    assert target in report["amended"], "the override must still be visible to an auditor"
    assert report["tampered"] == []


async def test_an_amendment_is_itself_a_chained_event(log) -> None:
    """The amendment carries who/from/to, and is hashed like any other row."""
    entries = await _write(log, 1)
    target = entries[0].id
    await log.update_decision(target, "allow", "analyst@acme", "reviewed")

    async with aiosqlite.connect(log.db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM events WHERE event_type = ?", (AMENDMENT_EVENT,)
        ) as cur:
            amendment = await cur.fetchone()
    assert amendment is not None
    payload = json.loads(amendment["action"])
    assert payload == {
        "amends": target,
        "from": "block",
        "to": "allow",
        "by": "analyst@acme",
    }
    # The analyst's identity lives in the payload, not in `decided_by`: the
    # frozen contract restricts that column to system/investigator/human.
    assert amendment["decided_by"] == "human"
    assert amendment["row_hash"]


async def test_a_forged_approval_is_detected(log) -> None:
    """The test that gives the chain its value.

    An attacker edits a decision to 'allow' in SQL, exactly as
    `update_decision` would have. Without the amendment event there is nothing
    to explain the mismatch, so it is reported as tampering rather than as a
    human override.
    """
    entries = await _write(log, 2)
    target = entries[0].id
    async with aiosqlite.connect(log.db_path) as db:
        await db.execute(
            "UPDATE events SET decision = 'allow', decided_by = 'analyst@acme' WHERE id = ?",
            (target,),
        )
        await db.commit()

    report = await log.verify_chain()
    assert report["ok"] is False
    assert target in report["tampered"]
    assert target not in report["amended"]


async def test_amending_an_unknown_entry_is_a_no_op(log) -> None:
    await _write(log, 1)
    before = await log.verify_chain()
    await log.update_decision("does-not-exist", "allow", "analyst", "n/a")
    after = await log.verify_chain()
    assert after["rows"] == before["rows"]
    assert after["ok"] is True


# ── migration and backward compatibility ─────────────────────────────────


async def test_a_pre_chain_database_is_migrated_and_flagged(tmp_path) -> None:
    """A database written before the chain existed must still open.

    `CREATE TABLE IF NOT EXISTS` is a no-op on an existing table, so without an
    explicit migration every INSERT would fail against an old file. The old
    rows cannot be verified, so they are reported as `unhashed` rather than
    counted as valid.
    """
    db_path = str(tmp_path / "old.db")
    legacy = (
        "CREATE TABLE events (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, "
        "timestamp TEXT NOT NULL, event_type TEXT NOT NULL, action TEXT NOT NULL, "
        "source_labels TEXT NOT NULL, layer TEXT NOT NULL, gate_score REAL, "
        "model_hash TEXT, evidence_ids TEXT NOT NULL, violation INTEGER NOT NULL DEFAULT 0, "
        "severity TEXT NOT NULL DEFAULT 'low', confidence REAL, "
        "reasoning TEXT NOT NULL DEFAULT '', decision TEXT NOT NULL DEFAULT 'pending', "
        "decided_by TEXT NOT NULL DEFAULT 'system', steps_used INTEGER NOT NULL DEFAULT 0, "
        "latency_ms REAL NOT NULL DEFAULT 0.0)"
    )
    async with aiosqlite.connect(db_path) as db:
        await db.execute(legacy)
        await db.execute(
            "INSERT INTO events (id, session_id, timestamp, event_type, action, "
            "source_labels, layer, evidence_ids) VALUES "
            "('old-1', 's-0', '2026-01-01T00:00:00', 'decision', 'x', '[]', 'invariant', '[]')"
        )
        await db.commit()

    instance = AuditLog()
    await instance.init(db_path)
    await instance.log(_entry())  # must not fail against the migrated table

    report = await instance.verify_chain()
    assert report["unhashed"] == ["old-1"]
    assert report["ok"] is False, "rows we cannot verify must not pass silently"
    assert report["rows"] == 2


async def test_reading_entries_still_works_with_the_extra_columns(log) -> None:
    """`prev_hash`/`row_hash` are storage metadata, not part of AuditEntry."""
    await _write(log, 2, session_id="s-read")
    entries = await log.get_session("s-read")
    assert len(entries) == 2
    assert all(isinstance(e, AuditEntry) for e in entries)
    assert not hasattr(entries[0], "row_hash")


async def test_export_still_works(log, tmp_path) -> None:
    await _write(log, 2, session_id="s-exp")
    out = tmp_path / "out.json"
    await log.export_json("s-exp", str(out))
    assert len(json.loads(out.read_text())) == 2


async def test_verification_does_not_modify_the_log(log) -> None:
    """A read-only check cannot repair, or quietly destroy, its own evidence."""
    await _write(log, 3)
    async with aiosqlite.connect(log.db_path) as db:
        async with db.execute("SELECT id, row_hash FROM events ORDER BY rowid") as cur:
            before = await cur.fetchall()
    await log.verify_chain()
    async with aiosqlite.connect(log.db_path) as db:
        async with db.execute("SELECT id, row_hash FROM events ORDER BY rowid") as cur:
            after = await cur.fetchall()
    assert before == after
