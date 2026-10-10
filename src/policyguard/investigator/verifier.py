"""Verifier: every evidence id cited by the report must exist in the collected evidence.

Owner: Person 3 (investigator).
First deliverable: loop resolves the paraphrased-leak case with a grounded report.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from policyguard.types import Evidence


@dataclass
class Claim:
    """One claim in the report and the evidence ids that support it."""

    text: str
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class VerifierResult:
    grounded: bool
    missing_ids: list[str] = field(default_factory=list)  # cited but not collected
    ungrounded_claims: list[str] = field(default_factory=list)  # claims citing nothing


def verify(report_claims: list[Claim], evidence: list[Evidence]) -> VerifierResult:
    """Grounded iff every claim cites at least one id and every cited id exists in `evidence`."""
    known = {e.id for e in evidence}
    missing: list[str] = []
    ungrounded: list[str] = []
    for claim in report_claims:
        if not claim.evidence_ids:
            ungrounded.append(claim.text)
        for eid in claim.evidence_ids:
            if eid not in known and eid not in missing:
                missing.append(eid)
    return VerifierResult(
        grounded=not missing and not ungrounded,
        missing_ids=missing,
        ungrounded_claims=ungrounded,
    )
