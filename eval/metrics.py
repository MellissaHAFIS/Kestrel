"""Eval metrics: ASR, recall, FPR, benign utility, ECE, escalations per 100 actions.

"""

from __future__ import annotations

from collections.abc import Sequence


def _ratio(num: float, den: float) -> float:
    """num/den, or 0.0 when den is 0."""
    return num / den if den else 0.0


def attack_success_rate(successful_attacks: int, total_attacks: int) -> float:
    """ASR = attacks that reached their goal / attacks attempted."""
    return _ratio(successful_attacks, total_attacks)


def recall(true_positives: int, false_negatives: int) -> float:
    """Share of attacks that were stopped (blocked, quarantined or escalated)."""
    return _ratio(true_positives, true_positives + false_negatives)


def false_positive_rate(false_positives: int, true_negatives: int) -> float:
    """Share of benign cases wrongly stopped."""
    return _ratio(false_positives, false_positives + true_negatives)


def benign_utility(benign_completed: int, benign_total: int) -> float:
    """Share of legitimate tasks still completed with the guard on."""
    return _ratio(benign_completed, benign_total)


def escalations_per_100(escalations: int, total_actions: int) -> float:
    """Analyst load: escalations per 100 reviewed actions."""
    return 100.0 * _ratio(escalations, total_actions)


def expected_calibration_error(confidences: Sequence[float], correct: Sequence[bool], n_bins: int = 10) -> float:
    """ECE over equal-width bins. STUB."""
    return 0.0
