"""Hard invariants: plain code, guaranteed. A violation is a final BLOCK the AI cannot override.

Owner: Person 2 (guard core).
First deliverable: Tool A quarantined; canary-in-args blocked.
"""

from __future__ import annotations

from policyguard.policy import Policy
from policyguard.types import Action, Decision


def check(action: Action, policy: Policy) -> Decision | None:
    """Return a BLOCK Decision (layer='invariants') on violation, else None."""
    for rule in (
        canary_or_secret_in_args,
        sensitive_path_denied,
        unexpected_params,
        schema_invalid,
    ):
        decision = rule(action, policy)
        if decision is not None:
            return decision
    return None


def canary_or_secret_in_args(action: Action, policy: Policy) -> Decision | None:
    """Canary token or secret (detect-secrets) in args sent to an untrusted server -> BLOCK."""
    # TODO(person2): walk args recursively; compare to policy.canaries; run detect-secrets
    return None


def sensitive_path_denied(action: Action, policy: Policy) -> Decision | None:
    """Path args matching policy.sensitive_paths -> BLOCK (or require approval)."""
    # TODO(person2): fnmatch/PurePath.match against policy.sensitive_paths
    return None


def unexpected_params(action: Action, policy: Policy) -> Decision | None:
    """Args not listed in the allowed tool's `params` (e.g. extra `context`) -> BLOCK."""
    # TODO(person2): compare action.args keys to policy.allowed_tools[..].params
    return None


def schema_invalid(action: Action, policy: Policy) -> Decision | None:
    """Args do not validate against the tool's declared schema -> BLOCK."""
    # TODO(person2): needs schemas from the registry
    return None
