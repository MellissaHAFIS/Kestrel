"""Hard invariants: plain deterministic code, guaranteed.

A violation here is a *final* BLOCK that no later layer (gate, Investigator,
human) may override. The layer is pure: no ML, no LLM, no network, no clock,
no randomness, no global state. The same Action + Policy always yields the
same Decision.

Rules (every rule runs on every call; results accumulate):

    1. tool_not_allowed  - tool not in policy.allowed_tools, when that list is
                           non-empty. Applies to every server.
    2. canary_match      - a policy canary appears anywhere in args. Untrusted
                           servers only (a canary legitimately reaching a
                           trusted internal server is not a leak).
    3. secret_pattern    - a built-in or policy secret pattern appears anywhere
                           in args. Untrusted servers only.
    4. sensitive_path    - a string arg matches a sensitive_paths glob. Applies
                           to every server (reading a secret file is dangerous
                           regardless of destination).
    5. unexpected_param  - args carry a parameter not in the tool's schema.
                           Only for tools that declare a schema.
    6. suspicious_param  - args carry a name from suspicious_param_names. Only
                           for untrusted tools that have no schema (a schema is
                           already stricter).

Obfuscation resistance (canary + secret matching):
    Matching survives case changes, whitespace/punctuation splitting (we
    compare with every non-alphanumeric character removed), URL-encoding, and
    base64 / url-safe-base64 chunks of 16+ chars. We check string *values* and
    dict *keys*, recursively, because data can be smuggled in either.

Known limits (do NOT try to "fix" these):
    * Matching cannot defeat encryption or a true paraphrase. A leak written as
      prose ("the credential starts with seven f three a") is invisible here by
      design -- that is the gate's and the Investigator's job. Invariants are a
      guarantee layer, not a judge.
    * The "strip non-alphanumerics" canary comparison can in theory
      false-positive if a canary's squashed form happens to appear inside a
      longer run of concatenated text. This is acceptable: the canaries are long
      and unique, so the odds are negligible, and a false BLOCK on a honeytoken
      is a safe failure.
    * Secret *values* are never written into evidence; only the type and the
      argument location (e.g. ``args['text']``) are reported.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
import urllib.parse
from typing import Any, Iterable

from policyguard.policy import Policy
# Legacy contract: see policyguard/compat.py. types.py is frozen and no
# longer exports Decision/Evidence(kind,detail)/Verdict-as-enum.
from policyguard.compat import Action, Decision, Evidence, Verdict

# --------------------------------------------------------------------------
# Built-in secret patterns. (name -> compiled regex)
# --------------------------------------------------------------------------
BUILTIN_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "assigned_secret": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*"
        r"['\"]?\S{16,}"
    ),
}

_MAX_PATH_LEN = 300
_B64_CHUNK = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")

#: Translation table for ROT13 (letters only; digits and symbols pass through).
_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)

#: Minimum number of *alphanumeric* characters of a canary that must appear
#: contiguously for a partial match to count as a leak.
#:
#: Why partial matching at all: an exfiltration does not have to be complete to
#: be a disclosure. "our token prefix is CANARY-PG-7f3a9c" hands an attacker
#: half the honeytoken, and exact matching scored it clean.
#:
#: Why 14: our canaries squash to 28 alphanumeric characters, so 14 is half the
#: token -- specific enough that an accidental collision is not realistic, while
#: still catching a prefix truncation. A shorter floor would start matching the
#: bare "CANARY-PG" brand prefix (8 chars), which legitimately appears in
#: documentation *about* the honeytoken; that case must stay with the
#: Investigator, not become a hard block.
CANARY_PARTIAL_MIN_CHARS = 14

#: Minimum run length for a fragment to contribute to the *cross-call*
#: reassembly check. Lower than the single-call floor on purpose: here we also
#: require that the fragments together cover the canary completely, which is a
#: far more specific condition than one partial match, so each piece can be
#: shorter. Eight characters is about the shortest run that is not a coincidence
#: ("canarypg" is exactly eight).
CANARY_FRAGMENT_MIN_CHARS = 8


# --------------------------------------------------------------------------
# Evidence collector
# --------------------------------------------------------------------------
class _Collector:
    """Accumulates evidence across all rules so a single Decision can carry them."""

    def __init__(self) -> None:
        self._items: list[Evidence] = []

    def add(self, kind: str, detail: str) -> None:
        self._items.append(Evidence(id="", kind=kind, detail=detail))

    @property
    def items(self) -> list[Evidence]:
        return self._items

    def __bool__(self) -> bool:
        return bool(self._items)


# --------------------------------------------------------------------------
# Arg walking
# --------------------------------------------------------------------------
def _walk_strings(args: Any, path: str = "args") -> Iterable[tuple[str, str]]:
    """Yield ``(location, string)`` for every string value *and* dict key in args.

    Nested dicts and lists are walked recursively. Keys are yielded because data
    can be smuggled into them.
    """
    if isinstance(args, dict):
        for key, value in args.items():
            if isinstance(key, str):
                yield (f"{path}.<key>", key)
            child = f"{path}[{key!r}]" if isinstance(key, str) else f"{path}[{key}]"
            yield from _walk_strings(value, child)
    elif isinstance(args, (list, tuple)):
        for i, value in enumerate(args):
            yield from _walk_strings(value, f"{path}[{i}]")
    elif isinstance(args, str):
        yield (path, args)


# --------------------------------------------------------------------------
# Normalisation helpers for obfuscation-resistant matching
# --------------------------------------------------------------------------
def _squash(s: str) -> str:
    """Lowercase and drop everything that is not a letter or digit."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _rot13(s: str) -> str:
    """ROT13 of ``s``. Its own inverse, so one pass covers both directions."""
    return s.translate(_ROT13_TABLE)


def _decode_variants(s: str) -> list[str]:
    """Return decoded views of ``s`` that a canary/secret might be hiding in.

    Always includes the original, a URL-decoded form and a ROT13 form. For each
    long base64-ish chunk, adds the decoded text (standard and url-safe) when it
    decodes cleanly, and the ROT13 of the original chunk text.

    ROT13 is cheap and is a documented obfuscation in our own test set; without
    it the "survives rot13" claim on the defence sheet was not true of this
    layer.
    """
    variants = [s]
    try:
        unquoted = urllib.parse.unquote_plus(s)
    except Exception:  # pragma: no cover - unquote is extremely tolerant
        unquoted = s
    if unquoted != s:
        variants.append(unquoted)

    for text in (s, unquoted):
        for chunk in _B64_CHUNK.findall(text):
            variants.extend(_try_base64(chunk))

    # ROT13 last, over the plain forms only: rot13 of base64 is not a thing an
    # attacker does, and it would only add noise.
    variants.extend(_rot13(text) for text in (s, unquoted) if text)
    return variants


def _try_base64(chunk: str) -> list[str]:
    """Attempt standard and url-safe base64 decoding of a chunk; ignore failures."""
    out: list[str] = []
    core = chunk.rstrip("=")
    padded = core + "=" * (-len(core) % 4)
    # Standard alphabet: translate url-safe chars so one decoder handles both.
    standard = padded.replace("-", "+").replace("_", "/")
    for candidate in (standard, padded):
        try:
            raw = base64.b64decode(candidate.encode("ascii"), validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            out.append(raw.decode("utf-8"))
        except UnicodeDecodeError:
            out.append(raw.decode("latin-1"))
    return out


# --------------------------------------------------------------------------
# Rule 1: tool allow-list
# --------------------------------------------------------------------------
def _check_allowed_tool(action: Action, policy: Policy, c: _Collector) -> None:
    if policy.allowed_tools and action.qualified_tool not in policy.allowed_tools:
        c.add("tool_not_allowed", f"{action.qualified_tool} is not on the allow-list")


# --------------------------------------------------------------------------
# Rule 2: canary in args (untrusted servers only)
# --------------------------------------------------------------------------
def _longest_canary_run(needle: str, haystack: str) -> int:
    """Length of the longest contiguous slice of ``needle`` present in ``haystack``.

    Both inputs are already squashed. Used to decide whether a *partial* canary
    disclosure is long enough to count. Walks candidate lengths downward from
    the full needle and stops at the first hit, so the common clean case costs
    one `in` test.
    """
    if not needle or not haystack:
        return 0
    for length in range(len(needle), CANARY_PARTIAL_MIN_CHARS - 1, -1):
        for start in range(0, len(needle) - length + 1):
            if needle[start : start + length] in haystack:
                return length
    return 0


def _check_canaries(action: Action, policy: Policy, c: _Collector) -> None:
    if policy.is_trusted(action.server):
        return
    squashed_canaries = [(cn, _squash(cn)) for cn in policy.canaries if cn]
    if not squashed_canaries:
        return
    for location, value in _walk_strings(action.args):
        for variant in _decode_variants(value):
            squashed = _squash(variant)
            for _original, needle in squashed_canaries:
                if not needle:
                    continue
                if needle in squashed:
                    c.add("canary_match", f"canary token detected in {location}")
                    return  # one canary hit is enough to prove the leak
                run = _longest_canary_run(needle, squashed)
                if run:
                    c.add(
                        "canary_match",
                        f"partial canary token detected in {location} "
                        f"({run} of {len(needle)} characters)",
                    )
                    return


# --------------------------------------------------------------------------
# Rule 3: secret pattern in args (untrusted servers only)
# --------------------------------------------------------------------------
def _compiled_secret_patterns(policy: Policy) -> dict[str, re.Pattern[str]]:
    patterns = dict(BUILTIN_SECRET_PATTERNS)
    for i, raw in enumerate(policy.secret_patterns):
        try:
            patterns[f"policy_pattern_{i}"] = re.compile(raw)
        except re.error:
            # A malformed policy regex must not crash the guard; skip it.
            continue
    return patterns


def _check_secrets(action: Action, policy: Policy, c: _Collector) -> None:
    if policy.is_trusted(action.server):
        return
    patterns = _compiled_secret_patterns(policy)
    seen: set[str] = set()
    for location, value in _walk_strings(action.args):
        for variant in _decode_variants(value):
            for name, rx in patterns.items():
                if rx.search(variant):
                    key = f"{name}@{location}"
                    if key not in seen:
                        seen.add(key)
                        # NEVER echo the matched value -- type + location only.
                        c.add(
                            "secret_pattern",
                            f"secret of type '{name}' detected in {location}",
                        )


# --------------------------------------------------------------------------
# Rule 4: sensitive path (all servers)
# --------------------------------------------------------------------------
def _looks_like_path(s: str) -> bool:
    if len(s) > _MAX_PATH_LEN or "\n" in s or "\r" in s:
        return False
    if re.match(r"^\s*https?://", s, re.IGNORECASE):
        return False
    return True


def _normalise_path(s: str) -> str:
    """Canonicalise a candidate path for glob matching.

    backslashes -> '/', URL-decode, strip ``file://`` and leading ``./``,
    collapse ``..`` with posixpath.normpath.
    """
    p = urllib.parse.unquote(s.strip())
    p = p.replace("\\", "/")
    if p.lower().startswith("file://"):
        p = p[len("file://") :]
    while p.startswith("./"):
        p = p[2:]
    # Preserve a leading '~' (home) and a leading '/' through normpath.
    home = p.startswith("~")
    collapsed = posixpath.normpath(p)
    if home and not collapsed.startswith("~"):
        collapsed = "~" + ("/" + collapsed if not collapsed.startswith("/") else collapsed)
    return collapsed


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a path glob into a regex.

    Supports ``**/`` (any depth incl. none), ``**``, ``*`` (within one segment),
    and ``?`` (one non-slash char).
    """
    out: list[str] = ["^"]
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if pattern[i : i + 3] == "**/":
                out.append("(?:.*/)?")  # any depth, including none
                i += 3
                continue
            if pattern[i : i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(ch))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def _matches_sensitive(path: str, patterns: list[str]) -> str | None:
    norm = _normalise_path(path)
    for pat in patterns:
        if _glob_to_regex(pat).match(norm):
            return pat
    return None


def _check_sensitive_paths(action: Action, policy: Policy, c: _Collector) -> None:
    if not policy.sensitive_paths:
        return
    for location, value in _walk_strings(action.args):
        if not _looks_like_path(value):
            continue
        hit = _matches_sensitive(value, policy.sensitive_paths)
        if hit is not None:
            c.add(
                "sensitive_path",
                f"{location} refers to a sensitive path (matched glob '{hit}')",
            )


# --------------------------------------------------------------------------
# Rule 5 + 6: parameter checks
# --------------------------------------------------------------------------
def _check_params(action: Action, policy: Policy, c: _Collector) -> None:
    schema = policy.tool_schemas.get(action.qualified_tool)
    if schema is not None:
        allowed = set(schema.get("allowed_params", []))
        extra = sorted(k for k in action.args if k not in allowed)
        if extra:
            c.add(
                "unexpected_param",
                f"{action.qualified_tool} received params not in its schema: {extra}",
            )
        return
    # No schema: only screen untrusted tools for suspicious param names.
    if not policy.is_trusted(action.server):
        suspicious = sorted(set(action.args) & set(policy.suspicious_param_names))
        if suspicious:
            c.add(
                "suspicious_param",
                f"untrusted tool {action.qualified_tool} received suspicious params: {suspicious}",
            )


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------
def check_invariants(action: Action, policy: Policy) -> Decision | None:
    """Run every hard invariant. Return a BLOCK Decision on any violation, else None.

    All violations are reported in one Decision; evidence ids are assigned
    deterministically as ``inv-1``, ``inv-2``, ... in rule order.
    """
    c = _Collector()
    _check_allowed_tool(action, policy, c)
    _check_canaries(action, policy, c)
    _check_secrets(action, policy, c)
    _check_sensitive_paths(action, policy, c)
    _check_params(action, policy, c)

    if not c:
        return None

    evidence: list[Evidence] = []
    for i, item in enumerate(c.items, start=1):
        item.id = f"inv-{i}"
        evidence.append(item)

    kinds = sorted({e.kind for e in evidence})
    reason = "hard invariant violated: " + ", ".join(kinds)
    return Decision(
        verdict=Verdict.BLOCK,
        layer="invariants",
        reason=reason,
        score=1.0,
        confidence=1.0,
        evidence_ids=[e.id for e in evidence],
        evidence=evidence,
    )


# Backwards-compatible alias for the original skeleton entry point.
check = check_invariants


# --------------------------------------------------------------------------
# Chain-level invariant: a canary reassembled across several calls
# --------------------------------------------------------------------------
def squashed_arg_text(action: Action) -> str:
    """Squashed concatenation of every string in ``action.args``.

    This is the form the cross-call check accumulates. Exposed so the pipeline
    records exactly what the check will later compare against.
    """
    return "".join(_squash(value) for _loc, value in _walk_strings(action.args))


def canary_coverage(needle: str, fragment: str) -> set[int]:
    """Indices of ``needle`` disclosed by ``fragment``.

    Both squashed. A position counts as disclosed only if it sits inside a run
    of at least `CANARY_FRAGMENT_MIN_CHARS` consecutive canary characters that
    appear verbatim in the fragment. Comparing each fragment against the canary
    independently is what makes this immune to padding between calls.
    """
    covered: set[int] = set()
    if not needle or not fragment:
        return covered
    n = len(needle)
    for start in range(n):
        # Longest run of needle starting at `start` that occurs in fragment.
        longest = 0
        for length in range(n - start, CANARY_FRAGMENT_MIN_CHARS - 1, -1):
            if needle[start : start + length] in fragment:
                longest = length
                break
        if longest:
            covered.update(range(start, start + longest))
    return covered


def check_cross_call_canary(
    action: Action, policy: Policy, prior_fragments: list[str]
) -> Decision | None:
    """Catch a canary assembled across several calls, none of which matches alone.

    Deterministic in (action, policy, prior_fragments): the state is passed in,
    never read from a global, so a decision stays replayable.

    The test is *positional coverage*, not string containment. Each call
    discloses a set of canary character positions; the session accumulates them.
    When the union covers the whole token, the honeytoken has been handed over
    in pieces and that is an exfiltration regardless of how it was spread out.

    Two guards against noise:
      * a position only counts inside a run of >= CANARY_FRAGMENT_MIN_CHARS, so
        incidental short overlaps contribute nothing;
      * full coverage is required, and the current call must disclose something
        the session did not already have. Otherwise every call after a leak
        would be blocked for a leak that already completed.
    """
    if policy.is_trusted(action.server):
        return None
    current = squashed_arg_text(action)
    if not current:
        return None

    for canary in policy.canaries:
        needle = _squash(canary)
        if len(needle) < CANARY_FRAGMENT_MIN_CHARS:
            continue

        current_cover = canary_coverage(needle, current)
        if not current_cover:
            continue  # this call discloses nothing; nothing to accumulate

        prior_cover: set[int] = set()
        for fragment in prior_fragments:
            prior_cover |= canary_coverage(needle, fragment)

        if len(prior_cover) == len(needle):
            continue  # already fully disclosed earlier; not this call's doing
        if not (current_cover - prior_cover):
            continue  # adds nothing new

        if len(prior_cover | current_cover) < len(needle):
            continue  # still incomplete

        evidence = [
            Evidence(
                id="inv-x1",
                kind="canary_reassembled",
                detail=(
                    f"a canary token is fully disclosed by this call combined with "
                    f"{len(prior_fragments)} earlier call(s) in the same session; "
                    f"no single call contains it "
                    f"(this call adds {len(current_cover - prior_cover)} of "
                    f"{len(needle)} characters)"
                ),
            )
        ]
        return Decision(
            verdict=Verdict.BLOCK,
            layer="invariants",
            reason="hard invariant violated: canary_reassembled",
            score=1.0,
            confidence=1.0,
            evidence_ids=[e.id for e in evidence],
            evidence=evidence,
        )
    return None
