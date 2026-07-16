"""Password composition & strength analytics for CRACKQ.

The defensive payoff of cracking your *own* hashes is a report: once a
plaintext falls, *why* was it weak, and how many others share the flaw? This
module turns recovered plaintexts into an actionable audit — character-class
breakdown, a charset-entropy estimate, common-pattern detection (year suffix,
leet, keyboard walks, repeats), reuse detection across a set, and plain-English
remediation guidance.

Everything here is pure standard library — no network, no third-party deps,
consistent with the rest of crackq. The entropy figure is a *search-space*
(NIST-style charset) estimate: ``length * log2(pool_size)``. It is an upper
bound on guessing difficulty, not a claim about a specific attacker's cost, and
is labelled as an estimate everywhere it surfaces.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence

__all__ = [
    "CHAR_CLASSES",
    "STRENGTH_TIERS",
    "character_classes",
    "estimate_entropy_bits",
    "classify_strength",
    "detect_patterns",
    "analyze_password",
    "analyze_batch",
    "crack_report",
]

# Character classes and the guessing-pool size each contributes. The pool is
# what an attacker must brute-force per position if that class is present.
CHAR_CLASSES = {
    "lower": (re.compile(r"[a-z]"), 26),
    "upper": (re.compile(r"[A-Z]"), 26),
    "digit": (re.compile(r"[0-9]"), 10),
    "symbol": (re.compile(r"[^A-Za-z0-9]"), 33),  # printable ASCII punctuation
}

# Ordered strength tiers keyed on the charset-entropy estimate (bits). The
# first tier whose ``max_bits`` the value is *below* wins; the final tier is the
# open-ended ceiling. Thresholds follow common NIST-era guidance.
STRENGTH_TIERS: Sequence = (
    ("very-weak", 28.0),
    ("weak", 36.0),
    ("fair", 60.0),
    ("strong", 128.0),
    ("very-strong", math.inf),
)

# Well-known adjacent keyboard runs (both directions matched via reversal).
_KEYBOARD_RUNS = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
    "qwerty", "azerty",
)

_YEAR_RE = re.compile(r"(?:19|20)\d{2}$")
_TRAILING_DIGITS_RE = re.compile(r"\d+$")
_LEET_CHARS = set("013457")
_LEET_MAP = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}


def character_classes(password: str) -> List[str]:
    """Return the sorted character classes present in ``password``.

    Classes are drawn from :data:`CHAR_CLASSES` (``lower``, ``upper``,
    ``digit``, ``symbol``). An empty string yields an empty list.
    """
    present = [name for name, (rx, _) in CHAR_CLASSES.items() if rx.search(password)]
    return sorted(present)


def estimate_entropy_bits(password: str) -> float:
    """Estimate charset (search-space) entropy in bits.

    Computed as ``len(password) * log2(pool)`` where ``pool`` is the summed
    guessing-pool size of every character class present. Returns ``0.0`` for an
    empty password. This is an *upper-bound estimate*, not a measured entropy.
    """
    if not password:
        return 0.0
    pool = sum(size for _, (rx, size) in CHAR_CLASSES.items() if rx.search(password))
    if pool <= 0:
        return 0.0
    return round(len(password) * math.log2(pool), 2)


def classify_strength(entropy_bits: float) -> str:
    """Map an entropy-bits estimate to a named strength tier.

    See :data:`STRENGTH_TIERS`. Values are compared against each tier's ceiling
    in order, so ``27.9`` -> ``very-weak`` and ``200`` -> ``very-strong``.
    """
    for name, ceiling in STRENGTH_TIERS:
        if entropy_bits < ceiling:
            return name
    return STRENGTH_TIERS[-1][0]  # pragma: no cover - inf ceiling guarantees a hit


def _looks_leet(password: str) -> bool:
    """Heuristic: does the password substitute leet digits *inside* a word?

    Requires at least one leet digit (0/1/3/4/5/7) sitting between two ASCII
    letters (an interior substitution such as ``p455w0rd``) and that de-leeting
    yields a mostly-alphabetic token. Trailing digit suffixes (``word123``,
    ``word2024``) are deliberately *not* flagged as leet — they are reported as
    ``trailing-digits`` / ``year-suffix`` instead.
    """
    interior_leet = any(
        password[i] in _LEET_CHARS
        and password[i - 1].isalpha()
        and password[i + 1].isalpha()
        for i in range(1, len(password) - 1)
    )
    if not interior_leet:
        return False
    deleeted = "".join(_LEET_MAP.get(c, c) for c in password.lower())
    letters = sum(c.isalpha() for c in deleeted)
    return letters >= max(3, len(deleeted) - 1)


def _has_keyboard_run(password: str, min_len: int = 4) -> bool:
    low = password.lower()
    for run in _KEYBOARD_RUNS:
        for i in range(len(run) - min_len + 1):
            if run[i:i + min_len] in low:
                return True
    return False


def _has_repeat(password: str, run: int = 3) -> bool:
    """True if any single character repeats ``run`` or more times in a row."""
    count = 1
    for a, b in zip(password, password[1:]):
        count = count + 1 if a == b else 1
        if count >= run:
            return True
    return False


def detect_patterns(password: str) -> List[str]:
    """Detect common weakening patterns in a password.

    Returns a sorted list of pattern tags, any of:
    ``all-digits``, ``all-lower``, ``all-upper``, ``capitalized``,
    ``keyboard-sequence``, ``leet``, ``repeat-run``, ``short``,
    ``trailing-digits``, ``year-suffix``. An empty/strong password may return
    an empty list.
    """
    tags: List[str] = []
    if not password:
        return tags
    if len(password) < 8:
        tags.append("short")
    if password.isdigit():
        tags.append("all-digits")
    elif password.isalpha() and password.islower():
        tags.append("all-lower")
    elif password.isalpha() and password.isupper():
        tags.append("all-upper")
    if len(password) > 1 and password[0].isupper() and password[1:].islower():
        tags.append("capitalized")
    if _YEAR_RE.search(password):
        tags.append("year-suffix")
    elif _TRAILING_DIGITS_RE.search(password):
        tags.append("trailing-digits")
    if _looks_leet(password):
        tags.append("leet")
    if _has_keyboard_run(password):
        tags.append("keyboard-sequence")
    if _has_repeat(password):
        tags.append("repeat-run")
    return sorted(set(tags))


def analyze_password(password: str) -> Dict[str, object]:
    """Analyze a single plaintext password.

    Returns a dict with ``password``, ``length``, ``classes``, ``class_count``,
    ``entropy_bits`` (estimate), ``strength`` tier, and detected ``patterns``.
    """
    if not isinstance(password, str):
        raise ValueError(
            f"password must be a string, got {type(password).__name__}"
        )
    entropy = estimate_entropy_bits(password)
    classes = character_classes(password)
    return {
        "password": password,
        "length": len(password),
        "classes": classes,
        "class_count": len(classes),
        "entropy_bits": entropy,
        "strength": classify_strength(entropy),
        "patterns": detect_patterns(password),
    }


def _recommendations(
    count: int,
    by_strength: Dict[str, int],
    pattern_frequency: Dict[str, int],
    reused: Dict[str, int],
    min_length: int,
) -> List[str]:
    recs: List[str] = []
    weak = by_strength.get("very-weak", 0) + by_strength.get("weak", 0)
    if weak:
        pct = round(100 * weak / count) if count else 0
        recs.append(
            f"{weak}/{count} ({pct}%) recovered passwords are weak or very-weak — "
            "force resets and require greater length/entropy."
        )
    if min_length < 12:
        recs.append(
            f"Shortest recovered password is {min_length} chars — enforce a "
            "12+ character minimum."
        )
    if pattern_frequency.get("year-suffix") or pattern_frequency.get("trailing-digits"):
        recs.append(
            "Digit/year suffixes are common — block predictable append rules and "
            "disallow the current/prior year."
        )
    if pattern_frequency.get("keyboard-sequence"):
        recs.append(
            "Keyboard-walk sequences detected — add them to a denylist."
        )
    if pattern_frequency.get("leet"):
        recs.append(
            "Leet substitutions offer little real entropy — do not treat them as "
            "complexity."
        )
    if reused:
        recs.append(
            f"{len(reused)} password(s) are reused across accounts — enforce "
            "uniqueness and consider a breached-password screen."
        )
    if not recs:
        recs.append("No systemic weaknesses detected in the recovered set.")
    return recs


def analyze_batch(
    passwords: Iterable[str],
    top_weak: int = 5,
) -> Dict[str, object]:
    """Aggregate analytics over a collection of recovered plaintexts.

    Returns counts, length/entropy summaries, per-strength and per-class
    tallies, pattern frequency, reuse detection, the ``top_weak`` weakest
    entries, and plain-English ``recommendations``. An empty input yields a
    well-formed report with ``count == 0``.
    """
    analyses = [analyze_password(p) for p in passwords]
    count = len(analyses)
    by_strength: Dict[str, int] = {name: 0 for name, _ in STRENGTH_TIERS}
    class_usage: Dict[str, int] = {name: 0 for name in CHAR_CLASSES}
    pattern_frequency: Counter = Counter()
    lengths: List[int] = []
    entropies: List[float] = []
    seen: Counter = Counter()

    for a in analyses:
        by_strength[str(a["strength"])] += 1
        for cls in a["classes"]:  # type: ignore[union-attr]
            class_usage[cls] += 1
        for pat in a["patterns"]:  # type: ignore[union-attr]
            pattern_frequency[pat] += 1
        lengths.append(int(a["length"]))
        entropies.append(float(a["entropy_bits"]))
        seen[str(a["password"])] += 1

    reused = {pw: n for pw, n in seen.items() if n > 1}
    weakest = sorted(
        analyses, key=lambda a: (a["entropy_bits"], a["length"])
    )[:top_weak]

    report: Dict[str, object] = {
        "count": count,
        "unique": len(seen),
        "avg_length": round(sum(lengths) / count, 2) if count else 0.0,
        "min_length": min(lengths) if lengths else 0,
        "max_length": max(lengths) if lengths else 0,
        "avg_entropy_bits": round(sum(entropies) / count, 2) if count else 0.0,
        "by_strength": by_strength,
        "class_usage": class_usage,
        "pattern_frequency": dict(pattern_frequency),
        "reused": reused,
        "weakest": [
            {
                "password": w["password"],
                "entropy_bits": w["entropy_bits"],
                "strength": w["strength"],
            }
            for w in weakest
        ],
        "recommendations": _recommendations(
            count, by_strength, dict(pattern_frequency), reused,
            min(lengths) if lengths else 0,
        ),
    }
    return report


def _record_field(record: object, field: str) -> object:
    """Read ``field`` from a Job-like object or a plain dict."""
    if isinstance(record, dict):
        return record.get(field)
    return getattr(record, field, None)


def _state_value(record: object) -> Optional[str]:
    state = _record_field(record, "state")
    # Job.state is a JobState enum; dicts already carry the string value.
    return getattr(state, "value", state) if state is not None else None


def crack_report(records: Iterable[object], top_weak: int = 5) -> Dict[str, object]:
    """Build a policy report from finished jobs (``Job`` objects or dicts).

    Accepts anything exposing ``state`` and ``plaintext`` — the :class:`Job`
    dataclass, ``Job.to_dict()`` output, or CLI JSON rows. Recovered plaintexts
    feed :func:`analyze_batch`; the summary also reports crack rate and a
    per-state breakdown. Records without a plaintext are counted but excluded
    from the composition analysis.
    """
    records = list(records)
    by_state: Counter = Counter()
    plaintexts: List[str] = []
    for rec in records:
        state = _state_value(rec)
        by_state[state or "unknown"] += 1
        if state == "cracked":
            pt = _record_field(rec, "plaintext")
            if isinstance(pt, str):
                plaintexts.append(pt)

    total = len(records)
    cracked = by_state.get("cracked", 0)
    return {
        "total_jobs": total,
        "cracked": cracked,
        "crack_rate": round(cracked / total, 4) if total else 0.0,
        "by_state": dict(by_state),
        "analysis": analyze_batch(plaintexts, top_weak=top_weak),
    }
