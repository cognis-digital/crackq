"""Tests for the password composition & strength analytics engine."""
import hashlib
import math
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crackq.analyze import (  # noqa: E402
    analyze_password,
    analyze_batch,
    crack_report,
    character_classes,
    classify_strength,
    detect_patterns,
    estimate_entropy_bits,
)
from crackq.core import CrackQ  # noqa: E402


# --------------------------------------------------------------------------- #
# character classes
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("pw,expected", [
    ("abc", ["lower"]),
    ("ABC", ["upper"]),
    ("123", ["digit"]),
    ("!@#", ["symbol"]),
    ("aB3", ["digit", "lower", "upper"]),
    ("aB3!", ["digit", "lower", "symbol", "upper"]),
    ("", []),
])
def test_character_classes(pw, expected):
    assert character_classes(pw) == expected


# --------------------------------------------------------------------------- #
# entropy estimate
# --------------------------------------------------------------------------- #
def test_entropy_empty_is_zero():
    assert estimate_entropy_bits("") == 0.0


def test_entropy_lowercase_matches_formula():
    # 8 lowercase chars over a 26-symbol pool
    assert estimate_entropy_bits("password") == round(8 * math.log2(26), 2)


def test_entropy_grows_with_pool_and_length():
    short_simple = estimate_entropy_bits("aaaa")
    long_simple = estimate_entropy_bits("aaaaaaaa")
    mixed = estimate_entropy_bits("aA1!")
    assert long_simple > short_simple
    assert mixed > estimate_entropy_bits("aaaa")


# --------------------------------------------------------------------------- #
# strength tiers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bits,tier", [
    (0.0, "very-weak"),
    (27.9, "very-weak"),
    (30.0, "weak"),
    (45.0, "fair"),
    (90.0, "strong"),
    (200.0, "very-strong"),
    (math.inf, "very-strong"),
])
def test_classify_strength(bits, tier):
    assert classify_strength(bits) == tier


# --------------------------------------------------------------------------- #
# pattern detection
# --------------------------------------------------------------------------- #
def test_patterns_all_digits_pin():
    assert "all-digits" in detect_patterns("1234")


def test_patterns_year_suffix():
    pats = detect_patterns("Summer2025")
    assert "year-suffix" in pats and "capitalized" in pats


def test_patterns_trailing_digits_not_year():
    pats = detect_patterns("welcome123")
    assert "trailing-digits" in pats and "year-suffix" not in pats


def test_patterns_leet_requires_interior_digit():
    assert "leet" in detect_patterns("p455w0rd")
    # a plain digit *suffix* must not be misread as leet
    assert "leet" not in detect_patterns("welcome123")


def test_patterns_keyboard_sequence():
    assert "keyboard-sequence" in detect_patterns("qwerty")
    assert "keyboard-sequence" in detect_patterns("myasdfghpw")


def test_patterns_repeat_run():
    assert "repeat-run" in detect_patterns("passsword")
    assert "repeat-run" not in detect_patterns("password")


def test_patterns_short_flag():
    assert "short" in detect_patterns("abc")
    assert "short" not in detect_patterns("abcdefghij")


def test_patterns_all_lower_and_upper():
    assert "all-lower" in detect_patterns("dictionary")
    assert "all-upper" in detect_patterns("SHOUTING")


def test_patterns_strong_password_is_clean():
    # a long random-ish mixed password should trip no weakening patterns
    assert detect_patterns("7Gq!zR#eW2vX") == []


# --------------------------------------------------------------------------- #
# analyze_password
# --------------------------------------------------------------------------- #
def test_analyze_password_shape():
    a = analyze_password("Summer2025")
    assert a["password"] == "Summer2025"
    assert a["length"] == 10
    assert a["class_count"] == 3
    assert a["strength"] in ("very-weak", "weak", "fair", "strong", "very-strong")
    assert "year-suffix" in a["patterns"]


def test_analyze_password_rejects_non_string():
    with pytest.raises(ValueError, match="string"):
        analyze_password(1234)  # type: ignore[arg-type]


def test_analyze_strong_beats_weak():
    weak = analyze_password("dragon")
    strong = analyze_password("7Gq!zR#eW2vX")
    assert strong["entropy_bits"] > weak["entropy_bits"]


# --------------------------------------------------------------------------- #
# analyze_batch
# --------------------------------------------------------------------------- #
def test_analyze_batch_empty():
    r = analyze_batch([])
    assert r["count"] == 0
    assert r["avg_length"] == 0.0
    assert r["recommendations"]  # always non-empty


def test_analyze_batch_aggregates():
    pws = ["dragon", "Summer2025", "welcome123", "p455w0rd", "7Gq!zR#eW2vX"]
    r = analyze_batch(pws, top_weak=3)
    assert r["count"] == 5
    assert r["unique"] == 5
    assert r["min_length"] == 6  # 'dragon'
    assert r["max_length"] == 12
    assert sum(r["by_strength"].values()) == 5
    assert len(r["weakest"]) == 3
    # weakest first: ascending entropy
    ent = [w["entropy_bits"] for w in r["weakest"]]
    assert ent == sorted(ent)
    assert r["pattern_frequency"].get("year-suffix", 0) >= 1


def test_analyze_batch_detects_reuse():
    r = analyze_batch(["hunter2", "hunter2", "unique"])
    assert r["unique"] == 2
    assert r["reused"] == {"hunter2": 2}
    assert any("reused" in rec for rec in r["recommendations"])


def test_analyze_batch_class_usage():
    r = analyze_batch(["abcdef", "ABC123"])
    assert r["class_usage"]["lower"] == 1
    assert r["class_usage"]["upper"] == 1
    assert r["class_usage"]["digit"] == 1


# --------------------------------------------------------------------------- #
# crack_report (over Job objects and dict rows)
# --------------------------------------------------------------------------- #
def test_crack_report_over_jobs(tmp_path):
    q = CrackQ(str(tmp_path / "a.jsonl"),
               wordlist=["dragon", "welcome"])
    q.submit(hashlib.md5(b"dragon").hexdigest(), "u")            # cracked
    q.submit(hashlib.md5(b"not-in-list").hexdigest(), "u")       # exhausted
    q.run_all()
    rep = crack_report(q.status())
    assert rep["total_jobs"] == 2
    assert rep["cracked"] == 1
    assert rep["crack_rate"] == 0.5
    assert rep["by_state"]["cracked"] == 1
    assert rep["by_state"]["exhausted"] == 1
    assert rep["analysis"]["count"] == 1  # only the cracked plaintext analysed


def test_crack_report_over_dict_rows():
    rows = [
        {"state": "cracked", "plaintext": "dragon"},
        {"state": "cracked", "plaintext": "Summer2025"},
        {"state": "exhausted", "plaintext": None},
    ]
    rep = crack_report(rows)
    assert rep["total_jobs"] == 3
    assert rep["cracked"] == 2
    assert rep["analysis"]["count"] == 2


def test_crack_report_empty():
    rep = crack_report([])
    assert rep["total_jobs"] == 0
    assert rep["crack_rate"] == 0.0
    assert rep["analysis"]["count"] == 0
