"""Edge cases and error paths for the crack engine + hash-type detection.

No network, pure stdlib. These exercise the validation and rule-handling code
paths that the happy-path smoke tests do not.
"""
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crackq.core import (  # noqa: E402
    crack_hash,
    scan,
    detect_algorithm,
    detect_algorithms,
    is_hex_digest,
    supported_algorithms,
)


# --------------------------------------------------------------------------- #
# hash-type detection
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("algo,expected_len", [
    ("md5", 32), ("sha1", 40), ("sha224", 56),
    ("sha256", 64), ("sha384", 96), ("sha512", 128),
])
def test_detect_algorithm_by_length(algo, expected_len):
    digest = hashlib.new(algo, b"probe").hexdigest()
    assert len(digest) == expected_len
    assert detect_algorithm(digest) == algo


def test_detect_algorithms_lists_all_candidates():
    digest = hashlib.sha256(b"x").hexdigest()
    assert detect_algorithms(digest) == ["sha256"]


def test_detect_algorithm_unknown_length_is_none():
    assert detect_algorithm("ab" * 5) is None  # 10 hex chars, no algo
    assert detect_algorithms("ab" * 5) == []


def test_detect_rejects_non_hex():
    assert detect_algorithm("z" * 32) is None
    assert detect_algorithms("z" * 32) == []
    assert detect_algorithm("") is None


def test_detect_strips_and_lowercases():
    digest = hashlib.md5(b"y").hexdigest().upper()
    assert detect_algorithm("  " + digest + "  ") == "md5"


@pytest.mark.parametrize("s,ok", [
    ("deadbeef", True),
    ("DEADBEEF", True),          # case-insensitive
    ("dead", True),
    ("deadbee", False),          # odd length
    ("nothex!!", False),
    ("", False),
    ("  abcd  ", True),          # surrounding whitespace tolerated
])
def test_is_hex_digest(s, ok):
    assert is_hex_digest(s) is ok


def test_supported_algorithms_sorted_and_complete():
    algos = supported_algorithms()
    assert algos == sorted(algos)
    for a in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        assert a in algos


# --------------------------------------------------------------------------- #
# crack_hash validation / error paths
# --------------------------------------------------------------------------- #
def test_empty_digest_raises():
    with pytest.raises(ValueError, match="empty"):
        crack_hash("", ["x"])


def test_non_hex_digest_raises():
    with pytest.raises(ValueError, match="hexadecimal"):
        crack_hash("not-a-hash!!", ["x"])


def test_non_string_digest_raises():
    with pytest.raises(ValueError, match="string"):
        crack_hash(12345, ["x"])  # type: ignore[arg-type]


def test_undetectable_length_raises():
    with pytest.raises(ValueError, match="undetectable|unknown"):
        crack_hash("ab" * 10, ["x"])  # 20 hex chars, valid hex, no algo


def test_length_mismatch_with_explicit_algorithm_raises():
    # A valid md5-length digest but the caller insists it is sha256.
    digest = hashlib.md5(b"z").hexdigest()
    with pytest.raises(ValueError, match="does not match"):
        crack_hash(digest, ["z"], algorithm="sha256")


def test_bad_max_candidates_raises():
    digest = hashlib.md5(b"z").hexdigest()
    with pytest.raises(ValueError, match="max_candidates"):
        crack_hash(digest, ["z"], max_candidates=0)
    with pytest.raises(ValueError, match="max_candidates"):
        crack_hash(digest, ["z"], max_candidates=-3)


def test_non_string_wordlist_entry_raises():
    digest = hashlib.md5(b"z").hexdigest()
    with pytest.raises(ValueError, match="strings"):
        crack_hash(digest, [123])  # type: ignore[list-item]


# --------------------------------------------------------------------------- #
# crack_hash behaviour
# --------------------------------------------------------------------------- #
def test_max_candidates_caps_work_and_reports_miss():
    digest = hashlib.md5(b"never-present").hexdigest()
    res = crack_hash(digest, ["a", "b", "c", "d", "e"], rules=True, max_candidates=3)
    assert res["cracked"] is False
    assert res["candidates_tried"] == 3


def test_empty_and_whitespace_words_skipped():
    digest = hashlib.md5(b"live").hexdigest()
    res = crack_hash(digest, ["", "\n", "live"], rules=False)
    assert res["cracked"] is True
    # only the one real word was tried
    assert res["candidates_tried"] == 1


def test_empty_wordlist_exhausts_cleanly():
    digest = hashlib.md5(b"x").hexdigest()
    res = crack_hash(digest, [], rules=True)
    assert res["cracked"] is False
    assert res["candidates_tried"] == 0
    assert res["plaintext"] is None


def test_rule_leet_variant():
    # leet maps a->4 s->5 o->0, so 'password' -> 'p455w0rd', reachable only with rules
    digest = hashlib.sha1("p455w0rd".encode()).hexdigest()
    assert crack_hash(digest, ["password"], rules=False)["cracked"] is False
    hit = crack_hash(digest, ["password"], rules=True)
    assert hit["cracked"] and hit["plaintext"] == "p455w0rd"


def test_rule_capitalized_suffix_variant():
    # 'Summer2025' = capitalize + append '2025'
    digest = hashlib.sha256("Summer2025".encode()).hexdigest()
    assert crack_hash(digest, ["summer"], rules=False)["cracked"] is False
    hit = crack_hash(digest, ["summer"], rules=True)
    assert hit["cracked"] and hit["plaintext"] == "Summer2025"


def test_rule_reverse_variant():
    digest = hashlib.md5("drowssap".encode()).hexdigest()
    assert crack_hash(digest, ["password"], rules=True)["plaintext"] == "drowssap"


def test_rules_increase_candidate_count():
    digest = hashlib.md5(b"zzz-miss").hexdigest()
    few = crack_hash(digest, ["word"], rules=False)["candidates_tried"]
    many = crack_hash(digest, ["word"], rules=True)["candidates_tried"]
    assert many > few


def test_explicit_algorithm_overrides_detection():
    # sha224 and would-be-detected value: force sha224 explicitly.
    digest = hashlib.sha224(b"forced").hexdigest()
    res = crack_hash(digest, ["forced"], algorithm="sha224", rules=False)
    assert res["algorithm"] == "sha224" and res["cracked"]


def test_unicode_plaintext_round_trips():
    secret = "pa??w?rd_??"
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    res = crack_hash(digest, [secret], rules=False)
    assert res["cracked"] and res["plaintext"] == secret


# --------------------------------------------------------------------------- #
# scan() convenience wrapper
# --------------------------------------------------------------------------- #
def test_scan_matches_crack_hash():
    digest = hashlib.sha256(b"monkey").hexdigest()
    assert scan(digest, wordlist=["monkey"], rules=False)["plaintext"] == "monkey"


def test_scan_loads_wordlist_from_path(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("alpha\nmonkey\n", encoding="utf-8")
    digest = hashlib.sha256(b"monkey").hexdigest()
    res = scan(digest, wordlist=str(wl), rules=False)
    assert res["cracked"] and res["plaintext"] == "monkey"


def test_scan_no_wordlist_exhausts():
    digest = hashlib.md5(b"x").hexdigest()
    assert scan(digest)["cracked"] is False
