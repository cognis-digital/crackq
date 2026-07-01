"""CLI tests: run, detect, audit, algos — success, error, and exit-code paths."""
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crackq.cli import main, build_parser  # noqa: E402


def _run(argv, capsys):
    rc = main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
def test_run_json_crack_success(tmp_path, capsys):
    digest = hashlib.md5(b"welcome").hexdigest()
    rc, out, _ = _run([
        "--format", "json", "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hash", digest, "--words", "welcome", "admin",
    ], capsys)
    assert rc == 0
    rows = json.loads(out)
    assert rows[0]["state"] == "cracked" and rows[0]["plaintext"] == "welcome"


def test_run_table_format(tmp_path, capsys):
    digest = hashlib.md5(b"welcome").hexdigest()
    rc, out, _ = _run([
        "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hash", digest, "--words", "welcome",
    ], capsys)
    assert rc == 0
    assert "cracked" in out and "welcome" in out


def test_run_exhausted_still_exit_zero(tmp_path, capsys):
    digest = hashlib.md5(b"not-in-list").hexdigest()
    rc, out, _ = _run([
        "--format", "json", "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hash", digest, "--words", "other",
    ], capsys)
    assert rc == 0  # ran cleanly, just didn't crack
    assert json.loads(out)[0]["state"] == "exhausted"


def test_run_bad_algorithm_exit_one(tmp_path, capsys):
    digest = hashlib.md5(b"welcome").hexdigest()  # 32 hex chars
    rc, _, _ = _run([
        "--format", "json", "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hash", digest, "--algorithm", "sha256", "--words", "welcome",
    ], capsys)
    assert rc == 1  # job FAILED (length mismatch)


def test_run_no_hashes_exit_two(tmp_path, capsys):
    rc, _, err = _run([
        "--audit-log", str(tmp_path / "a.jsonl"), "run", "--words", "x",
    ], capsys)
    assert rc == 2 and "no hashes" in err


def test_run_no_wordlist_exit_two(tmp_path, capsys):
    digest = hashlib.md5(b"x").hexdigest()
    rc, _, err = _run([
        "--audit-log", str(tmp_path / "a.jsonl"), "run", "--hash", digest,
    ], capsys)
    assert rc == 2 and "no wordlist" in err


def test_run_missing_wordlist_file_exit_two(tmp_path, capsys):
    digest = hashlib.md5(b"x").hexdigest()
    rc, _, err = _run([
        "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hash", digest, "--wordlist", str(tmp_path / "nope.txt"),
    ], capsys)
    assert rc == 2 and "error" in err.lower()


def test_run_no_rules_flag(tmp_path, capsys):
    # 'welcome1' only crackable with rules; --no-rules must miss it.
    digest = hashlib.md5(b"welcome1").hexdigest()
    rc, out, _ = _run([
        "--format", "json", "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hash", digest, "--words", "welcome", "--no-rules",
    ], capsys)
    assert rc == 0 and json.loads(out)[0]["state"] == "exhausted"


def test_run_hashfile_and_wordlist_files(tmp_path, capsys):
    hf = tmp_path / "h.txt"
    wf = tmp_path / "w.txt"
    hf.write_text(hashlib.sha256(b"monkey").hexdigest() + "\n", encoding="utf-8")
    wf.write_text("monkey\nalpha\n", encoding="utf-8")
    rc, out, _ = _run([
        "--format", "json", "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hashfile", str(hf), "--wordlist", str(wf), "--owner", "ci",
    ], capsys)
    assert rc == 0 and json.loads(out)[0]["plaintext"] == "monkey"


def test_run_metrics_flag(tmp_path, capsys):
    digest = hashlib.md5(b"welcome").hexdigest()
    rc, out, _ = _run([
        "--format", "json", "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hash", digest, "--words", "welcome", "--metrics",
    ], capsys)
    assert rc == 0
    m = json.loads(out)
    assert m["jobs"] == 1 and m["cracked"] == 1


# --------------------------------------------------------------------------- #
# detect
# --------------------------------------------------------------------------- #
def test_detect_identifies_sha256(capsys):
    digest = hashlib.sha256(b"x").hexdigest()
    rc, out, _ = _run(["--format", "json", "detect", "--hash", digest], capsys)
    assert rc == 0
    row = json.loads(out)[0]
    assert row["likely"] == "sha256" and row["valid_hex"] is True


def test_detect_unknown_exit_one(capsys):
    rc, out, _ = _run(["--format", "json", "detect", "--hash", "notahash"], capsys)
    assert rc == 1
    assert json.loads(out)[0]["likely"] == "-"


def test_detect_multiple_hashes(capsys):
    md5 = hashlib.md5(b"x").hexdigest()
    sha1 = hashlib.sha1(b"x").hexdigest()
    rc, out, _ = _run([
        "--format", "json", "detect", "--hash", md5, "--hash", sha1,
    ], capsys)
    assert rc == 0
    rows = json.loads(out)
    assert {r["likely"] for r in rows} == {"md5", "sha1"}


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #
def test_audit_verify_clean(tmp_path, capsys):
    audit = str(tmp_path / "a.jsonl")
    digest = hashlib.md5(b"welcome").hexdigest()
    _run(["--audit-log", audit, "run", "--hash", digest, "--words", "welcome"], capsys)
    rc, out, _ = _run(["--format", "json", "--audit-log", audit, "audit", "--verify"], capsys)
    assert rc == 0 and json.loads(out)["verified"] is True


def test_audit_verify_tampered_exit_one(tmp_path, capsys):
    audit = str(tmp_path / "a.jsonl")
    digest = hashlib.md5(b"welcome").hexdigest()
    _run(["--audit-log", audit, "run", "--hash", digest, "--words", "welcome"], capsys)
    with open(audit, "r", encoding="utf-8") as f:
        lines = f.readlines()
    lines[0] = lines[0].replace('"operator"', '"mallory"')
    with open(audit, "w", encoding="utf-8") as f:
        f.writelines(lines)
    rc, out, _ = _run(["--format", "json", "--audit-log", audit, "audit", "--verify"], capsys)
    assert rc == 1 and json.loads(out)["verified"] is False


def test_audit_print_entries(tmp_path, capsys):
    audit = str(tmp_path / "a.jsonl")
    digest = hashlib.md5(b"welcome").hexdigest()
    _run(["--audit-log", audit, "run", "--hash", digest, "--words", "welcome"], capsys)
    rc, out, _ = _run(["--format", "json", "--audit-log", audit, "audit"], capsys)
    assert rc == 0
    actions = [e["action"] for e in json.loads(out)]
    assert "submit" in actions and "crack" in actions


# --------------------------------------------------------------------------- #
# algos / parser / misc
# --------------------------------------------------------------------------- #
def test_algos_json_lists_all(capsys):
    rc, out, _ = _run(["--format", "json", "algos"], capsys)
    assert rc == 0
    names = {r["algorithm"] for r in json.loads(out)}
    assert {"md5", "sha1", "sha256", "sha512"} <= names


def test_no_subcommand_errors():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert "crackq" in capsys.readouterr().out
