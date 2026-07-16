"""CLI tests: run, scan, detect, analyze, audit, algos — success, error, exit codes."""
import csv
import hashlib
import io
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
    assert rc == 0
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


def test_run_report_flag(tmp_path, capsys):
    digest = hashlib.md5(b"dragon").hexdigest()
    rc, out, _ = _run([
        "--format", "json", "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hash", digest, "--words", "dragon", "--report",
    ], capsys)
    assert rc == 0
    rep = json.loads(out)
    assert rep["cracked"] == 1 and rep["crack_rate"] == 1.0
    assert rep["analysis"]["count"] == 1


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def test_scan_cracks_and_exits_zero(capsys):
    digest = hashlib.md5(b"monkey").hexdigest()
    rc, out, _ = _run(["--format", "json", "scan", digest, "--words", "monkey"], capsys)
    assert rc == 0
    res = json.loads(out)
    assert res["cracked"] and res["plaintext"] == "monkey"


def test_scan_miss_exits_one(capsys):
    digest = hashlib.md5(b"absent").hexdigest()
    rc, out, _ = _run(["--format", "json", "scan", digest, "--words", "other"], capsys)
    assert rc == 1
    assert json.loads(out)["cracked"] is False


def test_scan_bad_digest_exit_two(capsys):
    rc, _, err = _run(["scan", "not-a-hash", "--words", "x"], capsys)
    assert rc == 2 and "error" in err.lower()


def test_scan_max_candidates(capsys):
    digest = hashlib.md5(b"absent").hexdigest()
    rc, out, _ = _run([
        "--format", "json", "scan", digest,
        "--words", "a", "b", "c", "--no-rules", "--max-candidates", "2",
    ], capsys)
    assert rc == 1
    assert json.loads(out)["candidates_tried"] == 2


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
# analyze
# --------------------------------------------------------------------------- #
def test_analyze_per_password_json(capsys):
    rc, out, _ = _run([
        "--format", "json", "analyze", "--password", "Summer2025",
    ], capsys)
    assert rc == 0
    rows = json.loads(out)
    assert rows[0]["password"] == "Summer2025"
    assert "year-suffix" in rows[0]["patterns"]


def test_analyze_report_json(capsys):
    rc, out, _ = _run([
        "--format", "json", "analyze",
        "--password", "dragon", "--password", "7Gq!zR#eW2vX", "--report",
    ], capsys)
    assert rc == 0
    rep = json.loads(out)
    assert rep["count"] == 2 and rep["recommendations"]


def test_analyze_no_passwords_exit_two(capsys):
    rc, _, err = _run(["analyze"], capsys)
    assert rc == 2 and "no passwords" in err


def test_analyze_pwfile(tmp_path, capsys):
    pf = tmp_path / "pw.txt"
    pf.write_text("dragon\nSummer2025\n", encoding="utf-8")
    rc, out, _ = _run([
        "--format", "json", "analyze", "--pwfile", str(pf), "--report",
    ], capsys)
    assert rc == 0 and json.loads(out)["count"] == 2


# --------------------------------------------------------------------------- #
# csv output
# --------------------------------------------------------------------------- #
def test_csv_output_for_detect(capsys):
    digest = hashlib.sha256(b"x").hexdigest()
    rc, out, _ = _run(["--format", "csv", "detect", "--hash", digest], capsys)
    assert rc == 0
    reader = list(csv.DictReader(io.StringIO(out)))
    assert reader[0]["likely"] == "sha256"


def test_csv_output_for_metrics(tmp_path, capsys):
    digest = hashlib.md5(b"welcome").hexdigest()
    rc, out, _ = _run([
        "--format", "csv", "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hash", digest, "--words", "welcome", "--metrics",
    ], capsys)
    assert rc == 0
    rows = {r[0]: r[1] for r in csv.reader(io.StringIO(out)) if r}
    assert rows["cracked"] == "1"


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
    assert {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"} <= names


def test_mcp_without_extra_reports_helpfully(capsys):
    # cognis_core is not a hard dependency; the subcommand must degrade
    # gracefully with an actionable message rather than a traceback.
    import importlib.util
    if importlib.util.find_spec("cognis_core") is not None:
        pytest.skip("MCP extra installed; missing-dependency path not exercised")
    rc, _, err = _run(["mcp"], capsys)
    assert rc == 1 and "MCP support is not installed" in err


def test_no_subcommand_errors():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_format_flag_accepted_after_subcommand(tmp_path, capsys):
    # --format works both before and after the subcommand (forgiving UX).
    digest = hashlib.md5(b"welcome").hexdigest()
    rc, out, _ = _run([
        "run", "--audit-log", str(tmp_path / "a.jsonl"),
        "--hash", digest, "--words", "welcome", "--format", "json",
    ], capsys)
    assert rc == 0
    assert json.loads(out)[0]["state"] == "cracked"


def test_format_before_subcommand_survives(tmp_path, capsys):
    # A value given before the subcommand is not clobbered by the SUPPRESS default.
    digest = hashlib.md5(b"welcome").hexdigest()
    rc, out, _ = _run([
        "--format", "json", "--audit-log", str(tmp_path / "a.jsonl"),
        "run", "--hash", digest, "--words", "welcome",
    ], capsys)
    assert rc == 0
    json.loads(out)  # must be valid JSON, i.e. json format took effect


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert "crackq" in capsys.readouterr().out
