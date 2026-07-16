"""Tamper-evident audit-log tests: chaining, verification, and detection."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crackq.core import AuditLog, AuditError  # noqa: E402


def _log(tmp_path):
    return AuditLog(str(tmp_path / "audit.jsonl"))


def test_empty_log_verifies_and_has_no_entries(tmp_path):
    log = _log(tmp_path)
    assert log.entries() == []
    assert log.verify() is True


def test_append_returns_chained_record(tmp_path):
    log = _log(tmp_path)
    r1 = log.append("submit", "alice", job_id="a1")
    assert r1["prev"] == AuditLog.GENESIS
    assert r1["user"] == "alice" and r1["action"] == "submit"
    r2 = log.append("start", "alice", job_id="a1")
    # each record's prev is the previous record's this
    assert r2["prev"] == r1["this"]


def test_detail_kwargs_are_stored(tmp_path):
    log = _log(tmp_path)
    log.append("crack", "bob", job_id="j9", tried=42)
    rec = log.entries()[0]
    assert rec["detail"] == {"job_id": "j9", "tried": 42}


def test_multi_record_chain_verifies(tmp_path):
    log = _log(tmp_path)
    for i in range(10):
        log.append("event", f"user{i}", n=i)
    assert len(log.entries()) == 10
    assert log.verify() is True


def test_tampered_user_field_detected(tmp_path):
    log = _log(tmp_path)
    log.append("submit", "analyst", job_id="a1")
    log.append("start", "analyst", job_id="a1")
    with open(log.path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    lines[0] = lines[0].replace('"analyst"', '"mallory"')
    with open(log.path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    with pytest.raises(AuditError, match="digest mismatch|record altered"):
        log.verify()


def test_deleted_record_breaks_chain(tmp_path):
    log = _log(tmp_path)
    log.append("one", "u")
    log.append("two", "u")
    log.append("three", "u")
    with open(log.path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    del lines[1]  # remove the middle record
    with open(log.path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    with pytest.raises(AuditError, match="prev mismatch|chain broken"):
        log.verify()


def test_reordered_records_detected(tmp_path):
    log = _log(tmp_path)
    log.append("one", "u")
    log.append("two", "u")
    with open(log.path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    lines.reverse()
    with open(log.path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    with pytest.raises(AuditError):
        log.verify()


def test_appended_forged_record_detected(tmp_path):
    log = _log(tmp_path)
    log.append("one", "u")
    forged = {
        "ts": 1.0, "user": "mallory", "action": "grant",
        "detail": {}, "prev": "0" * 64, "this": "f" * 64,
    }
    with open(log.path, "a", encoding="utf-8") as f:
        f.write(json.dumps(forged, sort_keys=True) + "\n")
    with pytest.raises(AuditError):
        log.verify()


def test_entries_skips_blank_lines(tmp_path):
    log = _log(tmp_path)
    log.append("one", "u")
    with open(log.path, "a", encoding="utf-8") as f:
        f.write("\n\n")
    assert len(log.entries()) == 1
    assert log.verify() is True
