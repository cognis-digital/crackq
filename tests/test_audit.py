"""Audit-chain tests: append, verify, and tamper detection across attack modes."""
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crackq.core import AuditLog, AuditError, CrackQ  # noqa: E402


def _log(tmp_path):
    return AuditLog(str(tmp_path / "audit.jsonl"))


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.readlines()


def _write(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


# --------------------------------------------------------------------------- #
# empty / basic
# --------------------------------------------------------------------------- #
def test_empty_log_verifies_and_is_empty(tmp_path):
    log = _log(tmp_path)
    assert log.entries() == []
    assert log.verify() is True  # vacuously true


def test_first_record_chains_to_genesis(tmp_path):
    log = _log(tmp_path)
    rec = log.append("submit", "alice", job_id="1")
    assert rec["prev"] == AuditLog.GENESIS
    assert log.verify() is True


def test_chain_links_prev_to_this(tmp_path):
    log = _log(tmp_path)
    a = log.append("submit", "alice", job_id="1")
    b = log.append("start", "alice", job_id="1")
    assert b["prev"] == a["this"]
    assert log.verify() is True


def test_detail_is_preserved(tmp_path):
    log = _log(tmp_path)
    log.append("crack", "alice", job_id="1", tried=42)
    rec = log.entries()[0]
    assert rec["detail"] == {"job_id": "1", "tried": 42}


def test_append_returns_payload_with_this_hash(tmp_path):
    log = _log(tmp_path)
    rec = log.append("submit", "alice")
    assert len(rec["this"]) == 64  # sha256 hex


# --------------------------------------------------------------------------- #
# tamper detection — every mutation the chain is meant to catch
# --------------------------------------------------------------------------- #
def _seed(tmp_path):
    log = _log(tmp_path)
    log.append("submit", "alice", job_id="1")
    log.append("start", "alice", job_id="1")
    log.append("crack", "alice", job_id="1", tried=7)
    return log


def test_tamper_actor_field_detected(tmp_path):
    log = _seed(tmp_path)
    lines = _read(log.path)
    lines[0] = lines[0].replace('"alice"', '"mallory"')
    _write(log.path, lines)
    with pytest.raises(AuditError, match="digest mismatch|altered"):
        AuditLog(log.path).verify()


def test_tamper_detail_field_detected(tmp_path):
    log = _seed(tmp_path)
    lines = _read(log.path)
    lines[2] = lines[2].replace('"tried":7', '"tried":9999').replace('"tried": 7', '"tried": 9999')
    _write(log.path, lines)
    with pytest.raises(AuditError):
        AuditLog(log.path).verify()


def test_deleted_record_breaks_chain(tmp_path):
    log = _seed(tmp_path)
    lines = _read(log.path)
    del lines[1]  # remove the middle 'start' record
    _write(log.path, lines)
    with pytest.raises(AuditError, match="prev mismatch|broken"):
        AuditLog(log.path).verify()


def test_reordered_records_break_chain(tmp_path):
    log = _seed(tmp_path)
    lines = _read(log.path)
    lines[0], lines[1] = lines[1], lines[0]
    _write(log.path, lines)
    with pytest.raises(AuditError):
        AuditLog(log.path).verify()


def test_appended_forged_record_detected(tmp_path):
    log = _seed(tmp_path)
    forged = {
        "ts": 1.0, "user": "mallory", "action": "crack",
        "detail": {}, "prev": "0" * 64, "this": "f" * 64,
    }
    with open(log.path, "a", encoding="utf-8") as f:
        f.write(json.dumps(forged, sort_keys=True) + "\n")
    with pytest.raises(AuditError):
        AuditLog(log.path).verify()


def test_recomputed_this_but_wrong_prev_detected(tmp_path):
    """Attacker edits a record and recomputes its own `this` but the *next*
    record's prev no longer matches — the chain still catches it."""
    log = _seed(tmp_path)
    entries = log.entries()
    entries[1]["user"] = "mallory"
    # recompute this record's own digest so it looks internally consistent
    payload = {k: entries[1][k] for k in ("ts", "user", "action", "detail", "prev")}
    entries[1]["this"] = AuditLog._digest(entries[1]["prev"], payload)
    _write(log.path, [json.dumps(e, sort_keys=True) + "\n" for e in entries])
    with pytest.raises(AuditError):
        AuditLog(log.path).verify()


def test_untampered_log_still_verifies(tmp_path):
    log = _seed(tmp_path)
    assert AuditLog(log.path).verify() is True


def test_blank_lines_ignored(tmp_path):
    log = _seed(tmp_path)
    lines = _read(log.path)
    lines.insert(1, "\n")
    lines.append("   \n")
    _write(log.path, lines)
    assert AuditLog(log.path).verify() is True
    assert len(AuditLog(log.path).entries()) == 3


# --------------------------------------------------------------------------- #
# integration with the queue
# --------------------------------------------------------------------------- #
def test_full_run_audit_verifies(tmp_path):
    q = CrackQ(str(tmp_path / "a.jsonl"), wordlist=["secret"])
    q.submit(hashlib.sha256(b"secret").hexdigest(), "analyst")
    q.run_all()
    log = AuditLog(q.audit.path)
    assert log.verify() is True
    actions = [e["action"] for e in log.entries()]
    assert actions == ["submit", "start", "crack"]


def test_exhausted_run_logs_exhausted(tmp_path):
    q = CrackQ(str(tmp_path / "a.jsonl"), wordlist=["nope"])
    q.submit(hashlib.sha256(b"unfindable").hexdigest(), "analyst")
    q.run_all()
    actions = [e["action"] for e in AuditLog(q.audit.path).entries()]
    assert actions == ["submit", "start", "exhausted"]
