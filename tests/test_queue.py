"""Queue scheduling, priority, cancellation, and job-state tests."""
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crackq.core import CrackQ, Job, JobState  # noqa: E402


def _q(tmp_path, wordlist=None):
    return CrackQ(str(tmp_path / "audit.jsonl"),
                  wordlist=wordlist or ["alpha", "bravo", "charlie"])


# --------------------------------------------------------------------------- #
# scheduling / priority
# --------------------------------------------------------------------------- #
def test_priority_orders_lower_first(tmp_path):
    q = _q(tmp_path)
    q.submit(hashlib.md5(b"bravo").hexdigest(), "u", priority=9)
    hi = q.submit(hashlib.md5(b"alpha").hexdigest(), "u", priority=1)
    done = q.run_all()
    assert done[0].id == hi.id


def test_equal_priority_is_fifo(tmp_path):
    q = _q(tmp_path)
    first = q.submit(hashlib.md5(b"alpha").hexdigest(), "u", priority=5)
    second = q.submit(hashlib.md5(b"bravo").hexdigest(), "u", priority=5)
    done = q.run_all()
    assert [j.id for j in done] == [first.id, second.id]


def test_run_all_drains_everything(tmp_path):
    q = _q(tmp_path)
    for w in ("alpha", "bravo", "charlie"):
        q.submit(hashlib.md5(w.encode()).hexdigest(), "u")
    done = q.run_all()
    assert len(done) == 3
    assert all(j.state.is_terminal for j in done)


def test_run_all_on_empty_queue_returns_empty(tmp_path):
    assert _q(tmp_path).run_all() == []


def test_run_all_is_idempotent_after_drain(tmp_path):
    q = _q(tmp_path)
    q.submit(hashlib.md5(b"alpha").hexdigest(), "u")
    q.run_all()
    assert q.run_all() == []  # nothing left queued


def test_status_sorted_by_creation(tmp_path):
    q = _q(tmp_path)
    a = q.submit(hashlib.md5(b"alpha").hexdigest(), "u")
    b = q.submit(hashlib.md5(b"bravo").hexdigest(), "u")
    assert [j.id for j in q.status()] == [a.id, b.id]


# --------------------------------------------------------------------------- #
# submit validation
# --------------------------------------------------------------------------- #
def test_submit_rejects_empty_owner(tmp_path):
    q = _q(tmp_path)
    with pytest.raises(ValueError, match="owner"):
        q.submit(hashlib.md5(b"alpha").hexdigest(), "")


def test_submit_rejects_bad_digest(tmp_path):
    q = _q(tmp_path)
    with pytest.raises(ValueError, match="hexadecimal"):
        q.submit("not-a-hash", "u")


def test_submit_rejects_unknown_algorithm(tmp_path):
    q = _q(tmp_path)
    with pytest.raises(ValueError, match="unknown algorithm"):
        q.submit(hashlib.md5(b"alpha").hexdigest(), "u", algorithm="bcrypt")


def test_submit_rejects_bool_priority(tmp_path):
    q = _q(tmp_path)
    with pytest.raises(ValueError, match="priority"):
        q.submit(hashlib.md5(b"alpha").hexdigest(), "u", priority=True)


def test_submit_normalises_digest_case(tmp_path):
    q = _q(tmp_path)
    up = hashlib.md5(b"alpha").hexdigest().upper()
    job = q.submit(up, "u")
    assert job.hash == up.lower()


# --------------------------------------------------------------------------- #
# cancellation
# --------------------------------------------------------------------------- #
def test_cancel_queued_job_is_skipped(tmp_path):
    q = _q(tmp_path)
    keep = q.submit(hashlib.md5(b"alpha").hexdigest(), "u")
    drop = q.submit(hashlib.md5(b"bravo").hexdigest(), "u")
    q.cancel(drop.id)
    assert drop.state == JobState.CANCELLED
    done = q.run_all()
    assert [j.id for j in done] == [keep.id]  # cancelled job never ran


def test_cancel_unknown_job_raises(tmp_path):
    with pytest.raises(KeyError):
        _q(tmp_path).cancel("does-not-exist")


def test_cannot_cancel_finished_job(tmp_path):
    q = _q(tmp_path)
    job = q.submit(hashlib.md5(b"alpha").hexdigest(), "u")
    q.run_all()
    with pytest.raises(ValueError, match="cannot cancel"):
        q.cancel(job.id)


def test_cancel_writes_audit_record(tmp_path):
    q = _q(tmp_path)
    job = q.submit(hashlib.md5(b"alpha").hexdigest(), "u")
    q.cancel(job.id)
    actions = [e["action"] for e in q.audit.entries()]
    assert "cancel" in actions


# --------------------------------------------------------------------------- #
# get / metrics
# --------------------------------------------------------------------------- #
def test_get_returns_job(tmp_path):
    q = _q(tmp_path)
    job = q.submit(hashlib.md5(b"alpha").hexdigest(), "u")
    assert q.get(job.id) is job


def test_get_unknown_raises(tmp_path):
    with pytest.raises(KeyError):
        _q(tmp_path).get("nope")


def test_metrics_counts_states(tmp_path):
    q = _q(tmp_path)
    q.submit(hashlib.md5(b"alpha").hexdigest(), "u")          # cracked
    q.submit(hashlib.md5(b"not-present").hexdigest(), "u")     # exhausted
    cancelled = q.submit(hashlib.md5(b"bravo").hexdigest(), "u")
    q.cancel(cancelled.id)
    q.run_all()
    m = q.metrics()
    assert m["jobs"] == 3
    assert m["by_state"]["cracked"] == 1
    assert m["by_state"]["exhausted"] == 1
    assert m["by_state"]["cancelled"] == 1
    assert m["wordlist_size"] == 3


# --------------------------------------------------------------------------- #
# failure path
# --------------------------------------------------------------------------- #
def test_run_job_marks_failed_on_bad_algorithm(tmp_path):
    # Submit passes (valid md5-length hex), but we force a mismatched algorithm
    # so crack_hash raises ValueError inside run_job -> FAILED.
    q = _q(tmp_path)
    job = q.submit(hashlib.md5(b"alpha").hexdigest(), "u", algorithm="sha256")
    q.run_all()
    assert job.state == JobState.FAILED
    assert job.error


def test_failed_job_writes_fail_audit(tmp_path):
    q = _q(tmp_path)
    q.submit(hashlib.md5(b"alpha").hexdigest(), "u", algorithm="sha256")
    q.run_all()
    assert "fail" in [e["action"] for e in q.audit.entries()]


# --------------------------------------------------------------------------- #
# Job dataclass
# --------------------------------------------------------------------------- #
def test_job_to_dict_serialises_state_as_string():
    job = Job(hash="ab", owner="u")
    d = job.to_dict()
    assert d["state"] == "queued"
    assert isinstance(d["state"], str)


def test_job_ids_are_unique():
    ids = {Job(hash="ab", owner="u").id for _ in range(50)}
    assert len(ids) == 50


def test_load_wordlist_from_file(tmp_path):
    wl = tmp_path / "w.txt"
    wl.write_text("one\ntwo\nthree\n", encoding="utf-8")
    q = CrackQ(str(tmp_path / "a.jsonl"))
    n = q.load_wordlist(str(wl))
    assert n == 3 and q.wordlist == ["one", "two", "three"]


def test_load_wordlist_missing_file_raises(tmp_path):
    q = CrackQ(str(tmp_path / "a.jsonl"))
    with pytest.raises(FileNotFoundError):
        q.load_wordlist(str(tmp_path / "nope.txt"))
