"""Core engine for CRACKQ.

Implements:
  * crack_hash()      - a real dictionary attack against a wordlist using
                        hashlib algorithms (md5/sha1/sha256/sha512), with
                        optional rule mangling (append digits, capitalize,
                        leet, reverse).
  * Job / JobState    - queued work items with priority + ownership.
  * AuditLog          - a hash-chained, tamper-evident JSONL audit log.
  * CrackQ            - multi-user priority queue + scheduler that runs jobs
                        and writes every state transition to the audit log.

Nothing here talks to the network. The "cracking" is honest dictionary work
over an attacker-supplied wordlist, the same primitive a real queue would
hand to hashcat -a 0.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Iterable, Iterator, List, Optional

TOOL_NAME = "crackq"


def _read_version() -> str:
    """Read the shipped VERSION file; fall back to a sane default."""
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, os.pardir, "VERSION"),
        os.path.join(here, "VERSION"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                v = f.read().strip()
                if v:
                    return v
        except OSError:
            continue
    return "0.1.1"


TOOL_VERSION = _read_version()

_ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

# Hex digest length -> candidate algorithm(s), used to auto-detect. Some lengths
# are ambiguous (e.g. 56 hex chars = sha224); we return the first/most common.
_LEN_HINT = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}

# Every algorithm that can produce a digest of a given hex length (for detect_all).
_LEN_ALGOS: Dict[int, List[str]] = {}
for _name, _fn in _ALGOS.items():
    _LEN_ALGOS.setdefault(_fn().digest_size * 2, []).append(_name)

_HEX_RE = re.compile(r"^[0-9a-f]+$")

_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})


def supported_algorithms() -> List[str]:
    return sorted(_ALGOS)


def is_hex_digest(digest: str) -> bool:
    """True if the string is a plausible lowercase hex digest (even length)."""
    d = digest.strip().lower()
    return bool(d) and len(d) % 2 == 0 and bool(_HEX_RE.match(d))


def detect_algorithm(digest: str) -> Optional[str]:
    """Guess the most likely algorithm from a hex digest length.

    Returns None if the string is not a valid hex digest or the length does
    not correspond to any supported algorithm.
    """
    d = digest.strip().lower()
    if not is_hex_digest(d):
        return None
    return _LEN_HINT.get(len(d))


def detect_algorithms(digest: str) -> List[str]:
    """Return *all* supported algorithms whose output matches this length.

    A digest length can be ambiguous (e.g. 64 hex chars is sha256, but future
    algorithms could collide); this exposes every candidate so a caller can try
    each one rather than trusting a single guess.
    """
    d = digest.strip().lower()
    if not is_hex_digest(d):
        return []
    return sorted(_LEN_ALGOS.get(len(d), []))


# Suffixes appended by the append/capitalize+append rules.
_SUFFIXES = ("1", "12", "123", "!", "!!", "01", "2023", "2024", "2025")


def _candidates(word: str, rules: bool) -> Iterator[str]:
    """Yield the base word and, if rules enabled, common mangles.

    Duplicates are *not* de-duplicated here (that would cost memory on large
    lists); ``candidates_tried`` therefore counts raw attempts, which is the
    honest accounting a real engine reports.
    """
    yield word
    if not rules:
        return
    yield word.capitalize()
    yield word.upper()
    yield word[::-1]
    yield word.translate(_LEET)
    yield word.capitalize().translate(_LEET)
    for d in _SUFFIXES:
        yield word + d
        yield word.capitalize() + d


def crack_hash(
    digest: str,
    wordlist: Iterable[str],
    algorithm: Optional[str] = None,
    rules: bool = True,
    max_candidates: Optional[int] = None,
) -> Dict[str, object]:
    """Run a dictionary attack against a single hash.

    Returns a dict describing the outcome (cracked plaintext or not) plus the
    number of candidates tried -- the same accounting a real queue reports.

    Raises ``ValueError`` if the digest is not valid hex, the algorithm is
    unknown/undetectable, the digest length does not match the chosen
    algorithm, or ``max_candidates`` is not a positive integer.
    """
    if not isinstance(digest, str):
        raise ValueError(f"digest must be a string, got {type(digest).__name__}")
    digest = digest.strip().lower()
    if not digest:
        raise ValueError("digest is empty")
    if not is_hex_digest(digest):
        raise ValueError(
            f"digest is not valid hexadecimal: {digest[:16]!r}"
            + ("..." if len(digest) > 16 else "")
        )
    if max_candidates is not None and (not isinstance(max_candidates, int) or max_candidates <= 0):
        raise ValueError("max_candidates must be a positive integer or None")

    algo = (algorithm or detect_algorithm(digest) or "").lower()
    if algo not in _ALGOS:
        raise ValueError(
            f"unknown or undetectable algorithm for hash (len={len(digest)}); "
            f"specify one of {supported_algorithms()}"
        )
    expected_len = _ALGOS[algo]().digest_size * 2
    if len(digest) != expected_len:
        raise ValueError(
            f"digest length {len(digest)} does not match {algo} "
            f"(expected {expected_len} hex chars)"
        )

    h = _ALGOS[algo]
    tried = 0
    start = time.time()
    for word in wordlist:
        if not isinstance(word, str):
            raise ValueError(f"wordlist entries must be strings, got {type(word).__name__}")
        word = word.rstrip("\n\r")
        if not word:
            continue
        for cand in _candidates(word, rules):
            tried += 1
            if h(cand.encode("utf-8", "surrogatepass")).hexdigest() == digest:
                return {
                    "hash": digest,
                    "algorithm": algo,
                    "cracked": True,
                    "plaintext": cand,
                    "candidates_tried": tried,
                    "elapsed_sec": round(time.time() - start, 6),
                }
            if max_candidates is not None and tried >= max_candidates:
                return _miss(digest, algo, tried, start)
    return _miss(digest, algo, tried, start)


def _miss(digest: str, algo: str, tried: int, start: float) -> Dict[str, object]:
    return {
        "hash": digest,
        "algorithm": algo,
        "cracked": False,
        "plaintext": None,
        "candidates_tried": tried,
        "elapsed_sec": round(time.time() - start, 6),
    }


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    CRACKED = "cracked"
    EXHAUSTED = "exhausted"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        """True once the job will not transition further."""
        return self in (
            JobState.CRACKED,
            JobState.EXHAUSTED,
            JobState.FAILED,
            JobState.CANCELLED,
        )


@dataclass
class Job:
    hash: str
    owner: str
    algorithm: Optional[str] = None
    rules: bool = True
    priority: int = 5  # lower = sooner
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    state: JobState = JobState.QUEUED
    plaintext: Optional[str] = None
    candidates_tried: int = 0
    elapsed_sec: float = 0.0
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, object]:
        d = asdict(self)
        d["state"] = self.state.value
        return d


class AuditError(Exception):
    """Raised when the audit chain fails verification."""


class AuditLog:
    """Append-only, hash-chained audit log (JSONL).

    Each record carries the sha256 of the previous record, so any edit,
    deletion or reordering of history is detectable via verify().
    """

    GENESIS = "0" * 64

    def __init__(self, path: str):
        self.path = path

    def _last_hash(self) -> str:
        last = self.GENESIS
        if not os.path.exists(self.path):
            return last
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = json.loads(line)["this"]
        return last

    @staticmethod
    def _digest(prev: str, payload: Dict[str, object]) -> str:
        blob = prev + json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def append(self, action: str, user: str, **detail) -> Dict[str, object]:
        prev = self._last_hash()
        payload = {
            "ts": round(time.time(), 6),
            "user": user,
            "action": action,
            "detail": detail,
            "prev": prev,
        }
        payload["this"] = self._digest(prev, payload)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, sort_keys=True) + "\n")
        return payload

    def entries(self) -> List[Dict[str, object]]:
        out: List[Dict[str, object]] = []
        if not os.path.exists(self.path):
            return out
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def verify(self) -> bool:
        """Walk the chain; raise AuditError on the first tampered record."""
        prev = self.GENESIS
        for i, rec in enumerate(self.entries()):
            if rec.get("prev") != prev:
                raise AuditError(f"record {i}: prev mismatch (chain broken)")
            payload = {k: rec[k] for k in ("ts", "user", "action", "detail", "prev")}
            expect = self._digest(prev, payload)
            if expect != rec.get("this"):
                raise AuditError(f"record {i}: digest mismatch (record altered)")
            prev = rec["this"]
        return True


class CrackQ:
    """Multi-user priority queue + scheduler over crack_hash."""

    def __init__(self, audit_path: str, wordlist: Optional[List[str]] = None):
        self.jobs: Dict[str, Job] = {}
        self.wordlist: List[str] = list(wordlist or [])
        self.audit = AuditLog(audit_path)
        self._seq = itertools.count()

    def load_wordlist(self, path: str) -> int:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            self.wordlist = [ln.rstrip("\n\r") for ln in f]
        return len(self.wordlist)

    def submit(
        self,
        digest: str,
        owner: str,
        algorithm: Optional[str] = None,
        rules: bool = True,
        priority: int = 5,
    ) -> Job:
        if not isinstance(owner, str) or not owner.strip():
            raise ValueError("owner must be a non-empty string")
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise ValueError("priority must be an integer")
        if algorithm is not None and algorithm.lower() not in _ALGOS:
            raise ValueError(
                f"unknown algorithm {algorithm!r}; "
                f"choose from {supported_algorithms()}"
            )
        digest = (digest or "").strip().lower()
        if not is_hex_digest(digest):
            raise ValueError(f"digest is not valid hexadecimal: {digest[:16]!r}")
        job = Job(
            hash=digest,
            owner=owner,
            algorithm=algorithm.lower() if algorithm else None,
            rules=rules,
            priority=priority,
        )
        self.jobs[job.id] = job
        self.audit.append(
            "submit", owner, job_id=job.id, hash=job.hash,
            algorithm=algorithm, priority=priority,
        )
        return job

    def cancel(self, job_id: str) -> Job:
        """Cancel a QUEUED job so the scheduler skips it.

        Raises KeyError for an unknown id and ValueError if the job has already
        started or finished (only queued work can be cancelled).
        """
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(f"no such job: {job_id}")
        if job.state != JobState.QUEUED:
            raise ValueError(
                f"cannot cancel job {job_id} in state {job.state.value}"
            )
        job.state = JobState.CANCELLED
        self.audit.append("cancel", job.owner, job_id=job.id)
        return job

    def get(self, job_id: str) -> Job:
        """Fetch a job by id, raising KeyError if it does not exist."""
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(f"no such job: {job_id}")
        return job

    def _next(self) -> Optional[Job]:
        pending = [j for j in self.jobs.values() if j.state == JobState.QUEUED]
        if not pending:
            return None
        pending.sort(key=lambda j: (j.priority, j.created_at))
        return pending[0]

    def run_job(self, job: Job) -> Job:
        job.state = JobState.RUNNING
        self.audit.append("start", job.owner, job_id=job.id)
        try:
            res = crack_hash(
                job.hash, self.wordlist, job.algorithm, job.rules
            )
        except ValueError as exc:
            job.state = JobState.FAILED
            job.error = str(exc)
            self.audit.append("fail", job.owner, job_id=job.id, error=str(exc))
            return job
        job.candidates_tried = int(res["candidates_tried"])
        job.elapsed_sec = float(res["elapsed_sec"])
        job.algorithm = str(res["algorithm"])
        if res["cracked"]:
            job.state = JobState.CRACKED
            job.plaintext = str(res["plaintext"])
            self.audit.append(
                "crack", job.owner, job_id=job.id, tried=job.candidates_tried
            )
        else:
            job.state = JobState.EXHAUSTED
            self.audit.append(
                "exhausted", job.owner, job_id=job.id, tried=job.candidates_tried
            )
        return job

    def run_all(self) -> List[Job]:
        """Drain the queue in priority order, return processed jobs."""
        done: List[Job] = []
        while True:
            job = self._next()
            if job is None:
                break
            done.append(self.run_job(job))
        return done

    def status(self) -> List[Job]:
        return sorted(self.jobs.values(), key=lambda j: j.created_at)

    def metrics(self) -> Dict[str, object]:
        """Aggregate queue accounting for capacity planning / dashboards."""
        jobs = list(self.jobs.values())
        by_state: Dict[str, int] = {s.value: 0 for s in JobState}
        for j in jobs:
            by_state[j.state.value] += 1
        total_tried = sum(j.candidates_tried for j in jobs)
        total_elapsed = round(sum(j.elapsed_sec for j in jobs), 6)
        return {
            "jobs": len(jobs),
            "by_state": by_state,
            "candidates_tried": total_tried,
            "elapsed_sec": total_elapsed,
            "cracked": by_state[JobState.CRACKED.value],
            "wordlist_size": len(self.wordlist),
        }


def scan(target: str, **kwargs) -> Dict[str, object]:
    """Uniform single-shot entry point (the Cognis Neural Suite ``scan`` verb).

    ``target`` is a hex digest; ``wordlist`` (list or path) and the usual
    ``crack_hash`` keyword arguments are accepted. This is the function the MCP
    server exposes so crackq presents the same ``scan(target)`` shape as the
    rest of the suite.
    """
    wordlist = kwargs.pop("wordlist", None)
    if isinstance(wordlist, str):
        with open(wordlist, "r", encoding="utf-8", errors="replace") as f:
            wordlist = [ln.rstrip("\n\r") for ln in f]
    return crack_hash(target, wordlist or [], **kwargs)


__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "supported_algorithms",
    "is_hex_digest",
    "detect_algorithm",
    "detect_algorithms",
    "crack_hash",
    "scan",
    "JobState",
    "Job",
    "AuditError",
    "AuditLog",
    "CrackQ",
]
