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
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Iterable, Iterator, List, Optional

_ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

# Hex digest length -> likely algorithm, used to auto-detect.
_LEN_HINT = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})


def supported_algorithms() -> List[str]:
    return sorted(_ALGOS)


def detect_algorithm(digest: str) -> Optional[str]:
    """Guess the algorithm from a hex digest length."""
    return _LEN_HINT.get(len(digest.strip()))


def _candidates(word: str, rules: bool) -> Iterator[str]:
    """Yield the base word and, if rules enabled, common mangles."""
    yield word
    if not rules:
        return
    yield word.capitalize()
    yield word.upper()
    yield word[::-1]
    yield word.translate(_LEET)
    for d in ("1", "12", "123", "!", "2024", "2025"):
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
    """
    if not isinstance(digest, str) or not digest.strip():
        raise ValueError("digest must be a non-empty string")
    digest = digest.strip().lower()
    if not all(c in "0123456789abcdef" for c in digest):
        raise ValueError(
            f"digest contains non-hex characters: {digest!r}"
        )
    if max_candidates is not None and max_candidates < 1:
        raise ValueError(
            f"max_candidates must be a positive integer, got {max_candidates}"
        )
    algo = (algorithm or detect_algorithm(digest) or "").lower()
    if algo not in _ALGOS:
        raise ValueError(
            f"unknown or undetectable algorithm for hash (len={len(digest)}); "
            f"specify one of {supported_algorithms()}"
        )
    h = _ALGOS[algo]
    tried = 0
    start = time.time()
    for word in wordlist:
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
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditError(
                        f"audit log line {lineno} is not valid JSON: {exc}"
                    ) from exc
                if "this" not in rec:
                    raise AuditError(
                        f"audit log line {lineno} missing 'this' field"
                    )
                last = rec["this"]
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
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise AuditError(
                        f"audit log line {lineno} is not valid JSON: {exc}"
                    ) from exc
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
        if not os.path.exists(path):
            raise FileNotFoundError(f"wordlist not found: {path!r}")
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            self.wordlist = [ln.rstrip("\n\r") for ln in f if ln.strip()]
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
            raise ValueError(
                f"priority must be an integer, got {type(priority).__name__}"
            )
        if algorithm is not None and algorithm not in _ALGOS:
            raise ValueError(
                f"unknown algorithm {algorithm!r}; "
                f"choose one of {supported_algorithms()}"
            )
        job = Job(
            hash=digest.strip().lower(),
            owner=owner.strip(),
            algorithm=algorithm,
            rules=rules,
            priority=priority,
        )
        self.jobs[job.id] = job
        self.audit.append(
            "submit", owner, job_id=job.id, hash=job.hash,
            algorithm=algorithm, priority=priority,
        )
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
