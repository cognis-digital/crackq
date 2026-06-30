"""Shared helpers for the runnable demo scenarios.

Everything here is OFFLINE and uses the REAL crackq API (crackq.core): no
network, no external cracking engine, no shelling out. The "cracking" is honest
dictionary work over a small bundled wordlist -- the same primitive a real queue
would hand to ``hashcat -a 0``, just sized to run in well under a second.

Authorized / defensive use only: every hash in these demos is one we generated
ourselves from a known plaintext, exactly as you would test hashes you own or
are explicitly authorized to audit.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile

# allow `python demos/NN_name.py` from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crackq.core import CrackQ, AuditLog  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A tiny candidate dictionary. Real engagements point --wordlist at rockyou.txt
# or a custom list; this stays small so the demos finish instantly and offline.
WORDLIST = [
    "password", "letmein", "hunter", "admin", "welcome",
    "dragon", "qwerty", "monkey", "summer", "winter",
    "spring", "autumn", "secret", "shadow", "trustno",
]


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def sha512(s: str) -> str:
    return hashlib.sha512(s.encode()).hexdigest()


def fresh_queue(wordlist=None) -> CrackQ:
    """A CrackQ with a throwaway audit log and the bundled demo wordlist."""
    audit = os.path.join(tempfile.mkdtemp(prefix="crackq_demo_"), "audit.jsonl")
    return CrackQ(audit, wordlist=list(wordlist or WORDLIST))


def fresh_audit_path() -> str:
    return os.path.join(tempfile.mkdtemp(prefix="crackq_demo_"), "audit.jsonl")


def rule(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def note(msg: str) -> None:
    print(f"\n{msg}")


__all__ = [
    "CrackQ", "AuditLog", "WORDLIST", "REPO_ROOT",
    "md5", "sha1", "sha256", "sha512",
    "fresh_queue", "fresh_audit_path", "rule", "note",
]
