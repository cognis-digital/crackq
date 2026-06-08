"""CRACKQ - Self-hosted password cracking queue.

A multi-user job queue for hashcat-style cracking work with a tamper-evident
audit log. Pure standard library, zero install. The queue, scheduler, audit
chain and a real (educational) dictionary-cracking engine are all implemented
here; jobs run against a wordlist using the hash algorithm requested.
"""
from .core import (
    CrackQ,
    Job,
    JobState,
    AuditLog,
    AuditError,
    crack_hash,
    supported_algorithms,
)

TOOL_NAME = "crackq"
TOOL_VERSION = "1.0.0"

__all__ = [
    "CrackQ",
    "Job",
    "JobState",
    "AuditLog",
    "AuditError",
    "crack_hash",
    "supported_algorithms",
    "TOOL_NAME",
    "TOOL_VERSION",
]
