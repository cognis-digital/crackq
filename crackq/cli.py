"""Command line interface for CRACKQ.

Subcommands:
  run      submit hashes and drain the queue against a wordlist (--metrics for totals)
  detect   report the likely algorithm(s) for one or more hashes
  audit    print or verify the tamper-evident audit log
  algos    list supported hash algorithms

Because the queue lives in memory, `run` accepts hashes inline so a single
invocation submits + runs + reports -- the common operator flow.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    CrackQ,
    AuditLog,
    AuditError,
    detect_algorithm,
    detect_algorithms,
    is_hex_digest,
    supported_algorithms,
)


def _print(obj, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, sort_keys=True))
        return
    # table
    if isinstance(obj, list):
        if not obj:
            print("(no rows)")
            return
        cols = list(obj[0].keys())
        widths = {c: len(c) for c in cols}
        for row in obj:
            for c in cols:
                widths[c] = max(widths[c], len(str(row.get(c, ""))))
        line = "  ".join(c.ljust(widths[c]) for c in cols)
        print(line)
        print("  ".join("-" * widths[c] for c in cols))
        for row in obj:
            print("  ".join(str(row.get(c, "")).ljust(widths[c]) for c in cols))
    else:
        for k, v in obj.items():
            print(f"{k}: {v}")


def _load_words(args) -> List[str]:
    if args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8", errors="replace") as f:
            return [ln.rstrip("\n\r") for ln in f]
    if args.words:
        return list(args.words)
    return []


def _gather_hashes(args) -> List[str]:
    hashes: List[str] = list(args.hash or [])
    if getattr(args, "hashfile", None):
        with open(args.hashfile, "r", encoding="utf-8") as f:
            hashes += [ln.strip() for ln in f if ln.strip()]
    return hashes


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="Self-hosted password cracking queue.")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=("table", "json"), default="table")
    p.add_argument("--audit-log", default=os.path.join(tempfile.gettempdir(), "crackq_audit.jsonl"))
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="submit hashes and drain the queue")
    r.add_argument("--hash", action="append", help="hash digest (repeatable)")
    r.add_argument("--hashfile", help="file of hashes, one per line")
    r.add_argument("--owner", default="operator")
    r.add_argument("--algorithm", choices=supported_algorithms(), default=None)
    r.add_argument("--wordlist", help="path to a wordlist file")
    r.add_argument("--words", nargs="*", help="inline candidate words")
    r.add_argument("--no-rules", action="store_true", help="disable rule mangling")
    r.add_argument("--priority", type=int, default=5)
    r.add_argument("--metrics", action="store_true",
                   help="print aggregate queue metrics instead of the per-job table")

    a = sub.add_parser("audit", help="print or verify the audit log")
    a.add_argument("--verify", action="store_true")

    d = sub.add_parser("detect", help="report the likely algorithm(s) for a hash")
    d.add_argument("--hash", action="append", required=True,
                   help="hash digest to identify (repeatable)")

    sub.add_parser("algos", help="list supported algorithms")
    return p


def _cmd_run(args) -> int:
    hashes = _gather_hashes(args)
    if not hashes:
        print("error: no hashes provided (--hash/--hashfile)", file=sys.stderr)
        return 2
    words = _load_words(args)
    if not words:
        print("error: no wordlist provided (--wordlist/--words)", file=sys.stderr)
        return 2
    q = CrackQ(args.audit_log, wordlist=words)
    for h in hashes:
        q.submit(h, args.owner, algorithm=args.algorithm,
                 rules=not args.no_rules, priority=args.priority)
    q.run_all()
    rows = [j.to_dict() for j in q.status()]
    if args.metrics:
        _print(q.metrics(), args.format)
    else:
        _print(rows, args.format)
    # non-zero if any job failed (bad algo / error), 0 if all ran (even if uncracked)
    return 1 if any(j["state"] == "failed" for j in rows) else 0


def _cmd_audit(args) -> int:
    log = AuditLog(args.audit_log)
    if args.verify:
        try:
            log.verify()
        except AuditError as exc:
            _print({"verified": False, "error": str(exc)}, args.format)
            return 1
        _print({"verified": True, "records": len(log.entries())}, args.format)
        return 0
    _print(log.entries(), args.format)
    return 0


def _cmd_detect(args) -> int:
    rows = []
    for h in args.hash:
        h = h.strip()
        rows.append({
            "hash": h,
            "valid_hex": is_hex_digest(h),
            "likely": detect_algorithm(h) or "-",
            "candidates": ",".join(detect_algorithms(h)) or "-",
        })
    _print(rows, args.format)
    # non-zero if none of the supplied hashes could be identified
    return 0 if any(r["likely"] != "-" for r in rows) else 1


def _cmd_algos(args) -> int:
    _print([{"algorithm": a} for a in supported_algorithms()], args.format)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "run":
            return _cmd_run(args)
        if args.cmd == "audit":
            return _cmd_audit(args)
        if args.cmd == "detect":
            return _cmd_detect(args)
        if args.cmd == "algos":
            return _cmd_algos(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
