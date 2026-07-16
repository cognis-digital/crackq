"""Command line interface for CRACKQ.

Subcommands:
  run      submit hashes and drain the queue against a wordlist
           (``--metrics`` for totals, ``--report`` for a strength rollup)
  scan     single-shot crack of one hash (the uniform ``scan`` verb)
  detect   report the likely algorithm(s) for one or more hashes
  analyze  score recovered plaintexts for strength/composition
           (``--report`` rolls a set up into a policy summary)
  audit    print or verify the tamper-evident audit log
  algos    list supported hash algorithms

Because the queue lives in memory, ``run`` accepts hashes inline so a single
invocation submits + runs + reports -- the common operator flow. Every
subcommand honours the global ``--format {table,json,csv}`` switch.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import tempfile
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .analyze import analyze_batch, analyze_password, crack_report
from .core import (
    CrackQ,
    AuditLog,
    AuditError,
    detect_algorithm,
    detect_algorithms,
    is_hex_digest,
    scan as scan_hash,
    supported_algorithms,
)


def _flatten(value) -> str:
    """Collapse lists/dicts to a compact string for tabular/CSV output."""
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    if isinstance(value, dict):
        return ";".join(f"{k}={v}" for k, v in value.items())
    return str(value)


def _csv(obj) -> str:
    """Render a dict or list-of-dicts as CSV text (stable column order)."""
    buf = io.StringIO()
    if isinstance(obj, list):
        if not obj:
            return ""
        cols = list(obj[0].keys())
        w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for row in obj:
            w.writerow({c: _flatten(row.get(c, "")) for c in cols})
    else:
        w = csv.writer(buf)
        w.writerow(["key", "value"])
        for k, v in obj.items():
            w.writerow([k, _flatten(v)])
    return buf.getvalue().rstrip("\r\n")


def _print(obj, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2, sort_keys=True))
        return
    if fmt == "csv":
        print(_csv(obj))
        return
    # table
    if isinstance(obj, list):
        if not obj:
            print("(no rows)")
            return
        cols = list(obj[0].keys())
        widths = {c: len(c) for c in cols}
        rows = [{c: _flatten(r.get(c, "")) for c in cols} for r in obj]
        for row in rows:
            for c in cols:
                widths[c] = max(widths[c], len(row[c]))
        print("  ".join(c.ljust(widths[c]) for c in cols))
        print("  ".join("-" * widths[c] for c in cols))
        for row in rows:
            print("  ".join(row[c].ljust(widths[c]) for c in cols))
    else:
        for k, v in obj.items():
            print(f"{k}: {_flatten(v)}")


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


def _gather_passwords(args) -> List[str]:
    words: List[str] = list(args.password or [])
    if getattr(args, "pwfile", None):
        with open(args.pwfile, "r", encoding="utf-8", errors="replace") as f:
            words += [ln.rstrip("\n\r") for ln in f if ln.rstrip("\n\r")]
    return words


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="Self-hosted password cracking queue.")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=("table", "json", "csv"), default="table")
    p.add_argument("--audit-log", default=os.path.join(tempfile.gettempdir(), "crackq_audit.jsonl"))

    # Shared parent so --format / --audit-log are also accepted *after* the
    # subcommand (e.g. ``crackq run ... --format json``). SUPPRESS defaults let
    # a value given before the subcommand survive when not repeated after it.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=("table", "json", "csv"),
                        default=argparse.SUPPRESS)
    common.add_argument("--audit-log", default=argparse.SUPPRESS)

    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", parents=[common], help="submit hashes and drain the queue")
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
    r.add_argument("--report", action="store_true",
                   help="print a password strength/composition report over cracked jobs")

    s = sub.add_parser("scan", parents=[common], help="single-shot crack of one hash")
    s.add_argument("target", help="hash digest to crack")
    s.add_argument("--algorithm", choices=supported_algorithms(), default=None)
    s.add_argument("--wordlist", help="path to a wordlist file")
    s.add_argument("--words", nargs="*", help="inline candidate words")
    s.add_argument("--no-rules", action="store_true", help="disable rule mangling")
    s.add_argument("--max-candidates", type=int, default=None,
                   help="cap the number of candidates tried")

    a = sub.add_parser("audit", parents=[common], help="print or verify the audit log")
    a.add_argument("--verify", action="store_true")

    d = sub.add_parser("detect", parents=[common], help="report the likely algorithm(s) for a hash")
    d.add_argument("--hash", action="append", required=True,
                   help="hash digest to identify (repeatable)")

    an = sub.add_parser("analyze", parents=[common], help="score recovered plaintext passwords")
    an.add_argument("--password", action="append", help="plaintext password (repeatable)")
    an.add_argument("--pwfile", help="file of plaintext passwords, one per line")
    an.add_argument("--report", action="store_true",
                    help="roll the set up into an aggregate policy report")
    an.add_argument("--top-weak", type=int, default=5,
                    help="how many weakest passwords to list in the report")

    sub.add_parser("algos", parents=[common], help="list supported algorithms")
    sub.add_parser("mcp", parents=[common], help="run the MCP server (needs the 'mcp' extra)")
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
    elif args.report:
        _print(crack_report(rows), args.format)
    else:
        _print(rows, args.format)
    # non-zero if any job failed (bad algo / error), 0 if all ran (even if uncracked)
    return 1 if any(j["state"] == "failed" for j in rows) else 0


def _cmd_scan(args) -> int:
    words = _load_words(args)
    res = scan_hash(
        args.target,
        wordlist=args.wordlist or words,
        algorithm=args.algorithm,
        rules=not args.no_rules,
        max_candidates=args.max_candidates,
    )
    _print(res, args.format)
    # 0 when cracked, 1 when the search was exhausted without a hit (gateable)
    return 0 if res["cracked"] else 1


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


def _cmd_analyze(args) -> int:
    passwords = _gather_passwords(args)
    if not passwords:
        print("error: no passwords provided (--password/--pwfile)", file=sys.stderr)
        return 2
    if args.report:
        _print(analyze_batch(passwords, top_weak=args.top_weak), args.format)
    else:
        _print([analyze_password(p) for p in passwords], args.format)
    return 0


def _cmd_algos(args) -> int:
    _print([{"algorithm": a} for a in supported_algorithms()], args.format)
    return 0


def _cmd_mcp(args) -> int:
    """Launch the MCP server so AI agents can drive crackq's ``scan`` verb."""
    try:
        from .mcp_server import run_mcp_server
    except Exception as exc:  # pragma: no cover - optional integration
        print(
            "error: MCP support is not installed. Install the extra with "
            "`pip install \"cognis-crackq[mcp]\"`.\n"
            f"(import failed: {exc})",
            file=sys.stderr,
        )
        return 1
    run_mcp_server()  # pragma: no cover - blocks serving over stdio
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "run":
            return _cmd_run(args)
        if args.cmd == "scan":
            return _cmd_scan(args)
        if args.cmd == "audit":
            return _cmd_audit(args)
        if args.cmd == "detect":
            return _cmd_detect(args)
        if args.cmd == "analyze":
            return _cmd_analyze(args)
        if args.cmd == "algos":
            return _cmd_algos(args)
        if args.cmd == "mcp":
            return _cmd_mcp(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
