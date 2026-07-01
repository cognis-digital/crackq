"""Scenario 18 - CLI metrics: a one-line queue rollup for CI and cron.

`crackq run --metrics --format json` runs the batch and emits the aggregate
snapshot instead of the per-job table -- ideal for a cron job that appends a
throughput line to a dashboard feed. This demo drives the real CLI in-process.
Authorized / defensive use only.
"""
import io
import json
import os
import tempfile
from contextlib import redirect_stdout

from _common import md5, sha256, WORDLIST, rule, note
from crackq.cli import main as cli_main


def main() -> None:
    rule("CLI METRICS  -  aggregate queue rollup for CI / cron")

    work = tempfile.mkdtemp(prefix="crackq_metrics_")
    hashfile = os.path.join(work, "hashes.txt")
    wordfile = os.path.join(work, "words.txt")
    audit = os.path.join(work, "audit.jsonl")
    with open(hashfile, "w", encoding="utf-8") as f:
        f.write(md5("welcome1") + "\n")           # cracks (append rule)
        f.write(sha256("monkey") + "\n")          # cracks (base word)
        f.write(sha256("Zx#no_match_here") + "\n")  # exhausts
    with open(wordfile, "w", encoding="utf-8") as f:
        f.write("\n".join(WORDLIST) + "\n")

    note("Equivalent shell command:")
    print("   crackq --format json run --metrics \\")
    print("          --hashfile hashes.txt --wordlist words.txt")

    argv = [
        "--format", "json", "--audit-log", audit,
        "run", "--metrics", "--hashfile", hashfile, "--wordlist", wordfile,
    ]
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli_main(argv)
    m = json.loads(buf.getvalue())

    note(f"Exit code {rc}; metrics snapshot:")
    print(f"   jobs             : {m['jobs']}")
    print(f"   cracked          : {m['cracked']}")
    print(f"   candidates_tried : {m['candidates_tried']}")
    print(f"   elapsed_sec      : {m['elapsed_sec']}")
    print(f"   by_state         : "
          + ", ".join(f"{k}={v}" for k, v in m["by_state"].items() if v))

    assert rc == 0 and m["jobs"] == 3 and m["cracked"] == 2
    note("One JSON line per run is all a dashboard needs to plot throughput and "
         "crack-rate over time.")


if __name__ == "__main__":
    main()
