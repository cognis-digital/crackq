"""Scenario 5 - automation engineers wiring crackq into a pipeline.

CrackQ is scriptable: the same engine behind the queue is one CLI command away,
and its JSON output drops straight into the rest of your toolchain. This demo
drives the real ``crackq`` CLI in-process (no subprocess, no network), writes a
hashfile + wordlist to a temp dir, runs the queue, and parses the JSON the way a
CI job or downstream forwarder would.
"""
import io
import json
import os
import tempfile
from contextlib import redirect_stdout

from _common import md5, sha256, WORDLIST, rule, note
from crackq.cli import main as cli_main


def main() -> None:
    rule("CLI PIPELINE  -  the queue as a scriptable, JSON-emitting command")

    work = tempfile.mkdtemp(prefix="crackq_cli_")
    hashfile = os.path.join(work, "hashes.txt")
    wordfile = os.path.join(work, "words.txt")
    audit = os.path.join(work, "audit.jsonl")

    with open(hashfile, "w", encoding="utf-8") as f:
        f.write(md5("welcome1") + "\n")      # crackable (append-'1' rule)
        f.write(sha256("monkey") + "\n")     # crackable (base word)
        f.write(sha256("no_such_secret") + "\n")  # exhausted
    with open(wordfile, "w", encoding="utf-8") as f:
        f.write("\n".join(WORDLIST) + "\n")

    note("Equivalent shell command:")
    print("   crackq --format json --audit-log audit.jsonl \\")
    print("          run --hashfile hashes.txt --wordlist words.txt --owner ci")

    argv = [
        "--format", "json", "--audit-log", audit,
        "run", "--hashfile", hashfile, "--wordlist", wordfile, "--owner", "ci",
    ]
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli_main(argv)

    rows = json.loads(buf.getvalue())
    note(f"Exit code: {rc}  (0 = every job ran; 1 = a job failed/bad algo)")
    print(f"   {'state':<10}{'algorithm':<10}{'plaintext':<14}candidates")
    for r in rows:
        pt = r["plaintext"] if r["plaintext"] is not None else "-"
        print(f"   {r['state']:<10}{r['algorithm']:<10}{pt:<14}{r['candidates_tried']}")

    cracked = [r["plaintext"] for r in rows if r["state"] == "cracked"]
    note(f"A downstream job can now act on the {len(cracked)} recovered credential(s): "
         + ", ".join(repr(p) for p in cracked))
    print("Pipe `--format json` into jq, a SIEM forwarder, or `crackq-emit` to "
          "turn results into STIX/Sigma/Slack findings.")
    assert rc == 0, "all jobs should run cleanly"


if __name__ == "__main__":
    main()
