"""Scenario 15 - real wordlists: point the queue at a file on disk.

In the field you crack against a wordlist file (a curated list, or rockyou.txt).
This demo writes a wordlist to a temp file, loads it with CrackQ.load_wordlist(),
and cracks a batch -- exactly how you would wire in a real list, just sized to
run instantly and offline. Authorized / defensive use only.
"""
import os
import tempfile

from _common import fresh_audit_path, sha256, rule, note
from crackq.core import CrackQ


def main() -> None:
    rule("WORDLIST FROM FILE  -  load_wordlist() over a list on disk")

    work = tempfile.mkdtemp(prefix="crackq_wl_")
    wordfile = os.path.join(work, "custom.txt")
    words = ["orbit", "falcon", "tundra", "cascade", "monsoon", "quartz"]
    with open(wordfile, "w", encoding="utf-8") as f:
        f.write("\n".join(words) + "\n")
    note(f"Wrote a {len(words)}-word list to {os.path.basename(wordfile)}")

    q = CrackQ(fresh_audit_path())
    n = q.load_wordlist(wordfile)
    print(f"   load_wordlist() -> {n} words")

    note("Crack a batch drawn from that list (one miss on purpose):")
    targets = {
        "acct_1": sha256("falcon"),
        "acct_2": sha256("Cascade"),      # capitalize rule
        "acct_3": sha256("quartz2025"),   # append '2025' rule
        "acct_4": sha256("not_in_file"),  # exhausts
    }
    for owner, digest in targets.items():
        q.submit(digest, owner=owner, rules=True)
    q.run_all()

    for acct, job in zip(targets, q.status()):
        verdict = job.plaintext if job.state.value == "cracked" else f"<{job.state.value}>"
        print(f"   {acct:<8} -> {verdict}")

    cracked = sum(1 for j in q.status() if j.state.value == "cracked")
    note(f"Recovered {cracked}/{len(targets)} from a file-based list. Swap in "
         "rockyou.txt and the same call cracks against millions of words.")
    assert cracked == 3


if __name__ == "__main__":
    main()
