"""Scenario 1 - red teams & pentesters.

You dumped a credential store during an authorized engagement. You don't want to
crack them one terminal at a time -- you want to queue the lot, run them against
a wordlist with rule mangling, and get a clean per-credential verdict you can
paste into the report. This demo plays that flow against the real CrackQ.
"""
from _common import fresh_queue, md5, sha1, sha256, rule, note


def main() -> None:
    q = fresh_queue()
    rule("RED-TEAM RECOVERY  -  queue a dump, crack with rules, report verdicts")

    # Hashes we generated from known plaintexts -- stand-ins for a dump you are
    # authorized to test. Mixed algorithms, as a real dump would be.
    dump = {
        "svc_backup": md5("welcome1"),       # reachable via the append-'1' rule
        "j.lee":      sha1("Hunter"),         # reachable via the capitalize rule
        "a.khan":     sha256("letmein!"),     # append-'!' rule on 'letmein'
        "root":       sha256("trustno1"),     # append-'1' rule on 'trustno'
        "ci_token":   sha256("Zx9!q4mW#vault"),  # not in the wordlist -> exhausted
    }

    note("Queueing the dump (CrackQ auto-detects the algorithm by digest length):")
    for account, digest in dump.items():
        job = q.submit(digest, owner="redteam", rules=True)
        print(f"   + {account:<10} job={job.id}  {job.hash[:16]}...")

    note("Draining the queue against the wordlist + rule mangling...")
    q.run_all()

    rule("ENGAGEMENT FINDINGS")
    accounts = list(dump)
    cracked = 0
    for account, job in zip(accounts, q.status()):
        if job.state.value == "cracked":
            cracked += 1
            print(f"   [CRACKED  ] {account:<10} -> {job.plaintext!r:<14} "
                  f"({job.algorithm}, {job.candidates_tried} tries)")
        else:
            print(f"   [{job.state.value.upper():<9}] {account:<10}    "
                  f"resisted {job.candidates_tried} candidates ({job.algorithm})")

    note(f"Result: {cracked}/{len(accounts)} credentials recovered. "
         "The exhausted one is your evidence the policy held for that account.")
    print("Every submit/start/crack/exhausted transition is in the audit log "
          "(see scenario 3).")


if __name__ == "__main__":
    main()
