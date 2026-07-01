"""Scenario 14 - forensics: reconstruct an engagement from the audit log alone.

The audit log is not just tamper-evident -- it is a complete, ordered account of
everything the queue did. This demo runs an engagement, throws away the in-memory
queue, then reconstructs the timeline (who submitted what, what cracked, what
resisted) purely by replaying the log. Authorized / defensive use only.
"""
from _common import fresh_queue, sha256, AuditLog, rule, note


def main() -> None:
    q = fresh_queue()
    audit_path = q.audit.path
    rule("AUDIT REPLAY  -  rebuild the engagement timeline from the log")

    note("Run an engagement (three owners, mixed outcomes):")
    q.submit(sha256("welcome"), owner="alice")               # cracks
    q.submit(sha256("dragon"), owner="bob")                  # cracks
    doomed = q.submit(sha256("secret"), owner="carol")
    q.cancel(doomed.id)                                       # cancelled
    q.submit(sha256("Q!9z#nomatch"), owner="alice")          # exhausted
    q.run_all()

    note("Discard the queue; reopen only the log file:")
    del q
    log = AuditLog(audit_path)
    assert log.verify() is True
    entries = log.entries()
    print(f"   {len(entries)} records, chain verified.")

    note("Replay to reconstruct the timeline:")
    by_owner = {}
    outcomes = {"crack": 0, "exhausted": 0, "cancel": 0}
    for e in entries:
        by_owner.setdefault(e["user"], set()).add(e["action"])
        if e["action"] in outcomes:
            outcomes[e["action"]] += 1
    for owner in sorted(by_owner):
        print(f"   {owner:<8} actions: {sorted(by_owner[owner])}")

    note("Outcome tally from the log alone: "
         f"{outcomes['crack']} cracked, {outcomes['exhausted']} exhausted, "
         f"{outcomes['cancel']} cancelled.")
    assert outcomes["crack"] == 2
    assert outcomes["exhausted"] == 1
    assert outcomes["cancel"] == 1
    print("The log is sufficient evidence on its own -- no need to trust the "
          "process that produced it.")


if __name__ == "__main__":
    main()
