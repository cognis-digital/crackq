"""Scenario 20 - the whole story: detect -> queue -> crack -> audit -> report.

A single end-to-end run that ties the pieces together the way a real shared
service would: triage an incoming mixed file, reject the junk, queue the valid
hashes with per-owner priority, cancel a mistaken submission, drain the queue,
verify the audit chain, and print a final rollup. Authorized / defensive use only.
"""
from _common import fresh_queue, md5, sha1, sha256, AuditLog, rule, note
from crackq.core import detect_algorithm, is_hex_digest


def main() -> None:
    q = fresh_queue()
    rule("END TO END  -  detect, queue, crack, audit, report")

    incoming = [
        ("redteam", "hunter",      md5("hunter")),        # crackable
        ("redteam", "Welcome",     sha1("Welcome")),      # capitalize rule
        ("soc",     "letmein!",    sha256("letmein!")),   # append rule
        ("soc",     "trustno1",    sha256("trustno1")),   # append rule
        ("soc",     "junk-line",   "not-a-real-hash"),    # rejected at triage
        ("audit",   "unbreakable", sha256("9xQ!zR#eW2vX")),  # exhausts
    ]

    note("1) Triage: identify each line, drop anything that is not a valid hash.")
    accepted = []
    for owner, label, h in incoming:
        if is_hex_digest(h) and detect_algorithm(h):
            accepted.append((owner, label, h))
            print(f"   [accept] {owner:<8} {label:<12} {detect_algorithm(h)}")
        else:
            print(f"   [reject] {owner:<8} {label:<12} (not a hash)")

    note("2) Queue accepted hashes; SOC work gets higher priority than audit.")
    jobs = {}
    for owner, label, h in accepted:
        prio = 1 if owner == "soc" else (3 if owner == "redteam" else 7)
        jobs[label] = q.submit(h, owner=owner, priority=prio)

    note("3) An analyst realises one submission was a mistake and cancels it.")
    q.cancel(jobs["unbreakable"].id)
    print(f"   cancelled 'unbreakable' (job {jobs['unbreakable'].id})")

    note("4) Drain the queue.")
    q.run_all()

    note("5) Verify the audit chain end to end.")
    log = AuditLog(q.audit.path)
    print(f"   verify() -> {log.verify()}  ({len(log.entries())} records)")

    rule("FINAL REPORT")
    m = q.metrics()
    for job in q.status():
        verdict = (job.plaintext if job.state.value == "cracked"
                   else f"<{job.state.value}>")
        print(f"   p{job.priority} {job.owner:<8} {verdict:<12} "
              f"({job.candidates_tried} tries, {job.algorithm})")
    note(f"Totals: {m['cracked']} cracked, "
         f"{m['by_state']['cancelled']} cancelled, "
         f"{m['candidates_tried']} candidates tried. Chain verified -- the run is "
         "reproducible and provable.")
    assert m["cracked"] == 4 and m["by_state"]["cancelled"] == 1


if __name__ == "__main__":
    main()
