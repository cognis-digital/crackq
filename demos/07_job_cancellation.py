"""Scenario 7 - queue operator: pull a job back before it runs.

An analyst queued a job against the wrong dataset, or an engagement ended early.
crackq lets you cancel any *queued* job so the scheduler skips it -- and records
the cancellation in the audit log. Jobs that already started or finished cannot
be cancelled (the accounting stays honest). Authorized / defensive use only.
"""
from _common import fresh_queue, md5, rule, note
from crackq.core import JobState


def main() -> None:
    q = fresh_queue()
    rule("JOB CANCELLATION  -  withdraw queued work; audit records it")

    note("Queue four jobs; then withdraw two before draining:")
    keep_a = q.submit(md5("dragon"), owner="analyst", priority=5)
    drop_1 = q.submit(md5("qwerty"), owner="analyst", priority=5)
    keep_b = q.submit(md5("monkey"), owner="analyst", priority=5)
    drop_2 = q.submit(md5("shadow"), owner="analyst", priority=5)
    for j in (keep_a, drop_1, keep_b, drop_2):
        print(f"   submit  job={j.id}  ({j.hash[:12]}...)")

    note("Cancel two queued jobs:")
    for j in (drop_1, drop_2):
        q.cancel(j.id)
        print(f"   cancel  job={j.id}  -> {j.state.value}")

    note("Try to cancel a job that has already finished (must be refused):")
    q.run_job(q.get(keep_a.id))
    try:
        q.cancel(keep_a.id)
        print("   (unexpected) cancel succeeded")
    except ValueError as exc:
        print(f"   refused: {exc}")

    note("Drain the remaining queue -- cancelled jobs are skipped:")
    done = q.run_all()
    ran = [j.id for j in done]
    print(f"   ran: {ran}")
    assert drop_1.id not in ran and drop_2.id not in ran
    assert keep_b.id in ran

    cancelled = [j for j in q.status() if j.state == JobState.CANCELLED]
    note(f"{len(cancelled)} job(s) cancelled and skipped; "
         "each cancellation is in the tamper-evident audit log.")
    cancel_events = [e for e in q.audit.entries() if e["action"] == "cancel"]
    print(f"   audit 'cancel' records: {len(cancel_events)}")


if __name__ == "__main__":
    main()
