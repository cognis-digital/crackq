"""Scenario 2 - security operations / platform owners.

CrackQ is a *shared* service: several analysts submit jobs, and a CISO incident
should not wait behind a routine audit. The scheduler drains the queue in
priority order (lower number = sooner), breaking ties by submission time. This
demo submits jobs out of order from multiple owners and shows the scheduler
serve them in the right order, with fair accounting per job.
"""
from _common import fresh_queue, md5, sha256, rule, note


def main() -> None:
    q = fresh_queue()
    rule("SHARED PRIORITY QUEUE  -  multi-user, priority-scheduled, fair")

    # (owner, plaintext, priority) -- submitted deliberately out of order.
    submissions = [
        ("analyst_a", "qwerty",   5),   # routine
        ("analyst_b", "monkey",   5),   # routine, submitted later -> tie broken by time
        ("ciso_ir",   "dragon",   1),   # incident: jump the line
        ("analyst_a", "shadow",   8),   # low priority background job
    ]

    note("Three analysts submit four jobs out of priority order:")
    for owner, pt, prio in submissions:
        job = q.submit(md5(pt), owner=owner, priority=prio)
        print(f"   submit  owner={owner:<10} priority={prio}  job={job.id}")

    note("Scheduler drains the queue (priority asc, then FIFO):")
    done = q.run_all()
    for rank, job in enumerate(done, 1):
        verdict = job.plaintext if job.state.value == "cracked" else f"<{job.state.value}>"
        print(f"   {rank}. priority={job.priority}  owner={job.owner:<10} "
              f"-> {verdict:<10} ({job.candidates_tried} tries)")

    served = [j.owner for j in done]
    note("Service order: " + " -> ".join(served))
    assert served[0] == "ciso_ir", "incident job must be served first"
    print("The priority-1 incident jumped ahead of the routine jobs, and the two "
          "equal-priority jobs ran in submission order. No analyst is starved.")


if __name__ == "__main__":
    main()
