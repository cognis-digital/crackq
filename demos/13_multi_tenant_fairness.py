"""Scenario 13 - multi-tenant fairness: no owner is starved.

Three teams share one queue. Two flood it with routine jobs; one submits a
single urgent incident. The scheduler serves strictly by (priority, submit time),
so the incident jumps ahead and every routine job still gets served in order --
nobody is starved. Authorized / defensive use only.
"""
from _common import fresh_queue, md5, rule, note


def main() -> None:
    q = fresh_queue()
    rule("MULTI-TENANT FAIRNESS  -  priority first, then FIFO, no starvation")

    note("Two teams flood routine work while a third raises an incident:")
    order = []
    for i in range(3):
        j = q.submit(md5("qwerty"), owner="team_a", priority=5)
        order.append(("team_a", j.id))
        print(f"   submit team_a  priority=5  job={j.id}")
    for i in range(2):
        j = q.submit(md5("shadow"), owner="team_b", priority=5)
        order.append(("team_b", j.id))
        print(f"   submit team_b  priority=5  job={j.id}")
    incident = q.submit(md5("dragon"), owner="ir_team", priority=1)
    print(f"   submit ir_team  priority=1  job={incident.id}  <-- INCIDENT")

    note("Scheduler drains the queue:")
    done = q.run_all()
    for rank, j in enumerate(done, 1):
        print(f"   {rank}. priority={j.priority}  owner={j.owner:<8} job={j.id}")

    served = [j.owner for j in done]
    note("Service order: " + " -> ".join(served))
    assert served[0] == "ir_team", "incident must be served first"
    # every submitted job eventually ran
    assert len(done) == len(order) + 1
    # equal-priority jobs kept submission order (team_a's three run before team_b's two)
    routine = [j.owner for j in done if j.priority == 5]
    assert routine == ["team_a", "team_a", "team_a", "team_b", "team_b"]
    note("The incident pre-empted the flood, and equal-priority work stayed FIFO "
         "across tenants -- fair sharing without starvation.")


if __name__ == "__main__":
    main()
