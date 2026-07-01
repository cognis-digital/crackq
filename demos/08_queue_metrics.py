"""Scenario 8 - platform SRE: a metrics snapshot for dashboards & SLAs.

crackq.metrics() rolls up the whole queue into one dict -- job counts by state,
total candidates tried, elapsed time, crack count -- the shape you would scrape
into Prometheus or a status page. This demo builds a mixed queue and prints the
snapshot. Authorized / defensive use only.
"""
from _common import fresh_queue, md5, sha256, rule, note


def main() -> None:
    q = fresh_queue()
    rule("QUEUE METRICS  -  one snapshot for dashboards and SLAs")

    note("Build a realistic mixed workload:")
    q.submit(md5("dragon"), owner="a")            # will crack
    q.submit(sha256("monkey"), owner="b")          # will crack
    q.submit(sha256("Zx#unreachable_42"), owner="c")  # will exhaust
    doomed = q.submit(md5("shadow"), owner="d")
    q.cancel(doomed.id)                             # cancelled before run
    print("   4 jobs queued (1 cancelled up front)")

    q.run_all()

    m = q.metrics()
    note("metrics() snapshot:")
    print(f"   jobs            : {m['jobs']}")
    print(f"   cracked         : {m['cracked']}")
    print(f"   wordlist_size   : {m['wordlist_size']}")
    print(f"   candidates_tried: {m['candidates_tried']}")
    print(f"   elapsed_sec     : {m['elapsed_sec']}")
    print("   by_state:")
    for state, count in m["by_state"].items():
        if count:
            print(f"      {state:<12}{count}")

    note("These numbers are the raw material for throughput SLAs and cost "
         "reporting -- candidates_tried is the honest unit of work per cycle.")
    assert m["jobs"] == 4 and m["cracked"] == 2 and m["by_state"]["cancelled"] == 1


if __name__ == "__main__":
    main()
