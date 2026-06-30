"""Scenario 4 - platform / queue administrators.

If you run CrackQ as a service you care about throughput and bounded cost, not
plaintext. Two levers control work per job: the wordlist size and whether rule
mangling is on. This demo measures candidate counts and per-job timing across
those settings -- the accounting an admin uses for capacity planning and SLAs.
"""
from _common import fresh_queue, WORDLIST, sha256, rule, note


def _summary(jobs):
    total = sum(j.candidates_tried for j in jobs)
    elapsed = sum(j.elapsed_sec for j in jobs)
    cracked = sum(1 for j in jobs if j.state.value == "cracked")
    return total, elapsed, cracked


def main() -> None:
    rule("CAPACITY PLANNING  -  candidates, timing, the cost of rules")

    # Same batch of hashes, run two ways. 'autumn!' is only reachable with rules.
    batch = [sha256("summer"), sha256("autumn!"), sha256("nope_not_here")]

    note(f"Wordlist size: {len(WORDLIST)} words. Batch: {len(batch)} hashes.\n")

    q_norules = fresh_queue()
    for h in batch:
        q_norules.submit(h, owner="admin", rules=False)
    no_rules = q_norules.run_all()

    q_rules = fresh_queue()
    for h in batch:
        q_rules.submit(h, owner="admin", rules=True)
    with_rules = q_rules.run_all()

    nr_total, nr_time, nr_hit = _summary(no_rules)
    wr_total, wr_time, wr_hit = _summary(with_rules)

    print(f"   {'mode':<12}{'candidates':>12}{'cracked':>10}{'elapsed_sec':>14}")
    print(f"   {'-'*12}{'-'*12:>12}{'-'*10:>10}{'-'*14:>14}")
    print(f"   {'no-rules':<12}{nr_total:>12}{nr_hit:>10}{nr_time:>14.6f}")
    print(f"   {'rules':<12}{wr_total:>12}{wr_hit:>10}{wr_time:>14.6f}")

    factor = (wr_total / nr_total) if nr_total else 0
    note(f"Rule mangling expanded the search space ~{factor:.1f}x and recovered "
         f"{wr_hit - nr_hit} more credential(s) the plain wordlist missed.")
    print("Admin takeaway: rules buy coverage at a predictable, measurable cost "
          "per job -- size your workers and SLAs against these candidate counts.")


if __name__ == "__main__":
    main()
