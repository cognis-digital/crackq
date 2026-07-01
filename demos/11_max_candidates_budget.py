"""Scenario 11 - cost control: cap work per hash with a candidate budget.

On a shared service you may want a hard ceiling on effort per hash so one
stubborn digest cannot monopolise a worker. crack_hash(max_candidates=N) stops
after N attempts and reports a miss with the exact count -- a bounded, fair unit
of work. Authorized / defensive use only.
"""
from _common import sha256, WORDLIST, rule, note
from crackq.core import crack_hash


def main() -> None:
    rule("CANDIDATE BUDGET  -  bounded work per hash with max_candidates")

    # A password not in the list -> normally exhausts the whole search space.
    target = sha256("Zx9!q4mW#vault")

    note("Unbounded run over the demo wordlist (rules on):")
    full = crack_hash(target, WORDLIST, rules=True)
    print(f"   cracked={full['cracked']}  candidates_tried={full['candidates_tried']}")

    note("Now impose a strict budget of 20 candidates:")
    capped = crack_hash(target, WORDLIST, rules=True, max_candidates=20)
    print(f"   cracked={capped['cracked']}  candidates_tried={capped['candidates_tried']}"
          f"  (stopped at the cap)")

    note("A budget that comfortably covers a crackable secret still succeeds:")
    easy = crack_hash(sha256("monkey"), WORDLIST, rules=True, max_candidates=500)
    print(f"   'monkey' cracked={easy['cracked']} in {easy['candidates_tried']} tries")

    assert capped["candidates_tried"] == 20 and capped["cracked"] is False
    assert easy["cracked"] is True
    note("max_candidates gives an operator a predictable per-hash ceiling for "
         "fair scheduling and cost caps on a shared queue.")


if __name__ == "__main__":
    main()
