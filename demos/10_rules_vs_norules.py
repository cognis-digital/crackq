"""Scenario 10 - policy: what rule mangling actually buys you.

Rule mangling turns each dictionary word into many candidates (capitalize,
upper, reverse, leet, common suffixes). This demo takes passwords that a plain
wordlist misses and shows exactly which rule recovered each one -- the evidence
a policy owner uses to argue for length/complexity requirements. Authorized use.
"""
from _common import fresh_queue, sha256, rule, note


def main() -> None:
    rule("RULES vs NO-RULES  -  which mangle recovered which password")

    # (base word in list, actual password, human-readable rule that reaches it)
    cases = [
        ("summer",   "Summer",     "capitalize"),
        ("dragon",   "DRAGON",     "uppercase"),
        ("secret",   "terces",     "reverse"),
        ("password", "p455w0rd",   "leet (a->4 s->5 o->0)"),
        ("welcome",  "welcome123", "append '123'"),
        ("monkey",   "Monkey2025", "capitalize + append '2025'"),
    ]
    base_words = [c[0] for c in cases]

    note("Plain wordlist (rules OFF) -- most of these resist:")
    q_off = fresh_queue(wordlist=base_words)
    for _, pw, _ in cases:
        q_off.submit(sha256(pw), owner="policy", rules=False)
    q_off.run_all()
    off_hits = sum(1 for j in q_off.status() if j.state.value == "cracked")
    print(f"   recovered {off_hits}/{len(cases)} with the plain list")

    note("Same list, rules ON -- and the rule that cracked each:")
    q_on = fresh_queue(wordlist=base_words)
    for _, pw, _ in cases:
        q_on.submit(sha256(pw), owner="policy", rules=True)
    q_on.run_all()
    on_hits = 0
    for (base, pw, ruledesc), job in zip(cases, q_on.status()):
        if job.state.value == "cracked":
            on_hits += 1
            print(f"   [CRACKED] {pw:<12} from {base!r:<12} via {ruledesc}")
        else:
            print(f"   [MISS   ] {pw:<12}")

    note(f"Rules took recovery from {off_hits}/{len(cases)} to {on_hits}/{len(cases)}. "
         "The takeaway for policy: predictable transforms of a dictionary word are "
         "not a defense -- length and true randomness are.")
    assert on_hits > off_hits


if __name__ == "__main__":
    main()
