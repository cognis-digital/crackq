"""Scenario 06 - blue team: turn a crack run into a strength report.

The defensive payoff of cracking your *own* hashes is a report: once a
plaintext falls, *why* was it weak, and how many peers share the flaw? This
demo cracks a simulated employee set, then feeds the recovered plaintexts to
crackq's analytics engine (``crack_report``) to produce the composition
breakdown, pattern frequency, reuse detection, and remediation guidance a
security lead can act on. Offline, authorized use -- every hash is one we own.
"""
from _common import fresh_queue, sha256, rule, note

from crackq.analyze import crack_report


def main() -> None:
    q = fresh_queue()
    rule("PASSWORD ANALYTICS  -  crack your own hashes, brief leadership")

    # Simulated employee password hashes (all from known plaintexts we own).
    employees = {
        "e.reed":   sha256("dragon"),        # weak: base dictionary word
        "s.malik":  sha256("Summer2025"),    # weak: capitalize + year
        "t.okafor": sha256("welcome123"),    # weak: word + digit suffix
        "k.nyx":    sha256("p455w0rd"),      # weak: leet of a dictionary word
        "j.doe":    sha256("dragon"),        # weak AND reused (same as e.reed)
        "l.vance":  sha256("7Gq!zR#eW2vX"),  # strong: not derived from a word
    }
    for owner, digest in employees.items():
        q.submit(digest, owner=owner, rules=True)
    q.run_all()

    report = crack_report(q.status())
    a = report["analysis"]

    note(f"Cracked {report['cracked']}/{report['total_jobs']} hashes "
         f"({report['crack_rate'] * 100:.0f}% crack rate).")

    print("\n   Strength distribution of recovered passwords:")
    for tier, n in a["by_strength"].items():
        if n:
            print(f"      {tier:<12} {n}")

    print("\n   Most common weakening patterns:")
    for pat, n in sorted(a["pattern_frequency"].items(), key=lambda kv: -kv[1]):
        print(f"      {pat:<18} x{n}")

    if a["reused"]:
        print("\n   Reused across accounts:")
        for pw, n in a["reused"].items():
            print(f"      {pw!r} used by {n} accounts")

    print("\n   Weakest recovered credentials:")
    for w in a["weakest"][:3]:
        print(f"      {w['password']!r:<16} {w['strength']:<10} "
              f"~{w['entropy_bits']:.0f} bits")

    print("\n   Recommendations for leadership:")
    for rec in a["recommendations"]:
        print(f"      - {rec}")

    # Invariants the narrative above depends on.
    assert report["cracked"] == 5 and report["total_jobs"] == 6
    assert a["reused"] == {"dragon": 2}
    assert a["count"] == 5


if __name__ == "__main__":
    main()
