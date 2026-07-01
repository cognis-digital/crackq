"""Scenario 19 - blue team: turn a crack run into a policy report.

The defensive payoff of cracking your *own* hashes is a report: how many
credentials fell, to what class of guess, and which held. This demo audits a
simulated employee set and produces a summary a security lead can act on --
recommend resets for the weak, cite the survivors as the target. Authorized use.
"""
from _common import fresh_queue, sha256, rule, note


def main() -> None:
    q = fresh_queue()
    rule("PASSWORD-POLICY REPORT  -  audit your own hashes, brief leadership")

    # Simulated employee password hashes (all generated from known plaintexts we
    # own). Strong ones are absent from the wordlist and should survive.
    employees = {
        "e.reed":   sha256("dragon"),        # weak: base dictionary word
        "s.malik":  sha256("Summer2025"),    # weak: capitalize + year
        "t.okafor": sha256("welcome123"),    # weak: word + digits
        "k.nyx":    sha256("p455w0rd"),      # weak: leet of a dictionary word
        "l.vance":  sha256("7Gq!zR#eW2vX"),  # strong: not derived from a word
        "d.park":   sha256("Kx9$mLp2!qZr"),  # strong
    }
    for owner, digest in employees.items():
        q.submit(digest, owner=owner, rules=True)
    q.run_all()

    weak, strong = [], []
    for owner, job in zip(employees, q.status()):
        (weak if job.state.value == "cracked" else strong).append(
            (owner, job.plaintext, job.candidates_tried))

    note(f"Audited {len(employees)} accounts.")
    print(f"\n   WEAK -- recovered, force reset ({len(weak)}):")
    for owner, pw, tries in weak:
        print(f"      {owner:<10} -> {pw!r:<14} (fell after {tries} guesses)")
    print(f"\n   HELD -- policy-compliant, no action ({len(strong)}):")
    for owner, _, tries in strong:
        print(f"      {owner:<10} survived {tries} candidates")

    rate = 100 * len(weak) / len(employees)
    note(f"Headline for leadership: {len(weak)}/{len(employees)} ({rate:.0f}%) of "
         "sampled credentials were trivially guessable from a small wordlist + "
         "rules. Recommend forced resets and a length/entropy policy.")
    assert len(weak) == 4 and len(strong) == 2


if __name__ == "__main__":
    main()
