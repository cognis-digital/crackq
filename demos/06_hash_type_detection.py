"""Scenario 6 - triage: identify a hash before you spend cycles on it.

Before queueing a dump you often want to know *what* you are looking at. crackq
detects the likely algorithm from digest length and flags anything that is not a
valid hex digest at all -- so you can triage a mixed file without burning a
single crack cycle. Authorized / defensive use only.
"""
from _common import md5, sha1, sha256, sha512, rule, note
from crackq.core import detect_algorithm, detect_algorithms, is_hex_digest


def main() -> None:
    rule("HASH-TYPE DETECTION  -  triage a mixed dump before cracking")

    samples = [
        ("workstation admin", md5("hunter")),
        ("legacy service",    sha1("hunter")),
        ("app database",      sha256("hunter")),
        ("vault export",      sha512("hunter")),
        ("garbled line",      "zzzz-not-a-hash"),
        ("truncated digest",  "abc123"),
    ]

    note("For each line, guess the algorithm and validate the format:")
    print(f"   {'source':<20}{'valid':<7}{'likely':<9}{'candidates'}")
    print(f"   {'-'*20}{'-'*7}{'-'*9}{'-'*10}")
    identified = 0
    for label, h in samples:
        valid = is_hex_digest(h)
        likely = detect_algorithm(h) or "-"
        cands = ",".join(detect_algorithms(h)) or "-"
        if likely != "-":
            identified += 1
        print(f"   {label:<20}{str(valid):<7}{likely:<9}{cands}")

    note(f"Identified {identified}/{len(samples)} lines. The two rejected lines "
         "never reach the queue -- crackq refuses to run against non-hex input, "
         "so a corrupt dump fails loudly instead of silently wasting cycles.")


if __name__ == "__main__":
    main()
