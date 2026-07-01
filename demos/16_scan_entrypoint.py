"""Scenario 16 - suite integration: the uniform scan() verb.

Every tool in the Cognis Neural Suite exposes a single-shot scan(target) so an
orchestrator (or the MCP server) can drive them all the same way. For crackq the
target is a hash; scan() accepts an inline list or a wordlist path and returns
the same result dict as crack_hash. Authorized / defensive use only.
"""
import os
import tempfile

from _common import sha256, md5, rule, note
from crackq.core import scan


def main() -> None:
    rule("SCAN ENTRYPOINT  -  the suite-wide scan(target) verb")

    note("scan() with an inline candidate list:")
    r1 = scan(md5("hunter"), wordlist=["admin", "hunter", "root"], rules=False)
    print(f"   scan(md5('hunter')) -> cracked={r1['cracked']} "
          f"plaintext={r1['plaintext']!r} algo={r1['algorithm']}")

    note("scan() with a wordlist file path (as an orchestrator would pass):")
    work = tempfile.mkdtemp(prefix="crackq_scan_")
    wl = os.path.join(work, "words.txt")
    with open(wl, "w", encoding="utf-8") as f:
        f.write("welcome\nmonkey\ndragon\n")
    r2 = scan(sha256("monkey"), wordlist=wl, rules=True)
    print(f"   scan(sha256('monkey'), wordlist=<file>) -> cracked={r2['cracked']} "
          f"plaintext={r2['plaintext']!r}")

    note("scan() on a hash that is not in the list -> a clean miss, not an error:")
    r3 = scan(sha256("Zx#unreachable"), wordlist=["welcome"], rules=True)
    print(f"   cracked={r3['cracked']}  candidates_tried={r3['candidates_tried']}")

    assert r1["cracked"] and r2["cracked"] and not r3["cracked"]
    note("Same call shape as every other suite tool -- crackq drops straight into "
         "Cognis.Studio / the MCP server with no special-casing.")


if __name__ == "__main__":
    main()
