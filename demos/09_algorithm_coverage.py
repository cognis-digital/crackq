"""Scenario 9 - coverage: the same secret across every supported algorithm.

A dump rarely uses one hash type. crackq auto-detects and cracks md5, sha1,
sha224, sha256, sha384 and sha512 with the same wordlist and rules. This demo
hashes one known plaintext six ways and recovers all six. Authorized use only.
"""
import hashlib

from _common import fresh_queue, rule, note
from crackq.core import supported_algorithms


def main() -> None:
    q = fresh_queue(wordlist=["welcome"])
    rule("ALGORITHM COVERAGE  -  one secret, every supported hash type")

    secret = "welcome1"  # reachable from 'welcome' via the append-'1' rule
    note(f"Hash the same secret ({secret!r}) with every supported algorithm "
         "and queue them for auto-detected cracking:")
    for algo in supported_algorithms():
        digest = hashlib.new(algo, secret.encode()).hexdigest()
        q.submit(digest, owner="coverage", rules=True)
        print(f"   + {algo:<8} {digest[:20]}...  (len {len(digest)})")

    q.run_all()

    rule("RESULTS")
    recovered = 0
    for job in q.status():
        ok = job.state.value == "cracked"
        recovered += ok
        mark = "CRACKED " if ok else job.state.value.upper()
        print(f"   [{mark:<9}] {str(job.algorithm):<8} -> {job.plaintext!r} "
              f"({job.candidates_tried} tries)")

    note(f"Recovered {recovered}/{len(supported_algorithms())} algorithms with a "
         "one-word list + rules. crackq picked the algorithm from digest length "
         "for each -- no per-hash configuration needed.")
    assert recovered == len(supported_algorithms())


if __name__ == "__main__":
    main()
