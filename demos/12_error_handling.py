"""Scenario 12 - robustness: crackq fails loudly, never silently.

Bad input is normal in the field: corrupt dumps, wrong algorithms, empty owners.
crackq validates aggressively and raises clear errors instead of producing junk
results. This demo walks the error paths so you can see exactly what a caller
must handle. Authorized / defensive use only.
"""
from _common import fresh_queue, md5, sha256, rule, note
from crackq.core import crack_hash


def _expect(label, fn):
    try:
        fn()
        print(f"   [NO RAISE] {label}  (unexpected!)")
        return False
    except (ValueError, KeyError) as exc:
        print(f"   [rejected] {label}: {exc}")
        return True


def main() -> None:
    q = fresh_queue()
    rule("ERROR HANDLING  -  clear rejections beat silent garbage")

    note("crack_hash input validation:")
    ok = True
    ok &= _expect("empty digest",
                  lambda: crack_hash("", ["x"]))
    ok &= _expect("non-hex digest",
                  lambda: crack_hash("not-a-hash!!", ["x"]))
    ok &= _expect("undetectable length",
                  lambda: crack_hash("ab" * 10, ["x"]))
    ok &= _expect("digest/algorithm length mismatch",
                  lambda: crack_hash(md5("z"), ["z"], algorithm="sha256"))
    ok &= _expect("zero candidate budget",
                  lambda: crack_hash(md5("z"), ["z"], max_candidates=0))

    note("queue submit validation:")
    ok &= _expect("empty owner",
                  lambda: q.submit(md5("z"), ""))
    ok &= _expect("unknown algorithm",
                  lambda: q.submit(md5("z"), "u", algorithm="bcrypt"))
    ok &= _expect("bad digest on submit",
                  lambda: q.submit("nope", "u"))

    note("queue lifecycle validation:")
    job = q.submit(sha256("welcome"), "u")
    q.run_all()
    ok &= _expect("cancel an already-finished job",
                  lambda: q.cancel(job.id))
    ok &= _expect("fetch an unknown job",
                  lambda: q.get("does-not-exist"))

    note("Every bad input was rejected with an actionable message; "
         "no call returned a misleading 'not cracked'.")
    assert ok, "every case above must raise"


if __name__ == "__main__":
    main()
