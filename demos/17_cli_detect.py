"""Scenario 17 - CLI triage: `crackq detect` before you crack.

The detect subcommand identifies hashes straight from the command line and sets
its exit code so a script can branch: 0 if at least one hash was identified,
1 if none were. This demo drives the real CLI in-process and parses its JSON,
the way a pipeline would. Authorized / defensive use only.
"""
import io
import json
from contextlib import redirect_stdout

from _common import md5, sha1, sha256, sha512, rule, note
from crackq.cli import main as cli_main


def _detect(hashes):
    argv = ["--format", "json", "detect"]
    for h in hashes:
        argv += ["--hash", h]
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli_main(argv)
    return rc, json.loads(buf.getvalue())


def main() -> None:
    rule("CLI DETECT  -  identify hashes and branch on the exit code")

    note("Equivalent shell command:")
    print("   crackq --format json detect --hash <h1> --hash <h2> ...")

    mixed = [md5("a"), sha1("a"), sha256("a"), sha512("a")]
    rc, rows = _detect(mixed)
    note(f"A file of real hashes (exit {rc}):")
    print(f"   {'likely':<9}{'valid':<7}{'hash'}")
    for r in rows:
        print(f"   {r['likely']:<9}{str(r['valid_hex']):<7}{r['hash'][:24]}...")
    assert rc == 0
    assert {r["likely"] for r in rows} == {"md5", "sha1", "sha256", "sha512"}

    note("A file of junk lines (exit code signals 'nothing identified'):")
    rc2, rows2 = _detect(["garbage", "xyz123", "not-a-hash!"])
    for r in rows2:
        print(f"   {r['likely']:<9}{str(r['valid_hex']):<7}{r['hash']}")
    print(f"   exit code: {rc2}")
    assert rc2 == 1
    note("A pipeline can gate cracking on `crackq detect` -- skip the queue "
         "entirely if the input file has no recognisable hashes.")


if __name__ == "__main__":
    main()
