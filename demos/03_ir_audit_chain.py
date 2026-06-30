"""Scenario 3 - incident response & compliance.

When a credential audit is evidence, "who cracked what, and when" has to be a
fact you can prove -- not a guess. Every CrackQ state transition is appended to
a hash-chained, tamper-evident JSONL log: each record embeds the SHA-256 of the
previous one. This demo generates real audited activity, verifies the chain,
then tampers with one record and shows verification catch it.
"""
from _common import fresh_queue, AuditLog, sha256, rule, note
from crackq.core import AuditError


def main() -> None:
    q = fresh_queue()
    rule("AUDIT CHAIN  -  provable, tamper-evident who-cracked-what")

    note("Run an authorized audit of two service-account hashes:")
    q.submit(sha256("welcome"), owner="ir_analyst")      # crackable (base word)
    q.submit(sha256("Q!9z#unknown"), owner="ir_analyst")  # exhausted
    q.run_all()

    log = AuditLog(q.audit.path)
    records = log.entries()
    note(f"The run left {len(records)} records in the audit log:")
    for r in records:
        detail = {k: v for k, v in r["detail"].items() if k != "job_id"}
        print(f"   {r['action']:<10} user={r['user']:<10} "
              f"this={r['this'][:12]}...  {detail}")

    note("Verify the chain end to end:")
    print(f"   verify() -> {log.verify()}   (each record hashes the previous one)")

    note("Now tamper: rewrite an actor directly in the log file, bypassing append()...")
    with open(log.path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    lines[0] = lines[0].replace('"ir_analyst"', '"ghost_user"')
    with open(log.path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    try:
        AuditLog(log.path).verify()
        print("   verify() -> True   (unexpected!)")
    except AuditError as exc:
        print(f"   verify() -> AuditError: {exc}")
        note("The forged edit broke the chain at the first altered record. You can "
             "prove the log of who-ran-what was not rewritten after the fact.")


if __name__ == "__main__":
    main()
