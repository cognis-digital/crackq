# Demos

Five runnable scenarios in [`../demos/`](../demos/), each targeting a different
audience. Every scenario builds its own throwaway queue + audit log over a small
bundled wordlist — **offline, real API, no network, no external engine** — and
exits 0, so they double as smoke tests (see [`../tests/test_demos.py`](../tests/test_demos.py)).

```bash
PYTHONUTF8=1 python demos/run_all.py            # all five, end to end
PYTHONUTF8=1 python demos/02_secops_priority_queue.py   # or just one
```

> **Authorized / defensive use only.** Every hash in these demos is generated
> from a known plaintext we own — exactly how you should test hashes you are
> authorized to audit.

| # | Scenario | Audience | Shows |
|---|----------|----------|-------|
| 1 | [`01_red_team_recovery.py`](../demos/01_red_team_recovery.py) | Red teams / pentesters | Queue a credential dump, crack with rule mangling, report per-account verdicts |
| 2 | [`02_secops_priority_queue.py`](../demos/02_secops_priority_queue.py) | Security operations / platform owners | Multi-user submissions served in priority order; an incident jumps the line, no analyst starved |
| 3 | [`03_ir_audit_chain.py`](../demos/03_ir_audit_chain.py) | Incident response / compliance | Hash-chained audit log; `verify()` passes, then catches a forged record |
| 4 | [`04_platform_admin_capacity.py`](../demos/04_platform_admin_capacity.py) | Queue / platform admins | Candidate counts and timing with and without rules — capacity & SLA planning |
| 5 | [`05_cli_pipeline.py`](../demos/05_cli_pipeline.py) | Automation / CI engineers | Drive the real `crackq` CLI, parse its JSON, feed downstream tooling |

## 1. Red-team recovery — *queue a dump, get verdicts*
You dumped a credential store on an authorized engagement. Queue the lot, run
them against a wordlist with rule mangling, and get a clean per-credential
verdict for the report — including the one that resisted, which is your evidence
the policy held for that account.

## 2. Shared priority queue — *fair, multi-user scheduling*
crackq is a shared service. Several analysts submit out of order; the scheduler
drains by `(priority, submission time)`, so a priority-1 CISO incident is served
before routine jobs while equal-priority jobs stay FIFO.

## 3. IR audit chain — *provable who-cracked-what*
Every state transition lands in a hash-chained JSONL log. The demo verifies the
chain, then rewrites one actor field directly in the file and shows `verify()`
raise `AuditError` at the first altered record — the difference between "someone
cracked these" and an accountable, tamper-evident service.

## 4. Platform admin capacity — *the cost of rules*
The two levers on work-per-job are wordlist size and rule mangling. The demo
runs the same batch with and without rules and prints candidate counts and
timing, so an admin can size workers and SLAs against real numbers.

## 5. CLI pipeline — *the queue as a scriptable command*
Drives the real `crackq` CLI in-process, writes a hashfile + wordlist, runs the
queue, and parses the JSON the way a CI job or `crackq-emit` forwarder would —
including the exit-code contract (0 = all ran, 1 = a job failed).
