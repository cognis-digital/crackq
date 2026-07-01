# Demos

Twenty runnable scenarios in [`../demos/`](../demos/), each targeting a different
audience. Every scenario builds its own throwaway queue + audit log over a small
bundled wordlist — **offline, real API, no network, no external engine** — and
exits 0, so they double as smoke tests (see [`../tests/test_demos.py`](../tests/test_demos.py)).

```bash
PYTHONUTF8=1 python demos/run_all.py            # all twenty, end to end
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
| 6 | [`06_hash_type_detection.py`](../demos/06_hash_type_detection.py) | Triage / intake | Identify the likely algorithm from digest length; reject non-hex junk before cracking |
| 7 | [`07_job_cancellation.py`](../demos/07_job_cancellation.py) | Queue operators | Cancel queued jobs (scheduler skips them, audit records it); running/finished jobs refuse cancel |
| 8 | [`08_queue_metrics.py`](../demos/08_queue_metrics.py) | Platform SRE | `metrics()` rollup — counts by state, candidates tried, elapsed — for dashboards/SLAs |
| 9 | [`09_algorithm_coverage.py`](../demos/09_algorithm_coverage.py) | Coverage | One secret hashed six ways (md5…sha512), all auto-detected and cracked |
| 10 | [`10_rules_vs_norules.py`](../demos/10_rules_vs_norules.py) | Policy owners | Which rule (capitalize/upper/reverse/leet/suffix) recovered each password |
| 11 | [`11_max_candidates_budget.py`](../demos/11_max_candidates_budget.py) | Cost control | `max_candidates` caps work per hash for fair, bounded scheduling |
| 12 | [`12_error_handling.py`](../demos/12_error_handling.py) | Integrators | Every bad-input path (empty/non-hex digest, wrong algo, bad owner, bad lifecycle) rejected clearly |
| 13 | [`13_multi_tenant_fairness.py`](../demos/13_multi_tenant_fairness.py) | Multi-tenant ops | An incident pre-empts a flood; equal-priority work stays FIFO across tenants; no starvation |
| 14 | [`14_audit_replay.py`](../demos/14_audit_replay.py) | Forensics | Reconstruct the whole engagement timeline from the audit log alone |
| 15 | [`15_wordlist_file.py`](../demos/15_wordlist_file.py) | Operators | `load_wordlist()` over a file on disk — how you wire in rockyou.txt |
| 16 | [`16_scan_entrypoint.py`](../demos/16_scan_entrypoint.py) | Suite integration | The uniform `scan(target)` verb the MCP server / Cognis.Studio drive |
| 17 | [`17_cli_detect.py`](../demos/17_cli_detect.py) | Pipelines | `crackq detect` identifies hashes and sets an exit code to gate cracking |
| 18 | [`18_cli_metrics.py`](../demos/18_cli_metrics.py) | CI / cron | `crackq run --metrics` emits a one-line JSON rollup for a dashboard feed |
| 19 | [`19_password_policy_report.py`](../demos/19_password_policy_report.py) | Blue team | Turn a crack run into a weak-vs-held report for leadership |
| 20 | [`20_end_to_end_service.py`](../demos/20_end_to_end_service.py) | Everyone | Full flow: detect → queue → cancel → crack → verify audit → report |

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

## 6. Hash-type detection — *triage before you crack*
Identifies the likely algorithm from digest length and validates the hex format,
so a mixed or corrupt file is triaged without burning a crack cycle — non-hex
lines never reach the queue.

## 7. Job cancellation — *withdraw queued work*
Cancels queued jobs so the scheduler skips them and the audit log records it.
Jobs that already started or finished refuse cancellation, keeping the accounting
honest.

## 8. Queue metrics — *one snapshot for dashboards*
`metrics()` rolls the queue into a single dict — counts by state, total
candidates tried, elapsed time, crack count — the shape you scrape into
Prometheus or a status page.

## 9. Algorithm coverage — *one secret, every hash type*
Hashes the same plaintext with md5/sha1/sha224/sha256/sha384/sha512 and recovers
all six with one wordlist + rules, auto-detecting the algorithm per digest.

## 10. Rules vs no-rules — *which mangle cracked what*
Runs passwords a plain list misses and names the exact rule (capitalize, upper,
reverse, leet, suffix) that recovered each — the evidence for a length/entropy
policy.

## 11. Candidate budget — *bounded work per hash*
`crack_hash(max_candidates=N)` imposes a hard ceiling on effort per hash so one
stubborn digest cannot monopolise a worker; a budget that covers a crackable
secret still succeeds.

## 12. Error handling — *fail loudly, never silently*
Walks every validation path — empty/non-hex digest, wrong algorithm, empty owner,
cancelling a finished job — and shows each rejected with an actionable message
instead of a misleading result.

## 13. Multi-tenant fairness — *no owner starved*
Two teams flood the queue while a third raises an incident; the priority-1
incident pre-empts the flood and equal-priority work stays FIFO across tenants.

## 14. Audit replay — *rebuild the timeline from the log*
Runs an engagement, discards the in-memory queue, then reconstructs who-did-what
purely by replaying the verified audit log — the log is evidence on its own.

## 15. Wordlist from file — *point it at a list on disk*
Writes a wordlist file and loads it with `load_wordlist()` — exactly how you wire
in a curated list or rockyou.txt, just sized to run instantly.

## 16. Scan entrypoint — *the suite-wide verb*
Drives the uniform `scan(target)` function (inline list or wordlist path) that
the MCP server exposes, so crackq presents the same shape as every other suite
tool.

## 17. CLI detect — *identify hashes and branch*
Drives `crackq detect`, which identifies hashes from the command line and sets
its exit code (0 = at least one identified, 1 = none) so a pipeline can gate the
crack step.

## 18. CLI metrics — *a one-line rollup for cron*
`crackq run --metrics --format json` runs the batch and emits the aggregate
snapshot instead of the per-job table — one JSON line per run for a dashboard
feed.

## 19. Password-policy report — *brief leadership*
Turns a crack run against your own hashes into a weak-vs-held report a security
lead can act on: recommend resets for the guessable, cite the survivors as the
target.

## 20. End to end — *the whole story*
A single run that ties it together: triage a mixed file, reject junk, queue with
per-owner priority, cancel a mistake, drain, verify the audit chain, and print a
final rollup.
