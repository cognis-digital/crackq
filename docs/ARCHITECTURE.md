# Architecture

`crackq` is a self-hosted, multi-user password-cracking **queue**: submit hashes
you are authorized to test, and a priority scheduler drains them against a
wordlist with rule mangling, recording every state transition to a
tamper-evident audit log. This document explains how the pieces fit together.

> **Authorized / defensive use only.** Run it against hashes you own or are
> explicitly authorized to audit. See [`../DISCLAIMER.md`](../DISCLAIMER.md).

## The pipeline

```mermaid
flowchart LR
    op[Analyst / agent / CI] -->|submit hash + owner + priority| q[CrackQ<br/>priority scheduler]
    wl[(Wordlist)] --> eng[crack_hash<br/>dictionary + rules]
    q -->|run_job, priority order| eng
    eng --> res{cracked?}
    res -->|yes| cr[Job: CRACKED<br/>plaintext]
    res -->|no| ex[Job: EXHAUSTED]
    q --> audit[(Hash-chained<br/>audit log JSONL)]
    cr --> out[JSON / table out]
    ex --> out
    out --> cli[CLI / MCP / crackq-emit]
    audit -.verify.-> comp[IR / compliance]
    classDef hot stroke:#6b46c1,stroke-width:3px;
    class q,audit hot;
```

## Components

### Crack engine (`crackq/core.py` — `crack_hash`)
An honest dictionary attack over an attacker-supplied wordlist using stdlib
`hashlib` (`md5`, `sha1`, `sha256`, `sha512`). For each word it yields the base
candidate and — when `rules=True` — common mangles (capitalize, upper, reverse,
leet, and digit/`!`/year appends), the same primitive a real queue hands to
`hashcat -a 0`. It returns the outcome plus `candidates_tried` and `elapsed_sec`
so every job is accountable. Algorithm is auto-detected from digest length when
not given (`detect_algorithm`).

### Job & JobState (`crackq/core.py`)
A `Job` is a queued work item: `hash`, `owner`, `algorithm`, `rules`,
`priority` (lower = sooner), plus result fields filled in as it runs. `JobState`
moves `QUEUED → RUNNING → {CRACKED, EXHAUSTED, FAILED}`.

### Queue & scheduler (`crackq/core.py` — `CrackQ`)
The multi-user core. `submit()` enqueues a job for an owner and logs it;
`_next()` selects the next job by `(priority, created_at)` so an incident job
jumps ahead of routine work while equal-priority jobs stay FIFO; `run_job()`
runs one job and records the transition; `run_all()` drains the queue;
`status()` lists jobs. `load_wordlist()` reads a wordlist file once and shares
it across jobs.

### Audit log (`crackq/core.py` — `AuditLog`)
An append-only, hash-chained JSONL log. Each record stores the SHA-256 of the
previous record (`prev`) and its own digest (`this`), so any edit, deletion, or
reordering is detectable. `verify()` walks the chain and raises `AuditError` at
the first tampered record. This is what makes "who cracked what, and when" a
provable fact.

```mermaid
flowchart LR
    g[GENESIS<br/>0x000…] --> r1[submit<br/>this=H prev+data]
    r1 --> r2[start<br/>this=H prev+data]
    r2 --> r3[crack / exhausted<br/>this=H prev+data]
    r3 --> r4[…]
    classDef ok stroke:#23d160,stroke-width:2px;
    class r1,r2,r3,r4 ok;
```

### CLI (`crackq/cli.py`)
The scriptable front door. `run` submits hashes (`--hash`/`--hashfile`/`--words`/
`--wordlist`) and drains the queue, emitting `table` or `json`; exit code is `1`
if any job failed (bad algo / error), `0` otherwise. `audit` prints or
`--verify`s the log; `algos` lists supported algorithms.

### Interop (`crackq/connect.py`, `crackq/mcp_server.py`)
`crackq-emit` maps the JSON output to the canonical `Finding` and forwards it via
`cognis-connect` (STIX/MISP/Sigma/Splunk/Elastic/Slack/webhook) — a soft,
optional dependency. An MCP server entry point exposes the tool to AI agents.

## Data model

```mermaid
classDiagram
    class CrackQ {
      +dict jobs
      +list wordlist
      +AuditLog audit
      +submit(digest, owner, algorithm, rules, priority) Job
      +run_job(job) Job
      +run_all() Job[]
      +status() Job[]
    }
    class Job {
      +str id
      +str hash
      +str owner
      +int priority
      +JobState state
      +str plaintext
      +int candidates_tried
      +float elapsed_sec
    }
    class AuditLog {
      +str path
      +append(action, user, **detail)
      +entries() dict[]
      +verify() bool
    }
    CrackQ "1" o-- "many" Job
    CrackQ "1" o-- "1" AuditLog
```

## Why these choices

- **A queue, not a one-shot.** Cracking is shared, prioritized work; the
  scheduler is the product, the dictionary attack is just the primitive.
- **Offline by construction.** Nothing here touches the network. Hashes,
  wordlist, and audit log are local files you can copy, diff, and ship.
- **Provable by default.** The audit chain is the path every transition takes,
  not a feature bolted on — so credential audits stand up as evidence.
