# crackq usage

`crackq` is a self-hosted, **offline** password-recovery queue. It performs
honest dictionary work over a wordlist you supply, schedules multiple jobs by
priority, and records every state transition to a tamper-evident audit log.

> **Authorized / defensive use only.** Run it against hashes you own or are
> explicitly authorized to test.

All output honours the global `--format {table,json,csv}` switch, which must
appear **before** the subcommand:

```bash
crackq --format json <subcommand> [options]
```

## Global options

| Option | Default | Meaning |
|--------|---------|---------|
| `--format {table,json,csv}` | `table` | Output rendering for every subcommand. |
| `--audit-log PATH` | temp dir `crackq_audit.jsonl` | Where the hash-chained audit log is written/read. |
| `--version` | — | Print `crackq <version>` and exit. |

## Subcommands

### `algos` — list supported algorithms

```bash
crackq algos
```

Supported: `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`.

### `detect` — identify a hash's algorithm

Guesses the algorithm from digest length and lists every candidate. Exits `1`
if none of the supplied hashes could be identified (useful to gate a pipeline).

```bash
crackq detect --hash 5f4dcc3b5aa765d61d8327deb882cf99
crackq --format json detect --hash <d1> --hash <d2>
```

| Column | Meaning |
|--------|---------|
| `valid_hex` | Whether the string is plausible lowercase hex of even length. |
| `likely` | Most probable algorithm (by length), or `-`. |
| `candidates` | Every supported algorithm matching that length. |

### `run` — submit hashes and drain the queue

The common operator flow: submit one or more hashes, run them in priority order
against a wordlist, and report. Exit code is `1` if any job **failed** (bad
algorithm / error), `0` otherwise (even if nothing cracked).

```bash
# inline candidates
crackq run --hash 5f4dcc3b5aa765d61d8327deb882cf99 --words password admin --owner blue

# from files, machine-readable
crackq --format json run --hashfile hashes.txt --wordlist words.txt --owner soc

# aggregate queue metrics instead of the per-job table
crackq --format json run --hashfile hashes.txt --wordlist words.txt --metrics

# password strength/composition report over the cracked jobs
crackq --format json run --hashfile hashes.txt --wordlist words.txt --report
```

| Option | Meaning |
|--------|---------|
| `--hash` (repeatable) / `--hashfile` | The digests to crack. |
| `--wordlist PATH` / `--words ...` | Candidate source (file or inline). |
| `--algorithm` | Force an algorithm instead of auto-detecting. |
| `--no-rules` | Disable rule mangling (base words only). |
| `--priority N` | Lower runs sooner (default `5`). |
| `--owner NAME` | Recorded on every job and audit record. |
| `--metrics` | Print aggregate metrics rather than per-job rows. |
| `--report` | Print a strength/composition report over cracked jobs. |

### `scan` — single-shot crack of one hash

The uniform `scan(target)` verb shared across the suite. Exits `0` when
cracked, `1` when the search was exhausted without a hit.

```bash
crackq --format json scan 5f4dcc3b5aa765d61d8327deb882cf99 --words password
crackq scan <digest> --wordlist words.txt --no-rules --max-candidates 100000
```

### `analyze` — score recovered plaintexts

Turn recovered plaintexts into an actionable strength/composition report. Per
password it reports length, character classes, a charset-entropy **estimate**,
a strength tier, and detected weakening patterns. With `--report` it rolls a
set up into an aggregate with reuse detection and remediation guidance.

```bash
# per-password rows
crackq analyze --password Summer2025 --password 'Tr0ub4dor'

# aggregate policy report from a file of cracked plaintexts
crackq --format json analyze --pwfile cracked.txt --report --top-weak 10
```

Detected patterns include: `all-digits`, `all-lower`, `all-upper`,
`capitalized`, `keyboard-sequence`, `leet` (interior substitution only),
`repeat-run`, `short`, `trailing-digits`, `year-suffix`.

Strength tiers (by estimated bits): `very-weak` (<28), `weak` (<36),
`fair` (<60), `strong` (<128), `very-strong` (≥128). The entropy figure is a
search-space upper bound (`length × log2(pool)`), not a measured entropy.

### `audit` — print or verify the tamper-evident log

```bash
crackq --audit-log audit.jsonl audit            # print records
crackq --audit-log audit.jsonl audit --verify   # verify the hash chain
```

`--verify` exits `1` and reports the offending record if any entry was edited,
deleted, reordered, or forged.

### `mcp` — run the MCP server

Exposes the `scan` verb to AI agents over MCP. Requires the optional extra:

```bash
pip install "cognis-crackq[mcp]"
crackq mcp
```

If the extra is not installed, the command prints an actionable message and
exits `1`.

## Programmatic API

Everything the CLI does is available as a library:

```python
from crackq import CrackQ, crack_hash, scan
from crackq import analyze_password, analyze_batch, crack_report

# one-shot
scan("5f4dcc3b5aa765d61d8327deb882cf99", wordlist=["password"])

# a queue with an audit log
q = CrackQ("audit.jsonl", wordlist=["dragon", "welcome"])
q.submit("827ccb0eea8a706c4c34a16891f84e7b", owner="soc", priority=1)
q.run_all()
report = crack_report(q.status())     # crack rate + composition analysis
q.audit.verify()                       # True, or raises AuditError

# strength analytics on their own
analyze_password("Summer2025")         # -> dict with entropy, strength, patterns
analyze_batch(["dragon", "hunter2", "hunter2"])  # -> aggregate + reuse detection
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (ran cleanly; `scan` also requires a crack, `detect` an identification). |
| `1` | Ran but the gate failed: a job failed (`run`), no crack (`scan`), nothing identified (`detect`), tampered log (`audit --verify`), or MCP extra missing. |
| `2` | Usage / input error (missing args, bad digest, missing file). |
