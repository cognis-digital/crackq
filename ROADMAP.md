# crackq roadmap

This roadmap describes the intended direction of `crackq` — a self-hosted,
offline password-recovery queue with a tamper-evident audit log. It is a
statement of intent, not a commitment; priorities shift with real-world use and
contributor interest. Everything here respects the project's core principles:

- **Offline and honest** — no network calls; the "cracking" is real dictionary
  work over an attacker-supplied wordlist.
- **Zero required dependencies** — the engine, queue, audit log, and analytics
  run on the Python standard library alone. Integrations stay optional extras.
- **Additive** — new capability is layered on; existing APIs, CLI verbs, exit
  codes, and output formats are preserved.
- **Authorized / defensive use only** — features serve credential auditing of
  hashes you own or are explicitly authorized to test.

## Near-term (next few releases)

- **Rule engine depth** — a small, declarative rule set (append/prepend,
  case toggles, leet maps, combinator) with a `--rules-file` so operators can
  bring their own mangling rules instead of the built-in defaults.
- **Wordlist ergonomics** — de-duplication and streaming (line-at-a-time) for
  very large lists, plus multi-wordlist input.
- **Analytics expansion** — mask/pattern extraction (e.g. `?u?l?l?l?d?d`),
  top-N base words across a cracked set, and a Markdown/HTML report exporter
  built on the existing `crack_report` structure.
- **Detection breadth** — richer hash-type identification (encoded/formatted
  digests, salted forms) surfaced through the existing `detect` verb.
- **Docs & examples** — a cookbook of authorized-audit pipelines and CI recipes.

## Mid-term

- **Persistence** — an optional on-disk job store so a queue survives process
  restarts, with the audit log remaining the source of truth.
- **Concurrency** — a worker pool to run independent jobs in parallel while
  keeping deterministic priority scheduling and per-job accounting.
- **Pluggable algorithms** — a registry so additional hashlib-backed digests
  (and, behind an optional extra, KDF-style verifiers) can be added without
  touching the core loop.
- **Richer metrics** — throughput (candidates/sec), per-owner rollups, and a
  JSON metrics endpoint for dashboards.
- **Structured exporters** — first-class emit adapters (the `crackq-emit`
  bridge) for SIEM/notification targets, kept as optional extras.

## Long-term

- **Distributed queue** — an optional coordinator so multiple hosts share one
  prioritized, audited work queue.
- **Policy-as-code** — express password-policy checks (length, class, denylist,
  breach screen) declaratively and evaluate a cracked set against them.
- **Signed audit chains** — optional cryptographic signing of audit records on
  top of the existing hash chain for third-party verifiability.
- **Suite interoperability** — deepen the shared `scan(target)` verb and JSON
  contract so crackq composes cleanly with the rest of the tooling suite.

## Non-goals

- Bundling or wrapping a specific external cracking engine.
- Any capability aimed at unauthorized access. crackq is a defensive
  credential-audit tool; contributions must keep that framing.

Have an idea or a use case? Open a Discussion or an issue — see
[CONTRIBUTING.md](CONTRIBUTING.md).
