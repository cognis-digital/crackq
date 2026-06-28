<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=CRACKQ&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="CRACKQ"/>

# CRACKQ

### Self-hosted password cracking queue — multi-user hashcat with audit log

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Selfhosted+password+cracking+queue++multiuser+hashcat+with+a;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-crackq.svg?color=6b46c1)](https://pypi.org/project/cognis-crackq/) [![CI](https://github.com/cognis-digital/crackq/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/crackq/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Red Team / Offensive — adversary tooling for authorized engagements.*

</div>

```bash
pip install cognis-crackq
crackq scan .            # → prioritized findings in seconds
```


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ crackq-emit --version
crackq 0.1.0
```

```console
$ crackq-emit --help
usage: crackq [-h] [--version] [--format {table,json}] [--audit-log AUDIT_LOG]
              {run,audit,algos} ...

Self-hosted password cracking queue.

positional arguments:
  {run,audit,algos}
    run                 submit hashes and drain the queue
    audit               print or verify the audit log
    algos               list supported algorithms

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --format {table,json}
  --audit-log AUDIT_LOG
```

> Blocks above are real `crackq` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"findings": [
    {
        "id": "1234567890",
        "title": "Suspicious Network Traffic",
        "description": "Anomalous network traffic detected from 192.168.1.100 to 8.8.8.8",
        "severity": "medium",
        "created_at": "2023-02-20T14:30:00Z"
    }
]
}
```

<!-- cognis:example:end -->

## Usage — step by step

> Defensive / authorized password-recovery only. Use on hashes you own or are explicitly authorized to test.

1. Install the CLI (Python 3.9+):

   ```bash
   pip install crackq         # or: pip install .   from a checkout
   ```

2. List supported algorithms first:

   ```bash
   crackq algos
   ```

3. Submit hashes and drain the queue in one shot — the `run` subcommand submits + runs + reports against a wordlist:

   ```bash
   crackq run --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5 --wordlist rockyou.txt --owner blue-team
   ```

   You can repeat `--hash`, supply `--hashfile`, pass inline `--words`, or use `--no-rules` to disable rule mangling.

4. Read the result — `--format json` gives per-job state; exit code is `1` if any job failed (bad algo/error), `0` otherwise. Verify the tamper-evident audit log:

   ```bash
   crackq run --hashfile hashes.txt --wordlist rockyou.txt --format json | jq '.[] | {hash, state, plaintext}'
   crackq audit --verify
   ```

5. Use it in an authorized credential-audit pipeline — every action is appended to the audit log (default in the temp dir; override with `--audit-log`):

   ```bash
   crackq --audit-log audit.jsonl run --hashfile hashes.txt --wordlist words.txt --owner soc
   ```


## Contents

- [Why crackq?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why crackq?

Self-hosted password cracking queue — multi-user hashcat with audit log — without standing up heavyweight infrastructure.

`crackq` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Supported Algorithms
- ✅ Detect Algorithm
- ✅ Crack Hash
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-crackq
crackq --version
crackq scan .                       # scan current project
crackq scan . --format json         # machine-readable
crackq scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ crackq scan .
  [HIGH    ] CRA-001  example finding             (./src/app.py)
  [MEDIUM  ] CRA-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[crackq<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`crackq` is interoperable with every popular way of using AI:

- **MCP server** — `crackq mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `crackq scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis crackq** | typical tools |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |
<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`crackq mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/crackq.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/crackq.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/crackq.git" # uv
pip install cognis-crackq                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/crackq:latest --help        # Docker
brew install cognis-digital/tap/crackq                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/crackq/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/crackq` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`c2detect`](https://github.com/cognis-digital/c2detect) — C2 server fingerprinter — Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel
- [`payloadlab`](https://github.com/cognis-digital/payloadlab) — Static malicious payload analyzer — PE/ELF/LNK/macro/OneNote
- [`redpath`](https://github.com/cognis-digital/redpath) — Active Directory attack path mapper — minimum-cost paths + remediation priority
- [`pwnreview`](https://github.com/cognis-digital/pwnreview) — Pentest report generator — YAML findings to CREST-grade PDF

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `crackq` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
