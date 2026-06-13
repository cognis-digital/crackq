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
pip install "git+https://github.com/cognis-digital/crackq.git"
crackq scan .            # → prioritized findings in seconds
```

<!-- cognis:layman:start -->
## What is this?

CrackQ is a self-hosted tool that lets security teams queue up password hash cracking jobs and track them with a full audit trail. You give it a list of hashed passwords and a wordlist of candidate passwords, and it tries to recover the original passwords using common techniques like capitalization, digit suffixes, and character substitution. It is designed for authorized red-team and penetration testing work — think of it as a lightweight, self-contained manager that wraps the same dictionary-attack logic used by professional tools like hashcat, but runs entirely on your own machine with no cloud account required.
<!-- cognis:layman:end -->

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
<!-- cognis:domains:start -->
## Domains

**Primary domain:** Cyber & Security  ·  **JTF MERIDIAN division:** NULLBYTE · SPECTER

**Topics:** `cognis` `security` `infosec` `cybersecurity` `blue-team`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

<!-- cognis:install:start -->
## Install

`crackq` is source-available (not published to PyPI) — every method below installs
straight from GitHub. Pick whichever you prefer; the one-line scripts auto-detect
the best tool available on your machine.

**One-liner (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/cognis-digital/crackq/HEAD/install.sh | sh
```

**One-liner (Windows PowerShell):**
```powershell
irm https://raw.githubusercontent.com/cognis-digital/crackq/HEAD/install.ps1 | iex
```

**Or install manually — any one of:**
```sh
pipx install "git+https://github.com/cognis-digital/crackq.git"     # isolated (recommended)
uv tool install "git+https://github.com/cognis-digital/crackq.git"  # uv
pip install "git+https://github.com/cognis-digital/crackq.git"      # pip
```

**From source:**
```sh
git clone https://github.com/cognis-digital/crackq.git
cd crackq && pip install .
```

Then run:
```sh
crackq --help
```
<!-- cognis:install:end -->

## Quick start

```bash
pip install "git+https://github.com/cognis-digital/crackq.git"
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
  A[Input: file / dir / API] --> B[Collectors]
  B --> C[Rules / Analyzers]
  C --> D[Scorer]
  D --> E{Reporters}
  E --> F[Table]
  E --> G[JSON / SARIF]
  E --> H[MCP tool -. drives .-> AI agents]
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

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
