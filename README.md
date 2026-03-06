# clawdit

A Claude Code plugin for professional-grade Solidity smart contract security auditing.

Combines parallel agent architecture, static analysis (Slither + Aderyn), Solodit database search, and a comprehensive vulnerability knowledge base into a single integrated tool.

## Install

```bash
gh repo clone maxyz-xyz/clawdit
cd clawdit
bash scripts/setup.sh
claude --plugin-dir .
```

### Prerequisites

- Node.js 18+
- [uv](https://docs.astral.sh/uv/) (`brew install uv`) — runs Slither in an isolated environment via `uvx`
- [Aderyn](https://github.com/Cyfrin/aderyn) (`cargo install aderyn`)
- A [Solodit API key](https://solodit.cyfrin.io) — go to Profile → API Keys, then export it:
  ```bash
  export SOLODIT_API_KEY=sk_your_key
  ```
  Without this, the Solodit cross-referencing agent will fail to start. The rest of the audit still works.

## Usage

```
/clawdit [mode] [files...]
```

### Modes

| Mode      | Agents spawned                                        | Output           |
| --------- | ----------------------------------------------------- | ---------------- |
| (default) | 4 vector scanners (sonnet) + static analyzer (sonnet) | Findings report  |
| `deep`    | All of the above + adversarial reasoner (opus)        | Findings report  |
| `context` | Context builder only (opus)                           | Architecture doc |

**Default** — Fast parallel scan. Four sonnet agents each take a quarter of the 170+ attack vectors and scan the full codebase independently. A fifth agent runs Slither, Aderyn, and cross-references against Solodit. Results are deduplicated and merged into a single report. Best for quick assessments, iterating on fixes, or re-checking after changes.

**Deep** — Everything in default, plus an opus-powered adversarial reasoning agent that ignores the predefined attack vectors entirely and reasons freely about the code — looking for logic errors, economic exploits, novel cross-function attack paths, and anything the vector scanners might miss. Use this for thorough audits where coverage matters more than speed.

**Context** — No vulnerability scanning. Instead, an opus agent performs ultra-granular line-by-line analysis: function-level invariants, trust boundaries, cross-function data flows, actor models, and complexity clusters. Produces an architecture document, not a findings report.

### Recommended workflow

For the most thorough results, run **context first**, then **deep**:

```
# 1. Build deep architectural understanding
/clawdit context

# 2. Full audit with all agents (the context from step 1 is now
#    in your conversation, giving the deep audit better grounding)
/clawdit deep
```

The context pass gives both you and subsequent agents a precise mental model of the codebase — state variables, invariants, trust boundaries, and data flows. When the deep audit runs in the same conversation, that context is available, which helps you evaluate findings and catch false positives.

For quick iterations (e.g., re-checking after a fix), default mode is enough:

```
/clawdit src/Vault.sol
```

### Examples

```
# Audit all .sol files in current project
/clawdit

# Deep audit with adversarial reasoning
/clawdit deep

# Audit specific files only
/clawdit src/Vault.sol src/Router.sol

# Deep audit on specific files
/clawdit deep src/Vault.sol src/Router.sol

# Pre-audit context building
/clawdit context
```

## Architecture

### Three-Tier Reference System

| Tier | When loaded            | Content                                          |
| ---- | ---------------------- | ------------------------------------------------ |
| 0    | Always                 | CHEATSHEET.md — 170+ vulnerability types         |
| 1    | Per protocol detection | 21 protocol-specific context files               |
| 2    | On demand              | 107 vulnerability case files across 17 families  |

### Agents

| Agent                | Model  | Role                                                          |
| -------------------- | ------ | ------------------------------------------------------------- |
| vector-scanner (x4)  | sonnet | Parallel vulnerability scanning against attack vector bundles |
| static-analyzer      | sonnet | Slither/Aderyn triage + Solodit search                        |
| adversarial-reasoner | opus   | Free-form attack reasoning (deep mode)                        |
| context-builder      | opus   | Pre-audit deep context building                               |

### MCP Servers

- **solodit** — Search the Solodit vulnerability database for similar real-world findings
- **static-analysis** — Run Slither and Aderyn static analyzers

## Sources

Built from the best ideas across 9 open-source repos:

- [pashov/skills](https://github.com/pashov/skills) — Parallel agent architecture, attack vectors, FP-gate (MIT)
- [forefy/.context](https://github.com/forefy/.context) — Protocol detection, vulnerability families (MIT)
- [kadenzipfel/scv-scan](https://github.com/kadenzipfel/scv-scan) — Vulnerability references, cheatsheet
- [quillai-network/qs_skills](https://github.com/quillai-network/qs_skills) — Bayesian confidence scoring (MIT)
- [trailofbits/skills](https://github.com/trailofbits/skills) — Token integration patterns, entry-point analysis (CC-BY-SA-4.0)
- [Archethect/sc-auditor](https://github.com/Archethect/sc-auditor) — Slither/Aderyn MCP tools, Map-Hunt-Attack methodology
- [marchev/claudit](https://github.com/marchev/claudit) — Solodit MCP server (MIT)
- [Cyfrin/solskill](https://github.com/Cyfrin/solskill) — Solidity coding standards
- [auditmos/skills](https://github.com/auditmos/skills) — Liquidation, staking, CLM, and auction vulnerability families (MIT)

## License

This project is licensed under [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/) (Creative Commons Attribution-ShareAlike 4.0 International).

This license was chosen for compatibility with [trailofbits/skills](https://github.com/trailofbits/skills) (CC-BY-SA-4.0). You are free to use, modify, and redistribute this work — including commercially — as long as you provide attribution and distribute derivative works under the same license.
