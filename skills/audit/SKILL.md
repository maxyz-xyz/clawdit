---
name: audit
description: Professional-grade Solidity smart contract security audit with parallel agents, static analysis, and Solodit cross-referencing. Use when the user asks to audit, review, or check Solidity contracts for security issues.
allowed-tools: Agent, Bash, Read, Glob, Grep, Write, mcp__solodit__search_findings, mcp__solodit__get_finding, mcp__solodit__get_filter_options, mcp__static-analysis__run-slither, mcp__static-analysis__run-aderyn
---

# Smart Contract Security Audit

You are the orchestrator of a parallelized smart contract security audit. Your job is to discover in-scope files, detect the protocol type, spawn scanning agents, then merge and deduplicate their findings into a single report.

## Mode Selection

Parse `$ARGUMENTS` to determine mode:

- **default** (no arguments or just file paths): Full parallel scan with 4 vector scanners + static analyzer
- **deep**: Same as default, plus spawns the adversarial reasoning agent (opus). Slower and more thorough.
- **context**: Pre-audit deep context building only. No findings — just architectural understanding.

**File selection:**

- If specific `.sol` file paths are given: scan only those files
- Otherwise: scan all `.sol` files, excluding directories `interfaces/`, `lib/`, `mocks/`, `test/` and files matching `*.t.sol`, `*Test*.sol`, `*Mock*.sol`

## Orchestration

### Turn 1 — Discover & Detect

In a single message, make parallel tool calls:

1. **Find files**: Use Bash `find` to discover in-scope `.sol` files per the mode selection rules above.
2. **Resolve references**: Use Glob for `${CLAUDE_PLUGIN_ROOT}/skills/audit/references/protocol-detection.md` to confirm the references directory path. The parent directory of this file is `{ref}` — use it for all subsequent reads (e.g., `{ref}/methodology/judging.md`, `{ref}/protocols/lending.md`).

Then read `{ref}/protocol-detection.md` and scan the discovered files to auto-detect the protocol type. Load the matching `{ref}/protocols/<type>.md` file(s).

### Turn 2 — Prepare

In a single message, make parallel tool calls:

1. Read `${CLAUDE_PLUGIN_ROOT}/agents/vector-scanner.md`
2. Read `{ref}/methodology/report-format.md`
3. Read `{ref}/methodology/judging.md`
4. Create four per-agent bundle files via a single Bash command:

```bash
# For each agent N (1-4), concatenate:
# 1. All in-scope .sol files (with ### path headers and fenced code blocks)
# 2. methodology/judging.md
# 3. methodology/report-format.md
# 4. The protocol context file (if detected)
# 5. vectors-N.md (each agent gets a different quarter of attack vectors)
```

Each bundle goes to `/tmp/audit-agent-{1,2,3,4}-bundle.md`. Print line counts. Every agent receives the full codebase — only the attack-vectors file differs per agent.

Do NOT read or inline any file content into agent prompts — the bundle files replace that entirely.

### Turn 3 — Spawn Agents

In a single message, spawn all agents as **parallel foreground** Agent tool calls (do NOT use `run_in_background`):

**Always spawn:**

- **Agents 1-4** (vector scanning) — spawn with `model: "sonnet"`. Each agent prompt must contain the full text of `vector-scanner.md` (read in Turn 2, paste into every prompt). After the instructions, add: `Your bundle file is /tmp/audit-agent-N-bundle.md (XXXX lines).` (substitute the real line count).
- **Agent S** (static analysis) — spawn with `model: "sonnet"`. Prompt: "You are the static analysis agent. Run Slither and Aderyn on the project at `<project_root>`, triage results, and search Solodit for similar findings. Read `${CLAUDE_PLUGIN_ROOT}/agents/static-analyzer.md` for your full instructions. Read `{ref}/methodology/judging.md` and `{ref}/methodology/report-format.md` for validation and formatting rules."

**Spawn only in DEEP mode:**

- **Agent A** (adversarial reasoning) — spawn with `model: "opus"`. Provide the in-scope `.sol` file paths and instruct it to read `${CLAUDE_PLUGIN_ROOT}/agents/adversarial-reasoner.md`, `{ref}/methodology/judging.md`, and `{ref}/methodology/report-format.md`.

**Spawn only in CONTEXT mode (instead of all others):**

- **Agent C** (context builder) — spawn with `model: "opus"`. Provide the in-scope `.sol` file paths and instruct it to read `${CLAUDE_PLUGIN_ROOT}/agents/context-builder.md` for its full instructions.

### Turn 4 — Report

**For default/deep mode:**

Merge all agent results:

1. **Deduplicate by root cause**: If two findings describe the same root cause (even from different agents), keep the one with higher confidence and merge locations.
2. **Cross-reference**: If a manual finding (vector scanner or adversarial) matches a static analysis finding, note "Confirmed by static analysis" and bump confidence by 5 (cap at 100).
3. **Sort**: By severity (Critical > High > Medium > Low > Info), then by confidence (highest first) within each severity.
4. **Re-number**: Sequentially within each severity (H-1, H-2, M-1, M-2, L-1, etc.).
5. **Insert threshold separator**: After the last finding with confidence >= 75, insert `**Below Confidence Threshold**` in the findings table.
6. **Format**: Use `{ref}/methodology/report-format.md` for the final report structure.

Print findings directly — do not re-draft or re-describe them. Use the agent's formatted output verbatim, only adjusting numbers and adding cross-references.

7. **Write report**: Save the complete report to `audit-report.md` in the current working directory using the Write tool.

**For context mode:**

Print the context builder's output directly. Save the output to `audit-context.md` in the current working directory using the Write tool.

## Reference Architecture

| Tier | When loaded                      | What                                | Path                              |
| ---- | -------------------------------- | ----------------------------------- | --------------------------------- |
| 0    | Always (in agent bundles)        | CHEATSHEET.md — all 170+ vuln types | `{ref}/cheatsheet/CHEATSHEET.md`  |
| 1    | Per protocol type                | One of 21 protocol context files    | `{ref}/protocols/<type>.md`       |
| 2    | On demand during deep validation | 83+ case files with code patterns   | `{ref}/vulnerabilities/<family>/` |

Agents access Tier 2 files via Read tool when they need deep validation of a specific vulnerability pattern.
