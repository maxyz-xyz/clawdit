# clawdit

A Claude Code plugin for professional-grade Solidity smart contract security auditing.

## Specifications

- **Agent Skills spec**: https://agentskills.io/specification.md
- **Claude Code skills docs**: https://code.claude.com/docs/en/skills.md
- **Claude Code plugins docs**: https://code.claude.com/docs/en/plugins.md

## Plugin Structure

```
.claude-plugin/
  plugin.json
agents/                    # Agent definition files for parallel audit
skills/
  audit/
    SKILL.md               # Main orchestrator
    references/            # Three-tier reference architecture
mcp-servers/
  solodit/                 # Solodit search MCP server
  static-analysis/         # Slither + Aderyn MCP server
```

## Script Paths

All paths in SKILL.md and agent files must use `${CLAUDE_PLUGIN_ROOT}`:

```bash
node ${CLAUDE_PLUGIN_ROOT}/mcp-servers/solodit/dist/index.js
```

## Validation

```bash
uvx --from "git+https://github.com/agentskills/agentskills.git#subdirectory=skills-ref" skills-ref validate skills/clawdit
```

## Linting

```bash
npx prettier --write "**/*.md"
```

## Conventions

- Reference docs use three-tier progressive disclosure (Tier 0: always loaded, Tier 1: per-protocol, Tier 2: on-demand)
- Agent files in `agents/` are spawned by the orchestrator, not invoked directly by users
- MCP servers must be built before use: `bash scripts/setup.sh`
