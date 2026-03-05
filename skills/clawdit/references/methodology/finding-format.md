# Finding Format

Every finding MUST use this exact structure. Agents output raw findings in this format; the orchestrator merges and deduplicates before the final report.

## Schema

````
### [SEVERITY-NUMBER] Title

**Severity:** Critical | High | Medium | Low | Informational
**Confidence:** 0-100 (see judging.md)
**Category:** <vulnerability family from CHEATSHEET.md>
**Status:** Confirmed | Likely | Possible

**Location:**

- `path/to/File.sol#L42-L58`
- `path/to/Other.sol#L100`

**Description:**

One paragraph explaining what the vulnerability is and why it matters. Be precise about the root cause.

**Attack Path:**

1. Attacker calls `function()` with parameter X
2. State variable Y is modified before check Z
3. Re-entrant call exploits inconsistent state

**Impact:**

Concrete impact: funds at risk, protocol invariant broken, DoS vector, etc. Quantify when possible.

**Proof of Concept:**

```solidity
// Minimal code showing the exploit
````

**Recommendation:**

```solidity
// Suggested fix with code
```

**References:**

- Solodit: [finding title](url) (if found via Solodit search)
- CHEATSHEET entry: <entry-id>
- Similar real-world exploit: <reference>

```

## Field Rules

- **SEVERITY-NUMBER**: Use severity prefix + sequential number within that severity (e.g., `H-1`, `M-3`, `L-2`)
- **Confidence**: Must be computed via the scoring system in `judging.md`
- **Location**: Use exact file paths and line numbers. Multiple locations allowed.
- **Attack Path**: Must be concrete and sequential. No hand-waving.
- **Impact**: Must describe the worst realistic outcome, not the theoretical maximum.
- **Proof of Concept**: Required for Critical and High. Optional for Medium and below.
- **Recommendation**: Must include code when the fix is a code change.

## Deduplication Key

Findings are deduplicated by **root cause**. Two findings with the same root cause but different attack paths are merged into one finding with the higher severity and all attack paths listed.
```
