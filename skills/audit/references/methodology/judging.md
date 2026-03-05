# Finding Validation & Confidence Scoring

Each finding passes a false-positive gate, then gets a confidence score.

## FP Gate

Every finding must pass all three checks. If any check fails, drop the finding — do not score or report it.

1. You can trace a concrete attack path: caller -> function call -> state change -> loss/impact. Evaluate what the code _allows_, not what the deployer _might choose_.
2. The entry point is reachable by the attacker (check modifiers, `msg.sender` guards, `onlyOwner`, access control).
3. No existing guard already prevents the attack (`require`, `if`-revert, reentrancy lock, allowance check, etc.).

## Confidence Score (Deduction-Based)

Confidence measures certainty that the finding is real and exploitable — not how severe it is. Every finding that passes the FP gate starts at **100**.

**Deductions (apply all that fit):**

- Privileged caller required (owner, admin, multisig, governance) -> **-25**
- Attack path is partial (general idea is sound but cannot write exact caller -> call -> state change -> outcome) -> **-20**
- Impact is self-contained (only affects the attacker's own funds, no spillover to other users) -> **-15**

Confidence indicator: `[score]` (e.g., `[95]`, `[75]`, `[60]`).

## Bayesian Enhancement (for 60-80 range)

When the deduction-based score falls between 60-80 (the gray zone), apply Bayesian scoring for additional precision:

```
Confidence = (Evidence_Strength x Exploit_Feasibility x Impact_Severity) / False_Positive_Rate
```

### Evidence Strength (0-1)

| Score | Criteria                                       |
| ----- | ---------------------------------------------- |
| 1.0   | Concrete code path, no external dependencies   |
| 0.7   | Path depends on specific but achievable state  |
| 0.4   | Pattern-based theoretical vulnerability        |
| 0.1   | Heuristic suggestion without concrete evidence |

### Exploit Feasibility (0-1)

| Score | Criteria                                                      |
| ----- | ------------------------------------------------------------- |
| 1.0   | Single-transaction exploit, no setup required                 |
| 0.7   | Requires specific achievable contract state                   |
| 0.4   | Requires external conditions (oracle manipulation, MEV infra) |
| 0.1   | Theoretically possible, practically infeasible                |

### Impact Severity (1-5)

5=Complete fund loss/system compromise, 4=Partial loss/privilege escalation, 3=Griefing/DoS, 2=Info leak, 1=Best practice

### False Positive Rate Estimation

- 0.05: Well-known patterns (reentrancy without guard)
- 0.15: Moderate patterns (access control gaps)
- 0.40: Weak patterns (potential front-running)
- 0.60: Heuristic suggestions

### Resolution

If the Bayesian score (scaled to 0-100) diverges from the deduction score by more than 15 points, use the average. Otherwise keep the deduction score.

## Confidence Threshold

Default threshold: **75**. Findings below threshold are still included in the report table but do not get a **Fix** section — description only.

## Do Not Report

- Anything a linter, compiler, or seasoned developer would dismiss — INFO-level notes, gas micro-optimizations, naming, NatSpec, redundant comments.
- Owner/admin can set fees, parameters, or pause — these are by-design privileges, not vulnerabilities.
- Missing event emissions or insufficient logging.
- Centralization observations without a concrete exploit path (e.g., "owner could rug" with no specific mechanism beyond trust assumptions).
- Theoretical issues requiring implausible preconditions (e.g., compromised compiler, corrupt block producer, >50% token supply held by attacker).

**Exception:** Common ERC20 behaviors (fee-on-transfer, rebasing, blacklisting, pausing) are NOT implausible — if the code accepts arbitrary tokens, these are valid attack surfaces.
