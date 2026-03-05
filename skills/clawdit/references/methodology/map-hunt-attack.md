# Map-Hunt-Attack Methodology

## Core Principles

1. **Hypothesis-Driven Analysis** — Every potential issue is a hypothesis to falsify, not a conclusion to confirm. Actively search for reasons why something is NOT a bug before reporting.

2. **Cross-Reference Mandate** — Never validate a finding in isolation. Cross-check against protocol documentation, spec comments, related code paths, and protocol-level invariants.

3. **Devil's Advocate Protocol** — Before concluding exploitability, explicitly search for:
   - `require` statements, modifiers, or upstream validation that prevent exploitation
   - Whether the behavior is "by design" (documented in comments or specs)
   - Constraints in inherited contracts or imported libraries
   - Concrete values that make the attack economically infeasible

4. **Evidence Required** — Every confirmed finding must cite concrete evidence: specific line references, traced code path, and at least one supporting source (static analysis, CHEATSHEET pattern, or Solodit precedent).

5. **Privileged Roles Are Honest** — Assume owner/admin/governance roles act honestly unless the protocol explicitly states otherwise. Focus on what unprivileged users and external actors can exploit.

## The Four Phases

### Phase 1: MAP (Build System Understanding)

Before hunting for bugs, build a comprehensive system map:

**Components** — For each contract:

- Purpose (1-2 sentences)
- Key state variables (type and role)
- Roles/capabilities (who can call privileged functions)
- External surface: every `public`/`external` function with its access control, state writes, and external calls

**Invariants** — Identify:

- Local invariants (within a single contract)
- System-wide invariants (cross-contract properties)
- See `state-invariants.md` for the full invariant detection methodology

**Trust Boundaries** — Where does untrusted input enter? How does it propagate?

### Phase 2: HUNT (Systematic Hotspot Identification)

For each `public`/`external` function that writes state, moves value, or makes external calls:

1. Check against all 9 risk patterns (below)
2. Check against the CHEATSHEET vulnerability types
3. Evaluate against invariants from the MAP phase
4. Flag suspicious spots with: components involved, attacker type, related invariants, why suspicious, priority

### Phase 3: ATTACK (Deep Dive)

For each suspicious spot:

1. **Trace Call Path** — Read code, trace values through execution, map all external calls and state changes
2. **Construct Attack Narrative** — Define: attacker role, call sequence, which invariant breaks, what value is extracted
3. **Devil's Advocate** — Actively try to falsify the attack (see principles above)
4. **Verdict** — Either CONFIRMED (with full evidence) or DISMISSED (with specific refutation)

### Phase 4: VALIDATE (Cross-Reference)

For each confirmed finding:

- Search Solodit for similar real-world findings
- Check if static analysis (Slither/Aderyn) flagged the same code
- Verify the fix doesn't introduce new issues

## The 9 Risk Patterns

### 1. ERC-4626 Vault Share Inflation

First depositor mints 1 share for minimal deposit, donates tokens directly to vault, inflating share price. Subsequent depositors receive 0 shares due to rounding. Look for vaults without minimum deposit checks, missing virtual share offsets, no initial dead-share minting.

### 2. Oracle Staleness and Manipulation

Price oracles return stale data if staleness checks missing. TWAP oracles manipulated via flash loans or large swaps. Check freshness validation on every oracle read, fallback paths, manipulation-resistant configs.

### 3. Flash Loan Entry Points

Functions vulnerable when reading on-chain balances, computing prices from pool reserves, or checking collateral ratios in same transaction as flash loan. Verify balance-dependent logic uses snapshot or oracle pricing, not spot balances.

### 4. Rounding Direction in Share/Token Math

Integer division truncates toward zero. Deposits should round DOWN shares minted (favor vault). Withdrawals should round UP assets required (favor vault). Check `mulDiv` operations for explicit rounding parameters.

### 5. Upgradeable Proxy Storage Collisions

Storage slot layout changes cause silent corruption via `delegatecall`. Check `__gap` reservations, consistent inheritance ordering across versions, ERC-1967 compliance.

### 6. Cross-Contract Reentrancy via Callbacks

Reentrancy via ERC-777 hooks, ERC-721 `safeTransfer`, or flash loan receivers allows re-entering DIFFERENT contracts before state finalized. Apply checks-effects-interactions at protocol level, not just contract level.

### 7. Donation Attacks

Anyone can send ETH via `selfdestruct` or transfer tokens directly, bypassing accounting. If contract uses `address(this).balance` or `token.balanceOf(address(this))` for pricing/shares/solvency, those values are manipulable. Internal accounting variables are safe; raw balance queries are not.

### 8. Missing Slippage Protection

AMM swaps and vault operations without minimum output checks are vulnerable to sandwich attacks. Verify swap functions accept and enforce `minAmountOut` or `deadline`.

### 9. Unchecked Return Values on Token Transfers

Some ERC-20 tokens (USDT, BNB, OMG) return `false` on failure instead of reverting. Using `transfer()` or `transferFrom()` directly causes accounting discrepancies. Use `SafeERC20.safeTransfer()`.
