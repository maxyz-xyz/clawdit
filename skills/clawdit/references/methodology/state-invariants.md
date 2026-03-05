# State Invariant Detection Methodology

## What It Does

Automatically infers mathematical relationships between state variables, then finds functions that break those relationships. 65-70% of major DeFi hacks involve state invariant violations.

## Five Invariant Types

### Type 1: Sum (Aggregation)

```
totalSupply = Σ balance[i] for all users i
```

Found in: ERC20 tokens, staking pools, vaults, share systems

### Type 2: Difference (Conservation)

```
totalFunds = availableFunds + lockedFunds
```

Found in: Treasuries, liquidity pools, vesting contracts

### Type 3: Ratio (Proportional)

```
k = reserveA × reserveB  (constant product)
sharePrice = totalAssets / totalShares
```

Found in: AMMs, DEXs, vault share pricing, collateralization

### Type 4: Monotonic (Ordering)

```
newValue ≥ oldValue  (only increases)
```

Found in: Timestamps, nonces, accumulated rewards, total distributions

### Type 5: Synchronization (Coupling)

```
If stateA changes, stateB must change correspondingly
```

Found in: Deposit/mint pairs, burn/release pairs, collateral/borrowing power

## Three-Phase Detection

### Phase 1: State Variable Clustering

For each pair of state variables (A, B):

1. Track all functions that modify A
2. Track all functions that modify B
3. Calculate co-modification frequency:

```
CoMod(A, B) = |Functions modifying both A and B| / |Functions modifying A or B|
```

4. If CoMod(A, B) > 0.6 → A and B are likely related

### Phase 2: Invariant Inference

**Delta Pattern Matching:**

```
mint():     Δtotal = +amount, Δbalance = +amount  → Same direction, same magnitude
burn():     Δtotal = -amount, Δbalance = -amount  → Same direction, same magnitude
transfer(): Δbalance1 = -x, Δbalance2 = +x        → Net zero change

Inference: totalSupply = Σ balances (Aggregation invariant)
```

**Delta Correlation:**

```
If ΔA = ΔB in all cases      → Direct proportional (A = B + constant)
If ΔA = -ΔB in all cases     → Inverse proportional (A + B = constant)
If ΔA × constant = ΔB        → Ratio relationship
If ΔA occurs whenever ΔB     → Synchronization invariant
```

**Expression Mining:**

```solidity
// Code: available = total - locked;
// Extracted: available + locked = total
// Inferred: Conservation law

// Code: shares = assets * PRECISION / sharePrice;
// Extracted: shares * sharePrice = assets * PRECISION
// Inferred: Ratio invariant
```

**Invariant Confidence:**

| Confidence                      | Classification     |
| ------------------------------- | ------------------ |
| ≥ 90% of functions preserve it  | STRONG invariant   |
| 70-89% of functions preserve it | MODERATE invariant |
| < 70% of functions preserve it  | WEAK/NO invariant  |

### Phase 3: Violation Detection

For each inferred invariant I(stateA, stateB) and each function F that modifies stateA or stateB:

```
Before: Capture (stateA, stateB)
Simulate: Execute F
After: Capture (stateA', stateB')

If I(stateA, stateB) = True AND I(stateA', stateB') = False:
  → F is VULNERABLE
```

Only flag violations that **persist at function exit**. Temporary mid-function violations that revert or self-correct are not bugs.

## Quick Detection Checklist

- Does every function that modifies `balances` also update `totalSupply` (or have a valid zero-sum reason not to)?
- Does every function that moves between `available` and `locked` maintain `total = available + locked`?
- Does every swap function maintain the constant product `k = reserveA * reserveB`?
- Do aggregate counters (`totalStaked`, `totalRewards`) stay in sync with per-user mappings?
- Are monotonic variables (nonces, timestamps, cumulative counters) ever decremented?
- When one variable in a coupled pair changes, does the other always update?

## Common Violation Patterns

**The Broken Totalizer:** `adminBurn()` reduces `balances[user]` without reducing `totalSupply`. Protocol reports inflated market cap, share pricing breaks.

**The Desynced Pool:** `compoundRewards()` moves value from `userRewards` to `userStake` but updates neither `totalRewards` nor `totalStaked`. Aggregates drift permanently.

**The Broken AMM:** `adminAdjustReserve()` changes `reserveA` without recalculating `k`. Constant product violated, arbitrage possible.

**The Conservation Violation:** `emergencyUnlock()` increases `availableFunds` without decreasing `lockedFunds`. Funds created from nothing.

## Real-World Examples

| Hack                   | Invariant Violated                          | Loss  |
| ---------------------- | ------------------------------------------- | ----- |
| The DAO (2016)         | `contract_balance = Σ user_balances`        | $60M  |
| Poly Network (2021)    | Cross-chain asset conservation              | $600M |
| Indexed Finance (2021) | Pool weight proportionality (spot vs TWAP)  | $16M  |
| Audius (2022)          | Governance token supply = Σ delegated votes | $6M   |

## Rationalizations to Reject

- "The totalSupply is just for display" → Protocols use it for share pricing, voting power, and market cap
- "Admin functions can bypass invariants" → Broken accounting creates permanent insolvency
- "The difference is small" → Small errors compound across transactions
- "It's an emergency function" → Emergency functions that break invariants create worse emergencies
- "Transfer doesn't need to update totalSupply" → Correct, but verify net change in `Σ balances` is zero
