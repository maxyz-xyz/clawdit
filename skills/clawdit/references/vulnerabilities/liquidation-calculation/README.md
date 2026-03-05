# Liquidation Calculation Vulnerabilities

## TLDR

Decimal precision errors, fee ordering bugs, missing yield in collateral valuation, and oracle-gameable self-liquidation can make liquidations unprofitable, unfair, or exploitable. 65%+ of lending protocol hacks involve liquidation mechanism failures.

## Vulnerability Patterns

### 1. Incorrect Liquidator Reward Calculation

Decimal precision errors in reward calculations result in rewards that are too small (unusable) or too large (protocol insolvency).

- Hardcoding `1e18` when collateral uses 6 decimals (USDC) yields reward = 0
- Reward calculations must match collateral token decimals
- **Severity: Critical** - Prevents all liquidations or causes insolvency

### 2. Unprioritized Liquidator Reward

Liquidator rewards paid after other fees (protocol fees, penalties) can be reduced to zero.

- If protocol fee taken first: `reward = collateral - protocolFee - debt`
- If protocol fee large enough: `reward = 0`, no liquidation incentive
- **Severity: High** - Removes liquidation incentive, bad debt accumulates

### 3. Excessive Protocol Fee

Protocol fees >30% of seized collateral make liquidation unprofitable after gas costs.

- 10% bonus, 5% protocol fee = 5% net = unprofitable for small positions
- Gas costs: ~$5-$50 depending on chain
- **Severity: High** - Makes liquidation unprofitable

### 4. Missing Liquidation Fees in Minimum Collateral

Minimum collateral requirements that don't account for liquidation costs (gas + fees).

- If minimum = debt: no reward for liquidator at threshold
- Minimum should be: `debt + liquidation_costs + buffer`
- **Severity: Medium** - Allows unliquidatable positions at minimum

### 5. Unaccounted Yield/PNL in Collateral Valuation

Earned yield or positive PNL not included in collateral value causes unfair liquidations.

- Collateral value should include: deposited + earned_yield + positive_PNL
- Particularly critical in yield-bearing vaults and perpetuals
- **Severity: High** - Users liquidated despite being solvent

### 6. No Swap Fee During Liquidation

Liquidation swaps bypass protocol swap fees, losing revenue.

- Normal swaps charge 0.3% fee; liquidation swaps should too
- Not a security issue but economic inefficiency
- **Severity: Medium** - Protocol loses revenue

### 7. Oracle Sandwich Self-Liquidation

Users trigger oracle price updates to create profitable self-liquidation opportunities.

- User triggers oracle update when favorable, then immediately self-liquidates via alt account
- Liquidation bonus extracted as profit
- **Severity: Critical** - Direct value extraction via oracle manipulation

## Detection

Search terms: `liquidationReward`, `liquidationBonus`, `calculateReward`, `protocolFee`, `protocolFeeRate`, `getCollateralValue`, `isLiquidatable`, `getPNL`, `getYield`, `_swap`, `swapFee`

Red flags:
- `1e18` hardcoded in reward calculations with multi-decimal tokens
- Protocol fee deducted before liquidator reward
- `userDeposits[user]` instead of `vault.balanceOf(user)` for yield vaults
- No `require(msg.sender != user)` in liquidation functions
- Permissionless oracle update without liquidation delay

## Audit Checklist

### Decimal Precision
- [ ] Liquidator rewards scaled to collateral token decimals
- [ ] No hardcoded 1e18 assumptions
- [ ] Reward calculations tested with 6/8/18 decimal tokens
- [ ] Bonus percentage applied correctly (e.g., 110% = debt * 11/10)
- [ ] No overflow/underflow in reward calculations

### Fee Priority
- [ ] Liquidator reward calculated before protocol fees
- [ ] Protocol fees taken from remaining balance after reward
- [ ] Reward amount not reduced by other fees
- [ ] No edge cases where reward = 0 due to other fees

### Fee Economics
- [ ] Protocol fee <30% of liquidation bonus
- [ ] Net liquidator reward > gas costs for minimum positions
- [ ] Fee structure analyzed for different position sizes
- [ ] Minimum profitable position size documented

### Minimum Collateral
- [ ] Minimum accounts for: debt + liquidation_bonus + protocol_fee + gas_buffer
- [ ] Positions at minimum threshold profitably liquidatable
- [ ] Buffer accounts for gas price volatility

### Yield/PNL Inclusion
- [ ] Collateral value includes earned yield
- [ ] Positive PNL included in collateral calculations
- [ ] Yield-bearing tokens use current balance not deposit
- [ ] PNL updated before liquidation checks

### Self-Liquidation Protection
- [ ] Self-liquidation restricted (`msg.sender != user`)
- [ ] Oracle update delays prevent sandwich liquidation
- [ ] Multiple oracle price sources prevent manipulation

## Position Size Analysis

For each finding, calculate:

1. **Minimum profitable position**: `gas_cost / net_liquidator_reward_percentage`
2. **Break-even collateral ratio**: `debt * (1 + liquidation_costs / liquidation_bonus)`
3. **Maximum protocol fee before unprofitable**: `liquidation_bonus - (gas_cost / position_size)`

Gas cost estimates:
- Ethereum mainnet: ~$30-60 (simple-complex)
- L2s (Arbitrum/Optimism): ~$0.50-1
- BSC/Polygon: ~$0.10-0.20

## False Positives

**DO NOT flag:**
1. Trusted liquidator systems (admin/keeper bots) - profitability not required
2. Documented fee structures with alternative incentives
3. Yield distribution delays for gas optimization (if documented)
4. Admin-only oracle updates (no user manipulation risk)
5. Fixed reward structures with profitability analysis provided

**DO flag:**
1. Trustless liquidations without profitability guarantees
2. Undocumented fee priorities
3. Missing yield in calculations (even if documented - causes unfair liquidations)
4. User-triggered oracles without delays/restrictions
5. Self-liquidation allowed (even if documented - enables value extraction)

## Case Files

Run `cat` on any file in this directory for detailed vulnerable/fixed code examples:

#### examples.md
Complete vulnerable and secure code patterns for all 7 vulnerability types, including a full secure liquidation contract example.
