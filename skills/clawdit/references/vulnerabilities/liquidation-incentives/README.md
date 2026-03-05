# Liquidation Incentive Vulnerabilities

## TLDR

When liquidation is unprofitable, nobody liquidates. Missing rewards, small positions below gas cost thresholds, collateral withdrawal exploits, missing bad debt mechanisms, and partial liquidation cherry-picking all lead to underwater positions accumulating as protocol bad debt.

## Vulnerability Patterns

### 1. No Liquidation Incentive
Trustless liquidators have no economic incentive — rewards/bonuses don't exceed gas costs. Liquidator only receives exact debt amount.
- **Severity: High** - Positions remain underwater indefinitely

### 2. No Incentive for Small Positions
Small positions below gas cost threshold are unprofitable to liquidate. Dust positions become protocol liabilities.
- **Severity: Medium** - Systemic insolvency risk from accumulated dust

### 3. Profitable User Withdraws All Collateral
Users with positive PNL can withdraw collateral while maintaining positions. If market reverses, 0 collateral + debt = guaranteed bad debt.
- **Severity: High** - Unliquidatable positions with zero collateral

### 4. No Bad Debt Handling Mechanism
Insolvent positions (debt > collateral) have no recovery mechanism. No insurance fund or socialization.
- **Severity: Critical** - Protocol absorbs losses directly

### 5. Partial Liquidation Cherry-Picking
Liquidators partially liquidate profitable portion, leaving bad debt with protocol. Take 840 from 900 collateral (with bonus on 800 debt), leave 200 debt + 60 collateral.
- **Severity: High** - Protocol subsidizes liquidators

### 6. No Partial Liquidation for Whales
Large positions exceed individual liquidator capital capacity. Cannot be liquidated in single transaction.
- **Severity: Medium** - Whale positions remain underwater

## Detection

Search terms: `LIQUIDATION_BONUS`, `MIN_DEBT_SIZE`, `MIN_COLLATERAL_RATIO`, `insuranceFund`, `partialLiquidate`, `withdrawCollateral`, `unrealizedPnL`

Red flags:
- Liquidation function transfers exact debt amount (no bonus)
- No minimum position/debt size enforced
- Collateral withdrawal only checks current PNL, not future risk
- `require(insuranceFund >= badDebt)` without fallback
- Partial liquidation doesn't check post-liquidation health
- Only full liquidation supported (`require(token.balanceOf(msg.sender) >= pos.debt)`)

## Audit Checklist

- [ ] **Liquidation rewards:** Bonus/rewards implemented exceeding typical gas costs
- [ ] **Minimum position size:** Enforced to ensure all positions profitable to liquidate
- [ ] **Collateral withdrawal restrictions:** Maintain minimum collateral ratio even in profit
- [ ] **Bad debt handling:** Insurance fund or socialization mechanism exists
- [ ] **Partial liquidation accounting:** Prevents cherry-picking, forces full liquidation when insolvent
- [ ] **Partial liquidation support:** Enabled for whale positions with proper constraints

## Economic Analysis Framework

**Without incentive:**
- Gas cost: ~$30 (150k gas, 50 gwei, $2000 ETH)
- Collateral seized: exact debt = $3000
- Net profit: $0 - $30 = -$30 loss. Unprofitable.

**With 5% bonus:**
- Gas cost: $30
- Collateral seized: debt + 5% = $3150
- Net profit: $150 - $30 = $120. Profitable.

**Minimum profitable position:** `gas_cost / bonus_percentage`
- 5% bonus, $30 gas = $600 minimum position

## Case Files

#### examples.md
Vulnerable and fixed code patterns for all 6 incentive patterns, including bonus implementation, minimum position sizing, collateral withdrawal restrictions, insurance fund handling, partial liquidation anti-cherry-picking, and whale position support.
