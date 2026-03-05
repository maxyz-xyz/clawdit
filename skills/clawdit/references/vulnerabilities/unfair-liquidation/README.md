# Unfair Liquidation Vulnerabilities

## TLDR

Users can be liquidated unfairly through L2 sequencer downtime without grace periods, asymmetric pause mechanics, stale interest calculations, lost PNL/yield during settlement, collateral cherry-picking, and missing LTV gaps. These are distinct from liquidation *calculation* bugs — they affect liquidation *fairness and timing*.

## Vulnerability Patterns

### 1. Missing L2 Sequencer Grace Period
Users on L2 chains liquidated immediately when sequencer restarts after downtime, with no time to respond to price changes. Mass unfair liquidations.

### 2. Interest Accumulates While Paused
Interest/fees continue accruing while protocol is paused, causing users to become liquidatable without ability to repay.

### 3. Repayment Paused, Liquidation Active
Protocol pauses repayments but liquidation remains active. Users have no way to defend positions.

### 4. Late Interest/Fee Updates
`isLiquidatable()` uses stale interest values, not calling `accrueInterest()` first. Liquidation based on stale data.

### 5. Lost Positive PNL/Yield
Profitable positions with unrealized gains or earned yield lose these during liquidation settlement. Users lose more than necessary.

### 6. Unhealthier Post-Liquidation State
Liquidator cherry-picks stable collateral (USDC, WETH), leaving borrower with only volatile assets. Cascading liquidations more likely.

### 7. Corrupted Collateral Priority
Liquidation order doesn't match risk profile. Volatile assets should be liquidated first to reduce systemic risk.

### 8. Borrower Replacement Misattribution
After position transfer, original borrower's repayments credited to new owner.

### 9. No LTV Gap
Borrow LTV equals liquidation LTV. Any price movement triggers immediate liquidation after borrowing.

### 10. Interest During Auction
Borrowers continue accruing interest while position is being auctioned. Auction proceeds may not cover inflated debt.

### 11. No Liquidation Slippage Protection
Liquidators cannot specify minimum acceptable rewards. MEV can sandwich liquidation transactions.

## Detection

Search terms: `sequencerFeed`, `GRACE_PERIOD`, `repaymentsPaused`, `liquidationsPaused`, `accrueInterest`, `isLiquidatable`, `unrealizedPnL`, `earnedYield`, `collateralIndex`, `MAX_LTV`, `LIQUIDATION_THRESHOLD`, `inAuction`, `minReward`

Red flags:
- Sequencer uptime check without grace period after restart
- Separate pause flags for repayment vs liquidation
- `isLiquidatable()` as `view` function that doesn't accrue interest first
- `MAX_LTV == LIQUIDATION_THRESHOLD` (no gap)
- Liquidator chooses which collateral to seize
- No `frozenDebt` during auction period

## Audit Checklist

- [ ] **L2 sequencer grace period:** Grace period (1hr+) after sequencer restart before liquidations enabled
- [ ] **Interest during pause:** Interest accrual paused when repayments paused, OR liquidation also paused
- [ ] **Synchronized pause states:** Repayment pause also pauses liquidation
- [ ] **Fee updates before check:** All interest/fees accrued before `isLiquidatable()` evaluation
- [ ] **PNL/yield credit:** Positive unrealized PNL and earned yield credited during liquidation settlement
- [ ] **Health improvement:** Liquidation improves borrower health score, not just extracts value
- [ ] **Risk-based priority:** Collateral liquidated in order of risk (volatile before stable)
- [ ] **Position transfer handling:** Repayments routed correctly after position ownership transfer
- [ ] **LTV gap exists:** Gap between max borrow LTV and liquidation threshold (e.g., 80% borrow, 85% liquidate)
- [ ] **Auction interest pause:** Interest paused during liquidation auction period
- [ ] **Liquidator slippage:** Liquidation accepts minReward/maxDebt for slippage protection

## Case Files

#### examples.md
Vulnerable and fixed code patterns for all 11 fairness patterns, including L2 sequencer grace periods, symmetric pause mechanics, interest accrual timing, PNL credit, collateral priority, LTV gaps, auction interest freezing, and slippage protection.
