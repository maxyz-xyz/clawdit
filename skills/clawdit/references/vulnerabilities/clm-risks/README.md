# Concentrated Liquidity Manager (CLM) Vulnerabilities

## TLDR

CLMs managing Uniswap V3 / concentrated liquidity positions are vulnerable to MEV sandwich attacks on unprotected liquidity deployment, TWAP parameter manipulation by owners, dust accumulation from rounding errors, stale approval exploits on router updates, and retroactive fee increases on uncollected rewards.

## Vulnerability Patterns

### 1. Forced Unfavorable Liquidity Deployment
Some functions deploy liquidity without TWAP checks, allowing MEV bots to sandwich attack. `rebalance()` has TWAP check but `deposit()` does not — attacker sandwiches deposit at manipulated price.
- **Severity: High** - Protocol loses funds to sandwich attacks, immediate impermanent loss

### 2. Owner Rug-Pull via TWAP Parameters
Owner can set ineffective `maxDeviation` (100%) or `twapInterval` (1 second) that disable TWAP protection. Owner coordinates with MEV bot to sandwich protocol's liquidity deployments.
- **Severity: Medium** (admin-only, but enables rug pull)

### 3. Tokens Permanently Stuck
Rounding errors from Uniswap V3 `decreaseLiquidity`/`collect` leave dust tokens in contract. After 1000+ rebalances, accumulated dust can be significant. No sweep function to rescue.
- **Severity: Medium** - Protocol loses accumulated tokens permanently

### 4. Stale Token Approvals
Updating router/position manager address doesn't revoke approvals to old router. If old router is compromised, attacker drains all approved tokens.
- **Severity: High** - Full token drain if old router compromised

### 5. Retrospective Fee Application
Changing protocol fee percentage applies to already earned but uncollected rewards. Owner increases fee from 10% to 50%, then collects — users lose 40% more than expected.
- **Severity: Medium** - Users lose earned rewards retroactively

## Detection

Search terms: `_checkTWAP`, `maxDeviation`, `twapInterval`, `sqrtPriceX96`, `sqrtPriceTWAP`, `slot0`, `decreaseLiquidity`, `collect`, `approve`, `positionManager`, `protocolFeePercent`, `collectFees`, `setProtocolFee`

Red flags:
- Functions that call `_mintPosition()` or `addLiquidity()` without TWAP validation
- `setTWAPParams()` without min/max bounds on deviation and interval
- No `sweep()` or `rescue()` function for excess token balances
- `approve(newRouter, max)` without `approve(oldRouter, 0)` first
- `setProtocolFee()` without calling `collectFees()` first

## Audit Checklist

- [ ] **TWAP checks everywhere:** ALL functions deploying liquidity validate current price against TWAP
- [ ] **TWAP parameter bounds:** `maxDeviation` bounded (0.1%-5%), `twapInterval` bounded (5min-1hr)
- [ ] **No token accumulation:** No tokens stuck beyond active positions, or sweep function exists
- [ ] **Approval revocation:** Old approvals revoked before setting new router/manager
- [ ] **Fee immutability:** Fees collected before fee structure changes

## TWAP Validation Template

```solidity
function _checkTWAP() internal view {
    (uint160 sqrtPriceX96, , , , , , ) = pool.slot0();

    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval;
    secondsAgos[1] = 0;

    (int56[] memory tickCumulatives, ) = pool.observe(secondsAgos);
    int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 arithmeticMeanTick = int24(tickCumulativesDelta / int56(uint56(twapInterval)));

    uint160 sqrtPriceTWAP = TickMath.getSqrtRatioAtTick(arithmeticMeanTick);

    uint256 priceDiff = sqrtPriceX96 > sqrtPriceTWAP
        ? sqrtPriceX96 - sqrtPriceTWAP
        : sqrtPriceTWAP - sqrtPriceX96;

    require(
        priceDiff * 10000 / sqrtPriceTWAP <= maxDeviation,
        "Price deviation exceeded"
    );
}
```

## Case Files

#### examples.md
Vulnerable and fixed code patterns for all 5 CLM vulnerability types, including TWAP validation, parameter bounds, dust token rescue, approval management, and fee collection ordering. Includes a complete CLM sandwich attack example.
