# Liquidation Denial of Service Vulnerabilities

## TLDR

Attackers can prevent liquidation of underwater positions through gas exhaustion, data structure corruption, front-running, callback reverts, and token blocklist exploitation. Unliquidatable positions accumulate bad debt, leading to protocol insolvency.

## Vulnerability Patterns

### 1. Many Small Positions DoS
Iterating over unbounded user positions array causes out-of-gas revert. Attacker creates many small positions, liquidation runs out of gas.

### 2. Multiple Positions Corruption
EnumerableSet ordering corruption when positions removed during iteration. `remove()` during iteration skips positions.

### 3. Front-Run Prevention
Users change nonce or perform small self-liquidation to invalidate liquidator's transaction. Liquidation depends on exact state user can modify.

### 4. Pending Action Prevention
Pending withdrawals equal to balance force liquidation reverts on transfer. Users queue withdrawals to make liquidation revert.

### 5. Malicious Callback Prevention
`onERC721Received` or ERC20 hooks revert during collateral seizure. Malicious borrowers prevent liquidation via reverting callbacks.

### 6. Yield Vault Collateral Hiding
Collateral deposited in external vaults not seized during liquidation. Protocol only checks `collateralInProtocol[user]`, misses vault balances.

### 7. Insurance Fund Insufficient
Bad debt exceeding insurance fund causes liquidation revert (`require(insuranceFund >= badDebt)` without fallback). Insolvent positions cannot be cleared.

### 8. Fixed Bonus Insufficient Collateral
Fixed 110% liquidation bonus fails when collateral ratio < 110%. Underwater positions with low collateral ratios become unliquidatable.

### 9. Non-18 Decimal Reverts
Hardcoded `1e18` assumptions cause underflow/overflow for tokens with 6/8 decimals. Liquidation reverts for USDC, WBTC.

### 10. Multiple nonReentrant Modifiers
Complex liquidation paths hit multiple `nonReentrant` guards, causing "ReentrancyGuard: reentrant call" revert on internal functions.

### 11. Zero Value Transfer Reverts
Some tokens revert on zero transfer. Edge cases with zero amounts (bad debt positions) cause liquidation to revert.

### 12. Token Deny List Reverts
USDC-style blocklists prevent liquidation token transfers when borrower blacklisted. Blacklisted borrowers cannot be liquidated.

### 13. Single Borrower Edge Case
Protocol assumes >1 borrower. `share = debt / (totalBorrowers - 1)` causes division by zero with single borrower.

## Detection

Search terms: `positions.length`, `EnumerableSet`, `nonces[user]`, `pendingWithdrawals`, `safeTransferFrom`, `onERC721Received`, `insuranceFund`, `LIQUIDATION_BONUS`, `nonReentrant`

Red flags:
- `for (uint i = 0; i < positions.length; i++)` without bounds
- `EnumerableSet.remove()` called inside iteration loop
- Liquidation depends on nonce or state user can modify
- `safeTransferFrom` in liquidation path (callbacks)
- `require(insuranceFund >= badDebt)` without fallback
- Hardcoded `1e18` in decimal-sensitive calculations
- Multiple `nonReentrant` modifiers in call chain

## Audit Checklist

- [ ] **No unbounded loops:** Liquidation doesn't iterate over user-controlled arrays without max bounds
- [ ] **Data structure integrity:** EnumerableSet/mapping operations safe during liquidation
- [ ] **Front-run resistance:** Liquidation doesn't depend on exact state user can modify
- [ ] **Pending actions:** Withdrawals/deposits don't block liquidation transfers
- [ ] **Callback isolation:** Token callbacks cannot revert liquidation (use low-level calls or checks)
- [ ] **All collateral seized:** Checks both protocol and external vault collateral
- [ ] **Graceful bad debt:** Liquidation works even when bad debt exceeds insurance fund
- [ ] **Dynamic bonus:** Liquidation bonus capped at available collateral, no fixed assumptions
- [ ] **Decimal handling:** Correct conversions for all token decimals (6, 8, 18)
- [ ] **No reentrancy conflicts:** Single nonReentrant in liquidation path or proper guard placement
- [ ] **Zero transfer checks:** Skip transfers when amount == 0 for strict tokens
- [ ] **Deny list handling:** Liquidation routes through protocol, not directly to blacklisted addresses
- [ ] **Edge case validation:** Works with single borrower, zero positions, etc.

## Key Protections Summary

1. **Bounded iteration:** Liquidate by position ID, enforce max positions
2. **Safe data structures:** Don't modify EnumerableSet during iteration
3. **No nonce dependency:** Liquidation independent of user state
4. **Cancel pending actions:** Clear withdrawals during liquidation
5. **Callback isolation:** Use `transferFrom` or try/catch for callbacks
6. **Check all collateral:** Include external vaults
7. **Graceful bad debt:** Track uncovered losses, don't revert
8. **Dynamic bonus:** Cap at available collateral
9. **Decimal handling:** Use actual token decimals
10. **Single reentrancy guard:** Only on external entry point
11. **Zero checks:** Skip transfers when amount == 0
12. **Claimable pattern:** For deny lists, don't transfer directly to users
13. **Edge case validation:** Handle n=1 borrower, n=0 positions

## Case Files

#### examples.md
Vulnerable and fixed code patterns for all 13 DoS patterns, including unbounded loops, EnumerableSet corruption, front-running, callback isolation, insurance fund handling, dynamic bonus, deny list workarounds, and single borrower edge cases.
