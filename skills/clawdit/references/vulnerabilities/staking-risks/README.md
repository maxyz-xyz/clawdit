# Staking & Reward Vulnerabilities

## TLDR

Staking contracts are vulnerable to first-depositor front-running, reward dilution via direct token transfers, precision loss rounding rewards to zero, flash deposit/withdraw griefing, stale reward index after distribution, and balance caching bugs during claims.

## Vulnerability Patterns

### 1. Front-Running First Deposit
Attacker front-runs first deposit to become initial staker, steals initial rewards. Particularly dangerous when reward token = staking token (e.g., both WETH).
- **Severity: High** - First depositor steals all initial rewards

### 2. Reward Dilution via Direct Transfer
Sending staking tokens directly to contract inflates `totalSupply` (if using `balanceOf`) without proper accounting. Dilutes rewards for all legitimate stakers.
- **Severity: Medium** - Attacker reduces yield for all stakers

### 3. Precision Loss in Reward Calculation
Small stake amounts combined with large `totalSupply` cause rewards to round down to zero. `earned = 10 * (duration / 1000) / 1e18 = 0`.
- **Severity: Medium** - Small stakers permanently lose rewards

### 4. Flash Deposit/Withdraw Griefing
Large instant deposit followed by immediate withdrawal dilutes rewards for existing stakers in a single block without committing capital.
- **Severity: Medium** - Repeated griefing reduces everyone's yield

### 5. Update Not Called After Reward Distribution
`notifyRewardAmount()` doesn't call `updateReward()`, leaving `rewardPerTokenStored` stale. Next calculation uses wrong `lastUpdateTime`. Rewards double-counted or missed.
- **Severity: High** - Incorrect reward distribution

### 6. Balance Caching Issues
Claiming rewards incorrectly adds reward amount to staked balance. Subsequent `earned()` calculation uses inflated balance, enabling over-claiming.
- **Severity: High** - Double-claim exploits

## Detection

Search terms: `rewardPerToken`, `totalSupply`, `rewardRate`, `updateReward`, `notifyRewardAmount`, `earned`, `getReward`, `balanceOf(address(this))`, `MIN_DEPOSIT`, `LOCK_DURATION`

Red flags:
- `rewardToken == stakingToken` (same token)
- `totalSupply = stakingToken.balanceOf(address(this))` instead of tracked variable
- No minimum stake requirement
- No time lock on withdrawals
- `notifyRewardAmount()` without calling `updateReward()` first
- `balances[msg.sender] += reward` in claim function

## Audit Checklist

- [ ] **Separate tokens:** Reward token cannot be same as staking token
- [ ] **No direct transfer dilution:** `totalSupply` tracks staked amounts, not `balanceOf`
- [ ] **Precision protection:** Minimum stake enforced or sufficient scaling to prevent rounding to zero
- [ ] **Flash protection:** Time locks, minimum duration, or anti-sandwich mechanisms
- [ ] **Index updates:** `updateReward()` called before AND after reward distribution
- [ ] **Balance integrity:** Cached balances not modified during claims

## Key Protections

1. **Different tokens:** Reward token != staking token
2. **Tracked supply:** `totalSupply` separate from actual token balance
3. **Minimum stake:** Prevent precision loss (e.g., 1000 tokens minimum)
4. **Time lock:** Minimum 1 day lock prevents flash attacks
5. **Update timing:** Call `updateReward()` before reward distribution
6. **Balance integrity:** Don't modify stake balance during claims

## Case Files

#### examples.md
Vulnerable and fixed code patterns for all 6 staking vulnerability types, including first-depositor protection, dilution prevention, precision safeguards, flash griefing protection, reward index synchronization, and balance caching fixes. Includes a complete secure staking contract.
