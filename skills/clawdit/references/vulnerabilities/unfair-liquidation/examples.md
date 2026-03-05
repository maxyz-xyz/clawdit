# Unfair Liquidation Vulnerability Examples

## Pattern 1: Missing L2 Sequencer Grace Period

### Vulnerable
```solidity
contract VulnerableL2Lending {
    ISequencerUptimeFeed public sequencerFeed;

    function liquidate(address user) external {
        (, int256 answer, , , ) = sequencerFeed.latestRoundData();
        require(answer == 0, "Sequencer down");
        // Users liquidated immediately when sequencer restarts
        require(isLiquidatable(user), "Not liquidatable");
        _executeLiquidation(user);
    }
}
```

### Fixed
```solidity
contract FixedL2Lending {
    ISequencerUptimeFeed public sequencerFeed;
    uint256 public constant GRACE_PERIOD = 1 hours;

    function liquidate(address user) external {
        (, int256 answer, uint256 startedAt, , ) = sequencerFeed.latestRoundData();
        require(answer == 0, "Sequencer down");
        uint256 timeSinceUp = block.timestamp - startedAt;
        require(timeSinceUp >= GRACE_PERIOD, "Grace period active");
        require(isLiquidatable(user), "Not liquidatable");
        _executeLiquidation(user);
    }
}
```

## Pattern 2: Interest Accumulates While Paused

### Vulnerable
```solidity
contract VulnerableInterestAccrual {
    bool public repaymentsPaused;

    function accrueInterest() public {
        // Interest accrues even during pause
        uint256 elapsed = block.timestamp - lastAccrualTime;
        accumulatedInterest += calculateInterest(elapsed);
        lastAccrualTime = block.timestamp;
    }

    function repay(uint256 amount) external {
        require(!repaymentsPaused, "Repayments paused");
        // Users can't repay but interest keeps growing
    }

    function liquidate(address user) external {
        accrueInterest();
        require(isLiquidatable(user), "Not liquidatable");
        // Liquidation allowed even during repayment pause
    }
}
```

### Fixed
```solidity
contract FixedInterestAccrual {
    bool public repaymentsPaused;

    function accrueInterest() public {
        if (repaymentsPaused) return; // Don't accrue during pause
        uint256 elapsed = block.timestamp - lastAccrualTime;
        accumulatedInterest += calculateInterest(elapsed);
        lastAccrualTime = block.timestamp;
    }

    function unpauseRepayments() external onlyOwner {
        repaymentsPaused = false;
        lastAccrualTime = block.timestamp; // Skip paused period
    }
}
```

## Pattern 3: Repayment Paused, Liquidation Active

### Vulnerable
```solidity
function pauseRepayments() external onlyOwner {
    repaymentsPaused = true;
    // Liquidations remain active - users cannot defend positions
}
```

### Fixed
```solidity
function pauseOperations() external onlyOwner {
    operationsPaused = true;
    // Both repayments AND liquidations paused together
}

function liquidate(address user) external {
    require(!operationsPaused, "Operations paused");
    require(isLiquidatable(user), "Not liquidatable");
    _executeLiquidation(user);
}
```

## Pattern 4: Late Interest/Fee Updates

### Vulnerable
```solidity
function isLiquidatable(address user) public view returns (bool) {
    // Uses cached debt without accruing pending interest
    return userDebt[user] > getCollateralValue(user) * 100 / 125;
}

function liquidate(address user) external {
    require(isLiquidatable(user), "Not liquidatable");
    accrueInterest(); // Interest accrued AFTER check
    updateUserDebt(user); // Actual debt may be different
    _executeLiquidation(user);
}
```

### Fixed
```solidity
function isLiquidatable(address user) public returns (bool) {
    accrueInterest(); // Accrue FIRST
    updateUserDebt(user);
    return userDebt[user] > getCollateralValue(user) * 100 / 125;
}
```

## Pattern 5: Lost Positive PNL/Yield

### Vulnerable
```solidity
function liquidate(address user) external {
    Position memory pos = positions[user];
    // Positive PnL and yield ignored
    uint256 collateralToSeize = pos.debt * 105 / 100;
    // User loses earned profits
    _seizeCollateral(user, collateralToSeize);
    delete positions[user];
}
```

### Fixed
```solidity
function liquidate(address user) external {
    Position memory pos = positions[user];
    int256 effectiveValue = int256(pos.collateral) + pos.unrealizedPnL + int256(pos.earnedYield);
    uint256 debtWithBonus = pos.debt * 105 / 100;

    if (effectiveValue > int256(debtWithBonus)) {
        uint256 excess = uint256(effectiveValue) - debtWithBonus;
        _returnToUser(user, excess);
    }
    _seizeCollateral(user, pos.collateral);
    delete positions[user];
}
```

## Pattern 6: Unhealthier Post-Liquidation (Cherry-Picking)

### Vulnerable
```solidity
// Liquidator chooses which collateral to seize
function liquidate(address user, uint256 collateralIndex) external {
    Collateral storage col = userCollateral[user][collateralIndex];
    // Liquidator picks USDC (stable), leaves BTC (volatile)
    _seizeCollateral(user, col.token, col.amount);
}
```

### Fixed
```solidity
function liquidate(address user) external {
    Collateral[] storage cols = userCollateral[user];
    for (uint i = 0; i < cols.length; i++) {
        uint256 maxRiskIndex = _findHighestRisk(cols);
        _seizeCollateral(user, cols[maxRiskIndex].token, cols[maxRiskIndex].amount);
        if (!isLiquidatable(user)) break;
    }
    require(isHealthier(user), "Health must improve");
}
```

## Pattern 9: No LTV Gap

### Vulnerable
```solidity
uint256 public constant MAX_LTV = 8000; // 80%
uint256 public constant LIQUIDATION_THRESHOLD = 8000; // 80%
// Borrow at 80% LTV, any price drop = instant liquidation
```

### Fixed
```solidity
uint256 public constant MAX_LTV = 7500; // 75% max borrow
uint256 public constant LIQUIDATION_THRESHOLD = 8500; // 85% liquidation
// 10% gap: ~13% price drop needed before liquidation
```

## Pattern 10: Interest During Auction

### Vulnerable
```solidity
function settleAuction(uint256 auctionId) external {
    Auction memory auction = auctions[auctionId];
    accrueInterest(); // Interest continued during 24h auction
    uint256 currentDebt = userDebt[auction.borrower];
    // currentDebt > startDebt, proceeds may not cover
}
```

### Fixed
```solidity
function startAuction(address user) external {
    accrueInterest();
    inAuction[user] = true;
    auctions[nextAuctionId++] = Auction({
        borrower: user,
        startTime: block.timestamp,
        frozenDebt: userDebt[user] // Freeze at auction start
    });
}

function accrueInterest() public {
    for (address user : activeUsers) {
        if (inAuction[user]) continue; // Skip users in auction
        _accrueForUser(user);
    }
}

function settleAuction(uint256 auctionId) external {
    Auction memory auction = auctions[auctionId];
    _settleLiquidation(auction.borrower, auction.frozenDebt);
    inAuction[auction.borrower] = false;
}
```

## Pattern 11: No Liquidation Slippage Protection

### Vulnerable
```solidity
function liquidate(address user, uint256 debtToCover) external {
    require(isLiquidatable(user), "Not liquidatable");
    uint256 reward = calculateReward(debtToCover);
    // No slippage protection - MEV can sandwich
    token.transferFrom(msg.sender, address(this), debtToCover);
    collateral.transfer(msg.sender, reward);
}
```

### Fixed
```solidity
function liquidate(
    address user,
    uint256 debtToCover,
    uint256 minReward,
    uint256 maxDebtAccepted
) external {
    require(isLiquidatable(user), "Not liquidatable");
    uint256 actualDebt = getActualDebt(user);
    require(actualDebt <= maxDebtAccepted, "Debt changed");
    uint256 reward = calculateReward(debtToCover);
    require(reward >= minReward, "Reward below minimum");
    token.transferFrom(msg.sender, address(this), debtToCover);
    collateral.transfer(msg.sender, reward);
}
```
