# Liquidation Incentive Vulnerability Examples

## Pattern 1: No Liquidation Incentive

### Vulnerable
```solidity
function liquidate(address user) external {
    Position memory pos = positions[user];
    require(isLiquidatable(pos), "Not liquidatable");
    // No bonus - liquidator only gets exact debt amount
    uint256 collateralToLiquidator = pos.debt;
    token.transferFrom(msg.sender, address(this), pos.debt);
    token.transfer(msg.sender, collateralToLiquidator);
    // Gas costs make this unprofitable
    delete positions[user];
}
```

### Fixed
```solidity
uint256 public constant LIQUIDATION_BONUS = 1050; // 5% bonus
uint256 public constant BASIS_POINTS = 10000;

function liquidate(address user) external {
    Position memory pos = positions[user];
    require(isLiquidatable(pos), "Not liquidatable");
    uint256 liquidatorPayout = (pos.debt * LIQUIDATION_BONUS) / BASIS_POINTS;
    token.transferFrom(msg.sender, address(this), pos.debt);
    token.transfer(msg.sender, liquidatorPayout);
    delete positions[user];
}
```

## Pattern 2: No Incentive for Small Positions

### Vulnerable
```solidity
function openPosition(uint256 collateralAmount, uint256 borrowAmount) external {
    // Allows positions as small as 1 wei
    positions[msg.sender] = Position({collateral: collateralAmount, debt: borrowAmount});
    // Tiny position: 0.01 ETH debt, 5% bonus = 0.0005 ETH, gas = 0.05 ETH
    // Net loss: -0.0495 ETH. Nobody liquidates.
}
```

### Fixed
```solidity
uint256 public constant MIN_DEBT_SIZE = 1000e18;

function openPosition(uint256 collateralAmount, uint256 borrowAmount) external {
    require(borrowAmount >= MIN_DEBT_SIZE, "Position too small");
    positions[msg.sender] = Position({collateral: collateralAmount, debt: borrowAmount});
}

function partialRepay(uint256 amount) external {
    Position storage pos = positions[msg.sender];
    uint256 remaining = pos.debt - amount;
    require(remaining == 0 || remaining >= MIN_DEBT_SIZE, "Would leave unprofitable position");
    pos.debt = remaining;
}
```

## Pattern 3: Collateral Withdrawal Exploit

### Vulnerable
```solidity
function withdrawCollateral(uint256 amount) external {
    Position storage pos = positions[msg.sender];
    require(pos.unrealizedPnL > 0, "Not profitable");
    require(amount <= pos.collateral, "Insufficient");
    pos.collateral -= amount;
    token.transfer(msg.sender, amount);
    // If market reverses: 0 collateral + debt = guaranteed bad debt
}
```

### Fixed
```solidity
uint256 public constant MIN_COLLATERAL_RATIO = 1500; // 150%

function withdrawCollateral(uint256 amount) external {
    Position storage pos = positions[msg.sender];
    uint256 remainingCollateral = pos.collateral - amount;
    uint256 requiredCollateral = (pos.debt * MIN_COLLATERAL_RATIO) / 10000;
    require(remainingCollateral >= requiredCollateral, "Would violate collateral ratio");
    pos.collateral = remainingCollateral;
    token.transfer(msg.sender, amount);
}
```

## Pattern 4: No Bad Debt Handling

### Vulnerable
```solidity
function liquidate(address user) external {
    Position memory pos = positions[user];
    // Insolvent: debt > collateral
    token.transferFrom(msg.sender, address(this), pos.debt);
    token.transfer(msg.sender, pos.collateral);
    // Loss: pos.debt - pos.collateral absorbed by protocol
    // No insurance fund, no socialization
    totalDebt -= pos.debt;
    totalCollateral -= pos.collateral;
    delete positions[user];
}
```

### Fixed
```solidity
uint256 public insuranceFund;

function liquidate(address user) external {
    Position memory pos = positions[user];
    require(isLiquidatable(pos), "Not liquidatable");

    if (pos.debt > pos.collateral) {
        uint256 badDebt = pos.debt - pos.collateral;
        token.transferFrom(msg.sender, address(this), pos.collateral);
        token.transfer(msg.sender, pos.collateral);
        require(insuranceFund >= badDebt, "Insufficient insurance");
        insuranceFund -= badDebt;
        emit BadDebtSocialized(user, badDebt);
    } else {
        uint256 payout = (pos.debt * 1050) / 10000;
        token.transferFrom(msg.sender, address(this), pos.debt);
        token.transfer(msg.sender, payout);
    }
    delete positions[user];
}
```

## Pattern 5: Partial Liquidation Cherry-Picking

### Vulnerable
```solidity
function partialLiquidate(address user, uint256 debtToCover) external {
    Position memory pos = positions[user];
    require(isLiquidatable(pos), "Not liquidatable");
    uint256 collateralToLiquidator = (debtToCover * 1050) / 10000;
    token.transferFrom(msg.sender, address(this), debtToCover);
    token.transfer(msg.sender, collateralToLiquidator);
    positions[user].debt -= debtToCover;
    positions[user].collateral -= collateralToLiquidator;
    // If underwater: liquidator takes profitable portion, leaves bad debt
    // 1000 debt, 900 collateral: liquidate 800, take 840, leave 200 debt + 60 collateral
}
```

### Fixed
```solidity
function partialLiquidate(address user, uint256 debtToCover) external {
    Position memory pos = positions[user];
    require(isLiquidatable(pos), "Not liquidatable");

    if (pos.debt > pos.collateral) {
        revert("Position insolvent, must fully liquidate");
    }

    uint256 collateralToLiquidator = (debtToCover * 1050) / 10000;
    require(
        pos.collateral - collateralToLiquidator >=
        (pos.debt - debtToCover) * 1200 / 10000,
        "Would leave unhealthy position"
    );

    token.transferFrom(msg.sender, address(this), debtToCover);
    token.transfer(msg.sender, collateralToLiquidator);
    positions[user].debt -= debtToCover;
    positions[user].collateral -= collateralToLiquidator;
}
```

## Pattern 6: No Partial Liquidation for Whales

### Vulnerable
```solidity
function liquidate(address user) external {
    Position memory pos = positions[user];
    // Whale: 1,000,000 ETH debt. No individual liquidator has that.
    require(token.balanceOf(msg.sender) >= pos.debt, "Insufficient balance");
    token.transferFrom(msg.sender, address(this), pos.debt);
    delete positions[user];
}
```

### Fixed
```solidity
uint256 public constant MIN_LIQUIDATION_AMOUNT = 1000e18;
uint256 public constant MAX_LIQUIDATION_PERCENT = 5000; // 50% max per tx

function partialLiquidate(address user, uint256 debtToCover) external {
    Position memory pos = positions[user];
    require(isLiquidatable(pos), "Not liquidatable");
    require(debtToCover >= MIN_LIQUIDATION_AMOUNT, "Too small");
    require(debtToCover <= (pos.debt * MAX_LIQUIDATION_PERCENT) / 10000, "Exceeds max");

    uint256 remainingDebt = pos.debt - debtToCover;
    if (remainingDebt > 0) {
        require(!isInsolvent(pos), "Must fully liquidate insolvent");
    }

    uint256 collateralToLiquidator = (debtToCover * 1050) / 10000;
    token.transferFrom(msg.sender, address(this), debtToCover);
    token.transfer(msg.sender, collateralToLiquidator);
    positions[user].debt -= debtToCover;
    positions[user].collateral -= collateralToLiquidator;
}
```
