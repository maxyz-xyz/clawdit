# Liquidation Calculation Vulnerability Examples

## 1. Incorrect Liquidator Reward Calculation

### Vulnerable: Hardcoded 1e18 for USDC collateral

```solidity
contract VulnerableLiquidation {
    IERC20 public collateralToken; // USDC (6 decimals)
    IERC20 public debtToken; // DAI (18 decimals)
    uint256 constant LIQUIDATION_BONUS = 110; // 110%

    function liquidate(address user) external {
        uint256 collateral = collateralToken.balanceOf(user);
        uint256 debt = debtToken.balanceOf(user);
        // VULNERABLE: assumes 18 decimals for USDC
        uint256 reward = (debt * LIQUIDATION_BONUS) / 1e18;
        // If debt = 1000 DAI (1000e18), reward = 1100e0 = 0.0011 USDC!
        collateralToken.transfer(msg.sender, reward); // Transfers 0
    }
}
```

### Secure: Scaled to collateral decimals

```solidity
contract SecureLiquidation {
    IERC20 public collateralToken;
    IERC20 public debtToken;
    uint8 public collateralDecimals;
    uint8 public debtDecimals;
    uint256 constant LIQUIDATION_BONUS = 110;

    function liquidate(address user) external {
        uint256 collateral = collateralToken.balanceOf(user);
        uint256 debt = debtToken.balanceOf(user);
        uint256 debtInCollateralDecimals = debt *
            (10 ** collateralDecimals) / (10 ** debtDecimals);
        uint256 reward = (debtInCollateralDecimals * LIQUIDATION_BONUS) / 100;
        require(collateral >= reward, "Insufficient collateral");
        collateralToken.transfer(msg.sender, reward);
    }
}
```

## 2. Unprioritized Liquidator Reward

### Vulnerable: Protocol fee paid first

```solidity
contract VulnerableFeeOrder {
    uint256 constant PROTOCOL_FEE_RATE = 5000; // 50%
    uint256 constant LIQUIDATION_BONUS = 110;

    function liquidate(address user) external {
        uint256 collateral = getCollateral(user);
        uint256 debt = getDebt(user);
        // VULNERABLE: protocol fee first
        uint256 protocolFee = (collateral * PROTOCOL_FEE_RATE) / 10000;
        collateral -= protocolFee;
        uint256 liquidatorReward = collateral - debt; // Can be 0!
        protocolFeesAccrued += protocolFee;
        transfer(msg.sender, liquidatorReward);
        transfer(treasury, debt);
    }
}
```

Example: Collateral 1100, Debt 1000, Fee 550 (50%), Remaining 550, Reward = 550-1000 = reverts.

### Secure: Liquidator paid first

```solidity
contract SecureFeeOrder {
    uint256 constant PROTOCOL_FEE_RATE = 500; // 5%
    uint256 constant LIQUIDATION_BONUS = 110;

    function liquidate(address user) external {
        uint256 collateral = getCollateral(user);
        uint256 debt = getDebt(user);
        uint256 bonusAmount = (debt * LIQUIDATION_BONUS) / 100;
        uint256 liquidatorReward = bonusAmount - debt;
        uint256 protocolFee = (liquidatorReward * PROTOCOL_FEE_RATE) / 10000;
        uint256 netLiquidatorReward = liquidatorReward - protocolFee;
        require(collateral >= bonusAmount, "Insufficient collateral");
        transfer(msg.sender, netLiquidatorReward);
        transfer(treasury, debt + protocolFee);
    }
}
```

## 3. Unaccounted Yield/PNL

### Vulnerable: Ignores earned yield

```solidity
contract VulnerableYieldTracking {
    mapping(address => uint256) public userDeposits;
    IYieldVault public vault;

    function getCollateralValue(address user) public view returns (uint256) {
        return userDeposits[user]; // Wrong! Missing yield
    }

    function isLiquidatable(address user) public view returns (bool) {
        uint256 collateral = getCollateralValue(user); // Understated
        uint256 debt = getDebt(user);
        return collateral < debt * 120 / 100;
        // User liquidated despite having sufficient collateral + yield!
    }
}
```

Example: deposits=1000, yield=200, total=1200, debt=1000. `getCollateralValue()` returns 1000, user liquidated despite 1200 > 1000*1.2.

### Secure: Includes earned yield

```solidity
contract SecureYieldTracking {
    mapping(address => uint256) public userShares;
    IYieldVault public vault;

    function getCollateralValue(address user) public view returns (uint256) {
        return vault.balanceOf(user); // Includes yield
    }

    function isLiquidatable(address user) public view returns (bool) {
        uint256 collateral = getCollateralValue(user);
        uint256 debt = getDebt(user);
        return collateral < debt * 120 / 100;
    }
}
```

## 4. Oracle Sandwich Self-Liquidation

### Vulnerable: Self-liquidation allowed

```solidity
contract VulnerableSelfLiquidation {
    IOracle public oracle;

    function updateOracle() external {
        oracle.update(); // Anyone can update
    }

    function liquidate(address user) external {
        require(isLiquidatable(user), "Not liquidatable");
        uint256 collateral = getCollateral(user);
        uint256 debt = getDebt(user);
        // No check for self-liquidation
        transfer(msg.sender, collateral);
        transfer(treasury, debt);
    }
}
```

Attack: 1) Position becomes liquidatable (collateral=1100, debt=1000). 2) User calls `updateOracle()`. 3) User calls `liquidate(self)` from alt account. 4) User receives 1100, pays 1000 = 100 profit.

### Secure: Prevents self-liquidation

```solidity
contract SecureSelfLiquidation {
    IOracle public oracle;
    mapping(address => uint256) public lastOracleUpdate;
    uint256 constant ORACLE_DELAY = 1 hours;

    function updateOracle() external {
        oracle.update();
        lastOracleUpdate[msg.sender] = block.timestamp;
    }

    function liquidate(address user) external {
        require(msg.sender != user, "Cannot self-liquidate");
        require(isLiquidatable(user), "Not liquidatable");
        require(
            block.timestamp > lastOracleUpdate[msg.sender] + ORACLE_DELAY,
            "Oracle update delay"
        );
        uint256 collateral = getCollateral(user);
        uint256 debt = getDebt(user);
        transfer(msg.sender, collateral);
        transfer(treasury, debt);
    }
}
```

## 5. Complete Secure Liquidation Contract

```solidity
contract CompleteLiquidation {
    IERC20 public collateralToken;
    IERC20 public debtToken;
    IYieldVault public vault;
    IOracle public oracle;

    uint8 public immutable collateralDecimals;
    uint8 public immutable debtDecimals;

    uint256 constant LIQUIDATION_RATIO = 120;
    uint256 constant LIQUIDATION_BONUS = 110;
    uint256 constant PROTOCOL_FEE_RATE = 500; // 5%
    uint256 constant ORACLE_DELAY = 1 hours;

    mapping(address => uint256) public userShares;
    mapping(address => uint256) public userDebt;
    mapping(address => uint256) public lastOracleUpdate;

    function getCollateralValue(address user) public view returns (uint256) {
        return vault.balanceOf(user); // Include earned yield
    }

    function isLiquidatable(address user) public view returns (bool) {
        uint256 collateral = getCollateralValue(user);
        uint256 debt = userDebt[user];
        uint256 debtScaled = debt * (10 ** collateralDecimals) /
            (10 ** debtDecimals);
        return collateral * 100 < debtScaled * LIQUIDATION_RATIO;
    }

    function liquidate(address user) external {
        require(msg.sender != user, "Cannot self-liquidate");
        require(
            block.timestamp > lastOracleUpdate[msg.sender] + ORACLE_DELAY,
            "Oracle delay"
        );
        require(isLiquidatable(user), "Not liquidatable");

        uint256 collateral = getCollateralValue(user);
        uint256 debt = userDebt[user];
        uint256 debtScaled = debt * (10 ** collateralDecimals) /
            (10 ** debtDecimals);

        // Calculate liquidator reward FIRST
        uint256 bonusAmount = (debtScaled * LIQUIDATION_BONUS) / 100;
        uint256 liquidatorReward = bonusAmount - debtScaled;
        uint256 protocolFee = (liquidatorReward * PROTOCOL_FEE_RATE) / 10000;
        uint256 netLiquidatorReward = liquidatorReward - protocolFee;

        require(collateral >= bonusAmount, "Insufficient collateral");

        vault.withdraw(user, netLiquidatorReward, msg.sender);
        vault.withdraw(user, debtScaled, address(this));
        vault.withdraw(user, protocolFee, treasury);

        userDebt[user] = 0;
        userShares[user] = 0;
    }

    function borrow(uint256 amount) external {
        uint256 collateral = getCollateralValue(msg.sender);
        uint256 debt = userDebt[msg.sender] + amount;
        uint256 debtScaled = debt * (10 ** collateralDecimals) /
            (10 ** debtDecimals);
        require(
            collateral * 100 >= debtScaled * LIQUIDATION_RATIO,
            "Insufficient collateral"
        );
        userDebt[msg.sender] = debt;
        debtToken.transfer(msg.sender, amount);
    }

    function updateOracle() external {
        oracle.update();
        lastOracleUpdate[msg.sender] = block.timestamp;
    }
}
```

Key features: correct decimal scaling, liquidator paid first, low protocol fee (5%), minimum accounts for costs, includes yield, prevents self-liquidation, oracle update delay.
