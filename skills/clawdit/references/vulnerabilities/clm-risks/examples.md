# CLM Vulnerability Examples

## Pattern 1: Missing TWAP Check on Deposit

### Vulnerable
```solidity
contract VulnerableCLM {
    uint256 public maxDeviation = 200; // 2%
    uint32 public twapInterval = 1800; // 30 min

    function rebalance() external {
        _checkTWAP(); // Has protection
        _deployLiquidity();
    }

    function deposit(uint256 amount0, uint256 amount1) external {
        // NO TWAP validation - MEV can sandwich
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        _deployLiquidity(); // Deploys at manipulated price
    }
}
```

### Fixed
```solidity
contract FixedCLM {
    function deposit(uint256 amount0, uint256 amount1) external {
        _checkTWAP(); // Protection in ALL deployment functions
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        _deployLiquidity();
    }
}
```

## Pattern 2: Owner Rug-Pull via TWAP Parameters

### Vulnerable
```solidity
function setTWAPParams(uint256 _maxDeviation, uint32 _twapInterval) external onlyOwner {
    maxDeviation = _maxDeviation; // Can set to 10000 (100%)
    twapInterval = _twapInterval; // Can set to 1 (1 second)
    // With 100% deviation or 1-second TWAP, protection is useless
}
```

### Fixed
```solidity
uint256 public constant MIN_MAX_DEVIATION = 10; // 0.1%
uint256 public constant MAX_MAX_DEVIATION = 500; // 5%
uint32 public constant MIN_TWAP_INTERVAL = 300; // 5 minutes
uint32 public constant MAX_TWAP_INTERVAL = 3600; // 1 hour

function setTWAPParams(uint256 _maxDeviation, uint32 _twapInterval) external onlyOwner {
    require(
        _maxDeviation >= MIN_MAX_DEVIATION && _maxDeviation <= MAX_MAX_DEVIATION,
        "Deviation out of bounds"
    );
    require(
        _twapInterval >= MIN_TWAP_INTERVAL && _twapInterval <= MAX_TWAP_INTERVAL,
        "Interval out of bounds"
    );
    maxDeviation = _maxDeviation;
    twapInterval = _twapInterval;
}
```

## Pattern 3: Tokens Permanently Stuck

### Vulnerable
```solidity
function rebalance() external {
    positionManager.decreaseLiquidity(...);
    positionManager.collect(...);
    // Rounding errors leave dust tokens uncollected
    // After 1000 rebalances, significant tokens stuck
    positionManager.mint(...); // Uses balanceOf(address(this))
    // No function to withdraw stuck tokens
}
```

### Fixed
```solidity
function sweepTokens(address token, address to) external onlyOwner {
    uint256 expectedBalance = _getExpectedBalance(token);
    uint256 actualBalance = IERC20(token).balanceOf(address(this));
    require(actualBalance > expectedBalance, "No excess");
    uint256 excess = actualBalance - expectedBalance;
    IERC20(token).transfer(to, excess);
}
```

## Pattern 4: Stale Token Approvals

### Vulnerable
```solidity
function setPositionManager(address _newManager) external onlyOwner {
    positionManager = INonfungiblePositionManager(_newManager);
    token0.approve(_newManager, type(uint256).max);
    token1.approve(_newManager, type(uint256).max);
    // Old manager still has approval! Can drain tokens if compromised.
}
```

### Fixed
```solidity
function setPositionManager(address _newManager) external onlyOwner {
    address oldManager = address(positionManager);
    token0.approve(oldManager, 0); // Revoke old FIRST
    token1.approve(oldManager, 0);
    positionManager = INonfungiblePositionManager(_newManager);
    token0.approve(_newManager, type(uint256).max);
    token1.approve(_newManager, type(uint256).max);
}
```

## Pattern 5: Retrospective Fee Application

### Vulnerable
```solidity
function setProtocolFee(uint256 newFee) external onlyOwner {
    protocolFeePercent = newFee; // Applies to already earned but uncollected fees!
    // Owner: set fee 10%->50%, collect 30 days of fees at 50%
}

function collectFees() external {
    (uint256 amount0, uint256 amount1) = positionManager.collect(...);
    uint256 protocolAmount0 = amount0 * protocolFeePercent / 10000;
    // Uses current fee, not fee at time of earning
}
```

### Fixed
```solidity
function setProtocolFee(uint256 newFee) external onlyOwner {
    collectFees(); // Collect with OLD rate first
    protocolFeePercent = newFee; // New rate only for future fees
}
```

## Complete CLM Sandwich Attack

### Vulnerable
```solidity
contract CompleteCLMVulnerable {
    uint256 public maxDeviation = 10000; // 100% - ineffective
    uint32 public twapInterval = 1; // 1 second - ineffective

    function deposit(uint256 amount0, uint256 amount1) external {
        // Missing TWAP check
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        _mintPosition();
    }
}

contract AttackCLM {
    function attack() external {
        // 1. Flash loan 1000 ETH
        // 2. Swap 500 ETH -> USDC to move price 10%
        pool.swap(...);
        // 3. Deposit into CLM at manipulated price
        clm.deposit(100 ether, 300000 * 1e6);
        // 4. Swap back USDC -> ETH
        pool.swap(...);
        // 5. Repay flash loan, profit from CLM's impermanent loss
    }
}
```

### Fixed
```solidity
contract CompleteCLMFixed {
    uint256 public maxDeviation = 200; // 2% max
    uint32 public twapInterval = 1800; // 30 minutes
    uint256 public constant MIN_MAX_DEVIATION = 10;
    uint256 public constant MAX_MAX_DEVIATION = 500;

    function deposit(uint256 amount0, uint256 amount1) external {
        _checkTWAP(); // Protection enabled
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        _mintPosition();
    }
}
```
