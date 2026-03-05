# Liquidation DoS Vulnerability Examples

## Pattern 1: Many Small Positions DoS

### Vulnerable
```solidity
contract VulnerableUnboundedLoop {
    mapping(address => Position[]) public userPositions;

    function liquidate(address user) external {
        Position[] storage positions = userPositions[user];
        // Attacker creates 10,000 small positions
        // Loop consumes 30M+ gas, exceeds block limit
        for (uint i = 0; i < positions.length; i++) {
            if (isLiquidatable(positions[i])) {
                seizeCollateral(user, i);
            }
        }
    }
}
```

### Fixed
```solidity
contract FixedBoundedLoop {
    uint256 public constant MAX_POSITIONS = 50;

    function liquidate(address user, uint256 positionId) external {
        require(positionId < userPositions[user].length, "Invalid");
        Position storage pos = userPositions[user][positionId];
        require(isLiquidatable(pos), "Not liquidatable");
        seizeCollateral(user, positionId);
    }

    function createPosition(uint256 collateral, uint256 debt) external {
        require(userPositions[msg.sender].length < MAX_POSITIONS, "Max reached");
        userPositions[msg.sender].push(Position(collateral, debt));
    }
}
```

## Pattern 2: EnumerableSet Corruption During Iteration

### Vulnerable
```solidity
function liquidateAll(address user) external {
    EnumerableSet.UintSet storage posIds = userPositionIds[user];
    for (uint i = 0; i < posIds.length(); i++) {
        uint256 posId = posIds.at(i);
        if (isLiquidatable(positions[posId])) {
            posIds.remove(posId); // Corrupts iteration - skips positions
            delete positions[posId];
        }
    }
}
```

### Fixed
```solidity
function liquidate(address user, uint256 posId) external {
    require(userPositionIds[user].contains(posId), "Invalid");
    require(isLiquidatable(positions[posId]), "Not liquidatable");
    userPositionIds[user].remove(posId);
    delete positions[posId];
}
```

## Pattern 3: Front-Run via Nonce Change

### Vulnerable
```solidity
function liquidate(address user, uint256 nonce) external {
    require(nonces[user] == nonce, "Invalid nonce");
    // User front-runs with any tx to increment nonce
    nonces[user]++;
    seizeCollateral(user);
}
```

### Fixed
```solidity
function liquidate(address user) external {
    // No nonce dependency - cannot be front-run
    Position memory pos = positions[user];
    require(isLiquidatable(pos), "Not liquidatable");
    seizeCollateral(user);
    delete positions[user];
}
```

## Pattern 4: Pending Withdrawal Blocks Liquidation

### Vulnerable
```solidity
function liquidate(address user) external {
    uint256 userCollateral = collateral[user];
    // User queues withdrawal = collateral, available = 0
    require(
        userCollateral - pendingWithdrawals[user] > 0,
        "Insufficient available collateral"
    ); // Reverts
}
```

### Fixed
```solidity
function liquidate(address user) external {
    uint256 userCollateral = collateral[user];
    delete pendingWithdrawals[user]; // Cancel pending
    token.transfer(msg.sender, userCollateral);
    delete collateral[user];
}
```

## Pattern 5: Malicious Callback Prevents Liquidation

### Vulnerable
```solidity
function liquidate(address user) external {
    // safeTransferFrom triggers onERC721Received on user contract
    // Malicious borrower reverts in callback
    collateralNFT.safeTransferFrom(address(this), msg.sender, pos.tokenId);
    delete positions[user]; // Never reached
}
```

### Fixed
```solidity
function liquidate(address user) external {
    // Use transferFrom - no callbacks
    collateralNFT.transferFrom(address(this), msg.sender, pos.tokenId);
    delete positions[user];
}

// Alternative: try/catch
function liquidateWithTryCatch(address user) external {
    try collateralNFT.safeTransferFrom(address(this), msg.sender, pos.tokenId) {
    } catch {
        collateralNFT.transferFrom(address(this), msg.sender, pos.tokenId);
    }
    delete positions[user];
}
```

## Pattern 7: Insurance Fund Insufficient

### Vulnerable
```solidity
function liquidate(address user) external {
    uint256 badDebt = pos.debt > pos.collateral ? pos.debt - pos.collateral : 0;
    require(insuranceFund >= badDebt, "Insufficient insurance"); // Reverts!
    // Position cannot be liquidated until fund replenished
}
```

### Fixed
```solidity
function liquidate(address user) external {
    if (pos.debt > pos.collateral) {
        uint256 badDebt = pos.debt - pos.collateral;
        if (insuranceFund >= badDebt) {
            insuranceFund -= badDebt;
        } else {
            unrecoverableBadDebt += (badDebt - insuranceFund);
            insuranceFund = 0;
        }
        seizeCollateral(user, pos.collateral); // Proceeds regardless
    } else {
        seizeCollateral(user, pos.collateral);
    }
    delete positions[user];
}
```

## Pattern 8: Fixed Bonus Exceeds Available Collateral

### Vulnerable
```solidity
uint256 public constant LIQUIDATION_BONUS = 1100; // 110%

function liquidate(address user) external {
    // 110% bonus fails when collateral ratio < 110%
    // Position: 100 debt, 105 collateral (105% ratio)
    // Bonus: 100 * 1.1 = 110 required, only 105 available
    uint256 bonusAmount = (pos.debt * LIQUIDATION_BONUS) / 1000;
    require(pos.collateral >= bonusAmount, "Insufficient"); // Reverts!
}
```

### Fixed
```solidity
function liquidate(address user) external {
    uint256 idealBonus = (pos.debt * MAX_LIQUIDATION_BONUS) / 1000;
    uint256 actualBonus = idealBonus <= pos.collateral
        ? idealBonus
        : pos.collateral; // Cap at available
    token.transferFrom(msg.sender, address(this), pos.debt);
    token.transfer(msg.sender, actualBonus);
    delete positions[user];
}
```

## Pattern 10: Multiple nonReentrant in Call Chain

### Vulnerable
```solidity
function liquidate(address user) external nonReentrant {
    _liquidateInternal(user, pos);
}

function _liquidateInternal(address user, Position memory pos)
    internal nonReentrant // Second guard - causes revert!
{
    seizeCollateral(user, pos);
}
```

### Fixed
```solidity
function liquidate(address user) external nonReentrant {
    _liquidateInternal(user, pos);
}

function _liquidateInternal(address user, Position memory pos) internal {
    // No nonReentrant on internal function
    seizeCollateral(user, pos);
}
```

## Pattern 12: Token Deny List (USDC Blocklist)

### Vulnerable
```solidity
function liquidate(address user) external {
    // Transfer to blacklisted user reverts
    debtToken.transfer(user, repaymentRefund); // Reverts!
    // Liquidation blocked, position remains underwater
}
```

### Fixed
```solidity
mapping(address => uint256) public claimableRefunds;

function liquidate(address user) external {
    claimableRefunds[user] += repaymentRefund; // Don't transfer directly
    seizeCollateral(msg.sender, pos.collateral);
    delete positions[user];
}

function claimRefund() external {
    uint256 amount = claimableRefunds[msg.sender];
    claimableRefunds[msg.sender] = 0;
    debtToken.transfer(msg.sender, amount);
}
```

## Pattern 13: Single Borrower Division by Zero

### Vulnerable
```solidity
function liquidate(address user) external {
    // Division by zero when totalBorrowers == 1
    uint256 shareOfBadDebt = pos.debt / (totalBorrowers - 1); // Reverts!
}
```

### Fixed
```solidity
function liquidate(address user) external {
    uint256 shareOfBadDebt;
    if (totalBorrowers > 1) {
        shareOfBadDebt = pos.debt / (totalBorrowers - 1);
    } else {
        shareOfBadDebt = pos.debt; // Last borrower
    }
}
```
