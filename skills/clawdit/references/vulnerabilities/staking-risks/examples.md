# Staking & Reward Vulnerability Examples

## Pattern 1: Front-Running First Deposit

### Vulnerable
```solidity
contract VulnerableFirstDeposit {
    IERC20 public stakingToken; // WETH
    IERC20 public rewardToken; // WETH - SAME TOKEN!

    function deposit(uint256 amount) external {
        totalSupply += amount;
        balances[msg.sender] += amount;
        stakingToken.transferFrom(msg.sender, address(this), amount);
    }
    // Attack: Protocol deploys with 1000 WETH rewards
    // Attacker deposits 1 wei before first user
    // Claims ~990 WETH of rewards
}
```

### Fixed
```solidity
contract FixedFirstDeposit {
    IERC20 public stakingToken; // WETH
    IERC20 public rewardToken; // USDC - DIFFERENT TOKEN!

    function deposit(uint256 amount) external {
        require(amount >= MIN_DEPOSIT, "Amount too small");
        totalSupply += amount;
        balances[msg.sender] += amount;
        stakingToken.transferFrom(msg.sender, address(this), amount);
    }
}
```

## Pattern 2: Reward Dilution via Direct Transfer

### Vulnerable
```solidity
function rewardPerToken() public view returns (uint256) {
    uint256 totalSupply = stakingToken.balanceOf(address(this));
    // Attacker sends tokens directly, inflating totalSupply
    // 10k staked + 10k direct = 20k. Rewards halved.
    if (totalSupply == 0) return rewardPerTokenStored;
    return rewardPerTokenStored + (newRewards * 1e18 / totalSupply);
}
```

### Fixed
```solidity
uint256 public totalSupply; // Tracked separately

function stake(uint256 amount) external {
    totalSupply += amount; // Only increments through stake
    balances[msg.sender] += amount;
    stakingToken.transferFrom(msg.sender, address(this), amount);
}

function rewardPerToken() public view returns (uint256) {
    if (totalSupply == 0) return rewardPerTokenStored;
    return rewardPerTokenStored + (newRewards * 1e18 / totalSupply);
}
```

## Pattern 3: Precision Loss

### Vulnerable
```solidity
function earned(address account) public view returns (uint256) {
    uint256 duration = block.timestamp - lastUpdateTime;
    // balance=10 wei, totalSupply=1000 ether
    // rewardPerToken = duration * 1e18 / 1000e18 = duration / 1000
    // earned = 10 * (duration / 1000) / 1e18 = 0 (rounds to zero!)
    uint256 rewardPerToken = duration * rewardRate / totalSupply;
    return balances[account] * rewardPerToken / 1e18;
}
```

### Fixed
```solidity
uint256 public constant MIN_STAKE = 1000e18;

function stake(uint256 amount) external {
    require(balances[msg.sender] + amount >= MIN_STAKE, "Below minimum");
    totalSupply += amount;
    balances[msg.sender] += amount;
}
```

## Pattern 4: Flash Deposit/Withdraw Griefing

### Vulnerable
```solidity
function deposit(uint256 amount) external {
    updateReward(msg.sender);
    totalSupply += amount;
    balances[msg.sender] += amount;
    token.transferFrom(msg.sender, address(this), amount);
}

function withdraw(uint256 amount) external {
    updateReward(msg.sender);
    totalSupply -= amount;
    balances[msg.sender] -= amount;
    token.transfer(msg.sender, amount);
}
// Attack: deposit 1M (totalSupply 100k->1.1M), dilute rewards, withdraw immediately
```

### Fixed
```solidity
uint256 public constant LOCK_DURATION = 1 days;
mapping(address => uint256) public depositTime;

function deposit(uint256 amount) external {
    updateReward(msg.sender);
    totalSupply += amount;
    balances[msg.sender] += amount;
    depositTime[msg.sender] = block.timestamp;
    token.transferFrom(msg.sender, address(this), amount);
}

function withdraw(uint256 amount) external {
    require(block.timestamp >= depositTime[msg.sender] + LOCK_DURATION, "Locked");
    updateReward(msg.sender);
    totalSupply -= amount;
    balances[msg.sender] -= amount;
    token.transfer(msg.sender, amount);
}
```

## Pattern 5: Stale Index After Reward Distribution

### Vulnerable
```solidity
function notifyRewardAmount(uint256 reward) external {
    rewardRate = reward / DURATION;
    // Missing updateReward()!
    // rewardPerTokenStored not updated
    // Next calculation uses stale lastUpdateTime
}
```

### Fixed
```solidity
function notifyRewardAmount(uint256 reward) external {
    updateReward(address(0)); // Update index BEFORE changing rate
    rewardRate = reward / DURATION;
    lastUpdateTime = block.timestamp;
}
```

## Pattern 6: Balance Caching Bug

### Vulnerable
```solidity
function getReward() external {
    updateReward(msg.sender);
    uint256 reward = rewards[msg.sender];
    rewards[msg.sender] = 0;
    balances[msg.sender] += reward; // Wrong! Added to stake balance
    rewardToken.transfer(msg.sender, reward);
    // Next earned() uses inflated balance - can over-claim
}
```

### Fixed
```solidity
function getReward() external {
    updateReward(msg.sender);
    uint256 reward = rewards[msg.sender];
    rewards[msg.sender] = 0;
    rewardToken.transfer(msg.sender, reward); // Don't modify balances
}
```

## Complete Secure Staking Contract

```solidity
contract SecureStaking {
    IERC20 public stakingToken; // WETH
    IERC20 public rewardToken; // USDC - different!

    uint256 public totalSupply; // Tracked separately
    uint256 public rewardRate;
    uint256 public rewardPerTokenStored;
    uint256 public lastUpdateTime;
    uint256 public constant MIN_STAKE = 1000e18;
    uint256 public constant LOCK_DURATION = 1 days;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public depositTime;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public userRewardPerTokenPaid;

    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    function deposit(uint256 amount) external updateReward(msg.sender) {
        require(balances[msg.sender] + amount >= MIN_STAKE, "Below minimum");
        totalSupply += amount;
        balances[msg.sender] += amount;
        depositTime[msg.sender] = block.timestamp;
        stakingToken.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 amount) external updateReward(msg.sender) {
        require(block.timestamp >= depositTime[msg.sender] + LOCK_DURATION, "Locked");
        totalSupply -= amount;
        balances[msg.sender] -= amount;
        stakingToken.transfer(msg.sender, amount);
    }

    function getReward() external updateReward(msg.sender) {
        uint256 reward = rewards[msg.sender];
        rewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, reward);
    }

    function notifyRewardAmount(uint256 reward) external updateReward(address(0)) {
        rewardRate = reward / 7 days;
        lastUpdateTime = block.timestamp;
    }

    function rewardPerToken() public view returns (uint256) {
        if (totalSupply == 0) return rewardPerTokenStored;
        uint256 duration = block.timestamp - lastUpdateTime;
        return rewardPerTokenStored + (duration * rewardRate * 1e18 / totalSupply);
    }

    function earned(address account) public view returns (uint256) {
        return balances[account] * (rewardPerToken() - userRewardPerTokenPaid[account]) / 1e18
            + rewards[account];
    }
}
```
