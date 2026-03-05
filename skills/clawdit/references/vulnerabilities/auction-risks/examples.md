# Auction Manipulation Vulnerability Examples

## Pattern 1: Self-Bidding to Reset Auction

### Vulnerable
```solidity
function bid(uint256 auctionId, uint256 amount) external {
    Auction storage auction = auctions[auctionId];
    require(block.timestamp < auction.startTime + auction.duration, "Ended");
    require(amount > auction.highestBid, "Bid too low");
    // No check: borrower can bid on own auction
    auction.highestBid = amount;
    auction.highestBidder = msg.sender;
}
// Attack: borrower bids on own loan, "buys" it back, refinances, repeats
```

### Fixed
```solidity
function bid(uint256 auctionId, uint256 amount) external {
    Auction storage auction = auctions[auctionId];
    require(block.timestamp < auction.startTime + auction.duration, "Ended");
    require(amount > auction.highestBid, "Bid too low");
    require(msg.sender != auction.borrower, "Cannot bid on own auction");
    auction.highestBid = amount;
    auction.highestBidder = msg.sender;
}
```

## Pattern 2: Auction Start During L2 Sequencer Downtime

### Vulnerable
```solidity
function startAuction(uint256 loanId) external {
    // No sequencer check on Arbitrum/Optimism
    auctions[loanId] = Auction({
        startTime: block.timestamp,
        duration: 24 hours
    });
    // During 2hr downtime: auction starts, 22hr left when sequencer restarts
    // First bidder after restart has monopoly
}
```

### Fixed
```solidity
AggregatorV3Interface public sequencerUptimeFeed;
uint256 public constant GRACE_PERIOD = 1 hours;

function startAuction(uint256 loanId) external {
    if (address(sequencerUptimeFeed) != address(0)) {
        (, int256 answer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();
        require(answer == 0, "Sequencer down");
        require(block.timestamp >= startedAt + GRACE_PERIOD, "Grace period");
    }
    auctions[loanId] = Auction({
        startTime: block.timestamp,
        duration: 24 hours
    });
}
```

## Pattern 3: Insufficient Auction Length

### Vulnerable
```solidity
function startAuction(uint256 loanId, uint256 duration) external {
    // No minimum duration - can be 1 second!
    auctions[loanId] = Auction({
        startTime: block.timestamp,
        duration: duration
    });
}
// Attack: start 1-second auction, immediately seize collateral
```

### Fixed
```solidity
uint256 public constant MIN_AUCTION_DURATION = 1 hours;
uint256 public constant MAX_AUCTION_DURATION = 7 days;

function startAuction(uint256 loanId, uint256 duration) external {
    require(duration >= MIN_AUCTION_DURATION, "Too short");
    require(duration <= MAX_AUCTION_DURATION, "Too long");
    auctions[loanId] = Auction({
        startTime: block.timestamp,
        duration: duration
    });
}
```

## Pattern 4: Off-by-One Timestamp

### Vulnerable
```solidity
function seizeCollateral(uint256 loanId) external {
    Auction storage auction = auctions[loanId];
    // Using > instead of >= allows seizure 1 second early
    require(block.timestamp > auction.startTime + auction.duration, "Active");
}
```

### Best Practice
```solidity
function bid(uint256 loanId) external {
    Auction storage auction = auctions[loanId];
    require(block.timestamp < auction.startTime + auction.duration, "Ended");
    // Strict: before end only
}

function settle(uint256 loanId) external {
    Auction storage auction = auctions[loanId];
    require(block.timestamp > auction.startTime + auction.duration, "Active");
    // Strict: after end only
    // 1-second gap at exact boundary is acceptable
}
```

## Complete Secure Auction Contract

```solidity
contract SecureAuction {
    AggregatorV3Interface public sequencerUptimeFeed;
    uint256 public constant MIN_DURATION = 1 hours;
    uint256 public constant MAX_DURATION = 7 days;
    uint256 public constant GRACE_PERIOD = 1 hours;

    struct Auction {
        address borrower;
        uint256 startTime;
        uint256 duration;
        uint256 highestBid;
        address highestBidder;
    }

    mapping(uint256 => Auction) public auctions;

    function startAuction(uint256 loanId, uint256 duration) external {
        // L2 sequencer check
        if (address(sequencerUptimeFeed) != address(0)) {
            (, int256 answer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();
            require(answer == 0, "Sequencer down");
            require(block.timestamp >= startedAt + GRACE_PERIOD, "Grace period");
        }

        require(duration >= MIN_DURATION, "Too short");
        require(duration <= MAX_DURATION, "Too long");

        auctions[loanId] = Auction({
            borrower: msg.sender,
            startTime: block.timestamp,
            duration: duration,
            highestBid: 0,
            highestBidder: address(0)
        });
    }

    function bid(uint256 loanId, uint256 amount) external {
        Auction storage auction = auctions[loanId];
        require(msg.sender != auction.borrower, "No self-bid");
        require(block.timestamp < auction.startTime + auction.duration, "Ended");
        require(amount > auction.highestBid, "Bid too low");
        auction.highestBid = amount;
        auction.highestBidder = msg.sender;
    }

    function settle(uint256 loanId) external {
        Auction storage auction = auctions[loanId];
        require(block.timestamp > auction.startTime + auction.duration, "Active");
        // Transfer to highest bidder
    }
}
```
