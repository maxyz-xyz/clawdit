# Auction Manipulation Vulnerabilities

## TLDR

Liquidation auctions are vulnerable to self-bidding timer resets, L2 sequencer downtime exploitation, insufficient auction length allowing instant seizure, and off-by-one timestamp errors enabling premature settlement.

## Vulnerability Patterns

### 1. Self-Bidding to Reset Auction
Borrower bids on own auction to reset timer, extending indefinitely to avoid liquidation. Borrower "buys" own loan, refinances, repeats.
- **Severity: High** - Borrower avoids liquidation indefinitely, bad debt accumulates

### 2. Auction Start During Sequencer Downtime
On L2 chains, auctions starting during sequencer downtime give unfair advantage once sequencer restarts. First bidder after restart has monopoly.
- **Severity: Medium** - Unfair auction conditions on L2

### 3. Insufficient Auction Length Validation
No minimum auction length allows creating 1-second auctions for immediate seizure. Bypasses competitive bidding entirely.
- **Severity: High** - Liquidator seizes collateral without competitive bidding

### 4. Off-by-One Seizure Error
Using `>` instead of `>=` (or vice versa) in timestamp comparison allows seizure at exact auction end time, or creates a 1-second gap where neither bidding nor settling works.
- **Severity: Low** - Edge case timing issue

## Detection

Search terms: `Auction`, `bid`, `seize`, `settle`, `startAuction`, `duration`, `highestBid`, `highestBidder`, `sequencerFeed`, `MIN_DURATION`

Red flags:
- No `require(msg.sender != auction.borrower)` in bid function
- No sequencer uptime check in `startAuction()` on L2
- Auction duration accepted without minimum bound
- Inconsistent `>` vs `>=` in bid and settle timestamp checks

## Audit Checklist

- [ ] **No self-bidding:** Borrower/owner cannot bid on own auction or reset timer
- [ ] **Sequencer check:** Sequencer uptime validated before auction start on L2 chains
- [ ] **Minimum length:** Auction length has enforced minimum (e.g., 1 hour)
- [ ] **Maximum length:** Auction length has enforced maximum (e.g., 7 days)
- [ ] **Correct timestamps:** Bid uses `<`, settle uses `>` (no overlap, 1-second gap acceptable)

## Timestamp Comparison Reference

```solidity
// Correct pattern:
function canBid() public view returns (bool) {
    return block.timestamp < endTime; // Strict before
}

function canSettle() public view returns (bool) {
    return block.timestamp > endTime; // Strict after
}

// At T = endTime: both false (1-second gap is acceptable)
// At T = endTime + 1: canSettle() = true
```

## Key Protections

1. **Self-bidding prevention:** `require(msg.sender != auction.borrower)`
2. **Sequencer checks:** Validate uptime + grace period on L2
3. **Duration bounds:** Minimum 1 hour, maximum 7 days
4. **Correct comparisons:** Bid uses `<`, settle uses `>` (no overlap)

## Case Files

#### examples.md
Vulnerable and fixed code patterns for all 4 auction manipulation patterns, including self-bidding prevention, L2 sequencer checks, duration bounds enforcement, and timestamp comparison best practices. Includes a complete secure auction contract.
