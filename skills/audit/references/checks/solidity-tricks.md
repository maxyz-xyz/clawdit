# Solidity Quick Checks by Protocol Type

## All Protocols

- Check if external calls use `.call()` but don't validate return data length for contracts that might self-destruct
- Look for reentrancy guards that protect state but allow view function calls to manipulated external contracts
- Verify if token transfers assume 18 decimals but interact with tokens having different decimal precision

## DEX / AMM

- Search for oracle price feeds that don't validate if Chainlink aggregator rounds are stale or incomplete
- Check if swap calculations use mulDiv but don't handle intermediate overflow in complex pricing formulas
- Look for MEV extraction opportunities in multi-hop swaps or arbitrage paths
- Verify if slippage protection accounts for fee-on-transfer tokens reducing received amounts

## Lending / Borrowing

- Check if liquidation logic handles underwater positions correctly during market crashes
- Look for interest rate calculations that can overflow with extremely high utilization rates
- Verify if collateral valuation uses time-weighted average prices to prevent flash loan manipulation
- Search for repayment functions that don't update borrower's debt correctly with compound interest
- Check if flash loan callbacks don't verify the original caller owns the loan amount
- Look for governance proposals that can execute immediately during timelock by manipulating block.timestamp
- Verify if permit functions check deadline but don't prevent replay attacks across forks

## Cross-chain / Bridge

- Check if message verification validates merkle proofs against correct block headers
- Look for relay systems that don't verify message ordering or prevent replay attacks
- Verify if asset locks on source chain require corresponding unlocks/mints on destination
- Search for validator consensus mechanisms that can be manipulated with <33% stake
- Check if time-locked withdrawals can be front-run during dispute periods
- Look for bridge contracts that don't handle failed transactions or stuck assets
- Verify if cross-chain message passing validates sender authenticity

## NFT / Gaming

- Check if metadata URIs can be modified by unauthorized parties after minting
- Look for random number generation using predictable sources (block.timestamp, blockhash)
- Verify if royalty calculations handle edge cases (zero prices, maximum royalties)
- Search for batch operations that don't validate individual item permissions
- Check if game state transitions can be front-run or sandwich attacked
- Look for NFT approvals that don't expire or can be exploited across marketplaces
- Verify if play-to-earn mechanisms have anti-sybil protections

## Governance / DAO

- Check if voting power calculations can be manipulated through flash loans or delegate loops
- Look for proposal execution that doesn't validate proposal state before execution
- Verify if timelock delays can be bypassed through proposal dependencies or emergency functions
- Search for quorum calculations that don't account for total supply changes
- Check if delegation mechanisms prevent vote buying or circular delegation
- Look for treasury access controls that don't require multi-signature approval
- Verify if proposal cancellation can be abused by proposers or governance attacks
