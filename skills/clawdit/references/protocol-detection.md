# Protocol Type Detection

## Auto-Detection Heuristics

Scan in-scope `.sol` files for these patterns to determine protocol type. Multiple types may match — load all matching protocol context files.

| Detected Pattern                                                                                                         | Protocol Type            | Context File                            |
| ------------------------------------------------------------------------------------------------------------------------ | ------------------------ | --------------------------------------- |
| `swap`, `addLiquidity`, `removeLiquidity`, `getAmountOut`, `pair`, `pool`, `factory`, concentrated liquidity, order book | DEX                      | `protocols/dexes.md`                    |
| `borrow`, `repay`, `liquidate`, `collateral`, `healthFactor`, `interestRate`, `utilizationRate`, `flashLoan`             | Lending                  | `protocols/lending.md`                  |
| `bridge`, `relayer`, `messagePass`, `lockAndMint`, `crossChain`, `LayerZero`, `Wormhole`                                 | Bridge                   | `protocols/bridges.md`                  |
| `vault`, `strategy`, `harvest`, `compound`, `yield`, `ERC4626`, `deposit`+`withdraw`+`shares`                            | Yield                    | `protocols/yield.md`                    |
| `stake`, `unstake`, `validator`, `delegation`, `slashing`, `beacon`, `withdrawal`                                        | Staking                  | `protocols/staking.md`                  |
| `perpetual`, `funding`, `leverage`, `margin`, `position`, `openPosition`, `closePosition`                                | Derivatives              | `protocols/derivatives.md`              |
| `propose`, `vote`, `execute`, `timelock`, `quorum`, `governor`, `ballot`                                                 | Governance               | `protocols/governance.md`               |
| `listing`, `offer`, `bid`, `auction`, `royalty`, `ERC721`, `marketplace`                                                 | NFT Marketplace          | `protocols/nft-marketplace.md`          |
| `mint`, `breed`, `craft`, `reward`, `quest`, `ERC1155`, `gameItem`                                                       | NFT Gaming               | `protocols/nft-gaming.md`               |
| `sale`, `vesting`, `cliff`, `claim`, `whitelist`, `launchpad`, `IDO`                                                     | Launchpad                | `protocols/launchpad.md`                |
| `rebase`, `seigniorage`, `peg`, `algorithmicStable`, `expansion`, `contraction`                                          | Algo Stables             | `protocols/algo-stables.md`             |
| `CDP`, `collateralRatio`, `mintStable`, `liquidation`, `exogenous`                                                       | Decentralized Stablecoin | `protocols/decentralized-stablecoin.md` |
| `treasury`, `backing`, `bond`, `discount`, `protocolOwnedLiquidity`, `rebase`+`treasury`                                 | Reserve Currency         | `protocols/reserve-currency.md`         |
| `synthetic`, `debtPool`, `mirror`, `issuance`, `synth`                                                                   | Synthetics               | `protocols/synthetics.md`               |
| `rebalance`, `positionManager`, `tickRange`, `concentrated`, `Uniswap v3`+`vault`                                        | Liquidity Manager        | `protocols/liquidity-manager.md`        |
| `coverage`, `claim`, `premium`, `riskPool`, `parametric`, `payout`                                                       | Insurance                | `protocols/insurance.md`                |
| `index`, `basket`, `rebalance`, `constituent`, `weight`, `portfolio`                                                     | Indexes                  | `protocols/indexes.md`                  |
| `fee`, `keeper`, `aggregator`, `airdrop`, `merkle`, `service`                                                            | Services                 | `protocols/services.md`                 |
| `mixer`, `commitment`, `nullifier`, `zkProof`, `shielded`, `tornado`                                                     | Privacy                  | `protocols/privacy.md`                  |
| `RWA`, `tokenizedAsset`, `security`, `permissioned`, `KYC`, `compliance`                                                 | RWA Tokenization         | `protocols/rwa-tokenization.md`         |
| `creditFacility`, `realWorldAsset`+`lending`, `underwriter`, `borrowerPool`                                              | RWA Lending              | `protocols/rwa-lending.md`              |

## Detection Procedure

1. Run grep/search across all in-scope `.sol` files for the patterns above
2. Score each protocol type by number of pattern matches
3. Select the top 1-3 matching types
4. Load corresponding `protocols/<type>.md` files as Tier 1 context
5. If no type matches confidently, skip Tier 1 and rely on Tier 0 (CHEATSHEET) + Tier 2 (on-demand vulnerability families)

## Engine Selection Matrix

Based on detected protocol type, prioritize these analysis engines:

| Protocol Type | Primary Engines                                  | Secondary Engines         |
| ------------- | ------------------------------------------------ | ------------------------- |
| DEX           | Economic (MEV, sandwich), State Integrity        | Access Control            |
| Lending       | Economic (flash loan, oracle), State Integrity   | Access Control            |
| Bridge        | Access Control, State Integrity                  | Economic                  |
| Yield         | Economic (share inflation), State Integrity      | Access Control            |
| Staking       | Economic (reward calc), State Integrity          | Access Control            |
| Derivatives   | Economic (funding, liquidation), State Integrity | Access Control            |
| Governance    | Access Control (flash loan voting)               | Economic, State Integrity |
| NFT           | Access Control, State Integrity                  | Economic                  |
| Launchpad     | Economic (front-running), Access Control         | State Integrity           |
| Stablecoin    | Economic (peg, oracle), State Integrity          | Access Control            |
| Privacy       | Access Control (nullifier), State Integrity      | Economic                  |
| RWA           | Access Control (KYC), State Integrity            | Economic                  |
