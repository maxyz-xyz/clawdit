# Vulnerability Cheatsheet

Quick-reference for identifying smart contract vulnerabilities during codebase scanning. This is the Tier 0 reference — always loaded into agent bundles.

Organized into sections with grep-able keywords for syntactic scanning and semantic descriptions for structural analysis.

---

## 1. Reentrancy

External calls before state updates allow re-entry. Variants: single-function, cross-function, cross-contract, read-only, ERC721/ERC1155 callback, ERC777 hook, transient storage.

**Grep:** `.call{value`, `.send(`, `.transfer(`, `_safeMint`, `_safeTransfer`, `onERC721Received`, `onERC1155Received`, `tokensReceived`, `nonReentrant`, `ReentrancyGuard`
**Deep ref:** `vulnerabilities/reentrancy/`

---

## 2. Precision & Rounding Errors

Division before multiplication truncates. Token decimal mismatches. ERC4626 share inflation. Rounding direction inconsistency.

**Grep:** `/ `, `* `, `WAD`, `RAY`, `1e18`, `mulDiv`, `decimals`, `roundUp`, `roundDown`
**Deep ref:** `vulnerabilities/precision-errors/`

---

## 3. Arithmetic Errors

Overflow/underflow in `unchecked` blocks or assembly. Type truncation on downcasts. Sign extension. Misuse of `block.timestamp` in arithmetic.

**Grep:** `unchecked`, `SafeMath`, `SafeCast`, `uint8(`, `uint16(`, `int8(`, `assembly`, `shr`, `shl`
**Deep ref:** `vulnerabilities/arithmetic-errors/`

---

## 4. Access Control

Missing modifiers, `tx.origin` auth, unrestricted `initialize()`, signature replay, hash collision via `abi.encodePacked`, arbitrary external call, constructor bypass.

**Grep:** `onlyOwner`, `onlyRole`, `msg.sender ==`, `tx.origin`, `initialize(`, `initializer`, `ecrecover`, `ECDSA.recover`, `abi.encodePacked`, `delegatecall`
**Deep ref:** `vulnerabilities/access-control/`

---

## 5. Logic Errors

Boundary misalignment (`<` vs `<=`), incorrect conditionals, improper state transitions, misordered calculations, event misreporting, same-block snapshot abuse, `msg.value` reuse in multicall, force-sent ETH breaking balance checks, deployment config pitfalls.

**Grep:** `length - 1`, `<= length`, `msg.value`, `selfdestruct`, `block.timestamp`, `block.number`
**Deep ref:** `vulnerabilities/logic-errors/`

---

## 6. Unchecked Returns

Low-level calls (`.call()`, `.send()`) returning false without check. Non-standard ERC20 tokens without return values. `create`/`create2` silent deployment failure. Zero-amount transfer reverts. Return bomb attacks.

**Grep:** `.call(`, `.send(`, `.delegatecall(`, `require(success`, `SafeERC20`, `safeTransfer`, `returndatasize`, `ExcessivelySafeCall`
**Deep ref:** `vulnerabilities/unchecked-returns/`

---

## 7. Proxy & Upgradeability

Storage collision between proxy and implementation. Function selector collision. Uninitialized proxy. Implementation self-destruct. Upgrade lifecycle issues. Diamond proxy pitfalls.

**Grep:** `delegatecall`, `upgradeTo`, `implementation`, `ERC1967`, `TransparentProxy`, `UUPS`, `Diamond`, `initializer`, `_disableInitializers`
**Deep ref:** `vulnerabilities/proxy-insecurities/`

---

## 8. Slippage & MEV

Price manipulation via sandwich attacks. Front-running. Missing deadline checks. Missing `minAmountOut`. Oracle price update front-running. Insufficient liquidity exploitation.

**Grep:** `minAmountOut`, `deadline`, `slippage`, `amountOutMin`, `block.timestamp` as deadline
**Deep ref:** `vulnerabilities/slippage/`

---

## 9. Unbounded Loops & DoS

Dynamic array iteration exceeding gas limit. Unrestricted mapping growth. Recursive calls. Blacklistable token blocking payment loops. Gas griefing. Dust griefing.

**Grep:** `for (`, `while (`, `.length`, `.push(`, `gasleft()`, `.call{gas:`
**Deep ref:** `vulnerabilities/unbounded-loops/`

---

## 10. Oracle Manipulation

Spot price manipulation. TWAP oracle lag. Chainlink stale/invalid feeds. L2 sequencer uptime. Missing price bounds. Incorrect compounding. External market manipulation.

**Grep:** `latestRoundData`, `getPrice`, `oracle`, `TWAP`, `sequencerUptime`, `staleness`, `heartbeat`
**Deep ref:** `vulnerabilities/oracle-manipulation/`

---

## 11. Arbitrary Storage Write

User-controlled index on dynamic array write allows overwriting any storage slot.

**Grep:** `sstore`, `.length =`, `data[`, `array[`

---

## 12. Code Size Check Bypass

`extcodesize == 0` to check for EOA is bypassable from constructor.

**Grep:** `extcodesize`, `.code.length`, `isContract`

---

## 13. tx.origin Authorization

Phishing via malicious contract that calls back with victim's `tx.origin`.

**Grep:** `tx.origin`

---

## 14. Hash Collision (abi.encodePacked)

Adjacent variable-length args in `abi.encodePacked` produce collisions.

**Grep:** `abi.encodePacked`

---

## 15. Signature Malleability

Complementary `(r, n-s, flipped_v)` signature bypasses raw-bytes dedup.

**Grep:** `mapping(bytes =>`, `usedSignatures`, `ecrecover`

---

## 16. Missing Signature Replay Protection

No nonce, `address(this)`, or `block.chainid` in signed hash.

**Grep:** `ecrecover`, `ECDSA.recover`, `nonces`, `block.chainid`, `EIP712`, `domainSeparator`

---

## 17. msg.value Reuse

`msg.value` constant in loops/multicall allows paying once for N operations.

**Grep:** `msg.value`, `multicall`, `delegatecall`

---

## 18. Off-By-One

Wrong loop boundaries (`< length - 1` skips last, `<= length` OOB).

**Grep:** `length - 1`, `<= length`

---

## 19. Timestamp Dependence

Validator-manipulable `block.timestamp` in tight windows or randomness.

**Grep:** `block.timestamp`, `now`, `block.number`

---

## 20. Front-Running (Transaction Ordering)

Swaps without slippage, on-chain secrets, ERC20 approve race condition.

**Grep:** `minAmountOut`, `deadline`, `approve(`, `commit`, `reveal`

---

## 21. Weak Randomness

On-chain data (`block.prevrandao`, `blockhash`) is deterministic and observable.

**Grep:** `block.prevrandao`, `block.difficulty`, `blockhash`, `keccak256`, `% `

---

## 22. Variable Shadowing

Child contract re-declares parent's state variable (Solidity <0.6.0).

**Grep:** `is `, `override`, `virtual`

---

## 23. Incorrect Inheritance Order

C3 linearization: rightmost parent wins for conflicting functions.

**Grep:** `is `, `override(`, `super.`

---

## 24. Deprecated Functions

`suicide`, `sha3`, `block.blockhash`, `callcode`, `selfdestruct` post-Dencun.

**Grep:** `suicide`, `sha3`, `block.blockhash`, `callcode`, `selfdestruct`

---

## 25. Unsupported Opcodes

`PUSH0` on non-supporting chains. `.transfer()` 2300 gas on zkSync.

**Grep:** `pragma solidity 0.8.20`, `.transfer(`, `PUSH0`

---

## 26. Unbounded Return Data

Malicious callee returns megabytes causing OOG via memory expansion.

**Grep:** `returndatasize`, `returndatacopy`, `.call(`

---

## 27. ecrecover Null Address

`ecrecover` returns `address(0)` for invalid sigs; matches uninitialized signer.

**Grep:** `ecrecover`, `address(0)`, `ECDSA.recover`

---

## 28. Token Integration Risks

Fee-on-transfer, rebasing, blocklists, pausable, missing returns, low/high decimals, approval race, flash mintable, upgradable tokens. See `checks/token-integration.md` for all 24 patterns.

**Grep:** `SafeERC20`, `safeTransfer`, `.transfer(`, `.transferFrom(`, `.approve(`, `decimals`, `balanceOf`

---

## 29. ERC4626 Share Inflation

First depositor can inflate share price by donating tokens, causing rounding to zero shares for subsequent depositors.

**Grep:** `ERC4626`, `convertToShares`, `convertToAssets`, `deposit`, `totalAssets`

---

## 30. Flash Loan Governance Attack

Flash-borrow governance tokens, vote, return in same block.

**Grep:** `getPriorVotes`, `getPastVotes`, `delegate`, `propose`, `castVote`

---

## 31. Invariant Enforced on One Path But Not Another

Cap/limit checked in `deposit()` but not in settlement, reward distribution, or emergency paths.

**Grep:** Check all paths that modify constrained state variables.

---

## 32. Beacon Proxy Single Point of Failure

Single Beacon owner controls implementation for all proxies simultaneously.

**Grep:** `UpgradeableBeacon`, `Beacon`, `implementation()`

---

## 33. LayerZero Compose Sender Impersonation

`lzCompose` without validating `msg.sender == endpoint` and `_from == expectedOFT`.

**Grep:** `lzCompose`, `lzReceive`, `endpoint`, `OApp`

---

## 34. Cross-Chain Message Replay

Missing chain-specific nonce or source chain validation in bridge message verification.

**Grep:** `chainId`, `sourceChain`, `nonce`, `messageHash`

---

## 35. Insufficient Gas Griefing

Relayer provides insufficient gas to inner call while consuming nonce.

**Grep:** `gasleft()`, `.call{gas:`, `executed[`, `nonce`, `relayer`

---

## 36. Private Data On-Chain

`private` variables readable via `eth_getStorageAt`.

**Grep:** `private`, `secret`, `password`, `key`
