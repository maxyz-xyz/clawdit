# Token Integration Patterns

24 weird ERC20 patterns to check when a protocol integrates external tokens. Based on Trail of Bits' token integration checklist.

## Quick Reference

For each pattern: check if the protocol handles it correctly. If the protocol accepts arbitrary tokens, ALL patterns are potential attack surfaces.

### 1. Reentrant Calls

ERC777 tokens with `tokensReceived` hooks allow reentrancy during transfers. Also: ERC1155 `onERC1155Received`, flash-swap callbacks.

**Tokens**: Amp (AMP), imBTC
**Grep**: `tokensReceived`, `onERC1155Received`, `_safeMint`, `_safeTransfer`

### 2. Missing Return Values

Some tokens don't return `bool` on `transfer`/`transferFrom`/`approve`. Using `IERC20.transfer()` directly reverts.

**Tokens**: USDT, BNB, OMG
**Fix**: Use `SafeERC20.safeTransfer()`

### 3. Fee on Transfer

Actual received amount < sent amount. Balance-based accounting is wrong if it uses the transfer argument.

**Tokens**: STA, PAXG (also USDT/USDC can add fees via upgrade)
**Fix**: `balanceAfter - balanceBefore` pattern

### 4. Balance Modifications Outside Transfers

Rebasing tokens change balances without transfers. Cached balances go stale.

**Tokens**: Ampleforth, stETH, aTokens, Compound cTokens
**Fix**: Query `balanceOf` at point of use, not cached

### 5. Upgradable Tokens

Token logic can change after integration. New fees, pauses, or blocklists can appear.

**Tokens**: USDC, USDT
**Fix**: Consider wrapper contracts for isolation

### 6. Flash Mintable

Tokens that can be flash-minted to `type(uint256).max` supply in a single transaction.

**Tokens**: DAI
**Risk**: Governance voting, oracle manipulation, share inflation

### 7. Blocklists

Admin can block specific addresses from transferring. Contract can get trapped.

**Tokens**: USDC, USDT
**Risk**: Protocol funds frozen if contract address gets blocklisted

### 8. Pausable Tokens

Admin can pause all transfers. Protocol using pausable tokens may freeze.

**Tokens**: BNB, ZIL
**Risk**: User funds locked during pause

### 9. Approval Race Protections

Some tokens revert if you try to change a non-zero allowance to another non-zero value.

**Tokens**: USDT, KNC
**Fix**: Set allowance to 0 first, then to the desired amount

### 10. Revert on Approval to Zero Address

Some tokens revert on `approve(address(0), amount)`.

**Fix**: Check recipient before approve

### 11. Revert on Zero Value Approvals

Some tokens revert on `approve(spender, 0)`.

**Tokens**: BNB
**Fix**: Check amount before approve

### 12. Revert on Zero Value Transfers

Some tokens revert on `transfer(to, 0)`.

**Tokens**: LEND
**Fix**: Check amount before transfer

### 13. Multiple Token Addresses

Proxied tokens may have multiple addresses pointing to the same state.

**Risk**: Double-counting, rescue function exploits

### 14. Low Decimals

Tokens with < 18 decimals amplify precision loss in division.

**Tokens**: USDC (6), Gemini USD (2)
**Risk**: Rounding exploits, share inflation attacks

### 15. High Decimals

Tokens with > 18 decimals risk overflow in multiplication.

**Tokens**: YAM-V2 (24)
**Risk**: Overflow in price calculations

### 16. transferFrom with src == msg.sender

Some tokens skip allowance decrease when sender == from. Others always decrease.

**Tokens**: DSToken pattern
**Risk**: Inconsistent allowance behavior

### 17. Non-string Metadata

Some tokens return `bytes32` for `name()` and `symbol()` instead of `string`.

**Tokens**: MKR
**Risk**: Interface consumption failures

### 18. Revert on Transfer to Zero Address

OpenZeppelin tokens revert on transfer to `address(0)`.

**Risk**: Burn patterns that transfer to zero address break

### 19. No Revert on Failure

Some tokens return `false` instead of reverting on transfer failure.

**Tokens**: ZRX, EURS
**Fix**: Always check return value or use SafeERC20

### 20. Revert on Large Approvals

Some tokens use `uint96` internally and revert if approval >= 2^96.

**Tokens**: UNI, COMP
**Fix**: Don't use `type(uint256).max` approvals with these tokens

### 21. Code Injection via Token Name

Malicious tokens can embed JavaScript in `name()` for frontend XSS.

**Risk**: Frontend exploits (Etherdelta hack pattern)

### 22. Unusual Permit Function

Some tokens have non-EIP2612 permit. Calling `permit()` on a token without it doesn't revert (phantom function execution on EOAs).

**Tokens**: DAI, RAI, GLM (non-standard), WETH (no-op)

### 23. Transfer Less Than Amount

Some tokens transfer only up to the sender's balance even when a larger amount is specified.

**Tokens**: cUSDCv3 with `type(uint256).max`
**Risk**: Vault accounting mismatch

### 24. ERC-20 Native Currency Representation

Some chains represent native currency as an ERC-20 at a specific address.

**Chains**: Celo (CELO), Polygon (POL), zkSync Era (ETH)
**Risk**: Double spending, msg.value + token transfer confusion
