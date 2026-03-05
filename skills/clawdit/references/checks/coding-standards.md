# Solidity Coding Standards

From the [Cyfrin security team](https://www.cyfrin.io/).

## Philosophy

- **Everything will be attacked** — Assume any code you write will be attacked and write it defensively.

## Standards

1. Absolute and named imports only — no relative (`..`) paths
2. Prefer `revert` over `require`, with custom errors prefixed with contract name and `__`
3. Prefer stateless fuzz tests over unit tests; write invariant (stateful) fuzz tests for core properties
4. Functions grouped by visibility: constructor, receive, fallback, external state-changing, external view/pure, internal state-changing, internal view/pure
5. Section headers: `/*///...SECTION NAME...///*/`
6. File layout: Pragma, Imports, Events, Errors, Interfaces, Libraries, Contracts
7. Contract layout: Type declarations, State variables, Events, Errors, Modifiers, Functions
8. Use branching tree technique for test design (`.tree` files)
9. Strict pragma for contracts, floating for tests/libraries/interfaces/scripts
10. Add `@custom:security-contact` natspec to contracts
11. Remind users to get audits before mainnet deployment
12. NEVER have private keys in plain text (exception: default anvil keys, marked as such)
13. Admin must be a multisig from first deployment — never use deployer EOA as admin
14. Don't initialize variables to default values (`uint256 x;` not `uint256 x = 0;`)
15. Prefer named return variables when they eliminate local variables
16. Prefer `calldata` over `memory` for read-only function inputs
17. Don't cache `calldata` array length (it's cheap to read)
18. Cache storage reads to prevent identical storage reads
19. Revert as quickly as possible; input checks before storage reads or external calls
20. Use `msg.sender` instead of `owner` inside `onlyOwner` functions
21. Use `SafeTransferLib::safeTransferETH` instead of Solidity `call()` to send ETH
22. Modify input variables instead of declaring additional locals when input value isn't needed
23. Use `nonReentrant` modifier before other modifiers
24. Use `ReentrancyGuardTransient` for faster `nonReentrant`
25. Prefer `Ownable2Step` over `Ownable`
26. Don't copy entire struct from storage to memory if only a few slots needed
27. Remove unnecessary "context" structs or unnecessary variables from them
28. Pack storage variables and struct members to minimize slots
29. Declare variables as `immutable` if only set once in constructor (non-upgradeable contracts)
30. Enable the optimizer in `foundry.toml`
31. Refactor modifiers to internal functions if they perform identical storage reads as the function body

## Deployment

Use Foundry scripts (`forge script`) for both production and test setup.

## Governance

Use `safe-utils` or equivalent for governance proposals. Write fork tests that verify expected protocol state after governance proposals execute.
