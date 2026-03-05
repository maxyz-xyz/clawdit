# Severity Calibration Framework

## Severity Levels

### Critical

- Direct loss of user funds with no preconditions beyond normal protocol usage
- Protocol-level insolvency or permanent bricking
- Unauthorized minting/burning of protocol tokens at scale
- Governance takeover enabling treasury drain

**Threshold:** Attack is profitable, repeatable, and affects all/most users.

### High

- Direct loss of user funds requiring specific but realistic preconditions
- Temporary freezing of funds exceeding 1 week
- Permanent loss of yield/rewards for users
- Privilege escalation enabling admin-only operations
- Oracle manipulation leading to material mispricing

**Threshold:** Attack is feasible in production with reasonable effort.

### Medium

- Loss of funds requiring unlikely but possible preconditions
- Temporary freezing of funds (< 1 week) or griefing with material cost to attacker
- Protocol functionality degradation (not fund loss)
- Incorrect accounting that accumulates over time
- Missing access controls on non-critical functions

**Threshold:** Impact is meaningful but attack requires specific conditions or attacker motivation is unclear.

### Low

- Minor accounting imprecision with negligible cumulative effect
- Gas optimization with measurable waste
- Missing event emissions for important state changes
- Informational issues that could become vulnerabilities if code changes
- Deviations from EIP standards that don't cause loss

**Threshold:** No realistic path to fund loss, but code quality or correctness is affected.

### Informational

- Code style and best practices
- Documentation gaps
- Redundant code or unused variables
- Suggestions for gas optimization

## Calibration Rules

1. **Severity is based on impact, not likelihood alone.** A low-probability Critical is still Critical if the impact is catastrophic.

2. **Downgrade by one level** when:
   - Attack requires admin/privileged cooperation (unless admin is untrusted by design)
   - Impact is bounded by per-transaction limits
   - Attack is not profitable after gas costs on mainnet

3. **Upgrade by one level** when:
   - Multiple instances of the same vulnerability compound (e.g., rounding errors across many operations)
   - Vulnerability chains with another finding to increase impact
   - Protocol holds > $10M TVL and the vulnerability is in a hot path

4. **Never upgrade to Critical** based on compounding alone — the individual finding must meet Critical criteria.

5. **Privileged roles:** If the protocol documents that admins are trusted, admin-only issues are at most Medium. If admin trust is not documented, treat admin functions as attack surface.

## Common Miscalibrations to Avoid

| Overcall                        | Correct           | Why                                                  |
| ------------------------------- | ----------------- | ---------------------------------------------------- |
| "Critical: admin can rug"       | Medium or N/A     | Most protocols trust their admin                     |
| "High: front-running possible"  | Medium or Low     | Front-running is often not profitable                |
| "Critical: reentrancy possible" | Depends on impact | Reentrancy without fund extraction is Medium at best |
| "High: no zero-address check"   | Low or Info       | Unlikely mistake, easily caught in testing           |
| "Medium: missing event"         | Low or Info       | No security impact                                   |
