# Report Format

## Output Structure

````markdown
# Security Review — <Project Name>

---

## Scope

|                          |                                                        |
| ------------------------ | ------------------------------------------------------ |
| **Mode**                 | default / deep / context                               |
| **Files reviewed**       | `File1.sol` · `File2.sol`<br>`File3.sol` · `File4.sol` |
| **Protocol type**        | <detected type>                                        |
| **Confidence threshold** | 75                                                     |
| **Static analysis**      | Slither ✓/✗ · Aderyn ✓/✗                               |
| **Solodit cross-ref**    | ✓/✗                                                    |

---

## Findings

[95] **H-1. <Title>**

`ContractName.functionName` · `path/to/File.sol#L42-L58` · Confidence: 95

**Description**
<Root cause and why it is exploitable, in 1-2 sentences>

**Attack Path**

1. Step one
2. Step two
3. Impact

**Fix**

```diff
- vulnerable line(s)
+ fixed line(s)
```
````

**References**

- Solodit: [finding title](url)
- CHEATSHEET: <entry-id>

---

[82] **H-2. <Title>**

...

---

## Findings Summary

| #   | Confidence | Severity | Title                          |
| --- | ---------- | -------- | ------------------------------ |
| H-1 | [95]       | High     | <title>                        |
| H-2 | [82]       | High     | <title>                        |
| M-1 | [78]       | Medium   | <title>                        |
|     |            |          | **Below Confidence Threshold** |
| M-2 | [70]       | Medium   | <title>                        |
| L-1 | [60]       | Low      | <title>                        |

---

## Static Analysis Summary

### Slither

| Detector | Severity | Confidence | Files | Lines |
| -------- | -------- | ---------- | ----- | ----- |
| ...      | ...      | ...        | ...   | ...   |

### Aderyn

| Issue | Severity | Files | Lines |
| ----- | -------- | ----- | ----- |
| ...   | ...      | ...   | ...   |

---

> This review was performed by an AI assistant. AI analysis cannot verify the complete absence of vulnerabilities and no guarantee of security is given. Professional security reviews, bug bounty programs, and on-chain monitoring are strongly recommended.

```

## Rules

1. Follow the template above exactly.
2. Sort findings by confidence (highest first) within each severity level.
3. Order severity levels: Critical > High > Medium > Low > Informational.
4. Findings below the threshold get a description but no **Fix** or **Attack Path** block.
5. Use the finding format from `finding-format.md` for each individual finding.
6. Static analysis summary is only included when the static-analyzer agent runs.
7. Solodit references are only included when cross-referencing was performed.
8. Draft findings directly in report format — do not re-generate or re-describe.
9. Deduplicate by root cause. Two findings with the same root cause but different locations are merged into one finding listing all locations.
```
