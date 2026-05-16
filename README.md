# Solidity Vulnerability Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-%E2%9D%A4-red)](https://github.com/sponsors/Grems247-ZR)

Fast, offline Solidity smart contract vulnerability scanner targeting the **10 most common DeFi bug classes** — derived from analysis of 2,749 Immunefi reports and 681 DeFiHack reproductions.

## Why This Scanner?

Most security tools (Slither, Mythril) are general-purpose and produce overwhelming output. This scanner focuses on the bug classes that actually pay out:

| Bug Class | % of Critical Payouts | What It Finds |
|-----------|----------------------|---------------|
| Accounting Desync | 37% | Mismatched state variable updates |
| Access Control | 19% | Missing modifiers on sibling functions |
| Reentrancy | 15% | CEI violations, missing nonReentrant |
| Oracle Manipulation | 12% | TWAP vs spot price, flash loan vectors |
| ERC4626 Vault | 8% | Donation attacks, deposit/mint divergence |
| Proxy/Upgrade | 5% | Uninitialized implementations |
| Signature Replay | 2% | Missing chainId, nonce, expiry |
| Token Handling | 1% | Unsafe transfer(), non-standard tokens |
| Rounding Errors | 1% | Division precision loss, dust accumulation |

## Quick Start

```bash
# Scan a directory of Solidity contracts
python3 scanner_fast.py /path/to/contracts/

# Output: terminal report + scan_results.json
```

## Example Output

```
================================================================================
SMART CONTRACT VULNERABILITY SCAN REPORT
================================================================================
Files analyzed: 54
Total findings: 12

--- HIGH (3 findings) ---
  [Accounting Desync] deposit() updates totalSupply but not totalShares
  [Oracle Manipulation] Uses Uniswap V3 slot0() at StakingRewards.sol:245
  [ERC4626 Vault] No first-depositor protection in Vault.sol

--- MEDIUM (5 findings) ---
  [Access Control] Inconsistent access control: set* functions
  [Signature Replay] Missing chainId in ECDSA verification
  ...

--- LOW (4 findings) ---
  [Token Handling] Using .transfer() instead of safeTransfer()
  ...
```

## Features

- **Fast**: Multi-threaded, scans hundreds of files in seconds
- **Targeted**: Only reports on the 10 bug classes that matter for bug bounties
- **Offline**: No API calls, no external dependencies beyond Python stdlib
- **JSON output**: Machine-readable results for CI/CD pipelines
- **Severity-ranked**: HIGH/MEDIUM/LOW with actionable descriptions

## Use Cases

- **Bug Bounty Hunters**: Pre-scan targets before diving deep
- **Audit Firms**: First-pass triage to focus manual review
- **DeFi Protocols**: CI/CD security gate before deployments
- **Security Researchers**: Identify patterns across multiple protocols

## Installation

```bash
pip install -r requirements.txt
# requirements.txt is empty — no dependencies needed!
```

## Supported Platforms

- Ethereum / EVM chains
- Solidity ^0.8.0
- Foundry / Hardhat project structures

## Sponsorship

This tool is free and open-source. If it helps you find a bug, consider [sponsoring](https://github.com/sponsors/Grems247-ZR) to support continued development.

---

Built from analysis of real Immunefi payouts. MIT License.
