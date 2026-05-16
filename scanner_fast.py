#!/usr/bin/env python3
"""
Fast Solidity Vulnerability Scanner
Efficient grep-based scanning for the 10 most common DeFi bug classes.
Built from 2,749 Immunefi reports analysis. Targets real bug bounty findings.
"""

import re
import os
import sys
import json
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

class FastScanner:
    def __init__(self, contract_dir):
        self.contract_dir = Path(contract_dir)
        self.findings = []
        self.stats = {"files": 0, "lines": 0}

    def scan_file(self, filepath):
        """Scan a single Solidity file for all vulnerability patterns"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
        except:
            return []

        findings = []
        lines = content.split('\n')

        # ============================================================
        # 1. ACCOUNTING DESYNC (37% of Criticals)
        # ============================================================
        # Supply tracking variables
        supply_vars = set(re.findall(
            r'\b(totalSupply|totalAssets|totalShares|totalDebt|totalCollateral|totalStaked)\b',
            content
        ))
        if len(supply_vars) >= 2:
            # Find functions that modify some but not all supply vars
            for match in re.finditer(
                r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|external|internal|private)\s*[^{]*\{',
                content
            ):
                fn_name = match.group(1)
                fn_start = match.end()
                # Find matching close brace
                depth = 1
                i = fn_start
                while i < len(content) and depth > 0:
                    if content[i] == '{': depth += 1
                    elif content[i] == '}': depth -= 1
                    i += 1
                fn_body = content[fn_start:i-1]

                modifies = [v for v in supply_vars if re.search(rf'\b{v}\s*[+\-*/&|]?=', fn_body)]
                if len(modifies) >= 1 and len(modifies) < len(supply_vars):
                    missing = supply_vars - set(modifies)
                    findings.append({
                        'severity': 'HIGH',
                        'title': f'{fn_name}() updates {modifies} but not {missing}',
                        'file': str(filepath),
                        'category': 'Accounting Desync',
                        'description': f'Function modifies some supply variables but not all. Check if {missing} should also be updated.'
                    })

        # ============================================================
        # 2. ACCESS CONTROL (most common High)
        # ============================================================
        # Find functions with similar prefixes
        funcs_with_mods = []
        for match in re.finditer(
            r'function\s+(\w+)\s*\([^)]*\)\s*((?:public|external|internal|private)\s*(?:virtual\s*)?(?:override\s*)?(?:\w+\s*)*)',
            content
        ):
            funcs_with_mods.append({
                'name': match.group(1),
                'modifiers': match.group(2) or '',
                'pos': match.start()
            })

        # Group by prefix
        prefixes = defaultdict(list)
        for f in funcs_with_mods:
            for prefix in ['set', 'add', 'remove', 'transfer', 'mint', 'burn',
                          'deposit', 'withdraw', 'stake', 'unstake', 'claim',
                          'harvest', 'redeem', 'rescue', 'disable', 'enable',
                          'pause', 'unpause', 'update', 'initialize']:
                if f['name'].startswith(prefix):
                    prefixes[prefix].append(f)
                    break

        for prefix, funcs in prefixes.items():
            if len(funcs) < 2:
                continue
            modded = [f for f in funcs if any(m in f['modifiers'] for m in
                     ['onlyOwner', 'onlyRole', 'onlyAdmin', 'nonReentrant', 'onlyGovernor'])]
            unmodded = [f for f in funcs if not any(m in f['modifiers'] for m in
                       ['onlyOwner', 'onlyRole', 'onlyAdmin', 'nonReentrant', 'onlyGovernor'])]
            if modded and unmodded:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': f'Inconsistent access control: {prefix}* functions',
                    'file': str(filepath),
                    'category': 'Access Control',
                    'description': f'Protected: {[f["name"] for f in modded]}. Unprotected: {[f["name"] for f in unmodded]}. Verify the unprotected functions need access control.'
                })

        # ============================================================
        # 3. REENTRANCY (CEI violations)
        # ============================================================
        ext_call_pattern = r'\.(?:call\{value|call\(|safeTransfer\(|safeTransferFrom\(|transfer\()'
        state_change_pattern = r'(\w+)\s*=\s*[^=]|(\w+)\s*\+=\s*|(\w+)\s*-=\s*'

        for match in re.finditer(
            r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)\s*(?:virtual\s*)?(?:override\s*)?(?:\w+\s*)*(?:returns\s*\([^)]*\))?\s*\{',
            content
        ):
            fn_name = match.group(1)
            fn_start = match.end()
            depth = 1
            i = fn_start
            while i < len(content) and depth > 0:
                if content[i] == '{': depth += 1
                elif content[i] == '}': depth -= 1
                i += 1
            fn_body = content[fn_start:i-1]

            has_nonreentrant = 'nonReentrant' in match.group(0)
            ext_calls = list(re.finditer(ext_call_pattern, fn_body))

            if ext_calls and not has_nonreentrant:
                # Check CEI: state changes after external calls
                for ext in ext_calls:
                    after_call = fn_body[ext.end():ext.end()+500]
                    state_after = re.findall(state_change_pattern, after_call)
                    if state_after:
                        findings.append({
                            'severity': 'HIGH',
                            'title': f'Potential CEI violation in {fn_name}()',
                            'file': str(filepath),
                            'category': 'Reentrancy',
                            'description': f'External call at position {ext.start()}, state changes found after. Missing nonReentrant modifier.'
                        })
                        break

        # ============================================================
        # 4. ORACLE / FLASH LOAN MANIPULATION
        # ============================================================
        if 'slot0' in content:
            line_no = content[:content.find('slot0')].count('\n') + 1
            findings.append({
                'severity': 'HIGH',
                'title': 'Uses Uniswap V3 slot0() — manipulable via flash loans',
                'file': str(filepath), 'line': line_no,
                'category': 'Oracle Manipulation',
                'description': 'slot0() returns current tick which can be manipulated. Use TWAP (observe()) instead.'
            })

        if 'getReserves()' in content:
            line_no = content[:content.find('getReserves()')].count('\n') + 1
            findings.append({
                'severity': 'HIGH',
                'title': 'Uses Uniswap V2 getReserves() — manipulable via flash loans',
                'file': str(filepath), 'line': line_no,
                'category': 'Oracle Manipulation',
                'description': 'getReserves() returns spot reserves manipulable via flash swaps. Use TWAP.'
            })

        # ============================================================
        # 5. ERC4626 VAULT ISSUES
        # ============================================================
        if 'totalAssets' in content or 'ERC4626' in content:
            # balanceOf(address(this)) without first-depositor protection
            if 'balanceOf(address(this))' in content or 'balanceOf(IERC20' in content:
                has_protection = any(x in content for x in [
                    'MIN_SHARES', '_decimalsOffset', 'deadShares',
                    'virtualShares', 'MINIMUM_SHARES', 'initialShares', '1e'
                ])
                if not has_protection:
                    findings.append({
                        'severity': 'HIGH',
                        'title': 'No first-depositor protection in ERC4626 vault',
                        'file': str(filepath),
                        'category': 'ERC4626 Vault',
                        'description': 'totalAssets uses balanceOf(this) but no MIN_SHARES or decimals offset. First depositor can inflate share price via donation attack.'
                    })

            # Check deposit vs mint use same internal path
            has_deposit = 'function deposit(' in content
            has_mint = 'function mint(' in content
            if has_deposit and has_mint:
                dep_match = re.search(r'function\s+deposit\s*\([^)]*\)[^{]*\{', content)
                mint_match = re.search(r'function\s+mint\s*\([^)]*\)[^{]*\{', content)
                if dep_match and mint_match:
                    # Get function bodies (simple approach)
                    def get_body(start):
                        depth = 1; i = start
                        while i < len(content) and depth > 0:
                            if content[i] == '{': depth += 1
                            elif content[i] == '}': depth -= 1
                            i += 1
                        return content[start:i-1]

                    dep_body = get_body(dep_match.end())
                    mint_body = get_body(mint_match.end())

                    dep_internal = set(re.findall(r'(_\w+)\(', dep_body))
                    mint_internal = set(re.findall(r'(_\w+)\(', mint_body))

                    if dep_internal != mint_internal:
                        diff = dep_internal ^ mint_internal
                        findings.append({
                            'severity': 'MEDIUM',
                            'title': f'deposit() and mint() call different internal functions: {diff}',
                            'file': str(filepath),
                            'category': 'ERC4626 / Incomplete Path',
                            'description': 'The two entry points use different internal paths. One may skip validation checks.'
                        })

        # ============================================================
        # 6. PROXY / UPGRADE ISSUES
        # ============================================================
        init_funcs = re.findall(r'function\s+(?:initialize|init|__init)\s*\([^)]*\)[^{]*\{', content)
        for func_sig in init_funcs:
            has_initializer = 'initializer' in func_sig.lower()
            if not has_initializer and ('proxy' in str(filepath).lower() or
                'Upgradeable' in content or 'UUPS' in content):
                findings.append({
                    'severity': 'HIGH',
                    'title': 'initialize() missing initializer modifier in proxy contract',
                    'file': str(filepath),
                    'category': 'Proxy/Upgrade',
                    'description': 'Anyone can call initialize() and take ownership of the implementation contract.'
                })
                break

        if ('UUPSUpgradeable' in content or 'TransparentUpgradeableProxy' in content):
            if '_disableInitializers' not in content:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'Upgradeable contract missing _disableInitializers in constructor',
                    'file': str(filepath),
                    'category': 'Proxy/Upgrade',
                    'description': 'Implementation contract can be initialized by anyone.'
                })

        # ============================================================
        # 7. SIGNATURE REPLAY
        # ============================================================
        if 'ECDSA' in content or 'ecrecover' in content:
            if 'chainId' not in content and 'CHAIN_ID' not in content and 'chainid' not in content:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': 'Signature verification missing chainId — cross-chain replay risk',
                    'file': str(filepath),
                    'category': 'Signature Replay',
                    'description': 'Without chainId in the signed data, signatures can be replayed on forks or other chains.'
                })

            has_nonce = bool(re.search(r'\bnonce', content))
            has_deadline = bool(re.search(r'\bdeadline|\bexpir', content, re.I))
            if not has_nonce and not has_deadline:
                findings.append({
                    'severity': 'LOW',
                    'title': 'Signature missing nonce/deadline — may be replayable',
                    'file': str(filepath),
                    'category': 'Signature Replay',
                    'description': 'Consider adding nonce and deadline to prevent signature reuse.'
                })

        # ============================================================
        # 8. TOKEN HANDLING
        # ============================================================
        # Unsafe transfer() instead of safeTransfer()
        for match in re.finditer(r'(?<!safe)\.transfer\(', content):
            line_no = content[:match.start()].count('\n') + 1
            context = lines[line_no-1] if line_no <= len(lines) else ''
            if 'payable' not in context.lower() and 'address(' not in context:
                findings.append({
                    'severity': 'LOW',
                    'title': 'Using .transfer() which may fail silently on non-standard tokens',
                    'file': str(filepath), 'line': line_no,
                    'category': 'Token Handling',
                    'description': 'Some tokens (USDT, BNB) don\'t revert on transfer() failure. Use SafeERC20.safeTransfer().'
                })

        # ============================================================
        # 9. UNCHECKED EXTERNAL CALL RETURN VALUES
        # ============================================================
        # .call() without success check
        for match in re.finditer(r'\.call\{([^}]*)\}\(([^)]*)\)(?!\s*[;}]?\s*(?:require|if)\s*\()', content):
            # Verify there's no success check nearby
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 100)
            surrounding = content[start:end]
            if 'success' not in surrounding and 'require(' not in surrounding:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': '.call() without checking return value',
                    'file': str(filepath),
                    'category': 'Error Handling',
                    'description': 'Low-level .call() return value not checked. Failed calls silently succeed.'
                })

        # ============================================================
        # 10. UNINITIALIZED STATE VARIABLES
        # ============================================================
        # Check for owner/manager addresses set to address(0) by default
        for match in re.finditer(r'address\s+(?:public|private|internal)?\s*(\w*(?:owner|admin|manager|governor)\w*)', content):
            var_name = match.group(1)
            # Check if it's set in constructor
            if 'constructor' in content and var_name not in content[content.find('constructor'):content.find('constructor')+500]:
                findings.append({
                    'severity': 'MEDIUM',
                    'title': f'{var_name} may be uninitialized (not set in constructor)',
                    'file': str(filepath),
                    'category': 'Initialization',
                    'description': f'Variable {var_name} is declared but may not be initialized in the constructor. Defaults to address(0).'
                })

        return findings

    def run(self):
        """Scan all Solidity files in directory using thread pool"""
        sol_files = []
        for sol_file in self.contract_dir.rglob("*.sol"):
            path_str = str(sol_file).lower()
            # Skip test/mock/lib files
            if any(x in path_str for x in ['/test/', '/mock/', '/lib/', '/forge/', '/script/', '/node_modules/']):
                continue
            sol_files.append(sol_file)

        self.stats["files"] = len(sol_files)
        print(f"Scanning {len(sol_files)} Solidity files...")

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self.scan_file, f): f for f in sol_files}
            done = 0
            for future in as_completed(futures):
                file_findings = future.result()
                self.findings.extend(file_findings)
                done += 1
                if done % 50 == 0:
                    print(f"  Progress: {done}/{len(sol_files)} files, {len(self.findings)} findings so far")

        return self

    def print_report(self):
        """Print findings report grouped by severity"""
        print("\n" + "=" * 80)
        print("SMART CONTRACT VULNERABILITY SCAN REPORT")
        print("=" * 80)
        print(f"Files analyzed: {self.stats['files']}")
        print(f"Total findings: {len(self.findings)}")

        severity_order = ['HIGH', 'MEDIUM', 'LOW', 'INFO']
        for sev in severity_order:
            sev_findings = [f for f in self.findings if f['severity'] == sev]
            if sev_findings:
                print(f"\n--- {sev} ({len(sev_findings)} findings) ---")
                for f in sev_findings:
                    desc_short = f['description'][:120]
                    print(f"\n  [{f['category']}] {f['title']}")
                    print(f"  File: {f['file']}")
                    print(f"  {desc_short}")

        # Also save JSON
        with open('scan_results.json', 'w') as fp:
            json.dump({
                'stats': self.stats,
                'findings': self.findings
            }, fp, indent=2)
        print(f"\nResults saved to scan_results.json")

        return self.findings


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 scanner_fast.py <path_to_solidity_contracts>")
        sys.exit(1)

    path = sys.argv[1]
    scanner = FastScanner(path)
    scanner.run()
    scanner.print_report()
