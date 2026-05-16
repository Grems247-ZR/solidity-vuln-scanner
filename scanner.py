#!/usr/bin/env python3
"""
Smart Contract Vulnerability Scanner
Focuses on the 10 most common DeFi bug classes from Immunefi analysis.
Built from 2,749 Immunefi reports methodology.
"""

import re
import os
import sys
import json
from pathlib import Path
from collections import defaultdict

class SolidityScanner:
    def __init__(self, contract_dir):
        self.contract_dir = Path(contract_dir)
        self.findings = []
        self.files = {}

    def load_files(self):
        """Load all Solidity files from directory"""
        for sol_file in self.contract_dir.rglob("*.sol"):
            # Skip test files, mock files, libraries
            if any(x in str(sol_file).lower() for x in ['/test/', '/mock/', '/lib/', '/forge/', '/script/']):
                continue
            try:
                with open(sol_file, 'r') as f:
                    self.files[str(sol_file)] = f.read()
            except:
                pass
        print(f"Loaded {len(self.files)} Solidity files")

    def finding(self, severity, title, filepath, line, description, category=""):
        """Record a finding"""
        self.findings.append({
            'severity': severity,
            'title': title,
            'file': filepath,
            'line': line,
            'description': description,
            'category': category
        })

    def check_accounting_desync(self):
        """Check 1: Accounting State Desynchronization (37% of Criticals)"""
        print("\n[1/10] Checking for accounting desync patterns...")

        for filepath, content in self.files.items():
            lines = content.split('\n')

            # Pattern: find all state variables related to balance/supply
            supply_vars = re.findall(r'(totalSupply|totalAssets|totalShares|totalDebt|totalCollateral|totalStaked|totalCoolingDown)', content)
            unique_vars = set(supply_vars)

            if len(unique_vars) >= 2:
                # Check: are all supply vars updated together in each function?
                functions = re.findall(r'function\s+(\w+)\s*\([^)]*\)', content)

                for func_name in functions:
                    # Find the function body
                    func_match = re.search(rf'function\s+{func_name}\s*\([^)]*\)[^{{]*{{', content)
                    if not func_match:
                        continue

                    # Find matching closing brace
                    start = func_match.end()
                    depth = 1
                    i = start
                    while i < len(content) and depth > 0:
                        if content[i] == '{':
                            depth += 1
                        elif content[i] == '}':
                            depth -= 1
                        i += 1
                    func_body = content[start:i-1]

                    # Check which vars are modified
                    modified = [v for v in unique_vars if v in func_body and re.search(rf'{v}\s*[+\-*/=]', func_body)]

                    # Check for early returns before state updates
                    early_returns = re.findall(r'\breturn\b', func_body)
                    if early_returns and modified:
                        # Find early returns and check if all state updates happen BEFORE them
                        return_positions = [m.start() for m in re.finditer(r'\breturn\b', func_body)]
                        for v in modified:
                            last_update = func_body.rfind(v)
                            if any(last_update < pos for pos in return_positions if pos != return_positions[-1]):
                                self.finding(
                                    'HIGH', f'Potential accounting desync: {v} updated after early return',
                                    filepath, func_body[:50].count('\n') + 1,
                                    f'Function {func_name} has early returns. Variable {v} may not be updated in all code paths.',
                                    'Accounting Desync'
                                )

    def check_access_control(self):
        """Check 2: Access Control - Missing modifiers on sibling functions"""
        print("[2/10] Checking access control patterns...")

        for filepath, content in self.files.items():
            # Find all modifiers
            modifiers = re.findall(r'modifier\s+(\w+)', content)

            # Find functions and their modifiers
            func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|external|internal|private)\s*(?:virtual\s*)?(?:override\s*)?(\w+)?'
            functions = re.findall(func_pattern, content)

            # Find all functions with specific modifiers
            func_with_mod = defaultdict(list)
            for match in re.finditer(r'function\s+(\w+)\s*\([^)]*\)\s*((?:public|external|internal|private)\s*(?:virtual\s*)?(?:override\s*)?(?:\w+\s*)*)(?:returns\s*\([^)]*\))?\s*{', content):
                func_name = match.group(1)
                func_mods = match.group(2) if match.group(2) else ""

                for mod in ['onlyRole', 'onlyOwner', 'onlyAdmin']:
                    if mod in func_mods:
                        func_with_mod[mod].append(func_name)

            # Find functions that are sibling-like (similar prefixes)
            func_names = [m.group(1) for m in re.finditer(r'function\s+(\w+)\s*\(', content)]
            prefixes = defaultdict(list)
            for name in func_names:
                for prefix in ['set', 'add', 'remove', 'transfer', 'mint', 'burn', 'deposit', 'withdraw',
                               'stake', 'unstake', 'claim', 'harvest', 'redeem', 'rescue', 'disable', 'enable']:
                    if name.startswith(prefix):
                        prefixes[prefix].append(name)
                        break

            # Check: do all siblings have the same modifiers?
            for prefix, names in prefixes.items():
                if len(names) < 2:
                    continue
                modded = []
                unmodded = []
                for name in names:
                    func_pos = content.find(f'function {name}(')
                    if func_pos == -1:
                        continue
                    # Get the function signature line
                    end_of_line = content.find('\n', func_pos)
                    sig = content[func_pos:end_of_line]
                    if any(m in sig for m in ['onlyRole', 'onlyOwner', 'onlyAdmin', 'nonReentrant']):
                        modded.append(name)
                    else:
                        unmodded.append(name)

                if modded and unmodded:
                    self.finding(
                        'MEDIUM',
                        f'Sibling functions with {prefix} prefix have inconsistent access control',
                        filepath, 1,
                        f'Functions with modifiers: {modded}. Functions without: {unmodded}. '
                        f'Check if {unmodded} should also have access control.',
                        'Access Control / Incomplete Path'
                    )

    def check_reentrancy(self):
        """Check 3: Reentrancy - CEI violations"""
        print("[3/10] Checking reentrancy patterns...")

        for filepath, content in self.files.items():
            funcs = re.finditer(
                r'function\s+(\w+)\s*\([^)]*\)\s*((?:public|external|internal|private)\s*(?:virtual\s*)?(?:override\s*)?(?:\w+\s*)*)(?:returns\s*\([^)]*\))?\s*{',
                content
            )

            for match in funcs:
                func_name = match.group(1)
                func_sig = match.group(0)

                # Check if this function makes external calls
                has_external_call = bool(re.search(r'\.call\{value|\.call\(|\.safeTransfer\(|\.safeTransferFrom\(|[^\.]transfer\(', func_sig))
                has_nonreentrant = 'nonReentrant' in func_sig

                # Find function body
                start = match.end()
                depth = 1
                i = start
                while i < len(content) and depth > 0:
                    if content[i] == '{':
                        depth += 1
                    elif content[i] == '}':
                        depth -= 1
                    i += 1
                func_body = content[start:i-1]

                # Check for external calls
                ext_calls = list(re.finditer(r'\.call\{value|\.call\(|\.safeTransfer\(|\.safeTransferFrom\(|[^\.I]transfer\(', func_body))
                if ext_calls and not has_nonreentrant:
                    # Check if state changes happen after external calls
                    state_changes = list(re.finditer(
                        r'(?:^\s*|\b)(\w+)\s*=\s*[^=]|(\w+)\s*\+=\s*|(\w+)\s*-=\s*|(\w+)\.push\(|(\w+)\.pop\(', func_body))

                    for ext in ext_calls:
                        ext_pos = ext.start()
                        for sc in state_changes:
                            if sc.start() > ext_pos:
                                self.finding(
                                    'HIGH',
                                    f'Potential CEI violation: state change after external call in {func_name}',
                                    filepath, func_body[:ext_pos].count('\n') + 1,
                                    f'External call at position {ext_pos} may be followed by state change. '
                                    f'Consider adding nonReentrant.',
                                    'Reentrancy'
                                )
                                break

    def check_arithmetic(self):
        """Check 4: Arithmetic issues - division before multiplication, unchecked blocks"""
        print("[4/10] Checking arithmetic patterns...")

        for filepath, content in self.files.items():
            # Check unchecked blocks
            unchecked_blocks = re.finditer(r'unchecked\s*{', content)
            for match in unchecked_blocks:
                start = match.end()
                depth = 1
                i = start
                while i < len(content) and depth > 0:
                    if content[i] == '{': depth += 1
                    elif content[i] == '}': depth -= 1
                    i += 1
                block_body = content[start:i-1]

                # Look for dangerous patterns in unchecked blocks
                if '++' in block_body or '--' in block_body:
                    # ++ and -- in unchecked is usually fine for loop counters
                    pass
                if re.search(r'[+\-*/]\s*=', block_body) and re.search(r'amount|balance|shares|assets', block_body, re.I):
                    self.finding(
                        'MEDIUM',
                        'Arithmetic operation on financial variable in unchecked block',
                        filepath, content[:match.start()].count('\n') + 1,
                        'Verify that overflow/underflow is impossible for these financial calculations.',
                        'Arithmetic'
                    )

            # Check division before multiplication
            div_mul = re.finditer(r'(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)', content)
            for match in div_mul:
                line_no = content[:match.start()].count('\n') + 1
                self.finding(
                    'LOW',
                    f'Division before multiplication: {match.group(0)}',
                    filepath, line_no,
                    'Division before multiplication causes precision loss. Consider multiplying first.',
                    'Arithmetic'
                )

    def check_erc4626_vault(self):
        """Check 5: ERC4626 vault issues"""
        print("[5/10] Checking ERC4626 vault patterns...")

        for filepath, content in self.files.items():
            if 'ERC4626' not in content and 'totalAssets' not in content:
                continue

            lines = content.split('\n')

            # Check: totalAssets uses balanceOf(this) - donation attack vector
            balance_matches = re.finditer(r'balanceOf\(address\(this\)\)', content)
            for match in balance_matches:
                line_no = content[:match.start()].count('\n') + 1
                context = lines[line_no-1] if line_no <= len(lines) else ""

                # Check if there's mitigation (minShares, decimalsOffset, virtual shares)
                has_mitigation = any(x in content for x in [
                    'MIN_SHARES', '_decimalsOffset', 'deadShares', 'virtualShares',
                    '_checkMinShares', 'MINIMUM_SHARES', 'initialShares'
                ])

                if not has_mitigation:
                    self.finding(
                        'HIGH',
                        'totalAssets uses balanceOf(this) without first-depositor protection',
                        filepath, line_no,
                        'First depositor can inflate share price via donation attack. '
                        'Add MIN_SHARES, _decimalsOffset, or virtual shares.',
                        'ERC4626 Vault'
                    )

            # Check: deposit and mint functions have same validation path
            deposit_func = re.search(r'function\s+deposit\s*\([^)]*\)', content)
            mint_func = re.search(r'function\s+mint\s*\([^)]*\)', content)
            if deposit_func and mint_func:
                # Check both go through the same internal function
                deposit_impl = re.search(r'function\s+deposit\s*\([^)]*\)[^{]*{([^}]*(?:\{[^}]*\}[^}]*)*)}', content)
                mint_impl = re.search(r'function\s+mint\s*\([^)]*\)[^{]*{([^}]*(?:\{[^}]*\}[^}]*)*)}', content)
                if deposit_impl and mint_impl:
                    dep_calls = re.findall(r'(_\w+)\(', deposit_impl.group(1))
                    mint_calls = re.findall(r'(_\w+)\(', mint_impl.group(1))
                    if dep_calls != mint_calls and mint_calls:
                        diff = set(dep_calls) ^ set(mint_calls)
                        self.finding(
                            'MEDIUM',
                            f'Different internal function calls in deposit vs mint: {diff}',
                            filepath, 1,
                            'One path may skip validation. Check that both paths have equivalent security.',
                            'ERC4626 Vault / Incomplete Path'
                        )

    def check_rounding_and_boundary(self):
        """Check 6: Rounding errors and boundary conditions"""
        print("[6/10] Checking rounding and boundary conditions...")

        for filepath, content in self.files.items():
            lines = content.split('\n')

            # Check for division remainder handling
            div_patterns = re.finditer(r'(\w+)\s*=\s*\(?(\w+)\s*\*\s*(\w+)\)?\s*/\s*(\w+)', content)
            for match in div_patterns:
                line_no = content[:match.start()].count('\n') + 1

                # Check if remainder is handled
                func_start = content.rfind('function ', 0, match.start())
                if func_start == -1: continue
                func_end = content.find('}', match.end())
                if func_end == -1: continue

                surrounding = content[func_start:func_end]
                if 'remaining' not in surrounding.lower() and 'remainder' not in surrounding.lower():
                    # Only flag if the variable names suggest financial amounts
                    if any(x in match.group(0).lower() for x in ['amount', 'asset', 'reward', 'shares', 'balance']):
                        self.finding(
                            'LOW',
                            f'Potential rounding loss: {match.group(0)}',
                            filepath, line_no,
                            'Remainder from division is not handled. Dust amounts may accumulate or be lost.',
                            'Rounding'
                        )

    def check_initialization_and_proxy(self):
        """Check 7: Uninitialized state and proxy patterns"""
        print("[7/10] Checking initialization patterns...")

        for filepath, content in self.files.items():
            # Check: initialize() without initializer modifier
            init_funcs = re.finditer(r'function\s+(?:initialize|init|__init)\s*\([^)]*\)', content)
            for match in init_funcs:
                func_sig = match.group(0)
                line_no = content[:match.start()].count('\n') + 1

                # Check for initializer modifier
                has_initializer = bool(re.search(r'initializer\b', func_sig))

                # Check for _disableInitializers in constructor
                has_disable = '_disableInitializers' in content or 'initializer' in content

                if not has_initializer and 'proxy' in filepath.lower():
                    self.finding(
                        'HIGH',
                        f'initialize() without initializer modifier in proxy-like contract',
                        filepath, line_no,
                        'Anyone can call initialize() and potentially take ownership.',
                        'Proxy/Upgrade'
                    )

            # Check: constructor calls _disableInitializers
            if 'UUPSUpgradeable' in content or 'TransparentUpgradeableProxy' in content:
                if '_disableInitializers' not in content:
                    self.finding(
                        'MEDIUM',
                        'Upgradeable contract missing _disableInitializers in constructor',
                        filepath, 1,
                        'Without _disableInitializers, implementation contract can be initialized by anyone.',
                        'Proxy/Upgrade'
                    )

    def check_signature_replay(self):
        """Check 8: Signature replay vulnerabilities"""
        print("[8/10] Checking signature replay patterns...")

        for filepath, content in self.files.items():
            # Check ECDSA/permit usage
            if 'ECDSA' not in content and 'ecrecover' not in content:
                continue

            # Check for chainId in domain separator
            has_chain_id = 'chainId' in content or 'CHAIN_ID' in content or 'chainid' in content

            # Check for nonce tracking
            has_nonce = bool(re.search(r'nonce|_nonce|nonces', content))
            has_deadline = bool(re.search(r'deadline|expir|expiry', content, re.I))

            if not has_chain_id:
                self.finding(
                    'MEDIUM',
                    'Signature verification missing chainId - cross-chain replay possible',
                    filepath, 1,
                    'Without chainId in the signed data, signatures can be replayed across chains.',
                    'Signature Replay'
                )

            if not has_deadline and not has_nonce:
                self.finding(
                    'LOW',
                    'Signature missing deadline/nonce - may be replayable',
                    filepath, 1,
                    'Consider adding deadline and nonce to prevent signature reuse.',
                    'Signature Replay'
                )

    def check_token_handling(self):
        """Check 9: Token handling issues"""
        print("[9/10] Checking token handling patterns...")

        for filepath, content in self.files.items():
            lines = content.split('\n')

            # Check: direct transfer() call instead of safeTransfer()
            unsafe_transfers = re.finditer(r'(?<!safe)\.transfer\(', content)
            for match in unsafe_transfers:
                line_no = content[:match.start()].count('\n') + 1
                # Skip if it's address.transfer (native ETH transfer - different semantics)
                context = lines[line_no-1] if line_no <= len(lines) else ""
                if '.transfer(' in context and 'address(' not in context and 'payable' not in context:
                    self.finding(
                        'LOW',
                        'Using .transfer() instead of safeTransfer() for ERC20',
                        filepath, line_no,
                        'Some tokens (like USDT) don\'t revert on failure. Use SafeERC20.safeTransfer.',
                        'Token Handling'
                    )

            # Check: balanceOf(this) for critical calculations
            bal_checks = re.finditer(r'balanceOf\(address\(this\)\)', content)
            for match in bal_checks:
                line_no = content[:match.start()].count('\n') + 1
                self.finding(
                    'INFO',
                    'balanceOf(address(this)) used - susceptible to donation',
                    filepath, line_no,
                    'Direct transfers to this contract affect this balance. Verify this is intended.',
                    'Token Handling'
                )

    def check_flash_loan_vectors(self):
        """Check 10: Flash loan attack vectors"""
        print("[10/10] Checking flash loan attack vectors...")

        for filepath, content in self.files.items():
            # Check for price oracle usage
            if 'slot0' in content:
                line_no = content[:content.find('slot0')].count('\n') + 1
                self.finding(
                    'HIGH',
                    'Uses Uniswap V3 slot0() for price - flash loan manipulable',
                    filepath, line_no,
                    'slot0() returns current tick which can be manipulated via flash swaps. '
                    'Use TWAP (observe()) instead.',
                    'Oracle / Flash Loan'
                )

            if 'getReserves()' in content:
                line_no = content[:content.find('getReserves()')].count('\n') + 1
                self.finding(
                    'HIGH',
                    'Uses Uniswap V2 getReserves() for price - flash loan manipulable',
                    filepath, line_no,
                    'getReserves() returns spot reserves manipulable via flash swaps. Use TWAP.',
                    'Oracle / Flash Loan'
                )

            # Check for functions that can be called atomically with flash loans
            func_combos = []
            if 'deposit' in content and 'withdraw' in content:
                func_combos.append(('deposit', 'withdraw'))
            if 'mint' in content and 'redeem' in content:
                func_combos.append(('mint', 'redeem'))

            for combo in func_combos:
                # Check if both functions lack rate limiting / timelocks
                has_timelock = bool(re.search(r'cooldown|timelock|delay|vesting|lock', content, re.I))
                if not has_timelock:
                    self.finding(
                        'INFO',
                        f'{combo[0]}/{combo[1]} without cooldown - potential flash loan vector',
                        filepath, 1,
                        'An attacker could deposit, manipulate state, and withdraw in a single transaction '
                        'using a flash loan.',
                        'Flash Loan'
                    )
                    break

    def run_all_checks(self):
        """Run all vulnerability checks"""
        self.load_files()
        self.check_accounting_desync()
        self.check_access_control()
        self.check_reentrancy()
        self.check_arithmetic()
        self.check_erc4626_vault()
        self.check_rounding_and_boundary()
        self.check_initialization_and_proxy()
        self.check_signature_replay()
        self.check_token_handling()
        self.check_flash_loan_vectors()
        return self

    def print_report(self):
        """Print formatted findings report"""
        print("\n" + "="*80)
        print("SMART CONTRACT VULNERABILITY SCAN REPORT")
        print("="*80)
        print(f"Files analyzed: {len(self.files)}")
        print(f"Findings: {len(self.findings)}")

        severity_order = ['HIGH', 'MEDIUM', 'LOW', 'INFO']
        for sev in severity_order:
            sev_findings = [f for f in self.findings if f['severity'] == sev]
            if sev_findings:
                print(f"\n--- {sev} ({len(sev_findings)} findings) ---")
                for f in sev_findings:
                    print(f"\n  [{f['category']}] {f['title']}")
                    print(f"  File: {f['file']}")
                    print(f"  {f['description']}")

        return self.findings


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <path_to_solidity_contracts>")
        sys.exit(1)

    path = sys.argv[1]
    scanner = SolidityScanner(path)
    scanner.run_all_checks()
    scanner.print_report()

    # Save results
    with open('scan_results.json', 'w') as f:
        json.dump(scanner.findings, f, indent=2)
    print(f"\nResults saved to scan_results.json")
