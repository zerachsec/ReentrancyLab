# ⚔️ Reentrancy Lab

> A hands-on research repository demonstrating the reentrancy vulnerability — from first principles to a working Foundry exploit proof-of-concept.

![Foundry](https://img.shields.io/badge/Built_with-Foundry-FF6B35?style=flat-square)
![Solidity](https://img.shields.io/badge/Solidity-0.8.19-363636?style=flat-square&logo=solidity)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Educational-blue?style=flat-square)

> ⚠️ **For educational and research purposes only.** Do not deploy vulnerable contracts to any live network.

---

## 📁 Repository Structure

```
reentrancy-lab/
├── src/
│   ├── EtherVault.sol          # ❌ Vulnerable contract
│   └── EtherVaultFixed.sol     # ✅ Patched contract (CEI + mutex)
├── poc/
│   └── ReentrancyAttacker.sol  # 🔴 Exploit contract
├── test/
│   └── ReentrancyTest.t.sol    # 🧪 Full Foundry test suite
├── script/                     # Deploy scripts (optional)
├── foundry.toml
└── README.md
```

---

## 🧠 The Vulnerability at a Glance

Reentrancy occurs when a contract makes an **external call before updating its own state**, allowing the called contract to loop back in and call again while the state is still stale.

```
❌ WRONG ORDER (Vulnerable)        ✅ RIGHT ORDER (CEI Pattern)
─────────────────────────────      ──────────────────────────────
1. Check  (balances[x] > 0)        1. Check  (balances[x] > 0)
2. Interact (x.call{value}())      2. Effect  (balances[x] = 0)
3. Effect  (balances[x] = 0)       3. Interact (x.call{value}())
       ↑                                  ↑
  attacker re-enters here           state already consistent — safe
```

---

## 🚀 Quick Start

### Prerequisites

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Clone and Install

```bash
git clone https://github.com/YOUR_HANDLE/reentrancy-lab
cd reentrancy-lab
forge install OpenZeppelin/openzeppelin-contracts
```

### Run Tests

```bash
# Run all tests with full trace
forge test -vvvv

# Run only the attack demo
forge test --match-test test_attackSucceeds -vvvv

# Run the fuzz test
forge test --match-test test_fuzz_depositWithdrawInvariant -vvv

# View gas report
forge test --gas-report
```

---

## 🔍 Contract Breakdown

### `EtherVault.sol` — The Vulnerable Contract

The classic mistake: `withdraw()` sends ETH via `.call()` **before** zeroing the sender's balance.

```solidity
function withdraw() external {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "Nothing to withdraw");

    (bool success, ) = msg.sender.call{value: amount}(""); // ← external call first
    require(success, "ETH transfer failed");

    balances[msg.sender] = 0; // ← state update too late
}
```

### `ReentrancyAttacker.sol` — The Exploit

The attacker's `receive()` fallback fires every time the vault sends ETH, immediately calling `withdraw()` again before the vault's state updates.

```solidity
receive() external payable {
    if (address(vault).balance >= DEPOSIT_AMOUNT) {
        vault.withdraw(); // ← re-enters before balances[attacker] == 0
    }
}
```

### `EtherVaultFixed.sol` — The Fix

Two defences applied together:

1. **CEI (Checks-Effects-Interactions)** — zero the balance *before* the external call
2. **`nonReentrant` mutex** — OpenZeppelin's lock as a belt-and-suspenders guard

```solidity
function withdraw() external nonReentrant {
    uint256 amount = balances[msg.sender];
    require(amount > 0, "Nothing to withdraw");

    balances[msg.sender] = 0;          // ← Effect first
    (bool success, ) = msg.sender.call{value: amount}(""); // ← Interact last
    require(success, "ETH transfer failed");
}
```

---

## 🧪 Test Suite Overview

| Test | What it proves |
|------|---------------|
| `test_depositUpdatesBalance` | Baseline: vault accounting is correct |
| `test_legitimateWithdrawWorks` | Honest users can withdraw normally |
| `test_attackSucceeds` | **Exploit works** — vault is drained, victims lose funds |
| `test_victimCannotWithdrawAfterAttack` | Alice's withdrawal reverts after drain |
| `test_fixedVaultBlocksReentrancy` | Fixed vault blocks double-withdraw |
| `test_ceiPatternPreventsTheft` | Each withdrawal is exact — no over-drain |
| `test_fuzz_depositWithdrawInvariant` | 256-run fuzz: deposit always recoverable |
| `test_theDAOPattern` | Conceptual reproduction of The DAO 2016 attack |

---

## 📖 Real-World Cases Referenced

| Protocol | Year | Loss | Root Cause |
|----------|------|------|------------|
| The DAO | 2016 | ~$60M | `splitDAO()` called transfer before zeroing balance |
| Lendf.Me | 2020 | $25M | ERC-777 token hook + reentrancy |
| Cream Finance | 2021 | $18.8M | Cross-function reentrancy via flash loans |
| Reentrancy Guard bypass | 2022 | Various | `view` function reentrancy (read-only reentrancy) |

---

## 🛡️ Mitigations Summary

1. **CEI Pattern** — Always: Check → Effect → Interact
2. **ReentrancyGuard** — OpenZeppelin's `nonReentrant` modifier
3. **Pull-over-push** — Let users withdraw instead of pushing ETH to them
4. **Avoid ERC-777 / callback tokens** in sensitive contexts unless guarded

---

## 📝 License

MIT — free to use for learning and research.
