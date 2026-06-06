// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/// @title EtherVaultFixed — Reentrancy-safe version of EtherVault
/// @notice Shows TWO complementary defences applied together:
///         1. Checks-Effects-Interactions (CEI) — architectural fix
///         2. ReentrancyGuard (mutex) — belt-and-suspenders lock
contract EtherVaultFixed is ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // ✅ SAFE — CEI pattern + nonReentrant mutex
    //
    //  Execution order (CORRECT):
    //    1. Check:  require(amount > 0)
    //    2. Effect: balances[msg.sender] = 0   ← zeroed BEFORE the call
    //    3. Interact: msg.sender.call{...}()   ← re-entry now harmless
    //       └─ if attacker tries to re-enter:
    //          nonReentrant reverts immediately (mutex locked)
    //          AND balances[attacker] == 0 (guard also fails)
    //
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        // ✅ Effect first — balance zeroed before external call
        balances[msg.sender] = 0;

        // ✅ Interact last — state is already consistent
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    function totalLocked() external view returns (uint256) {
        return address(this).balance;
    }
}
