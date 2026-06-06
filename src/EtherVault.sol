// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title EtherVault — A deliberately vulnerable ETH savings vault
/// @notice ⚠️  DO NOT USE IN PRODUCTION — for educational purposes only
/// @dev    Demonstrates the classic reentrancy vulnerability pattern.
///         The bug: balance is decremented AFTER the external .call(),
///         allowing an attacker to re-enter withdraw() before their
///         balance is zeroed out.
contract EtherVault {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    // ✅ Deposit is fine — state is updated, then no external call
    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // ❌ VULNERABLE — violates Checks-Effects-Interactions
    //
    //  Execution order (WRONG):
    //    1. Check: require(balances[msg.sender] > 0)        ← guard passes
    //    2. Interact: (bool ok,) = msg.sender.call{...}()   ← triggers attacker fallback
    //       └─ attacker re-enters withdraw() here ──────────┐
    //          guard still passes (balance not zeroed yet!)  │
    //          another .call() fires …                       │ (repeats N times)
    //    3. Effect: balances[msg.sender] = 0  ←─────────────┘ only runs at the end
    //
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        // ❌ External call BEFORE state update — attacker re-enters here
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");

        // ❌ State update happens too late — attacker already drained the vault
        balances[msg.sender] = 0;

        emit Withdrawn(msg.sender, amount);
    }

    /// @notice Returns total ETH held in the vault
    function totalLocked() external view returns (uint256) {
        return address(this).balance;
    }
}
