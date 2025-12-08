// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.1.0) (interfaces/IERC1363Receiver.sol)

pragma solidity ^0.8.20;

/**
 * @title IERC1363Receiver
 * @dev Interface for any contract that wants to support `transferAndCall` or `transferFromAndCall`
 * from ERC-1363 token contracts.
 */
interface IERC1363Receiver {
    /**
     * @dev Handles the receipt of ERC-1363 tokens.
     * @param operator The address which called `transferAndCall` or `transferFromAndCall` function.
     * @param from The address which previously owned the token.
     * @param value The amount of tokens being transferred.
     * @param data Additional data with no specified format.
     * @return `bytes4(keccak256("onTransferReceived(address,address,uint256,bytes)"))` if transfer is allowed
     */
    function onTransferReceived(
        address operator,
        address from,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);
}

