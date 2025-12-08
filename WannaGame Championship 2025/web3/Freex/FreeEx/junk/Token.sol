// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./ERC20.sol";

contract WannaETH is ERC20 {
    uint256 constant TOTAL_SUPPLY = 1_000_000 * 10 ** 18;
    uint256 public maxAmountPerTx = 5 * 10 ** 18;

    constructor() ERC20("WannaETH", "WETH") {
        _mint(msg.sender, TOTAL_SUPPLY);
    }
}