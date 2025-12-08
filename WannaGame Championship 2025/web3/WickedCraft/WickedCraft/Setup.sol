// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {WannaCoin} from "./WannaCoin.sol";
import {Aggregator} from "./Aggregator.sol";

contract Setup {
    WannaCoin public immutable coin;
    Aggregator public immutable aggregator;

    constructor() {
        coin = new WannaCoin();
        aggregator = new Aggregator();
        coin.approve(address(aggregator), type(uint256).max);
    }

    function isSolved() external view returns (bool) {
        return coin.balanceOf(address(coin)) > 10_000 * 10 ** coin.decimals();
    }
}