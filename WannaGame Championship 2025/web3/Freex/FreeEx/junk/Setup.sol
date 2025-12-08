// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./Token.sol";
import "./Exchange.sol";

contract Setup {
    WannaETH public immutable weth;
    WannaETH public immutable oneEth;
    Exchange public immutable exchange;
    address player;
    mapping(address => uint) public receivedWannaETH;

    constructor() {
        weth = new WannaETH();
        oneEth = new WannaETH();
        exchange = new Exchange(address(weth),address(oneEth));
        weth.transfer(address(exchange), 100_000 * 10 ** 18);
        oneEth.transfer(address(exchange), 100_000 * 10 ** 18);

    }

    function register() external {
        //Only accept one register per instance 
        require(player == address(0), "Already registered");
        player = msg.sender;
    }

    function BalanceW(address addr) external view returns (uint256 balance) {
        return weth.balanceOf(addr);
    }

    function BalanceO(address addr) external view returns (uint256 balance) {
        return oneEth.balanceOf(addr);
    }

    function receiveWannaETH() external {
        require(receivedWannaETH[player] < 3, "Invalid amount");
        weth.transfer(player, 1 * 10 ** 18);
        receivedWannaETH[player]++;
    }

    function isSolved() external view returns (bool) {
        return (player!= address(0) && oneEth.balanceOf(player) > 10 * 10 ** 18);
    }
}