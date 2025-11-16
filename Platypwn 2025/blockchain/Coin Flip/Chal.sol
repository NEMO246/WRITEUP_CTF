pragma solidity ^0.8.13;

contract Chal {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Accept ether
    receive() external payable {}
    
    // Simple withdraw function - players need to drain the contract
    function flip() external payable {
        require(msg.value >= 0.05 ether, "Must send ether to flip");
        require(msg.value <= 5 ether, "Max 5 ether per flip");
        // Flip a coin
        if (uint256(blockhash(block.number - 1)) % 2 == 0) {
            // Win
            payable(msg.sender).transfer(msg.value * 12 / 10);
        }
    }
    
    // Get balance
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}