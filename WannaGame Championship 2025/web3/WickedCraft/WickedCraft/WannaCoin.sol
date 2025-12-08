pragma solidity ^0.8.20;

import {Multicall} from "./openzeppelin/Multicall.sol";
import "./openzeppelin/ERC20/ERC20.sol";

contract WannaCoin is ERC20, Multicall {
    constructor() ERC20("WannaCoin", "WC") {
        _mint(msg.sender, 1_000_000 * 10 ** decimals());
    }
}