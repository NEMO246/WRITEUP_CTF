// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./Token.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exchange {

    enum StakePhase {
		NOTSTAKED,
		LOCKED,
		FROZEN
	}


    struct Stake {
		uint64 amount; 
		StakePhase phase;
		uint64 lastActionTimestamp;
	}

    struct Liability {
		address asset;
		uint64 timestamp;
		uint192 outstandingAmount;
	}

    mapping(address => mapping(address => int192)) public assetBalances;
    mapping(address => Liability[]) private liabilities;
    mapping(address => Stake) private stakingData;
    mapping(address => uint) public receivedWannaETH;


    IERC20 _wToken;
    IERC20 _oneToken;

    constructor(address wToken, address oneToken) {
        _wToken = IERC20(wToken);
        _oneToken = IERC20(oneToken);
    }

    // ===== View functions =====

    function getLockedStakeBalance(address user) public view returns (uint256) {
        return stakingData[user].amount;
    }

    function getStakePhase(address user) public view returns (StakePhase) {
        return stakingData[user].phase;
    }

    function getLastActionTimestamp(address user) public view returns (uint64) {
        return stakingData[user].lastActionTimestamp;
    }

    function getAssetBalance(address user, address asset) public view returns (int192) {
        return assetBalances[user][asset];
    }

    function getLiabilityCount(address user) public view returns (uint256) {
        return liabilities[user].length;
    }

    function getReceivedWannaETH(address user) public view returns (uint256) {
        return receivedWannaETH[user];
    }

    function totalReceivedWannaETH(address user) public view returns (int192) {
        return _calcAsset(user) + int192(uint192(receivedWannaETH[user]));
    }

    // ===== External user actions =====

    function deposit(IERC20 asset, uint64 amount) public {
        require(asset.balanceOf(msg.sender) >= amount, "insufficient balance");
        require(asset.transferFrom(msg.sender, address(this), amount), "transferFrom failed");
        assetBalances[msg.sender][address(asset)] += int192(uint192(amount));
    }

    function withdraw(IERC20 asset, uint64 amount) public {
        require(asset.balanceOf(address(this)) >= amount, "insufficient balance");
        require(assetBalances[msg.sender][address(asset)] >= int192(uint192(amount)), "insufficient balance");
        require(asset.transfer(msg.sender, amount), "transfer failed");
        require(amount > 0, "amount must be greater than 0");
        assetBalances[msg.sender][address(asset)] -= int192(uint192(amount));
    }

    function claimReceivedWannaETH() public {
        int192 totalReceivedWanna = totalReceivedWannaETH(msg.sender);
        require(_oneToken.transfer(msg.sender, uint(uint192(totalReceivedWanna))), "transfer failed");
        receivedWannaETH[msg.sender] = 0;
    }

    function lockStake(uint64 amount) public {
        address user = msg.sender;
        require(assetBalances[user][address(_wToken)] >= int192(uint192(amount)));
        Stake storage stake = stakingData[user];

        assetBalances[user][address(_wToken)] -= int192(uint192(amount));
        stake.amount += amount;
        stake.phase = StakePhase.LOCKED;
        stake.lastActionTimestamp = uint64(block.timestamp);
    }

    function requestReleaseStake() public {
        address user = msg.sender;
        Stake storage stake = stakingData[user];
        assetBalances[user][address(_wToken)] += int192(uint192(stake.amount));
        _updateLiabilities(
            user,
            address(_wToken),
            uint112(stake.amount),
            assetBalances[user][address(_wToken)]
        );
        stake.amount = 0;
        stake.phase = StakePhase.NOTSTAKED;
    }

    function exchangeToken(
        address sender,
        address asset,
        uint64 amount
    ) public {
        _updateBalance(sender, asset, int192(-int256(uint256(amount))));
        receivedWannaETH[sender] += amount;
    }

    // ===== Internal helpers =====

    function _updateBalance(
        address user,
        address asset,
        int192 amount
    ) internal {
        int beforeBalance = int(assetBalances[user][asset]);
        int afterBalance = beforeBalance + amount;

        require(
            (amount > 0 && afterBalance >= beforeBalance) ||
                (amount < 0 && afterBalance < beforeBalance)
        );

        if (amount > 0 && beforeBalance < 0) {
            _updateLiabilities(
                user,
                asset,
                uint112(uint256(int256(amount))),
                int192(afterBalance)
            );
        } else if (beforeBalance >= 0 && afterBalance < 0) {
            _setLiabilities(user, asset, int192(beforeBalance - afterBalance));
        }

        if (beforeBalance != afterBalance) {
            require(
                afterBalance >= type(int192).min && afterBalance <= type(int192).max
            );
            assetBalances[user][asset] = int192(afterBalance);
        }
    }

    function _updateLiabilities(
        address user,
        address asset,
        uint112 amount,
        int192 currentBalance
    ) internal {
        if (currentBalance >= 0) {
            _removeLiabilities(user, asset);
        } else {
            uint256 i;
            uint256 len = liabilities[user].length;
            for (; i < len; i++) {
                if (liabilities[user][i].asset == asset) break;
            }
            Liability storage liability = liabilities[user][i];
            if (amount >= liability.outstandingAmount) {
                liability.outstandingAmount = uint192(-currentBalance);
                liability.timestamp = uint64(block.timestamp);
            } else {
                liability.outstandingAmount -= uint192(amount);
            }
        }
    }

    function _setLiabilities(
        address user,
        address asset,
        int192 balance
    ) internal {
        liabilities[user].push(
            Liability({
                asset: asset,
                timestamp: uint64(block.timestamp),
                outstandingAmount: uint192(-balance)
            })
        );
    }

    function _removeLiabilities(address user, address asset) internal {
        uint256 length = liabilities[user].length;

        for (uint256 i = 0; i < length; i++) {
            if (liabilities[user][i].asset == asset) {
                if (length > 1) {
                    liabilities[user][i] = liabilities[user][length - 1];
                }
                liabilities[user].pop();
                break;
            }
        }
    }

    function _calcAsset(address user) internal view returns (int192) {
        int192 totalLiabilities = 0;
        for (uint256 i = 0; i < liabilities[user].length; i++) {
            Liability storage liability = liabilities[user][i];
            int192 balance = assetBalances[user][liability.asset];
            totalLiabilities += balance;
        }
        return totalLiabilities;
    }
}
