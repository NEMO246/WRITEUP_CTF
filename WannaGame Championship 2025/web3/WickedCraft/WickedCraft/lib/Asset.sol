// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

error AssetNotReceived();
error ApprovalFailed();
error TransferFromFailed();
error TransferFailed();

library Asset {
    function permit(
        address self,
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        assembly {
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, 228))
            mstore(
                ptr,
                0xd505accf00000000000000000000000000000000000000000000000000000000
            )
            mstore(add(ptr, 4), owner)
            mstore(add(ptr, 36), spender)
            mstore(add(ptr, 68), amount)
            mstore(add(ptr, 100), deadline)
            mstore(add(ptr, 132), v)
            mstore(add(ptr, 164), r)
            mstore(add(ptr, 196), s)
            let success := call(gas(), self, 0, ptr, 228, 0, 0)
        }
    }

    function getBalanceOf(
        address self,
        address targetAddress
    ) internal view returns (uint256 amount) {
        assembly {
            switch self
            case 0 {
                amount := balance(targetAddress)
            }
            default {
                let currentInputPtr := mload(0x40)
                mstore(0x40, add(currentInputPtr, 68))
                mstore(
                    currentInputPtr,
                    0x70a0823100000000000000000000000000000000000000000000000000000000
                )
                mstore(add(currentInputPtr, 4), targetAddress)
                let currentOutputPtr := add(currentInputPtr, 36)
                if iszero(
                    staticcall(
                        gas(),
                        self,
                        currentInputPtr,
                        36,
                        currentOutputPtr,
                        32
                    )
                ) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }

                amount := mload(currentOutputPtr)
            }
        }
    }

    function approve(address self, address spender, uint256 amount) internal {
        uint256 ptr;
        assembly {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 68))
            mstore(
                ptr,
                0x095ea7b300000000000000000000000000000000000000000000000000000000
            )
            mstore(add(ptr, 4), spender)
            mstore(add(ptr, 36), amount)
        }

        bool success;
        assembly {
            success := call(gas(), self, 0, ptr, 68, 0, 0)
        }
        if (!success) {
            revert ApprovalFailed();
        }
    }

    function transferFrom(
        address self,
        address from,
        address to,
        uint256 amount
    ) internal {
        uint256 ptr;
        assembly {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 100))
            mstore(
                ptr,
                0x23b872dd00000000000000000000000000000000000000000000000000000000
            )
            mstore(add(ptr, 4), from)
            mstore(add(ptr, 36), to)
            mstore(add(ptr, 68), amount)
        }

        bool success;
        assembly {
            success := call(gas(), self, 0, ptr, 100, 0, 0)
        }
        if (!success) {
            revert TransferFromFailed();
        }
    }

    function transfer(address self, address to, uint256 amount) internal {
        uint256 ptr;
        assembly {
            ptr := mload(0x40)
            mstore(0x40, add(ptr, 68))
            mstore(
                ptr,
                0xa9059cbb00000000000000000000000000000000000000000000000000000000
            )
            mstore(add(ptr, 4), to)
            mstore(add(ptr, 36), amount)
        }

        bool success;
        assembly {
            success := call(gas(), self, 0, ptr, 68, 0, 0)
        }
        if (!success) {
            revert TransferFailed();
        }
    }
}
