// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Asset} from "./Asset.sol";

struct SwapData {
    address toAddress;
    address fromAssetAddress;
    address toAssetAddress;
    uint256 deadline;
    uint256 amountOutMin;
    uint256 swapFee;
    uint256 amountIn;
    bool hasPermit;
    bool hasAffiliate;
    address affiliateAddress;
    uint256 affiliateFee;
}

error InvalidSignature();
error ExpiredTransaction();

library Calldata {
    using Asset for address;

    function getSwapData() internal view returns (SwapData memory swapData) {
        assembly {
            let deadline := shr(
                shr(248, calldataload(132)), // dataOffset + 62
                calldataload(shr(240, calldataload(133))) // dataOffset + 62 + 1
            )

            if lt(deadline, timestamp()) {
                // ExpiredTransaction
                mstore(
                    0,
                    0x931997cf00000000000000000000000000000000000000000000000000000000
                )
                revert(0, 4)
            }

            mstore(swapData, shr(96, calldataload(72))) // toAddress / dataOffset + 2
            mstore(add(swapData, 32), shr(96, calldataload(92))) // fromAssetAddress / dataOffset + 22
            mstore(add(swapData, 64), shr(96, calldataload(112))) // toAssetAddress / dataOffset + 42
            mstore(add(swapData, 96), deadline)
            mstore(
                add(swapData, 128),
                shr(
                    shr(248, calldataload(135)), // dataOffset + 62 + 3
                    calldataload(shr(240, calldataload(136))) // dataOffset + 62 + 4
                )
            ) // amountOutMin
            mstore(
                add(swapData, 160),
                shr(
                    shr(248, calldataload(138)), // dataOffset + 62 + 6
                    calldataload(shr(240, calldataload(139))) // dataOffset + 62 + 7
                )
            ) // swapFee
            mstore(
                add(swapData, 192),
                shr(
                    shr(248, calldataload(141)), // dataOffset + 62 + 9
                    calldataload(shr(240, calldataload(142))) // dataOffset + 62 + 10
                )
            ) // amountIn
            // calldataload(144) // r
            // calldataload(176) // s
            // shr(248, calldataload(208)) // v
            let hasPermit := gt(shr(248, calldataload(209)), 0) // permit v
            mstore(add(swapData, 224), hasPermit) // hasPermit
            // calldataload(210) // permit r
            // calldataload(242) // permit s
            // calldataload(274) // permit deadline
            switch hasPermit
            case 1 {
                let hasAffiliate := shr(248, calldataload(277))
                mstore(add(swapData, 256), hasAffiliate) // hasAffiliate
                if eq(hasAffiliate, 1) {
                    mstore(add(swapData, 288), shr(96, calldataload(278))) // affiliateAddress
                    mstore(
                        add(swapData, 320),
                        shr(
                            shr(248, calldataload(298)),
                            calldataload(shr(240, calldataload(299)))
                        )
                    ) // affiliateFee
                }
            }
            default {
                let hasAffiliate := shr(248, calldataload(210))
                mstore(add(swapData, 256), hasAffiliate) // hasAffiliate
                if eq(hasAffiliate, 1) {
                    mstore(add(swapData, 288), shr(96, calldataload(211))) // affiliateAddress
                    mstore(
                        add(swapData, 320),
                        shr(
                            shr(248, calldataload(231)),
                            calldataload(shr(240, calldataload(232)))
                        )
                    ) // affiliateFee
                }
            }
        }
    }

    function permit(SwapData memory swapData, address fromAddress) internal {
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 deadline;
        assembly {
            v := shr(248, calldataload(209))
            r := calldataload(210)
            s := calldataload(242)
            deadline := shr(
                shr(248, calldataload(274)),
                calldataload(shr(240, calldataload(275)))
            )
        }

        swapData.fromAssetAddress.permit(
            fromAddress,
            address(this),
            swapData.amountIn + swapData.swapFee + swapData.affiliateFee,
            deadline,
            v,
            r,
            s
        );
    }
}
