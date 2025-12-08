// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {SwapData, Calldata} from "./lib/Calldata.sol";
import {Asset} from "./lib/Asset.sol";

enum CommandAction {
    Call, // Represents a generic call to a function within a contract.
    Approval, // Represents an approval operation.
    TransferFrom, // Indicates a transfer-from operation.
    Transfer, // Represents a direct transfer operation.
    EstimateGasStart,
    EstimateGasEnd
}

contract Aggregator {
    using Asset for address;

    event Swapped(
        address indexed fromAddress,
        address indexed toAddress,
        address fromAssetAddress,
        address toAssetAddress,
        uint256 amountIn,
        uint256 amountOut
    );

    function swap(bytes calldata) external returns (uint256 amountOut) {
        SwapData memory swapData = Calldata.getSwapData();
        address fromAddress = msg.sender;
        if (swapData.hasPermit) {
            Calldata.permit(swapData, fromAddress);
        }

        address fromAssetAddress = swapData.fromAssetAddress;
        address toAssetAddress = swapData.toAssetAddress;
        address toAddress = swapData.toAddress;
        uint256 amountOutMin = swapData.amountOutMin;
        uint256 amountIn = swapData.amountIn;
        uint256 transferFromAmount;
        uint256 gasUsed;

        amountOut = toAssetAddress.getBalanceOf(toAddress);

        (transferFromAmount, gasUsed) = execute(fromAddress, fromAssetAddress);

        amountOut = toAssetAddress.getBalanceOf(toAddress) - amountOut;

        if (amountOut < amountOutMin) revert();
        if (amountIn != transferFromAmount) revert();

        emit Swapped(
            fromAddress,
            toAddress,
            fromAssetAddress,
            toAssetAddress,
            transferFromAmount,
            amountOut
        );
    }

    function getCommandData()
        private
        pure
        returns (
            uint16 commandsOffset,
            uint16 commandsOffsetEnd,
            uint16 outputsLength
        )
    {
        assembly {
            commandsOffset := add(70, shr(240, calldataload(68))) // dataOffset + dataLength
            commandsOffsetEnd := add(68, calldataload(36)) // commandsOffsetEnd / swapArgsOffset + swapArgsLength (swapArgsOffset - 32)
            outputsLength := shr(240, calldataload(70)) // dataOffset + 32
        }
    }

    function execute(
        address fromAddress,
        address fromAssetAddress
    ) private returns (uint256 transferFromAmount, uint256 gasUsed) {
        (
            uint16 commandsOffset,
            uint16 commandsOffsetEnd,
            uint16 outputsLength
        ) = getCommandData();

        uint256 outputPtr;
        assembly {
            outputPtr := mload(0x40)
            mstore(0x40, add(outputPtr, outputsLength))
        }

        uint256 outputOffsetPtr = outputPtr;

        unchecked {
            for (uint256 i = commandsOffset; i < commandsOffsetEnd; ) {
                (transferFromAmount, gasUsed, outputOffsetPtr) = executeCommand(
                    i,
                    fromAddress,
                    fromAssetAddress,
                    outputPtr,
                    outputOffsetPtr,
                    transferFromAmount,
                    gasUsed
                );
                i += 9;
            }
        }

        if (outputOffsetPtr > outputPtr + outputsLength) {
            revert();
        }
    }

    function executeCommand(
        uint256 i,
        address fromAddress,
        address fromAssetAddress,
        uint256 outputPtr,
        uint256 outputOffsetPtr,
        uint256 transferFromAmount,
        uint256 gasUsed
    ) private returns (uint256, uint256, uint256) {
        CommandAction commandAction;
        assembly {
            commandAction := shr(248, calldataload(i))
        }

        if (commandAction == CommandAction.Call) {
            outputOffsetPtr = executeCommandCall(i, outputPtr, outputOffsetPtr);
        } else if (commandAction == CommandAction.Approval) {
            executeCommandApproval(i, outputPtr);
        } else if (commandAction == CommandAction.TransferFrom) {
            transferFromAmount = executeCommandTransferFrom(
                i,
                outputPtr,
                fromAssetAddress,
                fromAddress,
                transferFromAmount
            );
        } else if (commandAction == CommandAction.Transfer) {
            executeCommandTransfer(i, outputPtr);
        } else if (commandAction == CommandAction.EstimateGasStart) {
            gasUsed = gasleft();
        } else if (commandAction == CommandAction.EstimateGasEnd) {
            gasUsed -= gasleft();
        } else {
            revert();
        }

        return (transferFromAmount, gasUsed, outputOffsetPtr);
    }
    function executeCommandCall(
        uint256 i,
        uint256 outputPtr,
        uint256 outputOffsetPtr
    ) private returns (uint256) {
        bytes memory input;
        uint256 nativeAmount;
        (input, nativeAmount) = getInput(i, outputPtr);
        uint256 outputLength;
        assembly {
            outputLength := shr(240, calldataload(add(i, 1)))

            switch shr(224, mload(add(input, 32))) // selector
            case 0 {
                // InvalidSelector
                mstore(
                    0,
                    0x7352d91c00000000000000000000000000000000000000000000000000000000
                )
                revert(0, 4)
            }
            case 0x23b872dd {
                // Blacklist transferFrom in custom calls
                // InvalidTransferFromCall
                mstore(
                    0,
                    0x1751a8e400000000000000000000000000000000000000000000000000000000
                )
                revert(0, 4)
            }
            default {
                let targetAddress := shr(
                    96,
                    calldataload(shr(240, calldataload(add(i, 7))))
                ) // targetPosition
                if eq(targetAddress, address()) {
                    // InvalidCall
                    mstore(
                        0,
                        0xae962d4e00000000000000000000000000000000000000000000000000000000
                    )
                    revert(0, 4)
                }
                if iszero(
                    call(
                        gas(),
                        targetAddress,
                        nativeAmount,
                        add(input, 32),
                        mload(input),
                        outputOffsetPtr,
                        outputLength
                    )
                ) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }
            }
        }
        outputOffsetPtr += outputLength;

        return outputOffsetPtr;
    }

    function executeCommandApproval(uint256 i, uint256 outputPtr) private {
        (bytes memory input, ) = getInput(i, outputPtr);

        address self;
        address spender;
        uint256 amount;
        assembly {
            self := mload(add(input, 32))
            spender := mload(add(input, 64))
            amount := mload(add(input, 96))
        }
        self.approve(spender, amount);
    }

    function executeCommandTransferFrom(
        uint256 i,
        uint256 outputPtr,
        address fromAssetAddress,
        address fromAddress,
        uint256 transferFromAmount
    ) private returns (uint256) {
        (bytes memory input, ) = getInput(i, outputPtr);

        uint256 amount;
        assembly {
            amount := mload(add(input, 64))
        }
        if (amount > 0) {
            address to;
            assembly {
                to := mload(add(input, 32))
            }
            fromAssetAddress.transferFrom(fromAddress, to, amount);
            transferFromAmount += amount;
        }

        return transferFromAmount;
    }

    function executeCommandTransfer(uint256 i, uint256 outputPtr) private {
        (bytes memory input, ) = getInput(i, outputPtr);

        uint256 amount;
        assembly {
            amount := mload(add(input, 96))
        }
        if (amount > 0) {
            address self;
            address recipient;
            assembly {
                self := mload(add(input, 32))
                recipient := mload(add(input, 64))
            }
            self.transfer(recipient, amount);
        }
    }

    function getInput(
        uint256 i,
        uint256 outputPtr
    ) private view returns (bytes memory input, uint256 nativeAmount) {
        assembly {
            let sequencesPositionEnd := shr(240, calldataload(add(i, 5)))

            input := mload(0x40)
            nativeAmount := 0

            let j := shr(240, calldataload(add(i, 3))) // sequencesPosition
            let inputOffsetPtr := add(input, 32)

            for {} lt(j, sequencesPositionEnd) {} {
                let sequenceType := shr(248, calldataload(j))

                switch sequenceType
                // NativeAmount
                case 0 {
                    switch shr(240, calldataload(add(j, 3)))
                    case 1 {
                        nativeAmount := mload(
                            add(outputPtr, shr(240, calldataload(add(j, 1))))
                        )
                    }
                    default {
                        let p := shr(240, calldataload(add(j, 1)))
                        nativeAmount := shr(
                            shr(248, calldataload(p)),
                            calldataload(add(p, 1))
                        )
                    }
                    j := add(j, 5)
                }
                // Selector
                case 1 {
                    mstore(
                        inputOffsetPtr,
                        calldataload(shr(240, calldataload(add(j, 1))))
                    )
                    inputOffsetPtr := add(inputOffsetPtr, 4)
                    j := add(j, 3)
                }
                // Address
                case 2 {
                    mstore(
                        inputOffsetPtr,
                        shr(96, calldataload(shr(240, calldataload(add(j, 1)))))
                    )
                    inputOffsetPtr := add(inputOffsetPtr, 32)
                    j := add(j, 3)
                }
                // Amount
                case 3 {
                    let p := shr(240, calldataload(add(j, 1)))
                    mstore(
                        inputOffsetPtr,
                        shr(shr(248, calldataload(p)), calldataload(add(p, 1)))
                    )
                    inputOffsetPtr := add(inputOffsetPtr, 32)
                    j := add(j, 3)
                }
                // Data
                case 4 {
                    let l := shr(240, calldataload(add(j, 3)))
                    calldatacopy(
                        inputOffsetPtr,
                        shr(240, calldataload(add(j, 1))),
                        l
                    )
                    inputOffsetPtr := add(inputOffsetPtr, l)
                    j := add(j, 5)
                }
                // CommandOutput
                case 5 {
                    mstore(
                        inputOffsetPtr,
                        mload(add(outputPtr, shr(240, calldataload(add(j, 1)))))
                    )
                    inputOffsetPtr := add(inputOffsetPtr, 32)
                    j := add(j, 3)
                }
                // RouterAddress
                case 6 {
                    mstore(inputOffsetPtr, address())
                    inputOffsetPtr := add(inputOffsetPtr, 32)
                    j := add(j, 1)
                }
                // SenderAddress
                case 7 {
                    mstore(inputOffsetPtr, caller())
                    inputOffsetPtr := add(inputOffsetPtr, 32)
                    j := add(j, 1)
                }
                default {
                    // InvalidSequenceType
                    mstore(
                        0,
                        0xa90b6fde00000000000000000000000000000000000000000000000000000000
                    )
                    revert(0, 4)
                }
            }

            mstore(input, sub(inputOffsetPtr, add(input, 32)))
            mstore(0x40, inputOffsetPtr)
        }
    }
}
