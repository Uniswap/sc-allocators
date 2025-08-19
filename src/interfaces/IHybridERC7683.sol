// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';
import {IHybridAllocator} from 'src/interfaces/IHybridAllocator.sol';

interface IHybridERC7683 is IHybridAllocator, IOriginSettler {
    struct OrderDataOnChain {
        Order order; // The remaining BatchCompact and Mandate data
        uint256 expires; // COMPACT - The time at which the claim expires and the user is able to withdraw their funds.
    }

    struct OrderDataGasless {
        Order order; // The remaining BatchCompact and Mandate data
    }

    /// @dev The data that OnChain and Gasless orders have in common
    struct Order {
        address arbiter; // COMPACT - The account tasked with verifying and submitting the claim.
        uint256[2][] idsAndAmounts; // COMPACT - The token IDs and amounts to allocate.
        uint256 chainId; // MANDATE - (implicit arg, included in EIP712 payload)
        address tribunal; // MANDATE - (implicit arg, included in EIP712 payload)
        address recipient; // MANDATE - Recipient of settled tokens
        // uint256 expires; // MANDATE - Mandate expiration timestamp, which equals the fill deadline
        address settlementToken; // MANDATE - Settlement token (address(0) for native)
        uint256 minimumAmount; // MANDATE - Minimum settlement amount
        uint256 baselinePriorityFee; // MANDATE - Base fee threshold where scaling kicks in
        uint256 scalingFactor; // MANDATE - Fee scaling multiplier (1e18 baseline)
        uint256[] decayCurve; // MANDATE - Block durations, fill increases, & claim decreases.
        bytes32 salt; // MANDATE - Replay protection parameter
        bytes32 qualification; // ADDITIONAL INPUT - [uint199 targetBlock, uint56 maximumBlocksAfterTarget, uint1(0)] The block number at the target chain on which the PGA is executed / the reverse dutch auction starts & blocks after target block that are still fillable.
    }

    error InvalidOrderDataType(bytes32 orderDataType, bytes32 expectedOrderDataType);
    error InvalidOriginSettler(address originSettler, address expectedOriginSettler);
    error InvalidQualification(bytes32 qualification);
}
