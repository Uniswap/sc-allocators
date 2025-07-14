// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';
import {IHybridAllocator} from 'src/interfaces/IHybridAllocator.sol';

interface IHybridERC7683 is IHybridAllocator, IOriginSettler {
    struct OrderData {
        // BATCH COMPACT
        address arbiter; // The account tasked with verifying and submitting the claim.
        address sponsor; // The account to source the tokens from.
        // uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires; // The time at which the claim expires.
        uint256[2][] idsAndAmounts; // The ids of the ERC6909 tokens to allocate.
        // MANDATE
        uint256 chainId; // (implicit arg, included in EIP712 payload)
        address tribunal; // (implicit arg, included in EIP712 payload)
        address recipient; // Recipient of settled tokens
        // uint256 expires; // Mandate expiration timestamp
        address settlementToken; // Settlement token (address(0) for native)
        uint256 minimumAmount; // Minimum settlement amount
        uint256 baselinePriorityFee; // Base fee threshold where scaling kicks in
        uint256 scalingFactor; // Fee scaling multiplier (1e18 baseline)
        uint256[] decayCurve; // Block durations, fill increases, & claim decreases.
        bytes32 salt; // Replay protection parameter
        // ADDITIONAL INPUT
        uint128 targetBlock; // The block number at the target chain on which the PGA is executed / the reverse dutch auction starts.
        uint120 maximumBlocksAfterTarget; // Blocks after target block that are still fillable.
    }

    error InvalidOrderDataType(bytes32 orderDataType, bytes32 expectedOrderDataType);
    error InvalidOriginSettler(address originSettler, address expectedOriginSettler);
}
