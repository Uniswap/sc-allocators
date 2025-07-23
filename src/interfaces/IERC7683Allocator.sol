// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOriginSettler} from './ERC7683/IOriginSettler.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

interface IERC7683Allocator is IOriginSettler, IAllocator {
    struct OrderDataOnChain {
        // BATCH_COMPACT
        address arbiter; // The account tasked with verifying and submitting the claim.
        // address sponsor; // The account to source the tokens from.
        // uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires; // The time at which the claim expires.
        Order order; // The remaining BatchCompact and Mandate data
        // ADDITIONAL INPUT
        uint200 targetBlock; // The block number at the target chain on which the PGA is executed / the reverse dutch auction starts.
        uint56 maximumBlocksAfterTarget; // Blocks after target block that are still fillable.
    }

    struct OrderDataGasless {
        // BATCH_COMPACT
        address arbiter; // The account tasked with verifying and submitting the claim.
        // address sponsor; // The account to source the tokens from.
        // uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
        // uint256 expires; // The time at which the claim expires.
        Order order; // The remaining BatchCompact and Mandate data
    }

    /// @dev The data that OnChain and Gasless orders have in common
    struct Order {
        Lock[] commitments; // The token IDs and amounts to allocate.
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
    }

    error InvalidOriginSettler(address originSettler, address expectedOriginSettler);
    error InvalidOrderDataType(bytes32 orderDataType, bytes32 expectedOrderDataType);
    error InvalidNonce(uint256 nonce, uint256 expectedNonce);
    error BatchCompactsNotSupported();
    error InvalidAllocatorData(bytes32 expectedAllocatorData, bytes32 actualAllocatorData);

    /// @notice Returns the type string of the compact including the witness
    function getCompactWitnessTypeString() external pure returns (string memory);

    /// @notice Checks if a nonce is free to be used
    /// @dev The nonce is the most significant 96 bits. The least significant 160 bits must be the sponsor address
    function checkNonce(uint256 nonce_, address sponsor_) external view returns (bool nonceFree_);

    /// @notice Creates the filler data for the open event to be used on the IDestinationSettler
    /// @param claimant_ The address claiming the origin tokens after a successful fill (typically the address of the filler)
    function createFillerData(address claimant_) external pure returns (bytes memory fillerData);
}
