// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOriginSettler} from './ERC7683/IOriginSettler.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

interface IERC7683Allocator is IOriginSettler, IAllocator {
    struct OrderDataOnChain {
        Order order; // The remaining BatchCompact and Mandate data
        uint256 expires; // COMPACT - The time at which the claim expires and the user is able to withdraw their funds.
    }

    struct OrderDataGasless {
        Order order; // The remaining BatchCompact and Mandate data
        bool deposit; // Weather the order includes a deposit of the relevant tokens. This allows to skip a sponsor confirmation
    }

    /// @dev The data that OnChain and Gasless orders have in common
    struct Order {
        address arbiter; // COMPACT - The account tasked with verifying and submitting the claim.
        Lock[] commitments; // COMPACT - The token IDs and amounts to allocate.
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
        bytes32 qualification; // ADDITIONAL INPUT - abi.encodePacked(uint200 targetBlock, uint56 maximumBlocksAfterTarget) The block number at the target chain on which the PGA is executed / the reverse dutch auction starts & blocks after target block that are still fillable.
    }

    error InvalidOriginSettler(address originSettler, address expectedOriginSettler);
    error InvalidOrderDataType(bytes32 orderDataType, bytes32 expectedOrderDataType);
    error InvalidNonce(uint256 nonce, uint256 expectedNonce);
    error BatchCompactsNotSupported();
    error InvalidAllocatorData(bytes32 expectedAllocatorData, bytes32 actualAllocatorData);
    error UnsupportedToken(address token);

    /// @notice Returns the type string of the compact including the witness
    function getCompactWitnessTypeString() external pure returns (string memory);

    /// @notice Checks if a nonce is free to be used
    /// @dev The nonce is the most significant 96 bits. The least significant 160 bits must be the sponsor address
    function checkNonce(GaslessCrossChainOrder calldata order_, address caller)
        external
        view
        returns (bool nonceFree_);

    /// @notice Creates the filler data for the open event to be used on the IDestinationSettler
    /// @param claimant_ The address claiming the origin tokens after a successful fill (typically the address of the filler)
    function createFillerData(address claimant_) external pure returns (bytes memory fillerData);
}
