// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOriginSettler} from './ERC7683/IOriginSettler.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {Lock} from '@uniswap/the-compact/types/EIP712Types.sol';
import {Adjustment, Fill, Mandate, RecipientCallback} from '@uniswap/tribunal/types/TribunalStructs.sol';

interface IERC7683Allocator is IOriginSettler, IAllocator {
    struct OrderDataOnChain {
        Order order; // The remaining BatchCompact and Mandate data
        uint32 expires; // COMPACT - The time at which the claim expires and the user is able to withdraw their funds.
    }

    struct OrderDataGasless {
        Order order; // The remaining BatchCompact and Mandate data
        bool deposit; // Weather the order includes a deposit of the relevant tokens. This allows to skip a sponsor confirmation
    }

    /// @dev The data that OnChain and Gasless orders have in common
    struct Order {
        address arbiter; // COMPACT - The account tasked with verifying and submitting the claim.
        Lock[] commitments; // COMPACT - The token IDs and amounts to allocate.
        Mandate mandate; // MANDATE - Mandate struct fom tribunal
    }

    error InvalidOriginSettler(address originSettler, address expectedOriginSettler);
    error InvalidOrderDataType(bytes32 orderDataType, bytes32 expectedOrderDataType);
    error InvalidNonce(uint256 nonce, uint256 expectedNonce);
    error InvalidAllocatorData(bytes32 expectedAllocatorData, bytes32 actualAllocatorData);
    error UnsupportedToken(address token);
    error InvalidOrderData(bytes orderData);
    error InvalidRecipientCallbackLength();

    /// @notice Returns the type string of the compact including the witness
    function getCompactWitnessTypeString() external pure returns (string memory);

    /// @notice Returns the nonce for a given order and caller
    /// @dev The nonce is the most significant 96 bits. The least significant 160 bits must be the sponsor address
    function getNonce(GaslessCrossChainOrder calldata order_, address caller) external view returns (uint256 nonce);

    /// @notice Creates the filler data for the open event to be used on the IDestinationSettler
    /// @param claimant_ The address claiming the origin tokens after a successful fill (typically the address of the filler)
    function createFillerData(address claimant_) external pure returns (bytes memory fillerData);
}
