// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOriginSettler} from '../interfaces/ERC7683/IOriginSettler.sol';
import {IERC7683Allocator} from '../interfaces/IERC7683Allocator.sol';
import {OnChainAllocator} from './OnChainAllocator.sol';
import {AllocatorLib as AL} from './lib/AllocatorLib.sol';
import {ERC7683AllocatorLib as ERC7683AL} from './lib/ERC7683AllocatorLib.sol';

import {Tribunal} from '@uniswap/tribunal/Tribunal.sol';
import {Fill, Mandate, RecipientCallback} from '@uniswap/tribunal/types/TribunalStructs.sol';

import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {
    COMPACT_TYPEHASH_WITH_MANDATE,
    COMPACT_WITH_MANDATE_TYPESTRING,
    MANDATE_BATCH_COMPACT_TYPEHASH,
    MANDATE_FILL_TYPEHASH,
    MANDATE_RECIPIENT_CALLBACK_TYPEHASH,
    MANDATE_TYPEHASH
} from '@uniswap/tribunal/types/TribunalTypeHashes.sol';

import {LibBytes} from '@solady/utils/LibBytes.sol';
import {BatchCompact, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

/// @title ERC7683Allocator
/// @notice Allocates tokens deposited into the compact and broadcasts orders following the ERC7683 standard.
/// @dev The contract ensures tokens can not be double spent by a user in a fully decentralized manner.
/// @dev Users can open orders for themselves or for others by providing a signature or the tokens directly.
contract ERC7683Allocator is OnChainAllocator, IERC7683Allocator {
    constructor(address compact) OnChainAllocator(compact) {}

    /// @inheritdoc IOriginSettler
    function openFor(GaslessCrossChainOrder calldata order, bytes calldata sponsorSignature, bytes calldata) external {
        (
            IERC7683Allocator.Order calldata orderData,
            uint32 deposit,
            bytes32 mandateHash,
            IOriginSettler.ResolvedCrossChainOrder memory resolvedOrder
        ) = ERC7683AL.openForPreparation(order, sponsorSignature);

        uint160 caller = uint160(deposit * uint160(msg.sender)); // for a deposit, the nonce will be scoped to the caller

        // Early revert if the expected nonce is not the next nonce
        if (order.nonce != _getNonce(address(caller), order.user)) {
            revert InvalidNonce(order.nonce, _getNonce(address(caller), order.user));
        }

        uint256 nonce;
        if (deposit == 0) {
            // Register the allocation on chain
            (, nonce) = allocateFor(
                order.user,
                orderData.commitments,
                orderData.arbiter,
                order.openDeadline,
                COMPACT_TYPEHASH_WITH_MANDATE,
                mandateHash,
                sponsorSignature
            );
        } else {
            // Register the allocation on chain
            uint256[] memory registeredAmounts;
            (, registeredAmounts, nonce) = allocateAndRegister(
                order.user,
                orderData.commitments,
                orderData.arbiter,
                order.openDeadline,
                COMPACT_TYPEHASH_WITH_MANDATE,
                mandateHash
            );

            for (uint256 i = 0; i < orderData.commitments.length; i++) {
                resolvedOrder.minReceived[i].amount = registeredAmounts[i];
            }
        }
        // Emit an open event
        emit Open(bytes32(nonce), resolvedOrder);
    }

    /// @inheritdoc IOriginSettler
    function open(OnchainCrossChainOrder calldata order) external {
        (IERC7683Allocator.Order calldata orderData, uint32 expires, bytes32 mandateHash, bytes32[] memory fillHashes) =
            ERC7683AL.openPreparation(order);

        // Register the allocation on chain
        (, uint256 nonce) =
            allocate(orderData.commitments, orderData.arbiter, expires, COMPACT_TYPEHASH_WITH_MANDATE, mandateHash);

        ResolvedCrossChainOrder memory resolvedOrder =
            ERC7683AL.resolveOrder(msg.sender, nonce, expires, fillHashes, orderData, LibBytes.emptyCalldata());

        // Emit an open event
        emit Open(bytes32(nonce), resolvedOrder);
    }

    /// @inheritdoc IOriginSettler
    function resolveFor(GaslessCrossChainOrder calldata order, bytes calldata)
        external
        view
        returns (ResolvedCrossChainOrder memory)
    {
        (, uint32 deposit,, IOriginSettler.ResolvedCrossChainOrder memory resolvedOrder) =
            ERC7683AL.openForPreparation(order, LibBytes.emptyCalldata());

        uint160 caller = uint160(deposit * uint160(msg.sender)); // for a deposit, the nonce will be scoped to the caller + user

        // Early revert if the expected nonce is not the next nonce
        if (order.nonce != _getNonce(address(caller), order.user)) {
            revert InvalidNonce(order.nonce, _getNonce(address(caller), order.user));
        }

        return resolvedOrder;
    }

    /// @inheritdoc IOriginSettler
    function resolve(OnchainCrossChainOrder calldata order) external view returns (ResolvedCrossChainOrder memory) {
        (IERC7683Allocator.Order calldata orderData, uint32 expires,, bytes32[] memory fillHashes) =
            ERC7683AL.openPreparation(order);

        return ERC7683AL.resolveOrder(
            msg.sender, _getNonce(address(0), msg.sender), expires, fillHashes, orderData, LibBytes.emptyCalldata()
        );
    }

    /// @inheritdoc IERC7683Allocator
    function getCompactWitnessTypeString() external pure returns (string memory) {
        return COMPACT_WITH_MANDATE_TYPESTRING;
    }

    /// @inheritdoc IERC7683Allocator
    function getNonce(GaslessCrossChainOrder calldata order, address caller) external view returns (uint256 nonce) {
        (, uint32 deposit) = ERC7683AL.decodeOrderData(order.orderData);
        deposit = ERC7683AL.sanitizeBool(deposit);

        caller = address(uint160(deposit * uint160(caller))); // for a deposit, the nonce will be scoped to the caller + user

        return _getNonce(address(caller), order.user);
    }

    /// @inheritdoc IERC7683Allocator
    function createFillerData(address claimant) external pure returns (bytes memory fillerData) {
        return abi.encode(claimant);
    }

    function _getNonce(address calling, address sponsor) internal view returns (uint256 nonce) {
        assembly ("memory-safe") {
            calling := xor(calling, mul(sponsor, iszero(calling)))
            mstore(0x00, calling)
            mstore(0x20, nonces.slot)
            let nonceSlot := keccak256(0x00, 0x40)
            let nonce96 := sload(nonceSlot)
            nonce := or(shl(96, calling), add(nonce96, 1))
        }
    }
}
