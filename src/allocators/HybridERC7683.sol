// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {ERC7683AllocatorLib as ERC7683AL} from './lib/ERC7683AllocatorLib.sol';
import {LibBytes} from '@solady/utils/LibBytes.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {BatchCompact, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';
import {Tribunal} from '@uniswap/tribunal/Tribunal.sol';
import {Fill, Mandate} from '@uniswap/tribunal/types/TribunalStructs.sol';

import {
    COMPACT_TYPEHASH_WITH_MANDATE,
    COMPACT_WITH_MANDATE_TYPESTRING,
    MANDATE_BATCH_COMPACT_TYPEHASH,
    MANDATE_FILL_TYPEHASH,
    MANDATE_RECIPIENT_CALLBACK_TYPEHASH,
    MANDATE_TYPEHASH
} from '@uniswap/tribunal/types/TribunalTypeHashes.sol';
import {HybridAllocator} from 'src/allocators/HybridAllocator.sol';
import {IERC7683Allocator} from 'src/interfaces/IERC7683Allocator.sol';

import {AllocatorLib as AL} from 'src/allocators/lib/AllocatorLib.sol';
import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';

contract HybridERC7683 is HybridAllocator, IERC7683Allocator {
    error OnlyDepositsAllowed();

    constructor(address compact, address signer) HybridAllocator(compact, signer) {}

    /// @inheritdoc IOriginSettler
    function openFor(GaslessCrossChainOrder calldata order, bytes calldata sponsorSignature, bytes calldata) external {
        (
            IERC7683Allocator.Order calldata orderData,
            uint32 deposit,
            bytes32 mandateHash,
            IOriginSettler.ResolvedCrossChainOrder memory resolvedOrder
        ) = ERC7683AL.openForPreparation(order, sponsorSignature);

        if (deposit == 0) {
            // Hybrid Allocator requires a deposit
            revert OnlyDepositsAllowed();
        } else {
            // Create idsAndAmounts
            uint256[2][] memory idsAndAmounts = new uint256[2][](orderData.commitments.length);
            for (uint256 i = 0; i < orderData.commitments.length; i++) {
                idsAndAmounts[i][0] = AL.toId(orderData.commitments[i].lockTag, orderData.commitments[i].token);
                idsAndAmounts[i][1] = orderData.commitments[i].amount;
            }

            // Register the allocation on chain by using a deposit
            (, uint256[] memory registeredAmounts, uint256 nonce) = allocateAndRegister(
                order.user,
                idsAndAmounts,
                orderData.arbiter,
                order.openDeadline,
                COMPACT_TYPEHASH_WITH_MANDATE,
                mandateHash
            );

            // We ignore the order.nonce and use the one assigned by the hybrid allocator
            resolvedOrder.orderId = bytes32(nonce);

            // Update the resolved order with the registered amounts
            for (uint256 i = 0; i < orderData.commitments.length; i++) {
                resolvedOrder.minReceived[i].amount = registeredAmounts[i];
            }

            // Emit an open event
            emit Open(bytes32(nonce), resolvedOrder);
        }
    }

    /// @inheritdoc IOriginSettler
    function open(OnchainCrossChainOrder calldata order) external {
        (IERC7683Allocator.Order calldata orderData, uint32 expires, bytes32 mandateHash, bytes32[] memory fillHashes) =
            ERC7683AL.openPreparation(order);

        // Create idsAndAmounts
        uint256[2][] memory idsAndAmounts = new uint256[2][](orderData.commitments.length);
        for (uint256 i = 0; i < orderData.commitments.length; i++) {
            idsAndAmounts[i][0] = AL.toId(orderData.commitments[i].lockTag, orderData.commitments[i].token);
            idsAndAmounts[i][1] = orderData.commitments[i].amount;
        }

        // deposit the the tokens into the compact and register the claim
        (, uint256[] memory registeredAmounts, uint256 nonce) = allocateAndRegister(
            msg.sender, idsAndAmounts, orderData.arbiter, expires, COMPACT_TYPEHASH_WITH_MANDATE, mandateHash
        );
        ResolvedCrossChainOrder memory resolvedOrder =
            ERC7683AL.resolveOrder(msg.sender, nonce, expires, fillHashes, orderData, LibBytes.emptyCalldata());
        for (uint256 i = 0; i < orderData.commitments.length; i++) {
            resolvedOrder.minReceived[i].amount = registeredAmounts[i];
        }

        // Emit an open event
        emit Open(bytes32(nonce), resolvedOrder);
    }

    /// @inheritdoc IOriginSettler
    function resolveFor(GaslessCrossChainOrder calldata order, bytes calldata /*originFillerData*/ )
        external
        view
        returns (ResolvedCrossChainOrder memory)
    {
        (, uint32 deposit,, IOriginSettler.ResolvedCrossChainOrder memory resolvedOrder) =
            ERC7683AL.openForPreparation(order, LibBytes.emptyCalldata());

        // Revert if the nonce is not the next nonce
        if (order.nonce != nonces + 1) {
            revert InvalidNonce(order.nonce, nonces + 1);
        }

        if (deposit == 0) {
            // Hybrid Allocator requires a deposit
            revert OnlyDepositsAllowed();
        }

        return resolvedOrder;
    }

    /// @inheritdoc IOriginSettler
    function resolve(OnchainCrossChainOrder calldata order) external view returns (ResolvedCrossChainOrder memory) {
        (IERC7683Allocator.Order calldata orderData, uint32 expires,, bytes32[] memory fillHashes) =
            ERC7683AL.openPreparation(order);

        return ERC7683AL.resolveOrder(msg.sender, nonces + 1, expires, fillHashes, orderData, LibBytes.emptyCalldata());
    }

    function getCompactWitnessTypeString() external pure returns (string memory) {
        return COMPACT_WITH_MANDATE_TYPESTRING;
    }

    /// @inheritdoc IERC7683Allocator
    function getNonce(GaslessCrossChainOrder calldata order, address) external view returns (uint256 nonce) {
        (, uint32 deposit) = ERC7683AL.decodeOrderData(order.orderData);
        deposit = ERC7683AL.sanitizeBool(deposit);

        if (deposit == 0) {
            // Hybrid Allocator requires a deposit
            revert OnlyDepositsAllowed();
        }

        return nonces + 1;
    }

    /// @inheritdoc IERC7683Allocator
    function createFillerData(address claimant) external pure returns (bytes memory fillerData) {
        return abi.encode(claimant);
    }
}
