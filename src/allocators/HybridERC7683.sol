// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {LibBytes} from 'solady/utils/LibBytes.sol';

import {BatchClaim, Mandate} from './types/TribunalStructs.sol';
import {BatchCompact, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

import {HybridAllocator} from 'src/allocators/HybridAllocator.sol';
import {BATCH_COMPACT_WITNESS_TYPEHASH, MANDATE_TYPEHASH} from 'src/allocators/lib/TypeHashes.sol';

import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';

contract HybridERC7683 is HybridAllocator, IOriginSettler {
    // keccak256("OrderData(address arbiter,address sponsor,uint256 expires,uint256[2][] idsAndAmounts,
    //          uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt,uint256 targetBlock,uint256 maximumBlocksAfterTarget)")
    bytes32 constant ORDERDATA_TYPEHASH = 0xf93147c220566c5d99eedaa4ddd899c0a796b3721e418131b49cc9eedde5054d;

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
        uint256 targetBlock; // The block number at the target chain on which the PGA is executed / the reverse dutch auction starts.
        uint256 maximumBlocksAfterTarget; // Blocks after target block that are still fillable.
    }

    error InvalidOrderDataType(bytes32 orderDataType, bytes32 expectedOrderDataType);
    error InvalidOriginSettler(address originSettler, address expectedOriginSettler);

    constructor(address compact_, address signer_) HybridAllocator(compact_, signer_) {}

    function openFor(
        GaslessCrossChainOrder calldata, /*order_*/
        bytes calldata, /*sponsorSignature_*/
        bytes calldata /*originFillerData*/
    ) external pure {
        revert Unsupported();
    }

    function open(OnchainCrossChainOrder calldata order_) external {
        // Check if orderDataType is the one expected by the allocator
        if (order_.orderDataType != ORDERDATA_TYPEHASH) {
            revert InvalidOrderDataType(order_.orderDataType, ORDERDATA_TYPEHASH);
        }

        OrderData calldata orderData = _decodeOrderData(order_);

        // create witness hash
        bytes32 witnessHash = keccak256(
            abi.encode(
                MANDATE_TYPEHASH,
                orderData.chainId,
                orderData.tribunal,
                orderData.recipient,
                order_.fillDeadline,
                orderData.settlementToken,
                orderData.minimumAmount,
                orderData.baselinePriorityFee,
                orderData.scalingFactor,
                keccak256(abi.encodePacked(orderData.decayCurve)),
                orderData.salt
            )
        );

        // register claim
        (, uint256[] memory registeredAmounts, uint256 nonce_) = registerClaim(
            orderData.sponsor,
            orderData.idsAndAmounts,
            orderData.arbiter,
            orderData.expires,
            BATCH_COMPACT_WITNESS_TYPEHASH,
            witnessHash
        );
        Lock[] memory locks = new Lock[](registeredAmounts.length);
        for (uint256 i = 0; i < registeredAmounts.length; i++) {
            locks[i] = _createLock(orderData.idsAndAmounts[i][0], registeredAmounts[i]);
        }

        BatchCompact memory batchCompact = BatchCompact({
            arbiter: orderData.arbiter,
            sponsor: orderData.sponsor,
            nonce: nonce_,
            expires: orderData.expires,
            commitments: locks
        });

        // emit open event
        emit Open(
            bytes32(batchCompact.nonce), _convertToResolvedCrossChainOrder(orderData, order_.fillDeadline, batchCompact)
        );
    }

    function resolveFor(GaslessCrossChainOrder calldata, /*order*/ bytes calldata /*originFillerData*/ )
        external
        pure
        returns (ResolvedCrossChainOrder memory)
    {
        revert Unsupported();
    }

    function resolve(OnchainCrossChainOrder calldata order) external view returns (ResolvedCrossChainOrder memory) {
        OrderData calldata orderData = _decodeOrderData(order);
        uint256 idsLength = orderData.idsAndAmounts.length;
        Lock[] memory locks = new Lock[](idsLength);
        for (uint256 i = 0; i < idsLength; i++) {
            uint256 id = orderData.idsAndAmounts[i][0];
            locks[i] = _createLock(id, orderData.idsAndAmounts[i][1]);
        }
        BatchCompact memory batchCompact = BatchCompact({
            arbiter: orderData.arbiter,
            sponsor: orderData.sponsor,
            nonce: nonce + 1, // nonce is incremented by 1 when the claim is registered
            expires: orderData.expires,
            commitments: locks
        });
        return _convertToResolvedCrossChainOrder(orderData, order.fillDeadline, batchCompact);
    }

    function _decodeOrderData(OnchainCrossChainOrder calldata order_)
        internal
        pure
        returns (OrderData calldata orderData)
    {
        bytes calldata rawOrderData = LibBytes.dynamicStructInCalldata(order_.orderData, 0x00);
        assembly ("memory-safe") {
            orderData := rawOrderData.offset
        }
    }

    function _convertToResolvedCrossChainOrder(
        OrderData calldata orderData,
        uint256 fillDeadline,
        BatchCompact memory batchCompact
    ) internal view returns (ResolvedCrossChainOrder memory) {
        Output[] memory maxSpent = new Output[](1);
        maxSpent[0] = Output({
            token: bytes32(uint256(uint160(orderData.settlementToken))),
            amount: type(uint256).max,
            recipient: bytes32(uint256(uint160(orderData.recipient))),
            chainId: orderData.chainId
        });

        uint256 idsLength = orderData.idsAndAmounts.length;
        Output[] memory minReceived = new Output[](idsLength);
        for (uint256 i = 0; i < idsLength; i++) {
            minReceived[i] = Output({
                token: bytes32(uint256(uint160(orderData.idsAndAmounts[i][0]))),
                amount: orderData.minimumAmount,
                recipient: _convertAddressToBytes32(orderData.recipient),
                chainId: block.chainid
            });
        }

        Mandate memory mandate = Mandate({
            recipient: orderData.recipient,
            expires: fillDeadline,
            token: orderData.settlementToken,
            minimumAmount: orderData.minimumAmount,
            baselinePriorityFee: orderData.baselinePriorityFee,
            scalingFactor: orderData.scalingFactor,
            decayCurve: orderData.decayCurve,
            salt: orderData.salt
        });
        BatchClaim memory claim = BatchClaim({
            chainId: block.chainid,
            compact: batchCompact,
            sponsorSignature: '', // No signature required from the sponsor, the claim will be verified via the on chain registration.
            allocatorSignature: '' // No signature required from this allocator, it will verify the claim on chain via ERC1271.
        });

        FillInstruction[] memory fillInstructions = new FillInstruction[](1);
        fillInstructions[0] = FillInstruction({
            destinationChainId: orderData.chainId,
            destinationSettler: _convertAddressToBytes32(orderData.tribunal),
            originData: abi.encode(claim, mandate, orderData.targetBlock, orderData.maximumBlocksAfterTarget)
        });

        return ResolvedCrossChainOrder({
            user: orderData.sponsor,
            originChainId: block.chainid,
            openDeadline: uint32(fillDeadline),
            fillDeadline: uint32(fillDeadline),
            orderId: bytes32(batchCompact.nonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
    }

    function _convertAddressToBytes32(address address_) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(address_)));
    }

    function _createLock(uint256 id, uint256 amount) internal pure returns (Lock memory) {
        return Lock({lockTag: bytes12(bytes32(id)), token: _splitToken(id), amount: amount});
    }
}
