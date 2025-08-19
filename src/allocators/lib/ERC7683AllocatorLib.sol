// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {AllocatorLib as AL} from './AllocatorLib.sol';

import {BatchCompact, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';
import {Tribunal} from '@uniswap/tribunal/Tribunal.sol';
import {Fill, Mandate, RecipientCallback} from '@uniswap/tribunal/types/TribunalStructs.sol';
import {
    COMPACT_TYPEHASH_WITH_MANDATE,
    COMPACT_WITH_MANDATE_TYPESTRING,
    MANDATE_BATCH_COMPACT_TYPEHASH,
    MANDATE_FILL_TYPEHASH,
    MANDATE_RECIPIENT_CALLBACK_TYPEHASH,
    MANDATE_TYPEHASH
} from '@uniswap/tribunal/types/TribunalTypeHashes.sol';

import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';

import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';
import {IERC7683Allocator} from 'src/interfaces/IERC7683Allocator.sol';

library ERC7683AllocatorLib {
    /// @notice The typehash of the OrderDataOnChain struct
    //          keccak256("OrderDataOnChain(Order order,uint32 expires)
    //          Mandate(address adjuster,Mandate_Fill[] fills)
    //          Mandate_BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Mandate_Lock[] commitments)
    //          Mandate_Fill(uint256 chainId,address tribunal,uint256 expires,address fillToken,uint256 minimumFillAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] priceCurve,address recipient,Mandate_RecipientCallback[] recipientCallback,bytes32 salt)
    //          Mandate_Lock(bytes12 lockTag,address token,uint256 amount)
    //          Mandate_RecipientCallback(uint256 chainId,Mandate_BatchCompact compact,bytes context)
    //          Order(address arbiter,Lock[] commitments,Mandate mandate)")
    bytes32 public constant ORDERDATA_ONCHAIN_TYPEHASH =
        0x66007c95a1c1d0004397bbd6448c24b58a18d5d17e75321cdd119aa3b879d98e;

    /// @notice The typehash of the OrderDataGasless struct
    //          keccak256("OrderDataGasless(Order order,bool deposit)
    //          Mandate(address adjuster,Mandate_Fill[] fills)
    //          Mandate_BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Mandate_Lock[] commitments)
    //          Mandate_Fill(uint256 chainId,address tribunal,uint256 expires,address fillToken,uint256 minimumFillAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] priceCurve,address recipient,Mandate_RecipientCallback[] recipientCallback,bytes32 salt)
    //          Mandate_Lock(bytes12 lockTag,address token,uint256 amount)
    //          Mandate_RecipientCallback(uint256 chainId,Mandate_BatchCompact compact,bytes context)
    //          Order(address arbiter,Lock[] commitments,Mandate mandate)")
    bytes32 public constant ORDERDATA_GASLESS_TYPEHASH =
        0xca948fccb29bd545dea3361927ce0b7d8b680a214439e24af475831131515b4c;

    error InvalidRecipientCallbackLength();
    error InvalidOrderDataType(bytes32 orderDataType, bytes32 expectedOrderDataType);
    error InvalidOriginSettler(address originSettler, address expectedOriginSettler);
    error InvalidOrderData(bytes orderData);

    function openForPreparation(IOriginSettler.GaslessCrossChainOrder calldata order, bytes calldata sponsorSignature)
        internal
        view
        returns (
            IERC7683Allocator.Order calldata orderData,
            uint32 deposit,
            bytes32 mandateHash,
            IOriginSettler.ResolvedCrossChainOrder memory resolvedOrder
        )
    {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_GASLESS_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_GASLESS_TYPEHASH);
        }
        // Check if the originSettler is the allocator
        if (order.originSettler != address(this)) {
            revert InvalidOriginSettler(order.originSettler, address(this));
        }

        // Decode the orderData
        (orderData, deposit) = decodeOrderData(order.orderData);
        deposit = sanitizeBool(deposit);

        // Ensure a valid mandate is provided
        if (orderData.mandate.fills.length == 0 || order.fillDeadline != orderData.mandate.fills[0].expires) {
            revert InvalidOrderData(order.orderData);
        }
        bytes32[] memory fillHashes;
        (mandateHash, fillHashes) = hashMandate(orderData.mandate);
        resolvedOrder =
            resolveOrder(order.user, order.nonce, order.openDeadline, fillHashes, orderData, sponsorSignature);
    }

    function openPreparation(IOriginSettler.OnchainCrossChainOrder calldata order)
        internal
        pure
        returns (
            IERC7683Allocator.Order calldata orderData,
            uint32 expires,
            bytes32 mandateHash,
            bytes32[] memory fillHashes
        )
    {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_ONCHAIN_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_ONCHAIN_TYPEHASH);
        }

        // Decode the orderData
        (orderData, expires) = decodeOrderData(order.orderData);
        expires = sanitizeUint32(expires);

        // Ensure a valid mandate is provided
        if (orderData.mandate.fills.length == 0 || order.fillDeadline != orderData.mandate.fills[0].expires) {
            revert InvalidOrderData(order.orderData);
        }

        (mandateHash, fillHashes) = hashMandate(orderData.mandate);
    }

    function decodeOrderData(bytes calldata orderData)
        internal
        pure
        returns (IERC7683Allocator.Order calldata order, uint32 additionalInput)
    {
        // orderData includes the OrderData(OnChain/Gasless) struct, and the nested Order struct.
        // 0x00: OrderDataOnChain.offset
        // 0x20: OrderDataOnChain.order.offset
        // 0x40: OrderDataOnChain.expires

        // 0x00: OrderDataGasless.offset
        // 0x20: OrderDataGasless.order.offset

        assembly ("memory-safe") {
            let l := sub(orderData.length, 0x20)
            let s := calldataload(add(orderData.offset, 0x20)) // Relative offset of `orderBytes` from `orderData.offset` and the `OrderData...` struct.
            order := add(orderData.offset, add(s, 0x20)) // Add 0x20 since the OrderStruct is within the `OrderData...` struct
            if shr(64, or(s, or(l, orderData.offset))) { revert(l, 0x00) }

            additionalInput := calldataload(add(orderData.offset, 0x40))
        }
    }

    function resolveOrder(
        address sponsor,
        uint256 nonce,
        uint32 expires,
        bytes32[] memory fillHashes,
        IERC7683Allocator.Order calldata orderData,
        bytes calldata sponsorSignature
    ) internal view returns (IOriginSettler.ResolvedCrossChainOrder memory) {
        Fill memory mainFill = orderData.mandate.fills[0];

        IOriginSettler.ResolvedCrossChainOrder memory resolvedOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: sponsor,
            originChainId: block.chainid,
            openDeadline: expires,
            fillDeadline: uint32(mainFill.expires),
            orderId: bytes32(nonce),
            maxSpent: new IERC7683Allocator.Output[](0),
            minReceived: new IERC7683Allocator.Output[](0),
            fillInstructions: new IERC7683Allocator.FillInstruction[](0)
        });

        BatchCompact memory compact = BatchCompact({
            arbiter: orderData.arbiter,
            sponsor: sponsor,
            nonce: nonce,
            expires: expires,
            commitments: orderData.commitments
        });

        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: compact,
            sponsorSignature: sponsorSignature,
            allocatorSignature: '' // No signature required from this allocator, it will verify the claim on chain via ERC1271.
        });

        IOriginSettler.FillInstruction[] memory fillInstructions = new IOriginSettler.FillInstruction[](1);
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: mainFill.chainId,
            destinationSettler: addressToBytes32(mainFill.tribunal),
            originData: abi.encode(claim, mainFill, orderData.mandate.adjuster, fillHashes)
        });
        resolvedOrder.fillInstructions = fillInstructions;

        IOriginSettler.Output memory spent = IOriginSettler.Output({
            token: addressToBytes32(mainFill.fillToken),
            amount: type(uint256).max,
            recipient: addressToBytes32(mainFill.recipient),
            chainId: mainFill.chainId
        });
        IOriginSettler.Output[] memory maxSpent = new IOriginSettler.Output[](1);
        maxSpent[0] = spent;
        resolvedOrder.maxSpent = maxSpent;

        resolvedOrder.minReceived = createMinimumReceived(orderData.commitments);

        return resolvedOrder;
    }

    function createMinimumReceived(Lock[] calldata commitments)
        internal
        view
        returns (IOriginSettler.Output[] memory)
    {
        IOriginSettler.Output[] memory minReceived = new IOriginSettler.Output[](commitments.length);

        for (uint256 i = 0; i < commitments.length; i++) {
            IOriginSettler.Output memory received = IOriginSettler.Output({
                token: addressToBytes32(commitments[i].token),
                amount: commitments[i].amount,
                recipient: bytes32(0),
                chainId: block.chainid
            });
            minReceived[i] = received;
        }
        return minReceived;
    }

    function hashMandate(Mandate calldata mandate) internal pure returns (bytes32, bytes32[] memory fillHashes) {
        fillHashes = new bytes32[](mandate.fills.length);
        for (uint256 i = 0; i < mandate.fills.length; i++) {
            fillHashes[i] = hashFill(mandate.fills[i]);
        }
        return (
            keccak256(abi.encode(MANDATE_TYPEHASH, mandate.adjuster, keccak256(abi.encodePacked(fillHashes)))),
            fillHashes
        );
    }

    function hashFill(Fill calldata fill) internal pure returns (bytes32) {
        bytes32 priceCurveHash = keccak256(abi.encodePacked(fill.priceCurve));
        return keccak256(
            abi.encode(
                MANDATE_FILL_TYPEHASH,
                fill.chainId,
                fill.tribunal,
                fill.expires,
                fill.fillToken,
                fill.minimumFillAmount,
                fill.baselinePriorityFee,
                fill.scalingFactor,
                priceCurveHash,
                fill.recipient,
                hashRecipientCallback(fill.recipientCallback),
                fill.salt
            )
        );
    }

    function hashRecipientCallback(RecipientCallback[] calldata recipientCallback) internal pure returns (bytes32) {
        if (recipientCallback.length == 0) {
            // empty hash
            return 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        } else if (recipientCallback.length != 1) {
            revert InvalidRecipientCallbackLength();
        }

        RecipientCallback calldata callback = recipientCallback[0];

        return keccak256(
            abi.encodePacked(
                keccak256(
                    abi.encode(
                        MANDATE_RECIPIENT_CALLBACK_TYPEHASH,
                        callback.chainId,
                        AL.getClaimHash(
                            callback.compact.arbiter,
                            callback.compact.sponsor,
                            callback.compact.nonce,
                            callback.compact.expires,
                            AL.getCommitmentsHash(callback.compact.commitments),
                            callback.mandateHash,
                            MANDATE_BATCH_COMPACT_TYPEHASH
                        ),
                        callback.context
                    )
                )
            )
        );
    }

    function addressToBytes32(address input) internal pure returns (bytes32 output) {
        assembly ("memory-safe") {
            output := shr(96, shl(96, input))
        }
    }

    function sanitizeUint32(uint32 value) internal pure returns (uint32) {
        assembly ("memory-safe") {
            value := shr(224, shl(224, value))
        }
        return value;
    }

    function sanitizeBool(uint32 value) internal pure returns (uint32) {
        assembly ("memory-safe") {
            value := iszero(iszero(value))
        }
        return value;
    }
}
