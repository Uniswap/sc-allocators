// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {BatchClaim, Mandate} from './types/TribunalStructs.sol';
import {LibBytes} from '@solady/utils/LibBytes.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {BatchCompact, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

import {HybridAllocator} from 'src/allocators/HybridAllocator.sol';
import {BATCH_COMPACT_WITNESS_TYPEHASH, MANDATE_TYPEHASH} from 'src/allocators/lib/TypeHashes.sol';
import {IHybridERC7683} from 'src/interfaces/IHybridERC7683.sol';

import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';

contract HybridERC7683 is HybridAllocator, IHybridERC7683 {
    // mask for an active claim
    uint256 private constant _ACTIVE_CLAIM_MASK = 0x0000000000000000000000000000000000000000000000000000000000000001;

    /// @notice The typehash of the OrderDataOnChain struct
    //          keccak256("OrderDataOnChain(Order order,uint256 expires)
    //          Order(address arbiter,uint256[2][] idsAndAmounts,uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt,bytes32 qualification)")
    bytes32 public constant ORDERDATA_ONCHAIN_TYPEHASH =
        0xd13cc04099540f243b0042f68c0edbce9aefe428c22e0354a24061c5d98c7276;

    /// @notice The typehash of the OrderDataGasless struct
    //          keccak256("OrderDataGasless(Order order)
    //          Order(address arbiter,uint256[2][] idsAndAmounts,uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt,bytes32 qualification)")
    bytes32 public constant ORDERDATA_GASLESS_TYPEHASH =
        0xfba49b9453e7d260d702826a659947a671a3e6a970688a795c82065685236b52;

    /// @notice keccak256("QualifiedClaim(bytes32 claimHash,uint256 targetBlock,uint256 maximumBlocksAfterTarget)")
    bytes32 public constant QUALIFICATION_TYPEHASH = 0x59866b84bd1f6c909cf2a31efd20c59e6c902e50f2c196994e5aa85cdc7d7ce0;

    uint256 private constant _INVALID_QUALIFICATION_ERROR_SIGNATURE = 0x7ac3c7d4;

    constructor(address compact_, address signer_) HybridAllocator(compact_, signer_) {}

    /// @inheritdoc IOriginSettler
    function openFor(
        GaslessCrossChainOrder calldata order,
        bytes calldata, /*sponsorSignature_*/
        bytes calldata /*originFillerData*/
    ) external {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_GASLESS_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_GASLESS_TYPEHASH);
        }

        (Order calldata orderData,) = _decodeOrderData(order.orderData, false);

        // create witness hash
        bytes32 witnessHash = keccak256(
            abi.encode(
                MANDATE_TYPEHASH,
                orderData.chainId,
                orderData.tribunal,
                orderData.recipient,
                order.fillDeadline,
                orderData.settlementToken,
                orderData.minimumAmount,
                orderData.baselinePriorityFee,
                orderData.scalingFactor,
                keccak256(abi.encodePacked(orderData.decayCurve)),
                orderData.salt
            )
        );

        // register claim
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce_) = allocateAndRegister(
            order.user,
            orderData.idsAndAmounts,
            orderData.arbiter,
            order.openDeadline,
            BATCH_COMPACT_WITNESS_TYPEHASH,
            witnessHash
        );

        _storeQualification(claimHash, orderData.qualification);

        Lock[] memory locks = new Lock[](registeredAmounts.length);
        for (uint256 i = 0; i < registeredAmounts.length; i++) {
            locks[i] = _createLock(orderData.idsAndAmounts[i][0], registeredAmounts[i]);
        }

        BatchCompact memory batchCompact = BatchCompact({
            arbiter: orderData.arbiter,
            sponsor: order.user,
            nonce: nonce_,
            expires: order.openDeadline,
            commitments: locks
        });

        // emit open event
        emit Open(
            bytes32(batchCompact.nonce), _convertToResolvedCrossChainOrder(orderData, order.fillDeadline, batchCompact)
        );
    }

    /// @inheritdoc IOriginSettler
    function open(OnchainCrossChainOrder calldata order) external {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_ONCHAIN_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_ONCHAIN_TYPEHASH);
        }

        (Order calldata orderData, uint256 expires) = _decodeOrderData(order.orderData, true);

        // create witness hash
        bytes32 witnessHash = keccak256(
            abi.encode(
                MANDATE_TYPEHASH,
                orderData.chainId,
                orderData.tribunal,
                orderData.recipient,
                order.fillDeadline,
                orderData.settlementToken,
                orderData.minimumAmount,
                orderData.baselinePriorityFee,
                orderData.scalingFactor,
                keccak256(abi.encodePacked(orderData.decayCurve)),
                orderData.salt
            )
        );

        // register claim
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce_) = allocateAndRegister(
            msg.sender, orderData.idsAndAmounts, orderData.arbiter, expires, BATCH_COMPACT_WITNESS_TYPEHASH, witnessHash
        );

        _storeQualification(claimHash, orderData.qualification);

        Lock[] memory locks = new Lock[](registeredAmounts.length);
        for (uint256 i = 0; i < registeredAmounts.length; i++) {
            locks[i] = _createLock(orderData.idsAndAmounts[i][0], registeredAmounts[i]);
        }

        BatchCompact memory batchCompact = BatchCompact({
            arbiter: orderData.arbiter,
            sponsor: msg.sender,
            nonce: nonce_,
            expires: expires,
            commitments: locks
        });

        // emit open event
        emit Open(
            bytes32(batchCompact.nonce), _convertToResolvedCrossChainOrder(orderData, order.fillDeadline, batchCompact)
        );
    }

    /// @inheritdoc IAllocator
    function authorizeClaim(
        bytes32 claimHash,
        address, /*arbiter*/
        address, /*sponsor*/
        uint256, /*nonce*/
        uint256, /*expires*/
        uint256[2][] calldata, /*idsAndAmounts*/
        bytes calldata allocatorData_
    ) external override(HybridAllocator, IAllocator) returns (bytes4) {
        if (msg.sender != address(_COMPACT)) {
            revert InvalidCaller(msg.sender, address(_COMPACT));
        }
        // The compact will check the validity of the nonce and expiration

        (bool validClaim, uint128 targetBlock, uint120 maximumBlocksAfterTarget) =
            _checkClaim(claimHash, allocatorData_);
        // Check if the claim was allocated on chain
        if (validClaim) {
            delete claims[claimHash];

            // Authorize the claim
            return IAllocator.authorizeClaim.selector;
        }

        if (allocatorData_.length != 0xe0 && allocatorData_.length != 0xc0) revert InvalidSignature();

        // Create the digest for the qualified claim hash
        bytes32 qualifiedClaimHash =
            keccak256(abi.encode(QUALIFICATION_TYPEHASH, claimHash, targetBlock, maximumBlocksAfterTarget));
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), _COMPACT_DOMAIN_SEPARATOR, qualifiedClaimHash));
        // Check the allocator data for a valid signature by an authorized signer
        bytes calldata allocatorSignature = LibBytes.bytesInCalldata(allocatorData_, 0x40);
        if (!_checkSignature(digest, allocatorSignature)) {
            revert InvalidSignature();
        }

        // Authorize the claim
        return IAllocator.authorizeClaim.selector;
    }

    /// @inheritdoc IOriginSettler
    function resolveFor(GaslessCrossChainOrder calldata order, bytes calldata /*originFillerData*/ )
        external
        view
        returns (ResolvedCrossChainOrder memory)
    {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_GASLESS_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_GASLESS_TYPEHASH);
        }

        (Order calldata orderData,) = _decodeOrderData(order.orderData, false);

        Lock[] memory locks = new Lock[](orderData.idsAndAmounts.length);
        for (uint256 i = 0; i < orderData.idsAndAmounts.length; i++) {
            locks[i] = _createLock(orderData.idsAndAmounts[i][0], orderData.idsAndAmounts[i][1]);
        }

        BatchCompact memory batchCompact = BatchCompact({
            arbiter: orderData.arbiter,
            sponsor: order.user,
            nonce: nonce + 1,
            expires: order.openDeadline,
            commitments: locks
        });

        return _convertToResolvedCrossChainOrder(orderData, order.fillDeadline, batchCompact);
    }

    /// @inheritdoc IOriginSettler
    function resolve(OnchainCrossChainOrder calldata order) external view returns (ResolvedCrossChainOrder memory) {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_ONCHAIN_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_ONCHAIN_TYPEHASH);
        }

        (Order calldata orderData, uint256 expires) = _decodeOrderData(order.orderData, true);
        uint256 idsLength = orderData.idsAndAmounts.length;
        Lock[] memory locks = new Lock[](idsLength);
        for (uint256 i = 0; i < idsLength; i++) {
            uint256 id = orderData.idsAndAmounts[i][0];
            locks[i] = _createLock(id, orderData.idsAndAmounts[i][1]);
        }
        BatchCompact memory batchCompact = BatchCompact({
            arbiter: orderData.arbiter,
            sponsor: msg.sender,
            nonce: nonce + 1, // nonce is incremented by 1 when the claim is registered
            expires: expires,
            commitments: locks
        });
        return _convertToResolvedCrossChainOrder(orderData, order.fillDeadline, batchCompact);
    }

    function _storeQualification(bytes32 claimHash, bytes32 qualification) private {
        // store the allocator data with the claims mapping.
        assembly ("memory-safe") {
            if and(qualification, _ACTIVE_CLAIM_MASK) {
                mstore(0, _INVALID_QUALIFICATION_ERROR_SIGNATURE)
                mstore(0x20, qualification)
                revert(0x1c, 0x24)
            }

            mstore(0x00, claimHash)
            mstore(0x20, claims.slot)
            let claimSlot := keccak256(0x00, 0x40)
            let indicator := or(qualification, _ACTIVE_CLAIM_MASK)
            sstore(claimSlot, indicator)
        }
    }

    function _checkClaim(bytes32 claimHash, bytes calldata allocatorData)
        private
        view
        returns (bool valid, uint128 targetBlock, uint120 maximumBlocksAfterTarget)
    {
        assembly ("memory-safe") {
            mstore(0x00, claimHash)
            mstore(0x20, claims.slot)
            let claimSlot := keccak256(0x00, 0x40)
            let data := sload(claimSlot)

            valid := and(data, _ACTIVE_CLAIM_MASK)
            let storedTargetBlock := shr(57, data)
            let storedMaximumBlocksAfterTarget := shr(200, shl(199, data))

            targetBlock := calldataload(allocatorData.offset)
            maximumBlocksAfterTarget := calldataload(add(allocatorData.offset, 0x20))
            valid :=
                and(
                    valid,
                    and(eq(storedTargetBlock, targetBlock), eq(storedMaximumBlocksAfterTarget, maximumBlocksAfterTarget))
                )
        }
    }

    function _convertToResolvedCrossChainOrder(
        Order calldata orderData,
        uint256 fillDeadline,
        BatchCompact memory batchCompact
    ) private view returns (ResolvedCrossChainOrder memory) {
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
            originData: abi.encode(
                claim,
                mandate,
                uint200(bytes25(orderData.qualification >> 1)),
                uint56(uint256(orderData.qualification >> 1))
            )
        });

        return ResolvedCrossChainOrder({
            user: batchCompact.sponsor,
            originChainId: block.chainid,
            openDeadline: uint32(batchCompact.expires),
            fillDeadline: uint32(fillDeadline),
            orderId: bytes32(batchCompact.nonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
    }

    function _decodeOrderData(bytes calldata orderData, bool isOnChain)
        private
        pure
        returns (Order calldata order, uint256 expires)
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

            expires := mul(calldataload(add(orderData.offset, 0x40)), isOnChain)
        }
    }

    function _convertAddressToBytes32(address address_) private pure returns (bytes32) {
        return bytes32(uint256(uint160(address_)));
    }

    function _createLock(uint256 id, uint256 amount) private pure returns (Lock memory) {
        return Lock({lockTag: bytes12(bytes32(id)), token: _splitToken(id), amount: amount});
    }
}
