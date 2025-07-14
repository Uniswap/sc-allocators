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
    // the storage slot for the claims mapping
    uint256 private constant _CLAIMS_STORAGE_SLOT = 0;

    // mask for an active claim
    uint256 private constant _ACTIVE_CLAIM_MASK = 0x0000000000000000000000000000000000000000000000000000000000000001;

    // keccak256("OrderData(address arbiter,address sponsor,uint256 expires,uint256[2][] idsAndAmounts,
    //          uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt,uint128 targetBlock,uint120 maximumBlocksAfterTarget)")
    bytes32 public constant ORDERDATA_TYPEHASH = 0x293fe9f0f9b73ba619b34355bb68bfd5c0f97350dd85623f69698b8a8ecb6e59;

    /// @notice keccak256("QualifiedClaim(bytes32 claimHash,uint256 targetBlock,uint256 maximumBlocksAfterTarget)")
    bytes32 public constant QUALIFICATION_TYPEHASH = 0x59866b84bd1f6c909cf2a31efd20c59e6c902e50f2c196994e5aa85cdc7d7ce0;

    constructor(address compact_, address signer_) HybridAllocator(compact_, signer_) {}

    /// @inheritdoc IOriginSettler
    function openFor(
        GaslessCrossChainOrder calldata, /*order_*/
        bytes calldata, /*sponsorSignature_*/
        bytes calldata /*originFillerData*/
    ) external pure {
        revert Unsupported();
    }

    /// @inheritdoc IOriginSettler
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
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce_) = registerClaim(
            orderData.sponsor,
            orderData.idsAndAmounts,
            orderData.arbiter,
            orderData.expires,
            BATCH_COMPACT_WITNESS_TYPEHASH,
            witnessHash
        );

        // store the allocator data with the claims mapping.
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, _CLAIMS_STORAGE_SLOT)
            mstore(add(m, 0x20), claimHash)
            let claimSlot := keccak256(m, 0x40)
            let targetBlock := calldataload(and(orderData, 0x1a0))
            let maximumBlocksAfterTarget := calldataload(and(orderData, 0x1c0))
            let indicator := and(and(shl(128, targetBlock), shl(1, maximumBlocksAfterTarget)), _ACTIVE_CLAIM_MASK)
            sstore(claimSlot, indicator)
        }

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
    function resolveFor(GaslessCrossChainOrder calldata, /*order*/ bytes calldata /*originFillerData*/ )
        external
        pure
        returns (ResolvedCrossChainOrder memory)
    {
        revert Unsupported();
    }

    /// @inheritdoc IOriginSettler
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

    function _checkClaim(bytes32 claimHash, bytes calldata allocatorData)
        private
        view
        returns (bool valid, uint128 targetBlock, uint120 maximumBlocksAfterTarget)
    {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, _CLAIMS_STORAGE_SLOT)
            mstore(add(m, 0x20), claimHash)
            let claimSlot := keccak256(m, 0x40)
            let data := sload(claimSlot)

            valid := and(data, _ACTIVE_CLAIM_MASK)
            let storedTargetBlock := shr(128, data)
            let storedMaximumBlocksAfterTarget := shr(129, shl(128, data))

            targetBlock := calldataload(allocatorData.offset)
            maximumBlocksAfterTarget := calldataload(add(allocatorData.offset, 0x20))
            valid :=
                and(
                    valid,
                    and(eq(storedTargetBlock, targetBlock), eq(storedMaximumBlocksAfterTarget, maximumBlocksAfterTarget))
                )
        }
    }

    function _decodeOrderData(OnchainCrossChainOrder calldata order_)
        private
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

    function _convertAddressToBytes32(address address_) private pure returns (bytes32) {
        return bytes32(uint256(uint160(address_)));
    }

    function _createLock(uint256 id, uint256 amount) private pure returns (Lock memory) {
        return Lock({lockTag: bytes12(bytes32(id)), token: _splitToken(id), amount: amount});
    }
}
