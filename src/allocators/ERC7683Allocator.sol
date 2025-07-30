// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOriginSettler} from '../interfaces/ERC7683/IOriginSettler.sol';
import {IERC7683Allocator} from '../interfaces/IERC7683Allocator.sol';
import {OnChainAllocator} from './OnChainAllocator.sol';
import {BatchClaim, Mandate} from './types/TribunalStructs.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';

import {LibBytes} from '@solady/utils/LibBytes.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {BatchCompact, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

contract ERC7683Allocator is OnChainAllocator, IERC7683Allocator {
    /// @notice The typehash of the OrderDataOnChain struct
    //          keccak256("OrderDataOnChain(address arbiter,uint256 expires,Order order,uint200 targetBlock,uint56 maximumBlocksAfterTarget)
    //          Lock(bytes12 lockTag,address token,uint256 amount)
    //          Order(Lock[] commitments,uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
    bytes32 public constant ORDERDATA_ONCHAIN_TYPEHASH =
        0x95d7f00c299b34a562258ba851472a8d9bd0d8a1b88fce3a37b7d27ca06e77c4;

    /// @notice The typehash of the OrderDataGasless struct
    //          keccak256("OrderDataGasless(address arbiter,Order order)
    //          Lock(bytes12 lockTag,address token,uint256 amount)
    //          Order(Lock[] commitments,uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
    bytes32 public constant ORDERDATA_GASLESS_TYPEHASH =
        0xdebd9e7866045b7f0ce8613ffbb31daa3fa5c6e6ac228316ba9f57fda63b7489;

    /// @notice keccak256("BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)
    //          Lock(bytes12 lockTag,address token,uint256 amount)
    //          Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
    bytes32 public constant BATCH_COMPACT_WITNESS_TYPEHASH =
        0x5ede122c736b60a8b718f83dcfb5d6e4aa27c9714d0c7bc9ca86562b8f878463;

    /// @notice keccak256("Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
    bytes32 private constant MANDATE_TYPEHASH = 0x74d9c10530859952346f3e046aa2981a24bb7524b8394eb45a9deddced9d6501;

    mapping(bytes32 claimHash => bytes32 qualification) public qualifications;

    constructor(address compactContract_) OnChainAllocator(compactContract_) {}

    /// @inheritdoc IOriginSettler
    function openFor(GaslessCrossChainOrder calldata order_, bytes calldata sponsorSignature_, bytes calldata)
        external
    {
        // Check if orderDataType is the one expected by the allocator
        if (order_.orderDataType != ORDERDATA_GASLESS_TYPEHASH) {
            revert InvalidOrderDataType(order_.orderDataType, ORDERDATA_GASLESS_TYPEHASH);
        }
        /// TODO: Potentially useless check, since the allocator Id gets checked later.
        if (order_.originSettler != address(this)) {
            revert InvalidOriginSettler(order_.originSettler, address(this));
        }
        // Early revert if the expected nonce is not the next nonce
        if (order_.nonce != nonces[order_.user] + 1) {
            revert InvalidNonce(order_.nonce, nonces[order_.user] + 1);
        }

        // Decode the orderData
        (, Order calldata orderData,,) = _decodeOrderData(order_.orderData, false);

        ResolvedCrossChainOrder memory resolvedOrder = _resolveOrder(
            order_.user, order_.nonce, order_.openDeadline, order_.fillDeadline, orderData, sponsorSignature_, 0, 0
        );

        bytes32 mandateHash = _mandateHash(orderData, order_.fillDeadline);

        _open(order_.user, order_.openDeadline, orderData, sponsorSignature_, mandateHash, bytes32(0), resolvedOrder);
    }

    /// @inheritdoc IOriginSettler
    function open(OnchainCrossChainOrder calldata order) external {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_ONCHAIN_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_ONCHAIN_TYPEHASH);
        }

        // Decode the orderData
        (uint32 expires, Order calldata orderData, uint200 targetBlock, uint56 maximumBlocksAfterTarget) =
            _decodeOrderData(order.orderData, true);

        bytes32 mandateHash = _mandateHash(orderData, order.fillDeadline);

        ResolvedCrossChainOrder memory resolvedOrder = _resolveOrder(
            msg.sender,
            nonces[msg.sender] + 1,
            expires,
            order.fillDeadline,
            orderData,
            LibBytes.emptyCalldata(),
            targetBlock,
            maximumBlocksAfterTarget
        );

        _open(
            msg.sender,
            expires,
            orderData,
            LibBytes.emptyCalldata(),
            mandateHash,
            bytes32(abi.encodePacked(targetBlock, maximumBlocksAfterTarget)),
            resolvedOrder
        );
    }

    /// @inheritdoc IOriginSettler
    function resolveFor(GaslessCrossChainOrder calldata order_, bytes calldata)
        external
        view
        returns (ResolvedCrossChainOrder memory)
    {
        // Check if orderDataType is the one expected by the allocator
        if (order_.orderDataType != ORDERDATA_GASLESS_TYPEHASH) {
            revert InvalidOrderDataType(order_.orderDataType, ORDERDATA_GASLESS_TYPEHASH);
        }
        /// TODO: Potentially useless check, since the allocator Id gets checked later.
        if (order_.originSettler != address(this)) {
            revert InvalidOriginSettler(order_.originSettler, address(this));
        }
        // Early revert if the expected nonce is not the next nonce
        if (order_.nonce != nonces[order_.user] + 1) {
            revert InvalidNonce(order_.nonce, nonces[order_.user] + 1);
        }

        // Decode the orderData
        (, Order calldata orderData,,) = _decodeOrderData(order_.orderData, false);

        return _resolveOrder(
            order_.user,
            order_.nonce,
            order_.openDeadline,
            order_.fillDeadline,
            orderData,
            LibBytes.emptyCalldata(),
            0,
            0
        );
    }

    /// @inheritdoc IOriginSettler
    function resolve(OnchainCrossChainOrder calldata order) external view returns (ResolvedCrossChainOrder memory) {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_ONCHAIN_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_ONCHAIN_TYPEHASH);
        }

        // Decode the orderData
        (uint32 expires, Order calldata orderData, uint200 targetBlock, uint56 maximumBlocksAfterTarget) =
            _decodeOrderData(order.orderData, true);

        return _resolveOrder(
            msg.sender,
            nonces[msg.sender] + 1,
            expires,
            order.fillDeadline,
            orderData,
            LibBytes.emptyCalldata(),
            targetBlock,
            maximumBlocksAfterTarget
        );
    }

    /// @inheritdoc IAllocator
    function authorizeClaim(
        bytes32 claimHash,
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address sponsor, // The account sponsoring the claim.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) public override(OnChainAllocator, IAllocator) onlyCompact returns (bytes4) {
        super.authorizeClaim(claimHash, address(0), sponsor, 0, expires, idsAndAmounts, allocatorData);

        if (qualifications[claimHash] != bytes32(allocatorData)) {
            revert InvalidAllocatorData(bytes32(allocatorData), qualifications[claimHash]);
        }

        return this.authorizeClaim.selector;
    }

    /// @inheritdoc IAllocator
    function isClaimAuthorized(
        bytes32 claimHash,
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) public view override(OnChainAllocator, IAllocator) returns (bool) {
        if (
            !super.isClaimAuthorized(claimHash, address(0), sponsor, 0, expires, idsAndAmounts, LibBytes.emptyCalldata())
        ) {
            return false;
        }

        return qualifications[claimHash] == bytes32(allocatorData);
    }

    /// @inheritdoc IERC7683Allocator
    function getCompactWitnessTypeString() external pure returns (string memory) {
        return
        'BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)';
    }

    /// @inheritdoc IERC7683Allocator
    function checkNonce(uint256 nonce_, address sponsor_) external view returns (bool nonceValid) {
        return nonces[sponsor_] + 1 == nonce_;
    }

    /// @inheritdoc IERC7683Allocator
    function createFillerData(address claimant_) external pure returns (bytes memory fillerData) {
        return abi.encode(claimant_);
    }

    function _open(
        address sponsor,
        uint32 expires,
        Order calldata orderData,
        bytes calldata sponsorSignature_,
        bytes32 mandateHash_,
        bytes32 qualification_,
        ResolvedCrossChainOrder memory resolvedOrder_
    ) internal {
        // Register the allocation on chain
        (bytes32 claimHash, uint256 nonce) = allocateFor(
            sponsor,
            orderData.commitments,
            orderData.arbiter,
            expires,
            BATCH_COMPACT_WITNESS_TYPEHASH,
            mandateHash_,
            sponsorSignature_
        );

        qualifications[claimHash] = qualification_;

        // Emit an open event
        emit Open(bytes32(nonce), resolvedOrder_);
    }

    function _decodeOrderData(bytes calldata orderData, bool onChain)
        internal
        pure
        returns (uint32 expires, Order calldata order, uint200 targetBlock, uint56 maximumBlocksAfterTarget)
    {
        // orderData includes the OrderData(OnChain/Gasless) struct, and the nested Order struct.
        // 0x00: OrderDataOnChain.offset
        // 0x20: OrderDataOnChain.order.offset
        // 0x40: OrderDataOnChain.expires
        // 0x60: OrderDataOnChain.targetBlock
        // 0x80: OrderDataOnChain.maximumBlocksAfterTarget

        // 0x00: OrderDataGasless.offset
        // 0x20: OrderDataGasless.order.offset

        assembly ("memory-safe") {
            let l := sub(orderData.length, 0x20)
            let s := calldataload(add(orderData.offset, 0x20)) // Relative offset of `orderBytes` from `orderData.offset` and the `OrderData...` struct.
            order := add(orderData.offset, add(s, 0x20)) // Add 0x20 since the OrderStruct is within the `OrderData...` struct
            if shr(64, or(s, or(l, orderData.offset))) { revert(l, 0x00) }

            expires := mul(calldataload(add(orderData.offset, 0x40)), onChain)
            targetBlock := mul(calldataload(add(orderData.offset, 0x60)), onChain)
            maximumBlocksAfterTarget := mul(calldataload(add(orderData.offset, 0x80)), onChain)
        }
    }

    function _resolveOrder(
        address sponsor,
        uint256 nonce,
        uint32 expires,
        uint32 fillDeadline,
        Order calldata orderData,
        bytes calldata sponsorSignature,
        uint200 targetBlock,
        uint56 maximumBlocksAfterTarget
    ) internal view returns (ResolvedCrossChainOrder memory) {
        ResolvedCrossChainOrder memory resolvedOrder = ResolvedCrossChainOrder({
            user: sponsor,
            originChainId: block.chainid,
            openDeadline: uint32(expires),
            fillDeadline: fillDeadline,
            orderId: bytes32(nonce),
            maxSpent: new Output[](0),
            minReceived: new Output[](0),
            fillInstructions: new FillInstruction[](0)
        });

        BatchCompact memory compact = BatchCompact({
            arbiter: orderData.arbiter,
            sponsor: sponsor,
            nonce: nonce,
            expires: expires,
            commitments: orderData.commitments
        });

        BatchClaim memory claim = BatchClaim({
            chainId: block.chainid,
            compact: compact,
            sponsorSignature: sponsorSignature,
            allocatorSignature: '' // No signature required from this allocator, it will verify the claim on chain via ERC1271.
        });

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

        FillInstruction[] memory fillInstructions = new FillInstruction[](1);
        fillInstructions[0] = FillInstruction({
            destinationChainId: orderData.chainId,
            destinationSettler: _addressToBytes32(orderData.tribunal),
            originData: abi.encode(claim, mandate, targetBlock, maximumBlocksAfterTarget)
        });
        resolvedOrder.fillInstructions = fillInstructions;

        Output memory spent = Output({
            token: _addressToBytes32(mandate.token),
            amount: type(uint256).max,
            recipient: _addressToBytes32(mandate.recipient),
            chainId: orderData.chainId
        });
        Output[] memory maxSpent = new Output[](1);
        maxSpent[0] = spent;
        resolvedOrder.maxSpent = maxSpent;

        resolvedOrder.minReceived = _createMinimumReceived(orderData.commitments);

        return resolvedOrder;
    }

    function _createMinimumReceived(Lock[] calldata commitments) internal view returns (Output[] memory) {
        Output[] memory minReceived = new Output[](commitments.length);

        for (uint256 i = 0; i < commitments.length; i++) {
            Output memory received = Output({
                token: _addressToBytes32(commitments[i].token),
                amount: commitments[i].amount,
                recipient: bytes32(0),
                chainId: block.chainid
            });
            minReceived[i] = received;
        }
        return minReceived;
    }

    function _mandateHash(Order calldata orderData, uint32 fillDeadline) internal pure returns (bytes32 mandateHash_) {
        bytes32 decayCurveHash = keccak256(abi.encodePacked(orderData.decayCurve));
        mandateHash_ = keccak256(
            abi.encode(
                MANDATE_TYPEHASH,
                orderData.chainId,
                orderData.tribunal,
                orderData.recipient,
                fillDeadline,
                orderData.settlementToken,
                orderData.minimumAmount,
                orderData.baselinePriorityFee,
                orderData.scalingFactor,
                decayCurveHash,
                orderData.salt
            )
        );
    }

    function _addressToBytes32(address address_) internal pure returns (bytes32 output_) {
        assembly ("memory-safe") {
            output_ := shr(96, shl(96, address_))
        }
    }
}
