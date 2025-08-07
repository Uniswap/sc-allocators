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
    //          keccak256("OrderDataOnChain(Order order,uint256 expires)
    //          Lock(bytes12 lockTag,address token,uint256 amount)
    //          Order(address arbiter,Lock[] commitments,uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt,bytes32 qualification)")
    bytes32 public constant ORDERDATA_ONCHAIN_TYPEHASH =
        0x037a34e1ded3bcc84f59dfc185efc3553c509ebab317153a8dddefce2eaee6f0;

    /// @notice The typehash of the OrderDataGasless struct
    //          keccak256("OrderDataGasless(Order order,bool deposit)
    //          Lock(bytes12 lockTag,address token,uint256 amount)
    //          Order(address arbiter,Lock[] commitments,uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt,bytes32 qualification)")
    bytes32 public constant ORDERDATA_GASLESS_TYPEHASH =
        0x79e4af6feaa84a46fd69ed25e4595e9f6e8690ba3a6c564bfa235542f9faf55c;

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
        if (order_.originSettler != address(this)) {
            revert InvalidOriginSettler(order_.originSettler, address(this));
        }

        // Decode the orderData
        (Order calldata orderData, uint32 deposit) = _decodeOrderData(order_.orderData);

        uint160 caller = uint160(deposit * uint160(msg.sender)); // for a deposit, the nonce will be scoped to the caller + user
        bytes32 nonceIdentifier = _toNonceId(address(caller), order_.user);

        // Early revert if the expected nonce is not the next nonce
        if (order_.nonce != nonces[nonceIdentifier] + 1) {
            revert InvalidNonce(order_.nonce, nonces[nonceIdentifier] + 1);
        }

        bytes32 qualification = bytes32(uint256(orderData.qualification) * deposit); // delete qualification if not a deposit

        ResolvedCrossChainOrder memory resolvedOrder = _resolveOrder(
            order_.user,
            order_.nonce,
            order_.openDeadline,
            order_.fillDeadline,
            orderData,
            sponsorSignature_,
            qualification
        );

        bytes32 mandateHash = _mandateHash(orderData, order_.fillDeadline);

        if (deposit == 0) {
            _open(order_.user, order_.openDeadline, orderData, sponsorSignature_, mandateHash, resolvedOrder);
        } else {
            _openAndRegister(order_.user, order_.openDeadline, orderData, mandateHash, resolvedOrder);
        }
    }

    /// @inheritdoc IOriginSettler
    function open(OnchainCrossChainOrder calldata order) external {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_ONCHAIN_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_ONCHAIN_TYPEHASH);
        }

        // Decode the orderData
        (Order calldata orderData, uint32 expires) = _decodeOrderData(order.orderData);

        bytes32 mandateHash = _mandateHash(orderData, order.fillDeadline);

        ResolvedCrossChainOrder memory resolvedOrder = _resolveOrder(
            msg.sender,
            nonces[_toNonceId(address(0), msg.sender)] + 1,
            expires,
            order.fillDeadline,
            orderData,
            LibBytes.emptyCalldata(),
            orderData.qualification
        );

        _open(msg.sender, expires, orderData, LibBytes.emptyCalldata(), mandateHash, resolvedOrder);
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
        if (order_.originSettler != address(this)) {
            revert InvalidOriginSettler(order_.originSettler, address(this));
        }

        // Decode the orderData
        (Order calldata orderData, uint32 deposit) = _decodeOrderData(order_.orderData);

        uint160 caller = uint160(deposit * uint160(msg.sender)); // for a deposit, the nonce will be scoped to the caller + user
        bytes32 nonceIdentifier = _toNonceId(address(caller), order_.user);

        // Early revert if the expected nonce is not the next nonce
        if (order_.nonce != nonces[nonceIdentifier] + 1) {
            revert InvalidNonce(order_.nonce, nonces[nonceIdentifier] + 1);
        }

        bytes32 qualification = bytes32(uint256(orderData.qualification) * deposit);

        return _resolveOrder(
            order_.user,
            order_.nonce,
            order_.openDeadline,
            order_.fillDeadline,
            orderData,
            LibBytes.emptyCalldata(),
            qualification
        );
    }

    /// @inheritdoc IOriginSettler
    function resolve(OnchainCrossChainOrder calldata order) external view returns (ResolvedCrossChainOrder memory) {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_ONCHAIN_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_ONCHAIN_TYPEHASH);
        }

        // Decode the orderData
        (Order calldata orderData, uint32 expires) = _decodeOrderData(order.orderData);

        return _resolveOrder(
            msg.sender,
            nonces[_toNonceId(address(0), msg.sender)] + 1,
            expires,
            order.fillDeadline,
            orderData,
            LibBytes.emptyCalldata(),
            orderData.qualification
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
    function checkNonce(GaslessCrossChainOrder calldata order_, address caller)
        external
        view
        returns (bool nonceValid)
    {
        (, uint32 deposit) = _decodeOrderData(order_.orderData);

        caller = address(uint160(deposit * uint160(caller))); // for a deposit, the nonce will be scoped to the caller + user
        bytes32 nonceIdentifier = _toNonceId(caller, order_.user);

        // Early revert if the expected nonce is not the next nonce
        return (order_.nonce == nonces[nonceIdentifier] + 1);
    }

    /// @inheritdoc IERC7683Allocator
    function createFillerData(address claimant_) external pure returns (bytes memory fillerData) {
        return abi.encode(claimant_);
    }

    function _open(
        address sponsor,
        uint32 expires,
        Order calldata orderData,
        bytes calldata sponsorSignature,
        bytes32 mandateHash,
        ResolvedCrossChainOrder memory resolvedOrder
    ) internal {
        // Register the allocation on chain
        (bytes32 claimHash, uint256 nonce) = allocateFor(
            sponsor,
            orderData.commitments,
            orderData.arbiter,
            expires,
            BATCH_COMPACT_WITNESS_TYPEHASH,
            mandateHash,
            sponsorSignature
        );

        if (sponsor == msg.sender && orderData.qualification != bytes32(0)) {
            qualifications[claimHash] = orderData.qualification;
        }

        // Emit an open event
        emit Open(bytes32(nonce), resolvedOrder);
    }

    function _openAndRegister(
        address sponsor,
        uint32 expires,
        Order calldata orderData,
        bytes32 mandateHash_,
        ResolvedCrossChainOrder memory resolvedOrder
    ) internal {
        // Register the allocation on chain
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocateAndRegister(
            sponsor, orderData.commitments, orderData.arbiter, expires, BATCH_COMPACT_WITNESS_TYPEHASH, mandateHash_
        );

        if (orderData.qualification != bytes32(0)) {
            qualifications[claimHash] = orderData.qualification;
        }

        for (uint256 i = 0; i < orderData.commitments.length; i++) {
            resolvedOrder.minReceived[i].amount = registeredAmounts[i];
        }

        // Emit an open event
        emit Open(bytes32(nonce), resolvedOrder);
    }

    function _decodeOrderData(bytes calldata orderData)
        internal
        pure
        returns (Order calldata order, uint32 additionalInput)
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

    function _resolveOrder(
        address sponsor,
        uint256 nonce,
        uint32 expires,
        uint32 fillDeadline,
        Order calldata orderData,
        bytes calldata sponsorSignature,
        bytes32 qualification
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
            originData: abi.encode(claim, mandate, uint200(bytes25(qualification)), uint56(uint256(qualification)))
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
