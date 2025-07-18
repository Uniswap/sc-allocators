// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOriginSettler} from '../interfaces/ERC7683/IOriginSettler.sol';
import {IERC7683Allocator} from '../interfaces/IERC7683Allocator.sol';
import {SimpleAllocator} from './SimpleAllocator.sol';
import {Claim, Mandate} from './types/TribunalStructs.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';

import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {LibBytes} from '@solady/utils/LibBytes.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {Compact} from '@uniswap/the-compact/types/EIP712Types.sol';

contract ERC7683Allocator is SimpleAllocator, IERC7683Allocator {
    /// @notice The typehash of the OrderData struct
    //          keccak256("OrderData(address arbiter,address sponsor,uint256 nonce,uint256 expires,bytes12 lockTag,address inputToken,uint256 amount,
    //          uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt,uint256 targetBlock,uint256 maximumBlocksAfterTarget)")
    bytes32 public constant ORDERDATA_TYPEHASH = 0x2ec2bf7ae42e14efd81070a06d7410420dad2cf15d1d09c8a7d77d82f9e5eae5;

    /// @notice The typehash of the OrderDataGasless struct
    //          keccak256("OrderDataGasless(address arbiter,bytes12 lockTag,address inputToken,uint256 amount,
    //          uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
    bytes32 public constant ORDERDATA_GASLESS_TYPEHASH =
        0x29d853cc0f7a1e24319ad92f2404fd0ff5806cd6ac6f6325dfaa7c547074e912;

    /// @notice keccak256("QualifiedClaim(bytes32 claimHash,uint256 targetBlock,uint256 maximumBlocksAfterTarget)")
    bytes32 public constant QUALIFICATION_TYPEHASH = 0x59866b84bd1f6c909cf2a31efd20c59e6c902e50f2c196994e5aa85cdc7d7ce0;

    /// @notice keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,bytes12 lockTag,address token,uint256 amount,Mandate mandate)
    //          Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
    bytes32 public constant COMPACT_WITNESS_TYPEHASH =
        0x2ec0d30491bb66a6eb554b9d53f490d79b54fc5f4963bed4b2bb8096b4790f1f;

    /// @notice keccak256("Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
    bytes32 internal constant MANDATE_TYPEHASH = 0x74d9c10530859952346f3e046aa2981a24bb7524b8394eb45a9deddced9d6501;

    uint8 internal constant ORDERDATA_LOCKTAG_OFFSET = 0x80;

    uint8 internal constant ORDERDATA_GASLESS_LOCKTAG_OFFSET = 0x20;

    uint16 internal constant ORDERDATA_MANDATE_OFFSET = 0x1a4; // orderData.offset = 0xc4 + Mandate.chainId offset = 0xe0;

    uint16 internal constant ORDERDATA_GASLESS_MANDATE_OFFSET = 0x224; // orderData.offset = 0x1a4 + Mandate.chainId offset =  0x80;

    bytes32 immutable _COMPACT_DOMAIN_SEPARATOR;

    constructor(address compactContract_, uint256 minWithdrawalDelay_, uint256 maxWithdrawalDelay_)
        SimpleAllocator(compactContract_, minWithdrawalDelay_, maxWithdrawalDelay_)
    {
        _COMPACT_DOMAIN_SEPARATOR = ITheCompact(COMPACT_CONTRACT).DOMAIN_SEPARATOR();
    }

    /// @inheritdoc IOriginSettler
    function openFor(GaslessCrossChainOrder calldata order_, bytes calldata sponsorSignature_, bytes calldata)
        external
    {
        // With the users signature, we can create locks in the name of the user

        // Check if orderDataType is the one expected by the allocator
        if (order_.orderDataType != ORDERDATA_GASLESS_TYPEHASH) {
            revert InvalidOrderDataType(order_.orderDataType, ORDERDATA_GASLESS_TYPEHASH);
        }
        if (order_.originSettler != address(this)) {
            revert InvalidOriginSettler(order_.originSettler, address(this));
        }

        // Decode the orderData
        bytes calldata orderDataGaslessBytes = LibBytes.dynamicStructInCalldata(order_.orderData, 0x00);

        // Extract the resolved order early to reduce stack pressure
        ResolvedCrossChainOrder memory resolvedOrder = _resolveOrder(
            order_.user,
            order_.nonce,
            order_.openDeadline,
            order_.fillDeadline,
            orderDataGaslessBytes,
            ORDERDATA_GASLESS_LOCKTAG_OFFSET,
            sponsorSignature_
        );

        // Extract mandateHash early to reduce stack pressure
        bytes32 mandateHash = _mandateHash(orderDataGaslessBytes, ORDERDATA_GASLESS_MANDATE_OFFSET, order_.fillDeadline);

        _open(orderDataGaslessBytes, ORDERDATA_GASLESS_LOCKTAG_OFFSET, sponsorSignature_, mandateHash, resolvedOrder);
    }

    /// @inheritdoc IOriginSettler
    function open(OnchainCrossChainOrder calldata order) external {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_TYPEHASH);
        }

        // Decode the orderData
        bytes calldata orderDataBytes = LibBytes.dynamicStructInCalldata(order.orderData, 0x00);
        OrderData calldata orderData;
        assembly ("memory-safe") {
            orderData := orderDataBytes.offset
        }

        _checkMsgSender(orderData.sponsor);

        // Extract mandateHash early to reduce stack pressure
        bytes32 mandateHash = _mandateHash(orderDataBytes, ORDERDATA_MANDATE_OFFSET, order.fillDeadline);

        // Extract the resolved order early to reduce stack pressure
        ResolvedCrossChainOrder memory resolvedOrder = _resolveOrder(
            orderData.sponsor,
            orderData.nonce,
            uint32(orderData.expires),
            order.fillDeadline,
            orderDataBytes,
            ORDERDATA_LOCKTAG_OFFSET,
            LibBytes.emptyCalldata()
        );

        _open(orderDataBytes, ORDERDATA_LOCKTAG_OFFSET, LibBytes.emptyCalldata(), mandateHash, resolvedOrder);
    }

    /// @inheritdoc IOriginSettler
    function resolveFor(GaslessCrossChainOrder calldata order_, bytes calldata)
        external
        view
        returns (ResolvedCrossChainOrder memory)
    {
        bytes calldata orderDataGaslessBytes = LibBytes.dynamicStructInCalldata(order_.orderData, 0x00);

        return _resolveOrder(
            order_.user,
            order_.nonce,
            order_.openDeadline,
            order_.fillDeadline,
            orderDataGaslessBytes,
            ORDERDATA_GASLESS_LOCKTAG_OFFSET,
            LibBytes.emptyCalldata()
        );
    }

    /// @inheritdoc IOriginSettler
    function resolve(OnchainCrossChainOrder calldata order_) external view returns (ResolvedCrossChainOrder memory) {
        bytes calldata orderDataBytes = LibBytes.dynamicStructInCalldata(order_.orderData, 0x00);
        OrderData calldata orderData;
        assembly ("memory-safe") {
            orderData := orderDataBytes.offset
        }
        _nonceValidation(orderData.sponsor, orderData.nonce);
        return _resolveOrder(
            orderData.sponsor,
            orderData.nonce,
            orderData.expires,
            order_.fillDeadline,
            orderDataBytes,
            ORDERDATA_LOCKTAG_OFFSET,
            LibBytes.emptyCalldata()
        );
    }

    /// @inheritdoc IAllocator
    function authorizeClaim(
        bytes32 claimHash, // The message hash representing the claim.
        address, /* arbiter */ // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256, /* nonce */ // A parameter to enforce replay protection, scoped to allocator.
        uint256, /* expires */ // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) external override(SimpleAllocator, IAllocator) onlyCompact returns (bytes4) {
        uint256 length = idsAndAmounts.length;
        if (length > 1) {
            revert BatchCompactsNotSupported();
        }
        (uint256 targetBlock, uint256 maximumBlocksAfterTarget) = abi.decode(allocatorData, (uint256, uint256));
        claimHash = keccak256(abi.encode(QUALIFICATION_TYPEHASH, claimHash, targetBlock, maximumBlocksAfterTarget));

        if (!_claim[claimHash]) {
            revert InvalidLock(claimHash, 0);
        }
        delete _claim[claimHash];

        // Delete all allocations connected to the claim
        for (uint256 i = 0; i < length; ++i) {
            bytes32 tokenHash = _getTokenHash(idsAndAmounts[i][0], sponsor);
            delete _allocation[tokenHash];
        }

        // We expect the Compact to verify the expiration date is still valid and the nonce has not yet been consumed

        return this.authorizeClaim.selector;
    }

    /// @inheritdoc IAllocator
    function isClaimAuthorized(
        bytes32 claimHash,
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address, /*sponsor*/ // The account to source the tokens from.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) external view override(SimpleAllocator, IAllocator) returns (bool) {
        uint256 length = idsAndAmounts.length;
        if (length > 1) {
            revert BatchCompactsNotSupported();
        }
        (uint256 targetBlock, uint256 maximumBlocksAfterTarget) = abi.decode(allocatorData, (uint256, uint256));
        claimHash = keccak256(abi.encode(QUALIFICATION_TYPEHASH, claimHash, targetBlock, maximumBlocksAfterTarget));

        return _claim[claimHash] && expires > block.timestamp;
    }

    /// @inheritdoc IERC7683Allocator
    function getCompactWitnessTypeString() external pure returns (string memory) {
        return
        'Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,bytes12 lockTag,address token,uint256 amount,Mandate mandate)Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)';
    }

    /// @inheritdoc IERC7683Allocator
    function checkNonce(uint256 nonce_, address sponsor_) external view returns (bool nonceFree_) {
        _nonceValidation(sponsor_, nonce_);
        uint256 word = nonce_ / 256;
        uint256 bit = nonce_ % 256;
        assembly ("memory-safe") {
            let nonceBitmap := sload(or(NONCE_MASTER_SLOT_SEED, word))
            nonceFree_ := iszero(and(nonceBitmap, shl(bit, 1)))
        }
        return nonceFree_;
    }

    /// @inheritdoc IERC7683Allocator
    function createFillerData(address claimant_) external pure returns (bytes memory fillerData) {
        fillerData = abi.encode(claimant_);
        return fillerData;
    }

    function _open(
        bytes calldata orderData_,
        uint256 lockTagOffset,
        bytes calldata sponsorSignature_,
        bytes32 mandateHash_,
        ResolvedCrossChainOrder memory resolvedOrder_
    ) internal {
        uint256 nonce_ = uint256(resolvedOrder_.orderId);
        // Enforce a nonce where the most significant 96 bits are the nonce and the least significant 160 bits are the sponsor
        _nonceValidation(resolvedOrder_.user, nonce_);
        // Set a nonce or revert if it is already used
        _checkAndSetNonce(nonce_);

        // We do not enforce a specific tribunal or arbiter. This will allow to support new arbiters and tribunals after the deployment of the allocator
        // Going with an immutable arbiter and tribunal would limit support for new chains with a fully decentralized allocator

        bytes32 tokenHash =
            _verifyAllocation(resolvedOrder_.user, resolvedOrder_.openDeadline, orderData_, lockTagOffset);

        // Create the Compact claim hash
        bytes32 claimHash;
        uint256 lockTagAbsoluteOffset;
        assembly ("memory-safe") {
            lockTagAbsoluteOffset := add(orderData_.offset, lockTagOffset)

            let m := mload(0x40)
            mstore(m, COMPACT_WITNESS_TYPEHASH)
            calldatacopy(add(m, 0x20), orderData_.offset, 0x20) // arbiter
            mstore(add(m, 0x40), mload(resolvedOrder_)) // sponsor (first item in resolvedOrder_)
            mstore(add(m, 0x60), nonce_) // nonce
            mstore(add(m, 0x80), mload(add(resolvedOrder_, 0x40))) // Compact.expires (third item in resolvedOrder_)
            calldatacopy(add(m, 0xa0), lockTagAbsoluteOffset, 0x60) // lockTag, inputToken, amount
            mstore(add(m, 0x100), mandateHash_)
            claimHash := keccak256(m, 0x120)
        }

        // We check for the length, which means this could also be triggered by a zero length signature provided in the openFor function. This enables relaying of orders if the claim was registered on the compact.
        if (sponsorSignature_.length > 0) {
            bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), _COMPACT_DOMAIN_SEPARATOR, claimHash));
            // confirm the signature matches the digest
            address signer_ = _recoverSigner(digest, sponsorSignature_);
            if (resolvedOrder_.user != signer_) {
                revert InvalidSignature(resolvedOrder_.user, signer_);
            }
        } else {
            // confirm the claim hash is registered on the compact
            (bool isActive) =
                ITheCompact(COMPACT_CONTRACT).isRegistered(resolvedOrder_.user, claimHash, COMPACT_WITNESS_TYPEHASH);
            if (!isActive) {
                revert InvalidRegistration(resolvedOrder_.user, claimHash);
            }
        }

        bytes32 qualifiedClaimHash;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, QUALIFICATION_TYPEHASH)
            mstore(add(m, 0x20), claimHash)

            mstore(add(m, 0x40), 0x0) // clear targetBlock
            mstore(add(m, 0x60), 0x0) // clear maximumBlocksAfterTarget
            if eq(lockTagOffset, ORDERDATA_LOCKTAG_OFFSET) {
                // if data is of type OrderData, copy targetBlock and maximumBlocksAfterTarget
                calldatacopy(add(m, 0x40), add(lockTagAbsoluteOffset, 0x180), 0x40) // targetBlock, maximumBlocksAfterTarget
            }
            qualifiedClaimHash := keccak256(m, 0x80)
        }
        uint256 amount;
        assembly ("memory-safe") {
            // load amount from orderData_
            amount := calldataload(add(lockTagAbsoluteOffset, 0x40))
        }

        _lockTokens(tokenHash, amount, resolvedOrder_.openDeadline, qualifiedClaimHash);

        // Emit an open event
        emit Open(bytes32(nonce_), resolvedOrder_);
    }

    function _lockTokens(bytes32 tokenHash, uint256 amount, uint256 expires, bytes32 claimHash) internal {
        // Lock the tokens
        _claim[claimHash] = true;
        _allocation[tokenHash] = _allocationData(amount, expires);
    }

    function _verifyAllocation(address sponsor_, uint32 openDeadline_, bytes calldata orderData_, uint256 lockTagOffset)
        internal
        view
        returns (bytes32 tokenHash_)
    {
        bytes12 lockTag;
        address inputToken;
        uint256 amount;

        assembly ("memory-safe") {
            lockTag := calldataload(add(orderData_.offset, lockTagOffset))
            inputToken := calldataload(add(orderData_.offset, add(lockTagOffset, 0x20)))
            amount := calldataload(add(orderData_.offset, add(lockTagOffset, 0x40)))
        }

        // Check for a valid allocation
        tokenHash_ = _checkForActiveAllocation(sponsor_, lockTag, inputToken);
        _checkAllocator(lockTag);
        _checkExpiration(openDeadline_);
        _checkForcedWithdrawal(sponsor_, openDeadline_, lockTag, inputToken);
        _checkBalance(sponsor_, _getTokenId(lockTag, inputToken), amount);

        return tokenHash_;
    }

    function _resolveOrder(
        address sponsor,
        uint256 nonce,
        uint256 expires,
        uint32 fillDeadline,
        bytes calldata orderData,
        uint256 lockTagOffset,
        bytes calldata sponsorSignature
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

        Compact memory compact;

        assembly ("memory-safe") {
            let m := mload(0x40)

            calldatacopy(m, orderData.offset, 0x20) // arbiter
            mstore(add(m, 0x20), sponsor) // sponsor
            mstore(add(m, 0x40), nonce) // nonce
            mstore(add(m, 0x60), expires) // expires
            calldatacopy(add(m, 0x80), add(orderData.offset, lockTagOffset), 0x60) // lockTag, inputToken, amount

            compact := m
            mstore(0x40, add(m, 0xe0)) // update free memory pointer
        }

        Claim memory claim = Claim({
            chainId: block.chainid,
            compact: compact,
            sponsorSignature: sponsorSignature,
            allocatorSignature: '' // No signature required from this allocator, it will verify the claim on chain via ERC1271.
        });

        Mandate memory mandate;
        assembly ("memory-safe") {
            let m := mload(0x40)

            let mandateOffset := add(add(orderData.offset, lockTagOffset), 0x60)

            // Skip the chainId and tribunal, as they are implicit arguments in the Tribunal.Mandate

            calldatacopy(m, add(mandateOffset, 0x40), 0x20) // recipient
            mstore(add(m, 0x20), fillDeadline) // expires
            calldatacopy(add(m, 0x40), add(mandateOffset, 0x60), 0xc0) // settlementToken, minimumAmount, baselinePriorityFee, scalingFactor, decayCurve.offset, salt
            mstore(add(m, 0xc0), add(m, 0x100)) // update decayCurve.offset to point to the relative memory location of decayCurve.length within Mandate

            let decayCurveOffset := calldataload(add(mandateOffset, 0xe0))
            let decayCurveLength := calldataload(add(orderData.offset, decayCurveOffset))

            calldatacopy(add(m, 0x100), add(orderData.offset, decayCurveOffset), add(decayCurveLength, 0x20)) // decayCurve.length, decayCurve.content

            mandate := m

            let totalMandateLength := add(0x120, decayCurveLength)

            mstore(0x40, add(m, totalMandateLength)) // update free memory pointer
        }

        uint256 chainId;
        bytes32 tribunal;
        uint256 targetBlock;
        uint256 maximumBlocksAfterTarget;

        assembly ("memory-safe") {
            let mandateOffset := add(add(orderData.offset, lockTagOffset), 0x60)
            chainId := calldataload(mandateOffset)
            tribunal := calldataload(add(mandateOffset, 0x20))
            let isOrderData := eq(lockTagOffset, ORDERDATA_LOCKTAG_OFFSET)
            // Multiply the data calldata value by 0 if OrderDataGasless, as OrderDataGasless does not support targetBlock and maximumBlocksAfterTarget
            targetBlock := mul(calldataload(add(mandateOffset, mul(0x120, isOrderData))), isOrderData) // Multiply targetBlock offset by 0 if OrderDataGasless to prevent out of bounds calldata read
            maximumBlocksAfterTarget := mul(calldataload(add(mandateOffset, mul(0x140, isOrderData))), isOrderData) // Multiply maximumBlocksAfterTarget offset by 0 if OrderDataGasless to prevent out of bounds calldata read
        }

        FillInstruction[] memory fillInstructions = new FillInstruction[](1);
        fillInstructions[0] = FillInstruction({
            destinationChainId: chainId,
            destinationSettler: tribunal,
            originData: abi.encode(claim, mandate, targetBlock, maximumBlocksAfterTarget)
        });
        resolvedOrder.fillInstructions = fillInstructions;

        Output memory spent = Output({
            token: _addressToBytes32(mandate.token),
            amount: type(uint256).max,
            recipient: _addressToBytes32(mandate.recipient),
            chainId: chainId
        });
        Output[] memory maxSpent = new Output[](1);
        maxSpent[0] = spent;
        resolvedOrder.maxSpent = maxSpent;

        Output memory received = Output({
            token: _addressToBytes32(compact.token),
            amount: compact.amount,
            recipient: bytes32(0),
            chainId: block.chainid
        });
        Output[] memory minReceived = new Output[](1);
        minReceived[0] = received;
        resolvedOrder.minReceived = minReceived;

        return resolvedOrder;
    }

    function _nonceValidation(address sponsor_, uint256 nonce_) internal pure {
        // Enforce a nonce where the least significant 96 bits are the nonce and the most significant 160 bits are the sponsors address
        // This ensures that the nonce is unique for a given sponsor
        address expectedSponsor;
        assembly ("memory-safe") {
            expectedSponsor := shr(96, nonce_)
        }
        if (expectedSponsor != sponsor_) {
            revert InvalidNonce(nonce_);
        }
    }

    function _recoverSigner(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (signature.length == 65) {
            (r, s) = abi.decode(signature, (bytes32, bytes32));
            v = uint8(signature[64]);
        } else if (signature.length == 64) {
            bytes32 vs;
            (r, vs) = abi.decode(signature, (bytes32, bytes32));
            v = uint8(uint256(vs >> 255) + 27);
            s = vs << 1 >> 1;
        } else {
            return address(0);
        }

        return ecrecover(digest, v, r, s);
    }

    function _mandateHash(bytes calldata orderData, uint256 mandateOffset, uint32 fillDeadline)
        internal
        pure
        returns (bytes32 mandateHash_)
    {
        // total mandate length: x160 + decayCurve.length
        assembly ("memory-safe") {
            let decayCurveOffset := calldataload(add(mandateOffset, 0xe0))
            let decayCurveLength := calldataload(add(orderData.offset, decayCurveOffset))

            let m := mload(0x40)
            mstore(m, MANDATE_TYPEHASH)
            calldatacopy(add(m, 0x20), mandateOffset, 0x60) // chainid, tribunal and recipient
            mstore(add(m, 0x80), fillDeadline) // mandate.expires
            calldatacopy(add(m, 0xa0), add(mandateOffset, 0x60), 0xc0) // settlementToken, minimumAmount, baselinePriorityFee, scalingFactor, decayCurve.offset, salt

            for { let i := 0 } lt(i, decayCurveLength) { i := add(i, 0x20) } {
                mstore(add(m, add(0x160, i)), calldataload(add(add(orderData.offset, decayCurveOffset), add(i, 0x20)))) // copy the content of decayCurve to memory
            }

            mstore(add(m, 0x120), keccak256(add(m, 0x160), mul(decayCurveLength, 0x20))) // create and store the decayCurve hash

            mandateHash_ := keccak256(m, 0x160) // mandate typehash + mandate data length
        }

        // 0x00:  MANDATE_TYPEHASH
        // 0x20:  chainid
        // 0x40:  tribunal
        // 0x60:  recipient
        // 0x80:  fillDeadline
        // 0xa0:  settlementToken
        // 0xc0:  minimumAmount
        // 0xe0:  baselinePriorityFee
        // 0x100: scalingFactor
        // 0x120: decayCurve hash
        // 0x140: salt
    }

    function _addressToBytes32(address address_) internal pure returns (bytes32 output_) {
        assembly ("memory-safe") {
            output_ := shr(96, shl(96, address_))
        }
    }
}
