// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IERC7683Allocator} from '../interfaces/IERC7683Allocator.sol';
import {SimpleAllocator} from './SimpleAllocator.sol';
import {Claim, Mandate} from './types/TribunalStructs.sol';

import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {ECDSA} from '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {Compact} from '@uniswap/the-compact/types/EIP712Types.sol';

contract ERC7683Allocator is SimpleAllocator, IERC7683Allocator {
    /// @notice The typehash of the OrderData struct
    //          keccak256("OrderData(address arbiter,address sponsor,uint256 nonce,uint256 id,uint256 amount,
    //          uint256 chainId,address tribunal,address recipient,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt,uint256 targetBlock,uint256 maximumBlocksAfterTarget)")
    bytes32 public constant ORDERDATA_TYPEHASH = 0x9687614112a074c792f7035dc9365f34672a3aa8d3c312500bd47ddcaa0383b5;

    /// @notice The typehash of the OrderDataGasless struct
    //          keccak256("OrderDataGasless(address arbiter,uint256 id,uint256 amount,
    //          uint256 chainId,address tribunal,address recipient,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
    bytes32 public constant ORDERDATA_GASLESS_TYPEHASH =
        0xe9b624fa654c7f07ce16d31bf0165a4030d4022f62987afad8ef9d30fc8a0b88;

    /// @notice keccak256("QualifiedClaim(bytes32 claimHash,uint256 targetBlock,uint256 maximumBlocksAfterTarget)")
    bytes32 public constant QUALIFICATION_TYPEHASH = 0x59866b84bd1f6c909cf2a31efd20c59e6c902e50f2c196994e5aa85cdc7d7ce0;

    /// @notice keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Mandate mandate)
    //          Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
    bytes32 public constant COMPACT_WITNESS_TYPEHASH =
        0xfd9cda0e5e31a3a3476cb5b57b07e2a4d6a12815506f69c880696448cd9897a5;

    /// @notice keccak256("Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
    bytes32 internal constant MANDATE_TYPEHASH = 0x74d9c10530859952346f3e046aa2981a24bb7524b8394eb45a9deddced9d6501;

    /// @notice uint256(uint8(keccak256("ERC7683Allocator.nonce")))
    uint8 internal constant NONCE_MASTER_SLOT_SEED = 0x39;

    bytes32 immutable _COMPACT_DOMAIN_SEPARATOR;

    constructor(address compactContract_, uint256 minWithdrawalDelay_, uint256 maxWithdrawalDelay_)
        SimpleAllocator(compactContract_, minWithdrawalDelay_, maxWithdrawalDelay_)
    {
        _COMPACT_DOMAIN_SEPARATOR = ITheCompact(COMPACT_CONTRACT).DOMAIN_SEPARATOR();
    }

    /// @inheritdoc IERC7683Allocator
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
        OrderDataGasless memory orderDataGasless = abi.decode(order_.orderData, (OrderDataGasless));

        OrderData memory orderData =
            _convertGaslessOrderData(order_.user, order_.nonce, order_.openDeadline, orderDataGasless);

        _open(orderData, order_.fillDeadline, order_.user, sponsorSignature_);
    }

    /// @inheritdoc IERC7683Allocator
    function open(OnchainCrossChainOrder calldata order) external {
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_TYPEHASH);
        }

        // Decode the orderData
        OrderData memory orderData = abi.decode(order.orderData, (OrderData));
        if (orderData.sponsor != msg.sender) {
            revert InvalidSponsor(orderData.sponsor, msg.sender);
        }

        _open(orderData, order.fillDeadline, msg.sender, '');
    }

    /// @inheritdoc IERC7683Allocator
    function resolveFor(GaslessCrossChainOrder calldata order_, bytes calldata)
        external
        view
        returns (ResolvedCrossChainOrder memory)
    {
        OrderDataGasless memory orderDataGasless = abi.decode(order_.orderData, (OrderDataGasless));

        OrderData memory orderData =
            _convertGaslessOrderData(order_.user, order_.nonce, order_.openDeadline, orderDataGasless);
        return _resolveOrder(order_.user, order_.fillDeadline, order_.nonce, orderData, '');
    }

    /// @inheritdoc IERC7683Allocator
    function resolve(OnchainCrossChainOrder calldata order_) external view returns (ResolvedCrossChainOrder memory) {
        OrderData memory orderData = abi.decode(order_.orderData, (OrderData));
        return _resolveOrder(orderData.sponsor, order_.fillDeadline, orderData.nonce, orderData, '');
    }

    /// @inheritdoc IERC7683Allocator
    function getCompactWitnessTypeString() external pure returns (string memory) {
        return
        'Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Mandate mandate)Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt))';
    }

    /// @inheritdoc IERC7683Allocator
    function checkNonce(address sponsor_, uint256 nonce_) external view returns (bool nonceFree_) {
        uint96 nonceWithoutAddress = _checkNonce(sponsor_, nonce_);
        uint96 wordPos = uint96(nonceWithoutAddress / 256);
        uint96 bitPos = uint96(nonceWithoutAddress % 256);
        assembly ("memory-safe") {
            let masterSlot := or(shl(248, NONCE_MASTER_SLOT_SEED), or(shl(88, sponsor_), wordPos))
            nonceFree_ := iszero(and(sload(masterSlot), shl(bitPos, 1)))
        }
        return nonceFree_;
    }

    /// @inheritdoc IERC7683Allocator
    function createFillerData(address claimant_) external pure returns (bytes memory fillerData) {
        fillerData = abi.encode(claimant_);
        return fillerData;
    }

    function _open(OrderData memory orderData_, uint32 fillDeadline_, address sponsor_, bytes memory sponsorSignature_)
        internal
    {
        // Enforce a nonce where the most significant 96 bits are the nonce and the least significant 160 bits are the sponsor
        uint96 nonceWithoutAddress = _checkNonce(sponsor_, orderData_.nonce);

        // Set a nonce or revert if it is already used
        _setNonce(sponsor_, nonceWithoutAddress);

        // We do not enforce a specific tribunal or arbiter. This will allow to support new arbiters and tribunals after the deployment of the allocator
        // Going with an immutable arbiter and tribunal would limit support for new chains with a fully decentralized allocator

        bytes32 tokenHash = _lockTokens(orderData_, sponsor_, orderData_.nonce);

        // Work with a Compact digest
        bytes32 claimHash = keccak256(
            abi.encode(
                COMPACT_WITNESS_TYPEHASH,
                orderData_.arbiter,
                sponsor_,
                orderData_.nonce,
                orderData_.expires,
                orderData_.id,
                orderData_.amount,
                keccak256(
                    abi.encode(
                        MANDATE_TYPEHASH,
                        orderData_.chainId,
                        orderData_.tribunal,
                        orderData_.recipient,
                        fillDeadline_,
                        orderData_.token,
                        orderData_.minimumAmount,
                        orderData_.baselinePriorityFee,
                        orderData_.scalingFactor,
                        keccak256(abi.encodePacked(orderData_.decayCurve)),
                        orderData_.salt
                    )
                )
            )
        );

        // We check for the length, which means this could also be triggered by a zero length signature provided in the openFor function. This enables relaying of orders if the claim was registered on the compact.
        if (sponsorSignature_.length > 0) {
            bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), _COMPACT_DOMAIN_SEPARATOR, claimHash));
            // confirm the signature matches the digest
            address signer = ECDSA.recover(digest, sponsorSignature_);
            if (sponsor_ != signer) {
                revert InvalidSignature(sponsor_, signer);
            }
        } else {
            // confirm the claim hash is registered on the compact
            (bool isActive, uint256 registrationExpiration) =
                ITheCompact(COMPACT_CONTRACT).getRegistrationStatus(sponsor_, claimHash, COMPACT_WITNESS_TYPEHASH);
            if (!isActive || registrationExpiration < orderData_.expires) {
                revert InvalidRegistration(sponsor_, claimHash);
            }
        }

        bytes32 qualifiedClaimHash = keccak256(
            abi.encode(QUALIFICATION_TYPEHASH, claimHash, orderData_.targetBlock, orderData_.maximumBlocksAfterTarget)
        );
        bytes32 qualifiedDigest =
            keccak256(abi.encodePacked(bytes2(0x1901), _COMPACT_DOMAIN_SEPARATOR, qualifiedClaimHash));

        _sponsor[qualifiedDigest] = tokenHash;

        // Emit an open event
        emit Open(
            bytes32(orderData_.nonce),
            _resolveOrder(sponsor_, fillDeadline_, orderData_.nonce, orderData_, sponsorSignature_)
        );
    }

    function _lockTokens(OrderData memory orderData_, address sponsor_, uint256 nonce)
        internal
        returns (bytes32 tokenHash_)
    {
        return _lockTokens(orderData_.arbiter, sponsor_, nonce, orderData_.expires, orderData_.id, orderData_.amount);
    }

    function _lockTokens(address arbiter, address sponsor, uint256 nonce, uint256 expires, uint256 id, uint256 amount)
        internal
        returns (bytes32 tokenHash_)
    {
        tokenHash_ = _checkAllocation(
            Compact({arbiter: arbiter, sponsor: sponsor, nonce: nonce, expires: expires, id: id, amount: amount}), false
        );
        _claim[tokenHash_] = expires;
        _amount[tokenHash_] = amount;
        _nonce[tokenHash_] = nonce;
        return tokenHash_;
    }

    function _resolveOrder(
        address sponsor,
        uint32 fillDeadline,
        uint256 nonce,
        OrderData memory orderData,
        bytes memory sponsorSignature
    ) internal view returns (ResolvedCrossChainOrder memory) {
        FillInstruction[] memory fillInstructions = new FillInstruction[](1);

        Mandate memory mandate = Mandate({
            recipient: orderData.recipient,
            expires: fillDeadline,
            token: orderData.token,
            minimumAmount: orderData.minimumAmount,
            baselinePriorityFee: orderData.baselinePriorityFee,
            scalingFactor: orderData.scalingFactor,
            decayCurve: orderData.decayCurve,
            salt: orderData.salt
        });
        Claim memory claim = Claim({
            chainId: block.chainid,
            compact: Compact({
                arbiter: orderData.arbiter,
                sponsor: sponsor,
                nonce: orderData.nonce,
                expires: orderData.expires,
                id: orderData.id,
                amount: orderData.amount
            }),
            sponsorSignature: sponsorSignature,
            allocatorSignature: '' // No signature required from this allocator, it will verify the claim on chain via ERC1271.
        });

        fillInstructions[0] = FillInstruction({
            destinationChainId: orderData.chainId,
            destinationSettler: _addressToBytes32(orderData.tribunal),
            originData: abi.encode(claim, mandate, orderData.targetBlock, orderData.maximumBlocksAfterTarget)
        });

        Output memory spent = Output({
            token: _addressToBytes32(orderData.token),
            amount: type(uint256).max,
            recipient: _addressToBytes32(orderData.recipient),
            chainId: orderData.chainId
        });
        Output memory received = Output({
            token: _addressToBytes32(_idToToken(orderData.id)),
            amount: orderData.amount,
            recipient: bytes32(0),
            chainId: block.chainid
        });

        Output[] memory maxSpent = new Output[](1);
        maxSpent[0] = spent;
        Output[] memory minReceived = new Output[](1);
        minReceived[0] = received;

        ResolvedCrossChainOrder memory resolvedOrder = ResolvedCrossChainOrder({
            user: sponsor,
            originChainId: block.chainid,
            openDeadline: uint32(orderData.expires),
            fillDeadline: fillDeadline,
            orderId: bytes32(nonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        return resolvedOrder;
    }

    function _checkNonce(address sponsor_, uint256 nonce_) internal pure returns (uint96 nonce) {
        // Enforce a nonce where the least significant 96 bits are the nonce and the most significant 160 bits are the sponsors address
        // This ensures that the nonce is unique for a given sponsor
        address expectedSponsor;
        assembly ("memory-safe") {
            expectedSponsor := shr(96, nonce_)
            nonce := shr(160, shl(160, nonce_))
        }
        if (expectedSponsor != sponsor_) {
            revert InvalidNonce(nonce_);
        }
    }

    function _setNonce(address sponsor_, uint96 nonce_) internal {
        bool used;
        uint96 wordPos = nonce_ / 256; // uint96 divided by 256 means it becomes a uint88 (11 bytes)
        uint96 bitPos = nonce_ % 256;
        assembly ("memory-safe") {
            // [NONCE_MASTER_SLOT_SEED - 1 byte][sponsor address - 20 bytes][wordPos - 11 bytes]
            let masterSlot := or(shl(248, NONCE_MASTER_SLOT_SEED), or(shl(88, sponsor_), wordPos))
            let previouslyUsedNonces := sload(masterSlot)
            if and(previouslyUsedNonces, shl(bitPos, 1)) { used := 1 }
            {
                let usedNonces := or(previouslyUsedNonces, shl(bitPos, 1))
                sstore(masterSlot, usedNonces)
            }
        }
        if (used) {
            revert NonceAlreadyInUse(uint256(bytes32(abi.encodePacked(sponsor_, nonce_))));
        }
    }

    function _idToToken(uint256 id_) internal pure returns (address token_) {
        assembly ("memory-safe") {
            token_ := shr(96, shl(96, id_))
        }
    }

    function _addressToBytes32(address address_) internal pure returns (bytes32 output_) {
        assembly ("memory-safe") {
            output_ := shr(96, shl(96, address_))
        }
    }

    function _convertGaslessOrderData(
        address sponsor_,
        uint256 nonce_,
        uint32 openDeadline_,
        OrderDataGasless memory orderDataGasless_
    ) internal pure returns (OrderData memory orderData_) {
        orderData_ = OrderData({
            arbiter: orderDataGasless_.arbiter,
            sponsor: sponsor_,
            nonce: nonce_,
            expires: openDeadline_,
            id: orderDataGasless_.id,
            amount: orderDataGasless_.amount,
            chainId: orderDataGasless_.chainId,
            tribunal: orderDataGasless_.tribunal,
            recipient: orderDataGasless_.recipient,
            token: orderDataGasless_.token,
            minimumAmount: orderDataGasless_.minimumAmount,
            baselinePriorityFee: orderDataGasless_.baselinePriorityFee,
            scalingFactor: orderDataGasless_.scalingFactor,
            decayCurve: orderDataGasless_.decayCurve,
            salt: orderDataGasless_.salt,
            targetBlock: 0,
            maximumBlocksAfterTarget: 0
        });
        return orderData_;
    }
}
