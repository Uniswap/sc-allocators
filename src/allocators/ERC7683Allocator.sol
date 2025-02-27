// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IERC7683Allocator} from '../interfaces/IERC7683Allocator.sol';
import {SimpleAllocator} from './SimpleAllocator.sol';
import {Claim, Mandate} from './types/TribunalStructs.sol';
import {ECDSA} from '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {Compact} from '@uniswap/the-compact/types/EIP712Types.sol';

contract ERC7683Allocator is SimpleAllocator, IERC7683Allocator {
    // The typehash of the OrderData struct
    // keccak256("OrderData(address arbiter,address sponsor,uint256 nonce,uint256 id,uint256 amount,Mandate mandate)
    // Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,bytes32 salt)")
    bytes32 public constant ORDERDATA_TYPEHASH = 0x9e0e1bdb0df35509b65bbc49d209dd42496c5a3f13998f9a74dc842d6932656b;

    // The typehash of the OrderDataGasless struct
    // keccak256("OrderDataGasless(address arbiter,uint256 id,uint256 amount,Mandate mandate)
    // Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,bytes32 salt)")
    bytes32 public constant ORDERDATA_GASLESS_TYPEHASH =
        0x9ab67658b7c0f35b64fdadd7adee1e58b6399a8201f38c355d3a109a2d7081d7;

    // keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Mandate mandate)
    // Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,bytes32 salt)")
    bytes32 public constant COMPACT_WITNESS_TYPEHASH =
        0x27f09e0bb8ce2ae63380578af7af85055d3ada248c502e2378b85bc3d05ee0b0;

    bytes32 immutable _COMPACT_DOMAIN_SEPARATOR;

    mapping(uint256 nonce => bool nonceUsed) private _userNonce;

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
        'Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Mandate mandate)Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,bytes32 salt))';
    }

    /// @inheritdoc IERC7683Allocator
    function checkNonce(address sponsor_, uint256 nonce_) external view returns (bool nonceFree_) {
        _checkNonce(sponsor_, nonce_);
        nonceFree_ = !_userNonce[nonce_];
        return nonceFree_;
    }

    function _open(OrderData memory orderData_, uint32 fillDeadline_, address sponsor_, bytes memory sponsorSignature_)
        internal
    {
        // Enforce a nonce where the most significant 96 bits are the nonce and the least significant 160 bits are the sponsor
        _checkNonce(sponsor_, orderData_.nonce);

        // Check the nonce
        if (_userNonce[orderData_.nonce]) {
            revert NonceAlreadyInUse(orderData_.nonce);
        }
        _userNonce[orderData_.nonce] = true;

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
                        orderData_.chainId,
                        orderData_.tribunal,
                        orderData_.recipient,
                        fillDeadline_,
                        orderData_.token,
                        orderData_.minimumAmount,
                        orderData_.baselinePriorityFee,
                        orderData_.scalingFactor,
                        orderData_.salt
                    )
                )
            )
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), _COMPACT_DOMAIN_SEPARATOR, claimHash));

        // We check for the length, which means this could also be triggered by a zero length signature provided in the openFor function. This enables relaying of orders if the claim was registered on the compact.
        if (sponsorSignature_.length > 0) {
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

        _sponsor[digest] = tokenHash;

        // Emit an open event
        emit Open(
            bytes32(orderData_.nonce),
            _resolveOrder(sponsor_, fillDeadline_, orderData_.nonce, orderData_, sponsorSignature_)
        );
    }

    function _lockTokens(OrderData memory orderData_, address sponsor_, uint256 identifier)
        internal
        returns (bytes32 tokenHash_)
    {
        return
            _lockTokens(orderData_.arbiter, sponsor_, identifier, orderData_.expires, orderData_.id, orderData_.amount);
    }

    function _lockTokens(
        address arbiter,
        address sponsor,
        uint256 identifier,
        uint256 expires,
        uint256 id,
        uint256 amount
    ) internal returns (bytes32 tokenHash_) {
        tokenHash_ = _checkAllocation(
            Compact({arbiter: arbiter, sponsor: sponsor, nonce: identifier, expires: expires, id: id, amount: amount})
        );
        _claim[tokenHash_] = expires;
        _amount[tokenHash_] = amount;
        _nonce[tokenHash_] = identifier;

        return tokenHash_;
    }

    function _resolveOrder(
        address sponsor,
        uint32 fillDeadline,
        uint256 identifier,
        OrderData memory orderData,
        bytes memory sponsorSignature
    ) internal view returns (ResolvedCrossChainOrder memory) {
        FillInstruction[] memory fillInstructions = new FillInstruction[](1);

        Mandate memory mandate = Mandate({
            chainId: orderData.chainId,
            tribunal: orderData.tribunal,
            recipient: orderData.recipient,
            expires: fillDeadline,
            token: orderData.token,
            minimumAmount: orderData.minimumAmount,
            baselinePriorityFee: orderData.baselinePriorityFee,
            scalingFactor: orderData.scalingFactor,
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
            originData: abi.encode(claim, mandate)
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
            orderId: bytes32(identifier),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        return resolvedOrder;
    }

    function _checkNonce(address sponsor_, uint256 nonce_) internal pure {
        // Enforce a nonce where the most significant 96 bits are the nonce and the least significant 160 bits are the sponsor
        // This ensures that the nonce is unique for a given sponsor
        address expectedSponsor;
        assembly ("memory-safe") {
            expectedSponsor := shr(96, shl(96, nonce_))
        }
        if (expectedSponsor != sponsor_) {
            revert InvalidNonce(nonce_);
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
            salt: orderDataGasless_.salt
        });
        return orderData_;
    }
}
