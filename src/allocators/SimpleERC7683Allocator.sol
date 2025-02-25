// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { Compact, BatchCompact, BATCH_COMPACT_TYPEHASH, COMPACT_TYPEHASH } from "@uniswap/the-compact/types/EIP712Types.sol";
import { ITheCompact } from "@uniswap/the-compact/interfaces/ITheCompact.sol";
import { SimpleAllocator } from "./SimpleAllocator.sol";
import { Claim, Mandate } from "./types/TribunalStructs.sol";
import { IOriginSettler } from "../interfaces/ERC7683/IOriginSettler.sol";

contract SimpleERC7683Allocator is SimpleAllocator, IOriginSettler {

    struct OrderData {
        // COMPACT
        address arbiter; // The account tasked with verifying and submitting the claim.
        address sponsor; // The account to source the tokens from.
        uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires; // The time at which the claim expires.
        uint256 id; // The token ID of the ERC6909 token to allocate.
        uint256 amount; // The amount of ERC6909 tokens to allocate.
        // MANDATE
        uint256 chainId; // (implicit arg, included in EIP712 payload)
        address tribunal; // (implicit arg, included in EIP712 payload)
        address recipient; // Recipient of settled tokens
        // uint256 expires; // Mandate expiration timestamp
        address token; // Settlement token (address(0) for native)
        uint256 minimumAmount; // Minimum settlement amount
        uint256 baselinePriorityFee; // Base fee threshold where scaling kicks in
        uint256 scalingFactor; // Fee scaling multiplier (1e18 baseline)
        bytes32 salt; // Replay protection parameter
    }

    struct OrderDataGasless {
        // COMPACT
        // address arbiter; // The account tasked with verifying and submitting the claim.
        // address sponsor; // The account to source the tokens from.
        // uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires; // The time at which the claim expires.
        uint256 id; // The token ID of the ERC6909 token to allocate.
        uint256 amount; // The amount of ERC6909 tokens to allocate.
        // MANDATE
        uint256 chainId; // (implicit arg, included in EIP712 payload)
        address tribunal; // (implicit arg, included in EIP712 payload)
        address recipient; // Recipient of settled tokens
        // uint256 expires; // Mandate expiration timestamp
        address token; // Settlement token (address(0) for native)
        uint256 minimumAmount; // Minimum settlement amount
        uint256 baselinePriorityFee; // Base fee threshold where scaling kicks in
        uint256 scalingFactor; // Fee scaling multiplier (1e18 baseline)
        bytes32 salt; // Replay protection parameter
    }

    error InvalidOriginSettler(address originSettler, address expectedOriginSettler);
    error InvalidOrderDataType(bytes32 orderDataType, bytes32 expectedOrderDataType);
    error InvalidChainId(uint256 chainId, uint256 expectedChainId);
    error InvalidRecipient(address recipient, address expectedRecipient);
    error InvalidNonce(uint256 nonce);
    error NonceAlreadyInUse(uint256 nonce);
    error InvalidSignature(address signer, address expectedSigner);
    error InvalidRegistration(address sponsor, bytes32 claimHash);
    error InvalidSponsor(address sponsor, address expectedSponsor);

    // The typehash of the OrderData struct
    // keccak256("OrderData(address arbiter,address sponsor,uint256 nonce,uint256 id,uint256 amount,Mandate mandate)
    // Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,bytes32 salt)")
    bytes32 constant ORDERDATA_TYPEHASH = 0x9e0e1bdb0df35509b65bbc49d209dd42496c5a3f13998f9a74dc842d6932656b;

    // The typehash of the OrderDataGasless struct
    // keccak256("OrderDataGasless(address arbiter,uint256 id,uint256 amount,Mandate mandate)
    // Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,bytes32 salt)")
    bytes32 constant ORDERDATA_GASLESS_TYPEHASH = 0x9ab67658b7c0f35b64fdadd7adee1e58b6399a8201f38c355d3a109a2d7081d7;

    // keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Mandate mandate)
    // Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,bytes32 salt)")
    bytes32 constant COMPACT_WITNESS_TYPEHASH = 0x27f09e0bb8ce2ae63380578af7af85055d3ada248c502e2378b85bc3d05ee0b0;

    bytes32 immutable _COMPACT_DOMAIN_SEPARATOR;

    /// FOR SINGLE COMPACT WE HAVE:
    /// - arbiter
    /// - sponsor
    /// - nonce
    /// - expires
    /// - id
    /// - amount
    /// WHAT ADDITIONAL DATA NEEDS TO BE SIGNED:
    // Witness(
    // uint256 originChainId, 
    // uint256 targetChainId, 
    // bytes32 targetTokenAddress, 
    // uint256 targetMinAmount, 
    // bytes32 recipient, 
    // bytes32 destinationSettler, 
    // uint32 fillDeadline
    // )

    /// FOR BATCH COMPACT WE HAVE:
    /// - arbiter
    /// - sponsor
    /// - nonce
    /// - expires
    /// - idsAndAmounts
    /// WHAT ADDITIONAL DATA NEEDS TO BE SIGNED:
    // Witness(
    // uint256[] originChainId, 
    // uint256[] targetChainId, 
    // bytes32[] targetTokenAddress, 
    // uint256[] targetMinAmount, 
    // bytes32[] recipient, 
    // bytes32[] destinationSettler, 
    // uint32 fillDeadline
    // )

    /// TODO: batch compacts witness
    
    // The nonce of the allocator
    mapping(uint256 nonce => bool nonceUsed)  private _userNonce;

    constructor(address compactContract_, uint256 minWithdrawalDelay_, uint256 maxWithdrawalDelay_)
        SimpleAllocator(compactContract_, minWithdrawalDelay_, maxWithdrawalDelay_) {
        _COMPACT_DOMAIN_SEPARATOR = ITheCompact(COMPACT_CONTRACT).DOMAIN_SEPARATOR();
    }

    /// @notice Opens a gasless cross-chain order on behalf of a user.
	/// @dev To be called by the filler.
	/// @dev This method must emit the Open event
	/// @param order_ The GaslessCrossChainOrder definition
	/// @param sponsorSignature_ The user's signature over the order
	function openFor(GaslessCrossChainOrder calldata order_, bytes calldata sponsorSignature_, bytes calldata) external{
        // With the users signature, we can create locks in the name of the user

        // Check if orderDataType is the one expected by the allocator
        if (order_.orderDataType != ORDERDATA_GASLESS_TYPEHASH) {
            revert InvalidOrderDataType(order_.orderDataType, ORDERDATA_GASLESS_TYPEHASH);
        }

        // Decode the orderData
        OrderDataGasless memory orderDataGasless = abi.decode(order_.orderData, (OrderDataGasless));

        OrderData memory orderData = _convertGaslessOrderData(order_.user, order_.nonce, order_.originSettler, orderDataGasless);

        _open(orderData, order_.fillDeadline, order_.user, sponsorSignature_);
    }

	/// @notice Opens a cross-chain order
	/// @dev To be called by the user
	/// @dev This method must emit the Open event
    /// @dev This locks the users tokens
	/// @param order The OnchainCrossChainOrder definition
	function open(OnchainCrossChainOrder calldata order) external{
        // TODO: Think about if this can only be used with a registered compact? Or do we want the sponsor signature in the orderData?

        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_TYPEHASH);
        }

        // Decode the orderData
        OrderData memory orderData = abi.decode(order.orderData, (OrderData));
        if(orderData.sponsor != msg.sender) {
            revert InvalidSponsor(orderData.sponsor, msg.sender);
        }

        _open(orderData, order.fillDeadline, msg.sender, "");
    }

    /// @notice Resolves a specific GaslessCrossChainOrder into a generic ResolvedCrossChainOrder
	/// @dev Intended to improve standardized integration of various order types and settlement contracts
	/// @param order The GaslessCrossChainOrder definition
	/// @return ResolvedCrossChainOrder hydrated order data including the inputs and outputs of the order
	function resolveFor(GaslessCrossChainOrder calldata order, bytes calldata) external view returns (ResolvedCrossChainOrder memory){
        OrderDataGasless memory orderDataGasless = abi.decode(order.orderData, (OrderDataGasless));

        OrderData memory orderData = _convertGaslessOrderData(order.user, order.nonce, order.originSettler, orderDataGasless);
        return _resolveOrder(order.user, order.fillDeadline, order.nonce, orderData, "");
    }

	/// @notice Resolves a specific OnchainCrossChainOrder into a generic ResolvedCrossChainOrder
	/// @dev Intended to improve standardized integration of various order types and settlement contracts
	/// @param order The OnchainCrossChainOrder definition
	/// @return ResolvedCrossChainOrder hydrated order data including the inputs and outputs of the order
	function resolve(OnchainCrossChainOrder calldata order) external view returns (ResolvedCrossChainOrder memory){
        OrderData memory orderData = abi.decode(order.orderData, (OrderData));
        return _resolveOrder(orderData.sponsor, order.fillDeadline, orderData.nonce, orderData, "");
    }

    function getCompactWitnessString() external pure returns (string memory) {
        return "Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,bytes32 salt)";
    }

    function checkNonce(address sponsor_, uint256 nonce_) external view returns (bool nonceUnused_) {
        _checkNonce(sponsor_, nonce_);
        nonceUnused_ = !_userNonce[nonce_];
        return nonceUnused_;
    }

    function _open(OrderData memory orderData_, uint32 fillDeadline_, address sponsor_, bytes memory sponsorSignature_) internal {

        // Enforce a nonce where the most significant 96 bits are the nonce and the least significant 160 bits are the sponsor
        _checkNonce(sponsor_, orderData_.nonce);

        // Check the nonce
        if (_userNonce[orderData_.nonce]) {
            revert NonceAlreadyInUse(orderData_.nonce);
        }
        _userNonce[orderData_.nonce] = true;

        // We do not enforce a specific tribunal, so we do not check the address. This will allow to support new tribunals after the deployment of the allocator
        // Going with an immutable tribunal would limit support for new chains with a fully decentralized allocator
        /// TODO: THINK ABOUT IF THE ARBITER MUST BE ENFORCED OR NOT

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

        // TODO: This means everyone can open an order for a user if they have registered the claim hash on the compact (just call openFor with an empty signature). Any issues with that?
        //       Do not currently see an issue, since its the same with the sponsors signature.
        if(sponsorSignature_.length > 0) {
            // confirm the signature matches the digest
            bytes32 digest = keccak256(
                abi.encodePacked(
                    bytes2(0x1901),
                    _COMPACT_DOMAIN_SEPARATOR,
                    claimHash
                )
            );
            address signer = ECDSA.recover(digest, sponsorSignature_);
            if (sponsor_ != signer) {
                revert InvalidSignature(sponsor_, signer);
            }
        } else {
            // confirm the claim hash is registered on the compact
            (bool isActive, uint256 registrationExpiration) = ITheCompact(COMPACT_CONTRACT).getRegistrationStatus(sponsor_, claimHash, COMPACT_WITNESS_TYPEHASH);
            if (!isActive || registrationExpiration < orderData_.expires) {
                revert InvalidRegistration(sponsor_, claimHash);
            }
        }

        _sponsor[claimHash] = tokenHash;

        // Emit an open event
        emit Open(bytes32(orderData_.nonce), _resolveOrder(sponsor_, fillDeadline_, orderData_.nonce, orderData_, sponsorSignature_));
    }

    function _lockTokens(OrderData memory orderData_, address sponsor_, uint256 identifier) internal returns (bytes32 tokenHash_) {
        return _lockTokens(orderData_.arbiter, sponsor_, identifier, orderData_.expires, orderData_.id, orderData_.amount);
    }

    function _lockTokens(address arbiter, address sponsor, uint256 identifier, uint256 expires, uint256 id, uint256 amount) internal returns (bytes32 tokenHash_) {
        tokenHash_ = _checkAllocation(Compact({
            arbiter: arbiter,
            sponsor: sponsor,
            nonce: identifier,
            expires: expires,
            id: id,
            amount: amount
        }));
        _claim[tokenHash_] = expires;
        _amount[tokenHash_] = amount;
        _nonce[tokenHash_] = identifier;

        return tokenHash_;

    }

    function _resolveOrder(address sponsor, uint32 fillDeadline, uint256 identifier, OrderData memory orderData, bytes memory sponsorSignature) internal view returns (ResolvedCrossChainOrder memory) {
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
            allocatorSignature: "" // No signature required from this allocator, it will verify the claim on chain.
        });

        fillInstructions[0] = FillInstruction({
            destinationChainId: orderData.chainId,
            destinationSettler: bytes20(orderData.tribunal),
            originData: abi.encode(claim, mandate) // TODO: FILL WITH THE ORIGIN DATA REQUIRED BY THE TRIBUNAL
        });

        Output memory spent = Output({
            token: bytes20(orderData.token),
            amount: type(uint256).max,
            recipient: bytes20(orderData.recipient),
            chainId: orderData.chainId
        });
        Output memory received = Output({
            token: bytes20(_idToToken(orderData.id)),
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
        if(expectedSponsor != sponsor_) {
            revert InvalidNonce(nonce_);
        }
    }

    function _castToAddress(bytes32 address_) internal pure returns (address output_) {
        assembly ("memory-safe") {
            output_ := shr(96, shl(96, address_))
        }
    }

    function _idToToken(uint256 id_) internal pure returns (address token_) {
        assembly ("memory-safe") {
            token_ := shr(96, shl(96, id_))
        }
    }

    function _convertGaslessOrderData(address sponsor_, uint256 nonce_, address arbiter_, OrderDataGasless memory orderDataGasless_) internal pure returns (OrderData memory orderData_) {
        orderData_ = OrderData({
            arbiter: arbiter_,
            sponsor: sponsor_,
            nonce: nonce_,
            expires: orderDataGasless_.expires,
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
