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
        address sponsor;
        uint96 nonce;
        uint32 claimDeadline;
        Settlement[] settlements;
        address arbiter;
        bytes sponsorSignature;
    }

    struct OrderDataGasless {
        uint32 claimDeadline;
        Settlement[] settlements;
        address arbiter;
    }

    struct Settlement {
        Output input;
        Output output;
        bytes32 destinationSettler; // tribunal
    }

    struct Witness { // for single / non-batch compact
        uint256 originChainId;
        uint256 targetChainId;
        bytes32 targetTokenAddress;
        uint256 targetMinAmount;
        bytes32 recipient;
        bytes32 destinationSettler;
        uint32 fillDeadline;
    }

    error InvalidOriginSettler(address originSettler, address expectedOriginSettler);
    error InvalidOrderDataType(bytes32 orderDataType, bytes32 expectedOrderDataType);
    error InvalidChainId(uint256 chainId, uint256 expectedChainId);
    error InvalidRecipient(address recipient, address expectedRecipient);
    error InvalidNonce(uint256 nonce);
    error NonceAlreadyInUse(uint96 nonce);
    error InvalidSignature(address signer, address expectedSigner);

    // The typehash of the OrderData struct
    // keccak256("OrderData(address sponsor,uint96 nonce,uint32 claimDeadline,Settlement[] settlements,address arbiter,bytes sponsorSignature)Output(bytes32 token,uint256 amount,bytes32 recipient,uint256 chainId)Settlement(Output input,Output output,bytes32 destinationSettler)")
    bytes32 constant ORDERDATA_TYPEHASH = 0xe8225b67751f9ff0d865fdc55742ea54087b20406855f954bd737ab200819ab8;

    // The typehash of the OrderDataGasless struct
    // keccak256("OrderDataGasless(uint32 claimDeadline,Settlement[] settlements,address arbiter)Output(bytes32 token,uint256 amount,bytes32 recipient,uint256 chainId)Settlement(Output input,Output output,bytes32 destinationSettler)")
    bytes32 constant ORDERDATA_GASLESS_TYPEHASH = 0x4679e16e516a2f88beb96ee00964e5f28b9e2ed596592f8c3d92dd70411611a9;

    // keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Witness witness)
    // Witness(uint256 originChainId,uint256 targetChainId,bytes32 targetTokenAddress,uint256 targetMinAmount,bytes32 recipient,bytes32 destinationSettler,uint32 fillDeadline)")
    bytes32 constant COMPACT_WITNESS_TYPEHASH = 0x2f0f51aa07316f3d8860366b556177042fafb2edffc93c799091bae7c194d9a6;

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

    // keccak256("BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256[2][] idsAndAmounts,Witness witness)
    // Witness(uint256[] originChainId,uint256[] targetChainId,bytes32[] targetTokenAddress,uint256[] targetMinAmount,bytes32[] recipient,bytes32[] destinationSettler,uint32 fillDeadline)")
    bytes32 constant BATCH_COMPACT_WITNESS_TYPEHASH = 0x3158fb17880387b9302c66a40dd45893126fd532c2abb7deee6e53149c53646b;

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
    
    // The block interval on the deployed chain
    uint32 immutable BLOCK_INTERVAL;

    // The nonce of the allocator
    mapping(uint256 identifier => bool nonceUsed)  private _userNonce;

    constructor(address compactContract_, address arbiter_, uint256 minWithdrawalDelay_, uint256 maxWithdrawalDelay_, uint32 blockInterval_)
        SimpleAllocator(compactContract_, arbiter_, minWithdrawalDelay_, maxWithdrawalDelay_) {
            BLOCK_INTERVAL = blockInterval_;
    }

    /// @notice Opens a gasless cross-chain order on behalf of a user.
	/// @dev To be called by the filler.
	/// @dev This method must emit the Open event
	/// @param order The GaslessCrossChainOrder definition
	/// @param signature The user's signature over the order
	function openFor(GaslessCrossChainOrder calldata order, bytes calldata signature, bytes calldata) external{
        // since we have the users signature, we can create locks in the name of the user

        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_GASLESS_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_GASLESS_TYPEHASH);
        }
        // Check the allocator is the chosen origin settler
        // This check is not strictly necessary, since the user does not sign a allocator. The filler will not get payed if he maliciously choses a different allocator.
        if (order.originSettler != address(this)) {
            revert InvalidOriginSettler(order.originSettler, address(this));
        }

        // Decode the orderData
        OrderDataGasless memory orderDataGasless = abi.decode(order.orderData, (OrderDataGasless));
        // Enforce a uint96 nonce since the contract handles the nonce management by combining the provided nonce with the user address
        uint96 nonce = uint96(order.nonce);
        if (order.nonce != nonce) {
            revert InvalidNonce(order.nonce);
        }

        OrderData memory orderData = _convertGaslessOrderData(order.user, nonce, orderDataGasless, signature);

        _open(orderData, order.fillDeadline, false);
    }

	/// @notice Opens a cross-chain order
	/// @dev To be called by the user
	/// @dev This method must emit the Open event
    /// @dev This locks the users tokens
	/// @param order The OnchainCrossChainOrder definition
	function open(OnchainCrossChainOrder calldata order) external{
        // Check if orderDataType is the one expected by the allocator
        if (order.orderDataType != ORDERDATA_TYPEHASH) {
            revert InvalidOrderDataType(order.orderDataType, ORDERDATA_TYPEHASH);
        }

        // Decode the orderData
        OrderData memory orderData = abi.decode(order.orderData, (OrderData));
        _open(orderData, order.fillDeadline, false);
    }

    /// @notice Resolves a specific GaslessCrossChainOrder into a generic ResolvedCrossChainOrder
	/// @dev Intended to improve standardized integration of various order types and settlement contracts
	/// @param order The GaslessCrossChainOrder definition
	/// @return ResolvedCrossChainOrder hydrated order data including the inputs and outputs of the order
	function resolveFor(GaslessCrossChainOrder calldata order, bytes calldata) external pure returns (ResolvedCrossChainOrder memory){
        OrderDataGasless memory orderDataGasless = abi.decode(order.orderData, (OrderDataGasless));

        // Enforce a uint96 nonce since the contract handles the nonce management by combining the provided nonce with the user address
        uint96 nonce = uint96(order.nonce);
        if (order.nonce != nonce) {
            revert InvalidNonce(order.nonce);
        }
        OrderData memory orderData = _convertGaslessOrderData(order.user, nonce, orderDataGasless, "");
        return _resolveOrder(order.fillDeadline, orderData);
    }

	/// @notice Resolves a specific OnchainCrossChainOrder into a generic ResolvedCrossChainOrder
	/// @dev Intended to improve standardized integration of various order types and settlement contracts
	/// @param order The OnchainCrossChainOrder definition
	/// @return ResolvedCrossChainOrder hydrated order data including the inputs and outputs of the order
	function resolve(OnchainCrossChainOrder calldata order) external pure returns (ResolvedCrossChainOrder memory){
        OrderData memory orderData = abi.decode(order.orderData, (OrderData));
        return _resolveOrder(order.fillDeadline, orderData);
    }

    function getCompactWitnessString() external pure returns (string memory) {
        return "Witness(uint256 originChainId, uint256 targetChainId, bytes32 targetTokenAddress, uint256 targetMinAmount, bytes32 recipient, bytes32 destinationSettler, uint32 fillDeadline)";
    }

    function getBatchCompactWitnessString() external pure returns (string memory) {
        return "Witness(uint256[] originChainId,uint256[] targetChainId,bytes32[] targetTokenAddress,uint256[] targetMinAmount,bytes32[] recipient,bytes32[] destinationSettler,uint32 fillDeadline)";
    }

    function _open(OrderData memory orderData_, uint32 fillDeadline_, bool delegated_) internal {
        // Check the user
        if(!delegated_ && orderData_.sponsor != msg.sender) { 
            revert InvalidCaller(msg.sender, orderData_.sponsor);
        }
        // Check the arbiter
        if (orderData_.arbiter != ARBITER) {
            revert InvalidArbiter(orderData_.arbiter);
        }

        uint256 identifier = _createIdentifier(orderData_.sponsor, orderData_.nonce);
        // Check the nonce
        if (_userNonce[identifier]) {
            revert NonceAlreadyInUse(orderData_.nonce);
        }
        _userNonce[identifier] = true;

        // We do not enforce a specific tribunal, so we do not check the address. This will allow to support new tribunals after the deployment of the allocator
        // Going with an immutable tribunal would limit support for new chains with a fully decentralized allocator
        /// TODO: THINK ABOUT IF THE ARBITER MUST BE ENFORCED OR NOT

        uint256 settlementsLength = orderData_.settlements.length;

        bytes32 digest;
        bytes32 tokenHash;
        if(settlementsLength > 1) {
            uint256[2][] memory idsAndAmounts = new uint256[2][](settlementsLength);

            uint256[] memory originChainIds = new uint256[](settlementsLength);
            uint256[] memory targetChainIds = new uint256[](settlementsLength);
            bytes32[] memory targetTokenAddresses = new bytes32[](settlementsLength);
            uint256[] memory targetMinAmounts = new uint256[](settlementsLength);
            bytes32[] memory recipients = new bytes32[](settlementsLength);
            bytes32[] memory destinationSettlers = new bytes32[](settlementsLength);

            // Iterate over the inputs and lock the tokens
            for(uint256 i = 0; i < settlementsLength; ++i) {
                if (orderData_.settlements[i].input.chainId != block.chainid) {
                    // MultiChainCompact not supported
                    revert InvalidChainId(orderData_.settlements[i].input.chainId, block.chainid);
                }
                if (_castToAddress(orderData_.settlements[i].input.recipient) != orderData_.sponsor) {
                    // Sponsor must be the same throughout all settlements 
                    revert InvalidRecipient(_castToAddress(orderData_.settlements[i].input.recipient), orderData_.sponsor);
                }
                tokenHash = _lockTokens(orderData_, identifier, i);
                idsAndAmounts[i] = [uint256(orderData_.settlements[i].input.token), orderData_.settlements[i].input.amount];
                originChainIds[i] = block.chainid;
                targetChainIds[i] = orderData_.settlements[i].output.chainId;
                targetTokenAddresses[i] = orderData_.settlements[i].output.token;
                targetMinAmounts[i] = orderData_.settlements[i].output.amount;
                recipients[i] = orderData_.settlements[i].output.recipient;
                destinationSettlers[i] = orderData_.settlements[i].destinationSettler;
            }

            // Work with a BatchCompact digest
            digest = keccak256(
                abi.encodePacked(
                    bytes2(0x1901),
                    ITheCompact(COMPACT_CONTRACT).DOMAIN_SEPARATOR(),
                    keccak256(
                        abi.encode(
                            BATCH_COMPACT_WITNESS_TYPEHASH,
                            orderData_.arbiter, 
                            orderData_.sponsor, 
                            identifier, // TODO: IS THE CAST REQUIRED?
                            orderData_.claimDeadline, 
                            idsAndAmounts,
                            keccak256(
                                abi.encode(
                                    // Skip struct, because it would also need to be named 'Witness' (to be consistent with theCompact)
                                    originChainIds,
                                    targetChainIds,
                                    targetTokenAddresses,
                                    targetMinAmounts,
                                    recipients,
                                    destinationSettlers,
                                    fillDeadline_
                                )
                            )                        
                        )
                    )
                )
            );
        } else {
            if (orderData_.settlements[0].input.chainId != block.chainid) {
                revert InvalidChainId(orderData_.settlements[0].input.chainId, block.chainid);
            }
            if (_castToAddress(orderData_.settlements[0].input.recipient) != orderData_.sponsor) {
                // Sponsor must be the same throughout in the settlements 
                revert InvalidRecipient(_castToAddress(orderData_.settlements[0].input.recipient), orderData_.sponsor);
            }

            tokenHash = _lockTokens(orderData_, identifier, 0);

            // Work with a Compact digest
            digest = keccak256(
                abi.encodePacked(
                    bytes2(0x1901),
                    ITheCompact(COMPACT_CONTRACT).DOMAIN_SEPARATOR(),
                    keccak256(
                        abi.encode(
                            COMPACT_WITNESS_TYPEHASH,
                            orderData_.arbiter,
                            orderData_.sponsor,
                            identifier,
                            orderData_.claimDeadline,
                            uint256(orderData_.settlements[0].input.token), // TODO: IS THE CAST REQUIRED HERE?
                            orderData_.settlements[0].input.amount,
                            keccak256(
                                abi.encode(
                                    Witness({
                                        originChainId: orderData_.settlements[0].input.chainId,
                                        targetChainId: orderData_.settlements[0].output.chainId,
                                        targetTokenAddress: orderData_.settlements[0].output.token,
                                        targetMinAmount: orderData_.settlements[0].output.amount,
                                        recipient: orderData_.settlements[0].output.recipient,
                                        destinationSettler: orderData_.settlements[0].destinationSettler,
                                        fillDeadline: fillDeadline_
                                    })
                                )
                            )
                        )
                    )
                )
            );
        }

        /// TODO: SHOULD WE SKIP THE REQUIREMENT OF THE SPONSOR SIGNATURE FOR A NON DELEGATED OPEN FUNCTION?
        // confirm the signature matches the digest
        address signer = ECDSA.recover(digest, orderData_.sponsorSignature);
        if (orderData_.sponsor != signer) {
            revert InvalidSignature(orderData_.sponsor, signer);
        }

        // The stored tokenHash will only be used to check for the expiration of the order in the isValidSignature function.
        // Since the expiration is the same for all allocations, it does not matter which of the tokenHashes is stored for a batch compact.
        _sponsor[digest] = tokenHash;

        // Emit an open event
        emit Open(bytes32(identifier), _resolveOrder(fillDeadline_, orderData_));
    }

    function _lockTokens(OrderData memory orderData_, uint256 identifier, uint256 index_) internal returns (bytes32 tokenHash_) {
        return _lockTokens(orderData_.arbiter, orderData_.sponsor, identifier, orderData_.claimDeadline, uint256(orderData_.settlements[index_].input.token), orderData_.settlements[index_].input.amount);
    }

    function _lockTokens(address arbiter, address sponsor, uint256 identifier, uint32 expires, uint256 id, uint256 amount) internal returns (bytes32 tokenHash_) {
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

    function _resolveOrder(uint32 fillDeadline, OrderData memory orderData) internal pure returns (ResolvedCrossChainOrder memory) {
        uint256 settlementLength = orderData.settlements.length;
        FillInstruction[] memory fillInstructions = new FillInstruction[](settlementLength);

        Output[] memory outputs = new Output[](settlementLength);
        Output[] memory inputs = new Output[](settlementLength);

        for(uint256 i = 0; i < settlementLength; ++i) {
            inputs[i] = orderData.settlements[i].input;
            outputs[i] = orderData.settlements[i].output;

            /// TODO: FILL THE MANDATE
            Mandate memory mandate = Mandate({
                recipient: _castToAddress(orderData.settlements[i].output.recipient),
                expires: fillDeadline, // TODO: is this correct? Or do we ignore the fill deadline and only care about the claim deadline?
                token: _castToAddress(orderData.settlements[i].output.token),
                minimumAmount: orderData.settlements[i].output.amount,
                baselinePriorityFee: 0, // TODO: check whats happening here
                scalingFactor: 0, // TODO: check whats happening here
                salt: 0 // TODO: whats difference between salt and nonce? This is still sponsor signed data
            });
            Claim memory claim = Claim({
                chainId: orderData.settlements[i].input.chainId, // TODO: IS THIS TARGET OR ORIGIN CHAIN ID? IT APPARENTLY SHOULD BE THE ORIGIN CHAIN ID, BUT WHERE IS THE TARGET CHAIN ID ADDED?
                compact: Compact({
                    arbiter: orderData.arbiter,
                    sponsor: orderData.sponsor,
                    nonce: orderData.nonce,
                    expires: orderData.claimDeadline,
                    id: uint256(orderData.settlements[i].input.token), // TODO: make it clear in doc that outputs and inputs are always connected via the index
                    amount: orderData.settlements[i].input.amount
                }),
                sponsorSignature: orderData.sponsorSignature,
                allocatorSignature: "" // No signature required from this allocator, it will verify the claim on chain.
            });

            fillInstructions[i] = FillInstruction({
                destinationChainId: uint64(orderData.settlements[i].output.chainId), // TODO: WHY SUDDENLY A UINT64 INSTEAD OF UINT256?
                destinationSettler: orderData.settlements[i].destinationSettler,
                originData: abi.encode(claim, mandate) // TODO: FILL WITH THE ORIGIN DATA REQUIRED BY THE TRIBUNAL
            });
        }

        ResolvedCrossChainOrder memory resolvedOrder = ResolvedCrossChainOrder({
            user: orderData.sponsor,
            originChainId: orderData.settlements[0].input.chainId, // must be same for every input
            openDeadline: orderData.claimDeadline, /// TODO: CAN THE OPEN DEADLINE BE THE CLAIM DEADLINE?
            fillDeadline: fillDeadline,
            orderId: bytes32(_createIdentifier(orderData.sponsor, orderData.nonce)),
            maxSpent: inputs,
            minReceived: outputs,
            fillInstructions: fillInstructions
        });
        return resolvedOrder;
    }

    function _createIdentifier(address sponsor_, uint96 nonce_) internal pure returns (uint256 identifier_) {
        assembly ("memory-safe") {
            identifier_ := or(shl(160, nonce_), shr(96, shl(96,sponsor_)))
        }
        return identifier_;
    }

    function _castToAddress(bytes32 address_) internal pure returns (address output_) {
        assembly ("memory-safe") {
            output_ := shr(96, shl(96, address_))
        }
    }

    function _convertGaslessOrderData(address sponsor_, uint96 nonce_, OrderDataGasless memory orderDataGasless_, bytes memory signature_) internal pure returns (OrderData memory orderData_) {
        orderData_ = OrderData({
            sponsor: sponsor_,
            nonce: nonce_,
            claimDeadline: orderDataGasless_.claimDeadline, 
            settlements: orderDataGasless_.settlements,
            arbiter: orderDataGasless_.arbiter,
            sponsorSignature: signature_
        });
        return orderData_;
    }
}
