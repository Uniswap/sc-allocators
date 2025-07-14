// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOriginSettler} from './ERC7683/IOriginSettler.sol';

interface IERC7683Allocator is IOriginSettler {
    struct OrderData {
        // COMPACT
        address arbiter; // The account tasked with verifying and submitting the claim.
        address sponsor; // The account to source the tokens from.
        uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires; // The time at which the claim expires.
        bytes12 lockTag; // The token ID of the ERC6909 token to allocate.
        address inputToken; // The token address of the ERC6909 token to allocate.
        uint256 amount; // The amount of ERC6909 tokens to allocate.
        // MANDATE
        uint256 chainId; // (implicit arg, included in EIP712 payload)
        address tribunal; // (implicit arg, included in EIP712 payload)
        address recipient; // Recipient of settled tokens
        // uint256 expires; // Mandate expiration timestamp
        address settlementToken; // Settlement token (address(0) for native)
        uint256 minimumAmount; // Minimum settlement amount
        uint256 baselinePriorityFee; // Base fee threshold where scaling kicks in
        uint256 scalingFactor; // Fee scaling multiplier (1e18 baseline)
        uint256[] decayCurve; // Block durations, fill increases, & claim decreases.
        bytes32 salt; // Replay protection parameter
        // ADDITIONAL INPUT
        uint256 targetBlock; // The block number at the target chain on which the PGA is executed / the reverse dutch auction starts.
        uint256 maximumBlocksAfterTarget; // Blocks after target block that are still fillable.
    }

    struct OrderDataGasless {
        // COMPACT
        address arbiter; // The account tasked with verifying and submitting the claim.
        // address sponsor; // The account to source the tokens from.
        // uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
        // uint256 expires; // The time at which the claim expires.
        bytes12 lockTag; // The lock tag of the ERC6909 token to allocate.
        address inputToken; // The token address of the ERC6909 token to allocate.
        uint256 amount; // The amount of ERC6909 tokens to allocate.
        // MANDATE
        uint256 chainId; // (implicit arg, included in EIP712 payload)
        address tribunal; // (implicit arg, included in EIP712 payload)
        address recipient; // Recipient of settled tokens
        // uint256 expires; // Mandate expiration timestamp
        address settlementToken; // Settlement token (address(0) for native)
        uint256 minimumAmount; // Minimum settlement amount
        uint256 baselinePriorityFee; // Base fee threshold where scaling kicks in
        uint256 scalingFactor; // Fee scaling multiplier (1e18 baseline)
        uint256[] decayCurve; // Block durations, fill increases, & claim decreases.
        bytes32 salt; // Replay protection parameter
    }

    struct OderDataCallback {
        // COMPACT
        // address arbiter; // The account tasked with verifying and submitting the claim.
        // address sponsor; // The account to source the tokens from.
        // uint256 nonce; // A parameter to enforce replay protection, scoped to allocator.
        // uint256 expires; // The time at which the claim expires.
        // uint256 id; // The token ID of the ERC6909 token to allocate.
        // uint256 amount; // The amount of ERC6909 tokens to allocate.
        // MANDATE
        uint256 chainId; // (implicit arg, included in EIP712 payload)
        address tribunal; // (implicit arg, included in EIP712 payload)
        address recipient; // Recipient of settled tokens
        uint256 expires; // Mandate expiration timestamp
        address settlementToken; // Settlement token (address(0) for native)
        uint256 minimumAmount; // Minimum settlement amount
        uint256 baselinePriorityFee; // Base fee threshold where scaling kicks in
        uint256 scalingFactor; // Fee scaling multiplier (1e18 baseline)
        uint256[] decayCurve; // Block durations, fill increases, & claim decreases.
        bytes32 salt; // Replay protection parameter
        // ADDITIONAL INPUT
        uint256 targetBlock; // The block number at the target chain on which the PGA is executed / the reverse dutch auction starts.
        uint256 maximumBlocksAfterTarget; // Blocks after target block that are still fillable.
    }

    error InvalidOriginSettler(address originSettler, address expectedOriginSettler);
    error InvalidOrderDataType(bytes32 orderDataType, bytes32 expectedOrderDataType);
    error InvalidNonce(uint256 nonce);
    error InvalidSignature(address signer, address expectedSigner);
    error InvalidRegistration(address sponsor, bytes32 claimHash);
    error BatchCompactsNotSupported();

    /// @inheritdoc IOriginSettler
    function openFor(GaslessCrossChainOrder calldata order, bytes calldata signature, bytes calldata originFillerData)
        external;

    /// @inheritdoc IOriginSettler
    /// @dev Requires the user to have previously registered the claim hash on the compact
    function open(OnchainCrossChainOrder calldata order) external;

    /// @inheritdoc IOriginSettler
    function resolveFor(GaslessCrossChainOrder calldata order, bytes calldata originFillerData)
        external
        view
        returns (ResolvedCrossChainOrder memory);

    /// @inheritdoc IOriginSettler
    function resolve(OnchainCrossChainOrder calldata order) external view returns (ResolvedCrossChainOrder memory);

    /// @notice Returns the type string of the compact including the witness
    function getCompactWitnessTypeString() external pure returns (string memory);

    /// @notice Checks if a nonce is free to be used
    /// @dev The nonce is the most significant 96 bits. The least significant 160 bits must be the sponsor address
    function checkNonce(uint256 nonce_, address sponsor_) external view returns (bool nonceFree_);

    /// @notice Creates the filler data for the open event to be used on the IDestinationSettler
    /// @param claimant_ The address claiming the origin tokens after a successful fill (typically the address of the filler)
    function createFillerData(address claimant_) external pure returns (bytes memory fillerData);
}
