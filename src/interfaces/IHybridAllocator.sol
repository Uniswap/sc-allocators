// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IOnChainAllocation} from '@uniswap/the-compact/interfaces/IOnChainAllocation.sol';
import {DepositDetails} from '@uniswap/the-compact/types/DepositDetails.sol';
import {Lock} from '@uniswap/the-compact/types/EIP712Types.sol';
import {ISignatureTransfer} from 'permit2/src/interfaces/ISignatureTransfer.sol';

/// @title IHybridAllocator
/// @notice Interface for hybrid allocators supporting both on-chain and off-chain authorization mechanisms
/// @dev Combines direct token deposit functionality with signature-based off-chain allocation authorization
interface IHybridAllocator is IOnChainAllocation {
    struct HybridAllocationContext {
        uint256 nonce; // MUST start with the off chain command, followed by the sponsors address
        bytes signature;
    }

    error InvalidAllocatorRegistration(address alreadyRegisteredAllocator);
    error Unsupported();
    error InvalidIds();
    error InvalidAllocatorId(uint96 allocatorId, uint96 expectedAllocatorId);
    error InvalidCaller(address sender, address expectedSender);
    error InvalidSignature();
    error InvalidOwner();
    error InvalidSigner();
    error CallerNotOwner();
    error InvalidValue(uint256 value, uint256 expectedValue);
    error AttestationExpired();
    error InsufficientAttestationAmount(uint256 availableAmount, uint256 requestedAmount);

    /**
     * @notice Add an offchain signer to the allocator.
     * @param signer_ The address of the signer to add.
     * @dev The caller must be the owner.
     */
    function addSigner(address signer_) external;

    /**
     * @notice Remove an offchain signer from the allocator.
     * @dev The caller must be the owner.
     * @param signer_ The address of the signer to remove.
     */
    function removeSigner(address signer_) external;

    /**
     * @notice Replace an offchain signer with a new one.
     * @dev The caller must be the owner.
     * @param oldSigner_ The address of the old signer.
     * @param newSigner_ The address of the new signer.
     */
    function replaceSigner(address oldSigner_, address newSigner_) external;

    /**
     * @notice Propose a new owner for the allocator.
     * @dev The caller must be the current owner.
     * @param newOwner_ The address of the new owner.
     */
    function proposeOwnerReplacement(address newOwner_) external;

    /**
     * @notice Accept the ownership replacement.
     * @dev The caller must be the new (pending) owner.
     */
    function acceptOwnerReplacement() external;

    /**
     * @notice Authorizes an attestation for a subsequent ERC6909 transfer. The attestation is
     * stored in transient storage and consumed when the corresponding attest function is called.
     * @param sponsor The address of the sponsor.
     * @param nonce The nonce of the attestation.
     * @param expires The expiration time of the attestation.
     * @param commitments The commitments to authorize.
     * @param allocatorSignature The signature of the allocator.
     */
    function authorizeAttestation(
        address sponsor,
        uint256 nonce,
        uint256 expires,
        Lock[] calldata commitments,
        bytes calldata allocatorSignature
    ) external returns (bool authorized);

    /**
     * @notice Create an allocation and a registration on the compact by depositing the relevant tokens to the compact.
     * @dev If the provided amounts are zero, the contract will use its own token balance.
     * @param recipient The address receiving the deposited tokens and the sponsor of the compact.
     * @param idsAndAmounts The IDs and amounts of the tokens to register. Amounts can be zero.
     * @param arbiter The address of the arbiter for the compact.
     * @param expires The expiration time of the compact.
     * @param typehash The typehash of the compact.
     * @param witness The witness of the compact.
     * @return The claim hash, the registered amounts, and the nonce.
     */
    function allocateAndRegister(
        address recipient,
        uint256[2][] memory idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external payable returns (bytes32, uint256[] memory, uint256);
}
