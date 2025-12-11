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
    error InvalidAllocatorRegistration(address alreadyRegisteredAllocator);
    error Unsupported();
    error InvalidIds();
    error InvalidAllocatorId(uint96 allocatorId, uint96 expectedAllocatorId);
    error InvalidCaller(address sender, address expectedSender);
    error InvalidSignature();
    error InvalidSigner();
    error CallerNotSigner();
    error LastSigner();
    error InvalidValue(uint256 value, uint256 expectedValue);

    /**
     * @notice Add an offchain signer to the allocator.
     * @param signer_ The address of the signer to add.
     */
    function addSigner(address signer_) external;

    /**
     * @notice Remove an offchain signer from the allocator.
     * @dev The last signer cannot be removed.
     * @param signer_ The address of the signer to remove.
     */
    function removeSigner(address signer_) external;

    /**
     * @notice Replace an offchain signer with a new one.
     * @dev The caller must be the replaced signer.
     * @param newSigner_ The address of the new signer.
     */
    function replaceSigner(address newSigner_) external;

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

    /// @notice Deposits, registers and allocates a claim via Permit2 signature transfer
    /// @dev Deposits the tokens subject to the order and registers the claim directly with the compact, then allocates the claim
    /// @param arbiter The arbiter of the allocation
    /// @param depositor The address depositing tokens and the sponsor of the claim (must sign the Permit2 message)
    /// @param permitted The token permissions for the Permit2 transfer. Must match the commitments in the claim
    /// @param details The deposit details including nonce, deadline, and lock tag
    ///                Nonce must match the nonce structure expected by the allocator
    ///                Deadline will be used as the expiration of the claim
    /// @param claimHash The hash of the claim to register. Must match the claim hash recreated by the allocator
    /// @param witness The witness typestring for the Permit2 signature (empty string if no witness)
    /// @param witnessHash The hash of the witness data (bytes32(0) if no witness)
    /// @param signature The Permit2 signature from the depositor, will be verified by the compact
    /// @return commitments The lock commitments created by the allocation
    function permit2Allocation(
        address arbiter,
        address depositor,
        uint256 expires,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        DepositDetails calldata details,
        bytes32 claimHash,
        string calldata witness,
        bytes32 witnessHash,
        bytes calldata signature
    ) external returns (Lock[] memory commitments);
}
