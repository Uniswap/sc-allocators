// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ISignatureTransfer} from 'permit2/src/interfaces/ISignatureTransfer.sol';
import {DepositDetails} from 'the-compact/src/types/DepositDetails.sol';

interface IAllocationRouter {
    /// @notice Deposits, registers and allocates tokens to a given address in a single transaction.
    /// @dev Calculates claim hash, type hash and allocator address internally.
    /// @param sponsor The address of the sponsor.
    /// @param arbiter The address of the arbiter.
    /// @param permitted The array of token permissions.
    /// @param details Includes the nonce, deadline and lock tag.
    /// @param witnessHash The hash of the witness.
    /// @param witness The witness string.
    /// @param signature The signature of the permit2 transfer.
    function depositRegisterAndAllocate(
        address sponsor,
        address arbiter,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        DepositDetails calldata details,
        bytes32 witnessHash,
        string calldata witness,
        bytes calldata signature
    ) external payable;

    /// @notice Deposits, registers and allocates tokens to a given address in a single transaction.
    /// @dev Uses provided claim hash, type hash and allocator address.
    /// @param sponsor The address of the sponsor.
    /// @param arbiter The address of the arbiter.
    /// @param permitted The array of token permissions.
    /// @param details Includes the nonce, deadline and lock tag.
    /// @param witnessHash The hash of the witness.
    /// @param witness The witness string.
    /// @param signature The signature of the permit2 transfer.
    /// @param claimHash The hash of the claim registered in the compact. Claim nonce must match the expected allocator nonce.
    /// @param allocator The address of the allocator contract.
    /// @param typeHash The type hash of the batch compact.
    function depositRegisterAndAllocate(
        address sponsor,
        address arbiter,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        DepositDetails calldata details,
        bytes32 witnessHash,
        string calldata witness,
        bytes calldata signature,
        bytes32 claimHash,
        address allocator,
        bytes32 typeHash
    ) external payable;
}
