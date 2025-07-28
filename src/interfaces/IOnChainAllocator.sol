// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

interface IOnChainAllocator is IAllocator {
    struct Allocation {
        uint32 expires;
        uint224 amount;
        bytes32 claimHash;
    }

    /// @notice Thrown if a claim is already active
    error ClaimActive(address sponsor);

    /// @notice Thrown if the caller is invalid
    error InvalidCaller(address caller, address expected);

    /// @notice Thrown if the nonce has already been consumed on the compact contract
    error NonceAlreadyInUse(uint256 nonce);

    /// @notice Thrown if the sponsor does not have enough balance to lock the amount
    error InsufficientBalance(address sponsor, uint256 id, uint256 balance, uint256 expectedBalance);

    /// @notice Thrown if the provided expiration is not valid
    error InvalidExpiration(uint256 expires, uint256 minExpiration);

    /// @notice Thrown if the expiration is longer then the tokens forced withdrawal time
    error ForceWithdrawalAvailable(uint256 expires, uint256 forcedWithdrawalExpiration);

    /// @notice Thrown if the allocator is not the one expected
    error InvalidAllocator(uint96 allocatorId, uint96 expectedAllocatorId);

    /// @notice Thrown if the provided lock is not available or expired
    error InvalidClaim(bytes32 claimHash);

    /// @notice Thrown if the current allocation is bigger then uint224
    /// @dev Allocations above uint224 do not support attestations
    error ExtensiveAllocationActive(address sponsor, uint256 id);

    /// @notice Thrown if the provided amount is not valid
    error InvalidAmount(uint256 amount);

    /// @notice Thrown if the provided signature is invalid
    error InvalidSignature(address signer, address expectedSigner);

    /// @notice Thrown if the claim hash is not registered on the compact
    error InvalidRegistration(address sponsor, bytes32 claimHash);

    /// @notice Emitted when a lock is successfully created
    /// @param sponsor The address of the sponsor
    /// @param claimHash The hash of the claim
    /// @param nonce The nonce of the claim
    /// @param expires The expiration of the claim
    /// @param commitments The commitments of the allocations
    event AllocationRegistered(
        address indexed sponsor, bytes32 indexed claimHash, uint256 indexed nonce, uint256 expires, Lock[] commitments
    );

    /// @notice Registers an allocation for a set of tokens
    /// @param commitments The commitments of the allocations
    /// @param arbiter The arbiter of the allocation
    /// @param expires The expiration of the allocation
    /// @param typehash The typehash of the allocation
    /// @param witness The witness of the allocation
    function allocate(Lock[] memory commitments, address arbiter, uint32 expires, bytes32 typehash, bytes32 witness)
        external
        returns (bytes32 claimHash, uint256 claimNonce);

    /// @notice Registers an allocation for a set of tokens on behalf of a sponsor
    /// @param sponsor The address of the sponsor
    /// @param commitments The commitments of the allocations
    /// @param arbiter The arbiter of the allocation
    /// @param expires The expiration of the allocation
    /// @param typehash The typehash of the allocation
    /// @param witness The witness of the allocation
    /// @param signature The signature of the allocation
    function allocateFor(
        address sponsor,
        Lock[] memory commitments,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata signature
    ) external returns (bytes32 claimHash, uint256 claimNonce);
}
