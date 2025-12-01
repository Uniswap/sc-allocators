// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {AllocatorLib as AL} from '../allocators/lib/AllocatorLib.sol';
import {ISignatureTransfer} from 'permit2/src/interfaces/ISignatureTransfer.sol';
import {IOnChainAllocation} from 'the-compact/src/interfaces/IOnChainAllocation.sol';
import {ITheCompact} from 'the-compact/src/interfaces/ITheCompact.sol';
import {CompactCategory} from 'the-compact/src/types/CompactCategory.sol';
import {DepositDetails} from 'the-compact/src/types/DepositDetails.sol';
import {
    BATCH_COMPACT_TYPEHASH,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_SIX,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
    LOCK_TYPEHASH
} from 'the-compact/src/types/EIP712Types.sol';

/// @title AllocationRouter
/// @notice Router for depositing, registering and allocating tokens to a given address in a single transaction.
contract AllocationRouter {
    // Storage slot seed for mapping allocator IDs to allocator addresses
    uint256 private constant _ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED = 0x000044036fc77deaed2300000000000000000000000;

    function depositRegisterAndAllocate(
        address sponsor,
        address arbiter,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        DepositDetails calldata details,
        bytes32 witnessHash,
        string calldata witness,
        bytes calldata signature
    ) external payable {
        // Get the allocator address directly from the compact and revert if allocator is address(0)
        address allocator = AL.getRegisteredAllocator(AL.splitAllocatorId(details.lockTag));

        // Prepare the ids and amounts
        uint256[2][] memory idsAndAmounts = new uint256[2][](permitted.length);
        bytes32[] memory commitmentHashes = new bytes32[](permitted.length);
        for (uint256 i = 0; i < permitted.length; i++) {
            uint256 id = AL.toId(details.lockTag, permitted[i].token);
            idsAndAmounts[i][0] = id;
            idsAndAmounts[i][1] = permitted[i].amount;

            // Lock struct encoding: (bytes12 lockTag, address token, uint256 amount)
            commitmentHashes[i] =
                keccak256(abi.encode(LOCK_TYPEHASH, details.lockTag, permitted[i].token, permitted[i].amount));
        }

        bytes32 typeHash = _computeTypehash(witness);

        // Prepare allocation
        uint256 nonce = IOnChainAllocation(allocator).prepareAllocation(
            sponsor, idsAndAmounts, arbiter, details.deadline, typeHash, witnessHash, ''
        );
        // The signature MUST validate a claim hash with the allocators nonce. The nonce can be different from details.nonce

        bytes32 claimHash = _computeClaimHash(typeHash, arbiter, sponsor, nonce, commitmentHashes, witnessHash, witness);

        // Deposit and register the tokens using permit2
        ITheCompact(AL.THE_COMPACT).batchDepositAndRegisterViaPermit2{value: msg.value}(
            sponsor, permitted, details, claimHash, CompactCategory.BatchCompact, witness, signature
        );

        // Execute allocation
        IOnChainAllocation(allocator).executeAllocation(
            sponsor, idsAndAmounts, arbiter, details.deadline, typeHash, witnessHash, ''
        );
    }

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
    ) external payable {
        // Prepare the ids and amounts
        uint256[2][] memory idsAndAmounts = new uint256[2][](permitted.length);
        for (uint256 i = 0; i < permitted.length; i++) {
            idsAndAmounts[i][0] = AL.toId(details.lockTag, permitted[i].token);
            idsAndAmounts[i][1] = permitted[i].amount;
        }

        // Prepare allocation
        IOnChainAllocation(allocator).prepareAllocation(
            sponsor, idsAndAmounts, arbiter, details.deadline, typeHash, witnessHash, ''
        );
        // The signature MUST validate a claim hash with the allocators nonce. The nonce can be different from details.nonce

        // Deposit and register the tokens using permit2
        ITheCompact(AL.THE_COMPACT).batchDepositAndRegisterViaPermit2{value: msg.value}(
            sponsor, permitted, details, claimHash, CompactCategory.BatchCompact, witness, signature
        );

        // Execute allocation
        IOnChainAllocation(allocator).executeAllocation(
            sponsor, idsAndAmounts, arbiter, details.deadline, typeHash, witnessHash, ''
        );
    }

    function _computeTypehash(string calldata witness) internal pure returns (bytes32 typeHash) {
        assembly ("memory-safe") {
            typeHash := BATCH_COMPACT_TYPEHASH
            if witness.length {
                let m := mload(0x40)
                mstore(m, BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE)
                mstore(add(m, 0x20), BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO)
                mstore(add(m, 0x40), BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE)
                mstore(add(m, 0x60), BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR)
                mstore(add(m, 0x88), BATCH_COMPACT_TYPESTRING_FRAGMENT_SIX)
                mstore(add(m, 0x80), BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE)
                let witnessStart := add(m, 0xa8)
                calldatacopy(witnessStart, witness.offset, witness.length)
                mstore8(add(witnessStart, witness.length), 0x29) // Closing parenthesis
                typeHash := keccak256(m, add(0xa9, witness.length))
            }
        }
    }

    function _computeClaimHash(
        bytes32 typeHash,
        address arbiter,
        address sponsor,
        uint256 nonce,
        bytes32[] memory commitmentHashes,
        bytes32 witnessHash,
        string calldata witness
    ) internal pure returns (bytes32 claimHash) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, typeHash)
            mstore(add(m, 0x20), arbiter)
            mstore(add(m, 0x40), sponsor)
            mstore(add(m, 0x60), nonce)
            calldatacopy(add(m, 0x80), 0x84, 0x20) // details.deadline
            mstore(add(m, 0xa0), keccak256(add(commitmentHashes, 0x20), mul(mload(commitmentHashes), 0x20))) // abi.encodePacked(commitmentHashes)
            mstore(add(m, 0xc0), witnessHash)
            claimHash := keccak256(m, sub(0xe0, mul(iszero(witness.length), 0x20))) // Exclude witnessHash for no-witness cases
        }
    }
}
