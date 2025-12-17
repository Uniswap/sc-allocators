// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC6909} from '@solady/tokens/ERC6909.sol';

import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {
    BATCH_COMPACT_TYPEHASH,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FIVE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_FOUR,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_ONE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_SIX,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_THREE,
    BATCH_COMPACT_TYPESTRING_FRAGMENT_TWO,
    LOCK_TYPEHASH,
    Lock
} from '@uniswap/the-compact/types/EIP712Types.sol';
import {ISignatureTransfer} from 'permit2/src/interfaces/ISignatureTransfer.sol';

import {CompactCategory} from 'the-compact/src/types/CompactCategory.sol';
import {DepositDetails} from 'the-compact/src/types/DepositDetails.sol';

/// @title AllocatorLib
/// @notice Library providing core functionality for atomic token allocation verification using transient storage
/// @dev Implements prepare-execute pattern for ensuring token balance changes match expected allocations
/// @custom:security-contact security@uniswap.org
library AllocatorLib {
    address internal constant THE_COMPACT = 0x00000000000000171ede64904551eeDF3C6C9788;

    /// @notice Function selector for the prepareAllocation function, used as part of transient storage key derivation
    /// @dev bytes4(keccak256('prepareAllocation(address,uint256[2][],address,uint256,bytes32,bytes32,bytes)'))
    bytes4 public constant PREPARE_ALLOCATION_SELECTOR = 0x7ef6597a;

    /// @notice Function selector for the exttload function that gets called on the compact
    /// @dev bytes4(keccak256('exttload(bytes32)'))
    uint256 private constant EXTTLOAD_SELECTOR = 0xf135baaa;

    /// @notice Function selector for the extsload function that gets a value in transient storage
    /// @dev bytes4(keccak256('extsload(bytes32)'))
    uint256 private constant EXTSLOAD_SELECTOR = 0x1e2eaeaf;

    /// @notice Transient storage slot for the reentrancy guard within the compact
    uint256 private constant REENTRANCY_GUARD_SLOT = 0x929eee149b4bd21268;

    /// @notice Storage slot seed on the compact for mapping allocator IDs to allocator addresses.
    uint256 private constant ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED = 0x000044036fc77deaed2300000000000000000000000;

    /// @notice The command indicating an on chain nonce
    bytes1 internal constant ON_CHAIN_NONCE = 0x01;

    /// @notice The command indicating an off chain nonce
    bytes1 internal constant OFF_CHAIN_NONCE = 0x02;

    /// @notice The command indicating a permit2 nonce
    bytes1 internal constant PERMIT2_NONCE = 0x03;

    bytes1 internal constant NONCE_COMMAND_MASK = 0xff;

    error InvalidBalanceForAdditionalCommitments(uint256 availableBalance, uint256 expectedBalance);
    error InvalidAdditionalCommitmentsLength(uint256 providedLength, uint256 expectedLength);
    error InvalidBalanceChange(uint256 newBalance, uint256 oldBalance);
    error InvalidPreparation();
    error InvalidAllocatorId(uint96 providedId, uint96 allocatorId);
    error InvalidRegistration(address recipient, bytes32 claimHash, bytes32 typehash);
    error CompactReentrancyGuardActive();
    error InvalidAllocator();
    error UnauthorizedNonce(bytes1 command, address sponsor);
    error InvalidCompactCall(address theCompact);
    error InvalidClaim(bytes32 claimHash);

    function permit2Allocation(
        address arbiter,
        address depositor,
        uint256 expires,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        uint256[] calldata additionalCommitmentAmounts,
        DepositDetails calldata details,
        bytes32 claimHash, // This claim hash is connected to the allocation. This does not guarantee, that the allocated tokens are connected to the claim hash.
        string calldata witness,
        bytes32 witnessHash,
        bytes calldata signature
    )
        internal
        returns (Lock[] memory commitments, uint256[] memory previousBalances, bool containsAdditionalCommitments)
    {
        // Ensure the additional commitment amounts are the correct length
        checkAdditionalCommitmentsAndRevert(permitted.length, additionalCommitmentAmounts);

        // Verifying the nonce is scoped to a permit2 allocation and to the sponsor
        verifyNonce(details.nonce, PERMIT2_NONCE, depositor);
        // We can now trust permit2 to burn the nonce and prevent replay attacks

        commitments = new Lock[](permitted.length);
        previousBalances = new uint256[](permitted.length);

        bytes12 lockTag = details.lockTag;

        // Prepare allocation
        assembly ("memory-safe") {
            let m := mload(0x40) // Store the memory pointer. Will be dirtied and restored at the end of the function.

            // Memory layout for Lock[]:
            // - commitments + 0x00: length (permittedLength)
            // - commitments + 0x20: absolute pointer to the Lock struct [0]
            // - commitments + 0x40: absolute pointer to the Lock struct [1]
            // - commitments + 0x60: lockTag[0]
            // - commitments + 0x80: token[0]
            // - commitments + 0xa0: amount[0]
            // - commitments + 0xc0: lockTag[1]
            // - ...
            let permittedLength := permitted.length
            let commitmentsContent := add(commitments, 0x20)

            mstore(0x14, depositor) // Store the `owner` as the first argument for the balanceOf call.
            mstore(0x00, 0x00fdd58e000000000000000000000000) // function selector of `balanceOf(address,uint256)`.

            for { let i := 0 } lt(i, permittedLength) { i := add(i, 1) } {
                let token := calldataload(add(permitted.offset, mul(i, 0x40)))

                // Store the lockTag and token in the Lock struct
                let commitmentMemLoc := mload(add(commitmentsContent, mul(i, 0x20))) // load the absolute pointer to the Lock struct
                mstore(commitmentMemLoc, lockTag) // lockTag
                mstore(add(commitmentMemLoc, 0x20), token) // token

                // Store the id as the second argument for the balanceOf call.
                mstore(0x34, or(lockTag, token))

                // Retrieve and store the current balance of the depositor into the amount slot (temporarily)
                let commitmentAmountMemLoc := add(commitmentMemLoc, 0x40)

                if iszero(staticcall(gas(), THE_COMPACT, 0x10, 0x44, commitmentAmountMemLoc, 0x20)) {
                    mstore(0x00, 0x6d728277) // InvalidCompactCall(address theCompact)
                    mstore(0x20, THE_COMPACT)
                    revert(0x1c, 0x24)
                }
            }

            // Deposit and register the tokens using permit2
            mstore(add(m, 0x20), depositor)
            mstore(add(m, 0x0c), 0x45ebe218000000000000000000000000) // function selector of `batchDepositAndRegisterViaPermit2()`.
            mstore(add(m, 0x40), 0x120) // Store the offset for the permitted
            calldatacopy(add(m, 0x60), details, 0x60) // Store the details from calldata to memory
            mstore(add(m, 0xc0), claimHash)
            mstore(add(m, 0xe0), 0x01) // uint8(CompactCategory.BatchCompact)
            let witnessOffset := add(0x140, mul(permittedLength, 0x40))
            mstore(add(m, 0x100), witnessOffset)
            let signatureOffset := add(add(witnessOffset, 0x20), and(add(witness.length, 31), not(31))) // round up to the nearest multiple of 32
            mstore(add(m, 0x120), signatureOffset)
            // store permitted length & contents to memory
            mstore(add(m, 0x140), permittedLength)
            calldatacopy(add(m, 0x160), permitted.offset, mul(permittedLength, 0x40))
            // store witness contents to memory
            let witnessMemLoc := add(m, add(0x20, witnessOffset)) // Add 0x20 to skip the function selector
            mstore(witnessMemLoc, witness.length)
            calldatacopy(add(witnessMemLoc, 0x20), witness.offset, witness.length)
            // store signature contents to memory
            let signatureMemLoc := add(m, add(0x20, signatureOffset))
            mstore(signatureMemLoc, signature.length)
            calldatacopy(add(signatureMemLoc, 0x20), signature.offset, signature.length)
            let fullCallDataSize := add(add(signatureOffset, 0x24), and(add(signature.length, 31), not(31)))

            // Call the batchDepositAndRegisterViaPermit2 function and revert if it fails
            if iszero(call(gas(), THE_COMPACT, callvalue(), add(m, 0x1c), fullCallDataSize, 0, 0)) {
                mstore(0x00, 0x6d728277) // InvalidCompactCall(address theCompact)
                mstore(0x20, THE_COMPACT)
                revert(0x1c, 0x24)
            }

            let previousBalancesPointer := add(previousBalances, 0x20)

            // Confirm the allocation - calculate balance differences
            for { let i := 0 } lt(i, permittedLength) { i := add(i, 1) } {
                let commitmentMemLoc := mload(add(commitmentsContent, mul(i, 0x20))) // load the absolute pointer to the Lock struct
                // Reconstruct id from stored lockTag and token
                let token := mload(add(commitmentMemLoc, 0x20))

                let commitmentAmountMemLoc := add(commitmentMemLoc, 0x40)
                let oldBalance := mload(commitmentAmountMemLoc)

                // Store the id as the second argument for the balanceOf call.
                mstore(0x34, or(lockTag, token))

                // Retrieve the new balance of the depositor and store it in the amount slot of the commitment
                if iszero(staticcall(gas(), THE_COMPACT, 0x10, 0x44, commitmentAmountMemLoc, 0x20)) {
                    mstore(0x00, 0x6d728277) // InvalidCompactCall(address theCompact)
                    mstore(0x20, THE_COMPACT)
                    revert(0x1c, 0x24)
                }

                let currentBalance := mload(commitmentAmountMemLoc)
                if iszero(gt(currentBalance, oldBalance)) {
                    mstore(0x00, 0x9f2aec67) // InvalidBalanceChange()
                    mstore(0x20, currentBalance)
                    mstore(0x40, oldBalance)
                    revert(0x1c, 0x44)
                }
                let diffBalance := sub(currentBalance, oldBalance)

                let additionalCommitmentAmount := calldataload(add(additionalCommitmentAmounts.offset, mul(i, 0x20)))
                if gt(additionalCommitmentAmount, oldBalance) {
                    /// @dev This is NOT a sufficient check to guarantee the user has enough unallocated tokens available for the additional commitment.
                    ///      The additional committed amounts MUST be verified by the implementation of the allocator library before or after this function is called.
                    ///      This check will only be used to check if enough tokens are generally available to cover the additional commitment,
                    ///      not if those available tokens are actually unallocated.

                    mstore(0x00, 0x9a534c61) // InvalidBalanceForAdditionalCommitments()
                    mstore(0x20, oldBalance)
                    mstore(0x40, additionalCommitmentAmount)
                    revert(0x1c, 0x44)
                }

                // Store the old balance in the previousBalances array
                mstore(add(previousBalancesPointer, mul(i, 0x20)), oldBalance)

                // Add the additional commitment amount to the difference in balance. This amount must be verifiably unallocated.
                diffBalance := add(diffBalance, additionalCommitmentAmount)

                // Set the containsAdditionalCommitments flag if the additional commitment amount is not zero
                containsAdditionalCommitments := or(containsAdditionalCommitments, gt(additionalCommitmentAmount, 0))

                // Update the amount in the Lock struct with the balance difference
                mstore(commitmentAmountMemLoc, diffBalance)
            }

            mstore(0x40, m) // Restore the memory pointer
        }

        // Verify the claim hash includes proposed expiration
        if (
            claimHash
                != getClaimHash(
                    arbiter,
                    depositor,
                    details.nonce,
                    expires,
                    getCommitmentsHashMemory(commitments),
                    witnessHash,
                    computeBatchCompactTypehash(witness)
                )
        ) {
            revert InvalidClaim(claimHash);
        }

        return (commitments, previousBalances, containsAdditionalCommitments);
    }

    function prepareAllocation(
        uint256 nonce,
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        uint256[] calldata additionalCommitmentAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        uint96 allocatorId
    ) internal {
        // Ensure the additional commitment amounts are the correct length
        checkAdditionalCommitmentsAndRevert(idsAndAmounts.length, additionalCommitmentAmounts);
        // Before preparing the allocation, check if the compact's reentrancy guard is active
        checkCompactReentrancyGuardAndRevert();

        assembly ("memory-safe") {
            // identifier = keccak256(abi.encode(PREPARE_ALLOCATION_SELECTOR, recipient, ids, arbiter, expires, typehash, witness));
            let memoryPointer := mload(0x40)
            mstore(add(memoryPointer, 0x00), PREPARE_ALLOCATION_SELECTOR)
            mstore(add(memoryPointer, 0x20), recipient)
            mstore(add(memoryPointer, 0x40), 0xe0) // Store the offset for the ids
            mstore(add(memoryPointer, 0x60), arbiter)
            mstore(add(memoryPointer, 0x80), expires)
            mstore(add(memoryPointer, 0xa0), typehash)
            mstore(add(memoryPointer, 0xc0), witness)

            mstore(add(memoryPointer, 0xe0), idsAndAmounts.length) // Store the length of the ids

            for { let i := 0 } lt(i, idsAndAmounts.length) { i := add(i, 1) } {
                let id := calldataload(add(idsAndAmounts.offset, mul(i, 0x40)))

                // Verify the id fits the allocator
                if iszero(eq(shr(164, shl(4, id)), allocatorId)) {
                    mstore(0x00, 0x8bbfd798) // InvalidAllocatorId()
                    mstore(0x20, shr(164, shl(4, id)))
                    mstore(0x40, allocatorId)
                    revert(0x1c, 0x44)
                }

                // Retrieve and store the current balance of the recipient in transient storage
                mstore(0x14, recipient) // Store the `owner` argument.
                mstore(0x34, id)
                mstore(0x00, 0x00fdd58e000000000000000000000000) // `balanceOf(address,uint256)`.
                let currentBalance :=
                    mul( // The arguments of `mul` are evaluated from right to left.
                        mload(0x20),
                        and( // The arguments of `and` are evaluated from right to left.
                            gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                            staticcall(gas(), THE_COMPACT, 0x10, 0x44, 0x20, 0x20)
                        )
                    )

                // Verify the current balance is sufficient for the additional commitment amounts
                let additionalCommitmentAmount := calldataload(add(additionalCommitmentAmounts.offset, mul(i, 0x20)))
                if gt(additionalCommitmentAmount, currentBalance) {
                    /// @dev This is NOT a sufficient check to guarantee the user has enough unallocated tokens available for the additional commitment.
                    ///      The additional committed amounts MUST be verified by the implementation of the allocator library during the execution.
                    ///      This check will only be used to check if enough tokens are generally available to cover the additional commitment,
                    ///      not if those available tokens are actually unallocated.

                    mstore(0x00, 0x9a534c61) // InvalidBalanceForAdditionalCommitments()
                    mstore(0x20, currentBalance)
                    mstore(0x40, additionalCommitmentAmount)
                    revert(0x1c, 0x44)
                }

                mstore(0x00, PREPARE_ALLOCATION_SELECTOR)
                mstore(0x20, recipient)
                mstore(0x40, id)
                // Store the current balance in transient storage
                tstore(keccak256(0x00, 0x60), currentBalance)

                // store the id for the identifier creation
                mstore(add(add(memoryPointer, 0x100), mul(i, 0x20)), id)
            }

            // Derive the identifier for the transient storage slot to store the nonce
            let identifier := keccak256(memoryPointer, add(0x100, mul(idsAndAmounts.length, 0x20)))
            // Store the nonce for the identifier to ensure the same data is used in `executeAllocation` and protect against replay attacks
            tstore(identifier, nonce)

            // Reset the dirtied memory pointer
            mstore(0x40, memoryPointer) // Store the memory pointer for the identifier creation
        }
    }

    /// @dev Additional commitment amounts MUST be unallocated, which IS NOT verified by this library.
    function executeAllocation(
        uint256 nonce,
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        uint256[] calldata additionalCommitmentAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    )
        internal
        view
        returns (
            bytes32 claimHash,
            Lock[] memory commitments,
            uint256[] memory previousBalances,
            bool containsAdditionalCommitments
        )
    {
        commitments = new Lock[](idsAndAmounts.length);
        previousBalances = new uint256[](idsAndAmounts.length);

        bytes32[] memory commitmentHashes = new bytes32[](idsAndAmounts.length);
        bytes32 commitmentsHash;
        uint256 storedNonce;

        // Ensure the additional commitment amounts are the correct length
        checkAdditionalCommitmentsAndRevert(idsAndAmounts.length, additionalCommitmentAmounts);

        // Before executing the allocation, check if the compact's reentrancy guard is active
        checkCompactReentrancyGuardAndRevert();

        assembly ("memory-safe") {
            // identifier = keccak256(abi.encode(PREPARE_ALLOCATION_SELECTOR, recipient, ids, arbiter, expires, typehash, witness));
            let memoryPointer := mload(0x40)
            mstore(add(memoryPointer, 0x00), PREPARE_ALLOCATION_SELECTOR)
            mstore(add(memoryPointer, 0x20), recipient)
            mstore(add(memoryPointer, 0x40), 0xe0) // Store the offset for the ids
            mstore(add(memoryPointer, 0x60), arbiter)
            mstore(add(memoryPointer, 0x80), expires)
            mstore(add(memoryPointer, 0xa0), typehash)
            mstore(add(memoryPointer, 0xc0), witness)

            mstore(add(memoryPointer, 0xe0), idsAndAmounts.length) // Store the length of the ids

            let freeSlots := add(add(memoryPointer, 0x100), mul(idsAndAmounts.length, 0x20))
            mstore(freeSlots, LOCK_TYPEHASH) // Store the typehash for the commitment hash creation

            let previousBalancesPointer := add(previousBalances, 0x20)

            for { let i := 0 } lt(i, idsAndAmounts.length) { i := add(i, 1) } {
                let id := calldataload(add(idsAndAmounts.offset, mul(i, 0x40)))
                // store the id for the identifier creation
                mstore(add(add(memoryPointer, 0x100), mul(i, 0x20)), id)

                // Retrieve and store the current balance of the recipient in transient storage
                mstore(0x14, recipient) // Store the `owner` argument.
                mstore(0x34, id)
                mstore(0x00, 0x00fdd58e000000000000000000000000) // `balanceOf(address,uint256)`.
                let currentBalance :=
                    mul( // The arguments of `mul` are evaluated from right to left.
                        mload(0x20),
                        and( // The arguments of `and` are evaluated from right to left.
                            gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                            staticcall(gas(), THE_COMPACT, 0x10, 0x44, 0x20, 0x20)
                        )
                    )
                mstore(0x00, PREPARE_ALLOCATION_SELECTOR)
                mstore(0x20, recipient)
                mstore(0x40, id)
                // Read the old balance from transient storage
                let oldBalance := tload(keccak256(0x00, 0x60))
                if iszero(gt(currentBalance, oldBalance)) {
                    mstore(0x00, 0x9f2aec67) // InvalidBalanceChange()
                    mstore(0x20, currentBalance)
                    mstore(0x40, oldBalance)
                    revert(0x1c, 0x44)
                }
                let diffBalance := sub(currentBalance, oldBalance)

                let additionalCommitmentAmount := calldataload(add(additionalCommitmentAmounts.offset, mul(i, 0x20)))
                if gt(additionalCommitmentAmount, oldBalance) {
                    /// @dev This is NOT a sufficient check to guarantee the user has enough unallocated tokens available for the additional commitment.
                    ///      The additional committed amounts MUST be verified by the implementation of the allocator library.
                    ///      This check will only be used to check if enough tokens are generally available to cover the additional commitment,
                    ///      not if those available tokens are actually unallocated.

                    mstore(0x00, 0x9a534c61) // InvalidBalanceForAdditionalCommitments()
                    mstore(0x20, currentBalance)
                    mstore(0x40, diffBalance)
                    revert(0x1c, 0x44)
                }

                // Store the old balance in the previousBalances array
                mstore(add(previousBalancesPointer, mul(i, 0x20)), oldBalance)

                // Add the additional commitment amount.
                diffBalance := add(diffBalance, additionalCommitmentAmount)

                // Set the containsAdditionalCommitments flag if the additional commitment amount is not zero
                containsAdditionalCommitments := or(containsAdditionalCommitments, gt(additionalCommitmentAmount, 0))

                // Store the commitment
                let commitmentOffset := add(add(commitments, 0x20 /* skip length */ ), mul(i, 0x20))
                let commitmentContent :=
                    add(
                        add(commitments, 0x20 /* skip length */ ),
                        add(mul(idsAndAmounts.length, 0x20 /* skip offsets */ ), mul(i, 0x60))
                    )
                // Store the offset for the commitment in the Lock array
                mstore(commitmentOffset, commitmentContent) // lockTag
                // Store the actual Lock struct
                mstore(add(commitmentContent, 0x00), id) // lockTag
                mstore(add(commitmentContent, 0x20), id) // token
                mstore(add(commitmentContent, 0x0c), 0x00) // empty word to separate lockTag and token
                mstore(add(commitmentContent, 0x40), diffBalance) // amount

                // Create the commitment hash
                mstore(add(freeSlots, 0x20), id) // lockTag
                mstore(add(freeSlots, 0x40), id) // token
                mstore(add(freeSlots, 0x2c), 0) // empty word to separate lockTag and token
                mstore(add(freeSlots, 0x60), diffBalance) // amount
                mstore(add(add(commitmentHashes, 0x20 /* skip length */ ), mul(i, 0x20)), keccak256(freeSlots, 0x80))
            }

            // Derive the identifier for the transient storage slot to store the nonce
            let identifier := keccak256(memoryPointer, add(0x100, mul(idsAndAmounts.length, 0x20)))
            // Store the nonce for the identifier to ensure the same data is used in `executeAllocation` and protect against replay attacks
            storedNonce := tload(identifier)
            if xor(storedNonce, nonce) {
                mstore(0x00, 0xf3c41a04) // InvalidPreparation()
                revert(0x1c, 0x04)
            }

            // keccak256(abi.encodePacked(commitmentHashes))
            commitmentsHash :=
                keccak256(add(commitmentHashes, 0x20 /* skip length */ ), mul(idsAndAmounts.length, 0x20))

            // Reset the dirtied memory pointer
            mstore(0x40, memoryPointer) // Store the memory pointer for the identifier creation
        }

        // Check for a valid registration with the actual data
        claimHash = getClaimHash(arbiter, recipient, storedNonce, expires, commitmentsHash, witness, typehash);
        if (!ITheCompact(THE_COMPACT).isRegistered(recipient, claimHash, typehash)) {
            revert InvalidRegistration(recipient, claimHash, typehash);
        }
        return (claimHash, commitments, previousBalances, containsAdditionalCommitments);
    }

    function checkCompactReentrancyGuardAndRevert() internal view {
        assembly ("memory-safe") {
            mstore(0x00, EXTTLOAD_SELECTOR)
            mstore(0x20, REENTRANCY_GUARD_SLOT)
            if gt(
                or( // The arguments of `or` are evaluated from right to left.
                    mload(0x20),
                    mul(
                        2, // will end up as zero if the call is successful, else the 2 will trigger the revert.
                        iszero(
                            and(
                                gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                                staticcall(gas(), THE_COMPACT, 0x1c, 0x24, 0x20, 0x20)
                            )
                        )
                    )
                ),
                1 // A failing call or a successful call with a value of 1 will trigger the revert.
            ) {
                // revert CompactReentrancyGuardActive()
                mstore(0, 0x87621186)
                revert(0x1c, 0x04)
            }
        }
    }

    function checkAdditionalCommitmentsAndRevert(uint256 target, uint256[] calldata additionalCommitmentAmounts)
        private
        pure
    {
        assembly ("memory-safe") {
            let additionalCommitmentAmountsLength := additionalCommitmentAmounts.length
            if iszero(eq(target, additionalCommitmentAmountsLength)) {
                mstore(0x00, 0x81c2fd0e) // InvalidAdditionalCommitmentsLength()
                mstore(0x20, additionalCommitmentAmountsLength)
                mstore(0x40, target)
                revert(0x1c, 0x44)
            }
        }
    }

    function getRegisteredAllocator(uint96 allocatorId) internal view returns (address allocator) {
        assembly ("memory-safe") {
            mstore(0x00, EXTSLOAD_SELECTOR)
            mstore(0x20, or(ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED, allocatorId))

            if iszero(
                mul(
                    mload(0x20),
                    and(
                        gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                        staticcall(gas(), THE_COMPACT, 0x1c, 0x24, 0x20, 0x20)
                    )
                )
            ) {
                // revert InvalidAllocator()
                mstore(0x00, 0x59dad761)
                revert(0x1c, 0x04)
            }

            allocator := mload(0x20)
        }
    }

    function getCommitmentsHash(Lock[] calldata commitments, bytes32 typehash)
        internal
        pure
        returns (bytes32 commitmentsHash)
    {
        bytes32[] memory commitmentsHashes = new bytes32[](commitments.length);

        assembly ("memory-safe") {
            let memoryPointer := mload(0x40)
            mstore(memoryPointer, typehash) // store once to reuse typehash

            for { let i := 0 } lt(i, commitments.length) { i := add(i, 1) } {
                let commitmentOffset := add(commitments.offset, mul(i, 0x60))
                mstore(add(memoryPointer, 0x20), calldataload(commitmentOffset)) // lockTag
                mstore(add(memoryPointer, 0x40), calldataload(add(commitmentOffset, 0x20))) // token
                mstore(add(memoryPointer, 0x60), calldataload(add(commitmentOffset, 0x40))) // amount
                let commitmentsHashPointer := add(add(commitmentsHashes, 0x20 /* skip length */ ), mul(i, 0x20))
                mstore(commitmentsHashPointer, keccak256(memoryPointer, 0x80))
            }
            // keccak256(abi.encodePacked(commitmentsHashes))
            commitmentsHash := keccak256(add(commitmentsHashes, 0x20 /* skip length */ ), mul(commitments.length, 0x20))
        }
    }

    function getCommitmentsHash(Lock[] calldata commitments) internal pure returns (bytes32) {
        return getCommitmentsHash(commitments, LOCK_TYPEHASH);
    }

    function getCommitmentsHashMemory(Lock[] memory commitments) internal pure returns (bytes32 commitmentsHash) {
        assembly ("memory-safe") {
            let memoryPointer := mload(0x40)
            let commitmentsLength := mload(commitments)
            let commitmentsContent := add(commitments, 0x20)
            let commitmentHashes := add(memoryPointer, 0x80) // leave space for typehash, lockTag, token and amount
            mstore(memoryPointer, LOCK_TYPEHASH)
            for { let i := 0 } lt(i, commitmentsLength) { i := add(i, 1) } {
                let commitmentOffset := mload(add(commitmentsContent, mul(i, 0x20)))
                mcopy(add(memoryPointer, 0x20), commitmentOffset, 0x60) // copy lockTag, token and amount to different memory
                mstore(add(commitmentHashes, mul(i, 0x20)), keccak256(memoryPointer, 0x80))
            }
            commitmentsHash := keccak256(commitmentHashes, mul(commitmentsLength, 0x20))
        }
    }

    function getClaimHash(
        address arbiter,
        address sponsor,
        uint256 nonce,
        uint256 expires,
        bytes32 commitmentsHash,
        bytes32 witness,
        bytes32 typehash
    ) internal pure returns (bytes32 claimHash) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, typehash)
            mstore(add(m, 0x20), arbiter)
            mstore(add(m, 0x40), sponsor)
            mstore(add(m, 0x60), nonce)
            mstore(add(m, 0x80), expires)
            mstore(add(m, 0xa0), commitmentsHash)
            mstore(add(m, 0xc0), witness)
            claimHash := keccak256(m, sub(0xe0, mul(iszero(witness), 0x20)))
        }
    }

    function computeBatchCompactTypehash(string calldata witness) internal pure returns (bytes32 typeHash) {
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

    function recoverSigner(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (signature.length == 65) {
            (r, s) = abi.decode(signature, (bytes32, bytes32));
            v = uint8(signature[64]);
        } else if (signature.length == 64) {
            bytes32 vs;
            (r, vs) = abi.decode(signature, (bytes32, bytes32));
            v = uint8(uint256(vs >> 255) + 27);
            s = vs << 1 >> 1;
        } else {
            return address(0);
        }

        // The s value must lie in the lower half-order of the secp256k1 curve
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }

        return ecrecover(digest, v, r, s);
    }

    function getRecipient(address recipient) internal view returns (address) {
        assembly ("memory-safe") {
            recipient := xor(recipient, mul(caller(), iszero(recipient)))
        }
        return recipient;
    }

    function getNonceWithCommand(bytes1 command, uint248 noncePreCommand) internal pure returns (uint256 nonce) {
        assembly ("memory-safe") {
            nonce := or(command, noncePreCommand)
        }
        return nonce;
    }

    function verifyNonce(uint256 nonce, bytes1 expectedCommand, address expectedSponsor) internal pure {
        assembly ("memory-safe") {
            let command := and(nonce, NONCE_COMMAND_MASK)
            let sponsor := shr(96, shl(8, nonce))
            if iszero(and(eq(command, expectedCommand), eq(sponsor, expectedSponsor))) {
                mstore(0x00, 0xb8a0afb2) // UnauthorizedNonce()
                mstore(0x20, command)
                mstore(0x40, sponsor)
                revert(0x1c, 0x44)
            }
        }
    }

    function splitId(uint256 id) internal pure returns (uint96 allocatorId_, address token_) {
        return (splitAllocatorId(id), splitToken(id));
    }

    function splitAllocatorId(uint256 id) internal pure returns (uint96) {
        uint96 allocatorId_;
        assembly ("memory-safe") {
            allocatorId_ := shr(164, shl(4, id))
        }
        return allocatorId_;
    }

    function splitAllocatorId(bytes12 lockTag) internal pure returns (uint96) {
        uint96 allocatorId_;
        assembly ("memory-safe") {
            allocatorId_ := shr(164, shl(4, lockTag))
        }
        return allocatorId_;
    }

    function splitToken(uint256 id) internal pure returns (address) {
        return address(uint160(id));
    }

    function toId(bytes12 lockTag, address token) internal pure returns (uint256 id) {
        assembly ("memory-safe") {
            id := or(lockTag, token)
        }
    }

    function toLock(uint256 id, uint256 amount) internal pure returns (Lock memory) {
        return Lock({lockTag: bytes12(bytes32(id)), token: splitToken(id), amount: amount});
    }

    /// @dev copied from the-compact/src/lib/IdLib.sol
    function toAllocatorId(address allocator) internal pure returns (uint96 allocatorId) {
        uint8 compactFlag;
        assembly ("memory-safe") {
            // Extract the uppermost 72 bits of the address.
            let x := shr(184, shl(96, allocator))

            // Propagate the highest set bit.
            x := or(x, shr(1, x))
            x := or(x, shr(2, x))
            x := or(x, shr(4, x))
            x := or(x, shr(8, x))
            x := or(x, shr(16, x))
            x := or(x, shr(32, x))
            x := or(x, shr(64, x))

            // Count set bits to derive most significant bit in the last byte.
            let y := sub(x, and(shr(1, x), 0x5555555555555555))
            y := add(and(y, 0x3333333333333333), and(shr(2, y), 0x3333333333333333))
            y := and(add(y, shr(4, y)), 0x0f0f0f0f0f0f0f0f)
            y := add(y, shr(8, y))
            y := add(y, shr(16, y))
            y := add(y, shr(32, y))

            // Look up final value in the sequence.
            compactFlag := and(shr(and(sub(72, and(y, 127)), not(3)), 0xfedcba9876543210000), 15)
        }

        assembly ("memory-safe") {
            allocatorId := or(shl(88, compactFlag), shr(168, shl(168, allocator)))
        }
    }

    function toSeconds(bytes12 lockTag) internal pure returns (uint256 duration) {
        assembly ("memory-safe") {
            let resetPeriod := shr(253, shl(1, lockTag))

            // Bitpacked durations in 24-bit segments:
            // 278d00  094890  015180  000f3c  000258  00003c  00000f  000001
            // 30 days 7 days  1 day   1 hour  10 min  1 min   15 sec  1 sec
            let bitpacked := 0x278d00094890015180000f3c00025800003c00000f000001

            // Shift right by period * 24 bits & mask the least significant 24 bits.
            duration := and(shr(mul(resetPeriod, 24), bitpacked), 0xffffff)
        }
    }
}
