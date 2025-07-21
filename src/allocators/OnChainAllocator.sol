// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOnChainAllocator} from '../interfaces/IOnChainAllocator.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {LOCK_TYPEHASH, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

contract OnChainAllocator is IOnChainAllocator {
    address public immutable COMPACT_CONTRACT;
    bytes32 public immutable COMPACT_DOMAIN_SEPARATOR;
    uint96 public immutable ALLOCATOR_ID;

    mapping(bytes32 tokenHash => Allocation[] allocations) internal _allocations;

    mapping(address user => uint256 nonce) public nonces;

    modifier onlyCompact() {
        if (msg.sender != COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, COMPACT_CONTRACT);
        }
        _;
    }

    constructor(address compactContract_) {
        COMPACT_CONTRACT = compactContract_;
        COMPACT_DOMAIN_SEPARATOR = ITheCompact(COMPACT_CONTRACT).DOMAIN_SEPARATOR();
        ALLOCATOR_ID = ITheCompact(COMPACT_CONTRACT).__registerAllocator(address(this), '');
    }

    /// @inheritdoc IOnChainAllocator
    function registerAllocation(
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness
    ) public returns (bytes32 claimHash, uint256 claimNonce) {
        (claimHash, claimNonce) = _registerAllocation(msg.sender, idsAndAmounts, arbiter, expires, typehash, witness);

        emit AllocationRegistered(msg.sender, claimHash, claimNonce, expires, idsAndAmounts);

        return (claimHash, claimNonce);
    }

    /// @inheritdoc IOnChainAllocator
    function registerAllocationFor(
        address sponsor,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata signature
    ) public returns (bytes32 claimHash, uint256 claimNonce) {
        (claimHash, claimNonce) = _registerAllocation(sponsor, idsAndAmounts, arbiter, expires, typehash, witness);

        // Verify the signature
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), COMPACT_DOMAIN_SEPARATOR, claimHash));
        address signer = _recoverSigner(digest, signature);
        if (signer != sponsor) {
            revert InvalidSignature(signer, sponsor);
        }

        emit AllocationRegistered(sponsor, claimHash, claimNonce, expires, idsAndAmounts);

        return (claimHash, claimNonce);
    }

    /// @inheritdoc IAllocator
    function attest(address, address from_, address, uint256 id_, uint256 amount_) external returns (bytes4) {
        // Can be called by anyone, as this will only clean up expired allocations.
        uint256 balance = ERC6909(COMPACT_CONTRACT).balanceOf(from_, id_);

        // Check unlocked balance
        bytes32 tokenHash = _getTokenHash(id_, from_);
        uint256 fullAmount = amount_ + _allocatedBalance(tokenHash);

        if (balance < fullAmount) {
            revert InsufficientBalance(from_, id_, balance, fullAmount);
        }

        return this.attest.selector;
    }

    /// @inheritdoc IAllocator
    function authorizeClaim(
        bytes32 claimHash, // The message hash representing the claim.
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address sponsor, // The account sponsoring the claim.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256, /*expires*/ // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata /*allocatorData*/ // Arbitrary data provided by the arbiter.
    ) external virtual onlyCompact returns (bytes4) {
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            bytes32 tokenHash = _getTokenHash(idsAndAmounts[i][0], sponsor);

            if (_verifyClaim(tokenHash, claimHash)) {
                // Continue even if the claim is already verified to delete the other allocations.
                continue;
            }

            // claim could not be verified
            revert InvalidClaim(claimHash);
        }

        return this.authorizeClaim.selector;
    }

    /// @inheritdoc IAllocator
    function isClaimAuthorized(
        bytes32 claimHash,
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address sponsor, // The account sponsoring the claim.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata /*allocatorData*/ // Arbitrary data provided by the arbiter.
    ) external view virtual returns (bool) {
        if (expires < block.timestamp) {
            return false;
        }

        // We only need to check the first id to confirm or deny the claim.
        bytes32 tokenHash = _getTokenHash(idsAndAmounts[0][0], sponsor);
        Allocation[] memory allocations = _allocations[tokenHash];
        for (uint256 j = 0; j < allocations.length; j++) {
            if (allocations[j].claimHash == claimHash) {
                return true;
            }
        }

        return false;
    }

    function _registerAllocation(
        address sponsor,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness
    ) internal returns (bytes32 claimHash, uint256 nonce) {
        bytes32 commitmentsHash = _getCommitmentsHash(idsAndAmounts);
        nonce = ++nonces[sponsor];
        claimHash = keccak256(abi.encode(typehash, arbiter, sponsor, nonce, expires, commitmentsHash, witness));
        uint256 minResetPeriod;

        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            // TODO: Discuss which checks to leave in, and which to remove.
            // Some of the checks are decreasing the responsibility of the sponsor, others of the filler.

            // Check the allocator id fits this allocator
            if (_splitAllocatorId(idsAndAmounts[i][0]) != ALLOCATOR_ID) {
                revert InvalidAllocator(_splitAllocatorId(idsAndAmounts[i][0]), ALLOCATOR_ID);
            }

            // Check the amount fits in the supported range
            if (idsAndAmounts[i][1] > type(uint224).max) {
                revert InvalidAmount(idsAndAmounts[i][1]);
            }

            // Get the reset period for the token id
            uint256 duration = _toSeconds(idsAndAmounts[i][0]);
            if (duration < minResetPeriod) {
                minResetPeriod = duration;
            }

            // Ensure no forcedWithdrawal is active for the token id
            (, uint256 forcedWithdrawal) =
                ITheCompact(COMPACT_CONTRACT).getForcedWithdrawalStatus(sponsor, idsAndAmounts[i][0]);
            if (forcedWithdrawal != 0 && forcedWithdrawal < expires) {
                revert ForceWithdrawalAvailable(expires, forcedWithdrawal);
            }

            // Check the balance of the recipient is sufficient
            bytes32 tokenHash = _getTokenHash(idsAndAmounts[i][0], sponsor);
            uint256 allocatedBalance = _allocatedBalance(tokenHash);
            uint256 balance = ERC6909(COMPACT_CONTRACT).balanceOf(sponsor, idsAndAmounts[i][0]);
            if (allocatedBalance + idsAndAmounts[i][1] > balance) {
                revert InsufficientBalance(
                    sponsor, idsAndAmounts[i][0], balance, allocatedBalance + idsAndAmounts[i][1]
                );
            }

            // Store the allocation
            _allocations[tokenHash].push(
                Allocation({expires: expires, amount: uint224(idsAndAmounts[i][1]), claimHash: claimHash})
            );
        }
        // Ensure expiration is not bigger then the smallest reset period
        if (expires > block.timestamp + minResetPeriod) {
            revert InvalidExpiration(expires);
        }

        return (claimHash, nonce);
    }

    function _allocatedBalance(bytes32 tokenHash) internal returns (uint256 allocatedBalance) {
        // using assembly to only read the allocated balance + expiration slot and skipping the claimHash slot
        assembly ("memory-safe") {
            // TODO: caching will optimize for a claim that includes the same token multiple times. Is it worth the 200 gas?
            allocatedBalance := tload(tokenHash)
            if iszero(allocatedBalance) {
                // no previous cached balance, calculate the allocated balance
                mstore(0x00, tokenHash)
                mstore(0x20, _allocations.slot)
                // retrieve the array length slot
                let arrayLengthSlog := keccak256(0x00, 0x40)
                let origLength := sload(arrayLengthSlog)
                let length := origLength
                // retrieve the arrays content slot
                let contentSlot := keccak256(0x00, 0x20)
                for { let i := 0 } lt(i, length) {} {
                    let slot := add(contentSlot, mul(i, 0x40)) // 0x40 to skip the claimHash slot
                    let content := sload(slot)
                    let expiration := shr(224, shl(224, content))
                    if lt(expiration, timestamp()) {
                        // allocation expired, remove it
                        let lastSlot := add(contentSlot, mul(sub(length, 1), 0x40))
                        if iszero(eq(slot, lastSlot)) {
                            // is not the last allocation of the array
                            let contentLast1 := sload(lastSlot)
                            let contentLast2 := sload(add(lastSlot, 0x20))
                            sstore(slot, contentLast1)
                            sstore(add(slot, 0x20), contentLast2)
                        }
                        // remove the last allocation
                        length := sub(length, 1)
                        sstore(lastSlot, 0)
                        sstore(add(lastSlot, 0x20), 0)

                        // repeat the loop at the same index
                        continue
                    }

                    let amount := shr(32, content)
                    allocatedBalance := add(allocatedBalance, amount)

                    // jump to the next allocation
                    i := add(i, 1)
                }

                if lt(length, origLength) {
                    // update the array length
                    sstore(arrayLengthSlog, length)
                }

                // Cache the allocated balance in case the token is part of the same claim again.
                tstore(tokenHash, allocatedBalance)
            }
        }
        return allocatedBalance;
    }

    function _verifyClaim(bytes32 tokenHash, bytes32 claimHash) internal returns (bool verified) {
        // using assembly to only read the claimHash slot and skip the expires/amount slot
        assembly ("memory-safe") {
            mstore(0x00, tokenHash)
            mstore(0x20, _allocations.slot)
            let lengthSlot := keccak256(0x00, 0x40)
            let length := sload(lengthSlot)
            mstore(0x00, lengthSlot)
            let contentSlot := keccak256(0x00, 0x20)
            for { let i := 0 } lt(i, length) { i := add(i, 1) } {
                let slot2 := add(contentSlot, add(mul(i, 0x40), 0x20)) // add 0x20 to skip the expires/amount slot
                let content2 := sload(slot2)
                if eq(content2, claimHash) {
                    // delete the allocation
                    let lastSlot := add(contentSlot, mul(sub(length, 1), 0x40))
                    if iszero(eq(sub(slot2, 0x20), lastSlot)) {
                        // is not the last allocation of the array
                        let contentLast1 := sload(lastSlot)
                        let contentLast2 := sload(add(lastSlot, 0x20))
                        sstore(sub(slot2, 0x20), contentLast1)
                        sstore(slot2, contentLast2)
                    }

                    sstore(lastSlot, 0)
                    sstore(add(lastSlot, 0x20), 0)

                    // update the array length
                    sstore(lengthSlot, sub(length, 1))

                    // We return at the first match, no matter if the allocated amounts match.
                    // If the claim includes the same token multiple times (amounts mismatch),
                    // we will enter this function again until all entries are deleted.
                    verified := 1
                    break
                }
            }
        }
    }

    function _recoverSigner(bytes32 digest, bytes calldata signature) internal pure returns (address) {
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

        return ecrecover(digest, v, r, s);
    }

    function _getCommitmentsHash(uint256[2][] memory idsAndAmounts) internal pure returns (bytes32) {
        bytes32 commitmentsHash;
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            commitmentsHash = keccak256(
                abi.encode(
                    LOCK_TYPEHASH,
                    idsAndAmounts[i][0] >> 160 << 160,
                    idsAndAmounts[i][0] << 96 >> 96,
                    idsAndAmounts[i][1]
                )
            );
        }
        return commitmentsHash;
    }

    function _getTokenHash(uint256 id_, address sponsor_) internal pure returns (bytes32) {
        return keccak256(abi.encode(id_, sponsor_));
    }

    function _splitAllocatorId(uint256 id) internal pure returns (uint96) {
        uint96 allocatorId_;
        assembly ("memory-safe") {
            allocatorId_ := shr(164, shl(4, id))
        }
        return allocatorId_;
    }

    function _toSeconds(uint256 id) internal pure returns (uint256 duration) {
        assembly ("memory-safe") {
            let resetPeriod := shr(253, shl(1, id))

            // Bitpacked durations in 24-bit segments:
            // 278d00  094890  015180  000f3c  000258  00003c  00000f  000001
            // 30 days 7 days  1 day   1 hour  10 min  1 min   15 sec  1 sec
            let bitpacked := 0x278d00094890015180000f3c00025800003c00000f000001

            // Shift right by period * 24 bits & mask the least significant 24 bits.
            duration := and(shr(mul(resetPeriod, 24), bitpacked), 0xffffff)
        }
    }
}
