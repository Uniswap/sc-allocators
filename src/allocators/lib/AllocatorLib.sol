// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {LOCK_TYPEHASH, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

library AllocatorLib {
    // bytes4(keccak256('prepareAllocation(address,uint256[2][],address,uint256,bytes32,bytes32,bytes)'));
    bytes4 public constant PREPARE_ALLOCATION_SELECTOR = 0x7ef6597a;

    error InvalidBalanceChange(uint256 newBalance, uint256 oldBalance);
    error InvalidPreparation();
    error InvalidRegistration(address recipient, bytes32 claimHash, bytes32 typehash);

    function prepareAllocation(
        address compactContract,
        uint256 nonce,
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) internal {
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

                // Retrieve and store the current balance of the recipient in transient storage
                mstore(0x14, recipient) // Store the `owner` argument.
                mstore(0x34, id)
                mstore(0x00, 0x00fdd58e000000000000000000000000) // `balanceOf(address,uint256)`.
                let currentBalance :=
                    mul( // The arguments of `mul` are evaluated from right to left.
                        mload(0x20),
                        and( // The arguments of `and` are evaluated from right to left.
                            gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                            staticcall(gas(), compactContract, 0x10, 0x44, 0x20, 0x20)
                        )
                    )
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

    function executeAllocation(
        address compactContract,
        uint256 nonce,
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) internal view returns (bytes32 claimHash, Lock[] memory) {
        bytes32[] memory commitmentHashes = new bytes32[](idsAndAmounts.length);
        Lock[] memory commitments = new Lock[](idsAndAmounts.length);
        bytes32 commitmentsHash;
        uint256 storedNonce;

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
                            staticcall(gas(), compactContract, 0x10, 0x44, 0x20, 0x20)
                        )
                    )
                mstore(0x00, PREPARE_ALLOCATION_SELECTOR)
                mstore(0x20, recipient)
                mstore(0x40, id)
                // Store the current balance in transient storage
                let oldBalance := tload(keccak256(0x00, 0x60))
                if iszero(gt(currentBalance, oldBalance)) {
                    mstore(0x00, 0x9f2aec67) // InvalidBalanceChange(uint256,uint256)
                    mstore(0x20, currentBalance)
                    mstore(0x40, oldBalance)
                    revert(0x1c, 0x44)
                }
                let diffBalance := sub(currentBalance, oldBalance)

                // Store the commitment
                let commitmentOffset := add(add(commitments, 0x20 /* skip length */ ), mul(i, 0x20))
                let commitmentContent :=
                    add(
                        add(commitments, 0x20 /* skip length */ ),
                        add(mul(idsAndAmounts.length, 0x20 /* skip offsets */ ), mul(i, 0x60))
                    )
                // Store the offset for the commitment in the Lock array
                mstore(commitmentOffset, commitmentContent)
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
        if (!ITheCompact(compactContract).isRegistered(recipient, claimHash, typehash)) {
            revert InvalidRegistration(recipient, claimHash, typehash);
        }
        return (claimHash, commitments);
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
                calldatacopy(add(memoryPointer, 0x20), commitmentOffset, 0x60) // load lockTag, token and amount (3 words from calldata)
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

        return ecrecover(digest, v, r, s);
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
