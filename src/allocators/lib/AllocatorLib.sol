// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC6909} from '@solady/tokens/ERC6909.sol';

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
        uint256[] memory ids = new uint256[](idsAndAmounts.length);
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            uint256 id = idsAndAmounts[i][0];
            // Store Id for the identifier
            ids[i] = id;

            // Store the current balance to calculate the deposited amounts in `executeAllocation`
            uint256 currentBalance = ERC6909(compactContract).balanceOf(recipient, id);
            assembly ("memory-safe") {
                let m := mload(0x40)
                mstore(m, PREPARE_ALLOCATION_SELECTOR)
                mstore(add(m, 0x20), recipient)
                mstore(add(m, 0x40), id)
                tstore(keccak256(m, 0x60), currentBalance)
            }
        }

        // Store the nonce for the identifier to ensure the same data is used in `executeAllocation` and protect against replay attacks
        bytes32 identifier =
            keccak256(abi.encode(PREPARE_ALLOCATION_SELECTOR, recipient, ids, arbiter, expires, typehash, witness));
        assembly ("memory-safe") {
            tstore(identifier, nonce)
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
    ) internal view returns (bytes32 claimHash, Lock[] memory commitments) {
        uint256[] memory ids = new uint256[](idsAndAmounts.length);
        commitments = new Lock[](idsAndAmounts.length);
        bytes32[] memory commitmentHashes = new bytes32[](idsAndAmounts.length);

        // Check actual balance changes
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            // Store Id for the identifier
            ids[i] = idsAndAmounts[i][0];

            uint256 amount = _calculateBalanceChange(compactContract, recipient, ids[i]);

            // Create commitments
            bytes12 lockTag = bytes12(bytes32(ids[i]));
            address token = address(uint160(ids[i]));
            commitmentHashes[i] = keccak256(abi.encode(LOCK_TYPEHASH, lockTag, token, amount));
            commitments[i] = Lock({lockTag: lockTag, token: token, amount: amount});
        }

        // Ensure preparation was called with the same data
        bytes32 identifier =
            keccak256(abi.encode(PREPARE_ALLOCATION_SELECTOR, recipient, ids, arbiter, expires, typehash, witness));
        uint256 storedNonce;
        assembly ("memory-safe") {
            storedNonce := tload(identifier)
        }
        if (nonce != storedNonce) {
            revert InvalidPreparation();
        }

        // Check for a valid registration with the actual data
        claimHash = getClaimHash(
            arbiter, recipient, storedNonce, expires, keccak256(abi.encodePacked(commitmentHashes)), witness, typehash
        );
        if (!ITheCompact(compactContract).isRegistered(recipient, claimHash, typehash)) {
            revert InvalidRegistration(recipient, claimHash, typehash);
        }

        return (claimHash, commitments);
    }

    function getCommitmentsHash(Lock[] memory commitments, bytes32 typehash) internal pure returns (bytes32) {
        bytes32[] memory commitmentsHashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            commitmentsHashes[i] =
                keccak256(abi.encode(typehash, commitments[i].lockTag, commitments[i].token, commitments[i].amount));
        }
        return keccak256(abi.encodePacked(commitmentsHashes));
    }

    function getCommitmentsHash(Lock[] memory commitments) internal pure returns (bytes32) {
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

    function _calculateBalanceChange(address compactContract, address recipient, uint256 id)
        private
        view
        returns (uint256 amount)
    {
        // Calculate the balance
        uint256 oldBalance;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, PREPARE_ALLOCATION_SELECTOR)
            mstore(add(m, 0x20), recipient)
            mstore(add(m, 0x40), id)
            oldBalance := tload(keccak256(m, 0x60))
        }
        uint256 newBalance = ERC6909(compactContract).balanceOf(recipient, id);
        if (newBalance <= oldBalance) {
            revert InvalidBalanceChange(newBalance, oldBalance);
        }
        return newBalance - oldBalance;
    }
}
