// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IdLib} from 'lib/the-compact/src/lib/IdLib.sol';
import {BATCH_COMPACT_TYPEHASH, BatchCompact, LOCK_TYPEHASH, Lock} from 'lib/the-compact/src/types/EIP712Types.sol';

import {ResetPeriod} from 'lib/the-compact/src/types/ResetPeriod.sol';
import {Scope} from 'lib/the-compact/src/types/Scope.sol';

contract TestHelper {
    string constant BATCH_COMPACT_TYPESTRING_WITH_WITNESS =
        'BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint256 witness)';
    bytes32 constant BATCH_COMPACT_TYPEHASH_WITH_WITNESS = keccak256(bytes(BATCH_COMPACT_TYPESTRING_WITH_WITNESS));
    string constant WITNESS_STRING = 'uint256 witness';
    string constant WITNESS_TYPESTRING = string(abi.encodePacked('Mandate(', WITNESS_STRING, ')'));
    bytes32 constant WITNESS_TYPEHASH = keccak256(bytes(WITNESS_TYPESTRING));

    function _toLockTag(address allocator, Scope scope, ResetPeriod resetPeriod)
        internal
        pure
        returns (bytes12 lockTag)
    {
        uint96 allocatorId = _toAllocatorId(allocator);
        return IdLib.toLockTag(allocatorId, scope, resetPeriod);
    }

    function _toId(Scope scope, ResetPeriod resetPeriod, address allocator, address token)
        internal
        pure
        returns (uint256 id)
    {
        uint96 allocatorId = _toAllocatorId(allocator);
        bytes12 lockTag = IdLib.toLockTag(allocatorId, scope, resetPeriod);
        return uint256(uint256(uint96(lockTag)) << 160) | uint256(uint160(token));
    }

    function _toAllocatorId(address allocator) internal pure returns (uint96 allocatorId) {
        return IdLib.toAllocatorId(allocator);
    }

    function _updateBatchCompact(
        BatchCompact memory batchCompact,
        uint256[2][] memory idsAndAmounts,
        uint256[] memory registeredAmounts,
        uint256 nonce
    ) internal pure returns (BatchCompact memory) {
        batchCompact.commitments = new Lock[](idsAndAmounts.length);
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            batchCompact.commitments[i] = Lock({
                lockTag: bytes12(bytes32(idsAndAmounts[i][0])),
                token: address(uint160(idsAndAmounts[i][0])),
                amount: registeredAmounts[i]
            });
        }
        batchCompact.nonce = nonce;
        return batchCompact;
    }

    function _updateBatchCompact(BatchCompact memory batchCompact, uint256[2][] memory idsAndAmounts, uint256 nonce)
        internal
        pure
        returns (BatchCompact memory)
    {
        batchCompact.commitments = new Lock[](idsAndAmounts.length);
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            batchCompact.commitments[i] = Lock({
                lockTag: bytes12(bytes32(idsAndAmounts[i][0])),
                token: address(uint160(idsAndAmounts[i][0])),
                amount: idsAndAmounts[i][1]
            });
        }
        batchCompact.nonce = nonce;
        return batchCompact;
    }

    function _toBatchCompactHash(BatchCompact memory batchCompact) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH,
                batchCompact.arbiter,
                batchCompact.sponsor,
                batchCompact.nonce,
                batchCompact.expires,
                _toBatchCompactCommitmentsHash(batchCompact.commitments)
            )
        );
    }

    function _toBatchCompactHashWithWitness(bytes32 typeHash, BatchCompact memory batchCompact, bytes32 witness)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                typeHash,
                batchCompact.arbiter,
                batchCompact.sponsor,
                batchCompact.nonce,
                batchCompact.expires,
                _toBatchCompactCommitmentsHash(batchCompact.commitments),
                witness
            )
        );
    }

    function _toBatchCompactCommitmentsHash(Lock[] memory commitments) internal pure returns (bytes32) {
        bytes32[] memory commitmentsHashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            commitmentsHashes[i] = keccak256(
                abi.encode(LOCK_TYPEHASH, commitments[i].lockTag, commitments[i].token, commitments[i].amount)
            );
        }
        return keccak256(abi.encodePacked(commitmentsHashes));
    }

    function _toDigest(bytes32 claimHash, bytes32 domainSeparator) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, claimHash));
    }

    function _idsAndAmountsToCommitments(uint256[2][] memory idsAndAmounts)
        internal
        pure
        returns (Lock[] memory commitments)
    {
        commitments = new Lock[](idsAndAmounts.length);
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            commitments[i] = Lock({
                lockTag: bytes12(bytes32(idsAndAmounts[i][0])),
                token: address(uint160(idsAndAmounts[i][0])),
                amount: idsAndAmounts[i][1]
            });
        }
        return commitments;
    }
}
