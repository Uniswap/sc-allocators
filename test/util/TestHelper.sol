// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IdLib} from 'lib/the-compact/src/lib/IdLib.sol';

import {ResetPeriod} from 'lib/the-compact/src/types/ResetPeriod.sol';
import {Scope} from 'lib/the-compact/src/types/Scope.sol';

contract TestHelper {
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
}
