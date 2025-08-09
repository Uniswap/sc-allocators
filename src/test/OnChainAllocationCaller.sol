// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IOnChainAllocation} from '../interfaces/IOnChainAllocation.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';

contract OnChainAllocationCaller {
    IOnChainAllocation public immutable ALLOCATOR;
    ITheCompact public immutable COMPACT;

    constructor(address allocator_, address compact_) {
        ALLOCATOR = IOnChainAllocation(allocator_);
        COMPACT = ITheCompact(compact_);
    }

    function onChainAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        uint8 todo
    ) external {
        uint256 nonce;
        if (todo == 0) {
            // Correctly deposit and register
            nonce = ALLOCATOR.prepareAllocation(recipient, idsAndAmounts, arbiter, expires, typehash, witness, '');
            ITheCompact(COMPACT).batchDepositAndRegisterFor(
                recipient, idsAndAmounts, arbiter, nonce, expires, typehash, witness
            );
        } else if (todo == 1) {
            // Only deposit, do not register
            nonce = ALLOCATOR.prepareAllocation(recipient, idsAndAmounts, arbiter, expires, typehash, witness, '');
            ITheCompact(COMPACT).batchDeposit(idsAndAmounts, recipient);
        } else if (todo == 2) {
            // Do not prepare, but deposit and register
            ITheCompact(COMPACT).batchDepositAndRegisterFor(
                recipient, idsAndAmounts, arbiter, nonce, expires, typehash, witness
            );
        } else if (todo == 3) {
            nonce = ALLOCATOR.prepareAllocation(recipient, idsAndAmounts, arbiter, expires, typehash, witness, '');
        } else {
            // Correctly deposit and register
            nonce = ALLOCATOR.prepareAllocation(recipient, idsAndAmounts, arbiter, expires, typehash, witness, '');
            ITheCompact(COMPACT).batchDepositAndRegisterFor(
                recipient, idsAndAmounts, arbiter, nonce, expires, typehash, witness
            );
            ALLOCATOR.executeAllocation(recipient, idsAndAmounts, arbiter, expires, typehash, witness, '');
        }
        ALLOCATOR.executeAllocation(recipient, idsAndAmounts, arbiter, expires, typehash, witness, '');
    }
}
