// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {BatchCompact, Compact} from '@uniswap/the-compact/types/EIP712Types.sol';

struct Claim {
    uint256 chainId; // Claim processing chain ID
    Compact compact;
    bytes sponsorSignature; // Authorization from the sponsor
    bytes allocatorSignature; // Authorization from the allocator
}

struct BatchClaim {
    uint256 chainId; // Claim processing chain ID
    BatchCompact compact;
    bytes sponsorSignature; // Authorization from the sponsor
    bytes allocatorSignature; // Authorization from the allocator
}

struct Mandate {
    // uint256 chainId; // (implicit arg, included in EIP712 payload).
    // address tribunal; // (implicit arg, included in EIP712 payload).
    address recipient; // Recipient of filled tokens.
    uint256 expires; // Mandate expiration timestamp.
    address token; // Fill token (address(0) for native).
    uint256 minimumAmount; // Minimum fill amount.
    uint256 baselinePriorityFee; // Base fee threshold where scaling kicks in.
    uint256 scalingFactor; // Fee scaling multiplier (1e18 baseline).
    uint256[] decayCurve; // Block durations, fill increases, & claim decreases.
    bytes32 salt; // Replay protection parameter.
}
