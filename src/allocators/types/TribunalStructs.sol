// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { Compact } from "@uniswap/the-compact/types/EIP712Types.sol";


    struct Claim {
        uint256 chainId; // Claim processing chain ID
        Compact compact;
        bytes sponsorSignature; // Authorization from the sponsor
        bytes allocatorSignature; // Authorization from the allocator
    }

    struct Mandate {
        address recipient; // Recipient of settled tokens
        uint256 expires; // Mandate expiration timestamp
        address token; // Settlement token (address(0) for native)
        uint256 minimumAmount; // Minimum settlement amount
        uint256 baselinePriorityFee; // Base fee threshold where scaling kicks in
        uint256 scalingFactor; // Fee scaling multiplier (1e18 baseline)
        bytes32 salt; // Replay protection parameter
    }

    struct Directive {
        address claimant; // Recipient of claimed tokens
        uint256 dispensation; // Cross-chain message layer payment
    }