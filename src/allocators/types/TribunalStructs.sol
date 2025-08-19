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

// struct Mandate {
//     // uint256 chainId; // (implicit arg, included in EIP712 payload).
//     // address tribunal; // (implicit arg, included in EIP712 payload).
//     address recipient; // Recipient of filled tokens.
//     uint256 expires; // Mandate expiration timestamp.
//     address token; // Fill token (address(0) for native).
//     uint256 minimumAmount; // Minimum fill amount.
//     uint256 baselinePriorityFee; // Base fee threshold where scaling kicks in.
//     uint256 scalingFactor; // Fee scaling multiplier (1e18 baseline).
//     uint256[] decayCurve; // Block durations, fill increases, & claim decreases.
//     bytes32 salt; // Replay protection parameter.
// }

// Parent mandate signed by the sponsor on source chain. Note that the EIP-712 payload differs slightly from the structs declared here (mainly around utilizing full mandates rather than mandate hashes).
struct Mandate {
    address adjuster;
    Fill[] fills; // Arbitrary-length array; note that in EIP-712 payload this is Mandate_Fill
}

// Mandate_Fill in EIP-712 payload
struct Fill {
    uint256 chainId; // Same-chain if value matches chainId(), otherwise cross-chain
    address tribunal; // Contract where the fill is performed.
    uint256 expires; // Fill expiration timestamp.
    address fillToken; // Intermediate fill token (address(0) for native, same address for no action).
    uint256 minimumFillAmount; // Minimum fill amount.
    uint256 baselinePriorityFee; // Base fee threshold where scaling kicks in.
    uint256 scalingFactor; // Fee scaling multiplier (1e18 baseline).
    uint256[] priceCurve; // Block durations and uint240 additional scaling factors per each duration.
    address recipient; // Recipient of the tokens — address(0) or tribunal indicate that funds will be pulled by the directive.
    RecipientCallback[] recipientCallback; // Array of length 0 or 1; note that in EIP-712 payload this is Mandate_RecipientCallback[]
    bytes32 salt;
}

// If a callback is specified, tribunal will follow up with a call to the recipient with fill details (including realized fill amount), a new compact and hash of an accompanying mandate, a target chainId, and context
// Note that this does not directly map to the EIP-712 payload (which contains a Mandate_BatchCompact containing the full `Mandate mandate` rather than BatchCompact + mandateHash)
// Mandate_RecipientCallback in EIP-712 payload
struct RecipientCallback {
    uint256 chainId;
    BatchCompact compact;
    bytes32 mandateHash;
    bytes context;
}

// Arguments signed for by adjuster.
struct Adjustment {
    // bytes32 claimHash included in EIP-712 payload but not provided as an argument.
    uint256 fillIndex;
    uint256 targetBlock;
    uint256[] supplementalPriceCurve; // Additional scaling factor specified duration on price curve.
    bytes32 validityConditions; // Optional value consisting of a number of blocks past the target and a exclusive filler address.
}
