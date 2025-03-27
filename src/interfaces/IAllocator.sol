// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

interface IAllocator {
    // Called on standard transfers; must return this function selector (0x1a808f91).
    function attest(address operator, address from, address to, uint256 id, uint256 amount) external returns (bytes4);

    // Authorize a claim. Called from The Compact as part of claim processing.
    function authorizeClaim(
        bytes32 claimHash, // The message hash representing the claim.
        address arbiter, // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256 nonce, // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) external returns (bytes4); // Must return the function selector.

    // Handle a claim registration. Called from The Compact as a part of compact registration.
    function registerClaim(
        bytes32 claimHash, // The message hash representing the claim.
        address caller, // The account initiating the registration.
        address arbiter, // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256 nonce, // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the caller.
    ) external returns (bytes4); // Must return the function selector.

    function allocatorDataSpecification()
        external
        view
        returns (
            uint256 specificationId, // An identifier indicating a required "standard" for allocatorData.
            string memory claimEncoding, // The encoding of the `allocatorData` payload on claim processing.
            string memory registrationEncoding, // The encoding of the `allocatorData` payload on claim registration.
            bytes memory context
        ); // Any additional context as defined by the specificationId.
}
