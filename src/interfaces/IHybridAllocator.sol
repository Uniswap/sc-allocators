// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';

interface IHybridAllocator is IAllocator {
    error Unsupported();
    error InvalidIds();
    error InvalidAllocatorId(uint96 allocatorId, uint96 expectedAllocatorId);
    error InvalidCaller(address sender, address expectedSender);
    error InvalidAllocatorData(uint256 length);
    error InvalidSignature();
    error InvalidSigner();
    error LastSigner();
    error InvalidValue(uint256 value, uint256 expectedValue);
    error InvalidRegistration(address sponsor, bytes32 claimHash);

    event ClaimRegistered(address indexed sponsor, uint256[] registeredAmounts, uint256 nonce, bytes32 claimHash);

    /**
     * @notice Add an offchain signer to the allocator.
     * @param signer_ The address of the signer to add.
     */
    function addSigner(address signer_) external;

    /**
     * @notice Remove an offchain signer from the allocator.
     * @dev The last signer cannot be removed.
     * @param signer_ The address of the signer to remove.
     */
    function removeSigner(address signer_) external;

    /**
     * @notice Replace an offchain signer with a new one.
     * @dev The caller must be the replaced signer.
     * @param newSigner_ The address of the new signer.
     */
    function replaceSigner(address newSigner_) external;

    /**
     * @notice Create an allocation and a registration on the compact by depositing the relevant tokens to the compact.
     * @dev If the provided amounts are zero, the contract will use its own token balance.
     * @param recipient The address receiving the deposited tokens and the sponsor of the compact.
     * @param idsAndAmounts The IDs and amounts of the tokens to register. Amounts can be zero.
     * @param arbiter The address of the arbiter for the compact.
     * @param expires The expiration time of the compact.
     * @param typehash The typehash of the compact.
     * @param witness The witness of the compact.
     * @return The claim hash, the registered amounts, and the nonce.
     */
    function allocateAndRegister(
        address recipient,
        uint256[2][] memory idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external payable returns (bytes32, uint256[] memory, uint256);
}
