// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { IAllocator } from "../interfaces/IAllocator.sol";
import { Compact } from "@uniswap/the-compact/types/EIP712Types.sol";

interface ISimpleAllocator is IAllocator {
    /// @notice Thrown if a claim is already active
    error ClaimActive(address sponsor);

    /// @notice Thrown if the caller is invalid
    error InvalidCaller(address caller, address expected);

    /// @notice Thrown if the nonce has already been consumed on the compact contract
    error NonceAlreadyConsumed(uint256 nonce);

    /// @notice Thrown if the sponsor does not have enough balance to lock the amount
    error InsufficientBalance(address sponsor, uint256 id, uint256 balance, uint256 expectedBalance);

    /// @notice Thrown if the provided expiration is not valid
    error InvalidExpiration(uint256 expires);

    /// @notice Thrown if the expiration is longer then the tokens forced withdrawal time
    error ForceWithdrawalAvailable(uint256 expires, uint256 forcedWithdrawalExpiration);

    /// @notice Thrown if the allocator is not the one expected
    error InvalidAllocator(address allocator);

    /// @notice Thrown if the provided lock is not available or expired
    /// @dev The expiration will be '0' if no lock is available
    error InvalidLock(bytes32 digest, uint256 expiration);

    /// @notice Emitted when a lock is successfully created
    /// @param sponsor The address of the sponsor
    /// @param id The id of the token
    /// @param amount The amount of the token that was available for locking (the full balance of the token will get locked)
    /// @param expires The expiration of the lock
    event Locked(address indexed sponsor, uint256 indexed id, uint256 amount, uint256 expires);

    /// @notice Locks the tokens of an id for a claim
    /// @dev Locks all tokens of a sponsor for an id
    /// @param compact_ The compact that contains the data about the lock
    function lock(Compact calldata compact_) external;

    /// @notice Checks if the tokens of a sponsor for an id are locked
    /// @param id_ The id of the token
    /// @param sponsor_ The address of the sponsor
    /// @return amount_ The amount of the token that was available for locking (the full balance of the token will get locked)
    /// @return expires_ The expiration of the lock
    function checkTokensLocked(uint256 id_, address sponsor_) external view returns (uint256 amount_, uint256 expires_);

    /// @notice Checks if the a lock for the compact exists and is active
    /// @dev Also checks if the provided nonce has not yet been consumed on the compact contract
    /// @param compact_ The compact that contains the data about the lock
    /// @return locked_ Whether the compact is locked
    /// @return expires_ The expiration of the lock
    function checkCompactLocked(Compact calldata compact_) external view returns (bool locked_, uint256 expires_);
}
