// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { ERC6909 } from "@solady/tokens/ERC6909.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { ITheCompact } from "@uniswap/the-compact/interfaces/ITheCompact.sol";
import { Compact } from "@uniswap/the-compact/types/EIP712Types.sol";
import { ResetPeriod } from "@uniswap/the-compact/lib/IdLib.sol";
import { IAllocator } from "../interfaces/IAllocator.sol";
import { ISimpleAllocator } from "../interfaces/ISimpleAllocator.sol";

contract SimpleAllocator is ISimpleAllocator {
    // keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)")
    bytes32 constant COMPACT_TYPEHASH = 0xcdca950b17b5efc016b74b912d8527dfba5e404a688cbc3dab16cb943287fec2;

    address public immutable COMPACT_CONTRACT;
    address public immutable ARBITER;
    uint256 public immutable MIN_WITHDRAWAL_DELAY;
    uint256 public immutable MAX_WITHDRAWAL_DELAY;

    /// @dev mapping of tokenHash to the expiration of the lock
    mapping(bytes32 tokenHash => uint256 expiration) internal _claim;
    /// @dev mapping of tokenHash to the amount of the lock
    mapping(bytes32 tokenHash => uint256 amount) internal _amount;
    /// @dev mapping of tokenHash to the nonce of the lock
    mapping(bytes32 tokenHash => uint256 nonce) internal _nonce;
    /// @dev mapping of the lock digest to the tokenHash of the lock
    mapping(bytes32 digest => bytes32 tokenHash) internal _sponsor;

    constructor(address compactContract_, address arbiter_, uint256 minWithdrawalDelay_, uint256 maxWithdrawalDelay_) {
        COMPACT_CONTRACT = compactContract_;
        ARBITER = arbiter_;
        MIN_WITHDRAWAL_DELAY = minWithdrawalDelay_;
        MAX_WITHDRAWAL_DELAY = maxWithdrawalDelay_;

        ITheCompact(COMPACT_CONTRACT).__registerAllocator(address(this), "");
    }

    /// @inheritdoc ISimpleAllocator
    function lock(Compact calldata compact_) external {
        bytes32 tokenHash = _checkAllocation(compact_);

        bytes32 digest = keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                ITheCompact(COMPACT_CONTRACT).DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        COMPACT_TYPEHASH,
                        compact_.arbiter,
                        compact_.sponsor,
                        compact_.nonce,
                        compact_.expires,
                        compact_.id,
                        compact_.amount
                    )
                )
            )
        );

        _claim[tokenHash] = compact_.expires;
        _amount[tokenHash] = compact_.amount;
        _nonce[tokenHash] = compact_.nonce;
        _sponsor[digest] = tokenHash;

        emit Locked(compact_.sponsor, compact_.id, compact_.amount, compact_.expires);
    }

    /// @inheritdoc IAllocator
    function attest(address operator_, address from_, address, uint256 id_, uint256 amount_) external view returns (bytes4) {
        if (msg.sender != COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, COMPACT_CONTRACT);
        }
        // For a transfer, the sponsor is the arbiter
        if (operator_ != from_) {
            revert InvalidCaller(operator_, from_);
        }
        uint256 balance = ERC6909(COMPACT_CONTRACT).balanceOf(from_, id_);
        // Check unlocked balance
        bytes32 tokenHash = _getTokenHash(id_, from_);

        uint256 fullAmount = amount_;
        if (_claim[tokenHash] > block.timestamp) {
            // Lock is still active, add the locked amount if the nonce has not yet been consumed
            fullAmount += ITheCompact(COMPACT_CONTRACT).hasConsumedAllocatorNonce(_nonce[tokenHash], address(this)) ? 0 : _amount[tokenHash];
        }
        if (balance < fullAmount) {
            revert InsufficientBalance(from_, id_, balance, fullAmount);
        }

        return 0x1a808f91;
    }

    /// @inheritdoc IERC1271
    /// @dev we trust the compact contract to check the nonce is not already consumed
    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4 magicValue) {
        // The hash is the digest of the compact
        bytes32 tokenHash = _sponsor[hash];
        if (tokenHash == bytes32(0) || _claim[tokenHash] <= block.timestamp) {
            revert InvalidLock(hash, _claim[tokenHash]);
        }

        return IERC1271.isValidSignature.selector;
    }

    /// @inheritdoc ISimpleAllocator
    function checkTokensLocked(uint256 id_, address sponsor_) external view returns (uint256 amount_, uint256 expires_) {
        bytes32 tokenHash = _getTokenHash(id_, sponsor_);
        uint256 expires = _claim[tokenHash];
        if (expires <= block.timestamp || ITheCompact(COMPACT_CONTRACT).hasConsumedAllocatorNonce(_nonce[tokenHash], address(this))) {
            return (0, 0);
        }

        return (_amount[tokenHash], expires);
    }

    /// @inheritdoc ISimpleAllocator
    function checkCompactLocked(Compact calldata compact_) external view returns (bool locked_, uint256 expires_) {
        // TODO: Check the force unlock time in the compact contract and adapt expires_ if needed
        if (compact_.arbiter != ARBITER) {
            revert InvalidArbiter(compact_.arbiter);
        }
        bytes32 tokenHash = _getTokenHash(compact_.id, compact_.sponsor);
        bytes32 digest = keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                ITheCompact(COMPACT_CONTRACT).DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        COMPACT_TYPEHASH,
                        compact_.arbiter,
                        compact_.sponsor,
                        compact_.nonce,
                        compact_.expires,
                        compact_.id,
                        compact_.amount
                    )
                )
            )
        );
        uint256 expires = _claim[tokenHash];
        bool active = _sponsor[digest] == tokenHash && expires > block.timestamp && !ITheCompact(COMPACT_CONTRACT).hasConsumedAllocatorNonce(_nonce[tokenHash], address(this));
        return (active, active ? expires : 0);
    }

    function _getTokenHash(uint256 id_, address sponsor_) internal pure returns (bytes32) {
        return keccak256(abi.encode(id_, sponsor_));
    }

    function _checkAllocation(Compact memory compact_) internal view returns (bytes32) {
        // Check msg.sender is sponsor
        if (msg.sender != compact_.sponsor) {
            revert InvalidCaller(msg.sender, compact_.sponsor);
        }
        bytes32 tokenHash = _getTokenHash(compact_.id, msg.sender);
        // Check no lock is already active for this sponsor
        if (_claim[tokenHash] > block.timestamp && !ITheCompact(COMPACT_CONTRACT).hasConsumedAllocatorNonce(_nonce[tokenHash], address(this))) {
            revert ClaimActive(compact_.sponsor);
        }
        // Check arbiter is valid
        if (compact_.arbiter != ARBITER) {
            revert InvalidArbiter(compact_.arbiter);
        }
        // Check expiration is not too soon or too late
        if (compact_.expires < block.timestamp + MIN_WITHDRAWAL_DELAY || compact_.expires > block.timestamp + MAX_WITHDRAWAL_DELAY) {
            revert InvalidExpiration(compact_.expires);
        }
        // Check expiration is not longer then the tokens forced withdrawal time
        (,, ResetPeriod resetPeriod,) = ITheCompact(COMPACT_CONTRACT).getLockDetails(compact_.id);
        if (compact_.expires > block.timestamp + _resetPeriodToSeconds(resetPeriod)) {
            revert ForceWithdrawalAvailable(compact_.expires, block.timestamp + _resetPeriodToSeconds(resetPeriod));
        }
        // Check expiration is not past an active force withdrawal
        (, uint256 forcedWithdrawalExpiration) = ITheCompact(COMPACT_CONTRACT).getForcedWithdrawalStatus(compact_.sponsor, compact_.id);
        if (forcedWithdrawalExpiration != 0 && forcedWithdrawalExpiration < compact_.expires) {
            revert ForceWithdrawalAvailable(compact_.expires, forcedWithdrawalExpiration);
        }
        // Check nonce is not yet consumed
        if (ITheCompact(COMPACT_CONTRACT).hasConsumedAllocatorNonce(compact_.nonce, address(this))) {
            revert NonceAlreadyConsumed(compact_.nonce);
        }

        uint256 balance = ERC6909(COMPACT_CONTRACT).balanceOf(msg.sender, compact_.id);
        // Check balance is enough
        if (balance < compact_.amount) {
            revert InsufficientBalance(msg.sender, compact_.id, balance, compact_.amount);
        }

        return tokenHash;
    }

    /// @dev copied from IdLib.sol
    function _resetPeriodToSeconds(ResetPeriod resetPeriod_) internal pure returns (uint256 duration) {
        assembly ("memory-safe") {
            // Bitpacked durations in 24-bit segments:
            // 278d00  094890  015180  000f3c  000258  00003c  00000f  000001
            // 30 days 7 days  1 day   1 hour  10 min  1 min   15 sec  1 sec
            let bitpacked := 0x278d00094890015180000f3c00025800003c00000f000001

            // Shift right by period * 24 bits & mask the least significant 24 bits.
            duration := and(shr(mul(resetPeriod_, 24), bitpacked), 0xffffff)
        }
        return duration;
    }
}
