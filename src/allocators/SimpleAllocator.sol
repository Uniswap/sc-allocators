// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {ISimpleAllocator} from '../interfaces/ISimpleAllocator.sol';
import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {ResetPeriod} from '@uniswap/the-compact/lib/IdLib.sol';
import {COMPACT_TYPEHASH, Compact} from '@uniswap/the-compact/types/EIP712Types.sol';
import {ForcedWithdrawalStatus} from '@uniswap/the-compact/types/ForcedWithdrawalStatus.sol';

contract SimpleAllocator is ISimpleAllocator {
    /// @notice uint8(bytes1(keccak256("SimpleAllocator.nonce")))
    uint8 internal constant NONCE_MASTER_SLOT_SEED = 0x84;

    address public immutable COMPACT_CONTRACT;
    uint256 public immutable MIN_WITHDRAWAL_DELAY;
    uint256 public immutable MAX_WITHDRAWAL_DELAY;

    uint96 public immutable ALLOCATOR_ID;

    uint256 private constant EXPIRATION_BITS = 32;
    uint256 private constant AMOUNT_BITS = 224;

    // Bit masks
    uint256 private constant EXPIRATION_MASK = ((1 << EXPIRATION_BITS) - 1);
    bytes32 private constant AMOUNT_MASK = bytes32(((1 << AMOUNT_BITS) - 1) << EXPIRATION_BITS);

    /// @dev mapping of tokenHash to the expiration of the lock
    mapping(bytes32 claimHash => bool active) internal _claim;
    /// @dev mapping of tokenHash to the uint224 amount and uint32 expiration of the lock
    mapping(bytes32 tokenHash => bytes32 amountAndExpiration) internal _allocation;

    modifier onlyCompact() {
        if (msg.sender != COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, COMPACT_CONTRACT);
        }
        _;
    }

    constructor(address compactContract_, uint256 minWithdrawalDelay_, uint256 maxWithdrawalDelay_) {
        COMPACT_CONTRACT = compactContract_;
        MIN_WITHDRAWAL_DELAY = minWithdrawalDelay_;
        MAX_WITHDRAWAL_DELAY = maxWithdrawalDelay_;

        ALLOCATOR_ID = ITheCompact(COMPACT_CONTRACT).__registerAllocator(address(this), '');
    }

    /// @inheritdoc ISimpleAllocator
    function lock(Compact calldata compact_) external {
        _checkMsgSender(compact_.sponsor);
        bytes32 tokenHash = _checkForActiveAllocation(compact_.sponsor, compact_.lockTag, compact_.token);
        _checkAllocator(compact_.lockTag);
        _checkExpiration(compact_.expires);
        _checkAndSetNonce(compact_.nonce);
        _checkForcedWithdrawal(compact_.sponsor, compact_.expires, compact_.lockTag, compact_.token);
        _checkBalance(compact_.sponsor, _getTokenId(compact_.lockTag, compact_.token), compact_.amount);

        bytes32 claimHash = keccak256(
            abi.encode(
                COMPACT_TYPEHASH,
                compact_.arbiter,
                compact_.sponsor,
                compact_.nonce,
                compact_.expires,
                compact_.lockTag,
                compact_.token,
                compact_.amount
            )
        );

        _claim[claimHash] = true;
        _allocation[tokenHash] = _allocationData(compact_.amount, compact_.expires);

        emit Locked(compact_.sponsor, compact_.lockTag, compact_.token, compact_.amount, compact_.expires);
    }

    /// @inheritdoc ISimpleAllocator
    function lock(Compact calldata compact_, bytes32 witness_, bytes32 typeHash_) external {
        _checkMsgSender(compact_.sponsor);
        bytes32 tokenHash = _checkForActiveAllocation(compact_.sponsor, compact_.lockTag, compact_.token);
        _checkAllocator(compact_.lockTag);
        _checkExpiration(compact_.expires);
        _checkAndSetNonce(compact_.nonce);
        _checkForcedWithdrawal(compact_.sponsor, compact_.expires, compact_.lockTag, compact_.token);
        _checkBalance(compact_.sponsor, _getTokenId(compact_.lockTag, compact_.token), compact_.amount);

        bytes32 claimHash = keccak256(
            abi.encode(
                typeHash_,
                compact_.arbiter,
                compact_.sponsor,
                compact_.nonce,
                compact_.expires,
                compact_.lockTag,
                compact_.token,
                compact_.amount,
                witness_
            )
        );

        _claim[claimHash] = true;
        _allocation[tokenHash] = _allocationData(compact_.amount, compact_.expires);

        emit Locked(compact_.sponsor, compact_.lockTag, compact_.token, compact_.amount, compact_.expires);
    }

    /// @inheritdoc IAllocator
    function attest(address, address from_, address, uint256 id_, uint256 amount_)
        external
        view
        onlyCompact
        returns (bytes4)
    {
        uint256 balance = ERC6909(COMPACT_CONTRACT).balanceOf(from_, id_);

        // Check unlocked balance
        bytes32 tokenHash = _getTokenHash(id_, from_);
        uint256 fullAmount = amount_;
        bytes32 allocation = _allocation[tokenHash];

        // Check for an active allocation and reduce the balance by the allocated amount
        if (_expiration(allocation) > block.timestamp) {
            // revert attestation if an active allocation is bigger then or equal to uint224
            uint256 amount = _amount(allocation);
            if (amount == type(uint224).max) {
                revert ExtensiveAllocationActive(from_, id_);
            }

            // add the allocated amount
            fullAmount += amount;
        }
        if (balance < fullAmount) {
            revert InsufficientBalance(from_, id_, balance, fullAmount);
        }

        return this.attest.selector;
    }

    /// @inheritdoc IAllocator
    function authorizeClaim(
        bytes32 claimHash, // The message hash representing the claim.
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256, /*expires*/ // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata /*allocatorData*/ // Arbitrary data provided by the arbiter.
    ) external virtual onlyCompact returns (bytes4) {
        if (!_claim[claimHash]) {
            revert InvalidLock(claimHash, 0);
        }

        // We expect the Compact to verify the expiration date is still valid and the nonce has not yet been consumed

        delete _claim[claimHash];

        // Delete all allocations connected to the claim
        uint256 length = idsAndAmounts.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes32 tokenHash = _getTokenHash(idsAndAmounts[i][0], sponsor);
            delete _allocation[tokenHash];
        }

        return this.authorizeClaim.selector;
    }

    /// @inheritdoc IAllocator
    function isClaimAuthorized(
        bytes32 claimHash,
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address, /*sponsor*/ // The account to source the tokens from.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata, /*idsAndAmounts*/ // The allocated token IDs and amounts.
        bytes calldata /*allocatorData*/ // Arbitrary data provided by the arbiter.
    ) external view virtual returns (bool) {
        return _claim[claimHash] && expires > block.timestamp;
    }

    /// @inheritdoc ISimpleAllocator
    /// @dev this will not return the full amount if the allocated amount is above uint224
    function checkTokensLocked(uint256 id_, address sponsor_)
        external
        view
        returns (uint256 amount_, uint256 expires_)
    {
        bytes32 tokenHash = _getTokenHash(id_, sponsor_);
        bytes32 allocation = _allocation[tokenHash];
        if (_expiration(allocation) <= block.timestamp) {
            return (0, 0);
        }

        return (_amount(allocation), _expiration(allocation));
    }

    /// @inheritdoc ISimpleAllocator
    function checkCompactLocked(Compact calldata compact_) external view returns (bool locked_, uint256 expires_) {
        bytes32 claimHash = keccak256(
            abi.encode(
                COMPACT_TYPEHASH,
                compact_.arbiter,
                compact_.sponsor,
                compact_.nonce,
                compact_.expires,
                compact_.lockTag,
                compact_.token,
                compact_.amount
            )
        );
        bool active = _claim[claimHash] && compact_.expires > block.timestamp;
        // No need to check the force withdrawal status, as that is checked when allocation the tokens.

        return (active, active ? compact_.expires : 0);
    }

    /// @inheritdoc ISimpleAllocator
    function checkCompactLocked(Compact calldata compact_, bytes32 witness_, bytes32 typeHash_)
        external
        view
        returns (bool locked_, uint256 expires_)
    {
        bytes32 claimHash = keccak256(
            abi.encode(
                typeHash_,
                compact_.arbiter,
                compact_.sponsor,
                compact_.nonce,
                compact_.expires,
                compact_.lockTag,
                compact_.token,
                compact_.amount,
                witness_
            )
        );
        bool active = _claim[claimHash] && compact_.expires > block.timestamp;
        // No need to check the force withdrawal status, as that is checked when allocation the tokens.

        return (active, active ? compact_.expires : 0);
    }

    function _getTokenHash(uint256 id_, address sponsor_) internal pure returns (bytes32) {
        return keccak256(abi.encode(id_, sponsor_));
    }

    function _getTokenHash(bytes12 lockTag_, address token_, address sponsor_) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(lockTag_, token_, bytes12(0), sponsor_));
    }

    function _checkMsgSender(address sponsor_) internal view {
        // Check msg.sender is sponsor
        if (msg.sender != sponsor_) {
            revert InvalidCaller(msg.sender, sponsor_);
        }
    }

    function _checkForActiveAllocation(address sponsor_, bytes12 lockTag_, address token_)
        internal
        view
        returns (bytes32)
    {
        bytes32 tokenHash = _getTokenHash(lockTag_, token_, sponsor_);
        // Check no lock is already active for this sponsor
        if (_expiration(_allocation[tokenHash]) > block.timestamp) {
            revert ClaimActive(sponsor_);
        }
        return tokenHash;
    }

    function _checkForcedWithdrawal(address sponsor_, uint256 expires_, bytes12 lockTag_, address token_)
        internal
        view
    {
        ResetPeriod resetPeriod = _getResetPeriod(lockTag_);
        // Check expiration is not longer then the tokens forced withdrawal time
        if (expires_ > block.timestamp + _resetPeriodToSeconds(resetPeriod)) {
            revert ForceWithdrawalAvailable(expires_, block.timestamp + _resetPeriodToSeconds(resetPeriod));
        }
        // Check expiration is not past an active force withdrawal
        (, uint256 forcedWithdrawalExpiration) =
            ITheCompact(COMPACT_CONTRACT).getForcedWithdrawalStatus(sponsor_, _getTokenId(lockTag_, token_));
        if (forcedWithdrawalExpiration != 0 && forcedWithdrawalExpiration < expires_) {
            revert ForceWithdrawalAvailable(expires_, forcedWithdrawalExpiration);
        }
    }

    // TODO: The compact V1 is likely to check this by using the registered allocator for the callback
    function _checkAllocator(bytes12 lockTag_) internal view {
        // Check the token allocator is this contract
        uint96 allocatorId = uint96(lockTag_ << 4 >> 4);
        if (allocatorId != ALLOCATOR_ID) {
            revert InvalidAllocator(allocatorId, ALLOCATOR_ID);
        }
    }

    function _checkExpiration(uint256 expires_) internal view {
        // Check expiration is not too soon or too late
        if (expires_ < block.timestamp + MIN_WITHDRAWAL_DELAY || expires_ > block.timestamp + MAX_WITHDRAWAL_DELAY) {
            revert InvalidExpiration(expires_);
        }
    }

    /// TODO: CHECK THIS NONCE BITMAPPING AND INCLUDE IT INTO THE ERC7683SimpleAllocator TO ELIMINATE DOUBLE LOGIC
    function _checkAndSetNonce(uint256 nonce_) internal {
        uint256 word = nonce_ / 256; // becomes a uint248
        uint256 bit = nonce_ % 256;
        // Check nonce is not yet consumed
        assembly ("memory-safe") {
            let nonceBitmap := sload(or(NONCE_MASTER_SLOT_SEED, word))
            if and(nonceBitmap, shl(bit, 1)) {
                let m := mload(0x40)
                mstore(m, 0x566053b0) // NonceAlreadyInUse()
                mstore(add(m, 0x20), nonce_)
                revert(add(m, 0x1c), 0x24)
            }
            sstore(or(NONCE_MASTER_SLOT_SEED, word), or(nonceBitmap, shl(bit, 1)))
        }
    }

    function _checkBalance(address sponsor_, uint256 id_, uint256 amount_) internal view {
        uint256 balance = ERC6909(COMPACT_CONTRACT).balanceOf(sponsor_, id_);
        // Check for sufficient balance
        if (balance < amount_) {
            revert InsufficientBalance(sponsor_, id_, balance, amount_);
        }
    }

    function _allocationData(uint256 amount_, uint256 expires_) internal pure returns (bytes32 data) {
        if (amount_ >= type(uint224).max) {
            data = bytes32(AMOUNT_MASK | bytes32(expires_));
        } else {
            data = bytes32(amount_ << EXPIRATION_BITS | expires_);
        }
    }

    function _amount(bytes32 allocationData_) internal pure returns (uint256 amount) {
        amount = uint256(allocationData_ >> EXPIRATION_BITS);
    }

    function _isMaxAllocation(bytes32 allocationData_) internal pure returns (bool) {
        return (allocationData_ & AMOUNT_MASK) == AMOUNT_MASK;
    }

    function _expiration(bytes32 allocationData_) internal pure returns (uint256 expires) {
        assembly ("memory-safe") {
            expires := shr(224, shl(224, allocationData_))
        }
    }

    function _getResetPeriod(bytes12 lockTag_) internal pure returns (ResetPeriod resetPeriod) {
        assembly ("memory-safe") {
            resetPeriod := shr(253, shl(1, lockTag_))
        }
        return ResetPeriod(resetPeriod);
    }

    function _getTokenId(bytes12 lockTag_, address token_) internal pure returns (uint256 id) {
        assembly ("memory-safe") {
            id := or(lockTag_, token_)
        }
        return id;
    }

    function _separateId(uint256 id_) internal pure returns (bytes12 lockTag_, address token_) {
        assembly ("memory-safe") {
            lockTag_ := id_
            token_ := and(id_, 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff)
        }
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
