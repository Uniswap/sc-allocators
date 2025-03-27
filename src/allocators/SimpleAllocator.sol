// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IAllocator} from '../interfaces/IAllocator.sol';
import {ISimpleAllocator} from '../interfaces/ISimpleAllocator.sol';
import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {ResetPeriod} from '@uniswap/the-compact/lib/IdLib.sol';
import {Compact} from '@uniswap/the-compact/types/EIP712Types.sol';
import {ForcedWithdrawalStatus} from '@uniswap/the-compact/types/ForcedWithdrawalStatus.sol';

contract SimpleAllocator is ISimpleAllocator {
    // keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount)")
    bytes32 constant COMPACT_TYPEHASH = 0xcdca950b17b5efc016b74b912d8527dfba5e404a688cbc3dab16cb943287fec2;

    address public immutable COMPACT_CONTRACT;
    uint256 public immutable MIN_WITHDRAWAL_DELAY;
    uint256 public immutable MAX_WITHDRAWAL_DELAY;

    uint256 private constant EXPIRATION_BITS = 32;
    uint256 private constant AMOUNT_BITS = 224;

    // Bit masks
    uint256 private constant EXPIRATION_MASK = ((1 << EXPIRATION_BITS) - 1);
    bytes32 private constant AMOUNT_MASK = bytes32(((1 << AMOUNT_BITS) - 1) << EXPIRATION_BITS);

    /// @dev mapping of tokenHash to the expiration of the lock
    mapping(bytes32 claimHash => bool active) internal _claim;
    /// @dev mapping of tokenHash to the uint224 amount and uint32 expiration of the lock
    mapping(bytes32 tokenHash => bytes32 amountAndExpiration) internal _allocation;

    constructor(address compactContract_, uint256 minWithdrawalDelay_, uint256 maxWithdrawalDelay_) {
        COMPACT_CONTRACT = compactContract_;
        MIN_WITHDRAWAL_DELAY = minWithdrawalDelay_;
        MAX_WITHDRAWAL_DELAY = maxWithdrawalDelay_;

        ITheCompact(COMPACT_CONTRACT).__registerAllocator(address(this), '');
    }

    /// @inheritdoc ISimpleAllocator
    function lock(Compact calldata compact_) external {
        _checkMsgSender(compact_.sponsor);
        bytes32 tokenHash = _checkForActiveAllocation(compact_.sponsor, compact_.id);
        _checkAllocator(compact_.id);
        _checkExpiration(compact_.expires);
        _checkNonce(compact_.nonce);
        _checkForcedWithdrawal(compact_.sponsor, compact_.expires, compact_.id);
        _checkBalance(compact_.sponsor, compact_.id, compact_.amount);

        bytes32 claimHash = keccak256(
            abi.encode(
                COMPACT_TYPEHASH,
                compact_.arbiter,
                compact_.sponsor,
                compact_.nonce,
                compact_.expires,
                compact_.id,
                compact_.amount
            )
        );

        _claim[claimHash] = true;
        _allocation[tokenHash] = _allocationData(compact_.amount, compact_.expires);

        emit Locked(compact_.sponsor, compact_.id, compact_.amount, compact_.expires);
    }

    function lock(Compact calldata compact_, bytes32 witness_, bytes32 typeHash_) external {
        _checkMsgSender(compact_.sponsor);
        bytes32 tokenHash = _checkForActiveAllocation(compact_.sponsor, compact_.id);
        _checkAllocator(compact_.id);
        _checkExpiration(compact_.expires);
        _checkNonce(compact_.nonce);
        _checkForcedWithdrawal(compact_.sponsor, compact_.expires, compact_.id);
        _checkBalance(compact_.sponsor, compact_.id, compact_.amount);

        bytes32 claimHash = keccak256(
            abi.encode(
                typeHash_,
                compact_.arbiter,
                compact_.sponsor,
                compact_.nonce,
                compact_.expires,
                compact_.id,
                compact_.amount,
                witness_
            )
        );

        _claim[claimHash] = true;
        _allocation[tokenHash] = _allocationData(compact_.amount, compact_.expires);

        emit Locked(compact_.sponsor, compact_.id, compact_.amount, compact_.expires);
        /// TODO: Implement witness
    }

    /// @inheritdoc IAllocator
    function attest(address, address from_, address, uint256 id_, uint256 amount_) external view returns (bytes4) {
        if (msg.sender != COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, COMPACT_CONTRACT);
        }
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

    function registerClaim(
        bytes32 claimHash, // The message hash representing the claim.
        address, /* caller */ // The account initiating the registration.
        address, /* arbiter */ // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256, /* nonce */ // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata /*allocatorData*/ // Arbitrary data provided by the caller.
    ) external virtual returns (bytes4) {
        if (msg.sender != COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, COMPACT_CONTRACT);
        }
        _checkExpiration(expires);
        // We trust the compact to check the nonce and that this contract is the allocator connected to the id

        uint256 length = idsAndAmounts.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes32 tokenHash = _checkForActiveAllocation(sponsor, idsAndAmounts[i][0]);
            _checkForcedWithdrawal(sponsor, expires, idsAndAmounts[i][0]);
            _checkBalance(sponsor, idsAndAmounts[i][0], idsAndAmounts[i][1]); // TODO: Should the Compact check this prior to the callback?

            _allocation[tokenHash] = _allocationData(idsAndAmounts[i][1], expires);
        }

        _claim[claimHash] = true;

        return this.registerClaim.selector;
    }

    function authorizeClaim(
        bytes32 claimHash, // The message hash representing the claim.
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address sponsor, // The account to source the tokens from.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256, /*expires*/ // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata /*allocatorData*/ // Arbitrary data provided by the arbiter.
    ) external virtual returns (bytes4) {
        if (msg.sender != COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, COMPACT_CONTRACT);
        }

        if (!_claim[claimHash]) {
            revert InvalidLock(claimHash, 0);
        }
        delete _claim[claimHash];

        // Delete all allocations connected to the claim
        uint256 length = idsAndAmounts.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes32 tokenHash = _getTokenHash(idsAndAmounts[i][0], sponsor);
            delete _allocation[tokenHash];
        }

        // We expect the Compact to verify the expiration date is still valid and the nonce has not yet been consumed

        return this.authorizeClaim.selector;
    }

    function allocatorDataSpecification()
        external
        pure
        returns (
            uint256 specificationId, // An identifier indicating a required "standard" for allocatorData.
            string memory claimEncoding, // The encoding of the `allocatorData` payload on claim processing.
            string memory registrationEncoding, // The encoding of the `allocatorData` payload on claim registration.
            bytes memory context // Any additional context as defined by the specificationId.
        )
    {
        specificationId = 0;
        claimEncoding = '';
        registrationEncoding = '';
        context = '';
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
                compact_.id,
                compact_.amount
            )
        );
        bool valid = _claim[claimHash];
        bool active = valid && compact_.expires > block.timestamp;
        // No need to check the force withdrawal status, as that is checked when allocation the tokens.

        return (active, active ? compact_.expires : 0);
    }

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
                compact_.id,
                compact_.amount,
                witness_
            )
        );
        bool valid = _claim[claimHash];
        bool active = valid && compact_.expires > block.timestamp;
        // No need to check the force withdrawal status, as that is checked when allocation the tokens.

        return (active, active ? compact_.expires : 0);
    }

    function _getTokenHash(uint256 id_, address sponsor_) internal pure returns (bytes32) {
        return keccak256(abi.encode(id_, sponsor_));
    }

    function _checkMsgSender(address sponsor_) internal view {
        // Check msg.sender is sponsor
        if (msg.sender != sponsor_) {
            revert InvalidCaller(msg.sender, sponsor_);
        }
    }

    function _checkForActiveAllocation(address sponsor_, uint256 id_) internal view returns (bytes32) {
        bytes32 tokenHash = _getTokenHash(id_, sponsor_);
        // Check no lock is already active for this sponsor
        if (_allocation[tokenHash] != 0) {
            revert ClaimActive(sponsor_);
        }
        return tokenHash;
    }

    function _checkForcedWithdrawal(address sponsor_, uint256 expires_, uint256 id_) internal view {
        ResetPeriod resetPeriod = _getResetPeriod(id_);
        // Check expiration is not longer then the tokens forced withdrawal time
        if (expires_ > block.timestamp + _resetPeriodToSeconds(resetPeriod)) {
            revert ForceWithdrawalAvailable(expires_, block.timestamp + _resetPeriodToSeconds(resetPeriod));
        }
        // Check expiration is not past an active force withdrawal
        (, uint256 forcedWithdrawalExpiration) = ITheCompact(COMPACT_CONTRACT).getForcedWithdrawalStatus(sponsor_, id_);
        if (forcedWithdrawalExpiration != 0 && forcedWithdrawalExpiration < expires_) {
            revert ForceWithdrawalAvailable(expires_, forcedWithdrawalExpiration);
        }
    }

    // TODO: The compact V1 is likely to check this by using the registered allocator for the callback
    function _checkAllocator(uint256 id_) internal view {
        // Check the token allocator is this
        (, address allocator,,) = ITheCompact(COMPACT_CONTRACT).getLockDetails(id_);
        if (allocator != address(this)) {
            revert InvalidAllocator(allocator);
        }
    }

    function _checkExpiration(uint256 expires_) internal view {
        // Check expiration is not too soon or too late
        if (expires_ < block.timestamp + MIN_WITHDRAWAL_DELAY || expires_ > block.timestamp + MAX_WITHDRAWAL_DELAY) {
            revert InvalidExpiration(expires_);
        }
    }

    /// TODO: Can we remove this for a callback and simply trust the Compact to check this prior to the callback?
    function _checkNonce(uint256 nonce_) internal view {
        // Check nonce is not yet consumed
        if (ITheCompact(COMPACT_CONTRACT).hasConsumedAllocatorNonce(nonce_, address(this))) {
            revert NonceAlreadyConsumed(nonce_);
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

    function _getResetPeriod(uint256 id_) internal pure returns (ResetPeriod resetPeriod) {
        assembly ("memory-safe") {
            resetPeriod := shr(253, shl(1, id_))
        }
        return ResetPeriod(resetPeriod);
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
