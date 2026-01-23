// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOnChainAllocator} from '../interfaces/IOnChainAllocator.sol';

import {AllocatorLib as AL} from './lib/AllocatorLib.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {SafeTransferLib} from '@solady/utils/SafeTransferLib.sol';

import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {IOnChainAllocation} from '@uniswap/the-compact/interfaces/IOnChainAllocation.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {Extsload} from '@uniswap/the-compact/lib/Extsload.sol';
import {IdLib} from '@uniswap/the-compact/lib/IdLib.sol';
import {Lock} from '@uniswap/the-compact/types/EIP712Types.sol';
import {Utility} from '@uniswap/the-compact/utility/Utility.sol';

/// @title OnChainAllocator
/// @notice Allocates tokens deposited into the compact.
/// @dev The contract ensures tokens can not be double spent by a user in a fully decentralized manner.
/// @dev Users can open orders for themselves or for others by providing a signature or the tokens directly.
/// @custom:security-contact security@uniswap.org
contract OnChainAllocator is IOnChainAllocator, Utility {
    uint32 private constant _UINT32_MAX = 0xffffffff;
    bytes28 private constant _BYTES28_SELECTOR = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    /// @notice The chain id at the time of deployment
    uint256 private immutable _INITIAL_CHAIN_ID;
    /// @notice The EIP-712 domain separator for The Compact protocol, used for signature verification
    bytes32 public immutable COMPACT_DOMAIN_SEPARATOR;
    /// @notice The unique identifier for this allocator within The Compact protocol
    uint96 public immutable ALLOCATOR_ID;

    mapping(bytes28 tokenHash => uint32 nextExpiration) internal _nextExpirationPointer;
    /// @notice Similar to mapping(bytes28 tokenHash => mapping(uint32 expiration => BalanceExpiration balances)).
    mapping(bytes32 TokenHashWithExpiration => BalanceExpiration balances) internal _balancesByExpiration;
    mapping(bytes32 claimHash => uint32 normalizedExpiration) internal _allocatedClaims;

    /// @notice Mapping of user addresses to their current nonce for replay protection.
    /// @dev The actual nonce will be a combination of the next free nonce and the user address.
    mapping(address user => uint96 nonce) public nonces;

    modifier onlyCompact() {
        if (msg.sender != AL.THE_COMPACT) {
            revert InvalidCaller(msg.sender, AL.THE_COMPACT);
        }
        _;
    }

    constructor() {
        _INITIAL_CHAIN_ID = block.chainid;
        COMPACT_DOMAIN_SEPARATOR = ITheCompact(AL.THE_COMPACT).DOMAIN_SEPARATOR();
        try ITheCompact(AL.THE_COMPACT).__registerAllocator(address(this), '') returns (uint96 allocatorId) {
            ALLOCATOR_ID = allocatorId;
        } catch {
            // The Compact does not have a getter function for retrieving the status of allocator registration,
            // so we need to calculate it manually.
            uint96 allocatorId = IdLib.toAllocatorId(address(this));
            bytes32 allocatorSlot;
            assembly ("memory-safe") {
                // Identical to the registration logic slot calculation in The Compact:
                // let allocatorSlot := or(_ALLOCATOR_BY_ALLOCATOR_ID_SLOT_SEED, allocatorId)
                allocatorSlot := or(0x000044036fc77deaed2300000000000000000000000, allocatorId)
            }

            bytes32 registeredAllocator = Extsload(AL.THE_COMPACT).extsload(allocatorSlot);

            assembly ("memory-safe") {
                if iszero(eq(registeredAllocator, address())) {
                    // revert InvalidAllocatorRegistration(registeredAllocator)
                    mstore(0x00, 0x161ab6ea)
                    mstore(0x20, registeredAllocator)
                    revert(0x1c, 0x24)
                }
            }

            ALLOCATOR_ID = allocatorId;
        }
    }

    /// @inheritdoc IOnChainAllocator
    function allocate(Lock[] calldata commitments, address arbiter, uint32 expires, bytes32 typehash, bytes32 witness)
        public
        returns (bytes32 claimHash, uint256 claimNonce)
    {
        (claimHash, claimNonce) = _allocate(msg.sender, commitments, arbiter, expires, typehash, witness);

        emit Allocated(msg.sender, commitments, claimNonce, expires, claimHash);
    }

    /// @inheritdoc IOnChainAllocator
    function allocateFor(
        address sponsor,
        Lock[] calldata commitments,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata signature
    ) public returns (bytes32 claimHash, uint256 claimNonce) {
        (claimHash, claimNonce) = _allocate(sponsor, commitments, arbiter, expires, typehash, witness);

        // We check for the length, which means this could also be triggered by a zero length signature provided in the openFor function.
        // This enables relaying of orders if the claim was registered on the compact.
        if (signature.length > 0) {
            // confirm the provided signature is valid
            bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), COMPACT_DOMAIN_SEPARATOR, claimHash));
            if (block.chainid != _INITIAL_CHAIN_ID) {
                digest = keccak256(
                    abi.encodePacked(bytes2(0x1901), ITheCompact(AL.THE_COMPACT).DOMAIN_SEPARATOR(), claimHash)
                );
            }
            address signer_ = AL.recoverSigner(digest, signature);
            if (sponsor != signer_ || signer_ == address(0)) {
                revert InvalidSignature(signer_, sponsor);
            }
        } else {
            // confirm the claim hash is registered on the compact
            if (!ITheCompact(AL.THE_COMPACT).isRegistered(sponsor, claimHash, typehash)) {
                revert InvalidRegistration(sponsor, claimHash);
            }
        }
        emit Allocated(sponsor, commitments, claimNonce, expires, claimHash);
    }

    /// @inheritdoc IOnChainAllocator
    function allocateAndRegister(
        address recipient,
        Lock[] calldata commitments,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness
    ) public payable returns (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) {
        // Check for empty commitments
        if (commitments.length == 0) {
            revert InvalidCommitments();
        }
        if (expires <= block.timestamp) {
            revert InvalidExpiration(expires, block.timestamp);
        }

        recipient = AL.getRecipient(recipient);
        nonce = _getAndUpdateNonce(msg.sender, recipient);

        // Transformed locks will be stored in idsAndAmounts
        uint256[2][] memory idsAndAmounts = new uint256[2][](commitments.length);

        // Init minResetPeriod to the max value
        uint256 minResetPeriod = type(uint256).max;

        // Process native token (zero address) first
        uint256 i;
        if (commitments[i].token == address(0)) {
            // The Compact will revert if invalid value is provided for native token
            // Possible cases:
            // 1. The callvalue is zero but the first token is native
            // 2. the callvalue is nonzero but the first token is non-native
            // 3. the first token is native and the callvalue doesn't equal the first amount

            // Handle first and third points
            if (commitments[i].amount == 0 || commitments[i].amount != msg.value) {
                revert InvalidAmount(commitments[i].amount);
            }

            minResetPeriod = _checkInput(
                commitments[i].lockTag, commitments[i].token, commitments[i].amount, recipient, expires, minResetPeriod
            );

            idsAndAmounts[i][0] = AL.toId(commitments[i].lockTag, commitments[i].token);
            idsAndAmounts[i][1] = msg.value;

            unchecked {
                ++i;
            }
        } else {
            // Handle second point
            if (msg.value != 0) {
                revert InvalidAmount(msg.value);
            }
        }

        // Process the rest of the commitments
        for (; i < commitments.length; i++) {
            minResetPeriod = _checkInput(
                commitments[i].lockTag, commitments[i].token, commitments[i].amount, recipient, expires, minResetPeriod
            );

            address token = commitments[i].token;
            // Safe to cast - _checkInput validated that the value fits the uint224
            uint224 amount = uint224(commitments[i].amount);

            // If the amount is 0, we use the balance of the contract to deposit
            if (amount == 0) {
                uint256 balance = IERC20(token).balanceOf(address(this));
                // Check the amount fits in the supported range
                if (balance > type(uint224).max) {
                    revert InvalidAmount(balance);
                    // The balance limit of uint224.max might lead to unexpected behavior if an amount > type(uint224).max was previously deposited into the contract by a third party.
                    // To resolve this, allocate and register this token by providing the actual amount in the commitment.
                }
                amount = uint224(balance);
            }

            // Store the lock in idsAndAmounts
            idsAndAmounts[i][0] = AL.toId(commitments[i].lockTag, token);
            idsAndAmounts[i][1] = amount;

            // Approve the compact contract to spend the tokens.
            if (IERC20(token).allowance(address(this), AL.THE_COMPACT) < amount) {
                SafeTransferLib.safeApproveWithRetry(token, AL.THE_COMPACT, type(uint256).max);
            }
        }

        // Ensure expiration is less then the smallest reset period
        if (expires > block.timestamp + minResetPeriod) {
            revert InvalidExpiration(expires, block.timestamp + minResetPeriod);
        }

        // Deposit the tokens and register the claim in the compact
        (claimHash, registeredAmounts) = ITheCompact(AL.THE_COMPACT).batchDepositAndRegisterFor{value: msg.value}(
            recipient, idsAndAmounts, arbiter, nonce, expires, typehash, witness
        );

        // Update the commitments and store the allocation
        Lock[] memory registeredCommitments =
            _updateCommitmentsAndStoreAllocation(recipient, registeredAmounts, commitments, expires, claimHash);

        emit Allocated(recipient, registeredCommitments, nonce, expires, claimHash);

        return (claimHash, registeredAmounts, nonce);
    }

    /// @inheritdoc IOnChainAllocation
    function prepareAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata /* orderData */
    ) external returns (uint256 nonce) {
        if (expires > type(uint32).max) {
            revert InvalidExpiration(expires, type(uint32).max);
        }
        uint32 expiration = uint32(expires);
        nonce = _getNonce(msg.sender, recipient);

        AL.prepareAllocation(nonce, recipient, idsAndAmounts, arbiter, expiration, typehash, witness, ALLOCATOR_ID);

        return nonce;
    }

    /// @inheritdoc IOnChainAllocation
    function executeAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata /* orderData */
    ) external {
        if (expires > type(uint32).max) {
            revert InvalidExpiration(expires, type(uint32).max);
        }
        uint32 expiration = uint32(expires);
        uint256 nonce = _getAndUpdateNonce(msg.sender, recipient);

        (bytes32 claimHash, Lock[] memory commitments) =
            AL.executeAllocation(nonce, recipient, idsAndAmounts, arbiter, expires, typehash, witness);

        _executeAllocation(recipient, claimHash, commitments, expiration);

        emit Allocated(recipient, commitments, nonce, expiration, claimHash);
    }

    /// @inheritdoc IAllocator
    function attest(address, address from_, address, uint256 id_, uint256 amount_) external returns (bytes4) {
        // Can be called by anyone, as this will only clean up expired allocations.

        // do not use the settled balance, since this will be called within the _beforeTokenTransfer hook of the compact.
        uint256 balance = ERC6909(AL.THE_COMPACT).balanceOf(from_, id_);

        // Check unlocked balance
        bytes28 tokenHash = _getTokenHash(id_, from_);
        (uint256 allocatedBalance,,) = _readAllocatedBalance(tokenHash, type(uint32).max, false);
        uint256 fullAmount = amount_ + allocatedBalance;

        if (balance < fullAmount) {
            revert InsufficientBalance(from_, id_, balance - allocatedBalance, amount_);
        }

        return this.attest.selector;
    }

    /// @inheritdoc IAllocator
    function authorizeClaim(
        bytes32 claimHash, // The message hash representing the claim.
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address sponsor, // The account sponsoring the claim.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256, /*expires*/ // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) external virtual onlyCompact returns (bytes4) {
        (bool verified, uint32 normalizedExpiration) = _verifyClaim(claimHash);
        if (!verified) {
            revert InvalidClaim(claimHash);
        }

        // Delete the claim
        delete _allocatedClaims[claimHash];

        // If allocatorData is provided, ensure the length matches the expectation
        if (allocatorData.length != 0 && allocatorData.length != 4 * idsAndAmounts.length) {
            revert InvalidHint(allocatorData.length, 4 * idsAndAmounts.length);
        }

        // Delete the allocations
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            bytes28 tokenHash = _getTokenHash(idsAndAmounts[i][0], sponsor);

            uint32 hint = 0;
            if (allocatorData.length != 0) {
                assembly ("memory-safe") {
                    hint := shr(224, calldataload(add(allocatorData.offset, mul(i, 4 /* uint32 */ ))))
                }
            }
            // The amount is at this point verified to be within the range of uint224.max
            _deleteAllocatedBalance(tokenHash, normalizedExpiration, uint224(idsAndAmounts[i][1]), hint);
        }

        return this.authorizeClaim.selector;
    }

    /// @inheritdoc IAllocator
    function isClaimAuthorized(
        bytes32 claimHash,
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address, /*sponsor*/ // The account sponsoring the claim.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata /*allocatorData*/ // Arbitrary data provided by the arbiter.
    ) external view virtual returns (bool) {
        if (expires <= block.timestamp) {
            return false;
        }

        // We only need to check the first id to confirm or deny the claim.
        if (idsAndAmounts.length == 0) {
            return false;
        }
        (bool verified,) = _verifyClaim(claimHash);

        return verified;
    }

    /// @inheritdoc IOnChainAllocator
    function getNormalizedExpirationForClaim(bytes32 claimHash) external view returns (uint32 normalizedExpiration) {
        normalizedExpiration = _allocatedClaims[claimHash];
        return normalizedExpiration;
    }

    function _allocate(
        address sponsor,
        Lock[] calldata commitments,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness
    ) private returns (bytes32 claimHash, uint256 nonce) {
        if (commitments.length == 0) {
            revert InvalidCommitments();
        }
        if (expires <= block.timestamp) {
            revert InvalidExpiration(expires, block.timestamp);
        }

        uint32 normalizedExpiration = _normalizeExpiration(expires);

        nonce = _getAndUpdateNonce(address(0), sponsor); // address(0) as caller allows anyone to relay
        bytes32 commitmentsHash = AL.getCommitmentsHash(commitments);
        claimHash = AL.getClaimHash(arbiter, sponsor, nonce, expires, commitmentsHash, witness, typehash);

        uint256 minResetPeriod = type(uint256).max;
        for (uint256 i = 0; i < commitments.length; i++) {
            minResetPeriod = _checkInput(
                commitments[i].lockTag, commitments[i].token, commitments[i].amount, sponsor, expires, minResetPeriod
            );
            (bytes28 tokenHash, uint32 previousExpirationPointer, uint32 nextExpirationPointer) =
                _checkBalance(sponsor, commitments[i], normalizedExpiration);

            // Store the allocation
            uint224 amount = uint224(commitments[i].amount);
            _storeAllocatedBalance(
                tokenHash, amount, normalizedExpiration, previousExpirationPointer, nextExpirationPointer
            );
        }
        // Ensure expiration is not bigger then the smallest reset period
        if (expires > block.timestamp + minResetPeriod) {
            revert InvalidExpiration(expires, block.timestamp + minResetPeriod);
        }

        // Store the claim
        _storeClaim(claimHash, normalizedExpiration);

        return (claimHash, nonce);
    }

    function _executeAllocation(address recipient, bytes32 claimHash, Lock[] memory commitments, uint32 expires)
        private
    {
        // External allocation requires to normalize the expiration time
        uint32 normalizedExpires = _normalizeExpiration(expires);

        uint256 minResetPeriod = type(uint256).max;

        // Allocate the claim
        for (uint256 i = 0; i < commitments.length; i++) {
            Lock memory commitment = commitments[i];

            minResetPeriod =
                _checkInput(commitment.lockTag, commitment.token, commitment.amount, recipient, expires, minResetPeriod);

            // Store the allocation
            _storeAllocatedBalance(
                commitment.lockTag, commitment.token, recipient, uint224(commitment.amount), normalizedExpires
            );
        }

        // Ensure expiration is not bigger then the smallest reset period
        if (expires > block.timestamp + minResetPeriod) {
            revert InvalidExpiration(expires, block.timestamp + minResetPeriod);
        }

        // Store the claim
        _storeClaim(claimHash, normalizedExpires);
    }

    function _updateCommitmentsAndStoreAllocation(
        address recipient,
        uint256[] memory registeredAmounts,
        Lock[] memory commitments,
        uint32 expires,
        bytes32 claimHash
    ) private returns (Lock[] memory) {
        // External allocation requires to normalize the expiration time
        expires = _normalizeExpiration(expires);
        // Store the allocation
        for (uint256 i = 0; i < registeredAmounts.length; i++) {
            // Update the allocations with the actual registered amounts
            uint224 amount = uint224(registeredAmounts[i]);
            commitments[i].amount = amount;

            // Store the allocation
            _storeAllocatedBalance(commitments[i].lockTag, commitments[i].token, recipient, amount, expires);
        }

        // Store the claim
        _storeClaim(claimHash, expires);

        return commitments;
    }

    function _checkBalance(address sponsor, Lock calldata commitment, uint32 expires)
        private
        returns (bytes28 tokenHash, uint32 previousExpirationPointer, uint32 nextExpirationPointer)
    {
        // Check the balance of the recipient is sufficient
        tokenHash = _getTokenHash(commitment.lockTag, commitment.token, sponsor);
        uint256 balance = settledBalanceOf(sponsor, AL.toId(commitment.lockTag, commitment.token));
        uint256 allocatedBalance;
        (allocatedBalance, previousExpirationPointer, nextExpirationPointer) =
            _readAllocatedBalance(tokenHash, expires, false);
        uint256 requiredBalance = allocatedBalance + commitment.amount;
        if (requiredBalance > balance) {
            revert InsufficientBalance(
                sponsor, AL.toId(commitment.lockTag, commitment.token), balance - allocatedBalance, commitment.amount
            );
        }
    }

    function _storeClaim(bytes32 claimHash, uint32 normalizedExpiration) private {
        uint32 currentExpiration = _allocatedClaims[claimHash];
        if (currentExpiration > 0) {
            revert InvalidClaim(claimHash);
        }
        _allocatedClaims[claimHash] = normalizedExpiration;
    }

    function _readAllocatedBalance(bytes28 tokenHash, uint32 normalizedExpiration, bool onlyReturnPointers)
        private
        returns (uint256 allocatedBalance, uint32 previousExpirationPointer, uint32 nextExpirationPointer)
    {
        assembly ("memory-safe") {
            mstore(0x00, tokenHash)
            mstore(0x20, _nextExpirationPointer.slot)
            let _nextExpirationPointerSlot := keccak256(0x00, 0x40)
            let originalNextExpiration := sload(_nextExpirationPointerSlot)
            // Check if there are any allocated balances
            if iszero(originalNextExpiration) {
                // No allocated balance detected
                nextExpirationPointer := _UINT32_MAX
            }
            if iszero(nextExpirationPointer) {
                // Other allocated balances detected. Accumulate non expired balances
                let nextExpiration := originalNextExpiration

                // Store _balancesByExpiration.slot in advance to skip repeating calls in loops
                mstore(0x20, _balancesByExpiration.slot)

                // Loop through the expired balances and remove them
                for {} iszero(gt(nextExpiration, timestamp())) {} {
                    // Found expired balance, remove it
                    mstore(0x00, or(tokenHash, nextExpiration))
                    // Previously stored _balancesByExpiration.slot in 0x20
                    let pointer := keccak256(0x00, 0x40)
                    nextExpiration := and(sload(pointer), _UINT32_MAX)
                    // Delete
                    sstore(pointer, 0)
                }
                // Check if the next expiration pointer has changed during the loop. If so, update the pointer.
                if iszero(eq(nextExpiration, originalNextExpiration)) {
                    // Set nextExpiration to 0 if this was the last allocation (nextExpiration == type(uint32).max)
                    let nextExpirationFixed := mul(nextExpiration, lt(nextExpiration, _UINT32_MAX))
                    // Store nextExpirationFixed in _nextExpirationPointer[tokenHash]
                    sstore(_nextExpirationPointerSlot, nextExpirationFixed)
                }

                // Read the balances that expire before the ongoing allocation
                for {} gt(normalizedExpiration, nextExpiration) {} {
                    // Cache the previous expiration pointer
                    previousExpirationPointer := nextExpiration
                    mstore(0x00, or(tokenHash, nextExpiration))
                    // Previously stored _balancesByExpiration.slot in 0x20
                    let balanceStruct := sload(keccak256(0x00, 0x40))
                    allocatedBalance := add(allocatedBalance, shr(32, balanceStruct))
                    nextExpiration := and(balanceStruct, _UINT32_MAX)
                }
                // Cache the next expiration pointer
                nextExpirationPointer := nextExpiration

                // Check if not only the pointers are requested
                if iszero(onlyReturnPointers) {
                    for {} lt(nextExpiration, _UINT32_MAX) {} {
                        mstore(0x00, or(tokenHash, nextExpiration))
                        // Previously stored _balancesByExpiration.slot in 0x20
                        let balanceStruct := sload(keccak256(0x00, 0x40))
                        allocatedBalance := add(allocatedBalance, shr(32, balanceStruct))
                        nextExpiration := and(balanceStruct, _UINT32_MAX)
                    }
                }
            }
        }

        return (allocatedBalance, previousExpirationPointer, nextExpirationPointer);
    }

    function _storeAllocatedBalance(
        bytes28 tokenHash,
        uint224 amount,
        uint32 normalizedExpiration,
        uint32 previousExpirationPointer,
        uint32 nextExpirationPointer
    ) private {
        assembly ("memory-safe") {
            for {} true {} {
                // Check if if there is already an allocation for the same expiration
                if eq(normalizedExpiration, nextExpirationPointer) {
                    // Update the amount of the existing allocation and exit
                    mstore(0x00, or(tokenHash, normalizedExpiration))
                    mstore(0x20, _balancesByExpiration.slot)
                    let pointer := keccak256(0x00, 0x40)
                    let balanceStruct := sload(pointer)
                    let currentAllocation := shr(32, balanceStruct)
                    let newAllocatedAmount := add(currentAllocation, amount)
                    if lt(newAllocatedAmount, currentAllocation) {
                        // Revert for overflow
                        revert(0x00, 0x00)
                    }
                    let balanceStructWithoutAmount := and(balanceStruct, _UINT32_MAX)
                    sstore(pointer, or(shl(32, newAllocatedAmount), balanceStructWithoutAmount))

                    break
                }

                // Create and store the new allocation
                mstore(0x00, or(tokenHash, normalizedExpiration))
                mstore(0x20, _balancesByExpiration.slot)
                sstore(keccak256(0x00, 0x40), or(shl(32, amount), nextExpirationPointer))

                // Check if there are any balances expiring earlier than the new allocation
                if previousExpirationPointer {
                    // Insert the allocation into the linked list by updating the pointer of the earlier expiring allocation
                    mstore(0x00, or(tokenHash, previousExpirationPointer))
                    // Previously stored _balancesByExpiration.slot in 0x20
                    let pointer := keccak256(0x00, 0x40)
                    let balanceStructWithoutExpiration := and(sload(pointer), _BYTES28_SELECTOR)
                    // Write the updated struct to storage
                    sstore(pointer, or(balanceStructWithoutExpiration, normalizedExpiration))

                    break
                }

                // At this point, there must not be any balances expiring earlier than the new allocation

                // Update the _nextExpirationPointer pointer to the new allocation
                mstore(0x00, tokenHash)
                mstore(0x20, _nextExpirationPointer.slot)
                sstore(keccak256(0x00, 0x40), normalizedExpiration)

                break
            }
        }
    }

    function _storeAllocatedBalance(
        bytes12 lockTag,
        address token,
        address recipient,
        uint224 amount,
        uint32 normalizedExpiration
    ) private {
        bytes28 tokenHash = _getTokenHash(lockTag, token, recipient);
        (, uint32 previousExpirationPointer, uint32 nextExpirationPointer) =
            _readAllocatedBalance(tokenHash, normalizedExpiration, true);
        _storeAllocatedBalance(
            tokenHash, amount, normalizedExpiration, previousExpirationPointer, nextExpirationPointer
        );
    }

    function _deleteAllocatedBalance(bytes28 tokenHash, uint32 normalizedExpiration, uint224 amount, uint32 hint)
        private
    {
        assembly ("memory-safe") {
            for {} true {} {
                mstore(0x00, or(tokenHash, normalizedExpiration))
                mstore(0x20, _balancesByExpiration.slot)
                let balancesByExpirationPointer := keccak256(0x00, 0x40)
                let balanceStruct := sload(balancesByExpirationPointer)
                let allocation := shr(32, balanceStruct)
                let nextExpiration := and(balanceStruct, _UINT32_MAX)

                // Check if there is more allocated balance at the expiration than the amount to delete
                if gt(allocation, amount) {
                    sstore(balancesByExpirationPointer, or(shl(32, sub(allocation, amount)), nextExpiration))
                    break
                }

                // Delete the full allocation
                sstore(balancesByExpirationPointer, 0)

                // Find the previous expiration to update the pointers
                mstore(0x00, tokenHash)
                mstore(0x20, _nextExpirationPointer.slot)
                let _nextExpirationPointerSlot := keccak256(0x00, 0x40)
                let previousExpiration := sload(_nextExpirationPointerSlot)

                // Check if the allocation is the earliest expiring
                if eq(previousExpiration, normalizedExpiration) {
                    // Check if another allocation exists after this one. If so, update the pointer, else delete
                    nextExpiration := mul(nextExpiration, lt(nextExpiration, _UINT32_MAX))
                    sstore(_nextExpirationPointerSlot, nextExpiration)
                    break
                }

                // Store _balancesByExpiration.slot in advance to skip repeating calls
                mstore(0x20, _balancesByExpiration.slot)

                let previousBalanceStruct
                if hint {
                    mstore(0x00, or(tokenHash, and(hint, _UINT32_MAX))) // sanitizes hint
                    balancesByExpirationPointer := keccak256(0x00, 0x40)
                    previousBalanceStruct := sload(balancesByExpirationPointer)
                    let hintNextExpiration := and(previousBalanceStruct, _UINT32_MAX)
                    // Verify the hints next pointer is valid.
                    // It must be greater then the head pointer, as well as smaller or equal to the target expiration.
                    // Ideally the hints next pointer is equal to the target expiration. This will skip the next loop completely
                    let validHint :=
                        and(
                            gt(hintNextExpiration, previousExpiration), iszero(gt(hintNextExpiration, normalizedExpiration))
                        )

                    // Branchless: validHint ? hintNextExpiration : previousExpiration
                    // Setting previousExpiration = normalizedExpiration makes loop condition false, skipping it
                    previousExpiration :=
                        or(mul(previousExpiration, iszero(validHint)), mul(hintNextExpiration, validHint))
                }

                // Loop through the previously expiring balances to find the previous pointer
                for {} lt(previousExpiration, normalizedExpiration) {} {
                    mstore(0x00, or(tokenHash, previousExpiration))
                    balancesByExpirationPointer := keccak256(0x00, 0x40)
                    previousBalanceStruct := sload(balancesByExpirationPointer)
                    // Iterate previousExpiration to nextExpiration
                    previousExpiration := and(previousBalanceStruct, _UINT32_MAX)
                }

                // Update the next expiration pointer of the previous expiration
                sstore(balancesByExpirationPointer, or(and(previousBalanceStruct, _BYTES28_SELECTOR), nextExpiration))

                break
            }
        }
    }

    function _getAndUpdateNonce(address calling, address sponsor) internal returns (uint256 nonce) {
        assembly ("memory-safe") {
            sponsor := mul(sponsor, iszero(calling))
            mstore(0x00, sponsor)
            mstore(0x20, nonces.slot)
            let nonceSlot := keccak256(0x00, 0x40)
            let nonce96 := sload(nonceSlot)
            nonce := or(shl(96, sponsor), add(nonce96, 1))
            sstore(nonceSlot, add(nonce96, 1))
        }
    }

    function _getNonce(address calling, address sponsor) internal view returns (uint256 nonce) {
        assembly ("memory-safe") {
            sponsor := mul(sponsor, iszero(calling))
            mstore(0x00, sponsor)
            mstore(0x20, nonces.slot)
            let nonceSlot := keccak256(0x00, 0x40)
            let nonce96 := sload(nonceSlot)
            nonce := or(shl(96, sponsor), add(nonce96, 1))
        }
    }

    function _checkInput(
        bytes12 lockTag,
        address token,
        uint256 amount,
        address sponsor,
        uint32 expires,
        uint256 minResetPeriod
    ) internal view returns (uint256) {
        // Check the allocator id fits this allocator
        if (AL.splitAllocatorId(lockTag) != ALLOCATOR_ID) {
            revert InvalidAllocator(AL.splitAllocatorId(lockTag), ALLOCATOR_ID);
        }

        // Check the amount fits in the supported range
        if (amount > type(uint224).max) {
            revert InvalidAmount(amount);
        }

        // Get the reset period for the token id
        uint256 duration = AL.toSeconds(lockTag);
        if (duration < minResetPeriod) {
            minResetPeriod = duration;
        }

        // Ensure no forcedWithdrawal is active for the token id
        (, uint256 forcedWithdrawal) =
            ITheCompact(AL.THE_COMPACT).getForcedWithdrawalStatus(sponsor, AL.toId(lockTag, token));
        if (forcedWithdrawal != 0 && forcedWithdrawal <= expires) {
            revert ForceWithdrawalAvailable(expires, forcedWithdrawal);
        }

        return minResetPeriod;
    }

    function _verifyClaim(bytes32 claimHash) private view returns (bool verified, uint32 normalizedExpiration) {
        // Check if the claim is allocated
        normalizedExpiration = _allocatedClaims[claimHash];
        return (normalizedExpiration != 0, normalizedExpiration);
    }

    function _normalizeExpiration(uint32 expires) private view returns (uint32 normalizedExpires) {
        uint256 timeRemaining = expires - block.timestamp;
        if (timeRemaining < 10 minutes) {
            // No rounding - max size of 600 unique expirations
            normalizedExpires = expires;
        } else if (timeRemaining < 1 hours + 5 minutes) {
            // total of 55 minutes
            // Round up to the nearest 10 seconds - max size of 330 unique expirations
            normalizedExpires = (expires / 10 seconds) * 10 seconds + 10 seconds;
        } else if (timeRemaining < 1 days) {
            // total of 1,375 minutes
            // Round up to the nearest minute - max size of 1375 unique expirations
            normalizedExpires = (expires / 1 minutes) * 1 minutes + 1 minutes;
        } else if (timeRemaining < 1 weeks + 1 hours) {
            // total of 8,700 minutes
            // Round up to the nearest 10 minutes - max size of 870 unique expirations
            normalizedExpires = (expires / 10 minutes) * 10 minutes + 10 minutes;
        } else {
            // < 30 days - total of 33,060 minutes
            // Round up to the nearest hour - max size of 551 unique expirations
            normalizedExpires = (expires / 1 hours) * 1 hours + 1 hours;
        }
        // Total max of 3,726 unique expirations => 7,824,600 max gas costs for cold storage reads

        // Sanitize expiration
        assembly ("memory-safe") {
            normalizedExpires := and(normalizedExpires, _UINT32_MAX)
        }
    }

    function _generatePointer(bytes28 tokenHash, uint32 expiration) private pure returns (bytes32 pointer) {
        // Make sure the expiration is the most significant 32 bits
        assembly ("memory-safe") {
            pointer := or(tokenHash, expiration)
        }
    }

    function _getTokenHash(bytes12 lockTag, address token, address sponsor) private pure returns (bytes28 tokenHash) {
        assembly ("memory-safe") {
            mstore(0x00, lockTag)
            mstore(0x0c, shl(96, token))
            mstore(0x20, sponsor)
            tokenHash := and(keccak256(0x00, 0x40), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000)
        }
    }

    function _getTokenHash(uint256 id, address sponsor) private pure returns (bytes28 tokenHash) {
        assembly ("memory-safe") {
            mstore(0x00, id)
            mstore(0x20, sponsor)
            tokenHash := and(keccak256(0x00, 0x40), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000)
        }
    }
}
