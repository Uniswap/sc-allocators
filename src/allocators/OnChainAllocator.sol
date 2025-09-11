// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOnChainAllocator} from '../interfaces/IOnChainAllocator.sol';

import {AllocatorLib as AL} from './lib/AllocatorLib.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {SafeTransferLib} from '@solady/utils/SafeTransferLib.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

/// @title OnChainAllocator
/// @notice Allocates tokens deposited into the compact.
/// @dev The contract ensures tokens can not be double spent by a user in a fully decentralized manner.
/// @dev Users can open orders for themselves or for others by providing a signature or the tokens directly.
contract OnChainAllocator is IOnChainAllocator {
    address public immutable COMPACT_CONTRACT;
    bytes32 public immutable COMPACT_DOMAIN_SEPARATOR;
    uint96 public immutable ALLOCATOR_ID;

    mapping(bytes32 tokenHash => Allocation[] allocations) internal _allocations;

    mapping(address user => uint96 nonce) public nonces;

    modifier onlyCompact() {
        if (msg.sender != COMPACT_CONTRACT) {
            revert InvalidCaller(msg.sender, COMPACT_CONTRACT);
        }
        _;
    }

    constructor(address compactContract_) {
        COMPACT_CONTRACT = compactContract_;
        COMPACT_DOMAIN_SEPARATOR = ITheCompact(COMPACT_CONTRACT).DOMAIN_SEPARATOR();
        ALLOCATOR_ID = ITheCompact(COMPACT_CONTRACT).__registerAllocator(address(this), '');
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
            address signer_ = AL.recoverSigner(digest, signature);
            if (sponsor != signer_ || signer_ == address(0)) {
                revert InvalidSignature(signer_, sponsor);
            }
        } else {
            // confirm the claim hash is registered on the compact
            if (!ITheCompact(COMPACT_CONTRACT).isRegistered(sponsor, claimHash, typehash)) {
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
    ) public returns (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) {
        nonce = _getAndUpdateNonce(msg.sender, recipient);

        uint256[2][] memory idsAndAmounts = new uint256[2][](commitments.length);

        uint256 minResetPeriod = type(uint256).max;
        for (uint256 i = 0; i < commitments.length; i++) {
            minResetPeriod = _checkInput(commitments[i], recipient, expires, minResetPeriod);
            idsAndAmounts[i][0] = AL.toId(commitments[i].lockTag, commitments[i].token);
            uint224 amount = uint224(commitments[i].amount);

            // If the amount is 0, we use the balance of the contract to deposit.
            if (amount == 0) {
                amount = uint224(IERC20(commitments[i].token).balanceOf(address(this)));
            }
            idsAndAmounts[i][1] = amount;

            // Approve the compact contract to spend the tokens.
            if (IERC20(commitments[i].token).allowance(address(this), COMPACT_CONTRACT) < amount) {
                SafeTransferLib.safeApproveWithRetry(commitments[i].token, COMPACT_CONTRACT, type(uint256).max);
            }
        }
        // Ensure expiration is not bigger then the smallest reset period
        if (expires >= block.timestamp + minResetPeriod) {
            revert InvalidExpiration(expires, block.timestamp + minResetPeriod);
        }

        // Deposit the tokens and register the claim in the compact
        (claimHash, registeredAmounts) = ITheCompact(COMPACT_CONTRACT).batchDepositAndRegisterFor(
            recipient, idsAndAmounts, arbiter, nonce, expires, typehash, witness
        );

        // Update the commitments and store the allocation
        Lock[] memory registeredCommitments =
            _updateCommitmentsAndStoreAllocation(recipient, registeredAmounts, commitments, expires, claimHash);

        emit Allocated(recipient, registeredCommitments, nonce, expires, claimHash);

        return (claimHash, registeredAmounts, nonce);
    }

    function _updateCommitmentsAndStoreAllocation(
        address recipient,
        uint256[] memory registeredAmounts,
        Lock[] memory commitments,
        uint32 expires,
        bytes32 claimHash
    ) internal returns (Lock[] memory) {
        // Store the allocation
        for (uint256 i = 0; i < registeredAmounts.length; i++) {
            // Update the allocations with the actual registered amounts
            uint224 amount = uint224(registeredAmounts[i]);
            commitments[i].amount = amount;

            // Store the allocation
            _storeAllocation(commitments[i].lockTag, commitments[i].token, amount, recipient, expires, claimHash);
        }

        return commitments;
    }

    function prepareAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata /* orderData */
    ) external returns (uint256 nonce) {
        uint32 expiration = uint32(expires);
        nonce = _getNonce(msg.sender, recipient);
        AL.prepareAllocation(COMPACT_CONTRACT, nonce, recipient, idsAndAmounts, arbiter, expiration, typehash, witness);

        return nonce;
    }

    function executeAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata /* orderData */
    ) external {
        uint256 nonce = _getAndUpdateNonce(msg.sender, recipient);
        uint32 expiration = uint32(expires);

        (bytes32 claimHash, Lock[] memory commitments) =
            _executeAllocation(nonce, recipient, idsAndAmounts, arbiter, expiration, typehash, witness);

        emit Allocated(recipient, commitments, nonce, expiration, claimHash);
    }

    function _executeAllocation(
        uint256 nonce,
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness
    ) internal returns (bytes32, Lock[] memory) {
        (bytes32 claimHash, Lock[] memory commitments) =
            AL.executeAllocation(COMPACT_CONTRACT, nonce, recipient, idsAndAmounts, arbiter, expires, typehash, witness);

        // Allocate the claim
        for (uint256 i = 0; i < commitments.length; i++) {
            // Check the amount fits in the supported range
            if (commitments[i].amount > type(uint224).max) {
                revert InvalidAmount(commitments[i].amount);
            }

            _storeAllocation(
                commitments[i].lockTag,
                commitments[i].token,
                uint224(commitments[i].amount),
                recipient,
                expires,
                claimHash
            );
        }

        return (claimHash, commitments);
    }

    /// @inheritdoc IAllocator
    function attest(address, address from_, address, uint256 id_, uint256 amount_) external returns (bytes4) {
        // Can be called by anyone, as this will only clean up expired allocations.
        uint256 balance = ERC6909(COMPACT_CONTRACT).balanceOf(from_, id_);

        // Check unlocked balance
        bytes32 tokenHash = _getTokenHash(id_, from_);
        uint256 allocatedBalance = _allocatedBalance(tokenHash);
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
        bytes calldata /*allocatorData*/ // Arbitrary data provided by the arbiter.
    ) public virtual onlyCompact returns (bytes4) {
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            bytes32 tokenHash = _getTokenHash(idsAndAmounts[i][0], sponsor);

            if (_verifyClaim(tokenHash, claimHash)) {
                // Continue even if the claim is already verified to delete the other allocations.
                continue;
            }

            // claim could not be verified
            revert InvalidClaim(claimHash);
        }

        return this.authorizeClaim.selector;
    }

    /// @inheritdoc IAllocator
    function isClaimAuthorized(
        bytes32 claimHash,
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address sponsor, // The account sponsoring the claim.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256 expires, // The time at which the claim expires.
        uint256[2][] calldata idsAndAmounts, // The allocated token IDs and amounts.
        bytes calldata /*allocatorData*/ // Arbitrary data provided by the arbiter.
    ) public view virtual returns (bool) {
        if (expires < block.timestamp) {
            return false;
        }

        // We only need to check the first id to confirm or deny the claim.
        bytes32 tokenHash = _getTokenHash(idsAndAmounts[0][0], sponsor);
        Allocation[] memory allocations = _allocations[tokenHash];
        for (uint256 j = 0; j < allocations.length; j++) {
            if (allocations[j].claimHash == claimHash) {
                return true;
            }
        }

        return false;
    }

    function _allocate(
        address sponsor,
        Lock[] calldata commitments,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness
    ) internal returns (bytes32 claimHash, uint256 nonce) {
        if (expires < block.timestamp) {
            revert InvalidExpiration(expires, block.timestamp);
        }

        nonce = _getAndUpdateNonce(address(0), sponsor); // address(0) as caller allows anyone to relay
        bytes32 commitmentsHash = AL.getCommitmentsHash(commitments);
        claimHash = AL.getClaimHash(arbiter, sponsor, nonce, expires, commitmentsHash, witness, typehash);

        uint256 minResetPeriod = type(uint256).max;
        for (uint256 i = 0; i < commitments.length; i++) {
            minResetPeriod = _checkInput(commitments[i], sponsor, expires, minResetPeriod);
            bytes32 tokenHash = _checkBalance(sponsor, commitments[i]);

            // Store the allocation
            uint224 amount = uint224(commitments[i].amount);
            _storeAllocation(tokenHash, amount, expires, claimHash);
        }
        // Ensure expiration is not bigger then the smallest reset period
        if (expires >= block.timestamp + minResetPeriod) {
            revert InvalidExpiration(expires, block.timestamp + minResetPeriod);
        }

        return (claimHash, nonce);
    }

    function _checkInput(Lock calldata commitment, address sponsor, uint32 expires, uint256 minResetPeriod)
        internal
        view
        returns (uint256)
    {
        // Check the allocator id fits this allocator
        if (AL.splitAllocatorId(commitment.lockTag) != ALLOCATOR_ID) {
            revert InvalidAllocator(AL.splitAllocatorId(commitment.lockTag), ALLOCATOR_ID);
        }

        // Check the amount fits in the supported range
        if (commitment.amount > type(uint224).max) {
            revert InvalidAmount(commitment.amount);
        }

        // Get the reset period for the token id
        uint256 duration = AL.toSeconds(commitment.lockTag);
        if (duration < minResetPeriod) {
            minResetPeriod = duration;
        }

        // Ensure no forcedWithdrawal is active for the token id
        (, uint256 forcedWithdrawal) = ITheCompact(COMPACT_CONTRACT).getForcedWithdrawalStatus(
            sponsor, AL.toId(commitment.lockTag, commitment.token)
        );
        if (forcedWithdrawal != 0 && forcedWithdrawal <= expires) {
            revert ForceWithdrawalAvailable(expires, forcedWithdrawal);
        }

        return minResetPeriod;
    }

    function _checkBalance(address sponsor, Lock calldata commitment) internal returns (bytes32 tokenHash) {
        // Check the balance of the recipient is sufficient
        tokenHash = _getTokenHash(commitment.lockTag, commitment.token, sponsor);
        uint256 balance = ERC6909(COMPACT_CONTRACT).balanceOf(sponsor, AL.toId(commitment.lockTag, commitment.token));
        uint256 allocatedBalance = _allocatedBalance(tokenHash);
        uint256 requiredBalance = allocatedBalance + commitment.amount;
        if (requiredBalance > balance) {
            revert InsufficientBalance(
                sponsor, AL.toId(commitment.lockTag, commitment.token), balance - allocatedBalance, commitment.amount
            );
        }
    }

    function _storeAllocation(
        bytes12 lockTag,
        address token,
        uint224 amount,
        address recipient,
        uint32 expires,
        bytes32 claimHash
    ) internal {
        bytes32 tokenHash = _getTokenHash(lockTag, token, recipient);
        _storeAllocation(tokenHash, amount, expires, claimHash);
    }

    function _storeAllocation(bytes32 tokenHash, uint224 amount, uint32 expires, bytes32 claimHash) internal {
        Allocation memory allocation = Allocation({expires: expires, amount: amount, claimHash: claimHash});
        _allocations[tokenHash].push(allocation);
    }

    function _allocatedBalance(bytes32 tokenHash) internal returns (uint256 allocatedBalance) {
        // using assembly to only read the allocated balance + expiration slot and skipping the claimHash slot
        assembly ("memory-safe") {
            // no previous cached balance, calculate the allocated balance
            mstore(0x00, tokenHash)
            mstore(0x20, _allocations.slot)
            // retrieve the array length slot
            let arrayLengthSlot := keccak256(0x00, 0x40)
            let origLength := sload(arrayLengthSlot)
            let length := origLength
            // retrieve the arrays content slot
            mstore(0x00, arrayLengthSlot)
            let contentSlot := keccak256(0x00, 0x20)
            for { let i := 0 } lt(i, length) {} {
                let slot := add(contentSlot, mul(i, 2)) // 0x40 to skip the claimHash slot
                let content := sload(slot)
                let expiration := shr(224, shl(224, content))
                if lt(expiration, timestamp()) {
                    // allocation expired, remove it
                    let lastSlot := add(contentSlot, mul(sub(length, 1), 2))
                    if iszero(eq(slot, lastSlot)) {
                        // is not the last allocation of the array
                        let contentLast1 := sload(lastSlot)
                        let contentLast2 := sload(add(lastSlot, 1))
                        sstore(slot, contentLast1)
                        sstore(add(slot, 1), contentLast2)
                    }
                    // remove the last allocation
                    length := sub(length, 1)
                    sstore(lastSlot, 0)
                    sstore(add(lastSlot, 1), 0)

                    // repeat the loop at the same index
                    continue
                }

                let amount := shr(32, content)
                allocatedBalance := add(allocatedBalance, amount)

                // jump to the next allocation
                i := add(i, 1)
            }

            if lt(length, origLength) {
                // update the array length
                sstore(arrayLengthSlot, length)
            }
        }
    }

    function _verifyClaim(bytes32 tokenHash, bytes32 claimHash) internal returns (bool verified) {
        // using assembly to only read the claimHash slot and skip the expires/amount slot
        assembly ("memory-safe") {
            mstore(0x00, tokenHash)
            mstore(0x20, _allocations.slot)
            let lengthSlot := keccak256(0x00, 0x40)
            let length := sload(lengthSlot)
            mstore(0x00, lengthSlot)
            let contentSlot := keccak256(0x00, 0x20)
            for { let i := 0 } lt(i, length) { i := add(i, 1) } {
                // Each allocation occupies two consecutive slots:
                // first: packed expires/amount; second: claimHash
                let first := add(contentSlot, mul(i, 2))
                let second := add(first, 1)
                if eq(sload(second), claimHash) {
                    // Swap-and-pop delete
                    let lastFirst := add(contentSlot, mul(sub(length, 1), 2))
                    let lastSecond := add(lastFirst, 1)
                    if iszero(eq(first, lastFirst)) {
                        let contentLast1 := sload(lastFirst)
                        let contentLast2 := sload(lastSecond)
                        sstore(first, contentLast1)
                        sstore(second, contentLast2)
                    }

                    sstore(lastFirst, 0)
                    sstore(lastSecond, 0)

                    // update the array length
                    sstore(lengthSlot, sub(length, 1))

                    // We return at the first match, no matter if the allocated amounts match.
                    // If the claim includes the same token multiple times (amounts mismatch),
                    // we will enter this function again until all entries are deleted.
                    verified := 1
                    break
                }
            }
        }
    }

    function _getAndUpdateNonce(address calling, address sponsor) internal returns (uint256 nonce) {
        assembly ("memory-safe") {
            calling := xor(calling, mul(sponsor, iszero(calling)))
            mstore(0x00, calling)
            mstore(0x20, nonces.slot)
            let nonceSlot := keccak256(0x00, 0x40)
            let nonce96 := sload(nonceSlot)
            nonce := or(shl(96, calling), add(nonce96, 1))
            sstore(nonceSlot, add(nonce96, 1))
        }
    }

    function _getNonce(address calling, address sponsor) internal view returns (uint256 nonce) {
        assembly ("memory-safe") {
            calling := xor(calling, mul(sponsor, iszero(calling)))
            mstore(0x00, calling)
            mstore(0x20, nonces.slot)
            let nonceSlot := keccak256(0x00, 0x40)
            let nonce96 := sload(nonceSlot)
            nonce := or(shl(96, calling), add(nonce96, 1))
        }
    }

    function _getTokenHash(bytes12 lockTag, address token, address sponsor) internal pure returns (bytes32 tokenHash) {
        assembly ("memory-safe") {
            mstore(0x00, lockTag)
            mstore(0x0c, shl(96, token))
            mstore(0x20, sponsor)
            tokenHash := keccak256(0x00, 0x40)
        }
    }

    function _getTokenHash(uint256 id, address sponsor) internal pure returns (bytes32 tokenHash) {
        tokenHash = keccak256(abi.encode(id, sponsor));
    }
}
