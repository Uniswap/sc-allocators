// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IOnChainAllocator} from '../interfaces/IOnChainAllocator.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {SafeTransferLib} from '@solady/utils/SafeTransferLib.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {LOCK_TYPEHASH, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

import {console} from 'forge-std/console.sol';

contract OnChainAllocator is IOnChainAllocator {
    address public immutable COMPACT_CONTRACT;
    bytes32 public immutable COMPACT_DOMAIN_SEPARATOR;
    uint96 public immutable ALLOCATOR_ID;

    mapping(bytes32 tokenHash => Allocation[] allocations) internal _allocations;

    mapping(bytes32 user => uint256 nonce) public nonces;

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

        emit AllocationRegistered(msg.sender, claimHash, claimNonce, expires, commitments);
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
            address signer_ = _recoverSigner(digest, signature);
            if (sponsor != signer_ || signer_ == address(0)) {
                revert InvalidSignature(signer_, sponsor);
            }
        } else {
            // confirm the claim hash is registered on the compact
            if (!ITheCompact(COMPACT_CONTRACT).isRegistered(sponsor, claimHash, typehash)) {
                revert InvalidRegistration(sponsor, claimHash);
            }
        }
        emit AllocationRegistered(sponsor, claimHash, claimNonce, expires, commitments);
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
        nonce = ++nonces[_toNonceId(msg.sender, recipient)]; // prevents griefing of frontrunning nonces
        uint256[2][] memory idsAndAmounts = new uint256[2][](commitments.length);
        uint256 minResetPeriod = type(uint256).max;
        for (uint256 i = 0; i < commitments.length; i++) {
            minResetPeriod = _checkInput(commitments[i], recipient, expires, minResetPeriod);

            // Store the allocation
            idsAndAmounts[i][0] = _toId(commitments[i].lockTag, commitments[i].token);
            uint224 amount = uint224(commitments[i].amount);
            if (amount == 0) {
                amount = uint224(IERC20(commitments[i].token).balanceOf(address(this)));
            }
            idsAndAmounts[i][1] = amount;

            if (IERC20(commitments[i].token).allowance(address(this), COMPACT_CONTRACT) < amount) {
                SafeTransferLib.safeApproveWithRetry(commitments[i].token, COMPACT_CONTRACT, type(uint256).max);
            }
        }
        // Ensure expiration is not bigger then the smallest reset period
        if (expires >= block.timestamp + minResetPeriod) {
            revert InvalidExpiration(expires, block.timestamp + minResetPeriod);
        }

        (claimHash, registeredAmounts) = ITheCompact(COMPACT_CONTRACT).batchDepositAndRegisterFor(
            recipient, idsAndAmounts, arbiter, nonce, expires, typehash, witness
        );

        // Store the allocation
        for (uint256 i = 0; i < registeredAmounts.length; i++) {
            bytes32 tokenHash = _getTokenHash(commitments[i], recipient);

            Allocation memory allocation =
                Allocation({expires: expires, amount: uint224(registeredAmounts[i]), claimHash: claimHash});
            _allocations[tokenHash].push(allocation);
        }

        emit AllocationRegistered(recipient, claimHash, nonce, expires, commitments);

        return (claimHash, registeredAmounts, nonce);
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

        nonce = ++nonces[_toNonceId(address(0), sponsor)]; // address(0) as caller allows anyone to relay
        claimHash = _getClaimHash(commitments, arbiter, sponsor, nonce, expires, witness, typehash);

        uint256 minResetPeriod = type(uint256).max;
        for (uint256 i = 0; i < commitments.length; i++) {
            minResetPeriod = _checkInput(commitments[i], sponsor, expires, minResetPeriod);
            bytes32 tokenHash = _checkBalance(sponsor, commitments[i]);

            // Store the allocation
            uint224 amount = uint224(commitments[i].amount);
            Allocation memory allocation = Allocation({expires: expires, amount: amount, claimHash: claimHash});
            _allocations[tokenHash].push(allocation);
        }
        // Ensure expiration is not bigger then the smallest reset period
        if (expires >= block.timestamp + minResetPeriod) {
            revert InvalidExpiration(expires, block.timestamp + minResetPeriod - 1);
        }

        return (claimHash, nonce);
    }

    function _checkInput(Lock calldata commitment, address sponsor, uint32 expires, uint256 minResetPeriod)
        internal
        view
        returns (uint256)
    {
        // Check the allocator id fits this allocator
        if (_splitAllocatorId(commitment.lockTag) != ALLOCATOR_ID) {
            revert InvalidAllocator(_splitAllocatorId(commitment.lockTag), ALLOCATOR_ID);
        }

        // Check the amount fits in the supported range
        if (commitment.amount > type(uint224).max) {
            revert InvalidAmount(commitment.amount);
        }

        // Get the reset period for the token id
        uint256 duration = _toSeconds(commitment.lockTag);
        if (duration < minResetPeriod) {
            minResetPeriod = duration;
        }

        // Ensure no forcedWithdrawal is active for the token id
        (, uint256 forcedWithdrawal) = ITheCompact(COMPACT_CONTRACT).getForcedWithdrawalStatus(
            sponsor, _toId(commitment.lockTag, commitment.token)
        );
        if (forcedWithdrawal != 0 && forcedWithdrawal <= expires) {
            revert ForceWithdrawalAvailable(expires, forcedWithdrawal);
        }

        return minResetPeriod;
    }

    function _checkBalance(address sponsor, Lock calldata commitment) internal returns (bytes32 tokenHash) {
        // Check the balance of the recipient is sufficient
        tokenHash = _getTokenHash(commitment, sponsor);
        uint256 balance = ERC6909(COMPACT_CONTRACT).balanceOf(sponsor, _toId(commitment.lockTag, commitment.token));
        uint256 allocatedBalance = _allocatedBalance(tokenHash);
        uint256 requiredBalance = allocatedBalance + commitment.amount;
        if (requiredBalance > balance) {
            revert InsufficientBalance(
                sponsor, _toId(commitment.lockTag, commitment.token), balance - allocatedBalance, commitment.amount
            );
        }
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
                let slot2 := add(contentSlot, add(mul(i, 2), 1)) // add 0x20 to skip the expires/amount slot
                let content2 := sload(slot2)
                if eq(content2, claimHash) {
                    // delete the allocation
                    let lastSlot := add(contentSlot, mul(sub(length, 1), 0x40))
                    if iszero(eq(sub(slot2, 0x20), lastSlot)) {
                        // is not the last allocation of the array
                        let contentLast1 := sload(lastSlot)
                        let contentLast2 := sload(add(lastSlot, 0x20))
                        sstore(sub(slot2, 0x20), contentLast1)
                        sstore(slot2, contentLast2)
                    }

                    sstore(lastSlot, 0)
                    sstore(add(lastSlot, 0x20), 0)

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

    function _recoverSigner(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (signature.length == 65) {
            (r, s) = abi.decode(signature, (bytes32, bytes32));
            v = uint8(signature[64]);
        } else if (signature.length == 64) {
            bytes32 vs;
            (r, vs) = abi.decode(signature, (bytes32, bytes32));
            v = uint8(uint256(vs >> 255) + 27);
            s = vs << 1 >> 1;
        } else {
            return address(0);
        }

        return ecrecover(digest, v, r, s);
    }

    function _getCommitmentsHash(Lock[] memory commitments) internal pure returns (bytes32) {
        bytes32[] memory commitmentsHashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            commitmentsHashes[i] = keccak256(
                abi.encode(LOCK_TYPEHASH, commitments[i].lockTag, commitments[i].token, commitments[i].amount)
            );
        }
        return keccak256(abi.encodePacked(commitmentsHashes));
    }

    function _getTokenHash(Lock calldata commitment, address sponsor) internal pure returns (bytes32 tokenHash) {
        assembly ("memory-safe") {
            mstore(0x00, calldataload(commitment))
            mstore(0x0c, shl(96, calldataload(add(commitment, 0x20))))
            mstore(0x20, sponsor)
            tokenHash := keccak256(0x00, 0x40)
        }
    }

    function _getTokenHash(uint256 id, address sponsor) internal pure returns (bytes32 tokenHash) {
        tokenHash = keccak256(abi.encode(id, sponsor));
    }

    function _splitAllocatorId(bytes12 lockTag) internal pure returns (uint96) {
        uint96 allocatorId_;
        assembly ("memory-safe") {
            allocatorId_ := shr(164, shl(4, lockTag))
        }
        return allocatorId_;
    }

    function _toId(bytes12 lockTag, address token) internal pure returns (uint256 id) {
        assembly ("memory-safe") {
            id := or(lockTag, token)
        }
    }

    function _toNonceId(address caller, address sponsor) internal pure returns (bytes32 nonce) {
        return keccak256(abi.encode(caller, sponsor));
    }

    function _toSeconds(bytes12 lockTag) internal pure returns (uint256 duration) {
        assembly ("memory-safe") {
            let resetPeriod := shr(253, shl(1, lockTag))

            // Bitpacked durations in 24-bit segments:
            // 278d00  094890  015180  000f3c  000258  00003c  00000f  000001
            // 30 days 7 days  1 day   1 hour  10 min  1 min   15 sec  1 sec
            let bitpacked := 0x278d00094890015180000f3c00025800003c00000f000001

            // Shift right by period * 24 bits & mask the least significant 24 bits.
            duration := and(shr(mul(resetPeriod, 24), bitpacked), 0xffffff)
        }
    }

    function _getClaimHash(
        Lock[] calldata commitments,
        address arbiter,
        address sponsor,
        uint256 nonce,
        uint32 expires,
        bytes32 witness,
        bytes32 typehash
    ) internal pure returns (bytes32 claimHash) {
        bytes32 commitmentsHash = _getCommitmentsHash(commitments);

        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, typehash)
            mstore(add(m, 0x20), arbiter)
            mstore(add(m, 0x40), sponsor)
            mstore(add(m, 0x60), nonce)
            mstore(add(m, 0x80), expires)
            mstore(add(m, 0xa0), commitmentsHash)
            mstore(add(m, 0xc0), witness)
            claimHash := keccak256(m, sub(0xe0, mul(iszero(witness), 0x20)))
        }
    }
}
