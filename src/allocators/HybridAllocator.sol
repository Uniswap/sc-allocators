// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {SafeTransferLib} from '@solady/utils/SafeTransferLib.sol';
import {BatchCompact, LOCK_TYPEHASH, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {IHybridAllocator} from 'src/interfaces/IHybridAllocator.sol';

contract HybridAllocator is IHybridAllocator {
    uint96 public immutable ALLOCATOR_ID;
    ITheCompact internal immutable _COMPACT;
    bytes32 internal immutable _COMPACT_DOMAIN_SEPARATOR;

    mapping(bytes32 => bool) internal claims;

    /// @dev The off chain allocator must use a uint256 nonce where the first 160 bits are the sponsors address to ensure no nonce collisions
    uint96 public nonces;
    uint256 public signerCount;
    mapping(address => bool) public signers;

    modifier onlySigner() {
        if (!signers[msg.sender]) {
            revert InvalidSigner();
        }
        _;
    }

    constructor(address compact_, address signer_) {
        if (signer_ == address(0)) {
            revert InvalidSigner();
        }
        _COMPACT = ITheCompact(compact_);
        ALLOCATOR_ID = _COMPACT.__registerAllocator(address(this), '');
        _COMPACT_DOMAIN_SEPARATOR = _COMPACT.DOMAIN_SEPARATOR();

        signers[signer_] = true;
        signerCount++;
    }

    /// @inheritdoc IHybridAllocator
    function addSigner(address signer_) external onlySigner {
        if (signer_ == address(0)) {
            revert InvalidSigner();
        }
        signers[signer_] = true;
        signerCount++;
    }

    /// @inheritdoc IHybridAllocator
    function removeSigner(address signer_) external onlySigner {
        if (signerCount == 1) {
            revert LastSigner();
        }
        signers[signer_] = false;
        signerCount--;
    }

    /// @inheritdoc IHybridAllocator
    function replaceSigner(address newSigner_) external onlySigner {
        if (newSigner_ == address(0)) {
            revert InvalidSigner();
        }
        signers[msg.sender] = false;
        signers[newSigner_] = true;
    }

    /// @inheritdoc IAllocator
    function attest(address, /*operator*/ address, /*from*/ address, /*to*/ uint256, /*id*/ uint256 /*amount*/ )
        external
        pure
        returns (bytes4)
    {
        revert Unsupported();
    }

    /// @inheritdoc IHybridAllocator
    function allocateAndRegister(
        address recipient,
        uint256[2][] memory idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) public payable returns (bytes32, uint256[] memory, uint256) {
        idsAndAmounts = _actualIdsAndAmounts(idsAndAmounts);

        (bytes32 claimHash, uint256[] memory registeredAmounts) = _COMPACT.batchDepositAndRegisterFor{value: msg.value}(
            recipient, idsAndAmounts, arbiter, ++nonces, expires, typehash, witness
        );

        // Allocate the claim
        claims[claimHash] = true;

        emit ClaimRegistered(recipient, registeredAmounts, nonces, claimHash);

        return (claimHash, registeredAmounts, nonces);
    }

    function allocateFor(
        address sponsor,
        Lock[] calldata commitments,
        address arbiter,
        uint32 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata /*signature*/
    ) public returns (bytes32 claimHash, uint256 claimNonce) {
        for (uint256 i = 0; i < commitments.length; i++) {
            uint96 allocatorId = _splitAllocatorId(commitments[i].lockTag);

            // Check allocator id
            if (allocatorId != ALLOCATOR_ID) {
                revert InvalidAllocatorId(allocatorId, ALLOCATOR_ID);
            }
        }

        claimHash = _getClaimHash(commitments, arbiter, sponsor, ++nonces, expires, witness, typehash);

        // confirm the claim hash is registered on the compact
        if (!_COMPACT.isRegistered(sponsor, claimHash, typehash)) {
            revert InvalidRegistration(sponsor, claimHash);
        }

        // Allocate the claim
        claims[claimHash] = true;

        return (claimHash, nonces);
    }
    /// @inheritdoc IAllocator

    function authorizeClaim(
        bytes32 claimHash,
        address, /*arbiter*/
        address, /*sponsor*/
        uint256, /*nonce*/
        uint256, /*expires*/
        uint256[2][] calldata, /*idsAndAmounts*/
        bytes calldata allocatorData_
    ) external virtual returns (bytes4) {
        if (msg.sender != address(_COMPACT)) {
            revert InvalidCaller(msg.sender, address(_COMPACT));
        }
        // The compact will check the validity of the nonce and expiration

        // Check if the claim was allocated on chain
        if (claims[claimHash]) {
            delete claims[claimHash];

            // Authorize the claim
            return IAllocator.authorizeClaim.selector;
        }

        // Check the allocator data for a valid signature by an authorized signer
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), _COMPACT_DOMAIN_SEPARATOR, claimHash));
        if (!_checkSignature(digest, allocatorData_)) {
            revert InvalidSignature();
        }

        // Authorize the claim
        return IAllocator.authorizeClaim.selector;
    }

    /// @inheritdoc IAllocator
    function isClaimAuthorized(
        bytes32 claimHash, // The message hash representing the claim.
        address, /*arbiter*/ // The account tasked with verifying and submitting the claim.
        address, /*sponsor*/ // The account to source the tokens from.
        uint256, /*nonce*/ // A parameter to enforce replay protection, scoped to allocator.
        uint256, /*expires*/ // The time at which the claim expires.
        uint256[2][] calldata, /*idsAndAmounts*/ // The allocated token IDs and amounts.
        bytes calldata allocatorData // Arbitrary data provided by the arbiter.
    ) external view virtual returns (bool) {
        if (claims[claimHash]) {
            return true;
        }

        // Check the allocator data for a valid signature by an authorized allocator address
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), _COMPACT_DOMAIN_SEPARATOR, claimHash));
        return _checkSignature(digest, allocatorData);
    }

    function requestNonce(address /*sponsor*/ ) public view returns (uint256 nonce) {
        return nonces + 1;
    }

    function _actualIdsAndAmounts(uint256[2][] memory idsAndAmounts) internal returns (uint256[2][] memory) {
        uint256 idIndex = 0;
        uint256 idsLength = idsAndAmounts.length;
        if (idsLength == 0) {
            revert InvalidIds();
        }

        // Check for native token - Native tokens must always be the first id
        if (_splitToken(idsAndAmounts[0][0]) == address(0)) {
            // Check allocator id
            if (_splitAllocatorId(idsAndAmounts[0][0]) != ALLOCATOR_ID) {
                revert InvalidAllocatorId(_splitAllocatorId(idsAndAmounts[0][0]), ALLOCATOR_ID);
            }
            if (idsAndAmounts[0][1] != 0 && msg.value != idsAndAmounts[0][1]) {
                revert InvalidValue(msg.value, idsAndAmounts[0][1]);
            }
            idsAndAmounts[0][1] = msg.value;

            idIndex++;
        }

        for (; idIndex < idsLength; idIndex++) {
            (uint96 allocatorId, address token) = _splitId(idsAndAmounts[idIndex][0]);

            // Check allocator id
            if (allocatorId != ALLOCATOR_ID) {
                revert InvalidAllocatorId(allocatorId, ALLOCATOR_ID);
            }

            if (idsAndAmounts[idIndex][1] == 0) {
                // Amount is derived from the allocators token balance
                idsAndAmounts[idIndex][1] = IERC20(token).balanceOf(address(this));
            }

            if (IERC20(token).allowance(address(this), address(_COMPACT)) < idsAndAmounts[idIndex][1]) {
                SafeTransferLib.safeApproveWithRetry(token, address(_COMPACT), type(uint256).max);
            }
        }

        return idsAndAmounts;
    }

    function _checkSignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
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
            return false;
        }

        // Check if the signer is an authorized allocator address
        address signer = ecrecover(digest, v, r, s);
        return signers[signer] && signer != address(0);
    }

    function _splitId(uint256 id) internal pure returns (uint96 allocatorId_, address token_) {
        return (_splitAllocatorId(id), _splitToken(id));
    }

    function _splitAllocatorId(uint256 id) internal pure returns (uint96) {
        uint96 allocatorId_;
        assembly ("memory-safe") {
            allocatorId_ := shr(164, shl(4, id))
        }
        return allocatorId_;
    }

    function _splitAllocatorId(bytes12 lockTag) internal pure returns (uint96) {
        uint96 allocatorId;
        assembly ("memory-safe") {
            allocatorId := shr(164, shl(4, lockTag))
        }
        return allocatorId;
    }

    function _splitToken(uint256 id) internal pure returns (address) {
        return address(uint160(id));
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

    function _getCommitmentsHash(Lock[] memory commitments) internal pure returns (bytes32) {
        bytes32[] memory commitmentsHashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            commitmentsHashes[i] = keccak256(
                abi.encode(LOCK_TYPEHASH, commitments[i].lockTag, commitments[i].token, commitments[i].amount)
            );
        }
        return keccak256(abi.encodePacked(commitmentsHashes));
    }
}
