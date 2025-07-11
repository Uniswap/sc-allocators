// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {BatchCompact, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {IERC7683Allocator} from 'src/interfaces/IERC7683Allocator.sol';

contract HybridAllocator is IAllocator {
    uint96 public immutable ALLOCATOR_ID;
    ITheCompact internal immutable _COMPACT;
    bytes32 internal immutable _COMPACT_DOMAIN_SEPARATOR;

    mapping(bytes32 => bool) internal claims;

    uint256 public nonce;
    uint256 public signerCount;
    mapping(address => bool) public signers;

    error Unsupported();
    error InvalidIds();
    error InvalidAllocatorId(uint96 allocatorId, uint96 expectedAllocatorId);
    error InvalidCaller(address sender, address expectedSender);
    error InvalidAllocatorData(uint256 length);
    error InvalidSignature();
    error InvalidSigner();
    error LastSigner();
    error InvalidValue(uint256 value, uint256 expectedValue);

    event ClaimRegistered(address indexed sponsor, uint256[] registeredAmounts, uint256 nonce, bytes32 claimHash);

    modifier onlySigner() {
        if (!signers[msg.sender]) {
            revert InvalidSigner();
        }
        _;
    }

    constructor(address compact_, address signer_) {
        _COMPACT = ITheCompact(compact_);
        ALLOCATOR_ID = _COMPACT.__registerAllocator(address(this), '');
        _COMPACT_DOMAIN_SEPARATOR = _COMPACT.DOMAIN_SEPARATOR();

        signers[signer_] = true;
        signerCount++;

        // Block the first half of nonces for the offchain allocator
        nonce = type(uint128).max;
    }

    function addSigner(address signer_) external onlySigner {
        signers[signer_] = true;
        signerCount++;
    }

    function removeSigner(address signer_) external onlySigner {
        if (signerCount == 1) {
            revert LastSigner();
        }
        signers[signer_] = false;
        signerCount--;
    }

    function replaceSigner(address newSigner_) external onlySigner {
        signers[msg.sender] = false;
        signers[newSigner_] = true;
    }

    function attest(address, /*operator*/ address, /*from*/ address, /*to*/ uint256, /*id*/ uint256 /*amount*/ )
        external
        pure
        returns (bytes4)
    {
        revert Unsupported();
    }

    function registerClaim(
        address recipient,
        uint256[2][] memory idsAndAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) public payable returns (bytes32, uint256[] memory, uint256) {
        idsAndAmounts = _actualIdsAndAmounts(idsAndAmounts);

        (bytes32 claimHash, uint256[] memory registeredAmounts) = _COMPACT.batchDepositAndRegisterFor{value: msg.value}(
            recipient, idsAndAmounts, arbiter, ++nonce, expires, typehash, witness
        );

        // Allocate the claim
        claims[claimHash] = true;

        emit ClaimRegistered(recipient, registeredAmounts, nonce, claimHash);

        return (claimHash, registeredAmounts, nonce);
    }

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
            (uint96 allocatorId_, address token_) = _splitId(idsAndAmounts[idIndex][0]);

            // Check allocator id
            if (allocatorId_ != ALLOCATOR_ID) {
                revert InvalidAllocatorId(allocatorId_, ALLOCATOR_ID);
            }

            if (idsAndAmounts[idIndex][1] == 0) {
                // Amount is derived from the allocators token balance
                idsAndAmounts[idIndex][1] = IERC20(token_).balanceOf(address(this));
            }

            IERC20(token_).approve(address(_COMPACT), idsAndAmounts[idIndex][1]);
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
        return signers[ecrecover(digest, v, r, s)];
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

    function _splitToken(uint256 id) internal pure returns (address) {
        return address(uint160(id));
    }
}
