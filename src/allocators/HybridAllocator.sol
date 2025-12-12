// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {SafeTransferLib} from '@solady/utils/SafeTransferLib.sol';
import {Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';

import {AllocatorLib as AL} from './lib/AllocatorLib.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {IOnChainAllocation} from '@uniswap/the-compact/interfaces/IOnChainAllocation.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';

import {Extsload} from '@uniswap/the-compact/lib/Extsload.sol';
import {IdLib} from '@uniswap/the-compact/lib/IdLib.sol';
import {DepositDetails} from '@uniswap/the-compact/types/DepositDetails.sol';
import {ISignatureTransfer} from 'permit2/src/interfaces/ISignatureTransfer.sol';
import {IHybridAllocator} from 'src/interfaces/IHybridAllocator.sol';

/// @title HybridAllocator
/// @notice Hybrid allocator for The Compact supporting both on-chain and off-chain allocation authorization mechanisms
/// @dev Combines direct deposit functionality with signature-based off-chain authorization through multiple authorized signers
/// @custom:security-contact security@uniswap.org
contract HybridAllocator is IHybridAllocator {
    event SignerAdded(address signer);
    event SignerRemoved(address signer);
    event OwnerReplacementProposed(address newOwner);
    event OwnerReplaced(address oldOwner, address newOwner);
    event AllocatorInitialized(address compact, address owner, uint96 allocatorId);

    /// @notice The unique identifier for this allocator within The Compact protocol
    uint96 public immutable ALLOCATOR_ID;
    uint256 private immutable _INITIAL_CHAIN_ID;
    bytes32 internal immutable _COMPACT_DOMAIN_SEPARATOR;

    mapping(bytes32 claimHash => bool allocated) internal claims;

    /// @dev The off chain allocator must use a uint256 nonce where the first byte is the off chain nonce command (0xfc).
    ///      The next 20 bytes are the sponsors address, followed by the freely chosen nonce within the next 11 bytes.
    ///      This will prevent nonce collisions.
    uint88 public nonces;
    /// @notice The owner of the allocator, authorized to add and remove signers
    address public owner;
    /// @notice Mapping tracking which addresses are authorized signers for off-chain allocations
    mapping(address signer => bool isSigner) public signers;
    address private _pendingOwner;

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert CallerNotOwner();
        }
        _;
    }

    constructor(address owner_, address signer_) {
        if (owner_ == address(0)) {
            revert InvalidOwner();
        }
        _INITIAL_CHAIN_ID = block.chainid;
        _COMPACT_DOMAIN_SEPARATOR = ITheCompact(AL.THE_COMPACT).DOMAIN_SEPARATOR();
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

        owner = owner_;
        if (signer_ != address(0)) {
            signers[signer_] = true;
            emit SignerAdded(signer_);
        }

        emit AllocatorInitialized(AL.THE_COMPACT, owner_, ALLOCATOR_ID);
    }

    /// @inheritdoc IHybridAllocator
    function addSigner(address signer_) public onlyOwner {
        if (signer_ == address(0) || signers[signer_]) {
            revert InvalidSigner();
        }
        signers[signer_] = true;
        emit SignerAdded(signer_);
    }

    /// @inheritdoc IHybridAllocator
    function removeSigner(address signer_) public onlyOwner {
        if (!signers[signer_]) {
            revert InvalidSigner();
        }

        signers[signer_] = false;
        emit SignerRemoved(signer_);
    }

    /// @inheritdoc IHybridAllocator
    function replaceSigner(address oldSigner_, address newSigner_) external onlyOwner {
        if (oldSigner_ == newSigner_) {
            revert InvalidSigner();
        }
        removeSigner(oldSigner_);
        addSigner(newSigner_);
    }

    /// @inheritdoc IHybridAllocator
    function proposeOwnerReplacement(address newOwner_) external onlyOwner {
        if (newOwner_ == address(0)) {
            revert InvalidOwner();
        }
        _pendingOwner = newOwner_;
        emit OwnerReplacementProposed(newOwner_);
    }

    /// @inheritdoc IHybridAllocator
    function acceptOwnerReplacement() external {
        if (msg.sender != _pendingOwner) {
            revert InvalidOwner();
        }

        delete _pendingOwner;
        address previousOwner = owner;
        owner = msg.sender;
        emit OwnerReplaced(previousOwner, msg.sender);
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
        recipient = AL.getRecipient(recipient);
        idsAndAmounts = _actualIdsAndAmounts(idsAndAmounts);

        uint256 nonce = AL.getNonceWithCommand(AL.ON_CHAIN_NONCE, ++nonces);
        (bytes32 claimHash, uint256[] memory registeredAmounts) = ITheCompact(AL.THE_COMPACT).batchDepositAndRegisterFor{
            value: msg.value
        }(recipient, idsAndAmounts, arbiter, nonce, expires, typehash, witness);

        Lock[] memory commitments = new Lock[](idsAndAmounts.length);
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            commitments[i] = Lock({
                lockTag: bytes12(bytes32(idsAndAmounts[i][0])),
                token: address(uint160(idsAndAmounts[i][0])),
                amount: registeredAmounts[i]
            });
        }

        // Allocate the claim
        claims[claimHash] = true;

        emit Allocated(recipient, commitments, nonce, expires, claimHash);

        return (claimHash, registeredAmounts, nonce);
    }

    /// @inheritdoc IHybridAllocator
    function permit2Allocation(
        address arbiter,
        address depositor,
        uint256 expires,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        DepositDetails calldata details,
        bytes32 claimHash,
        string calldata witness,
        bytes32 witnessHash,
        bytes calldata signature
    ) external returns (Lock[] memory commitments) {
        commitments = AL.permit2Allocation(
            arbiter, depositor, expires, permitted, details, claimHash, witness, witnessHash, signature
        );

        // Allocate the claim
        claims[claimHash] = true;

        emit Allocated(depositor, commitments, details.nonce, expires, claimHash);
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
        uint88 nonce88 = nonces + 1;

        nonce =
            AL.prepareAllocation(nonce88, recipient, idsAndAmounts, arbiter, expires, typehash, witness, ALLOCATOR_ID);
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
        uint88 nonce88 = ++nonces;

        (bytes32 claimHash, Lock[] memory commitments, uint256 nonce) =
            AL.executeAllocation(nonce88, recipient, idsAndAmounts, arbiter, expires, typehash, witness);

        // Allocate the claim
        claims[claimHash] = true;

        emit Allocated(recipient, commitments, nonce, expires, claimHash);
    }

    /// @inheritdoc IAllocator
    function authorizeClaim(
        bytes32 claimHash,
        address, /*arbiter*/
        address sponsor,
        uint256 nonce,
        uint256, /*expires*/
        uint256[2][] calldata, /*idsAndAmounts*/
        bytes calldata allocatorData_
    ) external virtual returns (bytes4) {
        if (msg.sender != AL.THE_COMPACT) {
            revert InvalidCaller(msg.sender, AL.THE_COMPACT);
        }
        // The compact will check the validity of the nonce and expiration

        // Check if the claim was allocated on chain
        if (claims[claimHash]) {
            delete claims[claimHash];

            // If the claim hash is matching, the nonce must be either an on chain nonce, or a permit2 scoped nonce

            // Authorize the claim
            return IAllocator.authorizeClaim.selector;
        }

        // Verify the nonce is scoped to an off chain allocation and to the sponsor
        AL.verifyNonce(nonce, AL.OFF_CHAIN_NONCE, sponsor);

        // Check the allocator data for a valid signature by an authorized signer
        bytes32 digest = _deriveDigest(claimHash, _COMPACT_DOMAIN_SEPARATOR);
        if (block.chainid != _INITIAL_CHAIN_ID) {
            // If the chain was forked, we can not use the cached domain separator
            digest = _deriveDigest(claimHash, ITheCompact(AL.THE_COMPACT).DOMAIN_SEPARATOR());
        }
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
        bytes32 digest = _deriveDigest(claimHash, _COMPACT_DOMAIN_SEPARATOR);
        if (block.chainid != _INITIAL_CHAIN_ID) {
            // If the chain was forked, we can not use the cached domain separator
            digest = _deriveDigest(claimHash, ITheCompact(AL.THE_COMPACT).DOMAIN_SEPARATOR());
        }
        return _checkSignature(digest, allocatorData);
    }

    function _actualIdsAndAmounts(uint256[2][] memory idsAndAmounts) internal returns (uint256[2][] memory) {
        uint256 idIndex = 0;
        uint256 idsLength = idsAndAmounts.length;
        if (idsLength == 0) {
            revert InvalidIds();
        }

        // Check for native token - Native tokens must always be the first id
        if (AL.splitToken(idsAndAmounts[0][0]) == address(0)) {
            // Check allocator id
            if (AL.splitAllocatorId(idsAndAmounts[0][0]) != ALLOCATOR_ID) {
                revert InvalidAllocatorId(AL.splitAllocatorId(idsAndAmounts[0][0]), ALLOCATOR_ID);
            }
            // If first token is native and no value attached, revert early
            if (msg.value == 0) {
                revert InvalidValue(0, 1);
            }
            if (idsAndAmounts[0][1] != 0 && msg.value != idsAndAmounts[0][1]) {
                revert InvalidValue(msg.value, idsAndAmounts[0][1]);
            }
            idsAndAmounts[0][1] = msg.value;

            idIndex++;
        }

        for (; idIndex < idsLength; idIndex++) {
            (uint96 allocatorId, address token) = AL.splitId(idsAndAmounts[idIndex][0]);

            // Check allocator id
            if (allocatorId != ALLOCATOR_ID) {
                revert InvalidAllocatorId(allocatorId, ALLOCATOR_ID);
            }

            if (idsAndAmounts[idIndex][1] == 0) {
                // Amount is derived from the allocators token balance
                idsAndAmounts[idIndex][1] = IERC20(token).balanceOf(address(this));
            }

            if (IERC20(token).allowance(address(this), AL.THE_COMPACT) < idsAndAmounts[idIndex][1]) {
                SafeTransferLib.safeApproveWithRetry(token, AL.THE_COMPACT, type(uint256).max);
            }
        }

        return idsAndAmounts;
    }

    function _checkSignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        // Check if the signer is an authorized allocator address
        address signer = AL.recoverSigner(digest, signature);
        return signers[signer] && signer != address(0);
    }

    function _deriveDigest(bytes32 claimHash, bytes32 domainSeparator) internal pure returns (bytes32 digest) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 0x1901)
            mstore(add(m, 0x20), domainSeparator)
            mstore(add(m, 0x40), claimHash)
            digest := keccak256(add(m, 0x1e), 0x42)
        }
    }
}
