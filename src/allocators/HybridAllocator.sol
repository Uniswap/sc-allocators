// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {SafeTransferLib} from '@solady/utils/SafeTransferLib.sol';
import {LOCK_TYPEHASH, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

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
    event AttestationAuthorized(uint256 nonce);

    /// @dev The typehash for the HybridAllocationContext:
    ///      keccak256('HybridAllocationContext(bytes32 claimHash,Lock[] additionalCommitments)Lock(bytes12 lockTag,address token,uint256 amount)')
    bytes32 constant HYBRID_ALLOCATION_CONTEXT_TYPEHASH =
        0x3d88798eb330fca0ab1589827743878b2ccd0cdaa353080dffeb0d3e6fd7a639;

    /// @dev The typehash for the HybridAttestation:
    ///      keccak256('HybridAttestation(address sponsor,uint256 nonce,uint256 expires,Lock[] commitments)Lock(bytes12 lockTag,address token,uint256 amount)')
    bytes32 constant HYBRID_ATTESTATION_TYPEHASH = 0x85026382d0d24de6e57b7ed908c072c32612034a2cadacd54e95239975408a7f;

    /// @dev The slot for the attestation in transient storage
    ///      bytes4(keccak256('ATTESTATION_SLOT_SEED'))
    bytes4 constant ATTESTATION_SLOT_SEED = 0xd32d8248;

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

    /// @inheritdoc IHybridAllocator
    function authorizeAttestation(
        address sponsor,
        uint256 nonce,
        uint256 expires,
        Lock[] calldata commitments,
        bytes calldata allocatorSignature
    ) external returns (bool authorized) {
        // Verify expiration
        if (expires <= block.timestamp) {
            revert AttestationExpired();
        }
        // Verify the provided nonce
        AL.verifyNonce(nonce, AL.OFF_CHAIN_NONCE, sponsor);

        bytes32 hybridAttestationHash;
        // Store the attestation in transient storage and create the hybrid attestation hash
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, LOCK_TYPEHASH) // prestore the lock typehash for the commitmentsHash creation

            mstore(0x00, or(ATTESTATION_SLOT_SEED, sponsor)) // Store a combination of the slot seed and the sponsor address
            for { let i := 0 } lt(i, commitments.length) { i := add(i, 1) } {
                // Continue creating the transient slot hash
                let commitmentOffset := add(commitments.offset, mul(i, 0x60))
                let lockTag := calldataload(commitmentOffset)
                let token := calldataload(add(commitmentOffset, 0x20))
                let amount := calldataload(add(commitmentOffset, 0x40))

                mstore(0x20, or(lockTag, token)) // token id
                let slot := keccak256(0x00, 0x40) // create the slot out of the attestation slot seed, sponsor and token id

                // Store the amount authorized for transfer
                /// @dev This will override a previous attestation for the same Lock.
                ///      Make sure to design the commitment structure in a non repetitive way.
                tstore(slot, amount)

                // Create the commitment hash
                mstore(add(m, 0x20), lockTag)
                mstore(add(m, 0x40), token)
                mstore(add(m, 0x60), amount)
                let commitmentHash := keccak256(m, 0x80)
                // Store the commitment hash
                mstore(add(m, add(0x80, mul(i, 0x20))), commitmentHash)
            }
            let commitmentsHash := keccak256(add(m, 0x80), mul(commitments.length, 0x20))

            // Create the hybrid attestation hash
            mstore(m, HYBRID_ATTESTATION_TYPEHASH)
            mstore(add(m, 0x20), sponsor)
            mstore(add(m, 0x40), nonce)
            mstore(add(m, 0x60), expires)
            mstore(add(m, 0x80), commitmentsHash)
            hybridAttestationHash := keccak256(m, 0xa0)
        }

        // Verify signature
        bytes32 digest = _deriveDigest(hybridAttestationHash, _COMPACT_DOMAIN_SEPARATOR);
        if (block.chainid != _INITIAL_CHAIN_ID) {
            // If the chain was forked, we can not use the cached domain separator
            digest = _deriveDigest(hybridAttestationHash, ITheCompact(AL.THE_COMPACT).DOMAIN_SEPARATOR());
        }
        if (!_checkSignature(digest, allocatorSignature)) {
            revert InvalidSignature();
        }

        // Consume the nonce. Use the compacts nonce management
        uint256[] memory nonceArray = new uint256[](1);
        nonceArray[0] = nonce;
        ITheCompact(AL.THE_COMPACT).consume(nonceArray); // will revert if the nonce was already consumed

        emit AttestationAuthorized(nonce);
        authorized = true;
    }

    /// @inheritdoc IAllocator
    function attest(address, /*operator*/ address sponsor, address, /*to*/ uint256 id, uint256 amount)
        external
        returns (bytes4)
    {
        // Verify the caller is the compact
        if (msg.sender != AL.THE_COMPACT) {
            revert InvalidCaller(msg.sender, AL.THE_COMPACT);
        }

        assembly ("memory-safe") {
            mstore(0x00, or(ATTESTATION_SLOT_SEED, sponsor))
            mstore(0x20, id)
            let slot := keccak256(0x00, 0x40)
            let availableAmount := tload(slot)
            if lt(availableAmount, amount) {
                mstore(0x00, 0xc74b9fab) // InsufficientAttestationAmount()
                mstore(0x20, availableAmount)
                mstore(0x40, amount)
                revert(0x1c, 0x44)
            }

            tstore(slot, sub(availableAmount, amount))

            // Return the attest() selector to indicate a successful attestation
            mstore(0x00, 0x1a808f91)
            return(0x1c, 0x04)
        }
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

    /// @inheritdoc IOnChainAllocation
    function permit2Allocation(
        address arbiter,
        address depositor,
        uint256 expires,
        ISignatureTransfer.TokenPermissions[] calldata permitted,
        uint256[] calldata additionalCommitmentAmounts,
        DepositDetails calldata details,
        bytes32 claimHash,
        string calldata witness,
        bytes32 witnessHash,
        bytes calldata signature,
        bytes calldata context // allocator signature
    ) external returns (Lock[] memory) {
        (Lock[] memory commitments,, bool containsAdditionalCommitments) = AL.permit2Allocation(
            arbiter,
            depositor,
            expires,
            permitted,
            additionalCommitmentAmounts,
            details,
            claimHash,
            witness,
            witnessHash,
            signature
        );

        if (containsAdditionalCommitments) {
            // Validate the allocator's signature for the additional commitments
            _validateContext(commitments, additionalCommitmentAmounts, claimHash, context);
        }

        // Allocate the claim
        claims[claimHash] = true;

        emit Allocated(depositor, commitments, details.nonce, expires, claimHash);

        return commitments;
    }

    /// @inheritdoc IOnChainAllocation
    function prepareAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        uint256[] calldata additionalCommitmentAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata context
    ) external returns (uint256 nonce) {
        if (context.length > 0) {
            // Potential off chain nonce provided
            HybridAllocationContext calldata allocationContext = _decodeContext(context);

            // Verify the nonce is scoped to an off chain allocation and to the recipient
            AL.verifyNonce(allocationContext.nonce, AL.OFF_CHAIN_NONCE, recipient);
            nonce = allocationContext.nonce;
        } else {
            // No off chain nonce provided, use an on chain nonce
            uint88 nonce88 = nonces + 1;
            nonce = AL.getNonceWithCommand(AL.ON_CHAIN_NONCE, nonce88);
        }
        AL.prepareAllocation(
            nonce,
            recipient,
            idsAndAmounts,
            additionalCommitmentAmounts,
            arbiter,
            expires,
            typehash,
            witness,
            ALLOCATOR_ID
        );
    }

    /// @inheritdoc IOnChainAllocation
    function executeAllocation(
        address recipient,
        uint256[2][] calldata idsAndAmounts,
        uint256[] calldata additionalCommitmentAmounts,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness,
        bytes calldata context
    ) external {
        uint256 nonce;
        bytes32 claimHash;
        Lock[] memory commitments;
        bool containsAdditionalCommitments;

        if (context.length > 0) {
            // Off chain nonce and additional commitments amounts provided
            HybridAllocationContext calldata allocationContext = _decodeContext(context);

            // Verify the nonce is scoped to an off chain allocation and to the recipient
            AL.verifyNonce(allocationContext.nonce, AL.OFF_CHAIN_NONCE, recipient);

            nonce = allocationContext.nonce;
            (claimHash, commitments,, containsAdditionalCommitments) = AL.executeAllocation(
                nonce, recipient, idsAndAmounts, additionalCommitmentAmounts, arbiter, expires, typehash, witness
            );
            // Validate the signers signature for the hybrid allocation context
            _validateContext(commitments, additionalCommitmentAmounts, claimHash, allocationContext.signature);
        } else {
            // No off chain nonce provided, use an on chain nonce
            uint88 nonce88 = ++nonces;
            nonce = AL.getNonceWithCommand(AL.ON_CHAIN_NONCE, nonce88);
            (claimHash, commitments,, containsAdditionalCommitments) = AL.executeAllocation(
                nonce, recipient, idsAndAmounts, additionalCommitmentAmounts, arbiter, expires, typehash, witness
            );
            if (containsAdditionalCommitments) {
                revert InvalidSignature();
            }
        }

        // If the claim was already allocated, skip the allocation and the event emission
        if (claims[claimHash]) {
            return;
        }

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

    function _decodeContext(bytes calldata context)
        internal
        pure
        returns (HybridAllocationContext calldata allocationContext)
    {
        assembly ("memory-safe") {
            // context structure
            // 0x00: HybridAllocationContext.offset (0x20)
            // 0x20: HybridAllocationContext.nonce
            // 0x40: HybridAllocationContext.signature.offset (0x40 relative to struct start at 0x20)
            // 0x60: HybridAllocationContext.signature.length
            // 0x80: HybridAllocationContext.signature.content

            // required length must be 0x80 + signature length of 64 or 96 bytes (65 bytes will be padded to 96 bytes)

            let minimumLength := 0xc0

            let errorBuffer := or(lt(context.length, minimumLength), gt(context.length, add(minimumLength, 0x20))) // check length of context is valid
            errorBuffer := or(errorBuffer, xor(calldataload(add(context.offset, 0x40)), 0x40)) // check signature offset is valid (0x40 relative to struct start)

            // Check the signature is valid
            let calldataSignatureLength := calldataload(add(context.offset, 0x60))
            errorBuffer := or(errorBuffer, or(lt(calldataSignatureLength, 0x40), gt(calldataSignatureLength, 0x41))) // check signature length is valid (must be 64 or 65 bytes)
            if errorBuffer { revert(0x00, 0x00) }

            allocationContext := add(context.offset, 0x20)
        }
    }

    function _validateContext(
        Lock[] memory commitments,
        uint256[] calldata additionalCommitmentAmounts,
        bytes32 claimHash,
        bytes calldata allocatorSignature
    ) internal view {
        bytes32 hybridAllocationHash;
        bytes32[] memory commitmentsHashes = new bytes32[](commitments.length);

        // Create the hybrid allocation context hash
        assembly ("memory-safe") {
            // hybrid allocation context hash:
            // 0x00: typehash
            // 0x20: claimHash
            // 0x40: additionalCommitments hash

            let m := mload(0x40)
            mstore(m, HYBRID_ALLOCATION_CONTEXT_TYPEHASH) // typehash
            mstore(add(m, 0x20), claimHash) // claimHash

            // Create the commitments hash
            // Use the commitments lockTag and token, but the amount from additionalCommitmentAmounts
            let freeMemoryPointer := add(m, 0x60)
            let commitmentsLength := mload(commitments)
            // Populate all thecommitmentHashes
            mstore(freeMemoryPointer, LOCK_TYPEHASH)
            for { let i := 0 } lt(i, commitmentsLength) { i := add(i, 1) } {
                let commitmentOffset := mload(add(add(commitments, 0x20), mul(i, 0x20)))
                mstore(add(freeMemoryPointer, 0x20), mload(commitmentOffset)) // lockTag from commitments
                mstore(add(freeMemoryPointer, 0x40), mload(add(commitmentOffset, 0x20))) // token from commitments
                mstore(
                    add(freeMemoryPointer, 0x60), calldataload(add(additionalCommitmentAmounts.offset, mul(i, 0x20)))
                ) // amount from additionalCommitmentAmounts
                let commitmentsHashPointer := add(add(commitmentsHashes, 0x20 /* skip length */ ), mul(i, 0x20))
                mstore(commitmentsHashPointer, keccak256(freeMemoryPointer, 0x80))
            }

            // Create the commitments hash: keccak256(abi.encodePacked(commitmentsHashes))
            mstore(
                add(m, 0x40), keccak256(add(commitmentsHashes, 0x20 /* skip length */ ), mul(commitmentsLength, 0x20))
            )

            hybridAllocationHash := keccak256(m, 0x60)
        }
        bytes32 digest = _deriveDigest(hybridAllocationHash, _COMPACT_DOMAIN_SEPARATOR);
        if (block.chainid != _INITIAL_CHAIN_ID) {
            // If the chain was forked, we can not use the cached domain separator
            digest = _deriveDigest(claimHash, ITheCompact(AL.THE_COMPACT).DOMAIN_SEPARATOR());
        }
        if (!_checkSignature(digest, allocatorSignature)) {
            revert InvalidSignature();
        }
    }
}
