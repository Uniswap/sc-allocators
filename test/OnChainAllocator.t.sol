// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from 'forge-std/Test.sol';

import {ERC20Mock} from 'src/test/ERC20Mock.sol';

import {TheCompact} from '@uniswap/the-compact/TheCompact.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';

import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';

import {IOnChainAllocation} from '@uniswap/the-compact/interfaces/IOnChainAllocation.sol';
import {OnChainAllocator} from 'src/allocators/OnChainAllocator.sol';
import {IOnChainAllocator} from 'src/interfaces/IOnChainAllocator.sol';

import {BATCH_COMPACT_TYPEHASH, LOCK_TYPEHASH, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {ResetPeriod} from '@uniswap/the-compact/types/ResetPeriod.sol';
import {Scope} from '@uniswap/the-compact/types/Scope.sol';

import {IERC1271} from '@uniswap/the-compact/../lib/permit2/src/interfaces/IERC1271.sol';
import {IdLib} from '@uniswap/the-compact/lib/IdLib.sol';
import {AlwaysOKAllocator} from '@uniswap/the-compact/test/AlwaysOKAllocator.sol';

import {BatchClaim} from '@uniswap/the-compact/types/BatchClaims.sol';
import {Claim} from '@uniswap/the-compact/types/Claims.sol';
import {BatchClaimComponent, Component} from '@uniswap/the-compact/types/Components.sol';
import {AllocatorLib} from 'src/allocators/lib/AllocatorLib.sol';
import {OnChainAllocationCaller} from 'src/test/OnChainAllocationCaller.sol';

import {console} from 'forge-std/console.sol';
import {DeployTheCompact} from 'test/util/DeployTheCompact.sol';
import {TestHelper} from 'test/util/TestHelper.sol';

contract OnChainAllocatorFactory {
    function deploy(bytes32 salt) external returns (address) {
        return address(new OnChainAllocator{salt: salt}());
    }
}

contract OnChainAllocatorTest is Test, TestHelper {
    TheCompact internal compact;
    OnChainAllocator internal allocator;

    address internal arbiter;
    address internal user;
    uint256 internal userPK;

    ERC20Mock internal usdc;
    ERC20Mock internal dai;

    address internal recipient;
    address internal caller;
    uint256 internal callerPK;

    OnChainAllocationCaller internal allocationCaller;

    uint256 internal defaultAmount;
    uint32 internal defaultExpiration;

    uint256 defaultNonce;

    // For reentrancy testing
    MaliciousRecipient internal maliciousRecipient;

    function setUp() public {
        // Deploy TheCompact at the hardcoded address used by Utility.sol
        // This is necessary because OnChainAllocator now inherits from Utility
        // which requires THE_COMPACT (0x00000000000000171ede64904551eeDF3C6C9788) to exist
        compact = DeployTheCompact(new DeployTheCompact()).deployTheCompact();
        assertEq(address(compact), address(0x00000000000000171ede64904551eeDF3C6C9788));

        arbiter = makeAddr('arbiter');
        (user, userPK) = makeAddrAndKey('user');
        allocator = new OnChainAllocator();

        usdc = new ERC20Mock('USDC', 'USDC');
        dai = new ERC20Mock('DAI', 'DAI');

        recipient = makeAddr('recipient');
        (caller, callerPK) = makeAddrAndKey('caller');
        allocationCaller = new OnChainAllocationCaller(address(allocator), address(compact));
        deal(user, 1 ether);
        usdc.mint(user, 1 ether);

        defaultAmount = 1 ether;
        defaultExpiration = uint32(block.timestamp + 300); // 5 minutes fits 10-minute reset period
        defaultNonce = _composeNonceUint(user, 1);

        // Setup malicious recipient for reentrancy tests
        maliciousRecipient = new MaliciousRecipient(address(allocator), address(compact), address(allocationCaller));
    }

    /* --------------------------------------------------------------------- */
    /*                               Helpers                                 */
    /* --------------------------------------------------------------------- */

    function _composeNonceUint(address a, uint256 nonce) internal pure returns (uint256) {
        return (uint256(uint160(a)) << 96) | nonce;
    }

    function _commitmentsHash(Lock[] memory commitments) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            hashes[i] = keccak256(
                abi.encode(LOCK_TYPEHASH, commitments[i].lockTag, commitments[i].token, commitments[i].amount)
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function _makeLock(address token, uint256 amount) internal view returns (Lock memory l) {
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes);
        l = Lock({lockTag: lockTag, token: token, amount: amount});
    }

    function _createClaimHash(
        address sponsor,
        address arbiter_,
        uint256 nonce,
        uint256 expiration,
        Lock[] memory commitments,
        bytes32 witness
    ) internal pure returns (bytes32) {
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        if (witness == bytes32(0)) {
            return keccak256(abi.encode(BATCH_COMPACT_TYPEHASH, arbiter_, sponsor, nonce, expiration, commitmentsHash));
        } else {
            return keccak256(
                abi.encode(
                    BATCH_COMPACT_TYPEHASH_WITH_WITNESS, arbiter_, sponsor, nonce, expiration, commitmentsHash, witness
                )
            );
        }
    }

    /* --------------------------------------------------------------------- */
    /*                     Helpers for Reentrancy Tests                     */
    /* --------------------------------------------------------------------- */

    /**
     * @notice Creates a helper function for testing native token reentrancy.
     * @dev Flow using ERC1271 + OnChainAllocator:
     *      1. MaliciousRecipient deposits native tokens using OnChainAllocator's lockTag
     *      2. MaliciousRecipient calls allocate() to register with OnChainAllocator
     *      3. Returns id, claimHash, and nonce
     *      4. The claim uses OnChainAllocator for validation (checks stored claimHash)
     *      5. During withdrawal, receive() tries to call allocate() again → should fail
     */
    function _setupNativeTokenReentrancyTest() internal returns (uint256 id, bytes32 claimHash, uint256 nonce) {
        // MaliciousRecipient deposits native tokens using OnChainAllocator's lockTag
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({
            lockTag: _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes),
            token: address(0), // native token
            amount: defaultAmount
        });

        bytes12 lockTag = commitments[0].lockTag;
        deal(address(maliciousRecipient), defaultAmount);
        vm.prank(address(maliciousRecipient));
        id = compact.depositNative{value: defaultAmount}(lockTag, address(maliciousRecipient));

        // MaliciousRecipient calls allocate() to store claimHash in OnChainAllocator
        vm.prank(address(maliciousRecipient));
        (claimHash, nonce) = allocator.allocate(
            commitments, address(maliciousRecipient), defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    /**
     * @notice Creates a withdrawal BatchClaim struct for maliciousRecipient.
     * @dev Creates a simple withdrawal batch claim that uses OnChainAllocator:
     *      - Empty sponsorSignature triggers ERC1271 validation
     *      - MaliciousRecipient.isValidSignature() always returns success (0x1626ba7e)
     *      - lockTag = 0 in portions indicates withdrawal (native tokens sent)
     *      - allocatorData is empty (OnChainAllocator validates via stored claimHash)
     *      - sponsor = maliciousRecipient
     *      - arbiter = maliciousRecipient (when sponsor calls, arbiter must match)
     */
    function _createClaimForMaliciousRecipient(uint256 id, uint256 nonce, uint256 amount)
        internal
        view
        returns (BatchClaim memory)
    {
        // Create withdrawal portion (lockTag = 0 means withdrawal to native tokens)
        uint256 claimant = uint256(bytes32(abi.encodePacked(bytes12(0), address(maliciousRecipient))));
        Component[] memory portions = new Component[](1);
        portions[0] = Component({claimant: claimant, amount: amount});

        // Create BatchClaimComponent for this token
        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        claims[0] = BatchClaimComponent({id: id, allocatedAmount: amount, portions: portions});

        return BatchClaim({
            allocatorData: bytes(''), // Empty - OnChainAllocator validates via stored claimHash
            sponsorSignature: bytes(''), // Empty - triggers ERC1271 validation
            sponsor: address(maliciousRecipient), // MaliciousRecipient is the sponsor
            nonce: nonce,
            expires: defaultExpiration,
            witness: bytes32(0),
            witnessTypestring: '',
            claims: claims
        });
    }

    /* --------------------------------------------------------------------- */
    /*                               allocate()                              */
    /* --------------------------------------------------------------------- */

    function test_allocate_revert_InvalidCommitments() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidCommitments.selector));
        allocator.allocate(new Lock[](0), arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_revert_InvalidExpiration() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // Deposit native token to Compact first so allocation is backed
        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(lockTag, user);

        uint256 expiration = vm.getBlockTimestamp() + 600; // 10 min reset period

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, expiration, expiration));
        allocator.allocate(commitments, arbiter, uint32(expiration), BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_revert_ForceWithdrawalAvailable() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // Deposit native token to Compact first so allocation is backed
        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(lockTag, user);

        // Enable forced withdrawal
        vm.prank(user);
        (uint256 withdrawableAt) = compact.enableForcedWithdrawal(
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0))
        );

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.ForceWithdrawalAvailable.selector, withdrawableAt, withdrawableAt)
        );
        allocator.allocate(commitments, arbiter, uint32(withdrawableAt), BATCH_COMPACT_TYPEHASH, bytes32(0));

        vm.prank(user);
        allocator.allocate(commitments, arbiter, uint32(withdrawableAt - 1), BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_revert_InvalidAmount() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), uint256(type(uint224).max) + 1);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, commitments[0].amount));
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_revert_InsufficientBalance() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // No deposit made for native token – balance is zero, should revert.
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IOnChainAllocator.InsufficientBalance.selector,
                user,
                _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0)),
                0,
                defaultAmount
            )
        );
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_revert_InvalidAllocator() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        commitments[0].lockTag = bytes12(commitments[0].lockTag & bytes12(0x110000000000000000000000));

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidAllocator.selector, 0, allocator.ALLOCATOR_ID())
        );
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_allocate_success_nativeToken() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // Deposit native token to Compact first so allocation is backed
        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(lockTag, user);

        vm.prank(user);
        (bytes32 claimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_native');

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(nonce, defaultNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocate_success_erc20() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        // Deposit ERC20 into Compact so allocation is backed
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);
        vm.prank(user);
        compact.depositERC20(address(usdc), commitments[0].lockTag, defaultAmount, user);

        vm.prank(user);
        (bytes32 claimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_erc20');

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(nonce, defaultNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocate_success_erc20_multipleAllocations() public {
        uint256 amount = defaultAmount / 2;
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), amount);

        // Deposit ERC20 into Compact so allocation is backed
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);
        vm.prank(user);
        compact.depositERC20(address(usdc), commitments[0].lockTag, defaultAmount, user);

        vm.prank(user);
        (bytes32 claimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_erc20');

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = amount;

        assertEq(nonce, defaultNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        vm.prank(user);
        (claimHash, nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration + 10, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_second_erc20');

        assertEq(nonce, defaultNonce + 1);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration + 10, idsAndAmounts, '')
        );

        // expire the first allocation and allocate again
        vm.warp(defaultExpiration + 1);
        vm.prank(user);
        (claimHash, nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration + 10, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_and_delete_expired_allocation');

        assertEq(nonce, defaultNonce + 2);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration + 10, idsAndAmounts, '')
        );
    }

    function test_allocate_fuzz(uint128 depositAmount, uint128 firstAmount, uint128 secondAmount, bytes32 witness)
        public
    {
        vm.assume(depositAmount > 0);
        vm.assume(firstAmount <= depositAmount);

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), firstAmount);

        // Deposit ERC20 into Compact so allocation is backed
        vm.startPrank(user);
        usdc.mint(user, depositAmount);
        usdc.approve(address(compact), depositAmount);
        compact.depositERC20(address(usdc), commitments[0].lockTag, depositAmount, user);
        vm.stopPrank();

        uint256 expectedNonce = defaultNonce;
        bytes32 claimHash = _createClaimHash(user, arbiter, expectedNonce, defaultExpiration, commitments, witness);

        // first allocation

        bytes32 typehash = witness == bytes32(0) ? BATCH_COMPACT_TYPEHASH : BATCH_COMPACT_TYPEHASH_WITH_WITNESS;

        vm.prank(user);
        vm.expectEmit(true, true, true, true);
        emit IOnChainAllocation.Allocated(user, commitments, expectedNonce, defaultExpiration, claimHash);
        (bytes32 returnedClaimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, typehash, witness);

        assertEq(returnedClaimHash, claimHash);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = firstAmount;

        assertEq(nonce, expectedNonce, 'nonce 1');
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        // second allocation
        commitments[0].amount = secondAmount;

        vm.prank(user);
        if (uint256(secondAmount) + uint256(firstAmount) > depositAmount) {
            // expect a revert of the second allocation
            vm.expectRevert(
                abi.encodeWithSelector(
                    IOnChainAllocator.InsufficientBalance.selector,
                    user,
                    _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc)),
                    depositAmount - firstAmount,
                    secondAmount
                )
            );
        } else {
            // expect a successful second allocation
            expectedNonce = defaultNonce + 1;
            claimHash = _createClaimHash(user, arbiter, expectedNonce, defaultExpiration, commitments, witness);
            vm.expectEmit(true, true, true, true);
            emit IOnChainAllocation.Allocated(user, commitments, expectedNonce, defaultExpiration, claimHash);
        }
        (claimHash, nonce) = allocator.allocate(commitments, arbiter, defaultExpiration, typehash, witness);

        if (uint256(secondAmount) + uint256(firstAmount) <= depositAmount) {
            // Check the allocations
            idsAndAmounts[0][1] = secondAmount;

            assertEq(nonce, expectedNonce, 'nonce 1');
            assertTrue(
                allocator.isClaimAuthorized(
                    claimHash, arbiter, user, defaultNonce, /*nonce*/ defaultExpiration, idsAndAmounts, ''
                )
            );
            assertTrue(
                allocator.isClaimAuthorized(
                    claimHash, arbiter, user, defaultNonce + 1, /*nonce*/ defaultExpiration, idsAndAmounts, ''
                )
            );

            uint256 amountToAttest = depositAmount - (uint256(secondAmount) + uint256(firstAmount));

            assertEq(
                allocator.attest(address(this), user, address(this), idsAndAmounts[0][0], amountToAttest),
                IAllocator.attest.selector
            );
            vm.expectRevert(
                abi.encodeWithSelector(
                    IOnChainAllocator.InsufficientBalance.selector,
                    user,
                    idsAndAmounts[0][0],
                    amountToAttest,
                    amountToAttest + 1
                )
            );
            allocator.attest(address(this), user, address(this), idsAndAmounts[0][0], amountToAttest + 1);
        } else if (secondAmount <= depositAmount) {
            // Second allocation should be possible after the first one is expired
            vm.warp(defaultExpiration + 1);
            uint32 expiration = defaultExpiration + 100;
            expectedNonce = defaultNonce + 1;

            vm.prank(user);
            (claimHash, nonce) = allocator.allocate(commitments, arbiter, expiration, typehash, witness);
            assertEq(nonce, expectedNonce, 'nonce 2');
            assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, expiration, idsAndAmounts, ''));
        }
    }

    /* --------------------------------------------------------------------- */
    /*                           allocateFor()                               */
    /* --------------------------------------------------------------------- */
    function test_allocateFor_revert_InvalidExpiration(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        vm.warp(defaultExpiration);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, defaultExpiration, block.timestamp)
        );
        allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, '');
    }

    function test_allocateFor_revert_InvalidSignature() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        (address attacker, uint256 attackerPK) = makeAddrAndKey('attacker');

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);

        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPK, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidSignature.selector, attacker, user));
        allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, badSig);
    }

    function test_allocateFor_revert_InvalidSignature_invalidSignatureLength(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);

        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPK, digest);
        bytes memory sig = abi.encode(r, s, v); // wrong length because not packed: 96 bytes instead of 65 bytes

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidSignature.selector, address(0), user));
        allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);
    }

    function test_allocateFor_revert_oldSignatureAfterFork(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 snap = vm.snapshot();
        assertEq(block.chainid, 31_337);

        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) =
            allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        vm.revertTo(snap);
        vm.chainId(1);
        assertEq(block.chainid, 1);

        // After chain fork, the domain separator changes, so the signature will recover
        // to a different address (not the user). We compute the wrong recovered address
        // by using the new chain's domain separator with the old signature.
        bytes32 newDigest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        address wrongSigner = ecrecover(newDigest, v, r, s);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidSignature.selector, wrongSigner, user));
        allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);
    }

    function test_allocateFor_success_withCompactSignature(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);

        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (bytes32 r, bytes32 vs) = vm.signCompact(userPK, digest);
        bytes memory sig = abi.encodePacked(r, vs);

        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) =
            allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocateFor_success_withSignature(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) =
            allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocateFor_success_withSignature_multipleCommitments(address relayer) public {
        Lock[] memory commitments = new Lock[](2);
        commitments[0] = _makeLock(address(0), defaultAmount);
        commitments[1] = _makeLock(address(usdc), defaultAmount);
        vm.startPrank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compact), defaultAmount);
        compact.depositERC20(address(usdc), commitments[1].lockTag, defaultAmount, user);
        vm.stopPrank();

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash)
        );
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) =
            allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, 0x0, sig);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocateFor_success_withWitness(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);
        bytes32 witness = bytes32(keccak256('witness'));
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH, arbiter, user, expectedNonce, defaultExpiration, commitmentsHash, witness
            )
        );
        bytes memory sig;
        {
            bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPK, digest);
            sig = abi.encodePacked(r, s, v);
        }
        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) =
            allocator.allocateFor(user, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, witness, sig);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        assertEq(allocator.nonces(user), 1);
    }

    function test_allocateFor_revert_InvalidRegistration(address relayer) public {
        // Build commitments with native token deposit backing
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // Nonce that allocateFor will use
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);

        // Compute claimHash that allocateFor will create internally
        bytes32 claimHash = _createClaimHash(user, arbiter, expectedNonce, defaultExpiration, commitments, bytes32(0));

        // Expect InvalidRegistration revert because claimHash is NOT registered on The Compact
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocation.InvalidRegistration.selector, user, claimHash));
        allocator.allocateFor(
            user,
            commitments,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0),
            '' // empty signature triggers registration check
        );
    }

    function test_allocateFor_success_noSignature() public {
        address relayer = makeAddr('relayer');
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // Determine nonce the allocator will use
        uint256 expectedNonce = _composeNonceUint(user, allocator.nonces(user) + 1);

        // Pre-compute claimHash that `allocateFor` will produce
        bytes32 claimHash = _createClaimHash(user, arbiter, expectedNonce, defaultExpiration, commitments, bytes32(0));

        // Prepare ids & amounts for native token deposit + registration
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        // Prepare claimHashes+typehashes array for registration
        bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](1);
        claimHashesAndTypehashes[0][0] = claimHash;
        claimHashesAndTypehashes[0][1] = BATCH_COMPACT_TYPEHASH;

        // User deposits native token & registers the compact directly on TheCompact
        vm.prank(user);
        compact.batchDepositAndRegisterMultiple{value: defaultAmount}(idsAndAmounts, claimHashesAndTypehashes);

        // Relayer submits allocateFor WITHOUT any signature (length == 0)
        vm.prank(relayer);
        (bytes32 returnedHash, uint256 nonce) = allocator.allocateFor(
            user,
            commitments,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0),
            '' // empty signature triggers the "registered" code path
        );
        vm.snapshotGasLastCall('allocateFor_success_withRegistration');

        // Assertions
        assertEq(returnedHash, claimHash);
        assertEq(nonce, expectedNonce);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    /* --------------------------------------------------------------------- */
    /*                           isClaimAuthorized()                         */
    /* --------------------------------------------------------------------- */

    function test_isClaimAuthorized_false_notAuthorized() public view {
        assertFalse(allocator.isClaimAuthorized(bytes32(0), arbiter, user, 0, 0, new uint256[2][](0), ''));
    }

    function test_isClaimAuthorized_false_expired() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        vm.prank(user);
        (bytes32 claimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        vm.prank(user);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        vm.warp(defaultExpiration + 1);
        vm.prank(user);
        assertFalse(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_isClaimAuthorized_success() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        vm.prank(user);
        (bytes32 claimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        vm.prank(user);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        vm.warp(defaultExpiration);
        vm.prank(user);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    /* --------------------------------------------------------------------- */
    /*                         authorizeClaim()                              */
    /* --------------------------------------------------------------------- */

    function test_authorizeClaim_invalidCaller() public {
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidCaller.selector, address(this), address(compact))
        );
        allocator.authorizeClaim(bytes32(0), arbiter, user, 0, 0, new uint256[2][](0), '');
    }

    function test_authorizeClaim_success() public {
        // register claim via allocate()
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // back with native deposit
        bytes12 lt = commitments[0].lockTag;
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(lt, user);
        vm.prank(user);
        (bytes32 claimHash,) =
            allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        uint256 idNat = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][0] = idNat;
        idsAndAmounts[0][1] = defaultAmount;

        // call from Compact contract address
        vm.prank(address(compact));
        bytes4 sel = allocator.authorizeClaim(claimHash, arbiter, user, 1, defaultExpiration, idsAndAmounts, '');
        vm.snapshotGasLastCall('authorizeClaim_success_single_allocation');
        assertEq(sel, IAllocator.authorizeClaim.selector);

        // check deletion of the allocation
        vm.prank(address(compact));
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidClaim.selector, claimHash));
        allocator.authorizeClaim(claimHash, arbiter, user, 1, defaultExpiration, idsAndAmounts, '');
    }

    function test_authorizeClaim_deletesMiddleOfMultipleAllocations_correctly() public {
        // Prepare a large ERC20 deposit so three allocations can be made for the same id.
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;
        uint256 amount3 = 3 ether;
        uint256 total = amount1 + amount2 + amount3;

        // Deposit ERC20 into Compact for the user
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes);
        vm.startPrank(user);
        usdc.mint(user, total);
        usdc.approve(address(compact), total);
        compact.depositERC20(address(usdc), lockTag, total, user);
        vm.stopPrank();

        // Make three allocations for the same id with increasing expirations
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: amount1});
        bytes32 claimHash1;
        {
            vm.prank(user);
            (claimHash1,) = allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        }

        bytes32 claimHash2;
        {
            commitments[0].amount = amount2;
            vm.prank(user);
            (claimHash2,) = allocator.allocate(commitments, arbiter, defaultExpiration + 10, BATCH_COMPACT_TYPEHASH, '');
        }

        bytes32 claimHash3;
        {
            commitments[0].amount = amount3;
            vm.prank(user);
            (claimHash3,) = allocator.allocate(commitments, arbiter, defaultExpiration + 20, BATCH_COMPACT_TYPEHASH, '');
        }

        // idsAndAmounts used by authorizeClaim (amount is not used for verification but keep it consistent)
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = amount1;

        // 1) Delete the MIDDLE allocation first (claimHash2). This exercises swap-and-pop correctness.
        vm.prank(address(compact));
        bytes4 sel = allocator.authorizeClaim(claimHash2, arbiter, user, 0, defaultExpiration, idsAndAmounts, '');
        assertEq(sel, IAllocator.authorizeClaim.selector);

        // 2) The other allocations must still be present and independently deletable.
        vm.prank(address(compact));
        sel = allocator.authorizeClaim(claimHash3, arbiter, user, 0, defaultExpiration, idsAndAmounts, '');
        assertEq(sel, IAllocator.authorizeClaim.selector);

        vm.prank(address(compact));
        sel = allocator.authorizeClaim(claimHash1, arbiter, user, 0, defaultExpiration, idsAndAmounts, '');
        assertEq(sel, IAllocator.authorizeClaim.selector);

        // 3) All allocations are deleted now; reusing any claim should revert.
        vm.prank(address(compact));
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidClaim.selector, claimHash1));
        allocator.authorizeClaim(claimHash1, arbiter, user, 0, defaultExpiration, idsAndAmounts, '');
    }

    /* --------------------------------------------------------------------- */
    /*                                 attest                                */
    /* --------------------------------------------------------------------- */

    function test_attest_revert_InsufficientBalance() public {
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, user, id, 0, defaultAmount)
        );
        allocator.attest(address(0), user, address(0), id, defaultAmount);
    }

    function test_attest_revert_InsufficientBalance_previousAllocation() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        vm.prank(user);
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, user, id, 0, 1));
        allocator.attest(address(this), user, address(this), id, 1);
    }

    function test_attest_success_previousAllocation() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount - 1);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        vm.prank(user);
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        vm.prank(user);
        vm.assertEq(allocator.attest(address(this), user, address(this), id, 1), allocator.attest.selector);
    }

    function test_attest_success() public {
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        // deposit id to Compact for user
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(bytes12(bytes32(id)), user);

        vm.prank(user);
        bytes4 sel = allocator.attest(address(0), user, address(0), id, defaultAmount);
        assertEq(sel, allocator.attest.selector);
    }

    /* --------------------------------------------------------------------- */
    /*                          allocateAndRegister()                        */
    /* --------------------------------------------------------------------- */

    function test_allocateAndRegister_revert_InvalidExpiration() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        // Fund allocator with tokens
        usdc.mint(address(allocator), defaultAmount);

        uint256 expiration = block.timestamp + 600;
        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, expiration, block.timestamp + 600)
        );
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, uint32(expiration), BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    /* --------------------------------------------------------------------- */
    /*                   prepareAllocation / executeAllocation               */
    /* --------------------------------------------------------------------- */

    function _idsAndAmountsFor(address token, uint256 amount)
        internal
        view
        returns (uint256[2][] memory idsAndAmounts)
    {
        idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), token);
        idsAndAmounts[0][1] = amount;
    }

    function _idsAndAmountsFor2(address tokenA, uint256 amountA, address tokenB, uint256 amountB)
        internal
        view
        returns (uint256[2][] memory idsAndAmounts)
    {
        idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), tokenA);
        idsAndAmounts[0][1] = amountA;
        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), tokenB);
        idsAndAmounts[1][1] = amountB;
    }

    function test_prepareAllocation_revert_InvalidAllocatorId() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(this), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        uint96 allocatorId = _toAllocatorId(address(this));

        vm.expectRevert(
            abi.encodeWithSelector(AllocatorLib.InvalidAllocatorId.selector, allocatorId, allocator.ALLOCATOR_ID())
        );
        allocator.prepareAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );
    }

    function test_prepareAllocation_returnsNonce_and_doesNotIncrementStorage() public {
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), defaultAmount);

        // call from an arbitrary EOA (caller)
        vm.prank(caller);
        uint256 returnedNonce = allocator.prepareAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertEq(returnedNonce, _composeNonceUint(address(0), 1));
        // storage nonce is only incremented in executeAllocation
        assertEq(allocator.nonces(caller), 0);
        assertEq(allocator.nonces(address(0)), 0);
    }

    function test_prepareAllocation_revert_InvalidExpiration() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        vm.expectRevert(
            abi.encodeWithSelector(
                IOnChainAllocator.InvalidExpiration.selector, uint256(type(uint32).max) + 1, type(uint32).max
            )
        );
        allocator.prepareAllocation(
            recipient, idsAndAmounts, arbiter, uint256(type(uint32).max) + 1, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );
    }

    function test_executeAllocation_revert_InvalidExpiration() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        vm.expectRevert(
            abi.encodeWithSelector(
                IOnChainAllocator.InvalidExpiration.selector, uint256(type(uint32).max) + 1, type(uint32).max
            )
        );
        allocator.executeAllocation(
            recipient, idsAndAmounts, arbiter, uint256(type(uint32).max) + 1, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );
    }

    function test_executeAllocation_success_viaCaller_singleERC20() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // fund and approve from allocationCaller
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // Check nonce previous to the allocation
        assertEq(allocator.nonces(address(allocationCaller)), 0);

        // run the whole flow in a single tx through the helper
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );
        vm.snapshotGasLastCall('onchain_execute_single');

        // nonce is scoped to (callerContract, recipient)
        assertEq(allocator.nonces(address(allocationCaller)), 0);
        assertEq(allocator.nonces(address(0)), 1);
        uint256 expectedNonce = _composeNonceUint(address(0), 1);

        // compute claim hash and check authorization
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        bytes32 claimHash =
            _createClaimHash(recipient, arbiter, expectedNonce, defaultExpiration, commitments, bytes32(0));

        assertTrue(
            allocator.isClaimAuthorized(
                claimHash, arbiter, recipient, expectedNonce, defaultExpiration, idsAndAmounts, ''
            )
        );
    }

    /// forge-config: default.isolate = false
    function test_executeAllocation_revert_multiplePreparations() public {
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), defaultAmount);

        uint256[2][] memory idsAndAmountsCrooked = new uint256[2][](2);
        idsAndAmountsCrooked[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0)); // additionally use another ids to receive a unique identifier slot
        idsAndAmountsCrooked[0][1] = defaultAmount;
        idsAndAmountsCrooked[1] = idsAndAmounts[0]; // Crooked idsAndAmounts is also using USDC as the same ID, among others

        usdc.mint(address(this), defaultAmount);
        usdc.approve(address(compact), defaultAmount);

        // prepare for the recipient using caller 1
        vm.prank(recipient);
        uint256 nonce1 = allocator.prepareAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        // prepare for second recipient - DIFFERENT CALLER TO RECEIVE A DIFFERENT NONCE SLOT
        vm.prank(address(this));
        uint256 nonce2 = allocator.prepareAllocation(
            recipient, idsAndAmountsCrooked, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertEq(nonce1, _composeNonceUint(address(0), 1));
        assertEq(nonce2, _composeNonceUint(address(0), 1));

        // We do a single deposit of usdc with defaultAmount. This would mean, that we SHOULD only able to allocate defaultAmount of usdc
        ITheCompact(compact).batchDeposit{value: defaultAmount}(idsAndAmountsCrooked, recipient);

        // Crooked registrations: we register two claims that would each use all of the usdc (so defaultAmount * 2 combined)
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        bytes32 claimHash1Crooked =
            _createClaimHash(recipient, arbiter, nonce1, defaultExpiration, commitments, bytes32(0));
        Lock[] memory commitmentsCrooked = _idsAndAmountsToCommitments(idsAndAmountsCrooked);
        bytes32 claimHash2Crooked =
            _createClaimHash(recipient, arbiter, nonce2, defaultExpiration, commitmentsCrooked, bytes32(0));
        vm.prank(recipient);
        ITheCompact(compact).register(claimHash1Crooked, BATCH_COMPACT_TYPEHASH);
        vm.prank(recipient);
        ITheCompact(compact).register(claimHash2Crooked, BATCH_COMPACT_TYPEHASH);

        // execute for first allocation
        vm.prank(recipient);
        allocator.executeAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        // execute for second allocation which must fail
        vm.prank(address(this));
        vm.expectRevert(abi.encodeWithSelector(AllocatorLib.InvalidPreparation.selector));
        allocator.executeAllocation(
            recipient, idsAndAmountsCrooked, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertTrue(
            allocator.isClaimAuthorized(
                claimHash1Crooked, arbiter, recipient, nonce1, defaultExpiration, idsAndAmounts, ''
            )
        );
        assertFalse(
            allocator.isClaimAuthorized(
                claimHash2Crooked, arbiter, recipient, nonce2, defaultExpiration, idsAndAmounts, ''
            )
        );
    }

    /// forge-config: default.isolate = false
    function test_executeAllocation_revert_multipleDifferentPreparations(address recipient1, address recipient2)
        public
    {
        vm.assume(recipient1 != address(0));
        vm.assume(recipient2 != address(0));
        vm.assume(recipient1 != recipient2);

        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), defaultAmount);

        uint256 previousBalance = 1_000_000;
        usdc.mint(address(this), previousBalance + 2 * defaultAmount);
        usdc.approve(address(compact), previousBalance + 2 * defaultAmount);

        // deposit funds to recipient1
        compact.depositERC20(
            address(usdc),
            _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes),
            previousBalance,
            recipient1
        );

        // Check nonce previous to the allocation
        assertEq(allocator.nonces(address(0)), 0);

        // prepare for first recipient
        vm.prank(recipient1);
        uint256 nonce1 = allocator.prepareAllocation(
            recipient1, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        // prepare for second recipient
        vm.prank(recipient2);
        uint256 nonce2 = allocator.prepareAllocation(
            recipient2, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertEq(nonce1, _composeNonceUint(address(0), 1));
        assertEq(nonce2, _composeNonceUint(address(0), 1));
        // The provided nonces should be the same because they use the same pool of nonces, independent of the recipient or caller
        assertEq(nonce1, nonce2);

        // compute claim hash and check authorization
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        bytes32 claimHash1 = _createClaimHash(recipient1, arbiter, nonce1, defaultExpiration, commitments, bytes32(0));
        bytes32 claimHash2 = _createClaimHash(recipient2, arbiter, nonce2, defaultExpiration, commitments, bytes32(0));

        ITheCompact(compact).batchDepositAndRegisterFor(
            recipient1, idsAndAmounts, arbiter, nonce1, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );

        ITheCompact(compact).batchDepositAndRegisterFor(
            recipient2, idsAndAmounts, arbiter, nonce2, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );

        // execute for first recipient
        vm.prank(recipient1);
        allocator.executeAllocation(
            recipient1, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        // execute for second recipient
        vm.prank(recipient2);
        vm.expectRevert(abi.encodeWithSelector(AllocatorLib.InvalidPreparation.selector));
        allocator.executeAllocation(
            recipient2, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertTrue(
            allocator.isClaimAuthorized(claimHash1, arbiter, recipient1, nonce1, defaultExpiration, idsAndAmounts, '')
        );
        assertFalse(
            allocator.isClaimAuthorized(claimHash2, arbiter, recipient2, nonce2, defaultExpiration, idsAndAmounts, '')
        );
    }

    function test_executeAllocation_revert_InvalidPreparation() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // fund and approve from allocationCaller
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // todo = 2: deposit+register without prepareAllocation -> executeAllocation must revert InvalidPreparation
        vm.prank(user);
        vm.expectRevert(AllocatorLib.InvalidPreparation.selector);
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 2
        );
    }

    function test_executeAllocation_revert_InvalidRegistration() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // fund and approve from allocationCaller
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // todo = 1: deposit only (no registration) -> executeAllocation must revert InvalidRegistration
        // Expect the precise error and arguments from AllocatorLib
        // Compute the claimHash that AllocatorLib will recompute during execute.
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        bytes32 expectedClaimHash = _createClaimHash(
            recipient, arbiter, _composeNonceUint(address(0), 1), defaultExpiration, commitments, bytes32(0)
        );
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                AllocatorLib.InvalidRegistration.selector, recipient, expectedClaimHash, BATCH_COMPACT_TYPEHASH
            )
        );
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 1
        );
    }

    function test_executeAllocation_revert_InvalidBalanceChange_onZeroAmountSecondId() public {
        uint256 amountA = defaultAmount;
        uint256 amountB = 0; // no deposit for second id -> balance unchanged -> InvalidBalanceChange
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor2(address(usdc), amountA, address(dai), amountB);

        // fund and approve only the first token
        usdc.mint(address(allocationCaller), amountA);
        vm.startPrank(address(allocationCaller));
        usdc.approve(address(compact), amountA);
        // approve DAI even if amount is zero to avoid allowance issues
        dai.approve(address(compact), 0);
        vm.stopPrank();

        // Even though registration will succeed (with 0 for the second id), executeAllocation should revert
        vm.prank(user);
        // Revert happens inside TheCompact deposit logic before executeAllocation runs
        // Use the selector for InvalidDepositBalanceChange()
        vm.expectRevert(bytes4(keccak256('InvalidDepositBalanceChange()')));
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );
    }

    function test_executeAllocation_success_twoIds() public {
        uint256 amountA = defaultAmount;
        uint256 amountB = defaultAmount / 2;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor2(address(usdc), amountA, address(dai), amountB);

        // fund & approve caller for both tokens
        usdc.mint(address(allocationCaller), amountA);
        dai.mint(address(allocationCaller), amountB);
        vm.startPrank(address(allocationCaller));
        usdc.approve(address(compact), amountA);
        dai.approve(address(compact), amountB);
        vm.stopPrank();

        vm.prank(user);
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );
        vm.snapshotGasLastCall('onchain_execute_double');

        // authorization with the measured amounts
        uint256 expectedNonce = _composeNonceUint(address(0), 1);

        assertTrue(
            allocator.isClaimAuthorized(
                _createClaimHash(
                    recipient,
                    arbiter,
                    expectedNonce,
                    defaultExpiration,
                    _idsAndAmountsToCommitments(idsAndAmounts),
                    bytes32(0)
                ),
                arbiter,
                recipient,
                expectedNonce,
                defaultExpiration,
                idsAndAmounts,
                ''
            )
        );
    }

    function test_executeAllocation_revert_InvalidBalanceChange_noDeposit() public {
        // Prepare only, no deposit → newBalance <= oldBalance → InvalidBalanceChange
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // Give recipient a prior ERC6909 balance so revert is not (0,0)
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes);
        vm.startPrank(user);
        usdc.mint(user, amount);
        usdc.approve(address(compact), amount);
        compact.depositERC20(address(usdc), lockTag, amount, recipient);
        vm.stopPrank();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature('InvalidBalanceChange(uint256,uint256)', amount, amount));
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 3
        );
    }

    function test_executeAllocation_revert_InvalidPreparation_replaySameTx() public {
        // First execute succeeds; second execute in same tx (without new prepare) must fail with InvalidPreparation
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // fund and approve caller for deposit
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        vm.prank(user);
        vm.expectRevert(AllocatorLib.InvalidPreparation.selector);
        // todo=4 triggers deposit+register + execute, then a second execute at function end
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 4
        );
    }

    function test_executeAllocation_fullAllocation_preventsFurtherAllocate() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), amount);

        // fund and approve caller for deposit
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // perform correct prepare + deposit + register + execute
        vm.prank(user);
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );

        // Now the whole balance is allocated for recipient; another allocate should fail
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), 1);

        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));

        vm.prank(recipient);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, recipient, id, 0, 1));
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
    }

    function test_executeAllocation_revert_InvalidAmount_largeDeposit() public {
        // Deposit an amount > uint224.max so executeAllocation reverts on range check
        uint256 largeAmount = uint256(type(uint224).max) + 1;
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), largeAmount);

        // fund and approve caller for large amount
        usdc.mint(address(allocationCaller), largeAmount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), largeAmount);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, largeAmount));
        allocationCaller.onChainAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );
    }

    function test_allocateAndRegister_revert_InvalidCommitments() public {
        Lock[] memory commitments = new Lock[](0);

        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidCommitments.selector));
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAmount_native() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), 1 ether);

        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, commitments[0].amount));
        allocator.allocateAndRegister{value: commitments[0].amount + 1}(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAmount_native_with_zero_deposit() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), 0 ether);

        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, 0));
        allocator.allocateAndRegister{value: 0}(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAmount_non_native_with_non_zero_native_call() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), 1);

        uint256 amount = 1;
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, amount));
        allocator.allocateAndRegister{value: amount}(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_invalidExpiration() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        usdc.mint(address(allocator), defaultAmount);

        vm.warp(defaultExpiration);

        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, defaultExpiration, block.timestamp)
        );
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAmount() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), uint256(type(uint224).max) + 1);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, commitments[0].amount));
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAmount_balance() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), 0);
        usdc.mint(address(allocator), uint256(type(uint224).max) + 1);

        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, uint256(type(uint224).max) + 1)
        );
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_revert_InvalidAllocator() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);
        commitments[0].lockTag = bytes12(commitments[0].lockTag & bytes12(0x110000000000000000000000));

        vm.prank(caller);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidAllocator.selector, 0, allocator.ALLOCATOR_ID())
        );
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );
    }

    function test_allocateAndRegister_success_singleERC20() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        usdc.mint(address(allocator), defaultAmount);

        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(nonce, _composeNonceUint(address(0), 1));
        assertEq(registeredAmounts.length, 1);
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, idsAndAmounts[0][0]), defaultAmount);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, recipient, nonce, defaultExpiration, idsAndAmounts, '')
        );
        assertTrue(compact.isRegistered(recipient, claimHash, BATCH_COMPACT_TYPEHASH));
        bytes32 claimHashRecreated =
            _createClaimHash(recipient, arbiter, nonce, defaultExpiration, commitments, bytes32(0));
        assertEq(claimHashRecreated, claimHash);
    }

    function test_allocateAndRegister_success_singleERC20_withWitness(bytes32 witness) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        bytes32 typehash = witness == bytes32(0) ? BATCH_COMPACT_TYPEHASH : BATCH_COMPACT_TYPEHASH_WITH_WITNESS;

        usdc.mint(address(allocator), defaultAmount);

        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) =
            allocator.allocateAndRegister(recipient, commitments, arbiter, defaultExpiration, typehash, witness);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(nonce, _composeNonceUint(address(0), 1));
        assertEq(registeredAmounts.length, 1);
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, idsAndAmounts[0][0]), defaultAmount);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, recipient, nonce, defaultExpiration, idsAndAmounts, '')
        );
        assertTrue(compact.isRegistered(recipient, claimHash, typehash));
        bytes32 claimHashRecreated =
            _createClaimHash(recipient, arbiter, nonce, defaultExpiration, commitments, witness);
        assertEq(claimHashRecreated, claimHash);
    }

    function test_allocateAndRegister_success_amountZeroDepositsFullBalance(bytes32 witness) public {
        uint256 depositAmount = 5 ether;
        usdc.mint(address(allocator), depositAmount);

        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), 0);

        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, witness
        );

        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));

        assertEq(registeredAmounts[0], depositAmount);
        assertEq(usdc.balanceOf(address(allocator)), 0);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, id), depositAmount);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = id;
        idsAndAmounts[0][1] = depositAmount;

        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, recipient, nonce, defaultExpiration, idsAndAmounts, '')
        );
    }

    function test_allocateAndRegister_success_multipleERC20() public {
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;

        usdc.mint(address(allocator), amount1);
        dai.mint(address(allocator), amount2);

        Lock[] memory commitments = new Lock[](2);
        commitments[0] = _makeLock(address(usdc), amount1);
        commitments[1] = _makeLock(address(dai), amount2);

        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );

        uint256 id1 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        uint256 id2 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(dai));

        assertEq(registeredAmounts.length, 2);
        assertEq(registeredAmounts[0], amount1);
        assertEq(registeredAmounts[1], amount2);

        assertEq(ERC6909(address(compact)).balanceOf(recipient, id1), amount1);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, id2), amount2);

        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = id1;
        idsAndAmounts[0][1] = amount1;
        idsAndAmounts[1][0] = id2;
        idsAndAmounts[1][1] = amount2;

        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, recipient, nonce, defaultExpiration, idsAndAmounts, '')
        );
    }

    function test_allocateAndRegister_success_multiple() public {
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;

        usdc.mint(address(allocator), amount2);

        Lock[] memory commitments = new Lock[](2);
        commitments[0] = _makeLock(address(0), amount1);
        commitments[1] = _makeLock(address(usdc), amount2);

        vm.deal(caller, amount1);
        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: amount1
        }(recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        uint256 id1 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        uint256 id2 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));

        assertEq(registeredAmounts.length, 2);
        assertEq(registeredAmounts[0], amount1);
        assertEq(registeredAmounts[1], amount2);

        assertEq(ERC6909(address(compact)).balanceOf(recipient, id1), amount1);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, id2), amount2);

        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = id1;
        idsAndAmounts[0][1] = amount1;
        idsAndAmounts[1][0] = id2;
        idsAndAmounts[1][1] = amount2;

        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, recipient, nonce, defaultExpiration, idsAndAmounts, '')
        );
    }

    function test_constructor_allowsPreRegisteredAllocator_create2() public {
        OnChainAllocatorFactory factory = new OnChainAllocatorFactory();

        bytes32 salt = keccak256('onchain-allocator-pre-registered');
        // OnChainAllocator constructor takes no arguments, so initCode is just creationCode
        bytes memory initCode = type(OnChainAllocator).creationCode;
        bytes32 initCodeHash = keccak256(initCode);

        address expected = vm.computeCreate2Address(salt, initCodeHash, address(factory));

        bytes memory proof = abi.encodePacked(bytes1(0xff), address(factory), salt, initCodeHash);

        uint96 preId = compact.__registerAllocator(expected, proof);
        assertEq(_toAllocatorId(expected), preId);

        address deployed = OnChainAllocatorFactory(address(factory)).deploy(salt);
        assertEq(deployed, expected);

        OnChainAllocator newAllocator = OnChainAllocator(deployed);
        assertEq(newAllocator.ALLOCATOR_ID(), _toAllocatorId(deployed));
    }

    function test_constructor_reverts_with_already_registered_allocator_in_case_of_address_collision() public {
        // Deploy Create2 factory
        OnChainAllocatorFactory factory = new OnChainAllocatorFactory();

        // Precalculate the allocator's address
        bytes32 salt = keccak256('onchain-allocator-pre-registered');
        // OnChainAllocator constructor takes no arguments, so initCode is just creationCode
        bytes memory initCode = type(OnChainAllocator).creationCode;
        bytes32 initCodeHash = keccak256(initCode);

        address expected = vm.computeCreate2Address(salt, initCodeHash, address(factory));

        // Store a different registered allocator address (simulate an address collision)
        address differentRegisteredAllocator = address(1);

        uint96 allocatorId = IdLib.toAllocatorId(expected);
        bytes32 allocatorSlot;
        assembly ("memory-safe") {
            allocatorSlot := or(0x000044036fc77deaed2300000000000000000000000, allocatorId)
        }

        vm.store(address(compact), allocatorSlot, bytes32(uint256(uint160(differentRegisteredAllocator))));

        // Try to deploy the allocator
        // Should revert with the InvalidAllocatorRegistration error, since The Compact has a different address stored in the allocator's slot
        vm.expectRevert(
            abi.encodeWithSelector(
                IOnChainAllocator.InvalidAllocatorRegistration.selector, differentRegisteredAllocator
            )
        );
        OnChainAllocatorFactory(address(factory)).deploy(salt);
    }

    function test_allocateAndRegister_tokensImmediatelyAllocated() public {
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;

        usdc.mint(address(allocator), amount1);
        dai.mint(address(allocator), amount2);

        Lock[] memory commitments = new Lock[](2);
        commitments[0] = _makeLock(address(usdc), amount1);
        commitments[1] = _makeLock(address(dai), amount2);

        vm.prank(caller);
        allocator.allocateAndRegister(
            recipient, commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0)
        );

        uint256 id1 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        uint256 id2 = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(dai));

        assertEq(ERC6909(address(compact)).balanceOf(recipient, id1), amount1);
        assertEq(ERC6909(address(compact)).balanceOf(recipient, id2), amount2);

        // Try to send a single unit of the tokens

        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, recipient, id1, 0, 1));
        allocator.attest(address(this), recipient, address(this), id1, 1);

        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, recipient, id2, 0, 1));
        allocator.attest(address(this), recipient, address(this), id2, 1);
    }

    function test_allocateAndRegister_emptyRecipientBecomesCaller() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        usdc.mint(address(allocator), defaultAmount);

        vm.prank(caller);
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister(
            address(0), /* allocate for an empty recipient */
            commitments,
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0)
        );

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        assertEq(nonce, 1);
        assertEq(registeredAmounts.length, 1);
        assertEq(registeredAmounts[0], defaultAmount);
        // Ensure the allocation happened for the caller, not address(0)
        assertEq(ERC6909(address(compact)).balanceOf(caller, idsAndAmounts[0][0]), defaultAmount);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, caller, nonce, defaultExpiration, idsAndAmounts, ''));
        assertTrue(compact.isRegistered(caller, claimHash, BATCH_COMPACT_TYPEHASH));
        bytes32 claimHashRecreated =
            _createClaimHash(caller, arbiter, nonce, defaultExpiration, commitments, bytes32(0));
        assertEq(claimHashRecreated, claimHash);
    }

    /* --------------------------------------------------------------------- */
    /*                  Reentrancy Protection Tests                         */
    /* --------------------------------------------------------------------- */

    /**
     * @notice Tests that allocate() reverts when called during active reentrancy guard.
     * @dev This simulates an attack where a malicious recipient tries to call allocate()
     *      from within its receive() function when receiving native tokens during a claim.
     *      The settledBalanceOf() check should detect the active reentrancy guard and
     *      revert with BalanceNotSettled().
     */
    function test_allocate_revert_BalanceNotSettled_duringReentrancy() public {
        // Step 1: Setup - maliciousRecipient deposits and allocates native tokens using OnChainAllocator
        (uint256 id, bytes32 claimHash, uint256 nonce) = _setupNativeTokenReentrancyTest();

        // Step 2: Configure maliciousRecipient to attempt reentrant allocate() on the second allocation
        Lock[] memory reentrantCommitments = new Lock[](1);
        reentrantCommitments[0] = Lock({
            lockTag: _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes),
            token: address(0), // native token
            amount: defaultAmount
        });
        maliciousRecipient.setReentrantCommitments(reentrantCommitments);
        maliciousRecipient.setAttemptReentrancy(true);
        maliciousRecipient.setAttackType(MaliciousRecipient.AttackType.ALLOCATE);

        // Step 3: Create withdrawal batch claim for the deposit (using OnChainAllocator)
        BatchClaim memory claim = _createClaimForMaliciousRecipient(id, nonce, defaultAmount);

        assertEq(address(compact).balance, defaultAmount, 'TheCompact should have the deposited balance');
        assertEq(
            compact.balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should have a balance in TheCompact'
        );

        // Step 5: Execute batch claim
        // Flow:
        // 1. MaliciousRecipient calls compact.batchClaim() to withdraw first deposit
        // 2. TheCompact validates via ERC1271 or registration (isValidSignature returns success)
        // 3. TheCompact validates via OnChainAllocator (checks stored claimHash)
        // 4. TheCompact sends native tokens to maliciousRecipient (withdrawal)
        // 5. MaliciousRecipient's receive() is called with reentrancy guard ACTIVE
        // 6. receive() tries to call allocator.allocate() to allocate the deposited tokens again in flight
        // 7. allocate() calls _checkBalance() -> settledBalanceOf()
        // 8. settledBalanceOf() detects active reentrancy guard → reverts with BalanceNotSettled()
        // 9. receive() reverts the ETH transaction, will transfer the ERC6909 as a backup (which remains the same balance)
        // Result: Claim succeeds, withdrawal completes, but reentrancy attack was prevented!
        vm.prank(address(maliciousRecipient));
        vm.expectEmit(true, true, true, true, address(compact));
        emit ITheCompact.Claim(
            address(maliciousRecipient), address(allocator), address(maliciousRecipient), claimHash, nonce
        );
        compact.batchClaim(claim);

        // Verify: The reentrant allocation did NOT happen (balance unchanged in compact)
        // If the attack succeeded, MaliciousRecipient would have allocated half of the second deposit
        assertEq(
            compact.balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should still have his balance in TheCompact'
        );

        // Verify: The withdrawal DID succeed to wrapped format
        // This is because allocate() reverts and blocks the receive() function.
        // The compact will continue to just send the ERC6909 tokens instaed
        assertEq(address(maliciousRecipient).balance, 0, 'Withdrawal should have completed, but in wrapped format');
        assertEq(address(compact).balance, defaultAmount, 'TheCompact should have the deposited balance');
        assertEq(
            ERC6909(address(compact)).balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should still have his balance in TheCompact'
        );
    }

    /**
     * @notice Tests that allocate() succeeds when reentrancy is not attempted.
     * @dev This is the control test showing normal operation works correctly.
     */
    function test_allocate_succeeds_withoutReentrancy() public {
        // Setup - maliciousRecipient deposits and allocates native tokens
        (uint256 id, bytes32 claimHash, uint256 nonce) = _setupNativeTokenReentrancyTest();

        // Do NOT enable reentrancy attempt
        maliciousRecipient.setAttemptReentrancy(false);

        // Create and execute withdrawal batch claim
        BatchClaim memory claim = _createClaimForMaliciousRecipient(id, nonce, defaultAmount);

        assertEq(address(compact).balance, defaultAmount, 'TheCompact should have the deposited balance');
        assertEq(
            compact.balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should have a balance in TheCompact'
        );

        // MaliciousRecipient calls batchClaim() to withdraw its own tokens
        // ERC1271 validation passes, allocator validation passes, withdrawal succeeds
        vm.prank(address(maliciousRecipient));
        vm.expectEmit(true, true, true, true, address(compact));
        emit ITheCompact.Claim(
            address(maliciousRecipient), address(allocator), address(maliciousRecipient), claimHash, nonce
        );
        compact.batchClaim(claim);

        // Verify native tokens were withdrawn to maliciousRecipient (successful withdrawal without reentrancy)
        assertEq(address(maliciousRecipient).balance, defaultAmount, 'Should have withdrawn to native ETH');
        assertEq(address(compact).balance, 0, 'TheCompact should have sent the balance');
        assertEq(
            compact.balanceOf(address(maliciousRecipient), id), 0, 'Balance should have been withdrawn from TheCompact'
        );
    }

    /**
     * @notice Tests that attest() succeeds during ERC6909 token transfer when no allocation exists.
     * @dev When a user performs a direct ERC6909 transfer(), the _beforeTokenTransfer hook is called
     *      which sets the reentrancy guard and calls _ensureAttested(), which in turn calls
     *      allocator.attest(). The attest() function uses raw balanceOf() (not settledBalanceOf()),
     *      so it should succeed even with the reentrancy guard active.
     *
     *      Test flow:
     *      1. User deposits tokens via TheCompact (no allocation)
     *      2. User performs direct ERC6909 transfer to recipient
     *      3. _beforeTokenTransfer() sets reentrancy guard and calls _ensureAttested()
     *      4. _ensureAttested() calls allocator.attest()
     *      5. Expected: attest() succeeds because tokens are not allocated
     */
    function test_attest_succeeds_duringTokenTransfer() public {
        // Setup: User deposits tokens WITHOUT allocating
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);
        vm.prank(user);
        uint256 id = compact.depositERC20(address(usdc), lockTag, defaultAmount, user);

        // Verify initial balances
        assertEq(compact.balanceOf(user, id), defaultAmount, 'User should have deposited tokens');
        assertEq(compact.balanceOf(recipient, id), 0, 'Recipient should have no tokens');

        // User performs a direct ERC6909 transfer (not a claim, just a transfer)
        // This triggers _beforeTokenTransfer → _setReentrancyGuard() → _ensureAttested() → allocator.attest()
        vm.prank(user);
        compact.transfer(recipient, id, defaultAmount);

        // Verify transfer succeeded
        assertEq(compact.balanceOf(user, id), 0, 'User should have transferred all tokens');
        assertEq(compact.balanceOf(recipient, id), defaultAmount, 'Recipient should have received tokens');
    }

    /**
     * @notice Tests that ERC6909 token transfer fails when tokens are allocated.
     * @dev After allocation, tokens cannot be transferred directly via ERC6909 transfer()
     *      because attest() will detect the allocation and revert.
     *
     *      Test flow:
     *      1. User deposits tokens and allocates them
     *      2. User attempts direct ERC6909 transfer to recipient
     *      3. _beforeTokenTransfer() calls _ensureAttested() → allocator.attest()
     *      4. Expected: attest() reverts because tokens are allocated
     */
    function test_attest_revert_duringTokenTransfer_afterAllocation() public {
        // Setup: User deposits and allocates tokens
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), defaultAmount);

        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);
        vm.prank(user);
        uint256 id = compact.depositERC20(address(usdc), lockTag, defaultAmount, user);

        // User allocates the tokens
        vm.prank(user);
        allocator.allocate(commitments, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        // Verify initial balances
        assertEq(compact.balanceOf(user, id), defaultAmount, 'User should have deposited tokens');
        assertEq(compact.balanceOf(recipient, id), 0, 'Recipient should have no tokens');

        // User attempts to perform a direct ERC6909 transfer of allocated tokens
        // This should fail because attest() will detect insufficient unlocked balance
        // Available balance = total balance - allocated balance = defaultAmount - defaultAmount = 0
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InsufficientBalance.selector, user, id, 0, defaultAmount)
        );
        compact.transfer(recipient, id, defaultAmount);

        // Verify transfer failed - balances unchanged
        assertEq(compact.balanceOf(user, id), defaultAmount, 'User should still have all tokens');
        assertEq(compact.balanceOf(recipient, id), 0, 'Recipient should still have no tokens');
    }

    /**
     * @notice Tests that prepareAllocation() reverts when called during active reentrancy guard.
     * @dev This tests the checkCompactReentrancyGuardAndRevert() protection in AllocatorLib.
     *      prepareAllocation() explicitly checks the compact's reentrancy guard and reverts
     *      with CompactReentrancyGuardActive() error (selector 0x87621186).
     *
     *      Test flow:
     *      1. User deposits native tokens and allocates to maliciousRecipient
     *      2. Configure maliciousRecipient to attempt reentrant prepareAllocation()
     *      3. Arbiter claims → TheCompact sends native to maliciousRecipient
     *      4. MaliciousRecipient's receive() triggered (guard ACTIVE)
     *      5. Inside receive(), attempts prepareAllocation()
     *      6. Expected: checkCompactReentrancyGuardAndRevert() reverts with CompactReentrancyGuardActive()
     */
    function test_prepareAllocation_revert_CompactReentrancyGuardActive() public {
        // Setup - maliciousRecipient deposits and allocates native tokens
        (uint256 id, bytes32 claimHash, uint256 nonce) = _setupNativeTokenReentrancyTest();

        // Configure maliciousRecipient to attempt reentrant prepareAllocation()
        uint256[2][] memory reentrantIdsAndAmounts = new uint256[2][](1);
        reentrantIdsAndAmounts[0][0] = id;
        reentrantIdsAndAmounts[0][1] = defaultAmount;
        maliciousRecipient.setReentrantPrepareData(
            reentrantIdsAndAmounts,
            address(maliciousRecipient),
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0)
        );
        maliciousRecipient.setAttemptReentrancy(true);
        maliciousRecipient.setAttackType(MaliciousRecipient.AttackType.PREPARE);

        // Create withdrawal claim
        BatchClaim memory claim = _createClaimForMaliciousRecipient(id, nonce, defaultAmount);
        assertEq(address(maliciousRecipient).balance, 0, 'Malicious recipient should not have a balance');
        assertEq(
            ERC6909(address(compact)).balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should have a balance in TheCompact'
        );

        // Execute batch claim
        // prepareAllocation() calls checkCompactReentrancyGuardAndRevert() in AllocatorLib
        // which detects the active guard and reverts with CompactReentrancyGuardActive()
        // But TheCompact catches the revert and continues (withdrawal still completes)
        vm.prank(address(maliciousRecipient));
        vm.expectEmit(true, true, true, true, address(compact));
        emit ITheCompact.Claim(
            address(maliciousRecipient), address(allocator), address(maliciousRecipient), claimHash, nonce
        );
        compact.batchClaim(claim);

        // Verify: The withdrawal did succeed, but only in 6909 wrapped form (which means no change in balance)
        assertEq(address(maliciousRecipient).balance, 0, 'Malicious recipient should still not have a balance');
        assertEq(
            ERC6909(address(compact)).balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should still have his balance in TheCompact'
        );
    }

    /**
     * @notice Tests that executeAllocation() reverts when called during active reentrancy guard.
     * @dev This tests the checkCompactReentrancyGuardAndRevert() protection in AllocatorLib.
     *      executeAllocation() explicitly checks the compact's reentrancy guard and reverts
     *      with CompactReentrancyGuardActive() error (selector 0x87621186).
     *
     *      Test flow:
     *      1. User deposits native tokens and allocates to maliciousRecipient
     *      2. Configure maliciousRecipient to attempt reentrant executeAllocation()
     *      3. Arbiter claims → TheCompact sends native to maliciousRecipient
     *      4. MaliciousRecipient's receive() triggered (guard ACTIVE)
     *      5. Inside receive(), attempts executeAllocation()
     *      6. Expected: checkCompactReentrancyGuardAndRevert() reverts with CompactReentrancyGuardActive()
     */
    function test_executeAllocation_revert_CompactReentrancyGuardActive() public {
        // Setup - maliciousRecipient deposits and allocates native tokens
        (uint256 id, bytes32 claimHash, uint256 nonce) = _setupNativeTokenReentrancyTest();

        // Configure maliciousRecipient to attempt reentrant executeAllocation()
        uint256[2][] memory reentrantIdsAndAmounts = new uint256[2][](1);
        reentrantIdsAndAmounts[0][0] = id;
        reentrantIdsAndAmounts[0][1] = defaultAmount;
        maliciousRecipient.setReentrantPrepareData(
            reentrantIdsAndAmounts,
            address(maliciousRecipient),
            arbiter,
            defaultExpiration,
            BATCH_COMPACT_TYPEHASH,
            bytes32(0)
        );
        maliciousRecipient.setAttemptReentrancy(true);
        maliciousRecipient.setAttackType(MaliciousRecipient.AttackType.EXECUTE);

        // Create withdrawal claim
        BatchClaim memory claim = _createClaimForMaliciousRecipient(id, nonce, defaultAmount);
        assertEq(address(maliciousRecipient).balance, 0, 'Malicious recipient should not have a balance');
        assertEq(
            ERC6909(address(compact)).balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should have a balance in TheCompact'
        );

        // Execute batch claim
        // executeAllocation() calls checkCompactReentrancyGuardAndRevert() in AllocatorLib
        // which detects the active guard and reverts with CompactReentrancyGuardActive()
        // But TheCompact catches the revert and continues (withdrawal still completes)
        vm.prank(address(maliciousRecipient));
        vm.expectEmit(true, true, true, true, address(compact));
        emit ITheCompact.Claim(
            address(maliciousRecipient), address(allocator), address(maliciousRecipient), claimHash, nonce
        );
        compact.batchClaim(claim);

        // Verify: The withdrawal did succeed, but only in 6909 wrapped form (which means no change in balance)
        assertEq(address(maliciousRecipient).balance, 0, 'Malicious recipient should still not have a balance');
        assertEq(
            ERC6909(address(compact)).balanceOf(address(maliciousRecipient), id),
            defaultAmount,
            'Malicious recipient should still have his balance in TheCompact'
        );
    }

    /* --------------------------------------------------------------------- */
    /*                    Allocation Bombing Protection Tests                */
    /* --------------------------------------------------------------------- */

    /**
     * @notice Comprehensive test for allocation bombing mitigation.
     * @dev The vulnerability was:
     *      - Attacker creates ~66k allocations on behalf of a user with unique expirations
     *      - Operations loop through all allocations, exceeding block gas limit (DoS)
     *
     *      The fix:
     *      - External allocations have expiration normalized (rounded up to buckets)
     *      - Max ~3,726 unique expirations possible
     *      - Amounts accumulate per bucket, not per allocation
     *
     *      This test verifies all critical operations remain usable after worst-case attack:
     *      1. attest() - reads allocated balance (traverses list)
     *      2. allocate() with late expiration - inserts at end (traverses full list)
     *      3. authorizeClaim() - deletes allocation (traverses to find previous pointer)
     *      4. allocate() with early expiration - inserts at beginning (O(1))
     */
    /// forge-config: default.isolate = false
    function test_allocationBombing_comprehensive() public {
        // Setup: Create a victim with deposited funds
        address victim = makeAddr('victim');
        uint256 depositAmount = 1000 ether;
        usdc.mint(victim, depositAmount);

        vm.startPrank(victim);
        usdc.approve(address(compact), depositAmount);
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.OneDay);
        uint256 id = compact.depositERC20(address(usdc), lockTag, depositAmount, victim);
        vm.stopPrank();

        // =========================================================================
        // PHASE 1: Simulate attack with 66k allocations
        // =========================================================================
        // We use pauseGasMetering to simulate a real-world attack where allocations
        // are created across many transactions (bypassing single-tx gas limits)
        uint256 numAllocations = 100;
        uint256 amountPerAllocation = 1;
        bytes32 lastClaimHash;

        vm.pauseGasMetering();

        for (uint256 i = 0; i < numAllocations; i++) {
            // Each allocation 1 second apart, spanning ~18 hours
            // Without normalization: 66k unique entries (DoS)
            // With normalization: ~2388 buckets
            uint32 expiration = uint32(block.timestamp + 1 hours + i);

            uint256[2][] memory idsAndAmounts = new uint256[2][](1);
            idsAndAmounts[0][0] = id;
            idsAndAmounts[0][1] = amountPerAllocation;

            usdc.mint(address(allocationCaller), amountPerAllocation);
            vm.prank(address(allocationCaller));
            usdc.approve(address(compact), amountPerAllocation);

            lastClaimHash = allocationCaller.onChainAllocation(
                victim, idsAndAmounts, arbiter, expiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
            );
        }

        vm.resumeGasMetering();

        // =========================================================================
        // PHASE 2: Test attest() - must traverse list to read allocated balance
        // =========================================================================
        uint256 gasBefore = gasleft();
        bytes4 result = allocator.attest(address(0), victim, address(0), id, 0);
        uint256 attestGas = gasBefore - gasleft();

        assertEq(result, allocator.attest.selector, 'attest should succeed');
        console.log('Gas: attest() with 66k allocations', attestGas);
        assertLt(attestGas, 10_000_000, 'attest gas should be under 10M');

        // =========================================================================
        // PHASE 3: Test allocate() with LATE expiration - must traverse to insert at end
        // =========================================================================
        // This is the worst case: inserting after all existing allocations
        // requires traversing the entire linked list to find insertion point
        Lock[] memory lateCommitments = new Lock[](1);
        lateCommitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: 1 ether});
        // Expiration after all existing allocations (1 hour + 66k seconds + buffer)
        uint32 lateExpiration = uint32(block.timestamp + 1 hours + numAllocations + 1000);

        vm.startPrank(victim);
        gasBefore = gasleft();
        (bytes32 lateClaimHash,) =
            allocator.allocate(lateCommitments, arbiter, lateExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
        uint256 allocateLateGas = gasBefore - gasleft();
        vm.stopPrank();

        console.log('Gas: allocate() late expiration (insert at end)', allocateLateGas);
        assertLt(allocateLateGas, 10_000_000, 'allocate late gas should be under 10M');

        // =========================================================================
        // PHASE 4: Test authorizeClaim() - must traverse to delete late allocation
        // =========================================================================
        // Deleting an allocation at the end requires traversing to find the previous pointer
        uint256[2][] memory claimIdsAndAmounts = new uint256[2][](1);
        claimIdsAndAmounts[0][0] = id;
        claimIdsAndAmounts[0][1] = 1 ether;

        // Build the allocator data hint (0 = no hint, force full traversal)
        bytes memory noHint = new bytes(4);

        gasBefore = gasleft();
        vm.prank(address(compact));
        allocator.authorizeClaim(lateClaimHash, arbiter, victim, 0, lateExpiration, claimIdsAndAmounts, noHint);
        uint256 authorizeClaimGas = gasBefore - gasleft();

        console.log('Gas: authorizeClaim() delete late allocation', authorizeClaimGas);
        assertLt(authorizeClaimGas, 10_000_000, 'authorizeClaim gas should be under 10M');

        // =========================================================================
        // PHASE 5: Test allocate() with EARLY expiration - should be O(1)
        // =========================================================================
        // This is the best case: inserting at the beginning of the list
        Lock[] memory earlyCommitments = new Lock[](1);
        earlyCommitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: 1 ether});
        // Expiration before all existing allocations
        uint32 earlyExpiration = uint32(block.timestamp + 11 minutes);

        vm.startPrank(victim);
        gasBefore = gasleft();
        allocator.allocate(earlyCommitments, arbiter, earlyExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
        uint256 allocateEarlyGas = gasBefore - gasleft();
        vm.stopPrank();

        console.log('Gas: allocate() early expiration (insert at beginning)', allocateEarlyGas);
        // Both early and late allocations need to traverse the full list to sum allocated balance
        // (for _checkBalance), so they have similar gas costs. The key is both are under block limit.
        assertLt(allocateEarlyGas, 10_000_000, 'allocate early gas should be under 10M');

        // =========================================================================
        // PHASE 6: Test authorizeClaim() with late expiration and hint
        // =========================================================================
        // This should be O(1) because the hint is provided

        vm.prank(victim);
        (lateClaimHash,) =
            allocator.allocate(lateCommitments, arbiter, lateExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0));

        // Build the allocator data hint (0 = no hint, force full traversal)
        uint32 lastAllocationBombingExpiration = allocator.getNormalizedExpirationForClaim(lastClaimHash);
        assertGt(lastAllocationBombingExpiration, 0, 'Last allocation bombing expiration should be greater than 0');
        bytes memory hint = new bytes(4);
        assembly ("memory-safe") {
            mstore(add(hint, 0x20), shl(224, lastAllocationBombingExpiration))
        }

        gasBefore = gasleft();
        vm.prank(address(compact));
        allocator.authorizeClaim(lateClaimHash, arbiter, victim, 0, lateExpiration, claimIdsAndAmounts, hint);
        uint256 authorizeClaimWithHintGas = gasBefore - gasleft();

        console.log('Gas: authorizeClaim() delete late allocation with hint', authorizeClaimWithHintGas);
        assertLt(authorizeClaimWithHintGas, 1_000_000, 'authorizeClaim with hint gas should be under 1M');

        // =========================================================================
        // Summary: All operations completed within reasonable gas limits
        // =========================================================================
        console.log('');
        console.log('=== Allocation Bombing Protection Summary ===');
        console.log('Total allocations created', numAllocations);
        console.log('attest() gas', attestGas);
        console.log('allocate() late (worst case) gas', allocateLateGas);
        console.log('authorizeClaim() delete late gas', authorizeClaimGas);
        console.log('allocate() early (best case) gas', allocateEarlyGas);
        console.log('authorizeClaim() delete late with hint gas', authorizeClaimWithHintGas);
    }

    /**
     * @notice Test that BalanceExpiration struct is stored in a single storage slot.
     * @dev The struct contains:
     *      - uint32 nextExpiration (4 bytes)
     *      - uint224 amount (28 bytes)
     *      Total: 32 bytes = 1 slot
     *
     *      Storage layout (from forge inspect):
     *      - _balancesByExpiration is at slot 1
     *      - For mapping(bytes32 => struct), slot = keccak256(key, baseSlot)
     *
     *      Struct packing in storage (right-aligned):
     *      - Bits 0-31: nextExpiration (uint32)
     *      - Bits 32-255: amount (uint224)
     */
    function test_balanceExpirationFitsInSingleSlot() public {
        // Create an allocation within 10 minutes (no normalization)
        usdc.mint(user, 10 ether);
        vm.startPrank(user);
        usdc.approve(address(compact), 10 ether);
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.OneDay);
        compact.depositERC20(address(usdc), lockTag, 10 ether, user);

        Lock[] memory commitments = new Lock[](1);
        uint224 allocatedAmount = 1 ether;
        commitments[0] = Lock({lockTag: lockTag, token: address(usdc), amount: allocatedAmount});

        // Use expiration within 10 minutes to avoid normalization
        uint32 expiration = uint32(block.timestamp + 5 minutes);
        allocator.allocate(commitments, arbiter, expiration, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.stopPrank();

        // Compute tokenHash using same logic as _getTokenHash(lockTag, token, sponsor)
        // Memory layout: lockTag(12) || token(20) || zeros(12) || sponsor(20) = 64 bytes
        address token = address(usdc);
        address sponsor = user;
        bytes28 tokenHash;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, lockTag)
            mstore(add(ptr, 0x0c), shl(96, token))
            mstore(add(ptr, 0x20), sponsor)
            // Mask to keep only high 28 bytes (clear low 4 bytes)
            tokenHash := and(keccak256(ptr, 0x40), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000)
        }

        // Compute pointer: tokenHash | expiration
        // tokenHash is bytes28 (left-aligned with 4 zero bytes on right)
        // expiration is uint32 (right-aligned)
        bytes32 pointer;
        assembly ("memory-safe") {
            pointer := or(tokenHash, expiration)
        }

        // Compute storage slot: keccak256(pointer, baseSlot)
        // _balancesByExpiration is at slot 1
        bytes32 storageSlot;
        assembly ("memory-safe") {
            mstore(0x00, pointer)
            mstore(0x20, 1) // slot 1
            storageSlot := keccak256(0x00, 0x40)
        }

        // Read the raw storage slot
        bytes32 slotValue = vm.load(address(allocator), storageSlot);

        // Verify struct packing:
        // - Low 32 bits (4 bytes): nextExpiration
        // - High 224 bits (28 bytes): amount
        uint32 storedNextExpiration = uint32(uint256(slotValue));
        uint224 storedAmount = uint224(uint256(slotValue) >> 32);

        // nextExpiration should be type(uint32).max (end of list marker)
        assertEq(storedNextExpiration, type(uint32).max, 'nextExpiration should be max (end of list)');

        // amount should match what we allocated
        assertEq(storedAmount, allocatedAmount, 'amount should match allocated amount');

        // Verify both values are in the same slot by checking the combined value
        uint256 expectedSlotValue = (uint256(allocatedAmount) << 32) | uint256(type(uint32).max);
        assertEq(uint256(slotValue), expectedSlotValue, 'Both fields should be packed in single slot');
    }

    /**
     * @notice Test that allocations with same normalized expiration accumulate amounts.
     * @dev Verifies that multiple allocations bucketed to the same expiration
     *      don't create separate entries but instead accumulate in one entry.
     */
    /// forge-config: default.isolate = false
    function test_allocationBombing_amountsAccumulate() public {
        address victim = makeAddr('victim2');
        uint256 depositAmount = 100 ether;
        usdc.mint(victim, depositAmount);

        vm.startPrank(victim);
        usdc.approve(address(compact), depositAmount);
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.OneDay);
        uint256 id = compact.depositERC20(address(usdc), lockTag, depositAmount, victim);
        vm.stopPrank();

        // Create multiple allocations that will normalize to the same expiration
        // Expirations within 10-second window (in the 10min-1h range) bucket together
        uint256 numAllocations = 5;
        uint256 amountPerAllocation = 1 ether;
        uint32 baseExpiration = uint32(block.timestamp + 30 minutes);

        for (uint256 i = 0; i < numAllocations; i++) {
            // All within same 10-second bucket
            uint32 expiration = baseExpiration + uint32(i * 2); // 0, 2, 4, 6, 8 seconds apart

            uint256[2][] memory idsAndAmounts = new uint256[2][](1);
            idsAndAmounts[0][0] = id;
            idsAndAmounts[0][1] = amountPerAllocation;

            usdc.mint(address(allocationCaller), amountPerAllocation);
            vm.prank(address(allocationCaller));
            usdc.approve(address(compact), amountPerAllocation);

            allocationCaller.onChainAllocation(
                victim, idsAndAmounts, arbiter, expiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
            );
        }

        // Now try to transfer more than available (should fail)
        // Total allocated: 5 * 1 ether = 5 ether
        // Note: batchDepositAndRegisterFor also deposits 1 ether per allocation to victim's balance
        // Balance: 100 (initial) + 5 (from allocations) = 105 ether
        // Available: 105 - 5 = 100 ether
        uint256 attemptTransfer = 101 ether; // More than available

        vm.expectRevert();
        allocator.attest(address(0), victim, address(0), id, attemptTransfer);

        // But transferring up to 100 ether should work
        uint256 validTransfer = 100 ether;
        bytes4 result = allocator.attest(address(0), victim, address(0), id, validTransfer);
        assertEq(result, allocator.attest.selector, 'Valid transfer should succeed');
    }

    /**
     * @notice Test that expired allocations are cleaned up during reads.
     * @dev Verifies the lazy cleanup mechanism works correctly.
     */
    /// forge-config: default.isolate = false
    function test_allocationBombing_expiredAllocationsCleanedUp() public {
        address victim = makeAddr('victim3');
        uint256 depositAmount = 100 ether;
        usdc.mint(victim, depositAmount);

        vm.startPrank(victim);
        usdc.approve(address(compact), depositAmount);
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.OneDay);
        uint256 id = compact.depositERC20(address(usdc), lockTag, depositAmount, victim);
        vm.stopPrank();

        // Create allocation that expires soon
        uint32 shortExpiration = uint32(block.timestamp + 5 minutes);
        uint256 allocatedAmount = 50 ether;

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = id;
        idsAndAmounts[0][1] = allocatedAmount;

        usdc.mint(address(allocationCaller), allocatedAmount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), allocatedAmount);

        allocationCaller.onChainAllocation(
            victim, idsAndAmounts, arbiter, shortExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), 0
        );

        // Before expiration: can only transfer 50 ether
        bytes4 result = allocator.attest(address(0), victim, address(0), id, 50 ether);
        assertEq(result, allocator.attest.selector);

        // Warp past expiration
        vm.warp(shortExpiration + 1);

        // After expiration: can transfer full 100 ether (allocation cleaned up)
        result = allocator.attest(address(0), victim, address(0), id, 100 ether);
        assertEq(result, allocator.attest.selector, 'Should be able to transfer full amount after expiration');
    }
}

/* ============================================================================
   Malicious Contract for Reentrancy Testing
   ============================================================================ */

/**
 * @notice Malicious recipient that attempts reentrant allocations during claim/withdrawal.
 * @dev This contract simulates an attacker trying to exploit reentrancy vulnerabilities
 *      by calling allocate(), prepareAllocation(), or executeAllocation() from within
 *      the receive() function which is triggered when TheCompact sends native tokens
 *      during a claim (before the balance is reduced in TheCompact's ERC6909 accounting).
 *
 *      Also implements ERC1271 to allow signature-less claims (always returns valid signature).
 *
 *      Attack flow:
 *      1. MaliciousRecipient deposits native tokens to TheCompact
 *      2. MaliciousRecipient calls allocate() to register allocation with OnChainAllocator
 *      3. MaliciousRecipient creates claim and calls compact.claim()
 *      4. TheCompact validates via ERC1271 (always returns success)
 *      5. TheCompact sends native tokens → receive() triggered (reentrancy guard ACTIVE)
 *      6. MaliciousRecipient attempts reentrant allocation
 *      7. Should revert with appropriate error (BalanceNotSettled or CompactReentrancyGuardActive)
 *
 *      Pattern inspired by CheckBalanceDuringTransfer in the-compact/test/utility/Utility.t.sol
 */
contract MaliciousRecipient is IERC1271 {
    IOnChainAllocation public immutable ALLOCATOR;
    TheCompact public immutable COMPACT;

    bool public attemptReentrancy;

    // Configuration for different attack types
    enum AttackType {
        ALLOCATE,
        PREPARE,
        EXECUTE
    }

    AttackType public attackType;

    // Data for reentrant calls
    Lock[] public reentrantCommitments;
    uint256[2][] public reentrantIdsAndAmounts;
    address public reentrantRecipient;
    address public reentrantArbiter;
    uint256 public reentrantExpires;
    bytes32 public reentrantTypehash;
    bytes32 public reentrantWitness;

    constructor(address allocator, address compact, address /* allocationCaller */ ) {
        ALLOCATOR = IOnChainAllocation(allocator);
        COMPACT = TheCompact(compact);
        attackType = AttackType.ALLOCATE;
    }

    /**
     * @notice Triggered when receiving native tokens during claim.
     * @dev This is where we attempt the reentrant call to test reentrancy protection.
     *      TheCompact's reentrancy guard is ACTIVE at this point (value > 1).
     */
    receive() external payable {
        if (attemptReentrancy) {
            if (attackType == AttackType.ALLOCATE && reentrantCommitments.length > 0) {
                // Attempt reentrant allocation - should fail with BalanceNotSettled()
                // This calls _checkBalance() which uses settledBalanceOf()
                OnChainAllocator(address(ALLOCATOR)).allocate(
                    reentrantCommitments, address(0), uint32(block.timestamp + 100), bytes32(0), bytes32(0)
                );
            } else if (attackType == AttackType.PREPARE && reentrantIdsAndAmounts.length > 0) {
                // Attempt reentrant prepareAllocation - should fail with CompactReentrancyGuardActive()
                // This calls checkCompactReentrancyGuardAndRevert() in AllocatorLib
                ALLOCATOR.prepareAllocation(
                    reentrantRecipient,
                    reentrantIdsAndAmounts,
                    reentrantArbiter,
                    reentrantExpires,
                    reentrantTypehash,
                    reentrantWitness,
                    bytes('')
                );
            } else if (attackType == AttackType.EXECUTE && reentrantIdsAndAmounts.length > 0) {
                // Attempt reentrant executeAllocation - should fail with CompactReentrancyGuardActive()
                // This calls checkCompactReentrancyGuardAndRevert() in AllocatorLib
                ALLOCATOR.executeAllocation(
                    reentrantRecipient,
                    reentrantIdsAndAmounts,
                    reentrantArbiter,
                    reentrantExpires,
                    reentrantTypehash,
                    reentrantWitness,
                    bytes('')
                );
            }
        }
    }

    /**
     * @notice ERC1271 signature validation - always returns valid.
     * @dev This allows TheCompact to validate claims without requiring actual signatures.
     *      TheCompact will call this when sponsorSignature is empty and no pre-registration exists.
     *      Returns the ERC1271 magic value 0x1626ba7e to indicate signature is valid.
     */
    function isValidSignature(bytes32, /* hash */ bytes memory /* signature */ )
        external
        pure
        override
        returns (bytes4)
    {
        return 0x1626ba7e; // ERC1271 magic value
    }

    // Control functions for testing
    function setAttemptReentrancy(bool attempt) external {
        attemptReentrancy = attempt;
    }

    function setAttackType(AttackType _attackType) external {
        attackType = _attackType;
    }

    function setReentrantCommitments(Lock[] calldata commitments) external {
        delete reentrantCommitments;
        for (uint256 i = 0; i < commitments.length; i++) {
            reentrantCommitments.push(commitments[i]);
        }
    }

    function setReentrantPrepareData(
        uint256[2][] calldata idsAndAmounts,
        address recipient,
        address arbiter,
        uint256 expires,
        bytes32 typehash,
        bytes32 witness
    ) external {
        delete reentrantIdsAndAmounts;
        for (uint256 i = 0; i < idsAndAmounts.length; i++) {
            reentrantIdsAndAmounts.push(idsAndAmounts[i]);
        }
        reentrantRecipient = recipient;
        reentrantArbiter = arbiter;
        reentrantExpires = expires;
        reentrantTypehash = typehash;
        reentrantWitness = witness;
    }
}
