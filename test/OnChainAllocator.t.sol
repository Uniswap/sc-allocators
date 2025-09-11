// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/*
    Tests for OnChainAllocator.sol
    These largely mirror the structure & style of HybridAllocator.t.sol while
    focussing on the purely-on-chain allocation flow (no signature logic except
    the permit-style path in allocateFor).
*/

import {Test} from 'forge-std/Test.sol';

import {ERC20Mock} from 'src/test/ERC20Mock.sol';

import {TheCompact} from '@uniswap/the-compact/TheCompact.sol';

import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';

import {IOnChainAllocation} from '@uniswap/the-compact/interfaces/IOnChainAllocation.sol';
import {OnChainAllocator} from 'src/allocators/OnChainAllocator.sol';
import {IOnChainAllocator} from 'src/interfaces/IOnChainAllocator.sol';

import {BATCH_COMPACT_TYPEHASH, LOCK_TYPEHASH, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {ResetPeriod} from '@uniswap/the-compact/types/ResetPeriod.sol';
import {Scope} from '@uniswap/the-compact/types/Scope.sol';

import {AllocatorLib} from 'src/allocators/lib/AllocatorLib.sol';
import {OnChainAllocationCaller} from 'src/test/OnChainAllocationCaller.sol';
import {TestHelper} from 'test/util/TestHelper.sol';

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

    function setUp() public {
        compact = new TheCompact();
        arbiter = makeAddr('arbiter');
        (user, userPK) = makeAddrAndKey('user');
        allocator = new OnChainAllocator(address(compact));

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
    /*                               allocate()                              */
    /* --------------------------------------------------------------------- */

    function test_allocate_revert_InvalidExpiration() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);

        // Deposit native token to Compact first so allocation is backed
        bytes12 lockTag = commitments[0].lockTag;
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(lockTag, user);

        uint256 expiration = vm.getBlockTimestamp() + 600; // 10 min reset period

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, expiration, expiration)
        );
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

        vm.warp(defaultExpiration + 1);

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

    function test_prepareAllocation_returnsNonce_and_doesNotIncrementStorage() public {
        uint256[2][] memory idsAndAmounts = _idsAndAmountsFor(address(usdc), defaultAmount);

        // call from an arbitrary EOA (caller)
        vm.prank(caller);
        uint256 returnedNonce = allocator.prepareAllocation(
            recipient, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );

        assertEq(returnedNonce, _composeNonceUint(caller, 1));
        // storage nonce is only incremented in executeAllocation
        assertEq(allocator.nonces(caller), 0);
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
        assertEq(allocator.nonces(address(allocationCaller)), 1);
        uint256 expectedNonce = _composeNonceUint(address(allocationCaller), 1);

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
            recipient,
            arbiter,
            _composeNonceUint(address(allocationCaller), 1),
            defaultExpiration,
            commitments,
            bytes32(0)
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
        uint256 expectedNonce = _composeNonceUint(address(allocationCaller), 1);

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

    function test_allocateAndRegister_revert_InvalidAmount() public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(usdc), uint256(type(uint224).max) + 1);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidAmount.selector, commitments[0].amount));
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

        assertEq(nonce, _composeNonceUint(caller, 1));
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

        assertEq(nonce, _composeNonceUint(caller, 1));
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
}
