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

import {OnChainAllocator} from 'src/allocators/OnChainAllocator.sol';
import {IOnChainAllocator} from 'src/interfaces/IOnChainAllocator.sol';

import {BATCH_COMPACT_TYPEHASH, LOCK_TYPEHASH, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';

import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {ResetPeriod} from '@uniswap/the-compact/types/ResetPeriod.sol';
import {Scope} from '@uniswap/the-compact/types/Scope.sol';

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

    uint256 internal defaultAmount;
    uint32 internal defaultExpiration;

    function setUp() public {
        compact = new TheCompact();
        arbiter = makeAddr('arbiter');
        (user, userPK) = makeAddrAndKey('user');
        allocator = new OnChainAllocator(address(compact));

        usdc = new ERC20Mock('USDC', 'USDC');
        dai = new ERC20Mock('DAI', 'DAI');

        recipient = makeAddr('recipient');
        (caller, callerPK) = makeAddrAndKey('caller');
        deal(user, 1 ether);
        usdc.mint(user, 1 ether);

        defaultAmount = 1 ether;
        defaultExpiration = uint32(block.timestamp + 300); // 5 minutes fits 10-minute reset period
    }

    /* --------------------------------------------------------------------- */
    /*                               Helpers                                 */
    /* --------------------------------------------------------------------- */

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
            abi.encodeWithSelector(IOnChainAllocator.InvalidExpiration.selector, expiration, expiration - 1)
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

        assertEq(nonce, 1);
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

        assertEq(nonce, 1);
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

        assertEq(nonce, 1);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        vm.prank(user);
        (claimHash, nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration + 10, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_second_erc20');

        assertEq(nonce, 2);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration + 10, idsAndAmounts, '')
        );

        // expire the first allocation and allocate again
        vm.warp(defaultExpiration + 1);
        vm.prank(user);
        (claimHash, nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration + 10, BATCH_COMPACT_TYPEHASH, bytes32(0));
        vm.snapshotGasLastCall('allocate_and_delete_expired_allocation');

        assertEq(nonce, 3);
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

        bytes32 claimHash = _createClaimHash(user, arbiter, 1, defaultExpiration, commitments, witness);

        // first allocation

        bytes32 typehash = witness == bytes32(0) ? BATCH_COMPACT_TYPEHASH : BATCH_COMPACT_TYPEHASH_WITH_WITNESS;

        vm.prank(user);
        vm.expectEmit(true, true, true, true);
        emit IOnChainAllocator.Allocated(user, commitments, 1, defaultExpiration, claimHash);
        (bytes32 returnedClaimHash, uint256 nonce) =
            allocator.allocate(commitments, arbiter, defaultExpiration, typehash, witness);

        assertEq(returnedClaimHash, claimHash);

        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = firstAmount;

        assertEq(nonce, 1);
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
            claimHash = _createClaimHash(user, arbiter, 2, defaultExpiration, commitments, witness);
            vm.expectEmit(true, true, true, true);
            emit IOnChainAllocator.Allocated(user, commitments, 2, defaultExpiration, claimHash);
        }
        (claimHash, nonce) = allocator.allocate(commitments, arbiter, defaultExpiration, typehash, witness);

        if (uint256(secondAmount) + uint256(firstAmount) <= depositAmount) {
            // Check the allocations
            idsAndAmounts[0][1] = secondAmount;

            assertEq(nonce, 2);
            assertTrue(
                allocator.isClaimAuthorized(claimHash, arbiter, user, 1, /*nonce*/ defaultExpiration, idsAndAmounts, '')
            );
            assertTrue(
                allocator.isClaimAuthorized(claimHash, arbiter, user, 2, /*nonce*/ defaultExpiration, idsAndAmounts, '')
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
            vm.prank(user);
            (claimHash, nonce) = allocator.allocate(commitments, arbiter, expiration, typehash, witness);
            assertEq(nonce, 2);
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
        bytes32 nonceKey = keccak256(abi.encode(address(0), user));
        uint256 nonceBefore = allocator.nonces(nonceKey);
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, nonceBefore + 1, defaultExpiration, commitmentsHash)
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
        bytes32 nonceKey = keccak256(abi.encode(address(0), user));
        uint256 nonceBefore = allocator.nonces(nonceKey);
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, nonceBefore + 1, defaultExpiration, commitmentsHash)
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
        bytes32 nonceKey = keccak256(abi.encode(address(0), user));
        uint256 nonceBefore = allocator.nonces(nonceKey);
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, nonceBefore + 1, defaultExpiration, commitmentsHash)
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
        assertEq(nonce, nonceBefore + 1);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocateFor_success_withSignature(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        bytes32 nonceKey = keccak256(abi.encode(address(0), user));
        uint256 nonceBefore = allocator.nonces(nonceKey);
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, user, nonceBefore + 1, defaultExpiration, commitmentsHash)
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
        assertEq(nonce, nonceBefore + 1);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));
    }

    function test_allocateFor_success_withWitness(address relayer) public {
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // build digest exactly like allocator expects
        bytes32 nonceKey = keccak256(abi.encode(address(0), user));
        uint256 nonceBefore = allocator.nonces(nonceKey);
        bytes32 witness = bytes32(keccak256('witness'));
        bytes32 commitmentsHash = _commitmentsHash(commitments);
        bytes32 claimHash = keccak256(
            abi.encode(
                BATCH_COMPACT_TYPEHASH, arbiter, user, nonceBefore + 1, defaultExpiration, commitmentsHash, witness
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
        assertEq(nonce, nonceBefore + 1);
        assertTrue(allocator.isClaimAuthorized(claimHash, arbiter, user, nonce, defaultExpiration, idsAndAmounts, ''));

        assertEq(allocator.nonces(nonceKey), nonceBefore + 1);
    }

    function test_allocateFor_revert_InvalidRegistration(address relayer) public {
        // Build commitments with native token deposit backing
        Lock[] memory commitments = new Lock[](1);
        commitments[0] = _makeLock(address(0), defaultAmount);
        vm.prank(user);
        compact.depositNative{value: defaultAmount}(commitments[0].lockTag, user);

        // Nonce that allocateFor will use
        bytes32 nonceKey = keccak256(abi.encode(address(0), user));
        uint256 nonceBefore = allocator.nonces(nonceKey);
        uint256 expectedNonce = nonceBefore + 1;

        // Compute claimHash that allocateFor will create internally
        bytes32 claimHash = _createClaimHash(user, arbiter, expectedNonce, defaultExpiration, commitments, bytes32(0));

        // Expect InvalidRegistration revert because claimHash is NOT registered on The Compact
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidRegistration.selector, user, claimHash));
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

        // Determine nonce as allocator will use
        bytes32 nonceKey = keccak256(abi.encode(address(0), user));
        uint256 nonceBefore = allocator.nonces(nonceKey);
        uint256 expectedNonce = nonceBefore + 1;

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

        assertEq(nonce, 1);
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

        assertEq(nonce, 1);
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
