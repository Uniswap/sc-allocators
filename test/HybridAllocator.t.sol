// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {TestHelper} from './util/TestHelper.sol';
import {ERC20} from '@solady/tokens/ERC20.sol';
import {TheCompact} from '@uniswap/the-compact/TheCompact.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';

import {BatchClaim} from '@uniswap/the-compact/types/BatchClaims.sol';
import {BatchClaimComponent, Component} from '@uniswap/the-compact/types/Components.sol';
import {BATCH_COMPACT_TYPEHASH, BatchCompact, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';
import {ResetPeriod} from '@uniswap/the-compact/types/ResetPeriod.sol';
import {Scope} from '@uniswap/the-compact/types/Scope.sol';

import {Test} from 'forge-std/Test.sol';
import {HybridAllocator} from 'src/allocators/HybridAllocator.sol';

import {AllocatorLib} from 'src/allocators/lib/AllocatorLib.sol';
import {BATCH_COMPACT_WITNESS_TYPEHASH} from 'src/allocators/lib/TypeHashes.sol';
import {IHybridAllocator} from 'src/interfaces/IHybridAllocator.sol';
import {ERC20Mock} from 'src/test/ERC20Mock.sol';
import {OnChainAllocationCaller} from 'src/test/OnChainAllocationCaller.sol';

contract HybridAllocatorTest is Test, TestHelper {
    TheCompact compact;
    address arbiter;
    HybridAllocator allocator;
    address signer;
    uint256 signerPrivateKey;
    ERC20Mock usdc;
    address user;
    uint256 userPrivateKey;
    uint256 defaultAmount;
    uint256 defaultExpiration;

    OnChainAllocationCaller allocationCaller;

    BatchCompact batchCompact;

    function setUp() public {
        compact = new TheCompact();
        arbiter = makeAddr('arbiter');
        (signer, signerPrivateKey) = makeAddrAndKey('signer');
        allocator = new HybridAllocator(address(compact), signer);
        usdc = new ERC20Mock('USDC', 'USDC');
        (user, userPrivateKey) = makeAddrAndKey('user');
        deal(user, 1 ether);
        usdc.mint(user, 1 ether);
        defaultAmount = 1 ether;
        defaultExpiration = vm.getBlockTimestamp() + 1 days;

        allocationCaller = new OnChainAllocationCaller(address(allocator), address(compact));

        batchCompact.arbiter = arbiter;
        batchCompact.sponsor = user;
        batchCompact.nonce = 1;
        batchCompact.expires = defaultExpiration;
    }

    function _idsAndAmounts(address token, uint256 amount) internal view returns (uint256[2][] memory arr) {
        arr = new uint256[2][](1);
        arr[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), token);
        arr[0][1] = amount;
    }

    function _idsAndAmounts2(address tokenA, uint256 amountA, address tokenB, uint256 amountB)
        internal
        view
        returns (uint256[2][] memory arr)
    {
        arr = new uint256[2][](2);
        arr[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), tokenA);
        arr[0][1] = amountA;
        arr[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), tokenB);
        arr[1][1] = amountB;
    }

    function test_constructor_revert_signerIsAddressZero() public {
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSigner.selector));
        new HybridAllocator(address(compact), address(0));
    }

    function test_checkAllocatorId() public view {
        assertEq(allocator.ALLOCATOR_ID(), _toAllocatorId(address(allocator)));
    }

    function test_checkNonce() public view {
        assertEq(allocator.nonces(), 0);
    }

    function test_checkSignerCount() public view {
        assertEq(allocator.signerCount(), 1);
    }

    function test_checkSigners(address attacker) public view {
        vm.assume(attacker != signer);

        assertTrue(allocator.signers(signer));
        assertFalse(allocator.signers(attacker));
    }

    function test_prepareAllocation_returnsNonce_andDoesNotIncrement() public {
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), defaultAmount);
        uint96 beforeNonces = allocator.nonces();
        // call prepare directly
        uint256 returnedNonce = allocator.prepareAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, bytes32(0), ''
        );
        assertEq(returnedNonce, uint256(beforeNonces) + 1);
        // storage not incremented yet
        assertEq(allocator.nonces(), beforeNonces);
    }

    function test_executeAllocation_success_viaCaller_singleERC20() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), amount);
        // fund caller and approve
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // run flow in one tx
        vm.prank(user);
        allocationCaller.onChainAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '', 0
        );
        vm.snapshotGasLastCall('hybrid_execute_single');

        // nonces incremented
        assertEq(allocator.nonces(), 1);

        // derive claim hash and ensure isClaimAuthorized is true
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        bytes32 claimHash = _toBatchCompactHash(
            BatchCompact({
                arbiter: arbiter,
                sponsor: user,
                nonce: allocator.nonces(),
                expires: defaultExpiration,
                commitments: commitments
            })
        );
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_executeAllocation_revert_InvalidPreparation() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), amount);
        // fund caller and approve
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // todo=2: deposit+register without prepare -> expect AllocatorLib.InvalidPreparation
        vm.prank(user);
        vm.expectRevert(AllocatorLib.InvalidPreparation.selector);
        allocationCaller.onChainAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '', 2
        );
    }

    function test_executeAllocation_revert_InvalidRegistration() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), amount);
        // fund caller and approve
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        // Compute expected claim hash for the deposit-only path
        Lock[] memory commitments = _idsAndAmountsToCommitments(idsAndAmounts);
        uint256 expectedNonce = uint256(allocator.nonces()) + 1; // prepare will use this
        bytes32 expectedClaimHash = _toBatchCompactHash(
            BatchCompact({
                arbiter: arbiter,
                sponsor: user,
                nonce: expectedNonce,
                expires: defaultExpiration,
                commitments: commitments
            })
        );

        // todo=1: deposit only, no register -> AllocatorLib.InvalidRegistration
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                AllocatorLib.InvalidRegistration.selector, user, expectedClaimHash, BATCH_COMPACT_TYPEHASH
            )
        );
        allocationCaller.onChainAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '', 1
        );
    }

    function test_executeAllocation_revert_InvalidBalanceChange_noDeposit() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), amount);
        // give user prior ERC6909 balance so (oldBalance > 0)
        bytes12 lockTag = _toLockTag(address(allocator), Scope.Multichain, ResetPeriod.TenMinutes);
        vm.startPrank(user);
        usdc.mint(user, amount);
        usdc.approve(address(compact), amount);
        compact.depositERC20(address(usdc), lockTag, amount, user);
        vm.stopPrank();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature('InvalidBalanceChange(uint256,uint256)', amount, amount));
        allocationCaller.onChainAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '', 3
        );
    }

    function test_executeAllocation_revert_InvalidPreparation_replaySameTx() public {
        uint256 amount = defaultAmount;
        uint256[2][] memory idsAndAmounts = _idsAndAmounts(address(usdc), amount);
        // fund caller and approve
        usdc.mint(address(allocationCaller), amount);
        vm.prank(address(allocationCaller));
        usdc.approve(address(compact), amount);

        vm.prank(user);
        vm.expectRevert(AllocatorLib.InvalidPreparation.selector);
        allocationCaller.onChainAllocation(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '', 4
        );
    }

    function test_allocateAndRegister_revert_InvalidIds() public {
        vm.expectRevert(IHybridAllocator.InvalidIds.selector);
        allocator.allocateAndRegister(user, new uint256[2][](0), arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_allocateAndRegister_revert_InvalidAllocatorIdNative() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(this), /* wrong address */ address(0));
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(
            abi.encodeWithSelector(
                IHybridAllocator.InvalidAllocatorId.selector, _toAllocatorId(address(this)), allocator.ALLOCATOR_ID()
            )
        );
        allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
    }

    function test_allocateAndRegister_revert_InvalidAllocatorIdERC20() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(this), /* wrong address */ address(usdc));
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(
            abi.encodeWithSelector(
                IHybridAllocator.InvalidAllocatorId.selector, _toAllocatorId(address(this)), allocator.ALLOCATOR_ID()
            )
        );
        allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_allocateAndRegister_revert_InvalidValue() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0) /* use native */ );
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(
            abi.encodeWithSelector(IHybridAllocator.InvalidValue.selector, defaultAmount + 1, defaultAmount)
        );
        allocator.allocateAndRegister{value: defaultAmount + 1}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
    }

    function test_allocateAndRegister_revert_zeroNativeTokensAmount() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidBatchDepositStructure.selector));
        allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_allocateAndRegister_revert_zeroTokensAmount() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = 0;
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidDepositBalanceChange.selector));
        allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_allocateAndRegister_revert_tokensNotProvided() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(abi.encodeWithSignature('TransferFromFailed()'));
        allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_allocateAndRegister_revert_invalidTokenOrder() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = 0;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[1][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        vm.expectRevert(); // Will revert when trying to approve tokens of address(0)
        allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
    }

    function test_allocateAndRegister_success_nativeToken() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0) /* use native */ );
        idsAndAmounts[0][1] = defaultAmount;
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_nativeToken');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(registeredAmounts.length, 1);
        assertEq(address(compact).balance, defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, 1);
    }

    function test_allocateAndRegister_success_erc20Token() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) =
            allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_erc20Token');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, 1);
    }

    function test_allocateAndRegister_success_nativeTokenWithEmptyAmountInput() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0) /* use native */ );
        idsAndAmounts[0][1] = 0;
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_nativeToken_emptyAmountInput');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(address(compact).balance, defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, 1);
    }

    function test_allocateAndRegister_success_erc20TokenWithEmptyAmountInput() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) =
            allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_erc20Token_emptyAmountInput');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(registeredAmounts.length, 1);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, 1);
    }

    function test_allocateAndRegister_success_multipleTokens() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[1][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_multipleTokens');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(registeredAmounts[1], defaultAmount);
        assertEq(registeredAmounts.length, 2);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(address(compact).balance, defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[1][0]), defaultAmount);
        assertEq(nonce, 1);
    }

    function test_allocateAndRegister_checkNonceIncrements_nativeToken() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        assertEq(allocator.nonces(), 0);

        // Register first claim
        allocator.allocateAndRegister{value: 5e17}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
        assertEq(allocator.nonces(), 1);

        // Register second claim
        (bytes32 claimHash, uint256[] memory registeredAmounts,) = allocator.allocateAndRegister{value: 5e17}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
        vm.snapshotGasLastCall('allocateAndRegister_second_nativeToken');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], 5e17);
        assertEq(registeredAmounts.length, 1);

        assertEq(allocator.nonces(), 2);
    }

    function test_allocateAndRegister_checkNonceIncrements_erc20Token() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = 0;

        assertEq(allocator.nonces(), 0);

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount / 2);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount / 2);

        // Register first claim
        allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        assertEq(allocator.nonces(), 1);

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount / 2);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount / 2);

        // Register second claim
        (bytes32 claimHash, uint256[] memory registeredAmounts,) =
            allocator.allocateAndRegister(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('allocateAndRegister_second_erc20Token');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount / 2);
        assertEq(registeredAmounts.length, 1);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);

        assertEq(allocator.nonces(), 2);
    }

    function test_allocateAndRegister_checkClaimHashNoWitness() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, registeredAmounts, nonce);

        bytes32 createdHash = _toBatchCompactHash(batch);
        assertEq(createdHash, claimHash);
        assertTrue(allocator.isClaimAuthorized(createdHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_allocateAndRegister_checkClaimHashWitness() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness);
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, registeredAmounts, nonce);
        bytes32 createdHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, witness);
        assertEq(createdHash, claimHash);
        assertTrue(allocator.isClaimAuthorized(createdHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_allocateAndRegister_slot() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        (bytes32 claimHash,,) = allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness
        );

        bytes32 claimSlot = keccak256(abi.encode(claimHash, 0x00));
        bytes32 claimSlotData = vm.load(address(allocator), claimSlot);
        assertEq(claimSlotData, bytes32(uint256(1)));
    }

    function test_isClaimAuthorized_unauthorized() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.allocateAndRegister{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, registeredAmounts, nonce);

        // Use the same batchCompact, but add a witness
        bytes32 falseHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, bytes32(0));
        assertNotEq(falseHash, claimHash);
        assertFalse(allocator.isClaimAuthorized(falseHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_isClaimAuthorized_signerZeroAddress() public {
        // Create an arbitrary claim hash that has not been registered.
        bytes32 claimHash = keccak256('invalid');
        assertEq(ecrecover(claimHash, 0, bytes32(0), bytes32(0)), address(0));

        // Craft a 65-byte signature that will make ecrecover return the zero address:
        // r = 0, s = 0, v = 0 (v not 27/28).
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        // Forcing address(0) as signer
        uint256 signersSlot = 0x03;
        vm.store(address(allocator), keccak256(abi.encode(address(0), signersSlot)), bytes32(uint256(1)));

        assertTrue(allocator.signers(address(0)));

        assertFalse(
            allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), invalidSignature)
        );
    }

    function test_isClaimAuthorized_withSigner_bytes64() public view {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, 1);

        bytes32 claimHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, witness);
        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
        (bytes32 r, bytes32 vs) = vm.signCompact(signerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, vs);
        assertEq(signature.length, 64);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, user, 1, defaultExpiration, idsAndAmounts, signature)
        );
    }

    function test_isClaimAuthorized_withSigner_bytes65() public view {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, 1);

        bytes32 claimHash;
        bytes memory signature;
        {
            claimHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, witness);
            bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
            signature = abi.encodePacked(r, s, v);
        }
        assertEq(signature.length, 65);
        assertTrue(
            allocator.isClaimAuthorized(claimHash, arbiter, user, 1, defaultExpiration, idsAndAmounts, signature)
        );
    }

    function test_isClaimAuthorized_invalidSignature() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, 1);

        bytes32 claimHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, witness);
        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());

        bytes memory signature;
        {
            (, uint256 attackerPK) = makeAddrAndKey('attacker');
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPK, digest);
            signature = abi.encodePacked(r, s, v);
            assertEq(signature.length, 65);
        }
        assertFalse(
            allocator.isClaimAuthorized(claimHash, arbiter, user, 1, defaultExpiration, idsAndAmounts, signature)
        );
    }

    function test_attest_revert_Unsupported() public {
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        address target = makeAddr('target');

        assertEq(usdc.balanceOf(user), defaultAmount);

        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.Unsupported.selector));
        allocator.attest(signer, user, target, id, defaultAmount);
    }

    function test_attest_revert_transferFailed() public {
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        address target = makeAddr('target');

        assertEq(usdc.balanceOf(user), defaultAmount);
        vm.startPrank(user);
        usdc.approve(address(compact), defaultAmount);
        compact.depositERC20(address(usdc), bytes12(bytes32(id)), defaultAmount, user);

        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.Unsupported.selector), address(allocator));
        compact.transfer(target, id, defaultAmount);
        vm.stopPrank();
    }

    function test_authorizeClaim_revert_invalidCaller(address attacker) public {
        vm.assume(attacker != address(compact));
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);
        assertEq(address(allocator).balance, 0);

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        vm.prank(user);
        (bytes32 claimHash,,) = allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness
        );

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidCaller.selector, attacker, address(compact)));
        allocator.authorizeClaim(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), '');
    }

    function test_revert_authorizeClaim_InvalidSignature(uint128 nonce) public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[1][1] = defaultAmount;

        // Approve tokens
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        bytes32 claimHash = _toBatchCompactHashWithWitness(
            BATCH_COMPACT_TYPEHASH_WITH_WITNESS,
            BatchCompact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce,
                expires: defaultExpiration,
                commitments: _idsAndAmountsToCommitments(idsAndAmounts)
            }),
            witness
        );

        bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](1);
        claimHashesAndTypehashes[0][0] = claimHash;
        claimHashesAndTypehashes[0][1] = BATCH_COMPACT_TYPEHASH_WITH_WITNESS;

        // Deposit and register
        vm.prank(user);
        compact.batchDepositAndRegisterMultiple{value: defaultAmount}(idsAndAmounts, claimHashesAndTypehashes);

        // Off chain signing the claim
        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
        (address attacker, uint256 attackerPK) = makeAddrAndKey('attacker');
        (bytes32 r, bytes32 vs) = vm.signCompact(attackerPK, digest);
        bytes memory allocatorData = abi.encodePacked(r, vs);

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
        {
            Component[] memory portions = new Component[](1);
            portions[0] = Component({
                claimant: uint256(bytes32(abi.encodePacked(bytes12(0), attacker))), // indicating a withdrawal
                amount: defaultAmount
            });

            claims[0] =
                BatchClaimComponent({id: idsAndAmounts[0][0], allocatedAmount: defaultAmount, portions: portions});
            claims[1] =
                BatchClaimComponent({id: idsAndAmounts[1][0], allocatedAmount: defaultAmount, portions: portions});
        }

        BatchClaim memory claim = BatchClaim({
            allocatorData: allocatorData,
            sponsorSignature: '',
            sponsor: user,
            nonce: nonce,
            expires: defaultExpiration,
            witness: witness,
            witnessTypestring: WITNESS_STRING,
            claims: claims
        });

        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSignature.selector));
        compact.batchClaim(claim);
    }

    function test_authorizeClaim_success_onChain() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[1][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);
        assertEq(address(allocator).balance, 0);

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        vm.prank(user);
        (bytes32 claimHash,, uint256 nonce) = allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness
        );

        address target = makeAddr('target');

        bytes32 returnedClaimHash;
        {
            Component[] memory portions = new Component[](1);
            portions[0] = Component({
                claimant: uint256(bytes32(abi.encodePacked(bytes12(0), target))), // indicating a withdrawal
                amount: defaultAmount
            });

            BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
            claims[0] =
                BatchClaimComponent({id: idsAndAmounts[0][0], allocatedAmount: defaultAmount, portions: portions});
            claims[1] =
                BatchClaimComponent({id: idsAndAmounts[1][0], allocatedAmount: defaultAmount, portions: portions});

            BatchClaim memory claim = BatchClaim({
                allocatorData: '',
                sponsorSignature: '',
                sponsor: user,
                nonce: nonce,
                expires: defaultExpiration,
                witness: witness,
                witnessTypestring: WITNESS_STRING,
                claims: claims
            });
            vm.prank(arbiter);
            returnedClaimHash = compact.batchClaim(claim);
            assertEq(returnedClaimHash, claimHash);
        }

        assertEq(usdc.balanceOf(address(compact)), 0, 'compact usdc balance should be 0');
        assertEq(usdc.balanceOf(address(user)), 0, 'user usdc balance should be 0');
        assertEq(usdc.balanceOf(address(target)), defaultAmount, 'target usdc balance should be defaultAmount');
        assertEq(address(compact).balance, 0, 'compact balance should be 0');
        assertEq(address(user).balance, 0, 'user balance should be 0');
        assertEq(address(target).balance, defaultAmount, 'target balance should be defaultAmount');
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), 0, 'user eth compact balance of 0 should be 0');
        assertEq(
            compact.balanceOf(address(target), idsAndAmounts[0][0]), 0, 'target eth compact balance of 0 should be 0'
        );
        assertEq(compact.balanceOf(address(user), idsAndAmounts[1][0]), 0, 'user usdc compact balance of 0 should be 0');
        assertEq(
            compact.balanceOf(address(target), idsAndAmounts[1][0]), 0, 'target usdc compact balance of 0 should be 0'
        );
    }

    function test_authorizeClaim_success_offChain(uint128 nonce) public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = defaultAmount;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[1][1] = defaultAmount;

        // Approve tokens
        vm.prank(user);
        usdc.approve(address(compact), defaultAmount);

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        bytes32 claimHash = _toBatchCompactHashWithWitness(
            BATCH_COMPACT_TYPEHASH_WITH_WITNESS,
            BatchCompact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce,
                expires: defaultExpiration,
                commitments: _idsAndAmountsToCommitments(idsAndAmounts)
            }),
            witness
        );

        bytes32[2][] memory claimHashesAndTypehashes = new bytes32[2][](1);
        claimHashesAndTypehashes[0][0] = claimHash;
        claimHashesAndTypehashes[0][1] = BATCH_COMPACT_TYPEHASH_WITH_WITNESS;

        // Deposit and register
        vm.prank(user);
        compact.batchDepositAndRegisterMultiple{value: defaultAmount}(idsAndAmounts, claimHashesAndTypehashes);

        // Off chain signing the claim
        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
        (bytes32 r, bytes32 vs) = vm.signCompact(signerPrivateKey, digest);
        bytes memory allocatorData = abi.encodePacked(r, vs);

        address target = makeAddr('target');

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](2);
        {
            Component[] memory portions = new Component[](1);
            portions[0] = Component({
                claimant: uint256(bytes32(abi.encodePacked(bytes12(0), target))), // indicating a withdrawal
                amount: defaultAmount
            });

            claims[0] =
                BatchClaimComponent({id: idsAndAmounts[0][0], allocatedAmount: defaultAmount, portions: portions});
            claims[1] =
                BatchClaimComponent({id: idsAndAmounts[1][0], allocatedAmount: defaultAmount, portions: portions});
        }

        BatchClaim memory claim = BatchClaim({
            allocatorData: allocatorData,
            sponsorSignature: '',
            sponsor: user,
            nonce: nonce,
            expires: defaultExpiration,
            witness: witness,
            witnessTypestring: WITNESS_STRING,
            claims: claims
        });

        vm.prank(arbiter);
        bytes32 returnedClaimHash = compact.batchClaim(claim);
        assertEq(returnedClaimHash, claimHash);

        assertEq(usdc.balanceOf(address(compact)), 0, 'compact usdc balance should be 0');
        assertEq(usdc.balanceOf(address(user)), 0, 'user usdc balance should be 0');
        assertEq(usdc.balanceOf(address(target)), defaultAmount, 'target usdc balance should be defaultAmount');
        assertEq(address(compact).balance, 0, 'compact balance should be 0');
        assertEq(address(user).balance, 0, 'user balance should be 0');
        assertEq(address(target).balance, defaultAmount, 'target balance should be defaultAmount');
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), 0, 'user eth compact balance of 0 should be 0');
        assertEq(
            compact.balanceOf(address(target), idsAndAmounts[0][0]), 0, 'target eth compact balance of 0 should be 0'
        );
        assertEq(compact.balanceOf(address(user), idsAndAmounts[1][0]), 0, 'user usdc compact balance of 0 should be 0');
        assertEq(
            compact.balanceOf(address(target), idsAndAmounts[1][0]), 0, 'target usdc compact balance of 0 should be 0'
        );
    }

    function test_authorizeClaim_registrationDeleted() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        vm.prank(user);
        (bytes32 claimHash,, uint256 nonce) = allocator.allocateAndRegister{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );

        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
        (bytes32 r, bytes32 vs) = vm.signCompact(userPrivateKey, digest);
        bytes memory sponsorSignature = abi.encodePacked(r, vs);

        address target = makeAddr('target');

        Component[] memory portions = new Component[](1);
        portions[0] = Component({
            claimant: uint256(bytes32(abi.encodePacked(bytes12(0), target))), // indicating a withdrawal
            amount: defaultAmount
        });

        BatchClaimComponent[] memory claims = new BatchClaimComponent[](1);
        claims[0] = BatchClaimComponent({id: idsAndAmounts[0][0], allocatedAmount: defaultAmount, portions: portions});

        BatchClaim memory claim = BatchClaim({
            allocatorData: '',
            sponsorSignature: sponsorSignature,
            sponsor: user,
            nonce: nonce,
            expires: defaultExpiration,
            witness: '',
            witnessTypestring: '',
            claims: claims
        });

        vm.prank(arbiter);
        bytes32 returnedClaimHash = compact.batchClaim(claim);
        assertEq(returnedClaimHash, claimHash);

        assertFalse(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_addSigner_revert_InvalidSigner(address attacker) public {
        vm.assume(attacker != address(0));
        vm.assume(attacker != signer);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSigner.selector));
        allocator.addSigner(attacker);
        assertEq(allocator.signerCount(), 1);
        assertFalse(allocator.signers(attacker));
    }

    function test_addSigner_revert_signerIsZero() public {
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSigner.selector));
        allocator.addSigner(address(0));
        assertEq(allocator.signerCount(), 1);
        assertFalse(allocator.signers(address(0)));
    }

    function test_addSigner_success(address newSigner) public {
        vm.assume(newSigner != signer);
        vm.assume(newSigner != address(0));
        vm.prank(signer);
        allocator.addSigner(newSigner);
        assertEq(allocator.signerCount(), 2);
        assertTrue(allocator.signers(newSigner));
        assertTrue(allocator.signers(signer));
    }

    function test_removeSigner_revert_InvalidSigner(address attacker) public {
        vm.assume(attacker != signer);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSigner.selector));
        allocator.removeSigner(signer);
        assertEq(allocator.signerCount(), 1);
        assertTrue(allocator.signers(signer));
    }

    function test_removeSigner_revert_LastSigner() public {
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.LastSigner.selector));
        allocator.removeSigner(signer);
        assertEq(allocator.signerCount(), 1);
        assertTrue(allocator.signers(signer));
    }

    function test_removeSigner_success(address newSigner) public {
        vm.assume(newSigner != signer);
        vm.assume(newSigner != address(0));
        vm.prank(signer);
        allocator.addSigner(newSigner);
        assertEq(allocator.signerCount(), 2);
        vm.prank(newSigner);
        allocator.removeSigner(signer);
        assertEq(allocator.signerCount(), 1);
        assertFalse(allocator.signers(signer));
        assertTrue(allocator.signers(newSigner));
    }

    function test_removeSigner_success_deleteSelf(address newSigner) public {
        vm.assume(newSigner != signer);
        vm.assume(newSigner != address(0));
        vm.prank(signer);
        allocator.addSigner(newSigner);
        assertEq(allocator.signerCount(), 2);
        vm.prank(newSigner);
        allocator.removeSigner(newSigner);
        assertEq(allocator.signerCount(), 1);
        assertTrue(allocator.signers(signer));
        assertFalse(allocator.signers(newSigner));
    }

    function test_replaceSigner_revert_InvalidSigner(address attacker) public {
        vm.assume(attacker != signer);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSigner.selector));
        allocator.replaceSigner(attacker);
        assertEq(allocator.signerCount(), 1);
        assertFalse(allocator.signers(attacker));
    }

    function test_replaceSigner_revert_signerIsZero() public {
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSigner.selector));
        allocator.replaceSigner(address(0));
        assertEq(allocator.signerCount(), 1);
        assertFalse(allocator.signers(address(0)));
    }

    function test_replaceSigner_success(address newSigner) public {
        vm.assume(newSigner != signer);
        vm.assume(newSigner != address(0));
        vm.prank(signer);
        allocator.replaceSigner(newSigner);
        assertEq(allocator.signerCount(), 1);
        assertFalse(allocator.signers(signer));
        assertTrue(allocator.signers(newSigner));
    }
}
