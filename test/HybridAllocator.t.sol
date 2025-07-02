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
import {BATCH_COMPACT_WITNESS_TYPEHASH} from 'src/allocators/lib/TypeHashes.sol';
import {ERC20Mock} from 'src/test/ERC20Mock.sol';

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

        batchCompact.arbiter = arbiter;
        batchCompact.sponsor = user;
        batchCompact.nonce = uint256(type(uint128).max) + 1;
        batchCompact.expires = defaultExpiration;
    }

    function test_checkAllocatorId() public view {
        assertEq(allocator.ALLOCATOR_ID(), _toAllocatorId(address(allocator)));
    }

    function test_checkNonce() public view {
        assertEq(allocator.nonce(), type(uint128).max);
    }

    function test_checkSignerCount() public view {
        assertEq(allocator.signerCount(), 1);
    }

    function test_checkSigners(address attacker) public view {
        vm.assume(attacker != signer);

        assertTrue(allocator.signers(signer));
        assertFalse(allocator.signers(attacker));
    }

    function test_registerClaim_revert_InvalidIds() public {
        vm.expectRevert(HybridAllocator.InvalidIds.selector);
        allocator.registerClaim(user, new uint256[2][](0), arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_registerClaim_revert_InvalidAllocatorIdNative() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(this), /* wrong address */ address(0));
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(
            abi.encodeWithSelector(
                HybridAllocator.InvalidAllocatorId.selector, _toAllocatorId(address(this)), allocator.ALLOCATOR_ID()
            )
        );
        allocator.registerClaim{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
    }

    function test_registerClaim_revert_InvalidAllocatorIdERC20() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(this), /* wrong address */ address(usdc));
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(
            abi.encodeWithSelector(
                HybridAllocator.InvalidAllocatorId.selector, _toAllocatorId(address(this)), allocator.ALLOCATOR_ID()
            )
        );
        allocator.registerClaim(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_registerClaim_revert_InvalidValue() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0) /* use native */ );
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(abi.encodeWithSelector(HybridAllocator.InvalidValue.selector, defaultAmount + 1, defaultAmount));
        allocator.registerClaim{value: defaultAmount + 1}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
    }

    function test_registerClaim_revert_zeroNativeTokensAmount() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidBatchDepositStructure.selector));
        allocator.registerClaim(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_registerClaim_revert_zeroTokensAmount() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = 0;
        vm.expectRevert(abi.encodeWithSelector(ITheCompact.InvalidDepositBalanceChange.selector));
        allocator.registerClaim(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_registerClaim_revert_tokensNotProvided() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;
        vm.expectRevert(abi.encodeWithSignature('TransferFromFailed()'));
        allocator.registerClaim(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
    }

    function test_registerClaim_revert_invalidTokenOrder() public {
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
        allocator.registerClaim{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
    }

    function test_registerClaim_success_nativeToken() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0) /* use native */ );
        idsAndAmounts[0][1] = defaultAmount;
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.registerClaim{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('registerClaim_nativeToken');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(registeredAmounts.length, 1);
        assertEq(address(compact).balance, defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, type(uint128).max + 1);
    }

    function test_registerClaim_success_erc20Token() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = defaultAmount;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) =
            allocator.registerClaim(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('registerClaim_erc20Token');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, type(uint128).max + 1);
    }

    function test_registerClaim_success_nativeTokenWithEmptyAmountInput() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] =
            _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0) /* use native */ );
        idsAndAmounts[0][1] = 0;
        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.registerClaim{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('registerClaim_nativeToken_emptyAmountInput');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(address(compact).balance, defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, type(uint128).max + 1);
    }

    function test_registerClaim_success_erc20TokenWithEmptyAmountInput() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[0][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) =
            allocator.registerClaim(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('registerClaim_erc20Token_emptyAmountInput');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(registeredAmounts.length, 1);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, type(uint128).max + 1);
    }

    function test_registerClaim_success_multipleTokens() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](2);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        idsAndAmounts[1][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        idsAndAmounts[1][1] = 0;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(allocator), defaultAmount);
        assertEq(usdc.balanceOf(address(allocator)), defaultAmount);

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.registerClaim{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        vm.snapshotGasLastCall('registerClaim_multipleTokens');

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(registeredAmounts[1], defaultAmount);
        assertEq(registeredAmounts.length, 2);
        assertEq(usdc.balanceOf(address(compact)), defaultAmount);
        assertEq(address(compact).balance, defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[1][0]), defaultAmount);
        assertEq(nonce, type(uint128).max + 1);
    }

    function test_registerClaim_checkNonceIncrements() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        // Register first claim
        allocator.registerClaim{value: 5e17}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );
        // Register second claim
        (bytes32 claimHash, uint256[] memory registeredAmounts,) = allocator.registerClaim{value: 5e17}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, ''
        );

        assertTrue(compact.isRegistered(user, claimHash, BATCH_COMPACT_TYPEHASH));
        assertTrue(allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
        assertEq(registeredAmounts[0], 5e17);
        assertEq(registeredAmounts.length, 1);
        assertEq(address(compact).balance, defaultAmount);
        assertEq(compact.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(allocator.nonce(), type(uint128).max + 1);
    }

    function test_registerClaim_checkClaimHashNoWitness() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.registerClaim{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, registeredAmounts, nonce);

        bytes32 createdHash = _toBatchCompactHash(batch);
        assertEq(createdHash, claimHash);
        assertTrue(allocator.isClaimAuthorized(createdHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_registerClaim_checkClaimHashWitness() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        bytes32 witness = keccak256(abi.encode(WITNESS_TYPEHASH, 1));

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.registerClaim{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness);
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, registeredAmounts, nonce);
        bytes32 createdHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, witness);
        assertEq(createdHash, claimHash);
        assertTrue(allocator.isClaimAuthorized(createdHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
    }

    function test_isClaimAuthorized_unauthorized() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(0));
        idsAndAmounts[0][1] = 0;

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = allocator.registerClaim{
            value: defaultAmount
        }(user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH, '');
        BatchCompact memory batch = _updateBatchCompact(batchCompact, idsAndAmounts, registeredAmounts, nonce);

        // Use the same batchCompact, but add a witness
        bytes32 falseHash = _toBatchCompactHashWithWitness(BATCH_COMPACT_TYPEHASH_WITH_WITNESS, batch, bytes32(0));
        assertNotEq(falseHash, claimHash);
        assertFalse(allocator.isClaimAuthorized(falseHash, address(0), address(0), 0, 0, new uint256[2][](0), ''));
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

        vm.expectRevert(abi.encodeWithSelector(HybridAllocator.Unsupported.selector));
        allocator.attest(signer, user, target, id, defaultAmount);
    }

    function test_attest_revert_transferFailed() public {
        uint256 id = _toId(Scope.Multichain, ResetPeriod.TenMinutes, address(allocator), address(usdc));
        address target = makeAddr('target');

        assertEq(usdc.balanceOf(user), defaultAmount);
        vm.startPrank(user);
        usdc.approve(address(compact), defaultAmount);
        compact.depositERC20(address(usdc), bytes12(bytes32(id)), defaultAmount, user);

        vm.expectRevert(abi.encodeWithSelector(HybridAllocator.Unsupported.selector), address(allocator));
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
        (bytes32 claimHash,,) = allocator.registerClaim{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness
        );

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(HybridAllocator.InvalidCaller.selector, attacker, address(compact)));
        allocator.authorizeClaim(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), '');
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
        (bytes32 claimHash,, uint256 nonce) = allocator.registerClaim{value: defaultAmount}(
            user, idsAndAmounts, arbiter, defaultExpiration, BATCH_COMPACT_TYPEHASH_WITH_WITNESS, witness
        );

        bytes32 digest = _toDigest(claimHash, compact.DOMAIN_SEPARATOR());
        (bytes32 r, bytes32 vs) = vm.signCompact(userPrivateKey, digest);
        bytes memory sponsorSignature = abi.encodePacked(r, vs);

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
                sponsorSignature: sponsorSignature,
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
        (bytes32 claimHash,, uint256 nonce) = allocator.registerClaim{value: defaultAmount}(
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
        vm.assume(attacker != signer);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(HybridAllocator.InvalidSigner.selector));
        allocator.addSigner(attacker);
        assertEq(allocator.signerCount(), 1);
        assertFalse(allocator.signers(attacker));
    }

    function test_addSigner_success(address newSigner) public {
        vm.assume(newSigner != signer);
        vm.prank(signer);
        allocator.addSigner(newSigner);
        assertEq(allocator.signerCount(), 2);
        assertTrue(allocator.signers(newSigner));
        assertTrue(allocator.signers(signer));
    }

    function test_removeSigner_revert_InvalidSigner(address attacker) public {
        vm.assume(attacker != signer);
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(HybridAllocator.InvalidSigner.selector));
        allocator.removeSigner(signer);
        assertEq(allocator.signerCount(), 1);
        assertTrue(allocator.signers(signer));
    }

    function test_removeSigner_revert_LastSigner() public {
        vm.prank(signer);
        vm.expectRevert(abi.encodeWithSelector(HybridAllocator.LastSigner.selector));
        allocator.removeSigner(signer);
        assertEq(allocator.signerCount(), 1);
        assertTrue(allocator.signers(signer));
    }

    function test_removeSigner_success(address newSigner) public {
        vm.assume(newSigner != signer);
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
        vm.expectRevert(abi.encodeWithSelector(HybridAllocator.InvalidSigner.selector));
        allocator.replaceSigner(attacker);
        assertEq(allocator.signerCount(), 1);
        assertFalse(allocator.signers(attacker));
    }

    function test_replaceSigner_success(address newSigner) public {
        vm.assume(newSigner != signer);
        vm.prank(signer);
        allocator.replaceSigner(newSigner);
        assertEq(allocator.signerCount(), 1);
        assertFalse(allocator.signers(signer));
        assertTrue(allocator.signers(newSigner));
    }
}
