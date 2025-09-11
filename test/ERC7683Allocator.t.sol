// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {TheCompact} from '@uniswap/the-compact/TheCompact.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';

import {IdLib} from '@uniswap/the-compact/lib/IdLib.sol';

import {BatchClaim} from '@uniswap/the-compact/types/BatchClaims.sol';
import {BatchClaimComponent, Component} from '@uniswap/the-compact/types/Components.sol';
import {BatchCompact, COMPACT_TYPEHASH, LOCK_TYPEHASH, Lock} from '@uniswap/the-compact/types/EIP712Types.sol';
import {ForcedWithdrawalStatus} from '@uniswap/the-compact/types/ForcedWithdrawalStatus.sol';
import {ResetPeriod} from '@uniswap/the-compact/types/ResetPeriod.sol';
import {Scope} from '@uniswap/the-compact/types/Scope.sol';
import {Test} from 'forge-std/Test.sol';

import {TestHelper} from 'test/util/TestHelper.sol';

import {IOnChainAllocation} from '@uniswap/the-compact/interfaces/IOnChainAllocation.sol';

import {Tribunal} from '@uniswap/tribunal/Tribunal.sol';
import {Fill, Mandate, RecipientCallback} from '@uniswap/tribunal/types/TribunalStructs.sol';
import {
    COMPACT_TYPEHASH_WITH_MANDATE,
    MANDATE_BATCH_COMPACT_TYPEHASH,
    MANDATE_FILL_TYPEHASH,
    MANDATE_RECIPIENT_CALLBACK_TYPEHASH,
    MANDATE_TYPEHASH,
    WITNESS_TYPESTRING as WITNESS_TYPESTRING_TRIBUNAL
} from '@uniswap/tribunal/types/TribunalTypeHashes.sol';
import {ERC7683Allocator} from 'src/allocators/ERC7683Allocator.sol';
import {ERC7683AllocatorLib as ERC7683AL} from 'src/allocators/lib/ERC7683AllocatorLib.sol';
import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';
import {IERC7683Allocator} from 'src/interfaces/IERC7683Allocator.sol';
import {IOnChainAllocator} from 'src/interfaces/IOnChainAllocator.sol';

import {ERC20Mock} from 'src/test/ERC20Mock.sol';

import {
    CompactData,
    GaslessCrossChainOrderData,
    MocksSetup,
    OnChainCrossChainOrderData
} from 'test/util/ERC7683TestHelper.sol';

contract MockAllocator is GaslessCrossChainOrderData, OnChainCrossChainOrderData {
    ERC7683Allocator erc7683Allocator;

    function setUp() public virtual override(GaslessCrossChainOrderData, OnChainCrossChainOrderData) {
        TheCompact compactContract_ = new TheCompact();
        erc7683Allocator = new ERC7683Allocator(address(compactContract_));
        _setUp(address(erc7683Allocator), compactContract_, _composeNonceUint(user, 1));
        super.setUp();
    }
}

contract ERC7683Allocator_open is MockAllocator {
    function test_revert_InvalidOrderDataType() public {
        // Order data type is invalid
        bytes32 falseOrderDataType = keccak256('false');
        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();
        onChainCrossChainOrder_.orderDataType = falseOrderDataType;

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector, falseOrderDataType, ORDERDATA_ONCHAIN_TYPEHASH
            )
        );
        erc7683Allocator.open(onChainCrossChainOrder_);
    }

    // Removed redundant typehash equality check; we compare against library in setup.

    function test_revert_ManipulatedOrderData() public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        (bytes32 mandateHash,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHash);
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        vm.stopPrank();

        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();

        // Manipulate the order data
        uint256 outOfBounds = type(uint256).max; // uint256(type(uint64).max) + 1;

        bytes memory callData = abi.encodeWithSelector(IOriginSettler.open.selector, onChainCrossChainOrder_);
        // 0x00 selector
        // 0x24 OnchainCrossChainOrder.offset
        // 0x44 OnchainCrossChainOrder.fillDeadline
        // 0x64 OnchainCrossChainOrder.orderDataType
        // 0x84 OnchainCrossChainOrder.orderData.offset
        // 0xa4 OnchainCrossChainOrder.orderData.length
        // 0xc4 OnchainCrossChainOrder.OrderDataOnChain.offset
        // 0xe4 OnchainCrossChainOrder.OrderDataOnChain.Order.offset

        assembly ("memory-safe") {
            mstore(add(callData, 0xe4), outOfBounds)
        }

        vm.prank(user);
        (bool success, bytes memory returnData) = address(erc7683Allocator).call(callData);
        assertEq(success, false);
        assertEq(returnData.length, 0);
    }

    function test_revert_InvalidRegistration() public {
        // we deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // we do NOT register a claim

        vm.stopPrank();

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        (bytes32 mandateHash,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHash);
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) =
            _getOnChainCrossChainOrder(compact_, mandate_);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocation.InvalidRegistration.selector, user, claimHash));
        erc7683Allocator.open(onChainCrossChainOrder_);
    }

    function test_successful() public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        (bytes32 mHash,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mHash);
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        vm.stopPrank();

        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        IOriginSettler.Output[] memory maxSpent = new IOriginSettler.Output[](1);
        IOriginSettler.Output[] memory minReceived = new IOriginSettler.Output[](1);
        IOriginSettler.FillInstruction[] memory fillInstructions = new IOriginSettler.FillInstruction[](1);
        maxSpent[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(defaultOutputToken))),
            amount: type(uint256).max,
            recipient: bytes32(uint256(uint160(user))),
            chainId: defaultOutputChainId
        });
        minReceived[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(address(usdc)))),
            amount: defaultAmount,
            recipient: '',
            chainId: block.chainid
        });
        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: _getCompact(),
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, _getMandate().fills[0], adjuster, _buildFillHashes(_getMandate()))
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(_getClaimExpiration()),
            fillDeadline: uint32(_getFillExpiration()),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        vm.prank(user);
        vm.expectEmit(true, false, false, false, address(erc7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        erc7683Allocator.open(onChainCrossChainOrder_);
        vm.snapshotGasLastCall('open_simpleOrder');
    }
}

contract ERC7683Allocator_openFor is MockAllocator {
    function test_revert_InvalidOriginChainId(uint256 wrongChainId) public {
        vm.assume(wrongChainId != block.chainid);
        IOriginSettler.GaslessCrossChainOrder memory gasless = _getGaslessCrossChainOrder();
        gasless.originChainId = wrongChainId;
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(ERC7683AL.InvalidOriginChainId.selector, wrongChainId, block.chainid)
        );
        erc7683Allocator.openFor(gasless, '', '');
    }
    function test_revert_InvalidOrderDataType() public {
        // Order data type is invalid
        bytes32 falseOrderDataType = keccak256('false');

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector, falseOrderDataType, ORDERDATA_GASLESS_TYPEHASH
            )
        );
        IOriginSettler.GaslessCrossChainOrder memory falseGaslessCrossChainOrder = _getGaslessCrossChainOrder();
        falseGaslessCrossChainOrder.orderDataType = falseOrderDataType;
        erc7683Allocator.openFor(falseGaslessCrossChainOrder, '', '');
    }

    // removed redundant typehash getter check

    function test_revert_InvalidDecoding() public {
        // Decoding fails because of additional data
        vm.prank(user);
        vm.expectRevert();
        IOriginSettler.GaslessCrossChainOrder memory falseGaslessCrossChainOrder = _getGaslessCrossChainOrder();
        falseGaslessCrossChainOrder.orderData = abi.encode(falseGaslessCrossChainOrder.orderData, uint8(1));
        erc7683Allocator.openFor(falseGaslessCrossChainOrder, '', '');
    }

    function test_revert_InvalidOriginSettler() public {
        // Origin settler is not the allocator
        address falseOriginSettler = makeAddr('falseOriginSettler');
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOriginSettler.selector, falseOriginSettler, address(erc7683Allocator)
            )
        );
        IOriginSettler.GaslessCrossChainOrder memory falseGaslessCrossChainOrder = _getGaslessCrossChainOrder();
        falseGaslessCrossChainOrder.originSettler = falseOriginSettler;
        vm.prank(user);
        erc7683Allocator.openFor(falseGaslessCrossChainOrder, '', '');
    }

    function test_revert_InvalidNonce(uint256 nonce) public {
        vm.assume(nonce != defaultNonce);

        BatchCompact memory compact_ = _getCompact();
        compact_.nonce = nonce;
        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidNonce.selector, compact_.nonce, defaultNonce));
        IOriginSettler.GaslessCrossChainOrder memory falseGaslessCrossChainOrder = _getGaslessCrossChainOrder();
        falseGaslessCrossChainOrder.nonce = nonce;
        vm.prank(user);
        erc7683Allocator.openFor(falseGaslessCrossChainOrder, '', '');
    }

    function test_successful_userHimself() public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        (bytes32 mandateHash,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHash);

        // Register the claim to allow to open the order
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        vm.stopPrank();

        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ =
            _getGaslessCrossChainOrder(compact_, mandate_, false);
        IOriginSettler.Output[] memory maxSpent = new IOriginSettler.Output[](1);
        IOriginSettler.Output[] memory minReceived = new IOriginSettler.Output[](1);
        IOriginSettler.FillInstruction[] memory fillInstructions = new IOriginSettler.FillInstruction[](1);
        maxSpent[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(defaultOutputToken))),
            amount: type(uint256).max,
            recipient: bytes32(uint256(uint160(user))),
            chainId: defaultOutputChainId
        });
        minReceived[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(address(usdc)))),
            amount: defaultAmount,
            recipient: '',
            chainId: block.chainid
        });
        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: _getCompact(),
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, _getMandate(), uint256(0), uint256(0))
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(_getClaimExpiration()),
            fillDeadline: uint32(_getFillExpiration()),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        vm.prank(user);
        vm.expectEmit(true, false, false, false, address(erc7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        erc7683Allocator.openFor(gaslessCrossChainOrder_, '', '');
        vm.snapshotGasLastCall('openFor_simpleOrder_userHimself');
    }

    function test_successful_relayed_registration(address filler) public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        (bytes32 mandateHash,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHash);

        // Register the claim to allow to open the order
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        vm.stopPrank();

        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ =
            _getGaslessCrossChainOrder(compact_, mandate_, false);

        IOriginSettler.Output[] memory maxSpent = new IOriginSettler.Output[](1);
        IOriginSettler.Output[] memory minReceived = new IOriginSettler.Output[](1);
        IOriginSettler.FillInstruction[] memory fillInstructions = new IOriginSettler.FillInstruction[](1);
        maxSpent[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(defaultOutputToken))),
            amount: type(uint256).max,
            recipient: bytes32(uint256(uint160(user))),
            chainId: defaultOutputChainId
        });
        minReceived[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(address(usdc)))),
            amount: defaultAmount,
            recipient: '',
            chainId: block.chainid
        });
        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: _getCompact(),
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, _getMandate(), uint256(0), uint256(0))
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(_getClaimExpiration()),
            fillDeadline: uint32(_getFillExpiration()),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        vm.prank(filler);
        vm.expectEmit(true, false, false, false, address(erc7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        erc7683Allocator.openFor(gaslessCrossChainOrder_, '', '');
        vm.snapshotGasLastCall('openFor_simpleOrder_relayed');
    }

    function test_successful_relayed_signature(address filler) public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);
        vm.stopPrank();

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        bytes memory sponsorSignature = _hashAndSign(compact_, mandate_, address(compactContract), userPK);

        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ =
            _getGaslessCrossChainOrder(compact_, mandate_, false);

        IOriginSettler.Output[] memory maxSpent = new IOriginSettler.Output[](1);
        IOriginSettler.Output[] memory minReceived = new IOriginSettler.Output[](1);
        IOriginSettler.FillInstruction[] memory fillInstructions = new IOriginSettler.FillInstruction[](1);
        maxSpent[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(defaultOutputToken))),
            amount: type(uint256).max,
            recipient: bytes32(uint256(uint160(user))),
            chainId: defaultOutputChainId
        });
        minReceived[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(address(usdc)))),
            amount: defaultAmount,
            recipient: '',
            chainId: block.chainid
        });
        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: _getCompact(),
            sponsorSignature: sponsorSignature,
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, _getMandate(), uint256(0), uint256(0))
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(_getClaimExpiration()),
            fillDeadline: uint32(_getFillExpiration()),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });

        vm.prank(filler);
        vm.expectEmit(true, false, false, false, address(erc7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        erc7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');
        vm.snapshotGasLastCall('openFor_simpleOrder_relayed');
    }

    function test_revert_NonceAlreadyInUse(uint256 nonce) public {
        vm.assume(nonce != defaultNonce);
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);
        vm.stopPrank();

        // try to use a future nonce
        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder = _getGaslessCrossChainOrder();
        gaslessCrossChainOrder.nonce = nonce;
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidNonce.selector, nonce, defaultNonce));
        erc7683Allocator.openFor(gaslessCrossChainOrder, '', '');
    }
}

contract ERC7683Allocator_authorizeClaim is MockAllocator {
    function test_revert_InvalidSignature() public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        (bytes32 mandateHash,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHash);
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(compactContract.balanceOf(filler, usdcId), 0);

        vm.stopPrank();

        // we do NOT open the order or lock the tokens

        // claim should fail, because we did not open an order
        Component memory component = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        Component[] memory components = new Component[](1);
        components[0] = component;
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        BatchClaim memory claim = BatchClaim({
            allocatorData: '',
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: bytes32(0),
            witnessTypestring: '',
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(0x8baa579f)); // check for the InvalidSignature() error in the Compact contract
        compactContract.batchClaim(claim);

        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(compactContract.balanceOf(filler, usdcId), 0);
    }

    function test_revert_InvalidAllocatorData() public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        (bytes32 mandateHash2,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHash2);
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        erc7683Allocator.open(onChainCrossChainOrder_);
        vm.stopPrank();

        // claim should be successful
        (bytes32 witness,) = _hashMandate(mandate_);
        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        BatchClaim memory claim = BatchClaim({
            allocatorData: '',
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: witness,
            witnessTypestring: '',
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(0x8baa579f));
        compactContract.batchClaim(claim);
    }

    function test_successful_open() public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        (bytes32 mandateHash,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHash);
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) =
            _getOnChainCrossChainOrder(compact_, mandate_);
        erc7683Allocator.open(onChainCrossChainOrder_);
        vm.stopPrank();

        // claim should be successful
        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: compact_.commitments[0].amount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: compact_.commitments[0].amount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        BatchClaim memory claim = BatchClaim({
            allocatorData: '',
            sponsorSignature: '',
            sponsor: compact_.sponsor,
            nonce: compact_.nonce,
            expires: compact_.expires,
            witness: mandateHash,
            witnessTypestring: WITNESS_TYPESTRING_TRIBUNAL,
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        compactContract.batchClaim(claim);

        vm.assertEq(compactContract.balanceOf(user, usdcId), 0);
        vm.assertEq(usdc.balanceOf(filler), defaultAmount);
    }

    function test_successful_openFor() public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        (bytes32 mandateHash4,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHash4);
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ = _getGaslessCrossChainOrder();
        erc7683Allocator.openFor(gaslessCrossChainOrder_, '', '');
        vm.stopPrank();

        // claim should be successful
        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        (bytes32 mh,) = _hashMandate(mandate_);
        BatchClaim memory claim = BatchClaim({
            allocatorData: '',
            sponsorSignature: '',
            sponsor: compact_.sponsor,
            nonce: compact_.nonce,
            expires: compact_.expires,
            witness: mh,
            witnessTypestring: WITNESS_TYPESTRING_TRIBUNAL,
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        compactContract.batchClaim(claim);

        vm.assertEq(compactContract.balanceOf(user, usdcId), 0);
        vm.assertEq(usdc.balanceOf(filler), defaultAmount);
    }
}

contract ERC7683Allocator_isClaimAuthorized is MockAllocator {
    function test_failed_noClaimAllocated() public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        (bytes32 mandateHashA,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHashA);
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(compactContract.balanceOf(filler, usdcId), 0);

        vm.stopPrank();

        // we do NOT open the order or lock the tokens

        // isClaimAuthorized should be false, because we did not allocate the claim
        assertFalse(
            erc7683Allocator.isClaimAuthorized(
                claimHash,
                compact_.arbiter,
                compact_.sponsor,
                compact_.nonce,
                compact_.expires,
                defaultIdsAndAmounts,
                ''
            )
        );
    }

    function test_successful_open() public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        (bytes32 mandateHashC,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHashC);
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        erc7683Allocator.open(onChainCrossChainOrder_);
        vm.stopPrank();

        // claim should be successful
        (bytes32 witness,) = _hashMandate(mandate_);
        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        BatchClaim memory claim = BatchClaim({
            allocatorData: '',
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: witness,
            witnessTypestring: WITNESS_TYPESTRING_TRIBUNAL,
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        compactContract.batchClaim(claim);

        vm.assertEq(compactContract.balanceOf(user, usdcId), 0);
        vm.assertEq(usdc.balanceOf(filler), defaultAmount);
    }

    function test_successful_openFor() public {
        // Deposit tokens
        vm.startPrank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        (bytes32 mandateHashD,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHashD);
        compactContract.register(claimHash, COMPACT_TYPEHASH_WITH_MANDATE);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ = _getGaslessCrossChainOrder();
        erc7683Allocator.openFor(gaslessCrossChainOrder_, '', '');
        vm.stopPrank();

        // claim should be successful
        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        (bytes32 mh,) = _hashMandate(mandate_);
        BatchClaim memory claim = BatchClaim({
            allocatorData: '',
            sponsorSignature: '',
            sponsor: compact_.sponsor,
            nonce: compact_.nonce,
            expires: compact_.expires,
            witness: mh,
            witnessTypestring: WITNESS_TYPESTRING_TRIBUNAL,
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        compactContract.batchClaim(claim);

        vm.assertEq(compactContract.balanceOf(user, usdcId), 0);
        vm.assertEq(usdc.balanceOf(filler), defaultAmount);
    }
}

contract ERC7683Allocator_resolveFor is MockAllocator {
    function test_revert_InvalidOrderDataType() public {
        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ = _getGaslessCrossChainOrder();
        gaslessCrossChainOrder_.orderDataType = keccak256('false');
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector,
                gaslessCrossChainOrder_.orderDataType,
                ORDERDATA_GASLESS_TYPEHASH
            )
        );
        erc7683Allocator.resolveFor(gaslessCrossChainOrder_, '');
    }

    function test_revert_InvalidOriginSettler() public {
        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ = _getGaslessCrossChainOrder();
        gaslessCrossChainOrder_.originSettler = makeAddr('invalid');
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOriginSettler.selector,
                gaslessCrossChainOrder_.originSettler,
                address(erc7683Allocator)
            )
        );
        erc7683Allocator.resolveFor(gaslessCrossChainOrder_, '');
    }

    function test_revert_InvalidNonce() public {
        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ = _getGaslessCrossChainOrder();
        gaslessCrossChainOrder_.nonce = defaultNonce + 1;
        vm.expectRevert(
            abi.encodeWithSelector(IERC7683Allocator.InvalidNonce.selector, gaslessCrossChainOrder_.nonce, defaultNonce)
        );
        erc7683Allocator.resolveFor(gaslessCrossChainOrder_, '');
    }

    function test_resolve_successful() public {
        // WITH THE CURRENT ERC7683 DESIGN, THE SPONSOR SIGNATURE IS NOT PROVIDED TO THE RESOLVE FUNCTION
        // WHILE THE ResolvedCrossChainOrder WITHOUT THE SIGNATURE COULD STILL BE USED TO SIMULATE THE FILL,
        // ACTUALLY USING THIS DATA WOULD RESULT IN A LOSS OF THE REWARD TOKENS FOR THE FILLER.
        // THIS FEELS RISKY.
        // THE CURRENT ALTERNATIVE WOULD BE HAVE THE INPUT SIGNATURE BEING LEFT EMPTY AND INSTEAD BE PROVIDED IN THE THE orderData OF THE GaslessCrossChainOrderData.
        // THIS IS BOTH NOT IDEAL, SO CURRENTLY CHECKING FOR A SOLUTION.

        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ = _getGaslessCrossChainOrder();
        IOriginSettler.Output[] memory maxSpent = new IOriginSettler.Output[](1);
        IOriginSettler.Output[] memory minReceived = new IOriginSettler.Output[](1);
        IOriginSettler.FillInstruction[] memory fillInstructions = new IOriginSettler.FillInstruction[](1);
        maxSpent[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(defaultOutputToken))),
            amount: type(uint256).max,
            recipient: bytes32(uint256(uint160(user))),
            chainId: defaultOutputChainId
        });
        minReceived[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(address(usdc)))),
            amount: defaultAmount,
            recipient: '',
            chainId: block.chainid
        });
        BatchCompact memory compactExpected = _getCompact();
        compactExpected.nonce = defaultNonce;
        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: compactExpected,
            sponsorSignature: '', // sponsorSignature, // THE SIGNATURE MUST BE ADDED MANUALLY BY THE FILLER WITH THE CURRENT SYSTEM, BEFORE FILLING THE ORDER ON THE TARGET CHAIN
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, _getMandate().fills[0], adjuster, _buildFillHashes(_getMandate()))
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(_getClaimExpiration()),
            fillDeadline: uint32(_getFillExpiration()),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        IOriginSettler.ResolvedCrossChainOrder memory resolved =
            erc7683Allocator.resolveFor(gaslessCrossChainOrder_, '');
        assertEq(resolved.user, resolvedCrossChainOrder.user);
        assertEq(resolved.originChainId, resolvedCrossChainOrder.originChainId);
        assertEq(resolved.openDeadline, resolvedCrossChainOrder.openDeadline);
        assertEq(resolved.fillDeadline, resolvedCrossChainOrder.fillDeadline);
        assertEq(resolved.orderId, resolvedCrossChainOrder.orderId);
        assertEq(resolved.maxSpent.length, resolvedCrossChainOrder.maxSpent.length);
        assertEq(resolved.maxSpent[0].token, resolvedCrossChainOrder.maxSpent[0].token);
        assertEq(resolved.maxSpent[0].amount, resolvedCrossChainOrder.maxSpent[0].amount);
        assertEq(resolved.maxSpent[0].recipient, resolvedCrossChainOrder.maxSpent[0].recipient);
        assertEq(resolved.maxSpent[0].chainId, resolvedCrossChainOrder.maxSpent[0].chainId);
        assertEq(resolved.minReceived.length, resolvedCrossChainOrder.minReceived.length);
        assertEq(resolved.minReceived[0].token, resolvedCrossChainOrder.minReceived[0].token);
        assertEq(resolved.minReceived[0].amount, resolvedCrossChainOrder.minReceived[0].amount);
        assertEq(resolved.minReceived[0].recipient, resolvedCrossChainOrder.minReceived[0].recipient);
        assertEq(resolved.minReceived[0].chainId, resolvedCrossChainOrder.minReceived[0].chainId);
        assertEq(resolved.fillInstructions.length, resolvedCrossChainOrder.fillInstructions.length);
        assertEq(
            resolved.fillInstructions[0].destinationChainId,
            resolvedCrossChainOrder.fillInstructions[0].destinationChainId
        );
        assertEq(
            resolved.fillInstructions[0].destinationSettler,
            resolvedCrossChainOrder.fillInstructions[0].destinationSettler
        );
        assertEq(resolved.fillInstructions[0].originData, resolvedCrossChainOrder.fillInstructions[0].originData);
    }
}

contract ERC7683Allocator_resolve is MockAllocator {
    function test_revert_InvalidOrderDataType() public {
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        onChainCrossChainOrder_.orderDataType = keccak256('false');
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector,
                onChainCrossChainOrder_.orderDataType,
                ORDERDATA_ONCHAIN_TYPEHASH
            )
        );
        erc7683Allocator.resolve(onChainCrossChainOrder_);
    }

    function test_resolve_successful() public {
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        IOriginSettler.Output[] memory maxSpent = new IOriginSettler.Output[](1);
        IOriginSettler.Output[] memory minReceived = new IOriginSettler.Output[](1);
        IOriginSettler.FillInstruction[] memory fillInstructions = new IOriginSettler.FillInstruction[](1);
        maxSpent[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(defaultOutputToken))),
            amount: type(uint256).max,
            recipient: bytes32(uint256(uint160(user))),
            chainId: defaultOutputChainId
        });
        minReceived[0] = IOriginSettler.Output({
            token: bytes32(uint256(uint160(address(usdc)))),
            amount: defaultAmount,
            recipient: '',
            chainId: block.chainid
        });
        BatchCompact memory compactExpected = _getCompact();
        compactExpected.nonce = defaultNonce;
        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: compactExpected,
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, _getMandate().fills[0], adjuster, _buildFillHashes(_getMandate()))
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(_getClaimExpiration()),
            fillDeadline: uint32(_getFillExpiration()),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        vm.prank(user);
        IOriginSettler.ResolvedCrossChainOrder memory resolved = erc7683Allocator.resolve(onChainCrossChainOrder_);
        assertEq(resolved.user, resolvedCrossChainOrder.user);
        assertEq(resolved.originChainId, resolvedCrossChainOrder.originChainId);
        assertEq(resolved.openDeadline, resolvedCrossChainOrder.openDeadline);
        assertEq(resolved.fillDeadline, resolvedCrossChainOrder.fillDeadline);
        assertEq(resolved.orderId, resolvedCrossChainOrder.orderId);
        assertEq(resolved.maxSpent.length, resolvedCrossChainOrder.maxSpent.length);
        assertEq(resolved.maxSpent[0].token, resolvedCrossChainOrder.maxSpent[0].token);
        assertEq(resolved.maxSpent[0].amount, resolvedCrossChainOrder.maxSpent[0].amount);
        assertEq(resolved.maxSpent[0].recipient, resolvedCrossChainOrder.maxSpent[0].recipient);
        assertEq(resolved.maxSpent[0].chainId, resolvedCrossChainOrder.maxSpent[0].chainId);
        assertEq(resolved.minReceived.length, resolvedCrossChainOrder.minReceived.length);
        assertEq(resolved.minReceived[0].token, resolvedCrossChainOrder.minReceived[0].token);
        assertEq(resolved.minReceived[0].amount, resolvedCrossChainOrder.minReceived[0].amount);
        assertEq(resolved.minReceived[0].recipient, resolvedCrossChainOrder.minReceived[0].recipient);
        assertEq(resolved.minReceived[0].chainId, resolvedCrossChainOrder.minReceived[0].chainId);
        assertEq(resolved.fillInstructions.length, resolvedCrossChainOrder.fillInstructions.length);
        assertEq(
            resolved.fillInstructions[0].destinationChainId,
            resolvedCrossChainOrder.fillInstructions[0].destinationChainId
        );
        assertEq(
            resolved.fillInstructions[0].destinationSettler,
            resolvedCrossChainOrder.fillInstructions[0].destinationSettler
        );
        assertEq(resolved.fillInstructions[0].originData, resolvedCrossChainOrder.fillInstructions[0].originData);
    }
}

contract ERC7683Allocator_getCompactWitnessTypeString is MockAllocator {
    function test_getCompactWitnessTypeString() public view {
        bytes memory s = bytes(erc7683Allocator.getCompactWitnessTypeString());
        assertTrue(s.length > 0);
    }
}

// Removed: nonce check suite not applicable to the new interface

contract ERC7683Allocator_createFillerData is MockAllocator {
    function test_createFillerData(address claimant) public view {
        bytes memory fillerData = erc7683Allocator.createFillerData(claimant);
        assertEq(abi.decode(fillerData, (address)), claimant);
    }
}

// ------------------------------------------------------------
// Tests for _openAndRegister path via openFor with deposit true
// ------------------------------------------------------------
contract ERC7683Allocator_openForDeposit is MockAllocator {
    function test_openFor_withDeposit_success_emptyInputs(address relayer) public {
        vm.assume(relayer != address(0));
        assertEq(ERC6909(address(compactContract)).balanceOf(user, usdcId), 0);

        usdc.mint(address(erc7683Allocator), defaultAmount);

        BatchCompact memory compact_ = _getCompact();
        compact_.commitments[0].amount = 0;

        Mandate memory mandate_ = _getMandate();
        IOriginSettler.GaslessCrossChainOrder memory order_ = _getGaslessCrossChainOrder(compact_, mandate_, true);

        vm.prank(relayer);
        erc7683Allocator.openFor(order_, '', '');

        assertEq(ERC6909(address(compactContract)).balanceOf(user, usdcId), defaultAmount);

        compact_.nonce = _composeNonceUint(relayer, 1);
        compact_.commitments[0].amount = defaultAmount;

        (bytes32 mandateHash,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHash);
        assertTrue(compactContract.isRegistered(user, claimHash, COMPACT_TYPEHASH_WITH_MANDATE));
    }

    function test_openFor_withDeposit_success(address relayer) public {
        vm.assume(relayer != address(0));

        assertEq(ERC6909(address(compactContract)).balanceOf(user, usdcId), 0);

        uint256 amount = defaultAmount;
        usdc.mint(address(erc7683Allocator), amount);

        BatchCompact memory compact_ = _getCompact();
        compact_.nonce = _composeNonceUint(relayer, 1);

        Mandate memory mandate_ = _getMandate();
        IOriginSettler.GaslessCrossChainOrder memory order_ = _getGaslessCrossChainOrder(compact_, mandate_, true);

        vm.prank(relayer);
        erc7683Allocator.openFor(order_, '', '');

        // Check Balance
        assertEq(ERC6909(address(compactContract)).balanceOf(user, usdcId), amount);

        (bytes32 mandateHash,) = _hashMandate(mandate_);
        bytes32 claimHash = _deriveClaimHash(compact_, mandateHash);
        assertTrue(compactContract.isRegistered(user, claimHash, COMPACT_TYPEHASH_WITH_MANDATE));
    }
}
