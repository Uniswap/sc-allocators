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

import {HybridERC7683} from 'src/allocators/HybridERC7683.sol';

import {Fill, Mandate, RecipientCallback} from '@uniswap/tribunal/types/TribunalStructs.sol';
import {ERC7683AllocatorLib as ERC7683AL} from 'src/allocators/lib/ERC7683AllocatorLib.sol';

import {Tribunal} from '@uniswap/tribunal/Tribunal.sol';
import {
    COMPACT_TYPEHASH_WITH_MANDATE,
    MANDATE_BATCH_COMPACT_TYPEHASH,
    MANDATE_FILL_TYPEHASH,
    MANDATE_RECIPIENT_CALLBACK_TYPEHASH,
    MANDATE_TYPEHASH,
    WITNESS_TYPESTRING as WITNESS_TYPESTRING_TRIBUNAL
} from '@uniswap/tribunal/types/TribunalTypeHashes.sol';
import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';

import {IERC7683Allocator} from 'src/interfaces/IERC7683Allocator.sol';
import {IHybridAllocator} from 'src/interfaces/IHybridAllocator.sol';

import {ERC20Mock} from 'src/test/ERC20Mock.sol';
import {
    CompactData,
    GaslessCrossChainOrderData,
    MocksSetup,
    OnChainCrossChainOrderData
} from 'test/util/ERC7683TestHelper.sol';

contract MockAllocator is GaslessCrossChainOrderData, OnChainCrossChainOrderData {
    HybridERC7683 hybridERC7683Allocator;
    address signer;
    uint256 signerPK;

    function setUp() public virtual override(GaslessCrossChainOrderData, OnChainCrossChainOrderData) {
        (signer, signerPK) = makeAddrAndKey('signer');
        TheCompact compactContract_ = new TheCompact();
        hybridERC7683Allocator = new HybridERC7683(address(compactContract_), signer);
        _setUp(address(hybridERC7683Allocator), compactContract_, 1 /* defaultNonce */ );
        super.setUp();
    }
}

contract HybridERC7683_open is MockAllocator {
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
        hybridERC7683Allocator.open(onChainCrossChainOrder_);
    }

    function test_revert_ManipulatedOrderData() public {
        // Deposit tokens
        vm.prank(user);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        (bytes32 mandateHash,) = _hashMandate(_getMandate());

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
        (bool success, bytes memory returnData) = address(hybridERC7683Allocator).call(callData);
        assertEq(success, false);
        assertEq(returnData.length, 0);
    }

    function test_orderDataType() public view {
        assertEq(ERC7683AL.ORDERDATA_GASLESS_TYPEHASH, ORDERDATA_GASLESS_TYPEHASH);
    }

    function test_successful() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();
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
            amount: defaultMinimumAmount,
            recipient: bytes32(0),
            chainId: block.chainid
        });
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: compact_,
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, mandate_.fills[0], adjuster, _buildFillHashes(mandate_))
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.fills[0].expires),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        vm.prank(user);
        vm.expectEmit(true, false, false, true, address(hybridERC7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        hybridERC7683Allocator.open(onChainCrossChainOrder_);
    }
}

contract HybridERC7683_openFor is MockAllocator {
    function test_revert_InvalidOrderDataType() public {
        // Order data type is invalid
        bytes32 falseOrderDataType = keccak256('false');

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector, falseOrderDataType, ORDERDATA_GASLESS_TYPEHASH
            )
        );

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        (IOriginSettler.GaslessCrossChainOrder memory falseGaslessCrossChainOrder) =
            _getGaslessCrossChainOrder(compact_, mandate_, true);
        bytes memory signature = _hashAndSign(compact_, mandate_, address(compactContract), signerPK);

        falseGaslessCrossChainOrder.orderDataType = falseOrderDataType;
        hybridERC7683Allocator.openFor(falseGaslessCrossChainOrder, signature, '');
    }

    function test_orderDataType() public view {
        assertEq(ERC7683AL.ORDERDATA_ONCHAIN_TYPEHASH, ORDERDATA_ONCHAIN_TYPEHASH);
    }

    function test_successful_userHimself() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

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
            amount: defaultMinimumAmount,
            recipient: bytes32(0),
            chainId: block.chainid
        });

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: compact_,
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, mandate_.fills[0], adjuster, _buildFillHashes(mandate_))
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.fills[0].expires),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });

        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_) =
            _getGaslessCrossChainOrder(compact_, mandate_, true);

        vm.prank(user);
        vm.expectEmit(true, false, false, true, address(hybridERC7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        hybridERC7683Allocator.openFor(gaslessCrossChainOrder_, '', '');
    }

    function test_successful_relayed() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_) =
            _getGaslessCrossChainOrder(compact_, mandate_, true);

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
            amount: defaultMinimumAmount,
            recipient: bytes32(0),
            chainId: block.chainid
        });
        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: compact_,
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, mandate_.fills[0], adjuster, _buildFillHashes(mandate_))
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.fills[0].expires),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        vm.prank(makeAddr('filler'));
        vm.expectEmit(true, false, false, true, address(hybridERC7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        hybridERC7683Allocator.openFor(gaslessCrossChainOrder_, '', '');
    }
}

contract HybridERC7683_authorizeClaim is MockAllocator {
    function test_revert_InvalidCaller() public {
        vm.expectRevert(
            abi.encodeWithSelector(IHybridAllocator.InvalidCaller.selector, address(this), address(compactContract))
        );
        hybridERC7683Allocator.authorizeClaim(bytes32(0), address(0), address(0), 0, 0, new uint256[2][](0), bytes(''));
    }

    function test_successful_onChainClaim() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        vm.prank(user);
        hybridERC7683Allocator.open(onChainCrossChainOrder_);

        address filler = makeAddr('filler');

        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        {
            Component[] memory components = new Component[](1);
            components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
            BatchClaimComponent memory batchClaimComponent =
                BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
            batchClaimComponents[0] = batchClaimComponent;
        }
        (bytes32 mandateHash,) = _hashMandate(mandate_);
        BatchClaim memory claim = BatchClaim({
            allocatorData: '',
            sponsorSignature: '',
            sponsor: user,
            nonce: compact_.nonce,
            expires: compact_.expires,
            witness: mandateHash,
            witnessTypestring: WITNESS_TYPESTRING_TRIBUNAL,
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        compactContract.batchClaim(claim);

        assertEq(compactContract.balanceOf(user, usdcId), 0);
        assertEq(usdc.balanceOf(filler), defaultAmount);
    }

    function test_successful_signatureClaim() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_) =
            _getGaslessCrossChainOrder(compact_, mandate_, true);
        gaslessCrossChainOrder_ = _manipulateDeposit(gaslessCrossChainOrder_, true);
        bytes memory sponsorSignature = _hashAndSign(compact_, mandate_, address(compactContract), signerPK);

        (bytes32 mandateHash,) = _hashMandate(mandate_);

        vm.prank(user);
        hybridERC7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');

        address filler = makeAddr('filler');

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
            witness: mandateHash,
            witnessTypestring: WITNESS_TYPESTRING_TRIBUNAL,
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        compactContract.batchClaim(claim);

        assertEq(compactContract.balanceOf(user, usdcId), 0);
        assertEq(usdc.balanceOf(filler), defaultAmount);
    }

    function test_successful_signatureOnly() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.approve(address(compactContract), defaultAmount);

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        bytes32 claimHash = _deriveClaimHash(compact_, mandate_);

        vm.prank(user);
        compactContract.depositERC20AndRegister(
            address(usdc), usdcLockTag, defaultAmount, claimHash, COMPACT_TYPEHASH_WITH_MANDATE
        );

        address filler = makeAddr('filler');

        // Sign with signer
        bytes memory allocatorSignature = _hashAndSign(compact_, mandate_, address(compactContract), signerPK);

        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        {
            Component[] memory components = new Component[](1);
            components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
            BatchClaimComponent memory batchClaimComponent =
                BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
            batchClaimComponents[0] = batchClaimComponent;
        }
        (bytes32 mandateHash,) = _hashMandate(mandate_);
        BatchClaim memory claim = BatchClaim({
            allocatorData: allocatorSignature,
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: mandateHash,
            witnessTypestring: WITNESS_TYPESTRING_TRIBUNAL,
            claims: batchClaimComponents
        });

        vm.prank(arbiter);
        compactContract.batchClaim(claim);
    }

    function test_revert_InvalidSignature() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.approve(address(compactContract), defaultAmount);

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        bytes32 claimHash = _deriveClaimHash(compact_, mandate_);

        vm.prank(user);
        compactContract.depositERC20AndRegister(
            address(usdc), usdcLockTag, defaultAmount, claimHash, COMPACT_TYPEHASH_WITH_MANDATE
        );

        address filler = makeAddr('filler');

        // Sign with wrong signer
        bytes memory allocatorSignature = _hashAndSign(compact_, mandate_, address(compactContract), attackerPK);

        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        {
            Component[] memory components = new Component[](1);
            components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
            BatchClaimComponent memory batchClaimComponent =
                BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
            batchClaimComponents[0] = batchClaimComponent;
        }
        (bytes32 mandateHash,) = _hashMandate(mandate_);
        BatchClaim memory claim = BatchClaim({
            allocatorData: allocatorSignature, // signed by attacker
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: mandateHash,
            witnessTypestring: WITNESS_TYPESTRING_TRIBUNAL,
            claims: batchClaimComponents
        });

        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSignature.selector));
        compactContract.batchClaim(claim);
    }

    function test_revert_InvalidSignature_length() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.approve(address(compactContract), defaultAmount);

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        bytes32 claimHash = _deriveClaimHash(compact_, mandate_);

        vm.prank(user);
        compactContract.depositERC20AndRegister(
            address(usdc), usdcLockTag, defaultAmount, claimHash, COMPACT_TYPEHASH_WITH_MANDATE
        );

        address filler = makeAddr('filler');

        // Sign with signer and create the wrong length
        bytes memory allocatorSignature =
            abi.encodePacked(_hashAndSign(compact_, mandate_, address(compactContract), signerPK), uint8(0));

        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        {
            Component[] memory components = new Component[](1);
            components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
            BatchClaimComponent memory batchClaimComponent =
                BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
            batchClaimComponents[0] = batchClaimComponent;
        }
        (bytes32 mandateHash,) = _hashMandate(mandate_);
        BatchClaim memory claim = BatchClaim({
            allocatorData: allocatorSignature, // allocator signature with a length of 66 bytes
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: mandateHash,
            witnessTypestring: WITNESS_TYPESTRING_TRIBUNAL,
            claims: batchClaimComponents
        });

        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSignature.selector));
        compactContract.batchClaim(claim);
    }
}

contract HybridERC7683_resolveFor is MockAllocator {
    function test_revert_InvalidOrderDataType() public {
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_) =
            _getGaslessCrossChainOrder(compact_, mandate_, true);
        bytes32 falseOrderDataType = keccak256('false');
        gaslessCrossChainOrder_.orderDataType = falseOrderDataType;
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector, falseOrderDataType, ORDERDATA_GASLESS_TYPEHASH
            )
        );
        hybridERC7683Allocator.resolveFor(gaslessCrossChainOrder_, '');
    }

    function test_resolveFor_successful() public {
        // Provide tokens for allocation so allocator holds funds
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

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
            amount: defaultMinimumAmount,
            recipient: bytes32(0),
            chainId: block.chainid
        });

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: compact_,
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, mandate_.fills[0], adjuster, _buildFillHashes(mandate_))
        });

        IOriginSettler.ResolvedCrossChainOrder memory expected = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.fills[0].expires),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });

        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ =
            _getGaslessCrossChainOrder(compact_, mandate_, true);

        vm.prank(user);
        IOriginSettler.ResolvedCrossChainOrder memory resolved =
            hybridERC7683Allocator.resolveFor(gaslessCrossChainOrder_, '');
        assertEq(resolved.user, expected.user);
        assertEq(resolved.originChainId, expected.originChainId);
        assertEq(resolved.openDeadline, expected.openDeadline);
        assertEq(resolved.fillDeadline, expected.fillDeadline);
        assertEq(resolved.orderId, expected.orderId);
        assertEq(resolved.maxSpent.length, expected.maxSpent.length);
        assertEq(resolved.maxSpent[0].token, expected.maxSpent[0].token);
        assertEq(resolved.maxSpent[0].amount, expected.maxSpent[0].amount);
        assertEq(resolved.maxSpent[0].recipient, expected.maxSpent[0].recipient);
        assertEq(resolved.maxSpent[0].chainId, expected.maxSpent[0].chainId);
        assertEq(resolved.minReceived.length, expected.minReceived.length);
        assertEq(resolved.minReceived[0].token, expected.minReceived[0].token);
        assertEq(resolved.minReceived[0].amount, expected.minReceived[0].amount);
        assertEq(resolved.minReceived[0].recipient, expected.minReceived[0].recipient);
        assertEq(resolved.minReceived[0].chainId, expected.minReceived[0].chainId);
        assertEq(resolved.fillInstructions.length, expected.fillInstructions.length);
        assertEq(resolved.fillInstructions[0].destinationChainId, expected.fillInstructions[0].destinationChainId);
        assertEq(resolved.fillInstructions[0].destinationSettler, expected.fillInstructions[0].destinationSettler);
        assertEq(resolved.fillInstructions[0].originData, expected.fillInstructions[0].originData);
    }
}

contract HybridERC7683_resolve is MockAllocator {
    function test_revert_InvalidOrderDataType() public {
        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();
        onChainCrossChainOrder_.orderDataType = keccak256('false');
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector,
                onChainCrossChainOrder_.orderDataType,
                ORDERDATA_ONCHAIN_TYPEHASH
            )
        );
        hybridERC7683Allocator.resolve(onChainCrossChainOrder_);
    }

    function test_resolve_successful() public {
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
            amount: defaultMinimumAmount,
            recipient: bytes32(0),
            chainId: block.chainid
        });
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        Tribunal.BatchClaim memory claim = Tribunal.BatchClaim({
            chainId: block.chainid,
            compact: compact_,
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, mandate_.fills[0], adjuster, _buildFillHashes(mandate_))
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.fills[0].expires),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ =
            _getOnChainCrossChainOrder(compact_, mandate_);
        vm.prank(user);
        IOriginSettler.ResolvedCrossChainOrder memory resolved = hybridERC7683Allocator.resolve(onChainCrossChainOrder_);
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

contract HybridERC7683_hybridAllocatorInheritance is MockAllocator {
    function test_inheritsHybridAllocatorFunctionality() public view {
        // Test that it properly inherits from HybridAllocator
        assertEq(hybridERC7683Allocator.nonces(), 0);
        assertEq(hybridERC7683Allocator.signerCount(), 1);
        assertTrue(hybridERC7683Allocator.signers(signer));
        assertEq(hybridERC7683Allocator.ALLOCATOR_ID(), _toAllocatorId(address(hybridERC7683Allocator)));
    }

    function test_allocateAndRegister() public {
        uint256[2][] memory idsAndAmounts = new uint256[2][](1);
        idsAndAmounts[0][0] = usdcId;
        idsAndAmounts[0][1] = defaultAmount;

        // Provide tokens
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

        (bytes32 witness,) = _hashMandate(_getMandate());

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = hybridERC7683Allocator
            .allocateAndRegister(
            user, idsAndAmounts, arbiter, _getClaimExpiration(), COMPACT_TYPEHASH_WITH_MANDATE, witness
        );

        assertTrue(compactContract.isRegistered(user, claimHash, COMPACT_TYPEHASH_WITH_MANDATE));
        assertTrue(
            hybridERC7683Allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), '')
        );
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(usdc.balanceOf(address(compactContract)), defaultAmount);
        assertEq(compactContract.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, 1);
    }
}
