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

import {BATCH_COMPACT_WITNESS_TYPEHASH, MANDATE_TYPEHASH} from 'src/allocators/lib/TypeHashes.sol';
import {BatchClaim as TribunalClaim, Mandate} from 'src/allocators/types/TribunalStructs.sol';
import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';
import {IHybridAllocator} from 'src/interfaces/IHybridAllocator.sol';
import {IHybridERC7683} from 'src/interfaces/IHybridERC7683.sol';

import {ERC20Mock} from 'src/test/ERC20Mock.sol';

abstract contract MocksSetup is Test, TestHelper {
    address user;
    uint256 userPK;
    address attacker;
    uint256 attackerPK;
    address arbiter;
    address tribunal;
    address signer;
    uint256 signerPK;
    ERC20Mock usdc;
    TheCompact compactContract;
    HybridERC7683 hybridERC7683Allocator;
    bytes12 usdcLockTag;
    uint256 usdcId;

    ResetPeriod defaultResetPeriod = ResetPeriod.OneMinute;
    Scope defaultScope = Scope.Multichain;
    uint256 defaultResetPeriodTimestamp = 60;
    uint256 defaultAmount = 1000;
    uint256 defaultNonce;
    uint256 defaultOutputChainId = 130;
    address defaultOutputToken = makeAddr('outputToken');
    uint256 defaultMinimumAmount = 1000;
    uint256 defaultBaselinePriorityFee = 0;
    uint256 defaultScalingFactor = 0;
    uint256[] defaultDecayCurve = new uint256[](0);
    bytes32 defaultSalt = bytes32(0x0000000000000000000000000000000000000000000000000000000000000007);
    uint200 defaultTargetBlock = 100;
    uint56 defaultMaximumBlocksAfterTarget = 10;

    uint256[2][] defaultIdsAndAmounts = new uint256[2][](1);
    Lock[] defaultCommitments;

    bytes32 ORDERDATA_GASLESS_TYPEHASH;
    bytes32 ORDERDATA_ONCHAIN_TYPEHASH;

    function setUp() public virtual {
        (user, userPK) = makeAddrAndKey('user');
        (attacker, attackerPK) = makeAddrAndKey('attacker');
        (signer, signerPK) = makeAddrAndKey('signer');
        arbiter = makeAddr('arbiter');
        tribunal = makeAddr('tribunal');
        usdc = new ERC20Mock('USDC', 'USDC');
        compactContract = new TheCompact();
        hybridERC7683Allocator = new HybridERC7683(address(compactContract), signer);

        // Mint tokens to user
        deal(user, 1 ether);
        usdc.mint(user, 1 ether);

        usdcLockTag = _toLockTag(address(hybridERC7683Allocator), defaultScope, defaultResetPeriod);
        usdcId = _toId(defaultScope, defaultResetPeriod, address(hybridERC7683Allocator), address(usdc));
        defaultNonce = 1;

        ORDERDATA_GASLESS_TYPEHASH = hybridERC7683Allocator.ORDERDATA_GASLESS_TYPEHASH();
        ORDERDATA_ONCHAIN_TYPEHASH = hybridERC7683Allocator.ORDERDATA_ONCHAIN_TYPEHASH();
    }
}

abstract contract CreateHash is MocksSetup {
    struct Allocator {
        bytes32 hash;
    }

    // stringified types
    string EIP712_DOMAIN_TYPE = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'; // Hashed inside the function
    // EIP712 domain type
    string name = 'The Compact';
    string version = '1';

    string compactWitnessTypeString =
        'Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,bytes12 lockTag,address token,uint256 amount,Mandate mandate)Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)';
    string batchCompactWitnessTypeString =
        'BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)';
    string mandateTypeString =
        'Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)';
    string witnessTypeString =
        'uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt';

    function _hashCompact(BatchCompact memory data, Mandate memory mandate, address verifyingContract)
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 compactHash = _hashCompact(data, mandate);
        // hash typed data
        digest = keccak256(
            abi.encodePacked(
                '\x19\x01', // backslash is needed to escape the character
                _domainSeparator(verifyingContract),
                compactHash
            )
        );
    }

    function _hashCompact(BatchCompact memory data, Mandate memory mandate)
        internal
        view
        returns (bytes32 compactHash)
    {
        bytes32 mandateHash = _hashMandate(mandate);
        compactHash = keccak256(
            abi.encode(
                keccak256(bytes(batchCompactWitnessTypeString)),
                data.arbiter,
                data.sponsor,
                data.nonce,
                data.expires,
                _hashCommitments(data.commitments),
                mandateHash
            )
        );
    }

    function _hashMandate(Mandate memory mandate) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(bytes(mandateTypeString)),
                defaultOutputChainId,
                tribunal,
                mandate.recipient,
                mandate.expires,
                mandate.token,
                mandate.minimumAmount,
                mandate.baselinePriorityFee,
                mandate.scalingFactor,
                keccak256(abi.encodePacked(mandate.decayCurve)),
                mandate.salt
            )
        );
    }

    function _hashCommitments(Lock[] memory commitments) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            hashes[i] = keccak256(
                abi.encode(LOCK_TYPEHASH, commitments[i].lockTag, commitments[i].token, commitments[i].amount)
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function _getTypeHash() internal view returns (bytes32) {
        return keccak256(bytes(batchCompactWitnessTypeString));
    }

    function _domainSeparator(address verifyingContract) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(bytes(EIP712_DOMAIN_TYPE)),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                verifyingContract
            )
        );
    }

    function _signMessage(bytes32 hash_, uint256 signerPK_) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPK_, hash_);
        return abi.encodePacked(r, s, v);
    }

    function _hashAndSign(BatchCompact memory data, Mandate memory mandate, address verifyingContract, uint256 signerPK)
        internal
        view
        returns (bytes memory)
    {
        bytes32 hash = _hashCompact(data, mandate, verifyingContract);
        bytes memory signature = _signMessage(hash, signerPK);
        return signature;
    }

    function _createWitnessHash(Mandate memory mandate) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                MANDATE_TYPEHASH,
                defaultOutputChainId,
                tribunal,
                mandate.recipient,
                mandate.expires,
                mandate.token,
                mandate.minimumAmount,
                mandate.baselinePriorityFee,
                mandate.scalingFactor,
                keccak256(abi.encodePacked(mandate.decayCurve)),
                mandate.salt
            )
        );
    }

    function _allocatorData(uint200 targetBlock_, uint56 maximumBlocksAfterTarget_) internal pure returns (bytes32) {
        return bytes32(uint256(targetBlock_) << 57 | uint256(maximumBlocksAfterTarget_) << 1);
    }
}

abstract contract CompactData is CreateHash {
    BatchCompact internal compact;
    Mandate internal mandate;

    function setUp() public virtual override {
        super.setUp();

        defaultIdsAndAmounts[0][0] = usdcId;
        defaultIdsAndAmounts[0][1] = defaultAmount;

        defaultCommitments.push(Lock({lockTag: usdcLockTag, token: address(usdc), amount: defaultAmount}));

        compact.arbiter = arbiter;
        compact.sponsor = user;
        compact.nonce = defaultNonce;
        compact.expires = _getClaimExpiration();
        compact.commitments = defaultCommitments;

        mandate.recipient = user;
        mandate.expires = _getFillExpiration();
        mandate.token = defaultOutputToken;
        mandate.minimumAmount = defaultMinimumAmount;
        mandate.baselinePriorityFee = defaultBaselinePriorityFee;
        mandate.scalingFactor = defaultScalingFactor;
        mandate.decayCurve = defaultDecayCurve;
        mandate.salt = defaultSalt;
    }

    function _getCompact() internal returns (BatchCompact memory) {
        compact.expires = _getClaimExpiration();
        return compact;
    }

    function _getMandate() internal returns (Mandate memory) {
        mandate.expires = _getFillExpiration();
        return mandate;
    }

    function _getFillExpiration() internal view returns (uint256) {
        return vm.getBlockTimestamp() + defaultResetPeriodTimestamp - 1;
    }

    function _getClaimExpiration() internal view returns (uint256) {
        return vm.getBlockTimestamp() + defaultResetPeriodTimestamp;
    }
}

abstract contract GaslessCrossChainOrderData is CompactData {
    IOriginSettler.GaslessCrossChainOrder private gaslessCrossChainOrder;

    function setUp() public virtual override {
        super.setUp();

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        gaslessCrossChainOrder.originSettler = address(hybridERC7683Allocator);
        gaslessCrossChainOrder.user = compact_.sponsor;
        gaslessCrossChainOrder.nonce = compact_.nonce;
        gaslessCrossChainOrder.originChainId = block.chainid;
        gaslessCrossChainOrder.openDeadline = uint32(compact_.expires);
        gaslessCrossChainOrder.fillDeadline = uint32(mandate_.expires);
        gaslessCrossChainOrder.orderDataType = hybridERC7683Allocator.ORDERDATA_GASLESS_TYPEHASH();
        gaslessCrossChainOrder.orderData = abi.encode(
            IHybridERC7683.OrderDataGasless({
                order: IHybridERC7683.Order({
                    arbiter: compact_.arbiter,
                    idsAndAmounts: defaultIdsAndAmounts,
                    chainId: defaultOutputChainId,
                    tribunal: tribunal,
                    recipient: mandate_.recipient,
                    settlementToken: mandate_.token,
                    minimumAmount: mandate_.minimumAmount,
                    baselinePriorityFee: mandate_.baselinePriorityFee,
                    scalingFactor: mandate_.scalingFactor,
                    decayCurve: mandate_.decayCurve,
                    salt: mandate_.salt,
                    qualification: _allocatorData(defaultTargetBlock, defaultMaximumBlocksAfterTarget)
                })
            })
        );
    }

    function _getGaslessCrossChainOrder(
        address allocator,
        BatchCompact memory compact_,
        Mandate memory mandate_,
        uint256 chainId_,
        bytes32 orderDataGaslessTypeHash_,
        address verifyingContract,
        uint256 signerPK
    ) internal view returns (IOriginSettler.GaslessCrossChainOrder memory, bytes memory signature) {
        IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_ = IOriginSettler.GaslessCrossChainOrder({
            originSettler: allocator,
            user: compact_.sponsor,
            nonce: compact_.nonce,
            originChainId: chainId_,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.expires),
            orderDataType: orderDataGaslessTypeHash_,
            orderData: abi.encode(
                IHybridERC7683.OrderDataGasless({
                    order: IHybridERC7683.Order({
                        arbiter: compact_.arbiter,
                        idsAndAmounts: defaultIdsAndAmounts,
                        chainId: defaultOutputChainId,
                        tribunal: tribunal,
                        recipient: mandate_.recipient,
                        settlementToken: mandate_.token,
                        minimumAmount: mandate_.minimumAmount,
                        baselinePriorityFee: mandate_.baselinePriorityFee,
                        scalingFactor: mandate_.scalingFactor,
                        decayCurve: mandate_.decayCurve,
                        salt: mandate_.salt,
                        qualification: _allocatorData(defaultTargetBlock, defaultMaximumBlocksAfterTarget)
                    })
                })
            )
        });

        (bytes memory signature_) = _hashAndSign(compact_, mandate_, verifyingContract, signerPK);
        return (gaslessCrossChainOrder_, signature_);
    }

    function _getGaslessCrossChainOrder()
        internal
        returns (IOriginSettler.GaslessCrossChainOrder memory, bytes memory signature)
    {
        (bytes memory signature_) = _hashAndSign(_getCompact(), _getMandate(), address(compactContract), userPK);
        return (gaslessCrossChainOrder, signature_);
    }
}

abstract contract OnChainCrossChainOrderData is CompactData {
    IOriginSettler.OnchainCrossChainOrder private onchainCrossChainOrder;

    function setUp() public virtual override {
        super.setUp();

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        onchainCrossChainOrder.fillDeadline = uint32(mandate_.expires);
        onchainCrossChainOrder.orderDataType = hybridERC7683Allocator.ORDERDATA_ONCHAIN_TYPEHASH();
        onchainCrossChainOrder.orderData = abi.encode(
            IHybridERC7683.OrderDataOnChain({
                order: IHybridERC7683.Order({
                    arbiter: compact_.arbiter,
                    idsAndAmounts: defaultIdsAndAmounts,
                    chainId: defaultOutputChainId,
                    tribunal: tribunal,
                    recipient: mandate_.recipient,
                    settlementToken: mandate_.token,
                    minimumAmount: mandate_.minimumAmount,
                    baselinePriorityFee: mandate_.baselinePriorityFee,
                    scalingFactor: mandate_.scalingFactor,
                    decayCurve: mandate_.decayCurve,
                    salt: mandate_.salt,
                    qualification: _allocatorData(defaultTargetBlock, defaultMaximumBlocksAfterTarget)
                }),
                expires: compact_.expires
            })
        );
    }

    function _getOnChainCrossChainOrder() internal view returns (IOriginSettler.OnchainCrossChainOrder memory) {
        return onchainCrossChainOrder;
    }

    function _getOnChainCrossChainOrder(BatchCompact memory compact_, Mandate memory mandate_, bytes32 orderDataType_)
        internal
        view
        returns (IOriginSettler.OnchainCrossChainOrder memory)
    {
        IOriginSettler.OnchainCrossChainOrder memory onchainCrossChainOrder_ = IOriginSettler.OnchainCrossChainOrder({
            fillDeadline: uint32(mandate_.expires),
            orderDataType: orderDataType_,
            orderData: abi.encode(
                IHybridERC7683.OrderDataOnChain({
                    order: IHybridERC7683.Order({
                        arbiter: compact_.arbiter,
                        idsAndAmounts: defaultIdsAndAmounts,
                        chainId: defaultOutputChainId,
                        tribunal: tribunal,
                        recipient: mandate_.recipient,
                        settlementToken: mandate_.token,
                        minimumAmount: mandate_.minimumAmount,
                        baselinePriorityFee: mandate_.baselinePriorityFee,
                        scalingFactor: mandate_.scalingFactor,
                        decayCurve: mandate_.decayCurve,
                        salt: mandate_.salt,
                        qualification: _allocatorData(defaultTargetBlock, defaultMaximumBlocksAfterTarget)
                    }),
                    expires: compact_.expires
                })
            )
        });
        return onchainCrossChainOrder_;
    }
}

contract HybridERC7683_open is OnChainCrossChainOrderData {
    function test_revert_InvalidOrderDataType() public {
        // Order data type is invalid
        bytes32 falseOrderDataType = keccak256('false');
        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();
        onChainCrossChainOrder_.orderDataType = falseOrderDataType;

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IHybridERC7683.InvalidOrderDataType.selector,
                falseOrderDataType,
                hybridERC7683Allocator.ORDERDATA_ONCHAIN_TYPEHASH()
            )
        );
        hybridERC7683Allocator.open(onChainCrossChainOrder_);
    }

    function test_revert_InvalidQualification() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();
        (IHybridERC7683.OrderDataOnChain memory orderDataOnChain) =
            abi.decode(onChainCrossChainOrder_.orderData, (IHybridERC7683.OrderDataOnChain));
        orderDataOnChain.order.qualification = bytes32(uint256(1));
        onChainCrossChainOrder_.orderData = abi.encode(orderDataOnChain);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IHybridERC7683.InvalidQualification.selector, bytes32(uint256(1))));
        hybridERC7683Allocator.open(onChainCrossChainOrder_);
    }

    function test_revert_ManipulatedOrderData() public {
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash);

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
        assertEq(hybridERC7683Allocator.ORDERDATA_GASLESS_TYPEHASH(), ORDERDATA_GASLESS_TYPEHASH);
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
            recipient: bytes32(uint256(uint160(user))),
            chainId: block.chainid
        });
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        TribunalClaim memory claim =
            TribunalClaim({chainId: block.chainid, compact: compact_, sponsorSignature: '', allocatorSignature: ''});
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, mandate_, defaultTargetBlock, defaultMaximumBlocksAfterTarget)
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.expires),
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

contract HybridERC7683_openFor is GaslessCrossChainOrderData {
    function test_revert_InvalidOrderDataType() public {
        // Order data type is invalid
        bytes32 falseOrderDataType = keccak256('false');

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IHybridERC7683.InvalidOrderDataType.selector,
                falseOrderDataType,
                hybridERC7683Allocator.ORDERDATA_GASLESS_TYPEHASH()
            )
        );
        (IOriginSettler.GaslessCrossChainOrder memory falseGaslessCrossChainOrder, bytes memory signature) =
            _getGaslessCrossChainOrder();
        falseGaslessCrossChainOrder.orderDataType = falseOrderDataType;
        hybridERC7683Allocator.openFor(falseGaslessCrossChainOrder, signature, '');
    }

    function test_orderDataType() public view {
        assertEq(hybridERC7683Allocator.ORDERDATA_ONCHAIN_TYPEHASH(), ORDERDATA_ONCHAIN_TYPEHASH);
    }

    function test_successful_userHimself() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, bytes memory sponsorSignature) =
            _getGaslessCrossChainOrder();
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
            recipient: bytes32(uint256(uint160(user))),
            chainId: block.chainid
        });
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        TribunalClaim memory claim =
            TribunalClaim({chainId: block.chainid, compact: compact_, sponsorSignature: '', allocatorSignature: ''});
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, mandate_, defaultTargetBlock, defaultMaximumBlocksAfterTarget)
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.expires),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        vm.prank(user);
        vm.expectEmit(true, false, false, true, address(hybridERC7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        hybridERC7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');
    }

    function test_successful_relayed() public {
        // Provide tokens for allocation
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, bytes memory sponsorSignature) =
            _getGaslessCrossChainOrder();
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
            recipient: bytes32(uint256(uint160(user))),
            chainId: block.chainid
        });
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        TribunalClaim memory claim =
            TribunalClaim({chainId: block.chainid, compact: compact_, sponsorSignature: '', allocatorSignature: ''});
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, mandate_, defaultTargetBlock, defaultMaximumBlocksAfterTarget)
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.expires),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        vm.prank(makeAddr('filler'));
        vm.expectEmit(true, false, false, true, address(hybridERC7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        hybridERC7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');
    }
}

contract HybridERC7683_authorizeClaim is OnChainCrossChainOrderData, GaslessCrossChainOrderData {
    function setUp() public override(OnChainCrossChainOrderData, GaslessCrossChainOrderData) {
        super.setUp();
    }

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
        BatchClaim memory claim = BatchClaim({
            allocatorData: abi.encode(defaultTargetBlock, defaultMaximumBlocksAfterTarget),
            sponsorSignature: '',
            sponsor: user,
            nonce: compact_.nonce,
            expires: compact_.expires,
            witness: _createWitnessHash(mandate_),
            witnessTypestring: witnessTypeString,
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

        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, bytes memory sponsorSignature) =
            _getGaslessCrossChainOrder();

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);

        vm.prank(user);
        hybridERC7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');

        address filler = makeAddr('filler');

        // Create qualified claim hash for off-chain verification
        bytes32 qualifiedClaimHash =
            keccak256(abi.encode(hybridERC7683Allocator.QUALIFICATION_TYPEHASH(), claimHash, uint128(0), uint120(0)));
        bytes32 digest =
            keccak256(abi.encodePacked(bytes2(0x1901), compactContract.DOMAIN_SEPARATOR(), qualifiedClaimHash));

        // Sign with the signer
        bytes memory allocatorSignature = _signMessage(digest, signerPK);

        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        BatchClaim memory claim = BatchClaim({
            allocatorData: abi.encode(defaultTargetBlock, defaultMaximumBlocksAfterTarget, allocatorSignature),
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: _createWitnessHash(mandate_),
            witnessTypestring: witnessTypeString,
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
        bytes32 claimHash = _hashCompact(compact_, mandate_);

        vm.prank(user);
        compactContract.depositERC20AndRegister(
            address(usdc), usdcLockTag, defaultAmount, claimHash, BATCH_COMPACT_WITNESS_TYPEHASH
        );

        address filler = makeAddr('filler');

        // Create qualified claim hash for off-chain verification
        bytes32 qualifiedClaimHash = keccak256(
            abi.encode(
                hybridERC7683Allocator.QUALIFICATION_TYPEHASH(),
                claimHash,
                defaultTargetBlock,
                defaultMaximumBlocksAfterTarget
            )
        );
        bytes32 digest =
            keccak256(abi.encodePacked(bytes2(0x1901), compactContract.DOMAIN_SEPARATOR(), qualifiedClaimHash));

        // Sign with wrong signer
        bytes memory allocatorSignature = _signMessage(digest, signerPK);

        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        {
            Component[] memory components = new Component[](1);
            components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
            BatchClaimComponent memory batchClaimComponent =
                BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
            batchClaimComponents[0] = batchClaimComponent;
        }
        BatchClaim memory claim = BatchClaim({
            allocatorData: abi.encode(defaultTargetBlock, defaultMaximumBlocksAfterTarget, allocatorSignature),
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: _createWitnessHash(mandate_),
            witnessTypestring: witnessTypeString,
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
        bytes32 claimHash = _hashCompact(compact_, mandate_);

        vm.prank(user);
        compactContract.depositERC20AndRegister(
            address(usdc), usdcLockTag, defaultAmount, claimHash, BATCH_COMPACT_WITNESS_TYPEHASH
        );

        address filler = makeAddr('filler');

        // Create qualified claim hash for off-chain verification
        bytes32 qualifiedClaimHash = keccak256(
            abi.encode(
                hybridERC7683Allocator.QUALIFICATION_TYPEHASH(),
                claimHash,
                defaultTargetBlock,
                defaultMaximumBlocksAfterTarget
            )
        );
        bytes32 digest =
            keccak256(abi.encodePacked(bytes2(0x1901), compactContract.DOMAIN_SEPARATOR(), qualifiedClaimHash));

        // Sign with wrong signer
        bytes memory allocatorSignature = _signMessage(digest, attackerPK);

        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        {
            Component[] memory components = new Component[](1);
            components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
            BatchClaimComponent memory batchClaimComponent =
                BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
            batchClaimComponents[0] = batchClaimComponent;
        }
        BatchClaim memory claim = BatchClaim({
            allocatorData: abi.encode(defaultTargetBlock, defaultMaximumBlocksAfterTarget, allocatorSignature),
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: _createWitnessHash(mandate_),
            witnessTypestring: witnessTypeString,
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
        bytes32 claimHash = _hashCompact(compact_, mandate_);

        vm.prank(user);
        compactContract.depositERC20AndRegister(
            address(usdc), usdcLockTag, defaultAmount, claimHash, BATCH_COMPACT_WITNESS_TYPEHASH
        );

        address filler = makeAddr('filler');

        // Create qualified claim hash for off-chain verification
        bytes32 qualifiedClaimHash = keccak256(
            abi.encode(
                hybridERC7683Allocator.QUALIFICATION_TYPEHASH(),
                claimHash,
                defaultTargetBlock,
                defaultMaximumBlocksAfterTarget
            )
        );
        bytes32 digest =
            keccak256(abi.encodePacked(bytes2(0x1901), compactContract.DOMAIN_SEPARATOR(), qualifiedClaimHash));

        // Sign with wrong signer
        bytes memory allocatorSignature = _signMessage(digest, signerPK);

        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        {
            Component[] memory components = new Component[](1);
            components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
            BatchClaimComponent memory batchClaimComponent =
                BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
            batchClaimComponents[0] = batchClaimComponent;
        }
        BatchClaim memory claim = BatchClaim({
            allocatorData: abi.encode(defaultTargetBlock, defaultMaximumBlocksAfterTarget, allocatorSignature, uint8(0)), // wrong length
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: _createWitnessHash(mandate_),
            witnessTypestring: witnessTypeString,
            claims: batchClaimComponents
        });

        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(IHybridAllocator.InvalidSignature.selector));
        compactContract.batchClaim(claim);
    }
}

contract HybridERC7683_resolveFor is GaslessCrossChainOrderData {
    function test_revert_InvalidOrderDataType() public {
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_,) = _getGaslessCrossChainOrder();
        bytes32 falseOrderDataType = keccak256('false');
        gaslessCrossChainOrder_.orderDataType = falseOrderDataType;
        vm.expectRevert(
            abi.encodeWithSelector(
                IHybridERC7683.InvalidOrderDataType.selector,
                falseOrderDataType,
                hybridERC7683Allocator.ORDERDATA_GASLESS_TYPEHASH()
            )
        );
        hybridERC7683Allocator.resolveFor(gaslessCrossChainOrder_, '');
    }

    function test_resolveFor_successful() public {
        // Provide tokens for allocation so allocator holds funds
        vm.prank(user);
        usdc.transfer(address(hybridERC7683Allocator), defaultAmount);

        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_,) = _getGaslessCrossChainOrder();

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
            recipient: bytes32(uint256(uint160(user))),
            chainId: block.chainid
        });

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        TribunalClaim memory claim =
            TribunalClaim({chainId: block.chainid, compact: compact_, sponsorSignature: '', allocatorSignature: ''});
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, mandate_, defaultTargetBlock, defaultMaximumBlocksAfterTarget)
        });

        IOriginSettler.ResolvedCrossChainOrder memory expected = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.expires),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });

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

contract HybridERC7683_resolve is OnChainCrossChainOrderData {
    function test_revert_InvalidOrderDataType() public {
        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();
        onChainCrossChainOrder_.orderDataType = keccak256('false');
        vm.expectRevert(
            abi.encodeWithSelector(
                IHybridERC7683.InvalidOrderDataType.selector,
                onChainCrossChainOrder_.orderDataType,
                hybridERC7683Allocator.ORDERDATA_ONCHAIN_TYPEHASH()
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
            recipient: bytes32(uint256(uint160(user))),
            chainId: block.chainid
        });
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        TribunalClaim memory claim =
            TribunalClaim({chainId: block.chainid, compact: compact_, sponsorSignature: '', allocatorSignature: ''});
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, mandate_, defaultTargetBlock, defaultMaximumBlocksAfterTarget)
        });

        IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
            user: user,
            originChainId: block.chainid,
            openDeadline: uint32(compact_.expires),
            fillDeadline: uint32(mandate_.expires),
            orderId: bytes32(defaultNonce),
            maxSpent: maxSpent,
            minReceived: minReceived,
            fillInstructions: fillInstructions
        });
        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ =
            _getOnChainCrossChainOrder(compact_, mandate_, hybridERC7683Allocator.ORDERDATA_ONCHAIN_TYPEHASH());
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

contract HybridERC7683_qualificationTypehash is MocksSetup {
    function test_qualificationTypehash() public view {
        assertEq(
            hybridERC7683Allocator.QUALIFICATION_TYPEHASH(),
            0x59866b84bd1f6c909cf2a31efd20c59e6c902e50f2c196994e5aa85cdc7d7ce0
        );
    }
}

contract HybridERC7683_hybridAllocatorInheritance is MocksSetup {
    function test_inheritsHybridAllocatorFunctionality() public view {
        // Test that it properly inherits from HybridAllocator
        assertEq(hybridERC7683Allocator.nonce(), 0);
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

        (bytes32 claimHash, uint256[] memory registeredAmounts, uint256 nonce) = hybridERC7683Allocator
            .allocateAndRegister(user, idsAndAmounts, arbiter, _getClaimExpiration(), BATCH_COMPACT_WITNESS_TYPEHASH, '');

        assertTrue(compactContract.isRegistered(user, claimHash, BATCH_COMPACT_WITNESS_TYPEHASH));
        assertTrue(
            hybridERC7683Allocator.isClaimAuthorized(claimHash, address(0), address(0), 0, 0, new uint256[2][](0), '')
        );
        assertEq(registeredAmounts[0], defaultAmount);
        assertEq(usdc.balanceOf(address(compactContract)), defaultAmount);
        assertEq(compactContract.balanceOf(address(user), idsAndAmounts[0][0]), defaultAmount);
        assertEq(nonce, 1);
    }

    function _getClaimExpiration() internal view returns (uint256) {
        return vm.getBlockTimestamp() + defaultResetPeriodTimestamp;
    }
}
