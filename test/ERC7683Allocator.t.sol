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

import {ERC7683Allocator} from 'src/allocators/ERC7683Allocator.sol';
import {BatchClaim as TribunalClaim, Mandate} from 'src/allocators/types/TribunalStructs.sol';
import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';
import {IERC7683Allocator} from 'src/interfaces/IERC7683Allocator.sol';
import {IOnChainAllocator} from 'src/interfaces/IOnchainAllocator.sol';

import {ISimpleAllocator} from 'src/interfaces/ISimpleAllocator.sol';
import {ERC20Mock} from 'src/test/ERC20Mock.sol';
import {TheCompactMock} from 'src/test/TheCompactMock.sol';

abstract contract MocksSetup is Test, TestHelper {
    address user;
    uint256 userPK;
    address attacker;
    uint256 attackerPK;
    address arbiter;
    address tribunal;
    ERC20Mock usdc;
    TheCompact compactContract;
    ERC7683Allocator erc7683Allocator;
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
        arbiter = makeAddr('arbiter');
        tribunal = makeAddr('tribunal');
        usdc = new ERC20Mock('USDC', 'USDC');
        compactContract = new TheCompact();
        erc7683Allocator = new ERC7683Allocator(address(compactContract));

        usdcLockTag = _toLockTag(address(erc7683Allocator), defaultScope, defaultResetPeriod);
        usdcId = _toId(defaultScope, defaultResetPeriod, address(erc7683Allocator), address(usdc));
        (attacker, attackerPK) = makeAddrAndKey('attacker');
        defaultNonce = 1;

        ORDERDATA_GASLESS_TYPEHASH = keccak256(
            'OrderDataGasless(address arbiter,Order order)Lock(bytes12 lockTag,address token,uint256 amount)Order(Lock[] commitments,uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)'
        );
        ORDERDATA_ONCHAIN_TYPEHASH = keccak256(
            'OrderDataOnChain(address arbiter,uint256 expires,Order order,uint200 targetBlock,uint56 maximumBlocksAfterTarget)Lock(bytes12 lockTag,address token,uint256 amount)Order(Lock[] commitments,uint256 chainId,address tribunal,address recipient,address settlementToken,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)'
        );
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
}

abstract contract CompactData is CreateHash {
    BatchCompact private compact;
    Mandate private mandate;

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

        gaslessCrossChainOrder.originSettler = address(erc7683Allocator);
        gaslessCrossChainOrder.user = compact_.sponsor;
        gaslessCrossChainOrder.nonce = compact_.nonce;
        gaslessCrossChainOrder.originChainId = block.chainid;
        gaslessCrossChainOrder.openDeadline = uint32(_getClaimExpiration());
        gaslessCrossChainOrder.fillDeadline = uint32(_getFillExpiration());
        gaslessCrossChainOrder.orderDataType = erc7683Allocator.ORDERDATA_GASLESS_TYPEHASH();
        gaslessCrossChainOrder.orderData = abi.encode(
            IERC7683Allocator.OrderDataGasless({
                order: IERC7683Allocator.Order({
                    arbiter: compact_.arbiter,
                    commitments: compact_.commitments,
                    chainId: defaultOutputChainId,
                    tribunal: tribunal,
                    recipient: mandate_.recipient,
                    settlementToken: mandate_.token,
                    minimumAmount: mandate_.minimumAmount,
                    baselinePriorityFee: mandate_.baselinePriorityFee,
                    scalingFactor: mandate_.scalingFactor,
                    decayCurve: mandate_.decayCurve,
                    salt: mandate_.salt
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
                IERC7683Allocator.OrderDataGasless({
                    order: IERC7683Allocator.Order({
                        arbiter: compact_.arbiter,
                        commitments: compact_.commitments,
                        chainId: defaultOutputChainId,
                        tribunal: tribunal,
                        recipient: mandate_.recipient,
                        settlementToken: mandate_.token,
                        minimumAmount: mandate_.minimumAmount,
                        baselinePriorityFee: mandate_.baselinePriorityFee,
                        scalingFactor: mandate_.scalingFactor,
                        decayCurve: mandate_.decayCurve,
                        salt: mandate_.salt
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

        onchainCrossChainOrder.fillDeadline = uint32(_getFillExpiration());
        onchainCrossChainOrder.orderDataType = erc7683Allocator.ORDERDATA_ONCHAIN_TYPEHASH();
        onchainCrossChainOrder.orderData = abi.encode(
            IERC7683Allocator.OrderDataOnChain({
                expires: compact_.expires,
                order: IERC7683Allocator.Order({
                    arbiter: compact_.arbiter,
                    commitments: compact_.commitments,
                    chainId: defaultOutputChainId,
                    tribunal: tribunal,
                    recipient: mandate_.recipient,
                    settlementToken: mandate_.token,
                    minimumAmount: mandate_.minimumAmount,
                    baselinePriorityFee: mandate_.baselinePriorityFee,
                    scalingFactor: mandate_.scalingFactor,
                    decayCurve: mandate_.decayCurve,
                    salt: mandate_.salt
                }),
                targetBlock: defaultTargetBlock,
                maximumBlocksAfterTarget: defaultMaximumBlocksAfterTarget
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
                IERC7683Allocator.OrderDataOnChain({
                    expires: compact_.expires,
                    order: IERC7683Allocator.Order({
                        arbiter: compact_.arbiter,
                        commitments: compact_.commitments,
                        chainId: defaultOutputChainId,
                        tribunal: tribunal,
                        recipient: mandate_.recipient,
                        settlementToken: mandate_.token,
                        minimumAmount: mandate_.minimumAmount,
                        baselinePriorityFee: mandate_.baselinePriorityFee,
                        scalingFactor: mandate_.scalingFactor,
                        decayCurve: mandate_.decayCurve,
                        salt: mandate_.salt
                    }),
                    targetBlock: defaultTargetBlock,
                    maximumBlocksAfterTarget: defaultMaximumBlocksAfterTarget
                })
            )
        });
        return onchainCrossChainOrder_;
    }
}

abstract contract Deposited is MocksSetup {
    function setUp() public virtual override {
        super.setUp();

        vm.startPrank(user);

        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        vm.stopPrank();
    }
}

contract ERC7683Allocator_open is OnChainCrossChainOrderData {
    function test_revert_InvalidOrderDataType() public {
        // Order data type is invalid
        bytes32 falseOrderDataType = keccak256('false');
        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();
        onChainCrossChainOrder_.orderDataType = falseOrderDataType;

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector,
                falseOrderDataType,
                erc7683Allocator.ORDERDATA_ONCHAIN_TYPEHASH()
            )
        );
        erc7683Allocator.open(onChainCrossChainOrder_);
    }

    function test_orderDataType() public view {
        assertEq(erc7683Allocator.ORDERDATA_GASLESS_TYPEHASH(), ORDERDATA_GASLESS_TYPEHASH);
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
        (bool success, bytes memory returnData) = address(erc7683Allocator).call(callData);
        assertEq(success, false);
        assertEq(returnData.length, 0);
    }

    function test_revert_InvalidRegistration() public {
        // we deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // we do NOT register a claim

        vm.stopPrank();

        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        bytes32 claimHash = _hashCompact(compact_, mandate_);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidRegistration.selector, user, claimHash));
        erc7683Allocator.open(onChainCrossChainOrder_);
    }

    function test_successful() public {
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
        TribunalClaim memory claim = TribunalClaim({
            chainId: block.chainid,
            compact: _getCompact(),
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, _getMandate(), defaultTargetBlock, defaultMaximumBlocksAfterTarget)
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
        vm.expectEmit(true, false, false, true, address(erc7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        erc7683Allocator.open(onChainCrossChainOrder_);
        vm.snapshotGasLastCall('open_simpleOrder');
    }
}

contract ERC7683Allocator_openFor is GaslessCrossChainOrderData {
    function test_revert_InvalidOrderDataType() public {
        // Order data type is invalid
        bytes32 falseOrderDataType = keccak256('false');

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector,
                falseOrderDataType,
                erc7683Allocator.ORDERDATA_GASLESS_TYPEHASH()
            )
        );
        (IOriginSettler.GaslessCrossChainOrder memory falseGaslessCrossChainOrder, bytes memory signature) =
            _getGaslessCrossChainOrder();
        falseGaslessCrossChainOrder.orderDataType = falseOrderDataType;
        erc7683Allocator.openFor(falseGaslessCrossChainOrder, signature, '');
    }

    function test_orderDataType() public view {
        assertEq(erc7683Allocator.ORDERDATA_ONCHAIN_TYPEHASH(), ORDERDATA_ONCHAIN_TYPEHASH);
    }

    function test_revert_InvalidDecoding() public {
        // Decoding fails because of additional data
        vm.prank(user);
        vm.expectRevert();
        (IOriginSettler.GaslessCrossChainOrder memory falseGaslessCrossChainOrder, bytes memory signature) =
            _getGaslessCrossChainOrder();
        falseGaslessCrossChainOrder.orderData = abi.encode(falseGaslessCrossChainOrder.orderData, uint8(1));
        erc7683Allocator.openFor(falseGaslessCrossChainOrder, signature, '');
    }

    function test_revert_InvalidOriginSettler() public {
        // Origin settler is not the allocator
        address falseOriginSettler = makeAddr('falseOriginSettler');
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOriginSettler.selector, falseOriginSettler, address(erc7683Allocator)
            )
        );
        (IOriginSettler.GaslessCrossChainOrder memory falseGaslessCrossChainOrder, bytes memory signature) =
        _getGaslessCrossChainOrder(
            falseOriginSettler,
            _getCompact(),
            _getMandate(),
            block.chainid,
            ORDERDATA_GASLESS_TYPEHASH,
            address(erc7683Allocator),
            userPK
        );
        vm.prank(user);
        erc7683Allocator.openFor(falseGaslessCrossChainOrder, signature, '');
    }

    function test_revert_InvalidNonce(uint256 nonce) public {
        vm.assume(nonce != defaultNonce);

        BatchCompact memory compact_ = _getCompact();
        compact_.nonce = nonce;
        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidNonce.selector, compact_.nonce, defaultNonce));
        (IOriginSettler.GaslessCrossChainOrder memory falseGaslessCrossChainOrder, bytes memory signature) =
        _getGaslessCrossChainOrder(
            address(erc7683Allocator),
            compact_,
            _getMandate(),
            block.chainid,
            ORDERDATA_GASLESS_TYPEHASH,
            address(erc7683Allocator),
            userPK
        );
        vm.prank(user);
        erc7683Allocator.openFor(falseGaslessCrossChainOrder, signature, '');
    }

    function test_revert_InvalidSponsorSignature() public {
        // Sponsor signature is invalid

        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);
        vm.stopPrank();

        // Create a malicious signature
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, bytes memory sponsorSignature) =
        _getGaslessCrossChainOrder(
            address(erc7683Allocator),
            _getCompact(),
            _getMandate(),
            block.chainid,
            ORDERDATA_GASLESS_TYPEHASH,
            address(compactContract),
            attackerPK
        );
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IOnChainAllocator.InvalidSignature.selector, user, attacker));
        erc7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');
    }

    function test_successful_userHimself() public {
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);
        vm.stopPrank();

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
            amount: defaultAmount,
            recipient: '',
            chainId: block.chainid
        });
        TribunalClaim memory claim = TribunalClaim({
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
        vm.prank(user);
        vm.expectEmit(true, false, false, true, address(erc7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        erc7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');
        vm.snapshotGasLastCall('openFor_simpleOrder_userHimself');
    }

    function test_successful_relayed() public {
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);
        vm.stopPrank();

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
            amount: defaultAmount,
            recipient: '',
            chainId: block.chainid
        });
        TribunalClaim memory claim = TribunalClaim({
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
        vm.prank(makeAddr('filler'));
        vm.expectEmit(true, false, false, true, address(erc7683Allocator));
        emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
        erc7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');
        vm.snapshotGasLastCall('openFor_simpleOrder_relayed');
    }

    function test_revert_NonceAlreadyInUse(uint256 nonce) public {
        vm.assume(nonce != defaultNonce);
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);
        vm.stopPrank();

        // try to use a future nonce
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder, bytes memory sponsorSignature) =
            _getGaslessCrossChainOrder();
        gaslessCrossChainOrder.nonce = nonce;
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidNonce.selector, nonce, defaultNonce));
        erc7683Allocator.openFor(gaslessCrossChainOrder, sponsorSignature, '');
    }
}

// contract ERC7683Allocator_open is OnChainCrossChainOrderData {
//     function test_revert_InvalidOrderDataType() public {
//         // Order data type is invalid
//         bytes32 falseOrderDataType = keccak256('false');
//         IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();
//         onChainCrossChainOrder_.orderDataType = falseOrderDataType;

//         vm.prank(user);
//         vm.expectRevert(
//             abi.encodeWithSelector(
//                 IERC7683Allocator.InvalidOrderDataType.selector,
//                 falseOrderDataType,
//                 erc7683Allocator.ORDERDATA_TYPEHASH()
//             )
//         );
//         erc7683Allocator.open(onChainCrossChainOrder_);
//     }

//     function test_revert_InvalidSponsor() public {
//         IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();

//         vm.prank(attacker);
//         vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidSignature.selector, user, attacker));
//         erc7683Allocator.open(onChainCrossChainOrder_);
//     }

//     function test_revert_InvalidRegistration_Unavailable() public {
//         // we deposit tokens
//         vm.startPrank(user);
//         usdc.mint(user, defaultAmount);
//         usdc.approve(address(compactContract), defaultAmount);
//         compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

//         // we do NOT register a claim

//         vm.stopPrank();

//         (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();

//         Compact memory compact_ = _getCompact();
//         Mandate memory mandate_ = _getMandate();
//         bytes32 claimHash = _hashCompact(compact_, mandate_);

//         vm.prank(user);
//         vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidRegistration.selector, user, claimHash));
//         erc7683Allocator.open(onChainCrossChainOrder_);
//     }

//     function test_successful() public {
//         // Deposit tokens
//         vm.startPrank(user);
//         usdc.mint(user, defaultAmount);
//         usdc.approve(address(compactContract), defaultAmount);
//         compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

//         // register a claim
//         Compact memory compact_ = _getCompact();
//         Mandate memory mandate_ = _getMandate();

//         bytes32 claimHash = _hashCompact(compact_, mandate_);
//         bytes32 typeHash = _getTypeHash();
//         compactContract.register(claimHash, typeHash);

//         vm.stopPrank();

//         (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
//         IOriginSettler.Output[] memory maxSpent = new IOriginSettler.Output[](1);
//         IOriginSettler.Output[] memory minReceived = new IOriginSettler.Output[](1);
//         IOriginSettler.FillInstruction[] memory fillInstructions = new IOriginSettler.FillInstruction[](1);
//         maxSpent[0] = IOriginSettler.Output({
//             token: bytes32(uint256(uint160(defaultOutputToken))),
//             amount: type(uint256).max,
//             recipient: bytes32(uint256(uint160(user))),
//             chainId: defaultOutputChainId
//         });
//         minReceived[0] = IOriginSettler.Output({
//             token: bytes32(uint256(uint160(address(usdc)))),
//             amount: defaultAmount,
//             recipient: '',
//             chainId: block.chainid
//         });
//         TribunalClaim memory claim = TribunalClaim({
//             chainId: block.chainid,
//             compact: _getCompact(),
//             sponsorSignature: '',
//             allocatorSignature: ''
//         });
//         fillInstructions[0] = IOriginSettler.FillInstruction({
//             destinationChainId: defaultOutputChainId,
//             destinationSettler: bytes32(uint256(uint160(tribunal))),
//             originData: abi.encode(claim, _getMandate(), defaultTargetBlock, defaultMaximumBlocksAfterTarget)
//         });

//         IOriginSettler.ResolvedCrossChainOrder memory resolvedCrossChainOrder = IOriginSettler.ResolvedCrossChainOrder({
//             user: user,
//             originChainId: block.chainid,
//             openDeadline: uint32(_getClaimExpiration()),
//             fillDeadline: uint32(_getFillExpiration()),
//             orderId: bytes32(defaultNonce),
//             maxSpent: maxSpent,
//             minReceived: minReceived,
//             fillInstructions: fillInstructions
//         });
//         vm.prank(user);
//         vm.expectEmit(true, false, false, true, address(erc7683Allocator));
//         emit IOriginSettler.Open(bytes32(defaultNonce), resolvedCrossChainOrder);
//         erc7683Allocator.open(onChainCrossChainOrder_);
//     }
// }

contract ERC7683Allocator_authorizeClaim is OnChainCrossChainOrderData, GaslessCrossChainOrderData {
    function setUp() public override(OnChainCrossChainOrderData, GaslessCrossChainOrderData) {
        super.setUp();
    }

    function test_revert_InvalidSignature() public {
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
            allocatorData: abi.encodePacked(defaultTargetBlock, defaultMaximumBlocksAfterTarget),
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: keccak256(abi.encode(keccak256(bytes(mandateTypeString)), mandate_)),
            witnessTypestring: witnessTypeString,
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
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        erc7683Allocator.open(onChainCrossChainOrder_);
        vm.stopPrank();

        // claim should be successful
        bytes32 witness = keccak256(
            abi.encode(
                keccak256(bytes(mandateTypeString)),
                defaultOutputChainId,
                tribunal,
                mandate_.recipient,
                mandate_.expires,
                mandate_.token,
                mandate_.minimumAmount,
                mandate_.baselinePriorityFee,
                mandate_.scalingFactor,
                keccak256(abi.encodePacked(mandate_.decayCurve)),
                mandate_.salt
            )
        );
        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        BatchClaim memory claim = BatchClaim({
            allocatorData: abi.encodePacked(defaultTargetBlock + 1, defaultMaximumBlocksAfterTarget),
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: witness,
            witnessTypestring: witnessTypeString,
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidAllocatorData.selector,
                bytes32(claim.allocatorData),
                bytes32(abi.encodePacked(defaultTargetBlock, defaultMaximumBlocksAfterTarget))
            )
        );
        compactContract.batchClaim(claim);
    }

    function test_successful_open() public {
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

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        erc7683Allocator.open(onChainCrossChainOrder_);
        vm.stopPrank();

        // claim should be successful
        bytes32 witness = keccak256(
            abi.encode(
                keccak256(bytes(mandateTypeString)),
                defaultOutputChainId,
                tribunal,
                mandate_.recipient,
                mandate_.expires,
                mandate_.token,
                mandate_.minimumAmount,
                mandate_.baselinePriorityFee,
                mandate_.scalingFactor,
                keccak256(abi.encodePacked(mandate_.decayCurve)),
                mandate_.salt
            )
        );
        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        BatchClaim memory claim = BatchClaim({
            allocatorData: abi.encodePacked(defaultTargetBlock, defaultMaximumBlocksAfterTarget),
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: witness,
            witnessTypestring: witnessTypeString,
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
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, bytes memory sponsorSignature) =
            _getGaslessCrossChainOrder();
        erc7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');
        vm.stopPrank();

        // claim should be successful
        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        BatchClaim memory claim = BatchClaim({
            allocatorData: abi.encodePacked(uint200(0), uint56(0)),
            sponsorSignature: '',
            sponsor: compact_.sponsor,
            nonce: compact_.nonce,
            expires: compact_.expires,
            witness: _hashMandate(mandate_),
            witnessTypestring: witnessTypeString,
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        compactContract.batchClaim(claim);

        vm.assertEq(compactContract.balanceOf(user, usdcId), 0);
        vm.assertEq(usdc.balanceOf(filler), defaultAmount);
    }
}

contract ERC7683Allocator_isClaimAuthorized is OnChainCrossChainOrderData, GaslessCrossChainOrderData {
    function setUp() public override(OnChainCrossChainOrderData, GaslessCrossChainOrderData) {
        super.setUp();
    }

    function test_failed_noClaimAllocated() public {
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
                abi.encodePacked(defaultTargetBlock, defaultMaximumBlocksAfterTarget)
            )
        );
    }

    function test_failed_invalidAllocatorData() public {
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

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        erc7683Allocator.open(onChainCrossChainOrder_);
        vm.stopPrank();

        // isClaimAuthorized should be false, because the allocator data is invalid
        assertFalse(
            erc7683Allocator.isClaimAuthorized(
                claimHash,
                compact_.arbiter,
                compact_.sponsor,
                compact_.nonce,
                compact_.expires,
                defaultIdsAndAmounts,
                abi.encodePacked(defaultTargetBlock + 1, defaultMaximumBlocksAfterTarget) // invalid allocator data
            )
        );
    }

    function test_successful_open() public {
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

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        erc7683Allocator.open(onChainCrossChainOrder_);
        vm.stopPrank();

        // claim should be successful
        bytes32 witness = keccak256(
            abi.encode(
                keccak256(bytes(mandateTypeString)),
                defaultOutputChainId,
                tribunal,
                mandate_.recipient,
                mandate_.expires,
                mandate_.token,
                mandate_.minimumAmount,
                mandate_.baselinePriorityFee,
                mandate_.scalingFactor,
                keccak256(abi.encodePacked(mandate_.decayCurve)),
                mandate_.salt
            )
        );
        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        BatchClaim memory claim = BatchClaim({
            allocatorData: abi.encodePacked(defaultTargetBlock, defaultMaximumBlocksAfterTarget),
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: witness,
            witnessTypestring: witnessTypeString,
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
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), usdcLockTag, defaultAmount, user);

        // register a claim
        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(usdc.balanceOf(filler), 0);

        // we open the order and lock the tokens
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, bytes memory sponsorSignature) =
            _getGaslessCrossChainOrder();
        erc7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');
        vm.stopPrank();

        // claim should be successful
        Component[] memory components = new Component[](1);
        components[0] = Component({claimant: uint256(uint160(filler)), amount: defaultAmount});
        BatchClaimComponent memory batchClaimComponent =
            BatchClaimComponent({id: usdcId, allocatedAmount: defaultAmount, portions: components});
        BatchClaimComponent[] memory batchClaimComponents = new BatchClaimComponent[](1);
        batchClaimComponents[0] = batchClaimComponent;
        BatchClaim memory claim = BatchClaim({
            allocatorData: abi.encodePacked(uint200(0), uint56(0)),
            sponsorSignature: '',
            sponsor: compact_.sponsor,
            nonce: compact_.nonce,
            expires: compact_.expires,
            witness: _hashMandate(mandate_),
            witnessTypestring: witnessTypeString,
            claims: batchClaimComponents
        });
        vm.prank(arbiter);
        compactContract.batchClaim(claim);

        vm.assertEq(compactContract.balanceOf(user, usdcId), 0);
        vm.assertEq(usdc.balanceOf(filler), defaultAmount);
    }
}

contract ERC7683Allocator_resolveFor is GaslessCrossChainOrderData {
    function test_revert_InvalidOrderDataType() public {
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, /*bytes memory sponsorSignature*/ ) =
            _getGaslessCrossChainOrder();
        gaslessCrossChainOrder_.orderDataType = keccak256('false');
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector,
                gaslessCrossChainOrder_.orderDataType,
                erc7683Allocator.ORDERDATA_GASLESS_TYPEHASH()
            )
        );
        erc7683Allocator.resolveFor(gaslessCrossChainOrder_, '');
    }

    function test_revert_InvalidOriginSettler() public {
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, /*bytes memory sponsorSignature*/ ) =
            _getGaslessCrossChainOrder();
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
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, /*bytes memory sponsorSignature*/ ) =
            _getGaslessCrossChainOrder();
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

        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, /*bytes memory sponsorSignature*/ ) =
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
            amount: defaultAmount,
            recipient: '',
            chainId: block.chainid
        });
        TribunalClaim memory claim = TribunalClaim({
            chainId: block.chainid,
            compact: _getCompact(),
            sponsorSignature: '', // sponsorSignature, // THE SIGNATURE MUST BE ADDED MANUALLY BY THE FILLER WITH THE CURRENT SYSTEM, BEFORE FILLING THE ORDER ON THE TARGET CHAIN
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

contract ERC7683Allocator_resolve is OnChainCrossChainOrderData {
    function test_revert_InvalidOrderDataType() public {
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        onChainCrossChainOrder_.orderDataType = keccak256('false');
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC7683Allocator.InvalidOrderDataType.selector,
                onChainCrossChainOrder_.orderDataType,
                erc7683Allocator.ORDERDATA_ONCHAIN_TYPEHASH()
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
        TribunalClaim memory claim = TribunalClaim({
            chainId: block.chainid,
            compact: _getCompact(),
            sponsorSignature: '',
            allocatorSignature: ''
        });
        fillInstructions[0] = IOriginSettler.FillInstruction({
            destinationChainId: defaultOutputChainId,
            destinationSettler: bytes32(uint256(uint160(tribunal))),
            originData: abi.encode(claim, _getMandate(), defaultTargetBlock, defaultMaximumBlocksAfterTarget)
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

contract ERC7683Allocator_getCompactWitnessTypeString is MocksSetup {
    function test_getCompactWitnessTypeString() public view {
        assertEq(
            erc7683Allocator.getCompactWitnessTypeString(),
            'BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)Lock(bytes12 lockTag,address token,uint256 amount)Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)'
        );
    }
}

contract ERC7683Allocator_checkNonce is OnChainCrossChainOrderData {
    function test_invalidNonce(uint256 nonce_, address otherUser) public view {
        vm.assume(nonce_ != defaultNonce);

        assertFalse(erc7683Allocator.checkNonce(nonce_, otherUser));
    }

    function test_nextFreeNonce(address otherUser) public view {
        assertTrue(erc7683Allocator.checkNonce(defaultNonce, otherUser));
    }

    function test_usedNonce(address otherUser) public {
        vm.assume(otherUser != user);
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

        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        erc7683Allocator.open(onChainCrossChainOrder_);

        vm.assertFalse(erc7683Allocator.checkNonce(defaultNonce, user));
        vm.assertTrue(erc7683Allocator.checkNonce(defaultNonce, otherUser));
        vm.stopPrank();
    }
}

contract ERC7683Allocator_createFillerData is OnChainCrossChainOrderData {
    function test_createFillerData(address claimant) public view {
        bytes memory fillerData = erc7683Allocator.createFillerData(claimant);
        assertEq(abi.decode(fillerData, (address)), claimant);
    }
}
