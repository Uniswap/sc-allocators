// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {TheCompact} from '@uniswap/the-compact/TheCompact.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';

import {IdLib} from '@uniswap/the-compact/lib/IdLib.sol';
import {QualifiedClaimWithWitness} from '@uniswap/the-compact/types/Claims.sol';

import {COMPACT_TYPEHASH, Compact} from '@uniswap/the-compact/types/EIP712Types.sol';
import {ForcedWithdrawalStatus} from '@uniswap/the-compact/types/ForcedWithdrawalStatus.sol';
import {Lock} from '@uniswap/the-compact/types/Lock.sol';
import {ResetPeriod} from '@uniswap/the-compact/types/ResetPeriod.sol';
import {Scope} from '@uniswap/the-compact/types/Scope.sol';
import {Test} from 'forge-std/Test.sol';

import {console} from 'forge-std/console.sol';
import {ERC7683Allocator} from 'src/allocators/ERC7683Allocator.sol';
import {Claim, Mandate} from 'src/allocators/types/TribunalStructs.sol';
import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';
import {IERC7683Allocator} from 'src/interfaces/IERC7683Allocator.sol';

import {ISimpleAllocator} from 'src/interfaces/ISimpleAllocator.sol';
import {ERC20Mock} from 'src/test/ERC20Mock.sol';
import {TheCompactMock} from 'src/test/TheCompactMock.sol';

abstract contract MocksSetup is Test {
    address user;
    uint256 userPK;
    address attacker;
    uint256 attackerPK;
    address arbiter;
    address tribunal;
    ERC20Mock usdc;
    TheCompact compactContract;
    ERC7683Allocator erc7683Allocator;
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
    bytes32 defaultSalt = bytes32(0);
    uint256 defaultTargetBlock = 100;
    uint256 defaultMaximumBlocksAfterTarget = 10;

    bytes32 ORDERDATA_GASLESS_TYPEHASH;
    bytes32 ORDERDATA_TYPEHASH;

    function setUp() public virtual {
        (user, userPK) = makeAddrAndKey('user');
        arbiter = makeAddr('arbiter');
        tribunal = makeAddr('tribunal');
        usdc = new ERC20Mock('USDC', 'USDC');
        compactContract = new TheCompact();
        erc7683Allocator = new ERC7683Allocator(address(compactContract), 5, 100);
        Lock memory lock = Lock({
            token: address(usdc),
            allocator: address(erc7683Allocator),
            resetPeriod: defaultResetPeriod,
            scope: defaultScope
        });
        usdcId = IdLib.toId(lock);
        (attacker, attackerPK) = makeAddrAndKey('attacker');
        defaultNonce = uint256(bytes32(abi.encodePacked(user, uint96(1))));

        ORDERDATA_GASLESS_TYPEHASH = erc7683Allocator.ORDERDATA_GASLESS_TYPEHASH();
        ORDERDATA_TYPEHASH = erc7683Allocator.ORDERDATA_TYPEHASH();
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
    string version = '0';

    string compactWitnessTypeString =
        'Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Mandate mandate)Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)';
    string mandateTypeString =
        'Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)';
    string witnessTypeString =
        'Mandate mandate)Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)';

    function _hashCompact(Compact memory data, Mandate memory mandate, address verifyingContract)
        internal
        view
        returns (bytes32)
    {
        bytes32 compactHash = _hashCompact(data, mandate);
        // hash typed data
        return keccak256(
            abi.encodePacked(
                '\x19\x01', // backslash is needed to escape the character
                _domainSeparator(verifyingContract),
                compactHash
            )
        );
    }

    function _hashCompact(Compact memory data, Mandate memory mandate) internal view returns (bytes32 compactHash) {
        return keccak256(
            abi.encode(
                keccak256(bytes(compactWitnessTypeString)),
                data.arbiter,
                data.sponsor,
                data.nonce,
                data.expires,
                data.id,
                data.amount,
                keccak256(
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
                )
            )
        );
    }

    function _getTypeHash() internal view returns (bytes32) {
        return keccak256(bytes(compactWitnessTypeString));
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

    function _hashAndSign(Compact memory data, Mandate memory mandate, address verifyingContract, uint256 signerPK)
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
    Compact private compact;
    Mandate private mandate;

    function setUp() public virtual override {
        super.setUp();

        compact = Compact({
            arbiter: arbiter,
            sponsor: user,
            nonce: defaultNonce,
            expires: _getClaimExpiration(),
            id: usdcId,
            amount: defaultAmount
        });

        mandate = Mandate({
            recipient: user,
            expires: _getFillExpiration(),
            token: defaultOutputToken,
            minimumAmount: defaultMinimumAmount,
            baselinePriorityFee: defaultBaselinePriorityFee,
            scalingFactor: defaultScalingFactor,
            decayCurve: defaultDecayCurve,
            salt: defaultSalt
        });
    }

    function _getCompact() internal returns (Compact memory) {
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

        Compact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        gaslessCrossChainOrder = IOriginSettler.GaslessCrossChainOrder({
            originSettler: address(erc7683Allocator),
            user: compact_.sponsor,
            nonce: compact_.nonce,
            originChainId: block.chainid,
            openDeadline: uint32(_getClaimExpiration()),
            fillDeadline: uint32(_getFillExpiration()),
            orderDataType: erc7683Allocator.ORDERDATA_GASLESS_TYPEHASH(),
            orderData: abi.encode(
                IERC7683Allocator.OrderDataGasless({
                    arbiter: compact_.arbiter,
                    id: compact_.id,
                    amount: compact_.amount,
                    chainId: defaultOutputChainId,
                    tribunal: tribunal,
                    recipient: mandate_.recipient,
                    token: mandate_.token,
                    minimumAmount: mandate_.minimumAmount,
                    baselinePriorityFee: mandate_.baselinePriorityFee,
                    scalingFactor: mandate_.scalingFactor,
                    decayCurve: mandate_.decayCurve,
                    salt: mandate_.salt
                })
            )
        });
    }

    function _getGaslessCrossChainOrder(
        address allocator,
        Compact memory compact_,
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
                    arbiter: compact_.arbiter,
                    id: compact_.id,
                    amount: compact_.amount,
                    chainId: defaultOutputChainId,
                    tribunal: tribunal,
                    recipient: mandate_.recipient,
                    token: mandate_.token,
                    minimumAmount: mandate_.minimumAmount,
                    baselinePriorityFee: mandate_.baselinePriorityFee,
                    scalingFactor: mandate_.scalingFactor,
                    decayCurve: mandate_.decayCurve,
                    salt: mandate_.salt
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

        Compact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        onchainCrossChainOrder = IOriginSettler.OnchainCrossChainOrder({
            fillDeadline: uint32(_getFillExpiration()),
            orderDataType: erc7683Allocator.ORDERDATA_TYPEHASH(),
            orderData: abi.encode(
                IERC7683Allocator.OrderData({
                    arbiter: compact_.arbiter,
                    sponsor: compact_.sponsor,
                    nonce: compact_.nonce,
                    expires: compact_.expires,
                    id: compact_.id,
                    amount: compact_.amount,
                    chainId: defaultOutputChainId,
                    tribunal: tribunal,
                    recipient: mandate_.recipient,
                    token: mandate_.token,
                    minimumAmount: mandate_.minimumAmount,
                    baselinePriorityFee: mandate_.baselinePriorityFee,
                    scalingFactor: mandate_.scalingFactor,
                    decayCurve: mandate_.decayCurve,
                    salt: mandate_.salt,
                    targetBlock: defaultTargetBlock,
                    maximumBlocksAfterTarget: defaultMaximumBlocksAfterTarget
                })
            )
        });
    }

    function _getOnChainCrossChainOrder() internal view returns (IOriginSettler.OnchainCrossChainOrder memory) {
        return onchainCrossChainOrder;
    }

    function _getOnChainCrossChainOrder(Compact memory compact_, Mandate memory mandate_, bytes32 orderDataType_)
        internal
        view
        returns (IOriginSettler.OnchainCrossChainOrder memory)
    {
        IOriginSettler.OnchainCrossChainOrder memory onchainCrossChainOrder_ = IOriginSettler.OnchainCrossChainOrder({
            fillDeadline: uint32(mandate_.expires),
            orderDataType: orderDataType_,
            orderData: abi.encode(
                IERC7683Allocator.OrderData({
                    arbiter: compact_.arbiter,
                    sponsor: compact_.sponsor,
                    nonce: compact_.nonce,
                    expires: compact_.expires,
                    id: compact_.id,
                    amount: compact_.amount,
                    chainId: defaultOutputChainId,
                    tribunal: tribunal,
                    recipient: mandate_.recipient,
                    token: mandate_.token,
                    minimumAmount: mandate_.minimumAmount,
                    baselinePriorityFee: mandate_.baselinePriorityFee,
                    scalingFactor: mandate_.scalingFactor,
                    decayCurve: mandate_.decayCurve,
                    salt: mandate_.salt,
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
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );

        vm.stopPrank();
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

    function test_revert_InvalidNonce() public {
        // Nonce is invalid because the least significant 160 bits are not the sponsor address
        Compact memory compact_ = _getCompact();
        compact_.nonce = uint256(bytes32(abi.encodePacked(uint96(1), attacker)));
        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidNonce.selector, compact_.nonce));
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
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );
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
        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidSignature.selector, user, attacker));
        erc7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');
    }

    function test_successful_userHimself() public {
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );
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
        Claim memory claim = Claim({
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
    }

    function test_successful_relayed() public {
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );
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
        Claim memory claim = Claim({
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
    }

    function test_revert_NonceAlreadyInUse() public {
        // Nonce is already used

        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );
        vm.stopPrank();

        // use the nonce once
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, bytes memory sponsorSignature) =
            _getGaslessCrossChainOrder();
        vm.prank(user);
        erc7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');

        // try to use the nonce again
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder2, bytes memory sponsorSignature2) =
            _getGaslessCrossChainOrder();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.NonceAlreadyInUse.selector, defaultNonce));
        erc7683Allocator.openFor(gaslessCrossChainOrder2, sponsorSignature2, '');
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
                erc7683Allocator.ORDERDATA_TYPEHASH()
            )
        );
        erc7683Allocator.open(onChainCrossChainOrder_);
    }

    function test_revert_InvalidSponsor() public {
        IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_ = _getOnChainCrossChainOrder();

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidSponsor.selector, user, attacker));
        erc7683Allocator.open(onChainCrossChainOrder_);
    }

    function test_revert_InvalidRegistration_Unavailable() public {
        // we deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );

        // we do NOT register a claim

        vm.stopPrank();

        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();

        Compact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();
        bytes32 claimHash = _hashCompact(compact_, mandate_);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidRegistration.selector, user, claimHash));
        erc7683Allocator.open(onChainCrossChainOrder_);
    }

    function test_revert_InvalidRegistration_Expired() public {
        // we deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );

        // we register a claim with a expiration that is too short
        Compact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash, defaultResetPeriodTimestamp - 1);

        vm.stopPrank();
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidRegistration.selector, user, claimHash));
        erc7683Allocator.open(onChainCrossChainOrder_);
    }

    function test_successful() public {
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );

        // register a claim
        Compact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash, defaultResetPeriodTimestamp);

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
        Claim memory claim =
            Claim({chainId: block.chainid, compact: _getCompact(), sponsorSignature: '', allocatorSignature: ''});
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
    }
}

contract ERC7683Allocator_isValidSignature is OnChainCrossChainOrderData, GaslessCrossChainOrderData {
    function setUp() public override(OnChainCrossChainOrderData, GaslessCrossChainOrderData) {
        super.setUp();
    }

    function test_revert_InvalidLock() public {
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );

        // register a claim
        Compact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash, defaultResetPeriodTimestamp);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(compactContract.balanceOf(filler, usdcId), 0);

        vm.stopPrank();

        // we do NOT open the order or lock the tokens

        // claim should be fail, because we mess with the nonce
        QualifiedClaimWithWitness memory claim = QualifiedClaimWithWitness({
            allocatorSignature: '',
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: keccak256(abi.encode(keccak256(bytes(mandateTypeString)), mandate_)),
            witnessTypestring: witnessTypeString,
            qualificationTypehash: erc7683Allocator.QUALIFICATION_TYPEHASH(),
            qualificationPayload: abi.encode(defaultTargetBlock, defaultMaximumBlocksAfterTarget),
            id: usdcId,
            allocatedAmount: defaultAmount,
            claimant: filler,
            amount: defaultAmount
        });
        vm.prank(arbiter);
        vm.expectRevert(abi.encodeWithSelector(0x8baa579f)); // check for the InvalidSignature() error in the Compact contract
        compactContract.claim(claim);

        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(compactContract.balanceOf(filler, usdcId), 0);
    }

    function test_isValidSignature_successful_open() public {
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );

        // register a claim
        Compact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash, defaultResetPeriodTimestamp);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(compactContract.balanceOf(filler, usdcId), 0);

        // we open the order and lock the tokens
        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        erc7683Allocator.open(onChainCrossChainOrder_);
        vm.stopPrank();

        // claim should be successful
        QualifiedClaimWithWitness memory claim = QualifiedClaimWithWitness({
            allocatorSignature: '',
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: keccak256(
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
            ),
            witnessTypestring: witnessTypeString,
            qualificationTypehash: erc7683Allocator.QUALIFICATION_TYPEHASH(),
            qualificationPayload: abi.encode(defaultTargetBlock, defaultMaximumBlocksAfterTarget),
            id: usdcId,
            allocatedAmount: defaultAmount,
            claimant: filler,
            amount: defaultAmount
        });
        vm.prank(arbiter);
        compactContract.claim(claim);

        vm.assertEq(compactContract.balanceOf(user, usdcId), 0);
        vm.assertEq(compactContract.balanceOf(filler, usdcId), defaultAmount);
    }

    function test_isValidSignature_successful_openFor() public {
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );

        // register a claim
        Compact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash, defaultResetPeriodTimestamp);

        address filler = makeAddr('filler');
        vm.assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        vm.assertEq(compactContract.balanceOf(filler, usdcId), 0);

        // we open the order and lock the tokens
        (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, bytes memory sponsorSignature) =
            _getGaslessCrossChainOrder();
        erc7683Allocator.openFor(gaslessCrossChainOrder_, sponsorSignature, '');
        vm.stopPrank();

        // claim should be successful
        QualifiedClaimWithWitness memory claim = QualifiedClaimWithWitness({
            allocatorSignature: '',
            sponsorSignature: '',
            sponsor: user,
            nonce: defaultNonce,
            expires: compact_.expires,
            witness: keccak256(
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
            ),
            witnessTypestring: witnessTypeString,
            qualificationTypehash: erc7683Allocator.QUALIFICATION_TYPEHASH(),
            qualificationPayload: abi.encode(uint256(0), uint256(0)),
            id: usdcId,
            allocatedAmount: defaultAmount,
            claimant: filler,
            amount: defaultAmount
        });
        vm.prank(arbiter);
        compactContract.claim(claim);

        vm.assertEq(compactContract.balanceOf(user, usdcId), 0);
        vm.assertEq(compactContract.balanceOf(filler, usdcId), defaultAmount);
    }
}

contract ERC7683Allocator_resolveFor is GaslessCrossChainOrderData {
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
        Claim memory claim = Claim({
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
        Claim memory claim =
            Claim({chainId: block.chainid, compact: _getCompact(), sponsorSignature: '', allocatorSignature: ''});
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
            'Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Mandate mandate)Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt))'
        );
    }
}

contract ERC7683Allocator_checkNonce is OnChainCrossChainOrderData {
    function test_revert_invalidNonce(uint256 nonce_) public {
        address expectedSponsor;
        assembly ("memory-safe") {
            expectedSponsor := shr(96, nonce_)
        }
        vm.assume(user != expectedSponsor);

        vm.expectRevert(abi.encodeWithSelector(IERC7683Allocator.InvalidNonce.selector, nonce_));
        erc7683Allocator.checkNonce(user, nonce_);
    }

    function test_checkNonce_unused(uint96 nonce_) public view {
        address sponsor = user;
        uint256 nonce;
        assembly ("memory-safe") {
            nonce := or(shl(96, sponsor), shr(160, shl(160, nonce_)))
        }
        assertEq(erc7683Allocator.checkNonce(sponsor, nonce), true);
    }

    function test_checkNonce_used() public {
        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );

        // register a claim
        Compact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash, defaultResetPeriodTimestamp);

        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        erc7683Allocator.open(onChainCrossChainOrder_);

        vm.assertEq(erc7683Allocator.checkNonce(user, defaultNonce), false);
        vm.stopPrank();
    }

    function test_checkNonce_fuzz(uint8 nonce_) public {
        uint256 nonce = uint256(bytes32(abi.encodePacked(user, uint96(nonce_))));

        bool sameNonce = nonce == defaultNonce;

        // Deposit tokens
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.deposit(
            address(usdc), address(erc7683Allocator), defaultResetPeriod, defaultScope, defaultAmount, user
        );

        // register a claim
        Compact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        bytes32 claimHash = _hashCompact(compact_, mandate_);
        bytes32 typeHash = _getTypeHash();
        compactContract.register(claimHash, typeHash, defaultResetPeriodTimestamp);

        (IOriginSettler.OnchainCrossChainOrder memory onChainCrossChainOrder_) = _getOnChainCrossChainOrder();
        erc7683Allocator.open(onChainCrossChainOrder_);

        vm.assertEq(erc7683Allocator.checkNonce(user, nonce), !sameNonce);

        vm.stopPrank();
    }
}
