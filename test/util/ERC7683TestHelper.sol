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
    MANDATE_LOCK_TYPEHASH,
    MANDATE_RECIPIENT_CALLBACK_TYPEHASH,
    MANDATE_TYPEHASH
} from '@uniswap/tribunal/types/TribunalTypeHashes.sol';

import {ERC7683Allocator} from 'src/allocators/ERC7683Allocator.sol';
import {ERC7683AllocatorLib as ERC7683AL} from 'src/allocators/lib/ERC7683AllocatorLib.sol';
import {IOriginSettler} from 'src/interfaces/ERC7683/IOriginSettler.sol';
import {IERC7683Allocator} from 'src/interfaces/IERC7683Allocator.sol';
import {IOnChainAllocator} from 'src/interfaces/IOnChainAllocator.sol';
import {ERC20Mock} from 'src/test/ERC20Mock.sol';

abstract contract MocksSetup is Test, TestHelper {
    address user = makeAddr('user');
    uint256 userPK;
    address attacker;
    uint256 attackerPK;
    address arbiter;
    address tribunal;
    address adjuster;
    ERC20Mock usdc;
    TheCompact compactContract;
    address allocator;
    bytes12 usdcLockTag;
    uint256 usdcId;

    ResetPeriod defaultResetPeriod = ResetPeriod.OneMinute;
    Scope defaultScope = Scope.Multichain;
    uint256 defaultResetPeriodTimestamp = 60 - 1;
    uint256 defaultAmount = 1000;
    uint256 defaultNonce;
    uint256 defaultOutputChainId = 130;
    address defaultOutputToken = makeAddr('outputToken');
    uint256 defaultMinimumAmount = 1000;
    uint256 defaultBaselinePriorityFee = 0;
    uint256 defaultScalingFactor = 1e18;
    uint256[] defaultPriceCurve = new uint256[](0);
    bytes32 defaultSalt = bytes32(0x0000000000000000000000000000000000000000000000000000000000000007);

    uint256[2][] defaultIdsAndAmounts = new uint256[2][](1);
    Lock[] defaultCommitments;

    bytes32 ORDERDATA_GASLESS_TYPEHASH;
    bytes32 ORDERDATA_ONCHAIN_TYPEHASH;

    uint256 NONCES_STORAGE_SLOT = 1;

    function setUp() public virtual {
        (user, userPK) = makeAddrAndKey('user');
        arbiter = makeAddr('arbiter');
        tribunal = makeAddr('tribunal');
        adjuster = makeAddr('adjuster');
        usdc = new ERC20Mock('USDC', 'USDC');
        vm.startPrank(user);
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        vm.stopPrank();

        usdcLockTag = _toLockTag(allocator, defaultScope, defaultResetPeriod);
        usdcId = _toId(defaultScope, defaultResetPeriod, allocator, address(usdc));
        (attacker, attackerPK) = makeAddrAndKey('attacker');

        ORDERDATA_GASLESS_TYPEHASH = ERC7683AL.ORDERDATA_GASLESS_TYPEHASH;
        ORDERDATA_ONCHAIN_TYPEHASH = ERC7683AL.ORDERDATA_ONCHAIN_TYPEHASH;
    }

    function _setUp(address allocator_, TheCompact compactContract_, uint256 defaultNonce_) internal {
        allocator = allocator_;
        compactContract = compactContract_;
        defaultNonce = defaultNonce_;
    }

    function _composeNonceUint(address a, uint256 nonce) internal pure returns (uint256) {
        return (uint256(uint160(a)) << 96) | nonce;
    }

    function _composeNonce(address a, uint256 nonce) internal pure returns (bytes32) {
        return bytes32(_composeNonceUint(a, nonce));
    }
}

abstract contract CreateHash is MocksSetup {
    // stringified types
    string EIP712_DOMAIN_TYPE = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'; // Hashed inside the function
    // EIP712 domain type
    string name = 'The Compact';
    string version = '1';
    bytes32 internal constant EMPTY_HASH = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    function _hashCommitments(Lock[] memory commitments) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            hashes[i] = keccak256(
                abi.encode(LOCK_TYPEHASH, commitments[i].lockTag, commitments[i].token, commitments[i].amount)
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function _hashRecipientCallback(RecipientCallback[] memory rc) internal pure returns (bytes32) {
        if (rc.length == 0) {
            return EMPTY_HASH;
        } else if (rc.length != 1) {
            revert('RecipientCallback not supported in tests');
        } else {
            RecipientCallback memory rc_ = rc[0];
            bytes32[] memory commitmentsHashes = new bytes32[](rc_.compact.commitments.length);
            for (uint256 i = 0; i < rc_.compact.commitments.length; i++) {
                commitmentsHashes[i] = keccak256(
                    abi.encode(
                        MANDATE_LOCK_TYPEHASH,
                        rc_.compact.commitments[i].lockTag,
                        rc_.compact.commitments[i].token,
                        rc_.compact.commitments[i].amount
                    )
                );
            }
            bytes32 commitmentsHash = keccak256(abi.encodePacked(commitmentsHashes));

            return keccak256(
                abi.encode(
                    MANDATE_RECIPIENT_CALLBACK_TYPEHASH,
                    rc_.compact.arbiter,
                    rc_.compact.sponsor,
                    rc_.compact.nonce,
                    rc_.compact.expires,
                    commitmentsHash,
                    rc_.mandateHash
                )
            );
        }
    }

    function _hashFill(Fill memory f) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                MANDATE_FILL_TYPEHASH,
                f.chainId,
                f.tribunal,
                f.expires,
                f.fillToken,
                f.minimumFillAmount,
                f.baselinePriorityFee,
                f.scalingFactor,
                keccak256(abi.encodePacked(f.priceCurve)),
                f.recipient,
                _hashRecipientCallback(f.recipientCallback),
                f.salt
            )
        );
    }

    function _hashMandate(Mandate memory m) internal pure returns (bytes32 mandateHash, bytes32[] memory fillHashes) {
        fillHashes = new bytes32[](m.fills.length);
        for (uint256 i = 0; i < m.fills.length; i++) {
            fillHashes[i] = _hashFill(m.fills[i]);
        }
        mandateHash = keccak256(abi.encode(MANDATE_TYPEHASH, m.adjuster, keccak256(abi.encodePacked(fillHashes))));
    }

    function _deriveClaimHash(BatchCompact memory compact, Mandate memory mandate) internal pure returns (bytes32) {
        (bytes32 mandateHash,) = _hashMandate(mandate);
        return _deriveClaimHash(compact, mandateHash);
    }

    function _deriveClaimHash(BatchCompact memory compact, bytes32 mandateHash) internal pure returns (bytes32) {
        bytes32 commitmentsHash = _staticHashCommitments(compact.commitments);
        return keccak256(
            abi.encode(
                COMPACT_TYPEHASH_WITH_MANDATE,
                compact.arbiter,
                compact.sponsor,
                compact.nonce,
                compact.expires,
                commitmentsHash,
                mandateHash
            )
        );
    }

    function _staticHashCommitments(Lock[] memory commitments) private pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](commitments.length);
        for (uint256 i = 0; i < commitments.length; i++) {
            hashes[i] = keccak256(
                abi.encode(LOCK_TYPEHASH, commitments[i].lockTag, commitments[i].token, commitments[i].amount)
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function _buildFillHashes(Mandate memory m) internal pure returns (bytes32[] memory hashes) {
        hashes = new bytes32[](m.fills.length);
        for (uint256 i = 0; i < m.fills.length; i++) {
            hashes[i] = _hashFill(m.fills[i]);
        }
    }

    function _createDigest(BatchCompact memory data, Mandate memory mandate, address verifyingContract)
        internal
        view
        returns (bytes32 digest)
    {
        (bytes32 mandateHash,) = _hashMandate(mandate);
        bytes32 compactHash = _deriveClaimHash(data, mandateHash);
        // hash typed data
        digest = keccak256(
            abi.encodePacked(
                '\x19\x01', // backslash is needed to escape the character
                _domainSeparator(verifyingContract),
                compactHash
            )
        );
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
        bytes32 hash = _createDigest(data, mandate, verifyingContract);
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

        Fill memory mainFill;
        mainFill.chainId = defaultOutputChainId;
        mainFill.tribunal = tribunal;
        mainFill.expires = _getFillExpiration();
        mainFill.fillToken = defaultOutputToken;
        mainFill.minimumFillAmount = defaultMinimumAmount;
        mainFill.baselinePriorityFee = defaultBaselinePriorityFee;
        mainFill.scalingFactor = defaultScalingFactor;
        mainFill.priceCurve = defaultPriceCurve;
        mainFill.recipient = user;
        mainFill.salt = defaultSalt;

        mandate.adjuster = adjuster;
        mandate.fills = new Fill[](1);
        mandate.fills[0] = mainFill;
    }

    function _getCompact() internal returns (BatchCompact memory) {
        compact.expires = _getClaimExpiration();
        return compact;
    }

    function _getMandate() internal returns (Mandate memory) {
        mandate.fills[0].expires = _getFillExpiration();
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

        gaslessCrossChainOrder.originSettler = allocator;
        gaslessCrossChainOrder.user = compact_.sponsor;
        gaslessCrossChainOrder.nonce = _composeNonceUint(compact_.sponsor, defaultNonce);
        gaslessCrossChainOrder.originChainId = block.chainid;
        gaslessCrossChainOrder.openDeadline = uint32(_getClaimExpiration());
        gaslessCrossChainOrder.fillDeadline = uint32(_getFillExpiration());
        gaslessCrossChainOrder.orderDataType = ORDERDATA_GASLESS_TYPEHASH;
        gaslessCrossChainOrder.orderData = abi.encode(
            IERC7683Allocator.OrderDataGasless({
                order: IERC7683Allocator.Order({
                    arbiter: compact_.arbiter,
                    commitments: compact_.commitments,
                    mandate: mandate_
                }),
                deposit: false
            })
        );
    }

    function _getGaslessCrossChainOrder() internal view returns (IOriginSettler.GaslessCrossChainOrder memory) {
        return gaslessCrossChainOrder;
    }

    function _getGaslessCrossChainOrder(BatchCompact memory compact_, Mandate memory mandate_, bool deposit)
        internal
        view
        returns (IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_)
    {
        gaslessCrossChainOrder_.originSettler = allocator;
        gaslessCrossChainOrder_.user = compact_.sponsor;
        gaslessCrossChainOrder_.nonce = compact_.nonce;
        gaslessCrossChainOrder_.originChainId = block.chainid;
        gaslessCrossChainOrder_.openDeadline = uint32(compact_.expires);
        gaslessCrossChainOrder_.fillDeadline = uint32(mandate_.fills[0].expires);
        gaslessCrossChainOrder_.orderDataType = ORDERDATA_GASLESS_TYPEHASH;
        gaslessCrossChainOrder_.orderData = abi.encode(
            IERC7683Allocator.OrderDataGasless({
                order: IERC7683Allocator.Order({
                    arbiter: compact_.arbiter,
                    commitments: compact_.commitments,
                    mandate: mandate_
                }),
                deposit: deposit
            })
        );
        return gaslessCrossChainOrder_;
    }

    function _manipulateDeposit(IOriginSettler.GaslessCrossChainOrder memory gaslessCrossChainOrder_, bool deposit)
        internal
        pure
        returns (IOriginSettler.GaslessCrossChainOrder memory)
    {
        bytes memory orderData = gaslessCrossChainOrder_.orderData;
        assembly ("memory-safe") {
            mstore(add(orderData, 0x60), deposit)
        }
        return gaslessCrossChainOrder_;
    }
}

abstract contract OnChainCrossChainOrderData is CompactData {
    IOriginSettler.OnchainCrossChainOrder private onchainCrossChainOrder;

    function setUp() public virtual override {
        super.setUp();

        BatchCompact memory compact_ = _getCompact();
        Mandate memory mandate_ = _getMandate();

        onchainCrossChainOrder.fillDeadline = uint32(_getFillExpiration());
        onchainCrossChainOrder.orderDataType = ORDERDATA_ONCHAIN_TYPEHASH;
        onchainCrossChainOrder.orderData = abi.encode(
            IERC7683Allocator.OrderDataOnChain({
                order: IERC7683Allocator.Order({
                    arbiter: compact_.arbiter,
                    commitments: compact_.commitments,
                    mandate: mandate_
                }),
                expires: uint32(compact_.expires)
            })
        );
    }

    function _getOnChainCrossChainOrder() internal view returns (IOriginSettler.OnchainCrossChainOrder memory) {
        return onchainCrossChainOrder;
    }

    function _getOnChainCrossChainOrder(BatchCompact memory compact_, Mandate memory mandate_)
        internal
        view
        returns (IOriginSettler.OnchainCrossChainOrder memory)
    {
        IOriginSettler.OnchainCrossChainOrder memory onchainCrossChainOrder_ = IOriginSettler.OnchainCrossChainOrder({
            fillDeadline: uint32(mandate_.fills[0].expires),
            orderDataType: ORDERDATA_ONCHAIN_TYPEHASH,
            orderData: abi.encode(
                IERC7683Allocator.OrderDataOnChain({
                    order: IERC7683Allocator.Order({
                        arbiter: compact_.arbiter,
                        commitments: compact_.commitments,
                        mandate: mandate_
                    }),
                    expires: uint32(compact_.expires)
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
