// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';

import {TheCompact} from '@uniswap/the-compact/TheCompact.sol';
import {IAllocator} from '@uniswap/the-compact/interfaces/IAllocator.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';

import {Claim} from '@uniswap/the-compact/types/Claims.sol';
import {Component} from '@uniswap/the-compact/types/Components.sol';
import {COMPACT_TYPEHASH, Compact} from '@uniswap/the-compact/types/EIP712Types.sol';
import {ForcedWithdrawalStatus} from '@uniswap/the-compact/types/ForcedWithdrawalStatus.sol';
import {ResetPeriod} from '@uniswap/the-compact/types/ResetPeriod.sol';
import {Scope} from '@uniswap/the-compact/types/Scope.sol';

import {Test, console} from 'forge-std/Test.sol';

import {SimpleAllocator} from 'src/allocators/SimpleAllocator.sol';
import {ISimpleAllocator} from 'src/interfaces/ISimpleAllocator.sol';
import {ERC20Mock} from 'src/test/ERC20Mock.sol';
import {TestHelper} from 'test/util/TestHelper.sol';

abstract contract MocksSetup is Test, TestHelper {
    address user;
    uint256 userPK;
    address attacker;
    uint256 attackerPK;
    address arbiter;
    ERC20Mock usdc;
    TheCompact compactContract;
    SimpleAllocator simpleAllocator;
    bytes12 usdcLockTag;
    uint256 usdcId;
    bytes12 defaultLockTag;

    Scope defaultScope = Scope.Multichain;
    ResetPeriod defaultResetPeriod = ResetPeriod.OneMinute;
    uint256 defaultResetPeriodTime = 60;
    uint256 defaultAmount = 1000;
    uint256 defaultNonce = 1;
    uint256 defaultExpiration;

    function setUp() public virtual {
        arbiter = makeAddr('arbiter');
        usdc = new ERC20Mock('USDC', 'USDC');
        compactContract = new TheCompact();
        simpleAllocator = new SimpleAllocator(address(compactContract), 5, 100);
        usdcLockTag = _toLockTag(address(simpleAllocator), defaultScope, defaultResetPeriod);
        usdcId = _toId(defaultScope, defaultResetPeriod, address(simpleAllocator), address(usdc));
        defaultLockTag = _toLockTag(address(simpleAllocator), defaultScope, defaultResetPeriod);
        (user, userPK) = makeAddrAndKey('user');
        (attacker, attackerPK) = makeAddrAndKey('attacker');
    }
}

abstract contract CreateHash is Test {
    struct Allocator {
        bytes32 hash;
    }

    // stringified types
    string EIP712_DOMAIN_TYPE = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'; // Hashed inside the funcion
    // EIP712 domain type
    string name = 'The Compact';
    string version = '1';

    function _hashCompact(Compact memory data) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                COMPACT_TYPEHASH,
                data.arbiter,
                data.sponsor,
                data.nonce,
                data.expires,
                data.lockTag,
                data.token,
                data.amount
            )
        );
    }

    function _hashDigest(Compact memory data, address verifyingContract) internal view returns (bytes32) {
        // hash typed data
        return keccak256(
            abi.encodePacked(
                '\x19\x01', // backslash is needed to escape the character
                _domainSeparator(verifyingContract),
                keccak256(
                    abi.encode(
                        COMPACT_TYPEHASH,
                        data.arbiter,
                        data.sponsor,
                        data.nonce,
                        data.expires,
                        data.lockTag,
                        data.token,
                        data.amount
                    )
                )
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
}

abstract contract Deposited is MocksSetup {
    function setUp() public virtual override {
        super.setUp();

        vm.startPrank(user);

        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), defaultLockTag, defaultAmount, user);

        vm.stopPrank();
    }
}

abstract contract Locked is Deposited, CreateHash {
    bytes sponsorSignature;

    function setUp() public virtual override {
        super.setUp();

        vm.startPrank(user);

        defaultExpiration = vm.getBlockTimestamp() + defaultResetPeriodTime;
        Compact memory compact = Compact({
            arbiter: arbiter,
            sponsor: user,
            nonce: defaultNonce,
            lockTag: usdcLockTag,
            token: address(usdc),
            expires: defaultExpiration,
            amount: defaultAmount
        });
        simpleAllocator.lock(compact);

        vm.stopPrank();

        {
            bytes32 digest = _hashDigest(compact, address(compactContract));
            sponsorSignature = _signMessage(digest, userPK);
        }
    }
}

contract SimpleAllocator_Lock is MocksSetup, CreateHash {
    function test_revert_InvalidCaller() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.InvalidCaller.selector, user, attacker));
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: attacker,
                nonce: 1,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: block.timestamp + 1,
                amount: 1000
            })
        );
    }

    function test_revert_ClaimActive() public {
        vm.startPrank(user);

        // Mint, approve and deposit
        usdc.mint(user, defaultAmount);
        usdc.approve(address(compactContract), defaultAmount);
        compactContract.depositERC20(address(usdc), defaultLockTag, defaultAmount, user);

        // Successfully locked
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: block.timestamp + defaultResetPeriodTime,
                amount: defaultAmount
            })
        );

        vm.warp(block.timestamp + defaultResetPeriodTime - 1);

        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.ClaimActive.selector, user));
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce + 1,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: block.timestamp + defaultResetPeriodTime,
                amount: defaultAmount
            })
        );
    }

    function test_revert_InvalidExpiration_tooShort(uint128 delay_) public {
        delay_ = uint128(bound(delay_, 0, simpleAllocator.MIN_WITHDRAWAL_DELAY() - 1));
        uint256 expiration = vm.getBlockTimestamp() + delay_;
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.InvalidExpiration.selector, expiration));
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: 1,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: vm.getBlockTimestamp() + delay_,
                amount: 1000
            })
        );
    }

    function test_revert_InvalidExpiration_tooLong(uint128 delay_) public {
        vm.assume(delay_ > simpleAllocator.MAX_WITHDRAWAL_DELAY());
        uint256 expiration = vm.getBlockTimestamp() + delay_;
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.InvalidExpiration.selector, expiration));
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: 1,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: vm.getBlockTimestamp() + delay_,
                amount: 1000
            })
        );
    }

    function test_revert_ForceWithdrawalAvailable_ExpirationLongerThenResetPeriod(uint8 delay_) public {
        // Use bound to ensure delay_ is within valid range but greater than resetPeriod
        delay_ = uint8(
            bound(
                delay_,
                simpleAllocator.MIN_WITHDRAWAL_DELAY() > defaultResetPeriodTime
                    ? simpleAllocator.MIN_WITHDRAWAL_DELAY() + 1
                    : defaultResetPeriodTime + 1,
                simpleAllocator.MAX_WITHDRAWAL_DELAY() - 1
            )
        );

        uint256 expiration = vm.getBlockTimestamp() + delay_;
        uint256 maxExpiration = vm.getBlockTimestamp() + defaultResetPeriodTime;
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(ISimpleAllocator.ForceWithdrawalAvailable.selector, expiration, maxExpiration)
        );
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: 1,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: expiration,
                amount: 1000
            })
        );
    }

    function test_revert_ForceWithdrawalAvailable_ScheduledForceWithdrawal() public {
        vm.startPrank(user);
        compactContract.enableForcedWithdrawal(usdcId);

        // move time forward
        vm.warp(vm.getBlockTimestamp() + 1);

        // This expiration should be fine, if the force withdrawal was not enabled
        uint256 expiration = vm.getBlockTimestamp() + defaultResetPeriodTime;
        // check force withdrawal
        (ForcedWithdrawalStatus status, uint256 expires) = compactContract.getForcedWithdrawalStatus(user, usdcId);
        assertTrue(status == ForcedWithdrawalStatus.Pending);
        assertEq(expires, expiration - 1);

        vm.expectRevert(
            abi.encodeWithSelector(ISimpleAllocator.ForceWithdrawalAvailable.selector, expiration, expiration - 1)
        );
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: 1,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: expiration,
                amount: 1000
            })
        );
    }

    function test_revert_ForceWithdrawalAvailable_ActiveForceWithdrawal() public {
        vm.startPrank(user);
        compactContract.enableForcedWithdrawal(usdcId);

        // move time forward
        uint256 forceWithdrawalTimestamp = vm.getBlockTimestamp() + defaultResetPeriodTime;
        vm.warp(forceWithdrawalTimestamp);

        // This expiration should be fine, if the force withdrawal was not enabled
        uint256 expiration = vm.getBlockTimestamp() + defaultResetPeriodTime;
        // check force withdrawal
        (ForcedWithdrawalStatus status, uint256 expires) = compactContract.getForcedWithdrawalStatus(user, usdcId);
        assertEq(status == ForcedWithdrawalStatus.Enabled, true);
        assertEq(expires, forceWithdrawalTimestamp);

        vm.expectRevert(
            abi.encodeWithSelector(
                ISimpleAllocator.ForceWithdrawalAvailable.selector, expiration, forceWithdrawalTimestamp
            )
        );
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: 1,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: expiration,
                amount: 1000
            })
        );
    }

    function test_revert_NonceAlreadyInUse(uint256 nonce_) public {
        // Mint, approve and deposit
        uint256 amount = 1 ether;
        vm.startPrank(user);
        usdc.mint(user, amount);
        usdc.approve(address(compactContract), amount);
        compactContract.depositERC20(address(usdc), defaultLockTag, amount, user);

        uint256 expiration = vm.getBlockTimestamp() + 60;
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce_,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: expiration,
                amount: amount
            })
        );

        vm.warp(expiration + 1);

        expiration += 60;

        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.NonceAlreadyInUse.selector, nonce_));
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce_,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: expiration,
                amount: amount
            })
        );
    }

    function test_revert_InsufficientBalance(uint256 balance_, uint256 amount_) public {
        vm.assume(amount_ > 0);
        balance_ = bound(balance_, 0, amount_ - 1);

        vm.startPrank(user);

        // Mint, approve and deposit
        usdc.mint(user, balance_);
        usdc.approve(address(compactContract), balance_);
        if (balance_ > 0) {
            compactContract.depositERC20(address(usdc), defaultLockTag, balance_, user);
        }

        // Check balance
        assertEq(compactContract.balanceOf(user, usdcId), balance_);

        vm.expectRevert(
            abi.encodeWithSelector(ISimpleAllocator.InsufficientBalance.selector, user, usdcId, balance_, amount_)
        );
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: 1,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: block.timestamp + defaultResetPeriodTime,
                amount: amount_
            })
        );
    }

    function test_successfullyLocked(uint256 nonce_, uint128 amount_, uint32 delay_) public {
        vm.assume(amount_ > 0);
        delay_ = uint32(
            bound(
                delay_,
                simpleAllocator.MIN_WITHDRAWAL_DELAY() + 1,
                defaultResetPeriodTime < simpleAllocator.MAX_WITHDRAWAL_DELAY()
                    ? defaultResetPeriodTime
                    : simpleAllocator.MAX_WITHDRAWAL_DELAY() - 1
            )
        );

        vm.startPrank(user);

        // Mint, approve and deposit
        usdc.mint(user, amount_);
        usdc.approve(address(compactContract), amount_);
        compactContract.depositERC20(address(usdc), defaultLockTag, amount_, user);

        // Check no lock exists
        (uint256 amountBefore, uint256 expiresBefore) = simpleAllocator.checkTokensLocked(usdcId, user);

        assertEq(amountBefore, 0);
        assertEq(expiresBefore, 0);

        uint256 expiration = vm.getBlockTimestamp() + delay_;
        vm.expectEmit(true, true, false, true);
        emit ISimpleAllocator.Locked(user, usdcLockTag, address(usdc), amount_, expiration);
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce_,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: expiration,
                amount: amount_
            })
        );

        // Check lock exists
        (uint256 amountAfter, uint256 expiresAfter) = simpleAllocator.checkTokensLocked(usdcId, user);

        assertEq(amountAfter, amount_);
        assertEq(expiresAfter, expiration);
    }

    function test_successfullyLocked_AfterNonceConsumption(
        uint256 nonce_,
        uint256 noncePrev_,
        uint128 amount_,
        uint32 delay_
    ) public {
        delay_ = uint32(
            bound(
                delay_,
                simpleAllocator.MIN_WITHDRAWAL_DELAY() + 1,
                defaultResetPeriodTime < simpleAllocator.MAX_WITHDRAWAL_DELAY()
                    ? defaultResetPeriodTime
                    : simpleAllocator.MAX_WITHDRAWAL_DELAY() - 1
            )
        );
        vm.assume(noncePrev_ != nonce_);
        vm.assume(amount_ > 0);

        vm.startPrank(user);

        // Mint, approve and deposit the amount twice
        usdc.mint(user, uint256(amount_) * 2);
        usdc.approve(address(compactContract), uint256(amount_) * 2);
        compactContract.depositERC20(address(usdc), defaultLockTag, uint256(amount_) * 2, user);

        // Create a previous lock
        uint256 expirationPrev = vm.getBlockTimestamp() + delay_;
        vm.expectEmit(true, true, false, true);
        emit ISimpleAllocator.Locked(user, usdcLockTag, address(usdc), amount_, expirationPrev);
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: noncePrev_,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: expirationPrev,
                amount: amount_
            })
        );

        // Check a previous lock exists
        (uint256 amountBefore, uint256 expiresBefore) = simpleAllocator.checkTokensLocked(usdcId, user);
        assertEq(amountBefore, amount_);
        assertEq(expiresBefore, expirationPrev);

        // Check for revert if previous nonce not consumed
        uint256 expiration = vm.getBlockTimestamp() + delay_;

        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.ClaimActive.selector, user));
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce_,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: expiration,
                amount: amount_
            })
        );
        vm.stopPrank();

        // Claim previous lock
        Compact memory compact = Compact({
            arbiter: arbiter,
            sponsor: user,
            nonce: noncePrev_,
            lockTag: usdcLockTag,
            token: address(usdc),
            expires: expirationPrev,
            amount: amount_
        });
        bytes32 digest = _hashDigest(compact, address(compactContract));

        Component[] memory claimants = new Component[](1);
        claimants[0] = Component({
            claimant: uint256(uint160(address(this))), // withdrawal
            amount: amount_
        });
        Claim memory claim = Claim({
            allocatorData: '',
            sponsorSignature: _signMessage(digest, userPK),
            sponsor: user,
            nonce: noncePrev_,
            expires: expirationPrev,
            witness: bytes32(0),
            witnessTypestring: '',
            id: usdcId,
            allocatedAmount: amount_,
            claimants: claimants
        });

        vm.prank(address(arbiter));
        compactContract.claim(claim);

        vm.prank(user);

        vm.expectEmit(true, true, false, true);
        emit ISimpleAllocator.Locked(user, usdcLockTag, address(usdc), amount_, expiration);
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce_,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: expiration,
                amount: amount_
            })
        );

        // Check lock exists
        (uint256 amountAfter, uint256 expiresAfter) = simpleAllocator.checkTokensLocked(usdcId, user);

        assertEq(amountAfter, amount_);
        assertEq(expiresAfter, expiration);
    }
}

contract SimpleAllocator_Attest is Deposited {
    function test_revert_InvalidCaller_NotCompact() public {
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(ISimpleAllocator.InvalidCaller.selector, attacker, address(compactContract))
        );
        simpleAllocator.attest(address(user), address(user), address(usdc), usdcId, defaultAmount);
    }

    function test_revert_InsufficientBalance_NoActiveLock(uint128 falseAmount_) public {
        vm.assume(falseAmount_ > defaultAmount);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISimpleAllocator.InsufficientBalance.selector, user, usdcId, defaultAmount, falseAmount_
            )
        );
        compactContract.transfer(attacker, usdcId, falseAmount_);
    }

    function test_revert_InsufficientBalance_ActiveLock() public {
        vm.startPrank(user);

        // Lock a single token
        uint256 defaultExpiration_ = vm.getBlockTimestamp() + defaultResetPeriodTime;
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: defaultExpiration_,
                amount: 1
            })
        );

        // At this point, the deposited defaultAmount is not fully available anymore, because one of the tokens was locked

        // Revert if we try to transfer all of the deposited tokens
        vm.expectRevert(
            abi.encodeWithSelector(
                ISimpleAllocator.InsufficientBalance.selector, user, usdcId, defaultAmount, defaultAmount + 1
            )
        );
        compactContract.transfer(attacker, usdcId, defaultAmount);
    }

    function test_successfullyAttested_returnsSelector() public {
        bytes4 selector = bytes4(0x1a808f91);

        uint32 transferAmount = 10;
        uint32 lockedAmount = 90;

        address otherUser = makeAddr('otherUser');

        // Lock tokens
        uint256 defaultExpiration_ = vm.getBlockTimestamp() + defaultResetPeriodTime;
        vm.startPrank(user);
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: defaultExpiration_,
                amount: lockedAmount
            })
        );
        compactContract.transfer(otherUser, usdcId, transferAmount);
        vm.stopPrank();

        vm.prank(address(compactContract));
        bytes4 returnedSelector = simpleAllocator.attest(user, user, otherUser, usdcId, transferAmount);
        assertEq(returnedSelector, selector);
    }

    function test_successfullyAttested(uint32 lockedAmount_, uint32 transferAmount_) public {
        transferAmount_ = uint32(bound(transferAmount_, 0, defaultAmount));
        lockedAmount_ = uint32(bound(lockedAmount_, 0, defaultAmount - transferAmount_));

        address otherUser = makeAddr('otherUser');

        // Lock tokens
        uint256 defaultExpiration_ = vm.getBlockTimestamp() + defaultResetPeriodTime;
        vm.startPrank(user);
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: defaultExpiration_,
                amount: lockedAmount_
            })
        );

        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(user, user, otherUser, usdcId, transferAmount_);
        compactContract.transfer(otherUser, usdcId, transferAmount_);

        // Check that the other user has the tokens
        assertEq(compactContract.balanceOf(otherUser, usdcId), transferAmount_);
        assertEq(compactContract.balanceOf(user, usdcId), defaultAmount - transferAmount_);
    }
}

contract SimpleAllocator_AuthorizeClaim is Locked {
    function test_revert_InvalidLock_NoActiveLock() public {
        uint256 falseNonce = defaultNonce + 1; // use a nonce that is not the one used to lock the tokens

        Compact memory compact = Compact({
            arbiter: arbiter,
            sponsor: user,
            nonce: falseNonce,
            lockTag: usdcLockTag,
            token: address(usdc),
            expires: defaultExpiration,
            amount: defaultAmount
        });

        bytes32 claimHash = _hashCompact(compact);
        bytes32 digest = _hashDigest(compact, address(compactContract));

        Component[] memory claimants = new Component[](1);
        claimants[0] = Component({
            claimant: uint256(uint160(address(this))), // withdrawal
            amount: defaultAmount
        });
        Claim memory claim = Claim({
            allocatorData: '',
            sponsorSignature: _signMessage(digest, userPK),
            sponsor: user,
            nonce: falseNonce,
            expires: defaultExpiration,
            witness: bytes32(0),
            witnessTypestring: '',
            id: usdcId,
            allocatedAmount: defaultAmount,
            claimants: claimants
        });

        vm.prank(address(arbiter));
        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.InvalidLock.selector, claimHash, 0));
        compactContract.claim(claim);
    }

    function test_successfullyValidateClaim() public {
        assertEq(compactContract.balanceOf(user, usdcId), defaultAmount);
        assertEq(usdc.balanceOf(address(this)), 0);

        Component[] memory claimants = new Component[](1);
        claimants[0] = Component({
            claimant: uint256(uint160(address(this))), // withdrawal
            amount: defaultAmount
        });
        Claim memory claim = Claim({
            allocatorData: '',
            sponsorSignature: sponsorSignature,
            sponsor: user,
            nonce: defaultNonce,
            expires: defaultExpiration,
            witness: bytes32(0),
            witnessTypestring: '',
            id: usdcId,
            allocatedAmount: defaultAmount,
            claimants: claimants
        });

        vm.prank(address(arbiter));
        compactContract.claim(claim);

        assertEq(compactContract.balanceOf(user, usdcId), 0);
        assertEq(usdc.balanceOf(address(this)), defaultAmount);
    }
}

contract SimpleAllocator_CheckTokensLocked is Locked {
    function test_checkTokensLocked_NoActiveLock() public {
        address otherUser = makeAddr('otherUser');
        (uint256 amount, uint256 expires) = simpleAllocator.checkTokensLocked(usdcId, otherUser);
        assertEq(amount, 0);
        assertEq(expires, 0);
    }

    function test_checkTokensLocked_ExpiredLock() public {
        (uint256 amount, uint256 expires) = simpleAllocator.checkTokensLocked(usdcId, user);
        assertEq(amount, defaultAmount);
        assertEq(expires, defaultExpiration);

        vm.warp(defaultExpiration);

        (amount, expires) = simpleAllocator.checkTokensLocked(usdcId, user);
        assertEq(amount, 0);
        assertEq(expires, 0);
    }

    function test_checkTokensLocked_AfterClaim() public {
        (uint256 amount, uint256 expires) = simpleAllocator.checkTokensLocked(usdcId, user);
        assertEq(amount, defaultAmount);
        assertEq(expires, defaultExpiration);

        Component[] memory claimants = new Component[](1);
        claimants[0] = Component({
            claimant: uint256(uint160(address(this))), // withdrawal
            amount: defaultAmount
        });
        Claim memory claim = Claim({
            allocatorData: '',
            sponsorSignature: sponsorSignature,
            sponsor: user,
            nonce: defaultNonce,
            expires: defaultExpiration,
            witness: bytes32(0),
            witnessTypestring: '',
            id: usdcId,
            allocatedAmount: defaultAmount,
            claimants: claimants
        });
        vm.prank(address(arbiter));
        compactContract.claim(claim);

        (amount, expires) = simpleAllocator.checkTokensLocked(usdcId, user);
        assertEq(amount, 0);
        assertEq(expires, 0);
    }

    function test_checkTokensLocked_ActiveLock() public {
        vm.warp(defaultExpiration - 1);

        (uint256 amount, uint256 expires) = simpleAllocator.checkTokensLocked(usdcId, user);
        assertEq(amount, defaultAmount);
        assertEq(expires, defaultExpiration);
    }

    function test_checkCompactLocked_NoActiveLock() public {
        address otherUser = makeAddr('otherUser');
        (bool locked, uint256 expires) = simpleAllocator.checkCompactLocked(
            Compact({
                arbiter: arbiter,
                sponsor: otherUser,
                nonce: defaultNonce,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: defaultExpiration,
                amount: defaultAmount
            })
        );
        assertEq(locked, false);
        assertEq(expires, 0);
    }

    function test_checkCompactLocked_ExpiredLock() public {
        // Confirm that a lock is previously active
        (bool locked, uint256 expires) = simpleAllocator.checkCompactLocked(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: defaultExpiration,
                amount: defaultAmount
            })
        );
        assertEq(locked, true);
        assertEq(expires, defaultExpiration);

        // Move time forward so lock has expired
        vm.warp(defaultExpiration);

        // Check that the lock is no longer active
        (locked, expires) = simpleAllocator.checkCompactLocked(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: defaultExpiration,
                amount: defaultAmount
            })
        );
        assertEq(locked, false);
        assertEq(expires, 0);
    }

    function test_checkCompactLocked_AfterClaim() public {
        Component[] memory claimants = new Component[](1);
        claimants[0] = Component({
            claimant: uint256(uint160(address(this))), // withdrawal
            amount: defaultAmount
        });
        Claim memory claim = Claim({
            allocatorData: '',
            sponsorSignature: sponsorSignature,
            sponsor: user,
            nonce: defaultNonce,
            expires: defaultExpiration,
            witness: bytes32(0),
            witnessTypestring: '',
            id: usdcId,
            allocatedAmount: defaultAmount,
            claimants: claimants
        });
        vm.prank(address(arbiter));
        compactContract.claim(claim);

        // Check that the lock is no longer active
        (bool locked, uint256 expiration) = simpleAllocator.checkCompactLocked(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: defaultExpiration,
                amount: defaultAmount
            })
        );
        assertFalse(locked);
        assertEq(expiration, 0);
    }

    function test_checkCompactLocked_successfully() public {
        // Move time forward to last second before expiration
        vm.warp(defaultExpiration - 1);

        // Confirm that a lock is active
        (bool locked, uint256 expires) = simpleAllocator.checkCompactLocked(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                lockTag: usdcLockTag,
                token: address(usdc),
                expires: defaultExpiration,
                amount: defaultAmount
            })
        );
        assertEq(locked, true);
        assertEq(expires, defaultExpiration);
    }

    // Check a force withdrawal will impact the expiration
}
