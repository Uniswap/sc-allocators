// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {COMPACT_TYPEHASH, Compact} from '@uniswap/the-compact/types/EIP712Types.sol';
import {ForcedWithdrawalStatus} from '@uniswap/the-compact/types/ForcedWithdrawalStatus.sol';
import {Test} from 'forge-std/Test.sol';

import {console} from 'forge-std/console.sol';
import {SimpleAllocator} from 'src/allocators/SimpleAllocator.sol';
import {ISimpleAllocator} from 'src/interfaces/ISimpleAllocator.sol';
import {ERC20Mock} from 'src/test/ERC20Mock.sol';
import {TheCompactMock} from 'src/test/TheCompactMock.sol';

abstract contract MocksSetup is Test {
    address user;
    uint256 userPK;
    address attacker;
    uint256 attackerPK;
    address arbiter;
    ERC20Mock usdc;
    TheCompactMock compactContract;
    SimpleAllocator simpleAllocator;
    uint256 usdcId;

    uint256 defaultResetPeriod = 60;
    uint256 defaultAmount = 1000;
    uint256 defaultNonce = 1;
    uint256 defaultExpiration;

    function setUp() public virtual {
        arbiter = makeAddr('arbiter');
        usdc = new ERC20Mock('USDC', 'USDC');
        compactContract = new TheCompactMock();
        simpleAllocator = new SimpleAllocator(address(compactContract), 5, 100);
        usdcId = compactContract.getTokenId(address(usdc), address(simpleAllocator));
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
    string version = '0';

    function _hashCompact(Compact memory data, address verifyingContract) internal view returns (bytes32) {
        // hash typed data
        return keccak256(
            abi.encodePacked(
                '\x19\x01', // backslash is needed to escape the character
                _domainSeparator(verifyingContract),
                keccak256(
                    abi.encode(
                        COMPACT_TYPEHASH, data.arbiter, data.sponsor, data.nonce, data.expires, data.id, data.amount
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
        compactContract.deposit(address(usdc), address(simpleAllocator), defaultAmount);

        vm.stopPrank();
    }
}

abstract contract Locked is Deposited {
    function setUp() public virtual override {
        super.setUp();

        vm.startPrank(user);

        defaultExpiration = vm.getBlockTimestamp() + defaultResetPeriod;
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
                expires: defaultExpiration,
                amount: defaultAmount
            })
        );

        vm.stopPrank();
    }
}

contract SimpleAllocator_Lock is MocksSetup {
    function test_revert_InvalidCaller() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.InvalidCaller.selector, user, attacker));
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: attacker,
                nonce: 1,
                id: usdcId,
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
        compactContract.deposit(address(usdc), address(simpleAllocator), defaultAmount);

        // Successfully locked
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
                expires: block.timestamp + defaultResetPeriod,
                amount: defaultAmount
            })
        );

        vm.warp(block.timestamp + defaultResetPeriod - 1);

        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.ClaimActive.selector, user));
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce + 1,
                id: usdcId,
                expires: block.timestamp + defaultResetPeriod,
                amount: defaultAmount
            })
        );
    }

    function test_revert_InvalidExpiration_tooShort(uint128 delay_) public {
        vm.assume(delay_ < simpleAllocator.MIN_WITHDRAWAL_DELAY());
        uint256 expiration = vm.getBlockTimestamp() + delay_;
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.InvalidExpiration.selector, expiration));
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: 1,
                id: usdcId,
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
                id: usdcId,
                expires: vm.getBlockTimestamp() + delay_,
                amount: 1000
            })
        );
    }

    function test_revert_ForceWithdrawalAvailable_ExpirationLongerThenResetPeriod(uint8 delay_) public {
        vm.assume(delay_ > simpleAllocator.MIN_WITHDRAWAL_DELAY());
        vm.assume(delay_ < simpleAllocator.MAX_WITHDRAWAL_DELAY());
        vm.assume(delay_ > defaultResetPeriod);

        uint256 expiration = vm.getBlockTimestamp() + delay_;
        uint256 maxExpiration = vm.getBlockTimestamp() + defaultResetPeriod;
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(ISimpleAllocator.ForceWithdrawalAvailable.selector, expiration, maxExpiration)
        );
        simpleAllocator.lock(
            Compact({arbiter: arbiter, sponsor: user, nonce: 1, id: usdcId, expires: expiration, amount: 1000})
        );
    }

    function test_revert_ForceWithdrawalAvailable_ScheduledForceWithdrawal() public {
        vm.startPrank(user);
        compactContract.enableForceWithdrawal(usdcId);

        // move time forward
        vm.warp(vm.getBlockTimestamp() + 1);

        // This expiration should be fine, if the force withdrawal was not enabled
        uint256 expiration = vm.getBlockTimestamp() + defaultResetPeriod;
        // check force withdrawal
        (ForcedWithdrawalStatus status, uint256 expires) = compactContract.getForcedWithdrawalStatus(user, usdcId);
        assertEq(status == ForcedWithdrawalStatus.Enabled, true);
        assertEq(expires, expiration - 1);

        vm.expectRevert(
            abi.encodeWithSelector(ISimpleAllocator.ForceWithdrawalAvailable.selector, expiration, expiration - 1)
        );
        simpleAllocator.lock(
            Compact({arbiter: arbiter, sponsor: user, nonce: 1, id: usdcId, expires: expiration, amount: 1000})
        );
    }

    function test_revert_ForceWithdrawalAvailable_ActiveForceWithdrawal() public {
        vm.startPrank(user);
        compactContract.enableForceWithdrawal(usdcId);

        // move time forward
        uint256 forceWithdrawalTimestamp = vm.getBlockTimestamp() + defaultResetPeriod;
        vm.warp(forceWithdrawalTimestamp);

        // This expiration should be fine, if the force withdrawal was not enabled
        uint256 expiration = vm.getBlockTimestamp() + defaultResetPeriod;
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
            Compact({arbiter: arbiter, sponsor: user, nonce: 1, id: usdcId, expires: expiration, amount: 1000})
        );
    }

    function test_revert_NonceAlreadyConsumed(uint256 nonce_) public {
        vm.startPrank(user);
        uint256[] memory nonces = new uint256[](1);
        nonces[0] = nonce_;
        compactContract.consume(nonces);
        assertEq(compactContract.hasConsumedAllocatorNonce(nonce_, address(simpleAllocator)), true);

        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.NonceAlreadyConsumed.selector, nonce_));
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: nonce_,
                id: usdcId,
                expires: block.timestamp + defaultResetPeriod,
                amount: 1000
            })
        );
    }

    function test_revert_InsufficientBalance(uint256 balance_, uint256 amount_) public {
        vm.assume(balance_ < amount_);

        vm.startPrank(user);

        // Mint, approve and deposit
        usdc.mint(user, balance_);
        usdc.approve(address(compactContract), balance_);
        compactContract.deposit(address(usdc), address(simpleAllocator), balance_);

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
                id: usdcId,
                expires: block.timestamp + defaultResetPeriod,
                amount: amount_
            })
        );
    }

    function test_successfullyLocked(uint256 nonce_, uint128 amount_, uint32 delay_) public {
        vm.assume(delay_ > simpleAllocator.MIN_WITHDRAWAL_DELAY());
        vm.assume(delay_ < simpleAllocator.MAX_WITHDRAWAL_DELAY());
        vm.assume(delay_ <= defaultResetPeriod);

        vm.startPrank(user);

        // Mint, approve and deposit
        usdc.mint(user, amount_);
        usdc.approve(address(compactContract), amount_);
        compactContract.deposit(address(usdc), address(simpleAllocator), amount_);

        // Check no lock exists
        (uint256 amountBefore, uint256 expiresBefore) = simpleAllocator.checkTokensLocked(usdcId, user);

        assertEq(amountBefore, 0);
        assertEq(expiresBefore, 0);

        uint256 expiration = vm.getBlockTimestamp() + delay_;
        vm.expectEmit(true, true, false, true);
        emit ISimpleAllocator.Locked(user, usdcId, amount_, expiration);
        simpleAllocator.lock(
            Compact({arbiter: arbiter, sponsor: user, nonce: nonce_, id: usdcId, expires: expiration, amount: amount_})
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
        vm.assume(delay_ > simpleAllocator.MIN_WITHDRAWAL_DELAY());
        vm.assume(delay_ < simpleAllocator.MAX_WITHDRAWAL_DELAY());
        vm.assume(delay_ <= defaultResetPeriod);
        vm.assume(noncePrev_ != nonce_);

        vm.startPrank(user);

        // Mint, approve and deposit
        usdc.mint(user, amount_);
        usdc.approve(address(compactContract), amount_);
        compactContract.deposit(address(usdc), address(simpleAllocator), amount_);

        // Create a previous lock
        uint256 expirationPrev = vm.getBlockTimestamp() + delay_;
        vm.expectEmit(true, true, false, true);
        emit ISimpleAllocator.Locked(user, usdcId, amount_, expirationPrev);
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: noncePrev_,
                id: usdcId,
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
            Compact({arbiter: arbiter, sponsor: user, nonce: nonce_, id: usdcId, expires: expiration, amount: amount_})
        );

        // Consume previous nonce
        uint256[] memory nonces = new uint256[](1);
        nonces[0] = noncePrev_;
        vm.stopPrank();
        vm.prank(address(simpleAllocator));
        compactContract.consume(nonces);

        vm.prank(user);

        vm.expectEmit(true, true, false, true);
        emit ISimpleAllocator.Locked(user, usdcId, amount_, expiration);
        simpleAllocator.lock(
            Compact({arbiter: arbiter, sponsor: user, nonce: nonce_, id: usdcId, expires: expiration, amount: amount_})
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

    function test_revert_InvalidCaller_FromNotOperator() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.InvalidCaller.selector, attacker, user));
        compactContract.transfer(user, attacker, defaultAmount, address(usdc), address(simpleAllocator));
    }

    function test_revert_InsufficientBalance_NoActiveLock(uint128 falseAmount_) public {
        vm.assume(falseAmount_ > defaultAmount);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISimpleAllocator.InsufficientBalance.selector, user, usdcId, defaultAmount, falseAmount_
            )
        );
        compactContract.transfer(user, attacker, falseAmount_, address(usdc), address(simpleAllocator));
    }

    function test_revert_InsufficientBalance_ActiveLock() public {
        vm.startPrank(user);

        // Lock a single token
        uint256 defaultExpiration_ = vm.getBlockTimestamp() + defaultResetPeriod;
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
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
        compactContract.transfer(user, attacker, defaultAmount, address(usdc), address(simpleAllocator));
    }

    function test_successfullyAttested(uint32 lockedAmount_, uint32 transferAmount_) public {
        vm.assume(uint256(transferAmount_) + uint256(lockedAmount_) <= defaultAmount);

        address otherUser = makeAddr('otherUser');

        vm.startPrank(user);
        // Lock tokens
        uint256 defaultExpiration_ = vm.getBlockTimestamp() + defaultResetPeriod;
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
                expires: defaultExpiration_,
                amount: lockedAmount_
            })
        );

        vm.expectEmit(true, true, true, true);
        emit ERC6909.Transfer(address(0), user, otherUser, usdcId, transferAmount_);
        compactContract.transfer(user, otherUser, transferAmount_, address(usdc), address(simpleAllocator));

        // Check that the other user has the tokens
        assertEq(compactContract.balanceOf(otherUser, usdcId), transferAmount_);
        assertEq(compactContract.balanceOf(user, usdcId), defaultAmount - transferAmount_);
    }
}

contract SimpleAllocator_IsValidSignature is Deposited, CreateHash {
    function test_revert_InvalidLock_NoActiveLock() public {
        bytes32 digest = _hashCompact(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
                expires: block.timestamp + defaultResetPeriod,
                amount: defaultAmount
            }),
            address(compactContract)
        );

        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.InvalidLock.selector, digest, 0));
        simpleAllocator.isValidSignature(digest, '');
    }

    function test_revert_InvalidLock_ExpiredLock() public {
        vm.startPrank(user);

        // Lock tokens
        uint256 defaultExpiration_ = vm.getBlockTimestamp() + defaultResetPeriod;
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
                expires: defaultExpiration_,
                amount: defaultAmount
            })
        );

        // Move time forward so lock has expired
        vm.warp(block.timestamp + defaultResetPeriod);

        bytes32 digest = _hashCompact(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
                expires: defaultExpiration_,
                amount: defaultAmount
            }),
            address(compactContract)
        );

        vm.expectRevert(abi.encodeWithSelector(ISimpleAllocator.InvalidLock.selector, digest, defaultExpiration_));
        simpleAllocator.isValidSignature(digest, '');
    }

    function test_successfullyValidated() public {
        vm.startPrank(user);

        // Lock tokens
        uint256 defaultExpiration_ = vm.getBlockTimestamp() + defaultResetPeriod;
        simpleAllocator.lock(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
                expires: defaultExpiration_,
                amount: defaultAmount
            })
        );

        // Move time forward so lock has expired
        vm.warp(block.timestamp + defaultResetPeriod - 1);

        bytes32 digest = _hashCompact(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
                expires: defaultExpiration_,
                amount: defaultAmount
            }),
            address(compactContract)
        );

        bytes4 selector = simpleAllocator.isValidSignature(digest, '');
        assertEq(selector, IERC1271.isValidSignature.selector);
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

    function test_checkTokensLocked_NonceConsumed() public {
        (uint256 amount, uint256 expires) = simpleAllocator.checkTokensLocked(usdcId, user);
        assertEq(amount, defaultAmount);
        assertEq(expires, defaultExpiration);

        uint256[] memory nonces = new uint256[](1);
        nonces[0] = defaultNonce;
        vm.prank(address(simpleAllocator));
        compactContract.consume(nonces);

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
                id: usdcId,
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
                id: usdcId,
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
                id: usdcId,
                expires: defaultExpiration,
                amount: defaultAmount
            })
        );
        assertEq(locked, false);
        assertEq(expires, 0);
    }

    function test_checkCompactLocked_NonceConsumed() public {
        // Confirm that a lock is previously active
        (bool locked, uint256 expires) = simpleAllocator.checkCompactLocked(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
                expires: defaultExpiration,
                amount: defaultAmount
            })
        );
        assertEq(locked, true);
        assertEq(expires, defaultExpiration);

        // Consume nonce
        uint256[] memory nonces = new uint256[](1);
        nonces[0] = defaultNonce;
        vm.prank(address(simpleAllocator));
        compactContract.consume(nonces);

        // Check that the lock is no longer active
        (locked, expires) = simpleAllocator.checkCompactLocked(
            Compact({
                arbiter: arbiter,
                sponsor: user,
                nonce: defaultNonce,
                id: usdcId,
                expires: defaultExpiration,
                amount: defaultAmount
            })
        );
        assertEq(locked, false);
        assertEq(expires, 0);
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
                id: usdcId,
                expires: defaultExpiration,
                amount: defaultAmount
            })
        );
        assertEq(locked, true);
        assertEq(expires, defaultExpiration);
    }

    // Check a force withdrawal will impact the expiration
}
