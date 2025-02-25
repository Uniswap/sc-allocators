// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";
import { SimpleERC7683Allocator } from "src/allocators/SimpleERC7683Allocator.sol";
import { IOriginSettler } from "src/interfaces/ERC7683/IOriginSettler.sol";
import { ITheCompact } from "@uniswap/the-compact/interfaces/ITheCompact.sol";
import { Compact, COMPACT_TYPEHASH } from "@uniswap/the-compact/types/EIP712Types.sol";
import { ForcedWithdrawalStatus } from "@uniswap/the-compact/types/ForcedWithdrawalStatus.sol";
import { TheCompactMock } from "src/test/TheCompactMock.sol";
import { ERC20Mock } from "src/test/ERC20Mock.sol";
import { ERC6909 } from "@solady/tokens/ERC6909.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { console } from "forge-std/console.sol";

abstract contract MocksSetup is Test {
    address user;
    uint256 userPK;
    address attacker;
    uint256 attackerPK;
    address arbiter;
    ERC20Mock usdc;
    TheCompactMock compactContract;
    SimpleERC7683Allocator simpleERC7683Allocator;
    uint256 usdcId;

    uint256 defaultResetPeriod = 60;
    uint256 defaultAmount = 1000;
    uint256 defaultNonce = 1;
    uint256 defaultExpiration;

    function setUp() public virtual {
        arbiter = makeAddr("arbiter");
        usdc = new ERC20Mock("USDC", "USDC");
        compactContract = new TheCompactMock();
        simpleERC7683Allocator = new SimpleERC7683Allocator(address(compactContract), 5, 100);
        usdcId = compactContract.getTokenId(address(usdc), address(simpleERC7683Allocator));
        (user, userPK) = makeAddrAndKey("user");
        (attacker, attackerPK) = makeAddrAndKey("attacker");
    }
}

abstract contract CreateHash is Test {
    struct Allocator {
        bytes32 hash;
    }

    // stringified types
    string EIP712_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"; // Hashed inside the function
    // EIP712 domain type
    string name = "The Compact";
    string version = "0";

    function _hashCompact(Compact memory data, address verifyingContract) internal view returns (bytes32) {
        // hash typed data
        return keccak256(
            abi.encodePacked(
                "\x19\x01", // backslash is needed to escape the character
                _domainSeparator(verifyingContract),
                keccak256(abi.encode(COMPACT_TYPEHASH, data.arbiter, data.sponsor, data.nonce, data.expires, data.id, data.amount))
            )
        );
    }

    function _domainSeparator(address verifyingContract) internal view returns (bytes32) {
        return keccak256(abi.encode(keccak256(bytes(EIP712_DOMAIN_TYPE)), keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, verifyingContract));
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
        compactContract.deposit(address(usdc), address(simpleERC7683Allocator), defaultAmount);

        vm.stopPrank();
    }
}

abstract contract Locked is Deposited {
    function setUp() public virtual override {
        super.setUp();

        vm.startPrank(user);

        defaultExpiration = vm.getBlockTimestamp() + defaultResetPeriod;
        simpleERC7683Allocator.lock(Compact({ arbiter: arbiter, sponsor: user, nonce: defaultNonce, id: usdcId, expires: defaultExpiration, amount: defaultAmount }));

        vm.stopPrank();
    }
}