// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import { IAllocator } from "src/interfaces/IAllocator.sol";
import { ERC6909 } from "@solady/tokens/ERC6909.sol";
import { ERC20 } from "@solady/tokens/ERC20.sol";
import { IdLib } from "@uniswap/the-compact/lib/IdLib.sol";
import { ForcedWithdrawalStatus } from "@uniswap/the-compact/types/ForcedWithdrawalStatus.sol";
import { ResetPeriod } from "@uniswap/the-compact/types/ResetPeriod.sol";
import { Scope } from "@uniswap/the-compact/types/Scope.sol";
import { console2 } from "forge-std/console2.sol";

contract TheCompactMock is ERC6909 {
    using IdLib for uint96;
    using IdLib for uint256;
    using IdLib for address;

    // Mock Variables
    uint32 private constant DEFAULT_RESET_PERIOD = 60;
    ResetPeriod private constant DEFAULT_RESET_PERIOD_TYPE = ResetPeriod.OneMinute;
    Scope private constant DEFAULT_SCOPE = Scope.Multichain;
    address private DEFAULT_ALLOCATOR;

    // Mock State
    mapping(uint256 id => address token) public tokens;
    mapping(uint256 nonce => bool consumed) public consumedNonces;
    mapping(address allocator => bool registered) public registeredAllocators;
    mapping(address user => uint256 availableAt) public forcedWithdrawalStatus;

    function __registerAllocator(address allocator, bytes calldata) external returns (uint96) {
        registeredAllocators[allocator] = true;
        DEFAULT_ALLOCATOR = allocator;
        return 0;
    }

    function deposit(address token, uint256 amount, address allocator) external {
        ERC20(token).transferFrom(msg.sender, address(this), amount);
        uint256 id = _getTokenId(token, allocator);
        tokens[id] = token;
        _mint(msg.sender, id, amount);
    }

    function transfer(address from, address to, uint256 amount, address token, address allocator) external {
        uint256 id = _getTokenId(token, allocator);
        IAllocator(allocator).attest(msg.sender, from, to, id, amount);
        _transfer(address(0), from, to, id, amount);
    }

    function claim(address from, address to, address token, uint256 amount, address allocator, bytes calldata signature) external {
        uint256 id = _getTokenId(token, allocator);
        IAllocator(allocator).isValidSignature(keccak256(abi.encode(from, id, amount)), signature);
        _transfer(address(0), from, to, id, amount);
    }

    function withdraw(address token, uint256 amount, address allocator) external {
        uint256 id = _getTokenId(token, allocator);
        IAllocator(allocator).attest(msg.sender, msg.sender, msg.sender, id, amount);
        ERC20(token).transferFrom(address(this), msg.sender, amount);
        _burn(msg.sender, id, amount);
    }

    function consume(uint256[] calldata nonces) external returns (bool) {
        for (uint256 i = 0; i < nonces.length; ++i) {
            consumedNonces[nonces[i]] = true;
        }
        return true;
    }

    function hasConsumedAllocatorNonce(uint256 nonce, address) external view returns (bool) {
        return consumedNonces[nonce];
    }

    function getLockDetails(uint256 id) external view returns (address, address, ResetPeriod, Scope) {
        return (tokens[id], DEFAULT_ALLOCATOR, DEFAULT_RESET_PERIOD_TYPE, DEFAULT_SCOPE);
    }

    function enableForceWithdrawal(uint256) external returns (uint256) {
        forcedWithdrawalStatus[msg.sender] = block.timestamp + DEFAULT_RESET_PERIOD;
        return block.timestamp + DEFAULT_RESET_PERIOD;
    }

    function disableForceWithdrawal(uint256) external returns (bool) {
        forcedWithdrawalStatus[msg.sender] = 0;
        return true;
    }

    function getForcedWithdrawalStatus(address sponsor, uint256) external view returns (ForcedWithdrawalStatus, uint256) {
        uint256 expires = forcedWithdrawalStatus[sponsor];
        return (expires == 0 ? ForcedWithdrawalStatus.Disabled : ForcedWithdrawalStatus.Enabled, expires);
    }

    function getTokenId(address token, address allocator) external pure returns (uint256) {
        return _getTokenId(token, allocator);
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                // keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')
                0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                keccak256("The Compact"),
                keccak256("0"),
                block.chainid,
                address(this)
            )
        );
    }

    function name(
        uint256 // id
    ) public view virtual override returns (string memory) {
        return "TheCompactMock";
    }

    function symbol(
        uint256 // id
    ) public view virtual override returns (string memory) {
        return "TCM";
    }

    function tokenURI(
        uint256 // id
    ) public view virtual override returns (string memory) {
        return "";
    }

    function _getTokenId(address token, address allocator) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(token, allocator)));
    }
}
