// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ERC20} from '@openzeppelin/contracts/token/ERC20/ERC20.sol';

contract ERC20Mock is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
