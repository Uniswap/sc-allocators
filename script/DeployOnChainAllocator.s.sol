// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {OnChainAllocator} from '../src/allocators/OnChainAllocator.sol';
import {Script, console} from 'forge-std/Script.sol';

contract DeployOnChainAllocator is Script {
    // Use: cast create2 --starts-with <prefix> --ends-with <suffix> --init-code-hash <hash>
    bytes32 constant SALT = 0x6bd70ededcc48f126a839895c822f173c097ede0d2d896dcb5b2a80c3b5e8205;

    function run() public {
        bytes32 initCodeHash = keccak256(type(OnChainAllocator).creationCode);

        console.log('=== OnChainAllocator CREATE2 Deployment ===');
        console.log('Salt:', vm.toString(SALT));
        console.log('Init code hash:', vm.toString(initCodeHash));

        vm.startBroadcast();

        OnChainAllocator allocator = new OnChainAllocator{salt: SALT}();

        vm.stopBroadcast();

        console.log('Deployed at:', address(allocator));
        console.log('Allocator ID:', allocator.ALLOCATOR_ID());
    }
}
