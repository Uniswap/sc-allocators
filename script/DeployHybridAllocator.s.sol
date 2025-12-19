// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {HybridAllocator} from '../src/allocators/HybridAllocator.sol';
import {Script, console} from 'forge-std/Script.sol';

contract DeployHybridAllocator is Script {
    // Use: cast create2 --starts-with <prefix> --ends-with <suffix> --init-code-hash <hash>
    bytes32 constant SALT = 0xa73a1d77c4eeee782776c6349b59663c8e38157fbfc7f7ed35b46bb0479d0cc3;

    function run() public {
        // Read deployment parameters from environment
        address owner = vm.envAddress('OWNER_ADDRESS');
        address signer = vm.envOr('SIGNER_ADDRESS', address(0));

        console.log('=== HybridAllocator CREATE2 Deployment ===');
        console.log('Owner:', owner);
        console.log('Signer:', signer);
        console.log('Salt:', vm.toString(SALT));

        vm.startBroadcast();

        HybridAllocator allocator = new HybridAllocator{salt: SALT}(owner, signer);

        vm.stopBroadcast();

        console.log('Deployed at:', address(allocator));
    }
}
