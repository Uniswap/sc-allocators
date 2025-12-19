// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {HybridAllocator} from '../src/allocators/HybridAllocator.sol';
import {OnChainAllocator} from '../src/allocators/OnChainAllocator.sol';
import {Script, console} from 'forge-std/Script.sol';

contract ComputeInitCodeHash is Script {
    function run() public view {
        // OnChainAllocator - no constructor args
        bytes memory onChainInitCode = type(OnChainAllocator).creationCode;
        bytes32 onChainInitCodeHash = keccak256(onChainInitCode);

        console.log('=== OnChainAllocator ===');
        console.log('Init code hash:');
        console.logBytes32(onChainInitCodeHash);
        console.log('');

        // HybridAllocator - requires constructor args
        address owner = vm.envOr('OWNER_ADDRESS', address(0));
        address signer = vm.envOr('SIGNER_ADDRESS', address(0));

        if (owner != address(0)) {
            bytes memory hybridInitCode =
                abi.encodePacked(type(HybridAllocator).creationCode, abi.encode(owner, signer));
            bytes32 hybridInitCodeHash = keccak256(hybridInitCode);

            console.log('=== HybridAllocator ===');
            console.log('Owner:', owner);
            console.log('Signer:', signer);
            console.log('Init code hash:');
            console.logBytes32(hybridInitCodeHash);
        } else {
            console.log('=== HybridAllocator ===');
            console.log('Set OWNER_ADDRESS env var to compute init code hash');
        }
    }
}
