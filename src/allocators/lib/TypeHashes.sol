// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// keccak256("Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
bytes32 constant MANDATE_TYPEHASH = 0x74d9c10530859952346f3e046aa2981a24bb7524b8394eb45a9deddced9d6501;

//          keccak256("BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments,Mandate mandate)
//          Lock(bytes12 lockTag,address token,uint256 amount)
//          Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
bytes32 constant BATCH_COMPACT_WITNESS_TYPEHASH = 0x5ede122c736b60a8b718f83dcfb5d6e4aa27c9714d0c7bc9ca86562b8f878463;

// keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,bytes12 lockTag,address token,uint256 amount,Mandate mandate)
//          Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
bytes32 constant COMPACT_WITNESS_TYPEHASH = 0x2ec0d30491bb66a6eb554b9d53f490d79b54fc5f4963bed4b2bb8096b4790f1f;
