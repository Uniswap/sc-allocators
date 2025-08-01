// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// keccak256("Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
bytes32 constant MANDATE_TYPEHASH = 0x74d9c10530859952346f3e046aa2981a24bb7524b8394eb45a9deddced9d6501;

// keccak256("BatchCompact(address arbiter,address sponsor,uint256 nonce,uint256 expires,Lock[] commitments)Lock(bytes12 lockTag,address token,uint256 amount,Mandate mandate)
//          Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
bytes32 constant BATCH_COMPACT_WITNESS_TYPEHASH = 0xcddb20593d74f00cd789982c798bca41f8ba5f6835c95a771fd48b110d8b1249;

// keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,bytes12 lockTag,address token,uint256 amount,Mandate mandate)
//          Mandate(uint256 chainId,address tribunal,address recipient,uint256 expires,address token,uint256 minimumAmount,uint256 baselinePriorityFee,uint256 scalingFactor,uint256[] decayCurve,bytes32 salt)")
bytes32 constant COMPACT_WITNESS_TYPEHASH = 0x2ec0d30491bb66a6eb554b9d53f490d79b54fc5f4963bed4b2bb8096b4790f1f;
