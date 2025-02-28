// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {ISimpleAllocator} from './ISimpleAllocator.sol';
import {Compact} from '@uniswap/the-compact/types/EIP712Types.sol';

interface ISimpleWitnessAllocator is ISimpleAllocator {
    /// @notice Locks the tokens of an id for a claim with a witness
    /// @dev Locks all tokens of a sponsor for an id with a witness
    /// @dev example for the typeHash:
    /// keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Witness witness)Witness(uint256 witnessArgument)")
    ///
    /// @param compact_ The compact that contains the data about the lock
    /// @param typeHash_ The type hash of the full compact, including the witness
    /// @param witnessHash_ The witness hash of the witness
    function lockWithWitness(Compact calldata compact_, bytes32 typeHash_, bytes32 witnessHash_) external;

    /// @notice Returns the witness typestring hash including a given witness argument
    /// @dev example of a witness type string input:
    ///     "uint256 witnessArgument"
    /// @dev full typestring:
    ///     Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Witness witness)Witness(uint256 witnessArgument)
    ///
    /// @param witness_ The witness typestring argument
    /// @return typestringHash_ The full compact typestring hash, including the witness
    function getTypestringHashForWitness(string calldata witness_) external pure returns (bytes32 typestringHash_);
}
