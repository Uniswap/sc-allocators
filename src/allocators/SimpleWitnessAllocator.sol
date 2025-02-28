// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import {IAllocator} from '../interfaces/IAllocator.sol';
import {ISimpleWitnessAllocator} from '../interfaces/ISimpleWitnessAllocator.sol';
import {SimpleAllocator} from './SimpleAllocator.sol';
import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {ERC6909} from '@solady/tokens/ERC6909.sol';
import {ITheCompact} from '@uniswap/the-compact/interfaces/ITheCompact.sol';
import {Compact} from '@uniswap/the-compact/types/EIP712Types.sol';

contract SimpleWitnessAllocator is SimpleAllocator, ISimpleWitnessAllocator {
    // abi.decode(bytes("Compact(address arbiter,address "), (bytes32))
    bytes32 constant COMPACT_TYPESTRING_FRAGMENT_ONE =
        0x436f6d70616374286164647265737320617262697465722c6164647265737320;
    // abi.decode(bytes("sponsor,uint256 nonce,uint256 ex"), (bytes32))
    bytes32 constant COMPACT_TYPESTRING_FRAGMENT_TWO =
        0x73706f6e736f722c75696e74323536206e6f6e63652c75696e74323536206578;
    // abi.decode(bytes("pires,uint256 id,uint256 amount)"), (bytes32))
    bytes32 constant COMPACT_TYPESTRING_FRAGMENT_THREE =
        0x70697265732c75696e743235362069642c75696e7432353620616d6f756e7429;
    // uint200(abi.decode(bytes(",Witness witness)Witness("), (bytes25)))
    uint200 constant WITNESS_TYPESTRING = 0x2C5769746E657373207769746E657373295769746E65737328;

    constructor(address compactContract_, uint256 minWithdrawalDelay_, uint256 maxWithdrawalDelay_)
        SimpleAllocator(compactContract_, minWithdrawalDelay_, maxWithdrawalDelay_)
    {}

    /// @inheritdoc ISimpleWitnessAllocator
    function lockWithWitness(Compact calldata compact_, bytes32 typestringHash_, bytes32 witnessHash_) external {
        bytes32 tokenHash = _checkAllocation(compact_);

        bytes32 digest = keccak256(
            abi.encodePacked(
                bytes2(0x1901),
                ITheCompact(COMPACT_CONTRACT).DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        typestringHash_, // keccak256("Compact(address arbiter,address sponsor,uint256 nonce,uint256 expires,uint256 id,uint256 amount,Witness witness)Witness(uint256 witnessArgument)")
                        compact_.arbiter,
                        compact_.sponsor,
                        compact_.nonce,
                        compact_.expires,
                        compact_.id,
                        compact_.amount,
                        witnessHash_
                    )
                )
            )
        );

        _claim[tokenHash] = compact_.expires;
        _amount[tokenHash] = compact_.amount;
        _nonce[tokenHash] = compact_.nonce;
        _sponsor[digest] = tokenHash;

        emit Locked(compact_.sponsor, compact_.id, compact_.amount, compact_.expires);
    }

    /// @inheritdoc ISimpleWitnessAllocator
    function getTypestringHashForWitness(string calldata witness_) external pure returns (bytes32 typestringHash_) {
        assembly ("memory-safe") {
            let memoryOffset := mload(0x40)
            mstore(memoryOffset, COMPACT_TYPESTRING_FRAGMENT_ONE)
            mstore(add(memoryOffset, 0x20), COMPACT_TYPESTRING_FRAGMENT_TWO)
            mstore(add(memoryOffset, 0x40), COMPACT_TYPESTRING_FRAGMENT_THREE)
            mstore(add(memoryOffset, sub(0x60, 0x01)), shl(56, WITNESS_TYPESTRING))
            let witnessPointer := add(memoryOffset, add(sub(0x60, 0x01), 0x19))
            calldatacopy(witnessPointer, witness_.offset, witness_.length)
            let witnessEnd := add(witnessPointer, witness_.length)
            mstore8(witnessEnd, 0x29)
            typestringHash_ := keccak256(memoryOffset, sub(add(witnessEnd, 0x01), memoryOffset))

            mstore(0x40, add(or(witnessEnd, 0x1f), 0x20))
        }
        return typestringHash_;
    }
}
