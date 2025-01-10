> :warning: This is an early-stage contract under active development; it has not yet been properly tested, reviewed, or audited.

#### Table of Contents

- [Setup](#setup)
- [Allocators](#allocators)
- [Deployment](#deployment)
- [Docs](#docs)
- [Contributing](#contributing)

## Setup

Follow these steps to set up your local environment:

- [Install foundry](https://book.getfoundry.sh/getting-started/installation)
- Install dependencies: `forge install`
- Build contracts: `forge build`
- Test contracts: `forge test`

If you intend to develop on this repo, follow the steps outlined in [CONTRIBUTING.md](CONTRIBUTING.md#install).

## Allocators

The allocators are designed to be used with the [The Compact](https://github.com/uniswap/the-compact). Their purpose is to ensure that locked tokens are available to claim for fillers within the promised expiration time. This repository contains multiple allocators, each with different features:
    - [ServerAllocator](src/allocators/ServerAllocator.sol): The ServerAllocator stands as an on chain verification contract for a server based allocator. It is ready for the callbacks of the [The Compact](https://github.com/uniswap/the-compact) during a claim and verifies the allocator signatures have been signed by an authorized address. It does not keep track of any locked down tokens, but instead relies on the server to do so.
    - [SimpleAllocator](src/allocators/SimpleAllocator.sol): A simple, fully decentralized allocator that allows for a single claim per token. This means the contract will lock down all tokens of a sponsor for an id for a single claim, so it is not possible to start multiple claims for the same sponsor and id at the same time. The contract does though keep track of the amount of locked tokens and so it will faithfully attest for a transfer of those, even during an ongoing claim. The contract is a good starting point when learning about allocators and it is kept very simple on purpose to learn about the concept of an allocator or use this contract as a template. To be used in production, the contract would require the ability to work with witness data, since a real cross chain swap will always require a witness besides the Compact. An example implementation of a witness allocator can be found [here](src/allocators/SimpleWitnessAllocator.sol).
    - [SimpleWitnessAllocator](src/allocators/SimpleWitnessAllocator.sol): This contract enhances the [SimpleAllocator](src/allocators/SimpleAllocator.sol) with the ability of processing witness data besides the Compact. This makes it a much more production ready allocator.
    - [SimpleERC7683Allocator](src/allocators/SimpleERC7683Allocator.sol): This contract enhances the [SimpleAllocator](src/allocators/SimpleAllocator.sol) and making it compatible with the [ERC7683](https://eips.ethereum.org/EIPS/eip-7683) standard. The Allocator therefor also becomes a [IOriginSettler](src/interfaces/ERC7683/IOriginSettler.sol) and converts a OnchainCrossChainOrder to a `Compact`/`BatchCompact` and a `Claim` / `Mendate` as required by the tribunal on the target chain.

## Deployment

This repo utilizes versioned deployments. For more information on how to use forge scripts within the repo, check [here](CONTRIBUTING.md#deployment).

Smart contracts are deployed or upgraded using the following command:

```shell
forge script script/Deploy.s.sol --broadcast --rpc-url <rpc_url> --verify
```

## Docs

The documentation and architecture diagrams for the contracts within this repo can be found [here](docs/).
Detailed documentation generated from the NatSpec documentation of the contracts can be found [here](docs/autogen/src/src/).
When exploring the contracts within this repository, it is recommended to start with the interfaces first and then move on to the implementation as outlined [here](CONTRIBUTING.md#natspec--comments)

## Contributing

If you want to contribute to this project, please check [CONTRIBUTING.md](CONTRIBUTING.md) first.
