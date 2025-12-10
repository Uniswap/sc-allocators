# SC-Allocators

> **Warning**
> These contracts are under active development and have not been fully audited. Use with caution in production environments. The code may contain bugs, security vulnerabilities, or undergo breaking changes without notice.

## Table of Contents

- [Overview](#overview)
- [What is an Allocator?](#what-is-an-allocator)
- [Allocator Types](#allocator-types)
  - [OnChainAllocator](#onchainlocator)
  - [HybridAllocator](#hybridallocator)
  - [ERC7683Allocator](#erc7683allocator)
  - [HybridERC7683](#hybriderc7683)
- [Comparison Table](#comparison-table)
- [Key Concepts](#key-concepts)
  - [Prepare-Execute Pattern](#prepare-execute-pattern)
  - [Resource Locks and Token IDs](#resource-locks-and-token-ids)
  - [Claim Authorization Flow](#claim-authorization-flow)
- [Setup](#setup)
- [Deployment](#deployment)
- [Docs](#docs)
- [Contributing](#contributing)

## Overview

This repository contains allocator implementations for [The Compact](https://github.com/uniswap/the-compact) protocol. Allocators are critical infrastructure components that prevent double-spending of locked tokens while enabling credible cross-chain and asynchronous transaction commitments.

## What is an Allocator?

An allocator is a smart contract that mediates the use of resource locks in The Compact protocol. It serves as a **double-spend prevention layer** that ensures tokens committed to one compact cannot be simultaneously committed elsewhere or withdrawn before the commitment expires.

**Core Responsibilities:**

- Prevent double-spending of locked tokens
- Validate token transfers (via `attest`)
- Authorize claim execution (via `authorizeClaim`)
- Manage nonces for replay protection

**Trust Relationship:**

- Claimants trust allocators won't let sponsors over-commit tokens
- Sponsors trust allocators won't unduly censor valid allocations
- If an allocator fails to authorize a legitimate claim, sponsors can escape via forced withdrawal after the reset period

## Allocator Types

### OnChainAllocator

A **fully decentralized, zero-trust allocator** that tracks all allocations on-chain using persistent storage.

**Features:**

- Maintains `tokenHash => Allocation[]` mapping for complete allocation tracking
- Automatic expiration cleanup using gas-efficient assembly
- Three allocation methods: `allocate()`, `allocateFor()`, `allocateAndRegister()`
- Validates allocator IDs, reset periods, forced withdrawal status, and balance sufficiency

**Best For:** Trustless protocols where full on-chain verifiability is required.

**Trade-offs:** Higher gas costs due to storage operations and array iteration during authorization. Additionally, any follow up allocation will always require an on chain transaction.

### HybridAllocator

A **flexible allocator** that combines on-chain deposit tracking with off-chain signature-based authorization through multiple authorized signers.

**Features:**

- Simple `claimHash => bool` storage model for lower gas costs
- Configurable set of authorized signers (add/remove/replace)
- Two-step signer replacement to prevent accidental lockout
- Supports both deposit-based and signature-based claim authorization

**Best For:** Operators that want to optimize for speed, gas costs and minimize on chain transactions, at the cost of decentralization.

**Trade-offs:** Requires trust in authorized signers not to over-allocate. If signers authorize more claims than deposits exist, claims will fail.

### ERC7683Allocator

Extends `OnChainAllocator` with support for the [ERC-7683](https://eips.ethereum.org/EIPS/eip-7683) cross-chain intent standard.

**Features:**

- Implements `IOriginSettler` interface for cross-chain order creation
- `open()` and `openFor()` methods for ERC-7683 order lifecycle
- Encodes orders with Tribunal Mandate structures as witness data
- Supports both gasless (off-chain signed) and on-chain order creation
- Emits standardized `Open` events for filler discoverability

**Best For:** Operators aiming for compatibility with the Open Intent Standard, with the framework of the OnChainAllocator.

**Integration:** Works with [Uniswap's Tribunal](https://github.com/uniswap/tribunal) as the destination settler for cross-chain fill verification.

### HybridERC7683

Extends `HybridAllocator` with ERC-7683 support, but **requires deposits** (no signature-only authorization path).

**Features:**

- Combines hybrid signer management with ERC-7683 standard compliance
- Only supports deposit-based order creation
- Lower gas costs than ERC7683Allocator due to simpler storage model

**Best For:** Operators aiming for compatibility with the Open Intent Standard, with the framework of the HybridAllocator.

## Comparison Table

| Feature                          | OnChainAllocator            | HybridAllocator              |
| -------------------------------- | --------------------------- | ---------------------------- |
| **Trust Model**                  | Zero-trust (fully on-chain) | Trusts authorized signers    |
| **Storage Model**                | `tokenHash => Allocation[]` | `claimHash => bool`          |
| **ERC-7683 Support**             | No                          | No                           |
| **Deposit Required**             | Optional                    | Required                     |
| **Signer Management**            | N/A                         | Yes                          |
| **Gas Cost (allocation)**        | Higher                      | Lower                        |
| **Gas Cost (authorization)**     | Medium (array iteration)    | Low (signature verification) |
| **Automatic Expiration Cleanup** | Yes                         | No                           |
| **Double-Spend Prevention**      | Enforced on-chain           | Relies on signer honesty     |
| **Native Token Support**         | Yes                         | Yes                          |
| **Fee-on-Transfer Support**      | Yes                         | Yes                          |

## Key Concepts

### Prepare-Execute Pattern

All allocators implement a two-phase atomic allocation pattern, allowing to allocate tokens without the contract directly depositing those themselves into the compact (like in `allocateAndRegister`). This uses [EIP-1153 transient storage](https://eips.ethereum.org/EIPS/eip-1153) to keep track of the changes in balance.

**How it works:**

1. **Prepare Phase** (`prepareAllocation`):

   - Captures current ERC6909 balances from The Compact
   - Stores balance snapshots in transient storage with a unique identifier
   - Returns the nonce that will be used for the allocation

2. **Deposit Phase** (external):

   - Caller deposits tokens into The Compact
   - The Compact mints ERC6909 tokens to the recipient
   - The Compact registers the claim hash, connected to the deposit

3. **Execute Phase** (`executeAllocation`):
   - Reads new ERC6909 balances
   - Compares to stored snapshots from transient storage
   - Validates that balance increases match expected amounts
   - Verifies the claim is registered with The Compact
   - Returns actual deposited amounts for allocation tracking

**Benefits:**

- The allocator is only a witness to the deposit, which is cheaper and allows allocations if the allocator is not trusted with handling the tokens.
- Handles fee-on-transfer tokens correctly (verifies actual balance changes)

### Resource Locks and Token IDs

Token IDs in The Compact encode allocation parameters:

```
Token ID (uint256) = lockTag (96 bits) + token address (160 bits)

lockTag = scope (1 bit) + resetPeriod (3 bits) + allocatorId (92 bits)
```

**Components:**

- **allocatorId**: Derived from the allocator's address, determines which allocator mediates this lock
- **scope**: Multichain (0) or single-chain (1)
- **resetPeriod**: Time until forced withdrawal is available (ranges from 1 second to 30 days)
- **token**: The underlying ERC20 token address (or zero address for native tokens)

### Claim Authorization Flow

When a claim is processed by The Compact:

1. The Compact validates the claim exists and hasn't expired
2. The Compact calls `allocator.authorizeClaim(claimHash, ...)`
3. The allocator verifies the allocation:
   - **OnChainAllocator**: Finds and removes the allocation from storage
   - **HybridAllocator**: Checks on-chain deposit flag OR verifies signer signature
4. On success, The Compact transfers tokens to claimants

## Setup

Follow these steps to set up your local environment:

- [Install foundry](https://book.getfoundry.sh/getting-started/installation)
- Install dependencies: `forge install`
- Build contracts: `forge build`
- Test contracts: `forge test`

If you intend to develop on this repo, follow the steps outlined in [CONTRIBUTING.md](CONTRIBUTING.md#install).

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
