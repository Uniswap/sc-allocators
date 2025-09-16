# Allocators (for The Compact v1)

Allocator contracts and libraries that integrate with The Compact v1 and the ERC-7683 cross-chain order standard (via Uniswap Tribunal). These allocators prevent double-spend of ERC6909 resource locks and authorize claims according to compact commitments and allocator policy.

> 🕵 Although The Compact V1 and these example allocator implementations have undergone several independent security reviews (including from [OpenZeppelin](https://openzeppelin.com) and [Spearbit Cantina](https://cantina.xyz)), **we strongly recommend auditing any systems integrating with these contracts separately.**

## Table of Contents

1. [Summary](#summary)
2. [How It Fits With The Compact](#how-it-fits-with-the-compact)
3. [Allocator Types](#allocator-types)
4. [Contract Overview](#contract-overview)
   - [OnChainAllocator](#onchainallocator)
   - [HybridAllocator](#hybridallocator)
   - [ERC7683Allocator](#erc7683allocator)
   - [HybridERC7683](#hybriderc7683)
   - [Libraries](#libraries)
   - [Interfaces](#interfaces)
5. [Key Concepts](#key-concepts)
   - [Allocations and Claim Hashes](#allocations-and-claim-hashes)
   - [Nonces](#nonces)
   - [Expiration and Reset Periods](#expiration-and-reset-periods)
   - [Attestation on ERC6909 Transfers](#attestation-on-erc6909-transfers)
   - [Two-Phase On-Chain Allocation](#two-phase-on-chain-allocation)
6. [ERC-7683 + Tribunal Integration](#erc-7683--tribunal-integration)
7. [Setup](#setup)
8. [Gas Snapshots](#gas-snapshots)
9. [Deployment](#deployment)
10. [Security and Trust Assumptions](#security-and-trust-assumptions)
11. [Errors](#errors)
12. [Examples](#examples)
13. [Contributing](#contributing)
14. [License](#license)

## Summary

This repository provides various example allocator implementations for use with [The Compact](https://github.com/uniswap/the-compact/tree/v1), an ERC6909-based protocol for reusable resource locks. Allocators co-sign or authorize claims against sponsors’ locked balances, prevent under-allocation, and in the case of the HybridERC7683 implementation, broadcast cross-chain orders using ERC-7683. Some allocators also rely on [Uniswap Tribunal](https://github.com/uniswap/tribunal). The provided examples include both fully on-chain and hybrid (on-chain + off-chain) allocators.

Core goals:

- Ensure locked balances cannot be double-spent during the allocation window.
- Authorize arbiters to settle valid claims on The Compact against locked resources.
- Support direct integration with ERC-7683 order flows and Uniswap Tribunal settlement.

## How It Fits With The Compact

The Compact defines resource locks, compacts (credible commitments), arbiters, and claim processing. Allocators are registered on The Compact and must implement `IAllocator`. The Compact invokes the allocator’s `authorizeClaim` during claims, and `attest` to validate direct ERC6909 transfers.

For protocol details, read the [the full docs for The Compact](https://github.com/Uniswap/the-compact/blob/v1/README.md).

## Allocator Types

| Contract | Role | Off-chain Logic | ERC-7683 | Notes |
| --- | --- | --- | --- | --- |
| `OnChainAllocator` | Pure on-chain allocator | ❌ | ❌ | Manages per-id allocations entirely on-chain; nonces scoped; exhaustively validated. |
| `HybridAllocator` | Hybrid allocator | ✅ (signers) | ❌ | Accepts off-chain allocator signatures or on-chain allocations; simple signer management. |
| `ERC7683Allocator` | On-chain allocator + origin settler | ❌ | ✅ | Implements `IOriginSettler` and opens/relays ERC-7683 orders tied to Compact claims. |
| `HybridERC7683` | Hybrid allocator + origin settler | ✅ (signers) | ✅ | ERC-7683 origin settler requiring deposits (no signature path); combines Hybrid + ERC7683 flows. |

## Contract Overview

### OnChainAllocator

File: `src/allocators/OnChainAllocator.sol`

- Registers itself on The Compact and derives the domain separator and `allocatorId`.
- Maintains per-(sponsor,id) allocations with amount and expiry, deleting expired entries proactively.
- Key flows:
  - `allocate(commitments, arbiter, expires, typehash, witness)` → on-chain allocation for `msg.sender`.
  - `allocateFor(sponsor, ..., signature)` → allocation on behalf of a sponsor; requires sponsor signature or a prior Compact registration of the derived `claimHash`.
  - `allocateAndRegister(recipient, commitments, ...)` → deposits tokens held by the allocator into The Compact and registers claim(s) in a single flow.
  - `prepareAllocation` / `executeAllocation` → two-phase path that enforces correct deposit+registration via transient storage and balance delta checks.
  - `attest` → validates ERC6909 transfer safety by ensuring unallocated balance covers the transfer.
  - `authorizeClaim` / `isClaimAuthorized` → ensures the `claimHash` matches an active allocation and cleans it up on success.

### HybridAllocator

File: `src/allocators/HybridAllocator.sol`

- Maintains a set of authorized off-chain signers; exposes add/remove/replace signer administration.
- Supports two ways to authorize a claim:
  - On-chain allocation (claim pre-allocated in contract storage).
  - Off-chain signature over the Compact digest by an authorized signer.
- Provides `allocateAndRegister` for immediate deposit + register flows; does not support ERC6909 `attest` (reverts `Unsupported()`).

### ERC7683Allocator

File: `src/allocators/ERC7683Allocator.sol`

- Extends `OnChainAllocator` and implements `IOriginSettler` to open and resolve ERC-7683 orders.
- Two paths:
  - `open(...)` for on-chain orders: requires prior Compact registration; allocates on-chain and emits `Open` with a resolved order for fillers.
  - `openFor(...)` for gasless orders: supports either sponsor signature or deposit-based flows; allocates (and optionally deposits+registers) for the user and emits `Open`.
- Integrates with Uniswap Tribunal via `ERC7683AllocatorLib` to produce mandate hashes and destination fill instructions.

### HybridERC7683

File: `src/allocators/HybridERC7683.sol`

- Extends `HybridAllocator` and implements `IOriginSettler` for ERC-7683.
- Requires deposits for `openFor` and `resolveFor` paths (no pure signature path), then performs `allocateAndRegister` and emits `Open`.

### Libraries

- `src/allocators/lib/AllocatorLib.sol`
  - Transient-storage based `prepareAllocation` / `executeAllocation` to safely bind deposit+registration to a nonce and inputs.
  - Utilities to derive `claimHash`, split/pack ids, compute durations from `lockTag`, and recover ECDSA signers.
- `src/allocators/lib/ERC7683AllocatorLib.sol`
  - Decodes ERC-7683 order payloads, sanitizes values, constructs mandate and fill hashes, and resolves orders for fillers.
- `src/allocators/lib/TypeHashes.sol`
  - Typehash constants used by allocators (kept for clarity alongside Tribunal’s canonical set).

### Interfaces

- `src/interfaces/IOnChainAllocator.sol` — on-chain allocator API and error set.
- `src/interfaces/IHybridAllocator.sol` — hybrid allocator admin and allocation API.
- `src/interfaces/IERC7683Allocator.sol` — ERC-7683 origin settler + allocator API (includes `getNonce`, `createFillerData`).
- `src/interfaces/ERC7683/IOriginSettler.sol` — ERC-7683 origin settler standard used by allocators.

## Key Concepts

### Allocations and Claim Hashes

- Allocations lock part of a sponsor’s ERC6909 id (resource lock) for a specified `expires` timestamp.
- The allocator derives a `claimHash` from the compact parameters: `(arbiter, sponsor, nonce, expires, commitmentsHash, witness, typehash)`.
- During claim settlement on The Compact, the allocator’s `authorizeClaim` verifies that `claimHash` is active for the `(sponsor, ids)` and then consumes it.

### Nonces

- Nonces are 256-bit values where the most-significant 160 bits embed a scoping address and the least-significant 96 bits are incrementing counters.
- In `OnChainAllocator`:
  - `allocate` uses scope `(address(0), sponsor)` so anyone can relay; returned `nonce` encodes the sponsor.
  - `prepareAllocation/executeAllocation` scope the `nonce` to `(caller, recipient)` to allow relayed flows with distinct counters.

### Expiration and Reset Periods

- Allocations must expire before the resource lock’s `resetPeriod` elapses. The allocator enforces that `expires < now + minResetPeriod` across all commitments.
- If a forced withdrawal has been scheduled on The Compact for a lock, allocations must expire strictly before the withdrawal becomes available.

### Attestation on ERC6909 Transfers

- For standard ERC6909 transfers, The Compact calls `IAllocator.attest` to ensure that unallocated balances cover the transfer amount. `OnChainAllocator` calculates allocated balance lazily and reclaims expired entries.

### Two-Phase On-Chain Allocation

- `prepareAllocation` stores a transient snapshot of balances and binds the inputs to a unique identifier and `nonce`.
- `executeAllocation` re-reads balances, requires strictly positive deltas for each id, reconstructs the commitments, recomputes the `claimHash`, and requires that the claim has been registered on The Compact.

## ERC-7683 + Tribunal Integration

- `ERC7683Allocator` and `HybridERC7683` implement `IOriginSettler`:
  - `open` (on-chain) and `openFor` (gasless) compute mandate hashes, allocate deposits/locks, and emit `Open` with a resolved order containing `maxSpent`, `minReceived`, and `fillInstructions` for the destination settler (Uniswap Tribunal).
  - `resolve` / `resolveFor` produce a deterministic `ResolvedCrossChainOrder` for simulation and integration.
- Order data types are validated against expected typehashes, and origin settler address must match the allocator.

## Setup

1. Install Foundry: see the official guide.
2. Install dependencies:

```bash
forge install
```

3. Build:

```bash
forge build
```

4. Test (verbose):

```bash
forge test -v
```

If you intend to develop on this repo, follow [CONTRIBUTING.md](CONTRIBUTING.md#install).

## Gas Snapshots

Gas is measured via `forge-gas-snapshot` with `snapLastCall` in tests. See the `snapshots/` directory for reference outputs and [CONTRIBUTING.md](CONTRIBUTING.md#gas-metering).

## Deployment

Use the provided Foundry script and optional verification:

```bash
forge script script/Deploy.s.sol --broadcast --rpc-url <rpc_url> --verify
```

For deployment practices, resumable verification, and generating deployment logs/markdown, see [CONTRIBUTING.md](CONTRIBUTING.md#deployment).

## Security and Trust Assumptions

- `OnChainAllocator` is fully on-chain and deterministic; safety depends on The Compact’s guarantees and correct allocator registration.
- `HybridAllocator` and `HybridERC7683` depend on off-chain signer sets. Only authorized signers can approve claims; signer management is on-chain.
- ERC-7683 flows emit orders whose destination settlement is performed by Uniswap Tribunal; fillers should validate orders and signatures.

Always review and audit before production use.

## Errors

Key error families (non-exhaustive):

- Allocation lifecycle: `InvalidCommitments()`, `InvalidAmount(amount)`, `InvalidExpiration(expires, expected)`, `ForceWithdrawalAvailable(expires, forcedAt)`, `InsufficientBalance(sponsor, id, available, expected)`.
- Authorization and signatures: `InvalidSignature(signer, expectedSigner)` (on-chain allocator), `InvalidSignature()` (hybrid signer path), `InvalidClaim(claimHash)`.
- Two-phase checks: `InvalidPreparation()`, `InvalidRegistration(recipient, claimHash, typehash)`, `InvalidBalanceChange(newBalance, oldBalance)`.
- ERC-7683: `InvalidOrderDataType(got, expected)`, `InvalidOriginSettler(got, expected)`, `InvalidNonce(got, expected)`, `InvalidOrderData(orderData)`, `InvalidRecipientCallbackLength()`.

Refer to the interfaces and contract sources for the complete error set.

## Examples

### 1) OnChainAllocator: deposit → allocate → claim

```solidity
// 1) Sponsor deposits to The Compact, minting ERC6909 id for (lockTag, token)
// The `lockTag` encodes this allocator’s `allocatorId` and a valid reset period/scope
compact.depositERC20(token, lockTag, amount, sponsor);

// 2) Sponsor allocates on-chain for a future claim
Lock[] memory commitments = new Lock[](1);
commitments[0] = Lock({ lockTag: lockTag, token: token, amount: amount });
(bytes32 claimHash, uint256 nonce) = allocator.allocate(commitments, arbiter, expires, BATCH_COMPACT_TYPEHASH, bytes32(0));

// 3) Arbiter submits a claim on The Compact using the allocated id/amount
// The Compact will call allocator.authorizeClaim(claimHash, ...) which consumes the allocation.
// compact.batchClaim(...) // see The Compact’s ITheCompactClaims
```

### 2) OnChainAllocator: allocateFor with sponsor signature

```solidity
// Flow: Sponsor pre-deposits; a relayer allocates on behalf of the sponsor using the sponsor’s signature.

// Build the same commitments and compute the intended claimHash off-chain for user visibility
Lock[] memory commitments = new Lock[](1);
commitments[0] = Lock({ lockTag: lockTag, token: token, amount: amount });
bytes32 commitmentsHash = /* keccak256(abi.encodePacked(LOCK(...))) over commitments */;
bytes32 claimHash = keccak256(abi.encode(BATCH_COMPACT_TYPEHASH, arbiter, sponsor, expectedNonce, expires, commitmentsHash));
bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), compact.DOMAIN_SEPARATOR(), claimHash));
bytes memory sponsorSig = /* ECDSA signature over digest by sponsor */;

// Relayer submits the allocation on behalf of the sponsor
allocator.allocateFor(sponsor, commitments, arbiter, uint32(expires), BATCH_COMPACT_TYPEHASH, bytes32(0), sponsorSig);
```

It is also possible to pre-register the `claimHash` directly via The Compact, then call `allocateFor` with an empty signature.

### 3) OnChainAllocator: two‑phase prepare/execute with implicit deposit+register

```solidity
// Caller contract or EOA funds tokens and approves Compact.
uint256[2][] memory idsAndAmounts = new uint256[2][](2);
idsAndAmounts[0] = [uint256(AllocatorLib.toId(lockTagA, tokenA)), amountA];
idsAndAmounts[1] = [uint256(AllocatorLib.toId(lockTagB, tokenB)), amountB];

// 1) Prepare: caches current ERC6909 balances in transient storage and returns the scoped nonce
uint256 nonce = allocator.prepareAllocation(recipient, idsAndAmounts, arbiter, expires, BATCH_COMPACT_TYPEHASH, bytes32(0), "");

// 2) Deposit + register exact ids/amounts on The Compact using the returned nonce
compact.batchDepositAndRegisterFor(recipient, idsAndAmounts, arbiter, nonce, expires, BATCH_COMPACT_TYPEHASH, bytes32(0));

// 3) Execute: re-checks positive balance deltas per id, reconstructs commitments, recomputes claimHash
allocator.executeAllocation(recipient, idsAndAmounts, arbiter, expires, BATCH_COMPACT_TYPEHASH, bytes32(0), "");
```

### 4) HybridAllocator: allocateAndRegister (deposit path) or off‑chain signature path

```solidity
// Deposit path (no prior sponsor signature): allocator sends its own ERC20 to Compact and registers
Lock[] memory commitments = new Lock[](1);
commitments[0] = Lock({ lockTag: lockTag, token: token, amount: 0 }); // 0 means "use allocator’s full token balance"
(bytes32 claimHash,, uint256 nonce) = hybrid.allocateAndRegister(recipient, commitments, arbiter, expires, BATCH_COMPACT_TYPEHASH, bytes32(0));

// Signature path (no on-chain pre-allocation): an authorized signer signs the Compact digest of claimHash
bytes32 digest = /* keccak256(0x1901 || DOMAIN_SEPARATOR || claimHash) */;
bytes memory allocatorData = /* ECDSA signature from an authorized signer */;
// Later, during claim, The Compact passes allocatorData into hybrid.authorizeClaim to validate
```

### 5) ERC7683Allocator: open (on‑chain) and openFor (gasless, deposit‑optional)

```solidity
// a) User-opened order (requires prior Compact registration for the claim)
IOriginSettler.OnchainCrossChainOrder memory order = IOriginSettler.OnchainCrossChainOrder({
  fillDeadline: uint32(fillDeadline),
  orderDataType: ORDERDATA_ONCHAIN_TYPEHASH,
  orderData: abi.encode(IERC7683Allocator.OrderDataOnChain({
    order: IERC7683Allocator.Order({ arbiter: arbiter, commitments: commitments, mandate: mandate }),
    expires: uint32(claimExpires)
  }))
});
erc7683Allocator.open(order); // emits Open with ResolvedCrossChainOrder for fillers

// b) Gasless order opened by filler/relayer (either sponsor-signature or deposit path)
IOriginSettler.GaslessCrossChainOrder memory gasless = IOriginSettler.GaslessCrossChainOrder({
  originSettler: address(erc7683Allocator),
  user: sponsor,
  nonce: expectedNonce,
  originChainId: block.chainid,
  openDeadline: uint32(openDeadline),
  fillDeadline: uint32(fillDeadline),
  orderDataType: ORDERDATA_GASLESS_TYPEHASH,
  orderData: abi.encode(IERC7683Allocator.OrderDataGasless({
    order: IERC7683Allocator.Order({ arbiter: arbiter, commitments: commitments, mandate: mandate }),
    deposit: true // set true to use allocator-held funds via allocateAndRegister
  }))
});
erc7683Allocator.openFor(gasless, sponsorSignature, "");
```

For complete end-to-end tests (including Tribunal integration and `ResolvedCrossChainOrder` shape), see `test/ERC7683Allocator.t.sol`.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for installation, style, branching, testing, pre-commit hooks, and deployment guidance.

## License

This codebase is published under the MIT License. See the [LICENSE](LICENSE) file for full details.
