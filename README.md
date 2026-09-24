# @chironbuilder/ootle-sdk

A shared TypeScript client for [Tari Ootle](https://github.com/tari-project/tari-ootle) (L2): account
derivation, balances, transaction building/submission with automatic input resolution, HTLCs, and
stealth/confidential transfers.

This is the account core extracted from two independently-built wallets that had converged on
(mostly) the same code by hand — [Sapient](https://github.com/chironbuilds/tari-wallet), a Chrome
extension, and the [Tari L1 web wallet](https://universe.tari.mw)'s Ootle L2 support — after each had
picked up its own fixes the other was missing. This package exists so that stops happening: one
wallet core, used by both, with platform-specific concerns (storage, in this case) injected rather
than hardcoded.

**Status: early.** Extracted and reconciled in one pass; not yet wired back into either of the two
wallets above (they still carry their own local copies for now). Treat `0.x` as exactly that.

## Install

```bash
npm install @chironbuilder/ootle-sdk
```

This package vendors two small, still-unmerged patches: `@tari-project/ootle` (a `covenant_claims`
serialization gap in `StealthTransferStatement.toCompactJson()`, harmless for every transfer this SDK
builds today but not yet upstream-fixed) and `@tari-project/ootle-wasm` (adds
`createConfidentialWithdrawProofLiteral`, needed for confidential-vault withdrawals and not in the
published `0.39.x` builds). See `vendor/*/README.md` for each. Both are tracked for removal once
upstream ships the real fix — check there before assuming either is still needed.

## Storage

The SDK never touches a concrete storage API directly. It reads and writes through a small
`KeyValueStore` interface — configure one adapter, once, before calling anything else:

```ts
import { configureOotleStorage } from "@chironbuilder/ootle-sdk";
import { chromeStorageAdapter } from "@chironbuilder/ootle-sdk/adapters";
// or: localStorageAdapter, inMemoryAdapter (tests)

configureOotleStorage(chromeStorageAdapter());
```

Write your own adapter for any other host — it's three methods (`get`/`set`/`remove`).

This only covers what the account core itself needs (shielded outputs, pending shields, the
private-payment scan cursor, the known-substate-versions cache). Address books, connected-site
permissions, daemon connections, and a full transaction-history UI are application concerns with
very different shapes per host — keep those in your own app's storage layer.

## Usage

```ts
import { OotleAccount, toOotleNetwork } from "@chironbuilder/ootle-sdk";

const account = OotleAccount.fromSeed(entropy, /* index */ 0, "esmeralda");

const balances = await account.getBalances();
await account.send(recipientWalletAddress, resourceAddress, amount);
```

See `src/wallet.ts`'s doc comments for the full `OotleAccount` surface — `send`, `sendPrivately`,
`shield`/`unshield`, `htlcFund`/`htlcClaim`/`htlcRefund`, `claimTestnetXtr`, `execute` (the general
instruction-builder escape hatch, with automatic missing-input discovery and lock-contention retry).

### Claiming a Minotari (L1) burn

A burn addressed to this account's public key (`getPublicKey()`) is claimed with `claimBurn`. Build
the proof from the L1 burn's claim material and its kernel merkle proof (a base node's
`/generate_kernel_merkle_proof`), or read a `minotari_console_wallet` proof file:

```ts
import { assembleBurnClaimProof, parseConsoleWalletBurnProof } from "@chironbuilder/ootle-sdk";

const proof = assembleBurnClaimProof(l1BurnParts, kernelMerkleProof);
// or: const proof = parseConsoleWalletBurnProof(fileText);
const { claimedAmount, commitment } = await account.claimBurn(proof, /* maxFee */ 2000n);
```

The claimed funds arrive as a stealth output owned by this account and are recorded in its private
balance. Validators accept a burn only once its L1 block is well confirmed, so an early claim is
rejected and can be retried.

## What's in here, and what isn't

- **Account core** (`wallet.ts`): `OotleAccount`, balance/plan-resolution helpers, the transaction
  auto-resolve retry loop.
- **Crypto/derivation**: `derivation.ts`, `domainHash.ts`, `componentAddress.ts`, `vault.ts`,
  `ownershipProof.ts`, `confidential.ts`.
- **HTLC**: `htlc.ts`.
- **L1 burn claims**: `burnClaim.ts` (proof assembly) + `OotleAccount.claimBurn`.
- **Storage abstraction**: `storage.ts` + `adapters.ts`.
- **Not included**: UI, an approval/permission model for dApp connections, address books, daemon
  (`tari_ootle_walletd`) relay support, transaction-history persistence. Those stay in each
  consuming application.

## Developing

```bash
npm install
npm run typecheck
npm test
npm run build
```

## License

MIT — see [LICENSE](LICENSE). (The two wallets this was extracted from are licensed separately,
under PolyForm Noncommercial; this SDK is deliberately more permissive so other Ootle projects can
build on it without that restriction.)
