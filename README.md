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
// The fee is measured with a dry run; a stealth-revealed fee is never refunded, so it is not padded.
const { claimedAmount, fee } = await account.claimBurn(proof);
```

The claimed funds arrive as a stealth output owned by this account and are recorded in its private
balance. Validators accept a burn only once its L1 block is well confirmed, so an early claim is
rejected and can be retried.

### HTLCs and atomic swaps

`htlcFund` / `htlcClaim` / `htlcRefund` are built for settlement safety, not just for constructing
the transactions:

```ts
// Lock 5,000 units of a stealth-created asset from exact private outputs. The fee stays in its own
// native-TARI lane (here: private), the asset stays in the main lane, excess comes back as change.
const fund = await account.htlcFund(asset, 5_000n, claimantAddress, hashLockHex, refundEpoch, 50_000n,
  { kind: "private", feeResourceAddress: TARI }, { source: { kind: "stealth", commitments: [myUtxo] } });
// fund.conditions → send to the claimant. fund.outputMask is also journaled (fund.journalId).

// Claimant: nothing is revealed unless the funded output matches the agreed terms.
const check = await account.verifyHtlc(asset, fund.ownCommitment, fund.conditions, { amount: 5_000n, minEpochsBeforeRefund: 3n });
await account.htlcClaim(asset, fund.ownCommitment, fund.conditions, preimageHex, 50_000n, feeType,
  { expected: { amount: 5_000n, refunderPublicKeyHex, minEpochsBeforeRefund: 3n } });

// Funder, once currentEpoch >= refundEpoch:
await account.refundFromJournal(fund.journalId);
```

- **Two lanes.** The fee (native TARI, public or a private UTXO) never shares a UTXO with the HTLC
  value. `source: { kind: "stealth" }` spends this account's own stealth outputs of the resource,
  so no public balance of it is needed.
- **Dry run first.** Every fund/claim/refund dry-runs the exact transaction before the real submit
  (`preflight: false` to skip — a claim's dry run sends the preimage to the indexer's dry-run
  endpoint).
- **Verified before the preimage leaves the device.** `htlcClaim` (and `verifyHtlc`) checks the
  amount, that the claim leaf is your key and the refund leaf the agreed counterparty's, that the
  on-chain condition root equals the tree's root, that the preimage matches the hash lock, and that
  enough claim epochs remain; it throws `HtlcVerificationError` otherwise.
- **Durable journal.** The sealed transaction, the condition tree and the HTLC output's mask (the
  only thing that makes a refund possible) are persisted *before* submission. An ambiguous outcome
  throws `HtlcUnknownOutcomeError` — "pending", never "failed" — and `reconcileHtlcs()` (call at
  startup) resolves it by resubmitting the identical transaction and applying its bookkeeping.
  `listHtlcs()` shows every operation and its state.
- **Exact inputs are reserved** for the duration of an operation (and while its outcome is
  unknown), so a concurrent send/unshield/fee selection can't pick them.
- **Epoch rules match the engine:** the refund leaf is `AfterEpoch` (open when
  `currentEpoch >= refundEpoch`), the claim leaf `BeforeEpoch` — see `isHtlcRefundable` /
  `isHtlcClaimableByEpoch`.
- Claimed and refunded outputs are recorded in the shielded ledger, so they're spendable at once.

## What's in here, and what isn't

- **Account core** (`wallet.ts`): `OotleAccount`, balance/plan-resolution helpers, the transaction
  auto-resolve retry loop.
- **Crypto/derivation**: `derivation.ts`, `domainHash.ts`, `componentAddress.ts`, `vault.ts`,
  `ownershipProof.ts`, `confidential.ts`.
- **HTLC**: `htlc.ts` (condition trees), `htlcSafety.ts` (epoch rules, pre-claim verification,
  per-output masks, outcome classification) + the journaled `OotleAccount` HTLC methods.
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
