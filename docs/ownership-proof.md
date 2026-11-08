# Ownership proofs: the bytes, and how to verify them

Sapient can prove two things to a website without spending anything: that the connected account
holds an `otl_…` wallet address (`tari_signWalletOwnershipChallenge`), and that it controls one
specific output (`tari_signOwnershipChallenge`). Both are Ristretto Schnorr signatures over a
domain-separated message. This page fixes the bytes so a verifier never has to read the source,
and `verifyWalletOwnershipProof` / `verifyOwnershipProof` (exported from this package) implement it.
`src/fixtures/ownershipProof.vectors.json` carries fixed vectors produced with Tari's real signer.

## Hashing

Every message is Tari's domain-separated BLAKE2b-512 (`tari_crypto::hashing::DomainSeparatedHasher`,
reproduced in `domainHash.ts`):

```
tag     = "<domain>.v<version>.<label>"                 (UTF-8)
digest  = BLAKE2b-512( u64le(len(tag)) ‖ tag ‖ u64le(len(c1)) ‖ c1 ‖ u64le(len(c2)) ‖ c2 ‖ … )
```

Each chunk is prefixed by its byte length as a little-endian 64-bit integer. The output is 64 bytes.

## Message 1: wallet ownership

```
domain  = "com.tari.paylink.wallet_ownership_proof"   version = 1   label = "v1"
chunks  = [ networkByte (1 byte) , walletAddress (UTF-8) , challenge (UTF-8) ]
```

- `networkByte` is the byte carried by the address itself (`ParsedOotleAddress.network`): 0x00 mainnet, 0x26 Esmeralda, 0x24 Igor.
- `walletAddress` is the bech32m string exactly as the wallet returns it (no trimming by the signer).
- `challenge` is the verifier's text, at most 500 characters (`OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH`); the wallet refuses longer.

The signing key is the account's owner (spend) key. The wallet returns `{ walletAddress, publicNonce, signature }`, the last two as lowercase hex of 32 bytes each.

## Message 2: output ownership

```
domain  = "com.tari.paylink.ownership_proof"   version = 1   label = "v1"
chunks  = [ networkByte (1 byte) , resourceAddress (UTF-8) , substateId (UTF-8) , challenge (UTF-8) ]
```

The signing key is the output's one-time key (`stealthDhSecret`), which only the output's owner can derive. The wallet returns `{ publicNonce, signature }`.

## Signature and verification

Tari's Schnorr (`tari_crypto` `schnorr.rs`) over ristretto255, with `G` the base point and `l` the group order:

```
e      = BLAKE2b-512 under ("com.tari.schnorr_signature", 1, "challenge") of [ R , P , message ]   mod l
valid  ⇔  s·G == R + e·P
```

where `R` = `publicNonce`, `P` = the signer's public key and `s` = `signature`, scalars little-endian. A verifier must refuse `s = 0` and `s ≥ l` (non-canonical scalars are malleable), and an `R` or `P` that does not decode as a ristretto point.

**Where `P` comes from matters.** For the wallet proof, decode it from the `walletAddress` the verifier already had in mind (`parseOotleAddress(...).owner_key`); never accept a key the prover sends. For the output proof, use the one-time public key the verifier derived or read from the chain.

## Using the verifier

```ts
import { verifyWalletOwnershipProof } from "@chironbuilder/ootle-sdk";

const verdict = verifyWalletOwnershipProof({
  walletAddress,          // the address your site expects
  challenge,              // the exact text you issued
  publicNonce, signature, // as the wallet returned them (hex or bytes)
});
if (!verdict.valid) reject(verdict.reason);
else trust(verdict.network); // "mainnet" | "esmeralda" | "igor", read from the address
```

Issue a fresh, unguessable challenge per sign-in, bind it to the session that asked, and expire it within minutes: the signature proves control of the key at the time of signing, nothing more.

## Why these domains

The owner key also signs real transactions, under `"com.tari.ootle.transaction"`. A signature over caller-chosen bytes under that domain could be replayed as spend authorization; a disjoint, fixed domain prepended by the wallet's own code (never by the caller) makes the two message spaces unable to collide under the same assumption Tari already relies on to keep its own domains apart. The two proofs use different domains from each other for the same reason: one domain per kind of claim.
