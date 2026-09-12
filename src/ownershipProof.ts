// A dApp-facing proof that this account currently controls a specific stealth output's spend
// key, without spending it and without producing anything that could ever be replayed as a real
// transaction's authorization signature.
//
// The one-time secret this signs with (`c + k`, from `stealthDhSecret`) is exactly what
// `SecretKeyWallet.addStealthSignature` uses to authorize spending the same output -- so the
// message this signs must never be, or be derivable into, a real `hashUnsignedTransaction` output.
// Real transaction signing hashes under domain "com.tari.ootle.transaction"
// (tari-dan `crates/transaction/src/hashing.rs`); this hashes under a disjoint domain of its own,
// so the two message spaces cannot collide under the same collision-resistance assumption Tari's
// own protocol already relies on to keep ITS OWN domains apart (see domainHash.ts).
//
// Byte-identical across every consumer of this SDK -- a dApp must get the same signature semantics
// from any wallet built on it. Verified empirically against tari-crypto's own committed domain-tag
// test vector and round-tripped against the real `schnorrSign` WASM primitive; see
// ownershipProof.test.ts and tari-paylink-dapp's scripts/verify-schnorr-roundtrip.mjs, which this
// construction must stay byte-identical to.
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { DomainSeparatedHasher } from "./domainHash.js";

const OWNERSHIP_PROOF_DOMAIN = "com.tari.paylink.ownership_proof";
const OWNERSHIP_PROOF_VERSION = 1;
export const OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH = 500;

export function buildOwnershipProofMessage(
  networkByte: number,
  resourceAddress: string,
  substateId: string,
  challenge: string,
): Uint8Array {
  if (challenge.length > OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH) {
    throw new Error(`Challenge text is too long (${OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH} characters max).`);
  }
  return new DomainSeparatedHasher(OWNERSHIP_PROOF_DOMAIN, OWNERSHIP_PROOF_VERSION, "v1", 64)
    .chain(new Uint8Array([networkByte]))
    .chain(utf8ToBytes(resourceAddress))
    .chain(utf8ToBytes(substateId))
    .chain(utf8ToBytes(challenge))
    .finalize();
}

// A generic "I hold this otl_… wallet address" proof — signs with the account's own persistent
// owner key (the same key `SecretKeyWallet.signTransaction` uses for revealed-balance spends),
// NOT a per-output derived key. Same domain-separation reasoning as above applies with equal force
// here: this key signs real transactions too, so the message must live under its own domain,
// disjoint from "com.tari.ootle.transaction", or a signature could be replayable as spend
// authorization. Deliberately a DIFFERENT domain from the per-output proof above as well, even
// though the two never share a signing key -- one domain per distinct kind of claim being signed,
// so a signature can never be mistaken for the wrong kind of proof.
const WALLET_OWNERSHIP_PROOF_DOMAIN = "com.tari.paylink.wallet_ownership_proof";
const WALLET_OWNERSHIP_PROOF_VERSION = 1;

export function buildWalletOwnershipMessage(networkByte: number, walletAddress: string, challenge: string): Uint8Array {
  if (challenge.length > OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH) {
    throw new Error(`Challenge text is too long (${OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH} characters max).`);
  }
  return new DomainSeparatedHasher(WALLET_OWNERSHIP_PROOF_DOMAIN, WALLET_OWNERSHIP_PROOF_VERSION, "v1", 64)
    .chain(new Uint8Array([networkByte]))
    .chain(utf8ToBytes(walletAddress))
    .chain(utf8ToBytes(challenge))
    .finalize();
}
