// Verifiers for the two ownership proofs (ownershipProof.ts), so a site that receives
// `{ walletAddress, publicNonce, signature }` from `tari_signWalletOwnershipChallenge` can check it
// without rebuilding the bytes by hand. Until now every integrator re-derived the message
// construction from the source; the byte spec is in docs/ownership-proof.md and the fixed vectors
// in fixtures/ownershipProof.vectors.json pin it.
//
// What a verifier must never do: trust a public key the prover reports about themselves. The wallet
// proof takes its key FROM the address (`parseOotleAddress`), the address being the thing the
// verifier already had in mind; the per-output proof takes the one-time public key the verifier
// derived or read from the chain. Both are passed in by the verifier, never by the prover.
//
// The Schnorr check mirrors tari-crypto's `SchnorrSignature::verify` (schnorr.rs):
//   e = H("com.tari.schnorr_signature.v1.challenge", R, P, message) mod l
//   valid iff s·G == R + e·P
// with H the length-prefixed domain-separated BLAKE2b-512 (domainHash.ts) and l the ristretto255
// group order. `s` must be canonical (0 < s < l): a non-canonical scalar is a malleable signature,
// which tari-crypto also refuses.
import { ristretto255 } from "@noble/curves/ed25519.js";
import { parseOotleAddress } from "@tari-project/ootle-wasm";
import { DomainSeparatedHasher } from "./domainHash.js";
import { Network } from "@tari-project/ootle";
import { OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH, buildOwnershipProofMessage, buildWalletOwnershipMessage } from "./ownershipProof.js";

const { Point } = ristretto255;

/** The network an address or output says it is on. Wider than `NetworkName` on purpose: a verifier
 * checks proofs from any network an address can name, whether or not this SDK creates accounts
 * there. */
export type ProofNetwork = "mainnet" | "esmeralda" | "igor";

function proofNetworkFromByte(byte: number): ProofNetwork | undefined {
  switch (byte) {
    case Network.MainNet:
      return "mainnet";
    case Network.Esmeralda:
      return "esmeralda";
    case Network.Igor:
      return "igor";
    default:
      return undefined;
  }
}
const GROUP_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;

function scalarFromBytesLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return n;
}

function bytesOf(value: Uint8Array | string): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (typeof value !== "string" || value.length === 0 || value.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(value)) return null;
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/**
 * Tari Ristretto Schnorr verification over an already-built message. Never throws: a malformed
 * point, a non-canonical scalar or a wrong length is simply `false`.
 */
export function verifySchnorrSignature(publicKey: Uint8Array, message: Uint8Array, publicNonce: Uint8Array, signature: Uint8Array): boolean {
  try {
    if (publicKey.length !== 32 || publicNonce.length !== 32 || signature.length !== 32) return false;
    const s = scalarFromBytesLE(signature);
    if (s === 0n || s >= GROUP_ORDER) return false;
    const P = Point.fromBytes(publicKey);
    const R = Point.fromBytes(publicNonce);
    if (P.equals(Point.ZERO)) return false;
    const challenge = new DomainSeparatedHasher("com.tari.schnorr_signature", 1, "challenge", 64)
      .chain(publicNonce)
      .chain(publicKey)
      .chain(message)
      .finalize();
    const e = scalarFromBytesLE(challenge) % GROUP_ORDER;
    return Point.BASE.multiply(s).equals(R.add(P.multiply(e)));
  } catch {
    return false;
  }
}

export interface WalletOwnershipProof {
  /** The `otl_…` address the proof is about: the verifier's own copy, never the prover's claim. */
  walletAddress: string;
  /** The exact challenge text the verifier issued. */
  challenge: string;
  /** Hex or raw bytes, as `tari_signWalletOwnershipChallenge` returned them. */
  publicNonce: Uint8Array | string;
  signature: Uint8Array | string;
}

export type ProofVerdict = { valid: true; network: ProofNetwork } | { valid: false; reason: string };

/**
 * Checks a `tari_signWalletOwnershipChallenge` result: that `signature` is the account's owner key
 * (decoded from `walletAddress`) signing `buildWalletOwnershipMessage(network, walletAddress,
 * challenge)`, where `network` is the byte carried by the address itself.
 */
export function verifyWalletOwnershipProof({ walletAddress, challenge, publicNonce, signature }: WalletOwnershipProof): ProofVerdict {
  if (typeof walletAddress !== "string" || walletAddress.length === 0) return { valid: false, reason: "walletAddress must be a non-empty string." };
  if (typeof challenge !== "string" || challenge.length === 0) return { valid: false, reason: "challenge must be a non-empty string." };
  // UTF-16 code units, the same count the signer applies (ownershipProof.ts), so verifier and signer
  // agree on what is too long.
  if (challenge.length > OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH) {
    return { valid: false, reason: `challenge is longer than ${OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH} characters, which the wallet refuses to sign.` };
  }
  let parsed;
  try {
    parsed = parseOotleAddress(walletAddress.trim());
  } catch {
    return { valid: false, reason: "walletAddress is not a valid otl_ address." };
  }
  const network = proofNetworkFromByte(parsed.network);
  if (!network) return { valid: false, reason: `walletAddress is on an unsupported network (byte ${parsed.network}).` };
  const R = bytesOf(publicNonce);
  const s = bytesOf(signature);
  if (!R || !s) return { valid: false, reason: "publicNonce and signature must be 32-byte hex strings or byte arrays." };
  const message = buildWalletOwnershipMessage(parsed.network, walletAddress.trim(), challenge);
  return verifySchnorrSignature(parsed.owner_key, message, R, s)
    ? { valid: true, network }
    : { valid: false, reason: "The signature does not match this wallet address and challenge." };
}

export interface OutputOwnershipProof {
  /** The one-time public key of the output being proved, as the verifier derived or read it. */
  publicKey: Uint8Array | string;
  /** The network byte the output lives on (`ParsedOotleAddress.network`, or `Network.*`). */
  networkByte: number;
  resourceAddress: string;
  substateId: string;
  challenge: string;
  publicNonce: Uint8Array | string;
  signature: Uint8Array | string;
}

/** Checks a `tari_signOwnershipChallenge` result against the output's one-time public key. */
export function verifyOwnershipProof({ publicKey, networkByte, resourceAddress, substateId, challenge, publicNonce, signature }: OutputOwnershipProof): ProofVerdict {
  if (typeof challenge !== "string" || challenge.length === 0) return { valid: false, reason: "challenge must be a non-empty string." };
  if (challenge.length > OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH) {
    return { valid: false, reason: `challenge is longer than ${OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH} characters, which the wallet refuses to sign.` };
  }
  if (typeof resourceAddress !== "string" || resourceAddress.length === 0) return { valid: false, reason: "resourceAddress must be a non-empty string." };
  if (typeof substateId !== "string" || substateId.length === 0) return { valid: false, reason: "substateId must be a non-empty string." };
  if (!Number.isInteger(networkByte)) return { valid: false, reason: "networkByte must be an integer." };
  const network = proofNetworkFromByte(networkByte);
  if (!network) return { valid: false, reason: `unsupported network byte ${networkByte}.` };
  const P = bytesOf(publicKey);
  const R = bytesOf(publicNonce);
  const s = bytesOf(signature);
  if (!P || !R || !s) return { valid: false, reason: "publicKey, publicNonce and signature must be 32-byte hex strings or byte arrays." };
  const message = buildOwnershipProofMessage(networkByte, resourceAddress, substateId, challenge);
  return verifySchnorrSignature(P, message, R, s)
    ? { valid: true, network }
    : { valid: false, reason: "The signature does not match this output's key and challenge." };
}
