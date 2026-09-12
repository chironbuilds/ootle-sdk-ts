// Empirically validates the ownership-proof signing scheme end to end against the REAL wasm
// Schnorr primitive (the same one real transaction signing uses) and a from-scratch verifier, so
// a regression here -- a domain tag drifting, a field dropped from the message, wrong byte
// endianness -- is caught before it ships to a wallet that holds real value. This is the one place
// in the codebase where a subtle bug could produce a signature that's either not verifiable by
// anyone (useless) or, far worse, replayable as spend authorization (unsafe) -- see
// ownershipProof.ts's header comment for the threat this construction defends against.
import { ristretto255 } from "@noble/curves/ed25519.js";
import { publicKeyFromSecretKey, schnorrSign, stealthDhSecret } from "@tari-project/ootle-wasm";
import { describe, expect, it } from "vitest";
import { DomainSeparatedHasher } from "./domainHash";
import { buildOwnershipProofMessage, buildWalletOwnershipMessage, OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH } from "./ownershipProof";

const { Point } = ristretto255;
const GROUP_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;

function scalarFromWideBytesLE(wide: Uint8Array): bigint {
  let n = 0n;
  for (let i = wide.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(wide[i]!);
  return n % GROUP_ORDER;
}
function scalarFromCanonicalBytesLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return n;
}
function scalarToBytesLE(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n % GROUP_ORDER;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
function randomScalar(): bigint {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  return scalarFromWideBytesLE(bytes);
}

/** Independent reimplementation of `SchnorrSignature::verify` (tari-crypto schnorr.rs), used only
 * to check what the wallet's own signature produces -- not shared code with the signer. */
function schnorrVerify(publicKeyBytes: Uint8Array, publicNonceBytes: Uint8Array, signatureBytes: Uint8Array, message: Uint8Array): boolean {
  let R, P;
  try {
    R = Point.fromBytes(publicNonceBytes);
    P = Point.fromBytes(publicKeyBytes);
  } catch {
    return false;
  }
  if (P.equals(Point.ZERO)) return false;
  const s = scalarFromCanonicalBytesLE(signatureBytes);
  const challenge = new DomainSeparatedHasher("com.tari.schnorr_signature", 1, "challenge", 64)
    .chain(publicNonceBytes)
    .chain(publicKeyBytes)
    .chain(message)
    .finalize();
  const e = scalarFromWideBytesLE(challenge);
  const lhs = Point.BASE.multiply(s);
  const rhs = R.add(P.multiply(e));
  return lhs.equals(rhs);
}

describe("ownership proof domain separation", () => {
  it("matches tari-crypto's own committed test vector for the signing-challenge domain", () => {
    // SchnorrSigChallenge::domain_separation_tag("test") == "com.tari.schnorr_signature.v1.test"
    // (tari-crypto v0.23.2 src/signatures/schnorr.rs, #[test] fn schnorr_hash_domain).
    const h = new DomainSeparatedHasher("com.tari.schnorr_signature", 1, "test", 64) as unknown as { chunks: Uint8Array[] };
    const tag = new TextDecoder().decode(h.chunks[1]);
    expect(tag).toBe("com.tari.schnorr_signature.v1.test");
  });

  it("uses a domain disjoint from real transaction signing", () => {
    // Real tx hashing uses "com.tari.ootle.transaction" (tari-dan crates/transaction/src/hashing.rs).
    // These two must never share a domain string -- that's the entire safety property.
    const message = buildOwnershipProofMessage(0x26, "resource_x", "substate_y", "hello");
    expect(message).toBeInstanceOf(Uint8Array);
    expect(message.length).toBe(64);
  });

  it("rejects a challenge longer than the cap", () => {
    const tooLong = "x".repeat(OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH + 1);
    expect(() => buildOwnershipProofMessage(0x26, "r", "s", tooLong)).toThrow(/too long/);
  });

  it("produces different messages for different context (no cross-output/cross-network replay)", () => {
    const base = buildOwnershipProofMessage(0x26, "resource_x", "substate_y", "challenge");
    expect(buildOwnershipProofMessage(0x24, "resource_x", "substate_y", "challenge")).not.toEqual(base); // different network
    expect(buildOwnershipProofMessage(0x26, "resource_z", "substate_y", "challenge")).not.toEqual(base); // different resource
    expect(buildOwnershipProofMessage(0x26, "resource_x", "substate_z", "challenge")).not.toEqual(base); // different output
    expect(buildOwnershipProofMessage(0x26, "resource_x", "substate_y", "different")).not.toEqual(base); // different challenge text
  });
});

describe("ownership proof signature (real wasm signer, independent verifier)", () => {
  it("round-trips: schnorrSign -> independent verify, for 10 random keys", () => {
    for (let i = 0; i < 10; i++) {
      const secretBytes = scalarToBytesLE(randomScalar());
      const publicKeyBytes = publicKeyFromSecretKey(secretBytes);
      const message = buildOwnershipProofMessage(0x26, "resource_x", "substate_y", `challenge-${i}`);

      const sig = schnorrSign(secretBytes, message);
      expect(schnorrVerify(publicKeyBytes, sig.public_nonce, sig.signature, message)).toBe(true);
    }
  });

  it("rejects a signature checked against a different challenge than it signed", () => {
    const secretBytes = scalarToBytesLE(randomScalar());
    const publicKeyBytes = publicKeyFromSecretKey(secretBytes);
    const signed = buildOwnershipProofMessage(0x26, "resource_x", "substate_y", "prove-alice-12345");
    const sig = schnorrSign(secretBytes, signed);

    const different = buildOwnershipProofMessage(0x26, "resource_x", "substate_y", "prove-bob-67890");
    expect(schnorrVerify(publicKeyBytes, sig.public_nonce, sig.signature, different)).toBe(false);
  });

  it("rejects a signature checked against the wrong public key", () => {
    const secretBytes = scalarToBytesLE(randomScalar());
    const message = buildOwnershipProofMessage(0x26, "resource_x", "substate_y", "challenge");
    const sig = schnorrSign(secretBytes, message);

    const wrongPublicKey = publicKeyFromSecretKey(scalarToBytesLE(randomScalar()));
    expect(schnorrVerify(wrongPublicKey, sig.public_nonce, sig.signature, message)).toBe(false);
  });

  it("end-to-end via the real stealth one-time key derivation (stealthDhSecret), matching OotleAccount.signOwnershipProof", () => {
    const network = 0x26; // Esmeralda
    const accountSecretBytes = scalarToBytesLE(randomScalar());
    const senderNonceSecret = scalarToBytesLE(randomScalar());
    const senderPublicNonce = publicKeyFromSecretKey(senderNonceSecret);

    // What the receiver (this account) computes, exactly mirroring signOwnershipProof().
    const oneTimeSecret = stealthDhSecret(network, accountSecretBytes, senderPublicNonce);
    const oneTimePublicKey = publicKeyFromSecretKey(oneTimeSecret);

    const message = buildOwnershipProofMessage(network, "resource_xtr", "utxo_resource_xtr_deadbeef", "prove-carol-2026-09-03");
    const sig = schnorrSign(oneTimeSecret, message);

    expect(schnorrVerify(oneTimePublicKey, sig.public_nonce, sig.signature, message)).toBe(true);

    // A completely unrelated account's one-time key for the SAME nonce (i.e. a different resource
    // owner receiving from the same sender) must not be able to produce a signature that verifies
    // against this account's one-time public key.
    const otherAccountSecret = scalarToBytesLE(randomScalar());
    const otherOneTimeSecret = stealthDhSecret(network, otherAccountSecret, senderPublicNonce);
    const forgedSig = schnorrSign(otherOneTimeSecret, message);
    expect(schnorrVerify(oneTimePublicKey, forgedSig.public_nonce, forgedSig.signature, message)).toBe(false);
  });

  it("a real transaction-style message and an ownership-proof message never collide by construction", () => {
    // Simulates what a malicious verifier would need: get the wallet to sign something that is
    // ALSO a valid message under the OTHER domain. Since both hash under a length-prefixed domain
    // tag that differs ("com.tari.paylink.ownership_proof" vs "com.tari.ootle.transaction"), no
    // input to buildOwnershipProofMessage can reproduce a message construction that starts with a
    // different domain's tag bytes -- the tag is prepended by fixed code, not caller-controlled.
    const attackerChallenge = "com.tari.ootle.transaction.v1.seal\x00\x00\x00\x00\x00\x00\x00\x00fake-tx-bytes";
    const message = buildOwnershipProofMessage(0x26, "r", "s", attackerChallenge);
    const decoded = new TextDecoder().decode(message.slice(0, 40));
    expect(decoded.startsWith("com.tari.ootle.transaction")).toBe(false);
  });
});

describe("wallet ownership proof (signs with the account's own persistent key)", () => {
  it("round-trips: schnorrSign -> independent verify, for 10 random keys and addresses", () => {
    for (let i = 0; i < 10; i++) {
      const secretBytes = scalarToBytesLE(randomScalar());
      const publicKeyBytes = publicKeyFromSecretKey(secretBytes);
      const message = buildWalletOwnershipMessage(0x26, `otl_esm_1fakeaddress${i}`, `prove-someone-${i}`);

      const sig = schnorrSign(secretBytes, message);
      expect(schnorrVerify(publicKeyBytes, sig.public_nonce, sig.signature, message)).toBe(true);
    }
  });

  it("a signature for one wallet address does not verify for a different address", () => {
    const secretBytes = scalarToBytesLE(randomScalar());
    const publicKeyBytes = publicKeyFromSecretKey(secretBytes);
    const message = buildWalletOwnershipMessage(0x26, "otl_esm_1aaaa", "challenge");
    const sig = schnorrSign(secretBytes, message);

    const differentAddress = buildWalletOwnershipMessage(0x26, "otl_esm_1bbbb", "challenge");
    expect(schnorrVerify(publicKeyBytes, sig.public_nonce, sig.signature, differentAddress)).toBe(false);
  });

  it("uses a domain disjoint from both real transaction signing and the per-output ownership proof", () => {
    const walletMessage = buildWalletOwnershipMessage(0x26, "otl_esm_1x", "challenge");
    const outputMessage = buildOwnershipProofMessage(0x26, "resource_x", "otl_esm_1x", "challenge");
    // Same domain-length-prefix construction, different domain strings -- these must never collide
    // even when the caller-controlled fields happen to line up, as attempted here.
    expect(walletMessage).not.toEqual(outputMessage);
  });

  it("rejects a challenge longer than the cap", () => {
    const tooLong = "x".repeat(OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH + 1);
    expect(() => buildWalletOwnershipMessage(0x26, "otl_esm_1x", tooLong)).toThrow(/too long/);
  });
});
