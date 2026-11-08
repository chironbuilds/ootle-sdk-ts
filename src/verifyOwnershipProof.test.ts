// The verifiers against the real signer (round trips) and against fixed vectors produced with
// `@tari-project/ootle-wasm`'s `schnorrSign` + `generateOotleAddress` on another machine, so a
// drift in the message construction, the domain tag or the scalar handling is caught here.
import { generateOotleAddress, publicKeyFromSecretKey } from "@tari-project/ootle-wasm";
import { schnorrSign } from "@chironbuilder/ootle-wasm-legacy";
import { describe, expect, it } from "vitest";
import vectors from "./fixtures/ownershipProof.vectors.json" with { type: "json" };
import { buildOwnershipProofMessage, buildWalletOwnershipMessage } from "./ownershipProof";
import { verifyOwnershipProof, verifySchnorrSignature, verifyWalletOwnershipProof } from "./verifyOwnershipProof";

const GROUP_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;
function scalarToBytesLE(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n % GROUP_ORDER;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
function randomSecret(): Uint8Array {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return scalarToBytesLE(n % GROUP_ORDER);
}
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16));

describe("verifyWalletOwnershipProof (round trips with the real signer)", () => {
  for (const network of [0x00, 0x26, 0x24]) {
    it(`accepts what signWalletOwnership produces on network byte ${network}, and refuses every tampering`, () => {
      const owner = randomSecret(), view = randomSecret();
      const walletAddress = generateOotleAddress(publicKeyFromSecretKey(owner), publicKeyFromSecretKey(view), network, null);
      const challenge = `raddish.io wants you to sign in: nonce ${network}`;
      const sig = schnorrSign(owner, buildWalletOwnershipMessage(network, walletAddress, challenge));
      const proof = { walletAddress, challenge, publicNonce: hex(sig.public_nonce), signature: hex(sig.signature) };

      expect(verifyWalletOwnershipProof(proof)).toEqual({ valid: true, network: { 0: "mainnet", 0x26: "esmeralda", 0x24: "igor" }[network] });
      expect(verifyWalletOwnershipProof({ ...proof, publicNonce: sig.public_nonce, signature: sig.signature }).valid).toBe(true); // bytes accepted too

      const other = generateOotleAddress(publicKeyFromSecretKey(randomSecret()), publicKeyFromSecretKey(view), network, null);
      expect(verifyWalletOwnershipProof({ ...proof, walletAddress: other }).valid).toBe(false);
      expect(verifyWalletOwnershipProof({ ...proof, challenge: challenge + " " }).valid).toBe(false);
      const flipped = new Uint8Array(sig.signature);
      flipped[0]! ^= 1;
      expect(verifyWalletOwnershipProof({ ...proof, signature: flipped }).valid).toBe(false);
      expect(verifyWalletOwnershipProof({ ...proof, publicNonce: hex(publicKeyFromSecretKey(randomSecret())) }).valid).toBe(false);
    });
  }

  it("refuses a non-canonical or zero s (a malleable signature), a bad address and an over-long challenge, without throwing", () => {
    const owner = randomSecret();
    const walletAddress = generateOotleAddress(publicKeyFromSecretKey(owner), publicKeyFromSecretKey(randomSecret()), 0x26, null);
    const sig = schnorrSign(owner, buildWalletOwnershipMessage(0x26, walletAddress, "c"));
    const base = { walletAddress, challenge: "c", publicNonce: sig.public_nonce, signature: sig.signature };
    expect(verifyWalletOwnershipProof({ ...base, signature: "ff".repeat(32) }).valid).toBe(false);
    expect(verifyWalletOwnershipProof({ ...base, signature: "00".repeat(32) }).valid).toBe(false);
    expect(verifyWalletOwnershipProof({ ...base, signature: "zz" })).toMatchObject({ valid: false, reason: expect.stringContaining("hex") });
    expect(verifyWalletOwnershipProof({ ...base, walletAddress: "otl_esm1notanaddress" })).toMatchObject({ valid: false, reason: expect.stringContaining("otl_") });
    expect(verifyWalletOwnershipProof({ ...base, challenge: "x".repeat(501) })).toMatchObject({ valid: false, reason: expect.stringContaining("500") });
  });
});

describe("verifyWalletOwnershipProof (fixed vectors from Tari's real signer)", () => {
  it("every vector gives its expected verdict", () => {
    expect(vectors.vectors.length).toBeGreaterThanOrEqual(10);
    for (const v of vectors.vectors) {
      const verdict = verifyWalletOwnershipProof({ walletAddress: v.walletAddress, challenge: v.challenge, publicNonce: v.publicNonce, signature: v.signature });
      expect(verdict.valid, `${v.name}${"why" in v ? ` (${v.why})` : ""}`).toBe(v.valid);
      if (verdict.valid) expect(verdict.network).toBe(v.network);
    }
  });

  it("the message bytes are what buildWalletOwnershipMessage builds", () => {
    for (const v of vectors.vectors.filter((x) => x.valid)) {
      expect(hex(buildWalletOwnershipMessage(v.networkByte, v.walletAddress, v.challenge))).toBe(v.message);
    }
  });
});

describe("verifyOwnershipProof (per-output proof)", () => {
  it("accepts a signature by the output's key and refuses one by another key", () => {
    const secret = randomSecret();
    const publicKey = publicKeyFromSecretKey(secret);
    const fields = { networkByte: 0x26, resourceAddress: "resource_xtr", substateId: "utxo_resource_xtr_deadbeef", challenge: "prove-2026-11-07" };
    const sig = schnorrSign(secret, buildOwnershipProofMessage(fields.networkByte, fields.resourceAddress, fields.substateId, fields.challenge));
    expect(verifyOwnershipProof({ ...fields, publicKey, publicNonce: sig.public_nonce, signature: sig.signature })).toEqual({ valid: true, network: "esmeralda" });
    expect(verifyOwnershipProof({ ...fields, publicKey: publicKeyFromSecretKey(randomSecret()), publicNonce: sig.public_nonce, signature: sig.signature }).valid).toBe(false);
    expect(verifyOwnershipProof({ ...fields, substateId: "utxo_other", publicKey, publicNonce: sig.public_nonce, signature: sig.signature }).valid).toBe(false);
  });

  it("refuses non-string resourceAddress / substateId and a non-integer network byte without throwing", () => {
    const base = { publicKey: new Uint8Array(32), networkByte: 0x26, resourceAddress: "resource_x", substateId: "utxo_x", challenge: "c", publicNonce: new Uint8Array(32), signature: new Uint8Array(32) };
    expect(verifyOwnershipProof({ ...base, resourceAddress: 12 as unknown as string })).toMatchObject({ valid: false, reason: expect.stringContaining("resourceAddress") });
    expect(verifyOwnershipProof({ ...base, substateId: undefined as unknown as string })).toMatchObject({ valid: false, reason: expect.stringContaining("substateId") });
    expect(verifyOwnershipProof({ ...base, networkByte: 1.5 })).toMatchObject({ valid: false, reason: expect.stringContaining("networkByte") });
  });
});

describe("verifySchnorrSignature", () => {
  it("is a plain Schnorr check over the given message, and never throws on garbage", () => {
    const secret = randomSecret();
    const message = new TextEncoder().encode("hello");
    const sig = schnorrSign(secret, message);
    expect(verifySchnorrSignature(publicKeyFromSecretKey(secret), message, sig.public_nonce, sig.signature)).toBe(true);
    expect(verifySchnorrSignature(new Uint8Array(32), message, sig.public_nonce, sig.signature)).toBe(false);
    expect(verifySchnorrSignature(fromHex("00"), message, sig.public_nonce, sig.signature)).toBe(false);
  });
});
