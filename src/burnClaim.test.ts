import { describe, expect, it } from "vitest";
import { burnClaimStealthSecret, publicKeyFromSecretKey, validateBurnClaimOwnershipProof } from "@tari-project/ootle-wasm";
import { Network, WasmStealthCrypto } from "@tari-project/ootle";
import { assembleBurnClaimProof, claimProofFromL1, decodeBurnOutputFeatures, parseConsoleWalletBurnProof } from "./burnClaim";
import type { BurnOutputProof } from "./burnClaim";
import vectors from "./burnClaim.vectors.json";
import { fromHex, toHex } from "./vault";
import fixture from "./fixtures/l1-burn.json";

// A real burn built by the L1 wallet's WASM burn builder (tari_l1_wasm `build_burn`, Esmeralda) for
// a known Ootle account secret -- not hand-derived. Exercises the same derivations `claimBurn()`
// performs before it touches the network.
// A base node's output proof for the fixture burn: the real commitment, synthetic inclusion data.
function outputProof(): BurnOutputProof {
  const v = structuredClone(vectors[0]!.base_node_proof) as unknown as BurnOutputProof;
  v.output.commitment = fixture.commitmentHex;
  return v;
}

function parts() {
  return {
    claimPublicKeyHex: fixture.accountPublicHex,
    commitmentHex: fixture.commitmentHex,
    ownershipNonceHex: fixture.ownershipNonceHex,
    ownershipSignatureHex: fixture.ownershipSignatureHex,
    senderOffsetPublicKeyHex: fixture.senderOffsetPublicKeyHex,
    encryptedDataHex: fixture.encryptedDataHex,
    amount: BigInt(fixture.amount),
  };
}

/** JSON numbers and decimal strings are the same u64 on the wire. */
function normalize(v: unknown): unknown {
  return JSON.parse(JSON.stringify(v), (_k, x) => (typeof x === "number" ? String(x) : x));
}

describe("L1 burn output proof conversion (vs claim_proof_from_l1)", () => {
  // burnClaim.vectors.json is written by tari-ootle's own `claim_proof_from_l1`
  // (tests/claim_vectors.rs in tari_ootle_app_utilities, v0.42.0 + Minotari 6.0.1-pre.2).
  for (const [i, v] of vectors.entries()) {
    it(`matches the Rust conversion (vector ${i})`, () => {
      const l1 = v.base_node_proof as unknown as BurnOutputProof;
      const rust = v.claim_proof as { ownership_proof: { public_nonce: string; signature: string }; value: number };
      expect(normalize(claimProofFromL1(l1, rust.ownership_proof, rust.value))).toEqual(normalize(v.claim_proof));
    });
  }

  it("refuses outputs Ootle cannot mint against", () => {
    const burn = vectors[0]!.base_node_proof.output.features;
    const notBurn = "0000" + burn.slice(4); // output type Standard
    expect(() => decodeBurnOutputFeatures(notBurn)).toThrow(/not a burn/);
    const noSidechain = burn.slice(0, 2 + 2 + 16 + 8) + "00" + "00"; // None, then range proof type
    expect(() => decodeBurnOutputFeatures(noSidechain)).toThrow(/no sidechain feature/);
    const otherFeature = burn.slice(0, 30) + "03" + burn.slice(32);
    expect(() => decodeBurnOutputFeatures(otherFeature)).toThrow(/not a confidential output/);
    expect(() => decodeBurnOutputFeatures(burn.slice(0, -2))).toThrow(/truncated/);
    expect(() => decodeBurnOutputFeatures(burn + "00")).toThrow(/trailing/);
  });
});

describe("L1 burn claims", () => {
  it("assembles the proof in Ootle's serde shape", () => {
    const { claim_proof, encrypted_data } = assembleBurnClaimProof(parts(), outputProof());
    expect(claim_proof.commitment).toBe(fixture.commitmentHex);
    expect(claim_proof.ownership_proof).toEqual({ public_nonce: fixture.ownershipNonceHex, signature: fixture.ownershipSignatureHex });
    expect(claim_proof.value).toBe(String(fixture.amount));
    expect(claim_proof.inclusion_proof.block_hash).toBe(vectors[0]!.base_node_proof.block_hash);
    expect(encrypted_data).toBe(fixture.encryptedDataHex);
  });

  it("refuses an output proof for a different commitment", () => {
    const wrong = outputProof();
    wrong.output.commitment = "11".repeat(32);
    expect(() => assembleBurnClaimProof(parts(), wrong)).toThrow(/different commitment/);
  });

  it("derives the on-chain claim key, verifies ownership and decrypts the value", async () => {
    const accountSecret = fromHex(fixture.accountSecretHex);
    const senderOffset = fromHex(fixture.senderOffsetPublicKeyHex);
    const s = burnClaimStealthSecret(accountSecret, senderOffset);
    expect(toHex(publicKeyFromSecretKey(s))).toBe(fixture.stealthClaimPublicHex);

    const verify = (value: bigint, secret: Uint8Array) =>
      validateBurnClaimOwnershipProof(
        Network.Esmeralda,
        fromHex(fixture.ownershipNonceHex),
        fromHex(fixture.ownershipSignatureHex),
        fromHex(fixture.commitmentHex),
        value,
        secret
      );
    expect(verify(BigInt(fixture.amount), s)).toBe(true);
    expect(verify(BigInt(fixture.amount) + 1n, s)).toBe(false);

    const crypto = new WasmStealthCrypto(Network.Esmeralda);
    const key = await crypto.deriveAeadKey(accountSecret, senderOffset);
    const decrypted = await crypto.unblindOutput(fromHex(fixture.commitmentHex), fromHex(fixture.encryptedDataHex), key, true);
    expect(decrypted.value).toBe(BigInt(fixture.amount));
  });

  it("rejects a burn addressed to a different account", () => {
    const other = new Uint8Array(32);
    other[0] = 7;
    const s = burnClaimStealthSecret(other, fromHex(fixture.senderOffsetPublicKeyHex));
    expect(
      validateBurnClaimOwnershipProof(
        Network.Esmeralda,
        fromHex(fixture.ownershipNonceHex),
        fromHex(fixture.ownershipSignatureHex),
        fromHex(fixture.commitmentHex),
        BigInt(fixture.amount),
        s
      )
    ).toBe(false);
  });

  it("reads a minotari_console_wallet proof file (base64 encrypted_data)", () => {
    const { claim_proof } = assembleBurnClaimProof(parts(), outputProof());
    const b64 = btoa(String.fromCharCode(...fromHex(fixture.encryptedDataHex)));
    const file = {
      claim_proof: {
        burn_public_key: fixture.accountPublicHex,
        ownership_proof: { public_nonce: fixture.ownershipNonceHex, signature: fixture.ownershipSignatureHex },
        output_proof: outputProof(),
        value: Number(fixture.amount),
      },
      encrypted_data: b64,
      mined_in_epoch: 3,
    };
    const parsed = parseConsoleWalletBurnProof(JSON.stringify(file));
    expect(parsed.encrypted_data).toBe(fixture.encryptedDataHex);
    expect(parsed.claim_proof).toEqual(claim_proof);
  });

  it("explains a pre-0.42 (kernel) proof file instead of submitting it", () => {
    const old = { claim_proof: { burn_public_key: "00".repeat(32), kernel: {}, encoded_merkle_proof: {} }, encrypted_data: "00" };
    expect(() => parseConsoleWalletBurnProof(old)).toThrow(/predates Ootle 0.42/);
  });
});
