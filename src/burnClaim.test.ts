import { describe, expect, it } from "vitest";
import { burnClaimStealthSecret, publicKeyFromSecretKey, validateBurnClaimOwnershipProof } from "@tari-project/ootle-wasm";
import { Network, WasmStealthCrypto } from "@tari-project/ootle";
import { assembleBurnClaimProof, parseConsoleWalletBurnProof } from "./burnClaim";
import { fromHex, toHex } from "./vault";
import fixture from "./fixtures/l1-burn.json";

// A real burn built by the L1 wallet's WASM burn builder (tari_l1_wasm `build_burn`, Esmeralda) for
// a known Ootle account secret -- not hand-derived. Exercises the same derivations `claimBurn()`
// performs before it touches the network.
const merkle = { block_hash: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", encoded_merkle_proof: "AQID", leaf_index: 7 };

function parts() {
  return {
    claimPublicKeyHex: fixture.accountPublicHex,
    commitmentHex: fixture.commitmentHex,
    ownershipNonceHex: fixture.ownershipNonceHex,
    ownershipSignatureHex: fixture.ownershipSignatureHex,
    senderOffsetPublicKeyHex: fixture.senderOffsetPublicKeyHex,
    encryptedDataHex: fixture.encryptedDataHex,
    amount: BigInt(fixture.amount),
    kernel: {
      version: fixture.kernel.version,
      fee: BigInt(fixture.kernel.fee),
      lockHeight: BigInt(fixture.kernel.lockHeight),
      excessHex: fixture.kernel.excessHex,
      nonceHex: fixture.kernel.nonceHex,
      signatureHex: fixture.kernel.signatureHex,
    },
  };
}

describe("L1 burn claims", () => {
  it("assembles the proof in Ootle's serde shape", () => {
    const { claim_proof, encrypted_data } = assembleBurnClaimProof(parts(), merkle);
    expect(claim_proof.burn_public_key).toBe(fixture.accountPublicHex);
    expect(claim_proof.ownership_proof).toEqual({ public_nonce: fixture.ownershipNonceHex, signature: fixture.ownershipSignatureHex });
    expect(claim_proof.kernel.excess_sig).toEqual({ public_nonce: fixture.kernel.nonceHex, signature: fixture.kernel.signatureHex });
    expect(claim_proof.value).toBe(String(fixture.amount));
    expect(claim_proof.encoded_merkle_proof).toEqual({ ...merkle, leaf_index: "7" });
    expect(encrypted_data).toBe(fixture.encryptedDataHex);
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
    const { claim_proof } = assembleBurnClaimProof(parts(), merkle);
    const b64 = btoa(String.fromCharCode(...fromHex(fixture.encryptedDataHex)));
    const parsed = parseConsoleWalletBurnProof(JSON.stringify({ claim_proof, encrypted_data: b64, mined_in_epoch: 3 }));
    expect(parsed.encrypted_data).toBe(fixture.encryptedDataHex);
    expect(parsed.claim_proof).toEqual(claim_proof);
  });
});
