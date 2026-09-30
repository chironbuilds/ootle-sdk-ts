// LIVE Esmeralda dry run of an L1 burn claim in the Ootle 0.42 format (tari-ootle#2709). Nothing is
// submitted: the indexer's dry run checks everything about a claim except the burn's L1 inclusion,
// so this exercises the claim proof decode, the ownership proof, the claim-key signer rule, the
// revealed-output receiver (#2645) and the 0.42 transaction encoding against the real network.
//   npx vitest run --config live/vitest.live.config.ts live/claim-burn.live.test.ts
import { describe, expect, it } from "vitest";
import { SecretKeyWallet } from "@tari-project/ootle-secret-key-wallet";
import { Network } from "@tari-project/ootle";
import { OotleAccount, assembleBurnClaimProof, configureOotleStorage } from "../src/index";
import type { BurnOutputProof } from "../src/index";
import { inMemoryAdapter } from "../src/adapters";
import { fromHex } from "../src/vault";
import fixture from "../src/fixtures/l1-burn.json";

const u32le = (n: number) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, n >>> 24].map((b) => b.toString(16).padStart(2, "0")).join("");

// L1 borsh `OutputFeatures` of a burn made out to `claimKeyHex`, tagged for the default Ootle chain.
function burnFeatures(claimKeyHex: string): string {
  return "01" + "02" + "00".repeat(8) + u32le(0) + "01" + "02" + u32le(32) + claimKeyHex + "00" + "00";
}

describe("LIVE: burn claim dry run (Ootle 0.42)", () => {
  it("the network accepts the claim in everything but L1 inclusion", async () => {
    configureOotleStorage(inMemoryAdapter());
    const secret = fromHex(fixture.accountSecretHex);
    const view = crypto.getRandomValues(new Uint8Array(32));
    view[31]! &= 0x0f; // a canonical scalar
    const signer = SecretKeyWallet.fromSecretKey(secret, Network.Esmeralda, view);
    const account = new (OotleAccount as unknown as new (...a: unknown[]) => OotleAccount)(0, Network.Esmeralda, signer, secret);

    const zero = "00".repeat(32);
    const mmr = { leaf_index: 0, mmr_size: 1, path: [], peaks: [] };
    const outputProof: BurnOutputProof = {
      block_hash: "01".repeat(32),
      block_height: 1,
      output: {
        version: 1,
        features: burnFeatures(fixture.stealthClaimPublicHex),
        commitment: fixture.commitmentHex,
        rangeproof_hash: "05".repeat(32),
        script: "0173", // consensus encoding of the script `Nop`: length 1, opcode 0x73
        sender_offset_public_key: fixture.senderOffsetPublicKeyHex,
        metadata_signature: { ephemeral_commitment: zero, ephemeral_pubkey: zero, u_a: zero, u_x: zero, u_y: zero },
        covenant: "00",
        encrypted_data: fixture.encryptedDataHex,
        minimum_value_promise: 0,
      },
      normal_output_proof: mmr,
      normal_output_mr: "06".repeat(32),
      block_output_proof: mmr,
    };
    const contents = assembleBurnClaimProof(
      {
        claimPublicKeyHex: fixture.accountPublicHex,
        commitmentHex: fixture.commitmentHex,
        ownershipNonceHex: fixture.ownershipNonceHex,
        ownershipSignatureHex: fixture.ownershipSignatureHex,
        senderOffsetPublicKeyHex: fixture.senderOffsetPublicKeyHex,
        encryptedDataHex: fixture.encryptedDataHex,
        amount: BigInt(fixture.amount),
      },
      outputProof
    );

    const fee = await account.estimateClaimBurnFee(contents);
    console.log("dry-run claim fee:", fee);
    expect(fee).toBeGreaterThan(0n);
    expect(fee).toBeLessThan(BigInt(fixture.amount));
  }, 120_000);
});
