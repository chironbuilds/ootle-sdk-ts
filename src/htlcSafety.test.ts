import { describe, expect, it } from "vitest";
import { createStealthOutputWitness, generateKeypair, generateOotleAddress, generateStealthOutputsStatement } from "@tari-project/ootle-wasm";
import { htlcConditions } from "./htlc";
import {
  HtlcUnknownOutcomeError,
  conditionRootOf,
  decryptOwnStatementOutput,
  describeHtlcConditions,
  epochsUntilRefund,
  findScriptRoot,
  isDefinitiveRejection,
  isHtlcClaimableByEpoch,
  isHtlcRefundable,
  sha256Hex,
  statementInputCommitment,
  statementOutputCommitment,
  subtractScalars,
  verifyHtlcTerms,
} from "./htlcSafety";
import { buildHtlcSpendStatement } from "./wallet";
import { toHex } from "./vault";

const NETWORK = 0x26;
const RESOURCE = "resource_0101010101010101010101010101010101010101010101010101010101010101";

function findKey(node: unknown, key: string): string | null {
  if (node === null || typeof node !== "object") return null;
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    if (k === key && typeof v === "string") return v;
    const nested = findKey(v, key);
    if (nested) return nested;
  }
  return null;
}

async function fixture(refundEpoch = 100n) {
  const claimant = generateKeypair();
  const funder = generateKeypair();
  const preimage = new TextEncoder().encode("swap secret");
  const hashLockHex = await sha256Hex(preimage);
  const conditions = htlcConditions({
    hashLockHex,
    refundEpoch,
    claimantPublicKeyHex: toHex(claimant.public_key),
    refunderPublicKeyHex: toHex(funder.public_key),
  });
  return { claimant, funder, preimage, hashLockHex, conditions, refundEpoch };
}

describe("epoch rules match the engine's AfterEpoch/BeforeEpoch atoms", () => {
  it("refund is admissible AT the refund epoch (>=, not >)", () => {
    expect(isHtlcRefundable(99n, 100n)).toBe(false);
    expect(isHtlcRefundable(100n, 100n)).toBe(true);
    expect(isHtlcRefundable(101n, 100n)).toBe(true);
  });
  it("claim is admissible strictly BEFORE the refund epoch, so exactly one path is ever open", () => {
    for (const e of [98n, 99n, 100n, 101n]) {
      expect(isHtlcClaimableByEpoch(e, 100n)).toBe(!isHtlcRefundable(e, 100n));
    }
    expect(epochsUntilRefund(97n, 100n)).toBe(3n);
    expect(epochsUntilRefund(100n, 100n)).toBe(0n);
    expect(epochsUntilRefund(150n, 100n)).toBe(0n);
  });
});

describe("per-output HTLC mask from a two-output fund (real wasm crypto)", () => {
  it("aggregate − change mask = the HTLC output's own mask, and it reproduces the HTLC commitment in a refund", async () => {
    const f = await fixture();
    const claimantAddress = generateOotleAddress(f.claimant.public_key, f.claimant.public_key, NETWORK);
    const funderAddress = generateOotleAddress(f.funder.public_key, f.funder.public_key, NETWORK);
    const amount = 70_000n;
    const htlcWitness = createStealthOutputWitness(NETWORK, f.claimant.public_key, f.claimant.public_key, amount, RESOURCE, null, null, JSON.stringify({ Conditions: f.conditions }), 0n);
    const changeWitness = createStealthOutputWitness(NETWORK, f.funder.public_key, f.funder.public_key, 30_000n, RESOURCE, null, null, null, 0n);
    const result = generateStealthOutputsStatement(`[${htlcWitness},${changeWitness}]`, 0n);
    const aggregate = toHex(result.aggregated_output_mask);
    const htlcMask = findKey(JSON.parse(htlcWitness), "mask")!;
    const changeMask = findKey(JSON.parse(changeWitness), "mask")!;
    expect(htlcMask).toMatch(/^[0-9a-f]{64}$/);

    // The aggregate really is the sum of the per-output masks, in little-endian scalar encoding.
    expect(subtractScalars(aggregate, changeMask)).toBe(htlcMask.toLowerCase());

    // And the recovered mask spends the real HTLC commitment: a refund built from it names exactly
    // the committed output as its input. (A wrong mask produces a different commitment.)
    const statementJson = JSON.stringify(JSON.parse(result.statement_json));
    const htlcCommitment = (JSON.parse(result.statement_json) as { outputs: { output: { commitment: string } }[] }).outputs[0]!.output.commitment;
    const refund = buildHtlcSpendStatement({
      network: NETWORK, conditions: f.conditions, leaf: f.conditions[1]!, data: new Uint8Array(0),
      mask: subtractScalars(aggregate, changeMask), value: amount, destinationWalletAddress: funderAddress, resourceAddress: RESOURCE,
    });
    expect(statementInputCommitment(refund)).toBe(htlcCommitment.toLowerCase());
    const wrong = buildHtlcSpendStatement({
      network: NETWORK, conditions: f.conditions, leaf: f.conditions[1]!, data: new Uint8Array(0),
      mask: aggregate, value: amount, destinationWalletAddress: funderAddress, resourceAddress: RESOURCE,
    });
    expect(statementInputCommitment(wrong)).not.toBe(htlcCommitment.toLowerCase());
    expect(statementJson).toContain(htlcCommitment);
    expect(claimantAddress).toBeTruthy();
  });

  it("decryptOwnStatementOutput recovers our change output's mask from the statement itself (as htlcFund does)", async () => {
    const f = await fixture();
    const amount = 70_000n;
    const htlcWitness = createStealthOutputWitness(NETWORK, f.claimant.public_key, f.claimant.public_key, amount, RESOURCE, null, null, JSON.stringify({ Conditions: f.conditions }), 0n);
    const changeWitness = createStealthOutputWitness(NETWORK, f.funder.public_key, f.funder.public_key, 30_000n, RESOURCE, null, null, null, 0n);
    const result = generateStealthOutputsStatement(`[${htlcWitness},${changeWitness}]`, 0n);
    const outputs = (JSON.parse(result.statement_json) as { outputs: unknown[] }).outputs;
    // Our change (index 1) decrypts with our view secret…
    const change = decryptOwnStatementOutput(outputs[1], f.funder.secret_key);
    expect(change.value).toBe(30_000n);
    expect(change.maskHex).toBe(findKey(JSON.parse(changeWitness), "mask")!.toLowerCase());
    // …and yields the HTLC output's mask by subtraction, without ever decrypting the HTLC output.
    expect(subtractScalars(toHex(result.aggregated_output_mask), change.maskHex)).toBe(findKey(JSON.parse(htlcWitness), "mask")!.toLowerCase());
    // The HTLC output (addressed to the claimant) does NOT decrypt with the funder's key.
    expect(() => decryptOwnStatementOutput(outputs[0], f.funder.secret_key)).toThrow();
  });

  it("subtractScalars wraps modulo the group order", () => {
    const one = "01".padEnd(64, "0");
    const two = "02".padEnd(64, "0");
    expect(subtractScalars(two, one)).toBe(one);
    // 1 − 2 = ℓ − 1, which must round-trip: (ℓ − 1) − (ℓ − 1) = 0
    const minusOne = subtractScalars(one, two);
    expect(subtractScalars(minusOne, minusOne)).toBe("0".repeat(64));
  });
});

describe("condition roots", () => {
  it("conditionRootOf equals the root an HTLC output commits to on-chain (auth.Script)", async () => {
    const f = await fixture();
    const witness = JSON.parse(
      createStealthOutputWitness(NETWORK, f.claimant.public_key, f.claimant.public_key, 1n, RESOURCE, null, null, JSON.stringify({ Conditions: f.conditions }), 0n)
    );
    expect(conditionRootOf(f.conditions)).toBe(String(witness.auth.Script).toLowerCase());
    expect(findScriptRoot({ output: { auth: { Script: witness.auth.Script } } })).toBe(conditionRootOf(f.conditions));
    expect(findScriptRoot({ output: { auth: "StealthPublicKey" } })).toBeNull();
  });
  it("describeHtlcConditions reads back the hash lock and refund epoch", async () => {
    const f = await fixture(4242n);
    expect(describeHtlcConditions(f.conditions)).toEqual({ hashLockHex: f.hashLockHex, refundEpoch: 4242n });
  });
});

describe("verifyHtlcTerms (pre-claim checks)", () => {
  async function facts(over: Partial<Parameters<typeof verifyHtlcTerms>[0]> = {}) {
    const f = await fixture(100n);
    const base = {
      value: 5000n,
      onChainRoot: conditionRootOf(f.conditions),
      conditions: f.conditions,
      claimantPublicKeyHex: toHex(f.claimant.public_key),
      currentEpoch: 90n,
      preimageHashHex: f.hashLockHex,
    };
    return { f, facts: { ...base, ...over } };
  }

  it("passes a correct HTLC", async () => {
    const { f, facts: x } = await facts();
    expect(verifyHtlcTerms(x, { amount: 5000n, hashLockHex: f.hashLockHex, refundEpoch: 100n, refunderPublicKeyHex: toHex(f.funder.public_key), minEpochsBeforeRefund: 5n })).toEqual([]);
  });
  it("rejects a short amount", async () => {
    const { facts: x } = await facts({ value: 4999n });
    expect(verifyHtlcTerms(x, { amount: 5000n }).join(" ")).toMatch(/not the agreed 5000/);
    expect(verifyHtlcTerms(x, { minAmount: 5000n }).join(" ")).toMatch(/below the agreed minimum/);
  });
  it("rejects an output that isn't ours", async () => {
    const { facts: x } = await facts({ value: null });
    expect(verifyHtlcTerms(x).join(" ")).toMatch(/isn't addressed to you/);
  });
  it("rejects a tree whose claim leaf pays someone else", async () => {
    const { facts: x } = await facts({ claimantPublicKeyHex: toHex(generateKeypair().public_key) });
    expect(verifyHtlcTerms(x).join(" ")).toMatch(/not a standard HTLC paying you/);
  });
  it("rejects a refund leaf for an unexpected counterparty", async () => {
    const { facts: x } = await facts();
    expect(verifyHtlcTerms(x, { refunderPublicKeyHex: toHex(generateKeypair().public_key) }).join(" ")).toMatch(/not a standard HTLC/);
  });
  it("rejects when the on-chain output commits to a different tree, or isn't script-locked", async () => {
    const other = await fixture(100n);
    const { facts: x } = await facts({ onChainRoot: conditionRootOf(other.conditions) });
    expect(verifyHtlcTerms(x).join(" ")).toMatch(/different condition tree/);
    const { facts: y } = await facts({ onChainRoot: null });
    expect(verifyHtlcTerms(y).join(" ")).toMatch(/not script-locked/);
  });
  it("rejects a preimage that doesn't match the lock", async () => {
    const { facts: x } = await facts({ preimageHashHex: "00".repeat(32) });
    expect(verifyHtlcTerms(x).join(" ")).toMatch(/preimage does not hash/);
  });
  it("rejects a closed or too-short claim window", async () => {
    const { facts: closed } = await facts({ currentEpoch: 100n });
    expect(verifyHtlcTerms(closed).join(" ")).toMatch(/claim window has closed/);
    const { facts: tight } = await facts({ currentEpoch: 98n });
    expect(verifyHtlcTerms(tight, { minEpochsBeforeRefund: 5n }).join(" ")).toMatch(/Only 2 epoch\(s\) remain/);
  });
  it("rejects agreed-term mismatches on the hash lock and epoch", async () => {
    const { facts: x } = await facts();
    expect(verifyHtlcTerms(x, { hashLockHex: "11".repeat(32) }).join(" ")).toMatch(/hash lock is not the agreed one/);
    expect(verifyHtlcTerms(x, { refundEpoch: 101n }).join(" ")).toMatch(/refund epoch is 100, not the agreed 101/);
  });
});

describe("outcome classification", () => {
  it("only definitive rejections count as 'nothing happened'", () => {
    expect(isDefinitiveRejection(new Error("Transaction abc was rejected: InsufficientFeesPaid"))).toBe(true);
    expect(isDefinitiveRejection(new Error("Transaction abc accepted the fee but rejected the rest: {...}"))).toBe(true);
    expect(isDefinitiveRejection(new Error("Timed out after 60000ms while submitting the HTLC funding transaction."))).toBe(false);
    expect(isDefinitiveRejection(new Error("Failed to fetch"))).toBe(false);
  });
  it("HtlcUnknownOutcomeError carries the refund data", () => {
    const e = new HtlcUnknownOutcomeError("htlc-fund-1", { kind: "fund", conditions: [[], []], outputMask: "ab".repeat(32) }, new Error("Timed out"));
    expect(e.details.outputMask).toBe("ab".repeat(32));
    expect(e.message).toMatch(/reconcileHtlcs/);
  });
});

describe("statement helpers", () => {
  it("statementOutputCommitment reads a full statement's output commitment", async () => {
    const f = await fixture();
    const addr = generateOotleAddress(f.funder.public_key, f.funder.public_key, NETWORK);
    const stmt = buildHtlcSpendStatement({ network: NETWORK, conditions: f.conditions, leaf: f.conditions[1]!, data: new Uint8Array(0), mask: toHex(generateKeypair().secret_key), value: 10n, destinationWalletAddress: addr, resourceAddress: RESOURCE });
    expect(statementOutputCommitment(stmt)).toMatch(/^[0-9a-f]{64}$/);
  });
});
