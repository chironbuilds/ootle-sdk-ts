import { describe, expect, it } from "vitest";
import { Mask, type StealthCryptoProvider } from "@tari-project/ootle";
import type { Instruction, OutputBody, TransactionEntry } from "@tari-project/ootle-ts-bindings";
import { scanTransactionsForOwnedOutputs, sumConfidentialCommitments } from "./confidential";
import { toHex } from "./vault";

// This exercises OUR aggregation/error-handling logic (sumConfidentialCommitments), not the
// SDK's own WASM crypto -- the real decryptInputData is a thin wrapper around
// deriveAeadKey+unblindOutput, so a stub only needs to implement those two. Ownership/value are
// encoded directly into the fake `encrypted_data` bytes as test fixtures; this is not simulating
// real Pedersen/AEAD math, only the *contract* sumConfidentialCommitments depends on: decrypt
// succeeds and returns a value, or throws for an unowned commitment.
class FakeStealthCrypto implements StealthCryptoProvider {
  async generateOutputsStatement(): Promise<never> {
    throw new Error("not used by this test");
  }
  async buildInputsStatement(): Promise<never> {
    throw new Error("not used by this test");
  }
  async generateBalanceProofSignature(): Promise<never> {
    throw new Error("not used by this test");
  }
  async deriveAeadKey(privateKey: Uint8Array): Promise<Uint8Array> {
    return privateKey; // identity -- ownership is decided in unblindOutput below
  }
  async unblindOutput(_commitment: Uint8Array, encryptedData: Uint8Array, _aeadKey: Uint8Array) {
    const decoded = JSON.parse(new TextDecoder().decode(encryptedData)) as { owned: boolean; value: string };
    if (!decoded.owned) throw new Error("AEAD failure / commitment mismatch -- not owned");
    return { mask: Mask.zero(), value: BigInt(decoded.value) };
  }
  async aggregateInputMasks(): Promise<never> {
    throw new Error("not used by this test");
  }
  async stealthDhSecret(): Promise<never> {
    throw new Error("not used by this test");
  }
  async validateTransfer(): Promise<never> {
    throw new Error("not used by this test");
  }
}

function fakeOutputBody(owned: boolean, value: bigint): OutputBody {
  const payload = JSON.stringify({ owned, value: value.toString() });
  return {
    public_nonce: toHex(new Uint8Array(32)),
    encrypted_data: toHex(new TextEncoder().encode(payload)),
    minimum_value_promise: 0,
    viewable_balance: null,
  };
}

describe("sumConfidentialCommitments", () => {
  const crypto = new FakeStealthCrypto();
  const viewSecret = new Uint8Array(32).fill(1);

  it("returns zero for no commitments", async () => {
    const result = await sumConfidentialCommitments(crypto, viewSecret, {});
    expect(result).toEqual({ total: 0n, failedCount: 0 });
  });

  it("sums multiple owned commitments", async () => {
    const commitments = {
      aa: fakeOutputBody(true, 100n),
      bb: fakeOutputBody(true, 250n),
    };
    const result = await sumConfidentialCommitments(crypto, viewSecret, commitments);
    expect(result).toEqual({ total: 350n, failedCount: 0 });
  });

  it("isolates a failing (non-owned) commitment instead of losing the whole sum", async () => {
    const commitments = {
      aa: fakeOutputBody(true, 100n),
      bb: fakeOutputBody(false, 999n), // not ours -- unblindOutput throws
      cc: fakeOutputBody(true, 50n),
    };
    const result = await sumConfidentialCommitments(crypto, viewSecret, commitments);
    expect(result).toEqual({ total: 150n, failedCount: 1 });
  });

  it("counts every commitment failing, still returning a defined (zero) total rather than throwing", async () => {
    const commitments = {
      aa: fakeOutputBody(false, 1n),
      bb: fakeOutputBody(false, 2n),
    };
    const result = await sumConfidentialCommitments(crypto, viewSecret, commitments);
    expect(result).toEqual({ total: 0n, failedCount: 2 });
  });
});

function fakeStealthOutput(commitment: string, owned: boolean, value: bigint) {
  const body = fakeOutputBody(owned, value);
  return {
    output: { commitment, sender_public_nonce: body.public_nonce, encrypted_data: body.encrypted_data, minimum_value_promise: 0n, viewable_balance: null },
    auth: {},
    tag: "",
  };
}

function fakeStealthTransferInstruction(resourceAddress: string | null, outputs: ReturnType<typeof fakeStealthOutput>[]): Instruction {
  return {
    StealthTransfer: {
      resource_address_ref: resourceAddress === null ? { Workspace: { id: 0, offset: null } } : { Address: resourceAddress },
      statement: {
        inputs_statement: {} as never,
        outputs_statement: { outputs, revealed_output_amount: 0n, agg_range_proof: "" },
        balance_proof: null,
        covenant_claims: [],
      },
      revealed_input_bucket: null,
    },
  } as unknown as Instruction;
}

function fakeTransactionEntry(transactionId: string, instructions: Instruction[]): TransactionEntry {
  return {
    transaction_id: transactionId,
    transaction: {
      V1: {
        body: {
          transaction: {
            network: 0,
            fee_instructions: [],
            instructions,
            inputs: [],
            min_epoch: null,
            max_epoch: null,
            is_seal_signer_authorized: false,
            dry_run: false,
            blob_hashes: [],
            blob_sizes: [],
          },
          signatures: [],
        },
        seal_signature: {} as never,
      },
    },
    created_at: "",
    summary: null,
    rejected_reason: null,
  } as unknown as TransactionEntry;
}

describe("scanTransactionsForOwnedOutputs", () => {
  const crypto = new FakeStealthCrypto();
  const viewSecret = new Uint8Array(32).fill(1);
  const resourceAddress = "resource_test";

  it("finds an owned stealth output inside a StealthTransfer instruction", async () => {
    const entry = fakeTransactionEntry("tx1", [
      fakeStealthTransferInstruction(resourceAddress, [fakeStealthOutput("cc11", true, 500n)]),
    ]);
    const found = await scanTransactionsForOwnedOutputs(crypto, viewSecret, [entry], new Set());
    expect(found).toEqual([{ resourceAddress, commitment: "cc11", amount: 500n, transactionId: "tx1" }]);
  });

  it("skips outputs that don't belong to this account", async () => {
    const entry = fakeTransactionEntry("tx1", [
      fakeStealthTransferInstruction(resourceAddress, [fakeStealthOutput("cc11", false, 500n)]),
    ]);
    const found = await scanTransactionsForOwnedOutputs(crypto, viewSecret, [entry], new Set());
    expect(found).toEqual([]);
  });

  it("skips a commitment already in knownCommitments without re-decrypting it", async () => {
    const entry = fakeTransactionEntry("tx1", [
      fakeStealthTransferInstruction(resourceAddress, [fakeStealthOutput("cc11", true, 500n)]),
    ]);
    const found = await scanTransactionsForOwnedOutputs(crypto, viewSecret, [entry], new Set(["cc11"]));
    expect(found).toEqual([]);
  });

  it("skips a StealthTransfer whose resource address is a Workspace reference, not a literal Address", async () => {
    const entry = fakeTransactionEntry("tx1", [fakeStealthTransferInstruction(null, [fakeStealthOutput("cc11", true, 500n)])]);
    const found = await scanTransactionsForOwnedOutputs(crypto, viewSecret, [entry], new Set());
    expect(found).toEqual([]);
  });

  it("ignores non-StealthTransfer instructions, including bare string variants", async () => {
    const entry = fakeTransactionEntry("tx1", ["DropAllProofsInWorkspace" as Instruction]);
    const found = await scanTransactionsForOwnedOutputs(crypto, viewSecret, [entry], new Set());
    expect(found).toEqual([]);
  });

  it("scans multiple transactions and outputs, isolating one failure", async () => {
    const entries = [
      fakeTransactionEntry("tx1", [fakeStealthTransferInstruction(resourceAddress, [fakeStealthOutput("aa", true, 10n)])]),
      fakeTransactionEntry("tx2", [
        fakeStealthTransferInstruction(resourceAddress, [fakeStealthOutput("bb", false, 20n), fakeStealthOutput("cc", true, 30n)]),
      ]),
    ];
    const found = await scanTransactionsForOwnedOutputs(crypto, viewSecret, entries, new Set());
    expect(found).toEqual([
      { resourceAddress, commitment: "aa", amount: 10n, transactionId: "tx1" },
      { resourceAddress, commitment: "cc", amount: 30n, transactionId: "tx2" },
    ]);
  });
});
