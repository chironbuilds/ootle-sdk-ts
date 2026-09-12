import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { IndexerGetTransactionResultResponse } from "@tari-project/ootle-ts-bindings";
import type { IndexerProvider } from "@tari-project/ootle-indexer";
import type { ShieldedOutputRecord } from "./storage";
import {
  assertValidMinimumValuePromise,
  extractMissingSubstateAddress,
  extractStaleLockVersion,
  pollTransactionResult,
  resolveInputsWithRetry,
  resolveSendPrivatelyPlan,
  resolveUnshieldPlan,
  selectShieldedUtxosForAmount,
  selectUnspentShieldedOutputs,
  substateExists,
  summarizePrivateHoldings,
  synthesizeShieldedOnlyBalances,
} from "./wallet";

function fakeRecord(overrides: Partial<ShieldedOutputRecord> = {}): ShieldedOutputRecord {
  return {
    accountId: "local:0",
    resourceAddress: "resource_xtr",
    commitment: "aa".repeat(32),
    amount: "100",
    transactionId: "tx-shield-1",
    createdAt: 0,
    spent: false,
    ...overrides,
  };
}

/** A fake `IndexerProvider` returning `responses` in order (repeating the last one once
 * exhausted) — only `getTransactionResult` is ever called by `pollTransactionResult`. */
function fakeProvider(responses: IndexerGetTransactionResultResponse[]): IndexerProvider {
  let i = 0;
  return {
    getTransactionResult: async () => {
      const r = responses[Math.min(i, responses.length - 1)];
      i++;
      return r;
    },
  } as unknown as IndexerProvider;
}

/** Builds a minimal-but-correctly-typed `Finalized` response wrapping the given finalize outcome
 * -- pollTransactionResult only ever reads `.execution_result.finalize.result`, but every other
 * field is still filled with a real, correctly-typed value rather than force-cast, so a future
 * change to what this function reads would still get a type-correct fixture to test against. */
function finalizedWith(result: unknown): IndexerGetTransactionResultResponse {
  return {
    result: {
      Finalized: {
        final_decision: "Commit",
        execution_result: {
          finalize: { result },
          execution_time: { secs: 0, nanos: 0 },
          execute_epoch: null,
          wasm_execution_points: 0n,
        },
        execution_time: { secs: 0, nanos: 0 },
        finalized_time: new Date().toISOString(),
        abort_details: null,
      },
    },
  } as unknown as IndexerGetTransactionResultResponse;
}

describe("extractMissingSubstateAddress", () => {
  it("matches a plain call-target miss (address before 'not found')", () => {
    expect(extractMissingSubstateAddress("At instruction #1: component_44066f512439abf4baa18bf5d357b190b631f1cc8be9bd4912ab97396ac7eb29 not found")).toBe(
      "component_44066f512439abf4baa18bf5d357b190b631f1cc8be9bd4912ab97396ac7eb29"
    );
  });

  it("matches a template-internal reference (address after 'not found:')", () => {
    expect(
      extractMissingSubstateAddress("Template referenced substate but it was not found: resource_e9b9309fad4f89800d0ddf12c7754edeeb4bafa5418013a4c70a51cce26af8e7")
    ).toBe("resource_e9b9309fad4f89800d0ddf12c7754edeeb4bafa5418013a4c70a51cce26af8e7");
  });

  it("matches a quoted cross-template-call miss", () => {
    expect(
      extractMissingSubstateAddress(
        "Cross-template call failed for method 'swap' on component 'component_f61cab40bca62ba3e98ff9b4d64d3dacb4d390bc41ff526d01e0ad94b148ba41': Substate 'component_f61cab40bca62ba3e98ff9b4d64d3dacb4d390bc41ff526d01e0ad94b148ba41' not found or is not a transaction input"
      )
    ).toBe("component_f61cab40bca62ba3e98ff9b4d64d3dacb4d390bc41ff526d01e0ad94b148ba41");
  });

  it("returns null for a message with no recognizable missing-substate pattern", () => {
    expect(extractMissingSubstateAddress("Some unrelated error message")).toBeNull();
  });

  it("returns null for an unrelated rejection reason", () => {
    expect(extractMissingSubstateAddress("InsufficientFeesPaid: not enough balance")).toBeNull();
  });
});

describe("extractStaleLockVersion", () => {
  it("extracts the substate id and version from a lock-failure message", () => {
    expect(extractStaleLockVersion("Lock failure: Substate vault_44032dd6cfe5c099cb3de86b9a2341271f23a7c670f472cee08475117f42c6aa:8 is DOWN")).toEqual({
      substateId: "vault_44032dd6cfe5c099cb3de86b9a2341271f23a7c670f472cee08475117f42c6aa",
      version: 8,
    });
  });

  it("returns null when the message doesn't match the lock-failure shape", () => {
    expect(extractStaleLockVersion("Some other error")).toBeNull();
  });

  it("returns null for a lock failure message missing the version number", () => {
    expect(extractStaleLockVersion("Substate vault_44032dd6cfe5c099cb3de86b9a2341271f23a7c670f472cee08475117f42c6aa is DOWN")).toBeNull();
  });
});

const NOT_YET_FINALIZED_SUBSTATE_ID = "component_3c00c9e1d63655005813adcfed1c06d5169ad0f4b09d77de60ae82cc9ea55d55";
const NOT_YET_FINALIZED = `Failed to find input "${NOT_YET_FINALIZED_SUBSTATE_ID}": HTTP 404: - {"error":"Substate ${NOT_YET_FINALIZED_SUBSTATE_ID} not found"}. Verify the substate id is correct (typo? wrong network?) or wait for the producing transaction to finalize.`;

/** Runs a `resolveInputsWithRetry`/`substateExists` call while advancing fake timers past every
 * backoff delay it schedules, so a test doesn't have to wait out the real 500ms/1000ms/... pauses.
 * Requires `vi.useFakeTimers()` to already be active. */
async function runWithFakeBackoff<T>(work: Promise<T>): Promise<T> {
  let settled = false;
  // `.then(onFulfilled, onRejected)`, not `.finally()`: `.finally()`'s returned promise inherits
  // the original rejection, and discarding it with `void` (rather than chaining a `.catch`) leaves
  // that rejection unhandled — `.then` here always resolves, either branch.
  work.then(
    () => (settled = true),
    () => (settled = true),
  );
  while (!settled) {
    await vi.advanceTimersByTimeAsync(1000);
  }
  return work;
}

describe("resolveInputsWithRetry", () => {
  const requirement = { substate_id: NOT_YET_FINALIZED_SUBSTATE_ID, version: null };

  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("retries a substate that hasn't finalized yet in the indexer and succeeds once it appears", async () => {
    let calls = 0;
    const provider = {
      resolveInputs: async (reqs: typeof requirement[]) => {
        calls++;
        if (calls < 3) throw new Error(NOT_YET_FINALIZED);
        return reqs.map((r) => ({ ...r, version: 0 }));
      },
    } as unknown as IndexerProvider;

    const result = await runWithFakeBackoff(resolveInputsWithRetry(provider, [requirement], 5, 500));
    expect(result).toEqual([{ ...requirement, version: 0 }]);
    expect(calls).toBe(3);
  });

  it("does not retry an error unrelated to a not-yet-finalized substate", async () => {
    const provider = {
      resolveInputs: async () => {
        throw new Error("InsufficientFeesPaid: not enough balance");
      },
    } as unknown as IndexerProvider;

    await expect(resolveInputsWithRetry(provider, [requirement], 5, 500)).rejects.toThrow("InsufficientFeesPaid");
  });

  it("gives up and throws once the retry budget is exhausted", async () => {
    let calls = 0;
    const provider = {
      resolveInputs: async () => {
        calls++;
        throw new Error(NOT_YET_FINALIZED);
      },
    } as unknown as IndexerProvider;

    await expect(runWithFakeBackoff(resolveInputsWithRetry(provider, [requirement], 2, 500))).rejects.toThrow("Failed to find input");
    expect(calls).toBe(3); // initial attempt + 2 retries
  });
});

describe("substateExists", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("returns true for a substate the indexer already has", async () => {
    const provider = {
      resolveInputs: async (reqs: { substate_id: string; version: number | null }[]) => reqs.map((r) => ({ ...r, version: 0 })),
    } as unknown as IndexerProvider;

    await expect(substateExists(provider, NOT_YET_FINALIZED_SUBSTATE_ID)).resolves.toBe(true);
  });

  it("returns false for a substate that never existed, rather than throwing", async () => {
    const provider = {
      resolveInputs: async () => {
        throw new Error(NOT_YET_FINALIZED);
      },
    } as unknown as IndexerProvider;

    await expect(runWithFakeBackoff(substateExists(provider, NOT_YET_FINALIZED_SUBSTATE_ID))).resolves.toBe(false);
  });

  it("propagates an unrelated failure instead of reading it as nonexistence", async () => {
    const provider = {
      resolveInputs: async () => {
        throw new Error("Timed out after 15000ms while resolving inputs.");
      },
    } as unknown as IndexerProvider;

    await expect(substateExists(provider, NOT_YET_FINALIZED_SUBSTATE_ID)).rejects.toThrow("Timed out");
  });
});

describe("pollTransactionResult", () => {
  it("returns the response immediately on a successful Finalized/Accept result", async () => {
    const response = finalizedWith({ Accept: { up_substates: [], down_substates: [] } });
    const result = await pollTransactionResult(fakeProvider([response]), "tx1");
    expect(result).toBe(response);
  });

  it("throws on a Rejected result", async () => {
    const response: IndexerGetTransactionResultResponse = { result: { Rejected: { details: "bad juju", rejected_time: "" } } };
    await expect(pollTransactionResult(fakeProvider([response]), "tx1")).rejects.toThrow("was rejected: bad juju");
  });

  it("throws on a Finalized/Reject outcome", async () => {
    const response = finalizedWith({ Reject: "some reason" });
    await expect(pollTransactionResult(fakeProvider([response]), "tx1")).rejects.toThrow("was rejected");
  });

  it("throws on a Finalized/AcceptFeeRejectRest outcome", async () => {
    const response = finalizedWith({ AcceptFeeRejectRest: [{ up_substates: [] }, "rest rejected"] });
    await expect(pollTransactionResult(fakeProvider([response]), "tx1")).rejects.toThrow("accepted the fee but rejected the rest");
  });

  it("keeps polling through Pending responses until finalized", async () => {
    const finalized = finalizedWith({ Accept: { up_substates: [], down_substates: [] } });
    const provider = fakeProvider([{ result: "Pending" }, finalized]);
    const result = await pollTransactionResult(provider, "tx1", 60_000);
    expect(result).toBe(finalized);
  });

  it("times out if the transaction stays Pending past timeoutMs", async () => {
    const provider = fakeProvider([{ result: "Pending" }]);
    await expect(pollTransactionResult(provider, "tx1", 10)).rejects.toThrow("Timed out waiting for transaction tx1 to finalize.");
  });
});

describe("selectShieldedUtxosForAmount", () => {
  it("picks a single largest-first record when it alone covers the target", () => {
    const small = fakeRecord({ commitment: "aa".repeat(32), amount: "30" });
    const big = fakeRecord({ commitment: "bb".repeat(32), amount: "100" });
    const { selected, total, unselected } = selectShieldedUtxosForAmount([small, big], "resource_xtr", 40n);
    expect(selected.map((r) => r.commitment)).toEqual([big.commitment]);
    expect(total).toBe(100n);
    expect(unselected.map((r) => r.commitment)).toEqual([small.commitment]);
  });

  it("combines multiple records when no single one covers the target", () => {
    const a = fakeRecord({ commitment: "aa".repeat(32), amount: "60" });
    const b = fakeRecord({ commitment: "bb".repeat(32), amount: "50" });
    const c = fakeRecord({ commitment: "cc".repeat(32), amount: "10" });
    const { selected, total, unselected } = selectShieldedUtxosForAmount([c, a, b], "resource_xtr", 100n);
    // Largest-first: a (60) then b (50) covers 100 with only 2 inputs, c left unselected.
    expect(selected.map((r) => r.commitment)).toEqual([a.commitment, b.commitment]);
    expect(total).toBe(110n);
    expect(unselected.map((r) => r.commitment)).toEqual([c.commitment]);
  });

  it("ignores records for a different resource or already spent", () => {
    const wrongResource = fakeRecord({ amount: "100", resourceAddress: "resource_other" });
    const spent = fakeRecord({ amount: "100", spent: true });
    const { selected, total } = selectShieldedUtxosForAmount([wrongResource, spent], "resource_xtr", 10n);
    expect(selected).toEqual([]);
    expect(total).toBe(0n);
  });

  it("selects everything available when the target exceeds the total balance", () => {
    const record = fakeRecord({ amount: "100" });
    const { selected, total } = selectShieldedUtxosForAmount([record], "resource_xtr", 500n);
    expect(selected).toEqual([record]);
    expect(total).toBe(100n);
  });
});

describe("resolveUnshieldPlan", () => {
  it("computes the private remainder for a valid partial reveal from a single record", () => {
    const record = fakeRecord({ amount: "100" });
    const { commitments, remainder } = resolveUnshieldPlan([record], record.resourceAddress, 40n);
    expect(commitments).toEqual([record.commitment]);
    expect(remainder).toBe(60n);
  });

  it("spends multiple records in one plan when needed to cover the amount", () => {
    const a = fakeRecord({ commitment: "aa".repeat(32), amount: "60" });
    const b = fakeRecord({ commitment: "bb".repeat(32), amount: "50" });
    const { commitments, remainder } = resolveUnshieldPlan([a, b], a.resourceAddress, 100n);
    expect(commitments).toEqual([a.commitment, b.commitment]);
    expect(remainder).toBe(10n);
  });

  it("throws when the resource has no unspent balance at all", () => {
    const record = fakeRecord({ spent: true });
    expect(() => resolveUnshieldPlan([record], record.resourceAddress, 40n)).toThrow("Amount exceeds your private balance");
    expect(() => resolveUnshieldPlan([record], "resource_other", 40n)).toThrow("Amount exceeds your private balance");
  });

  it("throws for a zero or negative reveal amount", () => {
    const record = fakeRecord({ amount: "100" });
    expect(() => resolveUnshieldPlan([record], record.resourceAddress, 0n)).toThrow("The amount to reveal must be greater than zero.");
    expect(() => resolveUnshieldPlan([record], record.resourceAddress, -5n)).toThrow("The amount to reveal must be greater than zero.");
  });

  it("pulls in one more record when the minimal selection would leave zero remainder", () => {
    const a = fakeRecord({ commitment: "aa".repeat(32), amount: "60" });
    const b = fakeRecord({ commitment: "bb".repeat(32), amount: "60" });
    const { commitments, remainder } = resolveUnshieldPlan([a, b], a.resourceAddress, 60n);
    expect(commitments).toEqual([a.commitment, b.commitment]);
    expect(remainder).toBe(60n);
  });

  it("throws when revealing the full balance in one transaction with nothing left to add as remainder", () => {
    const record = fakeRecord({ amount: "100" });
    expect(() => resolveUnshieldPlan([record], record.resourceAddress, 100n)).toThrow(
      "Can't unshield your full private balance in one transaction"
    );
  });

  it("throws when the reveal amount exceeds the total private balance", () => {
    const record = fakeRecord({ amount: "100" });
    expect(() => resolveUnshieldPlan([record], record.resourceAddress, 150n)).toThrow("Amount exceeds your private balance");
  });

  it("allows revealing all but the smallest unit", () => {
    const record = fakeRecord({ amount: "100" });
    const { remainder } = resolveUnshieldPlan([record], record.resourceAddress, 99n);
    expect(remainder).toBe(1n);
  });
});

describe("resolveSendPrivatelyPlan", () => {
  it("computes zero change when sending the full balance", () => {
    const record = fakeRecord({ amount: "100" });
    const { commitments, changeAmount } = resolveSendPrivatelyPlan([record], record.resourceAddress, 100n);
    expect(commitments).toEqual([record.commitment]);
    expect(changeAmount).toBe(0n);
  });

  it("computes the private change for a partial send", () => {
    const record = fakeRecord({ amount: "100" });
    const { changeAmount } = resolveSendPrivatelyPlan([record], record.resourceAddress, 40n);
    expect(changeAmount).toBe(60n);
  });

  it("spends multiple records in one plan when needed to cover the amount", () => {
    const a = fakeRecord({ commitment: "aa".repeat(32), amount: "60" });
    const b = fakeRecord({ commitment: "bb".repeat(32), amount: "50" });
    const { commitments, changeAmount } = resolveSendPrivatelyPlan([a, b], a.resourceAddress, 100n);
    expect(commitments).toEqual([a.commitment, b.commitment]);
    expect(changeAmount).toBe(10n);
  });

  it("throws when the resource has no unspent balance at all", () => {
    const record = fakeRecord({ spent: true });
    expect(() => resolveSendPrivatelyPlan([record], record.resourceAddress, 40n)).toThrow("Amount exceeds your private balance");
    expect(() => resolveSendPrivatelyPlan([record], "resource_other", 40n)).toThrow("Amount exceeds your private balance");
  });

  it("throws for a zero or negative send amount", () => {
    const record = fakeRecord({ amount: "100" });
    expect(() => resolveSendPrivatelyPlan([record], record.resourceAddress, 0n)).toThrow("The amount to send must be greater than zero.");
    expect(() => resolveSendPrivatelyPlan([record], record.resourceAddress, -5n)).toThrow("The amount to send must be greater than zero.");
  });

  it("throws when the send amount exceeds the total private balance", () => {
    const record = fakeRecord({ amount: "100" });
    expect(() => resolveSendPrivatelyPlan([record], record.resourceAddress, 101n)).toThrow("Amount exceeds your private balance");
  });
});

describe("synthesizeShieldedOnlyBalances", () => {
  it("synthesizes a Stealth-kind balance for a resource with no vault at all", () => {
    const shieldedByResource = new Map([["resource_ghost", 250n]]);
    const [entry, ...rest] = synthesizeShieldedOnlyBalances(
      new Set(), // no vault-derived resources
      shieldedByResource,
      new Map([["resource_ghost", 6]]),
      new Map([["resource_ghost", "GHOST"]]),
      new Map([["resource_ghost", "Ghost Token"]])
    );
    expect(rest).toHaveLength(0);
    expect(entry).toEqual({
      resourceAddress: "resource_ghost",
      kind: "Stealth",
      amount: 0n,
      confidentialAmount: 250n,
      confidentialDecryptFailures: 0,
      divisibility: 6,
      symbol: "GHOST",
      name: "Ghost Token",
      nonFungibleTokenIds: null,
    });
  });

  it("skips a resource that already has a vault-derived entry", () => {
    const shieldedByResource = new Map([["resource_xtr", 100n]]);
    const result = synthesizeShieldedOnlyBalances(
      new Set(["resource_xtr"]), // already covered by a real vault
      shieldedByResource,
      new Map(),
      new Map(),
      new Map()
    );
    expect(result).toHaveLength(0);
  });

  it("falls back to divisibility 0 and null symbol/name when metadata lookup has nothing", () => {
    const shieldedByResource = new Map([["resource_unknown", 5n]]);
    const result = synthesizeShieldedOnlyBalances(new Set(), shieldedByResource, new Map(), new Map(), new Map());
    expect(result).toHaveLength(1);
    expect(result[0]?.divisibility).toBe(0);
    expect(result[0]?.symbol).toBeNull();
    expect(result[0]?.name).toBeNull();
  });

  it("returns nothing when there are no shielded-only resources", () => {
    expect(synthesizeShieldedOnlyBalances(new Set(), new Map(), new Map(), new Map(), new Map())).toHaveLength(0);
  });
});

describe("selectUnspentShieldedOutputs", () => {
  it("drops spent outputs", () => {
    // The whole point of the dApp-facing private balance: a spent output is gone, and must not be
    // counted or listed just because its record is still on file (records are kept, marked spent,
    // not deleted).
    const records = [
      fakeRecord({ commitment: "a", amount: "10" }),
      fakeRecord({ commitment: "b", amount: "20", spent: true }),
      fakeRecord({ commitment: "c", amount: "30" }),
    ];
    expect(selectUnspentShieldedOutputs(records).map((r) => r.commitment)).toEqual(["a", "c"]);
  });

  it("filters to one resource when asked", () => {
    const records = [
      fakeRecord({ commitment: "a", resourceAddress: "resource_xtr" }),
      fakeRecord({ commitment: "b", resourceAddress: "resource_demo" }),
    ];
    expect(selectUnspentShieldedOutputs(records, "resource_demo").map((r) => r.commitment)).toEqual(["b"]);
  });

  it("orders newest first", () => {
    const records = [
      fakeRecord({ commitment: "old", createdAt: 100 }),
      fakeRecord({ commitment: "new", createdAt: 300 }),
      fakeRecord({ commitment: "mid", createdAt: 200 }),
    ];
    expect(selectUnspentShieldedOutputs(records).map((r) => r.commitment)).toEqual(["new", "mid", "old"]);
  });

  it("returns an empty list rather than throwing on no records", () => {
    expect(selectUnspentShieldedOutputs([])).toEqual([]);
  });
});

describe("summarizePrivateHoldings", () => {
  it("sums per resource and counts the outputs behind each total", () => {
    const holdings = summarizePrivateHoldings([
      fakeRecord({ commitment: "a", resourceAddress: "resource_xtr", amount: "100" }),
      fakeRecord({ commitment: "b", resourceAddress: "resource_demo", amount: "7" }),
      fakeRecord({ commitment: "c", resourceAddress: "resource_xtr", amount: "250" }),
    ]);
    expect(holdings).toEqual([
      { resourceAddress: "resource_xtr", amount: 350n, outputCount: 2 },
      { resourceAddress: "resource_demo", amount: 7n, outputCount: 1 },
    ]);
  });

  it("keeps amounts as BigInt through values past Number.MAX_SAFE_INTEGER", () => {
    // Raw resource-native units are u64 on-chain; summing these through a JS number would silently
    // round, reporting a private balance that is quietly wrong at the low digits.
    const big = "9007199254740993"; // 2^53 + 1
    const holdings = summarizePrivateHoldings([
      fakeRecord({ commitment: "a", amount: big }),
      fakeRecord({ commitment: "b", amount: big }),
    ]);
    expect(holdings[0]!.amount).toBe(BigInt(big) * 2n);
  });

  it("returns nothing for no records", () => {
    expect(summarizePrivateHoldings([])).toEqual([]);
  });
});

describe("assertValidMinimumValuePromise", () => {
  it("allows no promise at all", () => {
    // The ordinary case: shielding without publishing anything about the amount.
    expect(() => assertValidMinimumValuePromise(0n, 100n)).not.toThrow();
  });

  it("allows a promise below the amount", () => {
    // Proving "at least 60" out of an output actually worth 100 is the whole point — the promise is
    // a floor, not a disclosure of the real value.
    expect(() => assertValidMinimumValuePromise(60n, 100n)).not.toThrow();
  });

  it("allows a promise exactly equal to the amount", () => {
    // The boundary matters: shielding exactly N and promising exactly N is the most natural way to
    // build a proof of funds, and an off-by-one here would reject it.
    expect(() => assertValidMinimumValuePromise(100n, 100n)).not.toThrow();
  });

  it("rejects a promise above the amount", () => {
    // The range proof asserting `m <= v` cannot be generated when m > v. Caught here, with an
    // explanation, rather than as an opaque wasm failure after the fee half of the transaction has
    // already been committed on-chain.
    expect(() => assertValidMinimumValuePromise(101n, 100n)).toThrow(/cannot exceed/);
  });

  it("rejects a negative promise", () => {
    expect(() => assertValidMinimumValuePromise(-1n, 100n)).toThrow(/negative/);
  });

  it("holds past Number.MAX_SAFE_INTEGER", () => {
    // Amounts are u64 on-chain. A comparison that went through a JS number would round both sides
    // and wave through a promise that exceeds the amount by a few units — precisely the case that
    // produces an unprovable output.
    const amount = 9007199254740993n; // 2^53 + 1
    expect(() => assertValidMinimumValuePromise(amount, amount)).not.toThrow();
    expect(() => assertValidMinimumValuePromise(amount + 1n, amount)).toThrow(/cannot exceed/);
  });
});
