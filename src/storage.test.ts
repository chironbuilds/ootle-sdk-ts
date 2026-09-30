import { beforeEach, describe, expect, it } from "vitest";
import { inMemoryAdapter } from "./adapters";
import {
  addPendingShield,
  addShieldedOutput,
  configureOotleStorage,
  getKnownVersions,
  getPrivatePaymentScanCursor,
  listPendingShields,
  listShieldedOutputs,
  markShieldedOutputSpent,
  removePendingShield,
  serialized,
  setKnownVersions,
  setPrivatePaymentScanCursor,
  wipeOotleState,
  getHtlcJournalEntry,
  listHtlcJournal,
  putHtlcJournalEntry,
  updateHtlcJournalEntry,
  reserveCommitments,
  releaseReservations,
  listReservedCommitments,
  CommitmentReservedError,
} from "./storage";
import type { HtlcJournalEntry } from "./storage";

function record(overrides: Partial<Parameters<typeof addShieldedOutput>[0]> = {}) {
  return {
    accountId: "local:0",
    resourceAddress: "resource_xtr",
    commitment: "aa".repeat(32),
    amount: "100",
    transactionId: "tx-1",
    createdAt: Date.now(),
    spent: false,
    ...overrides,
  };
}

describe("storage (KeyValueStore-backed)", () => {
  beforeEach(() => {
    configureOotleStorage(inMemoryAdapter());
  });

  it("round-trips shielded output records, scoped per account", async () => {
    await addShieldedOutput(record({ accountId: "local:0", commitment: "aa".repeat(32) }));
    await addShieldedOutput(record({ accountId: "local:1", commitment: "bb".repeat(32) }));

    expect(await listShieldedOutputs("local:0")).toHaveLength(1);
    expect(await listShieldedOutputs("local:1")).toHaveLength(1);
    expect((await listShieldedOutputs("local:0"))[0]?.commitment).toBe("aa".repeat(32));
  });

  it("marks exactly the matching account+commitment spent", async () => {
    await addShieldedOutput(record({ accountId: "local:0", commitment: "aa".repeat(32) }));
    await addShieldedOutput(record({ accountId: "local:0", commitment: "bb".repeat(32) }));

    await markShieldedOutputSpent("local:0", "aa".repeat(32));

    const records = await listShieldedOutputs("local:0");
    expect(records.find((r) => r.commitment === "aa".repeat(32))?.spent).toBe(true);
    expect(records.find((r) => r.commitment === "bb".repeat(32))?.spent).toBe(false);
  });

  it("dedupes a pending shield by transaction id", async () => {
    await addPendingShield({ transactionId: "tx-1", accountId: "local:0", resourceAddress: "resource_xtr", amount: "50" });
    await addPendingShield({ transactionId: "tx-1", accountId: "local:0", resourceAddress: "resource_xtr", amount: "999" });

    const pending = await listPendingShields();
    expect(pending).toHaveLength(1);
    expect(pending[0]?.amount).toBe("50");
  });

  it("removes a pending shield by transaction id", async () => {
    await addPendingShield({ transactionId: "tx-1", accountId: "local:0", resourceAddress: "resource_xtr", amount: "50" });
    await removePendingShield("tx-1");
    expect(await listPendingShields()).toHaveLength(0);
  });

  it("round-trips the private-payment scan cursor per account", async () => {
    expect(await getPrivatePaymentScanCursor("local:0")).toBeNull();
    await setPrivatePaymentScanCursor("local:0", "tx-42");
    expect(await getPrivatePaymentScanCursor("local:0")).toBe("tx-42");
  });

  it("round-trips known substate versions", async () => {
    expect(await getKnownVersions()).toEqual({});
    await setKnownVersions({ vault_abc: 3 });
    expect(await getKnownVersions()).toEqual({ vault_abc: 3 });
  });

  it("wipeOotleState() clears everything this module owns", async () => {
    await addShieldedOutput(record());
    await setKnownVersions({ vault_abc: 3 });

    await wipeOotleState();

    expect(await listShieldedOutputs("local:0")).toEqual([]);
    expect(await getKnownVersions()).toEqual({});
  });

  // Regression test for a real lost write: addShieldedOutput() didn't await its write(), so its
  // serialized() slot released before the record was stored. sendPrivately() with a private fee
  // records its change output and then the fee's change output back to back; against a real async
  // store (chrome.storage) the second add read the pre-first-add state and dropped the first record
  // -- confirmed live on esmeralda: a 208 TARI change output vanished from the private balance.
  it("keeps both records when two adds run back to back against a slow store", async () => {
    const inner = inMemoryAdapter();
    const slow = <T,>(v: T) => new Promise<T>((resolve) => setTimeout(() => resolve(v), 5));
    configureOotleStorage({
      get: async (key) => slow(await inner.get(key)),
      set: async (key, value) => { await slow(undefined); await inner.set(key, value); },
      remove: (key) => inner.remove(key),
    });

    await addShieldedOutput(record({ commitment: "aa".repeat(32), amount: "208000000" }));
    await addShieldedOutput(record({ commitment: "bb".repeat(32), amount: "4900000" }));

    expect((await listShieldedOutputs("local:0")).map((r) => r.commitment)).toEqual(["aa".repeat(32), "bb".repeat(32)]);
  });

  it("addShieldedOutput is idempotent per account+commitment (reconciliation can't double-count)", async () => {
    await addShieldedOutput(record({ commitment: "cc".repeat(32), amount: "10" }));
    await addShieldedOutput(record({ commitment: "cc".repeat(32), amount: "10" }));
    await addShieldedOutput(record({ accountId: "local:1", commitment: "cc".repeat(32), amount: "10" }));
    expect(await listShieldedOutputs("local:0")).toHaveLength(1);
    expect(await listShieldedOutputs("local:1")).toHaveLength(1);
  });

  describe("HTLC journal", () => {
    const entry = (over: Partial<HtlcJournalEntry> = {}): HtlcJournalEntry => ({
      id: "htlc-fund-1",
      accountId: "local:0",
      kind: "fund",
      status: "prepared",
      resourceAddress: "resource_xtr",
      amount: "100",
      conditions: [[], []],
      hashLockHex: "ab".repeat(32),
      refundEpoch: "50",
      outputMask: "cd".repeat(32),
      envelope: "sealed",
      createdAt: 1,
      updatedAt: 1,
      ...over,
    });

    it("persists an entry (with its refund data) and updates it in place", async () => {
      await putHtlcJournalEntry(entry());
      await putHtlcJournalEntry(entry()); // idempotent by id
      expect(await listHtlcJournal("local:0")).toHaveLength(1);
      const updated = await updateHtlcJournalEntry("htlc-fund-1", { status: "unknown", transactionId: "tx-9" });
      expect(updated?.status).toBe("unknown");
      expect(updated?.outputMask).toBe("cd".repeat(32)); // never lost by an update
      expect((await getHtlcJournalEntry("htlc-fund-1"))?.transactionId).toBe("tx-9");
      expect(await updateHtlcJournalEntry("nope", { status: "failed" })).toBeUndefined();
    });

    it("scopes entries per account", async () => {
      await putHtlcJournalEntry(entry({ id: "a" }));
      await putHtlcJournalEntry(entry({ id: "b", accountId: "local:1" }));
      expect((await listHtlcJournal("local:0")).map((e) => e.id)).toEqual(["a"]);
      expect(await listHtlcJournal()).toHaveLength(2);
    });
  });

  describe("commitment reservations", () => {
    const A = "aa".repeat(32), B = "bb".repeat(32), C = "cc".repeat(32);

    it("reserves all-or-nothing and blocks other holders", async () => {
      await reserveCommitments("local:0", [A, B], "op-1");
      await expect(reserveCommitments("local:0", [B, C], "op-2")).rejects.toBeInstanceOf(CommitmentReservedError);
      // op-2 got nothing (C was not reserved either)
      expect(await listReservedCommitments("local:0", "op-1")).toEqual(new Set());
      expect(await listReservedCommitments("local:0")).toEqual(new Set([A, B]));
      // the same holder may re-reserve (extends the lease)
      await reserveCommitments("local:0", [A], "op-1");
      // other accounts are unaffected
      await reserveCommitments("local:1", [A], "op-2");
    });

    it("release frees them, and an expired lease lapses on its own", async () => {
      await reserveCommitments("local:0", [A], "op-1");
      await releaseReservations("op-1");
      await reserveCommitments("local:0", [A], "op-2");
      await reserveCommitments("local:0", [B], "op-3", -1); // already expired
      expect(await listReservedCommitments("local:0")).toEqual(new Set([A]));
      await reserveCommitments("local:0", [B], "op-4");
    });
  });

  // Regression test for a real deadlock: wallet.ts's recordKnownVersions() used to wrap a call to
  // setKnownVersions() in its own serialized() block. Since setKnownVersions() already serializes
  // its own write against this same module-level queue, that nested call waited on a queue slot
  // that could only advance once it finished -- classic self-deadlock. Any caller doing the same
  // thing (queuing a callback that calls another serialized function) must not hang.
  it("does not deadlock when a serialized callback calls another serialized function", async () => {
    const resolved = await Promise.race([
      serialized(async () => {
        await setKnownVersions({ vault_a: 1 });
      }).then(() => "resolved"),
      new Promise((resolve) => setTimeout(() => resolve("timed out"), 500)),
    ]);
    expect(resolved).toBe("resolved");
    expect(await getKnownVersions()).toEqual({ vault_a: 1 });
  });
});
