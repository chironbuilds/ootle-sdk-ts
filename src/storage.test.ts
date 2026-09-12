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
  setKnownVersions,
  setPrivatePaymentScanCursor,
  wipeOotleState,
} from "./storage";

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
});
