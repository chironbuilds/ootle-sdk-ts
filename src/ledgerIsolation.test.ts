import { Network } from "@tari-project/ootle";
import { beforeEach, describe, expect, it } from "vitest";
import { inMemoryAdapter } from "./adapters";
import {
  addPendingShield,
  addShieldedOutput,
  configureOotleStorage,
  getPrivatePaymentScanCursor,
  isMainnetLedgerId,
  ledgerAccountId,
  listPendingShields,
  listShieldedOutputs,
  setPrivatePaymentScanCursor,
} from "./storage";
import { OotleAccount, forgetKnownVersions, recoverPendingShields } from "./wallet";

const R = "resource_0101010101010101010101010101010101010101010101010101010101010101";
const seed = new Uint8Array(16).fill(9);

describe("one seed on two networks keeps two ledgers", () => {
  beforeEach(() => configureOotleStorage(inMemoryAdapter()));

  it("names mainnet ledgers apart and keeps testnet ids as they always were", () => {
    expect(ledgerAccountId(0, false)).toBe("local:0");
    expect(ledgerAccountId(3, true)).toBe("mainnet:local:3");
    expect(isMainnetLedgerId("mainnet:local:3")).toBe(true);
    expect(isMainnetLedgerId("local:3")).toBe(false);
    expect(OotleAccount.fromSeed(seed, 0, "esmeralda").ledgerId).toBe("local:0");
    expect(OotleAccount.fromSeed(seed, 0, "igor").ledgerId).toBe("local:0");
    expect(OotleAccount.fromSeed(seed, 0, "mainnet").ledgerId).toBe("mainnet:local:0");
  });

  it("follows an index the host re-points (imported seeds)", () => {
    const account = OotleAccount.fromSeed(seed, 0, "mainnet");
    (account as { index: number }).index = 7;
    expect(account.ledgerId).toBe("mainnet:local:7");
  });

  it("never shows one network's shielded outputs or scan cursor to the other", async () => {
    const main = OotleAccount.fromSeed(seed, 0, "mainnet");
    const esme = OotleAccount.fromSeed(seed, 0, "esmeralda");
    await addShieldedOutput({ accountId: esme.ledgerId, resourceAddress: R, commitment: "aa", amount: "5", transactionId: "t1", spent: false, createdAt: 1 });
    await addShieldedOutput({ accountId: main.ledgerId, resourceAddress: R, commitment: "bb", amount: "7", transactionId: "t2", spent: false, createdAt: 2 });
    await setPrivatePaymentScanCursor(esme.ledgerId, "esme-cursor");

    expect((await listShieldedOutputs(esme.ledgerId)).map((r) => r.commitment)).toEqual(["aa"]);
    expect((await listShieldedOutputs(main.ledgerId)).map((r) => r.commitment)).toEqual(["bb"]);
    expect(await getPrivatePaymentScanCursor(esme.ledgerId)).toBe("esme-cursor");
    expect(await getPrivatePaymentScanCursor(main.ledgerId)).toBeNull();
  });

  it("only reconciles the pending shields of the network it was given", async () => {
    await addPendingShield({ transactionId: "esme-tx", accountId: "local:0", resourceAddress: R, amount: "1" });
    await addPendingShield({ transactionId: "main-tx", accountId: "mainnet:local:0", resourceAddress: R, amount: "1" });
    const asked: string[] = [];
    // A provider that records which transactions it was asked about and reports each as rejected,
    // so a reconciled entry is removed and an untouched one stays.
    const provider = {
      getTransactionResult: async (transactionId: string) => {
        asked.push(transactionId);
        return { result: { Rejected: { reason: "test" } } };
      },
    } as never;
    await recoverPendingShields(provider, Network.MainNet);
    expect(asked).toEqual(["main-tx"]);
    expect((await listPendingShields()).map((p) => p.transactionId)).toEqual(["esme-tx"]);
  });

  it("forgets known versions per network", async () => {
    // Forgetting an id that was never stored is a no-op on either network and must not throw.
    await expect(forgetKnownVersions(["component_x"], Network.MainNet)).resolves.toBeUndefined();
    await expect(forgetKnownVersions(["component_x"])).resolves.toBeUndefined();
  });
});
