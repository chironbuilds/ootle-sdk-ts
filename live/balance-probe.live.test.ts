// Reads balances for an account whose local ledger holds the live claimed output (commitment only;
// getBalances counts recorded amounts, it does not decrypt them).
import { it } from "vitest";
import { OotleAccount, configureOotleStorage } from "../src/index";
import { inMemoryAdapter } from "../src/adapters";
import { addShieldedOutput } from "../src/storage";

it("balances with a claimed burn output", async () => {
  configureOotleStorage(inMemoryAdapter());
  const acct = OotleAccount.fromSeed(crypto.getRandomValues(new Uint8Array(16)), 0, "esmeralda");
  await addShieldedOutput({
    accountId: "local:0",
    resourceAddress: "resource_0101010101010101010101010101010101010101010101010101010101010101",
    commitment: "3eb2639791c89b458a707e0da00dc073dd8dda62d8e3196a6472a28ea741d732",
    amount: "999986757",
    transactionId: "f466044d58fa1dedf342e7b77611247b98b47a6628d6702caf98fc42a44e2666",
    createdAt: Date.now(),
    spent: false,
  });
  for (const [name, f] of [["getBalances", () => acct.getBalances()], ["getPrivateBalances", () => acct.getPrivateBalances()]] as const) {
    try { console.log(name, JSON.stringify(await f(), (_k, v) => (typeof v === "bigint" ? v.toString() : v))); }
    catch (e) { console.log(name, "THREW:", (e as Error).message); }
  }
}, 120_000);
