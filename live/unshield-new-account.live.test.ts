// LIVE Esmeralda: unshield into an account whose component doesn't exist yet (the state a wallet is
// in after claiming an L1 burn). A funded account sends a private payment to a fresh account B; B,
// holding only that stealth output, unshields part of it, which must create its account.
//   LIVE_OUT=<dir> npx vitest run --config live/vitest.live.config.ts live/unshield-new-account.live.test.ts
import { expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { TARI_RESOURCE_ADDRESS } from "@tari-project/ootle";
import { OotleAccount, configureOotleStorage, substateExists, toHex } from "../src/index";
import { inMemoryAdapter } from "../src/adapters";

const OUT = process.env.LIVE_OUT ?? path.resolve("live-out");
fs.mkdirSync(OUT, { recursive: true });
function seed(name: string): Uint8Array {
  const f = path.join(OUT, `${name}.seed`);
  if (!fs.existsSync(f)) fs.writeFileSync(f, toHex(crypto.getRandomValues(new Uint8Array(16))));
  return Uint8Array.from(Buffer.from(fs.readFileSync(f, "utf8").trim(), "hex"));
}
const UNIT = 1_000_000n;

it("unshields into a new account", async () => {
  configureOotleStorage(inMemoryAdapter());
  const funder = OotleAccount.fromSeed(seed("funder"), 0, "esmeralda");
  const fresh = OotleAccount.fromSeed(crypto.getRandomValues(new Uint8Array(16)), 1, "esmeralda");
  const provider = await funder.getProvider();

  const pub = (await funder.getBalances()).find((b) => b.resourceAddress === TARI_RESOURCE_ADDRESS);
  if (!pub || pub.amount < 50n * UNIT) {
    console.log("claiming testnet TARI…");
    await funder.claimTestnetXtr();
  }
  console.log("funder public TARI:", (await funder.getBalances()).find((b) => b.resourceAddress === TARI_RESOURCE_ADDRESS)?.amount);

  // A private payment to the fresh account: a stealth output it can spend, and no component.
  await funder.shield(TARI_RESOURCE_ADDRESS, 20n * UNIT);
  const sent = await funder.sendPrivately(TARI_RESOURCE_ADDRESS, await fresh.getWalletAddress(), 10n * UNIT);
  console.log("private payment:", sent.transactionId);
  const found = await fresh.scanForPrivatePayments();
  console.log("fresh account found:", found);
  const freshAccount = await fresh.getComponentAddress();
  expect(await substateExists(provider, freshAccount)).toBe(false);

  const res = await fresh.unshield(TARI_RESOURCE_ADDRESS, 3n * UNIT);
  console.log("unshield into new account:", res.transactionId);
  expect(await substateExists(provider, freshAccount)).toBe(true);
  const bal = (await fresh.getBalances()).find((b) => b.resourceAddress === TARI_RESOURCE_ADDRESS);
  console.log("fresh balances:", bal);
  expect(bal?.amount).toBe(3n * UNIT);
  expect((bal?.confidentialAmount ?? 0n) > 6n * UNIT).toBe(true);

  // A second unshield now takes the ordinary path (account exists, fee from its public balance).
  const again = await fresh.unshield(TARI_RESOURCE_ADDRESS, 1n * UNIT);
  console.log("second unshield:", again.transactionId);
}, 600_000);
