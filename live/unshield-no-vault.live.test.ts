// LIVE Esmeralda: the unshield path for an account with no public vault for the resource. TARI can't be
// made vault-less (the account needs it for fees), so this forces the same code path on TARI: the stealth
// inputs reveal into a bucket, `deposit` stores it, and the account key authorizes both it and the fee.
//   LIVE_OUT=<dir> npx vitest run --config live/vitest.live.config.ts live/unshield-no-vault.live.test.ts
import { expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { TARI_RESOURCE_ADDRESS } from "@tari-project/ootle";
import { OotleAccount, configureOotleStorage, listShieldedOutputs, localAccountId, toHex } from "../src/index";
import { inMemoryAdapter } from "../src/adapters";

const OUT = process.env.LIVE_OUT ?? path.resolve("live-out");
fs.mkdirSync(OUT, { recursive: true });
function seed(name: string): Uint8Array {
  const f = path.join(OUT, `${name}.seed`);
  if (!fs.existsSync(f)) fs.writeFileSync(f, toHex(crypto.getRandomValues(new Uint8Array(16))));
  return Uint8Array.from(Buffer.from(fs.readFileSync(f, "utf8").trim(), "hex"));
}
const UNIT = 1_000_000n;

it("unshields through a bucket + deposit, authorized by the account key", async () => {
  configureOotleStorage(inMemoryAdapter());
  const funder = OotleAccount.fromSeed(seed("funder"), 0, "esmeralda");
  const fresh = OotleAccount.fromSeed(crypto.getRandomValues(new Uint8Array(16)), 1, "esmeralda");
  const provider = await funder.getProvider();

  const pub = (await funder.getBalances()).find((b) => b.resourceAddress === TARI_RESOURCE_ADDRESS);
  if (!pub || pub.amount < 50n * UNIT) await funder.claimTestnetXtr();
  await funder.shield(TARI_RESOURCE_ADDRESS, 20n * UNIT);
  await funder.sendPrivately(TARI_RESOURCE_ADDRESS, await fresh.getWalletAddress(), 10n * UNIT);
  await fresh.scanForPrivatePayments();
  await fresh.unshield(TARI_RESOURCE_ADDRESS, 3n * UNIT); // creates the account and its public TARI vault

  const before = (await fresh.getBalances()).find((b) => b.resourceAddress === TARI_RESOURCE_ADDRESS)!;
  const record = (await listShieldedOutputs(localAccountId(1))).find((r) => !r.spent && BigInt(r.amount) >= 4n * UNIT)!;
  expect(record).toBeTruthy();
  const account = await fresh.getComponentAddress();
  const res = await (fresh as unknown as { unshieldWithoutVault: (...a: unknown[]) => Promise<{ transactionId: string }> }).unshieldWithoutVault(
    provider, account, TARI_RESOURCE_ADDRESS, 2n * UNIT, [record.commitment], BigInt(record.amount) - 2n * UNIT, 100_000n, undefined, { kind: "transparent" }, localAccountId(1)
  );
  console.log("no-vault unshield:", res.transactionId);
  const after = (await fresh.getBalances()).find((b) => b.resourceAddress === TARI_RESOURCE_ADDRESS)!;
  console.log("public before/after:", before.amount, after.amount);
  // +2 revealed, minus a fee of at most 0.1 TARI
  expect(after.amount > before.amount + 2n * UNIT - 100_000n).toBe(true);
  expect(after.amount < before.amount + 2n * UNIT + 1n).toBe(true);
}, 900_000);
