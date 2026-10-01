// LIVE: a private send with a private fee from an account holding a single private UTXO (and no
// account component). The fee has no separate UTXO to come from, so it comes out of the send.
//   LIVE_OUT=<dir> [RETURN_TO=otl_…] npx vitest run --config live/vitest.live.config.ts live/single-utxo-private-fee
// First run prints the account's address (fund it with ONE private payment); later runs scan for
// it and, with RETURN_TO set, send part of it back privately with a private fee.
import { expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { TARI_RESOURCE_ADDRESS } from "@tari-project/ootle";
import { OotleAccount, configureOotleStorage, toHex } from "../src/index";
import type { KeyValueStore } from "../src/index";

const OUT = process.env.LIVE_OUT ?? path.resolve("live-out");
fs.mkdirSync(OUT, { recursive: true });
const STORE = path.join(OUT, "single-store.json");
const LOG = path.join(OUT, "single-log.txt");
const log = (...a: unknown[]) =>
  fs.appendFileSync(LOG, a.map((x) => (typeof x === "string" ? x : JSON.stringify(x, (_, v) => (typeof v === "bigint" ? v.toString() : v)))).join(" ") + "\n");
const rd = () => (fs.existsSync(STORE) ? JSON.parse(fs.readFileSync(STORE, "utf8")) : {});
const fileStore: KeyValueStore = {
  async get<T>(k: string) { return rd()[k] as T | undefined; },
  async set<T>(k: string, v: T) { const a = rd(); a[k] = v; fs.writeFileSync(STORE, JSON.stringify(a, null, 1)); },
  async remove(k: string) { const a = rd(); delete a[k]; fs.writeFileSync(STORE, JSON.stringify(a, null, 1)); },
};
configureOotleStorage(fileStore);

function seed(name: string): Uint8Array {
  const f = path.join(OUT, `${name}.seed`);
  if (!fs.existsSync(f)) fs.writeFileSync(f, toHex(crypto.getRandomValues(new Uint8Array(16))));
  return Uint8Array.from(Buffer.from(fs.readFileSync(f, "utf8").trim(), "hex"));
}

it("single UTXO, private fee", async () => {
  const acct = OotleAccount.fromSeed(seed("single"), 0, "esmeralda");
  log("address", await acct.getWalletAddress());
  const { found } = await acct.scanForPrivatePayments(5);
  log("scan found", found.map((f) => [f.commitment.slice(0, 10), f.amount]));
  const priv = await acct.getPrivateBalances();
  log("private", priv.map((p) => [p.amount, p.outputCount]));
  const to = process.env.RETURN_TO;
  if (!to) return;
  const res = await acct.sendPrivately(TARI_RESOURCE_ADDRESS, to, 1_000_000n, 1_000_000n, "single-utxo private fee", 0n, {
    kind: "private",
    feeResourceAddress: TARI_RESOURCE_ADDRESS,
  });
  log("sent", res);
  const after = await acct.getPrivateBalances();
  log("private after", after.map((p) => [p.amount, p.outputCount]));
  expect(res.transactionId).toMatch(/^[0-9a-f]{64}$/);
}, 600_000);
