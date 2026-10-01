// LIVE: private sends from an account with no on-chain component, and recovery from a stale local
// record (a UTXO the local ledger still lists but that was spent elsewhere).
//   LIVE_OUT=<dir> RETURN_TO=otl_… npx vitest run --config live/vitest.live.config.ts live/stale-record-no-account
// Uses the `single` account from single-utxo-private-fee.live.test.ts (private funds only).
import { expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { TARI_RESOURCE_ADDRESS } from "@tari-project/ootle";
import { OotleAccount, configureOotleStorage } from "../src/index";
import type { KeyValueStore } from "../src/index";

const OUT = process.env.LIVE_OUT ?? path.resolve("live-out");
const STORE = path.join(OUT, "single-store.json");
const LOG = path.join(OUT, "stale-log.txt");
const log = (...a: unknown[]) =>
  fs.appendFileSync(LOG, a.map((x) => (typeof x === "string" ? x : JSON.stringify(x, (_, v) => (typeof v === "bigint" ? v.toString() : v)))).join(" ") + "\n");
const rd = () => (fs.existsSync(STORE) ? JSON.parse(fs.readFileSync(STORE, "utf8")) : {});
const fileStore: KeyValueStore = {
  async get<T>(k: string) { return rd()[k] as T | undefined; },
  async set<T>(k: string, v: T) { const a = rd(); a[k] = v; fs.writeFileSync(STORE, JSON.stringify(a, null, 1)); },
  async remove(k: string) { const a = rd(); delete a[k]; fs.writeFileSync(STORE, JSON.stringify(a, null, 1)); },
};
configureOotleStorage(fileStore);
const seed = Uint8Array.from(Buffer.from(fs.readFileSync(path.join(OUT, "single.seed"), "utf8").trim(), "hex"));

it("no component + stale record", async () => {
  const to = process.env.RETURN_TO!;
  const acct = OotleAccount.fromSeed(seed, 0, "esmeralda");
  const unspent = async () => (await acct.getPrivateBalances()).map((p) => [p.amount, p.outputCount]);
  log("start private", await unspent());

  // 1. snapshot the ledger, then send with the default (public) fee type from an account with no component
  const snapshot = fs.readFileSync(STORE, "utf8");
  const first = await acct.sendPrivately(TARI_RESOURCE_ADDRESS, to, 500_000n, 1_000_000n, "no-component send");
  log("send 1 (no component, transparent fee type)", first.transactionId);
  log("after send 1", await unspent());

  // 2. put the old ledger back: the UTXO send 1 spent now looks unspent -- a stale record
  fs.writeFileSync(STORE, snapshot);
  log("restored stale ledger", await unspent());
  const { found } = await acct.scanForPrivatePayments(5);
  log("scan rediscovered", found.map((f) => [f.commitment.slice(0, 10), f.amount]));
  log("with stale + rediscovered change", await unspent());

  // 3. send again: the stale record must be detected and marked spent, and the send go through
  const second = await acct.sendPrivately(TARI_RESOURCE_ADDRESS, to, 500_000n, 1_000_000n, "after stale record");
  log("send 2", second.transactionId);
  log("after send 2", await unspent());
  const pruned = await acct.pruneSpentShieldedOutputs();
  log("prune afterwards marked", pruned);
  expect(second.transactionId).toMatch(/^[0-9a-f]{64}$/);
}, 900_000);
