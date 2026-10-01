// LIVE: a fresh private-payment scan (new device: empty ledger, no cursor) records only outputs of
// committed transactions -- an aborted send's outputs are not money.
//   LIVE_OUT=<dir> npx vitest run --config live/vitest.live.config.ts live/scan-committed-only
import { it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { OotleAccount, configureOotleStorage } from "../src/index";
import type { KeyValueStore } from "../src/index";

const OUT = process.env.LIVE_OUT ?? path.resolve("live-out");
const mem: Record<string, unknown> = {};
const memStore: KeyValueStore = {
  async get<T>(k: string) { return mem[k] as T | undefined; },
  async set<T>(k: string, v: T) { mem[k] = v; },
  async remove(k: string) { delete mem[k]; },
};
configureOotleStorage(memStore);
const seed = Uint8Array.from(Buffer.from(fs.readFileSync(path.join(OUT, "single.seed"), "utf8").trim(), "hex"));

it("fresh scan", async () => {
  const acct = OotleAccount.fromSeed(seed, 0, "esmeralda");
  const { found } = await acct.scanForPrivatePayments(4);
  const priv = await acct.getPrivateBalances();
  const provider = await acct.getProvider();
  const probes: unknown[] = [];
  for (const f of found) {
    const id = `utxo_${f.resourceAddress.replace(/^resource_/, "")}_${f.commitment}`;
    try {
      const sub = (await provider.getSubstate(id as never)) as unknown;
      probes.push([f.commitment.slice(0, 10), "OK", JSON.stringify(sub).slice(0, 160)]);
    } catch (e) {
      probes.push([f.commitment.slice(0, 10), "ERR", String(e).slice(0, 160)]);
    }
  }
  fs.writeFileSync(path.join(OUT, "scan-log.txt"), JSON.stringify({
    found: found.map((f) => [f.commitment.slice(0, 10), f.amount.toString(), f.transactionId.slice(0, 8)]),
    private: priv.map((p) => [p.amount.toString(), p.outputCount]),
    probes,
  }, null, 1));
}, 600_000);
