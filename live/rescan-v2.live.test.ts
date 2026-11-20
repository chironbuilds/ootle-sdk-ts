// LIVE: the private-payment rescan must read schema-V2 transactions (Ootle 0.55).
//   npx vitest run --config live/vitest.live.config.ts live/rescan-v2
import { expect, it } from "vitest";
import { OotleAccount, configureOotleStorage } from "../src/index";
import { inMemoryAdapter } from "../src/adapters";

it("rescan over V2 transactions", async () => {
  const r = await fetch("https://esme-indexer-a.ootle.tari.com/transactions/recent?limit=50");
  const body = await r.text();
  const v2 = (body.match(/"V2"\s*:/g) ?? []).length;
  console.log(`recent page: ${(body.match(/"V1"\s*:/g) ?? []).length} V1, ${v2} V2`);
  configureOotleStorage(inMemoryAdapter());
  const a = OotleAccount.fromSeed(crypto.getRandomValues(new Uint8Array(16)), 0, "esmeralda");
  const res = await a.scanForPrivatePayments(20, 50);
  console.log("rescan OK", res.claimed);
  expect(res.claimed).toBe(0);
}, 300_000);
