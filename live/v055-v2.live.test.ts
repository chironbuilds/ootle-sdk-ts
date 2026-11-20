// Ootle 0.55 transaction schema V2 smoke test (Esmeralda). Exercises every signing path the V2
// migration touched -- account-key signing, hand-built one-time stealth-input signers, and the
// private-fee co-signer joining an AuthorizedTransfer's authorizer set -- then confirms each
// committed transaction is stored with the V2 tag. The first failure stops the test.
//   LIVE_OUT=<dir> [SKIP_FAUCET=1] npx vitest run --config live/vitest.live.config.ts live/v055-v2
// Account A's seed is kept in LIVE_OUT, so when the faucet is dry, fund A's printed address with
// ~12 tTARI (public) and re-run with SKIP_FAUCET=1.
import { expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { OotleAccount, configureOotleStorage } from "../src/index";
import { inMemoryAdapter } from "../src/adapters";

const TARI = "resource_0101010101010101010101010101010101010101010101010101010101010101";
const INDEXER = "https://esme-indexer-a.ootle.tari.com";
const json = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const OUT = process.env.LIVE_OUT ?? path.resolve("live-out");
fs.mkdirSync(OUT, { recursive: true });
function seed(name: string): Uint8Array {
  const f = path.join(OUT, `${name}.seed`);
  if (!fs.existsSync(f)) fs.writeFileSync(f, Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex"));
  return Uint8Array.from(Buffer.from(fs.readFileSync(f, "utf8").trim(), "hex"));
}

async function schemaOf(txId: string): Promise<string> {
  const r = await fetch(`${INDEXER}/transactions/${txId}`);
  const body = await r.text();
  const m = body.match(/"(V1|V2)"\s*:/);
  return m ? m[1]! : `unknown (${r.status}: ${body.slice(0, 200)})`;
}

it("0.55 V2 signing paths", async () => {
  configureOotleStorage(inMemoryAdapter());
  const a = OotleAccount.fromSeed(seed("v2-a"), 0, "esmeralda");
  const b = OotleAccount.fromSeed(crypto.getRandomValues(new Uint8Array(16)), 1, "esmeralda");
  const txIds: [string, string][] = [];
  const step = async <T>(name: string, f: () => Promise<T>): Promise<T> => {
    const t = Date.now();
    try {
      const r = await f();
      console.log(`OK   ${name} (${Date.now() - t}ms)`, json(r)?.slice(0, 300));
      const id = (r as { transactionId?: string } | undefined)?.transactionId;
      if (typeof id === "string") txIds.push([name, id]);
      return r;
    } catch (e) {
      console.log(`FAIL ${name}:`, (e as Error).message?.slice(0, 1500));
      throw e;
    }
  };
  const aAddr = await a.getWalletAddress();
  const bAddr = await b.getWalletAddress();
  const aAccount = await a.getComponentAddress();
  console.log("A", aAddr, aAccount);
  console.log("B", bAddr);

  // Account key (SecretKeyWallet) as the only authorizer.
  if (!process.env.SKIP_FAUCET) await step("faucet A", () => a.claimTestnetXtr());
  await step("balances A", () => a.getBalances());
  await step("send A->B 5 TARI (transparent fee)", () => a.send(bAddr, TARI, 5_000_000n));
  // Account key; creates the stealth outputs the later steps spend.
  await step("shield A 3 TARI", () => a.shield(TARI, 3_000_000n));
  await step("shield A 2 TARI", () => a.shield(TARI, 2_000_000n));
  await step("shield A 2 TARI", () => a.shield(TARI, 2_000_000n));
  await step("private balances A", () => a.getPrivateBalances());
  // Account key + fee UTXO's one-time key (execute's extraSigners).
  await step("send A->B 1 TARI (private fee)", () => a.send(bAddr, TARI, 1_000_000n, 5000n, { kind: "private", feeResourceAddress: TARI } as never));
  // One-time keys only (stealthInputSigner per input).
  await step("sendPrivately A->B 1 TARI", () => a.sendPrivately(TARI, bAddr, 1_000_000n));
  // One-time keys for inputs and the private fee.
  await step("sendPrivately A->B 0.5 TARI (private fee)", () =>
    a.sendPrivately(TARI, bAddr, 500_000n, 100_000n, "v2 private fee", 0n, { kind: "private", feeResourceAddress: TARI } as never),
  );
  await step("unshield A 0.5 TARI", () => a.unshield(TARI, 500_000n));
  // AuthorizedTransfer + addAuthorizer(fee key) in sealWithPrivateFee.
  const outputs = await step("list A unspent", () => a.listUnspentShieldedOutputs(TARI));
  const redeem = (outputs as { commitment: string; amount: string | bigint }[]).find((o) => BigInt(o.amount) >= 400_000n);
  if (redeem) {
    await step("redeemStealthOutputAndExecute (private fee)", () =>
      a.redeemStealthOutputAndExecute(
        TARI,
        redeem.commitment,
        200_000n,
        [{ CallMethod: { call: { Address: aAccount }, method: "deposit", args: [{ Workspace: { id: 0, offset: null } }] } } as never],
        [aAccount],
        100_000n,
        { kind: "private", feeResourceAddress: TARI } as never,
      ),
    );
  } else {
    console.log("SKIP redeemStealthOutputAndExecute: no output large enough");
  }
  await step("scan B", () => b.scanForOwnedUtxos(TARI, INDEXER));
  await step("private balances B", () => b.getPrivateBalances());

  await sleep(2000);
  for (const [name, id] of txIds) {
    const schema = await schemaOf(id);
    console.log(`SCHEMA ${schema}  ${name}  ${id}`);
    expect(schema).toBe("V2");
  }
}, 900_000);
