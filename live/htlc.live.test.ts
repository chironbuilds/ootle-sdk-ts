// LIVE Esmeralda round trips for the HTLC swap-safety layer. Not part of the unit suite (see
// vitest.live.config.ts); run with:  npx vitest run --config live/vitest.live.config.ts
import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { parseOotleAddress } from "@tari-project/ootle-wasm";
import { TARI_RESOURCE_ADDRESS } from "@tari-project/ootle";
import { OotleAccount, configureOotleStorage, toHex, HtlcVerificationError } from "../src/index";
import type { KeyValueStore } from "../src/index";

const OUT = process.env.LIVE_OUT ?? path.resolve("live-out");
fs.mkdirSync(OUT, { recursive: true });
const STORE = path.join(OUT, "store.json");
const LOG = path.join(OUT, "log.txt");
const log = (...a: unknown[]) => {
  const line = `[${new Date().toISOString().slice(11, 19)}] ${a.map((x) => (typeof x === "string" ? x : JSON.stringify(x, (_, v) => (typeof v === "bigint" ? v.toString() : v)))).join(" ")}`;
  fs.appendFileSync(LOG, line + "\n");
  console.log(line);
};
const fileStore: KeyValueStore = {
  async get<T>(k: string) { const all = fs.existsSync(STORE) ? JSON.parse(fs.readFileSync(STORE, "utf8")) : {}; return all[k] as T | undefined; },
  async set<T>(k: string, v: T) { const all = fs.existsSync(STORE) ? JSON.parse(fs.readFileSync(STORE, "utf8")) : {}; all[k] = v; fs.writeFileSync(STORE, JSON.stringify(all, null, 1)); },
  async remove(k: string) { const all = fs.existsSync(STORE) ? JSON.parse(fs.readFileSync(STORE, "utf8")) : {}; delete all[k]; fs.writeFileSync(STORE, JSON.stringify(all, null, 1)); },
};
configureOotleStorage(fileStore);

// Seeds persist in OUT so a rerun reuses the same (already funded) test accounts.
function seed(name: string): Uint8Array {
  const f = path.join(OUT, `${name}.seed`);
  if (!fs.existsSync(f)) fs.writeFileSync(f, toHex(crypto.getRandomValues(new Uint8Array(16))));
  return Uint8Array.from(Buffer.from(fs.readFileSync(f, "utf8").trim(), "hex"));
}
const TARI = TARI_RESOURCE_ADDRESS;
const UNIT = 1_000_000n; // TARI divisibility 6
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function sha256(b: Uint8Array) { return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", b as BufferSource))); }

async function funded(acct: OotleAccount, label: string) {
  const bal = await acct.getBalances();
  const t = bal.find((b) => b.resourceAddress === TARI);
  if (!t || t.amount < 500n * UNIT) {
    log(label, "claiming testnet TARI…");
    await acct.claimTestnetXtr();
  }
  const after = (await acct.getBalances()).find((b) => b.resourceAddress === TARI);
  log(label, "public TARI:", after?.amount);
}

describe("LIVE: HTLC swap-safety on Esmeralda", () => {
  const funder = OotleAccount.fromSeed(seed("funder"), 0, "esmeralda");
  const claimant = OotleAccount.fromSeed(seed("claimant"), 0, "esmeralda");

  it("round trips", async () => {
    const provider = await funder.getProvider();
    const funderAddr = await funder.getWalletAddress();
    const claimantAddr = await claimant.getWalletAddress();
    const funderKey = toHex(parseOotleAddress(funderAddr).owner_key);
    log("funder", funderAddr.slice(0, 24), "claimant", claimantAddr.slice(0, 24));

    // ── setup: public TARI for both; the funder shields a main-lane coin and a fee-lane coin ──
    await funded(funder, "funder");
    await funded(claimant, "claimant");
    const privBefore = await funder.listUnspentShieldedOutputs(TARI);
    if (!privBefore.some((r) => BigInt(r.amount) >= 300n * UNIT)) {
      log("shielding 300 TARI (main lane)…"); await funder.shield(TARI, 300n * UNIT);
    }
    if (!(await funder.listUnspentShieldedOutputs(TARI)).some((r) => BigInt(r.amount) > 50_000n && BigInt(r.amount) < 100n * UNIT)) {
      log("shielding 5 TARI (fee lane)…"); await funder.shield(TARI, 5n * UNIT);
    }
    const priv = await funder.listUnspentShieldedOutputs(TARI);
    log("funder private outputs:", priv.map((r) => `${BigInt(r.amount) / UNIT} TARI ${r.commitment.slice(0, 8)}`));
    const mainCoin = priv.filter((r) => BigInt(r.amount) >= 300n * UNIT).sort((a, b) => (BigInt(a.amount) < BigInt(b.amount) ? -1 : 1))[0]!;

    // ── A: fund from an EXACT stealth coin, with change, private fee (two lanes) ──
    const epoch0 = BigInt(await provider.getCurrentEpoch());
    log("current epoch", epoch0);
    const preimage = crypto.getRandomValues(new Uint8Array(32));
    const preimageHex = toHex(preimage);
    const hashLock = await sha256(preimage);
    const amountA = 120n * UNIT;
    const t0 = Date.now();
    const fundA = await funder.htlcFund(TARI, amountA, claimantAddr, hashLock, epoch0 + 50n, 50_000n, { kind: "private", feeResourceAddress: TARI }, {
      source: { kind: "stealth", commitments: [mainCoin.commitment] },
    });
    log("A funded", { tx: fundA.transactionId, htlc: fundA.ownCommitment.slice(0, 12), change: fundA.changeCommitment?.slice(0, 12), secs: (Date.now() - t0) / 1000 });
    expect(fundA.changeCommitment).toBeTruthy();
    const afterA = await funder.listUnspentShieldedOutputs(TARI);
    const change = afterA.find((r) => r.commitment === fundA.changeCommitment);
    log("A change recorded:", change ? `${BigInt(change.amount) / UNIT} TARI` : "MISSING");
    expect(BigInt(change!.amount)).toBe(BigInt(mainCoin.amount) - amountA);
    expect(afterA.some((r) => r.commitment === mainCoin.commitment)).toBe(false); // main coin marked spent
    expect((await funder.listHtlcs()).find((e) => e.id === fundA.journalId)?.status).toBe("confirmed");

    // ── B: claimant's safety checks against the REAL on-chain HTLC ──
    const good = await claimant.verifyHtlc(TARI, fundA.ownCommitment, fundA.conditions, { amount: amountA, refunderPublicKeyHex: funderKey, minEpochsBeforeRefund: 3n }, preimageHex);
    log("B verify (correct terms):", good);
    expect(good.ok).toBe(true);
    const wrongAmt = await claimant.verifyHtlc(TARI, fundA.ownCommitment, fundA.conditions, { amount: amountA + 1n });
    log("B verify (wrong amount):", wrongAmt.problems);
    expect(wrongAmt.ok).toBe(false);
    const notMine = await funder.verifyHtlc(TARI, fundA.ownCommitment, fundA.conditions);
    log("B verify (as the funder, not the claimant):", notMine.problems);
    expect(notMine.ok).toBe(false);
    await expect(
      claimant.htlcClaim(TARI, fundA.ownCommitment, fundA.conditions, toHex(crypto.getRandomValues(new Uint8Array(32))))
    ).rejects.toBeInstanceOf(HtlcVerificationError);
    log("B wrong preimage refused locally (nothing submitted)");

    // ── C: claim (verify → dry run → CLAIM_ARMED → submit), claimed output recorded ──
    const t1 = Date.now();
    const claim = await claimant.htlcClaim(TARI, fundA.ownCommitment, fundA.conditions, preimageHex, 50_000n, { kind: "transparent" }, {
      expected: { amount: amountA, hashLockHex: hashLock, refunderPublicKeyHex: funderKey, minEpochsBeforeRefund: 3n },
    });
    log("C claimed", { tx: claim.transactionId, received: claim.receivedCommitment.slice(0, 12), amount: claim.amount, secs: (Date.now() - t1) / 1000 });
    const claimantPriv = await claimant.listUnspentShieldedOutputs(TARI);
    expect(claimantPriv.some((r) => r.commitment === claim.receivedCommitment && BigInt(r.amount) === amountA)).toBe(true);
    const gone = await claimant.verifyHtlc(TARI, fundA.ownCommitment, fundA.conditions);
    log("C HTLC after claim:", gone.problems);
    expect(gone.ok).toBe(false);
    // The received output is really ours and spendable: send 1 TARI of it back privately.
    const back = await claimant.sendPrivately(TARI, funderAddr, 1n * UNIT);
    log("C claimed funds spent onward (sendPrivately):", back.transactionId);

    // ── D: refund path — early refund refused, then refund from the journal once open ──
    const epochD = BigInt(await provider.getCurrentEpoch());
    const refundEpoch = epochD + 1n;
    const preimage2 = crypto.getRandomValues(new Uint8Array(32));
    const fundD = await funder.htlcFund(TARI, 10n * UNIT, claimantAddr, await sha256(preimage2), refundEpoch); // public source, public fee
    log("D funded (refund epoch", refundEpoch, ")", fundD.transactionId);
    await expect(funder.refundFromJournal(fundD.journalId)).rejects.toThrow(/refund path opens at epoch/);
    log("D early refund refused");
    let now = BigInt(await provider.getCurrentEpoch());
    const waitStart = Date.now();
    while (now < refundEpoch) {
      if (Date.now() - waitStart > 90 * 60_000) throw new Error("epoch did not advance within 90 min");
      await sleep(30_000);
      now = BigInt(await provider.getCurrentEpoch());
    }
    log("D epoch reached", now, "after", Math.round((Date.now() - waitStart) / 1000), "s");
    const closed = await claimant.verifyHtlc(TARI, fundD.ownCommitment, fundD.conditions);
    log("D claim window now:", closed.problems);
    expect(closed.problems.join(" ")).toMatch(/claim window has closed/);
    const refund = await funder.refundFromJournal(fundD.journalId);
    log("D refunded", { tx: refund.transactionId, received: refund.receivedCommitment.slice(0, 12), amount: refund.amount });
    expect((await funder.listUnspentShieldedOutputs(TARI)).some((r) => r.commitment === refund.receivedCommitment)).toBe(true);

    // ── E: nothing left open ──
    const open = (await funder.reconcileHtlcs()).concat(await claimant.reconcileHtlcs());
    log("E reconcile: open entries", open.map((e) => `${e.kind}:${e.status}`));
    expect(open.filter((e) => e.status !== "confirmed")).toEqual([]);
    log("ALL LIVE CHECKS PASSED");
  }, 3 * 60 * 60_000);
});
