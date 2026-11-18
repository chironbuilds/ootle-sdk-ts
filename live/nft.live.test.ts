// NFTs on Esmeralda: mint from the builtin NFT faucet, read typed ids back from getBalances, send one,
// send several in one transaction, and (if PHONE is set) send three to that wallet address.
import { it } from "vitest";
import { amountLiteral } from "@tari-project/ootle";
import type { Instruction } from "@tari-project/ootle-ts-bindings";
import { OotleAccount, configureOotleStorage } from "../src/index";
import { inMemoryAdapter } from "../src/adapters";

const NFT_FAUCET = "component_ff00000000000000000000000000000000000000000000000000000000000000";
const NFT_RES = "resource_ff00000000000000000000000000000000000000000000000000000000000001";
const json = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** CBOR text string. */
function text(s: string): number[] {
  const b = [...new TextEncoder().encode(s)];
  return (b.length < 24 ? [0x60 | b.length] : [0x78, b.length]).concat(b);
}
/** The faucet's `mutable_data` (a tari_bor::Value): a small map the wallet shows as the NFT's details. */
function nftData(name: string): { Literal: string } {
  const bytes = [0xa2, ...text("name"), ...text(name), ...text("description"), ...text("Minted from the Esmeralda NFT faucet")];
  return { Literal: bytes.map((x) => x.toString(16).padStart(2, "0")).join("") };
}

it("NFTs: mint, read, send one, send many", async () => {
  configureOotleStorage(inMemoryAdapter());
  // SEED_A (32 hex chars) keeps account A fixed, so it can be funded once when the TARI faucet is dry.
  const seedA = process.env.SEED_A ? Uint8Array.from(process.env.SEED_A.match(/../g)!.map((h) => parseInt(h, 16))) : crypto.getRandomValues(new Uint8Array(16));
  const a = OotleAccount.fromSeed(seedA, 0, "esmeralda");
  if (process.env.ADDRESS_ONLY) {
    (await import("node:fs")).writeFileSync(process.env.ADDRESS_ONLY, await a.getWalletAddress());
    return;
  }
  const b = OotleAccount.fromSeed(crypto.getRandomValues(new Uint8Array(16)), 1, "esmeralda");
  const step = async <T>(name: string, f: () => Promise<T>): Promise<T> => {
    const t = Date.now();
    try {
      const r = await f();
      console.log(`OK   ${name} (${Date.now() - t}ms)`, json(r)?.slice(0, 500));
      return r;
    } catch (e) {
      console.log(`FAIL ${name}:`, (e as Error).message?.slice(0, 1500));
      throw e;
    }
  };
  const aComp = await a.getComponentAddress();
  const bAddr = await b.getWalletAddress();
  console.log("A", await a.getWalletAddress(), aComp);
  console.log("B", bAddr);

  if (!process.env.SEED_A) await step("faucet A", () => a.claimTestnetXtr());
  const mint = (n: bigint, name: string): Instruction[] => [
    { CallMethod: { call: { Address: NFT_FAUCET }, method: "mint", args: [amountLiteral(n), nftData(name)] } },
    { PutLastInstructionOutputOnWorkspace: { key: 0 } },
    { CallMethod: { call: { Address: aComp }, method: "deposit", args: [{ Workspace: { id: 0, offset: null } }] } },
  ] as Instruction[];
  const phone = process.env.PHONE;
  await step("mint NFTs to A", () => a.execute(mint(phone ? 6n : 3n, "Sapient Test NFT"), { maxFee: 20_000n }));
  await sleep(2000);

  const nftOf = async (acct: OotleAccount) => (await acct.getBalances()).find((x) => x.resourceAddress === NFT_RES);
  const held = await step("A's NFTs", () => nftOf(a));
  const ids = held?.nonFungibleIds ?? [];
  if (ids.length < 3) throw new Error(`expected at least 3 typed ids, got ${json(held)}`);

  await step(`send one (${ids[0]}) A->B`, () => a.sendNonFungibles(bAddr, NFT_RES, [ids[0]!]));
  await step(`send two (${ids[1]}, ${ids[2]}) A->B`, () => a.sendNonFungibles(bAddr, NFT_RES, [ids[1]!, ids[2]!]));
  await sleep(2000);
  const bHeld = await step("B's NFTs", () => nftOf(b));
  const got = new Set(bHeld?.nonFungibleIds ?? []);
  if (![ids[0], ids[1], ids[2]].every((i) => got.has(i!))) throw new Error(`B is missing NFTs: ${json(bHeld)}`);
  const aAfter = await step("A's NFTs after", () => nftOf(a));
  if (aAfter?.nonFungibleIds?.some((i) => got.has(i))) throw new Error("A still lists an NFT it sent");

  if (phone) {
    const rest = ids.slice(3, 6);
    await step(`send ${rest.join(", ")} A->phone`, () => a.sendNonFungibles(phone, NFT_RES, rest));
  }
}, 900_000);
