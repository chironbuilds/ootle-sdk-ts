import { Network } from "@tari-project/ootle";
import { parseOotleAddress } from "@tari-project/ootle-wasm";
import { afterEach, describe, expect, it } from "vitest";
import { NETWORK_NAMES, indexerUrlFor, isNetworkName, isTestnet, networkNameFromByte, setIndexerUrl, toOotleNetwork } from "./ootleNetwork";
import { OotleAccount } from "./wallet";

describe("network names", () => {
  it("maps every name to its byte and back", () => {
    expect(toOotleNetwork("mainnet")).toBe(Network.MainNet);
    expect(toOotleNetwork("esmeralda")).toBe(Network.Esmeralda);
    expect(toOotleNetwork("igor")).toBe(Network.Igor);
    for (const name of NETWORK_NAMES) expect(networkNameFromByte(toOotleNetwork(name))).toBe(name);
    expect(networkNameFromByte(Network.LocalNet)).toBeUndefined();
  });

  it("knows which networks are testnets and refuses unknown names", () => {
    expect(isTestnet("mainnet")).toBe(false);
    expect(isTestnet("esmeralda")).toBe(true);
    expect(isNetworkName("mainnet")).toBe(true);
    expect(isNetworkName("MainNet")).toBe(false);
    expect(isNetworkName(undefined)).toBe(false);
    expect(() => toOotleNetwork("localnet" as never)).toThrow(/Unknown network/);
  });
});

describe("indexer URLs", () => {
  afterEach(() => {
    setIndexerUrl(Network.MainNet, null);
    setIndexerUrl(Network.Igor, null);
  });

  it("uses tari-ootle's mainnet default and keeps the existing Esmeralda one", () => {
    expect(indexerUrlFor(Network.MainNet)).toBe("https://indexer-a.ootle.tari.com");
    expect(indexerUrlFor(Network.Esmeralda)).toBe("https://ootle-indexer-a.tari.com");
  });

  it("throws for a network with no indexer until one is set, and honours overrides", () => {
    expect(() => indexerUrlFor(Network.Igor)).toThrow(/setIndexerUrl/);
    setIndexerUrl(Network.Igor, "https://my-indexer.example/");
    expect(indexerUrlFor(Network.Igor)).toBe("https://my-indexer.example");
    setIndexerUrl(Network.MainNet, "https://indexer-b.ootle.tari.com");
    expect(indexerUrlFor(Network.MainNet)).toBe("https://indexer-b.ootle.tari.com");
    setIndexerUrl(Network.MainNet, null);
    expect(indexerUrlFor(Network.MainNet)).toBe("https://indexer-a.ootle.tari.com");
  });

  it("refuses a URL that isn't http(s)", () => {
    expect(() => setIndexerUrl(Network.MainNet, "not a url")).toThrow(/valid/);
    expect(() => setIndexerUrl(Network.MainNet, "javascript:alert(1)")).toThrow(/http/);
  });
});

describe("mainnet accounts", () => {
  it("get an otl_1… address on network byte 0, same keys as on a testnet", async () => {
    const seed = new Uint8Array(16).fill(7);
    const main = OotleAccount.fromSeed(seed, 0, "mainnet");
    const esme = OotleAccount.fromSeed(seed, 0, "esmeralda");
    const mainAddress = await main.getWalletAddress();
    const esmeAddress = await esme.getWalletAddress();
    expect(mainAddress.startsWith("otl_1")).toBe(true);
    expect(esmeAddress.startsWith("otl_esm_1")).toBe(true);
    const parsedMain = parseOotleAddress(mainAddress);
    const parsedEsme = parseOotleAddress(esmeAddress);
    expect(parsedMain.network).toBe(Network.MainNet);
    expect(parsedEsme.network).toBe(Network.Esmeralda);
    expect(Array.from(parsedMain.owner_key)).toEqual(Array.from(parsedEsme.owner_key));
  });

  it("refuses the faucet", async () => {
    const main = OotleAccount.fromSeed(new Uint8Array(16).fill(7), 0, "mainnet");
    await expect(main.claimTestnetXtr()).rejects.toThrow(/no faucet on mainnet/);
  });
});
