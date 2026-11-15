import { describe, expect, it } from "vitest";
import { accountsOnChain, sapientDeepLink } from "./provider.js";
import { TARI_WC_METHODS, wcChainId } from "./namespace.js";

describe("walletconnect helpers", () => {
  it("builds chain ids", () => {
    expect(wcChainId("mainnet")).toBe("tari:mainnet");
    expect(wcChainId("esmeralda")).toBe("tari:esmeralda");
  });

  it("extracts addresses for one chain only", () => {
    const a = `component_${"ab".repeat(32)}`;
    expect(accountsOnChain([`tari:mainnet:${a}`, `tari:esmeralda:other`, "eip155:1:0xabc"], "tari:mainnet")).toEqual([a]);
  });

  it("encodes the pairing uri in the deep link", () => {
    const uri = "wc:abc@2?relay-protocol=irn&symKey=00ff";
    const link = sapientDeepLink(uri);
    expect(link.startsWith("sapient://wc?uri=")).toBe(true);
    expect(new URL(link).searchParams.get("uri")).toBe(uri);
  });

  it("has no duplicate methods", () => {
    expect(new Set(TARI_WC_METHODS).size).toBe(TARI_WC_METHODS.length);
  });
});
