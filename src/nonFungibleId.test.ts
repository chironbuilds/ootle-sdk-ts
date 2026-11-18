import { describe, expect, it } from "vitest";
import { nonFungibleAddressLiteral } from "@tari-project/ootle";
import {
  canonicalNonFungibleId,
  displayNonFungibleId,
  nonFungibleIdLiteral,
  nonFungibleIdsLiteral,
  parseNonFungibleId,
} from "./nonFungibleId";

const RES = "resource_ff00000000000000000000000000000000000000000000000000000000000001";
const HEX = "736bab0c3af393a0423c578ddcf7e19b81086f6ecbbc148713e95da75ef8171d";

/** Upstream's encoder wraps the id as Tag(130, [resource, id]); the id is everything after the resource. */
function upstreamIdHex(id: { U256: string } | { String: string } | { Uint32: number } | { Uint64: number }): string {
  const full = (nonFungibleAddressLiteral({ resource_address: RES, id } as never) as { Literal: string }).Literal;
  // d8 82 (tag 130), 82 (array 2), 58 20 + 32 bytes (resource): 4 + 2 + 64 hex chars of prefix... locate the resource bytes instead of counting.
  const res = RES.slice("resource_".length);
  const at = full.indexOf(res);
  expect(at).toBeGreaterThan(0);
  return full.slice(at + res.length);
}

describe("NFT ids", () => {
  it("encodes each variant exactly as the upstream encoder does", () => {
    expect(nonFungibleIdLiteral("u64_5")).toEqual({ Literal: upstreamIdHex({ Uint64: 5 }) });
    expect(nonFungibleIdLiteral("u64_300000")).toEqual({ Literal: upstreamIdHex({ Uint64: 300000 }) });
    expect(nonFungibleIdLiteral("u32_7")).toEqual({ Literal: upstreamIdHex({ Uint32: 7 }) });
    expect(nonFungibleIdLiteral("str_hello")).toEqual({ Literal: upstreamIdHex({ String: "hello" }) });
    expect(nonFungibleIdLiteral(`uuid_${HEX}`)).toEqual({ Literal: upstreamIdHex({ U256: HEX }) });
  });

  it("encodes a list as a CBOR array of ids", () => {
    const one = nonFungibleIdLiteral("u64_1") as { Literal: string };
    const two = nonFungibleIdLiteral("str_a") as { Literal: string };
    expect(nonFungibleIdsLiteral(["u64_1", "str_a"])).toEqual({ Literal: "82" + one.Literal + two.Literal });
  });

  it("reads every decoded shape into the canonical form", () => {
    expect(canonicalNonFungibleId({ Uint64: 5 })).toBe("u64_5");
    expect(canonicalNonFungibleId({ Uint32: "9" })).toBe("u32_9");
    expect(canonicalNonFungibleId({ String: "gold" })).toBe("str_gold");
    expect(canonicalNonFungibleId({ U256: HEX })).toBe(`uuid_${HEX}`);
    expect(canonicalNonFungibleId({ U256: Array.from({ length: 32 }, (_, i) => i) })).toBe(
      `uuid_${Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, "0")).join("")}`
    );
    expect(canonicalNonFungibleId([3, [12]])).toBe("u64_12");
    expect(canonicalNonFungibleId({ "@cbor": "tag", value: { Uint64: 2 } })).toBe("u64_2");
    expect(canonicalNonFungibleId("u64_4")).toBe("u64_4");
  });

  it("refuses what it can't type, rather than guessing", () => {
    expect(canonicalNonFungibleId("5")).toBeNull();
    expect(canonicalNonFungibleId({ U256: "abc" })).toBeNull();
    expect(canonicalNonFungibleId({ Mystery: 1 })).toBeNull();
    expect(parseNonFungibleId("u32_4294967296")).toBeNull(); // over u32
    expect(parseNonFungibleId("uuid_xyz")).toBeNull();
    expect(parseNonFungibleId("str_")).toBeNull();
    expect(() => nonFungibleIdLiteral("7")).toThrow(/Not a valid NFT id/);
  });

  it("shows the id without its type", () => {
    expect(displayNonFungibleId("u64_5")).toBe("5");
    expect(displayNonFungibleId("str_my_nft")).toBe("my_nft");
  });
});
