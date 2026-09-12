// Known-answer vectors copied verbatim from tari-crypto v0.23.2's own `src/hashing.rs` test
// module (`dst_hasher`, `application_hasher`) — free cross-checks of DomainSeparatedHasher's byte
// framing that don't require compiling anything, since they use tari-crypto's own committed
// expected outputs.
import { describe, expect, it } from "vitest";
import { DomainSeparatedHasher } from "./domainHash";
import { utf8ToBytes } from "@noble/hashes/utils.js";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("DomainSeparatedHasher", () => {
  it("matches tari-crypto's Blake2b<U32> dst_hasher vector", () => {
    const hash = new DomainSeparatedHasher("com.tari.generic", 1, "test_hasher", 32)
      .chain(utf8ToBytes("some foo"))
      .finalize();
    expect(toHex(hash)).toBe("a8326620e305430a0b632a0a5e33c6c1124d7513b4bd84736faaa3a0b9ba557f");
  });

  it("matches tari-crypto's Blake2b<U64> application_hasher vector", () => {
    const hash = new DomainSeparatedHasher("com.discworld", 42, "turtles", 64).chain(utf8ToBytes("elephants")).finalize();
    expect(toHex(hash)).toBe(
      "64a89c7160a1076a725fac97d3f67803abd0991d82518a595072fa62df4c870bddee9160f591231c381087831bf6925616013de317ce0b02846585caf41942ac"
    );
  });

  it("chains multiple fields with independent length prefixes (deconstruction vector)", () => {
    const hash = new DomainSeparatedHasher("com.tari.generic", 1, "mytest", 32)
      .chain(utf8ToBytes("rincewind"))
      .chain(utf8ToBytes("hex"))
      .finalize();
    expect(hash.length).toBe(32);
    // Same inputs, split differently across .chain() calls, must NOT match (each chain call adds
    // its own length prefix — concatenating first would silently collapse two different messages).
    const merged = new DomainSeparatedHasher("com.tari.generic", 1, "mytest", 32)
      .chain(utf8ToBytes("rincewindhex"))
      .finalize();
    expect(toHex(hash)).not.toBe(toHex(merged));
  });
});
