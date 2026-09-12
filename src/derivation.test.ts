// Fast, self-consistency tests. Byte-exact correctness against the real Rust
// `derive_ristretto_key` is checked separately in scripts/test-crypto.ts (npm run test:crypto)
// against golden vectors generated from the actual upstream tari-ootle/tari-crypto crates.
import { describe, expect, it } from "vitest";
import { deriveAccountKeys } from "./derivation";

const GROUP_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;

function leToBigInt(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

describe("deriveAccountKeys", () => {
  const entropyA = crypto.getRandomValues(new Uint8Array(16));
  const entropyB = crypto.getRandomValues(new Uint8Array(16));

  it("is deterministic: same entropy + index always derives the same keys", () => {
    const a = deriveAccountKeys(entropyA, 0);
    const b = deriveAccountKeys(entropyA, 0);
    expect(a.ownerSecret).toEqual(b.ownerSecret);
    expect(a.viewSecret).toEqual(b.viewSecret);
  });

  it("owner and view keys differ from each other", () => {
    const { ownerSecret, viewSecret } = deriveAccountKeys(entropyA, 0);
    expect(ownerSecret).not.toEqual(viewSecret);
  });

  it("different account indices derive different keys", () => {
    const key0 = deriveAccountKeys(entropyA, 0);
    const key1 = deriveAccountKeys(entropyA, 1);
    expect(key0.ownerSecret).not.toEqual(key1.ownerSecret);
    expect(key0.viewSecret).not.toEqual(key1.viewSecret);
  });

  it("different entropy derives different keys at the same index", () => {
    const keyA = deriveAccountKeys(entropyA, 0);
    const keyB = deriveAccountKeys(entropyB, 0);
    expect(keyA.ownerSecret).not.toEqual(keyB.ownerSecret);
  });

  it("derived scalars are 32 bytes and reduced below the Ristretto group order", () => {
    // A cheap sanity check that we didn't just return raw (unreduced) hash bytes: a uniformly
    // random 32-byte value would only be < GROUP_ORDER (which is just over 2^252) about 1-in-16
    // of the time, so if this were unreduced it would fail intermittently, not systematically.
    for (let index = 0; index < 5; index++) {
      const { ownerSecret, viewSecret } = deriveAccountKeys(entropyA, index);
      expect(ownerSecret).toHaveLength(32);
      expect(viewSecret).toHaveLength(32);
      expect(leToBigInt(ownerSecret)).toBeLessThan(GROUP_ORDER);
      expect(leToBigInt(viewSecret)).toBeLessThan(GROUP_ORDER);
    }
  });

  it("matches a golden vector generated from the real tari-ootle/tari-crypto crates", () => {
    // Same fixture as scripts/test-crypto.ts's "default passphrase" vector.
    const entropy = hexToBytes("3d78714125ebc4cf12d7063bc5e0c12a");
    const { ownerSecret, viewSecret } = deriveAccountKeys(entropy, 0);
    expect(toHex(ownerSecret)).toBe("66e5591b5dc48f82f7615dc4db2758da6ed9df4e8def7032cf052784c247000d");
    expect(toHex(viewSecret)).toBe("e103fb7197f3d17d074b55051f02fcada921967eb5b35b5a2e1a78c4220eac06");
    const { ownerSecret: owner1 } = deriveAccountKeys(entropy, 1);
    expect(toHex(owner1)).toBe("8b1425e448f80af88e57207da50c2bfca926676c8d485ad97e934dcd5c643609");
  });
});
