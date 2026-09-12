// HD key derivation: CipherSeed entropy + account index -> a deterministic (ownerSecret,
// viewSecret) Ristretto scalar pair, matching the shape `SecretKeyWallet.fromSecretKey` expects
// (owner/spend key + view-only key — the "account" / "view_only_key" branches).
//
// Reproduces `derive_ristretto_key` (tari-ootle's `crates/wallet/crypto/src/derive.rs`)
// byte-for-byte: a domain-separated Blake2b-512 hash under `KeyManagerDomain`
// (`domainHash.ts`), label `"derive_key"`, chaining `entropy ‖ branch ‖ index (u64 LE)`
// — each individually length-prefixed by the hasher, not concatenated first — wide-reduced mod
// the Ristretto group order. Branch strings ("account" / "view_only_key") are
// `KeyBranch::as_str()` (tari-ootle's `crates/wallet/sdk/src/models/key.rs`).
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { keyManagerDomainHasher } from "./domainHash";

// The Ristretto255 / Ed25519 group order l = 2^252 + 27742317777372353535851937790883648493.
const GROUP_ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;

function u64le(n: number): Uint8Array {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

/** Reduce a 64-byte wide value mod the group order and re-encode as a 32-byte little-endian scalar. */
function scalarFromWideBytes(wide: Uint8Array): Uint8Array {
  let n = 0n;
  for (let i = wide.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(wide[i] ?? 0);
  n %= GROUP_ORDER;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function deriveScalar(entropy: Uint8Array, branch: string, index: number): Uint8Array {
  const wide = keyManagerDomainHasher("derive_key", 64).chain(entropy).chain(utf8ToBytes(branch)).chain(u64le(index)).finalize();
  return scalarFromWideBytes(wide);
}

export interface DerivedAccountKeys {
  ownerSecret: Uint8Array;
  viewSecret: Uint8Array;
}

/** `entropy` is the 16-byte CipherSeed entropy (see cipherSeed.ts), not the raw seed/mnemonic. */
export function deriveAccountKeys(entropy: Uint8Array, index: number): DerivedAccountKeys {
  return {
    ownerSecret: deriveScalar(entropy, "account", index),
    viewSecret: deriveScalar(entropy, "view_only_key", index),
  };
}
