// Reproduces `tari_crypto::hashing::DomainSeparatedHasher<Blake2b<N>, Domain>` byte-for-byte
// (tari-crypto v0.23.2 `src/hashing.rs`), used by both CipherSeed (cipherSeed.ts) and account-key
// derivation (derivation.ts), which both hash under `KeyManagerDomain` — `("com.tari.base_layer.key
// _manager", version 1)`, per `tari_hashing` v5.5.0 `hashing/src/domains.rs`.
//
// `new_with_label(label)` seeds the digest with `u64LE(tag.len()) ‖ tag`, where
// `tag = "{domain}.v{version}.{label}"`. Every subsequent `.chain(data)` call adds its OWN
// `u64LE(data.len()) ‖ data` — every chained field is individually length-prefixed, not just the
// initial tag. `DomainSeparatedHasher` is generic over the domain, so this class takes
// domain/version as constructor args too — domainHash.test.ts checks it against tari-crypto's own
// committed test vectors, which use a different domain ("com.tari.generic") than the one this
// codebase actually needs.
import { blake2b } from "@noble/hashes/blake2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

function u64le(n: number): Uint8Array {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

export class DomainSeparatedHasher {
  private chunks: Uint8Array[];
  private readonly dkLen: 32 | 64;

  constructor(domain: string, version: number, label: string, dkLen: 32 | 64) {
    this.dkLen = dkLen;
    const tag = utf8ToBytes(label ? `${domain}.v${version}.${label}` : `${domain}.v${version}`);
    this.chunks = [u64le(tag.length), tag];
  }

  chain(data: Uint8Array): this {
    this.chunks.push(u64le(data.length), data);
    return this;
  }

  finalize(): Uint8Array {
    return blake2b(concatBytes(...this.chunks), { dkLen: this.dkLen });
  }
}

export const KEY_MANAGER_DOMAIN = "com.tari.base_layer.key_manager";
export const KEY_MANAGER_DOMAIN_VERSION = 1;

export function keyManagerDomainHasher(label: string, dkLen: 32 | 64): DomainSeparatedHasher {
  return new DomainSeparatedHasher(KEY_MANAGER_DOMAIN, KEY_MANAGER_DOMAIN_VERSION, label, dkLen);
}
