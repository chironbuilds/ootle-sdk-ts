import { blake2b } from "@noble/hashes/blake2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { parseOotleAddress } from "@tari-project/ootle-wasm";

/**
 * Derives an Ootle on-chain component address from a template address and an owner public key,
 * reproducing `derive_component_address_from_public_key` (`crates/engine_types/src/component.rs`,
 * tari-project/tari-ootle) byte-for-byte:
 *
 *   Blake2b-256( domain_separation_tag("com.tari.ootle.engine", v0, "ComponentAddress")
 *              ‖ template_address (32 raw bytes, Borsh array encoding — no length prefix)
 *              ‖ borsh_len_u32_le(32) ‖ public_key (32 bytes) )
 *
 * The public key is Borsh-*slice*-encoded (`RistrettoPublicKeyBytes`'s manual `BorshSerialize` impl
 * delegates to `self.as_bytes(): &[u8]`, which Borsh length-prefixes), unlike `template_address`
 * (`Hash32([u8; 32])`, a fixed array — Borsh does not prefix fixed-size arrays). Verified against all
 * three committed golden vectors in `tari-ootle`'s `crates/ootle_sdk_core/fixtures/address_derive/`.
 */
export function deriveComponentAddress(templateAddress: Uint8Array, publicKey: Uint8Array): string {
  if (templateAddress.length !== 32) throw new Error("templateAddress must be 32 bytes");
  if (publicKey.length !== 32) throw new Error("publicKey must be 32 bytes");

  const domain = "com.tari.ootle.engine";
  const version = "0";
  const label = "ComponentAddress";
  const tag = utf8ToBytes(`${domain}.v${version}.${label}`);

  const digest = blake2b(
    concatBytes(u64le(tag.length), tag, templateAddress, u32le(publicKey.length), publicKey),
    { dkLen: 32 }
  );
  return `component_${bytesToHex(digest)}`;
}

/** The builtin Account template's address: 32 zero bytes (`ACCOUNT_TEMPLATE_ADDRESS` in `tari_template_builtin`). */
export const ACCOUNT_TEMPLATE_ADDRESS = new Uint8Array(32);

export function deriveAccountComponentAddress(publicKey: Uint8Array): string {
  return deriveComponentAddress(ACCOUNT_TEMPLATE_ADDRESS, publicKey);
}

/**
 * Derives a recipient's on-chain account component address directly from their bech32m Ootle wallet
 * address ("otl_..."). The wallet address already encodes the owner (spending) public key that
 * `deriveAccountComponentAddress` derives the component address from -- the two identify the same
 * account -- so callers (e.g. the Send flow) only need to collect one address from the user instead
 * of also asking them to separately look up and paste their own `component_...` address.
 */
export function componentAddressFromWalletAddress(walletAddress: string): string {
  const { owner_key } = parseOotleAddress(walletAddress);
  return deriveAccountComponentAddress(owner_key);
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  b[2] = (n >>> 16) & 0xff;
  b[3] = (n >>> 24) & 0xff;
  return b;
}

function u64le(n: number): Uint8Array {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}
