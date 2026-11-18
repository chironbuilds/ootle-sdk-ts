/**
 * Non-fungible token ids, in the form the engine itself prints them (`NonFungibleId::to_canonical_string`
 * in tari-ootle's template_lib_types):
 *
 * - `uuid_<64 hex chars>` for a `U256` id
 * - `str_<text>`          for a `String` id
 * - `u32_<n>` / `u64_<n>` for the integer ids
 *
 * The type has to travel with the id: the same bare "5" could be a `Uint32`, a `Uint64` or a `String`,
 * and the engine treats them as different tokens. It is also exactly the suffix of an NFT's substate id
 * (`nft_<resource hex>_<canonical id>`), so the indexer can be asked for a token's data directly.
 */
import type { InstructionArg } from "@tari-project/ootle-ts-bindings";

/** One of the engine's four `NonFungibleId` variants, typed. */
export type ParsedNonFungibleId =
  | { kind: "uuid"; bytes: Uint8Array }
  | { kind: "str"; value: string }
  | { kind: "u32"; value: bigint }
  | { kind: "u64"; value: bigint };

const HEX64 = /^[0-9a-f]{64}$/i;
const U32_MAX = (1n << 32n) - 1n;
const U64_MAX = (1n << 64n) - 1n;
/** The engine's `NON_FUNGIBLE_ID_STR_MAX_LEN`. */
const STR_MAX_LEN = 64;

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Bytes from the shapes a decoded U256 payload arrives in: hex, a byte array, or a number array. */
function payloadBytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (typeof v === "string" && HEX64.test(v)) return hexToBytes(v);
  if (Array.isArray(v) && v.length === 32 && v.every((n) => Number.isInteger(n) && n >= 0 && n < 256)) return Uint8Array.from(v as number[]);
  return null;
}

/** Strips the indexer decoder's `{"@cbor": "tag", value}` envelopes. */
function unwrap(v: unknown): unknown {
  let node = v;
  while (node && typeof node === "object" && !Array.isArray(node) && !(node instanceof Uint8Array) && "@cbor" in node) {
    node = (node as { value?: unknown }).value;
  }
  return node;
}

/**
 * The canonical id of a decoded `NonFungibleId`, whatever shape the decoder produced: the serde-style
 * `{ U256 | String | Uint32 | Uint64: ... }` object, or the raw CBOR `[variant, [field]]` array.
 * Returns null for anything it doesn't recognise rather than guessing a type.
 */
export function canonicalNonFungibleId(id: unknown): string | null {
  const node = unwrap(id);
  if (typeof node === "string" && parseNonFungibleId(node)) return node; // already canonical
  if (Array.isArray(node) && node.length === 2 && typeof node[0] === "number") {
    const field = unwrap(Array.isArray(node[1]) ? node[1][0] : node[1]);
    return canonicalNonFungibleId({ [["U256", "String", "Uint32", "Uint64"][node[0]] ?? "?"]: field });
  }
  if (!node || typeof node !== "object") return null;
  const rec = node as Record<string, unknown>;
  if ("U256" in rec) {
    const bytes = payloadBytes(unwrap(rec.U256));
    return bytes && bytes.length === 32 ? `uuid_${bytesToHex(bytes)}` : null;
  }
  if ("String" in rec) {
    const s = unwrap(rec.String);
    return typeof s === "string" && s.length > 0 ? `str_${s}` : null;
  }
  for (const [key, prefix] of [["Uint32", "u32"], ["Uint64", "u64"]] as const) {
    if (key in rec) {
      const n = unwrap(rec[key]);
      if ((typeof n === "number" && Number.isInteger(n) && n >= 0) || typeof n === "bigint") return `${prefix}_${BigInt(n)}`;
      if (typeof n === "string" && /^\d+$/.test(n)) return `${prefix}_${n}`;
      return null;
    }
  }
  return null;
}

/** Parses a canonical id. Null when it isn't one (wrong prefix, out of range, bad hex). */
export function parseNonFungibleId(canonical: string): ParsedNonFungibleId | null {
  const sep = canonical.indexOf("_");
  if (sep < 0) return null;
  const type = canonical.slice(0, sep);
  const rest = canonical.slice(sep + 1);
  switch (type) {
    case "uuid":
      return HEX64.test(rest) ? { kind: "uuid", bytes: hexToBytes(rest) } : null;
    case "str":
      return rest.length > 0 && rest.length <= STR_MAX_LEN ? { kind: "str", value: rest } : null;
    case "u32":
    case "u64": {
      if (!/^\d+$/.test(rest)) return null;
      const value = BigInt(rest);
      return value <= (type === "u32" ? U32_MAX : U64_MAX) ? { kind: type, value } : null;
    }
    default:
      return null;
  }
}

/** The id as people read it: the number, the text, or the hex, without the type prefix. */
export function displayNonFungibleId(canonical: string): string {
  const sep = canonical.indexOf("_");
  return sep < 0 ? canonical : canonical.slice(sep + 1);
}

// ---- CBOR, as the engine's minicbor derive lays a NonFungibleId out ----------------------------
// An enum is a two-element array: the variant index, then an array of the variant's fields.
// Variant order: U256 = 0, String = 1, Uint32 = 2, Uint64 = 3.

function head(out: number[], major: number, n: bigint): void {
  const m = major << 5;
  if (n < 24n) out.push(m | Number(n));
  else if (n < 1n << 8n) out.push(m | 24, Number(n));
  else if (n < 1n << 16n) out.push(m | 25, Number(n >> 8n), Number(n & 0xffn));
  else if (n < 1n << 32n) out.push(m | 26, ...[24n, 16n, 8n, 0n].map((s) => Number((n >> s) & 0xffn)));
  else out.push(m | 27, ...[56n, 48n, 40n, 32n, 24n, 16n, 8n, 0n].map((s) => Number((n >> s) & 0xffn)));
}

function writeId(out: number[], id: ParsedNonFungibleId): void {
  head(out, 4, 2n); // [variant, [field]]
  switch (id.kind) {
    case "uuid":
      head(out, 0, 0n);
      head(out, 4, 1n);
      head(out, 2, 32n);
      out.push(...id.bytes);
      break;
    case "str": {
      const bytes = new TextEncoder().encode(id.value);
      head(out, 0, 1n);
      head(out, 4, 1n);
      head(out, 3, BigInt(bytes.length));
      out.push(...bytes);
      break;
    }
    case "u32":
    case "u64":
      head(out, 0, id.kind === "u32" ? 2n : 3n);
      head(out, 4, 1n);
      head(out, 0, id.value);
      break;
  }
}

function requireParsed(canonical: string): ParsedNonFungibleId {
  const id = parseNonFungibleId(canonical);
  if (!id) throw new Error(`Not a valid NFT id: "${canonical}" (expected uuid_<hex>, str_<text>, u32_<n> or u64_<n>)`);
  return id;
}

/** A `NonFungibleId` instruction argument, e.g. for the account's `withdraw_non_fungible`. */
export function nonFungibleIdLiteral(canonical: string): InstructionArg {
  const out: number[] = [];
  writeId(out, requireParsed(canonical));
  return { Literal: bytesToHex(Uint8Array.from(out)) };
}

/** A `Vec<NonFungibleId>` instruction argument, e.g. for `withdraw_many_non_fungibles`. */
export function nonFungibleIdsLiteral(canonicals: string[]): InstructionArg {
  const out: number[] = [];
  head(out, 4, BigInt(canonicals.length));
  for (const c of canonicals) writeId(out, requireParsed(c));
  return { Literal: bytesToHex(Uint8Array.from(out)) };
}
