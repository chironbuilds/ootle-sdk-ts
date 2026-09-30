// Claim proofs for Layer 1 (minotari) burns, in the exact serde shape Ootle's `ClaimBurn`
// instruction deserialises (`tari_engine_types::confidential::MinotariBurnClaimProof`).
//
// Since tari-ootle#2709 (Ootle 0.42, Minotari 6.0.1-pre.1) a claim proves the L1 burn *output*
// rather than its kernel: the output's hashed fields plus a two-level MMR inclusion proof (output
// hash -> normal output MMR root -> last leaf of the block's `block_output_mr`). A base node serves
// that proof as a Minotari `BurnOutputProof` (`/generate_burn_output_proof?commitment=<hex>`); this
// module converts it the way `claim_proof_from_l1` (tari_ootle_app_utilities) does, and
// `burnClaim.test.ts` checks the conversion against vectors produced by that Rust function.

import type { MinotariBurnClaimProof } from "@tari-project/ootle-ts-bindings";

/** What `OotleAccount.claimBurn()` consumes -- the wallet daemon's `ClaimBurnProofContents`. */
export interface BurnClaimProofContents {
  claim_proof: MinotariBurnClaimProof;
  /** The burn output's encrypted value/mask, hex. */
  encrypted_data: string;
}

/**
 * The claim material an L1 wallet has as soon as it builds a burn (see tari_l1_wasm's
 * `WasmSignedBurn`). Everything except the output's inclusion proof, which only exists once the
 * burn is mined.
 */
export interface L1BurnProofParts {
  /** The Ootle account public key `P` the burn was addressed to. */
  claimPublicKeyHex: string;
  commitmentHex: string;
  ownershipNonceHex: string;
  ownershipSignatureHex: string;
  senderOffsetPublicKeyHex: string;
  encryptedDataHex: string;
  amount: bigint;
  /** No longer part of a claim (tari-ootle#2709); kept so records written before it still load. */
  kernel?: unknown;
}

/** An L1 MMR inclusion proof, as a base node serialises it (hashes are hex). */
export interface L1MmrInclusionProof {
  leaf_index: number | string;
  mmr_size: number | string;
  path: string[];
  peaks: string[];
}

/**
 * A base node's `BurnOutputProof` (the `proof` of a `/generate_burn_output_proof` response, or
 * `claim_proof.output_proof` of a `minotari_console_wallet` proof file). Byte fields are hex.
 */
export interface BurnOutputProof {
  block_hash: string;
  block_height?: number | string;
  output: {
    version: number;
    /** Consensus (borsh) encoded `OutputFeatures` */
    features: string;
    commitment: string;
    rangeproof_hash: string;
    script: string;
    sender_offset_public_key: string;
    metadata_signature: {
      ephemeral_commitment: string;
      ephemeral_pubkey: string;
      u_a: string;
      u_x: string;
      u_y: string;
    };
    covenant: string;
    encrypted_data: string;
    minimum_value_promise: number | string;
  };
  normal_output_proof: L1MmrInclusionProof;
  normal_output_mr: string;
  block_output_proof: L1MmrInclusionProof;
}

const HEX_32 = /^[0-9a-f]{64}$/;

function hex32(value: string, field: string): string {
  const v = value.toLowerCase();
  if (!HEX_32.test(v)) throw new Error(`${field} must be 32 bytes of hex`);
  return v;
}

function hexToBytes(hex: string, field: string): Uint8Array {
  if (!/^[0-9a-f]*$/i.test(hex) || hex.length % 2 !== 0) throw new Error(`${field} must be hex`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Reads the L1 consensus (borsh) encoding. Every read is bounds-checked. */
class BorshReader {
  private pos = 0;
  constructor(private readonly buf: Uint8Array, private readonly what: string) {}
  private take(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new Error(`${this.what}: truncated`);
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  u8(): number {
    return this.take(1)[0]!;
  }
  u32(): number {
    const b = this.take(4);
    return (b[0]! | (b[1]! << 8) | (b[2]! << 16)) + b[3]! * 0x1000000;
  }
  u64(): bigint {
    const b = this.take(8);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
    return v;
  }
  /** A `Vec<u8>` / `&[u8]`: u32 length, then the bytes. */
  bytes(max: number): Uint8Array {
    const n = this.u32();
    if (n > max) throw new Error(`${this.what}: byte string of ${n} exceeds ${max}`);
    return this.take(n);
  }
  /** A compressed key or scalar, which L1 encodes as a 32-byte `&[u8]`. */
  key(field: string): string {
    const b = this.bytes(32);
    if (b.length !== 32) throw new Error(`${this.what}: ${field} is ${b.length} bytes, expected 32`);
    return bytesToHex(b);
  }
  option(): boolean {
    const tag = this.u8();
    if (tag > 1) throw new Error(`${this.what}: invalid Option tag ${tag}`);
    return tag === 1;
  }
  end(): void {
    if (this.pos !== this.buf.length) throw new Error(`${this.what}: ${this.buf.length - this.pos} trailing bytes`);
  }
}

const OUTPUT_TYPE_BURN = 2;
/** `SideChainFeatureData::ConfidentialOutput` */
const SIDECHAIN_CONFIDENTIAL_OUTPUT = 2;
/** `CoinBaseExtra = MaxSizeBytes<258>` */
const COINBASE_EXTRA_MAX = 258;

type BurnOutputFeatures = MinotariBurnClaimProof["output"]["features"];

/**
 * Decodes a burn output's consensus-encoded `OutputFeatures` into the fields a claim carries,
 * refusing anything Ootle can't mint against (not a burn, or no confidential-output sidechain
 * feature naming a claimant) -- the same checks as `claim_proof_from_l1`.
 */
export function decodeBurnOutputFeatures(featuresHex: string): BurnOutputFeatures {
  const r = new BorshReader(hexToBytes(featuresHex, "burn output features"), "burn output features");
  const version = r.u8();
  const outputType = r.u8();
  const maturity = r.u64();
  r.bytes(COINBASE_EXTRA_MAX);
  if (outputType !== OUTPUT_TYPE_BURN) throw new Error(`the output is not a burn (output type ${outputType})`);
  if (!r.option()) throw new Error("the burn output has no sidechain feature, so it names no claimant");
  const variant = r.u8();
  if (variant !== SIDECHAIN_CONFIDENTIAL_OUTPUT) {
    throw new Error(`the burn output's sidechain feature is not a confidential output (variant ${variant})`);
  }
  const claimPublicKey = r.key("claim_public_key");
  let sidechainId: BurnOutputFeatures["sidechain_id"] = null;
  if (r.option()) {
    const publicKey = r.key("sidechain public_key");
    const nonce = r.key("sidechain knowledge_proof.public_nonce");
    const signature = r.key("sidechain knowledge_proof.signature");
    sidechainId = { public_key: publicKey, knowledge_proof: { public_nonce: nonce, signature } };
  }
  const rangeProofType = r.u8();
  r.end();
  return {
    version,
    maturity: maturity.toString(),
    claim_public_key: claimPublicKey,
    sidechain_id: sidechainId,
    range_proof_type: rangeProofType,
  };
}

/** The L1 consensus (borsh) encoding of a `ComAndPubSignature`: five 32-byte fields, each length-prefixed. */
function encodeMetadataSignature(sig: BurnOutputProof["output"]["metadata_signature"]): Uint8Array {
  const fields = [sig.ephemeral_commitment, sig.ephemeral_pubkey, sig.u_a, sig.u_x, sig.u_y];
  const out = new Uint8Array(fields.length * 36);
  fields.forEach((f, i) => {
    out.set([32, 0, 0, 0], i * 36);
    out.set(hexToBytes(hex32(f, "metadata_signature field"), "metadata_signature field"), i * 36 + 4);
  });
  return out;
}

function mmrProof(p: L1MmrInclusionProof) {
  return {
    leaf_index: String(p.leaf_index),
    mmr_size: String(p.mmr_size),
    path: p.path.map((h) => hex32(h, "MMR path hash")),
    peaks: p.peaks.map((h) => hex32(h, "MMR peak hash")),
  };
}

/** A `BoundedVec<u8, 1, N>` field: non-empty, at most `max` bytes, serialised as base64. */
function opaque(hex: string, field: string, max: number): string {
  const b = hexToBytes(hex, field);
  if (b.length < 1 || b.length > max) throw new Error(`burn output ${field} length ${b.length} is out of range`);
  return bytesToBase64(b);
}

/**
 * Converts a base node's `BurnOutputProof` plus the burn's ownership proof and value into the
 * claim Ootle verifies (`claim_proof_from_l1`).
 */
export function claimProofFromL1(
  outputProof: BurnOutputProof,
  ownershipProof: { public_nonce: string; signature: string },
  value: bigint | string | number
): MinotariBurnClaimProof {
  const o = outputProof.output;
  return {
    commitment: hex32(o.commitment, "commitment"),
    ownership_proof: {
      public_nonce: hex32(ownershipProof.public_nonce, "ownership_proof.public_nonce"),
      signature: hex32(ownershipProof.signature, "ownership_proof.signature"),
    },
    value: BigInt(value).toString(),
    output: {
      version: o.version,
      features: decodeBurnOutputFeatures(o.features),
      rangeproof_hash: hex32(o.rangeproof_hash, "rangeproof_hash"),
      script: opaque(o.script, "script", 4096),
      sender_offset_public_key: hex32(o.sender_offset_public_key, "sender_offset_public_key"),
      metadata_signature: bytesToBase64(encodeMetadataSignature(o.metadata_signature)),
      covenant: opaque(o.covenant, "covenant", 4096),
      encrypted_data: opaque(o.encrypted_data, "encrypted data", 4096),
      minimum_value_promise: BigInt(o.minimum_value_promise).toString(),
    },
    inclusion_proof: {
      block_hash: hex32(outputProof.block_hash, "block_hash"),
      normal_output_proof: mmrProof(outputProof.normal_output_proof),
      normal_output_mr: hex32(outputProof.normal_output_mr, "normal_output_mr"),
      block_output_proof: mmrProof(outputProof.block_output_proof),
    },
  } as MinotariBurnClaimProof;
}

/**
 * Joins an L1 burn's claim material with its mined output's inclusion proof (a base node's
 * `/generate_burn_output_proof` `proof`) into a claimable proof.
 */
export function assembleBurnClaimProof(parts: L1BurnProofParts, outputProof: BurnOutputProof): BurnClaimProofContents {
  const commitment = hex32(parts.commitmentHex, "commitmentHex");
  if (outputProof.output.commitment.toLowerCase() !== commitment) {
    throw new Error("The base node's burn output proof is for a different commitment than this burn");
  }
  const claim = claimProofFromL1(
    outputProof,
    { public_nonce: parts.ownershipNonceHex, signature: parts.ownershipSignatureHex },
    parts.amount
  );
  return { claim_proof: claim, encrypted_data: bytesToHex(hexToBytes(parts.encryptedDataHex, "encryptedDataHex")) };
}

function base64ToHex(b64: string): string {
  const bin = atob(b64);
  let out = "";
  for (let i = 0; i < bin.length; i++) out += bin.charCodeAt(i).toString(16).padStart(2, "0");
  return out;
}

/**
 * Reads a proof file written by `minotari_console_wallet` into its `burn_proofs` directory
 * (`CompleteClaimBurnProof`: `claim_proof` is a Minotari `BurnClaimProof` carrying the
 * `output_proof`), converting it to Ootle's claim. A file already in Ootle's shape passes through.
 */
export function parseConsoleWalletBurnProof(json: string | Record<string, unknown>): BurnClaimProofContents {
  const file = (typeof json === "string" ? JSON.parse(json) : json) as {
    claim_proof?: {
      output_proof?: BurnOutputProof;
      ownership_proof?: { public_nonce: string; signature: string };
      value?: number | string;
    } & Partial<MinotariBurnClaimProof>;
    encrypted_data?: string | number[];
  };
  if (!file.claim_proof || file.encrypted_data === undefined) {
    throw new Error("Not a burn proof: expected `claim_proof` and `encrypted_data`");
  }
  const encrypted = Array.isArray(file.encrypted_data)
    ? file.encrypted_data.map((b) => b.toString(16).padStart(2, "0")).join("")
    : /^[0-9a-f]+$/i.test(file.encrypted_data) && file.encrypted_data.length % 2 === 0
      ? file.encrypted_data.toLowerCase()
      : base64ToHex(file.encrypted_data);
  const cp = file.claim_proof;
  if (cp.output_proof) {
    if (!cp.ownership_proof || cp.value === undefined) throw new Error("Burn proof is missing its ownership proof or value");
    return { claim_proof: claimProofFromL1(cp.output_proof, cp.ownership_proof, cp.value), encrypted_data: encrypted };
  }
  if (cp.inclusion_proof && cp.output) return { claim_proof: cp as MinotariBurnClaimProof, encrypted_data: encrypted };
  throw new Error(
    "This burn proof predates Ootle 0.42 (it proves the burn kernel, not the burn output). Regenerate it with a " +
      "Minotari 6.0.1+ wallet, or claim the burn from its commitment."
  );
}
