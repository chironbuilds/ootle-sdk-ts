// Claim proofs for Layer 1 (minotari) burns, in the exact serde shape Ootle's `ClaimBurn`
// instruction deserialises (`tari_engine_types::confidential::MinotariBurnClaimProof`): byte fields
// are hex, the merkle proof's two byte fields are base64, and every u64 is carried as a decimal
// string -- a burn value can exceed 2^53, and the engine accepts strings for all of them.

import type { MinotariBurnClaimProof } from "@tari-project/ootle-ts-bindings";

/** What `OotleAccount.claimBurn()` consumes -- the wallet daemon's `ClaimBurnProofContents`. */
export interface BurnClaimProofContents {
  claim_proof: MinotariBurnClaimProof;
  /** The burn output's encrypted value/mask, hex. */
  encrypted_data: string;
}

/**
 * The claim material an L1 wallet has as soon as it builds a burn (see tari_l1_wasm's
 * `WasmSignedBurn`). Everything except the kernel merkle proof, which only exists once the burn
 * is mined.
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
  kernel: {
    version: number;
    fee: bigint;
    lockHeight: bigint;
    excessHex: string;
    nonceHex: string;
    signatureHex: string;
  };
}

/** A base node's `/generate_kernel_merkle_proof` response, passed through unchanged. */
export interface KernelMerkleProof {
  /** base64 */
  block_hash: string;
  /** base64 */
  encoded_merkle_proof: string;
  leaf_index: number | string;
  block_height?: number | null;
}

const HEX_32 = /^[0-9a-f]{64}$/;

function hex32(value: string, field: string): string {
  const v = value.toLowerCase();
  if (!HEX_32.test(v)) throw new Error(`${field} must be 32 bytes of hex`);
  return v;
}

/** Joins an L1 burn's claim material with its kernel merkle proof into a claimable proof. */
export function assembleBurnClaimProof(parts: L1BurnProofParts, merkle: KernelMerkleProof): BurnClaimProofContents {
  if (!/^[0-9a-f]+$/i.test(parts.encryptedDataHex) || parts.encryptedDataHex.length % 2 !== 0) {
    throw new Error("encryptedDataHex must be hex");
  }
  return {
    claim_proof: {
      burn_public_key: hex32(parts.claimPublicKeyHex, "claimPublicKeyHex"),
      commitment: hex32(parts.commitmentHex, "commitmentHex"),
      ownership_proof: {
        public_nonce: hex32(parts.ownershipNonceHex, "ownershipNonceHex"),
        signature: hex32(parts.ownershipSignatureHex, "ownershipSignatureHex"),
      },
      encoded_merkle_proof: {
        block_hash: merkle.block_hash,
        encoded_merkle_proof: merkle.encoded_merkle_proof,
        leaf_index: String(merkle.leaf_index),
      },
      kernel: {
        version: parts.kernel.version,
        fee: parts.kernel.fee.toString(),
        lock_height: parts.kernel.lockHeight.toString(),
        excess: hex32(parts.kernel.excessHex, "kernel.excessHex"),
        excess_sig: {
          public_nonce: hex32(parts.kernel.nonceHex, "kernel.nonceHex"),
          signature: hex32(parts.kernel.signatureHex, "kernel.signatureHex"),
        },
      },
      value: parts.amount.toString(),
      sender_offset_public_key: hex32(parts.senderOffsetPublicKeyHex, "senderOffsetPublicKeyHex"),
    },
    encrypted_data: parts.encryptedDataHex.toLowerCase(),
  };
}

function base64ToHex(b64: string): string {
  const bin = atob(b64);
  let out = "";
  for (let i = 0; i < bin.length; i++) out += bin.charCodeAt(i).toString(16).padStart(2, "0");
  return out;
}

/**
 * Reads a proof file written by `minotari_console_wallet` into its `burn_proofs` directory
 * (`CompleteClaimBurnProof`). Its layout matches Ootle's except that `encrypted_data` is base64.
 */
export function parseConsoleWalletBurnProof(json: string | Record<string, unknown>): BurnClaimProofContents {
  const file = (typeof json === "string" ? JSON.parse(json) : json) as {
    claim_proof?: MinotariBurnClaimProof;
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
  return { claim_proof: file.claim_proof, encrypted_data: encrypted };
}
