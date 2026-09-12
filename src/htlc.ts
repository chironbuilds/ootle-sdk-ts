// HTLC (hashed timelock contract) condition-tree helpers for stealth outputs, built on TIP-0006
// script-path spending (`PayTo::Conditions`). See tari-project/tari-ootle#2426 and #2431 for the
// underlying wasm capability this builds on (buildScriptPathWitness/buildStealthTransferStatement,
// published in @tari-project/ootle-wasm@0.39.0).
//
// The exact nested shape here (`AccessRule`/`RestrictedAccessRule`/`RequireRule`/`RuleRequirement`/
// `NonFungibleAddress`) mirrors `tari-ootle`'s own reference implementation
// (`applications/tari_walletd/src/handlers/accounts.rs`'s `htlc_conditions`/`requires_public_key`
// test helpers) and is cross-verified byte-for-byte against a real Rust-generated golden vector in
// htlc.test.ts -- not hand-derived from docs alone. Getting this JSON shape wrong doesn't fail
// loudly: it produces a condition tree that either can't be claimed by the intended party or can be
// claimed by the wrong one, so treat any change here as fund-safety-critical.

/** The well-known, protocol-fixed resource address for public-key-derived "virtual" ownership
 * badges (`PUBLIC_IDENTITY_RESOURCE_ADDRESS` in `tari_template_lib_types::constants`). Presenting a
 * proof of the non-fungible `{resource_address: this, id: {U256: pubkeyHex}}` -- which the engine
 * auto-populates for any signer of the transaction -- is how "signed by this public key" is
 * expressed as an `AccessRule` in this engine, unlike Bitcoin-style direct signature checks. */
const PUBLIC_IDENTITY_RESOURCE_ADDRESS = "resource_0100000000000000000000000000000000000000000000000000000000000000";

/** An `AccessRule` satisfied only by a transaction signed with `publicKeyHex` (32 raw bytes, hex). */
export function accessRuleRequiringPublicKey(publicKeyHex: string): object {
  return {
    Restricted: {
      Require: {
        Require: {
          NonFungibleAddress: {
            resource_address: PUBLIC_IDENTITY_RESOURCE_ADDRESS,
            id: { U256: publicKeyHex },
          },
        },
      },
    },
  };
}

export interface HtlcConditionsParams {
  /** SHA-256 digest of the secret preimage, as 32 bytes hex. The party funding the HTLC never
   * needs (and should never be given) the preimage itself -- only this hash. */
  hashLockHex: string;
  /** The epoch at/after which the refund path becomes admissible, and strictly before which the
   * claim path is admissible -- so exactly one of the two leaves is ever satisfiable at a given
   * epoch. Must fit a JS safe integer (real network epochs are nowhere near 2^53). */
  refundEpoch: bigint;
  /** The claimant's raw 32-byte owner public key, hex. */
  claimantPublicKeyHex: string;
  /** The refunder's (funder's own) raw 32-byte owner public key, hex. */
  refunderPublicKeyHex: string;
}

/** The two-leaf HTLC condition tree, `[claimLeaf, refundLeaf]` -- pass directly as
 * `createOutput({ payTo: { Conditions: htlcConditions(...) }, ... })`.
 *
 * Claim leaf: hashlock AND before the refund epoch AND the claimant's key.
 * Refund leaf: at/after the refund epoch AND the refunder's key.
 *
 * The condition tree's root (computed on-chain from these leaves at output-creation time) is all
 * that's committed publicly; these full leaves must be handed to the claimant out of band (e.g. by
 * the swap protocol/dApp) so they can later reveal the claim leaf via `buildScriptPathWitness`. */
export function htlcConditions(params: HtlcConditionsParams): object[] {
  // The hash is the SHA-256 digest of the secret preimage: exactly 32 bytes (64 hex chars). A
  // malformed value here silently produces a claim path that can never be satisfied by the
  // intended claimant, so reject it up front rather than funding an unclaimable output. Hex is
  // case-insensitive; normalize to lowercase for a canonical, deterministic hash string.
  if (!/^[0-9a-f]{64}$/i.test(params.hashLockHex)) {
    throw new Error(`htlcConditions: hashLockHex must be exactly 64 hex characters (32 bytes), got ${JSON.stringify(params.hashLockHex)}`);
  }
  if (!Number.isSafeInteger(Number(params.refundEpoch))) {
    throw new Error(`htlcConditions: refundEpoch ${params.refundEpoch} is not representable as a safe JS integer`);
  }
  if (params.refundEpoch <= 0n) {
    throw new Error(`htlcConditions: refundEpoch must be a positive epoch, got ${params.refundEpoch}`);
  }
  const hashLockHex = params.hashLockHex.toLowerCase();
  const refundEpoch = Number(params.refundEpoch);
  const claim = [
    { Builtin: { HashLock: { hash: hashLockHex, alg: "Sha256" } } },
    { Builtin: { BeforeEpoch: refundEpoch } },
    { AccessRule: accessRuleRequiringPublicKey(params.claimantPublicKeyHex) },
  ];
  const refund = [
    { Builtin: { AfterEpoch: refundEpoch } },
    { AccessRule: accessRuleRequiringPublicKey(params.refunderPublicKeyHex) },
  ];
  return [claim, refund];
}
