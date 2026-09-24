/* tslint:disable */
/* eslint-disable */

/**
 * Decrypted contents of an inbound stealth UTXO.
 */
export class DecryptedOutputResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The 32-byte commitment mask scalar.
     */
    mask: Uint8Array;
    /**
     * JSON-encoded `Memo` (variants: `U256` / `Message` / `Bytes` / `PayRefAndBytes`), or `null` if
     * the payload carried no memo or `skipMemo` was set.
     */
    get memo_json(): string | undefined;
    /**
     * JSON-encoded `Memo` (variants: `U256` / `Message` / `Bytes` / `PayRefAndBytes`), or `null` if
     * the payload carried no memo or `skipMemo` was set.
     */
    set memo_json(value: string | null | undefined);
    /**
     * The plaintext value (u64).
     */
    value: bigint;
}

/**
 * A generated keypair (raw bytes).
 */
export class KeypairResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    public_key: Uint8Array;
    secret_key: Uint8Array;
}

/**
 * A pair of Ootle public keys derived from an OotleSecretKey.
 */
export class OotlePublicKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The owner (spending) public key bytes.
     */
    owner_key: Uint8Array;
    /**
     * The view-only public key bytes.
     */
    view_key: Uint8Array;
}

/**
 * A pair of Ootle secret keys (owner + view).
 */
export class OotleSecretKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The owner (spending) secret key bytes.
     */
    owner_key: Uint8Array;
    /**
     * The view-only secret key bytes.
     */
    view_key: Uint8Array;
}

/**
 * Parsed components of an Ootle address.
 */
export class ParsedOotleAddress {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Optional pay reference / memo bytes.
     */
    get memo(): Uint8Array | undefined;
    /**
     * Optional pay reference / memo bytes.
     */
    set memo(value: Uint8Array | null | undefined);
    /**
     * The network byte.
     */
    network: number;
    /**
     * The owner (spending) public key bytes.
     */
    owner_key: Uint8Array;
    /**
     * The view-only public key bytes.
     */
    view_key: Uint8Array;
}

/**
 * Result of a Schnorr signature operation (raw bytes). Also used for balance proof signatures, which
 * share the `(public_nonce, signature)` shape.
 */
export class SchnorrSignatureResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    public_nonce: Uint8Array;
    signature: Uint8Array;
}

/**
 * Result of generating a stealth outputs statement.
 */
export class StealthOutputsResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Sum of all witness masks, suitable for use as the `aggregated_output_mask` argument to
     * `generateStealthBalanceProofSignature`.
     */
    aggregated_output_mask: Uint8Array;
    /**
     * JSON-serialized `StealthOutputsStatement` (the wire-format payload).
     */
    statement_json: string;
}

/**
 * Add a signer to a transaction (unsigned or unsealed JSON).
 *
 * Accepts either an `UnsignedTransactionV1` or `UnsealedTransactionV1` JSON string.
 * Returns the `UnsealedTransactionV1` (with the new signature appended) as a JSON string.
 */
export function addTransactionSigner(tx_json: string, signer_secret_key: Uint8Array, seal_signer_public_key: Uint8Array): string;

/**
 * Aggregate the commitment masks of stealth inputs into a single 32-byte Ristretto scalar.
 *
 * `masks_concat` is the concatenated bytes of all input masks (32 bytes per mask, so the input
 * length must be a multiple of 32). Pass an empty array to obtain the zero scalar.
 *
 * Returns the sum as 32 bytes, suitable as the `aggregated_input_mask` argument to
 * `generateStealthBalanceProofSignature`. The output side of the same balance proof is aggregated
 * automatically by `generateStealthOutputsStatement` (returned as `aggregated_output_mask`).
 */
export function aggregateInputMasks(masks_concat: Uint8Array): Uint8Array;

/**
 * BOR-encode a Transaction (JSON string) → base64 string (TransactionEnvelope format).
 */
export function borEncodeTransaction(transaction_json: string): string;

/**
 * Build a script-path `SpendWitness` revealing `leaf` from the committed `conditions` set, optionally
 * supplying a witness `data` blob the leaf's predicate interprets (e.g. a hashlock preimage). Returns a
 * JSON object: `{ "witness": <SpendWitness>, "condition_root": <Hash32> }`.
 *
 * `conditions_json` is the JSON array of `SpendCondition` leaves exactly as passed to
 * `createStealthOutputWitness`'s `PayTo::Conditions` when the output was created; `leaf_json` is the
 * single leaf being revealed. The returned `condition_root` must match the `Script` root recorded in
 * that output's `SpendAuthorization` -- record it against the spent input via
 * `buildStealthInputsStatementFromInputs`.
 *
 * Pass an empty `data` array for a leaf whose predicate needs no spender-supplied data (e.g. a plain
 * timelock refund).
 */
export function buildScriptPathWitness(conditions_json: string, leaf_json: string, data: Uint8Array): string;

/**
 * Build a `StealthInputsStatement` JSON from raw input commitments and a revealed amount.
 *
 * `input_commitments` is the concatenated bytes of all 32-byte commitments (so the length must be a
 * multiple of 32). Pass an empty array for a revealed-only statement.
 *
 * This is a convenience helper so callers don't need to hand-craft the wire JSON; the result is used
 * as the `inputs_statement_json` argument to `generateStealthBalanceProofSignature` and friends.
 */
export function buildStealthInputsStatement(input_commitments: Uint8Array, revealed_amount_microtari: bigint): string;

/**
 * Build a `StealthInputsStatement` JSON from a JSON array of per-input `{commitment, witness}` pairs
 * and a revealed amount.
 *
 * Unlike `buildStealthInputsStatement`, which only builds key-path inputs from raw commitment bytes,
 * this accepts a caller-supplied `witness` per input -- the only way to spend an output committed with
 * `PayTo::Conditions` (e.g. claiming or refunding an HTLC-style hashlock/timelock output). Build each
 * script-path input's witness with `buildScriptPathWitness` first; a plain key-path input can still be
 * included in the same call, either with `"witness":"KeyPath"` or by omitting `witness` entirely
 * (defaults to key path).
 *
 * `inputs_json` shape: `[{ "commitment": <hex 32 bytes>, "witness"?: <SpendWitness> }, ...]`.
 */
export function buildStealthInputsStatementFromInputs(inputs_json: string, revealed_amount_microtari: bigint): string;

/**
 * Build a complete `StealthTransferStatement` JSON from unblinded input/output witnesses.
 *
 * Unlike `generateStealthOutputsStatement` / `buildStealthInputsStatementFromInputs` +
 * `generateStealthBalanceProofSignature`, which build and sign each half of a transfer
 * separately, this wraps the single primitive that produces the *entire*, internally-consistent
 * statement in one call, including a covenant balance-integrity proof for any script-path input
 * whose revealed leaf gates on `Covenant::BalancePreserved` (see `ootle_wasm_core::stealth::
 * transfer::build_stealth_transfer_statement` for when a claim is and isn't needed).
 *
 * `input_witnesses_json` is a JSON array of `{ "mask_and_value": { "value": <u64>, "mask": <hex
 * 32 bytes> }, "witness"?: <SpendWitness>, "condition_root"?: <Hash32> }` -- each entry's
 * `witness`/`condition_root` are the exact pair `buildScriptPathWitness` returns, for a
 * script-path input; omit both for a plain key-path input. Mixing key-path and script-path
 * inputs in one call is supported.
 *
 * `output_witnesses_json` is a JSON array of the same `{ "witness": {...}, "auth": ..., "tag":
 * ... }` shape `createStealthOutputWitness` returns -- collect one entry per output (including
 * change).
 */
export function buildStealthTransferStatement(input_witnesses_json: string, revealed_input_amount_microtari: bigint, output_witnesses_json: string, revealed_output_amount_microtari: bigint): string;

/**
 * Derive the stealth claim secret `s = H(p·R) + p` for claiming an L1 (minotari) burn, from the
 * account secret `p` and the burn's sender offset public key `R`. The claim transaction must be
 * sealed with this key.
 */
export function burnClaimStealthSecret(account_secret: Uint8Array, sender_offset_public_key: Uint8Array): Uint8Array;

/**
 * Builds a `ConfidentialWithdrawProof` for the Account template's `withdraw_confidential` /
 * `join_confidential` methods, and returns it `tari_bor`-encoded -- ready to hex-encode and wrap
 * as an instruction `Literal` arg exactly like `microTariLiteral`/`amountLiteral` do for simpler
 * types. Unlike those, this is NOT re-encoded on the JS side: the bytes are already the encoding
 * the chain itself decodes, produced by the same derive-generated `Encode` impl.
 *
 * `inputs_json` is a JSON array of `{ value, mask }` for each confidential UTXO being spent — `"[]"`
 * for a revealed-only withdrawal (depositing into the vault). `output_json` / `change_json` are each
 * an optional JSON object (see `createStealthOutputWitness`'s `OutputWitnessJson` shape) — omit to
 * skip that side. `*_revealed_amount` is the plaintext portion on each side; confidential and
 * revealed amounts can be mixed on either side.
 *
 * Throws if `inputs_json`/`output_json`/`change_json` don't parse, or if any mask isn't a valid
 * 32-byte Ristretto scalar.
 */
export function createConfidentialWithdrawProofLiteral(inputs_json: string, input_revealed_amount: bigint, output_json: string | null | undefined, output_revealed_amount: bigint, change_json: string | null | undefined, change_revealed_amount: bigint): Uint8Array;

/**
 * Build a single stealth output witness entirely client-side (sender side), mirroring the wallet
 * daemon's `create_output_witness`.
 *
 * A fresh commitment mask and ephemeral nonce are generated internally; the recipient recovers the
 * value and mask by decrypting `encrypted_data`. Returns one witness as a JSON string with the shape:
 * ```text
 * {
 *   "witness": {
 *     "amount": <u64>,
 *     "mask": <hex 32 bytes>,
 *     "sender_public_nonce": <hex 32 bytes>,
 *     "minimum_value_promise": <u64>,
 *     "encrypted_data": <hex variable-length>,
 *     "resource_view_key": <hex 32 bytes | null>
 *   },
 *   "auth": <SpendAuthorization>,
 *   "tag": <u32>
 * }
 * ```
 * Collect one witness per output (including change) into a JSON array and pass it to
 * `generateStealthOutputsStatement`.
 *
 * - `network` is the network byte (0x00 = MainNet, 0x10 = LocalNet, 0x26 = Esmeralda, ...).
 * - `destination_account_public_key` / `destination_view_public_key` are the recipient's 32-byte keys.
 * - `resource_address` is the `resource_<hex>` string of the resource being sent.
 * - `resource_view_key` is the resource view-key holder's 32-byte public key, or `null` for resources without a
 *   viewable balance (when set, the output receives an ElGamal proof at statement time).
 * - `memo_json` is an optional JSON-encoded `Memo` to embed in the encrypted payload.
 * - `pay_to_json` is an optional JSON-encoded `PayTo`: `"StealthPublicKey"` (the default when `null`, producing a
 *   one-time stealth spend key) or `{"AccessRule": <AccessRule>}`.
 * - `minimum_value_promise` is the range-proof lower bound and must be `<= amount` (use `0` normally).
 */
export function createStealthOutputWitness(network: number, destination_account_public_key: Uint8Array, destination_view_public_key: Uint8Array, amount: bigint, resource_address: string, resource_view_key: Uint8Array | null | undefined, memo_json: string | null | undefined, pay_to_json: string | null | undefined, minimum_value_promise: bigint): string;

/**
 * Brute-force decrypt an ElGamal viewable-balance proof to recover the bound value.
 *
 * Tries each value in `[min_value, max_value]` (inclusive). Returns `null` (via `Option`) if no
 * candidate matches. Uses an on-the-fly value lookup — there is no precomputed table dependency, so
 * callers should keep the range tight (large ranges produce proportional CPU cost).
 *
 * `commitment` is the Pedersen commitment the proof is bound to. Both the view public key and the
 * view secret key are required: the public key is used to re-verify the ZK proof (rejecting tampered
 * proofs before decrypting), the secret key performs the ElGamal decryption itself.
 */
export function decryptElgamalViewableBalance(proof_json: string, commitment: Uint8Array, view_public_key: Uint8Array, view_secret_key: Uint8Array, min_value: bigint, max_value: bigint): bigint | undefined;

/**
 * Derive the AEAD encryption key for `encrypted_data` from a Diffie-Hellman shared secret: `H(DH(s, P))`.
 * Sender derives it with `(sender_secret_nonce, recipient_view_pub)`; receiver derives the same key
 * with `(recipient_view_secret, sender_public_nonce)`.
 */
export function encryptedDataDhKdfAead(private_key: Uint8Array, public_key: Uint8Array): Uint8Array;

/**
 * Generate an ElGamal viewable-balance proof: a zero-knowledge proof that `amount` is the value bound
 * by `commitment`, encrypted to the resource view-key holder.
 *
 * Returns the JSON-encoded `ViewableBalanceProof` (8 × 32-byte fields).
 */
export function generateElgamalViewableBalanceProof(mask: Uint8Array, amount: bigint, commitment: Uint8Array, view_public_key: Uint8Array): string;

/**
 * Generate an extended bulletproof aggregating range proofs for a set of output witnesses, proving
 * each amount is in `[minimum_value_promise, 2^64)`. The number of witnesses is padded to the next
 * power of two internally.
 *
 * `witnesses_json` is a JSON array of "flat" output witnesses (the `witness` field shape from
 * [`generate_stealth_outputs_statement`] — without the surrounding `auth` / `tag`).
 *
 * Returns the raw range proof bytes (may be empty if the input array is empty).
 */
export function generateExtendedBulletProof(witnesses_json: string): Uint8Array;

/**
 * Generate a new random Ristretto keypair.
 * Returns { secret_key: Uint8Array, public_key: Uint8Array }.
 */
export function generateKeypair(): KeypairResult;

/**
 * Generate an Ootle address (bech32m string) from public keys.
 *
 * `network` is the network byte (0x00 = MainNet, 0x10 = LocalNet, 0x26 = Esmeralda, etc.).
 * `memo` is an optional pay reference (max 64 bytes).
 */
export function generateOotleAddress(owner_public_key: Uint8Array, view_public_key: Uint8Array, network: number, memo?: Uint8Array | null): string;

/**
 * Generate a new random pair of Ootle secret keys (owner + view).
 * Returns { owner_key: Uint8Array, view_key: Uint8Array }.
 */
export function generateOotleSecretKey(): OotleSecretKey;

/**
 * Sign the balance proof for a stealth transfer.
 *
 * `aggregated_input_mask` and `aggregated_output_mask` are the 32-byte sums of all input / output
 * commitment masks respectively. Returns a `(public_nonce, signature)` pair (each 32 bytes); the pair
 * may be all-zeros for revealed-only transfers — callers normally omit the balance proof in that case.
 */
export function generateStealthBalanceProofSignature(aggregated_input_mask: Uint8Array, aggregated_output_mask: Uint8Array, inputs_statement_json: string, outputs_statement_json: string): SchnorrSignatureResult;

/**
 * Generate the output side of a stealth transfer: per-output Pedersen commitments and encrypted data,
 * optional ElGamal viewable-balance proofs (for outputs with a `resource_view_key`), and an aggregated
 * bulletproof range proof.
 *
 * `witnesses_json` is a JSON array of stealth output witnesses. Each entry has the shape:
 * ```text
 * {
 *   "witness": {
 *     "amount": <u64>,
 *     "mask": <hex 32 bytes>,
 *     "sender_public_nonce": <hex 32 bytes>,
 *     "minimum_value_promise": <u64>,
 *     "encrypted_data": <hex variable-length>,
 *     "resource_view_key": <hex 32 bytes | null>
 *   },
 *   "auth": <SpendAuthorization>,
 *   "tag": <u32>
 * }
 * ```
 *
 * Returns the serialized statement plus the aggregated output mask, which the sender feeds to
 * `generateStealthBalanceProofSignature` together with the aggregated input mask.
 */
export function generateStealthOutputsStatement(witnesses_json: string, revealed_output_amount_microtari: bigint): StealthOutputsResult;

/**
 * Hash an UnsignedTransactionV1 (JSON string) for signing.
 * Returns the 64-byte signing message that must be Schnorr-signed.
 *
 * `seal_signer_public_key` is the raw bytes of the seal signer's public key (account owner).
 */
export function hashUnsignedTransaction(unsigned_tx_json: string, seal_signer_public_key: Uint8Array): Uint8Array;

/**
 * Called automatically when the WASM module is instantiated. Do not call directly.
 */
export function on_start(): void;

/**
 * Derive the Ootle public keys from a pair of secret keys.
 * Returns { owner_key: Uint8Array, view_key: Uint8Array }.
 */
export function ootlePublicKeyFromSecretKey(owner_key: Uint8Array, view_key: Uint8Array): OotlePublicKey;

/**
 * Parse a bech32m Ootle address string into its components.
 * Returns { owner_key: Uint8Array, view_key: Uint8Array, network: number, memo: Uint8Array | undefined }.
 */
export function parseOotleAddress(address: string): ParsedOotleAddress;

/**
 * Derive the public key from a secret key (both raw bytes).
 */
export function publicKeyFromSecretKey(secret_key: Uint8Array): Uint8Array;

/**
 * Schnorr-sign a message with a secret key.
 * Returns { public_nonce: Uint8Array, signature: Uint8Array }.
 */
export function schnorrSign(secret_key: Uint8Array, message: Uint8Array): SchnorrSignatureResult;

/**
 * Seal a transaction (unsigned or unsealed JSON) with the seal signer's secret key.
 *
 * Accepts either an `UnsignedTransactionV1` or `UnsealedTransactionV1` JSON string.
 * Returns the sealed `Transaction` as a JSON string.
 */
export function sealTransaction(tx_json: string, seal_signer_secret_key: Uint8Array): string;

/**
 * Derive the recipient's stealth spending scalar `c + k`, where `c = H(network || k.G * r)`. The
 * receiver runs this with their account secret key (`private_key`) and the sender-provided public
 * nonce to obtain the one-time secret that controls the stealth output.
 *
 * `network` is the network byte (0x00 = MainNet, 0x10 = LocalNet, 0x26 = Esmeralda, ...).
 */
export function stealthDhSecret(network: number, private_key: Uint8Array, public_nonce: Uint8Array): Uint8Array;

/**
 * Decrypt and verify the AEAD payload of an inbound stealth UTXO.
 *
 * `output_commitment` is the 32-byte Pedersen commitment; `encrypted_data` is the variable-length
 * XChaCha20Poly1305-encrypted blob; `encryption_key` is the 32-byte AEAD key derived via
 * `encryptedDataDhKdfAead`. Setting `skip_memo` to `true` returns no memo even if the payload carries
 * one (useful when only the value / mask are needed).
 *
 * Throws on AEAD failure or on a commitment mismatch — either indicates the payload was not produced
 * for this view key.
 */
export function unblindOutput(output_commitment: Uint8Array, encrypted_data: Uint8Array, encryption_key: Uint8Array, skip_memo: boolean): DecryptedOutputResult;

/**
 * Pre-flight check that a balance proof signature is cryptographically valid for the given input /
 * output statements. Returns `false` on a malformed proof or invalid signature; the engine performs
 * the authoritative check at submission.
 */
export function validateBalanceProofSignature(public_nonce: Uint8Array, signature: Uint8Array, inputs_statement_json: string, outputs_statement_json: string): boolean;

/**
 * Check an L1 burn's ownership proof against the stealth claim key derived from `stealth_secret`,
 * exactly as a validator will. `false` means the claim would be rejected.
 *
 * `network` is the network byte (0x00 = MainNet, 0x10 = LocalNet, 0x26 = Esmeralda, ...).
 */
export function validateBurnClaimOwnershipProof(network: number, ownership_nonce: Uint8Array, ownership_signature: Uint8Array, commitment: Uint8Array, value: bigint, stealth_secret: Uint8Array): boolean;

/**
 * Run the same validation the engine performs on a complete `StealthTransferStatement` envelope:
 * structural sanity, commitment well-formedness, range and balance-proof verification.
 *
 * `view_key` is the 32-byte resource view public key, required for resources with a viewable balance
 * and rejected otherwise. Pass `null` for resources without a view key.
 *
 * Throws on a validation failure; returns successfully on a valid statement.
 */
export function validateStealthTransfer(transfer_json: string, view_key?: Uint8Array | null): void;
