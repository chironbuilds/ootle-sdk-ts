/**
 * Decrypted contents of an inbound stealth UTXO.
 */
export class DecryptedOutputResult {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(DecryptedOutputResult.prototype);
        obj.__wbg_ptr = ptr;
        DecryptedOutputResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        DecryptedOutputResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_decryptedoutputresult_free(ptr, 0);
    }
    /**
     * The 32-byte commitment mask scalar.
     * @returns {Uint8Array}
     */
    get mask() {
        const ret = wasm.__wbg_get_decryptedoutputresult_mask(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * JSON-encoded `Memo` (variants: `U256` / `Message` / `Bytes` / `PayRefAndBytes`), or `null` if
     * the payload carried no memo or `skipMemo` was set.
     * @returns {string | undefined}
     */
    get memo_json() {
        const ret = wasm.__wbg_get_decryptedoutputresult_memo_json(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * The plaintext value (u64).
     * @returns {bigint}
     */
    get value() {
        const ret = wasm.__wbg_get_decryptedoutputresult_value(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * The 32-byte commitment mask scalar.
     * @param {Uint8Array} arg0
     */
    set mask(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_decryptedoutputresult_mask(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * JSON-encoded `Memo` (variants: `U256` / `Message` / `Bytes` / `PayRefAndBytes`), or `null` if
     * the payload carried no memo or `skipMemo` was set.
     * @param {string | null} [arg0]
     */
    set memo_json(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_decryptedoutputresult_memo_json(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * The plaintext value (u64).
     * @param {bigint} arg0
     */
    set value(arg0) {
        wasm.__wbg_set_decryptedoutputresult_value(this.__wbg_ptr, arg0);
    }
}
if (Symbol.dispose) DecryptedOutputResult.prototype[Symbol.dispose] = DecryptedOutputResult.prototype.free;

/**
 * A generated keypair (raw bytes).
 */
export class KeypairResult {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(KeypairResult.prototype);
        obj.__wbg_ptr = ptr;
        KeypairResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        KeypairResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keypairresult_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get public_key() {
        const ret = wasm.__wbg_get_keypairresult_public_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    get secret_key() {
        const ret = wasm.__wbg_get_keypairresult_secret_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} arg0
     */
    set public_key(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_public_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {Uint8Array} arg0
     */
    set secret_key(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_secret_key(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) KeypairResult.prototype[Symbol.dispose] = KeypairResult.prototype.free;

/**
 * A pair of Ootle public keys derived from an OotleSecretKey.
 */
export class OotlePublicKey {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(OotlePublicKey.prototype);
        obj.__wbg_ptr = ptr;
        OotlePublicKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        OotlePublicKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ootlepublickey_free(ptr, 0);
    }
    /**
     * The owner (spending) public key bytes.
     * @returns {Uint8Array}
     */
    get owner_key() {
        const ret = wasm.__wbg_get_ootlepublickey_owner_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * The view-only public key bytes.
     * @returns {Uint8Array}
     */
    get view_key() {
        const ret = wasm.__wbg_get_ootlepublickey_view_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * The owner (spending) public key bytes.
     * @param {Uint8Array} arg0
     */
    set owner_key(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_secret_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * The view-only public key bytes.
     * @param {Uint8Array} arg0
     */
    set view_key(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_public_key(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) OotlePublicKey.prototype[Symbol.dispose] = OotlePublicKey.prototype.free;

/**
 * A pair of Ootle secret keys (owner + view).
 */
export class OotleSecretKey {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(OotleSecretKey.prototype);
        obj.__wbg_ptr = ptr;
        OotleSecretKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        OotleSecretKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_ootlesecretkey_free(ptr, 0);
    }
    /**
     * The owner (spending) secret key bytes.
     * @returns {Uint8Array}
     */
    get owner_key() {
        const ret = wasm.__wbg_get_ootlesecretkey_owner_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * The view-only secret key bytes.
     * @returns {Uint8Array}
     */
    get view_key() {
        const ret = wasm.__wbg_get_ootlesecretkey_view_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * The owner (spending) secret key bytes.
     * @param {Uint8Array} arg0
     */
    set owner_key(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_secret_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * The view-only secret key bytes.
     * @param {Uint8Array} arg0
     */
    set view_key(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_public_key(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) OotleSecretKey.prototype[Symbol.dispose] = OotleSecretKey.prototype.free;

/**
 * Parsed components of an Ootle address.
 */
export class ParsedOotleAddress {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(ParsedOotleAddress.prototype);
        obj.__wbg_ptr = ptr;
        ParsedOotleAddressFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        ParsedOotleAddressFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_parsedootleaddress_free(ptr, 0);
    }
    /**
     * Optional pay reference / memo bytes.
     * @returns {Uint8Array | undefined}
     */
    get memo() {
        const ret = wasm.__wbg_get_parsedootleaddress_memo(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * The network byte.
     * @returns {number}
     */
    get network() {
        const ret = wasm.__wbg_get_parsedootleaddress_network(this.__wbg_ptr);
        return ret;
    }
    /**
     * The owner (spending) public key bytes.
     * @returns {Uint8Array}
     */
    get owner_key() {
        const ret = wasm.__wbg_get_parsedootleaddress_owner_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * The view-only public key bytes.
     * @returns {Uint8Array}
     */
    get view_key() {
        const ret = wasm.__wbg_get_parsedootleaddress_view_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Optional pay reference / memo bytes.
     * @param {Uint8Array | null} [arg0]
     */
    set memo(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_parsedootleaddress_memo(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * The network byte.
     * @param {number} arg0
     */
    set network(arg0) {
        wasm.__wbg_set_parsedootleaddress_network(this.__wbg_ptr, arg0);
    }
    /**
     * The owner (spending) public key bytes.
     * @param {Uint8Array} arg0
     */
    set owner_key(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_secret_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * The view-only public key bytes.
     * @param {Uint8Array} arg0
     */
    set view_key(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_public_key(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) ParsedOotleAddress.prototype[Symbol.dispose] = ParsedOotleAddress.prototype.free;

/**
 * Result of a Schnorr signature operation (raw bytes). Also used for balance proof signatures, which
 * share the `(public_nonce, signature)` shape.
 */
export class SchnorrSignatureResult {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(SchnorrSignatureResult.prototype);
        obj.__wbg_ptr = ptr;
        SchnorrSignatureResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SchnorrSignatureResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_schnorrsignatureresult_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get public_nonce() {
        const ret = wasm.__wbg_get_schnorrsignatureresult_public_nonce(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    get signature() {
        const ret = wasm.__wbg_get_schnorrsignatureresult_signature(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} arg0
     */
    set public_nonce(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_secret_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {Uint8Array} arg0
     */
    set signature(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_public_key(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) SchnorrSignatureResult.prototype[Symbol.dispose] = SchnorrSignatureResult.prototype.free;

/**
 * Result of generating a stealth outputs statement.
 */
export class StealthOutputsResult {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(StealthOutputsResult.prototype);
        obj.__wbg_ptr = ptr;
        StealthOutputsResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        StealthOutputsResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_stealthoutputsresult_free(ptr, 0);
    }
    /**
     * Sum of all witness masks, suitable for use as the `aggregated_output_mask` argument to
     * `generateStealthBalanceProofSignature`.
     * @returns {Uint8Array}
     */
    get aggregated_output_mask() {
        const ret = wasm.__wbg_get_stealthoutputsresult_aggregated_output_mask(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * JSON-serialized `StealthOutputsStatement` (the wire-format payload).
     * @returns {string}
     */
    get statement_json() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_stealthoutputsresult_statement_json(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Sum of all witness masks, suitable for use as the `aggregated_output_mask` argument to
     * `generateStealthBalanceProofSignature`.
     * @param {Uint8Array} arg0
     */
    set aggregated_output_mask(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_public_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * JSON-serialized `StealthOutputsStatement` (the wire-format payload).
     * @param {string} arg0
     */
    set statement_json(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_keypairresult_secret_key(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) StealthOutputsResult.prototype[Symbol.dispose] = StealthOutputsResult.prototype.free;

/**
 * Add a signer to a transaction (unsigned or unsealed JSON).
 *
 * Accepts either an `UnsignedTransactionV1` or `UnsealedTransactionV1` JSON string.
 * Returns the `UnsealedTransactionV1` (with the new signature appended) as a JSON string.
 * @param {string} tx_json
 * @param {Uint8Array} signer_secret_key
 * @param {Uint8Array} seal_signer_public_key
 * @returns {string}
 */
export function addTransactionSigner(tx_json, signer_secret_key, seal_signer_public_key) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(tx_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(signer_secret_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(seal_signer_public_key, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.addTransactionSigner(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Aggregate the commitment masks of stealth inputs into a single 32-byte Ristretto scalar.
 *
 * `masks_concat` is the concatenated bytes of all input masks (32 bytes per mask, so the input
 * length must be a multiple of 32). Pass an empty array to obtain the zero scalar.
 *
 * Returns the sum as 32 bytes, suitable as the `aggregated_input_mask` argument to
 * `generateStealthBalanceProofSignature`. The output side of the same balance proof is aggregated
 * automatically by `generateStealthOutputsStatement` (returned as `aggregated_output_mask`).
 * @param {Uint8Array} masks_concat
 * @returns {Uint8Array}
 */
export function aggregateInputMasks(masks_concat) {
    const ptr0 = passArray8ToWasm0(masks_concat, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.aggregateInputMasks(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * BOR-encode a Transaction (JSON string) → base64 string (TransactionEnvelope format).
 * @param {string} transaction_json
 * @returns {string}
 */
export function borEncodeTransaction(transaction_json) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(transaction_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.borEncodeTransaction(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

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
 * @param {string} conditions_json
 * @param {string} leaf_json
 * @param {Uint8Array} data
 * @returns {string}
 */
export function buildScriptPathWitness(conditions_json, leaf_json, data) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(conditions_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(leaf_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.buildScriptPathWitness(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Build a `StealthInputsStatement` JSON from raw input commitments and a revealed amount.
 *
 * `input_commitments` is the concatenated bytes of all 32-byte commitments (so the length must be a
 * multiple of 32). Pass an empty array for a revealed-only statement.
 *
 * This is a convenience helper so callers don't need to hand-craft the wire JSON; the result is used
 * as the `inputs_statement_json` argument to `generateStealthBalanceProofSignature` and friends.
 * @param {Uint8Array} input_commitments
 * @param {bigint} revealed_amount_microtari
 * @returns {string}
 */
export function buildStealthInputsStatement(input_commitments, revealed_amount_microtari) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(input_commitments, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.buildStealthInputsStatement(ptr0, len0, revealed_amount_microtari);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

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
 * @param {string} inputs_json
 * @param {bigint} revealed_amount_microtari
 * @returns {string}
 */
export function buildStealthInputsStatementFromInputs(inputs_json, revealed_amount_microtari) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(inputs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.buildStealthInputsStatementFromInputs(ptr0, len0, revealed_amount_microtari);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

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
 * @param {string} input_witnesses_json
 * @param {bigint} revealed_input_amount_microtari
 * @param {string} output_witnesses_json
 * @param {bigint} revealed_output_amount_microtari
 * @returns {string}
 */
export function buildStealthTransferStatement(input_witnesses_json, revealed_input_amount_microtari, output_witnesses_json, revealed_output_amount_microtari) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(input_witnesses_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(output_witnesses_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.buildStealthTransferStatement(ptr0, len0, revealed_input_amount_microtari, ptr1, len1, revealed_output_amount_microtari);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

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
 * @param {string} inputs_json
 * @param {bigint} input_revealed_amount
 * @param {string | null | undefined} output_json
 * @param {bigint} output_revealed_amount
 * @param {string | null | undefined} change_json
 * @param {bigint} change_revealed_amount
 * @returns {Uint8Array}
 */
export function createConfidentialWithdrawProofLiteral(inputs_json, input_revealed_amount, output_json, output_revealed_amount, change_json, change_revealed_amount) {
    const ptr0 = passStringToWasm0(inputs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(output_json) ? 0 : passStringToWasm0(output_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    var ptr2 = isLikeNone(change_json) ? 0 : passStringToWasm0(change_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len2 = WASM_VECTOR_LEN;
    const ret = wasm.createConfidentialWithdrawProofLiteral(ptr0, len0, input_revealed_amount, ptr1, len1, output_revealed_amount, ptr2, len2, change_revealed_amount);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

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
 * @param {number} network
 * @param {Uint8Array} destination_account_public_key
 * @param {Uint8Array} destination_view_public_key
 * @param {bigint} amount
 * @param {string} resource_address
 * @param {Uint8Array | null | undefined} resource_view_key
 * @param {string | null | undefined} memo_json
 * @param {string | null | undefined} pay_to_json
 * @param {bigint} minimum_value_promise
 * @returns {string}
 */
export function createStealthOutputWitness(network, destination_account_public_key, destination_view_public_key, amount, resource_address, resource_view_key, memo_json, pay_to_json, minimum_value_promise) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passArray8ToWasm0(destination_account_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(destination_view_public_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(resource_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(resource_view_key) ? 0 : passArray8ToWasm0(resource_view_key, wasm.__wbindgen_malloc);
        var len3 = WASM_VECTOR_LEN;
        var ptr4 = isLikeNone(memo_json) ? 0 : passStringToWasm0(memo_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len4 = WASM_VECTOR_LEN;
        var ptr5 = isLikeNone(pay_to_json) ? 0 : passStringToWasm0(pay_to_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len5 = WASM_VECTOR_LEN;
        const ret = wasm.createStealthOutputWitness(network, ptr0, len0, ptr1, len1, amount, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, minimum_value_promise);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

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
 * @param {string} proof_json
 * @param {Uint8Array} commitment
 * @param {Uint8Array} view_public_key
 * @param {Uint8Array} view_secret_key
 * @param {bigint} min_value
 * @param {bigint} max_value
 * @returns {bigint | undefined}
 */
export function decryptElgamalViewableBalance(proof_json, commitment, view_public_key, view_secret_key, min_value, max_value) {
    const ptr0 = passStringToWasm0(proof_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(commitment, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(view_public_key, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(view_secret_key, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.decryptElgamalViewableBalance(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, min_value, max_value);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    return ret[0] === 0 ? undefined : BigInt.asUintN(64, ret[1]);
}

/**
 * Derive the AEAD encryption key for `encrypted_data` from a Diffie-Hellman shared secret: `H(DH(s, P))`.
 * Sender derives it with `(sender_secret_nonce, recipient_view_pub)`; receiver derives the same key
 * with `(recipient_view_secret, sender_public_nonce)`.
 * @param {Uint8Array} private_key
 * @param {Uint8Array} public_key
 * @returns {Uint8Array}
 */
export function encryptedDataDhKdfAead(private_key, public_key) {
    const ptr0 = passArray8ToWasm0(private_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(public_key, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.encryptedDataDhKdfAead(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Generate an ElGamal viewable-balance proof: a zero-knowledge proof that `amount` is the value bound
 * by `commitment`, encrypted to the resource view-key holder.
 *
 * Returns the JSON-encoded `ViewableBalanceProof` (8 × 32-byte fields).
 * @param {Uint8Array} mask
 * @param {bigint} amount
 * @param {Uint8Array} commitment
 * @param {Uint8Array} view_public_key
 * @returns {string}
 */
export function generateElgamalViewableBalanceProof(mask, amount, commitment, view_public_key) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passArray8ToWasm0(mask, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(commitment, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(view_public_key, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.generateElgamalViewableBalanceProof(ptr0, len0, amount, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Generate an extended bulletproof aggregating range proofs for a set of output witnesses, proving
 * each amount is in `[minimum_value_promise, 2^64)`. The number of witnesses is padded to the next
 * power of two internally.
 *
 * `witnesses_json` is a JSON array of "flat" output witnesses (the `witness` field shape from
 * [`generate_stealth_outputs_statement`] — without the surrounding `auth` / `tag`).
 *
 * Returns the raw range proof bytes (may be empty if the input array is empty).
 * @param {string} witnesses_json
 * @returns {Uint8Array}
 */
export function generateExtendedBulletProof(witnesses_json) {
    const ptr0 = passStringToWasm0(witnesses_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.generateExtendedBulletProof(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Generate a new random Ristretto keypair.
 * Returns { secret_key: Uint8Array, public_key: Uint8Array }.
 * @returns {KeypairResult}
 */
export function generateKeypair() {
    const ret = wasm.generateKeypair();
    return KeypairResult.__wrap(ret);
}

/**
 * Generate an Ootle address (bech32m string) from public keys.
 *
 * `network` is the network byte (0x00 = MainNet, 0x10 = LocalNet, 0x26 = Esmeralda, etc.).
 * `memo` is an optional pay reference (max 64 bytes).
 * @param {Uint8Array} owner_public_key
 * @param {Uint8Array} view_public_key
 * @param {number} network
 * @param {Uint8Array | null} [memo]
 * @returns {string}
 */
export function generateOotleAddress(owner_public_key, view_public_key, network, memo) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passArray8ToWasm0(owner_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(view_public_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(memo) ? 0 : passArray8ToWasm0(memo, wasm.__wbindgen_malloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.generateOotleAddress(ptr0, len0, ptr1, len1, network, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Generate a new random pair of Ootle secret keys (owner + view).
 * Returns { owner_key: Uint8Array, view_key: Uint8Array }.
 * @returns {OotleSecretKey}
 */
export function generateOotleSecretKey() {
    const ret = wasm.generateOotleSecretKey();
    return OotleSecretKey.__wrap(ret);
}

/**
 * Sign the balance proof for a stealth transfer.
 *
 * `aggregated_input_mask` and `aggregated_output_mask` are the 32-byte sums of all input / output
 * commitment masks respectively. Returns a `(public_nonce, signature)` pair (each 32 bytes); the pair
 * may be all-zeros for revealed-only transfers — callers normally omit the balance proof in that case.
 * @param {Uint8Array} aggregated_input_mask
 * @param {Uint8Array} aggregated_output_mask
 * @param {string} inputs_statement_json
 * @param {string} outputs_statement_json
 * @returns {SchnorrSignatureResult}
 */
export function generateStealthBalanceProofSignature(aggregated_input_mask, aggregated_output_mask, inputs_statement_json, outputs_statement_json) {
    const ptr0 = passArray8ToWasm0(aggregated_input_mask, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(aggregated_output_mask, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(inputs_statement_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(outputs_statement_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.generateStealthBalanceProofSignature(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return SchnorrSignatureResult.__wrap(ret[0]);
}

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
 * @param {string} witnesses_json
 * @param {bigint} revealed_output_amount_microtari
 * @returns {StealthOutputsResult}
 */
export function generateStealthOutputsStatement(witnesses_json, revealed_output_amount_microtari) {
    const ptr0 = passStringToWasm0(witnesses_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.generateStealthOutputsStatement(ptr0, len0, revealed_output_amount_microtari);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return StealthOutputsResult.__wrap(ret[0]);
}

/**
 * Hash an UnsignedTransactionV1 (JSON string) for signing.
 * Returns the 64-byte signing message that must be Schnorr-signed.
 *
 * `seal_signer_public_key` is the raw bytes of the seal signer's public key (account owner).
 * @param {string} unsigned_tx_json
 * @param {Uint8Array} seal_signer_public_key
 * @returns {Uint8Array}
 */
export function hashUnsignedTransaction(unsigned_tx_json, seal_signer_public_key) {
    const ptr0 = passStringToWasm0(unsigned_tx_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(seal_signer_public_key, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.hashUnsignedTransaction(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Called automatically when the WASM module is instantiated. Do not call directly.
 */
export function on_start() {
    wasm.on_start();
}

/**
 * Derive the Ootle public keys from a pair of secret keys.
 * Returns { owner_key: Uint8Array, view_key: Uint8Array }.
 * @param {Uint8Array} owner_key
 * @param {Uint8Array} view_key
 * @returns {OotlePublicKey}
 */
export function ootlePublicKeyFromSecretKey(owner_key, view_key) {
    const ptr0 = passArray8ToWasm0(owner_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(view_key, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.ootlePublicKeyFromSecretKey(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return OotlePublicKey.__wrap(ret[0]);
}

/**
 * Parse a bech32m Ootle address string into its components.
 * Returns { owner_key: Uint8Array, view_key: Uint8Array, network: number, memo: Uint8Array | undefined }.
 * @param {string} address
 * @returns {ParsedOotleAddress}
 */
export function parseOotleAddress(address) {
    const ptr0 = passStringToWasm0(address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.parseOotleAddress(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ParsedOotleAddress.__wrap(ret[0]);
}

/**
 * Derive the public key from a secret key (both raw bytes).
 * @param {Uint8Array} secret_key
 * @returns {Uint8Array}
 */
export function publicKeyFromSecretKey(secret_key) {
    const ptr0 = passArray8ToWasm0(secret_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.publicKeyFromSecretKey(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Schnorr-sign a message with a secret key.
 * Returns { public_nonce: Uint8Array, signature: Uint8Array }.
 * @param {Uint8Array} secret_key
 * @param {Uint8Array} message
 * @returns {SchnorrSignatureResult}
 */
export function schnorrSign(secret_key, message) {
    const ptr0 = passArray8ToWasm0(secret_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.schnorrSign(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return SchnorrSignatureResult.__wrap(ret[0]);
}

/**
 * Seal a transaction (unsigned or unsealed JSON) with the seal signer's secret key.
 *
 * Accepts either an `UnsignedTransactionV1` or `UnsealedTransactionV1` JSON string.
 * Returns the sealed `Transaction` as a JSON string.
 * @param {string} tx_json
 * @param {Uint8Array} seal_signer_secret_key
 * @returns {string}
 */
export function sealTransaction(tx_json, seal_signer_secret_key) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(tx_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(seal_signer_secret_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.sealTransaction(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Derive the recipient's stealth spending scalar `c + k`, where `c = H(network || k.G * r)`. The
 * receiver runs this with their account secret key (`private_key`) and the sender-provided public
 * nonce to obtain the one-time secret that controls the stealth output.
 *
 * `network` is the network byte (0x00 = MainNet, 0x10 = LocalNet, 0x26 = Esmeralda, ...).
 * @param {number} network
 * @param {Uint8Array} private_key
 * @param {Uint8Array} public_nonce
 * @returns {Uint8Array}
 */
export function stealthDhSecret(network, private_key, public_nonce) {
    const ptr0 = passArray8ToWasm0(private_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(public_nonce, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.stealthDhSecret(network, ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

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
 * @param {Uint8Array} output_commitment
 * @param {Uint8Array} encrypted_data
 * @param {Uint8Array} encryption_key
 * @param {boolean} skip_memo
 * @returns {DecryptedOutputResult}
 */
export function unblindOutput(output_commitment, encrypted_data, encryption_key, skip_memo) {
    const ptr0 = passArray8ToWasm0(output_commitment, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(encrypted_data, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(encryption_key, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.unblindOutput(ptr0, len0, ptr1, len1, ptr2, len2, skip_memo);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return DecryptedOutputResult.__wrap(ret[0]);
}

/**
 * Pre-flight check that a balance proof signature is cryptographically valid for the given input /
 * output statements. Returns `false` on a malformed proof or invalid signature; the engine performs
 * the authoritative check at submission.
 * @param {Uint8Array} public_nonce
 * @param {Uint8Array} signature
 * @param {string} inputs_statement_json
 * @param {string} outputs_statement_json
 * @returns {boolean}
 */
export function validateBalanceProofSignature(public_nonce, signature, inputs_statement_json, outputs_statement_json) {
    const ptr0 = passArray8ToWasm0(public_nonce, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(signature, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(inputs_statement_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(outputs_statement_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.validateBalanceProofSignature(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * Run the same validation the engine performs on a complete `StealthTransferStatement` envelope:
 * structural sanity, commitment well-formedness, range and balance-proof verification.
 *
 * `view_key` is the 32-byte resource view public key, required for resources with a viewable balance
 * and rejected otherwise. Pass `null` for resources without a view key.
 *
 * Throws on a validation failure; returns successfully on a valid statement.
 * @param {string} transfer_json
 * @param {Uint8Array | null} [view_key]
 */
export function validateStealthTransfer(transfer_json, view_key) {
    const ptr0 = passStringToWasm0(transfer_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(view_key) ? 0 : passArray8ToWasm0(view_key, wasm.__wbindgen_malloc);
    var len1 = WASM_VECTOR_LEN;
    const ret = wasm.validateStealthTransfer(ptr0, len0, ptr1, len1);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}
export function __wbg_Error_8c4e43fe74559d73(arg0, arg1) {
    const ret = Error(getStringFromWasm0(arg0, arg1));
    return ret;
}
export function __wbg___wbindgen_throw_be289d5034ed271b(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
}
export function __wbg_getRandomValues_e9de607763a970bd() { return handleError(function (arg0, arg1) {
    globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
}, arguments); }
export function __wbindgen_init_externref_table() {
    const table = wasm.__wbindgen_externrefs;
    const offset = table.grow(4);
    table.set(0, undefined);
    table.set(offset + 0, undefined);
    table.set(offset + 1, null);
    table.set(offset + 2, true);
    table.set(offset + 3, false);
}
const DecryptedOutputResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_decryptedoutputresult_free(ptr >>> 0, 1));
const KeypairResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_keypairresult_free(ptr >>> 0, 1));
const OotlePublicKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_ootlepublickey_free(ptr >>> 0, 1));
const OotleSecretKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_ootlesecretkey_free(ptr >>> 0, 1));
const ParsedOotleAddressFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_parsedootleaddress_free(ptr >>> 0, 1));
const SchnorrSignatureResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_schnorrsignatureresult_free(ptr >>> 0, 1));
const StealthOutputsResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_stealthoutputsresult_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;


let wasm;
export function __wbg_set_wasm(val) {
    wasm = val;
}
