// Scan the live UTXO set for stealth outputs owned by this account's view key.
//
// Two complementary strategies:
//
//   scanUtxosDelta  — incremental, checkpoint-based (POST /utxos/stream).  Given the watermarks
//                     saved from the last call, returns only new/spent outputs since then.  Pass
//                     empty watermarks for the first call; the indexer will replay the full set.
//                     Also handles `Spent` / `Burnt` updates so the caller can mark old outputs
//                     as spent without polling individual substates.
//
//   scanUtxosPage   — paginated full scan (GET /utxos).  Fetches one page of the current UTXO
//                     set ordered by commitment id.  Use the returned `nextCursor` for the next
//                     call.  Useful for first-time imports or recovery when the watermarks are lost.
//
// The two share the same decryption helper.  `ScannedStealthOutput` (defined in confidential.ts)
// is the output type passed to `addShieldedOutput` in storage.ts.

import { decryptInputData, type StealthCryptoProvider } from "@tari-project/ootle";
import type { Shard, StateVersion, UtxoId, UtxoTag, WalletUtxoUpdate, Utxo } from "@tari-project/ootle-ts-bindings";

import { fromHex } from "./vault.js";
import type { ScannedStealthOutput } from "./confidential.js";

// ── wire types for the two REST endpoints ────────────────────────────────────────────────────────
// These mirror the Rust types exactly; they are not exported from @tari-project/ootle-ts-bindings.

interface GetUtxoUpdatesRequest {
  resource_address: string;
  shard_state_versions: Array<[Shard, StateVersion]>;
  unspent_only: boolean;
  per_shard_limit: number;
  from_epoch?: number;
}

interface GetUtxoUpdatesResponse {
  shard_updates: Record<string, { updates: WalletUtxoUpdate[]; max_state_version: StateVersion; max_epoch: number; has_more: boolean }>;
  per_shard_high_watermark: Array<[Shard, StateVersion]>;
}

interface GetUtxosRequest {
  resource_address: string;
  tag_and_nonce_pairs: Array<[UtxoTag, string]>;
}

interface GetUtxosResponse {
  utxos: Array<[UtxoId, Utxo]>;
}

interface ListUtxosRequest {
  resource_address: string;
  limit: number;
  from_id?: string;
}

interface ListUtxosResponse {
  utxos: Array<[UtxoId, Utxo]>;
}

// ── public types ──────────────────────────────────────────────────────────────────────────────────

/** Checkpoint for one resource's delta scan: a `[Shard, StateVersion]` pair per shard read so far.
 * Serialize as JSON; pass back verbatim as `shard_state_versions` on the next call. */
export type UtxoScanWatermark = Array<[Shard, StateVersion]>;

/** Result of a delta scan (`scanUtxosDelta`). */
export interface UtxosDeltaResult {
  /** Outputs we decrypted as ours. Pass each to `addShieldedOutput`. */
  owned: ScannedStealthOutput[];
  /** Commitments whose outputs were spent or burnt on-chain since the last scan.
   * Pass each to `markShieldedOutputSpent`. */
  spentCommitments: string[];
  /** Persist these with `setUtxoScanWatermarks` and pass on the next call. */
  watermarks: UtxoScanWatermark;
  /** True if at least one shard still has rows above the new watermark.
   * Call `scanUtxosDelta` again (with the returned `watermarks`) until this is false. */
  hasMore: boolean;
}

/** Result of one page of a full paginated scan (`scanUtxosPage`). */
export interface UtxosPageResult {
  /** Outputs we decrypted as ours. Pass each to `addShieldedOutput`. */
  owned: ScannedStealthOutput[];
  /** Cursor for the next page.  Save it with `setUtxoScanPageCursor` and pass as `fromId` on
   * the next call.  `null` means this was the last page. */
  nextCursor: string | null;
}

// ── helpers ───────────────────────────────────────────────────────────────────────────────────────

async function postJson<Req, Res>(baseUrl: string, path: string, body: Req): Promise<Res> {
  const url = baseUrl.replace(/\/$/, "") + "/" + path;
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`UTXO scan POST /${path} failed: ${resp.status} ${resp.statusText} — ${text}`);
  }
  return resp.json() as Promise<Res>;
}

async function getJson<Res>(baseUrl: string, path: string, params: Record<string, string | number | undefined>): Promise<Res> {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) qs.set(k, String(v));
  }
  const url = baseUrl.replace(/\/$/, "") + "/" + path + "?" + qs.toString();
  const resp = await fetch(url, { headers: { "Accept": "application/json" } });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`UTXO scan GET /${path} failed: ${resp.status} ${resp.statusText} — ${text}`);
  }
  return resp.json() as Promise<Res>;
}

/** Try to decrypt a UTXO output using the account's view key.
 * Returns a ScannedStealthOutput on success, null if the output doesn't belong to this key. */
async function tryDecryptUtxo(
  crypto: StealthCryptoProvider,
  viewSecret: Uint8Array,
  resourceAddress: string,
  utxoId: UtxoId,
  utxo: Utxo,
): Promise<ScannedStealthOutput | null> {
  if (!utxo.output) return null;
  const body = utxo.output.output;
  try {
    const { value, memo } = await decryptInputData(crypto, fromHex(utxoId), fromHex(body.encrypted_data), {
      senderPublicNonce: fromHex(body.public_nonce),
      viewSecret,
      skipMemo: false,
    });
    return {
      resourceAddress,
      commitment: utxoId,
      amount: value,
      transactionId: "",
      memo,
    };
  } catch {
    return null;
  }
}

// ── incremental delta scan ───────────────────────────────────────────────────────────────────────

/**
 * Fetches all UTXO updates (new outputs + spends) since the given watermarks from the indexer's
 * streaming endpoint, then decrypts any `Unspent` candidates with the account's view key.
 *
 * Pass `watermarks: []` (or the saved value from storage) on every call.  The very first call
 * with an empty watermarks array replays everything the indexer has retained, so it doubles as the
 * initial full scan.  Subsequent calls with the returned watermarks fetch only the delta.
 *
 * Call in a loop until `result.hasMore` is false:
 * ```ts
 * let wm = await getUtxoScanWatermarks(accountId, resourceAddress);
 * do {
 *   const r = await scanUtxosDelta(indexerUrl, resourceAddress, crypto, viewSecret, wm, 200);
 *   for (const o of r.owned)            await addShieldedOutput({ ...o, accountId, ... });
 *   for (const c of r.spentCommitments) await markShieldedOutputSpent(accountId, c);
 *   wm = r.watermarks;
 *   await setUtxoScanWatermarks(accountId, resourceAddress, wm);
 * } while (r.hasMore);
 * ```
 */
export async function scanUtxosDelta(
  indexerBaseUrl: string,
  resourceAddress: string,
  crypto: StealthCryptoProvider,
  viewSecret: Uint8Array,
  watermarks: UtxoScanWatermark,
  perShardLimit = 200,
): Promise<UtxosDeltaResult> {
  const req: GetUtxoUpdatesRequest = {
    resource_address: resourceAddress,
    shard_state_versions: watermarks,
    unspent_only: false,
    per_shard_limit: perShardLimit,
  };

  const updateSet = await postJson<GetUtxoUpdatesRequest, GetUtxoUpdatesResponse>(
    indexerBaseUrl, "utxos/stream", req,
  );

  // Collect spend updates and candidate (tag, nonce) pairs for new outputs
  const spentCommitments: string[] = [];
  const candidates: Array<[UtxoTag, string]> = [];

  for (const shardUpdates of Object.values(updateSet.shard_updates)) {
    for (const update of shardUpdates.updates) {
      if ("Spent" in update) {
        spentCommitments.push(update.Spent.id);
      } else if ("Burnt" in update) {
        spentCommitments.push(update.Burnt.id);
      } else if ("Unspent" in update) {
        candidates.push([update.Unspent.tag, update.Unspent.public_nonce]);
      }
    }
  }

  // Batch-fetch full UTXO bodies for all candidates, then decrypt
  const owned: ScannedStealthOutput[] = [];
  if (candidates.length > 0) {
    const fetchResp = await postJson<GetUtxosRequest, GetUtxosResponse>(
      indexerBaseUrl, "utxos/fetch",
      { resource_address: resourceAddress, tag_and_nonce_pairs: candidates },
    );
    for (const [utxoId, utxo] of fetchResp.utxos) {
      const result = await tryDecryptUtxo(crypto, viewSecret, resourceAddress, utxoId, utxo);
      if (result) owned.push(result);
    }
  }

  const hasMore = Object.values(updateSet.shard_updates).some((s) => s.has_more);

  return {
    owned,
    spentCommitments,
    watermarks: updateSet.per_shard_high_watermark,
    hasMore,
  };
}

// ── full paginated scan ───────────────────────────────────────────────────────────────────────────

/**
 * Fetches one page of the live UTXO set for a resource and tries to decrypt each output.
 *
 * Use this when the watermarks are lost or a full re-scan is needed.  The `fromId` cursor is the
 * `UtxoId` (32-byte commitment hex) of the last output seen on the previous page.
 *
 * Call in a loop until `result.nextCursor` is null:
 * ```ts
 * let cursor = await getUtxoScanPageCursor(accountId, resourceAddress);
 * do {
 *   const r = await scanUtxosPage(indexerUrl, resourceAddress, crypto, viewSecret, cursor);
 *   for (const o of r.owned) await addShieldedOutput({ ...o, accountId, ... });
 *   cursor = r.nextCursor;
 *   if (cursor) await setUtxoScanPageCursor(accountId, resourceAddress, cursor);
 * } while (cursor !== null);
 * await clearUtxoScanPageCursor(accountId, resourceAddress);
 * ```
 */
export async function scanUtxosPage(
  indexerBaseUrl: string,
  resourceAddress: string,
  crypto: StealthCryptoProvider,
  viewSecret: Uint8Array,
  fromId: string | null = null,
  pageSize = 100,
): Promise<UtxosPageResult> {
  const resp = await getJson<ListUtxosResponse>(indexerBaseUrl, "utxos", {
    resource_address: resourceAddress,
    limit: pageSize,
    from_id: fromId ?? undefined,
  });

  const owned: ScannedStealthOutput[] = [];
  let lastId: string | null = null;

  for (const [utxoId, utxo] of resp.utxos) {
    lastId = utxoId;
    const result = await tryDecryptUtxo(crypto, viewSecret, resourceAddress, utxoId, utxo);
    if (result) owned.push(result);
  }

  // If the page was full there may be more; if it was shorter than pageSize, we're done
  const nextCursor = resp.utxos.length >= pageSize ? lastId : null;

  return { owned, nextCursor };
}
