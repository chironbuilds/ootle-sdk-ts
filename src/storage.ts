// The persistence surface `wallet.ts` (the account core) needs, backed by whatever key-value store
// the host application supplies -- a Chrome extension has `chrome.storage.local`, a web page has
// `localStorage`, a future host might have something else again. This module never touches a
// concrete storage API directly; it reads and writes through `KeyValueStore`, configured once via
// `configureOotleStorage()` before any `OotleAccount` method that touches storage is called.
//
// Deliberately narrow: this is exactly what the account core itself needs (shielded outputs,
// pending shields, the private-payment scan cursor, the known-substate-versions cache) -- not
// address books, connected-site permissions, daemon connections, or a full transaction-history UI.
// Those are application concerns with very different shapes across hosts, and belong in each
// consuming app's own storage layer, not in this SDK.

export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T): Promise<void>;
  remove(key: string): Promise<void>;
}

let configuredStore: KeyValueStore | null = null;

/** Call once, before any storage-touching `OotleAccount` method, with an adapter over whatever
 * this host's real storage is (see `adapters.ts` for ready-made ones). */
export function configureOotleStorage(store: KeyValueStore): void {
  configuredStore = store;
}

function store(): KeyValueStore {
  if (!configuredStore) {
    throw new Error(
      "Ootle SDK storage has not been configured. Call configureOotleStorage(store) once at startup " +
        "with a KeyValueStore for this host (see adapters.ts).",
    );
  }
  return configuredStore;
}

const STORAGE_KEY = "ootle-sdk/v1";

export interface ShieldedOutputRecord {
  accountId: string;
  resourceAddress: string;
  /** 32-byte Pedersen commitment, hex. */
  commitment: string;
  /** Raw, resource-native units (matches TokenBalance.amount's convention). */
  amount: string;
  transactionId: string;
  createdAt: number;
  /** Set true once this output has been spent via unshield. */
  spent: boolean;
  /** The output's plaintext memo, if any. Absent, not empty-string, when it carries none. */
  memo?: string;
}

/**
 * A shield or unshield submitted but not yet recorded in `shieldedOutputs` — carries every field
 * needed to complete the write on recovery, since a reload between finalization and the storage
 * write would otherwise strand the only lead to a real commitment.
 */
export interface PendingShield {
  transactionId: string;
  accountId: string;
  resourceAddress: string;
  amount: string;
  /** For an unshield or private send: the now-spent commitments to mark on recovery. */
  spentCommitments?: string[];
  /** This account's own new commitment, when the operation creates one. */
  ownCommitment?: string;
  /** This account's own memo for the operation, if any. */
  memo?: string;
}

/**
 * Lifecycle of one HTLC operation, persisted *before* anything is submitted so a crash, a killed
 * service worker or a confirmation timeout can never strand the only copy of what's needed to
 * finish it (see `HtlcJournalEntry`):
 *
 * - `prepared`   the sealed envelope and every recovery field are stored; not yet submitted
 * - `claim_armed` (claims only) the funded output passed every pre-claim check and a dry run; the
 *                next step reveals the preimage on-chain
 * - `submitted`  the network accepted the envelope for processing; outcome not yet known
 * - `unknown`    submitted (or possibly submitted) but no final result arrived in time — resolved by
 *                `OotleAccount.reconcileHtlcs()`, never assumed to have failed
 * - `confirmed`  finalized and accepted; local bookkeeping done
 * - `failed`     definitively rejected; nothing happened on-chain beyond (possibly) the fee
 */
export type HtlcJournalStatus = "prepared" | "claim_armed" | "submitted" | "unknown" | "confirmed" | "failed";

export interface HtlcJournalEntry {
  /** Local id, stable across retries of the same operation. */
  id: string;
  accountId: string;
  kind: "fund" | "claim" | "refund";
  status: HtlcJournalStatus;
  resourceAddress: string;
  /** Raw units. For a fund: the HTLC amount. For a claim/refund: the amount moving to this account. */
  amount: string;
  /** The exact two-leaf `[claim, refund]` condition tree — needed by both sides, never recomputable
   * by the counterparty from on-chain data alone (only its root is committed). */
  conditions: object[];
  hashLockHex: string;
  refundEpoch: string;
  /** The HTLC output's commitment (hex): created by a fund, spent by a claim/refund. */
  htlcCommitment?: string;
  /** Fund only: the HTLC output's blinding mask. The funder can't decrypt an output addressed to the
   * claimant, so without this a refund is impossible — which is why it is written here before submit. */
  outputMask?: string;
  /** This account's own new stealth output from the operation (a fund's change, a claim/refund's
   * received output), recorded in the shielded ledger once the operation confirms. */
  ownCommitment?: string;
  ownAmount?: string;
  /** Stealth inputs this operation spends (fund-from-stealth), marked spent once it confirms. */
  spentCommitments?: string[];
  /** Private-fee bookkeeping, applied once the operation confirms. */
  privateFee?: { feeResourceAddress: string; spentCommitment: string; changeCommitment: string; changeAmount: string };
  /** The sealed transaction exactly as submitted — lets reconciliation resubmit the identical
   * transaction (same id, so it can never execute twice) if the first submit never reached the
   * network. For a claim this contains the preimage, so it is only ever resubmitted, never shown. */
  envelope: string;
  transactionId?: string;
  error?: string;
  createdAt: number;
  updatedAt: number;
}

/** A stealth commitment held by an in-flight operation, so a concurrent one can't select it too. */
export interface CommitmentReservation {
  accountId: string;
  commitment: string;
  /** Who holds it — an operation id; the same holder may re-reserve idempotently. */
  holder: string;
  /** Epoch ms after which the reservation lapses on its own (a crashed operation can never lock a
   * UTXO forever). */
  expiresAt: number;
}

interface OotleState {
  shieldedOutputs: ShieldedOutputRecord[];
  pendingShields: PendingShield[];
  privatePaymentScanCursors: Record<string, string>;
  /** Substate versions already seen, so a resubmission does not re-lock a stale version. */
  knownVersions: Record<string, number>;
  htlcJournal: HtlcJournalEntry[];
  reservations: CommitmentReservation[];
}

const DEFAULTS: OotleState = {
  shieldedOutputs: [],
  pendingShields: [],
  privatePaymentScanCursors: {},
  knownVersions: {},
  htlcJournal: [],
  reservations: [],
};

export function localAccountId(index: number): string {
  return `local:${index}`;
}

async function read(): Promise<OotleState> {
  const raw = await store().get<Partial<OotleState>>(STORAGE_KEY);
  return { ...DEFAULTS, ...raw };
}

async function write(patch: Partial<OotleState>): Promise<void> {
  await store().set(STORAGE_KEY, { ...(await read()), ...patch });
}

let writeQueue: Promise<unknown> = Promise.resolve();

// >0 while a callback passed to `serialized()` is actually running (including across its own
// `await`s) -- lets a call from *inside* that callback detect it's nested and run immediately
// instead of queuing behind a queue slot that can only advance once it finishes, which is a
// deadlock (confirmed empirically: wallet.ts's recordKnownVersions() used to wrap a call to
// setKnownVersions() -- which serializes its own write -- in its own serialized() block; the
// inner call waited for the outer call's queue slot to free up, which was itself awaiting the
// inner call). Safe for genuinely concurrent (non-nested) callers: `depth` is only ever
// incremented inside the deferred callback below, never at the synchronous call site, so two
// unrelated top-level `serialized()` calls dispatched back-to-back both see `depth === 0` and
// queue normally regardless of how their execution ends up overlapping in time -- this only ever
// fires for a call genuinely reachable from within an already-running callback's own call graph.
let depth = 0;

/** Runs a whole read-modify-write cycle to completion before the next one starts, so two
 * concurrent callers (two tabs, a page request racing a popup request) can't interleave their
 * read-modify-write on this key and silently clobber each other's write.
 *
 * Never nest a call to this (or to another function that itself calls this, like every setter in
 * this file) inside a `serialized()` callback if you can avoid it -- the fallback above keeps it
 * from deadlocking, but the nested call then runs *outside* the ordering guarantee this exists to
 * provide. */
export function serialized<T>(fn: () => Promise<T>): Promise<T> {
  if (depth > 0) return fn();
  const run = async () => {
    depth++;
    try {
      return await fn();
    } finally {
      depth--;
    }
  };
  const result = writeQueue.then(run, run);
  writeQueue = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

export async function listShieldedOutputs(accountId: string): Promise<ShieldedOutputRecord[]> {
  return (await read()).shieldedOutputs.filter((r) => r.accountId === accountId);
}

/** Idempotent: a commitment already recorded for the same account is left as it is, so a
 * reconciliation that re-applies a finished operation's bookkeeping can never double-count it. */
export async function addShieldedOutput(record: ShieldedOutputRecord): Promise<void> {
  await serialized(async () => {
    const existing = (await read()).shieldedOutputs;
    if (existing.some((r) => r.accountId === record.accountId && r.commitment === record.commitment)) return;
    await write({ shieldedOutputs: [...existing, record] });
  });
}

export async function markShieldedOutputSpent(accountId: string, commitment: string): Promise<void> {
  await serialized(async () => {
    const state = await read();
    await write({
      shieldedOutputs: state.shieldedOutputs.map((r) =>
        r.accountId === accountId && r.commitment === commitment ? { ...r, spent: true } : r,
      ),
    });
  });
}

export async function listPendingShields(): Promise<PendingShield[]> {
  return (await read()).pendingShields;
}

export async function addPendingShield(pending: PendingShield): Promise<void> {
  await serialized(async () => {
    const state = await read();
    if (state.pendingShields.some((p) => p.transactionId === pending.transactionId)) return;
    await write({ pendingShields: [...state.pendingShields, pending] });
  });
}

export async function removePendingShield(transactionId: string): Promise<void> {
  await serialized(async () => {
    const state = await read();
    await write({ pendingShields: state.pendingShields.filter((p) => p.transactionId !== transactionId) });
  });
}

export async function getPrivatePaymentScanCursor(accountId: string): Promise<string | null> {
  return (await read()).privatePaymentScanCursors[accountId] ?? null;
}

export async function setPrivatePaymentScanCursor(accountId: string, transactionId: string): Promise<void> {
  await serialized(async () => {
    const state = await read();
    await write({ privatePaymentScanCursors: { ...state.privatePaymentScanCursors, [accountId]: transactionId } });
  });
}

/** Substate version cache -- see `wallet.ts`'s own doc comment on `knownVersionsPromise` for why
 * this exists at all. */
export async function getKnownVersions(): Promise<Record<string, number>> {
  return (await read()).knownVersions;
}

export async function setKnownVersions(known: Record<string, number>): Promise<void> {
  await serialized(async () => {
    await write({ knownVersions: known });
  });
}

// ── HTLC journal ─────────────────────────────────────────────────────────────────────────────

export async function listHtlcJournal(accountId?: string): Promise<HtlcJournalEntry[]> {
  const all = (await read()).htlcJournal;
  return accountId ? all.filter((e) => e.accountId === accountId) : all;
}

export async function getHtlcJournalEntry(id: string): Promise<HtlcJournalEntry | undefined> {
  return (await read()).htlcJournal.find((e) => e.id === id);
}

/** Inserts or replaces (by id) — idempotent, so retrying the same write is always safe. */
export async function putHtlcJournalEntry(entry: HtlcJournalEntry): Promise<void> {
  await serialized(async () => {
    const state = await read();
    await write({ htlcJournal: [...state.htlcJournal.filter((e) => e.id !== entry.id), entry] });
  });
}

/** Applies `patch` to an existing entry and bumps `updatedAt`. A missing id is a no-op. */
export async function updateHtlcJournalEntry(id: string, patch: Partial<HtlcJournalEntry>): Promise<HtlcJournalEntry | undefined> {
  return serialized(async () => {
    const state = await read();
    const current = state.htlcJournal.find((e) => e.id === id);
    if (!current) return undefined;
    const next = { ...current, ...patch, id, updatedAt: Date.now() };
    await write({ htlcJournal: state.htlcJournal.map((e) => (e.id === id ? next : e)) });
    return next;
  });
}

// ── commitment reservations ──────────────────────────────────────────────────────────────────

/** Default lifetime of a reservation: long enough for any single operation (prepare + dry run +
 * submit + confirmation), short enough that a crashed one frees its UTXOs within minutes. */
export const RESERVATION_TTL_MS = 10 * 60_000;

/** Commitments currently reserved for `accountId` by anyone other than `exceptHolder`. */
export async function listReservedCommitments(accountId: string, exceptHolder?: string, now = Date.now()): Promise<Set<string>> {
  return new Set(
    (await read()).reservations
      .filter((r) => r.accountId === accountId && r.expiresAt > now && r.holder !== exceptHolder)
      .map((r) => r.commitment),
  );
}

/**
 * Atomically reserves every commitment in `commitments` for `holder`, or none of them: if any is
 * already held (unexpired) by a different holder, throws `CommitmentReservedError` naming them and
 * writes nothing. Re-reserving one's own commitments just extends the lease. Expired leases are
 * swept on every call.
 */
export async function reserveCommitments(
  accountId: string,
  commitments: string[],
  holder: string,
  ttlMs = RESERVATION_TTL_MS,
): Promise<void> {
  if (commitments.length === 0) return;
  await serialized(async () => {
    const now = Date.now();
    const state = await read();
    const live = state.reservations.filter((r) => r.expiresAt > now);
    const taken = commitments.filter((c) => live.some((r) => r.accountId === accountId && r.commitment === c && r.holder !== holder));
    if (taken.length > 0) throw new CommitmentReservedError(taken);
    const wanted = new Set(commitments);
    const kept = live.filter((r) => !(r.accountId === accountId && wanted.has(r.commitment)));
    const expiresAt = now + ttlMs;
    await write({ reservations: [...kept, ...commitments.map((commitment) => ({ accountId, commitment, holder, expiresAt }))] });
  });
}

/** Releases every reservation `holder` holds (all accounts). Safe to call more than once. */
export async function releaseReservations(holder: string): Promise<void> {
  await serialized(async () => {
    const now = Date.now();
    const state = await read();
    await write({ reservations: state.reservations.filter((r) => r.holder !== holder && r.expiresAt > now) });
  });
}

export class CommitmentReservedError extends Error {
  constructor(public readonly commitments: string[]) {
    super(
      `${commitments.length === 1 ? "A private output this operation needs is" : "Private outputs this operation needs are"} ` +
        `already in use by another operation in progress (${commitments.map((c) => c.slice(0, 12)).join(", ")}). ` +
        "Wait for it to finish, then try again.",
    );
    this.name = "CommitmentReservedError";
  }
}

/** Clears every key this module owns -- call this from a host's own "erase wallet" flow. Does not
 * touch anything else the host's `KeyValueStore` might hold (address books, settings, ...); this
 * SDK never wrote those keys, so it isn't this function's place to remove them. */
export async function wipeOotleState(): Promise<void> {
  await serialized(async () => {
    await store().remove(STORAGE_KEY);
  });
}
