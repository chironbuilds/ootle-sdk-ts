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

interface OotleState {
  shieldedOutputs: ShieldedOutputRecord[];
  pendingShields: PendingShield[];
  privatePaymentScanCursors: Record<string, string>;
  /** Substate versions already seen, so a resubmission does not re-lock a stale version. */
  knownVersions: Record<string, number>;
}

const DEFAULTS: OotleState = {
  shieldedOutputs: [],
  pendingShields: [],
  privatePaymentScanCursors: {},
  knownVersions: {},
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

/** Runs a whole read-modify-write cycle to completion before the next one starts, so two
 * concurrent callers (two tabs, a page request racing a popup request) can't interleave their
 * read-modify-write on this key and silently clobber each other's write. */
export function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const result = writeQueue.then(fn, fn);
  writeQueue = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

export async function listShieldedOutputs(accountId: string): Promise<ShieldedOutputRecord[]> {
  return (await read()).shieldedOutputs.filter((r) => r.accountId === accountId);
}

export async function addShieldedOutput(record: ShieldedOutputRecord): Promise<void> {
  await serialized(async () => {
    write({ shieldedOutputs: [...(await read()).shieldedOutputs, record] });
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

/** Clears every key this module owns -- call this from a host's own "erase wallet" flow. Does not
 * touch anything else the host's `KeyValueStore` might hold (address books, settings, ...); this
 * SDK never wrote those keys, so it isn't this function's place to remove them. */
export async function wipeOotleState(): Promise<void> {
  await serialized(async () => {
    await store().remove(STORAGE_KEY);
  });
}
