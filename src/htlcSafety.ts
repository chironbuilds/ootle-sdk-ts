// Settlement-safety helpers for HTLCs: the epoch rules, condition-root checks, pre-claim term
// verification and outcome classification that `OotleAccount`'s HTLC methods (and any swap
// protocol built on them) rely on. Everything here is pure or wasm-only — no provider, no storage —
// so every rule is unit-testable on its own (htlcSafety.test.ts).
import { buildScriptPathWitness, encryptedDataDhKdfAead, unblindOutput } from "@tari-project/ootle-wasm";
import { htlcConditions } from "./htlc.js";
import { fromHex, toHex } from "./vault.js";

// ── epoch rules (must match the engine's AfterEpoch / BeforeEpoch atoms exactly) ──────────────

/** The refund leaf is `AfterEpoch(refundEpoch)`: admissible when `currentEpoch >= refundEpoch`. */
export function isHtlcRefundable(currentEpoch: bigint, refundEpoch: bigint): boolean {
  return currentEpoch >= refundEpoch;
}

/** The claim leaf is `BeforeEpoch(refundEpoch)`: admissible only while `currentEpoch < refundEpoch`. */
export function isHtlcClaimableByEpoch(currentEpoch: bigint, refundEpoch: bigint): boolean {
  return currentEpoch < refundEpoch;
}

/** Epochs left in which a claim is still admissible (0 once the claim window has closed). */
export function epochsUntilRefund(currentEpoch: bigint, refundEpoch: bigint): bigint {
  return refundEpoch > currentEpoch ? refundEpoch - currentEpoch : 0n;
}

// ── condition roots ────────────────────────────────────────────────────────────────────────────

/**
 * The on-chain condition root of a `[claim, refund]` tree — what a `PayTo::Conditions` output
 * commits to (its `auth.Script`). Computed through the refund leaf, which consumes no witness data,
 * so no preimage is needed.
 */
export function conditionRootOf(conditions: object[]): string {
  const refundLeaf = conditions[1];
  if (!refundLeaf) throw new Error("conditionRootOf: expected the two-leaf [claim, refund] condition tree");
  const result = JSON.parse(buildScriptPathWitness(JSON.stringify(conditions), JSON.stringify(refundLeaf), new Uint8Array(0))) as { condition_root?: string };
  if (typeof result.condition_root !== "string") throw new Error("conditionRootOf: wasm returned no condition_root");
  return result.condition_root.toLowerCase();
}

/**
 * Finds the script-path condition root committed by an on-chain UTXO body — the `Script` variant of
 * its spend authorization. Searched structurally (a `Script` key holding 32 bytes of hex) rather
 * than by a fixed path, so an indexer-side field rename can't turn "is this our HTLC?" into a
 * silent pass: a body with no such field returns `null`, which every caller treats as a mismatch.
 */
export function findScriptRoot(body: unknown, depth = 0): string | null {
  if (depth > 8 || body === null || typeof body !== "object") return null;
  for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
    if (key === "Script" && typeof value === "string" && /^[0-9a-f]{64}$/i.test(value)) return value.toLowerCase();
    const nested = findScriptRoot(value, depth + 1);
    if (nested) return nested;
  }
  return null;
}

// ── pre-claim verification ──────────────────────────────────────────────────────────────────

/** What the claimant's side of the swap agreed to — checked against the chain before the preimage
 * is ever revealed. Omit a field to skip that particular check. */
export interface HtlcExpectations {
  /** Exact amount expected (raw units). */
  amount?: bigint;
  /** Minimum acceptable amount, when an exact figure isn't agreed. */
  minAmount?: bigint;
  hashLockHex?: string;
  refundEpoch?: bigint;
  /** The counterparty (funder) who may refund — checked by rebuilding the tree from expectations. */
  refunderPublicKeyHex?: string;
  /** Refuse to claim with fewer than this many claim-admissible epochs left, so the claim can't be
   * racing the refund window. Default 1 (the claim must land strictly before `refundEpoch`). */
  minEpochsBeforeRefund?: bigint;
}

export interface HtlcFacts {
  /** Decrypted value of the funded output (null when it didn't decrypt as ours). */
  value: bigint | null;
  /** Condition root the on-chain output actually commits to (null when absent/unreadable). */
  onChainRoot: string | null;
  /** The condition tree the claimant was handed. */
  conditions: object[];
  /** This account's own owner public key — must be the claim leaf's key. */
  claimantPublicKeyHex: string;
  currentEpoch: bigint;
  /** When a preimage is supplied, SHA-256(preimage) must equal the tree's hash lock. */
  preimageHashHex?: string;
}

/** Reads the hash lock and refund epoch back out of a `[claim, refund]` tree built by `htlcConditions`. */
export function describeHtlcConditions(conditions: object[]): { hashLockHex: string; refundEpoch: bigint } {
  const claim = conditions[0] as Array<{ Builtin?: { HashLock?: { hash: string }; BeforeEpoch?: number } }> | undefined;
  const hash = claim?.find((a) => a.Builtin?.HashLock)?.Builtin?.HashLock?.hash;
  const before = claim?.find((a) => a.Builtin?.BeforeEpoch !== undefined)?.Builtin?.BeforeEpoch;
  if (typeof hash !== "string" || typeof before !== "number") {
    throw new Error("Not an HTLC condition tree: the claim leaf has no HashLock/BeforeEpoch atoms.");
  }
  return { hashLockHex: hash.toLowerCase(), refundEpoch: BigInt(before) };
}

/**
 * Every reason the funded HTLC does not match what was agreed — empty means safe to reveal the
 * preimage. Checks, in order: the output decrypts as ours; its amount; the tree's shape (rebuilt
 * from `expected` + this account's key and compared byte-for-byte, which pins the claimant, the
 * refunder, the hash lock and the refund epoch at once); the on-chain root equals the tree's root
 * (so the tree we'd reveal is the one actually committed); the preimage hashes to the lock; and
 * enough claim-admissible epochs remain.
 */
export function verifyHtlcTerms(facts: HtlcFacts, expected: HtlcExpectations = {}): string[] {
  const problems: string[] = [];
  if (facts.value === null) problems.push("The funded output does not decrypt with this account's view key — it isn't addressed to you.");
  if (facts.value !== null && expected.amount !== undefined && facts.value !== expected.amount) {
    problems.push(`The funded amount is ${facts.value}, not the agreed ${expected.amount}.`);
  }
  if (facts.value !== null && expected.minAmount !== undefined && facts.value < expected.minAmount) {
    problems.push(`The funded amount ${facts.value} is below the agreed minimum ${expected.minAmount}.`);
  }

  let described: { hashLockHex: string; refundEpoch: bigint } | null = null;
  try {
    described = describeHtlcConditions(facts.conditions);
  } catch (e) {
    problems.push(e instanceof Error ? e.message : String(e));
  }
  if (described) {
    const hashLockHex = (expected.hashLockHex ?? described.hashLockHex).toLowerCase();
    const refundEpoch = expected.refundEpoch ?? described.refundEpoch;
    if (expected.hashLockHex !== undefined && expected.hashLockHex.toLowerCase() !== described.hashLockHex) {
      problems.push("The condition tree's hash lock is not the agreed one.");
    }
    if (expected.refundEpoch !== undefined && expected.refundEpoch !== described.refundEpoch) {
      problems.push(`The condition tree's refund epoch is ${described.refundEpoch}, not the agreed ${expected.refundEpoch}.`);
    }
    // Rebuild the tree the way a correct funder would have, and demand an exact match: this pins the
    // claim leaf to *our* key (nobody else can take the claim path) and, when known, the refund leaf
    // to the agreed counterparty.
    const refunder = expected.refunderPublicKeyHex ?? refunderKeyOf(facts.conditions);
    if (refunder) {
      try {
        const rebuilt = htlcConditions({ hashLockHex, refundEpoch, claimantPublicKeyHex: facts.claimantPublicKeyHex, refunderPublicKeyHex: refunder });
        if (JSON.stringify(rebuilt) !== JSON.stringify(facts.conditions)) {
          problems.push("The condition tree is not a standard HTLC paying you on the claim path (claimant key, refunder key, hash lock or epoch differ).");
        }
      } catch (e) {
        problems.push(e instanceof Error ? e.message : String(e));
      }
    }
    if (facts.preimageHashHex !== undefined && facts.preimageHashHex.toLowerCase() !== described.hashLockHex) {
      problems.push("The preimage does not hash to this HTLC's hash lock.");
    }
    const minLeft = expected.minEpochsBeforeRefund ?? 1n;
    const left = epochsUntilRefund(facts.currentEpoch, described.refundEpoch);
    if (left < minLeft) {
      problems.push(
        left === 0n
          ? `The claim window has closed (current epoch ${facts.currentEpoch} ≥ refund epoch ${described.refundEpoch}).`
          : `Only ${left} epoch(s) remain before the refund path opens; at least ${minLeft} required.`,
      );
    }
  }

  let treeRoot: string | null = null;
  try {
    treeRoot = conditionRootOf(facts.conditions);
  } catch (e) {
    problems.push(`The condition tree is malformed: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (treeRoot !== null && facts.onChainRoot !== treeRoot) {
    problems.push(
      facts.onChainRoot === null
        ? "The on-chain output is not script-locked (no condition root) — it is not this HTLC."
        : "The on-chain output commits to a different condition tree than the one you were given.",
    );
  }
  return problems;
}

/** The refund leaf's public key, read back from a tree built by `htlcConditions`. */
function refunderKeyOf(conditions: object[]): string | null {
  const refund = conditions[1] as Array<{ AccessRule?: unknown }> | undefined;
  const rule = refund?.find((a) => a.AccessRule)?.AccessRule as
    | { Restricted?: { Require?: { Require?: { NonFungibleAddress?: { id?: { U256?: string } } } } } }
    | undefined;
  return rule?.Restricted?.Require?.Require?.NonFungibleAddress?.id?.U256 ?? null;
}

export class HtlcVerificationError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Refusing to reveal the preimage — the funded HTLC doesn't match the agreed terms:\n- ${problems.join("\n- ")}`);
    this.name = "HtlcVerificationError";
  }
}

// ── outcome classification ────────────────────────────────────────────────────────────────────

/**
 * Whether an error from submitting/polling is a *definitive* rejection (the transaction will never
 * execute), as opposed to an ambiguous failure (timeout, network error, service worker killed)
 * after which the transaction may still land. Only a definitive rejection may be treated as
 * "nothing happened"; everything else must be reconciled, never assumed failed.
 */
export function isDefinitiveRejection(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : String(e);
  return /was rejected:|accepted the fee but rejected the rest/i.test(msg);
}

/**
 * Thrown (instead of a plain error) when an HTLC transaction was, or may have been, submitted but
 * its outcome didn't arrive in time. Carries everything the caller needs — including the refund
 * data — and the journal entry that `OotleAccount.reconcileHtlcs()` resolves later. Callers must
 * treat this as "pending", never as "failed".
 */
export class HtlcUnknownOutcomeError extends Error {
  constructor(
    public readonly journalId: string,
    public readonly details: {
      kind: "fund" | "claim" | "refund";
      transactionId?: string;
      conditions: object[];
      htlcCommitment?: string;
      outputMask?: string;
    },
    cause: unknown,
  ) {
    super(
      `The HTLC ${details.kind} was submitted but its outcome is not known yet (${cause instanceof Error ? cause.message : String(cause)}). ` +
        `It is recorded as journal entry ${journalId}; call reconcileHtlcs() to resolve it. Do not retry it as a new operation.`,
      { cause },
    );
    this.name = "HtlcUnknownOutcomeError";
  }
}

// ── output masks ──────────────────────────────────────────────────────────────────────────────

/** The Ristretto255 group order ℓ = 2^252 + 27742317777372353535851937790883648493. */
const RISTRETTO_L = (1n << 252n) + 27742317777372353535851937790883648493n;

function scalarFromLeHex(hex: string): bigint {
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error(`expected a 32-byte scalar in hex, got ${hex.length} chars`);
  let v = 0n;
  for (let i = 62; i >= 0; i -= 2) v = (v << 8n) | BigInt(parseInt(hex.slice(i, i + 2), 16));
  return v;
}

function scalarToLeHex(v: bigint): string {
  let out = "";
  for (let i = 0; i < 32; i++) {
    out += Number(v & 0xffn).toString(16).padStart(2, "0");
    v >>= 8n;
  }
  return out;
}

/**
 * `(a - b) mod ℓ` for 32-byte little-endian scalars. A transfer's `outputMask` is the *sum* of its
 * outputs' blinding masks (`aggregated_output_mask`), so when a fund creates the HTLC output plus
 * this account's own change, the HTLC output's own mask is `aggregate - changeMask` — the change
 * mask being recoverable because the change is addressed to this account. The result is only ever
 * trusted after `OotleAccount.htlcFund` proves it reproduces the HTLC commitment (see there).
 */
export function subtractScalars(aHex: string, bHex: string): string {
  const a = scalarFromLeHex(aHex) % RISTRETTO_L;
  const b = scalarFromLeHex(bHex) % RISTRETTO_L;
  return scalarToLeHex((((a - b) % RISTRETTO_L) + RISTRETTO_L) % RISTRETTO_L);
}

/**
 * Decrypts one of this account's *own* outputs straight out of a locally built outputs statement
 * (before anything is submitted) and returns its value and blinding mask. `outputJson` is the
 * statement's `outputs[i]` entry; `viewSecret` this account's view secret. Throws if the output
 * isn't addressed to this view key (AEAD or commitment check fails inside `unblindOutput`).
 */
export function decryptOwnStatementOutput(outputJson: unknown, viewSecret: Uint8Array): { value: bigint; maskHex: string; commitment: string } {
  const commitment = findHexField(outputJson, ["commitment"]);
  const nonce = findHexField(outputJson, ["public_nonce", "sender_public_nonce"]);
  const encrypted = findHexField(outputJson, ["encrypted_data"], true);
  if (!commitment || !nonce || !encrypted) throw new Error("decryptOwnStatementOutput: output is missing commitment/public nonce/encrypted data");
  const key = encryptedDataDhKdfAead(viewSecret, fromHex(nonce));
  const result = unblindOutput(fromHex(commitment), fromHex(encrypted), key, true);
  return { value: BigInt(result.value), maskHex: toHex(result.mask), commitment: commitment.toLowerCase() };
}

function findHexField(node: unknown, keys: string[], anyLength = false, depth = 0): string | null {
  if (depth > 6 || node === null || typeof node !== "object") return null;
  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    if (keys.includes(key) && typeof value === "string" && /^[0-9a-f]+$/i.test(value) && (anyLength || value.length === 64)) return value;
    const nested = findHexField(value, keys, anyLength, depth + 1);
    if (nested) return nested;
  }
  return null;
}

/** The Pedersen commitment of input `index` in a full statement JSON (what a spend of it commits to). */
export function statementInputCommitment(statementJson: string, index = 0): string | null {
  const parsed = JSON.parse(statementJson) as { inputs_statement?: { inputs?: unknown[] } };
  const input = parsed.inputs_statement?.inputs?.[index];
  return findCommitment(input);
}

function findCommitment(node: unknown, depth = 0): string | null {
  if (depth > 6 || node === null || typeof node !== "object") return null;
  for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
    if (key === "commitment" && typeof value === "string" && /^[0-9a-f]{64}$/i.test(value)) return value.toLowerCase();
    const nested = findCommitment(value, depth + 1);
    if (nested) return nested;
  }
  return null;
}

// ── statements / hashing ──────────────────────────────────────────────────────────────────────

/** The commitment of output `index` in a full `StealthTransferStatement` JSON string. Only the
 * commitment strings are read, so parsing precision on large numeric fields doesn't matter here. */
export function statementOutputCommitment(statementJson: string, index = 0): string {
  const parsed = JSON.parse(statementJson) as { outputs_statement?: { outputs?: { output?: { commitment?: string } }[] } };
  const commitment = parsed.outputs_statement?.outputs?.[index]?.output?.commitment;
  if (typeof commitment !== "string" || commitment.length === 0) {
    throw new Error(`statementOutputCommitment: no output commitment at index ${index}`);
  }
  return commitment;
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource)));
}

/** A fresh, random operation id (journal ids and reservation holders). */
export function newOperationId(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return `${prefix}-${toHex(bytes)}`;
}
