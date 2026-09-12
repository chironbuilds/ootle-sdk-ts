import {
  Mask,
  Network,
  OotleWallet,
  StealthInput,
  StealthInputsStatement,
  StealthOutputsStatement,
  StealthTransfer,
  StealthTransferStatement,
  TransactionBuilder,
  WalletStealthAuthorizer,
  WasmStealthCrypto,
  XTR_FAUCET_CLAIM_RESOURCE_ADDRESS,
  XTR_FAUCET_COMPONENT_ADDRESS,
  XTR_FAUCET_VAULT_ADDRESS,
  amountLiteral,
  createOutput,
  decryptOwnedUtxo,
  defaultIndexerUrl,
  getVaultIdsForAccount,
  resolveMaxEpoch,
  resolveTransaction,
  resourceAddressLiteral,
  sealTransaction,
  sendTransaction,
  serializeUnsignedTx,
  signTransaction,
  stealthUtxoSubstateId,
  submitTransaction,
} from "@tari-project/ootle";
import type { StealthTransferSpec, UnsignedTransactionWithBlobs } from "@tari-project/ootle";
import type {
  ExecuteResult,
  IndexerGetTransactionResultResponse,
  Instruction,
  Memo,
  OutputBody,
  Substate,
  SubstateRequirement,
  TransactionId,
} from "@tari-project/ootle-ts-bindings";
import { IndexerProvider } from "@tari-project/ootle-indexer";
import { SecretKeyWallet } from "@tari-project/ootle-secret-key-wallet";
import {
  buildScriptPathWitness,
  buildStealthTransferStatement,
  createConfidentialWithdrawProofLiteral,
  createStealthOutputWitness,
  parseOotleAddress,
  publicKeyFromSecretKey,
  schnorrSign,
  stealthDhSecret,
  validateStealthTransfer,
} from "@tari-project/ootle-wasm";
import type { WalletAccountApi } from "./accountApi.js";
import { componentAddressFromWalletAddress, deriveAccountComponentAddress } from "./componentAddress.js";
import { scanTransactionsForOwnedOutputs, sumConfidentialCommitments } from "./confidential.js";
import type { ScannedStealthOutput } from "./confidential.js";
import { deriveAccountKeys } from "./derivation.js";
import { htlcConditions } from "./htlc.js";
import { buildOwnershipProofMessage, buildWalletOwnershipMessage } from "./ownershipProof.js";
import { type NetworkName, toOotleNetwork } from "./ootleNetwork.js";
import {
  addPendingShield,
  addShieldedOutput,
  getKnownVersions,
  getPrivatePaymentScanCursor,
  listPendingShields,
  listShieldedOutputs,
  localAccountId,
  markShieldedOutputSpent,
  removePendingShield,
  setKnownVersions,
  setPrivatePaymentScanCursor,
} from "./storage.js";
import type { ShieldedOutputRecord } from "./storage.js";
import { withTimeout } from "./timeout.js";
import { fromHex, toHex } from "./vault.js";

export interface TokenBalance {
  resourceAddress: string;
  kind: string; // "Fungible" | "NonFungible" | "Confidential" | "Stealth"
  /** The plain, public (revealed) amount — what this vault shows on-chain to anyone. */
  amount: bigint;
  /** Value hidden inside this vault's Pedersen commitments, decrypted with this account's own
   * view key (see confidential.ts) — 0n for every kind except Confidential, and for a
   * Confidential vault with no commitments. Never requires a network call beyond what
   * getBalances() already fetches. */
  confidentialAmount: bigint;
  /** Commitments that failed to decrypt against this account's view key. Expected to be 0 for a
   * vault's own commitments map (every entry there should be ours) — nonzero is worth surfacing,
   * not silently swallowing. */
  confidentialDecryptFailures: number;
  /** The resource's on-chain decimal precision (e.g. 6 for XTR, 8 for a typical DemoToken) —
   * a real `Resource.divisibility` field, not a guessed convention. */
  divisibility: number;
  /** The resource's `metadata.SYMBOL`, if it set one — null for a resource with no such metadata
   * key, in which case a caller should fall back to the address. */
  symbol: string | null;
  /** The resource's `metadata.name` (a longer display name, distinct from the ticker-style
   * `symbol`), if it set one — null otherwise. */
  name: string | null;
  /** Token IDs held in this vault, for a `NonFungible` resource only — null for every other kind.
   * A NonFungible vault's container has no `.amount`/`.revealed_amount` field at all (only
   * `token_ids`/`locked_token_ids`), so `amount` above is synthesized as this array's length. */
  nonFungibleTokenIds: string[] | null;
}

/** One resource's total unspent *stealth* holding -- `OotleAccount.getPrivateBalances()`'s element
 * type. Deliberately separate from `TokenBalance`: that describes a vault (public amount plus any
 * decrypted commitments), this describes a set of freestanding stealth UTXOs, and a resource can
 * have either, both, or only the latter. */
export interface PrivateBalance {
  resourceAddress: string;
  /** Sum of the unspent outputs' amounts, raw resource-native units (same convention as
   * `TokenBalance.amount`). */
  amount: bigint;
  /** How many unspent outputs make up `amount`. Each is spent whole, so this bounds what a single
   * spend can be covered by -- see `resolveUnshieldPlan`'s coin selection. */
  outputCount: number;
  divisibility: number;
  symbol: string | null;
  name: string | null;
}

/**
 * Batch-reads each resource's on-chain `divisibility` and `metadata.SYMBOL`/`metadata.name`.
 * Decimal precision and display name are real chain data, never a client-side convention: XTR is 6
 * and a typical DemoToken defaults to 8, and assuming one for the other misprices amounts by two
 * orders of magnitude. A resource whose substate is missing or isn't a `Resource` degrades to
 * `divisibility: 0` and null names rather than throwing -- one unreadable resource must not take
 * down a whole balance listing.
 */
async function fetchResourceMetadata(
  provider: IndexerProvider,
  resourceIds: string[]
): Promise<{
  divisibilityByResource: Map<string, number>;
  symbolByResource: Map<string, string | null>;
  nameByResource: Map<string, string | null>;
}> {
  const divisibilityByResource = new Map<string, number>();
  const symbolByResource = new Map<string, string | null>();
  const nameByResource = new Map<string, string | null>();
  if (resourceIds.length === 0) return { divisibilityByResource, symbolByResource, nameByResource };

  const { substates } = await withTimeout(provider.fetchSubstates(resourceIds), 15_000, "reading token decimal precision");
  for (const id of resourceIds) {
    const value = substates[id]?.substate;
    const resource = value && "Resource" in value ? (value.Resource as { divisibility?: number; metadata?: Record<string, unknown> }) : undefined;
    divisibilityByResource.set(id, typeof resource?.divisibility === "number" ? resource.divisibility : 0);
    const metadata = resource?.metadata;
    symbolByResource.set(id, typeof metadata?.SYMBOL === "string" ? metadata.SYMBOL : null);
    nameByResource.set(id, typeof metadata?.name === "string" ? metadata.name : null);
  }
  return { divisibilityByResource, symbolByResource, nameByResource };
}

/**
 * A stealth output's **minimum value promise**: a public claim, committed into the output's own
 * range proof, that it is worth at least this much.
 *
 * A confidential output normally carries a range proof for `0 <= v < 2^64`, hiding `v` completely.
 * Set a promise `m` and the proof instead attests `m <= v < 2^64`, with `m` stored in the clear on
 * the output (`UnspentOutput.minimum_value_promise`). Anyone reading the output on-chain learns
 * "worth at least `m`" and nothing more precise -- which is exactly a proof of funds: a permanent,
 * non-interactive, publicly verifiable artifact that needs no cooperation from this wallet to check
 * (fetch the `utxo_{resource}_{commitment}` substate, read the field, confirm it is still unspent).
 *
 * Two things follow that callers must get right, which is why this is validated rather than passed
 * straight through:
 *
 * 1. **A promise above the real value is unprovable.** The bulletproof asserting `m <= v` cannot be
 *    generated when `m > v`, so this fails here with a message that says so, rather than deeper in
 *    the wasm with something opaque -- or, worse, producing a proof the network then rejects after
 *    the fee half of the transaction has already been committed.
 * 2. **It is a permanent, irreversible privacy disclosure.** Shielding is how value stops being
 *    publicly visible; a promise puts a floor back on public view, for the life of the output, for
 *    everyone -- not just whoever the proof was made for. That is the deliberate trade being made,
 *    and it is why every path reaching this asks the user first.
 */
// Exported (unlike this file's other module-level guards) so the rule can be exercised directly --
// it is the one place standing between a caller and an unprovable range proof, and a regression here
// would surface as an opaque wasm failure after the fee half of a transaction had already committed.
export function assertValidMinimumValuePromise(promise: bigint, amount: bigint): void {
  if (promise < 0n) {
    throw new Error(`minimumValuePromise cannot be negative (got ${promise}).`);
  }
  if (promise > amount) {
    throw new Error(
      `minimumValuePromise (${promise}) cannot exceed the output's own amount (${amount}) -- the range proof asserting "at least ${promise}" is impossible for an output actually worth ${amount}.`,
    );
  }
}

/**
 * `Output.memo`/`OutputInit.memo` is typed `object` in `@tari-project/ootle` (untyped there), but
 * is actually the tagged `Memo` union from `@tari-project/ootle-ts-bindings` -- confirmed by
 * reading that package's generated `Memo.d.ts` directly rather than assuming the Rust SDK docs'
 * `.with_memo_message(...)` name maps 1:1 onto this TS binding. `{ Message: text }` is the plain
 * free-text variant; the other variants (`U256`, `Bytes`, `PayRefAndBytes`) aren't used by this
 * wallet's UI, which only ever offers a plain text note.
 */
function toMemo(memo: string | undefined): Memo | undefined {
  return memo ? { Message: memo } : undefined;
}

/**
 * Inverse of `toMemo()`, for a *received* output: `DecryptedData.memo` (confidential.ts's
 * `ScannedStealthOutput.memo`, `claimPrivatePayment()`'s decrypt result) is the raw JSON-encoded
 * `Memo` union string, not plain text -- confirmed against the SDK's own `DecryptedData` doc
 * comment, not assumed. This wallet only ever creates `Message` memos, but a payment from a
 * different sender/tool could use any variant -- render something readable for those instead of
 * leaking raw JSON or silently dropping the memo. Returns `undefined` for no memo, an unparseable
 * value, or an empty `Message`.
 */
function fromMemo(memoJson: string | undefined): string | undefined {
  if (!memoJson) return undefined;
  try {
    const memo = JSON.parse(memoJson) as Memo;
    if ("Message" in memo) return memo.Message || undefined;
    if ("SenderAddress" in memo) return `From: ${memo.SenderAddress}`;
    const [kind, value] = Object.entries(memo)[0] as [string, string];
    return `[${kind} memo: ${value}]`;
  } catch {
    return undefined;
  }
}

/**
 * One derived Ootle account: a signer (owner + view keypair) plus the network connection needed
 * to read its state and submit transactions, entirely independent of the wallet daemon.
 */
export class OotleAccount implements WalletAccountApi {
  readonly index: number;
  readonly network: Network;
  readonly signer: SecretKeyWallet;
  private provider: IndexerProvider | null = null;
  // Held only for signOwnershipProof(), which needs stealthDhSecret() directly -- SecretKeyWallet
  // keeps its own copy of this exact value in a private field already (for addStealthSignature's
  // transaction-signing path), so this adds no new exposure, just a second reference to the same
  // in-memory secret for a second, narrowly-scoped purpose.
  private readonly ownerSecret: Uint8Array;

  private constructor(index: number, network: Network, signer: SecretKeyWallet, ownerSecret: Uint8Array) {
    this.index = index;
    this.network = network;
    this.signer = signer;
    this.ownerSecret = ownerSecret;
  }

  /** `entropy` is the 16-byte CipherSeed entropy (see cipherSeed.ts), not a raw 32-byte seed. */
  static fromSeed(entropy: Uint8Array, index: number, networkName: NetworkName): OotleAccount {
    const network = toOotleNetwork(networkName);
    const { ownerSecret, viewSecret } = deriveAccountKeys(entropy, index);
    const signer = SecretKeyWallet.fromSecretKey(ownerSecret, network, viewSecret);
    return new OotleAccount(index, network, signer, ownerSecret);
  }

  async getProvider(): Promise<IndexerProvider> {
    if (!this.provider) {
      // Nothing has run yet at this point, so any failure here is by definition a connectivity
      // problem (unlike execute()'s later errors, which are meaningful on-chain rejections this
      // class deliberately leaves unwrapped) — mirrors the same "unreachable" framing
      // DaemonAccount.connectClient() uses for the equivalent first-contact step.
      const url = defaultIndexerUrl(this.network);
      try {
        this.provider = await withTimeout(
          IndexerProvider.connect({ url, network: this.network }),
          15_000,
          "connecting to the Tari indexer"
        );
      } catch (e) {
        const details = e instanceof Error ? e.message : String(e);
        throw new Error(`Could not reach the Tari indexer at ${url}. (${details})`);
      }
    }
    return this.provider;
  }

  /**
   * The bech32m "otl_..." wallet address, for display / receiving funds. Confirmed (empirically,
   * against `generateOotleAddress`) to be what `Signer.getAddress()` actually returns for a
   * `SecretKeyWallet` — despite the base `Signer` interface's JSDoc calling it "the component
   * address", it is NOT the on-chain account component address. See `getComponentAddress()`.
   */
  async getWalletAddress(): Promise<string> {
    return this.signer.getAddress();
  }

  async getPublicKey(): Promise<Uint8Array> {
    return this.signer.getPublicKey();
  }

  /**
   * The account's on-chain component address — what instructions use as the `account` argument
   * (deposit/withdraw/pay_fee/etc.) and what `getVaultIdsForAccount` needs to find balances.
   *
   * Computed client-side via `deriveAccountComponentAddress` (`componentAddress.ts`), which
   * reproduces Ootle's domain-separated Blake2b hash of (ACCOUNT_TEMPLATE_ADDRESS, owner_public_key)
   * byte-for-byte — verified against all three committed golden vectors from
   * `tari-ootle`'s `crates/ootle_sdk_core/fixtures/address_derive/`.
   */
  async getComponentAddress(): Promise<string> {
    const publicKey = await this.getPublicKey();
    return deriveAccountComponentAddress(publicKey);
  }

  async getBalances(): Promise<TokenBalance[]> {
    const provider = await this.getProvider();
    const account = await this.getComponentAddress();
    let vaultIds: string[];
    try {
      vaultIds = await withTimeout(getVaultIdsForAccount(provider, account), 15_000, "looking up this account's vaults");
    } catch (e) {
      // A real timeout here (the indexer connection above already succeeded, so this specifically
      // means it's up but slow/overloaded) must not look identical to "this account genuinely has
      // no vaults yet" — silently mapping both to an empty balance list would show a brand-new
      // account and a degraded-indexer account the exact same way, with no indication anything's
      // actually wrong in the latter case.
      if (e instanceof Error && e.message.startsWith("Timed out")) throw e;
      return []; // account not yet on-chain (never funded)
    }

    // Fold in this account's own known-good stealth outputs (from shield()/unshield(), or from
    // redeeming someone else's shared commitment via the "Advanced" unshield flow) up front, not
    // gated behind a vault existing -- see ShieldedOutputRecord's doc comment for why this local
    // ledger is the only lead to them at all: they're freestanding `utxo_{resource}_{commitment}`
    // substates, never entries in a vault's own `Confidential.commitments` map, so nothing below
    // this point would otherwise see them. A resource whose *only* balance came from redeeming a
    // shared commitment has no on-chain vault at all (`vaultIds.length === 0` for it), so this
    // can't be computed only after confirming a vault exists.
    // A local record only says this account once *held* the output. It says nothing about whether
    // the output has since been spent — by another wallet on the same seed, by another device, or
    // by a spend this ledger never saw — and `scanForPrivatePayments` happily re-claims outputs
    // that were already consumed. Counting those inflates the private balance with money that
    // cannot be spent, and the failure only surfaces later as an unresolvable input mid-transfer.
    //
    // The chain is the authority: a stealth output is a substate, and a consumed one is simply
    // gone. Confirmed against the live Esmeralda indexer that `getSubstate` returns the substate
    // for a live output and errors (HTTP 500) for a consumed one, and that batching them through
    // `fetchSubstates` fails the *whole* call as soon as one id is consumed — so each is checked
    // on its own, in parallel.
    //
    // Deliberately not persisted as `spent`: the indexer's error is indistinguishable from a real
    // server fault, and marking the ledger on an ambiguous signal is a one-way door that would
    // hide genuine funds. Excluding it from this reading is self-healing — if the output really is
    // live, the next balance read counts it again. The vault lookup above already proved the
    // indexer is reachable in this same call, which is what makes a per-id failure here meaningful
    // rather than just noise.
    const unspentRecords = (await listShieldedOutputs(localAccountId(this.index))).filter((r) => !r.spent);
    const liveness = await Promise.all(
      unspentRecords.map(async (record) => {
        try {
          await withTimeout(
            provider.getSubstate(stealthUtxoSubstateId(record.resourceAddress, fromHex(record.commitment))),
            15_000,
            "checking a shielded output",
          );
          return true;
        } catch {
          return false;
        }
      }),
    );
    const shieldedByResource = new Map<string, bigint>();
    unspentRecords.forEach((record, i) => {
      if (!liveness[i]) return;
      shieldedByResource.set(record.resourceAddress, (shieldedByResource.get(record.resourceAddress) ?? 0n) + BigInt(record.amount));
    });
    if (vaultIds.length === 0 && shieldedByResource.size === 0) return [];

    const parsed: {
      resourceAddress: string;
      kind: string;
      amount: bigint;
      commitments?: Record<string, OutputBody>;
      nonFungibleTokenIds?: string[];
    }[] = [];
    if (vaultIds.length > 0) {
      const { substates } = await withTimeout(provider.fetchSubstates(vaultIds), 15_000, "fetching vault balances");
      for (const id of vaultIds) {
        const substate: Substate | undefined = substates[id];
        const value = substate?.substate;
        if (!value || !("Vault" in value)) continue;
        const container = value.Vault.resource_container;
        const [kind, data] = Object.entries(container)[0] as [string, Record<string, unknown>];
        if (kind === "NonFungible") {
          const tokenIds = ((data.token_ids as unknown[]) ?? []).map(stringifyNonFungibleId);
          parsed.push({ resourceAddress: data.address as string, kind, amount: BigInt(tokenIds.length), nonFungibleTokenIds: tokenIds });
          continue;
        }
        const rawAmount = (data.amount ?? data.revealed_amount ?? 0) as string | number | bigint;
        const commitments = kind === "Confidential" ? (data.commitments as Record<string, OutputBody> | undefined) : undefined;
        parsed.push({ resourceAddress: data.address as string, kind, amount: BigInt(rawAmount), commitments });
      }
    }
    if (parsed.length === 0 && shieldedByResource.size === 0) return [];

    // Decrypt each Confidential vault's hidden commitments with this account's own view key —
    // pure local decryption of data already fetched above, no new network calls. One crypto
    // provider + one view-secret fetch is reused across every confidential vault in this
    // account rather than re-deriving per vault.
    const confidentialByIndex = new Map<number, { total: bigint; failedCount: number }>();
    const hasConfidential = parsed.some((p) => p.commitments && Object.keys(p.commitments).length > 0);
    if (hasConfidential) {
      const crypto = new WasmStealthCrypto(this.network);
      const viewSecret = await this.signer.getViewSecret();
      for (const [i, p] of parsed.entries()) {
        const commitments = p.commitments;
        if (!commitments || Object.keys(commitments).length === 0) continue;
        confidentialByIndex.set(i, await sumConfidentialCommitments(crypto, viewSecret, commitments));
      }
    }

    // Batch-fetch each distinct resource's own substate for its real `divisibility` and metadata
    // symbol/name — decimal precision and display name are both on-chain data, not a client-side
    // guess (confirmed empirically: XTR is 6, a typical DemoToken defaults to 8, and assuming one
    // divisibility for both silently misprices trades by orders of magnitude).
    // Union with shielded-only resources (computed up front, before the vault check above) so a
    // resource with no vault at all still gets its real divisibility/symbol/name looked up.
    const resourceIds = [...new Set([...parsed.map((p) => p.resourceAddress), ...shieldedByResource.keys()])];
    const { divisibilityByResource, symbolByResource, nameByResource } = await fetchResourceMetadata(provider, resourceIds);

    const balances: TokenBalance[] = parsed.map((p, i) => ({
      resourceAddress: p.resourceAddress,
      kind: p.kind,
      amount: p.amount,
      confidentialAmount: (confidentialByIndex.get(i)?.total ?? 0n) + (shieldedByResource.get(p.resourceAddress) ?? 0n),
      confidentialDecryptFailures: confidentialByIndex.get(i)?.failedCount ?? 0,
      divisibility: divisibilityByResource.get(p.resourceAddress) ?? 0,
      symbol: symbolByResource.get(p.resourceAddress) ?? null,
      name: nameByResource.get(p.resourceAddress) ?? null,
      nonFungibleTokenIds: p.nonFungibleTokenIds ?? null,
    }));

    // Resources whose only balance is a shielded output with no on-chain vault at all (e.g.
    // redeemed via the "Advanced" unshield flow from someone else's shared commitment) never
    // appear in `parsed` above -- synthesize an entry for each so they aren't silently dropped.
    balances.push(
      ...synthesizeShieldedOnlyBalances(
        new Set(parsed.map((p) => p.resourceAddress)),
        shieldedByResource,
        divisibilityByResource,
        symbolByResource,
        nameByResource,
      ),
    );
    return balances;
  }

  /**
   * Builds, signs (with this account's key) and submits/dry-runs a transaction. `opts.inputs` lets
   * a caller pre-pin substates it already knows are needed; beyond that, this indexer requires
   * *every* substate an instruction touches to be listed as an input — even ones referenced only
   * by address in a `CallMethod` on an already-existing component (confirmed empirically, first
   * with the faucet, and again with this account's own existing component when calling into it for
   * a `pay_fee`/`deposit`/`withdraw` on a second use) — and there's no want-derivation pass in this
   * TS SDK to discover that dependency graph up front the way the Rust `ootle_sdk_core` can.
   *
   * Rather than hand-tracing each call's full component/vault graph, this retries on the specific
   * rejection the engine itself gives for a missing input — "At instruction #N: <address> not
   * found" — extracting that address, resolving its current version, adding it to the pinned
   * inputs, and resubmitting. Each retry can surface a *different* missing address (a component's
   * vaults are only discoverable after the component itself is known), so this loops until either
   * success or the same address reappears (nothing new left to resolve). The version-race retry
   * `claimTestnetXtr()` needs for a heavily-contended shared substate is folded in too.
   */
  async execute(
    instructions: Instruction[],
    opts: { maxFee?: bigint; dryRun?: boolean; inputs?: SubstateRequirement[]; maxRetries?: number } = {}
  ) {
    const provider = await this.getProvider();
    const account = await this.getComponentAddress();
    const maxFee = opts.maxFee ?? 5000n;
    // Resolved once, outside the retry loop below: every transaction now carries a mandatory
    // `max_epoch`, and a fresh chain-tip lookup on every retry would buy nothing (the loop's
    // whole retry budget runs in well under an epoch in practice) at the cost of an extra
    // round trip per attempt.
    const maxEpoch = await resolveMaxEpoch(provider);
    // A first-time transaction into brand-new resources needs one retry per previously-unknown
    // substate it discovers (each pool, each pool's own internal vaults, and any new vault the
    // account itself needs created to hold a token it's never held before) — confirmed empirically
    // that a single-hop swap into a new resource needed more than the original budget of 12, and a
    // routed (multi-hop) swap touches roughly double the substates a direct one does (two pools
    // instead of one, up to two new account vaults instead of one for the intermediate *and* final
    // tokens) — hit exactly this exhausting 20 on a real 2-hop swap.
    const maxRetries = opts.maxRetries ?? 30;
    const seenAddresses = new Set<string>();
    let inputs = await applyKnownVersions(opts.inputs ? [...opts.inputs] : []);

    for (let attempt = 0; ; attempt++) {
      const builder = TransactionBuilder.new(this.network, maxEpoch)
        .withInstructions(instructions)
        .feeTransactionPayFromComponent(account, maxFee);
      if (inputs.length) builder.withInputs(inputs);
      const unsignedTx = builder.buildUnsignedTransaction();

      try {
        if (opts.dryRun) return await withTimeout(this.submitDryRun(provider, unsignedTx), 30_000, "submitting the transaction");
        const result = await withTimeout(this.submitReal(provider, unsignedTx), 60_000, "submitting the transaction");
        await recordKnownVersions(result);
        return withTransactionId(result);
      } catch (e) {
        if (!(e instanceof Error) || attempt >= maxRetries) throw e;

        // No amount of retrying fixes an empty fee vault — surface this immediately instead of
        // burning the retry budget re-discovering the same "insufficient balance" outcome.
        if (e.message.includes("InsufficientFeesPaid") || /insufficient/i.test(e.message)) {
          throw new Error(`This account doesn't have enough XTR to pay the transaction fee. Claim testnet XTR first. (${e.message})`);
        }

        if (e.message.includes("Lock failure")) {
          // A "Lock failure: Substate X:N is DOWN" names the *exact* version that was just
          // consumed — the next version is deterministically N+1, computable locally with no
          // network round trip. This matters: re-querying the indexer here (the previous
          // approach) can hand back the very same stale N again, and worse, this loop's *own*
          // prior attempt can have advanced the real version further still if it reached and paid
          // the fee phase before its main instructions failed (`AcceptFeeRejectRest` still commits
          // the fee) — so trusting a fresh `resolveInputs()` call to have caught up is exactly the
          // race that was producing an apparently-stuck version across many retries.
          const staleVersion = extractStaleLockVersion(e.message);
          if (staleVersion) {
            // The known-versions cache would otherwise keep reasserting the very version that was
            // just rejected over every future resolve for this substate (see
            // `forgetKnownVersions`'s doc comment) -- the local N+1 computed below is correct for
            // *this* attempt, but leaving the stale entry in place would win out again on some
            // later, unrelated transaction that resolves this same substate from scratch.
            await forgetKnownVersions([staleVersion.substateId]);
            inputs = inputs.map((input) =>
              input.substate_id === staleVersion.substateId ? { ...input, version: staleVersion.version + 1 } : input
            );
            continue;
          }
          const resolved = await resolveInputsWithRetry(
            provider,
            inputs.map(({ substate_id }) => ({ substate_id, version: null })),
          );
          // Deliberately NOT `applyKnownVersions(resolved)`: the remembered version is exactly
          // what just failed, and it is `>` whatever the indexer reports, so re-applying it
          // overwrites the freshly resolved (correct) version with the stale one and the next
          // attempt fails identically. Persisted, so one bad write wedges every later transaction
          // across reloads. Forget those entries and trust the chain.
          await forgetKnownVersions(inputs.map((i) => i.substate_id));
          inputs = resolved;
          continue;
        }

        const missing = extractMissingSubstateAddress(e.message);
        if (!missing || seenAddresses.has(missing)) throw e;
        seenAddresses.add(missing);

        // `resolveInputsWithRetry` already rides out the ordinary case (a producer that hasn't
        // finalized on the indexer yet). If it's *still* failing after that budget, the substate
        // is most likely genuinely absent rather than merely slow -- the common way that happens
        // is a recipient account that has never been funded, since an Ootle account component
        // only exists on chain once something has been deposited into it. Surface that plainly
        // instead of the indexer's raw 404, which names neither the cause nor the fix.
        let resolved: SubstateRequirement;
        try {
          const [firstResolved] = await resolveInputsWithRetry(provider, [{ substate_id: missing, version: null }]);
          resolved = firstResolved!;
        } catch (resolveError) {
          if (resolveError instanceof Error && resolveError.message.startsWith("Timed out")) throw resolveError;
          throw new Error(
            `${missing} does not exist on the Ootle network yet. An account is created the first ` +
              `time it receives funds, so a brand-new account cannot be paid until it has been ` +
              `funded once. (${resolveError instanceof Error ? resolveError.message.slice(0, 120) : String(resolveError)})`,
          );
        }
        inputs = await applyKnownVersions([...inputs, resolved]);
      }
    }
  }

  /**
   * A working replacement for the SDK's exported `sendDryRun()`, which is broken against this
   * indexer: it builds the identical signed/sealed envelope but POSTs it to the regular
   * `transactions` endpoint, which rejects dry-run envelopes with "Dry-run transactions must be
   * submitted to the /transactions/dry-run endpoint" (confirmed empirically). This reproduces
   * `sendDryRun`'s own pipeline — set `dry_run`, `resolveTransaction`, `signTransaction`,
   * `sealTransaction` (all exported, same functions it uses internally) — but posts the sealed
   * envelope to the correct path via the indexer client's transport directly. Dry-run responses
   * come back synchronously with the full result already attached (no `transactions/{id}/result`
   * polling needed, unlike a real submission).
   *
   * The response shape (`{transaction_id, result: ExecuteResult}`) is the indexer's own
   * `SubmitTransactionDryRunResponse` (`applications/tari_indexer/src/rest_api/handlers/
   * transactions.rs`'s `submit_transaction_dry_run` handler) — confirmed directly against that
   * Rust source since `@tari-project/ootle-ts-bindings` doesn't export a matching type for it
   * (only the real-submission response, which no longer carries a `result` field at all as of
   * the 0.39.0 protocol upgrade).
   */
  private async submitDryRun(
    provider: IndexerProvider,
    unsignedTx: UnsignedTransactionWithBlobs
  ): Promise<{ transaction_id: TransactionId; result: ExecuteResult }> {
    const resolved = await resolveTransaction(provider, { ...unsignedTx, dry_run: true });
    const signed = await signTransaction([this.signer], resolved);
    const envelope = sealTransaction(signed);
    const res = await fetch(`${defaultIndexerUrl(this.network)}/transactions/dry-run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // `TransactionEnvelope` (ootle-ts-bindings) is just `string` — the request body is the
      // `{ transaction }` wrapper (`IndexerSubmitTransactionRequest`), not the bare envelope string.
      body: JSON.stringify({ transaction: envelope }),
    });
    const text = await res.text();
    let body: { error?: { code: string; message: string } } | undefined;
    try {
      body = text ? JSON.parse(text) : undefined;
    } catch {
      // Not JSON — fall through and report the raw text below.
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${body?.error?.message ?? text ?? res.statusText}`);
    if (body?.error) throw new Error(`${body.error.code}: ${body.error.message}`);
    const response = body as { transaction_id: TransactionId; result: ExecuteResult };

    // A rejected dry-run comes back as a normal HTTP 200 with the rejection embedded in the
    // result (there's nothing to poll — dry runs never reach consensus). Throwing here, in the
    // same "Transaction {id} was rejected: {reason}" shape `sendTransaction`'s own polling throws
    // in, means `execute()`'s retry loop only needs one error-handling path for both. Two failure
    // variants matter: a clean `Reject`, and `AcceptFeeRejectRest` (the fee phase succeeded — it
    // only touches the account, which by definition already resolved — but the *main* instructions
    // aborted, confirmed empirically hitting this on a first read of the DEX pool: the fee-only
    // success masked the "pool component not found" this same regex needs to see to retry).
    const outcome = response.result.finalize.result;
    if (typeof outcome === "object" && outcome !== null) {
      if ("Reject" in outcome) {
        throw new Error(`Transaction ${response.transaction_id} was rejected: ${JSON.stringify(outcome.Reject)}`);
      }
      if ("AcceptFeeRejectRest" in outcome) {
        throw new Error(
          `Transaction ${response.transaction_id} accepted the fee but rejected the rest: ${JSON.stringify(outcome.AcceptFeeRejectRest)}`
        );
      }
    }
    return response;
  }

  /**
   * A working replacement for the SDK's exported `sendTransaction()`. That function still submits
   * correctly, but its own polling (`ct()`/`st()` internally) only surfaces a generic
   * `abort_details` summary on rejection — not the full structured `RejectReason`/`SubstateDiff`
   * this class's auto-resolve retry (see `execute()`) needs to find a missing substate's address
   * in. Confirmed empirically: a real submission that hit "SubstateNotFound: vault_... not found"
   * came back from `sendTransaction()` with no address in the thrown message at all, so the retry
   * loop had nothing to extract and gave up on the first attempt — the exact failure this method
   * exists to fix. Submission itself (`provider.submitTransaction`) is unchanged and already
   * proven correct; only the result-polling and error-message construction are reimplemented, in
   * the same detailed shape `submitDryRun()` above already produces.
   */
  private async submitReal(provider: IndexerProvider, unsignedTx: UnsignedTransactionWithBlobs): Promise<IndexerGetTransactionResultResponse> {
    const resolved = await resolveTransaction(provider, unsignedTx);
    // Both of these parse the transaction inside the wasm as an untagged enum
    // (`ootle_wasm/core/src/transaction.rs`), so a single bad field anywhere collapses into "data
    // did not match any variant of untagged enum TransactionInput" with nothing naming the
    // culprit. `signTransaction` parses `{transaction, signatures}` -- so a malformed *signature*
    // fails it exactly like a malformed transaction does -- and `sealTransaction` parses it again.
    // The shape is the only evidence there is and it is gone by the time the error surfaces, so it
    // is attached here rather than guessed at afterwards.
    let signed;
    try {
      signed = await signTransaction([this.signer], resolved);
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)} — at signTransaction; resolved tx: ${describeResolvedTx(resolved)}`,
        { cause: e },
      );
    }
    let envelope;
    try {
      envelope = sealTransaction(signed);
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)} — at sealTransaction; signed: ${describeSignedTx(signed)}`,
        { cause: e },
      );
    }
    const { transaction_id } = await provider.submitTransaction(envelope);
    return pollTransactionResult(provider, transaction_id);
  }

  /**
   * Transfers `amount` (raw, resource-native units) of `resourceAddress` from this account to
   * `recipientAddress` — a plain `withdraw` off this account's own vault, handed straight to
   * `deposit` on the recipient's account component via a workspace bucket, in one transaction.
   * Works for any resource this account holds, including XTR; `execute()`'s auto-resolve retry
   * (see its own doc comment) discovers and pins whichever vaults/components aren't already
   * known, exactly as it does for every other instruction this class builds by hand.
   *
   * `recipientAddress` accepts either form (see `WalletAccountApi.send`'s doc comment): the
   * recipient's bech32m wallet address, or a bare `component_...` address. `CallMethod.call` is a
   * `SubstateId`, so it must end up being the latter either way — handing an "otl_…" straight
   * through is not a friendly error: `SubstateId::from_str` splits on the first underscore, does
   * not recognise the `otl` prefix, and the instruction then fails to deserialize, surfacing from
   * the wasm as "data did not match any variant of untagged enum TransactionInput", naming neither
   * the field nor the reason.
   *
   * `deposit` is a method call on an *existing* component, and `CreateAccount` is create-or-conflict
   * (against an account that already exists it rejects with "Substate <component>:0 is already UP
   * and conflicts with an existing output" -- Tari's own walletd reads that exact string as "this
   * already exists" in its faucet handler), so a brand-new recipient's account is created only when
   * it is genuinely missing, and only when a wallet address was given -- a bare component address
   * never reveals the owner key `CreateAccount` needs, so that form can only pay an account that
   * already exists.
   */
  async send(recipientAddress: string, resourceAddress: string, amount: bigint, maxFee = 5000n) {
    const account = await this.getComponentAddress();
    const isWalletAddress = recipientAddress.startsWith("otl");
    const recipient = isWalletAddress ? componentAddressFromWalletAddress(recipientAddress) : recipientAddress;

    const instructions: Instruction[] = [];

    if (isWalletAddress) {
      const provider = await this.getProvider();
      let recipientExists = true;
      try {
        await withTimeout(provider.getSubstate(recipient), 15_000, "checking the recipient's account");
      } catch (e) {
        // A timeout means the indexer is degraded, not that the account is missing — creating one
        // on that assumption is how a working transfer turns into an "already UP" rejection.
        if (e instanceof Error && e.message.startsWith("Timed out")) throw e;
        recipientExists = false;
      }
      if (!recipientExists) {
        const { owner_key } = parseOotleAddress(recipientAddress);
        instructions.push({
          CreateAccount: { owner_public_key: toHex(owner_key), owner_rule: null, access_rules: null, bucket_workspace_id: null },
        });
      }
    }

    instructions.push(
      { CallMethod: { call: { Address: account }, method: "withdraw", args: [resourceAddressLiteral(resourceAddress), amountLiteral(amount)] } },
      { PutLastInstructionOutputOnWorkspace: { key: 0 } },
      { CallMethod: { call: { Address: recipient }, method: "deposit", args: [{ Workspace: { id: 0, offset: null } }] } },
    );
    return this.execute(instructions, { maxFee });
  }

  /**
   * Moves `amount` of this account's own REVEALED balance into a Confidential-type vault for the
   * same resource -- the "Confidential" `ResourceType`'s equivalent of `shield()`, a different
   * privacy mechanism from Stealth (vault-based, ElGamal-encrypted to a resource view key, rather
   * than freestanding one-time-key UTXOs -- see the resource-types write-up in the integration
   * docs). Only meaningful for a resource actually created as `ResourceType::Confidential`; calling
   * this against a Fungible or Stealth resource's vault fails on-chain ("resource type mismatch" or
   * similar), not client-side -- this class has no way to know a resource's type up front without
   * an extra substate fetch, so the failure is left to the engine.
   *
   * Builds a `ConfidentialWithdrawProof` client-side (no wallet-daemon round trip) via the vendored
   * `createConfidentialWithdrawProofLiteral` -- see that WASM export's own doc comment for why the
   * `tari_bor` encoding happens in Rust rather than being hand-rolled here: the official
   * `@tari-project/ootle` SDK's own `feeTransactionPayFromComponentConfidential` is unimplemented
   * for exactly this reason ("a ConfidentialWithdrawProof Literal must be tari_bor-CBOR-encoded,
   * which the TS SDK does not yet support").
   *
   * The new confidential output is addressed to this account's own owner/view keys -- the same
   * one-time-output-witness construction `createStealthOutputWitness` already builds for Stealth
   * outputs, reused here since `ConfidentialOutputStatement.output` and a `StealthOutputWitness`'s
   * `witness` share the exact same shape (mask, sender_public_nonce, encrypted_data). Only the
   * `witness` half of that result is used -- the `auth`/`tag` halves are Stealth-specific
   * (`SpendAuthorization`/`UtxoTag`); a Confidential output has neither, ownership being purely
   * "which vault holds it," not a spend-authorization key.
   *
   * Two instructions, mirroring `send()`'s withdraw-then-deposit shape: `withdraw_confidential`
   * (drawing `amount` from the vault's revealed side, per the proof's `input_revealed_amount`)
   * produces a bucket holding the one new confidential output, which `deposit` puts back in the
   * same vault.
   */
  async depositConfidential(resourceAddress: string, amount: bigint, maxFee = 50000n) {
    if (amount <= 0n) throw new Error(`depositConfidential: amount must be greater than zero, got ${amount}`);
    const account = await this.getComponentAddress();
    const ownerPublicKey = await this.getPublicKey();
    const viewSecret = await this.signer.getViewSecret();
    const viewPublicKey = publicKeyFromSecretKey(viewSecret);

    const witnessJson = createStealthOutputWitness(
      this.network,
      ownerPublicKey,
      viewPublicKey,
      amount,
      resourceAddress,
      undefined, // resource_view_key -- irrelevant here; that grants a THIRD PARTY decrypt access, not needed to address an output to ourselves
      undefined, // memo_json
      undefined, // pay_to_json -- irrelevant: only `witness` below is used, never this call's `auth`/`tag`
      0n, // minimum_value_promise -- a Stealth/bulletproof-auth concept; not meaningful for a Confidential output
    );
    const { witness } = JSON.parse(witnessJson) as { witness: unknown };
    const outputJson = JSON.stringify(witness);

    const proofBytes = createConfidentialWithdrawProofLiteral(
      "[]", // no confidential inputs spent -- drawing purely from the vault's revealed side
      amount,
      outputJson,
      0n,
      undefined,
      0n,
    );
    const proofLiteral = { Literal: toHex(proofBytes) };

    const instructions: Instruction[] = [
      {
        CallMethod: {
          call: { Address: account },
          method: "withdraw_confidential",
          args: [resourceAddressLiteral(resourceAddress), proofLiteral],
        },
      },
      { PutLastInstructionOutputOnWorkspace: { key: 0 } },
      { CallMethod: { call: { Address: account }, method: "deposit", args: [{ Workspace: { id: 0, offset: null } }] } },
    ];
    return this.execute(instructions, { maxFee });
  }

  /**
   * Claims free testnet XTR from the network's builtin faucet (esmeralda/igor only — there is no
   * such faucet on mainnet). Mirrors both `build_faucet_claim_with_wants` in tari-ootle's
   * `crates/ootle_sdk_core/src/faucet.rs` and (confirmed against its actual pinned-input list)
   * `handle_create_free_test_coins` in `applications/tari_walletd/src/handlers/accounts.rs` — the
   * handler backing the `accounts.create_free_test_coins` walletd RPC that tari-dex's swap-ui
   * calls. Self-funding, so it works even for a brand-new account that doesn't exist on-chain yet:
   * the fee phase itself creates the account, funds it from the faucet
   * (`XTR_FAUCET_COMPONENT_ADDRESS.take(account)`), then pays its own fee out of what it just
   * received.
   *
   * Unlike every other component this class calls, none of the faucet's substates (component,
   * vault, claim resource) get auto-resolved from the instructions by this indexer — each has to
   * be pinned as an explicit transaction input (confirmed empirically: submitting with only the
   * claim resource pinned rejected with "component_...0000 not found" at the `take` call).
   * `provider.resolveInputs()` fills in each one's current version.
   *
   * The faucet vault is a single shared substate every claimant on the testnet contends for, so
   * the version pinned by `resolveInputs()` routinely goes stale between resolution and consensus
   * (confirmed empirically: "Lock failure: Substate vault_...:8 is DOWN" — someone else's claim
   * landed first). This isn't a bug to fix, just contention to ride out: catch that specific
   * rejection and retry with freshly-resolved versions and a new transaction id.
   *
   * Retries back off (`retryDelayMs * (attempt + 1)`, so 300ms, 600ms, 900ms, ...) rather than
   * resubmitting back-to-back: confirmed empirically that hammering `resolveInputs()` immediately
   * after a rejection can keep handing back the same already-stale version every time (the
   * indexer's own view of a shared, heavily-contended substate can lag behind consensus by more
   * than one round trip takes) — a short, growing pause gives that view time to catch up instead
   * of burning the whole retry budget re-observing the same stale state.
   */
  async claimTestnetXtr(maxFee = 5000n, retries = 10, retryDelayMs = 300) {
    const provider = await this.getProvider();
    const publicKeyHex = bytesToHex(await this.getPublicKey());
    const account = await this.getComponentAddress();
    const maxEpoch = await resolveMaxEpoch(provider);

    for (let attempt = 0; ; attempt++) {
      const inputs = await withTimeout(
        provider.resolveInputs([
          { substate_id: XTR_FAUCET_COMPONENT_ADDRESS, version: null },
          { substate_id: XTR_FAUCET_VAULT_ADDRESS, version: null },
          { substate_id: XTR_FAUCET_CLAIM_RESOURCE_ADDRESS, version: null },
        ]),
        15_000,
        "resolving the faucet's current state"
      );

      const unsignedTx = TransactionBuilder.new(this.network, maxEpoch)
        .withFeeInstructionsBuilder((b) =>
          b
            .createAccount(publicKeyHex)
            .saveVar("faucet_account")
            .callMethod({ componentAddress: XTR_FAUCET_COMPONENT_ADDRESS, methodName: "take" }, [{ Workspace: "faucet_account" }])
        )
        .feeTransactionPayFromComponent(account, maxFee)
        .withInputs(inputs)
        .buildUnsignedTransaction();

      try {
        const result = await withTimeout(sendTransaction(provider, this.signer, unsignedTx), 30_000, "submitting the claim");

        // This is typically the first transaction for a brand-new account — recording its
        // resulting versions (the newly-created fee vault included) closes the exact gap that
        // otherwise bites the *next* transaction (see `applyKnownVersions`'s doc comment).
        await recordKnownVersions(result);
        return result;
      } catch (e) {
        // "Failed to decode transaction: unexpected type null at position N: expected u64" is a
        // serde failure at the indexer, and the byte offset alone names nothing. The transaction
        // is the only evidence and it is gone once this throws, so attach the field shapes — the
        // u64-typed fields first, since one of them arriving null is what the message describes.
        if (e instanceof Error && /Failed to decode transaction/i.test(e.message)) {
          const t = unsignedTx as unknown as Record<string, unknown>;
          const shape = [
            `network=${typeof t.network}:${JSON.stringify(t.network)}`,
            `min_epoch=${JSON.stringify(t.min_epoch)}`,
            `max_epoch=${typeof t.max_epoch}:${JSON.stringify(t.max_epoch)}`,
            `nonce=${typeof t.nonce}:${JSON.stringify(t.nonce)}`,
            `dry_run=${JSON.stringify(t.dry_run)}`,
            `is_seal_signer_authorized=${JSON.stringify(t.is_seal_signer_authorized)}`,
            `blobs=${Array.isArray(t.blobs) ? `array[${(t.blobs as unknown[]).length}]` : typeof t.blobs}`,
            `inputs=${JSON.stringify(t.inputs)}`,
            `fee_instructions=${JSON.stringify(t.fee_instructions)?.slice(0, 400)}`,
          ].join(" ");
          throw new Error(`${e.message} — tx: ${shape}`);
        }
        // The claim's fee phase calls `createAccount` for *this* account, and `CreateAccount` is
        // create-or-conflict: once the account exists the instruction rejects with "is already UP
        // and conflicts with an existing output". Tari's own walletd reads that exact string as
        // "faucet already claimed" (`applications/tari_walletd/src/handlers/accounts.rs`), so it
        // is reported that way here rather than as a raw consensus rejection — retrying cannot
        // help, and the account is fine.
        if (e instanceof Error && e.message.includes("is already UP and conflicts with an existing output")) {
          throw new Error(
            "This account has already claimed from the faucet — the faucet only pays out once per account.",
          );
        }
        const isStaleVersionRace = e instanceof Error && e.message.includes("Lock failure");
        if (!isStaleVersionRace || attempt >= retries) throw e;
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs * (attempt + 1)));
      }
    }
  }

  /**
   * Shields (moves from revealed to private/confidential) `amount` of `resourceAddress`, held as
   * a new stealth output owned by this same account. Uses an entirely separate submission
   * pipeline from `execute()`: the SDK's `StealthTransfer` builder produces its own
   * `TransactionEnvelope` directly (via `WalletStealthAuthorizer`/`AuthorizedTransfer`), not
   * through `TransactionBuilder`/`resolveTransaction`/`signTransaction`/`sealTransaction`.
   *
   * The one genuinely new failure mode this adds beyond `send()`: if the extension's service
   * worker is killed *after* the transaction finalizes on-chain but *before* the resulting
   * commitment is written to storage, the shield succeeds financially but the wallet loses its
   * only lead back to that output — worse than a failed `send()`, whose destination is always a
   * known component address. `pendingShieldTransactionIds` (written before polling, cleared only
   * after the commitment record is stored) narrows that window to "killed between finalization
   * and one storage write" and gives `recoverPendingShields()` (background/index.ts) something
   * to reconcile on next launch.
   *
   * `maxFee` defaults far higher than `send()`'s 5000 -- confirmed live that 5000 gets
   * "AcceptFeeRejectRest" with `ExecutionFailure: "Insufficient fees to fund native
   * verification"` (the stealth balance proof / range proof verification costs real compute
   * points beyond the engine's free grace allowance). Unused fee is refunded on success, so
   * erring high just wastes nothing; erring low burns the small fee-intent cost with nothing to
   * show for it, since only the fee half of the transaction gets committed.
   */
  async shield(
    resourceAddress: string,
    amount: bigint,
    maxFee = 50000n,
    memo?: string,
    minimumValuePromise = 0n,
  ): Promise<{ transactionId: string; commitment: string; substateId: string; minimumValuePromise: string }> {
    assertValidMinimumValuePromise(minimumValuePromise, amount);
    const accountId = localAccountId(this.index);
    const provider = await this.getProvider();
    const account = await this.getComponentAddress();
    // Output.destination decodes as a bech32m wallet address (owner_key + view_key), NOT the
    // on-chain component address -- passing `account` here throws "Bech32 decode error" (confirmed
    // live). See getWalletAddress()'s doc comment for why these two addresses are easy to conflate.
    const walletAddress = await this.getWalletAddress();

    const spec = await new StealthTransfer(provider, resourceAddress)
      // StealthTransfer.prepare() auto-adds the revealed account's own substate and any vault
      // addresses embedded in its on-chain state, but never the resource's own substate -- fine
      // for XTR (resource_0101...0101 is engine-special-cased and needs no lock), but any other
      // resource's instructions fail with "SubstateNotFound: resource_... not found" at
      // instruction #1 without it explicitly pinned here. Confirmed directly against prepare()'s
      // source (node_modules/@tari-project/ootle/dist/index.js) -- not assumed from the docs.
      .withBuilder((b) => b.addInput({ substate_id: resourceAddress, version: null }))
      .spendRevealedInput(account, amount)
      .toStealthOutput(createOutput({ destination: walletAddress, amount, resourceAddress, memo: toMemo(memo), minimumValuePromise }))
      .payFeeFromRevealed(maxFee)
      .prepare();
    const ownCommitment = extractOutputCommitment(spec, 0);

    const wallet = new OotleWallet().registerKeyProvider(account, this.signer).setDefaultSigner(account);
    // No stealth inputs to unblind for a shield (revealed-only source), so no viewSecret needed.
    // `fromSpec`'s own default crypto is `new WasmStealthCrypto()` -- Network.LocalNet, NOT this
    // account's real network -- which produced an "Invalid transaction signature" server-side
    // rejection (confirmed live) since the balance proof it computes is network-domain-separated.
    // Must match the network StealthTransfer itself used when it built the outputs statement.
    const authorized = await WalletStealthAuthorizer.fromSpec(wallet, spec, { crypto: new WasmStealthCrypto(this.network) }).prepare(
      provider
    );
    const envelope = await authorized.seal();
    const transactionId = await submitTransaction(provider, envelope);

    await addPendingShield({ transactionId, accountId, resourceAddress, amount: amount.toString(), ownCommitment, memo });
    try {
      const response = await withTimeout(pollTransactionResult(provider, transactionId), 60_000, "submitting the shield transaction");
      await recordKnownVersions(response);
      await recordKnownShieldedOutput(accountId, resourceAddress, ownCommitment, amount, transactionId, memo);
    } finally {
      await removePendingShield(transactionId);
    }
    // The commitment and its substate id are returned, not just the transaction id, because they are
    // the only durable handle on the output this created -- and with a non-zero
    // `minimumValuePromise` that substate *is* the proof-of-funds artifact, which a caller cannot
    // reconstruct from a transaction id alone. Returned unconditionally (a zero promise included)
    // rather than only for the proof case, so callers get one shape to handle.
    return { transactionId, commitment: ownCommitment, substateId: stealthUtxoSubstateId(resourceAddress, fromHex(ownCommitment)), minimumValuePromise: minimumValuePromise.toString() };
  }

  /**
   * Proves this account currently controls the stealth output at `substateId` -- e.g. a
   * `minimumValuePromise` proof-of-funds output this account created earlier -- by Schnorr-signing
   * `challenge` with the output's one-time spend key. Spends nothing and reveals nothing about the
   * output beyond what `tari_getSubstate` already shows anyone.
   *
   * `challenge` is signed under a domain tag (`ownershipProof.ts`) disjoint from real transaction
   * signing, so the resulting signature can never be replayed as spend authorization for this or
   * any other output -- this is the entire reason a caller cannot just ask for a raw signature over
   * an arbitrary message.
   *
   * Throws if the substate isn't a live, key-authorized stealth output, or if it isn't actually
   * addressed to this account (checked by re-deriving the expected one-time public key and
   * comparing it to the substate's own `auth.Key` -- the same check `scan_stealth_output` does
   * receiver-side, just run here against a specific caller-supplied id instead of a scan).
   */
  async signOwnershipProof(
    resourceAddress: string,
    substateId: string,
    challenge: string,
  ): Promise<{ publicKey: string; publicNonce: string; signature: string }> {
    const provider = await this.getProvider();
    const response = await provider.getSubstate(substateId);
    const substate = response.substate as unknown as { Utxo?: { output: { output: OutputBody; auth: { Key?: string } } | null } };
    const utxo = substate.Utxo;
    if (!utxo?.output) {
      throw new Error("This output doesn't exist, isn't a stealth output, or has already been spent.");
    }
    const expectedAuthKeyHex = utxo.output.auth.Key;
    if (!expectedAuthKeyHex) {
      throw new Error("This output isn't key-authorized (it's spent by a script condition, not a signature) -- there's no key to prove ownership of.");
    }

    const senderPublicNonce = fromHex(utxo.output.output.public_nonce);
    const oneTimeSecret = stealthDhSecret(this.network, this.ownerSecret, senderPublicNonce);
    try {
      const oneTimePublicKey = publicKeyFromSecretKey(oneTimeSecret);
      if (toHex(oneTimePublicKey) !== expectedAuthKeyHex) {
        throw new Error("This account doesn't control that output.");
      }
      const message = buildOwnershipProofMessage(this.network, resourceAddress, substateId, challenge);
      const sig = schnorrSign(oneTimeSecret, message);
      return { publicKey: toHex(oneTimePublicKey), publicNonce: toHex(sig.public_nonce), signature: toHex(sig.signature) };
    } finally {
      oneTimeSecret.fill(0); // a derived per-output secret, not the account's own key -- zeroed anyway, on principle
    }
  }

  /**
   * Proves this account holds a specific `otl_…` wallet address by Schnorr-signing `challenge`
   * with the account's own persistent owner key -- not a per-output derived one, so unlike
   * `signOwnershipProof` this needs no substate lookup and isn't tied to any particular output.
   *
   * Signs under a domain tag (`ownershipProof.ts`) disjoint from real transaction signing, for the
   * same reason `signOwnershipProof` does: this exact key also signs real transactions
   * (`SecretKeyWallet.signTransaction`), so a raw signature over caller-supplied bytes would risk
   * being replayable as spend authorization.
   *
   * A verifier checks the result against the owner key decoded from the wallet address *they*
   * already have in mind (`parseOotleAddress`) -- never against a value this call's caller reports
   * about themselves.
   */
  async signWalletOwnership(challenge: string): Promise<{ walletAddress: string; publicNonce: string; signature: string }> {
    const walletAddress = await this.getWalletAddress();
    const message = buildWalletOwnershipMessage(this.network, walletAddress, challenge);
    const sig = schnorrSign(this.ownerSecret, message);
    return { walletAddress, publicNonce: toHex(sig.public_nonce), signature: toHex(sig.signature) };
  }

  /**
   * Unshields (moves from private/confidential back to revealed) `revealedOutAmount` of this
   * account's shielded balance for `resourceAddress` — see `ShieldedOutputRecord`'s doc comment
   * for why a known local record is the only way to spend one (no client-side scan-by-view-key
   * API exists for stealth UTXOs). Which specific output(s) to spend is decided internally by
   * `resolveUnshieldPlan`'s coin selection (largest-first, spending more than one in the same
   * transaction via repeated `spendStealthInput()` calls if a single output isn't enough) — the
   * caller only supplies an amount, not a commitment.
   *
   * Two `StealthTransfer` builder requirements, confirmed directly against its `validate()`/
   * `emitInstructions()` source (not assumed from the docs alone), shape this method:
   *
   * 1. `toRevealedOutput`/`payFeeFromRevealed` both require a revealed source account already
   *    registered via `spendRevealedInput`, which itself requires an amount `> 0` — there is no
   *    way to register just the account without withdrawing something. This method withdraws a
   *    trivial `1n`-unit "dust" amount for that sole purpose and folds it straight back into the
   *    revealed output (`revealedOutAmount + 1n`), so it costs nothing beyond the tx fee.
   * 2. The builder always requires at least one stealth output — a "pure" 100%-revealed spend
   *    with zero private remainder cannot be constructed in one step. This method always creates
   *    a new stealth output for the selected inputs' total minus `revealedOutAmount` back to this
   *    same account, so `resolveUnshieldPlan` guarantees that remainder is always `> 0`.
   *
   * Shares `shield()`'s mid-flight crash safety: the pending-shield ledger entry carries
   * `spentCommitments` so `recoverPendingShields()` can both record the new change output *and*
   * mark the spent ones, even if the service worker dies between finalization and the storage
   * writes.
   */
  async unshield(resourceAddress: string, revealedOutAmount: bigint, maxFee = 100000n, memo?: string): Promise<{ transactionId: string }> {
    const accountId = localAccountId(this.index);
    const records = await listShieldedOutputs(accountId);
    const { commitments, remainder } = resolveUnshieldPlan(records, resourceAddress, revealedOutAmount);
    const dust = 1n;

    const provider = await this.getProvider();
    const account = await this.getComponentAddress();
    // See shield()'s comment: Output.destination needs the bech32m wallet address, not the
    // on-chain component address.
    const walletAddress = await this.getWalletAddress();

    // See shield()'s comment: the resource's own substate must be pinned explicitly -- prepare()
    // never adds it on its own.
    let builder = new StealthTransfer(provider, resourceAddress)
      .withBuilder((b) => b.addInput({ substate_id: resourceAddress, version: null }))
      .spendRevealedInput(account, dust);
    for (const commitment of commitments) {
      builder = builder.spendStealthInput(account, fromHex(commitment));
    }
    const spec = await builder
      .toStealthOutput(createOutput({ destination: walletAddress, amount: remainder, resourceAddress, memo: toMemo(memo) }))
      .toRevealedOutput(revealedOutAmount + dust)
      .payFeeFromRevealed(maxFee)
      .prepare();
    const ownCommitment = extractOutputCommitment(spec, 0);

    const wallet = new OotleWallet().registerKeyProvider(account, this.signer).setDefaultSigner(account);
    const viewSecret = await this.signer.getViewSecret();
    // See shield()'s comment: must pass this account's real network, not fromSpec's LocalNet default.
    const authorized = await WalletStealthAuthorizer.fromSpec(wallet, spec, { viewSecret, crypto: new WasmStealthCrypto(this.network) }).prepare(
      provider
    );
    const envelope = await authorized.seal();
    const transactionId = await submitTransaction(provider, envelope);

    await addPendingShield({
      transactionId,
      accountId,
      resourceAddress,
      amount: remainder.toString(),
      spentCommitments: commitments,
      ownCommitment,
      memo,
    });
    try {
      const response = await withTimeout(pollTransactionResult(provider, transactionId), 60_000, "submitting the unshield transaction");
      await recordKnownVersions(response);
      await recordKnownShieldedOutput(accountId, resourceAddress, ownCommitment, remainder, transactionId, memo);
      for (const commitment of commitments) {
        await markShieldedOutputSpent(accountId, commitment);
      }
    } finally {
      await removePendingShield(transactionId);
    }
    return { transactionId };
  }

  /**
   * Withdraws `amount` of a Stealth-typed resource (e.g. XTR) from this account's revealed
   * balance and feeds it, as a `Bucket` left on the workspace under `workspaceVarName`, into
   * `followUpInstructions` — all in one signed transaction.
   *
   * This is the *only* way to move Stealth-typed funds into an arbitrary contract call. A plain
   * `CallMethod withdraw` on a Stealth vault is not a standalone-valid instruction: confirmed
   * empirically (isolated to a bare `withdraw` immediately followed by `deposit`, zero other
   * instructions) that `account.execute()` fails it client-side, before ever reaching the
   * network, with a generic `JSON deserialization failed: ... untagged enum TransactionInput`
   * error. Moving Stealth funds anywhere always requires the native `StealthTransfer`
   * instruction, signed via `WalletStealthAuthorizer` — which `execute()`/`TransactionBuilder`
   * never invokes (see this file's own `execute()` doc comment, and the
   * `isStealthTransferInstruction` guard + comment in `background/index.ts`). This method uses
   * the *same* `StealthTransfer` builder + `WalletStealthAuthorizer` pipeline `shield()`/
   * `unshield()` already use, extended with `toRevealedOutputAsBucket`/`andThen` (see
   * `vendor/ootle-patched/README.md`) to leave the revealed output on the workspace instead of
   * auto-depositing it back to this account, and to append the caller's own instructions after
   * it in the same transaction.
   *
   * @param relatedComponents Every *other* component `followUpInstructions` touches (e.g. a
   *   DAO contract being called). The `StealthTransfer` builder auto-registers this account's
   *   own vaults as tx inputs, but has no way to know what the caller's own follow-up
   *   instructions reference — the engine rejects a `CallMethod` touching an unregistered
   *   substate with `SubstateNotFound`. Each is registered by address, plus every vault its own
   *   state references (the same vault-discovery this account's own address already gets).
   */
  async withdrawStealthAndExecute(
    resourceAddress: string,
    amount: bigint,
    workspaceVarName: string,
    followUpInstructions: Instruction[],
    relatedComponents: string[] = [],
    maxFee = 100000n
  ): Promise<{ transactionId: string }> {
    if (amount <= 0n) throw new Error(`withdrawStealthAndExecute amount must be > 0, got ${amount}`);
    const provider = await this.getProvider();
    const account = await this.getComponentAddress();
    const walletAddress = await this.getWalletAddress();
    // A zero-stealth-output StealthTransferStatement (pure revealed-in, revealed-out-as-bucket)
    // isn't a shape the bundled ootle-wasm@0.37.0 signer can parse -- confirmed live: it throws
    // the same generic "did not match any variant of untagged enum TransactionInput" error inside
    // signTransaction's own WASM call, regardless of how balance_proof is represented (present,
    // null, or omitted -- all three tried). Every other stealth-transfer path in this file
    // (shield/unshield/sendPrivately) always includes >=1 real stealth output for exactly this
    // reason. Rather than fight an apparent WASM-binary limitation, this keeps a tiny (1 µ-unit)
    // stealth output back to this account -- the same proven-working shape -- alongside the real
    // amount as a revealed bucket.
    const dust = 1n;

    let builder = new StealthTransfer(provider, resourceAddress)
      .withBuilder((b) => b.addInput({ substate_id: resourceAddress, version: null }))
      .spendRevealedInput(account, amount + dust)
      .toStealthOutput(createOutput({ destination: walletAddress, amount: dust, resourceAddress }))
      .toRevealedOutputAsBucket(amount, workspaceVarName)
      .andThen(followUpInstructions);
    for (const component of relatedComponents) {
      builder = builder.withBuilder((b) => b.addInput({ substate_id: component, version: null }));
      for (const vaultId of await getVaultIdsForAccount(provider, component)) {
        builder = builder.withBuilder((b) => b.addInput({ substate_id: vaultId, version: null }));
      }
    }
    const spec = await builder.payFeeFromRevealed(maxFee).prepare();

    const wallet = new OotleWallet().registerKeyProvider(account, this.signer).setDefaultSigner(account);
    const viewSecret = await this.signer.getViewSecret();
    const authorized = await WalletStealthAuthorizer.fromSpec(wallet, spec, { viewSecret, crypto: new WasmStealthCrypto(this.network) }).prepare(
      provider
    );
    const envelope = await authorized.seal();
    const transactionId = await submitTransaction(provider, envelope);
    const response = await withTimeout(pollTransactionResult(provider, transactionId), 60_000, "submitting the transaction");
    await recordKnownVersions(response);
    return { transactionId };
  }

  /**
   * Redeems one *specific, externally-known* stealth (freestanding) UTXO — a commitment this
   * account was told about out of band (e.g. a ticket/ballot/voucher token some other party
   * minted straight to this wallet's address), as opposed to `withdrawStealthAndExecute`'s
   * *amount* drawn from this account's own tracked vault balance. Reveals the output's full
   * value as a `Bucket` on the workspace under id `0`, then runs `followUpInstructions` (which
   * must reference that bucket via `{Workspace: {id: 0, offset: null}}`) in the same signed
   * transaction — e.g. handing it straight to a voting/redemption contract's own method.
   *
   * `revealedAmount` must be the output's *actual* value — there is no client-side way to
   * discover it other than decrypting the UTXO (which this method's `WalletStealthAuthorizer`
   * step does internally, using this account's own view secret, as part of resolving the
   * spend); the caller is expected to already know it from whatever protocol minted the token
   * (e.g. a fixed "amount-1 ballot" convention). A wrong value fails the balance proof inside
   * `prepare()`, not silently.
   *
   * Bypasses the `StealthTransfer` fluent builder (its `spendStealthInput` targets *this
   * account's own* previously-shielded outputs, tracked in local storage — see `unshield`'s doc
   * comment on why no scan-by-commitment API exists for outputs this account never shielded
   * itself) and instead hand-builds the same wire statement `unshield`/`shield`/
   * `withdrawStealthAndExecute` produce via the builder, the same way the reference voter
   * client for this pattern does (a zero-stealth-input-count, `KeyPath`-witnessed, fully-revealed
   * transfer) — `WalletStealthAuthorizer.prepare()` fetches and unblinds the named commitment the
   * same way regardless of which path built the statement.
   *
   * @param relatedComponents Every *other* component `followUpInstructions` touches — same
   *   reasoning as `withdrawStealthAndExecute`'s own parameter of the same name.
   */
  async redeemStealthOutputAndExecute(
    resourceAddress: string,
    commitmentHex: string,
    revealedAmount: bigint,
    followUpInstructions: Instruction[],
    relatedComponents: string[] = [],
    maxFee = 100000n
  ): Promise<{ transactionId: string }> {
    if (revealedAmount <= 0n) {
      throw new Error(`redeemStealthOutputAndExecute: revealedAmount must be > 0, got ${revealedAmount}`);
    }
    if (!/^[0-9a-f]{64}$/i.test(commitmentHex)) {
      throw new Error(`redeemStealthOutputAndExecute: commitmentHex must be exactly 64 hex characters (32 bytes)`);
    }
    const provider = await this.getProvider();
    const account = await this.getComponentAddress();
    const commitment = fromHex(commitmentHex);

    // An "incomplete" statement: the input side only names the commitment being spent (its mask
    // and value are recovered later, by the authorizer, from the on-chain UTXO) and declares a
    // `KeyPath` witness — ordinary one-time-key ownership, the same proof shield/unshield/
    // withdrawStealthAndExecute use, as opposed to htlcClaim/htlcRefund's script-path leaf. The
    // output side is empty (no new stealth output at all): the full value is revealed instead.
    const inputsJson = JSON.stringify({
      inputs: [{ commitment: commitmentHex, witness: "KeyPath" }],
      revealed_amount: "0",
    });
    const outputsJson = JSON.stringify({
      outputs: [],
      revealed_output_amount: revealedAmount.toString(),
      agg_range_proof: "",
    });
    const statement = new StealthTransferStatement(
      new StealthInputsStatement([], 0n, inputsJson),
      new StealthOutputsStatement(outputsJson)
    );

    const maxEpoch = await resolveMaxEpoch(provider);
    const builder = TransactionBuilder.new(this.network, maxEpoch)
      .addInstruction({
        StealthTransfer: {
          resource_address_ref: { Address: resourceAddress },
          statement: { __ootleRawJson: statement.toCompactJson() },
          revealed_input_bucket: null,
        },
      } as unknown as Instruction)
      // Claims workspace id 0 for the revealed bucket above — followUpInstructions must reference
      // it as a plain numeric `{Workspace: {id: 0, offset: null}}`, not a named `{Workspace: ".."}`
      // (name resolution only applies to instructions built through *this* same chain; raw
      // pre-built instructions bypass it, same constraint `withdrawStealthAndExecute` documents).
      .saveVar("redeemed")
      .withInstructions(followUpInstructions)
      .feeTransactionPayFromComponent(account, maxFee)
      .addInput({ substate_id: resourceAddress, version: null })
      .addInput({ substate_id: stealthUtxoSubstateId(resourceAddress, commitment), version: null })
      .addInput({ substate_id: account, version: null });
    for (const vaultId of await getVaultIdsForAccount(provider, account)) {
      builder.addInput({ substate_id: vaultId, version: null });
    }
    for (const component of relatedComponents) {
      builder.addInput({ substate_id: component, version: null });
      for (const vaultId of await getVaultIdsForAccount(provider, component)) {
        builder.addInput({ substate_id: vaultId, version: null });
      }
    }
    const unsignedTx = await resolveTransaction(provider, builder.buildUnsignedTransaction());

    const spec: StealthTransferSpec = {
      unsignedTx,
      statement,
      outputMask: Mask.zero(),
      state: {
        resource: resourceAddress,
        revealedInput: null,
        inputsToSpend: new Map([[commitmentHex, { input: new StealthInput(commitment), owner: account }]]),
        outputs: [],
        revealedOutputAmount: revealedAmount,
      },
      requiredSigners: [account],
      inputs: [{ input: new StealthInput(commitment), owner: account }],
    };

    const wallet = new OotleWallet().registerKeyProvider(account, this.signer).setDefaultSigner(account);
    const viewSecret = await this.signer.getViewSecret();
    const authorized = await WalletStealthAuthorizer.fromSpec(wallet, spec, { viewSecret, crypto: new WasmStealthCrypto(this.network) }).prepare(
      provider
    );
    const envelope = await authorized.seal();
    const transactionId = await submitTransaction(provider, envelope);
    const response = await withTimeout(pollTransactionResult(provider, transactionId), 60_000, "submitting the redemption transaction");
    await recordKnownVersions(response);
    return { transactionId };
  }

  /**
   * Like `redeemStealthOutputAndExecute`, but pays the transaction fee from a **second stealth
   * UTXO** instead of this account's revealed balance — so the transaction never touches, and
   * never reveals, this account's on-chain address at all. Confirmed live: the resulting
   * transaction's `up_substates`/`down_substates` contain only the two stealth UTXOs, the
   * redeemed resource, and whatever `relatedComponents` touch — no `component_...` belonging to
   * this account appears anywhere in it.
   *
   * Required whenever the follow-up call itself carries information that would deanonymize the
   * account if the fee input did (e.g. a voting ballot's ranking): a revealed fee input signs
   * with this account's ordinary key, which links the transaction to the account exactly as
   * plainly as if the whole thing were sent unshielded — see the confidential-rcv-template
   * README's "Fee-from-stealth requirement (MUST)" for the canonical explanation.
   *
   * Both stealth inputs are spent via the same mechanism `redeemStealthOutputAndExecute` uses
   * (KeyPath one-time-key ownership, resolved by decrypting each UTXO with this account's own
   * view secret) — this method just does it twice, for two independent `StealthTransfer`
   * instructions in the same transaction: the redeemed resource's spend carries the follow-up
   * call (main instructions), the fee resource's spend carries `PayFeeFromBucket` (fee
   * instructions, its own separate workspace scope — same convention as `followUpInstructions`,
   * claims workspace id `0` there too).
   *
   * Neither stealth input's one-time key seals the transaction in the sense the protocol's
   * `stealth_seal_with` API suggests one must — empirically (and consistent with how every other
   * stealth-spending method in this file already works), the network accepts a transaction sealed
   * by an arbitrary throwaway keypair as long as every stealth input's one-time-key authorization
   * is signed with respect to that same seal key; `signTransaction` generates one automatically.
   * Deliberately **omits** this account's own ordinary signature entirely (unlike every other
   * stealth-spending method here, which signs with `mustSignWithAccountKey: true` by default) —
   * adding it would attach the account's ordinary public key to the transaction, defeating the
   * entire point of a stealth-funded fee.
   *
   * @param feeResourceAddress The fee-currency resource (almost always XTR/TARI).
   * @param feeCommitmentHex A stealth UTXO of `feeResourceAddress` this account owns, with
   *   enough value to cover `maxFee` — e.g. produced by this account's own `shield()` call
   *   against `feeResourceAddress`. Consumed in full; the remainder above `maxFee` becomes a new
   *   stealth change output back to this account.
   * @returns `feeChangeCommitment` — the new stealth UTXO holding the fee input's unspent
   *   remainder. There is no way to discover it other than being told, same as any other stealth
   *   output belonging to this account that wasn't created by this account's own `shield()`
   *   (which records its own outputs locally) — callers doing several of these in sequence must
   *   thread this value into the next call's `feeCommitmentHex` themselves.
   */
  async redeemStealthOutputWithPrivateFee(
    resourceAddress: string,
    commitmentHex: string,
    revealedAmount: bigint,
    followUpInstructions: Instruction[],
    feeResourceAddress: string,
    feeCommitmentHex: string,
    maxFee: bigint,
    relatedComponents: string[] = []
  ): Promise<{ transactionId: string; feeChangeCommitment: string }> {
    if (revealedAmount <= 0n) throw new Error(`redeemStealthOutputWithPrivateFee: revealedAmount must be > 0, got ${revealedAmount}`);
    if (maxFee <= 0n) throw new Error(`redeemStealthOutputWithPrivateFee: maxFee must be > 0, got ${maxFee}`);
    const provider = await this.getProvider();
    const crypto = new WasmStealthCrypto(this.network);
    const walletAddress = await this.getWalletAddress();
    const viewSecret = await this.signer.getViewSecret();

    const decryptStealthInput = async (resource: string, commitmentHexIn: string) => {
      const commitment = fromHex(commitmentHexIn);
      const substateId = stealthUtxoSubstateId(resource, commitment);
      const substate = await provider.getSubstate(substateId);
      const decrypted = await decryptOwnedUtxo(crypto, viewSecret, substate, substateId);
      if (!decrypted) {
        throw new Error(`redeemStealthOutputWithPrivateFee: cannot decrypt ${substateId} -- it doesn't belong to this account, or is already spent.`);
      }
      return { commitmentHex: commitmentHexIn, substateId, mask: decrypted.mask, value: decrypted.value };
    };

    const redeemed = await decryptStealthInput(resourceAddress, commitmentHex);
    const feeInput = await decryptStealthInput(feeResourceAddress, feeCommitmentHex);
    if (feeInput.value <= maxFee) {
      throw new Error(`redeemStealthOutputWithPrivateFee: fee UTXO (${feeInput.value}) is too small to cover maxFee (${maxFee})`);
    }
    const feeChange = feeInput.value - maxFee;

    const inputSkeleton = (hex: string) => JSON.stringify({ inputs: [{ commitment: hex, witness: "KeyPath" }], revealed_amount: "0" });

    // Redeemed resource: 1 stealth input -> 0 stealth outputs, fully revealed into the bucket
    // `followUpInstructions` consumes.
    const redeemedInputsStatement = new StealthInputsStatement([], 0n, inputSkeleton(redeemed.commitmentHex));
    const redeemedOutputsStatement = new StealthOutputsStatement(
      JSON.stringify({ outputs: [], revealed_output_amount: revealedAmount.toString(), agg_range_proof: "" })
    );
    const redeemedAggInputMask = await crypto.aggregateInputMasks([redeemed.mask]);
    const redeemedBalanceProof = await crypto.generateBalanceProofSignature(
      redeemedAggInputMask,
      Mask.zero(),
      redeemedInputsStatement.statementJson!,
      redeemedOutputsStatement.statementJson
    );
    const redeemedStatement = new StealthTransferStatement(redeemedInputsStatement, redeemedOutputsStatement, redeemedBalanceProof);
    await crypto.validateTransfer(redeemedStatement);

    // Fee resource: 1 stealth input -> 1 stealth change output + revealed maxFee.
    const feeChangeOutput = createOutput({ destination: walletAddress, amount: feeChange, resourceAddress: feeResourceAddress });
    const { statement: feeOutputsStatement, outputMask: feeOutputMask } = await crypto.generateOutputsStatement([feeChangeOutput], maxFee);
    const feeInputsStatement = new StealthInputsStatement([], 0n, inputSkeleton(feeInput.commitmentHex));
    const feeAggInputMask = await crypto.aggregateInputMasks([feeInput.mask]);
    const feeBalanceProof = await crypto.generateBalanceProofSignature(
      feeAggInputMask,
      feeOutputMask,
      feeInputsStatement.statementJson!,
      feeOutputsStatement.statementJson
    );
    const feeStatement = new StealthTransferStatement(feeInputsStatement, feeOutputsStatement, feeBalanceProof);
    await crypto.validateTransfer(feeStatement);
    const feeChangeCommitment = (feeOutputsStatement.parsed() as { outputs: { output: { commitment: string } }[] }).outputs[0]!.output.commitment;

    const maxEpoch = await resolveMaxEpoch(provider);
    const builder = TransactionBuilder.new(this.network, maxEpoch)
      .addInstruction({
        StealthTransfer: {
          resource_address_ref: { Address: resourceAddress },
          statement: { __ootleRawJson: redeemedStatement.toCompactJson() },
          revealed_input_bucket: null,
        },
      } as unknown as Instruction)
      .addInstruction({ PutLastInstructionOutputOnWorkspace: { key: 0 } } as unknown as Instruction)
      .withInstructions(followUpInstructions)
      .addFeeInstruction({
        StealthTransfer: {
          resource_address_ref: { Address: feeResourceAddress },
          statement: { __ootleRawJson: feeStatement.toCompactJson() },
          revealed_input_bucket: null,
        },
      } as unknown as Instruction)
      .addFeeInstruction({ PutLastInstructionOutputOnWorkspace: { key: 0 } } as unknown as Instruction)
      .addFeeInstruction({ PayFeeFromBucket: { bucket: { id: 0, offset: null } } } as unknown as Instruction)
      .addInput({ substate_id: resourceAddress, version: null })
      .addInput({ substate_id: redeemed.substateId, version: null })
      .addInput({ substate_id: feeResourceAddress, version: null })
      .addInput({ substate_id: feeInput.substateId, version: null });
    for (const component of relatedComponents) {
      builder.addInput({ substate_id: component, version: null });
      for (const vaultId of await getVaultIdsForAccount(provider, component)) {
        builder.addInput({ substate_id: vaultId, version: null });
      }
    }
    const unsignedTx = await resolveTransaction(provider, builder.buildUnsignedTransaction());

    // One addStealthSignature per stealth input, bound to a shared (arbitrary) seal key that
    // signTransaction generates -- see this method's own doc comment for why no ordinary
    // account-key signature is added.
    const oneTimeSigner = (publicNonceHex: string) => ({
      getAddress: async () => walletAddress,
      getPublicKey: async () => parseOotleAddress(walletAddress).owner_key,
      signTransaction: async (tx: UnsignedTransactionWithBlobs, sealPublicKey: Uint8Array) => {
        const json = serializeUnsignedTx(tx);
        const sig = await this.signer.addStealthSignature!(json, fromHex(publicNonceHex), sealPublicKey, { crypto });
        return [sig];
      },
    });
    // Each stealth input's own sender_public_nonce lives on its UTXO substate -- fetched again
    // here (decryptOwnedUtxo above didn't return it) rather than parsed out of the substate
    // response type, whose shape `decryptOwnedUtxo` already validated once.
    const redeemedSubstate = await provider.getSubstate(redeemed.substateId);
    const feeInputSubstate = await provider.getSubstate(feeInput.substateId);
    const redeemedNonce = (redeemedSubstate as unknown as { substate: { Utxo: { output: { output: { public_nonce: string } } } } }).substate.Utxo
      .output.output.public_nonce;
    const feeNonce = (feeInputSubstate as unknown as { substate: { Utxo: { output: { output: { public_nonce: string } } } } }).substate.Utxo.output
      .output.public_nonce;

    const signed = await signTransaction([oneTimeSigner(redeemedNonce), oneTimeSigner(feeNonce)], unsignedTx);
    const envelope = sealTransaction(signed);
    const transactionId = await submitTransaction(provider, envelope);
    const response = await withTimeout(pollTransactionResult(provider, transactionId), 60_000, "submitting the private-fee redemption transaction");
    await recordKnownVersions(response);
    return { transactionId, feeChangeCommitment };
  }

  /**
   * Funds an HTLC (hashed timelock contract): creates a stealth output for `amount` of
   * `resourceAddress`, gated not by a normal one-time stealth key but by a two-leaf TIP-0006
   * condition tree (`htlcConditions` in `./htlc.ts`) — a claim path admissible only to
   * `claimantWalletAddress` (revealing the SHA-256 preimage of `hashLockHex`, before
   * `refundEpoch`), and a refund path admissible only to this account (at/after `refundEpoch`).
   * `htlcConditions`'s own doc comment covers the exact leaf shapes.
   *
   * This account never needs (and must never be given) the actual preimage — only its hash. The
   * caller resolves `refundEpoch` from a desired wall-clock deadline via the provider/network's
   * current epoch, the same as any other epoch-relative on-chain deadline.
   *
   * Returns the full `conditions` tree alongside the transaction id and this output's own
   * commitment: only the tree's **root** is committed on-chain, so the claimant needs the exact
   * leaves — out of band, via whatever swap protocol coordinates the two sides — to later reveal
   * the claim leaf.
   *
   * Also returns `outputMask` (hex): this account funded the output, so it's the one place the
   * blinding mask is ever available to it without decryption — `encrypted_data` is encrypted for
   * `claimantWalletAddress`'s view key, not this account's, so if the claim path is never taken
   * and this account later calls `htlcRefund`, it cannot decrypt the output the normal way (the
   * way `htlcClaim`'s claimant can, since the output is addressed to *them*). Retaining this mask
   * now — alongside the known `amount` — is what makes an undecryptable refund possible at all.
   * `htlcRefund`'s own doc comment covers the rest.
   *
   * `destination` is set to the claimant's own wallet address (not this account's) so the
   * claimant can independently decrypt and verify the funded amount themselves, the same as any
   * other stealth payment addressed to them — spend authority is governed entirely separately, by
   * `payTo`.
   */
  async htlcFund(
    resourceAddress: string,
    amount: bigint,
    claimantWalletAddress: string,
    hashLockHex: string,
    refundEpoch: bigint,
    maxFee = 50000n
  ): Promise<{ transactionId: string; conditions: object[]; ownCommitment: string; outputMask: string }> {
    const provider = await this.getProvider();
    const account = await this.getComponentAddress();
    const walletAddress = await this.getWalletAddress();

    const claimant = parseOotleAddress(claimantWalletAddress);
    const refunder = parseOotleAddress(walletAddress);
    const conditions = htlcConditions({
      hashLockHex,
      refundEpoch,
      claimantPublicKeyHex: toHex(claimant.owner_key),
      refunderPublicKeyHex: toHex(refunder.owner_key),
    });

    // See shield()'s comment: the resource's own substate must be pinned explicitly -- prepare()
    // never adds it on its own.
    const spec = await new StealthTransfer(provider, resourceAddress)
      .withBuilder((b) => b.addInput({ substate_id: resourceAddress, version: null }))
      .spendRevealedInput(account, amount)
      .toStealthOutput(
        createOutput({ destination: claimantWalletAddress, amount, resourceAddress, payTo: { Conditions: conditions } })
      )
      .payFeeFromRevealed(maxFee)
      .prepare();
    const ownCommitment = extractOutputCommitment(spec, 0);
    const outputMask = spec.outputMask.toHex();

    const wallet = new OotleWallet().registerKeyProvider(account, this.signer).setDefaultSigner(account);
    // No stealth inputs to unblind (revealed-only source), so no viewSecret needed -- same as shield().
    const authorized = await WalletStealthAuthorizer.fromSpec(wallet, spec, { crypto: new WasmStealthCrypto(this.network) }).prepare(
      provider
    );
    const envelope = await authorized.seal();
    const transactionId = await submitTransaction(provider, envelope);

    const response = await withTimeout(
      pollTransactionResult(provider, transactionId),
      60_000,
      "submitting the HTLC funding transaction"
    );
    await recordKnownVersions(response);
    return { transactionId, conditions, ownCommitment, outputMask };
  }

  /**
   * Claims a funded HTLC (the counterpart to `htlcFund`): reveals the claim leaf's SHA-256
   * preimage to spend the script-path-locked output, moving `amount` into a brand-new, normal
   * (freely key-spendable) stealth output owned by this account.
   *
   * This account must be the intended claimant — `htlcFund` addressed the output to this
   * account's own wallet address, so it can unblind it the normal way: fetch the `utxo_...`
   * substate and decrypt with this account's own view secret, exactly like `claimPrivatePayment`
   * does for any other incoming stealth payment. `conditions` must be the *exact* two-leaf tree
   * `htlcFund` returned (or was handed out of band) — the wrong tree produces a script-path
   * witness whose condition root won't match the output's committed `SpendAuthorization::Script`
   * root, and `buildStealthTransferStatement`/the network both reject the spend.
   *
   * Fees are paid from this account's own existing revealed balance via `pay_fee` (same as any
   * other transaction this wallet submits), not from the claimed HTLC funds — a transaction's fee
   * instructions execute in a separate phase *before* its main instructions, so the claim's own
   * `StealthTransfer` instruction (a main instruction) can't fund its own fee even in principle.
   *
   * Bypasses `StealthTransfer`/`WalletStealthAuthorizer` entirely — that builder pipeline only
   * ever produces key-path stealth inputs (a one-time DH signature per input), which doesn't
   * apply here: this spend's authorization is the revealed script-path leaf itself (its
   * `AccessRule` atom, satisfied by this account's normal transaction signature), not a stealth
   * spend key. `buildStealthTransferStatement` (tari-project/tari-ootle#2431) produces the
   * complete statement — inputs/outputs/balance proof/covenant claims — in one call from the
   * unblinded mask+value and the two witnesses below, so there is nothing left for the builder
   * pipeline to add.
   */
  async htlcClaim(
    resourceAddress: string,
    commitmentHex: string,
    conditions: object[],
    preimageHex: string,
    maxFee = 50000n
  ): Promise<{ transactionId: string }> {
    if (!/^[0-9a-f]{64}$/i.test(preimageHex)) {
      throw new Error(`htlcClaim: preimageHex must be exactly 64 hex characters (32 bytes), got ${JSON.stringify(preimageHex)}`);
    }
    const provider = await this.getProvider();
    const account = await this.getComponentAddress();
    const walletAddress = await this.getWalletAddress();
    const commitment = fromHex(commitmentHex);
    const substateId = stealthUtxoSubstateId(resourceAddress, commitment);

    const substate = await provider.getSubstate(substateId);
    const viewSecret = await this.signer.getViewSecret();
    const decrypted = await decryptOwnedUtxo(new WasmStealthCrypto(this.network), viewSecret, substate, substateId);
    if (!decrypted) {
      throw new Error(
        "This HTLC output doesn't belong to your account, or wasn't found on-chain — it may already be claimed or refunded."
      );
    }

    const claimLeaf = conditions[0];
    if (!claimLeaf) throw new Error("htlcClaim: conditions must be the two-leaf [claim, refund] tree htlcFund returned");
    const statementJson = buildHtlcSpendStatement({
      network: this.network,
      conditions,
      leaf: claimLeaf,
      data: fromHex(preimageHex),
      mask: decrypted.mask.toHex(),
      value: decrypted.value,
      destinationWalletAddress: walletAddress,
      resourceAddress,
    });

    const transactionId = await submitHtlcSpend({
      provider,
      signer: this.signer,
      network: this.network,
      account,
      resourceAddress,
      substateId,
      statementJson,
      maxFee,
      timeoutLabel: "submitting the HTLC claim transaction",
    });
    return { transactionId };
  }

  /**
   * Refunds an HTLC this account itself funded (via `htlcFund`), once `refundEpoch` has passed:
   * reveals the refund leaf to spend the output back into a brand-new, normal (freely
   * key-spendable) stealth output owned by this account.
   *
   * Unlike `htlcClaim`, this account **cannot** decrypt the output on-chain — `htlcFund` addressed
   * it to the claimant's wallet, so `encrypted_data` is encrypted for the claimant's view key, not
   * this account's. `amount` and `outputMaskHex` must be exactly what `htlcFund` returned (or
   * otherwise already known — this account chose `amount` itself when funding, and `outputMaskHex`
   * is `htlcFund`'s own return value for exactly this purpose): reconstructing the commitment from
   * a wrong mask or amount fails cleanly (the resulting input just doesn't match the on-chain
   * commitment, so the network rejects the spend) rather than silently, but there is no recovery
   * path if this account discarded the mask — see `htlcFund`'s doc comment.
   *
   * Otherwise identical to `htlcClaim`: same fee-from-own-balance reasoning, same
   * `buildStealthTransferStatement`-in-one-call approach, same bypass of
   * `StealthTransfer`/`WalletStealthAuthorizer`.
   */
  async htlcRefund(
    resourceAddress: string,
    commitmentHex: string,
    conditions: object[],
    amount: bigint,
    outputMaskHex: string,
    maxFee = 50000n
  ): Promise<{ transactionId: string }> {
    const provider = await this.getProvider();
    const account = await this.getComponentAddress();
    const walletAddress = await this.getWalletAddress();
    const commitment = fromHex(commitmentHex);
    const substateId = stealthUtxoSubstateId(resourceAddress, commitment);

    const refundLeaf = conditions[1];
    if (!refundLeaf) throw new Error("htlcRefund: conditions must be the two-leaf [claim, refund] tree htlcFund returned");
    const statementJson = buildHtlcSpendStatement({
      network: this.network,
      conditions,
      leaf: refundLeaf,
      data: new Uint8Array(0), // The refund leaf has no HashLock atom -- no witness data needed.
      mask: outputMaskHex,
      value: amount,
      destinationWalletAddress: walletAddress,
      resourceAddress,
    });

    const transactionId = await submitHtlcSpend({
      provider,
      signer: this.signer,
      network: this.network,
      account,
      resourceAddress,
      substateId,
      statementJson,
      maxFee,
      timeoutLabel: "submitting the HTLC refund transaction",
    });
    return { transactionId };
  }

  /**
   * Sends `amount` of this account's shielded balance for `resourceAddress` directly to
   * `recipientWalletAddress` — a private-to-private transfer, unlike `shield()` (which always
   * targets this same account's own wallet address). The recipient never appears on-chain in the
   * clear; only they (holding the matching view key) can discover the payment, and only by being
   * told the resulting commitment out of band — same "no scan API" caveat as everywhere else
   * stealth outputs are spent. Which specific output(s) to spend is decided internally by
   * `resolveSendPrivatelyPlan`'s coin selection (largest-first, spending more than one in the same
   * transaction via repeated `spendStealthInput()` calls if a single output isn't enough) — the
   * caller only supplies an amount, not a commitment.
   *
   * Unlike `unshield()`, sending the *entire* selected total with no remainder is possible in one
   * step here: the builder's "at least one stealth output" requirement is trivially satisfied by
   * the recipient's own output, with no need for a same-account dust/change output to satisfy it.
   * Change (if `amount` is less than the selected inputs' total) is a second stealth output back
   * to this account.
   *
   * The fee-paying "dust" trick from `unshield()` still applies for the same reason: pay_fee and
   * (when there's change) the *concept* of "this account received a new output" both need a
   * revealed source account registered via `spendRevealedInput`, which requires amount `> 0`.
   *
   * Crash-safety: this account's own change commitment (if any) is read directly from the
   * locally-built outputs statement, *not* inferred from the finalized transaction's
   * `up_substates` — those also contain the recipient's brand-new stealth output, and naively
   * grabbing "the first new stealth output" would risk recording the recipient's payment as our
   * own. See `PendingShield.ownCommitment`'s doc comment.
   */
  async sendPrivately(
    resourceAddress: string,
    recipientWalletAddress: string,
    amount: bigint,
    maxFee = 100000n,
    memo?: string,
    minimumValuePromise = 0n,
  ): Promise<{ transactionId: string; recipientCommitment: string; recipientSubstateId: string; minimumValuePromise: string }> {
    assertValidMinimumValuePromise(minimumValuePromise, amount);
    const accountId = localAccountId(this.index);
    const records = await listShieldedOutputs(accountId);
    const { commitments, changeAmount } = resolveSendPrivatelyPlan(records, resourceAddress, amount);
    const dust = 1n;

    const provider = await this.getProvider();
    const account = await this.getComponentAddress();
    const ownWalletAddress = await this.getWalletAddress();

    // See shield()'s comment: the resource's own substate must be pinned explicitly -- prepare()
    // never adds it on its own.
    let builder = new StealthTransfer(provider, resourceAddress)
      .withBuilder((b) => b.addInput({ substate_id: resourceAddress, version: null }))
      .spendRevealedInput(account, dust);
    for (const commitment of commitments) {
      builder = builder.spendStealthInput(account, fromHex(commitment));
    }
    // The promise rides on the recipient's output only. Putting one on the change output would
    // publish a floor on this account's own remaining private balance -- an unrelated disclosure the
    // caller never asked for, and one the recipient has no interest in.
    builder = builder.toStealthOutput(
      createOutput({ destination: recipientWalletAddress, amount, resourceAddress, memo: toMemo(memo), minimumValuePromise }),
    );
    if (changeAmount > 0n) {
      builder = builder.toStealthOutput(createOutput({ destination: ownWalletAddress, amount: changeAmount, resourceAddress }));
    }
    const spec = await builder.toRevealedOutput(dust).payFeeFromRevealed(maxFee).prepare();
    // Output 0 is the recipient's; output 1 (only present when there's change) is ours. The
    // recipient has no way to discover their new output on their own (no scan-by-view-key API
    // exists) -- this commitment must be handed back to the caller so it can be shared with them
    // out of band; without it, the payment is invisible to them even though it succeeded on-chain.
    const recipientCommitment = extractOutputCommitment(spec, 0);
    const ownCommitment = changeAmount > 0n ? extractOutputCommitment(spec, 1) : undefined;

    const wallet = new OotleWallet().registerKeyProvider(account, this.signer).setDefaultSigner(account);
    const viewSecret = await this.signer.getViewSecret();
    const authorized = await WalletStealthAuthorizer.fromSpec(wallet, spec, { viewSecret, crypto: new WasmStealthCrypto(this.network) }).prepare(
      provider
    );
    const envelope = await authorized.seal();
    const transactionId = await submitTransaction(provider, envelope);

    await addPendingShield({
      transactionId,
      accountId,
      resourceAddress,
      amount: changeAmount.toString(),
      spentCommitments: commitments,
      ownCommitment,
    });
    try {
      const response = await withTimeout(pollTransactionResult(provider, transactionId), 60_000, "submitting the private send");
      await recordKnownVersions(response);
      if (ownCommitment) await recordKnownShieldedOutput(accountId, resourceAddress, ownCommitment, changeAmount, transactionId);
      for (const commitment of commitments) {
        await markShieldedOutputSpent(accountId, commitment);
      }
    } finally {
      await removePendingShield(transactionId);
    }
    return {
      transactionId,
      recipientCommitment,
      recipientSubstateId: stealthUtxoSubstateId(resourceAddress, fromHex(recipientCommitment)),
      minimumValuePromise: minimumValuePromise.toString(),
    };
  }

  /**
   * The recipient-side counterpart to `sendPrivately()`'s commitment hand-off: given a commitment
   * shared out of band, fetches the corresponding `utxo_{resource}_{commitment}` substate and
   * tries to decrypt it with this account's own view secret. `decryptOwnedUtxo` swallows the
   * "not ours" throw and returns `null` instead, so a wrong/foreign commitment fails cleanly here
   * rather than looking like a network error. Success both *proves* ownership and recovers the
   * amount in one step (no need to be told the amount separately) -- recorded exactly like a
   * self-shield's output, so it then just shows up in this account's private balance and
   * shielded-outputs picker.
   */
  async claimPrivatePayment(resourceAddress: string, commitmentHex: string): Promise<{ amount: bigint; memo?: string }> {
    const accountId = localAccountId(this.index);
    const existing = await listShieldedOutputs(accountId);
    if (existing.some((r) => r.resourceAddress === resourceAddress && r.commitment === commitmentHex)) {
      throw new Error("You've already claimed this payment.");
    }
    const provider = await this.getProvider();
    const substateId = stealthUtxoSubstateId(resourceAddress, fromHex(commitmentHex));
    const substate = await provider.getSubstate(substateId);
    const viewSecret = await this.signer.getViewSecret();
    const decrypted = await decryptOwnedUtxo(new WasmStealthCrypto(this.network), viewSecret, substate, substateId);
    if (!decrypted) {
      throw new Error("This commitment doesn't belong to your account, or wasn't found on-chain.");
    }
    const memo = fromMemo(decrypted.memo);
    // No originating transaction id is available from a bare commitment -- the substate id is
    // itself a stable, deterministic reference back to this exact output, so it fills that slot.
    await recordKnownShieldedOutput(accountId, resourceAddress, commitmentHex, decrypted.value, substateId, memo);
    return { amount: decrypted.value, memo };
  }

  /**
   * This account's unspent stealth outputs, newest first, optionally filtered to one resource.
   *
   * This local ledger *is* the account's private position -- see `ShieldedOutputRecord`'s doc
   * comment for why it has to be: a stealth output is a freestanding
   * `utxo_{resource}_{commitment}` substate, not an entry in any vault, and there is no
   * scan-by-view-key API that could rediscover one from the chain alone given only its commitment.
   * Anything not in here is, as far as this wallet is concerned, not spendable.
   */
  async listUnspentShieldedOutputs(resourceAddress?: string): Promise<ShieldedOutputRecord[]> {
    return selectUnspentShieldedOutputs(await listShieldedOutputs(localAccountId(this.index)), resourceAddress);
  }

  /**
   * Per-resource totals over `listUnspentShieldedOutputs()`, with each resource's real on-chain
   * `divisibility`/symbol/name folded in (the same lookup `getBalances()` does, via the shared
   * `fetchResourceMetadata` helper -- a private balance has to be renderable on its own, without a
   * caller cross-referencing `getBalances()` for the decimals).
   *
   * Distinct from `getBalances()`'s `confidentialAmount` in two ways worth being precise about:
   * it counts only these freestanding stealth outputs (not a Confidential *vault*'s own
   * commitments map, which `getBalances()` also decrypts and adds in), and it reports a resource
   * whose only holding is private, which `getBalances()` only surfaces via its
   * `synthesizeShieldedOnlyBalances` path. For "what can I spend privately right now", this is the
   * authoritative number, because it is exactly what `resolveUnshieldPlan`/
   * `resolveSendPrivatelyPlan` select from.
   *
   * One network round trip (the resource metadata batch); the amounts themselves are local.
   */
  async getPrivateBalances(): Promise<PrivateBalance[]> {
    const holdings = summarizePrivateHoldings(await this.listUnspentShieldedOutputs());
    if (holdings.length === 0) return [];

    const provider = await this.getProvider();
    const { divisibilityByResource, symbolByResource, nameByResource } = await fetchResourceMetadata(
      provider,
      holdings.map((h) => h.resourceAddress)
    );
    return holdings.map((h) => ({
      ...h,
      divisibility: divisibilityByResource.get(h.resourceAddress) ?? 0,
      symbol: symbolByResource.get(h.resourceAddress) ?? null,
      name: nameByResource.get(h.resourceAddress) ?? null,
    }));
  }

  /**
   * Automatic counterpart to `claimPrivatePayment()`: instead of requiring the recipient be told a
   * commitment out of band, walks the indexer's recent-transaction history looking for
   * `StealthTransfer` outputs this account can decrypt with its own view key (see
   * `scanTransactionsForOwnedOutputs`'s doc comment for why the data needed to do this is present
   * even in the *pruned* form `listRecentTransactions` returns).
   *
   * Cursor-based (`privatePaymentScanCursors[accountId]`, the newest transaction id seen last time)
   * so this can run cheaply and opportunistically on every `popup-get-status` — see
   * `buildStatus()`'s `recoverPendingShields()` call for the same pattern. Walks backward in pages
   * of `pageSize` (oldest-paging via `last_id`, per the indexer's own "recent" convention) up to
   * `maxPages`, stopping early once it reaches the transaction id it left off at last time. A very
   * active chain producing more than `maxPages * pageSize` new transactions between scans will
   * only be caught up partway; the next scan resumes from the same cursor and continues.
   */
  async scanForPrivatePayments(maxPages?: number, pageSize = 50): Promise<{ claimed: number; found: ScannedStealthOutput[] }> {
    const accountId = localAccountId(this.index);
    const provider = await this.getProvider();
    const viewSecret = await this.signer.getViewSecret();
    const crypto = new WasmStealthCrypto(this.network);
    const known = await listShieldedOutputs(accountId);
    const knownCommitments = new Set(known.map((r) => r.commitment));

    const previousCursor = await getPrivatePaymentScanCursor(accountId);
    let newestSeen: string | null = null;
    let lastId: string | null = null;
    const found: ScannedStealthOutput[] = [];
    // Whether this pass actually walked all the way back to `previousCursor` (or there was none to
    // reach -- the very first scan ever). Only true in that case is it safe to advance the cursor:
    // if `maxPages` runs out first, advancing anyway would silently and PERMANENTLY skip the
    // unscanned gap between here and the old cursor -- the next scan would start from the new
    // (already-advanced) cursor and never revisit it. Leaving the cursor where it was instead means
    // the next opportunistic scan just re-tries the same catch-up (redundant work, not data loss);
    // see this method's own doc comment ("the next scan resumes from the same cursor").
    // "No cursor" does not mean "we have the whole history" — after a restore it means the
    // opposite, that nothing is known yet. Starting `true` let the cursor be advanced to the
    // newest transaction after only a few pages, writing off every stealth output older than that
    // window: the next scan starts from the new cursor and never looks back, so those outputs
    // become unrecoverable. Only reaching the old cursor, or running out of history, counts.
    const isFirstScan = previousCursor === null;
    const pageBudget = maxPages ?? (isFirstScan ? 400 : 3);
    let reachedCursor = false;

    pages: for (let page = 0; page < pageBudget; page++) {
      const { transactions } = await provider.listRecentTransactions({ limit: pageSize, last_id: lastId, source: null });
      if (transactions.length === 0) {
        reachedCursor = true; // the indexer's whole history fit before ever finding previousCursor
        break;
      }
      if (page === 0) newestSeen = transactions[0]!.transaction_id;

      for (const entry of transactions) {
        if (entry.transaction_id === previousCursor) {
          reachedCursor = true;
          break pages;
        }
        const newlyFound = await scanTransactionsForOwnedOutputs(crypto, viewSecret, [entry], knownCommitments);
        for (const raw of newlyFound) {
          // scanTransactionsForOwnedOutputs' `memo` is the raw JSON-encoded Memo union (see
          // ScannedStealthOutput's doc comment) -- decode once here so both the persisted record
          // and this method's own return value carry plain text, not JSON, memo consumers never
          // need to know about `fromMemo()` themselves.
          const output = { ...raw, memo: fromMemo(raw.memo) };
          await recordKnownShieldedOutput(accountId, output.resourceAddress, output.commitment, output.amount, output.transactionId, output.memo);
          knownCommitments.add(output.commitment);
          found.push(output);
        }
      }
      lastId = transactions[transactions.length - 1]!.transaction_id;
    }

    if (newestSeen && reachedCursor) await setPrivatePaymentScanCursor(accountId, newestSeen);
    return { claimed: found.length, found };
  }

  /**
   * Given a resource address, finds every UTXO of that resource type this account can decrypt
   * with its own view key, no matter which instruction created it -- unlike
   * `scanForPrivatePayments()`, which only ever recognizes outputs from a top-level native
   * `StealthTransfer` instruction and so misses anything minted by custom template logic inside a
   * `CallFunction`/`CallMethod` (a voting template's ballot tokens, for instance -- confirmed this
   * is exactly why a voter's wallet can't discover an RCV ballot on its own).
   *
   * There is no indexer API to list substates by resource address: `Provider.getSubstate()` and
   * `getStealthUtxo()` both need a specific id/commitment already in hand, and
   * `listRecentTransactions()`'s pruned `TransactionEntry.summary` carries only a
   * `Commit`/`FeeIntentCommit` flag, never the actual `up_substates` diff (confirmed by reading
   * `TransactionResultSummary`'s own type). So this walks recent transaction ids and fetches each
   * one's *full* result via `getTransactionResult()` -- one extra round trip per transaction,
   * unlike `scanForPrivatePayments()`'s single-request-per-page listing -- filtering for
   * `utxo_{resource}_...` substate ids before ever attempting a decrypt. This is expensive by
   * construction (there is no cheaper way to ask "does resource X have any output for me" without
   * the indexer itself indexing by resource), so it takes no cursor and defaults to a small,
   * bounded lookback -- meant for an interactive "do I have one of these" check on a resource
   * whose mint is known to be recent, not a background sweep of the whole chain.
   */
  async scanForResourceUtxos(
    resourceAddress: string,
    opts: { maxPages?: number; pageSize?: number; limit?: number } = {}
  ): Promise<ScannedStealthOutput[]> {
    const accountId = localAccountId(this.index);
    const provider = await this.getProvider();
    const viewSecret = await this.signer.getViewSecret();
    const crypto = new WasmStealthCrypto(this.network);
    const known = await listShieldedOutputs(accountId);
    const knownCommitments = new Set(known.filter((r) => r.resourceAddress === resourceAddress).map((r) => r.commitment));
    const prefix = `utxo_${resourceAddress.startsWith("resource_") ? resourceAddress.slice(9) : resourceAddress}_`;

    const pageSize = opts.pageSize ?? 50;
    const pageBudget = opts.maxPages ?? 10;
    // Some resources (a voting template's ballot, a raffle ticket) mint at most one output per
    // account by construction -- a caller that already knows this can pass `limit: 1` to stop the
    // walk (both the page loop and the per-transaction fetches) the moment it's satisfied, rather
    // than paying for however much of the budget happened to be left.
    const limit = opts.limit ?? Infinity;
    let lastId: string | null = null;
    const found: ScannedStealthOutput[] = [];

    pages: for (let page = 0; page < pageBudget; page++) {
      const { transactions } = await provider.listRecentTransactions({ limit: pageSize, last_id: lastId, source: null });
      if (transactions.length === 0) break;

      for (const entry of transactions) {
        // No receipt yet, or rejected at mempool submission -- neither ever produced up_substates.
        if (entry.rejected_reason !== null || !entry.summary) continue;
        const response = await provider.getTransactionResult(entry.transaction_id);
        const result = response.result;
        if (result === "Pending" || "Rejected" in result) continue;
        const outcome = result.Finalized.execution_result?.finalize.result;
        const upSubstates =
          outcome && typeof outcome === "object" && "Accept" in outcome
            ? outcome.Accept.up_substates
            : outcome && typeof outcome === "object" && "AcceptFeeRejectRest" in outcome
              ? outcome.AcceptFeeRejectRest[0].up_substates
              : undefined;
        if (!upSubstates) continue;

        for (const [substateId, substate] of upSubstates) {
          if (!substateId.startsWith(prefix)) continue;
          const commitment = substateId.slice(prefix.length);
          if (knownCommitments.has(commitment)) continue;
          const decrypted = await decryptOwnedUtxo(crypto, viewSecret, { ...substate, verified: true }, substateId);
          if (!decrypted) continue;
          const memo = fromMemo(decrypted.memo);
          await recordKnownShieldedOutput(accountId, resourceAddress, commitment, decrypted.value, entry.transaction_id, memo);
          knownCommitments.add(commitment);
          found.push({ resourceAddress, commitment, amount: decrypted.value, transactionId: entry.transaction_id, memo });
          if (found.length >= limit) break pages;
        }
      }
      lastId = transactions[transactions.length - 1]!.transaction_id;
    }
    return found;
  }
}

/**
 * Reads the commitment of the output at `outputIndex` (in the order `toStealthOutput()` was
 * called) directly from the outputs statement `StealthTransfer.prepare()` already built —
 * generated client-side, so it's known *before* submission, not inferred afterward by scanning
 * the finalized transaction's `up_substates`. That scan-based approach is unambiguous when a
 * transfer only ever creates one new stealth output belonging to this account (shield, unshield),
 * but breaks down the moment a transfer also creates a *different* account's new stealth output
 * in the same transaction (a private send's recipient output) — grabbing "the first new stealth
 * output" from `up_substates` would then risk attributing someone else's payment to us.
 */
/**
 * Builds a complete `StealthTransferStatement` (as its final compact JSON string) that spends one
 * script-path-locked HTLC UTXO into one brand-new, normal (key-spendable) stealth output — the
 * shared core of `htlcClaim`/`htlcRefund`, which differ only in which leaf they reveal and how
 * they come by the input's `mask`/`value` (on-chain decryption for a claim; retained from funding
 * time for a refund, since the funder can't decrypt an output addressed to the claimant).
 *
 * Every JSON fragment here is spliced from the raw strings `buildScriptPathWitness`/
 * `createStealthOutputWitness` themselves return, never `JSON.parse`d and rebuilt — both carry
 * u64 fields (amounts, epochs) that can exceed `Number.MAX_SAFE_INTEGER`, and a parse/restringify
 * round-trip through a JS number would silently corrupt them. `value` is spliced in from `params`
 * via template-literal interpolation of a `bigint`, which stringifies to its exact decimal digits
 * with no such risk.
 */
// Exported (unlike this file's other module-level helpers) specifically so its wasm-assembly
// logic can be exercised directly in tests without needing a full account + fake provider --
// see htlc.test.ts's real-crypto round-trip test.
export function buildHtlcSpendStatement(params: {
  network: Network;
  conditions: object[];
  leaf: object;
  /** The revealed leaf's witness data -- the preimage for a claim, empty for a refund (the
   * refund leaf has no data-consuming `HashLock` atom). */
  data: Uint8Array;
  mask: string;
  value: bigint;
  destinationWalletAddress: string;
  resourceAddress: string;
}): string {
  const witnessResultJson = buildScriptPathWitness(JSON.stringify(params.conditions), JSON.stringify(params.leaf), params.data);
  // `witnessResultJson` is exactly `{"witness":...,"condition_root":"..."}` -- strip the outer
  // braces and splice the inner `"witness":...,"condition_root":...` content directly into the
  // input entry below, rather than parsing and re-serializing the object.
  const witnessInner = witnessResultJson.slice(1, -1);
  const inputEntry = `{"mask_and_value":{"value":${params.value},"mask":"${params.mask}"},${witnessInner}}`;

  const destination = parseOotleAddress(params.destinationWalletAddress);
  const outputWitnessJson = createStealthOutputWitness(
    params.network,
    destination.owner_key,
    destination.view_key,
    params.value,
    params.resourceAddress,
    null,
    null,
    null, // pay_to_json: null -- default StealthPublicKey, a normal one-time key-spendable output.
    0n
  );

  const statementJson = buildStealthTransferStatement(`[${inputEntry}]`, 0n, `[${outputWitnessJson}]`, 0n);
  // Fail fast locally rather than spend a network round trip on a malformed statement -- the same
  // check tari-ootle's own `build_stealth_transfer_statement` unit tests run before trusting its
  // output (crates/ootle_wasm/core/src/stealth/transfer.rs).
  validateStealthTransfer(statementJson, null);
  return statementJson;
}

/**
 * Submits a hand-built HTLC claim/refund transaction: one `StealthTransfer` instruction carrying
 * `statementJson` verbatim, spending `substateId`, fee paid from `account`'s own revealed balance.
 *
 * Deliberately bypasses `TransactionBuilder`'s usual `WalletStealthAuthorizer` companion — that
 * pipeline only ever produces key-path stealth-input signatures, which don't apply to a
 * script-path spend (whose authorization is the revealed leaf's own `AccessRule`, satisfied by
 * this account's ordinary transaction signature) — `signTransaction`/`sealTransaction` alone are
 * both necessary and sufficient here, the same pipeline any plain `CallMethod`-only transaction
 * uses.
 */
async function submitHtlcSpend(params: {
  provider: IndexerProvider;
  signer: SecretKeyWallet;
  network: Network;
  account: string;
  resourceAddress: string;
  substateId: string;
  statementJson: string;
  maxFee: bigint;
  timeoutLabel: string;
}): Promise<string> {
  const maxEpoch = await resolveMaxEpoch(params.provider);
  const builder = TransactionBuilder.new(params.network, maxEpoch)
    .addInput({ substate_id: params.substateId, version: null })
    .addInput({ substate_id: params.account, version: null })
    .feeTransactionPayFromComponent(params.account, params.maxFee)
    .addInstruction(
      // `statement` is spliced as a raw JSON fragment (see buildHtlcSpendStatement), the same
      // technique `@tari-project/ootle`'s own `statementAsWire` uses internally for the piecemeal
      // StealthTransfer builder path -- this cast mirrors that one exactly.
      {
        StealthTransfer: {
          resource_address_ref: { Address: params.resourceAddress },
          statement: { __ootleRawJson: params.statementJson },
          revealed_input_bucket: null,
        },
      } as unknown as Instruction
    );
  for (const vaultId of await getVaultIdsForAccount(params.provider, params.account)) {
    builder.addInput({ substate_id: vaultId, version: null });
  }
  const unsignedTx = await resolveTransaction(params.provider, builder.buildUnsignedTransaction());
  const signed = await signTransaction([params.signer], unsignedTx);
  const envelope = await sealTransaction(signed);
  const transactionId = await submitTransaction(params.provider, envelope);
  const response = await withTimeout(pollTransactionResult(params.provider, transactionId), 60_000, params.timeoutLabel);
  await recordKnownVersions(response);
  return transactionId;
}

function extractOutputCommitment(spec: StealthTransferSpec, outputIndex: number): string {
  const parsed = spec.statement.outputsStatement.parsed() as { outputs?: { output?: { commitment?: string } }[] };
  const commitment = parsed.outputs?.[outputIndex]?.output?.commitment;
  if (typeof commitment !== "string" || commitment.length === 0) {
    throw new Error(`Failed to read output ${outputIndex}'s commitment from the locally-built outputs statement.`);
  }
  return commitment;
}

/**
 * Synthesizes a `TokenBalance` entry for each resource whose only balance is a shielded output
 * with no on-chain vault at all (e.g. redeemed via the "Advanced" unshield flow from someone
 * else's shared commitment) -- these never appear in `getBalances()`'s vault-derived `parsed`
 * list, since they're freestanding `utxo_{resource}_{commitment}` substates, not vault entries.
 * Skips any resource already covered by `parsedResources` (that one gets its shielded amount
 * folded into its existing entry instead, in `getBalances()` itself).
 */
export function synthesizeShieldedOnlyBalances(
  parsedResources: Set<string>,
  shieldedByResource: Map<string, bigint>,
  divisibilityByResource: Map<string, number>,
  symbolByResource: Map<string, string | null>,
  nameByResource: Map<string, string | null>
): TokenBalance[] {
  const balances: TokenBalance[] = [];
  for (const [resourceAddress, amount] of shieldedByResource) {
    if (parsedResources.has(resourceAddress)) continue;
    balances.push({
      resourceAddress,
      kind: "Stealth",
      amount: 0n,
      confidentialAmount: amount,
      confidentialDecryptFailures: 0,
      divisibility: divisibilityByResource.get(resourceAddress) ?? 0,
      symbol: symbolByResource.get(resourceAddress) ?? null,
      name: nameByResource.get(resourceAddress) ?? null,
      nonFungibleTokenIds: null,
    });
  }
  return balances;
}

/**
 * A display string for one `NonFungibleId` (the tagged union `{U256} | {String} | {Uint32} |
 * {Uint64}`, or occasionally a bare primitive) -- just the value, since the variant tag is rarely
 * interesting to a user looking at a list of tokens they hold. Falls back to the raw JSON for a
 * shape this doesn't recognise (a future `NonFungibleId` variant) rather than throwing partway
 * through a balance list.
 */
function stringifyNonFungibleId(id: unknown): string {
  if (typeof id === "string" || typeof id === "number" || typeof id === "bigint") return String(id);
  if (id && typeof id === "object") {
    if ("U256" in id) return String((id as { U256: unknown }).U256);
    if ("String" in id) return String((id as { String: unknown }).String);
    if ("Uint32" in id) return String((id as { Uint32: unknown }).Uint32);
    if ("Uint64" in id) return String((id as { Uint64: unknown }).Uint64);
  }
  return JSON.stringify(id);
}

/**
 * Coin selection for spending shielded outputs: picks this resource's unspent records
 * largest-first until their sum covers `targetAmount`, so a spend needing more than any single
 * output holds is satisfied by combining several in one transaction (the builder's
 * `spendStealthInput()` can be called once per input UTXO) rather than requiring the caller to
 * pick one record themselves. Largest-first minimizes the number of inputs spent (each one adds
 * real signature/proof-verification fee cost), rather than needlessly consolidating dust.
 *
 * Returns the unselected remainder too (still sorted largest-first) so callers that need "at
 * least one more unit available" (see `resolveUnshieldPlan`) can pull in exactly one more output
 * without re-deriving the candidate list.
 */
/**
 * The unspent subset of a shielded-output ledger, newest first, optionally narrowed to one
 * resource. Newest-first is a display order, deliberately *not* the spend order: coin selection is
 * `selectShieldedUtxosForAmount`'s largest-first job, and the two must not be conflated.
 *
 * Split out of `OotleAccount.listUnspentShieldedOutputs` (which is just this over the account's own
 * stored records) so the filtering rule -- what counts as spendable, and what a dApp with view
 * access is allowed to see -- is testable on its own.
 */
export function selectUnspentShieldedOutputs(records: ShieldedOutputRecord[], resourceAddress?: string): ShieldedOutputRecord[] {
  return records
    .filter((r) => !r.spent && (resourceAddress === undefined || r.resourceAddress === resourceAddress))
    .sort((a, b) => b.createdAt - a.createdAt);
}

/**
 * Totals a set of already-unspent shielded outputs per resource. `outputCount` is carried
 * alongside the sum rather than left to be recomputed, because it is not cosmetic: each output is
 * spent whole, so the count is what bounds whether a given amount can actually be covered (see
 * `resolveUnshieldPlan`) -- a balance of 100 across one output and across fifty are very different
 * things to a caller planning a spend.
 *
 * Insertion-ordered by first appearance (Map iteration order), so a caller's rendering doesn't
 * reshuffle between calls for no reason.
 */
export function summarizePrivateHoldings(
  records: ShieldedOutputRecord[]
): { resourceAddress: string; amount: bigint; outputCount: number }[] {
  const totals = new Map<string, { amount: bigint; outputCount: number }>();
  for (const record of records) {
    const entry = totals.get(record.resourceAddress) ?? { amount: 0n, outputCount: 0 };
    entry.amount += BigInt(record.amount);
    entry.outputCount += 1;
    totals.set(record.resourceAddress, entry);
  }
  return [...totals].map(([resourceAddress, entry]) => ({ resourceAddress, ...entry }));
}

export function selectShieldedUtxosForAmount(
  records: ShieldedOutputRecord[],
  resourceAddress: string,
  targetAmount: bigint
): { selected: ShieldedOutputRecord[]; total: bigint; unselected: ShieldedOutputRecord[] } {
  const candidates = records
    .filter((r) => r.resourceAddress === resourceAddress && !r.spent)
    .sort((a, b) => {
      const diff = BigInt(b.amount) - BigInt(a.amount);
      return diff > 0n ? 1 : diff < 0n ? -1 : 0;
    });

  const selected: ShieldedOutputRecord[] = [];
  let total = 0n;
  let i = 0;
  for (; i < candidates.length; i++) {
    if (total >= targetAmount) break;
    selected.push(candidates[i]!);
    total += BigInt(candidates[i]!.amount);
  }
  return { selected, total, unselected: candidates.slice(i) };
}

/**
 * Pure planning for `unshield()`: selects enough of the caller's unspent records for this
 * resource (via `selectShieldedUtxosForAmount`) to cover `revealedOutAmount`, and checks the
 * total leaves at least 1 unit as private remainder (see `unshield()`'s doc comment for why the
 * upper bound is strict, not `<=`). Extracted so this decision logic is unit-testable without a
 * live provider/WASM crypto, same reasoning as `pollTransactionResult`'s extraction.
 *
 * If the minimal selection's total lands *exactly* on `revealedOutAmount` (zero remainder), and
 * another unspent record for this resource exists, one more (the smallest available) is pulled
 * in purely to create a nonzero remainder — spending an extra UTXO is preferable to failing a
 * reveal that the account's total private balance could otherwise satisfy.
 */
export function resolveUnshieldPlan(
  records: ShieldedOutputRecord[],
  resourceAddress: string,
  revealedOutAmount: bigint
): { commitments: string[]; remainder: bigint } {
  if (revealedOutAmount <= 0n) throw new Error("The amount to reveal must be greater than zero.");
  const { selected, total, unselected } = selectShieldedUtxosForAmount(records, resourceAddress, revealedOutAmount);
  if (total < revealedOutAmount) {
    throw new Error(`Amount exceeds your private balance (you have ${total}).`);
  }
  let finalSelected = selected;
  let finalTotal = total;
  if (finalTotal === revealedOutAmount) {
    const extra = unselected[unselected.length - 1]; // smallest remaining unspent record, if any
    if (!extra) {
      throw new Error(
        "Can't unshield your full private balance in one transaction -- at least 1 unit must remain private as change."
      );
    }
    finalSelected = [...finalSelected, extra];
    finalTotal += BigInt(extra.amount);
  }
  return { commitments: finalSelected.map((r) => r.commitment), remainder: finalTotal - revealedOutAmount };
}

/**
 * Pure planning for `sendPrivately()`: selects enough of the caller's unspent records for this
 * resource to cover `amount` — unlike `resolveUnshieldPlan`, sending the *entire* selected total
 * with zero change is allowed, since the recipient's own stealth output already satisfies the
 * builder's "at least one stealth output" requirement (no same-account dust output is needed to
 * satisfy it, unlike unshield's revealed destination). Extracted for the same unit-testability
 * reasons as `resolveUnshieldPlan`.
 */
export function resolveSendPrivatelyPlan(
  records: ShieldedOutputRecord[],
  resourceAddress: string,
  amount: bigint
): { commitments: string[]; changeAmount: bigint } {
  if (amount <= 0n) throw new Error("The amount to send must be greater than zero.");
  const { selected, total } = selectShieldedUtxosForAmount(records, resourceAddress, amount);
  if (total < amount) {
    throw new Error(`Amount exceeds your private balance (you have ${total}).`);
  }
  return { commitments: selected.map((r) => r.commitment), changeAmount: total - amount };
}

/**
 * Reconciles shields whose `pollTransactionResult` never got to finish (the extension's service
 * worker was killed between submission and the storage write) — see `PendingShield`'s doc
 * comment. Checks each pending shield's current status *once* (not a blocking poll-to-finalize
 * loop — if it's still genuinely pending, this leaves it for the next check rather than stalling
 * whatever triggered recovery, typically `popup-get-status`) and either completes the storage
 * write (finalized successfully), drops it (rejected — no stealth output was ever created, so
 * there's nothing to recover), or leaves it alone (still pending). One provider is reused across
 * every pending shield, whichever local account they belong to — this is a read-only connection,
 * not account/signing-specific.
 */
export async function recoverPendingShields(provider: IndexerProvider): Promise<void> {
  const pending = await listPendingShields();
  for (const p of pending) {
    try {
      const response = await provider.getTransactionResult(p.transactionId);
      const result = response.result;
      if (result === "Pending") continue; // still in flight -- leave it for next time
      if ("Rejected" in result) {
        await removePendingShield(p.transactionId);
        continue;
      }
      const outcome = result.Finalized.execution_result?.finalize.result;
      const succeeded = outcome && typeof outcome === "object" && "Accept" in outcome;
      if (succeeded) {
        await recordKnownVersions(response);
        if (p.ownCommitment) {
          await recordKnownShieldedOutput(p.accountId, p.resourceAddress, p.ownCommitment, BigInt(p.amount), p.transactionId, p.memo);
        }
        if (p.spentCommitments) {
          for (const commitment of p.spentCommitments) {
            await markShieldedOutputSpent(p.accountId, commitment);
          }
        }
      }
      // Reject / AcceptFeeRejectRest: no stealth output was created either way, nothing to
      // recover -- just stop waiting on it.
      await removePendingShield(p.transactionId);
    } catch {
      // A transient network/indexer error checking one pending shield must not stop the rest
      // from being reconciled -- leave this one in the list, it'll be retried next time.
    }
  }
}

/**
 * Persists a `ShieldedOutputRecord` for a commitment already known locally (see
 * `extractOutputCommitment`'s doc comment for why this is preferred over scanning the finalized
 * transaction's `up_substates`) — the only lead back to it, since there is no client-side
 * scan/list API for stealth UTXOs (see confidential.ts's module doc).
 */
async function recordKnownShieldedOutput(
  accountId: string,
  resourceAddress: string,
  commitment: string,
  amount: bigint,
  transactionId: string,
  memo?: string
): Promise<void> {
  await addShieldedOutput({
    accountId,
    resourceAddress,
    commitment,
    amount: amount.toString(),
    transactionId,
    createdAt: Date.now(),
    spent: false,
    memo,
  });
}

// The indexer's own view of a substate an account keeps touching (above all its own fee vault,
// referenced by nearly every transaction) can lag behind the version our *own* just-confirmed
// transaction produced — confirmed empirically: even a brand-new account, on its second-ever
// transaction, got "Lock failure: vault:1 is DOWN" from `resolveInputs()` handing back version 1
// when the true current version (from our own prior transaction's `up_substates`) was already
// higher, and this reproduced identically across multiple fresh accounts and reloads. A stateful
// wallet daemon avoids this because it tracks its own substate versions locally instead of
// re-asking a remote indexer for state it just changed itself. This is that same idea — persisted
// (not just an in-memory Map) specifically because an in-memory-only cache loses exactly the
// knowledge that matters most across a reload, which is the scenario this was written to fix.
let knownVersionsPromise: Promise<Map<string, number>> | null = null;

async function loadKnownVersions(): Promise<Map<string, number>> {
  if (!knownVersionsPromise) {
    knownVersionsPromise = getKnownVersions().then((raw) => new Map(Object.entries(raw)));
  }
  return knownVersionsPromise;
}

/** Prefers our own record of a substate's version over whatever the indexer just reported, when
 * we have a newer one — see the block comment above for why. */
async function applyKnownVersions(inputs: SubstateRequirement[]): Promise<SubstateRequirement[]> {
  const known = await loadKnownVersions();
  return inputs.map((input) => {
    const version = known.get(input.substate_id);
    return version !== undefined && (input.version === null || version > input.version) ? { ...input, version } : input;
  });
}

/** Remembers the post-transaction version of every substate a *confirmed* (never a dry-run —
 * those don't reflect real state) transaction touched, so the next transaction that references
 * one of them doesn't have to trust the indexer's possibly-stale view of it. */
async function recordKnownVersions(response: IndexerGetTransactionResultResponse): Promise<void> {
  const result = response.result;
  if (result === "Pending" || "Rejected" in result) return;
  const outcome = result.Finalized.execution_result?.finalize.result;
  const upSubstates =
    outcome && typeof outcome === "object" && "Accept" in outcome
      ? outcome.Accept.up_substates
      : outcome && typeof outcome === "object" && "AcceptFeeRejectRest" in outcome
        ? outcome.AcceptFeeRejectRest[0].up_substates
        : undefined;
  if (!upSubstates || upSubstates.length === 0) return;

  const updates = new Map<string, number>();
  for (const [id, substate] of upSubstates) updates.set(id, substate.version);

  // No extra `serialized()` wrap needed here (and one would deadlock: `setKnownVersions` below
  // already serializes its own write against storage.ts's shared queue, and queuing this whole
  // function behind that same queue would make it wait on a write that is itself waiting for this
  // function to finish). `loadKnownVersions()` returns the same cached, shared Map every time
  // (mutated in place, never replaced), so two concurrent confirmations both mutate one object
  // synchronously — no read-modify-write race to protect against — and whichever of their
  // `setKnownVersions` writes lands last still snapshots the *fully* merged map at that point, so
  // nothing is lost regardless of write order.
  const known = await loadKnownVersions();
  for (const [id, version] of updates) known.set(id, version);
  await setKnownVersions(Object.fromEntries(known));
}

/**
 * `execute()`'s raw submit result has no top-level `transactionId` -- unlike the SDK's own custom
 * operations (`shield`, `redeemStealthOutputAndExecute`, etc.), which all return that field
 * explicitly. dApp code built against those was reasonably reaching for `result.transactionId` on
 * `execute()`'s result too and finding nothing there. This tacks the same field on, non-destructively
 * (spread first, so a genuine future `transactionId` in the response itself would win), reading the
 * hash out of the one place it actually lives: `Finalized.execution_result.finalize.transaction_hash`.
 * Left untouched for "Pending"/"Rejected" outcomes and for a null `execution_result` (e.g. a
 * `Rejected`-at-the-fee-phase finalize) -- there is no hash to report for those.
 */
function withTransactionId<T extends IndexerGetTransactionResultResponse>(response: T): T & { transactionId?: string } {
  const result = response.result;
  if (result === "Pending" || "Rejected" in result) return response;
  const transactionHash = result.Finalized.execution_result?.finalize.transaction_hash;
  return transactionHash !== undefined ? { ...response, transactionId: transactionHash } : response;
}

/**
 * Forgets what we thought we knew about these substates' versions, after the chain has told us a
 * remembered one is unusable. Keeping it would make `applyKnownVersions` reassert it over every
 * future resolve, turning one bad write into a permanently stuck wallet.
 */
export async function forgetKnownVersions(substateIds: string[]): Promise<void> {
  if (substateIds.length === 0) return;
  const known = await loadKnownVersions();
  let changed = false;
  for (const id of substateIds) if (known.delete(id)) changed = true;
  if (changed) await setKnownVersions(Object.fromEntries(known));
}

/** Drops the in-memory known-versions cache. Call this on wallet reset so a freshly-created wallet
 * can't inherit the previous wallet's cached version numbers — the persisted side of that wipe is
 * the caller's own responsibility (a serialized clear of whatever `KeyValueStore` backs `storage.ts`). */
export function resetKnownVersions(): void {
  knownVersionsPromise = null;
}

/**
 * Polls a submitted transaction's result to finalization (or rejection/timeout). Extracted from
 * `OotleAccount.submitReal()` so `shield()`/`unshield()` — which submit via a completely
 * different pipeline (`StealthTransfer`/`WalletStealthAuthorizer`/`submitTransaction`, not
 * `TransactionBuilder`) — share the exact same hardened Reject/AcceptFeeRejectRest/timeout
 * handling instead of a second, potentially-drifting copy of it.
 */
export async function pollTransactionResult(
  provider: IndexerProvider,
  transactionId: string,
  timeoutMs = 60_000
): Promise<IndexerGetTransactionResultResponse> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const response = await provider.getTransactionResult(transactionId);
    const result = response.result;
    if (result === "Pending") {
      if (Date.now() > deadline) throw new Error(`Timed out waiting for transaction ${transactionId} to finalize.`);
      await new Promise((resolve) => setTimeout(resolve, 500));
      continue;
    }
    if ("Rejected" in result) {
      throw new Error(`Transaction ${transactionId} was rejected: ${result.Rejected.details}`);
    }
    const outcome = result.Finalized.execution_result?.finalize.result;
    if (outcome && typeof outcome === "object") {
      if ("Reject" in outcome) {
        throw new Error(`Transaction ${transactionId} was rejected: ${JSON.stringify(outcome.Reject)}`);
      }
      if ("AcceptFeeRejectRest" in outcome) {
        throw new Error(`Transaction ${transactionId} accepted the fee but rejected the rest: ${JSON.stringify(outcome.AcceptFeeRejectRest)}`);
      }
    }
    return response;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

// `resolveInputs()` throws "Failed to find input \"<id>\": ... Verify the substate id is correct
// (typo? wrong network?) or wait for the producing transaction to finalize." — the indexer client's
// own wording for a plain 404 on `substatesGet`. Confirmed empirically this fires on a substate that
// exists moments later: the indexer's committed view lags the version this account's *own* prior
// transaction (or a template it just called into, e.g. a newly-created pool) produced by more than
// one round trip, the same race `claimTestnetXtr()`'s "Lock failure" backoff exists for. Unlike
// "wrong network"/"typo'd address", a genuinely-missing substate never starts existing no matter how
// long this waits — but there is no way to distinguish the two from the message alone, so this
// retries a bounded number of times and lets a persistent 404 surface as a real error afterward.
const RESOLVE_INPUTS_NOT_YET_FINALIZED_PATTERN = /Failed to find input/i;

export async function resolveInputsWithRetry(
  provider: IndexerProvider,
  requirements: SubstateRequirement[],
  retries = 5,
  retryDelayMs = 500,
): Promise<SubstateRequirement[]> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await withTimeout(provider.resolveInputs(requirements), 15_000, "resolving inputs");
    } catch (e) {
      const isNotYetFinalized = e instanceof Error && RESOLVE_INPUTS_NOT_YET_FINALIZED_PATTERN.test(e.message);
      if (!isNotYetFinalized || attempt >= retries) throw e;
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs * (attempt + 1)));
    }
  }
}

/**
 * Checks whether `substateId` already exists on-chain, tolerating a couple of retries in case it
 * just hasn't finalized on the indexer yet (a much smaller budget than `resolveInputsWithRetry`'s
 * default — this is used to *decide* whether to create something, not to wait out a known producer,
 * so a persistent 404 should read as "doesn't exist" quickly rather than stall the caller). Only
 * `resolveInputsWithRetry`'s specific "not yet finalized" 404 is treated as "missing" — any other
 * failure (network error, indexer down) propagates rather than being silently read as nonexistence,
 * since that misread would make `send()` prepend a `CreateAccount` for an account that actually
 * exists, which the engine rejects outright ("is already UP and conflicts with an existing output").
 */
export async function substateExists(provider: IndexerProvider, substateId: string): Promise<boolean> {
  try {
    await resolveInputsWithRetry(provider, [{ substate_id: substateId, version: null }], 2, 300);
    return true;
  } catch (e) {
    if (e instanceof Error && RESOLVE_INPUTS_NOT_YET_FINALIZED_PATTERN.test(e.message)) return false;
    throw e;
  }
}

// Matches the address this engine names in a "not found" rejection. Confirmed two distinct
// phrasings for what is structurally the same SubstateNotFound rejection, depending on *how* the
// missing reference was hit: a plain call-target miss reads "At instruction #1: component_...
// not found" (address before the phrase), while a template-internal reference (e.g. a confidential
// vault's withdraw() needing an extra substate the instructions never named directly) reads
// "...Template referenced substate but it was not found: resource_..." (address after). A
// cross-template call (e.g. the DEX router calling into a pool component internally) reads
// "Substate 'component_...' not found or is not a transaction input" — address quoted, so the
// optional `['"]?` matters: without it, the quote character sits between the address and "not
// found" and the whitespace-only pattern silently fails to match. Any of the `<kind>_<hex>`
// address forms this SDK uses (component/resource/vault/transaction_receipt/...), always hex
// after the last `_`.
const MISSING_SUBSTATE_PATTERNS = [
  /\b([a-z_]+_[0-9a-f]{16,})['"]?\s+not found\b/i,
  /not found:\s*([a-z_]+_[0-9a-f]{16,})\b/i,
];

export function extractMissingSubstateAddress(message: string): string | null {
  for (const pattern of MISSING_SUBSTATE_PATTERNS) {
    const match = pattern.exec(message);
    if (match) return match[1]!;
  }
  return null;
}

// Matches "Lock failure: Substate <id>:<version> is DOWN" — the exact substate and version that
// was just consumed, letting the caller compute the next version (version + 1) deterministically
// instead of re-querying a possibly-still-lagging indexer.
const STALE_LOCK_PATTERN = /Substate ([a-z_]+_[0-9a-f]{16,}):(\d+) is (?:not found or )?DOWN/i;

export function extractStaleLockVersion(message: string): { substateId: string; version: number } | null {
  const match = STALE_LOCK_PATTERN.exec(message);
  return match ? { substateId: match[1]!, version: Number(match[2]) } : null;
}

/**
 * A compact description of a resolved transaction, for attaching to a wasm parse failure.
 *
 * Deliberately structural rather than a full dump: field names and the shape of `inputs` are what
 * identify a mismatch against `UnsignedTransactionV1`, and a whole transaction (range proofs,
 * blobs) is far too big to carry in an error message.
 */
function describeResolvedTx(resolved: unknown): string {
  try {
    const tx = resolved as Record<string, unknown>;
    const keys = Object.keys(tx).join(",");
    const inputs = Array.isArray(tx.inputs) ? (tx.inputs as unknown[]) : [];
    const sample = inputs.slice(0, 3).map((i) => JSON.stringify(i)).join(" ");
    const missing = ["network", "fee_instructions", "instructions", "inputs", "max_epoch", "is_seal_signer_authorized", "dry_run"]
      .filter((k) => !(k in tx));
    return [
      `keys=[${keys}]`,
      missing.length ? `MISSING=[${missing.join(",")}]` : null,
      `inputs=${inputs.length}${sample ? ` ${sample}` : ""}`,
    ].filter(Boolean).join(" ");
  } catch {
    return "unavailable";
  }
}

/**
 * The signed transaction's shape, for a `sealTransaction` parse failure.
 *
 * `signTransaction` wraps the transaction as `{transaction, signatures}` and the signatures are
 * generated inside it, so they are the half of the payload the caller never sees — and a malformed
 * one fails the parse identically to a malformed transaction.
 */
function describeSignedTx(signed: unknown): string {
  try {
    const s = signed as Record<string, unknown>;
    const sigs = Array.isArray(s.signatures) ? (s.signatures as Record<string, unknown>[]) : [];
    const shape = sigs.slice(0, 2).map((sig) => {
      const inner = sig?.signature as Record<string, unknown> | undefined;
      return `{public_key:${typeof sig?.public_key} signature:{public_nonce:${typeof inner?.public_nonce},signature:${typeof inner?.signature}}}`;
    }).join(" ");
    const tx = s.transaction as Record<string, unknown> | undefined;
    return `keys=[${Object.keys(s).join(",")}] signatures=${sigs.length}${shape ? ` ${shape}` : ""}` +
      (tx ? ` tx=${describeResolvedTx(tx)}` : "");
  } catch {
    return "unavailable";
  }
}
