// Decrypting the private portion of a vault's Confidential resource container -- the value
// hidden inside Pedersen commitments (`ResourceContainer.Confidential.commitments`), readable
// only with the account's own view key. This is a *read*, not a spend: it only interprets data
// the caller already fetched (a vault substate), never touches the network or the account's
// owner key, and can never move funds.
//
// `decryptInputData` (not `decryptOwnedUtxo`) is the correct primitive here: `decryptOwnedUtxo`
// expects a full fetched `Utxo`-shaped substate (via `parseSubstateUtxo`), but a vault's inline
// `commitments` map holds raw `OutputBody` values directly, with no substate wrapper -- verified
// against `@tari-project/ootle`'s own type signatures before writing this, not assumed.
import { decryptInputData, type StealthCryptoProvider } from "@tari-project/ootle";
import type { OutputBody, TransactionEntry } from "@tari-project/ootle-ts-bindings";
import { fromHex } from "./vault";

export interface ConfidentialSumResult {
  /** Total plaintext value recovered across every commitment this account could decrypt. */
  total: bigint;
  /** Commitments that failed to decrypt against this account's view key -- expected to be 0 for
   * a vault's own commitments map (every entry there should be ours), so a nonzero count here is
   * worth surfacing rather than silently swallowing. */
  failedCount: number;
}

/**
 * Sums the hidden value across every commitment in a vault's `Confidential.commitments` map.
 * Each `OutputBody` is decrypted independently -- one failing (e.g. a commitment this account
 * doesn't actually own) is counted rather than aborting the whole sum, so a single bad entry
 * can't hide the rest of a real balance.
 */
export async function sumConfidentialCommitments(
  crypto: StealthCryptoProvider,
  viewSecret: Uint8Array,
  commitments: Record<string, OutputBody>,
): Promise<ConfidentialSumResult> {
  let total = 0n;
  let failedCount = 0;
  for (const [commitmentHex, body] of Object.entries(commitments)) {
    try {
      const { value } = await decryptInputData(crypto, fromHex(commitmentHex), fromHex(body.encrypted_data), {
        senderPublicNonce: fromHex(body.public_nonce),
        viewSecret,
        skipMemo: true,
      });
      total += value;
    } catch {
      failedCount++;
    }
  }
  return { total, failedCount };
}

export interface ScannedStealthOutput {
  resourceAddress: string;
  /** 32-byte Pedersen commitment, hex. */
  commitment: string;
  amount: bigint;
  transactionId: string;
  /** The output's memo, if the sender attached one, as the raw JSON-encoded `Memo` union string
   * `DecryptedData.memo` returns (see the SDK's own doc comment -- not plain text yet; callers use
   * wallet.ts's `fromMemo()` to decode it). Decrypted alongside the amount, unlike
   * `sumConfidentialCommitments`, which passes `skipMemo: true` since it only needs a running total. */
  memo?: string;
}

/**
 * Walks a batch of `TransactionEntry`s (as returned by the indexer's `listRecentTransactions`)
 * looking for `StealthTransfer` instructions, and tries to decrypt each output against this
 * account's own view key -- the client-side half of the "scan new outputs" step described at
 * ootle.tari.com/guides/stealth-resources, which nothing in the SDK wraps end-to-end today.
 *
 * A *pruned* transaction (what `listRecentTransactions` returns) only omits large blob payloads
 * (template code, etc.) -- confirmed by reading the wire types, not assumed: instruction fields,
 * including a `StealthTransfer`'s full `outputs_statement`, are preserved verbatim. Each output
 * there carries its commitment, sender public nonce, and encrypted data as plain hex, which is
 * everything `decryptInputData` needs -- no further per-output substate fetch required.
 *
 * Skips: commitments already in `knownCommitments` (no need to re-decrypt something already
 * recorded), and any `StealthTransfer` whose resource address is a `Workspace` reference rather
 * than a literal `Address` -- resolving a workspace reference would mean replaying that
 * transaction's whole instruction sequence, out of scope for a lightweight scan. This wallet's own
 * shield/unshield/sendPrivately always emit a literal `Address`, so this only ever skips
 * unusually-built third-party transactions.
 */
export async function scanTransactionsForOwnedOutputs(
  crypto: StealthCryptoProvider,
  viewSecret: Uint8Array,
  transactions: TransactionEntry[],
  knownCommitments: ReadonlySet<string>
): Promise<ScannedStealthOutput[]> {
  const found: ScannedStealthOutput[] = [];
  for (const entry of transactions) {
    const tx = entry.transaction.V1.body.transaction;
    for (const instruction of [...tx.instructions, ...tx.fee_instructions]) {
      if (typeof instruction === "string" || !("StealthTransfer" in instruction)) continue;
      const { resource_address_ref, statement } = instruction.StealthTransfer;
      if (!("Address" in resource_address_ref)) continue;
      const resourceAddress = resource_address_ref.Address;
      for (const stealthOutput of statement.outputs_statement.outputs) {
        const commitmentHex = stealthOutput.output.commitment;
        if (knownCommitments.has(commitmentHex)) continue;
        try {
          const { value, memo } = await decryptInputData(crypto, fromHex(commitmentHex), fromHex(stealthOutput.output.encrypted_data), {
            senderPublicNonce: fromHex(stealthOutput.output.sender_public_nonce),
            viewSecret,
            skipMemo: false,
          });
          found.push({ resourceAddress, commitment: commitmentHex, amount: value, transactionId: entry.transaction_id, memo });
        } catch {
          // Not ours.
        }
      }
    }
  }
  return found;
}
