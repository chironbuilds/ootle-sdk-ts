// Public surface. Import from the package root ("@chironbuilder/ootle-sdk") rather than reaching
// into individual files -- the module layout underneath is free to change; this file is not.

export type { TransactionExecuteOpts, WalletAccountApi } from "./accountApi.js";

export {
  ACCOUNT_TEMPLATE_ADDRESS,
  componentAddressFromWalletAddress,
  deriveAccountComponentAddress,
  deriveComponentAddress,
} from "./componentAddress.js";

export type { ConfidentialSumResult, ScannedStealthOutput } from "./confidential.js";
export { scanTransactionsForOwnedOutputs, sumConfidentialCommitments } from "./confidential.js";

export type { DerivedAccountKeys } from "./derivation.js";
export { deriveAccountKeys } from "./derivation.js";

export { DomainSeparatedHasher, KEY_MANAGER_DOMAIN, KEY_MANAGER_DOMAIN_VERSION, keyManagerDomainHasher } from "./domainHash.js";

export type { HtlcConditionsParams } from "./htlc.js";
export { accessRuleRequiringPublicKey, htlcConditions } from "./htlc.js";

export type { NetworkName } from "./ootleNetwork.js";
export { toOotleNetwork } from "./ootleNetwork.js";

export { OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH, buildOwnershipProofMessage, buildWalletOwnershipMessage } from "./ownershipProof.js";

export type { EncryptedVault } from "./vault.js";
export { decryptVault, encryptVault, fromHex, toHex } from "./vault.js";

export { withTimeout } from "./timeout.js";

export type { KeyValueStore, PendingShield, ShieldedOutputRecord } from "./storage.js";
export {
  addPendingShield,
  addShieldedOutput,
  configureOotleStorage,
  getKnownVersions,
  getPrivatePaymentScanCursor,
  listPendingShields,
  listShieldedOutputs,
  localAccountId,
  markShieldedOutputSpent,
  removePendingShield,
  serialized,
  setKnownVersions,
  setPrivatePaymentScanCursor,
  wipeOotleState,
} from "./storage.js";

export { chromeStorageAdapter, inMemoryAdapter, localStorageAdapter } from "./adapters.js";

export type { PrivateBalance, TokenBalance } from "./wallet.js";
export {
  OotleAccount,
  assertValidMinimumValuePromise,
  buildHtlcSpendStatement,
  extractMissingSubstateAddress,
  extractStaleLockVersion,
  forgetKnownVersions,
  pollTransactionResult,
  recoverPendingShields,
  resetKnownVersions,
  resolveInputsWithRetry,
  resolveSendPrivatelyPlan,
  resolveUnshieldPlan,
  selectShieldedUtxosForAmount,
  selectUnspentShieldedOutputs,
  substateExists,
  summarizePrivateHoldings,
  synthesizeShieldedOnlyBalances,
} from "./wallet.js";
