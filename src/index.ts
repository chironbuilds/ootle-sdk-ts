// Public surface. Import from the package root ("@chironbuilds/ootle-sdk") rather than reaching
// into individual files -- the module layout underneath is free to change; this file is not.

export type { TransactionExecuteOpts, WalletAccountApi } from "./accountApi";

export {
  ACCOUNT_TEMPLATE_ADDRESS,
  componentAddressFromWalletAddress,
  deriveAccountComponentAddress,
  deriveComponentAddress,
} from "./componentAddress";

export type { ConfidentialSumResult, ScannedStealthOutput } from "./confidential";
export { scanTransactionsForOwnedOutputs, sumConfidentialCommitments } from "./confidential";

export type { DerivedAccountKeys } from "./derivation";
export { deriveAccountKeys } from "./derivation";

export { DomainSeparatedHasher, KEY_MANAGER_DOMAIN, KEY_MANAGER_DOMAIN_VERSION, keyManagerDomainHasher } from "./domainHash";

export type { HtlcConditionsParams } from "./htlc";
export { accessRuleRequiringPublicKey, htlcConditions } from "./htlc";

export type { NetworkName } from "./ootleNetwork";
export { toOotleNetwork } from "./ootleNetwork";

export { OWNERSHIP_PROOF_CHALLENGE_MAX_LENGTH, buildOwnershipProofMessage, buildWalletOwnershipMessage } from "./ownershipProof";

export type { EncryptedVault } from "./vault";
export { decryptVault, encryptVault, fromHex, toHex } from "./vault";

export { withTimeout } from "./timeout";

export type { KeyValueStore, PendingShield, ShieldedOutputRecord } from "./storage";
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
} from "./storage";

export { chromeStorageAdapter, inMemoryAdapter, localStorageAdapter } from "./adapters";

export type { PrivateBalance, TokenBalance } from "./wallet";
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
} from "./wallet";
