// The WalletConnect v2 namespace Tari wallets serve (Sapient for Android implements it): the same
// methods and events as the injected window.tari provider, under CAIP-2 chains "tari:<network>".
// Kept free of any WalletConnect import so wallets can share these constants without the client.
import type { NetworkName } from "../ootleNetwork.js";

export const TARI_WC_NAMESPACE = "tari";

export const TARI_WC_METHODS = [
  "tari_requestAccounts",
  "tari_getAccounts",
  "tari_getNetwork",
  "tari_switchNetwork",
  "tari_getWalletAddress",
  "tari_getBalances",
  "tari_getSubstate",
  "tari_getCapabilities",
  "tari_getTransactionResult",
  "tari_signAndSubmitTransaction",
  "tari_withdrawStealthAndExecute",
  "tari_htlcFund",
  "tari_createTransactionRequest",
  "tari_getTransactionRequest",
  "tari_submitTransactionRequest",
  "tari_requestViewAccess",
  "tari_getViewAccess",
  "tari_revokeViewAccess",
  "tari_getPrivateBalances",
  "tari_getShieldedOutputs",
  "tari_scanForPrivatePayments",
  "tari_scanForResourceUtxos",
  "tari_scanForOwnedUtxos",
  "tari_claimPrivatePayment",
  "tari_signOwnershipChallenge",
  "tari_signWalletOwnershipChallenge",
  "tari_disconnect",
] as const;

export type TariWcMethod = (typeof TARI_WC_METHODS)[number];

export const TARI_WC_EVENTS = ["accountsChanged", "networkChanged"] as const;

export type TariWcEvent = (typeof TARI_WC_EVENTS)[number];

export function wcChainId(network: NetworkName): string {
  return `${TARI_WC_NAMESPACE}:${network}`;
}
