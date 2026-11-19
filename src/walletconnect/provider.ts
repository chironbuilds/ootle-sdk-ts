// dApp-side WalletConnect v2 connector for Tari wallets. Returns an object shaped like the injected
// window.tari provider -- request({ method, params }), on/off for accountsChanged/networkChanged --
// so a dApp that already talks to window.tari can switch transports without touching its calls:
//
//   import { createWalletConnectProvider } from "@chironbuilder/ootle-sdk/walletconnect";
//   const tari = await createWalletConnectProvider({ network: "mainnet", metadata,
//     onDisplayUri: (uri) => showQr(uri) });
//   const [address] = await tari.connect();
//   const balances = await tari.request({ method: "tari_getBalances" });
//
// Requires the optional peer dependency @walletconnect/universal-provider.
// Named, not default: Node resolves this package to its CommonJS build, where the default export
// is the whole module object rather than the class (bundlers pick the ESM build, which has both).
import { UniversalProvider } from "@walletconnect/universal-provider";
import { isNetworkName, type NetworkName } from "../ootleNetwork.js";
import { TARI_WC_EVENTS, TARI_WC_METHODS, TARI_WC_NAMESPACE, wcChainId, type TariWcEvent, type TariWcMethod } from "./namespace.js";

export interface TariWalletConnectMetadata {
  name: string;
  description: string;
  url: string;
  icons: string[];
}

/**
 * Shared Reown project id used when a dApp doesn't pass its own. Fine for trying things out; in production pass
 * your own (free at cloud.reown.com) for your own relay quota and so Reown Verify can mark your domain verified.
 */
export const DEFAULT_WC_PROJECT_ID = "8bb31c50def7dc5a660461ff56b86588";

export interface TariWalletConnectOptions {
  /** Reown (WalletConnect) Cloud project id for this dApp. Optional; defaults to DEFAULT_WC_PROJECT_ID. */
  projectId?: string;
  /** The network the dApp runs on. The wallet refuses the session if it is on another one. */
  network: NetworkName;
  metadata: TariWalletConnectMetadata;
  /**
   * Called with the pairing URI when connect() needs a new session. Show it as a QR code for a
   * wallet on another device; on a phone, open sapientDeepLink(uri) to hand it to the wallet app.
   */
  onDisplayUri?: (uri: string) => void;
  /** Override the relay (defaults to WalletConnect's). */
  relayUrl?: string;
}

type Listener = (data: unknown) => void;

export interface TariWalletConnectProvider {
  /** Pairs with a wallet (or reuses a restored session) and returns the connected account(s). */
  connect(): Promise<string[]>;
  /** Sends one window.tari-style request to the wallet. */
  request<T = unknown>(args: { method: TariWcMethod; params?: unknown }): Promise<T>;
  on(event: TariWcEvent | "disconnect", listener: Listener): void;
  off(event: TariWcEvent | "disconnect", listener: Listener): void;
  /** Ends the session on both sides. */
  disconnect(): Promise<void>;
  /** Whether a session is live. */
  readonly connected: boolean;
  /** The network requests currently go to (follows the wallet's networkChanged events). */
  readonly network: NetworkName;
  /** The wallet's self-reported name, once connected. */
  readonly walletName: string | null;
}

/** A deep link that opens Sapient on this phone with a pairing URI (for dApps running on mobile). */
export function sapientDeepLink(uri: string): string {
  return `sapient://wc?uri=${encodeURIComponent(uri)}`;
}

/** The address part of CAIP-10 accounts ("tari:<network>:<address>") on `chain`. */
export function accountsOnChain(accounts: readonly string[], chain: string): string[] {
  const prefix = `${chain}:`;
  return accounts.filter((a) => a.startsWith(prefix)).map((a) => a.slice(prefix.length));
}

export async function createWalletConnectProvider(options: TariWalletConnectOptions): Promise<TariWalletConnectProvider> {
  // The chain requests go to. Starts as the dApp's network; follows the wallet when it reports a
  // network change (a tari_switchNetwork the user approved moves the session to the new chain).
  let chain = wcChainId(options.network);
  const provider = await UniversalProvider.init({
    projectId: options.projectId || DEFAULT_WC_PROJECT_ID,
    metadata: options.metadata,
    relayUrl: options.relayUrl,
  });

  const listeners = new Map<string, Set<Listener>>();
  const emit = (event: string, data: unknown) => {
    for (const listener of listeners.get(event) ?? []) {
      try {
        listener(data);
      } catch {
        // A throwing dApp listener must not break the others.
      }
    }
  };

  if (options.onDisplayUri) provider.on("display_uri", options.onDisplayUri);
  provider.on("session_event", (e: { params: { event: { name: string; data: unknown }; chainId: string } }) => {
    const { name, data } = e.params.event;
    if (name === "networkChanged" && typeof data === "string" && isNetworkName(data)) chain = wcChainId(data);
    if ((TARI_WC_EVENTS as readonly string[]).includes(name)) emit(name, data);
  });
  provider.on("session_delete", () => emit("disconnect", null));

  return {
    async connect() {
      if (!provider.session) {
        await provider.connect({
          // Optional rather than required, as WalletConnect recommends; the wallet still checks
          // the chain and refuses a session for a network it isn't on.
          optionalNamespaces: {
            [TARI_WC_NAMESPACE]: {
              chains: [chain],
              methods: [...TARI_WC_METHODS],
              events: [...TARI_WC_EVENTS],
            },
          },
        });
      }
      const accounts = accountsOnChain(provider.session?.namespaces[TARI_WC_NAMESPACE]?.accounts ?? [], chain);
      if (accounts.length > 0) return accounts;
      return provider.request<string[]>({ method: "tari_requestAccounts", params: {} }, chain);
    },

    async request<T>({ method, params }: { method: TariWcMethod; params?: unknown }): Promise<T> {
      if (!provider.session) throw new Error("Not connected: call connect() first.");
      const result = await provider.request<T>({ method, params: (params ?? {}) as object }, chain);
      // An approved switch answers with the new network; follow it right away rather than
      // waiting for the networkChanged event, so the very next request already targets it.
      if (method === "tari_switchNetwork" && isNetworkName(result)) chain = wcChainId(result);
      return result;
    },

    on(event, listener) {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event)!.add(listener);
    },

    off(event, listener) {
      listeners.get(event)?.delete(listener);
    },

    async disconnect() {
      if (provider.session) await provider.disconnect();
      emit("disconnect", null);
    },

    get connected() {
      return Boolean(provider.session);
    },

    get network() {
      return chain.slice(TARI_WC_NAMESPACE.length + 1) as NetworkName;
    },

    get walletName() {
      return provider.session?.peer.metadata.name ?? null;
    },
  };
}
