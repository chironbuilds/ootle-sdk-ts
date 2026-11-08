import { Network } from "@tari-project/ootle";

/** The networks this SDK creates accounts on. `"mainnet"` holds real value; the other two are testnets. */
export type NetworkName = "mainnet" | "esmeralda" | "igor";

/** Every `NetworkName`, mainnet first. */
export const NETWORK_NAMES: readonly NetworkName[] = ["mainnet", "esmeralda", "igor"];

/** True for a network whose funds have no value (anything but mainnet). */
export function isTestnet(name: NetworkName): boolean {
  return name !== "mainnet";
}

export function toOotleNetwork(name: NetworkName): Network {
  switch (name) {
    case "mainnet":
      return Network.MainNet;
    case "esmeralda":
      return Network.Esmeralda;
    case "igor":
      return Network.Igor;
    default:
      throw new Error(`Unknown network: ${name}`);
  }
}

/** The `NetworkName` for an Ootle network byte (as carried by an `otl_` address), or `undefined`. */
export function networkNameFromByte(byte: number): NetworkName | undefined {
  switch (byte) {
    case Network.MainNet:
      return "mainnet";
    case Network.Esmeralda:
      return "esmeralda";
    case Network.Igor:
      return "igor";
    default:
      return undefined;
  }
}

/** Accepts a `NetworkName` string and narrows it; anything else (an older stored value, a dApp's
 * parameter) is refused rather than guessed at. */
export function isNetworkName(value: unknown): value is NetworkName {
  return typeof value === "string" && (NETWORK_NAMES as readonly string[]).includes(value);
}

// Indexer endpoints. `@tari-project/ootle`'s `defaultIndexerUrl` knows only LocalNet and Esmeralda
// and throws for mainnet, so the SDK keeps its own table.
// - MainNet: tari-ootle's own default (`crates/wallet/ootle-rs/src/helpers.rs`, v0.50.1); the wallet
//   daemon preset lists indexer-b as its second.
// - Esmeralda: the URL `defaultIndexerUrl` has always returned, unchanged, so existing testnet
//   accounts keep talking to the same indexer.
// - Igor: no public indexer; set one with `setIndexerUrl`.
const DEFAULT_INDEXER_URLS: Partial<Record<Network, string>> = {
  [Network.MainNet]: "https://indexer-a.ootle.tari.com",
  [Network.Esmeralda]: "https://ootle-indexer-a.tari.com",
  [Network.LocalNet]: "http://localhost:12500",
};

const indexerOverrides = new Map<Network, string>();

/** The indexer this SDK uses for `network`: an override from `setIndexerUrl`, else the default.
 * Throws for a network with neither. Never has a trailing slash. */
export function indexerUrlFor(network: Network): string {
  const url = indexerOverrides.get(network) ?? DEFAULT_INDEXER_URLS[network];
  if (!url) throw new Error(`No indexer is configured for network ${Network[network] ?? network}. Set one with setIndexerUrl().`);
  return url;
}

/** Point `network` at another indexer (a self-hosted one, or a new public endpoint), or pass
 * `null` to go back to the default. Accounts created afterwards use it; an account that has
 * already connected keeps its connection. */
export function setIndexerUrl(network: Network, url: string | null): void {
  if (url === null) {
    indexerOverrides.delete(network);
    return;
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Not a valid indexer URL: ${url}`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error(`An indexer URL must be http(s): ${url}`);
  indexerOverrides.set(network, url.replace(/\/+$/, ""));
}
