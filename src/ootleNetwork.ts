import { Network } from "@tari-project/ootle";

export type NetworkName = "esmeralda" | "igor";

export function toOotleNetwork(name: NetworkName): Network {
  switch (name) {
    case "esmeralda":
      return Network.Esmeralda;
    case "igor":
      return Network.Igor;
    default:
      throw new Error(`Unknown network: ${name}`);
  }
}
