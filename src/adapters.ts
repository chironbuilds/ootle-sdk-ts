// Ready-made `KeyValueStore` adapters for the two hosts this SDK is known to run in. Pass one to
// `configureOotleStorage()` once at startup; write your own for any other host (see the interface
// in storage.ts -- it's three methods).

import type { KeyValueStore } from "./storage";

/** For a Chrome (or any Manifest V3) extension. `chrome.storage.local` already stores structured
 * values natively, so this is a thin wrapper, not a serializer. */
export function chromeStorageAdapter(area: chrome.storage.StorageArea = chrome.storage.local): KeyValueStore {
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const stored = await area.get(key);
      return stored[key] as T | undefined;
    },
    async set<T>(key: string, value: T): Promise<void> {
      await area.set({ [key]: value });
    },
    async remove(key: string): Promise<void> {
      await area.remove(key);
    },
  };
}

/** For a plain web page. `localStorage` only stores strings, so this serializes to/from JSON;
 * unavailable or over quota (private browsing, storage disabled) degrades to "nothing was ever
 * stored" rather than throwing, so a host can't be taken down by a browser storage restriction it
 * doesn't control. */
export function localStorageAdapter(prefix = ""): KeyValueStore {
  return {
    async get<T>(key: string): Promise<T | undefined> {
      try {
        const raw = localStorage.getItem(prefix + key);
        return raw === null ? undefined : (JSON.parse(raw) as T);
      } catch {
        return undefined;
      }
    },
    async set<T>(key: string, value: T): Promise<void> {
      try {
        localStorage.setItem(prefix + key, JSON.stringify(value));
      } catch {
        /* quota or disabled storage -- the in-flight operation still completes in memory */
      }
    },
    async remove(key: string): Promise<void> {
      try {
        localStorage.removeItem(prefix + key);
      } catch {
        /* nothing to do */
      }
    },
  };
}

/** For tests, or a short-lived context with no real persistence -- state lives only as long as
 * this object does. */
export function inMemoryAdapter(): KeyValueStore {
  const map = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      return map.get(key) as T | undefined;
    },
    async set<T>(key: string, value: T): Promise<void> {
      map.set(key, value);
    },
    async remove(key: string): Promise<void> {
      map.delete(key);
    },
  };
}
