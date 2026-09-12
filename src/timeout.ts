// A hung fetch (or any other network stall) inside a page-triggered request otherwise blocks that
// page's promise forever with no error and no way to recover short of reloading the extension —
// confirmed empirically hitting exactly this waiting on a testnet indexer response, and again
// waiting on an unreachable wallet daemon (a plain `fetch()` to a port nothing is listening on
// doesn't reject quickly on every platform). Every individual network step in OotleAccount's and
// DaemonAccount's execute() is wrapped in this so a stall surfaces as a clear timeout error
// instead of an indefinite hang.
export function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timed out after ${ms}ms while ${label}.`)), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      }
    );
  });
}
