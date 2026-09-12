import { describe, expect, it } from "vitest";
import { withTimeout } from "./timeout";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("withTimeout", () => {
  it("resolves with the inner value when it settles before the timeout", async () => {
    const result = await withTimeout(Promise.resolve("done"), 200, "doing a thing");
    expect(result).toBe("done");
  });

  it("rejects with the inner error when it rejects before the timeout", async () => {
    await expect(withTimeout(Promise.reject(new Error("boom")), 200, "doing a thing")).rejects.toThrow("boom");
  });

  it("rejects with a timeout error, including the label, when the promise never settles in time", async () => {
    const neverSettles = new Promise<void>(() => {});
    await expect(withTimeout(neverSettles, 20, "waiting for the indexer")).rejects.toThrow(
      "Timed out after 20ms while waiting for the indexer."
    );
  });

  it("does not fire the timeout once the inner promise has already resolved", async () => {
    const fast = sleep(10).then(() => "fast");
    const result = await withTimeout(fast, 20, "should not matter");
    expect(result).toBe("fast");
    // If clearTimeout wasn't actually called, this would still be safe (the promise already
    // resolved), but waiting past the original deadline here would surface an unhandled rejection
    // in the test run if the timer fired anyway.
    await sleep(30);
  });
});
