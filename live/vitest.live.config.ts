import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["live/**/*.live.test.ts"],
    testTimeout: 3 * 60 * 60_000,
    hookTimeout: 60_000,
    // See vitest.config.ts: ootle >= 0.19 needs its deps transformed by Vite under Node.
    server: { deps: { inline: true } },
  },
});
