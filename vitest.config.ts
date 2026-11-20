import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    // @tari-project/ootle >= 0.19 imports @tari-project/ootle-ts-bindings at runtime, whose ESM uses
    // extensionless relative imports plain Node cannot resolve; let Vite transform the deps instead.
    server: {
      deps: {
        inline: true,
      },
    },
  },
});
