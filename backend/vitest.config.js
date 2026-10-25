import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.js"],
    env: { NODE_ENV: "test" },
    // Integration files share one test database; run files sequentially.
    fileParallelism: false
  }
});
