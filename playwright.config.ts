import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./playwright/e2e",
  use: {
    headless: true,
  },
  reporter: [["list"]],
});
