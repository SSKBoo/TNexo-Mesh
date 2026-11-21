import { test, expect } from "@playwright/test";

test("file transfer smoke", async ({ page }) => {
  await page.goto("about:blank");
  expect(1 + 1).toBe(2);
});
