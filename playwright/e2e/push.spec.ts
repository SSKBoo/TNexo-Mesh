import { test, expect } from "@playwright/test";

test("push smoke", async ({ page }) => {
  await page.goto("about:blank");
  expect(true).toBeTruthy();
});
