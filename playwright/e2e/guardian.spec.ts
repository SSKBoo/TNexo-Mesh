import { test, expect } from "@playwright/test";

test("guardian smoke", async ({ page }) => {
  await page.goto("about:blank");
  expect(true).toBeTruthy();
});
