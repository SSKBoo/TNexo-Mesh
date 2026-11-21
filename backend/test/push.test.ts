import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createPushRouter, _resetSubscriptions } from "../src/push.ts";

test("push subscribe", async () => {
  _resetSubscriptions();
  const app = express();
  app.use(express.json());
  app.use("/push", createPushRouter());
  const server = app.listen(0);
  const port = (server.address() as any).port;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/push/subscribe`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpoint: "https://example.com/push/1", keys: { p256dh: "a", auth: "b" } }),
    });
    assert.equal(res.status, 200);
    const j = (await res.json()) as { ok: boolean };
    assert.equal(j.ok, true);
  } finally {
    server.close();
  }
});
