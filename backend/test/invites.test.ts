import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createInvitesRouter, _resetInvites } from "../src/invites.ts";

test("invite create and get", async () => {
  _resetInvites();
  const app = express();
  app.use(express.json());
  app.use("/", createInvitesRouter());
  const server = app.listen(0);
  const port = (server.address() as any).port;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/invite`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hello: "world" }),
    });
    assert.equal(res.status, 201);
    const inv = (await res.json()) as { id: string };
    assert.ok(inv.id);
    const res2 = await fetch(`http://127.0.0.1:${port}/invite/${inv.id}`);
    assert.equal(res2.status, 200);
    const got = (await res2.json()) as { id: string };
    assert.equal(got.id, inv.id);
  } finally {
    server.close();
  }
});

test("invite 404 for unknown", async () => {
  _resetInvites();
  const app = express();
  app.use(express.json());
  app.use("/", createInvitesRouter());
  const server = app.listen(0);
  const port = (server.address() as any).port;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/invite/nope`);
    assert.equal(res.status, 404);
  } finally {
    server.close();
  }
});
