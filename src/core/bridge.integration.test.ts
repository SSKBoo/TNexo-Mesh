import { test } from "node:test";
import assert from "node:assert/strict";
import { probeBridge, getStatus, sendCommand, isMock } from "./bridge.ts";

test("bridge real: health -> isMock false, status y command", async () => {
  if (!process.env.NEXOMESH_BRIDGE_LIVE) return;
  const mock = await probeBridge();
  assert.equal(mock, false);
  assert.equal(isMock, false);

  const status = await getStatus();
  assert.equal(status.ok, true);
  assert.equal(status.peers, 2);
  assert.equal(status.virtualIp, "10.0.0.2");

  const result = await sendCommand("status", { foo: "bar" });
  assert.equal(result.ok, true);
  assert.equal((result as any).echoed.command, "status");
});
