import { test } from "node:test";
import assert from "node:assert/strict";
import { SignalingHub } from "../src/signaling.ts";

test("register and remove", () => {
  const hub = new SignalingHub();
  const sent: string[] = [];
  const sock: any = { send: (d: string) => sent.push(d), close: () => {}, on: () => {} };
  hub.register("pk1", sock);
  assert.equal(hub.has("pk1"), true);
  assert.equal(hub.size, 1);
  hub.remove("pk1");
  assert.equal(hub.has("pk1"), false);
});

test("offer forwards to target", () => {
  const hub = new SignalingHub();
  const sentA: string[] = [];
  const sentB: string[] = [];
  const sockA: any = { send: (d: string) => sentA.push(d), close: () => {}, on: (e: string, cb: any) => {} };
  const sockB: any = { send: (d: string) => sentB.push(d), close: () => {}, on: (e: string, cb: any) => {} };
  hub.register("A", sockA);
  hub.register("B", sockB);
  // trigger message handler manually by calling private? Instead use socket on message capture
  // Re-register with capture
  // Simpler: invoke hub.handleMessage via any
  (hub as any).handleMessage("A", JSON.stringify({ type: "offer", to: "B", payload: { sdp: "x" } }));
  assert.ok(sentB.some((s) => s.includes("offer")));
});
