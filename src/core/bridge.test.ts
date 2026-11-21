import { test } from "node:test";
import assert from "node:assert/strict";
import { probeBridge, setMock, isMock } from "./bridge.ts";

test("probeBridge sets isMock false when health responds", async () => {
  setMock(true);
  const fetchFn = async () => new Response("ok", { status: 200 });
  const mock = await probeBridge(fetchFn as any);
  assert.equal(mock, false);
  assert.equal(isMock, false);
});

test("probeBridge sets isMock true when health fails", async () => {
  setMock(false);
  const fetchFn = async () => { throw new Error("down"); };
  const mock = await probeBridge(fetchFn as any);
  assert.equal(mock, true);
  assert.equal(isMock, true);
});

test("probeBridge sets isMock true on non-ok response", async () => {
  setMock(false);
  const fetchFn = async () => new Response("no", { status: 503 });
  const mock = await probeBridge(fetchFn as any);
  assert.equal(mock, true);
});
