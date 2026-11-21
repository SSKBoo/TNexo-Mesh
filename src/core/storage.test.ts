import { test } from "node:test";
import assert from "node:assert/strict";
import { readKey, writeKey, migrate, memoryStorage } from "./storage.ts";

function makeStorage() {
  const map = new Map<string, string>();
  return {
    getItem: (k: string) => (map.has(k) ? (map.get(k) as string) : null),
    setItem: (k: string, v: string) => { map.set(k, v); },
    removeItem: (k: string) => { map.delete(k); },
    key: (i: number) => Array.from(map.keys())[i] ?? null,
    get length() { return map.size; },
    clear: () => { map.clear(); },
  };
}

test("writeKey/readKey use v1 prefix", () => {
  const s = makeStorage();
  writeKey("foo", "bar", s);
  assert.equal(s.getItem("nexomesh_v1_foo"), "bar");
  assert.equal(readKey("foo", s), "bar");
  assert.equal(s.getItem("foo"), null);
});

test("migrate renames unprefixed keys", () => {
  const s = makeStorage();
  s.setItem("legacy", "value");
  migrate(s);
  assert.equal(s.getItem("nexomesh_v1_legacy"), "value");
  assert.equal(s.getItem("legacy"), null);
});

test("migrate is idempotent", () => {
  const s = makeStorage();
  s.setItem("legacy", "value");
  migrate(s);
  migrate(s);
  assert.equal(s.getItem("nexomesh_v1_legacy"), "value");
  assert.equal(s.getItem("legacy"), null);
});

test("migrate does not overwrite existing prefixed", () => {
  const s = makeStorage();
  s.setItem("foo", "old");
  s.setItem("nexomesh_v1_foo", "new");
  migrate(s);
  assert.equal(s.getItem("nexomesh_v1_foo"), "new");
});

test("memoryStorage works", () => {
  memoryStorage.clear?.();
  writeKey("x", "y", memoryStorage);
  assert.equal(readKey("x", memoryStorage), "y");
});
