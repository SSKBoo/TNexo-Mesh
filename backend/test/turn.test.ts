import { test } from "node:test";
import assert from "node:assert/strict";
import { generateCredentials } from "../src/turn.ts";

test("credentials shape", () => {
  const c = generateCredentials();
  assert.equal(typeof c.username, "string");
  assert.equal(typeof c.password, "string");
  assert.equal(c.ttl, 3600);
});
