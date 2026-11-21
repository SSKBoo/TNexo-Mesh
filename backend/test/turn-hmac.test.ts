import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { generateCredentials, verifyTurnPassword } from "../src/turn.ts";

test("turn credentials use coturn HMAC-SHA1 long-term format", () => {
  const secret = "test-secret";
  const c = generateCredentials(secret);
  const [ts, user] = c.username.split(":");
  assert.ok(Number(ts) > Date.now() / 1000, "username empieza con timestamp futuro");
  assert.ok(user.length > 0);
  const expected = crypto.createHmac("sha1", secret).update(c.username).digest("base64");
  assert.equal(c.password, expected);
  assert.equal(c.ttl, 3600);
});

test("verifyTurnPassword accepts valid and rejects invalid", () => {
  const secret = "test-secret";
  const c = generateCredentials(secret);
  assert.equal(verifyTurnPassword(c.username, c.password, secret), true);
  assert.equal(verifyTurnPassword(c.username, "wrong", secret), false);
  assert.equal(verifyTurnPassword("9999999999:other", c.password, secret), false);
});
