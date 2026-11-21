import { test } from "node:test";
import assert from "node:assert/strict";
import { encryptSecret, decryptSecret } from "./totpAuth.ts";

test("AES-GCM encrypt/decrypt with PIN", async () => {
  const secret = "JBSWY3DPEHPK3PXP";
  const pin = "1234";
  const blob = await encryptSecret(secret, pin);
  assert.ok(blob.length > secret.length);
  assert.ok(!blob.includes(secret));
  const out = await decryptSecret(blob, pin);
  assert.equal(out, secret);
});

test("wrong PIN fails", async () => {
  const blob = await encryptSecret("supersecret", "1111");
  await assert.rejects(() => decryptSecret(blob, "2222"));
});
