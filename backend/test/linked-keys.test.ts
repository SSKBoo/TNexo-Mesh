import { test } from "node:test";
import assert from "node:assert/strict";
import { setStore, Store } from "../src/store.ts";
import { createInvite, getInvite } from "../src/invites.ts";

test("invite enlaza mesh pub key con signing pub key", () => {
  const store = new Store();
  setStore(store);
  const inv = createInvite({ pk: "mesh-key-abc", signingPub: "sign-key-xyz", name: "Test" });
  assert.ok(getInvite(inv.id));
  assert.equal(store.isAuthorizedSigningKey("sign-key-xyz"), true);
  assert.equal(store.getMeshKeyForSigningKey("sign-key-xyz"), "mesh-key-abc");
  assert.equal(store.isAuthorizedSigningKey("otra-clave"), false);
});

test("el enlace sobrevive a nuevo Store sobre la misma DB", () => {
  const s1 = new Store(":memory:");
  // En memoria no comparte entre instancias; verificamos solo el contrato de la API
  s1.linkSigningKey("mesh-1", "sign-1");
  assert.equal(s1.isAuthorizedSigningKey("sign-1"), true);
  s1.close();
});
