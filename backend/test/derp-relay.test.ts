import { test } from "node:test";
import assert from "node:assert/strict";
import { SignalingHub } from "../src/signaling.ts";

class FakeSocket {
  sent: string[] = [];
  handlers: Record<string, (...a: any[]) => void> = {};
  send(data: string) { this.sent.push(data); }
  close() {}
  on(ev: string, cb: (...a: any[]) => void) { this.handlers[ev] = cb; }
  emit(ev: string, ...a: any[]) { this.handlers[ev]?.(...a); }
}

test("DERP-like relay reenvía frame NM1 binario sin descifrar", () => {
  const hub = new SignalingHub();
  const a = new FakeSocket();
  const b = new FakeSocket();
  hub.register("peerA", a as any);
  hub.register("peerB", b as any);

  // NM1 | len=8 | 10.0.0.2 | ciphertext simulado
  const vip = Buffer.from("10.0.0.2");
  const frame = Buffer.concat([Buffer.from([0x4e, 0x4d, 0x31, vip.length]), vip, Buffer.from("CIPHERTEXT")]);

  // Emitir como Buffer (ws entrega binarios así)
  a.emit("message", frame);

  assert.equal(b.sent.length, 1, "B debe recibir el relay");
  const msg = JSON.parse(b.sent[0]);
  assert.equal(msg.type, "relay");
  assert.equal(msg.from, "peerA");
  assert.equal(Buffer.from(msg.data, "base64").toString("hex"), frame.toString("hex"));
  const aRelays = a.sent.filter((s) => { try { return JSON.parse(s).type === "relay"; } catch { return false; } });
  assert.equal(aRelays.length, 0, "el emisor no debe recibir su propio frame relay");
  assert.ok(!b.sent[0].includes("CIPHERTEXT"), "el payload viaja en base64, no en claro");
});
