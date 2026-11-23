import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import WebSocket from "ws";
import { attachSignalingToHttpServer, SignalingHub } from "../src/signaling.ts";

class FakeSocket {
  sent: string[] = [];
  handlers: Record<string, (...a: any[]) => void> = {};
  send(data: string) { this.sent.push(data); }
  close() {}
  on(ev: string, cb: (...a: any[]) => void) { this.handlers[ev] = cb; }
  emit(ev: string, ...a: any[]) { this.handlers[ev]?.(...a); }
}

test("DERP rechaza broadcast NM1 inseguro y exige NM2 dirigido", () => {
  const hub = new SignalingHub();
  const a = new FakeSocket();
  const b = new FakeSocket();
  hub.register("peerA", a as any);
  hub.register("peerB", b as any);
  a.sent.length = 0;
  b.sent.length = 0;

  const vip = Buffer.from("10.0.0.2");
  const nm1 = Buffer.concat([Buffer.from([0x4e, 0x4d, 0x31, vip.length]), vip, Buffer.from("CIPHERTEXT")]);
  a.emit("message", nm1);

  assert.equal(b.sent.length, 0, "NM1 no debe hacerse broadcast a B");
  const err = JSON.parse(a.sent[0]);
  assert.equal(err.type, "error");
  assert.ok(String(err.payload).includes("nm1 broadcast rejected"));
});

test("JSON relay exige destinatario `to` y rechaza broadcast sin `to`", () => {
  const hub = new SignalingHub();
  const a = new FakeSocket();
  const b = new FakeSocket();
  hub.register("peerA", a as any);
  hub.register("peerB", b as any);
  a.sent.length = 0;
  b.sent.length = 0;

  a.emit("message", JSON.stringify({ type: "relay", data: "NM1PAYLOAD" }));
  assert.equal(b.sent.length, 0, "JSON relay sin `to` no debe transmitirse");
  assert.equal(JSON.parse(a.sent.at(-1)!).type, "error");

  a.emit("message", JSON.stringify({ type: "relay", to: "peerB", data: "NM2PAYLOAD" }));
  const bRelay = JSON.parse(b.sent.at(-1)!);
  assert.equal(bRelay.type, "relay");
  assert.equal(bRelay.from, "peerA");
  assert.equal(bRelay.data, "NM2PAYLOAD");
});

test("attachSignalingToHttpServer sirve relay dirigido sobre /ws en un único puerto", async () => {
  const server = createServer((_req, res) => {
    res.writeHead(200);
    res.end("ok");
  });
  const hub = new SignalingHub();
  const wss = attachSignalingToHttpServer(server, false, () => true, hub, "/ws");
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as { port: number };
  const wsUrl = `ws://127.0.0.1:${addr.port}/ws`;

  const wsA = new WebSocket(wsUrl);
  const wsB = new WebSocket(wsUrl);
  await Promise.all([
    new Promise<void>((r) => wsA.on("open", () => r())),
    new Promise<void>((r) => wsB.on("open", () => r())),
  ]);

  const receivedB: any[] = [];
  wsB.on("message", (raw) => receivedB.push(JSON.parse(String(raw))));

  wsA.send(JSON.stringify({ type: "register", from: "nodeA" }));
  wsB.send(JSON.stringify({ type: "register", from: "nodeB" }));
  await new Promise((r) => setTimeout(r, 80));

  wsA.send(JSON.stringify({ type: "relay", to: "nodeB", data: Buffer.from("CIPHER").toString("base64") }));
  await new Promise((r) => setTimeout(r, 80));

  const relay = receivedB.find((m) => m.type === "relay");
  assert.ok(relay, "nodeB debe recibir el frame dirigido por /ws");
  assert.equal(relay.from, "nodeA");

  wsA.close();
  wsB.close();
  wss.close();
  await new Promise<void>((r) => server.close(() => r()));
});
