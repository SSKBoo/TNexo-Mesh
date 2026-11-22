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

test("JSON relay sin `to` y list-peers funcionan para RelayClient", () => {
  const hub = new SignalingHub();
  const a = new FakeSocket();
  const b = new FakeSocket();
  hub.register("peerA", a as any);
  hub.register("peerB", b as any);

  a.emit("message", JSON.stringify({ type: "list-peers" }));
  const peersMsg = JSON.parse(a.sent.at(-1)!);
  assert.equal(peersMsg.type, "peers");
  assert.deepEqual(peersMsg.peers, ["peerB"]);

  a.emit("message", JSON.stringify({ type: "relay", data: "NM1PAYLOAD" }));
  const bRelay = JSON.parse(b.sent.at(-1)!);
  assert.equal(bRelay.type, "relay");
  assert.equal(bRelay.from, "peerA");
  assert.equal(bRelay.data, "NM1PAYLOAD");
});

test("attachSignalingToHttpServer sirve relay DERP sobre /ws en un único puerto", async () => {
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

  wsA.send(JSON.stringify({ type: "relay", data: Buffer.from("NM1\x0810.0.0.2ENC").toString("base64") }));
  await new Promise((r) => setTimeout(r, 80));

  const relay = receivedB.find((m) => m.type === "relay");
  assert.ok(relay, "nodeB debe recibir el frame por /ws");
  assert.equal(relay.from, "nodeA");

  wsA.close();
  wsB.close();
  wss.close();
  await new Promise<void>((r) => server.close(() => r()));
});
