import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createServer } from "node:http";
import WebSocket from "ws";
import { NetMapAuthority, verifyIdentityBinding, verifySignedNetMap } from "../src/netmap.ts";
import { attachSignalingToHttpServer, DerpMeshRouter, SignalingHub } from "../src/signaling.ts";
import { createApp } from "../src/index.ts";
import { Store } from "../src/store.ts";

class FakeSocket {
  sent: string[] = [];
  handlers: Record<string, (...a: any[]) => void> = {};
  send(data: string) { this.sent.push(data); }
  close() {}
  on(ev: string, cb: (...a: any[]) => void) { this.handlers[ev] = cb; }
  emit(ev: string, ...a: any[]) { this.handlers[ev]?.(...a); }
}

function genEd() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubB64 = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  const pubRaw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return {
    pubB64,
    pubRaw,
    sign: (msg: string) => crypto.sign(null, Buffer.from(msg), privateKey).toString("base64"),
  };
}

test("NM2 DERP dirigido entrega solo al destinatario de 32 bytes sin broadcast", () => {
  const hub = new SignalingHub();
  const a = genEd();
  const b = genEd();
  const c = genEd();
  const sa = new FakeSocket();
  const sb = new FakeSocket();
  const sc = new FakeSocket();

  hub.register(a.pubB64, sa as any);
  hub.register(b.pubB64, sb as any);
  hub.register(c.pubB64, sc as any);
  sa.sent.length = 0; sb.sent.length = 0; sc.sent.length = 0;

  const payload = Buffer.from("NM1\x0810.0.0.2ENC");
  const nm2 = Buffer.concat([Buffer.from("NM2"), b.pubRaw, payload]);
  sa.emit("message", nm2);

  assert.equal(sb.sent.length, 1, "B debe recibir el paquete dirigido");
  assert.equal(sc.sent.length, 0, "C no debe recibir tráfico de A->B");
  const parsed = JSON.parse(sb.sent[0]);
  assert.equal(parsed.type, "relay");
  assert.equal(parsed.from, a.pubB64);
  assert.equal(Buffer.from(parsed.data, "base64").toString("hex"), payload.toString("hex"));
});

test("NetMapAuthority verifica vínculo X25519<->Ed25519, aprobación, expiración y firma", () => {
  const auth = new NetMapAuthority();
  const id = genEd();
  const nodeKey = "X25519_NODE_KEY_1";

  // Prueba inválida falla
  assert.equal(verifyIdentityBinding(nodeKey, id.pubB64, id.sign("wrong")), false);
  assert.throws(() =>
    auth.registerNode(
      { nodeKey, signingKey: id.pubB64, userId: "u@test", virtualIp: "10.0.0.2", endpoints: [], subnets: [] },
      id.sign("wrong")
    )
  );

  // Registro válido pero aún no aprobado
  auth.registerNode(
    { nodeKey, signingKey: id.pubB64, userId: "u@test", virtualIp: "10.0.0.2", endpoints: ["1.2.3.4:51820"], subnets: ["192.168.1.0/24"] },
    id.sign(`bind:${nodeKey}`)
  );
  assert.equal(auth.isActiveAndApproved(id.pubB64), false);
  assert.equal(auth.issueSignedNetMap().payload.nodes.length, 0);

  // Aprobar dispositivo -> aparece en NetMap firmado
  auth.approveDevice(id.pubB64, true);
  assert.equal(auth.isActiveAndApproved(id.pubB64), true);
  const netmap = auth.issueSignedNetMap();
  assert.equal(netmap.payload.nodes.length, 1);
  assert.equal(netmap.payload.nodes[0].userId, "u@test");
  assert.equal(verifySignedNetMap(netmap), true);

  // Expiración de llave
  assert.equal(auth.isActiveAndApproved(id.pubB64, Date.now() + 30 * 24 * 60 * 60 * 1000), false);
});

test("Malla multi-región DERP enruta NM2 entre región 1 y región 2 y persiste NetMap", () => {
  const store = new Store(":memory:");
  const auth = new NetMapAuthority(store);
  const a = genEd();
  const b = genEd();
  auth.registerNode(
    { nodeKey: "NODE_A", signingKey: a.pubB64, userId: "a@mesh", virtualIp: "10.0.0.2", approved: true, homeDerp: 1, endpoints: [], subnets: [] },
    a.sign("bind:NODE_A")
  );
  auth.registerNode(
    { nodeKey: "NODE_B", signingKey: b.pubB64, userId: "b@mesh", virtualIp: "10.0.0.3", approved: true, homeDerp: 2, endpoints: [], subnets: [] },
    b.sign("bind:NODE_B")
  );

  // Simular reinicio del plano de control cargando desde el mismo Store SQLite
  const restartedAuth = new NetMapAuthority(store);
  assert.equal(restartedAuth.isActiveAndApproved(a.pubB64), true);
  assert.equal(restartedAuth.isActiveAndApproved(b.pubB64), true);

  const router = new DerpMeshRouter();
  const hub1 = new SignalingHub(1, router, restartedAuth);
  const hub2 = new SignalingHub(2, router, restartedAuth);
  const sa = new FakeSocket();
  const sb = new FakeSocket();
  hub1.register(a.pubB64, sa as any);
  hub2.register(b.pubB64, sb as any);
  sa.sent.length = 0;
  sb.sent.length = 0;

  const payload = Buffer.from("ENCRYPTED_PACKET");
  const nm2 = Buffer.concat([Buffer.from("NM2"), b.pubRaw, payload]);
  sa.emit("message", nm2);

  assert.equal(sb.sent.length, 1, "B en región 2 debe recibir el frame NM2 originado en región 1");
  const msg = JSON.parse(sb.sent[0]);
  assert.equal(msg.type, "relay");
  assert.equal(msg.from, a.pubB64);
  assert.equal(msg.viaRegion, 2);
  assert.equal(Buffer.from(msg.data, "base64").toString("hex"), payload.toString("hex"));
});

test("WS register exige firma válida, vínculo X25519<->Ed25519 y aprobación en NetMapAuthority", async () => {
  const store = new Store(":memory:");
  const auth = new NetMapAuthority(store);
  const dev = genEd();
  auth.registerNode(
    { nodeKey: "X25519_DEV", signingKey: dev.pubB64, userId: "dev@mesh", virtualIp: "10.0.0.4", approved: false, endpoints: [], subnets: [] },
    dev.sign("bind:X25519_DEV")
  );

  const server = createServer((_req, res) => { res.writeHead(200); res.end("ok"); });
  const hub = new SignalingHub(1, undefined, auth);
  const wss = attachSignalingToHttpServer(server, true, () => true, hub, "/ws", auth);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address() as { port: number };
  const url = `ws://127.0.0.1:${addr.port}/ws`;

  // 1. No aprobado aún -> rechazado en handshake WS
  const ws1 = new WebSocket(url);
  const msg1: any[] = [];
  await new Promise<void>((resolve) => {
    ws1.on("message", (raw) => {
      const m = JSON.parse(String(raw));
      msg1.push(m);
      if (m.type === "challenge") {
        ws1.send(JSON.stringify({
          type: "register",
          from: dev.pubB64,
          signature: dev.sign(m.nonce),
          nodeKey: "X25519_DEV",
          bindingSignature: dev.sign("bind:X25519_DEV"),
        }));
      } else if (m.type === "error") {
        resolve();
      }
    });
  });
  assert.ok(msg1.some((m) => m.type === "error" && String(m.payload).includes("unapproved")));
  ws1.close();

  // 2. Aprobar dispositivo -> WS registra y devuelve SignedNetMap
  auth.approveDevice(dev.pubB64, true);
  const ws2 = new WebSocket(url);
  const netmapMsg: any = await new Promise((resolve) => {
    ws2.on("message", (raw) => {
      const m = JSON.parse(String(raw));
      if (m.type === "challenge") {
        ws2.send(JSON.stringify({
          type: "register",
          from: dev.pubB64,
          signature: dev.sign(m.nonce),
          nodeKey: "X25519_DEV",
          bindingSignature: dev.sign("bind:X25519_DEV"),
        }));
      } else if (m.type === "netmap") {
        resolve(m);
      }
    });
  });
  assert.equal(verifySignedNetMap(netmapMsg.netmap), true);
  assert.equal(netmapMsg.netmap.payload.nodes.length, 1);

  ws2.close();
  wss.close();
  await new Promise<void>((r) => server.close(() => r()));
});

test("Federación HTTP/WS entre dos servidores DERP independientes (Región NA <-> Región EU)", async () => {
  const routerNa = new DerpMeshRouter();
  const hubNa = new SignalingHub(1, routerNa);
  const appNa = createApp(new NetMapAuthority(), hubNa, routerNa);
  const srvNa = createServer(appNa);
  const wssNa = attachSignalingToHttpServer(srvNa, false, () => true, hubNa, "/ws");

  const routerEu = new DerpMeshRouter();
  const hubEu = new SignalingHub(2, routerEu);
  const appEu = createApp(new NetMapAuthority(), hubEu, routerEu);
  const srvEu = createServer(appEu);
  const wssEu = attachSignalingToHttpServer(srvEu, false, () => true, hubEu, "/ws");

  await new Promise<void>((r) => srvNa.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => srvEu.listen(0, "127.0.0.1", r));
  const portNa = (srvNa.address() as { port: number }).port;
  const portEu = (srvEu.address() as { port: number }).port;

  routerNa.registerRemoteRegion(2, `http://127.0.0.1:${portEu}`);
  routerEu.registerRemoteRegion(1, `http://127.0.0.1:${portNa}`);

  const a = genEd();
  const b = genEd();
  // Anunciar que B reside en región 2 (EU)
  routerNa.setHomeRegion(b.pubB64, 2);

  const wsA = new WebSocket(`ws://127.0.0.1:${portNa}/ws`);
  const wsB = new WebSocket(`ws://127.0.0.1:${portEu}/ws`);
  await Promise.all([
    new Promise<void>((r) => wsA.on("open", () => r())),
    new Promise<void>((r) => wsB.on("open", () => r())),
  ]);
  wsA.send(JSON.stringify({ type: "register", from: a.pubB64 }));
  wsB.send(JSON.stringify({ type: "register", from: b.pubB64 }));

  const receivedB: Promise<any> = new Promise((resolve) => {
    wsB.on("message", (raw) => {
      const m = JSON.parse(String(raw));
      if (m.type === "relay") resolve(m);
    });
  });

  await new Promise((r) => setTimeout(r, 80));
  const inner = Buffer.from("SECRET_CROSS_REGION_PAYLOAD");
  const nm2 = Buffer.concat([Buffer.from("NM2"), b.pubRaw, inner]);
  wsA.send(nm2);

  const delivered = await receivedB;
  assert.equal(delivered.from, a.pubB64);
  assert.equal(delivered.viaRegion, 2);
  assert.equal(Buffer.from(delivered.data, "base64").toString("hex"), inner.toString("hex"));

  wsA.close();
  wsB.close();
  wssNa.close();
  wssEu.close();
  await Promise.all([
    new Promise<void>((r) => srvNa.close(() => r())),
    new Promise<void>((r) => srvEu.close(() => r())),
  ]);
});
