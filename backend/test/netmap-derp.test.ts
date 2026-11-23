import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { NetMapAuthority, verifyIdentityBinding, verifySignedNetMap } from "../src/netmap.ts";
import { SignalingHub } from "../src/signaling.ts";

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
