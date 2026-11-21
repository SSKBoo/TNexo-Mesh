import WebSocket from "ws";
import crypto from "node:crypto";

function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubRaw = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  return { pubRaw, sign: (n) => crypto.sign(null, Buffer.from(n), privateKey).toString("base64") };
}

const idA = makeIdentity();
const idB = makeIdentity();
const received = [];

function open(id, label) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket("ws://127.0.0.1:8443");
    ws.on("open", () => resolve(ws));
    ws.on("error", reject);
    ws.on("message", (raw) => {
      const msg = JSON.parse(String(raw));
      received.push({ label, msg });
      if (msg.type === "challenge") {
        ws.send(JSON.stringify({ type: "register", from: id.pubRaw, signature: id.sign(msg.nonce) }));
      }
    });
  });
}

const a = await open(idA, "A");
const b = await open(idB, "B");
await new Promise((r) => setTimeout(r, 700));

// A envía offer a B; B debe recibirlo reenviado
a.send(JSON.stringify({ type: "offer", from: idA.pubRaw, to: idB.pubRaw, payload: { sdp: "x" } }));
await new Promise((r) => setTimeout(r, 300));

const peerJoined = received.some((e) => e.msg.type === "peer-joined");
const offerForwarded = received.some((e) => e.label === "B" && e.msg.type === "offer");
const errors = received.filter((e) => e.msg.type === "error");
console.log("RESULT", JSON.stringify({ peerJoined, offerForwarded, errors: errors.length, messages: received.length }));
a.close(); b.close();
process.exit(peerJoined && offerForwarded && errors.length === 0 ? 0 : 1);
