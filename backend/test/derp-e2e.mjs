import WebSocket from "ws";
import crypto from "node:crypto";

function makeId() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  return { pub, sign: (n) => crypto.sign(null, Buffer.from(n), privateKey).toString("base64") };
}
const A = makeId(), B = makeId();
for (const [i, id] of [A, B].entries()) {
  await fetch("http://127.0.0.1:8080/invite", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pk: `mesh-${i}`, signingPub: id.pub }),
  });
}

function open(id, label, bag) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket("ws://127.0.0.1:8443");
    ws.on("open", () => resolve(ws));
    ws.on("error", reject);
    ws.on("message", (raw, isBinary) => {
      const msg = JSON.parse(String(raw));
      if (msg.type === "challenge") ws.send(JSON.stringify({ type: "register", from: id.pub, signature: id.sign(msg.nonce) }));
      if (msg.type === "relay") bag.push({ label, msg, isBinary });
    });
  });
}
const received = [];
const a = await open(A, "A", received);
const b = await open(B, "B", received);
await new Promise(r => setTimeout(r, 500));

// A envía un frame NM1 BINARIO real (cifrado simulado) por el relay del backend
const vip = Buffer.from("10.0.0.2");
const frame = Buffer.concat([Buffer.from([0x4e,0x4d,0x31, vip.length]), vip, Buffer.from("CIPHER")]);
a.send(frame);
await new Promise(r => setTimeout(r, 400));

const relays = received.filter(e => e.msg.type === "relay");
const ok = relays.length === 1 && relays[0].label === "B" &&
  Buffer.from(relays[0].msg.data, "base64").toString("hex") === frame.toString("hex") &&
  !JSON.stringify(relays).includes("CIPHER");
console.log("RESULT", JSON.stringify({ relays: relays.length, deliveredTo: relays[0]?.label, noPlaintext: ok }));
a.close(); b.close();
process.exit(ok ? 0 : 1);
