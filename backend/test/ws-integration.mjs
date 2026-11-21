import WebSocket from "ws";

const url = "ws://127.0.0.1:8443";
const log = [];

function openClient(name) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.on("open", () => resolve(ws));
    ws.on("error", reject);
    ws.on("message", (raw) => {
      try {
        const msg = JSON.parse(String(raw));
        log.push({ from: name, msg });
        console.log(name, "<<", JSON.stringify(msg));
      } catch {}
    });
  });
}

const a = await openClient("A");
const b = await openClient("B");

a.send(JSON.stringify({ type: "register", from: "pk-A" }));
b.send(JSON.stringify({ type: "register", from: "pk-B" }));
await new Promise((r) => setTimeout(r, 300));

// A envia offer a B
a.send(JSON.stringify({ type: "offer", from: "pk-A", to: "pk-B", payload: { sdp: "fake-sdp" } }));
await new Promise((r) => setTimeout(r, 300));

// heartbeat
a.send(JSON.stringify({ type: "heartbeat", from: "pk-A" }));
await new Promise((r) => setTimeout(r, 200));

const peerJoined = log.some((e) => e.from === "A" && e.msg.type === "peer-joined");
const offerForwarded = log.some((e) => e.from === "B" && e.msg.type === "offer" && e.msg.payload?.sdp === "fake-sdp");
console.log("RESULT", JSON.stringify({ peerJoined, offerForwarded, total: log.length }));
a.close();
b.close();
process.exit(peerJoined && offerForwarded ? 0 : 1);
