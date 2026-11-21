import webpush from "web-push";
import crypto from "node:crypto";

const { publicKey, privateKey } = webpush.generateVAPIDKeys();
webpush.setVapidDetails("mailto:admin@nexomesh.io", publicKey, privateKey);

// p256dh = punto P-256 sin comprimir: 0x04 || X(32) || Y(32) = 65 bytes
const { publicKey: ecPub } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const jwk = ecPub.export({ format: "jwk" });
const raw = Buffer.concat([
  Buffer.from([0x04]),
  Buffer.from(jwk.x, "base64url"),
  Buffer.from(jwk.y, "base64url"),
]);
const sub = {
  endpoint: "https://example.invalid/push/noop",
  keys: { p256dh: raw.toString("base64url"), auth: crypto.randomBytes(16).toString("base64url") },
};

try {
  await webpush.sendNotification(sub, JSON.stringify({ title: "NexoMesh", body: "test" }), { TTL: 60 });
  console.log("PUSH: sent (unexpected for invalid endpoint)");
} catch (e) {
  console.log("PUSH: VAPID-signed request attempted, status=", e?.statusCode ?? "dns/network", "reason=", String(e?.message).slice(0, 100));
}
console.log("VAPID keys generated:", publicKey.length, privateKey.length, "chars");
