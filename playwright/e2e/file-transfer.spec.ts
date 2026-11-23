import { test, expect } from "@playwright/test";
import crypto from "node:crypto";
import { createServer } from "node:http";
import { createApp } from "../../backend/src/index.ts";
import { NetMapAuthority } from "../../backend/src/netmap.ts";
import { attachSignalingToHttpServer, DerpMeshRouter, SignalingHub } from "../../backend/src/signaling.ts";

function genEd() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubRaw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return {
    pubB64: pubRaw.toString("base64"),
    pubRawArray: Array.from(pubRaw),
    sign: (msg: string) => crypto.sign(null, Buffer.from(msg), privateKey).toString("base64"),
  };
}

test("E2E File Transfer vía malla DERP federada NM2 (NA <-> EU) sin fugas a terceros", async ({ page }) => {
  const routerNa = new DerpMeshRouter();
  const hubNa = new SignalingHub(1, routerNa);
  const srvNa = createServer(createApp(new NetMapAuthority(), hubNa, routerNa));
  const wssNa = attachSignalingToHttpServer(srvNa, false, () => true, hubNa, "/ws");

  const routerEu = new DerpMeshRouter();
  const hubEu = new SignalingHub(2, routerEu);
  const srvEu = createServer(createApp(new NetMapAuthority(), hubEu, routerEu));
  const wssEu = attachSignalingToHttpServer(srvEu, false, () => true, hubEu, "/ws");

  await new Promise<void>((r) => srvNa.listen(0, "127.0.0.1", r));
  await new Promise<void>((r) => srvEu.listen(0, "127.0.0.1", r));
  const portNa = (srvNa.address() as { port: number }).port;
  const portEu = (srvEu.address() as { port: number }).port;

  routerNa.registerRemoteRegion(2, `http://127.0.0.1:${portEu}`);
  routerEu.registerRemoteRegion(1, `http://127.0.0.1:${portNa}`);

  try {
    const peerA = genEd();
    const peerB = genEd();
    const bystanderC = genEd();

    await page.setContent("<html><body><h1>NexoMesh Federated File Transfer</h1></body></html>");
    const result = await page.evaluate(
      async ({ wsNaUrl, wsEuUrl, peerA, peerB, bystanderC }) => {
        const connectPeer = (url: string, from: string) =>
          new Promise<WebSocket>((resolve) => {
            const ws = new WebSocket(url);
            ws.onopen = () => {
              ws.send(JSON.stringify({ type: "register", from }));
              resolve(ws);
            };
          });

        const wsA = await connectPeer(wsNaUrl, peerA.pubB64);
        const wsB = await connectPeer(wsEuUrl, peerB.pubB64);
        const wsC = await connectPeer(wsNaUrl, bystanderC.pubB64);

        const cReceived: any[] = [];
        wsC.onmessage = (ev) => cReceived.push(ev.data);

        const bPromise = new Promise<any>((resolve) => {
          wsB.onmessage = (ev) => {
            const m = JSON.parse(String(ev.data));
            if (m.type === "relay") resolve(m);
          };
        });

        await new Promise((r) => setTimeout(r, 120));

        // Enviar archivo cifrado encapsulado en frame binario NM2 desde Chromium Peer A (NA) a Peer B (EU)
        const filePayload = new TextEncoder().encode("NM_F|reporte.bin\nCONTENIDO_SECRETO_12345");
        const nm2 = new Uint8Array(3 + 32 + filePayload.length);
        nm2[0] = 0x4e; // 'N'
        nm2[1] = 0x4d; // 'M'
        nm2[2] = 0x32; // '2'
        nm2.set(peerB.pubRawArray, 3);
        nm2.set(filePayload, 35);
        wsA.send(nm2);

        const delivered = await bPromise;
        await new Promise((r) => setTimeout(r, 80));
        const decodedText = new TextDecoder().decode(
          Uint8Array.from(atob(delivered.data), (c) => c.charCodeAt(0))
        );
        const cRelays = cReceived.filter((raw) => {
          try {
            return JSON.parse(String(raw)).type === "relay";
          } catch {
            return false;
          }
        });

        wsA.close();
        wsB.close();
        wsC.close();
        return { viaRegion: delivered.viaRegion, decodedText, cRelaysCount: cRelays.length };
      },
      {
        wsNaUrl: `ws://127.0.0.1:${portNa}/ws`,
        wsEuUrl: `ws://127.0.0.1:${portEu}/ws`,
        peerA: { pubB64: peerA.pubB64, pubRawArray: peerA.pubRawArray },
        peerB: { pubB64: peerB.pubB64, pubRawArray: peerB.pubRawArray },
        bystanderC: { pubB64: bystanderC.pubB64, pubRawArray: bystanderC.pubRawArray },
      }
    );

    expect(result.viaRegion).toBe(2);
    expect(result.decodedText).toBe("NM_F|reporte.bin\nCONTENIDO_SECRETO_12345");
    expect(result.cRelaysCount).toBe(0);
  } finally {
    wssNa.close();
    wssEu.close();
    await Promise.all([
      new Promise<void>((r) => srvNa.close(() => r())),
      new Promise<void>((r) => srvEu.close(() => r())),
    ]);
  }
});
