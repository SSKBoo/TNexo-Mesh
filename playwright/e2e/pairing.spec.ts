import { test, expect } from "@playwright/test";
import crypto from "node:crypto";
import { createServer } from "node:http";
import { createApp } from "../../backend/src/index.ts";
import { NetMapAuthority, verifySignedNetMap } from "../../backend/src/netmap.ts";
import { attachSignalingToHttpServer, DerpMeshRouter, SignalingHub } from "../../backend/src/signaling.ts";
import { Store } from "../../backend/src/store.ts";

function genEd() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubB64 = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
  return {
    pubB64,
    sign: (msg: string) => crypto.sign(null, Buffer.from(msg), privateKey).toString("base64"),
  };
}

function makeFakeJwt(sub: string, expSec: number): string {
  const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const p = Buffer.from(JSON.stringify({ sub, exp: expSec })).toString("base64url");
  return `${h}.${p}.sig`;
}

test("E2E Pairing: invitación, OIDC->NodeKey->IPv6, NetMap firmado en Chromium WS y revocación instantánea", async ({ page }) => {
  const store = new Store(":memory:");
  const auth = new NetMapAuthority(store);
  const router = new DerpMeshRouter();
  const hub = new SignalingHub(1, router, auth);
  const app = createApp(auth, hub, router);
  const server = createServer(app);
  const wss = attachSignalingToHttpServer(
    server,
    true,
    (from) => auth.isActiveAndApproved(from),
    hub,
    "/ws",
    auth
  );
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const dev = genEd();
    const oidcJwt = makeFakeJwt("uriel@nexomesh.io", Math.floor(Date.now() / 1000) + 3600);

    // 1. Invitación + registro vinculado con OIDC y firma Ed25519->X25519
    const invRes = await page.request.post(`${baseUrl}/invite`, {
      data: { pk: "X25519_NODE_PAIRING", signingPub: dev.pubB64 },
    });
    expect(invRes.status()).toBe(201);
    const inv = await invRes.json();
    const getInv = await page.request.get(`${baseUrl}/invite/${inv.id}`);
    expect(getInv.status()).toBe(200);

    const regRes = await page.request.post(`${baseUrl}/netmap/register`, {
      data: {
        nodeKey: "X25519_NODE_PAIRING",
        signingKey: dev.pubB64,
        userId: "uriel@nexomesh.io",
        oidcToken: oidcJwt,
        virtualIp: "10.0.0.10",
        bindingSignature: dev.sign("bind:X25519_NODE_PAIRING"),
        approved: false,
      },
    });
    expect(regRes.status()).toBe(201);
    const regNode = await regRes.json();
    expect(regNode.virtualIpv6).toMatch(/^fd7a:115c:a1e0:/);

    // Aprobar dispositivo
    const approveRes = await page.request.post(`${baseUrl}/netmap/approve`, {
      data: { signingKey: dev.pubB64, approved: true },
    });
    expect(approveRes.status()).toBe(200);

    // 2. Navegador Chromium abre WebSocket contra /ws, firma challenge y recibe SignedNetMap
    await page.setContent("<html><body><h1>NexoMesh Pairing E2E</h1></body></html>");
    const challengeRes = await page.evaluate(async (wsUrl) => {
      return await new Promise<string>((resolve, reject) => {
        const ws = new WebSocket(wsUrl);
        (window as any).__meshWs = ws;
        ws.onmessage = (ev) => {
          const msg = JSON.parse(String(ev.data));
          if (msg.type === "challenge") resolve(msg.nonce);
        };
        ws.onerror = () => reject(new Error("ws failed"));
      });
    }, `ws://127.0.0.1:${port}/ws`);

    const sig = dev.sign(challengeRes);
    const bindSig = dev.sign("bind:X25519_NODE_PAIRING");
    const netmapMsg = await page.evaluate(
      async ({ from, signature, bindingSignature }) => {
        const ws: WebSocket = (window as any).__meshWs;
        return await new Promise<any>((resolve) => {
          ws.onmessage = (ev) => {
            const m = JSON.parse(String(ev.data));
            if (m.type === "netmap") resolve(m);
          };
          ws.send(
            JSON.stringify({
              type: "register",
              from,
              signature,
              nodeKey: "X25519_NODE_PAIRING",
              bindingSignature,
            })
          );
        });
      },
      { from: dev.pubB64, signature: sig, bindingSignature: bindSig }
    );

    expect(verifySignedNetMap(netmapMsg.netmap)).toBe(true);
    expect(netmapMsg.netmap.payload.nodes.length).toBe(1);
    expect(netmapMsg.netmap.payload.nodes[0].virtualIpv6).toMatch(/^fd7a:115c:a1e0:/);

    // 3. Revocación instantánea corta la sesión WebSocket activa en el navegador
    const closedPromise = page.evaluate(
      () =>
        new Promise<boolean>((resolve) => {
          const ws: WebSocket = (window as any).__meshWs;
          if (ws.readyState >= WebSocket.CLOSING) return resolve(true);
          ws.onclose = () => resolve(true);
        })
    );
    const revRes = await page.request.post(`${baseUrl}/netmap/revoke`, {
      data: { signingKey: dev.pubB64 },
    });
    expect(revRes.status()).toBe(200);
    expect(await closedPromise).toBe(true);
  } finally {
    wss.close();
    await new Promise<void>((r) => server.close(() => r()));
    store.close();
  }
});
