import { test, expect } from "@playwright/test";
import crypto from "node:crypto";
import { createServer } from "node:http";
import { createServer as createViteServer } from "vite";
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

test("E2E Guardian y ACLs: renderiza PWA real, aplica ACLs en NetMap firmado y bloquea broadcast NM1", async ({ page }) => {
  const store = new Store(":memory:");
  const auth = new NetMapAuthority(store);
  const router = new DerpMeshRouter();
  const hub = new SignalingHub(1, router, auth);
  const app = createApp(auth, hub, router);
  const backendSrv = createServer(app);
  const wss = attachSignalingToHttpServer(
    backendSrv,
    true,
    (from) => auth.isActiveAndApproved(from),
    hub,
    "/ws",
    auth
  );
  await new Promise<void>((r) => backendSrv.listen(0, "127.0.0.1", r));
  const backendPort = (backendSrv.address() as { port: number }).port;

  const vite = await createViteServer({
    server: { port: 0, host: "127.0.0.1" },
    logLevel: "silent",
  });
  await vite.listen();
  const viteAddr = vite.httpServer?.address() as { port: number };

  try {
    // 1. Verificar UI real del PWA
    await page.goto(`http://127.0.0.1:${viteAddr.port}/`);
    await expect(page.getByRole("heading", { name: "NexoMesh" })).toBeVisible();
    await expect(page.getByText("Panel de control")).toBeVisible();

    // 2. Registrar dispositivo dev (group:dev) + servidor (tag:server) con ACL SSH sin llaves
    const dev = genEd();
    const srv = genEd();
    await page.request.post(`http://127.0.0.1:${backendPort}/netmap/register`, {
      data: {
        nodeKey: "X25519_GUARDIAN",
        signingKey: dev.pubB64,
        userId: "sec@nexomesh.io",
        provider: "google",
        groups: ["group:dev"],
        virtualIp: "auto",
        bindingSignature: dev.sign("bind:X25519_GUARDIAN"),
        approved: true,
      },
    });
    await page.request.post(`http://127.0.0.1:${backendPort}/netmap/register`, {
      data: {
        nodeKey: "X25519_SERVER",
        signingKey: srv.pubB64,
        userId: "infra@nexomesh.io",
        provider: "github",
        tags: ["tag:server"],
        virtualIp: "auto",
        bindingSignature: srv.sign("bind:X25519_SERVER"),
        approved: true,
      },
    });
    const aclRes = await page.request.post(`http://127.0.0.1:${backendPort}/netmap/acls`, {
      data: {
        acls: [{ src: "group:dev", dst: "tag:server", proto: "tcp", port: 22, ssh: true }],
      },
    });
    expect(aclRes.status()).toBe(200);

    const sshOk = await page.request.post(`http://127.0.0.1:${backendPort}/netmap/ssh/authorize`, {
      data: { srcSigningKey: dev.pubB64, dstSigningKey: srv.pubB64 },
    });
    expect(sshOk.status()).toBe(200);
    expect((await sshOk.json()).allowed).toBe(true);

    const nmRes = await page.request.get(`http://127.0.0.1:${backendPort}/netmap`);
    const netmap = await nmRes.json();
    expect(verifySignedNetMap(netmap)).toBe(true);
    expect(netmap.payload.acls.length).toBe(1);
    expect(netmap.payload.acls[0].port).toBe(22);

    // 3. Probar que el WS en Chromium rechaza fallback NM1 y relay JSON sin destinatario `to`
    const nonce = await page.evaluate(async (wsUrl) => {
      return await new Promise<string>((resolve) => {
        const ws = new WebSocket(wsUrl);
        (window as any).__secWs = ws;
        ws.onmessage = (ev) => {
          const m = JSON.parse(String(ev.data));
          if (m.type === "challenge") resolve(m.nonce);
        };
      });
    }, `ws://127.0.0.1:${backendPort}/ws`);

    const errMsg = await page.evaluate(
      async ({ from, signature, bindingSignature }) => {
        const ws: WebSocket = (window as any).__secWs;
        return await new Promise<string>((resolve) => {
          let registered = false;
          ws.onmessage = (ev) => {
            const m = JSON.parse(String(ev.data));
            if (m.type === "netmap" && !registered) {
              registered = true;
              // Intentar envío broadcast inseguro sin `to`
              ws.send(JSON.stringify({ type: "relay", data: "BROADCAST_TEST" }));
            } else if (m.type === "error") {
              resolve(m.payload);
            }
          };
          ws.send(
            JSON.stringify({
              type: "register",
              from,
              signature,
              nodeKey: "X25519_GUARDIAN",
              bindingSignature,
            })
          );
        });
      },
      {
        from: dev.pubB64,
        signature: dev.sign(nonce),
        bindingSignature: dev.sign("bind:X25519_GUARDIAN"),
      }
    );
    expect(errMsg).toContain("relay requires target");
  } finally {
    await page.close();
    (vite.httpServer as any)?.closeAllConnections?.();
    await Promise.race([vite.close(), new Promise((r) => setTimeout(r, 500))]);
    wss.close();
    backendSrv.closeAllConnections?.();
    await new Promise<void>((r) => backendSrv.close(() => r()));
    store.close();
  }
});
