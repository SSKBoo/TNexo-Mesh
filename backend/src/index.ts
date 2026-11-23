import express from "express";
import { createServer } from "http";
import { attachSignalingToHttpServer, createSignalingServer, DerpMeshRouter, SignalingHub } from "./signaling.ts";
import { createTurnRouter } from "./turn.ts";
import { createPushRouter } from "./push.ts";
import { createInvitesRouter } from "./invites.ts";
import { NetMapAuthority } from "./netmap.ts";
import { getStore } from "./store.ts";

export function parseDerpRegionsEnv(): Array<{ id: number; name: string; host: string; port: number }> {
  if (process.env.DERP_REGIONS) {
    try {
      const parsed = JSON.parse(process.env.DERP_REGIONS);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    } catch {}
  }
  const host = process.env.PUBLIC_HOST ?? "127.0.0.1";
  const port = Number(process.env.PORT ?? 8080);
  return [
    { id: 1, name: "primary", host, port },
    { id: 2, name: "backup", host, port: Number(process.env.SIGNALING_PORT ?? 8443) },
  ];
}

export function createApp(authority: NetMapAuthority = new NetMapAuthority(getStore())) {
  const app = express();
  app.use(express.json());
  app.get("/health", (_req, res) => res.json({ ok: true, service: "nexomesh-backend" }));
  app.get("/derp/ping", (_req, res) => res.json({ pong: Date.now(), regionId: Number(process.env.DERP_REGION_ID ?? 1) }));
  app.get("/derp-map", (_req, res) => {
    res.json({ regions: parseDerpRegionsEnv() });
  });
  app.post("/netmap/register", (req, res) => {
    try {
      const { nodeKey, signingKey, userId, virtualIp, endpoints, subnets, bindingSignature, approved, ttlMs, homeDerp } =
        req.body ?? {};
      const node = authority.registerNode(
        {
          nodeKey,
          signingKey,
          userId: userId ?? "user",
          virtualIp: virtualIp ?? "10.0.0.2",
          endpoints: Array.isArray(endpoints) ? endpoints : [],
          subnets: Array.isArray(subnets) ? subnets : [],
          approved: Boolean(approved),
          ttlMs: typeof ttlMs === "number" ? ttlMs : undefined,
          homeDerp: typeof homeDerp === "number" ? homeDerp : 1,
        },
        String(bindingSignature ?? "")
      );
      res.status(201).json(node);
    } catch (e: any) {
      res.status(400).json({ error: e?.message ?? "registration failed" });
    }
  });
  app.post("/netmap/approve", (req, res) => {
    const { signingKey, approved } = req.body ?? {};
    const updated = authority.approveDevice(String(signingKey ?? ""), approved !== false);
    if (!updated) {
      res.status(404).json({ error: "device not found" });
      return;
    }
    res.json(updated);
  });
  app.get("/netmap", (_req, res) => {
    res.json(authority.issueSignedNetMap());
  });
  app.use("/", createTurnRouter());
  app.use("/push", createPushRouter());
  app.use("/", createInvitesRouter());
  return app;
}

export function start(port: number = 8080, signalingPort: number = 8443): void {
  const store = getStore();
  const authority = new NetMapAuthority(store);
  const app = createApp(authority);
  const server = createServer(app);
  const requireSig = process.env.SIGNALING_REQUIRE_SIGNATURE !== "0";
  const isAuthorized = (from: string) =>
    authority.isActiveAndApproved(from) || store.isAuthorizedSigningKey(from);

  const router = new DerpMeshRouter();
  const hubPrimary = new SignalingHub(1, router, authority);

  attachSignalingToHttpServer(server, requireSig, isAuthorized, hubPrimary, "/ws", authority);
  server.listen(port, () => console.log(`HTTP + WS(/ws) listening on ${port}`));

  if (signalingPort !== port) {
    try {
      const hubBackup = new SignalingHub(2, router, authority);
      createSignalingServer(signalingPort, requireSig, isAuthorized, hubBackup, authority);
      console.log(`DERP Region 2 listening on ${signalingPort}`);
    } catch (e) {
      console.error("signaling failed", e);
    }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  start(Number(process.env.PORT ?? 8080), Number(process.env.SIGNALING_PORT ?? 8443));
}
