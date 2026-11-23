import express from "express";
import { createServer } from "http";
import { attachSignalingToHttpServer, createSignalingServer, SignalingHub } from "./signaling.ts";
import { createTurnRouter } from "./turn.ts";
import { createPushRouter } from "./push.ts";
import { createInvitesRouter } from "./invites.ts";
import { NetMapAuthority } from "./netmap.ts";
import { getStore } from "./store.ts";

export function createApp(authority: NetMapAuthority = new NetMapAuthority()) {
  const app = express();
  app.use(express.json());
  app.get("/health", (_req, res) => res.json({ ok: true, service: "nexomesh-backend" }));
  app.get("/derp-map", (_req, res) => {
    res.json({
      regions: [
        { id: 1, name: "primary", host: process.env.PUBLIC_HOST ?? "127.0.0.1", port: Number(process.env.PORT ?? 8080) },
      ],
    });
  });
  app.post("/netmap/register", (req, res) => {
    try {
      const { nodeKey, signingKey, userId, virtualIp, endpoints, subnets, bindingSignature, approved } = req.body ?? {};
      const node = authority.registerNode(
        {
          nodeKey,
          signingKey,
          userId: userId ?? "user",
          virtualIp: virtualIp ?? "10.0.0.2",
          endpoints: Array.isArray(endpoints) ? endpoints : [],
          subnets: Array.isArray(subnets) ? subnets : [],
          approved: Boolean(approved),
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
  // signaling router mounted separately via WebSocket
  return app;
}

export function start(port: number = 8080, signalingPort: number = 8443): void {
  const app = createApp();
  const server = createServer(app);
  const requireSig = process.env.SIGNALING_REQUIRE_SIGNATURE !== "0";
  const isAuthorized = (from: string) => getStore().isAuthorizedSigningKey(from);
  const hub = new SignalingHub();

  attachSignalingToHttpServer(server, requireSig, isAuthorized, hub, "/ws");
  server.listen(port, () => console.log(`HTTP + WS(/ws) listening on ${port}`));

  if (signalingPort !== port) {
    try {
      createSignalingServer(signalingPort, requireSig, isAuthorized, hub);
      console.log(`Signaling listening on ${signalingPort}`);
    } catch (e) {
      console.error("signaling failed", e);
    }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  start(Number(process.env.PORT ?? 8080), Number(process.env.SIGNALING_PORT ?? 8443));
}
