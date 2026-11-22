import express from "express";
import { createServer } from "http";
import { attachSignalingToHttpServer, createSignalingServer, SignalingHub } from "./signaling.ts";
import { createTurnRouter } from "./turn.ts";
import { createPushRouter } from "./push.ts";
import { createInvitesRouter } from "./invites.ts";
import { getStore } from "./store.ts";

export function createApp() {
  const app = express();
  app.use(express.json());
  app.get("/health", (_req, res) => res.json({ ok: true, service: "nexomesh-backend" }));
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
