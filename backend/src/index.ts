import express from "express";
import { createServer } from "http";
import { createSignalingServer } from "./signaling.ts";
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
  server.listen(port, () => console.log(`HTTP listening on ${port}`));
  try {
    createSignalingServer(
      signalingPort,
      process.env.SIGNALING_REQUIRE_SIGNATURE !== "0",
      (from) => getStore().isAuthorizedSigningKey(from)
    );
    console.log(`Signaling listening on ${signalingPort}`);
  } catch (e) {
    console.error("signaling failed", e);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  start(Number(process.env.PORT ?? 8080), Number(process.env.SIGNALING_PORT ?? 8443));
}
