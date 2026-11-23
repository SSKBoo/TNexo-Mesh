import express from "express";
import { createServer } from "http";
import { attachSignalingToHttpServer, createSignalingServer, DerpMeshRouter, SignalingHub } from "./signaling.ts";
import { createTurnRouter } from "./turn.ts";
import { createPushRouter } from "./push.ts";
import { createInvitesRouter } from "./invites.ts";
import { NetMapAuthority, verifyOidcClaim } from "./netmap.ts";
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

export function createApp(
  authority: NetMapAuthority = new NetMapAuthority(getStore()),
  hub?: SignalingHub,
  router?: DerpMeshRouter
) {
  const app = express();
  app.use(express.json());
  app.get("/health", (_req, res) => res.json({ ok: true, service: "nexomesh-backend" }));
  app.get("/derp/ping", (_req, res) =>
    res.json({ pong: Date.now(), regionId: hub?.regionId ?? Number(process.env.DERP_REGION_ID ?? 1) })
  );
  app.get("/derp-map", (_req, res) => {
    res.json({ regions: parseDerpRegionsEnv() });
  });
  app.get("/derp/mesh/homes", (_req, res) => {
    res.json({ homes: router ? router.snapshotHomes() : {} });
  });
  app.post("/derp/mesh/announce", (req, res) => {
    const { peerKey, regionId } = req.body ?? {};
    if (!router || typeof peerKey !== "string" || typeof regionId !== "number") {
      res.status(400).json({ error: "invalid announce payload" });
      return;
    }
    router.setHomeRegion(peerKey, regionId);
    res.json({ ok: true });
  });
  app.post("/derp/mesh/deliver", (req, res) => {
    const { from, targetKey, payloadB64 } = req.body ?? {};
    if (!hub || typeof from !== "string" || typeof targetKey !== "string" || typeof payloadB64 !== "string") {
      res.status(400).json({ error: "invalid federation frame" });
      return;
    }
    const delivered = hub.deliverFromRemoteRegion(from, targetKey, payloadB64);
    res.status(delivered ? 200 : 404).json({ ok: delivered });
  });
  app.post("/netmap/register", (req, res) => {
    try {
      const {
        nodeKey, signingKey, userId, virtualIp, endpoints, subnets,
        bindingSignature, approved, ttlMs, homeDerp, oidcToken,
      } = req.body ?? {};
      const resolvedUser = String(userId ?? "user");
      if (typeof oidcToken === "string" && oidcToken.length > 0 && !verifyOidcClaim(oidcToken, resolvedUser)) {
        res.status(401).json({ error: "invalid oidcToken for userId" });
        return;
      }
      const node = authority.registerNode(
        {
          nodeKey,
          signingKey,
          userId: resolvedUser,
          virtualIp: virtualIp ?? "10.0.0.2",
          endpoints: Array.isArray(endpoints) ? endpoints : [],
          subnets: Array.isArray(subnets) ? subnets : [],
          approved: Boolean(approved),
          ttlMs: typeof ttlMs === "number" ? ttlMs : undefined,
          homeDerp: typeof homeDerp === "number" ? homeDerp : 1,
        },
        String(bindingSignature ?? "")
      );
      if (node.approved) hub?.broadcastNetMap();
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
    if (approved === false) {
      hub?.revokePeer(String(signingKey ?? ""));
    } else {
      hub?.broadcastNetMap();
    }
    res.json(updated);
  });
  app.post("/netmap/revoke", (req, res) => {
    const signingKey = String(req.body?.signingKey ?? "");
    const revoked = authority.revokeNode(signingKey);
    if (!revoked) {
      res.status(404).json({ error: "device not found" });
      return;
    }
    hub?.revokePeer(signingKey);
    res.json({ ok: true, revoked });
  });
  app.post("/netmap/acls", (req, res) => {
    const rules = Array.isArray(req.body?.acls) ? req.body.acls : [];
    authority.setAcls(rules);
    hub?.broadcastNetMap();
    res.json({ ok: true, acls: rules });
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
  const router = new DerpMeshRouter();
  const hubPrimary = new SignalingHub(1, router, authority);
  const app = createApp(authority, hubPrimary, router);
  const server = createServer(app);
  const requireSig = process.env.SIGNALING_REQUIRE_SIGNATURE !== "0";
  const isAuthorized = (from: string) =>
    authority.isActiveAndApproved(from) || store.isAuthorizedSigningKey(from);

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
