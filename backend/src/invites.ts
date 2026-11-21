import express from "express";
import crypto from "node:crypto";
import { getStore } from "./store.ts";

export interface Invite {
  id: string;
  payload: unknown;
  expiresAt: number;
}

const TTL_MS = 10 * 60 * 1000;

export function createInvite(payload: unknown): Invite {
  const id = crypto.randomBytes(8).toString("hex");
  const invite: Invite = { id, payload, expiresAt: Date.now() + TTL_MS };
  const store = getStore();
  store.saveInvite(id, payload, invite.expiresAt);
  // Si la invitación trae ambas llaves, las enlazamos para que el signaling
  // exija que `from` (firma Ed25519) corresponda a una identidad de malla invitada.
  const p = payload as { pk?: string; signingPub?: string };
  if (p?.pk && p?.signingPub) {
    store.linkSigningKey(p.pk, p.signingPub);
  }
  return invite;
}

export function getInvite(id: string): Invite | null {
  return getStore().getInvite(id);
}

export function createInvitesRouter(): express.Router {
  const router = express.Router();
  router.post("/invite", (req, res) => {
    const inv = createInvite(req.body ?? {});
    res.status(201).json(inv);
  });
  router.get("/invite/:id", (req, res) => {
    const inv = getInvite(req.params.id);
    if (!inv) {
      res.status(404).json({ error: "not found or expired" });
      return;
    }
    res.json(inv);
  });
  return router;
}
