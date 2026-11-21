import express from "express";
import crypto from "node:crypto";

export interface Invite {
  id: string;
  payload: unknown;
  expiresAt: number;
}

const invites = new Map<string, Invite>();
const TTL_MS = 10 * 60 * 1000;

export function createInvite(payload: unknown): Invite {
  const id = crypto.randomBytes(8).toString("hex");
  const invite: Invite = { id, payload, expiresAt: Date.now() + TTL_MS };
  invites.set(id, invite);
  return invite;
}

export function getInvite(id: string): Invite | null {
  const inv = invites.get(id);
  if (!inv) return null;
  if (Date.now() > inv.expiresAt) {
    invites.delete(id);
    return null;
  }
  return inv;
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

export function _resetInvites(): void {
  invites.clear();
}
