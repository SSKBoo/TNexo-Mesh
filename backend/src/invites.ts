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
  getStore().saveInvite(id, payload, invite.expiresAt);
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
