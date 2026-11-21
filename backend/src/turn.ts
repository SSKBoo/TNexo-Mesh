import express from "express";
import crypto from "node:crypto";

export interface TurnCredentials {
  username: string;
  password: string;
  ttl: number;
}

export function generateCredentials(): TurnCredentials {
  const username = crypto.randomBytes(8).toString("hex");
  const password = crypto.randomBytes(16).toString("hex");
  return { username, password, ttl: 3600 };
}

export function createTurnRouter(): express.Router {
  const router = express.Router();
  router.get("/credentials", (_req, res) => {
    res.json(generateCredentials());
  });
  return router;
}
