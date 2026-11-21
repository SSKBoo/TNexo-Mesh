import express from "express";
import crypto from "node:crypto";

export interface TurnCredentials {
  username: string;
  password: string;
  ttl: number;
}

/** Coturn usa long-term credentials: password = HMAC-SHA1(secret, "timestamp:username"). */
export function generateCredentials(secret?: string): TurnCredentials {
  const ttl = 3600;
  const timestamp = Math.floor(Date.now() / 1000) + ttl;
  const username = `${timestamp}:${crypto.randomBytes(8).toString("hex")}`;
  const sharedSecret = secret ?? process.env.COTURN_AUTH_SECRET ?? "nexomesh-dev-secret";
  const password = crypto.createHmac("sha1", sharedSecret).update(username).digest("base64");
  return { username, password, ttl };
}

export function verifyTurnPassword(username: string, password: string, secret?: string): boolean {
  const sharedSecret = secret ?? process.env.COTURN_AUTH_SECRET ?? "nexomesh-dev-secret";
  const expected = crypto.createHmac("sha1", sharedSecret).update(username).digest("base64");
  const a = Buffer.from(expected);
  const b = Buffer.from(password);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function createTurnRouter(): express.Router {
  const router = express.Router();
  router.get("/credentials", (_req, res) => {
    res.json(generateCredentials());
  });
  return router;
}
