import express from "express";
import webpush from "web-push";

export interface PushSubscriptionBody {
  endpoint: string;
  keys?: { p256dh?: string; auth?: string };
}

const subscriptions = new Map<string, PushSubscriptionBody>();

export function configureVapid(): void {
  const pub = process.env.VAPID_PUBLIC_KEY;
  const priv = process.env.VAPID_PRIVATE_KEY;
  const subject = process.env.VAPID_SUBJECT ?? "mailto:admin@example.com";
  if (pub && priv) {
    webpush.setVapidDetails(subject, pub, priv);
  }
}

export function createPushRouter(): express.Router {
  configureVapid();
  const router = express.Router();
  router.post("/subscribe", (req, res) => {
    const body = req.body as PushSubscriptionBody;
    if (!body?.endpoint) {
      res.status(400).json({ error: "endpoint required" });
      return;
    }
    subscriptions.set(body.endpoint, body);
    res.json({ ok: true });
  });
  router.post("/send", async (req, res) => {
    const { endpoint, payload } = req.body ?? {};
    const sub = subscriptions.get(endpoint);
    if (!sub) {
      res.status(404).json({ error: "subscription not found" });
      return;
    }
    try {
      await webpush.sendNotification(sub as any, JSON.stringify(payload ?? {}));
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });
  return router;
}

export function _resetSubscriptions(): void {
  subscriptions.clear();
}
