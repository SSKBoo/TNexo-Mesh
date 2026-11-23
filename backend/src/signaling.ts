import { WebSocket, WebSocketServer } from "ws";
import type { Server as HttpServer } from "node:http";
import crypto from "node:crypto";

export interface SignalingSocket {
  send(data: string): void;
  close(): void;
  on(event: string, cb: (...args: any[]) => void): void;
  readyState?: number;
}

export interface PeerRecord {
  publicKey: string;
  socket: SignalingSocket;
  lastHeartbeat: number;
}

/** Verifica una firma Ed25519 del nonce con la clave pública (base64/hex). */
export function verifySignature(publicKey: string, nonce: string, signature: string): boolean {
  try {
    const isHex = /^[0-9a-f]+$/i.test(publicKey) && publicKey.length === 64;
    const keyBytes = isHex ? Buffer.from(publicKey, "hex") : Buffer.from(publicKey, "base64");
    const sig = Buffer.from(signature, "base64");
    const key = crypto.createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), keyBytes]),
      format: "der",
      type: "spki",
    });
    return crypto.verify(null, Buffer.from(nonce), key, sig);
  } catch {
    return false;
  }
}

export class SignalingHub {
  private peers = new Map<string, PeerRecord>();
  private expiryMs = 5 * 60 * 1000;

  register(publicKey: string, socket: SignalingSocket): void {
    for (const [pk, rec] of this.peers) {
      if (pk !== publicKey) {
        safeSend(rec.socket, JSON.stringify({ type: "peer-joined", payload: { publicKey } }));
      }
    }
    this.peers.set(publicKey, { publicKey, socket, lastHeartbeat: Date.now() });
    socket.on("close", () => this.remove(publicKey));
    socket.on("message", (raw: any) => this.handleMessage(publicKey, raw));
  }

  private handleMessage(from: string, raw: any): void {
    // Frame NM2 binario dirigido (DERP real): 'N','M','2' | dstKey(32 bytes) | payload.
    // Se enruta ÚNICAMENTE al par destino (sin broadcast ni amplificación).
    if (Buffer.isBuffer(raw) && raw.length >= 36 && raw[0] === 0x4e && raw[1] === 0x4d && raw[2] === 0x32) {
      const dstBytes = raw.subarray(3, 35);
      const dstB64 = dstBytes.toString("base64");
      const dstHex = dstBytes.toString("hex");
      const targetRec = this.peers.get(dstB64) ?? this.peers.get(dstHex);
      if (targetRec) {
        const inner = raw.subarray(35);
        safeSend(targetRec.socket, JSON.stringify({ type: "relay", from, data: inner.toString("base64") }));
      } else {
        safeSend(this.peers.get(from)?.socket, JSON.stringify({ type: "error", payload: "target peer offline" }));
      }
      return;
    }
    // Frame NM1 binario: primer byte 'N','M','1' y luego len(senderVip)|vip|ciphertext.
    // Lo reenviamos a TODOS los pares salvo el emisor (DERP-like), sin descifrar.
    if (Buffer.isBuffer(raw) && raw.length >= 6 && raw[0] === 0x4e && raw[1] === 0x4d && raw[2] === 0x31) {
      const frame = { type: "relay", from, data: raw.toString("base64") };
      for (const [pk, rec] of this.peers) {
        if (pk !== from) safeSend(rec.socket, JSON.stringify(frame));
      }
      return;
    }
    let msg: any;
    try {
      msg = JSON.parse(String(raw));
    } catch {
      safeSend(this.peers.get(from)?.socket as any, JSON.stringify({ type: "error", payload: "invalid json" }));
      return;
    }
    const rec = this.peers.get(from);
    if (!rec) return;
    switch (msg.type) {
      case "heartbeat":
        rec.lastHeartbeat = Date.now();
        break;
      case "list-peers": {
        const peers = Array.from(this.peers.keys()).filter((pk) => pk !== from);
        safeSend(rec.socket, JSON.stringify({ type: "peers", peers }));
        break;
      }
      case "relay": {
        const target = msg.to;
        const out = JSON.stringify({ ...msg, from });
        if (target) {
          const targetRec = this.peers.get(target);
          if (targetRec) {
            // El payload es opaco (frame NM1 cifrado en base64). El backend nunca
            // descifra: solo reenvía entre pares registrados (equivalente a DERP).
            safeSend(targetRec.socket, out);
          } else {
            safeSend(rec.socket, JSON.stringify({ type: "error", payload: "peer not found" }));
          }
        } else {
          // Sin `to` explícito (p.ej. RelayClient): reenviar a los demás pares.
          for (const [pk, peerRec] of this.peers) {
            if (pk !== from) safeSend(peerRec.socket, out);
          }
        }
        break;
      }
      case "offer":
      case "answer":
      case "ice": {
        const target = msg.to;
        const targetRec = target ? this.peers.get(target) : undefined;
        if (targetRec) {
          safeSend(targetRec.socket, JSON.stringify({ ...msg, from }));
        } else {
          safeSend(rec.socket, JSON.stringify({ type: "error", payload: "peer not found" }));
        }
        break;
      }
      default:
        safeSend(rec.socket, JSON.stringify({ type: "error", payload: "unknown type" }));
    }
  }

  remove(publicKey: string): void {
    if (!this.peers.has(publicKey)) return;
    this.peers.delete(publicKey);
    for (const rec of this.peers.values()) {
      safeSend(rec.socket, JSON.stringify({ type: "peer-left", payload: { publicKey } }));
    }
  }

  sweep(): void {
    const now = Date.now();
    for (const [pk, rec] of this.peers) {
      if (now - rec.lastHeartbeat > this.expiryMs) {
        try { rec.socket.close(); } catch {}
        this.remove(pk);
      }
    }
  }

  get size(): number { return this.peers.size; }
  has(publicKey: string): boolean { return this.peers.has(publicKey); }
}

function safeSend(socket: SignalingSocket | undefined, data: string): void {
  try { socket?.send(data); } catch {}
}

function bindSignalingWss(
  wss: WebSocketServer,
  hub: SignalingHub,
  requireSignature: boolean,
  isAuthorized: (from: string) => boolean
): WebSocketServer {
  const sweepTimer = setInterval(() => hub.sweep(), 60000);
  wss.on("connection", (ws) => {
    let registered = false;
    const nonce = crypto.randomBytes(32).toString("base64");
    if (requireSignature) {
      ws.send(JSON.stringify({ type: "challenge", nonce }));
    }
    ws.on("message", (raw) => {
      if (!registered) {
        try {
          const msg = JSON.parse(String(raw));
          if (msg.type === "register" && msg.from) {
            if (requireSignature && !verifySignature(msg.from, nonce, msg.signature ?? "")) {
              ws.send(JSON.stringify({ type: "error", payload: "invalid signature" }));
              return;
            }
            if (requireSignature && !isAuthorized(msg.from)) {
              ws.send(JSON.stringify({ type: "error", payload: "unauthorized identity" }));
              return;
            }
            registered = true;
            hub.register(msg.from, ws as any);
            return;
          }
        } catch {}
        ws.send(JSON.stringify({ type: "error", payload: "register first" }));
        return;
      }
    });
  });
  wss.on("close", () => clearInterval(sweepTimer));
  return wss;
}

/**
 * Servidor de señalización con challenge-response:
 * 1. Al conectar envía { type: "challenge", nonce }.
 * 2. El cliente responde { type: "register", from, signature } where
 *    signature = Ed25519(nonce) con la privada asociada a `from`.
 * 3. Solo tras verificarlo se registra el par.
 * `requireSignature=false` mantiene compatibilidad con clientes legacy/tests.
 */
export function createSignalingServer(
  port: number,
  requireSignature: boolean = true,
  isAuthorized: (from: string) => boolean = () => true,
  hub: SignalingHub = new SignalingHub()
): WebSocketServer {
  const wss = new WebSocketServer({ port });
  return bindSignalingWss(wss, hub, requireSignature, isAuthorized);
}

/**
 * Adjunta el mismo hub de señalización/relay DERP sobre `/ws` en el servidor HTTP
 * principal para funcionar detrás de un único puerto reenviado (Codespaces, Colab,
 * cloudflared o reverse proxy).
 */
export function attachSignalingToHttpServer(
  server: HttpServer,
  requireSignature: boolean = true,
  isAuthorized: (from: string) => boolean = () => true,
  hub: SignalingHub = new SignalingHub(),
  wsPath: string = "/ws"
): WebSocketServer {
  const wss = new WebSocketServer({ noServer: true });
  bindSignalingWss(wss, hub, requireSignature, isAuthorized);
  server.on("upgrade", (req, socket, head) => {
    const reqPath = (req.url ?? "/").split("?")[0];
    if (reqPath !== wsPath && reqPath !== "/") {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  });
  return wss;
}
