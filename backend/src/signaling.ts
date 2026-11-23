import { WebSocket, WebSocketServer } from "ws";
import type { Server as HttpServer } from "node:http";
import crypto from "node:crypto";
import { NetMapAuthority, verifyIdentityBinding } from "./netmap.ts";

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

/**
 * Router multi-región para malla DERP distribuida: mantiene qué región DERP
 * sirve de Home DERP a cada nodo y reenvía frames NM2 entre regiones sin descifrar.
 */
export class DerpMeshRouter {
  private regions = new Map<number, SignalingHub>();
  private homeRegion = new Map<string, number>();

  attachRegion(regionId: number, hub: SignalingHub): void {
    this.regions.set(regionId, hub);
  }

  setHomeRegion(peerKey: string, regionId: number): void {
    this.homeRegion.set(peerKey, regionId);
  }

  getHomeRegion(peerKey: string): number | undefined {
    return this.homeRegion.get(peerKey);
  }

  removeHome(peerKey: string, regionId: number): void {
    if (this.homeRegion.get(peerKey) === regionId) {
      this.homeRegion.delete(peerKey);
    }
  }

  forwardToHomeRegion(
    sourceRegionId: number,
    from: string,
    targetKeys: string[],
    payloadB64: string
  ): boolean {
    for (const candidate of targetKeys) {
      const targetRegionId = this.homeRegion.get(candidate);
      if (targetRegionId !== undefined && targetRegionId !== sourceRegionId) {
        const remoteHub = this.regions.get(targetRegionId);
        if (remoteHub && remoteHub.deliverFromRemoteRegion(from, candidate, payloadB64)) {
          return true;
        }
      }
    }
    return false;
  }
}

export class SignalingHub {
  private peers = new Map<string, PeerRecord>();
  private expiryMs = 5 * 60 * 1000;
  readonly regionId: number;
  private router?: DerpMeshRouter;
  private authority?: NetMapAuthority;

  constructor(regionId: number = 1, router?: DerpMeshRouter, authority?: NetMapAuthority) {
    this.regionId = regionId;
    this.router = router;
    this.authority = authority;
    this.router?.attachRegion(regionId, this);
  }

  setAuthority(authority: NetMapAuthority): void {
    this.authority = authority;
  }

  register(publicKey: string, socket: SignalingSocket): void {
    for (const [pk, rec] of this.peers) {
      if (pk !== publicKey) {
        safeSend(rec.socket, JSON.stringify({ type: "peer-joined", payload: { publicKey } }));
      }
    }
    this.peers.set(publicKey, { publicKey, socket, lastHeartbeat: Date.now() });
    this.router?.setHomeRegion(publicKey, this.regionId);
    this.authority?.updateHomeDerp(publicKey, this.regionId);
    socket.on("close", () => this.remove(publicKey));
    socket.on("message", (raw: any) => this.handleMessage(publicKey, raw));
  }

  /** Entrega un frame ya validado desde otro nodo DERP de la malla. */
  deliverFromRemoteRegion(from: string, targetKey: string, payloadB64: string): boolean {
    const targetRec = this.peers.get(targetKey);
    if (!targetRec) return false;
    safeSend(
      targetRec.socket,
      JSON.stringify({ type: "relay", from, viaRegion: this.regionId, data: payloadB64 })
    );
    return true;
  }

  private handleMessage(from: string, raw: any): void {
    // ÚNICAMENTE tráfico binario dirigido NM2: 'N','M','2' | dstKey(32 bytes) | payload.
    if (Buffer.isBuffer(raw) && raw.length >= 36 && raw[0] === 0x4e && raw[1] === 0x4d && raw[2] === 0x32) {
      const dstBytes = raw.subarray(3, 35);
      const dstB64 = dstBytes.toString("base64");
      const dstHex = dstBytes.toString("hex");
      const innerB64 = raw.subarray(35).toString("base64");
      const targetRec = this.peers.get(dstB64) ?? this.peers.get(dstHex);
      if (targetRec) {
        safeSend(targetRec.socket, JSON.stringify({ type: "relay", from, data: innerB64 }));
        return;
      }
      if (this.router?.forwardToHomeRegion(this.regionId, from, [dstB64, dstHex], innerB64)) {
        return;
      }
      safeSend(this.peers.get(from)?.socket, JSON.stringify({ type: "error", payload: "target peer offline" }));
      return;
    }

    // Rechazar fallback inseguro NM1 (sin destinatario -> prohibido broadcast en DERP).
    if (Buffer.isBuffer(raw) && raw.length >= 3 && raw[0] === 0x4e && raw[1] === 0x4d && raw[2] === 0x31) {
      safeSend(
        this.peers.get(from)?.socket,
        JSON.stringify({ type: "error", payload: "nm1 broadcast rejected; use NM2" })
      );
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
      case "get-netmap": {
        if (!this.authority) {
          safeSend(rec.socket, JSON.stringify({ type: "error", payload: "netmap unavailable" }));
          break;
        }
        safeSend(rec.socket, JSON.stringify({ type: "netmap", netmap: this.authority.issueSignedNetMap() }));
        break;
      }
      case "relay": {
        const target = typeof msg.to === "string" ? msg.to.trim() : "";
        if (!target) {
          safeSend(rec.socket, JSON.stringify({ type: "error", payload: "relay requires target 'to'" }));
          break;
        }
        const targetRec = this.peers.get(target);
        if (targetRec) {
          safeSend(targetRec.socket, JSON.stringify({ ...msg, from }));
        } else if (
          typeof msg.data === "string" &&
          this.router?.forwardToHomeRegion(this.regionId, from, [target], msg.data)
        ) {
          // Entregado vía inter-DERP
        } else {
          safeSend(rec.socket, JSON.stringify({ type: "error", payload: "peer not found" }));
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
    this.router?.removeHome(publicKey, this.regionId);
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
  isAuthorized: (from: string) => boolean,
  authority?: NetMapAuthority
): WebSocketServer {
  if (authority) hub.setAuthority(authority);
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
            if (msg.nodeKey && msg.bindingSignature) {
              if (!verifyIdentityBinding(String(msg.nodeKey), String(msg.from), String(msg.bindingSignature))) {
                ws.send(JSON.stringify({ type: "error", payload: "invalid identity binding" }));
                return;
              }
            } else if (authority && requireSignature && !authority.getNode(msg.from)) {
              ws.send(JSON.stringify({ type: "error", payload: "missing bound nodeKey or unregistered node" }));
              return;
            }
            if (authority && requireSignature && !authority.isActiveAndApproved(msg.from)) {
              ws.send(JSON.stringify({ type: "error", payload: "device unapproved or key expired" }));
              return;
            }
            if (requireSignature && !isAuthorized(msg.from)) {
              ws.send(JSON.stringify({ type: "error", payload: "unauthorized identity" }));
              return;
            }
            registered = true;
            hub.register(msg.from, ws as any);
            if (authority) {
              ws.send(JSON.stringify({ type: "netmap", netmap: authority.issueSignedNetMap() }));
            }
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

export function createSignalingServer(
  port: number,
  requireSignature: boolean = true,
  isAuthorized: (from: string) => boolean = () => true,
  hub: SignalingHub = new SignalingHub(),
  authority?: NetMapAuthority
): WebSocketServer {
  const wss = new WebSocketServer({ port });
  return bindSignalingWss(wss, hub, requireSignature, isAuthorized, authority);
}

export function attachSignalingToHttpServer(
  server: HttpServer,
  requireSignature: boolean = true,
  isAuthorized: (from: string) => boolean = () => true,
  hub: SignalingHub = new SignalingHub(),
  wsPath: string = "/ws",
  authority?: NetMapAuthority
): WebSocketServer {
  const wss = new WebSocketServer({ noServer: true });
  bindSignalingWss(wss, hub, requireSignature, isAuthorized, authority);
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
