import { WebSocket, WebSocketServer } from "ws";

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

export class SignalingHub {
  private peers = new Map<string, PeerRecord>();
  private expiryMs = 5 * 60 * 1000;

  register(publicKey: string, socket: SignalingSocket): void {
    // notify existing peers
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

  get size(): number {
    return this.peers.size;
  }

  has(publicKey: string): boolean {
    return this.peers.has(publicKey);
  }
}

function safeSend(socket: SignalingSocket | undefined, data: string): void {
  try {
    socket?.send(data);
  } catch {}
}

export function createSignalingServer(port: number): WebSocketServer {
  const wss = new WebSocketServer({ port });
  const hub = new SignalingHub();
  const sweepTimer = setInterval(() => hub.sweep(), 60000);
  wss.on("connection", (ws) => {
    let registered = false;
    ws.on("message", (raw) => {
      if (!registered) {
        try {
          const msg = JSON.parse(String(raw));
          if (msg.type === "register" && msg.from) {
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
