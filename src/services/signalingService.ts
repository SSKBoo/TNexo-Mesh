import { SIGNALING_URL, HEARTBEAT_INTERVAL_MS, BACKOFF_BASE_MS, BACKOFF_MAX_MS } from "../core/config.ts";

export interface SignalingHandlers {
  onMessage?: (msg: unknown) => void;
  onOpen?: () => void;
  onClose?: () => void;
  onError?: (err: unknown) => void;
}

export class SignalingService {
  private ws: WebSocket | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectAttempt = 0;
  private url: string;
  private publicKey: string;
  private handlers: SignalingHandlers;
  private closedByUser = false;

  constructor(publicKey: string, handlers: SignalingHandlers = {}, url: string = SIGNALING_URL) {
    this.publicKey = publicKey;
    this.handlers = handlers;
    this.url = url;
  }

  connect(): void {
    this.closedByUser = false;
    this.openSocket();
  }

  private openSocket(): void {
    const ws = new WebSocket(this.url);
    this.ws = ws;
    ws.onopen = () => {
      this.reconnectAttempt = 0;
      ws.send(JSON.stringify({ type: "register", from: this.publicKey, timestamp: Date.now() }));
      this.startHeartbeat();
      this.handlers.onOpen?.();
    };
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(String(ev.data));
        this.handlers.onMessage?.(msg);
      } catch {
        this.handlers.onMessage?.(ev.data);
      }
    };
    ws.onclose = () => {
      this.stopHeartbeat();
      this.handlers.onClose?.();
      if (!this.closedByUser) this.scheduleReconnect();
    };
    ws.onerror = (err) => this.handlers.onError?.(err);
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: "heartbeat", from: this.publicKey, timestamp: Date.now() }));
      }
    }, HEARTBEAT_INTERVAL_MS);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private scheduleReconnect(): void {
    const delay = Math.min(BACKOFF_BASE_MS * Math.pow(2, this.reconnectAttempt), BACKOFF_MAX_MS);
    this.reconnectAttempt++;
    setTimeout(() => {
      if (!this.closedByUser) this.openSocket();
    }, delay);
  }

  send(message: unknown): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }

  disconnect(): void {
    this.closedByUser = true;
    this.stopHeartbeat();
    this.ws?.close();
    this.ws = null;
  }
}
