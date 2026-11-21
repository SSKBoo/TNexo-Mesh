import { test } from "node:test";
import assert from "node:assert/strict";
import { SignalingService } from "./signalingService.ts";

class FakeWebSocket {
  static OPEN = 1;
  readyState = 0;
  onopen: ((e: any) => void) | null = null;
  onmessage: ((e: any) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: ((e: any) => void) | null = null;
  sent: string[] = [];
  constructor(public url: string) {
    setTimeout(() => {
      this.readyState = FakeWebSocket.OPEN;
      this.onopen?.({});
    }, 0);
  }
  send(data: string) { this.sent.push(data); }
  close() { this.onclose?.(); }
}

test("registers on open", async () => {
  const orig = (globalThis as any).WebSocket;
  (globalThis as any).WebSocket = FakeWebSocket;
  try {
    const svc = new SignalingService("pk1", {}, "ws://test");
    svc.connect();
    await new Promise((r) => setTimeout(r, 10));
    assert.ok((svc as any).ws.sent.some((s: string) => s.includes("register")));
    svc.disconnect();
  } finally {
    (globalThis as any).WebSocket = orig;
  }
});
