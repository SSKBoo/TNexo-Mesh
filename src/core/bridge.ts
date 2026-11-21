import { LOCAL_BRIDGE_URL, BRIDGE_TIMEOUT_MS } from "./config.ts";

export interface BridgeStatus {
  ok: boolean;
  peers?: number;
  virtualIp?: string;
  [key: string]: unknown;
}

export interface BridgeCommandResult {
  ok: boolean;
  data?: unknown;
  error?: string;
}

export let isMock = true;

export function setMock(value: boolean): void {
  isMock = value;
}

export async function probeBridge(
  fetchFn: typeof fetch = fetch,
  healthUrl: string = LOCAL_BRIDGE_URL,
  timeoutMs: number = BRIDGE_TIMEOUT_MS
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(healthUrl, { signal: controller.signal });
    if (!res.ok) {
      isMock = true;
      return true;
    }
    isMock = false;
    return false;
  } catch {
    isMock = true;
    return true;
  } finally {
    clearTimeout(timer);
  }
}

export async function getStatus(fetchFn: typeof fetch = fetch): Promise<BridgeStatus> {
  if (isMock) return { ok: false };
  const res = await fetchFn("http://127.0.0.1:51820/status");
  return (await res.json()) as BridgeStatus;
}

export async function sendCommand(
  command: string,
  args: Record<string, unknown> = {},
  fetchFn: typeof fetch = fetch
): Promise<BridgeCommandResult> {
  if (isMock) return { ok: false, error: "mock mode" };
  const res = await fetchFn("http://127.0.0.1:51820/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command, ...args }),
  });
  return (await res.json()) as BridgeCommandResult;
}

export const bridge = {
  get isMock() {
    return isMock;
  },
  probe: probeBridge,
  getStatus,
  sendCommand,
};
