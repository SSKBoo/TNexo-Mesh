import { TELEMETRY_INTERVAL_MS } from "../core/config.ts";

export interface TelemetryPayload {
  event: string;
  timestamp: number;
  data?: Record<string, unknown>;
}

export function sendTelemetry(payload: TelemetryPayload, fetchFn: typeof fetch = fetch): void {
  fetchFn("/telemetry", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }).catch(() => {});
}

export function startTelemetryLoop(fetchFn: typeof fetch = fetch): ReturnType<typeof setInterval> {
  return setInterval(() => {
    sendTelemetry({ event: "heartbeat", timestamp: Date.now() }, fetchFn);
  }, TELEMETRY_INTERVAL_MS);
}
