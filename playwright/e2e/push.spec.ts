import { test, expect } from "@playwright/test";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { createApp } from "../../backend/src/index.ts";
import { NetMapAuthority } from "../../backend/src/netmap.ts";
import { verifyTurnPassword } from "../../backend/src/turn.ts";

test("E2E Push, TURN HMAC, DERP map RTT y simulación NAT real (Cone/Doble NAT/Simétrico + pérdida)", async ({ page }) => {
  const srv = createServer(createApp(new NetMapAuthority()));
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as { port: number }).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Suscripción Push real persistente
    const pushRes = await page.request.post(`${baseUrl}/push/subscribe`, {
      data: { endpoint: "https://push.nexomesh.test/sub-e2e", keys: { auth: "k1", p256dh: "k2" } },
    });
    expect(pushRes.status()).toBe(200);
    expect((await pushRes.json()).ok).toBe(true);

    // 2. Credenciales TURN HMAC-SHA1 estilo coturn
    const turnRes = await page.request.get(`${baseUrl}/credentials`);
    expect(turnRes.status()).toBe(200);
    const turnCreds = await turnRes.json();
    expect(verifyTurnPassword(turnCreds.username, turnCreds.password)).toBe(true);

    // 3. Mapa DERP + medición ping
    const mapRes = await page.request.get(`${baseUrl}/derp-map`);
    expect(mapRes.status()).toBe(200);
    const map = await mapRes.json();
    expect(Array.isArray(map.regions)).toBe(true);
    const pingRes = await page.request.get(`${baseUrl}/derp/ping`);
    expect(pingRes.status()).toBe(200);

    // 4. Simulación E2E nativa de topologías NAT (Doble Cone NAT + pérdida 20% + NAT Simétrico + failover DERP)
    const rustDir = path.resolve(process.cwd(), "rust-core");
    const natRun = spawnSync("cargo", ["test", "--test", "nat_e2e"], {
      cwd: rustDir,
      encoding: "utf8",
    });
    expect(natRun.status, natRun.stderr || natRun.stdout).toBe(0);
    expect(natRun.stdout).toContain("e2e_double_cone_nat_with_packet_loss_and_derp_p2p_failover ... ok");
    expect(natRun.stdout).toContain("e2e_symmetric_nat_birthday_paradox_probe_reaches_peer ... ok");
  } finally {
    await new Promise<void>((r) => srv.close(() => r()));
  }
});
