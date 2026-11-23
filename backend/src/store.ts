import { openDb } from "./db.ts";
import type Database from "better-sqlite3";

/**
 * Capa de persistencia SQLite. Sustituye los Map en memoria de invites y push
 * para que los datos sobrevivan al reinicio del backend (criterio Fase 4).
 */
export class Store {
  private db: Database.Database;

  constructor(path?: string) {
    this.db = openDb(path ?? process.env.DB_PATH ?? ":memory:");
  }

  // --- invites ---
  saveInvite(id: string, payload: unknown, expiresAt: number): void {
    this.db.prepare(
      "INSERT OR REPLACE INTO invites (id, payload, expires_at) VALUES (?, ?, ?)"
    ).run(id, JSON.stringify(payload), expiresAt);
  }

  getInvite(id: string): { id: string; payload: unknown; expiresAt: number } | null {
    const row = this.db.prepare("SELECT id, payload, expires_at FROM invites WHERE id = ?").get(id) as
      | { id: string; payload: string; expires_at: number }
      | undefined;
    if (!row) return null;
    if (Date.now() > row.expires_at) {
      this.db.prepare("DELETE FROM invites WHERE id = ?").run(id);
      return null;
    }
    return { id: row.id, payload: JSON.parse(row.payload), expiresAt: row.expires_at };
  }

  pruneInvites(): void {
    this.db.prepare("DELETE FROM invites WHERE expires_at < ?").run(Date.now());
  }

  // --- enlace identidad de malla (X25519) <-> firma signaling (Ed25519) ---
  linkSigningKey(meshPubKey: string, signingPubKey: string): void {
    this.db.prepare(
      "INSERT OR REPLACE INTO signing_keys (mesh_pub_key, signing_pub_key) VALUES (?, ?)"
    ).run(meshPubKey, signingPubKey);
  }

  isAuthorizedSigningKey(signingPubKey: string): boolean {
    return !!this.db.prepare(
      "SELECT 1 FROM signing_keys WHERE signing_pub_key = ?"
    ).get(signingPubKey);
  }

  getMeshKeyForSigningKey(signingPubKey: string): string | null {
    const row = this.db.prepare(
      "SELECT mesh_pub_key FROM signing_keys WHERE signing_pub_key = ?"
    ).get(signingPubKey) as { mesh_pub_key: string } | undefined;
    return row?.mesh_pub_key ?? null;
  }

  // --- estado persistente de NetMap (tolerante a reinicios del control plane) ---
  saveNetMapNode(node: {
    signingKey: string;
    nodeKey: string;
    userId: string;
    provider?: string;
    groups?: string[];
    tags?: string[];
    sshEnabled?: boolean;
    virtualIp: string;
    virtualIpv6?: string;
    approved: boolean;
    expiresAt: number;
    homeDerp?: number;
    endpoints: string[];
    subnets: string[];
  }): void {
    this.db.prepare(
      `INSERT OR REPLACE INTO netmap_nodes
       (signing_key, node_key, user_id, provider, groups_json, tags_json, ssh_enabled, virtual_ip, virtual_ipv6, approved, expires_at, home_derp, endpoints, subnets)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      node.signingKey,
      node.nodeKey,
      node.userId,
      node.provider ?? "oidc",
      JSON.stringify(node.groups ?? []),
      JSON.stringify(node.tags ?? []),
      node.sshEnabled === false ? 0 : 1,
      node.virtualIp,
      node.virtualIpv6 ?? "",
      node.approved ? 1 : 0,
      node.expiresAt,
      node.homeDerp ?? 1,
      JSON.stringify(node.endpoints),
      JSON.stringify(node.subnets)
    );
  }

  loadNetMapNodes(): Array<{
    signingKey: string;
    nodeKey: string;
    userId: string;
    provider: "google" | "github" | "oidc";
    groups: string[];
    tags: string[];
    sshEnabled: boolean;
    virtualIp: string;
    virtualIpv6: string;
    approved: boolean;
    expiresAt: number;
    homeDerp: number;
    endpoints: string[];
    subnets: string[];
  }> {
    const rows = this.db.prepare("SELECT * FROM netmap_nodes").all() as any[];
    return rows.map((r) => ({
      signingKey: r.signing_key,
      nodeKey: r.node_key,
      userId: r.user_id,
      provider: (r.provider ?? "oidc") as "google" | "github" | "oidc",
      groups: JSON.parse(r.groups_json ?? "[]"),
      tags: JSON.parse(r.tags_json ?? "[]"),
      sshEnabled: r.ssh_enabled !== 0,
      virtualIp: r.virtual_ip,
      virtualIpv6: String(r.virtual_ipv6 ?? ""),
      approved: Boolean(r.approved),
      expiresAt: Number(r.expires_at),
      homeDerp: Number(r.home_derp ?? 1),
      endpoints: JSON.parse(r.endpoints),
      subnets: JSON.parse(r.subnets),
    }));
  }

  saveNetMapAcls(rules: unknown[]): void {
    this.db.prepare("INSERT OR REPLACE INTO netmap_acls (id, rules) VALUES (1, ?)").run(
      JSON.stringify(rules)
    );
  }

  loadNetMapAcls(): unknown[] {
    const row = this.db.prepare("SELECT rules FROM netmap_acls WHERE id = 1").get() as
      | { rules: string }
      | undefined;
    return row ? JSON.parse(row.rules) : [];
  }

  // --- push subscriptions ---
  saveSubscription(endpoint: string, keys: unknown): void {
    this.db.prepare(
      "INSERT OR REPLACE INTO push_subscriptions (endpoint, keys) VALUES (?, ?)"
    ).run(endpoint, JSON.stringify(keys ?? {}));
  }

  getSubscription(endpoint: string): { endpoint: string; keys: unknown } | null {
    const row = this.db.prepare("SELECT endpoint, keys FROM push_subscriptions WHERE endpoint = ?").get(endpoint) as
      | { endpoint: string; keys: string }
      | undefined;
    return row ? { endpoint: row.endpoint, keys: JSON.parse(row.keys) } : null;
  }

  allSubscriptions(): { endpoint: string; keys: unknown }[] {
    return (this.db.prepare("SELECT endpoint, keys FROM push_subscriptions").all() as { endpoint: string; keys: string }[])
      .map((r) => ({ endpoint: r.endpoint, keys: JSON.parse(r.keys) }));
  }

  close(): void {
    this.db.close();
  }
}

let singleton: Store | null = null;
export function getStore(): Store {
  if (!singleton) singleton = new Store();
  return singleton;
}
export function setStore(store: Store | null): void {
  singleton = store;
}
