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
