import Database from "better-sqlite3";

export function openDb(path: string = ":memory:"): Database.Database {
  const db = new Database(path);
  db.exec(`
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      endpoint TEXT UNIQUE,
      keys TEXT
    );
    CREATE TABLE IF NOT EXISTS invites (
      id TEXT PRIMARY KEY,
      payload TEXT,
      expires_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS signing_keys (
      mesh_pub_key TEXT PRIMARY KEY,
      signing_pub_key TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS netmap_nodes (
      signing_key TEXT PRIMARY KEY,
      node_key TEXT NOT NULL,
      user_id TEXT NOT NULL,
      provider TEXT NOT NULL DEFAULT 'oidc',
      groups_json TEXT NOT NULL DEFAULT '[]',
      tags_json TEXT NOT NULL DEFAULT '[]',
      ssh_enabled INTEGER NOT NULL DEFAULT 1,
      virtual_ip TEXT NOT NULL,
      virtual_ipv6 TEXT NOT NULL DEFAULT '',
      approved INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      home_derp INTEGER NOT NULL DEFAULT 1,
      endpoints TEXT NOT NULL,
      subnets TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS netmap_acls (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      rules TEXT NOT NULL
    );
  `);
  for (const col of [
    "ALTER TABLE netmap_nodes ADD COLUMN virtual_ipv6 TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE netmap_nodes ADD COLUMN provider TEXT NOT NULL DEFAULT 'oidc'",
    "ALTER TABLE netmap_nodes ADD COLUMN groups_json TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE netmap_nodes ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE netmap_nodes ADD COLUMN ssh_enabled INTEGER NOT NULL DEFAULT 1",
  ]) {
    try {
      db.exec(col);
    } catch {
      // La columna ya existe
    }
  }
  return db;
}
