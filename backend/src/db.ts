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
  `);
  return db;
}
