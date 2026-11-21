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
  `);
  return db;
}
