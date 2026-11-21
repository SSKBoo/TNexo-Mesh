import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validateFile,
  validateBatch,
  truncateHistory,
  FileTransferQueue,
  MAX_FILE_BYTES,
  MAX_BATCH_BYTES,
} from "./fileTransfer.ts";
import { MeshEngine } from "./meshEngine.ts";
import { PeerGroupManager } from "./peerGroups.ts";
import { MAX_PEERS, MAX_GROUPS, MAX_TRANSFER_HISTORY } from "./config.ts";

test("rejects file > 2GB", () => {
  const r = validateFile(MAX_FILE_BYTES + 1);
  assert.equal(r.ok, false);
});

test("accepts file <= 2GB", () => {
  assert.equal(validateFile(1024).ok, true);
});

test("rejects batch > 10GB", () => {
  const r = validateBatch([MAX_FILE_BYTES, MAX_FILE_BYTES, MAX_FILE_BYTES, MAX_FILE_BYTES, MAX_FILE_BYTES, 1]);
  assert.equal(r.ok, false);
});

test("history truncated to MAX_TRANSFER_HISTORY", () => {
  const q = new FileTransferQueue();
  for (let i = 0; i < MAX_TRANSFER_HISTORY + 5; i++) {
    q.add({ id: String(i), fileName: `f${i}`, size: 1, status: "done" });
  }
  assert.equal(q.getHistory().length, MAX_TRANSFER_HISTORY);
});

test("truncateHistory", () => {
  const arr = Array.from({ length: MAX_TRANSFER_HISTORY + 3 }, (_, i) => i);
  assert.equal(truncateHistory(arr).length, MAX_TRANSFER_HISTORY);
});

test("MeshEngine rejects over MAX_PEERS", () => {
  const m = new MeshEngine();
  for (let i = 0; i < MAX_PEERS; i++) {
    m.addPeer({ id: String(i), publicKey: "pk", virtualIp: "10.0.0.2", relayInUse: false, online: true });
  }
  const r = m.addPeer({ id: "overflow", publicKey: "pk", virtualIp: "10.0.0.3", relayInUse: false, online: true });
  assert.equal(r.ok, false);
});

test("PeerGroupManager rejects over MAX_GROUPS", () => {
  const g = new PeerGroupManager();
  for (let i = 0; i < MAX_GROUPS; i++) {
    g.addGroup({ id: String(i), name: `g${i}` });
  }
  const r = g.addGroup({ id: "overflow", name: "x" });
  assert.equal(r.ok, false);
});
