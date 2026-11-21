import { MAX_TRANSFER_HISTORY } from "./config.ts";

export const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB
export const MAX_BATCH_BYTES = 10 * 1024 * 1024 * 1024; // 10 GB

export interface TransferEntry {
  id: string;
  fileName: string;
  size: number;
  status: string;
}

export function validateFile(sizeBytes: number): { ok: boolean; error?: string } {
  if (sizeBytes > MAX_FILE_BYTES) {
    return { ok: false, error: "file exceeds 2 GB limit" };
  }
  if (sizeBytes < 0) {
    return { ok: false, error: "invalid size" };
  }
  return { ok: true };
}

export function validateBatch(sizesBytes: number[]): { ok: boolean; error?: string } {
  const total = sizesBytes.reduce((a, b) => a + b, 0);
  if (total > MAX_BATCH_BYTES) {
    return { ok: false, error: "batch exceeds 10 GB limit" };
  }
  for (const s of sizesBytes) {
    const r = validateFile(s);
    if (!r.ok) return r;
  }
  return { ok: true };
}

export function truncateHistory<T>(history: T[]): T[] {
  if (history.length <= MAX_TRANSFER_HISTORY) return history.slice();
  return history.slice(history.length - MAX_TRANSFER_HISTORY);
}

export class FileTransferQueue {
  private history: TransferEntry[] = [];

  add(entry: TransferEntry): boolean {
    const v = validateFile(entry.size);
    if (!v.ok) return false;
    this.history.push(entry);
    this.history = truncateHistory(this.history);
    return true;
  }

  getHistory(): TransferEntry[] {
    return this.history.slice();
  }

  clear(): void {
    this.history = [];
  }
}
