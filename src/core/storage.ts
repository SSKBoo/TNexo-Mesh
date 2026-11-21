export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  key(index: number): string | null;
  readonly length: number;
  clear?(): void;
}

const memoryMap = new Map<string, string>();

export const memoryStorage: StorageLike = {
  getItem(key) {
    return memoryMap.has(key) ? (memoryMap.get(key) as string) : null;
  },
  setItem(key, value) {
    memoryMap.set(key, value);
  },
  removeItem(key) {
    memoryMap.delete(key);
  },
  key(index) {
    return Array.from(memoryMap.keys())[index] ?? null;
  },
  get length() {
    return memoryMap.size;
  },
  clear() {
    memoryMap.clear();
  },
};

function getStorage(storage?: StorageLike): StorageLike {
  if (storage) return storage;
  const g = globalThis as { localStorage?: StorageLike };
  return g.localStorage ?? memoryStorage;
}

export function storageKey(name: string): string {
  return `nexomesh_v1_${name}`;
}

export function readKey(name: string, storage?: StorageLike): string | null {
  const s = getStorage(storage);
  return s.getItem(storageKey(name));
}

export function writeKey(name: string, value: string, storage?: StorageLike): void {
  const s = getStorage(storage);
  s.setItem(storageKey(name), value);
}

export function migrate(storage?: StorageLike): void {
  const s = getStorage(storage);
  const keys: string[] = [];
  for (let i = 0; i < s.length; i++) {
    const k = s.key(i);
    if (k) keys.push(k);
  }
  for (const k of keys) {
    if (k.startsWith("nexomesh_v1_")) continue;
    // only migrate known unprefixed? migrate any key not prefixed
    const value = s.getItem(k);
    if (value === null) continue;
    const newKey = `nexomesh_v1_${k}`;
    if (s.getItem(newKey) === null) {
      s.setItem(newKey, value);
    }
    s.removeItem(k);
  }
}

export function clearAll(storage?: StorageLike): void {
  const s = getStorage(storage);
  s.clear?.();
}
