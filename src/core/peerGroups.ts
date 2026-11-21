import { MAX_GROUPS } from "./config.ts";

export class PeerGroupManager {
  private groups: { id: string; name: string; peers: string[] }[] = [];

  get count(): number {
    return this.groups.length;
  }

  addGroup(group: { id: string; name: string; peers?: string[] }): { ok: boolean; error?: string } {
    if (this.groups.length >= MAX_GROUPS) {
      return { ok: false, error: "max groups reached" };
    }
    this.groups.push({ id: group.id, name: group.name, peers: group.peers ?? [] });
    return { ok: true };
  }

  removeGroup(id: string): boolean {
    const idx = this.groups.findIndex((g) => g.id === id);
    if (idx < 0) return false;
    this.groups.splice(idx, 1);
    return true;
  }

  list(): { id: string; name: string; peers: string[] }[] {
    return this.groups.slice();
  }

  clear(): void {
    this.groups = [];
  }
}

export function canAddGroup(currentCount: number): boolean {
  return currentCount < MAX_GROUPS;
}
