import { MAX_PEERS } from "./config.ts";
import type { MeshPeer } from "./types.ts";

export class MeshEngine {
  private peers: Map<string, MeshPeer> = new Map();

  get peerCount(): number {
    return this.peers.size;
  }

  addPeer(peer: MeshPeer): { ok: boolean; error?: string } {
    if (this.peers.size >= MAX_PEERS && !this.peers.has(peer.id)) {
      return { ok: false, error: "max peers reached" };
    }
    this.peers.set(peer.id, peer);
    return { ok: true };
  }

  removePeer(id: string): boolean {
    return this.peers.delete(id);
  }

  getPeer(id: string): MeshPeer | undefined {
    return this.peers.get(id);
  }

  listPeers(): MeshPeer[] {
    return Array.from(this.peers.values());
  }

  clear(): void {
    this.peers.clear();
  }
}

export function canAddPeer(currentCount: number): boolean {
  return currentCount < MAX_PEERS;
}
