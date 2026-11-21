import type { MeshPeer, TransferRecord } from "./types.ts";

export const isMock = true;

export const seedPeers: MeshPeer[] = [
  { id: "demo-1", publicKey: "demo", virtualIp: "10.0.0.2", name: "Demo Peer", online: true, relayInUse: false },
];

export const seedTransfers: TransferRecord[] = [];
