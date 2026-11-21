import type { DefenseEventRecord, QuarantinedPeerInfo } from "./types.ts";

export const meshDefense = {
  events: [] as DefenseEventRecord[],
  quarantined: [] as QuarantinedPeerInfo[],
  recordEvent(ev: DefenseEventRecord): void {
    this.events.unshift(ev);
    if (this.events.length > 100) this.events.length = 100;
  },
  quarantine(peer: QuarantinedPeerInfo): void {
    this.quarantined.push(peer);
  },
};
