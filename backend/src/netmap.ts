import crypto from "node:crypto";
import { verifySignature } from "./signaling.ts";
import type { Store } from "./store.ts";

export interface NetMapAclRule {
  src: string;
  dst: string;
  proto: "any" | "tcp" | "udp" | "icmp";
  port?: number;
}

export interface NetMapNode {
  nodeKey: string;
  signingKey: string;
  userId: string;
  virtualIp: string;
  approved: boolean;
  expiresAt: number;
  homeDerp: number;
  endpoints: string[];
  subnets: string[];
}

export interface NetMapPayload {
  version: number;
  issuedAt: number;
  nodes: NetMapNode[];
  acls: NetMapAclRule[];
}

export interface SignedNetMap {
  payload: NetMapPayload;
  signature: string;
  controlPubKey: string;
}

/** Verifica el vínculo criptográfico: signingKey debe firmar `"bind:<nodeKey>"`. */
export function verifyIdentityBinding(
  nodeKey: string,
  signingKey: string,
  bindingSignature: string
): boolean {
  if (!nodeKey || !signingKey || !bindingSignature) return false;
  return verifySignature(signingKey, `bind:${nodeKey}`, bindingSignature);
}

export class NetMapAuthority {
  private readonly pubB64: string;
  private readonly privKey: crypto.KeyObject;
  private nodes = new Map<string, NetMapNode>();
  private acls: NetMapAclRule[] = [];
  private version = 1;
  private store?: Store;

  constructor(store?: Store) {
    this.store = store;
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    this.pubB64 = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
    this.privKey = privateKey;

    if (store) {
      for (const n of store.loadNetMapNodes()) {
        this.nodes.set(n.signingKey, n);
      }
      this.acls = store.loadNetMapAcls() as NetMapAclRule[];
      if (this.nodes.size > 0 || this.acls.length > 0) {
        this.version += 1;
      }
    }
  }

  get controlPublicKey(): string {
    return this.pubB64;
  }

  registerNode(
    node: Omit<NetMapNode, "approved" | "expiresAt" | "homeDerp"> & {
      approved?: boolean;
      ttlMs?: number;
      homeDerp?: number;
    },
    bindingSignature: string
  ): NetMapNode {
    if (!verifyIdentityBinding(node.nodeKey, node.signingKey, bindingSignature)) {
      throw new Error("invalid identity binding signature");
    }
    const ttlMs = node.ttlMs ?? 7 * 24 * 60 * 60 * 1000;
    const record: NetMapNode = {
      nodeKey: node.nodeKey,
      signingKey: node.signingKey,
      userId: node.userId,
      virtualIp: node.virtualIp,
      approved: node.approved ?? false,
      expiresAt: Date.now() + ttlMs,
      homeDerp: node.homeDerp ?? 1,
      endpoints: [...node.endpoints],
      subnets: [...node.subnets],
    };
    this.nodes.set(record.signingKey, record);
    this.store?.saveNetMapNode(record);
    this.store?.linkSigningKey(record.nodeKey, record.signingKey);
    this.version += 1;
    return record;
  }

  approveDevice(signingKey: string, approved: boolean = true): NetMapNode | null {
    const rec = this.nodes.get(signingKey);
    if (!rec) return null;
    rec.approved = approved;
    this.store?.saveNetMapNode(rec);
    this.version += 1;
    return rec;
  }

  updateHomeDerp(signingKey: string, homeDerp: number): NetMapNode | null {
    const rec = this.nodes.get(signingKey);
    if (!rec) return null;
    rec.homeDerp = homeDerp;
    this.store?.saveNetMapNode(rec);
    this.version += 1;
    return rec;
  }

  isActiveAndApproved(signingKey: string, now: number = Date.now()): boolean {
    const rec = this.nodes.get(signingKey);
    if (!rec) return false;
    return rec.approved && rec.expiresAt > now;
  }

  getNode(signingKey: string): NetMapNode | null {
    return this.nodes.get(signingKey) ?? null;
  }

  setAcls(acls: NetMapAclRule[]): void {
    this.acls = [...acls];
    this.store?.saveNetMapAcls(this.acls);
    this.version += 1;
  }

  issueSignedNetMap(now: number = Date.now()): SignedNetMap {
    const activeNodes = Array.from(this.nodes.values()).filter(
      (n) => n.approved && n.expiresAt > now
    );
    const payload: NetMapPayload = {
      version: this.version,
      issuedAt: now,
      nodes: activeNodes,
      acls: this.acls,
    };
    const canonical = JSON.stringify(payload);
    const sig = crypto.sign(null, Buffer.from(canonical), this.privKey).toString("base64");
    return {
      payload,
      signature: sig,
      controlPubKey: this.pubB64,
    };
  }
}

export function verifySignedNetMap(signed: SignedNetMap): boolean {
  const canonical = JSON.stringify(signed.payload);
  return verifySignature(signed.controlPubKey, canonical, signed.signature);
}
