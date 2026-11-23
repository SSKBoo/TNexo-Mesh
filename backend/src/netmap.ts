import crypto from "node:crypto";
import { verifySignature } from "./signaling.ts";

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

  constructor() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    this.pubB64 = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
    this.privKey = privateKey;
  }

  get controlPublicKey(): string {
    return this.pubB64;
  }

  registerNode(
    node: Omit<NetMapNode, "approved" | "expiresAt"> & {
      approved?: boolean;
      ttlMs?: number;
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
      endpoints: [...node.endpoints],
      subnets: [...node.subnets],
    };
    this.nodes.set(record.signingKey, record);
    this.version += 1;
    return record;
  }

  approveDevice(signingKey: string, approved: boolean = true): NetMapNode | null {
    const rec = this.nodes.get(signingKey);
    if (!rec) return null;
    rec.approved = approved;
    this.version += 1;
    return rec;
  }

  isActiveAndApproved(signingKey: string, now: number = Date.now()): boolean {
    const rec = this.nodes.get(signingKey);
    if (!rec) return false;
    return rec.approved && rec.expiresAt > now;
  }

  setAcls(acls: NetMapAclRule[]): void {
    this.acls = [...acls];
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
