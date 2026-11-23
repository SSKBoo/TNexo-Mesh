import crypto from "node:crypto";
import { verifySignature } from "./signaling.ts";
import type { Store } from "./store.ts";

export type OidcProvider = "google" | "github" | "oidc";

export interface NetMapAclRule {
  src: string;
  dst: string;
  proto: "any" | "tcp" | "udp" | "icmp";
  port?: number;
  ssh?: boolean;
}

export interface NetMapNode {
  nodeKey: string;
  signingKey: string;
  userId: string;
  provider: OidcProvider;
  groups: string[];
  tags: string[];
  sshEnabled: boolean;
  virtualIp: string;
  virtualIpv6: string;
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

export interface MeshSshAuthorization {
  allowed: boolean;
  reason?: string;
  sshCert?: {
    userId: string;
    srcNodeKey: string;
    dstNodeKey: string;
    srcIp: string;
    dstIp: string;
    expiresAt: number;
    controlPubKey: string;
    signature: string;
  };
}

/** Deriva IPv6 ULA `fd7a:115c:a1e0:...` determinista desde la NodeKey (dual-stack estilo Tailscale). */
export function deriveDualStackIpv6Ula(nodeKey: string): string {
  const hash = crypto.createHash("sha256").update(nodeKey).digest();
  const g3 = hash.subarray(0, 2).toString("hex");
  const g4 = hash.subarray(2, 4).toString("hex");
  const g5 = hash.subarray(4, 6).toString("hex");
  const g6 = hash.subarray(6, 8).toString("hex");
  return `fd7a:115c:a1e0:${g3}:${g4}:${g5}:${g6}::1`.replace(":::", "::");
}

function intToIpv4(n: number): string {
  return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

/** Valida un claim OIDC / SSO (Google, GitHub o OIDC genérico) asociado al `userId`. */
export function verifyOidcClaim(
  oidcToken: string,
  expectedUserId: string,
  expectedProvider?: OidcProvider
): boolean {
  const parts = oidcToken.split(".");
  if (parts.length !== 3) return false;
  try {
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    const sub = String(claims.email ?? claims.sub ?? "");
    const exp = Number(claims.exp ?? 0);
    if (!sub || sub !== expectedUserId) return false;
    if (exp > 0 && exp * 1000 < Date.now()) return false;
    if (expectedProvider === "google" && claims.iss && !String(claims.iss).includes("accounts.google.com")) {
      return false;
    }
    if (expectedProvider === "github" && claims.iss && !String(claims.iss).includes("github")) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
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

function nodeMatchesSelector(node: NetMapNode, selector: string): boolean {
  const sel = selector.trim();
  if (sel === "*" || sel === "autogroup:member") return true;
  if (sel.startsWith("group:")) return node.groups.includes(sel);
  if (sel.startsWith("tag:")) return node.tags.includes(sel);
  if (sel === node.userId) return true;
  if (sel === node.virtualIp) return true;
  if (sel === "100.64.0.0/10") {
    const oct = node.virtualIp.split(".").map(Number);
    return oct[0] === 100 && oct[1] >= 64 && oct[1] <= 127;
  }
  return false;
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

  /** Asigna una IP CGNAT libre sin colisiones dentro de `100.64.0.0/10` (4.19M direcciones). */
  allocateCgnatIp(forSigningKey?: string): string {
    const used = new Set<string>();
    for (const [sk, n] of this.nodes) {
      if (sk !== forSigningKey) used.add(n.virtualIp);
    }
    const base = (100 << 24) | (64 << 16); // 100.64.0.0
    const total = 1 << 22; // /10
    for (let offset = 1; offset < total - 1; offset++) {
      if ((offset & 0xff) === 0 || (offset & 0xff) === 255) continue;
      const candidate = intToIpv4((base + offset) >>> 0);
      if (!used.has(candidate)) {
        return candidate;
      }
    }
    throw new Error("CGNAT 100.64.0.0/10 IPAM exhausted");
  }

  registerNode(
    node: Omit<
      NetMapNode,
      "approved" | "expiresAt" | "homeDerp" | "virtualIpv6" | "provider" | "groups" | "tags" | "sshEnabled"
    > & {
      approved?: boolean;
      ttlMs?: number;
      homeDerp?: number;
      virtualIpv6?: string;
      provider?: OidcProvider;
      groups?: string[];
      tags?: string[];
      sshEnabled?: boolean;
    },
    bindingSignature: string
  ): NetMapNode {
    if (!verifyIdentityBinding(node.nodeKey, node.signingKey, bindingSignature)) {
      throw new Error("invalid identity binding signature");
    }

    let assignedIp = (node.virtualIp ?? "").trim();
    if (!assignedIp || assignedIp === "auto") {
      const existing = this.nodes.get(node.signingKey);
      assignedIp = existing?.virtualIp || this.allocateCgnatIp(node.signingKey);
    } else {
      for (const [sk, existing] of this.nodes) {
        if (sk !== node.signingKey && existing.virtualIp === assignedIp) {
          throw new Error(`virtualIp collision in IPAM: ${assignedIp}`);
        }
      }
    }

    const ttlMs = node.ttlMs ?? 7 * 24 * 60 * 60 * 1000;
    const record: NetMapNode = {
      nodeKey: node.nodeKey,
      signingKey: node.signingKey,
      userId: node.userId,
      provider: node.provider ?? "oidc",
      groups: [...(node.groups ?? [])],
      tags: [...(node.tags ?? [])],
      sshEnabled: node.sshEnabled ?? true,
      virtualIp: assignedIp,
      virtualIpv6: node.virtualIpv6 || deriveDualStackIpv6Ula(node.nodeKey),
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

  /** Revocación instantánea de dispositivo: invalida aprobación y expiración al instante. */
  revokeNode(signingKey: string): NetMapNode | null {
    const rec = this.nodes.get(signingKey);
    if (!rec) return null;
    rec.approved = false;
    rec.expiresAt = 0;
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

  getNodesByUser(userId: string): NetMapNode[] {
    return Array.from(this.nodes.values()).filter((n) => n.userId === userId);
  }

  setAcls(acls: NetMapAclRule[]): void {
    this.acls = [...acls];
    this.store?.saveNetMapAcls(this.acls);
    this.version += 1;
  }

  /** Evalúa política SSH basada en grupos/etiquetas OIDC y emite certificado efímero firmado. */
  authorizeSsh(srcSigningKey: string, dstSigningKey: string, ttlMs: number = 5 * 60 * 1000): MeshSshAuthorization {
    const now = Date.now();
    if (!this.isActiveAndApproved(srcSigningKey, now) || !this.isActiveAndApproved(dstSigningKey, now)) {
      return { allowed: false, reason: "source or destination device unapproved or expired" };
    }
    const src = this.nodes.get(srcSigningKey)!;
    const dst = this.nodes.get(dstSigningKey)!;
    if (!dst.sshEnabled) {
      return { allowed: false, reason: "destination node SSH disabled" };
    }
    const matched = this.acls.some(
      (r) => Boolean(r.ssh) && nodeMatchesSelector(src, r.src) && nodeMatchesSelector(dst, r.dst)
    );
    if (!matched) {
      return { allowed: false, reason: "denied by NetMap SSH ACL policy" };
    }
    const expiresAt = now + ttlMs;
    const canonical = `ssh|${src.userId}|${src.nodeKey}|${dst.nodeKey}|${expiresAt}`;
    const signature = crypto.sign(null, Buffer.from(canonical), this.privKey).toString("base64");
    return {
      allowed: true,
      sshCert: {
        userId: src.userId,
        srcNodeKey: src.nodeKey,
        dstNodeKey: dst.nodeKey,
        srcIp: src.virtualIp,
        dstIp: dst.virtualIp,
        expiresAt,
        controlPubKey: this.pubB64,
        signature,
      },
    };
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
