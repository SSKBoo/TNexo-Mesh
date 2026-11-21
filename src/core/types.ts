export type AppTab =
  | "dashboard"
  | "peers"
  | "files"
  | "defense"
  | "settings"
  | "identity";

export type TransportMode = "auto" | "cellular" | "wifi" | "ethernet" | "relay";

export type ThemeMode = "light" | "dark" | "system";

export interface DeviceProfile {
  id: string;
  name: string;
  platform: "android" | "ios" | "desktop" | "web";
  osVersion?: string;
  keepAliveEnabled: boolean;
}

export interface AndroidKeepAliveStep {
  id: string;
  title: string;
  description: string;
  completed: boolean;
}

export interface TOTPAccount {
  id: string;
  issuer: string;
  label: string;
  secret: string;
  digits: number;
  period: number;
  algorithm: "SHA1" | "SHA256" | "SHA512";
}

export interface RecoveryCode {
  code: string;
  used: boolean;
}

export interface DefensePolicy {
  autoQuarantine: boolean;
  autoRotateKeys: boolean;
  udpRateLimit: boolean;
  autoBunkerOnCritical: boolean;
  strictDns: boolean;
}

export interface ThreatVector {
  id: string;
  name: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}

export interface ArchitectureSnippet {
  id: string;
  title: string;
  body: string;
  language: string;
}

export type PushAlertEventKind =
  | "peer_joined"
  | "peer_left"
  | "threat_detected"
  | "transfer_complete"
  | "transfer_failed";

export interface DefenseEventRecord {
  id: string;
  timestamp: number;
  kind: string;
  message: string;
  severity: "info" | "warning" | "critical";
}

export interface QuarantinedPeerInfo {
  peerId: string;
  reason: string;
  quarantinedAt: number;
}

export interface VectorThreatGroup {
  vector: string;
  count: number;
  peers: string[];
}

export interface IpThreatGroup {
  ip: string;
  count: number;
  vectors: string[];
}

export interface ThreatFlowEdge {
  from: string;
  to: string;
  count: number;
}

export interface InvitePayload {
  id: string;
  inviterPublicKey: string;
  endpoint?: string;
  expiresAt: number;
  signature?: string;
}

export interface ZipEntry {
  path: string;
  size: number;
  compressedSize: number;
  method: ZipCompressionMethod;
}

export type ZipCompressionMethod = "store" | "deflate";

export interface ZipManifest {
  entries: ZipEntry[];
  totalSize: number;
  createdAt: number;
}

export type FileChannel = "lan" | "wan" | "relay";

export type FileSpeedMode = "fast" | "balanced" | "throttled";

export type FileStatus = "queued" | "transferring" | "done" | "error" | "cancelled";

export interface SignalingMessage {
  type:
    | "register"
    | "offer"
    | "answer"
    | "ice"
    | "heartbeat"
    | "peer-joined"
    | "peer-left"
    | "error";
  from?: string;
  to?: string;
  payload?: unknown;
  timestamp?: number;
}

export type MeshMode = "Direct" | "Relay TURN" | "Disconnected";

export interface MeshPeer {
  id: string;
  publicKey: string;
  virtualIp: string;
  name?: string;
  online: boolean;
  natType?: string;
  relayInUse: boolean;
  relayServer?: string;
  lastSeen?: number;
}

export interface TransferRecord {
  id: string;
  peerId: string;
  fileName: string;
  size: number;
  status: FileStatus;
  progress: number;
  startedAt: number;
  finishedAt?: number;
  channel?: FileChannel;
  speedMode?: FileSpeedMode;
}

export interface UserProfile {
  publicKey: string;
  displayName: string;
  avatar?: string;
  createdAt: number;
}
