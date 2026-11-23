# Architecture Decisions

- PWA role: control panel + WebSocket/WebRTC telemetry UI (`src/`)
- Mesh subnet: CGNAT `100.64.0.0/10` (4.19M IPs) collision-free IPAM in `NetMapAuthority` + dual-stack IPv6 ULA `fd7a:115c:a1e0::/48` (with legacy `10.0.0.0/24` route compatibility)
- MagicDNS: `100.100.100.100` resolving `.mesh` and `.nexomesh` via OS Split DNS (Windows NRPT, Linux `systemd-resolved`, macOS `/etc/resolver`, iOS `NEDNSSettings`, Android `VpnService.Builder`)
- Ports: file=51821, mesh/UDP=51820, signaling/DERP=/ws + 8443, stun=3478, turn=3479
- MTU default: 1280 (mobile/DERP-safe)
- Data plane: strict 1-RTT `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` from packet 0, 64-bit sliding anti-replay window, automatic 120s PFS rekeying, UDP batching + GSO/GRO support (`udp_batch.rs`)
- Relay: directed `NM2 | dstKey(32B) | payload` only (zero broadcast), multi-region federated `DerpMeshRouter`
- Auth & Policy: OIDC/SSO (`google`, `github`, `okta`, `oidc`), group/tag ACLs (`group:dev`, `tag:server`), Keyless SSH (`ssh.rs`), Serve/Funnel L7 proxies (`serve_funnel.rs`), Tailnet Lock (`tka`), and persistent SQLite Audit + Flow logs
