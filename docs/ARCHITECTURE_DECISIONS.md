# Architecture Decisions

- PWA role: control panel only (Option A)
- Mesh subnet: 10.0.0.0/24, stable IP by sha256(publicKey)
- Ports: file=51821, signaling=8443, stun=3478, turn=3479
- MTU default: 1420
- Max peers: 50
- Identity: Curve25519 public key only, no passwords
- Google account: backup + push only, not mesh auth
- Infra: VPS (Hetzner), coturn, VAPID keys on same VPS
