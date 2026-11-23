# Modelo de claves de NexoMesh

Existen **dos pares de claves con propósitos distintos**, vinculados criptográficamente en el plano de control.

## 1. Identidad de malla (X25519 / Curve25519)

- Se genera en el dispositivo (`getOrCreatePublicKey()` en `MainActivity.kt` o `nexomesh_pc.key` en PC).
- Las IPs virtuales dual-stack se derivan de `Blake2s256(publicKey)`: `10.0.0.0/24` (IPv4) y `fd7a:115c:a1e0::/48` (IPv6 ULA).
- Se usa para:
  - **ECDH + PFS efímero del data plane** (`rust-core/src/session.rs` y `rust-core/src/noise.rs`, con rotación automática cada 120 s / 2^20 mensajes y ventana deslizante anti-replay de 64 bits).
  - Handshake `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`.

## 2. Firma de señalización (Ed25519)

- Derivada de forma determinista con `derive_ed25519_keypair` (`rust-core/src/keys.rs`) o generada en el cliente.
- En el handshake WebSocket, el servidor envía un `challenge` con un nonce aleatorio; el cliente responde `signature = Ed25519-Sign(priv_firma, nonce)` y `from = pub_firma` (32 bytes base64/hex).

## 3. Vínculo criptográfico y NetMap firmado (`backend/src/netmap.ts`)

- Al registrar un dispositivo (`POST /netmap/register`), el cliente demuestra posesión firmando `"bind:<nodeKey>"` con su `signingKey` (`verifyIdentityBinding`).
- El plano de control mantiene **aprobación de dispositivos** (`approved`) y **expiración de llaves** (`expiresAt`), y emite un **`SignedNetMap`** firmado con su llave Ed25519 que distribuye nodos, IPs, endpoints y ACLs verificables sin confiar en el canal.
