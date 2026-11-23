# Modelo de claves de NexoMesh

Existen **dos pares de claves por dispositivo** vinculados criptográficamente en el plano de control, además de co-firmas multi-nodo (`Tailnet Lock`).

## 1. Identidad de malla (X25519 / Curve25519)

- Se genera en el dispositivo (`getOrCreatePublicKey()` en `MainActivity.kt` o `nexomesh_pc.key` en PC).
- El plano de control (`NetMapAuthority`) asigna direcciones dual-stack sin colisiones en el bloque CGNAT **`100.64.0.0/10`** (4.19M IPs, con MagicDNS en `100.100.100.100`) y una dirección IPv6 ULA **`fd7a:115c:a1e0::/48`**.
- Se usa para:
  - **Handshake inicial 1-RTT `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`** (`rust-core/src/noise.rs` y `session.rs`) con llaves efímeras aleatorias desde el primer paquete (`strict_noise_required`, PFS desde el byte 0).
  - Contadores monotónicos de 64 bits con ventana deslizante anti-replay de 64 paquetes y rotación automática cada 120 s / 2^20 mensajes.

## 2. Firma de señalización (Ed25519)

- Derivada de forma determinista con `derive_ed25519_keypair` (`rust-core/src/keys.rs`) o generada en el cliente.
- En el handshake WebSocket (`/ws`), el servidor envía un `challenge` con nonce aleatorio; el cliente responde `signature = Ed25519-Sign(priv_firma, nonce)` y `from = pub_firma` (32 bytes base64/hex).

## 3. Vínculo criptográfico, NetMap firmado y Tailnet Lock (`backend/src/netmap.ts`)

- Al registrar un dispositivo (`POST /netmap/register`), el cliente demuestra posesión firmando `"bind:<nodeKey>"` con su `signingKey` (`verifyIdentityBinding`) y vinculando identidad OIDC/SSO (`google`, `github`, `okta`, `oidc`), grupos (`group:dev`) y etiquetas (`tag:server`).
- El plano de control gestiona **aprobación**, **expiración de llaves** (`expiresAt`), **revocación instantánea** (`POST /netmap/revoke`), **rotación de llave raíz** (`POST /netmap/rotate-root` con ventana de transición) y **Tailnet Lock** (co-firma multi-nodo TKA contra compromiso del servidor de control).
