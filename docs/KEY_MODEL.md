# Modelo de claves de NexoMesh

Existen **dos pares de claves con propósitos distintos**. No son intercambiables.

## 1. Identidad de malla (X25519 / Curve25519)

- Se genera en el dispositivo (`getOrCreatePublicKey()` en `MainActivity.kt`) y se guarda en `host_pub_key`.
- La IP virtual es `sha256(publicKey)` dentro de `10.0.0.0/24` (decisión F0).
- Se usa para:
  - **ECDH del data plane**: cada extremo deriva la misma clave ChaCha20-Poly1305 con `DH(priv_local, pub_par)` (`rust-core/src/session.rs`).
  - Autenticación Noise IKpsk2 (`rust-core/src/noise.rs`).
- Se comparte en la invitación `nexomesh://join?pk=...` (parámetro `pk`, base64).

## 2. Firma de señalización (Ed25519)

- Par efímero generado por el cliente WebSocket en `backend/test/ws-auth.mjs` y por cualquier cliente que use el endpoint `/signal`.
- El servidor envía un `challenge` con un nonce aleatorio; el cliente responde con
  `signature = Ed25519-Sign(priv_firma, nonce)` y `from = pub_firma` (32 bytes en base64/hex).
- `backend/src/signaling.ts::verifySignature` valida la firma con `crypto.verify`.
- **No se usa para cifrar tráfico**, solo para probar posesión de la identidad declarada al registrarse.

## Relación entre ambas

El backend no exige hoy que `from` (firma) coincida con la `pk` de la invitación.
En un despliegue real conviene enlazarlas: derivar la clave Ed25519 de firma desde
la misma semilla X25519, o registrar en el backend el mapa `mesh_pub_key -> signing_pub_key`
al crear la invitación. Esto queda como endurecimiento pendiente.

## Nota de compatibilidad

`verifySignature` acepta la clave pública en base64 o en hex de 32 bytes y construye
el SPKI DER `302a300506032b6570032100 || pub`, por lo que funciona con claves
Ed25519 estándar (`crypto.generateKeyPairSync("ed25519")` de Node).
