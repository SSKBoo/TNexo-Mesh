# Backend API (Plano de Control y Malla DERP)

## Salud y Diagnóstico DERP
- `GET /health` → `{ ok: true, service: "nexomesh-backend" }`
- `GET /derp-map` → Lista de regiones DERP configuradas (`id`, `name`, `host`, `port`)
- `GET /derp/ping` → `{ pong, regionId }` para medición de latencia RTT
- `GET /derp/mesh/homes` → Mapa de región Home DERP por clave pública
- `POST /derp/mesh/announce` → Anuncia cambio de región Home DERP entre nodos federados
- `POST /derp/mesh/deliver` → Reenvío inter-DERP de frames cifrados `NM2`

## Señalización y Relay DERP (WebSocket `/ws` o puerto `8443`)
- Challenge-response Ed25519 al conectar: `{ type: "challenge", nonce }` → `{ type: "register", from, signature, nodeKey, bindingSignature }`
- Envío dirigido únicamente con frames binarios `NM2 | dstKey(32B) | payload` o JSON `{ type: "relay", to, data }` (todo frame `NM1` o broadcast sin destinatario es rechazado)
- Distribución automática en caliente `{ type: "netmap", netmap: SignedNetMap }`

## Plano de Control NetMap, IPAM `100.64.0.0/10`, OIDC y Tailnet Lock
- `POST /netmap/register` → Registra nodo con vínculo `bind:<nodeKey>`, token OIDC (`google` / `github` / `okta` / `oidc`), grupos (`group:dev`), etiquetas (`tag:server`) y asignación IPAM sin colisiones en `100.64.0.0/10` (`virtualIp: "auto"`) + IPv6 ULA `fd7a:115c:a1e0::/48`
- `POST /netmap/approve` → Aprueba o suspende un dispositivo y difunde nuevo `SignedNetMap`
- `POST /netmap/revoke` → Revocación instantánea de dispositivo (cierra WS al instante y propaga NetMap actualizado)
- `POST /netmap/acls` → Actualiza reglas ACL (por grupo/tag/CIDR y permiso `ssh`)
- `POST /netmap/ssh/authorize` → Evalúa política SSH sin llaves y emite certificado efímero firmado
- `POST /netmap/rotate-root` → Rota la llave raíz Ed25519 manteniendo llaves previas en ventana de transición sin cortar la malla
- `POST /netmap/tailnet-lock/enable` → Activa firma multi-nodo Tailnet Lock (TKA)
- `POST /netmap/tailnet-lock/cosign` → Registra co-firma TKA de un dispositivo
- `GET /netmap` → Devuelve el `SignedNetMap` vigente firmado por el plano de control

## Auditoría y Flujos de Red
- `GET /audit-logs?limit=100` → Registro persistente en SQLite de mutaciones de control (`register_node`, `approve_device`, `revoke_node`, `update_acls`, `rotate_control_key`, `ssh_authorized`, `tailnet_lock_cosign`)
- `POST /flow-logs` / `GET /flow-logs?limit=200` → Telemetría de flujos (`srcVip`, `dstVip`, `proto`, `dstPort`, `bytes`, `packets`, `action`)

## TURN, Push e Invitaciones
- `GET /credentials` → `{ username, password, ttl: 3600 }` (HMAC-SHA1 para `coturn`)
- `POST /push/subscribe` / `POST /push/send` → Suscripciones Web Push
- `POST /invite` / `GET /invite/:id` → Invitaciones con enlace X25519 ↔ Ed25519
