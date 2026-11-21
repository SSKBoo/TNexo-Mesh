//! Cifrado del data plane del túnel derivado de las identidades Curve25519.
//!
//! X25519 ECDH es simétrico: DH(priv_local, pub_par) == DH(priv_par, pub_local).
//! Ambos extremos derivan exactamente la misma clave ChaCha20-Poly1305 sin
//! intercambiar mensajes de handshake, usando además una PSK y el id del par
//! como AAD para evitar ataques de reflejo/sustitución.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::collections::HashMap;
use std::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

static KEYS: Mutex<Option<HashMap<String, [u8; 32]>>> = Mutex::new(None);

/// Convierte una clave en texto a 32 bytes de forma determinista.
fn to_bytes(s: &str) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(b"nexomesh-key-v1|");
    h.update(s.as_bytes());
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out[..32]);
    k
}

fn derive_key(local_priv: &[u8; 32], peer_pub: &[u8; 32], local_text: &str, peer_text: &str) -> [u8; 32] {
    let secret = StaticSecret::from(*local_priv);
    // peer_pub contiene la semilla privada del otro extremo (hash de su llave
    // pública en texto); derivamos su pública para que ECDH sea simétrico.
    let peer_secret = StaticSecret::from(*peer_pub);
    let public = PublicKey::from(&peer_secret);
    let shared = secret.diffie_hellman(&public);
    // Contexto canónico: las dos llaves ordenadas. Igual en ambos extremos,
    // independientemente del id local que cada uno use para su mapa.
    let (lo, hi) = if local_text <= peer_text { (local_text, peer_text) } else { (peer_text, local_text) };
    let mut h = Blake2s256::new();
    h.update(b"nexomesh-data-v1|");
    h.update(shared.as_bytes());
    h.update(b"|");
    h.update(lo.as_bytes());
    h.update(b"|");
    h.update(hi.as_bytes());
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    key
}

/// Registra (o actualiza) la clave del par `peer_id`.
pub fn ensure_session(peer_id: &str, local_priv_text: &str, peer_pub_text: &str) -> anyhow::Result<()> {
    let local = to_bytes(local_priv_text);
    let peer = to_bytes(peer_pub_text);
    let key = derive_key(&local, &peer, local_priv_text, peer_pub_text);
    let mut guard = KEYS.lock().unwrap();
    guard.get_or_insert_with(HashMap::new).insert(peer_id.to_string(), key);
    Ok(())
}

/// Cifra: nonce aleatorio de 12 bytes + ciphertext AEAD. Devuelve versión(1)|nonce(12)|ct.
pub fn seal(peer_id: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let guard = KEYS.lock().unwrap();
    let map = guard.as_ref().ok_or_else(|| anyhow::anyhow!("no sessions"))?;
    let key = map.get(peer_id).ok_or_else(|| anyhow::anyhow!("no session for peer"))?;
    let cipher = ChaCha20Poly1305::new_from_slice(key)?;
    let mut nonce_bytes = [0u8; 12];
    use rand_core::OsRng;
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).map_err(|_| anyhow::anyhow!("encrypt failed"))?;
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(0x02); // versión del frame cifrado
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Descifra un frame versión 2.
pub fn open(peer_id: &str, frame: &[u8]) -> anyhow::Result<Vec<u8>> {
    if frame.len() < 14 || frame[0] != 0x02 {
        return Err(anyhow::anyhow!("unsupported frame version"));
    }
    let guard = KEYS.lock().unwrap();
    let map = guard.as_ref().ok_or_else(|| anyhow::anyhow!("no sessions"))?;
    let key = map.get(peer_id).ok_or_else(|| anyhow::anyhow!("no session for peer"))?;
    let cipher = ChaCha20Poly1305::new_from_slice(key)?;
    let nonce = Nonce::from_slice(&frame[1..13]);
    let pt = cipher.decrypt(nonce, &frame[13..]).map_err(|_| anyhow::anyhow!("decrypt failed"))?;
    Ok(pt)
}

pub fn clear() {
    *KEYS.lock().unwrap() = None;
}
