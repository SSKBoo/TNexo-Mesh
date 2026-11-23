//! Cifrado del data plane del túnel con:
//! - Contadores monotónicos de 64 bits (nonces únicos sin colisión)
//! - Ventana deslizante Anti-Replay de 64 paquetes (RFC 6479 / estilo WireGuard)
//! - Rotación automática de claves (cada 120 s o 2^20 mensajes)
//! - Intercambio PFS dinámico por sesión mediante efímeros X25519 aleatorios

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

pub const REKEY_AFTER_SECS: u64 = 120;
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 20;
const FRAME_V3_COUNTER: u8 = 0x03;

/// Ventana deslizante Anti-Replay de 64 paquetes.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    max_seq: u64,
    bitmap: u64,
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            max_seq: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    /// Valida y registra el contador `seq`. Rechaza duplicados o paquetes demasiado antiguos.
    pub fn accept(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.max_seq = seq;
            self.bitmap = 1;
            return true;
        }
        if seq > self.max_seq {
            let shift = seq - self.max_seq;
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.max_seq = seq;
            return true;
        }
        let diff = self.max_seq - seq;
        if diff >= 64 {
            return false;
        }
        let bit = 1u64 << diff;
        if (self.bitmap & bit) != 0 {
            return false; // Replay detectado
        }
        self.bitmap |= bit;
        true
    }
}

struct PeerSessionState {
    key: [u8; 32],
    tx_counter: u64,
    rx_window: ReplayWindow,
    created_at: Instant,
    ephemeral_secret: Option<StaticSecret>,
}

static SESSIONS: Mutex<Option<HashMap<String, PeerSessionState>>> = Mutex::new(None);

fn to_bytes(s: &str) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(b"nexomesh-key-v1|");
    h.update(s.as_bytes());
    let out = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out[..32]);
    k
}

fn derive_static_key(
    local_priv: &[u8; 32],
    peer_pub: &[u8; 32],
    local_text: &str,
    peer_text: &str,
) -> [u8; 32] {
    let secret = StaticSecret::from(*local_priv);
    let peer_secret = StaticSecret::from(*peer_pub);
    let public = PublicKey::from(&peer_secret);
    let shared = secret.diffie_hellman(&public);
    let (lo, hi) = if local_text <= peer_text {
        (local_text, peer_text)
    } else {
        (peer_text, local_text)
    };
    let mut h = Blake2s256::new();
    h.update(b"nexomesh-data-v2|");
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

fn counter_to_nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Registra (o actualiza) la sesión del par `peer_id` con contadores y ventana anti-replay.
pub fn ensure_session(peer_id: &str, local_priv_text: &str, peer_pub_text: &str) -> anyhow::Result<()> {
    let local = to_bytes(local_priv_text);
    let peer = to_bytes(peer_pub_text);
    let key = derive_static_key(&local, &peer, local_priv_text, peer_pub_text);
    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(existing) = map.get_mut(peer_id) {
        if existing.key == key {
            return Ok(());
        }
    }
    map.insert(
        peer_id.to_string(),
        PeerSessionState {
            key,
            tx_counter: 0,
            rx_window: ReplayWindow::new(),
            created_at: Instant::now(),
            ephemeral_secret: None,
        },
    );
    Ok(())
}

/// Inicia un intercambio efímero X25519 (Perfect Forward Secrecy real) para `peer_id`.
/// Devuelve la clave pública efímera de 32 bytes para enviar al par.
pub fn begin_pfs_rekey(peer_id: &str) -> anyhow::Result<[u8; 32]> {
    use rand_core::OsRng;
    let eph = StaticSecret::random_from_rng(OsRng);
    let pub_bytes = PublicKey::from(&eph).to_bytes();
    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    let entry = map.entry(peer_id.to_string()).or_insert_with(|| PeerSessionState {
        key: [0u8; 32],
        tx_counter: 0,
        rx_window: ReplayWindow::new(),
        created_at: Instant::now(),
        ephemeral_secret: None,
    });
    entry.ephemeral_secret = Some(eph);
    Ok(pub_bytes)
}

/// Completa el intercambio efímero X25519 con la clave efímera pública recibida del par,
/// derivando una nueva clave de transporte con PFS y reiniciando contadores.
pub fn finish_pfs_rekey(peer_id: &str, peer_ephemeral_pub: &[u8; 32]) -> anyhow::Result<()> {
    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.as_mut().ok_or_else(|| anyhow::anyhow!("no sessions"))?;
    let state = map
        .get_mut(peer_id)
        .ok_or_else(|| anyhow::anyhow!("no session for peer"))?;
    let eph = state
        .ephemeral_secret
        .take()
        .ok_or_else(|| anyhow::anyhow!("no pending ephemeral key"))?;
    let shared = eph.diffie_hellman(&PublicKey::from(*peer_ephemeral_pub));
    let mut h = Blake2s256::new();
    h.update(b"nexomesh-pfs-v1|");
    h.update(&state.key);
    h.update(shared.as_bytes());
    let out = h.finalize();
    state.key.copy_from_slice(&out[..32]);
    state.tx_counter = 0;
    state.rx_window = ReplayWindow::new();
    state.created_at = Instant::now();
    Ok(())
}

/// Indica si la sesión alcanzó el límite de tiempo (~120s) o mensajes para rotación PFS.
pub fn needs_rekey(peer_id: &str) -> bool {
    let guard = SESSIONS.lock().unwrap();
    let Some(map) = guard.as_ref() else { return false };
    let Some(st) = map.get(peer_id) else { return false };
    st.tx_counter >= REKEY_AFTER_MESSAGES
        || st.created_at.elapsed() >= Duration::from_secs(REKEY_AFTER_SECS)
}

/// Cifra con contador secuencial de 64 bits: `0x03 | counter(8B LE) | ciphertext(AEAD)`.
pub fn seal(peer_id: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.as_mut().ok_or_else(|| anyhow::anyhow!("no sessions"))?;
    let st = map
        .get_mut(peer_id)
        .ok_or_else(|| anyhow::anyhow!("no session for peer"))?;
    let counter = st.tx_counter;
    st.tx_counter = st.tx_counter.saturating_add(1);

    let cipher = ChaCha20Poly1305::new_from_slice(&st.key)?;
    let nonce_bytes = counter_to_nonce(counter);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("encrypt failed"))?;

    let mut out = Vec::with_capacity(1 + 8 + ct.len());
    out.push(FRAME_V3_COUNTER);
    out.extend_from_slice(&counter.to_le_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Descifra validando versión, etiqueta AEAD y ventana deslizante anti-replay.
pub fn open(peer_id: &str, frame: &[u8]) -> anyhow::Result<Vec<u8>> {
    if frame.len() < 10 || frame[0] != FRAME_V3_COUNTER {
        return Err(anyhow::anyhow!("unsupported frame version"));
    }
    let mut cbytes = [0u8; 8];
    cbytes.copy_from_slice(&frame[1..9]);
    let counter = u64::from_le_bytes(cbytes);

    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.as_mut().ok_or_else(|| anyhow::anyhow!("no sessions"))?;
    let st = map
        .get_mut(peer_id)
        .ok_or_else(|| anyhow::anyhow!("no session for peer"))?;

    let cipher = ChaCha20Poly1305::new_from_slice(&st.key)?;
    let nonce_bytes = counter_to_nonce(counter);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher
        .decrypt(nonce, &frame[9..])
        .map_err(|_| anyhow::anyhow!("decrypt failed"))?;

    if !st.rx_window.accept(counter) {
        return Err(anyhow::anyhow!("replay packet rejected (seq={counter})"));
    }
    Ok(pt)
}

pub fn clear() {
    *SESSIONS.lock().unwrap() = None;
}
