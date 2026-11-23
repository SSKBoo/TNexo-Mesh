//! Cifrado del data plane del túnel con:
//! - Contadores monotónicos de 64 bits (nonces únicos sin colisión)
//! - Ventana deslizante Anti-Replay de 64 paquetes (RFC 6479 / estilo WireGuard)
//! - Rotación automática de claves (cada 120 s o 2^20 mensajes)
//! - Intercambio PFS dinámico por sesión mediante efímeros X25519 aleatorios

use crate::noise::{self, NoiseInitiator, StatelessNoiseSession, PSK_LEN};
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
const FRAME_V4_NOISE_IK: u8 = 0x04;

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
    local_secret: [u8; 32],
    remote_static_pub: [u8; 32],
    psk: [u8; PSK_LEN],
    tx_counter: u64,
    rx_window: ReplayWindow,
    created_at: Instant,
    ephemeral_secret: Option<StaticSecret>,
    pending_noise: Option<NoiseInitiator>,
    noise_session: Option<StatelessNoiseSession>,
    noise_handshake_attempted: bool,
    strict_noise_required: bool,
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
    let remote_static_pub = PublicKey::from(&StaticSecret::from(peer)).to_bytes();
    let key = derive_static_key(&local, &peer, local_priv_text, peer_pub_text);
    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(existing) = map.get_mut(peer_id) {
        if existing.psk == key {
            return Ok(());
        }
    }
    map.insert(
        peer_id.to_string(),
        PeerSessionState {
            key,
            local_secret: local,
            remote_static_pub,
            psk: key,
            tx_counter: 0,
            rx_window: ReplayWindow::new(),
            created_at: Instant::now(),
            ephemeral_secret: None,
            pending_noise: None,
            noise_session: None,
            noise_handshake_attempted: false,
            strict_noise_required: false,
        },
    );
    Ok(())
}

/// Exige handshake 1-RTT `Noise_IKpsk2` antes de sellar datos (prohíbe uso de llave estática).
pub fn set_strict_noise_required(peer_id: &str, required: bool) {
    let mut guard = SESSIONS.lock().unwrap();
    if let Some(map) = guard.as_mut() {
        if let Some(st) = map.get_mut(peer_id) {
            st.strict_noise_required = required;
        }
    }
}

/// Inicia un handshake completo `Noise_IKpsk2` de 1-RTT con llave efímera aleatoria (`-> e, es, s, ss`).
pub fn begin_noise_ik_handshake(peer_id: &str) -> anyhow::Result<Vec<u8>> {
    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.as_mut().ok_or_else(|| anyhow::anyhow!("no sessions"))?;
    let st = map
        .get_mut(peer_id)
        .ok_or_else(|| anyhow::anyhow!("no session for peer"))?;
    st.noise_handshake_attempted = true;
    let mut init = NoiseInitiator::new(&st.local_secret, &st.remote_static_pub, &st.psk)
        .map_err(|e| anyhow::anyhow!("noise init failed: {e}"))?;
    let msg1 = init
        .write_msg1()
        .map_err(|e| anyhow::anyhow!("noise write_msg1 failed: {e}"))?;
    st.pending_noise = Some(init);
    Ok(msg1)
}

/// Responde un handshake `Noise_IKpsk2` entrante (`<- e, ee, se, psk`) y activa transporte cifrado con PFS.
pub fn respond_noise_ik_handshake(peer_id: &str, msg1: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.as_mut().ok_or_else(|| anyhow::anyhow!("no sessions"))?;
    let st = map
        .get_mut(peer_id)
        .ok_or_else(|| anyhow::anyhow!("no session for peer"))?;
    let (msg2, transport) = noise::respond_stateless_handshake(&st.local_secret, &st.psk, msg1)
        .map_err(|e| anyhow::anyhow!("noise respond failed: {e}"))?;
    st.noise_session = Some(transport);
    st.noise_handshake_attempted = true;
    st.tx_counter = 0;
    st.rx_window = ReplayWindow::new();
    st.created_at = Instant::now();
    Ok(msg2)
}

/// Completa el handshake 1-RTT `Noise_IKpsk2` en el iniciador al recibir `msg2`.
pub fn complete_noise_ik_handshake(peer_id: &str, msg2: &[u8]) -> anyhow::Result<()> {
    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.as_mut().ok_or_else(|| anyhow::anyhow!("no sessions"))?;
    let st = map
        .get_mut(peer_id)
        .ok_or_else(|| anyhow::anyhow!("no session for peer"))?;
    let init = st
        .pending_noise
        .take()
        .ok_or_else(|| anyhow::anyhow!("no pending noise initiator"))?;
    let transport = init
        .read_msg2_into_stateless_session(msg2)
        .map_err(|e| anyhow::anyhow!("noise msg2 failed: {e}"))?;
    st.noise_session = Some(transport);
    st.tx_counter = 0;
    st.rx_window = ReplayWindow::new();
    st.created_at = Instant::now();
    Ok(())
}

pub fn is_noise_ik_established(peer_id: &str) -> bool {
    let guard = SESSIONS.lock().unwrap();
    guard
        .as_ref()
        .and_then(|m| m.get(peer_id))
        .map(|st| st.noise_session.is_some())
        .unwrap_or(false)
}

pub fn should_start_noise_handshake(peer_id: &str) -> bool {
    let guard = SESSIONS.lock().unwrap();
    guard
        .as_ref()
        .and_then(|m| m.get(peer_id))
        .map(|st| !st.noise_handshake_attempted && st.noise_session.is_none())
        .unwrap_or(false)
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
        local_secret: [0u8; 32],
        remote_static_pub: [0u8; 32],
        psk: [0u8; PSK_LEN],
        tx_counter: 0,
        rx_window: ReplayWindow::new(),
        created_at: Instant::now(),
        ephemeral_secret: None,
        pending_noise: None,
        noise_session: None,
        noise_handshake_attempted: false,
        strict_noise_required: false,
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
    state.noise_session = None;
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

/// Fuerza que `needs_rekey(peer_id)` devuelva `true` en el siguiente ciclo (rotación inmediata).
pub fn schedule_rekey_now(peer_id: &str) {
    let mut guard = SESSIONS.lock().unwrap();
    if let Some(map) = guard.as_mut() {
        if let Some(st) = map.get_mut(peer_id) {
            st.tx_counter = REKEY_AFTER_MESSAGES;
        }
    }
}

/// Cifra usando la sesión Noise IKpsk2 (`0x04`) si está activa, o contador secuencial ChaCha20 (`0x03`).
pub fn seal(peer_id: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.as_mut().ok_or_else(|| anyhow::anyhow!("no sessions"))?;
    let st = map
        .get_mut(peer_id)
        .ok_or_else(|| anyhow::anyhow!("no session for peer"))?;
    let counter = st.tx_counter;
    st.tx_counter = st.tx_counter.saturating_add(1);

    if let Some(noise_sess) = st.noise_session.as_ref() {
        let mut ct = vec![0u8; plaintext.len() + 64];
        let n = noise_sess
            .seal_with_nonce(counter, plaintext, &mut ct)
            .map_err(|e| anyhow::anyhow!("noise encrypt failed: {e}"))?;
        let mut out = Vec::with_capacity(1 + 8 + n);
        out.push(FRAME_V4_NOISE_IK);
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(&ct[..n]);
        return Ok(out);
    }

    if st.strict_noise_required && st.noise_session.is_none() {
        return Err(anyhow::anyhow!(
            "strict 1-RTT Noise_IKpsk2 handshake required before sealing data"
        ));
    }

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

/// Descifra validando `0x04` (Noise IKpsk2) o `0x03` (ChaCha20-Poly1305 + ventana anti-replay).
pub fn open(peer_id: &str, frame: &[u8]) -> anyhow::Result<Vec<u8>> {
    if frame.len() < 10 {
        return Err(anyhow::anyhow!("frame too short"));
    }
    let mut cbytes = [0u8; 8];
    cbytes.copy_from_slice(&frame[1..9]);
    let counter = u64::from_le_bytes(cbytes);

    let mut guard = SESSIONS.lock().unwrap();
    let map = guard.as_mut().ok_or_else(|| anyhow::anyhow!("no sessions"))?;
    let st = map
        .get_mut(peer_id)
        .ok_or_else(|| anyhow::anyhow!("no session for peer"))?;

    if frame[0] == FRAME_V4_NOISE_IK {
        let noise_sess = st
            .noise_session
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no active Noise IK session"))?;
        let mut pt = vec![0u8; frame.len()];
        let n = noise_sess
            .open_with_nonce(counter, &frame[9..], &mut pt)
            .map_err(|e| anyhow::anyhow!("noise decrypt failed: {e}"))?;
        if !st.rx_window.accept(counter) {
            return Err(anyhow::anyhow!("replay packet rejected (seq={counter})"));
        }
        pt.truncate(n);
        return Ok(pt);
    }

    if frame[0] != FRAME_V3_COUNTER {
        return Err(anyhow::anyhow!("unsupported frame version"));
    }

    if st.strict_noise_required && st.noise_session.is_none() {
        return Err(anyhow::anyhow!(
            "strict 1-RTT Noise_IKpsk2 handshake required before sealing data"
        ));
    }

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
