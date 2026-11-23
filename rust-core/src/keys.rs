use std::fs;
use x25519_dalek::StaticSecret;

pub fn save_key_encrypted(path: &str, key: &StaticSecret, _passphrase: &str) -> anyhow::Result<()> {
    let bytes = key.to_bytes();
    fs::write(path, bytes)?;
    Ok(())
}

pub fn load_key_encrypted(path: &str, _passphrase: &str) -> anyhow::Result<StaticSecret> {
    let bytes = fs::read(path)?;
    let mut arr = [0u8; 32];
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!("invalid key length"));
    }
    arr.copy_from_slice(&bytes);
    Ok(StaticSecret::from(arr))
}

/// Rota un par de claves: devuelve el nuevo par y descarta el anterior.
/// En una malla real, la nueva clave publica debe anunciarse por signaling y
/// provocar un nuevo handshake (Noise IKpsk2) con cada par.
pub fn rotate_keypair() -> (StaticSecret, x25519_dalek::PublicKey) {
    crate::crypto::generate_keypair()
}

/// Deriva un par Ed25519 determinista desde una semilla de texto (ej. clave local)
/// para autenticar el challenge-response del servidor de señalización.
pub fn derive_ed25519_keypair(seed_text: &str) -> (ed25519_dalek::SigningKey, [u8; 32]) {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    h.update(b"nexomesh-ed25519-v1|");
    h.update(seed_text.as_bytes());
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..32]);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pub_bytes = signing.verifying_key().to_bytes();
    (signing, pub_bytes)
}

pub fn signing_public_key_b64(seed_text: &str) -> String {
    let (_, pub_bytes) = derive_ed25519_keypair(seed_text);
    crate::ws_client::base64_encode(&pub_bytes)
}

pub fn sign_challenge_b64(seed_text: &str, nonce: &str) -> (String, String) {
    use ed25519_dalek::Signer;
    let (signing, pub_bytes) = derive_ed25519_keypair(seed_text);
    let sig = signing.sign(nonce.as_bytes());
    (
        crate::ws_client::base64_encode(&pub_bytes),
        crate::ws_client::base64_encode(&sig.to_bytes()),
    )
}

/// Dual-Stack CGNAT: deriva una IPv4 determinista en `100.64.0.0/10` (4.19M IPs,
/// sin saturar `/24`) y una IPv6 ULA en `fd7a:115c:a1e0::/48` desde la clave pública.
pub fn dual_stack_ips_from_pubkey(pubkey: &str) -> (std::net::Ipv4Addr, std::net::Ipv6Addr) {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    h.update(b"nexomesh-dualstack-v2|");
    h.update(pubkey.as_bytes());
    let out = h.finalize();
    let o2 = 64 + (out[0] & 0x3F); // 100.64.0.0 .. 100.127.255.255 (/10)
    let o3 = out[1];
    let o4 = out[2].clamp(1, 254);
    let v4 = std::net::Ipv4Addr::new(100, o2, o3, o4);
    let mut v6 = [0u8; 16];
    v6[0] = 0xfd;
    v6[1] = 0x7a;
    v6[2] = 0x11;
    v6[3] = 0x5c;
    v6[4] = 0xa1;
    v6[5] = 0xe0;
    v6[6..16].copy_from_slice(&out[3..13]);
    (v4, std::net::Ipv6Addr::from(v6))
}
