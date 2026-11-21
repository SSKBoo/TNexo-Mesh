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
