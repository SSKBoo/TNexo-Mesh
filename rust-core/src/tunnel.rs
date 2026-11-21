//! Encapsulación de paquetes con Noise IKpsk2.
//!
//! Mantiene compatibilidad con las funciones `encapsulate`/`decapsulate` originales
//! (copia simple) y añade variantes cifradas usando una sesión de transporte Noise.

use crate::noise::NoiseSession;

/// Formato: 1 byte de versión + payload cifrado.
const FRAME_VERSION: u8 = 0x01;

/// Encapsulación sin cifrar (compatibilidad).
pub fn encapsulate(plaintext: &[u8]) -> Vec<u8> {
    plaintext.to_vec()
}

/// Decapsulación sin cifrar (compatibilidad).
pub fn decapsulate(ciphertext: &[u8]) -> Vec<u8> {
    ciphertext.to_vec()
}

/// Cifra un paquete con la sesión Noise y añade la cabecera de versión.
pub fn seal(session: &mut NoiseSession, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; plaintext.len() + 64];
    let n = session.seal(plaintext, &mut buf)?;
    let mut frame = Vec::with_capacity(n + 1);
    frame.push(FRAME_VERSION);
    frame.extend_from_slice(&buf[..n]);
    Ok(frame)
}

/// Descifra un paquete con la sesión Noise validando la versión del frame.
pub fn open(session: &mut NoiseSession, frame: &[u8]) -> anyhow::Result<Vec<u8>> {
    if frame.is_empty() || frame[0] != FRAME_VERSION {
        return Err(anyhow::anyhow!("unsupported frame version"));
    }
    let mut buf = vec![0u8; frame.len()];
    let n = session.open(&frame[1..], &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}
