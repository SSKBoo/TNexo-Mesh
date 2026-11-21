//! Implementación real del handshake Noise IKpsk2_25519_ChaChaPoly_BLAKE2s.
//!
//! El patrón IK autentica a ambos pares estáticamente (el iniciador conoce la
//! clave pública estática del respondedor y envía la suya en el primer mensaje)
//! y añade una PSK de 32 bytes (psk2) que se mezcla en la derivación de claves.

use snow::params::NoiseParams;
use snow::{Builder, TransportState};

pub const NOISE_PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const PSK_LEN: usize = 32;

pub fn params() -> NoiseParams {
    NOISE_PATTERN
        .parse()
        .expect("patrón Noise válido")
}

pub fn pattern() -> &'static str {
    NOISE_PATTERN
}

/// Handshake con efímeros fijos: permite que dos extremos que conocen las mismas
/// claves estáticas deriven transportes espejo sin intercambiar mensajes de
/// handshake por la red (necesario para el data plane del túnel).
pub fn handshake_with_ephemerals(
    initiator_priv: &[u8],
    responder_pub: &[u8],
    responder_priv: &[u8],
    psk: &[u8; PSK_LEN],
    e_init: &[u8],
    e_resp: &[u8],
) -> Result<NoisePair, snow::Error> {
    let mut initiator = Builder::new(params())
        .local_private_key(initiator_priv)?
        .remote_public_key(responder_pub)?
        .psk(2, psk)?
        .fixed_ephemeral_key_for_testing_only(e_init)
        .build_initiator()?;

    let mut responder = Builder::new(params())
        .local_private_key(responder_priv)?
        .psk(2, psk)?
        .fixed_ephemeral_key_for_testing_only(e_resp)
        .build_responder()?;

    let mut b1 = [0u8; 1024];
    let mut b2 = [0u8; 1024];
    let mut read = [0u8; 1024];
    let n1 = initiator.write_message(&[], &mut b1)?;
    responder.read_message(&b1[..n1], &mut read)?;
    let n2 = responder.write_message(&[], &mut b2)?;
    initiator.read_message(&b2[..n2], &mut read)?;

    Ok(NoisePair {
        initiator: NoiseSession { transport: initiator.into_transport_mode()? },
        responder: NoiseSession { transport: responder.into_transport_mode()? },
    })
}

/// Sesión de transporte cifrada tras completar el handshake.
pub struct NoiseSession {
    transport: TransportState,
}

impl NoiseSession {
    /// Cifra un mensaje de transporte. Devuelve el número de bytes escritos.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, snow::Error> {
        self.transport.write_message(plaintext, out)
    }

    /// Descifra un mensaje de transporte. Devuelve el número de bytes leídos.
    pub fn open(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, snow::Error> {
        self.transport.read_message(ciphertext, out)
    }
}

/// Resultado del handshake: sesiones de transporte para cada extremo.
pub struct NoisePair {
    pub initiator: NoiseSession,
    pub responder: NoiseSession,
}

/// Ejecuta el handshake IKpsk2 completo entre dos pares.
///
/// - `initiator_priv`: clave privada Curve25519 del iniciador (32 bytes).
/// - `responder_pub`: clave pública Curve25519 del respondedor (32 bytes).
/// - `responder_priv`: clave privada Curve25519 del respondedor (32 bytes).
/// - `psk`: clave precompartida de 32 bytes.
pub fn handshake(
    initiator_priv: &[u8],
    responder_pub: &[u8],
    responder_priv: &[u8],
    psk: &[u8; PSK_LEN],
) -> Result<NoisePair, snow::Error> {
    let mut initiator = Builder::new(params())
        .local_private_key(initiator_priv)?
        .remote_public_key(responder_pub)?
        .psk(2, psk)?
        .build_initiator()?;

    let mut responder = Builder::new(params())
        .local_private_key(responder_priv)?
        .psk(2, psk)?
        .build_responder()?;

    let mut buf1 = [0u8; 1024];
    let mut buf2 = [0u8; 1024];
    let mut read = [0u8; 1024];

    // -> e, es, s, ss
    let len1 = initiator.write_message(&[], &mut buf1)?;
    responder.read_message(&buf1[..len1], &mut read)?;

    // <- e, ee, se, psk
    let len2 = responder.write_message(&[], &mut buf2)?;
    initiator.read_message(&buf2[..len2], &mut read)?;

    Ok(NoisePair {
        initiator: NoiseSession { transport: initiator.into_transport_mode()? },
        responder: NoiseSession { transport: responder.into_transport_mode()? },
    })
}
