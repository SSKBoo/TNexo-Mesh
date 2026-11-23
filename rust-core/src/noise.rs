//! Implementación real del handshake Noise IKpsk2_25519_ChaChaPoly_BLAKE2s.
//!
//! Usa llaves efímeras aleatorias por sesión (Perfect Forward Secrecy real)
//! mediante `snow::Builder` sin modos de prueba fijos.

use snow::params::NoiseParams;
use snow::{Builder, HandshakeState, TransportState};

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

/// Sesión de transporte cifrada tras completar el handshake Noise IKpsk2.
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

/// Estado interactivo del iniciador Noise IKpsk2 para intercambio por red (PFS).
pub struct NoiseInitiator {
    state: HandshakeState,
}

impl NoiseInitiator {
    pub fn new(
        local_priv: &[u8],
        remote_pub: &[u8],
        psk: &[u8; PSK_LEN],
    ) -> Result<Self, snow::Error> {
        let state = Builder::new(params())
            .local_private_key(local_priv)?
            .remote_public_key(remote_pub)?
            .psk(2, psk)?
            .build_initiator()?;
        Ok(Self { state })
    }

    /// Genera el primer mensaje del handshake (`-> e, es, s, ss`) con efímero aleatorio.
    pub fn write_msg1(&mut self) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; 256];
        let n = self.state.write_message(&[], &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Procesa la respuesta del respondedor (`<- e, ee, se, psk`) y entra en modo transporte.
    pub fn read_msg2_into_session(mut self, msg2: &[u8]) -> Result<NoiseSession, snow::Error> {
        let mut out = [0u8; 256];
        self.state.read_message(msg2, &mut out)?;
        Ok(NoiseSession {
            transport: self.state.into_transport_mode()?,
        })
    }
}

/// Responde un handshake IKpsk2 recibido por la red generando su propio efímero aleatorio.
pub fn respond_handshake(
    responder_priv: &[u8],
    psk: &[u8; PSK_LEN],
    msg1: &[u8],
) -> Result<(Vec<u8>, NoiseSession), snow::Error> {
    let mut responder = Builder::new(params())
        .local_private_key(responder_priv)?
        .psk(2, psk)?
        .build_responder()?;
    let mut read = [0u8; 256];
    responder.read_message(msg1, &mut read)?;
    let mut msg2 = vec![0u8; 256];
    let n = responder.write_message(&[], &mut msg2)?;
    msg2.truncate(n);
    Ok((
        msg2,
        NoiseSession {
            transport: responder.into_transport_mode()?,
        },
    ))
}

/// Ejecuta el handshake IKpsk2 completo con efímeros aleatorios (PFS real).
pub fn handshake(
    initiator_priv: &[u8],
    responder_pub: &[u8],
    responder_priv: &[u8],
    psk: &[u8; PSK_LEN],
) -> Result<NoisePair, snow::Error> {
    let mut init = NoiseInitiator::new(initiator_priv, responder_pub, psk)?;
    let msg1 = init.write_msg1()?;
    let (msg2, responder) = respond_handshake(responder_priv, psk, &msg1)?;
    let initiator = init.read_msg2_into_session(&msg2)?;
    Ok(NoisePair {
        initiator,
        responder,
    })
}
